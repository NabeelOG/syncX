//! The sYncX app: Rune UI plus the background worker that does the real work.
//!
//! The UI thread never blocks: handlers post `Action`s on a channel, a worker
//! thread runs them (scan via `pkexec` when not root, payload build, writing to
//! the Windows partition) and reports back with `handle.update`.

use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};

use rune::tok::{self, radius, space, type_, TextStyle};
use rune::{App, AppHandle, AppSpec, Cx, Cursor, El, col, el, row, text};

use crate::bt::{self, Device, Kind, Store};
use crate::payload::{self, Payload};
use crate::winpart;

// ---------------------------------------------------------------------------
// State and actions

#[derive(Debug, Clone)]
pub enum Status {
    Info(String),
    Ok(String),
    Err(String),
}

#[derive(Debug)]
pub enum Action {
    Scan,
    Export { adapter: String, devices: Vec<Device> },
}

pub struct State {
    tx: Sender<Action>,
    pub scanned: bool,
    pub devices: Vec<Device>,
    pub busy: bool,
    pub status: Option<Status>,
    pub written: Vec<String>,
}

impl State {
    pub fn new(tx: Sender<Action>) -> State {
        State { tx, scanned: false, devices: Vec::new(), busy: false, status: None, written: Vec::new() }
    }

    pub fn send_scan(&mut self) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.status = Some(Status::Info("Scanning Bluetooth pairings (root access may be requested)…".into()));
        let _ = self.tx.send(Action::Scan);
    }

    pub fn send_export(&mut self) {
        if self.busy {
            return;
        }
        let adapter = self
            .devices
            .iter()
            .find(|d| matches!(d.kind, Kind::Classic { .. }))
            .map(|d| d.adapter.clone());
        let Some(adapter) = adapter else {
            self.status = Some(Status::Err("Nothing to sync yet — no classic Bluetooth pairing with a key was found.".into()));
            return;
        };
        self.busy = true;
        self.status = Some(Status::Info("Building the Windows import script…".into()));
        let _ = self.tx.send(Action::Export { adapter, devices: self.devices.clone() });
    }
}

// ---------------------------------------------------------------------------
// Background worker

pub fn spawn_worker(handle: AppHandle<State>, rx: Receiver<Action>) {
    std::thread::spawn(move || {
        for action in rx {
            match action {
                Action::Scan => do_scan(&handle),
                Action::Export { adapter, devices } => do_export(&handle, adapter, devices),
            }
        }
    });
}

/// Read the BlueZ store directly when privileged, else through the pkexec helper
/// (this same binary, run as root by polkit, printing the store as JSON).
fn read_store() -> Result<Store, String> {
    match bt::scan(bt::default_root()) {
        Ok(store) => Ok(store),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let exe = std::env::current_exe().map_err(|e| format!("cannot locate the app: {e}"))?;
            let out = Command::new("pkexec")
                .arg(&exe)
                .arg("--export")
                .output()
                .map_err(|e| format!("could not start pkexec: {e}"))?;
            if !out.status.success() {
                let why = String::from_utf8_lossy(&out.stderr);
                return Err(if why.trim().is_empty() {
                    "Root access was not granted, so the pairing store (/var/lib/bluetooth) could not be read.".into()
                } else {
                    why.trim().to_string()
                });
            }
            serde_json::from_slice(&out.stdout).map_err(|e| format!("could not read the helper's output: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("No Bluetooth pairing store at /var/lib/bluetooth — is BlueZ installed?".into())
        }
        Err(e) => Err(e.to_string()),
    }
}

fn do_scan(handle: &AppHandle<State>) {
    let result = read_store();
    handle.update(move |s, _| {
        s.busy = false;
        match result {
            Ok(store) => {
                let n = store.syncable().len();
                s.scanned = true;
                s.devices = store.devices;
                s.status = Some(match n {
                    0 => Status::Info("No paired devices with copyable keys found. Pair the speaker on this OS first.".into()),
                    _ => Status::Ok(format!("{n} classic pairing{} found and ready to sync.", if n == 1 { "" } else { "s" })),
                });
            }
            Err(e) => {
                s.status = Some(Status::Err(e));
            }
        }
    });
}

/// Copy files into place as root (the Windows partition may be root-owned).
fn place_via_pkexec(ps1: &PathBuf, cmd: &PathBuf, target: &PathBuf) -> Result<Vec<PathBuf>, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let out = Command::new("pkexec")
        .arg(&exe)
        .arg("--place")
        .arg(ps1)
        .arg(cmd)
        .arg(target)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(vec![
        target.join(ps1.file_name().unwrap_or_default()),
        target.join(cmd.file_name().unwrap_or_default()),
    ])
}

fn do_export(handle: &AppHandle<State>, adapter: String, devices: Vec<Device>) {
    let result = build_and_place(&adapter, &devices);
    handle.update(move |s, _| {
        s.busy = false;
        match result {
            Ok((paths, status)) => {
                s.written = paths;
                s.status = Some(status);
            }
            Err(e) => s.status = Some(Status::Err(e)),
        }
    });
}

fn build_and_place(adapter: &str, devices: &[Device]) -> Result<(Vec<String>, Status), String> {
    let Some(payload) = Payload::from_devices(adapter, devices) else {
        return Err("None of the paired devices is a classic Bluetooth device with a copyable key.".into());
    };
    let json = serde_json::to_string(&payload).expect("payload serializes");
    let ps1 = payload::render_import_ps1(&payload::base64(json.as_bytes()));
    let cmd = payload::render_import_cmd();

    let mounts = winpart::ntfs_mounts().unwrap_or_default();
    let volumes = winpart::find_windows_volumes(&mounts);

    let mut written: Vec<PathBuf> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    if let Some(vol) = volumes.first() {
        match winpart::write_payload(&vol.target, &ps1, &cmd) {
            Ok(paths) => {
                written = paths;
            }
            Err(_) => {
                // Read-only mount (fast startup) or permissions: keep a copy for
                // the user, then try to get the files into place as root.
                let fb = winpart::fallback_dir();
                if let Ok(paths) = winpart::write_payload(&fb, &ps1, &cmd) {
                    written = paths;
                }
                if written.len() == 2 {
                    match place_via_pkexec(&written[0], &written[1], &vol.target) {
                        Ok(placed) => written = placed,
                        Err(_) => skipped.push("direct placement".into()),
                    }
                }
            }
        }
    } else {
        let fb = winpart::fallback_dir();
        if let Ok(paths) = winpart::write_payload(&fb, &ps1, &cmd) {
            written = paths;
        }
    }

    if written.is_empty() {
        return Err("Could not write the payload anywhere — check disk space and permissions.".into());
    }

    let location = written[0].parent().map(|p| p.display().to_string()).unwrap_or_default();
    let note = if volumes.is_empty() {
        "No Windows partition is mounted, so the files were saved locally — copy both to the Windows desktop (a USB stick works too) and run the .cmd there."
    } else if !skipped.is_empty() {
        "The Windows partition is not writable (usually because Windows was hibernated), so the files were saved locally — copy both to the Windows desktop and run the .cmd there."
    } else {
        ""
    };

    let ble: Vec<&Device> = devices.iter().filter(|d| matches!(d.kind, Kind::Ble)).collect();
    let ble_note = match ble.len() {
        0 => String::new(),
        1 => format!(" Skipped {} (BLE pairing — keys like this can't be copied safely).", ble[0].name),
        n => format!(" Skipped {n} BLE devices — their keys can't be copied safely."),
    };

    let status = Status::Ok(format!(
        "Wrote syncx-import.ps1 and syncx-import.cmd to {location}. Boot into Windows and double-click syncx-import.cmd — approve the UAC prompt and wait for \"Done\".{ble_note}{note_prefix}{note}",
        note_prefix = if note.is_empty() { "" } else { " " }
    ));

    Ok((
        written.iter().map(|p| p.display().to_string()).collect(),
        status,
    ))
}

/// `syncx --place <ps1-src> <cmd-src> <dst-dir>`: copy the payload as root.
pub fn cmd_place(args: &[String]) {
    if args.len() != 3 {
        eprintln!("usage: syncx --place <src-ps1> <src-cmd> <dst-dir>");
        std::process::exit(2);
    }
    let dst = PathBuf::from(&args[2]);
    for src in [&args[0], &args[1]] {
        let src = PathBuf::from(src);
        match std::fs::copy(&src, dst.join(src.file_name().unwrap_or_default())) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("copy failed: {e}");
                std::process::exit(1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture for headless rendering and tests

pub fn fixture_devices() -> Vec<Device> {
    vec![
        Device {
            adapter: "DC:41:A9:F1:8E:53".into(),
            mac: "AA:BB:CC:DD:EE:FF".into(),
            name: "Soundcore Motion+".into(),
            kind: Kind::Classic { link_key: "1F2A3B4C5D6E7F8090A1B2C3D4E5F600".into() },
        },
        Device {
            adapter: "DC:41:A9:F1:8E:53".into(),
            mac: "11:22:33:44:55:66".into(),
            name: "WH-1000XM5".into(),
            kind: Kind::Ble,
        },
    ]
}

// ---------------------------------------------------------------------------
// View

pub fn view(s: &State, cx: &mut Cx<State>) -> El {
    let t = tok::theme(cx.system_dark());
    col()
        .w_full()
        .h_full()
        .fill(t.bg)
        .px(space::S6)
        .py(space::S6)
        .gap(space::S3)
        .child(header(t))
        .child(device_card(s, t))
        .child(actions(s, t))
        .child(status_block(s, t))
        .child(footer(t))
}

fn header(t: tok::Theme) -> El {
    col()
        .w_full()
        .gap(2.0)
        .child(
            text("sYncX")
                .font(TextStyle::new(17.0, 650.0))
                .color(t.text),
        )
        .child(
            text("Bluetooth pairing sync for dual-boot Linux + Windows")
                .font(type_::BODY)
                .color(t.text_secondary)
                .wrap(),
        )
}

fn device_card(s: &State, t: tok::Theme) -> El {
    let mut card = col()
        .key("devices")
        .w_full()
        .px(space::S2)
        .py(space::S2)
        .gap(2.0)
        .radius(radius::MD)
        .fill(t.card)
        .border(1.0, t.card_border);

    if s.devices.is_empty() {
        card = card.child(
            text(if s.scanned {
                "No paired devices found. Pair your speaker on this OS first."
            } else {
                "Not scanned yet — press Scan."
            })
            .font(type_::BODY)
            .color(t.text_secondary)
            .pt(space::S2)
            .pb(space::S2),
        );
        return card;
    }

    for (i, d) in s.devices.iter().enumerate() {
        card = card.child(device_row(i, d, t));
    }
    card
}

fn device_row(i: usize, d: &Device, t: tok::Theme) -> El {
    let mac_no_colon = d.mac.replace(':', "").to_lowercase();
    let (badge, badge_fill, badge_text) = match &d.kind {
        Kind::Classic { .. } => ("syncable", tok::accent(4, true), t.text),
        Kind::Ble => ("BLE — can't sync", t.control_track, t.text_secondary),
        Kind::Unknown => ("no key", t.control_track, t.text_secondary),
    };
    row()
        .key(format!("dev-{mac_no_colon}"))
        .w_full()
        .h(36.0)
        .px(space::S2)
        .center_y()
        .gap(space::S2)
        .child(
            text(d.name.clone())
                .key(format!("dev-{i}-name"))
                .font(type_::BODY)
                .color(t.text)
                .grow(1.0),
        )
        .child(
            text(d.mac.clone())
                .font(type_::MONO_CAPTION)
                .color(t.text_secondary),
        )
        .child(
            el()
                .key(format!("dev-{i}-badge"))
                .px(space::S2)
                .py(3.0)
                .radius(radius::SM)
                .fill(badge_fill)
                .child(text(badge).font(type_::SECTION).color(badge_text)),
        )
}

fn button(key: &'static str, label: &'static str, primary: bool, t: tok::Theme, press: impl Fn(&mut State) + 'static) -> El {
    el()
        .key(key)
        .role("button")
        .label(label)
        .h(32.0)
        .px(space::S3)
        .center_y()
        .radius(radius::MD)
        .fill(if primary { tok::accent(0, true) } else { t.card })
        .border(if primary { 0.0 } else { 1.0 }, t.card_border)
        .cursor(Cursor::Pointer)
        .on_press(press)
        .child(
            text(label)
                .font(type_::LABEL)
                .color(if primary { t.knob } else { t.text }),
        )
}

fn actions(s: &State, t: tok::Theme) -> El {
    let mut row = row().key("actions").w_full().gap(space::S2);
    row = row
        .child(button(
            "scan",
            if s.scanned { "Re-scan" } else { "Scan" },
            false,
            t,
            |s: &mut State| s.send_scan(),
        ))
        .child(button(
            "sync",
            "Create Windows import",
            true,
            t,
            |s: &mut State| s.send_export(),
        ));
    row
}

fn status_block(s: &State, t: tok::Theme) -> El {
    let Some(status) = &s.status else {
        return el().key("status");
    };
    let (msg, color) = match status {
        Status::Info(m) => (m.clone(), t.text_secondary),
        Status::Ok(m) => (m.clone(), tok::accent(4, true)),
        Status::Err(m) => (m.clone(), tok::accent(3, true)),
    };
    let mut block = col()
        .key("status")
        .w_full()
        .px(space::S2)
        .py(space::S2)
        .gap(4.0)
        .radius(radius::MD)
        .fill(t.card)
        .border(1.0, t.card_border)
        .child(
            text(msg)
                .key("status-msg")
                .font(type_::BODY)
                .color(color)
                .wrap(),
        );
    for path in &s.written {
        block = block.child(
            text(path.clone())
                .font(type_::MONO_CAPTION)
                .color(t.text_secondary)
                .truncate(),
        );
    }
    block
}

fn footer(t: tok::Theme) -> El {
    col()
        .key("footer")
        .w_full()
        .grow(1.0)
        .child(
            text("One pairing, two systems: after the import, both OSes store the same key, so the speaker pairs on either without re-pairing.")
                .font(type_::SECTION)
                .color(t.text_secondary)
                .wrap(),
        )
}

// ---------------------------------------------------------------------------
// App entry

pub fn run() {
    let (tx, rx) = mpsc::channel::<Action>();
    let init_tx = tx.clone();
    let app = App::new(AppSpec::<State> {
        scenes: &[
            ("scanned", |s: &mut State| {
                s.scanned = true;
                s.devices = fixture_devices();
            }),
            ("done", |s: &mut State| {
                s.scanned = true;
                s.devices = fixture_devices();
                s.status = Some(Status::Ok(
                    "Wrote syncx-import.ps1 and syncx-import.cmd to /run/media/nabeel/Windows/Users/nabeel/Desktop. Boot into Windows and double-click syncx-import.cmd.".into(),
                ));
                s.written = vec![
                    "/run/media/nabeel/Windows/Users/nabeel/Desktop/syncx-import.ps1".into(),
                    "/run/media/nabeel/Windows/Users/nabeel/Desktop/syncx-import.cmd".into(),
                ];
            }),
        ],
        ..AppSpec::new("sYncX", (460.0, 540.0), no_init, view)
    })
    .init(move || State::new(init_tx.clone()));

    let handle = app.handle();
    spawn_worker(handle, rx);

    app.run();
}

/// The AppSpec's `init` must be a plain fn pointer; `App::init(..)` replaces it
/// with the real state constructor, so this should never run.
fn no_init() -> State {
    panic!("sYncX state is built by App::init");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune::{Env, Runtime};

    #[test]
    fn devices_render_and_the_sync_button_posts_an_export() {
        let (tx, rx) = mpsc::channel();
        let mut s = State::new(tx);
        s.scanned = true;
        s.devices = fixture_devices();
        let mut rt = Runtime::new(s, view, (460.0, 540.0), Env { system_dark: true, scale: 2.0 });
        rt.frame(0.0);

        // both devices render, keyed by MAC
        assert!(rt.find("dev-aabbccddeeff").is_some());
        assert!(rt.find("dev-112233445566").is_some());

        // pressing Create Windows import goes busy and posts the Export action
        let (x, y) = rt.find("sync").unwrap();
        rt.pointer_down(x, y);
        rt.pointer_up(x, y);
        rt.frame(0.0);
        assert!(rt.state.busy);
        match rx.try_recv().unwrap() {
            Action::Export { adapter, devices } => {
                assert_eq!(adapter, "DC:41:A9:F1:8E:53");
                assert_eq!(devices.len(), 2);
            }
            other => panic!("expected Export, got {other:?}"),
        }
    }

    #[test]
    fn scan_button_posts_a_scan() {
        let (tx, rx) = mpsc::channel();
        let s = State::new(tx);
        let mut rt = Runtime::new(s, view, (460.0, 540.0), Env { system_dark: true, scale: 2.0 });
        rt.frame(0.0);
        let (x, y) = rt.find("scan").unwrap();
        rt.pointer_down(x, y);
        rt.pointer_up(x, y);
        rt.frame(0.0);
        assert!(rt.state.busy);
        assert!(matches!(rx.try_recv().unwrap(), Action::Scan));
    }

    #[test]
    fn sync_is_a_no_op_while_busy() {
        let (tx, rx) = mpsc::channel();
        let mut s = State::new(tx);
        s.scanned = true;
        s.devices = fixture_devices();
        s.busy = true;
        s.send_export();
        assert!(rx.try_recv().is_err(), "no action while busy");
    }
}
