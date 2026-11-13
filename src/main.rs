//! sYncX — Bluetooth pairing sync for dual-boot Linux + Windows.
//!
//! One binary, three modes:
//! - `syncx`            the Rune GUI (scan pairings, create the Windows import payload)
//! - `syncx --export`   CLI: print the BlueZ store as JSON (the pkexec helper uses this)
//! - `syncx --place …`  CLI: copy the payload into the Windows partition as root

use std::path::PathBuf;

mod bt;
mod payload;
mod ui;
mod winpart;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--export") => cmd_export(),
        Some("--place") => ui::cmd_place(&args[1..]),
        Some("--help") | Some("-h") => {
            println!("sYncX — Bluetooth pairing sync for dual-boot Linux + Windows\n");
            println!("  syncx            open the app");
            println!("  syncx --export   print the Bluetooth pairing store as JSON (needs root)");
            println!("  syncx --place <ps1> <cmd> <dir>   copy the payload as root");
            println!("  syncx --sample [file]   write an example import script with demo data");
        }
        Some("--sample") => cmd_sample(args.get(1).map(String::as_str)),
        _ => ui::run(),
    }
}

fn cmd_export() {
    match bt::scan(bt::default_root()) {
        Ok(store) => {
            println!("{}", serde_json::to_string(&store).expect("store serializes"));
        }
        Err(e) => {
            eprintln!("sYncX: cannot read {}: {e}", bt::default_root().display());
            std::process::exit(1);
        }
    }
}

/// Write an example payload with demo devices, so the script Windows will run
/// can be reviewed without pairing anything.
fn cmd_sample(path: Option<&str>) {
    let devices = ui::fixture_devices();
    let Some(payload) = payload::Payload::from_devices(&devices[0].adapter, &devices) else {
        eprintln!("sYncX: nothing to put in the sample");
        std::process::exit(1);
    };
    let json = serde_json::to_string(&payload).expect("payload serializes");
    let ps1 = payload::render_import_ps1(&payload::base64(json.as_bytes()));
    let out = PathBuf::from(path.unwrap_or("syncx-import.ps1"));
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&out, ps1).unwrap_or_else(|e| {
        eprintln!("sYncX: cannot write {}: {e}", out.display());
        std::process::exit(1);
    });
    println!("wrote {}", out.display());
}
