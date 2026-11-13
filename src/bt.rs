//! Reading pairing keys from BlueZ's store: `/var/lib/bluetooth/<adapter>/<device>/info`.
//!
//! A classic (BR/EDR) device's info file has a `[LinkKey]` section:
//!
//! ```ini
//! [General]
//! Name=Soundcore Motion+
//! Class=0x00240404
//!
//! [LinkKey]
//! Key=1F2A3B4C5D6E7F8090A1B2C3D4E5F600
//! Type=4
//! ```
//!
//! BLE-only devices carry `[LongTermKey]`, `[IdentityAddress]`, … instead. Those
//! need more than a key copy (LTK/IRK/CSRK, and Windows stores them under a device
//! subkey with different value names), so sYncX reports them as unsupported.

use std::fs;
use std::path::Path;

use serde::Serialize;

/// One paired device, as the Linux side sees it.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct Device {
    /// Adapter MAC, `AA:BB:CC:DD:EE:FF`.
    pub adapter: String,
    /// Device MAC, `AA:BB:CC:DD:EE:FF`.
    pub mac: String,
    pub name: String,
    pub kind: Kind,
}

#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kind {
    /// Classic Bluetooth: a single link key, copyable between OSes byte for byte.
    Classic { link_key: String },
    /// BLE: needs more keys than a copy carries; sYncX refuses to half-sync it.
    Ble,
    /// Paired but no key material found (or the file is unreadable).
    Unknown,
}

/// Everything a scan of a BlueZ store produces; this is what the root helper
/// prints as JSON and what the payload generator consumes.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Store {
    pub devices: Vec<Device>,
}

impl Store {
    /// Devices that can be synced to Windows: classic pairings with a link key.
    pub fn syncable(&self) -> Vec<&Device> {
        self.devices
            .iter()
            .filter(|d| matches!(d.kind, Kind::Classic { .. }))
            .collect()
    }
}

/// `true` for a string that looks like a Bluetooth MAC: six colon-separated hex pairs.
pub fn is_mac(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        match i % 3 {
            2 => {
                if *b != b':' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Parse one BlueZ `info` file's contents.
pub fn parse_info(text: &str) -> Kind {
    let mut section = "";
    let mut link_key: Option<String> = None;
    let mut ble = false;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            if matches!(
                section,
                "LongTermKey"
                    | "SlaveLongTermKey"
                    | "IdentityAddress"
                    | "LocalSignatureKey"
                    | "SignKey"
            ) {
                ble = true;
            }
            continue;
        }
        if section == "LinkKey" {
            if let Some(value) = line.strip_prefix("Key=") {
                let value = value.trim();
                // BlueZ writes lowercase hex, 16 bytes (32 chars) for a standard link key.
                if is_hex(value) {
                    link_key = Some(value.to_uppercase());
                }
            }
        }
    }

    if let Some(link_key) = link_key {
        Kind::Classic { link_key }
    } else if ble {
        Kind::Ble
    } else {
        Kind::Unknown
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Read the `Name=` out of an info file, falling back to the MAC.
fn name_from_info(text: &str, mac: &str) -> String {
    let mut section = "";
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        if section == "General" {
            if let Some(name) = line.strip_prefix("Name=") {
                let name = name.trim();
                if !name.is_empty() {
                    return name.to_string();
                }
            }
        }
    }
    mac.to_string()
}

/// Scan a BlueZ store root (normally `/var/lib/bluetooth`) for paired devices.
///
/// Takes the root as a parameter so tests can run it against fixtures; the
/// production caller passes `/var/lib/bluetooth`, which needs root.
pub fn scan(root: &Path) -> std::io::Result<Store> {
    let mut devices = Vec::new();
    for adapter in fs::read_dir(root)? {
        let adapter = adapter?;
        let adapter_name = adapter.file_name().to_string_lossy().to_string();
        if !is_mac(&adapter_name) {
            continue;
        }
        for entry in fs::read_dir(adapter.path())? {
            let entry = entry?;
            let mac = entry.file_name().to_string_lossy().to_string();
            if !is_mac(&mac) {
                continue;
            }
            let info_path = entry.path().join("info");
            let Ok(text) = fs::read_to_string(&info_path) else {
                devices.push(Device {
                    adapter: adapter_name.clone(),
                    mac: mac.clone(),
                    name: mac.clone(),
                    kind: Kind::Unknown,
                });
                continue;
            };
            devices.push(Device {
                adapter: adapter_name.clone(),
                mac: mac.clone(),
                name: name_from_info(&text, &mac),
                kind: parse_info(&text),
            });
        }
    }
    devices.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(Store { devices })
}

/// The default BlueZ store location.
pub fn default_root() -> &'static Path {
    Path::new("/var/lib/bluetooth")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLASSIC: &str = "[General]\nName=Soundcore Motion+\nClass=0x00240404\nSupportedTechnologies=BR/EDR\nTrusted=true\nBlocked=false\n\n[LinkKey]\nKey=1f2a3b4c5d6e7f8090a1b2c3d4e5f600\nType=4\n";
    const BLE: &str = "[General]\nName=WH-1000XM5\n\n[LongTermKey]\nKey=a1b2c3d4e5f60718293a4b5c6d7e8f90\nEncSize=16\nEDiv=1234\nRand=1122334455667788\n";
    const EMPTY: &str = "[General]\nName=Mystery\n";

    #[test]
    fn macs_are_recognised() {
        assert!(is_mac("AC:12:3F:00:DE:FF"));
        assert!(is_mac("00:11:22:33:44:55"));
        assert!(!is_mac("00:11:22:33:44:5"));
        assert!(!is_mac("00-11-22-33-44-55"));
        assert!(!is_mac("cache"));
        assert!(!is_mac("000:11:22:33:44:55"));
    }

    #[test]
    fn classic_info_parses_to_uppercase_key() {
        let kind = parse_info(CLASSIC);
        assert_eq!(
            kind,
            Kind::Classic {
                link_key: "1F2A3B4C5D6E7F8090A1B2C3D4E5F600".into()
            }
        );
    }

    #[test]
    fn ble_info_is_detected() {
        assert_eq!(parse_info(BLE), Kind::Ble);
        assert_eq!(parse_info(EMPTY), Kind::Unknown);
    }

    #[test]
    fn name_comes_from_general_section() {
        assert_eq!(name_from_info(CLASSIC, "AA:00:00:00:00:01"), "Soundcore Motion+");
        assert_eq!(name_from_info("[General]\nClass=0x1\n", "AA:00:00:00:00:01"), "AA:00:00:00:00:01");
        assert_eq!(name_from_info(EMPTY, "AA:00:00:00:00:01"), "Mystery");
    }

    #[test]
    fn scan_reads_fixture_tree() {
        let dir = std::env::temp_dir().join("syncx-test-store");
        let a = dir.join("DC:41:A9:F1:8E:53").join("AA:BB:CC:DD:EE:FF");
        let b = dir.join("DC:41:A9:F1:8E:53").join("11:22:33:44:55:66");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        fs::write(a.join("info"), CLASSIC).unwrap();
        fs::write(b.join("info"), BLE).unwrap();

        let store = scan(&dir).unwrap();
        assert_eq!(store.devices.len(), 2);
        assert_eq!(store.devices[0].name, "Soundcore Motion+");
        assert!(matches!(store.devices[0].kind, Kind::Classic { .. }));
        assert!(matches!(store.devices[1].kind, Kind::Ble));
        assert_eq!(store.syncable().len(), 1);

        fs::remove_dir_all(&dir).unwrap();
    }
}
