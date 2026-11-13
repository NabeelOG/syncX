//! The Windows import payload: a self-contained PowerShell script that copies
//! classic link keys into Windows' registry.
//!
//! How Windows stores classic (BR/EDR) pairing keys:
//!
//! ```text
//! HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys\<adapter>
//! ```
//!
//! For a classic device, the device is not a subkey: it is a **REG_BINARY value
//! whose name is the device MAC without colons**, directly under the adapter
//! subkey (BLE devices, in contrast, get a subkey with LTK/IRK/CSRK values).
//! The key bytes copy from BlueZ's `[LinkKey] Key=` byte for byte — no reversal.
//!
//! The value tree is readable/writable only by SYSTEM (not plain Administrators),
//! so the script self-elevates: admin first (`RunAs`), then to SYSTEM through a
//! one-shot scheduled task, which needs no external tools.

use serde::Serialize;

use crate::bt::{Device, Kind};

/// The devices going into one payload, in the JSON shape the script decodes.
#[derive(Debug, Serialize)]
pub struct Payload {
    pub v: u32,
    pub adapter: String,
    pub devices: Vec<DeviceEntry>,
}

#[derive(Debug, Serialize)]
pub struct DeviceEntry {
    pub mac: String,
    pub name: String,
    pub key: String,
}

impl Payload {
    /// Build a payload from scanned devices; only classic devices with keys go in.
    pub fn from_devices(adapter: &str, devices: &[Device]) -> Option<Payload> {
        let entries: Vec<DeviceEntry> = devices
            .iter()
            .filter_map(|d| match &d.kind {
                Kind::Classic { link_key } => Some(DeviceEntry {
                    mac: d.mac.clone(),
                    name: d.name.clone(),
                    key: link_key.clone(),
                }),
                _ => None,
            })
            .collect();
        if entries.is_empty() {
            return None;
        }
        Some(Payload {
            v: 1,
            adapter: adapter.to_string(),
            devices: entries,
        })
    }
}

/// Minimal base64 (standard alphabet with padding) — the payload embeds its JSON
/// as base64 so no quoting rules inside the script can corrupt it.
pub fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Strip colons and lowercase a MAC the way Windows names the values.
/// (The script does this at runtime; kept here as the single documented form.)
#[allow(dead_code)]
pub fn mac_no_colons(mac: &str) -> String {
    mac.replace(':', "").to_lowercase()
}

/// The script the user runs on Windows. `data_b64` carries the JSON payload.
///
/// A placeholder keeps this a plain string: PowerShell braces don't need escaping.
pub fn render_import_ps1(data_b64: &str) -> String {
    SCRIPT.replace("__SYNCX_DATA__", data_b64)
}

const SCRIPT: &str = r#"# sYncX - Bluetooth pairing import for Windows
# Generated on Linux by sYncX. Run once; after it finishes this device pairs on
# both Windows and Linux without re-pairing.
#
# What it does:
#   1. asks for Administrator approval (UAC)
#   2. runs a one-shot scheduled task as SYSTEM (the pairing key tree is SYSTEM-only)
#   3. writes the link keys under HKLM\SYSTEM\...\BTHPORT\Parameters\Keys
#   4. restarts the Bluetooth support service
#
# Nothing is installed, and no pairing happens - this only copies keys.

param([switch]$AsSystem)

$ErrorActionPreference = 'Stop'

# --- pairing data, generated on Linux (base64 of JSON) ----------------------
$DataB64 = @'
__SYNCX_DATA__
'@
# ----------------------------------------------------------------------------

$ResultPath = Join-Path $env:ProgramData 'SyncX\import-result.json'
$TaskName   = 'SyncX_Import'

function Decode-Data {
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($DataB64)) | ConvertFrom-Json
}

function Write-Result($obj) {
    $dir = Split-Path $ResultPath
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $obj | ConvertTo-Json -Depth 5 | Set-Content -Path $ResultPath -Encoding UTF8
}

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Do-Import {
    $data = Decode-Data
    $keysRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys'
    if (!(Test-Path $keysRoot)) { throw "Bluetooth keys path not found: $keysRoot" }

    $adapter = ($data.adapter -replace ':', '').ToLower()
    $adapters = @(Get-ChildItem $keysRoot -ErrorAction SilentlyContinue)
    $adapterPath = $null
    foreach ($a in $adapters) {
        if ($a.PSChildName.ToLower() -eq $adapter) { $adapterPath = $a.PSPath; break }
    }
    if (-not $adapterPath) {
        if ($adapters.Count -gt 0) { $adapterPath = $adapters[0].PSPath }
        else { $adapterPath = (New-Item -Path (Join-Path $keysRoot $adapter) -Force).PSPath }
    }

    $written = @()
    foreach ($d in $data.devices) {
        $valueName = ($d.mac -replace ':', '').ToLower()
        $bytes = for ($i = 0; $i -lt $d.key.Length; $i += 2) { [Convert]::ToByte($d.key.Substring($i, 2), 16) }
        New-ItemProperty -Path $adapterPath -Name $valueName -Value ([byte[]]$bytes) -PropertyType Binary -Force | Out-Null
        $written += $d.mac
    }

    $svc = ''
    try {
        Restart-Service -Name bthserv -Force -ErrorAction Stop
        $svc = 'restarted bthserv'
    } catch {
        $svc = 'could not restart bthserv; reboot Windows to apply'
    }

    @{ ok = $true; written = $written; service = $svc }
}

if ($AsSystem) {
    try   { Write-Result (Do-Import) }
    catch { Write-Result @{ ok = $false; error = $_.Exception.Message } }
    exit 0
}

if (!(Test-Admin)) {
    try {
        Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"") -Wait
    } catch {
        '{"ok":false,"error":"the UAC prompt was declined or failed"}'
        Read-Host 'Press Enter to close'
        exit 1
    }
    if (Test-Path $ResultPath) {
        Get-Content $ResultPath -Raw
        Remove-Item $ResultPath -Force
    } else {
        '{"ok":false,"error":"no result - UAC was cancelled or the elevated step failed"}'
    }
    exit 0
}

if (Test-Path $ResultPath) { Remove-Item $ResultPath -Force }
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -AsSystem"
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Force | Out-Null
try {
    Start-ScheduledTask -TaskName $TaskName
    $deadline = (Get-Date).AddSeconds(90)
    do {
        Start-Sleep -Milliseconds 500
        $state = (Get-ScheduledTask -TaskName $TaskName).State
    } until ($state -ne 'Running' -or (Get-Date) -gt $deadline)
} finally {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

if (Test-Path $ResultPath) {
    Get-Content $ResultPath -Raw
    Remove-Item $ResultPath -Force
} else {
    '{"ok":false,"error":"the SYSTEM task produced no result"}'
}

Write-Host ''
Read-Host 'Done. Press Enter to close'
"#;

/// The one-click wrapper: double-click this on Windows and the script runs with
/// execution policy bypassed, no console fiddling required.
pub fn render_import_cmd() -> String {
    "@echo off\nrem sYncX - Bluetooth pairing import. This runs syncx-import.ps1 next to it.\npowershell -NoProfile -ExecutionPolicy Bypass -File \"%~dp0syncx-import.ps1\"\n".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bt::{Device, Kind};

    fn classic_device() -> Device {
        Device {
            adapter: "DC:41:A9:F1:8E:53".into(),
            mac: "AA:BB:CC:DD:EE:FF".into(),
            name: "Soundcore Motion+".into(),
            kind: Kind::Classic { link_key: "1F2A3B4C5D6E7F8090A1B2C3D4E5F600".into() },
        }
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"\x00\xff"), "AP8=");
    }

    #[test]
    fn macs_lose_their_colons() {
        assert_eq!(mac_no_colons("AA:BB:0C:DD:EE:FF"), "aabb0cddeeff");
    }

    #[test]
    fn payload_takes_only_classic_devices() {
        let ble = Device {
            adapter: "DC:41:A9:F1:8E:53".into(),
            mac: "11:22:33:44:55:66".into(),
            name: "WH-1000XM5".into(),
            kind: Kind::Ble,
        };
        let devices = vec![classic_device(), ble.clone()];
        let p = Payload::from_devices("DC:41:A9:F1:8E:53", &devices).unwrap();
        assert_eq!(p.devices.len(), 1);
        assert_eq!(p.devices[0].key, "1F2A3B4C5D6E7F8090A1B2C3D4E5F600");

        let ble_only = vec![ble];
        assert!(Payload::from_devices("DC:41:A9:F1:8E:53", &ble_only).is_none());
    }

    #[test]
    fn script_carries_the_data_and_the_right_registry_shape() {
        let devices = vec![classic_device()];
        let p = Payload::from_devices("DC:41:A9:F1:8E:53", &devices).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let script = render_import_ps1(&base64(json.as_bytes()));

        // the data block is present and no placeholder remains
        assert!(script.contains("$DataB64 = @'"));
        assert!(!script.contains("__SYNCX_DATA__"));
        // the registry path is the BTHPORT keys tree under CurrentControlSet
        assert!(script.contains("SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys"));
        // SYSTEM elevation via scheduled task, admin elevation via RunAs
        assert!(script.contains("ScheduledTaskPrincipal -UserId 'SYSTEM'"));
        assert!(script.contains("-Verb RunAs"));
        // binary values, one per device MAC without colons (name comes from JSON at runtime)
        assert!(script.contains("PropertyType Binary"));
        // service restart attempt with a reboot fallback
        assert!(script.contains("Restart-Service -Name bthserv"));

        // the base64 block round-trips back to the JSON payload
        let start = script.find("@'\n").unwrap() + 3;
        let end = script[start..].find("\n'@").unwrap() + start;
        let decoded = decode_base64(&script[start..end]);
        let round: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(round["adapter"], "DC:41:A9:F1:8E:53");
        assert_eq!(round["devices"][0]["key"], "1F2A3B4C5D6E7F8090A1B2C3D4E5F600");
        assert_eq!(round["devices"][0]["mac"], "AA:BB:CC:DD:EE:FF");
        assert_eq!(round["devices"][0]["name"], "Soundcore Motion+");
    }

    /// Test-only base64 decoder (mirrors `base64`).
    fn decode_base64(s: &str) -> Vec<u8> {
        let mut table = [255u8; 256];
        for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
            table[*c as usize] = i as u8;
        }
        let mut out = Vec::new();
        let mut n = 0u32;
        let mut bits = 0u32;
        for c in s.bytes() {
            if c == b'=' { break; }
            n = (n << 6) | table[c as usize] as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((n >> bits) as u8);
            }
        }
        out
    }
}
