# sYncX

Bluetooth pairing sync for dual-boot Linux + Windows, built with
[Rune](https://github.com/anomalyco/rune) — Anomaly's native GPU-rendered Rust UI framework.

**The problem:** a Bluetooth device paired on one OS doesn't work on the other.
Each OS generates its own link key during pairing, and the device only remembers
the *last* one — so every switch means re-pairing, which breaks the other OS
again.

**The fix:** make both OSes store the *same* key. Pair once on Linux, let sYncX
copy the key into Windows' registry, and the device pairs on both forever — no
app needed afterwards, until you re-pair the device someday.

## How it works

1. **On Linux**, sYncX reads the pairing keys from BlueZ's store
   (`/var/lib/bluetooth`, via `pkexec` when not running as root).
2. Press **Create Windows import**. sYncX generates a self-contained
   `syncx-import.ps1` + `syncx-import.cmd` and writes them to a detected Windows
   partition (the user's Desktop when found), or to `~/Downloads` if the
   partition is read-only or not mounted.
3. **Boot Windows** and double-click `syncx-import.cmd`. The script asks for UAC,
   runs a one-shot scheduled task **as SYSTEM** (the pairing-key tree in
   `HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys` is
   SYSTEM-only), writes the keys as REG_BINARY values named by device MAC
   (classic BR/EDR keys copy byte-for-byte, no reversal), restarts the Bluetooth
   support service, and reports the result.

Done. Both OSes now share the pairing.

## Build

Requires [Rust](https://rustup.rs) (stable).

```sh
cargo build --release
# binary: target/release/syncx
```

## Tech stack

- **[Rune](https://github.com/anomalyco/rune)** — the UI framework: a native,
  GPU-rendered Rust framework (its own renderer, text engine and layout) that
  compiles to a single small binary on macOS, Windows, Linux and the web. sYncX
  is a GUI on Linux today; the same codebase can build a Windows-side GUI later.
- **Rust** + `serde_json` for the payload format and the BlueZ-store export.
- **PowerShell** for the Windows-side import (built into Windows, so the sync
  needs no app installed there).
- Registry layout for Windows pairing keys was verified against
  [bt-dualboot](https://github.com/x2es/bt-dualboot)'s implementation.

Rune is pre-release, so it's pinned to a rev of
[anomalyco/rune](https://github.com/anomalyco/rune). Its vendored `winit`,
`wgpu-hal`, `parley_engine` and `accesskit_windows` patches are applied in this
repo too (a dependency's `[patch]` doesn't cross workspaces).

## Usage

```sh
./target/release/syncx            # the app
syncx --export                    # print the pairing store as JSON (needs root)
syncx --place <ps1> <cmd> <dir>   # copy the payload as root (the app uses this
                                  # when the Windows partition is not user-writable)
syncx --sample [file]             # write an example import script to inspect
```

## Notes and limits

- **Only classic (BR/EDR) devices sync.** BLE pairings need LTK/IRK/CSRK sets
  stored differently per OS; sYncX shows them as "can't sync" rather than
  half-copying and breaking the device. Most speakers and headphones pair
  classic when you pair them from the OS Bluetooth settings.
- **Windows fast startup makes NTFS read-only from Linux** (Windows hibernated).
  sYncX detects that, saves the payload to `~/Downloads` instead, and tells you
  to copy it over — or tries a root copy via `pkexec` first.
- **BitLocker** doesn't block this flow: with BitLocker the Windows partition
  won't mount on Linux at all, so sYncX saves the payload to `~/Downloads`
  instead and you copy it over with a USB stick.
- **Re-pairing breaks the sync again** — the device gets a fresh key. Just run
  the same flow again afterwards.
- **Windows → Linux direction** (pair on Windows first, import into BlueZ) is
  not implemented yet; pair on Linux and sync to Windows for now.
- If the device still doesn't connect after the import on Windows, reboot —
  some Bluetooth stacks only re-read keys at boot.

## Project layout

- `src/bt.rs` — BlueZ store scanning and `info` file parsing
- `src/payload.rs` — payload JSON, base64, and the PowerShell script generator
- `src/winpart.rs` — Windows partition discovery and payload delivery
- `src/ui.rs` — the Rune UI and the background worker
- `src/main.rs` — CLI dispatch

## License

MIT
