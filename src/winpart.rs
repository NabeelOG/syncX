//! Finding the Windows partition from Linux and delivering the payload.
//!
//! Windows leaves obvious fingerprints: an NTFS mount with a `Windows/System32`
//! tree. The payload lands in a user's `Desktop` folder when one exists, so it's
//! waiting there after the next boot into Windows; otherwise the volume root.
//! If the mount is read-only (Windows fast-startup/hibernation makes Linux mount
//! NTFS that way) the caller falls back to `~/Downloads` plus a root copy via
//! `pkexec`.

use std::fs;
use std::path::{Path, PathBuf};

/// An NTFS volume that looks like a Windows installation.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowsVolume {
    /// Mount point, e.g. `/run/media/nabeel/Windows`.
    pub mount: PathBuf,
    /// Where to put the payload files (Desktop if found, else the mount root).
    pub target: PathBuf,
}

/// Filesystem types that can host a Windows system partition.
fn is_windows_fstype(fstype: &str) -> bool {
    matches!(fstype, "ntfs" | "ntfs3" | "ntfs-3g" | "fuseblk")
}

/// Read `/proc/mounts` and return (fstype, mountpoint) pairs for NTFS-ish volumes.
pub fn ntfs_mounts() -> std::io::Result<Vec<(String, String)>> {
    let text = fs::read_to_string("/proc/mounts")?;
    Ok(ntfs_mounts_from(&text))
}

fn ntfs_mounts_from(proc_mounts: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in proc_mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && is_windows_fstype(fields[2]) {
            // /proc/mounts escapes spaces as \040; decode the common ones.
            let mount = fields[1]
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\134", "\\");
            out.push((fields[2].to_string(), mount));
        }
    }
    out
}

/// Case-insensitive child lookup (Windows uses `Windows`, tools sometimes show `windows`).
fn child_ci(parent: &Path, name: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(parent).ok()? {
        let entry = entry.ok()?;
        if entry.file_name().eq_ignore_ascii_case(name) {
            return Some(entry.path());
        }
    }
    None
}

/// Does this mount look like a Windows system volume?
pub fn looks_like_windows(mount: &Path) -> bool {
    let Some(windows) = child_ci(mount, "Windows").or_else(|| child_ci(mount, "WINNT")) else {
        return false;
    };
    let Some(system32) = child_ci(&windows, "System32") else {
        return false;
    };
    let Some(config) = child_ci(&system32, "config") else {
        return false;
    };
    child_ci(&config, "SYSTEM").is_some() || child_ci(&system32, "ntoskrnl.exe").is_some()
}

/// Choose the payload target inside a Windows volume: a real user's Desktop,
/// falling back to the volume root. Skips `Default` profiles and mount points.
fn target_for(mount: &Path) -> WindowsVolume {
    let fallback = WindowsVolume { mount: mount.to_path_buf(), target: mount.to_path_buf() };
    if let Some(users) = child_ci(mount, "Users") {
        if let Ok(entries) = fs::read_dir(&users) {
            let mut desktops: Vec<PathBuf> = Vec::new();
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if matches!(name.as_str(), "Default" | "DefaultAppPool" | "All Users")
                    || name.starts_with('.')
                {
                    continue;
                }
                if let Some(desktop) = child_ci(&entry.path(), "Desktop") {
                    // A mount point (empty dir) shouldn't win over a real Desktop.
                    if is_mount_point(&desktop) {
                        continue;
                    }
                    desktops.push(desktop);
                }
            }
            desktops.sort();
            if let Some(desktop) = desktops.into_iter().next() {
                return WindowsVolume { mount: mount.to_path_buf(), target: desktop };
            }
        }
    }
    fallback
}

/// A Desktop that is actually a mount point (e.g. a user-mounted partition)
/// has no real files of its own to speak of — treat a couple of real files as
/// evidence of a genuine desktop.
fn is_mount_point(dir: &Path) -> bool {
    match fs::read_dir(dir) {
        Ok(mut entries) => entries.next().is_none(),
        Err(_) => true,
    }
}

/// Find Windows volumes among already-filtered mount points.
pub fn find_windows_volumes(mounts: &[(String, String)]) -> Vec<WindowsVolume> {
    let mut found = Vec::new();
    for (_, mount) in mounts {
        let path = PathBuf::from(mount);
        if looks_like_windows(&path) {
            found.push(target_for(&path));
        }
    }
    found
}

/// Deliver both payload files to a target directory.
/// Returns the written paths (ps1 first, then cmd).
pub fn write_payload(dir: &Path, ps1: &str, cmd: &str) -> std::io::Result<Vec<PathBuf>> {
    fs::create_dir_all(dir)?;
    let ps1_path = dir.join("syncx-import.ps1");
    let cmd_path = dir.join("syncx-import.cmd");
    fs::write(&ps1_path, ps1)?;
    fs::write(&cmd_path, cmd)?;
    Ok(vec![ps1_path, cmd_path])
}

/// The user's Downloads directory (or home as a fallback landing spot).
pub fn fallback_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        let downloads = home.join("Downloads");
        if downloads.is_dir() {
            return downloads;
        }
        return home;
    }
    PathBuf::from("/tmp")
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTS: &str = r#"
/dev/nvme0n1p5 /windows ntfs3 rw 0 0
/dev/sda2 /run/media/nabeel/Win11 fuseblk ro 0 0
/dev/sda1 /boot/efi vfat rw 0 0
/dev/sda3 /home ext4 rw 0 0
"#;

    #[test]
    fn mounts_are_filtered_to_ntfs() {
        let m = ntfs_mounts_from(MOUNTS);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].1, "/windows");
        assert_eq!(m[1].1, "/run/media/nabeel/Win11");
    }

    #[test]
    fn escaped_spaces_decode() {
        let m = ntfs_mounts_from("/dev/sda2 /run/media/u/My\\040Disk ntfs3 rw 0 0\n");
        assert_eq!(m[0].1, "/run/media/u/My Disk");
    }

    #[test]
    fn fixture_volume_is_recognised_and_target_chosen() {
        let dir = std::env::temp_dir().join("syncx-test-vol");
        let win = dir.join("Windows");
        fs::create_dir_all(win.join("System32/config")).unwrap();
        fs::write(win.join("System32/config/SYSTEM"), "regf").unwrap();
        let users = dir.join("Users");
        fs::create_dir_all(users.join("nabeel/Desktop")).unwrap();
        fs::create_dir_all(users.join("Default/Desktop")).unwrap();
        fs::write(users.join("nabeel/Desktop/some-file.txt"), "x").unwrap();

        assert!(looks_like_windows(&dir));
        let vols = find_windows_volumes(&[("ntfs3".into(), dir.to_string_lossy().into_owned())]);
        assert_eq!(vols.len(), 1);
        // nabeel's Desktop (has a file), not Default's and not the mount root
        assert_eq!(vols[0].target, users.join("nabeel/Desktop"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn non_windows_mount_is_ignored() {
        let dir = std::env::temp_dir().join("syncx-test-linux");
        fs::create_dir_all(dir.join("home")).unwrap();
        assert!(!looks_like_windows(&dir));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn payload_files_are_written() {
        let dir = std::env::temp_dir().join("syncx-test-write");
        let written = write_payload(&dir, "PS1", "CMD").unwrap();
        assert_eq!(written.len(), 2);
        assert_eq!(fs::read_to_string(dir.join("syncx-import.ps1")).unwrap(), "PS1");
        assert_eq!(fs::read_to_string(dir.join("syncx-import.cmd")).unwrap(), "CMD");
        fs::remove_dir_all(&dir).unwrap();
    }
}
