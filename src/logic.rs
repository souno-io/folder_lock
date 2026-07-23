//! Headless application logic used by the GUI callbacks.
//!
//! All Win32 UI is gone; the GUI lives in `ui/app.slint` and is wired up in
//! `main.rs`. This module only exposes pure functions that map a mode + a
//! password onto the vault encrypt/decrypt primitives.

use std::path::Path;

use folder_lock::{crypto, vault};

/// Mode indices, matching the ComboBox order in `ui/app.slint`.
pub const MODE_FULL: i32 = 0;
pub const MODE_SIMPLE: i32 = 1;
pub const MODE_MOVE: i32 = 2;

/// Human-readable label for a mode index.
pub fn mode_label(mode: i32) -> &'static str {
    match mode {
        MODE_FULL => "完全加密",
        MODE_SIMPLE => "简单加密",
        MODE_MOVE => "极速锁定",
        _ => "极速锁定",
    }
}

/// Label for the mode stored in an existing vault (used when decrypting).
pub fn detect_mode_label(folder: &Path) -> String {
    match vault::read_vault_mode(folder) {
        Ok(vault::MODE_FULL) => "完全加密".into(),
        Ok(vault::MODE_SIMPLE) => "简单加密".into(),
        Ok(vault::MODE_MOVE) => "极速锁定".into(),
        _ => "未知".into(),
    }
}

/// Numeric mode of an existing vault, so “再次加密” can re-lock with the same
/// mode without asking the user again.
pub fn detect_mode(folder: &Path) -> Option<i32> {
    vault::read_vault_mode(folder).ok().map(|m| m as i32)
}

/// Is there at least one non-protected file/dir in the folder?
pub fn has_packable_content(folder: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(folder) else {
        return false;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        if vault::is_protected_name(&name.to_string_lossy()) {
            continue;
        }
        return true;
    }
    false
}

/// Derive a key from `password` and encrypt the folder using the chosen mode.
/// Returns the number of files processed.
pub fn encrypt(folder: &Path, mode: i32, password: &[u8]) -> Result<usize, String> {
    if !has_packable_content(folder) {
        return Err("当前文件夹没有可加密的文件。".into());
    }
    let salt = crypto::random_salt();
    let mut key = crypto::derive_key(password, &salt)?;
    let result = match mode {
        MODE_FULL => vault::encrypt_folder(folder, &key, &salt),
        MODE_SIMPLE => vault::encrypt_folder_simple(folder, &key, &salt),
        _ => vault::encrypt_folder_move(folder, &key, &salt),
    };
    crypto::zero_key(&mut key);
    if result.is_ok() {
        // Give the locked folder the app's own icon in Explorer.
        set_folder_icon(folder);
    }
    result
}

/// Derive a key from `password` and decrypt the folder (mode auto-detected).
/// Returns the number of files restored.
pub fn decrypt(folder: &Path, password: &[u8]) -> Result<usize, String> {
    let salt = vault::read_vault_salt(folder)?;
    let mut key = crypto::derive_key(password, &salt)?;
    let result = vault::decrypt_folder(folder, &key);
    crypto::zero_key(&mut key);
    if result.is_ok() {
        // Restore the folder's default Explorer icon.
        clear_folder_icon(folder);
    }
    result
}

// ─────────────────────────────────────── Windows folder icon ──
// A locked folder is given the app's icon via a hidden desktop.ini. The
// folder is marked read-only (the flag Explorer reads as "this folder is
// customized"); the ini itself is hidden + system. Everything is best-effort:
// icon styling must never fail a lock/unlock operation.

/// Point the folder's Explorer icon at the running exe (locked look).
#[cfg(windows)]
pub fn set_folder_icon(folder: &Path) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let ini = folder.join("desktop.ini");
    // Clear attributes first so we can overwrite an existing ini.
    run_attrib(&ini, &["-s", "-h", "-r"]);
    let content = format!(
        "[.ShellClassInfo]\r\nIconResource={},0\r\nConfirmFileOp=0\r\n",
        exe.display()
    );
    if std::fs::write(&ini, content).is_err() {
        return;
    }
    run_attrib(&ini, &["+s", "+h"]);
    run_attrib(folder, &["+r"]);
    notify_shell(folder);
}

/// Restore the folder's default Explorer icon (unlocked look).
#[cfg(windows)]
pub fn clear_folder_icon(folder: &Path) {
    let ini = folder.join("desktop.ini");
    run_attrib(&ini, &["-s", "-h", "-r"]);
    let _ = std::fs::remove_file(&ini);
    run_attrib(folder, &["-r"]);
    notify_shell(folder);
}

#[cfg(windows)]
fn run_attrib(path: &Path, flags: &[&str]) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = std::process::Command::new("attrib");
    cmd.args(flags);
    cmd.arg(path.as_os_str());
    cmd.creation_flags(CREATE_NO_WINDOW);
    let _ = cmd.output();
}

/// Ask Explorer to refresh the folder so the icon change shows immediately.
#[cfg(windows)]
fn notify_shell(folder: &Path) {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHChangeNotify(
            event: i32,
            flags: u32,
            item1: *const core::ffi::c_void,
            item2: *const core::ffi::c_void,
        );
    }
    const SHCNE_UPDATEDIR: i32 = 0x0000_1000;
    const SHCNF_PATHW: u32 = 0x0005;
    let wide: Vec<u16> = folder
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        SHChangeNotify(
            SHCNE_UPDATEDIR,
            SHCNF_PATHW,
            wide.as_ptr() as *const core::ffi::c_void,
            std::ptr::null(),
        );
    }
}

#[cfg(not(windows))]
pub fn set_folder_icon(_folder: &Path) {}

#[cfg(not(windows))]
pub fn clear_folder_icon(_folder: &Path) {}
