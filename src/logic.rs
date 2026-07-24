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
        Ok(vault::MODE_FULL) | Ok(vault::MODE_FULL_STREAM) => "完全加密".into(),
        Ok(vault::MODE_SIMPLE) => "简单加密".into(),
        Ok(vault::MODE_MOVE) => "极速锁定".into(),
        _ => "未知".into(),
    }
}

/// Numeric mode of an existing vault, so “再次加密” can re-lock with the same
/// mode without asking the user again. Maps the on-disk vault mode onto the
/// UI ComboBox index (both streamed and legacy full map to “完全加密”).
pub fn detect_mode(folder: &Path) -> Option<i32> {
    vault::read_vault_mode(folder).ok().map(|m| match m {
        vault::MODE_FULL | vault::MODE_FULL_STREAM => MODE_FULL,
        vault::MODE_SIMPLE => MODE_SIMPLE,
        vault::MODE_MOVE => MODE_MOVE,
        _ => MODE_MOVE,
    })
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
/// Returns the number of files processed. `progress` is called with
/// `(done, total)` after each file so a GUI can drive a progress bar (the
/// instant move-lock mode does not report per-file progress).
pub fn encrypt(
    folder: &Path,
    mode: i32,
    password: &[u8],
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
    if !has_packable_content(folder) {
        return Err("当前文件夹没有可加密的文件。".into());
    }
    let salt = crypto::random_salt();
    let mut key = crypto::derive_key(password, &salt)?;
    let result = match mode {
        MODE_FULL => vault::encrypt_folder_with_progress(folder, &key, &salt, progress),
        MODE_SIMPLE => vault::encrypt_folder_simple_with_progress(folder, &key, &salt, progress),
        _ => vault::encrypt_folder_move_with_progress(folder, &key, &salt, progress),
    };
    crypto::zero_key(&mut key);
    if result.is_ok() {
        // Give the locked folder the app's own icon in Explorer.
        set_folder_icon(folder);
    }
    result
}

/// Derive a key from `password` and decrypt the folder (mode auto-detected).
/// Returns the number of files restored. `progress` is called with
/// `(done, total)` after each entry so a GUI can drive a progress bar (the
/// instant move-lock mode does not report per-entry progress).
pub fn decrypt(
    folder: &Path,
    password: &[u8],
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
    let salt = vault::read_vault_salt(folder)?;
    let mut key = crypto::derive_key(password, &salt)?;
    let result = vault::decrypt_folder_with_progress(folder, &key, progress);
    crypto::zero_key(&mut key);
    if result.is_ok() {
        // Restore the folder's default Explorer icon.
        clear_folder_icon(folder);
    }
    result
}

// ─────────────────────────────────────── resume (crash recovery) ──

/// Direction of an unfinished operation left in the folder, if any. Drives the
/// "resume" prompt shown on startup.
pub fn pending_op(folder: &Path) -> Option<vault::PendingOp> {
    vault::read_pending(folder)
}

/// Resume an operation interrupted by a crash/kill/power-loss. Reads the
/// direction from `.flockstate`, derives the key from `password` (validated
/// against the vault via GCM), finishes the operation from where it stopped,
/// and fixes up the folder icon. Returns `(direction, files_processed)`.
pub fn resume(
    folder: &Path,
    password: &[u8],
    progress: &dyn Fn(usize, usize),
) -> Result<(vault::PendingOp, usize), String> {
    let op = vault::read_pending(folder).ok_or("没有检测到未完成的操作。")?;
    let salt = vault::read_vault_salt(folder)?;
    let mut key = crypto::derive_key(password, &salt)?;
    let result = match op {
        vault::PendingOp::Encrypt => vault::resume_encrypt(folder, &key, progress),
        vault::PendingOp::Decrypt => vault::decrypt_folder_with_progress(folder, &key, progress),
    };
    crypto::zero_key(&mut key);
    let n = result?;
    match op {
        vault::PendingOp::Encrypt => set_folder_icon(folder),
        vault::PendingOp::Decrypt => clear_folder_icon(folder),
    }
    Ok((op, n))
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

/// Ask Explorer to refresh the folder icon so the change shows immediately.
///
/// The folder's icon is drawn by its *parent* view, so notifying only the
/// folder's own contents (SHCNE_UPDATEDIR on itself) is not enough. We flag the
/// folder as a changed item (SHCNE_UPDATEITEM) and refresh the parent listing
/// (SHCNE_UPDATEDIR). On Windows 10/11 the per-folder icon is cached hard, so a
/// targeted notify is frequently ignored; we finish with SHCNE_ASSOCCHANGED,
/// which flushes the shell icon cache and forces Explorer to re-read
/// desktop.ini. All calls flush so they take effect right away.
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
    const SHCNE_UPDATEITEM: i32 = 0x0000_2000;
    const SHCNE_ASSOCCHANGED: i32 = 0x0800_0000;
    const SHCNF_IDLIST: u32 = 0x0000;
    const SHCNF_PATHW: u32 = 0x0005;
    const SHCNF_FLUSH: u32 = 0x1000;

    let to_wide = |p: &Path| -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    };

    // The folder itself changed (its icon).
    let w_folder = to_wide(folder);
    unsafe {
        SHChangeNotify(
            SHCNE_UPDATEITEM,
            SHCNF_PATHW | SHCNF_FLUSH,
            w_folder.as_ptr() as *const core::ffi::c_void,
            std::ptr::null(),
        );
    }
    // The parent listing (where the folder's icon is actually drawn).
    if let Some(parent) = folder.parent() {
        let w_parent = to_wide(parent);
        unsafe {
            SHChangeNotify(
                SHCNE_UPDATEDIR,
                SHCNF_PATHW | SHCNF_FLUSH,
                w_parent.as_ptr() as *const core::ffi::c_void,
                std::ptr::null(),
            );
        }
    }
    // Flush the global shell icon cache. Windows 10/11 caches folder icons hard
    // and ignores targeted notifications for an already-rendered folder; this is
    // the reliable way to make the new (or restored) icon appear at once.
    unsafe {
        SHChangeNotify(
            SHCNE_ASSOCCHANGED,
            SHCNF_IDLIST | SHCNF_FLUSH,
            std::ptr::null(),
            std::ptr::null(),
        );
    }
}

#[cfg(not(windows))]
pub fn set_folder_icon(_folder: &Path) {}

#[cfg(not(windows))]
pub fn clear_folder_icon(_folder: &Path) {}
