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
    result
}

/// Derive a key from `password` and decrypt the folder (mode auto-detected).
/// Returns the number of files restored.
pub fn decrypt(folder: &Path, password: &[u8]) -> Result<usize, String> {
    let salt = vault::read_vault_salt(folder)?;
    let mut key = crypto::derive_key(password, &salt)?;
    let result = vault::decrypt_folder(folder, &key);
    crypto::zero_key(&mut key);
    result
}
