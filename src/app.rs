//! Application flow: decide encrypt vs decrypt based on vault presence.

use std::path::PathBuf;

use folder_lock::crypto;
use folder_lock::vault;
use crate::ui::{self, DialogResult, DialogMode, EncryptMode};

/// Entry point. Determines whether to encrypt or decrypt.
pub fn run() -> Result<(), String> {
    let folder = current_folder()?;
    ensure_is_real_folder(&folder)?;

    if vault::vault_exists(&folder) {
        do_decrypt(&folder)
    } else {
        do_encrypt(&folder)
    }
}

/// The folder the exe lives in (current directory).
fn current_folder() -> Result<PathBuf, String> {
    std::env::current_dir().map_err(|e| format!("无法获取当前目录: {}", e))
}

fn ensure_is_real_folder(folder: &PathBuf) -> Result<(), String> {
    if !folder.is_dir() {
        return Err("程序必须在某个文件夹内运行。".into());
    }
    Ok(())
}

fn do_encrypt(folder: &PathBuf) -> Result<(), String> {
    // Warn if the folder appears empty (nothing to protect).
    if !has_packable_content(folder) {
        ui::message_box_info("当前文件夹没有可加密的文件。");
        return Ok(());
    }

    // Ask which encryption mode to use.
    let encrypt_mode = match ui::encrypt_mode_dialog() {
        Some(m) => m,
        None => return Ok(()), // cancelled
    };

    // Ask for a password, twice (confirmation).
    let pw1 = match prompt(DialogMode::SetPassword, "加密文件夹", "请设置密码（请牢记）：") {
        DialogResult::Ok {
            password, confirm, ..
        } => {
            let confirm = confirm.unwrap_or_default();
            if password.is_empty() {
                ui::message_box_error("密码不能为空。");
                return Ok(());
            }
            if !crypto::passwords_match(password.as_bytes(), confirm.as_bytes()) {
                ui::message_box_error("两次输入的密码不一致，已取消。");
                return Ok(());
            }
            password
        }
        DialogResult::Cancel => return Ok(()),
    };

    let mode_desc = match encrypt_mode {
        EncryptMode::Full => "完全加密",
        EncryptMode::Simple => "简单加密",
    };
    let extra_warn = if let EncryptMode::Simple = encrypt_mode {
        "\n\n注意：简单加密模式利用 NTFS ADS 隐藏文件，速度极快，\n但文件内容未加密，安全性低于完全加密模式。"
    } else {
        ""
    };

    if !ui::message_box_yesno(
        &format!("即将使用「{}」加密当前文件夹下的所有文件和子文件夹。{}\n\n原始文件将被删除，仅保留此程序和加密数据。\n请务必牢记密码，丢失密码将无法恢复！\n\n是否继续？", mode_desc, extra_warn),
        "确认加密",
    ) {
        return Ok(());
    }

    let salt = crypto::random_salt();
    let mut key = crypto::derive_key(pw1.as_bytes(), &salt)?;
    let result = match encrypt_mode {
        EncryptMode::Full => vault::encrypt_folder(folder, &key, &salt),
        EncryptMode::Simple => vault::encrypt_folder_simple(folder, &key, &salt),
    };
    crypto::zero_key(&mut key);
    match result {
        Ok(0) => ui::message_box_info("没有可加密的内容。"),
        Ok(n) => ui::message_box_info(&format!("{}完成。\n共加密 {} 个文件。\n\n现在此文件夹已被锁定。", mode_desc, n)),
        Err(e) => {
            ui::message_box_error(&format!("加密过程中出错:\n{}", e));
            return Err(e);
        }
    }
    Ok(())
}

fn do_decrypt(folder: &PathBuf) -> Result<(), String> {
    // Read the salt from the vault so we can derive the correct key.
    let salt = vault::read_vault_salt(folder)?;

    loop {
        let pw = match prompt(DialogMode::AskPassword, "解密文件夹", "请输入密码以解密：") {
            DialogResult::Ok { password, .. } => password,
            DialogResult::Cancel => return Ok(()),
        };

        let mut key = crypto::derive_key(pw.as_bytes(), &salt)?;
        let result = vault::decrypt_folder(folder, &key);
        crypto::zero_key(&mut key);

        match result {
            Ok(n) => {
                ui::message_box_info(&format!("解密完成。\n共恢复 {} 个文件。", n));
                return Ok(());
            }
            Err(e) => {
                // Likely wrong password (GCM tag failure). Offer retry.
                if e.contains("密码错误") {
                    let retry = ui::message_box_yesno("密码错误，是否重新输入？", "解密失败");
                    if retry {
                        continue;
                    } else {
                        return Ok(());
                    }
                } else {
                    ui::message_box_error(&format!("解密过程中出错:\n{}", e));
                    return Err(e);
                }
            }
        }
    }
}

/// Convenience wrapper around the UI password dialog.
fn prompt(mode: DialogMode, title: &str, label: &str) -> DialogResult {
    ui::password_dialog(mode, title, label)
}

/// Is there at least one non-protected file/dir in the folder?
fn has_packable_content(folder: &PathBuf) -> bool {
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
