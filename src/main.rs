//! folder_lock — a single-file folder encryption tool with a modern Slint GUI.
//!
//! Drop the built exe into a folder and run it:
//!  - If the folder is NOT locked yet, pick a mode, set a password (twice),
//!    confirm, and every file/subfolder is packed into a hidden vault.
//!  - If the folder IS locked (vault present), enter the password to restore
//!    everything back in place.
//!
//! Security:
//!   * Argon2id key derivation (memory-hard) from the password + random salt.
//!   * AES-256-GCM authenticated encryption of the manifest (and, in full
//!     mode, of every file's contents).
//!   * Secrets are zeroized from memory after use.

#![windows_subsystem = "windows"]
#![allow(unsafe_op_in_unsafe_fn)]

mod logic;

use std::sync::{Arc, Mutex};

use slint::ComponentHandle;

slint::include_modules!();

/// Password + mode kept in memory while a folder is temporarily decrypted, so
/// “再次加密” can re-lock without prompting again. Zeroized on drop.
#[derive(Clone)]
struct Stash {
    pw: Vec<u8>,
    mode: i32,
}

impl Drop for Stash {
    fn drop(&mut self) {
        for b in self.pw.iter_mut() {
            *b = 0;
        }
    }
}

fn main() {
    // The folder the exe lives in (current working directory).
    let folder = match std::env::current_dir() {
        Ok(f) if f.is_dir() => Arc::new(f),
        _ => {
            fatal("程序必须在某个文件夹内运行。");
            return;
        }
    };

    let app = match AppWindow::new() {
        Ok(a) => a,
        Err(e) => {
            fatal(&format!("无法创建窗口：{}", e));
            return;
        }
    };

    // ── initial state ──
    let locked = folder_lock::vault::vault_exists(&folder);
    app.set_folder_path(folder.display().to_string().into());
    app.set_locked(locked);
    if locked {
        app.set_detected_mode(logic::detect_mode_label(&folder).into());
        app.set_message("请输入密码以解锁此文件夹。".into());
    } else {
        app.set_message("选择加密模式并设置密码即可锁定此文件夹。".into());
    }
    app.set_is_error(false);
    app.set_temp_unlocked(false);

    // Credentials stashed during a temporary decrypt (for one-click re-lock).
    let stash: Arc<Mutex<Option<Stash>>> = Arc::new(Mutex::new(None));

    // ── encrypt callback ──
    {
        let folder = folder.clone();
        let weak = app.as_weak();
        app.on_encrypt(move |mode, pw1, pw2| {
            let Some(app) = weak.upgrade() else { return };
            if pw1.is_empty() {
                app.set_message("密码不能为空。".into());
                app.set_is_error(true);
                return;
            }
            if pw1 != pw2 {
                app.set_message("两次输入的密码不一致。".into());
                app.set_is_error(true);
                return;
            }
            app.set_busy(true);
            app.set_message("".into());

            let folder = folder.clone();
            let pw = pw1.to_string();
            let weak2 = weak.clone();
            std::thread::spawn(move || {
                let result = logic::encrypt(&folder, mode, pw.as_bytes());
                let _ = weak2.upgrade_in_event_loop(move |app| {
                    app.set_busy(false);
                    app.set_pw1("".into());
                    app.set_pw2("".into());
                    match result {
                        Ok(n) => {
                            app.set_locked(true);
                            app.set_detected_mode(logic::mode_label(mode).into());
                            app.set_is_error(false);
                            app.set_message(
                                format!("锁定完成，共处理 {} 个文件。", n).into(),
                            );
                        }
                        Err(e) => {
                            app.set_is_error(true);
                            app.set_message(e.into());
                        }
                    }
                });
            });
        });
    }

    // ── decrypt callback ──
    {
        let folder = folder.clone();
        let weak = app.as_weak();
        app.on_decrypt(move |pw| {
            let Some(app) = weak.upgrade() else { return };
            if pw.is_empty() {
                app.set_message("请输入密码。".into());
                app.set_is_error(true);
                return;
            }
            app.set_busy(true);
            app.set_message("".into());

            let folder = folder.clone();
            let pw = pw.to_string();
            let weak2 = weak.clone();
            std::thread::spawn(move || {
                let result = logic::decrypt(&folder, pw.as_bytes());
                let _ = weak2.upgrade_in_event_loop(move |app| {
                    app.set_busy(false);
                    match result {
                        Ok(n) => {
                            app.set_pw1("".into());
                            app.set_locked(false);
                            app.set_is_error(false);
                            app.set_message(
                                format!("解锁完成，共恢复 {} 个文件。", n).into(),
                            );
                        }
                        Err(e) => {
                            app.set_is_error(true);
                            app.set_message(e.into());
                        }
                    }
                });
            });
        });
    }

    // ── temporary-decrypt callback (restore files, keep creds for re-lock) ──
    {
        let folder = folder.clone();
        let weak = app.as_weak();
        let stash = stash.clone();
        app.on_temp_decrypt(move |pw| {
            let Some(app) = weak.upgrade() else { return };
            if pw.is_empty() {
                app.set_message("请输入密码。".into());
                app.set_is_error(true);
                return;
            }
            app.set_busy(true);
            app.set_message("".into());

            let folder = folder.clone();
            let pw = pw.to_string();
            let weak2 = weak.clone();
            let stash = stash.clone();
            std::thread::spawn(move || {
                let mode = logic::detect_mode(&folder).unwrap_or(logic::MODE_MOVE);
                let result = logic::decrypt(&folder, pw.as_bytes());
                let _ = weak2.upgrade_in_event_loop(move |app| {
                    app.set_busy(false);
                    match result {
                        Ok(n) => {
                            *stash.lock().unwrap() =
                                Some(Stash { pw: pw.into_bytes(), mode });
                            app.set_pw1("".into());
                            app.set_locked(false);
                            app.set_temp_unlocked(true);
                            app.set_is_error(false);
                            app.set_message(
                                format!(
                                    "已临时解密，共恢复 {} 个文件。使用完毕后点击“再次加密”即可重新锁定。",
                                    n
                                )
                                .into(),
                            );
                        }
                        Err(e) => {
                            app.set_is_error(true);
                            app.set_message(e.into());
                        }
                    }
                });
            });
        });
    }

    // ── re-encrypt callback (re-lock using stashed creds, no password prompt) ──
    {
        let folder = folder.clone();
        let weak = app.as_weak();
        let stash = stash.clone();
        app.on_re_encrypt(move || {
            let Some(app) = weak.upgrade() else { return };
            let creds = stash.lock().unwrap().clone();
            let Some(creds) = creds else {
                app.set_is_error(true);
                app.set_message("凭据已失效，请重新输入密码解锁。".into());
                return;
            };
            app.set_busy(true);
            app.set_message("".into());

            let folder = folder.clone();
            let weak2 = weak.clone();
            let stash = stash.clone();
            std::thread::spawn(move || {
                let mode = creds.mode;
                let result = logic::encrypt(&folder, mode, &creds.pw);
                let _ = weak2.upgrade_in_event_loop(move |app| {
                    app.set_busy(false);
                    match result {
                        Ok(n) => {
                            *stash.lock().unwrap() = None; // forget the password
                            app.set_temp_unlocked(false);
                            app.set_locked(true);
                            app.set_detected_mode(logic::mode_label(mode).into());
                            app.set_is_error(false);
                            app.set_message(
                                format!("已重新加密，共处理 {} 个文件。", n).into(),
                            );
                        }
                        Err(e) => {
                            // keep creds so the user can retry
                            app.set_is_error(true);
                            app.set_message(e.into());
                        }
                    }
                });
            });
        });
    }

    if let Err(e) = app.run() {
        fatal(&format!("运行出错：{}", e));
    }
}

/// Show a fatal error via a native message box (used before / instead of the
/// Slint window). Kept tiny so we don't drag the old Win32 UI back in.
#[cfg(windows)]
fn fatal(msg: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxW(hwnd: *mut core::ffi::c_void, text: *const u16, caption: *const u16, utype: u32) -> i32;
    }
    let to_wide = |s: &str| -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    };
    let text = to_wide(msg);
    let caption = to_wide("folder_lock 错误");
    const MB_ICONERROR: u32 = 0x0000_0010;
    unsafe {
        MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), MB_ICONERROR);
    }
}

#[cfg(not(windows))]
fn fatal(msg: &str) {
    eprintln!("folder_lock 错误: {}", msg);
}
