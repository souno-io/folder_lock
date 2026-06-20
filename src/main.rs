//! folder_lock — a single-file folder encryption tool.
//!
//! Usage: drop the built exe into a folder and run it.
//!  - If the folder is NOT encrypted yet, it asks for a password twice,
//!    then encrypts every file/subfolder into a single hidden vault file
//!    and deletes the originals. The folder then only shows this exe.
//!  - If the folder IS encrypted (vault present), it asks for the password,
//!    decrypts everything back into the folder, and removes the vault.
//!
//! Security:
//!   * Argon2id key derivation (memory-hard) from the password + random salt.
//!   * AES-256-GCM authenticated encryption (one stream entry per file).
//!   * Salts / nonces are random per vault and per file.
//!   * Secrets are zeroized from memory after use.

#![windows_subsystem = "windows"]
// We write careful FFI wrappers; allow unsafe ops inside unsafe fns to keep the
// wrappers readable (edition-2024 enables this lint by default).
#![allow(unsafe_op_in_unsafe_fn)]

mod ui;
mod app;

fn main() {
    // Run the application logic. Any error is shown to the user via a dialog.
    if let Err(e) = app::run() {
        ui::message_box_error(&format!("folder_lock 错误:\n\n{}", e));
        std::process::exit(1);
    }
}
