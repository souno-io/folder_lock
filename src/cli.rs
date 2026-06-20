//! Headless command-line helper (console subsystem) for scripting/testing.
//!
//! Usage:
//!   flock_cli encrypt <password>      encrypt the current folder in place (full mode)
//!   flock_cli encrypt-simple <password> encrypt using ADS simple mode (fast, no encryption)
//!   flock_cli decrypt <password>      decrypt the current folder in place
//!   flock_cli status                  report whether the folder is locked

use std::path::PathBuf;

use folder_lock::{crypto, vault};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(2);
    }
    let folder = std::env::current_dir().expect("cwd");
    let cmd = args[1].as_str();

    let result = match cmd {
        "status" => cmd_status(&folder),
        "encrypt" => cmd_encrypt(&folder, args.get(2)),
        "encrypt-simple" => cmd_encrypt_simple(&folder, args.get(2)),
        "decrypt" => cmd_decrypt(&folder, args.get(2)),
        _ => {
            eprintln!("unknown command: {}", cmd);
            usage();
            std::process::exit(2);
        }
    };

    match result {
        Ok(msg) => {
            println!("{}", msg);
        }
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}

fn usage() {
    eprintln!("usage: flock_cli <status|encrypt <pw>|encrypt-simple <pw>|decrypt <pw>>");
}

fn cmd_status(folder: &PathBuf) -> Result<String, String> {
    if vault::vault_exists(folder) {
        Ok("locked (encrypted vault present)".into())
    } else {
        Ok("unlocked (no vault present)".into())
    }
}

fn cmd_encrypt(folder: &PathBuf, pw: Option<&String>) -> Result<String, String> {
    let pw = pw.ok_or("missing password argument")?;
    let salt = crypto::random_salt();
    let mut key = crypto::derive_key(pw.as_bytes(), &salt)?;
    let n = vault::encrypt_folder(folder, &key, &salt)?;
    crypto::zero_key(&mut key);
    Ok(format!("encrypted {} file(s) (full mode)", n))
}

fn cmd_encrypt_simple(folder: &PathBuf, pw: Option<&String>) -> Result<String, String> {
    let pw = pw.ok_or("missing password argument")?;
    let salt = crypto::random_salt();
    let mut key = crypto::derive_key(pw.as_bytes(), &salt)?;
    let n = vault::encrypt_folder_simple(folder, &key, &salt)?;
    crypto::zero_key(&mut key);
    Ok(format!("encrypted {} file(s) (simple ADS mode)", n))
}

fn cmd_decrypt(folder: &PathBuf, pw: Option<&String>) -> Result<String, String> {
    let pw = pw.ok_or("missing password argument")?;
    let salt = vault::read_vault_salt(folder)?;
    let mut key = crypto::derive_key(pw.as_bytes(), &salt)?;
    let n = vault::decrypt_folder(folder, &key)?;
    crypto::zero_key(&mut key);
    Ok(format!("decrypted {} file(s)", n))
}
