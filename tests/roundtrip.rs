//! Headless round-trip test for the vault format (no GUI involved).
//!
//! Creates a temp folder, populates it with files + subfolders, encrypts,
//! checks that only the protected names remain, then decrypts with the right
//! password (and confirms a wrong password fails).

use std::fs;
use std::path::Path;

use folder_lock::{crypto, vault};

fn build_sample_tree(root: &Path) {
    fs::write(root.join("secret.txt"), "Hello secret content\r\n").unwrap();
    fs::write(root.join("notes.md"), "Another line of data\r\n").unwrap();
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub").join("nested.txt"), "nested file content").unwrap();
    fs::create_dir_all(root.join("a").join("b")).unwrap();
    fs::write(root.join("a").join("b").join("deep.bin"), vec![0u8; 4096]).unwrap();
    fs::create_dir_all(root.join("emptydir")).unwrap(); // empty dir survives
}

#[test]
fn encrypt_then_decrypt_roundtrip() {
    let dir = tempfile_dir();
    build_sample_tree(&dir);

    let password = b"correct horse battery staple";
    let salt = crypto::random_salt();
    let key = crypto::derive_key(password, &salt).unwrap();

    let n = vault::encrypt_folder(&dir, &key, &salt).unwrap();
    assert!(n >= 4, "expected at least 4 files packed, got {}", n);

    // After encryption: original files gone, vault present, exe-named files
    // would be skipped. Here we check no sample files remain.
    assert!(!dir.join("secret.txt").exists(), "secret.txt still present after encrypt");
    assert!(!dir.join("sub").exists(), "sub dir still present after encrypt");
    assert!(dir.join(vault::VAULT_FILE).exists(), "vault file missing");

    // Wrong password must fail.
    let wrong_salt = vault::read_vault_salt(&dir).unwrap();
    let wrong_key = crypto::derive_key(b"totally wrong password", &wrong_salt).unwrap();
    let err = vault::decrypt_folder(&dir, &wrong_key);
    assert!(err.is_err(), "wrong password should fail decryption");

    // Correct password restores everything.
    let right_salt = vault::read_vault_salt(&dir).unwrap();
    let right_key = crypto::derive_key(password, &right_salt).unwrap();
    let restored = vault::decrypt_folder(&dir, &right_key).unwrap();
    assert!(restored >= 4, "expected at least 4 files restored, got {}", restored);

    // Content integrity.
    assert_eq!(fs::read_to_string(dir.join("secret.txt")).unwrap(), "Hello secret content\r\n");
    assert_eq!(
        fs::read_to_string(dir.join("sub").join("nested.txt")).unwrap(),
        "nested file content"
    );
    let deep = fs::read(dir.join("a").join("b").join("deep.bin")).unwrap();
    assert_eq!(deep.len(), 4096);
    assert!(deep.iter().all(|&b| b == 0));
    assert!(dir.join("emptydir").is_dir(), "empty dir should be restored");
    assert!(!dir.join(vault::VAULT_FILE).exists(), "vault should be removed after decrypt");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn key_is_deterministic_for_same_password_and_salt() {
    let salt = [1u8; 16];
    let k1 = crypto::derive_key(b"pw", &salt).unwrap();
    let k2 = crypto::derive_key(b"pw", &salt).unwrap();
    assert_eq!(k1, k2, "same password+salt must derive the same key");

    let k3 = crypto::derive_key(b"PW", &salt).unwrap();
    assert_ne!(k1, k3, "different password must derive a different key");
}

fn tempfile_dir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "flock_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&p).unwrap();
    p
}
