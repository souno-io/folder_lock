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
fn move_lock_roundtrip() {
    let dir = tempfile_dir();
    build_sample_tree(&dir);

    let password = b"instant lock please";
    let salt = crypto::random_salt();
    let key = crypto::derive_key(password, &salt).unwrap();

    let n = vault::encrypt_folder_move(&dir, &key, &salt).unwrap();
    assert!(n >= 4, "expected at least 4 files moved, got {}", n);

    // Originals gone, vault present. (The hidden container may be ACL-denied
    // here, so we don't stat it while locked — accessibility varies by env.)
    assert!(!dir.join("secret.txt").exists(), "secret.txt still present after move-lock");
    assert!(!dir.join("sub").exists(), "sub dir still present after move-lock");
    assert!(dir.join(vault::VAULT_FILE).exists(), "vault file missing");

    // Wrong password must fail (manifest is still AES-GCM protected).
    let wrong_salt = vault::read_vault_salt(&dir).unwrap();
    let wrong_key = crypto::derive_key(b"nope", &wrong_salt).unwrap();
    assert!(vault::decrypt_folder(&dir, &wrong_key).is_err(), "wrong password should fail");

    // Correct password restores everything.
    let right_salt = vault::read_vault_salt(&dir).unwrap();
    let right_key = crypto::derive_key(password, &right_salt).unwrap();
    let restored = vault::decrypt_folder(&dir, &right_key).unwrap();
    assert!(restored >= 4, "expected at least 4 files restored, got {}", restored);

    // Content integrity + cleanup.
    assert_eq!(fs::read_to_string(dir.join("secret.txt")).unwrap(), "Hello secret content\r\n");
    assert_eq!(
        fs::read_to_string(dir.join("sub").join("nested.txt")).unwrap(),
        "nested file content"
    );
    let deep = fs::read(dir.join("a").join("b").join("deep.bin")).unwrap();
    assert_eq!(deep.len(), 4096);
    assert!(dir.join("emptydir").is_dir(), "empty dir should be restored");
    assert!(!dir.join(vault::VAULT_FILE).exists(), "vault should be removed after decrypt");
    assert!(!dir.join(vault::DATA_DIR).exists(), "data container should be removed after decrypt");

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

/// A crash mid-lock leaves the vault written (name mapping safe) but some
/// originals not yet moved and the journal set. `resume_encrypt` must finish
/// the lock idempotently: overwrite-and-delete the leftover originals, skip the
/// files already moved, clear the journal, and keep a decryptable vault.
#[test]
fn resume_encrypt_finishes_interrupted_simple() {
    let dir = tempfile_dir();
    build_sample_tree(&dir);

    let password = b"resume me please";
    let salt = crypto::random_salt();
    let key = crypto::derive_key(password, &salt).unwrap();

    let n = vault::encrypt_folder_simple(&dir, &key, &salt).unwrap();
    assert!(n >= 4, "expected at least 4 files locked, got {}", n);

    // Simulate the interrupt: two originals "weren't deleted yet" (their ADS
    // already exist), and the folder is still flagged mid-encrypt.
    fs::write(dir.join("secret.txt"), "Hello secret content\r\n").unwrap();
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("sub").join("nested.txt"), "nested file content").unwrap();
    vault::write_pending(&dir, vault::PendingOp::Encrypt);
    assert_eq!(vault::read_pending(&dir), Some(vault::PendingOp::Encrypt));

    let key2 = crypto::derive_key(password, &vault::read_vault_salt(&dir).unwrap()).unwrap();
    let done = vault::resume_encrypt(&dir, &key2, &|_, _| {}).unwrap();
    assert!(done >= 4, "resume should account for every file, got {}", done);

    assert_eq!(vault::read_pending(&dir), None, "journal must be cleared after resume");
    assert!(!dir.join("secret.txt").exists(), "leftover original not cleaned by resume");
    assert!(dir.join(vault::VAULT_FILE).exists(), "vault should remain after encrypt-resume");

    // A normal decrypt then restores everything with correct content.
    let key3 = crypto::derive_key(password, &vault::read_vault_salt(&dir).unwrap()).unwrap();
    let restored = vault::decrypt_folder(&dir, &key3).unwrap();
    assert!(restored >= 4, "expected at least 4 files restored, got {}", restored);
    assert_eq!(fs::read_to_string(dir.join("secret.txt")).unwrap(), "Hello secret content\r\n");
    assert_eq!(
        fs::read_to_string(dir.join("sub").join("nested.txt")).unwrap(),
        "nested file content"
    );
    let deep = fs::read(dir.join("a").join("b").join("deep.bin")).unwrap();
    assert_eq!(deep.len(), 4096);

    fs::remove_dir_all(&dir).ok();
}

/// A decrypt that restored the files but was killed before removing the vault
/// must be safe to replay: every source is already consumed, so the re-run is a
/// harmless no-op success — not the old "恢复文件失败 fl_000000" error.
#[test]
fn decrypt_move_is_idempotent_after_consume() {
    let dir = tempfile_dir();
    build_sample_tree(&dir);

    let password = b"instant lock please";
    let salt = crypto::random_salt();
    let key = crypto::derive_key(password, &salt).unwrap();

    vault::encrypt_folder_move(&dir, &key, &salt).unwrap();
    let vault_bytes = fs::read(dir.join(vault::VAULT_FILE)).unwrap();

    let key2 = crypto::derive_key(password, &vault::read_vault_salt(&dir).unwrap()).unwrap();
    let restored = vault::decrypt_folder(&dir, &key2).unwrap();
    assert!(restored >= 4, "expected at least 4 files restored, got {}", restored);
    assert!(!dir.join(vault::VAULT_FILE).exists(), "vault should be gone after decrypt");

    // Replay the (now stale) decrypt: put the vault back, flag mid-decrypt.
    fs::write(dir.join(vault::VAULT_FILE), &vault_bytes).unwrap();
    vault::write_pending(&dir, vault::PendingOp::Decrypt);
    let key3 = crypto::derive_key(password, &vault::read_vault_salt(&dir).unwrap()).unwrap();
    let again = vault::decrypt_folder(&dir, &key3).unwrap();
    assert!(again >= 4, "idempotent re-decrypt should still count files, got {}", again);

    assert_eq!(fs::read_to_string(dir.join("secret.txt")).unwrap(), "Hello secret content\r\n");
    assert!(!dir.join(vault::VAULT_FILE).exists(), "vault should be gone after re-decrypt");
    assert_eq!(vault::read_pending(&dir), None, "journal must be cleared after re-decrypt");

    fs::remove_dir_all(&dir).ok();
}

/// If a payload is genuinely lost (e.g. an ADS stream deleted by antivirus),
/// decrypt must still restore every survivor, report the loss, and keep the
/// vault so nothing is silently destroyed.
#[test]
fn decrypt_simple_tolerates_lost_stream() {
    let dir = tempfile_dir();
    build_sample_tree(&dir);

    let password = b"simple lossy";
    let salt = crypto::random_salt();
    let key = crypto::derive_key(password, &salt).unwrap();

    vault::encrypt_folder_simple(&dir, &key, &salt).unwrap();

    // Delete a single ADS stream. Stream names are assigned by sorted index, so
    // fl_000000 is the first file (a/b/deep.bin).
    let host = dir.join(vault::HOST_FILE);
    let ads = format!("{}:fl_000000", host.to_string_lossy());
    fs::remove_file(&ads).unwrap();

    let key2 = crypto::derive_key(password, &vault::read_vault_salt(&dir).unwrap()).unwrap();
    let err = vault::decrypt_folder(&dir, &key2);
    assert!(err.is_err(), "a lost stream must surface as an error");
    let msg = err.unwrap_err();
    assert!(msg.contains("丢失"), "error should summarize the loss, got: {}", msg);

    // Vault preserved; the lost file stays gone; the survivors came back intact.
    assert!(dir.join(vault::VAULT_FILE).exists(), "vault must be preserved on loss");
    assert!(!dir.join("a").join("b").join("deep.bin").exists(), "lost file should not reappear");
    assert_eq!(fs::read_to_string(dir.join("secret.txt")).unwrap(), "Hello secret content\r\n");
    assert_eq!(fs::read_to_string(dir.join("notes.md")).unwrap(), "Another line of data\r\n");
    assert_eq!(
        fs::read_to_string(dir.join("sub").join("nested.txt")).unwrap(),
        "nested file content"
    );

    fs::remove_dir_all(&dir).ok();
}

/// Deterministic pseudo-random bytes (simple LCG) so tests are reproducible
/// without pulling in an RNG dependency.
fn pseudo_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = seed.wrapping_add(0x9E3779B97F4A7C15);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

/// A file larger than the 1 MiB streaming chunk (crosses several chunk
/// boundaries plus a partial last chunk) must survive a full-mode round trip
/// byte-for-byte, and the vault must use the streamed mode.
#[test]
fn full_stream_roundtrip_large_file() {
    let dir = tempfile_dir();
    let big = pseudo_bytes(3 * 1024 * 1024 + 123, 42);
    fs::write(dir.join("big.bin"), &big).unwrap();
    fs::write(dir.join("small.txt"), "tiny").unwrap();
    fs::create_dir_all(dir.join("emptydir")).unwrap();

    let password = b"streamed full mode";
    let salt = crypto::random_salt();
    let key = crypto::derive_key(password, &salt).unwrap();

    let n = vault::encrypt_folder(&dir, &key, &salt).unwrap();
    assert!(n >= 2, "expected at least 2 files packed, got {}", n);
    assert!(!dir.join("big.bin").exists(), "big.bin still present after encrypt");
    assert!(dir.join(vault::VAULT_FILE).exists(), "vault file missing");
    assert_eq!(
        vault::read_vault_mode(&dir).unwrap(),
        vault::MODE_FULL_STREAM,
        "full encryption must now use the streamed mode"
    );

    // Wrong password fails on the metadata GCM.
    let wrong_key = crypto::derive_key(b"nope", &vault::read_vault_salt(&dir).unwrap()).unwrap();
    assert!(vault::decrypt_folder(&dir, &wrong_key).is_err(), "wrong password should fail");

    // Correct password restores everything, byte-for-byte.
    let right_key = crypto::derive_key(password, &vault::read_vault_salt(&dir).unwrap()).unwrap();
    let restored = vault::decrypt_folder(&dir, &right_key).unwrap();
    assert!(restored >= 2, "expected at least 2 files restored, got {}", restored);
    assert_eq!(fs::read(dir.join("big.bin")).unwrap(), big, "large file content mismatch");
    assert_eq!(fs::read_to_string(dir.join("small.txt")).unwrap(), "tiny");
    assert!(dir.join("emptydir").is_dir(), "empty dir should be restored");
    assert!(!dir.join(vault::VAULT_FILE).exists(), "vault should be removed after decrypt");

    fs::remove_dir_all(&dir).ok();
}

/// The chunked ADS copy in simple mode must also round-trip a large file
/// without corruption.
#[test]
fn simple_roundtrip_large_file() {
    let dir = tempfile_dir();
    let big = pseudo_bytes(3 * 1024 * 1024 + 7, 99);
    fs::write(dir.join("big.bin"), &big).unwrap();
    fs::write(dir.join("small.txt"), "tiny").unwrap();

    let password = b"streamed simple mode";
    let salt = crypto::random_salt();
    let key = crypto::derive_key(password, &salt).unwrap();

    let n = vault::encrypt_folder_simple(&dir, &key, &salt).unwrap();
    assert!(n >= 2, "expected at least 2 files locked, got {}", n);
    assert!(!dir.join("big.bin").exists(), "big.bin still present after simple lock");

    let right_key = crypto::derive_key(password, &vault::read_vault_salt(&dir).unwrap()).unwrap();
    let restored = vault::decrypt_folder(&dir, &right_key).unwrap();
    assert!(restored >= 2, "expected at least 2 files restored, got {}", restored);
    assert_eq!(fs::read(dir.join("big.bin")).unwrap(), big, "large file content mismatch");
    assert_eq!(fs::read_to_string(dir.join("small.txt")).unwrap(), "tiny");
    assert!(!dir.join(vault::VAULT_FILE).exists(), "vault should be removed after decrypt");

    fs::remove_dir_all(&dir).ok();
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
