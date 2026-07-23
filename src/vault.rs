//! Vault file format and folder packing/unpacking.
//!
//! ## On-disk format (both modes)
//! ```text
//!   [salt: 16 bytes]            Argon2 salt (plaintext)
//!   [mode: 1 byte]              0 = full encryption, 1 = simple (ADS hide)
//!   [manifest ciphertext...]    nonce || AES-256-GCM(manifest)
//! ```
//!
//! ## Full-encryption manifest (mode 0), before GCM
//! ```text
//!   [magic: 8 bytes]   = b"FLOCKVLT"
//!   [version: u16]
//!   [entry count: u32]
//!   entry_count × entry:
//!       [path_len: u32]
//!       [path bytes]   UTF-8, relative path using '/' separators
//!       [kind: u8]     0 = file, 1 = directory
//!       [data_len: u64]
//!       [data bytes]   files: nonce||ciphertext of file contents
//! ```
//!
//! ## Simple-encryption manifest (mode 1), before GCM
//! ```text
//!   [magic: 8 bytes]   = b"FLOCKLIT"
//!   [version: u16]
//!   [entry count: u32]
//!   entry_count × entry:
//!       [path_len: u32]
//!       [path bytes]   UTF-8, original relative path
//!       [kind: u8]     0 = file, 1 = directory
//!       if file:
//!           [stream_len: u32]
//!           [stream bytes]  ADS stream name on the host file
//! ```
//!
//! ## Move-lock manifest (mode 2), before GCM
//! ```text
//!   [magic: 8 bytes]   = b"FLOCKMOV"
//!   [version: u16]
//!   [entry count: u32]
//!   entry_count × entry:  (identical layout to mode 1)
//!       [path_len: u32] [path bytes] [kind: u8]
//!       if file: [name_len: u32] [name bytes]  obfuscated name inside `.flockdata`
//! ```
//!
//! File *contents* are stored as NTFS Alternate Data Streams on `.flockhost`
//! (mode 1), unencrypted but invisible to Explorer and plain `dir`. In mode 2
//! the file bytes are instead `rename`d into the hidden `.flockdata` container
//! (a same-volume metadata move, instant regardless of size) and further
//! guarded by a deny-everyone ACL. In every mode only the small manifest
//! (names + mapping) is AES-256-GCM encrypted.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{self, Key, Salt};

// ── Windows: hide files from Explorer ──

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
}

#[cfg(windows)]
fn hide_file(path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;

    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let path_wide: Vec<u16> = abs.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let ret = unsafe {
        SetFileAttributesW(path_wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
    };
    let _ = ret;
}

#[cfg(not(windows))]
fn hide_file(_path: &Path) {}

// ── Windows: ACL deny/restore layer (single-object, so it stays instant) ──

/// Run `icacls` on a single object without popping a console window.
#[cfg(windows)]
fn run_icacls(path: &Path, extra: &[&str]) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut cmd = std::process::Command::new("icacls");
    cmd.arg(abs.as_os_str());
    cmd.args(extra);
    cmd.creation_flags(CREATE_NO_WINDOW);
    let _ = cmd.output();
}

/// Deny the well-known `Everyone` group (SID S-1-1-0) access to `path`.
/// Applied to the directory object only (no inheritance) so it completes
/// instantly; blocking traversal of the container is enough to hide children.
/// Best-effort: the move itself is the primary protection.
#[cfg(windows)]
fn acl_deny_everyone(path: &Path) {
    run_icacls(path, &["/deny", "*S-1-1-0:(F)"]);
}

/// Remove the deny ACE added by [`acl_deny_everyone`]. The current user is the
/// owner, so it always retains the right to rewrite the DACL.
#[cfg(windows)]
fn acl_restore_everyone(path: &Path) {
    run_icacls(path, &["/remove:d", "*S-1-1-0"]);
}

#[cfg(not(windows))]
fn acl_deny_everyone(_path: &Path) {}
#[cfg(not(windows))]
fn acl_restore_everyone(_path: &Path) {}

const MAGIC_FULL: &[u8; 8] = b"FLOCKVLT";
const MAGIC_SIMPLE: &[u8; 8] = b"FLOCKLIT";
const MAGIC_MOVE: &[u8; 8] = b"FLOCKMOV";
const VERSION: u16 = 1;

/// Encryption mode stored in the vault header.
pub const MODE_FULL: u8 = 0;
pub const MODE_SIMPLE: u8 = 1;
pub const MODE_MOVE: u8 = 2;

/// Visible name of the vault file inside the folder.
pub const VAULT_FILE: &str = ".flockvault";
/// Host file that carries ADS streams in simple mode.
pub const HOST_FILE: &str = ".flockhost";
/// Hidden container directory that holds relocated files in move-lock mode.
pub const DATA_DIR: &str = ".flockdata";

/// Names that must never be packed (the tool itself + vault + host + data dir).
pub fn is_protected_name(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower == VAULT_FILE
        || lower == format!("{}.tmp", VAULT_FILE)
        || lower == HOST_FILE
        || lower == DATA_DIR
        || lower == "desktop.ini"
        || lower.ends_with(".exe")
}

// ────────────────────────────────────── salt / mode / exists ──

/// Read the plaintext salt prefix from an existing vault.
pub fn read_vault_salt(folder: &Path) -> Result<Salt, String> {
    let path = folder.join(VAULT_FILE);
    let mut f = File::open(&path).map_err(|e| format!("无法读取 vault: {}", e))?;
    let mut salt = [0u8; 16];
    f.read_exact(&mut salt)
        .map_err(|e| format!("读取 salt 失败: {}", e))?;
    Ok(salt)
}

/// Read the mode byte from an existing vault (offset 16).
pub fn read_vault_mode(folder: &Path) -> Result<u8, String> {
    let path = folder.join(VAULT_FILE);
    let mut f = File::open(&path).map_err(|e| format!("无法读取 vault: {}", e))?;
    let mut mode = [0u8; 1];
    f.seek(std::io::SeekFrom::Start(16))
        .map_err(|e| format!("无法定位 vault: {}", e))?;
    f.read_exact(&mut mode)
        .map_err(|e| format!("读取 mode 失败: {}", e))?;
    Ok(mode[0])
}

/// Is there a vault file in this folder?
pub fn vault_exists(folder: &Path) -> bool {
    folder.join(VAULT_FILE).is_file()
}

// ────────────────────────────────────── FULL encryption (mode 0) ──

enum Entry {
    Dir { rel: String },
    File { rel: String, cipher: Vec<u8> },
}

fn serialize_manifest_full(entries: &[Entry]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC_FULL);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        match e {
            Entry::Dir { rel } => {
                push_path(&mut buf, rel);
                buf.push(1u8);
                buf.extend_from_slice(&0u64.to_le_bytes());
            }
            Entry::File { rel, cipher } => {
                push_path(&mut buf, rel);
                buf.push(0u8);
                buf.extend_from_slice(&(cipher.len() as u64).to_le_bytes());
                buf.extend_from_slice(cipher);
            }
        }
    }
    buf
}

/// Full encryption: read & AES-256-GCM encrypt every file into the vault.
pub fn encrypt_folder(folder: &Path, key: &Key, salt: &Salt) -> Result<usize, String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_tree(folder, &mut dirs, &mut files)?;
    dirs.sort();
    files.sort();

    let mut entries: Vec<Entry> = Vec::new();
    let mut count = 0usize;

    for d in &dirs {
        entries.push(Entry::Dir { rel: rel_path(folder, d)? });
    }
    for f in &files {
        let rel = rel_path(folder, f)?;
        let mut data = Vec::new();
        File::open(f)
            .and_then(|mut h| h.read_to_end(&mut data))
            .map_err(|e| format!("读取文件失败 {}: {}", f.display(), e))?;
        let cipher = crypto::encrypt(key, &data)?;
        entries.push(Entry::File { rel, cipher });
        count += 1;
    }

    if entries.is_empty() {
        return Ok(0);
    }

    let manifest = serialize_manifest_full(&entries);
    let manifest_ct = crypto::encrypt(key, &manifest)?;

    write_vault(folder, salt, MODE_FULL, &manifest_ct)?;
    delete_tree(folder)?;
    Ok(count)
}

fn decrypt_folder_full(folder: &Path, key: &Key, manifest: &[u8]) -> Result<usize, String> {
    if manifest.len() < 8 + 2 + 4 {
        return Err("vault 数据损坏".into());
    }
    if &manifest[0..8] != MAGIC_FULL {
        return Err("vault 标识不匹配".into());
    }
    let count = u32::from_le_bytes([manifest[10], manifest[11], manifest[12], manifest[13]]) as usize;
    let mut pos = 14;
    let mut created: BTreeSet<PathBuf> = BTreeSet::new();
    let mut file_count = 0usize;

    for _ in 0..count {
        let (plen, consumed) = read_u32(manifest, pos)?;
        pos += consumed;
        let rel_bytes = manifest.get(pos..pos + plen as usize).ok_or("vault 数据损坏 (path)")?;
        pos += plen as usize;
        let rel = std::str::from_utf8(rel_bytes).map_err(|_| "vault 路径不是有效 UTF-8".to_string())?;
        if rel.contains("..") || rel.starts_with('/') || rel.contains('\\') {
            return Err(format!("拒绝不安全的路径: {}", rel));
        }

        let kind = *manifest.get(pos).ok_or("vault 数据损坏 (kind)")?;
        pos += 1;
        let (dlen, consumed) = read_u64(manifest, pos)?;
        pos += consumed;
        let data = manifest.get(pos..pos + dlen as usize).ok_or("vault 数据损坏 (data)")?;
        pos += dlen as usize;

        let target = folder.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        if kind == 1 {
            fs::create_dir_all(&target)
                .map_err(|e| format!("创建目录失败 {}: {}", target.display(), e))?;
            created.insert(target);
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("创建父目录失败: {}", e))?;
            }
            let plain = crypto::decrypt(key, data)?;
            let tmp = target.with_extension("flocktmp");
            {
                let mut f = File::create(&tmp)
                    .map_err(|e| format!("创建文件失败 {}: {}", target.display(), e))?;
                f.write_all(&plain)
                    .map_err(|e| format!("写入文件失败 {}: {}", target.display(), e))?;
                f.sync_all().ok();
            }
            fs::rename(&tmp, &target).map_err(|e| format!("重命名文件失败: {}", e))?;
            created.insert(target);
            file_count += 1;
        }
    }

    let _ = created;
    Ok(file_count)
}

// ────────────────────────────────────── SIMPLE encryption (mode 1, ADS) ──

/// Entry for simple mode: original path + ADS stream name.
struct SimpleEntry {
    rel: String,
    is_dir: bool,
    stream: Option<String>, // None for dirs
}

fn serialize_manifest_simple(magic: &[u8; 8], entries: &[SimpleEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(magic);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        push_path(&mut buf, &e.rel);
        buf.push(if e.is_dir { 1u8 } else { 0u8 });
        if let Some(s) = &e.stream {
            let sb = s.as_bytes();
            buf.extend_from_slice(&(sb.len() as u32).to_le_bytes());
            buf.extend_from_slice(sb);
        }
    }
    buf
}

/// Simple encryption: move each file's bytes into an ADS on the host file,
/// delete the original. Instant regardless of file size. NTFS only.
pub fn encrypt_folder_simple(folder: &Path, key: &Key, salt: &Salt) -> Result<usize, String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_tree(folder, &mut dirs, &mut files)?;
    dirs.sort();
    files.sort();

    if dirs.is_empty() && files.is_empty() {
        return Ok(0);
    }

    // Create the host file that will carry all ADS streams.
    let host_path = folder.join(HOST_FILE);
    {
        let mut h = File::create(&host_path)
            .map_err(|e| format!("无法创建 host 文件: {}", e))?;
        // Write a tiny marker so the file isn't zero-byte (some tools skip empty files).
        h.write_all(b"FL").map_err(|e| format!("写入 host 失败: {}", e))?;
        h.sync_all().ok();
    }

    let mut entries: Vec<SimpleEntry> = Vec::new();
    let mut count = 0usize;

    for d in &dirs {
        entries.push(SimpleEntry {
            rel: rel_path(folder, d)?,
            is_dir: true,
            stream: None,
        });
    }

    for f in &files {
        let rel = rel_path(folder, f)?;
        let stream_name = format!("fl_{:06}", count);
        let ads_path = format!("{}:{}", host_path.to_string_lossy(), stream_name);

        // Move file content into the ADS (raw byte copy, no encryption).
        let mut data = Vec::new();
        File::open(f)
            .and_then(|mut h| h.read_to_end(&mut data))
            .map_err(|e| format!("读取文件失败 {}: {}", f.display(), e))?;

        let mut ads = File::create(&ads_path)
            .map_err(|e| format!("无法创建 ADS (可能非 NTFS 卷): {}", e))?;
        ads.write_all(&data)
            .map_err(|e| format!("写入 ADS 失败: {}", e))?;
        ads.sync_all().ok();
        drop(ads);

        entries.push(SimpleEntry {
            rel,
            is_dir: false,
            stream: Some(stream_name),
        });
        count += 1;
    }

    if entries.is_empty() {
        let _ = fs::remove_file(&host_path);
        return Ok(0);
    }

    let manifest = serialize_manifest_simple(MAGIC_SIMPLE, &entries);
    let manifest_ct = crypto::encrypt(key, &manifest)?;

    write_vault(folder, salt, MODE_SIMPLE, &manifest_ct)?;
    hide_file(&host_path);
    delete_tree(folder)?;
    Ok(count)
}

fn decrypt_folder_simple(folder: &Path, _key: &Key, manifest: &[u8]) -> Result<usize, String> {
    if manifest.len() < 8 + 2 + 4 {
        return Err("vault 数据损坏".into());
    }
    if &manifest[0..8] != MAGIC_SIMPLE {
        return Err("vault 标识不匹配".into());
    }
    let count = u32::from_le_bytes([manifest[10], manifest[11], manifest[12], manifest[13]]) as usize;
    let mut pos = 14;
    let host_path = folder.join(HOST_FILE);
    let mut file_count = 0usize;

    for _ in 0..count {
        let (plen, consumed) = read_u32(manifest, pos)?;
        pos += consumed;
        let rel_bytes = manifest.get(pos..pos + plen as usize).ok_or("vault 数据损坏 (path)")?;
        pos += plen as usize;
        let rel = std::str::from_utf8(rel_bytes).map_err(|_| "vault 路径不是有效 UTF-8".to_string())?;
        if rel.contains("..") || rel.starts_with('/') || rel.contains('\\') {
            return Err(format!("拒绝不安全的路径: {}", rel));
        }

        let kind = *manifest.get(pos).ok_or("vault 数据损坏 (kind)")?;
        pos += 1;

        let target = folder.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));

        if kind == 1 {
            // directory
            fs::create_dir_all(&target)
                .map_err(|e| format!("创建目录失败 {}: {}", target.display(), e))?;
        } else {
            // file — read from ADS
            let (slen, consumed) = read_u32(manifest, pos)?;
            pos += consumed;
            let stream_bytes = manifest.get(pos..pos + slen as usize).ok_or("vault 数据损坏 (stream)")?;
            pos += slen as usize;
            let stream_name = std::str::from_utf8(stream_bytes).map_err(|_| "stream 名无效".to_string())?;

            let ads_path = format!("{}:{}", host_path.to_string_lossy(), stream_name);
            let mut data = Vec::new();
            File::open(&ads_path)
                .and_then(|mut h| h.read_to_end(&mut data))
                .map_err(|e| format!("读取 ADS 失败 {}: {}", stream_name, e))?;

            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("创建父目录失败: {}", e))?;
            }
            let tmp = target.with_extension("flocktmp");
            {
                let mut f = File::create(&tmp)
                    .map_err(|e| format!("创建文件失败 {}: {}", target.display(), e))?;
                f.write_all(&data)
                    .map_err(|e| format!("写入文件失败 {}: {}", target.display(), e))?;
                f.sync_all().ok();
            }
            fs::rename(&tmp, &target).map_err(|e| format!("重命名文件失败: {}", e))?;

            // Delete the ADS stream now that we've restored the file.
            let _ = fs::remove_file(&ads_path);
            file_count += 1;
        }
    }

    // Remove the host file and vault.
    let _ = fs::remove_file(&host_path);
    Ok(file_count)
}

// ────────────────────────────────────── MOVE-lock encryption (mode 2) ──

/// Move-lock encryption: relocate every file into the hidden `.flockdata`
/// container via `fs::rename` (a same-volume metadata move — instant no matter
/// how large the file), record the original→obfuscated mapping in the
/// AES-encrypted manifest, then hide the container and drop a deny-everyone ACL
/// on top. NTFS same-volume only.
pub fn encrypt_folder_move(folder: &Path, key: &Key, salt: &Salt) -> Result<usize, String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_tree(folder, &mut dirs, &mut files)?;
    dirs.sort();
    files.sort();

    if dirs.is_empty() && files.is_empty() {
        return Ok(0);
    }

    let data_dir = folder.join(DATA_DIR);
    fs::create_dir_all(&data_dir).map_err(|e| format!("无法创建数据容器: {}", e))?;

    let mut entries: Vec<SimpleEntry> = Vec::new();
    let mut count = 0usize;

    for d in &dirs {
        entries.push(SimpleEntry {
            rel: rel_path(folder, d)?,
            is_dir: true,
            stream: None,
        });
    }

    for f in &files {
        let rel = rel_path(folder, f)?;
        let name = format!("fl_{:06}", count);
        let target = data_dir.join(&name);
        // Pure metadata move: no byte copy, so this is instant for any size.
        fs::rename(f, &target)
            .map_err(|e| format!("移动文件失败 {}: {}", f.display(), e))?;
        entries.push(SimpleEntry {
            rel,
            is_dir: false,
            stream: Some(name),
        });
        count += 1;
    }

    let manifest = serialize_manifest_simple(MAGIC_MOVE, &entries);
    let manifest_ct = crypto::encrypt(key, &manifest)?;
    write_vault(folder, salt, MODE_MOVE, &manifest_ct)?;

    // Remove the now-empty original tree, then hide + lock the container.
    delete_tree(folder)?;
    hide_file(&data_dir);
    acl_deny_everyone(&data_dir);
    Ok(count)
}

fn decrypt_folder_move(folder: &Path, _key: &Key, manifest: &[u8]) -> Result<usize, String> {
    if manifest.len() < 8 + 2 + 4 {
        return Err("vault 数据损坏".into());
    }
    if &manifest[0..8] != MAGIC_MOVE {
        return Err("vault 标识不匹配".into());
    }
    let count = u32::from_le_bytes([manifest[10], manifest[11], manifest[12], manifest[13]]) as usize;
    let mut pos = 14;
    let data_dir = folder.join(DATA_DIR);

    // Lift the deny ACL first so we can read the container back.
    acl_restore_everyone(&data_dir);
    let mut file_count = 0usize;

    for _ in 0..count {
        let (plen, consumed) = read_u32(manifest, pos)?;
        pos += consumed;
        let rel_bytes = manifest.get(pos..pos + plen as usize).ok_or("vault 数据损坏 (path)")?;
        pos += plen as usize;
        let rel = std::str::from_utf8(rel_bytes).map_err(|_| "vault 路径不是有效 UTF-8".to_string())?;
        if rel.contains("..") || rel.starts_with('/') || rel.contains('\\') {
            return Err(format!("拒绝不安全的路径: {}", rel));
        }

        let kind = *manifest.get(pos).ok_or("vault 数据损坏 (kind)")?;
        pos += 1;

        let target = folder.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));

        if kind == 1 {
            fs::create_dir_all(&target)
                .map_err(|e| format!("创建目录失败 {}: {}", target.display(), e))?;
        } else {
            let (nlen, consumed) = read_u32(manifest, pos)?;
            pos += consumed;
            let name_bytes = manifest.get(pos..pos + nlen as usize).ok_or("vault 数据损坏 (name)")?;
            pos += nlen as usize;
            let name = std::str::from_utf8(name_bytes).map_err(|_| "名称无效".to_string())?;
            if name.contains('/') || name.contains('\\') || name.contains("..") {
                return Err(format!("拒绝不安全的容器名: {}", name));
            }

            let src = data_dir.join(name);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("创建父目录失败: {}", e))?;
            }
            // Move the file back to its original location (instant).
            fs::rename(&src, &target)
                .map_err(|e| format!("恢复文件失败 {}: {}", name, e))?;
            file_count += 1;
        }
    }

    // Drop the now-empty container.
    let _ = fs::remove_dir_all(&data_dir);
    Ok(file_count)
}

// ────────────────────────────────────── shared helpers ──

/// Write the vault file: salt + mode + manifest ciphertext.
fn write_vault(folder: &Path, salt: &Salt, mode: u8, manifest_ct: &[u8]) -> Result<(), String> {
    let vault_path = folder.join(VAULT_FILE);
    let tmp_path = folder.join(format!("{}.tmp", VAULT_FILE));
    {
        let mut f = File::create(&tmp_path).map_err(|e| format!("无法创建 vault 文件: {}", e))?;
        f.write_all(salt).map_err(|e| format!("写入 salt 失败: {}", e))?;
        f.write_all(&[mode]).map_err(|e| format!("写入 mode 失败: {}", e))?;
        f.write_all(manifest_ct).map_err(|e| format!("写入 vault 失败: {}", e))?;
        f.sync_all().ok();
    }
    fs::rename(&tmp_path, &vault_path).map_err(|e| format!("重命名 vault 失败: {}", e))?;
    hide_file(&vault_path);
    Ok(())
}

/// Decrypt the vault, auto-detecting full vs simple mode.
/// Returns the number of files restored.
pub fn decrypt_folder(folder: &Path, key: &Key) -> Result<usize, String> {
    let vault_path = folder.join(VAULT_FILE);
    let mut buf = Vec::new();
    File::open(&vault_path)
        .and_then(|mut h| h.read_to_end(&mut buf))
        .map_err(|e| format!("无法读取 vault: {}", e))?;

    if buf.len() < 16 + 1 + 12 {
        return Err("vault 数据损坏".into());
    }
    let mode = buf[16];
    let manifest_ct = &buf[17..];
    let manifest = crypto::decrypt(key, manifest_ct)?;

    let result = match mode {
        MODE_FULL => decrypt_folder_full(folder, key, &manifest),
        MODE_SIMPLE => decrypt_folder_simple(folder, key, &manifest),
        MODE_MOVE => decrypt_folder_move(folder, key, &manifest),
        _ => Err(format!("未知的 vault 模式: {}", mode)),
    };

    // Remove the vault file after successful restore.
    if result.is_ok() {
        let _ = fs::remove_file(&vault_path);
    }
    result
}

fn collect_tree(dir: &Path, dirs: &mut Vec<PathBuf>, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let rd = fs::read_dir(dir).map_err(|e| format!("读取目录失败 {}: {}", dir.display(), e))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
        let name = entry.file_name();
        if is_protected_name(&name.to_string_lossy()) {
            continue;
        }
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| format!("获取类型失败: {}", e))?;
        if ft.is_dir() {
            dirs.push(path.clone());
            collect_tree(&path, dirs, files)?;
        } else if ft.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn rel_path(root: &Path, p: &Path) -> Result<String, String> {
    let rel = p.strip_prefix(root).map_err(|e| format!("路径前缀错误: {}", e))?;
    let mut s = String::new();
    for (i, comp) in rel.components().enumerate() {
        if i > 0 {
            s.push('/');
        }
        s.push_str(&comp.as_os_str().to_string_lossy());
    }
    Ok(s)
}

fn delete_tree(root: &Path) -> Result<(), String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_tree(root, &mut dirs, &mut files)?;
    for f in &files {
        let _ = fs::remove_file(f);
    }
    dirs.sort();
    dirs.reverse();
    for d in &dirs {
        let _ = fs::remove_dir(d);
    }
    Ok(())
}

fn push_path(buf: &mut Vec<u8>, rel: &str) {
    let bytes = rel.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn read_u32(buf: &[u8], pos: usize) -> Result<(u32, usize), String> {
    let b = buf.get(pos..pos + 4).ok_or("vault 数据损坏 (u32)")?;
    Ok((u32::from_le_bytes([b[0], b[1], b[2], b[3]]), 4))
}

fn read_u64(buf: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let b = buf.get(pos..pos + 8).ok_or("vault 数据损坏 (u64)")?;
    Ok((u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]), 8))
}

// ── std::io::Seek trait import for read_vault_mode ──
use std::io::Seek;
