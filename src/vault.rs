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
use std::io::{BufReader, BufWriter, Read, Write};
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
/// Streamed full encryption (chunked AEAD, file contents kept out of the
/// manifest). Supersedes [`MODE_FULL`] for new vaults; the old value is still
/// decrypted for backward compatibility.
pub const MODE_FULL_STREAM: u8 = 3;

/// Visible name of the vault file inside the folder.
pub const VAULT_FILE: &str = ".flockvault";
/// Host file that carries ADS streams in simple mode.
pub const HOST_FILE: &str = ".flockhost";
/// Hidden container directory that holds relocated files in move-lock mode.
pub const DATA_DIR: &str = ".flockdata";
/// State-journal file: records the direction of an in-progress operation so a
/// crashed/killed run can be resumed after restart. Contains no secrets.
pub const STATE_FILE: &str = ".flockstate";

/// Names that must never be packed (the tool itself + vault + host + data dir).
pub fn is_protected_name(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower == VAULT_FILE
        || lower == format!("{}.tmp", VAULT_FILE)
        || lower == HOST_FILE
        || lower == DATA_DIR
        || lower == STATE_FILE
        || lower == "desktop.ini"
        || lower.ends_with(".exe")
}

// ────────────────────────────────────── state journal ──

/// Direction of an in-progress operation, persisted in `.flockstate`. Used only
/// to disambiguate "half-encrypted" vs "half-decrypted" when resuming; the
/// sensitive mapping still lives solely in the encrypted vault manifest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PendingOp {
    Encrypt,
    Decrypt,
}

/// Write the in-progress marker (`E` = encrypt, `D` = decrypt) and hide it.
pub fn write_pending(folder: &Path, op: PendingOp) {
    let path = folder.join(STATE_FILE);
    let byte: &[u8] = match op {
        PendingOp::Encrypt => b"E",
        PendingOp::Decrypt => b"D",
    };
    if let Ok(mut f) = File::create(&path) {
        let _ = f.write_all(byte);
        f.sync_all().ok();
    }
    hide_file(&path);
}

/// Read the in-progress marker, if the folder has one.
pub fn read_pending(folder: &Path) -> Option<PendingOp> {
    let path = folder.join(STATE_FILE);
    let mut f = File::open(&path).ok()?;
    let mut b = [0u8; 1];
    f.read_exact(&mut b).ok()?;
    match b[0] {
        b'E' => Some(PendingOp::Encrypt),
        b'D' => Some(PendingOp::Decrypt),
        _ => None,
    }
}

/// Remove the in-progress marker (operation finished cleanly).
pub fn clear_pending(folder: &Path) {
    let _ = fs::remove_file(folder.join(STATE_FILE));
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

// ────────────────────────────────────── FULL encryption (streamed, mode 3) ──

/// Serialize the small full-mode metadata (names + kinds only; file contents
/// are streamed separately). This is the only part protected by a one-shot GCM.
fn serialize_meta_full(
    folder: &Path,
    dirs: &[PathBuf],
    files: &[PathBuf],
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC_FULL);
    buf.extend_from_slice(&2u16.to_le_bytes()); // format version 2 (streamed)
    let count = dirs.len() + files.len();
    buf.extend_from_slice(&(count as u32).to_le_bytes());
    for d in dirs {
        push_path(&mut buf, &rel_path(folder, d)?);
        buf.push(1u8);
    }
    for f in files {
        push_path(&mut buf, &rel_path(folder, f)?);
        buf.push(0u8);
    }
    Ok(buf)
}

/// Parse [`serialize_meta_full`] back into `(rel, is_dir)` entries, preserving
/// order. File entries appear in the same order their streamed blobs were
/// written to the vault, so decrypt can read them back sequentially.
fn parse_meta_full(meta: &[u8]) -> Result<Vec<(String, bool)>, String> {
    if meta.len() < 8 + 2 + 4 {
        return Err("vault 数据损坏".into());
    }
    if &meta[0..8] != MAGIC_FULL {
        return Err("vault 标识不匹配".into());
    }
    let count = u32::from_le_bytes([meta[10], meta[11], meta[12], meta[13]]) as usize;
    let mut pos = 14;
    let mut out: Vec<(String, bool)> = Vec::new();
    for _ in 0..count {
        let (plen, consumed) = read_u32(meta, pos)?;
        pos += consumed;
        let rel_bytes = meta.get(pos..pos + plen as usize).ok_or("vault 数据损坏 (path)")?;
        pos += plen as usize;
        let rel = std::str::from_utf8(rel_bytes).map_err(|_| "vault 路径不是有效 UTF-8".to_string())?;
        if rel.split('/').any(|c| c == "..") || rel.starts_with('/') || rel.contains('\\') {
            return Err(format!("拒绝不安全的路径: {}", rel));
        }
        let kind = *meta.get(pos).ok_or("vault 数据损坏 (kind)")?;
        pos += 1;
        out.push((rel.to_string(), kind == 1));
    }
    Ok(out)
}

/// Full encryption: chunked-AEAD every file straight into the vault.
pub fn encrypt_folder(folder: &Path, key: &Key, salt: &Salt) -> Result<usize, String> {
    encrypt_folder_with_progress(folder, key, salt, &|_, _| {})
}

/// Same as [`encrypt_folder`], but reports `(done, total)` after each file so a
/// GUI can drive a progress bar. `progress` is called from the calling thread.
///
/// Memory stays flat regardless of file/folder size: only the small metadata is
/// buffered; each file's ciphertext is streamed directly to disk.
pub fn encrypt_folder_with_progress(
    folder: &Path,
    key: &Key,
    salt: &Salt,
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_tree(folder, &mut dirs, &mut files)?;
    dirs.sort();
    files.sort();

    if dirs.is_empty() && files.is_empty() {
        return Ok(0);
    }

    // The name/kind metadata is the sole GCM-encrypted part (small).
    let meta = serialize_meta_full(folder, &dirs, &files)?;
    let meta_ct = crypto::encrypt(key, &meta)?;

    // Write header + metadata, then stream each file's ciphertext into a temp
    // vault and rename it into place (atomic, so a crash resumes cleanly).
    let vault_path = folder.join(VAULT_FILE);
    let tmp_path = folder.join(format!("{}.tmp", VAULT_FILE));
    let total = files.len();
    let mut count = 0usize;
    {
        let mut out = BufWriter::new(
            File::create(&tmp_path).map_err(|e| format!("无法创建 vault 文件: {}", e))?,
        );
        out.write_all(salt).map_err(|e| format!("写入 salt 失败: {}", e))?;
        out.write_all(&[MODE_FULL_STREAM]).map_err(|e| format!("写入 mode 失败: {}", e))?;
        out.write_all(&(meta_ct.len() as u32).to_le_bytes())
            .map_err(|e| format!("写入清单长度失败: {}", e))?;
        out.write_all(&meta_ct).map_err(|e| format!("写入清单失败: {}", e))?;
        for f in &files {
            let mut inp = BufReader::new(
                File::open(f).map_err(|e| format!("读取文件失败 {}: {}", f.display(), e))?,
            );
            crypto::encrypt_stream(key, &mut inp, &mut out)?;
            count += 1;
            progress(count, total);
        }
        let f = out.into_inner().map_err(|e| format!("写入 vault 失败: {}", e))?;
        f.sync_all().ok();
    }
    fs::rename(&tmp_path, &vault_path).map_err(|e| format!("重命名 vault 失败: {}", e))?;
    hide_file(&vault_path);

    // Vault is atomic and now holds every file; mark the direction, then the
    // only remaining (idempotent) step is removing the plaintext originals.
    write_pending(folder, PendingOp::Encrypt);
    delete_tree(folder)?;
    clear_pending(folder);
    Ok(count)
}

fn decrypt_folder_full(
    folder: &Path,
    key: &Key,
    manifest: &[u8],
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
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

    for i in 0..count {
        let (plen, consumed) = read_u32(manifest, pos)?;
        pos += consumed;
        let rel_bytes = manifest.get(pos..pos + plen as usize).ok_or("vault 数据损坏 (path)")?;
        pos += plen as usize;
        let rel = std::str::from_utf8(rel_bytes).map_err(|_| "vault 路径不是有效 UTF-8".to_string())?;
        if rel.split('/').any(|c| c == "..") || rel.starts_with('/') || rel.contains('\\') {
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
        progress(i + 1, count);
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
    encrypt_folder_simple_with_progress(folder, key, salt, &|_, _| {})
}

/// Same as [`encrypt_folder_simple`], but reports `(done, total)` after each
/// file so a GUI can drive a progress bar. `progress` is called from the
/// calling thread.
pub fn encrypt_folder_simple_with_progress(
    folder: &Path,
    key: &Key,
    salt: &Salt,
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_tree(folder, &mut dirs, &mut files)?;
    dirs.sort();
    files.sort();

    if dirs.is_empty() && files.is_empty() {
        return Ok(0);
    }

    // Build the manifest first (assign stream names by index) so the vault —
    // the sole record of the name→stream mapping — exists on disk before we move
    // any bytes; a crash mid-move can then be resumed from the vault.
    let mut entries: Vec<SimpleEntry> = Vec::new();
    for d in &dirs {
        entries.push(SimpleEntry {
            rel: rel_path(folder, d)?,
            is_dir: true,
            stream: None,
        });
    }
    let mut file_rels: Vec<(String, String)> = Vec::new();
    for (i, f) in files.iter().enumerate() {
        let rel = rel_path(folder, f)?;
        let stream_name = format!("fl_{:06}", i);
        entries.push(SimpleEntry {
            rel: rel.clone(),
            is_dir: false,
            stream: Some(stream_name.clone()),
        });
        file_rels.push((rel, stream_name));
    }

    let manifest = serialize_manifest_simple(MAGIC_SIMPLE, &entries);
    let manifest_ct = crypto::encrypt(key, &manifest)?;
    write_vault(folder, salt, MODE_SIMPLE, &manifest_ct)?;
    write_pending(folder, PendingOp::Encrypt);

    let count = apply_simple_lock(folder, &file_rels, progress)?;

    // Remove the now-empty original tree (files were deleted as they were moved).
    delete_tree(folder)?;
    clear_pending(folder);
    Ok(count)
}

/// Idempotently move each `(rel, stream)` file's bytes into an ADS on the host
/// file and delete the original. Re-runnable after an interrupt:
/// - original present            → (re)write ADS, delete original
/// - original gone, ADS present  → already moved, skip
/// - both missing                → error (source lost)
fn apply_simple_lock(
    folder: &Path,
    file_rels: &[(String, String)],
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
    let host_path = folder.join(HOST_FILE);
    if !host_path.is_file() {
        let mut h = File::create(&host_path)
            .map_err(|e| format!("无法创建 host 文件: {}", e))?;
        // Tiny marker so the file isn't zero-byte (some tools skip empty files).
        h.write_all(b"FL").map_err(|e| format!("写入 host 失败: {}", e))?;
        h.sync_all().ok();
    }
    hide_file(&host_path);

    let total = file_rels.len();
    let mut count = 0usize;
    for (i, (rel, stream_name)) in file_rels.iter().enumerate() {
        let src = folder.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        let ads_path = format!("{}:{}", host_path.to_string_lossy(), stream_name);
        if src.is_file() {
            let mut input = File::open(&src)
                .map_err(|e| format!("读取文件失败 {}: {}", src.display(), e))?;
            let mut ads = File::create(&ads_path)
                .map_err(|e| format!("无法创建 ADS (可能非 NTFS 卷): {}", e))?;
            // Chunked copy (std::io::copy uses a fixed internal buffer) so a huge
            // file never gets fully loaded into memory.
            std::io::copy(&mut input, &mut ads)
                .map_err(|e| format!("写入 ADS 失败: {}", e))?;
            ads.sync_all().ok();
            drop(ads);
            drop(input);
            let _ = fs::remove_file(&src);
            count += 1;
        } else if File::open(&ads_path).is_ok() {
            // Already moved in a previous (interrupted) run.
            count += 1;
        } else {
            return Err(format!("源文件与 ADS 均缺失，无法锁定: {}", rel));
        }
        progress(i + 1, total);
    }
    Ok(count)
}

fn decrypt_folder_simple(
    folder: &Path,
    _key: &Key,
    manifest: &[u8],
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
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
    let mut lost: Vec<String> = Vec::new();

    for i in 0..count {
        let (plen, consumed) = read_u32(manifest, pos)?;
        pos += consumed;
        let rel_bytes = manifest.get(pos..pos + plen as usize).ok_or("vault 数据损坏 (path)")?;
        pos += plen as usize;
        let rel = std::str::from_utf8(rel_bytes).map_err(|_| "vault 路径不是有效 UTF-8".to_string())?;
        if rel.split('/').any(|c| c == "..") || rel.starts_with('/') || rel.contains('\\') {
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
            match File::open(&ads_path) {
                Ok(mut ads) => {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent).map_err(|e| format!("创建父目录失败: {}", e))?;
                    }
                    let tmp = target.with_extension("flocktmp");
                    {
                        let mut f = File::create(&tmp)
                            .map_err(|e| format!("创建文件失败 {}: {}", target.display(), e))?;
                        // Chunked copy so a huge stream never loads fully into RAM.
                        std::io::copy(&mut ads, &mut f)
                            .map_err(|e| format!("写入文件失败 {}: {}", target.display(), e))?;
                        f.sync_all().ok();
                    }
                    drop(ads);
                    fs::rename(&tmp, &target).map_err(|e| format!("重命名文件失败: {}", e))?;
                    // Delete the ADS stream now that we've restored the file.
                    let _ = fs::remove_file(&ads_path);
                    file_count += 1;
                }
                Err(_) => {
                    if target.is_file() {
                        // Already restored in a previous (interrupted) run.
                        file_count += 1;
                    } else {
                        // Neither source nor target present: data truly lost.
                        lost.push(rel.to_string());
                    }
                }
            }
        }
        progress(i + 1, count);
    }

    if lost.is_empty() {
        // Remove the host file (vault removed by the caller).
        let _ = fs::remove_file(&host_path);
        Ok(file_count)
    } else {
        Err(format!(
            "已恢复 {} 个文件，{} 个数据已丢失无法恢复: {}",
            file_count,
            lost.len(),
            lost.join(", ")
        ))
    }
}

// ────────────────────────────────────── MOVE-lock encryption (mode 2) ──

/// Move-lock encryption: relocate every file into the hidden `.flockdata`
/// container via `fs::rename` (a same-volume metadata move — instant no matter
/// how large the file), record the original→obfuscated mapping in the
/// AES-encrypted manifest, then hide the container and drop a deny-everyone ACL
/// on top. NTFS same-volume only.
pub fn encrypt_folder_move(folder: &Path, key: &Key, salt: &Salt) -> Result<usize, String> {
    encrypt_folder_move_with_progress(folder, key, salt, &|_, _| {})
}

/// Same as [`encrypt_folder_move`], but reports `(done, total)` after each file
/// so a GUI can drive a progress bar.
pub fn encrypt_folder_move_with_progress(
    folder: &Path,
    key: &Key,
    salt: &Salt,
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_tree(folder, &mut dirs, &mut files)?;
    dirs.sort();
    files.sort();

    if dirs.is_empty() && files.is_empty() {
        return Ok(0);
    }

    // Build the manifest first (assign obfuscated names by index) so the vault
    // — the sole record of the name mapping — exists on disk before we relocate
    // anything. A crash mid-move can then be resumed from the vault.
    let mut entries: Vec<SimpleEntry> = Vec::new();
    for d in &dirs {
        entries.push(SimpleEntry {
            rel: rel_path(folder, d)?,
            is_dir: true,
            stream: None,
        });
    }
    let mut file_rels: Vec<(String, String)> = Vec::new();
    for (i, f) in files.iter().enumerate() {
        let rel = rel_path(folder, f)?;
        let name = format!("fl_{:06}", i);
        entries.push(SimpleEntry {
            rel: rel.clone(),
            is_dir: false,
            stream: Some(name.clone()),
        });
        file_rels.push((rel, name));
    }

    let manifest = serialize_manifest_simple(MAGIC_MOVE, &entries);
    let manifest_ct = crypto::encrypt(key, &manifest)?;
    write_vault(folder, salt, MODE_MOVE, &manifest_ct)?;
    write_pending(folder, PendingOp::Encrypt);

    let count = apply_move_lock(folder, &file_rels, progress)?;

    // Remove the now-empty original tree, then hide + lock the container.
    delete_tree(folder)?;
    let data_dir = folder.join(DATA_DIR);
    hide_file(&data_dir);
    acl_deny_everyone(&data_dir);
    clear_pending(folder);
    Ok(count)
}

/// Idempotently relocate each `(rel, name)` file into `.flockdata/name` via a
/// same-volume `rename`. Re-runnable after an interrupt:
/// - source present              → rename into container
/// - source gone, container has it → already moved, skip
/// - both missing                → error (source lost)
fn apply_move_lock(
    folder: &Path,
    file_rels: &[(String, String)],
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
    let data_dir = folder.join(DATA_DIR);
    // A prior partial run may have dropped a deny ACL; lift it so we can write.
    acl_restore_everyone(&data_dir);
    fs::create_dir_all(&data_dir).map_err(|e| format!("无法创建数据容器: {}", e))?;

    let total = file_rels.len();
    let mut count = 0usize;
    for (i, (rel, name)) in file_rels.iter().enumerate() {
        let src = folder.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        let dst = data_dir.join(name);
        if src.is_file() {
            fs::rename(&src, &dst)
                .map_err(|e| format!("移动文件失败 {}: {}", src.display(), e))?;
            count += 1;
        } else if dst.is_file() {
            // Already moved in a previous (interrupted) run.
            count += 1;
        } else {
            return Err(format!("源文件与容器均缺失，无法锁定: {}", rel));
        }
        progress(i + 1, total);
    }
    Ok(count)
}

fn decrypt_folder_move(
    folder: &Path,
    _key: &Key,
    manifest: &[u8],
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
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
    let mut lost: Vec<String> = Vec::new();

    for i in 0..count {
        let (plen, consumed) = read_u32(manifest, pos)?;
        pos += consumed;
        let rel_bytes = manifest.get(pos..pos + plen as usize).ok_or("vault 数据损坏 (path)")?;
        pos += plen as usize;
        let rel = std::str::from_utf8(rel_bytes).map_err(|_| "vault 路径不是有效 UTF-8".to_string())?;
        if rel.split('/').any(|c| c == "..") || rel.starts_with('/') || rel.contains('\\') {
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
            if name.contains('/') || name.contains('\\') || name == ".." {
                return Err(format!("拒绝不安全的容器名: {}", name));
            }

            let src = data_dir.join(name);
            if src.is_file() {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| format!("创建父目录失败: {}", e))?;
                }
                // Move the file back to its original location (instant).
                fs::rename(&src, &target)
                    .map_err(|e| format!("恢复文件失败 {}: {}", name, e))?;
                file_count += 1;
            } else if target.is_file() {
                // Already restored in a previous (interrupted) run.
                file_count += 1;
            } else {
                // Neither container copy nor target present: data truly lost.
                lost.push(rel.to_string());
            }
        }
        progress(i + 1, count);
    }

    if lost.is_empty() {
        // Drop the now-empty container.
        let _ = fs::remove_dir_all(&data_dir);
        Ok(file_count)
    } else {
        Err(format!(
            "已恢复 {} 个文件，{} 个数据已丢失无法恢复: {}",
            file_count,
            lost.len(),
            lost.join(", ")
        ))
    }
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

/// Read the vault, decrypt its manifest, and return `(mode, manifest_plain)`.
/// Shared by the decrypt and resume paths; a wrong password fails GCM
/// authentication here, so this doubles as password validation.
fn read_and_decrypt_manifest(folder: &Path, key: &Key) -> Result<(u8, Vec<u8>), String> {
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
    Ok((mode, manifest))
}

/// Open a streamed (mode 3) vault, decrypt only its small metadata (which also
/// validates the password via GCM), and return the file handle positioned at
/// the first file's content blob. Never loads file contents into memory.
fn open_stream_meta(folder: &Path, key: &Key) -> Result<(File, Vec<u8>), String> {
    let vault_path = folder.join(VAULT_FILE);
    let mut f = File::open(&vault_path).map_err(|e| format!("无法读取 vault: {}", e))?;
    // Skip the plaintext header: salt (16) + mode (1).
    f.seek(std::io::SeekFrom::Start(17))
        .map_err(|e| format!("无法定位 vault: {}", e))?;
    let mut len_b = [0u8; 4];
    f.read_exact(&mut len_b)
        .map_err(|e| format!("读取清单长度失败: {}", e))?;
    let meta_len = u32::from_le_bytes(len_b) as usize;
    let mut meta_ct = vec![0u8; meta_len];
    f.read_exact(&mut meta_ct)
        .map_err(|e| format!("读取清单失败: {}", e))?;
    let meta = crypto::decrypt(key, &meta_ct)?;
    Ok((f, meta))
}

/// Decrypt a streamed (mode 3) vault. Reads each file's chunked-AEAD blob
/// sequentially from `file` and streams the plaintext to disk, so memory stays
/// flat regardless of file size.
fn decrypt_folder_full_stream(
    folder: &Path,
    key: &Key,
    file: File,
    meta: &[u8],
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
    let entries = parse_meta_full(meta)?;
    let total = entries.len();
    let mut reader = BufReader::new(file);
    let mut file_count = 0usize;

    for (i, (rel, is_dir)) in entries.iter().enumerate() {
        let target = folder.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        if *is_dir {
            fs::create_dir_all(&target)
                .map_err(|e| format!("创建目录失败 {}: {}", target.display(), e))?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("创建父目录失败: {}", e))?;
            }
            let tmp = target.with_extension("flocktmp");
            {
                let mut out = BufWriter::new(
                    File::create(&tmp)
                        .map_err(|e| format!("创建文件失败 {}: {}", target.display(), e))?,
                );
                crypto::decrypt_stream(key, &mut reader, &mut out)?;
                let f = out.into_inner().map_err(|e| format!("写入文件失败: {}", e))?;
                f.sync_all().ok();
            }
            fs::rename(&tmp, &target).map_err(|e| format!("重命名文件失败: {}", e))?;
            file_count += 1;
        }
        progress(i + 1, total);
    }
    Ok(file_count)
}

/// Decrypt the vault, auto-detecting full vs simple mode.
/// Returns the number of files restored.
pub fn decrypt_folder(folder: &Path, key: &Key) -> Result<usize, String> {
    decrypt_folder_with_progress(folder, key, &|_, _| {})
}

/// Same as [`decrypt_folder`], but reports `(done, total)` after each entry so
/// a GUI can drive a progress bar. `progress` is called from the calling
/// thread. Idempotent: safe to re-run after an interrupt.
pub fn decrypt_folder_with_progress(
    folder: &Path,
    key: &Key,
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
    let mode = read_vault_mode(folder)?;

    // Validate the password and start work. For the streamed mode we only read
    // the small metadata up front (never the whole vault); other modes decrypt
    // their small manifest as before. A wrong password fails here (`?`) before
    // the journal is touched.
    let result = if mode == MODE_FULL_STREAM {
        let (file, meta) = open_stream_meta(folder, key)?;
        write_pending(folder, PendingOp::Decrypt);
        decrypt_folder_full_stream(folder, key, file, &meta, progress)
    } else {
        let (m, manifest) = read_and_decrypt_manifest(folder, key)?;
        write_pending(folder, PendingOp::Decrypt);
        match m {
            MODE_FULL => decrypt_folder_full(folder, key, &manifest, progress),
            MODE_SIMPLE => decrypt_folder_simple(folder, key, &manifest, progress),
            MODE_MOVE => decrypt_folder_move(folder, key, &manifest, progress),
            _ => Err(format!("未知的 vault 模式: {}", m)),
        }
    };

    // On full success: remove the vault and clear the journal. On error (e.g.
    // some data truly lost) keep both so the situation stays inspectable.
    if result.is_ok() {
        let _ = fs::remove_file(folder.join(VAULT_FILE));
        clear_pending(folder);
    }
    result
}

/// Resume an interrupted *encrypt*. Reads the vault (which validates the
/// password via GCM), finishes moving/copying files idempotently, finalizes the
/// container, and clears the journal.
pub fn resume_encrypt(
    folder: &Path,
    key: &Key,
    progress: &dyn Fn(usize, usize),
) -> Result<usize, String> {
    let mode = read_vault_mode(folder)?;
    let count = match mode {
        MODE_FULL_STREAM => {
            // Streamed full vault is atomic (temp + rename); if it exists it is
            // complete, so only the plaintext originals remain to remove. Read
            // just the metadata (validates password) to count files.
            let (_f, meta) = open_stream_meta(folder, key)?;
            let entries = parse_meta_full(&meta)?;
            let n = entries.iter().filter(|(_, is_dir)| !*is_dir).count();
            delete_tree(folder)?;
            n
        }
        MODE_FULL => {
            // Legacy inline full vault already holds every file; the only
            // unfinished step is removing the plaintext originals.
            let (_m, manifest) = read_and_decrypt_manifest(folder, key)?;
            let n = manifest_file_count_full(&manifest)?;
            delete_tree(folder)?;
            n
        }
        MODE_SIMPLE => {
            let (_m, manifest) = read_and_decrypt_manifest(folder, key)?;
            let file_rels = parse_simple_file_rels(MAGIC_SIMPLE, &manifest)?;
            let n = apply_simple_lock(folder, &file_rels, progress)?;
            delete_tree(folder)?;
            n
        }
        MODE_MOVE => {
            let (_m, manifest) = read_and_decrypt_manifest(folder, key)?;
            let file_rels = parse_simple_file_rels(MAGIC_MOVE, &manifest)?;
            let n = apply_move_lock(folder, &file_rels, progress)?;
            delete_tree(folder)?;
            let data_dir = folder.join(DATA_DIR);
            hide_file(&data_dir);
            acl_deny_everyone(&data_dir);
            n
        }
        _ => return Err(format!("未知的 vault 模式: {}", mode)),
    };
    clear_pending(folder);
    Ok(count)
}

/// Parse a simple/move manifest and return the `(rel, stream_or_name)` pairs
/// for files only (directories are skipped). Used by the resume path.
fn parse_simple_file_rels(magic: &[u8; 8], manifest: &[u8]) -> Result<Vec<(String, String)>, String> {
    if manifest.len() < 8 + 2 + 4 {
        return Err("vault 数据损坏".into());
    }
    if &manifest[0..8] != magic {
        return Err("vault 标识不匹配".into());
    }
    let count = u32::from_le_bytes([manifest[10], manifest[11], manifest[12], manifest[13]]) as usize;
    let mut pos = 14;
    let mut out: Vec<(String, String)> = Vec::new();
    for _ in 0..count {
        let (plen, consumed) = read_u32(manifest, pos)?;
        pos += consumed;
        let rel_bytes = manifest.get(pos..pos + plen as usize).ok_or("vault 数据损坏 (path)")?;
        pos += plen as usize;
        let rel = std::str::from_utf8(rel_bytes).map_err(|_| "vault 路径不是有效 UTF-8".to_string())?;
        if rel.split('/').any(|c| c == "..") || rel.starts_with('/') || rel.contains('\\') {
            return Err(format!("拒绝不安全的路径: {}", rel));
        }
        let kind = *manifest.get(pos).ok_or("vault 数据损坏 (kind)")?;
        pos += 1;
        if kind == 0 {
            let (nlen, consumed) = read_u32(manifest, pos)?;
            pos += consumed;
            let name_bytes = manifest.get(pos..pos + nlen as usize).ok_or("vault 数据损坏 (name)")?;
            pos += nlen as usize;
            let name = std::str::from_utf8(name_bytes).map_err(|_| "名称无效".to_string())?;
            if name.contains('/') || name.contains('\\') || name == ".." {
                return Err(format!("拒绝不安全的容器名: {}", name));
            }
            out.push((rel.to_string(), name.to_string()));
        }
    }
    Ok(out)
}

/// Count the file (non-dir) entries in a full-mode manifest.
fn manifest_file_count_full(manifest: &[u8]) -> Result<usize, String> {
    if manifest.len() < 8 + 2 + 4 {
        return Err("vault 数据损坏".into());
    }
    if &manifest[0..8] != MAGIC_FULL {
        return Err("vault 标识不匹配".into());
    }
    let count = u32::from_le_bytes([manifest[10], manifest[11], manifest[12], manifest[13]]) as usize;
    let mut pos = 14;
    let mut files = 0usize;
    for _ in 0..count {
        let (plen, consumed) = read_u32(manifest, pos)?;
        pos += consumed;
        pos += plen as usize;
        let kind = *manifest.get(pos).ok_or("vault 数据损坏 (kind)")?;
        pos += 1;
        let (dlen, consumed) = read_u64(manifest, pos)?;
        pos += consumed;
        pos += dlen as usize;
        if kind == 0 {
            files += 1;
        }
    }
    Ok(files)
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
