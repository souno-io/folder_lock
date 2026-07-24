//! Cryptographic primitives: Argon2id key derivation + AES-256-GCM.

use aes_gcm::{
    aead::{
        generic_array::GenericArray,
        stream::{DecryptorBE32, EncryptorBE32},
        Aead, KeyInit,
    },
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use std::io::{Read, Write};
use zeroize::Zeroize;

/// 32-byte AES-256 key.
pub type Key = [u8; 32];
/// 16-byte Argon2 salt.
pub type Salt = [u8; 16];

/// Argon2id parameters. Memory-hard to resist GPU/ASIC brute force.
/// m_cost is in KiB: 64 MiB. t_cost = 3 passes. p_cost = 1 lane.
const ARGON2_M_COST: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// Derive a 32-byte key from a password and salt using Argon2id.
pub fn derive_key(password: &[u8], salt: &Salt) -> Result<Key, String> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| format!("Argon2 参数错误: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| format!("密钥派生失败: {}", e))?;
    Ok(key)
}

/// Generate a random salt.
pub fn random_salt() -> Salt {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generate a random 12-byte nonce.
fn random_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypt `plaintext` with `key`. Returns nonce || ciphertext (ciphertext
/// includes the GCM authentication tag).
pub fn encrypt(key: &Key, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = random_nonce();
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| format!("加密失败: {}", e))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt data previously produced by [`encrypt`].
/// Wrong password => GCM tag verification fails => Err.
pub fn decrypt(key: &Key, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 13 {
        return Err("密文数据太短".into());
    }
    let (nonce_bytes, ct) = data.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| "解密失败：密码错误或数据已损坏".to_string())?;
    Ok(pt)
}

/// Best-effort: zero out a key in memory.
pub fn zero_key(key: &mut Key) {
    key.zeroize();
}

// ────────────────────────────────────── streaming AEAD ──
//
// For large payloads the one-shot [`encrypt`]/[`decrypt`] would hold the whole
// plaintext *and* ciphertext in RAM. The STREAM construction (Rogaway et al.,
// as implemented by `aead::stream`) instead authenticates fixed-size chunks
// independently, so encrypting/decrypting a file only ever buffers a couple of
// chunks regardless of file size.
//
// Self-delimiting on-disk blob layout (so several files can be concatenated in
// one vault and read back sequentially):
// ```text
//   [stream nonce: 7 bytes]        (12-byte GCM nonce minus the 5-byte STREAM overhead)
//   repeat until a chunk with flag == 1:
//       [flag: u8]                 0 = more chunks follow, 1 = last chunk
//       [ct_len: u32 LE]
//       [ct bytes]                 chunk ciphertext incl. 16-byte GCM tag
// ```

/// Plaintext chunk size for streaming (1 MiB). Ciphertext adds a 16-byte tag.
const STREAM_CHUNK: usize = 1 << 20;

/// Fill `buf` from `r`, tolerating short reads; returns bytes read (0 = EOF).
fn read_fill(r: &mut impl Read, buf: &mut [u8]) -> Result<usize, String> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("读取失败: {}", e)),
        }
    }
    Ok(filled)
}

fn write_frame(w: &mut impl Write, flag: u8, ct: &[u8]) -> Result<(), String> {
    w.write_all(&[flag]).map_err(|e| format!("写入分块失败: {}", e))?;
    w.write_all(&(ct.len() as u32).to_le_bytes())
        .map_err(|e| format!("写入分块长度失败: {}", e))?;
    w.write_all(ct).map_err(|e| format!("写入分块失败: {}", e))?;
    Ok(())
}

/// Stream-encrypt everything from `reader` into `writer` using chunked AEAD.
/// Bounded memory: only a couple of `STREAM_CHUNK`-sized buffers are live.
pub fn encrypt_stream(
    key: &Key,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<(), String> {
    let mut nonce = [0u8; 7];
    rand::thread_rng().fill_bytes(&mut nonce);
    writer
        .write_all(&nonce)
        .map_err(|e| format!("写入 nonce 失败: {}", e))?;

    let key_ga = GenericArray::from_slice(key);
    let nonce_ga = GenericArray::from_slice(&nonce);
    let mut enc = EncryptorBE32::<Aes256Gcm>::new(key_ga, nonce_ga);

    // Read one chunk ahead so we know which chunk is the last (STREAM tags the
    // final chunk differently). An empty input becomes a single empty last chunk.
    let mut cur = vec![0u8; STREAM_CHUNK];
    let mut cur_len = read_fill(reader, &mut cur)?;
    loop {
        let mut nxt = vec![0u8; STREAM_CHUNK];
        let nxt_len = read_fill(reader, &mut nxt)?;
        if nxt_len == 0 {
            let ct = enc
                .encrypt_last(&cur[..cur_len])
                .map_err(|e| format!("加密失败: {}", e))?;
            write_frame(writer, 1, &ct)?;
            break;
        }
        let ct = enc
            .encrypt_next(&cur[..cur_len])
            .map_err(|e| format!("加密失败: {}", e))?;
        write_frame(writer, 0, &ct)?;
        cur = nxt;
        cur_len = nxt_len;
    }
    Ok(())
}

/// Reverse of [`encrypt_stream`]: read the nonce + framed chunks from `reader`,
/// decrypt each, and write the plaintext to `writer`. Stops after the last
/// chunk, leaving `reader` positioned at the next blob. A wrong key/corruption
/// fails GCM authentication.
pub fn decrypt_stream(
    key: &Key,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<(), String> {
    let mut nonce = [0u8; 7];
    reader
        .read_exact(&mut nonce)
        .map_err(|e| format!("读取 nonce 失败: {}", e))?;

    let key_ga = GenericArray::from_slice(key);
    let nonce_ga = GenericArray::from_slice(&nonce);
    let mut dec = DecryptorBE32::<Aes256Gcm>::new(key_ga, nonce_ga);

    loop {
        let mut flag = [0u8; 1];
        reader
            .read_exact(&mut flag)
            .map_err(|e| format!("读取分块标志失败: {}", e))?;
        let mut len_b = [0u8; 4];
        reader
            .read_exact(&mut len_b)
            .map_err(|e| format!("读取分块长度失败: {}", e))?;
        let len = u32::from_le_bytes(len_b) as usize;
        let mut ct = vec![0u8; len];
        reader
            .read_exact(&mut ct)
            .map_err(|e| format!("读取分块失败: {}", e))?;
        if flag[0] == 1 {
            let pt = dec
                .decrypt_last(ct.as_slice())
                .map_err(|_| "解密失败：密码错误或数据已损坏".to_string())?;
            writer
                .write_all(&pt)
                .map_err(|e| format!("写入文件失败: {}", e))?;
            break;
        }
        let pt = dec
            .decrypt_next(ct.as_slice())
            .map_err(|_| "解密失败：密码错误或数据已损坏".to_string())?;
        writer
            .write_all(&pt)
            .map_err(|e| format!("写入文件失败: {}", e))?;
    }
    Ok(())
}

/// Constant-time password comparison for the confirmation step.
pub fn passwords_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
