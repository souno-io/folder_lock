//! Cryptographic primitives: Argon2id key derivation + AES-256-GCM.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
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
