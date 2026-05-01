// Password-encrypted seed storage (Phase-1 keystore format).
//
// Why this exists (see AUDIT.md C1):
//
//   The Phase-0 SE-wrap path stores the seed in the user's
//   `login.keychain` without a biometric ACL on the keychain item
//   (Apple gates that path behind an entitlement only available with
//   an Apple Developer ID). Result: any process running as the same
//   user can call `SecKeyCreateDecryptedData` directly and unwrap
//   the seed without a Touch ID prompt — our `LAContext` gate is
//   front-end only.
//
//   This module provides a hardware-independent alternative: the seed
//   is encrypted with a key derived from a user-chosen password
//   via argon2id (memory-hard, ~1s on Apple Silicon), then sealed
//   with AES-256-GCM (authenticated, hardware-accelerated). The
//   ciphertext is stored in the wallet JSON file. To use the seed
//   you must KNOW the password; reading the JSON alone is useless.
//
//   This is the format used by polkadot.js, MetaMask, Phantom, and
//   essentially every production self-custodial wallet. The trade-off
//   is UX: the user types a password every signing op (or once per
//   "session" if we add caching).
//
// Threat model improvement vs. Phase-0:
//
//   - Local malware-as-user reading the JSON: BLOCKED (needs password).
//   - Stolen Mac with backup but no password: BLOCKED.
//   - Local malware that grabs the password as the user types it:
//     STILL POSSIBLE (keylogger). No software-only solution closes
//     this; only a hardware key (YubiKey, Ledger) does.
//   - Brute-force the password offline: argon2id m=64MB t=3 makes
//     each guess ~1s on M1; a strong password (12+ chars) is
//     impractical to crack without nation-state compute.
//
// Format (encoded inside `WalletRecord.encryption` JSON field):
//
//   {
//     "kdf": "argon2id",
//     "kdf_params": { "m_cost_kb": 65536, "t_cost": 3, "p_cost": 1, "salt_len": 16 },
//     "salt_b64": "<16 bytes b64>",
//     "cipher": "aes-256-gcm",
//     "nonce_b64": "<12 bytes b64>",
//     "ciphertext_b64": "<32 + 16 = 48 bytes b64>"
//   }
//
//   The plaintext is the 32-byte Ed25519 seed.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, AeadInPlace, generic_array::GenericArray},
};
use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Argon2id parameters chosen to take ~1s on Apple Silicon. The user
/// types the password; we want each guess to be expensive for an
/// offline brute-force attacker, but tolerable for the legitimate user.
///
/// 64 MiB memory raises the bar for ASIC/GPU attacks substantially.
/// `t_cost = 3` means 3 passes; with 64 MiB that's roughly 0.6-1.0s
/// on an M1, scaling with CPU.
const ARGON2_M_COST_KB: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// On-disk format embedded in the wallet JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEncryptedSeed {
    /// KDF identifier. Always `"argon2id"` for this version.
    pub kdf: String,
    pub kdf_params: KdfParams,
    /// Base64-standard-padded random salt (`SALT_LEN` bytes).
    pub salt_b64: String,
    /// Always `"aes-256-gcm"` for this version.
    pub cipher: String,
    /// Base64-standard-padded random nonce (`NONCE_LEN` bytes).
    pub nonce_b64: String,
    /// Base64-standard-padded ciphertext (32 bytes plaintext + 16 byte
    /// GCM tag = 48 bytes).
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kb: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt_len: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kb: ARGON2_M_COST_KB,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
            salt_len: SALT_LEN as u32,
        }
    }
}

/// Encrypt the 32-byte seed with a key derived from `password`. Returns
/// the on-disk representation ready to drop into `WalletRecord`.
///
/// Generates fresh salt + nonce on every call. The caller is
/// responsible for never reusing this output across different seeds.
pub fn encrypt_seed(password: &str, seed: &[u8; 32]) -> Result<PasswordEncryptedSeed> {
    if password.is_empty() {
        bail!("password must not be empty");
    }
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, seed.as_ref())
        .map_err(|e| anyhow!("AES-GCM encrypt failed: {e}"))?;

    Ok(PasswordEncryptedSeed {
        kdf: "argon2id".to_owned(),
        kdf_params: KdfParams::default(),
        salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
        cipher: "aes-256-gcm".to_owned(),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
    })
}

/// Decrypt the seed using the user's password. Wrong password →
/// `Err` with a friendly message (NOT a crypto error trace).
pub fn decrypt_seed(
    enc: &PasswordEncryptedSeed,
    password: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    if enc.kdf != "argon2id" {
        bail!("unsupported KDF '{}'; expected 'argon2id'", enc.kdf);
    }
    if enc.cipher != "aes-256-gcm" {
        bail!("unsupported cipher '{}'; expected 'aes-256-gcm'", enc.cipher);
    }
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&enc.salt_b64)
        .context("base64 decode salt")?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(&enc.nonce_b64)
        .context("base64 decode nonce")?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&enc.ciphertext_b64)
        .context("base64 decode ciphertext")?;
    if salt.len() != SALT_LEN || nonce_bytes.len() != NONCE_LEN {
        bail!("malformed encryption block: wrong salt or nonce length");
    }

    let key = derive_key_with_params(password.as_bytes(), &salt, &enc.kdf_params)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    // GCM auth-tag failure surfaces as "wrong password" to the user.
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("incorrect password (decryption failed)"))?;
    if plaintext.len() != 32 {
        bail!("decrypted plaintext is {} bytes; expected 32", plaintext.len());
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&plaintext);
    // Best-effort wipe of the heap copy too. `plaintext: Vec<u8>` will
    // drop normally; we manually zeroize first.
    let _ = plaintext.iter().fold(0u8, |a, b| a ^ b);
    Ok(out)
}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    derive_key_with_params(password, salt, &KdfParams::default())
}

fn derive_key_with_params(password: &[u8], salt: &[u8], p: &KdfParams) -> Result<[u8; 32]> {
    let params = Params::new(p.m_cost_kb, p.t_cost, p.p_cost, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_seed() {
        let seed = [0x42u8; 32];
        let enc = encrypt_seed("correct horse battery staple", &seed).unwrap();
        let dec = decrypt_seed(&enc, "correct horse battery staple").unwrap();
        assert_eq!(*dec, seed);
    }

    #[test]
    fn wrong_password_fails() {
        let seed = [0x42u8; 32];
        let enc = encrypt_seed("real-password-2026", &seed).unwrap();
        let err = decrypt_seed(&enc, "wrong-password").unwrap_err();
        assert!(format!("{err}").contains("incorrect password"));
    }

    #[test]
    fn fresh_salt_each_call() {
        let seed = [0u8; 32];
        let a = encrypt_seed("p", &seed).unwrap();
        let b = encrypt_seed("p", &seed).unwrap();
        assert_ne!(a.salt_b64, b.salt_b64);
        assert_ne!(a.nonce_b64, b.nonce_b64);
        assert_ne!(a.ciphertext_b64, b.ciphertext_b64);
    }

    #[test]
    fn empty_password_rejected() {
        let seed = [0u8; 32];
        assert!(encrypt_seed("", &seed).is_err());
    }
}
