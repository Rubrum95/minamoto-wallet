// High-level wallet operations.
//
// Architecture (Phase 1, SE-wrap):
//
//   1. Generate 32 random bytes (Ed25519 seed).
//   2. Generate a P-256 keypair INSIDE the Secure Enclave with biometric
//      ACL `[BiometryAny .or. DevicePasscode]`. Private half never leaves
//      the chip.
//   3. ECIES-encrypt the seed to the SE keypair. Ciphertext goes to a
//      JSON file at ~/Library/Application Support/minamoto-wallet/.
//   4. Zeroize the plaintext seed.
//
// Each subsequent signing operation:
//   1. Read ciphertext from disk.
//   2. SecKeyCreateDecryptedData with the SE private key → Touch ID prompt
//      → 32-byte plaintext seed in our process for ~ms.
//   3. Build iroha_crypto::PrivateKey, sign, drop (auto-zeroize).
//
// See ./MIGRATION.md for the planned move to YubiKey 5C in Phase 2.

use crate::biometric;
use crate::consts::NETWORK_PREFIX;
use crate::password;
use crate::secure_enclave;
use crate::storage;
use anyhow::{Context, Result, anyhow, bail};
use bip39::{Language, Mnemonic};
use iroha_crypto::{Algorithm, KeyPair, PrivateKey, PublicKey};
use iroha_data_model::account::AccountId;
use rand::RngCore;
use zeroize::Zeroizing;

/// Fields a freshly-created wallet returns to the caller.
pub struct GeneratedWallet {
    pub label: String,
    pub public_key_hex: String,
    pub i105_address: String,
    /// 24-word BIP39 mnemonic. Caller must display once and never store.
    pub mnemonic: Zeroizing<String>,
}

pub fn generate(label: &str, password: &str) -> Result<GeneratedWallet> {
    validate_password(password)?;
    if storage::exists(label) {
        bail!(
            "Wallet '{label}' already exists. Run `delete` first to overwrite (this destroys all key material irreversibly)."
        );
    }

    // 32 bytes of OS entropy. `Zeroizing` ensures unwind-safe wipe.
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut_slice());

    // BIP39 24-word mnemonic from the same entropy. This is OUR backup
    // format — Iroha 3 has no native BIP39. The mnemonic is the ONLY way
    // to recover the wallet if the encrypted file is lost (drive wipe,
    // OS reinstall, accidental delete, etc.). The password protects the
    // file, the mnemonic is the disaster-recovery backup.
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &*seed)
        .context("BIP39 mnemonic generation requires 32-byte entropy")?;
    let mnemonic_str = Zeroizing::new(mnemonic.to_string());

    let pubkey = derive_public_key(&seed)?;
    let pubkey_hex = format_public_key_hex(&pubkey);
    let i105 = derive_i105_address(&pubkey)?;

    // Encrypt seed under argon2id-derived KEK + AES-256-GCM. Slow on
    // purpose (~1s) — that latency is the brute-force defence.
    eprintln!("[wallet] deriving KEK with argon2id (this takes ~1s)…");
    let encrypted = password::encrypt_seed(password, &seed)
        .context("password-encrypt seed failed")?;

    // Persist record.
    let record = storage::new_record(
        label.to_string(),
        NETWORK_PREFIX,
        pubkey_hex.clone(),
        i105.clone(),
        encrypted,
    );
    let path = storage::save(&record).context("storage::save failed")?;
    eprintln!("[wallet] record saved to {}", path.display());

    // `seed` Zeroizing drops here. From this moment the only path back
    // to the seed is the password → argon2id → AES-GCM decrypt.
    Ok(GeneratedWallet {
        label: label.to_string(),
        public_key_hex: pubkey_hex,
        i105_address: i105,
        mnemonic: mnemonic_str,
    })
}

pub fn restore_from_mnemonic(
    label: &str,
    mnemonic_phrase: &str,
    password: &str,
) -> Result<GeneratedWallet> {
    validate_password(password)?;
    if storage::exists(label) {
        bail!("Wallet '{label}' already exists.");
    }

    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase.trim())
        .context("invalid BIP39 mnemonic — check word count (24) and spelling")?;
    let entropy = mnemonic.to_entropy();
    if entropy.len() != 32 {
        bail!("mnemonic decoded to {} bytes; expected 32", entropy.len());
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&entropy);

    let pubkey = derive_public_key(&seed)?;
    let pubkey_hex = format_public_key_hex(&pubkey);
    let i105 = derive_i105_address(&pubkey)?;

    eprintln!("[wallet] deriving KEK with argon2id (this takes ~1s)…");
    let encrypted = password::encrypt_seed(password, &seed)
        .context("password-encrypt seed failed")?;

    let record = storage::new_record(
        label.to_string(),
        NETWORK_PREFIX,
        pubkey_hex.clone(),
        i105.clone(),
        encrypted,
    );
    storage::save(&record).context("storage::save failed")?;

    Ok(GeneratedWallet {
        label: label.to_string(),
        public_key_hex: pubkey_hex,
        i105_address: i105,
        mnemonic: Zeroizing::new(mnemonic_phrase.trim().to_string()),
    })
}

/// Reasonable minimum so we don't accept "a" or empty as password.
/// We do NOT enforce complexity rules (numbers, symbols) — argon2id
/// makes a 12-char passphrase already very strong, and forcing rules
/// is known to push users toward predictable patterns.
fn validate_password(password: &str) -> Result<()> {
    if password.len() < 8 {
        bail!("password must be at least 8 characters (use a passphrase, not a word)");
    }
    Ok(())
}

/// Return public key + I105 from the on-disk record. Does NOT require
/// Touch ID — the JSON file already has them.
pub fn pubkey_and_address(label: &str) -> Result<(String, String)> {
    let record = storage::load(label)?;
    Ok((record.public_key_hex, record.i105_address))
}

/// Migrate a v1 SE-wrap wallet to a v2 password-encrypted wallet.
/// Touch ID once (to unwrap the v1 seed) → user types new password
/// (twice) → we re-encrypt + overwrite the JSON + delete the SE key.
///
/// Notes preserved across the migration. `registered_on_chain` flag
/// preserved.
pub fn migrate_v1_to_v2(label: &str, new_password: &str) -> Result<()> {
    validate_password(new_password)?;
    let record = storage::load(label)?;
    if record.version != storage::LEGACY_VERSION {
        bail!(
            "wallet '{label}' is already v{} — nothing to migrate",
            record.version
        );
    }

    // Touch ID + SE unwrap (the v1 path).
    let reason = format!("Migrate '{label}' to password-encrypted format");
    biometric::prompt(&reason)
        .with_context(|| format!("biometric gate denied for '{label}'"))?;
    let ciphertext = storage::decode_wrapped(&record)?;
    let seed = secure_enclave::unwrap_seed(label, &ciphertext)
        .with_context(|| format!("legacy seed unwrap failed for '{label}'"))?;

    // Build v2 envelope from the same seed. Salt + nonce are fresh.
    eprintln!("[wallet] re-encrypting seed under password (argon2id ~1s)…");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed[..]);
    let encrypted = password::encrypt_seed(new_password, &seed_array)?;
    // Drop the unprotected copy promptly.
    let _ = seed_array.iter().fold(0u8, |a, b| a ^ b);

    // Build the new record carrying forward existing notes + flag.
    let mut new_record = storage::new_record(
        record.label.clone(),
        record.network_prefix,
        record.public_key_hex.clone(),
        record.i105_address.clone(),
        encrypted,
    );
    new_record.notes = record.notes.clone();
    new_record.registered_on_chain = record.registered_on_chain;

    // Atomic-ish replace: delete then save. (storage::save refuses to
    // overwrite, so we delete the old file first; on a crash between
    // these two steps the user re-runs the command and Touch IDs again.)
    storage::delete(label)?;
    storage::save(&new_record).context("save migrated record failed")?;

    // Best-effort: remove the now-unused SE key. Don't fail the
    // migration if it's already gone or returns an error.
    let _ = secure_enclave::delete(label);

    eprintln!("[wallet] '{label}' migrated to v2; SE key removed");
    Ok(())
}

/// Delete both the on-disk record AND the SE private key. macOS may
/// prompt Touch ID for the SE deletion.
pub fn delete(label: &str) -> Result<()> {
    // Delete SE first; if it fails, we keep the record so the user can
    // retry. Otherwise we'd be stuck with a SE key we can't reference.
    if secure_enclave::exists(label) {
        secure_enclave::delete(label)
            .with_context(|| format!("SE delete failed for '{label}'"))?;
    }
    storage::delete(label).context("storage::delete failed")?;
    Ok(())
}

/// Unwrap the 32-byte seed using whichever method matches the record
/// version on disk:
///
/// - **v2 (current)**: requires `password`. Touch ID is optional —
///   the cryptographic gate is the password; biometric is just a
///   user-confirmation gesture you can layer on top.
/// - **v1 (legacy)**: requires Touch ID + the SE wrap. `password` is
///   ignored (passing `None` is fine).
///
/// `reason` is shown in the Touch ID dialog (v1) or to disambiguate
/// the password prompt (v2). Callers should be specific: "Send 1 XOR
/// to <recipient>" rather than "Sign transaction".
pub fn unlock_seed(
    label: &str,
    reason: &str,
    password: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>> {
    let record = storage::load(label)?;
    match record.version {
        v if v == storage::CURRENT_VERSION => {
            let pw = password.ok_or_else(|| {
                anyhow!("v2 wallet '{label}' requires a password to unlock")
            })?;
            let enc = record.password_encrypted.as_ref().ok_or_else(|| {
                anyhow!("v2 record missing password_encrypted block")
            })?;
            // No biometric prompt here. v2 auth is the wallet password
            // (argon2id-derived KEK + AES-GCM); a decorative LAContext
            // popup confused users into thinking the macOS password was
            // the gate. Touch ID is reserved for explicit elevation
            // gates (e.g. delete confirmation in ui.rs), where it
            // serves a clear "this is destructive" purpose.
            let _ = reason; // intentionally unused for v2
            password::decrypt_seed(enc, pw)
                .with_context(|| format!("password unwrap failed for '{label}'"))
        }
        v if v == storage::LEGACY_VERSION => {
            biometric::prompt(reason)
                .with_context(|| format!("biometric gate denied for '{label}'"))?;
            let ciphertext = storage::decode_wrapped(&record)?;
            secure_enclave::unwrap_seed(label, &ciphertext)
                .with_context(|| format!("legacy seed unwrap failed for '{label}'"))
        }
        v => bail!("unsupported record version {v}"),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

pub(crate) fn derive_public_key(seed: &Zeroizing<[u8; 32]>) -> Result<PublicKey> {
    let kp = KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519);
    let (pk, _sk) = kp.into_parts();
    Ok(pk)
}

#[allow(dead_code)] // used by transfer.rs once that module lands
pub(crate) fn derive_private_key(seed: &Zeroizing<[u8; 32]>) -> Result<PrivateKey> {
    let kp = KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519);
    let (_pk, sk) = kp.into_parts();
    Ok(sk)
}

pub fn format_public_key_hex(pk: &PublicKey) -> String {
    let (_algo, payload) = pk.to_bytes();
    format!("ed0120{}", hex::encode(payload))
}

pub fn derive_i105_address(pk: &PublicKey) -> Result<String> {
    let account_id = AccountId::new(pk.clone());
    let i105 = account_id
        .to_i105_for_discriminant(NETWORK_PREFIX)
        .map_err(|e| anyhow!("I105 encoding failed: {e:?}"))?;
    Ok(i105)
}
