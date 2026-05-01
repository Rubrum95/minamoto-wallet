// Disk storage for wallet metadata + SE-wrapped Ed25519 seed ciphertext.
//
// One JSON file per wallet, located at:
//
//   ~/Library/Application Support/minamoto-wallet/<label>.json
//
// File contents are NOT secret — the ciphertext is useless without the
// SE-resident private key, which never leaves the chip. We still set
// 0600 permissions so prying eyes can't read it (defense in depth).
//
// We intentionally choose `Application Support` over `Documents` /
// `Desktop` so the file is excluded from iCloud Drive sync by default.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// One wallet record on disk.
///
/// Two formats coexist:
///
/// - **v1 (legacy SE-wrap)**: `wrapped_seed_b64` carries the ECIES
///   ciphertext produced by `secure_enclave::wrap_seed`. The seed is
///   recovered by `SecKeyCreateDecryptedData` against a P-256 key in
///   `login.keychain`. No password required, but local-malware-as-user
///   can bypass our Touch ID gate (see `AUDIT.md` C1).
/// - **v2 (password-encrypted)**: `password_encrypted` carries an
///   argon2id-derived AES-256-GCM ciphertext of the seed. Recovery
///   requires the user password. Local malware reading the file gets
///   no closer to the seed than an offline brute-force attempt
///   against argon2id (m=64MB, t=3) — impractical without the
///   password.
///
/// Loaders dispatch on `version`. Generators of new wallets always
/// emit v2; v1 records are preserved untouched until the user runs
/// `migrate-to-v2` (see `wallet.rs`).
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletRecord {
    /// User-chosen label, also keys the Secure Enclave entry.
    pub label: String,
    /// Network discriminant prefix (753 for Minamoto). Stored so the file
    /// remains self-describing even if `consts.rs` changes.
    pub network_prefix: u16,
    /// Ed25519 public key, prefixed with the multihash tag `ed0120`.
    pub public_key_hex: String,
    /// I105 canonical address. Stored to avoid recomputing on every read.
    pub i105_address: String,
    /// **v1 only.** ECIES ciphertext of the 32-byte Ed25519 seed.
    /// Empty string for v2 records.
    #[serde(default)]
    pub wrapped_seed_b64: String,
    /// **v2 only.** Password-encrypted seed envelope. `None` for v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_encrypted: Option<crate::password::PasswordEncryptedSeed>,
    /// ISO-8601 timestamp in UTC.
    pub created_at: String,
    /// File-format version. 1 = legacy SE-wrap, 2 = password-encrypted.
    pub version: u32,
    /// Confidential notes we have created via Shield. Stored here so
    /// the wallet can later spend them (Phase 2: Unshield/ZkTransfer).
    /// Empty by default — `Default` skips serialisation when missing
    /// to keep older v1 files readable.
    #[serde(default)]
    pub notes: Vec<crate::shield::LocalNote>,

    /// Whether this account has been formally registered on chain via
    /// `Register::Account`. Default false; set to true after a Committed
    /// register tx (either standalone or batched in front of the first
    /// Transfer/Shield). Implicit accounts created via cross-chain claim
    /// CANNOT spend their balance until they are formally registered —
    /// without this step, `withdraw_numeric_asset` fails with "Failed to
    /// find asset" even though the asset is visible in the explorer.
    #[serde(default)]
    pub registered_on_chain: bool,
}

/// File format version we EMIT for newly-created wallets. Older v1
/// records on disk are still loaded (see `load`), but every fresh
/// `generate`/`restore_from_mnemonic` produces v2.
pub const CURRENT_VERSION: u32 = 2;
pub const LEGACY_VERSION: u32 = 1;

/// Resolve the directory we use for wallet records, creating it if missing.
pub fn wallet_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME not set"))?;
    let mut p = PathBuf::from(home);
    p.push("Library");
    p.push("Application Support");
    p.push("minamoto-wallet");
    if !p.exists() {
        fs::create_dir_all(&p)
            .with_context(|| format!("failed to create wallet dir at {p:?}"))?;
        // Tighten dir perms to 0700 so other users on this Mac (rare on
        // single-user laptops, but possible) can't see our file names.
        let mut perms = fs::metadata(&p)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&p, perms)?;
    }
    Ok(p)
}

fn record_path(label: &str) -> Result<PathBuf> {
    if label.is_empty() || label.contains('/') || label.contains('\0') {
        anyhow::bail!("invalid wallet label: {label:?}");
    }
    let mut p = wallet_dir()?;
    p.push(format!("{label}.json"));
    Ok(p)
}

/// Persist a wallet record. Refuses to overwrite an existing file —
/// callers should `delete` first if they really want to replace.
pub fn save(record: &WalletRecord) -> Result<PathBuf> {
    let path = record_path(&record.label)?;
    if path.exists() {
        anyhow::bail!(
            "wallet record already exists at {path:?} — refuse to overwrite"
        );
    }
    let json = serde_json::to_string_pretty(record).context("JSON serialize failed")?;
    fs::write(&path, json).with_context(|| format!("write {path:?}"))?;
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms)?;
    Ok(path)
}

/// Load a wallet record. Errors if missing or malformed.
pub fn load(label: &str) -> Result<WalletRecord> {
    let path = record_path(label)?;
    let json = fs::read_to_string(&path)
        .with_context(|| format!("read {path:?} (does the wallet exist?)"))?;
    let record: WalletRecord =
        serde_json::from_str(&json).with_context(|| format!("parse {path:?}"))?;
    match record.version {
        v if v == CURRENT_VERSION => {
            if record.password_encrypted.is_none() {
                anyhow::bail!(
                    "v{CURRENT_VERSION} record is missing the `password_encrypted` block"
                );
            }
        }
        v if v == LEGACY_VERSION => {
            if record.wrapped_seed_b64.is_empty() {
                anyhow::bail!(
                    "v{LEGACY_VERSION} record is missing the `wrapped_seed_b64` field"
                );
            }
        }
        v => {
            anyhow::bail!(
                "unsupported wallet record version {v}; this binary supports v{LEGACY_VERSION} (legacy) and v{CURRENT_VERSION} (current)"
            );
        }
    }
    Ok(record)
}

/// Whether a wallet record file exists for this label.
pub fn exists(label: &str) -> bool {
    record_path(label)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// List every wallet label currently on disk. Used by the local UI to
/// populate the wallet selector. Returns labels sorted alphabetically.
pub fn list_labels() -> Result<Vec<String>> {
    let dir = wallet_dir()?;
    let mut labels = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("readdir {dir:?}"))? {
        let entry = entry?;
        let name = entry.file_name();
        let s = name.to_string_lossy();
        if let Some(label) = s.strip_suffix(".json") {
            labels.push(label.to_string());
        }
    }
    labels.sort();
    Ok(labels)
}

/// Delete the wallet record file. SE key deletion is the caller's
/// responsibility (see `secure_enclave::delete`).
pub fn delete(label: &str) -> Result<()> {
    let path = record_path(label)?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("rm {path:?}"))?;
    }
    Ok(())
}

/// Build a fresh **v2** (password-encrypted) record. The caller has
/// already produced the `PasswordEncryptedSeed` via
/// `password::encrypt_seed`.
pub fn new_record(
    label: String,
    network_prefix: u16,
    public_key_hex: String,
    i105_address: String,
    encrypted: crate::password::PasswordEncryptedSeed,
) -> WalletRecord {
    use chrono::Utc;
    WalletRecord {
        label,
        network_prefix,
        public_key_hex,
        i105_address,
        wrapped_seed_b64: String::new(),
        password_encrypted: Some(encrypted),
        created_at: Utc::now().to_rfc3339(),
        version: CURRENT_VERSION,
        notes: Vec::new(),
        registered_on_chain: false,
    }
}

/// Build a legacy **v1** record from an SE-wrap ciphertext. Kept only
/// for tests / migration tooling — production no longer creates v1.
#[allow(dead_code)]
pub fn new_record_v1(
    label: String,
    network_prefix: u16,
    public_key_hex: String,
    i105_address: String,
    wrapped_seed: &[u8],
) -> WalletRecord {
    use base64::Engine;
    use chrono::Utc;
    WalletRecord {
        label,
        network_prefix,
        public_key_hex,
        i105_address,
        wrapped_seed_b64: base64::engine::general_purpose::STANDARD.encode(wrapped_seed),
        password_encrypted: None,
        created_at: Utc::now().to_rfc3339(),
        version: LEGACY_VERSION,
        notes: Vec::new(),
        registered_on_chain: false,
    }
}

/// Persist `registered_on_chain = true` for this wallet. Called after a
/// successful Committed Register::Account (either via the explicit
/// `register-self` command or the auto-register path inside transfer /
/// shield).
pub fn mark_registered(label: &str) -> Result<()> {
    let mut record = load(label)?;
    if record.registered_on_chain {
        return Ok(());
    }
    record.registered_on_chain = true;
    let path = record_path(label)?;
    let json = serde_json::to_string_pretty(&record).context("JSON serialize failed")?;
    fs::write(&path, json).with_context(|| format!("write {path:?}"))?;
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms)?;
    Ok(())
}

/// Append a confidential note (created by `shield`) to the wallet's
/// record on disk. Atomic-by-rewrite: load → mutate → save back. Loses
/// concurrent appends if two processes race, but the wallet is single-
/// user so we don't expect that.
pub fn append_note(label: &str, note: &crate::shield::LocalNote) -> Result<()> {
    let mut record = load(label)?;
    record.notes.push(note.clone());
    let path = record_path(label)?;
    let json = serde_json::to_string_pretty(&record).context("JSON serialize failed")?;
    fs::write(&path, json).with_context(|| format!("write {path:?}"))?;
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms)?;
    Ok(())
}

/// Decode the wrapped seed ciphertext from base64.
pub fn decode_wrapped(record: &WalletRecord) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(&record.wrapped_seed_b64)
        .context("base64 decode of wrapped_seed_b64 failed")
}
