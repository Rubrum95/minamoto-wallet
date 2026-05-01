// Shield ISI builder: convert public XOR into a shielded note.
//
// Phase-1 design (current):
//
//   - Build a fresh `rho` (32 random bytes from OsRng).
//   - Derive owner_tag from our spend_key (= the wallet seed) and the
//     default diversifier (Scalar::ONE).
//   - Compute the canonical note_commitment via `zk_v2::derive_confidential_note_v2`.
//   - **Use ConfidentialEncryptedPayload::default()** as the wire payload.
//     This means: nobody else scanning the chain can auto-detect this
//     note. We persist `(rho, amount, owner_tag, asset_def_id)` locally
//     so we can still spend it ourselves.
//   - Build Shield ISI, sign the tx, submit via Torii.
//
// What "default payload" loses:
//   - Recipient view-scanning: the wallet that owns this note can't auto-
//     discover it from the chain. Spending requires the local note record.
//   - Backup: if the local note record is lost, the note becomes orphan
//     (still on-chain, but un-spendable without rho).
//
// What the wire format looks like on-chain (verified end-to-end):
//   instruction = Shield { asset, from, amount, note_commitment, enc_payload }
//   - asset: AssetDefinitionId of XOR
//   - from: our AccountId (the I105)
//   - amount: u128 in user units (1 XOR = 1, NOT 1e18 — Iroha 3 uses
//     numeric arbitrary precision; the runtime accepts u128 directly).
//   - note_commitment: the 32-byte Pasta-LE Poseidon-pair output.
//   - enc_payload: ConfidentialEncryptedPayload::default() (version=1,
//     ephemeral=0×32, nonce=0×24, ciphertext=∅).
//
// Touch ID flow: identical to send_xor — `wallet::unlock_seed` runs
// LAContext + Keychain decrypt to materialise the seed in RAM, sign the
// tx with iroha_crypto::PrivateKey, drop with Zeroize.

use crate::biometric;
use crate::consts::{CHAIN_ID, XOR_ASSET_DEFINITION_ID};
use crate::storage;
use crate::torii;
use crate::wallet;
use crate::zk_v2;
use anyhow::{Context, Result, anyhow, bail};
use iroha_crypto::{Algorithm, KeyPair, PrivateKey, PublicKey};
use iroha_data_model::{
    ChainId,
    account::{AccountId, NewAccount},
    asset::AssetDefinitionId,
    confidential::ConfidentialEncryptedPayload,
    isi::{InstructionBox, Register, zk::Shield},
};
use iroha_version::codec::EncodeVersioned;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// On-disk record of a Shield we created. We persist enough state to
/// reconstruct the spend witness (Phase 2) without needing the chain to
/// re-yield our payload (which would be impossible without an encryption
/// recipe).
///
/// This is appended to the wallet JSON file under `notes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalNote {
    /// Asset def id (e.g. XOR `6TEAJqbb...`).
    pub asset_def_id: String,
    /// Amount in user units (matches what was submitted as u128 to Shield).
    pub amount_u128: String, // serialize as decimal string to preserve full u128 in JSON
    /// 32-byte rho randomness (hex). Required to derive nullifier and
    /// commitment when spending.
    pub rho_hex: String,
    /// 32-byte owner tag (hex). Derived from spend_key + diversifier.
    pub owner_tag_hex: String,
    /// 32-byte commitment (hex). The wire bytes that ended up on chain.
    pub commitment_hex: String,
    /// 32-byte diversifier (hex). For now always Scalar::ONE (default).
    pub diversifier_hex: String,
    /// v2 tx hash on Minamoto where this note was created.
    pub created_tx_hash_hex: String,
    /// ISO-8601 timestamp.
    pub created_at: String,
    /// `true` until we've submitted an Unshield/ZkTransfer that spends it.
    pub spendable: bool,
}

/// Output for the dry-run path: derive but do not sign nor submit.
#[derive(Debug, Serialize)]
pub struct ShieldDryRunOutcome {
    pub amount: String,
    pub recipient_owner_tag_hex: String,
    pub recipient_diversifier_hex: String,
    pub commitment_hex: String,
    pub rho_hex: String,
}

/// Parse a v3 recipient URI, derive the commitment we WOULD have submitted,
/// and return everything without touching the keychain or the chain. Useful
/// to validate a third-party address before committing real XOR.
pub fn shield_dry_run(amount_str: &str, recipient_address: &str) -> Result<ShieldDryRunOutcome> {
    use rand::RngCore;

    let amount: u128 = amount_str
        .parse::<u128>()
        .with_context(|| format!("amount must be a non-negative integer, got '{amount_str}'"))?;
    if amount == 0 {
        bail!("amount must be > 0");
    }
    let parsed = crate::confidential_address::parse(recipient_address)
        .context("failed to parse recipient v3 payment address")?;
    let owner_tag = parsed.owner_tag()?;
    let diversifier = parsed.diversifier()?;
    let mut rho = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut rho);
    let commitment = zk_v2::derive_confidential_note_v2(
        XOR_ASSET_DEFINITION_ID,
        amount,
        rho,
        owner_tag,
    )
    .map_err(|e| anyhow!("commitment derivation: {e}"))?;
    Ok(ShieldDryRunOutcome {
        amount: amount.to_string(),
        recipient_owner_tag_hex: hex::encode(owner_tag),
        recipient_diversifier_hex: hex::encode(diversifier),
        commitment_hex: hex::encode(commitment),
        rho_hex: hex::encode(rho),
    })
}

/// Output for the CLI / UI.
#[derive(Debug, Serialize)]
pub struct ShieldOutcome {
    pub tx_hash_hex: String,
    pub commitment_hex: String,
    pub amount: String,
    pub asset_def_id: String,
    /// 32-byte rho (note randomness) hex-encoded. Always returned. When
    /// shielding to a third party who can't decrypt the payload yet, the
    /// caller MUST share this out-of-band so the recipient can spend.
    pub rho_hex: String,
    /// `true` when the note targets a third-party v3 address (so we did
    /// NOT persist a local LocalNote entry).
    pub paid_to_external_recipient: bool,
}

/// Execute a Shield: build, sign, submit, persist local note.
///
/// `amount_str` is parsed as u128 (whole units). Iroha 3 uses numeric
/// arbitrary precision but Shield's `amount` field is `u128`, so the
/// caller must pre-convert XOR fractions to the smallest unit if needed.
/// For now we assume integer amounts (the simplest path).
///
/// If `recipient_address` is `Some`, the resulting note targets the
/// supplied v3 confidential payment address (their owner_tag/diversifier
/// instead of ours). The note is therefore spendable BY THEM later, not
/// by us — so we deliberately do NOT append it to our local notes file.
/// We do return the rho via `ShieldOutcome.rho_hex` so the caller can
/// share it out-of-band with the recipient (until the encryption recipe
/// is documented and we can ship a real `enc_payload`).
pub fn shield(
    label: &str,
    amount_str: &str,
    recipient_address: Option<&str>,
    password: Option<&str>,
) -> Result<ShieldOutcome> {
    // -----------------------------------------------------------------
    // 1. Validate inputs that don't need the seed.
    //    NOTE: do NOT call `AccountId::parse_encoded` for our own `from`
    //    — its canonicalisation produces an AccountController byte layout
    //    that diverges from the one the chain stored at our claim Mint.
    //    Use `AccountId::new(pubkey)` after seed unwrap instead.
    // -----------------------------------------------------------------
    let record = storage::load(label)?;

    let asset_def: AssetDefinitionId =
        AssetDefinitionId::parse_address_literal(XOR_ASSET_DEFINITION_ID)
            .map_err(|e| anyhow!("can't parse XOR asset def: {e:?}"))?;

    let amount: u128 = amount_str
        .parse::<u128>()
        .with_context(|| format!("amount must be a non-negative integer, got '{amount_str}'"))?;
    if amount == 0 {
        bail!("amount must be > 0");
    }

    let chain_id = ChainId::from(CHAIN_ID);
    let _ = &record; // record stays alive for storage::append_note below

    // -----------------------------------------------------------------
    // 2. Touch ID gate + seed unwrap.
    //    Build the AccountId from the derived public key (matches the
    //    chain's internal canonical form).
    // -----------------------------------------------------------------
    let reason = format!("Shield {amount_str} XOR (private note) from {label}");
    let seed = wallet::unlock_seed(label, &reason, password)?;

    let pubkey = wallet::derive_public_key(&seed)?;
    let from_account = AccountId::new(pubkey);

    // -----------------------------------------------------------------
    // 3. ZK derivations: owner_tag, fresh rho, commitment.
    //
    //    If a recipient v3 address was supplied, we use ITS owner_tag +
    //    diversifier (so the resulting note is owned by them). Otherwise
    //    we derive both from our own seed (a self-shield).
    // -----------------------------------------------------------------
    let parsed_recipient = recipient_address
        .map(crate::confidential_address::parse)
        .transpose()
        .with_context(|| "failed to parse recipient v3 payment address")?;
    let (owner_tag, diversifier): ([u8; 32], [u8; 32]) = match parsed_recipient.as_ref() {
        Some(addr) => {
            let ot = addr.owner_tag()?;
            let div = addr.diversifier()?;
            eprintln!(
                "[shield] sending to external recipient (owner_tag={}…, diversifier={}…)",
                &addr.shielded_owner_tag_hex[..16],
                &addr.shielded_diversifier_hex[..16]
            );
            (ot, div)
        }
        None => {
            let div = zk_v2::default_confidential_diversifier_v2();
            let ot = zk_v2::derive_confidential_owner_tag_v2_with_diversifier(&seed[..], div)
                .map_err(|e| anyhow!("owner_tag derivation: {e}"))?;
            (ot, div)
        }
    };
    let paid_to_external_recipient = parsed_recipient.is_some();

    let mut rho = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut rho);
    // NB: rho can be any 32 bytes — `derive_confidential_note_v2` runs
    // it through `hash_to_scalar` so even non-canonical Pasta byte
    // patterns are handled. No need to retry on canonicality.

    let commitment = zk_v2::derive_confidential_note_v2(
        XOR_ASSET_DEFINITION_ID,
        amount,
        rho,
        owner_tag,
    )
    .map_err(|e| anyhow!("commitment derivation: {e}"))?;

    // -----------------------------------------------------------------
    // 4. Build instruction list. As in transfer.rs, prepend
    //    Register::Account if this wallet hasn't been registered on
    //    chain yet — implicit accounts (created via cross-chain Mint)
    //    cannot Shield until they self-register at least once.
    // -----------------------------------------------------------------
    // Source-of-truth check: ask the chain directly. See transfer.rs
    // for the rationale (local flag is a cache, can drift).
    let needs_register = match torii::account_exists(&record.i105_address) {
        Ok(true) => {
            if !record.registered_on_chain {
                let _ = storage::mark_registered(label);
                eprintln!("[shield] chain confirms account is registered; updated local flag");
            }
            false
        }
        Ok(false) => {
            eprintln!("[shield] chain reports account NOT registered — prepending Register::Account");
            true
        }
        Err(e) => {
            eprintln!("[shield] couldn't check chain registration ({e}); using local flag");
            !record.registered_on_chain
        }
    };
    let mut instructions: Vec<InstructionBox> = Vec::with_capacity(2);
    if needs_register {
        let new_account = NewAccount::new(from_account.clone());
        instructions.push(Register::account(new_account).into());
    }
    let shield_isi = Shield::new(
        asset_def.clone(),
        from_account.clone(),
        amount,
        commitment,
        ConfidentialEncryptedPayload::default(),
    );
    instructions.push(shield_isi.into());

    let builder = iroha_data_model::transaction::TransactionBuilder::new(
        chain_id,
        from_account,
    )
    .with_instructions(instructions);

    let kp = KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519);
    let (_pk, sk): (PublicKey, PrivateKey) = kp.into_parts();
    let signed = builder.sign(&sk);

    // -----------------------------------------------------------------
    // 5. Norito-encode + POST to Torii. If we prepended Register, wait
    //    for the tx to settle before flipping `registered_on_chain` (so
    //    a Rejected tx doesn't poison the local flag).
    // -----------------------------------------------------------------
    let body: Vec<u8> = signed.encode_versioned();
    let tx_hash = signed.hash();
    let tx_hash_hex = hex::encode(tx_hash.as_ref());

    eprintln!("[shield] submitting tx {tx_hash_hex} ({} bytes)", body.len());
    let (status, _resp) = torii::submit_transaction(body)?;
    eprintln!("[shield] submitted (HTTP {status})");

    // -----------------------------------------------------------------
    // 5b. Wait for Committed before doing anything that depends on the
    //     tx having actually landed. We always wait now (not just for
    //     the auto-Register path), because persisting a LocalNote for a
    //     Rejected Shield was a real bug — it created "ghost notes"
    //     that would never have a counterpart in the on-chain Merkle
    //     tree, and Phase 2 spends would silently fail.
    // -----------------------------------------------------------------
    eprintln!("[shield] waiting for tx to be Committed before persisting state...");
    let final_status = match torii::wait_for_commit(&tx_hash_hex, 60) {
        Ok((s, reason)) => {
            eprintln!("[shield] tx settled status={s} reason={reason:?}");
            (s, reason)
        }
        Err(e) => {
            anyhow::bail!(
                "could not confirm tx status within 60s ({e}); refusing to persist a possibly-invalid note. tx hash: {tx_hash_hex}"
            );
        }
    };
    if final_status.0 != "Committed" {
        anyhow::bail!(
            "tx {tx_hash_hex} ended {} (reason: {:?}); no note persisted, no flag flipped",
            final_status.0,
            final_status.1
        );
    }

    if needs_register {
        storage::mark_registered(label).with_context(|| {
            format!("failed to persist registered_on_chain for '{label}'")
        })?;
        eprintln!(
            "[shield] wallet '{label}' marked registered_on_chain=true"
        );
    }

    // -----------------------------------------------------------------
    // 6. Persist the local note record IFF this was a self-shield AND
    //    the tx was Committed. For external recipients we do NOT keep
    //    a local copy: the note belongs to them and only confuses our
    //    own balance accounting. The rho is returned via ShieldOutcome
    //    so the caller can share it with the recipient out-of-band.
    // -----------------------------------------------------------------
    if !paid_to_external_recipient {
        let note = LocalNote {
            asset_def_id: XOR_ASSET_DEFINITION_ID.to_string(),
            amount_u128: amount.to_string(),
            rho_hex: hex::encode(rho),
            owner_tag_hex: hex::encode(owner_tag),
            commitment_hex: hex::encode(commitment),
            diversifier_hex: hex::encode(diversifier),
            created_tx_hash_hex: tx_hash_hex.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            spendable: true,
        };
        storage::append_note(label, &note)
            .with_context(|| format!("failed to persist local note for '{label}'"))?;
    }

    Ok(ShieldOutcome {
        tx_hash_hex,
        commitment_hex: hex::encode(commitment),
        amount: amount.to_string(),
        asset_def_id: XOR_ASSET_DEFINITION_ID.to_string(),
        rho_hex: hex::encode(rho),
        paid_to_external_recipient,
    })
}
