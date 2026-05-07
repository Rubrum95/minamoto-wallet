// Confidential-unshield prover (Phase 2, step 3 of ZK_ROADMAP.md).
//
// Thin wrapper over `iroha_core::zk::confidential_v2::build_confidential_unshield_proof_v2`.
// We keep the prover logic in the chain crate because:
//
//   - The ZK circuit definition (`ConfidentialUnshieldCircuitV2`) and its
//     constraint system live there; vendoring 700+ lines of Halo2 plonk
//     code into the wallet would create a maintenance liability.
//   - The exact constants (k=7, depth=16, public-input schema) MUST match
//     what the on-chain executor verifies; sharing the source removes any
//     chance of accidental divergence.
//
// The cost is a heavy `iroha_core` path-dep (network, consensus, storage
// types are all pulled, even with `default-features = false`). See the
// `[patch.crates-io]` block in `Cargo.toml` for the workspace dance that
// makes this build cleanly outside the iroha workspace.
//
// V2 vs V3: Minamoto currently only registers the V2 unshield circuit
// (`vk_unshield` → `anon-unshield-merkle16-poseidon-diversified`); the
// V3 variant with private-change outputs is not yet on chain. We target
// V2 for now and will switch to V3 when the chain accepts it.

use crate::indexer;
use crate::shield::LocalNote;
use crate::storage;
use crate::torii;
use crate::wallet;
use anyhow::{Context, Result, anyhow, bail};
use iroha_core::zk::confidential_v2::{
    ConfidentialUnshieldInputV2, ConfidentialUnshieldProofV2, build_confidential_unshield_proof_v2,
};
use iroha_data_model::ChainId;
use iroha_data_model::proof::{VerifyingKeyBox, VerifyingKeyId};

/// VK name registered on Minamoto for the V2 unshield circuit.
/// Sourced empirically from `GET /v1/zk/vk` on 2026-05-07; matches the
/// upstream constant `vk_unshield` set during genesis.
pub const UNSHIELD_VK_NAME: &str = "vk_unshield";

/// Backend identifier the chain uses for halo2-IPA VK lookups in
/// `VerifyingKeyId`. Sourced from the same listing.
pub const UNSHIELD_VK_BACKEND: &str = "halo2/ipa";

/// Outcome of a successful proof build. We hold the raw `ProofBox` so
/// the caller can wrap it into a `ProofAttachment` for the Unshield ISI;
/// the nullifier is needed both for the ISI and for marking the local
/// note as spent.
pub struct UnshieldProofBundle {
    /// Wire-ready proof envelope (Norito-encoded Halo2 envelope).
    pub proof_box: iroha_data_model::proof::ProofBox,
    /// Nullifier(s) emitted by the proof (one per input note).
    pub nullifiers: Vec<[u8; 32]>,
    /// Merkle root the proof binds to — must equal `tree_commitments`
    /// recomputed root for the chain to accept it.
    pub root: [u8; 32],
    /// VK reference (backend + name) — feeds into `ProofAttachment::new_ref`.
    pub vk_id: VerifyingKeyId,
}

/// Inputs needed to drive the prover. Constructed by `cmd_unshield_dry_run`
/// from local wallet state plus a fresh indexer snapshot.
pub struct UnshieldRequest {
    pub label: String,
    pub asset_def_id: String,
    pub chain_id: String,
    /// 32-byte wallet seed (Touch-ID-unlocked). Treated as `spend_key`
    /// by the chain; we own this for the duration of the prover call
    /// and zeroize ourselves on drop higher up the stack.
    pub spend_key: Vec<u8>,
    /// The local note we intend to spend.
    pub note: LocalNote,
    /// Public amount that should land in our transparent balance.
    /// For a no-change V2 unshield this MUST equal `note.amount_u128`.
    pub public_amount: u128,
}

/// Build a V2 unshield proof for one local note. The cache MUST already
/// be refreshed (`index-confidential`) and the note's `leaf_index` MUST
/// be populated (`verify-confidential`); both preconditions are checked
/// here so the caller gets a clear error rather than a cryptic ZK fail.
pub fn build_unshield_proof(req: &UnshieldRequest) -> Result<UnshieldProofBundle> {
    if req.spend_key.len() != 32 {
        bail!("spend_key must be exactly 32 bytes (got {})", req.spend_key.len());
    }
    let leaf_index = req
        .note
        .leaf_index
        .ok_or_else(|| anyhow!(
            "local note has no cached leaf_index; run `verify-confidential {} {}` first",
            req.label,
            req.asset_def_id,
        ))? as usize;

    // Decode the hex fields stored on disk. We re-validate every byte
    // length because LocalNote is plain JSON — a hand-edited record
    // could otherwise crash the prover with an unhelpful slice panic.
    let mut rho = [0u8; 32];
    hex::decode_to_slice(&req.note.rho_hex, &mut rho)
        .with_context(|| format!("decode rho_hex '{}'", req.note.rho_hex))?;
    let mut diversifier = [0u8; 32];
    hex::decode_to_slice(&req.note.diversifier_hex, &mut diversifier)
        .with_context(|| format!("decode diversifier_hex '{}'", req.note.diversifier_hex))?;
    let amount: u128 = req
        .note
        .amount_u128
        .parse()
        .with_context(|| format!("parse note amount '{}'", req.note.amount_u128))?;
    if req.public_amount != amount {
        // V2 has no private change — the prover would build a witness
        // that the chain rejects. Fail fast with a readable hint.
        bail!(
            "V2 unshield requires public_amount == note amount (got {} vs {}); \
             use V3 (not yet registered on Minamoto) when partial unshield is needed",
            req.public_amount,
            amount,
        );
    }

    // Snapshot the chain's confidential ledger from our local cache
    // (parity with `/v1/zk/roots` already verified by `verify-confidential`).
    let snap = indexer::read_cache(&req.asset_def_id)?
        .ok_or_else(|| anyhow!(
            "no indexer cache for {}; run `index-confidential` first",
            req.asset_def_id
        ))?;
    if leaf_index >= snap.commitments.len() {
        bail!(
            "leaf_index {leaf_index} out of bounds (cache has {} commitments)",
            snap.commitments.len()
        );
    }

    // Pull the VK from the chain. The bytes are exactly what
    // `parse_vk_for_unshield` expects — we don't unpack them here.
    let vk = torii::fetch_zk_verifying_key(UNSHIELD_VK_NAME)
        .context("fetch confidential unshield verifying key from Torii")?;
    let vk_box = VerifyingKeyBox::new(vk.backend.clone(), vk.bytes);

    let chain_id = ChainId::from(req.chain_id.clone());
    let inputs = vec![ConfidentialUnshieldInputV2 {
        amount,
        rho,
        diversifier,
        leaf_index,
    }];

    eprintln!(
        "[prover] building V2 unshield proof (depth=16 leaf={leaf_index} amount={amount}, \
         circuit_id='{}')",
        vk.circuit_id
    );
    let proof: ConfidentialUnshieldProofV2 = build_confidential_unshield_proof_v2(
        &chain_id,
        &req.asset_def_id,
        &req.spend_key,
        &snap.commitments,
        &inputs,
        req.public_amount,
        snap.recorded_root,
        &vk.circuit_id,
        &vk_box,
    )
    .map_err(|err| anyhow!("confidential unshield proof failed: {err}"))?;
    if proof.root != snap.recorded_root {
        bail!(
            "prover bound its proof to root {} but cache snapshot is {}",
            hex::encode(proof.root),
            hex::encode(snap.recorded_root),
        );
    }

    Ok(UnshieldProofBundle {
        proof_box: proof.proof,
        nullifiers: proof.nullifiers,
        root: proof.root,
        vk_id: VerifyingKeyId::new(UNSHIELD_VK_BACKEND, UNSHIELD_VK_NAME),
    })
}

/// Find the wallet's first spendable LocalNote for the given asset. If
/// multiple are present and `desired_commitment_hex` is `Some`, only the
/// matching one is selected; otherwise the caller must disambiguate.
pub fn pick_spendable_note(
    label: &str,
    asset_def_id: &str,
    desired_commitment_hex: Option<&str>,
) -> Result<LocalNote> {
    let record = storage::load(label)
        .with_context(|| format!("load wallet record for '{label}'"))?;
    let candidates: Vec<&LocalNote> = record
        .notes
        .iter()
        .filter(|n| n.asset_def_id == asset_def_id && n.spendable)
        .collect();
    if candidates.is_empty() {
        bail!(
            "wallet '{label}' has no spendable notes for asset {asset_def_id}; \
             create one with `shield`"
        );
    }
    if let Some(target) = desired_commitment_hex {
        for n in &candidates {
            if n.commitment_hex.eq_ignore_ascii_case(target) {
                return Ok((*n).clone());
            }
        }
        bail!("no spendable note with commitment '{target}'");
    }
    if candidates.len() > 1 {
        bail!(
            "wallet '{label}' has {} spendable notes; pass --commitment <hex> to disambiguate",
            candidates.len()
        );
    }
    Ok(candidates[0].clone())
}

/// CLI entry point for the **real** unshield: builds the proof, wraps
/// it into the Unshield ISI, signs the transaction with the wallet seed
/// and submits to Torii. Waits for the tx to commit. On success, marks
/// the local note as spent and persists the nullifier / spent-tx hash.
///
/// Touch ID is required (same flow as Shield). The XOR returns to the
/// wallet's transparent balance (`to = our AccountId`).
#[cfg(target_os = "macos")]
pub fn cmd_unshield(
    label: &str,
    chain_id_str: &str,
    asset_def_id: &str,
    desired_commitment_hex: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    use iroha_crypto::{Algorithm, KeyPair, PrivateKey, PublicKey};
    use iroha_data_model::asset::AssetDefinitionId;
    use iroha_data_model::isi::zk::Unshield;
    use iroha_data_model::isi::InstructionBox;
    use iroha_data_model::proof::ProofAttachment;
    use iroha_version::codec::EncodeVersioned;

    let note = pick_spendable_note(label, asset_def_id, desired_commitment_hex)?;
    let amount: u128 = note.amount_u128.parse()
        .with_context(|| format!("parse note amount '{}'", note.amount_u128))?;
    eprintln!("==== Unshield ====");
    eprintln!("Wallet:        {label}");
    eprintln!("Asset:         {asset_def_id}");
    eprintln!("Note amount:   {amount} XOR");
    eprintln!("Note commit:   {}…", &note.commitment_hex[..16]);
    eprintln!();

    let reason = format!("Unshield {amount} XOR back to public balance");
    let seed = wallet::unlock_seed(label, &reason, password)?;
    let req = UnshieldRequest {
        label: label.to_owned(),
        asset_def_id: asset_def_id.to_owned(),
        chain_id: chain_id_str.to_owned(),
        spend_key: seed.to_vec(),
        note: note.clone(),
        public_amount: amount,
    };
    let bundle = build_unshield_proof(&req)?;
    eprintln!(
        "[unshield] proof generated ({} bytes), wrapping into Unshield ISI…",
        bundle.proof_box.bytes.len()
    );

    let asset_def: AssetDefinitionId = AssetDefinitionId::parse_address_literal(asset_def_id)
        .map_err(|e| anyhow!("parse asset definition id: {e:?}"))?;

    // The ISI's `to` is where the unshielded XOR lands. We always credit
    // it back to the same account that owned the shielded note — sending
    // unshielded XOR to a third party is a separate flow we don't expose
    // here.
    let pubkey = wallet::derive_public_key(&seed)?;
    let to_account = iroha_data_model::account::AccountId::new(pubkey.clone());

    let attachment = ProofAttachment::new_ref(
        bundle.proof_box.backend.clone(),
        bundle.proof_box.clone(),
        bundle.vk_id.clone(),
    );

    let unshield_isi = Unshield::new(
        asset_def,
        to_account.clone(),
        amount,
        bundle.nullifiers.clone(),
        attachment,
        Some(bundle.root),
    );
    let instructions: Vec<InstructionBox> = vec![unshield_isi.into()];

    let chain_id = iroha_data_model::ChainId::from(chain_id_str.to_owned());
    let builder = iroha_data_model::transaction::TransactionBuilder::new(chain_id, to_account)
        .with_instructions(instructions);
    let kp = KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519);
    let (_pk, sk): (PublicKey, PrivateKey) = kp.into_parts();
    let signed = builder.sign(&sk);

    let body: Vec<u8> = signed.encode_versioned();
    let tx_hash = signed.hash();
    let tx_hash_hex = hex::encode(tx_hash.as_ref());
    eprintln!("[unshield] submitting tx {tx_hash_hex} ({} bytes)", body.len());

    let (status, _resp) = torii::submit_transaction(body)?;
    eprintln!("[unshield] submitted (HTTP {status})");
    eprintln!("[unshield] waiting for commit…");
    let (final_status, reason_opt) = torii::wait_for_commit(&tx_hash_hex, 120)
        .with_context(|| format!("could not confirm tx {tx_hash_hex}"))?;
    eprintln!("[unshield] tx settled status={final_status} reason={reason_opt:?}");
    if final_status != "Committed" {
        bail!(
            "tx {tx_hash_hex} ended {final_status} (reason: {reason_opt:?}); \
             local note NOT marked spent"
        );
    }

    let nullifier_hex = hex::encode(bundle.nullifiers[0]);
    storage::mark_note_spent(label, &note.commitment_hex, &nullifier_hex, &tx_hash_hex)
        .with_context(|| format!("persist spent flag for '{label}'"))?;

    println!();
    println!("✅ Unshield Committed.");
    println!("   tx hash:     {tx_hash_hex}");
    println!("   amount:      {amount} XOR (credited to public balance)");
    println!("   nullifier:   {nullifier_hex}");
    println!("   commitment:  {} (now spent)", note.commitment_hex);
    println!();
    println!("Verify on chain:");
    println!("  https://sorametrics.org/minamoto#tx/{tx_hash_hex}");
    Ok(())
}

/// CLI entry point for the dry-run unshield: builds a real ZK proof
/// against the local note, prints its summary, but does NOT submit any
/// transaction. Useful as a smoke test for the path-dep prover before
/// committing to a real on-chain Unshield ISI.
#[cfg(target_os = "macos")]
pub fn cmd_unshield_dry_run(
    label: &str,
    chain_id_str: &str,
    asset_def_id: &str,
    desired_commitment_hex: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    let note = pick_spendable_note(label, asset_def_id, desired_commitment_hex)?;
    let amount: u128 = note.amount_u128.parse()
        .with_context(|| format!("parse note amount '{}'", note.amount_u128))?;
    eprintln!("==== Unshield dry-run ====");
    eprintln!("Wallet:        {label}");
    eprintln!("Asset:         {asset_def_id}");
    eprintln!("Note amount:   {amount} XOR");
    eprintln!("Note commit:   {}…", &note.commitment_hex[..16]);
    eprintln!("Note leaf idx: {:?}", note.leaf_index);
    eprintln!();

    let reason = format!("Build unshield proof for {amount} XOR (dry-run, no tx submitted)");
    let seed = wallet::unlock_seed(label, &reason, password)?;
    let req = UnshieldRequest {
        label: label.to_owned(),
        asset_def_id: asset_def_id.to_owned(),
        chain_id: chain_id_str.to_owned(),
        spend_key: seed.to_vec(),
        note,
        public_amount: amount,
    };
    let bundle = build_unshield_proof(&req)?;
    println!();
    println!("✅ Proof generated locally.");
    println!("   Proof backend:  {}", bundle.proof_box.backend);
    println!("   Proof bytes:    {} bytes", bundle.proof_box.bytes.len());
    println!("   Nullifier(s):   {}", bundle.nullifiers.len());
    for (i, n) in bundle.nullifiers.iter().enumerate() {
        println!("     [{i}] {}", hex::encode(n));
    }
    println!("   Bound to root:  {}", hex::encode(bundle.root));
    println!("   VK reference:   backend='{}' name='{}'", bundle.vk_id.backend, bundle.vk_id.name);
    println!();
    println!("Next step: wrap proof_box into ProofAttachment::new_ref(vk_id) and submit");
    println!("via Unshield ISI. Not done in dry-run mode.");
    Ok(())
}
