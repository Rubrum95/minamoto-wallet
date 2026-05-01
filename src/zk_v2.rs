// Confidential-asset v2 derivations (Pasta Fp + Blake3) — port of the
// `iroha_core::zk::confidential_v2` runtime helpers.
//
// We re-implement these in our wallet crate (instead of depending on
// `iroha_core` directly) for two reasons:
//
//   1. `iroha_core` pulls the entire node runtime including consensus,
//      DA, smart-contracts, etc. — pulling that into a wallet binary
//      would explode compile time and binary size. We only need the
//      pure crypto helpers.
//
//   2. We pin the implementation to a specific revision of the
//      iroha source tree (i23-features at the time of writing). When
//      Iroha 3 ships breaking changes to the commitment formula, we
//      can update this module deliberately rather than via a tacit
//      dependency upgrade.
//
// **CRITICAL: this code MUST stay byte-for-byte identical to the
// upstream `iroha_core::zk::confidential_v2` for any chain that we
// interact with**, otherwise the notes we Shield will not be spendable
// (the on-chain Halo2-IPA circuit verifies the commitment with the
// same formula and rejects our future Unshield/ZkTransfer if the
// commitment doesn't match the expected `(value, viewing_pubkey, rho,
// owner_tag, asset_tag)` Poseidon-pair tree).
//
// Reference: iroha-source/iroha/crates/iroha_core/src/zk/confidential_v2.rs
// lines 340-507. Each function below cites the corresponding upstream line.

use blake3::Hasher as Blake3Hasher;
use ff::{Field, PrimeField};
use pasta_curves::Fp as Scalar;

// ---------------------------------------------------------------------------
// Low-level scalar helpers
// ---------------------------------------------------------------------------

/// Decode a 32-byte little-endian Pasta Fp scalar. Returns `None` if the
/// representation is non-canonical (bytes >= modulus).
///
/// Upstream: `scalar_from_repr` (line 340).
pub fn scalar_from_repr(bytes: [u8; 32]) -> Option<Scalar> {
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    Option::<Scalar>::from(Scalar::from_repr(repr))
}

/// Encode a Pasta Fp scalar to its 32-byte little-endian representation.
///
/// Upstream: `scalar_to_repr_bytes` (line 347).
pub fn scalar_to_repr_bytes(value: Scalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(value.to_repr().as_ref());
    out
}

/// Construct a Pasta Fp scalar from a u128 by placing its 16 little-endian
/// bytes in the low half of the 32-byte representation. Always succeeds
/// because u128 < Pasta Fp modulus.
///
/// Upstream: `scalar_from_u128` (line 375).
pub fn scalar_from_u128(amount: u128) -> Scalar {
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut()[..16].copy_from_slice(&amount.to_le_bytes());
    Scalar::from_repr(repr)
        .into_option()
        .expect("u128 always fits inside Pasta Fp")
}

// ---------------------------------------------------------------------------
// Hash-to-scalar via Blake3 with a counter-loop until canonical
// ---------------------------------------------------------------------------

/// Domain-separated hash to Pasta Fp.
///
/// The hash input is:
///
///     Blake3( label || counter (u64 LE) ||
///             (len_part (u64 LE) || part)* )
///
/// We retry with `counter += 1` until the resulting digest is canonical
/// for Pasta Fp (i.e. <= modulus - 1). This converges in ~1 try with
/// overwhelming probability.
///
/// Upstream: `hash_to_scalar` (line 354).
pub fn hash_to_scalar(label: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut counter: u64 = 0;
    loop {
        let mut hasher = Blake3Hasher::new();
        hasher.update(label);
        hasher.update(&counter.to_le_bytes());
        for part in parts {
            let len_u64 = u64::try_from(part.len()).unwrap_or(u64::MAX);
            hasher.update(&len_u64.to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(digest.as_bytes());
        if let Some(value) = scalar_from_repr(candidate) {
            return value;
        }
        counter = counter.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Pseudo-Poseidon pair
// ---------------------------------------------------------------------------

/// Two-input "Poseidon-style" hash: NOT the standard Poseidon. This is a
/// deliberate simplification used by the Iroha 3 v2 confidential circuit
/// to keep the constraint count low while still providing collision
/// resistance for the commitment / nullifier / Merkle tree. It MUST be
/// reproduced bit-for-bit.
///
///     poseidon_pair(lhs, rhs) =
///         let l = lhs + 7
///         let r = rhs + 13
///         2 * l^5 + 3 * r^5
///
/// Upstream: `poseidon_pair` (line 382).
pub fn poseidon_pair(lhs: Scalar, rhs: Scalar) -> Scalar {
    let lhs = lhs + Scalar::from(7u64);
    let rhs = rhs + Scalar::from(13u64);
    let lhs_sq = lhs * lhs;
    let lhs_fourth = lhs_sq * lhs_sq;
    let rhs_sq = rhs * rhs;
    let rhs_fourth = rhs_sq * rhs_sq;
    Scalar::from(2u64) * (lhs_fourth * lhs) + Scalar::from(3u64) * (rhs_fourth * rhs)
}

/// Internal: recursive structure for the note commitment.
fn note_commitment_scalar(
    amount: Scalar,
    rho: Scalar,
    owner_tag: Scalar,
    asset_tag: Scalar,
) -> Scalar {
    poseidon_pair(
        amount,
        poseidon_pair(rho, poseidon_pair(owner_tag, asset_tag)),
    )
}

// ---------------------------------------------------------------------------
// Public API matching iroha_core::zk::confidential_v2
// ---------------------------------------------------------------------------

/// `[0x01, 0x00, 0x00, ..., 0x00]` — the canonical 32-byte little-endian
/// representation of `Scalar::ONE` for Pasta Fp.
///
/// Upstream: `default_confidential_diversifier_v2` (line 426).
pub fn default_confidential_diversifier_v2() -> [u8; 32] {
    scalar_to_repr_bytes(Scalar::ONE)
}

/// Domain-separated derivation of a per-account diversifier from a seed.
/// This lets a single spend key produce many distinguishable diversified
/// owner tags (e.g. one per recipient context).
///
/// Upstream: `derive_confidential_diversifier_v2` (line 431).
pub fn derive_confidential_diversifier_v2(seed: &[u8]) -> [u8; 32] {
    scalar_to_repr_bytes(hash_to_scalar(
        b"iroha.confidential.v2.diversifier",
        &[seed],
    ))
}

/// Owner tag with explicit diversifier:
///
///     spend_scalar = hash_to_scalar("iroha.confidential.v2.spend_scalar", spend_key)
///     owner_tag = poseidon_pair(spend_scalar, scalar_from_repr(diversifier))
///
/// The diversifier MUST be a canonical Pasta scalar; non-canonical input
/// returns `Err`.
///
/// Upstream: `derive_confidential_owner_tag_v2_with_diversifier` (line 439).
pub fn derive_confidential_owner_tag_v2_with_diversifier(
    spend_key: &[u8],
    diversifier: [u8; 32],
) -> Result<[u8; 32], &'static str> {
    let spend_scalar = hash_to_scalar(b"iroha.confidential.v2.spend_scalar", &[spend_key]);
    let diversifier_scalar = scalar_from_repr(diversifier)
        .ok_or("diversifier must be a canonical Pasta scalar")?;
    Ok(scalar_to_repr_bytes(poseidon_pair(
        spend_scalar,
        diversifier_scalar,
    )))
}

/// Owner tag with the default diversifier (Scalar::ONE).
///
/// Upstream: `derive_confidential_owner_tag_v2` (line 417).
pub fn derive_confidential_owner_tag_v2(spend_key: &[u8]) -> [u8; 32] {
    derive_confidential_owner_tag_v2_with_diversifier(
        spend_key,
        default_confidential_diversifier_v2(),
    )
    .expect("default confidential diversifier is canonical")
}

/// Asset tag derived from the AssetDefinitionId string (trimmed).
///
/// Upstream: `derive_confidential_asset_tag_v2` (line 453).
pub fn derive_confidential_asset_tag_v2(asset_definition_id: &str) -> [u8; 32] {
    scalar_to_repr_bytes(hash_to_scalar(
        b"iroha.confidential.v2.asset_tag",
        &[asset_definition_id.trim().as_bytes()],
    ))
}

/// Chain tag derived from the ChainId string (trimmed). Used by nullifier
/// derivation; not needed for Shield's commitment alone.
///
/// Upstream: `derive_confidential_chain_tag_v2` (line 461).
pub fn derive_confidential_chain_tag_v2(chain_id: &str) -> [u8; 32] {
    scalar_to_repr_bytes(hash_to_scalar(
        b"iroha.confidential.v2.chain_tag",
        &[chain_id.trim().as_bytes()],
    ))
}

/// **THE function the wallet must call to produce a spendable note.**
///
///     rho_scalar       = hash_to_scalar("iroha.confidential.v2.note_rho", rho)
///     asset_tag_scalar = scalar_from_repr( derive_asset_tag(asset_def_id) )
///     amount_scalar    = scalar_from_u128(amount)
///     owner_tag_scalar = scalar_from_repr(owner_tag)
///
///     commitment = poseidon_pair(
///         amount,
///         poseidon_pair(rho, poseidon_pair(owner_tag, asset_tag))
///     )
///
/// Returns the 32-byte LE representation of the resulting Pasta scalar.
///
/// Upstream: `derive_confidential_note_v2` (line 469).
pub fn derive_confidential_note_v2(
    asset_definition_id: &str,
    amount: u128,
    rho: [u8; 32],
    owner_tag: [u8; 32],
) -> Result<[u8; 32], &'static str> {
    let owner_tag_scalar = scalar_from_repr(owner_tag)
        .ok_or("owner_tag must be a canonical Pasta scalar")?;
    let asset_tag_scalar = scalar_from_repr(derive_confidential_asset_tag_v2(asset_definition_id))
        .expect("asset tag is always canonical (hash_to_scalar guarantees it)");
    let rho_scalar = hash_to_scalar(b"iroha.confidential.v2.note_rho", &[&rho]);
    Ok(scalar_to_repr_bytes(note_commitment_scalar(
        scalar_from_u128(amount),
        rho_scalar,
        owner_tag_scalar,
        asset_tag_scalar,
    )))
}

/// Nullifier derivation. Needed for Unshield/ZkTransfer to prove "this
/// note has not been spent before". Implemented now so the API surface
/// is complete; callers in Phase 1 (Shield only) won't need it yet.
///
/// Upstream: `derive_confidential_nullifier_v2` (line 489).
pub fn derive_confidential_nullifier_v2(
    chain_id: &str,
    asset_definition_id: &str,
    spend_key: &[u8],
    rho: [u8; 32],
) -> [u8; 32] {
    let spend_scalar = hash_to_scalar(b"iroha.confidential.v2.spend_scalar", &[spend_key]);
    let asset_tag_scalar = scalar_from_repr(derive_confidential_asset_tag_v2(asset_definition_id))
        .expect("asset tag is canonical");
    let chain_tag_scalar = scalar_from_repr(derive_confidential_chain_tag_v2(chain_id))
        .expect("chain tag is canonical");
    let rho_scalar = hash_to_scalar(b"iroha.confidential.v2.note_rho", &[&rho]);
    scalar_to_repr_bytes(nullifier_scalar(
        spend_scalar,
        rho_scalar,
        asset_tag_scalar,
        chain_tag_scalar,
    ))
}

fn nullifier_scalar(sk: Scalar, rho: Scalar, asset_tag: Scalar, chain_tag: Scalar) -> Scalar {
    poseidon_pair(sk, poseidon_pair(rho, poseidon_pair(asset_tag, chain_tag)))
}

// ---------------------------------------------------------------------------
// Tests — bit-parity smoke checks against upstream invariants
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_diversifier_is_scalar_one_le() {
        let d = default_confidential_diversifier_v2();
        assert_eq!(d[0], 0x01);
        assert!(d.iter().skip(1).all(|&b| b == 0x00));
    }

    #[test]
    fn poseidon_pair_is_deterministic_and_position_dependent() {
        let a = Scalar::from(123u64);
        let b = Scalar::from(456u64);
        let pab = poseidon_pair(a, b);
        let pab2 = poseidon_pair(a, b);
        let pba = poseidon_pair(b, a);
        assert_eq!(pab, pab2);
        assert_ne!(pab, pba, "poseidon_pair is asymmetric (lhs and rhs use different constants)");
    }

    #[test]
    fn derive_note_changes_with_amount() {
        let asset_id = "test-asset";
        let owner_tag = derive_confidential_owner_tag_v2(b"my-spend-key");
        let rho = [0x42u8; 32];
        let c1 = derive_confidential_note_v2(asset_id, 100, rho, owner_tag).unwrap();
        let c2 = derive_confidential_note_v2(asset_id, 101, rho, owner_tag).unwrap();
        let c3 = derive_confidential_note_v2(asset_id, 100, rho, owner_tag).unwrap();
        assert_eq!(c1, c3, "same inputs must produce same commitment");
        assert_ne!(c1, c2, "different amounts must produce different commitments");
    }

    #[test]
    fn derive_note_changes_with_asset() {
        let owner_tag = derive_confidential_owner_tag_v2(b"my-spend-key");
        let rho = [0x42u8; 32];
        let c1 = derive_confidential_note_v2("asset-A", 100, rho, owner_tag).unwrap();
        let c2 = derive_confidential_note_v2("asset-B", 100, rho, owner_tag).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn nullifier_changes_with_chain_and_asset() {
        let sk = b"my-spend-key";
        let rho = [0x42u8; 32];
        let n1 = derive_confidential_nullifier_v2("chain-A", "asset-A", sk, rho);
        let n2 = derive_confidential_nullifier_v2("chain-B", "asset-A", sk, rho);
        let n3 = derive_confidential_nullifier_v2("chain-A", "asset-B", sk, rho);
        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
    }
}
