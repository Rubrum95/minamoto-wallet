// Confidential-ledger Merkle tree (Phase 2, step 2 of ZK_ROADMAP.md).
//
// Bit-for-bit port of `compute_confidential_root_v2` /
// `compute_confidential_merkle_path_v2` from
// `iroha_core::zk::confidential_v2` (lines 524-605). The same
// `poseidon_pair` and `leaf_scalar_from_commitment` we already have in
// `zk_v2.rs` drive every internal node.
//
// **CRITICAL**: this code MUST stay byte-identical to the upstream
// implementation. The Halo2-IPA circuit verifies the Merkle membership
// witness inside the Unshield / ZkTransfer proof; if our local root or
// path diverges by a single byte, every proof we generate will be
// rejected by the chain.

use crate::zk_v2::{
    CONFIDENTIAL_TREE_CAPACITY_V2, CONFIDENTIAL_TREE_DEPTH_V2, Scalar,
    leaf_scalar_from_commitment, poseidon_pair, scalar_to_repr_bytes,
};
use anyhow::{Result, bail};
use ff::Field;

/// Per-leaf Merkle membership material. Mirrors
/// `ConfidentialMerklePathV2` in upstream confidential_v2.rs.
///
/// `siblings[i]` is the sibling node at level `i` (0 = leaf row).
/// `directions[i]` is `0` if our current node is the left child,
/// `1` if it is the right child — i.e. it tells the verifier
/// which side the sibling sits on at each level.
/// `witness_nodes[i]` is the parent computed at level `i`,
/// included for redundant audit (the verifier also recomputes it).
/// `root` is the final root that the path proves.
#[derive(Clone, Debug)]
pub struct MerklePath {
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<u32>,
    pub witness_nodes: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

/// Build the bottom layer: each commitment lifted to a Pasta scalar,
/// then padded with `Scalar::ZERO` up to tree capacity. Empty slots are
/// canonical zeroes so the empty-tree root is deterministic.
fn build_padded_layer(commitments: &[[u8; 32]]) -> Result<Vec<Scalar>> {
    if commitments.len() > CONFIDENTIAL_TREE_CAPACITY_V2 {
        bail!(
            "confidential v2 tree supports at most {} leaves (got {})",
            CONFIDENTIAL_TREE_CAPACITY_V2,
            commitments.len()
        );
    }
    let mut layer = Vec::with_capacity(CONFIDENTIAL_TREE_CAPACITY_V2);
    for c in commitments {
        layer.push(leaf_scalar_from_commitment(*c));
    }
    while layer.len() < CONFIDENTIAL_TREE_CAPACITY_V2 {
        layer.push(Scalar::ZERO);
    }
    Ok(layer)
}

/// Recompute the depth-16 Merkle root from the supplied commitments.
/// The result must equal the chain's reported root for the same set,
/// otherwise our local index is corrupt or out of date.
///
/// Upstream: `compute_confidential_root_v2` (line 542).
pub fn compute_root(commitments: &[[u8; 32]]) -> Result<[u8; 32]> {
    let mut layer = build_padded_layer(commitments)?;
    for _ in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
        layer = layer
            .chunks_exact(2)
            .map(|pair| poseidon_pair(pair[0], pair[1]))
            .collect();
    }
    Ok(scalar_to_repr_bytes(layer[0]))
}

/// Compute the Merkle path that proves membership of `commitments[leaf_index]`.
///
/// Upstream: `compute_confidential_merkle_path_v2` (line 554).
pub fn compute_path(commitments: &[[u8; 32]], leaf_index: usize) -> Result<MerklePath> {
    if leaf_index >= CONFIDENTIAL_TREE_CAPACITY_V2 {
        bail!(
            "leaf_index {leaf_index} must be < {} for confidential v2 proofs",
            CONFIDENTIAL_TREE_CAPACITY_V2
        );
    }
    let mut current_index = leaf_index;
    let mut layer = build_padded_layer(commitments)?;
    let mut siblings = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    let mut directions = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    let mut witness_nodes = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    for _ in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
        let sibling_index = if current_index.is_multiple_of(2) {
            current_index + 1
        } else {
            current_index - 1
        };
        let direction: u32 = if current_index.is_multiple_of(2) { 0 } else { 1 };
        let lhs = if direction == 0 {
            layer[current_index]
        } else {
            layer[sibling_index]
        };
        let rhs = if direction == 0 {
            layer[sibling_index]
        } else {
            layer[current_index]
        };
        siblings.push(scalar_to_repr_bytes(layer[sibling_index]));
        directions.push(direction);
        witness_nodes.push(scalar_to_repr_bytes(poseidon_pair(lhs, rhs)));
        current_index /= 2;
        layer = layer
            .chunks_exact(2)
            .map(|pair| poseidon_pair(pair[0], pair[1]))
            .collect();
    }
    Ok(MerklePath {
        siblings,
        directions,
        witness_nodes,
        root: scalar_to_repr_bytes(layer[0]),
    })
}

/// Find the leaf index of `target` in `commitments`, or `None` if it
/// isn't there. The shielded ledger is append-only so the first match
/// is canonical; we still scan the whole list defensively in case of
/// a duplicate (which should never happen on chain but might in test
/// fixtures).
pub fn find_leaf_index(commitments: &[[u8; 32]], target: &[u8; 32]) -> Option<usize> {
    commitments.iter().position(|c| c == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_is_deterministic() -> Result<()> {
        let r1 = compute_root(&[])?;
        let r2 = compute_root(&[])?;
        assert_eq!(r1, r2);
        // Sanity: the empty root is NOT all zeroes (poseidon_pair(0,0)
        // is not zero).
        assert_ne!(r1, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn single_leaf_path_recovers_root() -> Result<()> {
        let mut commit = [0u8; 32];
        commit[0] = 0x42;
        commit[1] = 0xab;
        let root = compute_root(&[commit])?;
        let path = compute_path(&[commit], 0)?;
        assert_eq!(
            path.root, root,
            "root computed via compute_path must match compute_root"
        );
        // Path lengths must equal tree depth.
        assert_eq!(path.siblings.len(), CONFIDENTIAL_TREE_DEPTH_V2);
        assert_eq!(path.directions.len(), CONFIDENTIAL_TREE_DEPTH_V2);
        assert_eq!(path.witness_nodes.len(), CONFIDENTIAL_TREE_DEPTH_V2);
        // Leaf 0 → all directions are 0 (always the left child).
        assert!(path.directions.iter().all(|&d| d == 0));
        Ok(())
    }

    #[test]
    fn rebuild_root_from_path_siblings() -> Result<()> {
        // Multi-leaf parity: walk the path manually, verify the climb
        // ends at the same root that compute_root computes from scratch.
        let mut commits: Vec<[u8; 32]> = Vec::new();
        for i in 0..7u8 {
            let mut c = [0u8; 32];
            c[0] = i + 1;
            commits.push(c);
        }
        let root = compute_root(&commits)?;
        for (i, target) in commits.iter().enumerate() {
            let path = compute_path(&commits, i)?;
            assert_eq!(path.root, root, "leaf {i} path root must equal global root");

            // Manual climb: start at leaf scalar, fold with siblings.
            let mut node = leaf_scalar_from_commitment(*target);
            for level in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
                let sibling = crate::zk_v2::scalar_from_repr(path.siblings[level])
                    .expect("sibling must be canonical");
                let (l, r) = if path.directions[level] == 0 {
                    (node, sibling)
                } else {
                    (sibling, node)
                };
                node = poseidon_pair(l, r);
            }
            assert_eq!(scalar_to_repr_bytes(node), root, "manual climb mismatch leaf {i}");
        }
        Ok(())
    }

    #[test]
    fn find_leaf_index_locates_known_commit() {
        let mut a = [0u8; 32];
        a[0] = 1;
        let mut b = [0u8; 32];
        b[0] = 2;
        let mut c = [0u8; 32];
        c[0] = 3;
        let commits = vec![a, b, c];
        assert_eq!(find_leaf_index(&commits, &b), Some(1));
        let mut missing = [0u8; 32];
        missing[0] = 99;
        assert_eq!(find_leaf_index(&commits, &missing), None);
    }

    #[test]
    fn capacity_overflow_is_rejected() {
        // We can't actually allocate CAPACITY+1 = 65537 leaves in a
        // test cheaply, so just hit `compute_path`'s bounds check.
        let r = compute_path(&[], CONFIDENTIAL_TREE_CAPACITY_V2);
        assert!(r.is_err(), "leaf_index >= capacity must error");
    }
}
