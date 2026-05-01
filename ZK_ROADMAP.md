# Minamoto Wallet — ZK roadmap

Phased plan for integrating confidential transactions
(Shield / ZkTransfer / Unshield) on top of Iroha 3 / Minamoto.

## On-chain model (verified against the public i23-features branch)

Iroha 3 exposes three ISIs in `iroha_data_model::isi::zk`:

```rust
pub struct Shield {
    asset: AssetDefinitionId,
    from:  AccountId,
    amount: u128,                                 // burned from public balance
    note_commitment: [u8; 32],                    // pseudo-Poseidon over Pasta Fp
    enc_payload: ConfidentialEncryptedPayload,    // AEAD to recipient view-key
}

pub struct ZkTransfer {
    asset: AssetDefinitionId,
    inputs:  Vec<[u8; 32]>,                       // nullifiers consumed
    outputs: Vec<[u8; 32]>,                       // new commitments
    proof: ProofAttachment,                       // Halo2-IPA over Pasta
    root_hint: Option<[u8; 32]>,                  // Merkle root binding
}

pub struct Unshield {
    asset: AssetDefinitionId,
    to: AccountId,
    public_amount: u128,
    inputs: Vec<[u8; 32]>,
    outputs: Vec<[u8; 32]>,
    proof: ProofAttachment,
    root_hint: Option<[u8; 32]>,
}
```

XOR on Minamoto (asset def `6TEAJqbb8oEPmLncoNiMRbLEK6tw`) is configured
as a `Convertible` confidential asset:

```json
"confidential_policy": { "mode": "Convertible", "vk_set_hash": "..." },
"metadata": {
  "zk.policy": {
    "allow_shield": true,
    "allow_unshield": true,
    "vk_transfer": "halo2/ipa::vk_transfer",
    "vk_unshield": "halo2/ipa::vk_unshield"
  }
}
```

Shield and Unshield are permitted by policy. Verifying keys are
established on the executor side. The wallet must produce matching
proofs.

## Cryptographic primitives (verified)

The note-commitment scheme is **not** standard Poseidon. It is a
"pseudo-Poseidon" with `S-box x⁵` over **Pasta Fp** (Pallas scalar
field), hardcoded in `iroha_core::zk::confidential_v2`:

```
asset_tag    = pasta_repr( hash_to_scalar("iroha.confidential.v2.asset_tag",  asset_def_id) )
spend_scalar = hash_to_scalar("iroha.confidential.v2.spend_scalar", spend_key_bytes)
diversifier  = Scalar::ONE                       // default
owner_tag    = pasta_repr( poseidon_pair(spend_scalar, diversifier) )

rho_scalar      = hash_to_scalar("iroha.confidential.v2.note_rho", rho_bytes)
amount_scalar   = scalar_from_u128(amount)

note_commit_sc  = poseidon_pair(amount,
                    poseidon_pair(rho, poseidon_pair(owner_tag, asset_tag)))
note_commitment = pasta_repr_le_bytes(note_commit_sc)   // 32 bytes
```

with `poseidon_pair(l, r) = 2·(l+7)⁵ + 3·(r+13)⁵` in Pasta Fp, and
`hash_to_scalar(label, parts)` using Blake3 with a counter loop until
the digest is a canonical Pasta Fp.

Halo2 stack on the verifier side:

- Library: `halo2-axiom 0.5.1` (a fork of `halo2_proofs` by Axiom).
- Curve: Pasta (Pallas + Vesta).
- Polynomial commitment: IPA, k=7 (128 rows).
- Tree depth: 16 (max 65 536 leaves).
- VK is regenerated at runtime via `keygen_pk`. **No PK file is
  shipped** — the setup is transparent and deterministic.
- Circuit IDs: `halo2/pasta/ipa/anon-transfer-2x2-merkle16-poseidon-diversified`,
  `halo2/pasta/ipa/anon-unshield-merkle16-poseidon-diversified`.

## Phase 1 — implemented in this build

- `src/zk_v2.rs`: bit-for-bit port of the public confidential-v2
  helpers (`derive_confidential_diversifier_v2`, `…owner_tag…`,
  `…note_v2`, `…nullifier_v2`, `poseidon_pair`, `hash_to_scalar`).
  5 unit tests pass.
- `src/shield.rs`: builds a `Shield` ISI with a real Pasta-Fp
  commitment. `enc_payload = ConfidentialEncryptedPayload::default()`
  (zeros — see the open spec gap below).
- `src/confidential_address.rs`: parses and renders the
  `iroha:confidential:v3:<base64url>` envelope used in the wild.
- LocalNote persisted into the wallet record after Committed; required
  to spend the note in Phase 2.

## Phase 2 — pending

Steps and rough cost (Apple Silicon):

1. **Confidential-ledger indexer** (≈3 days): paginate
   `/v1/confidential/notes?asset_definition_id=…&from_block=…&cursor=…`
   from genesis (or from a known checkpoint) and persist commitments
   in a local cache. Live updates via `/v1/events/sse`.
2. **Local Merkle tree** (≈1 day): port
   `compute_confidential_merkle_path_v2`. Pure data structure built
   on the same `poseidon_pair` already implemented in Phase 1; depth
   16, max 65 536 leaves.
3. **Halo2 prover integration** (≈1-2 weeks): vendor or path-dep
   `iroha_core::zk::confidential_v2::build_confidential_unshield_proof_v2`
   and `…transfer_proof_v2`. Add `halo2-axiom 0.5.1` as a direct
   dependency. The provers are large (~700 lines each) but
   self-contained and feature-gated upstream.
4. **Unshield ISI builder** (≈1 day): construct the ISI from local
   notes + a freshly-computed Merkle path + proof. Submit and wait
   for Committed before marking the local note `spendable = false`.
5. **ZkTransfer ISI builder, self-spending** (≈1-2 days): same as
   Unshield but with output commitments derived from the wallet's
   own owner_tag (split notes for change).

### Open spec gap

`ConfidentialEncryptedPayload` (the field that lets a recipient
auto-discover incoming notes by scanning the chain with a viewing
key) is not documented in the public i23-features branch. Curve,
KDF, and AEAD are unknown. Without this, ZkTransfer to a third party
is not implementable beyond shipping zeros (which makes recipient
auto-discovery fail; the recipient must receive `rho` out-of-band).

ZkTransfer to oneself (note splitting / merging) does not need this
recipe and lands as part of step 5.

## What lands when

Phase 1 — present in v0.1.0:

- Full Shield path with real on-chain commitments.
- v3 payment-address parse / render / `pay-address` to third parties
  (recipient receives the commitment; needs `rho` out-of-band to
  spend).
- Local note storage.

Phase 2 — future release:

- Indexer and Merkle tree.
- Halo2 prover integration.
- Unshield (confidential → public).
- ZkTransfer self-split.

Phase 3 — blocked on upstream:

- ZkTransfer to a third party with auto-discovery (needs the
  documented encryption recipe, or an Iroha 3 SDK that exposes it).
