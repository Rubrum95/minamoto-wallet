# minamoto-wallet — STATUS

Snapshot of feature coverage and known limits as of v0.1.0.

## Working today

### Wallet plumbing
- `generate <label>` / `restore <label>`: Ed25519 seed creation + BIP39
  24-word mnemonic. Seed is encrypted at rest via argon2id-derived
  KEK + AES-256-GCM (Phase-1 keystore, see `password.rs`).
- `pubkey <label>` / `delete <label>` / `unlock-test <label>`: standard
  CLI surface for inspection and manual operations.
- `balance <label>`: queries `/v1/explorer/assets?owned_by=<i105>` and
  prints per-asset balance.
- `send-xor <label> <to_i105> <amount>`: builds Transfer ISI, signs
  Ed25519, POSTs to `/transaction`. Auto-prepends `Register::Account`
  on first signing operation by an unregistered account, gated by a
  chain-truth check (`torii::account_exists`).
- `register-self <label>`: standalone `Register::Account`.
- `mark-registered <label>` / `migrate-v2 <label>` / `bio-test`: migration
  and diagnostic utilities.

### Local web UI (`ui` command)
Native macOS window via `tao` + `wry`, embedding a WKWebView pointed
at `http://127.0.0.1:7825`. The HTTP server binds loopback only and
validates the `Host` header against DNS rebinding. Touch ID confirms
destructive operations; password modal handles the seed unlock with a
5-minute session cache.

UI cards: Wallet info, Balance, Send XOR, Shield XOR, My
confidential payment address (v3), Pay confidential address, Local
shielded notes, Reveal recovery secrets, Danger zone.

### Phase 1 ZK Shield
- `src/zk_v2.rs`: bit-for-bit port of the public confidential-v2
  helpers (`derive_confidential_*_v2`, `poseidon_pair`,
  `hash_to_scalar`). 5/5 unit tests pass.
- `src/shield.rs`: builds the `Shield` ISI with a real Pasta-Fp
  Poseidon commitment. `enc_payload = ConfidentialEncryptedPayload::default()`
  (zeros — see "Open spec gap" below).
- LocalNote persisted to the wallet record on Committed, required
  to spend the note in Phase 2.

### v3 confidential payment address
- Format: `iroha:confidential:v3:<base64url>` containing
  `{schema, receiveKeyId, receivePublicKeyBase64Url,
    shieldedOwnerTagHex, shieldedDiversifierHex, recoveryHint}`.
- All cryptographic primitives derive from the public Iroha 3 i23
  branch; the JSON envelope itself is reverse-engineered from
  in-wild samples and not present in the upstream public branch.
- `src/confidential_address.rs`: parse + render +
  `build_for_wallet`. 2/2 unit tests pass.
- CLI: `my-address <label>`, `pay-address <label> <recipient_uri>
  <amount> [--dry-run]`.

## Pending or blocked

### Phase 2 ZK (Unshield / ZkTransfer with real proofs)
The provers are in `iroha_core/src/zk/confidential_v2.rs` lines
2251-2700+, gated on `feature = "zk-halo2-ipa"`. Stack:
`halo2-axiom 0.5.1` + Pasta + IPA + k=7. No PK file shipped — the
runtime regenerates VK via `keygen_pk` (deterministic, milliseconds).

Pending work (estimated 1-2 weeks):

1. Vendor or path-dep `iroha_core::zk::confidential_v2` prover
   into the wallet.
2. Build a local Merkle tree from
   `/v1/confidential/notes?asset_definition_id=…` (paginated).
3. Subscribe to the `/v1/events/sse` stream for live updates.
4. Derive nullifiers from local notes and the chain's accumulator.
5. Submit `Unshield` and `ZkTransfer` ISIs.

### Open spec gap (not in i23-features public branch)
The encryption recipe behind `ConfidentialEncryptedPayload` (curve,
KDF, AEAD) is not documented publicly. Without it, recipients cannot
auto-discover incoming notes from the chain. Workaround: send `rho`
out-of-band to the recipient.

### Cross-platform builds
macOS only today (Touch ID + Keychain-legacy plumbing). Linux and
Windows ports are straightforward once the password-encrypted flow is
the only path; the `secure_enclave.rs` module would be elided behind
`cfg(target_os = "macos")`.

## Build / sign / run

```bash
cargo build --release
codesign --force --sign - target/release/minamoto-wallet
dist/make-app.sh --install     # also copies to /Applications
dist/make-dmg.sh               # produces dist/Minamoto-Wallet-X.Y.Z.dmg
```

The bundle is adhoc-signed (no entitlements). Sequoia kernel-kills
ad-hoc binaries that ship custom `keychain-access-groups`; the
production build avoids them.

## Next concrete steps (Phase 2 ramp-up)

1. **Confidential ledger indexer**: paginate
   `/v1/confidential/notes`, persist commitments in
   `~/Library/Application Support/minamoto-wallet/cache/<asset>.bin`.
2. **Locate own LocalNotes' leaf indices** in the global tree.
3. **Port `compute_confidential_merkle_path_v2`** (60 lines, depends
   only on the already-ported `poseidon_pair`).
4. **Decide vendor vs path-dep** for the Halo2 prover.
5. **Build `Unshield` ISI** using real proof attachments.
6. **Build `ZkTransfer` ISI** (self-split first; cross-recipient
   blocked on the encryption-recipe gap above).

## File map

| Path | Purpose |
|---|---|
| `src/main.rs` | clap CLI dispatch, subcommands |
| `src/wallet.rs` | seed lifecycle: generate / restore / unlock / migrate |
| `src/password.rs` | argon2id KDF + AES-256-GCM (Phase-1 keystore) |
| `src/secure_enclave.rs` | legacy v1 P-256 ECIES wrap (kept for v1 unlock) |
| `src/biometric.rs` | LAContext Touch ID gate (delete + v1 unlock) |
| `src/storage.rs` | wallet JSON record, schema v1 + v2 |
| `src/torii.rs` | HTTP client for Iroha REST endpoints |
| `src/transfer.rs` | Transfer ISI builder + auto-Register prepend |
| `src/balance.rs` | `/v1/explorer/assets` query + display |
| `src/zk_v2.rs` | port of `iroha_core::zk::confidential_v2` primitives |
| `src/shield.rs` | Shield ISI builder + commitment derivation |
| `src/confidential_address.rs` | v3 payment address parse / render |
| `src/delete_challenge.rs` | 3-word BIP39 confirmation for delete |
| `src/session.rs` | in-memory password cache (5-min TTL) |
| `src/ui.rs` + `src/ui_index.html` | tao+wry native window + tiny_http API |
| `src/consts.rs` | `TORII_BASE`, `CHAIN_ID`, `XOR_ASSET_DEFINITION_ID`, `NETWORK_PREFIX` |
| `WALLET_DESIGN.md` | architecture rationale |
| `ZK_ROADMAP.md` | confidential phase plan |
| `MIGRATION.md` | v1 → v2 keystore migration; future YubiKey 5C path |
| `AUDIT.md` | adversarial security review |
| `SECURITY.md` | disclosure policy |
