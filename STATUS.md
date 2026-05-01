# minamoto-wallet — STATUS at 2026-04-30

Snapshot of where the project stands. Updated when meaningful work lands.

## Working today (verified end-to-end)

### Wallet plumbing
- `generate <label>` / `restore <label>`: Ed25519 seed creation + BIP39 24-word
  mnemonic + ECIES P-256 wrap into login.keychain. Touch ID + password fallback
  via `LAContext.evaluatePolicy(2)`.
- `pubkey <label>` / `delete <label>` / `unlock-test <label>`: Touch ID gate
  works on ad-hoc-signed binaries (no Apple Developer ID).
- `balance <label>`: queries `/v1/explorer/assets?owned_by=<i105>` and prints
  the balance per asset.
- `send-xor <label> <to_i105> <amount>`: builds Transfer ISI, signs Ed25519,
  POSTs to `/transaction`. **Confirmed Committed on chain** (tx
  `e79723ed87c8e8d7587352bc3639ae72006347738200c0601a6080f6b9dd28e9`,
  block 39, mi-wallet → prova 2, 0.5 XOR). Auto-prepends `Register::Account`
  if the wallet's local `registered_on_chain` flag is `false`.
- `register-self <label>`: standalone `Register::Account`. **Confirmed
  Committed** for mi-wallet at block 37.
- `mark-registered <label>`: local-only flag flip for wallets registered
  before the auto-register feature shipped.

### Local web UI (`ui` command)
- tiny_http on `127.0.0.1:7825`. Cards: wallet info, balance, send XOR,
  shield XOR, local notes, danger zone. Auto-opens browser. Mnemonic shown
  only on creation, scrubbed + reload on dismiss.

### Phase 1 ZK Shield
- `src/zk_v2.rs` is a bit-for-bit port of
  `iroha_core::zk::confidential_v2` helpers (5/5 unit tests green):
  `derive_confidential_diversifier_v2`, `…owner_tag…`, `…note_v2`,
  `…nullifier_v2`, plus `poseidon_pair`, `hash_to_scalar`.
- `src/shield.rs` builds `Shield` ISI with **real** Pasta-Fp commitment.
  `enc_payload = ConfidentialEncryptedPayload::default()` (zeros — payload
  encryption recipe still undocumented upstream; recipient receives
  out-of-band, no auto-discovery).
- LocalNote persisted to `~/Library/Application Support/minamoto-wallet/<label>.json`
  for self-shields; skipped for external recipients.

### V3 confidential payment address — `iroha:confidential:v3:<base64url>`
- Format reverse-engineered from `@sora_xor`'s public Twitter post; **schema
  string `iroha-confidential-payment-address/v3` does not appear in
  i23-features public branch**, but every primitive that builds it does
  (`iroha_js_host::derive_confidential_receive_address_v2`,
  `iroha_crypto::ConfidentialKeyset` with HKDF-SHA3-512).
- `src/confidential_address.rs`: parse + render + `build_for_wallet`.
  2/2 unit tests pass (round-trip + tweet sample).
- CLI:
  - `my-address <label>` — generates our v3 URI (Touch ID).
  - `pay-address <label> <recipient_uri> <amount> [--dry-run]` —
    sends Shield to a third-party owner_tag/diversifier. `--dry-run`
    skips Touch ID + signing + submit (validation only).
- Cross-wallet round-trip verified offline:
  `my-address 'prova 2'` and `pay-address mi-wallet '<URI>' 1 --dry-run`
  produce **bit-identical** owner_tag + diversifier hex strings.

## Blocked or pending

### Phase 2 ZK (Unshield / ZkTransfer with real proofs)
- Audited `i23-features`: provers are in `iroha_core/src/zk/confidential_v2.rs`
  lines 2251-2700+, gated on `feature = "zk-halo2-ipa"`. Using
  `halo2-axiom 0.5.1` + Pasta + IPA + k=7. **No PK file shipped** — the
  runtime regenerates VK via `keygen_pk` (deterministic, milliseconds).
- Indexer endpoint exists: `GET /v1/confidential/notes?asset_definition_id=…&from_block=…&cursor=…`
  paginates over Shield/ZkTransfer/Unshield instructions per asset.
- Live event stream: `/v1/events/sse` (JSON SSE) + WebSocket `/events`.
- **Not started**: vendor or path-dep `iroha_core::zk::confidential_v2`
  prover into the wallet, build local Merkle tree from the indexer,
  derive nullifiers, submit Unshield. Estimated 1-2 weeks once we
  decide whether to vendor (manageable but maintenance debt) vs depend
  on `iroha_core` directly (binary balloons with ~100 transitive deps).
- **Open spec gap (not in i23-features)**: encryption recipe behind
  `ConfidentialEncryptedPayload` (curve, KDF, AEAD). Without it, recipients
  cannot auto-discover incoming notes from the chain. Workaround: send
  rho out-of-band.

### Stuck cross-chain burn (1.5 XOR)
- v2 burn `0x4b92217ecf2a727ebae8e4bb907fb3f61b28cd1bdb2f1433d84a02b36d6671d5`
  → `mi-wallet`, 1.5 XOR. Signer `cnVS46aLyfRHTossU1ZEXaw6Eok1Lk9NeMdhJsSNzp7ywJLEq`.
- Visible in sorametrics' `pending-burns` (sora-subsquid sees it). claim-api
  responds `indexed: false` permanently and POSTs `failed_claim_fee_required`.
- **Root cause confirmed**: across 15 burns by this signer, every claimed
  one is a **whole XOR** integer (1, 2, 3, 10, 20, 30, 100). 1.5 is the
  only fractional → indexer rejects as "not eligible finalized burn".
- v2 chain accepted the burn anyway (no client-side validation),
  so the 1.5 XOR is destroyed on v2 with no automatic mint on Minamoto.
- Manual fee path documented in `world.rs` exists (`POST /claim-api/v1/claims`
  with `claimantAccount` + `feeTxHash`) but operator account + fee amount
  not publicly documented; risk: pay fee + still rejected.
- **Recovery path: contact Soramitsu support directly** (not yet done).

### Balance under Shield minimum
- Shield ISI hardcodes `Numeric::new(amount_u128, 0)` (scale 0) at
  `iroha_core/src/smartcontracts/isi/world.rs:8289`. Only whole XOR
  amounts are valid (≥ 1).
- mi-wallet balance: 0.359 XOR. prova 2: 0.6 XOR. Pool combined: 0.959.
  **Cannot Shield with current funds.** Test of `pay-address` real
  submission blocked until ≥ 1 XOR enters one wallet.

## Compile / sign / run

- `cargo build --release` then `codesign --force --sign - target/release/minamoto-wallet`
  (no entitlements — Sequoia kills ad-hoc binaries with custom
  `keychain-access-groups`). Use `--no-default-features` is NOT needed.
- Always run from a user Terminal window. Touch ID prompts triggered by
  `Bash` subprocess get `LAError -4` (system cancel).
- After every rebuild macOS asks for Keychain password 3-5 times the first
  time the new cdhash is used. Click "Permitir siempre" once per rebuild.

## Next concrete steps (when balance lands)

1. **`pay-address mi-wallet '<prova-2-uri>' 1`** — first real Shield to a
   non-self owner_tag. Confirms the v3 envelope is operationally compatible
   with chain validation.
2. After Committed: confirm commitment shows up at `/v1/confidential/notes`
   filtered by XOR — that proves the global Merkle tree absorbed it.
3. Implement `import-note <label> --rho <hex> --amount <n>` so `prova 2`
   can register the received note in its local JSON for future spend.
4. Begin Phase 2 indexer (`src/confidential_index.rs`): paginate
   `/v1/confidential/notes`, persist commitment list, reconstruct Merkle
   path via ported `compute_confidential_merkle_path_v2`.
5. Decide vendor vs path-dep for the Halo2 prover.

## File map

| Path | Purpose |
|---|---|
| `src/main.rs` | clap CLI dispatch, subcommands |
| `src/wallet.rs` | seed lifecycle: generate / restore / unlock |
| `src/secure_enclave.rs` | login.keychain ECIES P-256 wrap (NOT real SE; ad-hoc binaries can't use SE token-id) |
| `src/biometric.rs` | LAContext Touch ID gate |
| `src/storage.rs` | wallet JSON record under `~/Library/Application Support/minamoto-wallet/` |
| `src/torii.rs` | HTTP client for `/transaction`, `/v1/explorer/...`, `wait_for_commit` |
| `src/transfer.rs` | Transfer ISI builder + auto-Register prepend |
| `src/balance.rs` | `/v1/explorer/assets` query + display |
| `src/zk_v2.rs` | port of `iroha_core::zk::confidential_v2` primitives |
| `src/shield.rs` | Shield ISI builder (self + external recipient) |
| `src/confidential_address.rs` | v3 payment address parse/render |
| `src/ui.rs` + `src/ui_index.html` | local web UI on 127.0.0.1:7825 |
| `src/consts.rs` | `TORII_BASE`, `CHAIN_ID = 00000000-0000-0000-0000-000000000000`, `XOR_ASSET_DEFINITION_ID = 6TEAJqbb8oEPmLncoNiMRbLEK6tw`, `NETWORK_PREFIX = 753` |
| `WALLET_DESIGN.md` | architecture rationale (v0) |
| `ZK_ROADMAP.md` | confidential phase plan, updated post-deep-dive |
| `MIGRATION.md` | path to YubiKey 5C and proper SE in v1 |
