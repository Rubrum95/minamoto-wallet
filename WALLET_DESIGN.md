# Minamoto Wallet — design and security model

This document describes the architecture and explicit security trade-offs
of the wallet. It is the canonical reference when reading the code:
choices that look surprising in `src/` are usually explained here.

## What the wallet does

A Rust binary, single executable, ad-hoc-signed for macOS, exposing a
CLI and a native window UI (tao + wry + WKWebView). Capabilities:

```
minamoto-wallet generate <label>          # new wallet: Ed25519 + I105 + BIP39 mnemonic
minamoto-wallet restore  <label>          # recover from mnemonic
minamoto-wallet pubkey   <label>          # show pubkey + I105 (no auth)
minamoto-wallet balance  <label>          # query Torii for live balances
minamoto-wallet send-xor <label> <to> <x> # build + sign + submit Transfer ISI
minamoto-wallet shield   <label> <amount> # build Shield ISI (Phase 1)
minamoto-wallet pay-address <label> <uri> <amount> [--dry-run]
minamoto-wallet my-address <label>        # generate iroha:confidential:v3:… URI
minamoto-wallet register-self <label>     # standalone Register::Account
minamoto-wallet migrate-v2 <label>        # migrate v1 (SE) → v2 (password)
minamoto-wallet ui                        # native window + local API
```

### Stack

- **Language**: Rust 1.92+, no other languages.
- **On-chain crypto**: `iroha_crypto` + `iroha_data_model` +
  `iroha_torii_shared` (path-deps to a local Iroha 3 i23-features
  clone).
- **Seed encryption (Phase 1)**: `argon2id` (m=64MB, t=3, p=1) +
  `aes-gcm` AES-256-GCM. See `src/password.rs`.
- **Touch ID**: macOS LocalAuthentication via `objc2-local-authentication`.
  Used as a confirmation gate for destructive ops (delete) and on the
  legacy v1 unlock path.
- **Native window**: `tao` (windowing) + `wry` (WKWebView) + `muda`
  (macOS menu bar so Cmd+C/V/X work in inputs).
- **Local API**: `tiny_http` bound to `127.0.0.1:7825`, with Host-header
  validation and a 5-minute session cache for unlocked passwords.
- **HTTP client**: `reqwest` (blocking, rustls-TLS).
- **ZK primitives (Phase 1)**: `pasta_curves` + `blake3` for the
  Pasta-Fp Poseidon-pair commitments used by Shield.

## Concepts the reader should know

1. **Account IDs are not Ethereum-style addresses.** They are **I105**
   strings: prefix `sora` + half-width katakana characters encoding
   the public key + checksum. Example shape:
   ```
   sorauﾛ1<KATAKANA-PAYLOAD-FROM-PUBKEY>XXXXXX
   ```
   The katakana characters are literal (U+FF65-U+FF9F), not Unicode
   escapes. Encoding mismatches between apps can corrupt the string.

2. **The cross-chain bridge (Sora v2 → Minamoto) is not trustless.**
   It is operator-mediated: a v2 burn extrinsic with a structured
   `system.remark` JSON (`{"type":"soraNexusXorClaim","version":1,
   "recipient":"<i105>"}`) is detected by an indexer, and a Soramitsu
   account mints the equivalent XOR on Minamoto. Burns of fractional
   XOR amounts are silently dropped by the indexer (whole-XOR-only
   eligibility). The wallet is not in this critical path; it only
   receives.

3. **Implicit accounts cannot spend until they are formally
   registered.** Accounts created by the operator's `Mint::Asset`
   from a cross-chain claim require a `Register::Account` ISI before
   any Transfer / Shield / Unshield is accepted. The wallet handles
   this transparently by prepending `Register::Account` on the first
   signing operation when the chain reports the account does not yet
   exist (`torii::account_exists`).

4. **Touch ID has explicit limits in this build.** macOS Sequoia
   blocks ad-hoc-signed binaries from applying biometric
   `kSecAttrAccessControl` to keychain items
   (`errSecMissingEntitlement` -34018, verified empirically via the
   `bio-test` subcommand). The hard cryptographic gate for v2
   wallets is therefore the **password**; Touch ID is a UX
   confirmation layer for destructive operations only. Phase 0
   wallets that pre-date password encryption (v1 keystore) still
   use Touch ID as the unlock factor — `migrate-v2 <label>` moves
   them onto the v2 path.

## Keystore

### v2 (current, password-encrypted)

```
WalletRecord {
  label:                String,
  network_prefix:       u16,         // 753 for Minamoto
  public_key_hex:       String,      // ed0120<hex>
  i105_address:         String,
  password_encrypted:   {
    kdf:                "argon2id",
    kdf_params:         { m_cost_kb: 65536, t_cost: 3, p_cost: 1, salt_len: 16 },
    salt_b64:           "<16 bytes b64>",
    cipher:             "aes-256-gcm",
    nonce_b64:          "<12 bytes b64>",
    ciphertext_b64:     "<48 bytes b64 = 32 plaintext + 16 GCM tag>"
  },
  created_at:           "<ISO-8601 UTC>",
  version:              2,
  notes:                Vec<LocalNote>,           // Phase-1 Shield records
  registered_on_chain:  bool,                     // hint, chain is source of truth
}
```

The encrypted blob lives in
`~/Library/Application Support/minamoto-wallet/<label>.json` (mode
`0600`, in a `0700` directory). Reading the file alone yields no
custody material; the password is required to decrypt the seed.

### v1 (legacy, Secure-Enclave-adjacent)

The v1 keystore stored an ECIES-wrapped seed under a software P-256
key in the user's `login.keychain`. No biometric ACL on the keychain
item itself (Apple gates that path behind an entitlement). Touch ID
was a user-space LAContext check, bypassable by other processes
running as the same user. v1 wallets are still loadable for backwards
compatibility but `migrate-v2` is recommended for any wallet holding
non-trivial XOR.

## Security trade-offs

The wallet's threat model and its concrete responses are documented
in detail in [`AUDIT.md`](./AUDIT.md). Headline points:

- **Local malware as same user**: blocked from extracting v2 seeds
  (needs the password). v1 seeds were vulnerable; migration
  recommended.
- **DNS rebinding from any browser tab**: blocked (Host-header
  validation in `src/ui.rs`).
- **Stolen Mac with backup but no password**: cannot extract any v2
  seed (offline brute-force against argon2id with m=64MB t=3 is
  impractical with a strong passphrase).
- **Lost mnemonic**: irrecoverable. By design.
- **Phase 2 confidential proofs**: not yet implemented; see
  [`ZK_ROADMAP.md`](./ZK_ROADMAP.md).

## Build outputs

```
target/release/minamoto-wallet     # 16 MB Rust binary, adhoc-signed
dist/Minamoto Wallet.app/          # macOS bundle (Info.plist + wrapper + icon)
dist/Minamoto-Wallet-X.Y.Z.dmg     # 8.8 MB distributable installer
```

`.cargo/config.toml` applies `--remap-path-prefix` to strip host paths
from the binary (cargo registry, project paths). The result is a
binary whose `strings(1)` output contains no host-identifying
references.

## What's not in this document

- Step-by-step build instructions → see [`README.md`](./README.md).
- Vulnerability reporting → see [`SECURITY.md`](./SECURITY.md).
- Confidential transfer roadmap → see [`ZK_ROADMAP.md`](./ZK_ROADMAP.md).
- v1 → v2 keystore migration mechanics → see [`MIGRATION.md`](./MIGRATION.md).
- Adversarial review and resolved findings →
  see [`AUDIT.md`](./AUDIT.md).
