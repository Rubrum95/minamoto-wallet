# Security policy

## Reporting a vulnerability

Do **not** open a public Issue for vulnerabilities.

Use GitHub's private security advisories:
<https://github.com/Rubrum95/minamoto-wallet/security/advisories/new>.
This route is end-to-end encrypted between reporter and maintainer,
and lets a fix + disclosure timeline be coordinated before public
disclosure.

Acknowledgement target: 72 hours. Fix target for custody-affecting
issues (seed extraction, signing without auth, etc.): 14 days.
Lower-severity issues: best-effort.

## Scope

In scope:

- The `minamoto-wallet` binary: signing flow, password handling,
  seed encryption / decryption, IPC between the embedded WKWebView
  and the loopback HTTP server, build / packaging scripts.
- `dist/make-app.sh` and `dist/make-dmg.sh`.
- Documentation that materially misleads about the security model
  (e.g. wrong threat-model claims in `README.md` / `AUDIT.md`).

Out of scope:

- Vulnerabilities in upstream Iroha 3 (`iroha_crypto`,
  `iroha_data_model`, etc.) — report to
  <https://github.com/hyperledger-iroha/iroha>.
- Third-party crate vulnerabilities (argon2, aes-gcm, reqwest, tao,
  wry, etc.) — report upstream.
- macOS / Apple platform bugs.
- Lost mnemonics — by design unrecoverable.
- Phishing / social-engineering / fake "Minamoto Wallet" downloads
  hosted elsewhere — only the official Releases page on this repo
  is authoritative.

## Self-verification path

The repo is fully open and the build is reproducible from source.

1. **Read the source** — 13 Rust files (~3500 lines) plus one
   HTML/JS UI. Entry points: `src/main.rs`, then `src/wallet.rs` +
   `src/password.rs` for the crypto path, `src/ui.rs` for the local
   API surface.

2. **Build from source and compare against the published `.dmg`**:

   ```bash
   git clone https://github.com/Rubrum95/minamoto-wallet
   cd minamoto-wallet
   cargo build --release
   shasum -a 256 target/release/minamoto-wallet
   ```

   The Release notes list both the binary SHA-256 and the `.dmg`
   SHA-256. The binary hash will match across machines because
   `.cargo/config.toml` strips host paths via `--remap-path-prefix`.
   The `.dmg` envelope itself contains timestamp metadata and may
   produce different overall hashes per build.

3. **Run the unit tests**:

   ```bash
   cargo test --release
   ```

   Current suite covers `password` (round-trip + wrong-password
   rejection + fresh-salt invariant + empty-password rejection) and
   `confidential_address` (round-trip + parse against the public
   `@sora_xor` v3 sample). Coverage is incomplete; PRs that add
   tests welcome.

## Limits of "code is open"

Public source eliminates the "what if the binary does something the
README doesn't say" risk class. It does not produce an audit by
itself: anyone can read the code, but few will. For genuine
third-party assurance, the wallet would need:

- A **paid scoped audit** by a firm such as Trail of Bits, Cure53,
  or Sigma Prime. Estimate: $30-80k for a wallet of this size.
- A **bug bounty program** (Immunefi or similar) with a published
  payout table.

Until either exists, treat this software as **Phase 1,
single-maintainer, use-at-your-own-risk**. Test with small amounts
first. The 24-word BIP39 mnemonic on paper is the only
disaster-recovery path.

## Past audits

- **Internal adversarial review** (the maintainer): see
  [`AUDIT.md`](./AUDIT.md). Findings classified CRITICAL → LOW with
  reproduction steps and mitigation status. Resolved findings are
  marked accordingly; outstanding items list scope and rationale.
