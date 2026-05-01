# Security policy

## Reporting a vulnerability

**If you find a vulnerability, do NOT open a public Issue.**

Use one of:

1. **GitHub Private Security Advisory** — preferred:
   <https://github.com/Rubrum95/minamoto-wallet/security/advisories/new>.
   This route is end-to-end encrypted and lets us coordinate a fix +
   disclosure timeline before anything hits the public.

2. **Email**: jtvr90 [at] gmail.com — subject line starts with
   `[minamoto-wallet security]`. Plain English is fine; if you want
   PGP, request the key in a first round-trip.

We aim to acknowledge within 72 hours and ship a patch within 14 days
for issues that affect custody (seed extraction, signing-without-auth,
etc.). Lower-severity issues get a best-effort timeline.

## Scope

In scope:

- The `minamoto-wallet` binary: signing flow, password handling, seed
  encryption / decryption, IPC between the embedded WKWebView and the
  loopback HTTP server, build / packaging scripts.
- The `dist/make-app.sh` and `dist/make-dmg.sh` packaging scripts.
- Documentation that materially misleads about the security model
  (e.g. wrong threat-model claims in README / AUDIT.md).

Out of scope (not "won't fix" — "we cannot fix"):

- Vulnerabilities in upstream Iroha 3 (`iroha_crypto`,
  `iroha_data_model`, etc.) — please report those to
  <https://github.com/hyperledger-iroha/iroha>.
- Vulnerabilities in third-party crates we depend on (argon2, aes-gcm,
  reqwest, tao, wry, etc.) — report upstream.
- macOS / Apple platform bugs.
- Lost mnemonics. By design we cannot recover them; the user is the
  only person who ever sees the seed phrase.
- Phishing / social-engineering / fake "Minamoto Wallet" downloads
  hosted elsewhere — only the official Releases page on this repo is
  ours.

## What you can audit yourself, today

The repo is fully open and the build is reproducible from source. The
realistic verification path:

1. **Read the source** — 13 Rust files (~3500 lines) + one HTML/JS UI.
   Start with `src/main.rs`, then `src/wallet.rs` and `src/password.rs`
   for the crypto path. `src/ui.rs` covers the local API surface.
2. **Build from source** and compare with the `.dmg` we publish:

   ```bash
   git clone https://github.com/Rubrum95/minamoto-wallet
   cd minamoto-wallet
   cargo build --release
   shasum -a 256 target/release/minamoto-wallet
   ```

   Compare against the `sha256sum` of the binary inside the published
   `.dmg` (the Release notes list both). They will match for the
   binary; the `.dmg` envelope itself includes timestamp metadata
   that may produce different overall hashes per build (see Apple's
   `hdiutil` documentation).

3. **Run the unit tests**:

   ```bash
   cargo test --release
   ```

   The current suite covers `password` round-trip + wrong-password
   rejection, and `confidential_address` round-trip + the public
   `@sora_xor` v3 sample. Coverage is incomplete; PRs adding more
   tests welcome.

## What "code review" doesn't fix

Honest framing: opening the source eliminates one class of risk
("what if the binary does something the README doesn't say") but
introduces no audit-by-default. Anyone can read it; not many will.
For genuine third-party assurance, the wallet would need:

- A **paid, scoped audit** by a firm like Trail of Bits, Cure53, or
  Sigma Prime. Estimate: $30-80k for a wallet of this size.
- A **Bug Bounty program** (Immunefi or similar) with a published
  payout table. Pre-funded; not free.

Until either of those exists, treat this software as **Phase 1,
single-maintainer, use-at-your-own-risk**. Test with small amounts.
The 24-word mnemonic on paper is your only disaster-recovery path.

## Past audits

- **2026-05-01 — internal adversarial review** (the maintainer):
  see [`AUDIT.md`](./AUDIT.md). Classifies findings CRITICAL → LOW
  with reproduction steps and mitigation status. Most useful sections:
  C1 (why we use password-encrypted keystore instead of native
  Keychain biometric ACL), H1 (DNS-rebinding defense), H2 (delete
  Touch-ID gate), and the long list of "Verifications that PASSED".
