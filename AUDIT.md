# minamoto-wallet — Security audit (2026-05-01)

Adversarial review of every byte that touches a secret. Findings are
ordered by severity. Each one says: what it is, who can exploit it,
how, and the proposed fix (status: **fixed**, **mitigated**, **accepted
risk**, or **deferred**).

## Threat model in scope

| Adversary | Capability | In scope |
|---|---|---|
| Local malware as same user | Read user files, exec processes, talk to localhost ports | ✅ primary |
| Other users on same Mac | No privileges over our user | ✅ |
| Remote network attacker | Sit between us and Torii | ✅ |
| Malicious website in user's browser | DNS rebinding / CORS abuse | ✅ |
| Physical access while unlocked | Keyboard, screen, USB | ✅ |
| Backup compromise | Time Machine / iCloud Drive sync | ✅ |
| Supply-chain | Malicious crate update | ✅ |
| Apple itself | Compromised SE / Keychain primitives | ❌ out of scope |
| Hardware attacker with cold-boot / DMA | Physical RAM extraction | ❌ — Phase 0 documented |
| Quantum adversary on Ed25519 | Future-state | ❌ — chain itself is not PQ-safe |

---

## Findings

### CRITICAL

#### C1 — ~~Software keychain wrap is not biometric-ACL-bound~~ → **CLOSED via Phase-1 password encryption (2026-05-01)**

The seed is wrapped with a **software** P-256 key in the user's
`login.keychain`, with **no `kSecAttrAccessControl` biometric flag**.
Touch ID is enforced separately via `LAContext.evaluatePolicy` in
`biometric.rs`, which is a process-level check **outside** of
`securityd`.

**Exploit**: any malicious process running as the same user can call
`SecKeyCreateDecryptedData` directly against the wrap key — the OS
unlocks the keychain item silently because the user's session is
already authenticated. The Touch ID prompt our wallet shows is
front-end only; an attacker that bypasses `unlock_seed()` extracts
the seed without any prompt.

**Why we're here**: SE-tokenID + native biometric ACL require
`com.apple.application-identifier` entitlement which only an Apple
Developer ID-signed binary gets ($99/yr). We tested this empirically
(see `STATUS.md` and `MIGRATION.md`).

**Empirical re-test 2026-05-01** (`bio-test` subcommand): we tried
the path of applying `kSecAccessControlBiometryAny | Or |
kSecAccessControlDevicePasscode` directly to a software P-256 key
(no SE-tokenID, no `keychain-access-groups` entitlement). Outcome:
`SecKeyCreateRandomKey` returns `errSecMissingEntitlement
(-34018)` at key generation time. The biometric-ACL path is therefore
**also** gated for ad-hoc binaries — it is not just SE-tokenID.
Confirmed: closing C1 without an Apple Developer ID is impossible
through the Keychain. Path forward is the password-encrypted Phase-1
design (this commit and following).

**Status**: documented in `biometric.rs` and `secure_enclave.rs`.
**Fix path**: Phase 1 of the wallet roadmap — Apple Developer ID
signing + native biometric ACL OR YubiKey 5C with on-device PIN +
touch.

**Mitigations in place**:
- Wallet record dir is `0700`, files `0600`.
- BIP39 mnemonic is the only off-machine secret (paper backup).
- Single-user Mac assumption documented in `WALLET_DESIGN.md`.

**Resolution (2026-05-01)**: this entire concern is structurally
eliminated by the Phase-1 keystore migration. New wallets (and
existing v1 wallets after `migrate-v2`) encrypt the seed with a
user-chosen password via argon2id (m=64MB, t=3) + AES-256-GCM. The
encrypted blob lives in the wallet JSON file; the Keychain plays no
role in custody anymore. Local malware reading the JSON gets nothing
without the password (offline brute-force ≈1s/guess on M1, so a
strong passphrase is impractical to crack). See `src/password.rs` and
`STATUS.md` for the full design. Both `mi-wallet` and `prova 2` were
migrated; the dead-code `make_access_control()` path is kept only for
the audit experiment (`bio-test`) that confirmed the entitlement
gating empirically.

---

### HIGH

#### H1 — DNS rebinding lets any website POST to our localhost API (FIXED)

`tiny_http` binds `127.0.0.1:7825`, which prevents remote-network
access. But a malicious website can resolve `evil.com` to `127.0.0.1`
mid-session (DNS rebinding). The browser then sends requests to
`evil.com` thinking it's same-origin, but the TCP target is our
loopback server.

Without `Host` header validation our server processes those requests
as legitimate.

**Exploit (pre-fix)**: a tab the user has open in any browser visits
a malicious page that periodically POSTs to its rebound `127.0.0.1`,
hitting `/api/wallet/<label>/send` etc. Touch ID still gates real
signing, but `/api/wallet/<label>` `DELETE` (see H2) and
`/api/quit` had no such gate.

**Fix (this turn)**: server checks the `Host` header is exactly
`127.0.0.1:7825` or `localhost:7825`; everything else returns 421
"Misdirected Request". DNS-rebound `evil.com` requests carry
`Host: evil.com` and now fail.

#### H2 — `DELETE /api/wallet/<label>` had no Touch ID server-side (FIXED)

The HTML UI's JS prompts `confirm()` before issuing DELETE, but the
backend itself didn't gate the operation. A successful DNS rebind
(see H1) or any local process calling `curl -X DELETE
http://127.0.0.1:7825/api/wallet/mi-wallet` would silently delete
the SE wrap and the on-disk record.

**Damage**: catastrophic — without the BIP39 mnemonic, the wallet is
unrecoverable.

**Fix (this turn)**:
1. The DELETE handler now calls `biometric::prompt(...)` BEFORE
   touching either the keychain or the file. Server-side enforcement,
   not browser trust.
2. H1's Host check is still the outer guard.

#### H3 — No Cargo.lock pinning workflow (deferred, accepted)

The `Cargo.lock` is committed (good), but our path-deps (`iroha_*`
local source) version-track upstream `i23-features` directly via
`git pull`. A malicious upstream commit lands in our build the moment
we rebuild. Same risk for crates.io: any compromised crate update is
pulled at the next `cargo update`.

**Mitigation in place**:
- All runtime deps are well-known crates (anyhow, reqwest, blake3,
  pasta_curves, etc.). No obscure or recently-published crates.
- The path-deps point at an Iroha checkout the user controls; they
  can `git diff` before rebuilding.

**Accepted risk** for now. Future hardening: `cargo deny` for advisory
checks, plus pinned `iroha-source` commit hash in CI.

---

### MEDIUM

#### M1 — Seed in process memory during sign window (accepted, mitigated)

Between `wallet::unlock_seed()` returning and `Zeroizing<[u8;32]>`
dropping at end of scope, the seed is in our heap for ~milliseconds.
A debugger attached to the process could read it.

**Mitigation in place**:
- `Zeroizing` wraps the seed.
- Build is hardened-runtime-OFF (we removed entitlements due to
  Sequoia kernel kill, see `STATUS.md`), but binary is still
  ad-hoc-signed.
- macOS by default blocks `task_for_pid()` against same-uid
  non-debugger-entitled processes (System Integrity Protection on +
  no `com.apple.security.cs.debugger` entitlement on the attacker).

**Residual**: SIP off + signed-by-user attacker tool can attach. Out
of scope for Phase 0.

#### M2 — `dump-client-toml` prints `private_key` plaintext (accepted, gated)

`minamoto-wallet dump-client-toml <label>` prints the Ed25519 seed in
hex on stdout, intended for debugging with the official `iroha` CLI.

**Risks**:
- Terminal scroll buffer / shell history records the value.
- Screen-recording extensions in browsers (irrelevant to CLI but
  worth noting if we ever pipe through a UI).
- Clipboard managers if user copies output.

**Mitigation**: warning printed before disclosure. Subcommand exists
only for testnet-style debugging, not for routine use.

**Recommendation (deferred)**: require an extra confirmation flag
(e.g. `--i-understand-this-prints-my-seed`) to stop accidental
double-tab-completion runs.

#### M3 — ~~`LAContext` policy is `DeviceOwnerAuthentication`~~ → **OBSOLETE** (2026-05-01)

The decorative `biometric::prompt` call inside the v2 unlock_seed path
was removed. v2 wallets (post-migration) now use the wallet password as
the sole auth factor, with no LAContext popup. Touch ID survives only
in:

- The DELETE handler (explicit destruction gate).
- The legacy v1 unlock path (kept for users who haven't migrated yet).

The original concern (device-password fallback being equivalent to
session login) is therefore moot for the canonical Phase-1 flow.

#### M4 — Torii responses are not authenticated end-to-end (accepted)

`reqwest` enforces `rustls-tls`, so a network MITM needs a valid TLS
cert for `minamoto.sora.org` — high bar. But a compromised Torii
endpoint (via Soramitsu-side breach) can:
- Lie about balances → user thinks they have more/less than they do.
- Lie about asset definitions → user shields to wrong asset.
- Drop our submitted tx silently → user thinks it landed.

**Mitigations in place**:
- Local tx is signed; attacker can't modify it without breaking Ed25519.
- `wait_for_commit` polls until the chain confirms or 60s timeout.
- We never sign a tx based on data the chain returned (the recipient
  I105 etc. is user input, not chain output).

**Out-of-scope**: validating block headers / Merkle proofs locally
(would require running an Iroha 3 light client).

#### M5 — No rate limiting on `/api/*` endpoints (deferred)

A local malware as same user can spam `POST /api/wallet/X/send` to
trigger Touch ID prompt fatigue (user clicks through prompts after
the 5th re-prompt, especially when their workflow has trained them
to expect prompts). Or just hit `/api/quit` in a loop to make the
wallet unusable.

**Recommendation (deferred)**: per-endpoint rate limit, e.g. 1 req/s
on signing endpoints with a 5-second cooldown after each Touch ID
denial.

---

### LOW

#### L1 — ECIES wrap algorithm choice (verified OK)
`ECIESEncryptionCofactorVariableIVX963SHA256AESGCM` — variable IV +
AES-GCM + SHA-256 KDF. Apple-recommended for software P-256 wraps.

#### L2 — BIP39 mnemonic UI display memory hygiene (mitigated)
On wallet creation, the mnemonic is rendered into the DOM. The
Continue button calls `clearChildren()` then `window.location.reload()`
to wipe DevTools network history and the JS heap. The Rust side wraps
the mnemonic in `Zeroizing<String>`.

#### L3 — Time Machine backups capture wrapped seed (accepted)
The Application Support file is included in default Time Machine
backups. The wrap key (`login.keychain`) is also backed up. A backup
volume + the user's macOS password = full wallet.

**Mitigation**: BIP39 mnemonic on paper is the canonical recovery and
the wallet's threat-model recovery path. Time Machine doesn't help
or hurt vs. that.

**Recommendation**: document for the user that they should consider
their Time Machine target as secret-bearing.

#### L4 — ~~`mark-registered` flag flip doesn't verify against chain~~ → **FIXED (2026-05-01)**
`transfer.rs` and `shield.rs` now consult the chain via
`torii::account_exists(i105)` before deciding whether to prepend
`Register::Account`. If the chain disagrees with the local flag we
update the local flag forward. The `mark-registered` CLI command
remains for offline use, but its output no longer matters at signing
time — the chain is the source of truth.

#### L5 — adhoc-signed binary, no notarization (accepted, distribution)
First-launch Gatekeeper warning. Required for `Cmd+Click → Open`
the first time. Notarization needs Apple Developer ID. See
`MIGRATION.md`.

#### L6 — `/api/quit` endpoint has no auth (FIXED via H1)
Before H1, any localhost peer could kill the wallet. Now Host
validation gates it; only same-origin (the WKWebView itself) can hit
it.

---

## Verifications that PASSED

| Check | Result |
|---|---|
| `tiny_http` bind is `127.0.0.1`, not `0.0.0.0` | ✅ |
| HTTPS-only Torii client (`reqwest` + `rustls-tls`) | ✅ |
| `Zeroizing` on seed across all unlock paths | ✅ |
| `ZeroizeOnDrop` on `iroha_crypto::PrivateKey` | ✅ |
| Wallet dir `0700`, files `0600` | ✅ |
| No accidental seed/key/mnemonic logging | ✅ (`grep -nE 'eprintln!|println!' src/*.rs` audited; only `dump-client-toml` and one-shot mnemonic display) |
| HTML UI uses `textContent` / `createElement` (no `innerHTML`) | ✅ |
| `extract_label` blocks path traversal post-URL-decode (`%2F` → `/` is checked AFTER decode) | ✅ |
| `loopback only` IP check on incoming connection | ✅ |
| `NoteSummary` exposed via `/api/notes` does NOT include `rho_hex` | ✅ |
| `pay-address` response includes `rho_hex` (intentional, sender shares with recipient) | ✅ |
| BIP39 entropy is exactly 32 bytes from `OsRng` | ✅ |
| Mnemonic-on-creation is the **only** way the seed plaintext touches stable storage (paper) | ✅ |
| Shield ISI now waits for `Committed` before persisting LocalNote (just fixed today, Aprl 30) | ✅ |
| Auto-Register only flips local flag after `wait_for_commit` returns Committed | ✅ |

---

## Fixes applied (chronological, post-audit)

1. **H1** (2026-05-01): `Host` header validation in `ui::handle()`.
2. **H2** (2026-05-01): server-side `biometric::prompt()` gate inside
   the DELETE handler.
3. **L6** (2026-05-01): Quit endpoint indirectly protected by H1.
4. **C1 closed via Phase-1** (2026-05-01): full migration to
   password-encrypted (argon2id + AES-256-GCM) keystore. The
   Keychain-based attack surface for v2 wallets is structurally
   eliminated. `migrate-v2 <label>` for legacy v1 wallets.
5. **WKWebView `confirm()` bug** (2026-05-01): native `window.confirm`
   silently returned false in WKWebView, breaking Send / Shield /
   Pay / Reveal / Delete buttons. Replaced with custom modal
   (`confirmDialog()`).
6. **M3 obsoleted** (2026-05-01): decorative LAContext prompt removed
   from v2 unlock — was confusing users into typing the macOS
   password instead of the wallet password.
7. **Sudo elevation for reveal-secrets** (2026-05-01): `take_password`
   gained a `bypass_cache: bool`. Reveal-secrets uses it so the
   wallet password is re-prompted every time, even when the session
   is warm.
8. **Delete-with-mnemonic-check** (2026-05-01): the DELETE flow now
   challenges the user with three random words from their BIP39
   mnemonic before proceeding, on top of H2's biometric gate. Server
   issues a single-use challenge token; words are validated against
   a re-derived mnemonic from the unlocked seed.
9. **L4 fixed** (2026-05-01): chain-truth verification of
   `registered_on_chain` via `torii::account_exists()` before
   prepending Register::Account. Local flag is now a cache, not a
   source of truth.

See git log for the diff.

## Deferred — recommended next steps

1. **C1 mitigation via Apple Developer ID + biometric ACL**
   (architectural, requires $99/yr).
2. **Per-launch session token** in the URL the WKWebView loads, with
   tiny_http requiring it on every state-changing endpoint. Closes
   the local-malware-on-localhost vector definitively.
3. **`cargo deny` integration** in CI for crate advisory checks.
4. **Rate limiting** on `/api/wallet/*/send|shield|pay-address` (M5).
5. **Confirmation flag** for `dump-client-toml` (M2).
6. **Phase 1 wallet** with YubiKey 5C support (eliminates C1
   entirely).

## Out of scope this audit

- ZK note-spending flow (Phase 2 — circuits not yet integrated).
- Cross-chain bridge security (operator-side, not our code).
- Hardware-level threats (cold-boot, DMA, supply-chain hardware).
