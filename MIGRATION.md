# minamoto-wallet — Migration plan to YubiKey 5C

## Current architecture (v0.1, Secure Enclave wrap)

The Ed25519 private key (32-byte seed) is **wrapped** by an ECDH operation
against a P-256 keypair generated inside the Apple Secure Enclave. The
P-256 private key **never leaves the SE chip**; it lives in the system
keychain managed by macOS and is gated by `[.biometryAny .or .devicePasscode]`
access control. Each unwrap requires Touch ID.

The wrapped (ciphertext) seed is stored in:

```
~/Library/Application Support/minamoto-wallet/<label>.json
```

This file contains the ECIES ciphertext. It is useless without the
Secure Enclave key it was wrapped to, and that key cannot be exfiltrated
from the SE.

### What this protects against

| Threat | Defense |
|---|---|
| Disk theft / Time Machine backup leak | Ciphertext only on disk; SE key never on disk |
| Keychain dump with root | SE-protected key cannot be extracted, even with root |
| Malware running as user | Touch ID required; user sees prompt and can decline |
| iCloud sync of secrets | ciphertext file is in `~/Library/Application Support/`, not iCloud Drive; SE key is `ThisDeviceOnly` |

### What it does NOT protect against

| Threat | Why we lose | Mitigation |
|---|---|---|
| **Cold boot / RAM dump while signing** | Iroha 3 requires Ed25519 signatures. macOS Secure Enclave does not support Ed25519 (only P-256). Therefore the unwrapped Ed25519 seed must briefly be in CPU RAM during the sign operation. We zeroize immediately, but the window exists. | Migrate to YubiKey (Phase 2 below) |
| **Malware with root + LLDB attached to wallet process** | Same root cause: any debugger can read RAM during the brief signing window. | Migrate to YubiKey |
| **OS-level keylogger capturing Touch ID prompt context** | Touch ID itself cannot be intercepted, but the prompt-text and the fact that an unlock happened can be observed. | Hardware keys with on-device button enforce a separate non-spoofable signal |

## Phase 2 — YubiKey 5C NFC (planned)

When the wallet starts holding non-trivial XOR amounts, migrate signing to
**YubiKey 5C NFC** with PIV applet (Ed25519 supported since firmware 5.7,
released May 2024). At that point:

1. Generate a fresh Ed25519 keypair **inside the YubiKey** (`yubico-piv-tool`
   or PIV-applet directly via `yubikey-rs` crate).
2. The private key never leaves the device. Signing happens onboard:
   the wallet sends a 32-byte hash to the YubiKey, gets back 64 bytes of
   Ed25519 signature.
3. PIN-protected (4-8 digits) + tap-to-sign physical button. No biometric
   on this model — capacitive-touch presence detection only, which is
   actually preferable for wallet use (no false positives, immune to
   sleeping-finger coercion).

### Migration path

Because Iroha 3 accounts are derived from the public key, **the YubiKey
account will have a different I105 address than the SE-wrap account.**
We cannot move the key material from one to the other. The migration is:

1. On YubiKey: `yubico-piv-tool -a generate -s 9c -A ED25519` (slot 9c =
   Digital Signature). Save the new public key.
2. Compute new I105 address with `network_prefix=753`.
3. Use the SE-wrap wallet to send all XOR to the new YubiKey-backed wallet.
4. Delete the SE-wrap wallet (`minamoto-wallet delete <label>` — also
   removes the SE key from the system keychain).

### Implementation notes for Phase 2

- Replace `secure_enclave.rs` with a `yubikey.rs` module using the
  `yubikey-rs` crate (or `pcsc-rs` + raw PIV APDUs).
- Touch ID prompts disappear; replaced with PIN entry + LED-blinks-and-tap.
- The I105 derivation, transfer-construction, and Torii submission code
  paths in `wallet.rs` / `transfer.rs` / `torii.rs` remain unchanged —
  they only see "give me a 64-byte Ed25519 signature for this hash",
  whether the implementation behind it is SE-wrap or YubiKey.

### Estimated effort

~1 day to swap the signing module + verify on testnet (Taira) before
re-running end-to-end.

## Why we did not start with YubiKey

1. Hardware purchase delay (~2-3 days from Amazon).
2. SE-wrap is sufficient for first end-to-end validation with 1 XOR.
3. Implementing both modules forces us to design the right abstraction
   boundary (the "give me a signature for this hash" interface) which we
   would otherwise hand-wave.

When the Phase 2 migration happens, this file gets archived with a final
section documenting the actual amounts moved.
