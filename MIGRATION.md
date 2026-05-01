# minamoto-wallet — keystore migration

## Versions in scope

- **v1 (legacy)** — Ed25519 seed wrapped via ECIES against a software
  P-256 key in `login.keychain`. No biometric ACL on the keychain
  item itself; Touch ID was a user-space LAContext check enforced
  in-binary, not in `securityd`. Local processes running as the same
  user could decrypt the seed via `SecKeyCreateDecryptedData` without
  triggering Touch ID.
- **v2 (current)** — Ed25519 seed encrypted with a key derived from a
  user-chosen password via argon2id (m=64MB, t=3, p=1) and sealed
  with AES-256-GCM. Reading the wallet JSON file alone is useless;
  the password is required to decrypt the seed. The Keychain plays
  no custody role for v2 records.

## Migrating v1 → v2

```
minamoto-wallet migrate-v2 <label>
```

Steps the command performs:

1. Verify the record on disk is v1; otherwise no-op.
2. Touch ID prompt to unwrap the v1 seed via the legacy SE path.
3. Read a new password from stdin (twice, with confirmation).
4. Derive the KEK (~1s on Apple Silicon) and encrypt the seed.
5. Persist a v2 record with the same label, public key, I105,
   `notes`, and `registered_on_chain` flag.
6. Delete the SE keychain item.

The BIP39 mnemonic does not change: it is the entropy of the seed,
which is preserved across the re-encryption.

## Future direction: hardware key (YubiKey 5C)

A future keystore would store the Ed25519 signing key on an external
hardware token (YubiKey 5C series, Ledger Nano, etc.) and remove the
on-disk encrypted seed entirely. Properties:

- Signing happens on the device; the seed never enters host RAM.
- Host-machine compromise does not compromise the key.
- Hardware-key compromise requires physical possession + device PIN.

Implementation notes:

- `iroha_crypto::PrivateKey` accepts a 32-byte Ed25519 seed. The
  YubiKey emits raw Ed25519 signatures over the transaction hash
  prepared by `TransactionBuilder::sign`. A wrapper that intercepts
  the sign call and routes to the YubiKey is sufficient — the rest
  of the Iroha 3 wire format remains untouched.
- Likely transports: PIV applet (PKCS#11) for a generic flow, or
  the FIDO2 applet for native Ed25519 (requires firmware ≥ 5.7 on
  YubiKey 5C series).
- A v3 keystore record would replace `password_encrypted` with a
  `hardware_key` block: `{kind, slot, pubkey, attestation_b64}`.
  No ciphertext to encrypt — the secret never leaves the device.

Not yet started.
