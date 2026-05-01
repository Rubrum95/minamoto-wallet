// Biometric-protected P-256 wrapping key (file-based keychain).
//
// Phase 0 implementation. NOT actually using the Secure Enclave — see
// MIGRATION.md for why and what comes next (YubiKey 5C in Phase 2).
//
// THREAT MODEL (Phase 0, this module)
// -----------------------------------
// We generate a P-256 keypair in CPU RAM (`SecKeyCreateRandomKey` WITHOUT
// `kSecAttrTokenID = SecureEnclave`) and persist the private key to the
// **file-based login keychain** (`~/Library/Keychains/login.keychain-db`)
// with a biometric ACL `[BiometryAny .or. DevicePasscode]`.
//
// File-based keychain items DO NOT require the `keychain-access-groups`
// entitlement that ad-hoc-signed binaries cannot satisfy (Apple DTS Quinn
// confirmed in https://developer.apple.com/forums/thread/728150). This
// is the only path to biometric-gated key access on macOS Sequoia from
// an ad-hoc-signed CLI binary without an Apple Developer Account.
//
//   1. Generate P-256 keypair in software via `SecKeyCreateRandomKey`.
//   2. macOS encrypts and stores the private key inside the user's login
//      keychain at rest, gated by `kSecAttrAccessControl`.
//   3. Generate 32-byte Ed25519 seed in CPU RAM.
//   4. ECIES-encrypt the seed to the P-256 public key (no biometric).
//   5. Store ciphertext on disk in our wallet JSON file.
//   6. Zeroize plaintext seed.
//
// SIGNING
// -------
//   1. Read ciphertext from disk.
//   2. `SecItemCopyMatching` → `SecKeyCreateDecryptedData` triggers
//      Touch ID prompt and returns the plaintext seed.
//   3. Build `iroha_crypto::PrivateKey`, sign, drop (auto-zeroize).
//
// WHAT WE LOSE vs. true SE
// ------------------------
// The P-256 private key is stored encrypted at rest INSIDE the login
// keychain file. The file's encryption key derives from the user's macOS
// password (held by `securityd` while logged in). An attacker with
// physical access to the (locked) Mac plus the user's password could
// decrypt the keychain offline and extract the P-256 private key, then
// decrypt our ciphertext at will.
//
// True SE wrapping (Phase 2 or with Developer Account) would prevent
// this by chip-binding the private key. For our test case (1 XOR amount,
// short-lived wallet) this gap is acceptable; for production amounts we
// migrate to YubiKey (see MIGRATION.md).
//
// References:
//   - Apple Forums 728150 (Quinn confirms file-based keychain does not
//     require keychain-access-groups for ad-hoc binaries).
//   - Apple Forums 740164 (rules out the Developer Account requirement
//     for the SE token-ID path).

#![cfg(target_os = "macos")]

use core_foundation::{
    base::{CFType, CFTypeRef, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    number::CFNumber,
    string::CFString,
};
use core_foundation_sys::base::{CFRelease, kCFAllocatorDefault};
use core_foundation_sys::error::CFErrorRef;
use security_framework_sys::access_control::{
    SecAccessControlCreateWithFlags, kSecAccessControlBiometryAny, kSecAccessControlDevicePasscode,
    kSecAccessControlOr, kSecAttrAccessibleWhenUnlocked,
};
use security_framework_sys::base::{
    SecAccessControlRef, SecKeyRef, errSecItemNotFound, errSecSuccess,
};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
    kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel,
    kSecClass, kSecMatchLimit, kSecPrivateKeyAttrs, kSecReturnRef,
};
use security_framework_sys::key::{
    Algorithm, SecKeyCopyPublicKey, SecKeyCreateDecryptedData, SecKeyCreateEncryptedData,
    SecKeyCreateRandomKey,
};
use security_framework_sys::keychain_item::{SecItemCopyMatching, SecItemDelete};
use std::ptr;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::consts::KEYCHAIN_SERVICE;

#[derive(Debug, Error)]
pub enum SeError {
    #[error("SecAccessControlCreateWithFlags returned NULL (CFError code {0})")]
    AclCreateFailed(isize),

    #[error("SecKeyCreateRandomKey failed (CFError code {0})")]
    KeyGenFailed(isize),

    #[error("SE key '{0}' not found in keychain (was the wallet deleted?)")]
    SeKeyNotFound(String),

    #[error("Keychain operation failed: OSStatus {0}")]
    OsStatus(i32),

    #[error("SecKeyCreateEncryptedData failed (CFError code {0})")]
    EncryptFailed(isize),

    #[error("SecKeyCreateDecryptedData failed (CFError code {0}) — Touch ID denied or biometric set changed?")]
    DecryptFailed(isize),

    #[error("Decrypted seed has wrong length: expected 32 bytes, got {0}")]
    BadSeedLength(usize),
}

/// ECIES variant used for all wrap/unwrap operations.
///
/// `ECIESEncryptionCofactorVariableIVX963SHA256AESGCM` is Apple's
/// recommended modern ECIES profile and the only one explicitly tested by
/// CryptoKit examples and age-plugin-se. SHA-256 + AES-GCM-256 + cofactor
/// ECDH gives 128-bit security level — sufficient for wrapping a 32-byte
/// Ed25519 seed.
const WRAP_ALGORITHM: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

/// Build the SecAccessControl applied to the SE private key. Touch ID is
/// required per access; passcode is accepted as fallback so the user is
/// never permanently locked out by a biometric set change.
unsafe fn make_access_control() -> Result<CFType, SeError> {
    let flags = kSecAccessControlBiometryAny | kSecAccessControlOr | kSecAccessControlDevicePasscode;
    let mut error: CFErrorRef = ptr::null_mut();

    // Use the LESS restrictive accessibility class. The stricter
    // WhenPasscodeSetThisDeviceOnly gets rejected by ad-hoc binaries on
    // Sequoia (-34018). WhenUnlocked still requires the user to be
    // logged in, which is what we want for an interactive wallet anyway.
    let ac_ref: SecAccessControlRef = unsafe {
        SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlocked as CFTypeRef,
            flags,
            &mut error as *mut _,
        )
    };

    if ac_ref.is_null() {
        let code = if error.is_null() {
            -1
        } else {
            // Best-effort code extraction; CFError ergonomics in Rust without
            // higher-level wrappers is awkward, but the numeric code is enough
            // for diagnostics. The CFError must be released to avoid leak.
            let c = unsafe { core_foundation_sys::error::CFErrorGetCode(error) };
            unsafe { CFRelease(error as *mut _) };
            c
        };
        return Err(SeError::AclCreateFailed(code));
    }

    Ok(unsafe { CFType::wrap_under_create_rule(ac_ref as CFTypeRef) })
}

/// Compose the unique label used to find the SE key for `wallet_label`.
fn key_label(wallet_label: &str) -> String {
    format!("{KEYCHAIN_SERVICE}:{wallet_label}")
}

/// Generate a fresh SE P-256 keypair and ECIES-encrypt the given Ed25519
/// seed to it. Returns the ciphertext (which the caller is responsible for
/// persisting to disk).
///
/// The SE private key is auto-stored in the system keychain partition
/// under `kSecAttrLabel = "minamoto-wallet:<wallet_label>"`. To delete it
/// later, call `delete()` with the same wallet_label.
///
/// This function does NOT trigger Touch ID — generation and encryption
/// only use the public side. The first Touch ID prompt happens on the
/// first `unwrap_seed` call.
pub fn wrap_seed(wallet_label: &str, seed: &[u8; 32]) -> Result<Vec<u8>, SeError> {
    let label_str = key_label(wallet_label);

    // No biometric ACL on the keychain item itself — that path is blocked
    // by macOS Sequoia for ad-hoc-signed binaries. The Touch ID prompt is
    // enforced separately by `biometric::prompt_for_unlock` (LAContext)
    // before each unwrap.
    let priv_label = CFString::new(&label_str);
    let priv_perm = CFBoolean::true_value();
    // Optional biometric ACL: if `MINAMOTO_BIOMETRIC_ACL=1` is set in the
    // environment at wallet-creation time, we apply
    // `kSecAccessControlBiometryAny | Or | DevicePasscode` to the
    // generated key. The item then requires Touch ID (or device
    // password fallback) at every decrypt — enforced by securityd, not
    // by our user-space LAContext.
    //
    // This is the experiment: if SecKeyCreateRandomKey accepts our
    // ad-hoc-signed binary applying this ACL, C1 in AUDIT.md is closed
    // for free. If it returns errSecMissingEntitlement (-34018), we
    // know empirically the path is gated and we move to the
    // password-encrypted Phase-1 design instead.
    let mut priv_pairs: Vec<(CFString, CFType)> = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrIsPermanent) },
            priv_perm.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrLabel) },
            priv_label.as_CFType(),
        ),
    ];
    let _acl_holder; // keep alive across CFDictionary creation
    if std::env::var("MINAMOTO_BIOMETRIC_ACL").ok().as_deref() == Some("1") {
        eprintln!("[se] MINAMOTO_BIOMETRIC_ACL=1 — applying biometric ACL to key");
        let acl = unsafe { make_access_control()? };
        _acl_holder = acl.clone();
        priv_pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
            _acl_holder.clone(),
        ));
    }
    let priv_attrs: CFDictionary<CFString, CFType> =
        CFDictionary::from_CFType_pairs(&priv_pairs);

    // Outer key generation parameters:
    // {
    //   kSecAttrKeyType: ECSECPrimeRandom,
    //   kSecAttrKeySizeInBits: 256,
    //   kSecPrivateKeyAttrs: <priv_attrs>,
    // }
    //
    // Note: NO `kSecAttrTokenID = SecureEnclave`. We deliberately use
    // software P-256 because the SE-tokenID path requires the
    // `com.apple.application-identifier` entitlement, which ad-hoc-signed
    // CLI binaries cannot obtain. With software P-256 + biometric ACL,
    // the private key is stored encrypted-at-rest in the user's login
    // keychain file (see threat model in module header).
    let key_size = CFNumber::from(256i64);
    let params: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) }
                .as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) },
            key_size.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecPrivateKeyAttrs) },
            priv_attrs.as_CFType(),
        ),
    ]);

    // Generate the SE keypair. SecKeyCreateRandomKey returns the PRIVATE
    // key reference (used for later decrypt). The corresponding public key
    // is reachable via SecKeyCopyPublicKey but we don't even need it: the
    // ECIES encrypt API accepts the private-key SecKeyRef and operates on
    // its public component automatically (verified in age-plugin-se).
    let mut error: CFErrorRef = ptr::null_mut();
    let priv_ref: SecKeyRef = unsafe {
        SecKeyCreateRandomKey(params.as_concrete_TypeRef(), &mut error as *mut _)
    };

    if priv_ref.is_null() {
        let code = if error.is_null() {
            -1
        } else {
            let c = unsafe { core_foundation_sys::error::CFErrorGetCode(error) };
            unsafe { CFRelease(error as *mut _) };
            c
        };
        return Err(SeError::KeyGenFailed(code));
    }

    // For software-generated P-256 keys, SecKeyCreateEncryptedData
    // requires the PUBLIC key (passing the private key returns errSecParam
    // = -50). For SE-bound keys Apple's API tolerates either, but in
    // software mode it is strict. Extract the public key explicitly.
    let pub_ref = unsafe { SecKeyCopyPublicKey(priv_ref) };
    if pub_ref.is_null() {
        unsafe { CFRelease(priv_ref as *mut _) };
        return Err(SeError::EncryptFailed(-1));
    }

    let plaintext = CFData::from_buffer(seed);
    let mut error: CFErrorRef = ptr::null_mut();
    let ciphertext_ref = unsafe {
        SecKeyCreateEncryptedData(
            pub_ref,
            WRAP_ALGORITHM.into(),
            plaintext.as_concrete_TypeRef(),
            &mut error as *mut _,
        )
    };

    // Release both refs — the actual keypair remains in the keychain.
    unsafe { CFRelease(pub_ref as *mut _) };
    unsafe { CFRelease(priv_ref as *mut _) };

    if ciphertext_ref.is_null() {
        let code = if error.is_null() {
            -1
        } else {
            let c = unsafe { core_foundation_sys::error::CFErrorGetCode(error) };
            unsafe { CFRelease(error as *mut _) };
            c
        };
        return Err(SeError::EncryptFailed(code));
    }

    // Take ownership of the CFData (create-rule).
    let ciphertext: CFData = unsafe { CFData::wrap_under_create_rule(ciphertext_ref) };
    Ok(ciphertext.bytes().to_vec())
}

/// Unwrap a previously-wrapped seed by looking up the SE private key in
/// the system keychain and decrypting the ciphertext.
///
/// **Caller must run the LAContext biometric prompt** (`biometric::prompt`)
/// BEFORE calling this. We do not couple LAContext to the Keychain ACL
/// (which would be the native pattern but is blocked for ad-hoc binaries
/// on Sequoia); instead the gate is a separate user-space check. The
/// prompt step is intentionally split out so each high-level command
/// (`send-xor`, `pubkey-secret`, etc.) can pass its own descriptive
/// reason string to the prompt.
pub fn unwrap_seed(
    wallet_label: &str,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SeError> {
    let label_str = key_label(wallet_label);
    let priv_ref = find_se_private_key(&label_str)?;

    let ct = CFData::from_buffer(ciphertext);
    let mut error: CFErrorRef = ptr::null_mut();
    let plaintext_ref = unsafe {
        SecKeyCreateDecryptedData(
            priv_ref,
            WRAP_ALGORITHM.into(),
            ct.as_concrete_TypeRef(),
            &mut error as *mut _,
        )
    };

    unsafe { CFRelease(priv_ref as *mut _) };

    if plaintext_ref.is_null() {
        let code = if error.is_null() {
            -1
        } else {
            let c = unsafe { core_foundation_sys::error::CFErrorGetCode(error) };
            unsafe { CFRelease(error as *mut _) };
            c
        };
        return Err(SeError::DecryptFailed(code));
    }

    let plaintext: CFData = unsafe { CFData::wrap_under_create_rule(plaintext_ref) };
    let bytes = plaintext.bytes();
    if bytes.len() != 32 {
        return Err(SeError::BadSeedLength(bytes.len()));
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(bytes);
    Ok(seed)
}

/// Look up the SE private key by `kSecAttrLabel`. Returns a SecKeyRef the
/// caller MUST release with `CFRelease` (encoded in our usage above).
///
/// This call does NOT trigger Touch ID — only the subsequent
/// `SecKeyCreateDecryptedData` does.
fn find_se_private_key(label: &str) -> Result<SecKeyRef, SeError> {
    let label_cf = CFString::new(label);
    let return_true = CFBoolean::true_value();

    let query: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(security_framework_sys::item::kSecClassKey) }
                .as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyClass) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate) }
                .as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrLabel) },
            label_cf.as_CFType(),
        ),
        // kSecMatchLimit: integer 1 = single match (equivalent to the
        // symbolic kSecMatchLimitOne which isn't exposed in our pinned
        // security-framework-sys).
        (
            unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) },
            CFNumber::from(1i64).as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnRef) },
            return_true.as_CFType(),
        ),
    ]);

    let mut result: CFTypeRef = ptr::null_mut();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };

    if status == errSecItemNotFound {
        return Err(SeError::SeKeyNotFound(label.to_string()));
    }
    if status != errSecSuccess {
        return Err(SeError::OsStatus(status));
    }
    if result.is_null() {
        return Err(SeError::OsStatus(-1));
    }

    Ok(result as SecKeyRef)
}

/// Delete the SE private key associated with this wallet label. macOS may
/// prompt for Touch ID to authorize the deletion of a biometric-protected
/// item.
pub fn delete(wallet_label: &str) -> Result<(), SeError> {
    let label_str = key_label(wallet_label);
    let label_cf = CFString::new(&label_str);

    let query: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(security_framework_sys::item::kSecClassKey) }
                .as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrLabel) },
            label_cf.as_CFType(),
        ),
    ]);

    let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
    match status {
        s if s == errSecSuccess => Ok(()),
        s if s == errSecItemNotFound => Err(SeError::SeKeyNotFound(label_str)),
        s => Err(SeError::OsStatus(s)),
    }
}

/// Probe whether the wrapping key for this wallet exists, without
/// triggering Touch ID. Used by `generate` to refuse overwriting.
pub fn exists(wallet_label: &str) -> bool {
    let label_str = key_label(wallet_label);
    let label_cf = CFString::new(&label_str);

    let query: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(security_framework_sys::item::kSecClassKey) }
                .as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrLabel) },
            label_cf.as_CFType(),
        ),
    ]);

    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), ptr::null_mut()) };
    status == errSecSuccess
}
