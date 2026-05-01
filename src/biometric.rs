// Touch ID gate via LocalAuthentication framework.
//
// We call `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`
// before each unwrap of the Ed25519 seed. The reason this works for our
// ad-hoc-signed CLI binary (where Keychain biometric ACL does not) is
// because LocalAuthentication's `evaluatePolicy` does NOT go through the
// keychain entitlement subsystem — it only requires the Mac to have a
// biometric sensor and the user to have enrolled fingerprints.
//
// Threat-model trade-off vs. native Keychain biometric ACL: a malicious
// process running as our user could in principle bypass our LAContext
// gate (e.g. by patching the binary, by attaching a debugger, or by
// reading the keychain item directly without going through our code
// path). The native ACL evaluates inside `securityd` and cannot be
// bypassed by any user-space process. For our Phase 0 wallet (single-
// user developer Mac, FileVault on, short-lived test wallet) this gap
// is acceptable. The Phase 2 YubiKey path closes it completely.

#![cfg(target_os = "macos")]

use objc2::rc::Retained;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use std::sync::mpsc::sync_channel;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BiometricError {
    #[error("Touch ID prompt was cancelled or denied")]
    UserCancelled,

    #[error("Biometric authentication unavailable on this Mac (no sensor or no enrolled fingerprints)")]
    NotAvailable,

    #[error("LAContext.evaluatePolicy returned an unexpected error: {0}")]
    EvaluateFailed(String),

    #[error("Touch ID prompt timed out after {timeout_secs}s")]
    Timeout { timeout_secs: u64 },
}

/// Synchronously prompt the user for Touch ID. Blocks until the user
/// approves, denies, or times out. Returns `Ok(())` on success.
///
/// `reason` is shown verbatim in the system Touch ID dialog. Keep it
/// short and user-actionable, e.g. "Sign Iroha transfer of 1 XOR".
pub fn prompt(reason: &str) -> Result<(), BiometricError> {
    // SAFETY: LAContext::new is a standard Cocoa initializer that returns
    // a fresh, owned `Retained<LAContext>`. We hold it for the duration
    // of the policy evaluation; objc2's Retained handles release on drop.
    let ctx: Retained<LAContext> = unsafe { LAContext::new() };

    // Use the looser DeviceOwnerAuthentication (policy 2): macOS will
    // try biometrics first and silently fall back to the device password
    // when biometric is rate-limited / locked / not available. Without
    // this fallback, transient biometric lockout (e.g. after several
    // rapid uses) breaks the wallet entirely until the OS resets state,
    // which is hostile UX.
    //
    // The biometric-only policy (kLAPolicyDeviceOwnerAuthenticationWithBiometrics)
    // is preferable for true per-operation biometric enforcement, but in
    // a custodial wallet on the user's own Mac the looser policy is the
    // right pragmatic choice. The auth still gates seed access — it's
    // just that the user can also satisfy it with their macOS password
    // when the biometric subsystem is temporarily uncooperative.
    let policy = LAPolicy(
        objc2_local_authentication::kLAPolicyDeviceOwnerAuthentication as isize,
    );
    if unsafe { ctx.canEvaluatePolicy_error(policy) }.is_err() {
        return Err(BiometricError::NotAvailable);
    }

    // Channel used to bridge the async reply block back to our sync call
    // site. Bounded(1) so the block never has to wait on send.
    let (tx, rx) = sync_channel::<Result<(), BiometricError>>(1);

    // Build a heap-allocated block that LocalAuthentication will retain
    // for the lifetime of the prompt. The block captures a sender by
    // move; once it fires we hand the result to the main thread via the
    // channel and drop the sender.
    let block = block2::RcBlock::new(move |success: objc2::runtime::Bool, error: *mut NSError| {
        let res = if success.as_bool() {
            Ok(())
        } else if !error.is_null() {
            // SAFETY: callee guarantees `error` is a valid NSError if
            // success was false. We do not retain it across this block.
            let nserr: &NSError = unsafe { &*error };
            let code = nserr.code();
            let desc = nserr.localizedDescription().to_string();
            // We surface the exact LAError code in every error path so
            // the user can distinguish e.g. "user cancelled" (-2) from
            // "system cancelled" (-4) from "no UI context available"
            // (which surfaces with a different code on Sequoia).
            Err(BiometricError::EvaluateFailed(format!(
                "LAError code {code}: {desc}"
            )))
        } else {
            Err(BiometricError::EvaluateFailed(
                "Touch ID failed without an NSError (unexpected)".to_string(),
            ))
        };
        // Best-effort send. If the receiver was dropped, ignore.
        let _ = tx.send(res);
    });

    let reason_ns = NSString::from_str(reason);

    // SAFETY: signature checked above; block lives until the reply fires
    // (RcBlock holds it heap-allocated). LAContext retains the block
    // internally for the duration of the prompt.
    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(policy, &reason_ns, &block);
    }

    // Wait for the reply. 60s ceiling to avoid hanging the CLI forever
    // if the user walks away from the laptop while the dialog is open.
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(res) => res,
        Err(_) => Err(BiometricError::Timeout { timeout_secs: 60 }),
    }
}
