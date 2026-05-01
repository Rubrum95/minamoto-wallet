// In-process password cache for the local web UI.
//
// Why this exists: the v2 password-encrypted wallet would otherwise
// prompt the user to type their password before *every* signing
// operation. That's the polkadot.js baseline, but for our local-only
// native app we can do better — the password is held in process
// memory for a short TTL, and any subsequent signing op reuses it
// without re-prompting. Quitting the app (Cmd+Q / Quit button)
// clears the cache. Idle TTL also clears it.
//
// Trust model:
//
//   - The cache lives ONLY in this process's heap, in `Zeroizing`
//     allocations. Other processes (even same-user) cannot read it
//     unless they attach a debugger (gated by SIP).
//   - The cache is never written to disk, never serialized, never
//     leaves the process.
//   - Browser-side cookies / localStorage are NEVER used to remember
//     the password — that would persist across reboots and across
//     processes.
//
// The cache is keyed by wallet label, so the user can have multiple
// unlocked wallets simultaneously without typing the password again
// when they switch between them.

#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// How long an unlocked password stays cached after the most recent
/// use. Reasonable middle ground: long enough for a normal signing
/// burst, short enough that an unattended laptop re-prompts.
pub const SESSION_TTL: Duration = Duration::from_secs(5 * 60);

struct Entry {
    password: Zeroizing<String>,
    last_used: Instant,
}

/// Global cache. `OnceLock` would be marginally cleaner, but we want
/// Mutex semantics for interior mutability so a plain `static` works.
static CACHE: Mutex<Option<HashMap<String, Entry>>> = Mutex::new(None);

fn with_cache<R>(f: impl FnOnce(&mut HashMap<String, Entry>) -> R) -> R {
    let mut guard = CACHE.lock().expect("session cache poisoned");
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// Look up the cached password for `label`. Returns the value if it
/// exists AND is fresh (< TTL since last use). Refreshes `last_used`
/// on every hit so an active user is never re-prompted mid-burst.
///
/// The returned `Zeroizing<String>` is a clone — the cache keeps its
/// own copy. Callers should let the clone drop quickly.
pub fn get(label: &str) -> Option<Zeroizing<String>> {
    with_cache(|map| {
        let entry = map.get_mut(label)?;
        if entry.last_used.elapsed() > SESSION_TTL {
            // Expired: evict and report miss.
            map.remove(label);
            return None;
        }
        entry.last_used = Instant::now();
        Some(entry.password.clone())
    })
}

/// Store a freshly-validated password in the cache. The caller MUST
/// have already verified it works (by successfully decrypting once).
pub fn store(label: &str, password: Zeroizing<String>) {
    with_cache(|map| {
        map.insert(
            label.to_string(),
            Entry {
                password,
                last_used: Instant::now(),
            },
        );
    });
}

/// Drop a single label's cached password. Called on `delete`.
pub fn forget(label: &str) {
    with_cache(|map| {
        map.remove(label);
    });
}

/// Clear all cached passwords. Called on the explicit "Lock" button
/// and at process shutdown.
pub fn lock_all() {
    with_cache(|map| {
        map.clear();
    });
}

/// How many wallets are currently cached. The UI uses this to render
/// a discreet indicator ("locked" vs "unlocked: N").
pub fn count_unlocked() -> usize {
    with_cache(|map| {
        // Lazy expiry: drop stale entries while we're here.
        let now = Instant::now();
        map.retain(|_, v| now.duration_since(v.last_used) <= SESSION_TTL);
        map.len()
    })
}
