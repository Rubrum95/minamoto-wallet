// Confirmation challenge for wallet deletion.
//
// The "Delete this wallet" button is the most destructive action in
// the UI: even with the BIP39 mnemonic on paper, a successful delete
// removes the on-disk record and forces the user to re-import. So we
// gate it with proof-of-mnemonic: the server picks 3 random word
// positions (e.g. 1, 5, 12) and the user must type those exact words
// from their BIP39 backup. Mismatch → no delete.
//
// Why server-picked positions: if the indices were client-picked, an
// attacker controlling the browser (DNS rebinding past our Host
// check, malicious extension in the embedded WKWebView, etc.) could
// always pick positions whose values they happen to know. Random
// server-side indices force whoever hits Delete to actually have the
// physical paper backup.
//
// Tokens are single-use, expire in 5 min, and stored only in process
// memory. Lifecycle:
//
//   POST /delete-challenge { label }
//     → server generates 3 random indices from 0..24,
//       stores (token, label, indices),
//       returns (token, indices) to UI.
//
//   DELETE /api/wallet/<label> { challenge_token, words }
//     → server looks up token, validates label match, validates each
//       word against the BIP39 mnemonic (re-derived from the seed
//       held in the session cache), invalidates token, proceeds with
//       biometric gate + actual delete.

#![cfg(target_os = "macos")]

use rand::{Rng, RngCore};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TOKEN_TTL: Duration = Duration::from_secs(5 * 60);

/// Server-issued challenge state. Held in memory only.
struct Pending {
    label: String,
    indices: [u8; 3],
    issued_at: Instant,
}

static PENDING: Mutex<Option<HashMap<String, Pending>>> = Mutex::new(None);

fn with_map<R>(f: impl FnOnce(&mut HashMap<String, Pending>) -> R) -> R {
    let mut g = PENDING.lock().expect("delete_challenge mutex poisoned");
    let m = g.get_or_insert_with(HashMap::new);
    f(m)
}

/// Pick 3 distinct indices from 0..24 and store the challenge under a
/// fresh random 16-byte hex token. Returns `(token, indices)`.
pub fn issue(label: &str) -> (String, [u8; 3]) {
    let mut indices = [0u8; 3];
    let mut rng = rand::thread_rng();
    indices[0] = rng.gen_range(0..24);
    loop {
        indices[1] = rng.gen_range(0..24);
        if indices[1] != indices[0] {
            break;
        }
    }
    loop {
        indices[2] = rng.gen_range(0..24);
        if indices[2] != indices[0] && indices[2] != indices[1] {
            break;
        }
    }
    let mut tok = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut tok);
    let token = hex::encode(tok);
    with_map(|m| {
        // Lazy expiry: drop stale entries.
        let now = Instant::now();
        m.retain(|_, v| now.duration_since(v.issued_at) <= TOKEN_TTL);
        m.insert(
            token.clone(),
            Pending {
                label: label.to_string(),
                indices,
                issued_at: now,
            },
        );
    });
    (token, indices)
}

/// Look up + invalidate the challenge. Returns the (label, indices)
/// pair if the token is valid and unexpired; otherwise None. Single-
/// use: the token is removed from the map regardless of caller success.
pub fn redeem(token: &str) -> Option<(String, [u8; 3])> {
    with_map(|m| {
        let entry = m.remove(token)?;
        if entry.issued_at.elapsed() > TOKEN_TTL {
            return None;
        }
        Some((entry.label, entry.indices))
    })
}
