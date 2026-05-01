// Minimal HTTP client for the Iroha 3 Torii REST API.
//
// We only need three endpoints:
//
//   POST /transaction                     — submit a Norito-encoded signed tx
//   GET  /v1/explorer/assets?owned_by=…   — fetch asset balances for a wallet
//   GET  /v1/explorer/transactions/{hash} — poll for tx commit status
//
// Submission body format (verified against
// `iroha-source/iroha/crates/iroha/src/client.rs:7479-7499`):
//
//   Content-Type: application/x-norito
//   Body: signed_transaction.encode_versioned()  (Vec<u8>)
//
// The official client also fetches `/v1/node/capabilities` first to verify
// data-model-version compatibility, but that is a client-side guard. The
// node accepts our submission without it.

use crate::consts::TORII_BASE;
use anyhow::{Context, Result, anyhow, bail};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use std::time::Duration;

const NORITO_MIME: &str = "application/x-norito";

/// Lazy-initialised HTTP client with sane timeouts.
fn http() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("minamoto-wallet/0.1")
        .build()
        .context("failed to build reqwest client")
}

/// POST a Norito-encoded SignedTransaction to the node. Returns the HTTP
/// status code and response body bytes on any 2xx; bails on transport
/// failure or non-2xx with the response body decoded as best-effort UTF-8
/// (Iroha errors are JSON or Norito but the failure mode usually surfaces
/// readable text).
pub fn submit_transaction(body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
    let url = format!("{TORII_BASE}/transaction");
    let resp = http()?
        .post(&url)
        .header(CONTENT_TYPE, NORITO_MIME)
        .header(ACCEPT, NORITO_MIME)
        .body(body)
        .send()
        .with_context(|| format!("POST {url}"))?;

    let status = resp.status();
    let bytes = resp.bytes().context("read response body")?.to_vec();

    if !status.is_success() {
        let body_preview = String::from_utf8_lossy(&bytes);
        bail!(
            "Torii rejected tx ({status}):\n{}",
            body_preview.chars().take(2000).collect::<String>()
        );
    }
    Ok((status.as_u16(), bytes))
}

/// GET balances for an account by I105 address.
/// Returns the raw JSON `items` array as a `serde_json::Value` so callers
/// can pluck out the fields they care about without binding to the full
/// asset schema.
pub fn list_assets_for(account_i105: &str) -> Result<Vec<serde_json::Value>> {
    let url = format!(
        "{TORII_BASE}/v1/explorer/assets?owned_by={}&limit=50",
        urlencoding::encode(account_i105)
    );
    let resp = http()?
        .get(&url)
        .header(ACCEPT, "application/json")
        .send()
        .with_context(|| format!("GET {url}"))?;

    let status = resp.status();
    if !status.is_success() {
        bail!("Torii GET failed: {}", status);
    }
    let json: serde_json::Value = resp.json().context("parse JSON response")?;
    let items = json
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .ok_or_else(|| anyhow!("response missing items[]"))?;
    Ok(items)
}

/// Block until a tx hash reaches a terminal status (Committed or Rejected).
/// Returns the parsed status string and rejection reason if any.
///
/// HTTP 202 from `submit_transaction` only means the node queued the tx
/// for execution — the actual outcome is decided when the next block
/// closes. This helper polls the explorer endpoint every 500ms up to
/// `timeout_secs` (default 30s) and returns when the tx settles.
pub fn wait_for_commit(
    hash_hex: &str,
    timeout_secs: u64,
) -> Result<(String, Option<String>)> {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let url = format!(
        "{TORII_BASE}/v1/explorer/transactions/{hash_hex}"
    );
    let client = http()?;
    let mut last_status = "unknown".to_string();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        let resp = client
            .get(&url)
            .header(ACCEPT, "application/json")
            .send();
        let resp = match resp {
            Ok(r) => r,
            Err(_) => continue, // transient — keep polling
        };
        if !resp.status().is_success() {
            continue;
        }
        let body: serde_json::Value = match resp.json() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let status = body
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        last_status = status.clone();
        if status == "Committed" {
            return Ok((status, None));
        }
        if status == "Rejected" {
            let reason = body
                .get("rejection_reason")
                .and_then(|v| v.get("message"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            return Ok((status, reason));
        }
    }
    anyhow::bail!(
        "tx {hash_hex} did not reach a terminal status within {timeout_secs}s (last seen: {last_status})"
    )
}

/// Check whether the chain knows about an account by I105 address.
/// Returns true if `/v1/explorer/accounts/<i105>` answers 200, false
/// if it 404s, and an error on transport / 5xx.
///
/// We use this as the source of truth for the auto-Register decision:
/// the local `registered_on_chain` flag can drift (e.g. user manually
/// flipped it, or migrated a v1 record that was never actually
/// registered). The chain itself is authoritative.
pub fn account_exists(account_i105: &str) -> Result<bool> {
    let url = format!(
        "{TORII_BASE}/v1/explorer/accounts/{}",
        urlencoding::encode(account_i105)
    );
    let resp = http()?
        .get(&url)
        .header(ACCEPT, "application/json")
        .send()
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(false);
    }
    if !status.is_success() {
        bail!("Torii GET /accounts/{account_i105} returned {status}");
    }
    Ok(true)
}

/// GET a transaction by hash. Returns Some(json) if found and committed,
/// None if not yet visible.
#[allow(dead_code)]
pub fn get_transaction(hash_hex: &str) -> Result<Option<serde_json::Value>> {
    let url = format!("{TORII_BASE}/v1/explorer/transactions/{hash_hex}");
    let resp = http()?
        .get(&url)
        .header(ACCEPT, "application/json")
        .send()
        .with_context(|| format!("GET {url}"))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        bail!("Torii GET failed: {}", resp.status());
    }
    Ok(Some(resp.json().context("parse JSON response")?))
}
