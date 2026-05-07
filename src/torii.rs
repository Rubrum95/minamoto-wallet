// Minimal HTTP client for the Iroha 3 Torii REST API.
//
// Endpoints used:
//
//   POST /transaction                       — submit a Norito-encoded signed tx
//   GET  /v1/explorer/assets?owned_by=…     — fetch asset balances for a wallet
//   GET  /v1/explorer/transactions/{hash}   — poll for tx commit status
//   GET  /v1/explorer/accounts/{i105}       — check whether an account exists
//   GET  /v1/confidential/notes?asset_…     — paginate Shield commitments (Phase-2 indexer)
//   POST /v1/zk/roots                       — fetch shielded ledger root + height (Phase-2)
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

/// One page of the confidential-notes index. Each commitment is the raw
/// 32-byte Pasta-Fp Poseidon-pair output — the same bytes that get hashed
/// into the Merkle tree on chain.
pub struct ConfidentialNotesPage {
    pub commitments: Vec<[u8; 32]>,
    /// Opaque pagination cursor; when `None`, the caller has reached the
    /// end of the indexed range.
    pub next_cursor: Option<String>,
    /// The block height up to which the server scanned for this response.
    /// Useful as a sanity check when the cursor exhausts.
    pub scanned_to_block: u64,
}

/// GET one page of the confidential-notes index for `asset_def_id`.
///
/// We extract `note_commitment` from each `Shield` instruction inside
/// `items[].instructions[]`, in the order returned. Items can in principle
/// contain other instruction kinds (transfers, etc.) — we ignore those.
pub fn fetch_confidential_notes_page(
    asset_def_id: &str,
    cursor: Option<&str>,
    limit: u32,
) -> Result<ConfidentialNotesPage> {
    let mut url = format!(
        "{TORII_BASE}/v1/confidential/notes?asset_definition_id={}&limit={limit}",
        urlencoding::encode(asset_def_id),
    );
    if let Some(c) = cursor {
        url.push_str(&format!("&cursor={}", urlencoding::encode(c)));
    }
    let resp = http()?
        .get(&url)
        .header(ACCEPT, "application/json")
        .send()
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        bail!(
            "Torii GET /v1/confidential/notes returned {status}: {}",
            body.chars().take(500).collect::<String>()
        );
    }
    let json: serde_json::Value = resp.json().context("parse confidential notes JSON")?;
    let items = json
        .get("items")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("response missing items[]"))?;
    let mut commitments: Vec<[u8; 32]> = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        let instructions = item
            .get("instructions")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("item {idx} missing instructions[]"))?;
        for instr in instructions {
            // Each instruction is wrapped as { "<variant>": ... }. We're
            // only interested in `zk.Shield`. Skip everything else — the
            // server may interleave non-Shield ZK instructions (RegisterZkAsset,
            // etc.) and we don't want to reject the page over them.
            let Some(shield) = instr.pointer("/zk/Shield") else { continue; };
            let commit_hex = shield
                .get("note_commitment")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Shield missing note_commitment"))?;
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(commit_hex, &mut bytes)
                .with_context(|| format!("decode note_commitment '{commit_hex}'"))?;
            commitments.push(bytes);
        }
    }
    let next_cursor = json
        .get("next_cursor")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let scanned_to_block = json
        .get("scanned_to_block")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    Ok(ConfidentialNotesPage {
        commitments,
        next_cursor,
        scanned_to_block,
    })
}

/// Snapshot of the shielded ledger Merkle root for a given asset.
pub struct ConfidentialRoot {
    /// Number of commitments accumulated so far (= leaf count of the tree).
    pub height: u32,
    /// Latest 32-byte Merkle root.
    pub latest: [u8; 32],
}

/// POST `/v1/zk/roots` to fetch the latest root + leaf count for an asset.
/// Used as ground truth to verify our paginated index is complete.
pub fn fetch_confidential_root(asset_def_id: &str) -> Result<ConfidentialRoot> {
    let url = format!("{TORII_BASE}/v1/zk/roots");
    let body = serde_json::json!({
        "asset_id": asset_def_id,
        "max": 1u32,
    });
    let resp = http()?
        .post(&url)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .json(&body)
        .send()
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().unwrap_or_default();
        bail!(
            "Torii POST /v1/zk/roots returned {status}: {}",
            txt.chars().take(500).collect::<String>()
        );
    }
    let json: serde_json::Value = resp.json().context("parse zk/roots JSON")?;
    let height = json
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("zk/roots response missing height"))? as u32;
    // `latest` is empty / absent when the shielded ledger has no commitments
    // for this asset yet. Treat that as all-zero root rather than an error.
    let mut latest = [0u8; 32];
    if let Some(latest_hex) = json.get("latest").and_then(|v| v.as_str())
        && !latest_hex.is_empty()
    {
        hex::decode_to_slice(latest_hex, &mut latest)
            .with_context(|| format!("decode root '{latest_hex}'"))?;
    }
    Ok(ConfidentialRoot { height, latest })
}

/// Verifying key record fetched from the chain. The bytes are exactly
/// what `iroha_core::zk::confidential_v2::parse_vk_for_unshield_*`
/// expects — we don't decode them locally.
pub struct ZkVerifyingKey {
    pub name: String,
    pub backend: String,
    pub circuit_id: String,
    pub bytes: Vec<u8>,
}

/// Fetch all registered ZK verifying keys from `GET /v1/zk/vk` and
/// return the one whose `id.name` equals `name`. The chain returns a
/// JSON array; each entry has `id.{backend, name}` plus a `record`
/// containing `key.bytes_b64` (Base64 of the raw VK envelope).
pub fn fetch_zk_verifying_key(name: &str) -> Result<ZkVerifyingKey> {
    let url = format!("{TORII_BASE}/v1/zk/vk");
    let resp = http()?
        .get(&url)
        .header(ACCEPT, "application/json")
        .send()
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("Torii GET /v1/zk/vk returned {status}");
    }
    let entries: serde_json::Value = resp.json().context("parse zk/vk JSON")?;
    let arr = entries
        .as_array()
        .ok_or_else(|| anyhow!("zk/vk endpoint did not return an array"))?;
    for entry in arr {
        let entry_name = entry
            .pointer("/id/name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if entry_name != name {
            continue;
        }
        let backend = entry
            .pointer("/id/backend")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("zk/vk entry missing /id/backend"))?
            .to_string();
        let circuit_id = entry
            .pointer("/record/circuit_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("zk/vk entry missing /record/circuit_id"))?
            .to_string();
        let bytes_b64 = entry
            .pointer("/record/key/bytes_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("zk/vk entry missing /record/key/bytes_b64"))?;
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(bytes_b64)
            .with_context(|| format!("decode VK bytes for '{name}'"))?;
        return Ok(ZkVerifyingKey {
            name: name.to_string(),
            backend,
            circuit_id,
            bytes,
        });
    }
    bail!("verifying key '{name}' not found among /v1/zk/vk entries")
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
