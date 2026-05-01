// Local-only web UI for the wallet.
//
// Architecture:
//   - tiny_http server bound to 127.0.0.1:7825 (NOT 0.0.0.0 — never
//     expose this server to the network; it can sign transactions).
//   - Single embedded HTML page with vanilla JS, served at `/`.
//   - JSON API endpoints under `/api/*` that wrap the existing CLI
//     functions in `wallet`, `transfer`, `balance`, `torii`.
//   - Touch ID prompts fire from the same process as the CLI, so the
//     OS-level dialog works the same way it does from `minamoto-wallet
//     send-xor`.
//
// Why local-only and not a remote daemon: the wallet binary holds the
// Keychain authorisation cookie (the cdhash that macOS verified once at
// the "always allow" prompt). If we forwarded those signing operations
// to a remote server we would need to either replicate that auth state
// (impossible) or proxy the seed bytes (catastrophic). Same-process is
// the only sane design.

#![cfg(target_os = "macos")]

use crate::biometric;
use crate::confidential_address;
use crate::delete_challenge;
use crate::password as pwd_module;
use crate::session;
use crate::shield;
use crate::storage;
use crate::torii;
use crate::transfer;
use crate::wallet;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::SocketAddr;
use tiny_http::{Header, Method, Request, Response, Server};

const BIND_ADDR: &str = "127.0.0.1:7825";
const INDEX_HTML: &str = include_str!("ui_index.html");

#[derive(Serialize)]
struct ApiError<'a> {
    error: &'a str,
}

/// Returned from any endpoint that needs a wallet seed but the
/// session cache has no fresh password for the target wallet. The
/// browser sees `need_password: true`, opens the modal, the user
/// types it, and the same request is retried with `password` in the
/// body. The middleware in `take_password()` accepts both shapes.
#[derive(Serialize)]
struct NeedPassword<'a> {
    need_password: bool,
    label: &'a str,
}

/// Resolve the password to use for `label`:
///   1. If `body_password` was supplied (browser modal sent it), use
///      it AND cache it for next time.
///   2. Else, try the in-process session cache (skipped if
///      `bypass_cache` is true — used by sensitive ops like
///      reveal-secrets where we want sudo-style re-prompt).
///   3. Else, the wallet is v2 and locked → return `NeedPassword` so
///      the browser can show the modal.
///
/// For v1 wallets (legacy SE-wrap), the password is simply ignored
/// throughout — `unlock_seed` only consults `password` for v2 records.
#[cfg(target_os = "macos")]
fn take_password(
    label: &str,
    body_password: Option<&str>,
    bypass_cache: bool,
) -> std::result::Result<Option<zeroize::Zeroizing<String>>, String> {
    use zeroize::Zeroizing;
    let record = match storage::load(label) {
        Ok(r) => r,
        Err(e) => return Err(format!("load wallet '{label}': {e}")),
    };
    if record.version != storage::CURRENT_VERSION {
        // v1 wallets: no password concept, callers pass None upstream.
        return Ok(None);
    }
    if let Some(pw) = body_password.filter(|s| !s.is_empty()) {
        // Validate by attempting decrypt before caching: this avoids
        // poisoning the cache with a wrong password (the user would
        // only learn after the next request mysteriously fails).
        let enc = record
            .password_encrypted
            .as_ref()
            .ok_or_else(|| "v2 record missing password_encrypted".to_string())?;
        if pwd_module::decrypt_seed(enc, pw).is_err() {
            return Err("incorrect password".to_string());
        }
        let zpw = Zeroizing::new(pw.to_string());
        // Cache even on bypass paths: once the user has just typed the
        // password for a sensitive op, subsequent everyday ops should
        // benefit from the cache. The bypass only forces re-prompting,
        // it doesn't refuse to remember the new value.
        session::store(label, zpw.clone());
        return Ok(Some(zpw));
    }
    if !bypass_cache {
        if let Some(cached) = session::get(label) {
            return Ok(Some(cached));
        }
    }
    Err("__NEED_PASSWORD__".to_string())
}

#[derive(Serialize)]
struct WalletList {
    labels: Vec<String>,
}

#[derive(Serialize)]
struct GenerateResponse {
    label: String,
    public_key: String,
    i105: String,
    /// 24-word BIP39 mnemonic. Returned ONCE on creation. The local UI
    /// renders it for the user to copy on paper, then forgets it.
    mnemonic: String,
}

#[derive(Serialize)]
struct WalletInfo {
    label: String,
    public_key: String,
    i105: String,
    network_prefix: u16,
    created_at: String,
    /// File-format version. 1 = legacy SE-wrap (no password). 2 =
    /// password-encrypted. The UI uses this to decide whether to
    /// preflight the unlock modal before signing operations.
    version: u32,
    registered_on_chain: bool,
}

#[derive(Serialize)]
struct BalanceAsset {
    def_id: String,
    symbol: Option<String>,
    value: String,
}

#[derive(Serialize)]
struct BalanceResponse {
    label: String,
    i105: String,
    assets: Vec<BalanceAsset>,
}

#[derive(Deserialize)]
struct SendRequest {
    to: String,
    amount: String,
    /// v2 wallet password (optional). If empty/missing, server tries
    /// the session cache; if no cache hit, server replies with
    /// `NeedPassword` and the browser modal prompts for it.
    #[serde(default)]
    password: String,
}

#[derive(Serialize)]
struct SendResponse {
    tx_hash: String,
}

#[derive(Deserialize)]
struct GenerateRequest {
    label: String,
    /// v2 password used to encrypt the new wallet's seed (≥ 8 chars).
    /// Defaults to empty so old front-ends fail loudly with the
    /// validation error from `wallet::generate`. The browser modal
    /// (Phase B7/B8) will populate this field.
    #[serde(default)]
    password: String,
}

#[derive(Deserialize)]
struct ShieldRequest {
    amount: String,
    #[serde(default)]
    password: String,
}

#[derive(Serialize)]
struct ShieldResponse {
    tx_hash: String,
    commitment: String,
    amount: String,
}

#[derive(Serialize)]
struct ConfidentialAddressResponse {
    /// Full `iroha:confidential:v3:<base64url>` URI ready to share.
    uri: String,
    /// 32-byte owner_tag in hex (also embedded in `uri`).
    owner_tag_hex: String,
    /// 32-byte diversifier in hex (also embedded in `uri`).
    diversifier_hex: String,
    /// Opaque 16-byte rotation tag in base64url.
    receive_key_id: String,
}

#[derive(Deserialize)]
struct PayAddressRequest {
    /// Full `iroha:confidential:v3:…` URI of the recipient.
    recipient: String,
    /// Whole-XOR integer amount as decimal string. Shield ISI is u128
    /// scale=0 on chain, so fractional inputs are rejected upfront.
    amount: String,
    /// If true, derive the commitment but do NOT touch the keychain or
    /// submit anything. Useful to confirm a recipient URI parses
    /// correctly before spending real XOR.
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    password: String,
}

#[derive(Deserialize)]
struct UnlockRequest {
    label: String,
    password: String,
}

#[derive(Serialize)]
struct DeleteChallengeResponse {
    challenge_token: String,
    /// 1-based for display. The UI shows e.g. "Type word #1, #5, #12".
    indices: [u8; 3],
}

#[derive(Deserialize)]
struct DeleteRequest {
    /// Issued by `/delete-challenge`. Single-use.
    challenge_token: String,
    /// Three words the user typed in the modal. Trimmed +
    /// case-insensitive comparison server-side.
    words: [String; 3],
    /// Optional. If the session is locked the v2 password gates the
    /// mnemonic derivation; if cached, we use the cache.
    #[serde(default)]
    password: String,
}

#[derive(Deserialize)]
struct RevealSecretsRequest {
    #[serde(default)]
    password: String,
}

#[derive(Serialize)]
struct RevealSecretsResponse {
    mnemonic: String,
    /// Raw 32-byte seed hex. This IS the private key material in
    /// Iroha 3 (the SDK calls it `seed` and derives the Ed25519
    /// keypair from it deterministically).
    seed_hex: String,
    /// Iroha-formatted multihash private key string, ready to drop
    /// into `client.toml` if the user wants to use the official CLI.
    iroha_private_key: String,
    public_key: String,
}

#[derive(Serialize)]
struct PayAddressResponse {
    dry_run: bool,
    /// `tx_hash` is empty in dry-run mode.
    tx_hash: String,
    commitment: String,
    rho: String,
    amount: String,
    /// Mirror of the recipient owner_tag we extracted from the URI.
    /// The UI shows this so the user can sanity-check it matches what
    /// the recipient publicly advertised.
    recipient_owner_tag: String,
    recipient_diversifier: String,
}

#[derive(Serialize)]
struct NoteSummary {
    asset_def_id: String,
    amount: String,
    commitment: String,
    created_tx_hash: String,
    created_at: String,
    spendable: bool,
}

/// Boot the local API server on a background thread and run the
/// native WKWebView window on the main thread. The window points at
/// the loopback HTTP server so the existing JSON API contract is
/// preserved unchanged. tao + wry handle the AppKit event loop.
///
/// `--browser` mode (legacy): if MINAMOTO_USE_BROWSER=1 is set, we
/// fall back to the old "spawn `open <url>`" path. Useful for
/// development or hostile environments.
pub fn run() -> Result<()> {
    use muda::{Menu, PredefinedMenuItem, Submenu};
    use tao::{
        dpi::LogicalSize,
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoopBuilder},
        window::{Theme, WindowBuilder},
    };
    use wry::WebViewBuilder;

    // 1) HTTP API server on a background thread. Same handlers as before.
    let server = Server::http(BIND_ADDR)
        .map_err(|e| anyhow!("failed to bind {BIND_ADDR}: {e}"))?;
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            if let Err(e) = handle(request) {
                eprintln!("[ui] handler error: {e:#}");
            }
        }
    });

    let url = format!("http://{BIND_ADDR}");

    // Legacy escape hatch: still open the default browser when asked.
    if std::env::var("MINAMOTO_USE_BROWSER").ok().as_deref() == Some("1") {
        eprintln!("[ui] MINAMOTO_USE_BROWSER=1 — opening default browser at {url}");
        let _ = std::process::Command::new("open").arg(&url).status();
        loop {
            std::thread::park();
        }
    }

    // 2) Native window with embedded WKWebView pointing at the loopback URL.
    // The menu bar must be created BEFORE the event loop on macOS so the
    // standard Edit/Cut/Copy/Paste shortcuts route to the focused web view
    // input. Without this, Cmd+V silently does nothing inside any input
    // field — the user cannot paste recipient addresses, mnemonic
    // phrases, or v3 URIs. Apple HIG also expects an `App > Quit`
    // (Cmd+Q) and a `Window > Minimize` (Cmd+M); we add those too.
    let app_menu = Submenu::new("Minamoto Wallet", true);
    let _ = app_menu.append_items(&[
        &PredefinedMenuItem::about(Some("Minamoto Wallet"), None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::hide(None),
        &PredefinedMenuItem::hide_others(None),
        &PredefinedMenuItem::show_all(None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::quit(None),
    ]);
    let edit_menu = Submenu::new("Edit", true);
    let _ = edit_menu.append_items(&[
        &PredefinedMenuItem::undo(None),
        &PredefinedMenuItem::redo(None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::cut(None),
        &PredefinedMenuItem::copy(None),
        &PredefinedMenuItem::paste(None),
        &PredefinedMenuItem::select_all(None),
    ]);
    let window_menu = Submenu::new("Window", true);
    let _ = window_menu.append_items(&[
        &PredefinedMenuItem::minimize(None),
        &PredefinedMenuItem::maximize(None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::close_window(None),
    ]);
    let menu = Menu::new();
    let _ = menu.append_items(&[&app_menu, &edit_menu, &window_menu]);
    #[cfg(target_os = "macos")]
    menu.init_for_nsapp();

    let event_loop = EventLoopBuilder::new()
        .build();
    let window = WindowBuilder::new()
        .with_title("Minamoto Wallet")
        .with_inner_size(LogicalSize::new(960.0, 820.0))
        .with_min_inner_size(LogicalSize::new(620.0, 540.0))
        .with_theme(Some(Theme::Dark))
        .build(&event_loop)
        .map_err(|e| anyhow!("create native window: {e}"))?;

    // Build the WKWebView. We pass the loopback HTTP URL — the same
    // tiny_http server we just spawned will answer.
    let _webview = WebViewBuilder::new()
        .with_url(&url)
        .with_devtools(cfg!(debug_assertions))
        .build(&window)
        .map_err(|e| anyhow!("create webview: {e}"))?;

    eprintln!("[ui] native window opened, API on {url}");

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    });
}

fn handle(mut req: Request) -> Result<()> {
    // -------- Defense layer 1: TCP source must be loopback --------
    // tiny_http binds 127.0.0.1 only, but a paranoia check costs
    // nothing and protects against future mistakes (e.g. someone
    // changing BIND_ADDR).
    if let Some(addr) = req.remote_addr() {
        match addr {
            SocketAddr::V4(a) if !a.ip().is_loopback() => {
                return respond(req, 403, json_string(&ApiError { error: "loopback only" }));
            }
            SocketAddr::V6(a) if !a.ip().is_loopback() => {
                return respond(req, 403, json_string(&ApiError { error: "loopback only" }));
            }
            _ => {}
        }
    }

    // -------- Defense layer 2: Host header must match expected --------
    // DNS rebinding: a malicious website resolves `evil.com` →
    // 127.0.0.1, then issues fetch() to `http://evil.com:7825/...`.
    // The browser sees same-origin (matching its cached resolution),
    // but the TCP destination is our loopback server. Without a Host
    // check, our server happily processes the request as legitimate.
    //
    // We allow only the literal `127.0.0.1:7825` and `localhost:7825`
    // — these are the only Hosts a non-tampered native window or
    // hand-typed URL would produce. Anything else (incl. 0.0.0.0,
    // ::1 spelling, FQDNs that happen to resolve to loopback) is
    // refused with 421 Misdirected Request.
    let host_ok = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Host"))
        .map(|h| h.value.as_str())
        .map(|v| v == "127.0.0.1:7825" || v == "localhost:7825")
        .unwrap_or(false);
    if !host_ok {
        return respond(
            req,
            421,
            json_string(&ApiError {
                error: "Host header mismatch — DNS rebinding refused",
            }),
        );
    }

    let method = req.method().clone();
    let url = req.url().to_string();
    // Strip query string for routing decisions.
    let path = url.split('?').next().unwrap_or(&url).to_string();

    match (&method, path.as_str()) {
        (Method::Get, "/") => respond_html(req, INDEX_HTML),

        (Method::Get, "/assets/logo.png") => match find_logo_bytes() {
            Some(bytes) => respond_png(req, &bytes),
            None => respond(
                req,
                404,
                json_string(&ApiError {
                    error: "logo.png not found in bundle Resources or dev dist/",
                }),
            ),
        },

        (Method::Get, "/api/wallets") => {
            let labels = storage::list_labels()?;
            respond(req, 200, json_string(&WalletList { labels }))
        }

        (Method::Post, "/api/generate") => {
            let body = read_body(&mut req)?;
            let payload: GenerateRequest = serde_json::from_str(&body)
                .context("invalid JSON body")?;
            match wallet::generate(&payload.label, &payload.password) {
                Ok(w) => {
                    let resp = GenerateResponse {
                        label: w.label.clone(),
                        public_key: w.public_key_hex.clone(),
                        i105: w.i105_address.clone(),
                        mnemonic: (*w.mnemonic).clone(),
                    };
                    respond(req, 200, json_string(&resp))
                }
                Err(e) => respond(req, 400, json_string(&ApiError {
                    error: &format!("{e:#}"),
                })),
            }
        }

        (Method::Get, p) if p.starts_with("/api/wallet/") && p.ends_with("/info") => {
            let label = extract_label(p, "/info")?;
            match storage::load(&label) {
                Ok(rec) => {
                    let info = WalletInfo {
                        label: rec.label,
                        public_key: rec.public_key_hex,
                        i105: rec.i105_address,
                        network_prefix: rec.network_prefix,
                        created_at: rec.created_at,
                        version: rec.version,
                        registered_on_chain: rec.registered_on_chain,
                    };
                    respond(req, 200, json_string(&info))
                }
                Err(e) => respond(req, 404, json_string(&ApiError {
                    error: &format!("{e:#}"),
                })),
            }
        }

        (Method::Get, p) if p.starts_with("/api/wallet/") && p.ends_with("/balance") => {
            let label = extract_label(p, "/balance")?;
            match build_balance(&label) {
                Ok(resp) => respond(req, 200, json_string(&resp)),
                Err(e) => respond(req, 502, json_string(&ApiError {
                    error: &format!("{e:#}"),
                })),
            }
        }

        (Method::Post, p) if p.starts_with("/api/wallet/") && p.ends_with("/send") => {
            let label = extract_label(p, "/send")?;
            let body = read_body(&mut req)?;
            let payload: SendRequest = serde_json::from_str(&body)
                .context("invalid JSON body")?;
            // Try session cache first; fall back to body password; if
            // neither, signal the browser to open the modal.
            let pw = match take_password(&label, Some(&payload.password), false) {
                Ok(p) => p,
                Err(e) if e == "__NEED_PASSWORD__" => {
                    return respond(req, 401, json_string(&NeedPassword { need_password: true, label: &label }));
                }
                Err(e) => {
                    return respond(req, 401, json_string(&ApiError { error: &e }));
                }
            };
            match transfer::send_xor(
                &label,
                &payload.to,
                &payload.amount,
                pw.as_deref().map(|s| s.as_str()),
            ) {
                Ok(tx_hash) => respond(req, 200, json_string(&SendResponse { tx_hash })),
                Err(e) => respond(req, 502, json_string(&ApiError {
                    error: &format!("{e:#}"),
                })),
            }
        }

        (Method::Post, p) if p.starts_with("/api/wallet/") && p.ends_with("/shield") => {
            let label = extract_label(p, "/shield")?;
            let body = read_body(&mut req)?;
            let payload: ShieldRequest = serde_json::from_str(&body)
                .context("invalid JSON body")?;
            // Shield: same Touch ID flow as send-xor. Builds the
            // commitment via zk_v2 + signs + submits + persists local note.
            let pw = match take_password(&label, Some(&payload.password), false) {
                Ok(p) => p,
                Err(e) if e == "__NEED_PASSWORD__" => {
                    return respond(req, 401, json_string(&NeedPassword { need_password: true, label: &label }));
                }
                Err(e) => {
                    return respond(req, 401, json_string(&ApiError { error: &e }));
                }
            };
            match shield::shield(&label, &payload.amount, None, pw.as_deref().map(|s| s.as_str())) {
                Ok(out) => respond(req, 200, json_string(&ShieldResponse {
                    tx_hash: out.tx_hash_hex,
                    commitment: out.commitment_hex,
                    amount: out.amount,
                })),
                Err(e) => respond(req, 502, json_string(&ApiError {
                    error: &format!("{e:#}"),
                })),
            }
        }

        (Method::Get, p) if p.starts_with("/api/wallet/") && p.ends_with("/notes") => {
            let label = extract_label(p, "/notes")?;
            match storage::load(&label) {
                Ok(rec) => {
                    let notes: Vec<NoteSummary> = rec.notes.iter().map(|n| NoteSummary {
                        asset_def_id: n.asset_def_id.clone(),
                        amount: n.amount_u128.clone(),
                        commitment: n.commitment_hex.clone(),
                        created_tx_hash: n.created_tx_hash_hex.clone(),
                        created_at: n.created_at.clone(),
                        spendable: n.spendable,
                    }).collect();
                    respond(req, 200, json_string(&serde_json::json!({"notes": notes})))
                }
                Err(e) => respond(req, 404, json_string(&ApiError {
                    error: &format!("{e:#}"),
                })),
            }
        }

        (Method::Get, p)
            if p.starts_with("/api/wallet/") && p.ends_with("/confidential-address") =>
        {
            let label = extract_label(p, "/confidential-address")?;
            let pw = match take_password(&label, None, false) {
                Ok(p) => p,
                Err(e) if e == "__NEED_PASSWORD__" => {
                    return respond(
                        req,
                        401,
                        json_string(&NeedPassword { need_password: true, label: &label }),
                    );
                }
                Err(e) => {
                    return respond(req, 401, json_string(&ApiError { error: &e }));
                }
            };
            match build_confidential_address(&label, pw.as_deref().map(|s| s.as_str())) {
                Ok(resp) => respond(req, 200, json_string(&resp)),
                Err(e) => respond(req, 502, json_string(&ApiError {
                    error: &format!("{e:#}"),
                })),
            }
        }

        (Method::Post, p) if p.starts_with("/api/wallet/") && p.ends_with("/pay-address") => {
            let label = extract_label(p, "/pay-address")?;
            let body = read_body(&mut req)?;
            let payload: PayAddressRequest = serde_json::from_str(&body)
                .context("invalid JSON body")?;
            let result = if payload.dry_run {
                shield::shield_dry_run(&payload.amount, &payload.recipient).map(|out| {
                    PayAddressResponse {
                        dry_run: true,
                        tx_hash: String::new(),
                        commitment: out.commitment_hex,
                        rho: out.rho_hex,
                        amount: out.amount,
                        recipient_owner_tag: out.recipient_owner_tag_hex,
                        recipient_diversifier: out.recipient_diversifier_hex,
                    }
                })
            } else {
                // Real send: parse recipient once HERE so we can echo back
                // the owner_tag/diversifier the UI displays alongside the
                // tx hash. The same parse happens inside `shield::shield`,
                // but we want the values for the response too.
                let parsed = confidential_address::parse(&payload.recipient)
                    .context("recipient v3 address parse failed")?;
                let pw = match take_password(&label, Some(&payload.password), false) {
                    Ok(p) => p,
                    Err(e) if e == "__NEED_PASSWORD__" => {
                        return respond(req, 401, json_string(&NeedPassword { need_password: true, label: &label }));
                    }
                    Err(e) => {
                        return respond(req, 401, json_string(&ApiError { error: &e }));
                    }
                };
                shield::shield(&label, &payload.amount, Some(&payload.recipient), pw.as_deref().map(|s| s.as_str())).map(|out| {
                    PayAddressResponse {
                        dry_run: false,
                        tx_hash: out.tx_hash_hex,
                        commitment: out.commitment_hex,
                        rho: out.rho_hex,
                        amount: out.amount,
                        recipient_owner_tag: parsed.shielded_owner_tag_hex,
                        recipient_diversifier: parsed.shielded_diversifier_hex,
                    }
                })
            };
            match result {
                Ok(r) => respond(req, 200, json_string(&r)),
                Err(e) => respond(req, 502, json_string(&ApiError {
                    error: &format!("{e:#}"),
                })),
            }
        }

        (Method::Post, p)
            if p.starts_with("/api/wallet/") && p.ends_with("/reveal-secrets") =>
        {
            let label = extract_label(p, "/reveal-secrets")?;
            let body = read_body(&mut req)?;
            let payload: RevealSecretsRequest = serde_json::from_str(&body)
                .context("invalid JSON body")?;
            // Reveal-secrets is the most sensitive read-only op: it
            // exposes the BIP39 mnemonic + raw private key. We force
            // a wallet-password re-prompt every time (bypass_cache =
            // true), even if the user is already logged in for other
            // ops. This is the sudo elevation pattern: ordinary
            // signing reuses the cache, but full key disclosure
            // demands a fresh password entry.
            let pw = match take_password(&label, Some(&payload.password), true) {
                Ok(p) => p,
                Err(e) if e == "__NEED_PASSWORD__" => {
                    return respond(req, 401, json_string(&NeedPassword { need_password: true, label: &label }));
                }
                Err(e) => {
                    return respond(req, 401, json_string(&ApiError { error: &e }));
                }
            };
            match build_reveal_secrets(&label, pw.as_deref().map(|s| s.as_str())) {
                Ok(resp) => respond(req, 200, json_string(&resp)),
                Err(e) => respond(req, 502, json_string(&ApiError {
                    error: &format!("{e:#}"),
                })),
            }
        }

        (Method::Post, "/api/session/unlock") => {
            let body = read_body(&mut req)?;
            let payload: UnlockRequest = serde_json::from_str(&body).context("invalid JSON body")?;
            // take_password validates the password (decrypts a probe)
            // and stores it in the cache on success.
            match take_password(&payload.label, Some(&payload.password), false) {
                Ok(_) => respond(req, 200, json_string(&serde_json::json!({"ok": true}))),
                Err(e) => respond(
                    req,
                    401,
                    json_string(&ApiError {
                        error: if e == "__NEED_PASSWORD__" { "password required" } else { &e },
                    }),
                ),
            }
        }

        (Method::Post, "/api/session/lock") => {
            session::lock_all();
            respond(req, 200, json_string(&serde_json::json!({"ok": true, "locked": true})))
        }

        (Method::Get, "/api/session/status") => {
            // Tiny endpoint the topbar polls to render "locked / unlocked: N".
            respond(req, 200, json_string(&serde_json::json!({
                "unlocked": session::count_unlocked(),
                "ttl_seconds": session::SESSION_TTL.as_secs(),
            })))
        }

        (Method::Post, "/api/quit") => {
            // Reply first, then exit. Without responding, the browser's
            // fetch hangs and the toast never lands.
            let _ = respond(req, 200, json_string(&serde_json::json!({"ok": true})));
            // Defer just enough for the OS to flush the socket. 200ms is
            // generous; any longer is wasted.
            std::thread::sleep(std::time::Duration::from_millis(200));
            std::process::exit(0);
        }

        (Method::Post, p)
            if p.starts_with("/api/wallet/") && p.ends_with("/delete-challenge") =>
        {
            let label = extract_label(p, "/delete-challenge")?;
            // Just verify the wallet exists (and trigger the password
            // dance if v2 is locked). We don't actually unlock here;
            // we only need to confirm the wallet exists before issuing
            // a challenge.
            if storage::load(&label).is_err() {
                return respond(
                    req,
                    404,
                    json_string(&ApiError { error: "wallet not found" }),
                );
            }
            let (token, indices) = delete_challenge::issue(&label);
            respond(
                req,
                200,
                json_string(&DeleteChallengeResponse {
                    challenge_token: token,
                    indices,
                }),
            )
        }

        (Method::Delete, p) if p.starts_with("/api/wallet/") => {
            // /api/wallet/<label>  (no trailing /...)
            let label = p.trim_start_matches("/api/wallet/");
            if label.is_empty() || label.contains('/') {
                return respond(req, 400, json_string(&ApiError { error: "bad label" }));
            }
            let label_owned = label.to_string();
            let body = read_body(&mut req)?;
            let payload: DeleteRequest = match serde_json::from_str(&body) {
                Ok(p) => p,
                Err(_) => {
                    return respond(req, 400, json_string(&ApiError {
                        error: "delete requires { challenge_token, words[3] } body — issue one via POST /delete-challenge first",
                    }));
                }
            };
            let (chal_label, indices) = match delete_challenge::redeem(&payload.challenge_token) {
                Some(v) => v,
                None => {
                    return respond(req, 401, json_string(&ApiError {
                        error: "challenge expired or invalid; request a new one",
                    }));
                }
            };
            if chal_label != label_owned {
                return respond(req, 401, json_string(&ApiError {
                    error: "challenge token was issued for a different wallet",
                }));
            }
            // Resolve the password (session-cache or body) and unlock
            // the seed so we can re-derive the BIP39 mnemonic.
            let pw = match take_password(&label_owned, Some(&payload.password), false) {
                Ok(p) => p,
                Err(e) if e == "__NEED_PASSWORD__" => {
                    return respond(req, 401, json_string(&NeedPassword { need_password: true, label: &label_owned }));
                }
                Err(e) => {
                    return respond(req, 401, json_string(&ApiError { error: &e }));
                }
            };
            let reason = format!("Confirm deletion of wallet '{label_owned}'");
            let seed = match wallet::unlock_seed(&label_owned, &reason, pw.as_deref().map(|s| s.as_str())) {
                Ok(s) => s,
                Err(e) => {
                    return respond(req, 401, json_string(&ApiError {
                        error: &format!("unlock failed: {e}"),
                    }));
                }
            };
            // Re-derive the mnemonic from the seed and check each word.
            // Compare trimmed + lowercased so trivial typos don't bite.
            use bip39::{Language, Mnemonic};
            let mnemonic = match Mnemonic::from_entropy_in(Language::English, &seed[..]) {
                Ok(m) => m,
                Err(e) => {
                    return respond(req, 500, json_string(&ApiError {
                        error: &format!("BIP39 derive: {e}"),
                    }));
                }
            };
            let words: Vec<&str> = mnemonic.words().collect();
            for (i, idx) in indices.iter().enumerate() {
                let expected = words.get(*idx as usize).copied().unwrap_or("");
                let got = payload.words[i].trim().to_lowercase();
                if got != expected {
                    return respond(req, 401, json_string(&ApiError {
                        error: &format!("word #{} doesn't match — request a new challenge and try again", *idx as usize + 1),
                    }));
                }
            }
            // All three words check out. Final biometric confirm
            // (Apple's HIG: destructive ops should still pass through
            // a system-level gate even after in-app verification).
            if let Err(e) = biometric::prompt(&reason) {
                return respond(req, 401, json_string(&ApiError {
                    error: &format!("biometric gate denied: {e}"),
                }));
            }
            match wallet::delete(&label_owned) {
                Ok(()) => {
                    session::forget(&label_owned);
                    respond(req, 200, json_string(&serde_json::json!({"ok": true})))
                }
                Err(e) => respond(req, 502, json_string(&ApiError {
                    error: &format!("{e:#}"),
                })),
            }
        }

        _ => respond(req, 404, json_string(&ApiError { error: "not found" })),
    }
}

/// Reveal the wallet's recovery secrets for export. Returns the BIP39
/// mnemonic (re-derived from the seed entropy), the raw seed hex, and
/// the Iroha-formatted multihash private key. The caller must have
/// already authenticated through `take_password()`.
fn build_reveal_secrets(label: &str, password: Option<&str>) -> Result<RevealSecretsResponse> {
    use bip39::{Language, Mnemonic};
    let reason = format!("Reveal recovery secrets for '{label}'");
    let seed = wallet::unlock_seed(label, &reason, password)?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &seed[..])
        .context("BIP39 from seed entropy")?;
    let record = storage::load(label)?;
    let seed_hex = hex::encode(&*seed);
    // Match the format dump-client-toml uses: 802620 prefix is the
    // multihash header for Ed25519 in Iroha's SDK.
    let iroha_private_key = format!("802620{}", seed_hex.to_uppercase());
    Ok(RevealSecretsResponse {
        mnemonic: mnemonic.to_string(),
        seed_hex,
        iroha_private_key,
        public_key: record.public_key_hex,
    })
}

/// Build the v3 confidential payment address for the wallet. Touch ID
/// fires inside `wallet::unlock_seed` because we need the spend_key to
/// derive the recipient material.
fn build_confidential_address(label: &str, password: Option<&str>) -> Result<ConfidentialAddressResponse> {
    let reason = format!("Generate confidential payment address for '{label}'");
    let seed = wallet::unlock_seed(label, &reason, password)?;
    if seed.len() != 32 {
        anyhow::bail!("expected 32-byte seed, got {}", seed.len());
    }
    let mut spend_key = [0u8; 32];
    spend_key.copy_from_slice(&seed[..]);
    let addr = confidential_address::build_for_wallet(label, &spend_key)?;
    let uri = confidential_address::render(&addr)?;
    Ok(ConfidentialAddressResponse {
        uri,
        owner_tag_hex: addr.shielded_owner_tag_hex,
        diversifier_hex: addr.shielded_diversifier_hex,
        receive_key_id: addr.receive_key_id,
    })
}

/// Build a balance response by querying the existing torii client and
/// reformatting into a UI-friendly shape (XOR rows are highlighted by
/// being labelled `XOR` in `symbol`; everything else falls through with
/// raw def_id).
fn build_balance(label: &str) -> Result<BalanceResponse> {
    use crate::consts::XOR_ASSET_DEFINITION_ID;
    let record = storage::load(label)?;
    let raw = torii::list_assets_for(&record.i105_address)?;
    let mut assets = Vec::with_capacity(raw.len());
    for asset in &raw {
        let id = asset
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let def_id = id.split('#').next().unwrap_or("?").to_string();
        let value = asset
            .get("value")
            .and_then(|v| v.as_str())
            .or_else(|| asset.get("quantity").and_then(|v| v.as_str()))
            .unwrap_or("?")
            .to_string();
        let symbol = if def_id == XOR_ASSET_DEFINITION_ID {
            Some("XOR".to_string())
        } else {
            None
        };
        assets.push(BalanceAsset { def_id, symbol, value });
    }
    Ok(BalanceResponse {
        label: record.label,
        i105: record.i105_address,
        assets,
    })
}

// ---------------------------------------------------------------------------
// Plumbing helpers
// ---------------------------------------------------------------------------

fn extract_label(path: &str, suffix: &str) -> Result<String> {
    // `/api/wallet/<label>/<suffix>` — strip the prefix and suffix, percent-decode.
    let mid = path
        .strip_prefix("/api/wallet/")
        .and_then(|p| p.strip_suffix(suffix))
        .ok_or_else(|| anyhow!("malformed path: {path}"))?;
    let decoded = urlencoding::decode(mid).context("percent decode")?;
    if decoded.is_empty() || decoded.contains('/') || decoded.contains('\0') {
        anyhow::bail!("invalid label: {decoded:?}");
    }
    Ok(decoded.into_owned())
}

fn read_body(req: &mut Request) -> Result<String> {
    let mut buf = String::new();
    req.as_reader()
        .read_to_string(&mut buf)
        .context("read request body")?;
    Ok(buf)
}

fn json_string<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| r#"{"error":"json serialize failed"}"#.to_string())
}

fn respond_html(req: Request, html: &str) -> Result<()> {
    let mut resp = Response::from_string(html);
    let header = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
        .map_err(|_| anyhow!("invalid content-type header"))?;
    resp.add_header(header);
    req.respond(resp).context("respond html")?;
    Ok(())
}

fn respond_png(req: Request, bytes: &[u8]) -> Result<()> {
    let mut resp = Response::from_data(bytes);
    let header = Header::from_bytes(&b"Content-Type"[..], &b"image/png"[..])
        .map_err(|_| anyhow!("invalid content-type header"))?;
    resp.add_header(header);
    let cache = Header::from_bytes(&b"Cache-Control"[..], &b"public, max-age=86400"[..])
        .map_err(|_| anyhow!("invalid cache-control header"))?;
    resp.add_header(cache);
    req.respond(resp).context("respond png")?;
    Ok(())
}

/// Resolve the path of `logo.png` for the current build:
///   - inside an .app bundle: `Contents/Resources/logo.png` next to the executable.
///   - dev / CLI run: `dist/logo.png` at the project root.
/// Returns the file contents on success.
fn find_logo_bytes() -> Option<Vec<u8>> {
    let candidates = [
        // Inside .app: …/Contents/MacOS/<bin> → ../Resources/logo.png
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("../Resources/logo.png"))),
        // Dev: <project>/dist/logo.png
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("../../dist/logo.png"))),
    ];
    for c in candidates.into_iter().flatten() {
        if c.exists() {
            if let Ok(b) = std::fs::read(&c) {
                return Some(b);
            }
        }
    }
    None
}

fn respond(req: Request, status: u16, body: String) -> Result<()> {
    let mut resp = Response::from_string(body).with_status_code(status as i32);
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..])
        .map_err(|_| anyhow!("invalid content-type header"))?;
    resp.add_header(header);
    req.respond(resp).context("respond")?;
    Ok(())
}
