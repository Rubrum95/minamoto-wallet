// V3 confidential payment address: parse + render.
//
// Format observed in the wild (e.g. https://x.com/sora_xor/status/...):
//
//   iroha:confidential:v3:<base64url-of-JSON>
//
// where the inner JSON looks like:
//
//   {
//     "schema": "iroha-confidential-payment-address/v3",
//     "receiveKeyId": "<22-char base64url>",
//     "receivePublicKeyBase64Url": "<43-char base64url ≈ 32 bytes>",
//     "shieldedOwnerTagHex": "<64-hex = 32 bytes>",
//     "shieldedDiversifierHex": "<64-hex = 32 bytes>",
//     "recoveryHint": "one-time-receive-key"
//   }
//
// The cryptographic primitives behind the four hex/b64url fields all live
// in the upstream `iroha-source/iroha` (i23-features branch):
//
//   - `iroha_crypto::confidential::derive_keyset` (HKDF-SHA3-512 over the
//     spend key) yields the `incoming_view_key` (ivk) — that's the 32-byte
//     scalar we publish as `receivePublicKeyBase64Url` (placeholder until
//     we know the curve recipe; safe-by-default: a sender that doesn't know
//     the encryption recipe just emits `enc_payload = default()` and the
//     recipient discovers the note out-of-band).
//   - `iroha_core::zk::confidential_v2::derive_confidential_diversifier_v2`
//     gives the 32-byte diversifier we publish as `shieldedDiversifierHex`.
//   - `iroha_core::zk::confidential_v2::derive_confidential_owner_tag_v2_with_diversifier`
//     gives the 32-byte owner_tag we publish as `shieldedOwnerTagHex`.
//
// What this module does NOT do:
//
//   - Encryption of the `enc_payload` field on Shield. The recipient's
//     `receivePublicKeyBase64Url` would normally be the public point used
//     to ECDH with an ephemeral sender key + KDF + AEAD. We don't know the
//     exact recipe and shipping zeros is fine for Phase 1 (recipient gets
//     the note out-of-band).
//   - `receiveKeyId` rotation. We emit a deterministic ID so the same
//     wallet always produces the same address. A rotation scheme is
//     a future enhancement.
//
// What this module DOES do (Phase 1 sufficient):
//
//   - Render: turn (owner_tag, diversifier, ivk) into the URI string.
//   - Parse: turn the URI string into the four byte arrays.
//   - The result is enough for a third party (you) to call our `shield`
//     builder targeting an external recipient: the commitment will be
//     spendable BY THEM later when ZK Phase 2 (Unshield/ZkTransfer) lands.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};

const URI_PREFIX: &str = "iroha:confidential:v3:";
const SCHEMA_TAG: &str = "iroha-confidential-payment-address/v3";

/// Decoded representation of a v3 payment address. All "Hex" fields are
/// expected to be 64 hex chars (32 bytes); the base64url ones are the
/// canonical url-safe-no-padding variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V3PaymentAddress {
    pub schema: String,
    /// Opaque rotation id chosen by the recipient. We treat it as opaque.
    #[serde(rename = "receiveKeyId")]
    pub receive_key_id: String,
    /// 32-byte recipient encryption key, base64url (no padding). May be
    /// empty if the recipient hasn't published an encryption key.
    #[serde(rename = "receivePublicKeyBase64Url")]
    pub receive_public_key_base64url: String,
    /// 32-byte recipient owner_tag (poseidon_pair(spend_scalar, diversifier)).
    #[serde(rename = "shieldedOwnerTagHex")]
    pub shielded_owner_tag_hex: String,
    /// 32-byte note diversifier (Pasta scalar repr).
    #[serde(rename = "shieldedDiversifierHex")]
    pub shielded_diversifier_hex: String,
    /// Free-form hint, e.g. "one-time-receive-key". Optional.
    #[serde(rename = "recoveryHint", default, skip_serializing_if = "String::is_empty")]
    pub recovery_hint: String,
}

impl V3PaymentAddress {
    /// 32-byte owner_tag as a Rust array, decoded from the hex field.
    pub fn owner_tag(&self) -> Result<[u8; 32]> {
        decode_hex32(&self.shielded_owner_tag_hex, "shieldedOwnerTagHex")
    }

    /// 32-byte diversifier as a Rust array, decoded from the hex field.
    pub fn diversifier(&self) -> Result<[u8; 32]> {
        decode_hex32(&self.shielded_diversifier_hex, "shieldedDiversifierHex")
    }
}

/// Parse a `iroha:confidential:v3:<base64url-json>` URI string. Whitespace
/// inside the trailing payload is stripped (Twitter wraps long strings).
pub fn parse(uri: &str) -> Result<V3PaymentAddress> {
    let body = uri
        .trim()
        .strip_prefix(URI_PREFIX)
        .ok_or_else(|| anyhow!("payment address must start with `{URI_PREFIX}`"))?;
    let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let json_bytes = base64_url_decode(&body)
        .with_context(|| "failed to base64url-decode payment address payload")?;
    let json = std::str::from_utf8(&json_bytes)
        .context("payment address payload is not valid UTF-8")?;
    let parsed: V3PaymentAddress = serde_json::from_str(json)
        .with_context(|| format!("payment address JSON parse failed; raw json: {json}"))?;
    if parsed.schema != SCHEMA_TAG {
        bail!(
            "unexpected schema `{}`, expected `{SCHEMA_TAG}`",
            parsed.schema
        );
    }
    // Validate all required hex fields parse to 32 bytes upfront so callers
    // get a clean error rather than a runtime panic later.
    let _ = parsed.owner_tag()?;
    let _ = parsed.diversifier()?;
    Ok(parsed)
}

/// Render a `V3PaymentAddress` back to the URI string.
pub fn render(addr: &V3PaymentAddress) -> Result<String> {
    let json = serde_json::to_string(addr).context("serialize V3 payment address")?;
    let body = base64_url_encode(json.as_bytes());
    Ok(format!("{URI_PREFIX}{body}"))
}

/// Build a v3 payment address for *our* wallet from its 32-byte spend key
/// (= the wallet seed) and a deterministic diversifier seed (we use the
/// label, so the same wallet always renders the same address).
///
/// `receive_public_key_base64url` is filled with the wallet's
/// `incoming_view_key` (the 32-byte HKDF-derived ivk from
/// `iroha_crypto::confidential`). We don't yet know the exact recipe a
/// third-party wallet uses to produce the AEAD nonce/key — so this field
/// is a best-effort placeholder. Senders that can't derive a payload
/// encryption key from `ivk` MUST emit `enc_payload = default()` and we'll
/// recover the note out-of-band (Phase 1 limitation).
pub fn build_for_wallet(
    label: &str,
    spend_key: &[u8; 32],
) -> Result<V3PaymentAddress> {
    use iroha_crypto::{ConfidentialKeyset, derive_keyset_from_slice};

    let keyset: ConfidentialKeyset = derive_keyset_from_slice(spend_key)
        .map_err(|e| anyhow!("derive ConfidentialKeyset failed: {e:?}"))?;
    let ivk: [u8; 32] = *keyset.incoming_view_key();

    // Deterministic diversifier from the wallet label so the address is
    // stable across calls. A future change can rotate it per-payment.
    let diversifier = crate::zk_v2::derive_confidential_diversifier_v2(label.as_bytes());
    let owner_tag = crate::zk_v2::derive_confidential_owner_tag_v2_with_diversifier(
        spend_key,
        diversifier,
    )
    .map_err(|e| anyhow!("derive owner_tag failed: {e}"))?;

    // Receive key id: deterministic 16-byte tag derived from the ivk.
    // Picked at 16 bytes because that's what the example we decoded from
    // `@sora_xor`'s tweet had (24 base64url chars = 16 raw bytes).
    let mut tag_in = Vec::with_capacity(64);
    tag_in.extend_from_slice(b"iroha:confidential:v3:receive_key_id:");
    tag_in.extend_from_slice(&ivk);
    let id_bytes = blake3::hash(&tag_in);
    let receive_key_id = base64_url_encode(&id_bytes.as_bytes()[..16]);

    Ok(V3PaymentAddress {
        schema: SCHEMA_TAG.to_owned(),
        receive_key_id,
        receive_public_key_base64url: base64_url_encode(&ivk),
        shielded_owner_tag_hex: hex::encode(owner_tag),
        shielded_diversifier_hex: hex::encode(diversifier),
        recovery_hint: "one-time-receive-key".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn decode_hex32(s: &str, field: &'static str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s)
        .with_context(|| format!("`{field}` is not valid hex: {s}"))?;
    if bytes.len() != 32 {
        bail!("`{field}` must decode to 32 bytes (got {})", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn base64_url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>> {
    // Be lenient: accept both URL_SAFE and STANDARD, with or without padding.
    let trimmed = data.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .with_context(|| format!("base64 decode failed for {trimmed:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Snapshot of the address visible in `@sora_xor`'s public tweet,
    /// reconstructed from the screenshot. The test asserts our parser can
    /// round-trip the format and recover the (owner_tag, diversifier).
    const TWEET_URI: &str = concat!(
        "iroha:confidential:v3:",
        "eyJzY2hlbWEiOiJpcm9oYS1jb25maWRlbnRpYWwtcGF5bWVudC1hZGRyZXNzL3YzIiwicmVj",
        "ZWl2ZUtleUlkIjoiOEdfaE90SXVDNXB5MGxDbklvOFhxVGcwIiwicmVjZWl2ZVB1YmxpY0tl",
        "eUJhc2U2NFVybCI6Ik9iRlM5TlkyMUFQRFJuR3JlWnBtZ1N3N3Y3RnJnbHR4Z0gwNU9WaWFw",
        "VTQiLCJzaGllbGRlZE93bmVyVGFnSGV4IjoiNDA0YjRlZmYzZDE3MGU2MWMwNjA2MWJmMGNl",
        "ZWQ2ZTc4NDY3NWZiZTRjNzhlYmMwOTQ3Yjg5ZmI5MmM0MGMxMiIsInNoaWVsZGVkRGl2ZXJz",
        "aWZpZXJIZXgiOiJlMmI5MGIyNmU2MTQ5MDc0MzMzM2M1OTU0OTc5OTY2NDhkYjJmMzM5OTUx",
        "ODFiN2E1NTBiNDJlNGI5MzNkN2Q3In0",
    );

    #[test]
    fn parses_tweet_address() {
        let addr = parse(TWEET_URI).expect("parse failed");
        assert_eq!(addr.schema, SCHEMA_TAG);
        assert_eq!(addr.shielded_owner_tag_hex.len(), 64);
        assert_eq!(addr.shielded_diversifier_hex.len(), 64);
        let _ot = addr.owner_tag().unwrap();
        let _div = addr.diversifier().unwrap();
    }

    #[test]
    fn round_trip_render_parse() {
        let addr = V3PaymentAddress {
            schema: SCHEMA_TAG.to_owned(),
            receive_key_id: "abc".to_owned(),
            receive_public_key_base64url: "xyz".to_owned(),
            shielded_owner_tag_hex: hex::encode([0x11u8; 32]),
            shielded_diversifier_hex: hex::encode([0x22u8; 32]),
            recovery_hint: String::new(),
        };
        let uri = render(&addr).unwrap();
        let parsed = parse(&uri).unwrap();
        assert_eq!(parsed.shielded_owner_tag_hex, addr.shielded_owner_tag_hex);
        assert_eq!(
            parsed.shielded_diversifier_hex,
            addr.shielded_diversifier_hex
        );
    }
}
