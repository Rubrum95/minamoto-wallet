// Minamoto network constants. These are not exposed by Torii REST API and
// must be hard-coded against the canonical defaults in the Iroha 3 source
// (see `iroha-source/iroha/defaults/kagami/iroha3-nexus/config.toml`).
//
// If a constant is wrong the network will reject our transaction with a
// structured error that exposes the expected value (e.g. ChainIdMismatch).
// We use that as the runtime oracle and update this file accordingly.

/// Torii base URL for Minamoto mainnet.
pub const TORII_BASE: &str = "https://minamoto.sora.org";

/// Network discriminant prefix (decimal) used to encode I105 account IDs.
/// Verified empirically: every account currently on chain has
/// `network_prefix: 753` in `/v1/explorer/accounts`.
pub const NETWORK_PREFIX: u16 = 753;

/// Chain ID. NOT exposed by any Torii REST endpoint (the executor
/// validates server-side; mismatch returns ChainIdMismatch).
///
/// **Discovered empirically on 2026-04-30** by submitting a Shield ISI
/// with the previous educated guess (`"iroha3-nexus"`, taken from the
/// canonical `defaults/kagami/iroha3-nexus/config.toml`). The Torii
/// rejection response leaks the expected value:
///
/// ```text
/// Expected ChainId("00000000-0000-0000-0000-000000000000"),
/// actual   ChainId("iroha3-nexus")
/// ```
///
/// The Soramitsu operators ship Minamoto with the UUID-zeros placeholder
/// rather than the named profile. This is consistent with
/// `defaults/client.toml` and `defaults/nexus/config.toml` upstream
/// (both also use the same UUID-zeros default).
pub const CHAIN_ID: &str = "00000000-0000-0000-0000-000000000000";

/// XOR asset definition ID. Verified via `/v1/assets/definitions` — same
/// 28-character base58 ID as on Taira testnet (asset definitions are global
/// and reused across Soramitsu networks). Mode = Convertible (ZK
/// shield/unshield supported).
pub const XOR_ASSET_DEFINITION_ID: &str = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";

/// Keychain identifiers for `kSecAttrService`. All wallet-managed keychain
/// items share this service string; per-wallet uniqueness comes from
/// `kSecAttrAccount = <wallet_label>`.
pub const KEYCHAIN_SERVICE: &str = "minamoto-wallet";
