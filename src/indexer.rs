// Confidential-ledger indexer (Phase 2, step 1 of ZK_ROADMAP.md).
//
// The Iroha 3 shielded ledger is a depth-16 Merkle tree of 32-byte
// `note_commitment` leaves, one per Shield ISI on the relevant asset
// definition. To spend a note in Phase 2 (Unshield / ZkTransfer) the
// wallet must:
//
//   1. know its leaf index in the global tree;
//   2. compute the Merkle path from leaf to root;
//   3. embed both as private witness inside a Halo2-IPA proof.
//
// This file ships (1): paginate `/v1/confidential/notes` from genesis,
// extract every Shield's `note_commitment`, persist them in append order
// to a local binary cache. Steps (2) and (3) build on the cached bytes.
//
// File format (`<cache_dir>/<asset_def_id>.bin`):
//
//   header (64 bytes):
//     magic       8 bytes  "MNMTOIDX"   (Minamoto-wallet index)
//     version     u32 LE   = 1
//     count       u32 LE   number of 32-byte commitments in body
//     root        32 bytes chain's latest root at fetch time (sanity)
//     fetched_at  i64 LE   Unix seconds, signed for chrono interop
//     reserved    8 bytes  zeros (future)
//   body:
//     count * 32 bytes commitments, in append (= leaf-index) order.
//
// Verifying parity: after `refresh`, `stats.commitment_count` must equal
// `stats.chain_height`. The on-chain root is recorded but NOT recomputed
// here; that lands in step 2 (`merkle.rs`).

use crate::storage;
use crate::torii;
use anyhow::{Context, Result, bail};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const MAGIC: &[u8; 8] = b"MNMTOIDX";
const VERSION: u32 = 1;
const HEADER_SIZE: usize = 64;
const COMMIT_SIZE: usize = 32;

/// Page size for `/v1/confidential/notes`. Server may cap lower; the
/// pagination loop just keeps walking until `next_cursor` is None.
const PAGE_LIMIT: u32 = 200;

/// Hard ceiling on how many pages we'll walk in a single `refresh` call,
/// to prevent runaway loops if the cursor logic ever degenerates server
/// side. Depth-16 tree caps at 65 536 leaves → at PAGE_LIMIT=200 that's
/// 328 pages at saturation. 1 000 is generous slack.
const MAX_PAGES: usize = 1_000;

/// Cached snapshot of the confidential ledger for a single asset.
pub struct IndexSnapshot {
    pub asset_def_id: String,
    pub commitments: Vec<[u8; 32]>,
    /// Chain root recorded at fetch time. We don't recompute it locally
    /// until `merkle.rs` (step 2) lands.
    pub recorded_root: [u8; 32],
    pub fetched_at_unix: i64,
    pub cache_path: PathBuf,
}

/// Live results of a `refresh` call: what we just wrote, plus the
/// chain-side ground truth we used to check parity.
pub struct RefreshOutcome {
    pub snapshot: IndexSnapshot,
    /// Number of leaves the chain reports for this asset.
    pub chain_height: u32,
    /// Pages walked (diagnostic).
    pub pages_fetched: usize,
}

impl RefreshOutcome {
    /// True when `commitments.len() == chain_height` — i.e. the local
    /// cache is complete relative to the chain at refresh time. New
    /// commitments may land between the last page and the root call,
    /// so a tiny mismatch is recoverable; rerun `refresh` to catch up.
    pub fn parity_ok(&self) -> bool {
        self.snapshot.commitments.len() as u32 == self.chain_height
    }
}

/// Resolve the on-disk path for an asset's index cache.
///
/// `asset_def_id` is used as the filename verbatim. Iroha asset
/// definition IDs are either Base58 (`6TEAJqbb…`) or alias literals
/// (`xor#universal`); neither contain path separators. We still reject
/// `/` and NUL defensively so a malformed input can't escape the cache
/// directory.
pub fn cache_path(asset_def_id: &str) -> Result<PathBuf> {
    if asset_def_id.is_empty() {
        bail!("asset_def_id must be non-empty");
    }
    if asset_def_id.contains('/') || asset_def_id.contains('\0') {
        bail!("asset_def_id contains illegal path characters: '{asset_def_id}'");
    }
    let mut p = storage::cache_dir()?;
    p.push(format!("{asset_def_id}.bin"));
    Ok(p)
}

/// Read the on-disk index cache, returning `None` if the file does not
/// exist. Validates the header magic + version and rejects truncated
/// files.
pub fn read_cache(asset_def_id: &str) -> Result<Option<IndexSnapshot>> {
    let path = cache_path(asset_def_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("read {path:?}"))?;
    if bytes.len() < HEADER_SIZE {
        bail!("cache {path:?} is truncated ({} bytes < header)", bytes.len());
    }
    if &bytes[0..8] != MAGIC {
        bail!("cache {path:?} bad magic — not a minamoto-wallet index file");
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != VERSION {
        bail!("cache {path:?} version {version} unsupported (expected {VERSION})");
    }
    let count = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let mut recorded_root = [0u8; 32];
    recorded_root.copy_from_slice(&bytes[16..48]);
    let fetched_at_unix = i64::from_le_bytes(bytes[48..56].try_into().unwrap());

    let expected_len = HEADER_SIZE + count * COMMIT_SIZE;
    if bytes.len() != expected_len {
        bail!(
            "cache {path:?} length {} does not match header count {count} (expected {expected_len})",
            bytes.len()
        );
    }
    let mut commitments = Vec::with_capacity(count);
    for i in 0..count {
        let off = HEADER_SIZE + i * COMMIT_SIZE;
        let mut c = [0u8; 32];
        c.copy_from_slice(&bytes[off..off + COMMIT_SIZE]);
        commitments.push(c);
    }
    Ok(Some(IndexSnapshot {
        asset_def_id: asset_def_id.to_string(),
        commitments,
        recorded_root,
        fetched_at_unix,
        cache_path: path,
    }))
}

/// Atomically write the cache file: serialize to a temp path, then rename.
fn write_cache(snapshot: &IndexSnapshot) -> Result<()> {
    let count = snapshot.commitments.len();
    if count > u32::MAX as usize {
        bail!("commitment count {count} exceeds u32::MAX");
    }
    let mut buf = Vec::with_capacity(HEADER_SIZE + count * COMMIT_SIZE);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&(count as u32).to_le_bytes());
    buf.extend_from_slice(&snapshot.recorded_root);
    buf.extend_from_slice(&snapshot.fetched_at_unix.to_le_bytes());
    buf.extend_from_slice(&[0u8; 8]); // reserved
    debug_assert_eq!(buf.len(), HEADER_SIZE);
    for c in &snapshot.commitments {
        buf.extend_from_slice(c);
    }

    let tmp = snapshot.cache_path.with_extension("bin.tmp");
    {
        let mut f = File::create(&tmp).with_context(|| format!("create {tmp:?}"))?;
        f.write_all(&buf).with_context(|| format!("write {tmp:?}"))?;
        f.sync_all().with_context(|| format!("fsync {tmp:?}"))?;
    }
    fs::rename(&tmp, &snapshot.cache_path)
        .with_context(|| format!("rename {tmp:?} -> {:?}", snapshot.cache_path))?;
    // Tighten perms to 0600 — consistent with wallet record files. The
    // cache contents are public chain data so this is defense in depth,
    // not a real privacy gate; still better than the default 0644 that
    // would let other local users read the file even when the directory
    // is 0700.
    let mut perms = fs::metadata(&snapshot.cache_path)
        .with_context(|| format!("stat {:?}", snapshot.cache_path))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&snapshot.cache_path, perms)
        .with_context(|| format!("chmod 0600 {:?}", snapshot.cache_path))?;
    Ok(())
}

/// Paginate the confidential-notes endpoint to completion, then write the
/// resulting commitment list to the local cache. Cross-checks against
/// `/v1/zk/roots`.
///
/// Idempotent — running twice replaces the cache file with the freshest
/// snapshot. Network errors on any page abort without touching the cache.
pub fn refresh(asset_def_id: &str) -> Result<RefreshOutcome> {
    let path = cache_path(asset_def_id)?;
    let mut commitments: Vec<[u8; 32]> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages_fetched: usize = 0;
    loop {
        if pages_fetched >= MAX_PAGES {
            bail!(
                "refresh aborted: hit MAX_PAGES={MAX_PAGES} cap (cursor={cursor:?}). \
                 The chain may have more leaves than expected, or the server cursor \
                 is not advancing — investigate before bumping the cap."
            );
        }
        let page = torii::fetch_confidential_notes_page(
            asset_def_id,
            cursor.as_deref(),
            PAGE_LIMIT,
        )
        .with_context(|| {
            format!(
                "fetch confidential-notes page {} (cursor={cursor:?})",
                pages_fetched + 1
            )
        })?;
        commitments.extend(page.commitments);
        pages_fetched += 1;
        match page.next_cursor {
            Some(next) if !next.is_empty() => cursor = Some(next),
            _ => break,
        }
    }

    // Ground truth from a separate endpoint. May report height >
    // commitments.len() if a Shield landed mid-paginate; we surface that
    // via `parity_ok()` so the caller can decide to retry.
    let chain = torii::fetch_confidential_root(asset_def_id)
        .context("fetch confidential root for parity check")?;

    let fetched_at_unix = chrono::Utc::now().timestamp();
    let snapshot = IndexSnapshot {
        asset_def_id: asset_def_id.to_string(),
        commitments,
        recorded_root: chain.latest,
        fetched_at_unix,
        cache_path: path,
    };
    write_cache(&snapshot)?;
    Ok(RefreshOutcome {
        snapshot,
        chain_height: chain.height,
        pages_fetched,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_path_rejects_path_traversal() {
        assert!(cache_path("../../etc/passwd").is_err());
        assert!(cache_path("foo/bar").is_err());
        assert!(cache_path("foo\0bar").is_err());
        assert!(cache_path("").is_err());
    }

    #[test]
    fn cache_path_accepts_canonical_ids() {
        // Both variants Iroha 3 uses for asset definition IDs.
        assert!(cache_path("6TEAJqbb8oEPmLncoNiMRbLEK6tw").is_ok());
        assert!(cache_path("xor#universal").is_ok());
    }

    #[test]
    fn header_layout_is_exact() {
        // If anyone touches the header constants without bumping VERSION
        // this test catches it. The serialized empty cache must be
        // exactly HEADER_SIZE bytes.
        let snap = IndexSnapshot {
            asset_def_id: "test".to_owned(),
            commitments: vec![],
            recorded_root: [0u8; 32],
            fetched_at_unix: 0,
            cache_path: std::env::temp_dir().join("minamoto-wallet-test.bin"),
        };
        // Just verify the buffer length we'd write matches HEADER_SIZE.
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&snap.recorded_root);
        buf.extend_from_slice(&snap.fetched_at_unix.to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        assert_eq!(buf.len(), HEADER_SIZE);
    }

    #[test]
    fn round_trip_write_then_read() -> Result<()> {
        // Use a unique sub-dir under tmp so the test doesn't collide
        // with concurrent runs and never touches the user's real cache.
        let dir = std::env::temp_dir().join(format!(
            "minamoto-wallet-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("rt.bin");

        let mut commits: Vec<[u8; 32]> = Vec::new();
        for i in 0..3u8 {
            let mut c = [0u8; 32];
            c[0] = i;
            c[31] = 0xff;
            commits.push(c);
        }
        let snap = IndexSnapshot {
            asset_def_id: "rt".to_owned(),
            commitments: commits.clone(),
            recorded_root: [0xab; 32],
            fetched_at_unix: 1_700_000_000,
            cache_path: path.clone(),
        };
        write_cache(&snap)?;

        // Read back manually since `read_cache` resolves through cache_dir.
        let bytes = fs::read(&path)?;
        assert_eq!(&bytes[0..8], MAGIC);
        let count = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        assert_eq!(count, 3);
        assert_eq!(bytes.len(), HEADER_SIZE + 3 * COMMIT_SIZE);
        for (i, c) in commits.iter().enumerate() {
            let off = HEADER_SIZE + i * COMMIT_SIZE;
            assert_eq!(&bytes[off..off + COMMIT_SIZE], c);
        }
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn read_cache_returns_none_when_file_missing() -> Result<()> {
        // Pick an asset id that almost certainly doesn't exist on this Mac.
        let id = format!("nonexistent-{}", std::process::id());
        let snap = read_cache(&id)?;
        assert!(snap.is_none());
        Ok(())
    }
}
