// minamoto-wallet — Touch-ID-protected Ed25519 wallet for Iroha 3 / Minamoto.
//
// Subcommands implemented in this iteration:
//   generate <label>   — fresh wallet, returns pubkey + I105 + 24-word mnemonic
//   restore  <label>   — restore from BIP39 mnemonic on stdin
//   pubkey   <label>   — show pubkey + I105 (Touch ID)
//   delete   <label>   — remove wallet (Touch ID)
//
// `send-xor`, `balance` follow once the keychain path is verified.

mod balance;
#[cfg(target_os = "macos")]
mod biometric;
mod confidential_address;
mod consts;
#[cfg(target_os = "macos")]
mod delete_challenge;
mod password;
#[cfg(target_os = "macos")]
mod shield;
mod zk_v2;
#[cfg(target_os = "macos")]
mod secure_enclave;
#[cfg(target_os = "macos")]
mod session;
mod storage;
mod torii;
mod transfer;
#[cfg(target_os = "macos")]
mod ui;
mod wallet;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{self, Read};
use zeroize::Zeroizing;

/// Look up the wallet record on disk and decide what we need to unlock
/// it: v2 records require a password (we prompt twice if `confirm=true`),
/// v1 records use the legacy SE/Touch-ID path (no password needed).
///
/// Returns `Ok(Some(password))` for v2, `Ok(None)` for v1, and `Err`
/// if the record is missing or unreadable.
#[cfg(target_os = "macos")]
fn read_password_for(label: &str) -> Result<Option<Zeroizing<String>>> {
    let record = storage::load(label)?;
    if record.version == storage::CURRENT_VERSION {
        let pw = rpassword::prompt_password(format!("Password for '{label}': "))
            .context("read password from terminal")?;
        Ok(Some(Zeroizing::new(pw)))
    } else {
        Ok(None)
    }
}

/// Prompt twice for a new password (creation / migration). Refuses if
/// the two entries don't match.
#[cfg(target_os = "macos")]
fn read_new_password(prompt: &str) -> Result<Zeroizing<String>> {
    let p1 = rpassword::prompt_password(format!("{prompt}: "))?;
    let p2 = rpassword::prompt_password(format!("{prompt} (confirm): "))?;
    if p1 != p2 {
        anyhow::bail!("passwords do not match");
    }
    Ok(Zeroizing::new(p1))
}

#[derive(Parser)]
#[command(
    name = "minamoto-wallet",
    about = "Touch-ID-protected Ed25519 wallet for Iroha 3 / Minamoto",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new wallet. Stores the seed in macOS Keychain with biometric
    /// ACL and prints the public key + I105 address + 24-word BIP39 mnemonic.
    /// **Write the mnemonic on paper before continuing.** It is the only way
    /// to recover the wallet if the Keychain item is destroyed.
    Generate {
        /// Local label used as `kSecAttrAccount` in the Keychain item. Must
        /// be unique per wallet on this Mac.
        label: String,
    },

    /// Restore a wallet from a 24-word BIP39 mnemonic provided on stdin.
    Restore {
        /// Local label for the new Keychain item.
        label: String,
    },

    /// Print the public key + I105 address for an existing wallet.
    /// Triggers Touch ID because the seed must be read to derive them.
    Pubkey {
        /// Wallet label.
        label: String,
    },

    /// Permanently delete a wallet's Keychain item. Triggers Touch ID
    /// (Apple requires biometric proof to delete biometric-ACL items).
    Delete {
        /// Wallet label.
        label: String,
    },

    /// Smoke test: prompt Touch ID and unwrap the seed. Verifies the
    /// biometric gate works end-to-end without sending any tx. Output
    /// is the 32-byte seed in hex (TEST WALLET ONLY — never run on a
    /// production wallet because it prints the secret).
    UnlockTest {
        /// Wallet label.
        label: String,
    },

    /// Show all asset balances for this wallet (live from Torii). No
    /// Touch ID — it only reads the public address from the on-disk
    /// record and queries the network.
    Balance {
        /// Wallet label.
        label: String,
    },

    /// Send XOR to another Minamoto account. Triggers the Touch ID gate
    /// before signing.
    SendXor {
        /// Wallet label.
        label: String,
        /// Recipient I105 address (sora…).
        to: String,
        /// Amount of XOR (decimal string, e.g. "1" or "0.5").
        amount: String,
    },

    /// Launch the local web UI (loopback only, http://127.0.0.1:7825).
    /// Wraps every CLI command behind a small JSON API and serves a
    /// single-page wallet manager. Browser opens automatically.
    Ui,

    /// Convert public XOR into a confidential note in the shielded
    /// ledger. Builds a real Pasta-Fp Poseidon-pair commitment via
    /// `zk_v2::derive_confidential_note_v2` and posts the Shield ISI to
    /// Torii. The `enc_payload` is shipped as zeros (Phase 1) — the
    /// local note record at ~/Library/Application Support/minamoto-wallet/
    /// is required to spend the note later. Triggers Touch ID.
    Shield {
        /// Wallet label.
        label: String,
        /// Public XOR amount to convert (integer u128).
        amount: String,
    },

    /// Convert a shielded note back to public XOR. NOT YET IMPLEMENTED —
    /// requires a Halo2-IPA proof over the user's notes (witness
    /// includes Merkle path to current shielded ledger root). See
    /// ZK_ROADMAP.md Phase 2.
    Unshield {
        /// Wallet label.
        label: String,
        /// Public amount to credit out of shielded notes.
        amount: String,
    },

    /// **DEBUG ONLY** — print Iroha-formatted client.toml for use with
    /// the official `iroha` CLI binary. Triggers Touch ID. Outputs the
    /// private_key in plaintext. Use ONLY for testnet debugging; never
    /// run on a wallet holding meaningful XOR.
    DumpClientToml {
        /// Wallet label.
        label: String,
    },

    /// **DIAGNOSTIC** — submit a `Register::Account` ISI for our own
    /// account, signed by our own seed. Tests whether implicit accounts
    /// (created via cross-chain Mint) can self-promote to formally-
    /// registered status, or whether registration requires a privileged
    /// authority. Triggers Touch ID. On Committed, also flips the local
    /// `registered_on_chain` flag so subsequent transfer/shield calls
    /// skip the auto-register prepend.
    RegisterSelf {
        /// Wallet label.
        label: String,
    },

    /// Print our own confidential payment address (v3 envelope), so we
    /// can publish it on Twitter / a website / a QR code and others can
    /// send us shielded XOR via `pay-address`. Triggers Touch ID because
    /// generating the receive material requires the wallet seed.
    MyAddress {
        /// Wallet label.
        label: String,
    },

    /// Send shielded XOR to a third-party `iroha:confidential:v3:…`
    /// address. Same on-chain primitive as `shield`, but the resulting
    /// note's owner_tag belongs to THEM (not us). Returns the
    /// transaction hash + the 32-byte rho — the rho MUST be shared with
    /// the recipient out-of-band (Phase 1: no payload encryption yet).
    ///
    /// Triggers Touch ID (unless `--dry-run`).
    PayAddress {
        /// Wallet label (sender).
        label: String,
        /// `iroha:confidential:v3:<base64url>` URI from the recipient.
        recipient_address: String,
        /// Amount of XOR (whole-units integer u128).
        amount: String,
        /// Skip Touch ID + signing + chain submit. Just parse the
        /// recipient URI, derive the note commitment we WOULD have
        /// committed, and print it. Use this to validate that a v3
        /// payment address is well-formed BEFORE spending real XOR.
        #[arg(long)]
        dry_run: bool,
    },

    /// Migrate a v1 (legacy SE-wrap) wallet to v2 (password-encrypted).
    /// One-shot: Touch ID once → enter new password → done. The SE
    /// keychain item is removed at the end. Existing local notes and
    /// the `registered_on_chain` flag are preserved.
    MigrateV2 {
        /// Wallet label (must currently be v1).
        label: String,
    },

    /// **AUDIT EXPERIMENT** — verify whether biometric ACL on the
    /// keychain item works for ad-hoc-signed binaries on this Mac.
    /// Generates a throwaway test wallet with `kSecAccessControlBiometryAny`
    /// applied, attempts to unwrap without our LAContext gate, and reports
    /// whether the OS triggered Touch ID automatically. Cleans up the
    /// test keychain item on success or failure. Does NOT touch your real
    /// wallets.
    BioTest,

    /// One-shot fix for wallets that were already registered on chain
    /// before the auto-register feature existed (so the local JSON has
    /// `registered_on_chain=false` even though the chain knows the
    /// account). Flips the flag without touching the chain. Verifying
    /// that the account is actually registered is the user's
    /// responsibility — getting it wrong only triggers a redundant
    /// Register::Account on the next tx, which the chain rejects
    /// harmlessly.
    MarkRegistered {
        /// Wallet label.
        label: String,
    },
}

#[cfg(not(target_os = "macos"))]
fn main() -> Result<()> {
    anyhow::bail!("minamoto-wallet only runs on macOS — biometric Keychain ACL is not portable")
}

#[cfg(target_os = "macos")]
fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Generate { label } => cmd_generate(&label),
        Cmd::Restore { label } => cmd_restore(&label),
        Cmd::Pubkey { label } => cmd_pubkey(&label),
        Cmd::Delete { label } => cmd_delete(&label),
        Cmd::UnlockTest { label } => cmd_unlock_test(&label),
        Cmd::Balance { label } => balance::print_balance(&label),
        Cmd::SendXor { label, to, amount } => cmd_send_xor(&label, &to, &amount),
        Cmd::Ui => ui::run(),
        Cmd::Shield { label, amount } => cmd_shield(&label, &amount),
        Cmd::Unshield { label, amount } => cmd_zk_stub("unshield", &label, &amount),
        Cmd::DumpClientToml { label } => cmd_dump_client_toml(&label),
        Cmd::RegisterSelf { label } => cmd_register_self(&label),
        Cmd::MarkRegistered { label } => cmd_mark_registered(&label),
        Cmd::BioTest => cmd_bio_test(),
        Cmd::MigrateV2 { label } => cmd_migrate_v2(&label),
        Cmd::MyAddress { label } => cmd_my_address(&label),
        Cmd::PayAddress {
            label,
            recipient_address,
            amount,
            dry_run,
        } => cmd_pay_address(&label, &recipient_address, &amount, dry_run),
    }
}

#[cfg(target_os = "macos")]
fn cmd_bio_test() -> Result<()> {
    // Use a label distinct from any real wallet so we never overwrite.
    let test_label = format!("bio-test-{}", chrono::Utc::now().timestamp_millis());
    eprintln!("==== minamoto-wallet — biometric ACL experiment ====");
    eprintln!();
    eprintln!("Test label: {test_label}");
    eprintln!();
    eprintln!("Step 1: generate 32-byte test seed (NOT a real wallet)");
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut seed);

    eprintln!("Step 2: wrap with biometric ACL (BiometryAny | Or | DevicePasscode)");
    // Force the env var ON for THIS process so wrap_seed applies the ACL.
    // SAFETY: we are in the only thread that reads the var, no observer race.
    unsafe { std::env::set_var("MINAMOTO_BIOMETRIC_ACL", "1") };
    let wrapped = match secure_enclave::wrap_seed(&test_label, &seed) {
        Ok(b) => b,
        Err(e) => {
            eprintln!();
            eprintln!("❌ wrap FAILED: {e:?}");
            eprintln!();
            eprintln!("This means SecKeyCreateRandomKey rejected the access control");
            eprintln!("on our ad-hoc-signed binary. Biometric ACL path is gated; we");
            eprintln!("must move to the password-encrypted (Phase-1) wallet design.");
            return Err(anyhow::anyhow!("biometric ACL rejected at key generation"));
        }
    };
    unsafe { std::env::remove_var("MINAMOTO_BIOMETRIC_ACL") };
    eprintln!("    OK — key created, seed wrapped ({} bytes ciphertext)", wrapped.len());
    eprintln!();

    eprintln!("Step 3: unwrap WITHOUT calling LAContext gate first.");
    eprintln!("        If the ACL is honored, macOS itself will prompt Touch ID.");
    eprintln!("        — Watch for the Touch ID dialog NOW —");
    eprintln!();
    let unwrap_result = secure_enclave::unwrap_seed(&test_label, &wrapped);

    // Clean up immediately, regardless of outcome — this is a test wallet.
    eprintln!();
    eprintln!("Step 4: cleanup test keychain item");
    let _ = secure_enclave::delete(&test_label);
    eprintln!("    OK — test item removed");
    eprintln!();

    match unwrap_result {
        Ok(decoded) => {
            let recovered: &[u8] = decoded.as_ref();
            if recovered == seed.as_slice() {
                eprintln!("✅ SUCCESS: biometric ACL works on this Mac.");
                eprintln!();
                eprintln!("   - The OS prompted Touch ID (or password) automatically at decrypt.");
                eprintln!("   - Decryption succeeded; round-trip seed matches.");
                eprintln!();
                eprintln!("   Implication: C1 in AUDIT.md can be CLOSED for free.");
                eprintln!("   We can apply the ACL by default to all new wallets.");
            } else {
                eprintln!("⚠ Unwrap returned data but it does NOT match the original seed.");
                eprintln!("  Something deeper is broken in our wrap/unwrap pipeline.");
            }
        }
        Err(e) => {
            eprintln!("❌ unwrap FAILED: {e:?}");
            eprintln!();
            eprintln!("Likely outcomes:");
            eprintln!("  -25293 (errSecAuthFailed): user denied/cancelled biometric.");
            eprintln!("  -25291 (errSecNotAvailable): no Touch ID enrolled / no sensor + no password.");
            eprintln!("  -34018 (errSecMissingEntitlement): ACL path is gated by entitlements.");
            eprintln!("  any other: see Apple's Security framework docs.");
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_migrate_v2(label: &str) -> Result<()> {
    let record = storage::load(label)?;
    if record.version == storage::CURRENT_VERSION {
        println!("Wallet '{label}' is already v{}. Nothing to do.", record.version);
        return Ok(());
    }
    eprintln!("==== Migrate '{label}' from v1 (SE-wrap) to v2 (password) ====");
    eprintln!();
    eprintln!("Touch ID is required ONCE to unwrap the legacy SE-protected seed.");
    eprintln!("Then choose a new password (≥ 8 chars). After this, every signing");
    eprintln!("operation will prompt for the password instead of relying on the");
    eprintln!("Keychain item. The SE key will be removed at the end.");
    eprintln!();
    let pw = read_new_password("New password")?;
    wallet::migrate_v1_to_v2(label, &pw)?;
    println!("OK — '{label}' migrated to v2 password-encrypted format.");
    println!("Future signing operations will prompt for this password.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_my_address(label: &str) -> Result<()> {
    let reason = format!("Generate v3 confidential payment address for '{label}'");
    let pw = read_password_for(label)?;
    let seed = wallet::unlock_seed(label, &reason, pw.as_deref().map(|s| s.as_str()))?;
    let mut spend_key = [0u8; 32];
    if seed.len() != 32 {
        anyhow::bail!("expected 32-byte seed, got {}", seed.len());
    }
    spend_key.copy_from_slice(&seed[..]);
    let addr = confidential_address::build_for_wallet(label, &spend_key)?;
    let uri = confidential_address::render(&addr)?;
    println!("====== Minamoto confidential payment address (v3) ======");
    println!();
    println!("{uri}");
    println!();
    println!("Owner tag:    {}", addr.shielded_owner_tag_hex);
    println!("Diversifier:  {}", addr.shielded_diversifier_hex);
    println!("Receive ID:   {}", addr.receive_key_id);
    println!();
    println!("Anyone can publish this URI on Twitter / a website / QR code.");
    println!("Senders use `minamoto-wallet pay-address <wallet> <uri> <amount>`");
    println!("to credit a confidential note to this address.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_pay_address(
    label: &str,
    recipient_address: &str,
    amount: &str,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        let outcome = shield::shield_dry_run(amount, recipient_address)?;
        println!("==== DRY RUN — no Touch ID, no signing, no tx submitted ====");
        println!();
        println!("Wallet (sender):   {label}");
        println!("Amount (XOR u128): {}", outcome.amount);
        println!();
        println!("Recipient owner_tag:    {}", outcome.recipient_owner_tag_hex);
        println!("Recipient diversifier:  {}", outcome.recipient_diversifier_hex);
        println!();
        println!("Commitment (would-be):  {}", outcome.commitment_hex);
        println!("Rho (random per call):  {}", outcome.rho_hex);
        println!();
        println!("Notes:");
        println!("  - Each invocation produces a new random rho, so the commitment");
        println!("    differs between dry-run and the real `pay-address` later.");
        println!("  - The recipient owner_tag/diversifier MUST be deterministic for");
        println!("    a given v3 URI. If they don't match across runs, the URI is");
        println!("    being parsed inconsistently — that's a bug.");
        return Ok(());
    }
    let pw = read_password_for(label)?;
    let outcome = shield::shield(label, amount, Some(recipient_address), pw.as_deref().map(|s| s.as_str()))?;
    println!("OK — shielded {} XOR to external recipient.", outcome.amount);
    println!();
    println!("tx hash:    {}", outcome.tx_hash_hex);
    println!("commitment: {}", outcome.commitment_hex);
    println!("rho:        {}", outcome.rho_hex);
    println!();
    println!("⚠  PHASE 1 LIMITATION — share the `rho` with the recipient out-of-band");
    println!("    (DM, Signal, etc.). Without it they cannot spend the note.");
    println!();
    println!("Verify on chain:");
    println!("  https://sorametrics.org/minamoto#tx/{}", outcome.tx_hash_hex);
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_mark_registered(label: &str) -> Result<()> {
    storage::mark_registered(label)
        .with_context(|| format!("failed to mark wallet '{label}' as registered"))?;
    println!("OK — '{label}' flagged as registered_on_chain=true (no chain action).");
    println!("Next transfer/shield will skip the auto-Register prepend.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_register_self(label: &str) -> Result<()> {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        ChainId,
        account::{AccountId, NewAccount},
        isi::{InstructionBox, Register},
    };
    use iroha_version::codec::EncodeVersioned;

    let record = storage::load(label)?;
    let chain_id = ChainId::from(consts::CHAIN_ID);

    let reason = format!("Self-register account {label} on Minamoto");
    let pw = read_password_for(label)?;
    let seed = wallet::unlock_seed(label, &reason, pw.as_deref().map(|s| s.as_str()))?;
    let pubkey = wallet::derive_public_key(&seed)?;
    let account_id = AccountId::new(pubkey.clone());

    eprintln!("[register-self] account_id: {}", record.i105_address);
    eprintln!("[register-self] building Register::Account ISI...");

    let new_account = NewAccount::new(account_id.clone());
    let register: InstructionBox = Register::account(new_account).into();

    let builder = iroha_data_model::transaction::TransactionBuilder::new(
        chain_id,
        account_id.clone(),
    )
    .with_instructions([register]);

    let kp = KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519);
    let (_pk, sk) = kp.into_parts();
    let signed = builder.sign(&sk);

    let body: Vec<u8> = signed.encode_versioned();
    let tx_hash_hex = hex::encode(signed.hash().as_ref());
    eprintln!("[register-self] submitting tx {tx_hash_hex} ({} bytes)", body.len());

    let (status, resp) = torii::submit_transaction(body)?;
    eprintln!("[register-self] HTTP {status} ({} bytes resp)", resp.len());

    eprintln!("[register-self] waiting for tx to be Committed...");
    match torii::wait_for_commit(&tx_hash_hex, 60) {
        Ok((s, _reason)) if s == "Committed" => {
            storage::mark_registered(label).with_context(|| {
                format!("failed to persist registered_on_chain for '{label}'")
            })?;
            println!("OK — Register::Account Committed. tx hash: {tx_hash_hex}");
            println!("Local wallet '{label}' marked registered_on_chain=true.");
        }
        Ok((s, reason)) => {
            println!("Tx settled with status={s} reason={reason:?}");
            println!("tx hash: {tx_hash_hex}");
            println!("Local flag NOT updated. Inspect on chain:");
            println!("  https://minamoto.sora.org/v1/explorer/transactions/{tx_hash_hex}");
        }
        Err(e) => {
            println!("Could not confirm tx status within timeout ({e}).");
            println!("tx hash: {tx_hash_hex}");
            println!("Local flag NOT updated. If you later confirm Committed, run:");
            println!("  minamoto-wallet mark-registered {label}");
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_dump_client_toml(label: &str) -> Result<()> {
    let reason = format!("DEBUG: dump iroha client.toml for {label}");
    let pw = read_password_for(label)?;
    let seed = wallet::unlock_seed(label, &reason, pw.as_deref().map(|s| s.as_str()))?;
    let record = storage::load(label)?;
    let pk_hex = record.public_key_hex.trim_start_matches("ed0120").to_uppercase();
    let sk_hex = hex::encode(&*seed).to_uppercase();

    eprintln!();
    eprintln!("==== iroha client.toml (paste into a file) ====");
    eprintln!();
    println!("chain = \"00000000-0000-0000-0000-000000000000\"");
    println!("torii_url = \"https://minamoto.sora.org/\"");
    println!();
    println!("[account]");
    // The CLI's Account config requires `domain` even though I105 is purely
    // pubkey-derived. Minamoto exposes `wonderland.universal` and other
    // domains; we pick `wonderland.universal` because it's the canonical
    // sample default. The chain_discriminant=753 is what we observed
    // empirically for Minamoto and matches consts::NETWORK_PREFIX.
    println!("domain = \"wonderland.universal\"");
    println!("public_key = \"ed0120{pk_hex}\"");
    println!("private_key = \"802620{sk_hex}\"");
    println!("chain_discriminant = {}", crate::consts::NETWORK_PREFIX);
    eprintln!();
    eprintln!("==== End ====");
    eprintln!();
    eprintln!("Your I105 (for reference): {}", record.i105_address);
    eprintln!();
    eprintln!("DELETE the file after use. The seed is in plaintext.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_shield(label: &str, amount: &str) -> Result<()> {
    let pw = read_password_for(label)?;
    let outcome = shield::shield(label, amount, None, pw.as_deref().map(|s| s.as_str()))?;
    println!("OK — shielded {} XOR (def {})", outcome.amount, outcome.asset_def_id);
    println!("tx hash:    {}", outcome.tx_hash_hex);
    println!("commitment: {}", outcome.commitment_hex);
    println!();
    println!("Local note record persisted; required to spend later.");
    println!("Verify on chain:");
    println!("  https://sorametrics.org/minamoto#tx/{}", outcome.tx_hash_hex);
    Ok(())
}

fn cmd_zk_stub(op: &str, label: &str, amount: &str) -> Result<()> {
    eprintln!("==== ZK {op} not implemented ====");
    eprintln!("Args: label={label} amount={amount}");
    eprintln!();
    eprintln!("Why: producing a Halo2-IPA proof that Minamoto's executor accepts");
    eprintln!("requires several pieces that we haven't pinned down yet:");
    eprintln!("  - exact Poseidon parameters used by the XOR note scheme;");
    eprintln!("  - viewing-key derivation (likely separate from the Ed25519 wallet seed);");
    eprintln!("  - Merkle commitment of the shielded ledger to query the path against;");
    eprintln!("  - shipped proving keys (~100-500 MB) for shield/unshield circuits.");
    eprintln!();
    eprintln!("See ZK_ROADMAP.md (next to WALLET_DESIGN.md) for the implementation plan");
    eprintln!("ordered by difficulty.");
    anyhow::bail!("ZK {op} not implemented yet")
}

#[cfg(target_os = "macos")]
fn cmd_send_xor(label: &str, to: &str, amount: &str) -> Result<()> {
    let pw = read_password_for(label)?;
    let tx_hash = transfer::send_xor(label, to, amount, pw.as_deref().map(|s| s.as_str()))?;
    println!("OK — submitted tx hash: {tx_hash}");
    println!("Verify on chain:");
    println!("  https://sorametrics.org/minamoto#tx/{tx_hash}");
    println!("  https://minamoto.sora.org/v1/explorer/transactions/{tx_hash}");
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_unlock_test(label: &str) -> Result<()> {
    let reason = format!("Smoke-test unlock of wallet '{label}'");
    let pw = read_password_for(label)?;
    let seed = wallet::unlock_seed(label, &reason, pw.as_deref().map(|s| s.as_str()))?;
    println!("OK — seed unwrapped successfully ({} bytes)", seed.len());
    println!("(seed bytes intentionally NOT printed; this only verifies the Touch ID flow)");
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_generate(label: &str) -> Result<()> {
    eprintln!("Choose a password (≥ 8 chars) to encrypt the new wallet's seed.");
    eprintln!("This password is required EVERY signing operation. Pick something");
    eprintln!("you can remember; losing it makes the wallet unrecoverable from");
    eprintln!("disk (the BIP39 mnemonic — printed below — is the only fallback).");
    eprintln!();
    let pw = read_new_password("Password")?;
    let w = wallet::generate(label, &pw).context("wallet::generate failed")?;
    print_wallet_summary(&w, /* show_mnemonic = */ true);
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_restore(label: &str) -> Result<()> {
    eprintln!(
        "Paste your 24-word BIP39 mnemonic and press Ctrl-D when done.\nThe phrase will NOT be echoed:"
    );
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .context("failed to read mnemonic from stdin")?;
    eprintln!();
    eprintln!("Now choose a password to encrypt the restored seed (≥ 8 chars).");
    let pw = read_new_password("Password")?;
    let w = wallet::restore_from_mnemonic(label, &buf, &pw).context("wallet::restore failed")?;
    print_wallet_summary(&w, /* show_mnemonic = */ false);
    Ok(())
}

fn cmd_pubkey(label: &str) -> Result<()> {
    let (pubkey, i105) = wallet::pubkey_and_address(label)?;
    println!("label:       {label}");
    println!("public_key:  {pubkey}");
    println!("i105:        {i105}");
    Ok(())
}

fn cmd_delete(label: &str) -> Result<()> {
    wallet::delete(label)?;
    println!("Deleted wallet '{label}' from Keychain.");
    Ok(())
}

fn print_wallet_summary(w: &wallet::GeneratedWallet, show_mnemonic: bool) {
    println!("====== MINAMOTO WALLET CREATED ======");
    println!("label:       {}", w.label);
    println!("public_key:  {}", w.public_key_hex);
    println!("i105:        {}", w.i105_address);
    println!();
    if show_mnemonic {
        println!("====== BIP39 MNEMONIC — WRITE THIS ON PAPER, NEVER STORE DIGITALLY ======");
        println!();
        println!("{}", &*w.mnemonic);
        println!();
        println!("If you lose this phrase AND the Keychain item is destroyed (Mac wipe,");
        println!("biometric set invalidation, etc.), the wallet is permanently lost.");
        println!("There is no recovery path other than this mnemonic.");
    }
}
