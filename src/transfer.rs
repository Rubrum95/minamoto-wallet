// Build + sign + submit a Transfer ISI to send XOR on Minamoto.
//
// Verified API entry points from the local Iroha 3 source:
//
//   - iroha_data_model::isi::Transfer::asset_numeric(asset_id, qty, to)
//   - iroha_data_model::transaction::TransactionBuilder::new(chain_id, authority)
//       .with_instructions([Transfer ISI])
//       .sign(&private_key)  → SignedTransaction
//   - iroha_version::EncodeVersioned::encode_versioned(&signed_tx)  → Vec<u8>
//   - POST {torii_base}/transaction  with Content-Type: application/x-norito

use crate::biometric;
use crate::consts::{CHAIN_ID, XOR_ASSET_DEFINITION_ID};
use crate::storage;
use crate::torii;
use crate::wallet;
use anyhow::{Context, Result, anyhow, bail};
use iroha_crypto::{Algorithm, KeyPair, PrivateKey, PublicKey};
use iroha_data_model::{
    ChainId,
    account::{AccountId, NewAccount},
    asset::{AssetDefinitionId, AssetId},
    isi::{InstructionBox, Register, Transfer},
};
use iroha_primitives::numeric::Numeric;
use iroha_version::codec::EncodeVersioned;
use std::str::FromStr;

/// Send `amount` XOR from the wallet identified by `label` to `recipient_i105`.
/// Returns the transaction hash (hex-encoded, 32 bytes).
///
/// Touch-ID / Keychain-auth gate fires inside `wallet::unlock_seed`. After
/// this, the seed lives in CPU RAM only for the duration of `.sign()`,
/// then drops with `Zeroizing` semantics.
pub fn send_xor(
    label: &str,
    recipient_i105: &str,
    amount_str: &str,
    password: Option<&str>,
) -> Result<String> {
    // -----------------------------------------------------------------
    // 1. Parse + validate inputs that don't need the seed yet.
    //    NOTE: we deliberately do NOT use `AccountId::parse_encoded`
    //    for our own `from` account. parse_encoded canonicalises through
    //    `address::chain_discriminant()` which produces an
    //    `AccountController` whose internal byte layout does not match
    //    the one stored on-chain when the operator's Mint::Asset created
    //    our balance. Verified empirically: the chain rejects with
    //    "Failed to find asset" when comparing the parsed AccountId
    //    against the stored one.
    //
    //    The reference path used by Iroha's own `implicit_account_receive`
    //    test (crates/iroha_core/tests/implicit_account_receive.rs:43-47)
    //    is `AccountId::new(public_key)` — so we replicate that by
    //    deriving the public key from the seed (after Touch ID).
    // -----------------------------------------------------------------
    let record = storage::load(label)?;
    let from_i105 = &record.i105_address;

    let to_account: AccountId = AccountId::parse_encoded(recipient_i105)
        .map(|p| p.into_account_id())
        .map_err(|e| anyhow!("invalid recipient I105 ({recipient_i105}): {e:?}"))?;

    let xor_def: AssetDefinitionId = AssetDefinitionId::parse_address_literal(XOR_ASSET_DEFINITION_ID)
        .map_err(|e| anyhow!("can't parse XOR asset definition id: {e:?}"))?;

    let amount: Numeric = Numeric::from_str(amount_str)
        .map_err(|e| anyhow!("invalid amount '{amount_str}': {e:?}"))?;
    if amount.is_zero() {
        bail!("amount must be > 0");
    }

    let chain_id = ChainId::from(CHAIN_ID);

    // -----------------------------------------------------------------
    // 2. Touch-ID / Keychain gate + derive AccountId from the seed.
    // -----------------------------------------------------------------
    let reason = format!(
        "Send {} XOR from {} to {}",
        amount_str,
        short(from_i105),
        short(recipient_i105)
    );
    let seed = wallet::unlock_seed(label, &reason, password)?;

    let pubkey = wallet::derive_public_key(&seed)?;
    let from_account = AccountId::new(pubkey.clone());
    let from_asset = AssetId::new(xor_def.clone(), from_account.clone());

    // -- DEBUG: compare both AccountId paths byte-for-byte --
    let parsed_account = AccountId::parse_encoded(from_i105)
        .map(|p| p.into_account_id())
        .map_err(|e| anyhow!("re-parse i105 failed: {e:?}"))?;

    use norito::codec::Encode;
    let from_new_bytes = from_account.encode();
    let from_parsed_bytes = parsed_account.encode();

    eprintln!("[debug] from_account (via new)    encoded = {}",
              hex::encode(&from_new_bytes));
    eprintln!("[debug] from_account (via parse)  encoded = {}",
              hex::encode(&from_parsed_bytes));
    eprintln!("[debug] equal? {}", from_new_bytes == from_parsed_bytes);
    eprintln!("[debug] eq op?  {}", from_account == parsed_account);

    let asset_new_bytes = from_asset.encode();
    let asset_via_parsed = AssetId::new(xor_def.clone(), parsed_account.clone());
    let asset_parsed_bytes = asset_via_parsed.encode();
    eprintln!("[debug] from_asset (via new)    encoded = {}",
              hex::encode(&asset_new_bytes));
    eprintln!("[debug] from_asset (via parse)  encoded = {}",
              hex::encode(&asset_parsed_bytes));

    // -----------------------------------------------------------------
    // 3. Build instruction list. If this account hasn't been formally
    //    registered on-chain yet, prepend a Register::Account ISI in the
    //    same atomic tx — implicit accounts (those created by the
    //    operator's cross-chain Mint) cannot spend until they execute a
    //    Register::Account at least once. Doing it as the FIRST ISI in
    //    the transfer tx means the user only pays one signature/Touch ID
    //    instead of having to call `register-self` separately.
    // -----------------------------------------------------------------
    // Source-of-truth check: ask the chain directly whether our
    // account is registered. The local `registered_on_chain` flag is
    // a hint we use when offline, but it can drift (manual
    // mark-registered, migration carry-over, etc.). The chain answer
    // is authoritative. If the lookup itself fails (network,
    // explorer down), fall back to the local flag rather than block
    // the user — a duplicate Register would be rejected by the chain
    // anyway, costing only the gas for a Rejected tx.
    let needs_register = match torii::account_exists(from_i105) {
        Ok(true) => {
            // If the chain says yes but our local flag was false,
            // sync it forward so subsequent ops skip this lookup.
            if !record.registered_on_chain {
                let _ = storage::mark_registered(label);
                eprintln!("[transfer] chain confirms account is registered; updated local flag");
            }
            false
        }
        Ok(false) => {
            eprintln!("[transfer] chain reports account NOT registered — prepending Register::Account");
            true
        }
        Err(e) => {
            eprintln!("[transfer] couldn't check chain registration ({e}); using local flag");
            !record.registered_on_chain
        }
    };
    let mut instructions: Vec<InstructionBox> = Vec::with_capacity(2);
    if needs_register {
        let new_account = NewAccount::new(from_account.clone());
        instructions.push(Register::account(new_account).into());
    }
    let transfer = Transfer::asset_numeric(from_asset, amount.clone(), to_account.clone());
    instructions.push(transfer.into());

    let builder = iroha_data_model::transaction::TransactionBuilder::new(
        chain_id,
        from_account.clone(),
    )
    .with_instructions(instructions);

    // PrivateKey is ZeroizeOnDrop so the SK clears at scope end.
    let kp = KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519);
    let (_pk, sk): (PublicKey, PrivateKey) = kp.into_parts();
    let signed = builder.sign(&sk);

    // -----------------------------------------------------------------
    // 4. Norito-encode + POST to Torii. If we prepended Register, wait
    //    for the tx to settle so we can flip `registered_on_chain` only
    //    when the chain has actually accepted it. Optimistically marking
    //    before the next block closes would silently break recovery if
    //    the tx ended Rejected.
    // -----------------------------------------------------------------
    let body: Vec<u8> = signed.encode_versioned();
    let tx_hash_hex = hex::encode(signed.hash().as_ref());

    eprintln!("[transfer] submitting tx hash {tx_hash_hex} ({} bytes)", body.len());
    let (status, resp_bytes) = torii::submit_transaction(body)?;
    eprintln!(
        "[transfer] submission accepted (HTTP {status}, {} bytes response)",
        resp_bytes.len()
    );

    if needs_register {
        eprintln!("[transfer] waiting for tx to be Committed before marking wallet registered...");
        match torii::wait_for_commit(&tx_hash_hex, 60) {
            Ok((status, reason)) if status == "Committed" => {
                storage::mark_registered(label).with_context(|| {
                    format!("failed to persist registered_on_chain for '{label}'")
                })?;
                eprintln!(
                    "[transfer] tx Committed; wallet '{label}' marked registered_on_chain=true"
                );
                let _ = reason;
            }
            Ok((status, reason)) => {
                eprintln!(
                    "[transfer] tx settled with status={status} reason={reason:?} — NOT marking registered"
                );
            }
            Err(e) => {
                eprintln!(
                    "[transfer] could not confirm tx status ({e}); leaving registered_on_chain unchanged"
                );
            }
        }
    }

    Ok(tx_hash_hex)
}

/// Shorten an I105 string for display. We keep the first 8 chars after
/// the literal `sora` prefix and the last 6, so the user can visually
/// identify wallets without showing the full mojibake-katakana payload.
fn short(i105: &str) -> String {
    if i105.chars().count() <= 18 {
        return i105.to_string();
    }
    let chars: Vec<char> = i105.chars().collect();
    let head: String = chars.iter().take(10).collect();
    let tail: String = chars.iter().rev().take(6).collect::<String>().chars().rev().collect();
    format!("{head}…{tail}")
}
