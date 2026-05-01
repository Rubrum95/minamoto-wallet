// Print the asset balances held by a wallet, fetched live from Torii.
//
// We deliberately use the public `/v1/explorer/assets?owned_by=…` endpoint
// rather than `/v1/accounts/{id}/assets` because the explorer route always
// returns Numeric values pre-formatted in user units, while the accounts
// route returns raw scaled values that depend on `spec.scale` per asset.

use crate::consts::XOR_ASSET_DEFINITION_ID;
use crate::storage;
use crate::torii;
use anyhow::Result;

/// Print balances for the given wallet label. Output is plain text, one
/// asset per line, with XOR highlighted at the top.
pub fn print_balance(label: &str) -> Result<()> {
    let record = storage::load(label)?;
    let i105 = &record.i105_address;

    println!("wallet:  {} ({})", label, &record.public_key_hex[..28]);
    println!("address: {i105}");
    println!();

    let assets = torii::list_assets_for(i105)?;
    if assets.is_empty() {
        println!("(no assets — wallet hasn't received any tokens yet)");
        return Ok(());
    }

    let mut xor_line = None;
    let mut other_lines = Vec::new();

    for asset in &assets {
        // Asset id field carries `<def_id>#<account_id>` form. We split on
        // `#` to surface the definition id alone.
        let id = asset
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let def = id.split('#').next().unwrap_or("?");
        let value = asset
            .get("value")
            .and_then(|v| v.as_str())
            .or_else(|| asset.get("quantity").and_then(|v| v.as_str()))
            .unwrap_or("?");

        let line = format!("  {def:<32}  {value}");
        if def == XOR_ASSET_DEFINITION_ID {
            xor_line = Some(format!("  {} (XOR)  {value}", def));
        } else {
            other_lines.push(line);
        }
    }

    println!("balances:");
    if let Some(line) = xor_line {
        println!("{line}");
    }
    for line in other_lines {
        println!("{line}");
    }
    Ok(())
}
