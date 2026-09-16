//! Offline Genesis-4 body verification against a separately trusted checkpoint.
//! Usage: verify_l1_body BODY.json TRUSTED_BLOCK_ID TRUSTED_SLOT
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::l1::{authenticate_body, FinalizedCheckpoint};
use serde_json::Value;
use std::{io::Read, str::FromStr};

fn decode(value: &Value) -> Result<Bytes, String> {
    let s = value.as_str().ok_or("Expected hex string")?;
    if !s.is_ascii() || s.len() % 2 != 0 {
        return Err("Invalid hexadecimal encoding".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "Invalid hexadecimal encoding".to_string()))
        .collect::<Result<Vec<_>, _>>()
        .map(Into::into)
}
fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("Usage: verify_l1_body BODY.json TRUSTED_BLOCK_ID TRUSTED_SLOT".into());
    }
    let checkpoint = FinalizedCheckpoint {
        block: B256::from_str(&args[2]).map_err(|_| "Invalid trusted block ID")?,
        slot: args[3].parse().map_err(|_| "Invalid trusted slot")?,
    };
    // Bound reads before JSON/hex allocation, including for streams/special files.
    const MAX_FILE: u64 = 40 * 1024 * 1024;
    let mut raw = Vec::new();
    std::fs::File::open(&args[1])
        .map_err(|_| "Cannot open body file")?
        .take(MAX_FILE + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "Cannot read body file")?;
    if raw.len() as u64 > MAX_FILE {
        return Err("Body file exceeds 40 MiB".into());
    }
    let input: Value = serde_json::from_slice(&raw).map_err(|_| "Invalid JSON")?;
    let headers = input["headers"].as_array().ok_or("Missing headers array")?;
    let transactions = input["transactions"].as_array().ok_or("Missing transactions array")?;
    if headers.len() > 2048 || transactions.len() > 4096 {
        return Err("Array count limit exceeded".into());
    }
    let headers = headers.iter().map(decode).collect::<Result<Vec<_>, _>>()?;
    let transactions = transactions.iter().map(decode).collect::<Result<Vec<_>, _>>()?;
    let body = authenticate_body(checkpoint, &headers, &transactions)
        .map_err(|error| format!("Authentication failed: {error:?}"))?;
    println!("Authenticated block: {}", body.block());
    println!("Slot: {} (not block height)", body.slot());
    println!("Transactions: {}", body.transactions().len());
    println!("Ancestry and complete body verified against the supplied checkpoint.");
    println!("Checkpoint finality, escrow ownership and settlement are not established by this tool.");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
