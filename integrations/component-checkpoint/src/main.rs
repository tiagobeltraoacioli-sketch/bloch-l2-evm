// SPDX-License-Identifier: AGPL-3.0-or-later
use bloch_component_checkpoint::*;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    env,
    fs::File,
    io::{Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

fn bytes(path: &str) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    File::open(path)
        .map_err(|_| "cannot open input")?
        .take((MAX_DOCUMENT + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| "cannot read input")?;
    if raw.len() > MAX_DOCUMENT {
        return Err("input exceeds 1 MiB".into());
    }
    Ok(raw)
}
fn json<T: DeserializeOwned>(path: &str) -> Result<T> {
    serde_json::from_slice(&bytes(path)?).map_err(|_| "invalid strict input schema".into())
}
fn output<T: Serialize>(value: &T) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value).map_err(|_| "cannot write result")?;
    stdout.write_all(b"\n").map_err(|_| "cannot write result".into())
}
fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("registry-id") if args.len() == 2 => {
            let r: Registry = json(&args[1])?;
            output(&serde_json::json!({"registry_sha3": r.commitment()?}))
        }
        Some("prepare") if args.len() == 3 => {
            let r: Registry = json(&args[1])?;
            let cp: Checkpoint = json(&args[2])?;
            cp.commitment(&r)?;
            output(&Envelope { checkpoint: cp, signatures: vec![] })
        }
        Some("sign") if args.len() == 5 => {
            let r: Registry = json(&args[1])?;
            let cp: Checkpoint = json(&args[2])?;
            // A holder supplies their own local file. Never accept a secret in argv.
            let file = File::open(&args[3]).map_err(|_| "cannot open private key file")?;
            let meta = file.metadata().map_err(|_| "cannot inspect private key file")?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
                    return Err("private key must be a regular owner-only file".into());
                }
            }
            let mut raw = Zeroizing::new(String::new());
            file.take(32_769).read_to_string(&mut raw).map_err(|_| "cannot read private key")?;
            if raw.len() > 32_768 { return Err("private key size limit".into()); }
            let key = Zeroizing::new(hex::decode(raw.trim()).map_err(|_| "private key must be hex")?);
            output(&sign(&r, &cp, &args[4], &key)?)
        }
        Some("assemble") if (5..=6).contains(&args.len()) => {
            let r: Registry = json(&args[1])?;
            let cp: Checkpoint = json(&args[2])?;
            cp.validate(&r)?;
            let signatures = args[3..].iter().map(|p| json(p)).collect::<Result<Vec<DetachedSignature>>>()?;
            // Assembly does not claim verification. The pinned trust gate is mandatory.
            output(&Envelope { checkpoint: cp, signatures })
        }
        Some("verify") if args.len() == 5 => {
            let r: Registry = json(&args[1])?;
            let env: Envelope = json(&args[2])?;
            let raw = bytes(&args[3])?;
            if hash(&raw) != args[4] { return Err("independent trust-file SHA3 pin mismatch".into()); }
            let trust: Trust = serde_json::from_slice(&raw).map_err(|_| "invalid trust schema")?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "invalid clock")?.as_secs();
            output(&verify(&r, &env, &trust, now)?)
        }
        _ => Err("usage: bloch-component-checkpoint registry-id REGISTRY | prepare REGISTRY PAYLOAD | sign REGISTRY PAYLOAD PRIVATE_KEY_HEX_FILE SIGNER_ID | assemble REGISTRY PAYLOAD SIGNATURE SIGNATURE [SIGNATURE] | verify REGISTRY ENVELOPE TRUST TRUST_FILE_SHA3".into()),
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("checkpoint refused: {error}");
        std::process::exit(1);
    }
}
