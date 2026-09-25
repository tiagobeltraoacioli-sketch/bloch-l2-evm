// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end offline ceremony using disposable test keys and the real native
//! binary. No production registry, signer key or chain endpoint is used.
use bloch_component_checkpoint::{hash, Registry, Signer};
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn run(program: &str, args: &[&str]) -> Output {
    Command::new(program).args(args).output().unwrap()
}
fn success(out: Output) -> Value {
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}
fn put(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn distributed_adapters_prepare_sign_assemble_and_verify_real_hybrid_signatures() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let root = std::env::temp_dir().join(format!("component-ceremony-test-{}-{now}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let _cleanup = Scratch(root.clone());
    let keys: Vec<_> = (0..3).map(|_| bloch_crypto::crypto::generate_keypair()).collect();
    let registry = Registry {
        version: 1,
        id: "test-only-disposable".into(),
        threshold: 2,
        min_external: 1,
        valid_from: now - 10,
        valid_until: now + 86400,
        signers: keys
            .iter()
            .enumerate()
            .map(|(i, (pk, _))| Signer {
                id: format!("test-{i}"),
                external: i == 2,
                public_key: hex::encode(pk),
            })
            .collect(),
    };
    let registry_path = root.join("registry.json");
    put(&registry_path, &registry);
    for (i, (_, sk)) in keys.iter().enumerate() {
        let p = root.join(format!("test-{i}.sk"));
        fs::write(&p, hex::encode(sk)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let binary = env!("CARGO_BIN_EXE_bloch-component-checkpoint");
    let binary_pin = hash(&fs::read(binary).unwrap());
    let source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/component-checkpoint.py")).unwrap();
    for component in ["l2", "dex", "bridge"] {
        let dir = root.join(component);
        fs::create_dir(&dir).unwrap();
        let adapter = dir.join("adapter.py");
        fs::write(
            &adapter,
            source.replace("COMPONENT = 'l2'", &format!("COMPONENT = '{component}'")),
        )
        .unwrap();
        fs::write(dir.join("build.txt"), b"synthetic test artifact").unwrap();
        put(
            &dir.join("config.json"),
            &json!({"synthetic": true, "component": component}),
        );
        put(
            &dir.join("header.json"),
            &json!({"height": 123, "hash": hash(b"test-block"), "state_root": hash(b"test-state")}),
        );
        let manifest = success(run(
            "python3",
            &[
                adapter.to_str().unwrap(),
                "manifest",
                "--root",
                dir.to_str().unwrap(),
                "--file",
                "build.txt",
            ],
        ));
        put(&dir.join("artifacts.json"), &manifest);
        let ceremony = dir.join("ceremony");
        let mut prepare = vec![
            adapter.to_str().unwrap().to_owned(),
            "prepare".into(),
            "--root".into(),
            dir.to_str().unwrap().into(),
            "--verifier".into(),
            binary.into(),
            "--verifier-sha3".into(),
            binary_pin.clone(),
            "--registry".into(),
            registry_path.to_str().unwrap().into(),
            "--configuration".into(),
            dir.join("config.json").to_str().unwrap().into(),
            "--artifacts".into(),
            dir.join("artifacts.json").to_str().unwrap().into(),
            "--chain-id".into(),
            "eip155:8453".into(),
            "--genesis".into(),
            hash(b"test-genesis"),
            "--finalized-header".into(),
            dir.join("header.json").to_str().unwrap().into(),
            "--sequence".into(),
            "1".into(),
            "--previous".into(),
            "00".repeat(32),
            "--lifetime-seconds".into(),
            "3600".into(),
            "--output".into(),
            ceremony.to_str().unwrap().into(),
        ];
        let result = success(run("python3", &prepare.iter().map(String::as_str).collect::<Vec<_>>()));
        assert_eq!(result["signatures"], 0);
        assert_eq!(result["checkpoint_verified"], false);
        // A ceremony is create-once: an accidental retry cannot replace it.
        assert!(!run("python3", &prepare.iter().map(String::as_str).collect::<Vec<_>>())
            .status
            .success());
        for i in [0, 2] {
            let signature = success(run(
                binary,
                &[
                    "sign",
                    registry_path.to_str().unwrap(),
                    ceremony.join("payload.json").to_str().unwrap(),
                    root.join(format!("test-{i}.sk")).to_str().unwrap(),
                    &format!("test-{i}"),
                ],
            ));
            put(&ceremony.join(format!("signature-{i}.json")), &signature);
        }
        let env = success(run(
            binary,
            &[
                "assemble",
                registry_path.to_str().unwrap(),
                ceremony.join("payload.json").to_str().unwrap(),
                ceremony.join("signature-0.json").to_str().unwrap(),
                ceremony.join("signature-2.json").to_str().unwrap(),
            ],
        ));
        put(&ceremony.join("envelope.json"), &env);
        prepare = vec![
            adapter.to_str().unwrap().into(),
            "verify".into(),
            "--root".into(),
            dir.to_str().unwrap().into(),
            "--verifier".into(),
            binary.into(),
            "--verifier-sha3".into(),
            binary_pin.clone(),
            "--registry".into(),
            registry_path.to_str().unwrap().into(),
            "--configuration".into(),
            dir.join("config.json").to_str().unwrap().into(),
            "--artifacts".into(),
            dir.join("artifacts.json").to_str().unwrap().into(),
            "--envelope".into(),
            ceremony.join("envelope.json").to_str().unwrap().into(),
            "--trust".into(),
            ceremony.join("trust.pending.json").to_str().unwrap().into(),
            "--trust-sha3".into(),
            result["trust_pending_sha3"].as_str().unwrap().into(),
        ];
        let valid = success(run("python3", &prepare.iter().map(String::as_str).collect::<Vec<_>>()));
        assert_eq!(valid["checkpoint_verified"], true);
        assert_eq!(valid["activation_authorized"], false);
        assert_eq!(valid["component"], component);
        // File hashes, not a saved success report, decide each subsequent review.
        fs::write(dir.join("build.txt"), b"tampered after signing").unwrap();
        assert!(!run("python3", &prepare.iter().map(String::as_str).collect::<Vec<_>>())
            .status
            .success());
        fs::write(dir.join("build.txt"), b"synthetic test artifact").unwrap();
        let last = prepare.len() - 1;
        prepare[last] = "00".repeat(32);
        assert!(!run("python3", &prepare.iter().map(String::as_str).collect::<Vec<_>>())
            .status
            .success());
    }
}
