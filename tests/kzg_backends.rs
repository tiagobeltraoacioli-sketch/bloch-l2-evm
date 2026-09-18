//! Run identically with defaults (c-kzg) and --no-default-features (arkworks).
use alloy_primitives::hex;
use revm::precompile::{
    kzg_point_evaluation::{kzg_to_versioned_hash, ADDRESS, GAS_COST},
    PrecompileHalt, PrecompileOutput, PrecompileStatus, Precompiles,
};

fn execute(input: &[u8], gas: u64) -> PrecompileOutput {
    // Exercise the registered Cancun precompile, not just a backend helper:
    // accidentally dropping 0x0a must fail this test even if a helper still works.
    Precompiles::cancun()
        .get(&ADDRESS)
        .expect("Cancun must register point evaluation with either backend")
        .execute(input, gas, 0)
        .unwrap()
}

fn input(commitment: [u8; 48], z: [u8; 32], y: [u8; 32], proof: [u8; 48]) -> Vec<u8> {
    [
        kzg_to_versioned_hash(&commitment).as_slice(),
        &z,
        &y,
        &commitment,
        &proof,
    ]
    .concat()
}

fn nontrivial_vector() -> Vec<u8> {
    // Ethereum c-kzg-4844 verify_kzg_proof_case_correct_proof_4_4, also
    // embedded in the pinned revm-precompile 41.0.0 distribution.
    input(
        hex!("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7"),
        hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
        hex!("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9"),
        hex!("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c"),
    )
}

fn assert_success(input: &[u8]) {
    let output = execute(input, GAS_COST);
    assert_eq!(output.status, PrecompileStatus::Success);
    assert_eq!(output.gas_used, 50_000);
    assert_eq!(output.bytes.as_ref(), &hex!("000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"));
}

#[test]
fn cancun_accepts_nontrivial_proof_and_zero_polynomial() {
    assert_success(&nontrivial_vector());
    let mut infinity = [0; 48];
    infinity[0] = 0xc0;
    assert_success(&input(infinity, [0; 32], [0; 32], infinity));
}

#[test]
fn cancun_rejects_altered_evaluation_proof_and_noncanonical_scalar() {
    let valid = nontrivial_vector();
    for offset in [95, 191] {
        let mut altered = valid.clone();
        altered[offset] ^= 1;
        assert_eq!(
            execute(&altered, GAS_COST).status,
            PrecompileStatus::Halt(PrecompileHalt::BlobVerifyKzgProofFailed)
        );
    }
    let modulus = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let mut infinity = [0; 48];
    infinity[0] = 0xc0;
    for scalar_start in [32, 64] {
        // For the zero polynomial, silently reducing modulus to zero would
        // accept; require canonical field elements instead.
        let mut altered = input(infinity, [0; 32], [0; 32], infinity);
        altered[scalar_start..scalar_start + 32].copy_from_slice(&modulus);
        assert_eq!(
            execute(&altered, GAS_COST).status,
            PrecompileStatus::Halt(PrecompileHalt::BlobVerifyKzgProofFailed)
        );
    }
}

#[test]
fn cancun_checks_hash_length_and_gas() {
    let valid = nontrivial_vector();
    let mut wrong_hash = valid.clone();
    wrong_hash[0] = 2;
    assert_eq!(
        execute(&wrong_hash, GAS_COST).status,
        PrecompileStatus::Halt(PrecompileHalt::BlobMismatchedVersion)
    );
    assert_eq!(
        execute(&valid[..191], GAS_COST).status,
        PrecompileStatus::Halt(PrecompileHalt::BlobInvalidInputLength)
    );
    assert_eq!(
        execute(&valid, GAS_COST - 1).status,
        PrecompileStatus::Halt(PrecompileHalt::OutOfGas)
    );
}

#[test]
fn cancun_matches_complete_pinned_ethereum_verification_corpus() {
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/kzg/verify_kzg_proof.json")).unwrap();
    assert_eq!(cases.len(), 122);
    for case in cases {
        let decode = |field: &str| alloy_primitives::hex::decode(case["input"][field].as_str().unwrap()).unwrap();
        let commitment = decode("commitment");
        let encoded = [
            kzg_to_versioned_hash(&commitment).to_vec(),
            decode("z"),
            decode("y"),
            commitment,
            decode("proof"),
        ]
        .concat();
        let result = execute(&encoded, GAS_COST);
        let expected = if encoded.len() != 192 {
            PrecompileStatus::Halt(PrecompileHalt::BlobInvalidInputLength)
        } else if case["output"] == true {
            PrecompileStatus::Success
        } else {
            // The C API distinguishes false from invalid-encoding null;
            // the EVM maps both to a failed point-evaluation precompile.
            PrecompileStatus::Halt(PrecompileHalt::BlobVerifyKzgProofFailed)
        };
        assert_eq!(result.status, expected, "{}", case["name"]);
        if case["output"] == true {
            assert_success(&encoded);
        }
    }
}
