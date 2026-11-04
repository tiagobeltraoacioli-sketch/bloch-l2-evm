use alloy_primitives::B256;
use bloch_l2_evm::{
    native_settlement::SettlementExpectationV1,
    native_settlement::{SettlementTransactionV1, SettlementWireFormat, NATIVE_SETTLEMENT_BYTES},
};
const TX: &[u8] = include_bytes!("fixtures/native-settlement/transaction.bin");
#[test]
fn native_envelope_is_exact_and_legacy_codec_remains_distinct() {
    assert_eq!(TX.len(), NATIVE_SETTLEMENT_BYTES);
    let (tx, format) = SettlementTransactionV1::decode_wire(TX).unwrap();
    assert_eq!(format, SettlementWireFormat::NativeV1);
    assert_eq!(tx.encode_wire(format), TX);
    assert!(SettlementTransactionV1::decode(TX).is_err());
    let (legacy, format) = SettlementTransactionV1::decode_wire(&tx.encode()).unwrap();
    assert_eq!(format, SettlementWireFormat::ExperimentalV1);
    assert_eq!(legacy.commitment(), tx.commitment());
    for len in 0..TX.len() {
        assert!(SettlementTransactionV1::decode_wire(&TX[..len]).is_err());
    }
    let mut suffix = TX.to_vec();
    suffix.push(0);
    assert!(SettlementTransactionV1::decode_wire(&suffix).is_err());
    let mut bad = TX.to_vec();
    bad[0] = 0x0f;
    assert!(SettlementTransactionV1::decode_wire(&bad).is_err());
    let mut nonempty = *tx.statement();
    nonempty.inbox_count = 1;
    let forged = SettlementTransactionV1::new(tx.proof_policy(), nonempty, [9; 356])
        .unwrap()
        .encode_wire(SettlementWireFormat::NativeV1);
    assert!(SettlementTransactionV1::decode_wire(&forged).is_err());
}
#[test]
fn native_source_digest_is_rederived_before_proof_verification() {
    use bloch_l2_evm::native_settlement::{
        SettlementError, SettlementPolicyV1, SettlementProofVerifierV1, SettlementRegistryV1,
    };
    struct Never;
    impl SettlementProofVerifierV1 for Never {
        fn verify(&self, _: B256, _: &[u8], _: &[u8]) -> bool {
            panic!("invalid source reached pairing")
        }
    }
    let (tx, _) = SettlementTransactionV1::decode_wire(TX).unwrap();
    let s = tx.statement();
    let p = SettlementPolicyV1 {
        network: s.network,
        genesis: s.genesis,
        domain: s.domain,
        configuration: s.configuration,
        program_elf_keccak: s.program_elf_keccak,
        program_vkey_koalabear: s.program_vkey_koalabear,
        program_vkey_bn254: s.program_vkey_bn254,
        proof_policy: tx.proof_policy(),
        chain_id: s.chain_id,
        first_l2_number: 1,
        initial_l2_parent_hash: s.l2_parent_hash,
        initial_l2_state_root: s.l2_previous_state_root,
    };
    let mut registry = SettlementRegistryV1::new(p).unwrap();
    let before = registry.state_commitment();
    let mut changed = TX.to_vec();
    changed[33 + 22 + 448] ^= 1;
    let statement = *SettlementTransactionV1::decode_wire(&changed).unwrap().0.statement();
    assert!(matches!(
        registry.verify_and_apply(
            &changed,
            &SettlementExpectationV1 {
                statement,
                source_predecessor: B256::ZERO
            },
            &Never
        ),
        Err(SettlementError::Transition)
    ));
    assert_eq!(registry.state_commitment(), before);
}
