// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real V2 storage with synthetic native provenance and an explicit proof double.
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{keccak256, Address, Signature, TxKind, B256};
use bloch_l2_evm::{
    native_settlement::{SettlementPolicyV1, SettlementTransactionV1, SETTLEMENT_PROOF_V1_BYTES},
    proof_statement::{configuration_commitment, SettlementStatementV2},
    ChainSpec, DepositMint, DepositProvenance,
};
use bloch_reth_execution::{
    prepare_genesis,
    settlement_binding::{with_canonical_settlement_audit, CanonicalSettlementAuditErrorV1},
    BlochChainSpec, BlochNextBlockEnvCtx, BlochProviderFactory, BlochTables, CanonicalCoordinator, ReplayFloor,
    ReplayLimits,
};
use k256::ecdsa::SigningKey;
use reth_chainspec::EthChainSpec;
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_db_api::transaction::DbTxMut;
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockIdReader, BlockReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
};
use std::{path::Path, sync::Arc};

fn h(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}
fn spec() -> Arc<BlochChainSpec> {
    Arc::new(BlochChainSpec::new(ChainSpec::testnet(), h(0xd3), 0).unwrap())
}
fn open(path: &Path) -> BlochProviderFactory {
    ProviderFactory::new(
        Arc::new(init_db_for::<_, BlochTables>(path.join("db"), DatabaseArguments::test()).unwrap()),
        spec(),
        StaticFileProvider::read_write(path.join("static")).unwrap(),
        RocksDBBuilder::new(path.join("rocks"))
            .with_default_tables()
            .build()
            .unwrap(),
        reth_tasks::Runtime::test(),
    )
    .unwrap()
}
fn attrs(number: u64) -> BlochNextBlockEnvCtx {
    BlochNextBlockEnvCtx {
        timestamp: number,
        prevrandao: B256::ZERO,
        anchor_root: h(22),
        deposits: vec![],
    }
}
fn seed(source: &BlochProviderFactory) {
    let genesis = prepare_genesis(&spec(), source.latest().unwrap().as_ref()).unwrap();
    let writer = source.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut coordinator = CanonicalCoordinator::attach(source.clone()).unwrap();
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    let mut funding = attrs(1);
    funding.deposits.push(DepositMint {
        recipient: sender,
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 70,
            l1_tx_index: 0,
            l1_txid: [22; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    });
    coordinator.extend(coordinator.head().hash(), funding, vec![]).unwrap();
    let tx = TxEip1559 {
        chain_id: ChainSpec::testnet().chain_id,
        to: TxKind::Call(sender),
        gas_limit: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        ..Default::default()
    };
    let signature: Signature = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    coordinator
        .extend(
            coordinator.head().hash(),
            attrs(2),
            vec![tx.into_signed(signature).into()],
        )
        .unwrap();
}
fn policy() -> SettlementPolicyV1 {
    let spec = spec();
    SettlementPolicyV1 {
        network: h(1),
        genesis: h(2),
        domain: spec.domain(),
        configuration: configuration_commitment(spec.execution()).unwrap(),
        program_elf_keccak: h(5),
        program_vkey_koalabear: h(6),
        program_vkey_bn254: h(7),
        proof_policy: h(8),
        chain_id: spec.execution().chain_id,
        first_l2_number: 1,
        initial_l2_parent_hash: spec.genesis_hash(),
        initial_l2_state_root: spec.genesis_header().0.state_root,
    }
}
fn floor(source: &BlochProviderFactory) -> ReplayFloor {
    ReplayFloor {
        number: 2,
        hash: source.sealed_header(2).unwrap().unwrap().hash(),
    }
}
/// One settlement per canonical block, chained by commitment. The transactions
/// are synthetic: this boundary checks correspondence, not the proof.
fn history(source: &BlochProviderFactory, wrong_first_body: bool) -> Vec<SettlementTransactionV1> {
    let p = policy();
    let mut transactions: Vec<SettlementTransactionV1> = vec![];
    for number in 1..=2 {
        let block = source.block_by_number(number).unwrap().unwrap();
        let header = &block.header.0;
        let statement = SettlementStatementV2 {
            network: p.network,
            genesis: p.genesis,
            domain: p.domain,
            configuration: p.configuration,
            program_elf_keccak: p.program_elf_keccak,
            program_vkey_koalabear: p.program_vkey_koalabear,
            program_vkey_bn254: p.program_vkey_bn254,
            previous_settlement: transactions.last().map_or(B256::ZERO, |tx| tx.commitment()),
            chain_id: p.chain_id,
            l2_number: number,
            l2_parent_hash: header.parent_hash,
            l2_previous_state_root: header.parent_state_root,
            l2_header_hash: header.hash(),
            l2_state_root: header.state_root,
            l1_block: header.anchor_root,
            l1_slot: 80,
            l1_height: 70,
            source_commitment: h(23),
            inbox_root: h(24),
            inbox_count: 1,
            consumed_start: number - 1,
            consumed_end: 1,
            body_commitment: if number == 1 && wrong_first_body {
                h(99)
            } else {
                keccak256(alloy_rlp::encode(block.body.as_core()))
            },
        };
        transactions
            .push(SettlementTransactionV1::new(p.proof_policy, statement, [9; SETTLEMENT_PROOF_V1_BYTES]).unwrap());
    }
    transactions
}

#[test]
fn binds_real_persisted_deposit_and_signed_transaction_blocks_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    let transactions = history(&source, false);
    let pinned = floor(&source);
    drop(source);
    let source = open(directory.path());
    let provider = CanonicalCoordinator::attach(source.clone()).unwrap().provider();
    assert_eq!(provider.finalized_block_num_hash().unwrap(), None);
    assert_eq!(provider.safe_block_num_hash().unwrap(), None);
    let (audited, report) =
        with_canonical_settlement_audit(&source, policy(), pinned, ReplayLimits::default(), |audit| {
            transactions.iter().try_for_each(|tx| audit.audit_transaction(tx))?;
            Ok::<_, alloy_evm::block::BlockExecutionError>(transactions.len())
        })
        .unwrap();
    assert_eq!(audited, 2);
    assert_eq!(report.audited_records, 2);
    assert_eq!(report.last_settlement.unwrap().hash, pinned.hash);
    assert_eq!(report.canonical_head.hash, pinned.hash);
    assert_eq!(report.genesis, spec().genesis_hash());
    assert!(report.canonical_bytes > 0);
    assert_eq!(provider.finalized_block_num_hash().unwrap(), None);
    assert_eq!(provider.safe_block_num_hash().unwrap(), None);
}

#[test]
fn rejects_old_body_mismatch_and_ignored_errors() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    let transactions = history(&source, true);
    let result = with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |audit| {
        transactions.iter().try_for_each(|tx| audit.audit_transaction(tx))
    });
    assert!(matches!(result, Err(CanonicalSettlementAuditErrorV1::Consumer(_))));
    let result = with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |audit| {
        assert!(audit.audit_transaction(&transactions[0]).is_err());
        // A poisoned audit refuses even a matching transaction.
        assert!(audit.audit_transaction(&transactions[1]).is_err());
        Ok::<(), ()>(()) // Deliberately broken caller; the outer boundary must refuse.
    });
    assert!(matches!(result, Err(CanonicalSettlementAuditErrorV1::Canonical(_))));
}

#[test]
fn refuses_wrong_policy_floor_and_budgets_before_calling_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    for case in 0..10 {
        let mut p = policy();
        let mut f = floor(&source);
        let mut limits = ReplayLimits::default();
        match case {
            0 => p.domain = h(99),
            1 => p.configuration = h(99),
            2 => p.chain_id += 1,
            3 => p.initial_l2_parent_hash = h(99),
            4 => p.initial_l2_state_root = h(99),
            5 => p.first_l2_number = u64::MAX,
            6 => f.hash = h(99),
            7 => f.number = 3,
            8 => limits.blocks = 1,
            9 => limits.bytes = 0,
            _ => unreachable!(),
        }
        let result = with_canonical_settlement_audit(&source, p, f, limits, |_| -> Result<(), ()> {
            panic!("invalid preflight reached recovery")
        });
        assert!(
            matches!(result, Err(CanonicalSettlementAuditErrorV1::Canonical(_))),
            "case {case}"
        );
    }
    assert!(
        with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |_| Ok::<
            _,
            (),
        >(
            ()
        ))
        .is_err()
    );
}

#[test]
fn exact_statement_fields_and_order_must_match_the_canonical_block() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    let transactions = history(&source, false);
    for case in 0..16 {
        let mut statement = *transactions[0].statement();
        let mut proof_policy = h(8);
        match case {
            0 => statement.domain = h(99),
            1 => statement.configuration = h(99),
            2 => statement.chain_id += 1,
            3 => statement.l2_header_hash = h(99),
            4 => statement.l2_parent_hash = h(99),
            5 => statement.l2_previous_state_root = h(99),
            6 => statement.l2_state_root = h(99),
            7 => statement.l1_block = h(99),
            8 => statement.body_commitment = h(99),
            9 => statement.consumed_end = 0,
            10 => statement.network = h(99),
            11 => statement.genesis = h(99),
            12 => statement.program_elf_keccak = h(99),
            13 => statement.program_vkey_koalabear = h(99),
            14 => statement.program_vkey_bn254 = h(99),
            15 => proof_policy = h(99),
            _ => unreachable!(),
        }
        let tx = SettlementTransactionV1::new(proof_policy, statement, [9; SETTLEMENT_PROOF_V1_BYTES]).unwrap();
        let result =
            with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |audit| {
                audit.audit_transaction(&tx)
            });
        assert!(
            matches!(result, Err(CanonicalSettlementAuditErrorV1::Consumer(_))),
            "case {case}"
        );
    }
    // The settlement of block 2 cannot stand in for the settlement of block 1.
    let result = with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |audit| {
        audit.audit_transaction(&transactions[1])
    });
    assert!(matches!(result, Err(CanonicalSettlementAuditErrorV1::Consumer(_))));
}

#[test]
fn acknowledged_tip_change_discards_the_audited_result() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    let transactions = history(&source, false);
    let mut competing = CanonicalCoordinator::attach(source.clone()).unwrap();
    let result = with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |audit| {
        transactions.iter().try_for_each(|tx| audit.audit_transaction(tx))?;
        // Deliberately violate the stopped-writer contract to test the final fence.
        competing.extend(competing.head().hash(), attrs(3), vec![]).unwrap();
        Ok::<_, alloy_evm::block::BlockExecutionError>(())
    });
    assert!(matches!(result, Err(CanonicalSettlementAuditErrorV1::Canonical(_))));
}

#[test]
fn missing_complete_body_fails_before_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    let pinned = floor(&source);
    let mut writer = source.database_provider_rw().unwrap();
    writer
        .tx_mut()
        .clear::<bloch_reth_execution::BlochV2Deposits>()
        .unwrap();
    writer.commit().unwrap();
    let result = with_canonical_settlement_audit(
        &source,
        policy(),
        pinned,
        ReplayLimits::default(),
        |_| -> Result<(), ()> { panic!("missing bodies reached recovery") },
    );
    assert!(matches!(result, Err(CanonicalSettlementAuditErrorV1::Canonical(_))));
}
