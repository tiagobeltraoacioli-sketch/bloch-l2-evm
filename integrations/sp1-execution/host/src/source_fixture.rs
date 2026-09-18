// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical synthetic native ancestry and locally allocated escrow, NOT native funds.
use crate::fixture::{self, Fixture};
use alloy_primitives::{Bytes, B256};
use bloch_evm_sp1_host::Result;
use bloch_l2_evm::{
    escrow::{Coin, EscrowLedger, LockIntent, Outpoint},
    escrow_execution::TrustedLockLocation,
    escrow_inbox::InboxProof,
    l1::{
        height::{HeightCursor, HeightPosition},
        FinalizedCheckpoint,
    },
    DepositPosition,
};
use bloch_native_domain_devnet::{SourceAnchor, SourceBatch, SourceRegistry, MAX_LOCKS};
use sha3::{Digest, Sha3_256};

pub struct SourceFixture {
    pub execution: Fixture,
    pub registry: SourceRegistry,
    pub headers: Vec<Bytes>,
    pub position: HeightPosition,
    pub batch: SourceBatch,
    pub proofs: Vec<InboxProof>,
    pub expected_source: B256,
}
fn header_id(bytes: &[u8]) -> B256 {
    let mut hash = Sha3_256::new();
    hash.update(b"BLCH4:BLOCK\0\0\0\0\0");
    hash.update(bytes);
    B256::from_slice(&hash.finalize())
}
pub fn source_contract() -> Result<SourceFixture> {
    let mut headers = Vec::new();
    let mut parent = B256::ZERO;
    for index in 0..2u64 {
        let mut bytes = vec![0u8; 304];
        bytes[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
        bytes[4..36].copy_from_slice(parent.as_slice());
        bytes[100..108].copy_from_slice(&(100 + index * 50).to_le_bytes());
        parent = header_id(&bytes);
        headers.push(Bytes::from(bytes));
    }
    let genesis = header_id(&headers[0]);
    let mut cursor = HeightCursor::from_genesis(genesis, &headers[0]).map_err(fixture_error)?;
    let network = B256::repeat_byte(0x51);
    let domain = B256::repeat_byte(0xd3);
    let registry = SourceRegistry::new(network, domain, cursor.clone())?;
    let position = cursor
        .advance(
            FinalizedCheckpoint {
                block: parent,
                slot: 150,
            },
            &headers,
        )
        .map_err(fixture_error)?;
    let existing = fixture::fixture()?;
    let recipient = existing.body.deposits[0].recipient;
    let owner = B256::repeat_byte(0x52);
    let funding = Outpoint {
        txid: B256::repeat_byte(0x53),
        vout: 0,
    };
    let mut ledger = EscrowLedger::new(
        network,
        domain,
        vec![(
            funding,
            Coin {
                value: 100_000_001,
                owner,
            },
        )],
        MAX_LOCKS,
    )
    .map_err(fixture_error)?;
    let lock = ledger
        .apply_authorized_lock(&LockIntent {
            network,
            domain,
            owner,
            inputs: vec![funding],
            recipient,
            amount: 100_000_000,
            fee: 1,
            change_owner: owner,
            nonce: 0,
        })
        .map_err(fixture_error)?;
    assert!(ledger.conserved());
    let inbox = ledger.inbox();
    let batch = SourceBatch {
        network,
        domain,
        genesis,
        previous: registry.commitment(),
        anchor: SourceAnchor {
            block: position.block(),
            slot: position.slot(),
            height: position.height(),
        },
        inbox_root: inbox.root(),
        count: 1,
        locations: vec![TrustedLockLocation {
            sequence: 0,
            intent: lock.id,
            transaction: B256::repeat_byte(0xd3),
            position: DepositPosition {
                l1_height: 1,
                l1_tx_index: 0,
                l1_vout: 0,
            },
        }],
    };
    // This commitment is fixture-owned independent policy, not proposer authority.
    let expected_source = batch.commitment()?;
    let proofs = inbox.proofs(0..1).ok_or("fixture inbox proof missing")?;
    let (execution, _, _) = fixture::execute_fixture_at(existing.body, position.block())?;
    let mut checked = registry.clone();
    checked.apply(expected_source, position, &headers, &batch, &proofs)?;
    let selection = checked.validate_v2_prefix(
        &bloch_l2_evm::ChainSpec::testnet(),
        0,
        &execution.header,
        &execution.body,
    )?;
    assert_eq!(selection.statement(), execution.expected);
    Ok(SourceFixture {
        execution,
        registry,
        headers,
        position,
        batch,
        proofs,
        expected_source,
    })
}

fn fixture_error(error: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::other(format!("synthetic source fixture: {error:?}"))
}
