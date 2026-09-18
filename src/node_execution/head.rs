// SPDX-License-Identifier: MIT OR Apache-2.0
//! V2 committed head metadata and explicit zero-issuance genesis.
use crate::{
    executor::{deposits_hash, BlockExecutionError},
    node_primitives::NodeHeaderV2,
    state::{
        ensure_system_account, HeadRecord, BLOCK_INFO_ANCHOR_ROOT_SLOT, BLOCK_INFO_BASE_FEE_SLOT,
        BLOCK_INFO_DEPOSITS_HASH_SLOT, BLOCK_INFO_FLAG_SLOT, BLOCK_INFO_GAS_USED_SLOT, BLOCK_INFO_NUMBER_SLOT,
        BLOCK_INFO_PARENT_HASH_SLOT, BLOCK_INFO_PREVRANDAO_SLOT, BLOCK_INFO_TIMESTAMP_SLOT,
    },
    ChainSpec, L2State,
};
#[cfg(not(feature = "std"))]
use alloc::format;
use alloy_primitives::{Address, Bloom, B256, U256};
use revm::{database::CacheDB, Database, DatabaseRef};

const HEAD_V2_USER_GAS_SLOT: U256 = U256::from_limbs([9, 0, 0, 0]);
const HEAD_V2_PARENT_STATE_SLOT: U256 = U256::from_limbs([10, 0, 0, 0]);
const HEAD_V2_TRANSACTIONS_ROOT_SLOT: U256 = U256::from_limbs([11, 0, 0, 0]);
const HEAD_V2_RECEIPTS_ROOT_SLOT: U256 = U256::from_limbs([12, 0, 0, 0]);
const HEAD_V2_BLOOM_START: u64 = 13;

/// V2 header fields stored inside the state, excluding its own root and domain.
/// Configuration constants are reconstructed from the trusted chain specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadRecordV2 {
    /// Existing execution metadata; the V2 reader uses an explicit version flag.
    pub base: HeadRecord,
    /// User-only cumulative gas, excluding fee-less deposits.
    pub user_gas_used: u64,
    /// State root before this recorded block, not its own post-state root.
    pub parent_state_root: B256,
    /// Ordered MPT commitment to canonical signed transaction bytes.
    pub transactions_root: B256,
    /// Ordered MPT commitment to actual typed user receipts.
    pub receipts_root: B256,
    /// Aggregate user-receipt bloom in eight consecutive storage words.
    pub logs_bloom: Bloom,
}
impl HeadRecordV2 {
    /// Reconstruct using the trusted V2 domain/spec and the root containing this head.
    /// Keeping the domain outside the head avoids a domain/genesis-root cycle.
    pub fn header(&self, spec: &ChainSpec, domain: B256, state_root: B256) -> NodeHeaderV2 {
        NodeHeaderV2 {
            domain,
            chain_id: spec.chain_id,
            number: self.base.number,
            timestamp: self.base.timestamp,
            base_fee_per_gas: self.base.base_fee_per_gas,
            gas_limit: spec.gas_limit,
            gas_used: self.base.gas_used,
            user_gas_used: self.user_gas_used,
            beneficiary: spec.coinbase(),
            prevrandao: self.base.prevrandao,
            anchor_root: self.base.anchor_root,
            parent_hash: self.base.parent_hash,
            parent_state_root: self.parent_state_root,
            transactions_root: self.transactions_root,
            receipts_root: self.receipts_root,
            deposits_hash: self.base.deposits_hash,
            logs_bloom: self.logs_bloom,
            state_root,
        }
    }
}
fn db_error(error: impl core::fmt::Debug) -> BlockExecutionError {
    BlockExecutionError::Database {
        detail: format!("{error:?}"),
    }
}
fn checked_u64(word: U256, field: &str) -> Result<u64, BlockExecutionError> {
    u64::try_from(word).map_err(|_| BlockExecutionError::HeaderState {
        detail: format!("V2 head {field} exceeds u64"),
    })
}
/// Read only an initialized V2 head, without truncating malformed integer slots.
pub(crate) fn read_head_v2<DB: DatabaseRef>(
    db: &mut CacheDB<DB>,
    address: Address,
) -> Result<HeadRecordV2, BlockExecutionError> {
    db.basic(address).map_err(db_error)?;
    if db.storage(address, BLOCK_INFO_FLAG_SLOT).map_err(db_error)? != U256::from(2) {
        return Err(BlockExecutionError::HeaderState {
            detail: "expected initialized V2 head flag 2".into(),
        });
    }
    let number = checked_u64(db.storage(address, BLOCK_INFO_NUMBER_SLOT).map_err(db_error)?, "number")?;
    let timestamp = checked_u64(
        db.storage(address, BLOCK_INFO_TIMESTAMP_SLOT).map_err(db_error)?,
        "timestamp",
    )?;
    let base_fee_per_gas = checked_u64(
        db.storage(address, BLOCK_INFO_BASE_FEE_SLOT).map_err(db_error)?,
        "base fee",
    )?;
    let gas_used = checked_u64(
        db.storage(address, BLOCK_INFO_GAS_USED_SLOT).map_err(db_error)?,
        "gas used",
    )?;
    let prevrandao = B256::from(db.storage(address, BLOCK_INFO_PREVRANDAO_SLOT).map_err(db_error)?);
    let anchor_root = B256::from(db.storage(address, BLOCK_INFO_ANCHOR_ROOT_SLOT).map_err(db_error)?);
    let parent_hash = B256::from(db.storage(address, BLOCK_INFO_PARENT_HASH_SLOT).map_err(db_error)?);
    let deposits_hash = B256::from(db.storage(address, BLOCK_INFO_DEPOSITS_HASH_SLOT).map_err(db_error)?);
    let user_gas_used = checked_u64(
        db.storage(address, HEAD_V2_USER_GAS_SLOT).map_err(db_error)?,
        "user gas",
    )?;
    if user_gas_used > gas_used {
        return Err(BlockExecutionError::HeaderState {
            detail: "V2 user gas exceeds total gas".into(),
        });
    }
    let parent_state_root = B256::from(db.storage(address, HEAD_V2_PARENT_STATE_SLOT).map_err(db_error)?);
    let transactions_root = B256::from(db.storage(address, HEAD_V2_TRANSACTIONS_ROOT_SLOT).map_err(db_error)?);
    let receipts_root = B256::from(db.storage(address, HEAD_V2_RECEIPTS_ROOT_SLOT).map_err(db_error)?);
    let mut bloom = [0u8; 256];
    for (index, chunk) in bloom.chunks_exact_mut(32).enumerate() {
        chunk.copy_from_slice(
            &db.storage(address, U256::from(HEAD_V2_BLOOM_START + index as u64))
                .map_err(db_error)?
                .to_be_bytes::<32>(),
        );
    }
    Ok(HeadRecordV2 {
        base: HeadRecord {
            number,
            timestamp,
            base_fee_per_gas,
            gas_used,
            prevrandao,
            anchor_root,
            parent_hash,
            deposits_hash,
        },
        user_gas_used,
        parent_state_root,
        transactions_root,
        receipts_root,
        logs_bloom: Bloom::from(bloom),
    })
}
/// Write a V2 head on a provisional overlay; callers stage the complete phase.
pub(crate) fn write_head_v2<DB: DatabaseRef>(
    db: &mut CacheDB<DB>,
    address: Address,
    record: &HeadRecordV2,
) -> Result<(), BlockExecutionError> {
    if record.user_gas_used > record.base.gas_used {
        return Err(BlockExecutionError::HeaderState {
            detail: "V2 user gas exceeds total gas".into(),
        });
    }
    ensure_system_account(db, address, None).map_err(db_error)?;
    let base = &record.base;
    for (slot, value) in [
        (BLOCK_INFO_FLAG_SLOT, U256::from(2)),
        (BLOCK_INFO_NUMBER_SLOT, U256::from(base.number)),
        (BLOCK_INFO_TIMESTAMP_SLOT, U256::from(base.timestamp)),
        (BLOCK_INFO_BASE_FEE_SLOT, U256::from(base.base_fee_per_gas)),
        (BLOCK_INFO_GAS_USED_SLOT, U256::from(base.gas_used)),
        (BLOCK_INFO_PREVRANDAO_SLOT, U256::from_be_bytes(base.prevrandao.0)),
        (BLOCK_INFO_ANCHOR_ROOT_SLOT, U256::from_be_bytes(base.anchor_root.0)),
        (BLOCK_INFO_PARENT_HASH_SLOT, U256::from_be_bytes(base.parent_hash.0)),
        (BLOCK_INFO_DEPOSITS_HASH_SLOT, U256::from_be_bytes(base.deposits_hash.0)),
        (HEAD_V2_USER_GAS_SLOT, U256::from(record.user_gas_used)),
        (
            HEAD_V2_PARENT_STATE_SLOT,
            U256::from_be_bytes(record.parent_state_root.0),
        ),
        (
            HEAD_V2_TRANSACTIONS_ROOT_SLOT,
            U256::from_be_bytes(record.transactions_root.0),
        ),
        (HEAD_V2_RECEIPTS_ROOT_SLOT, U256::from_be_bytes(record.receipts_root.0)),
    ] {
        db.insert_account_storage(address, slot, value).map_err(db_error)?;
    }
    for (index, chunk) in record.logs_bloom.as_slice().chunks_exact(32).enumerate() {
        db.insert_account_storage(
            address,
            U256::from(HEAD_V2_BLOOM_START + index as u64),
            U256::from_be_slice(chunk),
        )
        .map_err(db_error)?;
    }
    Ok(())
}

/// Create explicit block-zero V2 metadata before computing the genesis root.
/// No domain is stored and no native issuance occurs. Derive the V2 domain only
/// after computing this state's root. The first child applies the normal fee
/// update to this empty genesis block: `next_base_fee(initial_base_fee, 0)`.
pub fn genesis_v2(spec: &ChainSpec, timestamp: u64) -> Result<L2State, BlockExecutionError> {
    spec.validate().map_err(BlockExecutionError::InvalidChainSpec)?;
    let mut state = L2State::genesis(spec);
    let record = HeadRecordV2 {
        base: HeadRecord {
            number: 0,
            timestamp,
            base_fee_per_gas: spec.initial_base_fee,
            gas_used: 0,
            prevrandao: B256::ZERO,
            anchor_root: B256::ZERO,
            parent_hash: B256::ZERO,
            deposits_hash: deposits_hash(&[]),
        },
        user_gas_used: 0,
        parent_state_root: alloy_trie::EMPTY_ROOT_HASH,
        transactions_root: alloy_trie::EMPTY_ROOT_HASH,
        receipts_root: alloy_trie::EMPTY_ROOT_HASH,
        logs_bloom: Bloom::ZERO,
    };
    write_head_v2(state.db_mut(), spec.block_info, &record)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn genesis_is_deterministic_zero_issuance_and_domain_is_not_in_its_root() {
        let spec = ChainSpec::testnet();
        let mut first = genesis_v2(&spec, 17).unwrap();
        let mut second = genesis_v2(&spec, 17).unwrap();
        let root = first.commit_root();
        assert_eq!(root, second.commit_root());
        assert!(first.total_native_wei().is_zero());
        let head = read_head_v2(first.db_mut(), spec.block_info).unwrap();
        assert_eq!(head.base.number, 0);
        assert_eq!(head.base.timestamp, 17);
        assert_eq!(head.base.base_fee_per_gas, spec.initial_base_fee);
        assert_eq!(head.parent_state_root, alloy_trie::EMPTY_ROOT_HASH);
        assert_eq!(head.transactions_root, alloy_trie::EMPTY_ROOT_HASH);
        assert_eq!(head.receipts_root, alloy_trie::EMPTY_ROOT_HASH);
        assert_eq!(head.base.deposits_hash, deposits_hash(&[]));
        let a = head.header(&spec, B256::repeat_byte(1), root);
        let b = head.header(&spec, B256::repeat_byte(2), root);
        assert_ne!(a.hash(), b.hash());
        assert_eq!(first.commit_root(), root);
        assert_eq!(a.beneficiary, spec.coinbase());
        assert_eq!(a.gas_limit, spec.gas_limit);
    }
    #[test]
    fn missing_v1_and_unknown_flags_are_rejected() {
        let spec = ChainSpec::testnet();
        for flag in [0, 1, 3, u64::MAX] {
            let mut state = genesis_v2(&spec, 0).unwrap();
            state
                .db_mut()
                .insert_account_storage(spec.block_info, BLOCK_INFO_FLAG_SLOT, U256::from(flag))
                .unwrap();
            assert!(matches!(
                read_head_v2(state.db_mut(), spec.block_info),
                Err(BlockExecutionError::HeaderState { .. })
            ));
        }
        let mut absent = L2State::new();
        assert!(read_head_v2(absent.db_mut(), spec.block_info).is_err());
    }
    #[test]
    fn oversized_integer_fields_cannot_be_truncated() {
        let spec = ChainSpec::testnet();
        for slot in [
            BLOCK_INFO_NUMBER_SLOT,
            BLOCK_INFO_TIMESTAMP_SLOT,
            BLOCK_INFO_BASE_FEE_SLOT,
            BLOCK_INFO_GAS_USED_SLOT,
            HEAD_V2_USER_GAS_SLOT,
        ] {
            let mut state = genesis_v2(&spec, 0).unwrap();
            state
                .db_mut()
                .insert_account_storage(spec.block_info, slot, U256::from(u64::MAX) + U256::from(1))
                .unwrap();
            assert!(matches!(
                read_head_v2(state.db_mut(), spec.block_info),
                Err(BlockExecutionError::HeaderState { .. })
            ));
        }
    }
    #[test]
    fn bloom_and_extended_metadata_round_trip_and_change_header_hash() {
        let spec = ChainSpec::testnet();
        let mut state = genesis_v2(&spec, 0).unwrap();
        let mut head = read_head_v2(state.db_mut(), spec.block_info).unwrap();
        head.base.number = 42;
        head.base.gas_used = 100;
        head.user_gas_used = 75;
        head.parent_state_root = B256::repeat_byte(3);
        head.transactions_root = B256::repeat_byte(4);
        head.receipts_root = B256::repeat_byte(5);
        let mut bloom = [0u8; 256];
        for (index, byte) in bloom.iter_mut().enumerate() {
            *byte = index as u8;
        }
        head.logs_bloom = Bloom::from(bloom);
        write_head_v2(state.db_mut(), spec.block_info, &head).unwrap();
        assert_eq!(read_head_v2(state.db_mut(), spec.block_info).unwrap(), head);
        let header = head.header(&spec, B256::repeat_byte(7), state.commit_root());
        head.transactions_root = B256::repeat_byte(9);
        assert_ne!(
            header.hash(),
            head.header(&spec, header.domain, header.state_root).hash()
        );
        head.user_gas_used = 101;
        assert!(write_head_v2(state.db_mut(), spec.block_info, &head).is_err());
    }
}
