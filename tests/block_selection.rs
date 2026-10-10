// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic V2 block selection (`produce extend --txs`): limits,
//! overflow left for the next block, invalid candidates dropped with a reason,
//! deposits first, and an order that depends only on the candidate set.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    node_execution::{
        execute_node_block, genesis_v2, node_head,
        select::{select_node_transactions, BlockSelection, DeferReason, DropReason, SelectionLimits},
    },
    node_primitives::NodeBodyV2,
    transactions::TransactionAuthError,
    BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State,
};
use k256::ecdsa::SigningKey;

const TRANSFER_GAS: u64 = 21_000;

fn domain() -> B256 {
    B256::repeat_byte(0xd3)
}
fn key(i: u8) -> SigningKey {
    SigningKey::from_bytes((&[i + 1; 32]).into()).unwrap()
}
fn address(i: u8) -> Address {
    Address::from_public_key(key(i).verifying_key())
}
fn deposit(i: u8) -> DepositMint {
    DepositMint {
        recipient: address(i),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 5,
            l1_tx_index: u32::from(i),
            l1_txid: [i; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    }
}
struct Tx {
    nonce: u64,
    gas: u64,
    tip: u128,
    max_fee: u128,
    chain: u64,
    input: Vec<u8>,
}
impl Default for Tx {
    fn default() -> Self {
        Self {
            nonce: 0,
            gas: TRANSFER_GAS,
            tip: 100_000_000,
            max_fee: 2_000_000_000,
            chain: ChainSpec::testnet().chain_id,
            input: vec![],
        }
    }
}
fn sign(i: u8, tx: Tx) -> Bytes {
    let unsigned = TxEip1559 {
        chain_id: tx.chain,
        nonce: tx.nonce,
        to: TxKind::Call(Address::repeat_byte(0x55)),
        value: U256::from(1_000),
        input: tx.input.into(),
        gas_limit: tx.gas,
        max_fee_per_gas: tx.max_fee,
        max_priority_fee_per_gas: tx.tip,
        ..Default::default()
    };
    let signature: Signature = key(i)
        .sign_prehash_recoverable(unsigned.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(unsigned.into_signed(signature)).encoded_2718().into()
}
fn transfer(i: u8, nonce: u64) -> Bytes {
    sign(i, Tx { nonce, ..Tx::default() })
}
fn hash(raw: &Bytes) -> B256 {
    keccak256(raw)
}

struct Chain {
    spec: ChainSpec,
    state: L2State,
}
impl Chain {
    fn new() -> Self {
        let spec = ChainSpec::testnet();
        let state = genesis_v2(&spec, 10).unwrap();
        Self { spec, state }
    }
    fn context(&self) -> BlockContext {
        let parent = node_head(&self.spec, domain(), &self.state).unwrap();
        BlockContext {
            number: parent.number + 1,
            timestamp: parent.timestamp + 1,
            base_fee_per_gas: self.spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
            prevrandao: B256::repeat_byte(7),
            anchor_root: B256::repeat_byte(8),
        }
    }
    fn select(&self, deposits: &[DepositMint], candidates: &[Bytes], limits: SelectionLimits) -> BlockSelection {
        select_node_transactions(
            &self.spec,
            domain(),
            self.state.db(),
            self.state.state_root(),
            &self.context(),
            deposits,
            candidates,
            limits,
        )
        .unwrap()
    }
    /// Execute the selection exactly as a producer would; it must be valid.
    fn commit(&mut self, deposits: &[DepositMint], selection: &BlockSelection) {
        let body = NodeBodyV2 {
            deposits: deposits.to_vec(),
            transactions: selection.transactions.clone(),
        };
        let context = self.context();
        let outcome = execute_node_block(&self.spec, domain(), &mut self.state, &context, &body).unwrap();
        assert_eq!(outcome.transactions.len(), selection.transactions.len());
    }
}
fn unlimited() -> SelectionLimits {
    SelectionLimits::protocol(&ChainSpec::testnet())
}
fn funded(n: u8) -> Vec<DepositMint> {
    (0..n).map(deposit).collect()
}

#[test]
fn deposits_are_minted_first_so_newly_funded_senders_can_spend() {
    let chain = Chain::new();
    let txs: Vec<_> = (0..3).map(|i| transfer(i, 0)).collect();
    // Without the deposits nobody has funds: execution refuses every one.
    let none = chain.select(&[], &txs, unlimited());
    assert!(none.transactions.is_empty());
    assert_eq!(none.dropped.len(), 3);
    assert!(none
        .dropped
        .iter()
        .all(|d| matches!(d.reason, DropReason::Execution(_))));
    // With this block's deposits they all fit.
    let some = chain.select(&funded(3), &txs, unlimited());
    assert_eq!(some.transactions.len(), 3);
    assert!(some.deferred.is_empty() && some.dropped.is_empty());
}

#[test]
fn gas_byte_and_count_limits_are_respected_and_overflow_is_deferred() {
    let mut chain = Chain::new();
    let deposits = funded(10);
    let txs: Vec<_> = (0..10).map(|i| transfer(i, 0)).collect();
    let size = txs[0].len();
    assert!(txs.iter().all(|t| t.len() == size));
    for (limits, included, reason) in [
        (
            SelectionLimits {
                max_gas: TRANSFER_GAS * 4,
                ..unlimited()
            },
            4,
            DeferReason::GasLimit,
        ),
        (
            SelectionLimits {
                max_gas: TRANSFER_GAS * 4 + TRANSFER_GAS - 1,
                ..unlimited()
            },
            4,
            DeferReason::GasLimit,
        ),
        (
            SelectionLimits {
                max_bytes: size * 3,
                ..unlimited()
            },
            3,
            DeferReason::ByteLimit,
        ),
        (
            SelectionLimits {
                max_bytes: size * 3 + size - 1,
                ..unlimited()
            },
            3,
            DeferReason::ByteLimit,
        ),
        (
            SelectionLimits {
                max_transactions: 6,
                ..unlimited()
            },
            6,
            DeferReason::CountLimit,
        ),
        (
            SelectionLimits {
                max_gas: 0,
                ..unlimited()
            },
            0,
            DeferReason::GasLimit,
        ),
    ] {
        let s = chain.select(&deposits, &txs, limits);
        assert_eq!(s.transactions.len(), included, "{limits:?}");
        assert!(s.declared_gas <= limits.max_gas && s.bytes <= limits.max_bytes);
        assert!(s.transactions.len() <= limits.max_transactions);
        assert_eq!(s.deferred.len(), 10 - included);
        assert!(
            s.deferred.iter().all(|d| d.reason == reason),
            "{limits:?}: {:?}",
            s.deferred
        );
        assert!(s.dropped.is_empty());
        // Every candidate is accounted for exactly once.
        let mut all: Vec<B256> = s.hashes.clone();
        all.extend(s.deferred.iter().map(|d| d.hash));
        all.sort();
        let mut expected: Vec<B256> = txs.iter().map(hash).collect();
        expected.sort();
        assert_eq!(all, expected);
    }
    // Limits above the protocol maxima are clamped.
    let huge = SelectionLimits {
        max_gas: u64::MAX,
        max_bytes: usize::MAX,
        max_transactions: usize::MAX,
    };
    assert_eq!(huge.clamp(&chain.spec), unlimited());

    // Overflow is left for the next block and included there.
    let first = chain.select(
        &deposits,
        &txs,
        SelectionLimits {
            max_gas: TRANSFER_GAS * 4,
            ..unlimited()
        },
    );
    chain.commit(&deposits, &first);
    let leftover: Vec<Bytes> = first.deferred.iter().map(|d| txs[d.index].clone()).collect();
    let second = chain.select(&[], &leftover, unlimited());
    assert_eq!(second.transactions.len(), 6);
    assert!(second.deferred.is_empty() && second.dropped.is_empty());
    chain.commit(&[], &second);
    // Once included, resubmitting is a nonce-too-low drop.
    let replay = chain.select(&[], &txs[..1], unlimited());
    assert_eq!(
        replay.dropped[0].reason,
        DropReason::NonceTooLow { expected: 1, got: 0 }
    );
}

#[test]
fn invalid_candidates_are_dropped_with_a_reason() {
    let chain = Chain::new();
    let deposits = funded(4);
    let good = transfer(0, 0);
    let mut high_s_or_bad_sig = transfer(1, 0).to_vec();
    let last = high_s_or_bad_sig.len() - 1;
    high_s_or_bad_sig[last] ^= 0x01;
    let legacy_unprotected = {
        let tx = TxLegacy {
            chain_id: None,
            nonce: 0,
            gas_price: 2_000_000_000,
            gas_limit: TRANSFER_GAS,
            to: TxKind::Call(Address::repeat_byte(1)),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let signature: Signature = key(1)
            .sign_prehash_recoverable(tx.signature_hash().as_slice())
            .unwrap()
            .into();
        Bytes::from(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
    };
    let candidates = vec![
        good.clone(),                      // 0 included
        Bytes::from_static(&[0x02, 0xc0]), // 1 garbage
        sign(
            1,
            Tx {
                chain: 1,
                ..Tx::default()
            },
        ), // 2 wrong chain
        good.clone(),                      // 3 duplicate
        Bytes::new(),                      // 4 empty
        sign(
            2,
            Tx {
                gas: 30_000_001,
                ..Tx::default()
            },
        ), // 5 above block gas
        sign(5, Tx::default()),            // 6 unfunded sender
        sign(
            3,
            Tx {
                gas: 20_000,
                ..Tx::default()
            },
        ), // 7 below intrinsic gas
        Bytes::from(high_s_or_bad_sig),    // 8 tampered signature
        legacy_unprotected,                // 9 no replay domain
    ];
    let s = chain.select(&deposits, &candidates, unlimited());
    assert_eq!(s.hashes, vec![hash(&good)]);
    let reasons: Vec<(usize, DropReason)> = s.dropped.iter().map(|d| (d.index, d.reason.clone())).collect();
    let index_of = |i: usize| reasons.iter().find(|(j, _)| *j == i).map(|(_, r)| r.clone());
    assert!(matches!(
        index_of(1),
        Some(DropReason::Authentication(TransactionAuthError::InvalidEncoding))
    ));
    assert_eq!(
        index_of(2),
        Some(DropReason::Authentication(TransactionAuthError::WrongChain))
    );
    assert_eq!(index_of(3), Some(DropReason::Duplicate));
    assert_eq!(
        index_of(4),
        Some(DropReason::Authentication(TransactionAuthError::Empty))
    );
    assert!(matches!(index_of(5), Some(DropReason::Execution(_))));
    assert!(matches!(index_of(6), Some(DropReason::Execution(_))));
    assert!(matches!(index_of(7), Some(DropReason::Execution(_))));
    assert!(matches!(
        index_of(8),
        Some(DropReason::Authentication(_)) | Some(DropReason::Execution(_))
    ));
    assert_eq!(
        index_of(9),
        Some(DropReason::Authentication(TransactionAuthError::UnprotectedLegacy))
    );
    assert!(s.dropped.iter().all(|d| !d.reason.describe().is_empty()));
    // The selection is exactly what the executor accepts.
    let mut chain = chain;
    chain.commit(&deposits, &s);
}

#[test]
fn nonce_gaps_and_low_fee_caps_are_deferred_not_dropped() {
    let chain = Chain::new();
    let deposits = funded(3);
    let candidates = vec![
        transfer(0, 0),
        transfer(0, 2), // gap after nonce 0
        sign(
            1,
            Tx {
                max_fee: 1,
                tip: 1,
                ..Tx::default()
            },
        ), // fee cap below base fee
        sign(
            1,
            Tx {
                nonce: 1,
                ..Tx::default()
            },
        ), // blocked behind it
        sign(
            2,
            Tx {
                nonce: 0,
                gas: 20_000,
                ..Tx::default()
            },
        ), // dropped (intrinsic)
        sign(
            2,
            Tx {
                nonce: 1,
                ..Tx::default()
            },
        ), // blocked behind the drop
    ];
    let s = chain.select(&deposits, &candidates, unlimited());
    assert_eq!(s.hashes, vec![hash(&candidates[0])]);
    let deferred: Vec<(usize, DeferReason)> = s.deferred.iter().map(|d| (d.index, d.reason)).collect();
    assert_eq!(
        deferred,
        vec![
            (1, DeferReason::NonceGap),
            (2, DeferReason::FeeBelowBaseFee),
            (3, DeferReason::SenderBlocked),
            (5, DeferReason::SenderBlocked),
        ]
    );
    assert_eq!(s.dropped.len(), 1);
    assert_eq!(s.dropped[0].index, 4);
}

#[test]
fn order_depends_only_on_the_candidate_set() {
    let chain = Chain::new();
    let deposits = funded(4);
    // Sender 0: nonces 0..3 at a low tip; sender 1: one high tip; sender 2/3: equal tips.
    let mut candidates: Vec<Bytes> = (0..3)
        .map(|n| {
            sign(
                0,
                Tx {
                    nonce: n,
                    tip: 1,
                    ..Tx::default()
                },
            )
        })
        .collect();
    candidates.push(sign(
        1,
        Tx {
            tip: 900_000_000,
            ..Tx::default()
        },
    ));
    candidates.push(sign(
        2,
        Tx {
            tip: 5_000,
            ..Tx::default()
        },
    ));
    candidates.push(sign(
        3,
        Tx {
            tip: 5_000,
            ..Tx::default()
        },
    ));
    let reference = chain.select(&deposits, &candidates, unlimited());
    assert_eq!(reference.transactions.len(), 6);
    // Highest tip first; equal tips by lowest hash; one sender in nonce order.
    assert_eq!(reference.hashes[0], hash(&candidates[3]));
    let (a, b) = (hash(&candidates[4]), hash(&candidates[5]));
    assert_eq!(&reference.hashes[1..3], &[a.min(b), a.max(b)]);
    assert_eq!(
        &reference.hashes[3..],
        &[hash(&candidates[0]), hash(&candidates[1]), hash(&candidates[2])]
    );
    // Every rotation and the reversal of the input give the same block.
    for shift in 0..candidates.len() {
        let mut permuted = candidates.clone();
        permuted.rotate_left(shift);
        assert_eq!(chain.select(&deposits, &permuted, unlimited()).hashes, reference.hashes);
    }
    let mut reversed = candidates.clone();
    reversed.reverse();
    assert_eq!(chain.select(&deposits, &reversed, unlimited()).hashes, reference.hashes);
}

#[test]
fn deposits_consume_block_gas_before_user_transactions() {
    let mut spec = ChainSpec::testnet();
    // A tiny block: room for the deposits and exactly one transfer.
    spec.gas_limit = spec.deposit_gas * 2 + TRANSFER_GAS;
    spec.validate()
        .expect("a block holding two deposits and one transfer is a valid spec");
    let state = genesis_v2(&spec, 10).unwrap();
    let chain = Chain { spec, state };
    let txs = vec![transfer(0, 0), transfer(1, 0)];
    let s = chain.select(&funded(2), &txs, SelectionLimits::protocol(&chain.spec));
    assert_eq!(s.transactions.len(), 1);
    assert_eq!(s.deferred.len(), 1);
    assert_eq!(s.deferred[0].reason, DeferReason::GasLimit);
}
