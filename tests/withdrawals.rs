// SPDX-License-Identifier: MIT OR Apache-2.0
//! L2 → L1 withdrawal outbox (M4): the predeploy's call rules, the committed
//! tree, the burn out of the L2 supply, stateless re-execution and the shared
//! leaf/tree vectors (`tests/fixtures/l2-withdrawal-v1`).
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bloom, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    executor::deposits_hash,
    node_execution::{
        execute_node_block, generate_node_batch_witness, genesis_v2, verify_node_batch, HeadRecordV2,
        NodeExecutionOutcome,
    },
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2},
    sats_to_wei,
    withdrawal::{
        empty_withdrawal_root, verify_withdrawal_proof, withdrawal_leaf, Withdrawal, WithdrawalCommitment,
        WithdrawalTree, INITIATE_WITHDRAWAL_SELECTOR, L2_TO_L1_MESSAGE_PASSER, MIN_WITHDRAWAL_SATS, OUTBOX_CODE,
        OUTBOX_NONCE_SLOT, WITHDRAWAL_INITIATED_TOPIC,
    },
    BlockContext, ChainSpec, DepositMint, DepositProvenance, HeadRecord, L2State,
};
use k256::ecdsa::SigningKey;

const OUTBOX: Address = L2_TO_L1_MESSAGE_PASSER;

fn domain() -> B256 {
    B256::repeat_byte(0xd3)
}

fn genesis_header(spec: &ChainSpec, root: B256) -> NodeHeaderV2 {
    HeadRecordV2 {
        base: HeadRecord {
            number: 0,
            timestamp: 10,
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
    }
    .header(spec, domain(), root)
}

fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}

fn recipient(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn initiate(l1_recipient: B256) -> Bytes {
    let mut data = INITIATE_WITHDRAWAL_SELECTOR.to_vec();
    data.extend_from_slice(l1_recipient.as_slice());
    data.into()
}

/// Wrap a runtime (< 256 bytes) in `CODECOPY`/`RETURN` init code.
fn deploy(runtime: &[u8]) -> Bytes {
    let mut code = vec![
        0x60,
        runtime.len() as u8,
        0x80,
        0x60,
        0x0b,
        0x60,
        0x00,
        0x39,
        0x60,
        0x00,
        0xf3,
    ];
    code.extend_from_slice(runtime);
    code.into()
}

/// `CALL(gas, outbox, value_expr, calldata)`: copies the calldata to memory 0.
fn call_outbox(value: &[u8], opcode: u8) -> Vec<u8> {
    let mut code = vec![0x60, 0x00, 0x60, 0x00, 0x36, 0x60, 0x00];
    if opcode == 0xf1 {
        code.extend_from_slice(value);
    }
    code.push(0x73);
    code.extend_from_slice(OUTBOX.as_slice());
    code.extend_from_slice(&[0x5a, opcode]);
    code
}

const CALLDATACOPY_ALL: [u8; 6] = [0x36, 0x60, 0x00, 0x60, 0x00, 0x37];

/// Forwards the call and its value to the outbox; reverts if the outbox does.
fn forwarder() -> Vec<u8> {
    let mut code = CALLDATACOPY_ALL.to_vec();
    code.extend(call_outbox(&[0x34], 0xf1));
    let fail = code.len() as u8 + 5;
    code.extend_from_slice(&[0x15, 0x60, fail, 0x57, 0x00, 0x5b, 0x60, 0x00, 0x80, 0xfd]);
    code
}

/// Calls the outbox (successfully), then reverts its own frame.
fn forward_then_revert() -> Vec<u8> {
    let mut code = CALLDATACOPY_ALL.to_vec();
    code.extend(call_outbox(&[0x34], 0xf1));
    code.extend_from_slice(&[0x50, 0x60, 0x00, 0x80, 0xfd]);
    code
}

/// Two outbox calls of half the value each, in one frame.
fn forward_twice() -> Vec<u8> {
    let half = [0x60, 0x02, 0x34, 0x04];
    let mut code = CALLDATACOPY_ALL.to_vec();
    code.extend(call_outbox(&half, 0xf1));
    code.push(0x50);
    code.extend(call_outbox(&half, 0xf1));
    code.extend_from_slice(&[0x50, 0x00]);
    code
}

/// Runs the outbox code with `DELEGATECALL` (its own storage and address).
fn delegate() -> Vec<u8> {
    let mut code = CALLDATACOPY_ALL.to_vec();
    code.extend(call_outbox(&[], 0xf4));
    code.extend_from_slice(&[0x50, 0x00]);
    code
}

struct Chain {
    spec: ChainSpec,
    state: L2State,
    parent: NodeHeaderV2,
    nonce: u64,
    l1_height: u64,
}

impl Chain {
    fn new(spec: ChainSpec) -> Self {
        let mut state = genesis_v2(&spec, 10).unwrap();
        let parent = genesis_header(&spec, state.commit_root());
        Self {
            spec,
            state,
            parent,
            nonce: 0,
            l1_height: 1,
        }
    }

    fn context(&self) -> BlockContext {
        BlockContext {
            number: self.parent.number + 1,
            timestamp: self.parent.timestamp + 1,
            base_fee_per_gas: self
                .spec
                .next_base_fee(self.parent.base_fee_per_gas, self.parent.gas_used),
            prevrandao: B256::repeat_byte(7),
            anchor_root: B256::repeat_byte(8),
        }
    }

    fn deposit(&mut self, sats: u64) -> DepositMint {
        self.l1_height += 1;
        DepositMint {
            recipient: sender(),
            provenance: DepositProvenance::BridgedBlch {
                l1_height: self.l1_height,
                l1_tx_index: 0,
                l1_txid: [self.l1_height as u8; 32],
                l1_vout: 1,
                l1_sats: sats,
            },
        }
    }

    fn tx(&mut self, to: TxKind, value: U256, input: Bytes) -> Bytes {
        let tx = TxEip1559 {
            chain_id: self.spec.chain_id,
            nonce: self.nonce,
            to,
            value,
            input,
            gas_limit: 300_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            ..Default::default()
        };
        self.nonce += 1;
        let signature: Signature = key()
            .sign_prehash_recoverable(tx.signature_hash().as_slice())
            .unwrap()
            .into();
        TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
    }

    fn withdraw(&mut self, l1_recipient: B256, value: U256) -> Bytes {
        self.tx(TxKind::Call(OUTBOX), value, initiate(l1_recipient))
    }

    /// Execute a block, re-execute it statelessly from its witness and check
    /// that both agree, then check supply conservation.
    fn block(&mut self, deposits: Vec<DepositMint>, transactions: Vec<Bytes>) -> NodeExecutionOutcome {
        let body = NodeBodyV2 { deposits, transactions };
        let context = self.context();
        let (witness, recorded) =
            generate_node_batch_witness(&self.state, &self.spec, domain(), &context, &body).unwrap();
        let verified = verify_node_batch(&self.spec, domain(), &witness, &context, &body).unwrap();
        assert_eq!(verified.withdrawals, recorded.withdrawals);
        let outcome = execute_node_block(&self.spec, domain(), &mut self.state, &context, &body).unwrap();
        assert_eq!(outcome.header, recorded.header);
        assert_eq!(outcome.withdrawals, recorded.withdrawals);
        self.parent = outcome.header.clone();
        assert_eq!(
            self.state.total_native_wei(),
            self.state.total_minted_wei() - self.state.total_burned_wei() - self.state.total_withdrawn_wei(),
            "supply conservation"
        );
        outcome
    }

    fn commitment(&self) -> WithdrawalCommitment {
        self.state.withdrawal_commitment(OUTBOX).unwrap()
    }
}

fn wei(sats: u64) -> U256 {
    sats_to_wei(sats)
}

fn funded() -> Chain {
    let mut chain = Chain::new(ChainSpec::testnet_v3());
    let deposit = chain.deposit(100 * 100_000_000);
    let first = chain.block(vec![deposit], vec![]);
    // The first block installs the outbox; the empty tree is committed.
    assert_eq!(
        first.withdrawals.as_ref().unwrap().commitment,
        WithdrawalCommitment::empty()
    );
    assert_eq!(chain.state.account(&OUTBOX).unwrap().code_hash, keccak256(OUTBOX_CODE));
    chain
}

#[test]
fn withdrawals_burn_value_and_append_leaves() {
    let mut chain = funded();
    let chain_id = chain.spec.chain_id;
    let minted = chain.state.total_minted_wei();
    let before = chain.state.balance_of(&sender());
    let tx = chain.withdraw(recipient(0xa1), wei(2_500_000));
    let outcome = chain.block(vec![], vec![tx]);
    assert!(outcome.transactions[0].success);
    let summary = outcome.withdrawals.unwrap();
    let expected = Withdrawal {
        nonce: 0,
        l1_recipient: recipient(0xa1),
        sats: 2_500_000,
        sender: sender(),
    };
    assert_eq!(summary.withdrawals, vec![expected]);
    assert_eq!(summary.withdrawn_wei, wei(2_500_000));
    let mut leaves = vec![withdrawal_leaf(chain_id, 0, recipient(0xa1), 2_500_000)];
    let tree = WithdrawalTree::new(leaves.clone()).unwrap();
    assert_eq!(summary.commitment, tree.commitment());
    assert_eq!(chain.commitment(), tree.commitment());
    // The value left the L2 supply: nobody holds it, the ledger records it.
    assert_eq!(chain.state.balance_of(&OUTBOX), U256::ZERO);
    assert_eq!(chain.state.total_withdrawn_wei(), wei(2_500_000));
    assert_eq!(chain.state.total_minted_wei(), minted);
    let fee = before - chain.state.balance_of(&sender()) - wei(2_500_000);
    assert!(fee > U256::ZERO && fee < wei(100_000));

    // The event: (topic, nonce, l1Recipient) and data (sender, value in wei).
    let log = &outcome.transactions[0].result.logs()[0];
    assert_eq!(log.address, OUTBOX);
    assert_eq!(log.data.topics()[0], WITHDRAWAL_INITIATED_TOPIC);
    assert_eq!(log.data.topics()[2], recipient(0xa1));
    assert_eq!(&log.data.data[12..32], sender().as_slice());

    // Two more in one block, nonces 1 and 2; then an empty block keeps the root.
    let a = chain.withdraw(recipient(0xb2), wei(MIN_WITHDRAWAL_SATS));
    let b = chain.withdraw(recipient(0xc3), wei(7_000_000));
    let outcome = chain.block(vec![], vec![a, b]);
    leaves.push(withdrawal_leaf(chain_id, 1, recipient(0xb2), MIN_WITHDRAWAL_SATS));
    leaves.push(withdrawal_leaf(chain_id, 2, recipient(0xc3), 7_000_000));
    let tree = WithdrawalTree::new(leaves.clone()).unwrap();
    assert_eq!(outcome.withdrawals.unwrap().commitment, tree.commitment());
    let deposit = chain.deposit(5_000_000);
    let idle = chain.block(vec![deposit], vec![]);
    assert_eq!(idle.withdrawals.unwrap().commitment, tree.commitment());
    assert_eq!(
        chain.state.total_withdrawn_wei(),
        wei(2_500_000 + MIN_WITHDRAWAL_SATS + 7_000_000)
    );
    for (index, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof(index as u64).unwrap();
        assert!(verify_withdrawal_proof(
            *leaf,
            index as u64,
            &proof,
            chain.commitment().root
        ));
    }
}

#[test]
fn invalid_withdrawal_calls_revert_and_refund() {
    let mut chain = funded();
    let cases = [
        (
            "not a multiple of 10^10 wei",
            initiate(recipient(1)),
            wei(2_000_000) + U256::from(1),
        ),
        (
            "below the minimum",
            initiate(recipient(1)),
            wei(MIN_WITHDRAWAL_SATS - 1),
        ),
        ("zero value", initiate(recipient(1)), U256::ZERO),
        ("zero L1 recipient", initiate(B256::ZERO), wei(2_000_000)),
        ("plain transfer", Bytes::new(), wei(2_000_000)),
        (
            "unknown selector",
            {
                let mut data = initiate(recipient(1)).to_vec();
                data[0] ^= 1;
                data.into()
            },
            wei(2_000_000),
        ),
        (
            "trailing calldata",
            {
                let mut data = initiate(recipient(1)).to_vec();
                data.push(0);
                data.into()
            },
            wei(2_000_000),
        ),
        ("short calldata", initiate(recipient(1)).slice(..35), wei(2_000_000)),
    ];
    for (name, input, value) in cases {
        let before = chain.state.balance_of(&sender());
        let tx = chain.tx(TxKind::Call(OUTBOX), value, input);
        let outcome = chain.block(vec![], vec![tx]);
        assert!(!outcome.transactions[0].success, "{name} must revert");
        assert!(outcome.transactions[0].result.logs().is_empty(), "{name}");
        assert_eq!(
            outcome.withdrawals.unwrap().commitment,
            WithdrawalCommitment::empty(),
            "{name}"
        );
        // Only the fee was paid; the value came back.
        assert!(before - chain.state.balance_of(&sender()) < wei(100_000), "{name}");
        assert_eq!(chain.state.storage_of(&OUTBOX, OUTBOX_NONCE_SLOT), U256::ZERO, "{name}");
    }
    assert_eq!(chain.state.balance_of(&OUTBOX), U256::ZERO);
    assert_eq!(chain.state.total_withdrawn_wei(), U256::ZERO);
}

#[test]
fn contracts_withdraw_through_call_but_not_delegatecall() {
    let mut chain = funded();
    let chain_id = chain.spec.chain_id;
    let deployer = sender();
    let mut deployed = Vec::new();
    for runtime in [forwarder(), forward_then_revert(), forward_twice(), delegate()] {
        let address = deployer.create(chain.nonce);
        let tx = chain.tx(TxKind::Create, U256::ZERO, deploy(&runtime));
        let outcome = chain.block(vec![], vec![tx]);
        assert!(outcome.transactions[0].success);
        deployed.push(address);
    }
    let [forward, revert_after, twice, delegator] = deployed[..] else {
        unreachable!()
    };

    // A forwarding contract withdraws; the leaf names the L1 recipient, the
    // event names the contract as sender.
    let tx = chain.tx(TxKind::Call(forward), wei(3_000_000), initiate(recipient(0x11)));
    let outcome = chain.block(vec![], vec![tx]);
    let summary = outcome.withdrawals.unwrap();
    assert_eq!(summary.withdrawals.len(), 1);
    assert_eq!(summary.withdrawals[0].sender, forward);
    let mut leaves = vec![withdrawal_leaf(chain_id, 0, recipient(0x11), 3_000_000)];

    // A frame that reverts after a successful outbox call discards both the
    // nonce increment and the event: no leaf, no burn, value refunded.
    let tx = chain.tx(TxKind::Call(revert_after), wei(3_000_000), initiate(recipient(0x22)));
    let outcome = chain.block(vec![], vec![tx]);
    assert!(!outcome.transactions[0].success);
    assert!(outcome.withdrawals.unwrap().withdrawals.is_empty());
    assert_eq!(chain.state.balance_of(&revert_after), U256::ZERO);

    // Two outbox calls in one frame: two consecutive leaves (the outbox makes
    // no external call, so there is no reentrancy surface to order).
    let tx = chain.tx(TxKind::Call(twice), wei(4_000_000), initiate(recipient(0x33)));
    let outcome = chain.block(vec![], vec![tx]);
    let summary = outcome.withdrawals.unwrap();
    assert_eq!(
        summary.withdrawals.iter().map(|w| w.nonce).collect::<Vec<_>>(),
        vec![1, 2]
    );
    leaves.push(withdrawal_leaf(chain_id, 1, recipient(0x33), 2_000_000));
    leaves.push(withdrawal_leaf(chain_id, 2, recipient(0x33), 2_000_000));

    // DELEGATECALL runs the outbox code under the caller's address: its event
    // is not an outbox event, nothing is burned, the caller keeps the value.
    let tx = chain.tx(TxKind::Call(delegator), wei(5_000_000), initiate(recipient(0x44)));
    let outcome = chain.block(vec![], vec![tx]);
    assert!(outcome.transactions[0].success);
    assert_eq!(outcome.transactions[0].result.logs()[0].address, delegator);
    assert!(outcome.withdrawals.unwrap().withdrawals.is_empty());
    assert_eq!(chain.state.balance_of(&delegator), wei(5_000_000));

    let tree = WithdrawalTree::new(leaves).unwrap();
    assert_eq!(chain.commitment(), tree.commitment());
    assert_eq!(chain.state.total_withdrawn_wei(), wei(3_000_000 + 4_000_000));
    assert_eq!(chain.state.balance_of(&OUTBOX), U256::ZERO);
}

#[test]
fn value_forced_into_the_outbox_is_not_withdrawn() {
    let mut chain = funded();
    // Init code `PUSH20 outbox SELFDESTRUCT`: EIP-6780 sends the creation value
    // to the outbox without running its code.
    let mut init = vec![0x73];
    init.extend_from_slice(OUTBOX.as_slice());
    init.push(0xff);
    let tx = chain.tx(TxKind::Create, wei(9_000_000), init.into());
    let outcome = chain.block(vec![], vec![tx]);
    assert!(outcome.transactions[0].success);
    assert!(outcome.withdrawals.unwrap().withdrawals.is_empty());
    // It stays locked in the outbox and in the supply (no leaf, no burn).
    assert_eq!(chain.state.balance_of(&OUTBOX), wei(9_000_000));
    assert_eq!(chain.state.total_withdrawn_wei(), U256::ZERO);
    assert_eq!(chain.commitment(), WithdrawalCommitment::empty());
    // A later withdrawal burns exactly its own value.
    let tx = chain.withdraw(recipient(0x55), wei(2_000_000));
    chain.block(vec![], vec![tx]);
    assert_eq!(chain.state.balance_of(&OUTBOX), wei(9_000_000));
    assert_eq!(chain.state.total_withdrawn_wei(), wei(2_000_000));
}

#[test]
fn chains_without_the_outbox_have_no_withdrawals() {
    let mut chain = Chain::new(ChainSpec::testnet());
    let deposit = chain.deposit(100_000_000);
    chain.block(vec![deposit], vec![]);
    let tx = chain.withdraw(recipient(1), wei(2_000_000));
    let outcome = chain.block(vec![], vec![tx]);
    // No code at the address: a plain transfer to an empty account.
    assert!(outcome.transactions[0].success);
    assert!(outcome.withdrawals.is_none());
    assert_eq!(chain.state.balance_of(&OUTBOX), wei(2_000_000));
    assert!(chain.state.account(&OUTBOX).unwrap().code_hash != keccak256(OUTBOX_CODE));
}

#[test]
fn settlement_v3_publishes_the_post_block_commitment() {
    let mut chain = funded();
    let context = chain.context();
    let a = chain.withdraw(recipient(0x61), wei(1_500_000));
    let b = chain.withdraw(recipient(0x62), wei(1_600_000));
    let body = NodeBodyV2 {
        deposits: vec![],
        transactions: vec![a, b],
    };
    let (witness, recorded) =
        generate_node_batch_witness(&chain.state, &chain.spec, domain(), &context, &body).unwrap();
    let settlement = SettlementContextV2 {
        network: B256::repeat_byte(0x41),
        genesis: B256::repeat_byte(0x42),
        program_elf_keccak: B256::repeat_byte(0x43),
        program_vkey_koalabear: B256::repeat_byte(0x44),
        program_vkey_bn254: B256::repeat_byte(0x45),
        previous_settlement: B256::repeat_byte(0x48),
        l1_slot: 9,
        l1_height: 8,
        source_commitment: B256::repeat_byte(0x46),
        inbox_root: B256::repeat_byte(0x47),
        inbox_count: 1,
        consumed_start: 1,
        consumed_end: 1,
    };
    let statement =
        execute_settlement_statement_v3(&chain.spec, domain(), &witness, &context, &body, settlement).unwrap();
    let tree = WithdrawalTree::new(vec![
        withdrawal_leaf(chain.spec.chain_id, 0, recipient(0x61), 1_500_000),
        withdrawal_leaf(chain.spec.chain_id, 1, recipient(0x62), 1_600_000),
    ])
    .unwrap();
    assert_eq!(
        (statement.withdrawal_root, statement.withdrawal_count),
        (tree.root(), 2)
    );
    assert_eq!(recorded.withdrawals.unwrap().commitment, tree.commitment());
    assert_ne!(statement.withdrawal_root, empty_withdrawal_root());
}

/// Shared vectors (`tests/fixtures/l2-withdrawal-v1/vectors.json`), rebuilt
/// independently by the native repository and by `tools/withdrawal_vectors.py`.
/// Leaf `i` of the vector trees: chain 700771, nonce `i`, recipient 32 bytes of
/// `(i % 255) + 1`, sats `1_000_000 + i`.
#[test]
fn shared_withdrawal_vectors() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/l2-withdrawal-v1/vectors.json")).unwrap();
    let hex = |v: &serde_json::Value| -> B256 { v.as_str().unwrap().parse().unwrap() };
    let chain_id = fixture["chain_id"].as_u64().unwrap();
    assert_eq!(hex(&fixture["empty_root"]), empty_withdrawal_root());
    for leaf in fixture["leaves"].as_array().unwrap() {
        let computed = withdrawal_leaf(
            leaf["chain_id"].as_u64().unwrap(),
            leaf["nonce"].as_u64().unwrap(),
            hex(&leaf["l1_recipient"]),
            leaf["sats"].as_u64().unwrap(),
        );
        assert_eq!(computed, hex(&leaf["leaf"]));
    }
    let vector_leaf = |i: u64| withdrawal_leaf(chain_id, i, B256::repeat_byte((i % 255) as u8 + 1), 1_000_000 + i);
    for tree in fixture["trees"].as_array().unwrap() {
        let count = tree["count"].as_u64().unwrap();
        let built = WithdrawalTree::new((0..count).map(vector_leaf).collect()).unwrap();
        assert_eq!(built.root(), hex(&tree["root"]), "{count} leaves");
        for proof in tree["proofs"].as_array().unwrap() {
            let index = proof["index"].as_u64().unwrap();
            let siblings: Vec<B256> = proof["siblings"].as_array().unwrap().iter().map(hex).collect();
            let siblings: [B256; 32] = siblings.try_into().unwrap();
            assert_eq!(built.proof(index).unwrap(), siblings);
            assert!(verify_withdrawal_proof(
                vector_leaf(index),
                index,
                &siblings,
                built.root()
            ));
        }
    }
}

/// Regenerate the shared vectors (prints JSON). Run with `--ignored --nocapture`.
#[test]
#[ignore]
fn print_shared_withdrawal_vectors() {
    let chain_id = 700_771u64;
    let vector_leaf = |i: u64| withdrawal_leaf(chain_id, i, B256::repeat_byte((i % 255) as u8 + 1), 1_000_000 + i);
    let leaves = [(700_771u64, 0u64, B256::repeat_byte(0x11), 1_000_000u64), (700_771, 41, B256::repeat_byte(0xa5), 123_456_789), (1, u64::MAX, B256::repeat_byte(0xff), u64::MAX)]
        .iter()
        .map(|(c, n, r, s)| serde_json::json!({"chain_id": c, "nonce": n, "l1_recipient": r, "sats": s, "leaf": withdrawal_leaf(*c, *n, *r, *s)}))
        .collect::<Vec<_>>();
    let trees = [
        (1u64, vec![0u64]),
        (2, vec![0, 1]),
        (3, vec![0, 2]),
        (1000, vec![0, 511, 777, 999]),
    ]
    .iter()
    .map(|(count, indices)| {
        let tree = WithdrawalTree::new((0..*count).map(vector_leaf).collect()).unwrap();
        let proofs = indices
            .iter()
            .map(|i| serde_json::json!({"index": i, "siblings": tree.proof(*i).unwrap().to_vec()}))
            .collect::<Vec<_>>();
        serde_json::json!({"count": count, "root": tree.root(), "proofs": proofs})
    })
    .collect::<Vec<_>>();
    let fixture = serde_json::json!({
        "format": "BLOCH:L2:WITHDRAW:1 leaf = keccak256(domain || chain_id BE8 || nonce BE8 || l1_recipient || sats BE8); node = keccak256(left || right); depth 32; empty leaf = 0x00..00; tree leaf i = (chain_id, i, bytes32 of (i % 255) + 1, 1000000 + i)",
        "chain_id": chain_id,
        "empty_root": empty_withdrawal_root(),
        "leaves": leaves,
        "trees": trees,
    });
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}

/// Shared L1 claim vector (`tests/fixtures/l2-claim-v1/vectors.json`,
/// identical copy in the native repository, which pins the 0x16 frame, intent
/// root and txid). The L2 side checks what it owns: the claimed leaf is leaf 1
/// of the 3-leaf vector tree, its proof folds to the vector root, and the
/// nullifier a relayer looks up is keccak256("BLOCH:L2:CLAIM:1" || chain_id
/// BE8 || index BE8).
#[test]
fn shared_claim_vector() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/l2-claim-v1/vectors.json")).unwrap();
    let hex = |v: &serde_json::Value| -> B256 { v.as_str().unwrap().parse().unwrap() };
    let chain_id = fixture["chain_id"].as_u64().unwrap();
    let (index, count) = (fixture["index"].as_u64().unwrap(), fixture["count"].as_u64().unwrap());
    let vector_leaf = |i: u64| withdrawal_leaf(chain_id, i, B256::repeat_byte((i % 255) as u8 + 1), 1_000_000 + i);
    let leaf = withdrawal_leaf(chain_id, index, hex(&fixture["l1_recipient"]), fixture["sats"].as_u64().unwrap());
    assert_eq!(leaf, hex(&fixture["leaf"]));
    assert_eq!(leaf, vector_leaf(index));
    let tree = WithdrawalTree::new((0..count).map(vector_leaf).collect()).unwrap();
    assert_eq!(tree.root(), hex(&fixture["root"]));
    assert!(verify_withdrawal_proof(leaf, index, &tree.proof(index).unwrap(), tree.root()));
    let mut preimage = b"BLOCH:L2:CLAIM:1".to_vec();
    preimage.extend_from_slice(&chain_id.to_be_bytes());
    preimage.extend_from_slice(&index.to_be_bytes());
    assert_eq!(keccak256(&preimage), hex(&fixture["nullifier"]));
    // The frame names this leaf: tag 0x16, version 1.
    assert!(fixture["tx_hex"].as_str().unwrap().starts_with("1601"));
}
