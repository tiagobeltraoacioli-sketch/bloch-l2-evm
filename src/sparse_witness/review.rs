// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent adversarial review of the sparse witness (agent 88).
//!
//! Two kinds of test: a trie-level property (any exposure of any trie and any change
//! set either refuses or gives the true answer), and EVM-level blocks that aim at the
//! shapes a keccak-spread benchmark contract does not reach: inline trie nodes,
//! collapses onto untouched siblings, destruction of accounts already in the trie,
//! recreation in one block, ring deletions, and every opcode that reads state.

use super::*;
use crate::chainspec::{BEACON_ROOTS_ADDRESS, MAINNET_DOMAIN};
use crate::mpt::Mpt;
use crate::node_execution::{execute_node_block, genesis_v2, node_head};
use crate::proof_statement::execute_settlement_statement_v3;
use crate::state::{DepositMint, DepositProvenance};
use crate::stateroot::SparseTrieView;
use crate::withdrawal::{L2_TO_L1_MESSAGE_PASSER, INITIATE_WITHDRAWAL_SELECTOR};
use alloc::collections::BTreeMap;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Signature, TxKind};
use alloy_trie::HashBuilder;
use k256::ecdsa::SigningKey;

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

struct Rng(B256);

impl Rng {
    fn new(seed: &[u8]) -> Self {
        Self(keccak256(seed))
    }
    fn next(&mut self, bound: u64) -> u64 {
        self.0 = keccak256(self.0);
        u64::from_be_bytes(self.0[..8].try_into().unwrap()) % bound
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next(100) < percent
    }
    fn word(&mut self) -> B256 {
        self.0 = keccak256(self.0);
        self.0
    }
}

/// `REVIEW_SCALE` multiplies the randomized rounds.
fn scale() -> u64 {
    std::env::var("REVIEW_SCALE").ok().and_then(|text| text.parse().ok()).unwrap_or(1)
}

// ---------------------------------------------------------------------------
// Trie-level property
// ---------------------------------------------------------------------------

/// A 64-nibble key that shares `shared` nibbles with `base`, and differs right after.
fn clustered_key(rng: &mut Rng, base: &[u8; 64], shared: usize) -> Nibbles {
    let mut nibbles = *base;
    let tail = rng.word();
    for (index, nibble) in nibbles.iter_mut().enumerate().skip(shared) {
        let byte = tail[index / 2];
        *nibble = if index % 2 == 0 { byte >> 4 } else { byte & 0xf };
    }
    if shared < 64 && nibbles[shared] == base[shared] {
        nibbles[shared] = (base[shared] + 1) & 0xf;
    }
    Nibbles::from_nibbles_unchecked(nibbles)
}

fn random_key_set(rng: &mut Rng, count: u64) -> Vec<Nibbles> {
    let mut base = [0u8; 64];
    let seed = rng.word();
    for (index, nibble) in base.iter_mut().enumerate() {
        *nibble = if index % 2 == 0 { seed[index / 2] >> 4 } else { seed[index / 2] & 0xf };
    }
    const DEPTHS: [usize; 12] = [0, 1, 2, 3, 8, 9, 20, 40, 56, 60, 62, 63];
    let mut keys = BTreeSet::new();
    for _ in 0..count {
        let shared = DEPTHS[rng.next(DEPTHS.len() as u64) as usize];
        let key = clustered_key(rng, &base, shared);
        keys.insert(key);
        // Now and then a cluster around that key, so that branches have few children.
        if rng.chance(30) {
            let mut around = [0u8; 64];
            for (index, nibble) in around.iter_mut().enumerate() {
                *nibble = key.get_unchecked(index);
            }
            let shared = DEPTHS[rng.next(DEPTHS.len() as u64) as usize];
            keys.insert(clustered_key(rng, &around, shared));
        }
    }
    keys.into_iter().collect()
}

fn random_value(rng: &mut Rng) -> Vec<u8> {
    let value = match rng.next(3) {
        0 => U256::from(1 + rng.next(120)),
        1 => U256::from(1 + rng.next(1 << 40)),
        _ => U256::from_be_bytes(rng.word().0) | U256::from(1),
    };
    alloy_rlp::encode(value)
}

/// The independent oracle: a from-scratch root over the leaves.
fn rebuilt_root(leaves: &BTreeMap<Nibbles, Vec<u8>>) -> B256 {
    if leaves.is_empty() {
        return alloy_trie::EMPTY_ROOT_HASH;
    }
    let mut builder = HashBuilder::default();
    for (key, value) in leaves {
        builder.add_leaf(*key, value);
    }
    builder.root()
}

#[derive(Default, Debug)]
struct PropertyStats {
    tries: u64,
    accepted: u64,
    refused: u64,
    accepted_deletes: u64,
    lookups_some: u64,
    lookups_none: u64,
    lookups_err: u64,
    needs_expansion: u64,
}

fn property_round(rng: &mut Rng, stats: &mut PropertyStats) {
    let size = 1 + rng.next(48);
    let keys = random_key_set(rng, size);
    let mut truth: BTreeMap<Nibbles, Vec<u8>> = BTreeMap::new();
    let mut trie = Mpt::new();
    for key in &keys {
        let value = random_value(rng);
        trie.insert(*key, value.clone());
        truth.insert(*key, value);
    }
    let root = trie.root();
    assert_eq!(root, rebuilt_root(&truth), "Mpt and HashBuilder disagree");
    stats.tries += 1;

    let absent = random_key_set(rng, 12);
    let universe: Vec<Nibbles> = keys.iter().chain(&absent).copied().collect();

    for _ in 0..4 {
        // Any exposure: a random target set, then random nodes taken out again. A
        // malicious prover chooses exactly this.
        let targets: Vec<Nibbles> = universe.iter().copied().filter(|_| rng.chance(35)).collect();
        let mut proof = trie.proof(targets).unwrap();
        let removable: Vec<Nibbles> = proof.keys().copied().filter(|path| !path.is_empty()).collect();
        for path in removable {
            if rng.chance(12) {
                proof.remove(&path);
            }
        }
        let view = IndexedTrieView::from_proof(root, &proof).expect("real nodes authenticate");
        let plain = SparseTrieView::from_proof(root, &proof).expect("real nodes authenticate");

        // No read may be wrong.
        for key in &universe {
            match view.lookup(key) {
                Ok(Some(value)) => {
                    stats.lookups_some += 1;
                    assert_eq!(truth.get(key).map(Vec::as_slice), Some(value), "wrong value");
                }
                Ok(None) => {
                    stats.lookups_none += 1;
                    assert!(!truth.contains_key(key), "a live key was proved absent");
                }
                Err(_) => stats.lookups_err += 1,
            }
            match (view.lookup(key), plain.contains_key(key)) {
                (Ok(Some(_)), Ok(true)) | (Ok(None), Ok(false)) | (Err(_), Err(_)) => {}
                (a, b) => panic!("indexed {a:?} and plain {b:?} differ"),
            }
        }

        // No root may be wrong.
        let mut changes: BTreeMap<Nibbles, Option<Vec<u8>>> = BTreeMap::new();
        let mut after = truth.clone();
        let mut deletes = 0;
        for key in &universe {
            // Mostly keys the proof can answer, so that apply runs often. A few others
            // keep the refusals honest.
            if !rng.chance(if view.lookup(key).is_ok() { 45 } else { 2 }) {
                continue;
            }
            if truth.contains_key(key) && rng.chance(60) {
                changes.insert(*key, None);
                after.remove(key);
                deletes += 1;
            } else {
                let value = random_value(rng);
                changes.insert(*key, Some(value.clone()));
                after.insert(*key, value);
            }
        }
        let expected = rebuilt_root(&after);
        let mut updated = trie.clone();
        for (key, change) in &changes {
            match change {
                Some(value) => {
                    updated.insert(*key, value.clone());
                }
                None => {
                    updated.remove(key);
                }
            }
        }
        assert_eq!(updated.root(), expected, "Mpt update and HashBuilder rebuild disagree");
        let indexed = view.apply(&changes);
        match (&indexed, plain.apply(&changes)) {
            (Ok(a), Ok(b)) => assert_eq!(*a, b),
            (Err(a), Err(b)) => assert_eq!(*a, b),
            (a, b) => panic!("indexed {a:?} and plain {b:?} apply differ"),
        }
        match indexed {
            Ok(derived) => {
                assert_eq!(derived, expected, "a partial trie derived a wrong root; {} changes", changes.len());
                stats.accepted += 1;
                if deletes > 0 {
                    stats.accepted_deletes += 1;
                }
            }
            Err(WitnessError::OpaqueChildNeedsExpansion { .. }) => {
                stats.refused += 1;
                stats.needs_expansion += 1;
            }
            Err(_) => stats.refused += 1,
        }
    }
}

/// The soundness core. A prover picks the exposure; the guest picks nothing. For any
/// exposure, a lookup is true or an error, and a root is the true root or an error.
#[test]
fn any_exposure_of_any_trie_answers_truly_or_refuses() {
    let mut rng = Rng::new(b"review-trie-property");
    let mut stats = PropertyStats::default();
    for _ in 0..4000 * scale() {
        property_round(&mut rng, &mut stats);
    }
    std::println!("{stats:?}");
    assert!(stats.accepted > 2000 && stats.accepted_deletes > 500 && stats.needs_expansion > 50, "{stats:?}");
}

/// `IndexedTrieView` relies on this order for its range query, and `apply` for its sort.
#[test]
fn nibble_order_is_lexicographic_with_a_prefix_first() {
    let mut rng = Rng::new(b"review-nibble-order");
    for _ in 0..200_000 {
        let word = rng.word();
        let mut a = Nibbles::unpack(word);
        let b_word = if rng.chance(50) { word } else { rng.word() };
        let mut b = Nibbles::unpack(b_word);
        a = a.slice(..rng.next(65) as usize);
        b = b.slice(..rng.next(65) as usize);
        assert_eq!(a.cmp(&b), a.to_vec().cmp(&b.to_vec()), "{a:?} {b:?}");
    }
}

// ---------------------------------------------------------------------------
// The script contract: every state-reading opcode, driven by calldata
// ---------------------------------------------------------------------------

const SSTORE: u64 = 0;
const SLOAD: u64 = 1;
const BALANCE: u64 = 2;
const EXTCODESIZE: u64 = 3;
const EXTCODEHASH: u64 = 4;
const BLOCKHASH: u64 = 5;
const CALL: u64 = 6;
const STATICCALL: u64 = 7;
const DELEGATECALL: u64 = 8;
const CALLCODE: u64 = 9;
const SELFDESTRUCT: u64 = 10;
const CREATE2: u64 = 11;
const FORWARD: u64 = 12;
const REVERT: u64 = 13;
const EXTCODECOPY: u64 = 14;

/// Each entry is three words `op, a, b`. Reading ops log what they read, so a wrong
/// read changes the receipts root and the statement. `CREATE2` and `FORWARD` take the
/// rest of the calldata as initcode or call data and end the script.
fn script_runtime() -> Vec<u8> {
    enum I {
        B(&'static [u8]),
        L(&'static str),
        J(&'static str),
    }
    use I::*;
    let cleanup_call: &'static [u8] = &[0x91, 0x50, 0x50]; // SWAP2 POP POP
    let program = [
        B(&[0x60, 0x00]), // i
        L("loop"),
        B(&[0x36, 0x81, 0x10, 0x15]), // CALLDATASIZE DUP2 LT ISZERO
        J("stop"),
        B(&[0x57]),
        B(&[0x80, 0x35]),                   // op
        B(&[0x81, 0x60, 0x20, 0x01, 0x35]), // a
        B(&[0x82, 0x60, 0x40, 0x01, 0x35]), // b
        B(&[0x91]),                         // SWAP2: i b a op
        B(&[0x80, 0x60, 0, 0x14]),
        J("sstore"),
        B(&[0x57, 0x80, 0x60, 1, 0x14]),
        J("sload"),
        B(&[0x57, 0x80, 0x60, 2, 0x14]),
        J("balance"),
        B(&[0x57, 0x80, 0x60, 3, 0x14]),
        J("extcodesize"),
        B(&[0x57, 0x80, 0x60, 4, 0x14]),
        J("extcodehash"),
        B(&[0x57, 0x80, 0x60, 5, 0x14]),
        J("blockhash"),
        B(&[0x57, 0x80, 0x60, 6, 0x14]),
        J("call"),
        B(&[0x57, 0x80, 0x60, 7, 0x14]),
        J("staticcall"),
        B(&[0x57, 0x80, 0x60, 8, 0x14]),
        J("delegatecall"),
        B(&[0x57, 0x80, 0x60, 9, 0x14]),
        J("callcode"),
        B(&[0x57, 0x80, 0x60, 10, 0x14]),
        J("selfdestruct"),
        B(&[0x57, 0x80, 0x60, 11, 0x14]),
        J("create2"),
        B(&[0x57, 0x80, 0x60, 12, 0x14]),
        J("forward"),
        B(&[0x57, 0x80, 0x60, 14, 0x14]),
        J("extcodecopy"),
        B(&[0x57]),
        B(&[0x60, 0x00, 0x60, 0x00, 0xfd]), // op 13 and unknown: REVERT
        L("sstore"),
        B(&[0x50, 0x55]), // POP op; SSTORE(a, b)
        J("next"),
        B(&[0x56]),
        L("sload"),
        B(&[0x50, 0x54, 0x90, 0x50]), // POP op; SLOAD; SWAP1 POP
        J("emit"),
        B(&[0x56]),
        L("balance"),
        B(&[0x50, 0x31, 0x90, 0x50]),
        J("emit"),
        B(&[0x56]),
        L("extcodesize"),
        B(&[0x50, 0x3b, 0x90, 0x50]),
        J("emit"),
        B(&[0x56]),
        L("extcodehash"),
        B(&[0x50, 0x3f, 0x90, 0x50]),
        J("emit"),
        B(&[0x56]),
        L("blockhash"),
        B(&[0x50, 0x40, 0x90, 0x50]),
        J("emit"),
        B(&[0x56]),
        L("extcodecopy"),
        // POP op; [i b a]; EXTCODECOPY(a, 0, 0, 32); log mem[0]
        B(&[0x50, 0x60, 0x20, 0x60, 0x00, 0x60, 0x00, 0x83, 0x3c, 0x50, 0x60, 0x00, 0x51, 0x90, 0x50]),
        J("emit"),
        B(&[0x56]),
        L("call"),
        // POP op; 0 0 0 0; DUP6 value; DUP6 address; GAS; CALL
        B(&[0x50, 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x85, 0x85, 0x5a, 0xf1]),
        B(cleanup_call),
        J("emit"),
        B(&[0x56]),
        L("callcode"),
        B(&[0x50, 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x85, 0x85, 0x5a, 0xf2]),
        B(cleanup_call),
        J("emit"),
        B(&[0x56]),
        L("staticcall"),
        // POP op; 0 0 0 0; DUP5 address; GAS; STATICCALL
        B(&[0x50, 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x84, 0x5a, 0xfa]),
        B(cleanup_call),
        J("emit"),
        B(&[0x56]),
        L("delegatecall"),
        B(&[0x50, 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x84, 0x5a, 0xf4]),
        B(cleanup_call),
        J("emit"),
        B(&[0x56]),
        L("selfdestruct"),
        B(&[0x50, 0xff]),
        L("create2"),
        // POP op; [i b a]; offset = i + 96; len = size - offset; CALLDATACOPY(0, offset, len)
        B(&[0x50, 0x82, 0x60, 0x60, 0x01, 0x80, 0x36, 0x03, 0x90, 0x81, 0x90, 0x60, 0x00, 0x37]),
        // [i b a len]; 0; DUP4 value; CREATE2(value, 0, len, salt = a)
        B(&[0x60, 0x00, 0x83, 0xf5, 0x90, 0x50]),
        J("emitstop"),
        B(&[0x56]),
        L("forward"),
        B(&[0x50, 0x82, 0x60, 0x60, 0x01, 0x80, 0x36, 0x03, 0x90, 0x81, 0x90, 0x60, 0x00, 0x37]),
        // [i b a len]; 0 0; DUP3 len; 0 0; DUP7 address; DUP9 gas; CALL
        B(&[0x60, 0, 0x60, 0, 0x82, 0x60, 0, 0x60, 0, 0x86, 0x88, 0xf1]),
        J("emitstop"),
        B(&[0x56]),
        L("emit"),
        B(&[0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xa0]),
        L("next"),
        B(&[0x60, 0x60, 0x01]),
        J("loop"),
        B(&[0x56]),
        L("emitstop"),
        B(&[0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xa0, 0x00]),
        L("stop"),
        B(&[0x00]),
    ];
    let mut labels: BTreeMap<&str, usize> = BTreeMap::new();
    let mut offset = 0;
    for item in &program {
        match item {
            B(bytes) => offset += bytes.len(),
            L(name) => {
                labels.insert(name, offset);
                offset += 1;
            }
            J(_) => offset += 3,
        }
    }
    let mut code = Vec::with_capacity(offset);
    for item in &program {
        match item {
            B(bytes) => code.extend_from_slice(bytes),
            L(_) => code.push(0x5b),
            J(name) => {
                let target = labels[name];
                code.extend_from_slice(&[0x61, (target >> 8) as u8, target as u8]);
            }
        }
    }
    code
}

fn entry(op: u64, a: U256, b: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(&U256::from(op).to_be_bytes::<32>());
    data.extend_from_slice(&a.to_be_bytes::<32>());
    data.extend_from_slice(&b.to_be_bytes::<32>());
    data
}

fn word_of(address: Address) -> U256 {
    U256::from_be_slice(address.as_slice())
}

fn script(entries: &[(u64, U256, U256)]) -> Bytes {
    entries.iter().flat_map(|(op, a, b)| entry(*op, *a, *b)).collect::<Vec<u8>>().into()
}

fn u(value: u64) -> U256 {
    U256::from(value)
}

/// Initcode: `sstore(1, 5)`, then SELFDESTRUCT to `beneficiary`.
fn destroying_initcode(beneficiary: u8) -> Vec<u8> {
    vec![0x60, 0x05, 0x60, 0x01, 0x55, 0x60, beneficiary, 0xff]
}

/// Initcode: `sstore(1, value)`, then deploys `runtime`.
fn storing_initcode(value: u8, runtime: &[u8]) -> Vec<u8> {
    let len = runtime.len();
    let (high, low) = ((len >> 8) as u8, len as u8);
    // PUSH1 v PUSH1 1 SSTORE PUSH2 len PUSH1 19 PUSH1 0 CODECOPY PUSH2 len PUSH1 0 RETURN
    let mut code = vec![
        0x60, value, 0x60, 0x01, 0x55, 0x61, high, low, 0x60, 19, 0x60, 0x00, 0x39, 0x61, high, low, 0x60, 0x00, 0xf3,
    ];
    code.extend_from_slice(runtime);
    code
}

// ---------------------------------------------------------------------------
// Chain harness
// ---------------------------------------------------------------------------

struct Chain {
    spec: ChainSpec,
    state: L2State,
    key: SigningKey,
    sender: Address,
    nonce: u64,
    deposits: u64,
    anchor: B256,
    timestamp_step: u64,
}

impl Chain {
    fn new(spec: ChainSpec) -> Self {
        let mut state = genesis_v2(&spec, 0).unwrap();
        state.commit_root();
        let key = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let sender = Address::from_public_key(key.verifying_key());
        let mut chain = Self {
            spec,
            state,
            key,
            sender,
            nonce: 0,
            deposits: 0,
            anchor: B256::repeat_byte(8),
            timestamp_step: 1,
        };
        let sender = chain.sender;
        let body = chain.deposit_body(sender, vec![]);
        chain.commit(&body);
        chain
    }

    fn deposit_to(&mut self, recipient: Address, sats: u64) -> DepositMint {
        self.deposits += 1;
        DepositMint {
            recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: self.deposits,
                l1_tx_index: 0,
                l1_txid: [0xd3; 32],
                l1_vout: 0,
                l1_sats: sats,
            },
        }
    }

    fn deposit_body(&mut self, recipient: Address, transactions: Vec<Bytes>) -> NodeBodyV2 {
        NodeBodyV2 {
            deposits: vec![self.deposit_to(recipient, 100_000_000_000)],
            transactions,
        }
    }

    fn body(&mut self, transactions: Vec<Bytes>) -> NodeBodyV2 {
        let sender = self.sender;
        self.deposit_body(sender, transactions)
    }

    fn tx(&mut self, to: TxKind, value: U256, input: Bytes, gas_limit: u64) -> Bytes {
        let transaction = TxEip1559 {
            chain_id: self.spec.chain_id,
            nonce: self.nonce,
            to,
            value,
            input,
            gas_limit,
            max_fee_per_gas: 200_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            ..Default::default()
        };
        self.nonce += 1;
        let signature: Signature = self
            .key
            .sign_prehash_recoverable(transaction.signature_hash().as_slice())
            .unwrap()
            .into();
        TxEnvelope::from(transaction.into_signed(signature)).encoded_2718().into()
    }

    fn call(&mut self, to: Address, input: Bytes) -> Bytes {
        self.tx(TxKind::Call(to), U256::ZERO, input, 3_000_000)
    }

    fn pay(&mut self, to: Address, value: u64) -> Bytes {
        self.tx(TxKind::Call(to), U256::from(value), Bytes::new(), 21_000)
    }

    fn context(&self) -> BlockContext {
        let parent = node_head(&self.spec, MAINNET_DOMAIN, &self.state).unwrap();
        BlockContext {
            number: parent.number + 1,
            timestamp: match self.spec.block_derivation {
                Some(rule) => rule.timestamp(parent.timestamp, 1).unwrap(),
                None => parent.timestamp + self.timestamp_step,
            },
            base_fee_per_gas: self.spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
            prevrandao: match self.spec.block_derivation {
                Some(rule) => rule.prevrandao,
                None => B256::repeat_byte(7),
            },
            anchor_root: self.anchor,
        }
    }

    fn commit(&mut self, body: &NodeBodyV2) -> NodeExecutionOutcome {
        let context = self.context();
        let outcome = execute_node_block(&self.spec, MAINNET_DOMAIN, &mut self.state, &context, body).unwrap();
        self.state.commit_root();
        outcome
    }

    fn settlement(body: &NodeBodyV2) -> SettlementContextV2 {
        SettlementContextV2 {
            network: B256::repeat_byte(0x41),
            genesis: B256::repeat_byte(0x42),
            program_elf_keccak: B256::repeat_byte(0x43),
            program_vkey_koalabear: B256::repeat_byte(0x44),
            program_vkey_bn254: B256::repeat_byte(0x45),
            previous_settlement: B256::repeat_byte(0x48),
            l1_slot: 1,
            l1_height: 1,
            source_commitment: B256::repeat_byte(0x46),
            inbox_root: B256::repeat_byte(0x47),
            inbox_count: body.deposits.len() as u64,
            consumed_start: 0,
            consumed_end: body.deposits.len() as u64,
        }
    }

    /// The differential: canonical, complete witness, sparse lazy and sparse eager
    /// must agree byte for byte on the statement. A generator failure is a liveness
    /// bug; the panic names it.
    fn differential(&self, body: &NodeBodyV2, what: &str) -> (SparseBatchWitness, NodeExecutionOutcome, BlockContext) {
        let context = self.context();
        let settlement = Self::settlement(body);
        let (complete, _) = generate_node_batch_witness(&self.state, &self.spec, MAINNET_DOMAIN, &context, body)
            .unwrap_or_else(|error| panic!("{what}: complete witness: {error}"));
        // A settlement statement refuses a zero anchor (it is the L1 block), so a block
        // under one can never settle. The transition itself is still compared.
        let expected = (context.anchor_root != B256::ZERO).then(|| {
            execute_settlement_statement_v3(&self.spec, MAINNET_DOMAIN, &complete, &context, body, settlement)
                .unwrap_or_else(|error| panic!("{what}: complete statement: {error:?}"))
        });
        let mut lazy = None;
        for mode in [BlockHashes::Eager, BlockHashes::Lazy] {
            let (witness, canonical) =
                generate_sparse_node_witness(&self.state, &self.spec, MAINNET_DOMAIN, &context, body, mode)
                    .unwrap_or_else(|error| panic!("{what}: sparse witness {mode:?}: {error}"));
            if let Some(expected) = &expected {
                let statement =
                    execute_settlement_statement_v3_sparse(&self.spec, MAINNET_DOMAIN, &witness, &context, body, settlement, mode)
                        .unwrap_or_else(|error| panic!("{what}: sparse statement {mode:?}: {error}"));
                assert_eq!(statement.encode(), expected.encode(), "{what}: statement differs {mode:?}");
            } else {
                let verified = verify_node_batch_sparse(&self.spec, MAINNET_DOMAIN, &witness, &context, body, mode)
                    .unwrap_or_else(|error| panic!("{what}: sparse verify {mode:?}: {error}"));
                assert_eq!(verified.header, canonical.header, "{what}: header differs {mode:?}");
            }
            if mode == BlockHashes::Lazy {
                lazy = Some((witness, canonical));
            }
        }
        let (witness, canonical) = lazy.unwrap();
        (witness, canonical, context)
    }

    /// Differential, then commit.
    fn check(&mut self, body: &NodeBodyV2, what: &str) -> NodeExecutionOutcome {
        self.differential(body, what);
        let outcome = self.commit(body);
        // The state after the commit must be the root the witness derived, checked
        // by the differential through the header. Warm again for the next block.
        outcome
    }

    fn verify(&self, witness: &SparseBatchWitness, context: &BlockContext, body: &NodeBodyV2) -> Result<NodeExecutionOutcome, SparseNodeError> {
        verify_node_batch_sparse(&self.spec, MAINNET_DOMAIN, witness, context, body, BlockHashes::Lazy)
    }

    fn deploy_script(&mut self) -> Address {
        let address = self.sender.create(self.nonce);
        let tx = self.tx(TxKind::Create, U256::ZERO, deploy_code(&script_runtime()).into(), 3_000_000);
        let body = self.body(vec![tx]);
        let outcome = self.commit(&body);
        assert!(outcome.transactions[0].success, "script deployment failed");
        address
    }

    fn logged_word(outcome: &NodeExecutionOutcome, tx: usize, log: usize) -> U256 {
        U256::from_be_slice(&outcome.transactions[tx].result.logs()[log].data.data)
    }
}

fn both_rules() -> [ChainSpec; 2] {
    [ChainSpec::mainnet_v1(), ChainSpec::mainnet()]
}

/// Slots whose keccak keys share at least `bytes` leading bytes, in groups.
fn mined_slots(bytes: usize, groups: usize) -> Vec<Vec<u64>> {
    let mut seen: BTreeMap<Vec<u8>, Vec<u64>> = BTreeMap::new();
    let mut out = Vec::new();
    let mut slot = 1u64;
    while out.len() < groups {
        let key = keccak256(U256::from(slot).to_be_bytes::<32>());
        let group = seen.entry(key[..bytes].to_vec()).or_default();
        group.push(slot);
        if group.len() == 2 {
            out.push(group.clone());
        }
        slot += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// The script itself
// ---------------------------------------------------------------------------

#[test]
fn the_script_contract_does_what_it_says() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let script_a = chain.deploy_script();
    let script_b = chain.deploy_script();
    let tx = chain.call(script_a, script(&[(SSTORE, u(7), u(11)), (SLOAD, u(7), u(0)), (BALANCE, word_of(chain.sender), u(0))]));
    let body = chain.body(vec![tx]);
    let outcome = chain.check(&body, "sstore+sload");
    assert!(outcome.transactions[0].success);
    assert_eq!(Chain::logged_word(&outcome, 0, 0), u(11));
    assert_ne!(Chain::logged_word(&outcome, 0, 1), u(0));

    let runtime_len = script_runtime().len() as u64;
    let tx = chain.call(
        script_a,
        script(&[
            (EXTCODESIZE, word_of(script_b), u(0)),
            (EXTCODEHASH, word_of(script_b), u(0)),
            (EXTCODECOPY, word_of(script_b), u(0)),
            (BLOCKHASH, u(1), u(0)),
            (CALL, word_of(script_b), u(0)),
            (STATICCALL, word_of(script_b), u(0)),
            (DELEGATECALL, word_of(script_b), u(0)),
            (CALLCODE, word_of(script_b), u(0)),
        ]),
    );
    let body = chain.body(vec![tx]);
    let outcome = chain.check(&body, "reads");
    assert!(outcome.transactions[0].success);
    assert_eq!(Chain::logged_word(&outcome, 0, 0), u(runtime_len));
    assert_eq!(Chain::logged_word(&outcome, 0, 1), U256::from_be_bytes(keccak256(script_runtime()).0));
    assert_ne!(Chain::logged_word(&outcome, 0, 3), u(0));
    for log in 4..8 {
        assert_eq!(Chain::logged_word(&outcome, 0, log), u(1), "call op log {log}");
    }

    // Forward: run a script in another contract at a chosen gas.
    let mut forward = entry(FORWARD, word_of(script_b), u(500_000));
    forward.extend_from_slice(&entry(SSTORE, u(3), u(4)));
    let tx = chain.call(script_a, forward.into());
    let body = chain.body(vec![tx]);
    let outcome = chain.check(&body, "forward");
    assert_eq!(Chain::logged_word(&outcome, 0, 0), u(1));
    assert_eq!(chain.state.storage_of(&script_b, u(3)), u(4));
    let mut forward = entry(FORWARD, word_of(script_b), u(500_000));
    forward.extend_from_slice(&entry(REVERT, u(0), u(0)));
    let tx = chain.call(script_a, forward.into());
    let body = chain.body(vec![tx]);
    let outcome = chain.check(&body, "forward revert");
    assert!(outcome.transactions[0].success);
    assert_eq!(Chain::logged_word(&outcome, 0, 0), u(0));
}

// ---------------------------------------------------------------------------
// Inline nodes and mined trie shapes
// ---------------------------------------------------------------------------

/// A storage leaf at depth 9 with a one-byte value encodes to 31 bytes, so it is
/// embedded in its parent branch, and no proof node exists at its path. Two slots
/// with a common 4-byte key prefix take 2^16 hashes to find: anyone can make these.
#[test]
fn inline_storage_nodes_read_update_delete_and_exclude() {
    let groups = mined_slots(4, 3);
    for spec in both_rules() {
        let mut chain = Chain::new(spec);
        let target = chain.deploy_script();
        // Other storage, so that the pairs hang low in a real trie.
        let filler: Vec<(u64, U256, U256)> = (0..40).map(|slot| (SSTORE, u(slot + 1_000_000_000), u(77))).collect();
        let tx = chain.call(target, script(&filler));
        let body = chain.body(vec![tx]);
        chain.check(&body, "filler");

        for pair in &groups {
            let (a, b) = (pair[0], pair[1]);
            let tx = chain.call(target, script(&[(SSTORE, u(a), u(1)), (SSTORE, u(b), u(2))]));
            let body = chain.body(vec![tx]);
            chain.check(&body, "write inline pair");

            // The branch that holds them has embedded children.
            let trie = chain.state.warm_commitment().unwrap();
            let key = storage_key(&u(a));
            let proof = trie.storage_proof(&target, [key]).unwrap();
            let deepest = proof.keys().map(Nibbles::len).max().unwrap();
            assert!(deepest >= 8, "the pair must meet at depth 8 or below, got {deepest}");

            let tx = chain.call(target, script(&[(SLOAD, u(a), u(0)), (SLOAD, u(b), u(0))]));
            let body = chain.body(vec![tx]);
            let outcome = chain.check(&body, "read inline pair");
            assert_eq!(Chain::logged_word(&outcome, 0, 0), u(1));
            assert_eq!(Chain::logged_word(&outcome, 0, 1), u(2));

            // Update keeps it embedded; a big value takes it out of the parent.
            let tx = chain.call(target, script(&[(SSTORE, u(a), u(3))]));
            let body = chain.body(vec![tx]);
            chain.check(&body, "update inline");
            let big = U256::MAX - u(5);
            let tx = chain.call(target, script(&[(SSTORE, u(b), big), (SLOAD, u(a), u(0))]));
            let body = chain.body(vec![tx]);
            chain.check(&body, "inline sibling grows");
            let tx = chain.call(target, script(&[(SSTORE, u(b), u(9))]));
            let body = chain.body(vec![tx]);
            chain.check(&body, "sibling shrinks back to inline");

            // Delete one: the survivor is merged upward and leaves the embedded form.
            let tx = chain.call(target, script(&[(SSTORE, u(a), u(0))]));
            let body = chain.body(vec![tx]);
            let (witness, _, _) = chain.differential(&body, "delete inline, sibling untouched");
            let view = IndexedTrieView::from_proof(
                witness.pre_accounts.iter().find(|acc| acc.address == target).unwrap().storage_root,
                &witness.pre_accounts.iter().find(|acc| acc.address == target).unwrap().storage_proof,
            )
            .unwrap();
            assert!(view.lookup(&storage_key(&u(b))).unwrap().is_some(), "the embedded sibling is exposed");
            chain.commit(&body);
            // Exclusion at the old position, then back again.
            let tx = chain.call(target, script(&[(SLOAD, u(a), u(0)), (SSTORE, u(a), u(1)), (SSTORE, u(b), u(0))]));
            let body = chain.body(vec![tx]);
            let outcome = chain.check(&body, "exclude, reinsert, delete sibling");
            assert_eq!(Chain::logged_word(&outcome, 0, 0), u(0));
            let tx = chain.call(target, script(&[(SSTORE, u(a), u(0))]));
            let body = chain.body(vec![tx]);
            chain.check(&body, "delete the last of the pair");
        }
    }
}

/// Delete all but one child of branches at many depths in one block, on tries where
/// the survivor is a leaf, an extension or a branch, and is otherwise untouched.
#[test]
fn collapses_onto_untouched_siblings_at_every_shape() {
    let deep = mined_slots(3, 6);
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let target = chain.deploy_script();
    let mut fill: Vec<(u64, U256, U256)> = Vec::new();
    for pair in &deep {
        for slot in pair {
            fill.push((SSTORE, u(*slot), u(1)));
        }
    }
    for slot in 0..60 {
        fill.push((SSTORE, u(slot + 500_000_000), u(1)));
    }
    let tx = chain.call(target, script(&fill));
    let body = chain.body(vec![tx]);
    chain.check(&body, "fill");

    // One of each pair: leaf survivors.
    let round: Vec<(u64, U256, U256)> = deep.iter().map(|pair| (SSTORE, u(pair[0]), u(0))).collect();
    let tx = chain.call(target, script(&round));
    let body = chain.body(vec![tx]);
    chain.check(&body, "delete one of each pair");

    // Now a big drain in random order, block after block, down to the empty trie.
    let mut live: Vec<u64> = deep.iter().map(|pair| pair[1]).chain((0..60).map(|slot| slot + 500_000_000)).collect();
    let mut rng = Rng::new(b"drain");
    while !live.is_empty() {
        let count = 1 + rng.next(9.min(live.len() as u64));
        let mut round = Vec::new();
        for _ in 0..count {
            let index = rng.next(live.len() as u64) as usize;
            round.push((SSTORE, u(live.swap_remove(index)), u(0)));
        }
        let tx = chain.call(target, script(&round));
        let body = chain.body(vec![tx]);
        chain.check(&body, "drain");
    }
    let (root, _) = (chain.state.warm_commitment().unwrap().storage_root_cached(&target), ());
    assert_eq!(root, Some(alloy_trie::EMPTY_ROOT_HASH));
}

/// One transaction writes and another deletes in one block, including a slot deleted
/// and rewritten, and a slot inserted next to a deletion.
#[test]
fn delete_and_insert_in_one_block() {
    let pair = &mined_slots(3, 1)[0];
    let (a, b) = (pair[0], pair[1]);
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let target = chain.deploy_script();
    let tx = chain.call(target, script(&[(SSTORE, u(a), u(1)), (SSTORE, u(b), u(2)), (SSTORE, u(1234), u(3))]));
    let body = chain.body(vec![tx]);
    chain.check(&body, "fill");
    let first = chain.call(target, script(&[(SSTORE, u(a), u(0))]));
    let second = chain.call(target, script(&[(SLOAD, u(a), u(0)), (SSTORE, u(a), u(5)), (SSTORE, u(b), u(0))]));
    let third = chain.call(target, script(&[(SLOAD, u(b), u(0)), (SSTORE, u(4321), u(6)), (SSTORE, u(1234), u(0))]));
    let body = chain.body(vec![first, second, third]);
    let outcome = chain.check(&body, "mixed block");
    assert_eq!(Chain::logged_word(&outcome, 1, 0), u(0));
    assert_eq!(Chain::logged_word(&outcome, 2, 0), u(0));
    // Write then a reverted clear: the revert must restore the read.
    let mut forward = entry(FORWARD, word_of(target), u(200_000));
    forward.extend_from_slice(&entry(REVERT, u(0), u(0)));
    let caller = chain.deploy_script();
    let tx = chain.call(caller, forward.into());
    let reader = chain.call(target, script(&[(SLOAD, u(a), u(0))]));
    let body = chain.body(vec![tx, reader]);
    let outcome = chain.check(&body, "revert then read");
    assert_eq!(Chain::logged_word(&outcome, 1, 0), u(5));
}

// ---------------------------------------------------------------------------
// Account destruction and recreation, for accounts that are already in the trie
// ---------------------------------------------------------------------------

/// CREATE2 onto a funded, code-less address, whose leaf is already in the trie, with a
/// constructor that destroys itself: the leaf must leave the trie, and the block's
/// later transactions see the address as empty.
#[test]
fn destroying_an_account_that_is_already_in_the_trie() {
    for spec in both_rules() {
        let mut chain = Chain::new(spec);
        let factory = chain.deploy_script();
        let initcode = destroying_initcode(0x77);
        let hash = keccak256(&initcode);
        let salt = B256::repeat_byte(0x11);
        let doomed = factory.create2(salt, hash);
        let pay = chain.pay(doomed, 5);
        let body = chain.body(vec![pay]);
        chain.check(&body, "fund the doomed address");
        assert!(chain.state.account(&doomed).is_some());

        let mut data = entry(CREATE2, U256::from_be_bytes(salt.0), u(0));
        data.extend_from_slice(&initcode);
        let destroy = chain.call(factory, data.into());
        let reader = chain.call(factory, script(&[(BALANCE, word_of(doomed), u(0)), (EXTCODEHASH, word_of(doomed), u(0))]));
        let body = chain.body(vec![destroy, reader]);
        let outcome = chain.check(&body, "destroy in the same transaction as the creation");
        assert!(outcome.transactions[0].success);
        assert_eq!(Chain::logged_word(&outcome, 1, 0), u(0));
        assert_eq!(Chain::logged_word(&outcome, 1, 1), u(0));
        assert!(chain.state.account(&doomed).is_none(), "destroyed");

        // The same address, funded again in a later block: a fresh leaf.
        let pay = chain.pay(doomed, 7);
        let body = chain.body(vec![pay]);
        chain.check(&body, "refund after destruction");
    }
}

/// Destroy, then pay, then create again with storage, then read it, all in one block,
/// starting from a leaf in the trie.
#[test]
fn destroyed_paid_and_recreated_in_one_block() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let factory = chain.deploy_script();
    let runtime = script_runtime();
    let destroying = destroying_initcode(0x77);
    let salt = B256::repeat_byte(0x12);
    let doomed = factory.create2(salt, keccak256(&destroying));
    let pay = chain.pay(doomed, 5);
    let body = chain.body(vec![pay]);
    chain.check(&body, "fund");

    let mut data = entry(CREATE2, U256::from_be_bytes(salt.0), u(0));
    data.extend_from_slice(&destroying);
    let destroy = chain.call(factory, data.clone().into());
    let pay_again = chain.pay(doomed, 3);
    let destroy_again = chain.call(factory, data.into());
    let pay_third = chain.pay(doomed, 2);
    let body = chain.body(vec![destroy, pay_again, destroy_again, pay_third]);
    let outcome = chain.check(&body, "destroy, pay, destroy, pay");
    assert!(outcome.transactions.iter().all(|tx| tx.success));
    assert_eq!(chain.state.balance_of(&doomed), u(2));

    // Create with storage on an address with a balance; the next block reads through
    // the view, a following one deletes the only slot.
    let storing = storing_initcode(5, &runtime);
    let salt = B256::repeat_byte(0x13);
    let target = factory.create2(salt, keccak256(&storing));
    let pay = chain.pay(target, 9);
    let body = chain.body(vec![pay]);
    chain.check(&body, "fund the second");
    let mut data = entry(CREATE2, U256::from_be_bytes(salt.0), u(0));
    data.extend_from_slice(&storing);
    let create = chain.call(factory, data.into());
    let read = chain.call(target, script(&[(SLOAD, u(1), u(0)), (SLOAD, u(2), u(0)), (SSTORE, u(2), u(8))]));
    let body = chain.body(vec![create, read]);
    let outcome = chain.check(&body, "create over a balance and use it");
    assert_eq!(Chain::logged_word(&outcome, 1, 0), u(5));
    assert_eq!(Chain::logged_word(&outcome, 1, 1), u(0));
    let read = chain.call(target, script(&[(SLOAD, u(1), u(0)), (SLOAD, u(2), u(0)), (SSTORE, u(1), u(0))]));
    let clear = chain.call(target, script(&[(SSTORE, u(2), u(0))]));
    let body = chain.body(vec![read, clear]);
    let outcome = chain.check(&body, "read through the view, then empty the storage trie");
    assert_eq!(Chain::logged_word(&outcome, 0, 0), u(5));
    assert_eq!(Chain::logged_word(&outcome, 0, 1), u(8));
    // A collision: CREATE2 on a live contract fails, and nothing is wiped.
    let mut data = entry(CREATE2, U256::from_be_bytes(salt.0), u(0));
    data.extend_from_slice(&storing);
    let collide = chain.call(factory, data.into());
    let body = chain.body(vec![collide]);
    let outcome = chain.check(&body, "collision");
    assert_eq!(Chain::logged_word(&outcome, 0, 0), u(0));
    assert_eq!(chain.state.account(&target).unwrap().nonce, 1);
}

/// The doomed leaf's only neighbour in its branch is an untouched leaf: removing it
/// merges that neighbour's compact path into the parent, in the account trie.
#[test]
fn account_removal_collapses_onto_an_untouched_account() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let factory = chain.deploy_script();
    let initcode = destroying_initcode(0x77);
    let hash = keccak256(&initcode);

    // Mine two salts whose account keys share 3 bytes: a two-child branch deep down.
    let mut seen: BTreeMap<[u8; 3], B256> = BTreeMap::new();
    let mut found = None;
    for index in 0u64.. {
        let salt = keccak256(index.to_be_bytes());
        let address = factory.create2(salt, hash);
        let key = keccak256(address);
        let prefix = [key[0], key[1], key[2]];
        if let Some(other) = seen.get(&prefix) {
            found = Some((*other, salt));
            break;
        }
        seen.insert(prefix, salt);
    }
    let (salt_a, salt_b) = found.unwrap();
    let (a, b) = (factory.create2(salt_a, hash), factory.create2(salt_b, hash));
    let pay_a = chain.pay(a, 5);
    let pay_b = chain.pay(b, 6);
    let body = chain.body(vec![pay_a, pay_b]);
    chain.check(&body, "fund the pair");

    let mut data = entry(CREATE2, U256::from_be_bytes(salt_a.0), u(0));
    data.extend_from_slice(&initcode);
    let destroy = chain.call(factory, data.into());
    let body = chain.body(vec![destroy]);
    let outcome = chain.check(&body, "removal with an untouched sibling");
    assert!(outcome.transactions[0].success);
    assert!(chain.state.account(&a).is_none());
    assert_eq!(chain.state.balance_of(&b), u(6));

    // The other one, in a block that also creates a new account nearby.
    let mut data = entry(CREATE2, U256::from_be_bytes(salt_b.0), u(0));
    data.extend_from_slice(&initcode);
    let destroy = chain.call(factory, data.into());
    let pay = chain.pay(a, 4);
    let body = chain.body(vec![destroy, pay]);
    chain.check(&body, "remove one, recreate the other");
}

// ---------------------------------------------------------------------------
// Omissions under try/catch: every opcode
// ---------------------------------------------------------------------------

fn assert_fails_fatally(result: Result<NodeExecutionOutcome, SparseNodeError>, what: &str) {
    match result {
        Err(SparseNodeError::Execution(_)) | Err(SparseNodeError::Verify(_)) => {}
        Err(other) => panic!("{what}: unexpected failure: {other}"),
        Ok(outcome) => panic!("{what}: an uncovered read was accepted, root {}", outcome.header.state_root),
    }
}

/// An account the witness leaves out, reached by each opcode from inside a frame the
/// outer contract catches. A failure must be fatal for the block: if it were merely a
/// failed inner call, the prover could choose what `success` the outer contract sees.
#[test]
fn every_state_opcode_under_a_catching_frame_fails_the_block_when_its_account_is_omitted() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let outer = chain.deploy_script();
    let inner = chain.deploy_script();
    let victim = chain.deploy_script();
    let tx = chain.call(victim, script(&[(SSTORE, u(1), u(5))]));
    let body = chain.body(vec![tx]);
    chain.commit(&body);

    for (op, name) in [
        (BALANCE, "BALANCE"),
        (EXTCODESIZE, "EXTCODESIZE"),
        (EXTCODEHASH, "EXTCODEHASH"),
        (EXTCODECOPY, "EXTCODECOPY"),
        (CALL, "CALL"),
        (STATICCALL, "STATICCALL"),
        (DELEGATECALL, "DELEGATECALL"),
        (CALLCODE, "CALLCODE"),
        (SELFDESTRUCT, "SELFDESTRUCT"),
    ] {
        let mut data = entry(FORWARD, word_of(inner), u(800_000));
        data.extend_from_slice(&entry(op, word_of(victim), u(0)));
        let tx = chain.call(outer, data.into());
        let body = chain.body(vec![tx]);
        let (witness, canonical, context) = chain.differential(&body, name);
        assert!(canonical.transactions[0].success, "{name}");

        // Left out of pre_accounts.
        let mut omitted = witness.clone();
        let before = omitted.pre_accounts.len();
        omitted.pre_accounts.retain(|account| account.address != victim);
        assert_eq!(omitted.pre_accounts.len() + 1, before, "{name}: the victim is in the witness");
        assert_fails_fatally(chain.verify(&omitted, &context, &body), name);

        // Claimed absent instead: must fail on the exclusion proof.
        let mut claimed = omitted.clone();
        claimed.absent_accounts.push(victim);
        assert_fails_fatally(chain.verify(&claimed, &context, &body), name);
        chain.commit(&body);
    }
}

/// Slots: SLOAD and SSTORE in a frame that catches, at gas that does and does not
/// reach the cold load. A cold load the gas does not reach is skipped by revm with no
/// read at all, on both paths. Everything else must fail the block.
#[test]
fn an_omitted_slot_under_a_catching_frame_at_any_gas() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let outer = chain.deploy_script();
    let inner = chain.deploy_script();
    let fill: Vec<(u64, U256, U256)> = (0..40).map(|slot| (SSTORE, u(slot), u(slot + 1))).collect();
    let tx = chain.call(inner, script(&fill));
    let body = chain.body(vec![tx]);
    chain.commit(&body);

    let (mut survived, mut refused, mut skipped) = (0u64, 0u64, 0u64);
    for gas in [40_000u64, 3_000, 2_900, 2_500, 2_300, 2_200, 2_150, 2_100, 2_000, 1_000, 200, 50, 10] {
        for (op, a, b) in [(SLOAD, u(7), u(0)), (SSTORE, u(7), u(0)), (SSTORE, u(7), u(100)), (SLOAD, u(9999), u(0))] {
            let mut data = entry(FORWARD, word_of(inner), u(gas));
            data.extend_from_slice(&entry(op, a, b));
            let tx = chain.call(outer, data.into());
            let body = chain.body(vec![tx]);
            let (witness, canonical, context) = chain.differential(&body, "catching frame");
            let index = witness.pre_accounts.iter().position(|account| account.address == inner).unwrap();
            let key = storage_key(&a);
            let mut stripped = witness.clone();
            let proof = &mut stripped.pre_accounts[index].storage_proof;
            let deepest = proof.keys().filter(|path| key.starts_with(path)).max_by_key(|path| path.len()).copied();
            let deepest = deepest.unwrap();
            if deepest.is_empty() {
                // Only the root: at this gas revm skipped the cold load, and no read
                // reached the backing on any path.
                skipped += 1;
                chain.commit(&body);
                continue;
            }
            proof.remove(&deepest);
            // Accepting is fine only when the slot was not needed: then the answer
            // is the canonical one, whatever the gas did.
            if let Ok(outcome) = chain.verify(&stripped, &context, &body) {
                assert_eq!(outcome.header, canonical.header, "gas {gas} op {op}");
                assert_eq!(outcome.receipts, canonical.receipts, "gas {gas} op {op}");
                survived += 1;
            } else {
                refused += 1;
            }
            chain.commit(&body);
        }
    }
    std::println!("catching frame: refused {refused}, cold load skipped {skipped}, not needed {survived}");
    assert!(refused > 0 && skipped > 0, "both must occur: refused {refused}, skipped {skipped}");
}

// ---------------------------------------------------------------------------
// System predeploys
// ---------------------------------------------------------------------------

/// A zero anchor over a non-zero one at the same timestamp deletes a ring slot; the
/// EIP-4788 write itself restructures the storage trie, with no user transaction.
#[test]
fn the_beacon_ring_deletes_a_slot_on_a_zero_anchor() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    chain.timestamp_step = 0;
    let body = chain.body(vec![]);
    chain.check(&body, "non-zero anchor");
    chain.anchor = B256::ZERO;
    let body = NodeBodyV2::default();
    let (witness, _, context) = chain.differential(&body, "zero anchor at the same timestamp deletes the root slot");
    let index = witness.pre_accounts.iter().position(|account| account.address == BEACON_ROOTS_ADDRESS).unwrap();
    let ts = U256::from(context.timestamp);
    let root_slot = ts % U256::from(8191u64) + U256::from(8191u64);
    let view = IndexedTrieView::from_proof(witness.pre_accounts[index].storage_root, &witness.pre_accounts[index].storage_proof).unwrap();
    assert!(view.lookup(&storage_key(&root_slot)).unwrap().is_some(), "the root slot existed");
    chain.commit(&body);
    assert_eq!(chain.state.storage_of(&BEACON_ROOTS_ADDRESS, root_slot), U256::ZERO);
    chain.timestamp_step = 1;
    let body = NodeBodyV2::default();
    chain.check(&body, "and on");
}

/// The ring wraps at 8191 entries: the same slot is overwritten and the old timestamp
/// must then not answer. Timestamps jump, so this needs no 8191 blocks. Empty blocks
/// and one read per block; statement bytes compared with the complete witness.
#[test]
fn the_beacon_ring_wraps_and_user_reads_agree() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let reader = chain.deploy_script();
    chain.timestamp_step = 8191;
    for round in 0..4u64 {
        let context = chain.context();
        chain.anchor = if round == 2 { B256::ZERO } else { keccak256(round.to_be_bytes()) };
        let call = |chain: &mut Chain, timestamp: u64| {
            let mut data = entry(FORWARD, word_of(BEACON_ROOTS_ADDRESS), u(100_000));
            data.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>());
            chain.call(reader, data.into())
        };
        let same_block = call(&mut chain, context.timestamp);
        let previous = call(&mut chain, context.timestamp - 8191);
        let direct = {
            let input: Bytes = U256::from(context.timestamp).to_be_bytes::<32>().to_vec().into();
            chain.call(BEACON_ROOTS_ADDRESS, input)
        };
        let body = chain.body(vec![same_block, previous, direct]);
        let outcome = chain.check(&body, "ring");
        // The old timestamp was overwritten at the same ring position.
        assert_eq!(Chain::logged_word(&outcome, 1, 0), u(0), "round {round}");
        // A stored zero root still answers: the timestamp slot matches.
        assert_eq!(Chain::logged_word(&outcome, 0, 0), u(1), "round {round}");
    }
    chain.timestamp_step = 1;
    let body = NodeBodyV2::default();
    chain.check(&body, "and on");
}

/// BLOCKHASH at every interesting distance, from below the wrap to above it, inside a
/// nested frame, with both paths and with the value in the receipts.
#[test]
fn blockhash_in_all_positions_agrees_and_stays_a_proof_obligation() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let reader = chain.deploy_script();
    let outer = chain.deploy_script();
    let mut known: BTreeMap<u64, B256> = BTreeMap::new();
    for _ in 0..600u64 {
        let head = node_head(&chain.spec, MAINNET_DOMAIN, &chain.state).unwrap();
        known.insert(head.number, head.hash());
        let number = head.number + 1;
        let probe = |n: u64| (BLOCKHASH, u(n), u(0));
        let entries = [
            probe(number),
            probe(number + 1),
            probe(number - 1),
            probe(number.saturating_sub(2)),
            probe(number.saturating_sub(128)),
            probe(number.saturating_sub(255)),
            probe(number.saturating_sub(256)),
            probe(number.saturating_sub(257)),
            probe(0),
            (BLOCKHASH, U256::MAX, u(0)),
        ];
        let tx = chain.call(reader, script(&entries));
        let mut forward = entry(FORWARD, word_of(reader), u(200_000));
        forward.extend_from_slice(&script(&[probe(number.saturating_sub(100))]));
        let nested = chain.call(outer, forward.into());
        let body = chain.body(vec![tx, nested]);
        let check_this = number % 37 == 0 || !(250..=262).contains(&number) && number % 7 == 0 || (250..=262).contains(&number);
        let outcome = if check_this { chain.check(&body, "blockhash") } else { chain.commit(&body) };
        // The values themselves, against a record kept outside the state.
        for (log, n) in [
            (2usize, number - 1),
            (3, number.saturating_sub(2)),
            (4, number.saturating_sub(128)),
            (5, number.saturating_sub(255)),
            (6, number.saturating_sub(256)),
        ] {
            let got = B256::from(Chain::logged_word(&outcome, 0, log));
            if let Some(expected) = known.get(&n) {
                assert_eq!(got, *expected, "BLOCKHASH({n}) in block {number}");
            }
        }
        assert_eq!(Chain::logged_word(&outcome, 0, 0), u(0));
        assert_eq!(Chain::logged_word(&outcome, 0, 1), u(0));
        if number > 257 {
            assert_eq!(Chain::logged_word(&outcome, 0, 7), u(0));
        }
    }
}

// ---------------------------------------------------------------------------
// Deposits, withdrawals, fee vaults
// ---------------------------------------------------------------------------

/// Deposits land on an absent address, an EOA, an inflated contract, and an address
/// created in the same block. The contract's storage stays opaque.
#[test]
fn deposits_on_every_kind_of_recipient() {
    for spec in both_rules() {
        let mut chain = Chain::new(spec);
        let inflated = chain.deploy_script();
        for start in [0u64, 100, 200] {
            let fill: Vec<(u64, U256, U256)> = (start..start + 100).map(|slot| (SSTORE, u(slot), u(1))).collect();
            let tx = chain.call(inflated, script(&fill));
            let body = chain.body(vec![tx]);
            chain.commit(&body);
        }
        let sender = chain.sender;
        let upcoming = sender.create(chain.nonce);
        let deposits = vec![
            chain.deposit_to(inflated, 1_000_000),
            chain.deposit_to(Address::repeat_byte(0x55), 1_000_000),
            chain.deposit_to(sender, 100_000_000_000),
            chain.deposit_to(upcoming, 1_000_000),
            chain.deposit_to(Address::repeat_byte(0x55), 1_000_000),
        ];
        let create = chain.tx(TxKind::Create, U256::from(1u64), deploy_code(&script_runtime()).into(), 3_000_000);
        let read = chain.call(upcoming, script(&[(BALANCE, word_of(upcoming), u(0)), (SLOAD, u(1), u(0))]));
        let body = NodeBodyV2 {
            deposits,
            transactions: vec![create, read],
        };
        let (witness, canonical, context) = chain.differential(&body, "deposits");
        assert!(canonical.transactions.iter().all(|tx| tx.success));
        let index = witness.pre_accounts.iter().position(|account| account.address == inflated).unwrap();
        assert_eq!(witness.pre_accounts[index].storage_proof.len(), 1, "only the root node of the inflated contract");
        // The inflated contract left out: refused, not credited from nothing.
        let mut omitted = witness.clone();
        omitted.pre_accounts.remove(index);
        assert_fails_fatally(chain.verify(&omitted, &context, &body), "omitted recipient");
        let mut claimed = omitted;
        claimed.absent_accounts.push(inflated);
        assert_fails_fatally(chain.verify(&claimed, &context, &body), "recipient claimed absent");
        // The deposit's ledger cursor cannot be hidden either.
        let ledger = witness.pre_accounts.iter().position(|account| account.address == chain.spec.supply_ledger).unwrap();
        let mut stale = witness.clone();
        stale.pre_accounts[ledger].storage_proof.retain(|path, _| path.is_empty());
        assert_fails_fatally(chain.verify(&stale, &context, &body), "ledger hidden");
        chain.commit(&body);
    }
}

fn withdrawal_input(recipient: B256) -> Bytes {
    let mut input = INITIATE_WITHDRAWAL_SELECTOR.to_vec();
    input.extend_from_slice(recipient.as_slice());
    input.into()
}

/// The outbox frontier is rewritten by the protocol between block end and the root.
/// Sizes that cross many tree levels; nested and reverted calls; every statement byte
/// compared; and a hidden frontier word refused.
#[test]
fn withdrawals_frontier_root_and_count_agree() {
    let wei = U256::from(10_000_000_000_000_000u64);
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let router = chain.deploy_script();
    let mut total = 0u64;
    for (block, count) in [1u64, 1, 2, 3, 5, 8, 13, 1, 0, 2].into_iter().enumerate() {
        let mut txs = Vec::new();
        for leaf in 0..count {
            let recipient = keccak256(leaf.to_be_bytes());
            txs.push(chain.tx(TxKind::Call(L2_TO_L1_MESSAGE_PASSER), wei, withdrawal_input(recipient), 200_000));
            total += 1;
        }
        if block % 2 == 0 {
            // A withdrawal attempt that reverts in a caught frame must not count.
            let mut data = entry(FORWARD, word_of(L2_TO_L1_MESSAGE_PASSER), u(100_000));
            data.extend_from_slice(&withdrawal_input(B256::ZERO));
            txs.push(chain.call(router, data.into()));
        }
        let body = chain.body(txs);
        let (witness, canonical, context) = chain.differential(&body, "withdrawals");
        let summary = canonical.withdrawals.as_ref().unwrap();
        assert_eq!(summary.commitment.count, total);
        // Every storage node of the outbox is necessary or harmless.
        let index = witness.pre_accounts.iter().position(|account| account.address == L2_TO_L1_MESSAGE_PASSER).unwrap();
        for path in witness.pre_accounts[index].storage_proof.keys().copied().collect::<Vec<_>>() {
            let mut stripped = witness.clone();
            stripped.pre_accounts[index].storage_proof.remove(&path);
            if let Ok(outcome) = chain.verify(&stripped, &context, &body) {
                assert_eq!(outcome.header, canonical.header);
                assert_eq!(outcome.withdrawals, canonical.withdrawals);
            }
        }
        chain.commit(&body);
    }
}

/// The next rules: the fee vaults run a sweep. A vault called, paid and swept in one
/// block; a contract paying a vault by SELFDESTRUCT in its constructor.
#[test]
fn fee_vault_sweeps_agree() {
    let mut chain = Chain::new(ChainSpec::mainnet());
    let script_address = chain.deploy_script();
    let (base, sequencer) = (chain.spec.base_fee_vault, chain.spec.sequencer_fee_vault);
    for _ in 0..3 {
        let a = chain.call(base, Bytes::new());
        let b = chain.call(sequencer, Bytes::new());
        let c = chain.call(script_address, script(&[(BALANCE, word_of(base), u(0)), (CALL, word_of(sequencer), u(5))]));
        let body = chain.body(vec![a, b, c]);
        let outcome = chain.check(&body, "sweep");
        assert!(outcome.transactions.iter().all(|tx| tx.success));
    }
    let recipient = crate::chainspec::MAINNET_FEE_SWEEP_RECIPIENT;
    assert_ne!(chain.state.balance_of(&recipient), u(0));
    let initcode = vec![0x73]
        .into_iter()
        .chain(base.as_slice().iter().copied())
        .chain([0xff])
        .collect::<Vec<u8>>();
    let tx = chain.tx(TxKind::Create, U256::from(9u64), initcode.into(), 500_000);
    let body = chain.body(vec![tx]);
    chain.check(&body, "selfdestruct into a vault");
}

// ---------------------------------------------------------------------------
// Forged, stale, transplanted and duplicated parts
// ---------------------------------------------------------------------------

/// A block with most kinds of work, the witness at the previous block, and every part
/// of the witness attacked in turn. The verifier fails, or the outcome is canonical.
#[test]
fn every_witness_part_attacked_on_a_rich_block() {
    let pair = &mined_slots(3, 1)[0];
    let (a, b) = (pair[0], pair[1]);
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let target = chain.deploy_script();
    let other = chain.deploy_script();
    let mut fill: Vec<(u64, U256, U256)> = (0..30).map(|slot| (SSTORE, u(slot + 1000), u(5))).collect();
    fill.push((SSTORE, u(a), u(1)));
    fill.push((SSTORE, u(b), u(2)));
    let tx = chain.call(target, script(&fill));
    let tx2 = chain.call(other, script(&fill));
    let body = chain.body(vec![tx, tx2]);
    chain.commit(&body);
    let old_body_witness_context = {
        let tx = chain.call(target, script(&[(SLOAD, u(1000), u(0))]));
        let body = chain.body(vec![tx]);
        let (witness, _, context) = chain.differential(&body, "old");
        chain.commit(&body);
        (witness, context, body)
    };

    let wei = U256::from(10_000_000_000_000_000u64);
    let txs = vec![
        chain.call(target, script(&[(SLOAD, u(1001), u(0)), (SSTORE, u(a), u(0)), (SSTORE, u(9_000_000), u(7)), (SLOAD, u(8_000_000), u(0))])),
        chain.call(other, script(&[(BLOCKHASH, u(2), u(0)), (BALANCE, word_of(target), u(0)), (CALL, word_of(Address::repeat_byte(0x66)), u(1))])),
        chain.tx(TxKind::Call(L2_TO_L1_MESSAGE_PASSER), wei, withdrawal_input(B256::repeat_byte(1)), 200_000),
    ];
    let body = chain.body(txs);
    let (witness, canonical, context) = chain.differential(&body, "rich");

    let judge = |changed: &SparseBatchWitness, what: &str| match chain.verify(changed, &context, &body) {
        Err(_) => 0u64,
        Ok(outcome) => {
            assert_eq!(outcome.header, canonical.header, "{what}");
            assert_eq!(outcome.receipts, canonical.receipts, "{what}");
            assert_eq!(outcome.withdrawals, canonical.withdrawals, "{what}");
            1
        }
    };
    let mut rng = Rng::new(b"attack");
    let mut survivors = 0u64;
    let mut attempts = 0u64;

    // Fixed fields.
    let mut changed = witness.clone();
    changed.new_state_root = rng.word();
    assert_fails_fatally(chain.verify(&changed, &context, &body), "claimed root");
    let mut changed = witness.clone();
    changed.prev_state_root = rng.word();
    assert_fails_fatally(chain.verify(&changed, &context, &body), "previous root");

    let mutate_node = |rng: &mut Rng, node: &Bytes| -> Vec<Bytes> {
        let mut out = Vec::new();
        let mut flipped = node.to_vec();
        let at = rng.next(flipped.len() as u64) as usize;
        flipped[at] ^= 1 << rng.next(8);
        out.push(flipped.clone().into());
        let mut cut = node.to_vec();
        cut.pop();
        out.push(cut.into());
        let mut grown = node.to_vec();
        grown.push(0);
        out.push(grown.into());
        out
    };

    // Every account proof node: removed, mutated, moved.
    for path in witness.proof.keys().copied().collect::<Vec<_>>() {
        let mut changed = witness.clone();
        changed.proof.remove(&path);
        attempts += 1;
        survivors += judge(&changed, "account node removed");
        for node in mutate_node(&mut rng, &witness.proof[&path]) {
            let mut changed = witness.clone();
            changed.proof.insert(path, node);
            attempts += 1;
            survivors += judge(&changed, "account node mutated");
        }
    }
    // Every storage proof node of every account: removed, mutated, swapped between
    // accounts (same slots, other values), and every old one from the previous block.
    for (index, account) in witness.pre_accounts.iter().enumerate() {
        for path in account.storage_proof.keys().copied().collect::<Vec<_>>() {
            let mut changed = witness.clone();
            changed.pre_accounts[index].storage_proof.remove(&path);
            attempts += 1;
            survivors += judge(&changed, "storage node removed");
            for node in mutate_node(&mut rng, &account.storage_proof[&path]) {
                let mut changed = witness.clone();
                changed.pre_accounts[index].storage_proof.insert(path, node);
                attempts += 1;
                survivors += judge(&changed, "storage node mutated");
            }
        }
        // Stale: this account as the witness of the previous block had it.
        if let Some(old) = old_body_witness_context.0.pre_accounts.iter().find(|old| old.address == account.address) {
            let mut changed = witness.clone();
            changed.pre_accounts[index] = old.clone();
            attempts += 1;
            survivors += judge(&changed, "stale account");
            let mut changed = witness.clone();
            changed.pre_accounts[index].storage_proof = old.storage_proof.clone();
            attempts += 1;
            survivors += judge(&changed, "stale storage proof");
            let mut changed = witness.clone();
            changed.pre_accounts[index].storage_root = old.storage_root;
            changed.pre_accounts[index].storage_proof = old.storage_proof.clone();
            attempts += 1;
            survivors += judge(&changed, "stale storage root and proof");
        }
        // Fields.
        for change in 0..5 {
            let mut changed = witness.clone();
            let target = &mut changed.pre_accounts[index];
            match change {
                0 => target.balance = target.balance + U256::from(1u64),
                1 => target.nonce += 1,
                2 => target.storage_root = rng.word(),
                3 => target.code_hash = if target.code_hash == KECCAK_EMPTY { keccak256([0x00]) } else { KECCAK_EMPTY },
                _ => {
                    // The code itself: corrupt the entry this account's hash names.
                    let hash = target.code_hash;
                    let Some(position) = changed.codes.iter().position(|code| keccak256(code) == hash) else {
                        continue;
                    };
                    let mut code = changed.codes[position].to_vec();
                    let last = code.len() - 1;
                    code[last] ^= 1;
                    changed.codes[position] = code.into();
                }
            }
            assert_fails_fatally(chain.verify(&changed, &context, &body), "account field");
        }
        // Duplicated, in both lists.
        let mut changed = witness.clone();
        changed.pre_accounts.push(account.clone());
        assert_fails_fatally(chain.verify(&changed, &context, &body), "duplicate account");
        let mut changed = witness.clone();
        changed.absent_accounts.push(account.address);
        assert_fails_fatally(chain.verify(&changed, &context, &body), "listed in both");
        // Dropped.
        let mut changed = witness.clone();
        changed.pre_accounts.remove(index);
        assert_fails_fatally(chain.verify(&changed, &context, &body), "dropped account");
        // Proof of another account (real nodes of another storage trie).
        for other in witness.pre_accounts.iter().filter(|other| other.address != account.address) {
            let mut changed = witness.clone();
            changed.pre_accounts[index].storage_proof = other.storage_proof.clone();
            if account.storage_root != other.storage_root {
                assert_fails_fatally(chain.verify(&changed, &context, &body), "transplanted proof");
            }
            let mut changed = witness.clone();
            changed.pre_accounts[index].storage_root = other.storage_root;
            changed.pre_accounts[index].storage_proof = other.storage_proof.clone();
            if account.storage_root != other.storage_root {
                assert_fails_fatally(chain.verify(&changed, &context, &body), "transplanted root and proof");
            }
        }
    }
    for address in witness.absent_accounts.clone() {
        let mut changed = witness.clone();
        changed.absent_accounts.retain(|other| *other != address);
        assert_fails_fatally(chain.verify(&changed, &context, &body), "absent dropped");
        // Claimed present with invented contents.
        let mut changed = witness.clone();
        changed.absent_accounts.retain(|other| *other != address);
        changed.pre_accounts.push(SparseWitnessAccount {
            address,
            balance: U256::from(1_000_000u64),
            nonce: 3,
            code_hash: keccak256([0x00]),
            storage_root: alloy_trie::EMPTY_ROOT_HASH,
            storage_proof: BTreeMap::new(),
        });
        assert_fails_fatally(chain.verify(&changed, &context, &body), "absent claimed present");
    }

    // A whole old witness for the next block: refused by the head number or the root.
    let (old_witness, _, _) = &old_body_witness_context;
    assert_fails_fatally(chain.verify(old_witness, &context, &body), "the previous block's witness");
    // An old witness with its own old context and a new body: the old root is genuine,
    // the old block is real, so only the body differs: that is a different block on an
    // older head, and the statement names the parent, so it cannot pass as this block.
    if let Ok(outcome) = chain.verify(old_witness, &old_body_witness_context.1, &body) {
        assert_ne!(outcome.header.parent_hash, canonical.header.parent_hash);
        assert_ne!(outcome.header.parent_state_root, canonical.header.parent_state_root);
    }

    std::println!("attacks {attempts}, harmless survivors {survivors}");
    assert!(attempts > 200);
}

// ---------------------------------------------------------------------------
// Fuzz
// ---------------------------------------------------------------------------

fn fuzz_entries(rng: &mut Rng, chain: &Chain, targets: &[Address], slots: &[u64], addresses: &[Address]) -> Vec<(u64, U256, U256)> {
    let mut entries = Vec::new();
    let count = 1 + rng.next(10);
    let number = chain.context().number;
    let pick = |rng: &mut Rng, list: &[Address]| list[rng.next(list.len() as u64) as usize];
    for _ in 0..count {
        let slot = slots[rng.next(slots.len() as u64) as usize];
        let entry = match rng.next(14) {
            0..=2 => (SSTORE, u(slot), u(1 + rng.next(3))),
            3 => (SSTORE, u(slot), U256::MAX - u(rng.next(9))),
            4 | 5 => (SSTORE, u(slot), u(0)),
            6 | 7 => (SLOAD, u(slot), u(0)),
            8 => (BALANCE, word_of(pick(rng, addresses)), u(0)),
            9 => (EXTCODEHASH, word_of(pick(rng, addresses)), u(0)),
            10 => (BLOCKHASH, u(number.saturating_sub(rng.next(300))), u(0)),
            11 => (CALL, word_of(pick(rng, addresses)), u(rng.next(2))),
            12 => (DELEGATECALL, word_of(pick(rng, targets)), u(0)),
            _ => (STATICCALL, word_of(pick(rng, targets)), u(0)),
        };
        entries.push(entry);
    }
    entries
}

fn fuzz_chain(seed: &[u8], spec: ChainSpec, blocks: u64) {
    let mut rng = Rng::new(seed);
    let mut chain = Chain::new(spec);
    let targets: Vec<Address> = (0..3).map(|_| chain.deploy_script()).collect();
    // Mined groups make branches with two children, deep in the trie.
    let mut slots: Vec<u64> = mined_slots(3, 8).into_iter().flatten().collect();
    slots.extend(0..24u64);
    let factory = targets[0];
    let destroying = destroying_initcode(0x77);
    let storing = storing_initcode(5, &script_runtime());
    let mut addresses: Vec<Address> = targets.clone();
    addresses.extend([chain.sender, Address::repeat_byte(0x77), BEACON_ROOTS_ADDRESS, L2_TO_L1_MESSAGE_PASSER, chain.spec.block_info, chain.spec.base_fee_vault, chain.spec.supply_ledger]);
    addresses.extend((1..=9u8).map(|byte| { let mut raw = [0u8; 20]; raw[19] = byte; Address::from(raw) }));
    let salts: Vec<B256> = (0..6u8).map(|byte| B256::repeat_byte(byte + 1)).collect();
    for salt in &salts {
        addresses.push(factory.create2(*salt, keccak256(&destroying)));
        addresses.push(factory.create2(*salt, keccak256(&storing)));
    }
    let mut stats = (0u64, 0u64);
    let mut coverage = FuzzCoverage::default();
    for block in 0..blocks {
        let mut transactions = Vec::new();
        for _ in 0..rng.next(6) {
            let target = targets[rng.next(targets.len() as u64) as usize];
            let tx = match rng.next(12) {
                0..=5 => {
                    let entries = fuzz_entries(&mut rng, &chain, &targets, &slots, &addresses);
                    chain.call(target, script(&entries))
                }
                6 | 7 => {
                    // Nested at a chosen gas, in a frame that catches.
                    let inner = targets[rng.next(targets.len() as u64) as usize];
                    let gas = [0u64, 50, 2_000, 2_200, 5_000, 30_000, 300_000][rng.next(7) as usize];
                    let entries = fuzz_entries(&mut rng, &chain, &targets, &slots, &addresses);
                    let mut data = entry(FORWARD, word_of(inner), u(gas));
                    data.extend_from_slice(&script(&entries));
                    chain.call(target, data.into())
                }
                8 => {
                    let address = addresses[rng.next(addresses.len() as u64) as usize];
                    chain.pay(address, 1 + rng.next(3))
                }
                9 | 10 => {
                    let salt = salts[rng.next(salts.len() as u64) as usize];
                    let code = if rng.chance(50) { &destroying } else { &storing };
                    let mut data = entry(CREATE2, U256::from_be_bytes(salt.0), u(rng.next(2)));
                    data.extend_from_slice(code);
                    chain.call(factory, data.into())
                }
                _ => {
                    // A storing child may already be alive: use it.
                    let salt = salts[rng.next(salts.len() as u64) as usize];
                    let child = factory.create2(salt, keccak256(&storing));
                    let entries = fuzz_entries(&mut rng, &chain, &targets, &slots, &addresses);
                    chain.call(child, script(&entries))
                }
            };
            transactions.push(tx);
        }
        if rng.chance(20) {
            let wei = U256::from(10_000_000_000_000_000u64);
            transactions.push(chain.tx(TxKind::Call(L2_TO_L1_MESSAGE_PASSER), wei, withdrawal_input(rng.word()), 200_000));
        }
        if chain.spec.block_derivation.is_none() {
            chain.anchor = if rng.chance(15) { B256::ZERO } else { rng.word() };
            chain.timestamp_step = match rng.next(6) {
                0 => 0,
                1 => 8191,
                _ => 1,
            };
        }
        let body = chain.body(transactions);
        let what = alloc::format!("seed {seed:?} block {block}");
        let (witness, canonical, context) = chain.differential(&body, &what);

        // One random attack per block: remove or corrupt one storage node.
        if !witness.pre_accounts.is_empty() {
            let index = rng.next(witness.pre_accounts.len() as u64) as usize;
            let keys: Vec<Nibbles> = witness.pre_accounts[index].storage_proof.keys().copied().collect();
            if !keys.is_empty() {
                let path = keys[rng.next(keys.len() as u64) as usize];
                let mut changed = witness.clone();
                changed.pre_accounts[index].storage_proof.remove(&path);
                stats.0 += 1;
                if let Ok(outcome) = chain.verify(&changed, &context, &body) {
                    stats.1 += 1;
                    assert_eq!(outcome.header, canonical.header, "{what}");
                }
            }
        }
        let outcome = chain.commit(&body);
        coverage.txs += outcome.transactions.len() as u64;
        coverage.failed_txs += outcome.transactions.iter().filter(|tx| !tx.success).count() as u64;
        coverage.withdrawals += outcome.withdrawals.as_ref().map_or(0, |summary| summary.withdrawals.len() as u64);
        for account in &witness.pre_accounts {
            if chain.state.account(&account.address).is_none() {
                coverage.accounts_removed += 1;
            }
            let view = IndexedTrieView::from_proof(account.storage_root, &account.storage_proof).unwrap();
            for slot in &slots {
                if let Ok(Some(_)) = view.lookup(&storage_key(&u(*slot))) {
                    if chain.state.storage_of(&account.address, u(*slot)).is_zero() {
                        coverage.slots_deleted += 1;
                    }
                }
            }
            if chain.state.account(&account.address).is_some_and(|after| after.code_hash != KECCAK_EMPTY) && account.code_hash == KECCAK_EMPTY {
                coverage.created_over_a_leaf += 1;
            }
        }
        coverage.accounts_created += witness
            .absent_accounts
            .iter()
            .filter(|address| chain.state.account(address).is_some())
            .count() as u64;
    }
    std::println!("seed {seed:?}: node removals {}, harmless survivors {}, {coverage:?}", stats.0, stats.1);
    assert!(
        coverage.accounts_removed > 0 && coverage.accounts_created > 0 && coverage.slots_deleted > 0 && coverage.withdrawals > 0,
        "{coverage:?}"
    );
}

#[derive(Default, Debug)]
struct FuzzCoverage {
    txs: u64,
    failed_txs: u64,
    withdrawals: u64,
    accounts_removed: u64,
    accounts_created: u64,
    created_over_a_leaf: u64,
    slots_deleted: u64,
}

#[test]
fn fuzz_rich_blocks_v1_rules() {
    for round in 0..3 * scale() {
        fuzz_chain(alloc::format!("r{round}").as_bytes(), ChainSpec::mainnet_v1(), 250);
    }
}

#[test]
fn fuzz_rich_blocks_next_rules() {
    for round in 0..2 * scale() {
        fuzz_chain(alloc::format!("n{round}").as_bytes(), ChainSpec::mainnet(), 250);
    }
}

// ---------------------------------------------------------------------------
// Finding I1, fixed (agent 115): code travels by hash, and only when loaded
// ---------------------------------------------------------------------------

/// FINDING I1, fixed. A deposit cannot be refused, and it runs no code. The candidate
/// carried and hashed the recipient's whole code. Now the account carries its code
/// hash, bound by the leaf, and `codes` holds only what the block loads.
#[test]
fn a_deposit_does_not_carry_the_code_of_its_recipient() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    // PUSH2 24576 PUSH1 0 RETURN: 24,576 zero bytes of runtime.
    let tx = chain.tx(TxKind::Create, U256::ZERO, vec![0x61, 0x60, 0x00, 0x60, 0x00, 0xf3].into(), 6_000_000);
    let target = chain.sender.create(chain.nonce - 1);
    let body = chain.body(vec![tx]);
    assert!(chain.commit(&body).transactions[0].success);
    let body = NodeBodyV2 {
        deposits: vec![chain.deposit_to(target, 1_000_000)],
        transactions: vec![],
    };
    let (witness, _, _) = chain.differential(&body, "deposit to a large contract");
    let account = witness.pre_accounts.iter().find(|account| account.address == target).unwrap();
    assert_ne!(account.code_hash, KECCAK_EMPTY, "the recipient is a contract");
    let code_bytes: usize = witness.codes.iter().map(|code| code.len()).sum();
    assert!(
        code_bytes < 100,
        "the witness of a block that never runs code carries {code_bytes} bytes of code"
    );
}

/// The victim of the code tests: the script runtime with unreachable trailing bytes,
/// so its code hash differs from the outer and inner frames' code.
fn victim_runtime() -> Vec<u8> {
    let mut code = script_runtime();
    code.extend_from_slice(&[0x00, 0x11, 0x50]);
    code
}

/// Every opcode that reaches another account's code, from inside a frame the outer
/// contract catches. The witness must carry the code exactly when revm loads it, and
/// leaving it out, or putting another code in its place, must fail the block: never a
/// failed inner call, never empty code. An opcode that does not load code (BALANCE)
/// must not make the witness carry it.
#[test]
fn every_code_load_is_witnessed_and_fails_the_block_when_left_out() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let outer = chain.deploy_script();
    let inner = chain.deploy_script();
    let victim = chain.sender.create(chain.nonce);
    let tx = chain.tx(TxKind::Create, U256::ZERO, deploy_code(&victim_runtime()).into(), 3_000_000);
    let body = chain.body(vec![tx]);
    assert!(chain.commit(&body).transactions[0].success);
    let victim_hash = keccak256(victim_runtime());
    assert_ne!(victim_hash, keccak256(script_runtime()));
    let other_code: Bytes = storing_initcode(1, &[0x00]).into();

    let mut carried = alloc::vec::Vec::new();
    for (op, name) in [
        (BALANCE, "BALANCE"),
        (EXTCODESIZE, "EXTCODESIZE"),
        (EXTCODEHASH, "EXTCODEHASH"),
        (EXTCODECOPY, "EXTCODECOPY"),
        (CALL, "CALL"),
        (STATICCALL, "STATICCALL"),
        (DELEGATECALL, "DELEGATECALL"),
        (CALLCODE, "CALLCODE"),
    ] {
        let mut data = entry(FORWARD, word_of(inner), u(800_000));
        data.extend_from_slice(&entry(op, word_of(victim), u(0)));
        let tx = chain.call(outer, data.into());
        let body = chain.body(vec![tx]);
        let (witness, canonical, context) = chain.differential(&body, name);
        assert!(canonical.transactions[0].success, "{name}");
        let account = witness.pre_accounts.iter().find(|account| account.address == victim).unwrap();
        assert_eq!(account.code_hash, victim_hash, "{name}: the leaf's code hash");
        let position = witness.codes.iter().position(|code| keccak256(code) == victim_hash);
        if let Some(position) = position {
            carried.push(name);
            // Left out.
            let mut omitted = witness.clone();
            omitted.codes.remove(position);
            assert!(
                matches!(
                    chain.verify(&omitted, &context, &body),
                    Err(SparseNodeError::Execution(_))
                ),
                "{name}: omitted code"
            );
            // Another valid code in its place.
            let mut swapped = witness.clone();
            swapped.codes[position] = other_code.clone();
            assert_fails_fatally(chain.verify(&swapped, &context, &body), name);
            // The account claims the other code's hash: the leaf refuses it.
            let mut claimed = swapped.clone();
            let index = claimed.pre_accounts.iter().position(|account| account.address == victim).unwrap();
            claimed.pre_accounts[index].code_hash = keccak256(&other_code);
            assert!(
                matches!(
                    chain.verify(&claimed, &context, &body),
                    Err(SparseNodeError::Verify(SparseVerifyError::AccountNotProven(_)))
                ),
                "{name}: claimed code hash"
            );
        }
        chain.commit(&body);
    }
    std::println!("victim code carried for: {carried:?}");
    assert!(!carried.contains(&"BALANCE"), "BALANCE does not load code");
    for name in ["EXTCODESIZE", "EXTCODECOPY", "CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"] {
        assert!(carried.contains(&name), "{name} loads code: {carried:?}");
    }
}

/// The code list itself: duplicates, empty entries, invalid entries and the zero
/// code hash are refused; an extra entry the block never loads changes nothing.
#[test]
fn the_code_list_refuses_duplicates_empty_and_zero_hash() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let target = chain.deploy_script();
    let tx = chain.call(target, script(&[(SSTORE, u(1), u(2))]));
    let body = chain.body(vec![tx]);
    let (witness, canonical, context) = chain.differential(&body, "base");
    let script_hash = keccak256(script_runtime());
    let script_entries = witness.codes.iter().filter(|code| keccak256(code) == script_hash).count();
    assert_eq!(script_entries, 1, "the script's code, once");

    let mut changed = witness.clone();
    let script_code = changed.codes.iter().find(|code| keccak256(code) == script_hash).unwrap().clone();
    changed.codes.push(script_code);
    assert!(matches!(
        chain.verify(&changed, &context, &body),
        Err(SparseNodeError::Verify(SparseVerifyError::DuplicateCode(_)))
    ));
    let mut changed = witness.clone();
    changed.codes.push(Bytes::new());
    assert!(matches!(
        chain.verify(&changed, &context, &body),
        Err(SparseNodeError::Verify(SparseVerifyError::InvalidCode(_)))
    ));
    let mut changed = witness.clone();
    let index = changed.pre_accounts.iter().position(|account| account.address == target).unwrap();
    changed.pre_accounts[index].code_hash = B256::ZERO;
    assert!(matches!(
        chain.verify(&changed, &context, &body),
        Err(SparseNodeError::Verify(SparseVerifyError::ZeroCodeHash(_)))
    ));
    let sender = changed.pre_accounts.iter().position(|account| account.address == chain.sender).unwrap();
    let mut changed = witness.clone();
    changed.pre_accounts[sender].code_hash = B256::ZERO;
    assert!(matches!(
        chain.verify(&changed, &context, &body),
        Err(SparseNodeError::Verify(SparseVerifyError::ZeroCodeHash(_)))
    ));
    // The sender is an EOA: giving it the script's code hash is refused by the leaf.
    let mut changed = witness.clone();
    changed.pre_accounts[sender].code_hash = keccak256(script_runtime());
    assert!(matches!(
        chain.verify(&changed, &context, &body),
        Err(SparseNodeError::Verify(SparseVerifyError::AccountNotProven(_)))
    ));
    // Unused extra code: harmless, same outcome.
    let mut changed = witness.clone();
    changed.codes.push(victim_runtime().into());
    let outcome = chain.verify(&changed, &context, &body).unwrap();
    assert_eq!(outcome.header, canonical.header);
    // Without the script's code: the call loads it and fails the block.
    let mut changed = witness.clone();
    changed.codes.retain(|code| keccak256(code) != script_hash);
    assert!(matches!(chain.verify(&changed, &context, &body), Err(SparseNodeError::Execution(_))));
}

/// Not a finding: the witness is malleable, and the statement does not depend on it.
/// Order, padding and extra exposure only change the program's input.
#[test]
fn witness_malleability_does_not_reach_the_statement() {
    let mut chain = Chain::new(ChainSpec::mainnet_v1());
    let target = chain.deploy_script();
    let bystander = chain.deploy_script();
    let tx = chain.call(target, script(&[(SSTORE, u(1), u(2)), (SSTORE, u(2), u(3))]));
    let body = chain.body(vec![tx]);
    chain.commit(&body);
    let tx = chain.call(target, script(&[(SLOAD, u(1), u(0)), (SSTORE, u(9), u(1))]));
    let body = chain.body(vec![tx]);
    let (witness, _, context) = chain.differential(&body, "base");
    let settlement = Chain::settlement(&body);
    let expected =
        execute_settlement_statement_v3_sparse(&chain.spec, MAINNET_DOMAIN, &witness, &context, &body, settlement, BlockHashes::Lazy).unwrap();

    let trie = chain.state.warm_commitment().unwrap();
    let mut changed = witness.clone();
    changed.pre_accounts.reverse();
    changed.absent_accounts.reverse();
    // An account the block does not touch, hydrated and with all of its storage open.
    let info = chain.state.account(&bystander).unwrap();
    changed.proof.extend(trie.proof([account_key(&bystander)]).unwrap());
    changed.pre_accounts.push(SparseWitnessAccount {
        address: bystander,
        balance: info.balance,
        nonce: info.nonce,
        code_hash: keccak256(script_runtime()),
        storage_root: trie.storage_root_cached(&bystander).unwrap(),
        storage_proof: trie.storage_proof(&bystander, [storage_key(&u(1))]).unwrap(),
    });
    // An address the block does not touch, proved absent.
    let unrelated = Address::repeat_byte(0xab);
    changed.proof.extend(trie.proof([account_key(&unrelated)]).unwrap());
    changed.absent_accounts.push(unrelated);
    let got =
        execute_settlement_statement_v3_sparse(&chain.spec, MAINNET_DOMAIN, &changed, &context, &body, settlement, BlockHashes::Lazy).unwrap();
    assert_eq!(got.encode(), expected.encode());
}
