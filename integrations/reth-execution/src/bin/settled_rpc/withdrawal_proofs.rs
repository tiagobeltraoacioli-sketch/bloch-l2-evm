// SPDX-License-Identifier: MIT OR Apache-2.0
//! `bloch_getWithdrawalProof`: Merkle proofs of outbox withdrawals, finalized
//! settlements only.
//!
//! The index holds nothing that the follower's verified status has not finalized:
//! it reads a block's receipts only after a finalized settlement covers that
//! block and raised the withdrawal count, and it publishes the new leaves only
//! if they fold to the `(withdrawal_root, withdrawal_count)` of that settlement
//! statement. Any mismatch freezes the method. It is an RPC convenience, not a
//! trust root: the client verifies every proof against the L1's retained roots
//! (`deployment/mainnet/withdraw/bloch-l2-withdraw.py`), and the L1 verifies it
//! again in the claim transaction.
//!
//! A proof is served against any finalized settlement that added withdrawals,
//! because a claim must prove against a root old enough to have matured on L1
//! (`withdrawals.claimable`), which is usually not the newest root. Requests are
//! answered from memory, without touching the database. The index costs about
//! 170 bytes per withdrawal and is rebuilt at start from finalized blocks that
//! added withdrawals.
use alloy_primitives::{keccak256, Address, B256};
use bloch_l2_evm::withdrawal::{
    empty_withdrawal_root, verify_withdrawal_proof, zero_hashes, Withdrawal, WITHDRAWAL_TREE_DEPTH,
};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
};

/// The withdrawal exists on this RPC's chain but no finalized settlement covers it.
pub const ERR_NOT_FINALIZED: i32 = -32041;
/// No withdrawal with this index on this RPC's chain.
pub const ERR_UNKNOWN_INDEX: i32 = -32042;
/// The requested root is not the root of a finalized settlement that added withdrawals.
pub const ERR_UNKNOWN_ROOT: i32 = -32043;
/// The requested finalized root is older than this withdrawal.
pub const ERR_INDEX_NOT_IN_ROOT: i32 = -32044;
/// The index is still reading finalized blocks; retry.
pub const ERR_CATCHING_UP: i32 = -32045;
/// A finalized settlement disagreed with the local receipts; nothing is served.
pub const ERR_FROZEN: i32 = -32046;

/// One entry of the follower's `finalized_settlements`, already matched against
/// the local canonical chain by `verified_levels`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalEntry {
    pub number: u64,
    pub hash: B256,
    pub commitment: Option<(B256, u64)>,
    pub native_slot: Value,
    pub native_block: Value,
}

/// The entries above L2 block `after`, or why the list cannot be read.
pub fn final_entries(status: &Value, after: u64) -> Result<Vec<FinalEntry>, String> {
    let list = status["finalized_settlements"].as_array().ok_or("no settlement list")?;
    let mut entries = Vec::new();
    // The list is contiguous from block 1 (`verified_levels` checks it).
    for entry in list.iter().skip(usize::try_from(after).map_err(|_| "height exceeds usize")?) {
        let number = entry["l2_number"].as_u64().ok_or("bad l2_number")?;
        let hash = entry["l2_hash"].as_str().unwrap_or_default().parse::<B256>().map_err(|e| e.to_string())?;
        let commitment = match entry.get("withdrawals").filter(|v| !v.is_null()) {
            // A V2 settlement has no outbox.
            None => None,
            Some(w) => Some((
                w["root"].as_str().unwrap_or_default().parse::<B256>().map_err(|e| e.to_string())?,
                w["count"].as_u64().ok_or("bad withdrawal count")?,
            )),
        };
        entries.push(FinalEntry {
            number,
            hash,
            commitment,
            native_slot: entry["native_slot"].clone(),
            native_block: entry["native_block"].clone(),
        });
    }
    Ok(entries)
}

/// A finalized settlement that added withdrawals.
#[derive(Clone, Debug)]
struct Settled {
    number: u64,
    hash: B256,
    root: B256,
    count: u64,
    native_slot: Value,
    native_block: Value,
}

/// The finalized withdrawal tree. `levels[h][p]` is the root of the complete
/// subtree of height `h` at position `p`.
pub struct ProofIndex {
    chain_id: u64,
    zero: [B256; WITHDRAWAL_TREE_DEPTH + 1],
    levels: Vec<Vec<B256>>,
    leaves: Vec<(Withdrawal, u64)>,
    settled: Vec<Settled>,
    by_root: HashMap<B256, usize>,
    /// Last finalized L2 block whose commitment was checked.
    indexed: u64,
    frozen: Option<String>,
}

fn pair(left: B256, right: B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left.as_slice());
    buf[32..].copy_from_slice(right.as_slice());
    keccak256(buf)
}

impl ProofIndex {
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            zero: zero_hashes(),
            levels: vec![Vec::new(); WITHDRAWAL_TREE_DEPTH + 1],
            leaves: Vec::new(),
            settled: Vec::new(),
            by_root: HashMap::new(),
            indexed: 0,
            frozen: None,
        }
    }

    pub fn indexed(&self) -> u64 {
        self.indexed
    }

    pub fn count(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen.is_some()
    }

    /// Stop serving for good; the operator must investigate and restart.
    pub fn freeze(&mut self, reason: String) {
        self.frozen.get_or_insert(reason);
    }

    fn push(&mut self, withdrawal: Withdrawal, block: u64) {
        let mut node = withdrawal.leaf(self.chain_id);
        self.leaves.push((withdrawal, block));
        for height in 0..WITHDRAWAL_TREE_DEPTH {
            self.levels[height].push(node);
            let len = self.levels[height].len();
            if len % 2 == 1 {
                return;
            }
            node = pair(self.levels[height][len - 2], self.levels[height][len - 1]);
        }
        self.levels[WITHDRAWAL_TREE_DEPTH].push(node);
    }

    /// The subtree of height `height` at `position` in the tree over the first
    /// `count` leaves. Only one partial subtree exists per height, so a call
    /// hashes at most `height` times.
    fn subtree(&self, height: usize, position: u64, count: u64) -> B256 {
        let start = u128::from(position) << height;
        let end = start + (1u128 << height);
        if start >= u128::from(count) {
            self.zero[height]
        } else if end <= u128::from(count) {
            self.levels[height][position as usize]
        } else {
            pair(self.subtree(height - 1, position * 2, count), self.subtree(height - 1, position * 2 + 1, count))
        }
    }

    fn root_at(&self, count: u64) -> B256 {
        self.subtree(WITHDRAWAL_TREE_DEPTH, 0, count)
    }

    fn siblings(&self, index: u64, count: u64) -> [B256; WITHDRAWAL_TREE_DEPTH] {
        let mut siblings = [B256::ZERO; WITHDRAWAL_TREE_DEPTH];
        for (height, sibling) in siblings.iter_mut().enumerate() {
            *sibling = self.subtree(height, (index >> height) ^ 1, count);
        }
        siblings
    }

    /// How many withdrawals block `entry` adds, or an inconsistency.
    pub fn added_by(&self, entry: &FinalEntry) -> Result<u64, String> {
        let Some((_, count)) = entry.commitment else { return Ok(0) };
        count.checked_sub(self.count()).ok_or_else(|| {
            format!("settled withdrawal count {count} of block {} is below the indexed {}", entry.number, self.count())
        })
    }

    /// Apply the next finalized settlement with the withdrawals of its block.
    /// Nothing becomes servable unless the leaves fold to the settled commitment.
    pub fn apply(&mut self, entry: &FinalEntry, withdrawals: Vec<Withdrawal>) -> Result<(), String> {
        if entry.number != self.indexed + 1 {
            return Err(format!("finalized block {} follows indexed {}", entry.number, self.indexed));
        }
        let Some((root, count)) = entry.commitment else {
            if !withdrawals.is_empty() {
                return Err(format!("block {} has withdrawals but its settlement has no outbox", entry.number));
            }
            self.indexed = entry.number;
            return Ok(());
        };
        let added = self.added_by(entry)?;
        if added != withdrawals.len() as u64 {
            return Err(format!("block {} has {} withdrawals, its settlement adds {added}", entry.number, withdrawals.len()));
        }
        let first = self.count();
        for (withdrawal, nonce) in withdrawals.into_iter().zip(first..) {
            if withdrawal.nonce != nonce {
                return Err(format!("block {} withdrawal nonce {} where {nonce} is due", entry.number, withdrawal.nonce));
            }
            self.push(withdrawal, entry.number);
        }
        let own = if count == 0 { empty_withdrawal_root() } else { self.root_at(count) };
        if own != root {
            return Err(format!("block {} rebuilt withdrawal root {own} differs from settled {root} (count {count})", entry.number));
        }
        if added > 0 {
            self.by_root.insert(root, self.settled.len());
            self.settled.push(Settled {
                number: entry.number,
                hash: entry.hash,
                root,
                count,
                native_slot: entry.native_slot.clone(),
                native_block: entry.native_block.clone(),
            });
        }
        self.indexed = entry.number;
        Ok(())
    }

    /// The proof document: the `withdrawal-proof` shape that native
    /// `l2-claim prepare` reads, plus the settlement's L1 anchor.
    fn document(&self, index: u64, settled: &Settled) -> Result<Value, ErrorObjectOwned> {
        let (withdrawal, block) = &self.leaves[index as usize];
        let leaf = withdrawal.leaf(self.chain_id);
        let siblings = self.siblings(index, settled.count);
        if !verify_withdrawal_proof(leaf, index, &siblings, settled.root) {
            return Err(failure(-32603, "internal error: the proof does not verify", Value::Null));
        }
        Ok(json!({
            "chain_id": self.chain_id,
            "number": settled.number,
            "withdrawal_root": alloy_primitives::hex::encode(settled.root),
            "withdrawal_count": settled.count,
            "index": index,
            "withdrawal": {
                "nonce": withdrawal.nonce,
                "l1_recipient": alloy_primitives::hex::encode(withdrawal.l1_recipient),
                "sats": withdrawal.sats,
                "sender": alloy_primitives::hex::encode(withdrawal.sender),
                "l2_block": block,
                "leaf": alloy_primitives::hex::encode(leaf),
            },
            "siblings": siblings.iter().map(alloy_primitives::hex::encode).collect::<Vec<_>>(),
            "finalized": true,
            "l2_hash": alloy_primitives::hex::encode(settled.hash),
            "native_slot": settled.native_slot,
            "native_block": settled.native_block,
        }))
    }

    /// Answer one request. `latest_count` is the outbox counter at this RPC's
    /// head and `finalized` the highest L2 block the status finalizes; both only
    /// choose the error.
    pub fn answer(&self, index: u64, root: Option<B256>, latest_count: u64, finalized: u64) -> Result<Value, ErrorObjectOwned> {
        if self.frozen.is_some() {
            return Err(failure(ERR_FROZEN, "withdrawal proofs are frozen: finalized settlements disagree with this RPC's receipts", Value::Null));
        }
        let finalized_count = self.count();
        let data = || json!({"finalized_count": finalized_count, "latest_count": latest_count, "finalized_block": self.indexed});
        let settled = match root {
            Some(root) => {
                let Some(position) = self.by_root.get(&root) else {
                    let reason = if self.indexed < finalized { ERR_CATCHING_UP } else { ERR_UNKNOWN_ROOT };
                    return Err(failure(reason, "this root is not the withdrawal root of a finalized settlement known here", data()));
                };
                &self.settled[*position]
            }
            None => match self.settled.last() {
                Some(settled) if index < settled.count => settled,
                _ => {
                    let (code, message) = if index >= latest_count {
                        (ERR_UNKNOWN_INDEX, "no withdrawal with this index on this RPC's chain")
                    } else if self.indexed < finalized {
                        (ERR_CATCHING_UP, "the proof index is still reading finalized blocks")
                    } else {
                        (ERR_NOT_FINALIZED, "this withdrawal is not covered by a finalized settlement yet")
                    };
                    return Err(failure(code, message, data()));
                }
            },
        };
        if index >= settled.count {
            return Err(failure(ERR_INDEX_NOT_IN_ROOT, "this withdrawal is newer than the requested root", json!({"root_count": settled.count})));
        }
        self.document(index, settled)
    }
}

fn failure(code: i32, message: &str, data: Value) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, message.to_string(), (!data.is_null()).then_some(data))
}

fn invalid(message: &str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, message.to_string(), None::<()>)
}

fn parse_index(value: &Value) -> Result<u64, ErrorObjectOwned> {
    match value {
        Value::Number(n) => n.as_u64(),
        Value::String(text) => text.strip_prefix("0x").and_then(|hex| u64::from_str_radix(hex, 16).ok()),
        _ => None,
    }
    .ok_or_else(|| invalid("index must be a hex quantity or an integer"))
}

fn parse_root(value: &Value) -> Result<Option<B256>, ErrorObjectOwned> {
    let bad = || invalid("root must be 32 bytes of hex");
    match value {
        Value::Null => Ok(None),
        Value::String(text) => {
            let digits = text.strip_prefix("0x").unwrap_or(text);
            if digits.len() != 64 {
                return Err(bad());
            }
            digits.parse::<B256>().map(Some).map_err(|_| bad())
        }
        _ => Err(bad()),
    }
}

/// The index and what the polling task feeds it.
pub struct Shared {
    pub index: RwLock<ProofIndex>,
    pub latest_count: AtomicU64,
    pub finalized: AtomicU64,
    pub stop: AtomicBool,
    pub outbox: Address,
}

impl Shared {
    pub fn new(chain_id: u64, outbox: Address) -> Arc<Self> {
        Arc::new(Self {
            index: RwLock::new(ProofIndex::new(chain_id)),
            latest_count: AtomicU64::new(0),
            finalized: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            outbox,
        })
    }

    /// Apply `entries` in order. Blocks whose settlement adds nothing are not
    /// read at all. `read_block` errors are retried on the next call; a
    /// disagreement with the settled commitment freezes the index.
    pub fn catch_up(
        &self,
        entries: &[FinalEntry],
        mut read_block: impl FnMut(u64) -> Result<Vec<Withdrawal>, String>,
    ) -> Result<(), String> {
        for entry in entries {
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            let added = {
                let index = self.index.read().map_err(|_| "index lock poisoned")?;
                if index.is_frozen() {
                    return Ok(());
                }
                index.added_by(entry)
            };
            let withdrawals = match added {
                Ok(0) => Vec::new(),
                Ok(_) => read_block(entry.number)?,
                Err(reason) => {
                    self.index.write().map_err(|_| "index lock poisoned")?.freeze(reason.clone());
                    return Err(reason);
                }
            };
            let mut index = self.index.write().map_err(|_| "index lock poisoned")?;
            if let Err(reason) = index.apply(entry, withdrawals) {
                index.freeze(reason.clone());
                return Err(reason);
            }
        }
        Ok(())
    }
}

/// `bloch_getWithdrawalProof(index, root?)`. Without `root`: the newest finalized
/// settlement that added withdrawals.
pub fn rpc(shared: Arc<Shared>) -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("bloch_getWithdrawalProof", move |params, _, _| {
            let values: Vec<Value> = params.parse()?;
            if values.is_empty() || values.len() > 2 {
                return Err(invalid("expected [index, root?]"));
            }
            let index = parse_index(&values[0])?;
            let root = parse_root(values.get(1).unwrap_or(&Value::Null))?;
            let guard = shared.index.read().map_err(|_| failure(-32603, "index lock poisoned", Value::Null))?;
            guard.answer(index, root, shared.latest_count.load(Ordering::Relaxed), shared.finalized.load(Ordering::Relaxed))
        })
        .expect("the withdrawal proof method name is unique in a new module");
    module
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_l2_evm::withdrawal::{WithdrawalTree, MIN_WITHDRAWAL_SATS};

    const CHAIN: u64 = 700_770;

    fn withdrawal(nonce: u64) -> Withdrawal {
        Withdrawal {
            nonce,
            l1_recipient: B256::repeat_byte((nonce % 200 + 1) as u8),
            sats: MIN_WITHDRAWAL_SATS + nonce,
            sender: Address::repeat_byte(7),
        }
    }

    /// Blocks 1.. adding `sizes[n - 1]` withdrawals; `(entries, blocks)`.
    fn chain(sizes: &[u64]) -> (Vec<FinalEntry>, HashMap<u64, Vec<Withdrawal>>) {
        let (mut entries, mut blocks, mut leaves) = (Vec::new(), HashMap::new(), Vec::new());
        for (i, size) in sizes.iter().enumerate() {
            let number = i as u64 + 1;
            let first = leaves.len() as u64;
            let added: Vec<_> = (first..first + size).map(withdrawal).collect();
            leaves.extend(added.iter().map(|w| w.leaf(CHAIN)));
            blocks.insert(number, added);
            let tree = WithdrawalTree::new(leaves.clone()).unwrap();
            entries.push(FinalEntry {
                number,
                hash: B256::repeat_byte(number as u8),
                commitment: Some((tree.root(), tree.count())),
                native_slot: json!(1000 + number),
                native_block: json!(alloy_primitives::hex::encode(B256::repeat_byte(0xbb))),
            });
        }
        (entries, blocks)
    }

    fn shared() -> Arc<Shared> {
        Shared::new(CHAIN, Address::repeat_byte(1))
    }

    fn feed(s: &Shared, entries: &[FinalEntry], blocks: &HashMap<u64, Vec<Withdrawal>>) -> Result<(), String> {
        s.catch_up(entries, |n| Ok(blocks[&n].clone()))
    }

    fn code<T: core::fmt::Debug>(r: Result<T, ErrorObjectOwned>) -> i32 {
        r.unwrap_err().code()
    }

    #[test]
    fn every_proof_at_every_settled_root_matches_the_full_tree() {
        let sizes = [1, 0, 2, 3, 5, 0, 8, 13, 21, 1, 1, 64];
        let (entries, blocks) = chain(&sizes);
        let s = shared();
        feed(&s, &entries, &blocks).unwrap();
        let index = s.index.read().unwrap();
        assert_eq!(index.indexed(), sizes.len() as u64);
        assert_eq!(index.settled.len(), 10, "only settlements that added withdrawals are roots");
        let all: Vec<B256> = (0..index.count()).map(|n| withdrawal(n).leaf(CHAIN)).collect();
        for entry in entries.iter().filter(|e| !blocks[&e.number].is_empty()) {
            let (root, count) = entry.commitment.unwrap();
            let tree = WithdrawalTree::new(all[..count as usize].to_vec()).unwrap();
            for i in 0..count {
                let doc = index.answer(i, Some(root), count, index.indexed()).unwrap();
                let expected: Vec<String> = tree.proof(i).unwrap().iter().map(alloy_primitives::hex::encode).collect();
                assert_eq!(doc["siblings"], json!(expected), "index {i} at count {count}");
                assert_eq!(doc["number"], entry.number);
                assert_eq!(doc["withdrawal_count"], count);
                assert_eq!(doc["finalized"], true);
            }
        }
    }

    #[test]
    fn the_newest_finalized_root_is_the_default_and_the_document_is_the_produce_dev_shape() {
        let (entries, blocks) = chain(&[2, 3]);
        let s = shared();
        feed(&s, &entries, &blocks).unwrap();
        let doc = s.index.read().unwrap().answer(1, None, 5, 2).unwrap();
        assert_eq!(doc["number"], 2);
        assert_eq!(doc["withdrawal_count"], 5);
        assert_eq!(doc["chain_id"], CHAIN);
        assert_eq!(doc["index"], 1);
        assert_eq!(doc["withdrawal"]["nonce"], 1);
        assert_eq!(doc["withdrawal"]["sats"], MIN_WITHDRAWAL_SATS + 1);
        assert_eq!(doc["withdrawal"]["l2_block"], 1);
        assert_eq!(doc["withdrawal"]["leaf"], json!(alloy_primitives::hex::encode(withdrawal(1).leaf(CHAIN))));
        assert_eq!(doc["siblings"].as_array().unwrap().len(), 32);
        assert_eq!(doc["native_slot"], 1002);
    }

    #[test]
    fn unfinalized_unknown_and_foreign_requests_get_distinct_errors() {
        let (entries, blocks) = chain(&[2, 3, 4]);
        let s = shared();
        feed(&s, &entries[..2], &blocks).unwrap();
        let index = s.index.read().unwrap();
        // Index 5 exists at the head (9 withdrawals), block 3 is not finalized.
        assert_eq!(code(index.answer(5, None, 9, 2)), ERR_NOT_FINALIZED);
        assert_eq!(code(index.answer(9, None, 9, 2)), ERR_UNKNOWN_INDEX);
        assert_eq!(code(index.answer(u64::MAX, None, 9, 2)), ERR_UNKNOWN_INDEX);
        // The status finalized block 3, the index has not read it yet.
        assert_eq!(code(index.answer(5, None, 9, 3)), ERR_CATCHING_UP);
        // A root the producer computed but no finalized settlement carries.
        let (unsettled, _) = entries[2].commitment.unwrap();
        assert_eq!(code(index.answer(0, Some(unsettled), 9, 2)), ERR_UNKNOWN_ROOT);
        assert_eq!(code(index.answer(0, Some(unsettled), 9, 3)), ERR_CATCHING_UP);
        // An older finalized root does not hold a newer withdrawal.
        let (old, _) = entries[0].commitment.unwrap();
        assert_eq!(code(index.answer(4, Some(old), 9, 2)), ERR_INDEX_NOT_IN_ROOT);
        assert!(index.answer(1, Some(old), 9, 2).is_ok());
    }

    #[test]
    fn nothing_is_served_before_the_first_finalized_withdrawal() {
        let s = shared();
        let index = s.index.read().unwrap();
        assert_eq!(code(index.answer(0, None, 0, 0)), ERR_UNKNOWN_INDEX);
        assert_eq!(code(index.answer(0, None, 1, 0)), ERR_NOT_FINALIZED);
    }

    #[test]
    fn blocks_that_add_nothing_are_not_read() {
        let (entries, _) = chain(&[0, 0, 1, 0]);
        let s = shared();
        let mut read = Vec::new();
        s.catch_up(&entries, |n| {
            read.push(n);
            Ok(vec![withdrawal(0)])
        })
        .unwrap();
        assert_eq!(read, vec![3]);
        assert_eq!(s.index.read().unwrap().indexed(), 4);
    }

    #[test]
    fn a_receipt_read_failure_is_retried_without_freezing() {
        let (entries, blocks) = chain(&[1, 1]);
        let s = shared();
        assert!(s.catch_up(&entries, |n| if n == 2 { Err("busy".into()) } else { Ok(blocks[&n].clone()) }).is_err());
        assert!(!s.index.read().unwrap().is_frozen());
        assert_eq!(s.index.read().unwrap().indexed(), 1);
        feed(&s, &entries[1..], &blocks).unwrap();
        assert_eq!(s.index.read().unwrap().indexed(), 2);
    }

    #[test]
    fn local_receipts_that_disagree_with_the_settlement_freeze_the_method() {
        let check = |entries: &[FinalEntry], blocks: &HashMap<u64, Vec<Withdrawal>>| {
            let s = shared();
            assert!(feed(&s, entries, blocks).is_err());
            let index = s.index.read().unwrap();
            assert!(index.is_frozen());
            assert_eq!(code(index.answer(0, None, 1, 1)), ERR_FROZEN);
        };
        let (entries, blocks) = chain(&[2]);
        // Other sats in a local leaf.
        let mut wrong = blocks.clone();
        wrong.get_mut(&1).unwrap()[1].sats += 1;
        check(&entries, &wrong);
        // A count that does not match the local events.
        let mut wrong = blocks.clone();
        wrong.get_mut(&1).unwrap().pop();
        check(&entries, &wrong);
        // Nonces out of order.
        let mut wrong = blocks.clone();
        wrong.get_mut(&1).unwrap().swap(0, 1);
        check(&entries, &wrong);
        // A settled root that the leaves do not fold to.
        let mut other = entries.clone();
        other[0].commitment = Some((B256::repeat_byte(9), 2));
        check(&other, &blocks);
        // A settled count going backwards.
        let (mut two, two_blocks) = chain(&[2, 0]);
        let root = two[1].commitment.unwrap().0;
        two[1].commitment = Some((root, 1));
        check(&two, &two_blocks);
    }

    #[test]
    fn status_entries_parse_from_the_follower_shape() {
        let hash = alloy_primitives::hex::encode(B256::repeat_byte(3));
        let status = json!({"finalized_settlements": [
            {"l2_number": 1, "l2_hash": hash, "withdrawals": null, "native_slot": 5, "native_block": "aa"},
            {"l2_number": 2, "l2_hash": hash, "withdrawals": {"root": hash, "count": 4}, "native_slot": 6, "native_block": "bb"},
        ]});
        let all = final_entries(&status, 0).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].commitment, None);
        assert_eq!(all[1].commitment, Some((B256::repeat_byte(3), 4)));
        assert_eq!(final_entries(&status, 1).unwrap().len(), 1);
        assert!(final_entries(&status, 2).unwrap().is_empty());
        assert!(final_entries(&json!({}), 0).is_err());
        assert!(final_entries(&json!({"finalized_settlements": [{"l2_number": 1, "l2_hash": hash, "withdrawals": {"root": "zz", "count": 1}}]}), 0).is_err());
    }

    #[tokio::test]
    async fn the_method_parses_quantities_and_roots_and_refuses_the_rest() {
        let (entries, blocks) = chain(&[2, 1]);
        let s = shared();
        feed(&s, &entries, &blocks).unwrap();
        s.finalized.store(2, Ordering::Relaxed);
        s.latest_count.store(3, Ordering::Relaxed);
        let module = rpc(s);
        let (old, _) = entries[0].commitment.unwrap();
        let doc: Value = module.call("bloch_getWithdrawalProof", jsonrpsee::rpc_params![1]).await.unwrap();
        assert_eq!(doc["withdrawal_count"], 3);
        let doc: Value = module.call("bloch_getWithdrawalProof", jsonrpsee::rpc_params!["0x1"]).await.unwrap();
        assert_eq!(doc["index"], 1);
        let doc: Value = module.call("bloch_getWithdrawalProof", jsonrpsee::rpc_params![1, old]).await.unwrap();
        assert_eq!(doc["withdrawal_count"], 2);
        let bare = alloy_primitives::hex::encode(old);
        let doc: Value = module.call("bloch_getWithdrawalProof", jsonrpsee::rpc_params![1, bare]).await.unwrap();
        assert_eq!(doc["withdrawal_count"], 2);
        for bad in [
            jsonrpsee::rpc_params![],
            jsonrpsee::rpc_params!["1"],
            jsonrpsee::rpc_params![true],
            jsonrpsee::rpc_params![1, "abcd"],
            jsonrpsee::rpc_params![1, "not hex"],
            jsonrpsee::rpc_params![1, 5],
            jsonrpsee::rpc_params![1, old, 3],
        ] {
            assert!(module.call::<_, Value>("bloch_getWithdrawalProof", bad).await.is_err());
        }
    }
}
