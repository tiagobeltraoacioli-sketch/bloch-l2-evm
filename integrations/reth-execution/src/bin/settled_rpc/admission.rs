// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transaction-specific sequencer fee feedback. This is host admission policy;
//! the selector runs against a disposable cache and never persists a block.
//!
//! With an `admission.version` 2 policy file the producer's rules of what it executes at all
//! (`docs/SEQUENCER-POLICY-V2.md` section 6, `WritePrice` in `src/node_execution/select.rs`) are applied
//! here too, before any EVM run (review R308-5P-4): a plain transfer (gas limit 21,000, no data) always
//! passes; an exempt sender always passes; nothing else above `max_tx_gas` passes
//! (`sequencer-gas-limit-above-cap`); and a transaction above `uncovered_max_gas` passes only when its
//! sender's published credit is at least `gas limit x max(effective tip, 1)` (`sequencer-needs-credit`).
//! `bloch_admissionQuote` reports the same verdict for an unsigned call. The producer's per-block pools
//! and waits are not mirrored: they are states of one block, not properties of a transaction.
use alloy_primitives::{Address, B256, U256};
use bloch_l2_evm::{
    node_execution::select::{quote_node_transaction, select_node_transactions, QuoteCall, SelectionLimits, TxStats},
    AuthenticatedTransaction, BlockContext, ChainSpec,
};
use bloch_reth_execution::{BlochNodeHeader, BlochProviderFactory, LatestDerivedPending};
use jsonrpsee::types::ErrorObjectOwned;
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::SealedHeader;
use reth_provider::{AccountReader, BlockNumReader, HeaderProvider, StateProviderBox};
use reth_revm::database::StateProviderDatabase;
use std::{collections::BTreeMap, io::Read, path::Path, time::Instant};

use super::{rpc_error, SIMULATION_GAS_CAP, TIP_FILE_MAX_BYTES};

/// Published atomically in the existing required-tip file by policy v2.
/// A configured but incomplete/legacy file must not silently mean zero price.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Policy {
    pub required_tip: u128,
    pub fresh_slot_price: u128,
    pub exempt: Vec<Address>,
    /// The producer's execution rules (`admission.version` 2). `None` for a version 1 file: rules off.
    pub rules: Option<ExecutionRules>,
}

/// What the producer executes at all, as published by the policy (`WritePrice` in the root crate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExecutionRules {
    /// No transaction of a sender that is not exempt is executed above this gas limit.
    pub max_tx_gas: u64,
    /// A transaction that its sender's credit does not cover is executed only up to this gas limit.
    pub uncovered_max_gas: u64,
    /// Per sender: priority fees really paid, less the fee value of its wasted work (wei).
    pub credit: BTreeMap<Address, u128>,
}

/// The producer's verdict on one transaction, before it runs. `rules` off: always executable.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Executability {
    /// `None`, `"gas-limit-above-cap"` or `"needs-credit"`: the producer's own names.
    refusal: Option<&'static str>,
    covered: bool,
    credit: u128,
    /// `gas limit x max(tip, 1)`: the credit that covers this transaction at this tip.
    credit_needed: U256,
}

/// Priority fee per gas a transaction pays at `base_fee` (0 when its fee cap is below it): the figure the
/// producer's selection uses, here at the next block's base fee of the admission head.
fn effective_tip(fee_cap: u128, priority_fee: Option<u128>, base_fee: u64) -> u128 {
    let cap = fee_cap.saturating_sub(u128::from(base_fee));
    priority_fee.map_or(cap, |priority| priority.min(cap))
}

impl Policy {
    pub fn read(path: &Path) -> Result<Self, ErrorObjectOwned> {
        let mut text = String::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(TIP_FILE_MAX_BYTES + 1).read_to_string(&mut text))
            .map_err(|e| rpc_error(format!("sequencer admission policy unavailable: {e}")))?;
        if text.len() as u64 > TIP_FILE_MAX_BYTES {
            return Err(rpc_error("sequencer admission policy is too large"));
        }
        Self::parse(&text).ok_or_else(|| {
            rpc_error(
                "sequencer admission policy is incomplete or malformed; policy v2 admission version 1 or 2 is required",
            )
        })
    }

    fn parse(text: &str) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(text).ok()?;
        let admission = value.get("admission")?.as_object()?;
        let version = admission.get("version")?.as_u64()?;
        if !(1..=2).contains(&version) {
            return None;
        }
        // Decimal strings preserve u128 exactly across JSON implementations.
        let integer = |v: &serde_json::Value| {
            let text = v.as_str()?;
            (!text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()))
                .then(|| text.parse::<u128>().ok())
                .flatten()
        };
        let required_tip = integer(admission.get("required_tip_wei")?)?;
        let fresh_slot_price = integer(admission.get("fresh_slot_price_wei")?)?;
        let exempt = admission
            .get("write_limit_exempt_senders")?
            .as_array()?
            .iter()
            .map(|v| v.as_str()?.parse::<Address>().ok())
            .collect::<Option<Vec<_>>>()?;
        // Version 2 adds the producer's execution rules; every field is required and exactly typed. Gas limits
        // are JSON unsigned integers; credit is an object of lower-case 0x addresses to decimal wei strings.
        let rules = if version == 2 {
            let credit = admission
                .get("credit")?
                .as_object()?
                .iter()
                .map(|(sender, wei)| {
                    let lower = sender.len() == 42
                        && sender.starts_with("0x")
                        && sender[2..].bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
                    Some((lower.then(|| sender.parse::<Address>().ok()).flatten()?, integer(wei)?))
                })
                .collect::<Option<BTreeMap<_, _>>>()?;
            Some(ExecutionRules {
                max_tx_gas: admission.get("max_tx_gas")?.as_u64()?,
                uncovered_max_gas: admission.get("uncovered_max_gas")?.as_u64()?,
                credit,
            })
        } else {
            None
        };
        Some(Self {
            required_tip,
            fresh_slot_price,
            exempt,
            rules,
        })
    }

    /// The producer's decision of what it executes at all (`select_priced_in_session`, `unexecuted`), for a
    /// transaction of `sender` with this gas limit, call data length and tip. The one rule both admission and
    /// `bloch_admissionQuote` use. Pure arithmetic: nothing is executed.
    fn executability(&self, sender: Address, gas_limit: u64, no_data: bool, tip: U256) -> Executability {
        let credit_needed = U256::from(gas_limit) * tip.max(U256::from(1));
        let Some(rules) = &self.rules else {
            return Executability {
                refusal: None,
                covered: true,
                credit: 0,
                credit_needed,
            };
        };
        let exempt = self.exempt.contains(&sender);
        let credit = rules.credit.get(&sender).copied().unwrap_or(0);
        let covered = exempt || U256::from(credit) >= credit_needed;
        let plain = gas_limit == 21_000 && no_data;
        let refusal = if plain {
            None
        } else if gas_limit > rules.max_tx_gas && !exempt {
            Some("gas-limit-above-cap")
        } else if !covered && gas_limit > rules.uncovered_max_gas {
            Some("needs-credit")
        } else {
            None
        };
        Executability {
            refusal,
            covered,
            credit,
            credit_needed,
        }
    }

    /// Refuse, before any EVM run, what the producer will not execute for this sender (review R308-5P-4).
    fn check_executable(
        &self,
        tx: &AuthenticatedTransaction,
        head: &SealedHeader<BlochNodeHeader>,
        base_fee: u64,
    ) -> Result<(), ErrorObjectOwned> {
        let Some(rules) = &self.rules else {
            return Ok(());
        };
        let env = tx.environment();
        let tip = effective_tip(env.gas_price, env.gas_priority_fee, base_fee);
        let verdict = self.executability(tx.sender(), env.gas_limit, env.data.is_empty(), U256::from(tip));
        let Some(reason) = verdict.refusal else {
            return Ok(());
        };
        let data = serde_json::json!({
            "kind": format!("sequencer-{reason}"),
            "transactionHash": tx.hash(),
            "headHash": head.hash(),
            "headNumber": format!("0x{:x}", head.0.number),
            "baseFeePerGas": format!("0x{base_fee:x}"),
            "effectivePriorityFeePerGas": format!("0x{tip:x}"),
            "gas_limit": env.gas_limit,
            "max_tx_gas": rules.max_tx_gas,
            "uncovered_max_gas": rules.uncovered_max_gas,
            "credit_wei": verdict.credit.to_string(),
            "credit_needed_wei": verdict.credit_needed.to_string(),
            // Null for a covered sender (a refusal for the cap alone), as in the quote.
            "first_transfer_priority_fee_wei": (!verdict.covered).then(|| first_transfer_tip(verdict.credit_needed).to_string()),
            "scope": "latest-state-next-block"
        });
        let message = if reason == "gas-limit-above-cap" {
            "transaction will not be executed: its gas limit is above the sequencer's limit for one transaction \
             (error.data.max_tx_gas); a higher tip does not help, send it with a smaller gas limit"
        } else {
            "transaction will not be executed: its gas limit is above the limit for a sender without enough fee \
             credit (error.data.uncovered_max_gas); a higher tip does not help, send it with a smaller gas limit, or \
             first send a plain transfer (always executed) with a priority fee per gas of \
             error.data.first_transfer_priority_fee_wei, so that the priority fees you have paid reach \
             error.data.credit_needed_wei"
        };
        Err(ErrorObjectOwned::owned(-32000, message, Some(data)))
    }

    pub fn verify(&self, path: &Path) -> Result<(), ErrorObjectOwned> {
        if Self::read(path)? != *self {
            return Err(rpc_error(
                "sequencer admission policy changed during preflight; retry the transaction",
            ));
        }
        Ok(())
    }

    /// (new slots, charged new slots, required priority fee per gas) for one measured execution: the one
    /// rule both the admission verdict and `bloch_admissionQuote` use, so a quote is what admission asks.
    fn requirement(&self, stats: &TxStats) -> Result<(u64, u64, U256), ErrorObjectOwned> {
        let slots = stats
            .fresh_slots
            .iter()
            .try_fold(0u64, |total, (_, n)| total.checked_add(*n))
            .ok_or_else(|| rpc_error("sequencer admission storage count overflow"))?;
        let charged_slots = if self.exempt.contains(&stats.sender) { 0 } else { slots };
        // U256 keeps slots * price and exact ceiling division safe even for a
        // malformed extreme operator price. Never use floating-point fees.
        let cost = U256::from(charged_slots) * U256::from(self.fresh_slot_price);
        let gas = U256::from(stats.gas_used);
        if gas.is_zero() {
            return Err(rpc_error("sequencer admission returned zero gas used"));
        }
        let write_tip = cost / gas + U256::from(!((cost % gas).is_zero()));
        Ok((slots, charged_slots, write_tip.max(U256::from(self.required_tip))))
    }

    fn check(
        &self,
        stats: &TxStats,
        head: &SealedHeader<BlochNodeHeader>,
        base_fee: u64,
    ) -> Result<(), ErrorObjectOwned> {
        let (slots, charged_slots, required) = self.requirement(stats)?;
        if U256::from(stats.effective_tip) >= required {
            return Ok(());
        }
        let data = serde_json::json!({
            "kind": "sequencer-fee-underpriced",
            "transactionHash": stats.hash,
            "headHash": head.hash(),
            "headNumber": format!("0x{:x}", head.0.number),
            "baseFeePerGas": format!("0x{base_fee:x}"),
            "requiredPriorityFeePerGas": format!("0x{required:x}"),
            "requiredMaxFeePerGas": format!("0x{:x}", required + U256::from(base_fee)),
            "effectivePriorityFeePerGas": format!("0x{:x}", stats.effective_tip),
            "gasUsed": format!("0x{:x}", stats.gas_used),
            "freshSlots": format!("0x{slots:x}"),
            "chargedFreshSlots": format!("0x{charged_slots:x}"),
            "freshSlotPriceWei": format!("0x{:x}", self.fresh_slot_price),
            "scope": "latest-state-next-block"
        });
        Err(ErrorObjectOwned::owned(-32000,
            "transaction underpriced for sequencer policy; use the transaction-specific fee in error.data (inclusion is not guaranteed)", Some(data)))
    }
}

/// One immutable state view, bound to a canonical head. The producer can move
/// independently, so its identity is checked again before using any verdict.
pub(super) struct Snapshot {
    pub header: SealedHeader<BlochNodeHeader>,
    pub state: StateProviderBox,
    spec: ChainSpec,
    domain: B256,
    pub context: BlockContext,
}

impl Snapshot {
    pub fn read(factory: &BlochProviderFactory) -> Result<Self, ErrorObjectOwned> {
        let number = factory
            .best_block_number()
            .map_err(|e| rpc_error(format!("state unavailable: {e}")))?;
        let header = factory
            .sealed_header(number)
            .map_err(|e| rpc_error(format!("state unavailable: {e}")))?
            .ok_or_else(|| rpc_error("state unavailable: head header missing"))?;
        let state = factory
            .history_by_block_hash(header.hash())
            .map_err(|e| rpc_error(format!("state unavailable at admission head: {e}")))?;
        let number = number
            .checked_add(1)
            .ok_or_else(|| rpc_error("admission head number overflow"))?;
        let chain = factory.chain_spec();
        let spec = chain.execution_at(number).clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let attributes = LatestDerivedPending::attributes(header.header(), now, None);
        let context = BlockContext {
            number,
            timestamp: attributes.timestamp,
            base_fee_per_gas: chain.rules().base_fee_after(&header.0),
            prevrandao: attributes.prevrandao,
            anchor_root: attributes.anchor_root,
        };
        let snapshot = Self {
            header,
            state,
            spec,
            domain: chain.domain(),
            context,
        };
        snapshot.verify(factory)?;
        Ok(snapshot)
    }

    pub fn account(&self, address: Address) -> Result<(u64, U256), ErrorObjectOwned> {
        self.state
            .basic_account(&address)
            .map(|account| account.map_or((0, U256::ZERO), |a| (a.nonce, a.balance)))
            .map_err(|e| rpc_error(format!("state unavailable: {e}")))
    }

    pub fn verify(&self, factory: &BlochProviderFactory) -> Result<(), ErrorObjectOwned> {
        let best = factory
            .best_block_number()
            .map_err(|e| rpc_error(format!("state unavailable: {e}")))?;
        let hash = factory
            .sealed_header(best)
            .map_err(|e| rpc_error(format!("state unavailable: {e}")))?
            .map(|header| header.hash());
        if hash != Some(self.header.hash()) {
            return Err(rpc_error(
                "canonical head changed during admission preflight; retry the transaction",
            ));
        }
        Ok(())
    }

    pub fn preflight(&self, tx: &AuthenticatedTransaction, policy: &Policy) -> Result<(), ErrorObjectOwned> {
        // First, and for every nonce: what the producer will not execute needs no execution to be known.
        policy.check_executable(tx, &self.header, self.context.base_fee_per_gas)?;
        if tx.environment().nonce != self.account(tx.sender())?.0 {
            // Earlier pending nonces can change every storage fact. Do not
            // pretend one isolated execution represents their sequence.
            return Ok(());
        }
        let selection = select_node_transactions(
            &self.spec,
            self.domain,
            StateProviderDatabase::new(self.state.as_ref()),
            self.header.0.state_root,
            &self.context,
            &[],
            std::slice::from_ref(tx.raw()),
            SelectionLimits {
                max_gas: SIMULATION_GAS_CAP,
                max_bytes: tx.raw().len(),
                max_transactions: 1,
            },
        )
        .map_err(|e| rpc_error(format!("admission preflight unavailable: {e}")))?;
        let stats = selection
            .stats
            .first()
            .filter(|stats| stats.hash == tx.hash())
            .ok_or_else(|| {
                rpc_error(format!(
                    "transaction cannot execute at admission head: dropped={:?}, deferred={:?}",
                    selection.dropped, selection.deferred
                ))
            })?;
        policy.check(stats, &self.header, self.context.base_fee_per_gas)
    }
}

/// The call of `bloch_admissionQuote`: what a wallet knows before it signs.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuoteRequest {
    pub from: Address,
    #[serde(default)]
    pub to: Option<Address>,
    #[serde(default)]
    pub data: Option<alloy_primitives::Bytes>,
    #[serde(default)]
    pub input: Option<alloy_primitives::Bytes>,
    #[serde(default)]
    pub value: Option<U256>,
    #[serde(default)]
    pub gas: Option<alloy_primitives::U64>,
}

impl Snapshot {
    /// What admission would require of `request` sent now as the sender's next transaction: the same
    /// session, execution, new-slot count and fee rule as [`Snapshot::preflight`], on an unsigned call.
    /// Read-only. It says nothing about the spool, other senders, bans or waits, and nothing a refused
    /// `eth_sendRawTransaction` does not already say in `error.data`; inclusion is not promised.
    ///
    /// `executable` is the producer's verdict (see the module comment) for a transaction with the gas limit
    /// in `gas_limit` and a priority fee of exactly `requiredPriorityFeePerGas`: the transaction a wallet
    /// that follows the quote signs. A higher tip needs more credit (`gas_limit x tip`) to be covered. Without
    /// `gas`, a version 2 policy runs the call at `max_tx_gas` for a sender that is not exempt.
    pub fn quote(&self, request: &QuoteRequest, policy: &Policy) -> Result<serde_json::Value, ErrorObjectOwned> {
        if request.data.is_some() && request.input.is_some() && request.data != request.input {
            return Err(rpc_error("admission quote: `data` and `input` differ"));
        }
        let (nonce, balance) = self.account(request.from)?;
        let base_fee = self.context.base_fee_per_gas;
        let cap = SIMULATION_GAS_CAP.min(self.spec.gas_limit);
        // No `gas`: the largest limit the producer may execute for this sender, so the verdict is not a refusal
        // of a limit the caller never chose.
        let unasked = match &policy.rules {
            Some(rules) if !policy.exempt.contains(&request.from) => cap.min(rules.max_tx_gas),
            _ => cap,
        };
        let gas_limit = request.gas.map_or(unasked, |gas| gas.to::<u64>().min(cap));
        // Measured at the lowest fee the block accepts (tip zero), so the balance needed for the quote is
        // the least a real transaction with this gas limit could need.
        let value = request.value.unwrap_or_default();
        let needed = U256::from(gas_limit) * U256::from(base_fee) + value;
        if balance < needed {
            return Err(rpc_error(format!(
                "admission quote: sender balance {balance} is below gas limit {gas_limit} at the next base fee plus value ({needed}); pass a smaller `gas`"
            )));
        }
        let call = QuoteCall {
            sender: request.from,
            to: request.to,
            data: request
                .data
                .clone()
                .or_else(|| request.input.clone())
                .unwrap_or_default(),
            value,
            gas_limit,
            nonce,
            max_fee_per_gas: u128::from(base_fee),
        };
        let stats = quote_node_transaction(
            &self.spec,
            self.domain,
            StateProviderDatabase::new(self.state.as_ref()),
            self.header.0.state_root,
            &self.context,
            &call,
        )
        .map_err(|e| rpc_error(format!("admission quote unavailable: {e}")))?
        .map_err(|reason| rpc_error(format!("call cannot execute at admission head: {reason}")))?;
        let (slots, charged_slots, required) = policy.requirement(&stats)?;
        let verdict = policy.executability(request.from, gas_limit, call.data.is_empty(), required);
        let rules = policy.rules.as_ref();
        Ok(serde_json::json!({
            "kind": "sequencer-admission-quote",
            "headHash": self.header.hash(),
            "headNumber": format!("0x{:x}", self.header.0.number),
            "nonce": format!("0x{nonce:x}"),
            "baseFeePerGas": format!("0x{base_fee:x}"),
            "requiredPriorityFeePerGas": format!("0x{required:x}"),
            "requiredMaxFeePerGas": format!("0x{:x}", required + U256::from(base_fee)),
            "minimumPriorityFeePerGas": format!("0x{:x}", policy.required_tip),
            "gasUsed": format!("0x{:x}", stats.gas_used),
            "freshSlots": format!("0x{slots:x}"),
            "chargedFreshSlots": format!("0x{charged_slots:x}"),
            "freshSlotPriceWei": format!("0x{:x}", policy.fresh_slot_price),
            // The amount itself (review R308-2P-15): admission asks gasUsed x tip >= this, so a transaction that
            // uses less gas than this run (an access list, another gas limit) owes more per gas than the figure above.
            "writePriceOwedWei": format!("0x{:x}", U256::from(charged_slots) * U256::from(policy.fresh_slot_price)),
            // The producer's execution rules (review R308-5P-4), for `gas_limit` at the quoted priority fee.
            // Numeric fields are null under a version 1 policy (rules off).
            "executable": verdict.refusal.is_none(),
            "not_executable_reason": verdict.refusal,
            "covered": verdict.covered,
            "gas_limit": gas_limit,
            "credit_wei": rules.map(|_| verdict.credit.to_string()),
            "credit_needed_wei": rules.map(|_| verdict.credit_needed.to_string()),
            // Review R308-6P-1: the door of a sender that is not covered is a plain transfer first. One transfer
            // at this priority fee earns the credit this call needs (null when it is covered or the rules are off).
            "first_transfer_priority_fee_wei": rules
                .filter(|_| !verdict.covered)
                .map(|_| first_transfer_tip(verdict.credit_needed).to_string()),
            "uncovered_max_gas": rules.map(|rules| rules.uncovered_max_gas),
            "max_tx_gas": rules.map(|rules| rules.max_tx_gas),
            "scope": "latest-state-next-block"
        }))
    }
}

pub(super) fn check_deadline(deadline: Instant) -> Result<(), ErrorObjectOwned> {
    if Instant::now() >= deadline {
        return Err(rpc_error(
            "admission preflight timed out; no transaction was spooled, retry later",
        ));
    }
    Ok(())
}

/// Priority fee per gas of ONE plain transfer (21,000 gas) that earns `credit_needed` (rounded up).
fn first_transfer_tip(credit_needed: U256) -> U256 {
    let gas = U256::from(21_000u64);
    credit_needed / gas + U256::from(!(credit_needed % gas).is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Bytes, Signature, TxKind};
    use bloch_l2_evm::{DepositMint, DepositProvenance};
    use bloch_reth_execution::{BlochChainSpec, BlochNextBlockEnvCtx, BlochTables, CanonicalCoordinator};
    use k256::ecdsa::SigningKey;
    use reth_db::mdbx::{init_db_for, DatabaseArguments};
    use reth_provider::{
        providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
        DBProvider, DatabaseProviderFactory, ProviderFactory,
    };
    use std::{path::PathBuf, sync::Arc, time::Duration};

    const FLOOR: u128 = 100_000_000;
    const PRICE: u128 = 200_000_000_000_000;
    fn key() -> SigningKey {
        SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
    }
    fn sender() -> Address {
        Address::from_public_key(key().verifying_key())
    }
    fn policy(exempt: Vec<Address>) -> Policy {
        Policy {
            required_tip: FLOOR,
            fresh_slot_price: PRICE,
            exempt,
            rules: None,
        }
    }
    const MAX_TX_GAS: u64 = 5_000_000;
    const UNCOVERED_MAX_GAS: u64 = 1_500_000;
    /// A version 2 policy with the deployment's limits and this credit for the test sender.
    fn ruled(exempt: Vec<Address>, credit: Option<u128>) -> Policy {
        Policy {
            rules: Some(ExecutionRules {
                max_tx_gas: MAX_TX_GAS,
                uncovered_max_gas: UNCOVERED_MAX_GAS,
                credit: credit.map(|wei| (sender(), wei)).into_iter().collect(),
            }),
            ..policy(exempt)
        }
    }
    fn document(policy: &Policy) -> String {
        let mut document = serde_json::json!({"admission": {
            "version": 1, "required_tip_wei": policy.required_tip.to_string(),
            "fresh_slot_price_wei": policy.fresh_slot_price.to_string(),
            "write_limit_exempt_senders": policy.exempt,
        }});
        if let Some(rules) = &policy.rules {
            let admission = document["admission"].as_object_mut().unwrap();
            admission.insert("version".into(), 2.into());
            admission.insert("max_tx_gas".into(), rules.max_tx_gas.into());
            admission.insert("uncovered_max_gas".into(), rules.uncovered_max_gas.into());
            let credit: serde_json::Map<_, _> = rules
                .credit
                .iter()
                .map(|(sender, wei)| (format!("{sender:#x}"), wei.to_string().into()))
                .collect();
            admission.insert("credit".into(), credit.into());
        }
        document.to_string()
    }
    fn signed(spec: &ChainSpec, nonce: u64, to: TxKind, input: Bytes, tip: u128, cap: u128) -> Bytes {
        let gas_limit = if matches!(to, TxKind::Create) {
            1_000_000
        } else {
            200_000
        };
        signed_with_gas(spec, nonce, to, input, tip, cap, gas_limit)
    }
    fn signed_with_gas(
        spec: &ChainSpec,
        nonce: u64,
        to: TxKind,
        input: Bytes,
        tip: u128,
        cap: u128,
        gas_limit: u64,
    ) -> Bytes {
        let tx = TxEip1559 {
            chain_id: spec.chain_id,
            nonce,
            to,
            input,
            gas_limit,
            max_fee_per_gas: cap,
            max_priority_fee_per_gas: tip,
            ..Default::default()
        };
        let signature: Signature = key()
            .sign_prehash_recoverable(tx.signature_hash().as_slice())
            .unwrap()
            .into();
        TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
    }

    struct World {
        _dir: tempfile::TempDir,
        factory: BlochProviderFactory,
        coordinator: CanonicalCoordinator,
        spool: Arc<super::super::Spool>,
        file: PathBuf,
    }
    impl World {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let kernel = ChainSpec::testnet();
            let spec = Arc::new(BlochChainSpec::new(kernel.clone(), B256::repeat_byte(0x71), 17).unwrap());
            let factory: BlochProviderFactory = ProviderFactory::new(
                Arc::new(init_db_for::<_, BlochTables>(dir.path().join("db"), DatabaseArguments::test()).unwrap()),
                spec.clone(),
                StaticFileProvider::read_write(dir.path().join("static")).unwrap(),
                RocksDBBuilder::new(dir.path().join("rocks"))
                    .with_default_tables()
                    .build()
                    .unwrap(),
                reth_tasks::Runtime::test(),
            )
            .unwrap();
            let genesis = {
                let state = factory.latest().unwrap();
                bloch_reth_execution::prepare_genesis(&spec, state.as_ref()).unwrap()
            };
            let writer = factory.database_provider_rw().unwrap();
            writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
            writer.commit().unwrap();
            let mut coordinator = CanonicalCoordinator::attach(factory.clone()).unwrap();
            // The DEX's real TestToken, built with solc 0.8.24. The checked-in
            // source, compiler settings and bytecode digests live beside it.
            let init = alloy_primitives::hex::decode(include_str!("fixtures/TestToken.creation.hex").trim()).unwrap();
            let deployment = signed(&kernel, 0, TxKind::Create, init.into(), FLOOR, 100_000_000_000);
            coordinator
                .extend_raw(
                    coordinator.head().hash(),
                    BlochNextBlockEnvCtx {
                        timestamp: 18,
                        prevrandao: B256::repeat_byte(3),
                        anchor_root: B256::repeat_byte(4),
                        deposits: vec![DepositMint {
                            recipient: sender(),
                            provenance: DepositProvenance::BridgedBlch {
                                l1_height: 1,
                                l1_tx_index: 0,
                                l1_txid: [1; 32],
                                l1_vout: 0,
                                l1_sats: 100_000_000,
                            },
                        }],
                    },
                    &[deployment],
                )
                .unwrap();
            let pool = dir.path().join("pool");
            std::fs::create_dir(&pool).unwrap();
            let file = dir.path().join("policy.json");
            std::fs::write(&file, document(&policy(vec![]))).unwrap();
            let spool = Arc::new(super::super::Spool {
                spec: kernel,
                dir: pool,
                index: Default::default(),
                progress: Default::default(),
                limits: super::super::SPOOL_LIMITS,
            });
            Self {
                _dir: dir,
                factory,
                coordinator,
                spool,
                file,
            }
        }
        fn approve(&self, nonce: u64, value: u64, tip: u128, cap: u128) -> Bytes {
            let mut input = vec![0x09, 0x5e, 0xa7, 0xb3];
            input.extend(Address::repeat_byte(0x22).into_word());
            input.extend(U256::from(value).to_be_bytes::<32>());
            signed(
                &self.spool.spec,
                nonce,
                TxKind::Call(sender().create(0)),
                input.into(),
                tip,
                cap,
            )
        }
        /// `approve(0x22…, value)` on the token with a chosen gas limit, at a 20 gwei fee cap.
        fn approve_with_gas(&self, nonce: u64, value: u64, tip: u128, gas_limit: u64) -> Bytes {
            let request = approve_request(value, None);
            signed_with_gas(
                &self.spool.spec,
                nonce,
                TxKind::Call(request.to.unwrap()),
                request.data.unwrap(),
                tip,
                FEE_CAP,
                gas_limit,
            )
        }
        fn publish(&self, policy: &Policy) {
            std::fs::write(&self.file, document(policy)).unwrap();
        }
        fn send(&self, raw: &Bytes) -> Result<B256, ErrorObjectOwned> {
            self.spool.submit(
                &self.factory,
                raw,
                Some(&self.file),
                Instant::now() + Duration::from_secs(5),
            )
        }
        fn empty_pool(&self) {
            assert_eq!(std::fs::read_dir(&self.spool.dir).unwrap().count(), 0);
        }
    }
    fn data(error: &ErrorObjectOwned) -> serde_json::Value {
        assert_eq!(error.code(), -32000);
        serde_json::from_str(error.data().unwrap().get()).unwrap()
    }
    fn quantity(value: &serde_json::Value) -> u128 {
        u128::from_str_radix(value.as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
    }

    #[tokio::test]
    async fn first_approve_reports_exact_price_and_does_not_write_state_or_spool() {
        let world = World::new();
        let before = world.factory.latest().unwrap().state_root(Default::default()).unwrap();
        let error = world
            .send(&world.approve(1, 1, FLOOR * 125 / 100, 100_000_000_000))
            .unwrap_err();
        let quote = data(&error);
        assert_eq!(quote["kind"], "sequencer-fee-underpriced");
        assert_eq!(quantity(&quote["freshSlots"]), 1);
        assert_eq!(quantity(&quote["chargedFreshSlots"]), 1);
        let gas = quantity(&quote["gasUsed"]);
        let needed = PRICE.div_ceil(gas);
        assert_eq!(quantity(&quote["requiredPriorityFeePerGas"]), needed);
        assert_eq!(
            quantity(&quote["requiredMaxFeePerGas"]),
            needed + quantity(&quote["baseFeePerGas"])
        );
        world.empty_pool();
        assert_eq!(
            world.factory.latest().unwrap().state_root(Default::default()).unwrap(),
            before
        );
        assert_eq!(world.factory.best_block_number().unwrap(), 1);
        assert_eq!(
            world
                .factory
                .latest()
                .unwrap()
                .basic_account(&sender())
                .unwrap()
                .unwrap()
                .nonce,
            1
        );
        assert!(world.send(&world.approve(1, 1, needed, 100_000_000_000)).is_ok());
        assert_eq!(
            world.factory.latest().unwrap().state_root(Default::default()).unwrap(),
            before
        );
        assert_eq!(
            std::fs::read_dir(&world.spool.dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "tx"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn effective_tip_respects_the_fee_cap_at_the_next_base_fee() {
        let world = World::new();
        let base = Snapshot::read(&world.factory).unwrap().context.base_fee_per_gas as u128;
        let quote = data(
            &world
                .send(&world.approve(1, 1, base + FLOOR, base + FLOOR))
                .unwrap_err(),
        );
        // Priority must not exceed the fee cap at decoding, so the next base
        // fee must leave less priority than the signed maximum.
        assert_eq!(quantity(&quote["effectivePriorityFeePerGas"]), FLOOR);
        world.empty_pool();
    }

    #[tokio::test]
    async fn zero_slots_exemption_and_future_nonce_keep_their_distinct_semantics() {
        let zero = World::new();
        assert!(zero.send(&zero.approve(1, 0, FLOOR, 100_000_000_000)).is_ok());
        let exempt = World::new();
        std::fs::write(&exempt.file, document(&policy(vec![sender()]))).unwrap();
        assert!(exempt.send(&exempt.approve(1, 1, FLOOR, 100_000_000_000)).is_ok());
        let future = World::new();
        assert!(future.send(&future.approve(2, 1, FLOOR, 100_000_000_000)).is_ok());
        assert_eq!(
            future
                .factory
                .latest()
                .unwrap()
                .basic_account(&sender())
                .unwrap()
                .unwrap()
                .nonce,
            1
        );
    }

    #[tokio::test]
    async fn an_already_spooled_hash_never_becomes_a_definitive_fee_refusal() {
        let world = World::new();
        let raw = world.approve(1, 1, 10_000_000_000, 100_000_000_000);
        let hash = world.send(&raw).unwrap();
        let mut changed = policy(vec![]);
        changed.fresh_slot_price *= 100;
        std::fs::write(&world.file, document(&changed)).unwrap();
        assert_eq!(world.send(&raw).unwrap(), hash);
        std::fs::write(&world.file, "incomplete").unwrap();
        assert_eq!(world.send(&raw).unwrap(), hash);
    }

    #[tokio::test]
    async fn incomplete_policy_and_expired_deadline_leave_every_spool_file_untouched() {
        let world = World::new();
        let raw = world.approve(1, 1, FLOOR, 100_000_000_000);
        std::fs::write(
            &world.file,
            r#"{"required_tip_wei":100000000,"admission":{"version":1}}"#,
        )
        .unwrap();
        assert!(world
            .send(&raw)
            .unwrap_err()
            .message()
            .contains("incomplete or malformed"));
        world.empty_pool();
        assert!(world
            .spool
            .submit(&world.factory, &raw, Some(&world.file), Instant::now())
            .unwrap_err()
            .message()
            .contains("timed out"));
        world.empty_pool();
    }

    #[tokio::test]
    async fn head_and_policy_drift_invalidate_a_preflight_verdict() {
        let mut world = World::new();
        let snapshot = Snapshot::read(&world.factory).unwrap();
        world
            .coordinator
            .extend_raw(
                world.coordinator.head().hash(),
                BlochNextBlockEnvCtx {
                    timestamp: 19,
                    prevrandao: B256::repeat_byte(3),
                    anchor_root: B256::repeat_byte(4),
                    deposits: vec![],
                },
                &[],
            )
            .unwrap();
        assert!(snapshot
            .verify(&world.factory)
            .unwrap_err()
            .message()
            .contains("head changed"));
        let old = Policy::read(&world.file).unwrap();
        let mut changed = old.clone();
        changed.fresh_slot_price += 1;
        std::fs::write(&world.file, document(&changed)).unwrap();
        assert!(old
            .verify(&world.file)
            .unwrap_err()
            .message()
            .contains("policy changed"));
        world.empty_pool();
    }

    #[tokio::test]
    async fn drift_before_the_admission_lock_cannot_return_a_stale_fee_quote() {
        let mut world = World::new();
        let raw = world.approve(1, 1, FLOOR, 100_000_000_000);
        let spool = world.spool.clone();
        let error = spool
            .submit_checked(
                &world.factory,
                &raw,
                Some(&world.file),
                Instant::now() + Duration::from_secs(5),
                || {
                    world
                        .coordinator
                        .extend_raw(
                            world.coordinator.head().hash(),
                            BlochNextBlockEnvCtx {
                                timestamp: 19,
                                prevrandao: B256::repeat_byte(3),
                                anchor_root: B256::repeat_byte(4),
                                deposits: vec![],
                            },
                            &[],
                        )
                        .unwrap();
                },
                || {},
            )
            .unwrap_err();
        assert!(error.message().contains("head changed"));
        assert!(error.data().is_none());
        world.empty_pool();
    }

    #[tokio::test]
    async fn policy_drift_during_disk_write_preserves_the_previous_spooled_transaction() {
        let world = World::new();
        let old = world
            .send(&world.approve(1, 1, 10_000_000_000, 100_000_000_000))
            .unwrap();
        let entries = || {
            std::fs::read_dir(&world.spool.dir)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), std::fs::read(entry.path()).unwrap())
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let before = entries();
        let raw = world.approve(1, 1, 12_000_000_000, 110_000_000_000);
        let error = world
            .spool
            .submit_checked(
                &world.factory,
                &raw,
                Some(&world.file),
                Instant::now() + Duration::from_secs(5),
                || {},
                || {
                    let mut changed = policy(vec![]);
                    changed.fresh_slot_price *= 2;
                    std::fs::write(&world.file, document(&changed)).unwrap();
                },
            )
            .unwrap_err();
        assert!(error.message().contains("policy changed"));
        assert!(error.data().is_none());
        assert_eq!(entries(), before);
        assert!(world
            .spool
            .dir
            .join(format!("{}.tx", alloy_primitives::hex::encode(old)))
            .exists());
    }

    #[tokio::test]
    async fn deadline_expiry_after_writing_partial_preserves_the_previous_entry() {
        let world = World::new();
        world
            .send(&world.approve(1, 1, 10_000_000_000, 100_000_000_000))
            .unwrap();
        let files = || {
            std::fs::read_dir(&world.spool.dir)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), std::fs::read(entry.path()).unwrap())
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let before = files();
        let reached_disk_boundary = std::cell::Cell::new(false);
        let deadline = Instant::now() + Duration::from_secs(5);
        let error = world
            .spool
            .submit_checked(
                &world.factory,
                &world.approve(1, 1, 12_000_000_000, 110_000_000_000),
                Some(&world.file),
                deadline,
                || {},
                || {
                    reached_disk_boundary.set(true);
                    std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
                },
            )
            .unwrap_err();
        assert!(
            reached_disk_boundary.get(),
            "the test must exercise the final publication boundary"
        );
        assert!(error.message().contains("timed out"));
        assert_eq!(
            files(),
            before,
            "no late transaction, partial, sidecar change or eviction"
        );
    }

    #[tokio::test]
    async fn cold_spool_preview_does_not_create_sidecars_on_a_refusal() {
        let world = World::new();
        let old = world.approve(1, 1, 10_000_000_000, 100_000_000_000);
        let hash = bloch_l2_evm::decode_signed_transaction(&world.spool.spec, &old)
            .unwrap()
            .hash();
        let name = format!("{}.tx", alloy_primitives::hex::encode(hash));
        std::fs::write(world.spool.dir.join(&name), alloy_primitives::hex::encode(&old)).unwrap();
        // A legacy spool entry has no first-seen sidecar and an empty in-memory
        // index after restart. Refusing a replacement may inspect but not adopt it.
        let error = world.send(&world.approve(1, 2, FLOOR, 100_000_000_000)).unwrap_err();
        assert!(error.message().contains("replacement transaction underpriced"));
        assert!(world.spool.lock().is_empty());
        assert_eq!(std::fs::read_dir(&world.spool.dir).unwrap().count(), 1);
        assert_eq!(
            std::fs::read_to_string(world.spool.dir.join(name)).unwrap(),
            alloy_primitives::hex::encode(old)
        );
    }

    #[tokio::test]
    async fn head_drift_after_writing_partial_never_publishes_a_new_transaction() {
        let mut world = World::new();
        let spool = world.spool.clone();
        let error = spool
            .submit_checked(
                &world.factory,
                &world.approve(1, 1, 10_000_000_000, 100_000_000_000),
                Some(&world.file),
                Instant::now() + Duration::from_secs(5),
                || {},
                || {
                    world
                        .coordinator
                        .extend_raw(
                            world.coordinator.head().hash(),
                            BlochNextBlockEnvCtx {
                                timestamp: 19,
                                prevrandao: B256::repeat_byte(3),
                                anchor_root: B256::repeat_byte(4),
                                deposits: vec![],
                            },
                            &[],
                        )
                        .unwrap();
                },
            )
            .unwrap_err();
        assert!(error.message().contains("head changed"));
        world.empty_pool();
    }

    #[tokio::test]
    async fn submission_shares_the_simulation_gate_and_overload_does_not_write() {
        let world = World::new();
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = gate.clone().acquire_owned().await.unwrap();
        let module = super::super::sequencer_rpc(
            world.spool.clone(),
            world.factory.clone(),
            Some(world.file.clone()),
            gate,
            Duration::from_millis(10),
            Duration::from_secs(5),
        );
        let error = module
            .call::<_, B256>("eth_sendRawTransaction", (world.approve(1, 1, FLOOR, 100_000_000_000),))
            .await
            .unwrap_err();
        match error {
            jsonrpsee::core::server::MethodsError::JsonRpc(error) => assert_eq!(error.code(), -32005),
            other => panic!("unexpected error: {other}"),
        }
        world.empty_pool();
        drop(permit);
    }

    fn approve_request(value: u64, gas: Option<u64>) -> QuoteRequest {
        let mut input = vec![0x09, 0x5e, 0xa7, 0xb3];
        input.extend(Address::repeat_byte(0x22).into_word());
        input.extend(U256::from(value).to_be_bytes::<32>());
        QuoteRequest {
            from: sender(),
            to: Some(sender().create(0)),
            data: Some(input.into()),
            input: None,
            value: None,
            gas: gas.map(alloy_primitives::U64::from),
        }
    }

    /// Round 15 (DEX request): the quote for an unsigned call is, field by field, what a refused send of
    /// the same call reports, and a transaction that pays exactly the quote is admitted.
    #[tokio::test]
    async fn admission_quote_equals_the_refusal_of_the_same_call_and_is_enough() {
        let world = World::new();
        let policy = policy(vec![]);
        let snapshot = Snapshot::read(&world.factory).unwrap();
        let quote = snapshot.quote(&approve_request(7, Some(200_000)), &policy).unwrap();
        assert_eq!(quote["kind"], "sequencer-admission-quote");
        assert_eq!(quantity(&quote["freshSlots"]), 1);
        assert_eq!(quantity(&quote["chargedFreshSlots"]), 1);
        assert_eq!(quantity(&quote["minimumPriorityFeePerGas"]), FLOOR);
        let required = quantity(&quote["requiredPriorityFeePerGas"]);
        assert!(required > FLOOR, "a new slot costs more than the floor here");
        assert_eq!(quantity(&quote["writePriceOwedWei"]), PRICE);
        assert_eq!(required, PRICE.div_ceil(quantity(&quote["gasUsed"])));
        // The same call, signed at the floor tip, is refused with the same numbers.
        let cap = 100_000_000_000;
        let refused = world.send(&world.approve(1, 7, FLOOR, cap)).unwrap_err();
        let refusal = data(&refused);
        for field in [
            "headHash",
            "headNumber",
            "baseFeePerGas",
            "requiredPriorityFeePerGas",
            "requiredMaxFeePerGas",
            "gasUsed",
            "freshSlots",
            "chargedFreshSlots",
            "freshSlotPriceWei",
            "scope",
        ] {
            assert_eq!(quote[field], refusal[field], "{field}");
        }
        // One wei below the quote is refused; the quote itself is admitted.
        assert!(world.send(&world.approve(1, 7, required - 1, cap)).is_err());
        world.send(&world.approve(1, 7, required, cap)).unwrap();
        // F312-5: the spooled file is readable by the spool directory's group (the producer's way in).
        use std::os::unix::fs::PermissionsExt;
        let spooled: Vec<_> = std::fs::read_dir(&world.spool.dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|e| e == "tx"))
            .collect();
        assert_eq!(spooled.len(), 1);
        assert_eq!(
            std::fs::metadata(&spooled[0]).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[tokio::test]
    async fn admission_quote_charges_nothing_for_no_new_slot_or_an_exempt_sender_and_writes_nothing() {
        let world = World::new();
        let snapshot = Snapshot::read(&world.factory).unwrap();
        // approve(…, 0) leaves the allowance slot zero: no new slot, the floor alone.
        let none = snapshot.quote(&approve_request(0, None), &policy(vec![])).unwrap();
        assert_eq!(quantity(&none["freshSlots"]), 0);
        assert_eq!(quantity(&none["requiredPriorityFeePerGas"]), FLOOR);
        let exempt = snapshot
            .quote(&approve_request(7, None), &policy(vec![sender()]))
            .unwrap();
        assert_eq!(quantity(&exempt["freshSlots"]), 1);
        assert_eq!(quantity(&exempt["chargedFreshSlots"]), 0);
        assert_eq!(quantity(&exempt["requiredPriorityFeePerGas"]), FLOOR);
        // Read-only: nothing spooled, the head and the sender's nonce are where they were.
        assert_eq!(std::fs::read_dir(&world.spool.dir).unwrap().count(), 0);
        snapshot.verify(&world.factory).unwrap();
        assert_eq!(quantity(&exempt["nonce"]), 1);
    }

    #[tokio::test]
    async fn admission_quote_refuses_what_cannot_execute() {
        let world = World::new();
        let snapshot = Snapshot::read(&world.factory).unwrap();
        // An account without funds gets no quote (and no free simulation).
        let mut poor = approve_request(7, None);
        poor.from = Address::repeat_byte(0x99);
        let error = snapshot.quote(&poor, &policy(vec![])).unwrap_err();
        assert!(error.message().contains("below gas limit"), "{}", error.message());
        // Too little gas: the call cannot execute, so there is nothing to price.
        let error = snapshot
            .quote(&approve_request(7, Some(21_000)), &policy(vec![]))
            .unwrap_err();
        assert!(error.message().contains("cannot execute"), "{}", error.message());
        // `data` and `input` that disagree are refused, as wallets expect.
        let mut both = approve_request(7, None);
        both.input = Some(Bytes::from_static(&[1]));
        assert!(snapshot.quote(&both, &policy(vec![])).is_err());
        // Unknown fields (state overrides, block tags) are not silently ignored.
        assert!(serde_json::from_str::<QuoteRequest>(
            r#"{"from":"0x0000000000000000000000000000000000000001","stateOverride":{}}"#
        )
        .is_err());
    }

    #[test]
    fn strict_policy_schema_and_integer_rounding() {
        assert_eq!(
            Policy::parse(&document(&policy(vec![sender()]))),
            Some(policy(vec![sender()]))
        );
        for text in [
            "{}",
            "null",
            r#"{"admission":{"version":2}}"#,
            r#"{"admission":{"version":3,"required_tip_wei":"0","fresh_slot_price_wei":"0","write_limit_exempt_senders":[]}}"#,
            r#"{"admission":{"version":1,"required_tip_wei":"0","fresh_slot_price_wei":0,"write_limit_exempt_senders":[]}}"#,
        ] {
            assert!(Policy::parse(text).is_none());
        }
        let header = SealedHeader::new(BlochNodeHeader::default(), B256::repeat_byte(1));
        let stats = TxStats {
            hash: B256::repeat_byte(2),
            sender: sender(),
            nonce: 0,
            gas_used: 3,
            effective_tip: 3,
            fresh_slots: vec![(sender(), 1)],
            cleared_slots: vec![],
        };
        let p = Policy {
            required_tip: 0,
            fresh_slot_price: 10,
            exempt: vec![],
            rules: None,
        };
        assert_eq!(
            quantity(&data(&p.check(&stats, &header, 1).unwrap_err())["requiredPriorityFeePerGas"]),
            4
        );
        assert!(p
            .check(
                &TxStats {
                    effective_tip: 4,
                    ..stats.clone()
                },
                &header,
                1
            )
            .is_ok());
        let exact = Policy {
            fresh_slot_price: 9,
            ..p
        };
        assert!(exact.check(&stats, &header, 1).is_ok());
    }

    const FEE_CAP: u128 = 20_000_000_000;
    fn kind_of(result: Result<B256, ErrorObjectOwned>) -> serde_json::Value {
        data(&result.unwrap_err())
    }

    /// Review R308-5P-4: nothing above the policy's gas cap is executed, so nothing above it is admitted,
    /// whatever credit or tip it has. Exempt senders are not bound by it.
    #[tokio::test]
    async fn a_gas_limit_above_the_cap_is_refused_whatever_the_credit_or_tip() {
        let world = World::new();
        world.publish(&ruled(vec![], Some(u128::MAX)));
        for tip in [FLOOR, FLOOR * 50] {
            let error = world
                .send(&world.approve_with_gas(1, 0, tip, MAX_TX_GAS + 1))
                .unwrap_err();
            assert!(
                error.message().contains("a higher tip does not help"),
                "{}",
                error.message()
            );
            let refusal = data(&error);
            assert_eq!(refusal["kind"], "sequencer-gas-limit-above-cap");
            assert_eq!(refusal["gas_limit"], MAX_TX_GAS + 1);
            assert_eq!(refusal["max_tx_gas"], MAX_TX_GAS);
            assert_eq!(refusal["uncovered_max_gas"], UNCOVERED_MAX_GAS);
            assert_eq!(refusal["credit_wei"], u128::MAX.to_string());
            assert_eq!(
                refusal["credit_needed_wei"],
                (u128::from(MAX_TX_GAS + 1) * tip).to_string()
            );
            assert_eq!(quantity(&refusal["effectivePriorityFeePerGas"]), tip);
        }
        world.empty_pool();
        // Exactly at the cap, covered: admitted.
        world.send(&world.approve_with_gas(1, 0, FLOOR, MAX_TX_GAS)).unwrap();
        let exempt = World::new();
        exempt.publish(&ruled(vec![sender()], None));
        exempt
            .send(&exempt.approve_with_gas(1, 0, FLOOR, MAX_TX_GAS + 1))
            .unwrap();
    }

    /// A sender whose credit does not cover `gas limit x tip` is executed only up to the uncovered limit.
    #[tokio::test]
    async fn an_uncovered_sender_above_the_uncovered_limit_needs_credit_and_a_covered_one_passes() {
        let world = World::new();
        let gas = UNCOVERED_MAX_GAS + 1;
        let needed = u128::from(gas) * FLOOR;
        for (credit, published) in [(None, 0), (Some(needed - 1), needed - 1)] {
            world.publish(&ruled(vec![], credit));
            let error = world.send(&world.approve_with_gas(1, 0, FLOOR, gas)).unwrap_err();
            assert!(
                error.message().contains("a higher tip does not help"),
                "{}",
                error.message()
            );
            assert!(error.message().contains("plain transfer"), "{}", error.message());
            let refusal = data(&error);
            assert_eq!(refusal["kind"], "sequencer-needs-credit");
            assert_eq!(refusal["gas_limit"], gas);
            assert_eq!(refusal["uncovered_max_gas"], UNCOVERED_MAX_GAS);
            assert_eq!(refusal["max_tx_gas"], MAX_TX_GAS);
            assert_eq!(refusal["credit_wei"], published.to_string());
            assert_eq!(refusal["credit_needed_wei"], needed.to_string());
        }
        // A higher tip needs more credit; a future nonce (never simulated) is refused the same way; and a
        // fee that is also too low for a new slot does not hide this refusal: it comes before any execution.
        for raw in [
            world.approve_with_gas(1, 0, FLOOR * 2, gas),
            world.approve_with_gas(5, 0, FLOOR, gas),
            world.approve_with_gas(1, 7, FLOOR, gas),
        ] {
            assert_eq!(kind_of(world.send(&raw))["kind"], "sequencer-needs-credit");
        }
        world.empty_pool();
        // Exempt: covered whatever its credit.
        world.publish(&ruled(vec![sender()], None));
        world.send(&world.approve_with_gas(1, 0, FLOOR, gas)).unwrap();
        // Exactly at the uncovered limit without credit, and above it with exactly the credit needed.
        let small = World::new();
        small.publish(&ruled(vec![], None));
        small
            .send(&small.approve_with_gas(1, 0, FLOOR, UNCOVERED_MAX_GAS))
            .unwrap();
        let covered = World::new();
        covered.publish(&ruled(vec![], Some(needed)));
        covered.send(&covered.approve_with_gas(1, 0, FLOOR, gas)).unwrap();
    }

    /// A plain transfer (21,000 gas, no data) is never refused by these rules, even under limits below it;
    /// one more unit of gas, or one byte of data, makes it an ordinary transaction.
    #[tokio::test]
    async fn a_plain_transfer_always_passes_the_execution_rules() {
        let world = World::new();
        let mut tight = ruled(vec![], None);
        tight.rules.as_mut().unwrap().max_tx_gas = 20_000;
        tight.rules.as_mut().unwrap().uncovered_max_gas = 10_000;
        world.publish(&tight);
        let to = TxKind::Call(Address::repeat_byte(0x33));
        let transfer = |nonce, input: &'static [u8], gas| {
            signed_with_gas(
                &world.spool.spec,
                nonce,
                to,
                Bytes::from_static(input),
                FLOOR,
                FEE_CAP,
                gas,
            )
        };
        assert_eq!(
            kind_of(world.send(&transfer(1, &[], 21_001)))["kind"],
            "sequencer-gas-limit-above-cap"
        );
        // With data, 21,000 gas is below the intrinsic gas and never reaches these rules; the rule itself:
        assert_eq!(
            tight.executability(sender(), 21_000, false, U256::from(FLOOR)).refusal,
            Some("gas-limit-above-cap")
        );
        assert_eq!(
            tight.executability(sender(), 21_000, true, U256::from(FLOOR)).refusal,
            None
        );
        tight.rules.as_mut().unwrap().max_tx_gas = MAX_TX_GAS;
        world.publish(&tight);
        assert_eq!(
            kind_of(world.send(&transfer(1, &[], 21_001)))["kind"],
            "sequencer-needs-credit"
        );
        world.empty_pool();
        world.send(&transfer(1, &[], 21_000)).unwrap();
    }

    /// A version 1 policy file has no execution rules: admission and the quote are what they were.
    #[tokio::test]
    async fn a_version_1_policy_applies_no_execution_rule() {
        let world = World::new();
        assert!(document(&policy(vec![])).contains(r#""version":1"#));
        let snapshot = Snapshot::read(&world.factory).unwrap();
        let quote = snapshot
            .quote(
                &approve_request(0, Some(MAX_TX_GAS + 1)),
                &Policy::read(&world.file).unwrap(),
            )
            .unwrap();
        assert_eq!(quote["executable"], true);
        assert_eq!(quote["covered"], true);
        assert_eq!(quote["gas_limit"], MAX_TX_GAS + 1);
        for field in [
            "not_executable_reason",
            "credit_wei",
            "credit_needed_wei",
            "first_transfer_priority_fee_wei",
            "uncovered_max_gas",
            "max_tx_gas",
        ] {
            assert!(quote[field].is_null(), "{field}");
        }
        assert_eq!(quantity(&quote["requiredPriorityFeePerGas"]), FLOOR);
        world
            .send(&world.approve_with_gas(1, 0, FLOOR, MAX_TX_GAS + 1))
            .unwrap();
    }

    /// The quote's verdict is admission's: a call quoted executable, signed with the quoted gas limit and
    /// fee, is admitted; one quoted not executable is refused with the matching kind and the same figures.
    #[tokio::test]
    async fn admission_quote_and_admission_agree_on_the_execution_rules() {
        let credit = u128::from(UNCOVERED_MAX_GAS + 1) * FLOOR;
        // (credit, exempt, gas limit, new-slot value) -> (reason, covered)
        type Case<'a> = (Option<u128>, bool, u64, u64, Option<&'a str>, bool);
        let cases: [Case; 8] = [
            (None, false, 200_000, 7, None, false),
            (None, false, UNCOVERED_MAX_GAS, 0, None, false),
            (None, false, UNCOVERED_MAX_GAS + 1, 0, Some("needs-credit"), false),
            (
                Some(credit - 1),
                false,
                UNCOVERED_MAX_GAS + 1,
                0,
                Some("needs-credit"),
                false,
            ),
            (Some(credit), false, UNCOVERED_MAX_GAS + 1, 0, None, true),
            (Some(u128::MAX), false, MAX_TX_GAS, 0, None, true),
            (
                Some(u128::MAX),
                false,
                MAX_TX_GAS + 1,
                0,
                Some("gas-limit-above-cap"),
                true,
            ),
            (None, true, MAX_TX_GAS + 1, 7, None, true),
        ];
        for (credit, exempt, gas, value, reason, covered) in cases {
            let case = format!("credit {credit:?}, exempt {exempt}, gas {gas}, value {value}");
            let world = World::new();
            let policy = ruled(if exempt { vec![sender()] } else { vec![] }, credit);
            world.publish(&policy);
            let snapshot = Snapshot::read(&world.factory).unwrap();
            let quote = snapshot.quote(&approve_request(value, Some(gas)), &policy).unwrap();
            assert_eq!(quote["executable"], reason.is_none(), "{case}");
            assert_eq!(quote["not_executable_reason"], serde_json::json!(reason), "{case}");
            assert_eq!(quote["covered"], covered, "{case}");
            assert_eq!(quote["gas_limit"], gas, "{case}");
            assert_eq!(quote["max_tx_gas"], MAX_TX_GAS, "{case}");
            assert_eq!(quote["uncovered_max_gas"], UNCOVERED_MAX_GAS, "{case}");
            assert_eq!(quote["credit_wei"], credit.unwrap_or(0).to_string(), "{case}");
            let tip = quantity(&quote["requiredPriorityFeePerGas"]);
            assert_eq!(
                quote["credit_needed_wei"],
                (u128::from(gas) * tip).to_string(),
                "{case}"
            );
            let sent = world.send(&world.approve_with_gas(1, value, tip, gas));
            match reason {
                None => {
                    sent.unwrap_or_else(|error| panic!("{case}: {error}"));
                }
                Some(reason) => {
                    let refusal = kind_of(sent);
                    assert_eq!(refusal["kind"], format!("sequencer-{reason}"), "{case}");
                    for field in [
                        "headHash",
                        "headNumber",
                        "baseFeePerGas",
                        "gas_limit",
                        "max_tx_gas",
                        "uncovered_max_gas",
                        "credit_wei",
                        "credit_needed_wei",
                        "first_transfer_priority_fee_wei",
                        "scope",
                    ] {
                        assert_eq!(quote[field], refusal[field], "{case}: {field}");
                    }
                    world.empty_pool();
                }
            }
        }
        // Without `gas` the call is run and judged at the largest limit the producer executes for the sender.
        let world = World::new();
        let snapshot = Snapshot::read(&world.factory).unwrap();
        let unasked = snapshot.quote(&approve_request(0, None), &ruled(vec![], None)).unwrap();
        assert_eq!(unasked["gas_limit"], MAX_TX_GAS);
        assert_eq!(unasked["not_executable_reason"], "needs-credit");
        let exempt = snapshot
            .quote(&approve_request(0, None), &ruled(vec![sender()], None))
            .unwrap();
        assert_eq!(exempt["gas_limit"], SIMULATION_GAS_CAP);
        assert_eq!(exempt["executable"], true);
    }

    #[test]
    fn strict_version_2_schema() {
        let good = ruled(vec![sender()], Some(u128::MAX));
        assert_eq!(Policy::parse(&document(&good)), Some(good.clone()));
        let empty = ruled(vec![], None);
        assert_eq!(Policy::parse(&document(&empty)), Some(empty));
        // A version 1 file is read without rules even if it carries the version 2 fields.
        let mut legacy: serde_json::Value = serde_json::from_str(&document(&good)).unwrap();
        legacy["admission"]["version"] = 1.into();
        assert_eq!(Policy::parse(&legacy.to_string()), Some(policy(vec![sender()])));
        let address = format!("{:#x}", sender());
        let broken = |edit: &dyn Fn(&mut serde_json::Map<String, serde_json::Value>)| {
            let mut value: serde_json::Value = serde_json::from_str(&document(&good)).unwrap();
            edit(value["admission"].as_object_mut().unwrap());
            Policy::parse(&value.to_string())
        };
        for field in ["max_tx_gas", "uncovered_max_gas", "credit"] {
            assert!(broken(&|a| drop(a.remove(field))).is_none(), "missing {field}");
        }
        let bad_values: [(&str, serde_json::Value); 12] = [
            ("max_tx_gas", "5000000".into()),
            ("max_tx_gas", (-1).into()),
            ("max_tx_gas", 5000000.5.into()),
            ("uncovered_max_gas", serde_json::Value::Null),
            ("uncovered_max_gas", "0x16e360".into()),
            ("credit", serde_json::json!([])),
            ("credit", serde_json::json!({ (address.clone()): 5 })),
            ("credit", serde_json::json!({ (address.clone()): "0x5" })),
            ("credit", serde_json::json!({ (address.clone()): "" })),
            ("credit", serde_json::json!({ (address.clone()): "-1" })),
            (
                "credit",
                serde_json::json!({ (address.clone()): "340282366920938463463374607431768211456" }),
            ),
            (
                "credit",
                serde_json::json!({ (address.to_uppercase().replace("0X", "0x")): "5" }),
            ),
        ];
        for (field, value) in bad_values {
            assert!(
                broken(&|a| drop(a.insert(field.into(), value.clone()))).is_none(),
                "{field} = {value}"
            );
        }
        for key in [address[2..].to_string(), format!("{address}00"), "0x12".into()] {
            assert!(
                broken(&|a| drop(a.insert("credit".into(), serde_json::json!({ (key.clone()): "5" })))).is_none(),
                "credit key {key}"
            );
        }
    }

    /// The tip the rules use is the one the producer's selection computes: the declared priority fee, capped
    /// by the fee cap less the next base fee; a legacy gas price counts in full above the base fee.
    #[test]
    fn execution_rules_use_the_effective_tip_and_at_least_one_wei() {
        let rules = ruled(vec![], Some(2_000_000));
        let verdict = |gas, no_data, tip: u64| rules.executability(sender(), gas, no_data, U256::from(tip));
        // Tip zero is counted as one wei: any credit of at least the gas limit covers it.
        assert_eq!(verdict(2_000_000, false, 0).credit_needed, U256::from(2_000_000));
        assert!(verdict(2_000_000, false, 0).covered);
        assert_eq!(verdict(2_000_001, false, 0).refusal, Some("needs-credit"));
        assert_eq!(verdict(2_000_000, false, 2).refusal, Some("needs-credit"));
        assert_eq!(verdict(UNCOVERED_MAX_GAS, false, 2).refusal, None);
        assert!(!verdict(UNCOVERED_MAX_GAS, false, 2).covered);
        assert_eq!(verdict(21_000, true, u64::MAX).refusal, None);
        let spec = ChainSpec::testnet();
        let tip_of = |tip, cap, base_fee| {
            let raw = signed(&spec, 0, TxKind::Call(Address::ZERO), Bytes::new(), tip, cap);
            let tx = bloch_l2_evm::decode_signed_transaction(&spec, &raw).unwrap();
            effective_tip(tx.environment().gas_price, tx.environment().gas_priority_fee, base_fee)
        };
        assert_eq!(tip_of(5, 100, 10), 5);
        assert_eq!(tip_of(50, 100, 60), 40);
        assert_eq!(tip_of(50, 100, 200), 0);
        assert_eq!(effective_tip(100, None, 60), 40);
    }

    /// Opt-in cross-product rehearsal, always a fresh local chain and test key.
    /// The output file tells external clients where the loopback RPC listens.
    #[tokio::test]
    #[ignore = "explicit local DEX/bridge rehearsal; serves a disposable RPC for a bounded interval"]
    async fn serve_disposable_admission_rehearsal() {
        use reth_network_api::noop::NoopNetwork;
        use reth_rpc_eth_api::{node::RpcNodeCoreAdapter, EthApiServer};
        use reth_transaction_pool::noop::NoopTransactionPool;
        let output = PathBuf::from(
            std::env::var("BLOCH_ADMISSION_REHEARSAL_FILE")
                .expect("set BLOCH_ADMISSION_REHEARSAL_FILE to a new local fixture output path"),
        );
        assert!(!output.exists(), "refusing to overwrite a rehearsal output");
        let seconds = std::env::var("BLOCH_ADMISSION_REHEARSAL_SECONDS")
            .ok()
            .map(|value| value.parse::<u64>().unwrap())
            .unwrap_or(300);
        assert!((1..=1800).contains(&seconds));
        let world = World::new();
        let chain = world.factory.chain_spec();
        let api = super::super::build_eth_api_capped(
            RpcNodeCoreAdapter::new(
                world.coordinator.provider(),
                NoopTransactionPool::default(),
                NoopNetwork::default().with_chain_id(world.spool.spec.chain_id),
                bloch_reth_execution::BlochEvmConfig::for_chain(&chain),
            ),
            reth_tasks::Runtime::test(),
            bloch_reth_execution::PendingPolicy::LatestDerived,
            SIMULATION_GAS_CAP,
        );
        let mut module = api.into_rpc().remove_context();
        assert!(module.remove_method("eth_sendRawTransaction").is_some());
        let gate = Arc::new(tokio::sync::Semaphore::new(super::super::MAX_CONCURRENT_SIMULATIONS));
        module
            .merge(super::super::sequencer_rpc(
                world.spool.clone(),
                world.factory.clone(),
                Some(world.file.clone()),
                gate.clone(),
                super::super::SIMULATION_WAIT,
                super::super::SIMULATION_TIME_LIMIT,
            ))
            .unwrap();
        super::super::spool_pending_nonce(&mut module, world.spool.clone(), world.factory.clone()).unwrap();
        super::super::limit_simulations_with_gate(
            &mut module,
            gate,
            super::super::SIMULATION_WAIT,
            super::super::SIMULATION_TIME_LIMIT,
        )
        .unwrap();
        let server = bloch_reth_execution::start_http_rpc(module, 0).await.unwrap();
        let raw = world.approve(1, 1, FLOOR * 125 / 100, 100_000_000_000);
        let fixture = serde_json::json!({
            "schema": "bloch-admission-rehearsal-v1", "rpc": server.http_url(),
            "chain_id": world.spool.spec.chain_id, "sender": sender(), "nonce": 1,
            "test_private_key": format!("0x{}", "07".repeat(32)),
            "token": sender().create(0), "underpriced_approve_raw": raw,
            "underpriced_approve_hash": bloch_l2_evm::decode_signed_transaction(&world.spool.spec, &raw).unwrap().hash(),
            "policy": world.file, "spool": world.spool.dir, "lifetime_seconds": seconds,
        });
        std::fs::write(&output, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
        println!("disposable admission rehearsal ready: {}", output.display());
        tokio::time::sleep(Duration::from_secs(seconds)).await;
        server.stop().unwrap();
    }
}
