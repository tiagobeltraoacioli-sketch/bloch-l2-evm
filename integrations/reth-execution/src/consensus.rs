// SPDX-License-Identifier: MIT OR Apache-2.0
//! V2 header/body/receipt validation using genuine Reth consensus interfaces.
//! Post-execution trait inputs contain no computed state root. Callers must
//! separately compare the actual execution root and authenticate L1 inputs.
use crate::{BlochChainSpec, BlochNodeBlock, BlochNodeBody, BlochNodeHeader, BlochNodePrimitives};
use alloy_consensus::ReceiptEnvelope;
use alloy_primitives::B256;
use reth_chainspec::EthChainSpec;
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator, ReceiptRootBloom, TransactionRoot};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use std::sync::Arc;

/// Validator bound to the immutable configured V2 genesis/domain.
/// These checks do not select fork choice or establish L1 deposit provenance.
#[derive(Clone, Debug)]
pub struct BlochConsensus {
    spec: Arc<BlochChainSpec>,
}
impl BlochConsensus {
    /// Bind validation to the same specification used by execution and storage.
    pub fn new(spec: Arc<BlochChainSpec>) -> Self {
        Self { spec }
    }
}
impl HeaderValidator<BlochNodeHeader> for BlochConsensus {
    fn validate_header(&self, header: &SealedHeader<BlochNodeHeader>) -> Result<(), ConsensusError> {
        header
            .0
            .validate_configuration(self.spec.execution(), self.spec.domain())
            .map_err(ConsensusError::other)?;
        if header.hash() != header.0.hash() {
            return Err(ConsensusError::msg(
                "V2 cached header seal disagrees with canonical hash",
            ));
        }
        if header.0.number == 0 && &**header != self.spec.genesis_header() {
            return Err(ConsensusError::msg("V2 genesis differs from configured genesis"));
        }
        Ok(())
    }
    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<BlochNodeHeader>,
        parent: &SealedHeader<BlochNodeHeader>,
    ) -> Result<(), ConsensusError> {
        self.validate_header(header)?;
        self.validate_header(parent)?;
        // The rules of the child block (F387-1): under the next rules its base fee has the floor.
        header
            .0
            .validate_parent(self.spec.execution_at(header.0.number), &parent.0)
            .map_err(ConsensusError::other)
    }
}
impl Consensus<BlochNodeBlock> for BlochConsensus {
    fn validate_body_against_header(
        &self,
        body: &BlochNodeBody,
        header: &SealedHeader<BlochNodeHeader>,
    ) -> Result<(), ConsensusError> {
        self.validate_header(header)?;
        let body = body.as_core();
        body.validate(self.spec.execution()).map_err(ConsensusError::other)?;
        if body.transactions_root() != header.0.transactions_root || body.deposits_hash() != header.0.deposits_hash {
            return Err(ConsensusError::msg("V2 body commitments disagree with header"));
        }
        let deposit_gas = self
            .spec
            .execution()
            .deposit_gas
            .checked_mul(body.deposits.len() as u64);
        if deposit_gas != header.0.gas_used.checked_sub(header.0.user_gas_used) {
            return Err(ConsensusError::msg("V2 deposit gas disagrees with body"));
        }
        Ok(())
    }
    fn validate_block_pre_execution(&self, block: &SealedBlock<BlochNodeBlock>) -> Result<(), ConsensusError> {
        self.validate_body_against_header(block.body(), block.sealed_header())
    }
    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<BlochNodeBlock>,
        root: Option<TransactionRoot>,
    ) -> Result<(), ConsensusError> {
        self.validate_block_pre_execution(block)?;
        if root.is_some_and(|root| root != block.body().as_core().transactions_root()) {
            return Err(ConsensusError::msg("V2 cached transaction root disagrees with body"));
        }
        Ok(())
    }
}
impl FullConsensus<BlochNodePrimitives> for BlochConsensus {
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<BlochNodeBlock>,
        result: &BlockExecutionResult<crate::BlochRethReceipt>,
        receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        self.validate_block_pre_execution(block.sealed_block())?;
        if !result.requests.is_empty() || result.blob_gas_used != 0 || block_access_list_hash.is_some() {
            return Err(ConsensusError::msg("unsupported V2 execution extensions"));
        }
        if result.gas_used != block.header().0.gas_used {
            return Err(ConsensusError::msg("V2 executed total gas differs from header"));
        }
        if result.receipts.len() != block.body().as_core().transactions.len() {
            return Err(ConsensusError::msg("V2 receipt count differs from signed body"));
        }
        let receipts: Vec<ReceiptEnvelope> = result.receipts.iter().cloned().map(Into::into).collect();
        block
            .header()
            .0
            .validate_commitments(
                self.spec.execution(),
                self.spec.domain(),
                block.body().as_core(),
                &receipts,
            )
            .map_err(ConsensusError::other)?;
        if let Some((root, bloom)) = receipt_root_bloom {
            // validate_commitments just recomputed both from the actual receipts.
            if root != block.header().0.receipts_root || bloom != block.header().0.logs_bloom {
                return Err(ConsensusError::msg(
                    "V2 cached receipt commitments disagree with execution",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod next_rules_parent_tests {
    use super::*;
    use bloch_l2_evm::ChainSpec;

    /// F387-1, second half (agent 387's re-test of f694f88, agent 382 fix): once the
    /// producer builds the header with the next rules' floored base fee (block 575),
    /// every validator of the parent link must use the same rules. Agent 387's
    /// block 576 was refused with "V2 parent linkage or context mismatch" because
    /// `validate_header_against_parent` still judged the base fee on the BASE rules.
    /// Sequence: parent 574 (base fee 100,218,107, empty) -> 575 at the floor
    /// (100,000,000, empty) -> 576 at the floor again.
    #[test]
    fn f387_1_the_parent_link_is_judged_on_the_rules_of_the_child() {
        let base = ChainSpec::mainnet_v1();
        let next = ChainSpec::mainnet_next_or_rehearsal();
        let floor = next.min_base_fee;
        let rules = crate::RuleSchedule::new(base.clone(), next.clone()).unwrap();
        let chain = Arc::new(BlochChainSpec::scheduled(rules.clone(), B256::repeat_byte(0x70), 1_786_656_679).unwrap());
        rules.switch_at(1).unwrap();
        let consensus = BlochConsensus::new(chain.clone());
        let child_of = |parent: &BlochNodeHeader| {
            let mut h = parent.clone();
            h.0.number = parent.0.number + 1;
            h.0.parent_hash = parent.0.hash();
            h.0.parent_state_root = parent.0.state_root;
            h.0.base_fee_per_gas = chain.execution_at(h.0.number).next_base_fee(parent.0.base_fee_per_gas, parent.0.gas_used);
            h.0.gas_used = 0;
            h
        };
        let mut b574 = chain.genesis_header().clone();
        b574.0.number = 574;
        b574.0.base_fee_per_gas = 100_218_107;
        b574.0.gas_used = 0;
        let b575 = child_of(&b574);
        let b576 = child_of(&b575);
        assert_eq!((b575.0.base_fee_per_gas, b576.0.base_fee_per_gas), (floor, floor));
        assert!(base.next_base_fee(floor, 0) < floor, "the base rules would step under the floor");
        let seal = |h: &BlochNodeHeader| SealedHeader::seal_slow(h.clone());
        consensus
            .validate_header_against_parent(&seal(&b575), &seal(&b574))
            .expect("575 at the floor follows 574");
        consensus
            .validate_header_against_parent(&seal(&b576), &seal(&b575))
            .expect("576 at the floor follows 575 (387's refused block)");
        // A header that took the base rules' unfloored step is refused under the next rules.
        let mut stepped = b576.clone();
        stepped.0.base_fee_per_gas = base.next_base_fee(floor, 0);
        assert!(consensus.validate_header_against_parent(&seal(&stepped), &seal(&b575)).is_err());
    }
}
