// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-memory coordination of externally trusted source selection and SP1 execution.
//! This does not persist a combined cursor or activate native consensus rules.
use crate::{
    invalid,
    settlement::{SettlementCursor, SettlementMark},
    verification::{ProgramIdentity, QualifiedGroth16SettlementV2, VerifiedExecutionStatement},
    Result,
};
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::{
    escrow_inbox::InboxProof,
    l1::height::HeightPosition,
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    proof_statement::{configuration_commitment, SettlementContextV2, SettlementStatementV2},
    ChainSpec,
};
use bloch_native_domain_devnet::{proof_digest, SettlementPayloadV2, SourceBatch, SourceRegistry, ValidatedV2Prefix};

/// Published only after both execution and mandatory-prefix checks succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSettlementMark {
    pub execution: SettlementMark,
    pub next_sequence: u64,
    pub source_commitment: B256,
}

/// Result of one fully checked local V2 transition. The payload remains inert:
/// this type does not activate a native transaction or finality rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSettlementV2Mark {
    execution: SettlementMark,
    next_sequence: u64,
    source_commitment: B256,
    settlement_commitment: B256,
    payload: SettlementPayloadV2,
}

impl SourceSettlementV2Mark {
    pub fn execution(&self) -> SettlementMark {
        self.execution
    }
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub fn source_commitment(&self) -> B256 {
        self.source_commitment
    }
    pub fn settlement_commitment(&self) -> B256 {
        self.settlement_commitment
    }
    pub fn payload(&self) -> SettlementPayloadV2 {
        self.payload
    }
}

/// Owns source history and consumed position; callers cannot replace either.
pub struct SourceSettlement {
    source: SourceRegistry,
    execution: SettlementCursor,
    spec: ChainSpec,
    next_sequence: u64,
    last_payload: Option<SettlementPayloadV2>,
}

/// Data extracted from the unforgeable verifier capability before beginning a
/// state transition. Keeping this private prevents callers from bypassing SP1
/// verification while letting the mutation logic remain independently testable.
pub(crate) struct CheckedGroth16SettlementV2 {
    statement: SettlementStatementV2,
    program: ProgramIdentity,
    canonical_proof: Vec<u8>,
    proof_policy: B256,
}

impl CheckedGroth16SettlementV2 {
    pub(crate) fn from_capability(proof: &QualifiedGroth16SettlementV2) -> Result<Self> {
        Ok(Self {
            statement: proof.statement(),
            program: proof.program(),
            canonical_proof: proof.canonical_proof_bytes()?,
            proof_policy: proof.proof_policy_commitment()?,
        })
    }

    pub(crate) fn statement(&self) -> SettlementStatementV2 {
        self.statement
    }

    pub(crate) fn program(&self) -> ProgramIdentity {
        self.program
    }

    /// Cryptography-free fixture for transition tests. This constructor and
    /// every call site disappear from non-test builds.
    #[cfg(test)]
    fn test_fixture(statement: SettlementStatementV2, program: ProgramIdentity, proof_byte: u8) -> Self {
        Self {
            statement,
            program,
            canonical_proof: vec![proof_byte; crate::verification::GROTH16_CONSENSUS_PROOF_BYTES],
            proof_policy: B256::repeat_byte(proof_byte.wrapping_add(1)),
        }
    }
}

impl SourceSettlement {
    /// Independent policy pins native network/genesis and execution domain/program.
    /// Only a trusted EVM genesis with zero consumed deposits can bootstrap here.
    pub fn from_trusted_genesis(
        spec: ChainSpec,
        network: B256,
        genesis: B256,
        domain: B256,
        program: ProgramIdentity,
        anchor: NodeHeaderV2,
        source: SourceRegistry,
    ) -> Result<Self> {
        if anchor.number != 0
            || source.anchor().height != 0
            || source.count() != 0
            || source.network() != network
            || source.genesis() != genesis
            || source.domain() != domain
        {
            return Err(invalid("source settlement bootstrap identity mismatch"));
        }
        let mut state = bloch_l2_evm::node_execution::genesis_v2(&spec, anchor.timestamp)?;
        state.commit_root();
        let canonical = bloch_l2_evm::node_execution::node_head(&spec, domain, &state)?;
        if anchor != canonical {
            return Err(invalid("source settlement requires canonical unconsumed EVM genesis"));
        }
        let execution = SettlementCursor::from_trusted_anchor(spec.clone(), domain, program, anchor)?;
        Ok(Self {
            source,
            execution,
            spec,
            next_sequence: 0,
            last_payload: None,
        })
    }
    pub fn execution(&self) -> &SettlementCursor {
        &self.execution
    }
    pub fn source(&self) -> &SourceRegistry {
        &self.source
    }
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub fn last_payload(&self) -> Option<SettlementPayloadV2> {
        self.last_payload
    }
    pub fn last_settlement(&self) -> Result<Option<B256>> {
        payload_commitment(self.last_payload.as_ref())
    }

    /// Construct the exact V2 proof expectation from the independently retained
    /// source registry and execution cursor. This authenticates only the local
    /// experimental inputs; native consensus must enforce the same expectation.
    pub fn expected_statement_v2(&self, header: &NodeHeaderV2, body: &NodeBodyV2) -> Result<SettlementStatementV2> {
        expected_groth16_source_statement(
            SourceSettlementV2State::new(
                &self.spec,
                &self.execution,
                self.next_sequence,
                self.last_payload.as_ref(),
                &self.source,
            )?,
            header,
            body,
        )
    }

    /// `expected` is independently trusted authority, not derived from proposer input.
    pub fn apply_source(
        &mut self,
        expected: B256,
        position: HeightPosition,
        headers: &[Bytes],
        batch: &SourceBatch,
        proofs: &[InboxProof],
    ) -> Result<()> {
        self.source.apply(expected, position, headers, batch, proofs)?;
        Ok(())
    }
    /// All fallible checks precede publication of either execution or consumption.
    pub fn advance(
        &mut self,
        proof: &VerifiedExecutionStatement,
        header: &NodeHeaderV2,
        body: &NodeBodyV2,
    ) -> Result<SourceSettlementMark> {
        check_legacy_advance_allowed(self.last_payload.is_some())?;
        let (execution, mark) = prepare_source_advance(
            &self.spec,
            &self.execution,
            self.next_sequence,
            &self.source,
            proof,
            header,
            body,
        )?;
        self.execution = execution;
        self.next_sequence = mark.next_sequence;
        Ok(mark)
    }

    /// Check and publish one Groth16 V2 successor as a single in-memory state
    /// change. The predecessor, source cursor and proof digest are not supplied
    /// by the caller. All fallible work completes before any field is changed.
    pub fn advance_groth16_settlement_v2(
        &mut self,
        proof: &QualifiedGroth16SettlementV2,
        header: &NodeHeaderV2,
        body: &NodeBodyV2,
    ) -> Result<SourceSettlementV2Mark> {
        let checked = CheckedGroth16SettlementV2::from_capability(proof)?;
        self.advance_checked_groth16_settlement_v2(checked, header, body)
    }

    /// Shared transition after verifier-capability extraction. This remains
    /// private: production callers cannot manufacture checked evidence.
    fn advance_checked_groth16_settlement_v2(
        &mut self,
        proof: CheckedGroth16SettlementV2,
        header: &NodeHeaderV2,
        body: &NodeBodyV2,
    ) -> Result<SourceSettlementV2Mark> {
        let (execution, mark) = prepare_groth16_source_advance(
            SourceSettlementV2State::new(
                &self.spec,
                &self.execution,
                self.next_sequence,
                self.last_payload.as_ref(),
                &self.source,
            )?,
            &proof,
            header,
            body,
        )?;

        self.execution = execution;
        self.next_sequence = mark.next_sequence;
        self.last_payload = Some(mark.payload);
        Ok(mark)
    }
}

/// Pure checked V2 transition shared by in-memory coordination and durable
/// journals. The returned cursor/mark are candidates; this function publishes
/// no state. `proof` can only be constructed from a verified capability outside
/// test builds.
#[derive(Clone, Copy)]
pub(crate) struct SourceSettlementV2State<'a> {
    spec: &'a ChainSpec,
    execution: &'a SettlementCursor,
    next_sequence: u64,
    last_settlement: Option<B256>,
    source: &'a SourceRegistry,
}

impl<'a> SourceSettlementV2State<'a> {
    pub(crate) fn new(
        spec: &'a ChainSpec,
        execution: &'a SettlementCursor,
        next_sequence: u64,
        last_payload: Option<&SettlementPayloadV2>,
        source: &'a SourceRegistry,
    ) -> Result<Self> {
        Ok(Self {
            spec,
            execution,
            next_sequence,
            last_settlement: payload_commitment(last_payload)?,
            source,
        })
    }
}

/// Derive the exact independent public statement that must be supplied to the
/// verifier. Durable replay uses this before it can obtain a checked proof
/// capability from `TrustedProgram`.
pub(crate) fn expected_groth16_source_statement(
    state: SourceSettlementV2State<'_>,
    header: &NodeHeaderV2,
    body: &NodeBodyV2,
) -> Result<SettlementStatementV2> {
    Ok(expected_groth16_source_selection(state, header, body)?.0)
}

fn expected_groth16_source_selection(
    state: SourceSettlementV2State<'_>,
    header: &NodeHeaderV2,
    body: &NodeBodyV2,
) -> Result<(SettlementStatementV2, ValidatedV2Prefix)> {
    let SourceSettlementV2State {
        spec,
        execution,
        next_sequence,
        last_settlement,
        source,
    } = state;
    execution.expected_for_selected_header(header)?;
    let selected = source.validate_v2_prefix(spec, next_sequence, header, body)?;
    let anchor = selected.anchor();
    let range = selected.range();
    let program = execution.program();
    let statement = SettlementStatementV2::from_executed(
        configuration_commitment(spec)?,
        header,
        body,
        SettlementContextV2 {
            network: selected.network(),
            genesis: selected.genesis(),
            program_elf_keccak: program.elf_keccak(),
            program_vkey_koalabear: program.verifying_key_hash(),
            program_vkey_bn254: program.verifying_key_bn254(),
            previous_settlement: expected_previous_settlement(last_settlement),
            l1_slot: anchor.slot,
            l1_height: anchor.height,
            source_commitment: selected.source_commitment(),
            inbox_root: selected.inbox_root(),
            inbox_count: selected.inbox_count(),
            consumed_start: range.start,
            consumed_end: range.end,
        },
    )?;
    check_previous_settlement(&statement, last_settlement)?;
    Ok((statement, selected))
}

pub(crate) fn prepare_groth16_source_advance(
    state: SourceSettlementV2State<'_>,
    proof: &CheckedGroth16SettlementV2,
    header: &NodeHeaderV2,
    body: &NodeBodyV2,
) -> Result<(SettlementCursor, SourceSettlementV2Mark)> {
    let execution = state.execution;
    let (expected, selected) = expected_groth16_source_selection(state, header, body)?;
    let range = selected.range();
    let program = execution.program();
    if proof.statement != expected {
        return Err(invalid("verified Groth16 statement differs from retained source state"));
    }
    if proof.program != program {
        return Err(invalid(
            "Groth16 settlement V2 proof belongs to another trusted program",
        ));
    }

    let digest = proof_digest(&proof.canonical_proof)?;
    let payload = SettlementPayloadV2::from_unverified_statement_v2(expected, digest, proof.proof_policy)?;
    let settlement_commitment = payload.commitment()?;
    let mut candidate = execution.clone();
    let execution_mark = candidate.advance_checked_settlement_v2(proof, &expected, header)?;
    let mark = SourceSettlementV2Mark {
        execution: execution_mark,
        next_sequence: range.end,
        source_commitment: selected.source_commitment(),
        settlement_commitment,
        payload,
    };
    Ok((candidate, mark))
}

fn expected_previous_settlement(last_settlement: Option<B256>) -> B256 {
    last_settlement.unwrap_or(B256::ZERO)
}

fn payload_commitment(payload: Option<&SettlementPayloadV2>) -> Result<Option<B256>> {
    match payload.map(SettlementPayloadV2::commitment).transpose()? {
        Some(commitment) if commitment == B256::ZERO => Err(invalid("zero V2 settlement payload commitment")),
        commitment => Ok(commitment),
    }
}

fn check_previous_settlement(statement: &SettlementStatementV2, last_settlement: Option<B256>) -> Result<()> {
    if statement.previous_settlement != expected_previous_settlement(last_settlement) {
        return Err(invalid("settlement V2 predecessor differs from retained tip"));
    }
    Ok(())
}

fn check_legacy_advance_allowed(has_v2_payload: bool) -> Result<()> {
    if has_v2_payload {
        return Err(invalid("legacy settlement cannot advance after V2 tip publication"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "fixture.rs"]
#[allow(dead_code)]
mod execution_fixture;

/// Shared checked transition; callers publish only after any required durable sync.
pub(crate) fn prepare_source_advance(
    spec: &ChainSpec,
    execution: &SettlementCursor,
    next_sequence: u64,
    source: &SourceRegistry,
    proof: &VerifiedExecutionStatement,
    header: &NodeHeaderV2,
    body: &NodeBodyV2,
) -> Result<(SettlementCursor, SourceSettlementMark)> {
    let selected = source.validate_v2_prefix(spec, next_sequence, header, body)?;
    if selected.statement() != proof.statement() {
        return Err(invalid("source selection differs from verified execution"));
    }
    let mut candidate = execution.clone();
    let mark = candidate.advance(proof, header)?;
    Ok((
        candidate,
        SourceSettlementMark {
            execution: mark,
            next_sequence: selected.range().end,
            source_commitment: selected.source_commitment(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use bloch_l2_evm::{
        escrow::{Coin, EscrowLedger, LockIntent, Outpoint},
        escrow_execution::TrustedLockLocation,
        l1::{height::HeightCursor, FinalizedCheckpoint},
        DepositPosition,
    };
    use bloch_native_domain_devnet::{SourceAnchor, MAX_LOCKS};
    use sha3::{Digest, Sha3_256};

    struct SourceFixture {
        execution: execution_fixture::Fixture,
        registry: SourceRegistry,
        headers: Vec<Bytes>,
        position: HeightPosition,
        batch: SourceBatch,
        proofs: Vec<InboxProof>,
        expected_source: B256,
    }

    fn header_id(bytes: &[u8]) -> B256 {
        let mut hash = Sha3_256::new();
        hash.update(b"BLCH4:BLOCK\0\0\0\0\0");
        hash.update(bytes);
        B256::from_slice(&hash.finalize())
    }

    fn source_fixture() -> Result<SourceFixture> {
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
        let existing = execution_fixture::fixture()?;
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
        let expected_source = batch.commitment()?;
        let proofs = inbox
            .proofs(0..1)
            .ok_or_else(|| invalid("fixture inbox proof missing"))?;
        let (execution, _, _) = execution_fixture::execute_fixture_at(existing.body, position.block())?;
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

    fn fixture_error(error: impl core::fmt::Debug) -> std::io::Error {
        std::io::Error::other(format!("synthetic source fixture: {error:?}"))
    }

    fn coordinator(fixture: &SourceFixture, program: ProgramIdentity) -> SourceSettlement {
        SourceSettlement::from_trusted_genesis(
            ChainSpec::testnet(),
            fixture.registry.network(),
            fixture.registry.genesis(),
            fixture.registry.domain(),
            program,
            fixture.execution.parent.clone(),
            fixture.registry.clone(),
        )
        .unwrap()
    }

    fn empty_successor(parent: &NodeHeaderV2, variant: u8) -> (NodeHeaderV2, NodeBodyV2) {
        let spec = ChainSpec::testnet();
        let body = NodeBodyV2::default();
        let header = NodeHeaderV2 {
            domain: parent.domain,
            chain_id: parent.chain_id,
            number: parent.number + 1,
            timestamp: parent.timestamp + 1,
            base_fee_per_gas: spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
            gas_limit: parent.gas_limit,
            gas_used: 0,
            user_gas_used: 0,
            beneficiary: parent.beneficiary,
            prevrandao: B256::repeat_byte(variant),
            anchor_root: parent.anchor_root,
            parent_hash: parent.hash(),
            parent_state_root: parent.state_root,
            transactions_root: body.transactions_root(),
            deposits_hash: body.deposits_hash(),
            state_root: B256::repeat_byte(variant.wrapping_add(0x80)),
            ..Default::default()
        };
        (header, body)
    }

    fn assert_state(
        coordinator: &SourceSettlement,
        execution: SettlementMark,
        next_sequence: u64,
        last_settlement: Option<B256>,
        source: &SourceRegistry,
    ) {
        assert_eq!(coordinator.execution().mark(), execution);
        assert_eq!(coordinator.next_sequence(), next_sequence);
        assert_eq!(coordinator.last_settlement().unwrap(), last_settlement);
        assert_eq!(coordinator.source(), source);
    }

    fn statement_with_previous(previous_settlement: B256) -> SettlementStatementV2 {
        SettlementStatementV2 {
            network: B256::repeat_byte(1),
            genesis: B256::repeat_byte(2),
            domain: B256::repeat_byte(3),
            configuration: B256::repeat_byte(4),
            program_elf_keccak: B256::repeat_byte(5),
            program_vkey_koalabear: B256::repeat_byte(6),
            program_vkey_bn254: B256::repeat_byte(7),
            previous_settlement,
            chain_id: 700_771,
            l2_number: 1,
            l2_parent_hash: B256::repeat_byte(8),
            l2_previous_state_root: B256::repeat_byte(9),
            l2_header_hash: B256::repeat_byte(10),
            l2_state_root: B256::repeat_byte(11),
            l1_block: B256::repeat_byte(12),
            l1_slot: 2,
            l1_height: 1,
            source_commitment: B256::repeat_byte(13),
            inbox_root: B256::repeat_byte(14),
            inbox_count: 0,
            consumed_start: 0,
            consumed_end: 0,
            body_commitment: B256::repeat_byte(15),
        }
    }

    #[test]
    fn predecessor_is_zero_only_before_the_first_settlement() {
        let first = statement_with_previous(B256::ZERO);
        assert!(check_previous_settlement(&first, None).is_ok());

        let tip = B256::repeat_byte(42);
        assert!(check_previous_settlement(&statement_with_previous(tip), Some(tip)).is_ok());
        assert!(check_previous_settlement(&first, Some(tip)).is_err());
    }

    #[test]
    fn stale_fork_and_replay_predecessors_fail_closed() {
        let tip = B256::repeat_byte(42);
        for stale in [B256::repeat_byte(41), B256::repeat_byte(43), B256::ZERO] {
            assert!(check_previous_settlement(&statement_with_previous(stale), Some(tip)).is_err());
        }
    }

    #[test]
    fn legacy_path_cannot_split_state_after_v2_publication() {
        assert!(check_legacy_advance_allowed(false).is_ok());
        assert!(check_legacy_advance_allowed(true).is_err());
    }

    #[test]
    fn checked_v2_path_consumes_nonempty_source_chains_successors_and_is_atomic() {
        let fixture = source_fixture().unwrap();
        let program = ProgramIdentity::test_fixture(0x31);
        let other_program = ProgramIdentity::test_fixture(0x41);
        let mut coordinator = coordinator(&fixture, program);
        coordinator
            .apply_source(
                fixture.expected_source,
                fixture.position,
                &fixture.headers,
                &fixture.batch,
                &fixture.proofs,
            )
            .unwrap();

        let initial_execution = coordinator.execution().mark();
        let applied_source = coordinator.source().clone();
        let first_statement = coordinator
            .expected_statement_v2(&fixture.execution.header, &fixture.execution.body)
            .unwrap();
        assert_eq!(first_statement.consumed_start, 0);
        assert_eq!(first_statement.consumed_end, 1);
        assert_eq!(first_statement.inbox_count, 1);
        assert_ne!(first_statement.source_commitment, B256::ZERO);

        // A statement that otherwise matches cannot advance under another
        // program identity, and failure publishes none of the four cursors.
        let wrong_program = CheckedGroth16SettlementV2::test_fixture(first_statement, other_program, 0x91);
        assert!(coordinator
            .advance_checked_groth16_settlement_v2(wrong_program, &fixture.execution.header, &fixture.execution.body,)
            .is_err());
        assert_state(&coordinator, initial_execution, 0, None, &applied_source);

        // Proof-digest/payload preparation also occurs before publication.
        let empty_proof = CheckedGroth16SettlementV2 {
            statement: first_statement,
            program,
            canonical_proof: Vec::new(),
            proof_policy: B256::repeat_byte(0x92),
        };
        assert!(coordinator
            .advance_checked_groth16_settlement_v2(empty_proof, &fixture.execution.header, &fixture.execution.body,)
            .is_err());
        assert_state(&coordinator, initial_execution, 0, None, &applied_source);

        let first_proof = CheckedGroth16SettlementV2::test_fixture(first_statement, program, 0x93);
        let first = coordinator
            .advance_checked_groth16_settlement_v2(first_proof, &fixture.execution.header, &fixture.execution.body)
            .unwrap();
        assert_eq!(first.next_sequence(), 1);
        assert_eq!(first.execution().header_hash, fixture.execution.header.hash());
        assert_eq!(
            coordinator.last_settlement().unwrap(),
            Some(first.settlement_commitment())
        );

        let after_first_source = coordinator.source().clone();
        let replay_execution = coordinator.execution().mark();
        let replay_tip = coordinator.last_settlement().unwrap();
        let replay = CheckedGroth16SettlementV2::test_fixture(first_statement, program, 0x93);
        assert!(coordinator
            .advance_checked_groth16_settlement_v2(replay, &fixture.execution.header, &fixture.execution.body)
            .is_err());
        assert_state(&coordinator, replay_execution, 1, replay_tip, &after_first_source);

        // Two valid candidates share the same predecessor. Publishing one
        // makes the other a stale fork, while a fresh successor commits to the
        // exact prior settlement payload commitment.
        let (successor, successor_body) = empty_successor(&fixture.execution.header, 0x21);
        let (fork, fork_body) = empty_successor(&fixture.execution.header, 0x22);
        let successor_statement = coordinator.expected_statement_v2(&successor, &successor_body).unwrap();
        let fork_statement = coordinator.expected_statement_v2(&fork, &fork_body).unwrap();
        assert_eq!(successor_statement.consumed_start, 1);
        assert_eq!(successor_statement.consumed_end, 1);
        assert_eq!(successor_statement.previous_settlement, first.settlement_commitment());
        assert_eq!(fork_statement.previous_settlement, first.settlement_commitment());

        let successor_proof = CheckedGroth16SettlementV2::test_fixture(successor_statement, program, 0x94);
        let second = coordinator
            .advance_checked_groth16_settlement_v2(successor_proof, &successor, &successor_body)
            .unwrap();
        assert_eq!(second.next_sequence(), 1);
        assert_ne!(second.settlement_commitment(), first.settlement_commitment());

        let after_second_execution = coordinator.execution().mark();
        let after_second_tip = coordinator.last_settlement().unwrap();
        let stale_fork = CheckedGroth16SettlementV2::test_fixture(fork_statement, program, 0x95);
        assert!(coordinator
            .advance_checked_groth16_settlement_v2(stale_fork, &fork, &fork_body)
            .is_err());
        assert_state(
            &coordinator,
            after_second_execution,
            1,
            after_second_tip,
            &after_first_source,
        );

        // Replaying the accepted successor is likewise rejected without a
        // partial execution/source/predecessor update.
        let successor_replay = CheckedGroth16SettlementV2::test_fixture(successor_statement, program, 0x94);
        assert!(coordinator
            .advance_checked_groth16_settlement_v2(successor_replay, &successor, &successor_body)
            .is_err());
        assert_state(
            &coordinator,
            after_second_execution,
            1,
            after_second_tip,
            &after_first_source,
        );
    }
}
