//! Compile-time boundary for a future Bloch L2 production entrypoint.
//!
//! This crate contains interfaces only. It does not implement networking,
//! derivation, consensus, finality, genesis, RPC, persistence or recovery and
//! must not be used as evidence that a production node exists.

#![forbid(unsafe_code)]

/// The selected EIP-155 domain. This does not freeze a genesis.
pub const CHAIN_ID: u64 = 700_771;

/// No production implementation is registered in this crate.
pub const PRODUCTION_ENTRYPOINT_REGISTERED: bool = false;

/// Authenticated peer transport and chain-domain separation.
pub trait P2pNetworking {
    type PeerSession;
    type Error;

    fn validate_peer_session(&self, session: &Self::PeerSession) -> Result<(), Self::Error>;
}

/// Authenticated native/L1 checkpoint, ancestry and deposit-source derivation.
pub trait NativeL1Derivation {
    type AuthenticatedInput;
    type DerivedInput;
    type Error;

    fn derive(&self, input: &Self::AuthenticatedInput) -> Result<Self::DerivedInput, Self::Error>;
}

/// Deterministic production block selection, fork choice and reorganization policy.
pub trait ProductionConsensus {
    type Candidate;
    type Decision;
    type Error;

    fn decide(&self, candidate: &Self::Candidate) -> Result<Self::Decision, Self::Error>;
}

/// Non-regressing finalized head bound to accepted native settlement.
pub trait FinalizedHead {
    type Head;
    type SettlementEvidence;
    type Error;

    fn finalized_head(&self, evidence: &Self::SettlementEvidence) -> Result<Self::Head, Self::Error>;
}

/// Exact reviewed production-genesis bytes and commitments.
pub trait FrozenGenesis {
    type Genesis;
    type Error;

    fn verify_genesis(&self, genesis: &Self::Genesis) -> Result<(), Self::Error>;
}

/// JSON-RPC whose bind is controlled by the production readiness gate.
pub trait GatedJsonRpc {
    type Readiness;
    type Error;

    fn validate_bind_readiness(&self, readiness: &Self::Readiness) -> Result<(), Self::Error>;
}

/// Durable canonical head, state root, receipts and settlement cursor.
pub trait DurablePersistence {
    type Commit;
    type Error;

    fn persist(&self, commit: &Self::Commit) -> Result<(), Self::Error>;
}

/// Stop admission, drain writes, close storage and verify restart integrity.
pub trait GracefulShutdown {
    type ShutdownReceipt;
    type Error;

    fn shutdown(&self) -> Result<Self::ShutdownReceipt, Self::Error>;
}

/// Detect interrupted writes and perform reviewed replay or rollback only.
pub trait CrashRecovery {
    type RecoveryPlan;
    type RecoveryReceipt;
    type Error;

    fn recover(&self, plan: &Self::RecoveryPlan) -> Result<Self::RecoveryReceipt, Self::Error>;
}

/// Composite interface. There is deliberately no implementation in this crate.
pub trait ProductionEntrypoint:
    P2pNetworking
    + NativeL1Derivation
    + ProductionConsensus
    + FinalizedHead
    + FrozenGenesis
    + GatedJsonRpc
    + DurablePersistence
    + GracefulShutdown
    + CrashRecovery
{
    fn chain_id(&self) -> u64;
}

/// A precise missing capability at the workspace inspection boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityGap {
    pub capability_id: &'static str,
    pub status: GapStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GapStatus {
    MissingCompatibleImplementation,
}

pub const CAPABILITY_GAPS: [CapabilityGap; 9] = [
    gap("p2p-networking"),
    gap("authenticated-native-l1-derivation"),
    gap("production-consensus"),
    gap("finalized-head"),
    gap("frozen-genesis"),
    gap("gated-json-rpc"),
    gap("durable-persistence"),
    gap("graceful-shutdown"),
    gap("crash-recovery"),
];

const fn gap(capability_id: &'static str) -> CapabilityGap {
    CapabilityGap {
        capability_id,
        status: GapStatus::MissingCompatibleImplementation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_is_bound_to_chain_700771_but_registers_no_candidate() {
        assert_eq!(CHAIN_ID, 700_771);
        assert!(!PRODUCTION_ENTRYPOINT_REGISTERED);
    }

    #[test]
    fn every_contract_capability_remains_an_explicit_gap() {
        assert_eq!(CAPABILITY_GAPS.len(), 9);
        assert!(CAPABILITY_GAPS
            .iter()
            .all(|gap| gap.status == GapStatus::MissingCompatibleImplementation));
        let ids: Vec<_> = CAPABILITY_GAPS.iter().map(|gap| gap.capability_id).collect();
        assert_eq!(
            ids,
            [
                "p2p-networking",
                "authenticated-native-l1-derivation",
                "production-consensus",
                "finalized-head",
                "frozen-genesis",
                "gated-json-rpc",
                "durable-persistence",
                "graceful-shutdown",
                "crash-recovery",
            ]
        );
    }
}
