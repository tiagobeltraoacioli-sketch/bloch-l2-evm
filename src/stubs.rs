// SPDX-License-Identifier: MIT OR Apache-2.0
//! Honest stubs for the large integrations this scaffold does NOT contain.
//!
//! **SCAFFOLD, not a working L2.** Every function here panics with
//! `todo!()`/`unimplemented!()`. They exist to pin the intended surface from
//! BLOCH-L2-EVM-DESIGN §1 and to make it impossible to mistake this crate for
//! a node, an RPC server, a mempool, or a prover.

/// `eth_*` JSON-RPC — **STUBBED**.
///
/// The design mandates Reth's jsonrpsee RPC stack (eth_chainId, eth_call,
/// eth_sendRawTransaction, eth_getProof, eth_subscribe, ... — the full list
/// in §1 "Interfaces") so the surface is Reth's, not hand-rolled. None of it
/// exists here.
pub mod rpc {
    /// Start the JSON-RPC server.
    ///
    /// SCAFFOLD: the real implementation embeds reth-rpc; hand-rolling eth_*
    /// is exactly the compatibility bug-farm the design rejects.
    pub fn serve_eth_rpc() -> ! {
        // SCAFFOLD: Reth-SDK jsonrpsee eth_* stack, not hand-rolled RPC.
        unimplemented!("SCAFFOLD: eth_* JSON-RPC is provided by the Reth-SDK node embedding, not this scaffold")
    }

    /// The `bloch_anchorStatus` extension namespace (never `eth_*`).
    ///
    /// SCAFFOLD: reports honest finality state (anchored?, Bloch txid/height,
    /// confirmations, proofVerified) once the anchor reader exists.
    pub fn bloch_anchor_status() -> ! {
        // SCAFFOLD: needs the L2V0 anchor reader (sibling crate in the design).
        unimplemented!("SCAFFOLD: bloch_anchorStatus requires the L2V0 anchor layer")
    }
}

/// Transaction pool — **STUBBED**.
///
/// The design uses Reth's mainnet-grade txpool. This scaffold executes
/// pre-ordered `TxEnv`s only (verifier semantics: a block with an invalid
/// transaction is invalid); there is no mempool, no gossip, no replacement
/// rules, no signature recovery, and no block-builder that skips invalid
/// candidates.
pub mod txpool {
    /// Submit a raw RLP transaction to the pool.
    pub fn submit_raw_transaction(_rlp_bytes: &[u8]) -> ! {
        // SCAFFOLD: Reth txpool (validation, ordering, replacement, gossip).
        todo!("SCAFFOLD: txpool is Reth's, embedded via the node builder; not implemented here")
    }
}

/// Reth-SDK node embedding — **STUBBED**.
///
/// The design's NATIVE target is a Reth-SDK node (reth-node-builder with a
/// single-sequencer consensus stub, custom ChainSpec, reth-rpc, revm as the
/// executor — the op-reth pattern). That is a multi-month integration and a
/// heavy dependency; it is deliberately absent from this scaffold. The STF
/// core already enforces the consensus rules a node must feed it (header
/// validity against the committed head, `BLOCKHASH` from the committed ring,
/// the EIP-4788 system call — audit findings C13, C16, C17); the node's own
/// duties are the anchor reader (Bloch anchor root / prevrandao derivation),
/// the timestamp drift bound against the anchor, signature recovery and
/// receipts.
pub mod node {
    /// Build and launch the L2 full node / sequencer.
    pub fn launch_reth_node() -> ! {
        // SCAFFOLD: reth-node-builder embedding (consensus stub, txpool, RPC,
        // engine); this crate is only the STF core that node would call.
        todo!("SCAFFOLD: Reth-SDK node embedding is not part of this scaffold")
    }
}

/// SP1 guest (riscv32im) build target — **STUBBED**.
///
/// The design's GUEST target compiles this same execution logic for
/// riscv32im/no_std inside an SP1 program (the RSP pattern): verify a batch
/// witness against the pre-state root, re-execute with the SAME pinned revm,
/// commit public values, prove with FRI core proofs only (no Groth16/Plonk
/// wrap — the repo's post-quantum rule). The procedure the guest must run
/// exists and is tested on the host — [`crate::proving::verify_batch`] over a
/// [`crate::proving::BatchWitness`] produced by
/// [`crate::proving::generate_batch_witness`] — and the whole crate, revm and
/// alloy tree included, builds and tests in `no_std` + `alloc` with
/// `--no-default-features`; the witness has a `serde` wire format. What does
/// not exist here: the `sp1_zkvm` entrypoint, the public-values encoding, the
/// guest crate itself and its one documented feature delta (`c-kzg` → the
/// pure-Rust `kzg-rs` KZG backend for the Cancun point-evaluation precompile).
pub mod sp1_guest {
    /// Re-execute a batch inside the zkVM guest.
    pub fn guest_main() -> ! {
        // SCAFFOLD: sp1_zkvm entrypoint reading (ChainSpec, BlockInput,
        // BatchWitness), calling crate::proving::verify_batch, committing
        // (prev_state_root, new_state_root, deposits_hash) as public values.
        todo!("SCAFFOLD: the SP1 guest (riscv32im) target is not implemented in this scaffold")
    }
}
