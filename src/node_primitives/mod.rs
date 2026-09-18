// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental V2 node wire primitives, separate from the existing V1 domain.
//!
//! These codecs bind body and receipt commitments. They do not execute V2
//! blocks, authenticate L1 derivation, activate a domain or implement a node.
//! V2 execution must commit its header metadata before calculating the state
//! root and reconstruct the same parent hash/BLOCKHASH from that metadata.
mod block;
mod body;
mod header;

pub use block::{NodeBlockV2, MAX_NODE_BLOCK_BYTES, NODE_BLOCK_V2_TAG};
pub use body::{NodeBodyError, NodeBodyV2, MAX_NODE_BODY_BYTES, MAX_NODE_DEPOSITS};
pub use header::{NodeHeaderError, NodeHeaderV2, NODE_HEADER_V2_TAG};
