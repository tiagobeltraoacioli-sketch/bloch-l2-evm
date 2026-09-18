// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local selected-chain settlement; no native funding or finality authority.
use alloy_primitives::B256;
use bloch_evm_sp1_host::{
    artifact::load_selected_artifact,
    settlement::{SettlementCursor, SettlementJournal},
    verification::TrustedProgram,
    Result,
};
use bloch_l2_evm::{
    node_execution::{genesis_v2, node_head},
    ChainSpec,
};
use sp1_sdk::Elf;
use std::{ffi::OsString, fs, io, path::Path};

const MAX_BLOCKS: usize = 16;
const MAX_INPUT_BYTES: u64 = 128 * 1024 * 1024;
const USAGE: &str = "usage: bloch-evm-sp1-chain <settle|verify> TRUSTED_ELF JOURNAL TRUSTED_ARTIFACT PROOF [TRUSTED_ARTIFACT PROOF ...]\nSelect a complete local chain from canonical V2 genesis, at most 16 blocks. Fixed testnet/domain D3. No native funding/finality authorization. Stop input writers first.";

fn invalid(message: &'static str) -> Box<dyn std::error::Error> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

async fn run(args: &[OsString]) -> Result<()> {
    if args.len() == 1 && args[0] == "--help" {
        println!("{USAGE}");
        return Ok(());
    }
    if args.len() < 5 || !(args.len() - 3).is_multiple_of(2) || (args.len() - 3) / 2 > MAX_BLOCKS {
        return Err(invalid(USAGE));
    }
    let settle = args[0] == "settle";
    if !settle && args[0] != "verify" {
        return Err(invalid(USAGE));
    }
    let journal_path = Path::new(&args[2]);
    if settle && fs::symlink_metadata(journal_path).is_ok() {
        return Err(invalid(
            "settle requires a new journal path; existing output is never replaced",
        ));
    }
    let mut bytes = 0u64;
    for path in &args[3..] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(invalid("selected inputs must be nonempty regular files"));
        }
        bytes = bytes
            .checked_add(metadata.len())
            .ok_or_else(|| invalid("input size overflow"))?;
        if bytes > MAX_INPUT_BYTES {
            return Err(invalid("chain input exceeds 128 MiB aggregate bound"));
        }
    }
    let spec = ChainSpec::testnet();
    let domain = B256::repeat_byte(0xd3);
    // All input and proof validation precedes creation. Only headers and verified
    // tokens are retained; each artifact's witness is dropped before the next.
    let program = TrustedProgram::from_trusted_elf(Elf::from(fs::read(&args[1])?)).await?;
    let mut anchor = None;
    let mut candidate: Option<SettlementCursor> = None;
    let mut accepted = Vec::new();
    for pair in args[3..].as_chunks::<2>().0 {
        let artifact = load_selected_artifact(&pair[0])?;
        if candidate.is_none() {
            let mut genesis = genesis_v2(&spec, artifact.parent().timestamp)?;
            genesis.commit_root();
            if node_head(&spec, domain, &genesis)? != *artifact.parent() {
                return Err(invalid(
                    "selected chain must begin at canonical zero-consumption V2 genesis",
                ));
            }
            let cursor = SettlementCursor::from_trusted_anchor(
                spec.clone(),
                domain,
                program.identity(),
                artifact.parent().clone(),
            )?;
            anchor = Some(cursor.clone());
            candidate = Some(cursor);
        }
        let cursor = candidate.as_mut().ok_or_else(|| invalid("missing chain anchor"))?;
        if cursor.head() != artifact.parent() {
            return Err(invalid("selected artifacts omit, repeat or replace a chain parent"));
        }
        let expected = cursor.expected_for_selected_header(artifact.header())?;
        if expected != artifact.expected() {
            return Err(invalid("artifact statement differs from selected chain"));
        }
        let verified = program.verify_file(&pair[1], &expected)?;
        cursor.advance(&verified, artifact.header())?;
        accepted.push((artifact.header().clone(), verified));
    }
    let anchor = anchor.ok_or_else(|| invalid("empty selected chain"))?;
    let expected = candidate.ok_or_else(|| invalid("empty selected chain"))?;
    if settle {
        let mut journal = SettlementJournal::create(journal_path, anchor)?;
        for (header, proof) in &accepted {
            journal.append(proof, header)?;
        }
        if journal.cursor().head() != expected.head() {
            return Err(invalid("durable journal differs from selected chain"));
        }
    } else {
        let journal = SettlementJournal::open(journal_path, &program, anchor, expected.mark())?;
        // The underlying journal permits a valid suffix after its retained floor.
        // This complete-chain CLI deliberately requires the exact selected tip.
        if journal.cursor().head() != expected.head() {
            return Err(invalid("journal has a suffix outside the independently selected chain"));
        }
    }
    println!("LOCAL CHAIN {}: blocks={} number={} header={} state={}; actual SP1 proofs verified, no native funding/finality authority", if settle { "settled" } else { "verified" }, accepted.len(), expected.mark().number, expected.mark().header_hash, expected.mark().state_root);
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    run(&std::env::args_os().skip(1).collect::<Vec<_>>()).await
}
