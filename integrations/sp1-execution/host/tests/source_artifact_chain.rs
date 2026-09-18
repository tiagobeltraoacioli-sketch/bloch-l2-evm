//! One actual Reth/proof chain also settles against independently trusted source.
#![cfg(all(feature = "node-artifact", feature = "source-settlement", unix))]
#[path = "../src/fixture.rs"]
#[allow(dead_code)]
mod fixture;
#[path = "../src/source_fixture.rs"]
#[allow(dead_code)]
mod source_fixture;

use bloch_evm_sp1_host::{
    artifact::load_selected_artifact,
    source_journal::{SourceSettlementJournal, SourceSettlementPolicy},
    verification::TrustedProgram,
};
use bloch_l2_evm::{l1::height::HeightCursor, ChainSpec};
use bloch_native_domain_devnet::journal::{JournalLimits, SourceJournal};
use sp1_sdk::Elf;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bloch-source-artifact-chain-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn source_selection_matches_three_real_reth_exports_before_proving() {
    let host = Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = std::env::var_os("BLOCH_SP1_CHAIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| host.join("target/qualification-source-chain"));
    let f = source_fixture::source_contract().unwrap();
    let mut registry = f.registry.clone();
    registry
        .apply(f.expected_source, f.position, &f.headers, &f.batch, &f.proofs)
        .unwrap();
    let mut next = 0;
    let mut parent = f.execution.parent;
    for number in 1..=3 {
        let artifact = load_selected_artifact(directory.join(format!("block-{number}.json")))
            .expect("export actual source-bound Reth chain first");
        assert_eq!(artifact.parent(), &parent);
        let selected = registry
            .validate_v2_prefix(&ChainSpec::testnet(), next, artifact.header(), artifact.body())
            .unwrap();
        assert_eq!(selected.statement(), artifact.expected());
        next = selected.range().end;
        assert_eq!(next, 1);
        parent = artifact.header().clone();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_reth_three_block_proofs_recover_source_consumption_exactly_once() {
    let host = Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = std::env::var_os("BLOCH_SP1_CHAIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| host.join("target/qualification-source-chain"));
    let elf = std::env::var_os("BLOCH_SP1_ELF").map(PathBuf::from).unwrap_or_else(|| {
        host.join("../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bloch-evm-synthetic-guest")
    });
    let program = TrustedProgram::from_trusted_elf(Elf::from(fs::read(elf).expect("build pinned guest first")))
        .await
        .unwrap();
    let mut blocks = Vec::new();
    for number in 1..=3 {
        let artifact = load_selected_artifact(directory.join(format!("block-{number}.json")))
            .expect("export actual source-bound Reth chain first");
        let token = program
            .verify_file(directory.join(format!("block-{number}.proof")), &artifact.expected())
            .expect("generate actual SP1 proof for each selected block first");
        blocks.push((artifact, token));
    }
    let f = source_fixture::source_contract().unwrap();
    let spec = ChainSpec::testnet();
    assert_eq!(blocks[0].0.parent(), &f.execution.parent);
    for index in 1..blocks.len() {
        assert_eq!(blocks[index].0.parent(), blocks[index - 1].0.header());
    }
    for (artifact, _) in &blocks {
        assert_eq!(artifact.header().anchor_root, f.position.block());
    }
    assert_eq!(blocks[0].0.body().deposits.len(), 1);
    assert!(blocks[1].0.body().deposits.is_empty());
    assert!(blocks[2].0.body().deposits.is_empty());
    let bootstrap = || HeightCursor::from_genesis(f.registry.genesis(), &f.headers[0]).unwrap();
    let policy = || {
        SourceSettlementPolicy::new(
            spec.clone(),
            f.registry.network(),
            f.registry.genesis(),
            f.registry.domain(),
            program.identity(),
            blocks[0].0.parent().clone(),
        )
        .unwrap()
    };
    let temp = Temp::new();
    let source_path = temp.path("source");
    let execution_path = temp.path("execution");
    let mut source = SourceJournal::create(
        &source_path,
        f.registry.network(),
        f.registry.domain(),
        bootstrap(),
        JournalLimits::default(),
    )
    .unwrap();
    let mut journal = SourceSettlementJournal::create(&execution_path, policy(), &mut source).unwrap();
    let initial = journal.mark().unwrap();
    // No source authority may be inferred from an otherwise valid funding proof.
    assert!(journal
        .append(&mut source, &blocks[0].1, blocks[0].0.header(), blocks[0].0.body())
        .is_err());
    assert_eq!(journal.mark().unwrap(), initial);
    let source_mark = source
        .append(f.expected_source, f.position, &f.headers, &f.batch, &f.proofs)
        .unwrap();
    for (index, (artifact, token)) in blocks.iter().enumerate() {
        let before = journal.mark().unwrap();
        let disk = fs::read(&execution_path).unwrap();
        if index == 1 {
            // A genuine deploy proof cannot authorize consuming the first lock twice.
            let mut bad_body = artifact.body().clone();
            bad_body.deposits = blocks[0].0.body().deposits.clone();
            assert!(journal
                .append(&mut source, token, artifact.header(), &bad_body)
                .is_err());
            assert_eq!(journal.mark().unwrap(), before);
            assert_eq!(fs::read(&execution_path).unwrap(), disk);
        }
        let mark = journal
            .append(&mut source, token, artifact.header(), artifact.body())
            .unwrap();
        assert_eq!(mark.execution.number, index as u64 + 1);
        assert_eq!(mark.execution.header_hash, artifact.header().hash());
        assert_eq!(mark.execution.state_root, artifact.header().state_root);
        assert_eq!(mark.next_sequence, 1);
        assert_eq!(mark.last_source, source_mark);
    }
    let accepted = journal.mark().unwrap();
    let disk = fs::read(&execution_path).unwrap();
    assert!(journal
        .append(&mut source, &blocks[2].1, blocks[2].0.header(), blocks[2].0.body())
        .is_err());
    assert_eq!(journal.mark().unwrap(), accepted);
    assert_eq!(fs::read(&execution_path).unwrap(), disk);
    drop(journal);
    drop(source);
    let mut source = SourceJournal::open(
        &source_path,
        f.registry.network(),
        f.registry.domain(),
        bootstrap(),
        source_mark,
        JournalLimits::default(),
    )
    .unwrap();
    for floor in [initial, accepted] {
        let mut journal =
            SourceSettlementJournal::open(&execution_path, policy(), &program, &mut source, floor).unwrap();
        assert_eq!(journal.mark().unwrap(), accepted);
        assert_eq!(journal.cursor().unwrap().head(), blocks[2].0.header());
        assert!(journal
            .append(&mut source, &blocks[0].1, blocks[0].0.header(), blocks[0].0.body())
            .is_err());
        assert_eq!(journal.mark().unwrap(), accepted);
        assert_eq!(fs::read(&execution_path).unwrap(), disk);
    }
}
