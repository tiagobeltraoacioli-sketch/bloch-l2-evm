//! Genuine source-bound SP1 proof artifacts; no ignored or mock acceptance.
#![cfg(all(feature = "source-settlement", unix))]
#[path = "../src/fixture.rs"]
#[allow(dead_code)]
mod fixture;
#[path = "../src/source_fixture.rs"]
mod source_fixture;

use alloy_primitives::{keccak256, Bytes, B256};
use bloch_evm_sp1_host::{
    source_journal::{
        SourceSettlementJournal, SourceSettlementJournalMark, SourceSettlementPolicy, SOURCE_SETTLEMENT_MARK_BYTES,
    },
    verification::{ProgramIdentity, TrustedProgram},
};
use bloch_l2_evm::{
    l1::{height::HeightCursor, FinalizedCheckpoint},
    ChainSpec,
};
use bloch_native_domain_devnet::{
    journal::{JournalLimits, SourceJournal, SourceMark, MARK_BYTES},
    SourceAnchor,
};
use sha3::{Digest, Sha3_256};
use sp1_sdk::Elf;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bloch-source-sp1-journal-{}-{}",
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
fn artifact(variable: &str, default: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(default))
}
fn policy(f: &source_fixture::SourceFixture, program: ProgramIdentity) -> SourceSettlementPolicy {
    SourceSettlementPolicy::new(
        ChainSpec::testnet(),
        f.registry.network(),
        f.registry.genesis(),
        f.registry.domain(),
        program,
        f.execution.parent.clone(),
    )
    .unwrap()
}
fn cursor(f: &source_fixture::SourceFixture) -> HeightCursor {
    HeightCursor::from_genesis(f.registry.genesis(), &f.headers[0]).unwrap()
}
fn source(temp: &Temp, f: &source_fixture::SourceFixture) -> SourceJournal {
    SourceJournal::create(
        temp.path("source"),
        f.registry.network(),
        f.registry.domain(),
        cursor(f),
        JournalLimits::default(),
    )
    .unwrap()
}
fn native_id(header: &[u8]) -> B256 {
    let mut hash = Sha3_256::new();
    hash.update(b"BLCH4:BLOCK\0\0\0\0\0");
    hash.update(header);
    B256::from_slice(&hash.finalize())
}

fn alternative_source(temp: &Temp, f: &source_fixture::SourceFixture) -> SourceJournal {
    use alloy_primitives::Address;
    use bloch_l2_evm::escrow::{Coin, EscrowLedger, LockIntent, Outpoint};
    let funding = Outpoint {
        txid: B256::repeat_byte(0xa1),
        vout: 0,
    };
    let owner = B256::repeat_byte(0xa2);
    let mut ledger = EscrowLedger::new(
        f.registry.network(),
        f.registry.domain(),
        vec![(funding, Coin { value: 101, owner })],
        4096,
    )
    .unwrap();
    let deposit = ledger
        .apply_authorized_lock(&LockIntent {
            network: f.registry.network(),
            domain: f.registry.domain(),
            owner,
            inputs: vec![funding],
            recipient: Address::repeat_byte(0xa3),
            amount: 100,
            fee: 1,
            change_owner: owner,
            nonce: 0,
        })
        .unwrap();
    assert!(ledger.conserved());
    let inbox = ledger.inbox();
    let proofs = inbox.proofs(0..1).unwrap();
    let mut alternative = SourceJournal::create(
        temp.path("same-genesis-conflicting-history"),
        f.registry.network(),
        f.registry.domain(),
        cursor(f),
        JournalLimits::default(),
    )
    .unwrap();
    let mut first = f.batch.clone();
    first.inbox_root = inbox.root();
    first.locations[0].intent = deposit.id;
    alternative
        .append(first.commitment().unwrap(), f.position, &f.headers, &first, &proofs)
        .unwrap();
    let mut header = vec![0u8; 304];
    header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    header[4..36].copy_from_slice(f.position.block().as_slice());
    header[100..108].copy_from_slice(&200u64.to_le_bytes());
    let mut headers = f.headers.clone();
    headers.push(Bytes::from(header));
    let checkpoint = FinalizedCheckpoint {
        block: native_id(&headers[2]),
        slot: 200,
    };
    let mut native_cursor = cursor(f);
    let position = native_cursor.advance(checkpoint, &headers).unwrap();
    let mut second = first;
    second.previous = alternative.mark().unwrap().commitment;
    second.anchor = SourceAnchor {
        block: position.block(),
        slot: position.slot(),
        height: position.height(),
    };
    alternative
        .append(second.commitment().unwrap(), position, &headers[1..], &second, &proofs)
        .unwrap();
    alternative
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_and_real_proof_replay_derive_consumption_once_across_restart() {
    let f = source_fixture::source_contract().unwrap();
    let elf = fs::read(artifact(
        "BLOCH_SP1_ELF",
        "../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bloch-evm-synthetic-guest",
    ))
    .expect("build pinned guest first");
    let program = TrustedProgram::from_trusted_elf(Elf::from(elf)).await.unwrap();
    let verified = program
        .verify_file(
            artifact("BLOCH_SP1_SOURCE_PROOF", "target/qualification-source-contract.proof"),
            &f.execution.expected,
        )
        .expect("generate real source-contract proof first");
    let temp = Temp::new();
    let mut source = source(&temp, &f);
    let source_genesis = source.mark().unwrap();
    let path = temp.path("combined");
    let mut journal = SourceSettlementJournal::create(&path, policy(&f, program.identity()), &mut source).unwrap();
    let initial = journal.mark().unwrap();
    let prefix_len = fs::metadata(&path).unwrap().len() as usize;
    assert_eq!(initial.next_sequence, 0);
    assert_eq!(initial.execution.number, 0);
    assert!(SourceSettlementJournal::create(&path, policy(&f, program.identity()), &mut source).is_err());
    assert!(
        SourceSettlementJournal::open(&path, policy(&f, program.identity()), &program, &mut source, initial).is_err()
    );
    // Valid proof alone cannot mint before its source is accepted.
    let prefix = fs::read(&path).unwrap();
    assert!(journal
        .append(&mut source, &verified, &f.execution.header, &f.execution.body)
        .is_err());
    assert_eq!(journal.mark().unwrap(), initial);
    assert_eq!(fs::read(&path).unwrap(), prefix);
    let mut alternate_genesis = f.headers[0].to_vec();
    alternate_genesis[36] ^= 1;
    let alternate_cursor = HeightCursor::from_genesis(native_id(&alternate_genesis), &alternate_genesis).unwrap();
    let mut alternate_source = SourceJournal::create(
        temp.path("same-domain-other-native"),
        f.registry.network(),
        f.registry.domain(),
        alternate_cursor,
        JournalLimits::default(),
    )
    .unwrap();
    // The exact same real execution proof cannot bypass native network/genesis
    // policy merely because the execution domain value is equal.
    assert!(journal
        .append(&mut alternate_source, &verified, &f.execution.header, &f.execution.body)
        .is_err());
    assert_eq!(journal.mark().unwrap(), initial);
    assert_eq!(fs::read(&path).unwrap(), prefix);
    let source_first = source
        .append(f.expected_source, f.position, &f.headers, &f.batch, &f.proofs)
        .unwrap();
    let mut wrong_body = f.execution.body.clone();
    wrong_body.deposits[0].recipient[0] ^= 1;
    let mut wrong_header = f.execution.header.clone();
    wrong_header.deposits_hash = wrong_body.deposits_hash();
    assert!(journal
        .append(&mut source, &verified, &wrong_header, &wrong_body)
        .is_err());
    assert_eq!(journal.mark().unwrap(), initial);
    assert_eq!(fs::read(&path).unwrap(), prefix);
    let accepted = journal
        .append(&mut source, &verified, &f.execution.header, &f.execution.body)
        .unwrap();
    assert_eq!(accepted.execution.number, 1);
    assert_eq!(accepted.next_sequence, 1);
    assert_eq!(accepted.last_source, source_first);
    assert_eq!(accepted.execution.state_root, f.execution.header.state_root);
    assert_eq!(journal.cursor().unwrap().head(), &f.execution.header);
    let complete = fs::read(&path).unwrap();
    // This alternative has the SAME native genesis/network/execution domain,
    // valid escrow proofs, and a LARGER source record count. Identity and record
    // monotonicity alone are insufficient: the previously used exact source mark
    // must occur in this handle's authenticated history too.
    let mut alternative = alternative_source(&temp, &f);
    assert!(alternative.mark().unwrap().records > accepted.last_source.records);
    let conflict = journal
        .append(&mut alternative, &verified, &f.execution.header, &f.execution.body)
        .unwrap_err();
    assert!(conflict.to_string().contains("SnapshotMissing"), "{conflict}");
    assert_eq!(journal.mark().unwrap(), accepted);
    assert_eq!(fs::read(&path).unwrap(), complete);
    assert!(journal
        .append(&mut source, &verified, &f.execution.header, &f.execution.body)
        .is_err());
    assert_eq!(journal.mark().unwrap(), accepted);
    assert_eq!(fs::read(&path).unwrap(), complete);
    drop(journal);
    drop(source);
    let mut source = SourceJournal::open(
        temp.path("source"),
        f.registry.network(),
        f.registry.domain(),
        cursor(&f),
        source_first,
        JournalLimits::default(),
    )
    .unwrap();
    // Recover a fully durable but not externally acknowledged execution suffix.
    // Source authority remains the independent exact SourceMark supplied above.
    let mut journal =
        SourceSettlementJournal::open(&path, policy(&f, program.identity()), &program, &mut source, initial).unwrap();
    assert_eq!(journal.mark().unwrap(), accepted);
    assert!(journal
        .append(&mut source, &verified, &f.execution.header, &f.execution.body)
        .is_err());
    drop(journal);
    for wrong_floor in [
        SourceSettlementJournalMark {
            next_sequence: 0,
            ..accepted
        },
        SourceSettlementJournalMark {
            last_source: source_genesis,
            ..accepted
        },
    ] {
        assert!(SourceSettlementJournal::open(
            &path,
            policy(&f, program.identity()),
            &program,
            &mut source,
            wrong_floor
        )
        .is_err());
    }
    // Advance the source independently with no new locks. Reopening execution
    // must authenticate the historical selected source under this newer tip.
    let mut header = vec![0u8; 304];
    header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    header[4..36].copy_from_slice(f.position.block().as_slice());
    header[100..108].copy_from_slice(&200u64.to_le_bytes());
    let checkpoint = FinalizedCheckpoint {
        block: native_id(&header),
        slot: 200,
    };
    let mut all_headers = f.headers.clone();
    all_headers.push(Bytes::from(header));
    let mut native_cursor = cursor(&f);
    let position = native_cursor.advance(checkpoint, &all_headers).unwrap();
    let mut next = f.batch.clone();
    next.previous = source_first.commitment;
    next.anchor = SourceAnchor {
        block: position.block(),
        slot: position.slot(),
        height: position.height(),
    };
    let source_second = source
        .append(
            next.commitment().unwrap(),
            position,
            &all_headers[1..],
            &next,
            &f.proofs,
        )
        .unwrap();
    drop(source);
    let mut source = SourceJournal::open(
        temp.path("source"),
        f.registry.network(),
        f.registry.domain(),
        cursor(&f),
        source_second,
        JournalLimits::default(),
    )
    .unwrap();
    let journal =
        SourceSettlementJournal::open(&path, policy(&f, program.identity()), &program, &mut source, accepted).unwrap();
    assert_eq!(journal.mark().unwrap(), accepted);
    drop(journal);
    // A checksum-correct frame pointing at another real source snapshot still
    // cannot authorize the existing proof's deposit body.
    let mut wrong_source = complete.clone();
    let payload_len = u32::from_be_bytes(wrong_source[prefix_len..prefix_len + 4].try_into().unwrap()) as usize;
    let payload_start = prefix_len + 4;
    wrong_source[payload_start..payload_start + MARK_BYTES].copy_from_slice(&source_genesis.encode());
    let checksum = keccak256(&wrong_source[payload_start..payload_start + payload_len]);
    wrong_source[payload_start + payload_len..payload_start + payload_len + 32].copy_from_slice(checksum.as_slice());
    fs::write(&path, &wrong_source).unwrap();
    assert!(
        SourceSettlementJournal::open(&path, policy(&f, program.identity()), &program, &mut source, initial).is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), wrong_source);
    fs::write(&path, &complete).unwrap();
    for cut in [prefix_len + 1, complete.len() - 1] {
        fs::write(&path, &complete[..cut]).unwrap();
        assert!(
            SourceSettlementJournal::open(&path, policy(&f, program.identity()), &program, &mut source, accepted)
                .is_err()
        );
    }
    fs::write(&path, &complete).unwrap();
    let mut journal =
        SourceSettlementJournal::open(&path, policy(&f, program.identity()), &program, &mut source, accepted).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"uncoordinated")
        .unwrap();
    let changed = fs::read(&path).unwrap();
    assert!(journal
        .append(&mut source, &verified, &f.execution.header, &f.execution.body)
        .is_err());
    assert!(journal.is_poisoned());
    assert!(journal.mark().is_err());
    assert!(journal.cursor().is_err());
    assert_eq!(fs::read(&path).unwrap(), changed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_execution_domain_does_not_replace_native_identity_or_genesis() {
    let f = source_fixture::source_contract().unwrap();
    let elf = fs::read(artifact(
        "BLOCH_SP1_ELF",
        "../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bloch-evm-synthetic-guest",
    ))
    .unwrap();
    let program = TrustedProgram::from_trusted_elf(Elf::from(elf)).await.unwrap();
    let temp = Temp::new();
    let mut native_header = f.headers[0].to_vec();
    native_header[36] ^= 1;
    let other_cursor = HeightCursor::from_genesis(native_id(&native_header), &native_header).unwrap();
    let mut other_source = SourceJournal::create(
        temp.path("other-native"),
        f.registry.network(),
        f.registry.domain(),
        other_cursor,
        JournalLimits::default(),
    )
    .unwrap();
    assert!(SourceSettlementJournal::create(
        temp.path("wrong-genesis"),
        policy(&f, program.identity()),
        &mut other_source
    )
    .is_err());
    assert!(!temp.path("wrong-genesis").exists());
    let mut other_domain = SourceJournal::create(
        temp.path("other-domain"),
        f.registry.network(),
        B256::repeat_byte(77),
        cursor(&f),
        JournalLimits::default(),
    )
    .unwrap();
    assert!(SourceSettlementJournal::create(
        temp.path("wrong-domain"),
        policy(&f, program.identity()),
        &mut other_domain
    )
    .is_err());
    let mut forged_genesis = f.execution.parent.clone();
    forged_genesis.state_root[0] ^= 1;
    assert!(SourceSettlementPolicy::new(
        ChainSpec::testnet(),
        f.registry.network(),
        f.registry.genesis(),
        f.registry.domain(),
        program.identity(),
        forged_genesis
    )
    .is_err());
}

#[test]
fn complete_retained_floor_codec_is_bounded_and_canonical() {
    use bloch_evm_sp1_host::settlement::SettlementMark;
    let mark = SourceSettlementJournalMark {
        execution: SettlementMark {
            number: 4,
            header_hash: B256::repeat_byte(1),
            state_root: B256::repeat_byte(2),
        },
        next_sequence: 5,
        last_source: SourceMark {
            records: 6,
            commitment: B256::repeat_byte(3),
            anchor: SourceAnchor {
                block: B256::repeat_byte(4),
                slot: 90,
                height: 7,
            },
            inbox_count: 8,
            inbox_root: B256::repeat_byte(5),
        },
    };
    let bytes = mark.encode();
    assert_eq!(bytes.len(), SOURCE_SETTLEMENT_MARK_BYTES);
    assert_eq!(SourceSettlementJournalMark::decode(&bytes).unwrap(), mark);
    for cut in 0..bytes.len() {
        assert!(SourceSettlementJournalMark::decode(&bytes[..cut]).is_err());
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(SourceSettlementJournalMark::decode(&extra).is_err());
}
