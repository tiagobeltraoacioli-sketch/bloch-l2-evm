// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::tests::support;
use crate::tests::{fixture, fixture_recipient};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "bloch-source-journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn journal(&self) -> PathBuf {
        self.0.join("journal")
    }
    fn source(&self) -> PathBuf {
        self.journal().join("SOURCE")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn create(temp: &Temp) -> SourceJournal {
    SourceJournal::create(
        temp.journal(),
        B256::repeat_byte(1),
        B256::repeat_byte(2),
        support::cursor(),
        JournalLimits::default(),
    )
    .unwrap()
}
fn open(temp: &Temp, mark: SourceMark) -> Result<SourceJournal, JournalError> {
    SourceJournal::open(
        temp.journal(),
        B256::repeat_byte(1),
        B256::repeat_byte(2),
        support::cursor(),
        mark,
        JournalLimits::default(),
    )
}
fn append(journal: &mut SourceJournal) -> SourceMark {
    let (batch, proofs) = fixture(2);
    journal
        .append(
            batch.commitment().unwrap(),
            support::position(1),
            &support::headers(1),
            &batch,
            &proofs,
        )
        .unwrap()
}
fn next(journal: &SourceJournal) -> (SourceBatch, Vec<InboxProof>) {
    let (mut batch, proofs) = fixture(2);
    batch.previous = journal.mark().unwrap().commitment;
    let position = support::position(2);
    batch.anchor = SourceAnchor {
        block: position.block(),
        slot: position.slot(),
        height: position.height(),
    };
    (batch, proofs)
}

#[test]
fn actual_files_replay_only_at_exact_external_tip_and_preserve_appendability() {
    let temp = Temp::new();
    let mut journal = create(&temp);
    let initial = journal.mark().unwrap();
    assert_eq!(SourceMark::decode(&initial.encode()).unwrap(), initial);
    let first = append(&mut journal);
    let expected_registry = journal.registry().unwrap().clone();
    assert!(matches!(open(&temp, first), Err(JournalError::Locked)));
    assert!(SourceJournal::create(
        temp.journal(),
        B256::repeat_byte(1),
        B256::repeat_byte(2),
        support::cursor(),
        JournalLimits::default()
    )
    .is_err());
    drop(journal);
    assert!(matches!(open(&temp, initial), Err(JournalError::Mark)));
    let mut journal = open(&temp, first).unwrap();
    assert_eq!(journal.registry().unwrap(), &expected_registry);
    let (batch, proofs) = next(&journal);
    let second = journal
        .append(
            batch.commitment().unwrap(),
            support::position(2),
            &support::headers(2)[1..],
            &batch,
            &proofs,
        )
        .unwrap();
    assert_eq!(second.records, 2);
    drop(journal);
    assert!(matches!(open(&temp, first), Err(JournalError::Mark)));
    assert_eq!(open(&temp, second).unwrap().mark().unwrap(), second);
}

#[test]
fn failed_verification_and_limits_do_not_write_or_advance() {
    let temp = Temp::new();
    let mut journal = create(&temp);
    let before = journal.mark().unwrap();
    let bytes = fs::read(temp.source()).unwrap();
    let (batch, mut proofs) = fixture(2);
    proofs[1].deposit.amount += 1;
    assert!(matches!(
        journal.append(
            batch.commitment().unwrap(),
            support::position(1),
            &support::headers(1),
            &batch,
            &proofs
        ),
        Err(JournalError::Verification(Error::Inclusion))
    ));
    assert_eq!(journal.mark().unwrap(), before);
    assert_eq!(fs::read(temp.source()).unwrap(), bytes);
    let (_, proofs) = fixture(2);
    journal.limits.bytes = FILE_HEADER as u64;
    assert!(matches!(
        journal.append(
            batch.commitment().unwrap(),
            support::position(1),
            &support::headers(1),
            &batch,
            &proofs
        ),
        Err(JournalError::Limit)
    ));
    assert_eq!(journal.mark().unwrap(), before);
    assert_eq!(fs::read(temp.source()).unwrap(), bytes);
    journal.limits = JournalLimits::default();
    append(&mut journal);
}

#[test]
fn missing_suffix_truncation_checksum_and_valid_rewrite_fail_closed() {
    let temp = Temp::new();
    let mut journal = create(&temp);
    let first = append(&mut journal);
    let prefix = fs::read(temp.source()).unwrap();
    let (batch, proofs) = next(&journal);
    let second = journal
        .append(
            batch.commitment().unwrap(),
            support::position(2),
            &support::headers(2)[1..],
            &batch,
            &proofs,
        )
        .unwrap();
    let complete = fs::read(temp.source()).unwrap();
    drop(journal);
    fs::write(temp.source(), &prefix).unwrap();
    assert!(matches!(open(&temp, second), Err(JournalError::Mark)));
    for cut in [0, 7, FILE_HEADER - 1, FILE_HEADER + 1, complete.len() - 1] {
        fs::write(temp.source(), &complete[..cut]).unwrap();
        assert!(open(&temp, second).is_err(), "cut {cut}");
    }
    let mut corrupt = complete;
    corrupt[FILE_HEADER + 16] ^= 1;
    fs::write(temp.source(), corrupt).unwrap();
    assert!(matches!(open(&temp, second), Err(JournalError::Format)));
    // A completely valid replacement inbox with recomputed frame checksum is
    // still refused by the independently retained original source mark.
    let (replacement, proofs) = fixture_recipient(2, Address::repeat_byte(77));
    let mut bytes = prefix[..FILE_HEADER].to_vec();
    bytes.extend_from_slice(&encode_frame(&support::headers(1), &replacement, &proofs).unwrap());
    fs::write(temp.source(), &bytes).unwrap();
    assert!(matches!(open(&temp, first), Err(JournalError::Mark)));
    assert_eq!(fs::read(temp.source()).unwrap(), bytes); // No silent repair.
}

#[test]
fn uncertain_partial_or_complete_publication_poison_until_exact_recovery() {
    for complete in [false, true] {
        let temp = Temp::new();
        let mut journal = create(&temp);
        let old = journal.mark().unwrap();
        let state = journal.registry().unwrap().clone();
        let (batch, proofs) = fixture(2);
        let result = journal.append_with(
            batch.commitment().unwrap(),
            support::position(1),
            &support::headers(1),
            &batch,
            &proofs,
            |file, bytes| {
                file.write_all(if complete { bytes } else { &bytes[..17] })?;
                Err(io::Error::other("injected publication/fsync failure"))
            },
        );
        assert!(matches!(result, Err(JournalError::CommitUncertain(_))));
        assert_eq!(journal.registry, state);
        assert_eq!(journal.mark, old);
        assert!(matches!(journal.registry(), Err(JournalError::Poisoned)));
        assert!(matches!(journal.mark(), Err(JournalError::Poisoned)));
        assert!(matches!(
            journal.append(
                batch.commitment().unwrap(),
                support::position(1),
                &support::headers(1),
                &batch,
                &proofs
            ),
            Err(JournalError::Poisoned)
        ));
        drop(journal);
        assert!(open(&temp, old).is_err());
        // Never infer a new trusted mark from these uncertain journal bytes.
    }
}

#[test]
fn canonical_frame_and_mark_bounds_precede_allocations() {
    let (batch, proofs) = fixture(2);
    let frame = encode_frame(&support::headers(1), &batch, &proofs).unwrap();
    let payload = &frame[12..frame.len() - 32];
    let record = decode_payload(payload).unwrap();
    assert_eq!(record.batch, batch);
    assert_eq!(record.proofs, proofs);
    for cut in 0..payload.len() {
        assert!(decode_payload(&payload[..cut]).is_err(), "prefix {cut}");
    }
    let mut trailing = payload.to_vec();
    trailing.push(0);
    assert!(decode_payload(&trailing).is_err());
    let mut oversized = payload.to_vec();
    oversized[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(decode_payload(&oversized), Err(JournalError::Limit)));
    let mark = SourceMark {
        records: 1,
        commitment: batch.commitment().unwrap(),
        anchor: batch.anchor,
        inbox_count: batch.count,
        inbox_root: batch.inbox_root,
    };
    assert_eq!(SourceMark::decode(&mark.encode()).unwrap(), mark);
    for cut in 0..MARK_BYTES {
        assert!(SourceMark::decode(&mark.encode()[..cut]).is_err());
    }
    let mut mark_bytes = mark.encode().to_vec();
    mark_bytes.push(0);
    assert!(SourceMark::decode(&mark_bytes).is_err());
    let temp = Temp::new();
    let journal = create(&temp);
    let initial = journal.mark().unwrap();
    drop(journal);
    let mut bytes = fs::read(temp.source()).unwrap();
    bytes.extend_from_slice(FRAME_TAG);
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(&[0; 32]);
    fs::write(temp.source(), bytes).unwrap();
    let expected = SourceMark { records: 1, ..initial };
    assert!(matches!(open(&temp, expected), Err(JournalError::Limit)));
}

#[test]
fn wrong_domain_symlinks_and_fifo_are_rejected_without_blocking() {
    use std::{ffi::CString, os::unix::fs::symlink};
    let temp = Temp::new();
    let journal = create(&temp);
    let mark = journal.mark().unwrap();
    drop(journal);
    assert!(matches!(
        SourceJournal::open(
            temp.journal(),
            B256::repeat_byte(1),
            B256::repeat_byte(9),
            support::cursor(),
            mark,
            JournalLimits::default()
        ),
        Err(JournalError::WrongGenesis)
    ));
    let original = temp.0.join("original");
    fs::rename(temp.source(), &original).unwrap();
    symlink(&original, temp.source()).unwrap();
    assert!(open(&temp, mark).is_err());
    fs::remove_file(temp.source()).unwrap();
    let name = CString::new(temp.source().as_os_str().as_encoded_bytes()).unwrap();
    // Only a new test-owned FIFO; never touch production paths.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(matches!(open(&temp, mark), Err(JournalError::Format)));
}

#[test]
fn external_length_changes_poison_before_any_ack_or_further_write() {
    for truncate in [false, true] {
        let temp = Temp::new();
        let mut journal = create(&temp);
        let old = journal.mark().unwrap();
        let state = journal.registry().unwrap().clone();
        if truncate {
            OpenOptions::new()
                .write(true)
                .open(temp.source())
                .unwrap()
                .set_len(8)
                .unwrap();
        } else {
            OpenOptions::new()
                .append(true)
                .open(temp.source())
                .unwrap()
                .write_all(b"uncoordinated write")
                .unwrap();
        }
        let bytes = fs::read(temp.source()).unwrap();
        let (batch, proofs) = fixture(2);
        assert!(matches!(
            journal.append(
                batch.commitment().unwrap(),
                support::position(1),
                &support::headers(1),
                &batch,
                &proofs
            ),
            Err(JournalError::StorageChanged)
        ));
        assert_eq!(journal.mark, old);
        assert_eq!(journal.registry, state);
        assert!(matches!(journal.mark(), Err(JournalError::Poisoned)));
        assert!(matches!(journal.registry(), Err(JournalError::Poisoned)));
        assert!(matches!(
            journal.append(
                batch.commitment().unwrap(),
                support::position(1),
                &support::headers(1),
                &batch,
                &proofs
            ),
            Err(JournalError::Poisoned)
        ));
        assert_eq!(fs::read(temp.source()).unwrap(), bytes);
    }
}

#[test]
fn replay_rederives_heights_and_rejects_divergent_native_path_even_with_matching_mark() {
    let temp = Temp::new();
    let mut journal = create(&temp);
    let (first, proofs) = fixture(0);
    journal
        .append(
            first.commitment().unwrap(),
            support::position(1),
            &support::headers(1),
            &first,
            &proofs,
        )
        .unwrap();
    let first_mark = journal.mark().unwrap();
    let bytes = fs::read(temp.source()).unwrap();
    drop(journal);
    let mut batch = first.clone();
    batch.previous = first_mark.commitment;
    let mut branch = support::headers(2);
    let mut one = branch[1].to_vec();
    one[36] = 99;
    branch[1] = one.into();
    let mut two = branch[2].to_vec();
    two[4..36].copy_from_slice(support::id(&branch[1]).as_slice());
    branch[2] = two.into();
    batch.anchor = SourceAnchor {
        block: support::id(&branch[2]),
        slot: 200,
        height: 2,
    };
    let fork_mark = SourceMark {
        records: 2,
        commitment: batch.commitment().unwrap(),
        anchor: batch.anchor,
        inbox_count: 0,
        inbox_root: batch.inbox_root,
    };
    let mut fork_file = bytes.clone();
    fork_file.extend_from_slice(&encode_frame(&branch[1..], &batch, &[]).unwrap());
    fs::write(temp.source(), &fork_file).unwrap();
    assert!(matches!(open(&temp, fork_mark), Err(JournalError::Height)));
    assert_eq!(fs::read(temp.source()).unwrap(), fork_file);
    batch.anchor = SourceAnchor {
        block: support::position(2).block(),
        slot: 200,
        height: 200,
    }; // Claimed slot-as-height.
    let wrong_height = SourceMark {
        records: 2,
        commitment: batch.commitment().unwrap(),
        anchor: batch.anchor,
        inbox_count: 0,
        inbox_root: batch.inbox_root,
    };
    let mut bad_file = bytes;
    bad_file.extend_from_slice(&encode_frame(&support::headers(2)[1..], &batch, &[]).unwrap());
    fs::write(temp.source(), &bad_file).unwrap();
    assert!(matches!(
        open(&temp, wrong_height),
        Err(JournalError::Verification(Error::Identity))
    ));
    assert_eq!(fs::read(temp.source()).unwrap(), bad_file);
}

#[test]
fn historical_snapshot_revalidates_tip_and_does_not_move_live_cursor() {
    let temp = Temp::new();
    let mut journal = create(&temp);
    let genesis_mark = journal.mark().unwrap();
    let genesis = journal.registry().unwrap().clone();
    let first = append(&mut journal);
    let first_registry = journal.registry().unwrap().clone();
    let (batch, proofs) = next(&journal);
    let second = journal
        .append(
            batch.commitment().unwrap(),
            support::position(2),
            &support::headers(2)[1..],
            &batch,
            &proofs,
        )
        .unwrap();
    assert_eq!(journal.snapshot_at(first).unwrap(), first_registry);
    assert_eq!(journal.snapshot_at(genesis_mark).unwrap(), genesis);
    assert_eq!(journal.mark().unwrap(), second);
    for wrong in [
        SourceMark { records: 999, ..first },
        SourceMark {
            inbox_count: 0,
            ..first
        },
        SourceMark {
            inbox_root: B256::repeat_byte(90),
            ..first
        },
        SourceMark {
            commitment: B256::repeat_byte(91),
            ..first
        },
    ] {
        assert!(matches!(journal.snapshot_at(wrong), Err(JournalError::SnapshotMissing)));
        assert_eq!(journal.mark().unwrap(), second);
    }
    // Historical reads seek on this file descriptor. O_APPEND must still add a
    // new frame rather than overwrite a prior record after these reads.
    let mut third = batch;
    third.previous = second.commitment;
    let position = support::position(3);
    third.anchor = SourceAnchor {
        block: position.block(),
        slot: position.slot(),
        height: position.height(),
    };
    let third_mark = journal
        .append(
            third.commitment().unwrap(),
            position,
            &support::headers(3)[2..],
            &third,
            &proofs,
        )
        .unwrap();
    assert_eq!(third_mark.records, 3);
    drop(journal);
    let mut reopened = open(&temp, third_mark).unwrap();
    assert_eq!(reopened.snapshot_at(first).unwrap(), first_registry);
    assert_eq!(reopened.mark().unwrap(), third_mark);
}

#[test]
fn historical_lookup_never_exposes_valid_prefix_of_untrusted_alternative_tip() {
    let temp = Temp::new();
    let mut journal = create(&temp);
    append(&mut journal);
    let (batch, proofs) = next(&journal);
    journal
        .append(
            batch.commitment().unwrap(),
            support::position(2),
            &support::headers(2)[1..],
            &batch,
            &proofs,
        )
        .unwrap();
    let original_len = fs::metadata(temp.source()).unwrap().len();
    let accepted = journal.registry().unwrap().clone();
    let (first, replacement_proofs) = fixture_recipient(2, Address::repeat_byte(88));
    let first_mark = SourceMark {
        records: 1,
        commitment: first.commitment().unwrap(),
        anchor: first.anchor,
        inbox_count: first.count,
        inbox_root: first.inbox_root,
    };
    let mut second = batch;
    second.previous = first_mark.commitment;
    second.inbox_root = first.inbox_root;
    second.locations = first.locations.clone();
    // Both alternative transitions are individually valid. Only their final
    // identity differs from the independently trusted tip held by this journal.
    let mut alternative = journal.bootstrap.clone();
    alternative
        .apply(
            first_mark.commitment,
            support::position(1),
            &support::headers(1),
            &first,
            &replacement_proofs,
        )
        .unwrap();
    alternative
        .apply(
            second.commitment().unwrap(),
            support::position(2),
            &support::headers(2)[1..],
            &second,
            &replacement_proofs,
        )
        .unwrap();
    let mut bytes = fs::read(temp.source()).unwrap()[..FILE_HEADER].to_vec();
    bytes.extend_from_slice(&encode_frame(&support::headers(1), &first, &replacement_proofs).unwrap());
    bytes.extend_from_slice(&encode_frame(&support::headers(2)[1..], &second, &replacement_proofs).unwrap());
    assert_eq!(bytes.len() as u64, original_len);
    fs::write(temp.source(), &bytes).unwrap();
    assert!(matches!(journal.snapshot_at(first_mark), Err(JournalError::Mark)));
    assert_eq!(journal.registry, accepted);
    assert!(matches!(journal.registry(), Err(JournalError::Poisoned)));
    assert!(matches!(journal.snapshot_at(first_mark), Err(JournalError::Poisoned)));
    assert_eq!(fs::read(temp.source()).unwrap(), bytes);
}

#[test]
fn historical_lookup_detects_changed_file_length_and_poison() {
    let temp = Temp::new();
    let mut journal = create(&temp);
    let first = append(&mut journal);
    OpenOptions::new()
        .append(true)
        .open(temp.source())
        .unwrap()
        .write_all(b"extra")
        .unwrap();
    assert!(matches!(journal.snapshot_at(first), Err(JournalError::StorageChanged)));
    assert!(matches!(journal.mark(), Err(JournalError::Poisoned)));
}
