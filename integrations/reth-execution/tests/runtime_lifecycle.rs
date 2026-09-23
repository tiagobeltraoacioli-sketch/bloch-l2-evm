// SPDX-License-Identifier: MIT OR Apache-2.0
use alloy_primitives::B256;
use bloch_reth_execution::{
    acknowledge_recovered_runtime, initialize_runtime_record, read_runtime_record, read_runtime_record_with_floor,
    runtime_receipt_tip, DurableHead, RuntimeIdentity, RuntimeLease, RuntimeReceiptFloor, RuntimeStatus,
    SettlementCursor,
};
use std::fs;

fn identity() -> RuntimeIdentity {
    RuntimeIdentity {
        chain_id: 700_771,
        genesis_hash: B256::repeat_byte(0x11),
    }
}

fn head(number: u64) -> DurableHead {
    DurableHead {
        number,
        hash: B256::repeat_byte(number as u8 + 1),
        state_root: B256::repeat_byte(number as u8 + 2),
        receipts_root: B256::repeat_byte(number as u8 + 3),
        settlement: SettlementCursor {
            l1_height: 100 + number,
            l1_block_hash: B256::repeat_byte(number as u8 + 4),
            event_index: number as u32,
        },
    }
}

#[test]
fn clean_start_checkpoint_shutdown_and_restart_are_durable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runtime.state");
    initialize_runtime_record(&path, identity(), head(0)).unwrap();
    let mut lease = RuntimeLease::acquire(&path, identity(), head(0)).unwrap();
    assert_eq!(read_runtime_record(&path).unwrap().generation, 1);
    assert_eq!(read_runtime_record(&path).unwrap().status, RuntimeStatus::Running);
    lease.checkpoint(head(1)).unwrap();
    assert_eq!(read_runtime_record(&path).unwrap().generation, 2);
    assert_eq!(read_runtime_record(&path).unwrap().head, head(1));
    assert!(lease.checkpoint(head(3)).is_err());
    let mut conflicting_cursor = head(2);
    conflicting_cursor.settlement.l1_height = head(1).settlement.l1_height;
    assert!(lease.checkpoint(conflicting_cursor).is_err());
    assert!(lease.shutdown(head(0)).is_err());

    // A failed shutdown consumes the lease but deliberately leaves crash evidence.
    assert_eq!(read_runtime_record(&path).unwrap().status, RuntimeStatus::Running);
    assert!(RuntimeLease::acquire(&path, identity(), head(1)).is_err());
    acknowledge_recovered_runtime(&path, identity(), head(1)).unwrap();
    let lease = RuntimeLease::acquire(&path, identity(), head(1)).unwrap();
    lease.shutdown(head(1)).unwrap();
    assert_eq!(read_runtime_record(&path).unwrap().generation, 5);
    assert_eq!(read_runtime_record(&path).unwrap().status, RuntimeStatus::Clean);
    assert!(!directory.path().join("runtime.state.lock").exists());
}

#[cfg(unix)]
#[test]
fn symlink_hardlink_and_unsafe_parent_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runtime.state");
    initialize_runtime_record(&path, identity(), head(0)).unwrap();

    let hardlink = directory.path().join("runtime-hardlink.state");
    fs::hard_link(&path, &hardlink).unwrap();
    assert!(read_runtime_record(&path).is_err());
    fs::remove_file(hardlink).unwrap();

    let symlink_path = directory.path().join("runtime-symlink.state");
    symlink(&path, &symlink_path).unwrap();
    assert!(read_runtime_record(&symlink_path).is_err());

    let unsafe_directory = directory.path().join("unsafe");
    fs::create_dir(&unsafe_directory).unwrap();
    fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(initialize_runtime_record(unsafe_directory.join("runtime.state"), identity(), head(0)).is_err());
}

#[test]
fn crash_recovery_rejects_identity_or_head_divergence_without_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runtime.state");
    initialize_runtime_record(&path, identity(), head(4)).unwrap();
    let lease = RuntimeLease::acquire(&path, identity(), head(4)).unwrap();
    drop(lease); // Deliberate simulated crash: Drop must not clean anything.
    let before = fs::read(&path).unwrap();
    let wrong_identity = RuntimeIdentity {
        chain_id: 8_400,
        ..identity()
    };
    assert!(acknowledge_recovered_runtime(&path, wrong_identity, head(4)).is_err());
    assert!(acknowledge_recovered_runtime(&path, identity(), head(5)).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(directory.path().join("runtime.state.lock").exists());
    acknowledge_recovered_runtime(&path, identity(), head(4)).unwrap();
    assert_eq!(read_runtime_record(&path).unwrap().status, RuntimeStatus::Clean);
}

#[test]
fn corruption_duplicate_owner_and_nonexclusive_initialization_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runtime.state");
    initialize_runtime_record(&path, identity(), head(0)).unwrap();
    assert!(initialize_runtime_record(&path, identity(), head(0)).is_err());
    let lease = RuntimeLease::acquire(&path, identity(), head(0)).unwrap();
    assert!(RuntimeLease::acquire(&path, identity(), head(0)).is_err());
    drop(lease);
    acknowledge_recovered_runtime(&path, identity(), head(0)).unwrap();

    let mut bytes = fs::read(&path).unwrap();
    let position = bytes.iter().position(|byte| *byte == b'7').unwrap();
    bytes[position] = b'8';
    fs::write(&path, bytes).unwrap();
    assert!(read_runtime_record(&path).is_err());
    assert!(RuntimeLease::acquire(&path, identity(), head(0)).is_err());
}

#[test]
fn recovery_completes_a_clean_record_with_a_leftover_lock() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runtime.state");
    initialize_runtime_record(&path, identity(), head(0)).unwrap();
    let lock = directory.path().join("runtime.state.lock");
    fs::write(&lock, b"simulated shutdown interruption").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    acknowledge_recovered_runtime(&path, identity(), head(0)).unwrap();
    assert!(!lock.exists());
    assert_eq!(read_runtime_record(&path).unwrap().status, RuntimeStatus::Clean);
}

fn receipt_frames(bytes: &[u8]) -> (&[u8], Vec<Vec<u8>>) {
    const HEADER: &[u8] = b"BLOCH-L2-RUNTIME-RECEIPTS-V1\n";
    assert!(bytes.starts_with(HEADER));
    let mut offset = HEADER.len();
    let mut frames = Vec::new();
    while offset < bytes.len() {
        let start = offset;
        let length_offset = start + 8 + 32;
        let length = u32::from_be_bytes(bytes[length_offset..length_offset + 4].try_into().unwrap()) as usize;
        offset = length_offset + 4 + length + 32;
        frames.push(bytes[start..offset].to_vec());
    }
    (HEADER, frames)
}

fn three_receipt_fixture() -> (tempfile::TempDir, std::path::PathBuf, Vec<u8>, RuntimeReceiptFloor) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runtime.state");
    initialize_runtime_record(&path, identity(), head(0)).unwrap();
    let lease = RuntimeLease::acquire(&path, identity(), head(0)).unwrap();
    drop(lease);
    acknowledge_recovered_runtime(&path, identity(), head(0)).unwrap();
    let floor = runtime_receipt_tip(&path, None).unwrap();
    let bytes = fs::read(directory.path().join("runtime.state.receipts")).unwrap();
    (directory, path, bytes, floor)
}

#[test]
fn receipt_truncation_gap_reorder_and_fork_fail_closed() {
    let (directory, path, valid, _) = three_receipt_fixture();
    let receipts = directory.path().join("runtime.state.receipts");
    let (header, frames) = receipt_frames(&valid);
    assert_eq!(frames.len(), 3);

    fs::write(&receipts, &valid[..valid.len() - 1]).unwrap();
    assert!(read_runtime_record(&path).is_err(), "truncated digest must fail");

    let gap = [header, frames[0].as_slice(), frames[2].as_slice()].concat();
    fs::write(&receipts, gap).unwrap();
    assert!(read_runtime_record(&path).is_err(), "missing sequence must fail");

    let reordered = [header, frames[0].as_slice(), frames[2].as_slice(), frames[1].as_slice()].concat();
    fs::write(&receipts, reordered).unwrap();
    assert!(read_runtime_record(&path).is_err(), "reordered receipts must fail");

    let mut fork = valid.clone();
    let second_start = header.len() + frames[0].len();
    fork[second_start + 8] ^= 1; // Change the linked previous digest.
    fs::write(&receipts, fork).unwrap();
    assert!(read_runtime_record(&path).is_err(), "forked previous digest must fail");
}

#[test]
fn external_floor_detects_valid_old_record_and_log_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runtime.state");
    let receipts = directory.path().join("runtime.state.receipts");
    initialize_runtime_record(&path, identity(), head(0)).unwrap();
    let old_record = fs::read(&path).unwrap();
    let old_receipts = fs::read(&receipts).unwrap();

    let lease = RuntimeLease::acquire(&path, identity(), head(0)).unwrap();
    drop(lease);
    acknowledge_recovered_runtime(&path, identity(), head(0)).unwrap();
    let floor = runtime_receipt_tip(&path, None).unwrap();
    assert_eq!(floor.sequence, 2);

    fs::write(&path, old_record).unwrap();
    assert!(
        read_runtime_record(&path).is_err(),
        "snapshot-only rollback must disagree with receipt tip"
    );
    fs::write(&receipts, old_receipts).unwrap();
    assert_eq!(read_runtime_record(&path).unwrap().generation, 0);
    assert!(read_runtime_record_with_floor(&path, floor).is_err());
    assert!(RuntimeLease::acquire_with_floor(&path, identity(), head(0), floor).is_err());

    let wrong = RuntimeReceiptFloor {
        digest: B256::repeat_byte(0xee),
        ..runtime_receipt_tip(&path, None).unwrap()
    };
    assert!(read_runtime_record_with_floor(&path, wrong).is_err());
}
