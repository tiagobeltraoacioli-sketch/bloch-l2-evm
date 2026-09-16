// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sparse preparation of protocol writes against a mutable-only database.
use crate::{executor::BlockExecutionError, state::info_exists};
#[cfg(not(feature = "std"))]
use alloc::format;
use alloy_primitives::{Address, B256, KECCAK256_EMPTY as KECCAK_EMPTY, U256};
use core::cell::RefCell;
use revm::{
    database::{AccountState, CacheDB},
    state::{Account, AccountInfo, Bytecode, EvmState, EvmStorageSlot},
    Database, DatabaseCommit, DatabaseRef,
};

/// Read bridge used only while staging; no database reference escapes preparation.
pub(crate) struct MutableDatabaseRef<'a, DB>(RefCell<&'a mut DB>);
impl<DB: Database> DatabaseRef for MutableDatabaseRef<'_, DB> {
    type Error = DB::Error;
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.0.borrow_mut().basic(address)
    }
    fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
        self.0.borrow_mut().code_by_hash(hash)
    }
    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.0.borrow_mut().storage(address, slot)
    }
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.0.borrow_mut().block_hash(number)
    }
}

/// Read-complete protocol changes, applied only to the unchanged preparation state.
#[derive(Debug)]
pub(crate) struct PreparedProtocolChanges {
    deletions: EvmState,
    writes: EvmState,
}
impl PreparedProtocolChanges {
    /// Commit without reads. Deletion precedes recreation to retain storage wipes.
    pub(crate) fn commit(self, db: &mut impl DatabaseCommit) {
        if !self.deletions.is_empty() {
            db.commit(self.deletions);
        }
        if !self.writes.is_empty() {
            db.commit(self.writes);
        }
    }
}
fn db_error(error: impl core::fmt::Debug) -> BlockExecutionError {
    BlockExecutionError::Database {
        detail: format!("{error:?}"),
    }
}
fn normalized(mut info: AccountInfo) -> AccountInfo {
    if info.code_hash.is_zero() {
        info.code_hash = KECCAK_EMPTY;
    }
    info.code = None;
    info
}

/// Execute existing CacheDB protocol helpers on a disposable sparse overlay.
/// All fallible conversion reads finish before returning owned commit-ready maps.
/// Reads may warm the backing cache; no writes are committed on error or drop.
/// Unchanged canonical accounts are omitted. Loaded EIP-161-empty records are
/// pruned, matching the core overlay merge even when they were only read.
/// Block-hash cache entries are not account transitions; return them through `T`
/// if the caller needs them for its portable EVM cache.
pub(crate) fn stage_protocol<'a, DB: Database, T>(
    db: &'a mut DB,
    operation: impl FnOnce(&mut CacheDB<MutableDatabaseRef<'a, DB>>) -> Result<T, BlockExecutionError>,
) -> Result<(PreparedProtocolChanges, T), BlockExecutionError> {
    let mut overlay = CacheDB::new(MutableDatabaseRef(RefCell::new(db)));
    let value = operation(&mut overlay)?;
    let mut changes = PreparedProtocolChanges {
        deletions: EvmState::default(),
        writes: EvmState::default(),
    };
    for (address, entry) in &overlay.cache.accounts {
        let original = overlay.db.basic_ref(*address).map_err(db_error)?;
        let present = entry.account_state != AccountState::NotExisting && info_exists(&entry.info);
        let wipe = entry.account_state == AccountState::StorageCleared
            || original.as_ref().is_some_and(|info| !info_exists(info));
        if !present {
            if let Some(info) = original {
                let mut account = Account::from(info);
                account.mark_touch();
                account.mark_selfdestruct();
                changes.deletions.insert(*address, account);
            }
            continue;
        }
        let mut account = Account::from(entry.info.clone());
        let mut changed =
            original.as_ref().map(|info| normalized(info.clone())) != Some(normalized(entry.info.clone()));
        for (slot, present_value) in &entry.storage {
            let original_value = if original.is_some() {
                overlay.db.storage_ref(*address, *slot).map_err(db_error)?
            } else {
                U256::ZERO
            };
            if wipe {
                if !present_value.is_zero() {
                    // The preceding deletion/creation resets storage. The original
                    // value for the recreation transition is consequently zero.
                    account.storage.insert(
                        *slot,
                        EvmStorageSlot::new_changed(U256::ZERO, *present_value, revm::state::TransactionId::ZERO),
                    );
                }
            } else if original_value != *present_value {
                account.storage.insert(
                    *slot,
                    EvmStorageSlot::new_changed(original_value, *present_value, revm::state::TransactionId::ZERO),
                );
                changed = true;
            }
        }
        if !changed && !wipe {
            continue;
        }
        if entry.info.code_hash != KECCAK_EMPTY
            && !entry.info.code_hash.is_zero()
            && original.as_ref().map(|info| info.code_hash) != Some(entry.info.code_hash)
        {
            let code = overlay
                .cache
                .contracts
                .get(&entry.info.code_hash)
                .or(entry.info.code.as_ref())
                .ok_or_else(|| db_error("protocol code missing from staged overlay"))?;
            if code.hash_slow() != entry.info.code_hash {
                return Err(db_error("protocol code hash mismatch"));
            }
            account.info.code = Some(code.clone());
        }
        account.mark_touch();
        if wipe || original.is_none() {
            if let Some(info) = original {
                let mut deletion = Account::from(info);
                deletion.mark_touch();
                deletion.mark_selfdestruct();
                changes.deletions.insert(*address, deletion);
            }
            account.mark_created();
        }
        changes.writes.insert(*address, account);
    }
    Ok((changes, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{beacon_roots_bytecode, ensure_system_account};
    use revm::database::InMemoryDB;
    const ADDRESS: Address = Address::repeat_byte(23);
    const OTHER: Address = Address::repeat_byte(24);
    #[derive(Debug)]
    struct Unavailable;
    impl core::fmt::Display for Unavailable {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("fixture unavailable")
        }
    }
    impl core::error::Error for Unavailable {}
    impl revm::database_interface::DBErrorMarker for Unavailable {}
    struct MutableOnly {
        inner: InMemoryDB,
        reads: usize,
        commits: usize,
        fail: bool,
    }
    impl Database for MutableOnly {
        type Error = Unavailable;
        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            self.reads += 1;
            if self.fail {
                return Err(Unavailable);
            }
            Ok(self.inner.basic(address).unwrap())
        }
        fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
            self.reads += 1;
            Ok(self.inner.code_by_hash(hash).unwrap())
        }
        fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
            self.reads += 1;
            if self.fail {
                return Err(Unavailable);
            }
            Ok(self.inner.storage(address, slot).unwrap())
        }
        fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
            self.reads += 1;
            Ok(self.inner.block_hash(number).unwrap())
        }
    }
    impl DatabaseCommit for MutableOnly {
        fn commit(&mut self, state: EvmState) {
            self.commits += 1;
            self.inner.commit(state)
        }
    }
    fn db() -> MutableOnly {
        let mut inner = InMemoryDB::default();
        inner.insert_account_info(
            ADDRESS,
            AccountInfo {
                balance: U256::from(9),
                ..Default::default()
            },
        );
        inner
            .insert_account_storage(ADDRESS, U256::from(1), U256::from(11))
            .unwrap();
        inner
            .insert_account_storage(ADDRESS, U256::from(2), U256::from(22))
            .unwrap();
        MutableOnly {
            inner,
            reads: 0,
            commits: 0,
            fail: false,
        }
    }
    #[test]
    fn late_error_and_dropped_changes_do_not_commit_and_commit_never_reads() {
        let mut db = db();
        let error = stage_protocol(&mut db, |overlay| {
            overlay
                .insert_account_storage(ADDRESS, U256::from(1), U256::ZERO)
                .map_err(db_error)?;
            Err::<(), _>(db_error("late protocol failure"))
        })
        .unwrap_err();
        assert!(matches!(error, BlockExecutionError::Database { .. }));
        assert_eq!(db.commits, 0);
        assert_eq!(db.inner.storage(ADDRESS, U256::from(1)).unwrap(), U256::from(11));
        let (prepared, ()) = stage_protocol(&mut db, |overlay| {
            overlay
                .insert_account_storage(ADDRESS, U256::from(1), U256::ZERO)
                .map_err(db_error)
        })
        .unwrap();
        drop(prepared);
        assert_eq!(db.commits, 0);
        assert_eq!(db.inner.storage(ADDRESS, U256::from(1)).unwrap(), U256::from(11));
        let (prepared, ()) = stage_protocol(&mut db, |overlay| {
            overlay
                .insert_account_storage(ADDRESS, U256::from(1), U256::ZERO)
                .map_err(db_error)
        })
        .unwrap();
        let slot = &prepared.writes[&ADDRESS].storage[&U256::from(1)];
        assert_eq!(slot.original_value(), U256::from(11));
        assert_eq!(slot.present_value(), U256::ZERO);
        let reads = db.reads;
        db.fail = true;
        prepared.commit(&mut db);
        assert_eq!(db.reads, reads);
        assert_eq!(db.commits, 1);
        assert_eq!(db.inner.storage(ADDRESS, U256::from(1)).unwrap(), U256::ZERO);
        assert_eq!(db.inner.storage(ADDRESS, U256::from(2)).unwrap(), U256::from(22));
    }
    #[test]
    fn conversion_read_failure_never_publishes_staged_writes() {
        let mut db = db();
        let result = stage_protocol(&mut db, |overlay| {
            overlay
                .insert_account_storage(ADDRESS, U256::from(1), U256::ZERO)
                .map_err(db_error)?;
            // Simulate provider loss after the helper finished but before the
            // sparse conversion has read original information.
            overlay.db.0.borrow_mut().fail = true;
            Ok(())
        });
        assert!(matches!(result, Err(BlockExecutionError::Database { .. })));
        assert_eq!(db.commits, 0);
        assert_eq!(db.inner.storage(ADDRESS, U256::from(1)).unwrap(), U256::from(11));
    }

    #[test]
    fn read_only_accounts_and_equal_slots_are_omitted() {
        let mut db = db();
        let (prepared, ()) = stage_protocol(&mut db, |overlay| {
            overlay.basic(ADDRESS).map_err(db_error)?;
            overlay.basic(OTHER).map_err(db_error)?;
            overlay.storage(ADDRESS, U256::from(1)).map_err(db_error)?;
            Ok(())
        })
        .unwrap();
        assert!(prepared.deletions.is_empty());
        assert!(prepared.writes.is_empty());
        prepared.commit(&mut db);
        assert_eq!(db.commits, 0);
    }
    #[test]
    fn explicit_wipe_preserves_equal_replacement_and_discards_unknown_slots() {
        let mut db = db();
        let (prepared, ()) = stage_protocol(&mut db, |overlay| {
            let entry = overlay.load_account(ADDRESS).map_err(db_error)?;
            entry.account_state = AccountState::StorageCleared;
            entry.storage.insert(U256::from(1), U256::from(11));
            Ok(())
        })
        .unwrap();
        assert!(prepared.deletions[&ADDRESS].is_selfdestructed());
        assert!(prepared.writes[&ADDRESS].is_created());
        prepared.commit(&mut db);
        assert_eq!(db.commits, 2);
        assert_eq!(db.inner.storage(ADDRESS, U256::from(1)).unwrap(), U256::from(11));
        assert_eq!(db.inner.storage(ADDRESS, U256::from(2)).unwrap(), U256::ZERO);
    }
    #[test]
    fn loaded_empty_record_is_pruned_like_the_core_overlay_merge() {
        let mut db = db();
        db.inner.insert_account_info(OTHER, AccountInfo::default());
        db.inner
            .insert_account_storage(OTHER, U256::from(9), U256::from(99))
            .unwrap();
        let (prepared, ()) = stage_protocol(&mut db, |overlay| {
            overlay.basic(OTHER).map_err(db_error)?;
            Ok(())
        })
        .unwrap();
        assert!(prepared.writes.is_empty());
        assert!(prepared.deletions[&OTHER].is_selfdestructed());
        prepared.commit(&mut db);
        assert!(db.inner.basic(OTHER).unwrap().is_none());
        assert_eq!(db.inner.storage(OTHER, U256::from(9)).unwrap(), U256::ZERO);
    }

    #[test]
    fn absent_system_account_installs_actual_code_and_storage() {
        let mut db = db();
        let code = beacon_roots_bytecode();
        let mut absent = revm::database::DbAccount::new_not_existing();
        absent.storage.insert(U256::from(9), U256::from(99));
        db.inner.cache.accounts.insert(OTHER, absent);
        let (prepared, ()) = stage_protocol(&mut db, |overlay| {
            ensure_system_account(overlay, OTHER, Some(&code)).map_err(db_error)?;
            overlay
                .insert_account_storage(OTHER, U256::from(3), U256::from(33))
                .map_err(db_error)
        })
        .unwrap();
        assert!(prepared.writes[&OTHER].is_created());
        prepared.commit(&mut db);
        let info = db.inner.basic(OTHER).unwrap().unwrap();
        assert_eq!(info.nonce, 1);
        assert_eq!(info.code_hash, code.hash_slow());
        assert_eq!(db.inner.code_by_hash(info.code_hash).unwrap(), code);
        assert_eq!(db.inner.storage(OTHER, U256::from(3)).unwrap(), U256::from(33));
        assert_eq!(db.inner.storage(OTHER, U256::from(9)).unwrap(), U256::ZERO);
    }
    #[test]
    fn empty_backing_storage_is_not_inherited_and_deletion_is_explicit() {
        let mut db = db();
        db.inner.insert_account_info(OTHER, AccountInfo::default());
        db.inner
            .insert_account_storage(OTHER, U256::from(9), U256::from(99))
            .unwrap();
        let (prepared, ()) = stage_protocol(&mut db, |overlay| {
            ensure_system_account(overlay, OTHER, None).map_err(db_error)?;
            overlay.load_account(ADDRESS).map_err(db_error)?.account_state = AccountState::NotExisting;
            Ok(())
        })
        .unwrap();
        prepared.commit(&mut db);
        assert!(db.inner.basic(ADDRESS).unwrap().is_none());
        assert_eq!(db.inner.basic(OTHER).unwrap().unwrap().nonce, 1);
        assert_eq!(db.inner.storage(OTHER, U256::from(9)).unwrap(), U256::ZERO);
    }
}
