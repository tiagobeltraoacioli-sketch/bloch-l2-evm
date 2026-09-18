// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sparse conversion of an executed Bloch overlay into Reth's revm bundle.

use alloy_primitives::{Address, B256, U256};
use bloch_l2_evm::DatabaseBlockExecution;
use reth_revm::revm::{
    database::{
        states::{
            bundle_state::BundleRetention, AccountStatus, BundleState, StorageSlot, TransitionAccount, TransitionState,
        },
        AccountState, CacheDB,
    },
    primitives::KECCAK_EMPTY,
    state::AccountInfo,
    DatabaseRef,
};
use std::fmt;

/// Conversion failed before any state was published or written to the provider.
#[derive(Debug)]
pub enum BundleError<E> {
    /// Reading the original snapshot failed.
    Database(E),
    /// A changed nonempty code hash had no corresponding execution bytecode.
    MissingCode { address: Address, hash: B256 },
    /// Cached bytecode does not match its declared hash.
    CodeHashMismatch { address: Address, hash: B256 },
}

impl<E: fmt::Display> fmt::Display for BundleError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "original state read failed: {error}"),
            Self::MissingCode { address, hash } => write!(f, "missing execution bytecode {hash} for {address}"),
            Self::CodeHashMismatch { address, hash } => {
                write!(f, "execution bytecode hash mismatch {hash} for {address}")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for BundleError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

/// Convert one successful execution into one block of state changes and reverts.
///
/// The backing database must remain the same immutable pre-execution snapshot.
/// Only cached accounts and cached slots are visited; unchanged reads are omitted.
/// Wipes preserve Reth's storage-wipe markers rather than enumerating unknown old
/// slots. Persist reverts before state changes through Reth's state writer: it
/// obtains those old slots from the original database. This sparse bundle alone
/// is not a complete archive of deleted storage, an authenticated root or a commit.
pub fn execution_bundle<DB: DatabaseRef>(
    execution: &DatabaseBlockExecution<DB>,
) -> Result<BundleState, BundleError<DB::Error>> {
    overlay_bundle(execution.overlay())
}

fn normalized_info(mut info: AccountInfo) -> AccountInfo {
    if info.code_hash == B256::ZERO {
        info.code_hash = KECCAK_EMPTY;
    }
    info
}

// Matches the execution core's merge_account/info_exists rule, including entries
// flagged None that were changed by direct system-account storage writes.
fn exists(info: &AccountInfo) -> bool {
    info.nonce != 0 || !info.balance.is_zero() || !(info.code_hash == KECCAK_EMPTY || info.code_hash == B256::ZERO)
}

fn overlay_bundle<DB: DatabaseRef>(overlay: &CacheDB<DB>) -> Result<BundleState, BundleError<DB::Error>> {
    let mut transitions = TransitionState::default();
    for (&address, account) in &overlay.cache.accounts {
        let previous = overlay
            .db
            .basic_ref(address)
            .map_err(BundleError::Database)?
            .map(normalized_info);
        let previous_status = match &previous {
            None => AccountStatus::LoadedNotExisting,
            Some(info) if !exists(info) => AccountStatus::LoadedEmptyEIP161,
            Some(_) => AccountStatus::Loaded,
        };
        let mut present = (account.account_state != AccountState::NotExisting && exists(&account.info))
            .then(|| normalized_info(account.info.clone()));
        // merge_account also discards storage belonging to an EIP-161-empty
        // backing record rather than inheriting those noncanonical old slots.
        let wipe = account.account_state == AccountState::StorageCleared
            || previous.as_ref().is_some_and(|info| !exists(info));
        let mut storage = Default::default();
        let status = if let Some(info) = present.as_mut() {
            let mut slots = reth_revm::revm::database::states::StorageWithOriginalValues::default();
            for (&slot, &value) in &account.storage {
                // Wiped storage starts at zero. Equal nonzero values still need
                // writing after the wipe; zero values need no replacement entry.
                if wipe && value.is_zero() {
                    continue;
                }
                let original = if previous.is_some() {
                    overlay.db.storage_ref(address, slot).map_err(BundleError::Database)?
                } else {
                    U256::ZERO
                };
                if wipe || original != value {
                    slots.insert(slot, StorageSlot::new_changed(original, value));
                }
            }
            if !wipe && previous.as_ref() == Some(info) && slots.is_empty() {
                continue;
            }
            if info.code_hash != KECCAK_EMPTY && previous.as_ref().map(|old| old.code_hash) != Some(info.code_hash) {
                let code = overlay
                    .cache
                    .contracts
                    .get(&info.code_hash)
                    .or(info.code.as_ref())
                    .ok_or(BundleError::MissingCode {
                        address,
                        hash: info.code_hash,
                    })?;
                if code.hash_slow() != info.code_hash {
                    return Err(BundleError::CodeHashMismatch {
                        address,
                        hash: info.code_hash,
                    });
                }
                info.code = Some(code.clone());
            }
            storage = slots;
            if wipe && previous.is_some() {
                AccountStatus::DestroyedChanged
            } else if previous.is_none() {
                AccountStatus::InMemoryChange
            } else {
                AccountStatus::Changed
            }
        } else {
            if previous.is_none() {
                continue;
            }
            AccountStatus::Destroyed
        };
        transitions.transitions.insert(
            address,
            TransitionAccount {
                info: present,
                status,
                previous_info: previous,
                previous_status,
                storage,
                storage_was_destroyed: wipe || status == AccountStatus::Destroyed,
            },
        );
    }
    let mut bundle = BundleState::default();
    bundle.apply_transitions_and_create_reverts(transitions, BundleRetention::Reverts);
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_revm::revm::{
        bytecode::Bytecode,
        database::{states::OriginalValuesKnown, InMemoryDB},
    };
    const ADDRESS: Address = Address::repeat_byte(7);

    fn backing() -> InMemoryDB {
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            ADDRESS,
            AccountInfo {
                balance: U256::from(1),
                nonce: 1,
                ..Default::default()
            },
        );
        db.insert_account_storage(ADDRESS, U256::from(1), U256::from(7))
            .unwrap();
        db.insert_account_storage(ADDRESS, U256::from(2), U256::from(99))
            .unwrap();
        db
    }

    #[test]
    fn none_flag_writes_zero_tombstone_and_preserves_original_revert() {
        let mut overlay = CacheDB::new(backing());
        overlay
            .insert_account_storage(ADDRESS, U256::from(1), U256::ZERO)
            .unwrap();
        assert_eq!(overlay.cache.accounts[&ADDRESS].account_state, AccountState::None);
        let bundle = overlay_bundle(&overlay).unwrap();
        let account = &bundle.state[&ADDRESS];
        assert_eq!(account.status, AccountStatus::Changed);
        assert_eq!(account.storage.len(), 1);
        assert_eq!(
            account.storage[&U256::from(1)],
            StorageSlot::new_changed(U256::from(7), U256::ZERO)
        );
        assert_eq!(
            account.storage_slot(U256::from(2)),
            None,
            "untouched storage falls through to backing"
        );
        let (plain, reverts) = bundle.to_plain_state_and_reverts(OriginalValuesKnown::Yes);
        assert!(!plain.storage[0].wipe_storage);
        assert_eq!(plain.storage[0].storage, vec![(U256::from(1), U256::ZERO)]);
        assert!(!reverts.storage[0][0].wiped);
        assert_eq!(
            reverts.storage[0][0].storage_revert[0].1.to_previous_value(),
            U256::from(7)
        );
    }

    #[test]
    fn storage_wipe_keeps_equal_post_value_and_marks_unknown_storage_for_recovery() {
        let mut overlay = CacheDB::new(backing());
        overlay
            .replace_account_storage(ADDRESS, [(U256::from(1), U256::from(7))].into_iter().collect())
            .unwrap();
        let bundle = overlay_bundle(&overlay).unwrap();
        let account = &bundle.state[&ADDRESS];
        assert_eq!(account.status, AccountStatus::DestroyedChanged);
        assert_eq!(account.storage_slot(U256::from(2)), Some(U256::ZERO));
        let (plain, reverts) = bundle.to_plain_state_and_reverts(OriginalValuesKnown::Yes);
        assert!(plain.storage[0].wipe_storage);
        assert_eq!(plain.storage[0].storage, vec![(U256::from(1), U256::from(7))]);
        assert!(
            reverts.storage[0][0].wiped,
            "Reth must read unknown old slot 2 before writing"
        );
    }

    #[test]
    fn replacing_empty_backing_record_does_not_inherit_its_unknown_storage() {
        let mut db = backing();
        db.insert_account_info(ADDRESS, AccountInfo::default());
        let mut overlay = CacheDB::new(db);
        overlay.load_account(ADDRESS).unwrap().info.balance = U256::from(1);
        overlay
            .insert_account_storage(ADDRESS, U256::from(1), U256::from(7))
            .unwrap();
        let bundle = overlay_bundle(&overlay).unwrap();
        let account = &bundle.state[&ADDRESS];
        assert_eq!(account.status, AccountStatus::DestroyedChanged);
        assert_eq!(account.storage_slot(U256::from(2)), Some(U256::ZERO));
        let (plain, reverts) = bundle.to_plain_state_and_reverts(OriginalValuesKnown::Yes);
        assert!(plain.storage[0].wipe_storage);
        assert_eq!(plain.storage[0].storage, vec![(U256::from(1), U256::from(7))]);
        assert!(reverts.storage[0][0].wiped);
    }

    #[test]
    fn eip161_empty_results_delete_for_every_cache_flag() {
        for flag in [
            AccountState::None,
            AccountState::Touched,
            AccountState::StorageCleared,
            AccountState::NotExisting,
        ] {
            let mut overlay = CacheDB::new(backing());
            let account = overlay.load_account(ADDRESS).unwrap();
            account.info = AccountInfo::default();
            account.account_state = flag;
            let bundle = overlay_bundle(&overlay).unwrap();
            assert_eq!(bundle.state[&ADDRESS].status, AccountStatus::Destroyed);
            assert!(bundle.state[&ADDRESS].info.is_none());
            assert!(bundle.state[&ADDRESS].storage.is_empty());
            let (plain, reverts) = bundle.to_plain_state_and_reverts(OriginalValuesKnown::Yes);
            assert_eq!(plain.accounts, vec![(ADDRESS, None)]);
            assert!(plain.storage[0].wipe_storage);
            assert!(reverts.storage[0][0].wiped);
        }
    }

    #[test]
    fn unchanged_reads_and_absent_accounts_create_only_an_empty_block_revert_frame() {
        let mut overlay = CacheDB::new(backing());
        overlay.load_account(ADDRESS).unwrap();
        overlay.load_account(Address::repeat_byte(8)).unwrap();
        overlay
            .insert_account_storage(ADDRESS, U256::from(1), U256::from(7))
            .unwrap();
        let bundle = overlay_bundle(&overlay).unwrap();
        assert!(bundle.state.is_empty());
        assert_eq!(bundle.reverts.len(), 1);
        assert!(bundle.reverts[0].is_empty());
    }

    #[test]
    fn changed_code_is_required_validated_and_carried_in_the_bundle() {
        let mut overlay = CacheDB::new(InMemoryDB::default());
        let code = Bytecode::new_raw(vec![0x60, 0, 0x00].into());
        let hash = code.hash_slow();
        overlay.insert_account_info(
            ADDRESS,
            AccountInfo {
                nonce: 1,
                code_hash: hash,
                code: None,
                ..Default::default()
            },
        );
        assert!(matches!(overlay_bundle(&overlay), Err(BundleError::MissingCode { .. })));
        overlay.cache.contracts.insert(hash, Bytecode::default());
        assert!(matches!(
            overlay_bundle(&overlay),
            Err(BundleError::CodeHashMismatch { .. })
        ));
        overlay.cache.contracts.insert(hash, code.clone());
        let bundle = overlay_bundle(&overlay).unwrap();
        assert_eq!(bundle.contracts[&hash], code);
        assert_eq!(bundle.state[&ADDRESS].status, AccountStatus::InMemoryChange);
    }

    struct FailingStorage(InMemoryDB);
    impl DatabaseRef for FailingStorage {
        type Error = reth_storage_errors::provider::ProviderError;
        fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(self.0.basic_ref(address).unwrap())
        }
        fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(self.0.code_by_hash_ref(hash).unwrap())
        }
        fn storage_ref(&self, _address: Address, _slot: U256) -> Result<U256, Self::Error> {
            Err(reth_storage_errors::provider::ProviderError::UnsupportedProvider)
        }
        fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
            Ok(self.0.block_hash_ref(number).unwrap())
        }
    }

    #[test]
    fn original_slot_failure_returns_no_bundle_and_does_not_mutate_execution() {
        let db = backing();
        let before = format!("{db:?}");
        let mut overlay = CacheDB::new(FailingStorage(db));
        overlay
            .load_account(ADDRESS)
            .unwrap()
            .storage
            .insert(U256::from(1), U256::from(9));
        let cached_before = format!("{:?}", overlay.cache);
        assert!(matches!(overlay_bundle(&overlay), Err(BundleError::Database(_))));
        assert_eq!(format!("{:?}", overlay.db.0), before);
        assert_eq!(format!("{:?}", overlay.cache), cached_before);
    }
}
