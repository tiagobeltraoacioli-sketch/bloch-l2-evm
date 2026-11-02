// SPDX-License-Identifier: MIT OR Apache-2.0
// Included by `stateroot.rs` under the `sparse-witness` feature, for its private fields.

/// CANDIDATE, sparse storage witness: a [`SparseTrieView`] with an ordered index
/// of its opaque frontier, so one lookup costs O(log frontier) instead of a scan.
/// A storage multiproof over many slots has a frontier of about 15 entries per
/// exposed branch, which makes the linear lookup quadratic in the touched slots.
///
/// The answers are those of [`SparseTrieView::contains_key`]: a key under the
/// frontier is an error, never "absent".
#[derive(Debug, Clone, Default)]
pub struct IndexedTrieView {
    view: SparseTrieView,
    frontier: BTreeSet<Nibbles>,
}

impl IndexedTrieView {
    /// Authenticate `proof` against `root` exactly as [`SparseTrieView::from_proof`].
    pub fn from_proof(root: B256, proof: &BTreeMap<Nibbles, Bytes>) -> Result<Self, WitnessError> {
        let view = SparseTrieView::from_proof(root, proof)?;
        let frontier = view.frontier.iter().map(|(path, _)| *path).collect();
        Ok(Self { view, frontier })
    }

    /// The view of an account that does not exist: proven empty, nothing opaque.
    pub fn empty() -> Self {
        Self::default()
    }

    /// `Ok(Some(value))` for an exposed leaf, `Ok(None)` for a key the proof
    /// proves absent, `Err` for a key inside an opaque subtree.
    pub fn lookup(&self, key: &Nibbles) -> Result<Option<&[u8]>, WitnessError> {
        if key.len() != KEY_NIBBLES {
            return Err(WitnessError::InvalidKeyLength { key: *key });
        }
        if let Some(value) = self.view.leaves.get(key) {
            return Ok(Some(value));
        }
        // Frontier paths are positions of one tree, so no path is a prefix of
        // another. If one is a prefix of `key`, nothing can sort between them, and
        // it is the greatest path not above `key`.
        if let Some(frontier) = self.frontier.range(..=*key).next_back() {
            if key.starts_with(frontier) {
                return Err(WitnessError::KeyInOpaqueSubtree {
                    key: *key,
                    frontier: *frontier,
                });
            }
        }
        Ok(None)
    }

    /// [`SparseTrieView::apply`] with indexed validation and a sort without
    /// allocation. The same rules, and the same root, as that function.
    pub fn apply(&self, changes: &BTreeMap<Nibbles, Option<Vec<u8>>>) -> Result<B256, WitnessError> {
        enum Item<'a> {
            Leaf(Nibbles, &'a [u8]),
            Opaque(Nibbles, B256),
        }
        impl Item<'_> {
            fn path(&self) -> &Nibbles {
                match self {
                    Item::Leaf(path, _) | Item::Opaque(path, _) => path,
                }
            }
        }
        for (key, change) in changes {
            if self.lookup(key)?.is_none() && change.is_none() {
                return Err(WitnessError::DeleteOfAbsentKey { key: *key });
            }
        }
        let view = &self.view;
        let mut items: Vec<Item<'_>> = Vec::with_capacity(view.leaves.len() + view.frontier.len() + changes.len());
        for (key, current) in &view.leaves {
            match changes.get(key) {
                Some(None) => {}
                Some(Some(value)) => items.push(Item::Leaf(*key, value)),
                None => items.push(Item::Leaf(*key, current)),
            }
        }
        for (key, change) in changes {
            if let Some(value) = change {
                if !view.leaves.contains_key(key) {
                    items.push(Item::Leaf(*key, value));
                }
            }
        }
        for (path, hash) in &view.frontier {
            items.push(Item::Opaque(*path, *hash));
        }
        if items.is_empty() {
            return Ok(EMPTY_ROOT_HASH);
        }
        items.sort_unstable_by(|a, b| a.path().cmp(b.path()));
        for (i, item) in items.iter().enumerate() {
            let path = item.path();
            if !view.branch_children.contains(path) {
                continue;
            }
            let parent = path.slice(..path.len() - 1);
            let left = i.checked_sub(1).and_then(|j| items.get(j));
            let right = items.get(i + 1);
            if !left
                .into_iter()
                .chain(right)
                .any(|other| other.path().starts_with(&parent))
            {
                return Err(WitnessError::OpaqueChildNeedsExpansion { path: *path });
            }
        }
        let mut builder = HashBuilder::default();
        for item in &items {
            match item {
                Item::Leaf(key, value) => builder.add_leaf(*key, value),
                Item::Opaque(path, hash) => builder.add_branch(*path, *hash, false),
            }
        }
        Ok(builder.root())
    }
}

/// The trie key of a storage slot: `keccak256(slot)` as nibbles.
pub(crate) fn storage_key(slot: &U256) -> Nibbles {
    slot_key(slot)
}

/// The account-trie leaf of `info` over an already known storage root.
pub(crate) fn account_leaf_with_root(info: &AccountInfo, storage_root_hash: B256) -> Vec<u8> {
    let mut value = Vec::new();
    encode_account(
        info.nonce,
        info.balance,
        storage_root_hash,
        code_hash_of(info),
        &mut value,
    );
    value
}

impl StateTrie {
    /// The storage root of `address` (warm commitment only).
    pub(crate) fn storage_root_cached(&self, address: &Address) -> Option<B256> {
        match self.storage.get(address) {
            None => Some(EMPTY_ROOT_HASH),
            Some(trie) => trie.root_cached(),
        }
    }

    /// The storage multiproof of `address` for `targets` (warm commitment only).
    /// An account without storage has an empty proof, which opens only the empty root.
    pub(crate) fn storage_proof(
        &self,
        address: &Address,
        targets: impl IntoIterator<Item = Nibbles>,
    ) -> Option<BTreeMap<Nibbles, Bytes>> {
        match self.storage.get(address) {
            None => Some(BTreeMap::new()),
            Some(trie) => trie.proof(targets),
        }
    }

    /// Key-order neighbours of a storage key of `address`.
    pub(crate) fn storage_neighbours(&self, address: &Address, key: &Nibbles) -> (Option<Nibbles>, Option<Nibbles>) {
        match self.storage.get(address) {
            None => (None, None),
            Some(trie) => (trie.predecessor(key), trie.successor(key)),
        }
    }
}
