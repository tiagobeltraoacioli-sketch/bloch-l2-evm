// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded public native-history intake. Decoding is not consensus verification:
//! only `OwnedNativeHistoryV1::verify` creates the private replay capability.
use crate::native::{
    verify_native_finality, NativeFinalityErrorV1, NativeGenesisTrustV1, NativeReplayBlockV1, NativeReplayLimitsV1,
    VerifiedNativeFinalityV1,
};
use alloy_primitives::B256;
use bloch_l2_evm::native_settlement::SettlementPolicyV1;
use bloch_pos_committee::{
    interfaces::{ProposalEnvelope, StateReader},
    transition::CommittedState,
};
use bloch_pos_node::{
    codec,
    genesis::{Manifest, ManifestFormat},
};
use std::{
    collections::BTreeSet,
    ffi::{CString, OsStr},
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

const MIB: u64 = 1_048_576;

/// Allocation/I/O budgets, independent of the consensus replay work budgets.
/// `total_bytes` counts encoded block files, excluding manifest and index.
#[derive(Clone, Copy, Debug)]
pub struct NativeHistoryInputLimitsV1 {
    pub manifest_bytes: u64,
    pub index_bytes: u64,
    pub block_bytes: u64,
    pub total_bytes: u64,
    pub blocks: usize,
}
impl Default for NativeHistoryInputLimitsV1 {
    fn default() -> Self {
        Self {
            manifest_bytes: MIB,
            index_bytes: MIB,
            block_bytes: MIB,
            total_bytes: 64 * MIB,
            blocks: 10_000,
        }
    }
}

#[derive(Debug)]
pub enum NativeHistoryErrorV1 {
    Io(io::Error),
    Path,
    Limit,
    Encoding(&'static str),
    Identity,
    Changed,
}
impl std::fmt::Display for NativeHistoryErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native public-history intake refused: {self:?}")
    }
}
impl std::error::Error for NativeHistoryErrorV1 {}
impl From<io::Error> for NativeHistoryErrorV1 {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Owned public input selected by an independently retained manifest SHA3 pin.
/// No signature, proof, consensus or freshness claim exists until full replay.
pub struct OwnedNativeHistoryV1 {
    pub manifest: Manifest,
    pub genesis: CommittedState,
    pub policy: SettlementPolicyV1,
    pub blocks: Vec<NativeReplayBlockV1>,
    pub total_bytes: u64,
}
impl OwnedNativeHistoryV1 {
    pub fn trust(&self) -> NativeGenesisTrustV1 {
        NativeGenesisTrustV1 {
            state_root: self.genesis.state_root().into(),
            settlement_policy: self.policy,
        }
    }

    /// Reverify every signature, proof, transition and FFG checkpoint.
    pub fn verify(&self, limits: NativeReplayLimitsV1) -> Result<VerifiedNativeFinalityV1, NativeFinalityErrorV1> {
        verify_native_finality(&self.genesis, self.trust(), &self.blocks, limits)
    }
}

/// Read exact public files from a stopped export. Every directory component and
/// file is opened without following symlinks; directory handles anchor later
/// reads even if a pathname is replaced. Files must remain immutable while read.
/// A valid shortened branch still needs independently retained recovery floors:
/// the index and input byte counts are not rollback protection or freshness.
pub fn load_native_history(
    manifest_path: &Path,
    independent_network: B256,
    history_dir: &Path,
    limits: NativeHistoryInputLimitsV1,
) -> Result<OwnedNativeHistoryV1, NativeHistoryErrorV1> {
    use NativeHistoryErrorV1 as E;
    if limits.manifest_bytes == 0
        || limits.manifest_bytes > MIB
        || limits.index_bytes == 0
        || limits.index_bytes > MIB
        || limits.block_bytes == 0
        || limits.block_bytes > MIB
        || limits.total_bytes == 0
        || limits.total_bytes > 64 * MIB
        || limits.blocks == 0
        || limits.blocks > 10_000
    {
        return Err(E::Limit);
    }
    if independent_network.is_zero() {
        return Err(E::Identity);
    }
    let (manifest, genesis, policy) = load_native_manifest(manifest_path, independent_network, limits.manifest_bytes)?;
    let directory = open_directory(history_dir)?;
    let index = read_public_file(&directory, OsStr::new("index.json"), limits.index_bytes)?;
    let ids: Vec<String> = serde_json::from_slice(&index).map_err(|_| E::Encoding("index"))?;
    if ids.is_empty() || ids.len() > limits.blocks {
        return Err(E::Limit);
    }
    let mut unique = BTreeSet::new();
    for id in &ids {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) || !unique.insert(id)
        {
            return Err(E::Encoding("invalid or duplicate block id"));
        }
    }
    let mut total_bytes = 0u64;
    let mut blocks = Vec::with_capacity(ids.len());
    let mut parent = *genesis.head().as_bytes();
    let mut previous_slot = 0;
    for id in ids {
        let remaining = limits.total_bytes.checked_sub(total_bytes).ok_or(E::Limit)?;
        let bytes = read_public_file(
            &directory,
            OsStr::new(&format!("{id}.bin")),
            limits.block_bytes.min(remaining),
        )?;
        total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or(E::Limit)?;
        let envelope = codec::decode_envelope(&bytes).map_err(|_| E::Encoding("block envelope"))?;
        if codec::encode_envelope(&envelope) != bytes || codec::hex32(envelope.block_id().as_bytes()) != id {
            return Err(E::Encoding("noncanonical or misidentified block"));
        }
        if envelope.header.parent != parent || envelope.header.slot <= previous_slot {
            return Err(E::Encoding("incomplete or reordered ancestry"));
        }
        parent = *envelope.block_id().as_bytes();
        previous_slot = envelope.header.slot;
        blocks.push(NativeReplayBlockV1 {
            envelope: ProposalEnvelope {
                header: envelope.header,
                proposer_sig: envelope.proposer_sig,
            },
            attestations: envelope.body.attestations,
            transactions: envelope.body.transactions,
        });
    }
    Ok(OwnedNativeHistoryV1 {
        manifest,
        genesis,
        policy,
        blocks,
        total_bytes,
    })
}

/// Read and validate the pinned BPOSMAN3 manifest and derive the settlement
/// policy it commits to. The network identity must equal the independent pin.
pub fn load_native_manifest(
    manifest_path: &Path,
    independent_network: B256,
    manifest_limit: u64,
) -> Result<(Manifest, CommittedState, SettlementPolicyV1), NativeHistoryErrorV1> {
    use NativeHistoryErrorV1 as E;
    if manifest_limit == 0 || manifest_limit > MIB || independent_network.is_zero() {
        return Err(E::Limit);
    }
    let limits = NativeHistoryInputLimitsV1 { manifest_bytes: manifest_limit, ..Default::default() };
    let parent = manifest_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = open_directory(parent)?;
    let bytes = read_public_file(
        &directory,
        manifest_path.file_name().ok_or(E::Path)?,
        limits.manifest_bytes,
    )?;
    // Check the count before the native decoder allocates its validator vector.
    if bytes.len() < 28 || &bytes[..8] != b"BPOSMAN3" {
        return Err(E::Encoding("async manifest required"));
    }
    let count = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    if count == 0 || count > 4096 {
        return Err(E::Limit);
    }
    let manifest = Manifest::decode(&bytes).map_err(|_| E::Encoding("manifest"))?;
    if !matches!(manifest.format, ManifestFormat::V3L2Async(_)) || manifest.encode() != bytes {
        return Err(E::Encoding("noncanonical manifest"));
    }
    let mut indices = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut stake = 0u128;
    for validator in &manifest.validators {
        if !indices.insert(validator.index)
            || !keys.insert(&validator.pubkey)
            || validator.stake_sat == 0
            || validator.commission_bps > 10_000
        {
            return Err(E::Encoding("validator registry"));
        }
        stake = stake.checked_add(validator.stake_sat).ok_or(E::Limit)?;
    }
    let genesis = manifest.genesis_state();
    let state = genesis.l2_settlement().ok_or(E::Identity)?;
    let native = state.policy();
    if B256::from(native.identities[0]) != independent_network {
        return Err(E::Identity);
    }
    let policy = SettlementPolicyV1 {
        network: native.identities[0].into(),
        genesis: native.identities[1].into(),
        domain: native.identities[2].into(),
        configuration: native.identities[3].into(),
        program_elf_keccak: native.identities[4].into(),
        program_vkey_koalabear: native.identities[5].into(),
        program_vkey_bn254: native.identities[6].into(),
        proof_policy: native.proof_policy.into(),
        chain_id: native.chain_id,
        first_l2_number: 1,
        initial_l2_parent_hash: native.initial_l2_parent.into(),
        initial_l2_state_root: native.initial_l2_state.into(),
    };
    policy.commitment().map_err(|_| E::Identity)?;
    Ok((manifest, genesis, policy))
}

fn open_at(directory: &File, name: &OsStr, flags: libc::c_int) -> Result<File, NativeHistoryErrorV1> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(NativeHistoryErrorV1::Path);
    }
    let name = CString::new(bytes).map_err(|_| NativeHistoryErrorV1::Path)?;
    // SAFETY: the borrowed directory fd remains valid; the C string is NUL
    // terminated, and no creation flag requiring a mode argument is supplied.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a new owned fd and ownership is transferred once.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_directory(path: &Path) -> Result<File, NativeHistoryErrorV1> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut directory = File::open("/")?;
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => directory = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY)?,
            _ => return Err(NativeHistoryErrorV1::Path),
        }
    }
    Ok(directory)
}

fn read_public_file(directory: &File, name: &OsStr, limit: u64) -> Result<Vec<u8>, NativeHistoryErrorV1> {
    let mut file = open_at(directory, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(NativeHistoryErrorV1::Path);
    }
    if before.len() == 0 || before.len() > limit {
        return Err(NativeHistoryErrorV1::Limit);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(limit.checked_add(1).ok_or(NativeHistoryErrorV1::Limit)?)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
    {
        return Err(NativeHistoryErrorV1::Changed);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, Body, VERSION_G4};
    use bloch_pos_node::genesis::L2Config;
    use std::{fs, os::unix::fs::symlink};

    fn manifest_bytes() -> Vec<u8> {
        // Public shape-only key, never a generated private or operational key.
        let mut bytes = b"BPOSMAN3".to_vec();
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&2000u64.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&20_000_000_000_000u128.to_le_bytes());
        bytes.extend_from_slice(&[7; 32]);
        let mut public = vec![1; 3749];
        public[..4].copy_from_slice(&[0xb1, 0x0c, 1, 0]);
        codec::put_bytes(&mut bytes, &public);
        codec::put_bytes(&mut bytes, &[1; 4]);
        bytes.extend_from_slice(&500u128.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(
            &L2Config {
                identities: [[3; 32]; 5],
                proof_policy: bloch_l2_proof::policy_commitment(),
                chain_id: 700771,
                initial_l2_parent: [4; 32],
                initial_l2_state: [5; 32],
            }
            .encode(),
        );
        bytes
    }

    struct Fixture {
        root: tempfile::TempDir,
        manifest: std::path::PathBuf,
        history: std::path::PathBuf,
        id: String,
        pin: B256,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            // macOS's temporary-directory prefix may be a system symlink.
            let base = root.path().canonicalize().unwrap();
            let manifest = base.join("genesis.blg");
            let history = base.join("history");
            fs::create_dir(&history).unwrap();
            let bytes = manifest_bytes();
            fs::write(&manifest, &bytes).unwrap();
            let genesis = Manifest::decode(&bytes).unwrap().genesis_state();
            let pin = genesis.l2_settlement().unwrap().policy().identities[0].into();
            let envelope = BlockEnvelope {
                header: BlockHeaderV4 {
                    version: VERSION_G4,
                    parent: *genesis.head().as_bytes(),
                    state_root: [1; 32],
                    body_root: [2; 32],
                    slot: 1,
                    proposer_index: 0,
                    randao_reveal: [3; 32],
                    randao_mix: [4; 32],
                    justified_root: [5; 32],
                    finalized_root: [6; 32],
                    attestation_root: [7; 32],
                    coherence_root: [8; 32],
                },
                proposer_sig: vec![9; 32],
                body: Body {
                    transactions: vec![],
                    attestations: vec![],
                },
            };
            let id = codec::hex32(envelope.block_id().as_bytes());
            fs::write(history.join(format!("{id}.bin")), codec::encode_envelope(&envelope)).unwrap();
            fs::write(history.join("index.json"), serde_json::to_vec(&[&id]).unwrap()).unwrap();
            Self {
                root,
                manifest,
                history,
                id,
                pin,
            }
        }
        fn load(&self, limits: NativeHistoryInputLimitsV1) -> Result<OwnedNativeHistoryV1, NativeHistoryErrorV1> {
            load_native_history(&self.manifest, self.pin, &self.history, limits)
        }
    }

    #[test]
    fn public_decode_is_bound_to_manifest_but_does_not_authenticate_fake_signatures() {
        let fixture = Fixture::new();
        let history = fixture.load(NativeHistoryInputLimitsV1::default()).unwrap();
        assert_eq!(history.policy.network, fixture.pin);
        assert_eq!(history.policy.domain, B256::repeat_byte(3));
        assert_eq!(history.blocks.len(), 1);
        assert!(history.verify(NativeReplayLimitsV1::default()).is_err());
        assert!(load_native_history(
            &fixture.manifest,
            B256::repeat_byte(1),
            &fixture.history,
            NativeHistoryInputLimitsV1::default()
        )
        .is_err());
    }

    #[test]
    fn rejects_symlinked_manifest_history_parent_index_and_block() {
        let fixture = Fixture::new();
        let base = fixture.root.path().canonicalize().unwrap();
        let manifest_alias = base.join("manifest-alias");
        symlink(&fixture.manifest, &manifest_alias).unwrap();
        assert!(load_native_history(
            &manifest_alias,
            fixture.pin,
            &fixture.history,
            NativeHistoryInputLimitsV1::default()
        )
        .is_err());
        let history_alias = base.join("history-alias");
        symlink(&fixture.history, &history_alias).unwrap();
        assert!(load_native_history(
            &fixture.manifest,
            fixture.pin,
            &history_alias,
            NativeHistoryInputLimitsV1::default()
        )
        .is_err());
        let parent_alias = base.join("parent-alias");
        symlink(&base, &parent_alias).unwrap();
        assert!(load_native_history(
            &parent_alias.join("genesis.blg"),
            fixture.pin,
            &fixture.history,
            NativeHistoryInputLimitsV1::default()
        )
        .is_err());
        for name in ["index.json".to_owned(), format!("{}.bin", fixture.id)] {
            let path = fixture.history.join(&name);
            let saved = base.join(&name);
            fs::rename(&path, &saved).unwrap();
            symlink(saved, &path).unwrap();
            assert!(fixture.load(NativeHistoryInputLimitsV1::default()).is_err());
            fs::remove_file(&path).unwrap();
            fs::rename(base.join(&name), path).unwrap();
        }
    }

    #[test]
    fn refuses_each_input_budget_before_accepting_history() {
        let fixture = Fixture::new();
        let defaults = NativeHistoryInputLimitsV1::default();
        for limits in [
            NativeHistoryInputLimitsV1 {
                manifest_bytes: 27,
                ..defaults
            },
            NativeHistoryInputLimitsV1 {
                index_bytes: 1,
                ..defaults
            },
            NativeHistoryInputLimitsV1 {
                block_bytes: 1,
                ..defaults
            },
            NativeHistoryInputLimitsV1 {
                total_bytes: 1,
                ..defaults
            },
            NativeHistoryInputLimitsV1 { blocks: 0, ..defaults },
            NativeHistoryInputLimitsV1 {
                blocks: 10_001,
                ..defaults
            },
        ] {
            assert!(fixture.load(limits).is_err());
        }
    }

    #[test]
    fn rejects_duplicate_malformed_missing_and_truncated_blocks() {
        let fixture = Fixture::new();
        let index = fixture.history.join("index.json");
        for ids in [
            vec![fixture.id.clone(), fixture.id.clone()],
            vec!["../escape".into()],
            vec!["A".repeat(64)],
            vec!["0".repeat(64)],
            vec![],
        ] {
            fs::write(&index, serde_json::to_vec(&ids).unwrap()).unwrap();
            assert!(fixture.load(NativeHistoryInputLimitsV1::default()).is_err());
        }
        fs::write(index, serde_json::to_vec(&[&fixture.id]).unwrap()).unwrap();
        let block = fixture.history.join(format!("{}.bin", fixture.id));
        let mut bytes = fs::read(&block).unwrap();
        bytes.pop();
        fs::write(block, bytes).unwrap();
        assert!(fixture.load(NativeHistoryInputLimitsV1::default()).is_err());
    }

    #[test]
    fn rejects_manifest_count_before_native_decoder_allocation() {
        let fixture = Fixture::new();
        let mut bytes = fs::read(&fixture.manifest).unwrap();
        bytes[24..28].copy_from_slice(&1_000_000u32.to_le_bytes());
        fs::write(&fixture.manifest, bytes).unwrap();
        assert!(matches!(
            fixture.load(NativeHistoryInputLimitsV1::default()),
            Err(NativeHistoryErrorV1::Limit)
        ));
    }

    #[test]
    fn multi_block_intake_enforces_count_and_complete_ordered_ancestry() {
        let fixture = Fixture::new();
        let first_bytes = fs::read(fixture.history.join(format!("{}.bin", fixture.id))).unwrap();
        let mut second = codec::decode_envelope(&first_bytes).unwrap();
        second.header.parent = *second.block_id().as_bytes();
        second.header.slot = 2;
        let second_id = codec::hex32(second.block_id().as_bytes());
        fs::write(
            fixture.history.join(format!("{second_id}.bin")),
            codec::encode_envelope(&second),
        )
        .unwrap();
        let index = fixture.history.join("index.json");
        fs::write(&index, serde_json::to_vec(&[&fixture.id, &second_id]).unwrap()).unwrap();
        let loaded = fixture.load(NativeHistoryInputLimitsV1::default()).unwrap();
        assert_eq!(loaded.blocks.len(), 2);
        assert!(fixture
            .load(NativeHistoryInputLimitsV1 {
                blocks: 1,
                ..NativeHistoryInputLimitsV1::default()
            })
            .is_err());
        fs::write(&index, serde_json::to_vec(&[&second_id, &fixture.id]).unwrap()).unwrap();
        assert!(fixture.load(NativeHistoryInputLimitsV1::default()).is_err());
        fs::write(&index, serde_json::to_vec(&[&second_id]).unwrap()).unwrap();
        assert!(fixture.load(NativeHistoryInputLimitsV1::default()).is_err());
    }
}
