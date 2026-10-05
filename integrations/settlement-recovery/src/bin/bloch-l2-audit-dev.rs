// SPDX-License-Identifier: AGPL-3.0-or-later
//! Historical development auditor for the native asynchronous L2 settlement.
//!
//! `init` re-executes a stopped canonical L2 database, opened read-only, into a
//! new target and stages the first audit candidate there. `recover` repeats the
//! complete native and canonical audits against that target, requiring the
//! candidate commitment retained outside the database. Neither mode opens a
//! network listener, reads signing keys, produces proofs or publishes finality.
#![cfg(unix)]

use alloy_primitives::{hex, B256};
use bloch_l2_evm::ChainSpec;
use bloch_reth_execution::{
    inspect_canonical_prefix, replay_canonical_prefix_with_limits, BlochChainSpec, BlochProviderFactory, BlochTables,
    ReplayFloor, ReplayLimits,
};
use bloch_settlement_recovery::{
    async_cursor::{recover_and_stage_async_finality_candidate, AsyncFinalityCandidateRequestV1},
    history::{load_native_history, NativeHistoryInputLimitsV1},
    native::NativeReplayLimitsV1,
};
use reth_db::mdbx::{init_db_for, open_db, open_db_read_only, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, StaticFileProvider},
    ProviderFactory,
};
use reth_tasks::{Runtime, RuntimeBuilder, RuntimeConfig};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const USAGE: &str = "\
usage: bloch-l2-audit-dev init|recover [options]

Required:
  --manifest PATH            public BPOSMAN3 async manifest
  --network-pin HEX          independently retained native network identity
  --history DIR              stopped public export: index.json and <id>.bin
  --target DIR               init: must not exist; recover: existing audit DB
  --l2-floor-number N        independently retained L2 replay floor height
  --l2-floor-hash HEX        exact L2 header hash at that height
  --current-epoch N          observed native epoch bound (not freshness)
  --report PATH              new report file, created once
init only:
  --source DIR               stopped canonical L2 data dir, opened read-only
recover only:
  --expected-candidate HEX   commitment acknowledged by the previous run
Optional:
  --max-l2-blocks N          canonical replay block budget (default 10000)
  --max-l2-bytes N           canonical replay byte budget (default 67108864)

HEX values are 64 lowercase hex characters without 0x. No option may repeat.
Development audit only: production_finality and rpc_finality_published stay false.
";

const MIB: u64 = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Init,
    Recover,
}

struct Options {
    mode: Mode,
    manifest: PathBuf,
    network_pin: B256,
    history: PathBuf,
    source: Option<PathBuf>,
    target: PathBuf,
    floor: ReplayFloor,
    expected_candidate: Option<B256>,
    current_epoch: u64,
    report: PathBuf,
    limits: ReplayLimits,
}

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match parse(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("bloch-l2-audit-dev: {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let target_preexisted = fs::symlink_metadata(&options.target).is_ok();
    match run(&options) {
        Ok(commitment) => {
            println!("{}", hex::encode(commitment));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bloch-l2-audit-dev: refused: {error}");
            if options.mode == Mode::Init && !target_preexisted && options.target.exists() {
                eprintln!(
                    "bloch-l2-audit-dev: target {} may be incomplete; keep it for diagnosis and do not reuse it",
                    options.target.display()
                );
            }
            ExitCode::FAILURE
        }
    }
}

fn parse(args: &[String]) -> Result<Options, String> {
    let (mode, rest) = match args.split_first() {
        Some((mode, rest)) if mode == "init" => (Mode::Init, rest),
        Some((mode, rest)) if mode == "recover" => (Mode::Recover, rest),
        _ => return Err("first argument must be init or recover".into()),
    };
    if rest.len() % 2 != 0 {
        return Err("every option requires exactly one value".into());
    }
    let mut values = BTreeMap::new();
    for pair in rest.chunks(2) {
        let name = pair[0].strip_prefix("--").ok_or_else(|| format!("unexpected argument {}", pair[0]))?;
        if !matches!(
            name,
            "manifest"
                | "network-pin"
                | "history"
                | "source"
                | "target"
                | "l2-floor-number"
                | "l2-floor-hash"
                | "expected-candidate"
                | "current-epoch"
                | "report"
                | "max-l2-blocks"
                | "max-l2-bytes"
        ) {
            return Err(format!("unknown option --{name}"));
        }
        if values.insert(name, pair[1].as_str()).is_some() {
            return Err(format!("option --{name} repeated"));
        }
    }
    let mut take = |name: &str| values.remove(name);
    let source = take("source").map(PathBuf::from);
    let expected = take("expected-candidate");
    match mode {
        Mode::Init if source.is_none() => return Err("init requires --source".into()),
        Mode::Init if expected.is_some() => return Err("init must not receive --expected-candidate".into()),
        Mode::Recover if source.is_some() => return Err("recover must not receive --source".into()),
        Mode::Recover if expected.is_none() => {
            return Err("recover requires the independently retained --expected-candidate".into())
        }
        _ => {}
    }
    let floor = ReplayFloor {
        number: number(required(take("l2-floor-number"), "l2-floor-number")?, "l2-floor-number")?,
        hash: hash(required(take("l2-floor-hash"), "l2-floor-hash")?, "l2-floor-hash")?,
    };
    if floor.number == 0 {
        return Err("--l2-floor-number must select an acknowledged non-genesis block".into());
    }
    let limits = ReplayLimits {
        blocks: take("max-l2-blocks").map(|v| number(v, "max-l2-blocks")).transpose()?.unwrap_or(10_000),
        bytes: take("max-l2-bytes").map(|v| number(v, "max-l2-bytes")).transpose()?.unwrap_or(64 * MIB),
    };
    if limits.blocks == 0 || limits.blocks > 10_000 || limits.bytes == 0 || limits.bytes > 256 * MIB {
        return Err("L2 replay budget must be within 1..=10000 blocks and 1..=268435456 bytes".into());
    }
    Ok(Options {
        mode,
        manifest: PathBuf::from(required(take("manifest"), "manifest")?),
        network_pin: hash(required(take("network-pin"), "network-pin")?, "network-pin")?,
        history: PathBuf::from(required(take("history"), "history")?),
        source,
        target: PathBuf::from(required(take("target"), "target")?),
        floor,
        expected_candidate: expected.map(|v| hash(v, "expected-candidate")).transpose()?,
        current_epoch: number(required(take("current-epoch"), "current-epoch")?, "current-epoch")?,
        report: PathBuf::from(required(take("report"), "report")?),
        limits,
    })
}

fn required<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("missing --{name}"))
}

fn number(value: &str, name: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) || (value.len() > 1 && value.starts_with('0')) {
        return Err(format!("--{name} must be a canonical decimal integer"));
    }
    value.parse().map_err(|_| format!("--{name} is out of range"))
}

fn hash(value: &str, name: &str) -> Result<B256, String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(format!("--{name} must be 64 lowercase hex characters without 0x"));
    }
    let parsed = value.parse::<B256>().map_err(|_| format!("--{name} is not a 32-byte hash"))?;
    if parsed.is_zero() {
        return Err(format!("--{name} must not be zero"));
    }
    Ok(parsed)
}

/// Pinned development configuration of the historical canonical database.
/// The manifest commits to it but does not carry enough data to rebuild it.
fn spec() -> Result<Arc<BlochChainSpec>, String> {
    BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0xd3), 0)
        .map(Arc::new)
        .map_err(|e| format!("development chain specification: {e}"))
}

fn require_data_dir(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{label} {}: {e}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{label} {} must be a real directory", path.display()));
    }
    for directory in ["db", "static", "rocks"] {
        let child = fs::symlink_metadata(path.join(directory)).map_err(|_| format!("{label} is missing {directory}"))?;
        if !child.is_dir() {
            return Err(format!("{label} {directory} must be a real directory"));
        }
    }
    Ok(())
}

/// Resolve a path that may not exist yet through its existing parent.
fn absolute_new(path: &Path) -> Result<PathBuf, String> {
    let name = path.file_name().ok_or_else(|| format!("{} has no final component", path.display()))?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = parent.canonicalize().map_err(|e| format!("{}: {e}", parent.display()))?;
    Ok(parent.join(name))
}

fn open_read_only(path: &Path, spec: Arc<BlochChainSpec>, runtime: &Runtime) -> Result<BlochProviderFactory, String> {
    ProviderFactory::new(
        Arc::new(open_db_read_only(path.join("db"), DatabaseArguments::default()).map_err(|e| e.to_string())?),
        spec,
        StaticFileProvider::read_only(path.join("static")).map_err(|e| e.to_string())?,
        RocksDBBuilder::new(path.join("rocks"))
            .with_default_tables()
            .with_read_only(true)
            .build()
            .map_err(|e| e.to_string())?,
        runtime.clone(),
    )
    .map_err(|e| e.to_string())
}

/// Reth's read-only RocksDB opens a secondary instance whose scratch directory
/// is created beside `rocks`. A read-only source mount cannot hold it, so the
/// source is opened through a private writable view of symlinks to its stores.
/// Only RocksDB's secondary scratch is written, inside the view.
struct SourceView(PathBuf);
impl SourceView {
    fn create(source: &Path, target: &Path) -> Result<Self, String> {
        let name = target.file_name().ok_or("target has no final component")?.to_string_lossy();
        let view = target.with_file_name(format!(".{name}.source-view"));
        fs::create_dir(&view).map_err(|e| format!("create source view {}: {e}", view.display()))?;
        let view = Self(view);
        for directory in ["db", "static", "rocks"] {
            std::os::unix::fs::symlink(source.join(directory), view.0.join(directory))
                .map_err(|e| format!("source view {directory}: {e}"))?;
        }
        Ok(view)
    }
}
impl Drop for SourceView {
    fn drop(&mut self) {
        // remove_dir_all removes the symlinks themselves, never their targets.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open_writable(path: &Path, spec: Arc<BlochChainSpec>, runtime: &Runtime, create: bool) -> Result<BlochProviderFactory, String> {
    let db = if create {
        init_db_for::<_, BlochTables>(path.join("db"), DatabaseArguments::default())
    } else {
        open_db(path.join("db"), DatabaseArguments::default())
    }
    .map_err(|e| e.to_string())?;
    ProviderFactory::new(
        Arc::new(db),
        spec,
        StaticFileProvider::read_write(path.join("static")).map_err(|e| e.to_string())?,
        RocksDBBuilder::new(path.join("rocks"))
            .with_default_tables()
            .build()
            .map_err(|e| e.to_string())?,
        runtime.clone(),
    )
    .map_err(|e| e.to_string())
}

fn run(options: &Options) -> Result<B256, String> {
    let started = unix_seconds();
    // Refuse every path conflict before decoding inputs or opening a database.
    let report = absolute_new(&options.report)?;
    if fs::symlink_metadata(&report).is_ok() {
        return Err(format!("report {} already exists", report.display()));
    }
    let target = absolute_new(&options.target)?;
    let source = match options.mode {
        Mode::Init => {
            if fs::symlink_metadata(&target).is_ok() {
                return Err(format!("init target {} already exists", target.display()));
            }
            let source = options.source.as_deref().ok_or("init requires --source")?;
            require_data_dir(source, "source")?;
            let source = source.canonicalize().map_err(|e| e.to_string())?;
            if target.starts_with(&source) || source.starts_with(&target) {
                return Err("source and target must not overlap".into());
            }
            Some(source)
        }
        Mode::Recover => {
            require_data_dir(&target, "target")?;
            None
        }
    };
    if report.starts_with(&target) || source.as_ref().is_some_and(|s| report.starts_with(s)) {
        return Err("report must be outside the source and target databases".into());
    }

    let history = load_native_history(
        &options.manifest,
        options.network_pin,
        &options.history,
        NativeHistoryInputLimitsV1::default(),
    )
    .map_err(|e| e.to_string())?;
    let native_limits = NativeReplayLimitsV1 {
        blocks: 10_000,
        epochs: 4096,
        attestations: 100_000,
        transactions: 100_000,
        proofs: 1024,
        bytes: 64 * MIB as usize,
    };
    let verified = history.verify(native_limits).map_err(|e| format!("native replay: {e}"))?;
    let native = *verified.report();
    if options.current_epoch < bloch_pos_committee::epoch_of(native.replayed_slot) {
        return Err("--current-epoch is earlier than the replayed native history".into());
    }

    let spec = spec()?;
    let runtime = RuntimeBuilder::new(RuntimeConfig::default())
        .build()
        .map_err(|e| format!("task runtime: {e}"))?;
    let result = (|| -> Result<_, String> {
        let replay = if let Some(source) = &source {
            let view = SourceView::create(source, &target)?;
            let source = open_read_only(&view.0, spec.clone(), &runtime)?;
            // Preflight before creating any target file.
            inspect_canonical_prefix(&source, &spec, Some(options.floor), options.limits)
                .map_err(|e| format!("source preflight: {e}"))?;
            fs::create_dir(&target).map_err(|e| format!("create target: {e}"))?;
            let fresh = open_writable(&target, spec.clone(), &runtime, true)?;
            let outcome = replay_canonical_prefix_with_limits(&source, &fresh, Some(options.floor), options.limits)
                .map_err(|e| format!("canonical replay: {e}"))?;
            drop(source);
            drop(view);
            Some((fresh, outcome))
        } else {
            None
        };
        let (database, replay) = match replay {
            Some((database, outcome)) => (database, Some(outcome)),
            None => (open_writable(&target, spec.clone(), &runtime, false)?, None),
        };
        let staged = recover_and_stage_async_finality_candidate(
            &database,
            AsyncFinalityCandidateRequestV1 {
                settlement_policy: history.policy,
                l2_floor: options.floor,
                canonical_limits: options.limits,
                expected_cursor: options.expected_candidate,
                current_epoch: options.current_epoch,
            },
            &verified,
        )
        .map_err(|e| e.to_string())?;
        drop(database);
        Ok((staged, replay))
    })();
    let shut_down = runtime.graceful_shutdown_with_timeout(Duration::from_secs(10));
    let (staged, replay) = result?;
    if !shut_down {
        return Err("task runtime did not shut down; the candidate was committed but is NOT acknowledged".into());
    }

    let cursor = staged.cursor();
    let fields = cursor.fields();
    let canonical = staged.canonical();
    let commitment = cursor.commitment();
    let document = json!({
        "schema": "bloch.l2.audit-development-report.v1",
        "ok": true,
        "mode": match options.mode { Mode::Init => "init", Mode::Recover => "recover" },
        "classification": "historical-native-async-l2-development-audit",
        "release": { "binary": "bloch-l2-audit-dev", "package_version": env!("CARGO_PKG_VERSION") },
        "started_at_unix": started,
        "finished_at_unix": unix_seconds(),
        "inputs": {
            "manifest": options.manifest.display().to_string(),
            "network_pin": hex::encode(options.network_pin),
            "history": options.history.display().to_string(),
            "history_blocks": history.blocks.len(),
            "history_bytes": history.total_bytes,
            "source": source.as_ref().map(|s| s.display().to_string()),
            "source_opened_read_only": source.is_some(),
            "target": target.display().to_string(),
            "l2_floor_number": options.floor.number,
            "l2_floor_hash": hex::encode(options.floor.hash),
            "expected_candidate": options.expected_candidate.map(hex::encode),
            "current_epoch": options.current_epoch,
            "max_l2_blocks": options.limits.blocks,
            "max_l2_bytes": options.limits.bytes,
        },
        "native": {
            "genesis_state_root": hex::encode(native.genesis_state_root),
            "settlement_policy": hex::encode(native.settlement_policy),
            "replayed_blocks": native.replayed_blocks,
            "replayed_slot": native.replayed_slot,
            "finalized_epoch": native.finalized_epoch,
            "finalized_slot": native.finalized.slot,
            "finalized_block": hex::encode(native.finalized.block),
        },
        "canonical_replay": replay.as_ref().map(|r| json!({
            "head_number": r.head.0.number,
            "head_hash": hex::encode(r.head.hash()),
            "blocks": r.blocks,
            "bytes": r.bytes,
        })),
        "audit": {
            "audited_records": canonical.audited_records,
            "l2_genesis": hex::encode(canonical.genesis),
            "canonical_head_number": canonical.canonical_head.number,
            "canonical_head_hash": hex::encode(canonical.canonical_head.hash),
            "settlement_count": fields.settlement_count,
            "l2_number": fields.l2_number,
            "l2_hash": hex::encode(fields.l2_hash),
            "l2_state_root": hex::encode(fields.l2_state_root),
            "native_settlement_slot": fields.native_settlement_slot,
            "checked_at_epoch": fields.checked_at_epoch,
        },
        "candidate_commitment": hex::encode(commitment),
        "production_finality": false,
        "rpc_finality_published": false,
        "continuous_settlement_worker": false,
        "same_host_failure_domain": true,
    });
    let bytes = serde_json::to_vec_pretty(&document).map_err(|e| e.to_string())?;
    save_new(&report, &bytes).map_err(|e| {
        format!("candidate {} committed but report write failed ({e}); reconcile explicitly", hex::encode(commitment))
    })?;
    Ok(commitment)
}

fn save_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(path.parent().unwrap_or(Path::new("/")))?.sync_all()
}

fn unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}
