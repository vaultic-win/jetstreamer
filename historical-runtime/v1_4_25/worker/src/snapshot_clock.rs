//! Compile-time exact-input compressed census and typed serialized clock observation.
//! No extraction, native Bank construction, replay, archive assembly or publication.
use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use solana_runtime::serde_snapshot::observe_serialized_bank_clock;
use std::{
    env,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(all(
    feature = "epoch140-snapshot-clock-diagnostic",
    feature = "epoch144-snapshot-clock-diagnostic"
))]
compile_error!("exact snapshot observation profiles are mutually exclusive");

#[cfg(not(feature = "epoch144-snapshot-clock-diagnostic"))]
mod profile {
    pub const SLOT: u64 = 60_911_751;
    pub const INPUT: &str = "/home/sol/.jetstreamer-private/epoch140-snapshot-source-20261020-v1/download/snapshot-60911751-GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR.tar.zst";
    pub const INPUT_SIZE: u64 = 2_741_858_751;
    pub const INPUT_SHA: &str = "47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1";
    pub const INPUT_INODE: u64 = 105578537;
    pub const PROTECTED_FREE: u64 = 5_153_080_892_870;
    pub const SCHEMA: &str = "jetstreamer-epoch140-serialized-snapshot-clock-v1";
    pub const GUARD_SCHEMA: &str =
        "jetstreamer-epoch140-serialized-snapshot-clock-initial-guard-v1";
}
#[cfg(feature = "epoch144-snapshot-clock-diagnostic")]
mod profile {
    pub const SLOT: u64 = 62_639_490;
    pub const INPUT: &str = "/home/sol/.jetstreamer-private/epoch144-snapshot-source-20261021-v1/download/snapshot-62639490-59bAQjc2c1VqNWqGoCacp3tnyNyie3EYx4bjttvJhgeT.tar.zst";
    pub const INPUT_SIZE: u64 = 2_569_233_422;
    pub const INPUT_SHA: &str = "f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae";
    pub const INPUT_INODE: u64 = 105578509;
    pub const PROTECTED_FREE: u64 = 4_740_696_923_590;
    pub const SCHEMA: &str = "jetstreamer-epoch144-serialized-snapshot-clock-v1";
    pub const GUARD_SCHEMA: &str =
        "jetstreamer-epoch144-serialized-snapshot-clock-initial-guard-v1";
}
use self::profile::*;
const MAX_SECONDS: u64 = 900;
const LAYOUT_SHA: &str = "4baee9ce91616985b8872b6f77fc3358cce5ca44ef95a7d337d235598d7148db";
const LAYOUT_BYTES: &[u8] =
    include_bytes!("../../vendor/solana-runtime-1.4.25/src/serde_snapshot/future.rs");

#[derive(Serialize)]
pub struct Clock {
    slot: u64,
    bank_hash: String,
    parent_bank_hash: String,
    parent_slot: u64,
    last_blockhash: String,
    transaction_count: u64,
    tick_height: u64,
    capitalization: u64,
    max_tick_height: u64,
    hashes_per_tick: Option<u64>,
    ticks_per_slot: u64,
    complete: bool,
    bank_file_bytes: u64,
    bank_file_sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn clock<R: Read>(reader: R, expected_slot: u64) -> Result<Clock, String> {
    let mut reader = HashReader::new(reader);
    let prefix = observe_serialized_bank_clock(&mut reader)?;
    if prefix.slot != expected_slot
        || prefix.ticks_per_slot == 0
        || prefix.ticks_per_slot > 1024
        || prefix.hashes_per_tick == Some(0)
    {
        return Err("serialized slot/clock is outside diagnostic scope".into());
    }
    let expected_max = expected_slot
        .checked_add(1)
        .and_then(|slot| slot.checked_mul(prefix.ticks_per_slot))
        .ok_or("serialized clock arithmetic overflow")?;
    if prefix.max_tick_height != expected_max || prefix.tick_height > expected_max {
        return Err("serialized tick height/slot arithmetic mismatch".into());
    }
    io::copy(&mut reader, &mut io::sink()).map_err(|e| e.to_string())?;
    let (bank_file_bytes, bank_file_sha256) = reader.finish();
    Ok(Clock {
        slot: prefix.slot,
        bank_hash: prefix.hash.to_string(),
        parent_bank_hash: prefix.parent_hash.to_string(),
        parent_slot: prefix.parent_slot,
        last_blockhash: prefix.last_hash.to_string(),
        transaction_count: prefix.transaction_count,
        tick_height: prefix.tick_height,
        capitalization: prefix.capitalization,
        max_tick_height: prefix.max_tick_height,
        hashes_per_tick: prefix.hashes_per_tick,
        ticks_per_slot: prefix.ticks_per_slot,
        complete: prefix.tick_height == expected_max,
        bank_file_bytes,
        bank_file_sha256,
    })
}

struct HashReader<R> {
    inner: R,
    sha: Sha256,
    bytes: u64,
}
impl<R: Read> HashReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            sha: Sha256::default(),
            bytes: 0,
        }
    }
    fn finish(self) -> (u64, String) {
        (self.bytes, hex(&self.sha.result()))
    }
}
impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(bytes)?;
        self.sha.input(&bytes[..count]);
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "byte overflow"))?;
        Ok(count)
    }
}

#[derive(Serialize)]
struct Census {
    entries: u64,
    logical_bytes: u64,
    stored_bytes: u64,
    clock: Clock,
}

fn census<R: Read>(source: R, expected_slot: u64) -> Result<Census, String> {
    let source = HandoffTarReader::new(source, HANDOFF_EXTRACTION_LIMITS)?;
    let mut archive = Archive::new(source);
    let mut seen = HashSet::new();
    let mut entries = 0u64;
    let mut logical = 0u64;
    let mut stored = 0u64;
    let mut found_clock = None;
    let mut version = None;
    let bank_path = PathBuf::from(format!("snapshots/{0}/{0}", expected_slot));
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        entries = entries.checked_add(1).ok_or("entry count overflow")?;
        if entries > HANDOFF_EXTRACTION_LIMITS.entries {
            return Err("entry bound".into());
        }
        let path = entry.path().map_err(|e| e.to_string())?.into_owned();
        let kind = entry.header().entry_type();
        let limit = validate_handoff_entry_layout(&path, kind, expected_slot)?;
        if !seen.insert(path.clone()) {
            return Err("duplicate snapshot member".into());
        }
        let member_logical = entry.header().size().map_err(|e| e.to_string())?;
        let member_stored = entry.header().entry_size().map_err(|e| e.to_string())?;
        if member_logical > limit || member_stored > limit {
            return Err("snapshot member bound exceeded".into());
        }
        logical = logical
            .checked_add(member_logical)
            .ok_or("logical byte overflow")?;
        stored = stored
            .checked_add(member_stored)
            .ok_or("stored byte overflow")?;
        if logical > HANDOFF_EXTRACTION_LIMITS.extracted_size
            || stored > HANDOFF_EXTRACTION_LIMITS.extracted_size
        {
            return Err("snapshot aggregate bound exceeded".into());
        }
        if path == Path::new("version") {
            let mut text = String::new();
            entry.read_to_string(&mut text).map_err(|e| e.to_string())?;
            supported_snapshot_version(&text)?;
            version = Some(text);
        } else if path == bank_path {
            let summary = clock(&mut entry, expected_slot)?;
            if summary.bank_file_bytes != member_logical {
                return Err("bank file length mismatch".into());
            }
            found_clock = Some(summary);
        }
    }
    if version.is_none() || !seen.contains(Path::new("snapshots/status_cache")) {
        return Err("snapshot version/status cache missing".into());
    }
    // Drain through the compression trailer; the outer file digest separately
    // binds every compressed byte, including anything after the tar terminator.
    io::copy(&mut archive.into_inner(), &mut io::sink()).map_err(|e| e.to_string())?;
    Ok(Census {
        entries,
        logical_bytes: logical,
        stored_bytes: stored,
        clock: found_clock.ok_or("serialized bank missing")?,
    })
}

fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

struct Guard {
    start: Instant,
    floor: u64,
}
impl Guard {
    fn check(&self) -> io::Result<u64> {
        let path = std::ffi::CString::new("/home/sol").unwrap();
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        let available = stat.f_bavail.checked_mul(stat.f_frsize).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "free-byte arithmetic overflow")
        })?;
        if self.start.elapsed().as_secs() >= MAX_SECONDS || available < self.floor {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "snapshot observation reserve/runtime stop",
            ));
        }
        Ok(available)
    }
}
struct Guarded<'a, R> {
    inner: R,
    guard: &'a Guard,
}
impl<'a, R: Read> Read for Guarded<'a, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.guard.check()?;
        self.inner.read(bytes)
    }
}

pub fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 5
        || args[0] != "--output"
        || args[3] != "--self-sha256"
        || args[4].len() != 64
        || !args[4]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(
            "usage: --output ABSOLUTE_NEW_RECEIPT MINIMUM_PROTECTED_FREE_BYTES --self-sha256 HEX"
                .into(),
        );
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err("root required".into());
    }
    let floor = args[2].parse::<u64>().map_err(|e| e.to_string())?;
    if floor < PROTECTED_FREE {
        return Err("cannot lower retained protection".into());
    }
    let output = PathBuf::from(&args[1]);
    let parent = output.parent().ok_or("missing output parent")?;
    let m = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !output.is_absolute()
        || parent.canonicalize().map_err(|e| e.to_string())? != parent
        || !m.is_dir()
        || m.uid() != 0
        || m.mode() & 0o077 != 0
        || fs::symlink_metadata(&output).is_ok()
    {
        return Err("output must be absent in canonical root-private directory".into());
    }
    let guard = Guard {
        start: Instant::now(),
        floor,
    };
    guard.check().map_err(|e| e.to_string())?;
    let mut executable = HashReader::new(Guarded {
        inner: File::open("/proc/self/exe")
            .map_err(|e| e.to_string())?
            .take(64 * 1024 * 1024 + 1),
        guard: &guard,
    });
    io::copy(&mut executable, &mut io::sink()).map_err(|e| e.to_string())?;
    let (exe_bytes, exe_sha) = executable.finish();
    if exe_bytes > 64 * 1024 * 1024 || exe_sha != args[4] {
        return Err("running executable digest mismatch".into());
    }
    let mut source = HashReader::new(LAYOUT_BYTES);
    io::copy(&mut source, &mut io::sink()).map_err(|e| e.to_string())?;
    if source.finish().1 != LAYOUT_SHA {
        return Err("pinned serialized layout source changed".into());
    }
    let invocation = env::var("INVOCATION_ID").map_err(|e| e.to_string())?;
    if invocation.len() != 32
        || !invocation
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("persistent exact systemd invocation required".into());
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(INPUT)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != 0
        || before.mode() & 0o222 != 0
        || before.len() != INPUT_SIZE
        || before.dev() != 64512
        || before.ino() != INPUT_INODE
    {
        return Err("frozen exact snapshot identity mismatch".into());
    }
    let initial = output.with_file_name("initial-guard.json");
    if initial == output {
        return Err("guard/output overlap".into());
    }
    let initial_available = guard.check().map_err(|e| e.to_string())?;
    write_json(
        &initial,
        &serde_json::json!({
            "schema":GUARD_SCHEMA,
            "invocation_id":invocation,"self_sha256":exe_sha,"input":INPUT,
            "input_device":before.dev(),"input_inode":before.ino(),"minimum_free_bytes":floor,
            "available_bytes":initial_available,
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_secs(),
            "maximum_runtime_seconds":MAX_SECONDS,"guard_on_each_compressed_read":true,
            "trip":false,"replay_launch_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        }),
    )?;
    let mut hashed = HashReader::new(Guarded {
        inner: &mut file,
        guard: &guard,
    });
    io::copy(&mut hashed, &mut io::sink()).map_err(|e| e.to_string())?;
    let (length, sha) = hashed.finish();
    if length != INPUT_SIZE || sha != INPUT_SHA {
        return Err("full compressed snapshot digest mismatch".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let decoder = zstd::stream::read::Decoder::new(BufReader::new(Guarded {
        inner: &mut file,
        guard: &guard,
    }))
    .map_err(|e| e.to_string())?;
    let observed = census(decoder, SLOT)?;
    if identity(&before) != identity(&file.metadata().map_err(|e| e.to_string())?)
        || identity(&before) != identity(&fs::symlink_metadata(INPUT).map_err(|e| e.to_string())?)
    {
        return Err("snapshot identity changed".into());
    }
    guard.check().map_err(|e| e.to_string())?;
    let receipt = serde_json::json!({
        "schema":SCHEMA,
        "input":INPUT,"input_sha256":INPUT_SHA,"input_bytes":length,
        "input_device":before.dev(),"input_inode":before.ino(),
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_secs(),
        "elapsed_seconds":guard.start.elapsed().as_secs(),"minimum_free_bytes":floor,
        "invocation_id":invocation,"self_sha256":exe_sha,"layout_source_sha256":LAYOUT_SHA,
        "rustc":env!("HISTORICAL_RUSTC_VERSION"),"census":observed,
        "pinned_typed_serialized_clock_only":true,"native_bank_restored":false,
        "accounts_restored":false,"snapshot_extracted":false,"archive_modified":false,
        "native_checkpoint_match_proven":false,"poh_recovery_authorized":false,
        "replay_launch_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false
    });
    write_json(&output, &receipt)?;
    println!(
        "typed serialized snapshot clock observed; native restore/replay/publication unauthorized"
    );
    Ok(())
}

fn write_json(output: &Path, value: &serde_json::Value) -> Result<(), String> {
    let parent = output.parent().ok_or("missing receipt parent")?;
    let metadata = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !output.is_absolute()
        || parent.canonicalize().map_err(|e| e.to_string())? != parent
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        return Err("receipt parent must be canonical/root-private".into());
    }
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > 16384 {
        return Err("receipt size bound".into());
    }
    let mut destination = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&output)
        .map_err(|e| e.to_string())?;
    destination.write_all(&bytes).map_err(|e| e.to_string())?;
    destination.sync_all().map_err(|e| e.to_string())?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_runtime::{
        bank::Bank,
        snapshot_utils::{add_snapshot, SnapshotVersion},
    };

    #[test]
    fn exact_profile_preserves_frozen_input_scope() {
        if cfg!(feature = "epoch144-snapshot-clock-diagnostic") {
            assert_eq!(SLOT, 62_639_490);
            assert_eq!(INPUT_SIZE, 2_569_233_422);
            assert_eq!(INPUT_INODE, 105578509);
            assert_eq!(
                INPUT_SHA,
                "f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae"
            );
            assert!(INPUT.contains("/epoch144-snapshot-source-20261021-v1/"));
            assert_eq!(PROTECTED_FREE, 4_740_696_923_590);
            assert_eq!(SCHEMA, "jetstreamer-epoch144-serialized-snapshot-clock-v1");
        } else {
            assert_eq!(SLOT, 60_911_751);
            assert_eq!(INPUT_SIZE, 2_741_858_751);
            assert_eq!(INPUT_INODE, 105578537);
            assert_eq!(PROTECTED_FREE, 5_153_080_892_870);
            assert_eq!(SCHEMA, "jetstreamer-epoch140-serialized-snapshot-clock-v1");
        }
    }

    #[test]
    fn complete_digest_vector_and_no_clobber_receipt_failure() {
        let mut reader = HashReader::new(&b"123456789"[..]);
        io::copy(&mut reader, &mut io::sink()).unwrap();
        let (bytes, digest) = reader.finish();
        assert_eq!(bytes, 9);
        assert_eq!(
            digest,
            "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("preserved.json");
        fs::write(&path, b"original").unwrap();
        assert!(write_json(&path, &serde_json::json!({"replace":true})).is_err());
        assert_eq!(fs::read(path).unwrap(), b"original");
    }

    #[test]
    fn guarded_reader_propagates_exhausted_protection_before_reading() {
        let guard = Guard {
            start: Instant::now(),
            floor: u64::MAX,
        };
        let mut reader = Guarded {
            inner: &b"unchanged"[..],
            guard: &guard,
        };
        let mut byte = [0u8; 1];
        assert!(reader.read(&mut byte).is_err());
        assert_eq!(byte, [0]);
    }

    #[test]
    fn serialized_clock_matches_actual_pinned_bank_writer_not_unrelated_genesis() {
        let mut genesis = GenesisConfig::default();
        genesis.ticks_per_slot = 64;
        genesis.poh_config.hashes_per_tick = Some(17);
        let bank = Bank::new(&genesis);
        let dir = tempfile::tempdir().unwrap();
        let storage = bank.get_snapshot_storages();
        let snapshot = add_snapshot(dir.path(), &bank, &storage, SnapshotVersion::V1_2_0).unwrap();
        let path = snapshot.snapshot_file_path;
        let summary = clock(File::open(&path).unwrap(), 0).unwrap();
        assert_eq!(summary.ticks_per_slot, bank.ticks_per_slot());
        assert_eq!(summary.hashes_per_tick, *bank.hashes_per_tick());
        assert_eq!(summary.bank_hash, bank.hash().to_string());
        assert_eq!(summary.last_blockhash, bank.last_blockhash().to_string());
        assert_eq!(summary.capitalization, bank.capitalization());
        assert_eq!(summary.bank_file_bytes, fs::metadata(path).unwrap().len());
        let mut unrelated = genesis.clone();
        unrelated.ticks_per_slot = 32;
        unrelated.poh_config.hashes_per_tick = Some(99);
        assert_ne!(summary.ticks_per_slot, unrelated.ticks_per_slot);
        assert_ne!(
            summary.hashes_per_tick,
            unrelated.poh_config.hashes_per_tick
        );
    }

    #[test]
    fn truncated_bank_and_wrong_slot_fail_closed() {
        assert!(clock(&b"truncated"[..], SLOT).is_err());
        let genesis = GenesisConfig::default();
        let bank = Bank::new(&genesis);
        let dir = tempfile::tempdir().unwrap();
        let storage = bank.get_snapshot_storages();
        let snapshot = add_snapshot(dir.path(), &bank, &storage, SnapshotVersion::V1_2_0).unwrap();
        assert!(clock(File::open(snapshot.snapshot_file_path).unwrap(), SLOT).is_err());
    }

    #[test]
    fn census_rejects_unknown_paths_duplicates_or_missing_metadata() {
        use tar::{Builder, Header};
        let fixture = |paths: &[&str]| {
            let mut tar = Builder::new(Vec::new());
            for path in paths {
                let mut header = Header::new_gnu();
                header.set_size(5);
                header.set_mode(0o444);
                header.set_cksum();
                tar.append_data(&mut header, path, &b"1.2.0"[..]).unwrap();
            }
            tar.into_inner().unwrap()
        };
        assert!(census(&fixture(&["outside"])[..], SLOT).is_err());
        assert!(census(&fixture(&["version", "version"])[..], SLOT).is_err());
        assert!(census(&fixture(&["version"])[..], SLOT).is_err());
    }
}
