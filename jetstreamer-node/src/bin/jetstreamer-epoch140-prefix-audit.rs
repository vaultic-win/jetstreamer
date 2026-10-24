//! Exact, read-only epoch 140 selected-prefix audit. Never creates an archive or
//! ordinary segment manifest, starts replay, or authorizes publication.
use {
    anyhow::{Context, Result, ensure},
    jetstreamer_horizon::{
        account_updates::AccountUpdateView,
        archive::{
            ArchiveProvenance, ArchiveReader, BlockNotification, BootstrapStateKind, BucketHeader,
            Consumption, EntryRecord, EpochMeta, SemanticDigest, SlotKind, SlotVisitor,
        },
        transactions::Transaction,
    },
    jetstreamer_node::segment_manifest::SegmentCheckpointSummary,
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
        path::{Path, PathBuf},
        process::Command,
        time::{Duration, Instant},
    },
};

const SOURCE: &str = "/home/sol/.jetstreamer-private/epochs122-147-20260922-v1/lane-j/private/destination-dbfdd780def396afe992e723ea9c107d1ba5ee00b2bb34854c8cf4291b8f2113/work/root-cohort-140-143/run-828090-1791987085289451499/archives/epoch-140.jet";
const SOURCE_SHA: &str = "65d311f5b96b2c1f2b8ff50ecfbe5da29bcf57573b55b39c48282f6d259a6842";
const WORKER_SHA: &str = "abe395d482174e490833928c7343a33d135d8572096faf873ce3103c35fe520d";
const SNAPSHOT_SHA: &str = "47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1";
const FULL_SHA: &str = "68a96b3e79a62c23a3b9b246bda9fa5d36b937e4e283e09158dd77cdf7f59aa4";
const ANCHORED_SHA: &str = "5155e9952a8270d507686ecf84d1dda2bdf4c97d94db4c1195372eaa32a50afe";
const BOOTSTRAP_SHA: &str = "cba4b8ee834f47dae55a2cc076c9bc68fea04aedc3cb63dc4ef19eeaa707dd14";
const CHECKPOINT_SHA: &str = "8dfb8d6805d6b4d50ab340899447b90449c66117cc33b1af0ca6537b934a3b13";
const EDGE_SHA: &str = "dc4135977d89875b13f365a7888e38ed7fb627fd0c5bcb952c43dcccd3c45fcc";
const NATIVE_SHA: &str = "53f1aa88f8f5f24aed1e291ff02318c102fac3bfb8ececf5c215c9fb70c11b20";
const START: u64 = 60_480_000;
const CUT: u64 = 60_911_751;
const COUNT: u64 = CUT - START + 1;
const RAW_START: u64 = 27_313_300_928;
const RAW_END: u64 = 28_029_693_043;
const ANCHOR: &str = "HpCoYsom9ZgNNAyCG9Ct72GyQaSdeUpeQKPJ5sKNSCRG";
const CUT_HASH: &str = "8yiPTGWeYzuWFQc68fvKdG6Mp16XJTAqxGUtjMdHMFij";
const PROTECTED: u64 = 4_740_696_923_590;
const MAX_SLOT_WRITES: usize = 4_000_000;
const LEGACY_RUNTIME_SECONDS: u64 = 21_600;
const MAX_RUNTIME_SECONDS: u64 = 86_400;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    full: Bound,
    anchored: Bound,
    bootstrap: Bound,
    checkpoint: Bound,
    edge: Bound,
    native: Bound,
    output: PathBuf,
    minimum_free_bytes: u64,
    minimum_available_memory_bytes: u64,
    #[serde(default, deserialize_with = "provided_runtime")]
    maximum_runtime_seconds: Option<u64>,
}

fn provided_runtime<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error> {
    // Distinguish an absent legacy field from explicit null or non-integers.
    u64::deserialize(deserializer).map(Some)
}

fn plan_runtime(plan: &Plan) -> Result<Duration> {
    ensure!(
        plan.unit.starts_with("horizon-epoch140-prefix-audit-")
            && plan.unit.ends_with(".service")
            && plan
                .unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && plan.minimum_free_bytes >= PROTECTED
            && plan.minimum_available_memory_bytes >= 384 * 1024u64.pow(3),
        "wrong audit plan scope/bounds"
    );
    let seconds = match (plan.schema.as_str(), plan.maximum_runtime_seconds) {
        ("jetstreamer-epoch140-private-prefix-audit-plan-v1", None) => LEGACY_RUNTIME_SECONDS,
        ("jetstreamer-epoch140-private-prefix-audit-plan-v2", Some(seconds)) => {
            ensure!(
                (LEGACY_RUNTIME_SECONDS..=MAX_RUNTIME_SECONDS).contains(&seconds)
                    && plan
                        .unit
                        .starts_with("horizon-epoch140-prefix-audit-runtime-")
                    && plan
                        .output
                        .parent()
                        .and_then(Path::file_name)
                        .and_then(|p| p.to_str())
                        == plan
                            .unit
                            .strip_prefix("horizon-")
                            .and_then(|u| u.strip_suffix(".service")),
                "v2 audit requires a bounded runtime and matching distinct unit/output namespace"
            );
            seconds
        }
        _ => anyhow::bail!("wrong audit runtime profile; v1 cannot override its six-hour bound"),
    };
    Ok(Duration::from_secs(seconds))
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct Identity {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}
fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        device: m.dev(),
        inode: m.ino(),
        bytes: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
        links: m.nlink(),
        mtime_seconds: m.mtime(),
        mtime_nanoseconds: m.mtime_nsec(),
        ctime_seconds: m.ctime(),
        ctime_nanoseconds: m.ctime_nsec(),
    }
}
fn is_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn open(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input"
    );
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?)
}
fn bound_bytes(b: &Bound, maximum: u64, immutable: bool) -> Result<Vec<u8>> {
    ensure!(is_sha(&b.sha256), "invalid bound digest");
    let mut f = open(&b.path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.len() <= maximum
            && m.mode() & if immutable { 0o222 } else { 0o022 } == 0,
        "unsafe evidence identity"
    );
    let before = identity(&m);
    let mut bytes = Vec::new();
    (&mut f).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && digest(&bytes) == b.sha256
            && identity(&f.metadata()?) == before
            && identity(&fs::symlink_metadata(&b.path)?) == before,
        "bound evidence changed or digest mismatch"
    );
    Ok(bytes)
}
fn evidence(b: &Bound, expected: &str) -> Result<Value> {
    ensure!(
        b.sha256 == expected,
        "not the exact reviewed epoch 140 evidence"
    );
    Ok(serde_json::from_slice(&bound_bytes(b, 256 * 1024, false)?)?)
}
fn checkpoint(v: &Value) -> Result<SegmentCheckpointSummary> {
    let s = |key| {
        v[key]
            .as_str()
            .context("missing checkpoint string")
            .map(str::to_owned)
    };
    let n = |key| v[key].as_u64().context("missing checkpoint integer");
    ensure!(v["complete"] == true, "incomplete original checkpoint");
    Ok(SegmentCheckpointSummary {
        slot: n("slot")?,
        bank_hash: s("bank_hash")?,
        accounts_hash: s("accounts_hash")?,
        last_blockhash: s("last_blockhash")?,
        capitalization: n("capitalization")?,
        transaction_count: n("transactions")?,
        tick_height: n("tick_height")?,
        slot_complete: true,
        write_count: n("writes")?,
        next_write_version: n("next_write_version")?,
    })
}
fn validate_profile(
    full: &Value,
    anchored: &Value,
    bootstrap: &Value,
    journal: &Value,
    edge: &Value,
    native: &Value,
) -> Result<(SegmentCheckpointSummary, SegmentCheckpointSummary)> {
    ensure!(
        full["schema"] == "horizon-private-transient-full-verification-v2"
            && full["status"] == "passed"
            && full["archive"]["path"] == SOURCE
            && full["archive"]["sha256"] == SOURCE_SHA
            && full["archive"]["whole_source_rehashed_after_reread"] == true
            && full["unit"]["invocation_id"] == "6c553218f2d64309935be94785077ccd"
            && full["result"]["line"]
                == "RESULT: OK (internal only): all stored links verify; the first block is unanchored.",
        "not the independent source-bound full reread"
    );
    ensure!(
        anchored["schema"] == "horizon-private-anchored-chain-verification-v3"
            && anchored["status"] == "passed"
            && anchored["initial_anchor_proven"] == true
            && anchored["complete_prefix_qualification_proven"] == false
            && anchored["archive"]["path"] == SOURCE
            && anchored["archive"]["sha256"] == SOURCE_SHA
            && anchored["full_verification"]["sha256"] == FULL_SHA
            && anchored["command"]["chain"] == true
            && anchored["command"]["full"] == false
            && anchored["command"]["anchor"]["slot"] == START - 1
            && anchored["command"]["anchor"]["blockhash"] == ANCHOR,
        "not the exact separate anchored-chain proof"
    );
    for (v, schema, count) in [
        (
            bootstrap,
            "jetstreamer-epoch140-bootstrap-journal-observation-v1",
            1,
        ),
        (
            journal,
            "jetstreamer-epoch140-checkpoint-journal-observation-v1",
            2,
        ),
    ] {
        ensure!(
            v["schema"] == schema
                && v["producer_invocation_id"] == "b907f4e67095443cb02e9c815ee14499"
                && v["fields_mechanically_extracted"] == true
                && v["checkpoints"].as_array().map(Vec::len) == Some(count),
            "wrong original journal profile"
        );
    }
    let boot = checkpoint(&bootstrap["checkpoints"][0])?;
    let cut = checkpoint(&journal["checkpoints"][0])?;
    ensure!(
        boot.slot == 60_479_583
            && boot.next_write_version == 27_312_586_702
            && boot.write_count == 0
            && cut.slot == CUT
            && cut.next_write_version == RAW_END
            && cut.write_count == 20
            && cut.last_blockhash == CUT_HASH,
        "wrong bootstrap or selected checkpoint"
    );
    let raw = &edge["epoch140"];
    ensure!(
        edge["schema"] == "horizon-private-archive-edge-evidence-v1"
            && raw["archive"] == SOURCE
            && raw["whole_source_sha256"] == SOURCE_SHA
            && raw["runtime_profile"] == "solana-v1.4.25"
            && raw["parent_recorded_worker_executable_sha256"] == WORKER_SHA
            && raw["output_start_slot"] == START
            && raw["observed_first_write_version"] == RAW_START
            && raw["inspected_slot"]["slot"] == CUT
            && raw["inspected_slot"]["observed_next_write_version"] == RAW_END
            && raw["inspected_slot"]["observed_blockhash"] == CUT_HASH
            && raw["inspected_slot"]["observed_write_counts"]
                == json!({"pre":3,"transaction":788,"post":21}),
        "wrong raw-cut evidence"
    );
    ensure!(
        native["schema"] == "jetstreamer-private-epoch140-native-restore-probe-v1"
            && native["passed"] == true
            && native["native_result"]["comparison_passed"] == true
            && native["replay_entries_sent"] == 0
            && native["snapshot_sha256"] == SNAPSHOT_SHA
            && native["worker_sha256"] == WORKER_SHA
            && native["original_journal_sha256"] == CHECKPOINT_SHA
            && native["original_producer_cursor"] == RAW_END,
        "wrong independent native restoration"
    );
    let n = &native["native_result"]["native_checkpoint"];
    ensure!(
        n["slot"] == cut.slot
            && n["bank_hash"] == cut.bank_hash
            && n["accounts_hash"] == cut.accounts_hash
            && n["last_blockhash"] == cut.last_blockhash
            && n["capitalization"] == cut.capitalization
            && n["transaction_count"] == cut.transaction_count
            && n["tick_height"] == cut.tick_height
            && n["slot_complete"] == true
            && n["write_count"] == 0
            && n["next_write_version"] == 28_087_370_409u64,
        "native tuple differs; cursors must remain independent"
    );
    for v in [full, anchored, bootstrap, journal, edge, native] {
        ensure!(
            v["r2_mutations"] == false,
            "evidence has remote mutation authority"
        );
    }
    Ok((boot, cut))
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Serialize)]
struct Counts {
    epoch: u64,
    pre: u64,
    transaction: u64,
    post: u64,
}
impl Counts {
    fn total(self) -> u64 {
        self.epoch + self.pre + self.transaction + self.post
    }
}
struct Audit {
    next_slot: u64,
    current: Option<u64>,
    selected: bool,
    next_write: u64,
    writes: Vec<u64>,
    phases: Counts,
    cut_phases: Option<Counts>,
    totals: Counts,
    last_hash: String,
    last_block_slot: u64,
    epoch_seen: bool,
    digest: SemanticDigest,
    error: Option<String>,
}
impl Audit {
    fn new() -> Self {
        Self {
            next_slot: START,
            current: None,
            selected: false,
            next_write: RAW_START,
            writes: Vec::new(),
            phases: Counts::default(),
            cut_phases: None,
            totals: Counts::default(),
            last_hash: ANCHOR.into(),
            last_block_slot: START - 1,
            epoch_seen: false,
            digest: SemanticDigest::new(),
            error: None,
        }
    }
    fn fail(&mut self, message: &str) {
        if self.error.is_none() {
            self.error = Some(message.into());
        }
    }
    fn flush_slot(&mut self) {
        if self.error.is_some() {
            return;
        }
        self.writes.sort_unstable();
        for &raw in &self.writes {
            if raw != self.next_write || raw >= RAW_END {
                self.error =
                    Some("prefix raw write range has a gap,duplicate or out-of-bound value".into());
                return;
            }
            self.next_write += 1;
        }
        if self.current == Some(CUT) {
            self.cut_phases = Some(self.phases);
        }
        self.writes.clear();
        self.phases = Counts::default();
    }
    fn accept(&mut self, slot: u64, raw: u64) {
        if self.error.is_some() {
            return;
        }
        if self.current != Some(slot) || self.writes.len() >= MAX_SLOT_WRITES {
            self.fail("wrong slot or per-slot write limit exceeded");
            return;
        }
        self.writes.push(raw);
    }
    fn bucket(&mut self, h: &BucketHeader) -> Result<()> {
        ensure!(
            h.first_slot == self.next_slot && h.poh_start_hash.to_string() == self.last_hash,
            "selected prefix bucket coverage or incoming anchor mismatch"
        );
        Ok(())
    }
    fn finish(mut self) -> Result<Value> {
        self.flush_slot();
        ensure!(
            self.error.is_none(),
            "{}",
            self.error.as_deref().unwrap_or("audit error")
        );
        ensure!(
            self.next_slot == CUT + 1
                && self.next_write == RAW_END
                && self.epoch_seen
                && self.last_hash == CUT_HASH
                && self.last_block_slot == CUT,
            "prefix extent, raw cursor, epoch metadata or final PoH hash mismatch"
        );
        ensure!(
            self.cut_phases
                == Some(Counts {
                    epoch: 0,
                    pre: 3,
                    transaction: 788,
                    post: 21
                }),
            "cut phase counts differ"
        );
        ensure!(
            self.totals.total() == RAW_END - RAW_START,
            "selected update total differs from raw range"
        );
        Ok(
            json!({"first_slot":START,"last_slot":CUT,"slot_count":COUNT,
            "raw_write_versions":{"start":RAW_START,"end_exclusive":RAW_END},
            "all_update_phases":self.totals,"cut_phases":self.cut_phases,
            "wire_event_semantic_sha256":hex(&self.digest.finish()?),
            "incoming_parent_slot":START-1,"incoming_blockhash":ANCHOR,"terminal_blockhash":self.last_hash,
            "per_slot_versions_checked_without_reordering_wire_events":true}),
        )
    }
}
impl SlotVisitor for Audit {
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        self.flush_slot();
        self.selected = slot <= CUT;
        self.current = None;
        if !self.selected || self.error.is_some() {
            return;
        }
        if slot != self.next_slot {
            self.fail("selected slots are not contiguous");
            return;
        }
        if [START, CUT].contains(&slot) && kind != SlotKind::Block {
            self.fail("selected first and checkpoint slots must be blocks");
            return;
        }
        self.next_slot += 1;
        self.current = Some(slot);
        self.digest.on_slot_start(slot, kind);
    }
    fn on_epoch(&mut self, m: &EpochMeta) {
        if !self.selected || self.error.is_some() {
            return;
        }
        if self.epoch_seen
            || self.current != Some(START)
            || m.epoch != 140
            || m.start_slot != START
            || m.slot_count != 432_000
            || m.first_block_slot != START
        {
            self.fail("wrong selected epoch metadata");
            return;
        }
        self.epoch_seen = true;
        self.digest.on_epoch(m);
        for (u, _) in m.updates.iter() {
            self.accept(START, u.write_version);
            self.phases.epoch += 1;
            self.totals.epoch += 1;
        }
    }
    fn on_pre_account_update(&mut self, slot: u64, u: &AccountUpdateView<'_>) {
        if !self.selected || self.error.is_some() {
            return;
        }
        self.accept(slot, u.write_version);
        self.phases.pre += 1;
        self.totals.pre += 1;
        self.digest.on_pre_account_update(slot, u);
    }
    fn on_transaction(&mut self, slot: u64, index: u32, tx: &Transaction) {
        if !self.selected || self.error.is_some() {
            return;
        }
        for u in tx.account_updates() {
            self.accept(slot, u.write_version);
            self.phases.transaction += 1;
            self.totals.transaction += 1;
        }
        self.digest.on_transaction(slot, index, tx);
    }
    fn on_post_account_update(&mut self, slot: u64, u: &AccountUpdateView<'_>) {
        if !self.selected || self.error.is_some() {
            return;
        }
        self.accept(slot, u.write_version);
        self.phases.post += 1;
        self.totals.post += 1;
        self.digest.on_post_account_update(slot, u);
    }
    fn on_block(&mut self, n: &BlockNotification, e: &[EntryRecord]) {
        if !self.selected || self.error.is_some() {
            return;
        }
        if let BlockNotification::Block(m) = n {
            if Some(m.slot) != self.current
                || m.parent_slot != self.last_block_slot
                || m.parent_blockhash.to_string() != self.last_hash
            {
                self.fail("selected stored blockhash link differs");
                return;
            }
            self.last_hash = m.blockhash.to_string();
            self.last_block_slot = m.slot;
        }
        self.digest.on_block(n, e);
    }
    fn consumption(&self) -> Consumption {
        Consumption::all().without_block_account_update_arenas()
    }
}

fn available(path: &Path) -> Result<u64> {
    let p = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .context("free-space overflow")
}
struct Guard {
    started: Instant,
    last: Instant,
    floor: u64,
    runtime: Duration,
}
fn check_runtime(elapsed: Duration, limit: Duration) -> std::io::Result<()> {
    if elapsed > limit {
        return Err(std::io::Error::other(format!(
            "private prefix audit runtime guard tripped: elapsed {elapsed:?}, limit {limit:?}"
        )));
    }
    Ok(())
}
fn check_reserve(free: u64, floor: u64) -> std::io::Result<()> {
    if free < floor {
        return Err(std::io::Error::other(format!(
            "private prefix audit reserve guard tripped: available {free} bytes, floor {floor} bytes"
        )));
    }
    Ok(())
}
impl Guard {
    fn check(&mut self) -> std::io::Result<()> {
        if self.last.elapsed() < Duration::from_secs(1) {
            return Ok(());
        }
        self.last = Instant::now();
        check_runtime(self.started.elapsed(), self.runtime)?;
        check_reserve(
            available(Path::new("/home/sol")).map_err(std::io::Error::other)?,
            self.floor,
        )
    }
}
struct Guarded {
    file: File,
    guard: Guard,
}
impl Read for Guarded {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.guard.check()?;
        self.file.read(b)
    }
}
impl Seek for Guarded {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        self.guard.check()?;
        self.file.seek(p)
    }
}
fn hash_file(f: &mut impl Read) -> Result<String> {
    let mut hash = Sha256::new();
    let mut bytes = vec![0; 1024 * 1024];
    loop {
        let n = f.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn source_identity(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && identity(m)
                == Identity {
                    device: 64512,
                    inode: 99811416,
                    bytes: 103138915297,
                    uid: 1001,
                    gid: 1003,
                    mode: 0o440,
                    links: 1,
                    mtime_seconds: 1792366350,
                    mtime_nanoseconds: 258158104,
                    ctime_seconds: 1792366350,
                    ctime_nanoseconds: 292158293
                },
        "original source identity changed"
    );
    Ok(())
}
fn systemd(unit: &str) -> Result<BTreeMap<String, String>> {
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "--property=LoadState,ActiveState,MainPID,InvocationID,NRestarts,Restart",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384 && out.stderr.is_empty(),
        "unit identity query failed"
    );
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("malformed unit fields")?;
        ensure!(
            fields.insert(k.into(), v.into()).is_none(),
            "duplicate unit identity field"
        );
    }
    Ok(fields)
}
fn authenticate(unit: &str) -> Result<String> {
    let iid = env::var("INVOCATION_ID").context("persistent systemd invocation required")?;
    ensure!(
        iid.len() == 32 && is_sha(&format!("{iid}{iid}")),
        "invalid invocation identity"
    );
    let fields = systemd(unit)?;
    let get = |k| fields.get(k).map(String::as_str).unwrap_or("");
    ensure!(
        get("LoadState") == "loaded"
            && matches!(get("ActiveState"), "active" | "activating")
            && get("MainPID") == std::process::id().to_string()
            && get("InvocationID") == iid
            && get("NRestarts") == "0"
            && get("Restart") == "no",
        "wrong audit service identity"
    );
    Ok(iid)
}
fn output_parent(p: &Path) -> Result<()> {
    ensure!(
        p.file_name().and_then(|s| s.to_str()) == Some("prefix-audit.json"),
        "wrong result name"
    );
    let parent = p.parent().context("output parent absent")?;
    let leaf = parent
        .file_name()
        .and_then(|s| s.to_str())
        .context("bad output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && leaf.starts_with("epoch140-prefix-audit-")
            && leaf.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0
            && m.dev() == 64512,
        "output must be a distinct root-private campaign directory"
    );
    ensure!(
        fs::read_dir(parent)?.next().is_none(),
        "audit result directory must be empty"
    );
    Ok(())
}
fn write_new(p: &Path, v: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(v)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 65536, "result exceeded small receipt bound");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    File::open(p.parent().context("no parent")?)?.sync_all()?;
    Ok(())
}
fn run(args: &[String]) -> Result<()> {
    ensure!(
        matches!(args.len(), 5 | 6)
            && args[1] == "--plan-sha256"
            && args[3] == "--self-sha256"
            && (args.len() == 5 || args[5] == "--check-only"),
        "usage: jetstreamer-epoch140-prefix-audit PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let exe = fs::read_link("/proc/self/exe")?;
    bound_bytes(
        &Bound {
            path: exe,
            sha256: args[4].clone(),
        },
        256 * 1024 * 1024,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&bound_bytes(
        &Bound {
            path: PathBuf::from(&args[0]),
            sha256: args[2].clone(),
        },
        65536,
        true,
    )?)?;
    ensure!(
        fs::symlink_metadata(&args[0])?.mode() & 0o077 == 0,
        "audit plan must be owner-only"
    );
    let runtime = plan_runtime(&plan)?;
    let (boot, cut) = validate_profile(
        &evidence(&plan.full, FULL_SHA)?,
        &evidence(&plan.anchored, ANCHORED_SHA)?,
        &evidence(&plan.bootstrap, BOOTSTRAP_SHA)?,
        &evidence(&plan.checkpoint, CHECKPOINT_SHA)?,
        &evidence(&plan.edge, EDGE_SHA)?,
        &evidence(&plan.native, NATIVE_SHA)?,
    )?;
    output_parent(&plan.output)?;
    let input = open(Path::new(SOURCE))?;
    source_identity(&input.metadata()?)?;
    input.lock_shared()?;
    let mem = fs::read_to_string("/proc/meminfo")?;
    let kib: u64 = mem
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .context("missing MemAvailable")?
        .split_whitespace()
        .next()
        .context("bad MemAvailable")?
        .parse()?;
    ensure!(
        kib.checked_mul(1024)
            .context("memory arithmetic overflow")?
            >= plan.minimum_available_memory_bytes,
        "prefix audit memory admission failed"
    );
    let free_before = available(Path::new("/home/sol"))?;
    let receipt_floor = plan
        .minimum_free_bytes
        .checked_add(16 * 1024 * 1024)
        .context("receipt reserve overflow")?;
    ensure!(
        free_before >= receipt_floor,
        "prefix audit reserve admission failed"
    );
    let mut reader = ArchiveReader::open(input.try_clone()?)?;
    let h = reader.header().clone();
    ensure!(
        h.epoch == 140
            && h.slot_start == START
            && h.slot_count == 432_000
            && h.format_version == 2
            && reader.has_complete_slot_coverage()?,
        "wrong original source range/layout"
    );
    let Some(ArchiveProvenance::V2(provenance)) = reader.provenance()? else {
        anyhow::bail!("source must retain actual uninterrupted V2 provenance");
    };
    ensure!(
        provenance.base.runtime_profile == "solana-v1.4.25"
            && hex(&provenance.worker_executable_sha256) == WORKER_SHA
            && provenance.base.bootstrap_state_kind == BootstrapStateKind::SnapshotArchive
            && provenance.base.bootstrap_slot == boot.slot
            && provenance.base.bootstrap_state_hash.to_string() == boot.accounts_hash,
        "source provenance differs from journal/worker"
    );
    drop(reader);
    if args.len() == 6 {
        println!(
            "exact prefix profile, source identity and admission bindings passed; runtime_seconds={}; no whole hash, decode, output or mutation",
            runtime.as_secs()
        );
        return Ok(());
    }
    let invocation = authenticate(&plan.unit)?;
    let started = Instant::now();
    let mut source = Guarded {
        file: input,
        guard: Guard {
            started,
            last: Instant::now() - Duration::from_secs(2),
            floor: plan.minimum_free_bytes,
            runtime,
        },
    };
    eprintln!("epoch140 selected-prefix audit phase=whole-source-hash-before");
    source.seek(SeekFrom::Start(0))?;
    ensure!(
        hash_file(&mut source)? == SOURCE_SHA,
        "whole source hash changed before prefix audit"
    );
    source.seek(SeekFrom::Start(0))?;
    let mut reader = ArchiveReader::open(&mut source)?;
    reader.verify_chain = true;
    let mut audit = Audit::new();
    eprintln!(
        "epoch140 selected-prefix audit phase=selected-prefix-decode first={START} last={CUT}"
    );
    for index in 0..reader.bucket_count() {
        if reader.bucket_index()[index].first_slot > CUT {
            break;
        }
        reader.read_bucket_with_header(index, &mut audit, |h, a| {
            a.bucket(h).map_err(|_| {
                jetstreamer_horizon::archive::ArchiveFormatError::InvalidContainerLayout(
                    "selected prefix bucket anchor/coverage mismatch",
                )
            })
        })?;
        ensure!(
            audit.error.is_none(),
            "{}",
            audit.error.as_deref().unwrap_or("prefix audit failed")
        );
        if index % 128 == 0 {
            eprintln!(
                "epoch140 selected-prefix audit bucket={index} next_slot={} elapsed_seconds={}",
                audit.next_slot,
                started.elapsed().as_secs()
            );
        }
    }
    let selection = audit.finish()?;
    drop(reader);
    eprintln!(
        "epoch140 selected-prefix audit phase=whole-source-hash-after elapsed_seconds={}",
        started.elapsed().as_secs()
    );
    source.seek(SeekFrom::Start(0))?;
    ensure!(
        hash_file(&mut source)? == SOURCE_SHA,
        "whole source hash changed after prefix audit"
    );
    source_identity(&source.file.metadata()?)?;
    source_identity(&fs::symlink_metadata(SOURCE)?)?;
    ensure!(
        authenticate(&plan.unit)? == invocation,
        "audit identity changed"
    );
    output_parent(&plan.output)?;
    let free_after = available(Path::new("/home/sol"))?;
    ensure!(free_after >= receipt_floor, "result reserve gate failed");
    write_new(
        &plan.output,
        &json!({"schema":"jetstreamer-epoch140-private-selected-prefix-audit-v1","epoch":140,
        "unit":plan.unit,"invocation_id":invocation,"self_sha256":args[4],"plan_sha256":args[2],
        "plan_schema":plan.schema,"maximum_runtime_seconds":runtime.as_secs(),
        "source":{"path":SOURCE,"sha256":SOURCE_SHA,"identity":identity(&source.file.metadata()?),
            "original_declared_slot_count":432000,"whole_hash_verified_before_and_after":true,
            "provenance":{"version":2,"generation_profile":provenance.base.generation_profile,
                "runtime_profile":provenance.base.runtime_profile,"runtime_revision":provenance.base.runtime_revision,
                "runtime_toolchain":provenance.base.runtime_toolchain,"runtime_admission":provenance.base.runtime_admission as u8,
                "worker_executable_sha256":hex(&provenance.worker_executable_sha256),"genesis_hash":provenance.base.genesis_hash.to_string(),
                "bootstrap_state_kind":"snapshot_archive","bootstrap_slot":provenance.base.bootstrap_slot,
                "bootstrap_state_hash":provenance.base.bootstrap_state_hash.to_string(),
                "requested_slot_start":provenance.base.requested_slot_start,"requested_slot_count":provenance.base.requested_slot_count,
                "transaction_metadata":{"boundary_slot":provenance.base.transaction_metadata.boundary_slot,
                    "before_boundary":provenance.base.transaction_metadata.before_boundary as u8,
                    "at_or_after_boundary":provenance.base.transaction_metadata.at_or_after_boundary as u8}}},
        "selection":selection,"original_bootstrap":boot,"selected_terminal":cut,
        "independent_native_cursor":28087370409u64,"native_snapshot_sha256":SNAPSHOT_SHA,
        "evidence":{"full":plan.full,"anchored":plan.anchored,"bootstrap":plan.bootstrap,"checkpoint":plan.checkpoint,"edge":plan.edge,"native":plan.native},
        "available_bytes_before":free_before,"available_bytes_after":free_after,"minimum_free_bytes":plan.minimum_free_bytes,
        "elapsed_seconds":started.elapsed().as_secs(),"status":"passed",
        "ordinary_archive_manifest":false,"selected_prefix_mapping_proven":true,"complete_prefix_qualification_proven":false,
        "source_full_poh_and_anchor_proofs_preserved":true,"new_independent_full_poh_scan_performed":false,
        "archive_modified":false,"archive_created":false,"prefix_copy_created":false,"sidecar_created":false,
        "replay_launch_authorized":false,"assembly_authorized":false,"publication_authorized":false,"local_retirement_authorized":false,
        "remote_mutations":false,"r2_mutations":false}),
    )?;
    println!(
        "complete selected-prefix audit durable; no ordinary manifest, replay, assembly or publication authority"
    );
    Ok(())
}
fn main() {
    if let Err(e) = run(&env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_fixture(schema: &str, seconds: Option<u64>) -> Value {
        let bound = || json!({"path":"/unchanged-evidence","sha256":"0".repeat(64)});
        let mut value = json!({
            "schema":schema,
            "unit":"horizon-epoch140-prefix-audit-runtime-test.service",
            "full":bound(),"anchored":bound(),"bootstrap":bound(),
            "checkpoint":bound(),"edge":bound(),"native":bound(),
            "output":"/home/sol/.jetstreamer-private/epoch140-prefix-audit-runtime-test/prefix-audit.json",
            "minimum_free_bytes":PROTECTED,
            "minimum_available_memory_bytes":384 * 1024u64.pow(3)
        });
        if let Some(seconds) = seconds {
            value["maximum_runtime_seconds"] = json!(seconds);
        }
        value
    }

    #[test]
    fn legacy_runtime_remains_fixed_and_rejects_overrides() {
        let schema = "jetstreamer-epoch140-private-prefix-audit-plan-v1";
        let plan: Plan = serde_json::from_value(runtime_fixture(schema, None)).unwrap();
        assert_eq!(plan_runtime(&plan).unwrap(), Duration::from_secs(21_600));
        for seconds in [21_600, 86_400, u64::MAX] {
            let plan: Plan =
                serde_json::from_value(runtime_fixture(schema, Some(seconds))).unwrap();
            assert!(plan_runtime(&plan).is_err());
        }
    }

    #[test]
    fn explicit_runtime_is_bounded_and_requires_its_new_profile_namespace() {
        let schema = "jetstreamer-epoch140-private-prefix-audit-plan-v2";
        for seconds in [21_600, 43_200, 86_400] {
            let plan: Plan =
                serde_json::from_value(runtime_fixture(schema, Some(seconds))).unwrap();
            assert_eq!(plan_runtime(&plan).unwrap(), Duration::from_secs(seconds));
        }
        for seconds in [0, 21_599, 86_401, u64::MAX] {
            let plan: Plan =
                serde_json::from_value(runtime_fixture(schema, Some(seconds))).unwrap();
            assert!(plan_runtime(&plan).is_err());
        }
        let plan: Plan = serde_json::from_value(runtime_fixture(schema, None)).unwrap();
        assert!(plan_runtime(&plan).is_err());
        let mut value = runtime_fixture(schema, Some(86_400));
        value["unit"] = json!("horizon-epoch140-prefix-audit-reuse-test.service");
        let plan: Plan = serde_json::from_value(value).unwrap();
        assert!(plan_runtime(&plan).is_err());
    }

    #[test]
    fn runtime_profile_never_weakens_disk_memory_or_unit_bounds() {
        let original = runtime_fixture(
            "jetstreamer-epoch140-private-prefix-audit-plan-v2",
            Some(86_400),
        );
        for (field, value) in [
            ("minimum_free_bytes", json!(PROTECTED - 1)),
            (
                "minimum_available_memory_bytes",
                json!(384 * 1024u64.pow(3) - 1),
            ),
            (
                "unit",
                json!("horizon-epoch140-prefix-audit-runtime-test.service;other"),
            ),
            (
                "output",
                json!(
                    "/home/sol/.jetstreamer-private/epoch140-prefix-audit-reuse-test/prefix-audit.json"
                ),
            ),
            ("schema", json!("unqualified-profile")),
        ] {
            let mut bad = original.clone();
            bad[field] = value;
            let plan: Plan = serde_json::from_value(bad).unwrap();
            assert!(plan_runtime(&plan).is_err(), "accepted weakened {field}");
        }
        for value in [Value::Null, json!("86400"), json!(-1), json!(86_400.5)] {
            let mut bad = original.clone();
            bad["maximum_runtime_seconds"] = value;
            assert!(serde_json::from_value::<Plan>(bad).is_err());
        }
    }

    #[test]
    fn runtime_and_reserve_guards_have_distinct_exact_diagnostics() {
        let limit = Duration::from_secs(21_600);
        check_runtime(limit, limit).unwrap();
        let runtime = check_runtime(limit + Duration::from_millis(1), limit)
            .unwrap_err()
            .to_string();
        assert!(runtime.contains("runtime guard tripped"));
        assert!(runtime.contains("21600.001s") && runtime.contains("21600s"));
        assert!(!runtime.contains("reserve"));
        check_reserve(PROTECTED, PROTECTED).unwrap();
        let reserve = check_reserve(PROTECTED - 1, PROTECTED)
            .unwrap_err()
            .to_string();
        assert!(reserve.contains("reserve guard tripped"));
        assert!(reserve.contains(&(PROTECTED - 1).to_string()));
        assert!(reserve.contains(&PROTECTED.to_string()));
        assert!(!reserve.contains("runtime"));
    }

    #[test]
    fn selected_cut_keeps_all_phases_and_ignores_later_frames_in_its_bucket() {
        use jetstreamer_horizon::{
            archive::{ArchiveWriter, ArchiveWriterConfig},
            block_metas::BlockMeta,
        };
        let mut writer =
            ArchiveWriter::new(Vec::new(), 140, CUT, 2, ArchiveWriterConfig::default()).unwrap();
        let anchor: solana_hash::Hash = ANCHOR.parse().unwrap();
        writer.preserve_initial_poh_anchor(CUT, anchor).unwrap();
        writer.begin_slot(CUT).unwrap();
        let view = |write_version| AccountUpdateView {
            pubkey: solana_address::Address::new_from_array([1; 32]),
            lamports: 1,
            owner: solana_address::Address::new_from_array([2; 32]),
            executable: false,
            rent_epoch: 0,
            write_version,
            data: b"unchanged",
        };
        let mut raw = RAW_END - 812;
        for _ in 0..3 {
            writer.write_orphan_update(&view(raw)).unwrap();
            raw += 1;
        }
        for count in [128, 128, 128, 128, 128, 128, 20] {
            let mut tx = Transaction::new_boxed();
            tx.signatures.push(solana_signature::Signature::default());
            for _ in 0..count {
                tx.push_account_update(&view(raw)).unwrap();
                raw += 1;
            }
            writer.write_transaction(&tx).unwrap();
        }
        for _ in 0..21 {
            writer.write_orphan_update(&view(raw)).unwrap();
            raw += 1;
        }
        let mut block = BlockMeta::new_boxed();
        block.slot = CUT;
        block.parent_slot = CUT - 1;
        block.parent_blockhash = anchor;
        block.blockhash = CUT_HASH.parse().unwrap();
        block.entry_count = 1;
        block.executed_transaction_count = 7;
        writer
            .end_slot(
                &block,
                &[EntryRecord {
                    num_hashes: 1,
                    tx_count: 7,
                }],
            )
            .unwrap();
        writer.write_skipped_slot(CUT + 1).unwrap();
        let source = writer.finish().unwrap().0;
        let mut reader = ArchiveReader::open(std::io::Cursor::new(source)).unwrap();
        reader.verify_chain = true;
        // Exercise the final-bucket transition after the preceding prefix's
        // state; production always initializes at START with an empty digest.
        let mut audit = Audit::new();
        audit.next_slot = CUT;
        audit.next_write = RAW_END - 812;
        audit.epoch_seen = true;
        audit.last_block_slot = CUT - 1;
        audit.totals.pre = RAW_END - RAW_START - 812;
        reader
            .read_bucket_with_header(0, &mut audit, |h, a| {
                a.bucket(h).map_err(|_| {
                    jetstreamer_horizon::archive::ArchiveFormatError::InvalidContainerLayout(
                        "test bucket",
                    )
                })
            })
            .unwrap();
        assert!(!audit.selected);
        let result = audit.finish().unwrap();
        assert_eq!(
            result["cut_phases"],
            json!({"epoch":0,"pre":3,"transaction":788,"post":21})
        );
        assert_eq!(raw, RAW_END);
        assert_eq!(result["slot_count"], COUNT);
    }

    fn profile() -> [Value; 6] {
        let full = json!({"schema":"horizon-private-transient-full-verification-v2","status":"passed",
            "archive":{"path":SOURCE,"sha256":SOURCE_SHA,"whole_source_rehashed_after_reread":true},
            "unit":{"invocation_id":"6c553218f2d64309935be94785077ccd"},
            "result":{"line":"RESULT: OK (internal only): all stored links verify; the first block is unanchored."},"r2_mutations":false});
        let anchored = json!({"schema":"horizon-private-anchored-chain-verification-v3","status":"passed",
            "initial_anchor_proven":true,"complete_prefix_qualification_proven":false,
            "archive":{"path":SOURCE,"sha256":SOURCE_SHA},"full_verification":{"sha256":FULL_SHA},
            "command":{"chain":true,"full":false,"anchor":{"slot":START-1,"blockhash":ANCHOR}},"r2_mutations":false});
        let boot = json!({"slot":60479583,"bank_hash":"pHAJsPLpPS1yeKXx745oj45bWF6947LggZCNd7aox4r",
            "accounts_hash":"J8K4RVWeRvQavXqwbhA58KCWHKWGaRENqALCed65rfkZ",
            "last_blockhash":"Axv1hLgqindhdXQCDmFSNg5HTSMM4CYU8sdnvtzXoEFR",
            "capitalization":488588429281363761u64,"transactions":9214190271u64,"tick_height":3870693376u64,
            "complete":true,"writes":0,"next_write_version":27312586702u64});
        let cut = json!({"slot":CUT,"bank_hash":"BWG9oqUgYLKYA4sFwQRoFgcyQKTNuZaYatH9piAtGRiU",
            "accounts_hash":"GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR","last_blockhash":CUT_HASH,
            "capitalization":488588165537070640u64,"transactions":9398636535u64,"tick_height":3898352128u64,
            "complete":true,"writes":20,"next_write_version":RAW_END});
        let bootstrap = json!({"schema":"jetstreamer-epoch140-bootstrap-journal-observation-v1",
            "producer_invocation_id":"b907f4e67095443cb02e9c815ee14499","fields_mechanically_extracted":true,
            "checkpoints":[boot],"r2_mutations":false});
        let journal = json!({"schema":"jetstreamer-epoch140-checkpoint-journal-observation-v1",
            "producer_invocation_id":"b907f4e67095443cb02e9c815ee14499","fields_mechanically_extracted":true,
            "checkpoints":[cut.clone(),{}],"r2_mutations":false});
        let edge = json!({"schema":"horizon-private-archive-edge-evidence-v1","epoch140":{
            "archive":SOURCE,"whole_source_sha256":SOURCE_SHA,"runtime_profile":"solana-v1.4.25",
            "parent_recorded_worker_executable_sha256":WORKER_SHA,"output_start_slot":START,
            "observed_first_write_version":RAW_START,"inspected_slot":{"slot":CUT,"observed_next_write_version":RAW_END,
                "observed_blockhash":CUT_HASH,"observed_write_counts":{"pre":3,"transaction":788,"post":21}}},"r2_mutations":false});
        let native = json!({"schema":"jetstreamer-private-epoch140-native-restore-probe-v1","passed":true,
            "native_result":{"comparison_passed":true,"native_checkpoint":{"slot":CUT,
                "bank_hash":cut["bank_hash"],"accounts_hash":cut["accounts_hash"],"last_blockhash":CUT_HASH,
                "capitalization":cut["capitalization"],"transaction_count":cut["transactions"],"tick_height":cut["tick_height"],
                "slot_complete":true,"write_count":0,"next_write_version":28087370409u64}},
            "replay_entries_sent":0,"snapshot_sha256":SNAPSHOT_SHA,"worker_sha256":WORKER_SHA,
            "original_journal_sha256":CHECKPOINT_SHA,"original_producer_cursor":RAW_END,"r2_mutations":false});
        [full, anchored, bootstrap, journal, edge, native]
    }
    fn validate(v: &[Value; 6]) -> Result<(SegmentCheckpointSummary, SegmentCheckpointSummary)> {
        validate_profile(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5])
    }
    #[test]
    fn exact_distinct_profiles_bind_large_consensus_tuple() {
        let (boot, cut) = validate(&profile()).unwrap();
        assert_eq!(boot.slot, 60479583);
        assert_eq!(cut.slot, CUT);
        assert_eq!(cut.capitalization, 488588165537070640);
        assert_eq!(cut.next_write_version, RAW_END);
    }
    #[test]
    fn profile_mutations_never_relabel_full_receipts_or_force_cursor_equality() {
        for (index, pointer, value) in [
            (0, "/schema", json!("horizon-private-full-verification-v1")),
            (0, "/archive/sha256", json!("bad")),
            (1, "/initial_anchor_proven", json!(false)),
            (1, "/command/anchor/blockhash", json!("bad")),
            (1, "/command/full", json!(true)),
            (
                2,
                "/checkpoints/0/next_write_version",
                json!(27312586703u64),
            ),
            (3, "/checkpoints/0/writes", json!(21)),
            (
                4,
                "/epoch140/inspected_slot/observed_write_counts/post",
                json!(20),
            ),
            (
                5,
                "/native_result/native_checkpoint/capitalization",
                json!(488588165537070641u64),
            ),
            (
                5,
                "/native_result/native_checkpoint/next_write_version",
                json!(RAW_END),
            ),
            (5, "/native_result/native_checkpoint/write_count", json!(20)),
            (5, "/replay_entries_sent", json!(1)),
            (5, "/worker_sha256", json!("bad")),
            (5, "/r2_mutations", json!(true)),
        ] {
            let mut p = profile();
            *p[index].pointer_mut(pointer).unwrap() = value;
            assert!(validate(&p).is_err(), "accepted {index}:{pointer}");
        }
    }
    #[test]
    fn per_slot_permutations_are_not_wire_reordering_or_cursor_equality() {
        let mut audit = Audit::new();
        audit.current = Some(START);
        audit.writes = vec![RAW_START + 2, RAW_START, RAW_START + 1];
        audit.flush_slot();
        assert!(audit.error.is_none());
        assert_eq!(audit.next_write, RAW_START + 3);
        assert_ne!(RAW_END, 28_087_370_409);
    }
    #[test]
    fn raw_gaps_duplicates_and_bounds_fail_closed() {
        for writes in [
            vec![RAW_START + 1],
            vec![RAW_START, RAW_START],
            vec![RAW_END],
        ] {
            let mut audit = Audit::new();
            audit.current = Some(START);
            audit.writes = writes;
            audit.flush_slot();
            assert!(audit.error.is_some());
        }
    }
    #[test]
    fn missing_prefix_and_wrong_slots_never_finish() {
        assert!(Audit::new().finish().is_err());
        let mut audit = Audit::new();
        audit.on_slot_start(START + 1, SlotKind::Skipped);
        assert!(audit.finish().is_err());
    }
    #[test]
    fn independent_large_consensus_integers_remain_u64() {
        let c=checkpoint(&json!({"slot":CUT,"bank_hash":"bank","accounts_hash":"accounts","last_blockhash":CUT_HASH,
            "capitalization":488588165537070640u64,"transactions":9398636535u64,"tick_height":3898352128u64,
            "complete":true,"writes":20,"next_write_version":RAW_END})).unwrap();
        assert_eq!(c.capitalization, 488588165537070640);
        assert_eq!(c.next_write_version, RAW_END);
    }
}
