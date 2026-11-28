//! Five exact old220 staged peers. Read-only source candidate; no retirement authority.
//! This does not alter the index utility's fixed12/no_triggers or qualify global aliases.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
};
const OWNER: &str = "/home/ubuntu/.jetstreamer-private/adaptive-220-232-v1";
const REVIEW: &str = "/var/lib/jetstreamer/horizon-old220-peers1012-review-v1/review.json";
const SPEC_BYTES: &[u8] = include_bytes!("../specs.json");
const COMMANDS: [&str; 7] = [
    "ExecCondition",
    "ExecStartPre",
    "ExecStart",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
];
const ROOTS: [&str; 8] = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/run/systemd/transient",
    "/run/systemd/generator",
    "/run/systemd/generator.early",
    "/run/systemd/generator.late",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
];
const PROPERTIES: &str = "Id,Names,LoadState,ActiveState,SubState,FragmentPath,DropInPaths,Job,Transient,InvocationID,MainPID,ControlPID,ControlGroup,NRestarts,Restart,Result,ExecMainCode,ExecMainStatus,OnSuccess,OnFailure,Triggers,TriggeredBy,User,Group";
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn iid(s: &str) -> bool {
    s != "00000000000000000000000000000000"
        && s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn ordinary(s: &str) -> bool {
    Path::new(s).is_absolute()
        && Path::new(s)
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub path: String,
    pub canonical: String,
    pub sha256: String,
    pub kind: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub bytes: u64,
    pub single_link: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixture: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub bytes: u64,
    pub nlink: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}
impl Stamp {
    fn of(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            bytes: m.len(),
            nlink: m.nlink(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
        }
    }
}
/// Backend reports descriptor and named-path stamps from the SAME bounded read.
/// Main's adapter must use read_file below or preserve its complete behavior.
#[derive(Clone)]
pub struct ReadFile {
    pub bytes: Vec<u8>,
    pub before: Stamp,
    pub after: Stamp,
    pub named: Stamp,
    pub canonical: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub program: &'static str,
    pub argv: Vec<String>,
}
#[derive(Clone, Debug)]
pub struct Reply {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}
pub trait Backend {
    fn read(&mut self, pin: &Pin) -> Result<ReadFile>;
    fn query(&mut self, request: &Request) -> Result<Reply>;
    /// None is positively ENOENT only; access/read/type errors must propagate.
    /// Check safe Root custody and a stable directory FD/named identity.
    fn directory_names(&mut self, directory: &str) -> Result<Option<Vec<String>>>;
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    unit: String,
    role: String,
    recipe: Pin,
    dropins: Vec<Pin>,
    dependencies: Vec<Pin>,
    expected_start: Vec<String>,
    expected_environment: Vec<String>,
    expected_unset: Vec<String>,
    expected_conditions: Vec<(String, bool, bool, String)>,
    epoch: Option<u64>,
}
fn specs() -> Result<Vec<Spec>> {
    Ok(serde_json::from_slice(SPEC_BYTES)?)
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub evidence: Pin,
    pub unit_pointer: String,
    pub iid_pointer: String,
    pub original_iid: String,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct RowReview {
    unit: String,
    role: String,
    origin: Origin,
    bootstrap_interpreter: Option<Pin>,
    complete_selected_cache_readset_reviewed: bool,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Review {
    schema: String,
    source_specs_sha256: String,
    selected_owner: String,
    selected_epoch: u64,
    selected_inodes: Vec<u64>,
    rows: Vec<RowReview>,
    data_retirement_authorized: bool,
    global_alias_closure_qualified: bool,
}
/// An independently reviewed Root-sealed fixed-path document; supplied by Main's
/// separately hash-bound plan. It is NOT a flag waiving source/native validation.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBinding {
    pub sha256: String,
    pub bytes: u64,
}
fn review_pin(b: &ReviewBinding) -> Result<Pin> {
    ensure!(
        sha(&b.sha256) && b.bytes > 0 && b.bytes <= 1 << 20,
        "invalid sealed peer review binding"
    );
    Ok(Pin {
        path: REVIEW.into(),
        canonical: REVIEW.into(),
        sha256: b.sha256.clone(),
        kind: "RootReview".into(),
        uid: 0,
        gid: 0,
        mode: libc::S_IFREG | 0o444,
        bytes: b.bytes,
        single_link: true,
        fixture: None,
    })
}
fn verify_file(p: &Pin, f: ReadFile) -> Result<Vec<u8>> {
    ensure!(
        ordinary(&p.path) && ordinary(&p.canonical) && sha(&p.sha256),
        "unsafe peer input binding"
    );
    ensure!(
        f.before == f.after && f.after == f.named && f.canonical == p.canonical,
        "peer input identity/alias changed"
    );
    let m = &f.before;
    ensure!(
        m.uid == p.uid
            && m.gid == p.gid
            && m.mode == p.mode
            && m.mode & libc::S_IFMT == libc::S_IFREG
            && m.mode & 0o022 == 0
            && m.bytes == p.bytes
            && (!p.single_link || m.nlink == 1),
        "peer input custody changed"
    );
    ensure!(
        f.bytes.len() as u64 == p.bytes && digest(&f.bytes) == p.sha256,
        "peer input bytes/hash changed"
    );
    if p.kind == "Executable" {
        ensure!(
            f.bytes.starts_with(b"\x7fELF"),
            "peer executable is not ELF"
        );
    }
    Ok(f.bytes)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadWitness {
    pin: Pin,
    stamp: Stamp,
}
struct Budget {
    opens: usize,
    bytes: u64,
    reads: Vec<ReadWitness>,
}
impl Budget {
    fn read(&mut self, b: &mut impl Backend, p: &Pin) -> Result<Vec<u8>> {
        self.opens = self
            .opens
            .checked_add(1)
            .context("peer open count overflow")?;
        self.bytes = self
            .bytes
            .checked_add(p.bytes)
            .context("peer byte count overflow")?;
        ensure!(
            self.opens <= 128
                && self.bytes <= 512 << 20
                && p.bytes
                    <= if p.kind == "Executable" {
                        128 << 20
                    } else {
                        4 << 20
                    },
            "peer read budget"
        );
        let read = b.read(p)?;
        let stamp = read.before.clone();
        let bytes = verify_file(p, read)?;
        self.reads.push(ReadWitness {
            pin: p.clone(),
            stamp,
        });
        Ok(bytes)
    }
}
fn props(text: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for l in text.lines() {
        let (k, v) = l
            .split_once('=')
            .context("malformed peer native property")?;
        ensure!(
            out.insert(k.into(), v.into()).is_none(),
            "duplicate peer native property"
        );
    }
    ensure!(
        out.len() == PROPERTIES.split(',').count()
            && PROPERTIES.split(',').all(|p| out.contains_key(p)),
        "omitted/extra peer native field"
    );
    Ok(out)
}
fn set(v: &[String]) -> Result<BTreeSet<&str>> {
    let s = v.iter().map(String::as_str).collect::<BTreeSet<_>>();
    ensure!(s.len() == v.len(), "duplicate native set member");
    Ok(s)
}
fn bus_path(unit: &str) -> String {
    let mut p = "/org/freedesktop/systemd1/unit/".to_string();
    for b in unit.bytes() {
        if b.is_ascii_alphanumeric() {
            p.push(b as char)
        } else {
            p.push_str(&format!("_{b:02x}"))
        }
    }
    p
}
fn show(unit: &str) -> Request {
    Request {
        program: "/usr/bin/systemctl",
        argv: vec![
            "show".into(),
            "--no-pager".into(),
            format!("--property={PROPERTIES}"),
            "--".into(),
            unit.into(),
        ],
    }
}
fn bus(unit: &str, interface: &str, property: &str) -> Request {
    Request {
        program: "/usr/bin/busctl",
        argv: vec![
            "--system".into(),
            "--json=short".into(),
            "--no-pager".into(),
            "get-property".into(),
            "org.freedesktop.systemd1".into(),
            bus_path(unit),
            interface.into(),
            property.into(),
        ],
    }
}
fn queried(b: &mut impl Backend, records: &mut Vec<Value>, q: &Request) -> Result<String> {
    let r = b.query(q)?;
    ensure!(
        r.code == 0 && r.stderr.is_empty() && r.stdout.len() <= 1 << 20,
        "failed/oversized peer native query"
    );
    records.push(json!({"program":q.program,"argv":q.argv,"exit_code":r.code,"stdout":r.stdout,"stderr":r.stderr}));
    Ok(r.stdout)
}
fn bus_data(text: &str, signature: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(text)?;
    ensure!(
        v.as_object().is_some_and(|m| m.len() == 2)
            && v["type"] == signature
            && v.get("data").is_some(),
        "wrong peer native bus envelope"
    );
    Ok(v["data"].clone())
}
fn conditions(text: &str) -> Result<Vec<(String, bool, bool, String)>> {
    let v = bus_data(text, "a(sbbsi)")?;
    let mut out = Vec::new();
    for row in v.as_array().context("conditions not array")? {
        let a = row.as_array().context("condition row not array")?;
        ensure!(
            a.len() == 5 && a[4].as_i64().is_some_and(|n| i32::try_from(n).is_ok()),
            "condition tuple width/result"
        );
        out.push((
            a[0].as_str().context("condition kind")?.into(),
            a[1].as_bool().context("condition trigger")?,
            a[2].as_bool().context("condition negate")?,
            a[3].as_str().context("condition parameter")?.into(),
        ));
    }
    Ok(out)
}
fn commands(text: &str) -> Result<Vec<(String, Vec<String>, bool)>> {
    let v = bus_data(text, "a(sasbttttuii)")?;
    let mut out = Vec::new();
    for row in v.as_array().context("commands not array")? {
        let a = row.as_array().context("command not tuple")?;
        ensure!(
            a.len() == 10
                && a[3..8].iter().all(|v| v.as_u64().is_some())
                && a[7].as_u64().is_some_and(|n| u32::try_from(n).is_ok())
                && a[8..10]
                    .iter()
                    .all(|v| v.as_i64().is_some_and(|n| i32::try_from(n).is_ok())),
            "command native tuple width/types"
        );
        let argv = a[1]
            .as_array()
            .context("command argv not array")?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).context("nonstring argv"))
            .collect::<Result<Vec<_>>>()?;
        out.push((
            a[0].as_str().context("command executable")?.into(),
            argv,
            a[2].as_bool().context("ignore_errors")?,
        ));
    }
    Ok(out)
}
fn strings(text: &str) -> Result<Vec<String>> {
    let v = bus_data(text, "as")?;
    v.as_array()
        .context("native strings not array")?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .context("native member not string")
        })
        .collect()
}
fn check_native(b: &mut impl Backend, s: &Spec, origin: &Origin, jobs: &str) -> Result<Value> {
    ensure!(!jobs.split_whitespace().any(|v| v == s.unit), "queued peer");
    let mut native_evidence = Vec::new();
    let text = queried(b, &mut native_evidence, &show(&s.unit))?;
    let p = props(&text)?;
    for (k, v) in [
        ("Id", s.unit.as_str()),
        ("Names", s.unit.as_str()),
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("FragmentPath", s.recipe.path.as_str()),
        ("Job", ""),
        ("Transient", "no"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("ControlGroup", ""),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("OnSuccess", ""),
        ("OnFailure", ""),
        ("Triggers", ""),
        ("TriggeredBy", ""),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
    ] {
        ensure!(p[k] == v, "peer native mismatch field {k}");
    }
    ensure!(
        matches!(p["ExecMainCode"].as_str(), "0" | "1")
            && (p["InvocationID"].is_empty() || p["InvocationID"] == origin.original_iid),
        "peer original terminal identity changed"
    );
    let drops = p["DropInPaths"]
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let expected = s.dropins.iter().map(|p| p.path.clone()).collect::<Vec<_>>();
    ensure!(
        set(&drops)? == set(&expected)?,
        "foreign/missing peer drop-in"
    );
    let mut native_hashes = BTreeMap::new();
    native_hashes.insert("show".to_owned(), digest(text.as_bytes()));
    for hook in COMMANDS {
        let raw = queried(
            b,
            &mut native_evidence,
            &bus(&s.unit, "org.freedesktop.systemd1.Service", hook),
        )?;
        let actual = commands(&raw)?;
        let expected = if hook == "ExecStart" {
            vec![(s.expected_start[0].clone(), s.expected_start.clone(), false)]
        } else {
            vec![]
        };
        ensure!(
            actual == expected,
            "changed peer native command array {hook}"
        );
        native_hashes.insert(hook.into(), digest(raw.as_bytes()));
    }
    let raw = queried(
        b,
        &mut native_evidence,
        &bus(&s.unit, "org.freedesktop.systemd1.Unit", "Conditions"),
    )?;
    ensure!(
        conditions(&raw)? == s.expected_conditions,
        "changed peer conditions"
    );
    native_hashes.insert("Conditions".into(), digest(raw.as_bytes()));
    for (property, expected) in [
        ("Environment", &s.expected_environment),
        ("UnsetEnvironment", &s.expected_unset),
    ] {
        let raw = queried(
            b,
            &mut native_evidence,
            &bus(&s.unit, "org.freedesktop.systemd1.Service", property),
        )?;
        ensure!(
            set(&strings(&raw)?)? == set(expected)?,
            "changed peer environment property {property}"
        );
        native_hashes.insert(property.into(), digest(raw.as_bytes()));
    }
    let raw = queried(
        b,
        &mut native_evidence,
        &bus(
            &s.unit,
            "org.freedesktop.systemd1.Service",
            "EnvironmentFiles",
        ),
    )?;
    ensure!(
        bus_data(&raw, "a(sb)")? == json!([]),
        "peer environment file dispatch"
    );
    native_hashes.insert("EnvironmentFiles".into(), digest(raw.as_bytes()));
    let raw = queried(
        b,
        &mut native_evidence,
        &bus(
            &s.unit,
            "org.freedesktop.systemd1.Service",
            "PassEnvironment",
        ),
    )?;
    ensure!(
        strings(&raw)?.is_empty(),
        "peer inherited dispatch environment"
    );
    native_hashes.insert("PassEnvironment".into(), digest(raw.as_bytes()));
    let after = queried(b, &mut native_evidence, &show(&s.unit))?;
    ensure!(
        props(&after)? == p,
        "peer native terminal identity changed during command capture"
    );
    native_hashes.insert("show_after".into(), digest(after.as_bytes()));
    Ok(
        json!({"unit":s.unit,"original_invocation_id":origin.original_iid,"actual_terminal":p,"native_query_sha256":native_hashes,"native_raw_evidence":native_evidence}),
    )
}
fn json_input(s: &Spec, p: &Pin, bytes: &[u8]) -> Result<()> {
    if p.kind == "PreflightV4" {
        let v: Value = serde_json::from_slice(bytes)?;
        ensure!(
            v["manifest"]["schema"] == "jetstreamer-gcs-snapshot-preflight-v4"
                && v["manifest_fingerprint"]
                    == "sha256:3f0e03105ba1e6b166091d3519e1aea1f432d81e51044c3a35f49fb3e8991970",
            "foreign peer preflight"
        );
    }
    if p.kind == "PublicationV2" {
        let v: Value = serde_json::from_slice(bytes)?;
        ensure!(
            v["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
                && v["epochs"] == json!([s.epoch.context("batch epoch missing")?])
                && v["outcome"]["kind"] == "committed"
                && v["manifest_fingerprint"]
                    == "sha256:3f0e03105ba1e6b166091d3519e1aea1f432d81e51044c3a35f49fb3e8991970",
            "foreign peer batch"
        );
    }
    // Exact compiled bytes/hash also bind all base64 destination/context/outcome paths.
    Ok(())
}
fn verify_origin(b: &mut impl Backend, budget: &mut Budget, s: &Spec, o: &Origin) -> Result<()> {
    ensure!(
        iid(&o.original_iid)
            && o.evidence.uid == 0
            && o.evidence.gid == 0
            && o.evidence.single_link
            && o.evidence.kind == "History"
            && o.evidence.path.starts_with("/var/lib/jetstreamer/")
            && o.evidence.canonical == o.evidence.path
            && o.evidence.path.ends_with(".json")
            && o.unit_pointer.starts_with('/')
            && o.iid_pointer.starts_with('/')
            && o.unit_pointer != o.iid_pointer
            && o.unit_pointer.len() <= 512
            && o.iid_pointer.len() <= 512,
        "unqualified peer original history"
    );
    let v: Value = serde_json::from_slice(&budget.read(b, &o.evidence)?)?;
    ensure!(
        v.pointer(&o.unit_pointer).and_then(Value::as_str) == Some(s.unit.as_str())
            && v.pointer(&o.iid_pointer).and_then(Value::as_str) == Some(o.original_iid.as_str()),
        "peer history belongs to another original invocation"
    );
    Ok(())
}
/// Constructible only after complete five-role source/readset/native capture.
pub struct ValidatedPeers {
    rows: Vec<Value>,
    allowed: Vec<Pin>,
    exclusive: Vec<Pin>,
    review_sha256: String,
    reads: Vec<ReadWitness>,
    specs: Vec<Spec>,
    origins: Vec<Origin>,
}
pub fn capture(
    b: &mut impl Backend,
    binding: &ReviewBinding,
    jobs: &str,
) -> Result<ValidatedPeers> {
    capture_specs(b, binding, jobs, &specs()?)
}
fn capture_specs(
    b: &mut impl Backend,
    binding: &ReviewBinding,
    jobs: &str,
    specs: &[Spec],
) -> Result<ValidatedPeers> {
    let mut budget = Budget {
        opens: 0,
        bytes: 0,
        reads: Vec::new(),
    };
    let pin = review_pin(binding)?;
    let review: Review = serde_json::from_slice(&budget.read(b, &pin)?)?;
    ensure!(specs.len() == 5, "fixed peer source roster width");
    ensure!(
        review.schema == "horizon-old220-peers1012-independent-readsets-v1"
            && review.source_specs_sha256 == digest(SPEC_BYTES)
            && review.selected_owner == OWNER
            && review.selected_epoch == 220
            && review.selected_inodes == vec![20581075, 20582466]
            && !review.data_retirement_authorized
            && !review.global_alias_closure_qualified
            && review.rows.len() == 5,
        "foreign/incomplete peer qualification"
    );
    let mut rows = Vec::new();
    let mut allowed = Vec::new();
    let mut exclusive = Vec::new();
    for (s, r) in specs.iter().zip(&review.rows) {
        ensure!(
            r.unit == s.unit && r.role == s.role && r.complete_selected_cache_readset_reviewed,
            "unknown/reordered/unreviewed peer role"
        );
        verify_origin(b, &mut budget, s, &r.origin)?;
        for p in std::iter::once(&s.recipe).chain(&s.dropins) {
            budget.read(b, p)?;
            allowed.push(p.clone());
        }
        for root in ROOTS {
            let dir = format!("{root}/{}.d", s.unit);
            let actual = b.directory_names(&dir)?;
            let expected = s
                .dropins
                .iter()
                .filter(|p| Path::new(&p.path).parent() == Some(Path::new(&dir)))
                .map(|p| {
                    Path::new(&p.path)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect::<Vec<_>>();
            match actual {
                None => ensure!(
                    expected.is_empty(),
                    "required peer drop-in directory missing"
                ),
                Some(names) => ensure!(
                    !expected.is_empty() && set(&names)? == set(&expected)?,
                    "unqualified peer drop-in directory"
                ),
            }
        }
        for p in &s.dependencies {
            let bytes = budget.read(b, p)?;
            json_input(s, p, &bytes)?;
            if matches!(p.kind.as_str(), "Script" | "PublicationV2") {
                exclusive.push(p.clone());
            }
        }
        if s.role == "BootstrapRestoreNotSelected" {
            let p = r
                .bootstrap_interpreter
                .as_ref()
                .context("bootstrap interpreter provenance missing")?;
            ensure!(
                p.kind == "Executable"
                    && p.uid == 1000
                    && p.gid == 1000
                    && p.single_link
                    && p.canonical
                        .starts_with("/home/linuxbrew/.linuxbrew/Cellar/python@")
                    && Path::new(&p.canonical)
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("python3"))
                    && p.path == "/home/linuxbrew/.linuxbrew/bin/python3",
                "not exact login PATH Python provenance"
            );
            budget.read(b, p)?;
        } else {
            ensure!(
                r.bootstrap_interpreter.is_none(),
                "foreign bootstrap interpreter role"
            );
        }
        // Re-query complete properties/commands/env after the source/readset checks.
        rows.push(check_native(b, s, &r.origin, jobs)?);
    }
    Ok(ValidatedPeers {
        rows,
        allowed,
        exclusive,
        review_sha256: binding.sha256.clone(),
        reads: budget.reads,
        specs: specs.to_vec(),
        origins: review.rows.iter().map(|r| r.origin.clone()).collect(),
    })
}
impl ValidatedPeers {
    pub fn staged(&self, path: &Path, bytes: &[u8], jobs: &str) -> Result<bool> {
        let Some(p) = self.allowed.iter().find(|p| Path::new(&p.path) == path) else {
            return Ok(false);
        };
        ensure!(
            digest(bytes) == p.sha256,
            "changed staged exact peer source"
        );
        ensure!(
            !self.rows.iter().any(|r| jobs
                .split_whitespace()
                .any(|j| Some(j) == r["unit"].as_str())),
            "peer job appeared after capture"
        );
        Ok(true)
    }
    /// Only exclusive restore/probe scripts and original batches; SDK implementation
    /// sources remain dedicated bootstrap provenance, never a shared generic waiver.
    pub fn exclusive_inputs(&self) -> impl Iterator<Item = &Pin> {
        self.exclusive.iter()
    }
    pub fn summary(&self) -> Value {
        json!({"schema":"horizon-old220-peers1016-exact-five-current-v2",
            "review_sha256":self.review_sha256,"source_specs_sha256":digest(SPEC_BYTES),
            "selected_owner":OWNER,"selected_epoch":220,"selected_inodes":[20581075u64,20582466u64],
            "inputs":self.reads,"rows":self.rows,"data_retirement_authorized":false,
            "global_alias_closure_qualified":false,"capacity_credit_bytes":0})
    }
    /// Reopen exclusive inputs through the SAME custody/hash/budget core and
    /// bind their inode identity to this terminal boundary's original capture.
    pub fn exclusive_identities(&self, b: &mut impl Backend) -> Result<BTreeSet<(u64, u64)>> {
        let mut budget = Budget {
            opens: 0,
            bytes: 0,
            reads: Vec::new(),
        };
        let mut ids = BTreeSet::new();
        for pin in self.exclusive_inputs() {
            budget.read(b, pin)?;
            let actual = budget
                .reads
                .last()
                .context("missing exclusive read witness")?;
            ensure!(
                self.reads.contains(actual),
                "exclusive input changed since peer capture"
            );
            ids.insert((actual.stamp.dev, actual.stamp.ino));
        }
        Ok(ids)
    }
    pub fn staged_reference(
        &self,
        bytes: &[u8],
        mut path_reference: impl FnMut(&[u8], &[u8]) -> bool,
    ) -> bool {
        self.rows.iter().any(|r| {
            r["unit"]
                .as_str()
                .is_some_and(|u| path_reference(bytes, u.as_bytes()))
        }) || self.allowed.iter().chain(&self.exclusive).any(|p| {
            path_reference(bytes, p.path.as_bytes())
                || path_reference(bytes, p.canonical.as_bytes())
        })
    }
    pub fn indirect_reference(
        &self,
        bytes: &[u8],
        mut path_reference: impl FnMut(&[u8], &[u8]) -> bool,
    ) -> bool {
        self.exclusive.iter().any(|p| {
            path_reference(bytes, p.path.as_bytes())
                || path_reference(bytes, p.canonical.as_bytes())
        })
    }
    pub fn validate_predecessor_summary(&self, value: &Value) -> Result<()> {
        validate_summary_against(self, value)
    }
}
fn ancestry(path: &Path, root_only: bool) -> Result<Vec<(String, u64, u64, u32, u32, u32)>> {
    let mut current = std::path::PathBuf::new();
    let mut rows = Vec::new();
    for component in path.components() {
        ensure!(
            matches!(component, Component::RootDir | Component::Normal(_)),
            "peer ancestry component"
        );
        current.push(component);
        let m = fs::symlink_metadata(&current)?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.mode() & 0o022 == 0
                && (if root_only {
                    m.uid() == 0 && m.gid() == 0
                } else {
                    [0, 1000].contains(&m.uid()) && [0, 1000].contains(&m.gid())
                }),
            "unsafe peer input ancestry"
        );
        rows.push((
            current.to_string_lossy().into_owned(),
            m.dev(),
            m.ino(),
            m.uid(),
            m.gid(),
            m.mode(),
        ));
    }
    Ok(rows)
}
/// Root-only exact drop-in directory reader for the Backend adapter.
/// New/missing foreign directories are interpreted by capture(), never waived here.
pub fn read_directory_names(directory: &str) -> Result<Option<Vec<String>>> {
    let permitted = specs()?.iter().any(|s| {
        ROOTS
            .iter()
            .any(|root| directory == format!("{root}/{}.d", s.unit))
    });
    ensure!(permitted, "unknown peer directory request");
    let mut current = std::path::PathBuf::new();
    for component in Path::new(directory).components() {
        ensure!(
            matches!(component, Component::RootDir | Component::Normal(_)),
            "peer directory component"
        );
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(m) => ensure!(
                m.is_dir()
                    && !m.file_type().is_symlink()
                    && m.uid() == 0
                    && m.gid() == 0
                    && m.mode() & 0o022 == 0,
                "unsafe peer drop-in ancestry"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)?;
    let before = Stamp::of(&f.metadata()?);
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)? {
        ensure!(names.len() < 32, "peer drop-in directory member bound");
        names.push(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("nonUTF8 peer drop-in name"))?,
        );
    }
    ensure!(
        before == Stamp::of(&f.metadata()?)
            && before == Stamp::of(&fs::symlink_metadata(directory)?),
        "peer drop-in directory changed"
    );
    Ok(Some(names))
}
/// Read-only FD/named custody implementation for a Main Backend::read adapter.
/// Never opens a .jet/.index/snapshot body: only compiled pins or sealed review inputs
/// reach this through capture(); the caller must not expose it as a broad file API.
pub fn read_file(p: &Pin) -> Result<ReadFile> {
    ensure!(
        ordinary(&p.path) && ordinary(&p.canonical),
        "unsafe peer pathname"
    );
    let limit = if p.kind == "Executable" {
        128 << 20
    } else {
        4 << 20
    };
    ensure!(p.bytes <= limit, "peer file too large");
    // Source paths may be exact reviewed direct installation symlinks. Canonical
    // destinations are separately fixed, non-symlink paths and are opened nofollow.
    ensure!(
        fs::canonicalize(&p.path)? == Path::new(&p.canonical),
        "peer direct installation alias changed"
    );
    let parent = Path::new(&p.canonical)
        .parent()
        .context("peer canonical parent")?;
    let root_only = !p.canonical.starts_with("/home/");
    let parents = ancestry(parent, root_only)?;
    let logical = fs::symlink_metadata(&p.path)?;
    if logical.file_type().is_symlink() {
        ensure!(
            logical.uid() == p.uid && logical.gid() == p.gid,
            "unsafe peer direct installation link"
        );
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&p.canonical)?;
    let before = Stamp::of(&f.metadata()?);
    ensure!(
        before.mode & libc::S_IFMT == libc::S_IFREG && before.bytes == p.bytes,
        "peer file metadata changed before read"
    );
    let mut bytes = Vec::new();
    (&mut f).take(p.bytes + 1).read_to_end(&mut bytes)?;
    let after = Stamp::of(&f.metadata()?);
    let named = Stamp::of(&fs::symlink_metadata(&p.canonical)?);
    ensure!(
        fs::canonicalize(&p.path)? == Path::new(&p.canonical),
        "peer named alias changed during read"
    );
    ensure!(
        parents == ancestry(parent, root_only)?,
        "peer ancestry changed while reading"
    );
    Ok(ReadFile {
        bytes,
        before,
        after,
        named,
        canonical: p.canonical.clone(),
    })
}
#[cfg(test)]
mod tests;

// Only dev/test harnesses can select synthetic ELF transport. No Plan/CLI field
// selects test specs; normal production capture always calls compiled specs().
#[cfg(any(test, feature = "test-fixtures"))]
pub mod test_support;
include!("predecessor_summary.rs");

// Distinct condition-blocked scope; never converted to the original semantic proof.
mod condition_blocked;
pub use condition_blocked::{
    capture_condition_blocked, condition_blocked_requirements, ConditionBlockedPeers,
};
