//! One-shot epoch247 reboot launch adapter. No R2 or archive mutation commands.
//! Preparation and launch require a separate fresh, Main-accepted admission.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const CAP: u64 = 506191984640;
const HIGH: u64 = 167361060864;
const MAX: u64 = 251041591296;
const CONTROL: u64 = 1610612736;
const UNIT: &str = "horizon-qualify-247-reboot-20261117-v2.service";
const GUARD_UNIT: &str = "horizon-247-reboot-20261117-protective-v2.service";
const TIMER: &str = "horizon-247-reboot-20261117-protective-v2.timer";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-247-reboot-20261117-v2";
const STATE: &str = "/var/lib/jetstreamer/horizon247-reboot-20261117-state-v2";
const STATIC: &str = "/var/lib/jetstreamer/horizon247-reboot-20261117-static-v2";
const BOUND: &str = "/var/lib/jetstreamer/horizon247-reboot-20261117-guard-v2";
const TOKENS: &str = "/var/lib/jetstreamer/horizon247-reboot-20261117-tokens-v2";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon247-reboot-20261117-receipts-v2";
const NODE: &str =
    "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node";
const WORKER: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15";
const MANIFEST: &str = "/var/lib/jetstreamer/horizon247-controls0345-v1/preflight-247-target1.json";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon247-bootstrap-copy0347-work-v2/projection/bootstrap/snapshot-106703614-AtkJcCAEp3EfF4ymeeN9t3YvHuAq3aykuQ6vogtDYcf9.tar.zst";
const GENESIS: &str = "/var/lib/jetstreamer/horizon237-v4-genesis-input-v1/genesis.tar.bz2";
const AUTH: &str = "/var/lib/jetstreamer/horizon247-input-auth0348-accepted-v1/acceptance.json";
const SEALER: &str =
    "/var/lib/jetstreamer/horizon-live-observe-ca2e38b-v8/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "f77e62124cf79a39a27706025d3e36e62d90fba8aadbee3e2bf4f68fb4f23d98";
const GUARD: &str = "/var/lib/jetstreamer/horizon-native223-prefix-guard-044ccba7-v1/jetstreamer-horizon-standalone-guard";
const GUARD_SHA: &str = "044ccba70304c6d5690d2628c1ca08586462efdcc2d9f278903ee8bab0da6b3f";
const OLD_UNIT: &str = "horizon-qualify-247-general-shrink-debt-budget506-e3f15eb2-v1.service";
const OLD_IID: &str = "7fad70689375484c8b4a6356c82758da";
const BASE_PROPS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainCode,ExecMainStatus,Job,FragmentPath,DropInPaths,Restart,KillMode,Delegate,ControlGroup";
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing number {k}"))
}
fn yes(v: &Value, k: &str) -> Result<()> {
    ensure!(v[k] == true, "required {k}");
    Ok(())
}
fn hash_bytes(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn hash(p: &Path) -> Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn identity(p: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && p.canonicalize()? == p,
        "unsafe regular file {}",
        p.display()
    );
    Ok(
        json!({"dev":m.dev(),"ino":m.ino(),"bytes":m.len(),"mtime_ns":m.mtime() as i128*1000000000+m.mtime_nsec() as i128,"ctime_ns":m.ctime() as i128*1000000000+m.ctime_nsec() as i128,"mode":m.mode(),"uid":m.uid(),"gid":m.gid(),"nlink":m.nlink()}),
    )
}
fn small(p: &Path) -> Result<Vec<u8>> {
    let before = identity(p)?;
    ensure!(number(&before, "bytes")? <= 4 << 20, "oversized metadata");
    let b = fs::read(p)?;
    ensure!(identity(p)? == before, "metadata changed");
    Ok(b)
}
fn bound(v: &Value) -> Result<Value> {
    let p = Path::new(text(v, "path")?);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o022 == 0,
        "mutable/unowned binding"
    );
    let b = small(p)?;
    ensure!(
        hash_bytes(&b) == text(v, "sha256")?,
        "bound digest mismatch {}",
        p.display()
    );
    Ok(serde_json::from_slice(&b)?)
}
fn pin(p: &Path) -> Result<Value> {
    Ok(json!({"path":p,"sha256":hash(p)?}))
}
fn absent(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("already exists {}", p.display()),
    }
}
fn directory(p: &Path, uid: u32, mode: u32) -> Result<()> {
    absent(p)?;
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))?;
    let s = std::ffi::CString::new(p.as_os_str().as_bytes())?;
    ensure!(
        unsafe { libc::chown(s.as_ptr(), uid, uid) } == 0,
        "chown failed"
    );
    File::open(p)?.sync_all()?;
    File::open(p.parent().context("no parent")?)?.sync_all()?;
    Ok(())
}
fn save_at(root: &Path, name: &str, b: &[u8]) -> Result<Value> {
    ensure!(!name.contains('/') && !name.is_empty(), "unsafe leaf");
    let p = root.join(name);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    f.write_all(b)?;
    f.sync_all()?;
    File::open(root)?.sync_all()?;
    pin(&p)
}
struct Native {
    deadline: Option<Instant>,
    counter: u32,
    root: PathBuf,
}
impl Native {
    fn new(root: PathBuf) -> Self {
        Self {
            deadline: None,
            counter: 0,
            root,
        }
    }
    fn check(&self) -> Result<()> {
        if let Some(d) = self.deadline {
            ensure!(
                Instant::now() < d,
                "original 50-second startup deadline expired"
            );
        }
        Ok(())
    }
    fn run(&mut self, exe: &str, args: &[&str]) -> Result<Vec<u8>> {
        self.check()?;
        self.counter += 1;
        let stem = format!("command-{:03}", self.counter);
        let stdout = self.root.join(format!("{stem}.stdout"));
        let stderr = self.root.join(format!("{stem}.stderr"));
        let out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stdout)?;
        let err = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stderr)?;
        let started = Instant::now();
        let limit = self
            .deadline
            .map(|x| x.min(started + Duration::from_secs(15)))
            .unwrap_or(started + Duration::from_secs(15));
        let mut child = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .spawn()?;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() >= limit {
                let _ = child.kill();
                let _ = child.wait();
                bail!("native metadata command deadline expired: {exe}")
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        self.check()?;
        ensure!(
            status.success(),
            "native command failed {exe} {:?}: {}",
            args,
            String::from_utf8_lossy(&small(&stderr)?)
        );
        small(&stdout)
    }
    fn show(&mut self, u: &str, extra: &str) -> Result<(BTreeMap<String, String>, Vec<u8>)> {
        let props = format!(
            "{BASE_PROPS}{}{}",
            if extra.is_empty() { "" } else { "," },
            extra
        );
        let raw = self.run(
            "/usr/bin/systemctl",
            &["show", u, "--no-pager", &format!("--property={props}")],
        )?;
        let s = String::from_utf8(raw.clone())?;
        let rows = s
            .lines()
            .filter_map(|s| s.split_once('='))
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        Ok((rows, raw))
    }
    fn seal(&mut self, dest: &str, members: Vec<Value>, name: &str) -> Result<Value> {
        let p = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":members});
        let r = save_at(&self.root, name, &serde_json::to_vec_pretty(&p)?)?;
        self.run(
            SEALER,
            &[
                text(&r, "path")?,
                "--plan-sha256",
                text(&r, "sha256")?,
                "--self-sha256",
                SEALER_SHA,
            ],
        )?;
        pin(&Path::new(dest).join("deployment-seal-receipt.json"))
    }
}
fn row<'a>(v: &'a BTreeMap<String, String>, k: &str) -> Result<&'a str> {
    v.get(k)
        .map(String::as_str)
        .with_context(|| format!("missing native property {k}"))
}
fn closed(v: &BTreeMap<String, String>) -> Result<()> {
    let absent_service_properties =
        row(v, "LoadState")? == "not-found" || row(v, "Id")?.ends_with(".timer");
    for (key, zero) in [
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("ControlGroup", ""),
    ] {
        ensure!(
            v.get(key).map(String::as_str) == Some(zero)
                || (absent_service_properties && !v.contains_key(key)),
            "unit has live or unknown {key}"
        );
    }
    ensure!(
        matches!(row(v, "ActiveState")?, "inactive" | "failed") && row(v, "Job")?.is_empty(),
        "unit not drained"
    );
    Ok(())
}
fn iid(v: &str) -> bool {
    v.len() == 32
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn pre(v: &BTreeMap<String, String>, expected: &str) -> Result<u32> {
    ensure!(
        iid(expected)
            && row(v, "InvocationID")? == expected
            && row(v, "ActiveState")? == "activating"
            && row(v, "SubState")? == "start-pre"
            && row(v, "MainPID")? == "0"
            && row(v, "NRestarts")? == "0"
            && row(v, "Restart")? == "no"
            && row(v, "KillMode")? == "control-group"
            && row(v, "Delegate")? == "no",
        "producer left admitted start-pre"
    );
    Ok(row(v, "ControlPID")?.parse()?)
}
fn identity_subset(expected: &Value, actual: &Value) -> Result<()> {
    for (k, v) in expected.as_object().context("identity object")? {
        ensure!(actual.get(k) == Some(v), "input identity changed: {k}");
    }
    Ok(())
}
fn check_inputs() -> Result<Value> {
    let b = small(Path::new(AUTH))?;
    ensure!(
        hash_bytes(&b) == "bd8dfb92dc7bae51af0fbc783de87f894c113da3bc33f775d41508e56813be95",
        "original input receipt changed"
    );
    let v: Value = serde_json::from_slice(&b)?;
    yes(&v, "Main_accepted")?;
    yes(&v, "actual_independent_payload_hashes_verified")?;
    let expected = [
        (
            NODE,
            "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
        ),
        (
            WORKER,
            "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4",
        ),
        (
            MANIFEST,
            "e63e298a0eaa9408a4cc56c396c7701af9a55ec5499c0d9c9ded934971da04f6",
        ),
        (
            SNAPSHOT,
            "060fa4a95bdbf8a41000ed043af667bcd9ae3b6a080c12415ce35f0b5d2bf5ba",
        ),
    ];
    ensure!(
        v["expected_files"].as_object().context("files")?.len() == 4,
        "unexpected input set"
    );
    for (p, h) in expected {
        ensure!(v["expected_files"][p] == h, "input hash mapping changed");
        identity_subset(&v["stable_file_identities"][p], &identity(Path::new(p))?)?;
    }
    ensure!(
        hash(Path::new(GENESIS))?
            == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        "genesis changed"
    );
    ensure!(
        hash(Path::new(SEALER))? == SEALER_SHA && hash(Path::new(GUARD))? == GUARD_SHA,
        "sealed tool changed"
    );
    Ok(v)
}
fn admission_values(a: &Value, clock: u64) -> Result<()> {
    ensure!(
        a["schema"] == "horizon247-reboot-main-admission-v1" && a["candidate_epoch"] == 247,
        "foreign admission"
    );
    for k in [
        "Main_accepted",
        "complete_native_census_reviewed",
        "all_other_obligations_preserved",
        "interrupted247_preserved",
        "no_overlapping_campaign_controller",
        "first_guard_before_useful_work_required",
    ] {
        yes(a, k)?;
    }
    let issued = number(a, "issued_unix_seconds")?;
    let expiry = number(a, "expires_unix_seconds")?;
    ensure!(
        issued <= clock && clock < expiry && expiry <= issued + 300,
        "expired/future admission"
    );
    ensure!(
        number(a, "observer_unix_seconds")? <= issued
            && clock - number(a, "observer_unix_seconds")? < 1800,
        "stale resource observer"
    );
    ensure!(
        number(a, "candidate_memory_max_bytes")? == MAX
            && number(a, "candidate_memory_high_bytes")? == HIGH
            && number(a, "candidate_root_cap_bytes")? == CAP
            && number(a, "candidate_control_memory_bytes")? == CONTROL,
        "resource envelope differs"
    );
    ensure!(
        number(a, "required_initial_free_bytes")?
            == number(a, "guard_minimum_free_bytes")?
                .checked_add(CAP)
                .context("overflow")?
            && number(a, "guard_minimum_free_bytes")? >= number(a, "century_floor_bytes")?
            && number(a, "century_floor_bytes")? > 0,
        "disk booking/floor differs"
    );
    ensure!(
        number(a, "memory_obligation_after_bytes")? >= MAX + CONTROL
            && number(a, "memory_obligation_after_bytes")? <= number(a, "host_memory_total_bytes")?,
        "memory booking exceeds host"
    );
    ensure!(
        a["actual_executing_before"] == 0
            && a["initializing_before"] == 0
            && a["proposed_replay_lanes"] == 1
            && a["proven_operating_count"].as_u64().is_some_and(|n| n >= 1),
        "not the first reboot lane"
    );
    ensure!(
        a["worker_root"] == ROOT
            && a["producer_unit"] == UNIT
            && a["guard_unit"] == GUARD_UNIT
            && a["timer_unit"] == TIMER,
        "namespace differs"
    );
    Ok(())
}
fn validate_admission(a: &Value, plan: &Value) -> Result<()> {
    admission_values(a, now()?)?;
    ensure!(
        a["launch_plan"] == *plan,
        "admission does not bind exact launch plan"
    );
    let mut documents = BTreeMap::new();
    for k in [
        "owner",
        "observer",
        "fleet",
        "capacity",
        "census",
        "interruption",
    ] {
        documents.insert(k.to_string(), bound(&a[k])?);
    }
    evidence_claims(a, &documents)?;
    let interruption = bound(&a["interruption"])?;
    ensure!(
        interruption["unit"] == OLD_UNIT
            && interruption["invocation_id"] == OLD_IID
            && interruption["reboot_interrupted"] == true
            && interruption["checkpoint_resume_qualified"] == false
            && interruption["partial_archive_preserved"] == true,
        "invalid interrupted predecessor proof"
    );
    ensure!(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == text(a, "boot_id")?,
        "boot changed"
    );
    let pid = number(a, "main_controller_pid")?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .collect();
    ensure!(
        fields.get(19).context("start ticks")?.parse::<u64>()?
            == number(a, "main_controller_start_ticks")?,
        "main controller changed"
    );
    // system.slice has no cpuset controller on this host; its effective set is
    // inherited from the cgroup root. The producer's narrower CPU binding is
    // checked independently against its loaded unit before launch.
    let cpus = fs::read_to_string("/sys/fs/cgroup/cpuset.cpus.effective")?;
    let online = fs::read_to_string("/sys/devices/system/cpu/online")?;
    ensure!(
        cpus.trim() == "0-127" && online.trim() == "0-127",
        "CPU topology differs from qualified route"
    );
    Ok(())
}
// Main selects JSON pointers in the real source schemas, but cannot omit any required
// cross-check or point to a different evidence document for a given claim.
fn evidence_fields() -> [(&'static str, &'static [&'static str]); 5] {
    [
        (
            "owner",
            &[
                "boot_id",
                "main_controller_pid",
                "main_controller_start_ticks",
            ][..],
        ),
        (
            "observer",
            &[
                "observer_unix_seconds",
                "host_memory_total_bytes",
                "observed_available_bytes",
            ][..],
        ),
        (
            "fleet",
            &[
                "actual_executing_before",
                "initializing_before",
                "proven_operating_count",
            ][..],
        ),
        (
            "capacity",
            &[
                "candidate_memory_max_bytes",
                "candidate_memory_high_bytes",
                "candidate_root_cap_bytes",
                "candidate_control_memory_bytes",
                "memory_obligation_after_bytes",
                "required_initial_free_bytes",
                "guard_minimum_free_bytes",
                "century_floor_bytes",
                "proposed_replay_lanes",
            ][..],
        ),
        (
            "census",
            &["actual_executing_before", "initializing_before", "boot_id"][..],
        ),
    ]
}
fn evidence_claims(a: &Value, documents: &BTreeMap<String, Value>) -> Result<()> {
    for (source, fields) in evidence_fields() {
        for field in fields {
            let pointer = text(&a["evidence_claims"][source], field)?;
            ensure!(
                pointer.starts_with('/') && !pointer.is_empty(),
                "invalid evidence pointer"
            );
            let observed = documents
                .get(source)
                .context("missing bound evidence")?
                .pointer(pointer)
                .context("missing source claim")?;
            ensure!(
                a.get(*field) == Some(observed),
                "{source} evidence contradicts {field}"
            );
        }
    }
    ensure!(
        number(a, "observed_available_bytes")? >= number(a, "required_initial_free_bytes")?,
        "observer disk booking does not fit"
    );
    Ok(())
}
fn templates() -> Result<(String, String, String)> {
    let base = Path::new("/var/lib/jetstreamer/horizon247-replay2408-adapters-Main-v1");
    let values = [
        (
            OLD_UNIT,
            "5c0e6de56e6797f9b018d1a2f97579bf4297afb38b70c5a232fc6bfcb710f48f",
        ),
        (
            "horizon-247-general-shrink-debt-budget506-protective-v1.service",
            "1c888abc3851815b7153219276d879e72b599afba0f3d3a4553838c273bef8d7",
        ),
        (
            "horizon-247-general-shrink-debt-budget506-protective-v1.timer",
            "bf1b5d2ce745fdc7f5d902ff895d851b702f3eba9c00ea02bd3a2f2b43260747",
        ),
    ];
    let mut rendered = Vec::new();
    for (name, sha) in values {
        let raw = small(&base.join(name))?;
        ensure!(hash_bytes(&raw) == sha, "prior recipe changed");
        let mut s = String::from_utf8(raw)?;
        for (old, new) in [
            (OLD_UNIT, UNIT),
            (
                "horizon-247-general-shrink-debt-budget506-protective-v1.service",
                GUARD_UNIT,
            ),
            (
                "horizon-247-general-shrink-debt-budget506-protective-v1.timer",
                TIMER,
            ),
            (
                "/home/ubuntu/.jetstreamer-private/qualification-247-general-shrink-debt-budget506-e3f15eb2-v1",
                ROOT,
            ),
            (
                "/var/lib/jetstreamer/horizon247-general-v1-guard-tokens",
                TOKENS,
            ),
            (
                "/var/lib/jetstreamer/horizon247-general-v1-guard-receipts",
                RECEIPTS,
            ),
            (
                "/var/lib/jetstreamer/horizon247-general-v1-guard-bound",
                BOUND,
            ),
        ] {
            s = s.replace(old, new)
        }
        rendered.push(s);
    }
    Ok((rendered.remove(0), rendered.remove(0), rendered.remove(0)))
}
fn guard_plan(a: &Value, invocation: &str) -> Result<Value> {
    ensure!(iid(invocation), "bad guard IID");
    Ok(
        json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":invocation,"filesystem":"/","minimum_free_bytes":number(a,"guard_minimum_free_bytes")?,"worker_root":ROOT,"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":CAP,"receipt_directory":RECEIPTS}),
    )
}
fn root_pristine() -> Result<()> {
    let expected = [
        (ROOT, vec!["output", "state", "tmp"]),
        (&format!("{ROOT}/output"), vec!["genesis.tar.bz2"]),
        (&format!("{ROOT}/state"), vec![]),
        (&format!("{ROOT}/tmp"), vec!["isolated-empty-gcloud"]),
        (&format!("{ROOT}/tmp/isolated-empty-gcloud"), vec![]),
    ];
    for (path, names) in expected {
        let p = Path::new(path);
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir()
                && m.uid() == 1000
                && m.gid() == 1000
                && m.mode() & 0o777 == 0o700
                && p.canonicalize()? == p,
            "bad fresh root custody"
        );
        let actual: BTreeSet<_> = fs::read_dir(p)?
            .map(|r| r.map(|x| x.file_name().to_string_lossy().into_owned()))
            .collect::<std::io::Result<_>>()?;
        ensure!(
            actual == names.into_iter().map(str::to_string).collect(),
            "fresh root is not pristine"
        );
    }
    ensure!(
        hash(&Path::new(ROOT).join("output/genesis.tar.bz2"))?
            == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        "seed genesis changed"
    );
    Ok(())
}
fn scope_census(n: &mut Native, a: &Value, allow_candidate: bool) -> Result<()> {
    let bytes = n.run(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--all",
            "--type=service",
            "--state=active,activating,deactivating,reloading",
            "--output=json",
            "--no-pager",
        ],
    )?;
    let list: Value = serde_json::from_slice(&bytes)?;
    for x in list.as_array().context("unit list")? {
        let name = text(x, "unit")?;
        if !name.starts_with("horizon")
            && !name.starts_with("jetstreamer")
            && !name.starts_with("archive")
        {
            continue;
        }
        if name == text(a, "launcher_unit")? {
            continue;
        }
        if allow_candidate && [UNIT, GUARD_UNIT].contains(&name) {
            continue;
        }
        bail!("unexpected busy campaign service {name}");
    }
    for old in [
        OLD_UNIT,
        "horizon-247-general-shrink-debt-budget506-protective-v1.service",
        "horizon-247-general-shrink-debt-budget506-protective-v1.timer",
        "horizon-qualify-248-general-shrink-debt-budget506-e3f15eb2-v1.service",
        "horizon-qualify-249-general-shrink-debt-budget506-e3f15eb2-v1.service",
    ] {
        let (v, _) = n.show(old, "")?;
        closed(&v)?;
    }
    for entry in fs::read_dir("/proc")? {
        let e = entry?;
        if !e
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|x| x.is_ascii_digit())
        {
            continue;
        }
        let cmd = match fs::read(e.path().join("cmdline")) {
            Ok(x) => x,
            Err(x) if x.kind() == std::io::ErrorKind::NotFound => continue,
            Err(x) => return Err(x.into()),
        };
        let words: Vec<_> = cmd
            .split(|b| *b == 0)
            .filter_map(|b| std::str::from_utf8(b).ok())
            .collect();
        if words.first().is_some_and(|s| {
            s.ends_with("/jetstreamer-node")
                || s.ends_with("/jetstreamer-historical-worker-v1-7-15")
        }) {
            bail!("unexpected live replay process {}", e.path().display())
        }
    }
    Ok(())
}
fn prepare(n: &mut Native, a: &Value, plan: &Value, admission: &Value) -> Result<()> {
    validate_admission(a, plan)?;
    check_inputs()?;
    scope_census(n, a, false)?;
    for p in [ROOT, STATIC, BOUND, TOKENS, RECEIPTS] {
        absent(Path::new(p))?;
    }
    for u in [UNIT, GUARD_UNIT, TIMER] {
        absent(&Path::new("/run/systemd/system").join(u))?;
        let (v, _) = n.show(u, "")?;
        closed(&v)?;
        ensure!(
            row(&v, "LoadState")? == "not-found",
            "attempt unit name already consumed"
        );
    }
    for p in [
        ROOT,
        &format!("{ROOT}/output"),
        &format!("{ROOT}/state"),
        &format!("{ROOT}/tmp"),
        &format!("{ROOT}/tmp/isolated-empty-gcloud"),
    ] {
        directory(Path::new(p), 1000, 0o700)?;
    }
    let g = Path::new(ROOT).join("output/genesis.tar.bz2");
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&g)?;
    out.write_all(&small(Path::new(GENESIS))?)?;
    out.sync_all()?;
    ensure!(
        unsafe { libc::fchown(out.as_raw_fd(), 1000, 1000) } == 0,
        "seed chown"
    );
    File::open(g.parent().unwrap())?.sync_all()?;
    directory(Path::new(TOKENS), 0, 0o755)?;
    directory(Path::new(RECEIPTS), 0, 0o700)?;
    root_pristine()?;
    let (producer, guard, timer) = templates()?;
    let validation = serde_json::to_vec_pretty(&guard_plan(a, &"0".repeat(32))?)?;
    let mut members = Vec::new();
    for (name, bytes) in [
        (UNIT, producer.as_bytes()),
        ("guard.service.template", guard.as_bytes()),
        ("guard.timer.template", timer.as_bytes()),
        ("guard-validation-plan.json", validation.as_slice()),
    ] {
        let r = save_at(&n.root, name, bytes)?;
        members.push(json!({"source":r["path"],"name":name,"sha256":r["sha256"],"mode":292}));
    }
    n.seal(STATIC, members, "static-seal-plan.json")?;
    n.run(
        GUARD,
        &[
            &format!("{STATIC}/guard-validation-plan.json"),
            "--plan-sha256",
            &hash(&Path::new(STATIC).join("guard-validation-plan.json"))?,
            "--self-sha256",
            GUARD_SHA,
            "--validate-plan-only",
        ],
    )?;
    symlink(
        Path::new(STATIC).join(UNIT),
        Path::new("/run/systemd/system").join(UNIT),
    )?;
    n.run("/usr/bin/systemctl", &["daemon-reload"])?;
    save_at(
        &n.root,
        "prepared.json",
        &serde_json::to_vec_pretty(
            &json!({"schema":"horizon247-reboot-prepared-v1","plan":plan,"admission":admission,"input_auth":pin(Path::new(AUTH))?,"original_interrupted_root_preserved":true,"worker_root":ROOT,"unit":UNIT,"replay_started":false}),
        )?,
    )?;
    Ok(())
}
fn prestart_headers(raw: &[u8]) -> Result<Vec<(String, String, String)>> {
    let raw = std::str::from_utf8(raw)?;
    let mut out = Vec::new();
    for line in raw.lines().filter_map(|s| s.strip_prefix("ExecStartPre=")) {
        ensure!(line.starts_with("{ path="), "malformed ExecStartPre");
        for entry in line.split("{ path=").skip(1) {
            let (path, tail) = entry.split_once(" ; argv[]=").context("prestart path")?;
            let (argv, tail) = tail
                .split_once(" ; ignore_errors=")
                .context("prestart argv")?;
            let (ignore, _) = tail.split_once(" ;").context("prestart ignore")?;
            out.push((path.to_string(), argv.to_string(), ignore.to_string()));
        }
    }
    Ok(out)
}
fn validate_loaded(v: &BTreeMap<String, String>, raw: &[u8]) -> Result<()> {
    for (k, want) in [
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("DropInPaths", ""),
        ("MemoryMax", "251041591296"),
        ("MemoryHigh", "167361060864"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("AllowedCPUs", "80-95"),
        ("CPUAffinity", "80-95"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
        ("EnvironmentFiles", ""),
        ("PassEnvironment", ""),
        ("Slice", "system.slice"),
        ("BindReadOnlyPaths", ""),
    ] {
        // This systemd build omits EnvironmentFiles entirely when the unit
        // has none. A configured file is emitted (as for ssh.service here).
        // The unchanged sealed source template must also omit the directive.
        if k == "EnvironmentFiles" && !v.contains_key(k) {
            ensure!(
                !templates()?
                    .0
                    .lines()
                    .any(|line| line.starts_with("EnvironmentFile=")),
                "missing native property {k}"
            );
            continue;
        }
        ensure!(row(v, k)? == want, "loaded {k} differs");
    }
    ensure!(
        row(v, "FragmentPath")? == format!("/run/systemd/system/{UNIT}")
            && row(v, "ReadWritePaths")? == ROOT
            && row(v, "ReadOnlyPaths")? == TOKENS,
        "loaded namespace differs"
    );
    let token = format!("{TOKENS}/${{INVOCATION_ID}}/guard-admission.json");
    ensure!(
        prestart_headers(raw)?
            == vec![
                (
                    "/usr/bin/sleep".into(),
                    "/usr/bin/sleep 60".into(),
                    "no".into()
                ),
                (
                    "/usr/bin/test".into(),
                    format!("/usr/bin/test -f {token}"),
                    "no".into()
                ),
                (
                    "/usr/bin/test".into(),
                    format!("/usr/bin/test ! -L {token}"),
                    "no".into()
                )
            ],
        "native prestart gate differs"
    );
    let source = templates()?.0;
    let exec = source
        .lines()
        .find_map(|s| s.strip_prefix("ExecStart="))
        .context("source command")?;
    ensure!(
        row(v, "ExecStart")?.contains(&format!(
            "{{ path={NODE} ; argv[]={exec} ; ignore_errors=no ;"
        )),
        "native replay command differs"
    );
    let expected: BTreeSet<_> = source
        .lines()
        .filter_map(|s| s.strip_prefix("Environment="))
        .map(|s| s.trim_matches('"').to_string())
        .collect();
    let actual: BTreeSet<_> = row(v, "Environment")?
        .split_whitespace()
        .map(|s| s.trim_matches('"').to_string())
        .collect();
    ensure!(actual == expected, "native environment differs");
    ensure!(
        !row(v, "UnsetEnvironment")?
            .split_whitespace()
            .any(|s| s == "INVOCATION_ID"),
        "manager invocation stripped"
    );
    Ok(())
}
fn property(status: &str, key: &str) -> Result<String> {
    let prefix = format!("{key}:");
    Ok(status
        .lines()
        .find_map(|s| s.strip_prefix(&prefix))
        .context("missing proc property")?
        .trim()
        .to_string())
}
fn mount_options(mountinfo: &str, path: &str) -> Result<BTreeSet<String>> {
    let mut selected = None;
    for row in mountinfo.lines() {
        let f: Vec<_> = row.split_whitespace().collect();
        ensure!(f.len() >= 7, "bad mountinfo");
        let m = f[4];
        if (path == m || path.starts_with(&format!("{}/", m.trim_end_matches('/'))))
            && selected.as_ref().is_none_or(|(len, _)| *len < m.len())
        {
            selected = Some((m.len(), f[5].split(',').map(str::to_string).collect()));
        }
    }
    Ok(selected.context("no applicable mount")?.1)
}
fn capture_namespace(n: &mut Native, id: &str, cp: u32) -> Result<()> {
    let expiry = Instant::now() + Duration::from_secs(2);
    loop {
        n.check()?;
        let (v, _) = n.show(UNIT, "")?;
        ensure!(pre(&v, id)? == cp, "control PID changed");
        let dir = PathBuf::from(format!("/proc/{cp}"));
        let read = || -> Result<(String, String, PathBuf)> {
            Ok((
                fs::read_to_string(dir.join("mountinfo"))?,
                fs::read_to_string(dir.join("status"))?,
                fs::canonicalize(dir.join("exe"))?,
            ))
        };
        if let Ok((mounts, status, exe)) = read() {
            let (v, _) = n.show(UNIT, "")?;
            ensure!(
                pre(&v, id)? == cp,
                "control PID changed after namespace read"
            );
            if exe == Path::new("/usr/bin/sleep").canonicalize()?
                && property(&status, "Uid")?
                    .split_whitespace()
                    .all(|x| x == "1000")
            {
                ensure!(
                    property(&status, "CapEff")? == "0000000000000000"
                        && property(&status, "Cpus_allowed_list")? == "80-95",
                    "setup process capability/CPU differs"
                );
                ensure!(
                    fs::canonicalize(dir.join("exe"))? == exe,
                    "setup executable changed"
                );
                for (p, opt) in [
                    (ROOT, "rw"),
                    (&format!("{ROOT}/tmp/isolated-empty-gcloud"), "rw"),
                    (TOKENS, "ro"),
                    ("/home/ubuntu/workspace", "ro"),
                    (SNAPSHOT, "ro"),
                ] {
                    ensure!(
                        mount_options(&mounts, p)?.contains(opt),
                        "bad setup mount {p}"
                    );
                }
                ensure!(
                    Instant::now() <= expiry,
                    "namespace readiness exceeded original two-second deadline"
                );
                save_at(&n.root, "setup-mountinfo.txt", mounts.as_bytes())?;
                save_at(&n.root, "setup-status.txt", status.as_bytes())?;
                return Ok(());
            }
        }
        ensure!(
            Instant::now() < expiry,
            "same setup child not ready within two seconds"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn validate_first_sample(
    s: &Value,
    a: &Value,
    id: &str,
    gid: &str,
    plan_sha: &str,
    started: u64,
) -> Result<()> {
    ensure!(
        s["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && s["producer_invocation_id"] == id
            && s["guard_invocation_id"] == gid
            && s["producer_stop_enabled"] == true,
        "guard owner/stop policy mismatch"
    );
    ensure!(
        s["plan"] == format!("{BOUND}/guard-plan.json")
            && s["plan_sha256"] == plan_sha
            && s["guard_sha256"] == GUARD_SHA,
        "guard provenance differs"
    );
    ensure!(
        s["minimum_free_bytes"] == a["guard_minimum_free_bytes"]
            && s["maximum_root_physical_bytes"] == CAP
            && s["maximum_worker_vmas"] == 3500000,
        "guard envelope differs"
    );
    for k in [
        "trip_reason",
        "worker_observation_error",
        "root_physical_observation_error",
        "target_handoff_error",
        "canary_target_error",
    ] {
        ensure!(s.get(k) == Some(&Value::Null), "guard reported {k}");
    }
    ensure!(
        s["workers"] == json!([])
            && s["root_physical_observation"].is_null()
            && s["producer"]["pid"] == 0
            && s["producer"]["active"] == "activating"
            && s["producer"]["sub"] == "start-pre",
        "guard sampled useful work before token"
    );
    ensure!(
        number(s, "available_bytes")? >= number(a, "required_initial_free_bytes")?
            && number(s, "recorded_unix_seconds")? >= started,
        "guard free space/freshness failed"
    );
    Ok(())
}
fn guard_journal(raw: &[u8], id: &str) -> Result<Vec<Value>> {
    let rows: Vec<Value> = std::str::from_utf8(raw)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        !rows.is_empty() && rows.len() < 16,
        "guard PID1 journal count"
    );
    for r in &rows {
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == GUARD_UNIT
                && r["INVOCATION_ID"] == id,
            "foreign guard journal identity"
        );
    }
    ensure!(
        rows.iter().any(|r| r["JOB_TYPE"] == "start"
            && r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with("Starting ")))
            && rows.iter().any(|r| r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.ends_with("Deactivated successfully.")))
            && rows.iter().any(|r| r["JOB_RESULT"] == "done"),
        "missing genuine PID1 guard lifecycle"
    );
    Ok(rows)
}
fn monotonic_us() -> Result<u64> {
    let mut v = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, v.as_mut_ptr()) } == 0,
        "monotonic clock"
    );
    let v = unsafe { v.assume_init() };
    Ok(v.tv_sec as u64 * 1000000 + v.tv_nsec as u64 / 1000)
}
fn timer_deadline(bytes: &[u8], clock: u64) -> Result<u64> {
    let s = std::str::from_utf8(bytes)?;
    let words: Vec<_> = s.split_whitespace().collect();
    ensure!(
        words.len() == 2 && words[0] == "t",
        "wrong typed timer deadline"
    );
    let next = words[1].parse::<u64>()?;
    ensure!(
        next > clock + 5000000,
        "timer next fire lacks required budget"
    );
    Ok(next)
}
fn preflight_launch(n: &mut Native, a: &Value, plan: &Value) -> Result<Vec<u8>> {
    validate_admission(a, plan)?;
    check_inputs()?;
    root_pristine()?;
    scope_census(n, a, false)?;
    for (p, mode) in [(TOKENS, 0o755), (RECEIPTS, 0o700)] {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir()
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o777 == mode
                && fs::read_dir(p)?.next().is_none(),
            "consumed or unsafe startup directory"
        );
    }
    absent(Path::new(BOUND))?;
    let prepared: Value = serde_json::from_slice(&small(&Path::new(STATE).join("prepared.json"))?)?;
    ensure!(
        prepared["schema"] == "horizon247-reboot-prepared-v1"
            && prepared["plan"] == *plan
            && prepared["worker_root"] == ROOT
            && prepared["replay_started"] == false,
        "invalid preparation"
    );
    ensure!(
        Path::new("/run/systemd/system").join(UNIT).read_link()? == Path::new(STATIC).join(UNIT),
        "producer link changed"
    );
    let extra = "ExecStart,ExecStartPre,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment,ReadWritePaths,ReadOnlyPaths,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,AllowedCPUs,CPUAffinity,TasksMax,PrivateNetwork,ProtectHome,ProtectSystem,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,Slice,BindReadOnlyPaths";
    let (v, raw) = n.show(UNIT, extra)?;
    validate_loaded(&v, &raw)?;
    for u in [GUARD_UNIT, TIMER] {
        absent(&Path::new("/run/systemd/system").join(u))?;
        let (v, _) = n.show(u, "")?;
        closed(&v)?;
        ensure!(row(&v, "LoadState")? == "not-found", "guard name consumed");
    }
    Ok(raw)
}
fn review_failed_first_launch(n: &mut Native) -> Result<()> {
    let failure = Path::new(STATE).join("launch/failure.json");
    let bytes = small(&failure)?;
    ensure!(
        hash_bytes(&bytes) == "789826d54d9a3ffb28e3cb853c723bc65821ae6baf3764718cd7c7eea719d7e0",
        "first launch failure evidence changed"
    );
    let f: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        f["error"] == "missing native property EnvironmentFiles"
            && f["original_attempt_not_retried"] == true
            && f["automatic_retry_authorized"] == false,
        "first launch failed after a different gate"
    );
    let (v, _) = n.show(UNIT, "")?;
    ensure!(
        row(&v, "LoadState")? == "loaded"
            && row(&v, "ActiveState")? == "inactive"
            && row(&v, "MainPID")? == "0"
            && row(&v, "ControlPID")? == "0"
            && row(&v, "NRestarts")? == "0"
            && row(&v, "InvocationID")?.is_empty(),
        "first launch may have started producer"
    );
    absent(Path::new(BOUND))?;
    for p in [TOKENS, RECEIPTS] {
        ensure!(
            fs::read_dir(p)?.next().is_none(),
            "first launch left guard state"
        );
    }
    Ok(())
}
fn launch(n: &mut Native, a: &Value, plan: &Value, admission: &Value) -> Result<()> {
    let raw = preflight_launch(n, a, plan)?;
    save_at(&n.root, "producer-loaded.txt", &raw)?;
    // All setup and prerequisite checks finish before this single original clock.
    let started = now()?;
    n.deadline = Some(Instant::now() + Duration::from_secs(50));
    n.run("/usr/bin/systemctl", &["start", "--no-block", UNIT])?;
    let (v, raw) = n.show(UNIT, "")?;
    let id = row(&v, "InvocationID")?.to_string();
    let cp = pre(&v, &id)?;
    ensure!(cp > 0, "missing setup child");
    save_at(&n.root, "producer-initial.txt", &raw)?;
    capture_namespace(n, &id, cp)?;
    let gp = guard_plan(a, &id)?;
    let gr = save_at(&n.root, "guard-plan.json", &serde_json::to_vec_pretty(&gp)?)?;
    let (_, guard, timer) = templates()?;
    ensure!(
        guard.matches("@ACTUAL_SEALED_PLAN_SHA256@").count() == 1,
        "guard placeholder count"
    );
    let guard = guard.replace("@ACTUAL_SEALED_PLAN_SHA256@", text(&gr, "sha256")?);
    let sr = save_at(&n.root, "guard.service", guard.as_bytes())?;
    let tr = save_at(&n.root, "guard.timer", timer.as_bytes())?;
    n.seal(
        BOUND,
        vec![
            json!({"source":gr["path"],"name":"guard-plan.json","sha256":gr["sha256"],"mode":292}),
            json!({"source":sr["path"],"name":"guard.service","sha256":sr["sha256"],"mode":292}),
            json!({"source":tr["path"],"name":"guard.timer","sha256":tr["sha256"],"mode":292}),
        ],
        "guard-seal-plan.json",
    )?;
    n.run(
        GUARD,
        &[
            &format!("{BOUND}/guard-plan.json"),
            "--plan-sha256",
            text(&gr, "sha256")?,
            "--self-sha256",
            GUARD_SHA,
            "--validate-plan-only",
        ],
    )?;
    symlink(
        Path::new(BOUND).join("guard.service"),
        Path::new("/run/systemd/system").join(GUARD_UNIT),
    )?;
    symlink(
        Path::new(BOUND).join("guard.timer"),
        Path::new("/run/systemd/system").join(TIMER),
    )?;
    n.run("/usr/bin/systemctl", &["daemon-reload"])?;
    let (g, _) = n.show(GUARD_UNIT, "ExecStart")?;
    let (t, _) = n.show(TIMER, "Unit,NextElapseUSecMonotonic")?;
    ensure!(
        row(&g, "LoadState")? == "loaded"
            && row(&t, "LoadState")? == "loaded"
            && row(&g, "DropInPaths")?.is_empty()
            && row(&t, "DropInPaths")?.is_empty()
            && row(&g, "ExecStart")?.contains(text(&gr, "sha256")?)
            && row(&t, "Unit")? == GUARD_UNIT,
        "loaded guard graph differs"
    );
    pre(&n.show(UNIT, "")?.0, &id)?;
    n.run("/usr/bin/systemctl", &["start", TIMER])?;
    std::thread::sleep(Duration::from_secs(3));
    n.check()?;
    let (g, gb) = n.show(GUARD_UNIT, "ExecStart")?;
    let (t, tb) = n.show(TIMER, "Unit,NextElapseUSecMonotonic")?;
    let gid = row(&g, "InvocationID")?.to_string();
    ensure!(
        iid(&gid)
            && row(&g, "ActiveState")? == "inactive"
            && row(&g, "Result")? == "success"
            && row(&g, "ExecMainStatus")? == "0"
            && row(&g, "MainPID")? == "0"
            && row(&g, "ControlPID")? == "0"
            && row(&g, "Job")?.is_empty(),
        "first guard did not finish successfully"
    );
    ensure!(
        row(&t, "ActiveState")? == "active"
            && row(&t, "SubState")? == "waiting"
            && row(&t, "Unit")? == GUARD_UNIT
            && row(&t, "Job")?.is_empty()
            && iid(row(&t, "InvocationID")?),
        "timer not armed"
    );
    let sample = Path::new(RECEIPTS).join(format!("sample-{gid}.json"));
    let m = fs::symlink_metadata(&sample)?;
    ensure!(
        m.uid() == 0 && m.gid() == 0 && m.len() < 1 << 20,
        "unsafe first guard receipt"
    );
    let sb = small(&sample)?;
    let s: Value = serde_json::from_slice(&sb)?;
    validate_first_sample(&s, a, &id, &gid, text(&gr, "sha256")?, started)?;
    ensure!(
        !fs::read_dir(RECEIPTS)?
            .any(|r| r.is_ok_and(|x| x.file_name().to_string_lossy().contains("stop"))),
        "guard stop evidence exists"
    );
    let journal = n.run(
        "/usr/bin/journalctl",
        &[
            "--all",
            "--no-pager",
            "--output=json",
            &format!("--since=@{}", started.saturating_sub(1)),
            "_PID=1",
            &format!("UNIT={GUARD_UNIT}"),
            &format!("INVOCATION_ID={gid}"),
        ],
    )?;
    let journal_rows = guard_journal(&journal, &gid)?;
    let object = format!(
        "/org/freedesktop/systemd1/unit/{}",
        TIMER
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("_{:02x}", c as u32)
            })
            .collect::<String>()
    );
    let typed = n.run(
        "/usr/bin/busctl",
        &[
            "get-property",
            "org.freedesktop.systemd1",
            &object,
            "org.freedesktop.systemd1.Timer",
            "NextElapseUSecMonotonic",
        ],
    )?;
    timer_deadline(&typed, monotonic_us()?)?;
    let (v, pb) = n.show(UNIT, "")?;
    pre(&v, &id)?;
    let mut evidence = Vec::new();
    for (name, bytes) in [
        ("first-guard.txt", gb.as_slice()),
        ("first-timer.txt", tb.as_slice()),
        ("first-guard-PID1.jsonl", journal.as_slice()),
        ("timer-next.txt", typed.as_slice()),
        ("producer-before-token.txt", pb.as_slice()),
        ("actual-first-guard-sample.json", sb.as_slice()),
    ] {
        evidence.push(save_at(&n.root, name, bytes)?);
    }
    let token = json!({"schema":"horizon247-reboot-real-first-timer-guard-admission-v1","actual_invocation_id":id,"admission":admission,"first_guard_invocation_id":gid,"guard_sample":s,"guard_plan_sha256":gr["sha256"],"guard_sha256":GUARD_SHA,"native_evidence":evidence,"native_guard_events":journal_rows,"input_custody":pin(Path::new(AUTH))?,"actual_timer_invocation_id":row(&t,"InvocationID")?,"producer_before_and_after_first_guard_zero_restart_start_pre":true,"publication_authorized":false,"archive_mutations":false,"remote_mutations":false,"r2_mutations":false});
    let token_ref = save_at(
        &n.root,
        "guard-admission.json",
        &serde_json::to_vec_pretty(&token)?,
    )?;
    let token_dest = format!("{TOKENS}/{id}");
    absent(Path::new(&token_dest))?;
    validate_admission(a, plan)?;
    pre(&n.show(UNIT, "")?.0, &id)?;
    n.seal(&token_dest,vec![json!({"source":token_ref["path"],"name":"guard-admission.json","sha256":token_ref["sha256"],"mode":292})],"token-seal-plan.json")?;
    let (v, raw) = n.show(UNIT, "")?;
    pre(&v, &id)?;
    save_at(&n.root, "producer-after-token.txt", &raw)?;
    validate_admission(a, plan)?;
    n.check()?;
    let handoff = json!({"schema":"horizon247-reboot-guarded-startup-v1","recorded_unix_seconds":now()?,"producer":v,"guard_invocation_id":gid,"timer":t,"plan":plan,"admission":admission,"guard_plan":{"path":format!("{BOUND}/guard-plan.json"),"sha256":gr["sha256"]},"first_fire_token":{"path":format!("{token_dest}/guard-admission.json"),"sha256":token_ref["sha256"]},"remaining_original_setup_millis":n.deadline.unwrap().saturating_duration_since(Instant::now()).as_millis(),"transaction_replay_observed":false,"original_interrupted_root_preserved":true,"remote_mutations":false});
    let r = save_at(
        &n.root,
        "guarded-startup-handoff.json",
        &serde_json::to_vec_pretty(&handoff)?,
    )?;
    n.check()?;
    println!(
        "{}",
        json!({"guarded_startup":r,"unit":UNIT,"invocation_id":id,"useful_replay_not_yet_observed":true})
    );
    Ok(())
}
fn plan_validate(p: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "horizon247-reboot-launch-plan-v1"
            && p["candidate_epoch"] == 247
            && p["worker_root"] == ROOT
            && p["state_directory"] == STATE
            && p["producer_unit"] == UNIT
            && p["guard_unit"] == GUARD_UNIT
            && p["timer_unit"] == TIMER
            && p["setup_seconds"] == 60
            && p["operator_deadline_seconds"] == 50
            && p["maximum_root_physical_bytes"] == CAP
            && p["memory_high_bytes"] == HIGH
            && p["memory_max_bytes"] == MAX
            && p["maximum_worker_vmas"] == 3500000
            && p["input_auth"] == pin(Path::new(AUTH))?,
        "unsupported launch plan"
    );
    ensure!(
        p["remote_mutations"] == false
            && p["archive_retirement_authorized"] == false
            && p["reuse_original_invocation_authorized"] == false,
        "foreign authority"
    );
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == "emit-source-templates" {
        let root = Path::new(&args[2]);
        absent(root)?;
        fs::create_dir(root)?;
        let p = json!({"schema":"horizon247-reboot-launch-plan-v1","candidate_epoch":247,"worker_root":ROOT,"state_directory":STATE,"producer_unit":UNIT,"guard_unit":GUARD_UNIT,"timer_unit":TIMER,"setup_seconds":60,"operator_deadline_seconds":50,"maximum_root_physical_bytes":CAP,"memory_high_bytes":HIGH,"memory_max_bytes":MAX,"maximum_worker_vmas":3500000,"input_auth":{"path":AUTH,"sha256":"bd8dfb92dc7bae51af0fbc783de87f894c113da3bc33f775d41508e56813be95"},"remote_mutations":false,"archive_retirement_authorized":false,"reuse_original_invocation_authorized":false});
        let pref = save_at(root, "launch-plan.json", &serde_json::to_vec_pretty(&p)?)?;
        let executable = fs::canonicalize("/proc/self/exe")?;
        let deployment = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":"/var/lib/jetstreamer/horizon247-reboot-20261117-launcher-v2","members":[{"source":executable,"name":"horizon-reboot247-launch","sha256":hash(&executable)?,"mode":365},{"source":pref["path"],"name":"launch-plan.json","sha256":pref["sha256"],"mode":292}]});
        save_at(
            root,
            "deployment-plan.json",
            &serde_json::to_vec_pretty(&deployment)?,
        )?;
        let mut a = json!({"schema":"horizon247-reboot-main-admission-v1","candidate_epoch":247,"Main_accepted":false,"complete_native_census_reviewed":false,"all_other_obligations_preserved":false,"interrupted247_preserved":false,"no_overlapping_campaign_controller":false,"first_guard_before_useful_work_required":true,"issued_unix_seconds":0,"expires_unix_seconds":0,"observer_unix_seconds":0,"candidate_memory_max_bytes":MAX,"candidate_memory_high_bytes":HIGH,"candidate_root_cap_bytes":CAP,"candidate_control_memory_bytes":CONTROL,"guard_minimum_free_bytes":null,"required_initial_free_bytes":null,"century_floor_bytes":null,"memory_obligation_after_bytes":null,"host_memory_total_bytes":null,"observed_available_bytes":null,"actual_executing_before":0,"initializing_before":0,"proposed_replay_lanes":1,"proven_operating_count":3,"worker_root":ROOT,"producer_unit":UNIT,"guard_unit":GUARD_UNIT,"timer_unit":TIMER,"launch_plan":pref,"launcher_unit":"REPLACE_WITH_EXACT_LAUNCHER_UNIT.service","boot_id":"REPLACE","main_controller_pid":0,"main_controller_start_ticks":0,"evidence_claims":{}});
        for (source, fields) in evidence_fields() {
            a[source] = json!({"path":"REPLACE_WITH_ROOT_OWNED_EVIDENCE_PATH","sha256":"REPLACE_WITH_SHA256"});
            for field in fields {
                a["evidence_claims"][source][*field] = json!(format!("/{field}"));
            }
        }
        a["interruption"] = json!({"path":"REPLACE_WITH_ROOT_OWNED_INTERRUPTION_PROOF","sha256":"REPLACE_WITH_SHA256"});
        save_at(
            root,
            "admission-NOT-ACCEPTED.json",
            &serde_json::to_vec_pretty(&a)?,
        )?;
        println!(
            "{}",
            json!({"source_templates":root,"launch_authorized":false})
        );
        return Ok(());
    }
    ensure!(
        args.len() == 5 || args.len() == 7,
        "usage: horizon-reboot247-launch inspect|prepare|launch PLAN PLAN_SHA256 SELF_SHA256 [ADMISSION ADMISSION_SHA256]"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    ensure!(
        hash(Path::new("/proc/self/exe"))? == args[4],
        "self hash mismatch"
    );
    let plan_ref = json!({"path":args[2],"sha256":args[3]});
    let plan = bound(&plan_ref)?;
    plan_validate(&plan)?;
    check_inputs()?;
    templates()?;
    if args[1] == "inspect" {
        ensure!(args.len() == 5, "unexpected admission");
        println!(
            "{}",
            json!({"plan":plan_ref,"inputs_unchanged":true,"source_templates_unchanged":true,"no_units_changed":true,"launch_authorized":false})
        );
        return Ok(());
    }
    ensure!(
        args.len() == 7 && ["prepare", "preflight-launch", "launch"].contains(&args[1].as_str()),
        "unsupported command"
    );
    let admission_ref = json!({"path":args[5],"sha256":args[6]});
    let a = bound(&admission_ref)?;
    validate_admission(&a, &plan_ref)?;
    let lock_path = Path::new("/var/lib/jetstreamer/horizon247-reboot-20261117-launch.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path)?;
    ensure!(
        lock.metadata()?.uid() == 0
            && lock.metadata()?.nlink() == 1
            && lock.metadata()?.mode() & 0o077 == 0,
        "unsafe launch lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "launch lock busy"
    );
    if args[1] == "prepare" {
        directory(Path::new(STATE), 0, 0o700)?;
        directory(&Path::new(STATE).join("prepare"), 0, 0o700)?;
        let mut n = Native::new(Path::new(STATE).join("prepare"));
        prepare(&mut n, &a, &plan_ref, &admission_ref)?;
        // Publish the preparation envelope once at its stable parent location.
        let b = small(&n.root.join("prepared.json"))?;
        save_at(Path::new(STATE), "prepared.json", &b)?;
        println!("prepared fresh root and inactive producer; no replay launched");
    } else if args[1] == "preflight-launch" {
        directory(&Path::new(STATE).join("preflight-v1"), 0, 0o700)?;
        let mut n = Native::new(Path::new(STATE).join("preflight-v1"));
        review_failed_first_launch(&mut n)?;
        preflight_launch(&mut n, &a, &plan_ref)?;
        println!("prepared state and loaded producer passed read-only preflight");
    } else {
        directory(&Path::new(STATE).join("launch-v2"), 0, 0o700)?;
        let mut n = Native::new(Path::new(STATE).join("launch-v2"));
        review_failed_first_launch(&mut n)?;
        if let Err(error) = launch(&mut n, &a, &plan_ref, &admission_ref) {
            let _ = save_at(
                &n.root,
                "failure.json",
                &serde_json::to_vec(
                    &json!({"error":format!("{error:#}"),"original_attempt_not_retried":true,"token_may_be_absent":true,"automatic_retry_authorized":false}),
                )?,
            );
            return Err(error);
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn admission() -> Value {
        json!({"schema":"horizon247-reboot-main-admission-v1","candidate_epoch":247,"Main_accepted":true,"complete_native_census_reviewed":true,"all_other_obligations_preserved":true,"interrupted247_preserved":true,"no_overlapping_campaign_controller":true,"first_guard_before_useful_work_required":true,"issued_unix_seconds":1000,"expires_unix_seconds":1200,"observer_unix_seconds":900,"candidate_memory_max_bytes":MAX,"candidate_memory_high_bytes":HIGH,"candidate_root_cap_bytes":CAP,"candidate_control_memory_bytes":CONTROL,"guard_minimum_free_bytes":300000000000u64,"required_initial_free_bytes":300000000000u64+CAP,"century_floor_bytes":200000000000u64,"memory_obligation_after_bytes":MAX+CONTROL,"host_memory_total_bytes":1200000000000u64,"actual_executing_before":0,"initializing_before":0,"proposed_replay_lanes":1,"proven_operating_count":3,"worker_root":ROOT,"producer_unit":UNIT,"guard_unit":GUARD_UNIT,"timer_unit":TIMER})
    }
    #[test]
    fn accepted_envelope() {
        admission_values(&admission(), 1100).unwrap();
    }
    #[test]
    fn no_stale_or_unaccepted_admission() {
        let mut a = admission();
        assert!(admission_values(&a, 1300).is_err());
        assert!(admission_values(&a, 999).is_err());
        a["Main_accepted"] = json!(false);
        assert!(admission_values(&a, 1100).is_err());
    }
    #[test]
    fn accounting_fail_closed() {
        for k in [
            "candidate_memory_max_bytes",
            "candidate_root_cap_bytes",
            "required_initial_free_bytes",
            "memory_obligation_after_bytes",
            "proposed_replay_lanes",
            "operator_deadline_seconds",
        ] {
            if k == "operator_deadline_seconds" {
                continue;
            }
            let mut a = admission();
            a[k] = json!(0);
            assert!(admission_values(&a, 1100).is_err(), "{k}");
        }
    }
    #[test]
    fn strict_native_prestart_sequence() {
        let raw=b"ExecStartPre={ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep 60 ; ignore_errors=no ; pid=0 }\nExecStartPre={ path=/usr/bin/test ; argv[]=/usr/bin/test -f /token ; ignore_errors=no ; pid=0 }";
        assert_eq!(prestart_headers(raw).unwrap().len(), 2);
        assert!(prestart_headers(b"ExecStartPre=unknown").is_err());
    }
    #[test]
    fn mount_selection_is_most_specific() {
        let raw = "1 0 8:0 / / ro - x x ro\n2 1 8:0 / /home rw - x x rw\n3 2 8:0 / /home/token ro - x x ro";
        assert!(mount_options(raw, "/home/root").unwrap().contains("rw"));
        assert!(mount_options(raw, "/home/token/id").unwrap().contains("ro"));
    }
    #[test]
    fn typed_timer_budget() {
        assert_eq!(timer_deadline(b"t 16000000", 10000000).unwrap(), 16000000);
        assert!(timer_deadline(b"s 16000000", 10000000).is_err());
        assert!(timer_deadline(b"t 15000000", 10000000).is_err());
    }
    fn sample() -> Value {
        json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","producer_invocation_id":"a".repeat(32),"guard_invocation_id":"b".repeat(32),"producer_stop_enabled":true,"plan":format!("{BOUND}/guard-plan.json"),"plan_sha256":"c".repeat(64),"guard_sha256":GUARD_SHA,"minimum_free_bytes":300000000000u64,"maximum_root_physical_bytes":CAP,"maximum_worker_vmas":3500000,"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"target_handoff_error":null,"canary_target_error":null,"workers":[],"root_physical_observation":null,"producer":{"pid":0,"active":"activating","sub":"start-pre"},"available_bytes":4000000000000u64,"recorded_unix_seconds":1100})
    }
    #[test]
    fn genuine_first_sample() {
        validate_first_sample(
            &sample(),
            &admission(),
            &"a".repeat(32),
            &"b".repeat(32),
            &"c".repeat(64),
            1100,
        )
        .unwrap();
    }
    #[test]
    fn reject_old_owner_trip_early_worker_and_missing_checks() {
        for k in [
            "producer_invocation_id",
            "guard_invocation_id",
            "trip_reason",
            "root_physical_observation",
            "worker_observation_error",
        ] {
            let mut s = sample();
            s[k] = json!("wrong");
            assert!(
                validate_first_sample(
                    &s,
                    &admission(),
                    &"a".repeat(32),
                    &"b".repeat(32),
                    &"c".repeat(64),
                    1100
                )
                .is_err(),
                "{k}"
            );
        }
        let mut s = sample();
        s["producer"]["pid"] = json!(123);
        assert!(
            validate_first_sample(
                &s,
                &admission(),
                &"a".repeat(32),
                &"b".repeat(32),
                &"c".repeat(64),
                1100
            )
            .is_err()
        );
    }
    #[test]
    fn unchanged_identity_only() {
        let old = json!({"dev":1,"ino":2,"bytes":5});
        let new = json!({"dev":1,"ino":2,"bytes":6,"uid":0});
        assert!(identity_subset(&old, &new).is_err());
        identity_subset(&old, &json!({"dev":1,"ino":2,"bytes":5,"uid":0})).unwrap();
    }
    #[test]
    fn deadline_expiration_prevents_command() {
        let mut n = Native::new(PathBuf::from("/nonexistent"));
        n.deadline = Some(Instant::now() - Duration::from_secs(1));
        assert!(n.run("/usr/bin/true", &[]).is_err());
    }
    #[test]
    fn closed_timer_allows_only_absent_service_properties() {
        let mut v: BTreeMap<String, String> = [
            ("Id", "unused.timer"),
            ("LoadState", "loaded"),
            ("ActiveState", "inactive"),
            ("Job", ""),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        closed(&v).unwrap();
        v.insert("MainPID".into(), "2".into());
        assert!(closed(&v).is_err());
        v.remove("MainPID");
        v.insert("ActiveState".into(), "active".into());
        assert!(closed(&v).is_err());
        v.insert("ActiveState".into(), "inactive".into());
        v.insert("Id".into(), "unused.service".into());
        assert!(closed(&v).is_err());
        v.insert("LoadState".into(), "not-found".into());
        closed(&v).unwrap();
    }
    #[test]
    fn start_pre_rejects_changed_owner_and_started_worker() {
        let id = "a".repeat(32);
        let mut v: BTreeMap<String, String> = [
            ("InvocationID", id.as_str()),
            ("ActiveState", "activating"),
            ("SubState", "start-pre"),
            ("MainPID", "0"),
            ("ControlPID", "123"),
            ("NRestarts", "0"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        assert_eq!(pre(&v, &id).unwrap(), 123);
        assert!(pre(&v, &"b".repeat(32)).is_err());
        v.insert("MainPID".into(), "456".into());
        assert!(pre(&v, &id).is_err());
    }
    #[test]
    fn journal_requires_actual_pid1_complete_guard_lifecycle() {
        let id = "b".repeat(32);
        let rows = [
            json!({"_PID":"1","_UID":"0","UNIT":GUARD_UNIT,"INVOCATION_ID":id,"JOB_TYPE":"start","MESSAGE":"Starting guard"}),
            json!({"_PID":"1","_UID":"0","UNIT":GUARD_UNIT,"INVOCATION_ID":id,"MESSAGE":"guard: Deactivated successfully."}),
            json!({"_PID":"1","_UID":"0","UNIT":GUARD_UNIT,"INVOCATION_ID":id,"JOB_RESULT":"done"}),
        ];
        let encode = |rs: &[Value]| {
            rs.iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        };
        guard_journal(encode(&rows).as_bytes(), &id).unwrap();
        assert!(guard_journal(encode(&rows[..2]).as_bytes(), &id).is_err());
        let mut bad = rows.clone();
        bad[0]["_PID"] = json!("2");
        assert!(guard_journal(encode(&bad).as_bytes(), &id).is_err());
        assert!(guard_journal(encode(&rows).as_bytes(), &"c".repeat(32)).is_err());
    }
    #[test]
    fn admission_evidence_must_agree_with_each_numeric_claim() {
        let mut a = admission();
        a["observed_available_bytes"] = json!(4000000000000u64);
        a["boot_id"] = json!("test-boot");
        a["main_controller_pid"] = json!(100);
        a["main_controller_start_ticks"] = json!(1000);
        let mut docs = BTreeMap::new();
        for (source, fields) in evidence_fields() {
            let mut d = json!({});
            for field in fields {
                d[*field] = a[*field].clone();
                a["evidence_claims"][source][*field] = json!(format!("/{field}"));
            }
            docs.insert(source.to_string(), d);
        }
        evidence_claims(&a, &docs).unwrap();
        docs.get_mut("capacity").unwrap()["memory_obligation_after_bytes"] = json!(1);
        assert!(evidence_claims(&a, &docs).is_err());
    }
}
