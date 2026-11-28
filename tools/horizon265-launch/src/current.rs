//! Current retained-fleet admission, adapted from the qualified native211 controller.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[path = "current/admission.rs"]
mod admission;
#[path = "current/capacity.rs"]
mod capacity;
#[path = "current/delivery247.rs"]
mod delivery247;
#[path = "current/failed_attempts.rs"]
mod failed_attempts;
#[path = "current/finalization.rs"]
mod finalization;
#[path = "current/live.rs"]
mod live;
#[path = "current/peers.rs"]
mod peers;
#[path = "current/periodic.rs"]
mod periodic;
#[path = "current/publication.rs"]
mod publication;

const UNIT: &str = super::UNIT;
const GUARD_UNIT: &str = super::GUARD_UNIT;
const TIMER: &str = super::TIMER;
const ROOT: &str = super::ROOT;
const NODE: &str = super::NODE;
const NODE_SHA: &str = super::NODE_SHA;
const WORKER: &str = super::WORKER;
const GUARD: &str = super::GUARD;
const GUARD_SHA: &str = super::GUARD_SHA;
const SEALER: &str = super::SEALER;
const SEALER_SHA: &str = super::SEALER_SHA;
const MEMORY: u64 = super::MAX;
const SCRATCH: u64 = super::CAP;
const HOST: u64 = 68_719_476_736;
const CONTROL: u64 = super::CONTROL;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
impl Bound {
    fn new(path: impl Into<PathBuf>, sha256: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            sha256: sha256.into(),
        }
    }
    fn bytes(&self, immutable: bool) -> Result<Vec<u8>> {
        ensure!(hex(&self.sha256, 64), "invalid SHA256");
        let before = identity(&self.path)?;
        ensure!(before.2 <= 16 << 20 && before.3 == 0, "evidence size/owner");
        ensure!(
            before.4 & if immutable { 0o222 } else { 0o022 } == 0,
            "evidence writable"
        );
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)?;
        ensure!(
            metadata_identity(&f.metadata()?) == before,
            "evidence open race"
        );
        let mut bytes = Vec::new();
        (&mut f).take((16 << 20) + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 16 << 20
                && digest(&bytes) == self.sha256
                && metadata_identity(&f.metadata()?) == before
                && identity(&self.path)? == before,
            "evidence changed or digest mismatch"
        );
        Ok(bytes)
    }
    fn json(&self) -> Result<Value> {
        Ok(serde_json::from_slice(&self.bytes(false)?)?)
    }
    fn sealed(&self) -> Result<Value> {
        ensure!(
            self.path.starts_with("/var/lib/jetstreamer"),
            "sealed namespace"
        );
        trusted_parents(&self.path)?;
        Ok(serde_json::from_slice(&self.bytes(true)?)?)
    }
    fn artifact(&self) -> Result<()> {
        trusted_parents(&self.path)?;
        let before = identity(&self.path)?;
        ensure!(
            before.3 == 0 && before.4 & 0o222 == 0 && before.2 <= 256 << 20,
            "artifact custody"
        );
        ensure!(
            hash(&self.path)? == self.sha256 && identity(&self.path)? == before,
            "artifact changed"
        );
        Ok(())
    }
}
type Identity = (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64);
fn metadata_identity(m: &fs::Metadata) -> Identity {
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
fn identity(p: &Path) -> Result<Identity> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute() && p.canonicalize()? == p && m.is_file() && m.nlink() == 1,
        "unsafe file {}",
        p.display()
    );
    Ok(metadata_identity(&m))
}
fn trusted_parents(p: &Path) -> Result<()> {
    for p in p.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted parent {}",
            p.display()
        );
    }
    Ok(())
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn hash(p: &Path) -> Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut b = [0; 131072];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing number {k}"))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn binding(v: &Value) -> Result<Bound> {
    Ok(serde_json::from_value(v.clone())?)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn mono() -> Result<u64> {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } == 0,
        "monotonic clock"
    );
    (t.tv_sec as u64)
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(t.tv_nsec as u64 / 1000))
        .context("clock overflow")
}
fn fresh(t: u64, clock: u64, age: u64) -> Result<()> {
    ensure!(t <= clock && clock - t <= age, "stale/future evidence");
    Ok(())
}
fn no_authority(v: &Value) -> Result<()> {
    for k in [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[k] == false, "unexpected/missing authority flag {k}");
    }
    Ok(())
}
fn deny_authority(v: &mut Value) {
    for k in [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        v[k] = json!(false);
    }
}
fn save(root: &Path, leaf: &str, bytes: &[u8]) -> Result<Bound> {
    ensure!(!leaf.is_empty() && !leaf.contains('/'), "unsafe leaf");
    let p = root.join(leaf);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(Bound::new(p, digest(bytes)))
}
fn save_json(root: &Path, leaf: &str, value: &Value) -> Result<Bound> {
    save(root, leaf, &serde_json::to_vec_pretty(value)?)
}
fn absent(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("already exists {}", p.display()),
    }
}

/// Every subprocess is bounded; its actual stdout/stderr are retained, never synthesized.
struct Native {
    root: PathBuf,
    counter: u32,
    deadline: Option<u64>,
}
impl Native {
    fn check(&self) -> Result<()> {
        if let Some(d) = self.deadline {
            ensure!(mono()? < d, "original startup clock expired");
        }
        Ok(())
    }
    fn run(&mut self, exe: &str, args: &[&str]) -> Result<Vec<u8>> {
        self.check()?;
        self.counter += 1;
        let out = self
            .root
            .join(format!("command-{:04}.stdout", self.counter));
        let err = self
            .root
            .join(format!("command-{:04}.stderr", self.counter));
        let make = |p: &Path| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(p)
        };
        let mut child = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(make(&out)?)
            .stderr(make(&err)?)
            .spawn()?;
        let limit = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(s) = child.try_wait()? {
                ensure!(s.success(), "command failed: {exe}; see {}", err.display());
                break;
            }
            if Instant::now() >= limit || self.check().is_err() {
                let _ = child.kill();
                let _ = child.wait();
                bail!("command deadline {exe}");
            }
            // Publication checks execute thousands of short Git reads. A 10ms
            // polling floor per completed child can outlive the retained guard
            // invocation and the admission lease even though useful work is done.
            // Preserve both deadlines and every output/exit check; reduce only
            // the latency before observing child completion.
            std::thread::sleep(Duration::from_millis(1));
        }
        self.check()?;
        ensure!(
            fs::metadata(&out)?.len() <= 16 << 20,
            "native output oversized"
        );
        Ok(fs::read(out)?)
    }
    fn show(&mut self, unit: &str) -> Result<Value> {
        ensure!(
            (unit.ends_with(".service") || unit.ends_with(".timer") || unit.ends_with(".target"))
                && unit.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
            "unit suffix"
        );
        let bytes = self.run(
            "/usr/bin/systemctl",
            &["show", unit, "--no-pager", "--property", live::PROPS],
        )?;
        let mut v = serde_json::Map::new();
        for line in std::str::from_utf8(&bytes)?.lines() {
            let (k, val) = line.split_once('=').context("systemd property framing")?;
            ensure!(
                v.insert(k.into(), json!(val)).is_none(),
                "duplicate native property"
            );
        }
        Ok(Value::Object(v))
    }
}

pub(super) fn capture(path: &str, sha: &str, self_sha: &str, output: &str) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        hex(self_sha, 64) && hash(Path::new("/proc/self/exe"))? == self_sha,
        "launcher image differs"
    );
    let review_ref = Bound::new(path, sha);
    let review = review_ref.sealed()?;
    let plan = binding(&review["launch_plan"])?.sealed()?;
    super::inputs::plan_validate(&plan)?;
    super::inputs::check_inputs()?;
    let root = PathBuf::from(output);
    ensure!(
        root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon265-current-execution-")
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "execution namespace"
    );
    absent(&root)?;
    trusted_parents(&root)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let mut n = Native {
        root,
        counter: 0,
        deadline: None,
    };
    let result = (|| {
        let native = admission::validate(&mut n, &review, &review_ref, self_sha, false)?;
        retained_guards(&mut n, &review)?;
        let a = json!({"schema":"horizon265-current-fleet-launch-admission-v1","candidate_epoch":265,"admitted":true,"review":review_ref,"launch_plan":review["launch_plan"],"launcher_sha256":self_sha,"native_admission":native,"issued_unix_seconds":native["recorded_unix_seconds"],"expires_unix_seconds":native["expires_unix_seconds"],"guard_minimum_free_bytes":native["capacity"]["protected_existing_floor_bytes"],"required_initial_free_bytes":native["capacity"]["required_initial_free_bytes"],"candidate_memory_max_bytes":MEMORY,"candidate_root_cap_bytes":SCRATCH,"remote_mutations":false,"publication_authorized":false,"replay_observed":false});
        let out = save_json(&n.root, "admission.json", &a)?;
        println!("{}", serde_json::to_string(&out)?);
        Ok(())
    })();
    if let Err(ref e) = result {
        let _ = save_json(
            &n.root,
            "failure.json",
            &json!({"error":format!("{e:#}"),"automatic_retry":false,"remote_mutations":false}),
        );
    }
    result
}
pub(super) fn validate_admission(a: &Value, plan: &Value) -> Result<()> {
    ensure!(
        a["schema"] == "horizon265-current-fleet-launch-admission-v1"
            && a["candidate_epoch"] == 265
            && a["admitted"] == true
            && a["launch_plan"] == *plan
            && a["candidate_memory_max_bytes"] == MEMORY
            && a["candidate_root_cap_bytes"] == SCRATCH
            && a["remote_mutations"] == false
            && a["publication_authorized"] == false
            && a["replay_observed"] == false,
        "foreign admission"
    );
    let issued = num(a, "issued_unix_seconds")?;
    let expires = num(a, "expires_unix_seconds")?;
    ensure!(
        expires > issued && expires - issued <= 60 && now()? >= issued && now()? < expires,
        "original admission lease expired"
    );
    ensure!(
        a["native_admission"]["review"] == a["review"]
            && a["native_admission"]["capacity"]["protected_existing_floor_bytes"]
                == a["guard_minimum_free_bytes"]
            && a["native_admission"]["capacity"]["required_initial_free_bytes"]
                == a["required_initial_free_bytes"],
        "admission extraction changed"
    );
    ensure!(
        hash(Path::new("/proc/self/exe"))? == text(a, "launcher_sha256")?,
        "admission launcher changed"
    );
    let review = binding(&a["review"])?.sealed()?;
    ensure!(review["launch_plan"] == *plan, "review plan changed");
    no_authority(&a["native_admission"])?;
    Ok(())
}
pub(super) fn census(outer: &mut super::Native, a: &Value, candidate: bool) -> Result<()> {
    validate_admission(a, &a["launch_plan"])?;
    outer.check()?;
    outer.counter += 1;
    let root = outer
        .root
        .join(format!("current-census-{:03}", outer.counter));
    absent(&root)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let remaining = outer
        .deadline
        .map(|d| d.saturating_duration_since(Instant::now()));
    let deadline = remaining
        .map(|d| {
            mono().and_then(|m| {
                m.checked_add(d.as_micros().try_into()?)
                    .context("deadline overflow")
            })
        })
        .transpose()?;
    let mut n = Native {
        root,
        counter: 0,
        deadline,
    };
    let review_ref = binding(&a["review"])?;
    let review = review_ref.sealed()?;
    let fresh = admission::validate(
        &mut n,
        &review,
        &review_ref,
        text(a, "launcher_sha256")?,
        candidate,
    )?;
    // The fresh calculation can only require a tighter envelope, never renew the lease.
    ensure!(
        num(&fresh["capacity"], "protected_existing_floor_bytes")?
            <= num(a, "guard_minimum_free_bytes")?
            && num(&fresh["capacity"], "required_initial_free_bytes")?
                <= num(a, "required_initial_free_bytes")?,
        "new capacity needs a fresh admission"
    );
    retained_guards(&mut n, &review)?;
    save_json(&n.root, "fresh-current-census.json", &fresh)?;
    validate_admission(a, &a["launch_plan"])?;
    outer.check()?;
    Ok(())
}
fn retained_guards(n: &mut Native, review: &Value) -> Result<()> {
    let fleet = binding(&review["fleet"])?.json()?;
    let claims = review["retained_replay_guards"]
        .as_array()
        .context("retained replay guard census")?;
    let mut seen = BTreeSet::new();
    for active in fleet["active"].as_array().context("active fleet")? {
        if !matches!(active["phase"].as_str(), Some("replay" | "qualification")) {
            continue;
        }
        let unit = text(&active["producer"], "Id")?;
        if !seen.insert(unit) {
            continue;
        }
        let c: Vec<_> = claims
            .iter()
            .filter(|c| c["producer_unit"] == unit)
            .collect();
        ensure!(c.len() == 1, "missing/duplicate retained replay guard");
        let c = c[0];
        let producer_iid = text(&active["producer"], "InvocationID")?;
        let plan_ref = binding(&c["plan"])?;
        let p = plan_ref.json()?;
        let guard_ref = binding(&c["guard_artifact"])?;
        guard_ref.artifact()?;
        ensure!(
            p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
                && p["unit"] == unit
                && p["invocation_id"] == producer_iid,
            "retained guard owner differs"
        );
        let sample = binding(&c["sample"])?.json()?;
        let guard_iid = text(&sample, "guard_invocation_id")?;
        ensure!(
            hex(guard_iid, 32)
                && sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                && sample["producer_invocation_id"] == producer_iid
                && sample["plan"] == plan_ref.path.to_str().context("plan UTF8")?
                && sample["plan_sha256"] == plan_ref.sha256
                && sample["guard_sha256"] == guard_ref.sha256
                && sample["producer_stop_enabled"] == true,
            "retained guard sample binding differs"
        );
        fresh(num(&sample, "recorded_unix_seconds")?, now()?, 120)?;
        for key in [
            "trip_reason",
            "worker_observation_error",
            "root_physical_observation_error",
            "target_handoff_error",
            "canary_target_error",
        ] {
            ensure!(
                sample.get(key) == Some(&Value::Null),
                "retained guard error {key}"
            );
        }
        for key in [
            "minimum_free_bytes",
            "maximum_root_physical_bytes",
            "maximum_worker_vmas",
        ] {
            ensure!(sample[key] == p[key], "retained guard envelope changed");
        }
        let guard = n.show(text(c, "guard_unit")?)?;
        let timer = n.show(text(c, "timer_unit")?)?;
        ensure!(
            guard["InvocationID"] == guard_iid
                && guard["ActiveState"] == "inactive"
                && guard["Result"] == "success"
                && guard["ExecMainStatus"] == "0"
                && guard["MainPID"] == "0"
                && guard["ControlPID"] == "0"
                && guard["NRestarts"] == "0"
                && guard["Job"] == "",
            "retained guard not at accepted clean completion"
        );
        ensure!(
            timer["LoadState"] == "loaded"
                && timer["ActiveState"] == "active"
                && timer["SubState"] == "waiting"
                && timer["Unit"] == c["guard_unit"]
                && timer["Job"] == "",
            "retained guard timer unarmed"
        );
        let command = format!(
            "{{ path={} ; argv[]={0} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ;",
            guard_ref.path.display(),
            plan_ref.path.display(),
            plan_ref.sha256,
            guard_ref.sha256
        );
        ensure!(
            text(&guard, "ExecStart")?.starts_with(&command),
            "retained guard command changed"
        );
    }
    ensure!(seen.len() == claims.len(), "foreign retained guard claim");
    Ok(())
}

/// Exact native265 result and completed guard history accepted by the Rust capture.
pub(super) fn native_input(reference: &Value) -> Result<()> {
    peers::input265(reference)
}

// Use an actual retained timer window; never infer a fresh 60s interval from a
// manually triggered guard or accept a different guard IID under the old claim.
const RETAINED_START_WINDOW_US: u64 = 30_000_000;
const RETAINED_WINDOW_MARGIN_US: u64 = 5_000_000;
pub(super) fn guard_window_budget(next: u64, clock: u64) -> Result<u64> {
    let remaining = next
        .checked_sub(clock)
        .context("retained timer already due")?;
    ensure!(
        (RETAINED_START_WINDOW_US..=65_000_000).contains(&remaining),
        "retained timer lacks an actual 30s startup window"
    );
    Ok(remaining - RETAINED_WINDOW_MARGIN_US)
}
fn guard_window_next(raw: &[u8], clock: u64) -> Result<u64> {
    let words: Vec<_> = std::str::from_utf8(raw)?.split_whitespace().collect();
    ensure!(
        words.len() == 2 && words[0] == "t",
        "retained timer deadline type"
    );
    let next = words[1].parse::<u64>()?;
    guard_window_budget(next, clock)?;
    Ok(next)
}
pub(super) fn guard_start_window(outer: &mut super::Native, a: &Value) -> Result<u64> {
    validate_admission(a, &a["launch_plan"])?;
    outer.check()?;
    outer.counter += 1;
    let root = outer
        .root
        .join(format!("retained-window-{:03}", outer.counter));
    absent(&root)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let mut n = Native {
        root,
        counter: 0,
        deadline: None,
    };
    let review = binding(&a["review"])?.sealed()?;
    retained_guards(&mut n, &review)?;
    let claims = review["retained_replay_guards"]
        .as_array()
        .context("retained claims")?;
    ensure!(!claims.is_empty(), "no retained timer window");
    let mut earliest = u64::MAX;
    let mut evidence = Vec::new();
    for c in claims {
        let guard_unit = text(c, "guard_unit")?;
        let timer_unit = text(c, "timer_unit")?;
        let sample = binding(&c["sample"])?.json()?;
        let guard_before = n.show(guard_unit)?;
        let timer_before = n.show(timer_unit)?;
        ensure!(
            guard_before["InvocationID"] == sample["guard_invocation_id"],
            "retained guard changed before window capture"
        );
        let object = format!(
            "/org/freedesktop/systemd1/unit/{}",
            timer_unit
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() {
                    c.to_string()
                } else {
                    format!("_{:02x}", c as u32)
                })
                .collect::<String>()
        );
        let raw = n.run(
            "/usr/bin/busctl",
            &[
                "get-property",
                "org.freedesktop.systemd1",
                &object,
                "org.freedesktop.systemd1.Timer",
                "NextElapseUSecMonotonic",
            ],
        )?;
        let clock = mono()?;
        let next = guard_window_next(&raw, clock)?;
        let guard_after = n.show(guard_unit)?;
        let timer_after = n.show(timer_unit)?;
        // Exact snapshots deliberately reject a rollover, jobs, or timer changes.
        ensure!(
            guard_before == guard_after && timer_before == timer_after,
            "retained guard/timer changed across window capture"
        );
        earliest = earliest.min(next);
        evidence.push(json!({"claim":c,"guard":guard_after,"timer":timer_after,
            "typed_deadline":String::from_utf8(raw)?,"clock_monotonic_us":clock,
            "next_elapse_monotonic_us":next}));
    }
    // Reapply every original sample/owner/command/health check after all reads.
    retained_guards(&mut n, &review)?;
    guard_window_budget(earliest, mono()?)?;
    save_json(
        &n.root,
        "accepted-retained-window.json",
        &json!({
        "schema":"horizon265-actual-retained-start-window-v1", "review":a["review"],
        "evidence":evidence,"earliest_next_elapse_monotonic_us":earliest,
        "minimum_start_window_us":RETAINED_START_WINDOW_US,
        "deadline_margin_us":RETAINED_WINDOW_MARGIN_US,
        "guard_iid_rollover_accepted":false,"lease_renewed":false,
        "existing_units_changed":false,"replay_launch_authorized":false}),
    )?;
    validate_admission(a, &a["launch_plan"])?;
    outer.check()?;
    Ok(earliest)
}
#[cfg(test)]
mod guard_window_tests {
    use super::*;
    #[test]
    fn actual_28s_window_cannot_be_misreported_as_60s() {
        assert!(guard_window_budget(128_000_000, 100_000_000).is_err());
        assert_eq!(
            guard_window_budget(160_000_000, 100_000_000).unwrap(),
            55_000_000
        );
        assert_eq!(
            guard_window_budget(130_000_000, 100_000_000).unwrap(),
            25_000_000
        );
    }
    #[test]
    fn elapsed_windows_and_nonmonotonic_typed_deadlines_fail_closed() {
        for raw in [
            "s 160000000",
            "t 160000000 extra",
            "t 0",
            "t 100000000",
            "t 99999999",
            "t 166000000",
        ] {
            assert!(
                guard_window_next(raw.as_bytes(), 100_000_000).is_err(),
                "{raw}"
            );
        }
        assert_eq!(
            guard_window_next(b"t 160000000\n", 100_000_000).unwrap(),
            160_000_000
        );
    }
}
