//! Source-only replacement166–168 admission and exact launch-recipe emitter.
//! This binary does NOT start, stop, authenticate, seal, or publish anything.
//! Its preparation receipt is not a post-launch admission or guard receipt.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
mod local;
mod profile;
use local::LocalInputs;
use profile::{Profile, profile};
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-standard-replacement-recipes-20261110-v9/prepare";
const EVENT: &str = "/var/lib/jetstreamer/seven-standard-reserve-stop-20261110-v1/ORIGINAL_SEVEN_RESERVE_STOPS_AND_REPAIR_MODEL.json";
const EVENT_SHA: &str = "b3bff5d44d24dc507313d8dfdb8e5cd5bec50a7732b288327106ee20b7a7b0eb";
const AUTHORITY: &str = "/usr/local/lib/jetstreamer/horizon-original154-future-data-current-authority-20261110-v1/authority.json";
const AUTHORITY_SHA: &str = "2f88b7f91cc6df70804cd96027efbd0e18cb6452a48e76d813673b556d727caa";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const GUARD: &str = "/usr/local/lib/jetstreamer/horizon-original141-trace-guard-20261023-v1/jetstreamer-horizon-standalone-guard";
const GUARD_SHA: &str = "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
const DATA: u64 = 6_229_838_610_226;
const FLOOR: u64 = 6_264_131_239_730;
const MEMORY: u64 = 759_789_531_136;
const RESERVE: u64 = 17_179_869_184;
const ROOT_CAP: u64 = 309_237_645_312;
const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const OUT: &str = "/var/lib/jetstreamer/standard-replacement-recipes-20261110-v9";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    owner: String,
    primary_thread: String,
    epoch: u64,
    attempt: String,
    review: Bound,
    fleet: Bound,
    inventory: Bound,
    input_proof: Bound,
    cleanup_completion: Bound,
    closed_units: Vec<String>,
    producer_unit: String,
    guard_base: String,
    // Must already exist and be empty, owned sol:horizon0700.
    fresh_subtree: PathBuf,
    prepare_authorized: bool,
    replay_launch_authorized: bool,
    resource_promise_ending_authorized: bool,
    remote_mutations: bool,
    local_inputs: Option<LocalInputs>,
    existing_preparation: Option<Bound>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Review {
    schema: String,
    owner: String,
    primary_thread: String,
    epoch: u64,
    attempt: String,
    recorded_unix_seconds: u64,
    source_fleet: Bound,
    source_inventory: Bound,
    input_proof: Bound,
    cleanup_completion: Bound,
    complete_authority: Bound,
    full_current_proc_and_unit_census: Bound,
    all_original_and_replacement_launchers_in_closed_units: bool,
    no_target_active_or_queued_claim: bool,
    old_partial_and_inputs_preserved: bool,
    all_prior_promises_retained: bool,
    exclusive_original_slot_replacement: bool,
    complete_projected_memory_bytes: u64,
    complete_data_bytes: u64,
    minimum_initial_available_data_bytes: u64,
    candidate_remaining_growth_bytes: u64,
    fresh_subtree_overlap_booked_bytes: u64,
    // All values include original partial/input/state and are bound to a full
    // no-follow physical ledger. Rebinding an old promise never deletes it.
    retained_lane_physical_bytes: u64,
    existing_original_slot_future_growth_bytes: u64,
    proposed_fresh_working_maximum_bytes: u64,
    additional_growth_not_covered_by_existing_promise_bytes: u64,
    exact_slot_mapping_and_physical_ledger: Bound,
    normal_pool_bytes: u64,
    verifier_pool_bytes: u64,
    native_pool_bytes: u64,
    shared_pool_bytes: u64,
    complete_booked_cpu_quota_micros: u64,
    resource_credit_bytes: u64,
    memory_or_data_promise_ending_bytes: u64,
    ordinary_full_plugin_boundary_gates_retained: bool,
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn directory(p: &Path) -> Result<File> {
    ensure!(p.is_absolute(), "absolute path required");
    let mut d = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for c in p.components() {
        match c {
            Component::RootDir => (),
            Component::Normal(n) => {
                let n = CString::new(n.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        d.as_raw_fd(),
                        n.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(fd >= 0, "directory traversal failed: {}", p.display());
                d = unsafe { File::from_raw_fd(fd) };
            }
            _ => anyhow::bail!("noncanonical path"),
        }
    }
    ensure!(p.canonicalize()? == p, "directory alias");
    Ok(d)
}
fn raw(p: &Path, limit: u64, immutable: bool) -> Result<Vec<u8>> {
    let parent = directory(p.parent().context("parent")?)?;
    let name = CString::new(p.file_name().context("filename")?.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(fd >= 0, "open evidence failed: {}", p.display());
    let mut f = unsafe { File::from_raw_fd(fd) };
    let a = f.metadata()?;
    ensure!(
        a.is_file()
            && a.uid() == 0
            && a.nlink() == 1
            && a.len() <= limit
            && a.mode() & 0o022 == 0
            && (!immutable || a.mode() & 0o222 == 0),
        "unsafe evidence"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == a.len()
            && identity(&a) == identity(&f.metadata()?)
            && identity(&a) == identity(&fs::symlink_metadata(p)?),
        "evidence changed"
    );
    Ok(bytes)
}
fn bound(b: &Bound) -> Result<Value> {
    ensure!(lower_hex(&b.sha256, 64), "digest shape");
    let bytes = raw(&b.path, 32 << 20, false)?;
    ensure!(
        digest(&bytes) == b.sha256,
        "bound evidence differs: {}",
        b.path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn fixed(p: &str, sha: &str, limit: u64) -> Result<()> {
    ensure!(
        digest(&raw(Path::new(p), limit, true)?) == sha,
        "immutable image changed"
    );
    Ok(())
}
fn verify_self(expected: &str) -> Result<()> {
    let mut f = File::open("/proc/self/exe")?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o222 == 0 && m.len() <= 64 << 20,
        "unsafe executing image"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take((64 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        digest(&bytes) == expected && identity(&m) == identity(&f.metadata()?),
        "actual executing image digest differs"
    );
    fixed(IMAGE, expected, 64 << 20)?;
    ensure!(
        identity(&m) == identity(&fs::symlink_metadata(IMAGE)?),
        "runtime pathname differs from executing inode"
    );
    Ok(())
}
fn native(unit: &str) -> Result<BTreeMap<String, String>> {
    let o=Command::new("/usr/bin/systemctl").args(["show",unit,"-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Job"]).output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 65536,
        "native unit query failed"
    );
    let mut m = BTreeMap::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("unit field")?;
        ensure!(
            m.insert(k.into(), v.into()).is_none(),
            "duplicate native field"
        );
    }
    Ok(m)
}
fn closed(m: &BTreeMap<String, String>, unit: &str) -> Result<()> {
    ensure!(
        m.get("Id").map(String::as_str) == Some(unit)
            && m.get("ActiveState")
                .is_some_and(|x| matches!(x.as_str(), "inactive" | "failed"))
            && (m.get("MainPID").map(String::as_str) == Some("0")
                || (unit.ends_with(".timer") && !m.contains_key("MainPID")))
            && (m.get("ControlPID").map(String::as_str) == Some("0")
                || (unit.ends_with(".timer") && !m.contains_key("ControlPID")))
            && m.get("Job").map(String::as_str) == Some(""),
        "active or queued target owner"
    );
    Ok(())
}
fn unit_name(s: &str, suffix: &str) -> bool {
    s.len() <= 255
        && s.ends_with(suffix)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
}
fn shapes(p: &Plan) -> Result<&'static Profile> {
    let s = profile(p.epoch)?;
    ensure!(
        p.schema == "horizon-standard-replacement-recipe-plan-v1"
            && p.owner == "/root"
            && p.primary_thread == THREAD,
        "foreign plan"
    );
    ensure!(
        p.prepare_authorized
            && !p.replay_launch_authorized
            && !p.resource_promise_ending_authorized
            && !p.remote_mutations,
        "recipe-only authority required"
    );
    ensure!(
        !p.attempt.is_empty()
            && p.attempt.len() <= 64
            && p.attempt
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "attempt spelling"
    );
    ensure!(
        p.producer_unit
            == format!(
                "horizon-qualify-{}-replacement-{}-20261110-v1.service",
                p.epoch, p.attempt
            )
            && p.guard_base
                == format!(
                    "horizon-guard-replacement-{}-{}-20261110-v1",
                    p.epoch, p.attempt
                ),
        "new exact unit namespace required"
    );
    ensure!(
        p.fresh_subtree == Path::new(s.lane).join(format!("replacement-{}-20261110-v1", p.attempt)),
        "fresh subtree must be disjoint inside original bounded lane"
    );
    let set: BTreeSet<_> = p.closed_units.iter().map(String::as_str).collect();
    ensure!(
        set.len() == p.closed_units.len()
            && set.len() <= 64
            && set.contains(s.old_unit)
            && set.contains(p.producer_unit.as_str())
            && set.contains(format!("{}.timer", p.guard_base).as_str())
            && set.contains(format!("{}.service", p.guard_base).as_str())
            && set.contains(format!("{}.timer", s.old_guard).as_str())
            && set.contains(format!("{}.service", s.old_guard).as_str())
            && set.contains("jetstreamer-epochs159-173-target1-controller-v1-r2.service"),
        "incomplete exact closed-unit list"
    );
    ensure!(
        set.iter()
            .all(|u| unit_name(u, ".service") || unit_name(u, ".timer")),
        "unit spelling"
    );
    Ok(s)
}
fn review_shape(p: &Plan, r: &Review, at: u64) -> Result<()> {
    ensure!(
        r.schema == "horizon-standard-replacement-prelaunch-review-v1"
            && r.owner == "/root"
            && r.primary_thread == THREAD
            && r.epoch == p.epoch
            && r.attempt == p.attempt,
        "foreign prelaunch review"
    );
    ensure!(
        r.recorded_unix_seconds <= at && at - r.recorded_unix_seconds <= 120,
        "stale prelaunch review"
    );
    ensure!(
        r.source_fleet == p.fleet
            && r.source_inventory == p.inventory
            && r.input_proof == p.input_proof
            && r.cleanup_completion == p.cleanup_completion
            && r.complete_authority.path == Path::new(AUTHORITY)
            && r.complete_authority.sha256 == AUTHORITY_SHA,
        "review binding differs"
    );
    ensure!(
        r.all_original_and_replacement_launchers_in_closed_units
            && r.no_target_active_or_queued_claim
            && r.old_partial_and_inputs_preserved
            && r.all_prior_promises_retained
            && r.exclusive_original_slot_replacement
            && r.ordinary_full_plugin_boundary_gates_retained,
        "Root's complete census, preservation and exclusive old-slot mapping required"
    );
    ensure!(
        r.complete_projected_memory_bytes == MEMORY
            && r.complete_data_bytes == DATA
            && r.minimum_initial_available_data_bytes >= FLOOR
            && r.candidate_remaining_growth_bytes <= ROOT_CAP
            && r.fresh_subtree_overlap_booked_bytes >= 64 << 20
            && r.normal_pool_bytes == 10 << 30
            && r.verifier_pool_bytes == 96 << 30
            && r.native_pool_bytes == 16 << 30
            && r.shared_pool_bytes == 64 << 30
            && r.resource_credit_bytes == 0
            && r.memory_or_data_promise_ending_bytes == 0,
        "resource promise reduction or unsupported accounting"
    );
    ensure!(
        r.complete_booked_cpu_quota_micros >= 9_000_000,
        "candidate CPU missing"
    );
    slot_budget(r)?;
    Ok(())
}
fn slot_budget(r: &Review) -> Result<()> {
    let combined = r
        .retained_lane_physical_bytes
        .checked_add(r.proposed_fresh_working_maximum_bytes)
        .context("combined lane growth overflow")?;
    ensure!(
        r.retained_lane_physical_bytes > 0
            && r.proposed_fresh_working_maximum_bytes > 0
            && combined <= ROOT_CAP,
        "retained old data plus proposed fresh working set exceeds unchanged combined lane cap"
    );
    let original_remaining = ROOT_CAP
        .checked_sub(r.retained_lane_physical_bytes)
        .context("old lane already exceeds cap")?;
    ensure!(
        r.existing_original_slot_future_growth_bytes <= original_remaining,
        "old remaining promise exceeds actual retained-root allowance"
    );
    let extra = r
        .proposed_fresh_working_maximum_bytes
        .saturating_sub(r.existing_original_slot_future_growth_bytes);
    ensure!(
        extra == r.additional_growth_not_covered_by_existing_promise_bytes,
        "exclusive handoff arithmetic differs; old future promise cannot silently disappear"
    );
    let minimum = FLOOR
        .max(DATA)
        .checked_add(extra)
        .and_then(|n| n.checked_add(r.fresh_subtree_overlap_booked_bytes))
        .context("fresh disk demand overflow")?;
    ensure!(
        r.minimum_initial_available_data_bytes >= minimum
            && r.candidate_remaining_growth_bytes == r.proposed_fresh_working_maximum_bytes,
        "remaining-growth and overlap admission not fully charged"
    );
    Ok(())
}
fn stop_chain(s: &Profile) -> Result<Value> {
    let event = bound(&Bound {
        path: EVENT.into(),
        sha256: EVENT_SHA.into(),
    })?;
    ensure!(
        event["schema"] == "horizon-seven-standard-reserve-stop-repair-event-v1"
            && event["owner"] == "/root"
            && event["resource_promises_released"] == false,
        "foreign original stop event"
    );
    let r = &event["rows"][s.epoch.to_string()];
    ensure!(
        r["unit"] == s.old_unit
            && r["original_invocation_id"] == s.old_iid
            && r["preserve_partial_and_inputs"] == true
            && r["no_resource_release"] == true,
        "original epoch stop mismatch"
    );
    let ib: Bound = serde_json::from_value(r["stop_intent"].clone())?;
    let cb: Bound = serde_json::from_value(r["stop_completion"].clone())?;
    ensure!(
        ib.sha256 == s.intent_sha && cb.sha256 == s.completion_sha,
        "original stop-chain digests differ"
    );
    let i = bound(&ib)?;
    let c = bound(&cb)?;
    ensure!(
        i["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && c["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && i["producer_invocation_id"] == s.old_iid
            && c["producer_invocation_id"] == s.old_iid
            && i["reason"] == "filesystem-floor"
            && c["intent"] == serde_json::to_value(&ib.path)?
            && i["plan_sha256"] == c["plan_sha256"]
            && i["sample"]["producer_stop_enabled"] == true,
        "original stop chain invalid"
    );
    let j: Bound = serde_json::from_value(r["journal"].clone())?;
    let _ = bound(&j)?;
    let partial = PathBuf::from(r["original_archive"].as_str().context("old partial")?);
    let m = fs::symlink_metadata(&partial)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.uid() == 1001 && m.len() > 0,
        "old partial not preserved"
    );
    Ok(
        json!({"event":{"path":EVENT,"sha256":EVENT_SHA},"intent":ib,"completion":cb,"journal":j,"old_partial":{"path":partial,"identity":identity(&m)}}),
    )
}
fn input_shape(proof: &Value, manifest: &Value, p: &Plan, s: &Profile, at: u64) -> Result<()> {
    if let Some(inputs) = &p.local_inputs {
        return local::validate_inputs(inputs, proof, manifest, p, s, at);
    }

    ensure!(
        proof["schema"] == "horizon-standard-effective-generation-proof-v1"
            && proof["owner"] == "/root"
            && proof["epoch"] == p.epoch
            && proof["effective_config"] == format!("{}/config/gcloud", s.lane)
            && proof["account"] == "sam.johnson@anza.xyz"
            && proof["project"] == "principal-lane-200702"
            && proof["fresh_effective_config_installed"] == true,
        "fresh effective credential/input proof required"
    );
    let t = proof["recorded_unix_seconds"]
        .as_u64()
        .context("input proof clock")?;
    ensure!(t <= at && at - t <= 1800, "stale input proof");
    ensure!(
        proof["authentication_succeeded"] == true
            && proof["cached_bootstrap_used_to_bypass_authentication"] == false
            && proof["config_coherent_copy_receipt"].is_object(),
        "failed authentication cannot be bypassed"
    );
    let copy: Bound = serde_json::from_value(proof["config_coherent_copy_receipt"].clone())?;
    let _ = bound(&copy)?;
    let cs = manifest["manifest"]["verification_cohorts"]
        .as_array()
        .context("cohort")?;
    ensure!(
        cs.len() == 1
            && cs[0]["first_epoch"] == p.epoch
            && cs[0]["last_epoch"] == p.epoch
            && cs[0]["publish_through_epoch"] == p.epoch
            && cs[0]["runtime"] == "solana-v1.5.6",
        "wrong singleton runtime"
    );
    let mut expected = vec![cs[0]["bootstrap"].clone()];
    expected.extend(
        cs[0]["root_checkpoints"]
            .as_array()
            .context("root checkpoints")?
            .iter()
            .cloned(),
    );
    let probes = proof["generation_probes"]
        .as_array()
        .context("genuine exact generation probes")?;
    ensure!(
        probes.len() == expected.len(),
        "incomplete generation probes"
    );
    let mut seen = BTreeSet::new();
    for object in &expected {
        let uri = object["versioned_uri"].as_str().context("versioned URI")?;
        ensure!(seen.insert(uri), "duplicate manifest object");
        let candidates: Vec<_> = probes
            .iter()
            .filter(|q| q["versioned_uri"] == uri)
            .collect();
        ensure!(
            candidates.len() == 1,
            "missing/duplicate exact object probe"
        );
        let q = candidates[0];
        for field in ["generation", "size", "crc32c", "md5_hash"] {
            ensure!(
                q.get(field) == object.get(field),
                "effective GCS generation/size/digest mismatch"
            );
        }
        let e: Bound = serde_json::from_value(q["execution"].clone())?;
        let exec = bound(&e)?;
        ensure!(
            exec["code"] == 0
                && exec["effective_config"] == proof["effective_config"]
                && exec["versioned_uri"] == uri,
            "effective generation execution failed or wrong config"
        );
    }
    Ok(())
}
fn producer_recipe(original: &[String], p: &Plan, s: &Profile) -> Result<Vec<String>> {
    ensure!(
        original.first().map(String::as_str) == Some("/usr/bin/systemd-run"),
        "original launcher differs"
    );
    let mut out = Vec::with_capacity(original.len());
    let oldlog = format!("{}/producer.log", s.lane);
    let newlog = p.fresh_subtree.join("producer.log");
    let newprivate = p.fresh_subtree.join("private");
    let oldprivate = format!("{}/private", s.lane);
    let oldoutput = format!("{}/output", s.lane);
    let replacements = BTreeMap::from([
        (
            format!("--unit={}", s.old_unit),
            format!("--unit={}", p.producer_unit),
        ),
        (
            format!("--property=StandardOutput=append:{oldlog}"),
            format!("--property=StandardOutput=append:{}", newlog.display()),
        ),
        (
            format!("--property=StandardError=append:{oldlog}"),
            format!("--property=StandardError=append:{}", newlog.display()),
        ),
        (
            format!("--setenv=JETSTREAMER_PRIVATE_RUN_ROOT={oldprivate}"),
            format!(
                "--setenv=JETSTREAMER_PRIVATE_RUN_ROOT={}",
                newprivate.display()
            ),
        ),
        (
            oldoutput,
            p.fresh_subtree.join("output").display().to_string(),
        ),
    ]);
    let mut applied = BTreeSet::new();
    for a in original {
        ensure!(
            !a.contains("ROOT_COHORT_RESUME_RUN")
                && !a.contains("SNAPSHOT_ARCHIVE_OVERRIDE")
                && !a.contains("BOOTSTRAP_OVERRIDE"),
            "no retained output or cached credential bypass"
        );
        if let Some(b) = replacements.get(a) {
            ensure!(applied.insert(a.clone()), "duplicate mutable argv token");
            out.push(b.clone());
        } else {
            out.push(a.clone());
        }
    }
    ensure!(
        applied.len() == replacements.len(),
        "expected exact original token absent"
    );
    for x in [
        "--property=MemoryHigh=68719476736",
        "--property=MemoryMax=73014444032",
        "--property=MemorySwapMax=0",
        "--property=CPUQuota=900%",
        "--property=TasksMax=1024",
        "--property=Restart=no",
        "--setenv=JETSTREAMER_VERIFY_SNAPSHOTS=1",
        "--setenv=JETSTREAMER_SKIP_SNAPSHOT_VERIFY=0",
        "--setenv=JETSTREAMER_ENFORCE_ARCHIVE_HASH=1",
        "--verify",
        "--root-checkpoint-cohort",
    ] {
        ensure!(
            out.iter().any(|a| a == x),
            "standard immutable runtime/integrity token absent: {x}"
        );
    }
    if let Some(inputs) = &p.local_inputs {
        out.push(format!(
            "--snapshot-archive={}",
            inputs.bootstrap.path.display()
        ));
    }
    Ok(out)
}
fn guard_template(p: &Plan, s: &Profile) -> Value {
    json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":p.producer_unit,"invocation_id":"REPLACE_ONLY_WITH_ACTUAL_NEW_NATIVE_PRODUCER_IID","filesystem":"/home/sol","minimum_free_bytes":FLOOR,"worker_root":s.lane,"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":ROOT_CAP,"receipt_directory":format!("{OUT}/epoch{}/{}/guard-state/receipts",p.epoch,p.attempt)})
}
fn guard_recipe_template(p: &Plan) -> Vec<String> {
    let state = format!("{OUT}/epoch{}/{}/guard-state", p.epoch, p.attempt);
    let mut a = vec![
        "/usr/bin/systemd-run".into(),
        format!("--unit={}", p.guard_base),
    ];
    a.extend(
        [
            "--on-active=1s",
            "--on-unit-inactive=5s",
            "--timer-property=AccuracySec=1s",
            "--service-type=oneshot",
            "--property=User=root",
            "--property=Group=root",
            "--property=UMask=0077",
            "--property=Restart=no",
            "--property=MemoryMax=1G",
            "--property=MemorySwapMax=0",
            "--property=CPUQuota=100%",
            "--property=TasksMax=256",
            "--property=TimeoutStartSec=120",
            "--property=TimeoutStopSec=15",
            "--property=PrivateNetwork=yes",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=read-only",
            "--property=PrivateTmp=yes",
            "--property=NoNewPrivileges=yes",
            "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
            "--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
        ]
        .map(String::from),
    );
    a.extend([
        format!("--property=ReadWritePaths={state}/receipts"),
        format!("--property=StandardOutput=append:{state}/guard.stdout"),
        format!("--property=StandardError=append:{state}/guard.stderr"),
        GUARD.into(),
        "REPLACE_WITH_NORMALLY_SEALED_ACTUAL_IID_BOUND_GUARD_PLAN_PATH".into(),
        "--plan-sha256".into(),
        "REPLACE_WITH_SEALED_ACTUAL_PLAN_SHA256".into(),
        "--self-sha256".into(),
        GUARD_SHA.into(),
    ]);
    a
}
fn resource_check(r: &Review) -> Result<Value> {
    let mut mem = BTreeMap::new();
    for line in fs::read_to_string("/proc/meminfo")?.lines() {
        let (k, v) = line.split_once(':').context("meminfo")?;
        if matches!(k, "MemTotal" | "MemAvailable") {
            let n = v
                .split_whitespace()
                .next()
                .context("mem value")?
                .parse::<u64>()?
                .checked_mul(1024)
                .context("mem overflow")?;
            mem.insert(k.to_string(), n);
        }
    }
    let need = MEMORY.checked_add(RESERVE).context("memory overflow")?;
    ensure!(
        mem.get("MemTotal").is_some_and(|n| *n >= need)
            && mem.get("MemAvailable").is_some_and(|n| *n >= need),
        "fresh complete-memory plus16GiB reserve does not fit"
    );
    let root = CString::new("/home/sol")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(root.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs"
    );
    let stat = unsafe { stat.assume_init() };
    let available = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .context("disk overflow")?;
    ensure!(
        available >= r.minimum_initial_available_data_bytes && stat.f_favail > 0,
        "fresh DATA/inode fit failed"
    );
    let cores = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    ensure!(
        cores > 0
            && r.complete_booked_cpu_quota_micros
                <= u64::try_from(cores)?
                    .checked_mul(1_000_000)
                    .context("CPU overflow")?,
        "complete CPU fit failed"
    );
    Ok(
        json!({"host_memory":mem,"complete_memory_plus_reserve_bytes":need,"actual_available_data_bytes":available,"actual_available_inodes":stat.f_favail,"actual_online_cpus":cores,"booked_cpu_quota_micros":r.complete_booked_cpu_quota_micros,"minimum_initial_available_data_bytes":r.minimum_initial_available_data_bytes}),
    )
}
fn claims_epoch(value: &Value, epoch: u64) -> bool {
    match value {
        Value::Array(rows) => rows.iter().any(|row| claims_epoch(row, epoch)),
        Value::Object(row) => {
            row.get("epoch").and_then(Value::as_u64) == Some(epoch)
                || row
                    .get("range")
                    .and_then(Value::as_str)
                    .is_some_and(|range| {
                        range.parse::<u64>().ok() == Some(epoch)
                            || range
                                .split_once('-')
                                .and_then(|(first, last)| {
                                    Some((first.parse::<u64>().ok()?, last.parse::<u64>().ok()?))
                                })
                                .is_some_and(|(first, last)| first <= epoch && epoch <= last)
                    })
                || row.values().any(|child| claims_epoch(child, epoch))
        }
        _ => false,
    }
}
fn fleet_shape(fleet: &Value, inventory: &Value, p: &Plan) -> Result<()> {
    let epochs = fleet["epochs"]
        .as_array()
        .context("complete100 epoch fleet")?;
    ensure!(
        epochs.len() == 100
            && epochs
                .iter()
                .enumerate()
                .all(|(i, r)| r["epoch"] == 101 + i),
        "incomplete or misordered fleet"
    );
    ensure!(
        fleet["owner"] == "/root"
            && fleet["primary_thread"] == THREAD
            && fleet["complete_DATA_bytes"] == DATA
            && fleet["complete_projected_memory_bytes"] == MEMORY,
        "foreign complete fleet authority"
    );
    for key in ["actual_executing_replays", "actual_active_bootstraps"] {
        let rows = fleet[key].as_array().context("complete live-owner list")?;
        ensure!(
            !rows.iter().any(|r| claims_epoch(r, p.epoch)),
            "target already actively claimed"
        );
    }
    let entries = inventory["entries"]
        .as_array()
        .context("inventory entries")?;
    ensure!(
        entries.len() == 100 && inventory["anomalies"] == 0 && inventory["archive_only"] == 0,
        "authenticated inventory anomaly"
    );
    let selected: Vec<_> = entries.iter().filter(|r| r["epoch"] == p.epoch).collect();
    ensure!(
        selected.len() == 1 && selected[0]["state"] == "missing",
        "target not missing"
    );
    Ok(())
}
fn fresh_state(p: &Plan) -> Result<Value> {
    if let Some(prior) = &p.existing_preparation {
        ensure!(
            prior.path.as_os_str()
                == std::ffi::OsStr::new(&format!(
                    "/var/lib/jetstreamer/standard-replacement-recipes-20261110-v4/epoch{}/{}/prepared.json",
                    p.epoch, p.attempt
                )),
            "exact original staged preparation required"
        );
        let previous = bound(prior)?;
        ensure!(
            previous["schema"] == "horizon-standard-replacement-recipe-preparation-v1"
                && previous["owner"] == "/root"
                && previous["primary_thread"] == THREAD
                && previous["epoch"] == p.epoch
                && previous["attempt"] == p.attempt
                && previous["fresh_subtree"]["path"]
                    == p.fresh_subtree.to_str().context("fresh path")?
                && previous["local_inputs"] == serde_json::to_value(&p.local_inputs)?
                && previous["replay_launched"] == false
                && previous["resource_credit_bytes"] == 0,
            "original preparation scope differs"
        );
        let current = local::staged_genesis(&p.fresh_subtree, &previous["genesis_stage"])?;
        ensure!(
            current.as_array().context("staged identity")?[..5]
                == previous["fresh_subtree"]["identity"]
                    .as_array()
                    .context("original fresh identity")?[..5],
            "staged root inode/owner/mode changed"
        );
        Ok(current)
    } else {
        fresh_empty(&p.fresh_subtree)
    }
}
fn fresh_empty(p: &Path) -> Result<Value> {
    let d = directory(p)?;
    let m = d.metadata()?;
    ensure!(
        m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o7777 == 0o700
            && fs::read_dir(p)?.next().is_none(),
        "fresh subtree must be empty sol:horizon0700"
    );
    Ok(identity(&m))
}
fn atomic_json(dir: &Path, name: &str, v: &Value) -> Result<Bound> {
    let d = directory(dir)?;
    let m = d.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "private root output required"
    );
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "receipt name"
    );
    let bytes = serde_json::to_vec_pretty(v)?;
    let tmp = format!(".{name}.{}.tmp", std::process::id());
    let tmpc = CString::new(tmp.clone())?;
    let namec = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            d.as_raw_fd(),
            tmpc.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(fd >= 0, "temporary output collision");
    let mut f = unsafe { File::from_raw_fd(fd) };
    f.write_all(&bytes)?;
    f.sync_all()?;
    ensure!(
        unsafe {
            libc::renameat2(
                d.as_raw_fd(),
                tmpc.as_ptr(),
                d.as_raw_fd(),
                namec.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "receipt collision; failed temporary retained"
    );
    d.sync_all()?;
    Ok(Bound {
        path: dir.join(name),
        sha256: digest(&bytes),
    })
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 7,
        "usage: prepare PLAN --plan-sha256 SHA --self-sha256 SHA (--check-only|--prepare)"
    );
    ensure!(
        args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && lower_hex(&args[3], 64)
            && lower_hex(&args[5], 64),
        "strict separately bound invocation"
    );
    // Explicit mode prevents an accidental preparation receipt write.
    let check = match args[6].as_str() {
        "--check-only" => true,
        "--prepare" | "--measure-only" => false,
        _ => anyhow::bail!("explicit --check-only or --prepare required"),
    };
    ensure!(args.len() == 7, "unexpected trailing arguments");
    ensure!(unsafe { libc::geteuid() } == 0, "Root identity required");
    ensure!(
        fs::read_link("/proc/self/exe")? == Path::new(IMAGE),
        "sealed runtime path required"
    );
    verify_self(&args[5])?;
    let bytes = raw(Path::new(&args[1]), 32 << 20, true)?;
    ensure!(digest(&bytes) == args[3], "plan digest differs");
    let p: Plan = serde_json::from_slice(&bytes)?;
    let s = shapes(&p)?;
    let out = Path::new(OUT)
        .join(format!("epoch{}", p.epoch))
        .join(&p.attempt);
    let lockdir = directory(Path::new(OUT))?;
    let lc = CString::new("serialization.lock")?;
    let fd = unsafe {
        libc::openat(
            lockdir.as_raw_fd(),
            lc.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(fd >= 0, "serialization lock");
    let lock = unsafe { File::from_raw_fd(fd) };
    let lm = lock.metadata()?;
    ensure!(
        lm.is_file() && lm.uid() == 0 && lm.nlink() == 1 && lm.mode() & 0o7777 == 0o600,
        "unsafe serialization lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "concurrent replacement metadata transition"
    );
    let at = now()?;
    if args[6] == "--measure-only" {
        let fleet = bound(&p.fleet)?;
        let inventory = bound(&p.inventory)?;
        fleet_shape(&fleet, &inventory, &p)?;
        let sampled = fleet["recorded_unix_seconds"]
            .as_u64()
            .context("fleet clock")?;
        ensure!(
            sampled <= at && at - sampled <= 1800,
            "stale measurement fleet"
        );
        let mut before = BTreeMap::new();
        for unit in &p.closed_units {
            let n = native(unit)?;
            closed(&n, unit)?;
            before.insert(unit.clone(), n);
        }
        let original_stop = stop_chain(s)?;
        let measured = local::physical_ledger(Path::new(s.lane))?;
        for unit in &p.closed_units {
            let n = native(unit)?;
            closed(&n, unit)?;
            ensure!(before[unit] == n, "owner changed during measurement");
        }
        let receipt = atomic_json(
            &out,
            "physical.json",
            &json!({"schema":"horizon-standard-replacement-local-physical-ledger-v1","owner":"/root","epoch":p.epoch,"recorded_unix_seconds":now()?,"lane_root":s.lane,"fleet":p.fleet,"original_stop":original_stop,"physical":measured,"read_only":true,"resource_credit_bytes":0,"replay_launch_authorized":false}),
        )?;
        println!("{}", serde_json::to_string(&receipt)?);
        return Ok(());
    }
    let r: Review = serde_json::from_value(bound(&p.review)?)?;
    review_shape(&p, &r, at)?;
    let _ = bound(&r.full_current_proc_and_unit_census)?;
    let _ = bound(&r.exact_slot_mapping_and_physical_ledger)?;
    let authority = bound(&r.complete_authority)?;
    ensure!(
        authority["complete_DATA_bytes"] == DATA
            && authority["complete_projected_memory_bytes"] == MEMORY
            && authority["actual_guard_floor_bytes_unchanged"] == FLOOR,
        "authority fields differ"
    );
    let fleet = bound(&p.fleet)?;
    let inventory = bound(&p.inventory)?;
    fleet_shape(&fleet, &inventory, &p)?;
    let cleanup = bound(&p.cleanup_completion)?;
    let cleanup_bound: Bound = serde_json::from_value(cleanup["completion"].clone())?;
    let actual_cleanup = bound(&cleanup_bound)?;
    ensure!(
        cleanup["reservation_ending_bytes"] == 0
            && actual_cleanup["resource_promise_ending_authorized"] == false
            && actual_cleanup["resource_credit_bytes"] == 0
            && actual_cleanup["archive_deletion_authorized"] == false
            && actual_cleanup["replay_launch_authorized"] == false,
        "cleanup cannot release a promise or authorize this launch"
    );
    let stopped = stop_chain(s)?;
    let manifest = bound(&Bound {
        path: format!("{}/preflight-{}-v4.json", s.package, p.epoch).into(),
        sha256: s.manifest_sha.into(),
    })?;
    ensure!(
        manifest["manifest_fingerprint"] == s.fingerprint,
        "manifest fingerprint"
    );
    input_shape(&bound(&p.input_proof)?, &manifest, &p, s, at)?;
    fixed(
        &format!("{}/jetstreamer-node", s.package),
        NODE_SHA,
        64 << 20,
    )?;
    fixed(
        &format!("{}/jetstreamer-historical-worker-v1-5-6", s.package),
        WORKER_SHA,
        64 << 20,
    )?;
    fixed(GUARD, GUARD_SHA, 64 << 20)?;
    fixed(
        &format!("{}/deployment-seal-receipt.json", s.package),
        s.seal_sha,
        32 << 20,
    )?;
    fixed(
        &format!("{}/predecessor-capability.json", s.package),
        s.capability_sha,
        32 << 20,
    )?;
    let mut native_before = BTreeMap::new();
    for u in &p.closed_units {
        let n = native(u)?;
        closed(&n, u)?;
        native_before.insert(u.clone(), n);
    }
    let fresh = fresh_state(&p)?;
    let actual_ledger = local::ledger_summary(&local::physical_ledger(Path::new(s.lane))?)?;
    ensure!(
        actual_ledger["physical_bytes"].as_u64() == Some(r.retained_lane_physical_bytes),
        "actual full lane ledger differs from reviewed retained bytes"
    );
    let resources = resource_check(&r)?;
    let argv: Vec<String> = serde_json::from_value(bound(&Bound {
        path: s.argv.into(),
        sha256: s.argv_sha.into(),
    })?)?;
    let producer = producer_recipe(&argv, &p, s)?;
    let guard = guard_template(&p, s);
    let guard_argv = guard_recipe_template(&p);
    for u in &p.closed_units {
        let after = native(u)?;
        closed(&after, u)?;
        ensure!(
            native_before[u] == after,
            "closed owner changed during admission preparation"
        );
    }
    ensure!(fresh_state(&p)? == fresh, "fresh subtree changed");
    ensure!(
        local::ledger_summary(&local::physical_ledger(Path::new(s.lane))?)? == actual_ledger,
        "lane changed during preparation"
    );
    let genesis_stage = if let Some(prior) = &p.existing_preparation {
        Some(bound(prior)?["genesis_stage"].clone())
    } else if !check {
        if let Some(inputs) = &p.local_inputs {
            Some(local::stage_genesis(&p.fresh_subtree, &inputs.genesis)?)
        } else {
            None
        }
    } else {
        None
    };
    let result = json!({"schema":"horizon-standard-replacement-recipe-preparation-v1","owner":"/root","primary_thread":THREAD,"epoch":p.epoch,"attempt":p.attempt,"recorded_unix_seconds":now()?,"plan":{"path":args[1],"sha256":args[3]},"review":p.review,"fleet":p.fleet,"inventory":p.inventory,"input_proof":p.input_proof,"cleanup_completion":p.cleanup_completion,"original_stop_chain":stopped,"resource_checks":resources,"closed_units":native_before,"fresh_subtree":{"path":p.fresh_subtree,"identity":fresh},"producer_argv":producer,"actual_full_lane_ledger":actual_ledger,"local_inputs":p.local_inputs,"genesis_stage":genesis_stage,"existing_preparation":p.existing_preparation,"guard_plan_requires_actual_identity":guard,"guard_argv_requires_sealed_actual_plan":guard_argv,"ordinary_full_plugin_boundary_gates_retained":true,"resource_credit_bytes":0,"resource_promise_ending_bytes":0,"replay_launched":false,"replay_admission_receipt":false,"useful_replay_claimed":false,"guard_timer_started":false,"remote_mutations":false,"r2_mutations":false,"next_step":"Root must perform newly qualified bounded launch, actual producer IID-bound normally sealed guard, genuine first timer completion, then write postlaunch admission/protection from that actual evidence. Recipe receipt grants none of those claims."});
    if check {
        println!(
            "{}",
            serde_json::to_string(
                &json!({"check_passed":true,"epoch":p.epoch,"no_launch":true,"no_receipt_written":true})
            )?
        );
    } else {
        let receipt = atomic_json(&out, "prepared.json", &result)?;
        println!("{}", serde_json::to_string(&receipt)?);
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests;
