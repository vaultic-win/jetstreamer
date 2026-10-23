//! Fresh complete-fleet admission for one exact 227 singleton; never starts it.
use super::singleton227 as c;
use super::*;
use std::ffi::CString;
pub(super) const NATIVE_UNIT: &str = "horizon-native-input-227-capped-710f6523-v1.service";
pub(super) const NATIVE_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/native-input227-v1620-capped-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mode: String,
    observer: BoundFile,
    fleet: BoundFile,
    capability: BoundFile,
    native_input: Option<BoundFile>,
    resource_plan: BoundFile,
    protected_guards: BTreeMap<String, BoundFile>,
    output: PathBuf,
}
fn active_owner(row: &Value) -> Result<&Value> {
    match (row.get("producer"), row.get("unit"), row.get("controller")) {
        (Some(p), None, None) => Ok(p),
        (None, Some(p), None) => Ok(p),
        _ => anyhow::bail!(
            "227 unsupported/ambiguous active owner; reconcile its full envelope first"
        ),
    }
}
fn native223_claim(f: &Value, row: &Value) -> Result<PipelineClaim> {
    let owner = active_owner(row)?;
    let unit = owner["Id"].as_str().context("227 auxiliary unit")?;
    ensure!(
        row["epoch"] == 223
            && unit == "archive-223-v1620-native-input-release-actual-v1.service"
            && row["phase"] == "private-cold-snapshot-verification"
            && row["ordinary_replay_claim"] == false,
        "227 auxiliary is not the centrally registered optimized native223 profile"
    );
    let plan = bound_json(&BoundFile {
        path: f["plan"]
            .as_str()
            .context("227 accepted fleet plan")?
            .into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("227 fleet plan digest")?
            .into(),
    })?;
    let matching = plan["pipeline_claims"]
        .as_array()
        .context("227 fleet pipeline census")?
        .iter()
        .filter(|v| v["unit"] == unit)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "227 native223 registered claim missing/duplicate"
    );
    let claim: PipelineClaim = serde_json::from_value(matching[0].clone())?;
    ensure!(
        claim.invocation_id == owner["InvocationID"]
            && claim.evidence == serde_json::from_value::<Vec<BoundFile>>(row["evidence"].clone())?,
        "227 native223 live claim differs from accepted fleet"
    );
    cold223_scan::validate(&claim)?;
    Ok(claim)
}
fn remaining_hard_memory(cap: u64, charge: u64) -> Result<u64> {
    ensure!(
        cap == 128u64 << 30 && charge <= cap,
        "227 auxiliary hard cap/charge invalid or exceeded"
    );
    Ok(cap - charge)
}
fn auxiliary_memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    let mut total = 0u64;
    let mut evidence = Vec::new();
    for row in f["active"]
        .as_array()
        .context("227 auxiliary owner census")?
    {
        if row["epoch"] != 223 {
            continue;
        }
        let claim = native223_claim(f, row)?;
        let owner = active_owner(row)?;
        cold223_scan::validate_live(&claim, owner)?;
        let group = owner["ControlGroup"]
            .as_str()
            .context("227 auxiliary cgroup")?;
        ensure!(
            group == format!("/system.slice/{}", claim.unit),
            "227 auxiliary cgroup escaped"
        );
        let root = Path::new("/sys/fs/cgroup").join(&group[1..]);
        let read = |name: &str| -> Result<u64> {
            Ok(fs::read_to_string(root.join(name))?.trim().parse::<u64>()?)
        };
        let cap = read("memory.max")?;
        let high = read("memory.high")?;
        let charge = read("memory.current")?;
        ensure!(
            high == 112u64 << 30 && read("memory.swap.max")? == 0,
            "227 auxiliary memory controls changed"
        );
        let remaining = remaining_hard_memory(cap, charge)?;
        total = total
            .checked_add(remaining)
            .context("227 auxiliary growth overflow")?;
        evidence.push(json!({"epoch":223,"unit":claim.unit,"invocation_id":claim.invocation_id,
            "origin":private157::binding(&claim.evidence[0]),"hard_memory_cap_bytes":cap,"memory_high_bytes":high,
            "current_cgroup_charge_bytes":charge,"remaining_hard_memory_growth_bytes":remaining,
            "accounting":"kernel cgroup charge, never substituted lane RSS or a zero-growth claim"}));
    }
    Ok((total, evidence))
}
fn available_memory() -> Result<u64> {
    fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .context("227 actual available memory")?
        .checked_mul(1024)
        .context("227 available memory overflow")
}
fn century_floor(f: &Value) -> Result<u64> {
    let inventory = &f["inventory"];
    ensure!(
        inventory["schema"] == "jetstreamer-horizon-r2-inventory-v1"
            && inventory["first_epoch"] == 201
            && inventory["last_epoch"] == 300
            && inventory["anomalies"] == 0,
        "227 needs complete authenticated campaign inventory"
    );
    let rows = inventory["entries"]
        .as_array()
        .context("227 inventory entries")?;
    ensure!(rows.len() == 100, "227 incomplete inventory census");
    let mut seen = BTreeSet::new();
    let mut sum = 0u64;
    let mut count = 0u64;
    let mut ready = 0u64;
    for row in rows {
        let epoch = row["epoch"].as_u64().context("227 inventory epoch")?;
        ensure!(
            (201..=300).contains(&epoch) && seen.insert(epoch),
            "227 duplicate/foreign inventory epoch"
        );
        if epoch == 227 {
            ensure!(
                row["state"] == "missing",
                "227 already has a remote object; do not start a duplicate lane"
            );
        }
        if row["state"] == "ready-pair" {
            ready += 1;
            ensure!(
                canonical_digest(&row["sidecar_sha256"])
                    && row["sidecar_sha256"] == row["archive_metadata_sha256"],
                "227 ready pair lacks matching authenticated digest"
            );
            let bytes = row["archive_length"]
                .as_u64()
                .filter(|n| *n > 0)
                .context("227 ready archive size")?;
            if epoch < 300 {
                sum = sum.checked_add(bytes).context("227 century sum overflow")?;
                count += 1;
            }
        } else {
            ensure!(row["state"] == "missing", "227 inventory anomaly");
        }
    }
    ensure!(
        inventory["ready_pairs"] == ready && count > 0,
        "227 inventory ready census differs"
    );
    Ok(sum
        .checked_mul(2)
        .context("227 century floor overflow")?
        .div_ceil(count))
}
fn protected_growth(
    f: &Value,
    observer: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<(u64, Vec<Value>)> {
    let mut units = BTreeSet::new();
    let mut replay_guards = BTreeSet::new();
    let mut growth = 0u64;
    let mut measurements = Vec::new();
    for row in f["active"].as_array().context("227 active census")? {
        let owner = active_owner(row)?;
        let unit = owner["Id"].as_str().context("227 owner unit")?;
        ensure!(
            units.insert(unit.to_owned()) && owner["NRestarts"] == "0",
            "227 duplicate/restarted owner"
        );
        let epoch = row["epoch"].as_u64().context("227 owner epoch")?;
        if epoch == 223 {
            let claim = native223_claim(f, row)?;
            let intent = bound_json(&claim.evidence[0])?;
            ensure!(
                intent["maximum_memory_bytes"] == 128u64 << 30
                    && intent["tmpfs_bytes"] == 512u64 << 30,
                "227 native223 storage/memory profile changed"
            );
            // Private tmpfs has no root-filesystem growth claim. Its remaining
            // hard-memory growth is separately measured and reserved below.
            continue;
        }
        let full_envelope = match epoch {
            204 | 205 => c::PEAK,
            225 => 640u64 << 30,
            _ => anyhow::bail!("227 changed live owner needs a new resource model"),
        };
        let sampled = observer["diagnostic_replays"]
            .as_array()
            .context("227 protected replay samples")?
            .iter()
            .find(|r| r["observation"]["producer_after"]["invocation_id"] == owner["InvocationID"])
            .context("227 protected sample missing")?;
        let allocated = sampled["observation"]["conservative_observed_physical_bytes"]
            .as_u64()
            .context("227 current scratch allocation")?;
        ensure!(
            sampled["observation"]["invocation_binding_stable"] == true,
            "227 scratch identity changed"
        );
        let mut output_occupied = 0u64;
        let minimum = if epoch == 225 {
            let policy_binding = BoundFile {
                path: "/var/lib/jetstreamer/horizon-ownroot203-rebase-preparation-v1/policy.json"
                    .into(),
                sha256: "1c72102ae9e9659a27860158b225c53548560fb0b7261654740e5cca0de65dc9".into(),
            };
            let policy = bound_json(&policy_binding)?;
            ensure!(
                policy["schema"] == "jetstreamer-ownroot203-guard-rebase-policy-v1"
                    && policy["older225_remaining_bytes"] == full_envelope
                    && policy["guard_buffer_bytes"] == 64u64 << 30,
                "227225 remaining-growth policy differs"
            );
            let baseline_binding: BoundFile = serde_json::from_value(policy["observer"].clone())?;
            ensure!(
                baseline_binding.sha256
                    == "2fbcb8db4d793d52e43840c43ccce4f7c1b2db6dcc39adf70936d90ac864c2a5",
                "227225 baseline differs"
            );
            let baseline = bound_json(&baseline_binding)?;
            let old = baseline["diagnostic_replays"]
                .as_array()
                .context("227225 baseline census")?
                .iter()
                .find(|r| r["range"] == "225-226")
                .context("227225 baseline range")?;
            ensure!(
                old["observation"]["producer_after"]["invocation_id"] == owner["InvocationID"],
                "227225 baseline invocation changed"
            );
            let prior = old["observation"]["conservative_observed_physical_bytes"]
                .as_u64()
                .context("227225 baseline physical size")?;
            ensure!(
                allocated.saturating_sub(prior) < full_envelope,
                "227225 remaining-growth allowance exhausted"
            );
            // A reclaim is never new credit against the original remaining
            // claim. Output growth since the baseline stays conservatively
            // reserved because no baseline output allocation was captured.
            full_envelope.saturating_sub(allocated.saturating_sub(prior))
        } else {
            let root = Path::new(
                row["scratch_path"]
                    .as_str()
                    .context("227 protected private root")?,
            );
            ensure!(
                sampled["observation"]["scratch_path"].as_str() == root.join("scratch").to_str(),
                "227 scratch scope differs"
            );
            let output = root.join(format!("output/epoch-{epoch}-prefix.jet"));
            let occupied = match fs::symlink_metadata(&output) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
                Err(e) => return Err(e.into()),
                Ok(first) => {
                    ensure!(
                        first.is_file() && first.nlink() == 1 && first.uid() == 1000,
                        "227 unsafe protected partial output"
                    );
                    let second = fs::symlink_metadata(&output)?;
                    ensure!(
                        second.is_file()
                            && first.dev() == second.dev()
                            && first.ino() == second.ino(),
                        "227 partial output changed identity"
                    );
                    first
                        .blocks()
                        .min(second.blocks())
                        .checked_mul(512)
                        .context("227 output allocation overflow")?
                }
            };
            ensure!(
                allocated <= c::SCRATCH && occupied <= 128u64 << 30,
                "227 protected capped lane exceeded its admitted scratch/output envelope"
            );
            output_occupied = occupied;
            full_envelope
                .saturating_sub(allocated)
                .saturating_sub(occupied)
        };
        measurements.push(json!({"epoch":epoch,"unit":unit,"invocation_id":owner["InvocationID"],"sampled_scratch_physical_bytes":allocated,
            "current_output_allocated_bytes":output_occupied,"remaining_growth_bytes":minimum,"output_growth_credit_taken":epoch!=225}));
        let launch = BoundFile {
            path: row["launch_receipt"]
                .as_str()
                .context("227 protected launch path")?
                .into(),
            sha256: row["launch_receipt_sha256"]
                .as_str()
                .context("227 protected launch digest")?
                .into(),
        };
        let l = bound_json(&launch)?;
        ensure!(
            l["epoch"] == epoch && l["launched"] == true && l["publication_authorized"] == false,
            "227 protected launch scope differs"
        );
        if epoch != 225 {
            ensure!(
                l["experimental_envelope_bytes"] == c::PEAK
                    && l["maximum_scratch_bytes"] == c::SCRATCH,
                "227 protected capped envelope changed"
            );
        }
        let binding = guards
            .get(unit)
            .context("227 live replay has no protective guard")?;
        let g = bound_json(binding)?;
        let (guard_sha, plan_sha) = match epoch {
            225 => (
                "cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560",
                "831f3eae5d4326d04ae399b4046532cda5cceb32e8e3f89b87a1de0b299a3d22",
            ),
            205 => (
                c::GUARD_SHA,
                "2b639357a4754b914ad9f4af949fb7c38085a37b9cac7aa0b2c519950ee963e7",
            ),
            204 => (
                c::GUARD_SHA,
                "dfa45f5f8de36fab51fff7a669ceff8e0089bde058bf60be53fcfa7f02a4cd7d",
            ),
            _ => unreachable!(),
        };
        let recorded = g["recorded_unix_seconds"]
            .as_u64()
            .context("227 guard timestamp")?;
        ensure!(
            recorded >= sample
                && recorded <= now
                && now - recorded <= 1800
                && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                && g["guard_sha256"] == guard_sha
                && g["plan_sha256"] == plan_sha
                && g["producer_invocation_id"] == owner["InvocationID"]
                && g["producer"]["invocation_id"] == owner["InvocationID"]
                && g["producer"]["cgroup"] == owner["ControlGroup"]
                && g["producer"]["pid"]
                    .as_u64()
                    .map(|p| p.to_string())
                    .as_deref()
                    == owner["MainPID"].as_str()
                && g["producer"]["restarts"] == 0
                && g["producer"]["active"] == "active"
                && g["producer"]["sub"] == "running"
                && g["trip_reason"].is_null()
                && g["worker_observation_error"].is_null()
                && g["root_physical_observation_error"].is_null()
                && g["workers"].as_array().is_some_and(|a| a.len() == 1)
                && g["maximum_worker_vmas"] == 3500000
                && g["available_bytes"]
                    .as_u64()
                    .zip(g["minimum_free_bytes"].as_u64())
                    .is_some_and(|(a, b)| a >= b)
                && g["remote_mutations"] == false
                && g["r2_mutations"] == false,
            "227 protected guard stale/changed/tripped"
        );
        let w = &g["workers"][0];
        ensure!(
            w[1].as_u64().is_some_and(|n| n > 0 && n < 3500000),
            "227 protected worker VMA bound"
        );
        replay_guards.insert(unit.to_owned());
        growth = growth
            .checked_add(minimum)
            .context("227 protected growth overflow")?;
    }
    ensure!(
        replay_guards == guards.keys().cloned().collect(),
        "227 guard census omits or adds owners"
    );
    // One separately authorized shared buffer; do not count it per lane.
    Ok((
        growth
            .checked_add(64u64 << 30)
            .context("227 shared guard buffer overflow")?,
        measurements,
    ))
}
fn disk_free() -> Result<u64> {
    let path = CString::new("/")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "227 statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .context("227 disk overflow")
}
pub(super) fn owners(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    let old = f["unit_census"]
        .as_object()
        .context("227 predecessor census")?;
    let mut active = BTreeSet::new();
    for row in f["active"].as_array().context("227 active owners")? {
        let p = active_owner(row)?;
        let unit = p["Id"].as_str().context("227 owner name")?;
        ensure!(
            old.get(unit) == Some(p),
            "227 owner absent from accepted unit census"
        );
        let n = current.get(unit).context("227 current owner missing")?;
        for field in [
            "Id",
            "InvocationID",
            "MainPID",
            "ActiveState",
            "SubState",
            "NRestarts",
            "ControlGroup",
        ] {
            ensure!(
                n[field] == p[field],
                "227 protected owner changed:{unit}:{field}"
            );
        }
        ensure!(
            pipeline_status::same_exec_start(
                p["ExecStart"].as_str().context("227 old command")?,
                n["ExecStart"].as_str().context("227 live command")?
            ),
            "227 protected command changed"
        );
        ensure!(
            diagnostic_stage_running(n),
            "227 accepted active owner no longer live; reconcile first"
        );
        active.insert(unit.to_owned());
    }
    for (name, value) in current {
        ensure!(
            !diagnostic_stage_running(value) || active.contains(name),
            "227 unaccounted live competitor:{name}"
        );
    }
    Ok(())
}
fn limits(f: &Value) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for row in f["active"].as_array().context("227 active cap census")? {
        let owner = active_owner(row)?;
        let name = owner["Id"].as_str().context("227 cap owner")?;
        let output=ProcessCommand::new("/usr/bin/systemctl").args(["show",name,"--no-pager","--property=MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ControlGroup"]).output()?;
        ensure!(
            output.status.success() && output.stdout.len() < 16384,
            "227 protected caps unavailable"
        );
        let mut p = BTreeMap::new();
        for line in std::str::from_utf8(&output.stdout)?.lines() {
            let (k, v) = line.split_once('=').context("227 cap property")?;
            ensure!(
                p.insert(k.to_owned(), v.to_owned()).is_none(),
                "227 duplicate cap property"
            );
        }
        ensure!(
            p.get("MemoryMax")
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
                && p.get("MemorySwapMax").map(String::as_str) == Some("0")
                && p.get("ControlGroup").map(String::as_str) == owner["ControlGroup"].as_str(),
            "227 protected cap/control group differs"
        );
        if row["epoch"] == 223 {
            ensure!(
                p.get("MemoryMax").and_then(|s| s.parse::<u64>().ok()) == Some(128u64 << 30)
                    && p.get("MemoryHigh").and_then(|s| s.parse::<u64>().ok())
                        == Some(112u64 << 30),
                "227 native223 cap differs; reconcile its envelope first"
            );
        }
        result.insert(name.to_owned(), json!(p));
    }
    Ok(Value::Object(result))
}
fn sample(s: &Spec, o: &Value, f: &Value, now: u64, required: u64) -> Result<(u64, u64, u64)> {
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("227 observer time")?)?;
    ensure!(
        t <= now
            && now - t <= 1800
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0,
        "227 stale/incomplete fleet sample"
    );
    ensure!(
        o["filesystem"]["conservative_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= required)
            && o["vm_max_map_count"].as_u64().is_some_and(|n| n >= 4194304),
        "227 sampled disk/VMA envelope unavailable"
    );
    let history = &o["lane_rss_history"]["200"];
    let rss = history["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("227 century RSS missing")?;
    let reservation = rss.checked_mul(3).context("227 RSS overflow")? / 2;
    ensure!(
        history["reservation_ceiling_bytes"] == reservation,
        "227 RSS reservation differs"
    );
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("227 total memory")?
        .checked_mul(1024)
        .context("227 memory overflow")?;
    let available = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .context("227 memory available")?
        .checked_mul(1024)
        .context("227 memory overflow")?;
    let pending = if s.mode == "native-cold" {
        128u64 << 30
    } else {
        reservation
    };
    ensure!(
        available >= pending
            && available
                >= total / 10
                    + if s.mode == "native-cold" {
                        pending
                    } else {
                        rss
                    },
        "227 exceeds90percent memory target"
    );
    let psi = &o["host_global_pressure"]["cross_sample"];
    ensure!(
        psi["status"] == "observed"
            && psi["elapsed_millis"].as_u64().is_some_and(|n| n > 0)
            && psi["counter_delta_usec"]["memory.full_total_usec"]
                .as_u64()
                .zip(psi["elapsed_millis"].as_u64())
                .is_some_and(|(n, t)| n <= t.saturating_mul(100)),
        "227 severe/unobserved memory pressure"
    );
    for (counter, maximum_millis_fraction) in [
        ("cpu.some_total_usec", 500u64),
        ("io.full_total_usec", 100u64),
    ] {
        ensure!(
            psi["counter_delta_usec"][counter]
                .as_u64()
                .zip(psi["elapsed_millis"].as_u64())
                .is_some_and(|(n, t)| n <= t.saturating_mul(maximum_millis_fraction)),
            "227 CPU/I/O pressure leaves insufficient experimental headroom:{counter}"
        );
    }
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("227 replay observation census")?;
    let active = f["active"]
        .as_array()
        .context("227 accepted active census")?;
    let replays = active
        .iter()
        .filter(|r| r["epoch"] != 223)
        .collect::<Vec<_>>();
    ensure!(
        o["replays"].as_array().is_some_and(Vec::is_empty) && rows.len() == replays.len(),
        "227 observer replay census differs"
    );
    for row in rows {
        let v = &row["observation"];
        let iid = &v["producer_after"]["invocation_id"];
        ensure!(
            row["status"] == "observed"
                && row["error"].is_null()
                && v["invocation_binding_stable"] == true
                && v["producer_before"]["invocation_id"] == *iid
                && v["producer_after"]["restarts"] == 0
                && replays
                    .iter()
                    .filter(|r| r["producer"]["InvocationID"] == *iid)
                    .count()
                    == 1
                && v["worker_after"]["matching_workers"] == 1
                && v["worker_after"]["vmas"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 3500000),
            "227 replay sample changed/incomplete"
        );
    }
    Ok((
        t,
        reservation,
        total / 10
            + if s.mode == "native-cold" {
                pending
            } else {
                rss
            },
    ))
}
pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: admit-singleton227 SPEC --spec-sha256 SHA --self-sha256 SHA (root)"
    );
    let own = fs::symlink_metadata(fs::read_link("/proc/self/exe")?)?;
    ensure!(
        own.uid() == 0
            && own.nlink() == 1
            && own.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "227 admission helper unsealed"
    );
    let binding = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch227-singleton-admission-spec-v1"
            && matches!(s.mode.as_str(), "native-cold" | "replay")
            && s.capability.path == Path::new(c::CAPABILITY)
            && s.capability.sha256 == c::CAPABILITY_SHA,
        "227 admission scope differs"
    );
    let cap = bound_json(&s.capability)?;
    ensure!(
        cap["all_immutable_inputs_rehashed"] == true && cap["worker_spawned"] == false,
        "227 invalid input capability"
    );
    if s.mode == "replay" {
        c::native_valid(&bound_json(
            s.native_input
                .as_ref()
                .context("227 replay needs actual native proof")?,
        )?)?;
    } else {
        ensure!(
            s.native_input.is_none(),
            "227 native attempt cannot borrow a prior qualification"
        );
    }
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let p = bound_json(&s.resource_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("227 sample time")?)?;
    let floor = century_floor(&f)?;
    let free_before_measurements = disk_free()?;
    let (growth, growth_measurements) = protected_growth(&f, &o, &s.protected_guards, t, now)?;
    let computed_floor = floor.checked_add(growth).context("227 floor overflow")?;
    let protected = p["guard_minimum_free_bytes"]
        .as_u64()
        .context("227 planned guard floor")?;
    ensure!(
        protected >= computed_floor,
        "227 sealed plan under-reserves actual remaining growth"
    );
    let peak = if s.mode == "native-cold" {
        c::SCRATCH
    } else {
        c::PEAK
    };
    let required = protected
        .checked_add(peak)
        .context("227 required free overflow")?;
    let (unit, root) = if s.mode == "native-cold" {
        (NATIVE_UNIT, NATIVE_ROOT)
    } else {
        (c::UNIT, c::ROOT)
    };
    ensure!(
        p["schema"] == "jetstreamer-private-epoch227-singleton-resource-plan-v1"
            && p["epoch"] == 227
            && p["mode"] == s.mode
            && p["unit"] == unit
            && p["run_root"] == root
            && p["candidate_incremental_peak_bytes"] == peak
            && p["guard_minimum_free_bytes"] == protected
            && p["required_initial_free_bytes"] == required
            && p["worker_sha256"] == c::WORKER_SHA
            && p["snapshot_sha256"] == c::SNAPSHOT_SHA
            && p["maximum_scratch_bytes"] == c::SCRATCH
            && p["publication_authorized"] == false
            && p["r2_mutations"] == false,
        "227 resource plan differs"
    );
    let (_, reservation, memory_required) = sample(&s, &o, &f, now, required)?;
    if s.output.try_exists()? {
        let previous = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            previous["spec_sha256"] == binding.sha256
                && previous["self_sha256"] == args[6]
                && previous["admitted"] == true,
            "227 conflicting admission"
        );
        return Ok(());
    }
    ensure!(
        s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-227-admission-"))
            && s.output.file_name().is_some_and(|n| n == "admission.json"),
        "227 admission output scope differs"
    );
    validate_output_destination(&s.output)?;
    let names = f["unit_census"]
        .as_object()
        .context("227 unit census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 201, 300)?;
    owners(&f, &before)?;
    let caps = limits(&f)?;
    let memory_before_aux = available_memory()?;
    let (auxiliary_before, auxiliary_before_evidence) = auxiliary_memory(&f)?;
    let path = CString::new("/")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "227 statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    let free = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .context("227 disk overflow")?
        .min(free_before_measurements);
    let memory = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .context("227 actual memory")?
        .checked_mul(1024)
        .context("227 memory overflow")?;
    let maps = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    ensure!(
        free >= required
            && memory >= memory_required
            && memory
                >= if s.mode == "native-cold" {
                    128u64 << 30
                } else {
                    reservation
                }
            && maps >= 4194304,
        "227 actual resource envelope unavailable"
    );
    let after = census(&names, 201, 300)?;
    owners(&f, &after)?;
    let (auxiliary_after, auxiliary_after_evidence) = auxiliary_memory(&f)?;
    let memory = memory.min(memory_before_aux).min(available_memory()?);
    let auxiliary_growth = auxiliary_before.max(auxiliary_after);
    let protected_memory_required = memory_required
        .checked_add(auxiliary_growth)
        .context("227 protected memory overflow")?;
    ensure!(
        memory >= protected_memory_required,
        "227 new native lane would consume another auxiliary's remaining hard-memory growth"
    );
    ensure!(
        limits(&f)? == caps,
        "227 protected cgroup limits changed during admission"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample(&s, &o, &f, now, required)?;
    let (after_growth, after_measurements) = protected_growth(&f, &o, &s.protected_guards, t, now)?;
    ensure!(
        after_growth <= growth && disk_free()? >= required,
        "227 mutable output/free-space accounting changed unsafely during admission"
    );
    let measurements = json!({"mutable_output_measurements_bracketed_by_actual_free":true,"protected_growth_after_bytes":after_growth,
        "protected_growth_measurements_before":growth_measurements,"protected_growth_measurements_after":after_measurements,
        "computed_existing_floor_bytes":computed_floor,"conservative_additional_plan_margin_bytes":protected-computed_floor,
        "remaining_growth_policy225":{"path":"/var/lib/jetstreamer/horizon-ownroot203-rebase-preparation-v1/policy.json","sha256":"1c72102ae9e9659a27860158b225c53548560fb0b7261654740e5cca0de65dc9"},
        "unit_census_before":before,"unit_census_after":after,"protected_memory_limits":caps,
        "auxiliary_memory_before":auxiliary_before_evidence,"auxiliary_memory_after":auxiliary_after_evidence,
        "auxiliary_remaining_hard_memory_growth_bytes":auxiliary_growth,"required_available_memory_with_auxiliary_bytes":protected_memory_required,
        "auxiliary_memory_charge_bracketed_by_actual_available_memory":true});
    let mut payload = json!({"schema":"jetstreamer-private-epoch227-singleton-admission-v1","mode":s.mode,
        "admitted":true,"unit":unit,"private_run_root":root,"candidate_incremental_peak_bytes":peak,"maximum_scratch_bytes":c::SCRATCH,
        "protected_existing_floor_bytes":protected,"required_initial_free_bytes":required,"century_floor_bytes":floor,"protected_remaining_growth_bytes":growth,
        "memory_target_percent":90,"lane_memory_reservation_bytes":reservation,"available_memory_bytes":memory,"available_disk_bytes":free,"vm_max_map_count":maps,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"resource_plan":private157::binding(&s.resource_plan),
        "capability_sha256":c::CAPABILITY_SHA,"native_input":s.native_input.as_ref().map(private157::binding),"protected_guards":s.protected_guards,
        "fresh_complete_census_passed":true,"older_producers_and_guards_preserved":true,
        "spec_sha256":binding.sha256,"self_sha256":args[6],"recorded_unix_seconds":now,"maximum_launch_delay_seconds":900,
        "producer_started":false,"new_routine_resource_samples":0,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    for (key, value) in measurements.as_object().context("227 measurement object")? {
        ensure!(payload.get(key).is_none(), "227 evidence field collision");
        payload[key] = value.clone();
    }
    private157::immutable_receipt(&s.output, &payload)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inventory() -> Value {
        let rows=(201..=300).map(|epoch|if epoch<215 {json!({"epoch":epoch,"state":"ready-pair","archive_length":1000u64+epoch,"sidecar_sha256":"a".repeat(64),"archive_metadata_sha256":"a".repeat(64)})}else{json!({"epoch":epoch,"state":"missing"})}).collect::<Vec<_>>();
        json!({"inventory":{"schema":"jetstreamer-horizon-r2-inventory-v1","first_epoch":201,"last_epoch":300,"anomalies":0,"ready_pairs":14,"entries":rows}})
    }
    #[test]
    fn century_floor_recomputes_exactly_when_fourteenth_pair_arrives() {
        let f = inventory();
        assert_eq!(century_floor(&f).unwrap(), 2415);
        for pointer in [
            "/inventory/entries/0/archive_length",
            "/inventory/entries/0/sidecar_sha256",
            "/inventory/ready_pairs",
        ] {
            let mut bad = f.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(century_floor(&bad).is_err(), "{pointer}");
        }
        let mut duplicate = f.clone();
        duplicate["inventory"]["entries"][99] = duplicate["inventory"]["entries"][0].clone();
        assert!(century_floor(&duplicate).is_err());
        let mut completed = f.clone();
        completed["inventory"]["entries"][26] = json!({"epoch":227,"state":"ready-pair"});
        assert!(century_floor(&completed).is_err());
    }
    #[test]
    fn owner_shape_never_silently_drops_an_auxiliary_or_controller() {
        assert!(active_owner(&json!({"producer":{"Id":"known"}})).is_ok());
        assert!(active_owner(&json!({"unit":{"Id":"native223"}})).is_ok());
        assert!(active_owner(&json!({"producer":{},"unit":{}})).is_err());
        assert!(active_owner(&json!({"controller":{},"producer":{}})).is_err());
    }
    #[test]
    fn native_auxiliary_reserves_remaining_hard_cap_without_inventing_lane_rss() {
        assert_eq!(
            remaining_hard_memory(128u64 << 30, 50u64 << 30).unwrap(),
            78u64 << 30
        );
        assert_eq!(
            remaining_hard_memory(128u64 << 30, 0).unwrap(),
            128u64 << 30
        );
        assert!(remaining_hard_memory(256u64 << 30, 0).is_err());
        assert!(remaining_hard_memory(128u64 << 30, (128u64 << 30) + 1).is_err());
    }
    #[test]
    fn sample_rejects_stale_memory_missing_owner_and_pressure_instead_of_inventing_capacity() {
        let b = || BoundFile {
            path: "/observer.json".into(),
            sha256: "a".repeat(64),
        };
        let s = Spec {
            schema: "test".into(),
            mode: "replay".into(),
            observer: b(),
            fleet: b(),
            capability: b(),
            native_input: None,
            resource_plan: b(),
            protected_guards: BTreeMap::new(),
            output: "/out".into(),
        };
        let stamp = "2026-10-23T17:14:20Z";
        let now = utc_seconds(stamp).unwrap();
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":stamp,
            "filesystem":{"conservative_available_bytes":1000},"vm_max_map_count":4194304u64,
            "host_memory":{"total_kib":1_000_000_000u64,"conservative_available_kib":700_000_000u64},
            "lane_rss_history":{"200":{"maximum_observed_lane_rss_bytes":150_000_000_000u64,"reservation_ceiling_bytes":225_000_000_000u64}},
            "host_global_pressure":{"cross_sample":{"status":"observed","elapsed_millis":1800000,"counter_delta_usec":{"memory.full_total_usec":1,"cpu.some_total_usec":1,"io.full_total_usec":1}}},
            "replays":[],"diagnostic_replays":[{"status":"observed","error":null,"observation":{"invocation_binding_stable":true,"producer_before":{"invocation_id":"x"},"producer_after":{"invocation_id":"x","restarts":0},"worker_after":{"matching_workers":1,"vmas":100}}}]});
        let f = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"observer_receipt":"/observer.json","observer_sha256":"a".repeat(64),"sampled_at_utc":stamp,"inventory":{"anomalies":0},"active":[{"epoch":204,"producer":{"InvocationID":"x"}}]});
        assert!(sample(&s, &o, &f, now, 1000).is_ok());
        assert!(sample(&s, &o, &f, now + 1801, 1000).is_err());
        for pointer in [
            "/lane_rss_history/200/maximum_observed_lane_rss_bytes",
            "/host_memory/conservative_available_kib",
            "/diagnostic_replays/0/observation/worker_after/vmas",
            "/host_global_pressure/cross_sample/counter_delta_usec/io.full_total_usec",
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(sample(&s, &bad, &f, now, 1000).is_err(), "{pointer}");
        }
        let mut missing = f.clone();
        missing["active"] = json!([]);
        assert!(sample(&s, &o, &missing, now, 1000).is_err());
    }
}
