//! Preserve the accepted uncapped census and validate only declared cap changes.
use crate::{census, evidence};
use anyhow::{Context, Result, ensure};
use census::{Bound, Plan as LegacyPlan};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(not(horizon_uploader_freeze_fixture))]
const PRE_CAP_IMAGE_SHA: &str = "8e7a623793c3924d0d0aaab8356031ac34d10472de41123cd296fd24f2367483";
#[cfg(horizon_uploader_freeze_fixture)]
#[path = "fixture_predecessor.rs"]
mod fixture_predecessor;
#[cfg(horizon_uploader_freeze_fixture)]
const PRE_CAP_IMAGE_SHA: &str = fixture_predecessor::IMAGE_SHA256;
const EXTRA: &[&str] = &[
    "MemorySwapMax",
    "TasksMax",
    "MemoryAccounting",
    "NoNewPrivileges",
    "ProtectControlGroups",
    "User",
    "Group",
    "OOMPolicy",
];
#[cfg(not(horizon_uploader_freeze_fixture))]
const OUTPUT: &str = "/var/lib/jetstreamer/horizon-uploader-capped-census-20261111-v1";
#[cfg(horizon_uploader_freeze_fixture)]
const OUTPUT: &str = "/var/lib/jetstreamer/horizon-uploader-cap-transition-20261111-v2";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    CappedFrozen,
    CappedIdle,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    original_frozen_plan: Bound,
    original_frozen_proof: Bound,
    capped_frozen_proof: Option<Bound>,
    phase: Phase,
    memory_max_bytes: u64,
    minimum_unused_bytes: u64,
    runtime_cap_dropins: Vec<Bound>,
    output: PathBuf,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn scope(p: &Plan) -> Result<String> {
    let mut v = serde_json::to_value(p)?;
    let m = v.as_object_mut().context("cap scope object")?;
    for field in ["phase", "output", "capped_frozen_proof"] {
        m.remove(field);
    }
    Ok(evidence::sha(&serde_json::to_vec(&v)?))
}
fn shape(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "horizon-uploader-capped-census-plan-v1",
        "cap plan schema"
    );
    ensure!(
        p.memory_max_bytes >= 64 << 20 && p.memory_max_bytes <= 64 << 30,
        "finite experimental cap outside retained shared64"
    );
    ensure!(
        p.minimum_unused_bytes >= 64 << 20 && p.minimum_unused_bytes <= p.memory_max_bytes / 2,
        "conservative unused-cap allowance"
    );
    ensure!(
        (p.phase == Phase::CappedIdle) == p.capped_frozen_proof.is_some(),
        "cap phase predecessor differs"
    );
    ensure!(
        p.output.parent() == Some(Path::new(OUTPUT)),
        "foreign cap receipt directory"
    );
    ensure!(
        p.runtime_cap_dropins.len() == 2,
        "both exact cap source files required"
    );
    let prefix = format!("/run/systemd/system.control/{}.d", census::UNIT);
    let want = ["50-MemoryMax.conf", "50-MemorySwapMax.conf"];
    for (b, name) in p.runtime_cap_dropins.iter().zip(want) {
        ensure!(
            b.path == Path::new(&prefix).join(name) && evidence::is_sha(&b.sha256),
            "foreign or repeated cap source"
        );
    }
    Ok(())
}
fn cap_source(raw: &[u8], key: &str, value: u64) -> Result<()> {
    let lines = std::str::from_utf8(raw)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>();
    ensure!(
        lines == ["[Service]".to_owned(), format!("{key}={value}")],
        "runtime cap file contains undeclared settings"
    );
    Ok(())
}
fn source_files(p: &Plan) -> Result<()> {
    for (b, key, value) in [
        (&p.runtime_cap_dropins[0], "MemoryMax", p.memory_max_bytes),
        (&p.runtime_cap_dropins[1], "MemorySwapMax", 0),
    ] {
        let raw = evidence::bound_file(&b.path, &b.sha256, 65536, false)?;
        cap_source(&raw, key, value)?;
    }
    Ok(())
}
fn fresh(time: u64, current: u64) -> Result<()> {
    ensure!(
        time <= current && current - time <= 60,
        "handoff proof older than60seconds or future-dated"
    );
    Ok(())
}
fn original_proof(v: &Value, p: &Plan, legacy: &LegacyPlan, current: u64) -> Result<()> {
    fresh(
        v["recorded_unix_seconds"]
            .as_u64()
            .context("old proof clock")?,
        current,
    )?;
    ensure!(
        v["schema"] == "horizon-uploader-freeze-census-proof-v1"
            && v["self_sha256"] == PRE_CAP_IMAGE_SHA
            && v["plan"] == serde_json::to_value(&p.original_frozen_plan)?
            && v["scope_sha256"] == census::scope_hash(legacy)?
            && v["frozen"] == true
            && v["idle_census_proven"] == true,
        "foreign uncapped frozen proof"
    );
    ensure!(
        legacy.frozen && legacy.memory_max == "infinity",
        "pre-cap plan must honestly describe uncapped frozen state"
    );
    census::validate_unit(&v["unit"], legacy)?;
    ensure!(
        v["snapshot"]["actual_memory_max"] == "max"
            && v["snapshot"]["cgroup_frozen"] == true
            && v["snapshot"]["no_work_descriptors_or_mappings"] == true,
        "uncapped snapshot absent"
    );
    Ok(())
}
fn native(legacy: &LegacyPlan) -> Result<Value> {
    let mut base = census::unit(&legacy.unit)?;
    let keys = format!("Id,InvocationID,MainPID,{}", EXTRA.join(","));
    let out = Command::new("/usr/bin/systemctl")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .args([
            "show",
            &legacy.unit,
            "--no-pager",
            &format!("--property={keys}"),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 65536,
        "extra native capture failed"
    );
    let mut seen = BTreeSet::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("native field delimiter")?;
        ensure!(seen.insert(key.to_owned()), "duplicate extra native field");
        if ["Id", "InvocationID", "MainPID"].contains(&key) {
            ensure!(base[key] == value, "crossed native capture");
        } else {
            ensure!(EXTRA.contains(&key), "unknown extra native field");
            base.as_object_mut()
                .context("native object")?
                .insert(key.into(), json!(value));
        }
    }
    ensure!(seen.len() == EXTRA.len() + 3, "missing extra native fields");
    Ok(base)
}
fn native_delta(v: &Value, old: &Value, p: &Plan, legacy: &LegacyPlan) -> Result<()> {
    for (key, want) in [
        ("MemorySwapMax", "0"),
        ("TasksMax", "256"),
        ("MemoryAccounting", "yes"),
        ("NoNewPrivileges", "yes"),
        ("ProtectControlGroups", "yes"),
        ("User", "sol"),
        ("Group", "horizon"),
        ("OOMPolicy", "stop"),
    ] {
        ensure!(v[key] == want, "cap native constraint differs:{key}");
    }
    ensure!(
        v["MemoryMax"].as_str().and_then(|x| x.parse::<u64>().ok()) == Some(p.memory_max_bytes),
        "native finite cap differs"
    );
    let paths = v["DropInPaths"]
        .as_str()
        .context("effective cap sources")?
        .split_whitespace()
        .collect::<Vec<_>>();
    let actual = paths.iter().copied().collect::<BTreeSet<_>>();
    let wanted = legacy
        .source_files
        .iter()
        .skip(1)
        .chain(p.runtime_cap_dropins.iter())
        .map(|b| b.path.to_str().context("source UTF8"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        actual == wanted && paths.len() == wanted.len(),
        "missing, repeated or undeclared effective cap source"
    );
    let mut normalized = v.clone();
    let map = normalized.as_object_mut().context("native object")?;
    for key in EXTRA {
        ensure!(map.remove(*key).is_some(), "missing native extra");
    }
    map.insert("MemoryMax".into(), json!("infinity"));
    map.insert(
        "DropInPaths".into(),
        json!(
            legacy
                .source_files
                .iter()
                .skip(1)
                .map(|b| b.path.display().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ),
    );
    map.insert("FreezerState".into(), json!("frozen"));
    ensure!(
        normalized == *old,
        "an undeclared native property changed across cap handoff"
    );
    let mut phase_plan = legacy.clone();
    phase_plan.frozen = p.phase == Phase::CappedFrozen;
    let mut for_phase = normalized;
    for_phase["FreezerState"] = json!(if phase_plan.frozen {
        "frozen"
    } else {
        "running"
    });
    ensure!(
        v["FreezerState"] == for_phase["FreezerState"],
        "actual native freeze phase differs"
    );
    census::validate_unit(&for_phase, &phase_plan)
}
fn kernel_number(path: &Path) -> Result<u64> {
    let raw = fs::read_to_string(path)?;
    ensure!(raw.len() <= 64, "oversized kernel number");
    Ok(raw.trim().parse()?)
}
fn privileges(legacy: &LegacyPlan) -> Result<Value> {
    let root = PathBuf::from(format!("/proc/{}", legacy.main_pid));
    let raw = fs::read_to_string(root.join("status"))?;
    ensure!(raw.len() <= 65536, "oversized process status");
    let mounts = fs::read_to_string(root.join("mountinfo"))?;
    ensure!(mounts.len() <= 1 << 20, "oversized mountinfo");
    validate_privileges(&raw, &mounts)
}
fn validate_privileges(raw: &str, mounts: &str) -> Result<Value> {
    let mut fields = serde_json::Map::new();
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:", "NoNewPrivs:"] {
        let found = raw
            .lines()
            .filter_map(|l| l.strip_prefix(key))
            .map(str::trim)
            .collect::<Vec<_>>();
        ensure!(
            found.len() == 1,
            "missing/duplicate process privilege field"
        );
        if key == "NoNewPrivs:" {
            ensure!(found[0] == "1", "process lacks no-new-privileges");
        } else {
            ensure!(
                u64::from_str_radix(found[0], 16)? == 0,
                "process retained inheritable/permitted/effective/ambient capabilities"
            );
        }
        fields.insert(key.into(), json!(found[0]));
    }
    let cg = mounts
        .lines()
        .filter(|l| l.split_whitespace().nth(4) == Some("/sys/fs/cgroup"))
        .collect::<Vec<_>>();
    ensure!(
        cg.len() == 1
            && cg[0]
                .split_whitespace()
                .nth(5)
                .context("cgroup mount options")?
                .split(',')
                .any(|x| x == "ro")
            && cg[0]
                .split_once(" - ")
                .context("mount separator")?
                .1
                .starts_with("cgroup2 "),
        "future cgroup mutation is not blocked by read-only cgroup2 mount"
    );
    Ok(json!({"status":fields,"read_only_cgroup2_mount":cg[0]}))
}
fn kernel(p: &Plan, legacy: &LegacyPlan) -> Result<Value> {
    let cg =
        Path::new("/sys/fs/cgroup").join(legacy.expected_control_group.trim_start_matches('/'));
    ensure!(cg.canonicalize()? == cg, "cgroup escape");
    ensure!(
        kernel_number(&cg.join("memory.max"))? == p.memory_max_bytes
            && kernel_number(&cg.join("memory.swap.max"))? == 0
            && kernel_number(&cg.join("pids.max"))? == 256,
        "kernel cap does not match native limits"
    );
    let used = kernel_number(&cg.join("memory.current"))?;
    ensure!(
        used <= p.memory_max_bytes - p.minimum_unused_bytes,
        "insufficient unused experimental cap"
    );
    let mut ancestors = Vec::new();
    let mut parent = cg.parent();
    while let Some(path) = parent {
        ensure!(
            path.starts_with("/sys/fs/cgroup"),
            "foreign cgroup ancestor"
        );
        let max = path.join("memory.max");
        let raw = if max.try_exists()? {
            fs::read_to_string(&max)?
        } else {
            ensure!(
                path == Path::new("/sys/fs/cgroup"),
                "missing ancestor limit"
            );
            "max".into()
        };
        ensure!(
            raw.len() <= 64
                && (raw.trim() == "max"
                    || raw
                        .trim()
                        .parse::<u64>()
                        .is_ok_and(|n| n >= p.memory_max_bytes)),
            "ancestor cap is below the admitted experiment"
        );
        ancestors.push(json!({"path":path,"memory_max":raw.trim()}));
        if path == Path::new("/sys/fs/cgroup") {
            break;
        }
        parent = path.parent();
    }
    Ok(
        json!({"memory_max":p.memory_max_bytes,"memory_swap_max":0,"pids_max":256,"memory_current":used,"minimum_unused_bytes":p.minimum_unused_bytes,"ancestors":ancestors,"privileges":privileges(legacy)?}),
    )
}
pub(super) fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    for key in ["DBUS_SYSTEM_BUS_ADDRESS", "SYSTEMD_BUS_ADDRESS"] {
        ensure!(
            std::env::var_os(key).is_none(),
            "native bus environment override"
        );
    }
    let started = Instant::now();
    let a = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(a.len() == 3, "usage PLAN PLAN_SHA SELF_SHA");
    let exe = fs::read_link("/proc/self/exe")?;
    evidence::bound_file(&exe, &a[2], 64 << 20, true)?;
    let plan_bound = Bound {
        path: a[0].clone().into(),
        sha256: a[1].clone(),
    };
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        &plan_bound.path,
        &plan_bound.sha256,
        65536,
        true,
    )?)?;
    shape(&p)?;
    let mut legacy: LegacyPlan = serde_json::from_slice(&evidence::bound_file(
        &p.original_frozen_plan.path,
        &p.original_frozen_plan.sha256,
        65536,
        true,
    )?)?;
    census::shape(&legacy)?;
    census::image(&legacy.program)?;
    census::image(&legacy.wrapper)?;
    let old: Value = serde_json::from_slice(&evidence::bound_file(
        &p.original_frozen_proof.path,
        &p.original_frozen_proof.sha256,
        1 << 20,
        false,
    )?)?;
    original_proof(&old, &p, &legacy, now()?)?;
    let cap_scope = scope(&p)?;
    if let Some(b) = &p.capped_frozen_proof {
        let v: Value =
            serde_json::from_slice(&evidence::bound_file(&b.path, &b.sha256, 1 << 20, false)?)?;
        fresh(
            v["recorded_unix_seconds"]
                .as_u64()
                .context("capped frozen clock")?,
            now()?,
        )?;
        ensure!(
            v["schema"] == "horizon-uploader-capped-census-proof-v1"
                && v["scope_sha256"] == cap_scope
                && v["phase"] == "capped-frozen"
                && v["self_sha256"] == a[2]
                && v["same_invocation_capped_idle_proven"] == true,
            "foreign capped frozen predecessor"
        );
    }
    legacy.frozen = p.phase == Phase::CappedFrozen;
    source_files(&p)?;
    let before = native(&legacy)?;
    native_delta(&before, &old["unit"], &p, &legacy)?;
    let first = census::snapshot_at_memory_limit(&legacy, &p.memory_max_bytes.to_string())?;
    let k1 = kernel(&p, &legacy)?;
    let after = native(&legacy)?;
    native_delta(&after, &old["unit"], &p, &legacy)?;
    let second = census::snapshot_at_memory_limit(&legacy, &p.memory_max_bytes.to_string())?;
    let k2 = kernel(&p, &legacy)?;
    ensure!(
        before == after && first == second,
        "capped owner or idle census changed"
    );
    let mut stable1 = k1.clone();
    let mut stable2 = k2.clone();
    stable1
        .as_object_mut()
        .context("kernel object")?
        .remove("memory_current");
    stable2
        .as_object_mut()
        .context("kernel object")?
        .remove("memory_current");
    ensure!(
        stable1 == stable2,
        "kernel ceiling or privilege envelope changed"
    );
    source_files(&p)?;
    census::image(&legacy.program)?;
    census::image(&legacy.wrapper)?;
    ensure!(native(&legacy)? == after, "final native owner changed");
    let final_original: LegacyPlan = serde_json::from_slice(&evidence::bound_file(
        &p.original_frozen_plan.path,
        &p.original_frozen_plan.sha256,
        65536,
        true,
    )?)?;
    census::shape(&final_original)?;
    original_proof(&old, &p, &final_original, now()?)?;
    ensure!(
        started.elapsed().as_secs() < 30,
        "finite handoff capture exceeded30seconds"
    );
    let parent = p.output.parent().context("output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "unsafe output custody"
    );
    let proof = json!({"schema":"horizon-uploader-capped-census-proof-v1","recorded_unix_seconds":now()?,"scope_sha256":cap_scope,"phase":p.phase,"plan":plan_bound,"self_sha256":a[2],"original_frozen_proof":p.original_frozen_proof,"native":after,"snapshot":second,"kernel_before":k1,"kernel_after":k2,"same_invocation_capped_idle_proven":true,"service_state_changed":false,"signal_sent":false,"successful_production_upload_under_cap_qualified":false,"all_future_shared_roles_qualified":false,"memory_credit_bytes":0,"replay_admission_authorized":false,"R2_mutations":false});
    evidence::write_receipt(&p.output, &proof)
}

#[cfg(test)]
#[path = "capped_tests.rs"]
mod tests;
