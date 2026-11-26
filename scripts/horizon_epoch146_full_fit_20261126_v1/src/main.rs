use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const V17: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-170-full-metered-independent-v17";
const V17_SEAL: &str = "6649f2c650fc7774ffa054947ac94a96f8d3f8aefc4e1f7d10abe82eda4a2315";
const V24_SEAL: &str = "312d387a80ee5d8700acd180e2634938c80f15acc3d5efa056be026f767c1613";
const FOCUS_UNIT: &str = "horizon-qualify-168-full-metered-cold-v6-20261126.service";
const TERMINAL168: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch168-retry6-rebook-20261126-v1/FOCUSED_TERMINAL.json";
const TERMINAL168_SHA: &str = "5e67a984da9df5350bfce86060557a18603dbac5a18a06747c272922d14b7b71";
const TERMINAL168_IID: &str = "b693b39f54df4e5a9c65f5be75ad5fd2";
const ENTRY146: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch146-singleton-20261122-v1/bounded-entry-validated-184808-20261126-v1/BOUNDED146_ACCEPTED.json";
const ENTRY146_SHA: &str = "5afccf80e52fda308b1ac24ede5cc5ab7a49ab63a6d327f223958cae3574db26";
const ENTRY146_UNIT: &str = "horizon-146-full-local-qualification-20261124-v1.service";
const ENTRY146_IID: &str = "354e5658ddbc49fab9d16ea5b6cf219c";
const INPUT146: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch146-singleton-20261122-v1/RESTORED_BOUND_INPUTS_20261124.json";
const INPUT146_SHA: &str = "4fddd95143edc765795c76a1c86e1e5ced854a7973f5e13f7426196eb76ad43d";
const UNIT146: &str = "horizon-qualify-146-full-local-20261126-v1.service";
const TREE146: &str =
    "/home/sol/.jetstreamer-private/epoch146-standard-lane-20261122-v1/full-local-v1";
const GIB: u64 = 1 << 30;
const CAP_146: u64 = 288 * GIB;
const RAM_146: u64 = 69 * GIB;
const CPU_168: u64 = 9_250_000;
const RAM_168: u64 = 69 * GIB;
const HOLDING_185_OVERLAP: u64 = 123_350_028_052;
const HOLDING_185_ENLARGEMENT: u64 = 54_016_054_271;
const HOLDING_185_METADATA: u64 = 2_097_152;
const FULL_PLAN_SCHEMA: &str = "horizon-epoch146-full-fit-proposal-v1";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    path: PathBuf,
    sha256: String,
}

impl Binding {
    fn new(path: impl Into<PathBuf>, sha: &str) -> Self {
        Self {
            path: path.into(),
            sha256: sha.to_owned(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    schema: String,
    producer_cpu_quota_micros: u64,
    epoch168_followup_cpu_quota_micros: u64,
    epoch168_followup_memory_bytes: u64,
    epoch168_followup_additive_home_bytes: u64,
    reuse_ended_epoch168_compute: bool,
}

#[derive(Debug, Serialize)]
struct Fit {
    fits: bool,
    existing_home_floor_bytes: u64,
    projected_home_floor_bytes: u64,
    available_home_bytes: u64,
    home_shortfall_bytes: u64,
    existing_required_memory_bytes: u64,
    projected_required_memory_bytes: u64,
    available_memory_bytes: u64,
    memory_shortfall_bytes: u64,
    existing_cpu_quota_micros: u64,
    projected_cpu_quota_micros: u64,
    cpu_shortfall_micros: u64,
    donor_cpu_quota_micros_used: u64,
    donor_memory_bytes_used: u64,
}

fn sum(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("resource total overflow")
}

fn amount(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .with_context(|| format!("missing {name}"))
}

fn proposed_fit(base: &Value, plan: &Proposal) -> Result<Fit> {
    const GUARD146_CPU: u64 = 1_000_000;
    ensure!(
        plan.schema == FULL_PLAN_SCHEMA
            && (500_000..=9_000_000).contains(&plan.producer_cpu_quota_micros)
            && (plan.epoch168_followup_cpu_quota_micros == 0)
                == (plan.epoch168_followup_memory_bytes == 0),
        "invalid producer or epoch 168 follow-up budget"
    );
    let candidate_cpu = sum(plan.producer_cpu_quota_micros, GUARD146_CPU)?;
    let proposed_cpu = sum(candidate_cpu, plan.epoch168_followup_cpu_quota_micros)?;
    let proposed_ram = sum(RAM_146, plan.epoch168_followup_memory_bytes)?;
    let cpu_donor = if plan.reuse_ended_epoch168_compute {
        CPU_168.min(proposed_cpu)
    } else {
        0
    };
    let ram_donor = if plan.reuse_ended_epoch168_compute {
        RAM_168.min(proposed_ram)
    } else {
        0
    };
    let home = amount(base, "complete_required_HOME_bytes")?;
    let ram = amount(base, "required_available_memory_bytes")?;
    let cpu = amount(base, "complete_cpu_quota_micros")?;
    let home_available = amount(base, "available_HOME_bytes")?;
    let ram_available = amount(base, "available_memory_bytes")?;
    let required_home = sum(
        sum(home, CAP_146)?,
        plan.epoch168_followup_additive_home_bytes,
    )?;
    let required_ram = sum(ram, proposed_ram - ram_donor)?;
    let required_cpu = sum(cpu, proposed_cpu - cpu_donor)?;
    Ok(Fit {
        fits: base["fits"] == true
            && required_home <= home_available
            && required_ram <= ram_available
            && required_cpu <= cpu,
        existing_home_floor_bytes: home,
        projected_home_floor_bytes: required_home,
        available_home_bytes: home_available,
        home_shortfall_bytes: required_home.saturating_sub(home_available),
        existing_required_memory_bytes: ram,
        projected_required_memory_bytes: required_ram,
        available_memory_bytes: ram_available,
        memory_shortfall_bytes: required_ram.saturating_sub(ram_available),
        existing_cpu_quota_micros: cpu,
        projected_cpu_quota_micros: required_cpu,
        cpu_shortfall_micros: required_cpu.saturating_sub(cpu),
        donor_cpu_quota_micros_used: cpu_donor,
        donor_memory_bytes_used: ram_donor,
    })
}

fn stable_file(path: &Path, maximum: u64, root_owned: bool) -> Result<Vec<u8>> {
    ensure!(
        path.canonicalize()? == path,
        "indirect input {}",
        path.display()
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && (1..=maximum).contains(&before.len())
            && (!root_owned
                || before.uid() == 0 && before.mode() & 0o022 == 0 && before.nlink() == 1),
        "untrusted input {}",
        path.display()
    );
    let mut bytes = Vec::new();
    (&mut file).take(before.len() + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    let key = |m: &fs::Metadata| (m.dev(), m.ino(), m.ctime(), m.ctime_nsec(), m.len());
    ensure!(
        bytes.len() as u64 == before.len()
            && key(&before) == key(&after)
            && key(&after) == key(&named),
        "input changed during read {}",
        path.display()
    );
    Ok(bytes)
}

fn evidence(reference: &Binding) -> Result<Value> {
    let bytes = stable_file(&reference.path, 32 << 20, true)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == reference.sha256,
        "changed evidence {}",
        reference.path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn member_bytes(seal: &Value, name: &str) -> Result<(u64, String)> {
    let member = seal["members"]
        .as_array()
        .context("missing deployment members")?
        .iter()
        .find(|item| item["name"] == name)
        .context("missing deployment member")?;
    ensure!(member["mode"] == "0555", "unexpected native provider mode");
    Ok((
        amount(member, "bytes")?,
        member["sha256"]
            .as_str()
            .context("missing member digest")?
            .to_owned(),
    ))
}

fn sealed_provider() -> Result<PathBuf> {
    let parent = Path::new(V17);
    let generation = evidence(&Binding::new(
        parent.join("deployment-seal-receipt.json"),
        V17_SEAL,
    ))?;
    let (length, digest) = member_bytes(&generation, "post-stop-fit")?;
    let provider = parent.join("post-stop-fit");
    ensure!(
        generation["destination"].as_str() == Some(V17)
            && format!(
                "{:x}",
                Sha256::digest(stable_file(&provider, length, true)?)
            ) == digest,
        "different sealed capacity provider"
    );
    Ok(provider)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn idle(unit: &str, invocation: Option<&str>, terminal_pid: u64) -> Result<()> {
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "-p",
            "Id,ActiveState,SubState,Job,MainPID,ControlPID,InvocationID,ControlGroup,NRestarts",
            unit,
        ])
        .output()?;
    ensure!(output.status.success(), "could not read PID1 unit {unit}");
    let text = std::str::from_utf8(&output.stdout)?;
    let fields: std::collections::BTreeMap<_, _> =
        text.lines().filter_map(|l| l.split_once('=')).collect();
    ensure!(
        fields.get("Id") == Some(&unit)
            && matches!(fields.get("ActiveState"), Some(&"inactive" | &"failed"))
            && fields.get("Job") == Some(&"")
            && matches!(fields.get("MainPID"), None | Some(&"" | &"0"))
            && matches!(fields.get("ControlPID"), None | Some(&"" | &"0"))
            && matches!(fields.get("NRestarts"), None | Some(&"" | &"0"))
            && invocation.is_none_or(|iid| matches!(fields.get("InvocationID"), Some(&"") | None)
                || fields.get("InvocationID") == Some(&iid)),
        "terminal identity changed or producer still present {unit}"
    );
    if terminal_pid > 0 {
        ensure!(
            !PathBuf::from(format!("/proc/{terminal_pid}")).exists(),
            "terminal PID was reused"
        );
    }
    if let Some(cgroup) = fields.get("ControlGroup").filter(|group| !group.is_empty()) {
        let file = PathBuf::from("/sys/fs/cgroup")
            .join(cgroup.trim_start_matches('/'))
            .join("cgroup.procs");
        match fs::read_to_string(file) {
            Ok(procs) => ensure!(
                procs.trim().is_empty(),
                "terminal cgroup contains a process"
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn exact_baseline(base: &Value, fleet: &Value) -> Result<()> {
    let old = &base["retry5_complete_booking"];
    let suffix = &base["focused168_retry6"];
    let price185 = &base["epoch185_serial_cost"];
    let custody = &base["epoch185_lanel_holding"]["observation"];
    let booking = &base["epoch185_lanel_holding"]["holding_reservation"];
    let terminal = serde_json::to_value(Binding::new(TERMINAL168, TERMINAL168_SHA))?;
    ensure!(
        base["schema"] == "horizon-incident-replay-fit-v1"
            && base["epoch"] == 170
            && base["resource_credit_bytes"] == 0
            && base["replay_launch_authorized"] == false
            && base["complete_cpu_quota_micros"] == 64_000_000
            && base["complete_memory_plus_reserve_bytes"] == 810_658_050_048u64
            && base["status_registration"]["consumer_seal"]["sha256"] == V24_SEAL
            && base["population"].get(FOCUS_UNIT).is_none()
            && base["population"].get(UNIT146).is_none()
            && fleet["current_cold168_retry6_terminal"] == terminal
            && suffix["terminal"] == terminal
            && suffix["processes"].as_array().is_some_and(Vec::is_empty)
            && suffix["resource_credit_bytes"] == 0
            && old["funded"] == true
            && old["schema"] == "horizon-168-retry5-complete-booking-v1"
            && sum(
                amount(old, "producer_cpu_quota_micros")?,
                amount(old, "guard_cpu_quota_micros")?
            )? == CPU_168
            && sum(
                amount(old, "producer_memory_bytes")?,
                amount(old, "guard_memory_bytes")?
            )? == RAM_168
            && old["candidate_remaining_bytes"] == base["bookings"]["168"]["remaining_bytes"]
            && old["candidate_remaining_bytes"] == suffix["paid"]["remaining_bytes"]
            && amount(suffix, "minimum_free_bytes")?
                <= amount(base, "complete_required_HOME_bytes")?
            && price185["native_fleet"] == base["fleet"]
            && price185["required_home_bytes"] == base["complete_required_HOME_bytes"]
            && price185["serial_restore_enlargement_bytes"] == HOLDING_185_ENLARGEMENT
            && price185["metadata_allowance_bytes"] == HOLDING_185_METADATA
            && price185["resource_credit_bytes"] == 0
            && custody["stage"] == "custody-recorded"
            && custody["custody"]["sha256"]
                == "6d98a2cee2fb725179c4e0620b8ee4ed46e8665f7e24417bf8392eab1d8b70ca"
            && booking["restore_overlap_bytes"] == HOLDING_185_OVERLAP
            && booking["resource_credit_bytes"] == 0,
        "different native fleet, retained 168/185 commitments, or existing full owner"
    );
    let bounded = &base["bounded_qualification"];
    ensure!(
        bounded.is_null()
            || bounded["unit"] == ENTRY146_UNIT && bounded["invocation_id"] == ENTRY146_IID,
        "another bounded lease owns the native qualification slot"
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    ensure!(
        args.len() == 3,
        "usage: horizon-epoch146-full-fit FLEET FLEET_SHA256 PROPOSAL"
    );
    let fleet = Binding::new(
        PathBuf::from(&args[0]),
        args[1].to_str().context("fleet SHA")?,
    );
    ensure!(
        fleet.path.parent().and_then(Path::parent) == Some(Path::new(ROOT)),
        "foreign accepted fleet directory"
    );
    let accepted = evidence(&fleet)?;
    let plan_path = PathBuf::from(&args[2]);
    let plan_bytes = stable_file(&plan_path, 64 << 10, false)?;
    let plan: Proposal = serde_json::from_slice(&plan_bytes)?;
    let entry = evidence(&Binding::new(ENTRY146, ENTRY146_SHA))?;
    let input = evidence(&Binding::new(INPUT146, INPUT146_SHA))?;
    let terminal = evidence(&Binding::new(TERMINAL168, TERMINAL168_SHA))?;
    ensure!(
        entry["epoch"] == 146
            && entry["invocation_id"] == ENTRY146_IID
            && entry["bounded_entry_qualified"] == true
            && entry["full_replay_admitted"] == false
            && entry["terminal"]["exit_signal"] == "SIGXFSZ"
            && entry["terminal"]["cgroup_drained"] == true
            && entry["runtime"] == "solana-v1.4.25"
            && input["root_checkpoints"] == json!([63072070, 63503456])
            && input["runtime"]["worker"]["sha256"]
                == "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"
            && input["root_checkpoints"] == json!([63072070, 63503456])
            && terminal["producer_invocation_id"] == TERMINAL168_IID
            && terminal["clean_exit"] == true
            && terminal["producer_cgroup_drained"] == true
            && terminal["resource_credit_bytes"] == 0,
        "different bounded entry, full replay inputs or retired 168 compute owner"
    );
    idle(
        FOCUS_UNIT,
        Some(TERMINAL168_IID),
        amount(&terminal, "producer_pid")?,
    )?;
    idle(
        "horizon-guard-168-full-metered-cold-v6-20261126.timer",
        None,
        0,
    )?;
    idle(
        "horizon-guard-168-full-metered-cold-v6-20261126.service",
        None,
        0,
    )?;
    idle(ENTRY146_UNIT, Some(ENTRY146_IID), 3812261)?;
    idle(UNIT146, None, 0)?;
    let provider = sealed_provider()?;
    let fresh = Command::new(provider)
        .arg("--full170=active")
        .arg("145")
        .arg(&fleet.path)
        .arg(&fleet.sha256)
        .output()?;
    ensure!(
        fresh.status.success(),
        "V17 capacity failed: {}",
        String::from_utf8_lossy(&fresh.stderr)
    );
    let base: Value = serde_json::from_slice(&fresh.stdout)?;
    ensure!(
        base["fleet"] == serde_json::to_value(&fleet)?
            && now()?
                .checked_sub(amount(&base, "recorded_unix_seconds")?)
                .is_some_and(|age| age <= 120),
        "native capacity quote is stale or foreign"
    );
    exact_baseline(&base, &accepted)?;
    idle(
        FOCUS_UNIT,
        Some(TERMINAL168_IID),
        amount(&terminal, "producer_pid")?,
    )?;
    idle(ENTRY146_UNIT, Some(ENTRY146_IID), 3812261)?;
    idle(UNIT146, None, 0)?;
    let quote = proposed_fit(&base, &plan)?;
    let report = json!({
        "schema": "horizon-epoch146-full-prestart-fit-v1",
        "recorded_unix_seconds": now()?,
        "epoch": 146,
        "fleet": fleet,
        "proposal": Binding::new(plan_path, &format!("{:x}", Sha256::digest(plan_bytes))),
        "native_v17_provider_sha256": V17_SEAL,
        "native_v17_stdout_sha256": format!("{:x}", Sha256::digest(&fresh.stdout)),
        "native_v17_quote": base,
        "native_v17_recorded_unix_seconds": base["recorded_unix_seconds"],
        "native_v17_population": base["population"],
        "exact_native_entry": Binding::new(ENTRY146, ENTRY146_SHA),
        "full_replay_inputs": Binding::new(INPUT146, INPUT146_SHA),
        "terminal_168_owner": Binding::new(TERMINAL168, TERMINAL168_SHA),
        "retained_168_disk_bytes": base["bookings"]["168"]["remaining_bytes"],
        "retained_185_restore_overlap_bytes": HOLDING_185_OVERLAP,
        "retained_185_restore_enlargement_bytes": HOLDING_185_ENLARGEMENT,
        "retained_185_custody": base["epoch185_lanel_holding"]["observation"]["custody"],
        "retained_bounded_qualification": base["bounded_qualification"],
        "fit": quote,
        "pending_guard": {
            "unit": UNIT146, "worker_root": TREE146, "filesystem": "/home/sol",
            "maximum_root_physical_bytes": CAP_146, "maximum_worker_vmas": 3_500_000,
            "minimum_free_bytes": sum(quote.existing_home_floor_bytes, plan.epoch168_followup_additive_home_bytes)?,
            "producer_cpu_quota_micros": plan.producer_cpu_quota_micros, "producer_memory_bytes": 68 * GIB,
            "guard_cpu_quota_micros": 1_000_000, "guard_memory_bytes": GIB, "swap_bytes": 0,
        },
        "pending_epoch168_followup": {
            "cpu_quota_micros": plan.epoch168_followup_cpu_quota_micros,
            "memory_bytes": plan.epoch168_followup_memory_bytes,
            "additive_home_bytes": plan.epoch168_followup_additive_home_bytes,
        },
        "resource_credit_bytes": 0,
        "replay_launch_authorized": false,
        "publication_authorized": false,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> Value {
        json!({
            "fits": true,
            "complete_required_HOME_bytes": 9_113_207_738_261u64,
            "available_HOME_bytes": 9_435_416_489_984u64,
            "complete_cpu_quota_micros": 64_000_000,
            "required_available_memory_bytes": 663_467_622_400u64,
            "available_memory_bytes": 734_893_674_496u64
        })
    }

    fn proposal(
        cpu: u64,
        follow_cpu: u64,
        follow_ram: u64,
        additive: u64,
        reuse: bool,
    ) -> Proposal {
        Proposal {
            schema: FULL_PLAN_SCHEMA.into(),
            producer_cpu_quota_micros: cpu,
            epoch168_followup_cpu_quota_micros: follow_cpu,
            epoch168_followup_memory_bytes: follow_ram,
            epoch168_followup_additive_home_bytes: additive,
            reuse_ended_epoch168_compute: reuse,
        }
    }

    #[test]
    fn standard_lane_exceeds_cpu_and_memory_even_with_disk_margin() {
        let result = proposed_fit(&baseline(), &proposal(9_000_000, 0, 0, 0, false)).unwrap();
        assert!(!result.fits);
        assert_eq!(result.home_shortfall_bytes, 0);
        assert_eq!(result.cpu_shortfall_micros, 10_000_000);
        assert_eq!(result.memory_shortfall_bytes, 2_662_133_760);
        assert_eq!(result.donor_cpu_quota_micros_used, 0);
    }

    #[test]
    fn transfers_only_compute_and_charges_concurrent_followup_ram() {
        let result = proposed_fit(
            &baseline(),
            &proposal(6_250_000, 2_000_000, 8 * GIB, 0, true),
        )
        .unwrap();
        assert!(result.fits);
        assert_eq!(result.donor_cpu_quota_micros_used, CPU_168);
        assert_eq!(result.projected_cpu_quota_micros, 64_000_000);
        assert_eq!(result.donor_memory_bytes_used, RAM_168);
        assert_eq!(
            result.projected_required_memory_bytes,
            663_467_622_400 + 8 * GIB
        );
        assert_eq!(
            result.projected_home_floor_bytes,
            9_113_207_738_261 + CAP_146
        );
    }

    #[test]
    fn cannot_oversubscribe_the_ended_cpu_or_drop_followup_growth() {
        let cpu = proposed_fit(&baseline(), &proposal(9_000_000, 0, 0, 0, true)).unwrap();
        assert!(!cpu.fits);
        assert_eq!(cpu.cpu_shortfall_micros, 750_000);
        let disk = proposed_fit(
            &baseline(),
            &proposal(6_250_000, 2_000_000, 8 * GIB, 13 * GIB, true),
        )
        .unwrap();
        assert!(!disk.fits);
        assert_eq!(disk.home_shortfall_bytes, 987_537_301);
    }

    #[test]
    fn unrelated_followup_claim_and_non_fit_base_remain_closed() {
        assert!(proposed_fit(&baseline(), &proposal(6_250_000, 2_000_000, 0, 0, true)).is_err());
        let mut prior = baseline();
        prior["fits"] = json!(false);
        assert!(
            !proposed_fit(&prior, &proposal(6_250_000, 2_000_000, 8 * GIB, 0, true))
                .unwrap()
                .fits
        );
    }
}
