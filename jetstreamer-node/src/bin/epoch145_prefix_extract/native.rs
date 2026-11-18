//! Native checks are confined to this new extractor and its exact bound guard.
use super::{
    contract::{self, Admission, Budget, Owner, Plan},
    receipt,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub(super) fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub(super) fn utc_seconds(value: &str) -> Result<u64> {
    ensure!(
        value.len() == 20 && value.is_ascii(),
        "noncanonical UTC clock"
    );
    let raw = std::ffi::CString::new(value)?;
    let mut parsed: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(raw.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut parsed) };
    ensure!(!end.is_null() && unsafe { *end } == 0, "invalid UTC clock");
    let seconds = u64::try_from(unsafe { libc::timegm(&mut parsed) })?;
    let mut normalized: libc::tm = unsafe { std::mem::zeroed() };
    let t: libc::time_t = seconds.try_into()?;
    ensure!(
        !unsafe { libc::gmtime_r(&t, &mut normalized) }.is_null(),
        "UTC conversion failed"
    );
    ensure!(
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            normalized.tm_year + 1900,
            normalized.tm_mon + 1,
            normalized.tm_mday,
            normalized.tm_hour,
            normalized.tm_min,
            normalized.tm_sec
        ) == value,
        "normalized invalid UTC clock"
    );
    Ok(seconds)
}
fn show(unit: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        unit.starts_with("horizon-qualify-145-prefix-extract-")
            && (unit.ends_with(".service") || unit.ends_with("-guard.timer")),
        "foreign native query"
    );
    let output=Command::new("/usr/bin/systemctl").args(["show",unit,"--property=Id,LoadState,InvocationID,ActiveState,SubState,MainPID,ControlPID,NRestarts,Restart,KillMode,Delegate,ControlGroup,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,User,NoNewPrivileges,RuntimeMaxUSec,RootDirectory,RootImage,Unit,Job,Result,TimersMonotonic,ExecStart"]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 128 << 10,
        "own native query failed or exceeded bound"
    );
    let text = String::from_utf8(output.stdout)?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line
            .split_once('=')
            .context("own native property malformed")?;
        ensure!(
            values.insert(k.into(), v.into()).is_none(),
            "duplicate native property"
        );
    }
    Ok(values)
}
fn property<'a>(m: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    m.get(key)
        .map(String::as_str)
        .with_context(|| format!("missing native {key}"))
}
fn start_ticks() -> Result<u64> {
    let raw = std::fs::read_to_string("/proc/self/stat")?;
    raw.rsplit_once(") ")
        .context("self stat framing")?
        .1
        .split_whitespace()
        .nth(19)
        .context("self start ticks")?
        .parse()
        .map_err(Into::into)
}
fn validate_own(m: &BTreeMap<String, String>, owner: &Owner) -> Result<()> {
    for (k, v) in [
        ("Id", owner.unit.as_str()),
        ("InvocationID", owner.invocation_id.as_str()),
        ("ControlGroup", owner.cgroup.as_str()),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryAccounting", "yes"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "16s"),
        ("TasksMax", "512"),
        ("User", "root"),
        ("NoNewPrivileges", "yes"),
        ("RuntimeMaxUSec", "1d"),
        ("RootDirectory", ""),
        ("RootImage", ""),
    ] {
        ensure!(
            property(m, k)? == v,
            "extractor native identity/profile differs at {k}"
        );
    }
    ensure!(
        property(m, "MainPID")? == owner.pid.to_string()
            && property(m, "MemoryMax")? == contract::MEMORY.to_string(),
        "extractor PID or hard memory differs"
    );
    Ok(())
}
pub(super) fn capture(plan: &Plan) -> Result<Owner> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "extractor requires Root custody"
    );
    let unit = plan.unit();
    let m = show(&unit)?;
    let iid = property(&m, "InvocationID")?.to_owned();
    ensure!(
        contract::hex(&iid, 32) && iid.bytes().any(|c| c != b'0'),
        "native invocation is absent"
    );
    let owner = Owner {
        unit: unit.clone(),
        invocation_id: iid,
        pid: std::process::id(),
        start_ticks: start_ticks()?,
        cgroup: format!("/system.slice/{unit}"),
        started_unix_seconds: now()?,
        program_sha256: plan.program.sha256.clone(),
    };
    verify(&owner)?;
    ensure!(
        std::fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::{}", owner.cgroup),
        "extractor is outside admitted cgroup"
    );
    Ok(owner)
}
pub(super) fn verify(owner: &Owner) -> Result<()> {
    ensure!(
        owner.pid == std::process::id() && owner.start_ticks == start_ticks()?,
        "extractor process was replaced"
    );
    validate_own(&show(&owner.unit)?, owner)
}
fn guard_receipt(value: &Value, a: &Admission, plan: &Plan, budget: Budget, at: u64) -> Result<()> {
    let producer = &value["producer"];
    ensure!(
        value["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && value["plan"] == serde_json::to_value(&a.guard.plan.path)?
            && value["plan_sha256"] == a.guard.plan.sha256
            && value["guard_sha256"] == contract::GUARD_SHA
            && value["producer_invocation_id"] == a.owner.invocation_id
            && producer["invocation_id"] == a.owner.invocation_id
            && producer["pid"] == a.owner.pid
            && producer["cgroup"] == a.owner.cgroup
            && producer["active"] == "active"
            && producer["sub"] == "running"
            && producer["restart_policy"] == "no"
            && producer["kill_mode"] == "control-group"
            && producer["delegated"] == false
            && producer["restarts"] == 0
            && value["producer_stop_enabled"] == true
            && value["minimum_free_bytes"] == budget.floor
            && value["maximum_root_physical_bytes"] == contract::EXTRA_DATA
            && value["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= budget.floor)
            && value.get("trip_reason") == Some(&Value::Null)
            && value.get("worker_observation_error") == Some(&Value::Null)
            && value.get("root_physical_observation_error") == Some(&Value::Null)
            && value["r2_mutations"] == false
            && value["remote_mutations"] == false,
        "extractor lacks a genuine matching effective lifetime guard"
    );
    let recorded = value["recorded_unix_seconds"]
        .as_u64()
        .context("guard receipt clock")?;
    ensure!(
        recorded <= at && at - recorded <= 45 && recorded >= a.owner.started_unix_seconds,
        "guard receipt is stale or predates held owner"
    );
    ensure!(
        value["guard_invocation_id"]
            .as_str()
            .is_some_and(|iid| contract::hex(iid, 32) && iid.bytes().any(|c| c != b'0')),
        "guard receipt has no genuine invocation identity"
    );
    ensure!(plan.work().is_absolute(), "guard work is noncanonical");
    Ok(())
}
pub(super) struct Watch<'a> {
    plan: &'a Plan,
    a: &'a Admission,
    budget: Budget,
    last: Option<Value>,
    checked: Instant,
    started: u64,
}
impl<'a> Watch<'a> {
    pub fn new(plan: &'a Plan, a: &'a Admission, budget: Budget) -> Result<Self> {
        let p = receipt::bound(&a.guard.plan)?;
        ensure!(
            p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
                && p["unit"] == a.owner.unit
                && p["invocation_id"] == a.owner.invocation_id
                && p["filesystem"] == "/"
                && p["worker_root"] == serde_json::to_value(plan.work())?
                && p["receipt_directory"] == serde_json::to_value(&a.guard.receipt_directory)?
                && p["minimum_free_bytes"] == budget.floor
                && p["maximum_root_physical_bytes"] == contract::EXTRA_DATA
                && p["maximum_worker_vmas"] == 3_500_000u64
                && p["bounded_measurement"].is_null()
                && p["bounded_canary"].is_null()
                && p["native_main"].is_null(),
            "guard plan does not protect the exact copy/extraction lifetime"
        );
        ensure!(
            receipt::hash_file(&a.guard.program.path)? == a.guard.program.sha256,
            "guard executable changed"
        );
        ensure!(
            a.guard.first_sample.path.parent() == Some(a.guard.receipt_directory.as_path()),
            "first guard sample is outside exact receipt root"
        );
        let first = receipt::bound(&a.guard.first_sample)?;
        ensure!(
            a.guard
                .first_sample
                .path
                .file_name()
                .and_then(|n| n.to_str())
                == Some(
                    format!(
                        "sample-{}.json",
                        first["guard_invocation_id"]
                            .as_str()
                            .context("first guard IID")?
                    )
                    .as_str()
                ),
            "first guard sample name crosses invocation"
        );
        guard_receipt(&first, a, plan, budget, now()?)?;
        let mut w = Self {
            plan,
            a,
            budget,
            last: Some(first),
            checked: Instant::now(),
            started: now()?,
        };
        w.check(true)?;
        Ok(w)
    }
    pub fn check(&mut self, force: bool) -> Result<()> {
        if !force && self.checked.elapsed() < Duration::from_secs(1) {
            return Ok(());
        }
        let at = now()?;
        ensure!(
            at >= self.started && at - self.started <= 86400,
            "extractor lifetime expired"
        );
        verify(&self.a.owner)?;
        let stem = self
            .a
            .owner
            .unit
            .strip_suffix(".service")
            .context("extractor unit suffix")?;
        let guard_name = format!("{stem}-guard.service");
        let timer_name = format!("{stem}-guard.timer");
        let timer = show(&timer_name)?;
        ensure!(
            property(&timer, "Id")? == timer_name
                && property(&timer, "LoadState")? == "loaded"
                && property(&timer, "Unit")? == guard_name
                && property(&timer, "ActiveState")? == "active"
                && matches!(property(&timer, "SubState")?, "waiting" | "elapsed")
                && property(&timer, "Job")?.is_empty()
                && property(&timer, "TimersMonotonic")?.contains("OnUnitActiveUSec=30s"),
            "extractor guard timer is foreign or disarmed"
        );
        let guard = show(&guard_name)?;
        for (k, v) in [
            ("Id", guard_name.as_str()),
            ("LoadState", "loaded"),
            ("NRestarts", "0"),
            ("Restart", "no"),
            ("Delegate", "no"),
            ("MemoryMax", "536870912"),
            ("MemorySwapMax", "0"),
            ("User", "root"),
        ] {
            ensure!(
                property(&guard, k)? == v,
                "guard native profile differs at {k}"
            );
        }
        ensure!(
            property(&guard, "ActiveState")? != "failed"
                && property(&guard, "Result")? == "success",
            "extractor guard failed"
        );
        let command = property(&guard, "ExecStart")?
            .split_once("argv[]=")
            .context("guard command argv absent")?
            .1
            .split_once(" ; ignore_errors=")
            .context("guard command framing")?
            .0;
        ensure!(
            command
                == format!(
                    "{} {} --plan-sha256 {} --self-sha256 {}",
                    self.a.guard.program.path.display(),
                    self.a.guard.plan.path.display(),
                    self.a.guard.plan.sha256,
                    self.a.guard.program.sha256
                ),
            "guard executable or plan argv changed"
        );
        let iid = property(&guard, "InvocationID")?;
        if contract::hex(iid, 32) {
            let path = self
                .a
                .guard
                .receipt_directory
                .join(format!("sample-{iid}.json"));
            if path.try_exists()? {
                let v = receipt::private_json(&path)?;
                ensure!(
                    v["guard_invocation_id"] == iid,
                    "guard file contains a different invocation"
                );
                guard_receipt(&v, self.a, self.plan, self.budget, at)?;
                self.last = Some(v);
            }
        }
        guard_receipt(
            self.last
                .as_ref()
                .context("guard has not produced its first actual sample")?,
            self.a,
            self.plan,
            self.budget,
            at,
        )?;
        ensure!(
            receipt::available(&self.plan.work())? >= self.budget.floor,
            "extractor crossed protected DATA floor"
        );
        self.checked = Instant::now();
        Ok(())
    }
    pub fn output(&mut self, bytes: u64) -> std::io::Result<()> {
        if bytes > contract::OUTPUT {
            return Err(std::io::Error::other("canonical output ceiling crossed"));
        }
        self.check(false).map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Plan, Admission, Budget, Value) {
        let (p, _, _, a, _) = contract::tests::fixture();
        let budget = Budget {
            floor: contract::OLD_FLOOR,
            required_initial_free: contract::OLD_FLOOR + contract::EXTRA_DATA,
        };
        let value = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","plan":a.guard.plan.path,"plan_sha256":a.guard.plan.sha256,
            "guard_sha256":contract::GUARD_SHA,"guard_invocation_id":"e".repeat(32),"producer_invocation_id":a.owner.invocation_id,
            "producer":{"invocation_id":a.owner.invocation_id,"pid":a.owner.pid,"cgroup":a.owner.cgroup,"active":"active","sub":"running","restart_policy":"no","kill_mode":"control-group","delegated":false,"restarts":0},
            "producer_stop_enabled":true,"minimum_free_bytes":budget.floor,"maximum_root_physical_bytes":contract::EXTRA_DATA,"available_bytes":budget.required_initial_free,
            "trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"r2_mutations":false,"remote_mutations":false,"recorded_unix_seconds":1030});
        (p, a, budget, value)
    }
    #[test]
    fn effective_guard_binds_actual_held_owner_and_complete_copy_floor() {
        let (p, a, b, v) = fixture();
        guard_receipt(&v, &a, &p, b, 1040).unwrap();
    }
    #[test]
    fn capability_stale_foreign_and_tripped_guards_do_not_admit_archive_access() {
        for (path, value) in [
            ("/producer_stop_enabled", json!(false)),
            ("/producer/pid", json!(999)),
            ("/producer/invocation_id", json!("f".repeat(32))),
            ("/minimum_free_bytes", json!(0)),
            ("/trip_reason", json!("filesystem-floor")),
            ("/recorded_unix_seconds", json!(900)),
            ("/guard_invocation_id", json!("0".repeat(32))),
        ] {
            let (p, a, b, mut v) = fixture();
            *v.pointer_mut(path).unwrap() = value;
            assert!(guard_receipt(&v, &a, &p, b, 1040).is_err(), "{path}");
        }
    }
    #[test]
    fn real_utc_parser_does_not_normalize_invalid_or_future_calendar_values() {
        assert!(utc_seconds("2026-11-06T04:28:09Z").is_ok());
        assert!(utc_seconds("2026-02-30T00:00:00Z").is_err());
        assert!(utc_seconds("2026-11-06T24:00:00Z").is_err());
    }
    #[test]
    fn namespace_is_exactly_one_new_family() {
        assert!(!contract::hex("0123456789abcde/", 16));
        assert!(!contract::hex("A123456789abcdef", 16));
    }
}
