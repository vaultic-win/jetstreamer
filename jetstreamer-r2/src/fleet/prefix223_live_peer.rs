//! Lossless resource adapters for the closed 207 full epoch and 233 first root.
//! No historical view may erase one of these owners or grant allocation credit.
use super::{verification223_live_peer as base, *};
#[cfg(test)]
pub(super) use base::fixture_row;
fn profile(name: &str) -> Option<(u64, &'static str)> {
    match name {
        singleton207::UNIT => Some((207, "private-full-epoch-qualification")),
        first_root233::UNIT => Some((233, "private-known-root-prefix")),
        _ => None,
    }
}
fn selected(row: &Value) -> bool {
    singleton227_admission::active_owner(row)
        .ok()
        .and_then(|u| u["Id"].as_str())
        .is_some_and(|n| profile(n).is_some())
}
fn rows(f: &Value) -> Result<Vec<&Value>> {
    Ok(f["active"]
        .as_array()
        .context("closed peers complete active census")?
        .iter()
        .filter(|r| selected(r))
        .collect())
}
fn without(f: &Value) -> Result<Value> {
    let mut seen = BTreeSet::new();
    for row in rows(f)? {
        let u = singleton227_admission::active_owner(row)?;
        let name = u["Id"].as_str().context("closed peer name")?;
        let (epoch, phase) = profile(name).context("closed peer profile")?;
        ensure!(
            seen.insert(epoch)
                && row["epoch"] == epoch
                && row["phase"] == phase
                && row["ordinary_replay_claim"] == false
                && u["NRestarts"] == "0"
                && u["InvocationID"].as_str().is_some_and(private_prefix::iid)
                && row["launch_receipt"]
                    .as_str()
                    .is_some_and(|s| Path::new(s).is_absolute())
                && canonical_digest(&row["launch_receipt_sha256"])
                && f["active"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["epoch"] == epoch)
                    .count()
                    == 1,
            "closed peer duplicate, overlapping, changed or unbound owner"
        );
    }
    let mut copy = f.clone();
    copy["active"]
        .as_array_mut()
        .context("closed peer census")?
        .retain(|r| !selected(r));
    Ok(copy)
}
fn claim(f: &Value, row: &Value) -> Result<(DiagnosticClaim, Value)> {
    let u = singleton227_admission::active_owner(row)?;
    let name = u["Id"].as_str().context("closed peer unit")?;
    let plan: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"].as_str().context("closed peer fleet plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("closed peer fleet digest")?
            .into(),
    })?)?;
    let claims = plan
        .diagnostics
        .into_iter()
        .filter(|d| d.unit == name)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "closed peer lacks exactly one accepted claim"
    );
    let d = claims.into_iter().next().unwrap();
    ensure!(
        u["InvocationID"] == d.invocation_id
            && row["launch_receipt"].as_str() == d.launch_receipt.path.to_str()
            && row["launch_receipt_sha256"] == d.launch_receipt.sha256
            && f["unit_census"][name] == *u,
        "closed peer claim differs from full accepted raw census"
    );
    let launch = checked_diagnostic_launch(&d)?;
    Ok((d, launch))
}
pub(super) fn roster(f: &Value) -> Result<BTreeSet<String>> {
    let mut names = base::roster(&without(f)?)?;
    for row in rows(f)? {
        let name = singleton227_admission::active_owner(row)?["Id"]
            .as_str()
            .context("closed peer name")?;
        ensure!(names.insert(name.into()), "closed peer duplicate roster");
    }
    Ok(names)
}
fn live(d: &DiagnosticClaim, u: &Value) -> Result<()> {
    match d.epoch {
        207 => singleton207::validate_live(d, u),
        233 => first_root233::validate_live(d, u),
        _ => bail!("foreign closed peer"),
    }
}
fn guard_shape(
    d: &DiagnosticClaim,
    l: &Value,
    p: &Value,
    g: &Value,
    sha: &str,
    sample: u64,
    now: u64,
) -> Result<()> {
    let profile = match d.epoch {
        207 => singleton207::guard_matches(d, l, p),
        233 => first_root233::guard_matches(d, l, p),
        _ => false,
    };
    let t = g["recorded_unix_seconds"]
        .as_u64()
        .context("closed peer guard clock")?;
    ensure!(
        profile
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == singleton207::GUARD_SHA
            && g["plan_sha256"] == sha
            && t >= sample
            && t <= now
            && now - t <= 1800
            && g["producer_invocation_id"] == d.invocation_id
            && g["producer"]["invocation_id"] == d.invocation_id
            && g["producer"]["unit"] == d.unit
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["cgroup"] == format!("/system.slice/{}", d.unit)
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer_stop_enabled"] == true
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(p["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["maximum_worker_vmas"] == p["maximum_worker_vmas"]
            && g["maximum_root_physical_bytes"] == p["maximum_root_physical_bytes"]
            && g["root_physical_observation"]["maximum_physical_bytes"]
                == p["maximum_root_physical_bytes"]
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .zip(p["maximum_root_physical_bytes"].as_u64())
                .is_some_and(|(n, cap)| n <= cap)
            && g["workers"].as_array().is_some_and(|w| w.len() == 1)
            && g["workers"][0][0].as_u64().is_some_and(|n| n > 1)
            && g["workers"][0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3500000)
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error",
                "target_handoff_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["r2_mutations"] == false
            && g["remote_mutations"] == false,
        "closed peer protective evidence changed, stale, tripped or omitted an obligation"
    );
    Ok(())
}
pub(super) fn disk(
    f: &Value,
    o: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<(u64, Vec<Value>)> {
    roster(f)?;
    let mut rest = guards
        .iter()
        .map(|(k, b)| (k.clone(), binding(b.path.clone(), b.sha256.clone())))
        .collect::<BTreeMap<_, _>>();
    let mut extra = 0u64;
    let mut proof = Vec::new();
    for row in rows(f)? {
        let (d, l) = claim(f, row)?;
        let gb = rest
            .remove(&d.unit)
            .context("closed peer protective guard omitted")?;
        let g = bound_json(&gb)?;
        let pb: BoundFile = serde_json::from_value(l["guard_plan"].clone())?;
        let p = native209::immutable_json(&pb)?;
        guard_shape(&d, &l, &p, &g, &pb.sha256, sample, now)?;
        ensure!(
            g["producer"]["pid"]
                .as_u64()
                .map(|n| n.to_string())
                .as_deref()
                == singleton227_admission::active_owner(row)?["MainPID"].as_str(),
            "closed peer guard PID changed"
        );
        let (service, dir) = prefix223_native20_admission::guard_selector(&d.unit)?;
        let completed = warmup223::completed_guard_binding(service, Path::new(dir), sample, now)?;
        ensure!(
            completed["binding"] == private157::binding(&gb),
            "closed peer latest completed guard differs"
        );
        let timer = singleton227_capture::properties(
            &service.replace(".service", ".timer"),
            "ActiveState,SubState",
        )?;
        singleton227_capture::require(
            &timer,
            &[("ActiveState", "active"), ("SubState", "waiting")],
        )?;
        let budget = l["candidate_incremental_disk_reservation_bytes"]
            .as_u64()
            .context("closed peer disk cap missing")?;
        extra = extra
            .checked_add(budget)
            .context("closed peer disk overflow")?;
        proof.push(json!({"epoch":d.epoch,"unit":d.unit,"invocation_id":d.invocation_id,
            "remaining_growth_bytes":budget,"scratch_growth_credit_bytes":0,"guard":private157::binding(&gb),"source":"full conservative closed-owner reservation"}));
    }
    let (n, more) = base::disk(&without(f)?, o, &rest, sample, now)?;
    proof.extend(more);
    Ok((
        n.checked_add(extra)
            .context("closed peers combined disk overflow")?,
        proof,
    ))
}
fn binding(path: PathBuf, sha256: String) -> BoundFile {
    BoundFile { path, sha256 }
}
pub(super) fn memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    roster(f)?;
    let mut extra = 0u64;
    let mut proof = Vec::new();
    for row in rows(f)? {
        let (d, _) = claim(f, row)?;
        live(&d, singleton227_admission::active_owner(row)?)?;
        let path = Path::new("/sys/fs/cgroup/system.slice").join(&d.unit);
        ensure!(
            path.canonicalize()? == path,
            "closed peer cgroup redirected"
        );
        let read =
            |n: &str| -> Result<u64> { Ok(fs::read_to_string(path.join(n))?.trim().parse()?) };
        let cap = read("memory.max")?;
        let charge = read("memory.current")?;
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
        ensure!(
            page.is_power_of_two()
                && (4096..=65536).contains(&page)
                && cap == singleton207::MEMORY / page * page
                && charge <= cap
                && read("memory.swap.max")? == 0,
            "closed peer kernel hard memory differs"
        );
        // The guard can be between oneshot invocations; reserve its full hard
        // ceiling instead of silently zeroing it when its cgroup is absent.
        let (service, _) = prefix223_native20_admission::guard_selector(&d.unit)?;
        let properties = singleton227_capture::properties(service, "MemoryMax")?;
        singleton227_capture::require(&properties, &[("MemoryMax", "1073741824")])?;
        let growth = (cap - charge)
            .checked_add(1 << 30)
            .context("closed peer guard memory overflow")?;
        extra = extra
            .checked_add(growth)
            .context("closed peer memory overflow")?;
        proof.push(
            json!({"unit":d.unit,"invocation_id":d.invocation_id,"hard_memory_cap_bytes":cap,
            "current_cgroup_charge_bytes":charge,"guard_hard_memory_reserved_bytes":1u64<<30,
            "remaining_hard_memory_growth_bytes":growth}),
        );
    }
    let (n, more) = base::memory(&without(f)?)?;
    proof.extend(more);
    Ok((
        n.checked_add(extra)
            .context("closed peers combined memory overflow")?,
        proof,
    ))
}
pub(super) fn limits(f: &Value) -> Result<Value> {
    roster(f)?;
    let mut result = base::limits(&without(f)?)?;
    for row in rows(f)? {
        let (d, _) = claim(f, row)?;
        live(&d, singleton227_admission::active_owner(row)?)?;
        let (service, _) = prefix223_native20_admission::guard_selector(&d.unit)?;
        let guard = singleton227_capture::properties(service, "MemoryMax,TasksMax,ExecStart")?;
        let producer = singleton227_capture::properties(
            &d.unit,
            "MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,AllowedCPUs,CPUAffinity,ExecStart",
        )?;
        ensure!(
            result
                .as_object_mut()
                .context("closed peer caps object")?
                .insert(d.unit, json!({"producer":producer,"guard":guard}))
                .is_none(),
            "closed peer cap collision"
        );
    }
    Ok(result)
}
pub(super) fn current(f: &Value, census: &BTreeMap<String, Value>) -> Result<()> {
    roster(f)?;
    base::current(&without(f)?, census)?;
    for row in rows(f)? {
        let (d, _) = claim(f, row)?;
        let u = census
            .get(&d.unit)
            .context("closed peer current owner omitted")?;
        live(&d, u)?;
        let old = singleton227_admission::active_owner(row)?;
        for k in [
            "Id",
            "InvocationID",
            "MainPID",
            "NRestarts",
            "ControlGroup",
            "ActiveState",
            "SubState",
        ] {
            ensure!(old[k] == u[k], "closed peer current owner changed:{k}");
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(epoch: u64, name: &str, phase: &str) -> Value {
        json!({"epoch":epoch,"phase":phase,"ordinary_replay_claim":false,"launch_receipt":"/sealed/launch.json",
            "launch_receipt_sha256":"a".repeat(64),"producer":{"Id":name,"InvocationID":"b".repeat(32),"NRestarts":"0"}})
    }
    #[test]
    fn lossless_views_keep_all_raw_history_and_recognize_both_exact_profiles() {
        let a = row(207, singleton207::UNIT, "private-full-epoch-qualification");
        let b = row(233, first_root233::UNIT, "private-known-root-prefix");
        let f = json!({"active":[a,b],"unit_census":{"history":1},"epochs":[{"failed":204}],"diagnostics":[{"prior":true}],"plan":"retained"});
        let v = without(&f).unwrap();
        assert_eq!(v["active"], json!([]));
        for k in ["unit_census", "epochs", "diagnostics", "plan"] {
            assert_eq!(v[k], f[k]);
        }
        assert!(without(&json!({"active":[a,a]})).is_err());
        assert!(without(&json!({"active":[a,{"epoch":207,"producer":{"Id":"foreign"}}]})).is_err());
        let mut bad = a.clone();
        bad["ordinary_replay_claim"] = json!(true);
        assert!(without(&json!({"active":[bad]})).is_err());
    }
}
