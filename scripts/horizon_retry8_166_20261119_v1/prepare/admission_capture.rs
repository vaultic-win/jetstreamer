//! A synchronous admission transaction for peers born after the routine sample.
//! It does not create a routine observer receipt or advance any polling clock.
use super::*;
fn worker(o: &Owner, role: &Value) -> Result<u64> {
    let rows = census(&role["rss"])?;
    ensure!(
        rows.len() == 2
            && rows
                .get(&o.main_pid)
                .is_some_and(|(t, _)| *t == o.main_start_ticks),
        "exact stable parent plus one worker required"
    );
    rows.keys()
        .copied()
        .find(|pid| *pid != o.main_pid)
        .context("worker missing")
}
fn endpoint(o: &Owner) -> Result<(Value, Value, Value)> {
    let native = native_complete(&o.unit)?;
    let mut role = sample_role(o, &native)?;
    let pid = worker(o, &role)?;
    let images = process_images(o, &json!({"worker_after":{"pid":pid}}))?;
    let mut counters = BTreeMap::new();
    for key in ["max", "oom", "oom_kill"] {
        counters.insert(
            format!("memory_events.{key}"),
            n(&role["memory_events"], key)?,
        );
    }
    role["cgroup"] = json!({"counters":counters});
    Ok((native, role, images))
}
fn transaction(request: &Request) -> Result<Value> {
    let started = now()?;
    let before = resident_capture::host_resident();
    let mut lanes = BTreeMap::new();
    for o in &request.owners {
        let (native, role, images) = endpoint(o)?;
        lanes.insert(o.epoch.to_string(),json!({"native_before":native,"controller_before":role,"producer_before":role,"process_images_before":images}));
    }
    for o in &request.owners {
        let (native, role, images) = endpoint(o)?;
        let row = lanes
            .get_mut(&o.epoch.to_string())
            .context("peer missing")?;
        row["native_after"] = native;
        row["controller_after"] = role.clone();
        row["producer_after"] = role;
        row["process_images_after"] = images;
    }
    let after = resident_capture::host_resident();
    let finished = now()?;
    ensure!(
        started <= finished && finished - started <= 120,
        "bounded admission capture expired"
    );
    Ok(
        json!({"started_unix_seconds":started,"completed_unix_seconds":finished,"host_before":before,"host_after":after,"lanes":lanes}),
    )
}
fn snapshot(request: &Request, first: &Value, total: u64) -> Result<Value> {
    let mut rows = Vec::new();
    for o in &request.owners {
        let live = &first["lanes"][o.epoch.to_string()];
        ensure!(
            live["native_before"] == live["native_after"]
                && live["process_images_before"] == live["process_images_after"],
            "peer native/image changed in first admission capture"
        );
        let before = &live["producer_before"];
        let after = &live["producer_after"];
        let wb = worker(o, before)?;
        let wa = worker(o, after)?;
        ensure!(
            wb == wa
                && identities(&census(&before["rss"])?) == identities(&census(&after["rss"])?)
                && live["native_after"]["InvocationID"] == o.invocation_id,
            "peer process identity changed in admission capture"
        );
        let images = &live["process_images_after"];
        let image = &images[wa.to_string()];
        let mut delta = BTreeMap::new();
        for key in ["max", "oom", "oom_kill"] {
            delta.insert(
                format!("memory_events.{key}"),
                n(&after["memory_events"], key)?
                    .checked_sub(n(&before["memory_events"], key)?)
                    .context("peer memory event counter regressed")?,
            );
        }
        rows.push(json!({"range":o.epoch.to_string(),"invocation_binding_stable":true,"producer_cgroup_counter_delta":delta,"controller_before":live["controller_before"],"controller_after":live["controller_after"],"producer_before":before,"producer_after":after,"worker_before":{"pid":wb,"executable":image["executable"]},"worker_after":{"pid":wa,"executable":image["executable"]}}));
    }
    Ok(
        json!({"schema":"horizon-retry2-admission-only-resident-snapshot-v1","routine_observation":false,"previous_routine_observer":request.observer,"started_unix_seconds":first["started_unix_seconds"],"completed_unix_seconds":first["completed_unix_seconds"],"host_memory":{"total_kib":total/1024},"host_resident_memory":{"before":first["host_before"],"after":first["host_after"]},"replays":rows}),
    )
}
fn memory_endpoint() -> Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    for line in fs::read_to_string("/proc/meminfo")?.lines() {
        let (key, value) = line.split_once(':').context("meminfo shape")?;
        if matches!(key, "MemTotal" | "MemAvailable") {
            let mut fields = value.split_whitespace();
            let bytes = fields
                .next()
                .context("memory value")?
                .parse::<u64>()?
                .checked_mul(1024)
                .context("memory overflow")?;
            ensure!(
                fields.next() == Some("kB") && fields.next().is_none(),
                "memory units"
            );
            result.insert(key.into(), bytes);
        }
    }
    ensure!(result.len() == 2, "memory endpoint missing");
    Ok(result)
}
fn native_identity() -> Result<Value> {
    let iid =
        std::env::var("INVOCATION_ID").context("admission capture actual systemd invocation")?;
    ensure!(
        lower_hex(&iid, 32) && iid.bytes().any(|b| b != b'0'),
        "actual admission invocation required"
    );
    let executable = fs::read_link("/proc/self/exe")?;
    ensure!(
        executable == Path::new(IMAGE),
        "actual qualified own-image admission required"
    );
    let bytes = raw(&executable, 64 << 20, true)?;
    Ok(
        json!({"executable":executable,"executable_sha256":digest(&bytes),"pid":std::process::id(),"systemd_invocation_id":iid}),
    )
}
fn peer_guards(request: &Request) -> Result<()> {
    for o in &request.owners {
        let proof = bound(&o.guard_protection)?;
        let timer = text_field(&proof, "timer_unit")?;
        ensure!(
            timer
                == format!(
                    "horizon-guard-replacement-{}-{}-20261110-v1.timer",
                    o.epoch,
                    if o.unit.ends_with("-local3retry4-20261110-v1.service") {
                        "local3retry4"
                    } else if o.unit.ends_with("-local3retry3-20261110-v1.service") {
                        "local3retry3"
                    } else {
                        "local3retry2"
                    }
                ),
            "exact peer timer required"
        );
        let state = native(timer)?;
        ensure!(
            state.get("Id").is_some_and(|v| v == timer)
                && state.get("ActiveState").is_some_and(|v| v == "active")
                && state.get("Job").is_some_and(String::is_empty)
                && state.get("InvocationID").map(String::as_str)
                    == proof["timer_invocation_id"].as_str(),
            "peer protective timer changed or inactive"
        );
    }
    Ok(())
}
pub(super) fn fresh(
    request: &Request,
    p: &Plan,
    fleet: &Value,
    mem: &BTreeMap<String, u64>,
    at: u64,
) -> Result<Value> {
    let _ = owner_rows(fleet, request, p.epoch)?;
    peer_admissions(request)?;
    peer_guards(request)?;
    let previous = bound(&request.observer)?;
    ensure!(
        previous["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "prior routine observer provenance required"
    );
    let own = native_identity()?;
    let first = transaction(request)?;
    let middle = memory_endpoint()?;
    let current = transaction(request)?;
    let final_mem = memory_endpoint()?;
    for o in &request.owners {
        let a = &first["lanes"][o.epoch.to_string()];
        let b = &current["lanes"][o.epoch.to_string()];
        ensure!(
            a["native_after"] == b["native_before"]
                && a["native_after"] == b["native_after"]
                && a["process_images_after"] == b["process_images_before"]
                && a["process_images_after"] == b["process_images_after"],
            "peer native or executable changed across all four admission endpoints"
        );
    }
    let total = *mem.get("MemTotal").context("initial MemTotal")?;
    ensure!(
        middle["MemTotal"] == total && final_mem["MemTotal"] == total,
        "admission host total changed"
    );
    let available = (*mem.get("MemAvailable").context("initial MemAvailable")?)
        .min(middle["MemAvailable"])
        .min(final_mem["MemAvailable"]);
    let conservative = BTreeMap::from([
        ("MemTotal".into(), total),
        ("MemAvailable".into(), available),
    ]);
    let observed = snapshot(request, &first, total)?;
    let finished = now()?;
    ensure!(
        at <= finished && finished - at <= 120 && own == native_identity()?,
        "admission capture expired or own identity changed"
    );
    let result = checked(
        request,
        p.epoch,
        fleet,
        &observed,
        &current,
        &conservative,
        finished,
    )?;
    peer_admissions(request)?;
    peer_guards(request)?;
    Ok(
        json!({"qualified_accounting":result,"admission_only_snapshot":observed,"first_native_admission_transaction":first,"fresh_admission_transaction_capture":current,"native_identity":own,"previous_routine_observer":request.observer,"previous_routine_observer_used_for_new_peer_realization":false,"new_routine_observer_sample":false,"new_polling_loop":false,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_is_admission_evidence_and_rejects_native_or_process_changes() {
        let (mut request, _, _, mut live, mem, at) = super::super::tests::fixture();
        request.admission_only_capture = true;
        live["started_unix_seconds"] = json!(at - 2);
        live["completed_unix_seconds"] = json!(at - 1);
        let v = snapshot(&request, &live, mem["MemTotal"]).unwrap();
        assert_eq!(
            v["schema"],
            "horizon-retry2-admission-only-resident-snapshot-v1"
        );
        assert_eq!(v["routine_observation"], false);
        assert!(v.get("completed_at_utc").is_none());
        live["lanes"]["166"]["native_after"]["InvocationID"] = json!("f".repeat(32));
        assert!(snapshot(&request, &live, mem["MemTotal"]).is_err());
    }
}
