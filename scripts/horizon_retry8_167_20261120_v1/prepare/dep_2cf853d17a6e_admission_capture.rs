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
pub(super) fn endpoint(o: &Owner) -> Result<(Value, Value, Value)> {
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
// Report only bounded error metadata; never serialize a full host census on failure.
fn diagnostic_field(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.chars().take(1024).collect(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Null) => "null".into(),
        None => "missing".into(),
        _ => "non-scalar".into(),
    }
}
fn host_diagnostic(host: &Value) -> String {
    let attempts: Vec<String> = host["discarded_attempt_errors"]
        .as_array()
        .into_iter()
        .flatten()
        .take(3)
        .map(|v| {
            v.as_str()
                .unwrap_or("non-string")
                .chars()
                .take(400)
                .collect()
        })
        .collect();
    format!(
        "status={}; error={}; census_attempts={}; discarded_attempt_errors={attempts:?}; rss_stable={}; rss_error={}",
        diagnostic_field(host, "status"),
        diagnostic_field(host, "error"),
        diagnostic_field(host, "census_attempts"),
        diagnostic_field(&host["rss"], "census_stable"),
        diagnostic_field(&host["rss"], "error")
    )
}
fn require_host_capture(host: &Value, endpoint: &str) -> Result<()> {
    host_total(host)
        .map(|_| ())
        .with_context(|| format!("admission {endpoint}: {}", host_diagnostic(host)))
}
fn transaction(request: &Request) -> Result<Value> {
    let started = now()?;
    let terminal166_before = request
        .terminal166
        .as_ref()
        .map(terminal166::endpoint)
        .transpose()?;
    let terminal167_before = request
        .terminal167
        .as_ref()
        .map(terminal167::endpoint)
        .transpose()?;
    let before = resident_capture::host_resident();
    require_host_capture(&before, "host_before")?;
    let mut lanes = BTreeMap::new();
    for o in &request.owners {
        let (native, role, images) =
            endpoint(o).with_context(|| format!("admission peer {} {} before", o.epoch, o.unit))?;
        lanes.insert(o.epoch.to_string(),json!({"native_before":native,"controller_before":role,"producer_before":role,"process_images_before":images}));
    }
    for o in &request.owners {
        let (native, role, images) =
            endpoint(o).with_context(|| format!("admission peer {} {} after", o.epoch, o.unit))?;
        let row = lanes
            .get_mut(&o.epoch.to_string())
            .context("peer missing")?;
        row["native_after"] = native;
        row["controller_after"] = role.clone();
        row["producer_after"] = role;
        row["process_images_after"] = images;
    }
    let after = resident_capture::host_resident();
    require_host_capture(&after, "host_after")?;
    let terminal166_after = request
        .terminal166
        .as_ref()
        .map(terminal166::endpoint)
        .transpose()?;
    terminal166::equal_endpoints(&terminal166_before, &terminal166_after)?;
    let terminal167_after = request
        .terminal167
        .as_ref()
        .map(terminal167::endpoint)
        .transpose()?;
    ensure!(
        terminal167_before == terminal167_after,
        "terminal167 changed across resident transaction"
    );
    let finished = now()?;
    ensure!(
        started <= finished && finished - started <= 120,
        "bounded admission capture expired"
    );
    Ok(
        json!({"started_unix_seconds":started,"completed_unix_seconds":finished,"host_before":before,"host_after":after,"lanes":lanes,"terminal166_before":terminal166_before,"terminal166_after":terminal166_after,"terminal167_before":terminal167_before,"terminal167_after":terminal167_after}),
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
pub(super) fn peer_guards(request: &Request) -> Result<()> {
    for o in &request.owners {
        let proof = bound(&o.guard_protection)?;
        let timer = text_field(&proof, "timer_unit")?;
        ensure!(
            timer
                == if o.epoch == 166 && o.unit == retry167::NEW_PEER_UNIT {
                    "horizon-guard-independent-cold166-20261120-v1.timer".to_string()
                } else {
                    format!(
                        "horizon-guard-replacement-{}-{}-20261110-v1.timer",
                        o.epoch,
                        qualified_peer_attempt(o.epoch, &o.unit)?
                    )
                },
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
    let first = transaction(request).context("first admission transaction")?;
    let middle = memory_endpoint()?;
    let current = transaction(request).context("second admission transaction")?;
    let final_mem = memory_endpoint()?;
    if request.terminal166.is_some() {
        terminal166::cross_transactions(&first, &current)?;
    }
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
    let observed = snapshot(request, &first, total).context("first admission snapshot")?;
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
    )
    .context("cross-transaction resident admission")?;
    peer_admissions(request)?;
    peer_guards(request)?;
    // Close the final meminfo/fit/protection interval too, after both transactions.
    let terminal166_final = request
        .terminal166
        .as_ref()
        .map(terminal166::endpoint)
        .transpose()?;
    ensure!(
        current["terminal166_after"] == serde_json::to_value(&terminal166_final)?,
        "terminal166 changed after final resident transaction"
    );
    let completed = now()?;
    ensure!(
        at <= completed && completed - at <= 120,
        "final admission closure expired"
    );
    Ok(
        json!({"terminal166_before":first["terminal166_before"],"terminal166_after":terminal166_final,"qualified_accounting":result,"admission_only_snapshot":observed,"first_native_admission_transaction":first,"fresh_admission_transaction_capture":current,"native_identity":own,"previous_routine_observer":request.observer,"previous_routine_observer_used_for_new_peer_realization":false,"new_routine_observer_sample":false,"new_polling_loop":false,"resource_credit_bytes":0,"promise_ending_bytes":0}),
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

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn unavailable_host_keeps_original_error_endpoint_and_attempts() {
        let host = json!({"status":"unavailable","error":"PID 4321 disappeared",
            "census_attempts":3,"discarded_attempt_errors":["membership changed","PID 4321 disappeared"]});
        let error = format!(
            "{:#}",
            require_host_capture(&host, "host_before").unwrap_err()
        );
        for expected in [
            "host_before",
            "unavailable",
            "PID 4321 disappeared",
            "census_attempts=3",
            "membership changed",
            "resident census incomplete/unstable",
        ] {
            assert!(error.contains(expected), "{error}");
        }
    }
    #[test]
    fn stable_fixture_still_passes_without_data_mutation() {
        let (_, _, _, live, _, _) = super::super::tests::fixture();
        let before = live["host_before"].clone();
        require_host_capture(&before, "host_before").unwrap();
        assert_eq!(before, live["host_before"]);
    }
    #[test]
    fn missing_or_nonnull_rss_error_never_becomes_success() {
        let (_, _, _, live, _, _) = super::super::tests::fixture();
        for error in [None, Some(json!("unreadable")), Some(json!(false))] {
            let mut host = live["host_before"].clone();
            host["rss"].as_object_mut().unwrap().remove("error");
            if let Some(error) = error {
                host["rss"]["error"] = error;
            }
            assert!(require_host_capture(&host, "host_after").is_err());
        }
    }
    #[test]
    fn observed_label_does_not_admit_unstable_or_inconsistent_census() {
        let (_, _, _, live, _, _) = super::super::tests::fixture();
        let mut host = live["host_before"].clone();
        host["rss"]["census_stable"] = json!(false);
        assert!(require_host_capture(&host, "host_after").is_err());
        host = live["host_before"].clone();
        host["rss"]["aggregate_rss_bytes"] = json!(u64::MAX);
        assert!(require_host_capture(&host, "host_after").is_err());
    }
    #[test]
    fn missing_kernel_accounting_is_still_rejected() {
        let (_, _, _, live, _, _) = super::super::tests::fixture();
        let mut host = live["host_before"].clone();
        host.as_object_mut()
            .unwrap()
            .remove("kernel_components_bytes");
        assert!(require_host_capture(&host, "host_after").is_err());
    }
    #[test]
    fn diagnostics_bound_unicode_and_exclude_large_process_census() {
        let host = json!({"status":"unavailable","error":"é".repeat(10000),
            "census_attempts":3,"discarded_attempt_errors":vec!["x".repeat(10000);10],
            "rss":{"census_stable":false,"error":"z".repeat(10000),"processes":"SECRET_PROCESS_ROWS"}});
        let diagnostic = host_diagnostic(&host);
        assert!(diagnostic.len() < 6000);
        assert!(!diagnostic.contains("SECRET_PROCESS_ROWS"));
        assert_eq!(diagnostic_field(&json!({}), "error"), "missing");
        assert_eq!(diagnostic_field(&json!({"error":null}), "error"), "null");
    }
}
