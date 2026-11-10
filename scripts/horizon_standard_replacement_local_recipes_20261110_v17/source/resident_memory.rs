//! Existing resident allocations are realized portions of retained promises,
//! never new resource credits. No non-lane RSS is subtracted from promises.
use super::*;
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub observer: Bound,
    pub owners: Vec<Owner>,
    #[serde(default)]
    pub host_kernel_same_resident_basis: bool,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Owner {
    epoch: u64,
    unit: String,
    invocation_id: String,
    main_pid: u64,
    main_start_ticks: u64,
    admission: Bound,
    guard_protection: Bound,
    #[serde(default, rename = "DATA_guard_handoff")]
    data_guard_handoff: Option<Bound>,
}
type Census = BTreeMap<u64, (u64, u64)>;
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("resident integer {k}"))
}
fn text_field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("resident text {k}"))
}
fn sum(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values
        .into_iter()
        .try_fold(0u64, |a, b| a.checked_add(b).context("resident overflow"))
}
fn parse_time(v: &str) -> Result<u64> {
    let b = v.as_bytes();
    ensure!(
        b.len() == 20
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'Z',
        "resident observer UTC shape"
    );
    let d = |a: usize, z: usize| -> Result<u64> {
        ensure!(b[a..z].iter().all(u8::is_ascii_digit), "UTC digits");
        Ok(std::str::from_utf8(&b[a..z])?.parse()?)
    };
    let (y, m, day, h, min, sec) = (
        d(0, 4)?,
        d(5, 7)?,
        d(8, 10)?,
        d(11, 13)?,
        d(14, 16)?,
        d(17, 19)?,
    );
    ensure!(
        (2020..=2099).contains(&y) && (1..=12).contains(&m) && h < 24 && min < 60 && sec < 60,
        "UTC bounds"
    );
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let months = [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(day > 0 && day <= months[m as usize - 1], "UTC calendar");
    let mut days = 0;
    for a in 1970..y {
        days += if leap(a) { 366 } else { 365 };
    }
    days += months[..m as usize - 1].iter().sum::<u64>() + day - 1;
    Ok(days * 86400 + h * 3600 + min * 60 + sec)
}
fn census(v: &Value) -> Result<Census> {
    ensure!(
        v["census_stable"] == true && v.get("error") == Some(&Value::Null),
        "resident census incomplete/unstable"
    );
    let rows = v["processes"].as_array().context("resident process rows")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 75536,
        "resident census size"
    );
    let mut out = Census::new();
    for p in rows {
        let pid = n(p, "pid")?;
        let start = n(p, "start_ticks")?;
        ensure!(
            pid > 0 && start > 0 && out.insert(pid, (start, n(p, "rss_bytes")?)).is_none(),
            "resident duplicate/zero process identity"
        );
    }
    ensure!(
        sum(out.values().map(|(_, rss)| *rss))? == n(v, "aggregate_rss_bytes")?,
        "resident aggregate differs"
    );
    Ok(out)
}
fn identities(c: &Census) -> BTreeMap<u64, u64> {
    c.iter().map(|(p, (s, _))| (*p, *s)).collect()
}
fn kernel(host: &Value) -> Result<u64> {
    ensure!(host["status"] == "observed", "host resident unavailable");
    let c = host["kernel_components_bytes"]
        .as_object()
        .context("kernel components")?;
    ensure!(
        c.len() == 4,
        "kernel components must not include Slab children twice"
    );
    sum(["Slab", "KernelStack", "PageTables", "Percpu"]
        .iter()
        .map(|k| n(&host["kernel_components_bytes"], k))
        .collect::<Result<Vec<_>>>()?)
}
fn host_total(host: &Value) -> Result<(Census, u64)> {
    let c = census(&host["rss"])?;
    let total = sum([sum(c.values().map(|(_, r)| *r))?, kernel(host)?])?;
    Ok((c, total))
}
fn role(row: &Value, key: &str, o: &Owner) -> Result<Census> {
    let r = &row[key];
    let group = format!("/system.slice/{}", o.unit);
    ensure!(
        r["unit"] == o.unit
            && r["invocation_id"] == o.invocation_id
            && r["active_state"] == "active"
            && r["sub_state"] == "running"
            && r["restarts"] == 0
            && r["main_pid"] == o.main_pid
            && r["control_group"] == group,
        "resident owner/unit/source topology mismatch"
    );
    let c = census(&r["rss"])?;
    ensure!(
        c.get(&o.main_pid)
            .is_some_and(|(s, _)| *s == o.main_start_ticks),
        "resident main PID start does not match"
    );
    Ok(c)
}
fn row_census(row: &Value, suffix: &str, o: &Owner) -> Result<Census> {
    // This first qualified route supports the genuinely used identical
    // controller/producer unit. Other topologies require separate qualification.
    let c = role(row, &format!("controller_{suffix}"), o)?;
    let p = role(row, &format!("producer_{suffix}"), o)?;
    ensure!(
        identities(&c) == identities(&p),
        "duplicate role coverage differs"
    );
    let mut result = c;
    for (pid, (start, rss)) in p {
        let old = result.get_mut(&pid).context("role process disappeared")?;
        ensure!(old.0 == start, "role PID reused");
        old.1 = old.1.min(rss);
    }
    Ok(result)
}
fn matched(lane: &Census, host: &Census) -> Result<u64> {
    sum(lane
        .iter()
        .map(|(pid, (start, rss))| {
            let (hs, hr) = host
                .get(pid)
                .context("lane PID missing from same host census")?;
            ensure!(hs == start, "lane PID reused in host census");
            Ok((*rss).min(*hr))
        })
        .collect::<Result<Vec<_>>>()?)
}
fn owner_rows<'a>(
    fleet: &'a Value,
    request: &Request,
    candidate: Option<u64>,
) -> Result<Vec<&'a Value>> {
    ensure!(
        fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && fleet["owner"] == "/root"
            && fleet["primary_thread"] == THREAD
            && fleet["complete_projected_memory_bytes"] == MEMORY,
        "accepted complete fleet required"
    );
    ensure!(
        fleet["observer"] == serde_json::to_value(&request.observer)?,
        "resident observer differs from accepted fleet"
    );
    let mut rows = Vec::new();
    for key in ["actual_executing_replays", "actual_active_bootstraps"] {
        rows.extend(
            fleet[key]
                .as_array()
                .context("complete actual fleet owners")?
                .iter(),
        );
    }
    ensure!(
        !rows.is_empty()
            && rows.len() == request.owners.len()
            && rows.len() <= 7
            && (candidate.is_none() || rows.len() <= 6)
            && fleet["active_producer_count"] == rows.len(),
        "every live owner must be represented exactly once"
    );
    let (mut epochs, mut units, mut iids) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for o in &request.owners {
        ensure!(
            (166..=172).contains(&o.epoch)
                && candidate != Some(o.epoch)
                && epochs.insert(o.epoch)
                && units.insert(&o.unit)
                && iids.insert(&o.invocation_id)
                && unit_name(&o.unit, ".service")
                && lower_hex(&o.invocation_id, 32)
                && o.invocation_id.bytes().any(|b| b != b'0')
                && o.main_pid > 0
                && o.main_start_ticks > 0,
            "resident duplicate, foreign or placeholder owner"
        );
        let r: Vec<_> = rows.iter().filter(|r| r["epoch"] == o.epoch).collect();
        ensure!(
            r.len() == 1,
            "resident owner absent or duplicate in actual fleet"
        );
        let r = r[0];
        let unit = &r["unit"];
        ensure!(
            unit["Id"] == o.unit
                && unit["InvocationID"] == o.invocation_id
                && unit["MainPID"].as_str().and_then(|p| p.parse::<u64>().ok()) == Some(o.main_pid)
                && unit["ControlPID"] == "0"
                && unit["NRestarts"] == "0"
                && unit["ActiveState"] == "active"
                && unit["SubState"] == "running"
                && r["in_current_observer"] == true
                && r["admission"] == serde_json::to_value(&o.admission)?
                && r["guard_protection"] == serde_json::to_value(&o.guard_protection)?
                && match &o.data_guard_handoff {
                    Some(handoff) => r["DATA_guard_handoff"] == serde_json::to_value(handoff)?,
                    None => r.get("DATA_guard_handoff").is_none_or(Value::is_null),
                },
            "resident owner is stale, absent from sample, or bound to different admission/protection"
        );
    }
    Ok(rows)
}
fn checked(
    request: &Request,
    candidate: u64,
    fleet: &Value,
    observer: &Value,
    current: &Value,
    mem: &BTreeMap<String, u64>,
    at: u64,
) -> Result<Value> {
    let _ = owner_rows(fleet, request, Some(candidate))?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "coordinated v2 observer required"
    );
    let clock = parse_time(text_field(observer, "completed_at_utc")?)?;
    ensure!(
        clock <= at && at - clock <= 1800,
        "resident observer stale/future"
    );
    let fleet_clock = n(fleet, "recorded_unix_seconds")?;
    ensure!(
        clock <= fleet_clock && fleet_clock <= at && at - fleet_clock <= 1800,
        "accepted fleet/observer clocks differ"
    );
    let obs_rows = observer["replays"]
        .as_array()
        .context("ordinary observer lanes")?;
    ensure!(
        obs_rows.len() == request.owners.len(),
        "owner set changed or missing coordinated lane"
    );
    // Diagnostics and non-lane work remain host overhead. They cannot earn
    // subtraction from one of the seven standard68GiB actor promises.
    let host_first = host_total(&observer["host_resident_memory"]["before"])?;
    let host_last = host_total(&observer["host_resident_memory"]["after"])?;
    let current_first = host_total(&current["host_before"])?;
    let current_last = host_total(&current["host_after"])?;
    let mut all_processes = BTreeSet::new();
    let mut total_realized = 0;
    let mut lane_reports = Vec::new();
    for o in &request.owners {
        let matches: Vec<_> = obs_rows
            .iter()
            .filter(|r| {
                r["range"].as_str().and_then(|v| v.parse::<u64>().ok()) == Some(o.epoch)
                    || r["range"] == format!("{}-{}", o.epoch, o.epoch)
            })
            .collect();
        ensure!(
            matches.len() == 1,
            "resident exact observer epoch claim required"
        );
        let row = matches[0];
        ensure!(
            row["invocation_binding_stable"] == true,
            "unstable source invocation"
        );
        let sb = row_census(row, "before", o)?;
        let sa = row_census(row, "after", o)?;
        ensure!(
            identities(&sb) == identities(&sa),
            "observed lane census changed"
        );
        let live = &current["lanes"][o.epoch.to_string()];
        let cb = row_census(live, "before", o)?;
        let ca = row_census(live, "after", o)?;
        ensure!(
            identities(&sb) == identities(&cb) && identities(&sb) == identities(&ca),
            "current PID reuse/new worker/source topology differs"
        );
        let worker_before = n(&row["worker_before"], "pid")?;
        let worker_after = n(&row["worker_after"], "pid")?;
        ensure!(
            worker_before == worker_after
                && worker_after != o.main_pid
                && sb.len() == 2
                && sb.contains_key(&worker_after),
            "resident route requires exact parent plus one stable worker"
        );
        for (pid, (start, _)) in &sb {
            ensure!(
                all_processes.insert((*pid, *start)),
                "a process is claimed by two lanes"
            );
        }
        for suffix in ["before", "after"] {
            let native = &live[format!("native_{suffix}")];
            ensure!(
                native["Id"] == o.unit
                    && native["InvocationID"] == o.invocation_id
                    && native["MainPID"]
                        .as_str()
                        .and_then(|v| v.parse::<u64>().ok())
                        == Some(o.main_pid)
                    && native["NRestarts"] == "0"
                    && native["ActiveState"] == "active"
                    && native["SubState"] == "running"
                    && native["ControlGroup"] == format!("/system.slice/{}", o.unit)
                    && native["MemoryMax"] == "73014444032"
                    && native["MemorySwapMax"] == "0"
                    && native["LoadState"] == "loaded"
                    && native["ControlPID"] == "0"
                    && native["Job"] == "",
                "current exact native producer/cgroup/hard limit changed"
            );
        }
        for key in ["max", "oom", "oom_kill"] {
            let field = format!("memory_events.{key}");
            ensure!(
                row["producer_cgroup_counter_delta"][&field] == 0,
                "sample contains new hard-limit/OOM events"
            );
            let baseline = n(&row["producer_after"]["cgroup"]["counters"], &field)?;
            for suffix in ["before", "after"] {
                ensure!(
                    n(&live[format!("producer_{suffix}")]["memory_events"], key)? == baseline,
                    "new hard-limit/OOM event since accepted sample"
                );
            }
        }
        let images = &live["process_images_before"];
        ensure!(
            images == &live["process_images_after"],
            "live executable topology changed during admission"
        );
        let spec = profile(o.epoch)?;
        for (pid, (start, _)) in &sb {
            let image = &images[pid.to_string()];
            let executable = text_field(image, "executable")?;
            ensure!(
                n(image, "pid")? == *pid && n(image, "start_ticks")? == *start,
                "running image PID/start differs from RSS"
            );
            if *pid == o.main_pid {
                ensure!(
                    image["sha256"] == NODE_SHA
                        && executable == format!("{}/jetstreamer-node", spec.package),
                    "current parent is not the exact qualified node"
                );
            } else {
                ensure!(
                    image["sha256"] == WORKER_SHA
                        && row["worker_before"]["executable"] == executable
                        && row["worker_after"]["executable"] == executable
                        && Path::new(executable).starts_with(spec.lane),
                    "worker source/executable topology differs"
                );
            }
        }
        let values = [
            matched(&sb, &host_first.0)?,
            matched(&sa, &host_last.0)?,
            matched(&cb, &current_first.0)?,
            matched(&ca, &current_last.0)?,
            n(&row["producer_before"], "memory_current_bytes")?,
            n(&row["producer_after"], "memory_current_bytes")?,
            n(&live["producer_before"], "memory_current_bytes")?,
            n(&live["producer_after"], "memory_current_bytes")?,
            73_014_444_032,
        ];
        let realized = *values.iter().min().context("resident clamp")?;
        ensure!(realized > 0, "no positive qualified resident lower bound");
        total_realized = sum([total_realized, realized])?;
        lane_reports.push(json!({"epoch":o.epoch,"unit":o.unit,"invocation_id":o.invocation_id,"process_identities":identities(&sb),"all_endpoint_and_hard_cap_clamps_bytes":values,"realized_portion_of_retained68GiB_promise_bytes":realized}));
    }
    let total = *mem.get("MemTotal").context("fresh MemTotal")?;
    let available = *mem.get("MemAvailable").context("fresh MemAvailable")?;
    ensure!(
        n(&observer["host_memory"], "total_kib")?.checked_mul(1024) == Some(total),
        "observer/current host memory differs"
    );
    let resident = [host_first.1, host_last.1, current_first.1, current_last.1]
        .into_iter()
        .max()
        .context("host resident endpoints")?;
    let mut host_fulfillment = json!({"realized_host_component_bytes":0});
    if request.host_kernel_same_resident_basis {
        let proof = host_fulfillment::provenance()?;
        host_fulfillment = host_fulfillment::fulfilled(
            &[
                &observer["host_resident_memory"]["before"],
                &observer["host_resident_memory"]["after"],
                &current["host_before"],
                &current["host_after"],
            ],
            host_fulfillment::HOST_BUDGET,
        )?;
        host_fulfillment::same_identity(&proof)?;
        host_fulfillment["provenance"] = proof;
    }
    let point = host_fulfillment::point(
        total,
        available,
        resident,
        total_realized,
        n(&host_fulfillment, "realized_host_component_bytes")?,
    )?;
    ensure!(
        point["fits"] == true,
        "complete retained future growth plus reserve fails independent resident/MemAvailable fit; diagnostic_only_point={point}"
    );
    let future = n(&point, "remaining_future_growth_bytes")?;
    let required = n(&point, "required_available_bytes")?;
    let projected = n(&point, "resident_plus_future_and_reserve_bytes")?;
    Ok(
        json!({"mode":"invocation-matched-realized-resident-portions-v1","observer":request.observer,"complete_projected_memory_bytes":MEMORY,"realized_resident_bytes_subtracted_from_future_growth":total_realized,"complete_remaining_future_growth_bytes":future,"required_available_bytes":required,"fresh_MemAvailable_bytes":available,"host_resident_planning_upper_bytes":resident,"host_resident_plus_all_remaining_promises_and_reserve_bytes":projected,"fresh_MemTotal_bytes":total,"lanes":lane_reports,"non_lane_resident_credit_bytes":0,"host_component_realization":host_fulfillment,"independent_fit_point":point,"non_lane_and_kernel_still_charged_in_host_resident_bytes":true,"shared_role_processes_counted_once":true,"resource_credit_bytes":0,"promise_ending_bytes":0,"hard_memory_limits_changed":false,"memory_selected_target_changed":false}),
    )
}
fn native_complete(unit: &str) -> Result<Value> {
    let output=Command::new("/usr/bin/systemctl").args(["show",unit,"-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,ControlGroup,MemoryMax,MemorySwapMax,Job"]).output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty() && output.stdout.len() <= 65536,
        "current native resident owner query failed"
    );
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native resident field")?;
        ensure!(
            fields.insert(k, v).is_none(),
            "duplicate native resident field"
        );
    }
    Ok(serde_json::to_value(fields)?)
}
fn sample_role(o: &Owner, native: &Value) -> Result<Value> {
    ensure!(
        native["ControlGroup"] == format!("/system.slice/{}", o.unit)
            && native["InvocationID"] == o.invocation_id
            && native["MainPID"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                == Some(o.main_pid),
        "resident owner native binding changed before capture"
    );
    let group = PathBuf::from(text_field(native, "ControlGroup")?);
    let cg = Path::new("/sys/fs/cgroup").join(group.strip_prefix("/")?);
    let _ = directory(&cg)?;
    let current = fs::read_to_string(cg.join("memory.current"))?
        .trim()
        .parse::<u64>()?;
    let mut events = BTreeMap::new();
    for line in fs::read_to_string(cg.join("memory.events"))?.lines() {
        let mut fields = line.split_whitespace();
        let key = fields.next().context("memory event key")?;
        let value = fields
            .next()
            .context("memory event value")?
            .parse::<u64>()?;
        ensure!(
            fields.next().is_none() && events.insert(key.to_string(), value).is_none(),
            "memory event duplicate/shape"
        );
    }
    let rss = resident_capture::capture(&cg, &group);
    ensure!(
        rss.stable_process_start_ticks(o.main_pid)? == o.main_start_ticks,
        "current main PID reused"
    );
    Ok(
        json!({"unit":o.unit,"invocation_id":o.invocation_id,"active_state":native["ActiveState"],"sub_state":native["SubState"],"restarts":native["NRestarts"].as_str().context("restarts")?.parse::<u64>()?,"main_pid":o.main_pid,"control_group":group,"memory_current_bytes":current,"memory_events":events,"rss":rss}),
    )
}
fn peer_admissions(request: &Request, fleet: &Value) -> Result<()> {
    for o in &request.owners {
        let s = profile(o.epoch)?;
        let a = bound(&o.admission)?;
        let protection = bound(&o.guard_protection)?;
        ensure!(
            a["schema"] == "horizon-standard-replacement-admission-v1"
                && a["owner"] == "/root"
                && a["primary_thread"] == THREAD
                && a["epoch"] == o.epoch
                && a["producer_unit"] == o.unit
                && a["producer_invocation_id"] == o.invocation_id
                && a["producer_pid"] == o.main_pid
                && a["fresh_admission_passed"] == true
                && a["all_prior_promises_retained"] == true
                && a["candidate_hard_memory_bytes"] == 73_014_444_032u64
                && a["resource_credit_bytes"] == 0
                && a["memory_or_DATA_promise_ending_bytes"] == 0,
            "peer has no genuine retained68GiB admission"
        );
        ensure!(
            protection["schema"] == "horizon-standard-live-peer-protection-v1"
                && protection["epoch"] == o.epoch
                && protection["producer_unit"] == o.unit
                && protection["producer_invocation_id"] == o.invocation_id
                && protection["admission"] == serde_json::to_value(&o.admission)?,
            "peer protection binding differs"
        );
        let guard: Bound = serde_json::from_value(protection["plan"].clone())?;
        let gp = bound(&guard)?;
        ensure!(
            gp["unit"] == o.unit
                && gp["invocation_id"] == o.invocation_id
                && gp["worker_root"] == s.lane
                && gp["minimum_free_bytes"] == FLOOR
                && gp["maximum_root_physical_bytes"] == ROOT_CAP
                && gp["maximum_worker_vmas"] == 3500000,
            "peer protection/floor/profile differs"
        );
        if let Some(handoff) = &o.data_guard_handoff {
            let row = ["actual_executing_replays", "actual_active_bootstraps"]
                .into_iter()
                .flat_map(|k| fleet[k].as_array().into_iter().flatten())
                .find(|r| r["epoch"] == o.epoch)
                .context("DATA peer source start row")?;
            data_admission::peer_handoff(
                handoff,
                &o.guard_protection,
                o.epoch,
                &o.unit,
                &o.invocation_id,
                o.main_pid,
                n(row, "source_start_unix_seconds")?,
            )?;
        }
    }
    Ok(())
}
/// Complete owner reconciliation is separate from candidate exclusion. No historical guard
/// proof is overwritten; every live peer must have the same real successor registration.
pub(super) fn data_handoffs(
    request: &Request,
    fleet: &Value,
    candidate: u64,
    registration: &Value,
    contract: &Value,
) -> Result<Value> {
    let rows = owner_rows(fleet, request, Some(candidate))?;
    ensure!(
        request.owners.len() <= 6,
        "a disjoint local2 candidate can have at most six original-slot peers"
    );
    let mut captures = Vec::new();
    for o in &request.owners {
        let row = rows
            .iter()
            .find(|r| r["epoch"] == o.epoch)
            .context("DATA complete peer row")?;
        let handoff = o
            .data_guard_handoff
            .as_ref()
            .context("every live peer needs genuine continuous DATA guard handoff")?;
        let start = n(row, "source_start_unix_seconds")?;
        let accepted = data_admission::peer_handoff(
            handoff,
            &o.guard_protection,
            o.epoch,
            &o.unit,
            &o.invocation_id,
            o.main_pid,
            start,
        )?;
        ensure!(
            accepted.handoff["registration"] == *registration
                && accepted.plan["data_fulfillment"] == *contract,
            "live peer uses different runtime/contract registration"
        );
        let capture = data_admission::current_guard(
            &accepted,
            &o.guard_protection,
            o.epoch,
            &o.unit,
            &o.invocation_id,
            o.main_pid,
            o.main_start_ticks,
            start,
        )?;
        captures.push(json!({"epoch":o.epoch,"original_guard_protection":o.guard_protection,"DATA_guard_handoff":handoff,"current_guard_capture":capture}));
    }
    Ok(json!(captures))
}
fn process_images(o: &Owner, row: &Value) -> Result<Value> {
    let worker = n(&row["worker_after"], "pid")?;
    ensure!(
        worker > 0 && worker != o.main_pid,
        "exact current worker PID required"
    );
    let ticks = |pid: u64| -> Result<u64> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        ensure!(
            stat.split_whitespace().next() == Some(pid.to_string().as_str()),
            "stat PID differs"
        );
        Ok(stat
            .rsplit_once(')')
            .context("stat comm")?
            .1
            .split_whitespace()
            .nth(19)
            .context("process start ticks")?
            .parse()?)
    };
    let mut images = BTreeMap::new();
    for pid in [o.main_pid, worker] {
        let start = ticks(pid)?;
        let proc = PathBuf::from(format!("/proc/{pid}/exe"));
        let executable = fs::read_link(&proc)?;
        let mut f = File::open(&proc)?;
        let metadata = f.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() > 0 && metadata.len() <= 64 << 20,
            "bounded running executable required"
        );
        let mut sha = Sha256::new();
        let mut buf = [0u8; 128 * 1024];
        let mut bytes = 0u64;
        loop {
            let len = f.read(&mut buf)?;
            if len == 0 {
                break;
            }
            bytes = bytes
                .checked_add(len as u64)
                .context("executable bytes overflow")?;
            ensure!(bytes <= metadata.len(), "running executable grew");
            sha.update(&buf[..len]);
        }
        ensure!(
            bytes == metadata.len()
                && identity(&metadata) == identity(&f.metadata()?)
                && identity(&metadata) == identity(&fs::symlink_metadata(&executable)?)
                && fs::read_link(&proc)? == executable
                && ticks(pid)? == start,
            "running executable changed during exact hash"
        );
        images.insert(pid.to_string(),json!({"pid":pid,"start_ticks":start,"executable":executable,"sha256":format!("{:x}",sha.finalize()),"inode_identity":identity(&metadata)}));
    }
    Ok(serde_json::to_value(images)?)
}
pub(super) fn fresh(
    request: &Request,
    p: &Plan,
    fleet: &Value,
    mem: &BTreeMap<String, u64>,
    at: u64,
) -> Result<Value> {
    let _ = owner_rows(fleet, request, Some(p.epoch))?;
    peer_admissions(request, fleet)?;
    let observer = bound(&request.observer)?;
    let mut live = BTreeMap::new();
    let host_before = resident_capture::host_resident();
    for o in &request.owners {
        let row = observer["replays"]
            .as_array()
            .context("observer rows")?
            .iter()
            .find(|r| {
                r["range"].as_str().and_then(|v| v.parse::<u64>().ok()) == Some(o.epoch)
                    || r["range"] == format!("{}-{}", o.epoch, o.epoch)
            })
            .context("exact peer observer row")?;
        let native = native_complete(&o.unit)?;
        let role = sample_role(o, &native)?;
        let images = process_images(o, row)?;
        live.insert(o.epoch.to_string(),json!({"native_before":native,"controller_before":role,"producer_before":role,"process_images_before":images}));
    }
    for o in &request.owners {
        let source = observer["replays"]
            .as_array()
            .context("observer rows")?
            .iter()
            .find(|r| {
                r["range"].as_str().and_then(|v| v.parse::<u64>().ok()) == Some(o.epoch)
                    || r["range"] == format!("{}-{}", o.epoch, o.epoch)
            })
            .context("exact peer observer row")?;
        let native = native_complete(&o.unit)?;
        let role = sample_role(o, &native)?;
        let images = process_images(o, source)?;
        let row = live
            .get_mut(&o.epoch.to_string())
            .context("current lane capture")?;
        row["native_after"] = native;
        row["controller_after"] = role.clone();
        row["producer_after"] = role;
        row["process_images_after"] = images;
    }
    let host_after = resident_capture::host_resident();
    let current = json!({"host_before":host_before,"host_after":host_after,"lanes":live});
    let mut final_mem = mem.clone();
    let mut endpoint = BTreeMap::new();
    for line in fs::read_to_string("/proc/meminfo")?.lines() {
        let (k, v) = line.split_once(':').context("final meminfo")?;
        if matches!(k, "MemTotal" | "MemAvailable") {
            let mut fields = v.split_whitespace();
            let bytes = fields
                .next()
                .context("final memory value")?
                .parse::<u64>()?
                .checked_mul(1024)
                .context("final memory overflow")?;
            ensure!(
                fields.next() == Some("kB") && fields.next().is_none(),
                "final memory units"
            );
            endpoint.insert(k.to_string(), bytes);
        }
    }
    ensure!(
        endpoint.get("MemTotal") == mem.get("MemTotal"),
        "memory host changed within admission"
    );
    let available = mem
        .get("MemAvailable")
        .context("initial available")?
        .min(endpoint.get("MemAvailable").context("final available")?);
    final_mem.insert("MemAvailable".into(), *available);
    let finished = now()?;
    ensure!(finished >= at, "admission clock reversed");
    let result = checked(
        request, p.epoch, fleet, &observer, &current, &final_mem, finished,
    )?;
    Ok(
        json!({"qualified_accounting":result,"fresh_admission_transaction_capture":current,"new_routine_observer_sample":false,"new_polling_loop":false}),
    )
}
#[cfg(test)]
#[path = "resident_memory_tests.rs"]
mod tests;
