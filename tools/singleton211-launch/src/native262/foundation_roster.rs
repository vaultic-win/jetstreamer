//! Bind the current Foundation cohort for epoch 262 funding. This command is read-only.
use super::*;

const FLEET_ROOT: &str = "/home/ubuntu/.codex/diagnostics";
const FLEET_PREFIX: &str = "horizon-foundation-seven-lane-v";
const REPLAY_BOOKING: (&str, &str) = (
    "/var/lib/jetstreamer/horizon262-native-bootstrap-build-v1/cold-fit-v342.json",
    "9ff35b7b5902e65b23bf2e862692cce959948183fefd42537e2a9fa63107f36c",
);
const OWNER_FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Result,Job,Restart,KillMode,Delegate,ControlGroup,MemoryMax,MemorySwapMax,ExecStart,AllowedCPUs";
const GUARD_FIELDS: &str =
    "Id,LoadState,ActiveState,SubState,InvocationID,Unit,MemoryMax,ExecStart";
const KNOWN_GUARDS: [(u64, &str); 5] = [
    (226, "horizon-guard-226-checkpoint-continuation-extract-v3"),
    (230, "horizon-230-middle-protective-v1"),
    (252, "horizon-252-regional-singleton-protective-v1"),
    (261, "horizon-261-singleton-protective-v1"),
    (288, "horizon-288-full-shrink-debt-protective-v1"),
];
const AUXILIARY: [&str; 2] = [
    "foundation-226-original225-broker-v3.service",
    "foundation-public-audit-epoch148-256-cap1-v1.service",
];
const CADENCE_LOCK: &str =
    "/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock";
const STANDARD_GUARD: &str =
    "/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard";
const GUARD_288: &str = "/var/lib/jetstreamer/horizon288-shrink-debt-comparison-tools-v327/guard";
const GUARD_ENV_261: &str = "/var/lib/jetstreamer/horizon261-full-guard-v1/guard.env";

fn latest_completion() -> Result<Bound> {
    let mut latest = None;
    for entry in fs::read_dir(FLEET_ROOT)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(generation) = name
            .to_str()
            .and_then(|name| name.strip_prefix(FLEET_PREFIX))
        else {
            continue;
        };
        let Ok(generation) = generation.parse::<u64>() else {
            continue;
        };
        let completion = entry.path().join("completion.json");
        if completion.try_exists()? && latest.as_ref().is_none_or(|(last, _)| generation > *last) {
            latest = Some((generation, completion));
        }
    }
    let (_, path) = latest.context("Foundation cadence has no accepted fleet")?;
    Ok(Bound::new(&path, hash(&path)?))
}

fn fleet_roster<'a>(fleet: &'a Value, booking: &Value) -> Result<BTreeMap<u64, &'a Value>> {
    let rows = fleet["active"]
        .as_array()
        .context("Foundation active roster")?;
    let booked = booking["owners"]
        .as_object()
        .context("Foundation booked owners")?;
    let mut roster = BTreeMap::new();
    for row in rows {
        let epoch = num(row, "epoch")?;
        let owner = match (epoch, text(row, "phase")?) {
            (226, "private-held-extraction")
            | (230, "diagnostic-qualification")
            | (252 | 261 | 288, "replay") => &row["producer"],
            (257, "upload-readback") => &row["unit"],
            _ => bail!("unregistered Foundation peer {epoch}"),
        };
        let unit = text(owner, "Id")?;
        let previous = booked
            .get(unit)
            .context("unbooked Foundation fleet owner")?;
        ensure!(
            owner["InvocationID"] == previous["InvocationID"]
                && owner["MainPID"] == previous["MainPID"]
                && owner["ControlGroup"] == previous["ControlGroup"]
                && roster.insert(epoch, owner).is_none(),
            "Foundation owner changed or duplicated for epoch {epoch}"
        );
    }
    ensure!(
        roster.keys().copied().eq([226, 230, 252, 257, 261, 288]),
        "incomplete Foundation live roster"
    );
    let selected: BTreeSet<_> = roster
        .values()
        .map(|owner| text(owner, "Id"))
        .collect::<Result<_>>()?;
    ensure!(
        selected.len() == roster.len()
            && booked.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == selected.into_iter().chain(AUXILIARY).collect(),
        "missing or duplicate Foundation capacity booking"
    );
    Ok(roster)
}

fn listed_owners(n: &mut Native) -> Result<BTreeSet<String>> {
    let raw = n.run(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=running,activating",
            "--plain",
            "--no-legend",
            "--no-pager",
        ],
    )?;
    Ok(std::str::from_utf8(&raw)?
        .lines()
        .filter_map(|line| {
            let unit = line.split_whitespace().next()?;
            let scoped = ["horizon-", "foundation-", "archive-", "jetstreamer-"]
                .iter()
                .any(|prefix| unit.starts_with(prefix));
            (scoped
                && !KNOWN_GUARDS
                    .iter()
                    .any(|(_, guard)| unit == format!("{guard}.service")))
            .then(|| unit.to_owned())
        })
        .collect())
}

fn latest_guard_invocation(n: &Native, plan: &Value) -> Result<String> {
    let directory = Path::new(text(plan, "receipt_directory")?);
    trusted_parents(&directory.join("sample.json"))?;
    let mut latest = None;
    for entry in fs::read_dir(directory)? {
        n.check()?;
        let entry = entry?;
        let name = entry.file_name();
        let Some(iid) = name.to_str().and_then(|name| {
            name.strip_prefix("sample-")
                .and_then(|name| name.strip_suffix(".json"))
        }) else {
            continue;
        };
        if hex(iid, 32) && entry.file_type()?.is_file() {
            let candidate = (entry.metadata()?.modified()?, iid.to_owned());
            if latest.as_ref().is_none_or(|prior| candidate > *prior) {
                latest = Some(candidate);
            }
        }
    }
    Ok(latest.context("no completed Foundation guard sample")?.1)
}

fn guard_binding(
    n: &mut Native,
    epoch: u64,
    guard: &str,
    booking: &Value,
    owner: &Value,
    device: u64,
) -> Result<Value> {
    let proof = binding(&booking["sample"])?;
    let sample = proof.json()?;
    let guard_unit = format!("{guard}.service");
    let timer_unit = format!("{guard}.timer");
    let service = n.show_fields(&guard_unit, GUARD_FIELDS)?;
    let timer = n.show_fields(&timer_unit, GUARD_FIELDS)?;
    let plan = Bound::new(text(&sample, "plan")?, text(&sample, "plan_sha256")?);
    let body = plan.sealed()?;
    let command = text(&service, "ExecStart")?;
    // Systemd appends changing execution timestamps after the stable argument framing.
    let guard_pin = Bound::new(
        if epoch == 288 {
            GUARD_288
        } else {
            STANDARD_GUARD
        },
        text(&sample, "guard_sha256")?,
    );
    guard_pin.artifact()?;
    let plan_arg = if epoch == 261 {
        let env = n.show_fields(
            &guard_unit,
            "Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment",
        )?;
        ensure!(
            env["EnvironmentFiles"] == format!("{GUARD_ENV_261} (ignore_errors=no)")
                && ["Environment", "PassEnvironment", "UnsetEnvironment"]
                    .iter()
                    .all(|key| env[*key] == ""),
            "epoch 261 guard environment changed"
        );
        let path = Path::new(GUARD_ENV_261);
        let source = Bound::new(path, hash(path)?);
        trusted_parents(path)?;
        let bytes = source.bytes(true)?;
        ensure!(
            bytes == format!("HORIZON261_GUARD_PLAN_SHA256={}\n", plan.sha256).as_bytes(),
            "epoch 261 guard plan environment differs"
        );
        "${HORIZON261_GUARD_PLAN_SHA256}"
    } else {
        &plan.sha256
    };
    let expected = format!(
        "{{ path={} ; argv[]={0} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no",
        guard_pin.path.display(),
        plan.path.display(),
        plan_arg,
        guard_pin.sha256
    );
    ensure!(
        service["Id"] == guard_unit
            && service["LoadState"] == "loaded"
            && service["MemoryMax"] == "1073741824"
            && periodic::stable_command(command)? == expected
            && timer["Id"] == timer_unit
            && timer["LoadState"] == "loaded"
            && timer["ActiveState"] == "active"
            && timer["Unit"] == guard_unit
            && hex(text(&timer, "InvocationID")?, 32),
        "Foundation peer guard or timer changed: {guard}"
    );
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["producer_invocation_id"] == owner["InvocationID"]
            && sample["producer"]["pid"].as_u64() == Some(text(owner, "MainPID")?.parse()?)
            && sample["producer"]["cgroup"] == owner["ControlGroup"]
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && body["unit"] == owner["Id"]
            && body["invocation_id"] == owner["InvocationID"]
            && body["minimum_free_bytes"] == booking["floor_bytes"]
            && body["maximum_root_physical_bytes"] == booking["cap_bytes"]
            && fs::metadata(text(&body, "filesystem")?)?.dev() == device,
        "Foundation guard plan differs from booked peer {guard}"
    );
    let latest_iid = latest_guard_invocation(n, &body)?;
    let latest_proof = peer_window::guard_sample_ref(&body, &latest_iid)?;
    let latest =
        peer_window::validate_guard_sample(&latest_proof, &plan, &guard_pin, &body, &latest_iid)?;
    ensure!(
        latest["producer"] == sample["producer"],
        "Foundation guard changed producer identity: {guard}"
    );
    Ok(
        json!({"unit":guard_unit,"timer":timer_unit,"timer_invocation_id":timer["InvocationID"],
        "plan":plan,"executable":guard_pin,"retained_guard_sample":proof,"latest_guard_sample":latest_proof,
        "minimum_free_bytes":body["minimum_free_bytes"],"maximum_root_physical_bytes":body["maximum_root_physical_bytes"]}),
    )
}

fn receipt(n: &mut Native) -> Result<Value> {
    let completion = latest_completion()?;
    let done = completion.json()?;
    let fleet_ref = binding(&done["fleet"])?;
    let observer_ref = binding(&done["observer"])?;
    ensure!(
        fleet_ref.path == completion.path.with_file_name("fleet.json"),
        "Foundation fleet path"
    );
    let fleet = fleet_ref.json()?;
    let observer = observer_ref.json()?;
    fresh(num(&fleet, "recorded_unix_seconds")?, now()?, 1800)?;
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 201
            && fleet["last_epoch"] == 300
            && fleet["inventory"]["anomalies"] == 0
            && fleet["observer_receipt"] == json!(observer_ref.path)
            && fleet["observer_sha256"] == observer_ref.sha256
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"],
        "Foundation fleet and observation differ"
    );
    let booking_ref = Bound::new(REPLAY_BOOKING.0, REPLAY_BOOKING.1);
    let booking = booking_ref.sealed()?;
    let roster = fleet_roster(&fleet, &booking)?;
    let expected: BTreeSet<String> = booking["owners"]
        .as_object()
        .context("booked owners")?
        .keys()
        .cloned()
        .collect();
    let before = listed_owners(n)?;
    ensure!(
        before == expected,
        "unaccounted or missing Foundation owners: {:?}",
        before.symmetric_difference(&expected).collect::<Vec<_>>()
    );
    let device = fs::metadata(FILESYSTEM)?.dev();
    ensure!(
        fs::metadata(text(&observer["filesystem"], "path")?)?.dev() == device,
        "Foundation filesystem changed"
    );
    let mut recorded = BTreeMap::new();
    for unit in &before {
        let owner = n.show_fields(unit, OWNER_FIELDS)?;
        let recorded_owner = &booking["owners"][unit];
        for field in [
            "MainPID",
            "InvocationID",
            "ControlGroup",
            "AllowedCPUs",
            "MemoryMax",
        ] {
            ensure!(
                owner[field] == recorded_owner[field] && !owner[field].is_null(),
                "booked owner {unit} changed {field}"
            );
        }
        if let Some(prior) = roster.values().find(|prior| prior["Id"] == *unit) {
            live::same_owner(prior, &owner)?;
        }
        let cap = text(&owner, "MemoryMax")?.parse()?;
        let memory = live::finite_owner(&owner, unit, text(&owner, "InvocationID")?, cap)?;
        let process_start_ticks = process_ticks(text(&owner, "MainPID")?.parse()?)?;
        recorded.insert(unit.clone(), (owner, memory, process_start_ticks));
    }
    let mut guards = BTreeMap::new();
    for (epoch, guard) in KNOWN_GUARDS {
        let unit = text(roster[&epoch], "Id")?;
        guards.insert(
            epoch,
            guard_binding(
                n,
                epoch,
                guard,
                &booking["guard_growth"][epoch.to_string()],
                &recorded[unit].0,
                device,
            )?,
        );
    }
    for (unit, (owner, _, start_ticks)) in &recorded {
        let after = n.show_fields(unit, OWNER_FIELDS)?;
        live::same_owner(owner, &after)?;
        ensure!(
            owner["MemoryMax"] == after["MemoryMax"]
                && owner["AllowedCPUs"] == after["AllowedCPUs"]
                && *start_ticks == process_ticks(text(&after, "MainPID")?.parse()?)?,
            "owner cap, CPUs or process changed for {unit}"
        );
    }
    ensure!(
        listed_owners(n)? == before && latest_completion()? == completion,
        "Foundation cohort changed during roster binding"
    );
    for guard in guards.values() {
        let timer = n.show_fields(text(guard, "timer")?, "ActiveState,InvocationID,Unit")?;
        ensure!(
            timer["ActiveState"] == "active"
                && timer["InvocationID"] == guard["timer_invocation_id"]
                && timer["Unit"] == guard["unit"],
            "Foundation guard timer changed during roster binding"
        );
    }
    let on_host_owners: BTreeMap<_, _> = recorded
        .into_iter()
        .map(|(unit, (owner, memory, ticks))| {
            (
                unit,
                json!({"systemd":owner,"memory_current_bytes":memory,"process_start_ticks":ticks}),
            )
        })
        .collect();
    let mut evidence = json!({"schema":"foundation-epoch262-roster-binding-v1","epoch":EPOCH,
        "recorded_unix_seconds":now()?,"fleet":fleet_ref,"observer":observer_ref,
        "completion":completion,"booking":booking_ref,"filesystem_device":device,
        "owners":on_host_owners,"periodic_guards":guards,"admission_issued":false});
    deny_authority(&mut evidence);
    Ok(evidence)
}

pub fn run() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .context("provide a new Foundation roster evidence directory")?,
    );
    ensure!(
        args.next().is_none()
            && unsafe { libc::geteuid() } == 0
            && root.parent() == Some(Path::new(FILESYSTEM))
            && root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("horizon262-foundation-roster-")),
        "Foundation roster evidence directory scope"
    );
    trusted_parents(&root)?;
    let lock = File::open(CADENCE_LOCK)?;
    use std::os::fd::AsRawFd;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Foundation cadence lock is busy"
    );
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut native = Native {
        root,
        counter: 0,
        deadline: Some(capacity::add(mono()?, 60_000_000)?),
    };
    let result = receipt(&mut native);
    match result {
        Ok(evidence) => println!(
            "{}",
            serde_json::to_string(&save_json(&native.root, "roster.json", &evidence)?)?
        ),
        Err(error) => {
            save_json(
                &native.root,
                "failure.json",
                &json!({"error":format!("{error:#}"),"admission_issued":false}),
            )?;
            return Err(error);
        }
    }
    Ok(())
}
