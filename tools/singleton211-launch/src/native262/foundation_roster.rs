//! Bind the current Foundation cohort for epoch 262 funding and guard qualification.
use super::*;
mod allocation;

const FLEET_ROOT: &str = "/home/ubuntu/.codex/diagnostics";
const FLEET_PREFIX: &str = "horizon-foundation-seven-lane-v";
const REPLAY_BOOKING: (&str, &str) = (
    "/var/lib/jetstreamer/horizon262-native-bootstrap-build-v1/cold-fit-v342.json",
    "9ff35b7b5902e65b23bf2e862692cce959948183fefd42537e2a9fa63107f36c",
);
const DELIVERY_BOOKING: (&str, &str) = (
    "/var/lib/jetstreamer/horizon257-current-reader-delivery-v2/booking.json",
    "fe90d6ab3c352bf4f6f903457b16edb48c8a10d1a836941df5c8aa9544f51d13",
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
const FULL_REPLAY_INPUTS: (&str, &str) = (
    "/var/lib/jetstreamer/horizon262-full-node-b9b95b02-v1/replay-inputs.json",
    "4375f4e590dc98d3f37ba6c646fa2c93cc65680267c7c920ba5d3255b67661d2",
);
const SIZING_REFERENCE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-full-profile-v226-a1/profile.json",
    "6b27a27ff1596fe6688f207d460566c51d5c9552cef47817358d2008b484f281",
);

struct FullReplayQuote {
    reference: Bound,
    inputs: Bound,
    working_disk: u64,
    producer_memory: u64,
}

fn full_replay_quote() -> Result<FullReplayQuote> {
    let reference = Bound::new(SIZING_REFERENCE.0, SIZING_REFERENCE.1);
    let profile = reference.sealed()?;
    let inputs = Bound::new(FULL_REPLAY_INPUTS.0, FULL_REPLAY_INPUTS.1);
    let plan = inputs.sealed()?;
    let terminal = binding(&plan["native_bootstrap_terminal"])?.sealed()?;
    ensure!(
        plan["schema"] == "foundation-epoch262-full-replay-input-envelope-v1"
            && plan["epoch"] == EPOCH
            && plan["full_replay_admitted"] == false
            && terminal["epoch"] == EPOCH
            && terminal["native_input_qualified"] == true
            && profile["unit"] == "horizon-qualify-261-singleton-v1.service",
        "epoch 262 full-replay quote inputs changed"
    );
    binding(&plan["replay_node"])?.artifact()?;
    Ok(FullReplayQuote {
        reference,
        inputs,
        working_disk: num(&profile, "maximum_root_physical_bytes")?,
        producer_memory: num(&profile, "maximum_memory_bytes")?,
    })
}

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
        "guard_command":expected,"producer":owner,
        "minimum_free_bytes":body["minimum_free_bytes"],"maximum_root_physical_bytes":body["maximum_root_physical_bytes"]}),
    )
}

pub(super) struct Controller<'a> {
    pub unit: &'a str,
    pub invocation: &'a str,
    pub held: bool,
}

impl Controller<'_> {
    fn check(&self, n: &mut Native) -> Result<Value> {
        ensure!(
            self.unit.starts_with("horizon-native262-controller-")
                && self.unit.ends_with(".service")
                && self
                    .unit
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
                && fs::read_to_string("/proc/self/cgroup")?.trim()
                    == format!("0::/system.slice/{}", self.unit),
            "capacity check is outside epoch 262's booked controller"
        );
        let row = n.show_fields(self.unit, &format!("{OWNER_FIELDS},Type"))?;
        ensure!(
            row["Type"] == "exec" && text(&row, "MainPID")?.parse::<u32>()? == std::process::id(),
            "epoch 262 capacity checker is not the booked main process"
        );
        live::finite_owner(&row, self.unit, self.invocation, CONTROLLER_MEMORY)?;
        Ok(row)
    }
}

fn held_owner(n: &mut Native) -> Result<(Value, u64)> {
    let held = n.show_fields(UNIT, OWNER_FIELDS)?;
    let iid = text(&held, "InvocationID")?;
    let pid = text(&held, "MainPID")?.parse()?;
    live::finite_owner(&held, UNIT, iid, MEMORY)?;
    gate::held_image(pid, iid, UNIT, HARNESS)?;
    Ok((held, process_ticks(pid)?))
}

pub(super) fn receipt(n: &mut Native, controller: Option<Controller<'_>>) -> Result<Value> {
    measure(n, controller, None)
}

fn measure(
    n: &mut Native,
    controller: Option<Controller<'_>>,
    quote: Option<FullReplayQuote>,
) -> Result<Value> {
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
    let missing: Vec<_> = fleet["inventory"]["entries"]
        .as_array()
        .context("Foundation inventory")?
        .iter()
        .filter(|row| row["epoch"] == EPOCH)
        .collect();
    ensure!(
        missing.len() == 1 && missing[0]["state"] == "missing",
        "epoch 262 inventory no longer missing"
    );
    let booked: BTreeSet<String> = booking["owners"]
        .as_object()
        .context("booked owners")?
        .keys()
        .cloned()
        .collect();
    let mut expected = booked.clone();
    let controller_owner = controller.as_ref().map(|c| c.check(n)).transpose()?;
    let held = if controller.as_ref().is_some_and(|c| c.held) {
        Some(held_owner(n)?)
    } else {
        None
    };
    if let Some(c) = &controller {
        ensure!(
            expected.insert(c.unit.to_owned()),
            "epoch 262 controller already booked as a peer"
        );
    }
    if held.is_some() {
        ensure!(
            expected.insert(UNIT.to_owned()),
            "epoch 262 held owner already booked as a peer"
        );
    }
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
    let mount = if quote.is_some() {
        ensure!(
            fs::metadata("/home/ubuntu/.jetstreamer-private")?.dev() == device,
            "epoch 262 full replay output filesystem changed"
        );
        Value::Null
    } else {
        pristine(device)?
    };
    let resources_before = live::resources_at(Path::new(FILESYSTEM))?;
    let cpus = units::affinity(&json!({"cpu_affinity":(40..48).collect::<Vec<_>>() }))?;
    let selected = units::parse_cpu_list("40-47")?;
    let mut recorded = BTreeMap::new();
    for unit in &booked {
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
        ensure!(
            selected.is_disjoint(&units::parse_cpu_list(text(&owner, "AllowedCPUs")?)?),
            "epoch 262 CPUs overlap {unit}"
        );
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
    let allocation = allocation::measure(n, &guards, device)?;
    for (unit, (owner, memory, start_ticks)) in &mut recorded {
        let after = n.show_fields(unit, OWNER_FIELDS)?;
        live::same_owner(owner, &after)?;
        ensure!(
            owner["MemoryMax"] == after["MemoryMax"]
                && owner["AllowedCPUs"] == after["AllowedCPUs"]
                && *start_ticks == process_ticks(text(&after, "MainPID")?.parse()?)?,
            "owner cap, CPUs or process changed for {unit}"
        );
        *memory = (*memory).min(live::finite_owner(
            &after,
            unit,
            text(owner, "InvocationID")?,
            text(owner, "MemoryMax")?.parse()?,
        )?);
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
    if let (Some(controller), Some(prior)) = (&controller, &controller_owner) {
        live::same_owner(prior, &controller.check(n)?)?;
    }
    if let Some((prior, start)) = &held {
        let (after, new_start) = held_owner(n)?;
        live::same_owner(prior, &after)?;
        ensure!(*start == new_start, "held epoch 262 process was replaced");
    }
    let resources_after = live::resources_at(Path::new(FILESYSTEM))?;
    ensure!(
        resources_before.0 == resources_after.0
            && if quote.is_some() {
                fs::metadata("/home/ubuntu/.jetstreamer-private")?.dev() == device
            } else {
                mount == pristine(device)?
            },
        "epoch 262 resources or scratch mount changed"
    );
    let delivery_ref = Bound::new(DELIVERY_BOOKING.0, DELIVERY_BOOKING.1);
    let delivery = delivery_ref.sealed()?;
    let disk_floor = guards
        .values()
        .map(|g| num(g, "minimum_free_bytes"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .context("missing Foundation guard floor")?;
    let prior_growth = booking["guard_growth"]
        .as_object()
        .context("prior growth reservations")?
        .values()
        .try_fold(0, |sum, row| {
            capacity::add(sum, num(row, "remaining_growth_bytes")?)
        })?;
    let non_guard_disk = num(&booking, "full_protection_bytes")?
        .checked_sub(capacity::add(disk_floor, prior_growth)?)
        .context("prior protection arithmetic changed")?;
    ensure!(
        non_guard_disk >= num(&delivery, "receipt_scratch_maximum_bytes")?,
        "epoch 257 retained disk reserve missing"
    );
    let growth = allocation["roots"]
        .as_object()
        .context("allocation roots")?
        .values()
        .try_fold(0, |sum, row| {
            capacity::add(sum, num(row, "remaining_upper_bound_bytes")?)
        })?;
    let protected = capacity::add(capacity::add(disk_floor, non_guard_disk)?, growth)?;
    let (candidate_disk, candidate) = if let Some(quote) = &quote {
        (
            capacity::add(quote.working_disk, DISK_RECEIPTS)?,
            capacity::add(quote.producer_memory, capacity::add(CONTROLLER_MEMORY, 1 << 30)?)?,
        )
    } else {
        (DISK_RECEIPTS, capacity::add(MEMORY, capacity::add(CONTROLLER_MEMORY, GUARD_MEMORY)?)?)
    };
    let required = capacity::add(protected, candidate_disk)?;
    let free = num(&allocation, "conservative_available_bytes")?
        .min(resources_before.2)
        .min(resources_after.2);
    let reserve = capacity::add(
        resources_before.0 / 10,
        num(&delivery, "guard_memory_allowance")?,
    )?;
    let base_memory = capacity::add(reserve, candidate)?;
    let (hard, growth_memory) = recorded.values().try_fold(
        (base_memory, base_memory),
        |(hard, growth), (owner, current, _)| {
            let cap: u64 = text(owner, "MemoryMax")?.parse()?;
            Ok::<_, anyhow::Error>((
                capacity::add(hard, cap)?,
                capacity::add(
                    growth,
                    cap.checked_sub(*current)
                        .context("owner current exceeds cap")?,
                )?,
            ))
        },
    )?;
    let available_memory = resources_before.1.min(resources_after.1);
    let fit = json!({"guard_floor_bytes":disk_floor,"inherited_non_guard_disk_bytes":non_guard_disk,
        "remaining_guard_growth_bytes":growth,"protected_existing_disk_bytes":protected,
        "candidate_disk_bytes":candidate_disk,"required_disk_bytes":required,"available_disk_bytes":free,
        "disk_shortfall_bytes":required.saturating_sub(free),"disk_margin_bytes":free.saturating_sub(required),
        "combined_host_and_periodic_memory_reserve_bytes":reserve,"candidate_total_memory_bytes":candidate,
        "required_hard_memory_bytes":hard,"host_total_memory_bytes":resources_before.0,
        "required_remaining_memory_bytes":growth_memory,"available_memory_bytes":available_memory,
        "memory_shortfall_bytes":hard.saturating_sub(resources_before.0).max(growth_memory.saturating_sub(available_memory)),
        "fits":required<=free && hard<=resources_before.0 && growth_memory<=available_memory,
        "cpus":cpus,"candidate_mount":mount,"delivery_booking":delivery_ref});
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
        "owners":on_host_owners,"periodic_guards":guards,"local_allocation":allocation,"capacity":fit,
        "controller":controller_owner,"candidate_held":held.is_some(),"admission_issued":false});
    if let Some(quote) = quote {
        evidence["full_replay_quote"] = json!({"sizing_reference":quote.reference,"inputs":quote.inputs,
            "whole_tree_bytes":quote.working_disk,"producer_memory_bytes":quote.producer_memory,
            "receipt_disk_bytes":DISK_RECEIPTS,"control_memory_bytes":CONTROLLER_MEMORY,
            "guard_memory_bytes":1u64 << 30});
    }
    deny_authority(&mut evidence);
    Ok(evidence)
}

pub(crate) fn cadence_lock() -> Result<File> {
    let path = Path::new(CADENCE_LOCK);
    trusted_parents(path)?;
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = lock.metadata()?;
    ensure!(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "Foundation cadence lock custody"
    );
    use std::os::fd::AsRawFd;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Foundation cadence lock is busy"
    );
    Ok(lock)
}

pub fn run() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .context("provide a new Foundation roster evidence directory")?,
    );
    let mut quote = false;
    let controller_unit = match args.next() {
        None => None,
        Some(flag) if flag == "--full-replay-quote" => {
            quote = true;
            None
        }
        Some(flag) if flag == "--as-controller" => Some(
            args.next()
                .context("controller unit")?
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid controller name"))?,
        ),
        Some(_) => bail!("use --as-controller UNIT or --full-replay-quote"),
    };
    let synchronize = match args.next() {
        None => false,
        Some(flag) if flag == "--synchronize-peer-guards" && controller_unit.is_some() => true,
        Some(_) => bail!("guard synchronization requires the booked controller"),
    };
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
    let _lock = cadence_lock()?;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut native = Native {
        root,
        counter: 0,
        deadline: Some(capacity::add(mono()?, 60_000_000)?),
    };
    let invocation = controller_unit
        .as_ref()
        .map(|_| std::env::var("INVOCATION_ID"))
        .transpose()?;
    let controller =
        controller_unit
            .as_deref()
            .zip(invocation.as_deref())
            .map(|(unit, invocation)| Controller {
                unit,
                invocation,
                held: false,
            });
    let result = if quote {
        full_replay_quote().and_then(|quote| measure(&mut native, None, Some(quote)))
    } else {
        receipt(&mut native, controller)
    };
    match result {
        Ok(evidence) => {
            let fit = save_json(&native.root, "roster.json", &evidence)?;
            if controller_unit.is_some() {
                let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
                let review = json!({"fleet":evidence["fleet"],"observer":evidence["observer"],"boot_id":boot.trim(),
                    "synchronize_peer_guards":synchronize});
                let review_ref = save_json(&native.root, "controller-check-review.json", &review)?;
                let context = json!({"review":review_ref,"foundation_roster":fit});
                let result = if synchronize {
                    peer_window::capture(&mut native, &review, &context)
                } else {
                    peer_window::select_minimum(&mut native, &review, &context, 1)
                };
                let window = match result {
                    Ok(window) => window,
                    Err(error) => {
                        save_json(
                            &native.root,
                            "peer-window-failure.json",
                            &json!({"fit":fit,"error":format!("{error:#}"),"admission_issued":false}),
                        )?;
                        return Err(error);
                    }
                };
                println!(
                    "{}",
                    json!({"fit":fit,"peer_window":window.receipt,"admission_issued":false})
                );
            } else {
                println!("{}", serde_json::to_string(&fit)?);
            }
        }
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
