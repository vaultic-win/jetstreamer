//! Bind the live Foundation cohort for replay funding and guard qualification.
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
const KNOWN_GUARDS: [(u64, &str); 6] = [
    (226, "horizon-guard-226-checkpoint-continuation-extract-v3"),
    (230, "horizon-230-middle-protective-v1"),
    (252, "horizon-252-regional-singleton-protective-v1"),
    (261, "horizon-261-singleton-protective-v1"),
    (262, "horizon-262-singleton-protective-v1"),
    (288, "horizon-288-full-shrink-debt-protective-v1"),
];
const AUXILIARY: [&str; 2] = [
    BROKER_226,
    "foundation-public-audit-epoch148-256-cap1-v1.service",
];
const EXTRACT_226: &str = "horizon-qualify-226-checkpoint-continuation-extract-v3.service";
const BROKER_226: &str = "foundation-226-original225-broker-v3.service";
const GUARD_226: &str = "horizon-guard-226-checkpoint-continuation-extract-v3.service";
const TIMER_226: &str = "horizon-guard-226-checkpoint-continuation-extract-v3.timer";
const DRAIN_226: &str =
    "/var/lib/jetstreamer/horizon226-extract-v3/control/success-drain-completion.json";
const LAUNCH_226: (&str, &str) = (
    "/var/lib/jetstreamer/horizon226-extract-v3/fleet-launch.json",
    "30f1fd1a0009ff63c22f1aac39438caf570acaddfaf90bd656331e2895294df8",
);
const SUFFIX_226_ROOT: &str = "/var/lib/jetstreamer/horizon226-suffix-v1";
const SUFFIX_226_CAP: u64 = 160 << 30;
const REPLAY_230: &str = "horizon-qualify-230-middle-v1.service";
const TERMINAL_230: (&str, &str) = (
    "/var/lib/jetstreamer/horizon230-middle-fit-v1/terminal-execution-mismatch.json",
    "bd5e40f2c612b5e20cb9607379b2a8511983c4a7d9c71409ed3ed0fa3472882b",
);
const CADENCE_LOCK: &str =
    "/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock";
const STANDARD_GUARD: &str =
    "/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard";
const GUARD_288: &str = "/var/lib/jetstreamer/horizon288-shrink-debt-comparison-tools-v327/guard";
const GUARD_ENV_261: &str = "/var/lib/jetstreamer/horizon261-full-guard-v1/guard.env";
const GUARD_ENV_262: &str = "/var/lib/jetstreamer/horizon262-full-guard-v1/guard.env";
const FULL_REPLAY_INPUTS: (&str, &str) = (
    "/var/lib/jetstreamer/horizon262-full-node-b9b95b02-v1/replay-inputs.json",
    "4375f4e590dc98d3f37ba6c646fa2c93cc65680267c7c920ba5d3255b67661d2",
);
const SIZING_REFERENCE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-full-profile-v226-a1/profile.json",
    "6b27a27ff1596fe6688f207d460566c51d5c9552cef47817358d2008b484f281",
);
const AUDIT_148_TERMINAL: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-foundation-public-audit-148-accepted-v1/acceptance.json",
    "f91e7a158ce64ab2f0d6be6c8f29499d086660a07831d1775299c5eebe0336f7",
);
const REPLAY_261: &str = "horizon-qualify-261-singleton-v1.service";
const GUARD_261: &str = "horizon-261-singleton-protective-v1.service";
const TIMER_261: &str = "horizon-261-singleton-protective-v1.timer";
const TERMINAL_261_COLLECTOR: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-cohort-commit-source-v1/horizon-epoch257-commit-source",
    "805646f57ba9b5262e17541e3f940390a5996138b4b4ddee4887915df0605499",
);
const DELIVERY_261_PREPARATION: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-current-reader-preparation-v1/preparation.json",
    "1d20967729c44e166611dd9df86e919b5ae0df4af337ed2d3cc0b5b4268d6a61",
);
const UPLOAD_261: &str = "horizon-upload-261-current-reader-v1.service";
const CLAIM_261: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-current-reader-delivery-v1/pipeline-claim.json",
    "c7082008cc50a19a622ac49de4f47f6fcf6d9f936625aca5b22a2b1d4337273a",
);
const UPLOAD_261_MEMORY: u64 = 64 << 30;
const UPLOAD_261_DISK: u64 = 1 << 30;
const REPLAY_262: &str = "horizon-qualify-262-singleton-v1.service";
const RUN_262: (&str, &str) = (
    "/var/lib/jetstreamer/horizon262-full-guard-v1/cadence-registration.json",
    "1d509e8cf8217b6bff3d911cc340bb9d68b919450c5d29ab9a6f103c6581ca35",
);
const RECOVERY_296: (&str, &str) = (
    "/var/lib/jetstreamer/horizon296-unbounded-worker-build-v1/full-fit-v341.json",
    "1fb5f9af69d405b32a0098bde182ac105e853b877572c7285eaf4be494453281",
);

struct FullReplayQuote {
    reference: Bound,
    inputs: Bound,
    working_disk: u64,
    producer_memory: u64,
}

enum Quote {
    FullReplay(FullReplayQuote),
    Suffix226(Bound),
    Delivery261(Bound),
    Replay296(Replay296Quote),
}

struct Replay296Quote {
    prior_fit: Bound,
    worker: Bound,
    disk: u64,
    memory: u64,
}

struct LiveReplay262 {
    reference: Bound,
    owner: Value,
    memory: u64,
    ticks: u64,
    guard_booking: Value,
    receipt_disk: u64,
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
            && profile["unit"] == REPLAY_261,
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

fn replay_296_quote() -> Result<Replay296Quote> {
    let prior_fit = Bound::new(RECOVERY_296.0, RECOVERY_296.1);
    let prior = prior_fit.sealed()?;
    let sizing = binding(&prior["earlier_full_booking"])?.sealed()?;
    let deployment = binding(&prior["sealed_worker"])?.sealed()?;
    let member = deployment["members"]
        .as_array()
        .context("epoch 296 sealed worker members")?
        .iter()
        .find(|row| row["name"] == "jetstreamer-historical-worker-v1-8-11")
        .context("epoch 296 repaired worker missing")?;
    let worker = Bound::new(
        Path::new(text(&deployment, "destination")?).join(text(member, "name")?),
        text(member, "sha256")?,
    );
    let sizing = &sizing["quote"];
    let disk = num(&prior, "required_disk_bytes")?;
    let memory = num(&prior, "required_memory_bytes")?;
    ensure!(
        prior["epoch"] == 296
            && prior["replay_admitted"] == false
            && deployment["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && member["mode"] == "0555"
            && disk
                == capacity::add(
                    num(sizing, "maximum_whole_tree_bytes")?,
                    num(sizing, "staging_reserve_bytes")?
                )?
            && memory
                == capacity::add(
                    num(sizing, "memory_max_bytes")?,
                    num(sizing, "guard_memory_bytes")?
                )?,
        "epoch 296 replay sizing or worker evidence changed"
    );
    worker.artifact()?;
    Ok(Replay296Quote {
        prior_fit,
        worker,
        disk,
        memory,
    })
}

fn closed_audit() -> Result<(Bound, String)> {
    let reference = Bound::new(AUDIT_148_TERMINAL.0, AUDIT_148_TERMINAL.1);
    let audit = reference.sealed()?;
    ensure!(
        audit["schema"] == "foundation-epoch148-pinned-public-audit-acceptance-v1"
            && audit["epoch"] == 148
            && audit["unit"] == AUXILIARY[1]
            && audit["authenticated_readiness_rechecked"] == true,
        "epoch 148 terminal audit receipt changed"
    );
    Ok((reference, text(&audit, "invocation_id")?.to_owned()))
}

fn delivery_261_preparation() -> Result<Bound> {
    let reference = Bound::new(DELIVERY_261_PREPARATION.0, DELIVERY_261_PREPARATION.1);
    let preparation = reference.sealed()?;
    let reader_plan = binding(&preparation["reader_plan"])?.sealed()?;
    ensure!(
        preparation["schema"] == "foundation-epoch261-current-reader-preparation-v1"
            && preparation["epoch"] == 261
            && preparation["publication_authorized"] == false
            && reader_plan["schema"] == "horizon-current-reader-plan-v1"
            && reader_plan["threads"] == 8
            && preparation["independent_boundary"] == reader_plan["epoch_expectations"]["261"],
        "epoch 261 delivery preparation changed"
    );
    binding(&preparation["uploader"])?.artifact()?;
    Ok(reference)
}

fn live_delivery_261(n: &mut Native) -> Result<(Bound, Value, u64, u64)> {
    let reference = Bound::new(CLAIM_261.0, CLAIM_261.1);
    let claim = reference.sealed()?;
    let evidence = claim["evidence"]
        .as_array()
        .context("epoch 261 delivery evidence")?;
    ensure!(evidence.len() == 2, "epoch 261 delivery evidence count");
    let booking_ref = binding(&evidence[0])?;
    let booking = booking_ref.sealed()?;
    let launch = binding(&evidence[1])?.sealed()?;
    let booked_fit = binding(&booking["storage_quote"])?.sealed()?;
    let owner = n.show_fields(UPLOAD_261, OWNER_FIELDS)?;
    let launched = &launch["owner"];
    let invocation = text(&claim, "invocation_id")?;
    let pid = text(&owner, "MainPID")?.parse()?;
    let ticks = process_ticks(pid)?;
    ensure!(
        claim["epoch"] == 261
            && claim["unit"] == UPLOAD_261
            && claim["phase"] == "upload-readback"
            && booking["schema"] == "foundation-epoch261-delivery-booking-v1"
            && booking["epoch"] == 261
            && booking["unit"] == UPLOAD_261
            && booking["staging_copy_required"] == false
            && booked_fit["capacity"]["fits"] == true
            && booked_fit["capacity"]["candidate_disk_bytes"] == UPLOAD_261_DISK
            && booked_fit["delivery_quote"]["delivery_memory_max_bytes"] == UPLOAD_261_MEMORY
            && launch["schema"] == "foundation-epoch261-current-reader-delivery-launch-v1"
            && binding(&launch["booking"])? == booking_ref
            && launch["process_start_ticks"] == ticks
            && owner["AllowedCPUs"] == "24-31"
            && owner["ExecStart"] == claim["expected_exec_start"],
        "epoch 261 delivery booking or live invocation changed"
    );
    for field in [
        "Id",
        "InvocationID",
        "MainPID",
        "ControlGroup",
        "AllowedCPUs",
        "MemoryMax",
        "ExecStart",
    ] {
        ensure!(
            owner[field] == launched[field],
            "epoch 261 delivery changed {field}"
        );
    }
    let memory = live::finite_owner(&owner, UPLOAD_261, invocation, UPLOAD_261_MEMORY)?;
    Ok((reference, owner, memory, ticks))
}

fn live_replay_262(n: &mut Native) -> Result<LiveReplay262> {
    let reference = Bound::new(RUN_262.0, RUN_262.1);
    let registered = reference.sealed()?;
    let profile = binding(&registered["profile"])?.sealed()?;
    let admission = binding(&registered["admission"])?.sealed()?;
    let handoff = binding(&registered["handoff"])?.sealed()?;
    let admitted_fit = binding(&admission["roster"])?.sealed()?;
    let inputs = binding(&profile["inputs"])?.sealed()?;
    let node = binding(&inputs["replay_node"])?;
    node.artifact()?;
    let owner = n.show_fields(REPLAY_262, OWNER_FIELDS)?;
    let invocation = text(&registered, "invocation_id")?;
    let pid: u64 = text(&owner, "MainPID")?.parse()?;
    let ticks = process_ticks(pid)?;
    let running = fs::metadata(format!("/proc/{pid}/exe"))?;
    let sealed = fs::metadata(&node.path)?;
    let sample_ref = binding(&registered["active_guard"])?;
    let sample = sample_ref.json()?;
    let guard_plan = Bound::new(text(&sample, "plan")?, text(&sample, "plan_sha256")?).sealed()?;
    let floor = num(&admission, "guard_minimum_free_bytes")?;
    let cap = num(&profile, "maximum_root_physical_bytes")?;
    let receipt_disk = num(&profile, "receipt_disk_reservation_bytes")?;
    let memory_cap = num(&profile, "maximum_memory_bytes")?;
    ensure!(
        registered["schema"] == "foundation-epoch262-replay-cadence-registration-v1"
            && registered["epoch"] == EPOCH
            && registered["unit"] == REPLAY_262
            && registered["main_pid"] == pid
            && registered["run_root"] == profile["worker_root"]
            && registered["run_root"] == guard_plan["worker_root"]
            && registered["ready"] == false
            && handoff["producer"] == REPLAY_262
            && handoff["invocation_id"] == invocation
            && admission["schema"] == "foundation-epoch262-full-replay-admission-v1"
            && admission["epoch"] == EPOCH
            && admitted_fit["capacity"]["guard_floor_bytes"] == floor
            && admitted_fit["capacity"]["fits"] == true
            && admitted_fit["capacity"]["candidate_disk_bytes"]
                == capacity::add(cap, receipt_disk)?
            && admitted_fit["full_replay_quote"]["producer_memory_bytes"] == memory_cap
            && owner["AllowedCPUs"] == profile["allowed_cpus"]
            && (running.dev(), running.ino()) == (sealed.dev(), sealed.ino()),
        "epoch 262 replay booking or live invocation changed"
    );
    let memory = live::finite_owner(&owner, REPLAY_262, invocation, memory_cap)?;
    Ok(LiveReplay262 {
        reference,
        owner,
        memory,
        ticks,
        guard_booking: json!({"sample":sample_ref,"floor_bytes":floor,"cap_bytes":cap}),
        receipt_disk,
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

fn replay_261_guard_drained(n: &mut Native) -> Result<()> {
    let timer = n.show_fields(TIMER_261, "ActiveState,Job")?;
    let service = n.show_fields(GUARD_261, "ActiveState,MainPID,ControlGroup,Job")?;
    ensure!(
        timer["ActiveState"] == "inactive"
            && timer["Job"] == ""
            && matches!(service["ActiveState"].as_str(), Some("inactive" | "failed"))
            && service["MainPID"] == "0"
            && service["ControlGroup"] == ""
            && service["Job"] == "",
        "epoch 261 protective timer and service have not drained"
    );
    Ok(())
}

fn terminal_replay_261(n: &mut Native, booking: &Value) -> Result<Option<Value>> {
    let current = n.show_fields(REPLAY_261, "ActiveState")?;
    if current["ActiveState"] == "active" {
        return Ok(None);
    }
    let collector = Bound::new(TERMINAL_261_COLLECTOR.0, TERMINAL_261_COLLECTOR.1);
    collector.artifact()?;
    let terminal: Value =
        serde_json::from_slice(&n.run(TERMINAL_261_COLLECTOR.0, &["--epoch261"])?)?;
    collector.artifact()?;
    ensure!(
        terminal["schema"] == "foundation-epoch261-committed-cohort-source-v1"
            && terminal["state"] == "local-cohort-committed"
            && terminal["epoch"] == 261
            && terminal["unit"] == REPLAY_261
            && terminal["invocation_id"] == booking["owners"][REPLAY_261]["InvocationID"]
            && terminal["publication_authorized"] == false,
        "epoch 261 terminal does not match the booked replay"
    );
    replay_261_guard_drained(n)?;
    Ok(Some(json!({"collector":collector,"terminal":terminal})))
}

fn terminal_extract_226(n: &mut Native, booking: &Value, proof: &Bound) -> Result<()> {
    ensure!(
        proof.path == Path::new(DRAIN_226),
        "foreign extraction drain"
    );
    let terminal = proof.sealed()?;
    let launch_ref = Bound::new(LAUNCH_226.0, LAUNCH_226.1);
    let launch = launch_ref.sealed()?;
    let handoff = binding(&terminal["handoff"])?.sealed()?;
    ensure!(
        terminal["schema"] == "foundation-epoch226-extraction-success-drain-v1"
            && terminal["epoch"] == 226
            && terminal["prefix_retained"] == true
            && terminal["suffix_started"] == false
            && terminal["producer"]["Id"] == EXTRACT_226
            && terminal["producer"]["Result"] == "success"
            && terminal["after"]["broker"]["Id"] == BROKER_226
            && handoff["launch"] == json!(launch_ref)
            && launch["invocation_id"] == booking["owners"][EXTRACT_226]["InvocationID"]
            && launch["broker_invocation_id"] == booking["owners"][BROKER_226]["InvocationID"],
        "epoch 226 drain is outside the booked extraction"
    );
    let timer = n.show_fields(TIMER_226, "ActiveState,Job")?;
    ensure!(
        timer["ActiveState"] == "inactive" && timer["Job"] == "",
        "epoch 226 extraction timer has not drained"
    );
    for unit in [EXTRACT_226, BROKER_226, GUARD_226] {
        let state = n.show_fields(
            unit,
            "ActiveState,MainPID,ControlPID,ControlGroup,Job,InvocationID,Result",
        )?;
        ensure!(
            matches!(state["ActiveState"].as_str(), Some("inactive" | "failed"))
                && state["MainPID"] == "0"
                && state["ControlPID"] == "0"
                && state["ControlGroup"] == ""
                && state["Job"] == ""
                && !Path::new("/sys/fs/cgroup/system.slice").join(unit).exists(),
            "epoch 226 extraction owner {unit} has not drained"
        );
        if unit == EXTRACT_226 || unit == BROKER_226 {
            ensure!(
                state["InvocationID"] == ""
                    || state["InvocationID"] == booking["owners"][unit]["InvocationID"],
                "epoch 226 extraction owner {unit} was replaced"
            );
        }
    }
    Ok(())
}

fn terminal_replay_230(n: &mut Native, booking: &Value) -> Result<Option<Bound>> {
    let producer = n.show_fields(
        REPLAY_230,
        "ActiveState,InvocationID,MainPID,ControlGroup,Job,NRestarts,Result,ExecMainStatus",
    )?;
    if producer["ActiveState"] == "active" {
        return Ok(None);
    }
    let proof = Bound::new(TERMINAL_230.0, TERMINAL_230.1);
    let closed = proof.sealed()?;
    let invocation = &booking["owners"][REPLAY_230]["InvocationID"];
    let timer = n.show_fields("horizon-230-middle-protective-v1.timer", "ActiveState,Job")?;
    let guard = n.show_fields(
        "horizon-230-middle-protective-v1.service",
        "ActiveState,MainPID,ControlGroup,Job",
    )?;
    ensure!(
        closed["schema"] == "foundation-epoch230-middle-execution-mismatch-terminal-v1"
            && closed["epoch"] == 230
            && closed["producer"]["Id"] == REPLAY_230
            && &closed["producer"]["InvocationID"] == invocation
            && &closed["manager_event"]["INVOCATION_ID"] == invocation
            && closed["diagnostics_retained"] == true
            && closed["physical_reclamation_bytes"] == 0
            && producer["ActiveState"] == "failed"
            && &producer["InvocationID"] == invocation
            && producer["Result"] == "exit-code"
            && producer["ExecMainStatus"] == "1"
            && producer["MainPID"] == "0"
            && producer["ControlGroup"] == ""
            && producer["Job"] == ""
            && producer["NRestarts"] == "0"
            && timer["ActiveState"] == "inactive"
            && timer["Job"] == ""
            && matches!(guard["ActiveState"].as_str(), Some("inactive" | "failed"))
            && guard["MainPID"] == "0"
            && guard["ControlGroup"] == ""
            && guard["Job"] == "",
        "epoch 230 failed replay and protective guard do not match the recorded drain"
    );
    Ok(Some(proof))
}

fn fleet_roster<'a>(
    fleet: &'a Value,
    booking: &Value,
    released: &BTreeMap<u64, &str>,
    delivery_261: Option<&Value>,
    replay_262: Option<&Value>,
) -> Result<BTreeMap<u64, &'a Value>> {
    let rows = fleet["active"]
        .as_array()
        .context("Foundation active roster")?;
    let booked = booking["owners"]
        .as_object()
        .context("Foundation booked owners")?;
    let mut roster = BTreeMap::new();
    let mut observed_delivery = None;
    let mut observed_replay_262 = false;
    for row in rows {
        let epoch = num(row, "epoch")?;
        if epoch == 261 && row["phase"] == "upload-readback" {
            let owner = delivery_261.context("unbooked epoch 261 delivery in fleet")?;
            ensure!(
                observed_delivery.replace(&row["unit"]).is_none(),
                "duplicate epoch 261 delivery in fleet"
            );
            live::same_owner(&row["unit"], owner)?;
            continue;
        }
        if epoch == 262 {
            let owner = replay_262.context("unbooked epoch 262 replay in fleet")?;
            ensure!(
                row["phase"] == "replay" && !observed_replay_262,
                "unexpected or duplicate epoch 262 phase in fleet"
            );
            live::same_owner(&row["producer"], owner)?;
            observed_replay_262 = true;
            continue;
        }
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
        observed_delivery.is_none() || !roster.contains_key(&261),
        "duplicate epoch 261 phases in fleet"
    );
    let missing: BTreeMap<_, _> = released
        .iter()
        .filter_map(|(&epoch, &unit)| (!roster.contains_key(&epoch)).then_some((epoch, unit)))
        .collect();
    ensure!(
        roster.keys().copied().eq([226, 230, 252, 257, 261, 288]
            .into_iter()
            .filter(|epoch| !missing.contains_key(epoch))),
        "incomplete Foundation live roster"
    );
    let selected: BTreeSet<_> = roster
        .values()
        .map(|owner| text(owner, "Id"))
        .collect::<Result<_>>()?;
    ensure!(
        selected.len() == roster.len()
            && booked.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == selected
                    .into_iter()
                    .chain(AUXILIARY)
                    .chain(missing.into_values())
                    .collect(),
        "missing or duplicate Foundation capacity booking"
    );
    Ok(roster)
}

#[cfg(test)]
mod roster_tests {
    use super::*;

    #[test]
    fn funded_replay_can_leave_the_observer_only_after_validated_terminal() {
        let mut owners = serde_json::Map::new();
        let mut rows = Vec::new();
        for (epoch, phase) in [
            (226, "private-held-extraction"),
            (230, "diagnostic-qualification"),
            (252, "replay"),
            (257, "upload-readback"),
            (261, "replay"),
            (288, "replay"),
        ] {
            let unit = match epoch {
                226 => EXTRACT_226.to_owned(),
                261 => REPLAY_261.to_owned(),
                _ => format!("test-{epoch}.service"),
            };
            let owner = json!({"Id":unit,"InvocationID":format!("invocation-{epoch}"),
                "MainPID":epoch.to_string(),"ControlGroup":format!("/test/{epoch}")});
            owners.insert(unit, owner.clone());
            rows.push(json!({"epoch":epoch,"phase":phase,"producer":owner,"unit":owner}));
        }
        for unit in AUXILIARY {
            owners.insert(unit.to_owned(), Value::Null);
        }
        let booking = json!({"owners": owners});
        let before = json!({"active":rows});
        let none = BTreeMap::new();
        let first = BTreeMap::from([(261, REPLAY_261)]);
        let both = BTreeMap::from([(226, EXTRACT_226), (261, REPLAY_261)]);
        assert!(fleet_roster(&before, &booking, &none, None, None).is_ok());
        assert!(fleet_roster(&before, &booking, &both, None, None).is_ok());

        rows.retain(|row| row["epoch"] != 261);
        let after = json!({"active":rows});
        assert!(fleet_roster(&after, &booking, &none, None, None).is_err());
        assert!(fleet_roster(&after, &booking, &first, None, None).is_ok());

        rows.retain(|row| row["epoch"] != 226);
        let after = json!({"active":rows});
        assert!(fleet_roster(&after, &booking, &first, None, None).is_err());
        assert!(fleet_roster(&after, &booking, &both, None, None).is_ok());

        rows.retain(|row| row["epoch"] != 252);
        assert!(fleet_roster(&json!({"active":rows}), &booking, &both, None, None).is_err());
    }
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
    let guard_environment = match epoch {
        261 => Some((
            GUARD_ENV_261,
            "HORIZON261_GUARD_PLAN_SHA256",
            "${HORIZON261_GUARD_PLAN_SHA256}",
        )),
        262 => Some((
            GUARD_ENV_262,
            "HORIZON262_GUARD_PLAN_SHA256",
            "${HORIZON262_GUARD_PLAN_SHA256}",
        )),
        _ => None,
    };
    let plan_arg = if let Some((path, variable, argument)) = guard_environment {
        let env = n.show_fields(
            &guard_unit,
            "Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment",
        )?;
        ensure!(
            env["EnvironmentFiles"] == format!("{path} (ignore_errors=no)")
                && ["Environment", "PassEnvironment", "UnsetEnvironment"]
                    .iter()
                    .all(|key| env[*key] == ""),
            "epoch {epoch} guard environment changed"
        );
        let path = Path::new(path);
        let source = Bound::new(path, hash(path)?);
        trusted_parents(path)?;
        let bytes = source.bytes(true)?;
        ensure!(
            bytes == format!("{variable}={}\n", plan.sha256).as_bytes(),
            "epoch {epoch} guard plan environment differs"
        );
        argument
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
    quote: Option<Quote>,
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
    let mut released_replays = BTreeMap::new();
    let suffix = match &quote {
        Some(Quote::Suffix226(proof)) => {
            terminal_extract_226(n, &booking, proof)?;
            released_replays.insert(226, EXTRACT_226);
            Some(proof)
        }
        _ => None,
    };
    let closed_replay = if quote.is_some() {
        terminal_replay_261(n, &booking)?
    } else {
        None
    };
    let delivery_261 = matches!(&quote, Some(Quote::Delivery261(_)));
    ensure!(
        !delivery_261 || closed_replay.is_some(),
        "epoch 261 delivery requires a committed archive and drained replay guard"
    );
    if closed_replay.is_some() {
        released_replays.insert(261, REPLAY_261);
    }
    let closed_230 = if quote.is_some() {
        terminal_replay_230(n, &booking)?
    } else {
        None
    };
    if closed_230.is_some() {
        released_replays.insert(230, REPLAY_230);
    }
    let before = listed_owners(n)?;
    let active_delivery = if quote.is_some() && before.contains(UPLOAD_261) {
        ensure!(
            !delivery_261 && closed_replay.is_some(),
            "epoch 261 delivery overlaps its candidate or replay"
        );
        Some(live_delivery_261(n)?)
    } else {
        None
    };
    let active_262 = if before.contains(REPLAY_262) {
        ensure!(
            matches!(&quote, Some(Quote::Suffix226(_) | Quote::Replay296(_))),
            "epoch 262 full replay already owns its lane"
        );
        Some(live_replay_262(n)?)
    } else {
        None
    };
    let roster = fleet_roster(
        &fleet,
        &booking,
        &released_replays,
        active_delivery.as_ref().map(|(_, owner, _, _)| owner),
        active_262.as_ref().map(|replay| &replay.owner),
    )?;
    let epoch = match &quote {
        Some(Quote::Suffix226(_)) => 226,
        Some(Quote::Delivery261(_)) => 261,
        Some(Quote::Replay296(_)) => 296,
        _ => EPOCH,
    };
    let missing: Vec<_> = fleet["inventory"]["entries"]
        .as_array()
        .context("Foundation inventory")?
        .iter()
        .filter(|row| row["epoch"] == epoch)
        .collect();
    ensure!(
        missing.len() == 1 && missing[0]["state"] == "missing",
        "epoch {epoch} inventory no longer missing"
    );
    let booked: BTreeSet<String> = booking["owners"]
        .as_object()
        .context("booked owners")?
        .keys()
        .cloned()
        .collect();
    let mut released_units: BTreeSet<_> = released_replays.into_values().collect();
    if suffix.is_some() {
        released_units.insert(BROKER_226);
    }
    let closed_audit = quote.as_ref().map(|_| closed_audit()).transpose()?;
    let reserved_audit_memory = if let Some((_, invocation)) = &closed_audit {
        let audit = AUXILIARY[1];
        let reservation = &booking["owners"][audit];
        let current = n.show_fields(audit, "ActiveState,MainPID,InvocationID,ControlGroup,Job")?;
        ensure!(
            reservation["InvocationID"] == *invocation
                && current["ActiveState"] == "inactive"
                && current["MainPID"] == "0"
                && matches!(current["InvocationID"].as_str(), Some(id) if id.is_empty() || id == invocation)
                && current["ControlGroup"] == ""
                && current["Job"] == "",
            "epoch 148 audit closure no longer matches the booked auxiliary"
        );
        released_units.insert(audit);
        text(reservation, "MemoryMax")?.parse()?
    } else {
        0
    };
    let mut expected = booked.clone();
    for unit in &released_units {
        ensure!(
            expected.remove(*unit),
            "released Foundation reservation {unit} is missing"
        );
    }
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
    if active_delivery.is_some() {
        ensure!(
            expected.insert(UPLOAD_261.to_owned()),
            "epoch 261 delivery booked twice"
        );
    }
    if active_262.is_some() {
        ensure!(
            expected.insert(REPLAY_262.to_owned()),
            "epoch 262 replay booked twice"
        );
    }
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
            "Foundation replay output filesystem changed"
        );
        Value::Null
    } else {
        pristine(device)?
    };
    let resources_before = live::resources_at(Path::new(FILESYSTEM))?;
    let selected = units::parse_cpu_list(match epoch {
        226 => "16-23",
        261 => "24-31",
        296 => "56-63",
        _ => "40-47",
    })?;
    let cpus = units::affinity(&json!({"cpu_affinity":selected}))?;
    let mut recorded = BTreeMap::new();
    for unit in booked
        .iter()
        .filter(|unit| !released_units.contains(unit.as_str()))
    {
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
            "epoch {epoch} CPUs overlap {unit}"
        );
        let memory = live::finite_owner(&owner, unit, text(&owner, "InvocationID")?, cap)?;
        let process_start_ticks = process_ticks(text(&owner, "MainPID")?.parse()?)?;
        recorded.insert(unit.clone(), (owner, memory, process_start_ticks));
    }
    if let Some((_, owner, memory, ticks)) = &active_delivery {
        ensure!(
            selected.is_disjoint(&units::parse_cpu_list(text(owner, "AllowedCPUs")?)?),
            "epoch {epoch} CPUs overlap the epoch 261 delivery"
        );
        recorded.insert(UPLOAD_261.to_owned(), (owner.clone(), *memory, *ticks));
    }
    if let Some(replay) = &active_262 {
        ensure!(
            selected.is_disjoint(&units::parse_cpu_list(text(&replay.owner, "AllowedCPUs")?)?),
            "epoch {epoch} CPUs overlap the epoch 262 replay"
        );
        recorded.insert(
            REPLAY_262.to_owned(),
            (replay.owner.clone(), replay.memory, replay.ticks),
        );
    }
    let mut guards = BTreeMap::new();
    for (guard_epoch, guard) in KNOWN_GUARDS {
        if (guard_epoch == 226 && suffix.is_some())
            || (guard_epoch == 230 && closed_230.is_some())
            || (guard_epoch == 261 && closed_replay.is_some())
        {
            continue;
        }
        let (owner, guard_booking) = if guard_epoch == EPOCH {
            let Some(replay) = &active_262 else { continue };
            (&replay.owner, &replay.guard_booking)
        } else {
            let unit = text(roster[&guard_epoch], "Id")?;
            (
                &recorded[unit].0,
                &booking["guard_growth"][guard_epoch.to_string()],
            )
        };
        guards.insert(
            guard_epoch,
            guard_binding(n, guard_epoch, guard, guard_booking, owner, device)?,
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
    if closed_replay.is_some() {
        ensure!(
            terminal_replay_261(n, &booking)? == closed_replay,
            "epoch 261 terminal changed during roster binding"
        );
    }
    if closed_230.is_some() {
        ensure!(
            terminal_replay_230(n, &booking)? == closed_230,
            "epoch 230 terminal changed during roster binding"
        );
    }
    if let Some(proof) = suffix {
        terminal_extract_226(n, &booking, proof)?;
    }
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
        "epoch {epoch} resources or scratch mount changed"
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
    let delivery_261_disk = active_delivery.as_ref().map_or(0, |_| UPLOAD_261_DISK);
    let replay_262_disk = active_262.as_ref().map_or(0, |replay| replay.receipt_disk);
    let protected = capacity::add(
        capacity::add(
            capacity::add(disk_floor, non_guard_disk)?,
            capacity::add(delivery_261_disk, replay_262_disk)?,
        )?,
        growth,
    )?;
    let (candidate_disk, candidate) = match &quote {
        Some(Quote::FullReplay(quote)) => (
            capacity::add(quote.working_disk, DISK_RECEIPTS)?,
            capacity::add(
                quote.producer_memory,
                capacity::add(CONTROLLER_MEMORY, 1 << 30)?,
            )?,
        ),
        Some(Quote::Suffix226(_)) => (
            capacity::add(SUFFIX_226_CAP, DISK_RECEIPTS)?,
            capacity::add(SUFFIX_226_CAP, capacity::add(CONTROLLER_MEMORY, 1 << 30)?)?,
        ),
        Some(Quote::Delivery261(_)) => (
            num(&delivery, "receipt_scratch_maximum_bytes")?,
            capacity::add(
                num(&delivery, "memory_max_bytes")?,
                capacity::add(CONTROLLER_MEMORY, num(&delivery, "guard_memory_allowance")?)?,
            )?,
        ),
        Some(Quote::Replay296(quote)) => {
            (quote.disk, capacity::add(quote.memory, CONTROLLER_MEMORY)?)
        }
        None => (
            DISK_RECEIPTS,
            capacity::add(MEMORY, capacity::add(CONTROLLER_MEMORY, GUARD_MEMORY)?)?,
        ),
    };
    let required = capacity::add(protected, candidate_disk)?;
    let free = num(&allocation, "conservative_available_bytes")?
        .min(resources_before.2)
        .min(resources_after.2);
    let periodic_reserve = capacity::add(
        num(&delivery, "guard_memory_allowance")?,
        if active_262.is_some() { 1 << 30 } else { 0 },
    )?;
    let reserve = capacity::add(resources_before.0 / 10, periodic_reserve)?;
    let base_memory = capacity::add(capacity::add(reserve, candidate)?, reserved_audit_memory)?;
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
        "active_delivery_261_disk_bytes":delivery_261_disk,
        "active_replay_262_receipt_disk_bytes":replay_262_disk,
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
    let schema = match epoch {
        226 => "foundation-epoch226-suffix-roster-binding-v1",
        261 => "foundation-epoch261-delivery-roster-binding-v1",
        296 => "foundation-epoch296-replay-roster-binding-v1",
        _ => "foundation-epoch262-roster-binding-v1",
    };
    let mut evidence = json!({"schema":schema,"epoch":epoch,
        "recorded_unix_seconds":now()?,"fleet":fleet_ref,"observer":observer_ref,
        "completion":completion,"booking":booking_ref,"filesystem_device":device,
        "owners":on_host_owners,"periodic_guards":guards,"local_allocation":allocation,"capacity":fit,
        "controller":controller_owner,"candidate_held":held.is_some(),"admission_issued":false,
        "closed_middle_replay":closed_230,
        "active_delivery_261_claim":active_delivery.as_ref().map(|(claim, _, _, _)| claim),
        "active_replay_262_registration":active_262.as_ref().map(|replay| &replay.reference)});
    if let Some(Quote::FullReplay(quote)) = &quote {
        evidence["full_replay_quote"] = json!({"sizing_reference":quote.reference,"inputs":quote.inputs,
            "whole_tree_bytes":quote.working_disk,"producer_memory_bytes":quote.producer_memory,
            "receipt_disk_bytes":DISK_RECEIPTS,"control_memory_bytes":CONTROLLER_MEMORY,
            "guard_memory_bytes":1u64 << 30,"closed_audit":closed_audit.as_ref().map(|(proof, _)| proof),
            "reserved_audit_memory_bytes":reserved_audit_memory,"closed_replay":closed_replay});
    }
    if let Some(proof) = suffix {
        evidence["suffix_quote"] = json!({
            "completion":proof,"candidate_cap_bytes":SUFFIX_226_CAP,
            "candidate_memory_max_bytes":SUFFIX_226_CAP,"candidate_cpus":selected,
            "closed_audit":closed_audit.as_ref().map(|(proof, _)| proof),
            "reserved_audit_memory_bytes":reserved_audit_memory,"closed_replay":closed_replay,
        });
    }
    if let Some(Quote::Delivery261(preparation)) = &quote {
        evidence["delivery_quote"] = json!({
            "preparation":preparation,"delivery_memory_max_bytes":num(&delivery, "memory_max_bytes")?,
            "receipt_scratch_maximum_bytes":candidate_disk,"candidate_cpus":selected,
            "closed_audit":closed_audit.as_ref().map(|(proof, _)| proof),
            "reserved_audit_memory_bytes":reserved_audit_memory,"closed_replay":closed_replay,
        });
    }
    if let Some(Quote::Replay296(quote)) = &quote {
        evidence["replay_296_quote"] = json!({
            "prior_fit":quote.prior_fit,"repaired_worker":quote.worker,
            "candidate_disk_bytes":quote.disk,"candidate_memory_bytes":candidate,
            "closed_audit":closed_audit.as_ref().map(|(proof, _)| proof),
            "reserved_audit_memory_bytes":reserved_audit_memory,"closed_replay":closed_replay,
        });
    }
    deny_authority(&mut evidence);
    Ok(evidence)
}

/// Price the layered Foundation suffix while the caller holds the fleet cadence lock.
pub fn quote_226_suffix(drain_path: &Path, drain_sha256: &str) -> Result<Value> {
    use std::os::unix::fs::DirBuilderExt;

    ensure!(
        unsafe { libc::geteuid() } == 0 && drain_path == Path::new(DRAIN_226),
        "epoch 226 suffix quote scope"
    );
    let proof = Bound::new(drain_path, drain_sha256);
    let root = Path::new(SUFFIX_226_ROOT).join(format!(
        "capacity-witness-{}-{}",
        std::process::id(),
        mono()?
    ));
    trusted_parents(&root)?;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut native = Native {
        root,
        counter: 0,
        deadline: Some(capacity::add(mono()?, 60_000_000)?),
    };
    let roster = measure(&mut native, None, Some(Quote::Suffix226(proof.clone())))?;
    let fit = &roster["capacity"];
    let suffix = &roster["suffix_quote"];
    Ok(json!({
        "epoch":226,"resource_fit":fit["fits"],
        "disk_shortfall_bytes":fit["disk_shortfall_bytes"],
        "memory_shortfall_bytes":fit["memory_shortfall_bytes"],
        "protected_disk_bytes":fit["protected_existing_disk_bytes"],
        "required_disk_bytes":fit["required_disk_bytes"],
        "candidate_cap_bytes":suffix["candidate_cap_bytes"],
        "candidate_memory_max_bytes":suffix["candidate_memory_max_bytes"],
        "candidate_cpus":suffix["candidate_cpus"],
        "extraction226_terminal":{"completion":proof},
        "capacity_witness":native.root,"roster":roster,"publication_authorized":false,
    }))
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
    let command = args.next();
    let controller_unit = match command.as_deref() {
        None => None,
        Some(flag)
            if flag == "--full-replay-quote"
                || flag == "--delivery261-quote"
                || flag == "--replay296-quote" =>
        {
            None
        }
        Some(flag) if flag == "--as-controller" => Some(
            args.next()
                .context("controller unit")?
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid controller name"))?,
        ),
        Some(_) => bail!(
            "use --as-controller UNIT, --full-replay-quote, --delivery261-quote or --replay296-quote"
        ),
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
    let result = match command.as_deref() {
        Some(flag) if flag == "--full-replay-quote" => full_replay_quote()
            .and_then(|quote| measure(&mut native, None, Some(Quote::FullReplay(quote)))),
        Some(flag) if flag == "--delivery261-quote" => delivery_261_preparation()
            .and_then(|prep| measure(&mut native, None, Some(Quote::Delivery261(prep)))),
        Some(flag) if flag == "--replay296-quote" => replay_296_quote()
            .and_then(|quote| measure(&mut native, None, Some(Quote::Replay296(quote)))),
        _ => receipt(&mut native, controller),
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
