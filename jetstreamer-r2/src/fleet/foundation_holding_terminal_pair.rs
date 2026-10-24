//! Closed original-204/205 terminal transition for maintenance restoration only.
//! Historical floors remain charged; terminality supplies no reclaimed bytes.
use super::*;

pub(super) const SCHEMA: &str = "jetstreamer-foundation-holding-terminal-pair-basis-v2";
const HEALTHY: [&str; 3] = [
    "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
    "horizon-singleton-209-capped-4aeca563-v1.service",
    prefix223_native20::UNIT,
];
type OriginalProfile = (
    u64,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    u64,
);
const ORIGINALS: [OriginalProfile; 2] = [
    (
        204,
        "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        "448da7f2a3a34217afe7e115120b3cea",
        "/var/lib/jetstreamer/horizon-prefix204-launch-fcbf3992-v1/launch.json",
        "a1b38f09bb1314c9280ca924602bab1523d28755146919912f604c1ee9bbfdfb",
        88_559_361,
    ),
    (
        205,
        "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        "373359a11aef4993a1a949e19ff617c3",
        "/var/lib/jetstreamer/horizon-prefix205-launch-5c01bf93-v1/launch.json",
        "febbbb44b1d2b16afc3511e171dbb1f1aab732890893be1ce2f72239bc01ca9e",
        88_991_050,
    ),
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    launch: BoundFile,
    producer_result: BoundFile,
    terminal_properties: BoundFile,
    manager_journal: BoundFile,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Basis {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    inherited_capacity: BoundFile,
    historical_guards: BTreeMap<String, BoundFile>,
    protected_guards: BTreeMap<String, BoundFile>,
    terminal_originals: BTreeMap<u64, Terminal>,
}
fn sealed_bytes(b: &BoundFile) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && b.path.starts_with("/var/lib/jetstreamer")
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && is_lower_hex(&b.sha256, 64),
        "terminal-pair evidence must be immutable root-owned data"
    );
    let bytes = read_stable_bounded(&b.path, 4 << 20, "terminal-pair evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "terminal-pair evidence digest differs"
    );
    Ok(bytes)
}
fn sealed(b: &BoundFile) -> Result<Value> {
    Ok(serde_json::from_slice(&sealed_bytes(b)?)?)
}
fn journal(bytes: &[u8]) -> Result<Vec<Value>> {
    ensure!(
        bytes.len() <= 4 << 20,
        "terminal-pair journal exceeds bound"
    );
    let rows: Vec<Value> = if bytes.first() == Some(&b'[') {
        serde_json::from_slice(bytes)?
    } else {
        bytes
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(serde_json::from_slice)
            .collect::<std::result::Result<_, _>>()?
    };
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "terminal-pair journal is empty or truncated"
    );
    Ok(rows)
}
fn profile(epoch: u64) -> Result<OriginalProfile> {
    ORIGINALS
        .into_iter()
        .find(|p| p.0 == epoch)
        .context("only exact original 204/205 terminal proofs are supported")
}
fn terminal_state(epoch: u64, u: &Value, historical: bool) -> Result<()> {
    let (_, unit, iid, _, _, _) = profile(epoch)?;
    ensure!(
        u["Id"] == unit
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && u["ControlGroup"] == ""
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && ((u["LoadState"] == "loaded"
                && u["Result"] == "success"
                && u["ExecMainStatus"] == "0"
                && (u["InvocationID"] == iid || u["InvocationID"] == ""))
                || (!historical && u["LoadState"] == "not-found" && u["InvocationID"] == "")),
        "original is still live, failed, replaced or has ambiguous terminal ownership"
    );
    Ok(())
}
fn terminal_value(
    epoch: u64,
    t: &Terminal,
    artifacts: (&Value, &Value, &Value),
    rows: &[Value],
    f: &Value,
    boot: &str,
) -> Result<u64> {
    let (launch, result, manager) = artifacts;
    let (_, unit, iid, path, sha, slot) = profile(epoch)?;
    ensure!(
        t.launch.path == Path::new(path)
            && t.launch.sha256 == sha
            && launch["schema"]
                == format!("jetstreamer-private-epoch{epoch}-capped-root-prefix-launch-v1")
            && launch["epoch"] == epoch
            && launch["evidence"]["units"]
                .as_array()
                .is_some_and(|r| r.len() == 1)
            && launch["evidence"]["units"][0]["unit"] == unit
            && launch["evidence"]["units"][0]["invocation_id"] == iid,
        "terminal-pair original launch differs from the preserved genuine attempt"
    );
    ensure!(
        result["schema"]
            == format!("jetstreamer-private-epoch{epoch}-shrink-root-prefix-resource-v1")
            && result["epoch"] == epoch
            && result["unit"] == unit
            && result["invocation_id"] == iid
            && result["success"] == true
            && result["error"].is_null()
            && result["child_return_code"] == 0
            && result["external_signal"] == 0
            && result["natural_parent_completion_required"] == true
            && result["producer_canonical_root_prefix_present"] == true
            && result["target_slot"] == slot
            && result["terminal_root_slot"] == slot
            && result["plan"]["sha256"] == launch["plan_sha256"],
        "terminal-pair original lacks its genuine natural producer success"
    );
    for key in [
        "runner_sha256",
        "node_sha256",
        "worker_sha256",
        "snapshot_sha256",
    ] {
        ensure!(
            result[key] == launch[key] && result[key].as_str().is_some_and(|s| is_lower_hex(s, 64)),
            "terminal-pair original executable/input identity changed: {key}"
        );
    }
    for key in [
        "canonical_prefix_independently_qualified",
        "full_cold_epoch_peak_qualified",
        "ordinary_replay_authorized",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            result["authority"][key] == false,
            "terminal-pair producer receipt grants unrelated authority: {key}"
        );
    }
    terminal_state(epoch, manager, true)?;
    ensure!(
        manager["ExecStart"]
            .as_str()
            .zip(launch["expected_exec_start"].as_str())
            .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b)),
        "original terminal command changed"
    );
    let mut successes = Vec::new();
    let mut starts = Vec::new();
    let mut cursors = BTreeSet::new();
    let mut previous_time = 0;
    for row in rows {
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == unit
                && row["INVOCATION_ID"] == iid
                && row["_BOOT_ID"] == boot,
            "original full PID 1 history contains another invocation, owner or boot"
        );
        let clock = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("original manager clock missing")?;
        let at = clock.parse::<u64>()?;
        ensure!(
            at > previous_time
                && clock == at.to_string()
                && row["__CURSOR"]
                    .as_str()
                    .is_some_and(|cursor| !cursor.is_empty() && cursors.insert(cursor)),
            "original manager history is duplicated, unordered or truncated"
        );
        previous_time = at;
        let message = row["MESSAGE"]
            .as_str()
            .context("original terminal manager message missing")?;
        ensure!(
            !message.contains("Failed")
                && !message.contains("failed")
                && !message.contains("Killing")
                && !message.contains("Stopping "),
            "original manager history contains a failure or forced stop"
        );
        if row["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
            && message.starts_with(&format!("Started {unit}"))
        {
            starts.push(at);
        }
        if message == format!("{unit}: Deactivated successfully.") {
            ensure!(
                row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448",
                "original natural completion message identity changed"
            );
            successes.push(at);
        }
    }
    ensure!(
        starts.len() == 1
            && successes.len() == 1
            && starts[0] < successes[0]
            && f["recorded_unix_seconds"]
                .as_u64()
                .and_then(|s| s.checked_mul(1_000_000))
                .is_some_and(|at| at >= successes[0]),
        "accepted fleet predates the unique natural original completion"
    );
    Ok(successes[0])
}
pub(super) fn live_roster(f: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for row in f["active"]
        .as_array()
        .context("terminal-pair complete active roster missing")?
    {
        let u = singleton227_admission::active_owner(row)?;
        let name = u["Id"]
            .as_str()
            .context("terminal-pair owner name missing")?;
        ensure!(
            HEALTHY.contains(&name)
                && seen.insert(name)
                && u["NRestarts"] == "0"
                && diagnostic_stage_running(u)
                && f["unit_census"][name] == *u,
            "terminal-pair roster has a missing, extra, duplicate or replaced live owner"
        );
    }
    ensure!(
        seen == HEALTHY.into_iter().collect(),
        "terminal-pair requires exactly the actual three healthy replay owners"
    );
    prefix223_live_peer::roster(f)?;
    Ok(())
}
fn history(epoch: u64, t: &Terminal, f: &Value) -> Result<()> {
    let (_, unit, iid, _, _, _) = profile(epoch)?;
    let rows = f["diagnostics"]
        .as_array()
        .context("terminal-pair original diagnostic history missing")?
        .iter()
        .filter(|r| r["epoch"] == epoch && r["unit"]["Id"] == unit)
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1
            && rows[0]["live"] == false
            && rows[0]["launch_invocation_id"] == iid
            && rows[0]["launch_receipt"].as_str() == t.launch.path.to_str()
            && rows[0]["launch_receipt_sha256"] == t.launch.sha256,
        "terminal-pair dropped or relabelled an original diagnostic launch"
    );
    Ok(())
}
fn terminal_keys(s: &Basis) -> Result<()> {
    ensure!(
        s.terminal_originals.keys().copied().eq([204, 205]),
        "terminal-pair needs both positive original terminal proofs"
    );
    Ok(())
}
fn originals(s: &Basis, f: &Value, current: &BTreeMap<String, Value>, boot: &str) -> Result<Value> {
    terminal_keys(s)?;
    let mut proofs = serde_json::Map::new();
    for (epoch, t) in &s.terminal_originals {
        let (_, unit, _, _, _, _) = profile(*epoch)?;
        let launch = sealed(&t.launch)?;
        let result = sealed(&t.producer_result)?;
        let manager = sealed(&t.terminal_properties)?;
        let rows = journal(&sealed_bytes(&t.manager_journal)?)?;
        let at = terminal_value(*epoch, t, (&launch, &result, &manager), &rows, f, boot)?;
        history(*epoch, t, f)?;
        let u = current
            .get(unit)
            .context("original terminal unit omitted from complete current census")?;
        terminal_state(*epoch, u, false)?;
        ensure!(
            f["unit_census"][unit] == *u,
            "original terminal unit changed since accepted fleet"
        );
        if u["LoadState"] == "loaded" {
            ensure!(
                u["ExecStart"]
                    .as_str()
                    .zip(manager["ExecStart"].as_str())
                    .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b)),
                "current terminal original command was replaced"
            );
        }
        inactive_status::no_pending_owner_trigger(unit, u["LoadState"] == "not-found")?;
        let output = ProcessCommand::new("/usr/bin/journalctl")
            .args(["--unit", unit, "_PID=1", "--output=json", "--no-pager"])
            .output()?;
        ensure!(
            output.status.success() && journal(&output.stdout)? == rows,
            "original terminal history was lost or replaced after its genuine completion"
        );
        proofs.insert(epoch.to_string(),json!({"launch":private157::binding(&t.launch),"producer_result":private157::binding(&t.producer_result),
            "terminal_properties":private157::binding(&t.terminal_properties),"manager_journal":private157::binding(&t.manager_journal),
            "actual_current_terminal_unit":u,"natural_completion_unix_microseconds":at,"live":false,"reclamation_credit_bytes":0}));
    }
    Ok(Value::Object(proofs))
}
fn inherited(
    value: &Value,
    historical: &BTreeMap<String, BoundFile>,
) -> Result<(u64, u64, BoundFile)> {
    let cap = if value["schema"] == "jetstreamer-foundation-holding-restore-admission-v1" {
        &value["capacity"]
    } else {
        value
    };
    ensure!(
        cap["schema"] == "jetstreamer-foundation-holding-capacity-v1"
            && cap["host"] == "horizon-vaultic"
            && cap["first_epoch"] == 201
            && cap["last_epoch"] == 300
            && cap["restore_only"] == true
            && cap["all_live_growth_and_century_floor_protected"] == true
            && cap["resource_basis"]["protected_guards"] == serde_json::to_value(historical)?,
        "terminal-pair inherited capacity does not bind all five historical guard receipts"
    );
    for key in [
        "replay_launch_authorized",
        "local_retirement_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            cap[key] == false,
            "inherited capacity grants unrelated authority"
        );
    }
    let old_fleet = serde_json::from_value(cap["resource_basis"]["fleet"].clone())?;
    Ok((
        cap["minimum_free_bytes"]
            .as_u64()
            .filter(|n| *n > 0)
            .context("inherited capacity floor missing")?,
        cap["century_floor_bytes"]
            .as_u64()
            .filter(|n| *n > 0)
            .context("inherited century floor missing")?,
        old_fleet,
    ))
}
fn preserve_diagnostics(old: &Value, current: &Value) -> Result<()> {
    let expected: BTreeSet<_> = HEALTHY
        .into_iter()
        .chain(ORIGINALS.iter().map(|p| p.1))
        .collect();
    let mut names = BTreeSet::new();
    for row in old["active"]
        .as_array()
        .context("inherited active census missing")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        ensure!(
            names.insert(
                owner["Id"]
                    .as_str()
                    .context("inherited owner name missing")?
            ),
            "duplicate inherited owner"
        );
    }
    ensure!(
        names == expected,
        "inherited capacity is not the genuine five-owner basis"
    );
    let current_rows = current["diagnostics"]
        .as_array()
        .context("terminal-pair current diagnostic history missing")?;
    for previous in old["diagnostics"]
        .as_array()
        .context("inherited diagnostic history missing")?
    {
        let matches = current_rows
            .iter()
            .filter(|r| {
                r["epoch"] == previous["epoch"]
                    && r["unit"]["Id"] == previous["unit"]["Id"]
                    && r["launch_invocation_id"] == previous["launch_invocation_id"]
                    && r["launch_receipt"] == previous["launch_receipt"]
                    && r["launch_receipt_sha256"] == previous["launch_receipt_sha256"]
            })
            .count();
        ensure!(
            matches == 1,
            "terminal-pair dropped, duplicated or replaced historical diagnostic evidence"
        );
    }
    Ok(())
}
fn guard_partition(s: &Basis) -> Result<()> {
    let expected: BTreeSet<_> = HEALTHY
        .into_iter()
        .chain(ORIGINALS.iter().map(|p| p.1))
        .map(str::to_owned)
        .collect();
    ensure!(
        s.historical_guards.keys().cloned().collect::<BTreeSet<_>>() == expected
            && s.protected_guards
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == HEALTHY.into_iter().collect(),
        "terminal-pair must retain five historical and exactly three active guard bindings"
    );
    Ok(())
}
fn retained_guard_floor(name: &str, g: &Value, plan: &Value) -> Result<u64> {
    let minimum = g["minimum_free_bytes"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("historical protective floor missing")?;
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["unit"] == name
            && plan["minimum_free_bytes"] == minimum
            && plan["invocation_id"] == g["producer_invocation_id"],
        "historical protective floor or original plan binding changed"
    );
    Ok(minimum)
}
fn historical_floors(s: &Basis) -> Result<(u64, Value)> {
    guard_partition(s)?;
    let mut floor = 0;
    let mut rows = Vec::new();
    for (name, binding) in &s.historical_guards {
        let g = bound_json(binding)?;
        let p: BoundFile =
            serde_json::from_value(json!({"path":g["plan"],"sha256":g["plan_sha256"]}))?;
        let plan = bound_json(&p)?;
        let minimum = retained_guard_floor(name, &g, &plan)?;
        floor = floor.max(minimum);
        rows.push(json!({"unit":name,"guard":private157::binding(binding),"plan":private157::binding(&p),"minimum_free_bytes":minimum,"retained_as_floor":true}));
    }
    Ok((floor, json!(rows)))
}
fn active_guard_scopes(s: &Basis, f: &Value) -> Result<()> {
    for (name, binding) in &s.protected_guards {
        let old = bound_json(
            s.historical_guards
                .get(name)
                .context("active owner omitted from historical guard basis")?,
        )?;
        let current = bound_json(binding)?;
        let plan: BoundFile = serde_json::from_value(
            json!({"path":current["plan"],"sha256":current["plan_sha256"]}),
        )?;
        continuation_guards::same_guard(
            &old,
            &current,
            &bound_json(&plan)?,
            &f["unit_census"][name],
        )?;
    }
    Ok(())
}
fn complete_census(
    f: &Value,
    context: Option<&crate::holding::Foundation213RestoreContext<'_>>,
) -> Result<BTreeMap<String, Value>> {
    let mut names = f["unit_census"]
        .as_object()
        .context("terminal-pair complete census missing")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.extend(ORIGINALS.iter().map(|p| p.1.to_owned()));
    if let Some(c) = context {
        names.insert(c.unit_name().into());
    }
    let mut current = census(&names, 201, 300)?;
    // The old generic discovery namespace predates these private capped units.
    // Discover them as competitors, never exempt a scanner or a new native job.
    let output = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running,activating",
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 1 << 20,
        "terminal-pair capped-owner discovery failed"
    );
    let found: Vec<Value> = serde_json::from_slice(&output.stdout)?;
    for row in found {
        let name = row["unit"]
            .as_str()
            .context("terminal-pair discovered owner name missing")?;
        if (name.starts_with("horizon-capped204") || name.starts_with("horizon-capped205"))
            && !current.contains_key(name)
        {
            current.insert(name.into(), unit(name)?);
        }
    }
    if let Some(c) = context {
        singleton227_admission::owners_with_foundation_restore(f, &current, c)?;
    } else {
        singleton227_admission::owners(f, &current)?;
    }
    native210_peer_history::current(f, &current)?;
    prefix223_live_peer::current(f, &current)?;
    Ok(current)
}
fn floor(
    century: u64,
    growth: u64,
    active_guard: u64,
    historical_guard: u64,
    inherited: u64,
    running: u64,
) -> Result<u64> {
    Ok(century
        .checked_add(growth)
        .context("terminal-pair protected floor overflow")?
        .max(active_guard)
        .max(historical_guard)
        .max(inherited)
        .max(running))
}
pub(super) fn check(
    value: &Value,
    additional: u64,
    context: Option<&crate::holding::Foundation213RestoreContext<'_>>,
) -> Result<Value> {
    let s: Basis = serde_json::from_value(value.clone())?;
    ensure!(
        s.schema == SCHEMA
            && s.fleet
                .path
                .starts_with("/var/lib/jetstreamer/horizon-campaign-fleet"),
        "foreign terminal-pair maintenance basis"
    );
    if let Some(c) = context {
        ensure!(
            additional == 0,
            "typed continuation cannot issue another reservation"
        );
        c.revalidate()?;
        c.require_basis(value)?;
    }
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    ensure!(
        f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256,
        "terminal-pair fleet and observer differ"
    );
    live_roster(&f)?;
    native210_peer_history::validate(&f)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let entry = context.map_or(now, |c| c.entry_clock());
    let accounting = native227_terminal_observer_view(&f, &o)?;
    let sample = sampled(&accounting, &f, entry)?;
    let inherited_value = sealed(&s.inherited_capacity)?;
    let (old_floor, old_century, old_fleet) = inherited(&inherited_value, &s.historical_guards)?;
    preserve_diagnostics(&bound_json(&old_fleet)?, &f)?;
    let (historical_floor, historical_evidence) = historical_floors(&s)?;
    active_guard_scopes(&s, &f)?;
    let century = singleton227_admission::century_floor_for_maintenance(&f)?.max(old_century);
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(is_lower_hex(&boot, 32), "terminal-pair boot ID malformed");
    let before = complete_census(&f, context)?;
    let proofs = originals(&s, &f, &before, &boot)?;
    // Revalidate the admitted active receipts at entry before refreshing. Their
    // immutable scope is then compared on every genuine protective-fire refresh.
    prefix223_live_peer::disk(&f, &accounting, &s.protected_guards, sample, entry)?;
    let (guards, guard_history) =
        continuation_guards::refresh_terminal_pair(&f, &s.protected_guards, sample, now)?;
    let (growth, measurements) = prefix223_live_peer::disk(&f, &accounting, &guards, sample, now)?;
    let (_, active_floor) = native228_admission::protected_floor(century, growth, &guards)?;
    let mut minimum = floor(
        century,
        growth,
        active_floor,
        historical_floor,
        old_floor,
        context.map_or(0, |c| c.protected_floor()),
    )?;
    let sampled_free = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("terminal-pair sampled free bytes missing")?;
    let continuing = context.is_some_and(|c| c.entered());
    if !continuing {
        envelope(minimum, additional, sampled_free)?;
    }
    let actual_free = singleton227_admission::disk_free()?;
    envelope(minimum, additional, actual_free)?;
    let caps = prefix223_live_peer::limits(&f)?;
    let after = complete_census(&f, context)?;
    let after_proofs = originals(&s, &f, &after, &boot)?;
    ensure!(
        before == after && proofs == after_proofs && caps == prefix223_live_peer::limits(&f)?,
        "terminal-pair actual ownership or live controls changed"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sampled(&accounting, &f, context.map_or(now, |c| c.entry_clock()))?;
    let (after_guards, after_history) =
        continuation_guards::refresh_terminal_pair(&f, &s.protected_guards, sample, now)?;
    let (after_growth, after_measurements) =
        prefix223_live_peer::disk(&f, &accounting, &after_guards, sample, now)?;
    if continuing {
        let (_, after_floor) =
            native228_admission::protected_floor(century, after_growth, &after_guards)?;
        minimum = minimum.max(floor(
            century,
            after_growth,
            after_floor,
            historical_floor,
            old_floor,
            context.map_or(0, |c| c.protected_floor()),
        )?);
    } else {
        ensure!(
            after_growth <= growth,
            "terminal-pair protected growth increased during fresh admission"
        );
    }
    let final_free = singleton227_admission::disk_free()?;
    let required = envelope(minimum, additional, final_free)?;
    if let Some(c) = context {
        c.revalidate()?;
    }
    let mut result = json!({"schema":"jetstreamer-foundation-holding-capacity-v2","host":"horizon-vaultic","first_epoch":201,"last_epoch":300,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"resource_basis":value,"sampled_at_utc":f["sampled_at_utc"],
        "terminal_originals":proofs,"historical_protective_floors":historical_evidence,"inherited_capacity":private157::binding(&s.inherited_capacity),
        "inherited_fleet":private157::binding(&old_fleet),
        "inherited_minimum_free_bytes":old_floor,"century_floor_bytes":century,"maximum_historical_guard_floor_bytes":historical_floor,
        "maximum_existing_guard_floor_bytes":active_floor.max(historical_floor),"protected_remaining_growth_bytes":growth.max(after_growth),
        "minimum_free_bytes":minimum,"additional_restore_bytes":additional,"required_initial_free_bytes":required,"sampled_available_bytes":sampled_free,
        "actual_available_bytes_before":actual_free,"actual_available_bytes":final_free,"protected_growth_before":measurements,"protected_growth_after":after_measurements,
        "current_protected_guard_history_before":guard_history,"current_protected_guard_history_after":after_history,"protected_caps":caps,
        "unit_census_before":before,"unit_census_after":after,"recorded_unix_seconds":now,"maximum_age_seconds":900,
        "restore_only":true,"all_live_growth_and_century_floor_protected":true,"historical_floors_retained":true,"new_resource_samples":0,"reclamation_credit_bytes":0,
        "replay_launch_authorized":false,"local_retirement_authorized":false,"publication_authorized":false,"r2_mutations":false});
    if let Some(c) = context {
        result["self_maintenance_restore_accounting"] = c.evidence();
        result["entry_freshness_validation_unix_seconds"] = json!(entry);
        result["already_admitted_continuation_only"] = json!(continuing);
    }
    if let Some(e) = accounting.get("terminal_observation_accounting") {
        result["terminal_observation_accounting"] = e.clone();
    }
    Ok(result)
}

#[cfg(test)]
#[path = "foundation_holding_terminal_pair/tests.rs"]
mod tests;
