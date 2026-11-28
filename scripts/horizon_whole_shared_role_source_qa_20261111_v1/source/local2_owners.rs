//! Exact current local2 owner/protection adapter. Read-only finite evidence;
//! no future shared-role envelope, accounting selection or admission authority.
use super::*;
use std::collections::BTreeMap;

fn pins() -> Result<Value> {
    Ok(serde_json::from_str(include_str!("local2-owners.json"))?)
}
fn owners(p: &Value) -> Result<&Vec<Value>> {
    let rows = p["owners"]
        .as_array()
        .context("immutable local2 profiles")?;
    ensure!(rows.len() == 7, "seven immutable local2 profiles required");
    Ok(rows)
}
fn selected(p: &Value, epoch: u64) -> Result<&Value> {
    owners(p)?
        .iter()
        .find(|r| r["epoch"] == epoch)
        .context("epoch is not a current local2 owner")
}
pub(super) fn validate_request(plan: &Value) -> Result<()> {
    ensure!(
        plan["owner_basis"] == "exact-current-seven-local2-20261110-v1",
        "explicit current local2 basis required"
    );
    for key in [
        "resource_promise_ending_authorized",
        "replay_launch_authorized",
        "native_Frame_or_full_Reader_authority",
        "future_host_or_shared_role_bound_claimed",
    ] {
        ensure!(plan[key] == false, "forbidden projection authority: {key}");
    }
    let proofs = plan["current_guard_proofs"]
        .as_array()
        .context("fresh guard proof bindings")?;
    let epochs = proofs
        .iter()
        .map(|r| n(r, "epoch"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        proofs.len() == 7 && epochs == (166..=172).collect(),
        "all seven fresh guard proof bindings required"
    );
    for row in proofs {
        let b = &row["proof"];
        let path = Path::new(s(b, "path")?);
        let digest = s(b, "sha256")?;
        ensure!(
            path.is_absolute()
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && digest.bytes().any(|c| c != b'0'),
            "genuine fresh proof digest required"
        );
    }
    Ok(())
}
fn identity_fields(actual: &Value, p: &Value) -> Result<()> {
    ensure!(
        actual["Id"] == p["unit"]
            && actual["InvocationID"] == p["iid"]
            && s(actual, "MainPID")?.parse::<u64>()? == n(p, "pid")?
            && actual["ActiveState"] == "active"
            && actual["SubState"] == "running"
            && actual["ControlPID"] == "0"
            && actual["NRestarts"] == "0"
            && actual["Job"] == "",
        "exact current local2 original birth identity required"
    );
    Ok(())
}
fn profile_fields(actual: &Value, p: &Value) -> Result<()> {
    identity_fields(actual, p)?;
    for (key, value) in p["whole_service_profile"]
        .as_object()
        .context("pinned whole service profile")?
    {
        ensure!(
            actual[key] == *value,
            "local2 whole-service profile changed: {key}"
        );
    }
    Ok(())
}
pub(super) fn whole_service(actual: &Value) -> Result<()> {
    let p = pins()?;
    let exact = owners(&p)?
        .iter()
        .find(|r| r["unit"] == actual["Id"])
        .context("not an exact current local2 service")?;
    profile_fields(actual, exact)?;
    ensure!(
        actual["MemoryAccounting"] == "yes"
            && actual["MemoryMax"] == "73014444032"
            && actual["MemorySwapMax"] == "0"
            && actual["Delegate"] == "no"
            && actual["ControlGroup"] == format!("/system.slice/{}", s(exact, "unit")?),
        "complete own-service68GiB zero-swap hierarchical envelope required"
    );
    Ok(())
}
pub(super) fn validate_fleet(fleet: &Value) -> Result<Value> {
    let p = pins()?;
    let rows = fleet["actual_executing_replays"]
        .as_array()
        .context("current seven local2 rows")?;
    ensure!(
        rows.len() == 7
            && fleet["terminal_producer_count"] == 7
            && fleet["authenticated_status_count"] == 19
            && fleet["terminal_producer_event"] == p["terminal_producer_event"]
            && fleet["actual_active_bootstraps"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "current local2 seven plus seven terminal histories and19 statuses required"
    );
    let epochs = fleet["epochs"]
        .as_array()
        .context("full assigned epoch table")?;
    ensure!(
        epochs.len() == 100
            && epochs
                .iter()
                .map(|r| n(r, "epoch"))
                .collect::<Result<BTreeSet<_>>>()?
                == (101..=200).collect(),
        "complete101–200 fleet required"
    );
    let terminals = fleet["terminal_producers"]
        .as_array()
        .context("all original terminal histories")?;
    ensure!(
        terminals.len() == 7,
        "all seven original terminal histories required"
    );
    for old in p["terminal_producers"]
        .as_array()
        .context("pinned original histories")?
    {
        let matching = terminals
            .iter()
            .filter(|r| r["epoch"] == old["epoch"])
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "duplicate or missing original terminal epoch"
        );
        for (key, value) in old
            .as_object()
            .context("original terminal history object")?
        {
            ensure!(
                matching[0][key] == *value,
                "original terminal history/promise changed: {key}"
            );
        }
    }
    let mut seen = BTreeSet::new();
    let mut iids = BTreeSet::new();
    let mut groups = BTreeSet::new();
    for row in rows {
        let epoch = n(row, "epoch")?;
        let exact = selected(&p, epoch)?;
        ensure!(
            seen.insert(epoch)
                && iids.insert(s(exact, "iid")?)
                && groups.insert(s(&exact["whole_service_profile"], "ControlGroup")?),
            "duplicate epoch/IID/cgroup consumption"
        );
        identity_fields(&row["unit"], exact)?;
        profile_fields(&row["native_producer_profile"], exact)?;
        let d = &row["declaration"];
        ensure!(
            row["phase"] == "replay"
                && row["useful_transaction_replay"] == true
                && row["source_start_unix_seconds"] == exact["start"]
                && row["source_start_native"] == exact["start_native"]
                && row["run_directory"] == exact["run_directory"]
                && row["admission"] == exact["admission"]
                && row["guard_protection"] == exact["guard_protection"]
                && row["DATA_guard_handoff"] == exact["handoff"]
                && d["unit"] == exact["unit"]
                && d["invocation_id"] == exact["iid"]
                && s(d, "main_pid")?.parse::<u64>()? == n(exact, "pid")?
                && d["original_start_unix_seconds"] == exact["start"]
                && d["original_start_native"] == exact["start_native"]
                && d["admission"] == exact["admission"]
                && d["guard_protection"] == exact["guard_protection"]
                && d["DATA_guard_handoff"] == exact["handoff"],
            "current local2 birth/admission/protection history changed"
        );
        let complete = epochs
            .iter()
            .find(|r| r["epoch"] == epoch)
            .context("full current epoch row")?;
        ensure!(
            complete["state"] == "live-replay" && complete["current_live_producer"] == row["unit"],
            "active owner/full row mismatch"
        );
    }
    ensure!(
        seen == (166..=172).collect()
            && fleet["stable_non_replay_owners"] == p["stable_non_replay_owners"],
        "all seven local2 owners and both persistent owner identities retained"
    );
    Ok(
        json!({"source_pins_fleet":p["source_fleet"],"immutable_owner_profiles":p["owners"],
        "shared_native_verifier_normal_pools_retained_bytes":[64*GIB,16*GIB,96*GIB,10*GIB],
        "all_whole_service_and_shared_role_future_gates_still_required":true,"resource_credit_bytes":0}),
    )
}
fn admission(a: &Value, p: &Value) -> Result<()> {
    ensure!(
        a["schema"] == "horizon-standard-replacement-admission-v1"
            && a["owner"] == "/root"
            && a["primary_thread"] == PRIMARY
            && a["epoch"] == p["epoch"]
            && a["producer_unit"] == p["unit"]
            && a["producer_invocation_id"] == p["iid"]
            && a["producer_pid"] == p["pid"]
            && a["fresh_admission_passed"] == true
            && a["all_existing_growth_and_floor_protected"] == true
            && a["all_prior_promises_retained"] == true
            && a["old_partial_and_inputs_preserved"] == true
            && a["candidate_hard_memory_bytes"] == CAP
            && a["guard_minimum_free_bytes"] == data_guard_reader::FLOOR
            && a["resource_credit_bytes"] == 0
            && a["memory_or_DATA_promise_ending_bytes"] == 0
            && a["remote_mutations"] == false
            && a["r2_mutations"] == false,
        "exact retained original local2 admission required"
    );
    Ok(())
}
fn shared<T>(result: data_guard_reader::R<T>) -> Result<T> {
    result.map_err(|error| anyhow::anyhow!("{error}"))
}
fn context(p: &Value) -> Result<data_guard_reader::Context<'_>> {
    Ok(data_guard_reader::Context {
        epoch: n(p, "epoch")?,
        unit: s(p, "unit")?,
        iid: s(p, "iid")?,
        pid: n(p, "pid")?,
        start: n(p, "start")?,
        original_protection: &p["guard_protection"],
    })
}
fn command_identity(actual: &str, image: &str, argv: &[String]) -> Result<()> {
    let inner = actual
        .strip_prefix("{ ")
        .and_then(|v| v.strip_suffix(" }"))
        .context("one native guard command")?;
    let mut fields = BTreeMap::new();
    for member in inner.split(" ; ") {
        let (key, value) = member
            .split_once('=')
            .context("native guard command field")?;
        ensure!(
            fields.insert(key, value).is_none(),
            "duplicate guard command field"
        );
    }
    ensure!(
        fields.keys().copied().collect::<BTreeSet<_>>()
            == BTreeSet::from([
                "path",
                "argv[]",
                "ignore_errors",
                "start_time",
                "stop_time",
                "pid",
                "code",
                "status"
            ])
            && fields["path"] == image
            && fields["ignore_errors"] == "no"
            && fields["argv[]"]
                .split_whitespace()
                .eq(argv.iter().map(String::as_str)),
        "exact normally registered guard executable/argv required"
    );
    Ok(())
}
fn timer(t: &Value, p: &Value) -> Result<()> {
    ensure!(
        t["Id"] == p["timer_unit"]
            && t["InvocationID"] == p["timer_invocation_id"]
            && t["LoadState"] == "loaded"
            && t["ActiveState"] == "active"
            && matches!(
                t["SubState"].as_str(),
                Some("waiting" | "running" | "elapsed")
            )
            && t["Triggers"] == p["guard_unit"]
            && t["Job"] == "",
        "current exact protective timer is not armed"
    );
    Ok(())
}
fn service(v: &Value, p: &Value, a: &data_guard_reader::Accepted) -> Result<()> {
    ensure!(
        v["Id"] == p["guard_unit"]
            && v["LoadState"] == "loaded"
            && v["Restart"] == "no"
            && v["NRestarts"] == "0"
            && v["MemoryMax"] == "1073741824"
            && v["MemorySwapMax"] == "0"
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0",
        "unchanged successful1GiB protective service required"
    );
    let completed = v["ActiveState"] == "inactive"
        && v["SubState"] == "dead"
        && v["MainPID"] == "0"
        && v["ControlPID"] == "0"
        && v["Job"] == "";
    let running = (v["ActiveState"] == "activating"
        && matches!(v["SubState"].as_str(), Some("start" | "start-pre")))
        || (v["ActiveState"] == "active" && v["SubState"] == "running");
    ensure!(
        completed || running,
        "unknown or failed protective transition"
    );
    let image = s(&a.runtime, "path")?;
    let digest = s(&a.runtime, "sha256")?;
    command_identity(
        s(v, "ExecStart")?,
        image,
        &[
            image.into(),
            s(&p["plan"], "path")?.into(),
            "--plan-sha256".into(),
            s(&p["plan"], "sha256")?.into(),
            "--self-sha256".into(),
            digest.into(),
        ],
    )?;
    Ok(())
}
pub(super) fn current_guards(plan: &Value, fleet: &Value, clock: u64) -> Result<Value> {
    validate_request(plan)?;
    let p = pins()?;
    let proofs = plan["current_guard_proofs"]
        .as_array()
        .context("current proof list")?;
    let rows = fleet["actual_executing_replays"]
        .as_array()
        .context("current local2 owners")?;
    let mut captures = Vec::new();
    for exact in owners(&p)? {
        let epoch = n(exact, "epoch")?;
        let c = context(exact)?;
        let per_clock = now()?;
        ensure!(per_clock >= clock, "guard capture clock regressed");
        let row = rows
            .iter()
            .find(|r| r["epoch"] == epoch)
            .context("current local2 fleet row")?;
        ensure!(
            row["DATA_guard_handoff"] == exact["handoff"],
            "present handoff must match original accepted successor"
        );
        admission(&bound(&exact["admission"])?, exact)?;
        let original = bound(&exact["guard_protection"])?;
        let accepted = shared(data_guard_reader::load_handoff(
            &exact["handoff"],
            &c,
            clock,
        ))?;
        let proof_binding = &proofs
            .iter()
            .find(|r| r["epoch"] == epoch)
            .context("fresh exact guard proof")?["proof"];
        let proof = bound(proof_binding)?;
        let sample = bound(&proof["receipt"])?;
        shared(data_guard_reader::sample(
            &accepted, &sample, &c, clock, true,
        ))?;
        shared(data_guard_reader::proof(&accepted, &proof, &sample, &c))?;
        let mut closed = serde_json::Map::new();
        for (key, is_service) in [("timer_unit", false), ("guard_unit", true)] {
            let value = native(s(&original, key)?)?;
            shared(data_guard_reader::current_old_terminal(
                &accepted,
                &value,
                &original[key],
                is_service,
            ))?;
            closed.insert(key.into(), value);
        }
        let active_timer = native(s(&accepted.protection, "timer_unit")?)?;
        timer(&active_timer, &accepted.protection)?;
        let active_service = native(s(&accepted.protection, "guard_unit")?)?;
        service(&active_service, &accepted.protection, &accepted)?;
        let image = Path::new(s(&accepted.runtime, "path")?);
        ensure!(
            sha(&bytes(image, 32 << 20, false)?) == s(&accepted.runtime, "sha256")?,
            "normally registered protective image changed"
        );
        let receipt_directory = Path::new(s(&accepted.plan, "receipt_directory")?);
        ensure!(
            receipt_directory.is_absolute()
                && receipt_directory.canonicalize()? == receipt_directory
                && !receipt_directory.join("stop-intent.json").try_exists()?
                && !receipt_directory
                    .join("stop-completion.json")
                    .try_exists()?,
            "protective stop lifecycle has begun"
        );
        whole_service(&native(c.unit)?)?;
        captures.push(json!({"epoch":epoch,"original_admission":exact["admission"],"original_protection":exact["guard_protection"],
            "continuous_handoff":exact["handoff"],"fresh_native_PID1_timer_proof":proof_binding,"sample_recorded_unix_seconds":sample["recorded_unix_seconds"],
            "current_successor_timer":active_timer,"current_successor_service":active_service,"old_scopes_terminal":closed,
            "future_whole_service_or_shared_role_envelope_proven":false,"resource_credit_bytes":0}));
    }
    let captured = json!(captures);
    ensure!(
        protection_expiry(&captured)? >= now()?,
        "a guard proof expired during complete owner capture"
    );
    Ok(captured)
}
pub(super) fn protection_expiry(captures: &Value) -> Result<u64> {
    let rows = captures.as_array().context("guard capture expiry list")?;
    ensure!(rows.len() == 7, "complete seven-guard expiry required");
    rows.iter()
        .map(|r| {
            n(r, "sample_recorded_unix_seconds")?
                .checked_add(45)
                .context("guard proof expiry overflow")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .min()
        .context("guard expiry absent")
}
#[cfg(test)]
#[path = "local2_owners_tests.rs"]
mod tests;
