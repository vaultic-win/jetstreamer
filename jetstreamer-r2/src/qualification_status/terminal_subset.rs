//! Closed metadata handoff for naturally completed original 204/205 prefixes.
//! This omits old live countdowns only; it grants no replay or delivery authority.
use super::*;
use std::collections::BTreeSet;
pub(super) const SCHEMA: &str = "jetstreamer-qualification-status-plan-v2";
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Terminal {
    launch: Bound,
    producer_result: Bound,
    terminal_properties: Bound,
    manager_journal: Bound,
    #[serde(default)]
    successors: Vec<Successor>,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Successor {
    unit: String,
    invocation_id: String,
    phase: String,
    launch: Bound,
}
fn original_launch(epoch: u64) -> Result<(&'static str, &'static str)> {
    match epoch {
        204 => Ok((
            "/var/lib/jetstreamer/horizon-prefix204-launch-fcbf3992-v1/launch.json",
            "a1b38f09bb1314c9280ca924602bab1523d28755146919912f604c1ee9bbfdfb",
        )),
        205 => Ok((
            "/var/lib/jetstreamer/horizon-prefix205-launch-5c01bf93-v1/launch.json",
            "febbbb44b1d2b16afc3511e171dbb1f1aab732890893be1ce2f72239bc01ca9e",
        )),
        _ => anyhow::bail!("only original 204/205 prefixes may leave the live qualification set"),
    }
}
pub(super) fn sealed_bytes(b: &Bound) -> Result<Vec<u8>> {
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
        "original terminal evidence must be immutable root-owned sealed data"
    );
    let bytes = read_stable_bounded(
        &b.path,
        MAX_OBSERVER_RECEIPT_BYTES,
        "original terminal evidence",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "original terminal evidence digest differs"
    );
    Ok(bytes)
}
pub(super) fn sealed(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&sealed_bytes(b)?)?)
}
fn journal(bytes: &[u8]) -> Result<Vec<Value>> {
    ensure!(
        bytes.len() <= 1 << 20,
        "original terminal manager journal exceeds bound"
    );
    let rows = if bytes.first() == Some(&b'[') {
        serde_json::from_slice(bytes)?
    } else {
        bytes
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(serde_json::from_slice)
            .collect::<std::result::Result<Vec<Value>, _>>()?
    };
    ensure!(
        !rows.is_empty() && rows.len() <= 2048,
        "original terminal manager journal is empty or truncated"
    );
    Ok(rows)
}
fn command(value: &str) -> Option<&str> {
    let (identity, tail) = value.split_once(" ; ignore_errors=no")?;
    if tail == " }" {
        return Some(identity);
    }
    let fields = tail
        .strip_prefix(" ; start_time=")?
        .strip_suffix(" }")?
        .split(" ; ")
        .collect::<Vec<_>>();
    (fields.len() == 5
        && fields[0].starts_with('[')
        && fields[0].ends_with(']')
        && fields[1].starts_with("stop_time=[")
        && fields[1].ends_with(']')
        && fields[2]
            .strip_prefix("pid=")
            .is_some_and(|v| v.parse::<u32>().is_ok())
        && fields[3].starts_with("code=")
        && fields[4].starts_with("status=")
        && !fields[4].contains(['{', '}', '\n', '\r']))
    .then_some(identity)
}
fn owner(row: &Value) -> Result<&Value> {
    row.get("producer")
        .or_else(|| row.get("unit"))
        .filter(|v| v.is_object())
        .context("accepted fleet row has no actual owner")
}
fn terminal_state(p: &Profile, u: &Value, historical: bool) -> Result<()> {
    ensure!(
        u["Id"] == p.unit
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && u["ControlGroup"] == ""
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && ((u["LoadState"] == "loaded"
                && u["Result"] == "success"
                && u["ExecMainStatus"] == "0"
                && (u["InvocationID"] == p.iid || u["InvocationID"] == ""))
                || (!historical && u["LoadState"] == "not-found" && u["InvocationID"] == "")),
        "original prefix is live, failed, replaced or has ambiguous terminal state"
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
) -> Result<()> {
    let (launch, result, u) = artifacts;
    let p = profile(epoch)?;
    let (path, sha) = original_launch(epoch)?;
    ensure!(
        t.launch.path == Path::new(path) && t.launch.sha256 == sha,
        "original terminal launch binding differs from the genuine preserved attempt"
    );
    ensure!(
        launch["schema"]
            == format!("jetstreamer-private-epoch{epoch}-capped-root-prefix-launch-v1")
            && launch["epoch"] == epoch
            && launch["evidence"]["units"]
                .as_array()
                .is_some_and(|units| units.len() == 1)
            && launch["evidence"]["units"][0]["unit"] == p.unit
            && launch["evidence"]["units"][0]["invocation_id"] == p.iid
            && launch["private_run_root"] == p.root,
        "original prefix launch identity differs"
    );
    ensure!(
        result["schema"]
            == format!("jetstreamer-private-epoch{epoch}-shrink-root-prefix-resource-v1")
            && result["epoch"] == epoch
            && result["unit"] == p.unit
            && result["invocation_id"] == p.iid
            && result["success"] == true
            && result["error"].is_null()
            && result["child_return_code"] == 0
            && result["external_signal"] == 0
            && result["natural_parent_completion_required"] == true
            && result["producer_canonical_root_prefix_present"] == true
            && result["target_slot"] == p.terminal
            && result["terminal_root_slot"] == p.terminal
            && result["plan"]["sha256"] == launch["plan_sha256"],
        "original prefix lacks a genuine natural terminal producer receipt"
    );
    for key in [
        "runner_sha256",
        "node_sha256",
        "worker_sha256",
        "snapshot_sha256",
    ] {
        ensure!(
            result[key] == launch[key] && result[key].as_str().is_some_and(|v| is_lower_hex(v, 64)),
            "original terminal executable/input identity differs: {key}"
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
            "terminal prefix receipt grants unrelated authority: {key}"
        );
    }
    terminal_state(p, u, true)?;
    ensure!(
        command(
            u["ExecStart"]
                .as_str()
                .context("terminal command missing")?
        )
        .is_some()
            && command(u["ExecStart"].as_str().unwrap())
                == command(
                    launch["expected_exec_start"]
                        .as_str()
                        .context("original launch command missing")?
                ),
        "original terminal manager command differs"
    );
    let mut successes = 0;
    let mut completion = 0;
    for row in rows {
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == p.unit
                && row["INVOCATION_ID"] == p.iid
                && row["_BOOT_ID"] == boot,
            "original terminal manager journal contains another invocation or owner"
        );
        if row["MESSAGE"] == format!("{}: Deactivated successfully.", p.unit) {
            successes += 1;
            completion = row["__REALTIME_TIMESTAMP"]
                .as_str()
                .context("terminal manager clock missing")?
                .parse::<u64>()?;
        }
        ensure!(
            !row["MESSAGE"].as_str().is_some_and(|s| s.contains("Failed")
                || s.contains("failed")
                || s.contains("Killing")),
            "original terminal journal contains a failed or forced stop"
        );
    }
    ensure!(
        successes == 1
            && completion > 0
            && f["recorded_unix_seconds"]
                .as_u64()
                .and_then(|s| s.checked_mul(1_000_000))
                .is_some_and(|time| time >= completion),
        "accepted fleet predates the unique actual terminal completion"
    );
    Ok(())
}
fn recovery_successor_shape(epoch: u64, successor: &Successor, row: &Value) -> Result<()> {
    fleet::assembly204_recovery_binding_scope(
        epoch, &successor.unit,
        "horizon-qualify-204-assembly-only-recovery-v2.service",
        row["status"]["phase"].as_str().context("recovery successor wire phase missing")?,
    )?;
    ensure!(
        epoch == 204
            && successor.phase == "assembly-recovery204"
            && row["epoch"] == 204
            && row["phase"] == successor.phase
            && row["live"] == true
            && row["ordinary_replay_claim"] == false
            && row["source_failure_remains_failure"] == true
            && owner(row)?["Id"] == successor.unit
            && owner(row)?["InvocationID"] == successor.invocation_id
            && row["actor_launch"] == serde_json::to_value(&successor.launch)?
            && row["origin_launch"].is_object()
            && row["recovery_plan"].is_object(),
        "epoch 204 recovery successor differs from its complete accepted row"
    );
    Ok(())
}
fn recovery_current(p: &Plan, f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    for (epoch, terminal) in &p.omitted_originals {
        for successor in &terminal.successors {
            if successor.phase == "assembly-recovery204" {
                ensure!(*epoch == 204, "recovery successor belongs only to epoch 204");
                fleet::qualification_recovery204_successor(
                    f,
                    current,
                    &successor.unit,
                    &successor.invocation_id,
                    &serde_json::to_value(&successor.launch)?,
                )?;
            }
        }
    }
    Ok(())
}
fn active_scope(p: &Plan, f: &Value) -> Result<()> {
    let epochs = plan_epochs(p)?;
    let active = f["active"]
        .as_array()
        .context("complete accepted active fleet missing")?;
    let mut live_names = BTreeSet::new();
    for row in active {
        let u = owner(row)?;
        let unit = u["Id"]
            .as_str()
            .filter(|unit| !unit.is_empty())
            .context("active owner ID missing")?;
        ensure!(
            live_names.insert(unit) && f["unit_census"][unit] == *u,
            "accepted active owner is duplicated or differs from the complete census"
        );
    }
    for original in &PROFILES {
        let matching = active
            .iter()
            .filter(|row| owner(row).is_ok_and(|u| u["Id"] == original.unit))
            .collect::<Vec<_>>();
        if epochs.contains(&original.first)
            || p.delegated_verification.contains_key(&original.first)
        {
            let phase = if original.first < 225 {
                "private-known-root-prefix"
            } else {
                "diagnostic-qualification"
            };
            ensure!(
                matching.len() == 1
                    && matching[0]["epoch"] == original.first
                    && matching[0]["phase"] == phase
                    && owner(matching[0])?["InvocationID"] == original.iid,
                "remaining original profile is missing, duplicated or in another phase"
            );
        } else {
            ensure!(
                matching.is_empty(),
                "cannot omit an original owner that is still live"
            );
        }
    }
    for (epoch, t) in &p.omitted_originals {
        let original = profile(*epoch)?;
        terminal_state(original, &f["unit_census"][original.unit], false)?;
        let replacements = active
            .iter()
            .filter(|row| row["epoch"] == *epoch)
            .collect::<Vec<_>>();
        ensure!(
            replacements.len() == t.successors.len(),
            "terminal epoch has an omitted or unexpected replacement owner"
        );
        let mut seen = BTreeSet::new();
        for successor in &t.successors {
            ensure!(
                (successor.phase == "capped204205-continuation"
                    || (*epoch == 204 && successor.phase == "assembly-recovery204"))
                    && seen.insert(successor.unit.as_str()),
                "replacement must be a distinct independently bound continuation/verification owner"
            );
            let matches = replacements
                .iter()
                .filter(|r| owner(r).is_ok_and(|u| u["Id"] == successor.unit))
                .collect::<Vec<_>>();
            ensure!(matches.len() == 1, "replacement owner missing or duplicated");
            if successor.phase == "assembly-recovery204" {
                recovery_successor_shape(*epoch, successor, matches[0])?;
            } else {
                ensure!(
                    matches[0]["phase"] == successor.phase
                        && owner(matches[0])?["InvocationID"] == successor.invocation_id
                        && matches[0]["launch"]
                            == json!({"path":successor.launch.path,"sha256":successor.launch.sha256}),
                    "replacement owner phase, invocation or accepted launch binding differs"
                );
            }
        }
    }
    Ok(())
}
fn loaded_terminal(p: &Plan, f: &Value, boot: &str) -> Result<BTreeMap<u64, Vec<Value>>> {
    let mut journals = BTreeMap::new();
    for (epoch, t) in &p.omitted_originals {
        let rows = journal(&sealed_bytes(&t.manager_journal)?)?;
        terminal_value(
            *epoch,
            t,
            (
                &sealed(&t.launch)?,
                &sealed(&t.producer_result)?,
                &sealed(&t.terminal_properties)?,
            ),
            &rows,
            f,
            boot,
        )?;
        let original = profile(*epoch)?;
        terminal_state(original, &f["unit_census"][original.unit], false)?;
        let diagnostics = f["diagnostics"]
            .as_array()
            .context("original diagnostic history missing")?
            .iter()
            .filter(|row| row["epoch"] == *epoch && row["unit"]["Id"] == original.unit)
            .collect::<Vec<_>>();
        ensure!(
            diagnostics.len() == 1
                && diagnostics[0]["live"] == false
                && diagnostics[0]["launch_invocation_id"] == original.iid
                && diagnostics[0]["launch_receipt"].as_str() == t.launch.path.to_str()
                && diagnostics[0]["launch_receipt_sha256"] == t.launch.sha256,
            "accepted fleet dropped or changed the original terminal diagnostic history"
        );
        for successor in &t.successors {
            if successor.phase == "assembly-recovery204" {
                // Typed recovery validation is additional to the unchanged original
                // terminal proof above. The saved fleet is never projected or edited.
                let current = serde_json::from_value(f["unit_census"].clone())?;
                fleet::qualification_recovery204_successor(
                    f, &current, &successor.unit, &successor.invocation_id,
                    &serde_json::to_value(&successor.launch)?,
                )?;
                continue;
            }
            let origin = sealed(&successor.launch)?;
            ensure!(
                origin["schema"] == "jetstreamer-capped204205-continuation-launch-v1"
                    && origin["epoch"] == *epoch,
                "replacement does not bind the separately qualified continuation launch"
            );
        }
        journals.insert(*epoch, rows);
    }
    Ok(journals)
}
fn same_census(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    ensure!(
        serde_json::to_value(current)? == f["unit_census"],
        "complete owner census changed after accepted fleet"
    );
    Ok(())
}
pub(super) fn current(p: &Plan, f: &Value) -> Result<()> {
    if p.schema != SCHEMA {
        return Ok(());
    }
    ensure!(
        f["schema"] == "jetstreamer-horizon-campaign-fleet-v1",
        "v2 status requires complete accepted fleet"
    );
    active_scope(p, f)?;
    for (epoch, binding) in &p.delegated_verification {
        ensure!(
            *epoch == 205,
            "only the exact live original 205 verification phase can be delegated"
        );
        super::verification205::delegation(binding, f)?;
    }
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let journals = loaded_terminal(p, f, &boot)?;
    let bound = f["unit_census"]
        .as_object()
        .context("v2 fleet unit census missing")?;
    let names = bound.keys().cloned().collect::<BTreeSet<_>>();
    let before = fleet::census(&names, 201, 300)?;
    same_census(f, &before)?;
    recovery_current(p, f, &before)?;
    for (epoch, rows) in journals {
        let original = profile(epoch)?;
        inactive_status::no_pending_owner_trigger(
            original.unit,
            before[original.unit]["LoadState"] == "not-found",
        )?;
        let out = ProcessCommand::new("/usr/bin/journalctl")
            .args([
                "--unit",
                original.unit,
                "_PID=1",
                "--output=json",
                "--no-pager",
            ])
            .output()?;
        ensure!(
            out.status.success() && journal(&out.stdout)? == rows,
            "original manager history was lost, restarted or replaced after terminal proof"
        );
    }
    let after = fleet::census(&names, 201, 300)?;
    ensure!(
        after == before,
        "replacement or original owner changed during v2 status checks"
    );
    recovery_current(p, f, &after)?;
    Ok(())
}
#[cfg(test)]
mod tests;
