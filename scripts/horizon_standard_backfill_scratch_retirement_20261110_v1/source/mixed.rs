//! Disjoint peer preservation through an accepted complete fleet and explicit
//! admission/guard receipts. This module never admits or starts a peer.
use super::*;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct OtherLive {
    epoch: u64,
    phase: String,
    producer_unit: String,
    producer_invocation_id: String,
    producer_pid: u32,
    admission: Bound,
    guard_protection: Bound,
}

fn named_unit(value: &str, suffix: &str) -> bool {
    value.len() <= 255
        && value.ends_with(suffix)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
}

fn shapes(peer: &OtherLive, selected: u64) -> Result<()> {
    ensure!(
        (166..=172).contains(&peer.epoch) && peer.epoch != selected,
        "peer must be an exact disjoint original campaign epoch"
    );
    ensure!(
        matches!(peer.phase.as_str(), "replay" | "bootstrap")
            && named_unit(&peer.producer_unit, ".service")
            && peer.producer_pid > 0
            && peer.producer_invocation_id.len() == 32
            && peer
                .producer_invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid peer phase or exact producer identity"
    );
    for b in [&peer.admission, &peer.guard_protection] {
        ensure!(
            b.path.is_absolute() && lower_sha(&b.sha256),
            "peer authority must be separately hash bound"
        );
    }
    Ok(())
}

fn row<'a>(fleet: &'a Value, peer: &OtherLive) -> Result<&'a Value> {
    let key = if peer.phase == "replay" {
        "actual_executing_replays"
    } else {
        "actual_active_bootstraps"
    };
    let rows = fleet[key]
        .as_array()
        .context("complete actual peer owner list required")?;
    let matches = rows
        .iter()
        .filter(|r| r["epoch"] == peer.epoch)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "peer missing or duplicated in accepted complete fleet"
    );
    Ok(matches[0])
}

/// Every currently active producer must be explicitly listed. An old seven-live
/// observer, an unbound PID, or an unregistered admission does not fill the gap.
pub(super) fn fleet_shape(fleet: &Value, peers: &[OtherLive], selected: u64) -> Result<()> {
    ensure!(peers.len() <= 6, "too many disjoint peer roles");
    let mut epochs = BTreeSet::new();
    let mut units = BTreeSet::new();
    let mut replay_count = 0;
    let mut bootstrap_count = 0;
    for peer in peers {
        shapes(peer, selected)?;
        ensure!(
            epochs.insert(peer.epoch) && units.insert(peer.producer_unit.clone()),
            "duplicate or overlapping peer claim"
        );
        let live = row(fleet, peer)?;
        ensure!(
            live["unit"]["Id"] == peer.producer_unit
                && live["unit"]["InvocationID"] == peer.producer_invocation_id
                && live["unit"]["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    == Some(peer.producer_pid)
                && live["unit"]["ControlPID"] == "0"
                && live["unit"]["NRestarts"] == "0"
                && live["unit"]["ActiveState"] == "active"
                && live["unit"]["SubState"] == "running",
            "peer native owner differs from accepted complete fleet"
        );
        ensure!(
            live["admission"] == serde_json::to_value(&peer.admission)?
                && live["guard_protection"] == serde_json::to_value(&peer.guard_protection)?,
            "accepted mixed fleet must explicitly register the exact peer admission and guard receipts"
        );
        if peer.phase == "replay" {
            replay_count += 1;
        } else {
            bootstrap_count += 1;
        }
    }
    let replays = fleet["actual_executing_replays"]
        .as_array()
        .context("actual replay list required")?;
    let bootstraps = fleet["actual_active_bootstraps"]
        .as_array()
        .context("actual bootstrap list required")?;
    ensure!(
        replays.len() == replay_count
            && bootstraps.len() == bootstrap_count
            && fleet["live_replay_count"] == replay_count
            && fleet["guarded_bootstrap_owner_count"] == bootstrap_count
            && fleet["active_producer_count"] == peers.len(),
        "active peer census is incomplete or an undeclared producer appeared"
    );
    ensure!(
        !covers_target(&fleet["actual_executing_replays"])
            && !covers_target(&fleet["actual_active_bootstraps"]),
        "target still has an active claim"
    );
    Ok(())
}

fn receipt_shape(
    admission: &Value,
    protection: &Value,
    peer: &OtherLive,
    event: &Bound,
    fleet_time: u64,
) -> Result<()> {
    ensure!(
        admission["schema"] == "horizon-standard-replacement-admission-v1"
            && admission["owner"] == "/root"
            && admission["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53"
            && admission["epoch"] == peer.epoch
            && admission["producer_unit"] == peer.producer_unit
            && admission["producer_invocation_id"] == peer.producer_invocation_id
            && admission["producer_pid"] == peer.producer_pid
            && admission["original_stop_event"] == serde_json::to_value(event)?,
        "exact Root replacement admission binding required"
    );
    let admitted_at = admission["recorded_unix_seconds"]
        .as_u64()
        .context("peer admission clock")?;
    ensure!(
        admitted_at <= fleet_time
            && admission["fresh_admission_passed"] == true
            && admission["all_existing_growth_and_floor_protected"] == true
            && admission["all_prior_promises_retained"] == true
            && admission["old_partial_and_inputs_preserved"] == true
            && admission["resource_credit_bytes"] == 0
            && admission["memory_or_DATA_promise_ending_bytes"] == 0
            && admission["node_sha256"] == NODE_SHA
            && admission["worker_sha256"] == WORKER_SHA
            && admission["candidate_hard_memory_bytes"] == 73_014_444_032u64
            && admission["remote_mutations"] == false
            && admission["r2_mutations"] == false,
        "peer admission must retain original promises and every standard-runtime gate"
    );
    ensure!(
        protection["schema"] == "horizon-standard-live-peer-protection-v1"
            && protection["owner"] == "/root"
            && protection["epoch"] == peer.epoch
            && protection["producer_unit"] == peer.producer_unit
            && protection["producer_invocation_id"] == peer.producer_invocation_id
            && protection["admission"] == serde_json::to_value(&peer.admission)?,
        "exact accepted live-peer protection receipt required"
    );
    Ok(())
}

const GUARD_IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-original141-trace-guard-20261023-v1/jetstreamer-horizon-standalone-guard";
const GUARD_SHA: &str = "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";

fn guard_command(text: &str, plan: &Bound) -> Result<()> {
    let inner = text
        .strip_prefix("{ ")
        .and_then(|s| s.strip_suffix(" }"))
        .context("one canonical guard command required")?;
    let mut fields = BTreeMap::new();
    for item in inner.split(" ; ") {
        let (key, value) = item
            .split_once('=')
            .context("guard command property delimiter")?;
        ensure!(
            fields.insert(key, value).is_none(),
            "duplicate guard command property"
        );
    }
    ensure!(
        fields.len() == 8
            && [
                "path",
                "argv[]",
                "ignore_errors",
                "start_time",
                "stop_time",
                "pid",
                "code",
                "status"
            ]
            .iter()
            .all(|key| fields.contains_key(key)),
        "unexpected command count or property"
    );
    let expected = [
        GUARD_IMAGE,
        plan.path.to_str().context("guard plan UTF8")?,
        "--plan-sha256",
        &plan.sha256,
        "--self-sha256",
        GUARD_SHA,
    ];
    ensure!(
        fields["path"] == GUARD_IMAGE
            && fields["argv[]"].split_whitespace().collect::<Vec<_>>() == expected
            && fields["ignore_errors"] == "no",
        "exact guard executable/argv/ignore-errors differs"
    );
    Ok(())
}

fn completed_guard(
    service: &Value,
    sample: &Value,
    peer: &OtherLive,
    plan: &Bound,
    current: u64,
) -> Result<()> {
    let iid = service["InvocationID"]
        .as_str()
        .context("completed guard IID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && service["LoadState"] == "loaded"
            && service["ActiveState"] == "inactive"
            && service["SubState"] == "dead"
            && service["MainPID"] == "0"
            && service["ControlPID"] == "0"
            && service["NRestarts"] == "0"
            && service["Result"] == "success"
            && service["ExecMainStatus"] == "0"
            && service["Job"] == "",
        "guard has no genuine quiet successful completion"
    );
    let at = sample["recorded_unix_seconds"]
        .as_u64()
        .context("completed guard clock")?;
    ensure!(
        at <= current
            && current - at <= 45
            && sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["guard_invocation_id"] == iid
            && sample["guard_sha256"] == GUARD_SHA
            && sample["producer_invocation_id"] == peer.producer_invocation_id
            && sample["plan_sha256"] == plan.sha256
            && sample["producer_stop_enabled"] == true
            && sample.get("trip_reason") == Some(&Value::Null)
            && sample.get("worker_observation_error") == Some(&Value::Null)
            && sample.get("root_physical_observation_error") == Some(&Value::Null),
        "recent successful matching guard sample required"
    );
    Ok(())
}

fn guard_journal(unit: &str, iid: &str) -> Result<Value> {
    let result = Command::new("/usr/bin/journalctl")
        .args([
            "--all",
            "--no-pager",
            "-ojson",
            "-u",
            unit,
            "_PID=1",
            &format!("INVOCATION_ID={iid}"),
        ])
        .output()?;
    ensure!(
        result.status.success() && result.stderr.is_empty() && result.stdout.len() <= 1 << 20,
        "genuine bounded guard PID1 journal query failed"
    );
    let rows = std::str::from_utf8(&result.stdout)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.iter().any(|v| v["_PID"] == "1"
            && v["UNIT"] == unit
            && v["INVOCATION_ID"] == iid
            && (v["UNIT_RESULT"] == "success"
                || v["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")),
        "exact guard's original PID1 successful terminal event absent"
    );
    Ok(json!({"unit":unit,"invocation_id":iid,"journal_sha256":sha(&result.stdout),"events":rows}))
}

pub(super) fn same_peers(before: &Value, after: &Value) -> Result<()> {
    let a = before.as_object().context("first protected peer set")?;
    let b = after.as_object().context("last protected peer set")?;
    ensure!(a.keys().eq(b.keys()), "protected peer set changed");
    for (key, value) in a {
        ensure!(
            value["stable"] == b[key]["stable"],
            "protected peer producer/timer/plan changed"
        );
    }
    Ok(())
}

/// Kernel identities and genuine guard state are revalidated before and after
/// every selected-target gate. Periodic guard invocation IDs may roll; the
/// producer, armed timer, guard image/plan and resource profile may not change.
pub(super) fn live_peers(peers: &[OtherLive], fleet: &Value, event: &Bound) -> Result<Value> {
    fleet_shape(fleet, peers, EPOCH)?;
    let mut output = BTreeMap::new();
    for peer in peers {
        let admission = json_bound(&peer.admission)?;
        let protection = json_bound(&peer.guard_protection)?;
        let fleet_time = fleet["recorded_unix_seconds"]
            .as_u64()
            .context("fleet clock")?;
        receipt_shape(&admission, &protection, peer, event, fleet_time)?;
        let producer = native(&peer.producer_unit)?;
        ensure!(
            producer["Id"] == peer.producer_unit
                && producer["InvocationID"] == peer.producer_invocation_id
                && producer["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    == Some(peer.producer_pid)
                && producer["ControlPID"] == "0"
                && producer["NRestarts"] == "0"
                && producer["ActiveState"] == "active"
                && producer["SubState"] == "running"
                && producer["Job"] == ""
                && producer["MemoryMax"] == "73014444032"
                && producer["MemorySwapMax"] == "0"
                && producer["Restart"] == "no",
            "accepted disjoint producer changed or is no longer protected by the qualified standard profile"
        );
        let guard_binding: Bound = serde_json::from_value(protection["plan"].clone())?;
        let guard = json_bound(&guard_binding)?;
        ensure!(
            guard["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
                && guard["unit"] == peer.producer_unit
                && guard["invocation_id"] == peer.producer_invocation_id
                && guard["minimum_free_bytes"] == admission["guard_minimum_free_bytes"]
                && guard["worker_root"] == admission["lane_root"],
            "peer guard plan no longer matches admitted owner/floor/root"
        );
        let lane = Path::new(admission["lane_root"].as_str().context("peer lane root")?);
        ensure!(
            lane.is_absolute()
                && lane.canonicalize()? == lane
                && !lane.starts_with(LANE)
                && !Path::new(LANE).starts_with(lane),
            "peer live tree overlaps the deletion target"
        );
        let first_binding: Bound =
            serde_json::from_value(protection["first_guard_sample"].clone())?;
        let first = json_bound(&first_binding)?;
        ensure!(
            first["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                && first["guard_sha256"] == GUARD_SHA
                && first["producer_invocation_id"] == peer.producer_invocation_id
                && first["plan_sha256"] == guard_binding.sha256
                && first["producer_stop_enabled"] == true
                && first.get("trip_reason") == Some(&Value::Null)
                && first.get("worker_observation_error") == Some(&Value::Null)
                && first.get("root_physical_observation_error") == Some(&Value::Null),
            "peer requires its genuine successful first protective sample"
        );
        let timer_unit = protection["timer_unit"]
            .as_str()
            .context("peer protective timer")?;
        let service_unit = protection["guard_unit"]
            .as_str()
            .context("peer guard service")?;
        ensure!(
            named_unit(timer_unit, ".timer") && named_unit(service_unit, ".service"),
            "invalid protective unit names"
        );
        let timer = native(timer_unit)?;
        ensure!(
            timer["Id"] == timer_unit
                && timer["InvocationID"] == protection["timer_invocation_id"]
                && timer["LoadState"] == "loaded"
                && timer["ActiveState"] == "active"
                && matches!(timer["SubState"].as_str(), Some("waiting" | "running"))
                && timer["Job"] == ""
                && timer["Triggers"] == service_unit,
            "peer protective timer changed or is unarmed"
        );
        let service = native(service_unit)?;
        let command = service["ExecStart"]
            .as_str()
            .context("actual peer guard command")?;
        ensure!(
            service["LoadState"] == "loaded"
                && service["MemoryMax"] == "1073741824"
                && service["MemorySwapMax"] == "0"
                && service["Restart"] == "no",
            "actual peer guard image/plan or reserved profile differs"
        );
        guard_command(command, &guard_binding)?;
        ensure!(
            sha(&raw(Path::new(GUARD_IMAGE), 64 << 20, true, true)?) == GUARD_SHA,
            "qualified guard image changed"
        );
        let receipts = Path::new(
            guard["receipt_directory"]
                .as_str()
                .context("guard receipt directory")?,
        );
        ensure!(
            receipts.is_absolute()
                && receipts.canonicalize()? == receipts
                && !exists(&receipts.join("stop-intent.json"))?
                && !exists(&receipts.join("stop-completion.json"))?,
            "guard already entered stop lifecycle"
        );
        let completed_iid = service["InvocationID"]
            .as_str()
            .context("completed guard IID")?;
        ensure!(
            completed_iid.len() == 32
                && completed_iid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid completed guard IID"
        );
        let sample_path = receipts.join(format!("sample-{completed_iid}.json"));
        let bytes = raw(&sample_path, 65536, true, false)?;
        let sample: Value = serde_json::from_slice(&bytes)?;
        completed_guard(&service, &sample, peer, &guard_binding, now()?)?;
        let journal = guard_journal(service_unit, completed_iid)?;
        ensure!(
            native(&peer.producer_unit)? == producer
                && native(timer_unit)? == timer
                && native(service_unit)? == service,
            "peer producer or armed timer changed during guard check"
        );
        let mut stable_timer = timer.clone();
        stable_timer
            .as_object_mut()
            .context("timer object")?
            .remove("SubState");
        output.insert(peer.epoch, json!({"stable":{"producer":producer,"timer":stable_timer,"admission":peer.admission,"guard_protection":peer.guard_protection,"guard_plan":guard_binding,"first_guard_sample":first_binding},"genuine_recent_guard_completion":{"native":service,"timer_raw":timer,"sample":{"path":sample_path,"sha256":sha(&bytes)},"PID1":journal},"periodic_guard_instance_may_roll_only_after_genuine_success_under_unchanged_command":true}));
    }
    Ok(serde_json::to_value(output)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer(epoch: u64) -> OtherLive {
        OtherLive {
            epoch,
            phase: "replay".into(),
            producer_unit: format!("horizon-peer-{epoch}.service"),
            producer_invocation_id: "a".repeat(32),
            producer_pid: 123,
            admission: Bound {
                path: "/sealed/admission.json".into(),
                sha256: "b".repeat(64),
            },
            guard_protection: Bound {
                path: "/sealed/guard.json".into(),
                sha256: "c".repeat(64),
            },
        }
    }
    fn fixture(p: &OtherLive) -> Value {
        json!({"actual_executing_replays":[{"epoch":p.epoch,"unit":{"Id":p.producer_unit,"InvocationID":p.producer_invocation_id,"MainPID":"123","ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running"},"admission":p.admission,"guard_protection":p.guard_protection}],"actual_active_bootstraps":[],"live_replay_count":1,"guarded_bootstrap_owner_count":0,"active_producer_count":1})
    }
    #[test]
    fn an_accepted_disjoint_peer_can_be_preserved_but_target_or_missing_protection_cannot() {
        let other = if EPOCH == 166 { 167 } else { 166 };
        let p = peer(other);
        let mut f = fixture(&p);
        fleet_shape(&f, std::slice::from_ref(&p), EPOCH).unwrap();
        f["actual_executing_replays"][0]["guard_protection"] = Value::Null;
        assert!(fleet_shape(&f, std::slice::from_ref(&p), EPOCH).is_err());
        assert!(fleet_shape(&fixture(&peer(EPOCH)), &[peer(EPOCH)], EPOCH).is_err());
    }
    #[test]
    fn undeclared_or_restarted_live_owner_fails_the_complete_peer_census() {
        let p = peer(if EPOCH == 166 { 167 } else { 166 });
        let mut f = fixture(&p);
        assert!(fleet_shape(&f, &[], EPOCH).is_err());
        f["actual_executing_replays"][0]["unit"]["NRestarts"] = json!("1");
        assert!(fleet_shape(&f, std::slice::from_ref(&p), EPOCH).is_err());
    }
    #[test]
    fn duplicate_peers_or_an_unregistered_admission_do_not_count_as_accepted() {
        let p = peer(if EPOCH == 166 { 167 } else { 166 });
        let mut f = fixture(&p);
        assert!(fleet_shape(&f, &[p.clone(), p.clone()], EPOCH).is_err());
        f["actual_executing_replays"][0]["admission"]["sha256"] = json!("d".repeat(64));
        assert!(fleet_shape(&f, std::slice::from_ref(&p), EPOCH).is_err());
    }

    fn receipts(p: &OtherLive, event: &Bound) -> (Value, Value) {
        let admission = json!({"schema":"horizon-standard-replacement-admission-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","epoch":p.epoch,"producer_unit":p.producer_unit,"producer_invocation_id":p.producer_invocation_id,"producer_pid":p.producer_pid,"original_stop_event":event,"recorded_unix_seconds":100,"fresh_admission_passed":true,"all_existing_growth_and_floor_protected":true,"all_prior_promises_retained":true,"old_partial_and_inputs_preserved":true,"resource_credit_bytes":0,"memory_or_DATA_promise_ending_bytes":0,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"candidate_hard_memory_bytes":73014444032u64,"remote_mutations":false,"r2_mutations":false});
        let protection = json!({"schema":"horizon-standard-live-peer-protection-v1","owner":"/root","epoch":p.epoch,"producer_unit":p.producer_unit,"producer_invocation_id":p.producer_invocation_id,"admission":p.admission});
        (admission, protection)
    }
    #[test]
    fn peer_receipts_reject_the_old_owner_wrong_event_or_a_resource_ending() {
        let p = peer(if EPOCH == 166 { 167 } else { 166 });
        let event = Bound {
            path: EVENT.into(),
            sha256: specs::EVENT_SHA.into(),
        };
        let (a, g) = receipts(&p, &event);
        receipt_shape(&a, &g, &p, &event, 101).unwrap();
        let mut changed = a.clone();
        changed["producer_invocation_id"] = json!("d".repeat(32));
        assert!(receipt_shape(&changed, &g, &p, &event, 101).is_err());
        let mut changed = a.clone();
        changed["original_stop_event"]["sha256"] = json!("e".repeat(64));
        assert!(receipt_shape(&changed, &g, &p, &event, 101).is_err());
        let mut changed = a.clone();
        changed["memory_or_DATA_promise_ending_bytes"] = json!(1);
        assert!(receipt_shape(&changed, &g, &p, &event, 101).is_err());
    }
    #[test]
    fn protection_cannot_bind_another_admission_or_unreviewed_runtime() {
        let p = peer(if EPOCH == 166 { 167 } else { 166 });
        let event = Bound {
            path: EVENT.into(),
            sha256: specs::EVENT_SHA.into(),
        };
        let (mut a, mut g) = receipts(&p, &event);
        g["admission"]["sha256"] = json!("f".repeat(64));
        assert!(receipt_shape(&a, &g, &p, &event, 101).is_err());
        let (_, g) = receipts(&p, &event);
        a["worker_sha256"] = json!("0".repeat(64));
        assert!(receipt_shape(&a, &g, &p, &event, 101).is_err());
        assert!(receipt_shape(&a, &g, &p, &event, 99).is_err());
    }
    #[test]
    fn guard_command_requires_the_exact_executable_argv_and_ignore_errors() {
        let b = Bound {
            path: "/sealed/guard-plan.json".into(),
            sha256: "b".repeat(64),
        };
        let text = format!(
            "{{ path={GUARD_IMAGE} ; argv[]={GUARD_IMAGE} /sealed/guard-plan.json --plan-sha256 {} --self-sha256 {GUARD_SHA} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
            b.sha256
        );
        guard_command(&text, &b).unwrap();
        assert!(
            guard_command(
                &text.replacen(&format!("path={GUARD_IMAGE}"), "path=/bin/echo", 1),
                &b
            )
            .is_err()
        );
        assert!(guard_command(&text.replace("ignore_errors=no", "ignore_errors=yes"), &b).is_err());
        assert!(
            guard_command(
                &text.replace(" --self-sha256 ", " --extra --self-sha256 "),
                &b
            )
            .is_err()
        );
        assert!(guard_command(&(text.clone() + " " + &text), &b).is_err());
    }
    #[test]
    fn failed_stale_or_wrong_image_guard_never_inherits_a_first_sample() {
        let p = peer(if EPOCH == 166 { 167 } else { 166 });
        let b = Bound {
            path: "/guard-plan".into(),
            sha256: "b".repeat(64),
        };
        let iid = "d".repeat(32);
        let service = json!({"InvocationID":iid,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","NRestarts":"0","Result":"success","ExecMainStatus":"0","Job":""});
        let sample = json!({"recorded_unix_seconds":100,"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_invocation_id":iid,"guard_sha256":GUARD_SHA,"producer_invocation_id":p.producer_invocation_id,"plan_sha256":b.sha256,"producer_stop_enabled":true,"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null});
        completed_guard(&service, &sample, &p, &b, 101).unwrap();
        let mut changed = service.clone();
        changed["ActiveState"] = json!("failed");
        changed["Result"] = json!("exit-code");
        assert!(completed_guard(&changed, &sample, &p, &b, 101).is_err());
        assert!(completed_guard(&service, &sample, &p, &b, 146).is_err());
        let mut missing = sample.clone();
        missing.as_object_mut().unwrap().remove("trip_reason");
        assert!(completed_guard(&service, &missing, &p, &b, 101).is_err());
        let mut changed = sample;
        changed["guard_sha256"] = json!("0".repeat(64));
        assert!(completed_guard(&service, &changed, &p, &b, 101).is_err());
    }
    #[test]
    fn rollover_keeps_stable_peer_roles_but_does_not_ignore_a_changed_timer() {
        let a = json!({"166":{"stable":{"producer_iid":"one","timer_iid":"two"},"genuine_recent_guard_completion":{"iid":"old"}}});
        let mut b = a.clone();
        b["166"]["genuine_recent_guard_completion"]["iid"] = json!("new");
        same_peers(&a, &b).unwrap();
        b["166"]["stable"]["timer_iid"] = json!("different");
        assert!(same_peers(&a, &b).is_err());
    }
}
