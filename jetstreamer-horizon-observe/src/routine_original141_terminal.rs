//! Exact recovery of the 0809 observer after original 141 failed before adoption.
//! Keep the raw diagnostic in durable evidence; exclude only its authenticated
//! terminal owner from the legacy ETA view. No launch or archive authority.
use super::*;
const CONFIG_SHA: &str = "371d714d4846f777eb2a7905b7c229b4f93d7c0d0ab634cce05381324656481c";
const SPEC_SHA: &str = "705cc25c87c59cb9047615df263c4eb063a57a3306d4bceb6de376f215e441eb";
const SPEC: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-terminal-recovery-20261023-v2/spec.json";
const UNIT: &str = "horizon-qualify-141-original-entry-root-20261023-v1.service";
const IID: &str = "f9c0622f5005492bba91389b361e1c36";
const SCRATCH: &str =
    "/home/sol/.jetstreamer-private/epoch141-original-entry-root-20261023-v1/scratch";
pub(super) fn matches(p: &Plan) -> bool {
    p.schema == PLAN_SCHEMA_101
        && p.original141_root.is_none()
        && p.observer_config.sha256 == CONFIG_SHA
        && p.previous_observer.sha256
            == "1e549480ed88050ed13f6e22dfd9850a5625c95d883af5c3f149899fa144c2d1"
}
fn binding() -> Bound {
    Bound {
        path: SPEC.into(),
        sha256: SPEC_SHA.into(),
    }
}
pub(super) fn failure_recorded(ledger: &Value) -> bool {
    ledger["epochs"].as_array().is_some_and(|rows| {
        rows.iter().any(|r| {
            r["epoch"] == 141
                && r["state"] == "failed-needs-repair"
                && r["gate_evidence"]
                    .as_array()
                    .is_some_and(|e| e.iter().any(|b| b["sha256"] == SPEC_SHA))
        })
    })
}
fn prefix(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn terminal(v: &Value) -> Result<()> {
    for (key, value) in [
        ("Id", UNIT),
        ("InvocationID", IID),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Result", "exit-code"),
        ("ExecMainStatus", "1"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
    ] {
        ensure!(v[key] == value, "original 141 terminal owner differs:{key}");
    }
    ensure!(
        v.get("Restart").is_none_or(|r| r == "no"),
        "terminal 141 restart policy differs"
    );
    Ok(())
}
fn checked(p: &Plan) -> Result<Value> {
    ensure!(matches(p), "foreign terminal 141 recovery");
    let s = bound_json(&binding(), true)?;
    ensure!(
        s["schema"] == "jetstreamer-original141-terminal-recovery-spec-v2"
            && s["unit"] == UNIT
            && s["invocation_id"] == IID
            && s["observer_config"] == serde_json::to_value(&p.observer_config)?
            && s["observer"]["path"].as_str() == p.observer.to_str(),
        "terminal 141 recovery scope changed"
    );
    for k in [
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(s[k] == false, "terminal 141 recovery grants authority");
    }
    let b: Bound = serde_json::from_value(s["root_plan"].clone())?;
    let plan = bound_json(&b, true)?;
    ensure!(
        plan["epoch"] == 141
            && plan["unit"] == UNIT
            && plan["node_sha256"]
                == "d0c784a403d65819de70a499fc4d981217fd16fc30b70fac7e5ec979d0423ff0",
        "terminal 141 parent changed"
    );
    let recorded: Bound = serde_json::from_value(s["terminal_unit_file"].clone())?;
    let bytes = read_checked(&recorded.path, LIMIT, 0, true)?;
    ensure!(
        sha(&bytes) == recorded.sha256,
        "terminal 141 retained terminal changed"
    );
    let fields: serde_json::Map<_, _> = std::str::from_utf8(&bytes)?
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.into(), json!(v)))
        .collect();
    // Retained snapshot predates this verifier; Restart is read from the live
    // unit and separately required below.
    let old = Value::Object(fields);
    terminal(&old)?;
    let out=Command::new("/usr/bin/systemctl").args(["show",UNIT,"--no-pager","--property=Id,InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ActiveState,SubState,ExecStart"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "terminal 141 current unit unreadable"
    );
    let fields: serde_json::Map<_, _> = std::str::from_utf8(&out.stdout)?
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.into(), json!(v)))
        .collect();
    let current = Value::Object(fields);
    terminal(&current)?;
    ensure!(
        current["Restart"] == "no",
        "terminal 141 current restart policy missing"
    );
    ensure!(
        prefix(&current["ExecStart"]) == prefix(&plan["expected_exec_start"])
            && prefix(&old["ExecStart"]) == prefix(&current["ExecStart"]),
        "terminal 141 command changed"
    );
    let journal: Bound = serde_json::from_value(s["journal"].clone())?;
    let bytes = read_checked(&journal.path, LIMIT, 0, true)?;
    ensure!(
        sha(&bytes) == journal.sha256,
        "terminal 141 retained journal changed"
    );
    let mut found = false;
    for line in std::str::from_utf8(&bytes)?.lines() {
        let v: Value = serde_json::from_str(line)?;
        ensure!(
            v["_SYSTEMD_INVOCATION_ID"] == IID && v["_SYSTEMD_UNIT"] == UNIT,
            "foreign terminal 141 journal"
        );
        found |= v["MESSAGE"].as_str().is_some_and(|m| {
            m.contains("historical execution mismatch at slot 60912005 entry 388 transaction 378")
                && m.contains("expected None, got Some(InstructionError")
                && m.contains("Custom(2)")
        });
    }
    ensure!(found, "terminal 141 execution failure not evidenced");
    Ok(s)
}
fn strip(v: &Value, observation: bool) -> Result<Value> {
    let mut out = v.clone();
    let rows = out["diagnostic_replays"]
        .as_array_mut()
        .context("terminal 141 diagnostic census")?;
    ensure!(
        rows.len() == 2 && rows.iter().filter(|r| r["range"] == "141").count() == 1,
        "terminal 141 census changed"
    );
    let r = rows.iter().find(|r| r["range"] == "141").unwrap();
    ensure!(
        r["producer_unit"] == UNIT
            && r["expected_producer_invocation_id"] == IID
            && r["scratch_path"] == SCRATCH,
        "terminal 141 diagnostic owner changed"
    );
    if observation {
        ensure!(
            r["status"] == "unavailable"
                && r["observation"].is_null()
                && r["error"] == "systemd control group is not absolute: prefix not found",
            "terminal 141 observation is not the exact failed sample"
        );
        for key in [
            "replay_launch_authorized",
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "publication_authorized",
            "r2_mutations",
        ] {
            ensure!(r[key] == false, "terminal 141 diagnostic grants authority");
        }
    } else {
        ensure!(
            r["controller_unit"] == UNIT
                && r["expected_controller_invocation_id"] == IID
                && r["worker_executable_basename"] == "historical-worker",
            "terminal 141 diagnostic config changed"
        );
    }
    rows.retain(|r| r["range"] != "141");
    ensure!(
        rows.len() == 1 && rows[0]["range"] == "144",
        "terminal 141 dropped other diagnostic"
    );
    Ok(out)
}
pub(super) fn config(p: &Plan, v: &Value) -> Result<Value> {
    if !matches(p) {
        return Ok(v.clone());
    }
    checked(p)?;
    strip(v, false)
}
pub(super) fn observation(p: &Plan, v: &Value) -> Result<Value> {
    if !matches(p) {
        return Ok(v.clone());
    }
    let s = checked(p)?;
    let actual = bound_json(&serde_json::from_value(s["observer"].clone())?, false)?;
    ensure!(actual == *v, "terminal 141 observer changed");
    strip(v, true)
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    if !matches(p) {
        return Ok(());
    }
    checked(p)?;
    ensure!(
        f["gates"]["141"]["state"] == "failed-needs-repair",
        "terminal 141 cannot close repair"
    );
    let units = f["tracked_units"].as_array_mut().context("tracked units")?;
    if !units.contains(&json!(UNIT)) {
        units.push(json!(UNIT));
    }
    let e = f["gates"]["141"]["evidence"]
        .as_array_mut()
        .context("141 evidence")?;
    let b = serde_json::to_value(binding())?;
    if !e.contains(&b) {
        e.push(b);
    }
    f["gates"]["141"]["next_action"] = json!(
        "Private original-entry qualification reached Bank execution then failed at 60912005 entry 388 transaction 378: expected success, got InstructionError Custom(2). Preserve sealed terminal/journal/source evidence, extract the failing transaction and account/program facts, repair canonical execution before retry, and freshly admit the compatible disjoint 186 fallback while this repair proceeds. Never publish 141 or close its repair from this partial diagnostic."
    );
    Ok(())
}
pub(super) fn next_config(p: &Plan, c: &mut Value) -> Result<()> {
    if matches(p) {
        checked(p)?;
        *c = strip(c, false)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root exact 0809 full observer and sealed terminal evidence; immutable reads and terminal ownership only"]
    fn actual_terminal_recovery_preserves_five_producers_and_old144() {
        let b=Bound{path:"/var/lib/jetstreamer/horizon-routine-plan-101-200-20261023T080958Z-controller-rebind-repair185-repair183-upload144-census141-boundaries-native141-all-retry-public160-timed-scans-upload198-v1/cycle-plan.json".into(),sha256:"5b59944a3adffb8450a709ce42f2113f0026753793001e8a1addc0e1e00edd30".into()};
        let mut p: Plan = serde_json::from_value(bound_json(&b, true).unwrap()).unwrap();
        let s = bound_json(&binding(), true).unwrap();
        p.observer_config = serde_json::from_value(s["observer_config"].clone()).unwrap();
        let c = bound_json(&p.observer_config, true).unwrap();
        let o = bound_json(
            &serde_json::from_value(s["observer"].clone()).unwrap(),
            false,
        )
        .unwrap();
        let filtered = config(&p, &c).unwrap();
        assert_eq!(filtered["replays"], c["replays"]);
        assert_eq!(
            filtered["diagnostic_replays"][0],
            c["diagnostic_replays"][0]
        );
        let filtered = observation(&p, &o).unwrap();
        assert_eq!(filtered["replays"], o["replays"]);
        assert_eq!(
            filtered["diagnostic_replays"][0],
            o["diagnostic_replays"][0]
        );
        let mut f = bound_json(&p.fleet_template, true).unwrap();
        let before = f.clone();
        derive_fleet(&p, &mut f).unwrap();
        assert_eq!(f["gates"]["141"]["state"], "failed-needs-repair");
        f["gates"]["141"] = before["gates"]["141"].clone();
        f["tracked_units"] = before["tracked_units"].clone();
        assert_eq!(f, before);
    }
    #[test]
    fn only_the_exact_terminal_owner_can_leave_the_eta_view() {
        let u = json!({"Id":UNIT,"InvocationID":IID,"MainPID":"0","NRestarts":"0","Restart":"no","Result":"exit-code","ExecMainStatus":"1","ActiveState":"failed","SubState":"failed"});
        terminal(&u).unwrap();
        for (k, v) in [
            ("MainPID", "123"),
            ("InvocationID", "replacement"),
            ("NRestarts", "1"),
            ("Result", "success"),
            ("Restart", "always"),
        ] {
            let mut bad = u.clone();
            bad[k] = json!(v);
            assert!(terminal(&bad).is_err(), "{k}");
        }
        let r = json!({"range":"141","producer_unit":UNIT,"expected_producer_invocation_id":IID,"scratch_path":SCRATCH,"status":"unavailable","observation":null,"error":"systemd control group is not absolute: prefix not found","replay_launch_authorized":false,"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"publication_authorized":false,"r2_mutations":false});
        let v = json!({"diagnostic_replays":[{"range":"144","retained":u64::MAX},r],"replays":[{"retained":u64::MAX}]});
        let out = strip(&v, true).unwrap();
        assert_eq!(out["replays"], v["replays"]);
        assert_eq!(out["diagnostic_replays"][0], v["diagnostic_replays"][0]);
        for (k, val) in [
            ("status", json!("observed")),
            ("expected_producer_invocation_id", json!("replacement")),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = v.clone();
            bad["diagnostic_replays"][1][k] = val;
            assert!(strip(&bad, true).is_err(), "{k}");
        }
    }
}
