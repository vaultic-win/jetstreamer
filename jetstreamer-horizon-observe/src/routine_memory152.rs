//! One 152 controller-policy recovery; original producer and every archive gate survive.
use super::*;
const CONTROLLER: &str = "jetstreamer-epochs152-153-target3-controller-v1-r2.service";
const PRODUCER: &str =
    "jetstreamer-root-sweep-e152-153-t3-20261014-v1-r2-e152-153-lane-l-1.service";
const OLD_CID: &str = "61468cd13db74bffba41b36d0c5707c6";
const PID: &str = "1a7e8cde872b45f786979150d5639ab4";
const PROOF: &str =
    "/usr/local/lib/jetstreamer/horizon-memory152-controller-rebind-20261024-v1/rebind.json";
const HISTORICAL: &str =
    "/usr/local/lib/jetstreamer/horizon-controller-rebind-proof-20261023-v1/unit-bindings.json";
const HISTORICAL_SHA: &str = "a4ce1f8dd91853e8837fb8bf17b923fa4874c726ed551e84dc7b4ae720f2fab2";
const OLD: &str = "2026-10-24T03:16:00Z";
const FIRST: &str = "2026-10-24T04:16:00Z";
const OLD_OBSERVER: &str =
    "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261024T031600Z.json";
const OBSERVER_SHA: &str = "d84a0c4a8459eef580736daebeb2a551c3e28548bf37a8c0339c7fdb07fdf929";
const FAILED_OBSERVER: &str = "jetstreamer-horizon-observe-import191-034600-20261024-v1.service";
const FAILED_IID: &str = "6d55e3c3b64147799d7ca2b3f030ead9";
pub(super) fn enabled(p: &Plan) -> bool {
    p.memory152_rebind.is_some()
}
fn prefix(v: &Value) -> Result<&str> {
    v.as_str()
        .and_then(|s| s.split_once(" ; ignore_errors=").map(|x| x.0))
        .context("152 native command prefix missing")
}
fn properties(name: &str) -> Result<Value> {
    let o = Command::new("/usr/bin/systemctl").args(["show",name,"--no-pager","--all",
        "--property=Id,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,ExecStart,Result,ExecMainStatus,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,ControlGroup"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 32768,
        "152 manager metadata unavailable"
    );
    let mut v = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, x) = line.split_once('=').context("152 manager framing")?;
        ensure!(
            v.insert(k.into(), json!(x)).is_none(),
            "152 duplicate manager property"
        );
    }
    Ok(Value::Object(v))
}
fn live(v: &Value, unit: &str, iid: &str, pid: Option<&str>) -> Result<()> {
    ensure!(
        v["Id"] == unit
            && v["InvocationID"] == iid
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["MainPID"]
                .as_str()
                .is_some_and(|s| s.parse::<u64>().is_ok_and(|p| p > 0))
            && pid.is_none_or(|p| v["MainPID"] == p),
        "152 owner replaced/restarted/not running"
    );
    Ok(())
}
fn checked(v: &Value, historical: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-memory152-controller-rebind-v1"
            && is_sha(
                v["new_controller_invocation_id"]
                    .as_str()
                    .unwrap_or("")
                    .repeat(2)
                    .as_str()
            )
            && v["new_controller_invocation_id"] != OLD_CID,
        "152 rebind schema/new identity differs"
    );
    for flag in [
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
        "remaining_growth_released",
        "scratch_retirement_authorized",
    ] {
        ensure!(v[flag] == false, "152 rebind grants {flag}");
    }
    let cid = v["new_controller_invocation_id"]
        .as_str()
        .context("152 new controller ID")?;
    live(&v["current_units"][CONTROLLER], CONTROLLER, cid, None)?;
    live(
        &v["current_units"][PRODUCER],
        PRODUCER,
        PID,
        Some("1885971"),
    )?;
    let old = &historical["current_units"][CONTROLLER];
    ensure!(
        old["InvocationID"] == OLD_CID
            && historical["current_units"][PRODUCER]["InvocationID"] == PID,
        "152 original controller/producer history differs"
    );
    let before = prefix(&old["ExecStart"])?;
    ensure!(
        before.matches("--memory-high-gib=64").count() == 1
            && before.matches("--memory-max-gib=68").count() == 1,
        "152 original memory policy differs"
    );
    ensure!(
        prefix(&v["current_units"][CONTROLLER]["ExecStart"])? == before
            && prefix(&v["current_units"][PRODUCER]["ExecStart"])?
                == prefix(&historical["current_units"][PRODUCER]["ExecStart"])?,
        "152 restored policy changed a command/original producer"
    );
    let producer = &v["current_units"][PRODUCER];
    ensure!(
        producer["MemoryHigh"] == "68719476736"
            && producer["MemoryMax"] == "73014444032"
            && producer["MemorySwapMax"] == "0"
            && producer["CPUQuotaPerSecUSec"] == "9s",
        "152 original producer memory/CPU/swap was not restored"
    );
    Ok(())
}
fn proof(p: &Plan) -> Result<Option<Value>> {
    let Some(b) = &p.memory152_rebind else {
        return Ok(None);
    };
    ensure!(
        is_101(p)? && b.path == Path::new(PROOF),
        "foreign 152 rebind scope"
    );
    let v = bound_json(b, true)?;
    checked(
        &v,
        &bound_json(
            &Bound {
                path: HISTORICAL.into(),
                sha256: HISTORICAL_SHA.into(),
            },
            true,
        )?,
    )?;
    for (name, path, digest) in [
        (
            "admission",
            "/usr/local/lib/jetstreamer/horizon-memory152-admission-20261024-v1/admission.json",
            "43cfc22810ac23e0888dee8decd440aceca6852f5b2b2ab0aeb360d47ea76ff9",
        ),
        (
            "applied",
            "/usr/local/lib/jetstreamer/horizon-memory152-applied-20261024-v1/completion.json",
            "01a0e959d2131c2866336b9d0ab326e67f898321f8228de04088077d4b8f8d05",
        ),
        (
            "reverted",
            "/usr/local/lib/jetstreamer/horizon-memory152-reverted-20261024-v1/reverted.json",
            "a6154cbfba221fc36543b3fe5a26b36ce5474fac318f3dd71ad632c5e65e6a9f",
        ),
    ] {
        let binding: Bound = serde_json::from_value(v[name].clone())?;
        ensure!(
            binding.path == Path::new(path) && binding.sha256 == digest,
            "152 {name} binding differs"
        );
        bound_json(&binding, true)?;
    }
    let reverted = bound_json(&serde_json::from_value(v["reverted"].clone())?, true)?;
    ensure!(
        reverted["experiment_aborted"] == true
            && reverted["throughput_improvement_proven"] == false
            && reverted["controller_state_rewritten"] == false
            && reverted["producer_pid_before_and_after"] == 1885971
            && reverted["producer_invocation_id_before_and_after"] == PID
            && reverted["memory_high_bytes"] == 68719476736_u64
            && reverted["memory_max_bytes"] == 73014444032_u64,
        "152 recovery lacks actual native abort/reversion proof"
    );
    let profile = bound_json(&serde_json::from_value(v["guard_profile"].clone())?, true)?;
    let first = bound_json(&serde_json::from_value(v["first_guard"].clone())?, true)?;
    guard(&v, &profile, &first)?;
    Ok(Some(v))
}
fn guard(v: &Value, profile: &Value, first: &Value) -> Result<()> {
    let g = &first["evidence"];
    let cid = &v["new_controller_invocation_id"];
    ensure!(
        g["armed"] == true
            && g["trip"] == false
            && g["maximum_worker_vmas"] == 800000
            && g["minimum_free_bytes"] == 2027224563712_u64
            && g["controller"]["unit"] == CONTROLLER
            && g["controller"]["invocation_id"] == *cid
            && g["controller"]["restarts"] == 0
            && g["controller"]["active_state"] == "active"
            && g["controller"]["sub_state"] == "running"
            && g["producer"]["unit"] == PRODUCER
            && g["producer"]["invocation_id"] == PID
            && g["producer"]["main_pid"] == 1885971
            && g["producer"]["restarts"] == 0
            && g["producer"]["active_state"] == "active"
            && g["producer"]["sub_state"] == "running"
            && g["producer"]["worker_count"] == 1
            && g["producer"]["worker_vmas"]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 800000)
            && first["guard_unit"] == profile["unit"]
            && first["journal_cursor"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "152 first healthy native guard differs"
    );
    let argv: Vec<String> = serde_json::from_value(profile["argv"].clone())?;
    ensure!(
        argv.len() == 12
            && argv[0] == "/usr/bin/python3"
            && argv[1]
                == "/usr/local/lib/jetstreamer/adaptive-reserve-epochs152-153-20261014-v1/guard-adaptive-replay-reserve.py",
        "152 guard command/script census changed"
    );
    for exact in [
        format!("--controller-unit={CONTROLLER}"),
        format!("--producer-unit={PRODUCER}"),
        format!(
            "--expected-controller-invocation-id={}",
            cid.as_str().unwrap()
        ),
        format!("--expected-producer-invocation-id={PID}"),
        "--filesystem=/home/sol".into(),
        "--minimum-free-bytes=2027224563712".into(),
        "--maximum-worker-vmas=800000".into(),
        format!(
            "--guard-timer={}",
            profile["timer"].as_str().context("152 guard timer")?
        ),
    ] {
        ensure!(
            argv.iter().filter(|a| **a == exact).count() == 1,
            "152 native guard argument differs"
        );
    }
    let ts = first["journal_realtime_timestamp"]
        .as_str()
        .context("152 guard clock")?
        .parse::<u64>()?;
    ensure!(
        ts > utc_seconds("2026-10-24T03:30:01Z")? * 1_000_000
            && ts < utc_seconds(FIRST)? * 1_000_000,
        "152 first guard predates admission or postdates first target"
    );
    Ok(())
}
pub(super) fn validate_live(p: &Plan) -> Result<()> {
    let Some(v) = proof(p)? else { return Ok(()) };
    let cid = v["new_controller_invocation_id"].as_str().unwrap();
    for (name, id, pid) in [(CONTROLLER, cid, None), (PRODUCER, PID, Some("1885971"))] {
        let actual = properties(name)?;
        live(&actual, name, id, pid)?;
        for key in [
            "MainPID",
            "InvocationID",
            "ExecStart",
            "MemoryHigh",
            "MemoryMax",
            "MemorySwapMax",
            "CPUQuotaPerSecUSec",
        ] {
            if key == "ExecStart" {
                ensure!(
                    prefix(&actual[key])? == prefix(&v["current_units"][name][key])?,
                    "152 current argv changed"
                );
            } else {
                ensure!(
                    actual[key] == v["current_units"][name][key],
                    "152 current owner/policy changed:{key}"
                );
            }
        }
    }
    let profile = bound_json(&serde_json::from_value(v["guard_profile"].clone())?, true)?;
    let guard = properties(profile["unit"].as_str().context("152 guard unit")?)?;
    let timer = properties(profile["timer"].as_str().context("152 guard timer")?)?;
    let argv: Vec<String> = serde_json::from_value(profile["argv"].clone())?;
    ensure!(
        prefix(&guard["ExecStart"])? == format!("{{ path={} ; argv[]={}", argv[0], argv.join(" ")),
        "152 current guard command differs from sealed profile"
    );
    ensure!(
        guard["Result"] == "success"
            && guard["ExecMainStatus"] == "0"
            && guard["NRestarts"] == "0"
            && timer["ActiveState"] == "active",
        "152 current guard/timer failed"
    );
    let state: Value = serde_json::from_slice(&read_checked(
        Path::new("/var/lib/jetstreamer-root-sweep-epochs152-153-target3-20261014-v1/state.json"),
        LIMIT,
        0,
        false,
    )?)?;
    ensure!(
        state["configuration_sha256"]
            == "34b3cc57c613e28954b2aa93edef176d56108f41dd781887986b6e8bdf5a3c42"
            && state["assignments"]["lane-l"]["pid"] == 1885971
            && state["assignments"]["lane-l"]["unit"] == PRODUCER
            && state["assignments"]["lane-l"]["phase"] == "producer",
        "152 restored controller state/configuration changed"
    );
    Ok(())
}
pub(super) fn interval(p: &Plan) -> Result<Option<u64>> {
    if proof(p)?.is_none() {
        return Ok(None);
    }
    if p.previous_observer.path == Path::new(OLD_OBSERVER)
        && p.previous_observer.sha256 == OBSERVER_SHA
    {
        ensure!(
            p.sample_target_utc == FIRST && utc_seconds(FIRST)? - utc_seconds(OLD)? == 3600,
            "152 first transition must skip absent 03:46 on original grid"
        );
        Ok(Some(3600))
    } else {
        Ok(None)
    }
}
fn edit_model(m: &Value, cid: &str, to_new: bool) -> Result<Value> {
    let mut m = m.clone();
    let rows = m["ranges"].as_array_mut().context("152 model ranges")?;
    let r = rows
        .iter_mut()
        .find(|r| r["range"] == "152-153")
        .context("152 model row absent")?;
    ensure!(
        r["epochs"] == json!([152, 153])
            && r["expected_producer_invocation_id"] == PID
            && (r["expected_controller_invocation_id"] == OLD_CID
                || r["expected_controller_invocation_id"] == cid),
        "152 model controller transition changed producer/scope"
    );
    r["expected_controller_invocation_id"] = json!(if to_new { cid } else { OLD_CID });
    Ok(m)
}
pub(super) fn historical_model(p: &Plan, m: &Value) -> Result<Value> {
    let Some(v) = proof(p)? else {
        return Ok(m.clone());
    };
    edit_model(
        m,
        v["new_controller_invocation_id"].as_str().unwrap(),
        false,
    )
}
pub(super) fn model(p: &Plan, m: &Value) -> Result<Value> {
    let Some(v) = proof(p)? else {
        return Ok(m.clone());
    };
    let mut m = edit_model(m, v["new_controller_invocation_id"].as_str().unwrap(), true)?;
    let b = serde_json::to_value(p.memory152_rebind.as_ref().unwrap())?;
    let evidence = m["evidence"].as_array_mut().context("152 model evidence")?;
    if !evidence.contains(&b) {
        evidence.push(b)
    }
    Ok(m)
}
pub(super) fn enable(p: &mut Plan, c: &mut Value, b: &Bound) -> Result<()> {
    ensure!(
        p.memory152_rebind.is_none()
            && p.sample_target_utc == "2026-10-24T03:46:00Z"
            && p.previous_observer.path == Path::new(OLD_OBSERVER)
            && p.previous_observer.sha256 == OBSERVER_SHA
            && p.expected_epochs == [152, 153, 155, 156, 183, 184]
            && cohort191_import::enabled(p)
            && terminal185::enabled(p)
            && repair141_status::enabled(p),
        "152 recovery requires exact accepted03:16three-owner profile"
    );
    absent(Path::new(
        "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261024T034600Z.json",
    ))?;
    absent(&p.cycle_directory)?;
    absent(&p.estimate_output)?;
    absent(&p.fleet_output)?;
    let failed = properties(FAILED_OBSERVER)?;
    ensure!(
        failed["InvocationID"] == FAILED_IID
            && failed["ActiveState"] == "failed"
            && failed["MainPID"] == "0"
            && failed["NRestarts"] == "0"
            && failed["ExecMainStatus"] == "1",
        "152 recovery lacks exact failed 03:46observer"
    );
    p.memory152_rebind = Some(b.clone());
    let v = proof(p)?.context("152 proof")?;
    let rows = c["replays"].as_array_mut().context("152 observer rows")?;
    let r = rows
        .iter_mut()
        .find(|r| r["range"] == "152-153")
        .context("152 observer row absent")?;
    ensure!(
        r["expected_controller_invocation_id"] == OLD_CID
            && r["expected_producer_invocation_id"] == PID,
        "152 observer original identity differs"
    );
    r["expected_controller_invocation_id"] = v["new_controller_invocation_id"].clone();
    for path in [&mut p.observer, &mut p.estimate_output, &mut p.fleet_output] {
        *path = PathBuf::from(
            path.to_str()
                .context("152 output path")?
                .replace("20261024T034600Z", "20261024T041600Z"),
        );
    }
    p.sample_target_utc = FIRST.into();
    c["not_before_utc"] = json!(FIRST);
    c["output"] = json!(p.observer);
    p.observer_config.sha256 = sha(&next_preparation::encoded(c)?);
    validate_live(p)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value) {
        let command = "{ path=/python ; argv[]=/python /sealed/controller --memory-high-gib=64 --memory-max-gib=68 --cpu-quota-percent=900 ; ignore_errors=no ; result=none }";
        let producer_command =
            "{ path=/node ; argv[]=/node 152-153 /lane ; ignore_errors=no ; result=none }";
        let actor = |unit: &str, id: &str, pid: &str, cmd: &str| json!({"Id":unit,"InvocationID":id,"MainPID":pid,"LoadState":"loaded","ActiveState":"active","SubState":"running","NRestarts":"0","ExecStart":cmd,"MemoryHigh":"68719476736","MemoryMax":"73014444032","MemorySwapMax":"0","CPUQuotaPerSecUSec":"9s"});
        let old = json!({"current_units":{CONTROLLER:actor(CONTROLLER,OLD_CID,"514393",command),PRODUCER:actor(PRODUCER,PID,"1885971",producer_command)}});
        let new_id = "a".repeat(32);
        let v = json!({"schema":"jetstreamer-memory152-controller-rebind-v1","new_controller_invocation_id":new_id,"current_units":{CONTROLLER:actor(CONTROLLER,&new_id,"12345",command),PRODUCER:old["current_units"][PRODUCER]},"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,"remaining_growth_released":false,"scratch_retirement_authorized":false});
        (v, old)
    }
    #[test]
    fn restored_policy_rebind_preserves_producer_commands_and_original_limits() {
        let (v, old) = fixture();
        checked(&v, &old).unwrap();
        for (pointer, value) in [
            (format!("/current_units/{PRODUCER}/MainPID"), json!("999")),
            (
                format!("/current_units/{PRODUCER}/InvocationID"),
                json!("b".repeat(32)),
            ),
            (
                format!("/current_units/{PRODUCER}/MemoryHigh"),
                json!("103079215104"),
            ),
            (
                format!("/current_units/{PRODUCER}/MemoryMax"),
                json!("137438953472"),
            ),
            (
                format!("/current_units/{PRODUCER}/CPUQuotaPerSecUSec"),
                json!("10s"),
            ),
            (format!("/current_units/{CONTROLLER}/NRestarts"), json!("1")),
            ("/new_controller_invocation_id".into(), json!(OLD_CID)),
            ("/remaining_growth_released".into(), json!(true)),
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(&pointer).unwrap() = value;
            assert!(checked(&bad, &old).is_err(), "{pointer}");
        }
        let mut bad = v;
        bad["current_units"][CONTROLLER]["ExecStart"] = json!(
            prefix(&old["current_units"][CONTROLLER]["ExecStart"])
                .unwrap()
                .replace("--memory-high-gib=64", "--memory-high-gib=96")
                + " ; ignore_errors=no ; result=none }"
        );
        assert!(checked(&bad, &old).is_err());
    }
    #[test]
    fn only152_controller_changes_while_clocks_allowances_and_other_ranges_survive() {
        let cid = "a".repeat(32);
        let m = json!({"evidence":[],"ranges":[
            {"range":"152-153","epochs":[152,153],"expected_controller_invocation_id":OLD_CID,"expected_producer_invocation_id":PID,"elapsed_millis":u64::MAX,"downstream":777},
            {"range":"155-156","expected_controller_invocation_id":"untouched","elapsed_millis":42}]});
        let next = edit_model(&m, &cid, true).unwrap();
        assert_eq!(next["ranges"][0]["elapsed_millis"], u64::MAX);
        assert_eq!(next["ranges"][0]["downstream"], 777);
        assert_eq!(next["ranges"][1], m["ranges"][1]);
        assert_eq!(edit_model(&next, &cid, false).unwrap(), m);
        let mut bad = m;
        bad["ranges"][0]["expected_producer_invocation_id"] = json!("b".repeat(32));
        assert!(edit_model(&bad, &cid, true).is_err());
    }
}
