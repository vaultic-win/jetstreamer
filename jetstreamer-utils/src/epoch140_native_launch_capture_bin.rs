//! Observes one fixed zero-entry restore after its real guard first fire.
//! Never launches, stops, publishes, deletes, or grants those authorities.
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod common;

use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    std::{
        collections::BTreeMap,
        env, fs,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    },
};

const WORKER: &str = "abe395d482174e490833928c7343a33d135d8572096faf873ce3103c35fe520d";
const SNAPSHOT: &str = "47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1";
const JOURNAL: &str = "8dfb8d6805d6b4d50ab340899447b90449c66117cc33b1af0ca6537b934a3b13";
const CLOCK: &str = "f74aacd82655179686a43c6bb137e0c0e7c7bd2955809008a745ef80f16f8be2";
const GUARD: &str = "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194";
const FLOOR: u64 = 5_153_080_892_870;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    invocation_id: String,
    private_run_root: PathBuf,
    probe: Bound,
    restore_plan: Bound,
    guard_sample: Bound,
    guard_plan: Bound,
    guard_unit: String,
    output: PathBuf,
}

fn read_json(bound: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&common::bound_file(
        &bound.path,
        &bound.sha256,
        1 << 20,
        immutable,
    )?)?)
}
fn unit(name: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        name.starts_with("horizon-qualify-140-native-restore-")
            && name.ends_with(".service")
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "wrong unit namespace"
    );
    let result = Command::new("systemctl").args(["show", name,
        "--property=Id,LoadState,InvocationID,ActiveState,SubState,Result,NRestarts,Restart,KillMode,Delegate,ControlGroup,MainPID,ExecStart,ExecMainStatus,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities"]).output()?;
    ensure!(result.status.success(), "systemctl observation failed");
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("malformed unit state")?;
        ensure!(
            fields.insert(k.into(), v.into()).is_none(),
            "duplicate unit field"
        );
    }
    Ok(fields)
}
fn validate_unit(fields: &BTreeMap<String, String>, plan: &Plan) -> Result<()> {
    let get = |k| {
        fields
            .get(k)
            .map(String::as_str)
            .context("missing unit field")
    };
    ensure!(
        get("Id")? == plan.unit
            && get("LoadState")? == "loaded"
            && get("InvocationID")? == plan.invocation_id
            && get("ActiveState")? == "active"
            && get("SubState")? == "running"
            && get("Result")? == "success"
            && get("NRestarts")? == "0"
            && get("Restart")? == "no"
            && get("KillMode")? == "control-group"
            && get("Delegate")? == "no"
            && get("ControlGroup")? == format!("/system.slice/{}", plan.unit)
            && get("MainPID")?.parse::<u32>()? > 0,
        "producer is not exact live nonrestarting invocation"
    );
    let executable = plan.probe.path.to_str().context("non-UTF8 probe path")?;
    let restore_plan = plan
        .restore_plan
        .path
        .to_str()
        .context("non-UTF8 plan path")?;
    let expected = format!(
        "{{ path={executable} ; argv[]={executable} {restore_plan} --plan-sha256 {} --self-sha256 {} ;",
        plan.restore_plan.sha256, plan.probe.sha256
    );
    ensure!(
        get("ExecStart")?.starts_with(&expected),
        "actual probe command differs"
    );
    Ok(())
}
fn validate_sources(plan: &Plan, restore: &Value) -> Result<()> {
    ensure!(
        plan.schema == "jetstreamer-epoch140-native-launch-capture-plan-v1"
            && plan.invocation_id.len() == 32
            && plan
                .invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && plan.private_run_root.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && plan
                .private_run_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("epoch140-native-restore-"))
            && plan
                .probe
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-epoch140-native-restore-tool-"))
            && plan.probe.path.parent().and_then(Path::parent)
                == Some(Path::new("/usr/local/lib/jetstreamer"))
            && plan.probe.path.file_name().and_then(|s| s.to_str())
                == Some("jetstreamer-epoch140-native-restore-probe")
            && common::is_sha(&plan.probe.sha256)
            && common::is_sha(&plan.restore_plan.sha256),
        "wrong capture scope"
    );
    ensure!(
        restore["schema"] == "jetstreamer-private-epoch140-native-restore-probe-plan-v1"
            && restore["original_journal"]["sha256"] == JOURNAL
            && restore["serialized_clock"]["sha256"] == CLOCK
            && restore["scratch_directory"].as_str()
                == plan.private_run_root.join("scratch").to_str()
            && restore["output"].as_str()
                == plan.private_run_root.join("receipts/native.json").to_str()
            && restore["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= FLOOR + (128 << 30)),
        "restore plan source/scope differs"
    );
    Ok(())
}
fn validate_guard(
    plan: &Plan,
    sample: &Value,
    guard_plan: &Value,
    now: u64,
    pid: u32,
) -> Result<()> {
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["guard_sha256"] == GUARD
            && sample["producer_invocation_id"] == plan.invocation_id
            && sample["producer"]["invocation_id"] == plan.invocation_id
            && sample["producer"]["pid"] == pid
            && sample["producer"]["active"] == "active"
            && sample["producer"]["sub"] == "running"
            && sample["producer"]["restarts"] == 0
            && sample["producer"]["restart_policy"] == "no"
            && sample["producer"]["kill_mode"] == "control-group"
            && sample["producer"]["delegated"] == false
            && sample["producer"]["cgroup"] == format!("/system.slice/{}", plan.unit)
            && sample.get("trip_reason").is_some_and(Value::is_null)
            && sample
                .get("worker_observation_error")
                .is_some_and(Value::is_null)
            && sample.get("canary_target_error").is_none()
            && sample["bounded_measurement"] == false
            && sample.get("target_handoff").is_some_and(Value::is_null)
            && sample
                .get("target_handoff_error")
                .is_some_and(Value::is_null)
            && sample["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| now.checked_sub(t).is_some_and(|age| age <= 120))
            && sample["r2_mutations"] == false
            && sample["remote_mutations"] == false,
        "guard lacks exact fresh clean producer sample"
    );
    let workers = sample["workers"].as_array().context("missing workers")?;
    ensure!(
        workers.len() == 1
            && workers[0][0].as_u64().is_some_and(|p| p > 0)
            && workers[0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 3_500_000),
        "guard must observe one readable bound worker"
    );
    ensure!(
        guard_plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && guard_plan["unit"] == plan.unit
            && guard_plan["invocation_id"] == plan.invocation_id
            && guard_plan["worker_root"].as_str() == plan.private_run_root.to_str()
            && guard_plan["filesystem"] == "/home/sol"
            && guard_plan["bounded_measurement"].is_null()
            && guard_plan.get("bounded_canary").is_none()
            && guard_plan["maximum_worker_vmas"] == 3_500_000
            && sample["maximum_worker_vmas"] == guard_plan["maximum_worker_vmas"]
            && sample["plan_sha256"] == plan.guard_plan.sha256
            && sample["minimum_free_bytes"] == guard_plan["minimum_free_bytes"]
            && sample["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|v| v >= FLOOR)
            && sample["available_bytes"]
                .as_u64()
                .zip(sample["minimum_free_bytes"].as_u64())
                .is_some_and(|(f, n)| f >= n),
        "guard plan or protected floor differs"
    );
    Ok(())
}
fn validate_guard_service(
    fields: &BTreeMap<String, String>,
    plan: &Plan,
    sample: &Value,
) -> Result<()> {
    let get = |k| {
        fields
            .get(k)
            .map(String::as_str)
            .context("missing guard unit field")
    };
    ensure!(
        plan.guard_unit == format!("{}-guard.service", plan.unit.trim_end_matches(".service"))
            && get("Id")? == plan.guard_unit
            && get("LoadState")? == "loaded"
            && Some(get("InvocationID")?) == sample["guard_invocation_id"].as_str()
            && get("Result")? == "success"
            && get("ExecMainStatus")? == "0"
            && get("NRestarts")? == "0"
            && get("MainPID")? == "0"
            && ((get("ActiveState")? == "inactive" && get("SubState")? == "dead")
                || (get("ActiveState")? == "active" && get("SubState")? == "exited"))
            && get("ProtectSystem")? == "strict"
            && get("ProtectHome")? == "read-only"
            && get("PrivateNetwork")? == "yes"
            && get("NoNewPrivileges")? == "yes"
            && get("CapabilityBoundingSet")? == "cap_dac_override cap_sys_ptrace"
            && get("AmbientCapabilities")? == "cap_dac_override cap_sys_ptrace",
        "first fire is not the exact successful least-privilege sandbox"
    );
    let binary = "/usr/local/lib/jetstreamer/horizon-standalone-guard-target-handoff-20261019-v2/jetstreamer-horizon-standalone-guard";
    let prefix = format!(
        "{{ path={binary} ; argv[]={binary} {} --plan-sha256 {} --self-sha256 {GUARD} ;",
        plan.guard_plan.path.display(),
        plan.guard_plan.sha256
    );
    ensure!(
        get("ExecStart")?.starts_with(&prefix),
        "guard command changed"
    );
    Ok(())
}
fn execute(plan_path: &Path, plan_sha: &str, self_sha: &str) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "capture requires root");
    common::bound_file(&fs::read_link("/proc/self/exe")?, self_sha, 64 << 20, true)?;
    let plan: Plan =
        serde_json::from_slice(&common::bound_file(plan_path, plan_sha, 1 << 20, true)?)?;
    let restore = read_json(&plan.restore_plan, true)?;
    validate_sources(&plan, &restore)?;
    let worker = restore["worker"].as_str().context("missing worker path")?;
    common::bound_file(Path::new(worker), WORKER, 256 << 20, true)?;
    common::bound_file(&plan.probe.path, &plan.probe.sha256, 256 << 20, true)?;
    let root = fs::symlink_metadata(&plan.private_run_root)?;
    ensure!(
        plan.private_run_root.canonicalize()? == plan.private_run_root
            && root.is_dir()
            && root.uid() == 1001
            && root.mode() & 0o077 == 0,
        "private root identity differs"
    );
    let before = unit(&plan.unit)?;
    validate_unit(&before, &plan)?;
    let pid = before["MainPID"].parse::<u32>()?;
    ensure!(
        fs::read_link(format!("/proc/{pid}/exe"))? == plan.probe.path,
        "running probe executable differs"
    );
    let guard = read_json(&plan.guard_sample, false)?;
    let guard_plan = read_json(&plan.guard_plan, true)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    validate_guard(&plan, &guard, &guard_plan, now, pid)?;
    let guard_unit = unit(&plan.guard_unit)?;
    validate_guard_service(&guard_unit, &plan, &guard)?;
    let after = unit(&plan.unit)?;
    validate_unit(&after, &plan)?;
    ensure!(before == after, "producer changed during capture");
    let value = json!({"schema":"jetstreamer-private-epoch140-native-restore-launch-v1",
        "recorded_unix_seconds":now,"capture_plan":plan_path,"capture_plan_sha256":plan_sha,"capture_self_sha256":self_sha,
        "launched":true,"epoch":140,"private_run_root":plan.private_run_root,"snapshot_slot":60911751u64,
        "snapshot_sha256":SNAPSHOT,"worker_sha256":WORKER,"original_journal_sha256":JOURNAL,"serialized_clock_sha256":CLOCK,
        "probe_sha256":plan.probe.sha256,"plan_sha256":plan.restore_plan.sha256,"restore_plan":plan.restore_plan.path,
        "guard_sample":plan.guard_sample.path,"guard_sample_sha256":plan.guard_sample.sha256,
        "guard_unit":guard_unit,"sandboxed_first_fire_verified":true,
        "runtime":"solana-v1.4.25","solana_rayon_threads":2,"maximum_runtime_seconds":1800,
        "experimental_envelope_bytes":128u64<<30,"expected_exec_start":before["ExecStart"],
        "evidence":{"units":[{"unit":plan.unit,"invocation_id":plan.invocation_id,"restarts":0,
            "load_state":"loaded","result":"success","main_pid":pid,"active_state":"active","sub_state":"running"}]},
        "replay_entries_authorized":false,"archive_prefix_verified":false,"suffix_execution_authorized":false,
        "runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    common::write_receipt(&plan.output, &value)
}
fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let result = if args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256" {
        execute(Path::new(&args[0]), &args[2], &args[4])
    } else {
        Err(anyhow::anyhow!(
            "usage: PLAN --plan-sha256 HEX --self-sha256 HEX"
        ))
    };
    if let Err(e) = result {
        eprintln!("native launch capture failed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Plan, Value, BTreeMap<String, String>, Value, Value) {
        let p = Plan {
            schema:"jetstreamer-epoch140-native-launch-capture-plan-v1".into(),
            unit:"horizon-qualify-140-native-restore-test-v1.service".into(),
            invocation_id:"a".repeat(32),
            private_run_root:"/home/sol/.jetstreamer-private/epoch140-native-restore-test-v1".into(),
            probe:Bound{path:"/usr/local/lib/jetstreamer/horizon-epoch140-native-restore-tool-test-v1/jetstreamer-epoch140-native-restore-probe".into(),sha256:"b".repeat(64)},
            restore_plan:Bound{path:"/private/restore.json".into(),sha256:"c".repeat(64)},
            guard_sample:Bound{path:"/private/guard.json".into(),sha256:"d".repeat(64)},
            guard_plan:Bound{path:"/private/guard-plan.json".into(),sha256:"e".repeat(64)},
            guard_unit:"horizon-qualify-140-native-restore-test-v1-guard.service".into(),
            output:"/private/launch.json".into(),
        };
        let restore = json!({"schema":"jetstreamer-private-epoch140-native-restore-probe-plan-v1",
            "original_journal":{"sha256":JOURNAL},"serialized_clock":{"sha256":CLOCK},
            "scratch_directory":p.private_run_root.join("scratch"),
            "output":p.private_run_root.join("receipts/native.json"),"minimum_free_bytes":FLOOR+(128u64<<30)});
        let unit:BTreeMap<String,String>=[("Id",p.unit.clone()),("LoadState","loaded".into()),
            ("InvocationID",p.invocation_id.clone()),("ActiveState","active".into()),("SubState","running".into()),
            ("Result","success".into()),("NRestarts","0".into()),("Restart","no".into()),
            ("KillMode","control-group".into()),("Delegate","no".into()),
            ("ControlGroup",format!("/system.slice/{}",p.unit)),("MainPID","123".into()),
            ("ExecStart",format!("{{ path={} ; argv[]={0} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no }}",
                p.probe.path.display(),p.restore_plan.path.display(),p.restore_plan.sha256,p.probe.sha256))]
            .into_iter().map(|(k,v)|(k.into(),v)).collect();
        let guard = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_sha256":GUARD,
            "producer_invocation_id":p.invocation_id,"producer":{"invocation_id":p.invocation_id,
                "pid":123,"active":"active","sub":"running","restarts":0,"restart_policy":"no",
                "kill_mode":"control-group","delegated":false,"cgroup":format!("/system.slice/{}",p.unit)},
            "trip_reason":null,"worker_observation_error":null,"bounded_measurement":false,
            "target_handoff":null,"target_handoff_error":null,
            "recorded_unix_seconds":1000,"workers":[[456,400000]],"plan_sha256":p.guard_plan.sha256,
            "maximum_worker_vmas":3500000,"minimum_free_bytes":FLOOR,"available_bytes":FLOOR+1,
            "r2_mutations":false,"remote_mutations":false});
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":p.unit,
            "invocation_id":p.invocation_id,"worker_root":p.private_run_root,"filesystem":"/home/sol",
            "maximum_worker_vmas":3500000,"minimum_free_bytes":FLOOR});
        (p, restore, unit, guard, gp)
    }
    #[test]
    fn fixed_scope_and_exact_live_command_are_required() {
        let (p, r, u, g, gp) = fixture();
        validate_sources(&p, &r).unwrap();
        validate_unit(&u, &p).unwrap();
        validate_guard(&p, &g, &gp, 1001, 123).unwrap();
        for (key, value) in [
            ("InvocationID", "f".repeat(32)),
            ("NRestarts", "1".into()),
            ("Restart", "on-failure".into()),
            ("ActiveState", "inactive".into()),
            ("Delegate", "yes".into()),
            ("MainPID", "0".into()),
            ("ExecStart", "/bin/true".into()),
        ] {
            let mut bad = u.clone();
            bad.insert(key.into(), value);
            assert!(validate_unit(&bad, &p).is_err(), "{key}");
        }
        for (pointer, value) in [
            ("/original_journal/sha256", json!("0".repeat(64))),
            ("/serialized_clock/sha256", json!("0".repeat(64))),
            ("/scratch_directory", json!("/other/scratch")),
            ("/minimum_free_bytes", json!(FLOOR)),
        ] {
            let mut bad = r.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_sources(&p, &bad).is_err(), "{pointer}");
        }
    }
    #[test]
    fn failed_stale_foreign_or_workerless_guard_is_not_launch_evidence() {
        let (p, _, _, g, gp) = fixture();
        for (pointer, value) in [
            ("/guard_sha256", json!("0".repeat(64))),
            ("/producer_invocation_id", json!("f".repeat(32))),
            ("/producer/pid", json!(1)),
            ("/producer/restarts", json!(1)),
            ("/trip_reason", json!("reserve")),
            ("/worker_observation_error", json!("unreadable")),
            ("/target_handoff_error", json!("bad intent")),
            ("/recorded_unix_seconds", json!(879)),
            ("/recorded_unix_seconds", json!(1002)),
            ("/workers", json!([])),
            ("/workers", json!([[1, 2], [3, 4]])),
            ("/workers", json!([[1, 3500001]])),
            ("/available_bytes", json!(FLOOR - 1)),
            ("/plan_sha256", json!("0".repeat(64))),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_guard(&p, &bad, &gp, 1001, 123).is_err(),
                "{pointer}"
            );
        }
        let mut missing = g.clone();
        missing.as_object_mut().unwrap().remove("trip_reason");
        assert!(validate_guard(&p, &missing, &gp, 1001, 123).is_err());
        let mut bad = gp.clone();
        bad["bounded_canary"] = json!({"expected_uid":1001});
        assert!(validate_guard(&p, &g, &bad, 1001, 123).is_err());
        bad = gp.clone();
        bad["filesystem"] = json!("/");
        assert!(validate_guard(&p, &g, &bad, 1001, 123).is_err());
    }
    #[test]
    fn actual_pinned_eca_emit_schema_needs_no_invented_canary_fields() {
        let (p, _, _, _, gp) = fixture();
        let mut emitted: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/epoch140-eca-guard-sample.json"
        ))
        .unwrap();
        assert!(emitted.get("canary_target_error").is_none());
        emitted["producer_invocation_id"] = json!(p.invocation_id);
        emitted["producer"]["invocation_id"] = json!(p.invocation_id);
        emitted["producer"]["cgroup"] = json!(format!("/system.slice/{}", p.unit));
        emitted["producer"]["pid"] = json!(123);
        emitted["plan_sha256"] = json!(p.guard_plan.sha256);
        emitted["recorded_unix_seconds"] = json!(1000);
        validate_guard(&p, &emitted, &gp, 1001, 123).unwrap();
        let mut bad = emitted.clone();
        bad["canary_target_error"] = Value::Null;
        assert!(validate_guard(&p, &bad, &gp, 1001, 123).is_err());
        bad = emitted.clone();
        bad["bounded_measurement"] = json!(true);
        assert!(validate_guard(&p, &bad, &gp, 1001, 123).is_err());
        let mut bad_plan = gp;
        bad_plan["bounded_canary"] = Value::Null;
        assert!(validate_guard(&p, &emitted, &bad_plan, 1001, 123).is_err());
    }

    #[test]
    fn strict_plan_rejects_unknown_authority_or_replay_fields() {
        let (mut p, r, _, _, _) = fixture();
        let mut value = serde_json::to_value(&p).unwrap();
        assert!(serde_json::from_value::<Plan>(value.clone()).is_ok());
        value["replay_entries_authorized"] = json!(true);
        assert!(serde_json::from_value::<Plan>(value).is_err());
        p.private_run_root = "/home/sol/.jetstreamer-private/epoch213".into();
        assert!(validate_sources(&p, &r).is_err());
    }

    #[test]
    fn first_fire_must_be_real_successful_exact_guard_sandbox() {
        let (p, _, _, mut sample, _) = fixture();
        sample["guard_invocation_id"] = json!("f".repeat(32));
        let binary = "/usr/local/lib/jetstreamer/horizon-standalone-guard-target-handoff-20261019-v2/jetstreamer-horizon-standalone-guard";
        let fields:BTreeMap<String,String>=[("Id",p.guard_unit.clone()),("LoadState","loaded".into()),
            ("InvocationID","f".repeat(32)),("Result","success".into()),("ExecMainStatus","0".into()),
            ("NRestarts","0".into()),("MainPID","0".into()),("ActiveState","inactive".into()),("SubState","dead".into()),
            ("ProtectSystem","strict".into()),("ProtectHome","read-only".into()),("PrivateNetwork","yes".into()),
            ("NoNewPrivileges","yes".into()),("CapabilityBoundingSet","cap_dac_override cap_sys_ptrace".into()),
            ("AmbientCapabilities","cap_dac_override cap_sys_ptrace".into()),
            ("ExecStart",format!("{{ path={binary} ; argv[]={binary} {} --plan-sha256 {} --self-sha256 {GUARD} ; ignore_errors=no }}",p.guard_plan.path.display(),p.guard_plan.sha256))]
            .into_iter().map(|(k,v)|(k.into(),v)).collect();
        validate_guard_service(&fields, &p, &sample).unwrap();
        for (k, v) in [
            ("InvocationID", "0".repeat(32)),
            ("Result", "exit-code".into()),
            ("ExecMainStatus", "1".into()),
            ("MainPID", "9".into()),
            ("ProtectSystem", "false".into()),
            ("ProtectHome", "yes".into()),
            ("PrivateNetwork", "no".into()),
            ("NoNewPrivileges", "no".into()),
            ("CapabilityBoundingSet", "cap_dac_override".into()),
            ("ExecStart", "/bin/true".into()),
        ] {
            let mut bad = fields.clone();
            bad.insert(k.into(), v);
            assert!(validate_guard_service(&bad, &p, &sample).is_err(), "{k}");
        }
    }
}
