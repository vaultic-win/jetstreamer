//! Bounded exact213 maintenance, under the adapter's one transition flock.
//! No replay resource polling, public status, publication or generic cleanup.
use super::*;

pub(super) const UNIT: &str = "horizon-foundation-holding213-maintenance-v1.service";
const MAX_SECONDS: u64 = 14400;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mapping: Bound,
    park: Bound,
    custody: Option<Bound>,
    restoration: Option<Bound>,
    resource_basis: Value,
    maximum_execution_seconds: u64,
}
fn receipt(prefix: &str, plan: &Bound) -> PathBuf {
    Path::new(STATE)
        .join("receipts")
        .join(format!("{prefix}-{}.json", plan.sha256))
}
fn linked(p: &Spec, park: &ParkSpec) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-foundation-holding-maintenance-plan-v1"
            && p.maximum_execution_seconds == MAX_SECONDS
            && park.artifact == Artifact::Prefix213
            && serde_json::to_value(&park.mapping)? == serde_json::to_value(&p.mapping)?
            && p.custody
                .as_ref()
                .is_none_or(|b| b.path == receipt("custody", &p.park))
            && (p.restoration.is_none() || p.custody.is_some()),
        "maintenance is not one exact linked213 custody/restoration set"
    );
    Ok(())
}
fn own_unit() -> Result<(String, Value)> {
    let iid =
        env::var("INVOCATION_ID").context("maintenance requires systemd invocation identity")?;
    ensure!(
        iid.len() == 32 && iid.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid maintenance invocation"
    );
    let out=std::process::Command::new("/usr/bin/systemctl").args(["show",UNIT,"--no-pager",
        "--property=Id,ActiveState,SubState,MainPID,InvocationID,NRestarts,Restart,TimeoutStartUSec,MemoryMax,TasksMax,ExecStart,OnSuccess,OnFailure,TriggeredBy"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 32768,
        "maintenance unit metadata unavailable"
    );
    let values = std::str::from_utf8(&out.stdout)?
        .lines()
        .map(|l| {
            let (k, v) = l.split_once('=').context("maintenance property shape")?;
            Ok((k.to_owned(), json!(v)))
        })
        .collect::<Result<serde_json::Map<_, _>>>()?;
    let v = Value::Object(values);
    ensure!(
        v["Id"] == UNIT
            && v["InvocationID"] == iid
            && v["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok())
                == Some(std::process::id())
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["ActiveState"] == "activating"
            && v["SubState"] == "start"
            && v["TimeoutStartUSec"] == "4h"
            && v["MemoryMax"] == "6442450944"
            && v["TasksMax"] == "256"
            && v["OnSuccess"] == ""
            && v["OnFailure"] == ""
            && v["TriggeredBy"] == "",
        "maintenance must be one bounded non-restarting exact invocation"
    );
    Ok((iid, v))
}
fn deadline(started: u64) -> Result<()> {
    ensure!(
        clock()?
            .checked_sub(started)
            .is_some_and(|s| s < MAX_SECONDS),
        "maintenance deadline reached; preserve current phase for next admission"
    );
    Ok(())
}
fn phase(dir: &Path, name: &str, evidence: &Bound) -> Result<()> {
    let value = receipt_bound(evidence)?;
    let target = dir.join(format!("{name}.json"));
    durable_receipt(
        &target,
        &json!({"schema":"jetstreamer-foundation-holding-maintenance-phase-v1",
        "phase":name,"evidence":evidence,"artifact":"prefix213","evidence_schema":value["schema"],
        "replay_launch_authorized":false,"canonical_publication_authorized":false}),
    )
}
fn bind(path: &Path) -> Result<Bound> {
    let bytes = read_stable_bounded(path, MAX_RECEIPT_BYTES as u64, "maintenance phase evidence")?;
    let b = Bound {
        path: path.to_path_buf(),
        sha256: hex_lower(&Sha256::digest(bytes)),
    };
    receipt_bound(&b)?;
    Ok(b)
}
fn plan(dir: &Path, name: &str, value: Value) -> Result<Bound> {
    let path = dir.join(format!("{name}-plan.json"));
    durable_receipt(&path, &value)?;
    bind(&path)
}
/// systemd ExecStopPost records PID1's actual outcome even after timeout/OOM or
/// SIGKILL prevented the main Rust body from writing its application terminal.
pub(super) fn finalize(v: Value, spec: &Bound) -> Result<()> {
    let p: Spec = serde_json::from_value(v)?;
    mapping_binding(&p.mapping)?;
    ensure!(
        p.schema == "jetstreamer-foundation-holding-maintenance-plan-v1"
            && p.maximum_execution_seconds == MAX_SECONDS,
        "foreign maintenance terminal plan"
    );
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        iid.len() == 32 && iid.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid terminal invocation"
    );
    let dir = Path::new(STATE).join(format!("maintenance-{}-{iid}", spec.sha256));
    private(&dir)?;
    let claim = bind(&dir.join("claim.json"))?;
    let c = receipt_bound(&claim)?;
    ensure!(
        c["schema"] == "jetstreamer-foundation-holding-maintenance-claim-v1"
            && c["spec"] == serde_json::to_value(spec)?
            && c["unit"] == UNIT
            && c["invocation_id"] == iid,
        "maintenance terminal claim differs"
    );
    let result = env::var("SERVICE_RESULT")?;
    ensure!(
        matches!(
            result.as_str(),
            "success"
                | "timeout"
                | "exit-code"
                | "signal"
                | "core-dump"
                | "resources"
                | "oom-kill"
                | "start-limit-hit"
        ),
        "unknown systemd result"
    );
    let out=std::process::Command::new("/usr/bin/systemctl").args(["show",UNIT,"--no-pager",
        "--property=Id,InvocationID,MainPID,NRestarts,ActiveState,SubState,Restart,Result,ExecMainCode,ExecMainStatus"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16384,
        "maintenance terminal unit unavailable"
    );
    let fields = std::str::from_utf8(&out.stdout)?
        .lines()
        .map(|line| {
            let (k, v) = line
                .split_once('=')
                .context("terminal unit property shape")?;
            Ok((k.to_owned(), json!(v)))
        })
        .collect::<Result<serde_json::Map<_, _>>>()?;
    let unit = Value::Object(fields);
    ensure!(
        unit["Id"] == UNIT
            && unit["InvocationID"] == iid
            && unit["MainPID"] == "0"
            && unit["NRestarts"] == "0"
            && unit["Restart"] == "no"
            && unit["ActiveState"] == "deactivating"
            && unit["SubState"] == "stop-post",
        "terminal identity is not this completed main invocation"
    );
    let application = dir.join("terminal.json");
    let application = if application.try_exists()? {
        Some(bind(&application)?)
    } else {
        None
    };
    ensure!(
        result != "success"
            || application
                .as_ref()
                .is_some_and(|b| receipt_bound(b).is_ok_and(|v| v["success"] == true)),
        "systemd success lacks the complete application terminal"
    );
    durable_receipt(
        &dir.join("pid1-terminal.json"),
        &json!({"schema":"jetstreamer-foundation-holding-maintenance-pid1-terminal-v1",
        "spec":spec,"claim":claim,"application_terminal":application,"unit":unit,"invocation_id":iid,
        "service_result":result,"exit_code":env::var("EXIT_CODE").ok(),"exit_status":env::var("EXIT_STATUS").ok(),
        "recorded_unix_seconds":clock()?,"success":result=="success","replay_launch_authorized":false,
        "canonical_publication_authorized":false,"remote_mutations":false}),
    )
}
pub(super) async fn run(client: &Client, v: Value, spec: &Bound) -> Result<()> {
    let p: Spec = serde_json::from_value(v)?;
    mapping_binding(&p.mapping)?;
    let park_plan: ParkSpec = serde_json::from_value(bound(&p.park)?)?;
    linked(&p, &park_plan)?;
    let (iid, unit) = own_unit()?;
    let started = clock()?;
    let directory = Path::new(STATE).join(format!("maintenance-{}-{iid}", spec.sha256));
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    File::open(STATE)?.sync_all()?;
    private(&directory)?;
    let claim = json!({"schema":"jetstreamer-foundation-holding-maintenance-claim-v1",
        "spec":spec,"unit":UNIT,"invocation_id":iid,"unit_at_start":unit,"started_unix_seconds":started,
        "maximum_execution_seconds":MAX_SECONDS,"memory_max_bytes":6442450944u64,"tasks_max":256,
        "artifact":"prefix213","canonical_epoch_already_ready":true,"public_status_required":false,
        "transition_lock_held_through_terminal":true,"new_resource_samples":0,
        "replay_launch_authorized":false,"canonical_publication_authorized":false,
        "job_resume_authorized":false,"remote_overwrite_authorized":false,"remote_delete_authorized":false});
    durable_receipt(&directory.join("claim.json"), &claim)?;
    // Re-entry reuses durable transport receipts. Admission may be refreshed in
    // a new immutable plan after timeout without repeating completed transport.
    let result: Result<()> = async {
        deadline(started)?;
        let custody_path = receipt("custody", &p.park);
        if !custody_path.try_exists()? {
            park(client, &park_plan, &p.park).await?;
        }
        let custody_binding = if let Some(b) = &p.custody {
            b.clone()
        } else {
            bind(&custody_path)?
        };
        let c = receipt_bound(&custody_binding)?;
        ensure!(
            custody(&c)? == Artifact::Prefix213,
            "maintenance reused a foreign custody receipt"
        );
        phase(&directory, "parked", &custody_binding)?;
        deadline(started)?;
        let restored = if let Some(b) = &p.restoration {
            receipt_bound(b)?;
            b.clone()
        } else {
            let a = plan(
                &directory,
                "admit-restore",
                json!({"schema":"jetstreamer-foundation-holding-restore-admission-plan-v1",
                "mapping":p.mapping,"custody":custody_binding,"resource_basis":p.resource_basis}),
            )?;
            let admit_plan: AdmitSpec = serde_json::from_value(bound(&a)?)?;
            admit(&admit_plan, &a)?;
            let admitted = bind(&receipt("restore-admission", &a))?;
            phase(&directory, "admitted", &admitted)?;
            let r = plan(
                &directory,
                "restore",
                json!({"schema":"jetstreamer-foundation-holding-restore-plan-v1",
                "mapping":p.mapping,"custody":custody_binding,"admission":admitted}),
            )?;
            let restore_plan: RestoreSpec = serde_json::from_value(bound(&r)?)?;
            restore(client, &restore_plan, &r).await?;
            bind(&receipt("restore", &r))?
        };
        phase(&directory, "restored", &restored)?;
        deadline(started)?;
        let retirement = plan(
            &directory,
            "retire",
            json!({"schema":"jetstreamer-foundation-holding-retirement-plan-v1",
            "mapping":p.mapping,"custody":custody_binding,"restoration":restored,
            "accepted_fleet":p.resource_basis["fleet"],"resource_basis":p.resource_basis}),
        )?;
        retirement::run(client, bound(&retirement)?, &retirement).await?;
        deadline(started)?;
        Ok(())
    }
    .await;
    let terminal = json!({"schema":"jetstreamer-foundation-holding-maintenance-terminal-v1",
        "spec":spec,"unit":UNIT,"invocation_id":iid,"started_unix_seconds":started,
        "finished_unix_seconds":clock()?,"success":result.is_ok(),
        "error":result.as_ref().err().map(|e|format!("{e:#}")),"new_resource_samples":0,
        "replay_launch_authorized":false,"canonical_publication_authorized":false,
        "job_resume_authorized":false,"remote_delete_authorized":false,"remote_overwrite_authorized":false});
    durable_receipt(&directory.join("terminal.json"), &terminal)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_plan_cannot_add_a_launch_another_artifact_or_disable_the_deadline() {
        let b = json!({"path":"/sealed/evidence.json","sha256":"a".repeat(64)});
        let good = json!({"schema":"jetstreamer-foundation-holding-maintenance-plan-v1","mapping":b,
            "park":b,"custody":null,"restoration":null,"resource_basis":{},"maximum_execution_seconds":MAX_SECONDS});
        assert!(serde_json::from_value::<Spec>(good.clone()).is_ok());
        for field in [
            "launch",
            "delete_remote",
            "artifact",
            "public_status",
            "skip_admission",
        ] {
            let mut bad = good.clone();
            bad[field] = json!(true);
            assert!(serde_json::from_value::<Spec>(bad).is_err(), "{field}");
        }
        assert!(deadline(clock().unwrap() - MAX_SECONDS).is_err());
        assert!(deadline(clock().unwrap() + 1).is_err());
    }
}
