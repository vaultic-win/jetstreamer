//! Read-only inspection of the exact retained failed136 prefix. No retirement.
use super::*;
#[path = "holding_epoch136_control.rs"]
mod control;

pub(super) fn disable_retry(m: &Mapping, value: Value, spec: &Bound) -> Result<()> {
    control::disable(m, &serde_json::from_value(value)?, spec)
}

const SOURCE: &str = "/home/sol/.jetstreamer-private/epochs122-147-20260922-v1/lane-i/private/destination-c5792de2a8e0654934ff68ab4eeb99d2a05ffdde82ad8e388a4228ec95fe8bc2/work/root-cohort-136-139/run-821104-1791986784685460478/archives/epoch-136.jet";
const LANE: &str = "/home/sol/.jetstreamer-private/epochs122-147-20260922-v1/lane-i";
const LENGTH: u64 = 99_718_944_924;
const CONTROLLER: &str = "jetstreamer-epochs136-147-target4-controller-v1-r2.service";
const PRODUCER: &str =
    "jetstreamer-root-sweep-e136-147-t4-20261014-v1-r2-e136-139-lane-i-1.service";
const TERMINAL: &str = "/usr/local/lib/jetstreamer/horizon-inactive-136-143-terminal-evidence-20261020-v1/terminal-136.json";
const TERMINAL_SHA: &str = "2e291afbc113ac1cc84405f33e2f55bba2aeb521be0eea6d890a79c2eb00a21b";
const FAILURE: &str = "/usr/local/lib/jetstreamer/epoch136-failure-evidence-20261018-v1/epoch136-failure-evidence-20261018-v1.json";
const FAILURE_SHA: &str = "4629a2bb6806a45c21ab541d19cf6d3368cff47e6965c10304bdfb6c06c5be03";
const QUALIFICATION: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-qualification-20261023-v1/qualification.json";
const QUALIFICATION_SHA: &str = "15692445c39b47b011851b9db68798730077be2cb665dbb7e527049c5e9c5f70";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inspect {
    schema: String,
    mapping: Bound,
    terminal: Bound,
    qualification: Bound,
}

fn scope(p: &Inspect, m: &Mapping, t: &Value, q: &Value) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-inspect136-plan-v2"
            && m.host == HOST
            && m.prefix == "node_02/"
            && p.terminal.path == Path::new(TERMINAL)
            && p.terminal.sha256 == TERMINAL_SHA
            && p.qualification.path == Path::new(QUALIFICATION)
            && p.qualification.sha256 == QUALIFICATION_SHA
            && t["schema"] == "jetstreamer-horizon-terminal-failed-replay-evidence-v1"
            && t["host"] == HOST
            && t["epoch"] == 136
            && t["controller"]["unit"] == CONTROLLER
            && t["controller"]["launch_invocation_id"] == "c1fdb098a76948e093176ebf13061ddb"
            && t["controller"]["retry_path_stopped"] == true
            && t["producer"]["unit"] == PRODUCER
            && t["producer"]["invocation_id"] == "b2c48560af004c3c86c2a3cffd88722c"
            && t["producer"]["terminal_result"] == "exit-code"
            && t["producer"]["terminal_main_status"] == 1
            && t["failure"]["primary_evidence"]["path"] == FAILURE
            && t["failure"]["primary_evidence"]["sha256"] == FAILURE_SHA
            && q["schema"] == "jetstreamer-horizon-node02-holding-transport-qualification-v2"
            && q["host"] == HOST
            && q["prefix"] == m.prefix
            && q["mapping"]["path"].as_str() == p.mapping.path.to_str()
            && q["mapping"]["sha256"] == p.mapping.sha256
            && q["qualified"]["small_authenticated_holding_park_readback_restore"] == true,
        "136 inspection requires exact stopped failure lineage and qualified node_02 transport"
    );
    Ok(())
}

fn terminal_unit(name: &str) -> Result<Value> {
    let out = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", name, "--no-pager", "--property=Id,LoadState,ActiveState,SubState,MainPID,NRestarts,Triggers,TriggeredBy,OnFailure,OnSuccess"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 8192,
        "136 stopped owner metadata unavailable"
    );
    let fields: serde_json::Map<_, _> = std::str::from_utf8(&out.stdout)?
        .lines()
        .map(|line| line.split_once('=').context("136 unit property shape"))
        .map(|r| r.map(|(key, value)| (key.to_owned(), json!(value))))
        .collect::<Result<_>>()?;
    let v = Value::Object(fields);
    terminal_shape(name, &v)?;
    Ok(v)
}

fn terminal_shape(name: &str, v: &Value) -> Result<()> {
    ensure!(
        matches!(name, CONTROLLER | PRODUCER)
            && v["Id"] == name
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && (matches!(v["LoadState"].as_str(), Some("loaded" | "not-found"))
                || (name == CONTROLLER && v["LoadState"] == "masked"))
            && ["Triggers", "TriggeredBy", "OnFailure", "OnSuccess"]
                .iter()
                .all(|k| v[*k] == ""),
        "136 owner is live, restarted or has relaunch/handoff triggers"
    );
    Ok(())
}

fn retained_source(f: &Value) -> Result<(FileIdentity, Value)> {
    let path = Path::new(SOURCE);
    ensure!(
        path.canonicalize()? == path && Path::new(LANE).canonicalize()? == Path::new(LANE),
        "136 retained source or lane is aliased"
    );
    let md = fs::symlink_metadata(path)?;
    let id = regular_identity(path)?;
    let old = &f["partial_archive"];
    ensure!(
        f["epoch"] == 136
            && f["host"] == HOST
            && old["path"] == SOURCE
            && old["size_bytes"] == LENGTH
            && id.length == LENGTH
            && old["device"] == id.device
            && old["inode"] == id.inode
            && id.device == 64512
            && id.inode == 99352633
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.mtime() == 1792326715
            && md.ctime() == 1792326715,
        "136 retained failed prefix no longer matches original identity"
    );
    for suffix in ["jet.sha256", "sha256"] {
        let sidecar = path.with_extension(suffix);
        ensure!(
            fs::symlink_metadata(&sidecar).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "136 partial has a sidecar or unreadable sidecar path"
        );
    }
    Ok((
        id,
        json!({"device":md.dev(),"inode":md.ino(),"length":md.len(),"links":md.nlink(),
        "uid":md.uid(),"gid":md.gid(),"mode":md.mode()&0o7777,
        "mtime_seconds":md.mtime(),"mtime_nanoseconds":md.mtime_nsec(),
        "ctime_seconds":md.ctime(),"ctime_nanoseconds":md.ctime_nsec(),
        "physical_bytes":md.blocks().checked_mul(512).context("136 physical block overflow")?}),
    ))
}

pub(super) fn inspect(m: &Mapping, p: &Inspect, spec: &Bound) -> Result<()> {
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "136 mapping changed"
    );
    let terminal = bound(&p.terminal)?;
    let qualification = bound(&p.qualification)?;
    scope(p, m, &terminal, &qualification)?;
    let failure_binding = Bound {
        path: FAILURE.into(),
        sha256: FAILURE_SHA.into(),
    };
    let failure = bound(&failure_binding)?;
    let controller = terminal_unit(CONTROLLER)?;
    let producer = terminal_unit(PRODUCER)?;
    let (id, metadata) = retained_source(&failure)?;
    let before = no_references(Path::new(LANE))?;
    let proof = hash_and_etag(Path::new(SOURCE), id, DEFAULT_PART_SIZE)?;
    ensure!(
        retained_source(&failure)? == (id, metadata.clone()),
        "136 retained prefix changed while hashing"
    );
    let after = no_references(Path::new(LANE))?;
    ensure!(
        terminal_unit(CONTROLLER)? == controller && terminal_unit(PRODUCER)? == producer,
        "136 owner metadata changed during inspection"
    );
    let value = json!({"schema":"jetstreamer-horizon-holding-eligibility-v2","host":HOST,
        "source":SOURCE,"length":LENGTH,"sha256":proof.sha256_hex,"closed":true,
        "content_class":"public-chain-artifact","credentials_config_and_logs_excluded":true,
        "canonical_archive":false,"local_retirement_authorized":false,
        "epoch":136,"artifact_kind":"retained-failed-partial-archive",
        "original_failure":failure_binding,"terminal":p.terminal,"qualification":p.qualification,
        "mapping":p.mapping,"inspection_spec":{"path":spec.path,"sha256":spec.sha256},
        "source_identity":metadata,"multipart_etag":proof.multipart_etag,"part_size":DEFAULT_PART_SIZE,
        "controller":controller,"producer":producer,
        "reference_census_before":before,"reference_census_after":after,
        "staged_reference_and_retirement_review_required":true,
        "failure_repaired":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,
        "replay_launch_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false,"new_resource_samples":0});
    let destination = Path::new(STATE)
        .join("receipts")
        .join(format!("inspect136-{}.json", spec.sha256));
    persist(&destination, &value)?;
    println!("{}", destination.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_stopped_original_owners_without_triggers_are_accepted() {
        let v = json!({"Id":CONTROLLER,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead",
            "MainPID":"0","NRestarts":"0","Triggers":"","TriggeredBy":"","OnFailure":"","OnSuccess":""});
        terminal_shape(CONTROLLER, &v).unwrap();
        let mut masked = v.clone();
        masked["LoadState"] = json!("masked");
        terminal_shape(CONTROLLER, &masked).unwrap();
        masked["Id"] = json!(PRODUCER);
        assert!(terminal_shape(PRODUCER, &masked).is_err());
        for (key, value) in [
            ("MainPID", "12"),
            ("NRestarts", "1"),
            ("TriggeredBy", "retry.timer"),
            ("OnFailure", "retry.service"),
            ("ActiveState", "active"),
            ("LoadState", "error"),
        ] {
            let mut bad = v.clone();
            bad[key] = json!(value);
            assert!(terminal_shape(CONTROLLER, &bad).is_err(), "{key}");
        }
        assert!(terminal_shape("new-repair.service", &v).is_err());
    }
    #[test]
    fn inspector_cannot_select_another_file_or_grant_retirement() {
        let binding = json!({"path":"/sealed/evidence.json","sha256":"a".repeat(64)});
        let mut p = json!({"schema":"jetstreamer-horizon-holding-inspect136-plan-v2",
            "mapping":binding,"terminal":binding,"qualification":binding});
        assert!(serde_json::from_value::<Inspect>(p.clone()).is_ok());
        p["source"] = json!("/home/sol/horizon/epoch-136.jet");
        assert!(serde_json::from_value::<Inspect>(p.clone()).is_err());
        p.as_object_mut().unwrap().remove("source");
        p["retire"] = json!(true);
        assert!(serde_json::from_value::<Inspect>(p).is_err());
    }
}
