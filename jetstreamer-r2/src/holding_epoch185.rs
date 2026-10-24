//! Exact failed185 inspection, collected-controller closure and separately gated
//! authenticated-custody local retirement. No canonical publication or job resume.
use super::*;
#[path = "holding_epoch185_retire.rs"]
mod retire;

pub(super) async fn retire_local(
    client: &Client,
    m: &Mapping,
    value: Value,
    spec: &Bound,
    check: bool,
) -> Result<()> {
    retire::run(client, m, &serde_json::from_value(value)?, spec, check).await
}

const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch185-singleton-20261020-v1/lane-a/private/destination-9d993937f539bf7591c81fd831c0b525eead17dd3e52088d2fc90cec7f9e6fa9/work/root-cohort-185-185/run-333127-1792725435594713064/archives/epoch-185.jet";
const LANE: &str = "/home/sol/.jetstreamer-private/epoch185-singleton-20261020-v1/lane-a";
const LENGTH: u64 = 56_206_322_555;
const CONTROLLER: &str = "jetstreamer-epoch185-full-20261023-controller-v1-r2.service";
const PRODUCER: &str = "jetstreamer-root-sweep-e185-full-20261023-v1-r2-e185-185-lane-a-1.service";
const CONTROLLER_ID: &str = "fcc936d65490488aa95df0d1732bc40e";
const PRODUCER_ID: &str = "0de9498a3c2f4c6dbd7350d052fc7e02";
const GUARD_ROOT: &str =
    "/var/lib/jetstreamer-adaptive-reserve-controller-rebind-185-185-20261023-v1";
const INTENT_SHA: &str = "6f78b2e30358e96e025fe661b13c95ba277c3417c740b60ef990668f478fb545";
const COMPLETION_SHA: &str = "72c180d480c8780c802915201c68a575a648a3ec5dcc22b5a818d90f26f83890";
const DEPLOYMENT: &str =
    "/usr/local/lib/jetstreamer/deploy-epoch185-singleton-20261020-v1/deployment-seal-receipt.json";
const DEPLOYMENT_SHA: &str = "4aec45a16fd4a3da9eaed08e9f7e22a164d811a10dcbae89c8cbc427dd5c5ff4";
const QUALIFICATION: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-qualification-20261023-v1/qualification.json";
const QUALIFICATION_SHA: &str = "15692445c39b47b011851b9db68798730077be2cb665dbb7e527049c5e9c5f70";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inspect {
    schema: String,
    mapping: Bound,
    guard_intent: Bound,
    guard_completion: Bound,
    qualification: Bound,
    deployment: Bound,
}

fn scope(p: &Inspect, m: &Mapping, i: &Value, c: &Value, q: &Value) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-inspect185-plan-v2"
            && m.host == HOST
            && m.prefix == "node_02/"
            && p.guard_intent.path == Path::new(GUARD_ROOT).join("intent.json")
            && p.guard_intent.sha256 == INTENT_SHA
            && p.guard_completion.path == Path::new(GUARD_ROOT).join("completion.json")
            && p.guard_completion.sha256 == COMPLETION_SHA
            && p.deployment.path == Path::new(DEPLOYMENT)
            && p.deployment.sha256 == DEPLOYMENT_SHA
            && p.qualification.path == Path::new(QUALIFICATION)
            && p.qualification.sha256 == QUALIFICATION_SHA,
        "foreign185 stop or transport binding"
    );
    ensure!(
        i["schema"] == "jetstreamer-adaptive-replay-reserve-stop-intent-v1"
            && c["schema"] == "jetstreamer-adaptive-replay-reserve-stop-completion-v1"
            && i["controller_sample"]["invocation_id"] == CONTROLLER_ID
            && i["producer_sample"]["invocation_id"] == PRODUCER_ID
            && c["intent_receipt"] == p.guard_intent.path.to_str().unwrap()
            && c["scratch_deleted"] == false,
        "185 native stop lineage differs"
    );
    for v in [i, c] {
        ensure!(
            v["controller_unit"] == CONTROLLER
                && v["producer_unit"] == PRODUCER
                && v["expected_controller_invocation_id"] == CONTROLLER_ID
                && v["expected_producer_invocation_id"] == PRODUCER_ID
                && v["minimum_free_bytes"] == 3_503_746_342_342u64
                && v["remote_mutations"] == false
                && v["r2_mutations"] == false,
            "185 guard binding differs"
        );
    }
    for key in ["controller_final", "producer_final"] {
        ensure!(
            c[key]["active_state"] == "inactive"
                && c[key]["main_pid"] == 0
                && c[key]["restarts"] == 0,
            "185 native stop incomplete"
        );
    }
    ensure!(
        q["schema"] == "jetstreamer-horizon-node02-holding-transport-qualification-v2"
            && q["host"] == HOST
            && q["prefix"] == m.prefix
            && q["mapping"] == serde_json::to_value(&p.mapping)?
            && q["qualified"]["small_authenticated_holding_park_readback_restore"] == true,
        "185 transport not qualified"
    );
    Ok(())
}

fn terminal_unit(name: &str) -> Result<Value> {
    let out = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", name, "--no-pager", "--property=Id,LoadState,ActiveState,SubState,MainPID,NRestarts,Triggers,TriggeredBy,OnFailure,OnSuccess"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 8192,
        "185 stopped owner metadata unavailable"
    );
    let fields: serde_json::Map<_, _> = std::str::from_utf8(&out.stdout)?
        .lines()
        .map(|line| line.split_once('=').context("185 unit property shape"))
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
            && v["LoadState"] == "not-found"
            && ["Triggers", "TriggeredBy", "OnFailure", "OnSuccess"]
                .iter()
                .all(|k| v[*k] == ""),
        "185 owner is live, restarted or has relaunch/handoff triggers"
    );
    Ok(())
}

fn retained_source() -> Result<(FileIdentity, Value)> {
    let path = Path::new(SOURCE);
    ensure!(
        path.canonicalize()? == path && Path::new(LANE).canonicalize()? == Path::new(LANE),
        "185 retained source or lane is aliased"
    );
    let md = fs::symlink_metadata(path)?;
    let id = regular_identity(path)?;
    ensure!(
        id.length == LENGTH
            && id.device == 64512
            && id.inode == 100270097
            && md.nlink() == 1
            && md.mtime_nsec() == 171229060
            && md.ctime_nsec() == 171229060
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.mtime() == 1792801929
            && md.ctime() == 1792801929,
        "185 retained failed prefix no longer matches original identity"
    );
    for suffix in ["jet.sha256", "sha256"] {
        let sidecar = path.with_extension(suffix);
        ensure!(
            fs::symlink_metadata(&sidecar).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "185 partial has a sidecar or unreadable sidecar path"
        );
    }
    Ok((
        id,
        json!({"device":md.dev(),"inode":md.ino(),"length":md.len(),"links":md.nlink(),
        "uid":md.uid(),"gid":md.gid(),"mode":md.mode()&0o7777,
        "mtime_seconds":md.mtime(),"mtime_nanoseconds":md.mtime_nsec(),
        "ctime_seconds":md.ctime(),"ctime_nanoseconds":md.ctime_nsec(),
        "physical_bytes":md.blocks().checked_mul(512).context("185 physical block overflow")?}),
    ))
}

pub(super) fn inspect(m: &Mapping, p: &Inspect, spec: &Bound) -> Result<()> {
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "185 mapping changed"
    );
    let intent = evidence(&p.guard_intent, false)?;
    let completion = evidence(&p.guard_completion, false)?;
    let qualification = bound(&p.qualification)?;
    let _deployment = bound(&p.deployment)?;
    scope(p, m, &intent, &completion, &qualification)?;
    let controller = terminal_unit(CONTROLLER)?;
    let producer = terminal_unit(PRODUCER)?;
    let (id, metadata) = retained_source()?;
    let before = closed_references()?;
    let proof = hash_and_etag(Path::new(SOURCE), id, DEFAULT_PART_SIZE)?;
    ensure!(
        retained_source()? == (id, metadata.clone()),
        "185 retained prefix changed while hashing"
    );
    let after = closed_references()?;
    ensure!(
        terminal_unit(CONTROLLER)? == controller && terminal_unit(PRODUCER)? == producer,
        "185 owner metadata changed during inspection"
    );
    let value = json!({"schema":"jetstreamer-horizon-holding-eligibility-v2","host":HOST,
        "source":SOURCE,"length":LENGTH,"sha256":proof.sha256_hex,"closed":true,
        "content_class":"public-chain-artifact","credentials_config_and_logs_excluded":true,
        "canonical_archive":false,"local_retirement_authorized":false,
        "epoch":185,"artifact_kind":"retained-failed-partial-archive",
        "guard_intent":p.guard_intent,"guard_completion":p.guard_completion,"qualification":p.qualification,"deployment":p.deployment,
        "interrupted_container_unvalidated":true,"valid_prefix_established":false,
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
        .join(format!("inspect185-{}.json", spec.sha256));
    persist(&destination, &value)?;
    println!("{}", destination.display());
    Ok(())
}

fn closed_references() -> Result<Value> {
    // Collected transient owners must not have a persistent relaunch definition.
    for name in [CONTROLLER, PRODUCER] {
        terminal_unit(name)?;
        for root in [
            "/etc/systemd/system",
            "/run/systemd/system",
            "/run/systemd/transient",
        ] {
            ensure!(
                fs::symlink_metadata(Path::new(root).join(name))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "185 owner has retained relaunch configuration"
            );
        }
    }
    let processes = no_references(Path::new(LANE))?;
    let staged =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(Path::new(LANE))?;
    ensure!(
        staged["references"] == json!([]),
        "185 lane has staged consumers"
    );
    Ok(json!({"processes":processes,"staged":staged}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collected_exact_owners_only() {
        let v = json!({"Id":CONTROLLER,"LoadState":"not-found","ActiveState":"inactive","SubState":"dead",
            "MainPID":"0","NRestarts":"0","Triggers":"","TriggeredBy":"","OnFailure":"","OnSuccess":""});
        terminal_shape(CONTROLLER, &v).unwrap();
        for (k, x) in [
            ("LoadState", "loaded"),
            ("LoadState", "masked"),
            ("MainPID", "1"),
            ("TriggeredBy", "retry.timer"),
            ("OnSuccess", "next.service"),
            ("NRestarts", "1"),
        ] {
            let mut bad = v.clone();
            bad[k] = json!(x);
            assert!(terminal_shape(CONTROLLER, &bad).is_err());
        }
        assert!(terminal_shape("replacement.service", &v).is_err());
    }
    #[test]
    fn exact_guard_and_package_cannot_be_rebound() {
        let b = Bound {
            path: "/sealed/map.json".into(),
            sha256: "a".repeat(64),
        };
        let p = Inspect {
            schema: "jetstreamer-horizon-holding-inspect185-plan-v2".into(),
            mapping: b.clone(),
            guard_intent: Bound {
                path: Path::new(GUARD_ROOT).join("intent.json"),
                sha256: INTENT_SHA.into(),
            },
            guard_completion: Bound {
                path: Path::new(GUARD_ROOT).join("completion.json"),
                sha256: COMPLETION_SHA.into(),
            },
            qualification: Bound {
                path: QUALIFICATION.into(),
                sha256: QUALIFICATION_SHA.into(),
            },
            deployment: Bound {
                path: DEPLOYMENT.into(),
                sha256: DEPLOYMENT_SHA.into(),
            },
        };
        let m = Mapping {
            schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
            host: HOST.into(),
            prefix: "node_02/".into(),
            user_provided_prefix: true,
            authorization_reference: "fixture".into(),
        };
        let mut i = json!({"schema":"jetstreamer-adaptive-replay-reserve-stop-intent-v1",
            "controller_sample":{"invocation_id":CONTROLLER_ID},"producer_sample":{"invocation_id":PRODUCER_ID}});
        let mut c = json!({"schema":"jetstreamer-adaptive-replay-reserve-stop-completion-v1",
            "intent_receipt":p.guard_intent.path,"scratch_deleted":false,
            "controller_final":{"active_state":"inactive","main_pid":0,"restarts":0},
            "producer_final":{"active_state":"inactive","main_pid":0,"restarts":0}});
        for v in [&mut i, &mut c] {
            v["controller_unit"] = json!(CONTROLLER);
            v["producer_unit"] = json!(PRODUCER);
            v["expected_controller_invocation_id"] = json!(CONTROLLER_ID);
            v["expected_producer_invocation_id"] = json!(PRODUCER_ID);
            v["minimum_free_bytes"] = json!(3_503_746_342_342u64);
            v["remote_mutations"] = json!(false);
            v["r2_mutations"] = json!(false);
        }
        let q = json!({"schema":"jetstreamer-horizon-node02-holding-transport-qualification-v2",
            "host":HOST,"prefix":"node_02/","mapping":b,
            "qualified":{"small_authenticated_holding_park_readback_restore":true}});
        scope(&p, &m, &i, &c, &q).unwrap();
        let mut bad = c.clone();
        bad["expected_producer_invocation_id"] = json!("other");
        assert!(scope(&p, &m, &i, &bad, &q).is_err());
        bad = c.clone();
        bad["scratch_deleted"] = json!(true);
        assert!(scope(&p, &m, &i, &bad, &q).is_err());
        let mut badp = p;
        badp.deployment.sha256 = "b".repeat(64);
        assert!(scope(&badp, &m, &i, &c, &q).is_err());
    }
    #[test]
    fn plan_cannot_select_path_or_assert_continuation() {
        let b = json!({"path":"/sealed/x.json","sha256":"a".repeat(64)});
        let p = json!({"schema":"jetstreamer-horizon-holding-inspect185-plan-v2",
            "mapping":b,"guard_intent":b,"guard_completion":b,"qualification":b,"deployment":b});
        assert!(serde_json::from_value::<Inspect>(p.clone()).is_ok());
        for key in ["source", "retire", "job_resume_authorized"] {
            let mut bad = p.clone();
            bad[key] = json!(true);
            assert!(serde_json::from_value::<Inspect>(bad).is_err());
        }
    }
}
