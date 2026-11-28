//! Exact 185 metadata lifecycle reconciliation. Never selects replay data or excludes staged references.
use super::*;

const ROOT: &str = "/var/lib/jetstreamer/horizon-terminal185-staged-reconciliation-20261024-v1";
const BACKUP: &str =
    "/usr/local/lib/jetstreamer/horizon-node02-holding-epoch185-staged-backup-20261024-v1";
const OLD_CONTROLLER: &str = "jetstreamer-epoch185-singleton-20261020-controller-v1-r2.service";
const OLD_SHA: &str = "949de6d3feca587ea6c7bfcf8e798cf007042bc909c706acdd6ab6e62961c2cc";
const ORIGINAL: &str =
    "/etc/systemd/system/jetstreamer-epoch185-singleton-20261020-controller-v1-r2.service";
const RETAINED: &str = "/var/lib/jetstreamer/horizon-terminal185-staged-reconciliation-20261024-v1/original-controller.service.txt";

#[derive(Clone, Copy)]
struct Job {
    unit: &'static str,
    iid: &'static str,
    sha: &'static str,
    status: u64,
}
const JOBS: [Job; 8] = [
    Job {
        unit: "horizon-idle-credentials185-full-refresh-20261023-v2.service",
        iid: "8ba1b16aa699497aa9b6969c4c32b1d3",
        sha: "501b1a83bca50c3b0be9ef547d34a414fc2731cf4417a3948ef3e41603e891b6",
        status: 1,
    },
    Job {
        unit: "horizon-idle-credentials185-full-refresh-20261023-v1.service",
        iid: "8a6b59d5b41e4435ba250adb82bbba88",
        sha: "16f55d94c50a65c60d8669f1d481d517cb8e7dcf0c2a1b06827552446ed39795",
        status: 1,
    },
    Job {
        unit: "horizon-idle-credentials185-full-preflight-20261023-v3.service",
        iid: "19ed89435ee7400082e9024d4edaadba",
        sha: "f7d15ca9738fb4446281c5dba4baffb8140dd3ed8b4584bec34b4c53e2577172",
        status: 0,
    },
    Job {
        unit: "horizon-idle-credentials185-full-preflight-20261023-v1.service",
        iid: "b186503073ea4add9ae4bc1085bb9425",
        sha: "c1ee4781ad77c3627dc2d0055b16c8526160289f8804a11506bab5956de29611",
        status: 0,
    },
    Job {
        unit: "horizon-idle-credentials185-full-preflight-20261023-v2.service",
        iid: "4cc2800de24240e2afcfa9848a2f064e",
        sha: "57cbf46ba47d74966e9928507463c8e1284e0125c3474a699faae929130ba326",
        status: 0,
    },
    Job {
        unit: "horizon-epoch185-full-admission-20261023-v1.service",
        iid: "169c422dfcd944b8b71408746febc9ea",
        sha: "6c0808f547d8b34838c2e87dbac2a29fac176eae97d97f315a6abbd9416eea3a",
        status: 1,
    },
    Job {
        unit: "horizon-epoch185-full-admission-20261023-v2.service",
        iid: "14b9b17da2674ed6b9a28c22401b9f8b",
        sha: "a7dc98e979428bd40ec2ccfac308786f8be44a54ba014bba653e270b5513ebfb",
        status: 0,
    },
    Job {
        unit: "horizon-idle-credentials185-full-refresh-20261023-v3.service",
        iid: "8da436fc1486466f9a6c79402e96791d",
        sha: "31012d51b4bd68fdd6e4f761a94ab26516cdf947f538b20c4a7dc94ed0e145fd",
        status: 0,
    },
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reconcile {
    schema: String,
    mapping: Bound,
    inspection_plan: Bound,
    diagnostic: Bound,
    preservation: Bound,
}
fn config_path(unit: &str) -> PathBuf {
    if unit == OLD_CONTROLLER {
        PathBuf::from(ORIGINAL)
    } else {
        Path::new("/run/systemd/transient").join(unit)
    }
}
fn manager_raw(name: &str) -> Result<Value> {
    ensure!(
        name == OLD_CONTROLLER || JOBS.iter().any(|j| j.unit == name),
        "foreign 185 metadata owner"
    );
    let out=std::process::Command::new("/usr/bin/systemctl").args(["show",name,"--no-pager","--all",
        "--property=Id,LoadState,ActiveState,SubState,MainPID,NRestarts,InvocationID,Triggers,TriggeredBy,OnFailure,OnSuccess,ExecStop,ExecStopPost,Restart,Type,RemainAfterExit,ExecMainStatus,Result,ControlGroup,FragmentPath,Job,ControlPID"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "185 metadata manager read failed"
    );
    let fields: serde_json::Map<_, _> = std::str::from_utf8(&out.stdout)?
        .lines()
        .map(|l| l.split_once('=').context("185 metadata property shape"))
        .map(|r| r.map(|(k, v)| (k.to_owned(), json!(v))))
        .collect::<Result<_>>()?;
    Ok(Value::Object(fields))
}
fn object_path(name: &str) -> String {
    let mut path = String::from("/org/freedesktop/systemd1/unit/");
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() {
            path.push(char::from(b));
        } else {
            path.push_str(&format!("_{b:02x}"));
        }
    }
    path
}
fn property(name: &str, interface: &str, key: &str) -> Result<Value> {
    let out = std::process::Command::new("/usr/bin/busctl")
        .args([
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            &object_path(name),
            interface,
            key,
        ])
        .output()?;
    decode_property_output(out.status.success(), &out.stdout, key)
}
fn decode_property_output(success: bool, bytes: &[u8], key: &str) -> Result<Value> {
    ensure!(
        success && bytes.len() <= 1 << 20,
        "185 native property unreadable: {key}"
    );
    Ok(serde_json::from_slice(bytes)?)
}

fn empty_command_array(v: &Value) -> Result<()> {
    ensure!(
        v["type"] == "a(sasbttttuii)" && v["data"].as_array().is_some_and(|a| a.is_empty()),
        "185 stop commands lack positive recognized empty-array evidence"
    );
    Ok(())
}
fn zero_pid(v: &Value) -> Result<()> {
    ensure!(
        v["type"] == "u" && v["data"].as_u64() == Some(0),
        "185 native service has live or unreadable PID"
    );
    Ok(())
}
fn no_job(v: &Value) -> Result<()> {
    ensure!(
        v["type"] == "(uo)" && v["data"] == json!([0, "/"]),
        "185 owner has queued/running or unreadable job"
    );
    Ok(())
}
fn manager(name: &str) -> Result<Value> {
    let before = manager_raw(name)?;
    if before["LoadState"] == "not-found" {
        let mut proof = serde_json::Map::new();
        for (key, expected) in [
            ("Id", name),
            ("LoadState", "not-found"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
        ] {
            let v = property(name, "org.freedesktop.systemd1.Unit", key)?;
            ensure!(
                v["type"] == "s" && v["data"] == expected,
                "185 collected Unit property differs: {key}"
            );
            proof.insert(key.to_owned(), v);
        }
        let job = property(name, "org.freedesktop.systemd1.Unit", "Job")?;
        no_job(&job)?;
        let after = manager_raw(name)?;
        ensure!(
            before == after,
            "185 collected owner changed across native absence proof"
        );
        let mut normalized = after;
        normalized["Job"] = json!([0, "/"]);
        normalized["native_collected_proof"] =
            json!({"unit_properties":proof,"job":job,"raw_before":before});
        return Ok(normalized);
    }
    let id = property(name, "org.freedesktop.systemd1.Unit", "Id")?;
    ensure!(
        id["type"] == "s" && id["data"] == name,
        "185 native object identity differs"
    );
    let stop = property(name, "org.freedesktop.systemd1.Service", "ExecStop")?;
    empty_command_array(&stop)?;
    let post = property(name, "org.freedesktop.systemd1.Service", "ExecStopPost")?;
    empty_command_array(&post)?;
    let control = property(name, "org.freedesktop.systemd1.Service", "ControlPID")?;
    zero_pid(&control)?;
    let main = property(name, "org.freedesktop.systemd1.Service", "MainPID")?;
    zero_pid(&main)?;
    let job = property(name, "org.freedesktop.systemd1.Unit", "Job")?;
    no_job(&job)?;
    let after = manager_raw(name)?;
    ensure!(
        before == after,
        "185 native owner changed across structured property proof"
    );
    let mut normalized = after;
    // Normalize only fields with an independent recognized typed zero/empty proof.
    normalized["ExecStop"] = json!("");
    normalized["ExecStopPost"] = json!("");
    normalized["ControlPID"] = json!("0");
    normalized["MainPID"] = json!("0");
    normalized["Job"] = json!([0, "/"]);
    normalized["native_property_proof"] = json!({"identity":id,"exec_stop":stop,"exec_stop_post":post,
        "control_pid":control,"main_pid":main,"job":job,"raw_before":before});
    Ok(normalized)
}
fn collected_shape(v: &Value, name: &str) -> Result<()> {
    ensure!(
        v["Id"] == name
            && v["LoadState"] == "not-found"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["Job"] == json!([0, "/"]),
        "185 native collected owner shape differs"
    );
    // This is a separate positive absence branch, never a normalization of missing Service fields.
    for key in ["MainPID", "ControlPID", "NRestarts"] {
        ensure!(
            v[key].is_null() || v[key] == "0",
            "185 collected owner retains live service metadata"
        );
    }
    ensure!(
        v["InvocationID"].is_null() || v["InvocationID"] == "",
        "185 collected owner retains an invocation"
    );
    Ok(())
}
fn quiet(v: &Value, name: &str) -> Result<()> {
    ensure!(
        v["Id"] == name
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["ControlPID"] == "0"
            && v["Job"] == json!([0, "/"])
            && [
                "Triggers",
                "TriggeredBy",
                "OnFailure",
                "OnSuccess",
                "ExecStop",
                "ExecStopPost"
            ]
            .iter()
            .all(|k| v[*k] == ""),
        "185 metadata owner is live, restarted or has stop/handoff actions"
    );
    Ok(())
}
fn job_shape(v: &Value, j: Job, collected: bool) -> Result<()> {
    if collected && v["LoadState"] == "not-found" {
        return collected_shape(v, j.unit);
    }
    quiet(v, j.unit)?;
    let expected_status = match j.status {
        0 => "0",
        1 => "1",
        _ => bail!("foreign 185 terminal status"),
    };
    ensure!(
        v["LoadState"] == "loaded"
            && v["InvocationID"] == j.iid
            && v["Type"] == "oneshot"
            && v["RemainAfterExit"] == "yes"
            && v["ExecMainStatus"] == expected_status
            && v["Result"]
                == if j.status == 0 {
                    "success"
                } else {
                    "exit-code"
                }
            && v["FragmentPath"] == config_path(j.unit).to_str().unwrap()
            && (j.status == 0 || v["ActiveState"] != "active")
            && matches!(
                (v["ActiveState"].as_str(), v["SubState"].as_str()),
                (Some("active"), Some("exited"))
                    | (Some("failed"), Some("failed"))
                    | (Some("inactive"), Some("dead"))
            ),
        "185 metadata identity or completed lifecycle differs"
    );
    Ok(())
}
fn empty_cgroup(v: &Value) -> Result<()> {
    let group = v["ControlGroup"].as_str().context("185 metadata cgroup")?;
    if group.is_empty() {
        return Ok(());
    }
    ensure!(
        group.starts_with("/system.slice/") && !group.contains(".."),
        "foreign 185 metadata cgroup"
    );
    let path = Path::new("/sys/fs/cgroup")
        .join(group.trim_start_matches('/'))
        .join("cgroup.procs");
    let bytes = read_stable_bounded(&path, 65536, "185 metadata cgroup")?;
    ensure!(
        std::str::from_utf8(&bytes)?.trim().is_empty(),
        "185 metadata still has live child processes"
    );
    Ok(())
}
fn old_gate() -> Result<Value> {
    terminal_unit(CONTROLLER)?;
    terminal_unit(PRODUCER)?;
    let v = manager(OLD_CONTROLLER)?;
    quiet(&v, OLD_CONTROLLER)?;
    ensure!(
        v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && matches!(v["LoadState"].as_str(), Some("loaded" | "masked")),
        "obsolete 185 controller is live or changed"
    );
    if v["LoadState"] == "loaded" {
        ensure!(
            v["FragmentPath"] == ORIGINAL && v["Type"] == "exec" && v["RemainAfterExit"] == "no",
            "obsolete 185 loaded definition changed"
        );
    }
    empty_cgroup(&v)?;
    Ok(v)
}
fn allowed_staged(v: &Value) -> Result<()> {
    ensure!(
        v["terminal_fragment_exclusions"] == json!([]),
        "185 staged exclusions forbidden"
    );
    for reference in v["references"]
        .as_array()
        .context("185 staged references")?
    {
        let name = reference.as_str().context("185 staged reference path")?;
        ensure!(
            name == ORIGINAL
                || JOBS
                    .iter()
                    .any(|j| config_path(j.unit).to_str() == Some(name)),
            "unreviewed 185 staged consumer: {name}"
        );
    }
    Ok(())
}
fn checked_common(m: &Mapping, p: &Inspect) -> Result<()> {
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "185 staged mapping differs"
    );
    scope(
        p,
        m,
        &evidence(&p.guard_intent, false)?,
        &evidence(&p.guard_completion, false)?,
        &bound(&p.qualification)?,
    )?;
    let _ = bound(&p.deployment)?;
    Ok(())
}
pub(super) fn diagnose(m: &Mapping, p: &Inspect, spec: &Bound) -> Result<()> {
    checked_common(m, p)?;
    terminal_unit(CONTROLLER)?;
    terminal_unit(PRODUCER)?;
    let source_before = retained_source()?;
    let source = source_before.1.clone();
    let process =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), Path::new(LANE))?;
    let staged =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(Path::new(LANE))?;
    let mut owners = serde_json::Map::new();
    let mut configs = serde_json::Map::new();
    for name in std::iter::once(OLD_CONTROLLER).chain(JOBS.iter().map(|j| j.unit)) {
        owners.insert(name.to_owned(), manager(name)?);
        let path = config_path(name);
        if fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
            configs.insert(
                name.to_owned(),
                serde_json::to_value(OriginalId::from(regular_identity(&path)?))?,
            );
        }
    }
    ensure!(
        retained_source()? == source_before,
        "185 source changed during reference diagnostic"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let value = json!({"schema":"jetstreamer-horizon-staged185-reference-diagnostic-v2","host":HOST,
        "epoch":185,"inspection_plan":spec,"recorded_unix_seconds":now,"source_identity":source,
        "process_scan":process,"staged":staged,"metadata_owners":owners,"original_config_identities":configs,
        "source_hash_started":false,"reference_exclusions":[],"reconciliation_authorized":false,
        "growth_claims_released":false,"replay_data_removed":false,"remote_mutations":false,"r2_mutations":false});
    let path = Path::new(STATE)
        .join("receipts")
        .join(format!("diagnose185-{}-{now}.json", spec.sha256));
    persist(&path, &value)?;
    println!("{}", path.display());
    Ok(())
}
fn immutable_blob(b: &Bound, max: u64) -> Result<Vec<u8>> {
    let md = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.starts_with(BACKUP)
            && b.path.canonicalize()? == b.path
            && md.uid() == 0
            && md.is_file()
            && md.nlink() == 1
            && md.mode() & 0o222 == 0
            && digest(&b.sha256),
        "unsafe 185 preserved evidence"
    );
    let bytes = read_stable_bounded(&b.path, max, "185 preserved evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "185 preserved evidence digest differs"
    );
    Ok(bytes)
}
fn preservation(p: &Reconcile, d: &Value) -> Result<Value> {
    ensure!(
        p.preservation.path == Path::new(BACKUP).join("preservation.json"),
        "foreign 185 preservation manifest"
    );
    let v = bound(&p.preservation)?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-holding185-staged-preservation-v2"
            && v["host"] == HOST
            && v["diagnostic"] == serde_json::to_value(&p.diagnostic)?
            && v["inspection_plan"] == serde_json::to_value(&p.inspection_plan)?
            && v["replay_data_removed"] == false
            && v["growth_claims_released"] == false,
        "185 preservation scope differs"
    );
    for j in JOBS {
        job_shape(&d["metadata_owners"][j.unit], j, false)?;
    }
    let rows = v["members"].as_array().context("185 preserved members")?;
    ensure!(
        rows.len() == 9,
        "185 preservation must cover all 9reviewed owners"
    );
    let mut seen = std::collections::BTreeSet::new();
    let mut bytes = 0u64;
    for row in rows {
        let name = row["unit"].as_str().context("185 preservation unit")?;
        let sha = if name == OLD_CONTROLLER {
            OLD_SHA
        } else {
            JOBS.iter()
                .find(|j| j.unit == name)
                .context("foreign 185 preservation unit")?
                .sha
        };
        ensure!(
            seen.insert(name.to_owned()) && row["original"] == config_path(name).to_str().unwrap(),
            "duplicate/foreign185 preservation"
        );
        ensure!(
            row["original_identity"] == d["original_config_identities"][name]
                && row["original_identity"].is_object(),
            "185 original configuration identity differs from diagnostic"
        );
        let config: Bound = serde_json::from_value(row["config"].clone())?;
        let journal: Bound = serde_json::from_value(row["journal"].clone())?;
        ensure!(
            config.path == Path::new(BACKUP).join(format!("{name}.config.txt"))
                && config.sha256 == sha
                && journal.path == Path::new(BACKUP).join(format!("{name}.journal.jsonl")),
            "185 backup selection differs"
        );
        bytes = bytes
            .checked_add(immutable_blob(&config, 1 << 20)?.len() as u64)
            .context("185 backup size overflow")?;
        bytes = bytes
            .checked_add(immutable_blob(&journal, 16 << 20)?.len() as u64)
            .context("185 journal size overflow")?;
    }
    ensure!(bytes <= 16 << 20, "185 preservation exceeds 16 MiB");
    let mut expected: Vec<_> = std::iter::once(ORIGINAL.to_owned())
        .chain(
            JOBS.iter()
                .map(|j| config_path(j.unit).display().to_string()),
        )
        .collect();
    expected.sort();
    ensure!(
        d["staged"]["references"] == json!(expected),
        "185 initial diagnostic has missing or extra consumers"
    );
    Ok(v)
}
fn run_manager(action: &str, name: &str) -> Result<()> {
    ensure!(
        JOBS.iter().any(|j| j.unit == name) && matches!(action, "stop" | "reset-failed"),
        "foreign 185 manager mutation"
    );
    let out = std::process::Command::new("/usr/bin/systemctl")
        .args(["--job-mode=fail", action, name])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() + out.stderr.len() <= 65536,
        "185 terminal metadata collection failed"
    );
    Ok(())
}
fn current_refs() -> Result<Value> {
    terminal_unit(CONTROLLER)?;
    terminal_unit(PRODUCER)?;
    no_references(Path::new(LANE))?;
    let staged =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(Path::new(LANE))?;
    allowed_staged(&staged)?;
    Ok(staged)
}
fn metadata_frontier(
    intent: Option<&Value>,
    complete: Option<&Value>,
    expected: &Value,
    done: &Value,
) -> Result<()> {
    if let Some(old) = intent {
        ensure!(old == expected, "185 metadata collection intent conflict");
    }
    if let Some(old) = complete {
        ensure!(
            intent.is_some() && old == done,
            "185 metadata completion missing intent or conflicting"
        );
    }
    Ok(())
}
fn completion_scope(v: &Value, p: &Reconcile, spec: &Bound, mask: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-terminal185-staged-reconciliation-v2"
            && v["host"] == HOST
            && v["preservation"] == serde_json::to_value(&p.preservation)?
            && v["inspection_plan"] == serde_json::to_value(&p.inspection_plan)?
            && v["diagnostic"] == serde_json::to_value(&p.diagnostic)?
            && v["spec"] == serde_json::to_value(spec)?
            && v["mask_intent"] == *mask
            && v["original_controller_masked"] == true
            && v["all8metadata_jobs_collected"] == true
            && v["staged_after"]["references"] == json!([])
            && v["staged_after"]["terminal_fragment_exclusions"] == json!([])
            && v["replay_data_removed"] == false
            && v["processes_signalled"] == false
            && v["growth_claims_released"] == false
            && v["replay_launch_authorized"] == false
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "185 reconciliation completion scope conflicts"
    );
    Ok(())
}
fn collect_job(j: Job, p: &Reconcile, preserved: &Value) -> Result<()> {
    let row = preserved["members"]
        .as_array()
        .context("185 preserved members")?
        .iter()
        .find(|r| r["unit"] == j.unit)
        .context("185 missing original config identity")?;
    let expected: OriginalId = serde_json::from_value(row["original_identity"].clone())?;
    let intent = Path::new(ROOT).join(format!("{}.intent.json", j.unit));
    let completed = Path::new(ROOT).join(format!("{}.completed.json", j.unit));
    let descriptor = json!({"schema":"jetstreamer-terminal185-metadata-collection-intent-v2","unit":j.unit,
        "invocation_id":j.iid,"config_sha256":j.sha,"preservation":p.preservation,
        "process_signals_authorized":false,"replay_data_removed":false,"growth_claims_released":false});
    let done = json!({"schema":"jetstreamer-terminal185-metadata-collected-v2","intent":descriptor,
        "fragment_absent":true,"manager_collected":true,"replay_data_removed":false,"processes_signalled":false});
    let old = state_record(&intent, 0)?;
    let prior_done = state_record(&completed, 0)?;
    metadata_frontier(old.as_ref(), prior_done.as_ref(), &descriptor, &done)?;
    let before = manager(j.unit)?;
    job_shape(&before, j, old.is_some())?;
    if before["LoadState"] != "not-found" {
        empty_cgroup(&before)?;
        ensure!(
            OriginalId::from(regular_identity(&config_path(j.unit))?) == expected,
            "185 metadata config inode changed"
        );
        checked_bytes(&config_path(j.unit), j.sha, 0)?;
        current_refs()?;
        if old.is_none() {
            persist(&intent, &descriptor)?;
        }
        let again = manager(j.unit)?;
        job_shape(&again, j, false)?;
        empty_cgroup(&again)?;
        checked_bytes(&config_path(j.unit), j.sha, 0)?;
        ensure!(
            OriginalId::from(regular_identity(&config_path(j.unit))?) == expected,
            "185 metadata config changed before collection"
        );
        run_manager("stop", j.unit)?;
        let after = manager(j.unit)?;
        if after["ActiveState"] == "failed" {
            job_shape(&after, j, false)?;
            empty_cgroup(&after)?;
            run_manager("reset-failed", j.unit)?;
        }
    }
    let after = manager(j.unit)?;
    job_shape(&after, j, true)?;
    ensure!(
        after["LoadState"] == "not-found" && absent(&config_path(j.unit))?,
        "185 metadata not yet collected; preserve intent and retry later"
    );
    if let Some(old) = state_record(&completed, 0)? {
        ensure!(old == done, "185 metadata completion conflict");
    } else {
        persist(&completed, &done)?;
    }
    Ok(())
}
// Read-only closure gate; no manager/config mutation and no replay-data read.
pub(super) fn fenced_for_growth() -> Result<Value> {
    let before = old_gate()?;
    ensure!(
        before["LoadState"] == "masked" && fs::read_link(ORIGINAL)? == Path::new("/dev/null"),
        "old 185 controller is launchable"
    );
    checked_bytes(Path::new(RETAINED), OLD_SHA, 0)?;
    let completion = state_record(&Path::new(ROOT).join("completion.json"), 0)?
        .context("185 reconciliation completion missing")?;
    ensure!(
        completion["schema"] == "jetstreamer-terminal185-staged-reconciliation-v2"
            && completion["all8metadata_jobs_collected"] == true
            && completion["original_controller_masked"] == true
            && completion["staged_after"]["references"] == json!([])
            && completion["growth_claims_released"] == false,
        "185 reconciliation not complete"
    );
    let mut jobs = serde_json::Map::new();
    for j in JOBS {
        let v = manager(j.unit)?;
        job_shape(&v, j, true)?;
        ensure!(
            v["LoadState"] == "not-found" && absent(&config_path(j.unit))?,
            "185 metadata owner reappeared"
        );
        let intent = state_record(&Path::new(ROOT).join(format!("{}.intent.json", j.unit)), 0)?
            .context("185 metadata intent missing")?;
        let done = state_record(
            &Path::new(ROOT).join(format!("{}.completed.json", j.unit)),
            0,
        )?
        .context("185 metadata completion missing")?;
        ensure!(
            intent["unit"] == j.unit
                && intent["invocation_id"] == j.iid
                && intent["config_sha256"] == j.sha
                && done["intent"] == intent
                && done["manager_collected"] == true
                && done["fragment_absent"] == true,
            "185 metadata collection lineage differs"
        );
        jobs.insert(j.unit.into(), v);
    }
    for name in [CONTROLLER, PRODUCER] {
        terminal_unit(name)?;
        no_job(&property(name, "org.freedesktop.systemd1.Unit", "Job")?)?;
    }
    let references = current_refs()?;
    ensure!(
        references["references"] == json!([]),
        "185 old namespace still has staged consumers"
    );
    ensure!(
        old_gate()? == before,
        "185 old mask owner changed across closure proof"
    );
    Ok(
        json!({"old_controller":before,"metadata_jobs":jobs,"references":references,
        "replay_data_removed":false,"native_manager_mutations":false}),
    )
}
pub(super) fn reconcile(m: &Mapping, p: &Reconcile, spec: &Bound) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding185-staged-reconcile-plan-v2",
        "foreign 185 reconciliation schema"
    );
    let common: Inspect = serde_json::from_value(bound(&p.inspection_plan)?)?;
    ensure!(
        serde_json::to_value(&p.mapping)? == serde_json::to_value(&common.mapping)?,
        "185 reconciliation mapping differs"
    );
    checked_common(m, &common)?;
    let transaction = Path::new(ROOT).join("intent.json");
    let transaction_descriptor = json!({"schema":"jetstreamer-terminal185-staged-reconciliation-intent-v2",
        "mapping":p.mapping,"inspection_plan":p.inspection_plan,"diagnostic":p.diagnostic,"preservation":p.preservation,"spec":spec,
        "replay_data_removed":false,"process_signals_authorized":false,"growth_claims_released":false});
    let prior_transaction = state_record(&transaction, 0)?;
    if let Some(old) = &prior_transaction {
        ensure!(
            *old == transaction_descriptor,
            "185 reconciliation transaction differs"
        );
    } else {
        let mut frontiers = vec![
            Path::new(ROOT).join("completion.json"),
            Path::new(ROOT).join("mask-intent.json"),
            Path::new(ROOT).join("mask-exchanged.json"),
            PathBuf::from(RETAINED),
            partial_copy(Path::new(RETAINED))?,
            temporary_mask(Path::new(ORIGINAL))?,
        ];
        for j in JOBS {
            frontiers.push(Path::new(ROOT).join(format!("{}.intent.json", j.unit)));
            frontiers.push(Path::new(ROOT).join(format!("{}.completed.json", j.unit)));
        }
        for path in frontiers {
            ensure!(absent(&path)?, "185 orphaned reconciliation frontier");
        }
    }
    let d = bound(&p.diagnostic)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        d["schema"] == "jetstreamer-horizon-staged185-reference-diagnostic-v2"
            && d["host"] == HOST
            && d["inspection_plan"] == serde_json::to_value(&p.inspection_plan)?
            && d["process_scan"]["references"] == json!([])
            && d["reference_exclusions"] == json!([])
            && d["source_hash_started"] == false
            && d["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|at| at <= now && (prior_transaction.is_some() || now - at <= 1800)),
        "185 diagnostic stale or foreign"
    );
    allowed_staged(&d["staged"])?;
    let preserved = preservation(p, &d)?;
    let completion_path = Path::new(ROOT).join("completion.json");
    let prior_completion = state_record(&completion_path, 0)?;
    if let Some(old) = &prior_completion {
        ensure!(
            prior_transaction.is_some(),
            "185 completion lacks transaction"
        );
        let mask = state_record(&Path::new(ROOT).join("mask-intent.json"), 0)?
            .context("185 completion lacks mask intent")?;
        completion_scope(old, p, spec, &mask)?;
    }
    // The exact source remains local throughout metadata-only reconciliation.
    let _ = retained_source()?;
    current_refs()?;
    old_gate()?;
    private(Path::new(ROOT))?;
    if prior_transaction.is_none() {
        persist(&transaction, &transaction_descriptor)?;
    }
    for j in JOBS {
        collect_job(j, p, &preserved)?;
    }
    let remaining = current_refs()?;
    ensure!(
        remaining["references"] == json!([ORIGINAL]) || remaining["references"] == json!([]),
        "185 consumers remain after collection"
    );
    if prior_completion.is_some() {
        ensure!(
            old_gate()?["LoadState"] == "masked"
                && fs::read_link(ORIGINAL)? == Path::new("/dev/null")
                && remaining["references"] == json!([]),
            "185 completed mask or reference state changed"
        );
        checked_bytes(Path::new(RETAINED), OLD_SHA, 0)?;
        println!("{}", completion_path.display());
        return Ok(());
    }
    let intent = Path::new(ROOT).join("mask-intent.json");
    let exchanged = Path::new(ROOT).join("mask-exchanged.json");
    let mut descriptor = json!({"schema":"jetstreamer-terminal185-obsolete-controller-mask-intent-v2",
        "controller":OLD_CONTROLLER,"original":ORIGINAL,"retained":RETAINED,"config_sha256":OLD_SHA,
        "preservation":p.preservation,"replay_data_removed":false,"growth_claims_released":false});
    let expected: OriginalId = if let Some(old) = state_record(&intent, 0)? {
        let id = serde_json::from_value(old["original_identity"].clone())?;
        descriptor["original_identity"] = serde_json::to_value(id)?;
        ensure!(old == descriptor, "185 obsolete mask intent conflict");
        id
    } else {
        let id = OriginalId::from(regular_identity(Path::new(ORIGINAL))?);
        let old_row = preserved["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["unit"] == OLD_CONTROLLER)
            .context("185 preserved old controller")?;
        ensure!(
            serde_json::to_value(id)? == old_row["original_identity"],
            "obsolete 185 original identity changed since diagnostic"
        );
        checked_bytes(Path::new(ORIGINAL), OLD_SHA, 0)?;
        for path in [
            PathBuf::from(RETAINED),
            partial_copy(Path::new(RETAINED))?,
            temporary_mask(Path::new(ORIGINAL))?,
            exchanged.clone(),
        ] {
            ensure!(
                absent(&path)?,
                "185 obsolete first mask has occupied frontier"
            );
        }
        descriptor["original_identity"] = serde_json::to_value(id)?;
        persist(&intent, &descriptor)?;
        id
    };
    retain_and_mask(
        Path::new(ORIGINAL),
        Path::new(RETAINED),
        OLD_SHA,
        0,
        expected,
        &exchanged,
        || {
            old_gate()?;
            no_references(Path::new(LANE))?;
            Ok(())
        },
    )?;
    let out = std::process::Command::new("/usr/bin/systemctl")
        .arg("daemon-reload")
        .output()?;
    ensure!(
        out.status.success(),
        "185 obsolete mask durable but reload failed"
    );
    ensure!(
        old_gate()?["LoadState"] == "masked",
        "185 obsolete controller not masked"
    );
    let after = current_refs()?;
    ensure!(
        after["references"] == json!([]),
        "185 staged consumers remain after reconciliation"
    );
    let _ = retained_source()?;
    let completion = json!({"schema":"jetstreamer-terminal185-staged-reconciliation-v2","host":HOST,
        "preservation":p.preservation,"inspection_plan":p.inspection_plan,"diagnostic":p.diagnostic,
        "spec":spec,"mask_intent":descriptor,"staged_after":after,"original_controller_masked":true,
        "all8metadata_jobs_collected":true,"replay_data_removed":false,"processes_signalled":false,
        "growth_claims_released":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let path = Path::new(ROOT).join("completion.json");
    if let Some(old) = state_record(&path, 0)? {
        ensure!(old == completion, "185 reconciliation completion differs");
    } else {
        persist(&path, &completion)?;
    }
    println!("{}", path.display());
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginalId {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}
impl From<FileIdentity> for OriginalId {
    fn from(id: FileIdentity) -> Self {
        Self {
            device: id.device,
            inode: id.inode,
            length: id.length,
            modified_seconds: id.modified_seconds,
            modified_nanoseconds: id.modified_nanoseconds,
        }
    }
}

fn checked_bytes(path: &Path, sha: &str, uid: u32) -> Result<Vec<u8>> {
    let before = regular_identity(path)?;
    let md = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && md.uid() == uid
            && md.nlink() == 1
            && md.mode() & 0o022 == 0
            && before.length <= 1 << 20,
        "unsafe 185 obsolete controller configuration"
    );
    let bytes = read_stable_bounded(path, 1 << 20, "185 obsolete controller bytes")?;
    ensure!(
        regular_identity(path)? == before && hex_lower(&Sha256::digest(&bytes)) == sha,
        "185 obsolete controller configuration differs"
    );
    Ok(bytes)
}

fn state_record(path: &Path, uid: u32) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(md) => {
            ensure!(
                md.uid() == uid
                    && md.mode() & 0o222 == 0
                    && md.nlink() == 1
                    && md.is_file()
                    && path.canonicalize()? == path,
                "unsafe 185 obsolete control state"
            );
            Ok(Some(serde_json::from_slice(&read_stable_bounded(
                path,
                1 << 20,
                "185 obsolete control state",
            )?)?))
        }
    }
}
fn temporary_mask(original: &Path) -> Result<PathBuf> {
    let name = original
        .file_name()
        .and_then(|n| n.to_str())
        .context("185 obsolete controller filename")?;
    Ok(original.with_file_name(format!(".{name}.holding-mask.pending")))
}
fn partial_copy(retained: &Path) -> Result<PathBuf> {
    let name = retained
        .file_name()
        .and_then(|n| n.to_str())
        .context("185 obsolete retained filename")?;
    Ok(retained.with_file_name(format!(".{name}.copy.partial")))
}
fn absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
        Ok(_) => Ok(false),
    }
}

fn retained_copy(
    original: &Path,
    retained: &Path,
    sha: &str,
    uid: u32,
    expected: OriginalId,
) -> Result<()> {
    private(retained.parent().context("185 obsolete copy parent")?)?;
    let partial = partial_copy(retained)?;
    if !absent(retained)? {
        ensure!(
            absent(&partial)?,
            "185 obsolete copy has conflicting final and partial files"
        );
        checked_bytes(retained, sha, uid)?;
        ensure!(
            fs::symlink_metadata(retained)?.mode() & 0o222 == 0,
            "185 obsolete retained copy is mutable"
        );
        return Ok(());
    }
    ensure!(
        OriginalId::from(regular_identity(original)?) == expected,
        "185 obsolete original identity changed before copy"
    );
    let bytes = checked_bytes(original, sha, uid)?;
    ensure!(
        OriginalId::from(regular_identity(original)?) == expected,
        "185 obsolete original changed during copy read"
    );
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&partial)
    {
        Ok(file) => Some(file),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let md = fs::symlink_metadata(&partial)?;
            ensure!(
                md.is_file()
                    && md.nlink() == 1
                    && md.uid() == uid
                    && md.len() <= expected.length
                    && partial.canonicalize()? == partial,
                "unsafe 185 obsolete partial config copy"
            );
            if md.mode() & 0o777 == 0o400 {
                checked_bytes(&partial, sha, uid)?;
                None
            } else {
                ensure!(
                    md.mode() & 0o777 == 0o600,
                    "185 obsolete partial config copy mode differs"
                );
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&partial)?;
                ensure!(
                    identity(&file.metadata()?) == regular_identity(&partial)?,
                    "185 obsolete partial config copy changed"
                );
                Some(file)
            }
        }
        Err(e) => return Err(e.into()),
    };
    if let Some(file) = file.as_mut() {
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
    }
    checked_bytes(&partial, sha, uid)?;
    rename_noreplace(&partial, retained)?; // Same ROOT parent, never /etc→/var.
    checked_bytes(retained, sha, uid)?;
    Ok(())
}

fn exchange(original: &Path, temporary: &Path) -> Result<()> {
    let a = std::ffi::CString::new(original.as_os_str().as_encoded_bytes())?;
    let b = std::ffi::CString::new(temporary.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        } == 0,
        "185 obsolete atomic mask exchange failed: {}",
        std::io::Error::last_os_error()
    );
    File::open(original.parent().context("185 obsolete exchange parent")?)?.sync_all()?;
    Ok(())
}

// Production paths are compile-bound above. Fixtures cover copy/exchange/unlink
// interruptions with two independent parents and no host configuration access.
fn retain_and_mask(
    original: &Path,
    retained: &Path,
    sha: &str,
    uid: u32,
    expected: OriginalId,
    exchanged: &Path,
    mut owner_gate: impl FnMut() -> Result<()>,
) -> Result<()> {
    let temporary = temporary_mask(original)?;
    match fs::symlink_metadata(original) {
        Ok(md) if md.is_file() => {
            ensure!(
                OriginalId::from(regular_identity(original)?) == expected,
                "185 obsolete original inode changed"
            );
            retained_copy(original, retained, sha, uid, expected)?;
            if absent(&temporary)? {
                std::os::unix::fs::symlink("/dev/null", &temporary)?;
            }
            ensure!(
                fs::symlink_metadata(&temporary)?.file_type().is_symlink()
                    && fs::read_link(&temporary)? == Path::new("/dev/null"),
                "185 obsolete pending mask is occupied"
            );
            File::open(original.parent().context("185 obsolete mask parent")?)?.sync_all()?;
            owner_gate()?;
            ensure!(
                OriginalId::from(regular_identity(original)?) == expected,
                "185 obsolete original changed before exchange"
            );
            checked_bytes(original, sha, uid)?;
            exchange(original, &temporary)?;
        }
        Ok(md) if md.file_type().is_symlink() => {
            ensure!(
                fs::read_link(original)? == Path::new("/dev/null"),
                "foreign 185 obsolete controller alias"
            );
            checked_bytes(retained, sha, uid)?;
            ensure!(
                absent(&partial_copy(retained)?)?,
                "185 obsolete retained copy has a conflicting partial"
            );
        }
        Err(e) => {
            return Err(e).context(
                "185 obsolete original path absent or unreadable outside atomic exchange",
            );
        }
        _ => bail!("unsupported 185 obsolete controller path"),
    }
    ensure!(
        fs::read_link(original)? == Path::new("/dev/null"),
        "185 obsolete original is not masked"
    );
    checked_bytes(retained, sha, uid)?;
    ensure!(
        fs::symlink_metadata(retained)?.mode() & 0o222 == 0,
        "185 obsolete retained copy is mutable"
    );
    let descriptor = json!({"schema":"jetstreamer-terminal185 obsolete-controller-mask-exchanged-v2",
        "original":original,"retained":retained,"temporary":temporary,"config_sha256":sha,
        "original_identity":expected,"original_bytes_retained":true,"copy_fsynced":true});
    if !absent(&temporary)? {
        ensure!(
            OriginalId::from(regular_identity(&temporary)?) == expected,
            "185 obsolete exchanged original identity differs"
        );
        checked_bytes(&temporary, sha, uid)?;
        if let Some(old) = state_record(exchanged, uid)? {
            ensure!(
                old == descriptor,
                "185 obsolete exchanged frontier conflicts"
            );
        } else {
            persist(exchanged, &descriptor)?;
        }
        owner_gate()?;
        ensure!(
            fs::read_link(original)? == Path::new("/dev/null")
                && OriginalId::from(regular_identity(&temporary)?) == expected,
            "185 obsolete exchanged state changed before cleanup"
        );
        checked_bytes(retained, sha, uid)?;
        checked_bytes(&temporary, sha, uid)?;
        fs::remove_file(&temporary)?;
        File::open(original.parent().unwrap())?.sync_all()?;
    } else {
        ensure!(
            state_record(exchanged, uid)?.as_ref() == Some(&descriptor),
            "185 obsolete mask has unexplained absence of original temporary configuration"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_conflicting_or_missing_frontiers_fail_before_owner_mutation() {
        let intent = json!({"unit":JOBS[0].unit,"invocation_id":JOBS[0].iid});
        let done = json!({"intent":intent,"manager_collected":true});
        metadata_frontier(None, None, &intent, &done).unwrap();
        metadata_frontier(Some(&intent), None, &intent, &done).unwrap();
        metadata_frontier(Some(&intent), Some(&done), &intent, &done).unwrap();
        assert!(metadata_frontier(None, Some(&done), &intent, &done).is_err());
        assert!(metadata_frontier(Some(&json!({"unit":"other"})), None, &intent, &done).is_err());
        assert!(
            metadata_frontier(
                Some(&intent),
                Some(&json!({"intent":"other"})),
                &intent,
                &done
            )
            .is_err()
        );
    }
    #[test]
    fn command_arrays_require_typed_positive_empty_evidence() {
        empty_command_array(&json!({"type":"a(sasbttttuii)","data":[]})).unwrap();
        let bytes = br#"{"type":"a(sasbttttuii)","data":[]}"#;
        assert!(decode_property_output(false, bytes, "ExecStop").is_err());
        empty_command_array(&decode_property_output(true, bytes, "ExecStop").unwrap()).unwrap();
        assert!(decode_property_output(true, b"unreadable", "ExecStop").is_err());
        for v in [
            json!({}),
            json!({"type":"a(sasbttttuii)"}),
            json!({"type":"a(sasbttttuii)","data":null}),
            json!({"type":"as","data":[]}),
            json!({"type":"a(sasbttttuii)","data":[["/bin/action"]]}),
        ] {
            assert!(empty_command_array(&v).is_err());
        }
        assert!(zero_pid(&json!({})).is_err());
        assert!(zero_pid(&json!({"type":"u","data":1})).is_err());
        zero_pid(&json!({"type":"u","data":0})).unwrap();
        no_job(&json!({"type":"(uo)","data":[0,"/"]})).unwrap();
        assert!(no_job(&json!({})).is_err());
        assert!(no_job(&json!({"type":"(uo)","data":[9,"/job/9"]})).is_err());
    }
    #[test]
    fn collected_absence_does_not_require_or_invent_service_fields() {
        let j = JOBS[0];
        let v = json!({"Id":j.unit,"LoadState":"not-found","ActiveState":"inactive","SubState":"dead","Job":[0,"/"]});
        assert!(job_shape(&v, j, false).is_err());
        job_shape(&v, j, true).unwrap();
        let mut live = v.clone();
        live["MainPID"] = json!("12");
        assert!(job_shape(&live, j, true).is_err());
        let mut unknown = v;
        unknown["LoadState"] = json!("error");
        assert!(job_shape(&unknown, j, true).is_err());
    }
    #[test]
    fn only_original_terminal_metadata_without_stop_actions_can_collect() {
        let j = JOBS[0];
        let v = json!({"Id":j.unit,"MainPID":"0","NRestarts":"0","Restart":"no",
            "Triggers":"","TriggeredBy":"","OnFailure":"","OnSuccess":"","ExecStop":"","ExecStopPost":"","ControlPID":"0","Job":[0,"/"],
            "LoadState":"loaded","InvocationID":j.iid,"Type":"oneshot","RemainAfterExit":"yes",
            "ExecMainStatus":j.status.to_string(),"Result":"exit-code","FragmentPath":config_path(j.unit),
            "ActiveState":"failed","SubState":"failed"});
        job_shape(&v, j, false).unwrap();
        for (k, x) in [
            ("MainPID", "12"),
            ("ControlPID", "12"),
            ("InvocationID", "replacement"),
            ("NRestarts", "1"),
            ("ExecStop", "/bin/action"),
            ("ExecStopPost", "/bin/action"),
            ("TriggeredBy", "timer.timer"),
            ("Restart", "on-failure"),
            ("Result", "oom-kill"),
            ("SubState", "running"),
        ] {
            let mut bad = v.clone();
            bad[k] = json!(x);
            assert!(job_shape(&bad, j, false).is_err(), "{k}");
        }
        let mut gone = v;
        gone["LoadState"] = json!("not-found");
        gone["ActiveState"] = json!("inactive");
        gone["SubState"] = json!("dead");
        gone["InvocationID"] = json!("");
        assert!(job_shape(&gone, j, false).is_err());
        job_shape(&gone, j, true).unwrap();
    }
    #[test]
    fn staged_scope_never_excludes_or_accepts_an_extra_owner() {
        let v = json!({"references":[ORIGINAL,config_path(JOBS[0].unit)],"terminal_fragment_exclusions":[]});
        allowed_staged(&v).unwrap();
        let mut extra = v.clone();
        extra["references"] = json!(["/etc/systemd/system/new-owner.service"]);
        assert!(allowed_staged(&extra).is_err());
        let mut excluded = v;
        excluded["terminal_fragment_exclusions"] = json!([ORIGINAL]);
        assert!(allowed_staged(&excluded).is_err());
    }
    #[test]
    fn reconcile_plan_cannot_select_replay_data_or_arbitrary_units() {
        let b = json!({"path":"/sealed/x.json","sha256":"a".repeat(64)});
        let p = json!({"schema":"jetstreamer-horizon-holding185-staged-reconcile-plan-v2",
            "mapping":b,"inspection_plan":b,"diagnostic":b,"preservation":b});
        assert!(serde_json::from_value::<Reconcile>(p.clone()).is_ok());
        for key in ["unit", "source", "scratch", "exclusions", "retire_archive"] {
            let mut bad = p.clone();
            bad[key] = json!(true);
            assert!(serde_json::from_value::<Reconcile>(bad).is_err());
        }
    }
    #[allow(clippy::type_complexity)]
    fn fixture() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        PathBuf,
        String,
        OriginalId,
    ) {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let etc = d.path().join("etc");
        fs::create_dir(&etc).unwrap();
        let var = d.path().join("var");
        fs::create_dir(&var).unwrap();
        fs::set_permissions(&var, fs::Permissions::from_mode(0o700)).unwrap();
        let source = etc.join("old.service");
        let retained = var.join("retained.txt");
        let exchanged = var.join("exchanged.json");
        let bytes = b"[Service]\nExecStart=/fixture/never-launched\n";
        fs::write(&source, bytes).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let id = OriginalId::from(regular_identity(&source).unwrap());
        (
            d,
            source,
            retained,
            exchanged,
            hex_lower(&Sha256::digest(bytes)),
            id,
        )
    }
    #[test]
    fn independent_parents_copy_before_atomic_mask_and_retry_preserves_bytes() {
        let (_d, s, r, x, sha, id) = fixture();
        let uid = unsafe { libc::geteuid() };
        let bytes = fs::read(&s).unwrap();
        retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).unwrap();
        assert_eq!(fs::read_link(&s).unwrap(), Path::new("/dev/null"));
        assert_eq!(fs::read(&r).unwrap(), bytes);
        assert_ne!(
            OriginalId::from(regular_identity(&r).unwrap()).inode,
            id.inode
        );
        let marker = fs::read(&x).unwrap();
        retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).unwrap();
        assert_eq!(fs::read(&x).unwrap(), marker);
        assert!(absent(&temporary_mask(&s).unwrap()).unwrap());
    }
    #[test]
    fn partial_copy_and_exchange_frontiers_resume_without_losing_configuration() {
        for frontier in 0..=3 {
            let (_d, s, r, x, sha, id) = fixture();
            let uid = unsafe { libc::geteuid() };
            let bytes = fs::read(&s).unwrap();
            if frontier == 0 {
                let p = partial_copy(&r).unwrap();
                fs::write(&p, &bytes[..5]).unwrap();
                fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
            } else {
                retained_copy(&s, &r, &sha, uid, id).unwrap();
                let temp = temporary_mask(&s).unwrap();
                std::os::unix::fs::symlink("/dev/null", &temp).unwrap();
                if frontier >= 2 {
                    exchange(&s, &temp).unwrap();
                }
                if frontier == 3 {
                    let mut calls = 0;
                    assert!(
                        retain_and_mask(&s, &r, &sha, uid, id, &x, || {
                            calls += 1;
                            bail!("fixture interruption before cleanup")
                        })
                        .is_err()
                    );
                    assert_eq!(calls, 1);
                    assert!(temp.exists());
                }
            }
            retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).unwrap();
            assert_eq!(fs::read(&r).unwrap(), bytes);
            assert_eq!(fs::read_link(&s).unwrap(), Path::new("/dev/null"));
        }
    }
    #[test]
    fn changed_conflicting_or_unexplained_masks_are_never_replaced() {
        let (_d, s, r, x, sha, id) = fixture();
        let uid = unsafe { libc::geteuid() };
        fs::write(&r, b"conflict").unwrap();
        assert!(retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).is_err());
        assert_eq!(fs::read(&r).unwrap(), b"conflict");
        fs::remove_file(&r).unwrap();
        assert!(retain_and_mask(&s, &r, &"a".repeat(64), uid, id, &x, || Ok(())).is_err());
        assert_eq!(
            fs::read(&s).unwrap(),
            b"[Service]\nExecStart=/fixture/never-launched\n"
        );
        retained_copy(&s, &r, &sha, uid, id).unwrap();
        fs::remove_file(&s).unwrap();
        std::os::unix::fs::symlink("/dev/null", &s).unwrap();
        assert!(retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).is_err());
        assert!(r.exists());
    }

    #[test]
    fn completed_partial_copy_recovers_and_conflicting_partial_is_preserved() {
        let (_d, s, r, x, sha, id) = fixture();
        let uid = unsafe { libc::geteuid() };
        let partial = partial_copy(&r).unwrap();
        fs::write(&partial, fs::read(&s).unwrap()).unwrap();
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o400)).unwrap();
        retained_copy(&s, &r, &sha, uid, id).unwrap();
        assert!(absent(&partial).unwrap());
        fs::write(&partial, b"foreign partial").unwrap();
        assert!(retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).is_err());
        assert_eq!(fs::read(&partial).unwrap(), b"foreign partial");
        assert_eq!(OriginalId::from(regular_identity(&s).unwrap()), id);
    }

    #[test]
    fn failed_owner_gate_leaves_original_unmasked_and_retryable() {
        let (_d, s, r, x, sha, id) = fixture();
        let uid = unsafe { libc::geteuid() };
        assert!(
            retain_and_mask(&s, &r, &sha, uid, id, &x, || {
                bail!("fixture changed owner before exchange")
            })
            .is_err()
        );
        assert_eq!(OriginalId::from(regular_identity(&s).unwrap()), id);
        assert_eq!(fs::read(&s).unwrap(), fs::read(&r).unwrap());
        assert!(absent(&x).unwrap());
        retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).unwrap();
        assert_eq!(fs::read_link(&s).unwrap(), Path::new("/dev/null"));
    }
}
