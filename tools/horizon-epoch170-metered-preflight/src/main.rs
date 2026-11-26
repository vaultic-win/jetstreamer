//! Compose and validate the evidence for a metered full-root epoch 170 route.
//! The operator commands are read-only. The held service command can exec the
//! exact producer only after the invocation-bound native guard release.
mod admission;
mod held;

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const RT: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const LANE: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1";
const RUN_PARENT: &str =
    "replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1";
const OLD_RUN: &str = "cold-retry13-20261122";
const NEW_RUN: &str = "full-metered-20261124-v1";
const OLD_UNIT: &str = "horizon-qualify-170-replacement-local3retry13-20261122.service";
const UNIT: &str = "horizon-qualify-170-full-metered-20261124-v1.service";
const TIMER: &str = "horizon-guard-170-full-metered-20261124-v1.timer";
const GUARD_UNIT: &str = "horizon-guard-170-full-metered-20261124-v1.service";
const OBSERVER_UNIT: &str = "horizon-archive-status-cadence-after172-20261120-v1.service";
const BASE: &str = "epoch170-full-metered-rebook-20261124-v1";
const GUARD: &str = "epoch170-full-metered-guard-20261124-v1";
const RETRY: &str = "epoch170-retry13-rebook-20261122-v1";
const TERMINAL: &str = "failed-replay-20261124T123309Z/TERMINAL.json";
const TERMINAL_SHA: &str = "16664fda43d296d115858ff67a173d6d0cccb5f2ac90d446aa797da34a2f6c9d";
const PREPARED_SHA: &str = "e1759214d8f4865bd42d7992786d5b41e7ecebd25424ecc68d239c5d003a5ab3";
const DRAIN_SHA: &str = "e570c630afe4add0209a6af6ebd9da6cc0195bc0a5b4034dcf2716baf130bae7";
const DIAG_SHA: &str = "590ea4772161ce9ee96c7c93d06b69d8ae589ce25ffa4979b121f907924ee6bc";
const OFFLINE_SHA: &str = "aa61da0ccf7287bb9782843e159679cda51a10db138d6100e8c2625a6a1caf6d";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER_SHA: &str = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541";
const OLD_WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const WORKER: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch172-full-replay-20261120-v1/inputs-v1/jetstreamer-historical-worker-v1-5-6";
const WORKER_TARGET: &str =
    "/run/horizon-epoch170-full-metered/jetstreamer-historical-worker-v1-5-6";
const PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-independent170-singleton-package-20261109-v1";
const MANIFEST_SHA: &str = "61f9138b49c6db69b6e683214d51c82f042b4afc693ccf71a29972b093f820d8";
const BOOT_SHA: &str = "1fff1c4d4c76f56f7b5ba6ba17f379d7811cddb3e314043829ceb864205cab0a";
const ROOT_HASH: &str = "29vpNnumVyQE5dpygpinJJWj7UHXe8zU2H3Z71ojXhke";
const FINGERPRINT: &str = "sha256:a18e763167b4cd47833f89627209ea7b5e08e55de16152df612e2c0d9be05890";
const CAP: u64 = 384 << 30;
const MIN_FLOOR: u64 = 8_297_502_499_408;

fn rt(rel: &str) -> PathBuf {
    Path::new(RT).join(rel)
}

fn run(attempt: &str) -> PathBuf {
    Path::new(LANE).join(RUN_PARENT).join(attempt)
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("missing {key}"))
}

fn number(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .with_context(|| format!("missing {key}"))
}

fn file(path: &Path, uid: u32) -> Result<File> {
    ensure!(
        path.is_absolute()
            && path
                .canonicalize()
                .with_context(|| format!("checking {}", path.display()))?
                == path,
        "indirect input {}",
        path.display()
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.uid() == uid && m.mode() & 0o022 == 0,
        "unsafe input {}",
        path.display()
    );
    Ok(file)
}

fn stamp(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn stable(path: &Path, file: &File, before: &fs::Metadata) -> Result<()> {
    ensure!(
        stamp(before) == stamp(&file.metadata()?)
            && stamp(before) == stamp(&fs::symlink_metadata(path)?),
        "input changed {}",
        path.display()
    );
    Ok(())
}

fn doc(path: &Path, expected: &str, uid: u32) -> Result<Value> {
    let mut file = file(path, uid)?;
    let before = file.metadata()?;
    ensure!(
        before.len() <= 64 << 20,
        "oversized receipt {}",
        path.display()
    );
    let mut bytes = Vec::new();
    (&mut file).take((64 << 20) + 1).read_to_end(&mut bytes)?;
    stable(path, &file, &before)?;
    ensure!(
        sha(&bytes) == expected,
        "receipt sha256 mismatch {}",
        path.display()
    );
    serde_json::from_slice(&bytes).with_context(|| format!("invalid receipt {}", path.display()))
}

fn reference(path: &Path, sha256: &str) -> Value {
    json!({"path": path, "sha256": sha256})
}

fn bound(reference: &Value, uid: u32) -> Result<Value> {
    doc(
        Path::new(string(reference, "path")?),
        string(reference, "sha256")?,
        uid,
    )
}

fn image(binding: &Value) -> Result<Value> {
    let path = Path::new(string(binding, "path")?);
    let mut file = file(path, 0)?;
    let before = file.metadata()?;
    ensure!(
        before.len() <= 128 << 20,
        "oversized binary {}",
        path.display()
    );
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)?;
    stable(path, &file, &before)?;
    ensure!(
        format!("{:x}", hash.finalize()) == string(binding, "sha256")?,
        "binary sha256 mismatch {}",
        path.display()
    );
    Ok(
        json!({"reference": binding, "device": before.dev(), "inode": before.ino(), "bytes": before.len()}),
    )
}

fn replace_once(argv: &mut [String], old: &str, new: &str) -> Result<()> {
    let mut matches = argv.iter_mut().filter(|argument| argument.as_str() == old);
    let argument = matches
        .next()
        .with_context(|| format!("missing original argument {old}"))?;
    ensure!(
        matches.next().is_none(),
        "ambiguous original argument {old}"
    );
    *argument = new.to_owned();
    Ok(())
}

fn producer_argv(mut argv: Vec<String>) -> Result<Vec<String>> {
    let old_run = run(OLD_RUN);
    let new_run = run(NEW_RUN);
    let old_run = old_run.to_str().context("old run path")?;
    let new_run = new_run.to_str().context("new run path")?;
    let old_worker = format!("{PACKAGE}/jetstreamer-historical-worker-v1-5-6");
    let worker_var = "--setenv=JETSTREAMER_HISTORICAL_WORKER_V1_5_6=";
    replace_once(
        &mut argv,
        &format!("--unit={OLD_UNIT}"),
        &format!("--unit={UNIT}"),
    )?;
    replace_once(
        &mut argv,
        &format!("{worker_var}{old_worker}"),
        &format!("{worker_var}{WORKER_TARGET}"),
    )?;
    replace_once(
        &mut argv,
        &format!("--property=ExecPaths={PACKAGE}/jetstreamer-node {old_worker} {LANE}"),
        &format!("--property=ExecPaths={PACKAGE}/jetstreamer-node {WORKER_TARGET} {LANE}"),
    )?;
    let binds = argv
        .iter_mut()
        .find(|a| a.starts_with("--property=BindReadOnlyPaths="))
        .context("missing source mounts")?;
    ensure!(
        !binds.contains(WORKER_TARGET) && binds.contains(old_run),
        "original source mounts differ"
    );
    binds.push_str(&format!(" {WORKER}:{WORKER_TARGET}"));
    argv.iter_mut()
        .filter(|a| a.contains(old_run))
        .for_each(|a| *a = a.replace(old_run, new_run));
    ensure!(
        argv.first().is_some_and(|a| a == "/usr/bin/systemd-run")
            && argv
                .iter()
                .filter(|a| a.starts_with("--property=BindReadOnlyPaths="))
                .count()
                == 1
            && argv
                .iter()
                .any(|a| a == &format!("--property=ReadWritePaths={new_run}"))
            && argv
                .iter()
                .any(|a| a == &format!("--cohort-manifest-fingerprint={FINGERPRINT}"))
            && argv.iter().any(|a| a == "--root-checkpoint-cohort"),
        "changed full-root producer arguments"
    );
    Ok(argv)
}

fn topology(fleet_path: &Path, fleet_sha: &str) -> Result<Value> {
    ensure!(
        fleet_path.file_name().and_then(|p| p.to_str())
            == Some("ROOT_COMPLETE_OPERATIONAL_FLEET.json")
            && fleet_path.parent().and_then(Path::parent) == Some(Path::new(RT)),
        "foreign fleet receipt"
    );
    let fleet = doc(fleet_path, fleet_sha, 0)?;
    ensure!(
        fleet["cold170_retry13_execution_failure"]["terminal"]["sha256"] == TERMINAL_SHA,
        "fleet has no exact drained retry13 terminal"
    );
    let observer = bound(&fleet["observer"], 0)?;
    let next = bound(&fleet["sole_next_observer"], 0)?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["recorded_at_utc"] == fleet["sampled_at_utc"]
            && next["previous_sample"] == fleet["observer"]["path"]
            && next["minimum_interval_seconds"] == 1800
            && next["observation_reason"] == "routine",
        "fleet does not bind the sole coordinated observation"
    );
    let mut replays = Vec::new();
    for row in fleet["actual_executing_replays"]
        .as_array()
        .context("missing current producer roster")?
    {
        let epoch = number(row, "epoch")?;
        ensure!(
            epoch != 170
                && row["unit"]["ActiveState"] == "active"
                && row["observer_config"]["expected_producer_invocation_id"]
                    == row["unit"]["InvocationID"],
            "existing competing epoch 170 claim or changed owner"
        );
        replays.push(json!({"epoch": epoch, "unit": row["unit"]["Id"], "invocation_id": row["unit"]["InvocationID"]}));
    }
    ensure!(
        fleet["canonical_producer_count"] == replays.len(),
        "incomplete production roster"
    );
    Ok(
        json!({"fleet":reference(fleet_path,fleet_sha),"observer":fleet["observer"],
        "timer":fleet["sole_next_timer"],"next_observer":fleet["sole_next_observer"],
        "next_output":next["output"],"replays":replays}),
    )
}

fn inputs(
    offline_path: &Path,
    proof_path: &Path,
    fleet_path: &Path,
    fleet_sha: &str,
) -> Result<Value> {
    let base = rt(RETRY);
    let prepared_path = base.join("PREPARED.json");
    let terminal_path = base.join(TERMINAL);
    let drain_path = terminal_path.with_file_name("ORPHAN_GUARD_DRAINED.json");
    let prepared = doc(&prepared_path, PREPARED_SHA, 0)?;
    let terminal = doc(&terminal_path, TERMINAL_SHA, 0)?;
    doc(&drain_path, DRAIN_SHA, 0)?;
    let offline = doc(offline_path, OFFLINE_SHA, 1001)?;
    let proof = doc(proof_path, DIAG_SHA, 1001)?;
    let expected_worker = reference(Path::new(WORKER), WORKER_SHA);
    let expected_node = reference(&Path::new(PACKAGE).join("jetstreamer-node"), NODE_SHA);
    let expected_manifest = reference(
        &Path::new(PACKAGE).join("preflight-170-v4.json"),
        MANIFEST_SHA,
    );
    ensure!(
        prepared["node_sha256"] == NODE_SHA
            && prepared["worker_sha256"] == OLD_WORKER_SHA
            && terminal["retained_run"] == true
            && terminal["archive_ready"] == false
            && string(&terminal, "failure")?.contains(
                "historical execution mismatch at slot 73711515 entry 157 transaction 191"
            ),
        "another retry13 terminal or source"
    );
    ensure!(
        offline["diagnostic_acceptance"] == reference(proof_path, DIAG_SHA)
            && proof["independent_internal_full_verification"] == true
            && proof["slots_verified"] == 6801
            && offline["corrected_worker"]["path"] == WORKER
            && offline["corrected_worker"]["sha256"] == WORKER_SHA
            && offline["corrected_worker"]["features"] == json!(["historical-per-byte-logging"])
            && offline["node"]["path"] == expected_node["path"]
            && offline["node"]["sha256"] == NODE_SHA
            && offline["manifest"]["path"] == expected_manifest["path"]
            && offline["manifest"]["sha256"] == MANIFEST_SHA
            && offline["manifest"]["fingerprint"] == FINGERPRINT
            && offline["bootstrap"]["source_path"] == prepared["baseline"]["snapshot"]["path"]
            && offline["bootstrap"]["sha256"] == BOOT_SHA
            && offline["bootstrap"]["slot"] == 73439777
            && offline["canonical_root"] == json!({"slot":73871796,"accounts_hash":ROOT_HASH}),
        "changed metered worker or full-root provenance"
    );
    let manifest = bound(&expected_manifest, 0)?;
    let cohort = &manifest["manifest"]["verification_cohorts"][0];
    ensure!(
        manifest["manifest_fingerprint"] == FINGERPRINT
            && cohort["first_epoch"] == 170
            && cohort["last_epoch"] == 170
            && cohort["publish_through_epoch"] == 170
            && cohort["root_checkpoints"][0]["slot"] == 73871796
            && cohort["root_checkpoints"][0]["accounts_hash"] == ROOT_HASH,
        "manifest does not prove the canonical singleton goal"
    );
    let node = image(&expected_node)?;
    let worker = image(&expected_worker)?;
    let argv = producer_argv(serde_json::from_value(
        prepared["profile"]["producer_argv"].clone(),
    )?)?;
    let target = run(NEW_RUN);
    let old = run(OLD_RUN);
    let mut indexes = prepared["profile"]["indexes"]
        .as_array()
        .context("missing compact indexes")?
        .clone();
    ensure!(indexes.len() == 3, "changed compact index population");
    for item in &mut indexes {
        let relative = Path::new(string(item, "target")?).strip_prefix(&old)?;
        ensure!(
            relative.starts_with("output/compact-indexes")
                && !relative
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir)),
            "invalid compact-index projection"
        );
        item["target"] = json!(target.join(relative));
    }
    let guard = rt(GUARD);
    let runtime = rt(BASE);
    Ok(json!({
        "schema":"horizon-epoch170-full-metered-source-preflight-v1","epoch":170,
        "source":{"node":node,"worker":worker,"worker_target":WORKER_TARGET,"manifest":expected_manifest,
            "offline":reference(offline_path,OFFLINE_SHA),"diagnostic":reference(proof_path,DIAG_SHA),
            "bootstrap":offline["bootstrap"],"bootstrap_identity":prepared["baseline"]["snapshot"],
            "canonical_root":offline["canonical_root"],"indexes":indexes},
        "previous":{"prepared":reference(&prepared_path,PREPARED_SHA),"terminal":reference(&terminal_path,TERMINAL_SHA),"guard_drain":reference(&drain_path,DRAIN_SHA),"worker_sha256":OLD_WORKER_SHA},
        "actor":{"unit":UNIT,"run":target,"producer_argv_after_protection":argv,"requires_held_before_useful_work":true},
        "guard":{"timer":TIMER,"service":GUARD_UNIT,"producer_unit":UNIT,"worker_root":LANE,
            "candidate_root_receipt":runtime.join("SUCCESSOR_ROOT.json"),"qualification":guard.join("GUARD_QUALIFIED.json"),
            "image":guard.join("tools/guard"),"contract":guard.join("contract/contract.json"),
            "receipt_directory":runtime.join("guard-receipts"),"filesystem":"/home/sol","cap_bytes":CAP,"minimum_free_bytes":MIN_FLOOR,"maximum_worker_vmas":3500000},
        "observer":{"incumbent_unit":OBSERVER_UNIT,"candidate_range":"170","producer_unit":UNIT,"guard_timer":TIMER,
            "worker_source":WORKER,"worker_sha256":WORKER_SHA,"worker_device":worker["device"],"worker_inode":worker["inode"],
            "append_log":target.join("producer.log"),"active_fleet":topology(fleet_path,fleet_sha)?},
        "resource_credit_bytes":0,"replay_launch_authorized":false,"archive_publication_authorized":false
    }))
}

fn properties(unit: &str) -> Result<Value> {
    let child = Command::new("/usr/bin/timeout")
        .args([
            "15",
            "/usr/bin/systemctl",
            "show",
            unit,
            "-p",
            "Id,InvocationID,MainPID,ActiveState,SubState,LoadState,NRestarts,Triggers",
        ])
        .output()?;
    ensure!(child.status.success(), "manager query failed for {unit}");
    let text = std::str::from_utf8(&child.stdout)?;
    let pairs = text.lines().filter_map(|line| line.split_once('='));
    let object = pairs
        .map(|(key, val)| (key.to_owned(), json!(val)))
        .collect();
    Ok(Value::Object(object))
}

fn observer_incumbent(enrolled: &Value) -> Result<()> {
    let before = properties(OBSERVER_UNIT)?;
    let incumbent = &enrolled["incumbent"];
    ensure!(
        before["ActiveState"] == "active"
            && before["SubState"] == "running"
            && before["NRestarts"] == "0"
            && incumbent["unit"] == OBSERVER_UNIT
            && before["InvocationID"] == incumbent["invocation_id"],
        "wrong incumbent cadence owner"
    );
    let pid = number(incumbent, "pid")?;
    ensure!(
        pid > 1 && string(&before, "MainPID")?.parse::<u64>()? == pid,
        "cadence writer PID changed"
    );
    let proc = Path::new("/proc").join(pid.to_string());
    let stat = fs::read_to_string(proc.join("stat"))?;
    let start_ticks: u64 = stat
        .rsplit_once(')')
        .context("bad cadence stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing cadence starttime")?
        .parse()?;
    ensure!(
        start_ticks == number(incumbent, "start_ticks")?,
        "cadence writer starttime changed"
    );
    let program = string(&incumbent["program"], "path")?;
    ensure!(
        program.starts_with(&format!("{RT}/survivor172-cadence-20261122-v1/"))
            && program.ends_with("/status_cycle.py"),
        "unknown cadence writer route"
    );
    image(&incumbent["program"])?;
    let argv = fs::read(proc.join("cmdline"))?;
    ensure!(
        argv == format!("/usr/bin/python3\0-IB\0{program}\0").into_bytes(),
        "cadence writer argv changed"
    );
    let lock = &incumbent["lock"];
    let path = Path::new(string(lock, "path")?);
    ensure!(
        path == rt("stable-cadence-controller-20261120-v1/consumer.lock"),
        "different cadence lock"
    );
    let file = file(path, 0)?;
    let m = file.metadata()?;
    let fd = number(lock, "fd")?.to_string();
    let open = fs::metadata(proc.join("fd").join(&fd))?;
    ensure!(
        m.dev() == open.dev()
            && m.ino() == open.ino()
            && m.dev() == number(lock, "device")?
            && m.ino() == number(lock, "inode")?
            && fs::read_to_string(proc.join("fdinfo").join(fd))?.contains("FLOCK  ADVISORY  WRITE"),
        "cadence writer lost its exclusive lock"
    );
    ensure!(
        properties(OBSERVER_UNIT)? == before,
        "cadence writer changed during check"
    );
    Ok(())
}

fn cadence_registration(active: &Value) -> Result<Value> {
    let active_path = Path::new(string(active, "path")?);
    let cadence_root = rt("survivor172-cadence-20261122-v1");
    ensure!(
        active_path.parent() == Some(cadence_root.as_path()),
        "foreign active cadence registration"
    );
    let registered = bound(active, 0)?;
    ensure!(
        registered["producer_mutations"] == false,
        "unexpected producer changes in incumbent cadence registration"
    );
    let ready = bound(&registered["ready"], 0)?;
    let package = bound(&ready["package"], 0)?;
    if active_path == rt(admission::V13_REGISTRATION) {
        admission::check_v13_cadence(&registered, &ready, &package)?;
    }
    let mut incumbent = registered["new"].clone();
    let program = PathBuf::from(string(&incumbent, "program")?);
    ensure!(
        program.file_name().and_then(|p| p.to_str()) == Some("status_cycle.py")
            && package["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && package["destination"]
                == json!(
                    program
                        .parent()
                        .context("missing cadence programme directory")?
                ),
        "incumbent cadence is outside its sealed package"
    );
    let member = package["members"]
        .as_array()
        .context("missing cadence package members")?
        .iter()
        .find(|m| m["name"] == "status_cycle.py")
        .context("missing installed cadence program")?;
    incumbent["program"] = reference(&program, string(member, "sha256")?);
    observer_incumbent(&json!({"incumbent":incumbent}))?;
    Ok(json!({"registration":active,"incumbent":incumbent,"package":ready["package"]}))
}

fn guard_control(guard: &Value, plan: &Value, expected_unit: Option<&str>) -> Result<()> {
    let output = Command::new("/usr/bin/timeout")
        .args([
            "30",
            string(guard, "path")?,
            string(plan, "path")?,
            "--plan-sha256",
            string(plan, "sha256")?,
            "--self-sha256",
            string(guard, "sha256")?,
            "--validate-plan-only",
        ])
        .output()?;
    if let Some(unit) = expected_unit {
        ensure!(
            output.status.success(),
            "candidate guard refused its static plan"
        );
        let proof: Value = serde_json::from_slice(&output.stdout)?;
        ensure!(
            proof["validated"] == true
                && proof["unit"] == unit
                && proof["plan_sha256"] == plan["sha256"]
                && proof["self_sha256"] == guard["sha256"]
                && proof["resource_samples_taken"] == 0
                && proof["producer_signaled"] == false,
            "guard static plan evidence changed"
        );
    } else {
        ensure!(
            output.status.code() == Some(1)
                && std::str::from_utf8(&output.stderr)?.contains("unknown recovery guard unit"),
            "candidate guard did not reject retry13 by its native route identity"
        );
    }
    Ok(())
}

fn guard_ready(profile: &Value, guard_sha: &str) -> Result<Value> {
    let guard = &profile["guard"];
    let root_path = Path::new(string(guard, "candidate_root_receipt")?);
    let receipt_path = Path::new(string(guard, "qualification")?);
    let qualified = doc(receipt_path, guard_sha, 0)?;
    ensure!(
        qualified["schema"] == "horizon-170-full-metered-native-guard-qualified-v1"
            && qualified["physical_launch"] == false
            && qualified["guard"]["path"] == guard["image"]
            && qualified["contract"]["contract"]["path"] == guard["contract"],
        "foreign candidate guard qualification"
    );
    let executable = image(&qualified["guard"])?;
    let seal = bound(&qualified["seal"], 0)?;
    ensure!(
        seal["members"]
            .as_array()
            .context("missing sealed guard members")?
            .iter()
            .any(|member| member["name"] == "guard"
                && member["sha256"] == qualified["guard"]["sha256"]),
        "guard absent from deployment seal"
    );
    bound(&qualified["build"], 0)?;
    let contract = bound(&qualified["contract"]["contract"], 0)?;
    bound(&qualified["contract"]["deployment_seal"], 0)?;
    let witness = bound(&qualified["witness"], 0)?;
    ensure!(
        contract["qualified_native_witness"] == qualified["witness"]
            && witness["native_identity"]["executable"] == guard["image"]
            && witness["native_identity"]["executable_sha256"] == qualified["guard"]["sha256"],
        "wrong native witness executable"
    );
    let roots = witness["independent_roots_receipt"]["receipts"]
        .as_array()
        .context("missing native witness roots")?;
    let root_ref = roots
        .iter()
        .find(|x| x["path"] == json!(root_path))
        .context("guard witness does not bind candidate root")?;
    let root = bound(root_ref, 0)?;
    let target = run(NEW_RUN);
    let meta = fs::symlink_metadata(&target)?;
    ensure!(
        target.canonicalize()? == target
            && meta.is_dir()
            && meta.uid() == 1001
            && meta.gid() == 1003
            && meta.mode() & 0o7777 == 0o700
            && root["schema"] == "horizon-epoch170-metered-successor-root-v1"
            && root["root"] == json!(target)
            && root["device"] == meta.dev()
            && root["inode"] == meta.ino()
            && root["retained_retry13_terminal_sha256"] == TERMINAL_SHA,
        "native candidate root differs"
    );
    let positive = bound(&qualified["static_controls"]["positive"], 0)?;
    ensure!(
        positive["unit"] == UNIT
            && positive["worker_root"] == LANE
            && positive["filesystem"] == "/home/sol"
            && positive["receipt_directory"] == guard["receipt_directory"]
            && positive["maximum_root_physical_bytes"] == CAP
            && positive["minimum_free_bytes"] == MIN_FLOOR
            && positive["maximum_worker_vmas"] == 3500000
            && positive["data_fulfillment"] == qualified["contract"],
        "wrong route in positive guard control"
    );
    guard_control(
        &qualified["guard"],
        &qualified["static_controls"]["positive"],
        Some(UNIT),
    )?;
    let negative = bound(&qualified["static_controls"]["wrong-predecessor-170"], 0)?;
    ensure!(
        negative["unit"] == OLD_UNIT,
        "missing retry13 guard rejection control"
    );
    guard_control(
        &qualified["guard"],
        &qualified["static_controls"]["wrong-predecessor-170"],
        None,
    )?;
    Ok(
        json!({"qualification":reference(receipt_path,guard_sha),"image":executable,"root":root_ref}),
    )
}

fn same_route(proposed: &Value, enrollment: &Value) -> Result<()> {
    for key in [
        "candidate_range",
        "producer_unit",
        "guard_timer",
        "worker_source",
        "worker_sha256",
        "worker_device",
        "worker_inode",
        "append_log",
    ] {
        ensure!(
            proposed[key] == enrollment[key],
            "observer enrollment differs in {key}"
        );
    }
    Ok(())
}

fn preflight(profile: &Value, guard_sha: &str, obs_sha: &str, price: &Value) -> Result<Value> {
    let guard = guard_ready(profile, guard_sha)?;
    let runtime = rt(BASE);
    let fleet_sha = string(&profile["observer"]["active_fleet"]["fleet"], "sha256")?;
    let enrollment_path = admission::enrollment_path(fleet_sha);
    let enrollment_path = if enrollment_path.exists() {
        enrollment_path
    } else {
        runtime.join("OBSERVER_ENROLLMENT.json")
    };
    let enrollment = doc(&enrollment_path, obs_sha, 0)?;
    let expected = &profile["observer"];
    let active = &expected["active_fleet"];
    ensure!(
        enrollment["schema"] == "horizon-epoch170-metered-observer-enrollment-v1"
            && enrollment["guard_qualification"] == guard["qualification"]
            && enrollment["fleet"] == active["fleet"]
            && enrollment["previous_sample"] == active["observer"]
            && enrollment["incumbent_timer"] == active["timer"]
            && enrollment["scheduled_observer"] == active["next_observer"]
            && enrollment["activation_granted"] == false,
        "foreign candidate observer enrollment"
    );
    same_route(expected, &enrollment["candidate"])?;
    let producer_log = Path::new(string(expected, "append_log")?);
    let log = file(producer_log, 0)?;
    let meta = log.metadata()?;
    ensure!(
        meta.len() == 0
            && meta.gid() == 0
            && meta.mode() & 0o7777 == 0o600
            && enrollment["candidate"]["log_device"] == meta.dev()
            && enrollment["candidate"]["log_inode"] == meta.ino(),
        "staged append log differs"
    );
    let provider = bound(&price["reference"], 0)?;
    admission::validate_drained_price(&provider, &enrollment)?;
    let booking = &provider["bookings"]["170"];
    let proposal = &provider["epoch170_metered_full"];
    let remaining = number(booking, "remaining_bytes")?;
    let floor = number(&provider, "protected_raw_floor_bytes")?;
    let required = number(&provider, "complete_required_HOME_bytes")?;
    let donor = &provider["epoch159_donor_cover"];
    let donor_required = number(donor, "native_home_required")?;
    let donor_growth = donor_required
        .checked_sub(number(proposal, "original_complete_required_home_bytes")?)
        .context("unbound donor floor")?;
    let zero_donor = number(&provider, "full170_zero_remaining_native_HOME_bytes")?
        .checked_add(donor_growth)
        .context("zero remaining donor floor overflow")?;
    let protected_basis = donor_required.max(
        zero_donor
            .checked_add(remaining)
            .context("donor floor overflow")?,
    );
    let additional = required.checked_sub(protected_basis);
    ensure!(
        provider["schema"] == "horizon-incident-replay-fit-v1"
            && provider["epoch"] == 170
            && provider["fits"] == true
            && provider["fleet"] == active["fleet"]
            && provider["resource_credit_bytes"] == 0
            && provider["replay_launch_authorized"] == false
            && booking["root"] == LANE
            && booking["cap_bytes"] == CAP
            && number(booking, "physical_bytes")?.checked_add(remaining) == Some(CAP)
            && floor.checked_add(remaining) == Some(required)
            && proposal["zero_remaining_donor_floor_bytes"] == zero_donor
            && proposal["donor_required_HOME_bytes"] == protected_basis
            && additional == Some(number(proposal, "additional_reservation_bytes")?)
            && number(proposal, "additional_reservation_bytes")?
                <= number(donor, "remaining_home_bytes")?
            && proposal["producer_unit"] == UNIT
            && proposal["guard_timer"] == TIMER
            && proposal["guard_qualification"] == guard["qualification"]
            && proposal["observer_enrollment"] == reference(&enrollment_path, obs_sha)
            && proposal["candidate_root"] == guard["root"]
            && proposal["worker_sha256"] == WORKER_SHA
            && proposal["source_profile_sha256"] == sha(&serde_json::to_vec(profile)?)
            && number(&provider, "available_HOME_bytes")?
                >= number(&provider, "complete_required_HOME_bytes")?
            && number(&provider, "protected_raw_floor_bytes")? >= MIN_FLOOR
            && number(&provider, "available_memory_bytes")?
                >= number(&provider, "required_available_memory_bytes")?,
        "metered candidate lacks exact funded HOME and RAM quote"
    );
    let live_cadence = cadence_registration(&enrollment["incumbent_registration"])?;
    ensure!(
        live_cadence["incumbent"] == enrollment["incumbent"],
        "observer enrollment does not bind the registered running cadence"
    );
    for peer in active["replays"]
        .as_array()
        .context("missing live replay roster")?
    {
        let m = properties(string(peer, "unit")?)?;
        ensure!(
            m["ActiveState"] == "active"
                && m["InvocationID"] == peer["invocation_id"]
                && m["NRestarts"] == "0",
            "peer changed since coordinated sample"
        );
    }
    let timer = properties(string(active, "timer")?)?;
    ensure!(
        timer["ActiveState"] == "active"
            && timer["SubState"] == "waiting"
            && !Path::new(string(active, "next_output")?).exists(),
        "coordinated observation advanced or timer is absent"
    );
    for unit in [UNIT, TIMER, GUARD_UNIT] {
        ensure!(
            properties(unit)?["LoadState"] == "not-found",
            "candidate or guard already exists: {unit}"
        );
    }
    Ok(
        json!({"schema":"horizon-epoch170-metered-preflight-review-v1","profile":profile,
        "guard":guard,"observer":reference(&enrollment_path,obs_sha),"price":price["reference"],
        "replay_launch_authorized":false,"archive_publication_authorized":false}),
    )
}

fn dispatch() -> Result<Value> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, digest] if mode == "hold" => held::hold(digest),
        [
            mode,
            offline,
            proof,
            fleet,
            hash,
            guard,
            active_path,
            active_sha,
        ] if mode == "enroll" => {
            let profile = inputs(Path::new(offline), Path::new(proof), Path::new(fleet), hash)?;
            admission::enrollment(
                &profile,
                guard,
                &reference(Path::new(active_path), active_sha),
            )
        }
        [
            mode,
            offline,
            proof,
            fleet,
            hash,
            guard,
            enrollment_sha,
            route,
            provider_sha,
        ] if mode == "quote" => {
            let profile = inputs(Path::new(offline), Path::new(proof), Path::new(fleet), hash)?;
            let path = admission::enrollment_path(hash);
            admission::quote(
                &profile,
                guard,
                &reference(&path, enrollment_sha),
                route,
                provider_sha,
            )
        }
        [mode, path, digest] if mode == "cadence" => {
            cadence_registration(&reference(Path::new(path), digest))
        }
        [mode, offline, proof, fleet, hash] if mode == "inputs" => {
            inputs(Path::new(offline), Path::new(proof), Path::new(fleet), hash)
        }
        [
            mode,
            offline,
            proof,
            fleet,
            hash,
            guard,
            observer,
            price_path,
            price_hash,
        ] if mode == "preflight" => {
            let profile = inputs(Path::new(offline), Path::new(proof), Path::new(fleet), hash)?;
            preflight(
                &profile,
                guard,
                observer,
                &json!({"reference":reference(Path::new(price_path),price_hash)}),
            )
        }
        _ => bail!(
            "usage: cadence ACTIVE ACTIVE_SHA | inputs OFFLINE DIAGNOSTIC FLEET FLEET_SHA | enroll OFFLINE DIAGNOSTIC FLEET FLEET_SHA GUARD_SHA ACTIVE ACTIVE_SHA | quote OFFLINE DIAGNOSTIC FLEET FLEET_SHA GUARD_SHA ENROLLMENT_SHA PROVIDER_KIND PROVIDER_SEAL_SHA | preflight OFFLINE DIAGNOSTIC FLEET FLEET_SHA GUARD_SHA OBSERVER_SHA PRICE PRICE_SHA | hold PAYLOAD_SHA"
        ),
    }
}

fn main() {
    match dispatch() {
        Ok(report) => println!("{report}"),
        Err(e) => {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_argv() -> Vec<String> {
        let old = run(OLD_RUN).display().to_string();
        vec![
            "/usr/bin/systemd-run".into(),
            format!("--unit={OLD_UNIT}"),
            format!(
                "--setenv=JETSTREAMER_HISTORICAL_WORKER_V1_5_6={PACKAGE}/jetstreamer-historical-worker-v1-5-6"
            ),
            format!(
                "--property=ExecPaths={PACKAGE}/jetstreamer-node {PACKAGE}/jetstreamer-historical-worker-v1-5-6 {LANE}"
            ),
            format!("--property=ReadWritePaths={old}"),
            format!("--property=BindReadOnlyPaths=/stage/original:{old}/input"),
            format!("--cohort-manifest-fingerprint={FINGERPRINT}"),
            "--root-checkpoint-cohort".into(),
        ]
    }

    #[test]
    fn corrected_profile_keeps_full_root_and_changes_both_worker_bindings() {
        let command = producer_argv(retained_argv()).unwrap();
        let actual = command.join("\n");
        assert!(!actual.contains(OLD_RUN));
        assert!(!actual.contains(OLD_UNIT));
        assert!(actual.contains(&format!("{WORKER}:{WORKER_TARGET}")));
        assert!(actual.contains(&format!(
            "--setenv=JETSTREAMER_HISTORICAL_WORKER_V1_5_6={WORKER_TARGET}"
        )));
        assert!(actual.contains(FINGERPRINT));
    }

    #[test]
    fn rejects_ambiguous_worker_and_unqualified_root() {
        let mut duplicate = retained_argv();
        duplicate.push(duplicate[2].clone());
        assert!(producer_argv(duplicate).is_err());
        let mut replaced = retained_argv();
        replaced[6] = "--cohort-manifest-fingerprint=wrong".into();
        assert!(producer_argv(replaced).is_err());
    }

    #[test]
    fn observer_cannot_adopt_an_old_worker_or_guard() {
        let declared = json!({"candidate_range":"170", "producer_unit":UNIT, "guard_timer":TIMER,
            "worker_source":WORKER,"worker_sha256":WORKER_SHA,"worker_device":64512,"worker_inode":101134948,"append_log":run(NEW_RUN).join("producer.log")});
        assert!(same_route(&declared, &declared).is_ok());
        for (field, bad) in [
            ("worker_sha256", OLD_WORKER_SHA),
            ("producer_unit", OLD_UNIT),
            ("guard_timer", "another.timer"),
        ] {
            let mut foreign = declared.clone();
            foreign[field] = json!(bad);
            assert!(same_route(&declared, &foreign).is_err());
        }
    }
}
