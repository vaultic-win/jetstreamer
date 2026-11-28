//! Read-only singleton producer -> delivery evidence. Never launches or publishes.
//! Reuses the node's actual committed-cohort validator under the source owner.
#[allow(dead_code)]
#[path = "../jetstreamer-node/src/cohort_publication.rs"]
mod cohort;
#[allow(dead_code)]
#[path = "../jetstreamer-horizon-observe/src/full265.rs"]
mod full265;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    producer_unit: String,
    producer_invocation_id: String,
    expected_exec_prefix: String,
    startup_handoff: Bound,
    manifest: Bound,
    epoch_expectation: Bound,
    output_directory: PathBuf,
    output_device: u64,
    output_inode: u64,
    source_uid: u32,
    source_gid: u32,
    batch_receipt_directory: PathBuf,
    public_directory: PathBuf,
    receipt_directory: PathBuf,
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"length":m.len(),"mode":m.mode(),
        "uid":m.uid(),"gid":m.gid(),"link_count":m.nlink(),"modified_seconds":m.mtime(),
        "modified_nanoseconds":m.mtime_nsec(),"changed_seconds":m.ctime(),"changed_nanoseconds":m.ctime_nsec()})
}
fn bytes(path: &Path, uid: u32, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= limit,
        "unsafe input custody/size: {}",
        path.display()
    );
    let mut b = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 <= limit
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(path)?),
        "input changed"
    );
    Ok(b)
}
fn bound(b: &Bound) -> Result<Vec<u8>> {
    ensure!(hex(&b.sha256, 64), "invalid digest");
    let v = bytes(&b.path, 0, 32 << 20)?;
    ensure!(sha(&v) == b.sha256, "bound input differs");
    Ok(v)
}
fn json_bound(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&bound(b)?)?)
}
fn fingerprint(manifest: &Value) -> Result<[u8; 32]> {
    let s = manifest["manifest_fingerprint"]
        .as_str()
        .context("manifest fingerprint")?;
    let s = s.strip_prefix("sha256:").context("fingerprint prefix")?;
    ensure!(hex(s, 64), "fingerprint hex");
    let mut a = [0u8; 32];
    for (i, b) in a.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(a)
}
fn checkpoint_hash(v: &Value) -> Result<[u8; 32]> {
    let s = v.as_str().context("snapshot hash")?;
    bs58::decode(s)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("snapshot hash length"))
}
const UNIT_211: &str = "horizon-singleton-211-capped-4aeca563-v1.service";
const PLAN_211_SHA: &str = "802d597d92490396e39b5306d2319a980d3f6408fa4ac1554be2af06fee879a3";

fn bound_211_command(p: &Plan, startup: &Value, manifest: &Value) -> Result<()> {
    // PID 1 recorded the launcher. The same PID subsequently exec'd the node.
    let observed = json_bound(&Bound {
        path: "/home/ubuntu/.codex/diagnostics/horizon211-delivery-inputs-v187-a1/observed.json"
            .into(),
        sha256: "d00e8030f1a146ede14b66f4568e7c862818a7fddb4f45dfa609fa50389f361d".into(),
    })?;
    let capability: Bound = serde_json::from_value(startup["input_capability"].clone())?;
    let evidence = json_bound(&capability)?;
    let archive = observed["actual_argv"]
        .get(7)
        .and_then(Value::as_str)
        .and_then(|argument| argument.strip_prefix("--snapshot-archive="))
        .context("epoch 211 snapshot argument")?;
    let snapshot_name = manifest["manifest"]["verification_cohorts"][0]["bootstrap"]["uri"]
        .as_str()
        .and_then(|uri| uri.rsplit_once('/'))
        .map(|(_, name)| name)
        .context("epoch 211 bootstrap URI")?;
    ensure!(
        Path::new(archive).file_name().and_then(|s| s.to_str()) == Some(snapshot_name)
            && observed["input_capability"] == startup["input_capability"]
            && observed["observed_epoch"] == 211
            && observed["worker"] == startup["worker"]
            && evidence["all_inputs_rehashed"] == true
            && evidence["manifest_fingerprint"] == manifest["manifest_fingerprint"]
            && evidence["files"]
                .as_array()
                .is_some_and(
                    |files| files.iter().any(|row| row["binding"]["path"] == archive
                        && row["binding"]["sha256"]
                            == "958a8e5aad2423350f04470dffbd90fd8d7e458f7f8e774e15dd86d43291b5fb")
                ),
        "epoch 211 executed snapshot differs"
    );
    let argv = observed["actual_argv"]
        .as_array()
        .context("missing executed argv")?;
    ensure!(
        observed["plan"]["sha256"] == PLAN_211_SHA
            && observed["original_startup"] == serde_json::to_value(&p.startup_handoff)?
            && observed["pid"] == startup["main_pid"]
            && observed["producer_properties"]["InvocationID"] == p.producer_invocation_id
            && observed["node"] == startup["node"]
            && startup["same_pid_exec_observed"] == true
            && startup["producer"]["ExecStart"]
                .as_str()
                .and_then(|s| s.split_once(" ; ignore_errors="))
                .is_some_and(|(prefix, _)| prefix == p.expected_exec_prefix)
            && argv.len() == 8
            && argv[0] == startup["node"]["path"]
            && argv[1] == "211"
            && argv[2] == p.output_directory.to_string_lossy().as_ref()
            && argv[3] == "--verify"
            && argv[4] == "--root-checkpoint-cohort"
            && argv[5] == format!("--cohort-manifest={}", p.manifest.path.display())
            && argv[6]
                == format!(
                    "--cohort-manifest-fingerprint={}",
                    manifest["manifest_fingerprint"]
                        .as_str()
                        .context("manifest fingerprint")?
                ),
        "epoch 211 executed command differs"
    );
    Ok(())
}

fn validate_manifest(p: &Plan, manifest: &Value) -> Result<()> {
    fingerprint(manifest)?;
    let m = &manifest["manifest"];
    if p.epoch == 211 {
        let cohorts = m["verification_cohorts"]
            .as_array()
            .context("singleton cohort")?;
        ensure!(
            m["first_epoch"] == 211
                && m["last_epoch"] == 211
                && m["epoch_slots"] == 432000
                && cohorts.len() == 1
                && cohorts[0]["first_epoch"] == 211
                && cohorts[0]["last_epoch"] == 211
                && cohorts[0]["publication_gate"]
                    == "all-archives-validated-and-final-root-verified"
                && cohorts[0]["bootstrap"]["slot"] == 91151575
                && cohorts[0]["root_checkpoints"]
                    .as_array()
                    .is_some_and(|rows| rows.len() == 1 && rows[0]["slot"] == 91583512),
            "epoch 211 singleton manifest differs"
        );
        return Ok(());
    }
    ensure!(
        m["first_epoch"] == p.epoch
            && m["last_epoch"] == p.epoch
            && m["publication_boundary_epoch"] == p.epoch
            && m["epoch_slots"] == 432000
            && m["epochs"].as_array().is_some_and(|x| x.len() == 1)
            && m["epochs"][0]["epoch"] == p.epoch,
        "not an exact singleton manifest"
    );
    Ok(())
}
fn validate_plan(p: &Plan) -> Result<Value> {
    ensure!(
        p.schema == "horizon-singleton-delivery-handoff-plan-v1"
            && ((247..=251).contains(&p.epoch) || matches!(p.epoch, 211 | 265))
            && p.source_uid == 1000
            && p.source_gid == 1000
            && hex(&p.producer_invocation_id, 32)
            && (if p.epoch == 211 {
                p.producer_unit == UNIT_211
            } else {
                p.producer_unit
                    .starts_with(&format!("horizon-qualify-{}-", p.epoch))
            })
            && p.producer_unit.ends_with(".service")
            && p.producer_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
            && p.expected_exec_prefix
                .starts_with("{ path=/var/lib/jetstreamer/")
            && !p.expected_exec_prefix.contains('\n')
            && p.output_directory
                .starts_with("/home/ubuntu/.jetstreamer-private")
            && p.output_directory
                .file_name()
                .is_some_and(|s| s == "output")
            && p.public_directory == Path::new("/home/ubuntu/horizon")
            && p.receipt_directory.starts_with("/var/lib/jetstreamer")
            && !p.receipt_directory.starts_with(&p.output_directory),
        "invalid handoff plan scope"
    );
    if p.epoch == 265 {
        full265::validate_delivery(
            p.epoch,
            &p.producer_unit,
            &p.producer_invocation_id,
            &p.expected_exec_prefix,
            &p.output_directory,
            &json!({"path":p.manifest.path,"sha256":p.manifest.sha256}),
            &json!({"path":p.startup_handoff.path,"sha256":p.startup_handoff.sha256}),
        )?;
    }
    let startup = json_bound(&p.startup_handoff)?;
    ensure!(
        startup["producer"]["Id"] == p.producer_unit
            && startup["producer"]["InvocationID"] == p.producer_invocation_id
            && startup["producer"]["NRestarts"] == "0"
            && startup["remote_mutations"] == false,
        "startup owner differs"
    );
    let manifest = json_bound(&p.manifest)?;
    validate_manifest(p, &manifest)?;
    let expectation = json_bound(&p.epoch_expectation)?;
    ensure!(
        expectation["epoch"] == p.epoch
            && matches!(
                expectation["schema"].as_str(),
                Some(
                    "horizon-current-reader-epoch-expectation-v1"
                        | "horizon-current-reader-epoch-expectation-v2"
                )
            )
            && expectation["terminal_slot"]
                .as_u64()
                .is_some_and(|s| (p.epoch * 432000..(p.epoch + 1) * 432000).contains(&s)),
        "independent terminal expectation differs"
    );
    if p.epoch == 211 {
        bound_211_command(p, &startup, &manifest)?;
        return Ok(manifest);
    }
    ensure!(
        p.expected_exec_prefix.contains(&format!(
            " {} {} --verify --root-checkpoint-cohort ",
            p.epoch,
            p.output_directory.display()
        )) && p
            .expected_exec_prefix
            .contains(&format!("--cohort-manifest={} ", p.manifest.path.display()))
            && p.expected_exec_prefix.contains(&format!(
                "--cohort-manifest-fingerprint={} ",
                manifest["manifest_fingerprint"]
                    .as_str()
                    .context("fingerprint")?
            )),
        "producer command does not bind singleton inputs"
    );
    Ok(manifest)
}
fn terminal_values(p: &Plan, u: &BTreeMap<String, String>, rows: &[Value]) -> Result<Value> {
    let val = |k: &str| u.get(k).map(String::as_str).unwrap_or("");
    ensure!(
        val("Id") == p.producer_unit
            && val("LoadState") == "loaded"
            && val("ActiveState") == "inactive"
            && val("SubState") == "dead"
            && val("MainPID") == "0"
            && val("NRestarts") == "0"
            && val("Result") == "success"
            && val("ExecMainCode") == "1"
            && val("ExecMainStatus") == "0"
            && (val("InvocationID") == p.producer_invocation_id
                || (p.epoch != 265 && val("InvocationID").is_empty()))
            && val("ExecStart")
                .split_once(" ; ignore_errors=")
                .is_some_and(|(a, _)| a == p.expected_exec_prefix),
        "producer is not the exact clean terminal owner"
    );
    ensure!(
        !rows.is_empty() && rows.len() < 256,
        "manager history empty/truncated"
    );
    let own: Vec<_> = rows
        .iter()
        .filter(|r| r["_PID"] == "1" && r["_UID"] == "0" && r["UNIT"] == p.producer_unit)
        .collect();
    let starts: Vec<_> = own
        .iter()
        .filter(|r| {
            r["INVOCATION_ID"] == p.producer_invocation_id
                && r["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("Started {} -", p.producer_unit)))
        })
        .collect();
    let ends: Vec<_> = own
        .iter()
        .filter(|r| {
            r["INVOCATION_ID"] == p.producer_invocation_id
                && r["MESSAGE"] == format!("{}: Deactivated successfully.", p.producer_unit)
        })
        .collect();
    ensure!(
        starts.len() == 1 && ends.len() == 1,
        "exact PID1 start/end missing or duplicate"
    );
    let clock = |r: &Value| -> Result<u64> {
        Ok(r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("manager time")?
            .parse()?)
    };
    let start = clock(starts[0])?;
    ensure!(
        clock(ends[0])? > start
            && own.iter().all(|r| clock(r)
                .is_ok_and(|t| t < start || r["INVOCATION_ID"] == p.producer_invocation_id)),
        "reordered or replaced producer"
    );
    Ok(json!({"unit":u,"events":[starts[0],ends[0]]}))
}
fn terminal(p: &Plan) -> Result<Value> {
    let out=Command::new("/usr/bin/systemctl").args(["show",&p.producer_unit,
        "--property=Id,LoadState,ActiveState,SubState,MainPID,NRestarts,Result,ExecMainCode,ExecMainStatus,InvocationID,ExecStart"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1 << 20,
        "manager query failed"
    );
    let u = String::from_utf8(out.stdout)?
        .lines()
        .map(|s| {
            s.split_once('=')
                .context("manager row")
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let out = Command::new("/usr/bin/journalctl")
        .args([
            "--unit",
            &p.producer_unit,
            "_PID=1",
            "--output=json",
            "--no-pager",
            "--lines=256",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "manager history failed"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    terminal_values(p, &u, &rows)
}
fn drain_properties(p: &Plan) -> Result<BTreeMap<String, String>> {
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            &p.producer_unit,
            "--property=ControlGroup,ControlPID,Job,Restart,KillMode,Delegate,TriggeredBy",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 65536,
        "drain manager query failed"
    );
    let values = String::from_utf8(out.stdout)?
        .lines()
        .map(|line| {
            let (k, v) = line.split_once('=').context("drain manager row")?;
            Ok((k.to_owned(), v.to_owned()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    validate_drain_properties(&values, &format!("/system.slice/{}", p.producer_unit))?;
    Ok(values)
}
fn validate_drain_properties(v: &BTreeMap<String, String>, group: &str) -> Result<()> {
    let get = |key: &str| v.get(key).map(String::as_str);
    ensure!(
        get("ControlPID") == Some("0")
            && get("Job") == Some("")
            && get("Restart") == Some("no")
            && get("KillMode") == Some("control-group")
            && get("Delegate") == Some("no")
            && get("TriggeredBy") == Some("")
            && matches!(get("ControlGroup"), Some(s) if s.is_empty() || s == group),
        "producer has control work, restart/delegation or a changed cgroup"
    );
    Ok(())
}
fn in_group(record: &str, group: &str) -> Result<bool> {
    let rows: Vec<_> = record.lines().collect();
    ensure!(rows.len() == 1, "unified cgroup record required");
    let path = rows[0].strip_prefix("0::").context("not cgroup v2")?;
    ensure!(path.starts_with('/'), "nonabsolute process cgroup");
    Ok(path == group || path.strip_prefix(group).is_some_and(|s| s.starts_with('/')))
}
fn empty_cgroup(path: &Path, remaining: &mut usize) -> Result<()> {
    ensure!(*remaining > 0, "too many cgroup descendants");
    *remaining -= 1;
    ensure!(
        fs::symlink_metadata(path)?.is_dir() && path.canonicalize()? == path,
        "unsafe cgroup directory"
    );
    let events = fs::read_to_string(path.join("cgroup.events"))?;
    ensure!(
        events.lines().filter(|s| *s == "populated 0").count() == 1
            && !events
                .lines()
                .any(|s| s.starts_with("populated ") && s != "populated 0")
            && fs::read_to_string(path.join("cgroup.procs"))?
                .trim()
                .is_empty()
            && fs::read_to_string(path.join("cgroup.threads"))?
                .trim()
                .is_empty(),
        "producer cgroup remains populated"
    );
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            empty_cgroup(&entry.path(), remaining)?;
        }
    }
    Ok(())
}
fn drained(p: &Plan) -> Result<Value> {
    ensure!(
        Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "host cgroup v2 required"
    );
    ensure!(
        fs::read_link("/proc/self/ns/cgroup")? == fs::read_link("/proc/1/ns/cgroup")?,
        "drain capture must share PID1 cgroup namespace"
    );
    let properties = drain_properties(p)?;
    let group = format!("/system.slice/{}", p.producer_unit);
    let path = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    let present = match fs::symlink_metadata(&path) {
        Ok(_) => {
            empty_cgroup(&path, &mut 1024)?;
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let mut inspected = 0u64;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        match fs::read_to_string(entry.path().join("cgroup")) {
            Ok(record) => {
                ensure!(!in_group(&record, &group)?, "producer still owns a process");
                inspected += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    ensure!(
        inspected > 1 && drain_properties(p)? == properties,
        "drain census changed"
    );
    Ok(
        json!({"properties":properties,"original_cgroup":group,"cgroup_present":present,
        "process_cgroups_inspected":inspected,"descendant_processes":0}),
    )
}
fn capture_drain(p: &Plan, binding: &Bound, terminal_sha: &str, self_sha: &str) -> Result<()> {
    let handoff = Bound {
        path: p.receipt_directory.join("terminal-handoff.json"),
        sha256: terminal_sha.into(),
    };
    let prior = json_bound(&handoff)?;
    ensure!(
        prior["schema"] == "horizon-singleton-delivery-handoff-v1"
            && prior["plan"] == serde_json::to_value(binding)?
            && prior["epoch"] == p.epoch
            && matches!(prior["self_sha256"].as_str(), Some(s) if s == self_sha || s ==
            "b90e9ca43b438ee6eb26e066a4ea6838f03f14b0dada0951913473195c878e95"),
        "terminal handoff origin differs"
    );
    let startup = json_bound(&p.startup_handoff)?;
    ensure!(
        startup["producer"]["ControlGroup"] == format!("/system.slice/{}", p.producer_unit)
            && startup["producer"]["Delegate"] == "no"
            && startup["producer"]["KillMode"] == "control-group"
            && startup["producer"]["Restart"] == "no",
        "startup containment differs"
    );
    let before = terminal(p)?;
    ensure!(
        before == prior["producer"],
        "terminal owner changed since handoff"
    );
    let first = drained(p)?;
    let second = drained(p)?;
    ensure!(
        before == terminal(p)?,
        "terminal owner changed during drain capture"
    );
    let dir = fs::symlink_metadata(&p.receipt_directory)?;
    ensure!(
        p.receipt_directory.canonicalize()? == p.receipt_directory
            && dir.is_dir()
            && dir.uid() == 0
            && dir.mode() & 0o077 == 0,
        "unsafe drain receipt directory"
    );
    let receipt = p.receipt_directory.join("terminal-drain.json");
    let value = json!({"schema":"horizon-singleton-terminal-drain-v1","plan":binding,
        "terminal_handoff":handoff,"epoch":p.epoch,"self_sha256":self_sha,
        "recorded_unix_seconds":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        "producer":before,"first_census":first,"second_census":second,
        "producer_cgroup_drained":true,"fresh_complete_fleet_admission_required":true,
        "recheck_terminal_and_drain_at_admission_required":true,
        "resource_release_authorized":false,"replay_launch_authorized":false,
        "publication_authorized":false,"local_retirement_authorized":false,"remote_mutations":false});
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&receipt)?;
    serde_json::to_writer_pretty(&mut f, &value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(&p.receipt_directory)?.sync_all()?;
    println!(
        "{}",
        json!({"receipt":receipt,"producer_cgroup_drained":true,"resource_release_authorized":false})
    );
    Ok(())
}
// A manager reload can clear the runtime fields following ExecStart's command.
// Validate both command prefixes against the plan and bind the original PID1
// journal cursors across the reload.
fn same_terminal_events(p: &Plan, saved: &Value, current: &Value, boot: &str) -> Result<()> {
    let unit: BTreeMap<String, String> = serde_json::from_value(saved["unit"].clone())?;
    let events = saved["events"]
        .as_array()
        .context("saved terminal events")?;
    let checked = terminal_values(p, &unit, events)?;
    ensure!(checked == *saved, "saved terminal record differs");
    let live = current["events"]
        .as_array()
        .context("current terminal events")?;
    ensure!(
        live.len() == 2
            && events.iter().zip(live).all(|(a, b)| {
                a["_BOOT_ID"] == boot
                    && b["_BOOT_ID"] == boot
                    && a["__CURSOR"].as_str().is_some_and(|s| !s.is_empty())
                    && [
                        "__CURSOR",
                        "MESSAGE_ID",
                        "__REALTIME_TIMESTAMP",
                        "INVOCATION_ID",
                    ]
                    .iter()
                    .all(|&k| a[k] == b[k])
            }),
        "original terminal journal events changed"
    );
    Ok(())
}
fn check_drain(p: &Plan, binding: &Bound, drain_sha: &str) -> Result<()> {
    let drain = Bound {
        path: p.receipt_directory.join("terminal-drain.json"),
        sha256: drain_sha.into(),
    };
    let saved = json_bound(&drain)?;
    let handoff: Bound = serde_json::from_value(saved["terminal_handoff"].clone())?;
    ensure!(
        handoff.path == p.receipt_directory.join("terminal-handoff.json"),
        "handoff path changed"
    );
    let prior = json_bound(&handoff)?;
    ensure!(
        saved["schema"] == "horizon-singleton-terminal-drain-v1"
            && prior["schema"] == "horizon-singleton-delivery-handoff-v1"
            && saved["producer_cgroup_drained"] == true
            && saved["producer"] == prior["producer"]
            && [&saved, &prior].iter().all(|v| v["epoch"] == p.epoch
                && v["resource_release_authorized"] == false
                && v["replay_launch_authorized"] == false
                && v["local_retirement_authorized"] == false
                && v["publication_authorized"] == false
                && v["remote_mutations"] == false)
            && saved["plan"] == serde_json::to_value(binding)?
            && prior["plan"] == saved["plan"],
        "drain and handoff differ"
    );
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let before = terminal(p)?;
    same_terminal_events(p, &prior["producer"], &before, &boot)?;
    let census = drained(p)?;
    ensure!(
        before == terminal(p)?,
        "producer changed during drain recheck"
    );
    println!(
        "{}",
        json!({"epoch":p.epoch,"terminal_handoff":handoff,"terminal_drain":drain,
        "plan":binding,"census":census,"producer_cgroup_drained":true,"resource_release_authorized":false})
    );
    Ok(())
}
fn source_directory(p: &Plan) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == p.source_uid,
        "source validation must use original owner"
    );
    let m = fs::symlink_metadata(&p.output_directory)?;
    ensure!(
        p.output_directory.canonicalize()? == p.output_directory
            && m.is_dir()
            && m.dev() == p.output_device
            && m.ino() == p.output_inode
            && m.uid() == p.source_uid
            && m.gid() == p.source_gid,
        "source directory changed"
    );
    ensure!(
        p.batch_receipt_directory.canonicalize()? == p.batch_receipt_directory
            && p.batch_receipt_directory.file_name().is_some_and(
                |s| s == format!("destination-{:016x}-{:016x}", m.dev(), m.ino()).as_str()
            )
            && p.batch_receipt_directory
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|s| s == "archive-batches"),
        "receipt directory binding differs"
    );
    json_bound(&p.epoch_expectation)?;
    Ok(())
}
fn source(p: &Plan, manifest: &Value) -> Result<Value> {
    source_directory(p)?;
    let files = fs::read_dir(&p.batch_receipt_directory)?
        .take(17)
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(files.len() <= 16, "too many batch directory entries");
    let receipts: Vec<_> = files
        .iter()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|s| s.starts_with("batch-") && s.ends_with(".json"))
        })
        .collect();
    ensure!(
        receipts.len() == 1,
        "need exactly one completed singleton batch receipt"
    );
    let path = receipts[0].path();
    let before = bytes(&path, p.source_uid, 32 << 20)?;
    let target = fs::symlink_metadata(&p.public_directory)?;
    let admitted = cohort::admit_committed_cohort_receipt(
        &path,
        fingerprint(manifest)?,
        &[p.epoch],
        cohort::DestinationBinding {
            path: &p.public_directory,
            device: target.dev(),
            inode: target.ino(),
        },
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        admitted.source_path == p.output_directory && admitted.members.len() == 1,
        "cohort source changed"
    );
    let gate = &admitted.root_checkpoint_gate;
    let expectation = json_bound(&p.epoch_expectation)?;
    ensure!(
        gate.members.len() == 1
            && Some(gate.members[0].terminal.slot) == expectation["terminal_slot"].as_u64()
            && gate.members[0].terminal.last_blockhash
                == checkpoint_hash(&expectation["terminal_blockhash"])?,
        "native terminal does not match independent final block"
    );
    let (e, checkpoints) = if p.epoch == 211 {
        (
            &manifest["manifest"]["verification_cohorts"][0],
            "root_checkpoints",
        )
    } else {
        (
            &manifest["manifest"]["epochs"][0],
            "post_bootstrap_root_checkpoints",
        )
    };
    ensure!(
        gate.members.len() == 1
            && gate.members[0].epoch == p.epoch
            && Some(gate.members[0].bootstrap.slot) == e["bootstrap"]["slot"].as_u64()
            && gate.members[0].bootstrap.accounts_hash
                == checkpoint_hash(&e["bootstrap"]["accounts_hash"])?,
        "bootstrap evidence differs from sealed manifest"
    );
    let expected = e[checkpoints].as_array().context("manifest checkpoints")?;
    ensure!(
        !expected.is_empty() && gate.verified_manifest_checkpoints.len() == expected.len(),
        "root checkpoint census differs"
    );
    for (actual, expected) in gate.verified_manifest_checkpoints.iter().zip(expected) {
        ensure!(
            Some(actual.slot) == expected["slot"].as_u64()
                && actual.accounts_hash == checkpoint_hash(&expected["accounts_hash"])?,
            "canonical root differs"
        );
    }
    let a = &admitted.members[0];
    admitted.revalidate().map_err(anyhow::Error::msg)?;
    ensure!(
        before == bytes(&path, p.source_uid, 32 << 20)?,
        "receipt changed during validation"
    );
    Ok(
        json!({"publication_receipt":{"path":path,"sha256":sha(&before)},"root_checkpoint_gate":gate,
        "archive":{"path":a.archive_path,"sha256":jetstreamer_node::segment_manifest::sha256_hex_string(&a.sha256),
            "identity":identity(&fs::symlink_metadata(&a.archive_path)?)},
        "sidecar":{"path":a.checksum_path,"identity":identity(&fs::symlink_metadata(&a.checksum_path)?)},
        "archive_body_verified":false,"current_reader_verified":false}),
    )
}
fn run(args: &[String]) -> Result<()> {
    ensure!(
        (args.len() == 6
            || (args.len() == 8
                && ((args[0] == "capture-drain" && args[6] == "--terminal-sha256")
                    || (args[0] == "check-drain" && args[6] == "--drain-sha256"))))
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256",
        "expected OPERATION PLAN --plan-sha256 HEX --self-sha256 HEX; capture-drain requires --terminal-sha256 HEX and check-drain requires --drain-sha256 HEX"
    );
    ensure!(
        matches!(
            args[0].as_str(),
            "capture"
                | "capture-drain"
                | "check-drain"
                | "check-plan"
                | "source"
                | "check-source-inputs"
        ),
        "unknown operation"
    );
    let exe = std::env::current_exe()?;
    ensure!(
        sha(&bytes(&exe, 0, 128 << 20)?) == args[5] && hex(&args[5], 64),
        "self hash differs"
    );
    ensure!(
        identity(&File::open("/proc/self/exe")?.metadata()?)
            == identity(&fs::symlink_metadata(&exe)?),
        "running executable identity differs"
    );
    let binding = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_slice(&bound(&binding)?)?;
    ensure!(
        p.epoch != 211 || binding.sha256 == PLAN_211_SHA,
        "unexpected epoch 211 delivery plan"
    );
    if matches!(args[0].as_str(), "source" | "check-source-inputs") {
        // The root parent checks private startup evidence before dropping UID.
        // The child needs only the sealed plan/manifest and owner-readable source.
        let manifest = json_bound(&p.manifest)?;
        validate_manifest(&p, &manifest)?;
        if args[0] == "source" {
            println!("{}", source(&p, &manifest)?);
        } else {
            source_directory(&p)?;
            println!(
                "{}",
                json!({"source_owner_inputs_readable":true,"uid":unsafe{libc::geteuid()}})
            );
        }
        return Ok(());
    }
    validate_plan(&p)?;
    ensure!(unsafe { libc::geteuid() } == 0, "root capture required");
    if args[0] == "check-drain" {
        ensure!(args.len() == 8, "check-drain requires --drain-sha256 HEX");
        return check_drain(&p, &binding, &args[7]);
    }
    if args[0] == "capture-drain" {
        ensure!(
            args.len() == 8,
            "capture-drain requires --terminal-sha256 HEX"
        );
        return capture_drain(&p, &binding, &args[7], &args[5]);
    }
    if args[0] == "check-plan" {
        let child = Command::new(&exe)
            .arg("check-source-inputs")
            .args(&args[1..])
            .uid(p.source_uid)
            .gid(p.source_gid)
            .output()?;
        ensure!(
            child.status.success(),
            "source owner preflight failed: {}",
            String::from_utf8_lossy(&child.stderr)
        );
        println!(
            "{}",
            json!({"configuration_validated":true,"producer_observed":false,"publication_authorized":false})
        );
        return Ok(());
    }
    let initial = terminal(&p)?;
    let out = Command::new(&exe)
        .arg("source")
        .args(&args[1..])
        .uid(p.source_uid)
        .gid(p.source_gid)
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 32 << 20,
        "source validator failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let evidence: Value = serde_json::from_slice(&out.stdout)?;
    ensure!(
        initial == terminal(&p)?,
        "producer changed during source handoff"
    );
    let dir = fs::symlink_metadata(&p.receipt_directory)?;
    ensure!(
        p.receipt_directory.canonicalize()? == p.receipt_directory
            && dir.is_dir()
            && dir.uid() == 0
            && dir.mode() & 0o077 == 0,
        "unsafe receipt directory"
    );
    let receipt = p.receipt_directory.join("terminal-handoff.json");
    let v = json!({"schema":"horizon-singleton-delivery-handoff-v1","plan":binding,"self_sha256":args[5],
        "epoch":p.epoch,"producer":initial,"source":evidence,"fresh_delivery_admission_required":true,
        "resource_release_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,
        "local_retirement_authorized":false,"remote_mutations":false});
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&receipt)?;
    serde_json::to_writer_pretty(&mut f, &v)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(&p.receipt_directory)?.sync_all()?;
    println!(
        "{}",
        json!({"receipt":receipt,"epoch":p.epoch,"publication_authorized":false})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn epoch211_manifest_requires_original_bootstrap_and_terminal_checkpoint() {
        let (mut p, _, _) = fixture();
        p.epoch = 211;
        let original = json!({"manifest_fingerprint":format!("sha256:{}","a".repeat(64)),
            "manifest":{"first_epoch":211,"last_epoch":211,"epoch_slots":432000,
            "verification_cohorts":[{"first_epoch":211,"last_epoch":211,
            "bootstrap":{"slot":91151575},"root_checkpoints":[{"slot":91583512}],
            "publication_gate":"all-archives-validated-and-final-root-verified"}]}});
        validate_manifest(&p, &original).unwrap();
        for (pointer, value) in [
            ("/manifest/last_epoch", json!(212)),
            ("/manifest/verification_cohorts/0/first_epoch", json!(210)),
            (
                "/manifest/verification_cohorts/0/bootstrap/slot",
                json!(91151999),
            ),
            (
                "/manifest/verification_cohorts/0/root_checkpoints",
                json!([]),
            ),
            (
                "/manifest/verification_cohorts/0/root_checkpoints/0/slot",
                json!(91583999),
            ),
            (
                "/manifest/verification_cohorts/0/publication_gate",
                json!(""),
            ),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(validate_manifest(&p, &invalid).is_err(), "{pointer}");
        }
    }
    #[test]
    fn full265_terminal_delivery_keeps_original_identity_and_requires_clean_pid1_pair() {
        let (mut p, mut u, mut rows) = fixture();
        p.epoch = 265;
        p.producer_unit = full265::UNIT.into();
        p.expected_exec_prefix = full265::prefix();
        u.insert("Id".into(), p.producer_unit.clone());
        u.insert(
            "ExecStart".into(),
            format!(
                "{} ; ignore_errors=no ; status=0/0 }}",
                p.expected_exec_prefix
            ),
        );
        rows[0]["UNIT"] = json!(p.producer_unit);
        rows[0]["MESSAGE"] = json!(format!("Started {} - full265.", p.producer_unit));
        rows[1]["UNIT"] = json!(p.producer_unit);
        rows[1]["MESSAGE"] = json!(format!("{}: Deactivated successfully.", p.producer_unit));
        terminal_values(&p, &u, &rows).unwrap();
        for (key, value) in [
            ("InvocationID", ""),
            ("InvocationID", "replaced"),
            ("MainPID", "42"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
        ] {
            let mut bad = u.clone();
            bad.insert(key.into(), value.into());
            assert!(terminal_values(&p, &bad, &rows).is_err(), "{key}");
        }
        assert!(terminal_values(&p, &u, &rows[..1]).is_err());
        let mut manifest = json!({"manifest_fingerprint":format!("sha256:{}","a".repeat(64)),"manifest":{"first_epoch":265,"last_epoch":265,"publication_boundary_epoch":265,"epoch_slots":432000,"epochs":[{"epoch":265}]}});
        validate_manifest(&p, &manifest).unwrap();
        manifest["manifest"]["epochs"][0]["epoch"] = json!(264);
        assert!(validate_manifest(&p, &manifest).is_err());
    }
    #[test]
    fn drained_owner_survives_manager_reload_only_with_original_journal() {
        let (p, mut unit, mut rows) = fixture();
        for (i, row) in rows.iter_mut().enumerate() {
            row["_BOOT_ID"] = json!("boot");
            row["__CURSOR"] = json!(format!("original-{i}"));
        }
        let saved = terminal_values(&p, &unit, &rows).unwrap();
        unit.insert("InvocationID".into(), String::new());
        unit.insert(
            "ExecStart".into(),
            format!("{} ; ignore_errors=no ; pid=0 }}", p.expected_exec_prefix),
        );
        let current = terminal_values(&p, &unit, &rows).unwrap();
        same_terminal_events(&p, &saved, &current, "boot").unwrap();
        assert!(same_terminal_events(&p, &saved, &current, "other-boot").is_err());
        let mut unrelated = current;
        unrelated["events"][1]["__CURSOR"] = json!("later");
        assert!(same_terminal_events(&p, &saved, &unrelated, "boot").is_err());
    }
    #[test]
    fn drain_rejects_control_work_restart_delegation_and_triggers() {
        let group = "/system.slice/example.service";
        let good = BTreeMap::from_iter(
            [
                ("ControlPID", "0"),
                ("Job", ""),
                ("Restart", "no"),
                ("KillMode", "control-group"),
                ("Delegate", "no"),
                ("ControlGroup", group),
                ("TriggeredBy", ""),
            ]
            .map(|(k, v)| (k.to_owned(), v.to_owned())),
        );
        validate_drain_properties(&good, group).unwrap();
        for (key, value) in [
            ("ControlPID", "1"),
            ("Job", "123"),
            ("Restart", "always"),
            ("KillMode", "process"),
            ("Delegate", "yes"),
            ("ControlGroup", "/other"),
            ("TriggeredBy", "example.timer"),
        ] {
            let mut bad = good.clone();
            bad.insert(key.into(), value.into());
            assert!(validate_drain_properties(&bad, group).is_err(), "{key}");
        }
        for key in good.keys() {
            let mut bad = good.clone();
            bad.remove(key);
            assert!(
                validate_drain_properties(&bad, group).is_err(),
                "missing {key}"
            );
        }
    }
    #[test]
    fn process_cgroup_matching_covers_descendants_but_not_similar_names() {
        let group = "/system.slice/test.service";
        for text in [
            "0::/system.slice/test.service\n",
            "0::/system.slice/test.service/child\n",
        ] {
            assert!(in_group(text, group).unwrap());
        }
        assert!(!in_group("0::/system.slice/test.service-other\n", group).unwrap());
        assert!(!in_group("0::/\n", group).unwrap());
        for text in [
            "",
            "1:memory:/system.slice/test.service",
            "0::relative",
            "0::/\n0::/other",
        ] {
            assert!(in_group(text, group).is_err());
        }
    }
    #[test]
    fn empty_cgroup_requires_all_descendants_and_threads_to_be_empty() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("child");
        fs::create_dir(&child).unwrap();
        for path in [dir.path(), child.as_path()] {
            fs::write(path.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
            fs::write(path.join("cgroup.procs"), "").unwrap();
            fs::write(path.join("cgroup.threads"), "").unwrap();
        }
        empty_cgroup(dir.path(), &mut 8).unwrap();
        for (leaf, value) in [
            ("cgroup.procs", "12\n"),
            ("cgroup.threads", "13\n"),
            ("cgroup.events", "populated 1\n"),
        ] {
            let path = child.join(leaf);
            let previous = fs::read(&path).unwrap();
            fs::write(&path, value).unwrap();
            assert!(empty_cgroup(dir.path(), &mut 8).is_err());
            fs::write(path, previous).unwrap();
        }
        assert!(empty_cgroup(dir.path(), &mut 1).is_err());
    }
    #[test]
    #[ignore = "root native persistent test unit; no production owner"]
    fn native_drain_rejects_live_and_accepts_clean_terminal_owner() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let unit = format!(
            "horizon-qualify-247-drain-native-{}.service",
            std::process::id()
        );
        let file = Path::new("/run/systemd/system").join(&unit);
        let target = unit.replace(".service", ".target");
        let target_file = Path::new("/run/systemd/system").join(&target);
        struct Cleanup(PathBuf, String, PathBuf, String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = Command::new("/usr/bin/systemctl")
                    .args(["stop", &self.3, &self.1])
                    .status();
                let _ = fs::remove_file(&self.0);
                let _ = fs::remove_file(&self.2);
                let _ = Command::new("/usr/bin/systemctl")
                    .arg("daemon-reload")
                    .status();
            }
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&file)
            .unwrap();
        f.write_all(b"[Unit]\nDescription=Disjoint native terminal drain test\n[Service]\nType=exec\nExecStart=/usr/bin/sleep 3\nRestart=no\nKillMode=control-group\nMemoryMax=16777216\nMemorySwapMax=0\nTasksMax=8\nCPUQuota=100%\n").unwrap();
        f.sync_all().unwrap();
        let _cleanup = Cleanup(file, unit.clone(), target_file.clone(), target.clone());
        let mut target_handle = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&target_file)
            .unwrap();
        write!(
            target_handle,
            "[Unit]\nDescription=Retain disjoint native terminal evidence\nAfter={unit}\n"
        )
        .unwrap();
        target_handle.sync_all().unwrap();
        assert!(
            Command::new("/usr/bin/systemctl")
                .arg("daemon-reload")
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/usr/bin/systemctl")
                .args(["start", &target])
                .status()
                .unwrap()
                .success()
        );
        let unused = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                &unit,
                "--property=MainPID,ExecMainCode,InvocationID",
            ])
            .output()
            .unwrap();
        assert!(unused.status.success());
        let unused = String::from_utf8(unused.stdout).unwrap();
        assert!(unused.lines().any(|l| l == "MainPID=0"));
        assert!(unused.lines().any(|l| l == "ExecMainCode=0"));
        assert!(unused.lines().any(|l| l == "InvocationID="));
        assert!(
            Command::new("/usr/bin/systemctl")
                .args(["start", &unit])
                .status()
                .unwrap()
                .success()
        );
        let (mut p, _, _) = fixture();
        p.producer_unit = unit.clone();
        let out = Command::new("/usr/bin/systemctl")
            .args(["show", &unit, "--property=InvocationID", "--value"])
            .output()
            .unwrap();
        assert!(out.status.success());
        p.producer_invocation_id = String::from_utf8(out.stdout).unwrap().trim().to_owned();
        p.expected_exec_prefix = "{ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep 3".into();
        assert!(terminal(&p).is_err());
        assert!(drained(&p).is_err());
        std::thread::sleep(std::time::Duration::from_secs(4));
        terminal(&p).unwrap();
        let proof = drained(&p).unwrap();
        assert_eq!(proof["descendant_processes"], 0);
        assert!(proof["process_cgroups_inspected"].as_u64().unwrap() > 1);
        terminal(&p).unwrap();
        assert!(
            Command::new("/usr/bin/systemctl")
                .args(["restart", &target])
                .status()
                .unwrap()
                .success()
        );
        terminal(&p).unwrap();
        drained(&p).unwrap();
    }
    #[test]
    #[ignore = "root native PID1 terminal capture with a disjoint bounded service"]
    fn native_terminal_capture_uses_actual_manager_history() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let name = format!("horizon-qualify-247-handoff-native-{}", std::process::id());
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = Command::new("/usr/bin/systemctl")
                    .args([
                        "stop",
                        &format!("{}.timer", self.0),
                        &format!("{}.service", self.0),
                    ])
                    .status();
            }
        }
        let _cleanup = Cleanup(name.clone());
        assert!(
            Command::new("/usr/bin/systemd-run")
                .args([
                    &format!("--unit={name}"),
                    "--on-active=1h",
                    "--property=MemoryMax=16777216",
                    "--property=MemorySwapMax=0",
                    "--property=TasksMax=8",
                    "--property=CPUQuota=100%",
                    "/usr/bin/true"
                ])
                .status()
                .unwrap()
                .success()
        );
        let unit = format!("{name}.service");
        assert!(
            Command::new("/usr/bin/systemctl")
                .args(["start", "--wait", &unit])
                .status()
                .unwrap()
                .success()
        );
        let out = Command::new("/usr/bin/journalctl")
            .args(["--unit", &unit, "_PID=1", "--output=json", "--no-pager"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let rows = serde_json::Deserializer::from_slice(&out.stdout)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let start = rows
            .iter()
            .find(|r| {
                r["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("Started {unit} -")))
            })
            .unwrap();
        let (mut p, _, _) = fixture();
        p.producer_unit = unit;
        p.producer_invocation_id = start["INVOCATION_ID"].as_str().unwrap().into();
        p.expected_exec_prefix = "{ path=/usr/bin/true ; argv[]=/usr/bin/true".into();
        let proof = terminal(&p).unwrap();
        assert_eq!(proof["unit"]["Result"], "success");
        assert_eq!(proof["events"].as_array().unwrap().len(), 2);
        p.producer_invocation_id = "0".repeat(32);
        assert!(terminal(&p).is_err());
    }
    #[test]
    #[ignore = "root native publication receipt and source validation; no canonical archive"]
    fn native_publisher_receipt_passes_source_handoff_and_replacement_fails() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let private = |name: &str| {
            let p = root.join(name);
            fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&p)
                .unwrap();
            p
        };
        let staging = private("staging");
        let output = private("output");
        let public = private("public");
        let m = fs::metadata(&output).unwrap();
        let receipts = private(&format!(
            "archive-batches/destination-{:016x}-{:016x}",
            m.dev(),
            m.ino()
        ));
        let staged = staging.join("epoch-247.jet");
        fs::write(&staged, b"synthetic metadata qualification only").unwrap();
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o440)).unwrap();
        let evidence =
            jetstreamer_node::archive_checksum::measure_open_archive(&File::open(&staged).unwrap())
                .unwrap();
        let item = jetstreamer_node::archive_publish::ArchiveBatchItem {
            epoch: 247,
            staged_archive: staged,
            destination_archive: output.join("epoch-247.jet"),
            evidence,
        };
        let summary = |slot| cohort::RootCheckpointSummary {
            slot,
            bank_hash: [1; 32],
            accounts_hash: [2; 32],
            last_blockhash: [3; 32],
            capitalization: 1,
            transaction_count: 2,
            tick_height: 3,
            slot_complete: true,
            write_count: 4,
            next_write_version: 5,
        };
        let gate = cohort::RootCheckpointGateEvidence {
            kind: cohort::ROOT_CHECKPOINT_GATE_KIND.into(),
            version: 1,
            verified_manifest_checkpoints: vec![cohort::VerifiedManifestCheckpoint {
                slot: 107135393,
                accounts_hash: [2; 32],
            }],
            members: vec![cohort::RootCheckpointGateMember {
                epoch: 247,
                bootstrap: summary(106703614),
                terminal: summary(107135999),
            }],
        };
        let fingerprint = [0x24; 32];
        let context =
            cohort::encode_root_checkpoint_gate_context(fingerprint, &[247], &gate).unwrap();
        let publication =
            jetstreamer_node::archive_publish::publish_verified_archive_batch_with_context(
                fingerprint,
                &[247],
                std::slice::from_ref(&item),
                &context,
            )
            .unwrap();
        cohort::finish_root_checkpoint_publication(
            cohort::DestinationBinding {
                path: &output,
                device: m.dev(),
                inode: m.ino(),
            },
            &receipts,
            fingerprint,
            &[cohort::ExpectedCohortArchive {
                epoch: 247,
                destination_archive: &item.destination_archive,
                sha256: item.evidence.sha256,
            }],
            &publication,
            &gate,
        )
        .unwrap();
        let expectation = root.join("expectation.json");
        let expected=serde_json::to_vec(&json!({"terminal_slot":107135999,"terminal_blockhash":bs58::encode([3;32]).into_string()})).unwrap();
        fs::write(&expectation, &expected).unwrap();
        let (mut p, _, _) = fixture();
        p.source_uid = 0;
        p.source_gid = m.gid();
        p.output_directory = output.clone();
        p.output_device = m.dev();
        p.output_inode = m.ino();
        p.public_directory = public;
        p.batch_receipt_directory = receipts;
        p.epoch_expectation = Bound {
            path: expectation,
            sha256: sha(&expected),
        };
        let manifest = json!({"manifest_fingerprint":format!("sha256:{}",jetstreamer_node::segment_manifest::sha256_hex_string(&fingerprint)),
            "manifest":{"epochs":[{"bootstrap":{"slot":106703614,"accounts_hash":bs58::encode([2;32]).into_string()},
                "post_bootstrap_root_checkpoints":[{"slot":107135393,"accounts_hash":bs58::encode([2;32]).into_string()}]}]}});
        let proof = source(&p, &manifest).unwrap();
        assert_eq!(proof["archive_body_verified"], false);
        assert_eq!(
            proof["archive"]["identity"]["inode"],
            fs::metadata(&item.destination_archive).unwrap().ino()
        );
        let mut wrong = manifest.clone();
        wrong["manifest"]["epochs"][0]["post_bootstrap_root_checkpoints"][0]["slot"] =
            json!(107135392);
        assert!(source(&p, &wrong).is_err());
        fs::remove_file(&item.destination_archive).unwrap();
        fs::write(&item.destination_archive, b"replacement").unwrap();
        fs::set_permissions(&item.destination_archive, fs::Permissions::from_mode(0o440)).unwrap();
        assert!(source(&p, &manifest).is_err());
    }
    fn fixture() -> (Plan, BTreeMap<String, String>, Vec<Value>) {
        let p = Plan {
            schema: "horizon-singleton-delivery-handoff-plan-v1".into(),
            epoch: 247,
            producer_unit: "horizon-qualify-247-native.service".into(),
            producer_invocation_id: "a".repeat(32),
            expected_exec_prefix: "{ path=/native ; argv[]=/native".into(),
            startup_handoff: Bound {
                path: "/startup".into(),
                sha256: "b".repeat(64),
            },
            manifest: Bound {
                path: "/manifest".into(),
                sha256: "c".repeat(64),
            },
            epoch_expectation: Bound {
                path: "/expectation".into(),
                sha256: "d".repeat(64),
            },
            output_directory: "/source".into(),
            output_device: 1,
            output_inode: 2,
            source_uid: 1000,
            source_gid: 1000,
            batch_receipt_directory: "/batches".into(),
            public_directory: "/target".into(),
            receipt_directory: "/receipt".into(),
        };
        let u = BTreeMap::from_iter(
            [
                ("Id", p.producer_unit.clone()),
                ("LoadState", "loaded".into()),
                ("ActiveState", "inactive".into()),
                ("SubState", "dead".into()),
                ("MainPID", "0".into()),
                ("NRestarts", "0".into()),
                ("Result", "success".into()),
                ("ExecMainCode", "1".into()),
                ("ExecMainStatus", "0".into()),
                ("InvocationID", p.producer_invocation_id.clone()),
                (
                    "ExecStart",
                    format!(
                        "{} ; ignore_errors=no ; status=0/0 }}",
                        p.expected_exec_prefix
                    ),
                ),
            ]
            .map(|(k, v)| (k.to_owned(), v)),
        );
        let rows = vec![
            json!({"_PID":"1","_UID":"0","UNIT":p.producer_unit,"INVOCATION_ID":p.producer_invocation_id,
                "MESSAGE":format!("Started {} - native.",p.producer_unit),"__REALTIME_TIMESTAMP":"1"}),
            json!({"_PID":"1","_UID":"0","UNIT":p.producer_unit,"INVOCATION_ID":p.producer_invocation_id,
                "MESSAGE":format!("{}: Deactivated successfully.",p.producer_unit),"__REALTIME_TIMESTAMP":"2"}),
        ];
        (p, u, rows)
    }
    #[test]
    fn terminal_rejects_live_failed_restarted_replaced_or_different_command() {
        let (p, u, rows) = fixture();
        terminal_values(&p, &u, &rows).unwrap();
        for (k, v) in [
            ("ActiveState", "active"),
            ("MainPID", "42"),
            ("NRestarts", "1"),
            ("Result", "exit-code"),
            ("ExecMainCode", "2"),
            ("ExecMainStatus", "1"),
            ("InvocationID", "other"),
            ("ExecStart", "different"),
        ] {
            let mut wrong = u.clone();
            wrong.insert(k.into(), v.into());
            assert!(terminal_values(&p, &wrong, &rows).is_err(), "{k}");
        }
    }
    #[test]
    fn terminal_requires_unambiguous_ordered_pid1_events() {
        let (p, u, rows) = fixture();
        assert!(terminal_values(&p, &u, &rows[..1]).is_err());
        for (k, v) in [
            ("_PID", "42"),
            ("_UID", "1000"),
            ("INVOCATION_ID", "other"),
            ("__REALTIME_TIMESTAMP", "0"),
        ] {
            let mut wrong = rows.clone();
            wrong[1][k] = json!(v);
            assert!(terminal_values(&p, &u, &wrong).is_err(), "{k}");
        }
        let mut duplicate = rows.clone();
        duplicate.push(rows[1].clone());
        assert!(terminal_values(&p, &u, &duplicate).is_err());
        let mut replacement = rows.clone();
        let mut row = rows[0].clone();
        row["INVOCATION_ID"] = json!("b".repeat(32));
        row["__REALTIME_TIMESTAMP"] = json!("3");
        replacement.push(row);
        assert!(terminal_values(&p, &u, &replacement).is_err());
    }
    #[test]
    fn manifest_must_cover_exactly_the_claimed_singleton() {
        let (p, _, _) = fixture();
        let v = json!({"manifest_fingerprint":format!("sha256:{}","a".repeat(64)),
            "manifest":{"first_epoch":247,"last_epoch":247,"publication_boundary_epoch":247,
                "epoch_slots":432000,"epochs":[{"epoch":247}]}});
        validate_manifest(&p, &v).unwrap();
        for key in [
            "first_epoch",
            "last_epoch",
            "publication_boundary_epoch",
            "epoch_slots",
        ] {
            let mut wrong = v.clone();
            wrong["manifest"][key] = json!(248);
            assert!(validate_manifest(&p, &wrong).is_err());
        }
        let mut wrong = v;
        wrong["manifest"]["epochs"] = json!([{"epoch":247},{"epoch":248}]);
        assert!(validate_manifest(&p, &wrong).is_err());
    }
}
