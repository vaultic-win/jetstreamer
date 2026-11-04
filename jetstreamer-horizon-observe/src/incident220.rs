//! Read-only primary-source capture of the exact failed 220--223 cohort.
//! Checkpoints are observations, not reconstructed manifests or publication gates.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const PRODUCER: &str =
    "jetstreamer-root-sweep-horizon-220-223-current-v1-e220-223-lane-a-1.service";
const IID: &str = "c2adebaad0cb42b385156631156813fe";
const CONTROLLER: &str = "horizon-controller-220-223-current-v1.service";
const CONTROLLER_IID: &str = "0b69b5009dc74bbda94b94d059a3daa7";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-contiguous-220-223-current-9d8e964-v1";
const MANIFEST: &str = "preflight-220-223-target4-9d8e964.json";
const MANIFEST_SHA: &str = "c9299a857367f80bdf18d545909c8c25853add54170cfb10620b31cabd2c1727";
const NODE_SHA: &str = "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1";
const FINGERPRINT: &str = "sha256:155907db8b743b54af2746d949893cad0c299cda3ad8900017420bc06ff9de42";
const ERROR: &str = "horizon: post-orphan update failed at slot 96540992: archive post-transaction account updates is too large: 16385 bytes (limit 16384)";
const PATTERN: &str = "historical checkpoint slot=|horizon archive complete:|root-checkpoint cohort retained validated epoch|post-orphan update failed at slot";
const MAX_CAPTURE: u64 = 128 * 1024;

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn stable(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= limit,
        "unsafe input"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        bytes.len() as u64 == before.len()
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "input changed"
    );
    Ok(bytes)
}

fn unit(name: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl").args(["show", name, "--no-pager", "--property=Id,LoadState,ActiveState,SubState,InvocationID,NRestarts,MainPID,Result,ExecMainStatus"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 65536,
        "unit probe failed"
    );
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("unit field")?;
        ensure!(fields.insert(key, value).is_none(), "duplicate unit field");
    }
    Ok(serde_json::to_value(fields)?)
}

fn terminal(controller: &Value, producer: &Value) -> Result<()> {
    for (state, name, invocation, active, sub, result, code) in [
        (
            controller,
            CONTROLLER,
            CONTROLLER_IID,
            "inactive",
            "dead",
            "success",
            "0",
        ),
        (
            producer,
            PRODUCER,
            IID,
            "failed",
            "failed",
            "exit-code",
            "1",
        ),
    ] {
        ensure!(
            state["Id"] == name
                && state["LoadState"] == "loaded"
                && state["InvocationID"] == invocation
                && state["ActiveState"] == active
                && state["SubState"] == sub
                && state["Result"] == result
                && state["ExecMainStatus"] == code
                && state["MainPID"] == "0"
                && state["NRestarts"] == "0",
            "original owner live, replaced, collected or ambiguous"
        );
    }
    Ok(())
}

fn fields(message: &str, marker: &str) -> Result<BTreeMap<String, String>> {
    let (_, tail) = message
        .split_once(marker)
        .context("missing message marker")?;
    let mut values = BTreeMap::new();
    for field in tail.split_whitespace() {
        let (key, value) = field
            .split_once('=')
            .context("malformed checkpoint field")?;
        ensure!(
            values.insert(key.to_owned(), value.to_owned()).is_none(),
            "duplicate checkpoint field"
        );
    }
    Ok(values)
}

fn extract(records: &[Value], manifest: &Value) -> Result<Value> {
    ensure!(
        manifest["manifest_fingerprint"] == FINGERPRINT,
        "foreign manifest"
    );
    let mut checkpoints = BTreeMap::new();
    let mut closes = Vec::new();
    let mut retained = Vec::new();
    let mut failure_time = None;
    let mut cursors = BTreeSet::new();
    let mut previous_time = 0;
    for record in records {
        ensure!(
            record["_SYSTEMD_UNIT"] == PRODUCER
                && record["_SYSTEMD_INVOCATION_ID"] == IID
                && record["_UID"] == "1000"
                && record["_PID"] == "2161856"
                && record["_EXE"] == format!("{PACKAGE}/jetstreamer-node"),
            "foreign primary-source record"
        );
        let timestamp: u64 = record["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("journal time")?
            .parse()?;
        let cursor = record["__CURSOR"].as_str().context("journal cursor")?;
        ensure!(
            timestamp > previous_time && !cursor.is_empty() && cursors.insert(cursor),
            "duplicate or unordered primary records"
        );
        previous_time = timestamp;
        let message = record["MESSAGE"].as_str().context("journal message")?;
        if message.contains("historical checkpoint slot=") {
            let values = fields(message, "historical checkpoint ")?;
            ensure!(
                values.len() == 10 && values.get("complete").is_some_and(|v| v == "true"),
                "incomplete checkpoint tuple"
            );
            for key in [
                "slot",
                "capitalization",
                "transactions",
                "tick_height",
                "writes",
                "next_write_version",
            ] {
                let value = values
                    .get(key)
                    .context("missing numeric checkpoint field")?;
                ensure!(
                    value.parse::<u64>()?.to_string() == *value,
                    "noncanonical checkpoint integer"
                );
            }
            for key in ["bank_hash", "accounts_hash", "last_blockhash"] {
                let value = values.get(key).context("missing checkpoint hash")?;
                ensure!(
                    !value.is_empty()
                        && value.len() <= 44
                        && value.bytes().all(|b| b.is_ascii_alphanumeric()),
                    "malformed checkpoint hash"
                );
            }
            let slot: u64 = values["slot"].parse()?;
            ensure!(checkpoints.insert(slot, json!({"fields":values,"timestamp_micros":timestamp,"journal_cursor":cursor,"message":message})).is_none(), "duplicate checkpoint slot");
        } else if message.contains("horizon archive complete:") {
            closes.push((timestamp, message));
        } else if message.contains("root-checkpoint cohort retained validated epoch") {
            retained.push((timestamp, message));
        } else {
            ensure!(
                message == ERROR && failure_time.replace(timestamp).is_none(),
                "unexpected or duplicate failure"
            );
        }
    }
    ensure!(
        checkpoints.len() == 7
            && closes.len() == 3
            && retained.len() == 3
            && failure_time.is_some(),
        "incomplete failed-prefix census"
    );
    let bootstrap = checkpoints.get(&95039516).context("missing bootstrap")?;
    ensure!(
        bootstrap["fields"]["accounts_hash"] == "9TaEWfKXJYo2a5UYx3HuE72aGa8FVXJzHCVzQjvF6HDG"
            && bootstrap["fields"]["writes"] == "0",
        "foreign bootstrap"
    );
    let epochs = manifest["manifest"]["epochs"]
        .as_array()
        .context("manifest epochs")?;
    let mut prefix = Vec::new();
    let mut prior_time = bootstrap["timestamp_micros"].as_u64().unwrap();
    for (index, epoch) in (220..=222u64).enumerate() {
        let bound: Vec<_> = epochs.iter().filter(|e| e["epoch"] == epoch).collect();
        ensure!(bound.len() == 1, "missing or duplicated manifest epoch");
        let roots = bound[0]["post_bootstrap_root_checkpoints"]
            .as_array()
            .context("manifest roots")?;
        ensure!(roots.len() == 1, "foreign checkpoint scope");
        let slot = roots[0]["slot"].as_u64().context("manifest root slot")?;
        let root = checkpoints
            .get(&slot)
            .context("missing trusted root observation")?;
        let terminal = checkpoints
            .get(&((epoch + 1) * 432000 - 1))
            .context("missing terminal observation")?;
        ensure!(
            root["fields"]["accounts_hash"] == roots[0]["accounts_hash"],
            "root accounts hash disagrees with sealed source"
        );
        let root_time = root["timestamp_micros"].as_u64().unwrap();
        let terminal_time = terminal["timestamp_micros"].as_u64().unwrap();
        ensure!(
            prior_time < root_time
                && root_time < terminal_time
                && terminal_time < closes[index].0
                && closes[index].0 < retained[index].0,
            "prefix stage ordering differs"
        );
        ensure!(
            closes[index].1.contains("slots=432000 ")
                && retained[index].1.contains(&format!(
                    "retained validated epoch {epoch} privately; publication remains closed"
                )),
            "wrong closed-archive epoch/coverage"
        );
        prefix.push(json!({"epoch":epoch,"manifest_root":roots[0],"observed_root":root,"terminal":terminal,"archive_complete_message":closes[index].1,"retained_validation_message":retained[index].1}));
        prior_time = retained[index].0;
    }
    ensure!(
        prior_time < failure_time.unwrap(),
        "failure preceded completed prefix"
    );
    Ok(
        json!({"bootstrap":bootstrap,"complete_prefix":prefix,"failed_slot":96540992,"failure_message":ERROR,"failure_timestamp_micros":failure_time}),
    )
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 4 && args[2] == "--self-sha256",
        "usage: OUTPUT --self-sha256 HEX (root)"
    );
    ensure!(
        sha(&stable(
            Path::new("/proc/self/exe").canonicalize()?.as_path(),
            128 << 20
        )?) == args[3],
        "collector digest differs"
    );
    let output = PathBuf::from(&args[1]);
    let parent = output.parent().context("output parent")?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        output.is_absolute()
            && parent.canonicalize()? == parent
            && meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o077 == 0
            && !output.try_exists()?,
        "unsafe or occupied output"
    );
    let manifest_path = Path::new(PACKAGE).join(MANIFEST);
    let manifest_bytes = stable(&manifest_path, 1 << 20)?;
    ensure!(
        sha(&manifest_bytes) == MANIFEST_SHA
            && sha(&stable(
                &Path::new(PACKAGE).join("jetstreamer-node"),
                128 << 20
            )?) == NODE_SHA,
        "original immutable inputs differ"
    );
    let controller = unit(CONTROLLER)?;
    let producer = unit(PRODUCER)?;
    terminal(&controller, &producer)?;
    let mut child = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "-o",
            "json",
            "--since=2026-10-14 17:17:24 UTC",
            "--until=2026-10-21 17:48:23 UTC",
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
            &format!("--grep={PATTERN}"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .context("missing journal stdout")?
        .take(MAX_CAPTURE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CAPTURE {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("filtered journal exceeds bound");
    }
    ensure!(child.wait()?.success(), "journal capture failed");
    let text = std::str::from_utf8(&bytes)?;
    let records: Vec<Value> = text
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let extracted = extract(&records, &serde_json::from_slice(&manifest_bytes)?)?;
    ensure!(
        controller == unit(CONTROLLER)?
            && producer == unit(PRODUCER)?
            && manifest_bytes == stable(&manifest_path, 1 << 20)?,
        "terminal/input race"
    );
    let receipt = json!({"schema":"jetstreamer-epoch220-complete-prefix-primary-evidence-v1","collector_sha256":args[3],"producer":producer,"controller":controller,"manifest_path":manifest_path,"manifest_sha256":MANIFEST_SHA,"node_sha256":NODE_SHA,"journal_raw_utf8":text,"journal_sha256":sha(&bytes),"journal_records":records.len(),"extracted":extracted,"resource_samples":0,"recovery_manifest_created":false,"archive_mutations":false,"service_mutations":false,"replay_launch_authorized":false,"publication_authorized":false,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&output)?;
    serde_json::to_writer_pretty(&mut file, &receipt)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("complete-prefix evidence capture failed closed: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<Value>, Value) {
        let hash = "9TaEWfKXJYo2a5UYx3HuE72aGa8FVXJzHCVzQjvF6HDG";
        let checkpoint = |slot, writes| {
            format!(
                "historical checkpoint slot={slot} bank_hash={hash} accounts_hash={hash} last_blockhash={hash} capitalization=1 transactions=1 tick_height=1 complete=true writes={writes} next_write_version=1"
            )
        };
        let mut messages = vec![checkpoint(95039516, 0)];
        let mut epochs = Vec::new();
        for (epoch, root) in [(220, 95471337), (221, 95903534), (222, 96335538)] {
            messages.extend([
                checkpoint(root, 1),
                checkpoint((epoch + 1) * 432000 - 1, 1),
                "horizon archive complete: slots=432000 blocks=1".into(),
                format!("root-checkpoint cohort retained validated epoch {epoch} privately; publication remains closed"),
            ]);
            epochs.push(json!({"epoch":epoch,"post_bootstrap_root_checkpoints":[{"slot":root,"accounts_hash":hash}]}));
        }
        messages.push(ERROR.into());
        let records = messages.into_iter().enumerate().map(|(index, message)| json!({
            "MESSAGE":message,"_SYSTEMD_UNIT":PRODUCER,"_SYSTEMD_INVOCATION_ID":IID,
            "_UID":"1000","_PID":"2161856","_EXE":format!("{PACKAGE}/jetstreamer-node"),
            "__REALTIME_TIMESTAMP":(index+1).to_string(),"__CURSOR":format!("cursor-{index}")
        })).collect();
        (
            records,
            json!({"manifest_fingerprint":FINGERPRINT,"manifest":{"epochs":epochs}}),
        )
    }

    #[test]
    fn complete_primary_prefix_is_extracted_without_creating_recovery_authority() {
        let (records, manifest) = fixture();
        let result = extract(&records, &manifest).unwrap();
        assert_eq!(result["complete_prefix"].as_array().unwrap().len(), 3);
        assert_eq!(result["complete_prefix"][2]["epoch"], 222);
        assert_eq!(result["failed_slot"], 96540992);
        assert!(result.get("publication_authorized").is_none());
    }

    #[test]
    fn prefix_requires_exact_origin_unique_records_and_sealed_root_hashes() {
        let (records, manifest) = fixture();
        for (key, value) in [
            ("_SYSTEMD_INVOCATION_ID", json!("a".repeat(32))),
            ("_SYSTEMD_UNIT", json!("another.service")),
            ("_PID", json!("2161857")),
            ("_UID", json!("0")),
            ("_EXE", json!("/tmp/node")),
            ("__CURSOR", records[0]["__CURSOR"].clone()),
            (
                "__REALTIME_TIMESTAMP",
                records[0]["__REALTIME_TIMESTAMP"].clone(),
            ),
        ] {
            let mut bad = records.clone();
            bad[1][key] = value;
            assert!(extract(&bad, &manifest).is_err(), "accepted {key}");
        }
        let mut bad = manifest.clone();
        bad["manifest"]["epochs"][1]["post_bootstrap_root_checkpoints"][0]["accounts_hash"] =
            json!("other");
        assert!(extract(&records, &bad).is_err());
        let mut bad = records.clone();
        bad.remove(6);
        assert!(extract(&bad, &manifest).is_err());
        let mut bad = records.clone();
        bad[2]["MESSAGE"] = records[1]["MESSAGE"].clone();
        assert!(extract(&bad, &manifest).is_err());
        let mut bad = records.clone();
        bad[2]["MESSAGE"] = json!(
            records[2]["MESSAGE"]
                .as_str()
                .unwrap()
                .replace("complete=true", "complete=false")
        );
        assert!(extract(&bad, &manifest).is_err());
        let mut bad = records.clone();
        bad[3]["MESSAGE"] = json!("horizon archive complete: slots=431999 blocks=1");
        assert!(extract(&bad, &manifest).is_err());
        assert!(extract(&records[..records.len() - 1], &manifest).is_err());
    }

    #[test]
    fn tuple_parser_rejects_duplicate_and_missing_markers() {
        assert!(
            fields(
                "historical checkpoint slot=1 slot=2",
                "historical checkpoint "
            )
            .is_err()
        );
        assert!(fields("not a checkpoint", "historical checkpoint ").is_err());
    }

    #[test]
    fn collected_or_live_owners_are_not_terminal_evidence() {
        assert!(terminal(&json!({}), &json!({})).is_err());
        let state = |name, iid, active, sub, result, code| json!({"Id":name,"LoadState":"loaded","InvocationID":iid,"ActiveState":active,"SubState":sub,"Result":result,"ExecMainStatus":code,"MainPID":"0","NRestarts":"0"});
        let controller = state(
            CONTROLLER,
            CONTROLLER_IID,
            "inactive",
            "dead",
            "success",
            "0",
        );
        let producer = state(PRODUCER, IID, "failed", "failed", "exit-code", "1");
        terminal(&controller, &producer).unwrap();
        let mut replaced = producer.clone();
        replaced["InvocationID"] = json!("a".repeat(32));
        assert!(terminal(&controller, &replaced).is_err());
        let mut live = controller.clone();
        live["ActiveState"] = json!("active");
        assert!(terminal(&live, &producer).is_err());
    }

    #[test]
    fn incomplete_journal_cannot_become_a_prefix_receipt() {
        assert!(extract(&[], &json!({"manifest_fingerprint":FINGERPRINT})).is_err());
        assert!(
            extract(
                &[json!({"MESSAGE":ERROR})],
                &json!({"manifest_fingerprint":FINGERPRINT})
            )
            .is_err()
        );
    }
}
