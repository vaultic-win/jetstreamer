//! Read-only qualification of one stopped epoch166 partial for potential holding.
//! No retirement, canonical publication, resource credit or replay authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";

struct Attempt {
    number: u8,
    run: &'static str,
    receipts: &'static str,
    completion_sha: &'static str,
    intent_sha: &'static str,
    invocation: &'static str,
    pid: u64,
    length: u64,
    blocks: u64,
    inode: u64,
}

const RETRY7: Attempt = Attempt {
    number: 7,
    pid: 1450368,
    invocation: "03fa3ce80d8c4769a1e9dec548cdbeca",
    run: "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/private/destination-2d43fd7f2cb337f324aafbe7404d605eca42c04a38fb91405c81cf8e62022c9b/work/root-cohort-166-166/run-1450368-1795028473959689559",
    receipts: "/var/lib/jetstreamer/retry7-preparation-20261118-v1/epoch166/local3retry7/guard-state-recovery-v2/receipts",
    intent_sha: "68ca26b67441deed9931c84b08d864aadf252613662fac65ee91711df9f1d97d",
    completion_sha: "846c5f57fa2600a1aec5ee9ac0d3a32590b97d6982a66cc5db091f2fadda390e",
    length: 13_817_409_670,
    blocks: 26_987_184,
    inode: 104_071_284,
};

const RETRY8: Attempt = Attempt {
    number: 8,
    pid: 1746683,
    invocation: "4f09db5f45074244a45b06aeef932d1d",
    run: "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1/private/destination-f5ca2c2ad058437c08aaf6b1f7ce14a26791e7ff9d9fb375ce654c014d85a2c3/work/root-cohort-166-166/run-1746683-1795053006864315025",
    receipts: "/var/lib/jetstreamer/retry8-preparation-20261119-v1/epoch166/local3retry8/guard-state-recovery-v2/receipts",
    intent_sha: "f663f933ec2ceba6ed27c9d863a126a23027b16f9bd2d40c4074cae2a61e496c",
    completion_sha: "b99e26a6836609dc68b4c646eb19ce2b2c0edd0d7547c80b1e0b517be4875b08",
    length: 55_516_564_111,
    blocks: 108_430_936,
    inode: 106_109_795,
};

fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.blocks(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn closed(attempt: &Attempt) -> Result<Value> {
    let mut evidence = Vec::new();
    let number = attempt.number;
    for unit in [
        format!("horizon-qualify-166-replacement-local3retry{number}-20261110-v1.service"),
        format!("horizon-guard-replacement-166-local3retry{number}-20261110-v1.service"),
        format!("horizon-guard-replacement-166-local3retry{number}-20261110-v1.timer"),
    ] {
        let result = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                unit.as_str(),
                "-pId,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID",
            ])
            .output()?;
        ensure!(
            result.status.success() && result.stderr.is_empty(),
            "native unit query failed"
        );
        let s = String::from_utf8(result.stdout)?;
        let mut fields = serde_json::Map::new();
        for line in s.lines() {
            let (key, value) = line.split_once('=').context("unit field")?;
            ensure!(
                fields.insert(key.into(), json!(value)).is_none(),
                "duplicate field"
            );
        }
        let v = Value::Object(fields);
        ensure!(
            v["Id"] == unit
                && (!unit.starts_with("horizon-qualify-")
                    || v["InvocationID"] == ""
                    || v["InvocationID"] == attempt.invocation)
                && v["ActiveState"] == "inactive"
                && v["SubState"] == "dead"
                && v["Job"] == ""
                && (v["MainPID"].is_null() || v["MainPID"] == "0")
                && (v["ControlPID"].is_null() || v["ControlPID"] == "0"),
            "owner is not closed: {unit}"
        );
        evidence.push(v);
    }
    Ok(json!(evidence))
}
fn references(attempt: &Attempt) -> Result<Value> {
    let processes = jetstreamer_horizon_observe::process_references::scan(
        Path::new("/proc"),
        Path::new(attempt.run),
    )?;
    let staged = jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(
        Path::new(attempt.run),
    )?;
    Ok(json!({"processes":processes,"staged":staged}))
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4 && args[2] == "--self-sha256",
        "usage: retry7|retry8 --self-sha256 HEX"
    );
    let image = fs::read("/proc/self/exe")?;
    ensure!(
        format!("{:x}", Sha256::digest(image)) == args[3],
        "inspector image changed"
    );
    let attempt = match args[1].as_str() {
        "retry7" => &RETRY7,
        "retry8" => &RETRY8,
        _ => anyhow::bail!("unknown predecessor"),
    };
    let base = Path::new(BASE);
    let parent_dir = base.join(format!(
        "epoch166-retry{}-prefix-inspection-20261120-v1",
        attempt.number
    ));

    ensure!(
        fs::metadata(base)?.dev() == fs::metadata("/home/sol")?.dev(),
        "HOME backing required"
    );
    let stop = stop_proof(attempt)?;
    let parent_md = fs::symlink_metadata(&parent_dir)?;
    ensure!(
        parent_md.is_dir()
            && parent_md.uid() == 0
            && parent_md.mode() & 0o7777 == 0o700
            && parent_dir.canonicalize()? == parent_dir
            && parent_md.dev() == fs::metadata(base)?.dev(),
        "private root-owned HOME receipt parent required"
    );
    let evidence_dir = tempfile::Builder::new()
        .prefix("review-")
        .tempdir_in(&parent_dir)?
        .keep();
    let parent = evidence_dir.as_path();
    let output = parent.join("INSPECTION.json");
    let path = Path::new(attempt.run).join("archives/epoch-166.jet");
    ensure!(path.canonicalize()? == path, "canonical source required");
    let before = fs::symlink_metadata(&path)?;
    ensure!(
        before.is_file()
            && before.dev() == 64512
            && before.ino() == attempt.inode
            && before.len() == attempt.length
            && before.blocks() == attempt.blocks
            && before.uid() == 1001
            && before.gid() == 1003
            && before.mode() & 0o7777 == 0o600
            && before.nlink() == 1,
        "exact source identity changed"
    );
    match fs::symlink_metadata(path.with_extension("jet.sha256")) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
        Ok(_) => anyhow::bail!("unexpected readiness sidecar"),
        Err(err) => return Err(err.into()),
    }
    let closed_before = closed(attempt)?;
    let refs_before = references(attempt)?;
    // Preserve negative consumer findings too; do not hash an actively used candidate.
    let clean = refs_before["processes"]["references"] == json!([])
        && refs_before["staged"]["references"] == json!([]);
    let mut digest = None;
    if clean {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        ensure!(
            identity(&file.metadata()?) == identity(&before),
            "source changed before hash"
        );
        let mut hash = Sha256::new();
        let mut buffer = vec![0; 1 << 20];
        let mut total = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total = total.checked_add(n as u64).context("length overflow")?;
            ensure!(total <= attempt.length, "source grew");
            hash.update(&buffer[..n]);
        }
        ensure!(
            total == attempt.length && identity(&file.metadata()?) == identity(&before),
            "source changed while hashing"
        );
        digest = Some(format!("{:x}", hash.finalize()));
    }
    let closed_after = closed(attempt)?;
    let refs_after = references(attempt)?;
    ensure!(
        closed_before == closed_after
            && identity(&fs::symlink_metadata(&path)?) == identity(&before),
        "candidate changed"
    );
    let clear_after = refs_after["processes"]["references"] == json!([])
        && refs_after["staged"]["references"] == json!([]);
    let evidence = json!({"schema":"horizon-epoch166-stopped-prefix-inspection-v1", "attempt":attempt.number,"stopped_producer":stop,"inspector_sha256":args[3],
        "owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "source":path,"source_identity":identity(&before),"length":attempt.length,"sha256":digest,
        "source_stable":true,"native_owners":closed_after,"references_before":refs_before,"references_after":refs_after,
        "native_consumers_clear":clean&&clear_after,"complete_transitive_consumer_graph_qualified":false,
        "holding_custody_exists":false,"local_retirement_authorized":false,"canonical_publication_authorized":false,
        "replay_launch_authorized":false,"resource_credit_bytes":0,"remote_mutations":false});
    let inspection = save(&output, &evidence)?;
    ensure!(
        clean && clear_after,
        "closed prefix has process or staged readers; see inspection"
    );
    let sha = digest.context("clean inspection missing archive digest")?;
    ensure!(
        bound(Path::new(MAPPING), MAPPING_SHA)?.is_object(),
        "invalid host mapping"
    );
    let dest = base.join(format!(
        "epoch166-retry{}-prefix-sealed-20261120-v1",
        attempt.number
    ));
    let eligibility = save(
        &parent.join("eligibility.json"),
        &json!({
            "schema":"jetstreamer-horizon-holding-eligibility-v2","host":"dev-samjohnson",
            "source":path,"length":attempt.length,"sha256":sha,"closed":true,
            "content_class":"public-chain-artifact","credentials_config_and_logs_excluded":true,
            "canonical_archive":false,"local_retirement_authorized":false,"inspection":inspection,
            "purpose":"Retain stopped public-chain partial for capacity recovery of epoch 166 retry9",
            "resource_credit_bytes":0,"restore_overlap_bytes":attempt.length,
            "runtime_checkpoint_qualified":false,"complete_transitive_consumer_graph_qualified":false
        }),
    )?;
    let plan = save(
        &parent.join("plan.json"),
        &json!({
            "schema":"jetstreamer-horizon-holding-park-plan-v2","source":path,"length":attempt.length,"sha256":sha,
            "mapping":{"path":MAPPING,"sha256":MAPPING_SHA},
            "eligibility":{"path":dest.join("eligibility.json"),"sha256":eligibility["sha256"]}
        }),
    )?;
    let members: Vec<_> = [("eligibility.json", eligibility), ("plan.json", plan)]
        .into_iter()
        .map(|(name, b)| json!({"name":name,"source":b["path"],"sha256":b["sha256"],"mode":292}))
        .collect();
    let seal = save(
        &parent.join("seal-plan.json"),
        &json!({
            "schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":members
        }),
    )?;
    println!(
        "{}",
        json!({"inspection":inspection,"seal_plan":seal,"remote_mutations":false,"local_retirement_authorized":false})
    );
    Ok(())
}

fn bound(path: &Path, expected: &str) -> Result<Value> {
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.nlink() == 1
            && md.mode() & 0o022 == 0
            && path.canonicalize()? == path
            && md.len() < 2 << 20,
        "invalid evidence {}",
        path.display()
    );
    let raw = fs::read(path)?;
    ensure!(
        format!("{:x}", Sha256::digest(&raw)) == expected,
        "evidence changed {}",
        path.display()
    );
    Ok(serde_json::from_slice(&raw)?)
}
fn stop_proof(a: &Attempt) -> Result<Value> {
    let dir = Path::new(a.receipts);
    let ip = dir.join("stop-intent.json");
    let cp = dir.join("stop-completion.json");
    let i = bound(&ip, a.intent_sha)?;
    let c = bound(&cp, a.completion_sha)?;
    validate_stop(a, &ip, &i, &c)?;
    Ok(
        json!({"intent":{"path":ip,"sha256":a.intent_sha},"completion":{"path":cp,"sha256":a.completion_sha},"invocation_id":a.invocation,"pid":a.pid}),
    )
}
fn validate_stop(a: &Attempt, ip: &Path, i: &Value, c: &Value) -> Result<()> {
    ensure!(
        i["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && c["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && i["reason"] == "DATA-fulfillment-observation-failed"
            && i["producer_invocation_id"] == a.invocation
            && i["sample"]["producer"]["pid"] == a.pid
            && i["sample"]["producer"]["invocation_id"] == a.invocation
            && c["producer_invocation_id"] == a.invocation
            && c["intent"] == ip.to_str().context("intent path")?
            && c["plan_sha256"] == i["plan_sha256"]
            && c["terminal"]["invocation_id"] == a.invocation
            && c["terminal"]["active"] == "inactive"
            && c["terminal"]["sub"] == "dead"
            && c["terminal"]["pid"] == 0
            && c["terminal"]["restarts"] == 0
            && c["r2_mutations"] == false
            && c["remote_mutations"] == false
            && c["scratch_deleted"] == false,
        "terminal stop evidence does not bind this producer"
    );
    Ok(())
}
fn save(output: &Path, value: &Value) -> Result<Value> {
    let parent = output.parent().context("receipt parent")?;
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(json!({"path":output,"sha256":format!("{:x}",Sha256::digest(&bytes))}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentic_stops_bind_their_own_producers_only() {
        for attempt in [&RETRY7, &RETRY8] {
            let receipts = Path::new(attempt.receipts);
            let ip = receipts.join("stop-intent.json");
            let intent = bound(&ip, attempt.intent_sha).unwrap();
            let mut completion = bound(
                &receipts.join("stop-completion.json"),
                attempt.completion_sha,
            )
            .unwrap();
            validate_stop(attempt, &ip, &intent, &completion).unwrap();
            let other = if attempt.number == 7 {
                &RETRY8
            } else {
                &RETRY7
            };
            assert!(validate_stop(other, &ip, &intent, &completion).is_err());
            completion["terminal"]["pid"] = json!(1);
            assert!(validate_stop(attempt, &ip, &intent, &completion).is_err());
        }
    }
}
