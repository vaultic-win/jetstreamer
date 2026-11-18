//! Exact closed epoch 141 compressed input retirement after holding custody.
//! No canonical archive, publication or replay authority is derived here.
use super::*;
use serde_json::json;

const SOURCE: &str =
    "/home/sol/.jetstreamer-private/epoch141-ledger-source-20261020-v1/download/rocksdb.tar.bz2";
const SHA: &str = "7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b";
const LENGTH: u64 = 189_943_475_031;
const ALLOCATED: u64 = 189_943_668_736;
const ELIGIBILITY: &str =
    "/usr/local/lib/jetstreamer/horizon-closed141-input-holding-plan-20261118-v1/eligibility.json";
const ELIGIBILITY_SHA: &str = "9ac5f97139f98c9e9fbae536bf8346fc90ff4eb4710825b3588cfb854eb057a7";
const DOWNLOAD: &str = "horizon-epoch141-ledger-source-download-20261020-v1.service";
const DOWNLOAD_IID: &str = "f629505db361470babeaaef64f07f10b";
const PARK: &str = "horizon-closed141-input-park-20261118-v1.service";
const PARK_IID: &str = "1c113358b7a14265a4e2d8d16576d6ae";
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch141-7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b.tar.bz2";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retire {
    schema: String,
    mapping: Bound,
    eligibility: Bound,
    custody: Bound,
    prior_check: Option<Bound>,
}

fn source_identity(path: &Path) -> Result<FileIdentity> {
    let id = regular_identity(path)?;
    let md = fs::symlink_metadata(path)?;
    ensure!(
        id.device == 64512
            && id.inode == 105526093
            && id.length == LENGTH
            && md.uid() == 0
            && md.gid() == 0
            && md.mode() & 0o7777 == 0o444
            && md.nlink() == 1
            && md.blocks().checked_mul(512) == Some(ALLOCATED),
        "141 exact immutable source identity changed"
    );
    Ok(id)
}

fn terminal(unit: &str, iid: &str, result: &str) -> Result<Value> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", unit, "-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,Result,ExecMainStatus,Restart,TriggeredBy"])
        .output()?;
    ensure!(output.status.success(), "141 terminal unit unavailable");
    let mut map = serde_json::Map::new();
    for line in String::from_utf8(output.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("141 native unit row")?;
        ensure!(!map.contains_key(key), "duplicate 141 native property");
        map.insert(key.into(), json!(value));
    }
    let row = Value::Object(map);
    let closed = if result == "success" {
        (row["ActiveState"] == "inactive" && row["SubState"] == "dead")
            || (row["ActiveState"] == "active" && row["SubState"] == "exited")
    } else {
        row["ActiveState"] == "failed" && row["SubState"] == "failed"
    };
    ensure!(
        row["Id"] == unit
            && row["InvocationID"] == iid
            && closed
            && row["Result"] == result
            && row["ExecMainStatus"] == if result == "success" { "0" } else { "1" }
            && row["MainPID"] == "0"
            && row["ControlPID"] == "0"
            && row["Job"] == ""
            && row["Restart"] == "no"
            && row["TriggeredBy"] == "",
        "141 producer or holding unit is not the exact closed invocation"
    );
    Ok(row)
}

fn closure(path: &Path) -> Result<Value> {
    let download = terminal(DOWNLOAD, DOWNLOAD_IID, "exit-code")?;
    let park = terminal(PARK, PARK_IID, "success")?;
    let processes = no_references(path)?;
    let staged = jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(path)?;
    ensure!(
        staged["references"] == json!([]),
        "141 source has staged relaunch references"
    );
    Ok(json!({"download":download,"park":park,"processes":processes,"staged":staged}))
}

fn exact_custody(c: &Value) -> Result<()> {
    ensure!(
        c["source"] == SOURCE
            && c["sha256"] == SHA
            && c["length"] == LENGTH
            && c["eligibility"]["path"] == ELIGIBILITY
            && c["eligibility"]["sha256"] == ELIGIBILITY_SHA
            && c["mapping"]["path"]
                == "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json"
            && c["manifest"]["uid"] == 0
            && c["manifest"]["gid"] == 0
            && c["manifest"]["mode"] == 0o444,
        "141 custody does not bind the exact closed source"
    );
    Ok(())
}

async fn remote(client: &Client, m: &Mapping, c: &Value) -> Result<RemoteArchive> {
    let (key, etag, sha, length) = custody(c, m)?;
    exact_custody(c)?;
    let owner = owner_bytes(m)?;
    ensure!(
        get_mutable_object(client, BUCKET, &format!("{}owner.json", m.prefix))
            .await?
            .is_some_and(|o| o.bytes == owner),
        "141 holding owner differs"
    );
    let manifest = get_mutable_object(
        client,
        BUCKET,
        c["manifest_key"].as_str().context("141 manifest key")?,
    )
    .await?
    .context("141 holding manifest absent")?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest.bytes)) == c["manifest_sha256"]
            && serde_json::from_slice::<Value>(&manifest.bytes)? == c["manifest"],
        "141 holding manifest differs"
    );
    let blob = head_archive(client, BUCKET, &key)
        .await?
        .context("141 held blob absent")?;
    remote_matches(&blob, &key, length, &sha, Some(&etag))?;
    Ok(blob)
}

fn record(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(md) => {
            ensure!(
                md.is_file()
                    && md.uid() == 0
                    && md.nlink() == 1
                    && md.mode() & 0o222 == 0
                    && md.len() <= 1 << 20,
                "unsafe 141 transition record"
            );
            let id = regular_identity(path)?;
            let bytes = fs::read(path)?;
            ensure!(regular_identity(path)? == id, "141 record changed");
            Ok(Some(serde_json::from_slice(&bytes)?))
        }
    }
}

fn transition_shape(intent: bool, moved: bool, unlink: bool, complete: bool) -> Result<()> {
    ensure!(!moved || intent, "141 moved without intent");
    ensure!(!unlink || moved, "141 unlink without moved proof");
    ensure!(!complete || unlink, "141 completion without unlink intent");
    Ok(())
}

pub(super) async fn run(
    client: &Client,
    m: &Mapping,
    p: &Retire,
    spec: &Bound,
    check: bool,
) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-retire141-plan-v1"
            && p.eligibility.path == Path::new(ELIGIBILITY)
            && p.eligibility.sha256 == ELIGIBILITY_SHA,
        "foreign 141 retirement scope"
    );
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "141 mapping changed"
    );
    let e = bound(&p.eligibility)?;
    ensure!(
        e["schema"] == "jetstreamer-horizon-holding-eligibility-v2"
            && e["source"] == SOURCE
            && e["sha256"] == SHA
            && e["length"] == LENGTH
            && e["closed"] == true
            && e["canonical_archive"] == false
            && e["identity"]["device"] == 64512
            && e["identity"]["inode"] == 105526093
            && e["identity"]["allocated_bytes"] == ALLOCATED,
        "141 closed eligibility changed"
    );
    let c = bound(&p.custody)?;
    ensure!(
        c["mapping"] == serde_json::to_value(&p.mapping)?
            && c["eligibility"] == serde_json::to_value(&p.eligibility)?,
        "141 custody plan bindings differ"
    );
    let _ = remote(client, m, &c).await?;
    let root = Path::new(STATE).join("retirements");
    private(&root)?;
    let source = Path::new(SOURCE);
    let quarantine = Path::new(QUARANTINE);
    let intent_path = root.join("epoch141-intent.json");
    let moved_path = root.join("epoch141-moved.json");
    let unlink_path = root.join("epoch141-unlink-intent.json");
    let completion_path = root.join("epoch141-completion.json");
    let descriptor = json!({"schema":"jetstreamer-holding-retire141-intent-v1",
        "source":SOURCE,"quarantine":QUARANTINE,"sha256":SHA,"length":LENGTH,
        "eligibility":p.eligibility,"custody":p.custody,"mapping":p.mapping,
        "canonical_archive":false,"remote_mutations":false,"r2_mutations":false});
    let expected_moved = json!({"schema":"jetstreamer-holding-retire141-moved-v1",
        "intent":descriptor,"local_sha256":SHA,
        "local_multipart_etag":c["object_etag"]});
    let expected_unlink = json!({"schema":"jetstreamer-holding-retire141-unlink-intent-v1",
        "moved":expected_moved,"authenticated_custody_revalidated":true});
    let expected_completion = json!({"schema":"jetstreamer-holding-retire141-completion-v1",
        "intent":descriptor,"source_absent":true,"quarantine_absent":true,
        "retired_censused_physical_bytes":ALLOCATED,"actual_free_delta_claimed":false,
        "authenticated_custody_revalidated":true,"remote_mutations":false,"r2_mutations":false});
    let old_intent = record(&intent_path)?;
    let old_moved = record(&moved_path)?;
    let old_unlink = record(&unlink_path)?;
    let old_completion = record(&completion_path)?;
    ensure!(
        old_intent.as_ref().is_none_or(|v| v == &descriptor),
        "141 intent differs"
    );
    ensure!(
        old_moved.as_ref().is_none_or(|v| v == &expected_moved),
        "141 moved proof differs"
    );
    ensure!(
        old_unlink.as_ref().is_none_or(|v| v == &expected_unlink),
        "141 unlink intent differs"
    );
    ensure!(
        old_completion
            .as_ref()
            .is_none_or(|v| v == &expected_completion),
        "141 completion differs"
    );
    transition_shape(
        old_intent.is_some(),
        old_moved.is_some(),
        old_unlink.is_some(),
        old_completion.is_some(),
    )?;
    ensure!(
        !old_moved.is_some() || !source.exists(),
        "141 moved record conflicts with original source"
    );
    ensure!(
        source.exists() || !quarantine.exists() || old_intent.is_some(),
        "141 quarantine has no durable intent"
    );
    let current = if source.exists() { source } else { quarantine };
    ensure!(
        old_completion.is_none() || !current.exists(),
        "141 source reappeared after completion"
    );
    if old_completion.is_some() {
        println!("{}", completion_path.display());
        return Ok(());
    }
    if current.exists() {
        ensure!(
            !(source.exists() && quarantine.exists()),
            "141 duplicate transition source"
        );
        let id = source_identity(current)?;
        let proof = hash_and_etag(current, id, DEFAULT_PART_SIZE)?;
        ensure!(
            proof.sha256_hex == SHA && proof.multipart_etag == c["object_etag"],
            "141 local source differs from authenticated custody"
        );
        let _ = closure(current)?;
        let _ = remote(client, m, &c).await?;
    } else {
        ensure!(
            old_unlink.is_some(),
            "141 source absent without unlink intent"
        );
    }
    let check_path = Path::new(STATE)
        .join("receipts")
        .join(format!("retire141-check-{}.json", spec.sha256));
    if check {
        ensure!(
            p.prior_check.is_none() && current.exists(),
            "141 check requires original source"
        );
        persist(
            &check_path,
            &json!({"schema":"jetstreamer-holding-retire141-check-v1",
            "descriptor":descriptor,"checked":true,"data_removed":false,
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()}),
        )?;
        println!("{}", check_path.display());
        return Ok(());
    }
    let prior = bound(
        p.prior_check
            .as_ref()
            .context("141 retirement requires prior check")?,
    )?;
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        prior["schema"] == "jetstreamer-holding-retire141-check-v1"
            && prior["descriptor"] == descriptor
            && prior["checked"] == true
            && prior["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= at && at - t <= 900),
        "141 prior check stale or foreign"
    );
    if old_intent.is_none() {
        persist(&intent_path, &descriptor)?;
    }
    if current == source {
        rename_noreplace(source, quarantine)?;
        source_identity(quarantine)?;
    }
    if quarantine.exists() {
        let id = source_identity(quarantine)?;
        let proof = hash_and_etag(quarantine, id, DEFAULT_PART_SIZE)?;
        ensure!(
            proof.sha256_hex == SHA && proof.multipart_etag == c["object_etag"],
            "141 quarantined bytes differ"
        );
        ensure!(
            proof.sha256_hex == expected_moved["local_sha256"]
                && proof.multipart_etag == expected_moved["local_multipart_etag"],
            "141 moved local proof differs"
        );
        if old_moved.is_none() {
            persist(&moved_path, &expected_moved)?;
        }
        let _ = closure(quarantine)?;
        let _ = remote(client, m, &c).await?;
        if old_unlink.is_none() {
            persist(&unlink_path, &expected_unlink)?;
        }
        ensure!(
            !source.exists() && source_identity(quarantine)? == id,
            "141 source reappeared or quarantine replaced"
        );
        fs::remove_file(quarantine)?;
        File::open(root)?.sync_all()?;
    }
    ensure!(
        !source.exists() && !quarantine.exists(),
        "141 local source remains"
    );
    let _ = remote(client, m, &c).await?;
    if old_completion.is_none() {
        persist(&completion_path, &expected_completion)?;
    }
    println!("{}", completion_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_accepts_the_manifest_written_by_the_holding_producer() {
        let mapping = Mapping {
            schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
            host: HOST.into(), prefix: "node_02/".into(), user_provided_prefix: true,
            authorization_reference: "test fixture".into(),
        };
        let plan = Park {
            schema: "jetstreamer-horizon-holding-park-plan-v2".into(),
            mapping: Bound {path: "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json".into(),sha256:"a".repeat(64)},
            eligibility: Bound {path:ELIGIBILITY.into(),sha256:ELIGIBILITY_SHA.into()},
            source:SOURCE.into(),length:LENGTH,sha256:SHA.into(),
        };
        let manifest: Value = serde_json::from_slice(&manifest_bytes(
            &mapping, &plan, &object_key(&mapping,SHA).unwrap(), 0, 0, 0o100444,
        ).unwrap()).unwrap();
        let mut receipt = json!({"source":SOURCE,"sha256":SHA,"length":LENGTH,
            "eligibility":plan.eligibility,"mapping":plan.mapping,"manifest":manifest});
        exact_custody(&receipt).unwrap();
        for bad_mode in [0o100444,0o644,0o400] {
            receipt["manifest"]["mode"] = json!(bad_mode);
            assert!(exact_custody(&receipt).is_err());
        }
    }

    #[test]
    fn retirement_markers_require_durable_predecessors() {
        for (intent, moved, unlink, complete) in [
            (false, false, false, false),
            (true, false, false, false),
            (true, true, false, false),
            (true, true, true, false),
            (true, true, true, true),
        ] {
            transition_shape(intent, moved, unlink, complete).unwrap();
        }
        for state in [
            (false, true, false, false),
            (true, false, true, false),
            (true, true, false, true),
        ] {
            assert!(transition_shape(state.0, state.1, state.2, state.3).is_err());
        }
    }
}
