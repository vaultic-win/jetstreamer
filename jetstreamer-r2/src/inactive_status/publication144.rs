//! Preserve failed/ended publisher artifacts before any upload intent exists.
//! Artifact presence is not liveness. This proves custody, not archive validity.
use super::*;
const PUB: &str = "horizon-publish-144-v4-20261022-v1.service";
const UPLOAD: &str = "horizon-upload-144-v4-20261022-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-publication144-owner-20261022-v1";
const SCHEMA: &str = "jetstreamer-exact144-terminal-publication-preservation-v1";
pub(super) fn recognized(v: &Value) -> bool {
    v["schema"] == SCHEMA
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturePlan {
    schema: String,
    origin: Bound,
    terminal: Bound,
    output: PathBuf,
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn artifacts() -> Result<Value> {
    let mut values = serde_json::Map::new();
    for name in ["epoch-144.jet", "epoch-144.jet.sha256"] {
        let path = Path::new("/home/sol/horizon").join(name);
        let value = match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Value::Null,
            Err(e) => return Err(e.into()),
            Ok(m) => {
                ensure!(
                    m.is_file()
                        && m.uid() == 1001
                        && m.gid() == 1003
                        && m.nlink() == 1
                        && m.mode() & 0o022 == 0,
                    "unsafe preserved publisher artifact:{name}"
                );
                let sidecar = if name.ends_with("sha256") {
                    Some(hex_lower(&Sha256::digest(read_stable_bounded(
                        &path,
                        4096,
                        "preserved publisher sidecar",
                    )?)))
                } else {
                    None
                };
                ensure!(
                    identity(&fs::symlink_metadata(&path)?) == identity(&m),
                    "publisher artifact changed during capture"
                );
                json!({"identity":identity(&m),"sidecar_sha256":sidecar})
            }
        };
        values.insert(name.into(), value);
    }
    Ok(Value::Object(values))
}
fn lineage(origin: &Bound, terminal: &Bound) -> Result<(Value, Value)> {
    ensure!(
        origin.path == Path::new(ROOT).join("launch.json")
            && terminal.path == Path::new(ROOT).join("terminal.json"),
        "foreign publisher preservation lineage paths"
    );
    let o = bound_json(origin)?;
    let t = bound_json(terminal)?;
    checked_lineage(origin, &o, &t)?;
    Ok((o, t))
}
fn checked_lineage(origin: &Bound, o: &Value, t: &Value) -> Result<()> {
    ensure!(
        o["schema"] == "jetstreamer-exact144-publication-launch-v1"
            && o["epoch"] == 144
            && o["launched"] == true
            && o["publisher_sha256"]
                == "4274f83c6d84a2bc2014b30122a38406b6498045f543ba170598baa8369a7efa"
            && o["claim"]["unit"] == PUB
            && o["claim"]["phase"] == "local-publication"
            && t["schema"] == "jetstreamer-exact144-publication-terminal-v1"
            && t["epoch"] == 144
            && t["launch"]["path"].as_str() == origin.path.to_str()
            && t["launch"]["sha256"] == origin.sha256
            && t["owner"]["Id"] == PUB
            && t["owner"]["InvocationID"] == o["claim"]["invocation_id"]
            && t["archive_verification_or_ready_pair_proven"] == false
            && t["r2_mutations"] == false,
        "publisher preservation lost exact launch/terminal lineage"
    );
    Ok(())
}
fn idle_upload(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == UPLOAD
            && v["MainPID"] == "0"
            && v["InvocationID"] == ""
            && matches!(v["LoadState"].as_str(), Some("loaded" | "not-found"))
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead",
        "publisher has an active, replaced or previously launched upload; use its delivery evidence"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preservation_requires_original_terminal_publisher_not_another_attempt() {
        let origin = Bound {
            path: Path::new(ROOT).join("launch.json"),
            sha256: "a".repeat(64),
        };
        let o = json!({"schema":"jetstreamer-exact144-publication-launch-v1","epoch":144,"launched":true,
            "publisher_sha256":"4274f83c6d84a2bc2014b30122a38406b6498045f543ba170598baa8369a7efa",
            "claim":{"unit":PUB,"phase":"local-publication","invocation_id":"b".repeat(32)}});
        let t = json!({"schema":"jetstreamer-exact144-publication-terminal-v1","epoch":144,
            "launch":{"path":origin.path,"sha256":origin.sha256},"owner":{"Id":PUB,"InvocationID":"b".repeat(32)},
            "archive_verification_or_ready_pair_proven":false,"r2_mutations":false});
        checked_lineage(&origin, &o, &t).unwrap();
        for (which, pointer) in [
            (0, "/publisher_sha256"),
            (0, "/claim/unit"),
            (0, "/claim/invocation_id"),
            (1, "/launch/sha256"),
            (1, "/owner/InvocationID"),
            (1, "/archive_verification_or_ready_pair_proven"),
        ] {
            let mut values = [o.clone(), t.clone()];
            *values[which].pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(
                checked_lineage(&origin, &values[0], &values[1]).is_err(),
                "{which}:{pointer}"
            );
        }
    }
    #[test]
    fn never_capture_over_a_live_replacement_or_previously_started_uploader() {
        let v = json!({"Id":UPLOAD,"LoadState":"not-found","MainPID":"0","InvocationID":"","ActiveState":"inactive","SubState":"dead"});
        idle_upload(&v).unwrap();
        let mut installed = v.clone();
        installed["LoadState"] = json!("loaded");
        idle_upload(&installed).unwrap();
        for field in ["Id", "MainPID", "InvocationID", "ActiveState", "SubState"] {
            let mut bad = v.clone();
            bad[field] = json!("foreign");
            assert!(idle_upload(&bad).is_err(), "{field}");
        }
    }
    #[test]
    fn custody_receipt_cannot_authorize_archive_completion_or_other_epochs() {
        let (mut p, _) = super::super::tests::plan_fixture();
        p.epoch = 144;
        p.public_archive_directory = "/home/sol/horizon".into();
        p.status_receipt_directory = "/home/sol/.jetstreamer-private/r2-status-receipts".into();
        let v = json!({"schema":SCHEMA,"epoch":144,"archive_completion_claimed":false,"archive_mutations":false,"remote_mutations":false,"r2_mutations":false});
        scope(&p, &v).unwrap();
        for field in [
            "archive_completion_claimed",
            "archive_mutations",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = v.clone();
            bad[field] = json!(true);
            assert!(scope(&p, &bad).is_err(), "{field}");
        }
        p.epoch = 145;
        assert!(scope(&p, &v).is_err());
    }
}
fn owners(current: &BTreeMap<String, Value>, o: &Value, t: &Value) -> Result<()> {
    let publisher = current.get(PUB).context("publisher absent from census")?;
    let iid = o["claim"]["invocation_id"]
        .as_str()
        .context("publisher IID")?;
    preserved144::terminal_owner(publisher, &t["owner"], iid)?;
    idle_upload(current.get(UPLOAD).context("upload absent from census")?)?;
    no_pending_owner_trigger(PUB, false)?;
    no_pending_owner_trigger(UPLOAD, current[UPLOAD]["LoadState"] == "not-found")?;
    Ok(())
}
pub(super) fn scope(p: &Plan, v: &Value) -> Result<()> {
    ensure!(
        recognized(v)
            && v["epoch"] == 144
            && p.epoch == 144
            && p.public_archive_directory == Path::new("/home/sol/horizon")
            && p.status_receipt_directory
                == Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
            && v["archive_completion_claimed"] == false
            && v["archive_mutations"] == false
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "foreign or authorizing publisher preservation receipt"
    );
    Ok(())
}
fn bound_lineage(v: &Value) -> Result<(Value, Value)> {
    lineage(
        &serde_json::from_value(v["origin"].clone())?,
        &serde_json::from_value(v["terminal"].clone())?,
    )
}
pub(super) fn owner(p: &Plan, v: &Value, r: &StatusPublicationReceipt) -> Result<()> {
    scope(p, v)?;
    let (o, _) = bound_lineage(v)?;
    let b = r
        .pipeline_binding
        .as_ref()
        .context("publisher status ownership missing")?;
    ensure!(
        r.epoch == 144
            && b.unit == PUB
            && b.origin_unit == PUB
            && b.claim_phase == "local-publication"
            && b.invocation_id == b.origin_invocation_id
            && o["claim"]["invocation_id"] == b.invocation_id,
        "publisher preservation belongs to another status owner"
    );
    Ok(())
}
pub(super) fn terminal_census(
    p: &Plan,
    v: &Value,
    current: &BTreeMap<String, Value>,
) -> Result<()> {
    scope(p, v)?;
    let (o, t) = bound_lineage(v)?;
    owners(current, &o, &t)
}
pub(super) fn local(p: &Plan, v: &Value) -> Result<()> {
    scope(p, v)?;
    bound_lineage(v)?;
    ensure!(
        p.public_archive_directory.canonicalize()? == p.public_archive_directory
            && artifacts()? == v["artifacts"],
        "preserved publisher artifacts changed; keep status pending reconciliation"
    );
    Ok(())
}
pub(super) fn prepare() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 5 && args[3] == "--plan-sha256" && unsafe { libc::geteuid() } == 0,
        "usage: status-prepare-publication144-preservation PLAN --plan-sha256 SHA"
    );
    let b = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let p: CapturePlan = serde_json::from_value(bound_json(&b)?)?;
    let root = p.output.parent().context("preservation parent")?;
    let m = fs::symlink_metadata(root)?;
    ensure!(
        p.schema == "jetstreamer-exact144-terminal-publication-preservation-plan-v1"
            && root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-epoch144-terminal-preservation-"))
            && p.output == root.join("preservation.json")
            && root.canonicalize()? == root
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o700,
        "unsafe publisher preservation scope/output"
    );
    let (o, t) = lineage(&p.origin, &p.terminal)?;
    let names = BTreeSet::from([PUB.into(), UPLOAD.into()]);
    let before = fleet::census(&names, 101, 200)?;
    owners(&before, &o, &t)?;
    let a = artifacts()?;
    ensure!(
        fleet::census(&names, 101, 200)? == before && artifacts()? == a,
        "publisher ownership/artifacts changed during preservation"
    );
    let v = json!({"schema":SCHEMA,"epoch":144,"plan":{"path":b.path,"sha256":b.sha256},"origin":{"path":p.origin.path,"sha256":p.origin.sha256},
        "terminal":{"path":p.terminal.path,"sha256":p.terminal.sha256},"observed_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "artifacts":a,"census":before,"archive_completion_claimed":false,"archive_mutations":false,"remote_mutations":false,"r2_mutations":false});
    fleet::persist(&p.output, &v)?;
    println!("{}", p.output.display());
    Ok(())
}
