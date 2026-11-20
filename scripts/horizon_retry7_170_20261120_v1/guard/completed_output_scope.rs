//! Exact read-only consumer for the completed scratch167 output allowance.
//! It never changes an existing guard, booking, file, or replay.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const RETAINED_CAP: u64 = 128 << 20;
pub const OLD_CAP: u64 = 5 << 30;
const ROOT: &str = "/home/sol/.jetstreamer-private/retry3-scratch167-retirement-20261115-v2";
const REVIEW: &str = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-controls-v7/scratch167-completed-output-scope-review-v1/sealed/REVIEW.json";
const REVIEW_SHA: &str = "ccd816b11dc91d40d5aa8cd78c15325051d605cd9d699585a87cae692315440f";
const BOOKING_SHA: &str = "a292c44fb8adb1dab8ac8581f4b795cd4e800c74c9c57e9a3735b328e90dc6ed";
const SEQUENCE_SHA: &str = "d7a3a2a93439ae501439aa96a1473474148bf313556c00551a305bbd172c9a7b";
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job,Triggers,TriggeredBy,OnSuccess,OnFailure,FragmentPath";
const UNITS: [&str; 2] = [
    "horizon-retry3-scratch167-retire-167-check-20261115-v2.service",
    "horizon-retry3-scratch167-retire-167-execute-20261115-v2.service",
];
fn identity(m: &fs::Metadata) -> Result<Value> {
    let ns = |sec: i64, part: i64| {
        sec.checked_mul(1_000_000_000)
            .and_then(|v| v.checked_add(part))
            .context("timestamp overflow")
    };
    Ok(json!([
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.len(),
        ns(m.mtime(), m.mtime_nsec())?,
        ns(m.ctime(), m.ctime_nsec())?,
        m.blocks()
    ]))
}
fn hash_file(file: &mut File) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn small_bound(b: &Value) -> Result<Value> {
    let path = Path::new(b["path"].as_str().context("bound path")?);
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && m.len() <= 1 << 20
            && path.canonicalize()? == path,
        "small bound custody"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        identity(&file.metadata()?)? == identity(&m)?,
        "bound open changed"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == b["sha256"].as_str().context("bound hash")?
            && identity(&file.metadata()?)? == identity(&m)?
            && identity(&fs::symlink_metadata(path)?)? == identity(&m)?,
        "bound content or identity changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn absent(n: &Value) -> Result<()> {
    ensure!(
        n["LoadState"] == "not-found"
            && n["ActiveState"] == "inactive"
            && n["SubState"] == "dead"
            && n["MainPID"] == "0"
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0",
        "original writer not absent"
    );
    for key in [
        "Job",
        "Triggers",
        "TriggeredBy",
        "OnSuccess",
        "OnFailure",
        "FragmentPath",
        "InvocationID",
    ] {
        ensure!(
            n[key] == "",
            "writer has a job, hook, definition or invocation"
        );
    }
    Ok(())
}
fn native(phase: &str, remaining: &mut std::time::Duration) -> Result<Vec<Value>> {
    let r = crate::writer_query::query(&UNITS, FIELDS, phase, remaining)?;
    let mut rows = Vec::new();
    for block in std::str::from_utf8(&r.stdout)?.trim_end().split("\n\n") {
        let mut row = serde_json::Map::new();
        for line in block.lines() {
            let (key, value) = line.split_once('=').context("native delimiter")?;
            ensure!(
                row.insert(key.into(), json!(value)).is_none(),
                "duplicate native field"
            );
        }
        rows.push(Value::Object(row));
    }
    ensure!(rows.len() == 2, "complete writer set");
    for (n, unit) in rows.iter().zip(UNITS) {
        ensure!(n["Id"] == unit, "writer order");
        absent(n)?;
    }
    Ok(rows)
}
fn paths(root: &Path) -> BTreeSet<PathBuf> {
    [
        root.to_path_buf(),
        root.join("epoch167"),
        root.join("epoch167/check.json"),
        root.join("epoch167/ledger.json"),
        root.join("epoch167/intent.json"),
        root.join("epoch167/completion.json"),
    ]
    .into_iter()
    .collect()
}
fn tree(root: &Path, records: &[Value], cap: u64, full_hash: bool) -> Result<u64> {
    let expected = paths(root);
    ensure!(records.len() == 6, "six exact records");
    let recorded = records
        .iter()
        .map(|r| r["path"].as_str().map(PathBuf::from).context("record path"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        recorded == expected,
        "missing, duplicate or foreign output record"
    );
    let children = fs::read_dir(root)?
        .map(|v| v.map(|e| e.path()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    ensure!(
        children == BTreeSet::from([root.join("epoch167")]),
        "unexpected root child"
    );
    let children = fs::read_dir(root.join("epoch167"))?
        .map(|v| v.map(|e| e.path()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    ensure!(
        children
            == expected
                .iter()
                .filter(|p| p.parent() == Some(root.join("epoch167").as_path()))
                .cloned()
                .collect(),
        "unexpected output child"
    );
    let mut physical = 0u64;
    let mut inodes = BTreeSet::new();
    for row in records {
        let path = Path::new(row["path"].as_str().unwrap());
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path
                && m.uid() == 0
                && m.gid() == 0
                && identity(&m)? == row["identity"]
                && inodes.insert((m.dev(), m.ino())),
            "output custody or identity changed"
        );
        ensure!(
            (m.is_dir() && m.mode() & 0o7777 == 0o700)
                || (m.is_file() && m.mode() & 0o7777 == 0o400 && m.nlink() == 1),
            "output kind, mode or links"
        );
        let bytes = m.blocks().checked_mul(512).context("blocks overflow")?;
        ensure!(row["physical_bytes"] == bytes, "physical binding");
        physical = physical
            .checked_add(bytes)
            .context("physical total overflow")?;
        if m.is_file() {
            ensure!(row["binding"]["path"] == row["path"], "file binding path");
            if full_hash {
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path)?;
                ensure!(
                    identity(&file.metadata()?)? == row["identity"],
                    "opened output changed"
                );
                ensure!(
                    hash_file(&mut file)?
                        == row["binding"]["sha256"].as_str().context("file digest")?,
                    "output digest changed"
                );
                ensure!(
                    identity(&file.metadata()?)? == row["identity"],
                    "read output changed"
                );
            }
        } else {
            ensure!(row["binding"].is_null(), "directory has file binding");
        }
        ensure!(
            identity(&fs::symlink_metadata(path)?)? == row["identity"],
            "output changed after read"
        );
    }
    ensure!(physical <= cap, "retained output cap exceeded");
    Ok(physical)
}
pub fn validate(full_hash: bool) -> Result<Value> {
    let review = small_bound(&json!({"path":REVIEW,"sha256":REVIEW_SHA}))?;
    ensure!(
        review["schema"] == "horizon-completed-scratch167-output-capacity-review-v1"
            && review["owner"] == "/root"
            && review["root_retires_future_writes_to_this_completed_output"] == true
            && review["future_attempt_requires_fresh_separate_output_and_booking"] == true
            && review["existing_future_allowance_bytes"] == OLD_CAP
            && review["proposed_retained_capacity_bytes"] == RETAINED_CAP
            && review["proposed_reduction_bytes"] == OLD_CAP - RETAINED_CAP
            && review["prior_DATA_booking"]["sha256"] == BOOKING_SHA
            && review["completed_sequence"]["sha256"] == SEQUENCE_SHA,
        "fixed completed-output scope review"
    );
    let booking = small_bound(&review["prior_DATA_booking"])?;
    ensure!(
        booking["additional_DATA_bytes"] == OLD_CAP && booking["root"] == ROOT,
        "original output booking"
    );
    let sequence = small_bound(&review["completed_sequence"])?;
    for (index, phase) in ["check", "execute"].iter().enumerate() {
        let accepted = small_bound(&sequence[*phase])?;
        let terminal = small_bound(&accepted["terminal"])?;
        let original = small_bound(&review["original_successful_native_invocations"][index])?;
        ensure!(
            terminal == original
                && terminal["Id"] == UNITS[index]
                && terminal["MainPID"] == "0"
                && terminal["ControlPID"] == "0"
                && terminal["Result"] == "success"
                && terminal["ExecMainStatus"] == "0"
                && terminal["InvocationID"] == accepted["invocation_id"],
            "original completed writer"
        );
        ensure!(
            small_bound(&review["original_successful_drains"][index])?["code"] == 0,
            "original writer drain"
        );
        small_bound(&accepted["receipt"])?;
    }
    let mut query_budget = crate::writer_query::PAIR_BUDGET;
    let before = native("before retained-tree verification", &mut query_budget)?;
    let records = review["exact_retained_records"]
        .as_array()
        .context("records")?;
    let physical = tree(Path::new(ROOT), records, RETAINED_CAP, full_hash)?;
    let check = small_bound(
        &json!({"path":format!("{ROOT}/epoch167/check.json"),"sha256":records.iter().find(|r|r["path"]==format!("{ROOT}/epoch167/check.json")).context("check")?["binding"]["sha256"]}),
    )?;
    let done = small_bound(
        &json!({"path":format!("{ROOT}/epoch167/completion.json"),"sha256":records.iter().find(|r|r["path"]==format!("{ROOT}/epoch167/completion.json")).context("completion")?["binding"]["sha256"]}),
    )?;
    ensure!(
        done["scratch_empty"] == true
            && done["scratch_root_preserved"] == true
            && done["basis"] == check["basis"],
        "completed scope changed"
    );
    ensure!(
        native("after retained-tree verification", &mut query_budget)? == before,
        "writer changed across retained-output check"
    );
    tree(Path::new(ROOT), records, RETAINED_CAP, false)?;
    let report = json!({"schema":"horizon-completed-scratch167-output-scope-validation-v1","review":{"path":REVIEW,"sha256":REVIEW_SHA},"retained_physical_bytes":physical,"retained_capacity_bytes":RETAINED_CAP,"original_allowance_bytes":OLD_CAP,"potential_allowance_reduction_bytes":OLD_CAP-RETAINED_CAP,"full_file_hashes_checked":full_hash,"native":before,"existing_guards_changed":false,"booking_changed":false,"resource_credit_bytes":0,"replay_admission_authorized":false});
    crate::completed_output_report::validate_report(&report, full_hash)?;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> (tempfile::TempDir, Vec<Value>) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("epoch167")).unwrap();
        for p in paths(dir.path()) {
            if p.is_dir() {
                fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            } else {
                fs::write(&p, b"original").unwrap();
                fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
            }
        }
        let rows=paths(dir.path()).into_iter().map(|p|{
            let m=fs::symlink_metadata(&p).unwrap();
            json!({"path":p,"identity":identity(&m).unwrap(),"physical_bytes":m.blocks()*512,"binding":if m.is_file(){json!({"path":p,"sha256":hash_file(&mut File::open(&p).unwrap()).unwrap()})}else{Value::Null}})
        }).collect();
        (dir, rows)
    }
    #[test]
    fn exact_read_only_fixture_passes_both_modes() {
        let (d, r) = fixture();
        assert_eq!(
            tree(d.path(), &r, RETAINED_CAP, true).unwrap(),
            tree(d.path(), &r, RETAINED_CAP, false).unwrap()
        );
    }
    #[test]
    fn extra_output_and_underfunding_reject() {
        let (d, r) = fixture();
        assert!(tree(d.path(), &r, 0, false).is_err());
        fs::write(d.path().join("epoch167/new"), b"unplanned").unwrap();
        assert!(tree(d.path(), &r, RETAINED_CAP, false).is_err());
    }
    #[test]
    fn changed_body_and_replacement_reject() {
        let (d, r) = fixture();
        let p = d.path().join("epoch167/ledger.json");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&p, b"changed!").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(tree(d.path(), &r, RETAINED_CAP, true).is_err());
        fs::remove_file(&p).unwrap();
        fs::write(&p, b"original").unwrap();
        assert!(tree(d.path(), &r, RETAINED_CAP, false).is_err());
    }
    #[test]
    fn duplicate_binding_and_digest_substitution_reject() {
        let (d, mut r) = fixture();
        r[0] = r[1].clone();
        assert!(tree(d.path(), &r, RETAINED_CAP, false).is_err());
        let (d, mut r) = fixture();
        let row = r.iter_mut().find(|r| !r["binding"].is_null()).unwrap();
        row["binding"]["sha256"] = json!("0".repeat(64));
        assert!(tree(d.path(), &r, RETAINED_CAP, true).is_err());
    }
    #[test]
    fn absent_writer_requires_no_new_invocation_job_or_hook() {
        let n = json!({"LoadState":"not-found","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","NRestarts":"0","Job":"","Triggers":"","TriggeredBy":"","OnSuccess":"","OnFailure":"","FragmentPath":"","InvocationID":""});
        absent(&n).unwrap();
        for (k, v) in [
            ("LoadState", "loaded"),
            ("MainPID", "5"),
            ("Job", "start"),
            ("Triggers", "timer"),
            ("InvocationID", "replacement"),
            ("OnFailure", "retry.service"),
        ] {
            let mut changed = n.clone();
            changed[k] = json!(v);
            assert!(absent(&changed).is_err());
        }
    }
    #[test]
    fn native_retained_completed_output_is_still_exact() {
        let v = validate(true).unwrap();
        assert_eq!(v["retained_physical_bytes"], 127434752u64);
        assert_eq!(v["potential_allowance_reduction_bytes"], 5234491392u64);
    }
}
