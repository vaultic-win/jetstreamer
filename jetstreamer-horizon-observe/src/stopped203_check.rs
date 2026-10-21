//! Read-only qualification of one exact reserve-stopped disk scratch tree.
//! This binary cannot unlink, signal, restart, publish or access remote storage.
use {
    crate::{
        dev_cache_check, process_references,
        ram_artifact_retention::{self as retained, Bound},
        ram_scratch_retire,
    },
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeSet,
        env, fs,
        os::unix::{ffi::OsStrExt, fs::MetadataExt},
        path::{Path, PathBuf},
        process::Command,
    },
};

const ROOT: &str = "/home/ubuntu/.jetstreamer-private/root-prefix-resource-203-v1";
const UNIT: &str = "horizon-qualify-203-root-prefix-resource-v1.service";
const INV: &str = "92e367eb7cf944a1825fe5a20d9243ca";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-focused-203-complete-span-store8-ca2e38b-v1";
const NODE: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
const WORKER: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
const SNAPSHOT: &str = "snapshot-87695515-CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX.tar.zst";
const SNAPSHOT_SHA: &str = "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4";
const INCIDENT: &str =
    "/var/lib/jetstreamer/horizon-203-reserve-stop-incident-20261021-v1/incident.json";
const INCIDENT_SHA: &str = "216f090a859f5136c131e43ae378da6646c16b32b982f5d5ee39474f67a866dc";
const BUILD_SHA: &str = "a6fc3a7cbb98b3b22657cf0e1dc5396fa6ec26b006f46e499135eaa92b5b176a";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    incident: Bound,
    source_review: Bound,
    build_receipt: Bound,
    output: PathBuf,
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-epoch203-stopped-scratch-check-plan-v1"
            && p.incident.path == Path::new(INCIDENT)
            && p.incident.sha256 == INCIDENT_SHA
            && p.build_receipt.sha256 == BUILD_SHA,
        "not the exact stopped203 evidence"
    );
    let parent = p.output.parent().context("missing output parent")?;
    ensure!(
        p.output.file_name().is_some_and(|s| s == "check.json")
            && parent.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && parent
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-203-stopped-scratch-check-")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))),
        "unsafe check destination"
    );
    Ok(())
}
fn validate_review(review: &Value, build: &Value) -> Result<()> {
    ensure!(
        review["schema"] == "jetstreamer-epoch203-stopped-scratch-source-review-v1"
            && review["run_root"] == ROOT
            && review["producer_invocation_id"] == INV
            && review["node_sha256"] == NODE
            && review["worker_sha256"] == WORKER
            && review["node_source_commit"] == "3de96e71010a8a2f5e629f666227b137483bff7b"
            && review["node_source_sha256"]
                == "cc67feab4e38d0dac1be4138c98d4103136cd70a44e9eb7f2582ef49c44b3ef3"
            && review["runner_source_sha256"]
                == "7beb46a036979e5fe3d3658a14db57bbdf7f09728d3ad18e89dba0fab903c6d8"
            && review["scratch_contains_replay_cursor"] == false
            && review["restarts_from_sealed_bootstrap"] == true
            && review["fresh_runtime_directory_on_initialization"] == true
            && review["preserve_partial_archive_and_inputs"] == true,
        "source review does not establish exact cursor-free restart"
    );
    for field in [
        "scratch_deletion_authorized",
        "archive_deletion_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            review[field] == false,
            "read-only review grants authority: {field}"
        );
    }
    ensure!(
        build["repository"]["head"] == review["node_source_commit"]
            && build["repository"]["tracked_worktree_clean"] == true
            && build["attestation"]["exact_commit_build_observed"] == true
            && build["artifacts"].as_array().is_some_and(|a| a
                .iter()
                .any(|v| v["name"] == "jetstreamer-node" && v["sha256"] == NODE)),
        "source build does not bind exact immutable parent"
    );
    Ok(())
}
fn source_bytes(spec: &str, expected: &str) -> Result<()> {
    let output = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "safe.directory=/home/ubuntu/workspace/jetstreamer",
            "-C",
            "/home/ubuntu/workspace/jetstreamer",
            "show",
            spec,
        ])
        .output()?;
    ensure!(
        output.status.success()
            && output.stdout.len() <= 1 << 20
            && format!("{:x}", Sha256::digest(&output.stdout)) == expected,
        "reviewed historical source bytes unavailable or changed"
    );
    Ok(())
}
pub(crate) fn terminal() -> Result<Value> {
    let names = "Id,Names,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,Restart,Result,ExecMainStatus,Triggers,TriggeredBy,FragmentPath,DropInPaths,ExecStart";
    let v = retained::properties(UNIT, names)?;
    for (k, w) in [
        ("Id", UNIT),
        ("Names", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("MainPID", "0"),
        ("InvocationID", INV),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "exit-code"),
        ("ExecMainStatus", "1"),
        ("Triggers", ""),
        ("TriggeredBy", ""),
        ("DropInPaths", ""),
    ] {
        ensure!(
            v.get(k).map(String::as_str) == Some(w),
            "terminal binding differs: {k}"
        );
    }
    let fragment = format!("/run/systemd/transient/{UNIT}");
    ensure!(
        v.get("FragmentPath") == Some(&fragment),
        "terminal unit fragment changed"
    );
    let command = v.get("ExecStart").context("owner command missing")?;
    ensure!(command.starts_with("{ path=/var/lib/jetstreamer/horizon-203-root-prefix-resource-v1/jetstreamer-epoch203-root-prefix-resource ; argv[]=")
        && command.contains(" /var/lib/jetstreamer/horizon-203-root-prefix-resource-v1/resource-plan.json --plan-sha256 90c64b0a516ca23d7e93c6906b48c4182833128d68426d07f8addf880622d99d --self-sha256 dee8959e8436ebd856b5b8d7e18f06464377b26fadb3a7a9f09ab158f9fd4a4e ;"),
        "not the exact failed runner command");
    let timer = retained::properties(
        "horizon-root-prefix-203-reserve-v2.timer",
        "ActiveState,SubState",
    )?;
    ensure!(
        timer.get("ActiveState").map(String::as_str) == Some("inactive")
            && timer.get("SubState").map(String::as_str) == Some("dead"),
        "reserve timer still armed"
    );
    let jobs = Command::new("/usr/bin/systemctl")
        .args(["list-jobs", "--no-legend", "--plain"])
        .output()?;
    ensure!(
        jobs.status.success() && jobs.stdout.len() <= 1 << 20,
        "jobs census failed"
    );
    let jobs = std::str::from_utf8(&jobs.stdout)?;
    ensure!(
        !jobs.lines().any(|l| l.split_whitespace().any(|s| s == UNIT
            || s == "horizon-root-prefix-203-reserve-v2.timer"
            || s == "horizon-root-prefix-203-reserve-v2.service")),
        "stopped owner has a queued job"
    );
    Ok(json!({"producer":v,"guard_timer":timer,"pending_owner_jobs":false}))
}
pub(crate) fn file_identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),
        "links":m.nlink(),"mtime":[m.mtime(),m.mtime_nsec()],"ctime":[m.ctime(),m.ctime_nsec()]})
}
pub(crate) fn artifact(
    path: &Path,
    uid: u32,
    expected: Option<&str>,
    maximum: u64,
) -> Result<Value> {
    ensure!(path.canonicalize()? == path, "artifact path not canonical");
    let (digest, m) = retained::hash_file(path, maximum)?;
    ensure!(
        m.uid() == uid
            && m.mode() & 0o022 == 0
            // The manager-owned transient fragment is hashed before and after
            // inspection but is not an immutable package member. Every pinned
            // root-owned input remains strictly non-writable.
            && (uid != 0 || expected.is_none() || m.mode() & 0o222 == 0)
            && expected.is_none_or(|e| e == digest),
        "retained artifact ownership/hash changed"
    );
    Ok(json!({"path":path,"sha256":digest,"identity":file_identity(&m)}))
}
pub(crate) fn tree(path: &Path) -> Result<Value> {
    ensure!(path.canonicalize()? == path, "scratch path changed");
    let root = fs::symlink_metadata(path)?;
    ensure!(
        root.is_dir() && root.uid() == 1000 && root.gid() == 1000 && root.mode() & 0o777 == 0o700,
        "unsafe scratch root"
    );
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let point = Path::new(
            line.split_whitespace()
                .nth(4)
                .context("invalid mountinfo")?,
        );
        ensure!(
            !point.starts_with(path) || point == path,
            "nested scratch mount"
        );
    }
    let mut pending = vec![(path.to_path_buf(), 0)];
    let mut digest = Sha256::new();
    let mut entries = 0u64;
    let mut bytes = 0u64;
    let mut files = 0u64;
    while let Some((p, depth)) = pending.pop() {
        entries += 1;
        ensure!(
            entries <= 2_000_000 && depth <= 128,
            "scratch inventory bound exceeded"
        );
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            m.dev() == root.dev()
                && m.uid() == 1000
                && m.gid() == 1000
                && m.mode() & 0o022 == 0
                && (m.is_dir() || (m.is_file() && m.nlink() == 1)),
            "foreign/link/special scratch entry"
        );
        let rel = p.strip_prefix(path)?.as_os_str().as_bytes();
        let identity = serde_json::to_vec(&file_identity(&m))?;
        digest.update((rel.len() as u64).to_le_bytes());
        digest.update(rel);
        digest.update((identity.len() as u64).to_le_bytes());
        digest.update(identity);
        bytes = bytes
            .checked_add(m.blocks().checked_mul(512).context("blocks overflow")?)
            .context("bytes overflow")?;
        if m.is_file() {
            files += 1;
        } else {
            let mut children = fs::read_dir(&p)?
                .map(|e| Ok(e?.path()))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                children.len() <= 1_000_000,
                "scratch directory exceeds bound"
            );
            children.sort();
            for child in children.into_iter().rev() {
                pending.push((child, depth + 1));
            }
        }
    }
    ensure!(
        file_identity(&root) == file_identity(&fs::symlink_metadata(path)?),
        "scratch root changed during inventory"
    );
    Ok(
        json!({"path":path,"root":file_identity(&root),"entries":entries,"files":files,"physical_bytes":bytes,
        "catalog_sha256":format!("{:x}",digest.finalize()),"content_hashed":false,"resumption_qualified":false}),
    )
}

/// Produce only a private read-only check. There is deliberately no execute mode.
pub fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 6 && a[2] == "--plan-sha256" && a[4] == "--self-sha256",
        "usage: stopped203-check PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "checker requires privileged complete process census"
    );
    let (self_sha, m) = retained::hash_file(&fs::read_link("/proc/self/exe")?, 32 << 20)?;
    ensure!(
        self_sha == a[5] && m.uid() == 0 && m.mode() & 0o222 == 0,
        "checker is not sealed"
    );
    let pb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(retained::bound_json(&pb)?)?;
    validate_plan(&p)?;
    let parent = p.output.parent().context("output parent")?;
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && pm.is_dir()
            && pm.uid() == 0
            && pm.mode() & 0o7777 == 0o700,
        "output parent must be root-private"
    );
    ensure!(
        fs::symlink_metadata(&p.output).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "check output occupied"
    );
    let incident = retained::bound_json(&p.incident)?;
    ensure!(
        incident["producer_invocation_id"] == INV
            && incident["guard_stop_reason"] == "filesystem-floor"
            && incident["natural_parent_success"] == false
            && incident["repair_closed"] == false,
        "wrong terminal incident"
    );
    validate_review(
        &retained::bound_json(&p.source_review)?,
        &retained::bound_json(&p.build_receipt)?,
    )?;
    source_bytes(
        "3de96e71010a8a2f5e629f666227b137483bff7b:jetstreamer-node/src/historical.rs",
        "cc67feab4e38d0dac1be4138c98d4103136cd70a44e9eb7f2582ef49c44b3ef3",
    )?;
    source_bytes(
        "76fc1eb58040bb9f7a688c9a6796f9c2f2271c30:jetstreamer-utils/src/bounded_resource_runner.rs",
        "7beb46a036979e5fe3d3658a14db57bbdf7f09728d3ad18e89dba0fab903c6d8",
    )?;
    let owner = terminal()?;
    let fragment = PathBuf::from(format!("/run/systemd/transient/{UNIT}"));
    let fragment_proof = artifact(&fragment, 0, None, 1 << 20)?;
    let mut missing = Vec::new();
    let staged = dev_cache_check::staged_references_exact(
        &[
            Path::new("/etc/systemd/system"),
            Path::new("/run/systemd/transient"),
            Path::new("/run/systemd/system"),
            Path::new("/usr/lib/systemd/system"),
            Path::new("/home/ubuntu/.config/systemd/user"),
        ],
        Path::new(ROOT),
        &mut missing,
        &BTreeSet::from([fragment.clone()]),
    )?;
    ensure!(
        staged.is_empty(),
        "staged consumers reference stopped run: {staged:?}"
    );
    let refs = process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        refs.references.is_empty(),
        "stopped run has live references: {:?}",
        refs.references
    );
    let mut artifacts = vec![artifact(
        &Path::new(ROOT).join("output/epoch-203-prefix.jet"),
        1000,
        None,
        128 << 30,
    )?];
    ensure!(
        artifacts[0]["identity"]["bytes"] == 81_739_258_626u64,
        "partial archive length differs from terminal incident"
    );
    for (path, uid, digest, max) in [
        (
            format!("{ROOT}/receipts/failure.json"),
            1000,
            "af3a4ef5a60007a18f764dbc3295539f41d07678c99b2926466646071c053dfe",
            1 << 20,
        ),
        (
            format!("{ROOT}/ledger/genesis.tar.bz2"),
            1000,
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            1 << 20,
        ),
        (format!("{PACKAGE}/jetstreamer-node"), 0, NODE, 256 << 20),
        (
            format!("{PACKAGE}/jetstreamer-historical-worker-v1-6-16-store8"),
            0,
            WORKER,
            256 << 20,
        ),
        (format!("{PACKAGE}/{SNAPSHOT}"), 0, SNAPSHOT_SHA, 16 << 30),
    ] {
        artifacts.push(artifact(Path::new(&path), uid, Some(digest), max)?);
    }
    let scratch = Path::new(ROOT).join("scratch");
    let before = tree(&scratch)?;
    let second_refs = process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        second_refs.references.is_empty() && terminal()? == owner && tree(&scratch)? == before,
        "terminal ownership/scratch/reference evidence changed"
    );
    ensure!(
        artifact(&fragment, 0, None, 1 << 20)? == fragment_proof,
        "terminal fragment changed"
    );
    for v in &artifacts {
        let path = Path::new(v["path"].as_str().context("artifact path")?);
        ensure!(
            file_identity(&fs::symlink_metadata(path)?) == v["identity"],
            "retained artifact changed before proof"
        );
    }
    let report = json!({"schema":"jetstreamer-epoch203-stopped-scratch-check-v1","self_sha256":self_sha,
        "plan":{"path":pb.path,"sha256":pb.sha256},"incident_sha256":p.incident.sha256,
        "source_review_sha256":p.source_review.sha256,"build_receipt_sha256":p.build_receipt.sha256,
        "owner":owner,"terminal_fragment":fragment_proof,"artifacts":artifacts,"scratch":before,
        "process_scan_before":refs,"process_scan_after":second_refs,"staged_references":staged,
        "terminal_fragments_excluded_from_staged_scan":[fragment],"missing_inactive_aliases":missing,
        "source_bytes_independently_rehashed":true,"scratch_deletion_authorized":false,
        "archive_deletion_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    ram_scratch_retire::persist(&p.output, &report)?;
    println!("{}", p.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn plan() -> Plan {
        Plan {
            schema: "jetstreamer-epoch203-stopped-scratch-check-plan-v1".into(),
            incident: Bound {
                path: INCIDENT.into(),
                sha256: INCIDENT_SHA.into(),
            },
            source_review: Bound {
                path: "/review.json".into(),
                sha256: "a".repeat(64),
            },
            build_receipt: Bound {
                path: "/build.json".into(),
                sha256: BUILD_SHA.into(),
            },
            output: "/var/lib/jetstreamer/horizon-203-stopped-scratch-check-test/check.json".into(),
        }
    }
    fn review() -> (Value, Value) {
        let mut r = json!({"schema":"jetstreamer-epoch203-stopped-scratch-source-review-v1",
            "run_root":ROOT,"producer_invocation_id":INV,"node_sha256":NODE,"worker_sha256":WORKER,
            "node_source_commit":"3de96e71010a8a2f5e629f666227b137483bff7b",
            "node_source_sha256":"cc67feab4e38d0dac1be4138c98d4103136cd70a44e9eb7f2582ef49c44b3ef3",
            "runner_source_sha256":"7beb46a036979e5fe3d3658a14db57bbdf7f09728d3ad18e89dba0fab903c6d8",
            "scratch_contains_replay_cursor":false,"restarts_from_sealed_bootstrap":true,
            "fresh_runtime_directory_on_initialization":true,"preserve_partial_archive_and_inputs":true});
        for k in [
            "scratch_deletion_authorized",
            "archive_deletion_authorized",
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[k] = json!(false);
        }
        let b = json!({"repository":{"head":r["node_source_commit"],"tracked_worktree_clean":true},
            "attestation":{"exact_commit_build_observed":true},"artifacts":[{"name":"jetstreamer-node","sha256":NODE}]});
        (r, b)
    }
    #[test]
    fn scope_is_one_fixed_readonly_incident_not_a_target_selector() {
        validate_plan(&plan()).unwrap();
        for path in [
            "/var/lib/jetstreamer/check.json",
            "/home/ubuntu/check.json",
            "/var/lib/jetstreamer/horizon-203-stopped-scratch-check-../other.json",
        ] {
            let mut p = plan();
            p.output = path.into();
            assert!(validate_plan(&p).is_err());
        }
        let mut p = plan();
        p.incident.path = "/foreign/incident.json".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.build_receipt.sha256 = "b".repeat(64);
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn exact_build_and_cursor_free_review_cannot_grant_deletion_or_retry() {
        let (r, b) = review();
        validate_review(&r, &b).unwrap();
        for (k, v) in [
            ("node_sha256", json!("foreign")),
            ("scratch_contains_replay_cursor", json!(true)),
            ("restarts_from_sealed_bootstrap", json!(false)),
            ("preserve_partial_archive_and_inputs", json!(false)),
            ("scratch_deletion_authorized", json!(true)),
            ("archive_deletion_authorized", json!(true)),
            ("replay_launch_authorized", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[k] = v;
            assert!(validate_review(&bad, &b).is_err());
        }
        let mut bad = b;
        bad["artifacts"][0]["sha256"] = json!("foreign");
        assert!(validate_review(&r, &bad).is_err());
    }
    fn scratch() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    #[test]
    fn readonly_tree_accepts_legacy_readable_modes_but_never_writable_peers_or_links() {
        if unsafe { libc::geteuid() } != 1000 {
            return;
        }
        let d = scratch();
        let p = d.path().join("accounts");
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        let file = p.join("store");
        fs::write(&file, b"data").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let v = tree(d.path()).unwrap();
        assert_eq!(v["entries"], 3);
        assert_eq!(v["files"], 1);
        assert_eq!(tree(d.path()).unwrap(), v);
        let link = p.join("alias");
        fs::hard_link(&file, &link).unwrap();
        assert!(tree(d.path()).is_err());
        fs::remove_file(&link).unwrap();
        symlink(&file, &link).unwrap();
        assert!(tree(d.path()).is_err());
        fs::remove_file(&link).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(tree(d.path()).is_err());
    }
    #[test]
    fn tree_catalog_binds_bytes_identity_not_only_filename_or_total_size() {
        if unsafe { libc::geteuid() } != 1000 {
            return;
        }
        let d = scratch();
        let p = d.path().join("store");
        fs::write(&p, b"old").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let old = tree(d.path()).unwrap();
        fs::write(&p, b"new").unwrap();
        assert_ne!(
            tree(d.path()).unwrap()["catalog_sha256"],
            old["catalog_sha256"]
        );
    }
}
