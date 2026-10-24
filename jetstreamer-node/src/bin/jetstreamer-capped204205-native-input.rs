//! Metadata-only original capped 204/205 input-policy preparation. No Bank,
//! prefix-body read, service query/launch, admission or remote mutation.
use anyhow::{Context, Result, ensure};
use jetstreamer_node::{
    archive_checksum::{
        archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
    },
    capped_prefix204205::{
        GENESIS_SHA256, MetadataInputs, WORKER_SHA256, bind_metadata, hex_sha, parse_sha, profile,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    env, fs,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    original_launch: Bound,
    producer_result: Bound,
    terminal_properties: Bound,
    manager_journal: Bound,
    prefix_manifest: Bound,
    prefix_validation: Bound,
    worker: Bound,
    genesis_archive: Bound,
    output: PathBuf,
}

struct Args {
    plan: PathBuf,
    plan_sha: String,
    self_sha: String,
    check_only: bool,
}

fn args(values: Vec<String>) -> Result<Args> {
    ensure!(
        (values.len() == 5 || values.len() == 6)
            && values[1] == "--plan-sha256"
            && values[3] == "--self-sha256"
            && (values.len() == 5 || values[5] == "--check-only"),
        "usage: jetstreamer-capped204205-native-input PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    parse_sha(&values[2])?;
    parse_sha(&values[4])?;
    Ok(Args {
        plan: values[0].clone().into(),
        plan_sha: values[2].clone(),
        self_sha: values[4].clone(),
        check_only: values.len() == 6,
    })
}

fn validate_plan(p: &Plan) -> Result<()> {
    let scope = profile(p.epoch)?;
    ensure!(
        p.schema == "jetstreamer-capped204205-native-input-plan-v1"
            && p.original_launch.path == Path::new(scope.launch_path)
            && p.original_launch.sha256 == scope.launch_sha256
            && p.worker.sha256 == WORKER_SHA256
            && p.genesis_archive.sha256 == GENESIS_SHA256
            && p.genesis_archive
                .path
                .file_name()
                .is_some_and(|s| s == "genesis.tar.bz2"),
        "wrong closed native-input plan"
    );
    let root = p.output.parent().context("output parent")?;
    ensure!(
        p.output
            .file_name()
            .is_some_and(|s| s == "native-input-policy.json")
            && root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix(&format!("horizon-capped-native-input-{}-", p.epoch)))
                .is_some_and(
                    |s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                ),
        "input-policy output must use its exact epoch-private namespace"
    );
    for b in [
        &p.original_launch,
        &p.producer_result,
        &p.terminal_properties,
        &p.manager_journal,
        &p.prefix_manifest,
        &p.prefix_validation,
        &p.worker,
        &p.genesis_archive,
    ] {
        ensure!(
            b.path.is_absolute() && !b.path.starts_with(root) && parse_sha(&b.sha256)? != [0; 32],
            "invalid or overlapping bound input"
        );
    }
    Ok(())
}

fn bound(b: &Bound, maximum: u64) -> Result<Vec<u8>> {
    bound_for_owner(b, maximum, 0)
}

fn bound_for_owner(b: &Bound, maximum: u64, owner: u32) -> Result<Vec<u8>> {
    ensure!(
        b.path.is_absolute() && b.path.canonicalize()? == b.path,
        "bound input is redirected"
    );
    let mut f = open_regular_nofollow(&b.path)?;
    let m = f.metadata()?;
    let identity = archive_file_identity(&f)?;
    ensure!(
        m.uid() == owner && m.nlink() == 1 && m.mode() & 0o222 == 0 && m.len() <= maximum,
        "input must be bounded, immutable and root owned"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && hex_sha(&bytes) == b.sha256
            && archive_file_identity(&f)? == identity
            && path_matches_archive_identity(&b.path, identity)?,
        "input hash or identity changed"
    );
    Ok(bytes)
}

fn output(root: &Path, path: &Path, value: &serde_json::Value) -> Result<()> {
    output_for_owner(root, path, value, 0)
}

fn output_for_owner(root: &Path, path: &Path, value: &serde_json::Value, owner: u32) -> Result<()> {
    ensure!(root.canonicalize()? == root, "output parent is redirected");
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let m = dir.metadata()?;
    ensure!(
        m.uid() == owner && m.mode() & 0o6077 == 0,
        "output parent must be root private"
    );
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let mut f = open_regular_nofollow(path)?;
            let before = archive_file_identity(&f)?;
            let metadata = f.metadata()?;
            ensure!(
                metadata.uid() == owner
                    && metadata.nlink() == 1
                    && metadata.mode() & 0o7777 == 0o400
                    && metadata.len() == bytes.len() as u64,
                "occupied policy receipt differs"
            );
            let mut actual = Vec::new();
            Read::by_ref(&mut f)
                .take(bytes.len() as u64 + 1)
                .read_to_end(&mut actual)?;
            ensure!(
                actual == bytes
                    && archive_file_identity(&f)? == before
                    && path_matches_archive_identity(path, before)?,
                "occupied policy receipt changed"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut file = tempfile::NamedTempFile::new_in(root)?;
            file.write_all(&bytes)?;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(0o400))?;
            file.as_file().sync_all()?;
            file.persist_noclobber(path)
                .map_err(|e| anyhow::anyhow!("policy publication conflict: {e}"))?;
        }
        Err(e) => return Err(e.into()),
    }
    let after = fs::symlink_metadata(root)?;
    ensure!(
        m.dev() == after.dev()
            && m.ino() == after.ino()
            && m.uid() == after.uid()
            && m.mode() == after.mode()
            && root.canonicalize()? == root,
        "output parent changed"
    );
    dir.sync_all()?;
    Ok(())
}

fn run(a: Args) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "root-owned preparation/capture required"
    );
    let mut own = File::open("/proc/self/exe")?;
    let mut binary = Vec::new();
    Read::by_ref(&mut own)
        .take((256 << 20) + 1)
        .read_to_end(&mut binary)?;
    ensure!(
        binary.len() <= 256 << 20 && hex_sha(&binary) == a.self_sha,
        "executing tool hash differs"
    );
    let plan_bound = Bound {
        path: a.plan,
        sha256: a.plan_sha,
    };
    let p: Plan = serde_json::from_slice(&bound(&plan_bound, 1 << 20)?)?;
    validate_plan(&p)?;
    if a.check_only {
        println!(
            "{}",
            json!({"schema":"jetstreamer-capped204205-native-input-preflight-v1","epoch":p.epoch,
            "static_plan_validated":true,"primary_evidence_read":false,"snapshot_inspected":false,
            "policy_written":false,"native_initialized":false,"suffix_execution_authorized":false,
            "assembly_authorized":false,"publication_authorized":false,"r2_mutations":false})
        );
        return Ok(());
    }
    let launch = bound(&p.original_launch, 1 << 20)?;
    let result = bound(&p.producer_result, 1 << 20)?;
    let properties = bound(&p.terminal_properties, 1 << 20)?;
    let manager = bound(&p.manager_journal, 4 << 20)?;
    let manifest = bound(&p.prefix_manifest, 1 << 20)?;
    let reader = bound(&p.prefix_validation, 1 << 20)?;
    let policy = bind_metadata(
        p.epoch,
        MetadataInputs {
            launch: &launch,
            producer_result: &result,
            terminal_properties: &properties,
            manager_journal: &manager,
            prefix_manifest: &manifest,
            prefix_validation: &reader,
        },
    )?;
    bound(&p.worker, 256 << 20)?;
    bound(&p.genesis_archive, 10 << 20)?;
    let scope = profile(p.epoch)?;
    let snapshot = Path::new(scope.snapshot_path);
    let sm = fs::symlink_metadata(snapshot)?;
    ensure!(
        snapshot.canonicalize()? == snapshot
            && sm.is_file()
            && sm.uid() == 0
            && sm.nlink() == 1
            && sm.mode() & 0o222 == 0
            && sm.len() == scope.snapshot_bytes,
        "retained immutable snapshot metadata differs"
    );
    let value = json!({"schema":"jetstreamer-capped204205-native-input-prepared-v1","input_policy":policy,
        "plan":plan_bound,"tool_sha256":a.self_sha,"worker":p.worker,"genesis_archive":p.genesis_archive,
        "worker_and_genesis_rehashed":true,"snapshot_body_rehashed":false,
        "snapshot_metadata":{"device":sm.dev(),"inode":sm.ino(),"bytes":sm.len(),"uid":sm.uid(),"mode":sm.mode(),"nlink":sm.nlink()},
        "executing_native_worker_must_rehash_snapshot":true,"current_source_idleness_proven":false,
        "resource_admission_passed":false,"native_initialized":false,"suffix_execution_authorized":false,
        "assembly_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    output(
        p.output.parent().context("output parent")?,
        &p.output,
        &value,
    )?;
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

fn main() -> Result<()> {
    run(args(env::args().skip(1).collect())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan(epoch: u64) -> Plan {
        let p = profile(epoch).unwrap();
        let input = |name: &str| Bound {
            path: Path::new("/var/lib/jetstreamer/input-fixture").join(name),
            sha256: "42".repeat(32),
        };
        Plan { schema:"jetstreamer-capped204205-native-input-plan-v1".into(),epoch,
            original_launch:Bound { path:p.launch_path.into(),sha256:p.launch_sha256.into() },
            producer_result:input("original-result.json"),terminal_properties:input("terminal.json"),
            manager_journal:input("manager.jsonl"),prefix_manifest:input("manifest.json"),prefix_validation:input("reader.json"),
            worker:Bound {path:"/var/lib/jetstreamer/worker-fixture/worker".into(),sha256:WORKER_SHA256.into()},
            genesis_archive:Bound {path:"/var/lib/jetstreamer/genesis-fixture/genesis.tar.bz2".into(),sha256:GENESIS_SHA256.into()},
            output:format!("/var/lib/jetstreamer/horizon-capped-native-input-{epoch}-fixture/native-input-policy.json").into() }
    }
    #[test]
    fn static_plan_rejects_old205_worker_foreign_launch_and_overlapping_paths_without_io() {
        for epoch in [204, 205] {
            let p = plan(epoch);
            validate_plan(&p).unwrap();
            let mut changed = plan(epoch);
            changed.worker.sha256 =
                "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a".into();
            assert!(validate_plan(&changed).is_err());
            let mut changed = plan(epoch);
            changed.original_launch.sha256 = "42".repeat(32);
            assert!(validate_plan(&changed).is_err());
            let mut changed = plan(epoch);
            changed.prefix_manifest.path = changed.output.clone();
            assert!(validate_plan(&changed).is_err());
            let mut changed = plan(epoch);
            changed.output = "/home/ubuntu/horizon/native-input-policy.json".into();
            assert!(validate_plan(&changed).is_err());
        }
        let mut changed = plan(205);
        changed.epoch = 203;
        assert!(validate_plan(&changed).is_err());
    }
    #[test]
    fn cli_requires_exact_plan_and_self_hashes_and_explicit_static_preflight_flag() {
        let base = vec![
            "/nonexistent/plan.json".into(),
            "--plan-sha256".into(),
            "42".repeat(32),
            "--self-sha256".into(),
            "43".repeat(32),
        ];
        assert!(!args(base.clone()).unwrap().check_only);
        let mut values = base.clone();
        values.push("--check-only".into());
        assert!(args(values).unwrap().check_only);
        let mut values = base;
        values.push("--execute-suffix".into());
        assert!(args(values).is_err());
        assert!(args(vec![]).is_err());
    }

    #[test]
    fn bounded_fixture_reads_require_exact_hash_readonly_identity_and_no_links() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("fixture.json");
        let data = b"synthetic fixture, never operational evidence";
        fs::write(&path, data).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let owner = unsafe { libc::geteuid() };
        let input = Bound {
            path: path.clone(),
            sha256: hex_sha(data),
        };
        assert_eq!(bound_for_owner(&input, 1024, owner).unwrap(), data);
        assert!(bound_for_owner(&input, 1, owner).is_err());
        assert!(bound_for_owner(&input, 1024, owner + 1).is_err());
        let wrong = Bound {
            path: path.clone(),
            sha256: "42".repeat(32),
        };
        assert!(bound_for_owner(&wrong, 1024, owner).is_err());
        fs::hard_link(&path, root.path().join("linked.json")).unwrap();
        assert!(bound_for_owner(&input, 1024, owner).is_err());
        fs::remove_file(root.path().join("linked.json")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(bound_for_owner(&input, 1024, owner).is_err());
        std::os::unix::fs::symlink(&path, root.path().join("alias.json")).unwrap();
        assert!(
            bound_for_owner(
                &Bound {
                    path: root.path().join("alias.json"),
                    sha256: hex_sha(data)
                },
                1024,
                owner
            )
            .is_err()
        );
    }

    #[test]
    fn private_policy_output_is_idempotent_and_preserves_conflicting_or_linked_files() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("native-input-policy.json");
        let owner = unsafe { libc::geteuid() };
        let value = json!({"synthetic_fixture":true});
        output_for_owner(root.path(), &path, &value, owner).unwrap();
        let before = fs::metadata(&path).unwrap();
        let content = fs::read(&path).unwrap();
        output_for_owner(root.path(), &path, &value, owner).unwrap();
        assert_eq!(before.ino(), fs::metadata(&path).unwrap().ino());
        assert!(output_for_owner(root.path(), &path, &json!({"different":true}), owner).is_err());
        assert_eq!(content, fs::read(&path).unwrap());
        fs::hard_link(&path, root.path().join("linked.json")).unwrap();
        assert!(output_for_owner(root.path(), &path, &value, owner).is_err());
        fs::remove_file(root.path().join("linked.json")).unwrap();
        fs::remove_file(&path).unwrap();
        let target = root.path().join("preserve.json");
        fs::write(&target, b"preserve fixture").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(output_for_owner(root.path(), &path, &value, owner).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserve fixture");
    }
}
