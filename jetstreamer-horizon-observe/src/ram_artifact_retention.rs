//! Retain a terminal private RAM diagnostic in place and seal its inventory on
//! durable storage. This executable cannot remove artifacts or unmount storage.
use {
    crate::process_references,
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        process::Command,
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bound {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    schema: String,
    pub(crate) run_root: PathBuf,
    pub(crate) producer_unit: String,
    pub(crate) producer_invocation_id: String,
    mount_unit: String,
    mount_invocation_id: String,
    pub(crate) mount_device: [u64; 2],
    root_inode: u64,
    pub(crate) outcome: Bound,
    pub(crate) expected_files: BTreeMap<String, String>,
    output: PathBuf,
}

fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u64, i64, i64, i64, i64, u32, u32, u32) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.uid(),
        m.gid(),
        m.mode(),
    )
}
pub(crate) fn hash_file(path: &Path, maximum: u64) -> Result<(String, fs::Metadata)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.nlink() == 1 && before.len() <= maximum,
        "unsafe/oversized retained file"
    );
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .context("file length overflow")?;
        ensure!(bytes <= maximum, "file exceeded bound while read");
        hash.update(&buffer[..read]);
    }
    ensure!(
        bytes == before.len()
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "retained file changed"
    );
    Ok((format!("{:x}", hash.finalize()), before))
}
pub(crate) fn bound_json(bound: &Bound) -> Result<Value> {
    ensure!(
        hex(&bound.sha256, 64)
            && bound.path.is_absolute()
            && bound.path.canonicalize()? == bound.path,
        "noncanonical evidence binding"
    );
    let (sha, m) = hash_file(&bound.path, 1 << 20)?;
    ensure!(
        sha == bound.sha256 && m.uid() == 0 && m.mode() & 0o222 == 0,
        "mutable or mismatching evidence"
    );
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&bound.path)?
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1 << 20
            && format!("{:x}", Sha256::digest(&bytes)) == bound.sha256
            && identity(&m) == identity(&fs::symlink_metadata(&bound.path)?),
        "evidence changed at decode"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
pub(crate) fn properties(unit: &str, names: &str) -> Result<BTreeMap<String, String>> {
    let result = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--no-pager", "--property", names])
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 65536,
        "unit properties unavailable"
    );
    let mut values = BTreeMap::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("malformed property")?;
        ensure!(
            values.insert(key.into(), value.into()).is_none(),
            "duplicate property"
        );
    }
    Ok(values)
}
pub(crate) fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-epoch203-ram-retain-plan-v1",
        "wrong retention schema"
    );
    ["baseline", "shrink"]
        .into_iter()
        .find(|family| {
            p.producer_unit
                .starts_with(&format!("horizon-203-ram-resource-{family}-"))
                && p.run_root
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.starts_with(&format!("ram-resource-203-{family}-")))
        })
        .context("retention owner namespace differs")?;
    ensure!(
        p.run_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && p.run_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)))
            && p.producer_unit.ends_with(".service")
            && p.producer_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && hex(&p.producer_invocation_id, 32)
            && hex(&p.mount_invocation_id, 32)
            && p.mount_unit.ends_with(".mount")
            && p.mount_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.\\".contains(&b))
            && p.mount_device[0] == 0
            && p.mount_device[1] > 0
            && p.root_inode > 0,
        "unsafe retention scope"
    );
    ensure!(
        p.output.file_name().is_some_and(|s| s == "retention.json")
            && p.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-203-ram-retention-")),
        "retention output is not durable private metadata"
    );
    ensure!(
        !p.expected_files.is_empty() && p.expected_files.len() <= 128,
        "invalid artifact census"
    );
    for (path, sha) in &p.expected_files {
        ensure!(
            hex(sha, 64)
                && !path.starts_with('/')
                && !path
                    .split('/')
                    .any(|s| s.is_empty() || s == "." || s == "..")
                && ["output/", "receipts/", "ledger/"]
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
                && !path.ends_with(".sha256"),
            "invalid retained artifact path/digest"
        );
    }
    Ok(())
}
pub(crate) fn validate_terminal(values: &BTreeMap<String, String>, p: &Plan) -> Result<()> {
    for (key, expected) in [
        ("Id", p.producer_unit.as_str()),
        ("LoadState", "loaded"),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Triggers", ""),
        ("TriggeredBy", ""),
    ] {
        ensure!(
            values.get(key).map(String::as_str) == Some(expected),
            "terminal owner gate differs: {key}"
        );
    }
    ensure!(
        matches!(
            values.get("ActiveState").map(String::as_str),
            Some("inactive" | "failed")
        ),
        "retention owner is live or unreadable"
    );
    // systemd clears InvocationID after some oneshot exits. A nonempty different
    // identity must still reject. The sealed outcome preserves the exact owner.
    ensure!(
        values
            .get("InvocationID")
            .is_some_and(|s| s.is_empty() || s == &p.producer_invocation_id),
        "terminal owner was replaced"
    );
    Ok(())
}
pub(crate) fn validate_outcome(outcome: &Value, p: &Plan) -> Result<()> {
    let sandbox = match outcome["schema"].as_str() {
        Some("jetstreamer-private-epoch203-ram-supervisor-storage-capability-v1") => {
            &outcome["sandbox"]
        }
        Some("jetstreamer-private-epoch203-ram-bounded-resource-v1") => {
            &outcome["storage_evidence"]["sandbox"]
        }
        _ => anyhow::bail!("unsupported RAM retention outcome"),
    };
    ensure!(
        outcome["unit"] == p.producer_unit
            && outcome["invocation_id"] == p.producer_invocation_id
            && sandbox["run_root"].as_str() == p.run_root.to_str()
            && sandbox["mount_unit"] == p.mount_unit
            && sandbox["mount_invocation_id"] == p.mount_invocation_id
            && sandbox["mount_device"] == json!(p.mount_device),
        "outcome is not the exact RAM owner and mount generation"
    );
    Ok(())
}

pub(crate) fn mount(p: &Plan) -> Result<(BTreeMap<String, String>, u64)> {
    let values = properties(
        &p.mount_unit,
        "Id,InvocationID,ActiveState,SubState,What,Where,Type,StopWhenUnneeded,BindsTo,PartOf",
    )?;
    for (key, value) in [
        ("Id", p.mount_unit.as_str()),
        ("InvocationID", p.mount_invocation_id.as_str()),
        ("ActiveState", "active"),
        ("SubState", "mounted"),
        ("What", "tmpfs"),
        ("Type", "tmpfs"),
        ("StopWhenUnneeded", "no"),
        ("BindsTo", ""),
        ("PartOf", ""),
        ("Where", p.run_root.to_str().context("non-UTF8 root")?),
    ] {
        ensure!(
            values.get(key).map(String::as_str) == Some(value),
            "persistent mount gate differs: {key}"
        );
    }
    ensure!(
        p.run_root.canonicalize()? == p.run_root,
        "retention root is not exact"
    );
    let m = fs::symlink_metadata(&p.run_root)?;
    ensure!(
        m.is_dir()
            && m.ino() == p.root_inode
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o777 == 0o700
            && [
                u64::from(libc::major(m.dev())),
                u64::from(libc::minor(m.dev()))
            ] == p.mount_device,
        "retention mount inode/device changed"
    );
    let path = std::ffi::CString::new(p.run_root.as_os_str().as_encoded_bytes())?;
    let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
    let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statfs(path.as_ptr(), &mut stats) } == 0
            && stats.f_type == 0x01021994
            && unsafe { libc::statvfs(path.as_ptr(), &mut space) } == 0
            && space.f_blocks.checked_mul(space.f_frsize) == Some(768u64 << 30),
        "retention backend differs"
    );
    Ok((values, m.dev()))
}
pub(crate) fn inventory(p: &Plan, device: u64) -> Result<Value> {
    inventory_owned(p, device, 1000, 1000)
}

fn inventory_owned(p: &Plan, device: u64, uid: u32, gid: u32) -> Result<Value> {
    let mut pending = vec![p.run_root.clone()];
    let mut files = BTreeMap::new();
    let mut entries = 0;
    let mut physical = 0u64;
    let mut directories = BTreeSet::new();
    while let Some(path) = pending.pop() {
        entries += 1;
        ensure!(entries <= 1_000_000, "retention tree exceeds entry budget");
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.dev() == device
                && m.uid() == uid
                && m.gid() == gid
                && m.mode() & 0o077 == 0
                && (m.is_file() || m.is_dir())
                && (!m.is_file() || m.nlink() == 1),
            "foreign/link/special retention entry: {}",
            path.display()
        );
        physical = physical
            .checked_add(m.blocks().checked_mul(512).context("block overflow")?)
            .context("tree overflow")?;
        ensure!(
            physical <= 224u64 << 30,
            "retained tree exceeds RAM file budget"
        );
        let relative = path
            .strip_prefix(&p.run_root)?
            .to_str()
            .context("non-UTF8 artifact")?;
        if m.is_dir() {
            if path.parent() == Some(p.run_root.as_path()) {
                directories.insert(relative.to_string());
            }
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if !relative.starts_with("scratch/") {
            let expected = p
                .expected_files
                .get(relative)
                .context("unplanned retained artifact")?;
            let (sha, m) = hash_file(&path, 16u64 << 30)?;
            ensure!(&sha == expected, "retained artifact digest mismatch");
            files.insert(
                relative.to_string(),
                json!({"sha256":sha,"bytes":m.len(),"device":m.dev(),"inode":m.ino()}),
            );
        }
    }
    ensure!(
        directories
            == BTreeSet::from_iter(
                ["scratch", "output", "ledger", "tmp", "receipts"].map(String::from)
            )
            && files.len() == p.expected_files.len(),
        "retention tree census differs"
    );
    Ok(
        json!({"entries":entries,"physical_bytes":physical,"files":files,"scratch_content_hashed":false}),
    )
}
/// Execute the non-destructive retention CLI with separately bound inputs.
pub fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "retention inspection requires root"
    );
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "usage: retain PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let (sha, m) = hash_file(&exe, 32 << 20)?;
    ensure!(
        sha == args[5] && m.uid() == 0 && m.mode() & 0o222 == 0,
        "unsealed retention executable"
    );
    let binding = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_value(bound_json(&binding)?)?;
    validate_plan(&p)?;
    let parent = p.output.parent().context("missing output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "unsafe metadata output directory"
    );
    ensure!(!p.output.try_exists()?, "retention receipt already exists");
    let outcome = bound_json(&p.outcome)?;
    validate_outcome(&outcome, &p)?;
    let names = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,Triggers,TriggeredBy,Result,ExecMainStatus,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic";
    let before = properties(&p.producer_unit, names)?;
    validate_terminal(&before, &p)?;
    let (mounted, device) = mount(&p)?;
    let refs = process_references::scan(Path::new("/proc"), &p.run_root)?;
    ensure!(
        refs.references.is_empty(),
        "RAM artifacts have live process references"
    );
    let artifacts = inventory(&p, device)?;
    ensure!(
        properties(&p.producer_unit, names)? == before && mount(&p)? == (mounted.clone(), device),
        "owner/mount changed during retention"
    );
    let report = json!({"schema":"jetstreamer-private-epoch203-ram-retained-artifacts-v1",
        "self_sha256":sha,"plan_sha256":binding.sha256,"unit":p.producer_unit,"invocation_id":p.producer_invocation_id,
        "run_root":p.run_root,"mount":mounted,"outcome_sha256":p.outcome.sha256,
        "artifacts":artifacts,"process_reference_scan":refs,"artifacts_retained_in_place":true,
        "durable_artifact_copy_created":false,"scratch_resumption_qualified":false,
        "retirement_authorized":false,"unmount_authorized":false,"replay_launch_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 1 << 20, "retention metadata exceeds bound");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p.output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!("{}", p.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn plan() -> Plan {
        serde_json::from_value(json!({"schema":"jetstreamer-private-epoch203-ram-retain-plan-v1",
            "run_root":"/home/ubuntu/.jetstreamer-private/ram-resource-203-baseline-test",
            "producer_unit":"horizon-203-ram-resource-baseline-test.service","producer_invocation_id":"a".repeat(32),
            "mount_unit":"retention-test.mount","mount_invocation_id":"b".repeat(32),"mount_device":[0,68],"root_inode":1,
            "outcome":{"path":"/sealed/outcome.json","sha256":"c".repeat(64)},
            "expected_files":{"ledger/genesis.tar.bz2":"d".repeat(64)},
            "output":"/var/lib/jetstreamer/horizon-203-ram-retention-test/retention.json"})).unwrap()
    }

    #[test]
    fn retain_scope_cannot_select_other_trees_sidecars_or_public_metadata() {
        validate_plan(&plan()).unwrap();
        for mutation in 0..6 {
            let mut p = plan();
            match mutation {
                0 => p.run_root = "/home/ubuntu/.jetstreamer-private".into(),
                1 => p.producer_unit = "horizon-qualify-203-root-prefix-resource-v1.service".into(),
                2 => {
                    p.expected_files =
                        BTreeMap::from([("output/../epoch-203.jet".into(), "d".repeat(64))])
                }
                3 => {
                    p.expected_files =
                        BTreeMap::from([("output/epoch-203.jet.sha256".into(), "d".repeat(64))])
                }
                4 => p.output = "/home/ubuntu/horizon/retention.json".into(),
                5 => p.mount_device = [0, 0],
                _ => unreachable!(),
            }
            assert!(validate_plan(&p).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn exact_terminal_owner_and_no_pending_trigger_are_required() {
        let p = plan();
        let values = BTreeMap::from_iter(
            [
                ("Id", p.producer_unit.as_str()),
                ("LoadState", "loaded"),
                ("MainPID", "0"),
                ("NRestarts", "0"),
                ("Restart", "no"),
                ("Triggers", ""),
                ("TriggeredBy", ""),
                ("ActiveState", "inactive"),
                ("InvocationID", ""),
            ]
            .map(|(k, v)| (k.into(), v.into())),
        );
        validate_terminal(&values, &p).unwrap();
        for (key, value) in [
            ("ActiveState", "active"),
            ("MainPID", "12"),
            ("TriggeredBy", "future.timer"),
            ("Restart", "on-failure"),
            ("InvocationID", "replacement"),
        ] {
            let mut wrong = values.clone();
            wrong.insert(key.into(), value.into());
            assert!(validate_terminal(&wrong, &p).is_err(), "{key}");
        }
    }

    #[test]
    fn outcome_binds_owner_root_and_persistent_mount_not_only_unit_name() {
        let p = plan();
        let outcome = json!({"schema":"jetstreamer-private-epoch203-ram-supervisor-storage-capability-v1",
            "unit":p.producer_unit,"invocation_id":p.producer_invocation_id,"sandbox":{
                "run_root":p.run_root,"mount_unit":p.mount_unit,"mount_invocation_id":p.mount_invocation_id,
                "mount_device":p.mount_device}});
        validate_outcome(&outcome, &p).unwrap();
        for key in [
            "run_root",
            "mount_invocation_id",
            "mount_unit",
            "mount_device",
        ] {
            let mut wrong = outcome.clone();
            wrong["sandbox"][key] = json!("changed");
            assert!(validate_outcome(&wrong, &p).is_err(), "{key}");
        }
    }

    #[test]
    fn artifact_inventory_is_exact_hashed_and_refuses_links_or_extra_files() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut p = plan();
        p.run_root = temp.path().into();
        for child in ["scratch", "output", "ledger", "tmp", "receipts"] {
            fs::create_dir(temp.path().join(child)).unwrap();
            fs::set_permissions(temp.path().join(child), fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let file = temp.path().join("ledger/genesis.tar.bz2");
        fs::write(&file, b"genesis fixture").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        p.expected_files.insert(
            "ledger/genesis.tar.bz2".into(),
            hash_file(&file, 100).unwrap().0,
        );
        let m = fs::metadata(temp.path()).unwrap();
        let result = inventory_owned(&p, m.dev(), m.uid(), m.gid()).unwrap();
        assert_eq!(result["files"].as_object().unwrap().len(), 1);
        assert_eq!(result["scratch_content_hashed"], false);
        symlink(&file, temp.path().join("output/link")).unwrap();
        assert!(inventory_owned(&p, m.dev(), m.uid(), m.gid()).is_err());
    }

    #[test]
    fn changing_digest_or_oversized_artifact_is_not_retained_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("file");
        fs::write(&path, b"0123456789").unwrap();
        assert!(hash_file(&path, 9).is_err());
        let sha = hash_file(&path, 10).unwrap().0;
        fs::write(&path, b"changed123").unwrap();
        assert_ne!(hash_file(&path, 10).unwrap().0, sha);
        let link = temp.path().join("alias");
        fs::hard_link(&path, &link).unwrap();
        assert!(hash_file(&path, 10).is_err());
    }
}
