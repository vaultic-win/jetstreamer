use super::*;

const DESTINATION: &str = "/home/sol/.jetstreamer-private/epochs122-147-20260922-v1/lane-k/private/destination-4040d89ae2c3ff0ab31bdaa642d8288c9ffbee25742a1d7a612eb1b583b296bd";
const RUN: &str = "work/root-cohort-144-147/run-850000-1791987386142844105";
const KEEPER: &str = "/home/sol/horizon/epoch-144.jet";
const CANONICAL_SHA: &str = "153d3e5e5b7cbdc31bb4229315786000b84442a75b3b83cf4a50184b20b84a33";
const CANONICAL_BYTES: u64 = 109_177_480_876;
const RECEIPT: &str = "/home/sol/.jetstreamer-private/r2-receipts/epoch-144.r2.json";
const RECEIPT_SHA: &str = "b3fc91d860bd61623229a1c420c45dcb28db1df70892084b2d58dbae8e853b3f";
const PUBLICATION: &str =
    "/var/lib/jetstreamer/horizon-epoch144-publication-evidence-20261022-v1/evidence.json";
const PUBLICATION_SHA: &str = "5196699c86959e9704269ae7dbfc1c9432ebc82eb40f305dca6dd56ded891f64";
const READER: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1/current-reader-tools-v2/verify_archive";
const READER_SHA: &str = "eec3a8093b52f7dd3a87d508b3b09e34680f2a5d887343cf12df70621d99f8a0";

pub(super) fn is_target(target: &Target) -> bool {
    let identity = &target.identity;
    target.epoch == 144
        && target.path
            == Path::new(DESTINATION)
                .join(RUN)
                .join("archives/epoch-144.jet")
        && identity.dev == 64512
        && identity.ino == 100401230
        && identity.len == 31_415_337_919
        && identity.blocks == 61_358_176
        && identity.uid == 1001
        && identity.gid == 1003
        && identity.mode == 0o100600
        && identity.nlink == 1
        && (identity.mtime, identity.mtime_ns) == (1_792_116_099, 593_666_447)
        && (identity.ctime, identity.ctime_ns) == (1_792_116_099, 593_666_447)
}

pub(super) fn lock_original_owner() -> Result<File> {
    let path = Path::new(DESTINATION).join("locks/epoch-144.lock");
    ensure!(path.canonicalize()? == path, "aliased lane K epoch lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file()
            && (m.dev(), m.ino(), m.uid(), m.gid(), m.nlink(), m.mode())
                == (64512, 100008008, 1001, 1003, 1, 0o100600),
        "different lane K epoch lock"
    );
    // The replay producer takes the same per-epoch lock.
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "lane K epoch 144 still has an owner"
    );
    Ok(lock)
}

fn record(path: &Path, sha256: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&bound(
        &Bound {
            path: path.into(),
            sha256: sha256.into(),
        },
        LIMIT,
    )?)?)
}

pub(super) fn check_owners() -> Result<()> {
    let matches = Command::new("/usr/bin/rg")
        .args([
            "--files-with-matches",
            "--fixed-strings",
            "run-850000-1791987386142844105",
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
            "/run/systemd/transient",
        ])
        .output()?;
    ensure!(
        matches.status.success() || matches.status.code() == Some(1),
        "cannot census scheduled lane K consumers"
    );
    let mut units = BTreeSet::new();
    for path in std::str::from_utf8(&matches.stdout)?.lines() {
        let unit = Path::new(path)
            .file_name()
            .and_then(|v| v.to_str())
            .context("invalid lane K unit path")?;
        ensure!(
            unit.ends_with(".service"),
            "possible scheduled lane K consumer: {path}"
        );
        ensure!(
            unit.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.@-".contains(&b)),
            "invalid lane K unit name"
        );
        units.insert(unit);
    }
    for unit in units {
        let output = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                unit,
                "-p",
                "ActiveState,MainPID,ControlPID,Job,TriggeredBy",
            ])
            .output()?;
        let state = std::str::from_utf8(&output.stdout)?
            .lines()
            .collect::<BTreeSet<_>>();
        ensure!(
            output.status.success()
                && (state.contains("ActiveState=inactive") || state.contains("ActiveState=failed"))
                && ["MainPID=0", "ControlPID=0", "Job=", "TriggeredBy="]
                    .iter()
                    .all(|property| state.contains(property)),
            "lane K consumer is live or scheduled: {unit}"
        );
    }
    Ok(())
}

pub(super) fn verify(plan: &Plan, mutation_lock: &File) -> Result<()> {
    let [target] = plan.targets.as_slice() else {
        anyhow::bail!("lane K epoch 144 must retire individually");
    };
    let [proof] = plan.proofs.as_slice() else {
        anyhow::bail!("missing canonical epoch 144 receipt");
    };
    let lock_meta = mutation_lock.metadata()?;
    ensure!(
        is_target(target)
            && proof.epoch == 144
            && proof.receipt.path == Path::new(RECEIPT)
            && proof.receipt.sha256 == RECEIPT_SHA
            && (
                lock_meta.dev(),
                lock_meta.ino(),
                lock_meta.uid(),
                lock_meta.gid()
            ) == (64512, 101135013, 1001, 1003),
        "different lane K retirement, receipt or mutation lock"
    );
    let run_state = record(
        &Path::new(DESTINATION).join(RUN).join("cohort-state.json"),
        "8ab14e50cc1b636233967fdd3585844a47367fe0cfd3496d8830ed0b3fb1b03c",
    )?;
    let published = record(Path::new(PUBLICATION), PUBLICATION_SHA)?;
    let keeper = exact(Path::new(KEEPER))?;
    let sidecar = Path::new("/home/sol/horizon/epoch-144.jet.sha256");
    ensure!(
        run_state["schema"] == "jetstreamer-root-cohort-run-v1"
            && run_state["start_epoch"] == 144
            && published["epoch"] == 144
            && published["archive_bytes"] == CANONICAL_BYTES
            && published["archive_sha256"] == CANONICAL_SHA
            && published["independent_full_and_plugin_receipts_validated"] == true
            && (keeper.dev(), keeper.ino(), keeper.len()) == (64512, 95225627, CANONICAL_BYTES)
            && keeper.mode() & 0o222 == 0
            && exact(sidecar)?.len() <= 256
            && fs::read_to_string(sidecar)? == format!("{CANONICAL_SHA}  epoch-144.jet\n"),
        "canonical epoch 144 does not supersede the selected partial"
    );
    check_owners()?;
    let reader = exact(Path::new(READER))?;
    ensure!(
        reader.uid() == 0 && reader.mode() & 0o222 == 0 && digest(Path::new(READER))? == READER_SHA,
        "different sealed archive reader"
    );
    let output = Command::new(READER)
        .arg(&target.path)
        .args(["1", "62208000"])
        .output()?;
    ensure!(
        !output.status.success()
            && std::str::from_utf8(&output.stderr)?.contains("open archive: bad magic bytes"),
        "source no longer matches the incomplete lane K archive"
    );
    check_target(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_k_retirement_selects_only_the_original_partial() -> Result<()> {
        let mut target: Target = serde_json::from_value(json!({
            "epoch":144,
            "path":Path::new(DESTINATION).join(RUN).join("archives/epoch-144.jet"),
            "reason":"superseded incomplete lane K partial",
            "identity":{
                "dev":64512,"ino":100401230,"len":31_415_337_919u64,"blocks":61358176,
                "uid":1001,"gid":1003,"mode":33152,"nlink":1,
                "mtime":1792116099,"mtime_ns":593666447,
                "ctime":1792116099,"ctime_ns":593666447
            }
        }))?;
        assert!(is_target(&target));
        target.identity.ino = 95225627;
        assert!(!is_target(&target));
        target.identity.ino = 100401230;
        target.path = PathBuf::from(KEEPER);
        assert!(!is_target(&target));
        Ok(())
    }
}
