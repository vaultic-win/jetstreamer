//! Input identities for the cold replay following the independent retry10 HOME stop.
use super::*;

pub(super) const ROOT_INODE: u64 = 93782068;
pub(super) const LOG_INODE: u64 = 93782084;
pub(crate) const BASE: &str = "epoch166-retry11-rebook-20261122-v1";
pub(crate) const UNIT: &str = "horizon-qualify-166-independent-retry11-20261122.service";
pub(crate) const TIMER: &str = "horizon-guard-166-independent-retry11-20261122.timer";
pub(crate) const ATTEMPT: &str = "replacement-local3retry10-20261121-v1/cold-retry11-20261122";
pub(crate) const GUARD_SHA: &str =
    "deef554d1c43e16ed6d4026e31918da8bec3ebf33f4e9ace8e6dfe67f5f2f557";
pub(crate) const GSEAL: &str = "769b72d0ae2744c55963e3ce2feeff7afdc11daa29b900a4bbd009e59e1949f2";
pub(crate) const CONTRACT: &str =
    "24f342477d6db8b7928f51efb0d141726003fb7a9e1bd8ef68b873559e073274";
pub(crate) const CSEAL: &str = "d3e09148aad7c42ca5ea4c2df2ef4fd30f89ac558475baa1c55fb8eebf6cbb84";
pub(crate) const WITNESS: &str = "337e0e80188d6d91393152af7ff2f33fd749190489c6e2bf350dd95392915076";
const CLEANUP: &str = "epoch166-independent-closed-accounts-20261122-v1";
const PREDECESSOR: &str = "epoch166-independent-cold-recovery-20261121-v1";
const PRIOR_UNIT: &str = "horizon-qualify-166-independent-recovery-20261121-v1.service";
const PRIOR_RUN: &str = "replacement-local3retry10-20261121-v1/private/destination-7a798c2c541f09bf18d3c3b33df9faa66e8609f5d416fb227745547144979d81/work/root-cohort-166-166/run-3866816-1795260845522831443";
const PRIOR_IID: &str = "3c220efd0d0740f59572a96447e83762";

pub(super) fn bootstrap() -> PathBuf {
    Path::new(LANE)
        .join(PRIOR_RUN)
        .join("scratch/.historical-runtime/jetstreamer-historical-parent-cXUtki/bound-bootstrap")
        .join(BOOT)
}

pub(super) fn snapshot(full: bool) -> Result<Value> {
    let path = bootstrap();
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let stamp = |m: fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let expected = (
        64512, 93782058, 0o100600, 1001, 1003, 1, 1968014870, 1795260856, 694454583, 1795260856,
        694454583,
    );
    ensure!(
        path.canonicalize()? == path && stamp(file.metadata()?) == expected,
        "retained HOME bootstrap changed"
    );
    if full {
        let mut hash = Sha256::new();
        std::io::copy(&mut file, &mut hash)?;
        ensure!(
            format!("{:x}", hash.finalize()) == BOOT_SHA,
            "retained bootstrap checksum differs"
        );
    }
    ensure!(
        stamp(file.metadata()?) == expected && stamp(fs::symlink_metadata(&path)?) == expected,
        "retained bootstrap moved during validation"
    );
    Ok(
        json!({"path":path,"device":expected.0,"inode":expected.1,"length":expected.6,"ctime":[expected.9,expected.10],"sha256":BOOT_SHA,"generation":1634787359098769u64}),
    )
}

pub(super) fn files() -> Result<Value> {
    let (roots, root_ref) = doc(
        &rt(CLEANUP).join("SUCCESSOR_ROOT.json"),
        Some("02ca91b396f6bc9327b626eb80583af4ce004d63fb6854c7a5e2c50f38c12329"),
    )?;
    let root = fs::symlink_metadata(run())?;
    ensure!(
        roots["root"] == json!(run())
            && roots["inode"] == ROOT_INODE
            && run().canonicalize()? == run()
            && (root.dev(), root.ino(), root.uid(), root.gid(), root.mode())
                == (64512, ROOT_INODE, 1001, 1003, 0o40700),
        "replacement directory or booking changed"
    );
    let dir = rt(PREDECESSOR).join("guard-receipts");
    let (stop, sr) = doc(
        &dir.join("stop-completion.json"),
        Some("a72e48f26f716ac397b974d73040fec59c68957ce21be60634627039b3e7cab6"),
    )?;
    let (intent, ir) = doc(
        &dir.join("stop-intent.json"),
        Some("2d7e50767cea5c8f4d411860cfd81f821d6302b15f594cfd9f739c315d45e786"),
    )?;
    ensure!(
        stop["intent"] == ir["path"]
            && stop["producer_invocation_id"] == PRIOR_IID
            && intent["producer_invocation_id"] == PRIOR_IID
            && intent["reason"] == "filesystem-floor"
            && stop["terminal"]["pid"] == 0
            && stop["scratch_deleted"] == false,
        "prior stop differs"
    );
    for unit in [OLD_UNIT, PRIOR_UNIT] {
        let m = native(unit)?;
        ensure!(
            m["ActiveState"] == "inactive" && m["MainPID"] == "0" && members(unit)?.is_empty(),
            "prior producer remains"
        );
    }
    for (attempt, digest) in [
        (
            "local3retry9",
            "da23e6cace88f26e708f6c9ed49042dc998f6abb5cdc3ad55581277c63365556",
        ),
        (
            "local3retry10",
            "03c0000e4aec797c6c161eae6d18621d5f8d29147638675175cb38a0ea4d76c8",
        ),
    ] {
        let (row, _) = doc(
            &rt(CLEANUP)
                .join("state")
                .join(attempt)
                .join("COMPLETE.json"),
            Some(digest),
        )?;
        ensure!(
            row["scope_empty"] == true && fs::read_dir(st(&row, "scope")?)?.next().is_none(),
            "closed AccountsDb changed"
        );
    }
    let (_, manifest) = doc(
        &Path::new(PACKAGE).join("preflight-166-v4.json"),
        Some(MANIFEST_SHA),
    )?;
    Ok(
        json!({"predecessor_stop":sr,"predecessor_intent":ir,"stable_roots":root_ref,"root":{"path":run(),"device":root.dev(),"inode":root.ino()},"snapshot":snapshot(false)?,"manifest":manifest,"profile":profile()?}),
    )
}

/// A full transfer to the host's scratch prefix and a separate local retirement fund this launch.
pub(crate) fn holding_complete() -> Result<()> {
    let park = rt("epoch166-retry10-holding-20261122-v1");
    let (plan, _) = doc(
        &park.join("PREPARED.json"),
        Some("dd02c73abfee1065873cf370e9a72d566717bd1b4efab4ae206032ce4424778e"),
    )?;
    let path = Path::new(st(&plan, "expected_receipt")?);
    let (custody, custody_ref) = doc(path, None)?;
    let archive = Path::new(LANE)
        .join(PRIOR_RUN)
        .join("archives/epoch-166.jet");
    ensure!(
        plan["closed_sources"]["local3retry10"]["source"]["path"] == json!(archive)
            && custody["schema"] == "jetstreamer-horizon-holding-custody-v2"
            && custody["source"] == json!(archive)
            && custody["remote_sha256_readback"] == true
            && custody["local_source_revalidated"] == true
            && custody["length"] == 64922604512u64
            && custody["sha256"] == plan["verified_digest"]
            && custody["object_key"] == plan["expected_object"]
            && custody["manifest_key"] == plan["expected_manifest"]
            && custody["manifest_sha256"] == plan["expected_manifest_sha256"]
            && custody["canonical_publication_authorized"] == false,
        "private holding custody incomplete"
    );
    let holding = Path::new("/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1");
    let state = holding.join("retirements");
    let quarantine = state.join(format!("epoch166-retry10-{}.jet", st(&custody, "sha256")?));
    let terminal_path = holding
        .join("receipts/epoch166-retry10-park-terminal-57146d4b5c9940449cd129433a5acd2b.json");
    let (terminal, terminal_ref) = doc(&terminal_path, None)?;
    let (intent, _) = doc(&state.join("epoch166-retry10-intent.json"), None)?;
    let (completion, _) = doc(&state.join("epoch166-retry10-completion.json"), None)?;
    let retired_custody = doc(
        Path::new(st(&intent["custody"], "path")?),
        Some(st(&custody_ref, "sha256")?),
    )?
    .0;
    let retired_terminal = doc(
        Path::new(st(&intent["park_terminal"], "path")?),
        Some(st(&terminal_ref, "sha256")?),
    )?
    .0;
    ensure!(
        terminal["custody"] == custody_ref
            && retired_custody == custody
            && retired_terminal == terminal
            && intent["schema"] == "jetstreamer-holding-retire166-retry10-intent-v1"
            && intent["source"] == json!(archive)
            && intent["quarantine"] == json!(quarantine)
            && intent["inode"] == 93782070
            && intent["length"] == custody["length"]
            && intent["sha256"] == custody["sha256"]
            && intent["custody"]["sha256"] == custody_ref["sha256"]
            && intent["park_terminal"]["sha256"] == terminal_ref["sha256"]
            && intent["inspection"]["sha256"]
                == "dd02c73abfee1065873cf370e9a72d566717bd1b4efab4ae206032ce4424778e"
            && intent["mapping"] == custody["mapping"]
            && intent["eligibility"] == custody["eligibility"],
        "retirement intent does not bind the original held partial and transfer"
    );
    verify_retirement(&completion, &intent, &archive, &quarantine)
}

fn verify_retirement(
    completion: &Value,
    intent: &Value,
    archive: &Path,
    quarantine: &Path,
) -> Result<()> {
    ensure!(
        completion["schema"] == "jetstreamer-holding-retire166-retry10-completion-v1"
            && completion["intent"] == *intent
            && completion["source_absent"] == true
            && completion["quarantine_absent"] == true
            && completion["authenticated_custody_revalidated"] == true
            && completion["retired_censused_physical_bytes"] == 64922697728u64
            && completion["actual_free_delta_claimed"] == false
            && completion["resource_credit_bytes"] == 0,
        "native retirement has not completed"
    );
    for path in [archive, quarantine] {
        ensure!(
            matches!(fs::symlink_metadata(path), Err(e) if e.kind()==std::io::ErrorKind::NotFound),
            "retired prefix still present at {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retirement_requires_native_completion_and_both_absences() {
        let lease = tempfile::tempdir().unwrap();
        let archive = lease.path().join("archive");
        let quarantine = lease.path().join("quarantine");
        let intent = json!({"source":archive,"quarantine":quarantine});
        let completion = json!({"schema":"jetstreamer-holding-retire166-retry10-completion-v1","intent":intent,
            "source_absent":true,"quarantine_absent":true,"authenticated_custody_revalidated":true,
            "retired_censused_physical_bytes":64922697728u64,"actual_free_delta_claimed":false,"resource_credit_bytes":0});
        assert!(verify_retirement(&completion, &intent, &archive, &quarantine).is_ok());
        fs::write(&quarantine, b"preserved until unlink").unwrap();
        assert!(verify_retirement(&completion, &intent, &archive, &quarantine).is_err());
        fs::rename(&quarantine, &archive).unwrap();
        assert!(verify_retirement(&completion, &intent, &archive, &quarantine).is_err());
        fs::remove_file(&archive).unwrap();
        for (key, bad) in [
            ("source_absent", json!(false)),
            ("quarantine_absent", json!(false)),
            ("retired_censused_physical_bytes", json!(0)),
            ("intent", json!({})),
            ("authenticated_custody_revalidated", json!(false)),
        ] {
            let mut changed = completion.clone();
            changed[key] = bad;
            assert!(
                verify_retirement(&changed, &intent, &archive, &quarantine).is_err(),
                "{key}"
            );
        }
    }
}
