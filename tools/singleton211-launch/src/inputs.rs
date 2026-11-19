//! Full immutable input hash outside the short startup clock; identity recheck inside it.
use super::*;

fn files() -> Vec<(Bound, Option<u64>)> {
    vec![
        (Bound::new(NODE, NODE_SHA), None),
        (Bound::new(WORKER, WORKER_SHA), None),
        (Bound::new(PREFLIGHT, PREFLIGHT_SHA), None),
        (
            Bound::new(Path::new(INPUT).join(SNAPSHOT), SNAPSHOT_SHA),
            Some(8_731_506_223),
        ),
        (
            Bound::new(Path::new(INPUT).join("genesis.tar.bz2"), GENESIS_SHA),
            Some(20_144),
        ),
    ]
}
fn native() -> Result<()> {
    let v = Bound::new(NATIVE_PROOF, NATIVE_PROOF_SHA).sealed()?;
    no_authority(&v)?;
    ensure!(
        v["schema"] == "jetstreamer-private-epoch211-native-terminal-proof-v1"
            && v["epoch"] == 211
            && v["native_input_qualified"] == true
            && v["invocation_id"] == "9267f2c2c64949c29b9da7c27a46df94"
            && v["native_marker"]["slot"] == "91151575"
            && v["native_marker"]["accounts_hash"] == "xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx"
            && v["native_marker"]["replay_entries"] == "0"
            && v["native_marker"]["bootstrap_writes"] == "0"
            && v["terminal_manager"]["Result"] == "success"
            && v["terminal_manager"]["ExecMainStatus"] == "0"
            && v["terminal_manager"]["MainPID"] == "0"
            && v["terminal_manager"]["ControlPID"] == "0"
            && v["terminal_manager"]["NRestarts"] == "0",
        "actual native211 proof differs"
    );
    Ok(())
}
pub(super) fn validate(v: &Value) -> Result<()> {
    validate_identities(v)?;
    native()
}
pub(super) fn validate_scope(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-singleton211-input-capability-v1"
            && v["epoch"] == 211
            && v["all_inputs_rehashed"] == true
            && v["native_input"] == json!(Bound::new(NATIVE_PROOF, NATIVE_PROOF_SHA))
            && v["manifest_fingerprint"] == FINGERPRINT,
        "input capability differs"
    );
    no_authority(v)?;
    let actual = v["files"].as_array().context("input identities")?;
    let expected = files();
    ensure!(actual.len() == expected.len(), "input coverage");
    for (row, (binding, length)) in actual.iter().zip(expected) {
        ensure!(row["binding"] == json!(binding), "input binding differs");
        let id: Identity = serde_json::from_value(row["identity"].clone())?;
        ensure!(
            id.3 == 0 && id.4 & 0o222 == 0 && length.is_none_or(|n| id.2 == n),
            "hashed input custody differs"
        );
    }
    Ok(())
}
pub(super) fn validate_identities(v: &Value) -> Result<()> {
    validate_scope(v)?;
    for row in v["files"].as_array().context("input identities")? {
        let b = binding(&row["binding"])?;
        trusted_parents(&b.path)?;
        ensure!(
            row["identity"] == json!(identity(&b.path)?),
            "hashed input identity changed"
        );
    }
    Ok(())
}
pub(super) fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 5 && unsafe { libc::geteuid() } == 0,
        "usage: launcher inputs SELF_SHA256 NEW_EVIDENCE_DIRECTORY SEALED_DESTINATION"
    );
    ensure!(
        hex(&args[2], 64)
            && hash(Path::new("/proc/self/exe"))? == args[2]
            && fs::canonicalize("/proc/self/exe")? == Path::new(GATE),
        "capability helper image differs"
    );
    let evidence = PathBuf::from(&args[3]);
    let dest = PathBuf::from(&args[4]);
    for (p, prefix) in [
        (&evidence, "horizon-singleton211-input-execution-"),
        (&dest, "horizon-singleton211-input-capability-"),
    ] {
        ensure!(
            p.parent() == Some(Path::new("/var/lib/jetstreamer"))
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.starts_with(prefix)),
            "input destination namespace"
        );
        absent(p)?;
        trusted_parents(p)?;
    }
    fs::create_dir(&evidence)?;
    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700))?;
    let mut rows = Vec::new();
    for (b, length) in files() {
        trusted_parents(&b.path)?;
        let before = identity(&b.path)?;
        ensure!(
            before.3 == 0 && before.4 & 0o222 == 0 && length.is_none_or(|n| before.2 == n),
            "input custody"
        );
        ensure!(
            hash(&b.path)? == b.sha256 && identity(&b.path)? == before,
            "input body hash or identity differs"
        );
        rows.push(json!({"binding":b,"identity":before}));
    }
    native()?;
    let mut v = json!({"schema":"horizon-singleton211-input-capability-v1","epoch":211,
        "all_inputs_rehashed":true,"files":rows,"native_input":Bound::new(NATIVE_PROOF,NATIVE_PROOF_SHA),
        "manifest_fingerprint":FINGERPRINT,"helper_sha256":args[2],"recorded_unix_seconds":now()?});
    deny_authority(&mut v);
    validate(&v)?;
    let b = save_json(&evidence, "capability.json", &v)?;
    let mut n = Native {
        root: evidence,
        counter: 0,
        deadline: None,
    };
    n.seal(&dest, &[("capability.json", b.clone())])?;
    println!(
        "{}",
        json!(Bound::new(dest.join("capability.json"), b.sha256))
    );
    Ok(())
}
