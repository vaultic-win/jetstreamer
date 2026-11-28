//! Validate retained G2 and G3 evidence before opening the separate G4 execution namespace.
use super::*;
use std::collections::BTreeSet;
pub(super) const OLD_SOURCE: &str = "bf733bf0549bcaddd33a21b382ab5014297f34cd";
const G2_SOURCE: &str = "5a67854cac09dbc4b73b9136d667f2d47c69b040";
const OLD: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-admission-20261120-v2";
const OLD_IID: &str = "5986d31775c647fc971d4bd41a482158";
const OLD_TIMER_IID: &str = "3c5bc20091094872994b7ee7047fe82c";
const OLD_GUARD_IID: &str = "0c29c33ca3a743d7be4b65106449e15f";
const OLD_FLOOR: u64 = 8_513_508_777_282;
const OLD_UNIT: &str = "horizon-qualify-169-focused-20261120-v2.service";
const PINS: &[(&str, &str)] = &[
    (
        "PREFLIGHT.json",
        "3d730a513a6d124d77a486d3fe1de45632d75feaba8152b499d7236eca7676d4",
    ),
    (
        "RETRY1_COLD_SETUP.json",
        "d9b3b66497ffd6bc47501d925df416506a1c15a19158450f9c1cc28022012b38",
    ),
    (
        "RETRY1_PREFLIGHT.json",
        "30afbbeb1d8b49e6569f262c1f932d27584d9fb316a73ed3711e93b028a9325e",
    ),
    (
        "FINAL_PRELAUNCH_FIT.json",
        "4c3a0ef92da2ebbf275bf5ef40887615ffa6fae1812e792187d00698283480ac",
    ),
    (
        "FAILED_SETUP.json",
        "331955f986f9c84c06759a9ed545c4b3c1aaa1f9ea2100be7b14de7b7bf54710",
    ),
    (
        "FIRST_GUARD.json",
        "335cd7b43ee1c6895fbe94c9acbd2b4190c88e54c934d243df03ad51f341b1c5",
    ),
    (
        "ACTUAL_GUARD_PLAN.json",
        "de464d031256e4c172ab305e98d730e13eb93c4a1a14ee54adfc8499938ec367",
    ),
    (
        "PRODUCER_NATIVE.json",
        "ec0559addb99b182fb8ac037fa74453b5591bcb6b41e4ec84ea7acad5c35e3cb",
    ),
    (
        "admission-v1/deployment-seal-receipt.json",
        "fcf906c9a087220848d90d639f01822f149490c0993a75c1983e6fa56c842c22",
    ),
    (
        "admission-v1/artifact-proof.json",
        "8c2e902dd0550dc16e2963e6a7727130575441d525b4cd10016672ae83bd0183",
    ),
    (
        "admission-retry1-v1/deployment-seal-receipt.json",
        "6eddc34d96da24e19f4264d1bfb555a79cb985d089df6fb8d32e73b7541f5dfa",
    ),
    (
        "admission-retry1-v1/artifact-proof.json",
        "29533a5dc0df3d7f5e8a3010d0b7e3fff06bd4a19debcee9e9723937ccd0a26a",
    ),
];
const SAMPLES: &[(&str, &str)] = &[
    (
        "sample-0c29c33ca3a743d7be4b65106449e15f.json",
        "81c7a79351d1761f932944aad3fe8555d2a4bbbde9d73b3c6f12af1fe2adaf23",
    ),
    (
        "sample-0bc3fd250944495599f04a82a648175f.json",
        "255a1ae4985e931aac44a494b3018bc836689b824e684b3ce98e9cb802dc1e99",
    ),
    (
        "sample-e95be2df5256428095f43d3547097f97.json",
        "a275fb341053b4ac055991ef27cff3fc81edcf33e7a7cf437dc58822a418d437",
    ),
];
fn names(path: &Path) -> Result<BTreeSet<String>> {
    fs::read_dir(path)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 entry"))
        })
        .collect()
}
fn entries(path: &Path, expected: &[&str]) -> Result<()> {
    ensure!(
        names(path)? == expected.iter().map(|s| s.to_string()).collect(),
        "unexpected stage entries: {}",
        path.display()
    );
    Ok(())
}
fn checked_file(
    path: &Path,
    inode: Option<u64>,
    uid: u32,
    gid: u32,
    mode: u32,
    len: u64,
) -> Result<File> {
    ensure!(path.canonicalize()? == path, "noncanonical custody file");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.dev() == fs::metadata("/home/sol")?.dev()
            && inode.is_none_or(|i| m.ino() == i)
            && m.uid() == uid
            && m.gid() == gid
            && m.mode() & 0o7777 == mode
            && m.len() == len
            && m.nlink() == 1,
        "changed custody file {}",
        path.display()
    );
    Ok(f)
}
pub(super) fn open_lock() -> Result<File> {
    checked_file(
        &Path::new(OLD).join("admission.lock"),
        Some(101132300),
        0,
        0,
        0o600,
        0,
    )
}
fn lineage(failure: &Value, first: &Value, plan: &Value, producer: &Value) -> Result<()> {
    ensure!(
        failure["error"] == "post-guard protected floor increased"
            && failure["rolled_back"] == true
            && failure["rollback_error"].is_null()
            && failure["remote_mutations"] == false
            && first["genuine_first_timer_driven_success"] == true
            && first["raw_floor_bytes"] == OLD_FLOOR
            && first["producer"]["Id"] == OLD_UNIT
            && first["producer"]["InvocationID"] == OLD_IID
            && first["producer"]["MainPID"] == "2955906"
            && first["timer"]["InvocationID"] == OLD_TIMER_IID
            && first["guard"]["InvocationID"] == OLD_GUARD_IID
            && producer["InvocationID"] == OLD_IID
            && producer["MainPID"] == "2955906"
            && plan["unit"] == OLD_UNIT
            && plan["invocation_id"] == OLD_IID
            && plan["minimum_free_bytes"] == OLD_FLOOR,
        "failed G2 first-guard/rollback lineage differs"
    );
    Ok(())
}
fn drained(unit: &str) -> Result<()> {
    peers::idle(unit)?;
    let path = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    if path.try_exists()? {
        ensure!(
            fs::read_to_string(path.join("cgroup.events"))?
                .lines()
                .any(|s| s == "populated 0"),
            "retained cgroup populated {unit}"
        );
    }
    Ok(())
}
fn retained() -> Result<Value> {
    let old = Path::new(OLD);
    custody(old, 0, 0, Some(101131907), 0o700)?;
    let mut documents = json!({});
    let mut refs = json!({});
    for (name, sha) in PINS {
        documents[*name] = json_pin(&old.join(name), sha)?;
        refs[*name] = binding(&old.join(name), sha);
    }
    lineage(
        &documents["FAILED_SETUP.json"],
        &documents["FIRST_GUARD.json"],
        &documents["ACTUAL_GUARD_PLAN.json"],
        &documents["PRODUCER_NATIVE.json"],
    )?;
    ensure!(
        documents["admission-retry1-v1/artifact-proof.json"]["source_commit"] == G2_SOURCE
            && documents["RETRY1_COLD_SETUP.json"]["schema"] == "epoch169-g2-pre-spawn-custody-v1",
        "retained source/cold stage changed"
    );
    for name in [
        "AUTHORIZED_GATED_PAYLOAD.json",
        "POST_GUARD_CAPACITY.json",
        "VERIFIED_STAGING.json",
        "ACTUAL_ADMISSION_AND_PROTECTION.json",
    ] {
        ensure!(
            fs::symlink_metadata(old.join(name))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "G2 progressed beyond denied floor: {name}"
        );
    }
    custody(&old.join("barrier"), 0, 0, Some(101132303), 0o755)?;
    entries(&old.join("barrier"), &[])?;
    custody(&old.join("guard-receipts"), 0, 0, Some(101132302), 0o700)?;
    entries(
        &old.join("guard-receipts"),
        &SAMPLES.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
    )?;
    for (name, sha) in SAMPLES {
        let path = old.join("guard-receipts").join(name);
        let s = json_pin(&path, sha)?;
        ensure!(
            s["producer_invocation_id"] == OLD_IID
                && s["workers"] == json!([])
                && s["trip_reason"].is_null(),
            "old guard advanced/tripped"
        );
        refs[*name] = binding(&path, sha);
    }
    ensure!(
        documents["FIRST_GUARD.json"]["receipt"] == refs[SAMPLES[0].0],
        "old first sample binding"
    );
    checked_file(
        &old.join("guard.stdout"),
        Some(101132304),
        0,
        0,
        0o600,
        5070,
    )?;
    pinned(
        &old.join("guard.stdout"),
        "fec29e6163748336e6bb7c424962f11d594af9d43e45e07dfa09449833768abc",
    )?;
    checked_file(&old.join("guard.stderr"), Some(101132305), 0, 0, 0o600, 0)?;
    let prior_attempt = Path::new(LANE).join("attempt-g2");
    custody(&prior_attempt, 1001, 1003, Some(113313296), 0o700)?;
    entries(&prior_attempt, &["producer.log"])?;
    checked_file(
        &prior_attempt.join("producer.log"),
        Some(113313521),
        1001,
        1003,
        0o600,
        0,
    )?;
    for unit in [
        OLD_UNIT,
        "horizon-guard-169-focused-20261120-v2.service",
        "horizon-guard-169-focused-20261120-v2.timer",
    ] {
        drained(unit)?;
    }
    open_lock()?;
    Ok(
        json!({"retained":refs,"failed_invocation":OLD_IID,"first_guard_invocation":OLD_GUARD_IID,
        "rollback_verified":true,"barrier_still_empty":true,"old_producer_log_bytes":0,"resource_credit_bytes":0}),
    )
}
fn retained_g3() -> Result<Value> {
    let root = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-admission-20261120-v3",
    );
    let previous = root.join("ACTUAL_ADMISSION_AND_PROTECTION.json");
    let admission_sha = "10183aa990641c4d41fcce37ce9ee6c27cbac25c67a72c09b100fdccd1fa7084";
    let admission = json_pin(&previous, admission_sha)?;
    let terminal_path = root.join("TRANSFER_TERMINAL.json");
    let terminal_sha = "511c7c8bbdf7788fb76f4e99f0bf2ed0dc5fddc76295218af7af4f0cd3e8d260";
    let terminal = json_pin(&terminal_path, terminal_sha)?;
    ensure!(
        terminal["admission"] == binding(&previous, admission_sha)
            && terminal["native"]["InvocationID"] == admission["producer_invocation_id"]
            && terminal["restored_slot"] == 73007829
            && terminal["transaction_replay_confirmed"] == false,
        "G3 transfer lineage"
    );
    for key in ["post_guard_capacity", "last_guard_sample"] {
        let r = &terminal[key];
        pinned(Path::new(at(r, "path")?), at(r, "sha256")?)?;
    }
    let log_path = Path::new(LANE).join("attempt-g3/producer.log");
    let mut log = checked_file(&log_path, Some(114236973), 1001, 1003, 0o600, 5615)?;
    let mut bytes = Vec::new();
    log.read_to_end(&mut bytes)?;
    ensure!(
        terminal["producer_log"] == binding(&log_path, &digest(&bytes)),
        "G3 producer log changed"
    );
    for u in [
        "horizon-qualify-169-focused-20261120-v3.service",
        "horizon-guard-169-focused-20261120-v3.service",
        "horizon-guard-169-focused-20261120-v3.timer",
    ] {
        drained(u)?;
    }
    let proof = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch169-index-projection-20261120-v1",
    );
    let comparison = proof.join("full-comparison.json");
    let hash = "a7fafc89d8e40168b6efde85134d4966251b641eac5e01297fdaf67633e41ef9";
    let verified = json_pin(&comparison, hash)?;
    ensure!(
        verified["matched_all_bytes"] == true
            && verified["bytes"] == 4_322_853_290u64
            && verified["source"] == json!(Path::new(cache::SOURCE).join(cache::CID))
            && verified["sha256"]
                == "e30ef8ef05b5f29deea60efad6ed6f2a75511447b26a94c529412d14897b04a4",
        "invalid index comparison"
    );
    let projection = proof.join("projection.json");
    let projection_sha = "82cfef595094cc89738f93ce3fc014041ea83d9d7c537a29dabefe418963d48a";
    json_pin(&projection, projection_sha)?;
    Ok(
        json!({"terminal":binding(&terminal_path,terminal_sha),"comparison":binding(&comparison,hash),"projection":binding(&projection,projection_sha)}),
    )
}
pub(super) fn cold() -> Result<Value> {
    let retained = retained()?;
    let g3 = retained_g3()?;
    let root = Path::new(BASE);
    custody(root, 0, 0, None, 0o700)?;
    let mandatory = [
        "admission-v1",
        "barrier",
        "guard-receipts",
        "guard.stdout",
        "guard.stderr",
    ];
    let optional = [
        "artifact-proof.json",
        "controller-plan.json",
        "native-controls.log",
    ];
    let found = names(root)?;
    ensure!(
        mandatory.iter().all(|s| found.contains(*s))
            && found
                .iter()
                .all(|s| mandatory.contains(&s.as_str()) || optional.contains(&s.as_str())),
        "G4 runtime is not a clean prepared namespace"
    );
    for (name, mode) in [("barrier", 0o755), ("guard-receipts", 0o700)] {
        custody(&root.join(name), 0, 0, None, mode)?;
        entries(&root.join(name), &[])?;
    }
    for name in ["guard.stdout", "guard.stderr"] {
        checked_file(&root.join(name), None, 0, 0, 0o600, 0)?;
    }
    custody(Path::new(LANE), 1001, 1003, Some(111744585), 0o700)?;
    let attempt = Path::new(ATTEMPT);
    custody(attempt, 1001, 1003, None, 0o700)?;
    entries(attempt, &["producer.log"])?;
    let log =
        checked_file(&attempt.join("producer.log"), None, 1001, 1003, 0o600, 0)?.metadata()?;
    for unit in [UNIT, GUARD_SERVICE, TIMER] {
        unused(unit)?;
        drained(unit)?;
    }
    let jobs = run(
        "/usr/bin/systemctl",
        &["list-jobs".into(), "--no-legend".into(), "--plain".into()],
        bounded(),
    )?;
    ensure!(
        !jobs
            .lines()
            .filter_map(|s| s.split_whitespace().nth(1))
            .any(|s| s.starts_with("horizon-")
                && s.contains("169")
                && (s.starts_with("horizon-qualify-")
                    || s.starts_with("horizon-guard-")
                    || s.starts_with("horizon-admit-"))),
        "pending 169 job"
    );
    Ok(
        json!({"schema":"epoch169-g4-index-retry-cold-custody-v1","retained_g2":retained,"retained_g3":g3,
        "runtime_inode":fs::metadata(root)?.ino(),"runtime_entries":found,"attempt":attempt,
        "attempt_inode":fs::metadata(attempt)?.ino(),"producer_log_inode":log.ino(),"producer_log_bytes":0,
        "original_admission_lock":Path::new(OLD).join("admission.lock"),"admission_lock_inode":101132300,
        "native_units_unused":[UNIT,GUARD_SERVICE,TIMER],"cgroups_unpopulated":true,"recorded_at":now()?,"resource_credit_bytes":0}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires immutable production receipts and drained G2/G3 services"]
    fn original_index_failure_and_remote_comparison() {
        retained().unwrap();
        retained_g3().unwrap();
        cache::host_cache(Path::new(DEST)).unwrap();
        cache::scratch(&Path::new(DEST).join("scratch")).unwrap();
    }

    #[test]
    fn different_guard_or_unsuccessful_rollback_cannot_fund_retry() {
        let failure = json!({"error":"post-guard protected floor increased","rolled_back":true,"rollback_error":null,"remote_mutations":false});
        let producer = json!({"Id":OLD_UNIT,"InvocationID":OLD_IID,"MainPID":"2955906"});
        let first = json!({"genuine_first_timer_driven_success":true,"raw_floor_bytes":OLD_FLOOR,"producer":producer,
            "timer":{"InvocationID":OLD_TIMER_IID},"guard":{"InvocationID":OLD_GUARD_IID}});
        let plan = json!({"unit":OLD_UNIT,"invocation_id":OLD_IID,"minimum_free_bytes":OLD_FLOOR});
        lineage(&failure, &first, &plan, &producer).unwrap();
        let mut bad = first.clone();
        bad["guard"]["InvocationID"] = json!("f".repeat(32));
        assert!(lineage(&failure, &bad, &plan, &producer).is_err());
        let mut bad = failure;
        bad["rolled_back"] = json!(false);
        assert!(lineage(&bad, &first, &plan, &producer).is_err());
    }
    #[test]
    fn fresh_stage_cannot_contain_an_old_release_token() {
        let dir = tempfile::tempdir().unwrap();
        entries(dir.path(), &[]).unwrap();
        fs::write(dir.path().join("allow"), OLD_IID).unwrap();
        assert!(entries(dir.path(), &[]).is_err());
    }
}
