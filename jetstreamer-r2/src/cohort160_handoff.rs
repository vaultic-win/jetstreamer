//! Exact pending/importing160 controller. Observations grant no publication authority.
use super::*;
use std::process::Command;
pub(super) const CONTROLLER: &str =
    "jetstreamer-epoch160-singleton-20261020-controller-v1-r2.service";
pub(super) const IID: &str = "f07e4e26c28642b8826b13d625edf89c";
pub(super) const ARCHIVE: &str =
    "/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1/lane-a/output/epoch-160.jet";
const STATE: &str = "/var/lib/jetstreamer-root-sweep-epoch160-singleton-20261020-v1/state.json";
const RECEIPT: &str = "/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1/lane-a/private/destination-586105dbe82bb0446e1b4c9295bfb7f16e3fc6f70ff439cab2672ef48275f8db/evidence/archive-batches/destination-000000000000fc00-0000000005f50114/batch-4a5b4e3389da9c015128758c5874e750c4d5f5b7995aec9b8fed296c4f00d743.json";
const RECEIPT_SHA: &str = "92c949f845d3c554cd2c6026b5ef970ece11425bdfe8ffc28eba39bf5d2bc237";
pub(super) fn binding_matches(unit: &str, iid: &str, origin: &str, origin_iid: &str) -> bool {
    unit == CONTROLLER
        && iid == IID
        && origin == cohort160_finalization::UNIT
        && origin_iid == cohort160_finalization::IID
}
pub(super) fn owner(v: &Value) -> Result<()> {
    for (k, x) in [
        ("Id", CONTROLLER),
        ("InvocationID", IID),
        ("MainPID", "2939001"),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("NRestarts", "0"),
    ] {
        ensure!(v[k] == x, "160 controller differs:{k}");
    }
    let argv = v["ExecStart"]
        .as_str()
        .and_then(|s| s.split_once(" ; ignore_errors="))
        .context("160 controller command")?
        .0;
    ensure!(
        hex_lower(&Sha256::digest(argv.as_bytes()))
            == "17fe3acf7573621193a7a5b2a0afca864bf10a0ff633c40efaed728329f0681a",
        "160 controller command changed"
    );
    Ok(())
}
fn state(s: &Value) -> Result<()> {
    let a = &s["assignments"]["lane-a"];
    ensure!(
        s["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3"
            && s["configuration_sha256"]
                == "45cdde5340b30b23f76ad1fccda509f13517320cb5572e6f7d4d089899d135e1"
            && s["assignments"].as_object().is_some_and(|a| a.len() == 1)
            && a["first_epoch"] == 160
            && a["last_epoch"] == 160
            && a["attempt"] == 1
            && a["unit"] == cohort160_finalization::UNIT
            && a["pid"] == 1237930
            && a["pid_start_time"] == 80665681
            && a["receipt"] == RECEIPT
            && a["failure"].is_null()
            && a["source_recovery"] != true
            && ((a["phase"] == "staged"
                && s["import_owner"].is_null()
                && a["import_unit"].is_null())
                || (a["phase"] == "importing" && s["import_owner"] == "lane-a")),
        "160 handoff state changed"
    );
    Ok(())
}
fn manager(records: &[Value], sample: u64) -> Result<Value> {
    let selected: Vec<_> = records
        .iter()
        .filter(|r| {
            r["UNIT"] == cohort160_finalization::UNIT
                && r["INVOCATION_ID"] == cohort160_finalization::IID
                && r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                && r["MESSAGE"]
                    == format!(
                        "{}: Deactivated successfully.",
                        cohort160_finalization::UNIT
                    )
        })
        .collect();
    ensure!(
        selected.len() == 1,
        "160 clean terminal manager missing/duplicated"
    );
    let t = selected[0]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("160 terminal time")?
        .parse::<u64>()?;
    ensure!(
        t == 1792683730017883 && t <= sample.checked_mul(1000000).context("160 time overflow")?,
        "160 terminal time differs/future"
    );
    Ok(selected[0].clone())
}
pub(super) fn observe(current: &Value, sample: u64) -> Result<Value> {
    owner(current)?;
    cohort160_finalization::inputs()?;
    let script = Path::new(
        "/usr/local/lib/jetstreamer/controller-epoch160-singleton-20261020-v2/adaptive-root-cohort-sweep.py",
    );
    let sm = fs::symlink_metadata(script)?;
    ensure!(
        sm.is_file()
            && sm.uid() == 0
            && sm.nlink() == 1
            && sm.mode() & 0o222 == 0
            && script.canonicalize()? == script
            && hex_lower(&Sha256::digest(read_stable_bounded(
                script,
                1 << 20,
                "160 controller script"
            )?)) == "62592209a3fc2b659ea4bfb924bbcf34435b4228c87e56232eb6b962b907023e",
        "160 controller script changed"
    );
    let proof = Path::new(
        "/var/lib/jetstreamer/horizon-epoch160-delivery-observations-20261022-v1/proof.json",
    );
    let b = read_stable_bounded(proof, 1 << 20, "160 terminal proof")?;
    ensure!(
        hex_lower(&Sha256::digest(&b))
            == "032dfc226e2c831ba82cdeaf84892dd49659952ff28a0062743adf49a1c1f564",
        "160 terminal proof changed"
    );
    let proof: Value = serde_json::from_slice(&b)?;
    let producer = fleet::unit(cohort160_finalization::UNIT)?;
    ensure!(
        producer["MainPID"] == "0"
            && producer["NRestarts"] == "0"
            && producer["Result"] == "success"
            && producer["ExecMainStatus"] == "0"
            && producer["ActiveState"] == "inactive"
            && producer["SubState"] == "dead"
            && ((producer["LoadState"] == "not-found" && producer["InvocationID"] == "")
                || (producer["LoadState"] == "loaded"
                    && producer["InvocationID"] == cohort160_finalization::IID)),
        "160 producer not cleanly terminal"
    );
    let out = Command::new("/usr/bin/journalctl")
        .args([
            "_PID=1",
            "_UID=0",
            &format!("UNIT={}", cohort160_finalization::UNIT),
            &format!("INVOCATION_ID={}", cohort160_finalization::IID),
            "-n",
            "64",
            "-o",
            "json",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1 << 20,
        "160 terminal manager journal unreadable"
    );
    let rows: Vec<Value> = std::str::from_utf8(&out.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let terminal = manager(&rows, sample)?;
    let meta = fs::symlink_metadata(STATE)?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.nlink() == 1 && meta.mode() & 0o077 == 0,
        "unsafe160 state"
    );
    let sb = read_stable_bounded(Path::new(STATE), 1 << 20, "160 controller state")?;
    let s: Value = serde_json::from_slice(&sb)?;
    state(&s)?;
    let rb = read_stable_bounded(Path::new(RECEIPT), 1 << 20, "160 committed source receipt")?;
    ensure!(
        hex_lower(&Sha256::digest(&rb)) == RECEIPT_SHA,
        "160 committed receipt changed"
    );
    let receipt: Value = serde_json::from_slice(&rb)?;
    ensure!(
        receipt["epochs"] == serde_json::json!([160])
            && receipt["outcome"]["kind"] == "committed"
            && receipt["outcome"]["members"]
                .as_array()
                .is_some_and(|a| a.len() == 1)
            && receipt["outcome"]["members"][0]["archive_sha256"]
                == "35897b5dcd00c2b36d143a21fe759be7ef5315f0912eb530dc36acad6013cdcc",
        "160 source scope differs"
    );
    let m = fs::symlink_metadata(ARCHIVE)?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 1001
            && m.mode() & 0o222 == 0
            && m.len() == 148095631232
            && Path::new(ARCHIVE).canonicalize()? == Path::new(ARCHIVE)
            && proof["evidence"]["archive"]["inode"] == m.ino()
            && proof["evidence"]["archive"]["device"] == m.dev(),
        "160 staged archive identity changed"
    );
    let importer = if s["assignments"]["lane-a"]["phase"] == "importing" {
        let name = s["assignments"]["lane-a"]["import_unit"]
            .as_str()
            .context("160 importer missing")?;
        ensure!(
            name == "jetstreamer-root-import-e160-s1-20261020-v1-r2-e160-160-2.service",
            "160 foreign importer"
        );
        let u = fleet::unit(name)?;
        let expected = format!(
            "{{ path=/usr/local/lib/jetstreamer/deploy-epoch160-singleton-20261020-v2/jetstreamer-node ; argv[]=/usr/local/lib/jetstreamer/deploy-epoch160-singleton-20261020-v2/jetstreamer-node 160 /home/sol/horizon --verify --recover-staged-cohort-only --cohort-manifest=/usr/local/lib/jetstreamer/deploy-epoch160-singleton-20261020-v2/preflight-160-singleton-v4.json --cohort-manifest-fingerprint=sha256:2e5c41babafac408dca76e0f9f203a5556bc50093bab7e924e65bbc129591266 --source-cohort-receipt={RECEIPT} --publish-through-epoch=160"
        );
        ensure!(
            u["ActiveState"] == "active"
                && u["SubState"] == "running"
                && u["NRestarts"] == "0"
                && u["MainPID"]
                    .as_str()
                    .is_some_and(|p| p.parse::<u32>().is_ok_and(|p| p > 0))
                && u["InvocationID"]
                    .as_str()
                    .is_some_and(|s| is_lower_hex(s, 32))
                && u["ExecStart"]
                    .as_str()
                    .and_then(|s| s.split_once(" ; ignore_errors="))
                    .is_some_and(|(a, _)| a == expected),
            "160 importer identity/command differs"
        );
        Some(u)
    } else {
        None
    };
    ensure!(
        fleet::unit(CONTROLLER)? == *current
            && fleet::unit(cohort160_finalization::UNIT)? == producer
            && read_stable_bounded(Path::new(STATE), 1 << 20, "160 state race")? == sb,
        "160 handoff changed during observation"
    );
    if let Some(u) = &importer {
        ensure!(
            fleet::unit(u["Id"].as_str().unwrap())? == *u,
            "160 importer changed"
        );
    }
    Ok(
        serde_json::json!({"schema":"jetstreamer-epoch160-controller-import-handoff-v1","controller":current,
        "producer":producer,"producer_terminal_manager":terminal,"controller_state":s,"importer":importer,
        "terminal_evidence":proof["evidence"]["events"],"source_receipt":RECEIPT,"source_receipt_sha256":RECEIPT_SHA,
        "archive_path":ARCHIVE,"archive_bytes":m.len(),"archive_inode":m.ino(),"archive_hash_performed":false,
        "publication_authorized":false,"r2_mutations":false,"replay_launch_authorized":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_binding_never_borrows_another_producer_or_origin() {
        assert!(binding_matches(
            CONTROLLER,
            IID,
            cohort160_finalization::UNIT,
            cohort160_finalization::IID
        ));
        assert!(!binding_matches(
            CONTROLLER,
            IID,
            cohort198_finalization::UNIT,
            cohort160_finalization::IID
        ));
        assert!(!binding_matches(
            CONTROLLER,
            "a",
            cohort160_finalization::UNIT,
            cohort160_finalization::IID
        ));
    }
    #[test]
    fn manager_requires_exact_clean_terminal_and_never_absence_alone() {
        let r = serde_json::json!({"UNIT":cohort160_finalization::UNIT,"INVOCATION_ID":cohort160_finalization::IID,"_PID":"1","_UID":"0","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{}: Deactivated successfully.",cohort160_finalization::UNIT),"__REALTIME_TIMESTAMP":"1792683730017883"});
        manager(&[r.clone()], 1792684000).unwrap();
        assert!(manager(&[], 1792684000).is_err());
        assert!(manager(&[r.clone(), r.clone()], 1792684000).is_err());
        assert!(manager(&[r.clone()], 1792683730).is_err());
        for k in [
            "UNIT",
            "INVOCATION_ID",
            "_PID",
            "_UID",
            "MESSAGE_ID",
            "MESSAGE",
            "__REALTIME_TIMESTAMP",
        ] {
            let mut b = r.clone();
            b[k] = serde_json::json!("foreign");
            assert!(manager(&[b], 1792684000).is_err(), "{k}");
        }
    }
}
