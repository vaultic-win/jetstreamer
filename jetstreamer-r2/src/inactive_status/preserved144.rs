//! Status-only cleanup for a terminal exact144 delivery. Canonical and staged
//! archives remain untouched; no ready pair is invented and no retry is started.
use super::*;
const PUB: &str = "horizon-publish-144-v4-20261022-v1.service";
const UPLOAD: &str = "horizon-upload-144-v4-20261022-v1.service";
const DIGEST: &str = "153d3e5e5b7cbdc31bb4229315786000b84442a75b3b83cf4a50184b20b84a33";
const LENGTH: u64 = 109177480876;
pub(super) fn scope(p: &Plan, i: &Value) -> Result<()> {
    ensure!(
        p.epoch == 144
            && p.public_archive_directory == Path::new("/home/sol/horizon")
            && p.status_receipt_directory
                == Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
            && i["schema"] == "horizon-exact144-delivery-intent-v1"
            && i["self_sha256"]
                == "9fdca9475356c3f8c82c8dbdd55d57476116771be2e3ca6b8914c40c8f41e08e"
            && i["lock_acquisition_mode"] == "nonblocking-no-queue"
            && i["owner"]["Id"] == UPLOAD
            && i["publisher"]["publisher"]["Id"] == PUB
            && i["publisher"]["publisher"]["Result"] == "success"
            && i["publisher"]["publisher"]["MainPID"] == "0"
            && i["publisher"]["publication"]["committed"] == true
            && i["publisher"]["publication"]["epoch"] == 144
            && i["publisher"]["publication"]["archive_sha256"] == DIGEST
            && i["publisher"]["publication"]["archive_bytes"] == LENGTH,
        "preserved delivery is not the exact committed144 artifact and nonqueued owner"
    );
    Ok(())
}
fn evidence(p: &Plan, i: &Value) -> Result<()> {
    scope(p, i)?;
    let plan: Bound = serde_json::from_value(i["plan"].clone())?;
    let d = bound_json(&plan)?;
    let root = Path::new(d["output_directory"].as_str().context("delivery root")?);
    ensure!(
        root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-epoch144-delivery-"))
            && p.preserved144_delivery
                .as_ref()
                .context("preserved intent")?
                .path
                == root.join("intent.json")
            && d["schema"] == "jetstreamer-exact144-single-delivery-plan-v1"
            && d["r2_create_missing_pair_authorized"] == true
            && d["r2_overwrite_authorized"] == false
            && d["local_retirement_authorized"] == false,
        "foreign preserved144 delivery plan"
    );
    let origin = Bound {
        path: "/var/lib/jetstreamer/horizon-publication144-owner-20261022-v1/launch.json".into(),
        sha256: i["publisher"]["origin_sha256"]
            .as_str()
            .context("origin SHA")?
            .into(),
    };
    let o = bound_json(&origin)?;
    ensure!(
        o["schema"] == "jetstreamer-exact144-publication-launch-v1"
            && o["epoch"] == 144
            && o["launched"] == true
            && o["publisher_plan"] == d["publisher_plan"]
            && o["tracker_plan"] == d["tracker_plan"]
            && o["claim"]["invocation_id"] == i["publisher"]["publisher"]["InvocationID"],
        "preserved144 original publisher differs"
    );
    Ok(())
}
pub(super) fn owner(p: &Plan, i: &Value, r: &StatusPublicationReceipt) -> Result<()> {
    if publication144::recognized(i) {
        return publication144::owner(p, i, r);
    }
    scope(p, i)?;
    let b = r
        .pipeline_binding
        .as_ref()
        .context("preserved144 requires exact pipeline status owner")?;
    ensure!(
        r.epoch == 144
            && b.origin_unit == PUB
            && i["publisher"]["publisher"]["InvocationID"] == b.origin_invocation_id
            && ((b.unit == UPLOAD
                && b.claim_phase == "upload-readback"
                && i["owner"]["InvocationID"] == b.invocation_id)
                || (b.unit == PUB
                    && b.claim_phase == "local-publication"
                    && b.invocation_id == b.origin_invocation_id)),
        "preserved artifacts belong to a different status owner/origin"
    );
    Ok(())
}
pub(super) fn terminal_owner(current: &Value, historical: &Value, iid: &str) -> Result<()> {
    for v in [current, historical] {
        ensure!(
            matches!(v["Id"].as_str(), Some(PUB | UPLOAD))
                && v["LoadState"] == "loaded"
                && v["InvocationID"] == iid
                && v["MainPID"] == "0"
                && v["NRestarts"] == "0"
                && v["Restart"] == "no"
                && v["Type"] == "oneshot"
                && v["RemainAfterExit"] == "yes"
                && ((v["ActiveState"] == "active"
                    && v["SubState"] == "exited"
                    && v["Result"] == "success"
                    && v["ExecMainStatus"] == "0")
                    || (v["ActiveState"] == "failed" && v["SubState"] == "failed")
                    || (v["ActiveState"] == "inactive" && v["SubState"] == "dead"))
                && v["Result"].as_str().is_some_and(|s| !s.is_empty())
                && v["ExecMainStatus"]
                    .as_str()
                    .is_some_and(|s| s.parse::<u32>().is_ok()),
            "preserved144 owner is live, replaced, restarting, collected or ambiguous"
        );
    }
    ensure!(
        current["ExecStart"]
            .as_str()
            .zip(historical["ExecStart"].as_str())
            .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b)),
        "preserved144 terminal command changed"
    );
    Ok(())
}
pub(super) fn terminal_census(
    p: &Plan,
    i: &Value,
    current: &BTreeMap<String, Value>,
) -> Result<()> {
    if publication144::recognized(i) {
        return publication144::terminal_census(p, i, current);
    }
    scope(p, i)?;
    for (name, capture) in [(PUB, &i["publisher"]["publisher"]), (UPLOAD, &i["owner"])] {
        let v = current
            .get(name)
            .context("preserved144 publisher/uploader absent from full census")?;
        // The capture is live at intent creation; require the terminal census
        // independently, retaining its exact captured invocation and command.
        let iid = capture["InvocationID"]
            .as_str()
            .context("preserved144 capture IID")?;
        terminal_owner(v, v, iid)?;
        ensure!(
            v["ExecStart"]
                .as_str()
                .zip(capture["ExecStart"].as_str())
                .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b)),
            "preserved144 captured command changed"
        );
        no_pending_owner_trigger(name, false)?;
    }
    Ok(())
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
pub(super) fn local(p: &Plan, i: &Value) -> Result<()> {
    if publication144::recognized(i) {
        return publication144::local(p, i);
    }
    evidence(p, i)?;
    ensure!(
        p.public_archive_directory.canonicalize()? == p.public_archive_directory,
        "noncanonical preserved directory"
    );
    let path = p.public_archive_directory.join("epoch-144.jet");
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        m.is_file()
            && m.uid() == 1001
            && m.gid() == 1003
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o440
            && m.len() == LENGTH
            && archive_matches(&identity(&m), &i["publisher"]["archive_identity"]),
        "preserved144 canonical identity changed"
    );
    let sidecar = p.public_archive_directory.join("epoch-144.jet.sha256");
    let s = fs::symlink_metadata(&sidecar)?;
    ensure!(
        s.is_file()
            && s.uid() == 1001
            && s.gid() == 1003
            && s.nlink() == 1
            && s.mode() & 0o7777 == 0o440
            && read_stable_bounded(&sidecar, 4096, "preserved144 local sidecar")?
                == format!("{DIGEST}  epoch-144.jet\n").as_bytes()
            && identity(&fs::symlink_metadata(path)?) == identity(&m),
        "preserved144 canonical sidecar or archive changed"
    );
    Ok(())
}
fn archive_matches(actual: &Value, captured: &Value) -> bool {
    actual == captured
        && actual.as_array().is_some_and(|a| a.len() == 10)
        && actual[2] == LENGTH
        && actual[3] == 1001
        && actual[4] == (libc::S_IFREG | 0o440)
        && actual[5] == 1
}
pub(super) async fn remote(s3: &Client, r2: &R2Config) -> Result<Value> {
    let e = inventory_epoch(s3, r2, 144).await?;
    ensure!(
        matches!(
            e.state,
            InventoryState::Missing | InventoryState::ArchiveOnly
        ),
        "ready/anomalous144 pair requires separate reconciliation"
    );
    if e.state == InventoryState::ArchiveOnly {
        ensure!(
            e.archive_length == Some(LENGTH)
                && e.archive_metadata_sha256
                    .as_deref()
                    .is_none_or(|s| s == DIGEST),
            "staged144 remote identity conflicts with preserved canonical archive"
        );
    }
    let key = "epoch-144.jet";
    let uploads = s3
        .list_multipart_uploads()
        .bucket(&r2.bucket)
        .prefix(key)
        .max_uploads(1000)
        .send()
        .await?;
    ensure!(
        uploads.is_truncated() != Some(true)
            && !uploads.uploads().iter().any(|u| u.key() == Some(key)),
        "144 multipart remains active or ambiguous; preserve it and reconcile ownership"
    );
    Ok(
        json!({"state":e.state,"length":e.archive_length,"etag":e.archive_etag,"metadata_sha256":e.archive_metadata_sha256}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_identity_is_preserved_not_replaced_by_a_same_size_file() {
        let a = json!([
            64512,
            123,
            LENGTH,
            1001,
            libc::S_IFREG | 0o440,
            1,
            100,
            0,
            100,
            0
        ]);
        assert!(archive_matches(&a, &a));
        for index in 0..10 {
            let mut bad = a.clone();
            bad[index] = json!(999);
            assert!(!archive_matches(&bad, &a), "{index}");
        }
        for index in [2, 3, 4, 5] {
            let mut both = a.clone();
            both[index] = json!(999);
            assert!(!archive_matches(&both, &both), "{index}");
        }
    }
    #[test]
    fn terminal_artifact_owners_must_be_exact_not_replaced_live_or_restartable() {
        let v = json!({"Id":UPLOAD,"LoadState":"loaded","InvocationID":"a".repeat(32),"MainPID":"0","NRestarts":"0",
            "Restart":"no","Type":"oneshot","RemainAfterExit":"yes","ActiveState":"failed","SubState":"failed",
            "Result":"exit-code","ExecMainStatus":"1","ExecStart":"exact command"});
        terminal_owner(&v, &v, &"a".repeat(32)).unwrap();
        let mut success = v.clone();
        success["ActiveState"] = json!("active");
        success["SubState"] = json!("exited");
        success["Result"] = json!("success");
        success["ExecMainStatus"] = json!("0");
        terminal_owner(&success, &success, &"a".repeat(32)).unwrap();
        for field in [
            "InvocationID",
            "MainPID",
            "NRestarts",
            "Restart",
            "Type",
            "ActiveState",
            "SubState",
            "ExecStart",
        ] {
            let mut bad = v.clone();
            bad[field] = json!("foreign");
            assert!(
                terminal_owner(&bad, &v, &"a".repeat(32)).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn preservation_scope_never_weakens_other_epochs_or_uncommitted_artifacts() {
        let (mut p, _) = super::super::tests::plan_fixture();
        p.epoch = 144;
        p.public_archive_directory = "/home/sol/horizon".into();
        p.status_receipt_directory = "/home/sol/.jetstreamer-private/r2-status-receipts".into();
        let i = json!({"schema":"horizon-exact144-delivery-intent-v1","self_sha256":"9fdca9475356c3f8c82c8dbdd55d57476116771be2e3ca6b8914c40c8f41e08e",
            "lock_acquisition_mode":"nonblocking-no-queue","owner":{"Id":UPLOAD},"publisher":{"publisher":{"Id":PUB,"Result":"success","MainPID":"0"},
                "publication":{"committed":true,"epoch":144,"archive_sha256":DIGEST,"archive_bytes":LENGTH}}});
        scope(&p, &i).unwrap();
        for pointer in [
            "/self_sha256",
            "/lock_acquisition_mode",
            "/owner/Id",
            "/publisher/publication/committed",
            "/publisher/publication/archive_sha256",
            "/publisher/publication/archive_bytes",
        ] {
            let mut bad = i.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(scope(&p, &bad).is_err(), "{pointer}");
        }
        p.epoch = 143;
        assert!(scope(&p, &i).is_err());
    }
}
