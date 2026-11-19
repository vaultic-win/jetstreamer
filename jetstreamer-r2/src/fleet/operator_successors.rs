//! Closed operator metadata chains for original 247 delivery and 265 input work.
//! A chain authenticates status continuity, never replay, admission or capacity.
use super::*;
const ROOT: &str = "/home/ubuntu/.codex/diagnostics";
const THREAD: &str = "01a1b2db-33e3-7163-a8b3-480390e3aaf3";
const PACKET: &str =
    "/home/ubuntu/.codex/diagnostics/horizon265-input-cache-20261119-v1/input-packet.json";
const PACKET_SHA: &str = "f7dbb6eedd4f47c940c959639d399ea3af68343f18fc894c736170f6dc089153";
struct Record {
    basis: Value,
    completion: Value,
    status: EpochStatus,
    raw: Value,
    bytes: Vec<u8>,
}
fn prefix(epoch: u64) -> Result<&'static str> {
    match epoch {
        247 => Ok("horizon247-terminal-status-20261119-v"),
        265 => Ok("horizon265-input-status-20261119-v"),
        _ => bail!("unsupported operator status epoch"),
    }
}
fn anchors(epoch: u64) -> Result<[&'static str; 3]> {
    match epoch {
        247 => Ok([
            "ec66051f6e599502ec3c8674da27c2caa855a5b0893bbbf6ef4c6eb5d2430e2b",
            "a1570028aa826db237a8d3e16de08438fdf63e6516b7fe1b6b59113819095c7b",
            "52d9cdd1796c619b0917261c3acc57696bb0bddd88a78729e3a3515a1d60fa9a",
        ]),
        265 => Ok([
            "6ae1087b42e72c52822b57ede325777b4a38eef11d8f17a4bf0e5d8450555dc4",
            "0740663a1d0a091787240dd1b867458661ffa35af89f0231a0f3f1212345e4d3",
            "6defe1c84fe14d791edc6dfc574f378c00ce936c4a091cfc1b2796e3e7f779b1",
        ]),
        _ => bail!("unsupported operator anchor"),
    }
}
fn bytes(binding: &BoundFile) -> Result<Vec<u8>> {
    let p = &binding.path;
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == *p
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0,
        "unsafe operator chain input"
    );
    let bytes = read_stable_bounded(p, 1 << 20, "operator chain input")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == binding.sha256,
        "operator chain input digest differs"
    );
    Ok(bytes)
}
fn load(epoch: u64, generation: usize, bindings: [&BoundFile; 3]) -> Result<Record> {
    let dir = Path::new(ROOT).join(format!("{}{generation}", prefix(epoch)?));
    let anchor = anchors(epoch)?;
    let mut values = Vec::new();
    let mut raw_bytes = Vec::new();
    for (i, (binding, name)) in bindings
        .into_iter()
        .zip(["intent.json", "completion.json", "readback.json"])
        .enumerate()
    {
        ensure!(
            binding.path == dir.join(name),
            "operator chain skipped/reordered generation"
        );
        if generation == 1 {
            ensure!(binding.sha256 == anchor[i], "operator anchor differs");
        }
        let b = bytes(binding)?;
        values.push(serde_json::from_slice::<Value>(&b)?);
        if i == 2 {
            raw_bytes = b;
        }
    }
    let raw = values.pop().unwrap();
    let completion = values.pop().unwrap();
    let basis = values.pop().unwrap();
    let status: EpochStatus = serde_json::from_value(raw.clone())?;
    validate_epoch_status(&status, epoch)?;
    Ok(Record {
        basis,
        completion,
        status,
        raw,
        bytes: raw_bytes,
    })
}
fn sample_ms(record: &Record) -> Result<u64> {
    utc_seconds(&record.status.sampled_at_utc)?
        .checked_mul(1000)
        .context("operator sample overflow")
}
fn etag(record: &Record) -> Result<&str> {
    let s = record.completion["new_etag"]
        .as_str()
        .context("operator ETag absent")?;
    ensure!(
        s.len() > 2 && s.starts_with('"') && s.ends_with('"') && !s[1..s.len() - 1].contains('"'),
        "operator ETag malformed"
    );
    Ok(&s[1..s.len() - 1])
}
fn common(record: &Record, epoch: u64) -> Result<()> {
    let b = &record.basis;
    let c = &record.completion;
    let key = format!("epoch-{epoch}.epoch-status.json");
    let digest = hex_lower(&Sha256::digest(&record.bytes));
    ensure!(
        b["epoch"] == epoch
            && b["key"] == key
            && b["owner"] == "/root"
            && b["thread_id"] == THREAD
            && b["archive_or_sidecar_mutation"] == false
            && b["replay_launch_authorized"] == false
            && b["estimate_high_uncertainty"] == true
            && b["basis"].as_str().is_some_and(|s| !s.trim().is_empty())
            && b["status"] == record.raw
            && record.raw == serde_json::to_value(&record.status)?
            && b["replacement_sha256"] == digest
            && c["schema"] == "horizon-status-only-correction-completion-v1"
            && c["epoch"] == epoch
            && c["key"] == key
            && c["owner"] == "/root"
            && c["new_sha256"] == digest
            && c["sampled_at_utc"] == record.status.sampled_at_utc
            && c["authenticated_exact_byte_readback"] == true
            && c["archive_or_sidecar_mutation"] == false,
        "operator record identity/readback differs"
    );
    etag(record)?;
    Ok(())
}
fn input265(record: &Record) -> Result<()> {
    let b = &record.basis;
    let parts = b["estimate_components"]
        .as_object()
        .context("265 estimate components missing")?;
    let fields = [
        "capacity_and_delivery_queue_millis",
        "delivery_allowance_millis",
        "qualification_allowance_millis",
        "replay_millis",
    ];
    let total = fields.iter().try_fold(0_u64, |sum, k| {
        parts
            .get(*k)
            .and_then(Value::as_u64)
            .and_then(|n| sum.checked_add(n))
    });
    ensure!(
        parts.len() == 4
            && total == Some(record.status.estimated_remaining_millis)
            && b["schema"] == "horizon265-input-operator-status-v1"
            && b["stage"] == "input-and-runtime-qualification"
            && b["original_start_unit"] == "horizon265-index-digests-20261119-v1.service"
            && b["original_start_invocation_id"] == "8ecd870da37f41e4aaabc29204d664fb"
            && b["original_start_utc"] == "2026-11-19T15:47:44Z"
            && b["repair_agent"] == "/root/replacement265_input"
            && b["current_activity"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty())
            && b["input_packet"] == json!({"path":PACKET,"sha256":PACKET_SHA})
            && record.status.phase == "verification"
            && record.status.jet_size_bytes == 0
            && sample_ms(record)?.checked_sub(utc_seconds("2026-11-19T15:47:44Z")? * 1000)
                == Some(record.status.elapsed_execution_millis),
        "265 original input owner/start/estimate differs"
    );
    Ok(())
}
fn chain(records: &[Record], epoch: u64, now: u64) -> Result<()> {
    ensure!(
        !records.is_empty() && records.len() <= 2048,
        "operator chain length invalid"
    );
    let original = sample_ms(&records[0])?
        .checked_sub(records[0].status.elapsed_execution_millis)
        .context("operator original clock invalid")?;
    for (i, r) in records.iter().enumerate() {
        common(r, epoch)?;
        ensure!(
            sample_ms(r)?.checked_sub(r.status.elapsed_execution_millis) == Some(original),
            "operator original clock changed"
        );
        if epoch == 247 {
            ensure!(
                terminal247::status_values(
                    &r.basis,
                    &r.completion,
                    &r.raw,
                    &r.status,
                    &r.bytes,
                    etag(r)?,
                    sample_ms(r)? / 1000
                )?,
                "247 successor status invalid"
            );
            ensure!(
                r.status.jet_size_bytes == records[0].status.jet_size_bytes
                    && r.basis["original_producer"] == records[0].basis["original_producer"],
                "247 original archive/owner changed"
            );
        } else {
            input265(r)?;
        }
        if i > 0 {
            let prior = &records[i - 1];
            ensure!(
                sample_ms(prior)? < sample_ms(r)?
                    && r.basis["before_sha256"] == prior.completion["new_sha256"]
                    && r.basis["before_etag"] == prior.completion["new_etag"]
                    && r.completion["before_sha256"] == r.basis["before_sha256"]
                    && r.completion["before_etag"] == r.basis["before_etag"],
                "operator conditional successor chain broken"
            );
            if epoch == 265 {
                ensure!(
                    r.basis["authenticated_status_absent_before"] == false
                        && r.completion["authenticated_status_absent_before"] == false,
                    "265 successor cannot recreate absent object"
                );
            }
        } else if epoch == 265 {
            ensure!(
                r.basis["authenticated_status_absent_before"] == true
                    && r.completion["authenticated_status_absent_before"] == true,
                "265 initial absence anchor differs"
            );
        }
    }
    let last = sample_ms(records.last().unwrap())? / 1000;
    ensure!(
        last <= now && now - last <= 1800,
        "operator status stale or future"
    );
    Ok(())
}
pub(super) fn matches(
    evidence: &OperatorStatusEvidence,
    epoch: u64,
    status: &EpochStatus,
    object: &MutableRemoteObject,
    current: Option<&Value>,
    now: u64,
) -> Result<bool> {
    ensure!(
        matches!(epoch, 247 | 265) && evidence.predecessors.len() < 2048,
        "operator successor scope/count differs"
    );
    let mut records = Vec::new();
    for (i, p) in evidence.predecessors.iter().enumerate() {
        records.push(load(
            epoch,
            i + 1,
            [&p.basis, &p.completion, &p.raw_status],
        )?);
    }
    records.push(load(
        epoch,
        records.len() + 1,
        [&evidence.basis, &evidence.completion, &evidence.raw_status],
    )?);
    chain(&records, epoch, now)?;
    if epoch == 247 {
        terminal247::validate_current(current.context("247 terminal owner missing")?, now)?;
    } else {
        let packet = bytes(&BoundFile {
            path: PACKET.into(),
            sha256: PACKET_SHA.into(),
        })?;
        let packet: Value = serde_json::from_slice(&packet)?;
        ensure!(packet["epoch"] == 265, "265 input packet epoch differs");
        for r in &records {
            let binding: BoundFile = serde_json::from_value(r.basis["observer"].clone())?;
            let o: Value = serde_json::from_slice(&bytes(&binding)?)?;
            ensure!(
                o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                    && utc_seconds(
                        o["recorded_at_utc"]
                            .as_str()
                            .context("265 source observer clock missing")?
                    )? <= sample_ms(r)? / 1000,
                "265 source observer identity/clock differs"
            );
        }
    }
    let last = records.last().unwrap();
    Ok(last.status == *status && last.bytes == object.bytes && etag(last)? == object.etag)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(epoch: u64, sample: &str, previous: Option<&Record>) -> Record {
        let sample_seconds = utc_seconds(sample).unwrap();
        let start = if epoch == 265 {
            utc_seconds("2026-11-19T15:47:44Z").unwrap() * 1000
        } else {
            1794882672859
        };
        let status = EpochStatus {
            epoch,
            jet_size_bytes: if epoch == 247 { 180370916960 } else { 0 },
            elapsed_execution_millis: sample_seconds * 1000 - start,
            estimated_remaining_millis: if epoch == 247 { 77400000 } else { 334800000 },
            sampled_at_utc: sample.into(),
            phase: "verification".into(),
        };
        let raw = serde_json::to_value(&status).unwrap();
        let bytes = serde_json::to_vec(&raw).unwrap();
        let digest = hex_lower(&Sha256::digest(&bytes));
        let key = format!("epoch-{epoch}.epoch-status.json");
        let before_etag = previous
            .map(|r| r.completion["new_etag"].clone())
            .unwrap_or(json!("\"old\""));
        let before_sha = previous
            .map(|r| r.completion["new_sha256"].clone())
            .unwrap_or(json!("old-sha"));
        let mut basis = json!({"epoch":epoch,"key":key,"owner":"/root","thread_id":THREAD,"basis":"ongoing qualified preparation",
            "archive_or_sidecar_mutation":false,"replay_launch_authorized":false,"estimate_high_uncertainty":true,
            "status":raw,"replacement_sha256":digest,"before_etag":before_etag,"before_sha256":before_sha});
        let mut completion = json!({"schema":"horizon-status-only-correction-completion-v1","epoch":epoch,"key":key,"owner":"/root",
            "new_sha256":digest,"new_etag":format!("\"{sample_seconds}\""),"sampled_at_utc":sample,
            "authenticated_exact_byte_readback":true,"archive_or_sidecar_mutation":false,"before_etag":before_etag,"before_sha256":before_sha});
        if epoch == 247 {
            basis["schema"] = json!("horizon247-postterminal-operator-status-v1");
            basis["stage"] = json!("postterminal-delivery-admission");
            basis["terminal_handoff_sha256"] =
                json!("cb3dcc396a776034019133b9c542f443c3c9636867938a36e75c4c6ae50f377a");
            basis["terminal_drain_sha256"] =
                json!("e4cd3c344ad0b1aeac6d5a8309d6306c7ae935788e362617efe994f564e2face");
            basis["original_producer"] =
                json!({"InvocationID":terminal247::IID,"ActiveState":"inactive"});
            basis["remaining_seconds"] = json!({"current_full_reader":7200,"current_local_plugin":21600,"current_remote_plugin":28800,
                "serial_delivery_queue":7200,"source_revalidation_and_sidecar":1800,"upload_and_authenticated_readback":10800});
        } else {
            basis["schema"] = json!("horizon265-input-operator-status-v1");
            basis["stage"] = json!("input-and-runtime-qualification");
            basis["original_start_unit"] = json!("horizon265-index-digests-20261119-v1.service");
            basis["original_start_invocation_id"] = json!("8ecd870da37f41e4aaabc29204d664fb");
            basis["original_start_utc"] = json!("2026-11-19T15:47:44Z");
            basis["repair_agent"] = json!("/root/replacement265_input");
            basis["current_activity"] = json!("source qualification continues");
            basis["input_packet"] = json!({"path":PACKET,"sha256":PACKET_SHA});
            basis["estimate_components"] = json!({"capacity_and_delivery_queue_millis":7200000,"delivery_allowance_millis":72000000,
                "qualification_allowance_millis":21600000,"replay_millis":234000000});
            basis["authenticated_status_absent_before"] = json!(previous.is_none());
            completion["authenticated_status_absent_before"] = json!(previous.is_none());
        }
        Record {
            basis,
            completion,
            status,
            raw,
            bytes,
        }
    }
    fn fixture(epoch: u64) -> Vec<Record> {
        let a = record(epoch, "2026-11-19T16:15:07Z", None);
        let b = record(epoch, "2026-11-19T16:39:42Z", Some(&a));
        let c = record(epoch, "2026-11-19T17:10:00Z", Some(&b));
        vec![a, b, c]
    }
    #[test]
    fn both_operator_profiles_accept_contiguous_successors_without_refreshing_original_clock() {
        let now = utc_seconds("2026-11-19T17:10:00Z").unwrap();
        for epoch in [247, 265] {
            let r = fixture(epoch);
            chain(&r, epoch, now).unwrap();
            assert!(chain(&r, epoch, now - 1).is_err());
            assert!(chain(&r, epoch, now + 1801).is_err());
            let mut r = fixture(epoch);
            r.remove(1);
            assert!(chain(&r, epoch, now).is_err());
            let mut r = fixture(epoch);
            r.swap(0, 1);
            assert!(chain(&r, epoch, now).is_err());
        }
    }
    #[test]
    fn changed_owner_task_conditional_precondition_or_readback_is_rejected() {
        let now = utc_seconds("2026-11-19T17:10:00Z").unwrap();
        for epoch in [247, 265] {
            for key in [
                "owner",
                "thread_id",
                "stage",
                "before_sha256",
                "before_etag",
            ] {
                let mut r = fixture(epoch);
                r[1].basis[key] = json!("replacement");
                assert!(chain(&r, epoch, now).is_err(), "{epoch}/{key}");
            }
            for key in [
                "before_sha256",
                "before_etag",
                "new_sha256",
                "new_etag",
                "owner",
            ] {
                let mut r = fixture(epoch);
                r[1].completion[key] = json!("replacement");
                assert!(chain(&r, epoch, now).is_err(), "{epoch}/{key}");
            }
            let mut r = fixture(epoch);
            r[1].completion["authenticated_exact_byte_readback"] = json!(false);
            assert!(chain(&r, epoch, now).is_err());
            let mut r = fixture(epoch);
            r[1].status.elapsed_execution_millis += 1;
            assert!(chain(&r, epoch, now).is_err());
            let mut r = fixture(epoch);
            r[1].bytes.push(b' ');
            assert!(chain(&r, epoch, now).is_err());
        }
    }
    #[test]
    fn input265_cannot_change_original_source_or_recreate_object_on_successor() {
        let now = utc_seconds("2026-11-19T17:10:00Z").unwrap();
        for key in [
            "original_start_unit",
            "original_start_invocation_id",
            "original_start_utc",
            "repair_agent",
            "input_packet",
        ] {
            let mut r = fixture(265);
            r[1].basis[key] = json!("changed");
            assert!(chain(&r, 265, now).is_err(), "{key}");
        }
        let mut r = fixture(265);
        r[1].basis["authenticated_status_absent_before"] = json!(true);
        assert!(chain(&r, 265, now).is_err());
        let mut r = fixture(265);
        r[1].basis["estimate_components"]["replay_millis"] = json!(1);
        assert!(chain(&r, 265, now).is_err());
        assert!(prefix(266).is_err());
        assert!(anchors(266).is_err());
    }
}
