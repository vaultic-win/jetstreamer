//! An exact actual post-cutoff170,171 or172 status handoff, preserving the completed audit.
use super::replacement_validation::utc;
use super::*;
fn step(pr: &Value, previous: &Value, previous_binding: &Value, clock: u64, epoch: u64) -> R<()> {
    need(
        pr["schema"] == "horizon-status-only-correction-v1"
            && pr["epoch"] == epoch
            && pr["key"] == format!("epoch-{epoch}.epoch-status.json")
            && pr["authenticated_readback"] == true
            && pr["conditional_header"] == "If-Match"
            && pr["owner_evidence"]["current_operator"] == "/root"
            && pr["archive_publication_authorized"] == false
            && pr["replay_launch_authorized"] == false
            && pr["resource_sample_claimed"] == false,
        "exact authenticated status-only170 correction required",
    )?;
    need(
        pr["previous_receipt"] == *previous_binding
            && pr["before_status"] == previous["after_status"]
            && pr["before_sha256"] == previous["after_sha256"]
            && pr["before_etag"] == previous["after_etag"],
        "conditional170 status chain differs from completed audit",
    )?;
    let sample = s(&pr["after_status"], "sampled_at_utc")?;
    wire(&pr["after_status"], epoch, sample)?;
    need(
        pr["sampled_at_utc"] == sample
            && utc(sample)? > utc(s(&previous["after_status"], "sampled_at_utc")?)?
            && utc(sample)? <= clock,
        "status event must be genuinely later and not future",
    )?;
    let mut body = serde_json::to_vec(&pr["after_status"])?;
    body.push(b'\n');
    let before = s(pr, "before_body")?.as_bytes();
    need(
        pr["after_sha256"] == sha(&body)
            && pr["before_sha256"] == sha(before)
            && serde_json::from_slice::<Value>(before)? == pr["before_status"]
            && !s(pr, "after_etag")?.is_empty(),
        "status event canonical body/key/digest/ETag required",
    )?;
    Ok(())
}
pub(super) fn overlay(
    plan: &Value,
    audit: &Value,
    obs: &Value,
    mut current: BTreeMap<u64, (Value, Value)>,
) -> R<BTreeMap<u64, (Value, Value)>> {
    if plan
        .get("status_event_supplement")
        .is_none_or(Value::is_null)
    {
        return Ok(current);
    }
    let supplement = bound(&plan["status_event_supplement"])?;
    let epoch = n(&supplement, "epoch")?;
    need(
        matches!(epoch, 170..=172),
        "unsupported post-cutoff status epoch",
    )?;
    need(
        supplement["schema"] == format!("horizon-Root-postcutoff{epoch}-status-chain-v1")
            && supplement["owner"] == "/root"
            && supplement["primary_thread"] == plan["primary_thread"]
            && supplement["epoch"] == epoch
            && supplement["source_status_audit"] == plan["status_audit"]
            && supplement["observer"] == plan["observer"]
            && supplement["original_audit_unchanged"] == true
            && supplement["new_resource_sample"] == false
            && supplement["resource_credit_bytes"] == 0
            && supplement["replay_launch_authorized"] == false,
        "scoped Root170 event supplement required",
    )?;
    let declarations = replacement_validation::declarations(plan)?;
    let owners = declarations
        .iter()
        .filter(|d| d["epoch"] == epoch)
        .collect::<Vec<_>>();
    need(
        owners.len() == 1,
        "exact one170 replacement declaration required",
    )?;
    let d = owners[0];
    let cutoff = utc(s(obs, "recorded_at_utc")?)?;
    let clock = now()?;
    need(
        n(d, "original_start_unix_seconds")? > cutoff
            && n(d, "original_start_unix_seconds")? <= clock
            && !obs["replays"]
                .as_array()
                .ok_or("ordinary owner rows")?
                .iter()
                .any(|r| r["range"].as_str() == Some(epoch.to_string().as_str())),
        "170 supplement must preserve genuine postcutoff absent owner",
    )?;
    let corrections = supplement["corrections"]
        .as_array()
        .ok_or("correction chain")?;
    need(
        !corrections.is_empty() && corrections.len() <= 4,
        "bounded nonempty170 status chain required",
    )?;
    let (mut previous, mut binding) = current
        .get(&epoch)
        .ok_or("base170 audit outcome missing")?
        .clone();
    for next in corrections {
        let pr = bound(next)?;
        step(&pr, &previous, &binding, clock, epoch)?;
        need(
            utc(s(&pr["after_status"], "sampled_at_utc")?)? >= utc(s(audit, "sampled_at_utc")?)?,
            "event cannot precede completed audit",
        )?;
        previous = pr;
        binding = next.clone();
    }
    let owner = &previous["owner_evidence"];
    need(
        owner["actual_producer"]["InvocationID"] == d["invocation_id"]
            && owner["replacement_admission"] == d["admission"]
            && owner["guard_protection"] == d["guard_protection"]
            && owner["replacement_launch_proof"] == d["launch_proof"]
            && owner["replacement_phase_event"] == d["phase_event"],
        "event status must bind exact independent replacement launch/phase/protection",
    )?;
    // The complete replacement reader independently authenticates current native
    // owner, inputs, images, original/current guards and the actual phase event.
    current.insert(epoch, (previous, binding));
    bound(&plan["status_event_supplement"])?;
    Ok(current)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Value, u64) {
        let old = json!({"epoch":170,"jet_size_bytes":0,"elapsed_execution_millis":1,"estimated_remaining_millis":2,"sampled_at_utc":"2026-11-10T21:32:07Z","phase":"verification"});
        let mut before = serde_json::to_vec(&old).unwrap();
        before.push(b'\n');
        let binding = json!({"path":"/fixture/previous.json","sha256":"a".repeat(64)});
        let previous = json!({"after_status":old,"after_sha256":sha(&before),"after_etag":"old"});
        let new = json!({"epoch":170,"jet_size_bytes":7,"elapsed_execution_millis":5,"estimated_remaining_millis":9,"sampled_at_utc":"2026-11-10T21:35:28Z","phase":"verification"});
        let mut body = serde_json::to_vec(&new).unwrap();
        body.push(b'\n');
        let pr = json!({"schema":"horizon-status-only-correction-v1","epoch":170,"key":"epoch-170.epoch-status.json","authenticated_readback":true,"conditional_header":"If-Match","owner_evidence":{"current_operator":"/root"},"archive_publication_authorized":false,"replay_launch_authorized":false,"resource_sample_claimed":false,"previous_receipt":binding,"before_status":previous["after_status"],"before_sha256":sha(&before),"before_etag":"old","before_body":String::from_utf8(before).unwrap(),"after_status":new,"after_sha256":sha(&body),"after_etag":"new","sampled_at_utc":"2026-11-10T21:35:28Z"});
        (pr, previous, binding, 1794347000)
    }
    #[test]
    fn genuine_conditional_handoff_keeps_original_audit_body() {
        let f = fixture();
        step(&f.0, &f.1, &f.2, f.3, 170).unwrap();
    }
    #[test]
    fn wrong_epoch_or_key_cannot_overlay_another_report() {
        for (k, v) in [
            ("epoch", json!(169)),
            ("key", json!("epoch-169.epoch-status.json")),
        ] {
            let mut f = fixture();
            f.0[k] = v;
            assert!(step(&f.0, &f.1, &f.2, f.3, 170).is_err());
        }
    }
    #[test]
    fn wrong_previous_receipt_or_etag_is_rejected() {
        for (k, v) in [
            ("previous_receipt", json!({"path":"/other"})),
            ("before_etag", json!("different")),
        ] {
            let mut f = fixture();
            f.0[k] = v;
            assert!(step(&f.0, &f.1, &f.2, f.3, 170).is_err());
        }
    }
    #[test]
    fn unauthenticated_or_unconditional_writes_fail() {
        for (k, v) in [
            ("authenticated_readback", json!(false)),
            ("conditional_header", json!("If-None-Match")),
        ] {
            let mut f = fixture();
            f.0[k] = v;
            assert!(step(&f.0, &f.1, &f.2, f.3, 170).is_err());
        }
    }
    #[test]
    fn changed_payload_digest_and_changed_before_bytes_fail() {
        for (k, v) in [
            ("after_sha256", json!("0".repeat(64))),
            ("before_body", json!("{}")),
        ] {
            let mut f = fixture();
            f.0[k] = v;
            assert!(step(&f.0, &f.1, &f.2, f.3, 170).is_err());
        }
    }
    #[test]
    fn changed_previous_body_cannot_hide_behind_receipt_pointer() {
        let mut f = fixture();
        f.0["before_status"]["epoch"] = json!(169);
        assert!(step(&f.0, &f.1, &f.2, f.3, 170).is_err());
    }
    #[test]
    fn future_or_backdated_event_is_rejected() {
        let f = fixture();
        assert!(step(&f.0, &f.1, &f.2, 1, 170).is_err());
        let mut g = f;
        g.0["after_status"]["sampled_at_utc"] = json!("2026-11-10T21:00:22Z");
        g.0["sampled_at_utc"] = json!("2026-11-10T21:00:22Z");
        assert!(step(&g.0, &g.1, &g.2, g.3, 170).is_err());
    }
    #[test]
    fn event_cannot_grant_resource_or_archive_authority() {
        for k in [
            "resource_sample_claimed",
            "archive_publication_authorized",
            "replay_launch_authorized",
        ] {
            let mut f = fixture();
            f.0[k] = json!(true);
            assert!(step(&f.0, &f.1, &f.2, f.3, 170).is_err());
        }
    }

    #[test]
    fn exact171_conditional_handoff_and_cross_epoch_rejection() {
        let mut f = fixture();
        f.0["epoch"] = json!(171);
        f.0["key"] = json!("epoch-171.epoch-status.json");
        f.0["before_status"]["epoch"] = json!(171);
        f.1["after_status"]["epoch"] = json!(171);
        f.0["after_status"]["epoch"] = json!(171);
        let mut before = serde_json::to_vec(&f.0["before_status"]).unwrap();
        before.push(b'\n');
        f.0["before_body"] = json!(String::from_utf8(before.clone()).unwrap());
        f.0["before_sha256"] = json!(sha(&before));
        f.1["after_sha256"] = json!(sha(&before));
        let mut after = serde_json::to_vec(&f.0["after_status"]).unwrap();
        after.push(b'\n');
        f.0["after_sha256"] = json!(sha(&after));
        step(&f.0, &f.1, &f.2, f.3, 171).unwrap();
        assert!(step(&f.0, &f.1, &f.2, f.3, 170).is_err());
        f.0["before_etag"] = json!("foreign");
        assert!(step(&f.0, &f.1, &f.2, f.3, 171).is_err());
    }
    #[test]
    fn exact172_conditional_handoff_preserves_independent_audit_chain() {
        let mut f = fixture();
        f.0["epoch"] = json!(172);
        f.0["key"] = json!("epoch-172.epoch-status.json");
        f.0["before_status"]["epoch"] = json!(172);
        f.1["after_status"]["epoch"] = json!(172);
        f.0["after_status"]["epoch"] = json!(172);
        let mut before = serde_json::to_vec(&f.0["before_status"]).unwrap();
        before.push(b'\n');
        f.0["before_body"] = json!(String::from_utf8(before.clone()).unwrap());
        f.0["before_sha256"] = json!(sha(&before));
        f.1["after_sha256"] = json!(sha(&before));
        let mut after = serde_json::to_vec(&f.0["after_status"]).unwrap();
        after.push(b'\n');
        f.0["after_sha256"] = json!(sha(&after));
        step(&f.0, &f.1, &f.2, f.3, 172).unwrap();
        for epoch in [170, 171, 173] {
            assert!(step(&f.0, &f.1, &f.2, f.3, epoch).is_err());
        }
        f.0["before_etag"] = json!("unrelated172");
        assert!(step(&f.0, &f.1, &f.2, f.3, 172).is_err());
    }
}
