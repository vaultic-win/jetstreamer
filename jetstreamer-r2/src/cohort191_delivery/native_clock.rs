//! A real native handoff clock may follow the retained resource sample. It
//! never becomes a second resource observation or backdates the new manager.
use super::*;
pub(super) fn sample(p: &Capture, observer: &Value) -> Result<String> {
    let resource = observer["recorded_at_utc"]
        .as_str()
        .context("191 resource clock")?;
    let Some(binding) = &p.native_event_clock else {
        return Ok(resource.into());
    };
    let proof = bound(binding, true)?;
    let event = proof["recorded_unix_seconds"]
        .as_u64()
        .context("191 native event clock")?;
    let sample = proof["sampled_at_utc"]
        .as_str()
        .context("191 native event UTC")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if proof["schema"] == readback_handoff::SCHEMA {
        readback_handoff::validate(p, observer, &proof)?;
        clocks(
            fleet::utc_seconds(resource)?,
            event,
            fleet::utc_seconds(sample)?,
            now,
        )?;
        return Ok(sample.into());
    }
    let anchor_binding: Bound = serde_json::from_value(proof["recovery_anchor"].clone())?;
    ensure!(
        anchor_binding.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-cohort191-delivery-queue-20261023-v1/history/state-000003.json"
            )
            && anchor_binding.sha256
                == "3e3d7ee6f52fdfca86504c1125e1d7d790a4277636d89e0fe1b4c4886acc2a7a",
        "191 recovery lineage anchor changed"
    );
    let anchor = bound(&anchor_binding, true)?;
    let state = bound(&serde_json::from_value(proof["queue_state"].clone())?, true)?;
    ensure!(
        proof["schema"] == "jetstreamer-cohort191-native-handoff-clock-v2"
            && proof["observer"] == json!(p.observer)
            && proof["terminal"] == json!(p.native_terminal_proof)
            && p.native_pending_proof.is_none()
            && p.queue
                .as_ref()
                .is_some_and(|q| proof["queue_plan"] == json!(q.plan)
                    && proof["queue_state"] == json!(q.state))
            && p.observer.sha256
                == "0db9966d4b29d38984e8a2d9d0938d61dfb005356195a29e63362ea7ca4e70f1"
            && lineage(&anchor, &state)
            && proof["queue_invocation_id"] == state["invocation_id"]
            && state["updated_unix_millis"]
                .as_u64()
                .is_some_and(|n| n <= event.saturating_mul(1000))
            && proof["resource_samples_taken"] == 0
            && proof["publication_authorized"] == false
            && proof["r2_mutations"] == false,
        "191 event clock lost exact recovered owner or retained resource evidence"
    );
    clocks(
        fleet::utc_seconds(resource)?,
        event,
        fleet::utc_seconds(sample)?,
        now,
    )?;
    Ok(sample.into())
}
fn clocks(resource: u64, event: u64, sample: u64, now: u64) -> Result<()> {
    ensure!(
        event == sample
            && event > resource
            && event - resource <= 1800
            && event <= now
            && now - event <= 1800,
        "191 native event clock stale/future/backdated"
    );
    Ok(())
}
pub(super) fn fleet_sample(evidence: &Value, resource: u64) -> Result<u64> {
    if evidence["native_event_clock"].is_null() {
        return Ok(resource);
    }
    let clock = bound(
        &serde_json::from_value(evidence["native_event_clock"].clone())?,
        true,
    )?;
    let observer = bound(
        &serde_json::from_value(evidence["observer"].clone())?,
        false,
    )?;
    ensure!(
        fleet::utc_seconds(
            observer["recorded_at_utc"]
                .as_str()
                .context("191 resource UTC")?
        )? == resource,
        "191 event replaced resource sample"
    );
    clock["recorded_unix_seconds"]
        .as_u64()
        .context("191 event clock missing")
}
/// Register only actual task owners authenticated by the complete native queue
/// event. The ordinary queue claim owns the epoch; these are census peers.
pub(super) fn fleet_peers(evidence: &Value) -> Result<Vec<String>> {
    if evidence["schema"] != EVENT_SCHEMA || evidence["queue"].is_null() {
        return Ok(vec![]);
    }
    let cutoff = evidence["sample_unix_seconds"]
        .as_u64()
        .context("191 peer clock")?;
    validate_event(evidence, cutoff)?;
    let state = bound(
        &serde_json::from_value(evidence["queue_observation"]["state"].clone())?,
        true,
    )?;
    let mut peers = BTreeSet::new();
    for row in state["epochs"].as_array().context("191 peer rows")? {
        if row["task_owner"].is_object() {
            let name = row["task_owner"]["unit"]
                .as_str()
                .context("191 peer unit")?;
            peers.insert(name.to_owned());
        }
    }
    Ok(peers.into_iter().collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_clock_cannot_replace_resource_or_admit_future_stale_time() {
        clocks(100, 101, 101, 102).unwrap();
        for (resource, event, sample, now) in [
            (100, 100, 100, 101),
            (100, 1901, 1901, 1902),
            (100, 101, 102, 103),
            (100, 102, 102, 101),
            (100, 101, 101, 1902),
        ] {
            assert!(clocks(resource, event, sample, now).is_err());
        }
    }
}

pub(super) fn utc(time: u64) -> Result<String> {
    let time: libc::time_t = time.try_into()?;
    let mut t = std::mem::MaybeUninit::<libc::tm>::uninit();
    ensure!(
        !unsafe { libc::gmtime_r(&time, t.as_mut_ptr()) }.is_null(),
        "191 UTC conversion"
    );
    let t = unsafe { t.assume_init() };
    let value = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.tm_year + 1900,
        t.tm_mon + 1,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec
    );
    ensure!(
        fleet::utc_seconds(&value)? == time as u64,
        "191 UTC roundtrip"
    );
    Ok(value)
}

fn lineage(anchor: &Value, state: &Value) -> bool {
    state["status"] == "managing"
        && state["revision"].as_u64().is_some_and(|n| n >= 3)
        && state["invocation_id"] == "0defba8ed0844040a2601c68d79060b2"
        && anchor["revision"] == 3
        && anchor["invocation_id"] == state["invocation_id"]
        && anchor["plan"] == state["plan"]
        && anchor["epochs"][0]["task_owner"]["invocation_id"] == "2ea71518e5ea48a3986c8f2fb07b34e5"
}
#[cfg(test)]
mod lineage_tests {
    use super::*;
    #[test]
    fn later_real_stage_keeps_recovery_anchor_without_claiming_old_actor_current() {
        let anchor = json!({"revision":3,"invocation_id":"0defba8ed0844040a2601c68d79060b2","plan":"sealedqueue","epochs":[{"task_owner":{"invocation_id":"2ea71518e5ea48a3986c8f2fb07b34e5"}}]});
        let later = json!({"status":"managing","revision":4,"invocation_id":anchor["invocation_id"],"plan":anchor["plan"],"epochs":[{"stage":"queued-plugin","task_owner":null}]});
        assert!(lineage(&anchor, &later));
        for key in ["status", "revision", "invocation_id", "plan"] {
            let mut bad = later.clone();
            bad[key] = json!("foreign");
            assert!(!lineage(&anchor, &bad));
        }
    }
}
