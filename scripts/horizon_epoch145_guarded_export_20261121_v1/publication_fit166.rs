//! A final 166 publisher consumes at most 1 CPU and 2 GiB of its
//! authenticated, drained producer's independently retained 9 CPU / 68 GiB.
use super::*;

const ADDITIONAL_HOME: u64 = 16 << 20;

fn budget(sample: &Value) -> Result<u64> {
    let baseline = capacity::n(sample, "protected_bytes")?;
    let floor = match sample.get("joint136") {
        Some(joint) => capacity::n(joint, "required_total_bytes")?.max(baseline),
        None => baseline,
    };
    let protected = floor
        .checked_add(ADDITIONAL_HOME)
        .context("publication HOME overflow")?;
    ensure!(
        capacity::n(sample, "free_bytes")? >= protected,
        "166 publication exceeds protected HOME"
    );
    ensure!(
        capacity::n(sample, "available_memory")? >= capacity::n(sample, "required_memory")?,
        "166 publication would exceed retained RAM"
    );
    Ok(protected)
}

fn publication(fleet: &Bound, terminal: &Bound, evidence: &Value, sample: &Value) -> Result<Value> {
    let protected = budget(sample)?;
    let live = &evidence["joint_closed166"];
    ensure!(
        live["unit"] == closed166::NODE
            && live["pid1_success"] == true
            && live["terminal"] == json!(terminal)
            && live["resource_credit_bytes"] == 0,
        "missing authenticated drained 166 reservation"
    );
    let cpu = capacity::n(evidence, "charged_cpu_micros")?;
    let mem = capacity::n(evidence, "existing_total_memory")?;
    ensure!(
        cpu == 64_000_000 && mem == 810_658_050_048,
        "unexpected complete host envelope"
    );
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    Ok(
        json!({"schema":"horizon-166-publication-fit-v1","boot_id":boot.trim(),"observed_unix_seconds":custody::now()?,
        "fleet":fleet,"terminal":terminal,"available_bytes":sample["free_bytes"],"protected_bytes":protected,
        "complete_cpu_quota_micros":cpu,"complete_memory_plus_reserve_bytes":mem,"available_memory_bytes":sample["available_memory"],
        "required_available_memory_bytes":sample["required_memory"],"all_existing_commitments_retained":true,
        "resource_credit_bytes":0,"publication_cpu_quota_micros":1_000_000,"publication_memory_bytes":2u64<<30,
        "extra_home_bytes":ADDITIONAL_HOME,"source_producer_invocation_id":live["invocation_id"],"joint136":sample["joint136"]}),
    )
}

pub fn measure(b: &Bound) -> Result<Value> {
    let fit = capacity::capture_publication(b)?;
    let first = fit.evidence["joint_closed166"]["terminal"].clone();
    let terminal: Bound = serde_json::from_value(first.clone())?;
    fit.topology()?;
    let sample = fit.current(ADDITIONAL_HOME)?;
    let end = closed166::evidence()?;
    ensure!(
        end["terminal"] == first && end == fit.evidence["joint_closed166"],
        "166 terminal source changed"
    );
    fit.topology()?;
    let next = fit.current(ADDITIONAL_HOME)?;
    capacity::holding_budget(&capacity::holding_owners()?)?;
    let mut result = publication(b, &terminal, &fit.evidence, &next)?;
    let required = budget(&sample)?.max(budget(&next)?);
    let available = capacity::n(&sample, "free_bytes")?.min(capacity::n(&next, "free_bytes")?);
    let required_mem =
        capacity::n(&sample, "required_memory")?.max(capacity::n(&next, "required_memory")?);
    let available_mem =
        capacity::n(&sample, "available_memory")?.min(capacity::n(&next, "available_memory")?);
    ensure!(
        available >= required
            && available_mem >= required_mem
            && sample["joint136"]["armed"] == next["joint136"]["armed"]
            && ["invocation_id", "admission", "process_tree"]
                .iter()
                .all(|k| sample["joint136"]["identity"][k] == next["joint136"]["identity"][k]),
        "publication participants or headroom changed"
    );
    result["protected_bytes"] = required.into();
    result["available_bytes"] = available.into();
    result["required_available_memory_bytes"] = required_mem.into();
    result["available_memory_bytes"] = available_mem.into();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn charges_the_publication_once_and_preserves_armed_136() {
        let mut sample = json!({"free_bytes":ADDITIONAL_HOME+100,"protected_bytes":40,"available_memory":100,"required_memory":100});
        assert_eq!(budget(&sample).unwrap(), ADDITIONAL_HOME + 40);
        sample["joint136"] = json!({"required_total_bytes":100});
        assert_eq!(budget(&sample).unwrap(), ADDITIONAL_HOME + 100);
        sample["free_bytes"] = (ADDITIONAL_HOME + 99).into();
        assert!(budget(&sample).is_err());
        sample["free_bytes"] = u64::MAX.into();
        sample["protected_bytes"] = u64::MAX.into();
        assert!(budget(&sample).is_err());
    }

    #[test]
    #[ignore = "requires original five native owners, fresh authoritative fleet, and booked HOME measurement"]
    fn original_166_denied_and_real_post_terminal_resource_projection() {
        let path = PathBuf::from(std::env::var("QA_FLEET").unwrap());
        let bound = Bound {
            path,
            sha256: std::env::var("QA_FLEET_SHA").unwrap(),
        };
        assert!(
            measure(&bound)
                .unwrap_err()
                .to_string()
                .contains("166 still executing")
        );
        let fit = capacity::project_publication(&bound).unwrap();
        let sample = fit.await_current(ADDITIONAL_HOME).unwrap();
        assert!(budget(&sample).unwrap() <= capacity::n(&sample, "free_bytes").unwrap());
        assert!(fit.evidence["remaining_native_owners"].get("166").is_none());
        assert!(fit.evidence["remaining_native_owners"].get("172").is_some());
        assert!(fit.evidence["joint_closed166"].is_null());
        assert!(publication(&bound, &bound, &fit.evidence, &sample).is_err());
        let mut fixture = fit.evidence.clone();
        let mock = Bound {
            path: "/private-fixture/TERMINAL_SUCCESS.json".into(),
            sha256: "a".repeat(64),
        };
        fixture["joint_closed166"] = json!({"unit":closed166::NODE,"pid1_success":true,"terminal":mock,"resource_credit_bytes":0,"invocation_id":"private-fixture"});
        let preview = publication(&bound, &mock, &fixture, &sample).unwrap();
        assert_eq!(preview["schema"], "horizon-166-publication-fit-v1");
        assert_eq!(preview["publication_memory_bytes"], 2u64 << 30);
        assert_eq!(preview["fleet"], json!(bound));
        assert_eq!(preview["terminal"], json!(mock));
        assert!(publication(&bound, &bound, &fixture, &sample).is_err());
        let mut crossed = bound.clone();
        crossed.sha256 = "0".repeat(64);
        assert!(capacity::project_publication(&crossed).is_err());
        let qa = PathBuf::from(std::env::var("QA_RUNTIME").unwrap());
        custody::write_new(&qa.join("projected-post166.json"),&json!({"schema":"private-native-projected-fit-no-terminal","fleet":bound,"sample":sample,"retained":fit.evidence,"genuine_terminal":false,"publication_authorized":false})).unwrap();
    }
}
