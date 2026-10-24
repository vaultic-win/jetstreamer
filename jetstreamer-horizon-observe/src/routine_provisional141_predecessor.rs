//! Continue from the real, successful 0813 ledger after only its duplicate
//! final read exceeded freshness. Never mark the failed read successful.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261023T081357Z-controller-rebind-repair185-repair183-upload144-census141-boundaries-native141-all-retry-public160-timed-scans-upload198-v1";
const LEDGER_SHA: &str = "bb9ea6318c17027a72fa71b64e2a09f4b2cf18b2db27a3e41e6e23dabd07f724";
pub(super) fn candidate(p: &Plan) -> bool {
    p.schema == PLAN_SCHEMA_101
        && p.previous_fleet.path == Path::new(ROOT).join("public198-provisional-fleet.json")
}
fn checked_receipt(p: &Plan, v: &Value) -> Result<()> {
    ensure!(
        candidate(p)
            && p.previous_fleet.sha256 == LEDGER_SHA
            && p.previous_observer.sha256
                == "5cb6d07c82f38c9a122c0bd71623acb0886a71ef5dc0a612f70274783cf7d122"
            && p.model_template.sha256
                == "235381c2f3b8c9025bd81ecd8ee27c1de07b93aaff8a73ddb1d0c03bd4e79de1"
            && p.previous_estimates.sha256
                == "a8664c9f6ea8a3903aa3b8fe73519b0f5d21bf26b19f4ca053106edf0e90a32a"
            && p.fleet_template.sha256
                == "49d7e1ec63bde96f639bb674dcdabd2f4d871337d065bf77ae5d1251be3f44ad"
            && p.observer_config.sha256
                == "7965946e9e45012789c55dfbbe86f456ac5d24a45dac535a4babaafaa1a09ce7"
            && v["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && v["first_epoch"] == 101
            && v["last_epoch"] == 200
            && v["sampled_at_utc"] == "2026-10-23T08:13:57Z"
            && v["observer_sha256"] == p.previous_observer.sha256
            && v["plan_sha256"] == p.fleet_template.sha256
            && v["plan"].as_str() == p.fleet_template.path.to_str()
            && v["inventory"]["anomalies"] == 0
            && v["producer_mutations"] == false
            && v["remote_mutations"] == false
            && v["publication_authorized"] == false,
        "foreign provisional 141 predecessor"
    );
    let t = utc_seconds(v["sampled_at_utc"].as_str().unwrap())?;
    ensure!(
        v["recorded_unix_seconds"]
            .as_u64()
            .is_some_and(|n| n >= t && n - t <= 1800),
        "provisional ledger was not committed while its source was fresh"
    );
    Ok(())
}
pub(super) fn canonical_predecessor(p: &Plan, v: &Value) -> Result<Option<Bound>> {
    if !candidate(p) {
        return Ok(None);
    }
    checked_receipt(p, v)?;
    // Verify the already completed R2 command, original failure, and exact
    // output-only difference between its two independently sealed plans.
    let failure = bound_json(
        &Bound {
            path: Path::new(ROOT).join("failure.json"),
            sha256: "9d3bf2430359fc78544b10c8f3c18142a2953f5caae5cbbce12ffe6a5b5f9c4d".into(),
        },
        false,
    )?;
    ensure!(
        failure["plan"]["sha256"]
            == "56e1ceeb96609df7843c716d2546af995e96f7b48c284d088b01f9465a6a3b36"
            && failure["observer"]["sha256"] == p.previous_observer.sha256
            && failure["automatic_retry_authorized"] == false,
        "provisional predecessor failure lineage differs"
    );
    let read = |name: &str| -> Result<Value> {
        Ok(serde_json::from_slice(&read_checked(
            &Path::new(ROOT).join(name),
            LIMIT,
            0,
            false,
        )?)?)
    };
    let rejected = read("child-fleet.json")?;
    ensure!(
        rejected["success"] == false
            && rejected["exit_code"] == 1
            && rejected["signal"].is_null()
            && rejected["tool"] == serde_json::to_value(&p.tools.r2)?
            && rejected["stderr"]["text"]
                == "Error: observer became stale during fleet reconciliation\n",
        "not the exact failed duplicate fleet read"
    );
    let succeeded = read("child-public198-fleet.json")?;
    ensure!(
        succeeded["success"] == true
            && succeeded["exit_code"] == 0
            && succeeded["signal"].is_null()
            && succeeded["tool"] == serde_json::to_value(&p.tools.r2)?,
        "provisional R2 command did not succeed"
    );
    let mut original = bound_json(
        &Bound {
            path: Path::new(ROOT).join("sealed/fleet-plan.json"),
            sha256: "1d30ca6423ac4a3931d0a4ad15974e90b85a9941bfa59b4d23b7d33c3e9a3fea".into(),
        },
        true,
    )?;
    original["output"] = json!(p.previous_fleet.path);
    ensure!(
        original == bound_json(&p.fleet_template, true)?,
        "provisional plan changes more than output"
    );
    let canonical: Bound = serde_json::from_value(v["previous_fleet"].clone())?;
    ensure!(
        canonical.path == Path::new(FLEET_ROOT_101).join("fleet-20261023T073958Z.json")
            && canonical.sha256
                == "ce0d0b87e33e7444b2e93f8f670d7a2f92900f019e58fd43075e7d808c33cff1",
        "provisional ledger forks canonical history"
    );
    bound_json(&canonical, false)?;
    Ok(Some(canonical))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_real_fresh_committed_receipt_can_bridge_a_failed_duplicate() {
        let (mut p, ..) = crate::tests::fixture101();
        p.previous_fleet = Bound {
            path: Path::new(ROOT).join("public198-provisional-fleet.json"),
            sha256: LEDGER_SHA.into(),
        };
        p.previous_observer.sha256 =
            "5cb6d07c82f38c9a122c0bd71623acb0886a71ef5dc0a612f70274783cf7d122".into();
        p.model_template.sha256 =
            "235381c2f3b8c9025bd81ecd8ee27c1de07b93aaff8a73ddb1d0c03bd4e79de1".into();
        p.previous_estimates.sha256 =
            "a8664c9f6ea8a3903aa3b8fe73519b0f5d21bf26b19f4ca053106edf0e90a32a".into();
        p.fleet_template.sha256 =
            "49d7e1ec63bde96f639bb674dcdabd2f4d871337d065bf77ae5d1251be3f44ad".into();
        p.observer_config.sha256 =
            "7965946e9e45012789c55dfbbe86f456ac5d24a45dac535a4babaafaa1a09ce7".into();
        let t = utc_seconds("2026-10-23T08:13:57Z").unwrap();
        let v = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,"sampled_at_utc":"2026-10-23T08:13:57Z","observer_sha256":p.previous_observer.sha256,"plan_sha256":p.fleet_template.sha256,"plan":p.fleet_template.path,"inventory":{"anomalies":0},"producer_mutations":false,"remote_mutations":false,"publication_authorized":false,"recorded_unix_seconds":t+1800});
        checked_receipt(&p, &v).unwrap();
        for (k, value) in [
            ("recorded_unix_seconds", json!(t + 1801)),
            ("observer_sha256", json!("foreign")),
            ("publication_authorized", json!(true)),
            ("last_epoch", json!(300)),
        ] {
            let mut bad = v.clone();
            bad[k] = value;
            assert!(checked_receipt(&p, &bad).is_err(), "{k}");
        }
    }
}
