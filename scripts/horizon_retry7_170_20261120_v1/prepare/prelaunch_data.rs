//! Read the guard's genuine own-image witness before launch. No fabricated IID.
use super::*;
pub(super) const RUNTIME: &str =
    "/usr/local/lib/jetstreamer/horizon-retry4-166-data-guard-20261114-v1/guard";
pub(super) const TERMINAL_RUNTIME: &str =
    "/usr/local/lib/jetstreamer/horizon-peer170-terminal169-data-guard-20261115-v1/guard";
const LEGACY_RUNTIME: &str =
    "/usr/local/lib/jetstreamer/horizon-retry3-data-guard-20261113-v1/guard";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub contract: data_fulfillment::Binding,
    pub runtime: Bound,
    pub runtime_seal: Bound,
    pub qualification: Bound,
}
pub(super) fn shape(r: &Request) -> Result<()> {
    ensure!(
        [
            Path::new(RUNTIME),
            Path::new(LEGACY_RUNTIME),
            Path::new(TERMINAL_RUNTIME),
            Path::new(completed167_native_guard::RUNTIME),
            Path::new(retry167_native_guard::RUNTIME),
            Path::new(retry170::GUARD_RUNTIME)
        ]
        .contains(&r.runtime.path.as_path())
            && lower_hex(&r.runtime.sha256, 64),
        "exact successor guard image required"
    );
    ensure!(
        r.runtime_seal.path
            == r.runtime
                .path
                .as_path()
                .parent()
                .context("runtime parent")?
                .join("deployment-seal-receipt.json"),
        "normal runtime seal required"
    );
    for b in [&r.runtime_seal, &r.qualification] {
        ensure!(
            b.path.is_absolute() && lower_hex(&b.sha256, 64),
            "bound Root proof required"
        );
    }
    Ok(())
}
fn proof_shape(r: &Request, seal: &Value, qualified: &Value) -> Result<()> {
    shape(r)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["sealer_sha256"] == SEALER_SHA
            && seal["destination"]
                == r.runtime
                    .path
                    .as_path()
                    .parent()
                    .context("runtime parent")?
                    .to_str()
                    .context("UTF8")?
            && seal["replay_launch_authorized"] == false
            && seal["remote_mutations"] == false,
        "normal successor runtime seal differs"
    );
    let members = seal["members"].as_array().context("runtime seal members")?;
    let selected: Vec<_> = members.iter().filter(|v| v["name"] == "guard").collect();
    ensure!(
        selected.len() == 1
            && selected[0]["sha256"] == r.runtime.sha256
            && selected[0]["mode"] == "0555",
        "exact normally sealed guard member required"
    );
    ensure!(
        qualified["schema"] == "horizon-retry3-guard-build-acceptance-v1"
            && qualified["owner"] == "/root"
            && qualified["primary_thread"] == THREAD
            && qualified["runtime"] == serde_json::to_value(&r.runtime)?
            && qualified["four_strict_configurations_passed"] == true
            && qualified["ordinary_tests_passed"]
                .as_u64()
                .is_some_and(|n| n >= 54)
            && qualified["replay_launch_authorized"] == false
            && qualified["resource_credit_bytes"] == 0,
        "exact-image Root build acceptance required"
    );
    Ok(())
}
pub(super) fn authenticate(r: &Request) -> Result<()> {
    shape(r)?;
    if r.runtime.path == Path::new(retry170::GUARD_RUNTIME) {
        return crate::retry170_guard::authenticate(r);
    }
    if r.runtime.path == Path::new(retry167_native_guard::RUNTIME) {
        ensure!(
            serde_json::to_value(&r.qualification)?
                == retry167_native_guard::qualification_binding()
                && serde_json::to_value(&r.runtime_seal)? == retry167_native_guard::seal_binding(),
            "exact candidate167 successor guard native proof and normal seal required"
        );
        retry167_native_guard::authenticate(
            &serde_json::to_value(&r.runtime)?,
            &serde_json::to_value(&r.qualification)?,
            &serde_json::to_value(&r.runtime_seal)?,
            |v| bound(&serde_json::from_value(v.clone())?),
        )?;
        fixed(
            r.runtime
                .path
                .to_str()
                .context("successor guard path UTF8")?,
            &r.runtime.sha256,
            32 << 20,
        )?;
        ensure!(
            fs::symlink_metadata(&r.runtime.path)?.mode() & 0o7777 == 0o555,
            "successor guard must be normally sealed0555"
        );
        return Ok(());
    }
    if r.runtime.path == Path::new(completed167_native_guard::RUNTIME) {
        ensure!(
            serde_json::to_value(&r.qualification)?
                == completed167_native_guard::qualification_binding()
                && serde_json::to_value(&r.runtime_seal)?
                    == completed167_native_guard::seal_binding(),
            "exact successor guard proof and seal required"
        );
        completed167_native_guard::authenticate(
            &serde_json::to_value(&r.runtime)?,
            &serde_json::to_value(&r.qualification)?,
            &serde_json::to_value(&r.runtime_seal)?,
            |v| bound(&serde_json::from_value(v.clone())?),
        )?;
    }
    fixed(
        r.runtime.path.to_str().context("guard path UTF8")?,
        &r.runtime.sha256,
        32 << 20,
    )?;
    ensure!(
        fs::symlink_metadata(&r.runtime.path)?.mode() & 0o7777 == 0o555,
        "sealed guard mode differs"
    );
    let seal = bound(&r.runtime_seal)?;
    let qualified = bound(&r.qualification)?;
    if r.runtime.path == Path::new(completed167_native_guard::RUNTIME) {
        return Ok(()); // The complete native proof was authenticated before image IO.
    }
    if r.runtime.path == Path::new(TERMINAL_RUNTIME) {
        return native_guard::authenticate(
            &serde_json::to_value(&r.runtime)?,
            &serde_json::to_value(&r.qualification)?,
            &serde_json::to_value(&r.runtime_seal)?,
            |v| bound(&serde_json::from_value(v.clone())?),
        );
    }
    proof_shape(r, &seal, &qualified)?;
    let executions = qualified["executions"]
        .as_object()
        .context("actual five strict build/test executions")?;
    ensure!(
        executions.len() == 5,
        "exact five build/test executions required"
    );
    for key in [
        "production",
        "build-tests",
        "clippy-production",
        "clippy-tests",
        "ordinary-tests",
    ] {
        let b: Bound = serde_json::from_value(
            executions
                .get(key)
                .context("actual execution missing")?
                .clone(),
        )?;
        let result = bound(&b)?;
        ensure!(result["code"] == 0, "actual build/test execution failed");
    }
    Ok(())
}
pub(super) fn freshness(evidence: &Value, at: u64) -> Result<()> {
    let t = evidence["qualified_native_recorded_unix_seconds"]
        .as_u64()
        .context("native witness clock")?;
    ensure!(
        t <= at && at - t <= 120,
        "prelaunch native witness stale or future"
    );
    Ok(())
}
pub(super) fn observe(r: &Request, review: &Review, available: u64, at: u64) -> Result<Value> {
    authenticate(r)?;
    let observed = data_fulfillment::observe_preparation(
        &serde_json::to_value(&r.contract)?,
        Path::new("/home/sol"),
        available,
        &data_fulfillment::Bound {
            path: r.runtime.path.clone(),
            sha256: r.runtime.sha256.clone(),
        },
    )?;
    let completed = now()?;
    ensure!(
        at <= completed,
        "prelaunch observation clock moved backwards"
    );
    freshness(&observed.evidence, completed)?;
    ensure!(
        observed.available_plus_fulfilled_bytes
            == observed
                .conservative_available_bytes
                .checked_add(observed.fulfilled_bytes)
                .context("DATA observation overflow")?
            && observed.effective_required_free_bytes
                == FLOOR
                    .checked_sub(observed.fulfilled_bytes)
                    .context("historical DATA underflow")?,
        "historical observation arithmetic differs"
    );
    let point = current_budget::disk_point(
        observed.conservative_available_bytes,
        observed.fulfilled_bytes,
        review.minimum_initial_available_data_bytes,
        review.additional_growth_not_covered_by_existing_promise_bytes,
        review.fresh_subtree_overlap_booked_bytes,
    )?;
    Ok(
        json!({"current_fit":point,"qualified_witness":observed.evidence,"qualified_guard":r.runtime,"guard_runtime_seal":r.runtime_seal,"guard_build_acceptance":r.qualification,"prelaunch_native_witness_maximum_age_seconds":120,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}
#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn request() -> Request {
        let b = Bound {
            path: "/var/lib/qualification.json".into(),
            sha256: "b".repeat(64),
        };
        Request {
            contract: data_fulfillment::Binding {
                contract: data_fulfillment::Bound {
                    path: "/sealed/contract.json".into(),
                    sha256: "c".repeat(64),
                },
                deployment_seal: data_fulfillment::Bound {
                    path: "/sealed/deployment-seal-receipt.json".into(),
                    sha256: "d".repeat(64),
                },
            },
            runtime: Bound {
                path: RUNTIME.into(),
                sha256: "a".repeat(64),
            },
            runtime_seal: Bound {
                path: Path::new(RUNTIME)
                    .parent()
                    .unwrap()
                    .join("deployment-seal-receipt.json"),
                sha256: "e".repeat(64),
            },
            qualification: b,
        }
    }
    #[test]
    fn stale_missing_and_future_native_clocks_rejected() {
        freshness(
            &json!({"qualified_native_recorded_unix_seconds":1000}),
            1120,
        )
        .unwrap();
        assert!(
            freshness(
                &json!({"qualified_native_recorded_unix_seconds":1000}),
                1121
            )
            .is_err()
        );
        assert!(
            freshness(
                &json!({"qualified_native_recorded_unix_seconds":1001}),
                1000
            )
            .is_err()
        );
        assert!(freshness(&json!({}), 1000).is_err());
    }
    #[test]
    fn exact_runtime_seal_and_acceptance_are_bound_together() {
        let r = request();
        let seal = json!({"schema":"jetstreamer-sealed-deployment-receipt-v1","sealer_sha256":SEALER_SHA,"destination":Path::new(RUNTIME).parent().unwrap(),"members":[{"name":"guard","sha256":r.runtime.sha256,"mode":"0555"}],"replay_launch_authorized":false,"remote_mutations":false});
        let mut acceptance = json!({"schema":"horizon-retry3-guard-build-acceptance-v1","owner":"/root","primary_thread":THREAD,"runtime":r.runtime,"four_strict_configurations_passed":true,"ordinary_tests_passed":54,"replay_launch_authorized":false,"resource_credit_bytes":0});
        proof_shape(&r, &seal, &acceptance).unwrap();
        acceptance["runtime"]["sha256"] = json!("f".repeat(64));
        assert!(proof_shape(&r, &seal, &acceptance).is_err());
        let mut changed = r.clone();
        changed.runtime.path = "/tmp/foreign-guard".into();
        assert!(shape(&changed).is_err());
        let mut changed = seal;
        changed["members"][0]["mode"] = json!("0755");
        assert!(proof_shape(&r, &changed, &acceptance).is_err());
    }

    #[test]
    fn complete_successor_guard_reader_uses_genuine_artifact_and_normal_seal() {
        let mut r = request();
        r.runtime = Bound {
            path: completed167_native_guard::RUNTIME.into(),
            sha256: completed167_native_guard::IMAGE_SHA.into(),
        };
        r.qualification =
            serde_json::from_value(completed167_native_guard::qualification_binding()).unwrap();
        r.runtime_seal = serde_json::from_value(completed167_native_guard::seal_binding()).unwrap();
        authenticate(&r).unwrap();
        let mut bad = r.clone();
        bad.qualification.sha256 = "f".repeat(64);
        assert!(authenticate(&bad).is_err());
        let mut bad = r.clone();
        bad.runtime_seal.sha256 = "f".repeat(64);
        assert!(authenticate(&bad).is_err());
        let mut bad = r.clone();
        bad.runtime.sha256 = "f".repeat(64);
        assert!(authenticate(&bad).is_err());
        let mut bad = r;
        bad.runtime.path = TERMINAL_RUNTIME.into();
        assert!(authenticate(&bad).is_err());
    }
}
