//! Original-boot custody of the failed pre-incident epoch 145 semantic pass.
use super::*;

#[cfg(incident_focused145_only)]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5d/export145";
#[cfg(all(incident_timeout145_only, not(incident_focused145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5c/export145";
#[cfg(all(incident_rejoin145_only, not(incident_timeout145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5b/export145";
#[cfg(not(incident_rejoin145_only))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5/export145";
pub const PREVIOUS: &str = "add576f115cc4d3b897f47d024af72fd";
const PREVIOUS_IMAGE: &str = "1f9c1c588954811cc031d0a28cd22cffe463d7a20ba07344f4c4728cc0bf6802";
const STAGE: &str =
    "epoch168-full-metered-20261121-v1/same-five-stage-3e9b1aacd1264383bfdc235c05601511.json";
const STAGE_SHA: &str = "76a835a3068d0e16c81820eba6d88cabf227f0c93e55d38f71c71360d3b2b079";
const STARTED: &str = "9cdcfdb688ee018b9cddd43c9c5ba129712195e11d6c8172104a7f4a9a160a28";
const FAIL: &str = "33e011228a58df3c2a82ca49013a7d524eeca1e849fc59993effe5d2faf18e74";

pub fn predecessor() -> Result<Value> {
    let state = Path::new(BASE).join("state").join(PREVIOUS);
    let stage = Bound {
        path: Path::new(RUNTIME).join(STAGE),
        sha256: STAGE_SHA.into(),
    };
    let prior = custody::evidence(&stage)?;
    let captured = &prior["fit"]["phase145"];
    let window = &captured["window"];
    let started = Bound {
        path: state.join("recovery-started.json"),
        sha256: STARTED.into(),
    };
    let failed = Bound {
        path: state.join("failed.json"),
        sha256: FAIL.into(),
    };
    let s = custody::evidence(&started)?;
    let f = custody::evidence(&failed)?;
    let native = continuity::failure(PREVIOUS)?;
    let paid = Path::new(OUTPUT).join(".tmp36MvkN");
    ensure!(
        captured["Id"] == UNIT
            && captured["InvocationID"] == PREVIOUS
            && captured["MainPID"] == "3839142"
            && captured["start_ticks"] == 360478723u64
            && window["native_child"] == json!({"pid":3839343,"start_ticks":360480014u64})
            && window["mode"] == "recover-full-output"
            && window["recovery"] == json!(started)
            && captured["holding_lock"]["device"] == 64512
            && captured["holding_lock"]["inode"] == 95818311
            && native["failure"] == json!(failed)
            && f["iid"] == PREVIOUS
            && f["error"].as_str().is_some_and(|e| e
                .contains("horizon-qualify-independent-cold166-20261120-v1.service")
                && e.contains("exit status: 124"))
            && s["iid"] == PREVIOUS
            && s["image"] == PREVIOUS_IMAGE
            && s["file"] == json!(paid)
            && s["r2_mutations"] == false,
        "different failed frozen 145 generation"
    );
    for key in ["leases_parent", "leases_worker"] {
        let leases = window[key]
            .as_object()
            .context("original paid read leases")?;
        ensure!(
            leases.len() == 3
                && [100214429, 100214450, 103237059]
                    .iter()
                    .all(|ino| leases.get(&ino.to_string()).is_some_and(Value::is_u64)),
            "original paid objects changed"
        );
    }
    ensure!(
        native::ticks(3839142).ok() != Some(360478723)
            && native::ticks(3839343).ok() != Some(360480014),
        "old frozen verifier remains live"
    );
    for n in [
        "source-semantics.json",
        "verified-frozen.json",
        "extraction-complete.json",
        "complete.json",
    ] {
        ensure!(
            !state.join(n).try_exists()?,
            "unexpected completed predecessor evidence: {n}"
        );
    }
    let m = fs::symlink_metadata(&paid)?;
    ensure!(
        paid.canonicalize()? == paid
            && m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o400
            && m.dev() == 64512
            && m.ino() == 103237059
            && m.len() == BYTES,
        "lost original paid frozen output"
    );
    Ok(
        json!({"current_boot_failure":native,"original_leases":stage,"prior_started":started,
        "original_candidate":custody::frozen_identity(&paid)?,"source_checkpoint_exists":false,
        "resource_credit_bytes":0}),
    )
}

#[cfg(incident_rejoin145_only)]
pub fn failed_census() -> Result<Value> {
    const IID: &str = "5e0e20bc974149f096ea4bab10b15e1b";
    let state = Path::new(BASE).join("state").join(IID);
    let failed = continuity::failure(IID)?;
    ensure!(
        failed["failure"]["sha256"]
            == "00de799e968fa8c6e31a76284f0610bcc84bbe617193361ef457629b7294d38f",
        "different native failure"
    );
    let f = custody::evidence(&serde_json::from_value(failed["failure"].clone())?)?;
    let started = Bound {
        path: state.join("recovery-started.json"),
        sha256: "03cf2deacc6d38f5107bb894c59ced4ba2381aac425a1e3d9c401260053ca04f".into(),
    };
    let s = custody::evidence(&started)?;
    let progress = Bound {
        path: Path::new(RUNTIME)
            .join("epoch145-semantic-continuity-20261121-v1/V5_ACTUAL_ADVANCING_WORKER.json"),
        sha256: "511cee5b1559001e5691eda9f9d9de923849dc4a3b661792cade776cad6e55d6".into(),
    };
    let observed = custody::evidence(&progress)?;
    let paid = Path::new(OUTPUT).join(".tmp36MvkN");
    ensure!(
        f["iid"] == IID
            && f["error"] == "stopped worker fresh-census deadline"
            && s["iid"] == IID
            && s["image"] == "0a24d0ab666e532630c3223a9ede9ba86107a65a211041ed0ecd12b35f0b5061"
            && s["file"] == json!(paid)
            && s["r2_mutations"] == false
            && observed["invocation_id"] == IID
            && observed["start"] == json!(started)
            && native::ticks(3890323).ok() != Some(360965610)
            && native::ticks(3890831).ok() != Some(360969081),
        "different prior verifier, file, or terminal"
    );
    verify_observed_pair(&observed, (3890323, 360965610), (3890831, 360969081))?;
    let id = retained_output(&state, &paid)?;
    Ok(
        json!({"current_boot_failure":failed,"prior_started":started,"advancing":progress,
        "original_candidate":id,"source_checkpoint_exists":false,"resource_credit_bytes":0}),
    )
}

#[cfg(incident_rejoin145_only)]
fn verify_observed_pair(observed: &Value, parent: (u32, u64), child: (u32, u64)) -> Result<()> {
    let rows = observed["observations"]
        .as_array()
        .context("prior leased samples")?;
    ensure!(
        rows.len() == 2
            && capacity::n(&rows[1], "source_offset")? > capacity::n(&rows[0], "source_offset")?,
        "missing prior advance"
    );
    for row in rows {
        ensure!(
            row["parent_pid"] == parent.0
                && row["child_pid"] == child.0
                && row["parent_ticks"] == parent.1
                && row["child_ticks"] == child.1
                && row["native_members"] == json!([parent.0.to_string(), child.0.to_string()])
                && row["source_inode"] == 100214450,
            "original epoch145 native pair changed"
        );
        let leases = row["native_leases"]
            .as_array()
            .context("previous native leases")?;
        ensure!(
            leases.len() == 7
                && leases.contains(&json!([
                    "FLOCK",
                    "ADVISORY",
                    "WRITE",
                    parent.0.to_string(),
                    "fc:00:95818311",
                    "0",
                    "EOF"
                ])),
            "different predecessor FLOCK"
        );
        for pid in [parent.0.to_string(), child.0.to_string()] {
            for ino in ["100214429", "100214450", "103237059"] {
                ensure!(
                    leases.contains(&json!([
                        "LEASE",
                        "ACTIVE",
                        "READ",
                        pid,
                        format!("fc:00:{ino}"),
                        "0",
                        "EOF"
                    ])),
                    "missing predecessor lease"
                );
            }
        }
    }
    Ok(())
}

#[cfg(incident_rejoin145_only)]
fn retained_output(state: &Path, paid: &Path) -> Result<Value> {
    for checkpoint in [
        "source-semantics.json",
        "verified-frozen.json",
        "extraction-complete.json",
        "complete.json",
    ] {
        ensure!(
            !state.join(checkpoint).try_exists()?,
            "unexpected durable {checkpoint}"
        );
    }
    let id = custody::frozen_identity(&paid)?;
    ensure!(
        id.device == 64512 && id.inode == 103237059 && id.bytes == BYTES,
        "original frozen candidate changed"
    );
    Ok(json!(id))
}

#[cfg(incident_timeout145_only)]
pub fn failed_manager_query() -> Result<Value> {
    const IID: &str = "dc043eb78c4a4349b0098760dc764a1f";
    let state = Path::new(BASE).join("state").join(IID);
    let failed = continuity::failure(IID)?;
    ensure!(
        failed["failure"]["sha256"]
            == "baa00ca8b52aca80b105bf5582f955af8a3f9e22ce662908ce7a75afccfb1943",
        "different manager-query failure"
    );
    let f = custody::evidence(&serde_json::from_value(failed["failure"].clone())?)?;
    let started = Bound {
        path: state.join("recovery-started.json"),
        sha256: "e992566275e63b28a020c847c02637626b245161a2e39f843ac1da4d64793b2f".into(),
    };
    let s = custody::evidence(&started)?;
    let progress = Bound {
        path: Path::new(RUNTIME)
            .join("epoch145-semantic-continuity-20261121-v1/V5B_ACTUAL_ADVANCING_WORKER.json"),
        sha256: "c8c4a5572906fb348658759ed4c81a7edaf4ee790faab391d700ad9fd4e4c199".into(),
    };
    let observed = custody::evidence(&progress)?;
    let manager: Bound = serde_json::from_value(observed["manager"].clone())?;
    let actual = custody::evidence(&manager)?;
    let paid = Path::new(OUTPUT).join(".tmp36MvkN");
    let trace = f["error"]
        .as_str()
        .and_then(|e| e.strip_prefix("complete 145 capacity observation failed exit status: 1: "))
        .context("missing native timeout trace")?;
    ensure!(
        f["iid"] == IID
            && crate::incident_fit::manager_timeout(
                trace,
                "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v6/post-stop-fit"
            ) == Some("horizon-qualify-168-full-metered-20261121-v1.service")
            && s["iid"] == IID
            && s["image"] == "710b9c840fe26d964874fa6fadc2b0be9fc59d011755ce5da57a46c6ca2349f1"
            && s["file"] == json!(paid)
            && s["r2_mutations"] == false
            && observed["invocation_id"] == IID
            && observed["start"] == json!(started)
            && observed["resource_credit_bytes"] == 0
            && manager.sha256 == "f17ed7e2c744287b42fa8fe3fbbf922bb8e534fb9e8361b98c64b5dcda5c8525"
            && actual["new"]["InvocationID"] == IID
            && actual["parent_pid"] == 3944205
            && actual["parent_start_ticks"] == 361483926
            && native::ticks(3944205).ok() != Some(361483926)
            && native::ticks(3944778).ok() != Some(361486356),
        "different epoch 145 verifier or terminal"
    );
    verify_observed_pair(&observed, (3944205, 361483926), (3944778, 361486356))?;
    let rows = &observed["observations"];
    ensure!(
        capacity::n(&rows[1], "worker_cpu_ticks")? > capacity::n(&rows[0], "worker_cpu_ticks")?,
        "missing CPU advancement"
    );
    let id = retained_output(&state, &paid)?;
    Ok(
        json!({"current_boot_failure":failed,"prior_started":started,"advancing":progress,"prior_manager":manager,"original_candidate":id,"source_checkpoint_exists":false,"resource_credit_bytes":0}),
    )
}

/// Bind the natural V5C failure to its original paid candidate and advancing worker.
#[cfg(incident_focused145_only)]
pub fn failed_status_owner() -> Result<Value> {
    const IID: &str = "d37f36f898a44932a19fd50d7014a6fe";
    let base = Path::new(RUNTIME).join("epoch145-semantic-continuity-20261121-v1");
    let state = Path::new(BASE).join("state").join(IID);
    let failed = continuity::failure(IID)?;
    ensure!(
        failed["failure"]["sha256"]
            == "6533e594be11534e7fb58ac0f1fd752ead37cfd114e36899a956970b8318bb29",
        "wrong original status failure"
    );
    let failure = custody::evidence(&serde_json::from_value(failed["failure"].clone())?)?;
    let started = Bound {
        path: state.join("recovery-started.json"),
        sha256: "a3d623b47ea9612824d102714703b0d095db18e07bf8ce3570ec08331ad84e81".into(),
    };
    let original = custody::evidence(&started)?;
    let progress = Bound {
        path: base.join("V5C_ACTUAL_ADVANCING_WORKER.json"),
        sha256: "6235fbd8e36064d57a9cd6b7af2ad0d05ce8b41766134cde7be7337ebc133d76".into(),
    };
    let observed = custody::evidence(&progress)?;
    let manager: Bound = serde_json::from_value(observed["manager"].clone())?;
    let native = custody::evidence(&manager)?;
    let paid = Path::new(OUTPUT).join(".tmp36MvkN");
    let original_identity = retained_output(&state, &paid)?;
    let trace = failure["error"]
        .as_str()
        .and_then(|t| t.strip_prefix("complete 145 capacity observation failed exit status: 1: "))
        .context("missing original status error")?;
    ensure!(
        failure["iid"] == IID
            && crate::incident_fit::missing_status_owner(
                trace,
                "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v10/post-stop-fit"
            )
            && observed["start"] == json!(started)
            && observed["invocation_id"] == IID
            && manager.sha256 == "9e1ff569a5f6373a9f0d8a2c6339ce9a5d91bff92009f3e5ead9bb105f9d1f44"
            && native["new"]["InvocationID"] == IID
            && native["parent_pid"] == 4011654
            && native["parent_start_ticks"] == 362077125u64
            && original["image"]
                == "34d90f2a5ae8a821109b2bbf99c5527d43c3eb141f68cea212109fc876f28c8d"
            && original["iid"] == IID
            && original["file"] == json!(paid)
            && original["r2_mutations"] == false
            && original["prior_frozen_recovery"]["failed_preincident_verifier"]["original_candidate"]
                == original_identity
            && native::ticks(4011654).ok() != Some(362077125)
            && native::ticks(4011889).ok() != Some(362079682),
        "different paid verifier, original failure or frozen candidate"
    );
    verify_observed_pair(&observed, (4011654, 362077125), (4011889, 362079682))?;
    Ok(
        json!({"current_boot_failure":failed,"prior_started":started,"advancing":progress,"prior_manager":manager,
              "original_candidate":original_identity,"source_checkpoint_exists":false,"resource_credit_bytes":0}),
    )
}

#[cfg(all(test, incident_focused145_only))]
#[test]
#[ignore = "requires the original terminal 145 verifier and guard artifacts"]
fn preserves_the_actual_cadence_failure_and_frozen_inode() {
    let prior = failed_status_owner().unwrap();
    assert_eq!(prior["original_candidate"]["inode"], 103237059);
    assert_eq!(prior["source_checkpoint_exists"], false);
    let reference: Bound =
        serde_json::from_value(prior["current_boot_failure"]["failure"].clone()).unwrap();
    let failed = custody::evidence(&reference).unwrap();
    let trace = failed["error"]
        .as_str()
        .unwrap()
        .strip_prefix("complete 145 capacity observation failed exit status: 1: ")
        .unwrap();
    let provider = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v10/post-stop-fit";
    for (old, new) in [
        (provider, "/other-provider"),
        ("in registered_status", "in other"),
        ("cadence publisher absent", "source corrupt"),
        ("status168.py", "unregistered.py"),
        ("raise ValueError(message)", "raise OtherError(message)"),
    ] {
        let other = trace.replace(old, new);
        assert_ne!(other, trace);
        assert!(!crate::incident_fit::missing_status_owner(&other, provider));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(incident_timeout145_only)]
    #[test]
    #[ignore = "requires the original manager's native failure"]
    fn distinguishes_native_query_timeout_from_foreign_or_malformed_failures() {
        let p = Path::new(BASE).join("state/dc043eb78c4a4349b0098760dc764a1f/failed.json");
        let original = custody::evidence(&Bound {
            path: p,
            sha256: "baa00ca8b52aca80b105bf5582f955af8a3f9e22ce662908ce7a75afccfb1943".into(),
        })
        .unwrap();
        let actual = original["error"]
            .as_str()
            .unwrap()
            .strip_prefix("complete 145 capacity observation failed exit status: 1: ")
            .unwrap();
        let provider = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v6/post-stop-fit";
        let unit = "horizon-qualify-168-full-metered-20261121-v1.service";
        assert_eq!(
            crate::incident_fit::manager_timeout(actual, provider),
            Some(unit)
        );
        for (old, new) in [
            (unit, "other.service"),
            ("timed out after 10", "timed out after 1"),
            ("'/usr/bin/systemctl'", "'/tmp/systemctl'"),
            (" 'show',", " 'stop',"),
            ("CPUQuotaPerSecUSec", "MainPID"),
            ("in _check_timeout", "in other_call"),
            ("status168.py", "foreign.py"),
            ("subprocess.TimeoutExpired:", "RuntimeError:"),
            ("tools-v6/post-stop-fit", "other/provider"),
        ] {
            let changed = actual.replace(old, new);
            assert_ne!(changed, actual);
            assert_eq!(
                crate::incident_fit::manager_timeout(&changed, provider),
                None,
                "{old}"
            );
        }
        assert_eq!(
            crate::incident_fit::manager_timeout(&format!("{actual}different failure"), provider),
            None
        );
    }
    #[test]
    #[ignore = "requires the original root-owned stopped verifier and frozen inode"]
    fn failed_145_pass_keeps_the_original_leased_objects_and_requires_restart() {
        let r = predecessor().unwrap();
        assert_eq!(r["current_boot_failure"]["failure"]["sha256"], FAIL);
        assert_eq!(r["original_candidate"]["inode"], 103237059);
        assert_eq!(r["source_checkpoint_exists"], false);
        #[cfg(incident_rejoin145_only)]
        assert_eq!(
            failed_census().unwrap()["original_candidate"]["inode"],
            103237059
        );
        #[cfg(incident_timeout145_only)]
        assert_eq!(
            failed_manager_query().unwrap()["original_candidate"]["inode"],
            103237059
        );
        assert!(
            verify_cgroup().is_err(),
            "a build service cannot act as the production verifier"
        );
    }
}
