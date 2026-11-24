//! Original-boot custody of the failed pre-incident epoch 145 semantic pass.
use super::*;

#[cfg(all(incident_encoded_prefix145_only, not(incident_audit_turnover145_only)))]
compile_error!("the encoded-prefix successor requires the complete audit-turnover guard");

#[cfg(all(incident_v5s_guard_recovery145_only, not(incident_v5r_guard_recovery145_only)))]
compile_error!("the allocation-walk retry requires the guarded verifier");

#[cfg(all(incident_v5t_guard_recovery145_only, not(incident_v5s_guard_recovery145_only)))]
compile_error!("the fresh-census retry requires the allocation-walk guard");

#[cfg(all(incident_v5u_guard_recovery145_only, not(incident_v5t_guard_recovery145_only)))]
compile_error!("the timed-out V5u successor requires the previous fresh-census guard");

#[cfg(incident_v5u_guard_recovery145_only)]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5v/export145";
#[cfg(all(incident_v5t_guard_recovery145_only, not(incident_v5u_guard_recovery145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5u/export145";
#[cfg(all(incident_v5s_guard_recovery145_only, not(incident_v5t_guard_recovery145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5t/export145";
#[cfg(all(incident_v5r_guard_recovery145_only, not(incident_v5s_guard_recovery145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5s/export145";
#[cfg(all(incident_encoded_prefix145_only, not(incident_v5r_guard_recovery145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5r/export145";
#[cfg(all(incident_audit_turnover145_only, not(incident_encoded_prefix145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5q/export145";
#[cfg(all(incident_status_owner145_only, not(incident_audit_turnover145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5p/export145";
#[cfg(all(incident_donor_pressure145_only, not(incident_status_owner145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5o/export145";
#[cfg(all(incident_guard_walk145_only, not(incident_donor_pressure145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5n/export145";
#[cfg(all(incident_missed_clock145_only, not(incident_guard_walk145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5m/export145";
#[cfg(all(incident_lease_start145_only, not(incident_missed_clock145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5k/export145";
#[cfg(all(incident_retry4_145_only, not(incident_lease_start145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5j/export145";
#[cfg(all(incident_retry3_145_only, not(incident_retry4_145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5i/export145";
#[cfg(all(incident_five_lane145_only, not(incident_retry3_145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5h/export145";
#[cfg(all(incident_homefloor145_only, not(incident_five_lane145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5g/export145";
#[cfg(all(incident_fixture145_only, not(incident_homefloor145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5f/export145";
#[cfg(all(incident_timer145_only, not(incident_fixture145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5e/export145";
#[cfg(all(incident_focused145_only, not(incident_timer145_only)))]
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

#[cfg(incident_v5u_guard_recovery145_only)]
pub fn failed_v5u() -> Result<Value> {
    let iid = "8452dba9df42437b9874b35cb44d059f";
    let state = Path::new(BASE).join("state").join(iid);
    let startup = Bound {
        path: state.join("recovery-started.json"),
        sha256: "85dede3d71e27414b28369d1686fe4d7e9ee207bcf6ac4a2c083836961149549".into(),
    };
    let failure = Bound {
        path: state.join("failed.json"),
        sha256: "635ca9e4a87decf519815c27728b2b49884ff3f4e1149f2542d8f931f3731609".into(),
    };
    let start = custody::evidence(&startup)?;
    let native = continuity::failure(iid)?;
    let terminal_file = Path::new(RUNTIME).join(
        "epoch145-semantic-continuity-20261121-v1/v5v-name-handoff/V5U_TERMINAL.json",
    );
    let terminal = custody::binding(&terminal_file)?;
    let preflight = custody::evidence(&terminal)?;
    let file = materialized::leaf()?;
    let id = custody::frozen_identity(&file)?;
    ensure!(
        start["iid"] == iid
            && start["image"] == "18f46b23edd8061eb7ed9ae1566134bc7ea2cbaa6fa7b85cdd1745488366dca4"
            && start["file"] == json!(file)
            && start["r2_mutations"] == false
            && native["failure"] == json!(failure)
            && preflight["schema"] == "horizon-epoch145-v5u-query-timeout-terminal-v1"
            && preflight["startup"] == json!(startup)
            && preflight["failure"] == json!(failure)
            && preflight["manager"]["InvocationID"] == iid
            && preflight["manager"]["Result"] == "exit-code"
            && preflight["candidate"]["path"] == json!(file)
            && preflight["candidate"]["device"] == id.device
            && preflight["candidate"]["inode"] == id.inode
            && preflight["candidate"]["bytes"] == id.bytes
            && preflight["candidate"]["mtime_ns"].as_i64().map(i128::from) == Some(id.mtime_ns)
            && preflight["candidate"]["ctime_ns"].as_i64().map(i128::from) == Some(id.ctime_ns)
            && preflight["resource_credit_bytes"] == 0
            && preflight["archive_publication_authorized"] == false
            && preflight["r2_mutations"] == false,
        "V5u terminal and immutable paid candidate do not agree"
    );
    Ok(json!({"terminal":terminal,"current_boot_failure":native,"startup":startup}))
}

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
struct FailedObservation {
    iid: &'static str,
    failure_hash: &'static str,
    start_hash: &'static str,
    progress_name: &'static str,
    progress_sha: &'static str,
    manager_sha: &'static str,
    prior_image: &'static str,
    provider: &'static str,
    recognize: fn(&str, &str) -> bool,
    parent: (u32, u64),
    child: (u32, u64),
}

#[cfg(incident_focused145_only)]
pub fn failed_status_owner() -> Result<Value> {
    failed_observation(FailedObservation {
        iid: "d37f36f898a44932a19fd50d7014a6fe",
        failure_hash: "6533e594be11534e7fb58ac0f1fd752ead37cfd114e36899a956970b8318bb29",
        start_hash: "a3d623b47ea9612824d102714703b0d095db18e07bf8ce3570ec08331ad84e81",
        progress_name: "V5C_ACTUAL_ADVANCING_WORKER.json",
        progress_sha: "6235fbd8e36064d57a9cd6b7af2ad0d05ce8b41766134cde7be7337ebc133d76",
        manager_sha: "9e1ff569a5f6373a9f0d8a2c6339ce9a5d91bff92009f3e5ead9bb105f9d1f44",
        prior_image: "34d90f2a5ae8a821109b2bbf99c5527d43c3eb141f68cea212109fc876f28c8d",
        provider: "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v10/post-stop-fit",
        recognize: crate::incident_fit::missing_status_owner,
        parent: (4011654, 362077125),
        child: (4011889, 362079682),
    })
}

#[cfg(incident_timer145_only)]
pub fn failed_timer_inspection() -> Result<Value> {
    failed_observation(FailedObservation {
        iid: "e6551a0bb8a14b989902e15c9ecc0751",
        failure_hash: "9ef9c938290ea2b43d3b2ce4aa617f08b33f4c893961e63f53ba3f48768e215f",
        start_hash: "55d2a0504271e8a1eea2ca8c105a288be9497f1a2b80177279481692d06e041f",
        progress_name: "V5D_RETRY1_ACTUAL_ADVANCING_WORKER.json",
        progress_sha: "3a41dac31746938b482133b9ff224f9d9d821569cc16f63c83f872fe907c13e0",
        manager_sha: "4e16813452fb3a5e965b6f939aa632c5b435592911a8c592ca9989abd4c24f85",
        prior_image: "3d60de86d45a497bcd1b9836c485ffab4ce1da19cb6d989d56c9d3b92ad60066",
        provider: "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v14/post-stop-fit",
        recognize: crate::incident_fit::timer_inspection_timeout,
        parent: (11975, 364473153),
        child: (12292, 364475843),
    })
}

#[cfg(incident_focused145_only)]
fn failed_observation(
    FailedObservation {
        iid,
        failure_hash,
        start_hash,
        progress_name,
        progress_sha,
        manager_sha,
        prior_image,
        provider,
        recognize,
        parent,
        child,
    }: FailedObservation,
) -> Result<Value> {
    let base = Path::new(RUNTIME).join("epoch145-semantic-continuity-20261121-v1");
    let state = Path::new(BASE).join("state").join(iid);
    let failed = continuity::failure(iid)?;
    ensure!(
        failed["failure"]["sha256"] == failure_hash,
        "wrong original status failure"
    );
    let failure = custody::evidence(&serde_json::from_value(failed["failure"].clone())?)?;
    let started = Bound {
        path: state.join("recovery-started.json"),
        sha256: start_hash.into(),
    };
    let original = custody::evidence(&started)?;
    let progress = Bound {
        path: base.join(progress_name),
        sha256: progress_sha.into(),
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
        failure["iid"] == iid
            && recognize(trace, provider)
            && observed["start"] == json!(started)
            && observed["invocation_id"] == iid
            && manager.sha256 == manager_sha
            && native["new"]["InvocationID"] == iid
            && native["parent_pid"] == parent.0
            && native["parent_start_ticks"] == parent.1
            && original["image"] == prior_image
            && original["iid"] == iid
            && original["file"] == json!(paid)
            && original["r2_mutations"] == false
            && original["prior_frozen_recovery"]["failed_preincident_verifier"]["original_candidate"]
                == original_identity
            && native::ticks(parent.0).ok() != Some(parent.1)
            && native::ticks(child.0).ok() != Some(child.1),
        "different paid verifier, original failure or frozen candidate"
    );
    verify_observed_pair(&observed, parent, child)?;
    Ok(
        json!({"current_boot_failure":failed,"prior_started":started,"advancing":progress,"prior_manager":manager,
              "original_candidate":original_identity,"source_checkpoint_exists":false,"resource_credit_bytes":0}),
    )
}

#[cfg(incident_fixture145_only)]
fn original_fixture_census(trace: &str, provider: &str) -> bool {
    trace.starts_with(&format!(
        "Traceback (most recent call last):\n  File \"{provider}\", line "
    )) && trace.contains(&format!("  File \"{provider}\", line 543, in census\n"))
        && trace
            .trim_end()
            .ends_with("ValueError: unregistered replay process 227497")
}

#[cfg(incident_fixture145_only)]
pub fn failed_qualification_census() -> Result<Value> {
    failed_observation(FailedObservation {
        iid: "a99ed8b51e8a482b805b8a36a11b2700",
        failure_hash: "da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43",
        start_hash: "6e06652ea695717b18fc29b955e463da8dc2dde16f8173da552df707c478e624",
        progress_name: "V5E_ACTUAL_ADVANCING_WORKER.json",
        progress_sha: "073711680a623bf30c08f3305c08dd711481b31335f6b6d40de49ec8b378b0e2",
        manager_sha: "2397790bdcf978bfda5fe9a2dfe3eb1d2954448d86152231c8433c65e7d424d0",
        prior_image: "148804337a0c47093f67ae642fe01dc3a529cb07dbc809bfd9ab0ff9ca714a7c",
        provider: "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v16/post-stop-fit",
        recognize: original_fixture_census,
        parent: (94449, 365122971),
        child: (94696, 365125891),
    })
}

#[cfg(incident_homefloor145_only)]
fn retry1_census(trace: &str, provider: &str) -> bool {
    trace.starts_with(&format!(
        "Traceback (most recent call last):\n  File \"{provider}\", line "
    )) && trace.contains(&format!("  File \"{provider}\", line 558, in census\n"))
        && trace
            .trim_end()
            .ends_with("ValueError: unregistered replay process 429808")
}

#[cfg(incident_homefloor145_only)]
pub fn failed_retry1() -> Result<Value> {
    failed_observation(FailedObservation {
        iid: "afcf6cdd1ec0400ea2757f81472987b3",
        failure_hash: "5e001f59750a67f2cdce6aa43fb11b7d55e648a40d52e3fbee26ed3ead66a366",
        start_hash: "82532ce3f39356a26d78b2eb07ef32d6a90d604f7537d024ba5e696c42573ceb",
        progress_name: "V5F_RETRY1_ACTUAL_ADVANCING_WORKER.json",
        progress_sha: "1b16ce2d061e2ec97ab8c1ba81cd2dbcff9d0a759f317fbaf53b64e731a19501",
        manager_sha: "46b2a40efce3c995060ec8a2f426ff9cc72057f1c9032f5f80d7d24688d84932",
        prior_image: "016f1beab41795dae2bbaa1cef5173773eeafae617a5f5db92ebd4aaa1887c21",
        provider: "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v20/post-stop-fit",
        recognize: retry1_census,
        parent: (367458, 367957081),
        child: (367741, 367960010),
    })
}

#[cfg(all(test, incident_homefloor145_only))]
#[test]
#[ignore = "requires original immutable recovery evidence and journal"]
fn accepts_only_the_actual_stopped_retry1_and_retained_candidate() {
    let observed = failed_retry1().unwrap();
    assert_eq!(observed["original_candidate"]["inode"], 103237059);
    assert_eq!(observed["original_candidate"]["bytes"], 105610995833u64);
    assert_eq!(observed["source_checkpoint_exists"], false);
    let failed: Bound =
        serde_json::from_value(observed["current_boot_failure"]["failure"].clone()).unwrap();
    let body = custody::evidence(&failed).unwrap();
    let trace = body["error"]
        .as_str()
        .unwrap()
        .split_once("exit status: 1: ")
        .unwrap()
        .1;
    let provider = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v20/post-stop-fit";
    assert!(retry1_census(trace, provider));
    for (from, to) in [
        ("429808", "227497"),
        ("tools-v20", "tools-v16"),
        ("in census", "in refresh"),
    ] {
        assert!(!retry1_census(&trace.replace(from, to), provider));
    }
}

#[cfg(all(test, incident_fixture145_only))]
#[test]
#[ignore = "requires the original 145 terminal journal and frozen candidate"]
fn authenticates_the_failed_fixture_census_and_frozen_inode() {
    let evidence = failed_qualification_census().unwrap();
    assert_eq!(evidence["original_candidate"]["inode"], 103237059);
    let failure = custody::evidence(
        &serde_json::from_value(evidence["current_boot_failure"]["failure"].clone()).unwrap(),
    )
    .unwrap();
    let trace = failure["error"]
        .as_str()
        .unwrap()
        .strip_prefix("complete 145 capacity observation failed exit status: 1: ")
        .unwrap();
    let provider = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v16/post-stop-fit";
    assert!(original_fixture_census(trace, provider));
    assert!(!original_fixture_census(
        &trace.replace("227497", "227498"),
        provider
    ));
    assert!(!original_fixture_census(
        &trace.replace("in census", "in other"),
        provider
    ));
    assert!(!original_fixture_census(trace, "/another/provider"));
}

#[cfg(all(test, incident_timer145_only))]
#[test]
#[ignore = "requires the retained e655 failure and original paid inode"]
fn proves_retirement_timeout_and_rejects_other_commands() {
    let prior = failed_timer_inspection().unwrap();
    let binding = serde_json::from_value(prior["current_boot_failure"]["failure"].clone()).unwrap();
    let failure = custody::evidence(&binding).unwrap();
    let trace = failure["error"]
        .as_str()
        .unwrap()
        .strip_prefix("complete 145 capacity observation failed exit status: 1: ")
        .unwrap();
    let provider = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v14/post-stop-fit";
    assert!(crate::incident_fit::timer_inspection_timeout(
        trace, provider
    ));
    for (from, to) in [
        ("'inspect'", "'retire'"),
        ("20 seconds", "2 seconds"),
        ("in proof_stops", "in another_probe"),
        ("retire-original-timers.py", "foreign.py"),
    ] {
        assert!(!crate::incident_fit::timer_inspection_timeout(
            &trace.replace(from, to),
            provider
        ));
    }
    assert_eq!(prior["original_candidate"]["inode"], 103237059);
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
