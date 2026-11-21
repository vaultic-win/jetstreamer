//! Original-boot custody of the failed pre-incident epoch 145 semantic pass.
use super::*;

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the original root-owned stopped verifier and frozen inode"]
    fn failed_145_pass_keeps_the_original_leased_objects_and_requires_restart() {
        let r = predecessor().unwrap();
        assert_eq!(r["current_boot_failure"]["failure"]["sha256"], FAIL);
        assert_eq!(r["original_candidate"]["inode"], 103237059);
        assert_eq!(r["source_checkpoint_exists"], false);
        assert!(
            verify_cgroup().is_err(),
            "a build service cannot act as the production verifier"
        );
    }
}
