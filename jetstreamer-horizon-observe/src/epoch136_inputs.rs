//! Exact 136 immutable input capability. No replay or process-launch API.
use {
    crate::ram_artifact_retention::{Bound, bound_json, hash_file},
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    std::{
        env, fs,
        fs::{File, OpenOptions},
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    },
};

const PACKAGE: &str = "/usr/local/lib/jetstreamer/horizon-epoch136-capped-inputs-20261023-v1";
const UNIT: &str = "horizon-epoch136-capped-input-capability-20261023-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch136-capped-input-capability-20261023-v1";
const BOOTSTRAP: &str = "snapshot-58751483-84kyzaerEY1FbjzX898LB3cimVkrPXsiRByumLGvTy8C.tar.zst";
const TERMINAL: &str = "snapshot-59183944-HHd1o9dwpbyderGihEgb9inCBtMhqtoU855aFJPxnzk8.tar.zst";
const WORKER: &str = "fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759";
const NODE: &str = "d0c784a403d65819de70a499fc4d981217fd16fc30b70fac7e5ec979d0423ff0";
const SNAPSHOT: &str = "0d78ac8daa69790f984ccfaddb01b6a497eb05cc7222533b94b4353dd8abc767";
const DENIED: &[&str] = &[
    "worker_spawned",
    "bank_initialized",
    "snapshot_restored",
    "archive_created",
    "replay_launch_authorized",
    "canonical_prefix_qualified",
    "full_cold_epoch_peak_qualified",
    "complete_epoch_span_covered",
    "runtime_promotion_authorized",
    "publication_authorized",
    "local_retirement_authorized",
    "remote_mutations",
    "r2_mutations",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    run_root: PathBuf,
}

fn validate(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-epoch136-input-capability-plan-v2"
            && p.unit == UNIT
            && p.run_root == Path::new(ROOT),
        "foreign 136 capability scope"
    );
    Ok(())
}

fn immutable(path: &Path, digest: &str, maximum: u64) -> Result<u64> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical immutable path"
    );
    let (actual, m) = hash_file(path, maximum)?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o222 == 0 && actual == digest,
        "mutable or mismatching 136 input: {}",
        path.display()
    );
    Ok(m.len())
}

fn manifest(v: &Value) -> Result<()> {
    let epochs = v["manifest"]["epochs"]
        .as_array()
        .context("manifest epoch census")?;
    let rows: Vec<_> = epochs.iter().filter(|r| r["epoch"] == 136).collect();
    ensure!(rows.len() == 1, "epoch 136 missing or duplicated");
    let r = rows[0];
    ensure!(
        r["runtime"] == "solana-v1.4.25"
            && r["bootstrap"]["slot"] == 58751483
            && r["bootstrap"]["size"] == 1930905776u64
            && r["bootstrap"]["generation"] == 1634786431177741u64
            && r["bootstrap"]["accounts_hash"] == "84kyzaerEY1FbjzX898LB3cimVkrPXsiRByumLGvTy8C"
            && r["post_bootstrap_root_checkpoints"]
                .as_array()
                .is_some_and(|r| r.len() == 1)
            && r["post_bootstrap_root_checkpoints"][0]["slot"] == 59183944
            && r["post_bootstrap_root_checkpoints"][0]["accounts_hash"]
                == "HHd1o9dwpbyderGihEgb9inCBtMhqtoU855aFJPxnzk8"
            && r["post_bootstrap_root_checkpoints"][0]["generation"] == 1634786476182569u64,
        "epoch 136 canonical input lineage differs"
    );
    Ok(())
}

fn receipt(invocation: &str, bindings: Value) -> Value {
    let mut result = json!({"schema":"jetstreamer-private-epoch136-capped-input-capability-v2",
        "epoch":136,"unit":UNIT,"invocation_id":invocation,"bindings":bindings,
        "node_sha256":NODE,"worker_sha256":WORKER,"snapshot_sha256":SNAPSHOT,
        "worker_feature":"capped-shrink-candidate","snapshot_bytes":1930905776u64,
        "bootstrap_slot":58751483,"terminal_root_slot":59183944,
        "output_slot_start":58752000,"output_slot_count":431945,"excluded_epoch_suffix_slots":55,
        "all_immutable_inputs_rehashed":true,"checkpoint_names_verified":true,
        "fresh_admission_required":true,"invocation_bound_guard_required":true,
        "first_real_guard_fire_required":true,"native_restore_and_replay_qualification_required":true,
        "new_resource_samples":0});
    for key in DENIED {
        result[*key] = json!(false);
    }
    result
}

fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path && m.is_dir() && m.uid() == 1001 && m.mode() & 0o777 == 0o700,
        "unsafe 136 private capability directory"
    );
    Ok(())
}

fn write_receipt(path: &Path, value: &Value) -> Result<()> {
    private(path.parent().context("receipt parent")?)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(&bytes)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

pub fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1001,
        "136 capability requires isolated sol identity"
    );
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && args[6] == "--storage-capability",
        "only --storage-capability is enabled"
    );
    immutable(&fs::read_link("/proc/self/exe")?, &args[5], 256 << 20)?;
    let plan_binding = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_value(bound_json(&plan_binding)?)?;
    validate(&p)?;
    let invocation = env::var("INVOCATION_ID")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid capability invocation"
    );
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{UNIT}"),
        "foreign capability cgroup"
    );
    private(&p.run_root)?;
    private(&p.run_root.join("receipts"))?;
    ensure!(
        fs::read_dir(p.run_root.join("receipts"))?.next().is_none(),
        "capability receipt path occupied"
    );
    let package = Path::new(PACKAGE);
    let metadata = fs::symlink_metadata(package)?;
    ensure!(
        package.canonicalize()? == package
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0,
        "136 input package not immutable"
    );
    for (name, sha, maximum) in [
        ("jetstreamer-node", NODE, 512 << 20),
        ("jetstreamer-historical-worker-v1-4-25", WORKER, 256 << 20),
        (
            "genesis.tar.bz2",
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            10 << 20,
        ),
        (BOOTSTRAP, SNAPSHOT, 11 << 30),
        (
            "epoch-hashes-136.txt",
            "5b98d81e9fc843f0a8150df5e4e948fc3dfe9c33c212eefbc797060bfa1b438c",
            1 << 20,
        ),
        (
            "source-manifest.json",
            "ec62e2ce730a28033e5626e7afdb59c2b6e73a2ce188ae1040a77a7a09e396c3",
            1 << 20,
        ),
        (
            "original-failure.json",
            "4629a2bb6806a45c21ab541d19cf6d3368cff47e6965c10304bdfb6c06c5be03",
            1 << 20,
        ),
        (
            "review.json",
            "2c7c5a0f6e670aa78287cd1117b3c49e9ac6e959e46944340906573f63b42739",
            1 << 20,
        ),
    ] {
        let length = immutable(&package.join(name), sha, maximum)?;
        if name == BOOTSTRAP {
            ensure!(length == 1930905776, "136 bootstrap size differs");
        }
    }
    let raw = fs::read(package.join("source-manifest.json"))?;
    manifest(&serde_json::from_slice(&raw)?)?;
    ensure!(
        fs::read_to_string(package.join("epoch-hashes-136.txt"))?
            == format!("{BOOTSTRAP}\n{TERMINAL}\n"),
        "136 checkpoint names differ"
    );
    let value = receipt(
        &invocation,
        json!({"plan_path":plan_binding.path,"plan_sha256":plan_binding.sha256,
        "self_sha256":args[5],"package":PACKAGE}),
    );
    write_receipt(&p.run_root.join("receipts/capability.json"), &value)?;
    println!("epoch136 exact immutable inputs verified; no worker spawn, restore or replay");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_cannot_borrow_another_host_epoch_or_replay_mode() {
        let mut p = Plan {
            schema: "jetstreamer-private-epoch136-input-capability-plan-v2".into(),
            unit: UNIT.into(),
            run_root: ROOT.into(),
        };
        validate(&p).unwrap();
        p.unit = "horizon-qualify-186-capped-root-prefix-inputs-20261023-v1.service".into();
        assert!(validate(&p).is_err());
        p.unit = UNIT.into();
        p.run_root = "/home/ubuntu/.jetstreamer-private/epoch136-inputs".into();
        assert!(validate(&p).is_err());
        assert!(
            serde_json::from_value::<Plan>(
                json!({"schema":p.schema,"unit":UNIT,"run_root":ROOT,"execute":true})
            )
            .is_err()
        );
    }
    #[test]
    fn input_receipt_never_claims_execution_or_canonical_completion() {
        let r = receipt(&"a".repeat(32), json!({}));
        assert_eq!(r["output_slot_count"], 431945);
        assert_eq!(r["excluded_epoch_suffix_slots"], 55);
        assert_eq!(r["snapshot_bytes"], 1930905776u64);
        for key in DENIED {
            assert_eq!(r[*key], false, "{key}");
        }
    }
    #[test]
    fn lineage_rejects_wrong_root_or_duplicate_epoch() {
        let row = json!({"epoch":136,"runtime":"solana-v1.4.25",
            "bootstrap":{"slot":58751483,"size":1930905776u64,"generation":1634786431177741u64,"accounts_hash":"84kyzaerEY1FbjzX898LB3cimVkrPXsiRByumLGvTy8C"},
            "post_bootstrap_root_checkpoints":[{"slot":59183944,"generation":1634786476182569u64,"accounts_hash":"HHd1o9dwpbyderGihEgb9inCBtMhqtoU855aFJPxnzk8"}]});
        let v = json!({"manifest":{"epochs":[row]}});
        manifest(&v).unwrap();
        for pointer in [
            "/manifest/epochs/0/bootstrap/generation",
            "/manifest/epochs/0/post_bootstrap_root_checkpoints/0/slot",
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(1);
            assert!(manifest(&bad).is_err());
        }
        let bad = json!({"manifest":{"epochs":[row,row]}});
        assert!(manifest(&bad).is_err());
    }
}
