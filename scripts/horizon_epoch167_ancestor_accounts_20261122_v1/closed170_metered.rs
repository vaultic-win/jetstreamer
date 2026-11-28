//! The stopped producer cold-restores a verified bootstrap and cannot resume
//! from these AppendVecs. Keep both the private archive and every checkpoint.
use super::retirement_evidence::*;
pub(super) use super::retirement_evidence::{leases, verify_campaign_lock, verify_image};
use super::*;

pub(super) const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-storage-witness-recovery-20261127-v1/closed-accounts";
pub(super) const PROFILE: &[u8] = include_bytes!("profiles170_metered.json");
pub(super) const CHECK_SCHEMA: &str = "horizon170-full-metered-stopped-accounts-check-v1";
pub(super) const COMPLETE_SCHEMA: &str = "horizon170-full-metered-stopped-accounts-complete-v1";
const UNIT: &str = "horizon-qualify-170-full-metered-20261124-v1.service";
const IID: &str = "34e13d0e054d48d88337d3673f241695";
const GROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-raised-guard-qualification-20261126-v1";
const BOOT_SHA: &str = "1fff1c4d4c76f56f7b5ba6ba17f379d7811cddb3e314043829ceb864205cab0a";
const WORKER_SHA: &str = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const FINGERPRINT: &str = "sha256:a18e763167b4cd47833f89627209ea7b5e08e55de16152df612e2c0d9be05890";

fn names(path: &Path) -> Result<Vec<String>> {
    let mut names = fs::read_dir(path)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 name"))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}

fn validate_terminal(
    terminal: &Value,
    worker: &Value,
    admission: &Value,
    stop: &Value,
    intent: &Value,
) -> Result<()> {
    let evt = &terminal["pid1_terminal_event"];
    let actor = &stop["terminal"];
    ensure!(
        terminal["schema"] == "horizon-epoch170-full-metered-guard-stop-v1"
            && terminal["epoch"] == 170
            && terminal["producer_unit"] == UNIT
            && terminal["producer_pid"] == 3667208
            && terminal["producer_start_ticks"] == 404163368
            && terminal["resource_credit_bytes"] == 0
            && terminal["reservation_ending_bytes"] == 0
            && terminal["private_output_preserved"] == true
            && terminal["archive_ready"] == false
            && terminal["all_twelve_witness_file_identities_preserved"] == true
            && evt["_PID"] == "1"
            && evt["UNIT"] == UNIT
            && evt["INVOCATION_ID"] == IID
            && evt["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448",
        "wrong stopped 170 incarnation or outcome"
    );
    ensure!(
        [terminal, worker, admission, stop, intent]
            .iter()
            .all(|r| r["producer_invocation_id"] == IID)
            && worker["admission"] == terminal["admission"]
            && worker["worker_pid"] == 3667695
            && worker["worker_start_ticks"] == 404169190
            && worker["worker_sha256"] == WORKER_SHA
            && worker["producer_unit"] == UNIT
            && worker["producer_pid"] == 3667208
            && admission["producer_unit"] == UNIT
            && admission["start_ticks"] == 404163368
            && intent["reason"] == "DATA-fulfillment-observation-failed"
            && intent["sample"]["trip_reason"] == intent["reason"]
            && intent["sample"]["producer"]["pid"] == 3667208
            && intent["plan_sha256"] == terminal["plan"]["sha256"]
            && stop["plan_sha256"] == intent["plan_sha256"]
            && actor["invocation_id"] == IID
            && actor["active"] == "inactive"
            && actor["sub"] == "dead"
            && actor["pid"] == 0
            && actor["cgroup"] == ""
            && actor["restarts"] == 0
            && actor["restart_policy"] == "no"
            && stop["scratch_deleted"] == false
            && stop["remote_mutations"] == false,
        "guard did not drain the original producer"
    );
    Ok(())
}

fn check_drained(name: &str) -> Result<()> {
    let u = unit(name)?;
    ensure!(
        matches!(
            (u["ActiveState"].as_str(), u["SubState"].as_str()),
            ("inactive", "dead") | ("failed", "failed")
        ) && ["MainPID", "ControlPID", "NRestarts"]
            .iter()
            .all(|k| u.get(*k).is_none_or(|s| s == "0")),
        "occupied producer or guard: {name}"
    );
    let cg = Path::new("/sys/fs/cgroup/system.slice")
        .join(name)
        .join("cgroup.procs");
    if cg.try_exists()? {
        ensure!(fs::read(cg)?.is_empty(), "occupied producer/guard cgroup");
    }
    Ok(())
}

pub(super) fn gates(p: &Value, manifest: &Value) -> Result<Value> {
    let scope = &manifest["scope"];
    let saved = &scope["preserved"];
    let evidence = &scope["evidence"];
    let terminal = bound(&evidence["terminal"])?;
    ensure!(
        path(&evidence["terminal"])? == Path::new(GROOT).join("TERMINAL_20261127.json"),
        "different terminal"
    );
    let worker = bound(&terminal["first_worker"])?;
    let admission = bound(&terminal["admission"])?;
    let stop = bound(&terminal["stop_completion"])?;
    let intent = bound(&terminal["stop_intent"])?;
    validate_terminal(&terminal, &worker, &admission, &stop, &intent)?;
    closed(UNIT)?;
    for name in [
        "horizon-guard-170-full-metered-20261124-v1.timer",
        "horizon-guard-170-full-metered-20261124-v1.service",
        "horizon-guard-170-full-metered-raised-20261126-v1.timer",
        "horizon-guard-170-full-metered-raised-20261126-v1.service",
    ] {
        check_drained(name)?;
    }
    let scratch = Path::new(string(&worker["observer_row"], "scratch_path")?);
    let root = scratch.parent().context("missing run root")?;
    let runtime=scratch.join(".historical-runtime/jetstreamer-historical-parent-8JIkug/jetstreamer-historical-v1.5.6-KYpAzO");
    let target = Path::new(string(p, "target")?);
    ensure!(
        target == runtime.join("accounts-state")
            && target.canonicalize()? == target
            && target.symlink_metadata()?.ino() == 114563410
            && p["inode"] == 114563410
            && p["iid"] == IID
            && scope["original_scratch"] == worker["observer_row"]["scratch_path"]
            && scope["original_runtime"].as_str() == runtime.to_str()
            && path(&saved["prefix_archive"])? == root.join("archives/epoch-170.jet")
            && path(&saved["cohort"])? == root.join("cohort-state.json")
            && path(&saved["log"])? == path(&terminal["producer_log"])?
            && saved["log"]["identity"][2] == terminal["producer_log"]["length"]
            && path(&saved["original_bank"])?
                == runtime.join("unpacked/snapshots/73439777/73439777")
            && names(&runtime)? == ["accounts-state", "genesis-unpacked", "unpacked"]
            && names(&runtime.join("unpacked/snapshots"))? == ["73439777", "status_cache"]
            && names(&runtime.join("unpacked/snapshots/73439777"))? == ["73439777"],
        "changed recovery tree or newer Bank exists"
    );
    for input in saved.as_object().context("preserved material")?.values() {
        ensure!(
            !path(input)?.starts_with(target),
            "protected input intersects retirement"
        );
        open_input(input)?;
    }
    let profile = bound(&evidence["payload"])?;
    let prep = bound(&admission["source"])?;
    ensure!(
        profile == prep["profile"]
            && profile["epoch"] == 170
            && profile["source"]["bootstrap"]["slot"] == 73439777
            && profile["source"]["bootstrap"]["sha256"] == BOOT_SHA
            && profile["source"]["bootstrap"]["source_path"] == saved["bootstrap"]["path"]
            && profile["source"]["worker"]["reference"]["sha256"] == WORKER_SHA
            && profile["source"]["node"]["reference"]["sha256"] == NODE_SHA
            && profile["source"]["manifest"]["sha256"] == saved["cohort_manifest"]["sha256"]
            && profile["source"]["canonical_root"]["slot"] == 73871796
            && profile["actor"]["unit"] == UNIT,
        "cold restored recipe no longer bound"
    );
    let args = profile["actor"]["producer_argv_after_protection"]
        .as_array()
        .context("missing original argv")?;
    for arg in [
        "--setenv=JETSTREAMER_CLEAR_ACCOUNTS_ON_START=true",
        "--setenv=JETSTREAMER_LOAD_FROM_DIR=0",
        "--root-checkpoint-cohort",
    ] {
        ensure!(
            args.iter().any(|v| v == arg),
            "missing original restore policy"
        );
    }
    let mut contents = Vec::new();
    open_input(&saved["cohort"])?
        .take(65537)
        .read_to_end(&mut contents)?;
    let cohort: Value = serde_json::from_slice(&contents)?;
    ensure!(
        sha(&contents) == string(&saved["cohort"], "sha256")?
            && cohort
                == json!({
        "schema":"jetstreamer-root-cohort-run-v1","status":"running-private","start_epoch":170,"end_epoch":170,
        "manifest_fingerprint":FINGERPRINT}),
        "committed or different cohort"
    );
    let mut visited = std::collections::BTreeSet::new();
    for dir in [
        "/run/systemd/transient",
        "/run/systemd/system",
        "/etc/systemd/system",
    ] {
        staged_references(Path::new(dir), &[target, &runtime], &[], &mut visited)?;
    }
    witness_disjoint(target, &evidence["witness"])?;
    Ok(
        json!({"original_invocation":IID,"scope":target,"terminal":evidence["terminal"],
        "preserved":saved,"witness":evidence["witness"],"cold_restart_bootstrap_slot":73439777}),
    )
}
pub(super) fn check_inventory(
    p: &Value,
    manifest: &Value,
    ledger: &stopped_tree::Ledger,
    allocated: u64,
) -> Result<()> {
    check_appendvecs(p, ledger, allocated, 384 << 30)?;
    ensure!(
        p["expected_bytes"] == allocated && p["expected_entries"] == (ledger.len() - 1) as u64,
        "unbound AppendVec census"
    );
    for row in manifest["scope"]["preserved"]
        .as_object()
        .context("missing inputs")?
        .values()
    {
        if let Some(expected) = row["sha256"].as_str() {
            ensure!(
                digest(row)? == expected,
                "file digest differs: {}",
                row["path"]
            );
        }
    }
    bound_bytes(&manifest["scope"]["evidence"]["terminal"], 1 << 20)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_drained_original_and_reject_changed_worker_or_release() {
        let mut f: Value =
            serde_json::from_slice(include_bytes!("fixtures/full170_stop.json")).unwrap();
        let check = |f: &Value| {
            validate_terminal(
                &f["terminal"],
                &f["worker"],
                &f["admission"],
                &f["stop"],
                &f["intent"],
            )
        };
        check(&f).unwrap();
        f["worker"]["worker_pid"] = json!(3667696);
        assert!(check(&f).is_err());
        f["worker"]["worker_pid"] = json!(3667695);
        f["stop"]["terminal"]["pid"] = json!(301);
        assert!(check(&f).is_err());
        f["stop"]["terminal"]["pid"] = json!(0);
        f["terminal"]["reservation_ending_bytes"] = json!(1);
        assert!(check(&f).is_err());
    }

    #[test]
    fn enrolled_sources_all_lie_outside_the_appendvec_tree() {
        let f: Value = serde_json::from_slice(PROFILE).unwrap();
        let target = Path::new(f["profiles"]["full-metered"]["target"].as_str().unwrap());
        assert_eq!(target.file_name().unwrap(), "accounts-state");
        assert_eq!(
            f["profiles"]["full-metered"]["expected_bytes"],
            47_283_544_064u64
        );
        for row in f["scope"]["preserved"].as_object().unwrap().values() {
            assert!(!path(row).unwrap().starts_with(target));
        }
    }
}
