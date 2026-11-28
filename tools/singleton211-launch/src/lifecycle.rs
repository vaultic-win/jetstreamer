//! Immutable full211 startup graph. Validity never implies full archive qualification.
use super::*;

pub(super) fn replay_only(v: &Value) -> Result<()> {
    ensure!(
        v["replay_launch_authorized"] == true && v["entry_replay"] == false,
        "missing private launch authority or invented execution evidence"
    );
    for k in [
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[k] == false, "unexpected publication authority {k}");
    }
    Ok(())
}
pub(super) fn admission(a: &Value, p: &Value) -> Result<()> {
    let qualification = qualification::operation(p)?;
    if qualification {
        no_authority(a)?;
    } else {
        replay_only(a)?;
    }
    ensure!(
        a["schema"] == "horizon-singleton211-current-fleet-admission-v1"
            && a["epoch"] == 211
            && a["mode"]
                == if qualification {
                    "protective-stop-qualification"
                } else {
                    "full-replay"
                }
            && a["operation"] == p["operation"]
            && a["held_gate_launch_authorized"] == true
            && a["unit"] == UNIT
            && a["private_run_root"] == ROOT
            && a["maximum_memory_bytes"] == MEMORY
            && a["candidate_incremental_peak_bytes"] == SCRATCH
            && a["admitted"] == true
            && a["protected_existing_floor_bytes"] == p["minimum_free_bytes"]
            && a["gate"] == p["gate"]
            && a["node"] == p["node"]
            && a["worker"] == p["worker"]
            && a["input_capability"] == p["input_capability"]
            && a["native_input"] == p["native_input"]
            && a["boot_id"] == p["boot_id"]
            && a["guard"] == p["guard"]
            && num(a, "recorded_unix_seconds")? < num(a, "expires_unix_seconds")?
            && num(a, "expires_unix_seconds")? - num(a, "recorded_unix_seconds")? <= 60,
        "full replay admission differs"
    );
    let review = binding(&a["review"])?.sealed()?;
    prepare::historical(&review, p, a)?;
    for k in [
        "review",
        "source_publication",
        "observer",
        "fleet",
        "reservation_ledger",
    ] {
        binding(&a[k])?;
    }
    Ok(())
}
pub(super) fn validate_handoff(v: &Value) -> Result<()> {
    replay_only(v)?;
    ensure!(
        v["schema"] == "horizon-singleton211-guarded-startup-v1"
            && v["epoch"] == 211
            && v["unit"] == UNIT
            && v["launched"] == true
            && v["private_run_root"] == ROOT
            && v["node"] == json!(Bound::new(NODE, NODE_SHA))
            && v["worker"] == json!(Bound::new(WORKER, WORKER_SHA))
            && v["native_input"] == json!(Bound::new(NATIVE_PROOF, NATIVE_PROOF_SHA))
            && v["output_slot_start"] == 91152000u64
            && v["terminal_slot"] == 91583999u64
            && v["canonical_root_slot"] == 91583512u64
            && v["post_root_slot_count"] == 487
            && v["output_slot_count"] == 432000
            && v["same_pid_exec_observed"] == true
            && v["entry_replay_observed"] == false,
        "full211 handoff scope differs"
    );
    let iid = text(v, "invocation_id")?;
    let pid = num(v, "main_pid")?;
    ensure!(hex(iid, 32) && pid > 1, "handoff identity");
    let pr = binding(&v["startup_plan"])?;
    let p = pr.sealed()?;
    ensure!(
        !qualification::operation(&p)?,
        "qualification cannot be a replay handoff"
    );
    gate::plan(
        &p,
        text(&p["gate"], "sha256")?,
        text(&p, "boot_id")?,
        num(v, "recorded_monotonic_us")?,
    )?;
    let ar = binding(&v["admission"])?;
    ensure!(
        p["admission"] == v["admission"],
        "handoff admission changed"
    );
    let a = ar.sealed()?;
    admission(&a, &p)?;
    ensure!(
        v["input_capability"] == p["input_capability"] && v["native_input_qualified"] == true,
        "handoff input qualification changed"
    );
    inputs::validate_scope(&binding(&p["input_capability"])?.sealed()?)?;
    Bound::new(NATIVE_PROOF, NATIVE_PROOF_SHA).sealed()?;
    let review = binding(&a["review"])?.sealed()?;
    let gate = binding(&p["gate"])?;
    gate.artifact()?;
    ensure!(
        gate.path == Path::new(GATE)
            && v["launcher_sha256"] == gate.sha256
            && review["source_publication"] == a["source_publication"]
            && review["guard"] == a["guard"]
            && review["input_capability"] == a["input_capability"],
        "review or launcher changed"
    );
    let qualification = binding(&review["prestart_qualification"])?.sealed()?;
    super::admission::prestart(&qualification, &review, &gate.sha256)?;
    binding(&qualification["qualification_evidence"])?.json()?;
    let source = binding(&a["source_publication"])?.sealed()?;
    ensure!(
        source["schema"] == "horizon-singleton211-source-publication-v1"
            && source["remote_ref"] == "refs/heads/account-updates"
            && source["all_required_dependencies_in_remote"] == true
            && source["exact_deployed_source_provenance_reviewed"] == true
            && source["no_untracked_required_source"] == true,
        "publication provenance missing"
    );
    let artifacts = source["artifacts"].as_array().context("source artifacts")?;
    let mut roles = BTreeSet::new();
    for item in artifacts {
        let role = text(item, "role")?;
        ensure!(roles.insert(role), "duplicate source role");
        let b = binding(&item["artifact"])?;
        b.artifact()?;
        let provenance = binding(&item["provenance"])?.sealed()?;
        ensure!(
            provenance["schema"] == "horizon-singleton211-exact-artifact-provenance-v1"
                && provenance["artifact"] == item["artifact"]
                && provenance["source_commit"] == item["source_commit"]
                && provenance["all_source_dependencies_enumerated"] == true
                && provenance["source_files"]
                    .as_array()
                    .is_some_and(|s| !s.is_empty()),
            "artifact source provenance differs"
        );
        match role {
            "node" => ensure!(b == Bound::new(NODE, NODE_SHA), "node source role"),
            "worker" => ensure!(b == Bound::new(WORKER, WORKER_SHA), "worker source role"),
            "launcher" => ensure!(b == gate, "launcher source role"),
            "guard" => ensure!(item["artifact"] == p["guard"], "guard source role"),
            "sealer" => ensure!(b == Bound::new(SEALER, SEALER_SHA), "sealer source role"),
            "observer" | "fleet" | "inactive-status" => (),
            _ => bail!("unknown source role"),
        }
    }
    ensure!(
        roles
            == BTreeSet::from([
                "node",
                "worker",
                "launcher",
                "guard",
                "sealer",
                "observer",
                "fleet",
                "inactive-status"
            ]),
        "missing lifecycle source role"
    );
    let tr = binding(&v["first_guard_token"])?;
    ensure!(
        tr.path == Path::new(TOKENS).join(iid).join("guard-admission.json"),
        "token namespace differs"
    );
    let t = tr.sealed()?;
    for (h, k) in [
        ("guard_plan", "guard_plan"),
        ("first_guard_sample", "guard_sample"),
        ("first_guard_pid1_journal", "guard_pid1_journal"),
    ] {
        ensure!(v[h] == t[k], "handoff first-fire member changed");
    }
    let wall = num(v, "recorded_unix_seconds")?;
    ensure!(
        wall >= num(&a, "recorded_unix_seconds")? && wall <= num(&a, "expires_unix_seconds")?,
        "handoff outside original admission"
    );
    gate::token(
        &p,
        &pr,
        &t,
        iid,
        pid,
        num(v, "recorded_monotonic_us")?,
        wall,
    )?;
    let affinity = super::launch::cpus(&review)?;
    let expected = launch::producer_template(&pr.path, &affinity, &gate.sha256);
    let unit = binding(&v["unit_file"])?;
    ensure!(
        unit.sha256 == digest(expected.as_bytes()) && unit.bytes(true)? == expected.as_bytes(),
        "unit template changed"
    );
    let producer = &v["producer"];
    ensure!(
        producer["Id"] == UNIT
            && producer["InvocationID"] == iid
            && producer["MainPID"] == pid.to_string().as_str()
            && producer["ActiveState"] == "active"
            && producer["SubState"] == "running"
            && producer["NRestarts"] == "0"
            && producer["MemoryMax"] == MEMORY.to_string().as_str()
            && producer["MemorySwapMax"] == "0"
            && producer["Restart"] == "no"
            && producer["KillMode"] == "control-group"
            && producer["Delegate"] == "no",
        "captured producer identity changed"
    );
    launch::producer_properties(producer, &pr, &affinity, &gate.sha256)?;
    prepare::verify_pair(&binding(&v["guard_plan"])?, prepare::GUARD_ARG)?;
    let guard = binding(&p["guard"])?;
    ensure!(
        guard.path == Path::new(GUARD) && v["guard_sha256"] == guard.sha256,
        "guard hash substitution"
    );
    let retain = &v["retention"];
    ensure!(
        retain["Id"] == RETENTION
            && retain["LoadState"] == "loaded"
            && retain["ActiveState"] == "active"
            && retain["SubState"] == "active"
            && launch::retains_all(retain)?
            && retain["DefaultDependencies"] == "no"
            && retain["IgnoreOnIsolate"] == "yes"
            && retain["Job"] == ""
            && retain["DropInPaths"] == "",
        "retention owner changed"
    );
    for k in ["Wants", "Requires", "BindsTo", "Upholds"] {
        ensure!(retain[k] == "", "retention activates work");
    }
    Ok(())
}
pub(super) fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 5,
        "usage: launcher validate-handoff HANDOFF SHA256 SELF_SHA256"
    );
    ensure!(
        hex(&args[4], 64) && hash(Path::new("/proc/self/exe"))? == args[4],
        "validator image differs"
    );
    let b = Bound::new(&args[2], &args[3]);
    let v = b.sealed()?;
    ensure!(
        v["launcher_sha256"] == args[4],
        "handoff uses another qualified launcher"
    );
    validate_handoff(&v)?;
    println!(
        "{}",
        json!({"schema":"horizon-singleton211-handoff-validation-v1","handoff":b,"valid":true,
        "resource_samples_taken":0,"publication_authorized":false,"r2_mutations":false})
    );
    Ok(())
}
