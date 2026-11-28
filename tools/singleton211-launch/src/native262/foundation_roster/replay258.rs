//! Price the prepared epoch 258 singleton and recognize its guarded successor.
use super::*;

pub(super) const EPOCH: u64 = 258;
pub(super) const CPUS: &str = "48-55";
pub(super) const UNIT: &str = "horizon-qualify-258-singleton-v1.service";
pub(super) const GUARD: &str = "horizon-258-singleton-protective-v1";
pub(super) const ROSTER_SCHEMA: &str = "foundation-epoch258-full-replay-roster-binding-v1";
pub(super) const REGISTRATION: ReplayRegistration = ReplayRegistration {
    epoch: EPOCH,
    unit: UNIT,
    receipt: (
        "/var/lib/jetstreamer/horizon258-full-replay-runtime-v1/cadence-registration.json",
        "",
    ),
    schema: "foundation-epoch258-replay-cadence-registration-v1",
    node_key: "node",
    receipt_disk: DISK_RECEIPTS,
};
const HANDOFF: (&str, &str) = (
    "/var/lib/jetstreamer/horizon258-full-source-static-preparation-v1/integration.json",
    "4eeb953b99cd89fc5ea4ff26a3b60c2dbbbe109310398cbf41bcdcc15383ce67",
);
const PROFILE: &str = "/var/lib/jetstreamer/horizon258-full-replay-runtime-v1/profile.json";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-258-singleton-v1";
const CAP: u64 = 514_359_320_727;
const MEMORY: u64 = 160 << 30;
const BOOTSTRAP_SLOT: u64 = 111_455_044;
const CHECKPOINT_SLOT: u64 = 111_887_310;
const CHECKPOINT_GENERATION: &str = "1640052103311598";

fn handoff() -> Bound {
    Bound::new(HANDOFF.0, HANDOFF.1)
}

fn rebound_profile(mut profile: Value) -> Result<Value> {
    ensure!(
        profile["schema"] == "foundation-epoch258-full-static-producer-profile-v1"
            && profile["epoch"] == EPOCH
            && profile["unit"] == UNIT
            && profile["worker_root"] == ROOT
            && profile["guard_unit"] == format!("{GUARD}.service")
            && profile["allowed_cpus"] == "56-63"
            && profile["properties"]["AllowedCPUs"] == "56-63"
            && profile["properties"]["CPUAffinity"] == "56-63"
            && profile["admission"] == false
            && profile["replay_launched"] == false
            && profile["publication_authorized"] == false,
        "epoch 258 static producer profile differs"
    );
    profile["allowed_cpus"] = json!(CPUS);
    profile["properties"]["AllowedCPUs"] = json!(CPUS);
    profile["properties"]["CPUAffinity"] = json!(CPUS);
    Ok(profile)
}

pub(super) fn quote() -> Result<FullReplayQuote> {
    let reference = handoff();
    let prepared = reference.sealed()?;
    let inputs = binding(&prepared["source_recheck"])?;
    let source = inputs.sealed()?;
    let profile_ref = binding(&prepared["profile"])?;
    let profile = rebound_profile(profile_ref.sealed()?)?;
    let namespace = binding(&prepared["namespace"])?.sealed()?;
    let guard = binding(&prepared["guard_validation"])?.sealed()?;
    let guard_plan = binding(&prepared["guard_plan"])?;
    let guard_template = guard_plan.sealed()?;
    let terminal = binding(&source["native_restore"])?.sealed()?;
    let checkpoint = binding(&source["inputs"]["terminal_checkpoint"])?.sealed()?;
    let sizing = &prepared["candidate_resources"];
    ensure!(
        prepared["schema"] == "foundation-epoch258-singleton-static-handoff-v1"
            && prepared["epoch"] == EPOCH
            && prepared["admission_issued"] == false
            && prepared["replay_launched"] == false
            && prepared["campaign_accounting_changed"] == false
            && sizing["cpus_reserved"] == false
            && sizing["disk_tree_cap_bytes"] == CAP
            && sizing["guard_receipt_reserve_bytes"] == DISK_RECEIPTS
            && sizing["producer_memory_max_bytes"] == MEMORY
            && sizing["guard_memory_max_bytes"] == (1u64 << 30)
            && sizing["prestart_coordinator_memory_bytes"] == CONTROLLER_MEMORY
            && source["schema"] == "foundation-epoch258-full-replay-static-input-recheck-v1"
            && source["epoch"] == EPOCH
            && source["canonical_accounts_checkpoint_slot"] == CHECKPOINT_SLOT
            && source["admission_issued"] == false
            && source["publication_authorized"] == false
            && terminal["schema"] == "foundation-epoch258-native-restore-terminal-v1"
            && terminal["epoch"] == EPOCH
            && terminal["unit"] == RESTORE_258.unit
            && terminal["checkpoint_slot"] == BOOTSTRAP_SLOT
            && terminal["native_restore_qualified"] == true
            && terminal["guard_drained"] == true
            && terminal["replay_entries_sent"] == 0
            && checkpoint["generation"] == CHECKPOINT_GENERATION
            && profile["inputs"] == json!(inputs)
            && profile["maximum_root_physical_bytes"] == CAP
            && profile["maximum_memory_bytes"] == MEMORY
            && profile["static_guard_plan"] == json!(guard_plan)
            && namespace["profile"] == json!(profile_ref)
            && namespace["private_state_writable"] == true
            && namespace["host_guard_sees_empty_placeholders"] == true
            && namespace["worker_started"] == false
            && guard["validated"] == true
            && guard["producer_signaled"] == false
            && guard["plan_sha256"] == guard_plan.sha256
            && guard_template["unit"] == UNIT
            && guard_template["worker_root"] == ROOT
            && guard_template["maximum_root_physical_bytes"] == CAP,
        "epoch 258 source, sizing, or static guard evidence differs"
    );
    for artifact in ["node", "worker", "genesis"] {
        binding(&source["inputs"][artifact])?.artifact()?;
    }
    for prepared_input in ["manifest", "slot_ranges_override"] {
        binding(&source["inputs"][prepared_input])?.sealed()?;
    }
    for epoch in ["257", "258"] {
        binding(&source["repaired_slot_ranges"][epoch])?.artifact()?;
    }

    let bootstrap = &source["bootstrap"];
    let path = Path::new(text(bootstrap, "path")?);
    let (device, inode, length, uid, mode, _, mtime, mtime_ns, ctime, ctime_ns) = identity(path)?;
    let expected = &bootstrap["identity"];
    ensure!(
        uid == 1000
            && mode & 0o022 == 0
            && expected["device"] == device
            && expected["inode"] == inode
            && expected["length"] == length
            && expected["mtime_ns"]
                == mtime
                    .checked_mul(1_000_000_000)
                    .and_then(|s| s.checked_add(mtime_ns))
                    .context("bootstrap mtime overflow")?
            && expected["ctime_ns"]
                == ctime
                    .checked_mul(1_000_000_000)
                    .and_then(|s| s.checked_add(ctime_ns))
                    .context("bootstrap ctime overflow")?,
        "epoch 258 bootstrap identity differs from the native restore"
    );
    let restore = binding(&terminal["native_result"])?.sealed()?;
    ensure!(
        restore["snapshot_sha256"] == bootstrap["sha256"]
            && restore["worker_sha256"] == source["inputs"]["worker"]["sha256"]
            && restore["matched_pinned_accounts_root"] == true,
        "epoch 258 bootstrap differs from the verified native restore"
    );
    Ok(FullReplayQuote {
        epoch: EPOCH,
        reference,
        inputs,
        working_disk: CAP,
        producer_memory: MEMORY,
    })
}

pub(super) fn check_live_binding(
    registration: &Value,
    profile: &Value,
    admission: &Value,
    fit: &Value,
    input_ref: &Bound,
) -> Result<()> {
    let reference = handoff();
    let prepared = reference.sealed()?;
    let inputs = binding(&prepared["source_recheck"])?;
    let source = inputs.sealed()?;
    let expected = rebound_profile(binding(&prepared["profile"])?.sealed()?)?;
    let quoted_cpus: BTreeSet<u64> = text(&fit["capacity"], "cpus")?
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        *input_ref == inputs
            && fit["schema"] == ROSTER_SCHEMA
            && fit["epoch"] == EPOCH
            && fit["full_replay_quote"]["inputs"] == json!(inputs)
            && fit["full_replay_quote"]["sizing_reference"] == json!(reference)
            && fit["full_replay_quote"]["whole_tree_bytes"] == CAP
            && quoted_cpus == units::parse_cpu_list(CPUS)?
            && *profile == expected
            && admission["profile"] == registration["profile"]
            && binding(&registration["profile"])?.path == Path::new(PROFILE)
            && registration["worker"] == source["inputs"]["worker"],
        "epoch 258 registered replay differs from its disjoint full-roster admission"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebound_profile_changes_only_cpu_fields() {
        let original = json!({"schema":"foundation-epoch258-full-static-producer-profile-v1",
            "epoch":EPOCH,"unit":UNIT,"worker_root":ROOT,"guard_unit":format!("{GUARD}.service"),
            "allowed_cpus":"56-63","properties":{"AllowedCPUs":"56-63","CPUAffinity":"56-63","Restart":"no"},
            "admission":false,"replay_launched":false,"publication_authorized":false,"argv":["node","258"]});
        let mut rebound = rebound_profile(original.clone()).unwrap();
        assert_eq!(rebound["allowed_cpus"], CPUS);
        assert_eq!(rebound["properties"]["AllowedCPUs"], CPUS);
        assert_eq!(rebound["properties"]["CPUAffinity"], CPUS);
        rebound["allowed_cpus"] = json!("56-63");
        rebound["properties"] = original["properties"].clone();
        assert_eq!(rebound, original);
        let mut changed = original;
        changed["properties"]["CPUAffinity"] = json!("48-55");
        assert!(rebound_profile(changed).is_err());
    }

    #[test]
    #[ignore = "reads the exact root-owned static epoch 258 evidence without measuring the fleet"]
    fn quote_uses_prepared_host_inputs() {
        let quote = quote().unwrap();
        assert_eq!(quote.epoch, EPOCH);
        assert_eq!(quote.working_disk + DISK_RECEIPTS, 514_627_756_183);
        assert_eq!(
            quote.producer_memory + CONTROLLER_MEMORY + (1 << 30),
            173_140_869_120
        );
    }
}
