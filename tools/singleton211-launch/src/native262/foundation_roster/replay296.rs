//! Bind the corrected full epoch 296 retry to its qualified checkpoint and guard.
use super::*;

pub(super) const UNIT: &str = "horizon-qualify-296-full-retry-v2.service";
pub(super) const CPUS: &str = "32-39";
const ORIGINAL_CPUS: &str = "56-63";
const EFFECTIVE_NAMESPACE: &str =
    "/var/lib/jetstreamer/horizon296-full-retry-v2/effective-namespace-32-39.json";
const ORIGINAL_NAMESPACE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon296-full-retry-v2/namespace.json",
    "7f6d0f4bc92b1ed901085e7b16d3c24b5eecd48cd7a34e6aaa17eb423a3f4df7",
);
const PLACEMENT: (&str, &str) = (
    "/var/lib/jetstreamer/horizon296-disjoint-placement-proposal-v376/placement.json",
    "eee23d784cd32f1292c6fc8dd605cd9d2d3d298b6382e52c0c1714a504118014",
);
pub(super) const GUARD: &str = "horizon-296-full-retry-protective-v2";
pub(super) const GUARD_SERVICE: &str = "horizon-296-full-retry-protective-v2.service";
pub(super) const REGISTRATION: ReplayRegistration = ReplayRegistration {
    epoch: 296,
    unit: UNIT,
    receipt: (
        "/var/lib/jetstreamer/horizon296-full-retry-v2/cadence-registration.json",
        "",
    ),
    schema: "foundation-epoch296-full-retry-cadence-registration-v2",
    node_key: "node",
    receipt_disk: 64 << 20,
};
const PROFILE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon296-full-retry-preparation-v2/profile.json",
    "c9287ddad9c6bba36fda7bedb7c76cf42ca57576b76c3b6a648ce1b7f473d0f0",
);

pub(super) struct Placement {
    pub reference: Bound,
    pub exclusive_cpus: BTreeSet<u64>,
}

fn validate_placement(proposal: &Value, profile: &Value) -> Result<BTreeSet<u64>> {
    let original = Bound::new(PROFILE.0, PROFILE.1);
    let exclusive = units::parse_cpu_list("32-39,96-103")?;
    ensure!(
        proposal["schema"] == "foundation-epoch296-full-retry-placement-v2"
            && proposal["epoch"] == 296
            && proposal["unit"] == UNIT
            && proposal["original_profile"] == json!(original)
            && proposal["previous_allowed_cpus"] == ORIGINAL_CPUS
            && profile["properties"]["AllowedCPUs"] == ORIGINAL_CPUS
            && proposal["allowed_cpus"] == CPUS
            && proposal["planned_epoch258_cpuset"] == replay258::CPUS
            && proposal["online_cpus_on_same_physical_cores"] == json!(exclusive)
            && proposal["namespace_qualified_on_this_cpuset"] == false
            && proposal["fresh_complete_fit_for_this_profile"] == false
            && proposal["capacity_reserved"] == false
            && proposal["replay_launched"] == false
            && proposal["publication_authorized"] == false,
        "epoch 296 placement differs from the sealed preparation or claims authority"
    );
    Ok(exclusive)
}

pub(super) fn placement() -> Result<Placement> {
    let reference = Bound::new(PLACEMENT.0, PLACEMENT.1);
    let proposal = reference.sealed()?;
    let profile = Bound::new(PROFILE.0, PROFILE.1).sealed()?;
    let exclusive_cpus = validate_placement(&proposal, &profile)?;
    Ok(Placement {
        reference,
        exclusive_cpus,
    })
}

pub(super) fn verify_topology(placement: &Placement) -> Result<()> {
    verify_cpu_group(CPUS, &placement.exclusive_cpus)
}

pub(super) fn verify_cpu_group(cpus: &str, exclusive: &BTreeSet<u64>) -> Result<()> {
    let sys = Path::new("/sys/devices/system/cpu");
    let online = units::parse_cpu_list(fs::read_to_string(sys.join("online"))?.trim())?;
    let selected = units::parse_cpu_list(cpus)?;
    let mut siblings = BTreeSet::new();
    for cpu in &selected {
        let path = sys.join(format!("cpu{cpu}/topology/thread_siblings_list"));
        let core = units::parse_cpu_list(fs::read_to_string(path)?.trim())?;
        ensure!(
            core.contains(cpu) && core.intersection(&selected).count() == 1,
            "CPUs {cpus} do not select distinct physical cores"
        );
        siblings.extend(core.intersection(&online).copied());
    }
    ensure!(
        selected.is_subset(&online) && &siblings == exclusive,
        "online physical-core placement for {cpus} changed"
    );
    Ok(())
}

fn validate_namespace(proof: &Value, profile: &Bound, placement: &Placement) -> Result<()> {
    let selected = units::parse_cpu_list(CPUS)?;
    ensure!(
        proof["schema"] == "foundation-epoch296-full-retry-effective-namespace-v2"
            && proof["epoch"] == 296
            && proof["producer_unit"] == UNIT
            && proof["profile"] == json!(profile)
            && proof["placement"] == json!(placement.reference)
            && proof["original_namespace"]
                == json!(Bound::new(ORIGINAL_NAMESPACE.0, ORIGINAL_NAMESPACE.1))
            && proof["properties"]["AllowedCPUs"] == CPUS
            && proof["cpuset_effective"] == json!(selected)
            && proof["process_affinity"] == json!(selected)
            && proof["private_work_writable"] == true
            && proof["token_mount_read_only"] == true
            && proof["readonly_bindings"]
                .as_array()
                .is_some_and(|items| items.len() == 5)
            && proof["worker_started"] == false
            && proof["replay_launched"] == false
            && proof["publication_authorized"] == false,
        "epoch 296 effective namespace qualification differs from the admitted placement"
    );
    Ok(())
}

pub(super) fn check_live_binding(
    n: &mut Native,
    registration: &Value,
    admission: &Value,
    fit: &Value,
    profile_ref: &Bound,
    profile: &Value,
) -> Result<()> {
    let (worker, checkpoint) = focused::feature_296_terminal(n)?;
    let quote = &fit["replay_296_quote"];
    let placement = placement()?;
    verify_topology(&placement)?;
    let namespace_ref = binding(&registration["effective_namespace"])?;
    ensure!(
        namespace_ref.path == Path::new(EFFECTIVE_NAMESPACE),
        "epoch 296 effective namespace custody changed"
    );
    validate_namespace(&namespace_ref.sealed()?, profile_ref, &placement)?;
    let selected = units::parse_cpu_list(CPUS)?;
    let quoted_cpus: BTreeSet<u64> = text(&fit["capacity"], "cpus")?
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        profile_ref.path == Path::new(PROFILE.0)
            && profile_ref.sha256 == PROFILE.1
            && profile["epoch"] == 296
            && profile["schema"] == "foundation-epoch296-corrected-full-replay-preparation-v2"
            && profile["unit"] == UNIT
            && profile["guard_unit"] == GUARD_SERVICE
            && profile["guard"]["path"] == STANDARD_GUARD
            && profile["properties"]["AllowedCPUs"] == ORIGINAL_CPUS
            && profile["terminal_checkpoint"]["slot"] == 128_303_325
            && profile["worker"] == json!(worker)
            && profile["checkpoint_qualification_path"] == json!(checkpoint.path)
            && registration["worker"] == json!(worker)
            && registration["node"] == profile["node"]
            && registration["checkpoint_qualification"] == json!(checkpoint)
            && admission["profile"] == registration["profile"]
            && admission["checkpoint_qualification"] == registration["checkpoint_qualification"]
            && registration["placement"] == json!(placement.reference)
            && admission["placement"] == registration["placement"]
            && admission["effective_namespace"] == json!(namespace_ref)
            && quote["placement"] == registration["placement"]
            && quote["candidate_cpus"] == json!(selected)
            && quote["exclusive_online_cpus"] == json!(placement.exclusive_cpus)
            && quoted_cpus == selected
            && fit["schema"] == "foundation-epoch296-replay-roster-binding-v1"
            && fit["epoch"] == 296
            && quote["repaired_worker"] == json!(worker)
            && quote["checkpoint_qualification"] == json!(checkpoint)
            && quote["candidate_disk_bytes"] == fit["capacity"]["candidate_disk_bytes"]
            && quote["candidate_memory_bytes"] == fit["capacity"]["candidate_total_memory_bytes"],
        "epoch 296 corrected replay differs from its checkpoint or full-roster admission"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal() -> Value {
        json!({
            "schema":"foundation-epoch296-full-retry-placement-v2",
            "epoch":296,
            "unit":UNIT,
            "original_profile":Bound::new(PROFILE.0, PROFILE.1),
            "previous_allowed_cpus":ORIGINAL_CPUS,
            "allowed_cpus":CPUS,
            "planned_epoch258_cpuset":replay258::CPUS,
            "online_cpus_on_same_physical_cores":units::parse_cpu_list("32-39,96-103").unwrap(),
            "namespace_qualified_on_this_cpuset":false,
            "fresh_complete_fit_for_this_profile":false,
            "capacity_reserved":false,
            "replay_launched":false,
            "publication_authorized":false,
        })
    }

    #[test]
    fn placement_respects_both_peer_routes_and_rejects_an_smt_overlap() {
        let profile = json!({"properties":{"AllowedCPUs":ORIGINAL_CPUS}});
        let mut prepared = proposal();
        let exclusive = validate_placement(&prepared, &profile).unwrap();
        for (peer, cpus) in [
            (replay258::UNIT, replay258::CPUS),
            (replay260::UNIT, "56-63"),
        ] {
            assert!(
                require_disjoint_cpus(296, &exclusive, peer, &json!({"AllowedCPUs":cpus})).is_ok()
            );
        }
        assert!(
            require_disjoint_cpus(296, &exclusive, "smt-peer", &json!({"AllowedCPUs":"96"}))
                .is_err()
        );
        prepared["online_cpus_on_same_physical_cores"] =
            json!(units::parse_cpu_list(CPUS).unwrap());
        assert!(validate_placement(&prepared, &profile).is_err());
        prepared = proposal();
        prepared["fresh_complete_fit_for_this_profile"] = json!(true);
        assert!(validate_placement(&prepared, &profile).is_err());
    }

    #[test]
    fn effective_namespace_must_authenticate_the_bound_placement_and_actual_affinity() {
        let placement = Placement {
            reference: Bound::new(PLACEMENT.0, PLACEMENT.1),
            exclusive_cpus: units::parse_cpu_list("32-39,96-103").unwrap(),
        };
        let profile = Bound::new(PROFILE.0, PROFILE.1);
        let selected = units::parse_cpu_list(CPUS).unwrap();
        let mut proof = json!({
            "schema":"foundation-epoch296-full-retry-effective-namespace-v2",
            "epoch":296,
            "producer_unit":UNIT,
            "profile":profile,
            "placement":placement.reference,
            "original_namespace":Bound::new(ORIGINAL_NAMESPACE.0, ORIGINAL_NAMESPACE.1),
            "properties":{"AllowedCPUs":CPUS},
            "cpuset_effective":selected,
            "process_affinity":selected,
            "private_work_writable":true,
            "token_mount_read_only":true,
            "readonly_bindings":vec![json!({"read_only":true});5],
            "worker_started":false,
            "replay_launched":false,
            "publication_authorized":false,
        });
        validate_namespace(&proof, &profile, &placement).unwrap();
        proof["process_affinity"] = json!(units::parse_cpu_list(ORIGINAL_CPUS).unwrap());
        assert!(validate_namespace(&proof, &profile, &placement).is_err());
        proof["process_affinity"] = json!(selected);
        proof["placement"]["sha256"] = json!("0".repeat(64));
        assert!(validate_namespace(&proof, &profile, &placement).is_err());
    }
}
