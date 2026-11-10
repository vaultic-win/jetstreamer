//! A measured host component already occurs inside the unchanged complete promise.
//! Kernel pages stay inside the independent resident projection, including Slab.
use super::*;
pub(super) const HOST_BUDGET: u64 = 43_603_734_528;
const MARGIN: u64 = 1 << 30;
fn b(v: &Value) -> Result<Value> {
    bound(&serde_json::from_value::<Bound>(v.clone())?)
}
pub(super) fn provenance() -> Result<Value> {
    let proof=Bound{path:"/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/anon173-host-kernel-qa-v14/native-r2/ACTUAL_FULFILLED_ANON_HOST_KERNEL_MEMORY_QUALIFICATION.json".into(),sha256:"f7d633adda3a1ccbca5cd4855ed47c3ff080c246f7ce8a8238a56b6d1ea978bf".into()};
    let prior = bound(&proof)?;
    ensure!(
        prior["owner"] == "/root"
            && prior["complete_hard_memory_promises_preserved_bytes"] == MEMORY
            && prior["complete_DATA_promises_preserved_bytes"] == DATA
            && prior["corrected_conservative_authority"]
                == serde_json::to_value(Bound {
                    path: AUTHORITY.into(),
                    sha256: AUTHORITY_SHA.into()
                })?,
        "historical host component belongs to another complete authority"
    );
    let h = &prior["historical_true_host_component_provenance"];
    let o = b(&h["observer"])?;
    let raw = b(&h["raw_accounting"])?;
    let selected = b(&h["selected_memory"])?;
    ensure!(
        o["recorded_at_utc"] == "2026-11-09T15:30:22Z"
            && o["replays"].as_array().is_some_and(Vec::is_empty),
        "original host census scope"
    );
    let mut measured = 0u64;
    for side in ["before", "after"] {
        let v = &o["host_resident_memory"][side];
        ensure!(
            v["status"] == "observed"
                && v["rss"]["census_stable"] == true
                && v["rss"]["error"].is_null(),
            "original host census incomplete"
        );
        let mut total = v["rss"]["aggregate_rss_bytes"]
            .as_u64()
            .context("host RSS")?;
        for k in ["Slab", "KernelStack", "PageTables", "Percpu"] {
            total = total
                .checked_add(
                    v["kernel_components_bytes"][k]
                        .as_u64()
                        .context("host kernel")?,
                )
                .context("host overflow")?;
        }
        measured = measured.max(total);
    }
    let mut direct = 0u64;
    let mut typed = 0u64;
    for p in raw["active_peer_allocations"]
        .as_array()
        .context("raw peers")?
    {
        let tag = match p.get("native_pool_suballocation") {
            Some(Value::Bool(v)) => Some(*v),
            None => None,
            _ => anyhow::bail!("unknown original pool tag"),
        };
        let bytes = p["memory_max_bytes"].as_u64().context("raw peer memory")?;
        if tag != Some(true) {
            direct = direct.checked_add(bytes).context("direct overflow")?;
        }
        if tag == Some(false) {
            typed = typed.checked_add(bytes).context("typed overflow")?;
        }
    }
    ensure!(
        measured == HOST_BUDGET
            && h["true_measured_host_component_bytes"] == HOST_BUDGET
            && direct == 834_834_268_160
            && typed == 832_149_913_600
            && direct - typed == 2_684_354_560
            && selected["selection"]["raw_peer_memory_bytes"] == typed
            && selected["selection"]["raw_total_memory_promises_bytes"] == 1_102_313_172_992u64
            && measured + (128 + 16 + 64) * (1 << 30) + (1 << 29) + direct == 1_102_313_172_992,
        "true host component cannot absorb input/pool promises"
    );
    let identity = identity()?;
    ensure!(
        identity == prior["kernel_identity_after"],
        "kernel ABI/boot differs from the qualified historical source contract"
    );
    Ok(
        json!({"historical_native_proof":proof,"historical_true_host_component_provenance":h,"source_proven_host_budget_bytes":HOST_BUDGET,"kernel_identity":identity,"old_anon_only_counter_route_reused":false,"new_same_resident_basis_route":true}),
    )
}
fn identity() -> Result<Value> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(
        release.len() < 256 && boot.len() < 128 && std::env::consts::ARCH == "x86_64",
        "kernel identity bound"
    );
    Ok(json!({"release":release.trim(),"boot_id":boot.trim(),"machine":"x86_64"}))
}
pub(super) fn fulfilled(hosts: &[&Value], budget: u64) -> Result<Value> {
    ensure!(
        budget == HOST_BUDGET && hosts.len() == 4,
        "one exact historical host component and four coordinated/admission endpoints"
    );
    let mut minima = BTreeMap::new();
    for h in hosts {
        ensure!(h["status"] == "observed", "host counter scope");
        let map = h["kernel_components_bytes"]
            .as_object()
            .context("kernel components")?;
        ensure!(
            map.len() == 4
                && ["Slab", "KernelStack", "PageTables", "Percpu"]
                    .iter()
                    .all(|k| map.contains_key(*k)),
            "whole Slab must remain in the resident basis without child overlap"
        );
        for k in ["Slab", "KernelStack", "PageTables"] {
            let bytes = map[k].as_u64().context("kernel bytes")?;
            minima
                .entry(k)
                .and_modify(|v: &mut u64| *v = (*v).min(bytes))
                .or_insert(bytes);
        }
    }
    let sum = minima.values().try_fold(0u64, |a, b| {
        a.checked_add(*b).context("kernel sum overflow")
    })?;
    let realized = sum.saturating_sub(MARGIN).min(budget);
    Ok(
        json!({"component_minima_bytes":minima,"physical_kernel_bytes_before_margin":sum,"additional_margin_bytes":MARGIN,"realized_host_component_bytes":realized,"source_proven_host_component_bytes":budget,"remaining_host_component_bytes":budget-realized,"global_kernel_entries":1,"Percpu_credited_bytes":0,"kernel_credit_inside_lane_RSS_bytes":0,"outside_input_promise_credited_bytes":0,"whole_Slab_still_charged_in_independent_resident_projection":true,"promise_ending_bytes":0,"resource_credit_bytes":0}),
    )
}
pub(super) fn point(
    total: u64,
    available: u64,
    resident: u64,
    lane: u64,
    host: u64,
) -> Result<Value> {
    ensure!(
        host <= HOST_BUDGET,
        "host fulfillment exceeds source proven component"
    );
    let realized = lane.checked_add(host).context("realized overflow")?;
    let future = MEMORY
        .checked_sub(realized)
        .context("realized portions exceed complete promises")?;
    let required = future.checked_add(RESERVE).context("required overflow")?;
    let projected = resident
        .checked_add(required)
        .context("resident projection overflow")?;
    let full = MEMORY.checked_add(RESERVE).context("complete overflow")?;
    Ok(
        json!({"complete_hard_promises_preserved_bytes":MEMORY,"headroom_bytes":RESERVE,"lane_realized_bytes":lane,"host_realized_bytes":host,"remaining_future_growth_bytes":future,"required_available_bytes":required,"actual_available_bytes":available,"resident_basis_bytes":resident,"resident_plus_future_and_reserve_bytes":projected,"actual_total_bytes":total,"fits":total>=full && available>=required && projected<=total,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}
pub(super) fn same_identity(proof: &Value) -> Result<()> {
    ensure!(
        identity()? == proof["kernel_identity"],
        "kernel identity changed inside admission"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn host(slab: u64, stack: u64, pt: u64, percpu: u64) -> Value {
        json!({"status":"observed","kernel_components_bytes":{"Slab":slab,"KernelStack":stack,"PageTables":pt,"Percpu":percpu}})
    }
    #[test]
    fn global_kernel_is_counted_once_with_component_minima_and_margin() {
        let a = host(40 << 30, 2 << 30, 3 << 30, 8 << 30);
        let b = host(35 << 30, 3 << 30, 2 << 30, 9 << 30);
        let p = fulfilled(&[&a, &b, &a, &b], HOST_BUDGET).unwrap();
        assert_eq!(p["realized_host_component_bytes"], 38u64 << 30);
        assert_eq!(p["Percpu_credited_bytes"], 0);
    }
    #[test]
    fn unknown_budget_or_duplicate_slab_children_are_rejected() {
        let mut h = host(1, 2, 3, 4);
        assert!(fulfilled(&[&h, &h, &h, &h], HOST_BUDGET + 1).is_err());
        h["kernel_components_bytes"]["SReclaimable"] = json!(1);
        assert!(fulfilled(&[&h, &h, &h, &h], HOST_BUDGET).is_err());
    }
    #[test]
    fn independent_projection_still_rejects_double_counted_available_pages() {
        let p = point(MEMORY + RESERVE + 10, MEMORY, 30, 0, 0).unwrap();
        assert_eq!(p["fits"], false);
    }
    #[test]
    fn already_booked_host_kernel_resolves_false_extra_host_charge() {
        let total = 810_902_843_392;
        let resident = 182_000_000_000;
        let lanes = 135_000_000_000;
        let available = 730_000_000_000;
        assert_eq!(
            point(total, available, resident, lanes, 0).unwrap()["fits"],
            false
        );
        assert_eq!(
            point(total, available, resident, lanes, 36_000_000_000).unwrap()["fits"],
            true
        );
    }
    #[test]
    fn host_fulfillment_never_absorbs_unlimited_kernel_or_input_promises() {
        let h = host(100 << 30, 2 << 30, 3 << 30, 50 << 30);
        let p = fulfilled(&[&h, &h, &h, &h], HOST_BUDGET).unwrap();
        assert_eq!(p["realized_host_component_bytes"], HOST_BUDGET);
        assert_eq!(p["outside_input_promise_credited_bytes"], 0);
        assert!(point(u64::MAX, u64::MAX, 0, 0, HOST_BUDGET + 1).is_err());
    }
}
