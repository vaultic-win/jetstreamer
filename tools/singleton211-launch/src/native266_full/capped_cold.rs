//! Price the capped worker's cold snapshot beside the original retained attempts.
use super::*;

const REVIEW: &str =
    "/home/ubuntu/.codex/diagnostics/horizon266-capped-cold-funding-v200-a1/review.json";
const REVIEW_SHA: &str = "b7086a68007fc0970e8bfdcdfe8a974c4a4d369321440e05a6efd92e472c60ec";
const V194_PRODUCER: u64 = 176_000_000_000;
const CONTROL_PAIR: u64 = 512 << 20;
const RECEIPTS: u64 = 256 << 20;

fn price(
    winner: &Value,
    prior: &Value,
    resources: (u64, u64, u64),
    current: u64,
    floor: u64,
) -> Result<Value> {
    let (total, available, free) = resources;
    let hard = num(winner, "hard")?;
    ensure!(
        hard == 1_212_131_577_856
            && winner["memory"] == V194_PRODUCER
            && winner["retained_211"] == 47_657_822_720u64
            && winner["retained_265"] == 128_000_000_000u64
            && prior["from_closed_266"] == V194_PRODUCER
            && prior["from_closed_228"] == 16_536_870_912u64
            && prior["retained_228"] == 103_463_129_088u64
            && prior["controller_and_guard_bytes"] == CONTROL_PAIR,
        "original allocation changed"
    );
    let from_228 = native261::MEMORY + CONTROL_PAIR - V194_PRODUCER;
    let residual = num(prior, "retained_228")?
        .checked_sub(from_228)
        .context("228 donor exhausted")?;
    let growth = hard
        .checked_sub(num(winner, "retained_211")?)
        .and_then(|v| v.checked_sub(128_000_000_000))
        .and_then(|v| v.checked_sub(current))
        .context("retained obligation underflow")?;
    let required = capacity::add(floor, RECEIPTS)?;
    ensure!(
        hard <= total && growth <= available && required <= free,
        "capped snapshot capacity unavailable"
    );
    Ok(
        json!({"producer_maximum_bytes":native261::MEMORY,"controller_and_guard_bytes":CONTROL_PAIR,
        "from_v194_266":V194_PRODUCER,"from_residual_228":from_228,"remaining_228":residual,
        "additional_hard_charge":0,"memory_obligation_after_bytes":hard,"remaining_hard_growth_bytes":growth,
        "observed_memory_available_bytes":available,"protected_existing_floor_bytes":floor,"required_initial_free_bytes":required,"observed_available_bytes":free}),
    )
}

fn terminal_manager(n: &mut Native, expected: &Value) -> Result<()> {
    let unit = text(expected, "Id")?;
    turnover::dormant(n, unit)?;
    let manager = n.show(unit)?;
    for (field, value) in expected.as_object().context("original manager fields")? {
        if let Some(actual) = manager.get(field) {
            ensure!(actual == value, "terminal {unit} {field} changed");
        } else {
            ensure!(
                command_field(n, unit, field)? == value.as_str().context("manager value")?,
                "terminal {unit} {field} changed"
            );
        }
    }
    Ok(())
}

pub(crate) fn assess(
    n: &mut Native,
    fleet_ref: &Bound,
    controller: &str,
    held: bool,
) -> Result<Value> {
    original_boot()?;
    let review = Bound::new(REVIEW, REVIEW_SHA).json()?;
    let fleet = peer261::latest(fleet_ref)?;
    let (ledger, book) = peer261::sources(n, &fleet)?;
    let active = rows(&fleet, "active")?;
    ensure!(
        active.len() == 1 && active[0]["epoch"] == 247 && active[0]["phase"] == "upload-readback",
        "unexpected live delivery or replay"
    );
    let basis = binding(&review["basis"])?.json()?;
    let closed = &basis["fit"]["drained_261"];
    let history = binding(&binding(&closed["terminal"])?.json()?["history"])?.sealed()?;
    let hand261 = binding(&history["handoff"])?.sealed()?;
    let admission = binding(&hand261["admission"])?.sealed()?;
    let guard = binding(&history["terminal_guard"])?.json()?;
    let guard_plan = binding(&hand261["guard_plan"])?.sealed()?;
    let cold_floor = num(&guard_plan, "minimum_free_bytes")?;
    ensure!(
        history["handoff"] == review["old_261_handoff"]
            && history["resources_released"] == false
            && history["full_accounts_commitment"] == true
            && guard["producer_invocation_id"] == hand261["invocation_id"]
            && guard["drain"]["original_processes_gone"] == true
            && guard["drain"]["kernel_cgroup"] == "absent"
            && fs::metadata("/run/horizon261-native-cold-v1")?.dev()
                == num(&admission["tmpfs"], "device")?,
        "original 261 closure or mount differs"
    );
    let stop = binding(&review["fresh_266_memory_source"])?.json()?;
    let hand = turnover_window::handoff().sealed()?;
    let trip = binding(&stop["trip"])?.json()?;
    let end = binding(&stop["original_guard"])?.json()?;
    ensure!(
        hand["iid"] == review["current_266_stopped_iid"]
            && hand["iid"] != review["original_261_266_donor_iid"]
            && stop["handoff"] == json!(turnover_window::handoff())
            && trip["producer_invocation_id"] == hand["iid"]
            && trip["trip_reason"] == "root-physical-budget"
            && end["manager"]["drained"] == true
            && hand["held_fit"] == review["fresh_266_allocation"],
        "incorrect v194 stop or predecessor"
    );
    let donor = json!({"unit":hand["unit"],"iid":hand["iid"],"held":hand["held_fit"],"handoff":stop["handoff"],
        "terminal":review["fresh_266_memory_source"],"partial":stop["partial_archive"],"memory_retained":V194_PRODUCER});
    let award = peer261::donor(n, &donor, V194_PRODUCER)?;
    let (u, iid, cap) = funding::OWNERS[2];
    let mut allowed: BTreeSet<String> = rows(&ledger["periodic_controls"], "controls")?
        .iter()
        .map(|r| Ok(text(r, "unit")?.to_owned()))
        .collect::<Result<_>>()?;
    allowed.extend(
        [
            u,
            controller,
            "horizon-native261-protective-v1.service",
            "horizon-native266-protective-v1.service",
            "horizon-266-general-protective-v1.service",
            "horizon-228-root-tail-protective-v1.service",
            "horizon-266-instructions-2789f821-v169-protective.service",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    if held {
        allowed.extend([
            native266_capped::UNIT.to_owned(),
            native266_capped::GUARD_UNIT.to_owned(),
        ]);
    }
    let check = |n: &mut Native| -> Result<(u64, Value)> {
        ensure!(
            funding::manager_units(n)?.is_subset(&allowed),
            "unexpected active service"
        );
        terminal_manager(n, &history["manager"])?;
        terminal_manager(n, &end["manager"]["terminal"])?;
        let timer = n.show(text(&admission, "timer")?)?;
        let old = n.show("horizon-266-instructions-2789f821-v194-protective.timer")?;
        ensure!(
            timer["ActiveState"] == "active"
                && timer["Unit"] == admission["guard_unit"]
                && old["ActiveState"] == "inactive"
                && old["InvocationID"] == hand["timer"],
            "retained guard timer changed"
        );
        let up = n.show(u)?;
        live::same_owner(&active[0]["unit"], &up)?;
        let pid = text(&up, "MainPID")?;
        let argv = rows(&book, "argv")?
            .iter()
            .map(|v| v.as_str().context("uploader argv"))
            .collect::<Result<Vec<_>>>()?;
        let cmd = fs::read(format!("/proc/{pid}/cmdline"))?;
        ensure!(
            !argv.is_empty()
                && fs::read_link(format!("/proc/{pid}/exe"))? == Path::new(argv[0])
                && cmd
                    .strip_suffix(&[0])
                    .is_some_and(|v| v.split(|b| *b == 0).eq(argv.iter().map(|s| s.as_bytes()))),
            "247 uploader identity changed"
        );
        Ok((live::finite_owner(&up, u, iid, cap)?, up))
    };
    let (before, owner) = check(n)?;
    let a = live::resources_at(Path::new(V))?;
    let lease = peer228_extents::Extents::turnover266()?;
    let (after, last) = check(n)?;
    let allocation = lease.finish()?;
    let z = live::resources_at(Path::new(V))?;
    live::same_owner(&owner, &last)?;
    ensure!(
        a.0 == z.0
            && peer261::latest(fleet_ref)? == fleet
            && allocation["source_held"] == hand["held_fit"]["sha256"],
        "host, backing or fleet changed"
    );
    let floor = num(&award["winner"], "required_free")?
        .checked_sub(num(&allocation, "credit")?)
        .context("backing credit exceeds gross floor")?
        .max(cold_floor);
    let result = price(
        &award["winner"],
        &admission["capacity"]["capacity"],
        (
            a.0,
            a.1.min(z.1),
            a.2.min(z.2).min(num(&allocation, "free_lower")?),
        ),
        before.min(after),
        floor,
    )?;
    Ok(
        json!({"review":Bound::new(REVIEW,REVIEW_SHA),"fleet":fleet_ref,"capacity":result,"actual_current_memory":{u:before.min(after)},
        "allocation":allocation,"retained_261":closed,"stopped_266":donor,"uploader":last,"resource_release_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capped_bootstrap_retains_prior_assignment_and_checks_both_resources() {
        let w = json!({"hard":1212131577856u64,"memory":V194_PRODUCER,"retained_211":47657822720u64,"retained_265":128000000000u64});
        let p = json!({"from_closed_266":V194_PRODUCER,"from_closed_228":16536870912u64,"retained_228":103463129088u64,"controller_and_guard_bytes":CONTROL_PAIR});
        let total = w["hard"].as_u64().unwrap();
        let growth = total - 47657822720 - 128000000000;
        let floor = 4289292376064;
        let free = floor + RECEIPTS;
        let r = price(&w, &p, (total, growth, free), 0, floor).unwrap();
        assert_eq!(r["remaining_228"], 86926258176u64);
        for resources in [
            (total - 1, growth, free),
            (total, growth - 1, free),
            (total, growth, free - 1),
        ] {
            assert!(price(&w, &p, resources, 0, floor).is_err());
        }
    }
}
