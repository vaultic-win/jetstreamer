//! Fence the original held gate by each live replay peer's *observed* timer window.
//! Periodic booking and the ordinary admission census still cover dormant commitments.
use super::*;
mod selection;
pub(super) use selection::full211_capture_start;
pub(super) use selection::select;
pub(super) use selection::select_minimum;

const MARGIN: u64 = 5_000_000;
fn start_limit(next: u64, clock: u64) -> Result<u64> {
    let remaining = next
        .checked_sub(clock)
        .context("retained timer already due")?;
    ensure!(
        (30_000_000..=65_000_000).contains(&remaining),
        "retained timer lacks a 30s start window"
    );
    Ok(next - MARGIN)
}
pub(super) fn deadline(n: &mut Native, timer: &str) -> Result<u64> {
    timer_clock(n, timer, "NextElapseUSecMonotonic")
}
pub(super) fn timer_clock(n: &mut Native, timer: &str, property: &str) -> Result<u64> {
    unit_clock(n, timer, "org.freedesktop.systemd1.Timer", property)
}
fn unit_clock(n: &mut Native, unit: &str, interface: &str, property: &str) -> Result<u64> {
    let id: String = unit
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("_{b:02x}")
            }
        })
        .collect();
    let raw = n.run(
        "/usr/bin/busctl",
        &[
            "get-property",
            "org.freedesktop.systemd1",
            &format!("/org/freedesktop/systemd1/unit/{id}"),
            interface,
            property,
        ],
    )?;
    let words: Vec<_> = std::str::from_utf8(&raw)?.split_whitespace().collect();
    ensure!(
        words.len() == 2 && words[0] == "t",
        "retained timer deadline type"
    );
    Ok(words[1].parse()?)
}
struct Peer {
    control: periodic::Control,
    producer: String,
    producer_iid: String,
    guard_iid: String,
    timer_iid: String,
    next: u64,
    sample: Bound,
}
pub(super) fn peer_state(
    n: &mut Native,
    c: &periodic::Control,
    unit: &str,
    iid: &str,
) -> Result<(String, String, u64)> {
    let owner = n.show(unit)?;
    ensure!(
        owner["Id"] == unit
            && owner["InvocationID"] == iid
            && owner["ActiveState"] == "active"
            && owner["SubState"] == "running"
            && owner["Job"] == ""
            && owner["NRestarts"] == "0",
        "retained producer changed"
    );
    let guard = n.show(&c.unit)?;
    let timer = n.show(&c.timer)?;
    let gid = text(&guard, "InvocationID")?;
    let tid = text(&timer, "InvocationID")?;
    ensure!(
        hex(gid, 32)
            && hex(tid, 32)
            && guard["Id"] == c.unit
            && guard["ActiveState"] == "inactive"
            && guard["SubState"] == "dead"
            && guard["Result"] == "success"
            && guard["ExecMainStatus"] == "0"
            && guard["MainPID"] == "0"
            && guard["ControlPID"] == "0"
            && guard["Job"] == ""
            && timer["Id"] == c.timer
            && timer["ActiveState"] == "active"
            && timer["SubState"] == "waiting"
            && timer["Unit"] == c.unit
            && timer["Job"] == "",
        "peer guard not between actual timer firings"
    );
    let next = deadline(n, &c.timer)?;
    ensure!(
        guard == n.show(&c.unit)? && timer == n.show(&c.timer)?,
        "peer owner changed across typed timer read"
    );
    Ok((gid.into(), tid.into(), next))
}
pub(super) fn healthy_sample(c: &periodic::Control, p: &Value, gid: &str) -> Result<Bound> {
    let sample = guard_sample_ref(p, gid)?;
    validate_guard_sample(&sample, &c.guard_plan, &c.executable, p, gid)?;
    Ok(sample)
}

pub(super) fn guard_sample_ref(plan: &Value, iid: &str) -> Result<Bound> {
    ensure!(hex(iid, 32), "invalid guard invocation ID");
    let path = Path::new(text(plan, "receipt_directory")?).join(format!("sample-{iid}.json"));
    trusted_parents(&path)?;
    Ok(Bound::new(&path, hash(&path)?))
}

pub(super) fn validate_guard_sample(
    sample: &Bound,
    guard_plan: &Bound,
    executable: &Bound,
    p: &Value,
    gid: &str,
) -> Result<Value> {
    let s = sample.json()?;
    ensure!(
        s["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && s["guard_invocation_id"] == gid
            && s["producer_invocation_id"] == p["invocation_id"]
            && s["plan"] == json!(guard_plan.path)
            && s["plan_sha256"] == guard_plan.sha256
            && s["guard_sha256"] == executable.sha256
            && s["producer_stop_enabled"] == true,
        "retained peer guard sample differs"
    );
    fresh(num(&s, "recorded_unix_seconds")?, now()?, 120)?;
    for key in [
        "trip_reason",
        "worker_observation_error",
        "root_physical_observation_error",
        "target_handoff_error",
        "canary_target_error",
    ] {
        ensure!(
            s.get(key) == Some(&Value::Null),
            "retained guard error {key}"
        );
    }
    for key in [
        "minimum_free_bytes",
        "maximum_root_physical_bytes",
        "maximum_worker_vmas",
    ] {
        ensure!(s[key] == p[key], "retained guard envelope changed");
    }
    Ok(s)
}
pub(super) struct Window {
    peers: Vec<Peer>,
    full211: Option<full211_window::Window>,
    turnover266: Option<native266_full::turnover_window::Window>,
    pub(super) limit: u64,
    pub(super) receipt: Bound,
}
fn original_state(claimed: (&str, &str, u64), actual: (&str, &str, u64)) -> Result<()> {
    ensure!(
        claimed == actual,
        "retained guard, timer or monotonic deadline rolled over"
    );
    Ok(())
}
impl Window {
    pub(super) fn verify(&mut self, n: &mut Native) -> Result<()> {
        if let Some(window) = &mut self.turnover266 {
            window.verify(n)?;
        }
        if let Some(window) = &mut self.full211 {
            window.verify(n)?;
        }
        for p in &self.peers {
            let c = &p.control;
            periodic::observe(n, c)?;
            let s = peer_state(n, c, &p.producer, &p.producer_iid)?;
            original_state((&p.guard_iid, &p.timer_iid, p.next), (&s.0, &s.1, s.2))?;
            p.sample.json()?;
        }
        ensure!(
            mono()? < self.limit,
            "earliest original peer deadline exhausted"
        );
        n.check()
    }
}
// A native cold peer is registered under the pipeline unit rather than the replay producer.
pub(super) fn protected_owner(candidate: u64, row: &Value) -> Option<&Value> {
    if full211_peer::active(row)
        || matches!(row["phase"].as_str(), Some("replay" | "qualification"))
    {
        Some(&row["producer"])
    } else if row["phase"] == "private-cold-snapshot-verification"
        && (candidate == 266
            || candidate == 212
                && matches!(
                    row["unit"]["Id"].as_str(),
                    Some(native257::UNIT | native261::UNIT)
                ))
    {
        Some(&row["unit"])
    } else {
        None
    }
}
fn roster(review: &Value, a: &Value) -> Result<Vec<(periodic::Control, Value)>> {
    let fleet = binding(&review["fleet"])?.json()?;
    let (_, _, controls) = admission::reservations(review)?;
    let current = a["actual_current_memory"]
        .as_object()
        .context("actual owner census")?;
    let mut expected = BTreeSet::new();
    for active in fleet["active"].as_array().context("active fleet")? {
        if let Some(owner) = protected_owner(a["epoch"].as_u64().unwrap_or_default(), active) {
            expected.insert((
                text(owner, "Id")?.to_owned(),
                text(owner, "InvocationID")?.to_owned(),
            ));
        }
    }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for c in controls {
        let p = c.guard_plan.sealed()?;
        let unit = text(&p, "unit")?;
        let iid = text(&p, "invocation_id")?;
        if !current.contains_key(unit) {
            continue;
        }
        ensure!(
            seen.insert((unit.to_owned(), iid.to_owned())),
            "duplicate scheduled live peer"
        );
        if c.unit == GUARD_UNIT {
            ensure!(
                matches!(a["epoch"].as_u64(), Some(212 | 257 | 261 | 266))
                    && !expected.is_empty()
                    && current.contains_key(UNIT),
                "full211 rollover scope differs"
            );
        }
        entries.push((c, p));
    }
    ensure!(
        expected.is_subset(&seen),
        "live replay has no held timer window"
    );
    Ok(entries)
}
pub(super) fn capture(n: &mut Native, review: &Value, a: &Value) -> Result<Window> {
    if review.get("closed266_booking").is_some() {
        native266_full::closed266_for257::booking(review)?;
        ensure!(a["epoch"]==257 && a["capacity"]["closed266_booking"]==review["closed266_booking"]
            && native266_full::closed266_for257::confirmed_census(&a["actual_current_memory"])?,
            "missing 257 funding census"
        );
        // The enrolled cohort consists solely of uploaders and private transfers. Its
        // exact manager/cgroup roster is rechecked before activation and token release.
        return capture_roster(n,review,a,vec![]);
    }
    if review.get("capped_cold_fit").is_some() {
        native266_capped::checked_review(review)?;
        let fleet = native266_full::peer261::latest(&binding(&review["fleet"])?)?;
        let active = fleet["active"].as_array().context("missing capped fleet owners")?;
        ensure!(
            active.len() == 1
                && active[0]["epoch"] == 247
                && active[0]["phase"] == "upload-readback"
                && active[0]["unit"]["Id"] == delivery247::SUCCESSOR_UNIT
                && a["epoch"] == 266
                && a["actual_current_memory"]
                    .as_object()
                    .is_some_and(|m| m.len() == 1 && m.contains_key(delivery247::SUCCESSOR_UNIT)),
            "unexpected active owner during capped cold admission"
        );
        // The sole delivery owner has no replay timer. Bound this window by the
        // controller deadline and recheck its exact ownership at each funding pass.
        let limit = n.deadline.context("finite controller deadline")?;
        let receipt = save_json(
            &n.root,
            "peer-window.json",
            &json!({"schema":"horizon-singleton211-original-peer-window-v1",
            "review":a["review"],"boot_id":a["boot_id"],"peers":[],"delivery":active[0]["unit"]["Id"],
            "delivery_invocation_id":active[0]["unit"]["InvocationID"],"deadline_with_margin_monotonic_us":limit,
            "recorded_monotonic_us":mono()?}),
        )?;
        return Ok(Window {
            peers: Vec::new(),
            full211: None,
            turnover266: None,
            limit,
            receipt,
        });
    }
    if review.get("turnover_funding").is_some() {
        let origin = native266_full::peer261::trace();
        ensure!(
            a["epoch"] == 261 && review["turnover_funding"] == json!(origin),
            "unknown turnover window"
        );
        let proof = Bound::new(
            "/var/lib/jetstreamer/horizon266-instructions-2789f821-v194-control/peer-window-261-v196-a1/qualification.json",
            "ab9d5b9b189626e6512fd15401d1a08bf25de1a45b4410d05239cbbd636a8f5c",
        );
        let old = proof.sealed()?;
        ensure!(
            review["turnover_peer_qualification"] == json!(proof)
                && old["handoff"] == json!(native266_full::turnover_window::handoff())
                && old["before"]["iid"] != old["after"]["iid"],
            "missing original 266 rollover qualification"
        );
        let fleet = native266_full::peer261::latest(&binding(&review["fleet"])?)?;
        let active = fleet["active"].as_array().context("fleet peers")?;
        let mut expected = BTreeSet::new();
        for row in active {
            let owner = match (row["epoch"].as_u64(), row["phase"].as_str()) {
                (Some(247), Some("upload-readback")) => &row["unit"],
                (Some(266), Some("diagnostic-qualification")) => &row["producer"],
                _ => bail!("unexpected 261 turnover peer"),
            };
            expected.insert(text(owner, "Id")?);
        }
        ensure!(
            expected.len() == 2
                && active.len() == 2
                && a["actual_current_memory"]
                    .as_object()
                    .is_some_and(|v| v.len() == 2 && expected.iter().all(|k| v.contains_key(*k))),
            "incomplete 261 peer census"
        );
        let window = native266_full::turnover_window::Window::open(n)?;
        let limit = n.deadline.context("finite operator window")?;
        let receipt = save_json(
            &n.root,
            "peer-window.json",
            &json!({"schema":"horizon-singleton211-original-peer-window-v1",
            "review":a["review"],"boot_id":a["boot_id"],"peers":[{"epoch":266,"qualification":proof,"firing":window.current}],
            "delivery":delivery247::SUCCESSOR_UNIT,"deadline_with_margin_monotonic_us":limit,"recorded_monotonic_us":mono()?}),
        )?;
        return Ok(Window {
            peers: Vec::new(),
            full211: None,
            turnover266: Some(window),
            limit,
            receipt,
        });
    }
    capture_roster(n, review, a, roster(review, a)?)
}
fn capture_roster(
    n: &mut Native,
    review: &Value,
    a: &Value,
    entries: Vec<(periodic::Control, Value)>,
) -> Result<Window> {
    let mut peers = Vec::new();
    let mut rows = Vec::new();
    let mut limit = u64::MAX;
    let mut full211 = None;
    for (c, p) in entries {
        let unit = text(&p, "unit")?;
        let iid = text(&p, "invocation_id")?;
        if c.unit == GUARD_UNIT {
            ensure!(full211.is_none(), "duplicate full211 window");
            let window = full211_window::Window::admitted(n, review)?;
            rows.push(json!({"control":c,"producer":unit,"producer_iid":iid,"qualification":review["full211_window_qualification"],"completed_firing":window.receipt()}));
            full211 = Some(window);
            continue;
        }
        periodic::observe(n, &c)?;
        let (gid, tid, next) = peer_state(n, &c, unit, iid)?;
        let sample = healthy_sample(&c, &p, &gid)?;
        limit = limit.min(start_limit(next, mono()?)?);
        rows.push(json!({"control":c,"producer":unit,"producer_iid":iid,"guard_iid":gid,"timer_iid":tid,"next_elapse_monotonic_us":next,"sample":sample}));
        peers.push(Peer {
            control: c,
            producer: unit.into(),
            producer_iid: iid.into(),
            guard_iid: gid,
            timer_iid: tid,
            next,
            sample,
        });
    }
    if !peers.is_empty() {
        start_limit(limit + MARGIN, mono()?)?;
    }
    let receipt = save_json(
        &n.root,
        "peer-window.json",
        &json!({"schema":"horizon-singleton211-original-peer-window-v1","review":a["review"],"boot_id":a["boot_id"],"peers":rows,"deadline_with_margin_monotonic_us":limit,"recorded_monotonic_us":mono()?}),
    )?;
    Ok(Window {
        peers,
        full211,
        turnover266: None,
        limit,
        receipt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_owner_and_deadline_must_remain_from_one_firing() {
        let original = ("guard-265", "timer-265", 160_000_000);
        original_state(original, original).unwrap();
        for changed in [
            ("next-guard", "timer-265", 160_000_000),
            ("guard-265", "other-timer", 160_000_000),
            ("guard-265", "timer-265", 220_000_000),
        ] {
            assert!(original_state(original, changed).is_err());
        }
    }
    #[test]
    fn use_original_typed_deadline_and_leave_time_for_publication() {
        assert_eq!(start_limit(130_000_000, 100_000_000).unwrap(), 125_000_000);
        for next in [99_000_000, 129_999_999, 165_000_001, u64::MAX] {
            assert!(start_limit(next, 100_000_000).is_err());
        }
    }
}
