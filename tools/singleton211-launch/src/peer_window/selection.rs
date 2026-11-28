//! Observe natural firings before issuing a protective-stop admission.
use super::*;

const SECOND: u64 = 1_000_000;
const MAX_WAIT: u64 = 120 * SECOND;
const TRIGGER_TOLERANCE: u64 = 2 * SECOND;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Observation {
    timer: String,
    guard: String,
    trigger: u64,
    start: u64,
    // An executing guard has no completed sample or next deadline to admit.
    completed: Option<(u64, Bound)>,
}

impl Observation {
    fn follows(&self, prior: &Self) -> Result<()> {
        ensure!(self.timer == prior.timer, "original peer timer replaced");
        if self.guard == prior.guard {
            ensure!(
                self.trigger == prior.trigger
                    && self.start == prior.start
                    && (prior.completed.is_none() || self.completed == prior.completed),
                "same guard firing changed"
            );
        } else {
            let (due, _) = prior
                .completed
                .as_ref()
                .context("uncompleted peer guard replaced")?;
            ensure!(
                self.trigger >= *due && self.trigger - due <= TRIGGER_TOLERANCE,
                "unexpected, late or skipped peer firing"
            );
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ManagerState {
    timer: String,
    guard: String,
    start: u64,
    dormant: bool,
}
impl ManagerState {
    fn read(c: &periodic::Control, guard: &Value, timer: &Value) -> Result<Self> {
        let dormant = periodic::service_values(c, guard)?;
        // The two manager reads can span a guard transition. A stable dormant
        // sample below still requires the timer to be waiting.
        periodic::timer_values(c, timer, false)?;
        let tid = text(timer, "InvocationID")?;
        let gid = text(guard, "InvocationID")?;
        ensure!(
            hex(tid, 32) && hex(gid, 32),
            "original peer identities absent"
        );
        Ok(Self {
            timer: tid.into(),
            guard: gid.into(),
            start: text(guard, "ExecMainStartTimestampMonotonic")?.parse()?,
            dormant,
        })
    }
    fn same_firing(&self, other: &Self) -> bool {
        self.timer == other.timer && self.guard == other.guard && self.start == other.start
    }
    fn natural_edge(&self, after: &Self, prior: Option<&Observation>, trigger: u64) -> Result<()> {
        ensure!(
            self.timer == after.timer,
            "original peer timer replaced in read bracket"
        );
        if self.same_firing(after) {
            ensure!(
                !self.dormant && after.dormant && self.start.abs_diff(trigger) <= SECOND,
                "guard changed outside a natural completion"
            );
        } else {
            // Only advance from a completed, already authenticated firing whose
            // concrete deadline was observed before the crossing.
            let previous = prior.context("no prior original deadline for changed guard")?;
            let (due, _) = previous
                .completed
                .as_ref()
                .context("uncompleted peer guard replaced")?;
            ensure!(
                self.dormant
                    && self.guard != after.guard
                    && self.guard == previous.guard
                    && self.timer == previous.timer
                    && self.start == previous.start
                    && after.start > self.start
                    && after.start.abs_diff(trigger) <= SECOND
                    && trigger >= *due
                    && trigger - *due <= TRIGGER_TOLERANCE,
                "unproven peer successor in read bracket"
            );
        }
        Ok(())
    }
}

fn completed_journal(
    n: &mut Native,
    c: &periodic::Control,
    row: &Observation,
    next: u64,
) -> Result<()> {
    let raw = n.run(
        "/usr/bin/journalctl",
        &[
            "--all",
            "--no-pager",
            "--output=json",
            "--boot=0",
            "_PID=1",
            &format!("UNIT={}", c.unit),
            &format!("INVOCATION_ID={}", row.guard),
        ],
    )?;
    let rows = serde_json::Deserializer::from_slice(&raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let (started, ended) = full211_window::guard_clocks(&rows, boot.trim(), &c.unit, &row.guard)?;
    ensure!(
        started.abs_diff(row.start) <= SECOND
            && started.abs_diff(row.trigger) <= SECOND
            && ended < next,
        "peer PID1 history differs from actual guard firing"
    );
    Ok(())
}

fn observe(
    n: &mut Native,
    c: &periodic::Control,
    plan: &Value,
    owner: &Value,
    ticks: u64,
    previous: Option<&Observation>,
) -> Result<Observation> {
    let unit = text(plan, "unit")?;
    let pid = text(owner, "MainPID")?.parse()?;
    let receipts = Path::new(text(plan, "receipt_directory")?);
    let mut crossing: Option<(ManagerState, u64)> = None;
    // One attempt may span a start and the second its completion. Only a
    // third stable read can finish that sequence, under the outer deadline.
    for _ in 0..3 {
        n.check()?;
        let actual = n.show(unit)?;
        live::same_owner(owner, &actual)?;
        ensure!(
            actual["Job"] == "" && native257::process_ticks(pid)? == ticks,
            "retained producer process replaced"
        );
        for name in ["stop-intent.json", "stop-completion.json"] {
            absent(&receipts.join(name))?;
        }
        let guard = n.show(&c.unit)?;
        let timer = n.show(&c.timer)?;
        let before = ManagerState::read(c, &guard, &timer)?;
        let trigger = timer_clock(n, &c.timer, "LastTriggerUSecMonotonic")?;
        let timing = if before.dormant {
            let next = deadline(n, &c.timer)?;
            let ended = if c.unit == GUARD_UNIT {
                None
            } else {
                Some(unit_clock(
                    n,
                    &c.unit,
                    "org.freedesktop.systemd1.Unit",
                    "InactiveEnterTimestampMonotonic",
                )?)
            };
            Some((next, ended))
        } else {
            None
        };
        let guard_after = n.show(&c.unit)?;
        let timer_after = n.show(&c.timer)?;
        let after = ManagerState::read(c, &guard_after, &timer_after)?;
        if let Some((pinned, stamp)) = &crossing {
            ensure!(
                pinned.same_firing(&before)
                    && *stamp == trigger
                    && (!pinned.dormant || before.dormant),
                "guard or trigger changed across re-observation"
            );
        }
        if guard != guard_after || timer != timer_after {
            // Obtain the after trigger again: a start can occur after the first
            // timestamp read. Do not use any mixed cadence or sample as proof.
            let after_trigger = timer_clock(n, &c.timer, "LastTriggerUSecMonotonic")?;
            ensure!(
                after_trigger > 0 && after_trigger <= mono()?,
                "unusable guard trigger"
            );
            if before.same_firing(&after) {
                ensure!(trigger == after_trigger, "same guard trigger changed");
            }
            before.natural_edge(&after, previous, after_trigger)?;
            crossing = Some((after, after_trigger));
            continue;
        }
        periodic::timer_values(c, &timer, before.dormant)?;
        ensure!(
            trigger > 0 && trigger <= mono()? && trigger.abs_diff(before.start) <= SECOND,
            "peer guard did not start at original timer trigger"
        );
        let completed = if let Some((next, ended)) = timing {
            if let Some(ended) = ended {
                ensure!(
                    ended >= before.start
                        && next
                            .checked_sub(ended)
                            .is_some_and(|d| d.abs_diff(60 * SECOND) <= SECOND),
                    "peer completion or timer cadence changed"
                );
            } else {
                ensure!(
                    next.checked_sub(trigger)
                        .is_some_and(|d| d.abs_diff(30 * SECOND) <= SECOND),
                    "full211 timer cadence changed"
                );
            }
            Some((next, healthy_sample(c, plan, &before.guard)?))
        } else {
            None
        };
        let row = Observation {
            timer: before.timer,
            guard: before.guard,
            start: before.start,
            trigger,
            completed,
        };
        if let Some(prior) = previous {
            row.follows(prior)?;
        }
        if let Some((next, _)) = &row.completed
            && (crossing.is_some()
                || previous
                    .is_some_and(|prior| prior.guard != row.guard || prior.completed.is_none()))
        {
            completed_journal(n, c, &row, *next)?;
        }
        return Ok(row);
    }
    bail!("guard failed to stabilize within natural firing observations")
}

// A capacity census can reach the full211 guard while its original oneshot is
// executing. Keep that exact firing pinned through completion before using it.
fn finish_current_firing(
    mut observe: impl FnMut(Option<&Observation>) -> Result<Observation>,
    mut clock: impl FnMut() -> Result<u64>,
    mut sleep: impl FnMut(Duration),
    outer: Option<u64>,
) -> Result<Observation> {
    let mut row = observe(None)?;
    if row.completed.is_some() {
        return Ok(row);
    }
    let end = row
        .trigger
        .checked_add(17 * SECOND)
        .context("full211 firing clock overflow")?;
    let end = outer.map_or(end, |d| d.min(end));
    loop {
        let now = clock()?;
        ensure!(
            now < end,
            "original full211 firing exceeded its completion deadline"
        );
        sleep(Duration::from_micros((end - now).min(150_000)));
        ensure!(clock()? < end, "original full211 firing wait expired");
        let next = observe(Some(&row))?;
        next.follows(&row)?;
        ensure!(clock()? < end, "original full211 firing proof expired");
        if next.completed.is_some() {
            return Ok(next);
        }
        row = next;
    }
}

pub(crate) fn full211_capture_start(
    n: &mut Native,
    c: &periodic::Control,
    plan: &Value,
) -> Result<((String, String, u64), u64)> {
    let owner = &full211_peer::handoff().sealed()?["producer"];
    let ticks = native257::process_ticks(text(owner, "MainPID")?.parse()?)?;
    let deadline = n.deadline;
    let row = finish_current_firing(
        |previous| observe(n, c, plan, owner, ticks, previous),
        mono,
        std::thread::sleep,
        deadline,
    )?;
    let (next, _) = row.completed.context("missing completed full211 sample")?;
    Ok(((row.guard, row.timer, next), row.trigger))
}

fn next_probe(
    rows: &[(bool, Observation)],
    clock: u64,
    end: u64,
    minimum: u64,
) -> Result<Option<u64>> {
    ensure!(clock < end, "simultaneous peer selection expired");
    let mut wake = None;
    for (full211, row) in rows {
        let target = if let Some((next, _)) = &row.completed {
            let remaining = next.saturating_sub(clock);
            ensure!(
                remaining <= 65 * SECOND && clock <= next.saturating_add(TRIGGER_TOLERANCE),
                "peer timer absent or overdue"
            );
            if *full211 {
                if remaining > MARGIN {
                    continue;
                }
            } else if remaining >= minimum {
                start_limit(*next, clock)?;
                continue;
            }
            (*next).max(clock.saturating_add(250_000))
        } else {
            clock.saturating_add(350_000)
        };
        wake = Some(wake.map_or(target, |old: u64| old.min(target)));
    }
    if let Some(target) = wake {
        ensure!(
            target < end,
            "no simultaneous peer window before selection deadline"
        );
    }
    Ok(wake)
}

fn select_inner(n: &mut Native, review: &Value, a: &Value, minimum: u64) -> Result<Window> {
    let entries = roster(review, a)?;
    let fleet_ref = binding(&review["fleet"])?;
    let fleet = fleet_ref.json()?;
    let resource = binding(&review["resource_review"])?.sealed()?;
    let mut owners = Vec::new();
    for (_, p) in &entries {
        let unit = text(p, "unit")?;
        let owner = &fleet["unit_census"][unit];
        ensure!(
            owner["Id"] == unit && owner["InvocationID"] == p["invocation_id"],
            "original peer missing from fleet census"
        );
        let pid = text(owner, "MainPID")?.parse()?;
        owners.push((owner, native257::process_ticks(pid)?));
    }
    let check = || -> Result<()> {
        native257::controller_scope(review)?;
        fresh(num(&fleet, "recorded_unix_seconds")?, now()?, 300)?;
        fresh(num(&resource, "recorded_unix_seconds")?, now()?, 300)
    };
    let end = n.deadline.context("finite selection clock required")?;
    let mut previous: Vec<(bool, Observation)> = Vec::new();
    let mut pass = 0;
    loop {
        check()?;
        n.check()?;
        let mut observed = Vec::new();
        for (i, ((c, p), (owner, ticks))) in entries.iter().zip(&owners).enumerate() {
            let row = observe(n, c, p, owner, *ticks, previous.get(i).map(|(_, r)| r))?;
            observed.push((c.unit == GUARD_UNIT, row));
        }
        let clock = mono()?;
        let wake = next_probe(&observed, clock, end, minimum)?;
        save_json(
            &n.root,
            &format!("peer-selection-{pass:03}.json"),
            &json!({"monotonic_us":clock,"end_monotonic_us":end,"minimum_retained_window_us":minimum,"wake_monotonic_us":wake,"observations":observed}),
        )?;
        if let Some(target) = wake {
            previous = observed;
            pass += 1;
            std::thread::sleep(Duration::from_micros(target.saturating_sub(mono()?)));
            continue;
        }
        // Reopen the accepted controls, original samples and completed firings
        // through the same path used for the original held-gate contract.
        let window = capture(n, review, a)?;
        for ((c, _), (_, row)) in entries.iter().zip(&observed) {
            let (next, sample) = row
                .completed
                .as_ref()
                .context("incomplete selected firing")?;
            if c.unit == GUARD_UNIT {
                let firing = window
                    .full211
                    .as_ref()
                    .context("missing full211")?
                    .receipt();
                ensure!(
                    firing["timer"] == row.timer
                        && firing["guard"] == row.guard
                        && firing["trigger"] == row.trigger
                        && firing["next"] == *next
                        && firing["sample"] == json!(sample),
                    "full211 changed before admission"
                );
            } else {
                let p = window
                    .peers
                    .iter()
                    .find(|p| p.control.unit == c.unit)
                    .context("missing selected peer")?;
                original_state(
                    (&row.guard, &row.timer, *next),
                    (&p.guard_iid, &p.timer_iid, p.next),
                )?;
                ensure!(&p.sample == sample, "selected sample changed");
            }
        }
        check()?;
        ensure!(
            next_probe(&observed, mono()?, end, minimum)?.is_none(),
            "common peer window closed during capture"
        );
        return Ok(window);
    }
}

pub(crate) fn select(n: &mut Native, review: &Value, a: &Value) -> Result<Window> {
    select_minimum(n, review, a, 30 * SECOND)
}
pub(crate) fn select_minimum(
    n: &mut Native,
    review: &Value,
    a: &Value,
    minimum: u64,
) -> Result<Window> {
    ensure!(
        (30 * SECOND..=65 * SECOND).contains(&minimum),
        "peer guard cadence cannot accommodate required time"
    );
    if review.get("turnover_funding").is_some() || review.get("capped_cold_fit").is_some() {
        return capture(n, review, a);
    }
    let end = mono()?
        .checked_add(MAX_WAIT)
        .context("selection clock overflow")?;
    let outer = n.deadline;
    n.deadline = Some(outer.map_or(end, |d| d.min(end)));
    let result = select_inner(n, review, a, minimum);
    n.deadline = outer;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn next_probe(rows: &[(bool, Observation)], clock: u64, end: u64) -> Result<Option<u64>> {
        super::next_probe(rows, clock, end, 30 * SECOND)
    }
    #[test]
    fn original_v156_inflight_guard_must_complete_before_either_deadline() {
        let guard = "8d975e61dc2341f5a740809eb4850f5d";
        let timer = "47e861b5e73747b392c7556b1610c5ca";
        let start = 366_922_047_370;
        let active = Observation {
            guard: guard.into(),
            timer: timer.into(),
            start,
            trigger: start - 1000,
            completed: None,
        };
        let mut done = active.clone();
        done.completed = Some((
            active.trigger + 30 * SECOND,
            Bound::new("/sample", digest(guard.as_bytes())),
        ));
        let replay = |last: Observation, elapsed: u64, outer: u64| {
            let mut rows = [active.clone(), last].into_iter();
            let mut clocks = [start, start + 150_000, start + elapsed].into_iter();
            finish_current_firing(
                |_| rows.next().context("excess capture"),
                || clocks.next().context("excess clock read"),
                |_| {},
                Some(outer),
            )
        };
        assert_eq!(replay(done.clone(), 200_000, start + SECOND).unwrap(), done);
        let mut other = done.clone();
        other.guard = "ee47f9a5d37f44ac860590249431830e".into();
        assert!(replay(other, 200_000, start + SECOND).is_err());
        let mut other = done.clone();
        other.timer = "replacement".into();
        assert!(replay(other, 200_000, start + SECOND).is_err());
        assert!(replay(done.clone(), 17 * SECOND, start + 30 * SECOND).is_err());
        assert!(replay(done, SECOND, start + SECOND).is_err());
    }
    #[test]
    fn actual_v151_251_deadline_waits_for_a_natural_successor() {
        let case: Value =
            serde_json::from_str(include_str!("../fixtures/native261-v151-window.json")).unwrap();
        let next = case["timer_due_us"].as_u64().unwrap();
        let end = case["controller_exit_us"].as_u64().unwrap();
        let budget = crate::native261::stop_window(
            case["prior_v150"]["capture_to_admission_write_us"]
                .as_u64()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(budget, 38_519_097);
        let old = completed(case["guard_iid"].as_str().unwrap(), next);
        assert_eq!(next - end, 622315);
        assert_eq!(
            super::next_probe(&[(false, old)], end, end + MAX_WAIT, budget).unwrap(),
            Some(next)
        );
        let now = next + 1_000_000;
        let renewed = completed("modeled-next-original-firing", next + 61 * SECOND);
        let other = completed("modeled-other-original", now + 45 * SECOND);
        assert!(
            super::next_probe(
                &[(false, renewed.clone()), (false, other)],
                now,
                end + MAX_WAIT,
                budget
            )
            .unwrap()
            .is_none()
        );
        let short = completed("modeled-overlap-too-short", now + 35 * SECOND);
        assert!(
            super::next_probe(
                &[(false, renewed), (false, short)],
                now,
                end + MAX_WAIT,
                budget
            )
            .unwrap()
            .is_some()
        );
    }
    fn completed(gid: &str, due: u64) -> Observation {
        Observation {
            guard: gid.into(),
            timer: "original".into(),
            trigger: due - 62 * SECOND,
            start: due - 62 * SECOND + 100,
            completed: Some((
                due,
                Bound::new(format!("/receipt/{gid}"), digest(gid.as_bytes())),
            )),
        }
    }
    #[test]
    fn staggered_actual_peers_must_share_one_window_after_a_real_firing() {
        let a = completed("251a", 339813273751);
        let b = completed("265a", 339839068306);
        let clock = 339810000000;
        let end = clock + MAX_WAIT;
        assert_eq!(
            next_probe(&[(false, a.clone()), (false, b.clone())], clock, end).unwrap(),
            Some(339813273751)
        );
        let mut firing = completed("251b", 339875273900);
        firing.trigger = 339813273900;
        firing.start = firing.trigger + 100;
        let waiting = Observation {
            completed: None,
            ..firing.clone()
        };
        waiting.follows(&a).unwrap();
        firing.follows(&waiting).unwrap();
        let rows = [(false, firing), (false, b)];
        assert!(next_probe(&rows, 339816000000, end).unwrap().is_some());
        let next265 = completed("265b", 339901068500);
        next265.follows(&rows[1].1).unwrap();
        assert!(
            next_probe(
                &[(false, rows[0].1.clone()), (false, next265)],
                339842000000,
                end
            )
            .unwrap()
            .is_none()
        );
        assert!(next_probe(&rows, 339816000000, 339820000000).is_err());
    }
    #[test]
    fn v142_actual_same_pid1_guard_completes_between_manager_reads() {
        let state = |gid: &str, tid: &str, start, dormant| ManagerState {
            guard: gid.into(),
            timer: tid.into(),
            start,
            dormant,
        };
        let gid = "24fb9ec1c08149be840ca21d7ed752f4";
        let tid = "8a2ba7744065496b8bf4c794d225935f";
        let trigger = 341627306350;
        let running = state(gid, tid, 341627308440, false);
        let done = state(gid, tid, running.start, true);
        running.natural_edge(&done, None, trigger).unwrap();
        assert!(done.natural_edge(&running, None, trigger).is_err());
        assert!(
            running
                .natural_edge(&state("foreign", tid, running.start, true), None, trigger)
                .is_err()
        );
        assert!(
            running
                .natural_edge(
                    &state(gid, "replacement", running.start, true),
                    None,
                    trigger
                )
                .is_err()
        );
        assert!(
            running
                .natural_edge(&done, None, trigger - 2 * SECOND)
                .is_err()
        );
        let first = completed("prior", 341627301629);
        let old = state(&first.guard, &first.timer, first.start, true);
        let later = state(gid, &first.timer, running.start, false);
        old.natural_edge(&later, Some(&first), trigger).unwrap();
        assert!(old.natural_edge(&later, None, trigger).is_err());
        assert!(
            old.natural_edge(&later, Some(&first), 341627301628)
                .is_err()
        );
    }
    #[test]
    fn changed_timer_spoofed_firing_and_late_successor_are_fatal() {
        let a = completed("251a", 200 * SECOND);
        for mut b in [
            completed("251a", 262 * SECOND),
            completed("251b", 265 * SECOND),
            completed("251b", 261 * SECOND),
        ] {
            assert!(b.follows(&a).is_err());
            b.timer = "replacement".into();
            assert!(b.follows(&a).is_err());
        }
        let early = completed("early", 200 * SECOND);
        assert!(
            next_probe(&[(false, early.clone())], 160 * SECOND, 240 * SECOND)
                .unwrap()
                .is_none()
        );
        assert!(
            next_probe(&[(false, early)], 172 * SECOND, 240 * SECOND)
                .unwrap()
                .is_some()
        );
    }
}
