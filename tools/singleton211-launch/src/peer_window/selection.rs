//! Observe natural firings before issuing the native257 protective-stop admission.
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

fn observe(
    n: &mut Native,
    c: &periodic::Control,
    plan: &Value,
    owner: &Value,
    ticks: u64,
) -> Result<Observation> {
    let unit = text(plan, "unit")?;
    let pid = text(owner, "MainPID")?.parse()?;
    let actual = n.show(unit)?;
    live::same_owner(owner, &actual)?;
    ensure!(
        actual["Job"] == "" && native257::process_ticks(pid)? == ticks,
        "retained producer process replaced"
    );

    let receipts = Path::new(text(plan, "receipt_directory")?);
    for name in ["stop-intent.json", "stop-completion.json"] {
        absent(&receipts.join(name))?;
    }
    let guard = n.show(&c.unit)?;
    let dormant = periodic::service_values(c, &guard)?;
    let timer = n.show(&c.timer)?;
    periodic::timer_values(c, &timer, dormant)?;
    let guard_id = text(&guard, "InvocationID")?;
    let timer_id = text(&timer, "InvocationID")?;
    ensure!(
        hex(guard_id, 32) && hex(timer_id, 32),
        "original peer identities absent"
    );
    let trigger = timer_clock(n, &c.timer, "LastTriggerUSecMonotonic")?;
    let start = text(&guard, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?;
    ensure!(
        trigger > 0 && trigger <= mono()? && trigger.abs_diff(start) <= SECOND,
        "peer guard did not start at original timer trigger"
    );
    let completed = if dormant {
        let next = deadline(n, &c.timer)?;
        let elapsed = next
            .checked_sub(trigger)
            .context("invalid original timer cadence")?;
        if c.unit == GUARD_UNIT {
            ensure!(
                elapsed.abs_diff(30 * SECOND) <= SECOND,
                "full211 timer cadence changed"
            );
        } else {
            // OnUnitInactiveSec=60s is relative to the actual completed service.
            let ended = unit_clock(
                n,
                &c.unit,
                "org.freedesktop.systemd1.Unit",
                "InactiveEnterTimestampMonotonic",
            )?;
            ensure!(
                ended >= start
                    && next
                        .checked_sub(ended)
                        .is_some_and(|d| d.abs_diff(60 * SECOND) <= SECOND),
                "peer completion or timer cadence changed"
            );
        }
        Some((next, healthy_sample(c, plan, guard_id)?))
    } else {
        None
    };
    ensure!(
        guard == n.show(&c.unit)? && timer == n.show(&c.timer)?,
        "peer changed during observation"
    );
    Ok(Observation {
        timer: timer_id.into(),
        guard: guard_id.into(),
        trigger,
        start,
        completed,
    })
}

fn next_probe(rows: &[(bool, Observation)], clock: u64, end: u64) -> Result<Option<u64>> {
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
            } else if remaining >= 30 * SECOND {
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

fn select_inner(n: &mut Native, review: &Value, a: &Value) -> Result<Window> {
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
            let row = observe(n, c, p, owner, *ticks)?;
            if let Some((_, last)) = previous.get(i) {
                row.follows(last)?;
            }
            observed.push((c.unit == GUARD_UNIT, row));
        }
        let clock = mono()?;
        let wake = next_probe(&observed, clock, end)?;
        save_json(
            &n.root,
            &format!("peer-selection-{pass:03}.json"),
            &json!({"monotonic_us":clock,"end_monotonic_us":end,"wake_monotonic_us":wake,"observations":observed}),
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
            next_probe(&observed, mono()?, end)?.is_none(),
            "common peer window closed during capture"
        );
        return Ok(window);
    }
}

pub(crate) fn select(n: &mut Native, review: &Value, a: &Value) -> Result<Window> {
    let end = mono()?
        .checked_add(MAX_WAIT)
        .context("selection clock overflow")?;
    let outer = n.deadline;
    n.deadline = Some(outer.map_or(end, |d| d.min(end)));
    let result = select_inner(n, review, a);
    n.deadline = outer;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
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
