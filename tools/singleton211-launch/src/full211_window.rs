//! Distinguish an actual completed timer firing from a proposed future firing.
use super::*;

const CADENCE: u64 = 30_000_000;
const ACCURACY: u64 = 1_000_000;
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Firing {
    guard: String,
    timer: String,
    trigger: u64,
    next: u64,
    start: u64,
    end: u64,
    sample: Bound,
    journal: Bound,
    lower_physical: u64,
    free: u64,
}
fn measurement(s: &Value, floor: u64, gid: &str) -> Result<(u64, u64)> {
    let c = full211_peer::control();
    let p = &s["producer"];
    ensure!(
        s["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && s["guard_invocation_id"] == gid
            && s["producer_invocation_id"] == full211_peer::IID
            && s["plan"] == json!(c.guard_plan.path)
            && s["plan_sha256"] == c.guard_plan.sha256
            && s["guard_sha256"] == c.executable.sha256
            && s["producer_stop_enabled"] == true
            && s["bounded_measurement"] == false
            && s["scratch_deleted"] == false
            && s["minimum_free_bytes"] == floor
            && s["maximum_root_physical_bytes"] == SCRATCH
            && s["maximum_worker_vmas"] == 3_500_000
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error",
                "target_handoff_error",
                "target_handoff",
                "bounded_canary",
                "native_main"
            ]
            .iter()
            .all(|k| s.get(*k) == Some(&Value::Null))
            && s["remote_mutations"] == false
            && s["r2_mutations"] == false
            && p["pid"] == 1962046
            && p["invocation_id"] == full211_peer::IID
            && p["load_state"] == "loaded"
            && p["active"] == "active"
            && p["sub"] == "running"
            && p["result"] == "success"
            && p["restarts"] == 0
            && p["restart_policy"] == "no"
            && p["delegated"] == false
            && p["kill_mode"] == "control-group"
            && p["cgroup"] == format!("/system.slice/{UNIT}"),
        "full211 measured guard scope or producer differs"
    );
    let root = &s["root_physical_observation"];
    let bytes = |key: &str| -> Result<u64> {
        let pass = &root[key];
        ensure!(
            num(pass, "vanished_entries")? == 0
                && num(pass, "symlinks")? == 0
                && num(pass, "directories")? > 0
                && num(pass, "entries")? > 0,
            "incomplete full211 physical pass"
        );
        num(pass, "physical_bytes")
    };
    let (a, b) = (bytes("first")?, bytes("second")?);
    let free = num(s, "available_bytes")?;
    ensure!(
        free >= floor
            && root["exceeds_budget"] == false
            && root["maximum_physical_bytes"] == SCRATCH
            && a.max(b) <= SCRATCH
            && root["conservative_physical_bytes"] == a.max(b),
        "guard free space or physical cap differs"
    );
    Ok((a.min(b), free))
}
pub(super) fn guard_clocks(
    rows: &[Value],
    boot: &str,
    unit: &str,
    gid: &str,
) -> Result<(u64, u64)> {
    let mut start = None;
    let mut end = None;
    for r in rows {
        ensure!(
            r["_BOOT_ID"] == boot.replace('-', "")
                && r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == unit
                && r["INVOCATION_ID"] == gid,
            "unexpected periodic guard PID1 record"
        );
        let t = text(r, "__MONOTONIC_TIMESTAMP")?.parse()?;
        let msg = text(r, "MESSAGE")?;
        match text(r, "MESSAGE_ID")? {
            "7d4958e842da4a758f6c1cdc7b36dcc5"
                if msg.starts_with(&format!("Starting {unit} -")) =>
            {
                ensure!(start.replace(t).is_none(), "repeated guard start")
            }
            "7ad2d189f7e94e70a38c781354912448"
                if msg == format!("{unit}: Deactivated successfully.") =>
            {
                ensure!(end.replace(t).is_none(), "repeated guard exit")
            }
            "39f53479d3a045ac8e11786248231fbf"
                if msg.starts_with(&format!("Finished {unit} -")) => {}
            "ae8f7b866b0347b9af31fe1c80b127c0"
                if msg.starts_with(&format!("{unit}: Consumed ")) => {}
            _ => bail!("unexpected periodic guard PID1 result"),
        }
    }
    let (start, end) = (
        start.context("guard start absent")?,
        end.context("guard completion absent")?,
    );
    ensure!(start < end, "guard journal order");
    Ok((start, end))
}
impl Firing {
    fn same_or_successor(&self, new: &Self) -> Result<()> {
        ensure!(self.timer == new.timer, "full211 timer replaced");
        if self.guard == new.guard {
            ensure!(
                self.trigger == new.trigger
                    && self.next == new.next
                    && self.start == new.start
                    && self.end == new.end
                    && self.sample == new.sample
                    && self.lower_physical == new.lower_physical
                    && self.free == new.free
                    && (self.journal.sha256 == new.journal.sha256
                        || equal_journal_rows(
                            &self.journal.bytes(false)?,
                            &new.journal.bytes(false)?
                        )?),
                "original full211 guard changed"
            );
        } else {
            ensure!(
                self.end < self.next
                    && new.trigger >= self.next
                    && new.trigger - self.next <= ACCURACY + 1_000_000
                    && new.start > self.end
                    && new.next > self.next
                    && new.sample != self.sample
                    && new.journal.sha256 != self.journal.sha256,
                "full211 firing was skipped, early, delayed, or substituted"
            );
        }
        Ok(())
    }
    fn await_successor(&self, n: &mut Native) -> Result<()> {
        let due = self
            .next
            .checked_add(1_000_000)
            .context("guard clock overflow")?;
        ensure!(
            n.deadline.is_none_or(|d| due < d),
            "next full211 firing exceeds the original operator deadline"
        );
        std::thread::sleep(Duration::from_micros(due.saturating_sub(mono()?)));
        let wait_until = self
            .next
            .checked_add(17_000_000)
            .context("guard deadline overflow")?;
        loop {
            n.check()?;
            ensure!(
                mono()? < wait_until,
                "next full211 protection failed to complete within its existing runtime and accuracy"
            );
            let s = n.show(GUARD_UNIT)?;
            if s["ActiveState"] == "inactive"
                && s["SubState"] == "dead"
                && s["InvocationID"] != self.guard
            {
                break;
            }
            ensure!(
                s["Result"] == "success"
                    && matches!(s["ActiveState"].as_str(), Some("activating" | "inactive")),
                "full211 guard failed during natural rollover"
            );
            std::thread::sleep(Duration::from_millis(150));
        }
        Ok(())
    }
    pub(super) fn capture(n: &mut Native) -> Result<Self> {
        let c = full211_peer::control();
        let p = c.guard_plan.sealed()?;
        let root = launch::package(full211_peer::ATTEMPT, "guard-receipts");
        ensure!(
            p["worker_root"] == ROOT
                && p["receipt_directory"] == json!(root)
                && p["filesystem"] == "/"
                && fs::metadata(ROOT)?.dev() == fs::metadata("/")?.dev(),
            "full211 guard root or filesystem changed"
        );
        let fence = |n: &mut Native| -> Result<_> {
            for name in ["stop-intent.json", "stop-completion.json"] {
                absent(&root.join(name))?;
            }
            let state = peer_window::peer_state(n, &c, UNIT, full211_peer::IID)?;
            Ok((
                state,
                peer_window::timer_clock(n, TIMER, "LastTriggerUSecMonotonic")?,
            ))
        };
        periodic::observe(n, &c)?;
        let before = peer_window::full211_capture_start(n, &c, &p)?;
        let ((gid, timer, next), trigger) = &before;
        let sample = peer_window::healthy_sample(&c, &p, gid)?;
        let s = sample.json()?;
        let useroot = fs::metadata(ROOT)?;
        ensure!(
            Path::new(ROOT).canonicalize()? == Path::new(ROOT),
            "full211 scratch root alias"
        );
        let (lower_physical, free) = measurement(&s, num(&p, "minimum_free_bytes")?, gid)?;
        let raw = n.run(
            "/usr/bin/journalctl",
            &[
                "--all",
                "--no-pager",
                "--output=json",
                "--boot=0",
                "_PID=1",
                &format!("UNIT={GUARD_UNIT}"),
                &format!("INVOCATION_ID={gid}"),
            ],
        )?;
        let journal = Bound::new(
            n.root.join(format!("command-{:04}.stdout", n.counter)),
            digest(&raw),
        );
        journal.bytes(false)?;
        let rows = decode_journal(&raw)?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let (start, end) = guard_clocks(&rows, boot.trim(), GUARD_UNIT, gid)?;
        let clock = mono()?;
        ensure!(
            start.abs_diff(*trigger) <= ACCURACY
                && next.saturating_sub(*trigger).abs_diff(CADENCE) <= ACCURACY
                && end <= clock
                && *next > clock
                && end <= *next
                && clock - start <= CADENCE + ACCURACY,
            "full211 timer and completed PID1 firing disagree"
        );
        ensure!(
            fence(n)? == before
                && sample.json()? == s
                && fs::metadata(ROOT)?.dev() == useroot.dev()
                && fs::metadata(ROOT)?.ino() == useroot.ino(),
            "full211 guard completed or root changed during evidence capture"
        );
        Ok(Self {
            guard: gid.clone(),
            timer: timer.clone(),
            trigger: *trigger,
            next: *next,
            start,
            end,
            sample,
            journal,
            lower_physical,
            free,
        })
    }
    pub(super) fn capacity(
        &self,
        row: &mut capacity::Reservation,
        free: &mut u64,
    ) -> Result<Value> {
        ensure!(
            row.unit == UNIT
                && row.invocation_id == full211_peer::IID
                && row.release.is_none()
                && row.maximum_memory_bytes == MEMORY
                && row.remaining_disk_growth_bytes >= SCRATCH,
            "full211 nominal reservation missing"
        );
        let nominal = row.remaining_disk_growth_bytes;
        row.remaining_disk_growth_bytes = nominal
            .checked_sub(self.lower_physical)
            .context("full211 resident bytes exceed nominal cap")?;
        *free = (*free).min(self.free);
        Ok(
            json!({"handoff":full211_peer::handoff(),"guard":self,"nominal_disk_growth_bytes":nominal,"remaining_disk_growth_bytes":row.remaining_disk_growth_bytes,"minimum_free_bytes":row.minimum_free_bytes,"conservative_free_bytes":*free}),
        )
    }
}

fn decode_journal(raw: &[u8]) -> Result<Vec<Value>> {
    Ok(serde_json::Deserializer::from_slice(raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
// journald may serialize fields in a different order on each read. Each raw
// output retains its own digest. Compare all fields and the original row order.
fn equal_journal_rows(left: &[u8], right: &[u8]) -> Result<bool> {
    Ok(decode_journal(left)? == decode_journal(right)?)
}

fn reopen(f: &Firing, boot: &str) -> Result<()> {
    let c = full211_peer::control();
    let p = c.guard_plan.sealed()?;
    let path = Path::new(text(&p, "receipt_directory")?).join(format!("sample-{}.json", f.guard));
    ensure!(
        hex(&f.guard, 32) && hex(&f.timer, 32) && f.sample.path == path,
        "full211 qualification path changed"
    );
    trusted_parents(&path)?;
    let (lower, free) = measurement(&f.sample.json()?, num(&p, "minimum_free_bytes")?, &f.guard)?;
    trusted_parents(&f.journal.path)?;
    let rows = decode_journal(&f.journal.bytes(false)?)?;
    ensure!(
        guard_clocks(&rows, boot, GUARD_UNIT, &f.guard)? == (f.start, f.end)
            && (lower, free) == (f.lower_physical, f.free)
            && f.start.abs_diff(f.trigger) <= ACCURACY
            && f.next.saturating_sub(f.trigger).abs_diff(CADENCE) <= ACCURACY
            && f.end < f.next,
        "full211 saved qualification changed"
    );
    Ok(())
}
pub(super) struct Window {
    current: Firing,
}
impl Window {
    pub(super) fn admitted(n: &mut Native, r: &Value) -> Result<Self> {
        let proof = binding(&r["full211_window_qualification"])?;
        let q = proof.sealed()?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        ensure!(
            q["schema"] == "horizon-full211-live-guard-rollover-v1"
                && q["boot_id"] == boot.trim()
                && q["handoff"] == json!(full211_peer::handoff())
                && q["guard_plan"] == json!(full211_peer::control().guard_plan)
                && q["guard_or_producer_mutations"] == false,
            "unregistered full211 rollover qualification"
        );
        let old: Firing = serde_json::from_value(q["before"].clone())?;
        let new: Firing = serde_json::from_value(q["after"].clone())?;
        for f in [&old, &new] {
            reopen(f, boot.trim())?;
        }
        ensure!(
            old.guard != new.guard,
            "qualification must cross a real firing"
        );
        old.same_or_successor(&new)?;
        let current = Firing::capture(n)?;
        ensure!(
            current.timer == new.timer && current.trigger >= new.trigger,
            "full211 qualified timer changed"
        );
        Ok(Self { current })
    }
    pub(super) fn receipt(&self) -> Value {
        json!(self.current)
    }
    fn transition_firing(
        &self,
        mut clock: impl FnMut() -> Result<u64>,
        mut capture: impl FnMut(bool) -> Result<Firing>,
    ) -> Result<Firing> {
        let has_margin = |now: u64, next: u64| now.checked_add(5_000_000).is_some_and(|t| t < next);
        let mut wait = !has_margin(clock()?, self.current.next);
        loop {
            let new = capture(wait)?;
            self.current.same_or_successor(&new)?;
            ensure!(
                !wait || self.current.guard != new.guard,
                "full211 successor did not fire"
            );
            if has_margin(clock()?, new.next) {
                return Ok(new);
            }
            // A fenced capture can consume the last fraction of the five-second reserve.
            // Wait for one adjacent firing under the existing peer and operator deadlines.
            ensure!(
                !wait && new.guard == self.current.guard,
                "full211 next firing too near for a custody transition"
            );
            wait = true;
        }
    }
    pub(super) fn verify(&mut self, n: &mut Native) -> Result<()> {
        let new = self.transition_firing(mono, |wait| {
            if wait {
                self.current.await_successor(n)?;
            }
            Firing::capture(n)
        })?;
        if new.guard != self.current.guard {
            save_json(
                &n.root,
                &format!("full211-rollover-{}.json", new.guard),
                &json!({"before":self.current,"after":new,"guard_or_producer_mutations":false}),
            )?;
        }
        self.current = new;
        Ok(())
    }
}
pub(super) fn qualify(n: &mut Native) -> Result<Value> {
    let h = full211_peer::handoff();
    let (_, a) = full211_peer::original_owner(n)?;
    full211_peer::control().executable.artifact()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(a["boot_id"] == boot.trim(), "full211 boot changed");
    let first = Firing::capture(n)?;
    first.await_successor(n)?;
    let second = Firing::capture(n)?;
    ensure!(first.guard != second.guard, "full211 guard failed to roll");
    first.same_or_successor(&second)?;
    Ok(
        json!({"schema":"horizon-full211-live-guard-rollover-v1","boot_id":boot.trim(),"handoff":h,"guard_plan":full211_peer::control().guard_plan,"before":first,"after":second,"guard_or_producer_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const GID: &str = "e911b65425c544cdac15b1c6ad5e0a6a";
    const FLOOR: u64 = 3_908_104_436_088;
    fn sample() -> Value {
        serde_json::from_str(include_str!("fixtures/full211-guard-sample-v134.json")).unwrap()
    }
    fn firing(gid: &str, t: u64) -> Firing {
        Firing {
            guard: gid.into(),
            timer: "d".repeat(32),
            trigger: t,
            next: t + CADENCE,
            start: t + 200,
            end: t + 2_000_000,
            sample: Bound::new(format!("/sample-{gid}"), "e".repeat(64)),
            journal: Bound::new(format!("/journal-{gid}"), digest(gid.as_bytes())),
            lower_physical: 65_641_033_728,
            free: 4_352_129_073_152,
        }
    }
    #[test]
    fn v134_physical_growth_uses_lower_pass_and_free_with_original_floor() {
        let s = sample();
        let (used, free) = measurement(&s, FLOOR, GID).unwrap();
        assert_eq!((used, free), (65_641_033_728, 4_352_129_073_152));
        let mut row = capacity::Reservation {
            unit: UNIT.into(),
            invocation_id: full211_peer::IID.into(),
            maximum_memory_bytes: MEMORY,
            remaining_disk_growth_bytes: SCRATCH,
            minimum_free_bytes: FLOOR,
            release: None,
            source: full211_peer::handoff(),
        };
        let mut available = free + 1;
        let f = firing(GID, CADENCE);
        f.capacity(&mut row, &mut available).unwrap();
        assert_eq!(
            (
                row.remaining_disk_growth_bytes,
                row.minimum_free_bytes,
                row.maximum_memory_bytes,
                available
            ),
            (SCRATCH - used, FLOOR, MEMORY, free)
        );
        assert!(f.capacity(&mut row, &mut available).is_err());
        for (key, value) in [
            (
                "/root_physical_observation/second/vanished_entries",
                json!(1),
            ),
            ("/root_physical_observation/first/symlinks", json!(1)),
            (
                "/root_physical_observation/conservative_physical_bytes",
                json!(used),
            ),
            ("/root_physical_observation/exceeds_budget", json!(true)),
            ("/trip_reason", json!("disk floor")),
            ("/minimum_free_bytes", json!(0)),
            ("/producer/pid", json!(1)),
            ("/guard_invocation_id", json!("c".repeat(32))),
            ("/guard_sha256", json!("b".repeat(64))),
            ("/plan", json!("/other")),
            ("/available_bytes", json!(FLOOR - 1)),
        ] {
            let mut bad = s.clone();
            *bad.pointer_mut(key).unwrap() = value;
            assert!(measurement(&bad, FLOOR, GID).is_err(), "{key}");
        }
    }
    #[test]
    fn repeat_read_accepts_json_field_order_but_preserves_every_row_and_field() {
        let rows = br#"{"__CURSOR":"a","UNIT":"guard","__MONOTONIC_TIMESTAMP":"10"}
{"__CURSOR":"b","MESSAGE_ID":"finished"}"#;
        let reordered = br#"{"UNIT":"guard","__MONOTONIC_TIMESTAMP":"10","__CURSOR":"a"}
{"MESSAGE_ID":"finished","__CURSOR":"b"}"#;
        assert_ne!(digest(rows), digest(reordered));
        assert!(equal_journal_rows(rows, reordered).unwrap());
        let first = rows.split(|x| *x == b'\n').next().unwrap();
        assert!(!equal_journal_rows(rows, first).unwrap());
        let parsed = decode_journal(rows).unwrap();
        for bad in [
            vec![parsed[1].clone(), parsed[0].clone()],
            vec![parsed[0].clone(), parsed[1].clone(), parsed[1].clone()],
            vec![
                parsed[0].clone(),
                json!({"__CURSOR":"c","MESSAGE_ID":"finished"}),
            ],
            vec![
                parsed[0].clone(),
                json!({"__CURSOR":"b","MESSAGE_ID":"finished","new":"field"}),
            ],
        ] {
            let raw = bad
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(!equal_journal_rows(rows, raw.as_bytes()).unwrap());
        }
        assert!(equal_journal_rows(rows, b"incomplete").is_err());
    }

    #[test]
    fn capture_crossing_the_custody_reserve_requires_one_completed_successor() {
        let original = firing(GID, 364_880_555_906);
        let successor = firing(&"b".repeat(32), original.next + 500_000);
        let window = Window {
            current: original.clone(),
        };
        // v155 entered the repeat capture with over five seconds and finished with 4.844s.
        let mut times = [364_905_417_520, 364_905_711_521, successor.end + 1].into_iter();
        let mut waits = Vec::new();
        let selected = window
            .transition_firing(
                || Ok(times.next().unwrap()),
                |wait| {
                    waits.push(wait);
                    Ok(if wait {
                        successor.clone()
                    } else {
                        original.clone()
                    })
                },
            )
            .unwrap();
        assert_eq!(waits, [false, true]);
        assert_eq!(selected.guard, successor.guard);
        // A stale re-read or a second rollover cannot supply custody.
        for returned in [
            original.clone(),
            firing(&"c".repeat(32), successor.next + 500_000),
        ] {
            assert!(
                window
                    .transition_firing(|| Ok(original.next), |_| Ok(returned.clone()))
                    .is_err()
            );
        }
        let mut times = [original.next, successor.next - 5_000_000].into_iter();
        assert!(
            window
                .transition_firing(|| Ok(times.next().unwrap()), |_| Ok(successor.clone()))
                .is_err()
        );
    }

    #[test]
    fn original_or_one_adjacent_timer_firing_only() {
        let a = firing(GID, CADENCE);
        a.same_or_successor(&a).unwrap();
        let b = firing(&"b".repeat(32), a.next + 500_000);
        a.same_or_successor(&b).unwrap();
        for changed in [
            Firing {
                timer: "c".repeat(32),
                ..b.clone()
            },
            Firing {
                guard: a.guard.clone(),
                ..b.clone()
            },
            Firing {
                trigger: a.next - 1,
                ..b.clone()
            },
            Firing {
                trigger: a.next + CADENCE,
                ..b.clone()
            },
            Firing {
                sample: a.sample.clone(),
                ..b.clone()
            },
        ] {
            assert!(a.same_or_successor(&changed).is_err());
        }
    }
}
