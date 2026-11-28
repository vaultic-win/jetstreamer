//! Follow the original 20-second guard while bringing up the epoch 261 peer.
use super::*;

const TIMER_SHA: &str = "eea62e3d044307f9efa75d5b13878dbb5ec9812faa1e43c5c6762ce12b0447ba";
const SERVICE_SHA: &str = "a55192180b402706aeab2515828ac970661504092d80dc3b47b57d3d88f95d94";
const START: &str = "7d4958e842da4a758f6c1cdc7b36dcc5";
const END: &str = "7ad2d189f7e94e70a38c781354912448";

#[derive(Clone, PartialEq, Serialize)]
pub(crate) struct Firing {
    iid: String,
    start: u64,
    end: u64,
    cursor: String,
    sample: Bound,
}

impl Firing {
    fn adjacent(&self, next: &Self) -> Result<()> {
        let interval = next
            .start
            .checked_sub(self.end)
            .context("reversed peer firing")?;
        ensure!(
            self.iid != next.iid && (19_900_000..=21_500_000).contains(&interval),
            "missing or late 266 protective guard"
        );
        Ok(())
    }
}

pub(crate) fn handoff() -> Bound {
    Bound::new(
        Path::new(turnover::STATE).join("pilot/handoff.json"),
        "fcab517e7281c8c1dde68c9e7f56cbabc294eff2154c181bdb72b1742170a4df",
    )
}

fn rows_since(n: &mut Native, p: &Profile, h: &Value, stop: &str) -> Result<Vec<Firing>> {
    let boot = BOOT.replace('-', "");
    let raw = n.run(
        "/usr/bin/journalctl",
        &[
            "--boot",
            &boot,
            "--quiet",
            "--no-pager",
            "-n",
            "12",
            "-o",
            "json",
            "_UID=0",
            "_PID=1",
            &format!("UNIT={}", p.guard),
            &format!("MESSAGE_ID={START}"),
            &format!("MESSAGE_ID={END}"),
        ],
    )?;
    let history = serde_json::Deserializer::from_slice(&raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    // Trim only the leading, unpaired completion and any later firing which
    // began during this bracket. The PID 1 end must belong to the loaded unit.
    let first = history
        .iter()
        .position(|e| e["MESSAGE_ID"] == START)
        .context("no peer start")?;
    let last = history
        .iter()
        .rposition(|e| e["MESSAGE_ID"] == END && e["INVOCATION_ID"] == stop)
        .context("missing loaded guard completion")?;
    ensure!(
        last > first && (last - first + 1) % 2 == 0,
        "incomplete guard history"
    );
    let g = binding(&h["guard"])?;
    let plan = g.sealed()?;
    let mut firings: Vec<Firing> = Vec::new();
    for pair in history[first..=last].chunks_exact(2) {
        let a = &pair[0];
        let b = &pair[1];
        let iid = text(a, "INVOCATION_ID")?;
        ensure!(
            hex(iid, 32)
                && a["MESSAGE_ID"] == START
                && b["MESSAGE_ID"] == END
                && b["INVOCATION_ID"] == iid
                && pair.iter().all(|v| v["_BOOT_ID"] == boot
                    && v["_UID"] == "0"
                    && v["_PID"] == "1"
                    && v["UNIT"] == p.guard
                    && v.get("UNIT_RESULT").is_none_or(|r| r == "success")),
            "different peer guard journal"
        );
        let sample = bound_at(&p.state.join("receipts").join(format!("sample-{iid}.json")))?;
        let v = sample.json()?;
        start::validate_sample_for(
            GUARD_SHA,
            &v,
            &p.unit,
            text(h, "iid")?,
            num(h, "pid")?,
            &g,
            None,
        )?;
        ensure!(
            v["guard_invocation_id"] == iid
                && v["minimum_free_bytes"] == plan["minimum_free_bytes"]
                && v["worker_observation_error"].is_null()
                && v["root_physical_observation_error"].is_null(),
            "unhealthy 266 protective sample"
        );
        let row = Firing {
            iid: iid.into(),
            start: text(a, "__MONOTONIC_TIMESTAMP")?.parse()?,
            end: text(b, "__MONOTONIC_TIMESTAMP")?.parse()?,
            cursor: text(b, "__CURSOR")?.into(),
            sample,
        };
        ensure!(row.start < row.end, "invalid 266 guard clocks");
        if let Some(prev) = firings.last() {
            prev.adjacent(&row)?;
        }
        firings.push(row);
    }
    Ok(firings)
}

pub(crate) struct Window {
    pub(crate) current: Firing,
}

impl Window {
    fn capture(n: &mut Native, prior: Option<&Firing>) -> Result<Firing> {
        original_boot()?;
        let p = Profile::new(Lane::Turnover266, "pilot")?;
        let h = handoff().sealed()?;
        let owner = n.show(&p.unit)?;
        live::finite_owner(&owner, &p.unit, text(&h, "iid")?, successor::MEMORY)?;
        ensure!(
            text(&owner, "MainPID")?.parse::<u64>()? == num(&h, "pid")?,
            "changed 266 PID"
        );
        let timer_file = Bound::new(p.state.join(&p.timer), TIMER_SHA);
        let guard_file = Bound::new(p.state.join(&p.guard), SERVICE_SHA);
        timer_file.artifact()?;
        guard_file.artifact()?;
        let stop_at = mono()?.checked_add(32_000_000).context("peer deadline")?;
        loop {
            n.check()?;
            ensure!(mono()? < stop_at, "no healthy 266 guard window");
            for marker in [
                "stop-intent.json",
                "pressure-stop.json",
                "manager-stop-completion.json",
            ] {
                ensure!(
                    !p.state.join("receipts").join(marker).try_exists()?,
                    "266 stop pending"
                );
            }
            let timer = n.show(&p.timer)?;
            let guard = n.show(&p.guard)?;
            ensure!(
                timer["InvocationID"] == h["timer"]
                    && timer["ActiveState"] == "active"
                    && timer["Unit"] == p.guard
                    && timer["Job"] == ""
                    && timer["DropInPaths"] == ""
                    && guard["DropInPaths"] == ""
                    && fs::canonicalize(text(&timer, "FragmentPath")?)? == timer_file.path
                    && fs::canonicalize(text(&guard, "FragmentPath")?)? == guard_file.path,
                "266 guard units changed"
            );
            ensure!(
                guard["Result"] == "success"
                    && matches!(
                        guard["ActiveState"].as_str(),
                        Some("inactive" | "activating")
                    ),
                "266 guard unhealthy"
            );
            if guard["ActiveState"] == "inactive"
                && guard["SubState"] == "dead"
                && guard["ExecMainStatus"] == "0"
                && timer["SubState"] == "waiting"
            {
                let gid = text(&guard, "InvocationID")?;
                let rows = rows_since(n, &p, &h, gid)?;
                let latest = rows.last().context("no completed guard firing")?;
                if let Some(old) = prior {
                    ensure!(
                        rows.contains(old),
                        "original guard no longer in continuous history"
                    );
                }
                let next = peer_window::deadline(n, &p.timer)?;
                let current = n.show(&p.guard)?;
                let after = n.show(&p.timer)?;
                live::same_owner(&owner, &n.show(&p.unit)?)?;
                ensure!(
                    after["InvocationID"] == timer["InvocationID"]
                        && after["ActiveState"] == "active"
                        && after["Job"] == "",
                    "266 timer replaced"
                );
                if current["InvocationID"] == gid
                    && current["ActiveState"] == "inactive"
                    && after["SubState"] == "waiting"
                {
                    ensure!(
                        next.abs_diff(
                            latest
                                .end
                                .checked_add(20_000_000)
                                .context("266 timer overflow")?
                        ) <= 1_000_000,
                        "266 protective timer deadline changed"
                    );
                    if mono()?
                        .checked_add(5_000_000)
                        .is_some_and(|clock| clock < next)
                    {
                        return Ok(latest.clone());
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    pub(crate) fn open(n: &mut Native) -> Result<Self> {
        Ok(Self {
            current: Self::capture(n, None)?,
        })
    }
    pub(crate) fn verify(&mut self, n: &mut Native) -> Result<()> {
        let new = Self::capture(n, Some(&self.current))?;
        if new != self.current {
            save_json(
                &n.root,
                &format!("turnover266-rollover-{}.json", new.iid),
                &json!({"previous":self.current,"next":new,"handoff":handoff()}),
            )?;
            self.current = new;
        }
        Ok(())
    }
}

pub(super) fn qualify(n: &mut Native) -> Result<Value> {
    let registered = Bound::new(
        "/home/ubuntu/.codex/diagnostics/horizon261-live266-peer-cadence-v195-a1/qualification.json",
        "ea92d211328dbc429aae96bb7fc740aa70128923f58a9f3b699431e00eff9ae5",
    );
    let basis = registered.json()?;
    ensure!(
        basis["handoff"] == json!(handoff()) && basis["timer"]["sha256"] == TIMER_SHA,
        "266 cadence origin"
    );
    let mut window = Window::open(n)?;
    let before = window.current.clone();
    let wake = before.end.checked_add(20_000_000).context("peer due")?;
    std::thread::sleep(Duration::from_micros(wake.saturating_sub(mono()?)));
    window.verify(n)?;
    before.adjacent(&window.current)?;
    Ok(
        json!({"schema":"horizon261-live266-peer-window-v1","basis":registered,"handoff":handoff(),
        "before":before,"after":window.current,"replay_launch_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_must_follow_the_last_completed_invocation() {
        let a = Firing {
            iid: "a".into(),
            start: 1,
            end: 2_000_000,
            cursor: "one".into(),
            sample: Bound::new("/a", "a".repeat(64)),
        };
        let mut b = Firing {
            iid: "b".into(),
            start: 22_100_000,
            end: 23_000_000,
            ..a.clone()
        };
        a.adjacent(&b).unwrap();
        b.iid = a.iid.clone();
        assert!(a.adjacent(&b).is_err());
        b.iid = "b".into();
        b.start += 22_000_000;
        assert!(a.adjacent(&b).is_err());
        b.start = a.end - 1;
        assert!(a.adjacent(&b).is_err());
    }
}
