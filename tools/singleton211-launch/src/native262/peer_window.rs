//! Keep the 262 startup inside an authenticated window of the unchanged live guards.
use super::*;
pub(super) use crate::peer_window::{
    deadline, guard_sample_ref, protected_owner, validate_guard_sample,
};

const SECOND: u64 = 1_000_000;
const GUARD_PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,Result,ExecMainStatus,ExecStart,Type,User,Restart,RemainAfterExit,RefuseManualStart,KillMode,Delegate,MemoryMax,MemorySwapMax,TriggeredBy,DropInPaths";
const TIMER_PROPERTIES: &str =
    "Id,LoadState,ActiveState,SubState,InvocationID,Unit,Job,DropInPaths,RandomizedDelayUSec";
const PRODUCER_PROPERTIES: &str = "Id,LoadState,MainPID,InvocationID,ControlGroup,ActiveState,SubState,NRestarts,Result,ExecStart,Job";

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Firing {
    guard: String,
    timer: String,
    next: u64,
    sample: Bound,
}

fn manager(n: &mut Native, peer: &Value) -> Result<(Value, Value)> {
    let guard = text(peer, "unit")?;
    let timer = text(peer, "timer")?;
    let producer = &peer["producer"];
    let current = n.show_fields(text(producer, "Id")?, PRODUCER_PROPERTIES)?;
    live::same_owner(producer, &current)?;
    ensure!(current["Job"] == "", "peer producer changed job");
    let service = n.show_fields(guard, GUARD_PROPERTIES)?;
    let timer_state = n.show_fields(timer, TIMER_PROPERTIES)?;
    ensure!(
        service["Id"] == guard
            && service["LoadState"] == "loaded"
            && service["Type"] == "oneshot"
            && service["User"] == "root"
            && service["Restart"] == "no"
            && service["RemainAfterExit"] == "no"
            && service["RefuseManualStart"] == "no"
            && service["KillMode"] == "control-group"
            && service["Delegate"] == "no"
            && service["MemoryMax"] == "1073741824"
            && service["MemorySwapMax"] == "0"
            && service["TriggeredBy"] == timer
            && service["DropInPaths"] == ""
            && service["Result"] == "success"
            && periodic::stable_command(text(&service, "ExecStart")?)?
                == text(peer, "guard_command")?
            && timer_state["Id"] == timer
            && timer_state["LoadState"] == "loaded"
            && timer_state["ActiveState"] == "active"
            && timer_state["Unit"] == guard
            && timer_state["Job"] == ""
            && timer_state["DropInPaths"] == ""
            && timer_state["RandomizedDelayUSec"] == "0"
            && timer_state["InvocationID"] == peer["timer_invocation_id"],
        "changed Foundation guard/timer configuration: {guard}"
    );
    Ok((service, timer_state))
}

fn firing(n: &mut Native, peer: &Value) -> Result<Firing> {
    let (service, timer) = manager(n, peer)?;
    let unit = text(peer, "unit")?;
    ensure!(
        service["ActiveState"] == "inactive"
            && service["SubState"] == "dead"
            && service["MainPID"] == "0"
            && service["ControlPID"] == "0"
            && service["ExecMainStatus"] == "0"
            && service["Job"] == ""
            && timer["SubState"] == "waiting",
        "Foundation guard is between start and successful completion: {unit}"
    );
    let gid = text(&service, "InvocationID")?;
    let tid = text(&timer, "InvocationID")?;
    ensure!(
        hex(gid, 32) && hex(tid, 32),
        "Foundation guard invocation is missing"
    );
    let plan_ref = binding(&peer["plan"])?;
    let plan = plan_ref.sealed()?;
    let exe = binding(&peer["executable"])?;
    let sample = crate::peer_window::guard_sample_ref(&plan, gid)?;
    let health = crate::peer_window::validate_guard_sample(&sample, &plan_ref, &exe, &plan, gid)?;
    let owner = &peer["producer"];
    ensure!(
        health["producer"]["pid"].as_u64() == Some(text(owner, "MainPID")?.parse()?)
            && health["producer"]["cgroup"] == owner["ControlGroup"],
        "Foundation firing bound to a different producer"
    );
    let next = deadline(n, text(peer, "timer")?)?;
    ensure!(
        (service.clone(), timer.clone()) == manager(n, peer)?,
        "Foundation guard fired during typed deadline read"
    );
    Ok(Firing {
        guard: gid.to_owned(),
        timer: tid.to_owned(),
        next,
        sample,
    })
}

fn pid1(n: &mut Native, peer: &Value, fire: &Firing, boot: &str) -> Result<Value> {
    let unit = text(peer, "unit")?;
    let raw = n.run(
        "/usr/bin/journalctl",
        &[
            "--all",
            "--no-pager",
            "--output=json",
            "--boot=0",
            "_PID=1",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={}", fire.guard),
        ],
    )?;
    let rows = serde_json::Deserializer::from_slice(&raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (_, end) = full211_window::guard_clocks(&rows, boot, unit, &fire.guard)?;
    ensure!(
        fire.next
            .checked_sub(end)
            .is_some_and(|duration| duration.abs_diff(60 * SECOND) <= SECOND),
        "Foundation firing interval changed: {unit}"
    );
    Ok(json!(rows))
}

fn timer_property(n: &mut Native, timer: &str, property: &str) -> Result<String> {
    let id: String = timer
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte).to_string()
            } else {
                format!("_{byte:02x}")
            }
        })
        .collect();
    Ok(String::from_utf8(n.run(
        "/usr/bin/busctl",
        &[
            "get-property",
            "org.freedesktop.systemd1",
            &format!("/org/freedesktop/systemd1/unit/{id}"),
            "org.freedesktop.systemd1.Timer",
            property,
        ],
    )?)?)
}

fn spent_initial_timer(value: &str, now: u64) -> Result<()> {
    let words: Vec<_> = value.split_whitespace().collect();
    ensure!(
        words.len() == 8 && words[..2] == ["a(stt)", "2"],
        "peer timer has an unqualified trigger set"
    );
    let mut entries = BTreeMap::new();
    for row in words[2..].chunks_exact(3) {
        ensure!(
            entries
                .insert(row[0], (row[1].parse::<u64>()?, row[2].parse::<u64>()?))
                .is_none(),
            "duplicate peer timer trigger"
        );
    }
    ensure!(
        entries
            .get("\"OnActiveUSec\"")
            .is_some_and(|&(interval, due)| interval == SECOND && due > 0 && due < now)
            && entries
                .get("\"OnUnitInactiveUSec\"")
                .is_some_and(|&(interval, _)| interval == 60 * SECOND),
        "peer timer is not operating on its one-minute post-exit cadence"
    );
    Ok(())
}

fn synchronize_once(
    n: &mut Native,
    controls: &serde_json::Map<String, Value>,
) -> Result<BTreeMap<String, Value>> {
    let mut before = BTreeMap::new();
    let mut args = vec!["start"];
    for peer in controls.values() {
        let (service, _) = manager(n, peer)?;
        let timer = text(peer, "timer")?;
        spent_initial_timer(&timer_property(n, timer, "TimersMonotonic")?, mono()?)?;
        ensure!(
            timer_property(n, timer, "TimersCalendar")?.trim() == "a(sst) 0",
            "unexpected peer timer calendar"
        );
        let unit = text(peer, "unit")?;
        ensure!(
            before.insert(unit.to_owned(), service).is_none(),
            "duplicate eligible peer guard"
        );
        args.push(unit);
    }
    n.run("/usr/bin/systemctl", &args)?;
    Ok(before)
}

pub(super) struct Window {
    peers: Vec<(Value, Firing)>,
    pub limit: u64,
    pub receipt: Bound,
}

impl Window {
    pub(super) fn verify(&mut self, n: &mut Native) -> Result<()> {
        for (peer, fire) in &self.peers {
            ensure!(
                firing(n, peer)? == *fire,
                "Foundation peer guard crossed its original deadline"
            );
        }
        ensure!(mono()? < self.limit, "Foundation peer window elapsed");
        n.check()
    }
}

pub(super) fn select_minimum(
    n: &mut Native,
    review: &Value,
    context: &Value,
    minimum: u64,
) -> Result<Window> {
    let roster_ref = binding(&context["foundation_roster"])?;
    let roster = roster_ref.json()?;
    ensure!(
        roster["fleet"] == review["fleet"] && roster["observer"] == review["observer"],
        "Foundation peer window must use the current review cohort"
    );
    let controls = roster["periodic_guards"]
        .as_object()
        .context("Foundation protective guards")?;
    ensure!(
        controls.len() == 5,
        "incomplete epoch 262 peer guard coverage"
    );
    let prior = if review["synchronize_peer_guards"] == true {
        Some(synchronize_once(n, controls)?)
    } else {
        None
    };
    let boot = text(review, "boot_id")?;
    let mut limit = n.deadline.context("epoch 262 operator deadline")?;
    let mut peers = Vec::new();
    let mut evidence = Vec::new();
    for peer in controls.values() {
        let fire = firing(n, peer)?;
        if let Some(prior) = &prior {
            let previous = prior
                .get(text(peer, "unit")?)
                .context("missing earlier guard state")?;
            ensure!(
                previous["ActiveState"] == "activating" || previous["InvocationID"] != fire.guard,
                "requested peer guard did not complete a new or already running firing"
            );
        }
        let journal = pid1(n, peer, &fire, boot)?;
        limit = limit.min(
            fire.next
                .checked_sub(5 * SECOND)
                .context("peer deadline underflow")?,
        );
        evidence.push(json!({"guard":peer,"firing":fire,"pid1":journal}));
        peers.push((peer.clone(), fire));
    }
    let remaining = limit.saturating_sub(mono()?);
    ensure!(
        remaining >= minimum,
        "Foundation guards leave {} ms of shared startup time. Required {} ms",
        remaining / 1000,
        minimum / 1000
    );
    let receipt = save_json(
        &n.root,
        "peer-window.json",
        &json!({
        "schema":"horizon-singleton211-original-peer-window-v1","review":context["review"],
        "boot_id":boot,"roster":roster_ref,"peers":evidence,"synchronization_before":prior,
        "deadline_with_margin_monotonic_us":limit,"recorded_monotonic_us":mono()?}),
    )?;
    let mut window = Window {
        peers,
        limit,
        receipt,
    };
    window.verify(n)?;
    Ok(window)
}

pub(super) fn capture(n: &mut Native, review: &Value, context: &Value) -> Result<Window> {
    // The profiled Foundation census is roughly ten seconds. Preserve time for two
    // pre-activation censuses, the held census and the candidate's first firing.
    select_minimum(n, review, context, 40 * SECOND)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synchronization_requires_a_spent_initial_timer_and_unchanged_recurring_trigger() {
        let triggers =
            r#"a(stt) 2 "OnUnitInactiveUSec" 60000000 140000000 "OnActiveUSec" 1000000 1100000"#;
        spent_initial_timer(triggers, 100 * SECOND).unwrap();
        assert!(spent_initial_timer(triggers, SECOND).is_err());
        assert!(
            spent_initial_timer(&triggers.replace("60000000", "30000000"), 100 * SECOND).is_err()
        );
        assert!(
            spent_initial_timer(
                &triggers.replace("OnActiveUSec", "OnUnitInactiveUSec"),
                100 * SECOND
            )
            .is_err()
        );
    }
}
