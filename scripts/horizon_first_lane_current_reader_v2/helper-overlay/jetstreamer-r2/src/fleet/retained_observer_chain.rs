//! Bounded ancestry proof for retained monitoring after a missing fleet cycle.
//! Real observer gaps remain gaps. No source creates a sample, fleet, admission or clock.
use super::cached145_terminal_observer as terminal;
use super::{BoundFile, Plan, bound_json, cached145, utc_seconds};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
// Finite multi-day recovery; every link remains hash/identity/cadence checked.
const MAXIMUM_LINKS: usize = 128;
#[derive(Clone)]
pub(in crate::fleet) struct Scope {
    anchor: BoundFile,
    anchor_seconds: u64,
    current: BoundFile,
    unit: String,
    iid: String,
    pid: u64,
    work: PathBuf,
    predecessor: Value,
    terminal: Option<terminal::Witness>,
}
#[derive(Clone)]
pub(in crate::fleet) struct Proof {
    scope: Scope,
    samples: Vec<(BoundFile, Value)>,
}
fn bound(b: &BoundFile) -> Result<()> {
    ensure!(
        b.path.is_absolute()
            && b.sha256.len() == 64
            && b.sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "observer chain binding path or digest invalid"
    );
    Ok(())
}
fn clock(v: &Value) -> Result<u64> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "observer chain requires complete v2 sample"
    );
    utc_seconds(
        v["recorded_at_utc"]
            .as_str()
            .context("observer chain timestamp")?,
    )
}
fn prior(v: &Value) -> Result<BoundFile> {
    Ok(serde_json::from_value(
        json!({"path":v["cadence"]["previous_sample"],"sha256":v["cadence"]["previous_sample_sha256"]}),
    )?)
}
fn owner(v: &Value, s: &Scope) -> Result<()> {
    let rows = v["diagnostic_replays"]
        .as_array()
        .context("observer chain complete diagnostic census")?;
    let selected = rows
        .iter()
        .filter(|r| r["producer_unit"] == s.unit)
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "observer chain cached145 owner absent or duplicated"
    );
    let r = selected[0];
    ensure!(
        r["status"] == "observed"
            && r["range"] == "145"
            && r["scratch_path"] == serde_json::to_value(&s.work)?
            && r["expected_producer_invocation_id"] == s.iid
            && r["observation"]["invocation_binding_stable"] == true,
        "observer chain cached145 claim crosses admitted identity"
    );
    for role in ["producer", "controller"] {
        for end in ["before", "after"] {
            let n = &r["observation"][format!("{role}_{end}")];
            ensure!(
                n["unit"] == s.unit
                    && n["invocation_id"] == s.iid
                    && n["main_pid"] == s.pid
                    && n["control_group"] == format!("/system.slice/{}", s.unit)
                    && n["active_state"] == "active"
                    && n["sub_state"] == "running"
                    && n["restarts"] == 0,
                "observer chain changes cached145 invocation, PID or healthy sampled owner"
            );
        }
    }
    Ok(())
}
pub(in crate::fleet) fn scope(plan: &Plan, previous: &Value) -> Result<Scope> {
    scope_selected(plan, previous, None)
}
pub(in crate::fleet) fn scope_terminal(
    plan: &Plan,
    previous: &Value,
    terminal: terminal::Witness,
) -> Result<Scope> {
    scope_selected(plan, previous, Some(terminal))
}
fn scope_selected(
    plan: &Plan,
    previous: &Value,
    terminal: Option<terminal::Witness>,
) -> Result<Scope> {
    ensure!(
        plan.admission_transition_guard.is_none(),
        "observer recovery cannot enroll or admit an actor"
    );
    let claims = plan
        .diagnostics
        .iter()
        .filter(|c| cached145::namespace(c))
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "observer recovery requires exact existing cached145 owner"
    );
    let c = claims[0];
    let n = &previous["unit_census"][&c.unit];
    let pid = if n["InvocationID"] == c.invocation_id
        && n["ActiveState"] == "active"
        && n["SubState"] == "running"
        && n["NRestarts"] == "0"
    {
        let pid = n["MainPID"]
            .as_str()
            .context("prior cached145 original PID")?
            .parse::<u64>()?;
        ensure!(pid > 1, "prior cached145 original PID absent");
        pid
    } else {
        terminal
            .as_ref()
            .context(
                "observer recovery lacks prior accepted healthy owner or typed original terminal",
            )?
            .predecessor(previous, &utc_seconds)?;
        terminal::PID
    };
    if terminal.is_some() {
        ensure!(
            c.unit == terminal::UNIT
                && c.invocation_id == terminal::IID
                && c.scratch_path.as_path() == std::path::Path::new(terminal::WORK)
                && pid == terminal::PID,
            "terminal observer recovery cannot replace original admitted scope"
        );
    }
    let anchor = serde_json::from_value(
        json!({"path":previous["observer_receipt"],"sha256":previous["observer_sha256"]}),
    )?;
    Ok(Scope {
        anchor,
        anchor_seconds: utc_seconds(
            previous["sampled_at_utc"]
                .as_str()
                .context("prior accepted fleet sample")?,
        )?,
        current: plan.observer.clone(),
        unit: c.unit.clone(),
        iid: c.invocation_id.clone(),
        pid,
        work: c.scratch_path.clone(),
        predecessor: previous.clone(),
        terminal,
    })
}
fn owner_phase(v: &Value, s: &Scope, current: Option<&Value>) -> Result<u8> {
    let Some(witness) = &s.terminal else {
        owner(v, s)?;
        return Ok(0);
    };
    let rows = v["diagnostic_replays"]
        .as_array()
        .context("terminal ancestry diagnostics")?;
    let selected = rows
        .iter()
        .filter(|r| r["producer_unit"] == s.unit)
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "terminal ancestry original diagnostic absent or duplicated"
    );
    if selected[0]["status"] == "observed" {
        witness.healthy(v, &utc_seconds)?;
        owner(v, s)?;
        return Ok(0);
    }
    let identity = terminal::Identity {
        unit: &s.unit,
        iid: &s.iid,
        pid: s.pid,
        work: s.work.to_str().context("terminal ancestry work UTF8")?,
    };
    let has_gap = ["before", "after"]
        .into_iter()
        .any(|end| v["host_resident_memory"][end]["status"] == "unavailable");
    let phase = if let Some(current) = current.filter(|_| has_gap) {
        witness.historical_unavailable(&identity, v, current, &s.predecessor, &utc_seconds)?
    } else {
        witness.unavailable(&identity, v, &utc_seconds)?
    };
    Ok(match phase {
        terminal::Phase::ParentVerification => 1,
        terminal::Phase::OriginalCompleted => 2,
    })
}
/// Reader must enforce the exact bound file's custody, size, stable identity and raw-byte SHA.
/// Production passes the existing bound_json reader; tests inject explicit complete receipts.
pub(in crate::fleet) fn prove(
    s: &Scope,
    now: u64,
    mut read: impl FnMut(&BoundFile) -> Result<Value>,
) -> Result<Proof> {
    bound(&s.anchor)?;
    bound(&s.current)?;
    ensure!(
        s.anchor != s.current,
        "observer recovery cannot reuse anchor as current sample"
    );
    let mut next = s.current.clone();
    let mut samples: Vec<(BoundFile, Value)> = Vec::new();
    let mut paths = BTreeSet::new();
    let mut later_phase = None;
    loop {
        ensure!(
            samples.len() < MAXIMUM_LINKS && paths.insert(next.path.clone()),
            "observer recovery depth exceeded or cyclic path"
        );
        bound(&next)?;
        let v = read(&next)?;
        let at = clock(&v)?;
        let phase = owner_phase(&v, s, samples.first().map(|(_, current)| current))?;
        if let Some(later) = later_phase {
            ensure!(
                phase <= later,
                "observer ancestry phase regressed or revived original parent"
            );
        }
        later_phase = Some(phase);
        if samples.is_empty() {
            ensure!(
                at <= now && now - at <= 1800,
                "observer recovery current sample is stale or future"
            );
        }
        let p = prior(&v)?;
        bound(&p)?;
        ensure!(
            v["cadence"]["routine_minimum_interval_enforced"] == true
                && v["cadence"]["minimum_interval_seconds"] == 1800
                && v["cadence"]["observed_interval_seconds"]
                    .as_u64()
                    .is_some_and(|n| n >= 1800),
            "observer recovery cannot use a status-only, unbounded or non-routine sample"
        );
        if let Some((_, later)) = samples.last() {
            let elapsed = clock(later)?
                .checked_sub(at)
                .context("observer chain time reversed")?;
            ensure!(
                elapsed >= 1800 && later["cadence"]["observed_interval_seconds"] == elapsed,
                "observer chain elapsed interval differs from real receipts"
            );
        }
        samples.push((next, v));
        if p == s.anchor {
            let oldest = &samples.last().context("observer recovery oldest sample")?.1;
            let elapsed = clock(oldest)?
                .checked_sub(s.anchor_seconds)
                .context("observer chain predates accepted fleet")?;
            ensure!(
                elapsed >= 1800 && oldest["cadence"]["observed_interval_seconds"] == elapsed,
                "observer chain fails exact accepted anchor interval"
            );
            break;
        }
        ensure!(
            p.path != s.anchor.path,
            "observer recovery crosses anchor digest"
        );
        next = p;
    }
    Ok(Proof {
        scope: s.clone(),
        samples,
    })
}
pub(in crate::fleet) fn recovery(
    plan: &Plan,
    previous: &Value,
    sample: &str,
) -> Result<Option<Proof>> {
    let current = bound_json(&plan.observer)?;
    let anchor: BoundFile = serde_json::from_value(
        json!({"path":previous["observer_receipt"],"sha256":previous["observer_sha256"]}),
    )?;
    let old = utc_seconds(
        previous["sampled_at_utc"]
            .as_str()
            .context("recovery predecessor UTC")?,
    )?;
    let terminal_selected = current["diagnostic_replays"]
        .as_array()
        .is_some_and(|rows| {
            rows.iter()
                .any(|r| r["producer_unit"] == terminal::UNIT && r["status"] == "unavailable")
        });
    if !terminal_selected
        && prior(&current)? == anchor
        && utc_seconds(sample)?
            == old
                .checked_add(1800)
                .context("observer direct clock overflow")?
    {
        return Ok(None);
    }
    let s = if terminal_selected {
        let witness = terminal::Witness::load(
            |source| {
                bound_json(&BoundFile {
                    path: source.path.into(),
                    sha256: source.sha256.into(),
                })
            },
            &utc_seconds,
        )?;
        scope_terminal(plan, previous, witness)?
    } else {
        scope(plan, previous)?
    };
    let proof = prove(
        &s,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        bound_json,
    )?;
    ensure!(
        clock(&proof.samples[0].1)? == utc_seconds(sample)?,
        "recovery route sample differs from current observer"
    );
    Ok(Some(proof))
}
impl Proof {
    pub(in crate::fleet) fn revalidate(&self) -> Result<()> {
        let again = prove(
            &self.scope,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            bound_json,
        )?;
        ensure!(
            again.samples == self.samples,
            "observer recovery complete source chain changed"
        );
        Ok(())
    }
    pub(in crate::fleet) fn intermediates(&self) -> Vec<BoundFile> {
        self.samples
            .iter()
            .skip(1)
            .rev()
            .map(|(b, _)| b.clone())
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    fn b(name: &str) -> BoundFile {
        serde_json::from_value(json!({"path":format!("/test/{name}"),"sha256":"a".repeat(64)}))
            .unwrap()
    }
    fn fixture() -> (Scope, BTreeMap<PathBuf, Value>, u64) {
        let anchor = utc_seconds("2026-11-02T07:18:00Z").unwrap();
        let current = utc_seconds("2026-11-02T13:28:00Z").unwrap();
        let s = Scope {
            anchor: b("0718"),
            anchor_seconds: anchor,
            current: b("1328"),
            unit: "cached145.service".into(),
            iid: "1".repeat(32),
            pid: 123,
            work: "/test/work145".into(),
            predecessor: Value::Null,
            terminal: None,
        };
        let point = json!({"unit":s.unit,"invocation_id":s.iid,"main_pid":123,"control_group":"/system.slice/cached145.service","active_state":"active","sub_state":"running","restarts":0});
        let row = json!({"producer_unit":s.unit,"expected_producer_invocation_id":s.iid,"range":"145","scratch_path":s.work,"status":"observed","observation":{"invocation_binding_stable":true,"producer_before":point,"producer_after":point,"controller_before":point,"controller_after":point}});
        let sample = |time: &str, prev: BoundFile, elapsed: u64| json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":time,"cadence":{"previous_sample":prev.path,"previous_sample_sha256":prev.sha256,"routine_minimum_interval_enforced":true,"minimum_interval_seconds":1800,"observed_interval_seconds":elapsed},"diagnostic_replays":[row]});
        (
            s,
            BTreeMap::from([
                (
                    b("0748").path,
                    sample("2026-11-02T07:48:00Z", b("0718"), 1800),
                ),
                (
                    b("1328").path,
                    sample("2026-11-02T13:28:00Z", b("0748"), 20400),
                ),
            ]),
            current + 60,
        )
    }
    #[test]
    fn real_long_gap_keeps_all_actual_samples_and_exact_elapsed_times() {
        let (s, m, now) = fixture();
        let p = prove(&s, now, |b| {
            m.get(&b.path).cloned().context("missing receipt")
        })
        .unwrap();
        assert_eq!(p.intermediates(), [b("0748")]);
        assert_eq!(
            p.samples[0].1["cadence"]["observed_interval_seconds"],
            20400
        );
    }
    #[test]
    fn stale_current_missing_intermediate_crossed_hash_cycle_and_false_elapsed_reject() {
        let (s, m, now) = fixture();
        assert!(
            prove(&s, now + 1801, |b| m
                .get(&b.path)
                .cloned()
                .context("missing"))
            .is_err()
        );
        for mode in 0..4 {
            let mut bad = m.clone();
            match mode {
                0 => {
                    bad.remove(&b("0748").path);
                }
                1 => {
                    bad.get_mut(&b("0748").path).unwrap()["cadence"]["previous_sample_sha256"] =
                        json!("b".repeat(64))
                }
                2 => {
                    bad.get_mut(&b("0748").path).unwrap()["cadence"]["previous_sample"] =
                        json!("/test/1328")
                }
                _ => {
                    bad.get_mut(&b("1328").path).unwrap()["cadence"]["observed_interval_seconds"] =
                        json!(1800)
                }
            }
            assert!(
                prove(&s, now, |b| bad.get(&b.path).cloned().context("missing")).is_err(),
                "mode {mode}"
            );
        }
    }
    #[test]
    fn changed_owner_or_nonroutine_point_cannot_bridge() {
        for field in ["iid", "pid", "cadence"] {
            let (s, mut m, now) = fixture();
            let v = m.get_mut(&b("0748").path).unwrap();
            match field {
                "iid" => {
                    v["diagnostic_replays"][0]["observation"]["producer_after"]["invocation_id"] =
                        json!("2".repeat(32))
                }
                "pid" => {
                    v["diagnostic_replays"][0]["observation"]["controller_before"]["main_pid"] =
                        json!(456)
                }
                _ => v["cadence"]["routine_minimum_interval_enforced"] = json!(false),
            }
            assert!(
                prove(&s, now, |b| m.get(&b.path).cloned().context("missing")).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn chain_bound_is_exact_and_future_current_is_rejected() {
        let (s, m, now) = fixture();
        assert!(prove(&s, now - 61, |b| m.get(&b.path).cloned().context("missing")).is_err());
        for count in [24usize, 128usize, 129usize] {
            let (mut s, m, _) = fixture();
            let template = m.get(&b("1328").path).unwrap().clone();
            let mut map = BTreeMap::new();
            for i in 1..=count {
                let current = b(&format!("step-{i}"));
                let previous = if i == 1 {
                    s.anchor.clone()
                } else {
                    b(&format!("step-{}", i - 1))
                };
                let at = s.anchor_seconds + (i as u64) * 1800;
                let mut v = template.clone();
                v["recorded_at_utc"] = json!(format!(
                    "2026-11-{:02}T{:02}:{:02}:{:02}Z",
                    2 + (at / 86400 - s.anchor_seconds / 86400),
                    (at % 86400) / 3600,
                    (at % 3600) / 60,
                    at % 60
                ));
                v["cadence"]["previous_sample"] = json!(previous.path);
                v["cadence"]["previous_sample_sha256"] = json!(previous.sha256);
                v["cadence"]["observed_interval_seconds"] = json!(1800);
                map.insert(current.path, v);
            }
            s.current = b(&format!("step-{count}"));
            let result = prove(&s, s.anchor_seconds + (count as u64) * 1800 + 10, |b| {
                map.get(&b.path).cloned().context("missing")
            });
            assert_eq!(result.is_ok(), count <= MAXIMUM_LINKS);
        }
    }
}

#[cfg(test)]
#[path = "retained_observer_chain_terminal_tests.rs"]
mod terminal_ancestry_tests;
