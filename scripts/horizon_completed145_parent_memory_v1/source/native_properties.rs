//! Exact native property representation for the retained original 199 timer.
//! Timer schedules and dependency sets use the already-qualified Frame representation.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeSet;
const TIMER: &str = "jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.timer";
fn timer_base(value: &str) -> Option<&str> {
    let value = value.strip_prefix("{ ")?.strip_suffix(" }")?;
    let (base, due) = value.split_once(" ; next_elapse=")?;
    (matches!(base, "OnActiveUSec=1s" | "OnUnitActiveUSec=30s")
        && !due.is_empty()
        && due.len() <= 256
        && !due.chars().any(|c| c.is_control() || "{};".contains(c)))
    .then_some(base)
}
pub(super) fn parse(name: &str, raw: &str, requested: &str) -> Result<Value> {
    let mut row = serde_json::Map::new();
    for line in raw.lines() {
        let (key, value) = line.split_once('=').context("native framing")?;
        ensure!(
            requested.split(',').any(|v| v == key),
            "unexpected native property"
        );
        if name == TIMER && key == "TimersMonotonic" {
            let base = timer_base(value).context("invalid original199 timer vector entry")?;
            let field = row.entry(key.to_owned()).or_insert_with(|| json!(""));
            let old = field
                .as_str()
                .context("original199 timer vector is not text")?;
            ensure!(
                !old.lines().any(|v| timer_base(v) == Some(base)),
                "duplicate original199 timer base"
            );
            let mut entries = old
                .lines()
                .chain(std::iter::once(value))
                .collect::<Vec<_>>();
            ensure!(entries.len() <= 2, "original199 timer has extra schedules");
            entries.sort();
            *field = json!(entries.join("\n"));
        } else {
            ensure!(
                row.insert(key.into(), json!(value)).is_none(),
                "duplicate native field"
            );
        }
    }
    ensure!(
        row.get("Id") == Some(&json!(name)),
        "native identity crossed"
    );
    if name == TIMER {
        for key in ["After", "Conflicts", "OnFailure", "Triggers", "TriggeredBy"] {
            if let Some(value) = row.get_mut(key) {
                let raw = value
                    .as_str()
                    .context("original199 dependency set is not text")?;
                let words = raw.split_whitespace().collect::<Vec<_>>();
                let sorted = words.iter().copied().collect::<BTreeSet<_>>();
                ensure!(
                    words.len() == sorted.len(),
                    "duplicate original199 dependency member"
                );
                *value = json!(sorted.into_iter().collect::<Vec<_>>().join(" "));
            }
        }
    }
    Ok(Value::Object(row))
}
#[cfg(test)]
mod tests {
    use super::*;
    const KEYS: &str = "Id,MainPID,TimersMonotonic,After,Conflicts,OnFailure,Triggers,TriggeredBy";
    fn timer(tail: &str) -> Result<Value> {
        parse(TIMER, &format!("Id={TIMER}\n{tail}"), KEYS)
    }
    #[test]
    fn authentic_two_schedule_reproduction_preserves_every_value() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../fixtures/actual-parent-timer-duplicate-reproduction.json"
        ))
        .unwrap();
        let raw = fixture["raw_stdout"].as_str().unwrap();
        let fields = fixture["fields"].as_str().unwrap();
        let actual = parse(TIMER, raw, fields).unwrap();
        let mut schedules = raw
            .lines()
            .filter_map(|v| v.strip_prefix("TimersMonotonic="))
            .collect::<Vec<_>>();
        schedules.sort();
        assert_eq!(actual["TimersMonotonic"], schedules.join("\n"));
        assert_eq!(
            actual["TimersMonotonic"].as_str().unwrap().lines().count(),
            2
        );
        for line in raw.lines() {
            let (key, value) = line.split_once('=').unwrap();
            if ![
                "TimersMonotonic",
                "After",
                "Conflicts",
                "OnFailure",
                "Triggers",
                "TriggeredBy",
            ]
            .contains(&key)
            {
                assert_eq!(actual[key], value, "{key}");
            }
        }
    }
    #[test]
    fn schedule_order_is_canonical_and_due_values_are_preserved() {
        let a = "TimersMonotonic={ OnUnitActiveUSec=30s ; next_elapse=2min }\nTimersMonotonic={ OnActiveUSec=1s ; next_elapse=1s }\n";
        let b = "TimersMonotonic={ OnActiveUSec=1s ; next_elapse=1s }\nTimersMonotonic={ OnUnitActiveUSec=30s ; next_elapse=2min }\n";
        assert_eq!(timer(a).unwrap(), timer(b).unwrap());
        assert_ne!(
            timer(a).unwrap(),
            timer(&a.replace("2min", "3min")).unwrap()
        );
    }
    #[test]
    fn duplicate_properties_schedules_foreign_bases_and_injections_reject() {
        for bad in [
            "MainPID=0\nMainPID=0\n",
            "TimersMonotonic={ OnActiveUSec=1s ; next_elapse=0 }\nTimersMonotonic={ OnActiveUSec=1s ; next_elapse=1 }\n",
            "TimersMonotonic={ OnBootUSec=1s ; next_elapse=0 }\n",
            "TimersMonotonic={ OnActiveUSec=1s ; next_elapse=0 }; { injected }\n",
            "Id=foreign.timer\n",
            "Unknown=value\n",
        ] {
            assert!(timer(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn repeated_timer_is_never_accepted_for_another_native_owner() {
        assert!(
            parse(
                "foreign.timer",
                "Id=foreign.timer\nTimersMonotonic=a\nTimersMonotonic=b\n",
                KEYS
            )
            .is_err()
        );
        assert!(
            parse(
                "original.service",
                "Id=original.service\nMainPID=0\nMainPID=1\n",
                KEYS
            )
            .is_err()
        );
    }
    #[test]
    fn only_original_timer_dependency_order_is_canonical_without_dropping_duplicates() {
        assert_eq!(
            timer("After=z.service a.target\n").unwrap(),
            timer("After=a.target z.service\n").unwrap()
        );
        assert!(timer("After=a.target a.target\n").is_err());
        let a = parse(
            "original.service",
            "Id=original.service\nAfter=z.service a.target\n",
            KEYS,
        )
        .unwrap();
        let b = parse(
            "original.service",
            "Id=original.service\nAfter=a.target z.service\n",
            KEYS,
        )
        .unwrap();
        assert_ne!(a, b);
    }
}
