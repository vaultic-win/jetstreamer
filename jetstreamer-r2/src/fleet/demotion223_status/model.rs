//! Closed epoch223 recovery ETA: always through verified sidecar commit.
use super::*;
pub(super) const ORIGIN_UNIT: &str =
    "horizon-qualify-223-v1620-root-prefix-resource-full-v1.service";
pub(super) const ORIGIN_IID: &str = "e70aaf097e7c4583b216aba454145910";
const START: u64 = 96_335_539;
const END: u64 = 96_544_588;
const STAGES: [&str; 16] = [
    "native_input",
    "bracket",
    "full_root_worker_qualification",
    "cold_restart",
    "full_root_replay",
    "prefix_reread",
    "native_handoff",
    "suffix",
    "archive_close",
    "assembly",
    "full_verification",
    "plugin_verification",
    "boundary_verification",
    "upload",
    "readback",
    "sidecar_commit",
];
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    pub schema: String,
    pub stage_millis: BTreeMap<String, u64>,
    pub fallback_millis_per_bracket_slot: u64,
    pub overdue_recovery_millis: u64,
    pub explanation: String,
    pub evidence: Vec<BoundFile>,
}
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Progress {
    pub slot: u64,
    pub terminal: u64,
    pub unix_micros: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Estimate {
    pub phase: String,
    pub remaining_millis: u64,
    pub elapsed_millis: u64,
    pub current_stage: String,
    pub current_stage_remaining_millis: u64,
    pub downstream_remaining_millis: u64,
    pub measured_rate_used: bool,
}
pub(super) fn origin(journal: &[u8]) -> Result<u64> {
    let mut selected = None;
    for row in serde_json::Deserializer::from_slice(journal).into_iter::<Value>() {
        let row = row?;
        if row["_PID"] == "1"
            && row["UNIT"] == ORIGIN_UNIT
            && row["INVOCATION_ID"] == ORIGIN_IID
            && row["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with(&format!("Started {ORIGIN_UNIT} - ")))
        {
            let start = row["__REALTIME_TIMESTAMP"]
                .as_str()
                .context("223 original PID1 clock")?
                .parse::<u64>()?
                / 1000;
            ensure!(
                start > 0 && selected.replace(start).is_none(),
                "223 original start is ambiguous"
            );
        }
    }
    selected.context("223 original PID1 start missing")
}
fn checked_sum<'a>(mut values: impl Iterator<Item = &'a u64>) -> Result<u64> {
    values.try_fold(0u64, |sum, n| {
        sum.checked_add(*n).context("223 inclusive ETA overflow")
    })
}
pub(super) fn estimate(
    p: &Policy,
    kind: &str,
    origin: u64,
    actor_started: u64,
    sampled: u64,
    progress: &[Progress],
) -> Result<Estimate> {
    ensure!(
        p.schema == "jetstreamer-epoch223-demotion-eta-policy-v1"
            && !p.explanation.trim().is_empty()
            && !p.evidence.is_empty()
            && p.stage_millis.len() == STAGES.len()
            && STAGES
                .iter()
                .all(|name| p.stage_millis.get(*name).is_some_and(|n| *n > 0))
            && p.fallback_millis_per_bracket_slot > 0
            && p.overdue_recovery_millis > 0,
        "223 complete positive recovery-to-sidecar model required"
    );
    let index = match kind {
        "native-input" => 0,
        "bracket" => 1,
        _ => bail!("223 unsupported recovery actor"),
    };
    ensure!(
        origin <= actor_started && actor_started <= sampled,
        "223 repair clock changed or is future"
    );
    ensure!(
        kind == "bracket" || progress.is_empty(),
        "native bootstrap cannot claim entry replay"
    );
    let elapsed = sampled
        .checked_sub(origin)
        .context("223 original elapsed underflow")?;
    let age = sampled - actor_started;
    let budget = p.stage_millis[STAGES[index]];
    let mut current = if age < budget {
        budget - age
    } else {
        p.overdue_recovery_millis
            .checked_add((age - budget) / 2)
            .context("223 overdue recovery overflow")?
    };
    let mut measured = false;
    if let Some(last) = progress.last() {
        ensure!(
            last.terminal == END && (START..=END).contains(&last.slot),
            "223 progress is outside private bracket"
        );
        let slots = END - last.slot;
        current = slots
            .checked_mul(p.fallback_millis_per_bracket_slot)
            .context("223 fallback ETA overflow")?;
        if progress.len() > 1 {
            let first = &progress[0];
            ensure!(
                progress.windows(2).all(|pair| pair[1].slot >= pair[0].slot
                    && pair[1].unix_micros > pair[0].unix_micros)
                    && progress
                        .iter()
                        .all(|v| v.terminal == END && (START..=END).contains(&v.slot)),
                "223 progress resets or crosses runtime bracket"
            );
            let delta = last.slot - first.slot;
            if delta > 0 {
                let numerator =
                    u128::from(slots) * u128::from(last.unix_micros - first.unix_micros);
                let denominator = u128::from(delta) * 1000;
                current = u64::try_from(numerator.div_ceil(denominator))?;
                measured = true;
            }
        }
    }
    if let Some(last) = progress.last() {
        ensure!(
            last.unix_micros / 1000 <= sampled,
            "223 observed progress is future-dated"
        );
        if last.slot < END {
            current = current
                .checked_add(sampled - last.unix_micros / 1000)
                .context("223 observed stall/recovery overflow")?;
        }
    }
    let downstream = checked_sum(
        STAGES
            .iter()
            .skip(index + 1)
            .map(|name| &p.stage_millis[*name]),
    )?;
    let remaining = current
        .checked_add(downstream)
        .context("223 sidecar ETA overflow")?;
    ensure!(
        remaining > 0,
        "223 active repair cannot publish sidecar completion"
    );
    Ok(Estimate {
        phase: if progress.is_empty() || progress.last().is_some_and(|p| p.slot == END) {
            "verification"
        } else {
            "replay"
        }
        .into(),
        remaining_millis: remaining,
        elapsed_millis: elapsed,
        current_stage: STAGES[index].into(),
        current_stage_remaining_millis: current,
        downstream_remaining_millis: downstream,
        measured_rate_used: measured,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            schema: "jetstreamer-epoch223-demotion-eta-policy-v1".into(),
            stage_millis: STAGES.iter().map(|name| (name.to_string(), 1000)).collect(),
            fallback_millis_per_bracket_slot: 10,
            overdue_recovery_millis: 500,
            explanation: "fixture with delivery allowances".into(),
            evidence: vec![BoundFile {
                path: "/sealed/fixture".into(),
                sha256: "a".repeat(64),
            }],
        }
    }
    #[test]
    fn terminal_bracket_retains_every_full_root_and_delivery_stage() {
        let p = policy();
        let progress = [Progress {
            slot: END,
            terminal: END,
            unix_micros: 1000000,
        }];
        let e = estimate(&p, "bracket", 1, 100, 1000, &progress).unwrap();
        assert_eq!(e.remaining_millis, 14_000);
        assert_eq!(e.elapsed_millis, 999);
        assert_eq!(e.phase, "verification");
        let mut missing = policy();
        missing.stage_millis.remove("readback");
        assert!(estimate(&missing, "bracket", 1, 100, 200, &progress).is_err());
        let mut missing = policy();
        missing.stage_millis.remove("sidecar_commit");
        assert!(estimate(&missing, "bracket", 1, 100, 200, &progress).is_err());
    }
    #[test]
    fn native_age_never_resets_original_elapsed_or_produces_zero_eta() {
        let e = estimate(&policy(), "native-input", 1, 10000, 20000, &[]).unwrap();
        assert_eq!(e.elapsed_millis, 19999);
        assert_eq!(e.phase, "verification");
        assert!(e.remaining_millis > 15000);
        assert!(estimate(&policy(), "native-input", 100, 1, 200, &[]).is_err());
        assert!(
            estimate(
                &policy(),
                "native-input",
                1,
                10,
                200,
                &[Progress {
                    slot: START,
                    terminal: END,
                    unix_micros: 1
                }]
            )
            .is_err()
        );
    }
    #[test]
    fn exact_integer_rate_rejects_reset_and_excludes_unqualified_full_epoch_slots() {
        let progress = [
            Progress {
                slot: END - 20,
                terminal: END,
                unix_micros: 1_000_000,
            },
            Progress {
                slot: END - 10,
                terminal: END,
                unix_micros: 2_000_000,
            },
        ];
        let e = estimate(&policy(), "bracket", 1, 10, 2000, &progress).unwrap();
        assert!(e.measured_rate_used);
        assert_eq!(e.current_stage_remaining_millis, 1000);
        let bad = [progress[1].clone(), progress[0].clone()];
        assert!(estimate(&policy(), "bracket", 1, 10, 200, &bad).is_err());
        let bad = [Progress {
            slot: 96_767_522,
            terminal: 96_767_522,
            unix_micros: 1,
        }];
        assert!(estimate(&policy(), "bracket", 1, 10, 200, &bad).is_err());
    }
    #[test]
    fn stalled_progress_adds_real_wait_instead_of_reusing_an_expired_countdown() {
        let rows = [
            Progress {
                slot: END - 20,
                terminal: END,
                unix_micros: 1_000_000,
            },
            Progress {
                slot: END - 10,
                terminal: END,
                unix_micros: 2_000_000,
            },
        ];
        let fresh = estimate(&policy(), "bracket", 1, 10, 2000, &rows).unwrap();
        let stalled = estimate(&policy(), "bracket", 1, 10, 7000, &rows).unwrap();
        assert_eq!(stalled.remaining_millis, fresh.remaining_millis + 5000);
        assert_eq!(stalled.elapsed_millis, 6999);
    }
    #[test]
    fn original_start_is_unique_and_a_new_task_cannot_replace_e70_clock() {
        let old = json!({"_PID":"1","UNIT":ORIGIN_UNIT,"INVOCATION_ID":ORIGIN_IID,
            "MESSAGE":format!("Started {ORIGIN_UNIT} - fixture."),"__REALTIME_TIMESTAMP":"1792806478075603"});
        let later = json!({"_PID":"1","UNIT":"horizon-native-input-223-demotion-fixture.service","INVOCATION_ID":"f".repeat(32),
            "MESSAGE":"Started new actual native task - fixture.","__REALTIME_TIMESTAMP":"1792809999999999"});
        assert_eq!(
            origin(format!("{old}\n{later}\n").as_bytes()).unwrap(),
            1792806478075
        );
        assert!(origin(format!("{old}\n{old}\n").as_bytes()).is_err());
        assert!(origin(format!("{later}\n").as_bytes()).is_err());
    }
}
