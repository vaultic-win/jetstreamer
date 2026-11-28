//! Exact private epoch 230 windows using the upstream v1.6.27 worker.
use crate::{BankHashExpectation, QualificationPlan, require_existing_private_directory};
use std::{collections::BTreeMap, path::Path};

use crate::compatibility::{
    EPOCH230_V1627_BOOTSTRAP as BOOTSTRAP, EPOCH230_V1627_NEXT_TERMINAL as NEXT_TERMINAL,
    EPOCH230_V1627_TERMINAL as TERMINAL,
};
const BOOTSTRAP_HASH: &str = "9Hgyrxkc5h5mkAwPL7rUGASHZFMByNzE1TYmCPb4z4e7";
const TERMINAL_HASH: &str = "5kWV3NT4f15DCB3XkmiYSLu9a1H88XK4GYGEV54nimcQ";
const OUTPUT: &str = "epoch-230-v1-6-27-diagnostic.jet";
const NEXT_TERMINAL_HASH: &str = "26wibqVauVjaet3eM6o8hssvaXi4awt7ndjwCaYJZyPK";
const NEXT_OUTPUT: &str = "epoch-230-slots-99468090-99476782.jet";

struct Window {
    bootstrap: u64,
    terminal: u64,
    bootstrap_hash: &'static str,
    terminal_hash: &'static str,
    output: &'static str,
}

const WINDOWS: [Window; 2] = [
    Window {
        bootstrap: BOOTSTRAP,
        terminal: TERMINAL,
        bootstrap_hash: BOOTSTRAP_HASH,
        terminal_hash: TERMINAL_HASH,
        output: OUTPUT,
    },
    Window {
        bootstrap: TERMINAL,
        terminal: NEXT_TERMINAL,
        bootstrap_hash: TERMINAL_HASH,
        terminal_hash: NEXT_TERMINAL_HASH,
        output: NEXT_OUTPUT,
    },
];

fn window_for_plan(plan: QualificationPlan) -> Result<&'static Window, String> {
    WINDOWS
        .iter()
        .find(|window| {
            plan.epoch == 230
                && plan.bootstrap_slot == window.bootstrap
                && plan.replay_start == window.bootstrap + 1
                && plan.output_runtime_range() == (window.bootstrap + 1..window.terminal + 1)
        })
        .ok_or_else(|| {
            "the epoch 230 v1.6.27 diagnostic requires an exact bootstrap and replay span".into()
        })
}

// Restrict the standalone build before it can dispatch an unrelated helper.
pub(crate) fn validate_entrypoint(args: &[String]) -> Result<(), String> {
    if matches!(args, [help] if matches!(help.as_str(), "-h" | "--help")) {
        return Ok(());
    }
    let [epoch, ledger, options @ ..] = args else {
        return Err("the v1.6.27 diagnostic requires an explicit epoch and ledger".into());
    };
    if !matches!(epoch.as_str(), "230" | "230-230") || !Path::new(ledger).is_absolute() {
        return Err("the v1.6.27 diagnostic requires epoch 230 and an absolute ledger path".into());
    }

    let mut supplied = [false; 6];
    for arg in options {
        let index = if arg == "--verify" {
            0
        } else if let Some((option, value)) = arg.split_once('=') {
            match option {
                "--qualification-end-slot"
                    if value
                        .parse::<u64>()
                        .is_ok_and(|end| WINDOWS.iter().any(|window| end == window.terminal)) =>
                {
                    1
                }
                "--snapshot-archive" if Path::new(value).is_absolute() => 2,
                "--epoch-hashes" if Path::new(value).is_absolute() => 3,
                "--horizon-output" if Path::new(value).is_absolute() => 4,
                "--replay-scratch" if Path::new(value).is_absolute() => 5,
                _ => return Err(format!("unsupported epoch 230 v1.6.27 argument {option}")),
            }
        } else {
            return Err(format!("unsupported epoch 230 v1.6.27 argument {arg}"));
        };
        if std::mem::replace(&mut supplied[index], true) {
            return Err("duplicate epoch 230 v1.6.27 option".into());
        }
    }
    if !supplied.into_iter().all(|present| present) {
        return Err("the epoch 230 v1.6.27 diagnostic requires verification, its exact terminal, both snapshot inputs, output and scratch".into());
    }
    Ok(())
}

pub(crate) fn validate_launch(
    qualification: Option<QualificationPlan>,
    ledger: &Path,
    output: Option<&Path>,
    scratch: Option<&Path>,
) -> Result<(), String> {
    let window = window_for_plan(
        qualification.ok_or("the epoch 230 v1.6.27 diagnostic requires a qualification span")?,
    )?;
    let scratch = scratch.ok_or("the epoch 230 v1.6.27 diagnostic requires private scratch")?;
    if output != Some(ledger.join(window.output).as_path()) || scratch == ledger {
        return Err("the epoch 230 v1.6.27 diagnostic requires its named private output and separate scratch".into());
    }
    for directory in [ledger, scratch] {
        require_existing_private_directory(directory)?;
        if directory
            .canonicalize()
            .map_err(|error| error.to_string())?
            != directory
        {
            return Err(format!(
                "private v1.6.27 directory must be canonical: {}",
                directory.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_expectations(
    plan: QualificationPlan,
    expected: &BTreeMap<u64, BankHashExpectation>,
) -> Result<(), String> {
    let window = window_for_plan(plan)?;
    for (slot, hash) in [
        (window.bootstrap, window.bootstrap_hash),
        (window.terminal, window.terminal_hash),
    ] {
        let binding =
            BankHashExpectation::LegacyAccountsHash(hash.parse().expect("fixed accounts hash"));
        if expected.get(&slot) != Some(&binding) {
            return Err(format!(
                "the epoch 230 v1.6.27 accounts checkpoint at slot {slot} differs from the pinned hash"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compatibility;

    fn plan(window: &Window) -> QualificationPlan {
        QualificationPlan {
            epoch: 230,
            bootstrap_slot: window.bootstrap,
            replay_start: window.bootstrap + 1,
            output_slot_start: window.bootstrap + 1,
            end_inclusive: window.terminal,
        }
    }

    #[test]
    fn selects_only_the_exact_private_range() {
        for window in &WINDOWS {
            let plan = plan(window);
            let span = plan.output_runtime_range();
            let selected =
                compatibility::select_focused_qualification_runtime(span.clone(), true).unwrap();
            assert_eq!(selected.descriptor.identity.name, "solana-v1.6.27");
            let ordinary = compatibility::select_runtime(span.clone(), true).unwrap();
            assert_ne!(ordinary.descriptor.identity.name, "solana-v1.6.27");
            for other in [
                window.bootstrap..span.end,
                span.start..window.terminal,
                span.start..span.end + 1,
            ] {
                let selected =
                    compatibility::select_focused_qualification_runtime(other, true).unwrap();
                assert_ne!(selected.descriptor.identity.name, "solana-v1.6.27");
            }
            assert!(
                compatibility::select_focused_qualification_runtime(span.clone(), false).is_err()
            );
            assert!(
                compatibility::select_focused_qualification_runtime_with_snapshot_warmup(
                    window.bootstrap,
                    span,
                    true
                )
                .is_err()
            );
            assert!(
                window_for_plan(QualificationPlan {
                    replay_start: window.bootstrap,
                    ..plan
                })
                .is_err()
            );
        }
    }

    #[test]
    fn refuses_ordinary_and_recovery_entrypoints() {
        let mut args = [
            "230",
            "/ledger",
            "--verify",
            "--qualification-end-slot=99468089",
            "--snapshot-archive=/snapshot",
            "--epoch-hashes=/hashes",
            "--horizon-output=/ledger/archive",
            "--replay-scratch=/scratch",
        ]
        .map(str::to_owned)
        .to_vec();
        assert!(validate_entrypoint(&args).is_ok());
        args[3] = "--qualification-end-slot=99476782".into();
        assert!(validate_entrypoint(&args).is_ok());
        args[3] = "--qualification-end-slot=99476783".into();
        assert!(validate_entrypoint(&args).is_err());
        args[3] = "--qualification-end-slot=99476782".into();
        assert!(validate_entrypoint(&args[..2]).is_err());
        for option in [
            "--root-checkpoint-cohort",
            "--recover-staged-only",
            "--verify",
        ] {
            args.push(option.into());
            assert!(validate_entrypoint(&args).is_err());
            args.pop();
        }
    }

    #[test]
    fn binds_both_accounts_checkpoints() {
        for (index, window) in WINDOWS.iter().enumerate() {
            let parse = |hash: &str| BankHashExpectation::LegacyAccountsHash(hash.parse().unwrap());
            let bootstrap = parse(window.bootstrap_hash);
            let terminal = parse(window.terminal_hash);
            let bound =
                BTreeMap::from([(window.bootstrap, bootstrap), (window.terminal, terminal)]);
            assert!(validate_expectations(plan(window), &bound).is_ok());
            assert!(validate_expectations(plan(&WINDOWS[1 - index]), &bound).is_err());
            assert!(
                validate_expectations(
                    plan(window),
                    &BTreeMap::from([(window.bootstrap, bootstrap), (window.terminal, bootstrap)])
                )
                .is_err()
            );
            assert!(
                validate_expectations(
                    plan(window),
                    &BTreeMap::from([(window.bootstrap, terminal), (window.terminal, terminal)])
                )
                .is_err()
            );
        }
    }
}
