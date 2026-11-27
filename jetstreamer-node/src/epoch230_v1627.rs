//! Scope of the private upstream v1.6.27 comparison around the epoch 230 vote.
use crate::{
    BankHashExpectation, QualificationPlan, compatibility, require_existing_private_directory,
};
use std::{collections::BTreeMap, ops::Range, path::Path};

pub(crate) const BOOTSTRAP: u64 = 99_461_591;
const TERMINAL: u64 = 99_468_089;
const BOOTSTRAP_HASH: &str = "9Hgyrxkc5h5mkAwPL7rUGASHZFMByNzE1TYmCPb4z4e7";
const TERMINAL_HASH: &str = "5kWV3NT4f15DCB3XkmiYSLu9a1H88XK4GYGEV54nimcQ";
const OUTPUT: &str = "epoch-230-v1-6-27-diagnostic.jet";

pub(crate) fn selected(range: &Range<u64>) -> bool {
    *range == (BOOTSTRAP + 1..TERMINAL + 1)
}

pub(crate) fn selection(allow_candidate: bool) -> Result<compatibility::RuntimeSelection, String> {
    if !allow_candidate {
        return Err(
            "the private epoch 230 v1.6.27 diagnostic requires candidate runtime opt-in".into(),
        );
    }
    let descriptor = &compatibility::SOLANA_V1_6_27_RUNTIME;
    Ok(compatibility::RuntimeSelection {
        backend: descriptor.backend,
        descriptor,
        admission: compatibility::AdmissionLevel::Candidate,
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
                "--qualification-end-slot" if value.parse::<u64>() == Ok(TERMINAL) => 1,
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
    if !qualification.is_some_and(|p| {
        p.epoch == 230 && p.bootstrap_slot == BOOTSTRAP && selected(&p.output_runtime_range())
    }) {
        return Err(
            "the epoch 230 v1.6.27 diagnostic requires its exact bootstrap and replay span".into(),
        );
    }
    let scratch = scratch.ok_or("the epoch 230 v1.6.27 diagnostic requires private scratch")?;
    if output != Some(ledger.join(OUTPUT).as_path()) || scratch == ledger {
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
    expected: &BTreeMap<u64, BankHashExpectation>,
) -> Result<(), String> {
    for (slot, hash) in [(BOOTSTRAP, BOOTSTRAP_HASH), (TERMINAL, TERMINAL_HASH)] {
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

    #[test]
    fn selects_only_the_exact_private_range() {
        assert!(selected(&(BOOTSTRAP + 1..TERMINAL + 1)));
        assert!(!selected(&(BOOTSTRAP..TERMINAL + 1)));
        assert!(!selected(&(BOOTSTRAP + 1..TERMINAL)));
        assert!(!selected(&(BOOTSTRAP + 1..TERMINAL + 2)));
        assert!(selection(false).is_err());
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
        let bootstrap = BankHashExpectation::LegacyAccountsHash(BOOTSTRAP_HASH.parse().unwrap());
        let terminal = BankHashExpectation::LegacyAccountsHash(TERMINAL_HASH.parse().unwrap());
        assert!(
            validate_expectations(&BTreeMap::from([
                (BOOTSTRAP, bootstrap),
                (TERMINAL, terminal)
            ]))
            .is_ok()
        );
        assert!(
            validate_expectations(&BTreeMap::from([
                (BOOTSTRAP, bootstrap),
                (TERMINAL, bootstrap)
            ]))
            .is_err()
        );
        assert!(
            validate_expectations(&BTreeMap::from([
                (BOOTSTRAP, terminal),
                (TERMINAL, terminal)
            ]))
            .is_err()
        );
    }
}
