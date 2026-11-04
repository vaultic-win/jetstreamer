//! A new retention admission may release terminal obligations, never live guards.
//! This fixed seven-job profile does not change source-integrity evidence.
use {
    super::epoch141_ledger_common::{bound_file, is_sha},
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::Value,
    std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt, path::PathBuf, process::Command},
};

const GIB: u64 = 1 << 30;
const FLOOR_SHA: &str = "39673f485b44ffb5c2053e2a553819da0bd0be30dcfc3cb8990553dd4de0f682";
const RELEASED: [&str; 5] = [
    "horizon-qualify-epoch154-rayon10-growth-20261019-v1.service",
    "jetstreamer-epoch185-singleton-20261020-controller-v1-r2.service",
    "jetstreamer-root-sweep-e185-s1-20261020-v1-r2-e185-185-lane-a-1.service",
    "horizon-epoch141-ledger-census-20261020-v2.service",
    "horizon-qualify-140-native-restore-20261020-v1.service",
];
const RANGES: [&str; 7] = ["144", "152-153", "155-156", "157", "160", "191-194", "198"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    controller_unit: String,
    controller_invocation_id: String,
    producer_unit: String,
    producer_invocation_id: String,
    remaining_growth_bytes: u64,
    guard_unit: String,
    guard_timer: String,
    guard_fragment: Bound,
    guard_executable: Bound,
    guard_floor_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    source_verification_sha256: String,
    complete_census_sha256: String,
    previous_protected_free_bytes: u64,
    observer: Bound,
    fleet: Bound,
    century_floor: Bound,
    claims: BTreeMap<String, Claim>,
    priority_margin_bytes: u64,
    protected_free_bytes: u64,
}

fn json(e: &Bound, maximum: u64) -> Result<Value> {
    Ok(serde_json::from_slice(&bound_file(
        &e.path, &e.sha256, maximum, false,
    )?)?)
}
fn unit(name: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        name.ends_with(".service") || name.ends_with(".timer"),
        "invalid unit suffix"
    );
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "invalid unit name"
    );
    let out = Command::new("/usr/bin/systemctl").args(["show", name,
        "--property=LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,Result,ExecStart,FragmentPath,DropInPaths,Unit"]).output()?;
    ensure!(
        out.status.success(),
        "cannot inspect protection unit {name}"
    );
    Ok(String::from_utf8(out.stdout)?
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}
fn live(state: &Value, invocation: &str) -> bool {
    state["LoadState"] == "loaded"
        && state["ActiveState"] == "active"
        && state["SubState"] == "running"
        && state["InvocationID"] == invocation
        && state["NRestarts"] == "0"
        && state["MainPID"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n > 0)
}
fn terminal(state: &Value) -> bool {
    state["ActiveState"] == "inactive"
        && state["MainPID"] == "0"
        && state["NRestarts"] == "0"
        && state["Result"] == "success"
        && (state["LoadState"] == "loaded" || state["LoadState"] == "not-found")
}
fn observer_live(state: &Value, name: &str, invocation: &str) -> bool {
    state["unit"] == name
        && state["load_state"] == "loaded"
        && state["active_state"] == "active"
        && state["sub_state"] == "running"
        && state["invocation_id"] == invocation
        && state["restarts"] == 0
        && state["main_pid"].as_u64().is_some_and(|n| n > 0)
}

fn command_names_executable(args: &[&str], path: &str) -> bool {
    // systemctl renders a direct shebang command with path=/... and
    // argv[]=/..., while an interpreter's script is a bare subsequent argv.
    args.iter().any(|arg| {
        *arg == path
            || arg.strip_prefix("path=") == Some(path)
            || arg.strip_prefix("argv[]=") == Some(path)
    })
}

fn required_floor(claims: &BTreeMap<String, Claim>, floor: u64, margin: u64) -> Result<u64> {
    ensure!(
        claims.keys().map(String::as_str).eq(RANGES),
        "incomplete seven-job protection census"
    );
    ensure!(margin >= 64 * GIB, "priority margin weakened");
    let mut remaining = floor;
    let mut largest_guard = 0;
    for (range, c) in claims {
        let minimum = if range == "160" || range == "198" {
            768
        } else {
            512
        } * GIB;
        ensure!(
            c.remaining_growth_bytes >= minimum,
            "full conservative claim weakened for {range}"
        );
        remaining = remaining
            .checked_add(c.remaining_growth_bytes)
            .context("protection sum overflow")?;
        largest_guard = largest_guard.max(c.guard_floor_bytes);
    }
    remaining
        .max(largest_guard)
        .checked_add(margin)
        .context("protection margin overflow")
}

/// Only a complete-retention launch can rebind the old operational floor.
/// Source bytes, generation, identity, census, and old receipts remain unchanged.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate(
    path: &std::path::Path,
    sha: &str,
    source_sha: &str,
    census_sha: &str,
    previous_floor: u64,
    planned_floor: u64,
    manifest: &Value,
    now: u64,
) -> Result<()> {
    let policy: Policy = serde_json::from_slice(&bound_file(path, sha, 128 * 1024, true)?)?;
    ensure!(
        policy.schema == "jetstreamer-epoch141-retention-protection-transition-v1"
            && policy.source_verification_sha256 == source_sha
            && policy.complete_census_sha256 == census_sha
            && policy.previous_protected_free_bytes == previous_floor
            && previous_floor == 5_153_013_784_006,
        "wrong original protection/source/census binding"
    );
    ensure!(
        policy.century_floor.sha256 == FLOOR_SHA,
        "unqualified century floor evidence"
    );
    let floor = json(&policy.century_floor, 65536)?;
    ensure!(
        floor["schema"] == "jetstreamer-horizon-century-jet-floor-v1"
            && floor["century"]["first_epoch"] == 200
            && floor["century"]["last_epoch"] == 300
            && floor["arithmetic"]["floor_bytes"] == 205_211_459_014u64
            && floor["arithmetic"]["sample_count"] == 1
            && floor["arithmetic"]["sum_jet_size_bytes"] == 102_605_729_507u64,
        "wrong qualified century arithmetic"
    );
    ensure!(
        policy.protected_free_bytes
            == required_floor(
                &policy.claims,
                205_211_459_014,
                policy.priority_margin_bytes
            )?
            && planned_floor >= policy.protected_free_bytes,
        "incomplete current protected-space envelope"
    );
    let observer = json(&policy.observer, 16 * 1024 * 1024)?;
    let fleet = json(&policy.fleet, 16 * 1024 * 1024)?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet["observer_receipt"].as_str() == policy.observer.path.to_str()
            && fleet["observer_sha256"] == policy.observer.sha256
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"],
        "wrong current coordinated evidence"
    );
    let age = now
        .checked_sub(u64::try_from(
            fs::symlink_metadata(&policy.observer.path)?.mtime(),
        )?)
        .context("future observer")?;
    ensure!(
        age <= 1800
            && now
                .checked_sub(
                    fleet["recorded_unix_seconds"]
                        .as_u64()
                        .context("fleet time")?
                )
                .is_some_and(|a| a <= 1800),
        "stale protection transition evidence"
    );
    let replays = observer["replays"]
        .as_array()
        .context("missing observer census")?;
    ensure!(
        replays.len() == policy.claims.len(),
        "extra/missing replay claims"
    );
    let active = fleet["active"]
        .as_array()
        .context("missing fleet active claims")?;
    ensure!(
        active.len() == 12
            && fleet["diagnostics"]
                .as_array()
                .context("missing diagnostics")?
                .is_empty(),
        "unbudgeted fleet work"
    );
    for old in RELEASED {
        ensure!(
            terminal(&fleet["unit_census"][old]) && terminal(&serde_json::to_value(unit(old)?)?),
            "released obligation remains live or ambiguous: {old}"
        );
    }
    for (range, c) in &policy.claims {
        ensure!(
            is_sha(&format!("{0}{0}", c.controller_invocation_id))
                && is_sha(&format!("{0}{0}", c.producer_invocation_id)),
            "invalid claim invocation"
        );
        let replay = replays
            .iter()
            .find(|r| r["range"] == *range)
            .context("missing exact observer range")?;
        ensure!(
            replay["invocation_binding_stable"] == true
                && observer_live(
                    &replay["controller_after"],
                    &c.controller_unit,
                    &c.controller_invocation_id
                )
                && observer_live(
                    &replay["producer_after"],
                    &c.producer_unit,
                    &c.producer_invocation_id
                ),
            "wrong stable observer claim"
        );
        for (name, invocation) in [
            (&c.controller_unit, &c.controller_invocation_id),
            (&c.producer_unit, &c.producer_invocation_id),
        ] {
            ensure!(
                live(&fleet["unit_census"][name], invocation)
                    && live(&serde_json::to_value(unit(name)?)?, invocation),
                "current claim changed: {name}"
            );
            ensure!(
                manifest["expected_units"]
                    .as_array()
                    .context("missing admitted units")?
                    .iter()
                    .any(|u| u["unit"] == *name
                        && u["invocation_id"] == *invocation
                        && u["active_state"] == "active"
                        && u["sub_state"] == "running"
                        && u["restarts"] == 0),
                "claim omitted from fresh admission"
            );
        }
        ensure!(
            active.iter().any(|a| a["producer"]["Id"] == c.producer_unit
                && a["producer"]["InvocationID"] == c.producer_invocation_id),
            "claim absent from fleet active list"
        );
        // Check effective commands, not merely a unit file or timer's existence.
        bound_file(
            &c.guard_fragment.path,
            &c.guard_fragment.sha256,
            1024 * 1024,
            false,
        )?;
        bound_file(
            &c.guard_executable.path,
            &c.guard_executable.sha256,
            64 * 1024 * 1024,
            true,
        )?;
        let guard = unit(&c.guard_unit)?;
        let timer = unit(&c.guard_timer)?;
        ensure!(
            guard.get("LoadState").map(String::as_str) == Some("loaded")
                && guard.get("FragmentPath").map(String::as_str) == c.guard_fragment.path.to_str()
                && guard.get("DropInPaths").is_some_and(String::is_empty)
                && guard.get("Result").map(String::as_str) == Some("success")
                && guard.get("NRestarts").map(String::as_str) == Some("0")
                && timer.get("ActiveState").map(String::as_str) == Some("active")
                && timer.get("Unit") == Some(&c.guard_unit),
            "guard/timer not qualified or changed"
        );
        let args: Vec<_> = guard
            .get("ExecStart")
            .context("missing guard command")?
            .split_whitespace()
            .collect();
        ensure!(
            command_names_executable(
                &args,
                c.guard_executable
                    .path
                    .to_str()
                    .context("non-UTF8 guard path")?
            ) && args
                .iter()
                .filter_map(|a| a.strip_prefix("--minimum-free-bytes="))
                .collect::<Vec<_>>()
                == [c.guard_floor_bytes.to_string()]
                && (args.contains(
                    &format!(
                        "--expected-producer-invocation-id={}",
                        c.producer_invocation_id
                    )
                    .as_str()
                ) || (c.controller_unit == c.producer_unit
                    && args.contains(
                        &format!("--expected-invocation-id={}", c.producer_invocation_id).as_str()
                    )))
                && (c.controller_unit == c.producer_unit
                    || args.contains(
                        &format!(
                            "--expected-controller-invocation-id={}",
                            c.controller_invocation_id
                        )
                        .as_str()
                    )),
            "guard command does not protect the exact live claim/floor"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claims() -> BTreeMap<String, Claim> {
        RANGES
            .into_iter()
            .map(|r| {
                (
                    r.into(),
                    Claim {
                        controller_unit: "owner.service".into(),
                        controller_invocation_id: "1".repeat(32),
                        producer_unit: "worker.service".into(),
                        producer_invocation_id: "2".repeat(32),
                        remaining_growth_bytes: if r == "160" || r == "198" {
                            768 * GIB
                        } else {
                            512 * GIB
                        },
                        guard_unit: "guard.service".into(),
                        guard_timer: "guard.timer".into(),
                        guard_fragment: Bound {
                            path: "/unit".into(),
                            sha256: "3".repeat(64),
                        },
                        guard_executable: Bound {
                            path: "/guard".into(),
                            sha256: "4".repeat(64),
                        },
                        guard_floor_bytes: 4_671_977_446_854,
                    },
                )
            })
            .collect()
    }
    #[test]
    fn protects_complete_growth_and_highest_live_guard_plus_margin() {
        let mut c = claims();
        assert_eq!(
            required_floor(&c, 205_211_459_014, 64 * GIB).unwrap(),
            4_740_696_923_590
        );
        c.get_mut("144").unwrap().remaining_growth_bytes = 1024 * GIB;
        assert!(required_floor(&c, 205_211_459_014, 64 * GIB).unwrap() > 4_740_696_923_590);
        c.get_mut("144").unwrap().guard_floor_bytes = u64::MAX;
        assert!(required_floor(&c, 205_211_459_014, 64 * GIB).is_err());
    }
    #[test]
    fn incomplete_or_lowered_claims_and_margin_fail_closed() {
        let mut c = claims();
        assert!(required_floor(&c, 205_211_459_014, 64 * GIB - 1).is_err());
        c.get_mut("160").unwrap().remaining_growth_bytes -= 1;
        assert!(required_floor(&c, 205_211_459_014, 64 * GIB).is_err());
        c = claims();
        c.remove("144");
        assert!(required_floor(&c, 205_211_459_014, 64 * GIB).is_err());
    }
    #[test]
    fn live_restarts_missing_units_and_activating_replacements_are_not_releases() {
        let good = serde_json::json!({"LoadState":"loaded","ActiveState":"inactive","MainPID":"0","NRestarts":"0","Result":"success"});
        assert!(terminal(&good));
        for (key, value) in [
            ("ActiveState", "active"),
            ("ActiveState", "activating"),
            ("MainPID", "1"),
            ("NRestarts", "1"),
            ("Result", "exit-code"),
            ("LoadState", "error"),
        ] {
            let mut bad = good.clone();
            bad[key] = value.into();
            assert!(!terminal(&bad));
        }
        assert!(!terminal(&Value::Null));
    }

    #[test]
    fn observer_identity_uses_actual_v2_field_names_and_integer_types() {
        let invocation = "1".repeat(32);
        let good = serde_json::json!({"unit":"owner.service","load_state":"loaded",
            "active_state":"active","sub_state":"running","invocation_id":invocation,
            "restarts":0,"main_pid":123});
        assert!(observer_live(&good, "owner.service", &invocation));
        assert!(!observer_live(&good, "foreign.service", &invocation));
        assert!(!observer_live(&good, "owner.service", &"2".repeat(32)));
        for key in good.as_object().unwrap().keys() {
            let mut bad = good.clone();
            bad[key] = Value::Null;
            assert!(
                !observer_live(&bad, "owner.service", &invocation),
                "accepted missing {key}"
            );
        }
        let mut bad = good.clone();
        bad["restarts"] = 1.into();
        assert!(!observer_live(&bad, "owner.service", &invocation));
        let mut bad = good;
        bad["main_pid"] = "123".into();
        assert!(!observer_live(&bad, "owner.service", &invocation));
    }

    #[test]
    fn exact_guard_executable_accepts_real_systemctl_shebang_and_interpreter_shapes() {
        let path = "/sealed/guard.py";
        for command in [
            "{ path=/sealed/guard.py ; argv[]=/sealed/guard.py --minimum-free-bytes=1 ; }",
            "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /sealed/guard.py --minimum-free-bytes=1 ; }",
        ] {
            let args: Vec<_> = command.split_whitespace().collect();
            assert!(command_names_executable(&args, path));
            assert!(!command_names_executable(&args, "/sealed/guard.py-other"));
            assert!(!command_names_executable(&args, "/sealed/guard"));
        }
        assert!(!command_names_executable(
            &["--note=/sealed/guard.py"],
            path
        ));
    }
}
