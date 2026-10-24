//! Fixed protected-fleet contract for compressed input acquisition, not replay admission.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

const CLAIMS: [(u64, &str, &str, &str); 3] = [
    (
        203,
        "203-203",
        "horizon-qualify-203-shrink-root-prefix-resource-f9fc5a0-v1.service",
        "748ffa40e0a2408da0a10fc9e160cf0a",
    ),
    (
        223,
        "223-223",
        "horizon-qualify-223-singleton-postcount-ad1d65a-v1.service",
        "04ef9d97a36446d49b452d982cb0be46",
    ),
    (
        225,
        "225-226",
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
        "4cd76ae1353a4411885b997f04306402",
    ),
];

fn observer_unit(v: &Value, unit: &str, iid: &str) -> Result<()> {
    ensure!(
        v["unit"] == unit
            && v["invocation_id"] == iid
            && v["load_state"] == "loaded"
            && v["active_state"] == "active"
            && v["sub_state"] == "running"
            && v["restarts"].as_u64() == Some(0)
            && v["main_pid"].as_u64().is_some_and(|n| n > 0),
        "protected observer unit identity/state changed"
    );
    Ok(())
}

fn observation(v: &Value, range: &str, unit: &str, iid: &str) -> Result<()> {
    ensure!(
        v["range"] == range && v["invocation_binding_stable"] == true,
        "protected observation claim or binding changed"
    );
    for role in ["controller", "producer"] {
        let before = &v[format!("{role}_before")];
        let after = &v[format!("{role}_after")];
        observer_unit(before, unit, iid)?;
        observer_unit(after, unit, iid)?;
        ensure!(
            before["main_pid"] == after["main_pid"],
            "protected PID changed"
        );
    }
    Ok(())
}

pub(super) fn validate_observer(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "wrong observer schema"
    );
    let ordinary = v["replays"].as_array().context("missing ordinary census")?;
    let diagnostics = v["diagnostic_replays"]
        .as_array()
        .context("missing diagnostic census")?;
    ensure!(
        ordinary.len() == 1 && diagnostics.len() == 2,
        "protected census changed"
    );
    observation(&ordinary[0], CLAIMS[1].1, CLAIMS[1].2, CLAIMS[1].3)?;
    for (_, range, unit, iid) in [CLAIMS[0], CLAIMS[2]] {
        let entries: Vec<_> = diagnostics.iter().filter(|e| e["range"] == range).collect();
        ensure!(entries.len() == 1, "missing or duplicate diagnostic claim");
        let e = entries[0];
        ensure!(
            e["status"] == "observed"
                && e.get("error") == Some(&Value::Null)
                && e["ordinary_replay_claim"] == false
                && e["publication_authorized"] == false
                && e["r2_mutations"] == false
                && e["replay_launch_authorized"] == false
                && e["producer_unit"] == unit
                && e["expected_producer_invocation_id"] == iid,
            "diagnostic observation failed or changed role"
        );
        observation(&e["observation"], range, unit, iid)?;
    }
    Ok(())
}

fn fleet_unit(v: &Value, unit: &str, iid: &str) -> Result<()> {
    ensure!(
        v["Id"] == unit
            && v["InvocationID"] == iid
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|n| n > 0),
        "protected fleet unit identity/state changed"
    );
    Ok(())
}

pub(super) fn validate_fleet(v: &Value, observer: &Value, path: &Path, sha: &str) -> Result<()> {
    validate_observer(observer)?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && v["first_epoch"] == 201
            && v["last_epoch"] == 300
            && v["observer_receipt"].as_str() == path.to_str()
            && v["observer_sha256"] == sha
            && v["sampled_at_utc"] == observer["recorded_at_utc"]
            && v["sampled_at_utc"].as_str().is_some()
            && v["remote_mutations"] == false
            && v["publication_authorized"] == false,
        "fleet range, observer binding or non-authorizing policy changed"
    );
    ensure!(
        v["inventory"]["ready_pairs"] == 13 && v["inventory"]["anomalies"] == 0,
        "fixed inventory profile changed; new review required"
    );
    let active = v["active"]
        .as_array()
        .context("missing fleet active census")?;
    ensure!(active.len() == CLAIMS.len(), "fleet active census changed");
    for (epoch, range, unit, iid) in CLAIMS {
        let claims: Vec<_> = active.iter().filter(|a| a["epoch"] == epoch).collect();
        ensure!(
            claims.len() == 1,
            "missing or duplicate protected fleet claim"
        );
        let claim = claims[0];
        ensure!(
            claim["phase"]
                == if epoch == 223 {
                    "replay"
                } else {
                    "diagnostic-qualification"
                }
                && claim["sampled_at_utc"] == v["sampled_at_utc"],
            "fleet role or timestamp changed"
        );
        fleet_unit(&claim["producer"], unit, iid)?;
        let observed = if epoch == 223 {
            &observer["replays"][0]
        } else {
            ensure!(
                claim["scope_first_epoch"] == epoch
                    && claim["scope_last_epoch"] == if epoch == 225 { 226 } else { 203 }
                    && claim["ordinary_replay_claim"] == false,
                "diagnostic fleet scope changed"
            );
            &observer["diagnostic_replays"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["range"] == range)
                .context("missing protected observation")?["observation"]
        };
        ensure!(
            claim["producer"]["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == observed["producer_after"]["main_pid"].as_u64(),
            "fleet/observer producer PID mismatch"
        );
        if epoch == 223 {
            fleet_unit(&claim["controller"], unit, iid)?;
            ensure!(
                claim["controller"]["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    == observed["controller_after"]["main_pid"].as_u64(),
                "fleet/observer controller PID mismatch"
            );
        }
    }
    Ok(())
}

/// Read-only, immutable lock: callers cannot replace the shared lock inode.
pub(super) fn lease(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical transfer lease"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.uid() == unsafe { libc::geteuid() }
            && before.mode() & 0o7777 == 0o400,
        "unsafe transfer lease"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "transfer lease already held"
    );
    ensure!(
        super::identity(&before) == super::identity(&file.metadata()?)
            && super::identity(&before) == super::identity(&fs::symlink_metadata(path)?),
        "transfer lease changed"
    );
    Ok(file)
}

#[cfg(test)]
pub(super) fn observer_fixture(mut v: Value) -> Value {
    use serde_json::json;
    let observations: Vec<_> = CLAIMS
        .iter()
        .map(|(_, range, unit, iid)| {
            let identity = json!({"unit":unit,"invocation_id":iid,"load_state":"loaded",
            "active_state":"active","sub_state":"running","restarts":0,"main_pid":123});
            json!({"range":range,"invocation_binding_stable":true,
            "controller_before":identity,"controller_after":identity,
            "producer_before":identity,"producer_after":identity})
        })
        .collect();
    v["replays"] = json!([observations[1]]);
    v["diagnostic_replays"] = json!([0, 2].map(|i| json!({"range":CLAIMS[i].1,
        "status":"observed","error":null,"ordinary_replay_claim":false,
        "publication_authorized":false,"r2_mutations":false,"replay_launch_authorized":false,
        "producer_unit":CLAIMS[i].2,"expected_producer_invocation_id":CLAIMS[i].3,
        "observation":observations[i]})));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn observer() -> Value {
        observer_fixture(
            json!({"schema":"jetstreamer-horizon-live-resource-sample-v2",
            "recorded_at_utc":"2026-10-22T04:57:16Z"}),
        )
    }
    fn fleet() -> Value {
        let active: Vec<_> = CLAIMS.iter().map(|(epoch, _, unit, iid)| {
            let identity = json!({"Id":unit,"InvocationID":iid,"LoadState":"loaded",
                "ActiveState":"active","SubState":"running","NRestarts":"0","MainPID":"123"});
            json!({"epoch":epoch,"phase":if *epoch == 223 {"replay"} else {"diagnostic-qualification"},
                "sampled_at_utc":"2026-10-22T04:57:16Z","producer":identity,"controller":identity,
                "scope_first_epoch":epoch,"scope_last_epoch":if *epoch == 225 {226} else {*epoch},
                "ordinary_replay_claim":*epoch == 223})
        }).collect();
        json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":201,"last_epoch":300,
            "observer_receipt":"/observer.json","observer_sha256":"a".repeat(64),
            "sampled_at_utc":"2026-10-22T04:57:16Z","remote_mutations":false,
            "publication_authorized":false,"inventory":{"ready_pairs":13,"anomalies":0},"active":active})
    }
    fn check_fleet(v: &Value) -> Result<()> {
        validate_fleet(v, &observer(), Path::new("/observer.json"), &"a".repeat(64))
    }
    #[test]
    fn exact_protected_observer_and_fleet_pass() {
        validate_observer(&observer()).unwrap();
        check_fleet(&fleet()).unwrap();
    }
    #[test]
    fn observer_rejects_wrong_identity_restart_state_pid_and_binding() {
        for frame in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            for (key, value) in [
                ("invocation_id", json!("wrong")),
                ("restarts", json!(1)),
                ("main_pid", json!(0)),
                ("active_state", json!("inactive")),
                ("unit", json!("other.service")),
            ] {
                let mut v = observer();
                v["replays"][0][frame][key] = value;
                assert!(validate_observer(&v).is_err(), "{frame}/{key}");
            }
        }
        let mut v = observer();
        v["replays"][0]["invocation_binding_stable"] = json!(false);
        assert!(validate_observer(&v).is_err());
        let mut v = observer();
        v["replays"][0]["producer_after"]["main_pid"] = json!(124);
        assert!(validate_observer(&v).is_err());
    }
    #[test]
    fn observer_rejects_failed_missing_duplicate_or_new_claims() {
        for i in 0..2 {
            for (key, value) in [
                ("status", json!("failed")),
                ("error", json!("failed")),
                ("ordinary_replay_claim", json!(true)),
                ("producer_unit", json!("other")),
            ] {
                let mut v = observer();
                v["diagnostic_replays"][i][key] = value;
                assert!(validate_observer(&v).is_err());
            }
            let mut v = observer();
            v["diagnostic_replays"][i]["observation"]["producer_after"]["restarts"] = json!(1);
            assert!(validate_observer(&v).is_err());
        }
        for key in ["replays", "diagnostic_replays"] {
            let mut v = observer();
            v[key].as_array_mut().unwrap().pop();
            assert!(validate_observer(&v).is_err());
            let mut v = observer();
            let extra = v[key][0].clone();
            v[key].as_array_mut().unwrap().push(extra);
            assert!(validate_observer(&v).is_err());
        }
        let mut v = observer();
        v["diagnostic_replays"][1] = v["diagnostic_replays"][0].clone();
        assert!(validate_observer(&v).is_err());
    }
    #[test]
    fn fleet_rejects_unbound_stale_range_policy_inventory_and_roles() {
        for (key, value) in [
            ("observer_receipt", json!("/other.json")),
            ("observer_sha256", json!("b".repeat(64))),
            ("sampled_at_utc", json!("2026-10-22T04:27:16Z")),
            ("first_epoch", json!(202)),
            ("last_epoch", json!(301)),
            ("remote_mutations", json!(true)),
            ("publication_authorized", json!(true)),
        ] {
            let mut v = fleet();
            v[key] = value;
            assert!(check_fleet(&v).is_err(), "{key}");
        }
        for (key, value) in [("ready_pairs", 14), ("anomalies", 1)] {
            let mut v = fleet();
            v["inventory"][key] = json!(value);
            assert!(check_fleet(&v).is_err());
        }
        for i in 0..3 {
            for (key, value) in [
                ("InvocationID", json!("other")),
                ("NRestarts", json!("1")),
                ("MainPID", json!("0")),
                ("MainPID", json!("124")),
            ] {
                let mut v = fleet();
                v["active"][i]["producer"][key] = value;
                assert!(check_fleet(&v).is_err());
            }
            let mut v = fleet();
            v["active"][i]["phase"] = json!("upload");
            assert!(check_fleet(&v).is_err());
            let mut v = fleet();
            v["active"][i]["epoch"] = json!(227);
            assert!(check_fleet(&v).is_err());
        }
        let mut v = fleet();
        v["active"].as_array_mut().unwrap().pop();
        assert!(check_fleet(&v).is_err());
        let mut v = fleet();
        let extra = v["active"][0].clone();
        v["active"].as_array_mut().unwrap().push(extra);
        assert!(check_fleet(&v).is_err());
    }
    #[test]
    fn readonly_lease_excludes_another_holder_and_rejects_links_modes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lease");
        fs::write(&path, b"fixed lease\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let held = lease(&path).unwrap();
        assert!(lease(&path).is_err());
        drop(held);
        drop(lease(&path).unwrap());
        let link = dir.path().join("symlink");
        symlink(&path, &link).unwrap();
        assert!(lease(&link).is_err());
        let hard = dir.path().join("hardlink");
        fs::hard_link(&path, &hard).unwrap();
        assert!(lease(&path).is_err());
        fs::remove_file(hard).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(lease(&path).is_err());
        assert!(lease(dir.path()).is_err());
    }
}
