//! Build with `--features independent166` to select the two stopped epoch 166 AccountsDb trees.
//! The paid check opens all three existing leases, captures two identical descriptor-relative
//! inventories, and hashes the original bootstrap, worker and compact indexes. The sealed
//! execute step revalidates those identities and removes only inventoried AppendVecs.
//! A completed check is bound to its own manifest, binary and run. No release is credited globally.
use super::*;
use std::collections::BTreeSet;
use std::os::{fd::AsRawFd, unix::fs::FileExt};

#[cfg(not(feature = "standard170"))]
mod generation {
    pub const EPOCH: u64 = 166;
    pub const SLOT: &str = "71711708";
    pub const ACCOUNTS_HASH: &str = "73JLv83cyRgHUNxtajhwXimfDSH4GUmu6R8LHKPbxu76";
    pub const SNAPSHOT_BYTES: u64 = 1968014870;
    pub const RETRY9_ATTEMPT: &str = "replacement-local3retry9-20261110-v1";
    pub const RETRY10_ATTEMPT: &str = "replacement-local3retry10-20261121-v1";
    pub const RETRY9_INODE: u64 = 94651424;
    pub const RETRY10_INODE: u64 = 103623935;
    pub const RETRY9_CAP: u64 = 288 << 30;
    pub const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-independent-closed-accounts-20261122-v1";
    pub const PROFILE: &[u8] = include_bytes!("profiles166.json");
    pub const CHECK_SCHEMA: &str = "horizon166-independent-closed-accounts-check-v1";
    pub const COMPLETE_SCHEMA: &str = "horizon166-independent-closed-accounts-complete-v1";
    pub const LANE: &str = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1";
    pub const SNAPSHOT: &str =
        "snapshot-71711708-73JLv83cyRgHUNxtajhwXimfDSH4GUmu6R8LHKPbxu76.tar.zst";
    pub const SNAPSHOT_SHA: &str =
        "1e8fa388737b80a9e2218cd09f2fee43b064e19a65e26e466abda25d5e3688f4";
    pub const FINGERPRINT: &str =
        "sha256:08b441e89d7c9456aba5026ce206db8e08a14f96cb31cbad94a4a5c5e6e5622b";
    pub const RETRY9: &str = "fa16ee2f14fe44ecbc37c59e197553ac";
    pub const RETRY10: &str = "3c220efd0d0740f59572a96447e83762";
    pub const CAP: u64 = 288 << 30;
}
#[cfg(feature = "standard170")]
#[path = "closed170.rs"]
mod generation;
use generation::{
    ACCOUNTS_HASH, CAP, EPOCH, FINGERPRINT, LANE, RETRY9, RETRY9_ATTEMPT, RETRY9_CAP, RETRY9_INODE,
    RETRY10, RETRY10_ATTEMPT, RETRY10_INODE, SLOT, SNAPSHOT, SNAPSHOT_BYTES, SNAPSHOT_SHA,
};
pub(super) use generation::{BASE, CHECK_SCHEMA, COMPLETE_SCHEMA, PROFILE};
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";

fn open_file(row: &Value) -> Result<File> {
    let path = Path::new(string(row, "path")?);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.nlink() == 1
            && m.dev() == DEVICE
            && row["device"] == m.dev()
            && row["inode"] == m.ino()
            && row["mode"] == m.mode()
            && row["uid"] == m.uid()
            && row["gid"] == m.gid()
            && row["size"] == m.len()
            && row["mtime_ns"] == m.mtime() * 1_000_000_000 + m.mtime_nsec()
            && row["ctime_ns"] == m.ctime() * 1_000_000_000 + m.ctime_nsec(),
        "changed retained file {}",
        path.display()
    );
    Ok(file)
}
fn checksum(row: &Value, expected: &str) -> Result<()> {
    let mut file = open_file(row)?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest)?;
    ensure!(
        format!("{:x}", digest.finalize()) == expected,
        "retained input hash differs"
    );
    open_file(row)?;
    Ok(())
}

pub(super) fn leases(manifest: &Value) -> Result<Vec<File>> {
    let mut held = Vec::new();
    // All three are existing regular lease files. The operation lock is held by the caller.
    for row in [
        &manifest["lock"],
        &manifest["profiles"]["local3retry9"]["lease"],
        &manifest["profiles"]["local3retry10"]["lease"],
    ] {
        let file = open_file(row)?;
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "operation or epoch lease already held: {}",
            row["path"]
        );
        held.push(file);
    }
    Ok(held)
}

fn names(path: &Path) -> Result<BTreeSet<String>> {
    fs::read_dir(path)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 directory member"))
        })
        .collect()
}
fn sorted(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn check_runtime(row: &Value) -> Result<()> {
    let target = Path::new(string(row, "target")?);
    let retry10 = row["attempt"] == "local3retry10";
    let expected = if retry10 {
        (RETRY10_ATTEMPT, RETRY10_INODE, RETRY10, "filesystem-floor")
    } else {
        (
            RETRY9_ATTEMPT,
            RETRY9_INODE,
            RETRY9,
            "DATA-fulfillment-observation-failed",
        )
    };
    ensure!(
        (retry10 || row["attempt"] == "local3retry9")
            && row["iid"] == expected.2
            && row["inode"] == expected.1
            && target.starts_with(Path::new(LANE).join(expected.0).join("private"))
            && target.file_name().is_some_and(|n| n == "accounts-state")
            && fs::symlink_metadata(target)?.ino() == expected.1
            && target.canonicalize()? == target,
        "unknown stopped worker or scope"
    );
    for key in ["unit", "guard", "timer"] {
        closed(string(row, key)?)?;
    }
    let stopped = bound(&row["stop"])?;
    let intent = bound(&row["intent"])?;
    let plan = bound(&row["plan"])?;
    let admission = bound(&row["admission"])?;
    let proof = bound(&row["protection"])?;
    let retirement = bound(&row["retirement"])?;
    ensure!(
        plan["unit"] == row["unit"]
            && plan["invocation_id"] == row["iid"]
            && plan["worker_root"] == LANE
            && plan["maximum_root_physical_bytes"] == (if retry10 { CAP } else { RETRY9_CAP })
            && admission["epoch"] == EPOCH
            && admission["producer_unit"] == row["unit"]
            && admission["producer_invocation_id"] == row["iid"]
            && proof["admission"] == row["admission"]
            && proof["producer_invocation_id"] == row["iid"]
            && stopped["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && stopped["producer_invocation_id"] == row["iid"]
            && stopped["intent"] == row["intent"]["path"]
            && stopped["plan_sha256"] == row["plan"]["sha256"]
            && intent["plan_sha256"] == stopped["plan_sha256"]
            && intent["producer_invocation_id"] == row["iid"]
            && intent["reason"] == expected.3
            && stopped["terminal"]["active"] == "inactive"
            && stopped["terminal"]["sub"] == "dead"
            && stopped["terminal"]["pid"] == 0
            && stopped["terminal"]["restarts"] == 0
            && stopped["scratch_deleted"] == false
            && stopped["remote_mutations"] == false,
        "incorrect owner or stop"
    );
    let launch = bound(&row["launch"])?;
    let args = if retry10 {
        ensure!(
            admission["actual_guard_plan"] == row["plan"]
                && proof["worker_sha256"] == WORKER_SHA
                && retirement["binding"]["admission"] == row["admission"]
                && retirement["binding"]["producer_invocation_id"] == row["iid"],
            "different retry10 guard and terminal"
        );
        {
            #[cfg(not(feature = "standard170"))]
            {
                &launch["baseline"]["profile"]["producer_argv"]
            }
            #[cfg(feature = "standard170")]
            {
                &launch
            }
        }
    } else {
        ensure!(
            admission["fresh_admission_passed"] == true
                && proof["plan"] == row["plan"]
                && retirement["expected"][EPOCH.to_string()]["producer_invocation_id"]
                    == row["iid"],
            "different retry9 guard and terminal"
        );
        &launch
    };
    let args = args.as_array().context("missing producer argv")?;
    for arg in [
        "--setenv=JETSTREAMER_CLEAR_ACCOUNTS_ON_START=true",
        "--setenv=JETSTREAMER_LOAD_FROM_DIR=0",
    ] {
        ensure!(
            args.iter().any(|a| a == arg),
            "missing cold initialization setting"
        );
    }
    ensure!(
        args.last()
            .and_then(Value::as_str)
            .is_some_and(|a| a.starts_with("--snapshot-archive=")
                && Path::new(a).file_name().is_some_and(|n| n == SNAPSHOT)),
        "unrecognized bootstrap argument"
    );
    let run = Path::new(string(row, "run")?);
    let files = row["preserved"]
        .as_array()
        .context("missing retained files")?;
    ensure!(
        files.len() == 5
            && Path::new(string(&files[0], "path")?)
                == run.join(format!("archives/epoch-{EPOCH}.jet"))
            && Path::new(string(&files[3], "path")?) == run.join("cohort-state.json")
            && Path::new(string(&files[4], "path")?)
                == Path::new(LANE).join(expected.0).join("producer.log"),
        "unexpected archive, state or log scope"
    );
    let runtime = target.parent().context("missing runtime")?;
    ensure!(
        run.starts_with(Path::new(LANE).join(expected.0))
            && target.starts_with(run.join("scratch/.historical-runtime"))
            && names(runtime)? == sorted(&["accounts-state", "unpacked", "genesis-unpacked"])
            && names(&runtime.join("unpacked/snapshots"))? == sorted(&[SLOT, "status_cache"])
            && names(&runtime.join("unpacked/snapshots").join(SLOT))? == sorted(&[SLOT])
            && Path::new(string(&files[2], "path")?)
                == runtime.join("unpacked/snapshots").join(SLOT).join(SLOT),
        "unexpected retained bank or new checkpoint"
    );
    for f in files.iter().chain([&row["bound_worker"]]) {
        ensure!(
            !Path::new(string(f, "path")?).starts_with(target),
            "protected object intersects target"
        );
        open_file(f)?;
    }
    let state = fs::read(string(&files[3], "path")?)?;
    let cohort: Value = serde_json::from_slice(&state)?;
    ensure!(
        sha(&state) == row["cohort_sha256"]
            && cohort["status"] == "running-private"
            && cohort["start_epoch"] == EPOCH
            && cohort["end_epoch"] == EPOCH
            && cohort["manifest_fingerprint"] == FINGERPRINT,
        "changed retained private state"
    );
    let mark = &row["native_checkpoint"];
    let length = mark["length"]
        .as_u64()
        .context("missing checkpoint length")?;
    ensure!(
        length <= 4096 && files[4]["uid"] == 0,
        "unexpected log capture"
    );
    let mut segment = vec![0; length as usize];
    open_file(&files[4])?.read_exact_at(
        &mut segment,
        mark["offset"].as_u64().context("missing log offset")?,
    )?;
    let log = std::str::from_utf8(&segment)?;
    ensure!(
        sha(&segment) == mark["sha256"]
            && log.contains(&format!("checkpoint slot={SLOT} "))
            && log.contains(&format!("accounts_hash={ACCOUNTS_HASH} "))
            && log.contains("complete=true"),
        "original node did not accept the bootstrap"
    );
    Ok(())
}

pub(super) fn gates(profile: &Value, manifest: &Value) -> Result<Value> {
    let rows = manifest["profiles"].as_object().context("no profiles")?;
    ensure!(
        rows.len() == 2 && rows.get(string(profile, "attempt")?) == Some(profile),
        "foreign account scope"
    );
    for key in ["local3retry9", "local3retry10"] {
        check_runtime(&rows[key])?;
    }
    let target = Path::new(string(profile, "target")?);
    let package = bound(&manifest["stock_package"])?;
    let members = package["members"].as_array().context("package members")?;
    ensure!(
        members
            .iter()
            .any(|m| m["name"] == "jetstreamer-node" && m["sha256"] == NODE_SHA)
            && members
                .iter()
                .any(|m| m["name"] == "jetstreamer-historical-worker-v1-5-6"
                    && m["sha256"] == WORKER_SHA),
        "different sealed stock worker"
    );
    let prepared = bound(&manifest["prepared"])?;
    let retained = manifest["indexes"]
        .as_array()
        .context("missing retained index manifest")?;
    #[cfg(not(feature = "standard170"))]
    let (actual, source_key) = {
        let original = &prepared["baseline"]["snapshot"];
        ensure!(
            prepared["epoch"] == 166
                && prepared["worker_sha256"] == WORKER_SHA
                && prepared["node_sha256"] == NODE_SHA
                && original == &manifest["root_snapshot"]
                && original["generation"] == 1634787359098769u64
                && original["length"] == 1968014870
                && original["sha256"] == SNAPSHOT_SHA,
            "different bank input"
        );
        let actual = prepared["baseline"]["profile"]["indexes"]
            .as_array()
            .context("missing source indexes")?;
        (actual.as_slice(), "path")
    };
    #[cfg(feature = "standard170")]
    let (actual, source_key) = generation::validated_indexes(&prepared, manifest)?;
    ensure!(
        retained.len() == 3 && actual.len() == 3,
        "incorrect index inventory"
    );
    for (f, source) in retained.iter().zip(actual) {
        ensure!(
            f["path"] == source[source_key]
                && f["sha256"] == source["sha256"]
                && f["size"] == source["identity"][2]
                && !Path::new(string(f, "path")?).starts_with(target),
            "changed compact index"
        );
        open_file(f)?;
    }
    witness_disjoint(target, &manifest["witness"])?;
    Ok(
        json!({"owner":profile["iid"],"scope":target,"sources":manifest["prepared"],"stops":[rows["local3retry9"]["stop"],rows["local3retry10"]["stop"]],"bootstrap_slot":SLOT.parse::<u64>()?,"witness":manifest["witness"]}),
    )
}

pub(super) fn check_inventory(
    p: &Value,
    manifest: &Value,
    ledger: &stopped_tree::Ledger,
    allocated: u64,
) -> Result<()> {
    check_appendvecs(p, ledger, allocated, CAP)?;
    #[cfg(not(feature = "standard170"))]
    if p["attempt"] == "local3retry9" {
        let census = bound(&manifest["earlier_census"])?;
        ensure!(
            census["two_identical_metadata_walks"] == true
                && census["files"] == (ledger.len() - 5) as u64
                && census["original"]["target"]["inode"] == p["inode"]
                && p["expected_entries"] == (ledger.len() - 1) as u64
                && p["expected_bytes"] == allocated,
            "retry9 diverged from previous census"
        );
    }
    #[cfg(feature = "standard170")]
    ensure!(
        p["expected_entries"] == (ledger.len() - 1) as u64 && p["expected_bytes"] == allocated,
        "closed 170 files differ from the enrolled physical scopes"
    );
    // Protect the operation's recovery inputs by proving contents only in the paid check.
    let snap = &p["preserved"][1];
    ensure!(
        Path::new(string(snap, "path")?)
            .file_name()
            .is_some_and(|n| n == SNAPSHOT)
            && snap["size"] == SNAPSHOT_BYTES,
        "missing complete bootstrap"
    );
    checksum(snap, SNAPSHOT_SHA)?;
    checksum(&p["bound_worker"], WORKER_SHA)?;
    for f in manifest["indexes"].as_array().context("missing indexes")? {
        checksum(f, string(f, "sha256")?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Runs only when explicitly selected on the original host under its private receipt reader.
    /// This opens small metadata records and original log windows. No lock, tree walk or deletion.
    #[test]
    #[ignore = "requires the original stopped 166 host and private receipts"]
    fn authentic_inputs_and_changed_scope_controls() {
        let original: Value = serde_json::from_slice(PROFILE).unwrap();
        for attempt in ["local3retry9", "local3retry10"] {
            let expected = &original["profiles"][attempt];
            gates(expected, &original).unwrap();
            for (key, bad) in [
                ("iid", json!("00000000000000000000000000000000")),
                ("target", expected["run"].clone()),
                ("inode", json!(0)),
                ("unit", json!("horizon-qualify-wrong.service")),
                ("cohort_sha256", json!("00")),
                (
                    "native_checkpoint",
                    json!({"offset":0,"length":20,"sha256":"00"}),
                ),
            ] {
                let mut changed = original.clone();
                changed["profiles"][attempt][key] = bad;
                assert!(
                    gates(&changed["profiles"][attempt], &changed).is_err(),
                    "{attempt} {key}"
                );
            }
        }
    }

    #[test]
    fn rejects_banks_snapshots_aliases_and_file_shaped_directories() {
        for name in ["", "0", "1", "2", "3"] {
            assert!(appendvec_name(name, true));
        }
        for name in ["0/71711708.0", "3/71954303.193"] {
            assert!(appendvec_name(name, false));
        }
        for name in [
            "0/71711708",
            "0/snapshot.tar",
            "0/1.2/3",
            "4/1.2",
            "0/1.2.3",
            "0/../1.2",
            "0/+1.2",
            "0/1.",
            "/0.1",
        ] {
            assert!(!appendvec_name(name, false));
        }
        assert!(!appendvec_name("0/1.2", true));
        assert!(!appendvec_name("3", false));
    }
}
