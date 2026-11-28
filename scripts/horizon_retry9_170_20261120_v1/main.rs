//! Read-only witness planning for a standard-root 170 retry9 alongside independent 166 and 167.
mod config;
#[path = "../horizon_170_join_independent166_20261120_v1/peer.rs"]
mod peer;
mod terminal8;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, os::unix::fs::MetadataExt, path::Path};
const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1";
const GUARD_SHA: &str = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016";
const ROOTS: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/SUCCESSOR_ROOTS_BEFORE_WITNESS.json";
const ROOTS_SHA: &str = "5b1d793e46d51361bb4b43c7ccc74693cca57c8b65ffe28734b7cd3ffb560fb0";
const LANE: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1";
const ATTEMPT: &str = "replacement-local3retry7-20261110-v1/replacement-local3retry9-20261110-v1";
const BOOKING: &str = "/var/lib/jetstreamer/epoch167-retry6-zeropeer-20261118-v1/ROOT_DATA_BOOKING-20261119T0647Z.json";
const BOOKING_SHA: &str = "4b51da0a5b2c60f4039edca0f66a99c6acf46182c8cf9f89dee467d6f5d7d38c";
fn check_root() -> Result<u64> {
    let dest = Path::new(LANE).join(ATTEMPT);
    let r = peer::bound(&peer::pair(ROOTS, ROOTS_SHA))?;
    ensure!(
        r["predecessor_event_sha256"] == terminal8::event()["sha256"]
            && r["live_peer_epochs"] == json!([166, 167]),
        "wrong successor root lineage"
    );
    let rows = r["roots"].as_array().context("precreation rows")?;
    let matched: Vec<_> = rows.iter().filter(|x| x["epoch"] == 170).collect();
    ensure!(
        matched.len() == 1 && matched[0]["path"] == json!(dest),
        "wrong precreated170 path"
    );
    let m = fs::symlink_metadata(&dest)?;
    let device = fs::metadata("/home/sol")?.dev();
    ensure!(
        dest.canonicalize()? == dest
            && m.is_dir()
            && m.mode() & 0o7777 == 0o700
            && m.uid() == 1001
            && m.gid() == 1003
            && m.dev() == device
            && matched[0]["dev"] == device
            && matched[0]["ino"] == m.ino()
            && fs::read_dir(&dest)?.next().is_none(),
        "170 successor no longer empty or precreated"
    );
    let mut stack = vec![Path::new(LANE).to_owned()];
    let mut seen = BTreeSet::new();
    let mut bytes: u64 = 0;
    while let Some(p) = stack.pop() {
        let m = fs::symlink_metadata(&p)?;
        ensure!(m.dev() == device, "foreign DATA mount: {}", p.display());
        if !seen.insert((m.dev(), m.ino())) {
            continue;
        }
        bytes = bytes
            .checked_add(m.blocks().checked_mul(512).context("block overflow")?)
            .context("allocation overflow")?;
        if m.is_dir() {
            for child in fs::read_dir(&p)? {
                stack.push(child?.path());
            }
        }
    }
    ensure!(
        bytes > 0 && bytes < peer::CAP,
        "170 root cap already exhausted"
    );
    Ok(bytes)
}
fn guard_argv(output: &Path) -> Result<Vec<String>> {
    let guard = Path::new(BASE).join("guard-v1/guard");
    ensure!(
        format!("{:x}", Sha256::digest(fs::read(&guard)?)) == GUARD_SHA,
        "170 guard changed"
    );
    let parent = output
        .parent()
        .context("output parent")?
        .parent()
        .context("generation parent")?;
    ensure!(
        output.file_name().and_then(|x| x.to_str()) == Some("NATIVE_WITNESS.json")
            && parent == Path::new(BASE).join("stage-state")
            && output
                .parent()
                .and_then(Path::file_name)
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.starts_with("guard-witness-")
                    && x.len() > 14
                    && x.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
            && !output.try_exists()?,
        "fresh witness must be under a new HOME stage-state guard-witness generation"
    );
    Ok([guard.to_str().context("guard path")?,"--qualify-data-witness","/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/witness-set.json","--seed-sha256","8eb041519cba5c3f6368cb1432be9e289489ce1acdc28aa8b49f3d6ec7f382ee","--seal","/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/deployment-seal-receipt.json","--seal-sha256","611c29b18c52e02fce0be67314cdaae4ff780bea72b0e8e6c22a7dd248dfc24f","--output",output.to_str().context("output path")?,"--self-sha256",GUARD_SHA].into_iter().map(String::from).collect())
}
fn prepare_witness(output: &Path) -> Result<Value> {
    let e = peer::evidence()?;
    peer::live(&e)?;
    ensure!(e["active167"].is_object(), "epoch167 retry8 must be active");
    let bytes = check_root()?;
    let argv = guard_argv(output)?;
    let b = peer::pair(BOOKING, BOOKING_SHA);
    let old = peer::bound(&b)?;
    ensure!(
        old["epoch"] == 167
            && old["candidate_root_cap_bytes"] == 512u64 << 30
            && old["complete_DATA_bytes"] == 6_794_761_027_378u64
            && old["raw_floor_bytes"] == peer::FLOOR
            && old["all_prior_promises_retained"] == true
            && old["resource_promise_ending_bytes"] == 0,
        "historical167 reservation changed"
    );
    peer::live(&e)?;
    Ok(
        json!({"schema":"horizon-170-one-peer-witness-request-v1","epoch":170,"attempt":"local3retry9","active166":e["active166"],"active167":e["active167"],"terminal167":e["terminal167"],"post_guard_capacity166":e["post_guard_capacity"],"retained167_booking":b,"historical_170_lane":LANE,"precreated_roots":peer::pair(ROOTS,ROOTS_SHA),"current_170_physical_bytes":bytes,"original_170_cap_bytes":peer::CAP,"remaining_original_170_headroom_bytes":peer::CAP-bytes,"guard_argv":argv,"replay_admission_authorized":false,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).is_some_and(|a| a == "stage-config") {
        println!("{}", config::config(&args[2..])?);
        return Ok(());
    }
    ensure!(
        args.len() == 3 && args[1] == "witness-request",
        "join170 witness-request ABSOLUTE_NEW_WITNESS_PATH"
    );
    println!("{}", prepare_witness(Path::new(&args[2]))?);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_retry9_precreation_binds_the_nested_leaf() {
        let roots = peer::bound(&peer::pair(ROOTS, ROOTS_SHA)).unwrap();
        assert_eq!(roots["live_peer_epochs"], json!([166, 167]));
        assert_eq!(
            roots["roots"][0]["path"],
            json!(Path::new(LANE).join(ATTEMPT))
        );
        assert_eq!(
            roots["predecessor_event_sha256"],
            terminal8::event()["sha256"]
        );
        assert_eq!(
            roots["roots"][0]["ino"],
            fs::symlink_metadata(Path::new(LANE).join(ATTEMPT))
                .unwrap()
                .ino()
        );
    }

    #[test]
    fn genuine_independent166_and_latest_terminal167_are_bound() {
        let e = peer::evidence().unwrap();
        assert_eq!(e["active166"]["main_start_ticks"], 349365780);
        assert_eq!(e["terminal167"]["sha256"], peer::STOP167_SHA);
        let mut capacities = e["retained_capacities"].clone();
        capacities["independent_DATA_obligation"]["independent_physical_cap_bytes"] = json!(0);
        assert!(peer::validate_ledger(&capacities).is_err());
    }
    #[test]
    fn old167_lease_remains_even_with_no_live_peer() {
        let v = peer::bound(&peer::pair(BOOKING, BOOKING_SHA)).unwrap();
        assert_eq!(v["candidate_root_cap_bytes"], 512u64 << 30);
        assert_eq!(v["resource_promise_ending_bytes"], 0);
    }
}
