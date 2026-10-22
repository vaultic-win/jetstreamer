//! Exact160 post-replay evidence, never independent verification/publication.
use super::*;
use std::process::Command;
pub(super) const UNIT: &str =
    "jetstreamer-root-sweep-e160-s1-20261020-v1-r2-e160-160-lane-a-1.service";
pub(super) const IID: &str = "f3ec98a134d544e78cb2083f502ed292";
const NODE: &str =
    "/usr/local/lib/jetstreamer/deploy-epoch160-singleton-20261020-v2/jetstreamer-node";
const NODE_SHA: &str = "e987401354f0cddbd838b71439768d6ed84baddfe8c0c2b484addec553db1887";
const MANIFEST: &str = "/usr/local/lib/jetstreamer/deploy-epoch160-singleton-20261020-v2/preflight-160-singleton-v4.json";
const MANIFEST_SHA: &str = "c1e080ec49f5070185fbbb476a5d949e049e4e8d401d33bfbde4966cf80cdc19";
const DEST: &str = "/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1/lane-a/output";
const SNAPSHOT: &str = "/usr/local/lib/jetstreamer/deploy-epoch160-singleton-20261020-v2/snapshot-69119821-BbTHV1PRmaBoqFSxKi1qGwwvsf6SeZPSW9KJj9wcDwEV.tar.zst";
const ARCHIVE: &str = "/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1/lane-a/private/destination-586105dbe82bb0446e1b4c9295bfb7f16e3fc6f70ff439cab2672ef48275f8db/work/root-cohort-160-160/run-1237930-1792459999139141808/archives/epoch-160.jet";
const OUTPUT_ROOT: &str = "/var/lib/jetstreamer/horizon-epoch160-delivery-observations-20261022-v1";
const LENGTH: u64 = 148095631232;
fn owner(v: &Value) -> Result<()> {
    for (k, x) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", IID),
        ("MainPID", "1237930"),
        ("NRestarts", "0"),
    ] {
        ensure!(v[k] == x, "160 finalization owner changed:{k}");
    }
    let command = format!(
        "{{ path={NODE} ; argv[]={NODE} 160 {DEST} --verify --root-checkpoint-cohort --cohort-manifest={MANIFEST} --cohort-manifest-fingerprint=sha256:2e5c41babafac408dca76e0f9f203a5556bc50093bab7e924e65bbc129591266 --snapshot-archive={SNAPSHOT}"
    );
    ensure!(
        v["ExecStart"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .is_some_and(|(a, b)| a == command && b.starts_with("no ;")),
        "160 producer command changed"
    );
    Ok(())
}
pub(super) fn inputs() -> Result<()> {
    for (path, digest, limit) in [
        (NODE, NODE_SHA, 128 << 20),
        (MANIFEST, MANIFEST_SHA, 1 << 20),
    ] {
        let p = Path::new(path);
        let m = fs::symlink_metadata(p)?;
        ensure!(
            p.canonicalize()? == p
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o222 == 0,
            "unsealed160input"
        );
        let b = read_stable_bounded(p, limit, "160 immutable input")?;
        ensure!(
            hex_lower(&Sha256::digest(&b)) == digest,
            "160 immutable input hash differs"
        );
    }
    Ok(())
}
fn events(records: &[Value], sample: u64) -> Result<Value> {
    let mut selected = Vec::new();
    for marker in [
        "historical checkpoint slot=69551776 ",
        "historical checkpoint slot=69551999 ",
        "snapshot verification complete",
        "horizon archive complete:",
    ] {
        let r: Vec<_> = records
            .iter()
            .filter(|r| r["MESSAGE"].as_str().is_some_and(|m| m.contains(marker)))
            .collect();
        ensure!(r.len() == 1, "160 event missing/duplicated:{marker}");
        let r = r[0];
        ensure!(
            r["_SYSTEMD_INVOCATION_ID"] == IID
                && r["_SYSTEMD_UNIT"] == UNIT
                && r["_PID"] == "1237930"
                && r["_UID"] == "1001",
            "160 event owner differs"
        );
        let t = r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("160 event timestamp")?
            .parse::<u64>()?;
        ensure!(
            t > 0 && t <= sample.checked_mul(1_000_000).context("sample overflow")?,
            "160 event after sample"
        );
        selected.push((t, r));
    }
    ensure!(
        selected.windows(2).all(|w| w[0].0 < w[1].0),
        "160 event order differs"
    );
    for (index, slot) in [(0, 69551776), (1, 69551999)] {
        cohort198_finalization::checkpoint(selected[index].1["MESSAGE"].as_str().unwrap(), slot)?;
    }
    let root = cohort198_finalization::fields(
        selected[0].1["MESSAGE"].as_str().unwrap(),
        "historical checkpoint ",
    )?;
    ensure!(
        root["accounts_hash"] == "2Yofackr8rZLb4MRW6Ww8uNmQnH4X8ehiRLnQuSxpjTu",
        "160 trusted manifest root mismatch"
    );
    let close = cohort198_finalization::fields(
        selected[3].1["MESSAGE"].as_str().unwrap(),
        "horizon archive complete: ",
    )?;
    ensure!(
        close.len() == 8
            && cohort198_finalization::integer(&close, "slots")? == 432000
            && cohort198_finalization::integer(&close, "epochs")? == 1
            && cohort198_finalization::integer(&close, "buckets")? == 3375
            && cohort198_finalization::integer(&close, "bytes")? == LENGTH
            && cohort198_finalization::integer(&close, "blocks")? == 387933,
        "160 archive close scope differs"
    );
    for key in ["txs", "tx_updates", "orphan_updates"] {
        cohort198_finalization::integer(&close, key)?;
    }
    Ok(
        serde_json::json!({"schema":"jetstreamer-epoch160-finalization-events-v1","unit":UNIT,"invocation_id":IID,"node_sha256":NODE_SHA,"manifest_sha256":MANIFEST_SHA,"terminal_slot":69551999,"trusted_root_slot":69551776,"events":selected.iter().map(|(_,r)|*r).collect::<Vec<_>>(),"archive_close_bytes":LENGTH,"replay_terminal_observed":true,"independent_full_verification_passed":false,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false}),
    )
}
pub(super) fn observe(v: &Value, sample: u64) -> Result<Value> {
    owner(v)?;
    inputs()?;
    let o=Command::new("/usr/bin/journalctl").args([&format!("_SYSTEMD_INVOCATION_ID={IID}"),&format!("_SYSTEMD_UNIT={UNIT}"),"--grep=historical checkpoint slot=69551776 |historical checkpoint slot=69551999 |snapshot verification complete|horizon archive complete:","-n","16","-o","json","--no-pager"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 1 << 20,
        "160 event journal unreadable/oversized"
    );
    let records: Vec<Value> = std::str::from_utf8(&o.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let proof = events(&records, sample)?;
    let path = Path::new(ARCHIVE);
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 1001
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() == LENGTH
            && path.canonicalize()? == path,
        "160 closed archive identity differs"
    );
    ensure!(
        fleet::unit(UNIT)? == *v,
        "160 owner changed during event observation"
    );
    Ok(
        serde_json::json!({"schema":"jetstreamer-epoch160-finalization-observation-v1","owner":v,"events":proof,"archive":{"path":ARCHIVE,"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"mode":m.mode(),"owner_uid":m.uid()},"archive_hash_performed":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    output: PathBuf,
    not_before_unix_seconds: u64,
    expires_unix_seconds: u64,
}
pub(super) fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        (a.len() == 7 || (a.len() == 8 && a[7] == "--check-only"))
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: observe-delivery-160 PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    for (p, digest, limit) in [
        (exe.as_path(), a[6].as_str(), 128 << 20),
        (Path::new(&a[2]), a[4].as_str(), 1 << 20),
    ] {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o222 == 0
                && p.canonicalize()? == p,
            "unsealed160observer input"
        );
        ensure!(
            hex_lower(&Sha256::digest(read_stable_bounded(
                p,
                limit,
                "160 observer input"
            )?)) == digest,
            "160 observer input digest differs"
        );
    }
    let p: Plan =
        serde_json::from_slice(&read_stable_bounded(Path::new(&a[2]), 1 << 20, "160 plan")?)?;
    let handoff = a[1] == "observe-handoff-160";
    ensure!(
        p.schema
            == if handoff {
                "jetstreamer-epoch160-handoff-observation-plan-v1"
            } else {
                "jetstreamer-epoch160-delivery-observation-plan-v1"
            }
            && p.output.parent() == Some(Path::new(OUTPUT_ROOT))
            && p.output.file_name().is_some_and(|n| n
                == if handoff {
                    "handoff.json"
                } else {
                    "proof.json"
                })
            && p.not_before_unix_seconds > 0
            && p.expires_unix_seconds
                .checked_sub(p.not_before_unix_seconds)
                .is_some_and(|n| n > 0 && n <= 1800),
        "foreign160observation plan"
    );
    resource_audit::private_directory(Path::new(OUTPUT_ROOT))?;
    ensure!(!p.output.try_exists()?, "160 proof already exists");
    let before = fleet::unit(if handoff {
        cohort160_handoff::CONTROLLER
    } else {
        UNIT
    })?;
    if handoff {
        cohort160_handoff::owner(&before)?;
    } else {
        owner(&before)?;
    }
    inputs()?;
    if a.len() == 8 {
        println!("exact160 owner inputs valid; no resource sample, proof, archive or R2 mutation");
        return Ok(());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        (p.not_before_unix_seconds..=p.expires_unix_seconds).contains(&now),
        "160 proof outside event window"
    );
    let proof = if handoff {
        cohort160_handoff::observe(&before, now)?
    } else {
        observe(&before, now)?
    };
    cohort198_finalization::write_observation(
        &p.output,
        &serde_json::json!({"schema":"jetstreamer-epoch160-delivery-proof-v1","observed_unix_seconds":now,"plan":a[2],"plan_sha256":a[4],"observer_sha256":a[6],"evidence":proof,"resource_samples":0,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    println!("{}", p.output.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn records() -> Vec<Value> {
        let messages = [
            "historical checkpoint slot=69551776 bank_hash=4PzBniKhw7o9Di7YUumYts4QK8wFud7bFmyttWqPA3Fe accounts_hash=2Yofackr8rZLb4MRW6Ww8uNmQnH4X8ehiRLnQuSxpjTu last_blockhash=HNuCAV7H6QcfEHzFyShgNHYkd6pqmBVQeegqRqZSYWCD capitalization=490924553509189701 transactions=13656905022 tick_height=4451313728 complete=true writes=39 next_write_version=48194287518",
            "historical checkpoint slot=69551999 bank_hash=A5ekHRqopuZW1qa4Js8V88NmX4Ew3HHSReJg5TMyAVVK accounts_hash=EoJ4x4Zp8EDEtXidn1t3LQjEz3JJmcyFyKGGuJ4En5ar last_blockhash=9CpmwXYeYgoX6M31wP4PuGeo2FMSABEpaF1fLtK6sKhf capitalization=490924553254693210 transactions=13656990000 tick_height=4451328000 complete=true writes=43 next_write_version=48194534652",
            "snapshot verification complete",
            "horizon archive complete: slots=432000 blocks=387933 txs=217130710 tx_updates=546643689 orphan_updates=26444320 epochs=1 buckets=3375 bytes=148095631232 (payload 895569840694 uncompressed)",
        ];
        messages.into_iter().enumerate().map(|(i,m)|serde_json::json!({"MESSAGE":m,"_SYSTEMD_INVOCATION_ID":IID,"_SYSTEMD_UNIT":UNIT,"_PID":"1237930","_UID":"1001","__REALTIME_TIMESTAMP":((i+1)*1000000).to_string()})).collect()
    }
    #[test]
    fn exact160_terminal_is_observational_not_archive_or_remote_verification() {
        let r = records();
        let proof = events(&r, 5).unwrap();
        assert_eq!(proof["independent_full_verification_passed"], false);
        for key in [
            "_SYSTEMD_INVOCATION_ID",
            "_SYSTEMD_UNIT",
            "_PID",
            "_UID",
            "MESSAGE",
            "__REALTIME_TIMESTAMP",
        ] {
            let mut bad = r.clone();
            bad[1][key] = serde_json::json!("foreign");
            assert!(events(&bad, 5).is_err(), "{key}");
        }
        let mut bad = r.clone();
        bad.push(r[0].clone());
        assert!(events(&bad, 5).is_err());
        assert!(events(&r, 2).is_err());
        let mut bad = r;
        bad[0]["MESSAGE"] = serde_json::json!(bad[0]["MESSAGE"].as_str().unwrap().replace(
            "2Yofackr8rZLb4MRW6Ww8uNmQnH4X8ehiRLnQuSxpjTu",
            "A5ekHRqopuZW1qa4Js8V88NmX4Ew3HHSReJg5TMyAVVK"
        ));
        assert!(events(&bad, 5).is_err());
    }
}
