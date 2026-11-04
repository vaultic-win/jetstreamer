//! Independent source-only provenance expectation for exact 144 assembly recovery.
//! Never accepts the original continuation's success profile or opens the target.
#[allow(dead_code)]
#[path = "jetstreamer-epoch144-provenance-expectation.rs"]
mod provenance;
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::encode_archive_provenance;
use jetstreamer_node::segment_manifest::HistoricalSegmentManifest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
const UNIT: &str = "horizon-qualify-144-assembly-only-recovery-20261022-v1.service";
const ORIGINAL: &str = "horizon-qualify-144-checkpoint-continuation-20261022-v1.service";
const ORIGINAL_IID: &str = "8fddd3ef045c4fe5b12c7d25f43a4b73";
const TOOL_SHA: &str = "25402432882dc8fdcb7331c34be7a20056c0df13ce0eaec33f571edba9695b97";
const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch144-assembly-only-20261022-v2/epoch-144-assembly-only-v4.jet";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    prefix_manifest: Bound,
    suffix_manifest: Bound,
    assembly_launch: Bound,
    assembly_outcome: Bound,
    output: PathBuf,
}
fn read(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&provenance::bound_file(
        &b.path,
        &b.sha256,
        4 << 20,
        true,
    )?)?)
}
fn shape(p: &Plan, r: &Value, o: &Value) -> Result<()> {
    let iid = r["invocation_id"].as_str().context("assembly launch iid")?;
    ensure!(
        r["schema"] == "jetstreamer-private144-assembly-only-launch-v1"
            && r["unit"] == UNIT
            && r["epoch"] == 144
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && r["assembler_sha256"] == TOOL_SHA
            && r["launched"] == true
            && r["assembly_only_no_replay"] == true
            && r["maximum_runtime_seconds"] == 86400
            && r["maximum_archive_bytes"] == 112u64 << 30,
        "not exact assembly-only launch"
    );
    ensure!(
        o["schema"] == "jetstreamer-private144-assembly-only-v1"
            && o["epoch"] == 144
            && o["unit"] == UNIT
            && o["invocation_id"] == iid
            && o["assembler_sha256"] == TOOL_SHA
            && o["plan"] == r["assembly_plan"]
            && o["private_output"] == SOURCE
            && o["prefix_manifest"] == serde_json::to_value(&p.prefix_manifest)?
            && o["suffix_manifest"] == serde_json::to_value(&p.suffix_manifest)?
            && o["prefix_sha256"]
                == "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273"
            && o["suffix_sha256"]
                == "3df30cabba516ff6de39bfc236fca030e3bb75b45603d88ef7baf7a6d669a414"
            && o["archive_sha256"].as_str().is_some_and(provenance::is_sha)
            && o["archive_bytes"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 112u64 << 30)
            && o["source_archives"] == 2
            && o["slots_merged"] == 432000
            && o["provenance_version"] == 4
            && o["assembly_profile"] == "jetstreamer-epoch144-assembly-only-v1"
            && o["no_replay"] == true,
        "not genuine complete assembly-only outcome"
    );
    timeout(&o["original_terminal"])?;
    for key in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "full_epoch_verified",
        "local_retirement_authorized",
        "replay_launch_authorized",
    ] {
        ensure!(
            r[key] == false,
            "assembly launch cannot supply verification/authority:{key}"
        );
    }
    for v in [r, o] {
        for key in [
            "canonical_sidecar_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            ensure!(v[key] == false, "assembly evidence grants authority:{key}");
        }
    }
    for key in [
        "independent_final_archive_verification_passed",
        "current_plugin_verification_passed",
        "retirement_authorized",
    ] {
        ensure!(
            o[key] == false,
            "assembly outcome cannot supply final verification:{key}"
        );
    }
    Ok(())
}
fn timeout(v: &Value) -> Result<()> {
    ensure!(
        v["InvocationID"] == ORIGINAL_IID
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Result"] == "timeout"
            && v["ActiveState"] == "failed"
            && v["SubState"] == "failed"
            && v["RuntimeMaxUSec"] == "2h"
            && matches!(v["ExecMainStatus"].as_str(), Some("9" | "15" | "1")),
        "original is not exact retained terminal timeout"
    );
    Ok(())
}
fn unit(name: &str) -> Result<Value> {
    let o=Command::new("/usr/bin/systemctl").args(["show",name,"--property=InvocationID,MainPID,NRestarts,Restart,Result,ActiveState,SubState,RuntimeMaxUSec,ExecMainStatus,Type"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 16384,
        "terminal service observation failed"
    );
    Ok(Value::Object(
        std::str::from_utf8(&o.stdout)?
            .lines()
            .map(|s| {
                let (k, v) = s.split_once('=').context("unit property")?;
                Ok((k.into(), json!(v)))
            })
            .collect::<Result<_>>()?,
    ))
}
fn terminal(v: &Value, iid: &str) -> Result<()> {
    ensure!(
        v["InvocationID"] == iid
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Type"] == "exec"
            && v["RuntimeMaxUSec"] == "1d"
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && v["ActiveState"] == "active"
            && v["SubState"] == "exited",
        "assembly-only producer not clean terminal"
    );
    Ok(())
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let check = a.len() == 7 && a[6] == "--check-only";
    ensure!(
        (a.len() == 6 || check)
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: jetstreamer-epoch144-assembly-expectation PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    provenance::bound_file(
        &std::fs::read_link("/proc/self/exe")?,
        &a[5],
        128 << 20,
        true,
    )?;
    let p: Plan = serde_json::from_slice(&provenance::bound_file(
        Path::new(&a[1]),
        &a[3],
        1 << 20,
        true,
    )?)?;
    ensure!(
        p.schema == "jetstreamer-private144-assembly-expectation-plan-v1"
            && p.prefix_manifest.sha256
                == "691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a"
            && p.suffix_manifest.sha256
                == "065445bef8d301a45a24ba8e14f34b2c0c06906a9cfe7a06cbfd04eeba3f15ce"
            && p.output
                == Path::new(
                    "/var/lib/jetstreamer/horizon-epoch144-assembly-only-verification-20261022-v1/provenance.json"
                ),
        "foreign assembly expectation plan"
    );
    let prefix: HistoricalSegmentManifest = serde_json::from_value(read(&p.prefix_manifest)?)?;
    let suffix: HistoricalSegmentManifest = serde_json::from_value(read(&p.suffix_manifest)?)?;
    let bytes = encode_archive_provenance(&provenance::derive_pair(&prefix, &suffix, true)?)?;
    if check {
        println!(
            "assembly-only source expectation preflight passed; no outcome,service,target,remote observation or writes; real terminal outcome still required"
        );
        return Ok(());
    }
    let original = unit(ORIGINAL)?;
    timeout(&original)?;
    let r = read(&p.assembly_launch)?;
    let o = read(&p.assembly_outcome)?;
    shape(&p, &r, &o)?;
    let iid = r["invocation_id"].as_str().context("assembly iid")?;
    let own = unit(UNIT)?;
    terminal(&own, iid)?;
    ensure!(
        unit(ORIGINAL)? == original && unit(UNIT)? == own,
        "source producer identity changed"
    );
    provenance::write_receipt(
        &p.output,
        &json!({"schema":"jetstreamer-private144-assembly-only-provenance-expectation-v1","epoch":144,
        "prefix_manifest":p.prefix_manifest,"suffix_manifest":p.suffix_manifest,"assembly_launch":p.assembly_launch,"assembly_outcome":p.assembly_outcome,
        "tool_sha256":a[5],"expected_provenance_sha256":format!("{:x}",Sha256::digest(&bytes)),"expected_provenance_encoded_bytes":bytes.len(),
        "source_manifest_scope_validated":true,"assembly_only_profile_validated":true,"original_terminal_timeout":original,"assembly_terminal_success":own,
        "assembled_target_opened":false,"source_archives_rehashed":false,"independent_final_archive_verification_passed":false,"current_plugin_verification_passed":false,
        "runtime_admission_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_distinct_successful_assembly_outcome_can_supply_expectation_inputs() {
        let b = || Bound {
            path: "/sealed/source".into(),
            sha256: "a".repeat(64),
        };
        let p = Plan {
            schema: "jetstreamer-private144-assembly-expectation-plan-v1".into(),
            prefix_manifest: b(),
            suffix_manifest: b(),
            assembly_launch: b(),
            assembly_outcome: b(),
            output: "/private/output".into(),
        };
        let mut r = json!({"schema":"jetstreamer-private144-assembly-only-launch-v1","unit":UNIT,"epoch":144,"invocation_id":"a".repeat(32),
            "assembler_sha256":TOOL_SHA,"launched":true,"assembly_only_no_replay":true,"maximum_runtime_seconds":86400,
            "maximum_archive_bytes":112u64<<30,"assembly_plan":b()});
        for key in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "full_epoch_verified",
            "local_retirement_authorized",
            "replay_launch_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            r[key] = json!(false);
        }
        let mut o = json!({"schema":"jetstreamer-private144-assembly-only-v1","epoch":144,"unit":UNIT,"invocation_id":r["invocation_id"],"assembler_sha256":TOOL_SHA,
            "plan":r["assembly_plan"],"private_output":SOURCE,"prefix_manifest":p.prefix_manifest,"suffix_manifest":p.suffix_manifest,
            "prefix_sha256":"917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273",
            "suffix_sha256":"3df30cabba516ff6de39bfc236fca030e3bb75b45603d88ef7baf7a6d669a414",
            "archive_sha256":"c".repeat(64),"archive_bytes":109000000000u64,"source_archives":2,"slots_merged":432000,"provenance_version":4,
            "assembly_profile":"jetstreamer-epoch144-assembly-only-v1","no_replay":true,
            "original_terminal":{"InvocationID":ORIGINAL_IID,"MainPID":"0","NRestarts":"0","Restart":"no","Result":"timeout",
                "ActiveState":"failed","SubState":"failed","RuntimeMaxUSec":"2h","ExecMainStatus":"9"}});
        for key in [
            "canonical_sidecar_authorized",
            "publication_authorized",
            "r2_mutations",
            "independent_final_archive_verification_passed",
            "current_plugin_verification_passed",
            "retirement_authorized",
        ] {
            o[key] = json!(false);
        }
        shape(&p, &r, &o).unwrap();
        for (key, v) in [
            (
                "schema",
                json!("jetstreamer-private-epoch144-checkpoint-continuation-v2"),
            ),
            ("assembly_profile", json!("uninterrupted")),
            ("no_replay", json!(false)),
            ("publication_authorized", json!(true)),
            ("slots_merged", json!(431999)),
            ("current_plugin_verification_passed", json!(true)),
        ] {
            let mut bad = o.clone();
            bad[key] = v;
            assert!(shape(&p, &r, &bad).is_err(), "{key}");
        }
    }
    #[test]
    fn original_success_live_or_wrong_invocation_never_becomes_recovery_proof() {
        let good = json!({"InvocationID":ORIGINAL_IID,"MainPID":"0","NRestarts":"0","Restart":"no","Result":"timeout",
            "ActiveState":"failed","SubState":"failed","RuntimeMaxUSec":"2h","ExecMainStatus":"9"});
        timeout(&good).unwrap();
        for (k, v) in [
            ("Result", "success"),
            ("MainPID", "123"),
            ("InvocationID", "different"),
            ("RuntimeMaxUSec", "1d"),
        ] {
            let mut bad = good.clone();
            bad[k] = json!(v);
            assert!(timeout(&bad).is_err());
        }
        let own = json!({"InvocationID":"a".repeat(32),"MainPID":"0","NRestarts":"0","Restart":"no","Type":"exec",
            "RuntimeMaxUSec":"1d","Result":"success","ExecMainStatus":"0","ActiveState":"active","SubState":"exited"});
        terminal(&own, &"a".repeat(32)).unwrap();
        assert!(terminal(&own, ORIGINAL_IID).is_err());
        let mut bad = own;
        bad["SubState"] = json!("running");
        assert!(terminal(&bad, &"a".repeat(32)).is_err());
    }
}
