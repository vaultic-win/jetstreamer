//! Dormant producer/guard source packets. No service mutation or replay launch.
mod epoch251;
mod fifth251;
mod network251;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::Write, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::{Path, PathBuf}};

const BASE: &str = "/var/lib/jetstreamer/horizon249-replay2445-static-v1";
const OUT: &str = "/home/ubuntu/workspace/jetstreamer/tools/horizon250-replacement-source/packet-v2";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1";
const CACHE: &str = "/var/lib/jetstreamer/horizon250-index-reboot-20261117-cache-v1";
const AUTH: &str = "/var/lib/jetstreamer/horizon250-reboot-20261117-input-auth-v1/acceptance.json";
const CAP: &str = "/home/ubuntu/workspace/horizon250-readiness-20261117-v1/index-capability/capability-v4.json";
const PROBE: &str = "/home/ubuntu/.codex/diagnostics/horizon250-sealed-boundary-probe-20261117-v1.json";
const UNIT: &str = "horizon-qualify-250-reboot-20261117-v1.service";
const GUARD: &str = "horizon-250-reboot-20261117-protective-v1.service";
const TIMER: &str = "horizon-250-reboot-20261117-protective-v1.timer";
const TOKENS: &str = "/var/lib/jetstreamer/horizon250-reboot-20261117-tokens-v1";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon250-reboot-20261117-receipts-v1";
const BOUND: &str = "/var/lib/jetstreamer/horizon250-reboot-20261117-guard-v1";
const OLDROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-249-general-shrink-debt-budget506-e3f15eb2-v1";
const BOOTSTRAP: &str = "/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/input/snapshot-107999217-4GDh8KkBUc2Yj6Xa3qLWGVkNSm44i4XSk8PXWSN2s274.tar.zst";
const MANIFEST: &str = "/var/lib/jetstreamer/horizon250-controls2402-v1/preflight-250-target1.json";
const FINGERPRINT: &str = "sha256:7517bfa7560d6d353cd7c683b1491195ccb5fec689a57e2e1a6bb099fe3e7bc4";

fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn bound_json(path: &str, sha: &str) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| path.to_string())?;
    ensure!(digest(&bytes) == sha, "bound evidence changed: {path}");
    Ok(serde_json::from_slice(&bytes)?)
}
fn replace_one(s: &mut String, old: &str, new: &str) -> Result<()> {
    let count = s.matches(old).count();
    ensure!(count == 1, "expected exactly one {old:?}, got {count}");
    *s = s.replacen(old, new, 1); Ok(())
}
fn replace_all(s: &mut String, old: &str, new: &str) -> Result<()> {
    ensure!(s.contains(old), "missing source pattern {old:?}");
    *s = s.replace(old, new); Ok(())
}
fn source(name: &str, sha: &str) -> Result<String> {
    let p = PathBuf::from(BASE).join(name); let bytes = fs::read(&p)?;
    ensure!(digest(&bytes) == sha, "249 source changed: {name}");
    Ok(String::from_utf8(bytes)?)
}
fn producer() -> Result<String> {
    let mut s = source("horizon-qualify-249-general-shrink-debt-budget506-e3f15eb2-v1.service", "21ca5d51711f39c5e30a47f4e680554f7f28f29bd1894da8566e24288175336b")?;
    replace_all(&mut s, OLDROOT, ROOT)?;
    replace_all(&mut s, "/var/lib/jetstreamer/horizon249-general-v1-guard-tokens", TOKENS)?;
    replace_all(&mut s, "/var/lib/jetstreamer/horizon249-index2443-cache-root/sealed-cache-v1", CACHE)?;
    replace_one(&mut s, "Description=General full epoch 249 replay", "Description=General full epoch 250 replay")?;
    let prior_binds = format!("BindReadOnlyPaths={CACHE}:{ROOT}/output/compact-indexes/248 {CACHE}:{ROOT}/output/compact-indexes/249");
    let next_binds = format!("BindReadOnlyPaths={CACHE}:{ROOT}/output/compact-indexes/249 {CACHE}:{ROOT}/output/compact-indexes/250");
    replace_one(&mut s, &prior_binds, &next_binds)?;
    let old_exec = "ExecStart=/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 249 ";
    let new_exec = "ExecStart=/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 250 ";
    replace_one(&mut s, old_exec, new_exec)?;
    replace_one(&mut s, "/var/lib/jetstreamer/horizon249-controls2418-v1/preflight-249-target1.json", MANIFEST)?;
    replace_one(&mut s, "sha256:1eba23638b04526c0ee06e2ddda702eb21c3e9bedb7010729d430b1443d080bc", FINGERPRINT)?;
    replace_one(&mut s, "/var/lib/jetstreamer/horizon-contiguous-249-251-current-46b4b4a-v1/snapshot-107567592-DBPics19TxLy8wawfQYvS65d72vKvFGLCW9HZv5q6GeH.tar.zst", BOOTSTRAP)?;
    let old_read_only = format!("ReadOnlyPaths={TOKENS} {ROOT}/output/compact-indexes");
    let new_read_only = format!("{old_read_only} {ROOT}/input");
    replace_one(&mut s, &old_read_only, &new_read_only)?;
    ensure!(s.contains("ExecStartPre=/usr/bin/sleep 60") && s.contains("ExecStartPre=/usr/bin/test -f") && s.contains("ExecStartPre=/usr/bin/test ! -L"), "prestart gate lost");
    ensure!(s.contains("MemoryMax=251041591296") && s.contains("MemoryHigh=167361060864") && s.contains("CPUQuota=800%") && s.contains("RuntimeMaxSec=259200") && s.contains("Restart=no"), "resource envelope changed");
    ensure!(s.contains("--verify --root-checkpoint-cohort") && s.contains(&format!("--snapshot-archive={BOOTSTRAP}"))
        && s.contains(&format!("ReadOnlyPaths={TOKENS} {ROOT}/output/compact-indexes {ROOT}/input")), "replay route changed");
    ensure!(!s.contains("qualification-249") && !s.contains("horizon249-") && !s.contains(" 249 "), "stale 249 producer source");
    Ok(s)
}
fn guard() -> Result<String> {
    let mut s = source("horizon-249-general-shrink-debt-budget506-protective-v1.service", "7ec76f34533a41c6fcf01c3d4fa0e9d944e259718dbbc294074c73272a412a55")?;
    replace_one(&mut s, "epoch 249 v1", "epoch 250 v1")?;
    replace_all(&mut s, "/var/lib/jetstreamer/horizon249-general-v1-guard-receipts", RECEIPTS)?;
    replace_all(&mut s, "/var/lib/jetstreamer/horizon249-general-v1-guard-bound", BOUND)?;
    ensure!(s.contains("@ACTUAL_SEALED_PLAN_SHA256@") && s.contains("Restart=no") && s.contains("MemoryMax=1073741824"), "guard source changed");
    Ok(s)
}
fn timer() -> Result<String> {
    let mut s = source("horizon-249-general-shrink-debt-budget506-protective-v1.timer", "1c95002f3201dcd4a54b6becdc07bd154b035269e39a40de5d5f89eeb56d19d7")?;
    replace_one(&mut s, "epoch 249 v1", "epoch 250 v1")?;
    replace_one(&mut s, "Unit=horizon-249-general-shrink-debt-budget506-protective-v1.service", &format!("Unit={GUARD}"))?;
    ensure!(s.contains("OnActiveSec=1s") && s.contains("OnUnitInactiveSec=60s"), "guard timer changed");
    Ok(s)
}
fn check_input() -> Result<()> {
    let auth = bound_json(AUTH, "8c7bcf8828827081f6005e0be006aa8bb3b25fb64a03b55dc5ebf1919943bf04")?;
    ensure!(auth["accepted_input_custody"] == true && auth["epoch"] == 250 && auth["bootstrap"]["path"] == BOOTSTRAP && auth["manifest"]["path"] == MANIFEST && auth["replay_launch_authorized"] == false, "250 input binding mismatch");
    let cap = bound_json(CAP, "d158bc2593702a552b9db6edf16b98481cfc169ee949f352ec935a0edeabef73")?;
    ensure!(cap["accepted"] == true && cap["epoch"] == 250 && cap["indexes"].as_array().is_some_and(|items| items.len() == 3) && cap["replay_launch_authorized"] == false, "250 cache capability mismatch");
    let probe = bound_json(PROBE, "2f185dc9bd453c389e8e588b33efa99770e39c1dc05776aaa2fecb2e6ae8338a")?;
    ensure!(probe["exit_code"] == 0 && probe["output"]["epoch"] == 251 && probe["output"]["parent_slot"] == 108431999 && probe["output"]["first_block_slot"] == 108432004 && probe["native_replay_admission_authorized"] == false, "successor probe mismatch");
    let root = fs::symlink_metadata(ROOT)?;
    ensure!(root.is_dir() && root.uid() == 1000 && root.gid() == 1000 && root.mode() & 0o777 == 0o700, "candidate root custody changed");
    ensure!(fs::symlink_metadata(Path::new(ROOT).join("output/genesis.tar.bz2"))?.is_file(), "missing genesis");
    Ok(())
}
fn save(name: &str, bytes: &[u8]) -> Result<Value> {
    let p = PathBuf::from(OUT).join(name);
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o444).open(&p)?;
    f.write_all(bytes)?; f.sync_all()?;
    Ok(json!({"path":p,"sha256":digest(bytes),"bytes":bytes.len()}))
}
fn run() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("prepare-251-fifth") {
        return fifth251::run();
    }
    if std::env::args().nth(1).as_deref() == Some("capture-251-network") {
        return network251::run();
    }
    if std::env::args().nth(1).as_deref() == Some("prepare-251") {
        return epoch251::run();
    }
    ensure!(std::env::args().len() == 1, "no arguments accepted");
    ensure!(!Path::new(OUT).exists(), "source packet already exists");
    check_input()?;
    let producer = producer()?; let guard = guard()?; let timer = timer()?;
    fs::create_dir(OUT)?;
    let files = vec![save(UNIT, producer.as_bytes())?, save(GUARD, guard.as_bytes())?, save(TIMER, timer.as_bytes())?];
    let plan = json!({"schema":"horizon250-replacement-source-plan-v2","candidate_epoch":250,"producer_unit":UNIT,"guard_unit":GUARD,"timer_unit":TIMER,"worker_root":ROOT,"index_cache":CACHE,"input_acceptance":{"path":AUTH,"sha256":"8c7bcf8828827081f6005e0be006aa8bb3b25fb64a03b55dc5ebf1919943bf04"},"index_capability":{"path":CAP,"sha256":"d158bc2593702a552b9db6edf16b98481cfc169ee949f352ec935a0edeabef73"},"successor_probe":{"path":PROBE,"sha256":"2f185dc9bd453c389e8e588b33efa99770e39c1dc05776aaa2fecb2e6ae8338a"},"files":files,"candidate_memory_max_bytes":251041591296u64,"candidate_memory_high_bytes":167361060864u64,"candidate_root_cap_bytes":506191984640u64,"bootstrap_input_read_only":true,"fourth_lane_memory_fit_proven":false,"replacement_requires_terminal_lane_event":true,"service_effective_car_header_route_qualified":true,"fresh_main_admission_accepted":false,"native_replay_qualified":false,"first_guard_fired":false,"replay_launch_authorized":false,"r2_mutations":false,"remote_mutations":false});
    let source_plan = save("source-plan.json", format!("{}\n", serde_json::to_string_pretty(&plan)?).as_bytes())?;
    let mut members: Vec<Value> = files.iter().map(|f| json!({"source":f["path"],"name":Path::new(f["path"].as_str().unwrap()).file_name().unwrap().to_string_lossy(),"sha256":f["sha256"],"mode":292})).collect();
    members.push(json!({"source":source_plan["path"],"name":"source-plan.json","sha256":source_plan["sha256"],"mode":292}));
    members.push(json!({"source":"/var/lib/jetstreamer/horizon250-reboot-20261117-static-v1/service-effective-car-header-proof.json","name":"service-effective-car-header-proof.json","sha256":"b0f4e19f2b2755559138dda7c5823ac9723249e1052928fb9512fffdbb80e9b7","mode":292}));
    let deployment = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":"/var/lib/jetstreamer/horizon250-reboot-20261117-static-v2","members":members});
    save("deployment-plan.json", format!("{}\n", serde_json::to_string_pretty(&deployment)?).as_bytes())?;
    File::open(OUT)?.sync_all()?; File::open(Path::new(OUT).parent().context("packet parent")?)?.sync_all()?;
    println!("{OUT}"); Ok(())
}
fn main() { if let Err(error) = run() { eprintln!("Error: {error:#}"); std::process::exit(1); } }
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn source_templates_keep_exact_route_and_guard() {
        let p = producer().unwrap(); let g = guard().unwrap(); let t = timer().unwrap();
        assert!(p.contains("jetstreamer-node 250 "));
        assert!(p.contains("/compact-indexes/249")); assert!(p.contains("/compact-indexes/250"));
        assert!(p.contains("--cohort-manifest-fingerprint=sha256:7517bfa7560d6d353cd7c683b1491195ccb5fec689a57e2e1a6bb099fe3e7bc4"));
        assert!(g.contains("@ACTUAL_SEALED_PLAN_SHA256@")); assert!(t.contains(&format!("Unit={GUARD}")));
    }
}
