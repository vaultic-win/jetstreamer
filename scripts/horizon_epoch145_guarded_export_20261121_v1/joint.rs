//! Read-only fit for the 136 writer. The active 145 image and the read-only
//! observer are independently identified. An empty handoff gap is never ready.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

const AFTER_TRACE: bool = cfg!(all(joint145_only, partial145_only, materialized145_only));
pub(super) const RECOVERY: &str = "5dfb817906f74b73a27f61a386751d75";
const RECOVERY_IMAGE: &str = "f8c57a5c069ee60430221c16534d3fb5b265e62f5d554ad9a3dd8c71404179a6";
const RECOVERY_SEAL: &str = "d0152a51339f3a867ae3e406eb30e5c4b8d8839fb1cc77c0ffee90c00fc91210";
#[cfg(all(joint145_only, partial145_only, materialized145_only))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1/joint-tools-v3/export145";
#[cfg(not(all(joint145_only, partial145_only, materialized145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1/joint-tools-v2/export145";
const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1";
const EXPORT: &str = "de6780b860b3467bae21fbd19176ca14";
const EXPORT_IMAGE: &str = "b143476e50f508fe7f0fb3685dd04c8c321faf44c0e98a191810e181da2c0447";

pub fn receipt(p: &Path) -> Result<(Bound, Value)> {
    if fs::symlink_metadata(p)?.mode() & 0o222 == 0 {
        return joint_candidate::immutable(p);
    }
    let b = custody::binding(p)?;
    let v = custody::evidence(&b)?;
    Ok((b, v))
}
fn binding(path: &Path, digest: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: digest.into(),
    }
}
pub(super) fn route(sha: &str) -> Result<Bound> {
    let image = Path::new(IMAGE);
    let parent = image.parent().unwrap();
    let b = joint_candidate::immutable(&parent.join("staged-phases.json"))?;
    let seal = joint_candidate::immutable(&parent.join("deployment-seal-receipt.json"))?.1;
    ensure!(
        seal["members"].as_array().is_some_and(|a| a
            .iter()
            .any(|m| m["name"] == "staged-phases.json" && m["sha256"] == b.0.sha256))
            && b.1["schema"] == "horizon-145-staged-joint-phases-v1"
            && b.1["provider"] == json!(binding(image, sha))
            && b.1["unit"] == UNIT
            && b.1["holding_lock"] == HOLDING_LOCK
            && b.1["export_invocation_id"] == EXPORT
            && b.1["post_mode"] == "post-full"
            && b.1["publication_mode"] == "publish"
            && b.1["candidate_unit"] == joint_candidate::UNIT
            && b.1["candidate_limit_bytes"] == joint_candidate::LIMIT,
        "next 145 phase route is not sealed to the joint image"
    );
    if AFTER_TRACE {
        ensure!(
            b.1["recovery_invocation_id"] == RECOVERY
                && b.1["recovery_image"]
                    == json!(binding(Path::new(materialized::IMAGE), RECOVERY_IMAGE))
                && b.1["recovery_seal_sha256"] == RECOVERY_SEAL,
            "staged route does not bind the native partial recovery"
        );
    }
    Ok(b.0)
}

fn service() -> Result<Value> {
    joint_candidate::show(
        UNIT,
        "Id,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,ControlGroup,NRestarts,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax",
    )
}
fn paid_output(mode: &str) -> Result<fs::Metadata> {
    let paid = receipt(
        &Path::new(BASE)
            .join("state")
            .join(EXPORT)
            .join("allocated.json"),
    )?
    .1;
    let temp = Path::new(paid["temporary"].as_str().context("145 prepaid file")?);
    let canonical = Path::new(OUTPUT).join("epoch-145.jet");
    let f = if !canonical.try_exists()? && matches!(mode, "run" | "gap" | "recover-full-output") {
        temp
    } else {
        &canonical
    };
    let m = fs::symlink_metadata(f)?;
    ensure!(
        f.parent() == Some(Path::new(OUTPUT))
            && f.canonicalize()? == f
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.dev() == 64512
            && m.ino() == 103237059
            && m.len() <= BYTES
            && (f == temp || m.len() == BYTES)
            && m.blocks() * 512 >= capacity::output_allocation()
            && m.blocks() * 512 <= 105611071488 + (128 << 20),
        "145 prepaid output changed"
    );
    Ok(m)
}
fn verify_recovery(
    native: &Value,
    iid: &str,
    hash: &str,
    fleet: &[String],
    locked: bool,
) -> Result<()> {
    let fit = &native["fresh_fit"];
    ensure!(
        locked
            && iid == RECOVERY
            && hash == RECOVERY_IMAGE
            && native["iid"] == iid
            && native["image"] == hash
            && fit["joint136_enabled"] == false
            && fit["terminal168"]["resource_credit_bytes"] == 0
            && fleet
                == [
                    fit["fleet"]["path"].as_str().context("recovery fleet")?,
                    fit["fleet"]["sha256"]
                        .as_str()
                        .context("recovery fleet hash")?
                ],
        "incompatible recovery differs from its native five-owner fit"
    );
    Ok(())
}
fn phase(sha: &str, staged: &Bound) -> Result<Value> {
    let v = service()?;
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    if v["ActiveState"] == "inactive" {
        ensure!(
            v["Job"] == ""
                && v["MainPID"] == "0"
                && v["ControlPID"] == "0"
                && (!cg.exists()
                    || fs::read_to_string(cg.join("cgroup.events"))?
                        .lines()
                        .any(|v| v == "populated 0")),
            "145 handoff still draining"
        );
        let paid = paid_output("gap")?;
        return Ok(
            json!({"phase":"gap","unit":UNIT,"invocation_id":null,"pid":0,"start_ticks":0,"image":null,
            "seven_capable":false,"activation_compatible":false,"output_device":paid.dev(),"output_inode":paid.ino(),"staged_route":staged}),
        );
    }
    let iid = v["InvocationID"].as_str().context("145 IID")?;
    let pid = v["MainPID"].as_str().context("145 PID")?.parse::<u32>()?;
    ensure!(
        custody::hex(iid, 32)
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["Job"] == ""
            && v["ControlGroup"] == format!("/system.slice/{UNIT}")
            && v["CPUQuotaPerSecUSec"] == "1s"
            && v["MemoryMax"] == "2147483648"
            && v["MemorySwapMax"] == "0"
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::/system.slice/{UNIT}"),
        "foreign 145 owner or funding"
    );
    let ticks = native::ticks(pid)?;
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(
        raw.len() < 1 << 20 && raw.last() == Some(&0),
        "145 native command line"
    );
    let args = raw[..raw.len() - 1]
        .split(|b| *b == 0)
        .map(|b| String::from_utf8(b.to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mode = args.get(1).context("145 phase")?.as_str();
    let old_root = Path::new(BASE).join("deployment-v4/export145");
    let (known, hash) = match mode {
        "recover-full-output" if AFTER_TRACE && iid == RECOVERY => {
            let path = Path::new(materialized::IMAGE);
            let seal = binding(
                &path.with_file_name("deployment-seal-receipt.json"),
                RECOVERY_SEAL,
            );
            custody::bytes(&seal, 1 << 20, true)?;
            (path.to_owned(), RECOVERY_IMAGE)
        }
        "run" if !AFTER_TRACE && iid == EXPORT => (old_root, EXPORT_IMAGE),
        "post-full" | "publish" if args[0] == IMAGE => (PathBuf::from(IMAGE), sha),
        "post-full" | "publish" if args[0] == format!("{ROOT}/joint-tools/export145") => (
            Path::new(ROOT).join("joint-tools/export145"),
            "92e07a4f0531aa86c37cc4a6b916abcd11f9e2586143b2ddf26fa61822a50f63",
        ),
        "post-full" => (
            Path::new(ROOT).join("post-tools/export145"),
            "c22e1758110a36165950c645f8dc8cefd44285d17efd4378eaaa0e36895ece42",
        ),
        "publish" => (
            Path::new(ROOT).join("network-tools/export145"),
            "3850f3ea6936816089b4cacd7da0416564086c75f303d872afd6e577fb907005",
        ),
        _ => anyhow::bail!("unknown 145 phase {mode}"),
    };
    let i = binding(&known, hash);
    ensure!(
        args[0] == known.to_str().unwrap()
            && args.last().is_some_and(|s| s == hash)
            && args.len() == if mode == "publish" { 6 } else { 5 },
        "incorrect 145 native invocation"
    );
    let disk = custody::frozen_identity(&known)?;
    let proc = fs::metadata(format!("/proc/{pid}/exe"))?;
    ensure!(
        proc.dev() == disk.device
            && proc.ino() == disk.inode
            && fs::read_link(format!("/proc/{pid}/exe"))? == known,
        "145 process-image mismatch"
    );
    if known != Path::new(IMAGE) {
        custody::bytes(&i, 64 << 20, true)?;
    }
    let m = paid_output(mode)?;
    let lock = fs::read_to_string("/proc/locks")?.lines().any(|l| {
        let f = l.split_whitespace().collect::<Vec<_>>();
        f.len() == 8
            && f[1..4] == ["FLOCK", "ADVISORY", "WRITE"]
            && f[4] == pid.to_string()
            && f[5] == "fc:00:95818311"
            && f[6..8] == ["0", "EOF"]
    });
    let capable = known == Path::new(IMAGE) && matches!(mode, "post-full" | "publish");
    if mode == "recover-full-output" {
        let start = binding(
            &Path::new(BASE)
                .join("state")
                .join(RECOVERY)
                .join("recovery-started.json"),
            "abfd9eca8c8249e4f1f6b69aaa7ba05c6b970a3d0a932d0087b8cea51e0ff0c2",
        );
        let native = custody::evidence(&start)?;
        verify_recovery(&native, iid, hash, &args[2..4], lock)?;
    }
    let admitted = if capable && lock {
        let label = if mode == "post-full" {
            "full"
        } else {
            "network"
        };
        let started = Path::new(ROOT).join(format!("{label}-{iid}/started.json"));
        if started.try_exists()? {
            let r = receipt(&started)?.1;
            ensure!(
                r["invocation"] == iid
                    && r["fit"]["joint136_enabled"] == true
                    && r["fit"]["charged_cpu_micros"] == 64_000_000
                    && (!AFTER_TRACE || r["fit"]["terminal168"]["resource_credit_bytes"] == 0),
                "joint phase has no complete funding proof"
            );
            true
        } else {
            false
        }
    } else {
        false
    };
    ensure!(
        native::ticks(pid)? == ticks && service()? == v,
        "145 changed during observation"
    );
    Ok(
        json!({"phase":mode,"unit":UNIT,"invocation_id":iid,"pid":pid,"start_ticks":ticks,"image":i,
        "seven_capable":capable,"activation_compatible":admitted,"staged_route":staged,"holding_lock_held":lock,
        "output_device":m.dev(),"output_inode":m.ino()}),
    )
}
pub(super) fn incumbents(fleet: &Value) -> Result<BTreeMap<String, Value>> {
    let mut owners = BTreeMap::new();
    for field in [
        "actual_executing_replays",
        "actual_active_bootstraps",
        "actual_active_private_diagnostics",
    ] {
        for row in fleet[field].as_array().context("fleet rows")? {
            let e = capacity::n(row, "epoch")?;
            if e == 136 {
                continue;
            }
            let unit = row["unit"]["Id"].as_str().context("owner")?;
            let i = row["unit"]["InvocationID"].as_str().context("owner iid")?;
            let (timer, tid) = if let Some(t) = row.get("guard_timer") {
                (t["Id"].clone(), t["InvocationID"].clone())
            } else {
                let b: Bound = serde_json::from_value(row["guard_protection"].clone())?;
                let p = custody::evidence(&b)?;
                ensure!(
                    p["producer_unit"] == unit && p["producer_invocation_id"] == i,
                    "crossed incumbent guard"
                );
                (p["timer_unit"].clone(), p["timer_invocation_id"].clone())
            };
            let t = timer.as_str().context("timer name")?;
            ensure!(
                t.starts_with("horizon-guard-")
                    && t.ends_with(".timer")
                    && custody::hex(tid.as_str().context("timer generation")?, 32),
                "timer scope"
            );
            let native = joint_candidate::show(t, "Id,ActiveState,InvocationID,Job,Triggers")?;
            ensure!(
                native["Id"] == timer
                    && native["ActiveState"] == "active"
                    && native["Job"] == ""
                    && native["InvocationID"] == tid
                    && native["Triggers"] == t.replace(".timer", ".service")
                    && capacity::native_values(unit)?["InvocationID"] == i,
                "incumbent {e} changed"
            );
            ensure!(owners.insert(e.to_string(),json!({"unit":unit,"invocation_id":i,"guard_timer":timer,"guard_timer_invocation_id":tid})).is_none(),"duplicate incumbent");
        }
    }
    ensure!(
        if cfg!(continuity145_only) {
            let epochs = owners
                .keys()
                .map(|k| k.parse())
                .collect::<std::result::Result<BTreeSet<u64>, _>>()?;
            crate::continuity::roster(&epochs)
        } else {
            owners.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == if cfg!(partial145_only) {
                    BTreeSet::from(["166", "167", "169", "170", "172"])
                } else if cfg!(materialized145_only) {
                    BTreeSet::from(["167", "168", "169", "170", "172"])
                } else {
                    BTreeSet::from(["166", "167", "168", "169", "170", "172"])
                }
        },
        "incomplete incumbents"
    );
    Ok(owners)
}
pub fn inspect(fleet: Bound, sha: &str, tail: &[String]) -> Result<()> {
    check_image(sha, Path::new(IMAGE))?;
    let staged = route(sha)?;
    let first = phase(sha, &staged)?;
    let fit = capacity::capture_phase(&fleet, true)?;
    let body: Value = serde_json::from_slice(&custody::bytes(&fleet, 32 << 20, false)?)?;
    let six = incumbents(&body)?;
    let sample = fit.await_existing()?;
    let c = joint_candidate::observe()?;
    match tail {
        [] => ensure!(
            !c.occupied,
            "occupied 136 requires explicit original admission and invocation"
        ),
        [iid, path, digest] => ensure!(
            c.occupied
                && c.identity["invocation_id"] == iid.as_str()
                && c.identity["admission"] == json!(binding(Path::new(path), digest)),
            "136 arguments cross the actual native generation"
        ),
        _ => anyhow::bail!("joint-fit FLEET SHA SELF_SHA [IID ADMISSION ADMISSION_SHA]"),
    }
    let floor = capacity::n(&sample, "protected_bytes")?.max(c.floor);

    fit.topology()?;
    let final_sample = fit.await_existing()?;
    let again = joint_candidate::observe()?;
    ensure!(
        again.armed == c.armed
            && again.identity["invocation_id"] == c.identity["invocation_id"]
            && again.identity["admission"] == c.identity["admission"]
            && again.identity["process_tree"] == c.identity["process_tree"]
            && phase(sha, &staged)? == first
            && incumbents(&body)? == six,
        "joint participants changed"
    );
    let floor = floor
        .max(capacity::n(&final_sample, "protected_bytes")?)
        .max(again.floor);
    let realized = c.realized.min(again.realized);
    let candidate = joint_candidate::Candidate { realized, ..c }.json(floor)?;
    let free = capacity::home()?
        .0
        .min(capacity::n(&sample, "free_bytes")?)
        .min(capacity::n(&final_sample, "free_bytes")?);
    let out = json!({"schema":"horizon-145-136-joint-fit-v1","fleet":fleet,"provider":binding(Path::new(IMAGE),sha),
        "recorded_unix_seconds":custody::now()?,"incumbents":six,"phase145":first,
        "resources":{"existing_cpu_quota_micros":64_000_000,"unfenced_with_candidate_cpu_micros":68_250_000,
            "complete_memory_plus_reserve_bytes":fit.evidence["existing_total_memory"],"available_memory_bytes":sample["available_memory"],
            "required_available_memory_bytes":sample["required_memory"],"free_HOME_bytes":free,"protected_existing_only_bytes":floor},
        "disk_fits":free>=capacity::n(&candidate,"required_total_bytes")?,"candidate":candidate,"actual_native_fit":fit.evidence,
        "replay_launch_authorized":false,"r2_mutations":false});
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[test]
    fn recovery_binds_the_exact_incompatible_phase_and_the_charged_fleet() {
        let native = json!({"iid": RECOVERY, "image": RECOVERY_IMAGE, "fresh_fit": {
            "joint136_enabled": false, "terminal168": {"resource_credit_bytes": 0},
            "fleet": {"path": "/fleet", "sha256": "a".repeat(64)}}});
        let args = ["/fleet".to_owned(), "a".repeat(64)];
        assert!(verify_recovery(&native, RECOVERY, RECOVERY_IMAGE, &args, true).is_ok());
        assert!(verify_recovery(&native, EXPORT, RECOVERY_IMAGE, &args, true).is_err());
        assert!(verify_recovery(&native, RECOVERY, EXPORT_IMAGE, &args, true).is_err());
        assert!(verify_recovery(&native, RECOVERY, RECOVERY_IMAGE, &args, false).is_err());
        assert!(verify_recovery(&native, RECOVERY, RECOVERY_IMAGE, &args[..1], true).is_err());
        let mut wrong = native.clone();
        wrong["fresh_fit"]["joint136_enabled"] = true.into();
        assert!(verify_recovery(&wrong, RECOVERY, RECOVERY_IMAGE, &args, true).is_err());
        let mut wrong = native;
        wrong["fresh_fit"]["terminal168"]["resource_credit_bytes"] = 1.into();
        assert!(verify_recovery(&wrong, RECOVERY, RECOVERY_IMAGE, &args, true).is_err());
    }
}
