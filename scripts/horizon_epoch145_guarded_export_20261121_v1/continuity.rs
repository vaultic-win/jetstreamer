//! Resume a frozen 145 verifier after the original 166 and trace168 owners end.
use super::*;
use std::{collections::BTreeSet, os::unix::fs::PermissionsExt};

pub const PREVIOUS: &str = "5dfb817906f74b73a27f61a386751d75";
#[cfg(all(not(early145_only), not(incident145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v3/export145";
#[cfg(incident145_only)]
pub const IMAGE: &str = crate::incident145::IMAGE;
#[cfg(all(early145_only, not(incident145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v4/export145";
pub const REPLACEMENT: &str = "horizon-qualify-168-full-metered-20261121-v1.service";
const METERED: &str = "epoch168-full-metered-20261121-v1";
const ORIGINAL_TRACE: &str = "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2";
const APPEND: &str = "9d8fc46ba227c4875f516d2318b2e397caa8884d058ccb217313ec3ae9071fc4";

fn state(iid: &str) -> PathBuf {
    Path::new(BASE).join("state").join(iid)
}
pub(super) fn failure(iid: &str) -> Result<Value> {
    ensure!(custody::hex(iid, 32), "foreign recovery IID");
    let p = state(iid);
    let f = custody::binding(&p.join("failed.json"))?;
    let v = custody::evidence(&f)?;
    ensure!(
        v["iid"] == iid
            && v["error"].as_str().is_some_and(|e| !e.is_empty())
            && !p.join("complete.json").try_exists()?,
        "missing failed recovery"
    );
    let rows = capacity::run(
        "/usr/bin/journalctl",
        &[
            "--no-pager",
            "-ojson",
            "--output-fields=UNIT,INVOCATION_ID,EXIT_CODE,EXIT_STATUS,_BOOT_ID,MESSAGE_ID",
            "_PID=1",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={iid}"),
            "MESSAGE_ID=98e322203f7a4ed290d09fe03c09fe15",
        ],
        "10",
    )?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let event = rows
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| {
            v["UNIT"] == UNIT
                && v["INVOCATION_ID"] == iid
                && v["_BOOT_ID"] == boot
                && v["EXIT_CODE"] == "exited"
                && v["EXIT_STATUS"] == "1"
        })
        .context("missing manager-confirmed recovery failure")?;
    Ok(json!({"failure":f,"native":event}))
}
pub fn predecessor() -> Result<Value> {
    ensure!(
        native::ticks(3738161).ok() != Some(359708608)
            && native::ticks(3751536).ok() != Some(359803826),
        "original frozen 145 verifier still owns its interval"
    );
    let failed = failure(PREVIOUS)?;
    let p = Bound {
        path: state(PREVIOUS).join("append-complete.json"),
        sha256: APPEND.into(),
    };
    let v = custody::evidence(&p)?;
    ensure!(
        v["source_sha256"] == SOURCE_SHA
            && v["device"] == 64512
            && v["inode"] == 103237059
            && v["prefix_bytes_compared"] == 40_871_330_316u64
            && v["appended"] == 64_739_665_517u64,
        "frozen candidate lost its completed append"
    );
    let previous = json!({"verified_predecessor_failure":failed,"append":p});
    #[cfg(incident145_only)]
    let previous = {
        let mut evidence = previous;
        evidence["failed_preincident_verifier"] = crate::incident145::predecessor()?;
        #[cfg(incident_rejoin145_only)]
        {
            evidence["failed_fresh_census"] = crate::incident145::failed_census()?;
        }
        #[cfg(incident_timeout145_only)]
        {
            evidence["failed_manager_query"] = crate::incident145::failed_manager_query()?;
        }
        #[cfg(incident_focused145_only)]
        {
            evidence["failed_status_owner"] = crate::incident145::failed_status_owner()?;
        }
        #[cfg(incident_timer145_only)]
        {
            evidence["failed_timer_inspection"] = crate::incident145::failed_timer_inspection()?;
        }
        #[cfg(incident_fixture145_only)]
        {
            evidence["failed_qualification_census"] =
                crate::incident145::failed_qualification_census()?;
        }
        #[cfg(incident_homefloor145_only)]
        {
            evidence["failed_retry1"] = crate::incident145::failed_retry1()?;
        }
        #[cfg(incident_v5u_guard_recovery145_only)]
        {
            let v5u = crate::incident145::failed_v5u()?;
            #[cfg(incident_v5v_guard_recovery145_only)]
            {
                evidence["failed_v5v"] = crate::incident145::failed_v5v(&v5u)?;
            }
            evidence["failed_v5u"] = v5u;
        }
        #[cfg(incident_v5w_guard_recovery145_only)]
        {
            let v5w = crate::incident145::failed_v5w()?;
            #[cfg(incident_v5x_guard_recovery145_only)]
            {
                let v5x = crate::incident145::failed_v5x(&v5w).context("V5x predecessor custody")?;
                #[cfg(incident_v5y_guard_recovery145_only)]
                {
                    evidence["failed_v5y"] = crate::incident145::failed_v5y(&v5x).context("V5y predecessor custody")?;
                }
                evidence["failed_v5x"] = v5x;
            }
            evidence["failed_v5w"] = v5w;
        }
        evidence
    };
    Ok(previous)
}
pub fn roster(epochs: &BTreeSet<u64>) -> bool {
    epochs.contains(&172)
        && epochs
            .iter()
            .all(|e| matches!(e, 167 | 168 | 169 | 170 | 172) || cfg!(early145_only) && *e == 166)
}
fn fixed_ref(v: &Value, p: &Path) -> Result<Value> {
    let b: Bound = serde_json::from_value(v.clone())?;
    ensure!(b.path == p, "foreign metered 168 reference");
    custody::evidence(&b)
}
/// Admit a replacement that began after this source pass started. The private
/// gate may be waiting for the first guard. Only the sealed registration can
/// turn it into an active owner in the verifier's census.
pub fn replacement_row() -> Result<Option<Value>> {
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(REPLACEMENT);
    if !cg.try_exists()? {
        return Ok(None);
    }
    let root = Path::new(RUNTIME).join(METERED);
    let m = joint_candidate::show(
        REPLACEMENT,
        "Id,InvocationID,MainPID,ActiveState,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,NRestarts",
    )?;
    ensure!(
        m["Id"] == REPLACEMENT
            && m["NRestarts"] == "0"
            && m["MemorySwapMax"] == "0"
            && m["MemoryMax"] == (68u64 << 30).to_string()
            && m["CPUQuotaPerSecUSec"] == "9s"
            && matches!(m["ActiveState"].as_str(), Some("active" | "activating")),
        "foreign replacement 168"
    );
    let a = root.join("ACTUAL_ADMISSION_AND_PROTECTION.json");
    if !a.try_exists()? {
        return Err(peer_terminal::Pending(168).into());
    }
    let (_, v) = joint_candidate::immutable(&a)?;
    let row = json!({"epoch":168,"unit":{"Id":REPLACEMENT,"InvocationID":m["InvocationID"]},
        "guard_timer":{"Id":v["timer_unit"],"InvocationID":v["timer_invocation_id"]}});
    Ok(Some(row))
}
pub fn metered(owners: &Value) -> Result<Option<Value>> {
    let row = &owners["168"];
    if row.is_null() {
        return Ok(None);
    }
    let root = Path::new(RUNTIME).join(METERED);
    let (proof, a) =
        joint_candidate::immutable(&root.join("ACTUAL_ADMISSION_AND_PROTECTION.json"))?;
    let iid = row["invocation_id"].as_str().context("168 generation")?;
    let pid = u32::try_from(capacity::n(&a, "producer_pid")?)?;
    let main = capacity::native_values(REPLACEMENT)?;
    let timer = "horizon-guard-168-full-metered-20261121-v1.timer";
    ensure!(
        a["schema"] == "horizon-168-full-metered-admission-protection-v1"
            && a["epoch"] == 168
            && a["producer_unit"] == REPLACEMENT
            && row["unit"] == REPLACEMENT
            && custody::hex(iid, 32)
            && iid != "c081016844dd40c5a78b594bf7ede73a"
            && a["producer_invocation_id"] == iid
            && a["timer_unit"] == timer
            && row["guard_timer"] == timer
            && a["timer_invocation_id"] == row["guard_timer_invocation_id"]
            && main["MainPID"] == pid.to_string()
            && main["InvocationID"] == iid
            && main["CPUQuotaPerSecUSec"] == "9s"
            && main["MemoryMax"] == (68u64 << 30).to_string()
            && native::ticks(pid)? == capacity::n(&a, "start_ticks")?
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::/system.slice/{REPLACEMENT}")
            && a["resource_credit_bytes"] == 0
            && a["bootstrap_only"] == true
            && a["transaction_replay_claimed"] == false
            && a["prior_trace_terminal"]["sha256"] == ORIGINAL_TRACE
            && a["input_seal"]["sha256"]
                == "e00db5e753a2cc37af403933f54bcb3216594d1fac3d91cc8984623999295a93",
        "new 168 has no matching genuine metered bootstrap and guard"
    );
    fixed_ref(
        &a["prior_trace_terminal"],
        &Path::new(RUNTIME).join("epoch168-terminal-trace-20261121-v1/TERMINAL.json"),
    )?;
    fixed_ref(
        &a["input_seal"],
        &root.join("inputs-v1/deployment-seal-receipt.json"),
    )?;
    let payload = custody::evidence(&Bound {
        path: root.join("inputs-v1/payload.json"),
        sha256: "6c56c0cad87c9d22ca72ad8e2cf97cb0cc0c5e1b4d1d01e4f051dfc01875b240".into(),
    })?;
    let name = payload["members"]["jetstreamer-node"][0]
        .as_str()
        .context("168 normal node")?;
    let node = fs::metadata(name)?;
    let exe = fs::metadata(format!("/proc/{pid}/exe"))?;
    ensure!(
        (node.dev(), node.ino()) == (exe.dev(), exe.ino()),
        "168 bootstrap is not in its normal executable"
    );
    let plan = fixed_ref(
        &a["actual_guard_plan"],
        &root.join("ACTUAL_GUARD_PLAN.json"),
    )?;
    let first = fixed_ref(&a["first_guard"], &root.join("FIRST_GUARD.json"))?;
    let capacity = fixed_ref(
        &a["post_guard_capacity"],
        &root.join("POST_GUARD_CAPACITY.json"),
    )?;
    let first_iid = first["guard_invocation"]
        .as_str()
        .context("168 first guard invocation")?;
    ensure!(
        custody::hex(first_iid, 32),
        "invalid first guard invocation"
    );
    let sample = fixed_ref(
        &first["receipt"],
        &root
            .join("guard-receipts")
            .join(format!("sample-{first_iid}.json")),
    )?;
    ensure!(
        first["genuine_first_timer_driven_success"] == true
            && first["producer"]["InvocationID"] == iid
            && first["timer"]["InvocationID"] == a["timer_invocation_id"]
            && sample["guard_invocation_id"] == first_iid
            && sample["producer_invocation_id"] == iid
            && sample["plan_sha256"] == a["actual_guard_plan"]["sha256"]
            && sample["trip_reason"].is_null()
            && capacity["complete_memory_plus_reserve_bytes"] == 810_658_050_048u64
            && capacity["resource_credit_bytes"] == 0
            && capacity::n(&capacity, "complete_cpu_quota_micros")? <= 64_000_000
            && capacity::n(&capacity, "available_HOME_bytes")?
                >= capacity::n(&capacity, "complete_required_DATA_bytes")?,
        "168 first guard or full funded fit differs"
    );
    let fleet_bound: Bound = serde_json::from_value(a["fleet"].clone())?;
    custody::evidence(&fleet_bound)?;
    ensure!(
        plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["filesystem"] == "/home/sol"
            && plan["invocation_id"] == iid
            && plan["unit"] == REPLACEMENT
            && plan["worker_root"]
                == "/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1"
            && plan["receipt_directory"] == json!(root.join("guard-receipts"))
            && plan["maximum_root_physical_bytes"] == 309_237_645_312u64
            && plan["maximum_worker_vmas"] == 3_500_000
            && capacity::n(&plan, "minimum_free_bytes")? >= 8_297_502_499_408,
        "168 first guard or cap changed"
    );
    Ok(Some(
        json!({"admission":proof,"guard":a["actual_guard_plan"]}),
    ))
}
pub fn source_pass(
    iid: &str,
    image: &str,
    file: &Path,
    derive: &mut dyn FnMut() -> Result<[u8; 32]>,
) -> Result<[u8; 32]> {
    let scope = json!({"schema":"epoch145-frozen-source-semantic-pass-v1","image_sha256":image,
        "original_append_sha256":APPEND,"source_sha256":SOURCE_SHA,"manifest_sha256":MANIFEST_SHA,
        "source":custody::frozen_identity(Path::new(SOURCE))?,"manifest":custody::frozen_identity(Path::new(MANIFEST))?,
        "candidate":custody::frozen_identity(file)?});
    cached_pass(
        &Path::new(BASE).join("state"),
        iid,
        image,
        &scope,
        derive,
        |prior| failure(prior).map(|_| ()),
    )
}
fn cached_pass(
    all: &Path,
    iid: &str,
    image: &str,
    scope: &Value,
    derive: &mut dyn FnMut() -> Result<[u8; 32]>,
    failed: impl Fn(&str) -> Result<()>,
) -> Result<[u8; 32]> {
    let mut accepted = None;
    for entry in fs::read_dir(all)? {
        let entry = entry?;
        let who = entry.file_name();
        let Some(prior) = who.to_str() else { continue };
        let path = entry.path().join("source-semantics.json");
        if prior == iid || !custody::hex(prior, 32) || !path.try_exists()? {
            continue;
        }
        let (_, v) = joint_candidate::immutable(&path)?;
        if &v["scope"] != scope {
            continue;
        }
        let started = custody::evidence(&custody::binding(
            &entry.path().join("recovery-started.json"),
        )?)?;
        ensure!(
            v["iid"] == prior && started["iid"] == prior && started["image"] == image,
            "foreign source checkpoint writer"
        );
        failed(prior)?;
        let hash = decode_sha(
            v["semantic_sha256"]
                .as_str()
                .context("stored semantic digest")?,
        )?;
        ensure!(
            accepted.is_none_or(|h| h == hash),
            "conflicting authenticated source pass"
        );
        accepted = Some(hash);
    }
    let hash = match accepted {
        Some(hash) => hash,
        None => derive()?,
    };
    let path = all.join(iid);
    let mut tmp = tempfile::NamedTempFile::new_in(&path)?;
    serde_json::to_writer_pretty(
        tmp.as_file_mut(),
        &json!({"scope":scope,"iid":iid,"semantic_sha256":hex_sha(&hash),"reused":accepted.is_some()}),
    )?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path.join("source-semantics.json"))?;
    File::open(path)?.sync_all()?;
    Ok(hash)
}
pub fn reusable_completion(
    iid: &str,
    sha: &str,
    file: &Path,
    projection: &Path,
) -> Result<Option<Value>> {
    let current = json!(custody::frozen_identity(file)?);
    for item in fs::read_dir(Path::new(BASE).join("state"))? {
        let entry = item?;
        let raw = entry.file_name();
        let Some(who) = raw.to_str() else { continue };
        let path = entry.path().join("verified-frozen.json");
        if who == iid || !custody::hex(who, 32) || !path.try_exists()? {
            continue;
        }
        let r = custody::binding(&path)?;
        let v = custody::evidence(&r)?;
        if v["before"] != current {
            continue;
        }
        let started = custody::evidence(&custody::binding(
            &entry.path().join("recovery-started.json"),
        )?)?;
        if who == PREVIOUS {
            ensure!(
                v["parent"] == 3738161
                    && v["pid"] == 3751536
                    && started["image"]
                        == "f8c57a5c069ee60430221c16534d3fb5b265e62f5d554ad9a3dd8c71404179a6",
                "foreign original verified result"
            );
        } else if started["image"] != sha {
            continue;
        }
        ensure!(
            v["iid"] == who
                && started["iid"] == who
                && v["paid_source"] == json!(file)
                && v["private_projection"] == json!(projection)
                && v["r2_mutations"] == false,
            "foreign completed source/candidate result"
        );
        post::extraction(&v["extraction"], projection)?;
        let terminal = failure(who)?;
        return Ok(Some(
            json!({"iid":iid,"parent":std::process::id(),"before":current,"paid_source":file,
            "private_projection":projection,"extraction":v["extraction"],"r2_mutations":false,
            "reused_independent_verification":r,"predecessor_failure":terminal}),
        ));
    }
    Ok(None)
}
fn hex_sha(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_roster_only_accepts_the_four_originals_and_optional_new_168() {
        assert!(roster(&BTreeSet::from([167, 169, 170, 172])));
        assert!(roster(&BTreeSet::from([167, 168, 169, 170, 172])));
        assert_eq!(
            roster(&BTreeSet::from([166, 167, 169, 170, 172])),
            cfg!(early145_only)
        );
        for other in [[136, 167, 169, 170, 172], [167, 168, 169, 170, 173]] {
            assert!(!roster(&BTreeSet::from(other)));
        }
    }
    #[test]
    #[ignore = "root-private native atomic checkpoint and predecessor fixtures"]
    fn native_source_checkpoint_and_live_denials() {
        if cfg!(early145_only) {
            predecessor().unwrap();
        } else {
            assert!(predecessor().is_err());
        }
        assert!(closed166::drained().is_err());
        assert!(partial::closed168().is_ok());
        assert!(metered(&json!({})).unwrap().is_none());
        assert!(metered(&json!({"168":{"unit":partial::NODE,"invocation_id":"c081016844dd40c5a78b594bf7ede73a"}})).is_err());
        let dir = tempfile::tempdir().unwrap();
        let a = "1".repeat(32);
        let b = "2".repeat(32);
        let c = "3".repeat(32);
        let image = "f".repeat(64);
        let scope = json!({"source":"x","candidate":"frozen"});
        for iid in [&a, &b, &c] {
            let path = dir.path().join(iid);
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            custody::write_new(
                &path.join("recovery-started.json"),
                &json!({"iid":iid,"image":image}),
            )
            .unwrap();
        }
        assert_eq!(
            cached_pass(dir.path(), &a, &image, &scope, &mut || Ok([4; 32]), |_| Ok(
                ()
            ))
            .unwrap(),
            [4; 32]
        );
        assert!(
            cached_pass(
                dir.path(),
                &b,
                &image,
                &scope,
                &mut || panic!("duplicate source pass"),
                |_| anyhow::bail!("original active")
            )
            .is_err()
        );
        assert_eq!(
            cached_pass(
                dir.path(),
                &b,
                &image,
                &scope,
                &mut || panic!("duplicate source pass"),
                |_| Ok(())
            )
            .unwrap(),
            [4; 32]
        );
        assert_eq!(
            cached_pass(
                dir.path(),
                &c,
                &image,
                &json!({"source":"changed"}),
                &mut || Ok([5; 32]),
                |_| Ok(())
            )
            .unwrap(),
            [5; 32]
        );
        let v = joint_candidate::immutable(&dir.path().join(&b).join("source-semantics.json"))
            .unwrap()
            .1;
        assert_eq!(v["reused"], true);
    }
}
