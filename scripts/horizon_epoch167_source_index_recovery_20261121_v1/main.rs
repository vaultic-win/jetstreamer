use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
mod support;
use support::*;
#[cfg(not(epoch168_cold_retry3))]
const COLD168_LAUNCHER: &str = "tools-v2/recover168";
#[cfg(all(epoch168_cold_retry3, not(epoch168_cold_retry5)))]
const COLD168_LAUNCHER: &str = "tools/recover168";
#[cfg(all(
    epoch168_cold_retry5,
    not(any(epoch168_cold_retry5_v13, epoch168_cold_retry5_v10))
))]
const COLD168_LAUNCHER: &str = "fit-launcher-v3/recover168";
#[cfg(all(epoch168_cold_retry5, epoch168_cold_retry5_v13))]
const COLD168_LAUNCHER: &str = "fit-launcher-v4/recover168";
#[cfg(all(epoch168_cold_retry5, epoch168_cold_retry5_v10, not(epoch168_cold_retry5_independent145)))]
const COLD168_LAUNCHER: &str = "fit-launcher-v5/recover168";
#[cfg(all(epoch168_cold_retry5, epoch168_cold_retry5_v10, epoch168_cold_retry5_independent145))]
const COLD168_LAUNCHER: &str = "fit-launcher-v9/recover168";
mod actor;
#[cfg(epoch166_after168)]
#[path = "../horizon_epoch166_guard_recovery_20261121_v1/after168.rs"]
mod after168;
#[cfg_attr(
    any(epoch166_recovery, epoch166_retry11),
    path = "../horizon_epoch166_guard_recovery_20261121_v1/source166.rs"
)]
#[cfg_attr(
    any(epoch170_retry11, epoch170_retry12, epoch170_retry13),
    path = "../horizon_epoch170_guard_recovery_20261121_v1/source170.rs"
)]
#[cfg_attr(epoch167_cold_rebook, path = "cold167.rs")]
#[cfg_attr(
    epoch168_cold_rebook,
    path = "../horizon_epoch168_full_metered_20261121_v1/cold168.rs"
)]
mod source;
use source::{ATTEMPT, BASE, CAP, EPOCH, LANE, OLD, PREVIOUS_GUARD_ARGV, TIMER, UNIT};
#[cfg(not(any(
    epoch167_cold_rebook,
    epoch166_retry11,
    epoch170_retry11,
    epoch170_retry12,
    epoch170_retry13,
    epoch168_cold_rebook
)))]
const GUARD_SHA: &str = "07f6924ee1cf8d8311aa7bed6620dcf1af580a5546e948206af628c57aa3443b";
#[cfg(not(any(
    epoch167_cold_rebook,
    epoch166_retry11,
    epoch170_retry11,
    epoch170_retry12,
    epoch170_retry13,
    epoch168_cold_rebook
)))]
const GSEAL: &str = "736a46ffcea86d0937518c728791a4843c57862e37c301bf81095fd5779aed1d";
#[cfg(epoch167_cold_rebook)]
const GUARD_SHA: &str = "0d02c342a3993dea74f5a452d91c8ed655e551f28794b0333093fb767d18251b";
#[cfg(epoch167_cold_rebook)]
const GSEAL: &str = "0fd5e8a3f7113e5c373222b6aa647b179617876a6855253461a6633f5f9c5cb3";
#[cfg(not(any(
    epoch167_cold_rebook,
    epoch166_retry11,
    epoch170_retry11,
    epoch170_retry12,
    epoch170_retry13,
    epoch168_cold_rebook
)))]
const CONTRACT: &str = "9dc683e3b5eef14b4ead27f626cc2421a31442ba1c85a376e98881938abd0ba2";
#[cfg(not(any(
    epoch167_cold_rebook,
    epoch166_retry11,
    epoch170_retry11,
    epoch170_retry12,
    epoch170_retry13,
    epoch168_cold_rebook
)))]
const CSEAL: &str = "11879726e524215d4f0581a33619bc707dee1f01d59f37863886dea37871ba3b";
#[cfg(epoch167_cold_rebook)]
const CONTRACT: &str = "5be3255e74b43ada890dc3c0ba9d60c3cec4a2585dcbe15a8dfe336bf2eede65";
#[cfg(epoch167_cold_rebook)]
const CSEAL: &str = "891f54b03201bcb2e0811400a9906bf9e04a3b789231b176e5b20f011195dccf";
#[cfg(epoch167_cold_rebook)]
const WITNESS: &str = "62a24a8bc04d1f6615367428a725f00c6062b6d81a32d255c5d2f96b54eec296";
#[cfg(not(any(
    epoch167_cold_rebook,
    epoch166_retry11,
    epoch170_retry11,
    epoch170_retry12,
    epoch170_retry13,
    epoch168_cold_rebook
)))]
const WITNESS: &str = "33e62f01194935876985fabdc18a283ac00baccef58e30e97c65360420bb7f91";
#[cfg(any(
    epoch166_retry11,
    epoch170_retry11,
    epoch170_retry12,
    epoch170_retry13,
    epoch168_cold_rebook
))]
use source::{CONTRACT, CSEAL, GSEAL, GUARD_SHA, WITNESS};
fn member(path: &Path, sealdigest: &str) -> Result<Value> {
    let d = path.parent().context("package")?;
    let (seal, sr) = doc(&d.join("deployment-seal-receipt.json"), Some(sealdigest))?;
    let filename = path
        .file_name()
        .and_then(|v| v.to_str())
        .context("member")?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(d)
            && seal["sealer_sha256"] == SEALER
            && seal["remote_mutations"] == false,
        "foreign deployment"
    );
    let rows: Vec<_> = seal["members"]
        .as_array()
        .context("members")?
        .iter()
        .filter(|x| x["name"] == filename)
        .collect();
    ensure!(
        rows.len() == 1 && rows[0]["sha256"] == file_digest(path)?,
        "different installed member"
    );
    Ok(sr)
}
fn fit(fleet: &Value, fit_seal: &str) -> Result<Value> {
    #[cfg(epoch167_cold_rebook)]
    let path = rt("incident-replay-fit-20261121-v1/tools-homefloor-cold167-v3/post-stop-fit");
    #[cfg(not(any(
        epoch167_cold_rebook,
        epoch166_retry11,
        epoch170_retry11,
        epoch170_retry12,
        epoch170_retry13,
        epoch168_cold_rebook
    )))]
    let path = if fit_seal == "e8ba73178277950ed2bcc976534f49af21413745c8244026fcb1502bea9adc7e" {
        rt(PROVIDER)
    } else {
        rt("incident-replay-fit-20261121-v1/tools-v2/post-stop-fit")
    };
    #[cfg(all(epoch166_retry11, not(epoch166_after170)))]
    let path = rt("incident-replay-fit-20261121-v1/tools-homefloor-retry11-166-v2/post-stop-fit");
    #[cfg(all(epoch166_after170, not(epoch166_after168)))]
    let path = rt("incident-replay-fit-20261121-v1/tools-homefloor-166-after170-v1/post-stop-fit");
    #[cfg(epoch166_after168)]
    let path = {
        ensure!(
            fit_seal == after168::FIT_SEAL,
            "different 166 capacity deployment"
        );
        rt(after168::FIT)
    };
    #[cfg(epoch170_retry11)]
    let path = rt("incident-replay-fit-20261121-v1/tools-homefloor-retry11-170-v1/post-stop-fit");
    #[cfg(epoch170_retry12)]
    let path = rt("incident-replay-fit-20261121-v1/tools-homefloor-retry12-170-v1/post-stop-fit");
    #[cfg(epoch170_retry13)]
    let path = rt("incident-replay-fit-20261121-v1/tools-homefloor-retry13-170-v1/post-stop-fit");
    #[cfg(epoch168_cold_rebook)]
    let path = rt(source::FIT);
    #[cfg(epoch166_after168)]
    doc(&base().join("PREPARED.json"), Some(after168::PREPARED))?;
    let se = member(&path, fit_seal)?;
    let b = command(
        path.to_str().unwrap(),
        &[&EPOCH.to_string(), st(fleet, "path")?, st(fleet, "sha256")?],
        150,
    )?;
    let mut v: Value = serde_json::from_slice(&b)?;
    #[cfg(all(epoch168_cold_retry5, epoch168_cold_retry5_v10, not(epoch168_cold_retry5_independent145)))]
    ensure!(
        v["phase145"]["stage"] == "v10-semantic-complete-drained"
            && v["phase145"]["completed_invocation_id"] == "104f023c5cd24a55b6585ef525b80067",
        "epoch 168 capacity requires the drained V10 verifier"
    );
    #[cfg(all(epoch168_cold_retry5, epoch168_cold_retry5_v10, epoch168_cold_retry5_independent145))]
    ensure!(
        v["phase145"]["stage"] == "independent-semantic-complete-v10-drained"
            && v["phase145"]["previous_verifier_invocation_id"] == "104f023c5cd24a55b6585ef525b80067"
            && matches!(
                v["phase145"]["completed_invocation_id"].as_str(),
                Some("cb3313b857d94b9f82e06d5c033c0ac5" | "a89c1de125694cb3bdcef19a8c82848a")
            )
            && v["phase145"]["resource_credit_bytes"] == 0,
        "epoch 168 capacity requires the selected verified archive and drained V10"
    );
    ensure!(
        v["schema"] == "horizon-incident-replay-fit-v1"
            && v["fits"] == true
            && n(&v, "available_HOME_bytes")? >= n(&v, "complete_required_HOME_bytes")?
            && n(&v, "available_memory_bytes")? >= n(&v, "required_available_memory_bytes")?
            && n(&v, "protected_raw_floor_bytes")? >= 8_297_502_499_408u64,
        "unfunded original replay booking"
    );
    #[cfg(any(
        epoch167_cold_rebook,
        epoch166_retry11,
        epoch170_retry11,
        epoch170_retry12,
        epoch170_retry13,
        epoch168_cold_rebook
    ))]
    ensure!(
        v["epoch"] == EPOCH
            && v["fleet"] == *fleet
            && v["resource_credit_bytes"] == 0
            && v["bookings"][EPOCH.to_string()]["root"] == LANE
            && v["bookings"][EPOCH.to_string()]["cap_bytes"] == CAP
            && v["replay_launch_authorized"] == false,
        "foreign successor budget or candidate"
    );
    #[cfg(epoch166_after168)]
    {
        after168::peers_and_writer(&v)?;
        if v["candidate"].is_null() {
            after168::prestart(&v)?;
        }
    }
    #[cfg(epoch166_after168_closed)]
    ensure!(
        v["replacements"].get("168").is_none()
            && v["closed_retry3_bootstrap"]["failure"]["sha256"]
                == "cf8ef71b5b000cc4138f726d019c59a107b9b3d45f741b0b4802a6f4f31f1d21"
            && v["closed_retry3_bootstrap"]["admission"]["sha256"]
                == "8dd692fda6b1098a22a2162792e7165005692385795e6cae72b6df472c7e83c0"
            && v["closed_retry3_bootstrap"]["resource_credit_bytes"] == 0
            && v["bookings"]["168"]["cap_bytes"] == 288u64 << 30,
        "missing retained 168 bootstrap booking"
    );
    v["provider_seal"] = se;
    Ok(v)
}
#[cfg(epoch166_after170)]
fn fourth_lane_floor(price: &Value) -> Result<u64> {
    let partial = &price["startup_nonexact_peer_floor"];
    let protected = n(price, "protected_raw_floor_bytes")?;
    let required = n(price, "complete_required_HOME_bytes")?;
    let remaining = n(&price["bookings"]["166"], "remaining_bytes")?;
    let observed_actor = &price["replacements"]["170"];
    ensure!(
        price["epoch"] == 166
            && price["candidate"].is_null()
            && price["fits"] == true
            && partial["funded"] == true
            && observed_actor["producer_invocation_id"] == "c44b5215f8d949159e7ce9cf911e9be1"
            && protected >= n(observed_actor, "floor")?
            && n(partial, "protected_raw_floor_bytes")? == protected
            && n(partial, "complete_required_HOME_bytes")? == required
            && protected.checked_add(remaining) == Some(required),
        "incomplete peer reservations for the fourth replay lane"
    );
    let surplus = n(price, "available_HOME_bytes")?
        .checked_sub(required)
        .context("insufficient HOME for conservative peer bookings")?;
    protected
        .checked_add(surplus.min(10 << 30))
        .context("armed peer floor overflow")
}
fn require_missing() -> Result<Value> {
    let p = rt("epoch145-publication-20261121-v1/uploader-tools/jetstreamer-r2");
    ensure!(
        file_digest(&p)? == "eb448ede557144f04446dbe00a2d2ec7ad88c934a7a227797d0569a15307a904",
        "different inventory binary"
    );
    let b = command(
        p.to_str().unwrap(),
        &[
            "inventory",
            "/home/sol/horizon",
            "--epochs",
            &format!("{EPOCH}-{EPOCH}"),
        ],
        60,
    )?;
    let v: Value = serde_json::from_slice(&b)?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-r2-inventory-v1"
            && v["requested_epochs"] == 1
            && v["missing"] == 1
            && v["anomalies"] == 0
            && v["entries"][0]["epoch"] == EPOCH
            && v["entries"][0]["state"] == "missing",
        "epoch not missing"
    );
    Ok(v)
}
fn pkg() -> PathBuf {
    #[cfg(epoch167_cold_rebook)]
    let guard = rt("epoch167-cold-guard-20261122-v3/tools/guard");
    #[cfg(not(any(
        epoch167_cold_rebook,
        epoch166_retry11,
        epoch170_retry11,
        epoch170_retry12,
        epoch170_retry13,
        epoch168_cold_rebook
    )))]
    let guard = rt(COMMON).join("tools/guard");
    #[cfg(epoch166_retry11)]
    let guard = rt("epoch166-retry11-guard-20261122-v1/tools/guard");
    #[cfg(epoch170_retry11)]
    let guard = rt("epoch170-retry11-guard-20261122-v1/tools/guard");
    #[cfg(epoch170_retry12)]
    let guard = rt("epoch170-retry12-guard-20261122-v1/tools/guard");
    #[cfg(epoch170_retry13)]
    let guard = rt("epoch170-retry13-guard-20261122-v1/tools/guard");
    #[cfg(epoch168_cold_rebook)]
    let guard = rt(source::GUARD_BASE).join("tools/guard");
    guard
}
fn contract() -> Result<Value> {
    #[cfg(epoch167_cold_rebook)]
    let path = rt("epoch167-cold-guard-20261122-v3/contract/contract.json");
    #[cfg(not(any(
        epoch167_cold_rebook,
        epoch166_retry11,
        epoch170_retry11,
        epoch170_retry12,
        epoch170_retry13,
        epoch168_cold_rebook
    )))]
    let path = rt(COMMON).join("contract/contract.json");
    #[cfg(epoch166_retry11)]
    let path = rt("epoch166-retry11-guard-20261122-v1/contract/contract.json");
    #[cfg(epoch170_retry11)]
    let path = rt("epoch170-retry11-guard-20261122-v1/contract/contract.json");
    #[cfg(epoch170_retry12)]
    let path = rt("epoch170-retry12-guard-20261122-v1/contract/contract.json");
    #[cfg(epoch170_retry13)]
    let path = rt("epoch170-retry13-guard-20261122-v1/contract/contract.json");
    #[cfg(epoch168_cold_rebook)]
    let path = rt(source::GUARD_BASE).join("contract/contract.json");
    let (v, cr) = doc(&path, Some(CONTRACT))?;
    let sr = member(&path, CSEAL)?;
    let gb = member(&pkg(), GSEAL)?;
    ensure!(
        gb["sha256"] == GSEAL
            && file_digest(&pkg())? == GUARD_SHA
            && v["qualified_native_witness"]["sha256"] == WITNESS,
        "changed incident guard"
    );
    Ok(json!({"contract":cr,"deployment_seal":sr}))
}
fn guard_plan(iid: &Value, floor: u64, binding: &Value) -> Value {
    json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,"worker_root":LANE,"filesystem":"/home/sol","minimum_free_bytes":floor,"maximum_root_physical_bytes":CAP,"maximum_worker_vmas":3500000,"receipt_directory":base().join("guard-receipts"),"data_fulfillment":binding})
}
#[cfg(any(
    epoch167_cold_rebook,
    epoch166_retry11,
    epoch170_retry11,
    epoch170_retry12,
    epoch170_retry13,
    epoch168_cold_rebook
))]
fn verify_guard_route(binding: &Value) -> Result<()> {
    let expected = guard_plan(
        &json!("00000000000000000000000000000001"),
        8297502499408,
        binding,
    );
    let path = base().join("STATIC_GUARD_ROUTE.json");
    let plan = if path.try_exists()? {
        let (saved, reference) = doc(&path, None)?;
        ensure!(saved == expected, "different prestart guard route");
        reference
    } else {
        record("STATIC_GUARD_ROUTE.json", &expected)?
    };
    let result: Value = serde_json::from_slice(&command(
        pkg().to_str().unwrap(),
        &[
            st(&plan, "path")?,
            "--plan-sha256",
            st(&plan, "sha256")?,
            "--self-sha256",
            GUARD_SHA,
            "--validate-plan-only",
        ],
        10,
    )?)?;
    ensure!(
        result["validated"] == true
            && result["unit"] == UNIT
            && result["producer_signaled"] == false,
        "new guard cannot enforce this exact generation"
    );
    Ok(())
}
fn guarded(actor: &Value, floor: u64, binding: &Value) -> Result<(Value, Value)> {
    let pr = record(
        "ACTUAL_GUARD_PLAN.json",
        &guard_plan(&actor["producer_invocation_id"], floor, binding),
    )?;
    let p = pkg();
    let tail = [
        st(&pr, "path")?,
        "--plan-sha256",
        st(&pr, "sha256")?,
        "--self-sha256",
        GUARD_SHA,
    ];
    let mut validation = tail.to_vec();
    validation.push("--validate-plan-only");
    let v: Value = serde_json::from_slice(&command(p.to_str().unwrap(), &validation, 10)?)?;
    ensure!(
        v["validated"] == true && v["unit"] == UNIT && v["producer_signaled"] == false,
        "guard static scope"
    );
    #[cfg(epoch168_cold_rebook)]
    let old = rt(OLD).join("SESSION_GUARD_ARGV.json");
    #[cfg(not(epoch168_cold_rebook))]
    let old = rt(OLD).join(format!(
        "launch-state/epoch{EPOCH}/ORIGINAL_GUARD_ARGV.json"
    ));
    let (v, _) = doc(&old, Some(PREVIOUS_GUARD_ARGV))?;
    let old: Vec<String> = serde_json::from_value(v)?;
    let mut argv = Vec::new();
    for item in old.iter().skip(1) {
        #[cfg(epoch168_cold_rebook)]
        if let Some(rhs) = item.strip_prefix("--timer-property=") {
            if let Some((key, value)) = rhs.split_once('=') {
                if matches!(key, "After" | "Requisite" | "StopPropagatedFrom") {
                    ensure!(value == source::OLD_UNIT, "unexpected guard dependency");
                    argv.push(format!("--timer-property={key}={UNIT}"));
                    continue;
                }
            }
        }
        let new = if item.starts_with("--unit=") {
            format!("--unit={}", TIMER.trim_end_matches(".timer"))
        } else if item.starts_with("--property=ReadWritePaths=") {
            format!(
                "--property=ReadWritePaths={}/guard-receipts",
                base().display()
            )
        } else if item.starts_with("--property=StandardOutput=") {
            format!(
                "--property=StandardOutput=append:{}/guard.stdout",
                base().display()
            )
        } else if item.starts_with("--property=StandardError=") {
            format!(
                "--property=StandardError=append:{}/guard.stderr",
                base().display()
            )
        } else if !item.starts_with("--") {
            break;
        } else {
            item.clone()
        };
        argv.push(new)
    }
    #[cfg(epoch168_cold_rebook)]
    for key in ["After", "Requisite", "StopPropagatedFrom"] {
        ensure!(
            argv.iter()
                .filter(|a| *a == &format!("--timer-property={key}={UNIT}"))
                .count()
                == 1,
            "missing guard dependency"
        );
    }
    argv.push(p.to_string_lossy().into());
    argv.extend(tail.iter().map(|x| x.to_string()));
    record("GUARD_ARGV.json", &json!(argv))?;
    command(
        "/usr/bin/systemd-run",
        &argv.iter().map(String::as_str).collect::<Vec<_>>(),
        10,
    )?;
    let until = Instant::now() + Duration::from_secs(115);
    let first = loop {
        ensure!(
            actor::sample()? == *actor,
            "node changed before first guard"
        );
        match actor::guard(actor, &pr) {
            Ok((row, _)) => break row,
            Err(e) if Instant::now() < until => {
                let _ = e;
                thread::sleep(Duration::from_millis(400));
            }
            Err(e) => return Err(e),
        }
    };
    let fr = record("FIRST_GUARD.json", &first)?;
    Ok((pr, fr))
}
/// A cold node can fork its historical reader between the first timer survey and
/// the fleet census. Let the timer inspect that same child before charging it.
fn post_guard_fit(
    actor: &Value,
    plan: &Value,
    first: &Value,
    fleet: &Value,
    seal: &str,
) -> Result<Value> {
    let first_row = bound(first, &base().join("FIRST_GUARD.json"))?;
    let mut previous = st(&first_row, "guard_invocation")?.to_owned();
    let deadline = Instant::now() + Duration::from_secs(100);
    loop {
        ensure!(
            Instant::now() < deadline,
            "no later matching worker guard before admission deadline"
        );
        ensure!(
            actor::sample()? == *actor,
            "producer changed after first timer guard"
        );
        let (receipt, sample) = actor::guard(actor, plan)?;
        let generation = st(&receipt, "guard_invocation")?;
        let pid = n(actor, "producer_pid")?;
        let mut live = members(UNIT)?;
        ensure!(
            live.contains(&pid) && live.len() <= 2,
            "foreign producer descendants"
        );
        live.retain(|p| *p != pid);
        if let Some(&child) = live.first() {
            let exe = Path::new("/proc").join(child.to_string()).join("exe");
            let target = fs::read_link(&exe)?;
            let (parent, _, group) = proc_row(child)?;
            ensure!(
                parent == pid
                    && group == format!("0::/system.slice/{UNIT}")
                    && target.starts_with(run().join("private"))
                    && target.file_name().is_some_and(|s| s == "historical-worker")
                    && same(&exe, &target)?,
                "foreign candidate worker"
            );
        }
        let observed = sample["workers"].as_array().context("worker census")?;
        let identities = observed
            .iter()
            .map(|r| {
                let pid = r[0].as_u64().context("worker PID")?;
                ensure!(
                    r[1].as_u64().is_some_and(|v| v > 0 && v < 3_500_000),
                    "invalid worker VMA count"
                );
                Ok(pid)
            })
            .collect::<Result<Vec<_>>>()?;
        if generation != previous && identities == live {
            match fit(fleet, seal) {
                Ok(capacity) => return Ok(capacity),
                Err(e)
                    if e.to_string()
                        .trim_end()
                        .ends_with("ValueError: native worker transition or guard mismatch") =>
                {
                    // This verified child can appear during the provider's slower scan.
                    // Require an independently completed later guard before retrying it.
                    previous = generation.to_owned();
                }
                Err(e) => return Err(e),
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn start(fleet: &Value, fit_seal: &str) -> Result<Value> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/run/horizon-epoch171-to136-g1.operation.lock")?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another admission active"
    );
    #[cfg(epoch168_cold_rebook)]
    if base().join("barrier/allow").try_exists()? {
        return source::finish_released(fleet, fit_seal);
    }
    let baseline = source::files()?;
    let (prep, pr) = doc(&base().join("PREPARED.json"), None)?;
    ensure!(
        prep["baseline"] == baseline
            && native(UNIT)?["LoadState"] == "not-found"
            && native(TIMER)?["LoadState"] == "not-found"
            && !base().join("START_INTENT.json").try_exists()?
            && fs::read_dir(base().join("guard-receipts"))?
                .next()
                .is_none(),
        "prior successor or changed inputs"
    );
    ensure!(source::ready()? == pr, "fresh index profile changed");
    let binding = contract()?;
    #[cfg(any(
        epoch167_cold_rebook,
        epoch166_retry11,
        epoch170_retry11,
        epoch170_retry12,
        epoch170_retry13,
        epoch168_cold_rebook
    ))]
    verify_guard_route(&binding)?;
    #[cfg(not(any(epoch168_cold_rebook, epoch166_after168)))]
    let inv = record("INVENTORY_PRESTART.json", &require_missing()?)?;
    #[cfg(epoch166_retry11)]
    source::holding_complete()?;
    let before = fit(fleet, fit_seal)?;
    ensure!(before["candidate"].is_null(), "candidate already active");
    #[cfg(any(epoch170_retry12, epoch170_retry13, epoch168_cold_rebook))]
    let floor = source::funded_guard_floor(&before)?;
    #[cfg(epoch166_after170)]
    let floor = fourth_lane_floor(&before)?;
    #[cfg(not(any(
        epoch170_retry12,
        epoch170_retry13,
        epoch166_after170,
        epoch168_cold_rebook
    )))]
    let floor = n(&before, "protected_raw_floor_bytes")?
        .checked_add(128 << 20)
        .context("guard slack")?
        .min(n(&before, "available_HOME_bytes")?);
    #[cfg(epoch166_after168)]
    let peers = after168::peers_and_writer(&before)?;
    #[cfg(epoch166_after168)]
    let inv = after168::inventory(&require_missing()?)?;
    #[cfg(epoch168_cold_rebook)]
    let peers = source::peer_identity(&before)?;
    #[cfg(epoch168_cold_rebook)]
    let receiver = source::status_receiver(&before, &pr)?;
    #[cfg(epoch168_cold_rebook)]
    let inv = source::inventory_record(&require_missing()?)?;
    let own = record(
        "START_INTENT.json",
        &json!({"schema":format!("horizon-{EPOCH}-recovery-start-intent-v1"),"epoch":EPOCH,"producer_unit":UNIT,"timer_unit":TIMER,"recorded_unix_seconds":now()?,"prepared":pr,"fleet":fleet,"prestart":before,"armed_floor":floor,"authenticated_inventory":inv,"predecessor_stop":baseline["predecessor_stop"],"stable_root":baseline["root"],"resource_credit_bytes":0}),
    )?;
    let profile = source::profile()?;
    let argv: Vec<String> = serde_json::from_value(profile["producer_argv"].clone())?;
    let mut started = None;
    let mut last_live_fit = None;
    let attempt = (|| -> Result<Value> {
        command(
            &argv[0],
            &argv.iter().skip(1).map(String::as_str).collect::<Vec<_>>(),
            20,
        )?;
        // Retain the new manager IID before validating its remaining execution properties.
        let early = native(UNIT)?;
        ensure!(
            hex(st(&early, "InvocationID")?, 32),
            "missing new manager generation"
        );
        started = Some(early["InvocationID"].clone());
        let actor = actor::sample()?;
        record("ACTUAL_PRODUCER_NATIVE.json", &actor)?;
        let (plan, first) = guarded(&actor, floor, &binding)?;
        let after = post_guard_fit(&actor, &plan, &first, fleet, fit_seal)?;
        // A rejected live quote cannot be reconstructed exactly after the worker drains.
        last_live_fit = Some(after.clone());
        ensure!(
            after["candidate"]["producer_invocation_id"] == actor["producer_invocation_id"]
                && after["candidate"]["producer_pid"] == actor["producer_pid"]
                && after["candidate"]["start_ticks"] == actor["start_ticks"],
            "capacity was captured for another generation"
        );
        #[cfg(epoch166_after168)]
        ensure!(
            after168::peers_and_writer(&after)? == peers,
            "166 peer or writer changed after guard"
        );
        #[cfg(epoch168_cold_rebook)]
        ensure!(
            source::peer_identity(&after)? == peers
                && source::status_receiver(&after, &pr)? == receiver
                && after["status_registration"] == before["status_registration"]
                && after["fleet"] == before["fleet"],
            "168 peer or receiver changed after guard"
        );
        let required_floor = n(&after, "protected_raw_floor_bytes")?;
        ensure!(
            required_floor <= floor,
            "post-guard floor {required_floor} exceeds armed floor {floor}"
        );
        ensure!(
            actor::sample()? == actor,
            "producer changed after post-guard capacity check"
        );
        let post = record("POST_GUARD_CAPACITY.json", &after)?;
        source::index_selected()?;
        let (sample, _) = actor::guard(&actor, &plan)?;
        #[cfg(epoch168_cold_rebook)]
        let actor = source::release_gate(&actor, &plan, &first, &post)?;
        let mut ad = actor;
        for (k,v) in json!({"schema":format!("horizon-{EPOCH}-source-index-admission-protection-v1"),"epoch":EPOCH,"timer_unit":TIMER,"timer_invocation_id":sample["timer"]["InvocationID"],"actual_guard_plan":plan,"first_guard":first,"post_guard_capacity":post,"fleet":fleet,"intent":own,"source":pr,"predecessor_stop":baseline["predecessor_stop"],"stable_root":baseline["root"],"bootstrap_only":true,"transaction_replay_claimed":false,"resource_credit_bytes":0}).as_object().unwrap(){ad[k]=v.clone()}
        record("ACTUAL_ADMISSION_AND_PROTECTION.json", &ad)
    })();
    if let Err(e) = &attempt {
        #[cfg(epoch168_cold_rebook)]
        if base().join("barrier/allow").try_exists()? {
            return source::finish_released(fleet, fit_seal)
                .with_context(|| format!("after 168 gate release: {e:#}"));
        }
        if let Some(iid) = started.as_ref() {
            let m = native(UNIT)?;
            if m["InvocationID"] == *iid && m["ActiveState"] == "active" {
                command("/usr/bin/systemctl", &["stop", UNIT], 140)?;
            }
            if base().join("GUARD_ARGV.json").try_exists()?
                && native(TIMER)?["ActiveState"] == "active"
            {
                command("/usr/bin/systemctl", &["stop", TIMER], 25)?;
            }
        }
        let mut failure = json!({"error":format!("{e:#}"),"intent":own,"producer_invocation_id":started,
            "cgroup":members(UNIT)?,"partial_retained":true});
        if let Some(quote) = last_live_fit {
            failure["post_guard_capacity"] = quote;
        }
        record("START_FAILURE.json", &failure)?;
    }
    attempt
}
fn dispatch() -> Result<Value> {
    ensure!(unsafe { libc::geteuid() } == 0, "root needed");
    let a: Vec<_> = env::args().collect();
    if a.get(1).map(String::as_str) == Some("prepare") {
        let prep = source::prepare()?;
        source::prepare_log()?;
        return Ok(prep);
    }
    ensure!(
        env::current_exe()?
            == base().join(if EPOCH == 167 {
                "tools-v2/recover167"
            } else if cfg!(any(epoch170_retry11, epoch170_retry12, epoch170_retry13)) {
                "tools/recover170"
            } else if cfg!(epoch168_cold_rebook) {
                COLD168_LAUNCHER
            } else if cfg!(epoch166_after168_retry4) {
                "tools-v8/recover166"
            } else if cfg!(epoch166_after168_closed) {
                "tools-v7/recover166"
            } else if cfg!(epoch166_after168_retry3) {
                "tools-v6/recover166"
            } else if cfg!(epoch166_after168) {
                "tools-v5/recover166"
            } else if cfg!(epoch166_after170) {
                "tools-v4/recover166"
            } else if cfg!(epoch166_retry11) {
                "tools-v3/recover166"
            } else {
                "tools/recover166"
            }),
        "use sealed recovery executable"
    );
    match a.as_slice() {
        [_, m] if m == "record-worker" => actor::worker(),
        #[cfg(epoch168_cold_rebook)]
        [_, m] if m == "profile" => source::profile(),
        [_, m, path, hash, seal] if m == "start" || m == "preflight" => {
            let path = Path::new(path);
            ensure!(
                path.file_name()
                    == Some(std::ffi::OsStr::new("ROOT_COMPLETE_OPERATIONAL_FLEET.json"))
                    && path.parent().and_then(Path::parent) == Some(Path::new(R)),
                "foreign fleet"
            );
            let (_, fleet) = doc(path, Some(hash))?;
            if m == "start" {
                start(&fleet, seal)
            } else {
                source::files()?;
                #[cfg(any(
                    epoch167_cold_rebook,
                    epoch166_retry11,
                    epoch170_retry11,
                    epoch170_retry12,
                    epoch170_retry13,
                    epoch168_cold_rebook
                ))]
                verify_guard_route(&contract()?)?;
                #[cfg(not(any(
                    epoch167_cold_rebook,
                    epoch166_retry11,
                    epoch170_retry11,
                    epoch170_retry12,
                    epoch170_retry13,
                    epoch168_cold_rebook
                )))]
                contract()?;
                fit(&fleet, seal)
            }
        }
        _ => bail!("prepare | record-worker | preflight/start FLEET SHA FIT_SEAL_SHA"),
    }
}
fn main() {
    match dispatch() {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("{e:#}");
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(any(
        epoch166_recovery,
        epoch166_retry11,
        epoch167_cold_rebook,
        epoch170_retry11,
        epoch170_retry12,
        epoch170_retry13,
        epoch168_cold_rebook
    )))]
    #[test]
    fn original_stop_and_permanent_witness_roots() {
        let v = source::files().unwrap();
        assert_eq!(v["root"]["inode"], 107675649);
        assert_eq!(v["snapshot"]["length"], 2022614652u64);
        assert!(
            doc(
                &rt(source::PKG).join("successor-profile.json"),
                Some(&"f".repeat(64))
            )
            .is_err()
        );
    }
    #[cfg(epoch166_after170)]
    #[test]
    fn fourth_lane_preserves_the_actual_170_floor_and_166_allowance() {
        let (mut price, _) = doc(
            &rt("epoch170-retry13-rebook-20261122-v1/ADOPTED_WORKER_PEER166_FULL_PRICE_root221757-live166167170-20261122-v1.json"),
            Some("df8311efaf97c80d55cbff73b18e8b696cf54097dd8085108ca1e64746b5667c"),
        ).unwrap();
        // The bootstrap-only quote from before conservative peer pricing cannot fund a start.
        assert!(fourth_lane_floor(&price).is_err());
        let protected = n(&price, "protected_raw_floor_bytes").unwrap();
        let required = n(&price, "complete_required_HOME_bytes").unwrap();
        price["startup_nonexact_peer_floor"] = json!({"protected_raw_floor_bytes": protected,
            "complete_required_HOME_bytes":required,"funded":true});
        price["available_HOME_bytes"] = json!(required + 12);
        assert_eq!(fourth_lane_floor(&price).unwrap(), protected + 12);
        price["available_HOME_bytes"] = json!(required - 1);
        assert!(fourth_lane_floor(&price).is_err());
        price["available_HOME_bytes"] = json!(required);
        price["replacements"]["170"]["floor"] = json!(protected + 1);
        assert!(fourth_lane_floor(&price).is_err());
    }
    #[test]
    fn common_guard_accepts_real_incident_binding_only() {
        let b = contract().unwrap();
        assert_eq!(b["contract"]["sha256"], CONTRACT);
        assert!(member(&pkg(), &"f".repeat(64)).is_err());
    }
    #[test]
    fn refuse_old_worker_or_absent_replacement() {
        assert!(members(UNIT).unwrap().is_empty());
        assert!(actor::sample().is_err());
    }
}
