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
mod actor;
#[cfg_attr(
    any(epoch166_recovery, epoch166_retry11),
    path = "../horizon_epoch166_guard_recovery_20261121_v1/source166.rs"
)]
#[cfg_attr(epoch167_cold_rebook, path = "cold167.rs")]
mod source;
use source::{ATTEMPT, BASE, CAP, EPOCH, LANE, OLD, PREVIOUS_GUARD_ARGV, TIMER, UNIT};
#[cfg(not(any(epoch167_cold_rebook, epoch166_retry11)))]
const GUARD_SHA: &str = "07f6924ee1cf8d8311aa7bed6620dcf1af580a5546e948206af628c57aa3443b";
#[cfg(not(any(epoch167_cold_rebook, epoch166_retry11)))]
const GSEAL: &str = "736a46ffcea86d0937518c728791a4843c57862e37c301bf81095fd5779aed1d";
#[cfg(epoch167_cold_rebook)]
const GUARD_SHA: &str = "0d02c342a3993dea74f5a452d91c8ed655e551f28794b0333093fb767d18251b";
#[cfg(epoch167_cold_rebook)]
const GSEAL: &str = "0fd5e8a3f7113e5c373222b6aa647b179617876a6855253461a6633f5f9c5cb3";
#[cfg(not(any(epoch167_cold_rebook, epoch166_retry11)))]
const CONTRACT: &str = "9dc683e3b5eef14b4ead27f626cc2421a31442ba1c85a376e98881938abd0ba2";
#[cfg(not(any(epoch167_cold_rebook, epoch166_retry11)))]
const CSEAL: &str = "11879726e524215d4f0581a33619bc707dee1f01d59f37863886dea37871ba3b";
#[cfg(epoch167_cold_rebook)]
const CONTRACT: &str = "5be3255e74b43ada890dc3c0ba9d60c3cec4a2585dcbe15a8dfe336bf2eede65";
#[cfg(epoch167_cold_rebook)]
const CSEAL: &str = "891f54b03201bcb2e0811400a9906bf9e04a3b789231b176e5b20f011195dccf";
#[cfg(epoch167_cold_rebook)]
const WITNESS: &str = "62a24a8bc04d1f6615367428a725f00c6062b6d81a32d255c5d2f96b54eec296";
#[cfg(not(any(epoch167_cold_rebook, epoch166_retry11)))]
const WITNESS: &str = "33e62f01194935876985fabdc18a283ac00baccef58e30e97c65360420bb7f91";
#[cfg(epoch166_retry11)]
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
    #[cfg(not(any(epoch167_cold_rebook, epoch166_retry11)))]
    let path = if fit_seal == "e8ba73178277950ed2bcc976534f49af21413745c8244026fcb1502bea9adc7e" {
        rt(PROVIDER)
    } else {
        rt("incident-replay-fit-20261121-v1/tools-v2/post-stop-fit")
    };
    #[cfg(epoch166_retry11)]
    let path = rt("incident-replay-fit-20261121-v1/tools-homefloor-retry11-166-v2/post-stop-fit");
    let se = member(&path, fit_seal)?;
    let b = command(
        path.to_str().unwrap(),
        &[&EPOCH.to_string(), st(fleet, "path")?, st(fleet, "sha256")?],
        150,
    )?;
    let mut v: Value = serde_json::from_slice(&b)?;
    ensure!(
        v["schema"] == "horizon-incident-replay-fit-v1"
            && v["fits"] == true
            && n(&v, "available_HOME_bytes")? >= n(&v, "complete_required_HOME_bytes")?
            && n(&v, "available_memory_bytes")? >= n(&v, "required_available_memory_bytes")?
            && n(&v, "protected_raw_floor_bytes")? >= 8_297_502_499_408u64,
        "unfunded original replay booking"
    );
    #[cfg(any(epoch167_cold_rebook, epoch166_retry11))]
    ensure!(
        v["epoch"] == EPOCH
            && v["fleet"] == *fleet
            && v["resource_credit_bytes"] == 0
            && v["bookings"][EPOCH.to_string()]["root"] == LANE
            && v["bookings"][EPOCH.to_string()]["cap_bytes"] == CAP
            && v["replay_launch_authorized"] == false,
        "foreign successor budget or candidate"
    );
    v["provider_seal"] = se;
    Ok(v)
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
    #[cfg(not(any(epoch167_cold_rebook, epoch166_retry11)))]
    let guard = rt(COMMON).join("tools/guard");
    #[cfg(epoch166_retry11)]
    let guard = rt("epoch166-retry11-guard-20261122-v1/tools/guard");
    guard
}
fn contract() -> Result<Value> {
    #[cfg(epoch167_cold_rebook)]
    let path = rt("epoch167-cold-guard-20261122-v3/contract/contract.json");
    #[cfg(not(any(epoch167_cold_rebook, epoch166_retry11)))]
    let path = rt(COMMON).join("contract/contract.json");
    #[cfg(epoch166_retry11)]
    let path = rt("epoch166-retry11-guard-20261122-v1/contract/contract.json");
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
#[cfg(any(epoch167_cold_rebook, epoch166_retry11))]
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
    let old = rt(OLD).join(format!(
        "launch-state/epoch{EPOCH}/ORIGINAL_GUARD_ARGV.json"
    ));
    let (v, _) = doc(&old, Some(PREVIOUS_GUARD_ARGV))?;
    let old: Vec<String> = serde_json::from_value(v)?;
    let mut argv = Vec::new();
    for item in old.iter().skip(1) {
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
    #[cfg(any(epoch167_cold_rebook, epoch166_retry11))]
    verify_guard_route(&binding)?;
    let inv = record("INVENTORY_PRESTART.json", &require_missing()?)?;
    #[cfg(epoch166_retry11)]
    source::holding_complete()?;
    let before = fit(fleet, fit_seal)?;
    ensure!(before["candidate"].is_null(), "candidate already active");
    let floor = n(&before, "protected_raw_floor_bytes")?
        .checked_add(128 << 20)
        .context("guard slack")?
        .min(n(&before, "available_HOME_bytes")?);
    let own = record(
        "START_INTENT.json",
        &json!({"schema":format!("horizon-{EPOCH}-recovery-start-intent-v1"),"epoch":EPOCH,"producer_unit":UNIT,"timer_unit":TIMER,"recorded_unix_seconds":now()?,"prepared":pr,"fleet":fleet,"prestart":before,"armed_floor":floor,"authenticated_inventory":inv,"predecessor_stop":baseline["predecessor_stop"],"stable_root":baseline["root"],"resource_credit_bytes":0}),
    )?;
    let profile = source::profile()?;
    let argv: Vec<String> = serde_json::from_value(profile["producer_argv"].clone())?;
    let mut started = None;
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
        ensure!(
            after["candidate"]["producer_invocation_id"] == actor["producer_invocation_id"]
                && after["candidate"]["producer_pid"] == actor["producer_pid"]
                && after["candidate"]["start_ticks"] == actor["start_ticks"],
            "capacity was captured for another generation"
        );
        ensure!(
            n(&after, "protected_raw_floor_bytes")? <= floor && actor::sample()? == actor,
            "post-guard floor or actor changed"
        );
        let post = record("POST_GUARD_CAPACITY.json", &after)?;
        source::index_selected()?;
        let (sample, _) = actor::guard(&actor, &plan)?;
        let mut ad = actor;
        for (k,v) in json!({"schema":format!("horizon-{EPOCH}-source-index-admission-protection-v1"),"epoch":EPOCH,"timer_unit":TIMER,"timer_invocation_id":sample["timer"]["InvocationID"],"actual_guard_plan":plan,"first_guard":first,"post_guard_capacity":post,"fleet":fleet,"intent":own,"source":pr,"predecessor_stop":baseline["predecessor_stop"],"stable_root":baseline["root"],"bootstrap_only":true,"transaction_replay_claimed":false,"resource_credit_bytes":0}).as_object().unwrap(){ad[k]=v.clone()}
        record("ACTUAL_ADMISSION_AND_PROTECTION.json", &ad)
    })();
    if let Err(e) = &attempt {
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
        record(
            "START_FAILURE.json",
            &json!({"error":format!("{e:#}"),"intent":own,"producer_invocation_id":started,"cgroup":members(UNIT)?,"partial_retained":true}),
        )?;
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
            } else if cfg!(epoch166_retry11) {
                "tools-v3/recover166"
            } else {
                "tools/recover166"
            }),
        "use sealed recovery executable"
    );
    match a.as_slice() {
        [_, m] if m == "record-worker" => actor::worker(),
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
                #[cfg(any(epoch167_cold_rebook, epoch166_retry11))]
                verify_guard_route(&contract()?)?;
                #[cfg(not(any(epoch167_cold_rebook, epoch166_retry11)))]
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
    #[cfg(not(any(epoch166_recovery, epoch166_retry11, epoch167_cold_rebook)))]
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
