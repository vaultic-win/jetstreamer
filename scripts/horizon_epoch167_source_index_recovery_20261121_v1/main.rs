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
mod source;
const GUARD_SHA: &str = "07f6924ee1cf8d8311aa7bed6620dcf1af580a5546e948206af628c57aa3443b";
const GSEAL: &str = "736a46ffcea86d0937518c728791a4843c57862e37c301bf81095fd5779aed1d";
const CONTRACT: &str = "9dc683e3b5eef14b4ead27f626cc2421a31442ba1c85a376e98881938abd0ba2";
const CSEAL: &str = "11879726e524215d4f0581a33619bc707dee1f01d59f37863886dea37871ba3b";
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
    let path = rt(PROVIDER);
    let se = member(&path, fit_seal)?;
    let b = command(
        path.to_str().unwrap(),
        &["167", st(fleet, "path")?, st(fleet, "sha256")?],
        150,
    )?;
    let mut v: Value = serde_json::from_slice(&b)?;
    ensure!(
        v["schema"] == "horizon-incident-replay-fit-v1"
            && v["fits"] == true
            && n(&v, "available_HOME_bytes")? >= n(&v, "complete_required_HOME_bytes")?
            && n(&v, "available_memory_bytes")? >= n(&v, "required_available_memory_bytes")?
            && n(&v, "protected_raw_floor_bytes")? >= 8_297_502_499_408u64,
        "unfunded original 167 booking"
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
        &["inventory", "/home/sol/horizon", "--epochs", "167-167"],
        60,
    )?;
    let v: Value = serde_json::from_slice(&b)?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-r2-inventory-v1"
            && v["requested_epochs"] == 1
            && v["missing"] == 1
            && v["anomalies"] == 0
            && v["entries"][0]["epoch"] == 167
            && v["entries"][0]["state"] == "missing",
        "167 not missing"
    );
    Ok(v)
}
fn pkg() -> PathBuf {
    rt(COMMON).join("tools/guard")
}
fn contract() -> Result<Value> {
    let path = rt(COMMON).join("contract/contract.json");
    let (v, cr) = doc(&path, Some(CONTRACT))?;
    let sr = member(&path, CSEAL)?;
    let gb = member(&pkg(), GSEAL)?;
    ensure!(
        gb["sha256"] == GSEAL
            && file_digest(&pkg())? == GUARD_SHA
            && v["qualified_native_witness"]["sha256"]
                == "33e62f01194935876985fabdc18a283ac00baccef58e30e97c65360420bb7f91",
        "changed incident guard"
    );
    Ok(json!({"contract":cr,"deployment_seal":sr}))
}
fn guarded(actor: &Value, floor: u64, binding: &Value) -> Result<(Value, Value)> {
    let pr = record(
        "ACTUAL_GUARD_PLAN.json",
        &json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":actor["producer_invocation_id"],"worker_root":LANE,"filesystem":"/home/sol","minimum_free_bytes":floor,"maximum_root_physical_bytes":512u64<<30,"maximum_worker_vmas":3500000,"receipt_directory":base().join("guard-receipts"),"data_fulfillment":binding}),
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
    let old = rt(OLD).join("launch-state/epoch167/ORIGINAL_GUARD_ARGV.json");
    let (v, _) = doc(
        &old,
        Some("4fbff52bb7cf7f7443cd7466289494b23c1b32c8c433e6ecf196356f6f8fc76f"),
    )?;
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
    let inv = record("INVENTORY_PRESTART.json", &require_missing()?)?;
    let before = fit(fleet, fit_seal)?;
    let floor = n(&before, "protected_raw_floor_bytes")?
        .checked_add(128 << 20)
        .context("guard slack")?
        .min(n(&before, "available_HOME_bytes")?);
    let own = record(
        "START_INTENT.json",
        &json!({"schema":"horizon-167-recovery-start-intent-v1","epoch":167,"producer_unit":UNIT,"timer_unit":TIMER,"recorded_unix_seconds":now()?,"prepared":pr,"fleet":fleet,"prestart":before,"armed_floor":floor,"authenticated_inventory":inv,"predecessor_stop":baseline["predecessor_stop"],"stable_root":baseline["root"],"resource_credit_bytes":0}),
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
        let after = fit(fleet, fit_seal)?;
        ensure!(
            n(&after, "protected_raw_floor_bytes")? <= floor && actor::sample()? == actor,
            "post-guard floor or 167 changed"
        );
        let post = record("POST_GUARD_CAPACITY.json", &after)?;
        source::index_selected()?;
        let (sample, _) = actor::guard(&actor, &plan)?;
        let mut ad = actor;
        for (k,v) in json!({"schema":"horizon-167-source-index-admission-protection-v1","epoch":167,"timer_unit":TIMER,"timer_invocation_id":sample["timer"]["InvocationID"],"actual_guard_plan":plan,"first_guard":first,"post_guard_capacity":post,"fleet":fleet,"intent":own,"source":pr,"predecessor_stop":baseline["predecessor_stop"],"stable_root":baseline["root"],"bootstrap_only":true,"transaction_replay_claimed":false,"resource_credit_bytes":0}).as_object().unwrap(){ad[k]=v.clone()}
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
        return source::prepare();
    }
    ensure!(
        env::current_exe()? == base().join("tools/recover167"),
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
    #[test]
    fn original_stop_and_permanent_witness_roots() {
        let v = source::files().unwrap();
        assert_eq!(v["root"]["inode"], 107675649);
        assert_eq!(v["snapshot"]["length"], 2022614652u64);
        assert!(
            doc(
                &rt(PKG).join("successor-profile.json"),
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
