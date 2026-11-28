// Bind the real stop to both PID1 journals and retire only its four exact symlinks.
use super::*;
use crate::qualification::{collect_retired, installed_link, same_terminal};

fn event(
    raw: &[u8],
    unit: &str,
    iid: &str,
    boot: &str,
    message: impl Fn(&str) -> bool,
) -> Result<u64> {
    let mut found = Vec::new();
    for row in serde_json::Deserializer::from_slice(raw).into_iter::<Value>() {
        let v = row?;
        if v["_PID"] == "1"
            && v["_UID"] == "0"
            && v["UNIT"] == unit
            && v["INVOCATION_ID"] == iid
            && v["_BOOT_ID"] == boot.replace('-', "")
            && v["MESSAGE"].as_str().is_some_and(&message)
        {
            found.push(text(&v, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?);
        }
    }
    ensure!(
        found.len() == 1,
        "missing or duplicate owner-bound PID1 event for {unit}"
    );
    Ok(found[0])
}
pub(super) fn order(c: &Value, p: &Value, producer: &[u8], guard: &[u8]) -> Result<()> {
    let iid = text(c, "producer_invocation_id")?;
    let gid = text(c, "guard_invocation_id")?;
    let boot = text(c, "boot_id")?;
    ensure!(
        hex(iid, 32) && hex(gid, 32) && iid != gid && p["boot_id"] == boot,
        "qualification owner IDs"
    );
    let prod_start = event(producer, UNIT, iid, boot, |s| {
        s.starts_with(&format!("Started {UNIT} -"))
    })?;
    let guard_start = event(guard, GUARD_UNIT, gid, boot, |s| {
        s.starts_with(&format!("Starting {GUARD_UNIT} -"))
    })?;
    let prod_stopping = event(producer, UNIT, iid, boot, |s| {
        s.starts_with(&format!("Stopping {UNIT} -"))
    })?;
    let prod_stop = event(producer, UNIT, iid, boot, |s| {
        s.starts_with(&format!("Stopped {UNIT} -"))
    })?;
    let guard_failure = event(guard, GUARD_UNIT, gid, boot, |s| {
        s == format!("{GUARD_UNIT}: Failed with result 'exit-code'.")
    })?;
    ensure!(
        num(p, "issued_monotonic_us")? <= prod_start
            && prod_start < guard_start
            && guard_start <= prod_stopping
            && prod_stopping < prod_stop
            && guard_start < guard_failure
            && prod_stop.max(guard_failure) < num(p, "expires_monotonic_us")?,
        "out-of-order producer or guard stop outside original startup lease"
    );
    Ok(())
}
// The production guard persists the initiating sample verbatim before it
// rechecks the live owner and submits the stop job. Require this independently
// of the later request and PID1 journals.
pub(super) fn incident_evidence(
    sample: &Value,
    request: &Value,
    intent: &Value,
    iid: &str,
    gid: &str,
    plan: &Bound,
) -> Result<()> {
    ensure!(
        intent
            == &json!({
                "schema":STOP_INTENT,
                "producer_invocation_id":iid, "guard_invocation_id":gid,
                "plan_sha256": plan.sha256, "reason":"filesystem-floor",
                "sample":sample, "remote_mutations":false
            })
            && request
                == &json!({
                    "schema":STOP_REQUEST, "producer_invocation_id":iid,
                    "guard_invocation_id":gid, "plan_sha256":plan.sha256,
                    "drain_proven":false, "remote_mutations":false
                }),
        "stop intent or request differs from the original qualification floor trip"
    );
    Ok(())
}

pub(super) fn stop_intent(c: &Value) -> Result<Bound> {
    let dir = Path::new(text(c, "receipts")?);
    let m = fs::symlink_metadata(dir)?;
    ensure!(
        dir.canonicalize()? == dir && m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "stop receipt directory custody"
    );
    let path = dir.join("stop-intent.json");
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o777 == 0o600
            && m.nlink() == 1
            && m.len() <= 16 << 20,
        "stop intent custody"
    );
    Ok(Bound::new(&path, hash(&path)?))
}
pub(super) fn validate_capture(c: &Value) -> Result<Value> {
    ensure!(
        c["schema"] == STOP_CAPTURE
            && c["harness"] == json!(Bound::new(HARNESS, HARNESS_SHA))
            && c["guard"] == json!(Bound::new(GUARD, GUARD_SHA))
            && c["actual_stop_observed"] == true
            && c["token_absent"] == true
            && c["kernel_drained"] == true
            && c["worker_root_empty"] == true,
        "foreign native stop"
    );
    let startup = binding(&c["startup_plan"])?.sealed()?;
    let gp = binding(&c["guard_plan"])?;
    let plan = gp.sealed()?;
    let iid = text(c, "producer_invocation_id")?;
    let gid = text(c, "guard_invocation_id")?;
    let pid = num(c, "producer_main_pid")?;
    let a = binding(&startup["admission"])?.sealed()?;
    let r = binding(&a["review"])?.sealed()?;
    let attempt = text(&r, "attempt")?;
    ensure!(
        crate::launch::safe_attempt(attempt)
            && qualify(&r)?
            && startup["schema"] == PLAN_SCHEMA
            && startup["operation"] == "qualify-guard"
            && startup["harness"] == c["harness"]
            && startup["guard"] == c["guard"]
            && startup["worker_root"] == ROOT
            && startup["maximum_root_physical_bytes"] == SCRATCH
            && startup["maximum_memory_bytes"] == MEMORY
            && plan["boot_id"] == c["boot_id"]
            && plan["unit"] == UNIT
            && plan["invocation_id"] == iid
            && plan["native_main"]["main_pid"] == pid
            && plan["native_main"]["sha256"] == HARNESS_SHA
            && plan["native_main"]["executable"] == HARNESS
            && plan["filesystem"] == EXPECTED_FILESYSTEM
            && plan["worker_root"] == ROOT
            && plan["minimum_free_bytes"] == u64::MAX
            && plan["maximum_root_physical_bytes"] == SCRATCH
            && c["receipts"] == plan["receipt_directory"]
            && c["receipts"]
                == format!("/var/lib/jetstreamer/horizon-native{EPOCH}-guard-receipts-{iid}")
            && gp.path == package(attempt, "guard-binding").join("guard-plan.json")
            && binding(&c["startup_plan"])?.path
                == package(attempt, "startup-plan").join("plan.json")
            && c["producer_package"] == json!(package(attempt, "producer"))
            && c["guard_package"] == json!(package(attempt, "guard-units")),
        "qualification attempted different plans, unit packages, or resources"
    );
    let sample = binding(&c["sample"])?;
    ensure!(
        sample.path == Path::new(text(c, "receipts")?).join(format!("sample-{gid}.json")),
        "guard sample path"
    );
    let sample = sample.json()?;
    check_mount_sample(&a, &sample)?;
    handoff::limited_sample(&startup, &plan, &sample)?;
    stop::check_sample(&sample, iid, pid, &gp)?;
    ensure!(
        sample["guard_invocation_id"] == gid
            && sample["plan"] == json!(gp.path)
            && sample["native_main"] == plan["native_main"],
        "guard sample owner"
    );
    let req = binding(&c["stop_request"])?;
    ensure!(
        req.path == Path::new(text(c, "receipts")?).join(format!("stop-request-{gid}.json")),
        "guard stop request path"
    );
    let req = req.json()?;
    let incident = stop_intent(c)?;
    incident_evidence(&sample, &req, &incident.json()?, iid, gid, &gp)?;
    stop::killed(&c["producer_terminal"], iid)?;
    let gt = &c["guard_terminal"];
    ensure!(
        gt["Id"] == GUARD_UNIT
            && gt["InvocationID"] == gid
            && gt["MainPID"] == "0"
            && gt["ControlPID"] == "0"
            && gt["Job"] == ""
            && gt["Result"] == "exit-code"
            && gt["ExecMainStatus"] == "1",
        "wrong guard terminal"
    );
    order(
        c,
        &startup,
        &binding(&c["producer_pid1"])?.bytes(false)?,
        &binding(&c["guard_pid1"])?.bytes(false)?,
    )?;
    Ok(r)
}
fn drained(c: &Value) -> Result<()> {
    stop::empty_cgroup()?;
    absent(&PathBuf::from(format!(
        "/proc/{}",
        num(c, "producer_main_pid")?
    )))?;
    absent(&Path::new(TOKENS).join(text(c, "producer_invocation_id")?))?;
    units::pristine()
}
pub(super) fn run(n: &mut Native, cr: &Bound, c: &Value) -> Result<()> {
    let r = validate_capture(c)?;
    drained(c)?;
    let attempt = text(&r, "attempt")?;
    let preparation = binding(&r["preparation"])?.sealed()?;
    let mut links = Vec::new();
    for name in [UNIT, RETENTION, GUARD_UNIT, TIMER] {
        let kind = if name == UNIT || name == RETENTION {
            "producer"
        } else {
            "guard-units"
        };
        let target = binding(&preparation["units"][name])?;
        ensure!(
            target.path == package(attempt, kind).join(name),
            "prepared link target"
        );
        target.bytes(true)?;
        links.push((name.to_owned(), target));
    }
    let dest = package(attempt, "retirement-intent");
    let intent_path = dest.join("retirement-before.json");
    let before = match fs::symlink_metadata(&dest) {
        Ok(_) => {
            let b = Bound::new(&intent_path, hash(&intent_path)?);
            b.sealed()?;
            b
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let producer = n.show(UNIT)?;
            let guard = n.show(GUARD_UNIT)?;
            let timer = n.show(TIMER)?;
            same_terminal(&c["producer_terminal"], &producer)?;
            same_terminal(&c["guard_terminal"], &guard)?;
            ensure!(
                timer["ActiveState"] == "inactive" && timer["Job"] == "",
                "timer not drained"
            );
            let retention = units::retention(n, Path::new(text(c, "producer_package")?))?;
            let mut ids = BTreeMap::new();
            for (u, b) in &links {
                ids.insert(u, installed_link(u, b)?);
            }
            let v = save_json(
                &n.root,
                "retirement-before.json",
                &json!({"capture":c,"capture_ref":cr,"unit_files":links,"link_identities":ids,
            "retention":retention,"producer":producer,"guard":guard,"timer":timer,"boot_id":c["boot_id"]}),
            )?;
            n.seal(&dest, &[("retirement-before.json", v.clone())])?;
            Bound::new(intent_path, v.sha256)
        }
        Err(e) => return Err(e.into()),
    };
    let intent = before.sealed()?;
    ensure!(
        intent["capture"] == *c
            && intent["capture_ref"] == json!(cr)
            && intent["unit_files"] == json!(links)
            && intent["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "another retirement intent"
    );
    let retain = n.show(RETENTION)?;
    let armed = retain["ActiveState"] == "active";
    if armed {
        ensure!(retain == intent["retention"], "retention replaced");
        same_terminal(&intent["producer"], &n.show(UNIT)?)?;
        let guard = n.show(GUARD_UNIT)?;
        if guard["ActiveState"] == "failed" {
            same_terminal(&intent["guard"], &guard)?;
        } else {
            ensure!(
                guard["ActiveState"] == "inactive"
                    && guard["Job"] == ""
                    && guard["MainPID"] == "0"
                    && guard["ControlPID"] == "0"
                    && (guard["InvocationID"] == intent["guard"]["InvocationID"]
                        || guard["InvocationID"] == ""),
                "guard changed after reset"
            );
        }
        ensure!(
            n.show(TIMER)? == intent["timer"],
            "qualification timer changed"
        );
    } else {
        ensure!(
            retain["ActiveState"] == "inactive" && retain["Job"] == "",
            "ambiguous retention"
        );
    }
    for (u, b) in &links {
        for parent in ["/etc/systemd/system", "/run/systemd/system"] {
            absent(&Path::new(parent).join(format!("{u}.d")))?;
        }
        absent(&Path::new("/run/systemd/system").join(u))?;
        let path = Path::new("/etc/systemd/system").join(u);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                ensure!(
                    armed && intent["link_identities"][u] == json!(installed_link(u, b)?),
                    "installed link changed"
                );
                fs::remove_file(&path)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    File::open("/etc/systemd/system")?.sync_all()?;
    if armed {
        let guard = n.show(GUARD_UNIT)?;
        if guard["ActiveState"] == "failed" {
            same_terminal(&intent["guard"], &guard)?;
            n.run("/usr/bin/systemctl", &["reset-failed", GUARD_UNIT])?;
        }
        ensure!(
            n.show(RETENTION)? == intent["retention"],
            "retention changed before stop"
        );
        n.run("/usr/bin/systemctl", &["stop", RETENTION])?;
    }
    let after = collect_retired(n, &links)?;
    drained(c)?;
    let mut result = json!({"schema":STOP_RETIRED,"capture":cr,"before":before,"after":after,"sealed_packages_and_diagnostics_preserved":true,
        "stop_intent":stop_intent(c)?,"all_four_links_removed":true,"producer_restarted":false,"kernel_drained":true,"token_absent":true});
    deny_authority(&mut result);
    let out = save_json(&n.root, "retirement-complete.json", &result)?;
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rows(unit: &str, iid: &str, events: &[(&str, u64)]) -> Vec<u8> {
        events
            .iter()
            .map(|(message, t)| {
                json!({"_PID":"1","_UID":"0","_BOOT_ID":"boot","UNIT":unit,"INVOCATION_ID":iid,
            "MESSAGE":message,"__MONOTONIC_TIMESTAMP":t.to_string()})
                .to_string()
                    + "\n"
            })
            .collect::<String>()
            .into_bytes()
    }
    #[test]
    fn original_stop_intent_and_request_bind_the_exact_triggering_sample() {
        let plan = Bound::new("/fixed/guard-plan.json", "a".repeat(64));
        let iid = "b".repeat(32);
        let gid = "c".repeat(32);
        let sample = json!({"trip_reason":"filesystem-floor","guard_invocation_id":gid,"producer_invocation_id":iid,"native_main":{"main_pid":42}});
        let intent = json!({"schema":STOP_INTENT,"producer_invocation_id":iid,"guard_invocation_id":gid,"plan_sha256":plan.sha256,"reason":"filesystem-floor","sample":sample,"remote_mutations":false});
        let request = json!({"schema":STOP_REQUEST,"producer_invocation_id":iid,"guard_invocation_id":gid,"plan_sha256":plan.sha256,"drain_proven":false,"remote_mutations":false});
        let check = |i: &Value, r: &Value| incident_evidence(&sample, r, i, &iid, &gid, &plan);
        check(&intent, &request).unwrap();
        for key in [
            "schema",
            "sample",
            "reason",
            "guard_invocation_id",
            "producer_invocation_id",
            "plan_sha256",
            "remote_mutations",
        ] {
            let mut changed = intent.clone();
            changed[key] = Value::Null;
            assert!(check(&changed, &request).is_err(), "{key}");
        }
        let mut other = intent.clone();
        other["sample"]["native_main"]["main_pid"] = json!(43);
        assert!(check(&other, &request).is_err());
        let mut transition = intent.clone();
        transition.as_object_mut().unwrap().remove("sample");
        transition["transition"] = json!("transition-foreign.json");
        assert!(check(&transition, &request).is_err());
        for key in [
            "schema",
            "guard_invocation_id",
            "producer_invocation_id",
            "plan_sha256",
            "drain_proven",
            "remote_mutations",
        ] {
            let mut changed = request.clone();
            changed[key] = Value::Null;
            assert!(check(&intent, &changed).is_err(), "{key}");
        }
    }

    #[test]
    fn a_genuine_floor_stop_requires_both_original_pid1_histories_in_order() {
        let iid = "a".repeat(32);
        let gid = "b".repeat(32);
        let c = json!({"producer_invocation_id":iid,"guard_invocation_id":gid,"boot_id":"boot"});
        let p = json!({"issued_monotonic_us":100,"expires_monotonic_us":300,"boot_id":"boot"});
        let start = format!("Started {UNIT} - Bootstrap.");
        let stopping = format!("Stopping {UNIT} - Bootstrap...");
        let end = format!("Stopped {UNIT} - Bootstrap.");
        let fire = format!("Starting {GUARD_UNIT} - Guard...");
        let failed = format!("{GUARD_UNIT}: Failed with result 'exit-code'.");
        let producer = rows(UNIT, &iid, &[(&start, 110), (&stopping, 200), (&end, 250)]);
        let guard = rows(GUARD_UNIT, &gid, &[(&fire, 190), (&failed, 260)]);
        order(&c, &p, &producer, &guard).unwrap();
        for bad in [
            rows(GUARD_UNIT, &iid, &[(&fire, 190), (&failed, 260)]),
            rows(GUARD_UNIT, &gid, &[(&fire, 210), (&failed, 260)]),
            rows(GUARD_UNIT, &gid, &[(&fire, 190), (&failed, 300)]),
            rows(
                GUARD_UNIT,
                &gid,
                &[(&fire, 180), (&fire, 190), (&failed, 260)],
            ),
        ] {
            assert!(order(&c, &p, &producer, &bad).is_err());
        }
        assert!(order(&c, &p, b"", &guard).is_err());
    }
}
