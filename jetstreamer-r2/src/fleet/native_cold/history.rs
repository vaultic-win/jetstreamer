// Enumerate every guard artifact and reconcile its invocation with the original PID1 journal.
use super::current as c;
use super::*;
use crate::fleet::native265::{binding, hex, num, sealed, text};
pub(in crate::fleet) fn actual(h: &Value, gp: &Value, a: &Value, issued: u64) -> Result<Value> {
    let dir = guard::directory(h, gp)?;
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(&dir)? {
        let e = entry?;
        let name = e
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("invalid native bootstrap guard filename"))?;
        if name == "guard.lock" {
            let m = fs::symlink_metadata(e.path())?;
            ensure!(
                m.is_file()
                    && m.uid() == 0
                    && m.nlink() == 1
                    && e.path().canonicalize()? == e.path(),
                "native bootstrap lock custody"
            );
            continue;
        }
        ensure!(files.len() < 1024, "native bootstrap guard record bound");
        files.insert(name, guard::record(&e.path())?);
    }
    let root = fs::symlink_metadata(c::ROOT)?;
    ensure!(
        Path::new(c::ROOT).canonicalize()? == Path::new(c::ROOT)
            && root.is_dir()
            && root.uid() == 1000
            && root.gid() == 1000
            && root.mode() & 0o777 == 0o700,
        "native bootstrap scratch root replaced"
    );
    let pin = files
        .get("root-pin.json")
        .context("native bootstrap root pin absent")?;
    ensure!(
        pin["device"] == root.dev() && pin["inode"] == root.ino() && pin["mode"] == root.mode(),
        "native bootstrap scratch inode changed"
    );
    let rows = guard::journal(&[
        format!(
            "--since=@{}",
            num(a, "issued_unix_seconds")?.saturating_sub(60)
        ),
        "_PID=1".into(),
        format!("UNIT={}", c::GUARD_UNIT),
    ])?;
    let mut kept = Vec::new();
    for row in rows {
        if text(&row, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()? >= issued {
            kept.push(row);
        }
    }
    Ok(json!({"records":files,"guard_pid1":kept}))
}
#[allow(clippy::too_many_arguments)]
pub(in crate::fleet) fn validate(
    history: &Value,
    h: &Value,
    gp: &Value,
    issued: u64,
    terminal: u64,
    manager: &Value,
    clean: bool,
    worker: Option<u64>,
) -> Result<(Vec<u64>, Option<String>)> {
    let first = sealed(&binding(&h["first_guard_sample"])?)?;
    records(
        history, h, gp, issued, terminal, manager, clean, worker, &first,
    )
}
#[allow(clippy::too_many_arguments)]
fn records(
    history: &Value,
    h: &Value,
    gp: &Value,
    issued: u64,
    terminal: u64,
    manager: &Value,
    clean: bool,
    worker: Option<u64>,
    first: &Value,
) -> Result<(Vec<u64>, Option<String>)> {
    let (_, guard_sha) = guard::identity(h)?;
    let files = history["records"]
        .as_object()
        .context("native bootstrap guard files")?;
    let rows = history["guard_pid1"]
        .as_array()
        .context("native bootstrap guard PID1")?;
    let mut starts = BTreeMap::new();
    let mut ends = BTreeMap::new();
    let mut last = issued;
    for r in rows {
        let gid = text(r, "INVOCATION_ID")?;
        let mono = text(r, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == c::GUARD_UNIT
                && r["_BOOT_ID"] == text(gp, "boot_id")?.replace('-', "")
                && hex(gid, 32)
                && mono >= last,
            "native bootstrap guard journal owner/clock"
        );
        last = mono;
        let msg = text(r, "MESSAGE")?;
        if msg.starts_with(&format!("Starting {} -", c::GUARD_UNIT)) {
            ensure!(
                starts.insert(gid, mono).is_none(),
                "duplicate native bootstrap guard start"
            );
        }
        let good = msg == format!("{}: Deactivated successfully.", c::GUARD_UNIT);
        if good || msg.starts_with(&format!("{}: Failed with result ", c::GUARD_UNIT)) {
            ensure!(
                ends.insert(gid, (mono, good)).is_none(),
                "duplicate native bootstrap guard end"
            );
        }
    }
    ensure!(
        !starts.is_empty()
            && starts.len() == ends.len()
            && starts.iter().all(|(id, t)| ends
                .get(id)
                .is_some_and(|(end, _)| end > t && end - t <= 60_000_000)),
        "native bootstrap guard history truncated"
    );
    let first_gid = text(first, "guard_invocation_id")?;
    ensure!(
        files.get(&format!("sample-{first_gid}.json")) == Some(first)
            && starts.contains_key(first_gid)
            && starts.get(first_gid) == starts.values().min()
            && starts[first_gid] - issued <= 60_000_000,
        "native bootstrap guard history lost first fire"
    );
    ensure!(
        files.contains_key("root-pin.json"),
        "native bootstrap root pin missing"
    );
    let main = num(h, "main_pid")?;
    let mut ids = vec![main];
    let mut pins = Vec::new();
    for (kind, exe, sha, parent) in [
        ("main", c::TEST, c::TEST_SHA, 1),
        ("worker", c::PROFILE.worker.path, c::PROFILE.worker.sha256, main),
    ] {
        let Some(v) = files.get(&format!("{kind}-pin.json")) else {
            ensure!(
                kind == "worker" && worker.is_none(),
                "native bootstrap process pin missing"
            );
            continue;
        };
        let p = &v["pin"];
        let pid = num(p, "pid")?;
        ensure!(
            v["schema"] == epoch_name!("horizon", "-native-guard-process-pin-v1")
                && v["kind"] == kind
                && v["remote_mutations"] == false
                && p["boot_id"] == gp["boot_id"]
                && p["executable"] == exe
                && p["sha256"] == sha
                && p["parent_pid"] == parent
                && p["uid"] == 0
                && p["nlink"] == 1
                && num(p, "mode")? & 0o222 == 0
                && num(p, "start_ticks")? >= num(gp, "main_start_ticks")?,
            "native bootstrap process lineage differs"
        );
        if kind == "main" {
            ensure!(
                pid == main && p["start_ticks"] == gp["main_start_ticks"],
                "native bootstrap harness start differs"
            );
        } else {
            ensure!(
                pid > 1 && pid != main && worker.is_none_or(|w| w == pid),
                "native bootstrap worker PID"
            );
            ids.push(pid);
        }
        pins.push(p.clone());
    }
    let intent = files.get("stop-intent.json");
    let mut covered = BTreeSet::new();
    let mut drains = 0;
    let mut times = Vec::new();
    for (name, r) in files {
        ensure!(
            r["plan_sha256"] == h["guard_plan"]["sha256"]
                && r["producer_invocation_id"] == h["invocation_id"],
            "native bootstrap foreign guard record {name}"
        );
        if name == "root-pin.json" {
            c::pin_mount(first, r)?;
            ensure!(
                r["schema"] == epoch_name!("horizon", "-native-guard-root-pin-v1")
                    && r["uid"] == 1000
                    && r["gid"] == 1000
                    && num(r, "mode")? & 0o777 == 0o700,
                "native bootstrap root pin"
            );
            continue;
        }
        if matches!(name.as_str(), "main-pin.json" | "worker-pin.json") {
            continue;
        }
        let gid = text(r, "guard_invocation_id")?;
        let (end, good) = *ends
            .get(gid)
            .context("native bootstrap guard receipt lacks PID1 firing")?;
        let start = starts[gid];
        if name == "stop-intent.json" {
            ensure!(
                !clean
                    && r["schema"] == epoch_name!("horizon", "-native-guard-stop-intent-v1")
                    && !text(r, "reason")?.is_empty()
                    && r["remote_mutations"] == false,
                "native bootstrap invalid stop intent"
            );
            if let Some(t) = r["transition"].as_str() {
                ensure!(
                    t == format!("transition-{gid}.json")
                        && files.contains_key(t)
                        && r["reason"] == "producer-state-changed-during-sample",
                    "native bootstrap changed intent transition"
                );
            } else {
                let subject = files
                    .get(&format!("sample-{gid}.json"))
                    .context("native bootstrap intent sample")?;
                ensure!(
                    r.get("sample") == Some(subject) && r["reason"] == subject["trip_reason"],
                    "native bootstrap intent does not match sample"
                );
            }
            continue;
        }
        if name == &format!("stop-request-{gid}.json") {
            ensure!(
                !clean
                    && intent.is_some()
                    && !good
                    && r["schema"] == epoch_name!("horizon", "-native-guard-stop-request-v1")
                    && r["drain_proven"] == false
                    && r["remote_mutations"] == false,
                "native bootstrap invalid stop request"
            );
            continue;
        }
        ensure!(
            covered.insert(gid),
            "native bootstrap ambiguous primary guard record"
        );
        if name == &format!("sample-{gid}.json") {
            ensure!(
                start <= terminal
                    && r["guard_sha256"] == guard_sha
                    && r["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                    && r["plan"] == h["guard_plan"]["path"]
                    && r["producer"]["pid"] == main
                    && r["producer"]["invocation_id"] == h["invocation_id"]
                    && r["producer"]["cgroup"] == format!("/system.slice/{}", c::UNIT)
                    && r["remote_mutations"] == false
                    && r["r2_mutations"] == false,
                "native bootstrap sample owner"
            );
            if r.get("trip_reason") == Some(&Value::Null) {
                ensure!(good, "native bootstrap healthy guard failed");
                c::sample_mount(first, r)?;
                guard::sample(h, gp, r, num(r, "recorded_unix_seconds")?, 0)?;
                for pin in r["process_observation"]["processes"]
                    .as_array()
                    .context("native bootstrap sample process pins")?
                {
                    ensure!(
                        pins.contains(pin),
                        "native bootstrap changed historical process pin"
                    );
                }
            } else {
                ensure!(
                    !clean && !good && intent.is_some() && !text(r, "trip_reason")?.is_empty(),
                    "native bootstrap unaccounted guard trip"
                );
            }
            times.push(start);
        } else if name == &format!("transition-{gid}.json") {
            ensure!(
                !good
                    && r["schema"] == epoch_name!("horizon", "-native-guard-transition-v1")
                    && r["before"]["pid"] == main
                    && r["before"]["invocation_id"] == h["invocation_id"]
                    && r["before"]["active"] == "active"
                    && r["after"]["invocation_id"] == h["invocation_id"]
                    && r["remote_mutations"] == false
                    && (if r["after"]["pid"] == 0 {
                        matches!(r["after"]["active"].as_str(), Some("inactive" | "failed"))
                            && start <= terminal
                            && end >= terminal.saturating_sub(1_000_000)
                    } else {
                        intent.is_some() && !clean && r["after"]["pid"] == main
                    })
                    && (!clean || r.get("trip_reason") == Some(&Value::Null)),
                "native bootstrap transition not bound to terminal or stop"
            );
            times.push(start);
        } else {
            ensure!(
                name == &format!("terminal-{gid}.json")
                    && good
                    && r["schema"] == epoch_name!("horizon", "-native-guard-terminal-v1")
                    && r["guard_sha256"] == guard_sha
                    && r["terminal"]["invocation_id"] == h["invocation_id"]
                    && r["terminal"]["pid"] == 0
                    && r["terminal"]["control_pid"] == 0
                    && r["terminal"]["active"] == manager["ActiveState"]
                    && r["terminal"]["result"] == manager["Result"]
                    && r.get("drain_error") == Some(&Value::Null)
                    && r.get("prior_stop_intent") == Some(intent.unwrap_or(&Value::Null))
                    && r["drain"]["original_processes_gone"] == true
                    && r["drain"]["retained_process_pins"] == json!(pins)
                    && matches!(
                        r["drain"]["kernel_cgroup"].as_str(),
                        Some("empty" | "absent")
                    )
                    && start >= terminal
                    && r["resource_release_authorized"] == false
                    && r["remote_mutations"] == false
                    && r["r2_mutations"] == false,
                "native bootstrap incomplete terminal guard drain"
            );
            drains += 1;
        }
    }
    times.sort_unstable();
    ensure!(
        covered.len() == starts.len()
            && drains > 0
            && !times.is_empty()
            && times.windows(2).all(|w| w[1] - w[0] <= 120_000_000)
            && terminal.saturating_sub(*times.last().unwrap()) <= 120_000_000,
        "native bootstrap missing guard coverage or final drain"
    );
    Ok((
        ids,
        intent
            .map(|v| text(v, "reason").map(str::to_owned))
            .transpose()?,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_first_fire_and_terminal_drain_bind_every_pin_record_and_firing() {
        let (_, token, mut gp, mut sample, _) = native265_guard::fixture();
        let main = 42;
        let iid = "a".repeat(32);
        let g1 = "b".repeat(32);
        let g2 = "c".repeat(32);
        let h = json!({"invocation_id":iid,"main_pid":main,"guard_plan":token["guard_plan"]});
        gp["native_main"] = json!({"main_pid":main,"executable":c::TEST,"sha256":c::TEST_SHA});
        sample["native_main"] = gp["native_main"].clone();
        sample["producer"]["cgroup"] = json!(format!("/system.slice/{}", c::UNIT));
        sample["guard_sha256"] = json!(c::GUARD_SHA);
        sample["maximum_root_physical_bytes"] = json!(c::PROFILE.scratch);
        sample["root_physical_observation"]["maximum_physical_bytes"] = json!(c::PROFILE.scratch);
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        sample["memory_observation"]["maximum_bytes"] = json!(c::PROFILE.memory / page * page);
        sample["memory_observation"]["high_bytes"] = json!(100_000_000_000u64 / page * page);
        sample["scratch_deleted"] = json!(false);
        let pin = json!({"pid":main,"parent_pid":1,"start_ticks":5,"boot_id":"boot","executable":c::TEST,"sha256":c::TEST_SHA,"uid":0,"nlink":1,"mode":0o100555});
        sample["process_observation"]["processes"] = json!([pin]);
        let worker = json!({"pid":43,"parent_pid":main,"start_ticks":8,"boot_id":"boot","executable":c::PROFILE.worker.path,"sha256":c::PROFILE.worker.sha256,"uid":0,"nlink":1,"mode":0o100555});
        let bound = |mut v: Value| {
            v["plan_sha256"] = h["guard_plan"]["sha256"].clone();
            v["producer_invocation_id"] = json!(iid);
            v
        };
        let drain = bound(
            json!({"schema":epoch_name!("horizon", "-native-guard-terminal-v1"),"guard_invocation_id":g2,"guard_sha256":c::GUARD_SHA,"terminal":{"invocation_id":iid,"pid":0,"control_pid":0,"active":"inactive","result":"success"},
        "prior_stop_intent":null,"drain_error":null,"drain":{"kernel_cgroup":"absent","original_processes_gone":true,"retained_process_pins":[pin,worker]},"resource_release_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        );
        let event = |n, gid: &str, msg: String| json!({"_PID":"1","_UID":"0","UNIT":c::GUARD_UNIT,"_BOOT_ID":"boot","INVOCATION_ID":gid,"__MONOTONIC_TIMESTAMP":format!("{n}"),"MESSAGE":msg});
        let start = format!("Starting {} - guard", c::GUARD_UNIT);
        let end = format!("{}: Deactivated successfully.", c::GUARD_UNIT);
        let mut bundle = json!({"guard_pid1":[event(110,&g1,start.clone()),event(130,&g1,end.clone()),event(210,&g2,start),event(220,&g2,end)],"records":{}});
        for (kind, p) in [("main", pin), ("worker", worker)] {
            bundle["records"][format!("{kind}-pin.json")] = bound(
                json!({"schema":epoch_name!("horizon", "-native-guard-process-pin-v1"),"remote_mutations":false,"kind":kind,"pin":p}),
            );
        }
        bundle["records"]["root-pin.json"] = bound(
            json!({"schema":epoch_name!("horizon", "-native-guard-root-pin-v1"),"uid":1000,"gid":1000,"mode":0o40700}),
        );
        c::mount_fixture(&mut sample, &mut bundle["records"]["root-pin.json"]);
        bundle["records"][format!("sample-{g1}.json")] = sample.clone();
        bundle["records"][format!("terminal-{g2}.json")] = drain;
        let good = json!({"ActiveState":"inactive","Result":"success"});
        let check = |bundle: &Value, manager: &Value, clean| {
            records(bundle, &h, &gp, 100, 200, manager, clean, Some(43), &sample)
        };
        assert_eq!(check(&bundle, &good, true).unwrap().0, [42, 43]);
        for ptr in [
            "/records/worker-pin.json/pin/parent_pid",
            "/records/main-pin.json/pin/start_ticks",
            "/guard_pid1/1/INVOCATION_ID",
            "/guard_pid1/0/_UID",
            &format!("/records/terminal-{g2}.json/drain/retained_process_pins/1/sha256"),
            &format!("/records/sample-{g1}.json/native_main/main_pid"),
        ] {
            let mut bad = bundle.clone();
            *bad.pointer_mut(ptr).unwrap() = Value::Null;
            assert!(check(&bad, &good, true).is_err(), "{ptr}");
        }
        let failed = json!({"ActiveState":"failed","Result":"exit-code"});
        let terminal = &mut bundle["records"][format!("terminal-{g2}.json")]["terminal"];
        terminal["active"] = failed["ActiveState"].clone();
        terminal["result"] = failed["Result"].clone();
        check(&bundle, &failed, false).unwrap();
        bundle["records"]
            .as_object_mut()
            .unwrap()
            .remove(&format!("terminal-{g2}.json"));
        assert!(check(&bundle, &failed, false).is_err());
    }
}
