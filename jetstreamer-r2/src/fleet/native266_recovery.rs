//! Accept the separately recovered 266 launch inventory without reissuing its admission.
use super::*;
use native265::{EvidenceReader, FsEvidence, binding, num, sealed, text};
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch266-recovered-input-v1";
const IID: &str = "de754f74bbac40b9877d3b912af14886";
const REPORT: &str =
    "/var/lib/jetstreamer/horizon266-original-census-v160-de754f74-v1/recovery.json";
const REPORT_SHA: &str = "cd903100511486d20f4d8972d97943b825d20b94d8edead4a27574f0860ad1c6";
const ORIGINAL: &str = "/home/ubuntu/.codex/diagnostics/horizon266-capture-v160-original-census";
const HAND_SHA: &str = "5479bc3f98e609aa49158ea812482ed018dfb0d88290481c735b95f19eecbb24";
const CONTROL: &str = "horizon-265-replacement-20261119-protective-v3.service";
const CLOCK: u64 = 1795229218;
const TRANSITION: &str =
    "/var/lib/jetstreamer/horizon266-successor-consumer-v161-v1/transition.json";
fn report_ref() -> BoundFile {
    BoundFile {
        path: REPORT.into(),
        sha256: REPORT_SHA.into(),
    }
}
fn checked_report() -> Result<Value> {
    let r = sealed(&report_ref())?;
    ensure!(
        r["original_capture_clock"] == CLOCK
            && r["native_handoff"]["sha256"] == HAND_SHA
            && r["manager_rows"] == 238
            && r["invocation_id"] == IID
            && r["native_unit"] == native266::UNIT
            && r["running_origin_written_by_original_helper"] == false,
        "different original capture"
    );
    let source = Path::new(ORIGINAL);
    let dir = fs::symlink_metadata(source)?;
    use std::os::unix::fs::MetadataExt;
    ensure!(
        dir.is_dir()
            && source.canonicalize()? == source
            && dir.uid() == 0
            && dir.mode() & 0o077 == 0,
        "original census private custody"
    );
    for (name, row) in r["source_files"]
        .as_object()
        .context("original capture members")?
    {
        let b = binding(row)?;
        let m = fs::symlink_metadata(&b.path)?;
        ensure!(
            b.path == source.join(name)
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o077 == 0,
            "private original {} changed",
            name
        );
        let bytes = read_stable_bounded(&b.path, 4 << 20, "original private census")?;
        ensure!(
            hex_lower(&Sha256::digest(bytes)) == b.sha256,
            "original private {} digest",
            name
        );
    }
    for g in r["guard_265_history"]
        .as_array()
        .context("original 265 rotation")?
    {
        let s = bound_json(&binding(&g["sample"])?)?;
        ensure!(
            s["guard_invocation_id"] == g["iid"]
                && s["plan_sha256"] == r["guard_265"]["guard_plan"]["sha256"]
                && s["trip_reason"].is_null(),
            "265 original sample changed"
        );
    }
    for g in r["native_266_bracket"]
        .as_array()
        .context("original native guard bracket")?
    {
        let s = bound_json(&binding(&g["sample"])?)?;
        ensure!(
            s["producer_invocation_id"] == IID
                && s["process_observation"]["processes"] == g["processes"]
                && s["trip_reason"].is_null(),
            "266 original sample changed"
        );
    }
    Ok(r)
}
pub(super) fn recovered(h: &Value, a: &Value, wall: u64) -> Result<Value> {
    let r = checked_report()?;
    ensure!(
        r["native_admission"] == h["admission"]
            && r["fleet"] == a["fleet"]
            && r["observer"] == a["observer"]
            && r["ledger"] == a["reservation_ledger"]
            && h["invocation_id"] == IID
            && h["main_pid"] == 2563315
            && num(h, "recorded_unix_seconds")?
                .checked_add(300)
                .is_some_and(|limit| CLOCK <= limit)
            && wall > CLOCK
            && wall <= native266::now()?,
        "266 recovery chronology"
    );
    let mut v = json!({"schema":SCHEMA,"epoch":266,"unit":native266::UNIT,"invocation_id":IID,"main_pid":h["main_pid"],"expected_exec_start":h["producer"]["ExecStart"],"private_run_root":native266::ROOT,
        "bootstrap_slot":114910768,"startup_handoff":r["native_handoff"],"admission":h["admission"],"original_capture_spec":r["original_spec"],"retained_evidence":private157::binding(&report_ref()),"observed_unix_seconds":CLOCK,
        "recorded_unix_seconds":wall,"sampled_at_utc":publication203::utc(wall)?,"observer":a["observer"],"fleet":a["fleet"],"boot_id":a["boot_id"],"peer_window":h["peer_window"],
        "replay_entries":0,"resource_samples_taken":0,"native_input_qualified":false,"ordinary_replay_claim":false,"original_native_capture_succeeded":false});
    native265::deny(&mut v);
    Ok(v)
}
pub(super) fn claim(c: &PipelineClaim, v: &Value) -> Result<()> {
    let (h, a) = native266::startup(&binding(&v["startup_handoff"])?)?;
    ensure!(
        v == &recovered(&h, &a, num(v, "recorded_unix_seconds")?)?
            && c.epoch == 266
            && c.phase == native266::PHASE
            && c.unit == native266::UNIT
            && c.invocation_id == IID
            && v["expected_exec_start"] == c.expected_exec_start,
        "different recovered native owner"
    );
    Ok(())
}
/// Revalidate the successor build and its Main-approved evidence-only transition.
/// The original role stays authoritative for every normal capture and launch.
pub(super) fn successor(a: &Value, actor: &str, actual: bool) -> Result<()> {
    let old = BoundFile {
        path: TRANSITION.into(),
        sha256: FIRST_TRANSITION.into(),
    };
    let tb = if actor == FIRST_HELPER {
        old.clone()
    } else {
        let first = sealed(&old)?;
        let second = binding(&private157::file_binding(Path::new(NEXT_TRANSITION))?)?;
        let v = sealed(&second)?;
        ensure!(
            v["previous_transition"] == private157::binding(&old)
                && v["previous_helper"] == first["successor"]
                && first["successor"]["sha256"] == FIRST_HELPER
                && v["original_handoff"] == first["original_handoff"]
                && v["successor"]["path"]
                    == "/var/lib/jetstreamer/horizon266-successor-consumer-v162-terminal-v1/jetstreamer-r2",
            "wrong 266 terminal successor lineage"
        );
        second
    };
    let t = sealed(&tb)?;
    ensure!(
        t["schema"] == "horizon-native266-consumer-transition-v1"
            && t["original_handoff"]["sha256"] == HAND_SHA
            && t["original_publication"] == a["source_publication"]
            && t["original_helper"]["sha256"]
                == "185de79a143dc027161c0b855d2d838f03d5bdd939d9987f6c92dbefd171b913"
            && t["Main_accepted"] == true
            && t["source_only_consumer_change"] == true
            && t["remote_ref"] == "refs/heads/account-updates"
            && t["successor"]["sha256"] == actor
            && native265::hex(actor, 64),
        "unqualified 266 successor"
    );
    let pubn = sealed(&binding(&a["source_publication"])?)?;
    let roles = pubn["artifacts"].as_array().context("original roles")?;
    let old = roles
        .iter()
        .find(|r| r["role"] == "fleet")
        .context("original fleet")?;
    ensure!(
        old["artifact"] == t["original_helper"] && old["provenance"] == t["original_provenance"],
        "original source lineage"
    );
    let image = binding(&t["successor"])?;
    let p = sealed(&binding(&t["successor_provenance"])?)?;
    let q = sealed(&binding(&t["qualification"])?)?;
    ensure!(
        p["artifact"] == t["successor"]
            && p["all_source_dependencies_enumerated"] == true
            && p["source_commit"] == t["source_commit"]
            && native265::hex(text(&t, "source_commit")?, 40)
            && q["source_commit"] == t["source_commit"]
            && q["image"] == t["successor"]
            && q["remote_containment_verified"] == true
            && q["qualified"] == true
            && q["remote_mutations"] == false,
        "successor build evidence"
    );
    if actual {
        ensure!(
            std::env::current_exe()?.canonicalize()? == image.path && image.sha256 == actor,
            "wrong successor execution"
        );
        let _ = FsEvidence.bytes(&image, 128 << 20)?;
    }
    Ok(())
}
/// The only recurring control allowed to rotate is the admitted 265 protective
/// oneshot. Reopen its exact receipt and root manager start/terminal first.
fn peers_265(previous: &Value, current: &BTreeMap<String, Value>, exclude: &str) -> Result<()> {
    let old = &previous["unit_census"][CONTROL];
    let next = current.get(CONTROL).context("missing recorded 265 guard")?;
    if old["InvocationID"] == next["InvocationID"] {
        return native265_capture::peers(previous, current, exclude);
    }
    let report = checked_report()?;
    let ctl = &report["guard_265"];
    for k in ["executable", "service_source", "timer_source", "guard_plan"] {
        let b = binding(&ctl[k])?;
        let _ = FsEvidence.bytes(&b, 4 << 20)?;
    }
    let gp = sealed(&binding(&ctl["guard_plan"])?)?;
    for row in [old, next] {
        let iid = text(row, "InvocationID")?;
        ensure!(
            native265::hex(iid, 32)
                && row["Id"] == CONTROL
                && row["MainPID"] == "0"
                && row["SubState"] == "dead"
                && row["ActiveState"] == "inactive"
                && row["Result"] == "success",
            "265 timer not at drained boundary"
        );
        let p = Path::new(text(&gp, "receipt_directory")?).join(format!("sample-{iid}.json"));
        let s = bound_json(&binding(&private157::file_binding(&p)?)?)?;
        ensure!(
            s["guard_invocation_id"] == iid
                && s["guard_sha256"] == ctl["executable"]["sha256"]
                && s["plan_sha256"] == ctl["guard_plan"]["sha256"]
                && s["producer_invocation_id"] == gp["invocation_id"]
                && s["trip_reason"].is_null(),
            "unbound actual 265 firing"
        );
        let out = ProcessCommand::new("journalctl")
            .args([
                "-b",
                "--no-pager",
                "-o",
                "json",
                "_UID=0",
                "_PID=1",
                &format!("UNIT={CONTROL}"),
                &format!("INVOCATION_ID={iid}"),
            ])
            .output()?;
        ensure!(out.status.success(), "265 timer journal");
        let events = serde_json::Deserializer::from_slice(&out.stdout)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in [
            "7d4958e842da4a758f6c1cdc7b36dcc5",
            "7ad2d189f7e94e70a38c781354912448",
        ] {
            ensure!(
                events
                    .iter()
                    .filter(|v| v["_PID"] == "1"
                        && v["_UID"] == "0"
                        && v["INVOCATION_ID"] == iid
                        && v["UNIT"] == CONTROL
                        && v["MESSAGE_ID"] == id)
                    .count()
                    == 1,
                "ambiguous 265 firing"
            );
        }
    }
    let mut adjusted = previous.clone();
    adjusted["unit_census"][CONTROL]["InvocationID"] = next["InvocationID"].clone();
    native265_capture::peers(&adjusted, current, exclude)
}

const V161_PLAN: &str = "1936767f7ad2d590608c3ed0231cc0f9646c6d072bf9bcd468bffd59497762dc";
const V161_OBS: &str = "6136dedbae503a38bc2b74db0ba32cbaa835e6b61b882c14817ad48eafcccb60";
const FIRST_HELPER: &str = "6700d996883f1168347386b012b705ade7cba47aca78ad548af747afebfda652";
const FIRST_TRANSITION: &str = "8dad0a211f80c28632464fc80e7946873d2d13b097852e9618c9f7068e381b98";
const NEXT_TRANSITION: &str =
    "/var/lib/jetstreamer/horizon266-successor-consumer-v162-terminal-v1/transition.json";
const PARK: &str = "horizon223-adaptive-park-v158-a1.service";
const PARK_IID: &str = "c67759c819ed4d6fb154e7c8b3bb49e4";
const CHECK: &str = "horizon223-adaptive-check-v159-a1.service";
const NATIVE_GUARD: &str = "horizon-native266-protective-v1.service";
const BOOT: &str = "3b17d0055c3a4a0e8841da097e0957b5";
const START: &str = "7d4958e842da4a758f6c1cdc7b36dcc5";
const STARTED: &str = "39f53479d3a045ac8e11786248231fbf";
const DONE: &str = "7ad2d189f7e94e70a38c781354912448";
fn custodied(path: &Path) -> Result<Value> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && path.canonicalize()? == path
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0,
        "wrong private evidence {}",
        path.display()
    );
    serde_json::from_slice(&read_stable_bounded(
        path,
        4 << 20,
        "266 private peer evidence",
    )?)
    .map_err(Into::into)
}
fn original_rows(unit: &str, iid: Option<&str>) -> Result<Vec<Value>> {
    let mut cmd = ProcessCommand::new("journalctl");
    cmd.args([
        "--no-pager",
        "-o",
        "json",
        &format!("_BOOT_ID={BOOT}"),
        "_UID=0",
        "_PID=1",
        &format!("UNIT={unit}"),
    ]);
    if let Some(id) = iid {
        cmd.arg(format!("INVOCATION_ID={id}"));
    }
    let out = cmd.output()?;
    ensure!(out.status.success(), "266 peer journal failed");
    serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}
fn manager_pair<'a>(
    rows: &'a [Value],
    unit: &str,
    iid: &str,
    start: &str,
) -> Result<(&'a Value, &'a Value)> {
    let mut s = None;
    let mut e = None;
    for r in rows {
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["_BOOT_ID"] == BOOT
                && r["UNIT"] == unit
                && r["INVOCATION_ID"] == iid,
            "foreign service history"
        );
        if r["MESSAGE_ID"] == start {
            ensure!(s.replace(r).is_none(), "duplicate original start");
        }
        if r["MESSAGE_ID"] == DONE {
            ensure!(e.replace(r).is_none(), "duplicate original terminal");
        }
        ensure!(
            r["MESSAGE_ID"] != "d9b373ed55a64feb8242e02dbe79a49c",
            "failed guard/holding peer"
        );
    }
    let s = s.context("original start missing")?;
    let e = e.context("original terminal missing")?;
    ensure!(
        text(s, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?
            < text(e, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?,
        "wrong original manager order"
    );
    Ok((s, e))
}
fn guard_endpoint(row: &Value, h: &Value, gp: &Value, root: &Path) -> Result<u64> {
    let iid = text(row, "InvocationID")?;
    ensure!(
        native265::hex(iid, 32)
            && row["Id"] == NATIVE_GUARD
            && row["LoadState"] == "loaded"
            && row["Type"] == "oneshot"
            && row["ActiveState"] == "inactive"
            && row["SubState"] == "dead"
            && row["MainPID"] == "0"
            && row["ControlGroup"] == ""
            && row["NRestarts"] == "0"
            && row["ExecMainStatus"] == "0"
            && row["Result"] == "success",
        "native 266 guard not at successful drained boundary"
    );
    let rows = original_rows(NATIVE_GUARD, Some(iid))?;
    let (s, e) = manager_pair(&rows, NATIVE_GUARD, iid, START)?;
    let start = text(s, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
    ensure!(
        text(e, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()? - start <= 60_000_000,
        "native 266 guard exceeded deadline"
    );
    let sample = root.join(format!("sample-{iid}.json"));
    let terminal = root.join(format!("terminal-{iid}.json"));
    ensure!(
        sample.try_exists()? != terminal.try_exists()?,
        "ambiguous native guard primary"
    );
    let v = if sample.try_exists()? {
        custodied(&sample)?
    } else {
        custodied(&terminal)?
    };
    ensure!(
        v["guard_invocation_id"] == iid
            && v["producer_invocation_id"] == IID
            && v["guard_sha256"] == native266::GUARD_SHA
            && v["plan_sha256"] == h["guard_plan"]["sha256"]
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "foreign 266 guard evidence"
    );
    if v["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1" {
        ensure!(
            sample.try_exists()?
                && v["trip_reason"] == Value::Null
                && v["producer"]["invocation_id"] == IID
                && v["producer"]["pid"] == h["main_pid"]
                && v["producer"]["active"] == "active"
                && v["producer"]["cgroup"] == format!("/system.slice/{}", native266::UNIT)
                && v["plan"] == h["guard_plan"]["path"]
                && v["producer_stop_enabled"] == true
                && v["process_observation"]["stable_census"] == true
                && v["process_observation"]["boot_id"] == gp["boot_id"],
            "native 266 first/next sample"
        );
    } else {
        let mut pins = Vec::new();
        for role in ["main", "worker"] {
            let v = custodied(&root.join(format!("{role}-pin.json")))?;
            ensure!(
                v["kind"] == role
                    && v["producer_invocation_id"] == IID
                    && v["plan_sha256"] == h["guard_plan"]["sha256"],
                "266 terminal pin changed"
            );
            pins.push(v["pin"].clone());
        }
        ensure!(
            terminal.try_exists()?
                && v["schema"] == "horizon266-native-guard-terminal-v1"
                && v["terminal"]["invocation_id"] == IID
                && v["terminal"]["pid"] == 0
                && v["terminal"]["control_pid"] == 0
                && v.get("drain_error") == Some(&Value::Null)
                && v["drain"]["original_processes_gone"] == true
                && v["drain"]["retained_process_pins"] == json!(pins)
                && matches!(
                    v["drain"]["kernel_cgroup"].as_str(),
                    Some("empty" | "absent")
                )
                && v["resource_release_authorized"] == false,
            "266 terminal guard lacks original drain"
        );
    }
    Ok(start)
}
fn private_digest(path: &Path) -> Result<Value> {
    let reference = private157::file_binding(path)?;
    custodied(path)?;
    Ok(reference)
}
fn holding(unit: &str, prior: Option<&Value>, next: &Value) -> Result<()> {
    let park = unit == PARK;
    ensure!(park || unit == CHECK, "unregistered holding peer");
    let dir = Path::new("/home/ubuntu/.codex/diagnostics").join(unit.trim_end_matches(".service"));
    let book_ref = private_digest(&dir.join("booking.json"))?;
    let launch_ref = private_digest(&dir.join("launch.json"))?;
    let book = bound_json(&binding(&book_ref)?)?;
    let launch = bound_json(&binding(&launch_ref)?)?;
    let iid = text(&launch["unit"], "InvocationID")?;
    ensure!(
        native265::hex(iid, 32)
            && launch["booking"] == book_ref
            && launch["unit"]["Id"] == unit
            && launch["unit"]["NRestarts"] == "0"
            && book["unit"] == unit
            && book["requested_memory"] == 4u64 << 30
            && book["disk_reserve"] == 256u64 << 20,
        "223 original booking or launch"
    );
    if park {
        ensure!(
            iid == PARK_IID
                && book_ref["sha256"]
                    == "d7a665a1c9d73fb4263cc1f475b7671b95bffcd110a0659692e5692001262abd"
                && launch_ref["sha256"]
                    == "d795621cd4cdcb16fb70abfe689d8e12b18e1287ed78878d4d342e742a0128fb"
                && prior.is_some_and(|p| p["InvocationID"] == iid
                    && p["Id"] == unit
                    && p["MainPID"] == launch["unit"]["MainPID"]
                    && p["ActiveState"] == "active"
                    && p["SubState"] == "running"),
            "changed v161 original park"
        );
    }
    let bspec = binding(&book["spec"])?;
    let _ = sealed(&bspec)?;
    let command = book["args"]
        .as_array()
        .context("223 holding argv")?
        .iter()
        .map(|a| a.as_str().context("223 argv string"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        command
            == [
                "/var/lib/jetstreamer/horizon223-holding-production-facdd1e9-20261120-v1/jetstreamer-r2",
                if park {
                    "holding-foundation-private-park"
                } else {
                    "holding-foundation-private-check-retire"
                },
                text(&book["spec"], "path")?,
                "--spec-sha256",
                &bspec.sha256,
                "--self-sha256",
                "b88cf6d908b3f03e6d9bbabc833762b0a72f77dcb1ba3e337bbde4d5dfbbb49d"
            ],
        "223 private holding command"
    );
    if !park {
        let parked = custodied(
            &Path::new("/home/ubuntu/.codex/diagnostics")
                .join(PARK.trim_end_matches(".service"))
                .join("completion.json"),
        )?;
        ensure!(
            book["custody"] == parked["native_result"]
                && book["fleet"]["sha256"]
                    == "82b0bbdf68c4040b061e24693a35de6e787cf5a5b34bf993e8548f531d9ff8d8"
                && book["disk_reserve"] == 268435456
                && book["requested_memory"] == 4294967296u64,
            "holding check not the v161 booked successor"
        );
        if next["ActiveState"] == "active" {
            let rows = original_rows(unit, None)?;
            let starts = rows
                .iter()
                .filter(|r| r["MESSAGE_ID"] == STARTED)
                .collect::<Vec<_>>();
            ensure!(
                rows.iter().all(|r| r["INVOCATION_ID"] == iid
                    && r["UNIT"] == unit
                    && r["_UID"] == "0"
                    && r["_PID"] == "1"
                    && r["_BOOT_ID"] == BOOT
                    && r["MESSAGE_ID"] != DONE
                    && r["MESSAGE_ID"] != "d9b373ed55a64feb8242e02dbe79a49c")
                    && starts.len() == 1
                    && starts[0]["JOB_RESULT"] == "done"
                    && text(starts[0], "MESSAGE")?.contains(&command.join(" ")),
                "different holding check native start"
            );
            ensure!(
                next["Id"] == unit
                    && next["InvocationID"] == iid
                    && next["MainPID"] == launch["unit"]["MainPID"]
                    && text(next, "MainPID")?.parse::<u64>()? > 1
                    && next["SubState"] == "running"
                    && next["Type"] == "exec"
                    && next["LoadState"] == "loaded"
                    && next["ControlGroup"] == format!("/system.slice/{unit}")
                    && next["Result"] == "success"
                    && next["NRestarts"] == "0"
                    && text(next, "ExecStart")?.contains(&command.join(" ")),
                "different live holding check"
            );
            return Ok(());
        }
    }
    ensure!(
        next["Id"] == unit
            && next["ActiveState"] == "inactive"
            && next["SubState"] == "dead"
            && next["MainPID"] == "0"
            && next["NRestarts"] == "0"
            && next["Result"] == "success"
            && next["ExecMainStatus"] == "0"
            && next["ControlGroup"] == ""
            && ((next["LoadState"] == "not-found"
                && next["InvocationID"] == ""
                && next["ExecStart"] == "")
                || (next["LoadState"] == "loaded"
                    && next["InvocationID"] == iid
                    && text(next, "ExecStart")?.contains(&command.join(" "))))
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(unit)
                .try_exists()?,
        "223 actor not positively drained"
    );
    let completed = custodied(&dir.join("completion.json"))?;
    let proof = binding(&completed["native_result"])?;
    ensure!(
        proof.path.to_str() == book["expected_result"].as_str()
            && completed["credited_disk_bytes"] == 0,
        "223 custody changed"
    );
    let val = custodied(&proof.path)?;
    ensure!(
        private157::file_binding(&proof.path)? == completed["native_result"],
        "holding native result digest changed"
    );
    let rows = original_rows(unit, None)?;
    let (start, end) = manager_pair(&rows, unit, iid, STARTED)?;
    ensure!(
        start["JOB_RESULT"] == "done" && text(start, "MESSAGE")?.contains(&command.join(" ")),
        "223 actual launch command"
    );
    if park {
        ensure!(
            completed["launch"] == launch_ref
                && completed["unit"] == unit
                && completed["invocation_id"] == iid
                && completed["pid1_start"] == start["__CURSOR"]
                && completed["pid1_success"] == end["__CURSOR"]
                && completed["source_retained"] == true,
            "223 original park completion"
        );
    } else {
        let parked = custodied(
            &Path::new("/home/ubuntu/.codex/diagnostics")
                .join(PARK.trim_end_matches(".service"))
                .join("completion.json"),
        )?;
        ensure!(
            completed["terminal"]["outcome"] == "success"
                && completed["terminal"]["invocation_id"] == iid
                && completed["terminal"]["launch"] == launch_ref
                && completed["terminal"]["booking"] == book_ref
                && completed["terminal"]["start_cursor"] == start["__CURSOR"]
                && completed["terminal"]["terminal_cursor"] == end["__CURSOR"]
                && val["schema"] == "jetstreamer-adaptive-223-private-retirement-check-v1"
                && val["check_only"] == true
                && val["local_retirement_authorized"] == false
                && val["original_source_hash_verified"] == true
                && val["check_spec"] == book["spec"]
                && book["custody"] == parked["native_result"]
                && completed["custody"] == parked["native_result"]
                && val["operation"]["custody"] == parked["native_result"],
            "223 distinct check custody"
        );
    }
    Ok(())
}

pub(super) fn peers(
    previous: &Value,
    current: &BTreeMap<String, Value>,
    exclude: &str,
) -> Result<()> {
    if previous["plan_sha256"] != V161_PLAN {
        return peers_265(previous, current, exclude);
    }
    ensure!(
        exclude == native266::UNIT && previous["observer_sha256"] == V161_OBS,
        "not the registered v161 observation"
    );
    let original = &previous["unit_census"];
    let mut adjusted = previous.clone();
    let old = &original[NATIVE_GUARD];
    let next = current
        .get(NATIVE_GUARD)
        .context("missing native 266 guard")?;
    ensure!(
        old["InvocationID"] == "9ee80cd07cfd45168aa69fc59f7b83a9",
        "changed v161 guard origin"
    );
    if old["InvocationID"] != next["InvocationID"] {
        let report = checked_report()?;
        let (h, _) = native266::startup(&binding(&report["native_handoff"])?)?;
        let gp = sealed(&binding(&h["guard_plan"])?)?;
        let root = Path::new(text(&gp, "receipt_directory")?);
        ensure!(
            gp["unit"] == native266::UNIT
                && gp["invocation_id"] == IID
                && gp["boot_id"] == "3b17d005-5c3a-4a0e-8841-da097e0957b5"
                && root
                    == Path::new(
                        "/var/lib/jetstreamer/horizon-native266-guard-receipts-de754f74bbac40b9877d3b912af14886"
                    ),
            "wrong native guard binding"
        );
        ensure!(
            guard_endpoint(old, &h, &gp, root)? < guard_endpoint(next, &h, &gp, root)?,
            "native 266 guard rotation reversed"
        );
        adjusted["unit_census"][NATIVE_GUARD]["InvocationID"] = next["InvocationID"].clone();
    }
    let old_park = &original[PARK];
    let next_park = current
        .get(PARK)
        .context("lost original park manager row")?;
    if next_park["ActiveState"] != old_park["ActiveState"] {
        holding(PARK, Some(old_park), next_park)?;
        adjusted["unit_census"][PARK] = next_park.clone();
    }
    let check_dir = Path::new("/home/ubuntu/.codex/diagnostics/horizon223-adaptive-check-v159-a1");
    if check_dir.join("launch.json").try_exists()? {
        // Collected new transients may have disappeared from automatic name discovery.
        let live;
        let next_check = if let Some(row) = current.get(CHECK) {
            row
        } else {
            live = json!(singleton227_capture::properties(
                CHECK,
                "Id,LoadState,ActiveState,SubState,MainPID,NRestarts,Result,ExecMainStatus,ControlGroup,InvocationID,ExecStart,Type"
            )?);
            ensure!(
                live["LoadState"] == "not-found",
                "unaccounted live holding check"
            );
            &live
        };
        holding(CHECK, None, next_check)?;
        if current.contains_key(CHECK) {
            adjusted["unit_census"][CHECK] = next_check.clone();
        }
    } else {
        ensure!(
            current
                .get(CHECK)
                .is_none_or(|r| r["LoadState"] == "not-found"),
            "unbound holding check"
        );
    }
    peers_265(&adjusted, current, exclude)
}
