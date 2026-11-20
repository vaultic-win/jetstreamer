//! Exact ordinary full265 v3 peer. Native265 and private diagnostics are separate owners.
use super::*;
use full265_owner as exact;

pub(super) const IID: &str = "182de64d33674f95b7758d410eb1812b";
const HANDOFF_SHA: &str = "40107f949cc5efa836a0637c41c4d642245b83507327c2983db60fe9457f9a88";
const ADMISSION: &str =
    "/var/lib/jetstreamer/horizon265-current-execution-0240-20261120-launch-r2/admission.json";
const ADMISSION_SHA: &str = "95b88e475d3aabe509101c07103ae5aee31fcb6018a01fbb775b9aa61855b82b";
pub(super) const GUARD_UNIT: &str = "horizon-265-replacement-20261119-protective-v3.service";
const TIMER: &str = "horizon-265-replacement-20261119-protective-v3.timer";
const ENV: &str = "/var/lib/jetstreamer/horizon265-replacement-20261119-guard-v3/guard.env";
const ENV_SHA: &str = "4c0864c1bc6408dc3a0559e321ca13003ac34beb182ad2690739da7421af5013";
const PLAN: &str = "/var/lib/jetstreamer/horizon265-replacement-20261119-guard-v3/guard-plan.json";
const PLAN_SHA: &str = "ebd9d801abd65d504dd4b63e8e6106fa771cae4d1b320a5ae3ce358df983501a";
const TOKEN: &str = "/var/lib/jetstreamer/horizon265-replacement-20261119-tokens-v3/182de64d33674f95b7758d410eb1812b/guard-admission.json";
const TOKEN_SHA: &str = "f07338f2ddb07ebc2a54b5d37a8fac753a6c1020085002bcc33ef2dcf29da4c3";
const HARD: u64 = 128_000_000_000;
const GROWTH: u64 = 506_191_984_640;
const FLOOR: u64 = 3_908_104_436_088;
const STATIC: &str = "/var/lib/jetstreamer/horizon265-replacement-20261119-static-v3";

pub(super) fn control() -> periodic::Control {
    periodic::Control {
        unit: GUARD_UNIT.into(),
        timer: TIMER.into(),
        maximum_memory_bytes: 1_073_741_824,
        service_source: Bound::new(
            format!("{STATIC}/{GUARD_UNIT}"),
            "049b5ddcba4a7ee373ee563b7768ca3850f507702763cebd92bb38f2577cf32d",
        ),
        timer_source: Bound::new(
            format!("{STATIC}/{TIMER}"),
            "2590387503c0e1a8d61838aaef782777d91f5e3d5cc275451cda86e0becc903f",
        ),
        guard_plan: Bound::new(PLAN, PLAN_SHA),
        executable: Bound::new(
            "/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard",
            "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d",
        ),
    }
}
pub(super) fn guard_environment() -> Result<()> {
    let environment = Bound::new(ENV, ENV_SHA);
    environment.artifact()?;
    ensure!(
        environment.bytes(true)? == format!("HORIZON265_GUARD_PLAN_SHA256={PLAN_SHA}\n").as_bytes(),
        "full265 guard digest environment changed"
    );
    Ok(())
}
pub(super) fn guard_properties(v: &Value) -> Result<()> {
    ensure!(
        v["EnvironmentFiles"] == format!("{ENV} (ignore_errors=no)")
            && v["Environment"] == ""
            && v["PassEnvironment"] == ""
            && v["UnsetEnvironment"] == ""
            && v["Group"] == "",
        "full265 guard environment override"
    );
    Ok(())
}
pub(super) fn guard_source(source: &str) -> Result<()> {
    let expected = format!("EnvironmentFile={ENV}");
    ensure!(
        source
            .lines()
            .filter(|l| l.starts_with("EnvironmentFile="))
            .collect::<Vec<_>>()
            == vec![expected.as_str()],
        "full265 guard EnvironmentFile changed"
    );
    guard_environment()
}
pub(super) fn guard_argv(c: &periodic::Control, expanded: bool) -> String {
    let argument = if expanded {
        PLAN_SHA
    } else {
        "${HORIZON265_GUARD_PLAN_SHA256}"
    };
    format!(
        "{} {} --plan-sha256 {argument} --self-sha256 {}",
        c.executable.path.display(),
        c.guard_plan.path.display(),
        c.executable.sha256
    )
}
fn owner(boot: &str) -> exact::Owner {
    exact::Owner {
        iid: IID.into(),
        boot: boot.into(),
        handoff_sha: HANDOFF_SHA.into(),
    }
}
pub(super) fn pipeline(e: &Value) -> bool {
    e["epoch"] == 265 && e["phase"] == "producer-finalization" && e["unit"]["Id"] == exact::UNIT
}
pub(super) fn diagnostic(d: &Value) -> bool {
    d["producer_unit"] == exact::UNIT
        || [
            "producer_before",
            "producer_after",
            "controller_before",
            "controller_after",
        ]
        .iter()
        .any(|k| d["observation"][*k]["unit"] == exact::UNIT)
}
fn primary(r: &Value) -> bool {
    r["range"]
        .as_str()
        .and_then(|s| s.split_once('-'))
        .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?)))
        .is_some_and(|(a, b)| a <= 265 && 265 <= b)
        || [
            "producer_before",
            "producer_after",
            "controller_before",
            "controller_after",
        ]
        .iter()
        .any(|k| r[*k]["unit"] == exact::UNIT)
}
fn rows<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    v[key]
        .as_array()
        .with_context(|| format!("full265 missing {key}"))
}
fn denied(v: &Value, fields: &[&str]) -> Result<()> {
    for k in fields {
        ensure!(v[*k] == false, "full265 unexpected authority {k}");
    }
    Ok(())
}
fn observation(o: &Value, current: &Value, resource_only: bool) -> Result<()> {
    ensure!(
        o["range"] == "265-265" && o["invocation_binding_stable"] == true,
        "full265 observation scope or continuity"
    );
    if !resource_only {
        ensure!(
            o["scratch_path"] == exact::ROOT
                && o.get("resource_only")
                    .is_none_or(|v| v.as_bool() == Some(false))
                && o.get("post_replay_finalization")
                    .is_none_or(|v| v.as_bool() == Some(false)),
            "full265 ordinary root/role changed"
        );
    }
    ensure!(
        o.get("scratch_path").is_none_or(|v| v == exact::ROOT),
        "full265 diagnostic carries stale root"
    );
    let pid = text(current, "MainPID")?.parse::<u64>()?;
    for k in [
        "producer_before",
        "producer_after",
        "controller_before",
        "controller_after",
    ] {
        let v = &o[k];
        ensure!(
            v["unit"] == exact::UNIT
                && v["invocation_id"] == IID
                && v["main_pid"] == pid
                && v["load_state"] == "loaded"
                && v["active_state"] == "active"
                && v["sub_state"] == "running"
                && v["restarts"] == 0
                && v["result"] == "success"
                && v["control_group"] == format!("/system.slice/{}", exact::UNIT)
                && v["cgroup"]["gauges"]["memory.max"] == HARD
                && v["cgroup"]["gauges"]["memory.swap.max"] == 0,
            "full265 complete observed owner/cap differs"
        );
    }
    Ok(())
}
fn fleet_owner(v: &Value) -> Result<()> {
    // Fleet census intentionally omits ControlPID/Job/envelope properties. Those
    // are read independently by check_manager and live::finite_owner; never invent them here.
    ensure!(
        v["Id"] == exact::UNIT
            && v["InvocationID"] == IID
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["Result"] == "success"
            && v["NRestarts"] == "0"
            && text(v, "MainPID")?.parse::<u64>()? > 1
            && v["ControlGroup"] == format!("/system.slice/{}", exact::UNIT)
            && periodic::stable_command(text(v, "ExecStart")?)?
                == format!("{} ; ignore_errors=no", exact::prefix()),
        "full265 fleet owner/command differs; require separate terminal transition"
    );
    Ok(())
}
fn booking(bookings: &[capacity::Reservation]) -> Result<()> {
    let r: Vec<_> = bookings.iter().filter(|r| r.unit == exact::UNIT).collect();
    ensure!(r.len() == 1, "full265 reservation omitted or duplicated");
    let r = r[0];
    ensure!(
        r.invocation_id == IID
            && r.maximum_memory_bytes == HARD
            && r.remaining_disk_growth_bytes >= GROWTH
            && r.minimum_free_bytes >= FLOOR
            && r.release.is_none(),
        "full265 original hard booking or floor reduced/released"
    );
    Ok(())
}
/// Pure cross-document checks; native265's terminal diagnostic never substitutes for this owner.
pub(super) fn validate(
    fleet: &Value,
    observer: &Value,
    bookings: &[capacity::Reservation],
    boot: &str,
) -> Result<bool> {
    let active = rows(fleet, "active")?;
    let pipelines = rows(fleet, "pipelines")?;
    let primary_rows = observer["replays"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let diagnostics = rows(observer, "diagnostic_replays")?;
    let present = bookings.iter().any(|r| r.unit == exact::UNIT)
        || active.iter().any(|a| a["epoch"] == 265)
        || pipelines.iter().any(pipeline)
        || primary_rows.iter().any(primary)
        || diagnostics.iter().any(diagnostic)
        || fleet["unit_census"][exact::UNIT]["LoadState"] == "loaded";
    if !present {
        return Ok(false);
    }
    booking(bookings)?;
    let current = &fleet["unit_census"][exact::UNIT];
    fleet_owner(current)?;
    let a: Vec<_> = active.iter().filter(|a| a["epoch"] == 265).collect();
    let p: Vec<_> = pipelines
        .iter()
        .filter(|e| e["epoch"] == 265 && !peers::selected(e))
        .collect();
    let r: Vec<_> = primary_rows.iter().filter(|r| primary(r)).collect();
    let d: Vec<_> = diagnostics.iter().filter(|d| diagnostic(d)).collect();
    ensure!(
        a.len() == 1,
        "full265 active owner omitted, doubled or private"
    );
    let a = a[0];
    ensure!(
        a["sampled_at_utc"] == fleet["sampled_at_utc"],
        "full265 fleet sample changed"
    );
    if a["phase"] == "replay" {
        ensure!(
            p.is_empty() && d.is_empty() && r.len() == 1,
            "full265 ordinary replay overlaps pipeline/diagnostic or lacks telemetry"
        );
        ensure!(
            a["producer"] == *current
                && a["controller"] == *current
                && a["scratch_path"] == exact::ROOT
                && a.get("ordinary_replay_claim")
                    .is_none_or(|v| v.as_bool() == Some(true))
                && a.get("private_qualification_only")
                    .is_none_or(|v| v.as_bool() == Some(false))
                && a["useful_work"] == r[0]["useful_work"],
            "full265 ordinary row/root differs"
        );
        observation(r[0], current, false)?;
    } else {
        ensure!(
            pipeline(a) && p.len() == 1 && p[0] == a && d.len() == 1 && r.len() <= 1,
            "full265 unregistered/private/duplicated finalization"
        );
        ensure!(
            a["unit"] == *current && a["live"] == true && a["expected_invocation_id"] == IID,
            "full265 finalizing owner differs"
        );
        denied(
            a,
            &[
                "ordinary_replay_claim",
                "current_sidecar_eta_valid",
                "grants_launch_or_publication_authority",
            ],
        )?;
        let proof = &a["finalization_evidence"];
        let sample = num(proof, "sampled_unix_seconds")?;
        fresh(sample, num(fleet, "recorded_unix_seconds")?, 300)?;
        let events = rows(proof, "events")?;
        let reconstructed = exact::events(
            &owner(boot),
            text(current, "MainPID")?.parse()?,
            events,
            sample,
        )?
        .context("full265 EOF absent")?;
        ensure!(
            *proof == reconstructed,
            "full265 finalization proof differs from exact original events"
        );
        let d = d[0];
        let o = &d["observation"];
        ensure!(
            d.get("scratch_path").is_none_or(|v| v == exact::ROOT),
            "full265 diagnostic root changed"
        );
        ensure!(
            d["range"] == "265-265"
                && d["producer_unit"] == exact::UNIT
                && d["expected_producer_invocation_id"] == IID
                && d["status"] == "observed"
                && d["error"].is_null()
                && d["post_replay_resource_only"] == true
                && o["resource_only"] == true
                && o["post_replay_finalization"] == true
                && o["phase_evidence"] == *proof
                && o["useful_work"]["sufficient_for_rates"] == false
                && o["useful_work"]["entry_progress_observed"] == false,
            "full265 finalization telemetry differs"
        );
        let flags = [
            "entry_replay",
            "ordinary_replay_claim",
            "terminal_completion_proven",
            "resource_release_authorized",
            "publication_authorized",
            "r2_mutations",
        ];
        denied(d, &flags)?;
        denied(o, &flags)?;
        observation(o, current, true)?;
        if let Some(r) = r.first() {
            observation(r, current, false)?;
            ensure!(
                exact::matches_primary(a, r),
                "full265 retained primary row not same finalizing owner"
            );
        }
    }
    Ok(true)
}
pub(super) fn verify_inputs(fleet: &Value) -> Result<()> {
    if !rows(fleet, "active")?.iter().any(|e| e["epoch"] == 265) {
        return Ok(());
    }
    let h = Bound::new(exact::HANDOFF, HANDOFF_SHA).sealed()?;
    let a = Bound::new(ADMISSION, ADMISSION_SHA).sealed()?;
    let gp = Bound::new(PLAN, PLAN_SHA).sealed()?;
    startup_bindings(&h, &a, &gp)?;
    guard_environment()?;
    // This is the existing qualified consumer, not a weaker handoff-schema shortcut.
    let accepted = exact::check_manager(&fleet["unit_census"][exact::UNIT])?;
    ensure!(
        accepted.iid == IID && accepted.handoff_sha == HANDOFF_SHA,
        "full265 consumer selected different actual handoff"
    );
    let root = Path::new(exact::ROOT);
    let m = fs::symlink_metadata(root)?;
    ensure!(
        root.canonicalize()? == root
            && m.is_dir()
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o777 == 0o700,
        "full265 root custody differs"
    );
    Ok(())
}

fn startup_bindings(h: &Value, a: &Value, gp: &Value) -> Result<()> {
    ensure!(
        h["producer"]["InvocationID"] == IID
            && h["admission"] == json!(Bound::new(ADMISSION, ADMISSION_SHA))
            && h["guard_plan"] == json!(Bound::new(PLAN, PLAN_SHA))
            && h["first_fire_token"] == json!(Bound::new(TOKEN, TOKEN_SHA)),
        "full265 actual startup binding changed"
    );
    ensure!(
        a["candidate_memory_max_bytes"] == HARD
            && a["candidate_root_cap_bytes"] == GROWTH
            && a["guard_minimum_free_bytes"] == FLOOR
            && a["native_admission"]["private_run_root"] == exact::ROOT
            && gp["worker_root"] == exact::ROOT
            && gp["invocation_id"] == IID
            && gp["minimum_free_bytes"] == FLOOR,
        "full265 original admission root/envelope differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
    fn fixture() -> (Value, Value, Vec<capacity::Reservation>) {
        let current = json!({"Id":exact::UNIT,"InvocationID":IID,"MainPID":"42","LoadState":"loaded",
            "ActiveState":"active","SubState":"running","Result":"success","NRestarts":"0",
            "ControlGroup":format!("/system.slice/{}",exact::UNIT),
            "ExecStart":format!("{} ; ignore_errors=no ; start_time=[x] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }}",exact::prefix())});
        let u = json!({"unit":exact::UNIT,"invocation_id":IID,"main_pid":42,"load_state":"loaded",
            "active_state":"active","sub_state":"running","result":"success","restarts":0,
            "control_group":format!("/system.slice/{}",exact::UNIT),"cgroup":{"gauges":{"memory.max":HARD,"memory.swap.max":0}}});
        let replay = json!({"range":"265-265","scratch_path":exact::ROOT,"invocation_binding_stable":true,
            "producer_before":u,"producer_after":u,"controller_before":u,"controller_after":u,
            "useful_work":{"sufficient_for_rates":true,"slot_delta":3}});
        let active = json!({"epoch":265,"phase":"replay","producer":current,"controller":current,
            "scratch_path":exact::ROOT,"sampled_at_utc":"sample","useful_work":replay["useful_work"]});
        let f = json!({"active":[active],"pipelines":[],"diagnostics":[],"auxiliary_diagnostics":[],
            "unit_census":{(exact::UNIT):current},"sampled_at_utc":"sample","recorded_unix_seconds":100});
        let o = json!({"replays":[replay],"diagnostic_replays":[]});
        let r = vec![capacity::Reservation {
            unit: exact::UNIT.into(),
            invocation_id: IID.into(),
            maximum_memory_bytes: HARD,
            remaining_disk_growth_bytes: GROWTH,
            minimum_free_bytes: FLOOR,
            source: Bound::new("/unused", "a".repeat(64)),
            release: None,
        }];
        (f, o, r)
    }
    fn check(f: &Value, o: &Value, r: &[capacity::Reservation]) -> Result<()> {
        finalization::validate(f, o, r, BOOT)
    }
    #[test]
    fn full_finalization_dispatch_accepts_ordinary265_with_complete_owner_and_booking() {
        let (f, mut o, r) = fixture();
        check(&f, &o, &r).unwrap();
        // Same epoch, distinct completed native owner: retain its diagnostic unchanged.
        let old: Value = serde_json::from_str(include_str!(
            "fixtures/retained-native265-diagnostic-20261119.json"
        ))
        .unwrap();
        // Fixture is the actual single diagnostic row, not an invented ordinary265 record.
        o["diagnostic_replays"].as_array_mut().unwrap().push(old);
        check(&f, &o, &r).unwrap();
    }
    #[test]
    fn ordinary265_rejects_omitted_duplicate_private_or_stale_roots() {
        let (f, o, r) = fixture();
        for (pointer, value) in [
            ("/active", json!([])),
            ("/active/0/phase", json!("diagnostic-qualification")),
            (
                "/active/0/scratch_path",
                json!(
                    "/home/ubuntu/.jetstreamer-private/qualification-265-replacement-20261119-v2"
                ),
            ),
            ("/active/0/producer/InvocationID", json!("b".repeat(32))),
            ("/active/0/sampled_at_utc", json!("stale")),
            (
                "/diagnostics",
                json!([{"epoch":265,"unit":f["unit_census"][exact::UNIT],"live":true}]),
            ),
        ] {
            let mut b = f.clone();
            *b.pointer_mut(pointer).unwrap() = value;
            assert!(check(&b, &o, &r).is_err(), "{pointer}");
        }
        let mut b = f.clone();
        b["active"]
            .as_array_mut()
            .unwrap()
            .push(f["active"][0].clone());
        assert!(check(&b, &o, &r).is_err());
        for (pointer, value) in [
            ("/replays", json!([])),
            ("/replays/0/range", json!("264-266")),
            ("/replays/0/scratch_path", json!("/stale")),
            ("/replays/0/producer_after/main_pid", json!(43)),
            (
                "/replays/0/controller_before/cgroup/gauges/memory.max",
                json!(HARD - 4096),
            ),
        ] {
            let mut b = o.clone();
            *b.pointer_mut(pointer).unwrap() = value;
            assert!(check(&f, &b, &r).is_err(), "{pointer}");
        }
        let mut b = o.clone();
        b["replays"]
            .as_array_mut()
            .unwrap()
            .push(o["replays"][0].clone());
        assert!(check(&f, &b, &r).is_err());
    }
    #[test]
    fn full265_cannot_drop_reduce_or_release_a_reservation() {
        let (f, o, r) = fixture();
        assert!(check(&f, &o, &[]).is_err());
        let mut dup = r.clone();
        dup.push(r[0].clone());
        assert!(check(&f, &o, &dup).is_err());
        for field in [
            "maximum_memory_bytes",
            "remaining_disk_growth_bytes",
            "minimum_free_bytes",
        ] {
            let mut v = serde_json::to_value(&r[0]).unwrap();
            v[field] = json!(1);
            assert!(
                check(&f, &o, &[serde_json::from_value(v).unwrap()]).is_err(),
                "{field}"
            );
        }
        let mut b = r.clone();
        b[0].release = Some(Bound::new("/fake-release", "a".repeat(64)));
        assert!(check(&f, &o, &b).is_err());
        let cap = capacity::arithmetic(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            1,
            &r,
            &BTreeMap::new(),
            (0, control().maximum_memory_bytes),
        )
        .unwrap();
        assert_eq!(
            cap["memory_obligation_after_bytes"],
            HOST + CONTROL + MEMORY + HARD + 1_073_741_824
        );
        assert_eq!(cap["retained_disk_growth_bytes"], GROWTH);
        assert_eq!(cap["protected_existing_floor_bytes"], FLOOR);
    }
    fn finalizing() -> (Value, Value, Vec<capacity::Reservation>) {
        let (mut f, mut o, r) = fixture();
        let events=[format!("jetstreamer::firehose] processed slot {}",exact::LAST_SLOT),"jetstreamer::firehose] 🚒 firehose finished successfully.".into()]
            .into_iter().enumerate().map(|(i,m)|json!({"MESSAGE":m,"_SYSTEMD_UNIT":exact::UNIT,"_SYSTEMD_INVOCATION_ID":IID,
                "_PID":"42","_UID":"1000","_EXE":exact::NODE,"_CMDLINE":exact::command(),"_BOOT_ID":BOOT.replace('-',""),
                "__REALTIME_TIMESTAMP":((90+i as u64)*1_000_000).to_string()})).collect::<Vec<_>>();
        let proof = exact::events(&owner(BOOT), 42, &events, 100)
            .unwrap()
            .unwrap();
        let a = json!({"epoch":265,"phase":"producer-finalization","unit":f["unit_census"][exact::UNIT],"live":true,
            "expected_invocation_id":IID,"sampled_at_utc":"sample","finalization_evidence":proof,
            "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"grants_launch_or_publication_authority":false});
        f["active"] = json!([a]);
        f["pipelines"] = json!([a]);
        let mut observation = o["replays"][0].clone();
        observation["resource_only"] = json!(true);
        observation["post_replay_finalization"] = json!(true);
        observation["phase_evidence"] = proof;
        observation["useful_work"] =
            json!({"entry_progress_observed":false,"sufficient_for_rates":false});
        let mut d = json!({"range":"265-265","producer_unit":exact::UNIT,"expected_producer_invocation_id":IID,
            "status":"observed","error":null,"post_replay_resource_only":true});
        for k in [
            "entry_replay",
            "ordinary_replay_claim",
            "terminal_completion_proven",
            "resource_release_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            d[k] = json!(false);
            observation[k] = json!(false);
        }
        d["observation"] = observation;
        o["diagnostic_replays"] = json!([d]);
        (f, o, r)
    }
    #[test]
    fn full265_finalizing_resource_diagnostic_is_not_private_or_second_replay() {
        let (f, o, r) = finalizing();
        check(&f, &o, &r).unwrap();
        let mut without_primary = o.clone();
        without_primary["replays"] = json!([]);
        check(&f, &without_primary, &r).unwrap();
        let mut b = f.clone();
        b["active"]
            .as_array_mut()
            .unwrap()
            .push(fixture().0["active"][0].clone());
        assert!(check(&b, &o, &r).is_err());
        for (pointer, value) in [
            ("/diagnostic_replays", json!([])),
            (
                "/diagnostic_replays/0/expected_producer_invocation_id",
                json!("b".repeat(32)),
            ),
            (
                "/diagnostic_replays/0/observation/phase_evidence/producer_terminal_proven",
                json!(true),
            ),
            (
                "/diagnostic_replays/0/resource_release_authorized",
                json!(true),
            ),
        ] {
            let mut b = o.clone();
            *b.pointer_mut(pointer).unwrap() = value;
            assert!(check(&f, &b, &r).is_err(), "{pointer}");
        }
        let mut b = f.clone();
        b["active"][0]["finalization_evidence"]["events"][1]["_BOOT_ID"] = json!("0".repeat(32));
        b["pipelines"] = b["active"].clone();
        assert!(check(&b, &o, &r).is_err());
        let mut b = o.clone();
        b["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(o["diagnostic_replays"][0].clone());
        assert!(check(&f, &b, &r).is_err());
    }
    #[test]
    fn actual_sealed265_startup_inputs_cannot_be_rebound_to_an_old_attempt() {
        let hb = include_bytes!("fixtures/full265-v3-startup-handoff-20261120.json");
        let ab = include_bytes!("fixtures/full265-v3-admission-20261120.json");
        let gb = include_bytes!("fixtures/full265-v3-guard-plan-20261120.json");
        assert_eq!(digest(hb), HANDOFF_SHA);
        assert_eq!(digest(ab), ADMISSION_SHA);
        assert_eq!(digest(gb), PLAN_SHA);
        let h: Value = serde_json::from_slice(hb).unwrap();
        let a: Value = serde_json::from_slice(ab).unwrap();
        let g: Value = serde_json::from_slice(gb).unwrap();
        startup_bindings(&h, &a, &g).unwrap();
        for (pointer, value) in [
            ("/producer/InvocationID", json!("b".repeat(32))),
            ("/guard_plan/sha256", json!("0".repeat(64))),
            ("/first_fire_token/path", json!("/old/token")),
        ] {
            let mut b = h.clone();
            *b.pointer_mut(pointer).unwrap() = value;
            assert!(startup_bindings(&b, &a, &g).is_err());
        }
        let mut b = g.clone();
        b["worker_root"] =
            json!("/home/ubuntu/.jetstreamer-private/qualification-265-replacement-20261119-v2");
        assert!(startup_bindings(&h, &a, &b).is_err());
        let mut b = a.clone();
        b["native_admission"]["private_run_root"] = json!("/stale");
        assert!(startup_bindings(&h, &b, &g).is_err());
    }
}
