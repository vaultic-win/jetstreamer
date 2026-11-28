//! The staged recovery has an independent PID1 owner and an additional full booking.
use super::*;
pub(crate) const UNIT: &str = "horizon-upload-247-staged-680e1173-v1.service";
const IID: &str = "3e08307874db424886cd8c46b3ecfba6";
const PID: &str = "2149076";
pub(super) const HARD_CAP: u64 = 10 << 30;
const TOTAL_MEMORY: u64 = HARD_CAP + (512 << 20);
const DISK: u64 = 1 << 30;
const FLOOR: u64 = 3_908_104_436_088;
const IMAGE: &str = "/var/lib/jetstreamer/horizon247-public-images-680e1173-v1/jetstreamer-r2";
const IMAGE_SHA: &str = "89ee0047fca4b46840230472b2a85aa518cfde6e7a556b20ed43eccf14607571";
const PLAN: &str = "/var/lib/jetstreamer/horizon247-public-reader-680e1173-v1/epoch-247-plan.json";
const PLAN_SHA: &str = "e9e7234224b04ab9ae03bfa7459344bec37a6bb241c84e98a7e8dbcaa29bdd1e";
const ROOT: &str = "/home/ubuntu/.codex/diagnostics/horizon-upload-247-staged-680e1173-v1";
const FRAGMENT_SHA: &str = "9d7d7dc43fbcd84e77f7a110a08892eaf18b4869cb56bc5bf828d8c6dec8ed77";
const BOOT: &str = "3b17d005-5c3a-4a0e-8841-da097e0957b5";
fn source(name: &str, sha: &str) -> Bound {
    Bound::new(Path::new(ROOT).join(name), sha)
}
fn booking() -> Bound {
    source(
        "booking.json",
        "f2716aa9619500bed9e722e9a5de23c80f57203d137f6b937d27ba1a9972919e",
    )
}
fn launch() -> Bound {
    source(
        "launch.json",
        "0ae7be456361ec2a5870b8ae0907a463cf750ecd07de0b2f45b7252c807e1380",
    )
}
fn witness() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../fixtures/staged-delivery247-v145.json"
    ))?)
}

pub(super) fn selected(e: &Value) -> bool {
    e["epoch"] == 247 && e["phase"] == "upload-readback" && e["unit"]["Id"] == UNIT
}
pub(super) fn mentions(e: &Value) -> bool {
    e["expected_invocation_id"] == IID
        || ["producer", "controller", "unit"]
            .iter()
            .any(|k| e[*k]["Id"] == UNIT || e[*k]["InvocationID"] == IID)
}
fn census(current: &Value, w: &Value) -> Result<()> {
    live::same_owner(&w["unit"], current)?;
    ensure!(
        current["Type"] == "exec" && current["ExecMainStatus"] == "0",
        "staged uploader execution changed"
    );
    Ok(())
}
pub(super) fn validate_roster(f: &Value, rows: &[capacity::Reservation]) -> Result<()> {
    let pipelines = f["pipelines"].as_array().context("delivery pipelines")?;
    let active = f["active"].as_array().context("active delivery census")?;
    let mut entries = pipelines.iter().filter(|e| mentions(e) || selected(e));
    let mut bookings = rows
        .iter()
        .filter(|r| r.unit == UNIT || r.invocation_id == IID);
    let mut owners = active.iter().filter(|a| mentions(a) || selected(a));
    let Some(e) = entries.next() else {
        ensure!(
            bookings.next().is_none()
                && owners.next().is_none()
                && f["unit_census"][UNIT]["InvocationID"] != IID,
            "staged delivery missing from census"
        );
        return Ok(());
    };
    let w = witness()?;
    let live = e["live"].as_bool().context("staged owner liveness")?;
    ensure!(
        entries.next().is_none()
            && selected(e)
            && e["expected_invocation_id"] == IID
            && e["unit"] == f["unit_census"][UNIT]
            && e["sampled_at_utc"] == f["sampled_at_utc"]
            && e["ordinary_replay_claim"] == false
            && e["grants_launch_or_publication_authority"] == false
            && e["current_sidecar_eta_valid"] == false
            && e.get("finalization_evidence") == Some(&Value::Null)
            && e.get("producer").is_none()
            && e.get("controller").is_none()
            && e["evidence"] == json!([booking(), launch()])
            && owners.next() == live.then_some(e)
            && owners.next().is_none(),
        "staged delivery identity, evidence or active membership changed"
    );
    if live {
        census(&e["unit"], &w)?;
    } else {
        terminal_identity(&e["unit"], &w)?;
    }
    ensure!(
        pipelines.iter().any(|p| original(p) && p["live"] == false),
        "staged delivery lacks its separately retained original"
    );
    let r = bookings
        .next()
        .context("staged delivery has no reservation")?;
    ensure!(
        bookings.next().is_none()
            && r.unit == UNIT
            && r.invocation_id == IID
            && r.maximum_memory_bytes == TOTAL_MEMORY
            && r.remaining_disk_growth_bytes == DISK
            && r.minimum_free_bytes == FLOOR
            && r.release.is_none()
            && (live
                || r.source
                    == Bound::new(
                        "/var/lib/jetstreamer/horizon-native257-current-bookings-v145-ops-v1/recovery247-source.json",
                        "894935276887541c6be208249be4e0ddd42864f23757a831b6caa01a774e046a"
                    )),
        "staged delivery booking changed"
    );
    Ok(())
}
pub(super) fn manager(v: &Value) -> Result<()> {
    let w = witness()?;
    census(v, &w)?;
    for (k, expected) in w["manager"]
        .as_object()
        .context("staged manager evidence")?
    {
        ensure!(&v[k] == expected, "staged uploader manager changed {k}");
    }
    Ok(())
}
pub(super) fn mapped_owner() -> Result<()> {
    ensure!(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == BOOT,
        "staged uploader boot changed"
    );
    let w = witness()?;
    let root = Path::new("/proc").join(PID);
    let mapped = root.join("exe");
    let stamp = fs::read_to_string(root.join("stat"))?;
    let ticks = stamp
        .rsplit_once(')')
        .context("staged /proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("staged start ticks")?;
    let argv = fs::read(root.join("cmdline"))?;
    let command = w["argv"]
        .as_array()
        .context("staged argv")?
        .iter()
        .map(|a| a.as_str().context("staged argument"))
        .collect::<Result<Vec<_>>>()?
        .join("\0")
        + "\0";
    ensure!(
        w["start_ticks"] == ticks
            && fs::read_link(&mapped)? == Path::new(IMAGE)
            && metadata_identity(&fs::metadata(&mapped)?) == identity(Path::new(IMAGE))?
            && argv == command.as_bytes()
            && fs::read_to_string(root.join("cgroup"))?.trim()
                == format!("0::/system.slice/{UNIT}"),
        "staged uploader process replaced"
    );
    Ok(())
}
pub(super) fn verify_inputs(e: &Value) -> Result<()> {
    let w = witness()?;
    let b = booking().json()?;
    let l = launch().json()?;
    let c = source(
        "pipeline-claim.json",
        "8ef94d868ee29e47f9777aaaa9ba941df11d176334984e5a00f2e713c4a05b80",
    )
    .json()?;
    ensure!(
        c == w["claim"]
            && e["evidence"] == c["evidence"]
            && l["booking"] == json!(booking())
            && c["expected_exec_start"] == l["unit"]["ExecStart"]
            && c["invocation_id"] == l["unit"]["InvocationID"]
            && b["argv"] == w["argv"]
            && b["unit"] == UNIT
            && b["historical_booking_preserved"] == true
            && b["failed_delivery_retained_entire_nominal_booking"]["InvocationID"] == IID247
            && b["approved_plan"] == json!(Bound::new(PLAN, PLAN_SHA))
            && b["capacity_credit"] == 0
            && b["local_reclamation_credit"] == 0
            && b["additional_memory_reserve"] == TOTAL_MEMORY
            && b["disk_reserve"] == DISK,
        "staged admission or original delivery binding changed"
    );
    ensure!(
        binding(&b["admission"])?.sealed()?["protected_existing_floor_bytes"] == FLOOR,
        "staged inherited floor changed"
    );
    binding(&b["original_terminal"])?.json()?;
    Bound::new(PLAN, PLAN_SHA).sealed()?;
    Bound::new(IMAGE, IMAGE_SHA).artifact()?;
    Bound::new(text(&w["manager"], "FragmentPath")?, FRAGMENT_SHA).bytes(false)?;
    if e["live"] == true {
        mapped_owner()
    } else {
        terminal_identity(&e["unit"], &w)
    }
}

fn terminal_identity(v: &Value, w: &Value) -> Result<()> {
    successor::evidence::terminal(v, UNIT, IID)?;
    ensure!(
        v["Type"] == "exec"
            && v["LoadState"] == "loaded"
            && v["ControlGroup"] == ""
            && periodic::stable_command(text(v, "ExecStart")?)?
                == periodic::stable_command(text(&w["unit"], "ExecStart")?)?,
        "staged failure command changed"
    );
    Ok(())
}
pub(super) fn terminal(n: &mut Native, v: &Value) -> Result<()> {
    let w = witness()?;
    terminal_identity(v, &w)?;
    for (key, value) in w["manager"].as_object().context("staged manager proof")? {
        ensure!(&v[key] == value, "staged terminal manager changed {key}");
    }
    ensure!(v["ExecMainCode"] == "1", "staged failure exit type");
    Bound::new(text(v, "FragmentPath")?, FRAGMENT_SHA).bytes(false)?;
    let bytes = n.run(
        "/usr/bin/journalctl",
        &[
            "--boot=0",
            "--no-pager",
            "--output=json",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={IID}"),
        ],
    )?;
    let events = std::str::from_utf8(&bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        events.iter().all(|r| r["_PID"] == "1"
            && r["_UID"] == "0"
            && r["UNIT"] == UNIT
            && r["INVOCATION_ID"] == IID
            && r["_BOOT_ID"] == BOOT.replace('-', ""))
            && events
                .iter()
                .filter(|r| r["MESSAGE_ID"] == "d9b373ed55a64feb8242e02dbe79a49c"
                    && r["UNIT_RESULT"] == "exit-code")
                .count()
                == 1
            && events
                .iter()
                .filter(|r| r["EXIT_CODE"] == "exited" && r["EXIT_STATUS"] == v["ExecMainStatus"])
                .count()
                == 1,
        "staged original PID1 failure missing"
    );
    for path in [
        Path::new("/proc").join(PID),
        Path::new("/sys/fs/cgroup/system.slice").join(UNIT),
    ] {
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => bail!("staged process or cgroup not drained"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_recovery_retains_both_actual_v147_rows_without_credit() -> Result<()> {
        let f: Value = serde_json::from_str(include_str!(
            "../../../../jetstreamer-horizon-observe/src/fixtures/successor247-history.json"
        ))?;
        let mut fleet = json!({"sampled_at_utc":f["observed_fleet_time"],"pipelines":f["historical_fleet_rows"],"active":f["historical_active"],"unit_census":{},"diagnostics":[],"auxiliary_diagnostics":[]});
        let mut units = json!({});
        for e in fleet["pipelines"].as_array().unwrap() {
            units[e["unit"]["Id"].as_str().unwrap()] = e["unit"].clone();
        }
        fleet["unit_census"] = units;
        let mut rows: Vec<capacity::Reservation> =
            serde_json::from_value(f["historical_reservations"]["rows"].clone())?;
        super::super::validate_roster(&fleet, &rows)?;
        let idx = fleet["pipelines"]
            .as_array()
            .unwrap()
            .iter()
            .position(|e| e["unit"]["Id"] == UNIT)
            .unwrap();
        let mut ended = fleet["unit_census"][UNIT].clone();
        for (k, v) in [
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("MainPID", "0"),
            ("ControlGroup", ""),
        ] {
            ended[k] = json!(v);
        }
        fleet["pipelines"][idx]["unit"] = ended.clone();
        fleet["unit_census"][UNIT] = ended;
        fleet["pipelines"][idx]["live"] = json!(false);
        fleet["active"] = json!([]);
        super::super::validate_roster(&fleet, &rows)?;
        assert_eq!(
            rows.iter().map(|r| r.maximum_memory_bytes).sum::<u64>(),
            18_274_289_152
        );
        assert_eq!(
            rows.iter()
                .map(|r| r.remaining_disk_growth_bytes)
                .sum::<u64>(),
            186_444_658_784
        );
        for r in &rows {
            assert!(r.release.is_none());
        }
        let pos = rows.iter().position(|r| r.unit == UNIT).unwrap();
        rows[pos].remaining_disk_growth_bytes -= 1;
        assert!(super::super::validate_roster(&fleet, &rows).is_err());
        Ok(())
    }
    fn pair() -> (Value, Vec<capacity::Reservation>) {
        let original_unit = terminal::witness().unwrap()["transition"]["after"].clone();
        let original = json!({"epoch":247,"phase":"upload-readback","live":false,"expected_invocation_id":IID247,
            "unit":original_unit,"sampled_at_utc":"sample","ordinary_replay_claim":false,"finalization_evidence":null,"current_sidecar_eta_valid":false,
            "grants_launch_or_publication_authority":false,"evidence":[Bound::new(REVIEW,REVIEW_SHA),Bound::new(FLEET_OWNER,FLEET_OWNER_SHA)]});
        let w = witness().unwrap();
        let mut staged = original.clone();
        staged["unit"] = w["unit"].clone();
        staged["live"] = json!(true);
        staged["expected_invocation_id"] = json!(IID);
        staged["evidence"] = w["claim"]["evidence"].clone();
        let f = json!({"pipelines":[original,staged],"active":[staged],"unit_census":{(UNIT247):original_unit,(UNIT):w["unit"]},
            "sampled_at_utc":"sample","diagnostics":[],"auxiliary_diagnostics":[]});
        let rows = vec![
            capacity::Reservation {
                unit: UNIT247.into(),
                invocation_id: IID247.into(),
                maximum_memory_bytes: 7_000_000_000,
                remaining_disk_growth_bytes: 185_370_916_960,
                minimum_free_bytes: 3_000_000_000_000,
                source: terminal::booking(),
                release: None,
            },
            capacity::Reservation {
                unit: UNIT.into(),
                invocation_id: IID.into(),
                maximum_memory_bytes: TOTAL_MEMORY,
                remaining_disk_growth_bytes: DISK,
                minimum_free_bytes: FLOOR,
                source: booking(),
                release: None,
            },
        ];
        (f, rows)
    }
    #[test]
    fn joint_roster_charges_the_drained_original_and_the_entire_new_envelope() {
        let (f, rows) = pair();
        finalization::validate(&f, &json!({"diagnostic_replays":[]}), &rows, BOOT).unwrap();
        assert_eq!(owner_cap(&rows[1]), HARD_CAP);
        let credit = BTreeMap::from([(UNIT.to_owned(), HARD_CAP)]);
        let result = |rows: &[capacity::Reservation], currents: &BTreeMap<String, u64>| {
            capacity::booked_arithmetic(
                (u64::MAX, u64::MAX, u64::MAX),
                1,
                rows,
                currents,
                (0, 0),
                (0, 0),
            )
            .unwrap()
        };
        let initial = result(&rows[..1], &BTreeMap::new());
        let joint = result(&rows, &credit);
        for (k, diff) in [
            ("memory_obligation_after_bytes", TOTAL_MEMORY),
            ("remaining_hard_growth_bytes", TOTAL_MEMORY - HARD_CAP),
            ("retained_disk_growth_bytes", DISK),
        ] {
            assert_eq!(num(&joint, k).unwrap() - num(&initial, k).unwrap(), diff);
        }
        assert!(super::super::validate_roster(&f, &rows[..1]).is_err());
        assert!(super::super::validate_roster(&f, &rows[1..]).is_err());
        for (field, v) in [
            ("maximum_memory_bytes", json!(HARD_CAP)),
            ("remaining_disk_growth_bytes", json!(0)),
            ("minimum_free_bytes", json!(0)),
            ("release", json!(booking())),
        ] {
            let mut bad = rows.clone();
            let mut row = serde_json::to_value(&bad[1]).unwrap();
            row[field] = v;
            bad[1] = serde_json::from_value(row).unwrap();
            assert!(super::super::validate_roster(&f, &bad).is_err(), "{field}");
        }
    }
    #[test]
    fn joint_delivery_rejects_replacement_claims_and_omitted_or_shared_owners() {
        let (f, rows) = pair();
        let check = |f: &Value| super::super::validate_roster(f, &rows);
        for (field, value) in [
            ("pipelines", json!([f["pipelines"][1]])),
            ("pipelines", json!([f["pipelines"][0]])),
            ("active", json!([f["pipelines"][0], f["pipelines"][1]])),
            ("active", json!([])),
            ("active", json!([f["active"][0], f["active"][0]])),
        ] {
            let mut bad = f.clone();
            bad[field] = value;
            assert!(check(&bad).is_err(), "{field}");
        }
        for (field, value) in [
            ("expected_invocation_id", json!(IID247)),
            ("evidence", f["pipelines"][0]["evidence"].clone()),
            ("sampled_at_utc", json!("old")),
            ("ordinary_replay_claim", json!(true)),
            ("live", json!(false)),
            ("grants_launch_or_publication_authority", json!(true)),
        ] {
            let mut bad = f.clone();
            bad["pipelines"][1][field] = value;
            bad["active"][0] = bad["pipelines"][1].clone();
            assert!(check(&bad).is_err(), "{field}");
        }
        for k in [
            "Id",
            "InvocationID",
            "ExecStart",
            "MainPID",
            "ControlGroup",
            "NRestarts",
        ] {
            let mut bad = f.clone();
            bad["unit_census"][UNIT][k] = json!("other");
            bad["pipelines"][1]["unit"] = bad["unit_census"][UNIT].clone();
            bad["active"][0] = bad["pipelines"][1].clone();
            assert!(check(&bad).is_err(), "{k}");
        }
    }
    #[test]
    #[ignore = "requires a booked root host check while the exact independently admitted successor is running"]
    fn original_and_staged_on_the_current_host() -> Result<()> {
        let review = Bound::new(
            std::env::var("HORIZON247_JOINT_REVIEW")?,
            std::env::var("HORIZON247_JOINT_REVIEW_SHA")?,
        )
        .sealed()?;
        let f = binding(&review["fleet"])?.json()?;
        let (rows, _, _) = admission::reservations(&review)?;
        super::super::validate_roster(&f, &rows)?;
        let entries = f["pipelines"].as_array().context("pipelines")?;
        let root = PathBuf::from(std::env::var("HORIZON247_TERMINAL_CAPTURE")?);
        fs::create_dir(&root)?;
        let mut n = Native {
            root,
            counter: 0,
            deadline: None,
        };
        for select in [original as fn(&Value) -> bool, selected] {
            let entry = entries
                .iter()
                .find(|e| select(e))
                .context("paired delivery missing")?;
            super::super::verify_inputs(entry)?;
        }
        let mut current = u64::MAX;
        for _ in 0..2 {
            let failed = n.show(UNIT247)?;
            terminal::observe(&mut n, &failed)?;
            let owner = n.show(UNIT)?;
            manager(&owner)?;
            mapped_owner()?;
            current = current.min(live::finite_owner(&owner, UNIT, IID, HARD_CAP)?);
        }
        ensure!(current <= HARD_CAP, "successor current outside its cap");
        save_json(
            &n.root,
            "pair.json",
            &json!({"fleet":review["fleet"],"original_current_memory_bytes":0,
            "staged_current_memory_bytes":current,"original_cap_bytes":7_000_000_000u64,"staged_cap_bytes":HARD_CAP,
            "staged_full_booking_bytes":TOTAL_MEMORY,"staged_disk_growth_bytes":DISK,"staged_inherited_floor_bytes":FLOOR,
            "resource_release_authorized":false,"publication_authorized":false}),
        )?;
        Ok(())
    }
}
