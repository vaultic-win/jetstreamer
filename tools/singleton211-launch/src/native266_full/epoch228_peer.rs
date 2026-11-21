//! The original guarded epoch 266 pilot spends its own cold-owner memory.
use super::*;
const IID: &str = "09dcaaddbbc34f3eb5f81c0a4f8a909e";
const PID: u64 = 2791171;
pub(super) const UNIT: &str = "horizon-qualify-266-general-v1.service";
pub(super) const SERVICE: &str = "horizon-266-general-protective-v1.service";
const TIMER: &str = "horizon-266-general-protective-v1.timer";
const CAP: u64 = 176_000_000_000;
pub(super) const EXCLUSIVE_DISK: u64 = (112 << 30) + (768 << 20); // First 266 disk QA is already charged.
fn handoff() -> Bound {
    Bound::new(
        "/var/lib/jetstreamer/horizon266-native-full-v165-a2/pilot/handoff.json",
        "1fd365a05f8f74c1456b1bfaf44199fd006afd6785d0161afca34fdf20e262d5",
    )
}
fn originals() -> Result<(Value, Value, Value)> {
    let h = handoff().sealed()?;
    let token = binding(&h["token"])?.sealed()?;
    let fit = binding(&h["held_fit"])?.sealed()?;
    let spec = binding(&h["spec"])?.sealed()?;
    let guard = binding(&h["guard"])?;
    let s = binding(&h["first_guard"])?.json()?;
    start::validate_sample_for(GUARD_SHA, &s, UNIT, IID, PID, &guard, None)?;
    let journal = binding(&token["guard_pid1"])?.sealed()?;
    full211_window::guard_clocks(
        rows(&journal, "pid1")?,
        &BOOT.replace('-', ""),
        SERVICE,
        text(&s, "guard_invocation_id")?,
    )?;
    ensure!(
        h["unit"] == UNIT
            && h["iid"] == IID
            && h["pid"] == PID
            && h["held_fit"] == token["held_fit"]
            && h["guard"] == token["guard"]
            && h["first_guard"] == token["first_guard"]
            && h["spec"] == token["spec"]
            && fit["winner"]["fits"] == true
            && fit["winner"]["root"] == 112u64 << 30
            && fit["winner"]["memory"] == CAP
            && spec["root_cap"] == fit["winner"]["root"]
            && fit["cpus"] == json!([32, 33, 34, 35, 36, 37, 38, 39])
            && num(&fit, "protected_floor")?.checked_add(112 << 30)
                == Some(num(&fit["winner"], "required_free")?)
            && CAP + GUARD_MEM + CONTROL_MEM <= 191932891136
            && guard.sealed()?["invocation_id"] == IID,
        "original bounded 266 handoff"
    );
    Ok((h, fit, spec))
}
fn terminal_receipt() -> Bound {
    Bound::new(
        "/home/ubuntu/.codex/diagnostics/horizon266-instruction-repair-v166-a1/terminal.json",
        "7445122e9ca61f7a7c46d7ca47140c63edb174c7e2fb97b56bff35bb7dd554ff",
    )
}
fn terminal_events(doc: &Value, events: &[Value]) -> Result<()> {
    let tags = [
        "39f53479d3a045ac8e11786248231fbf",
        "98e322203f7a4ed290d09fe03c09fe15",
        "d9b373ed55a64feb8242e02dbe79a49c",
    ];
    let saved = rows(doc, "pid1")?;
    let mut last = 0u64;
    for (index, mid) in tags.iter().enumerate() {
        let filtered = events
            .iter()
            .filter(|v| v["MESSAGE_ID"] == *mid)
            .collect::<Vec<_>>();
        let expected = saved
            .iter()
            .filter(|v| v["MESSAGE_ID"] == *mid)
            .collect::<Vec<_>>();
        ensure!(
            filtered.len() == 1 && expected.len() == 1,
            "ambiguous 266 terminal journal"
        );
        let e = filtered[0];
        let timestamp = text(e, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            e["__CURSOR"] == expected[0]["__CURSOR"]
                && e["UNIT"] == UNIT
                && e["INVOCATION_ID"] == IID
                && e["_BOOT_ID"] == BOOT.replace('-', "")
                && e["_PID"] == "1"
                && e["_UID"] == "0"
                && timestamp > last,
            "266 PID1 terminal source"
        );
        if index == 1 {
            ensure!(
                e["EXIT_CODE"] == "exited" && e["EXIT_STATUS"] == "1",
                "266 natural exit 1"
            );
        }
        if index == 2 {
            ensure!(e["UNIT_RESULT"] == "exit-code", "266 failed manager result");
        }
        last = timestamp;
    }
    ensure!(
        !events
            .iter()
            .any(|v| v["MESSAGE_ID"] == "de5b426a63be47a7b6ac3eaac82e2f6f"),
        "266 manager stopped this generation"
    );
    Ok(())
}
fn original_failure(doc: &Value) -> Result<()> {
    let m = &doc["manager"];
    let err = &doc["conversion_error"];
    ensure!(
        doc["handoff"] == json!(handoff())
            && doc["entry_progress_recorded"] == true
            && doc["resource_release_authorized"] == false
            && doc["restart_authorized"] == false
            && doc["full_epoch_qualified"] == false
            && m["InvocationID"] == IID
            && m["Id"] == UNIT
            && m["ActiveState"] == "failed"
            && m["SubState"] == "failed"
            && m["Result"] == "exit-code"
            && m["MainPID"] == "0"
            && m["ExecMainPID"] == "2791171"
            && m["NRestarts"] == "0"
            && m["ExecMainCode"] == "1"
            && m["ExecMainStatus"] == "1",
        "266 original terminal manager"
    );
    ensure!(
        err["_SYSTEMD_INVOCATION_ID"] == IID
            && err["_SYSTEMD_UNIT"] == UNIT
            && err["_PID"] == "2791171"
            && err["_UID"] == "1000"
            && err["_BOOT_ID"] == BOOT.replace('-', "")
            && text(err, "MESSAGE")?
                .contains("message.instructions: length 65 exceeds inline capacity 64"),
        "266 original conversion failure"
    );
    terminal_events(doc, rows(doc, "pid1")?)
}
fn terminal(n: &mut Native, m: &Value, root: &Path) -> Result<Bound> {
    let bound = terminal_receipt();
    let doc = bound.json()?;
    original_failure(&doc)?;
    let saved = &doc["manager"];
    for key in [
        "Id",
        "InvocationID",
        "ActiveState",
        "SubState",
        "Result",
        "NRestarts",
        "MainPID",
        "ExecMainCode",
        "ExecMainStatus",
        "ExecMainStartTimestampMonotonic",
    ] {
        ensure!(
            m.get(key).is_some() && m[key] == saved[key],
            "266 terminal field differs: {key}"
        );
    }
    for key in ["ExecMainPID", "ExecMainExitTimestampMonotonic"] {
        ensure!(
            command_field(n, UNIT, key)? == text(saved, key)?,
            "266 terminal execution changed"
        );
    }
    ensure!(
        m["Job"] == "" && m["ControlGroup"] == "" && m["ControlPID"] == "0",
        "266 pending control or cgroup"
    );
    live::verify_drained_group(UNIT)?;
    absent(Path::new("/proc/2791171"))?;
    let raw = n.run(
        "/usr/bin/journalctl",
        &[
            "-b",
            "-n",
            "32",
            "--no-pager",
            "-o",
            "json",
            "_UID=0",
            "_PID=1",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={IID}"),
        ],
    )?;
    let events = std::str::from_utf8(&raw)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    terminal_events(&doc, &events)?;
    let item = &doc["partial_archive"];
    let path = Path::new(text(item, "path")?);
    let st = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && path.starts_with(root.join("state"))
            && path.file_name().is_some_and(|s| s == "epoch-266.jet")
            && st.is_file()
            && st.dev() == fs::metadata(root)?.dev()
            && st.ino() == num(item, "inode")?
            && st.ino() == 4194330
            && st.len() == 0
            && item["size"] == 0,
        "266 partial custody changed"
    );
    Ok(bound)
}
// Only the original, preserved loop's future growth is discharged. The
// inherited free-space floor and every auxiliary disk charge still apply.
fn readonly_loop(root: &Path, img: &Path) -> Result<Bound> {
    let receipt = Bound::new(
        "/home/ubuntu/.codex/diagnostics/horizon266-closed-storage-v167-a1/completion.json",
        "f0312d5f559dd2adca57c89e5a01f1d66d1ea72512248e4635b0dd252aef3f76",
    );
    let completed = receipt.json()?;
    let kept = binding(&completed["readonly"])?.json()?;
    let saved = binding(&completed["before"])?.json()?;
    let image = fs::symlink_metadata(img)?;
    let guest = fs::symlink_metadata(root)?;
    let id = json!([
        guest.dev(),
        guest.ino(),
        image.dev(),
        image.ino(),
        image.len()
    ]);
    ensure!(
        completed["epoch"] == 266
            && completed["partial"]["inode"] == 4194330
            && kept["identity"] == id
            && id == json!([1795, 2, 66305, 18314256, 112u64 << 30])
            && saved["contents"] == kept["contents"]
            && kept["block_readonly"] == true
            && kept["guest_write_errno"] == libc::EROFS
            && image.is_file()
            && image.uid() == 0
            && image.nlink() == 1
            && image.mode() & 0o777 == 0o600
            && img.canonicalize()? == img
            && root.canonicalize()? == root
            && fs::read_to_string("/sys/block/loop3/loop/backing_file")?.trim()
                == img.to_str().context("266 backing path")?
            && fs::read_to_string("/sys/block/loop3/ro")?.trim() == "1",
        "original epoch 266 retained read-only loop"
    );
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    ensure!(
        mountinfo.lines().any(|line| {
            let Some((left, right)) = line.split_once(" - ") else {
                return false;
            };
            let fields: Vec<_> = left.split_whitespace().collect();
            let fs: Vec<_> = right.split_whitespace().collect();
            fields.len() >= 6
                && fields[2] == "7:3"
                && fields[3] == "/"
                && Some(fields[4]) == root.to_str()
                && fields[5].split(',').any(|f| f == "ro")
                && fs.len() == 3
                && fs[0] == "ext4"
                && fs[1] == "/dev/loop3"
                && fs[2].split(',').any(|f| f == "ro")
        }),
        "266 guest must remain read-only at both filesystem and mount"
    );
    Ok(receipt)
}
pub(super) fn verify(n: &mut Native, r: &Value) -> Result<Value> {
    ensure!(
        r["bounded266_handoff"] == json!(handoff()),
        "review must retain the issued 266 pilot"
    );
    let (h, fit, spec) = originals()?;
    let proof = funding::discharge()?;
    ensure!(
        fit["cold_discharge"] == json!(proof),
        "266 allocation requires its own genuine cold discharge"
    );
    let m = n.show(UNIT)?;
    let prof = Profile::new(Lane::Epoch266, "pilot")?;
    let failure = if m["ActiveState"] == "active" {
        absent(&terminal_receipt().path)?;
        live::finite_owner(&m, UNIT, IID, CAP)?;
        ensure!(m["MainPID"] == PID.to_string(), "266 parent replaced");
        epoch228::mapped_command(&m, &spec)?;
        let status = fs::read_to_string("/proc/2791171/status")?;
        let mask = status
            .lines()
            .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
            .context("266 affinity")?;
        ensure!(
            funding::cpus(mask)? == funding::cpus("32-39")?,
            "266 CPU envelope changed"
        );
        None
    } else {
        Some(terminal(n, &m, &prof.root)?)
    };
    for name in [&prof.unit, &prof.guard, &prof.timer] {
        let pin = prof.state.join(name);
        let svc = n.show(name)?;
        let path = Path::new(text(&svc, "FragmentPath")?);
        ensure!(
            path.canonicalize()? == pin && svc["DropInPaths"] == "",
            "unexpected 266 unit source"
        );
        let m = fs::metadata(pin)?;
        ensure!(
            m.uid() == 0 && m.mode() & 0o222 == 0,
            "266 unit source is writable"
        );
        if name == &prof.timer {
            ensure!(
                svc["ActiveState"] == "active"
                    && svc["InvocationID"] == h["timer"]
                    && svc["Unit"] == SERVICE,
                "266 timer changed"
            );
        }
        if name == &prof.guard {
            ensure!(
                svc["MemoryMax"] == GUARD_MEM.to_string()
                    && svc["MemorySwapMax"] == "0"
                    && svc["Result"] == "success",
                "266 protective guard"
            );
        }
    }
    let img = prof.state.join("private.ext4");
    ensure!(
        fs::metadata(&img)?.len() == 112 << 30
            && fs::metadata(&prof.root)?.dev() == num(&spec, "root_device")?
            && fs::read_to_string("/sys/block/loop3/loop/backing_file")?.trim()
                == img.to_str().context("266 image")?,
        "266 live loop"
    );
    let closed = if failure.is_some() {
        Some(readonly_loop(&prof.root, &img)?)
    } else {
        None
    };
    let additional_disk = if closed.is_some() {
        EXCLUSIVE_DISK - (112 << 30)
    } else {
        EXCLUSIVE_DISK
    };
    for qa in ["qa-disk", "qa-memory"] {
        let p = Profile::new(Lane::Epoch266, qa)?;
        ensure!(
            fs::metadata(p.state.join("private.ext4"))?.len() == 256 << 20
                && bound_at(&p.state.join("qualification.json"))?.sealed()?["drained"] == true,
            "266 retained QA"
        );
        live::verify_drained_group(&p.unit)?;
    }
    for name in ["pressure-stop.json", "stop-intent.json"] {
        absent(&prof.state.join("receipts").join(name))?;
    }
    live::verify_drained_group(CTRL)?;
    ensure!(
        command_field(n, UNIT, "InvocationID")? == IID
            && command_field(n, UNIT, "MainPID")? == text(&m, "MainPID")?,
        "266 changed during booking"
    );
    Ok(
        json!({"handoff":handoff(),"cold_discharge_for_266_only":proof,"held_fit":h["held_fit"],"unit":UNIT,"iid":IID,"main_pid":text(&m,"MainPID")?.parse::<u64>()?,"original_main_pid":PID,"terminal_failure":failure,"memory_max":CAP,"cpu_mask":"32-39","readonly_loop":closed,"additional_disk_above_shared_qa":additional_disk,"original_floor":num(&fit,"protected_floor")?-RECEIPTS,"memory_credit_for_228":0}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the original root-owned 266 conversion terminal receipt"]
    fn original_failed_266_has_its_own_pid1_exit_and_no_release() {
        let d = terminal_receipt().json().unwrap();
        original_failure(&d).unwrap();
        for (key, v) in [
            (
                "manager",
                json!({"Id": UNIT,"InvocationID":IID,"MainPID":"0","Result":"success"}),
            ),
            ("resource_release_authorized", json!(true)),
        ] {
            let mut wrong = d.clone();
            wrong[key] = v;
            assert!(original_failure(&wrong).is_err());
        }
        let mut ev = rows(&d, "pid1").unwrap().clone();
        ev.retain(|e| e["EXIT_CODE"] != "exited");
        assert!(terminal_events(&d, &ev).is_err());
    }
    #[test]
    #[ignore = "requires the retained read-only epoch 266 guest"]
    fn original_closed_image_preserves_evidence_and_rejects_substitution() {
        let profile = Profile::new(Lane::Epoch266, "pilot").unwrap();
        let image = profile.state.join("private.ext4");
        readonly_loop(&profile.root, &image).unwrap();
        assert!(readonly_loop(&profile.root, &profile.state.join("mount.json")).is_err());
        assert!(readonly_loop(&profile.root.join("output"), &image).is_err());
    }
    #[test]
    #[ignore = "requires original 266 held fit, timer receipt and private guard sample"]
    fn original_266_and_228_cannot_share_the_same_loop_allowance() {
        let (_, fit, _) = originals().unwrap();
        let free = num(&fit, "free").unwrap();
        let need = num(&fit["winner"], "required_free").unwrap();
        assert_eq!(free - need, 1_937_377_280);
        assert_eq!(need + EXCLUSIVE_DISK - free, 119_127_013_376);
    }
}
