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
    live::finite_owner(&m, UNIT, IID, CAP)?;
    ensure!(m["MainPID"] == PID.to_string(), "266 parent replaced");
    epoch228::mapped_command(&m, &spec)?;
    let prof = Profile::new(Lane::Epoch266, "pilot")?;
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
            && command_field(n, UNIT, "MainPID")? == PID.to_string(),
        "266 changed during booking"
    );
    Ok(
        json!({"handoff":handoff(),"cold_discharge_for_266_only":proof,"held_fit":h["held_fit"],"unit":UNIT,"iid":IID,"main_pid":PID,"memory_max":CAP,"cpu_mask":"32-39","additional_disk_above_shared_qa":EXCLUSIVE_DISK,"original_floor":num(&fit,"protected_floor")?-RECEIPTS,"memory_credit_for_228":0}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
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
