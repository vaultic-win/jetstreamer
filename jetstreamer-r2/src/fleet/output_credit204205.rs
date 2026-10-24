//! Explicit sampled-output profile; never used by the legacy admission route.
//! Metadata only: no archive data reads and no new routine observer/poll loop.
use super::*;
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::Component,
};
pub(super) const PROFILE: &str = "sampled-output-204205-v1";
const SCHEMA: &str = "jetstreamer-exact-prefix-output-file-v1";
const CAP: u64 = 128 << 30;
#[derive(Clone, Copy)]
struct Owner {
    epoch: u64,
    unit: &'static str,
    iid: &'static str,
    pid: u64,
    start: u64,
    root: &'static str,
    output: &'static str,
}
const OWNERS: [Owner; 2] = [
    Owner {
        epoch: 204,
        unit: "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        iid: "448da7f2a3a34217afe7e115120b3cea",
        pid: 3822861,
        start: 170369985,
        root: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1",
        output: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1/output/epoch-204-prefix.jet",
    },
    Owner {
        epoch: 205,
        unit: "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        iid: "373359a11aef4993a1a949e19ff617c3",
        pid: 3730044,
        start: 169848742,
        root: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1",
        output: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1/output/epoch-205-prefix.jet",
    },
];
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    logical_bytes: u64,
    allocated_bytes: u64,
}
impl Metadata {
    fn capture(m: &fs::Metadata) -> Result<Self> {
        let result = Self {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            mode: m.mode(),
            nlink: m.nlink(),
            logical_bytes: m.len(),
            allocated_bytes: m
                .blocks()
                .checked_mul(512)
                .context("sampled output allocation overflow")?,
        };
        result.valid()?;
        Ok(result)
    }
    fn valid(&self) -> Result<()> {
        ensure!(
            self.inode > 0
                && self.uid == 1000
                && self.mode == libc::S_IFREG | 0o600
                && self.nlink == 1
                && self.allocated_bytes % 512 == 0
                && self.allocated_bytes <= CAP,
            "sampled output metadata identity, ownership or cap differs"
        );
        Ok(())
    }
    fn same_file(&self, other: &Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.uid == other.uid
            && self.mode == other.mode
            && self.nlink == other.nlink
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observed {
    schema: String,
    epoch: u64,
    producer_unit: String,
    producer_invocation_id: String,
    producer_main_pid: u64,
    producer_start_ticks: u64,
    path: PathBuf,
    pass_1: Metadata,
    pass_2: Metadata,
    identity_stable: bool,
    append_only_growth: bool,
    invocation_binding_stable: bool,
    conservative_observed_physical_bytes: u64,
}
fn pair(first: &Metadata, second: &Metadata) -> Result<u64> {
    first.valid()?;
    second.valid()?;
    ensure!(
        first.same_file(second)
            && second.logical_bytes >= first.logical_bytes
            && second.allocated_bytes >= first.allocated_bytes,
        "sampled output was replaced, truncated or reclaimed within its metadata bracket"
    );
    Ok(first.allocated_bytes.min(second.allocated_bytes))
}
fn sample_owner(owner: Owner, p: &Value) -> Result<()> {
    ensure!(
        p["unit"] == owner.unit
            && p["invocation_id"] == owner.iid
            && p["main_pid"] == owner.pid
            && p["restarts"] == 0
            && p["active_state"] == "active"
            && p["sub_state"] == "running"
            && p["load_state"] == "loaded"
            && p["result"] == "success"
            && p["control_group"] == format!("/system.slice/{}", owner.unit)
            && p["rss"]["census_stable"] == true,
        "sampled output producer identity differs"
    );
    let processes = p["rss"]["processes"]
        .as_array()
        .context("sampled output process start census missing")?;
    let matching = processes
        .iter()
        .filter(|p| p["pid"] == owner.pid)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1 && matching[0]["start_ticks"] == owner.start,
        "sampled output producer PID was reused or start binding is absent"
    );
    Ok(())
}
fn observed(owner: Owner, row: &Value, sample: u64, now: u64) -> Result<Observed> {
    ensure!(
        sample <= now && now - sample <= 1800,
        "sampled output receipt is stale or from the future"
    );
    ensure!(
        row["scratch_path"] == format!("{}/scratch", owner.root)
            && row["invocation_binding_stable"] == true,
        "sampled output overlaps or substitutes the scratch scope"
    );
    for key in [
        "producer_before",
        "producer_after",
        "controller_before",
        "controller_after",
    ] {
        sample_owner(owner, &row[key])?;
    }
    let raw = row.get("output_file").context(
        "new output-credit profile requires actual output metadata; no zero or live-stat fallback",
    )?;
    let output: Observed = serde_json::from_value(raw.clone())?;
    ensure!(
        output.schema == SCHEMA
            && output.epoch == owner.epoch
            && output.producer_unit == owner.unit
            && output.producer_invocation_id == owner.iid
            && output.producer_main_pid == owner.pid
            && output.producer_start_ticks == owner.start
            && output.path == Path::new(owner.output)
            && output.identity_stable
            && output.append_only_growth
            && output.invocation_binding_stable,
        "sampled output closed profile or declared bindings differ"
    );
    let physical = pair(&output.pass_1, &output.pass_2)?;
    ensure!(
        physical == output.conservative_observed_physical_bytes,
        "sampled output declared physical minimum differs"
    );
    Ok(output)
}
// O_PATH on all components: no content-readable archive descriptor is opened.
fn handle(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute(),
        "sampled output reference is not absolute"
    );
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/")?;
    let mut parts = path.components().peekable();
    ensure!(
        parts.next() == Some(Component::RootDir),
        "sampled output path lacks root"
    );
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            anyhow::bail!("sampled output path is aliased")
        };
        let name = CString::new(name.as_bytes())?;
        let directory = parts.peek().is_some();
        let flags = libc::O_PATH
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if directory { libc::O_DIRECTORY } else { 0 };
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        ensure!(
            fd >= 0,
            "sampled output reference cannot be opened without aliases"
        );
        let next = unsafe { File::from_raw_fd(fd) };
        if !directory {
            ensure!(
                next.metadata()?.is_file(),
                "sampled output reference is not regular"
            );
            return Ok(next);
        }
        current = next;
    }
    anyhow::bail!("sampled output reference has no leaf")
}
fn process_start(owner: Owner) -> Result<u64> {
    let text = fs::read_to_string(format!("/proc/{}/stat", owner.pid))?;
    ensure!(
        text.len() < 4096,
        "sampled output process stat exceeds bound"
    );
    let end = text
        .rfind(')')
        .context("sampled output process comm absent")?;
    let fields = text[end + 1..].split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() > 19 && matches!(fields[0], "R" | "S" | "D" | "I"),
        "sampled output producer is not live"
    );
    Ok(fields[19].parse()?)
}
fn current_owner(owner: Owner, expected: &Value) -> Result<Value> {
    let p = singleton227_capture::properties(
        owner.unit,
        "Id,LoadState,InvocationID,MainPID,NRestarts,ControlGroup,ActiveState,SubState,Result,ExecStart",
    )?;
    let result = serde_json::to_value(&p)?;
    for key in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ControlGroup",
        "ActiveState",
        "SubState",
        "Result",
    ] {
        ensure!(
            result[key] == expected[key],
            "current output producer changed:{key}"
        );
    }
    ensure!(
        diagnostic_stage_running(&result)
            && result["MainPID"] == owner.pid.to_string()
            && result["InvocationID"] == owner.iid
            && pipeline_status::same_exec_start(
                expected["ExecStart"]
                    .as_str()
                    .context("sampled output original command missing")?,
                result["ExecStart"]
                    .as_str()
                    .context("sampled output current command missing")?
            )
            && process_start(owner)? == owner.start,
        "current output producer command or PID start changed"
    );
    Ok(result)
}
fn current_reference(owner: Owner, expected: &Value) -> Result<(Metadata, Metadata)> {
    let before = current_owner(owner, expected)?;
    let first = handle(Path::new(owner.output))?;
    let a = Metadata::capture(&first.metadata()?)?;
    let second = handle(Path::new(owner.output))?;
    let b = Metadata::capture(&second.metadata()?)?;
    ensure!(
        a.device == fs::metadata("/")?.dev(),
        "output credit belongs to a different filesystem than the protected root claim"
    );
    pair(&a, &b)?;
    ensure!(
        before == current_owner(owner, expected)?,
        "current output producer changed during metadata bracket"
    );
    // Reopen the name after the producer bracket while both original inodes
    // remain pinned. Detect rename/replacement as well as truncation/reclaim.
    let final_handle = handle(Path::new(owner.output))?;
    let final_metadata = Metadata::capture(&final_handle.metadata()?)?;
    pair(&a, &Metadata::capture(&first.metadata()?)?)?;
    pair(&b, &Metadata::capture(&second.metadata()?)?)?;
    pair(&b, &final_metadata)?;
    Ok((a, final_metadata))
}
fn credit(
    output: &Observed,
    current_a: &Metadata,
    current_b: &Metadata,
    legacy: u64,
) -> Result<u64> {
    let current = pair(current_a, current_b)?;
    ensure!(
        legacy <= CAP
            && output.pass_1.same_file(current_a)
            && output.pass_2.same_file(current_b)
            && current_a.logical_bytes >= output.pass_2.logical_bytes,
        "current output is not the sampled file or was truncated since observation"
    );
    Ok(output
        .conservative_observed_physical_bytes
        .min(current)
        .min(legacy))
}
fn replace(
    growth: u64,
    row: &mut Value,
    owner: Owner,
    output: &Observed,
    a: &Metadata,
    b: &Metadata,
) -> Result<(u64, Value)> {
    ensure!(
        row.get("output_credit_profile").is_none(),
        "sampled output credit already consumed"
    );
    ensure!(
        row["epoch"] == owner.epoch
            && row["unit"] == owner.unit
            && row["invocation_id"] == owner.iid
            && row["output_growth_credit_taken"] == true,
        "new output profile cannot replace an absent or whole-root credit"
    );
    let legacy = row["current_output_allocated_bytes"]
        .as_u64()
        .context("legacy output credit missing; no default zero")?;
    let replacement = credit(output, a, b, legacy)?;
    let delta = legacy
        .checked_sub(replacement)
        .context("sampled output credit increased legacy allowance")?;
    let remaining = row["remaining_growth_bytes"]
        .as_u64()
        .context("legacy output growth missing")?
        .checked_add(delta)
        .context("sampled output remaining growth overflow")?;
    row["current_output_allocated_bytes"] = json!(replacement);
    row["remaining_growth_bytes"] = json!(remaining);
    row["output_credit_profile"] = json!(PROFILE);
    row["legacy_live_output_credit_replaced_bytes"] = json!(legacy);
    let evidence = json!({"epoch":owner.epoch,"unit":owner.unit,"invocation_id":owner.iid,"path":owner.output,"sampled_pass_1":output.pass_1,"sampled_pass_2":output.pass_2,"current_pass_1":a,"current_pass_2":b,"legacy_live_output_credit_bytes":legacy,"replacement_output_credit_bytes":replacement,"no_additional_output_credit_taken":true,"scratch_credit_unchanged":true});
    Ok((
        growth
            .checked_add(delta)
            .context("sampled output total growth overflow")?,
        evidence,
    ))
}
// Explicit gate: output evidence does not model a live park/restore/retirement.
pub(super) fn maintenance_idle(f: &Value) -> Result<()> {
    let units = f["unit_census"]
        .as_object()
        .context("new output profile requires complete unit census")?;
    let park = "horizon-foundation-prefix213-park348-v2.service";
    let recorded = units
        .get(park)
        .context("new output profile requires explicit park identity or terminal census entry")?;
    ensure!(
        recorded["Id"] == park
            && recorded["MainPID"] == "0"
            && recorded["NRestarts"] == "0"
            && recorded["ControlGroup"] == ""
            && (recorded["LoadState"] == "loaded" || recorded["LoadState"] == "not-found")
            && (recorded["ActiveState"] == "inactive" || recorded["ActiveState"] == "failed")
            && (recorded["SubState"] == "dead" || recorded["SubState"] == "failed"),
        "park213 or its maintenance owner is live, malformed or requires separately qualified auxiliary accounting"
    );
    for (name, u) in units {
        ensure!(
            !(name.starts_with("horizon-foundation-prefix213-")
                || name.starts_with("horizon-foundation-holding-"))
                || !diagnostic_stage_running(u),
            "unmodeled Foundation maintenance owner is live"
        );
    }
    Ok(())
}
pub(super) fn apply(
    f: &Value,
    o: &Value,
    sample: u64,
    now: u64,
    mut growth: u64,
    mut measurements: Vec<Value>,
) -> Result<(u64, Vec<Value>, Value)> {
    maintenance_idle(f)?;
    ensure!(
        utc_seconds(
            o["recorded_at_utc"]
                .as_str()
                .context("sampled output clock absent")?
        )? == sample,
        "sampled output receipt clock differs"
    );
    let active = f["active"]
        .as_array()
        .context("sampled output complete active census missing")?;
    let sampled = o["diagnostic_replays"]
        .as_array()
        .context("sampled output diagnostic census missing")?;
    let mut evidence = Vec::new();
    for owner in OWNERS {
        let matching = active
            .iter()
            .filter(|r| r["epoch"] == owner.epoch)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            ensure!(
                !measurements.iter().any(|r| r["epoch"] == owner.epoch),
                "output credit exists without an active owner"
            );
            continue;
        }
        ensure!(matching.len() == 1, "duplicate sampled output owner");
        let expected = singleton227_admission::active_owner(matching[0])?;
        ensure!(
            expected["Id"] == owner.unit
                && expected["InvocationID"] == owner.iid
                && expected["MainPID"] == owner.pid.to_string()
                && expected["NRestarts"] == "0",
            "output owner differs from closed producer profile"
        );
        let rows = sampled
            .iter()
            .filter(|r| r["producer_unit"] == owner.unit)
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1 && rows[0]["status"] == "observed" && rows[0]["error"].is_null(),
            "new output profile needs one actual coordinated observation per owner"
        );
        let output = observed(owner, &rows[0]["observation"], sample, now)?;
        let indices = measurements
            .iter()
            .enumerate()
            .filter(|(_, r)| r["epoch"] == owner.epoch && r["unit"] == owner.unit)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        ensure!(
            indices.len() == 1,
            "new output profile needs exactly one existing credit to replace"
        );
        ensure!(
            measurements[indices[0]]["sampled_scratch_physical_bytes"]
                == rows[0]["observation"]["conservative_observed_physical_bytes"],
            "sampled output cannot replace a differently scoped scratch measurement"
        );
        let (a, b) = current_reference(owner, expected)?;
        let (next, proof) = replace(
            growth,
            &mut measurements[indices[0]],
            owner,
            &output,
            &a,
            &b,
        )?;
        growth = next;
        evidence.push(proof);
    }
    Ok((
        growth,
        measurements,
        json!({"profile":PROFILE,"replacement_evidence":evidence,"no_fallback_to_legacy_or_logical_bytes":true,"park_maintenance_idle_required":true}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata(blocks: u64) -> Metadata {
        Metadata {
            device: 1,
            inode: 42,
            uid: 1000,
            mode: libc::S_IFREG | 0o600,
            nlink: 1,
            logical_bytes: 100000,
            allocated_bytes: blocks * 512,
        }
    }
    fn output(owner: Owner) -> Observed {
        Observed {
            schema: SCHEMA.into(),
            epoch: owner.epoch,
            producer_unit: owner.unit.into(),
            producer_invocation_id: owner.iid.into(),
            producer_main_pid: owner.pid,
            producer_start_ticks: owner.start,
            path: owner.output.into(),
            pass_1: metadata(90),
            pass_2: metadata(100),
            identity_stable: true,
            append_only_growth: true,
            invocation_binding_stable: true,
            conservative_observed_physical_bytes: 90 * 512,
        }
    }
    fn unit(owner: Owner) -> Value {
        json!({"unit":owner.unit,"invocation_id":owner.iid,"main_pid":owner.pid,"restarts":0,"active_state":"active","sub_state":"running","load_state":"loaded","result":"success","control_group":format!("/system.slice/{}",owner.unit),"rss":{"census_stable":true,"processes":[{"pid":owner.pid,"start_ticks":owner.start}]}})
    }
    fn row(owner: Owner) -> Value {
        let u = unit(owner);
        json!({"scratch_path":format!("{}/scratch",owner.root),"invocation_binding_stable":true,"producer_before":u,"producer_after":u,"controller_before":u,"controller_after":u,"output_file":output_json(owner)})
    }
    fn output_json(owner: Owner) -> Value {
        let p = output(owner);
        json!({"schema":p.schema,"epoch":p.epoch,"producer_unit":p.producer_unit,"producer_invocation_id":p.producer_invocation_id,"producer_main_pid":p.producer_main_pid,"producer_start_ticks":p.producer_start_ticks,"path":p.path,"pass_1":p.pass_1,"pass_2":p.pass_2,"identity_stable":true,"append_only_growth":true,"invocation_binding_stable":true,"conservative_observed_physical_bytes":p.conservative_observed_physical_bytes})
    }
    #[test]
    fn sampled_physical_credit_is_minimum_and_replaces_old_credit_once() {
        for owner in OWNERS {
            let p = output(owner);
            let mut measurement = json!({"epoch":owner.epoch,"unit":owner.unit,"invocation_id":owner.iid,"output_growth_credit_taken":true,"current_output_allocated_bytes":100*512,"remaining_growth_bytes":1000});
            let (g, proof) = replace(
                2000,
                &mut measurement,
                owner,
                &p,
                &metadata(85),
                &metadata(87),
            )
            .unwrap();
            assert_eq!(g, 2000 + 15 * 512);
            assert_eq!(measurement["remaining_growth_bytes"], 1000 + 15 * 512);
            assert_eq!(measurement["current_output_allocated_bytes"], 85 * 512);
            assert_eq!(proof["scratch_credit_unchanged"], true);
            assert!(replace(g, &mut measurement, owner, &p, &metadata(85), &metadata(87)).is_err());
            let mut whole = measurement.clone();
            whole["output_growth_credit_taken"] = json!(false);
            assert!(replace(g, &mut whole, owner, &p, &metadata(85), &metadata(87)).is_err());
        }
    }
    #[test]
    fn missing_logical_only_foreign_or_stale_metadata_never_defaults_to_zero() {
        let owner = OWNERS[0];
        let r = row(owner);
        observed(owner, &r, 100, 101).unwrap();
        let mut missing = r.clone();
        missing.as_object_mut().unwrap().remove("output_file");
        assert!(observed(owner, &missing, 100, 101).is_err());
        for path in [
            "/output_file/pass_1/allocated_bytes",
            "/output_file/producer_start_ticks",
        ] {
            let mut bad = r.clone();
            let (parent, key) = path.rsplit_once('/').unwrap();
            bad.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(observed(owner, &bad, 100, 101).is_err());
        }
        assert!(observed(owner, &r, 100, 1901).is_err());
        for (path, value) in [
            (
                "/output_file/path",
                json!(format!("{}/scratch/epoch-204-prefix.jet", owner.root)),
            ),
            ("/output_file/producer_invocation_id", json!("foreign")),
            ("/output_file/pass_2/inode", json!(43)),
            (
                "/output_file/conservative_observed_physical_bytes",
                json!(999999),
            ),
            (
                "/producer_after/rss/processes/0/start_ticks",
                json!(owner.start + 1),
            ),
        ] {
            let mut bad = r.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(observed(owner, &bad, 100, 101).is_err(), "{path}");
        }
    }
    #[test]
    fn current_replacement_truncation_reclaim_and_invalid_metadata_fail_closed() {
        let p = output(OWNERS[0]);
        let mut wrong = metadata(85);
        wrong.inode = 43;
        assert!(credit(&p, &wrong, &wrong, 100 * 512).is_err());
        let mut short = metadata(85);
        short.logical_bytes = 99999;
        assert!(credit(&p, &short, &short, 100 * 512).is_err());
        assert!(pair(&metadata(90), &metadata(89)).is_err());
        for field in ["mode", "uid", "nlink", "allocated"] {
            let mut m = metadata(1);
            match field {
                "mode" => m.mode = libc::S_IFREG | 0o644,
                "uid" => m.uid = 0,
                "nlink" => m.nlink = 2,
                _ => m.allocated_bytes = CAP + 512,
            }
            assert!(m.valid().is_err());
        }
    }
    #[test]
    fn measured_zero_is_valid_but_omitted_or_double_credit_is_not() {
        let mut p = output(OWNERS[0]);
        p.pass_1 = metadata(0);
        p.pass_2 = metadata(0);
        p.conservative_observed_physical_bytes = 0;
        assert_eq!(credit(&p, &metadata(0), &metadata(0), 0).unwrap(), 0);
        let mut row = json!({"epoch":204,"unit":OWNERS[0].unit,"invocation_id":OWNERS[0].iid,"output_growth_credit_taken":true,"remaining_growth_bytes":100});
        assert!(replace(100, &mut row, OWNERS[0], &p, &metadata(0), &metadata(0)).is_err());
    }
    #[test]
    fn current_metadata_handles_are_path_only_and_reject_parent_and_leaf_aliases() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("fixture");
        fs::write(&path, b"test-owned fixture").unwrap();
        let fd = handle(&path).unwrap();
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0 && flags & libc::O_PATH != 0);
        let leaf = temp.path().join("leaf-alias");
        symlink(&path, &leaf).unwrap();
        assert!(handle(&leaf).is_err());
        let parent = temp.path().join("parent-alias");
        symlink(&directory, &parent).unwrap();
        assert!(handle(&parent.join("fixture")).is_err());
    }
    #[test]
    fn live_or_missing_park_is_a_gate_not_an_unaccounted_auxiliary() {
        let unit = "horizon-foundation-prefix213-park348-v2.service";
        assert!(maintenance_idle(&json!({"unit_census":{}})).is_err());
        let mut f = json!({"unit_census":{unit:{"ActiveState":"activating","SubState":"start"}}});
        assert!(maintenance_idle(&f).is_err());
        f["unit_census"][unit]["ActiveState"] = json!("inactive");
        f["unit_census"][unit]["SubState"] = json!("dead");
        f["unit_census"][unit]["Id"] = json!(unit);
        f["unit_census"][unit]["MainPID"] = json!("0");
        f["unit_census"][unit]["NRestarts"] = json!("0");
        f["unit_census"][unit]["ControlGroup"] = json!("");
        f["unit_census"][unit]["LoadState"] = json!("not-found");
        maintenance_idle(&f).unwrap();
        f["unit_census"]["horizon-foundation-prefix213-restore-v1.service"] =
            json!({"ActiveState":"active","SubState":"running"});
        assert!(maintenance_idle(&f).is_err());
    }
}
