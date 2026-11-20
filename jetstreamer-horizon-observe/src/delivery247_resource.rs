//! Exact live delivery owner, measured inside the coordinated observer cadence.
//! Reuses native process-image checks and ordinary unit/cgroup/RSS sampling.
use super::*;
use jetstreamer_horizon_observe::staged247_rss as staged;
use serde_json::json;
const UNIT: &str = "horizon-upload-247-singleton-20261119-v1.service";
const IID: &str = "69218e2e0924497ea595a1227a6c31db";
const PID: u32 = 1439838;
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon-full265-fast-consumers-20261119-v1/jetstreamer-r2";
const IMAGE_SHA: &str = "4f70b21bd930a6e2890088eb236858ca1952a2dfa4c6404bfb9d9e68d07ba0ba";
#[derive(Clone, Copy)]
struct Owner {
    unit: &'static str,
    iid: &'static str,
    pid: u32,
    image: &'static str,
    sha: &'static str,
    cap: u64,
}
const ORIGINAL: Owner = Owner {
    unit: UNIT,
    iid: IID,
    pid: PID,
    image: IMAGE,
    sha: IMAGE_SHA,
    cap: 7_000_000_000,
};
const STAGED: Owner = Owner {
    unit: staged::UNIT,
    iid: staged::IID,
    pid: staged::PID,
    image: staged::IMAGE,
    sha: staged::IMAGE_SHA,
    cap: staged::CAP,
};

fn staged_inputs() -> Result<Value> {
    let mut proof = json!({});
    let mut docs = json!({});
    for (name, (path, digest)) in [
        ("booking", staged::BOOKING),
        ("launch", staged::LAUNCH),
        ("claim", staged::CLAIM),
        ("plan", staged::PLAN),
    ] {
        let path = Path::new(path);
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
            "staged 247 provenance custody"
        );
        let bytes = read_bounded(path, 1 << 20, "staged 247 provenance")?;
        ensure!(
            sha256(&bytes) == digest,
            "staged 247 provenance digest differs"
        );
        docs[name] = serde_json::from_slice(&bytes)?;
        proof[name] = json!({"path":path,"sha256":digest});
    }
    let b = &docs["booking"];
    let l = &docs["launch"];
    let c = &docs["claim"];
    ensure!(
        l["booking"] == proof["booking"]
            && b["approved_plan"] == proof["plan"]
            && b["unit"] == staged::UNIT
            && c["unit"] == staged::UNIT
            && c["invocation_id"] == staged::IID
            && c["expected_exec_start"] == l["unit"]["ExecStart"]
            && l["unit"]["MainPID"] == staged::PID.to_string(),
        "staged 247 resource provenance graph"
    );
    let cmd = fs::read(format!("/proc/{}/cmdline", staged::PID))?;
    let args: Vec<_> = cmd
        .strip_suffix(&[0])
        .context("staged 247 argv terminator")?
        .split(|b| *b == 0)
        .map(std::str::from_utf8)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(json!(args) == b["argv"], "staged 247 argv differs");
    let manager = Command::new("/usr/bin/systemctl")
        .args(["show", staged::UNIT, "--property=ExecStart", "--value"])
        .output()?;
    ensure!(
        manager.status.success()
            && c["expected_exec_start"] == std::str::from_utf8(&manager.stdout)?.trim(),
        "staged 247 manager execution differs"
    );
    Ok(proof)
}
pub(super) fn validate(c: &Config) -> Result<()> {
    ensure!(
        !(c.delivery247_resource_only && c.staged247_resource_only),
        "choose one 247 delivery observation"
    );
    let owner = if c.staged247_resource_only {
        STAGED
    } else {
        ORIGINAL
    };
    if !c.delivery247_resource_only && !c.staged247_resource_only {
        return Ok(());
    }
    for r in c.replays.iter().chain(&c.diagnostic_replays) {
        ensure!(
            r.producer_unit != owner.unit
                && r.controller_unit != owner.unit
                && r.expected_producer_invocation_id != owner.iid
                && r.expected_controller_invocation_id != owner.iid,
            "delivery247 cannot alias replay telemetry"
        );
    }
    ensure!(
        c.epoch203_ram_auxiliary.is_none(),
        "delivery247 is not an auxiliary replay"
    );
    Ok(())
}
fn main_ticks(rss: &Value, pid: u32) -> Result<u64> {
    ensure!(
        rss["census_stable"] == true && rss["error"].is_null(),
        "delivery247 RSS unavailable"
    );
    let rows: Vec<_> = rss["processes"]
        .as_array()
        .context("delivery247 RSS processes")?
        .iter()
        .filter(|p| p["pid"] == pid)
        .collect();
    ensure!(
        rows.len() == 1,
        "delivery247 main missing/duplicated in RSS census"
    );
    rows[0]["start_ticks"]
        .as_u64()
        .context("delivery247 main start ticks")
}
fn process_starts(u: &UnitObservation) -> Result<BTreeMap<u64, u64>> {
    let rss = serde_json::to_value(&u.rss)?;
    let mut found = BTreeMap::new();
    for p in rss["processes"]
        .as_array()
        .context("delivery247 complete cgroup RSS census")?
    {
        let pid = p["pid"].as_u64().context("delivery child PID")?;
        let start = p["start_ticks"].as_u64().context("delivery child start")?;
        ensure!(
            found.insert(pid, start).is_none(),
            "duplicate delivery process"
        );
    }
    Ok(found)
}
fn endpoint(u: &UnitObservation, owner: Owner) -> Result<u64> {
    ensure!(
        u.unit == owner.unit
            && u.invocation_id == owner.iid
            && u.main_pid == u64::from(owner.pid)
            && u.load_state == "loaded"
            && u.active_state == "active"
            && u.sub_state == "running"
            && u.restarts == 0
            && u.control_group == Path::new(&format!("/system.slice/{}", owner.unit)),
        "delivery247 resource owner changed"
    );
    let raw = serde_json::to_value(u)?;
    // Kernel hard cap is page-aligned; retain actual measured gauges and full RSS.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(page > 0, "delivery247 page size");
    let cap = owner.cap / (page as u64) * (page as u64);
    ensure!(
        raw["cgroup"]["gauges"]["memory.max"] == cap
            && raw["cgroup"]["gauges"]["memory.swap.max"] == 0,
        "delivery247 original kernel cap changed"
    );
    main_ticks(&raw["rss"], owner.pid)
}
fn observe(clock: u64, owner: Owner) -> Result<Value> {
    let provenance = if owner.iid == staged::IID {
        Some(staged_inputs()?)
    } else {
        None
    };
    let before = observe_unit(owner.unit, owner.iid)?;
    let first_ticks = endpoint(&before, owner)?;
    let image_before = native_input_diagnostic::mapped_image_at(
        Path::new(owner.image),
        owner.sha,
        owner.pid,
        Path::new("/proc"),
        0,
    )?;
    let after = observe_unit(owner.unit, owner.iid)?;
    let last_ticks = endpoint(&after, owner)?;
    let image_after = native_input_diagnostic::mapped_image_at(
        Path::new(owner.image),
        owner.sha,
        owner.pid,
        Path::new("/proc"),
        0,
    )?;
    ensure!(
        stable_unit(&before, &after)
            && first_ticks == last_ticks
            && process_starts(&before)? == process_starts(&after)?
            && image_before["mapped_inode"] == image_after["mapped_inode"]
            && image_before["mapped_device"] == image_after["mapped_device"],
        "delivery247 identity changed during same-cadence sample"
    );
    let mut sample = json!({"range":"247-247","sampled_unix_seconds":clock,"resource_only":true,
        "delivery_resource_only":true,"phase":"upload-readback",
        "controller_before":before,"producer_before":before,"controller_after":after,"producer_after":after,
        "mapped_image_before":image_before,"mapped_image_after":image_after,
        "invocation_binding_stable":true,"useful_work":{"sufficient_for_rates":false,"entry_progress_observed":false},
        "entry_replay":false,"ordinary_replay_claim":false,"terminal_completion_proven":false,
        "resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false});
    if let Some(proof) = provenance {
        ensure!(proof == staged_inputs()?, "staged 247 evidence changed");
        sample["staged_owner"] = proof;
        staged::validate(&sample)?;
    }
    Ok(sample)
}
fn row(result: Result<Value>, owner: Owner) -> Value {
    let (status, observation, error) = match result {
        Ok(v) => ("observed", Some(v), None),
        Err(e) => ("unavailable", None, Some(format!("{e:#}"))),
    };
    json!({"range":"247-247","producer_unit":owner.unit,"expected_producer_invocation_id":owner.iid,
        "delivery_resource_only":true,"status":status,"observation":observation,"error":error,
        "entry_replay":false,"ordinary_replay_claim":false,"terminal_completion_proven":false,
        "resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false})
}
pub(super) fn sample(enabled: bool, staged: bool, clock: u64) -> Vec<Value> {
    if enabled || staged {
        let owner = if staged { STAGED } else { ORIGINAL };
        vec![row(observe(clock, owner), owner)]
    } else {
        Vec::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "reads only the exact live staged uploader; no global observation or state change"]
    fn native_staged_owner_kernel_rss() {
        let row = row(observe(now_unix().unwrap(), STAGED), STAGED);
        assert_eq!(row["status"], "observed", "{row}");
        println!("STAGED247_RSS={row}");
    }
    #[test]
    fn unavailable_staged_owner_never_substitutes_original_or_zero() {
        let data = row(Err(anyhow!("changed")), STAGED);
        assert_eq!(data["producer_unit"], staged::UNIT);
        assert_eq!(data["expected_producer_invocation_id"], staged::IID);
        assert_eq!(data["status"], "unavailable");
        assert!(data["observation"].is_null());
    }
    #[test]
    fn missing_delivery_is_unavailable_not_zero_rss_or_replay() {
        let v = row(Err(anyhow!("original uploader finished")), ORIGINAL);
        assert_eq!(v["status"], "unavailable");
        assert!(v["observation"].is_null());
        for k in [
            "entry_replay",
            "ordinary_replay_claim",
            "terminal_completion_proven",
            "resource_release_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            assert_eq!(v[k], false);
        }
    }
    #[test]
    fn actual_pid_required_once_in_stable_rss_census() {
        let good =
            json!({"census_stable":true,"error":null,"processes":[{"pid":PID,"start_ticks":123}]});
        assert_eq!(main_ticks(&good, PID).unwrap(), 123);
        for value in [
            json!({"census_stable":false,"error":null,"processes":[{"pid":PID,"start_ticks":123}]}),
            json!({"census_stable":true,"error":null,"processes":[]}),
            json!({"census_stable":true,"error":null,"processes":[{"pid":42,"start_ticks":123}]}),
            json!({"census_stable":true,"error":null,"processes":[{"pid":PID,"start_ticks":123},{"pid":PID,"start_ticks":123}]}),
        ] {
            assert!(main_ticks(&value, PID).is_err());
        }
    }
}
