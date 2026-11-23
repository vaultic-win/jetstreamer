// Reopen the actual bootstrap startup graph for downstream resource consumers.
use super::*;
pub(super) fn limited_sample(p: &Value, gp: &Value, g: &Value) -> Result<()> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(
        page > 0 && (page as u64).is_power_of_two(),
        "kernel page size"
    );
    let page = page as u64;
    let m = &g["memory_observation"];
    let proc = &g["process_observation"];
    let one = proc["processes"]
        .as_array()
        .context("first-fire process census")?;
    ensure!(
        g.get("memory_observation_error") == Some(&Value::Null)
            && g.get("filesystem_observation_error") == Some(&Value::Null)
            && num(m, "maximum_bytes")? == MEMORY / page * page
            && num(m, "high_bytes")? == 100_000_000_000 / page * page
            && num(m, "current_bytes")? <= MEMORY
            && m["swap_bytes"] == 0
            && (1..=512).contains(&num(m, "tasks")?)
            && ["oom", "oom_kill", "oom_group_kill"]
                .iter()
                .all(|k| m["events"][*k] == 0)
            && proc["stable_census"] == true
            && proc["token_present"] == false
            && proc["boot_id"] == p["boot_id"]
            && one.len() == 1
            && one[0]["pid"] == gp["native_main"]["main_pid"]
            && one[0]["executable"] == HARNESS
            && one[0]["sha256"] == HARNESS_SHA
            && one[0]["parent_pid"] == 1
            && one[0]["start_ticks"] == gp["main_start_ticks"]
            && num(&one[0], "start_ticks")? > 0,
        "original first guard lacks a stable held harness and kernel resource proof"
    );
    Ok(())
}
fn verify(
    h: &Value,
    p: &Value,
    a: &Value,
    t: &Value,
    gp: &Value,
    g: &Value,
    j: &Value,
) -> Result<()> {
    no_authority(h)?;
    no_authority(a)?;
    no_authority(t)?;
    let iid = text(h, "invocation_id")?;
    let pid = num(h, "main_pid")?;
    let harness = json!(Bound::new(HARNESS, HARNESS_SHA));
    let (path, sha) = if EPOCH == 257 {
        crate::native257::saved_guard(h)?
    } else {
        (GUARD, GUARD_SHA)
    };
    let guard = json!(Bound::new(path, sha));
    let worker = json!(Bound::new(WORKER, WORKER_SHA));
    let packet = json!(Bound::new(PACKET, PACKET_SHA));
    ensure!(
        h["schema"] == HANDOFF_SCHEMA
            && h["epoch"] == EPOCH
            && h["unit"] == UNIT
            && h["native_input_qualified"] == false
            && h["harness"] == harness
            && h["worker"] == worker
            && h["input_packet"] == packet
            && p["schema"] == PLAN_SCHEMA
            && p["operation"] == "native-cold"
            && p["epoch"] == EPOCH
            && p["worker_root"] == ROOT
            && p["bootstrap_slot"] == SLOT
            && p["snapshot_sha256"] == SNAPSHOT_SHA
            && p["genesis_sha256"] == GENESIS_SHA
            && p["input_packet"] == packet
            && p["harness"] == harness
            && p["guard"] == guard
            && p["worker"] == worker
            && p["maximum_root_physical_bytes"] == SCRATCH
            && p["maximum_memory_bytes"] == MEMORY
            && a["schema"] == ADMISSION_SCHEMA
            && a["operation"] == "native-cold"
            && a["admitted"] == true
            && a["candidate_incremental_peak_bytes"] == RESERVATION
            && a["maximum_memory_bytes"] == MEMORY
            && a["harness"] == harness
            && a["guard"] == guard
            && a["worker"] == worker
            && a["input_packet"] == packet
            && a["boot_id"] == p["boot_id"]
            && p["minimum_free_bytes"] == a["protected_existing_floor_bytes"]
            && h["peer_window"] == p["peer_window"]
            && h["admission"] == p["admission"]
            && t["admission"] == p["admission"]
            && t["schema"] == TOKEN_SCHEMA
            && t["harness"] == harness
            && t["guard"] == guard
            && t["unit"] == UNIT
            && t["boot_id"] == p["boot_id"]
            && t["invocation_id"] == iid
            && t["main_pid"] == pid
            && t["startup_plan_sha256"] == h["startup_plan"]["sha256"]
            && t["guard_plan"] == h["guard_plan"]
            && t["guard_sample"] == h["first_guard_sample"]
            && t["guard_pid1_journal"] == h["first_guard_pid1_journal"]
            && binding(&h["first_guard_token"])?.path
                == Path::new(TOKENS).join(iid).join("guard-admission.json"),
        "native startup graph mismatch"
    );
    let v = &h["producer"];
    ensure!(
        v["Id"] == UNIT
            && v["InvocationID"] == iid
            && text(v, "MainPID")?.parse::<u64>()? == pid
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["ControlGroup"] == format!("/system.slice/{UNIT}")
            && v["NRestarts"] == "0"
            && text(v, "MemoryMax")?.parse::<u64>()? == MEMORY
            && v["MemorySwapMax"] == "0"
            && v["TasksMax"] == "512"
            && periodic::stable_command(text(v, "ExecStart")?)?
                == format!("{{ path={HARNESS} ; argv[]={HARNESS} ; ignore_errors=no"),
        "historical producer tuple differs"
    );
    let hr = num(h, "recorded_monotonic_us")?;
    let wall = num(h, "recorded_unix_seconds")?;
    ensure!(
        hr >= num(t, "recorded_monotonic_us")?
            && hr < num(p, "expires_monotonic_us")?
            && wall >= num(a, "issued_unix_seconds")?
            && wall <= num(a, "expires_unix_seconds")?,
        "handoff outside original admission"
    );
    check_mount_sample(a, g)?;
    limited_sample(p, gp, g)?;
    first_guard::first_guard(p, t, gp, g, j, wall)
}
pub(super) fn reopen(h: &Value) -> Result<()> {
    let p = binding(&h["startup_plan"])?.sealed()?;
    let a = binding(&h["admission"])?.sealed()?;
    let t = binding(&h["first_guard_token"])?.sealed()?;
    let gp = binding(&h["guard_plan"])?.sealed()?;
    let g = binding(&h["first_guard_sample"])?.sealed()?;
    let j = binding(&h["first_guard_pid1_journal"])?.sealed()?;
    verify(h, &p, &a, &t, &gp, &g, &j)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn merge(target: &mut Value, extra: Value) {
        target
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
    }
    #[test]
    fn complete_positive_graph_binds_the_measured_harness_to_the_original_first_fire() {
        let (mut p, seed, mut gp, mut g, j) = first_guard::tests::fixture();
        gp["main_start_ticks"] = json!(123);
        merge(
            &mut g,
            json!({"memory_observation_error":null,"filesystem_observation_error":null,
            "memory_observation":{"maximum_bytes":MEMORY/4096*4096,"high_bytes":100_000_000_000u64/4096*4096,"current_bytes":1000,
                "swap_bytes":0,"tasks":1,"events":{"oom":0,"oom_kill":0,"oom_group_kill":0}},
            "process_observation":{"stable_census":true,"token_present":false,"boot_id":p["boot_id"],
                "processes":[{"pid":42,"executable":HARNESS,"sha256":HARNESS_SHA,"parent_pid":1,"start_ticks":123}]}}),
        );
        let hreg = json!(Bound::new(HARNESS, HARNESS_SHA));
        let greg = json!(Bound::new(GUARD, GUARD_SHA));
        let w = json!(Bound::new(WORKER, WORKER_SHA));
        let i = json!(Bound::new(PACKET, PACKET_SHA));
        let b = |name: &str| {
            json!(Bound::new(
                format!("/var/lib/jetstreamer/fixture/{name}"),
                "c".repeat(64)
            ))
        };
        let ar = b("admission");
        let pr = b("plan");
        let peer = b("peer");
        let sr = b("sample");
        let jr = b("journal");
        merge(
            &mut p,
            json!({"schema":PLAN_SCHEMA,"operation":"native-cold","epoch":EPOCH,"worker_root":ROOT,
      "bootstrap_slot":SLOT,"snapshot_sha256":SNAPSHOT_SHA,"genesis_sha256":GENESIS_SHA,"input_packet":i,"harness":hreg,"guard":greg,
      "worker":w,"maximum_root_physical_bytes":SCRATCH,"maximum_memory_bytes":MEMORY,"admission":ar,"peer_window":peer}),
        );
        let mut a = json!({"schema":ADMISSION_SCHEMA,"operation":"native-cold","admitted":true,
        "candidate_incremental_peak_bytes":RESERVATION,"maximum_memory_bytes":MEMORY,"harness":hreg,"guard":greg,"worker":w,"input_packet":i,
        "boot_id":p["boot_id"],"protected_existing_floor_bytes":p["minimum_free_bytes"],"issued_unix_seconds":60,"expires_unix_seconds":120});
        let t = startup::cold_input_token(
            &p,
            text(&pr, "sha256").unwrap(),
            &gp,
            text(&seed, "guard_invocation_id").unwrap(),
            startup::FirstGuardProof {
                plan: binding(&seed["guard_plan"]).unwrap(),
                sample: binding(&sr).unwrap(),
                journal: binding(&jr).unwrap(),
            },
            num(&seed, "recorded_monotonic_us").unwrap(),
        );
        let token = binding(&b("guard-admission")).unwrap();
        let iid = text(&t, "invocation_id").unwrap();
        let mut h = json!({"schema":HANDOFF_SCHEMA,"epoch":EPOCH,"unit":UNIT,"native_input_qualified":false,"harness":hreg,
        "worker":w,"input_packet":i,"peer_window":peer,"admission":ar,"startup_plan":pr,"guard_plan":t["guard_plan"],
        "first_guard_sample":sr,"first_guard_pid1_journal":jr,"first_guard_token":Bound::new(Path::new(TOKENS).join(iid).join("guard-admission.json"),token.sha256),
        "invocation_id":iid,"main_pid":42,"recorded_monotonic_us":3001,"recorded_unix_seconds":100,
        "producer":{"Id":UNIT,"InvocationID":iid,"MainPID":"42","ActiveState":"active","SubState":"running","ControlGroup":format!("/system.slice/{UNIT}"),
        "NRestarts":"0","MemoryMax":MEMORY.to_string(),"MemorySwapMax":"0","TasksMax":"512",
        "ExecStart":format!("{{ path={HARNESS} ; argv[]={HARNESS} ; ignore_errors=no ; start_time=[x] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }}")}});
        for x in [&mut h, &mut a] {
            deny_authority(x);
        }
        sample_fixture(&mut a, &mut g);
        if EPOCH == 257 {
            h["guard"] = greg.clone();
            let mut mixed = h.clone();
            mixed.as_object_mut().unwrap().remove("guard");
            assert!(verify(&mixed, &p, &a, &t, &gp, &g, &j).is_err());
            mixed["guard"] = json!({"path": GUARD, "sha256": "f".repeat(64)});
            assert!(verify(&mixed, &p, &a, &t, &gp, &g, &j).is_err());
        }
        verify(&h, &p, &a, &t, &gp, &g, &j).unwrap();
        let mut promoted = t.clone();
        promoted["replay_launch_authorized"] = json!(true);
        assert!(verify(&h, &p, &a, &promoted, &gp, &g, &j).is_err());
        for key in [
            "first_guard_token",
            "first_guard_sample",
            "admission",
            "worker",
            "recorded_monotonic_us",
            "producer",
            "native_input_qualified",
        ] {
            let mut bad = h.clone();
            bad[key] = Value::Null;
            assert!(verify(&bad, &p, &a, &t, &gp, &g, &j).is_err(), "{key}");
        }
        let mut shifted = a.clone();
        shifted["candidate_incremental_peak_bytes"] = json!(SCRATCH);
        assert!(verify(&h, &p, &shifted, &t, &gp, &g, &j).is_err());
    }
}
