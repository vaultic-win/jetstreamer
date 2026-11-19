//! Two exact completed cold-input owners. Their full bookings remain charged.
//! Native265 pins are registered only after the qualified capture has succeeded.
use super::*;
#[derive(Clone, Copy)]
struct Peer {
    epoch: u64,
    unit: &'static str,
    iid: &'static str,
    pid: u64,
    memory: u64,
    growth: u64,
    origin_path: &'static str,
    origin_sha: &'static str,
    proof_path: &'static str,
    proof_sha: &'static str,
}
const PEERS: [Peer; 2] = [
    Peer {
        epoch: 211,
        unit: "archive-211-v1616-native-input-actual-v1.service",
        iid: "9267f2c2c64949c29b9da7c27a46df94",
        pid: 1264515,
        memory: 137_438_953_472,
        growth: 300_000_000_000,
        origin_path: "/var/lib/jetstreamer/horizon-native211-running-1828-v1/intent.json",
        origin_sha: "e68ce7b372c50c12210be7562cd8c8f18feb03078f6756190f1d7935f279282a",
        proof_path: "/var/lib/jetstreamer/horizon-native211-terminal-proof-1836-v1/proof.json",
        proof_sha: "97b3ae139f81af08fed1f0e94ccd9606b838d742fb679939969dd79e0ae357e5",
    },
    Peer {
        epoch: 265,
        unit: "horizon-265-native-input-20261119-v1.service",
        iid: "ce5f66a82fdd4c0e93ca99f27b925112",
        pid: 1307638,
        memory: 128_000_000_000,
        growth: 506_191_984_640,
        origin_path: "/var/lib/jetstreamer/horizon-native265-execution-native-20261119-v1/guarded-startup-handoff.json",
        origin_sha: "896c9678b442fb31f0eb679d457c425423f24e0afd3fbc1ea3432fb318e8a208",
        proof_path: "/var/lib/jetstreamer/horizon-native265-terminal-proof-2048-20261119-v1/proof.json",
        proof_sha: "62d7d71ee1a9c7215c4fffa7d5fec49ef449bb6be24de3e450432217a3efa519",
    },
];
impl Peer {
    fn origin(self) -> Bound {
        Bound::new(self.origin_path, self.origin_sha)
    }
    fn proof(self) -> Bound {
        Bound::new(self.proof_path, self.proof_sha)
    }
    fn selected(self, e: &Value) -> bool {
        e["phase"] == "private-cold-snapshot-verification"
            && e["epoch"] == self.epoch
            && e["unit"]["Id"] == self.unit
    }
}
pub(super) fn selected(e: &Value) -> bool {
    // Direct native265 recovery deliberately never invents a pipeline claim.
    PEERS[0].selected(e)
}
pub(super) fn terminal_diagnostic(d: &Value) -> Result<bool> {
    let p = PEERS[1];
    if d["range"] != "265-265" && d["producer_unit"] != p.unit {
        return Ok(false);
    }
    // The independently accepted terminal proof and retained booking are checked
    // by validate before finalization census. An unavailable resource diagnostic
    // for that exact completed owner is not a finalizing or executing producer.
    ensure!(
        d["range"] == "265-265"
            && d["producer_unit"] == p.unit
            && d["expected_producer_invocation_id"] == p.iid
            && d["scratch_path"]
                == "/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1"
            && d["status"] == "unavailable"
            && d["observation"].is_null()
            && d["error"] == "systemd control group is not absolute: prefix not found"
            && d["native_resource_only"] == true
            && d["entry_replay"] == false
            && d["ordinary_replay_claim"] == false
            && d["publication_authorized"] == false
            && d["r2_mutations"] == false,
        "retained native265 diagnostic changed"
    );
    Ok(true)
}
fn proof(p: Peer) -> Result<Value> {
    let v = p.proof().sealed()?;
    ensure!(
        v["schema"]
            == format!(
                "jetstreamer-private-epoch{}-native-terminal-proof-v1",
                p.epoch
            )
            && v["epoch"] == p.epoch
            && v["unit"] == p.unit
            && v["invocation_id"] == p.iid
            && v["main_pid"] == p.pid
            && v["native_input_qualified"] == true,
        "retained native terminal identity"
    );
    no_authority(&v)?;
    ensure!(
        text(&v, "boot_id")? == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "retained native terminal boot changed"
    );
    let origin = p.origin().sealed()?;
    ensure!(
        origin["unit"] == p.unit && origin["invocation_id"] == p.iid && origin["main_pid"] == p.pid,
        "retained native original identity"
    );
    if p.epoch == 211 {
        ensure!(
            v["running_origin"] == json!(p.origin())
                && origin["epoch"] == 211
                && origin["boot_id"] == v["boot_id"],
            "native211 running origin differs"
        );
    } else {
        ensure!(
            origin["schema"] == "horizon-native265-guarded-startup-v1"
                && v.get("running_origin").is_none()
                && v["startup_handoff"] == json!(p.origin())
                && v["original_launch_clock_preserved"] == true,
            "native265 direct terminal original startup differs"
        );
        let admission = binding(&origin["admission"])?.sealed()?;
        ensure!(
            admission["boot_id"] == v["boot_id"],
            "native265 original boot differs"
        );
    }
    binding(&v["journal"])?.bytes(false)?;
    if p.epoch == 265 {
        // These are the exact complete-result/history inputs of the pinned Rust
        // capture, not a second success-only or user-constructed qualification.
        let spec = binding(&v["capture_spec"])?.sealed()?;
        ensure!(
            spec["schema"] == "jetstreamer-native265-terminal-capture-spec-v2"
                && spec.get("running_origin").is_none()
                && spec["startup_handoff"] == v["startup_handoff"]
                && spec["consumer_transition"] == v["consumer_transition"]
                && spec["journal"] == v["journal"]
                && spec["native_result"] == v["native_result"]
                && spec["guard_history"] == v["guard_history"]
                && spec["observer"] == v["observer"]
                && spec["fleet"] == v["fleet"]
                && spec["output"] == p.proof_path
                && v["resource_samples_taken"] == 0,
            "native265 accepted capture graph differs"
        );
        binding(&v["consumer_transition"])?.sealed()?;
        binding(&v["native_result"])?.sealed()?;
        binding(&v["guard_history"])?.sealed()?;
    }
    Ok(v)
}
fn entry(p: Peer, f: &Value, e: &Value, terminal: &Value) -> Result<()> {
    ensure!(
        p.selected(e)
            && e["expected_invocation_id"] == p.iid
            && e["evidence"] == json!([p.origin()])
            && e["private_qualification_only"] == true
            && e["ordinary_replay_claim"] == false
            && e["grants_launch_or_publication_authority"] == false
            && e["live"] == false
            && e["unit"] == f["unit_census"][p.unit]
            && e["sampled_at_utc"] == f["sampled_at_utc"],
        "native terminal fleet row differs"
    );
    terminal_census(p, &e["unit"], terminal)?;
    ensure!(
        !f["active"]
            .as_array()
            .context("fleet active")?
            .iter()
            .any(|a| p.selected(a)
                || a["unit"]["Id"] == p.unit
                || a["producer"]["Id"] == p.unit
                || a["controller"]["Id"] == p.unit),
        "terminal native marked active"
    );
    Ok(())
}
fn booking(p: Peer, r: &capacity::Reservation, floor: u64) -> Result<()> {
    ensure!(
        r.unit == p.unit
            && r.invocation_id == p.iid
            && r.release.is_none()
            && r.maximum_memory_bytes == p.memory
            && r.remaining_disk_growth_bytes >= p.growth
            && r.minimum_free_bytes >= floor,
        "retained native obligations reduced"
    );
    Ok(())
}
pub(super) fn validate(f: &Value, rows: &[capacity::Reservation]) -> Result<()> {
    let entries = f["pipelines"].as_array().context("pipelines")?;
    // Both tests actually ran before full265; omitting either is not capacity.
    for p in PEERS {
        let v = proof(p)?;
        if p.epoch == 211 {
            let found: Vec<_> = entries.iter().filter(|e| p.selected(e)).collect();
            ensure!(
                found.len() == 1,
                "missing/duplicate retained native211 owner"
            );
            entry(p, f, found[0], &v["terminal_manager"])?;
        } else {
            ensure!(
                !entries
                    .iter()
                    .any(|e| e["epoch"] == 265 || e["unit"]["Id"] == p.unit),
                "native265 direct recovery must not invent a running claim"
            );
            ensure!(
                !f["active"]
                    .as_array()
                    .context("active")?
                    .iter()
                    .any(|e| e["epoch"] == 265
                        || e["unit"]["Id"] == p.unit
                        || e["producer"]["Id"] == p.unit
                        || e["controller"]["Id"] == p.unit),
                "native265 direct terminal marked active"
            );
            terminal_census(p, &f["unit_census"][p.unit], &v["terminal_manager"])?;
        }
        let reservations: Vec<_> = rows.iter().filter(|r| r.unit == p.unit).collect();
        ensure!(reservations.len() == 1, "missing/duplicate native booking");
        let origin = p.origin().sealed()?;
        let admission = binding(&origin["admission"])?.json()?;
        booking(
            p,
            reservations[0],
            num(&admission, "protected_existing_floor_bytes")?,
        )?;
    }
    Ok(())
}
pub(super) fn is_retained(unit: &str) -> bool {
    PEERS.iter().any(|p| p.unit == unit)
}
fn terminal_census(p: Peer, v: &Value, terminal: &Value) -> Result<()> {
    live::same_owner(terminal, v)?;
    ensure!(
        v["Id"] == p.unit
            && v["InvocationID"] == p.iid
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0",
        "retained native census differs"
    );
    Ok(())
}
fn terminal_identity(p: Peer, v: &Value, terminal: &Value) -> Result<()> {
    ensure!(
        v["Id"] == p.unit
            && v["InvocationID"] == p.iid
            && v["LoadState"] == "loaded"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"] == ""
            && v["NRestarts"] == "0"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["Result"] == "success"
            && v["ExecMainCode"] == "1"
            && v["ExecMainStatus"] == "0"
            && v["Restart"] == "no"
            && v["KillMode"] == "control-group"
            && v["Delegate"] == "no"
            && v["TriggeredBy"] == ""
            && text(v, "MemoryMax")?.parse::<u64>()? == p.memory
            && v["MemorySwapMax"] == "0",
        "retained native terminal changed"
    );
    live::same_owner(terminal, v)?;
    for key in [
        "ControlPID",
        "Job",
        "Restart",
        "KillMode",
        "Delegate",
        "TriggeredBy",
        "ExecMainCode",
        "ExecMainStatus",
        "MemoryMax",
        "MemoryHigh",
        "MemorySwapMax",
        "TasksMax",
        "Type",
        "User",
        "Group",
    ] {
        ensure!(
            !terminal[key].is_null() && v[key] == terminal[key],
            "retained terminal changed {key}"
        );
    }
    Ok(())
}
pub(super) fn terminal_owner(unit: &str, v: &Value) -> Result<()> {
    let p = PEERS
        .iter()
        .copied()
        .find(|p| p.unit == unit)
        .context("unregistered native terminal")?;
    let terminal = proof(p)?;
    terminal_identity(p, v, &terminal["terminal_manager"])?;
    absent(Path::new(&format!("/proc/{}", p.pid)))?;
    if p.epoch == 265 {
        let result = binding(&terminal["native_result"])?.sealed()?;
        let pid = num(&result, "worker_pid")?;
        ensure!(pid == 1307832 && pid != p.pid, "native265 child PID");
        absent(Path::new(&format!("/proc/{pid}")))?;
    }
    let root = Path::new("/sys/fs/cgroup/system.slice").join(p.unit);
    match fs::symlink_metadata(&root) {
        Ok(_) => live::drained_tree(&root, &mut 1024)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let group = format!("0::/system.slice/{}", p.unit);
    for e in fs::read_dir("/proc")? {
        let e = e?;
        if !e
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
        {
            continue;
        }
        match fs::read_to_string(e.path().join("cgroup")) {
            Ok(s) => ensure!(
                !s.lines()
                    .any(|l| l == group || l.starts_with(&format!("{group}/"))),
                "retained native still owns a process"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
/// Input capability binds the same exact proof as the retained fleet owner.
pub(super) fn input265(reference: &Value) -> Result<()> {
    let p = PEERS[1];
    ensure!(
        *reference == json!(p.proof()),
        "native265 input proof substituted"
    );
    let terminal = proof(p)?;
    let result = binding(&terminal["native_result"])?.sealed()?;
    ensure!(
        result["schema"] == "horizon265-exact-worker-cold-input-result-v1"
            && result["epoch"] == 265
            && result["worker"]
                == json!({"path":WORKER,"sha256":"c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4"})
            && result["bootstrap_sha256"]
                == "04eb59e2dbbc2b0d4f1535741fa9d56794c32ad18e14c98df4fa76a5ae397641"
            && result["genesis_sha256"]
                == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"
            && result["bootstrap_slot"] == 114479281
            && result["accounts_hash"] == "Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW"
            && result["full_accounts_commitment_verified"] == true
            && result["worker_shutdown_acknowledged"] == true
            && result["worker_reaped"] == true
            && result["native_terminal_and_guard_history_acceptance_required"] == true
            && result["entry_replay"] == false,
        "native265 cold-input result differs"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_terminal_diagnostic_is_never_promoted_to_live_work() {
        let d: Value = serde_json::from_str(include_str!(
            "fixtures/retained-native265-diagnostic-20261119.json"
        ))
        .unwrap();
        assert!(terminal_diagnostic(&d).unwrap());
        for (key, value) in [
            ("expected_producer_invocation_id", json!("f".repeat(32))),
            ("status", json!("observed")),
            ("native_resource_only", json!(false)),
            ("ordinary_replay_claim", json!(true)),
            ("observation", json!({})),
        ] {
            let mut bad = d.clone();
            bad[key] = value;
            assert!(terminal_diagnostic(&bad).is_err(), "{key}");
        }
        assert!(
            !terminal_diagnostic(&json!({"range":"250-250","producer_unit":"another.service"}))
                .unwrap()
        );
    }
    #[test]
    fn actual_fleet_terminal_census_does_not_invent_manager_fields() {
        let rows: Vec<Value> = serde_json::from_str(include_str!(
            "fixtures/retained-native-census-20261119.json"
        ))
        .unwrap();
        for (p, row) in PEERS.iter().zip(rows) {
            assert_eq!(row["epoch"], p.epoch);
            assert!(row["census"].get("MemoryMax").is_none());
            terminal_census(*p, &row["census"], &row["terminal"]).unwrap();
            let mut bad = row["census"].clone();
            bad["InvocationID"] = json!("f".repeat(32));
            assert!(terminal_census(*p, &bad, &row["terminal"]).is_err());
            bad = row["census"].clone();
            bad["ExecMainStatus"] = json!("1");
            assert!(terminal_census(*p, &bad, &row["terminal"]).is_err());
        }
    }
    fn fixture(p: Peer) -> (Value, Value, Value, capacity::Reservation) {
        let unit = json!({"Id":p.unit,"InvocationID":p.iid,"LoadState":"loaded",
            "MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0",
            "ActiveState":"inactive","SubState":"dead","Result":"success",
            "ExecMainCode":"1","ExecMainStatus":"0","Restart":"no","KillMode":"control-group",
            "Delegate":"no","TriggeredBy":"","ControlGroup":"","MemoryMax":p.memory.to_string(),
            "MemoryHigh":"100000000000","MemorySwapMax":"0","TasksMax":"512","Type":"exec",
            "User":"ubuntu","Group":"ubuntu",
            "ExecStart":"{ path=/test ; argv[]=/test ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"});
        let e = json!({"epoch":p.epoch,"phase":"private-cold-snapshot-verification","unit":unit,
            "expected_invocation_id":p.iid,"evidence":[p.origin()],"private_qualification_only":true,
            "ordinary_replay_claim":false,"grants_launch_or_publication_authority":false,
            "live":false,"sampled_at_utc":"sample"});
        let mut f = json!({"pipelines":[e],"active":[],"sampled_at_utc":"sample","unit_census":{}});
        f["unit_census"][p.unit] = unit.clone();
        let r = capacity::Reservation {
            unit: p.unit.into(),
            invocation_id: p.iid.into(),
            maximum_memory_bytes: p.memory,
            remaining_disk_growth_bytes: p.growth,
            minimum_free_bytes: 900,
            source: p.origin(),
            release: None,
        };
        (unit, e, f, r)
    }
    #[test]
    fn exact_terminal_peers_preserve_owner_and_complete_bookings() {
        for p in PEERS {
            let (u, e, f, r) = fixture(p);
            assert_eq!(selected(&e), p.epoch == 211);
            entry(p, &f, &e, &u).unwrap();
            booking(p, &r, 900).unwrap();
            let mut active = f.clone();
            active["active"] = json!([e]);
            assert!(entry(p, &active, &e, &u).is_err());
            for key in [
                "live",
                "private_qualification_only",
                "ordinary_replay_claim",
                "grants_launch_or_publication_authority",
            ] {
                let mut changed = e.clone();
                changed[key] = json!(!e[key].as_bool().unwrap());
                assert!(entry(p, &f, &changed, &u).is_err(), "accepted {key}");
            }
            for key in [
                "InvocationID",
                "MemoryMax",
                "MemoryHigh",
                "MainPID",
                "ControlPID",
                "Job",
                "NRestarts",
                "ActiveState",
                "Result",
                "ExecMainStatus",
                "TriggeredBy",
                "ControlGroup",
            ] {
                let mut changed = u.clone();
                changed[key] = json!("changed");
                assert!(
                    terminal_identity(p, &changed, &u).is_err(),
                    "accepted {key}"
                );
            }
            for k in 0..5 {
                let mut changed = r.clone();
                match k {
                    0 => changed.maximum_memory_bytes -= 1,
                    1 => changed.remaining_disk_growth_bytes -= 1,
                    2 => changed.minimum_free_bytes -= 1,
                    3 => changed.release = Some(p.proof()),
                    _ => changed.invocation_id = "b".repeat(32),
                }
                assert!(booking(p, &changed, 900).is_err());
            }
        }
    }
    #[test]
    fn only_exact_registered_native_rows_leave_original_finalization_validation() {
        for p in PEERS {
            let (_, e, _, _) = fixture(p);
            for (k, v) in [
                ("epoch", json!(266)),
                ("phase", json!("producer-finalization")),
                ("unit", json!({"Id":"other.service"})),
            ] {
                let mut changed = e.clone();
                changed[k] = v;
                assert!(!selected(&changed));
            }
        }
        assert!(!selected(
            &json!({"epoch":248,"phase":"producer-finalization"})
        ));
        assert!(validate(&json!({"pipelines":[],"active":[]}), &[]).is_err());
    }
    #[test]
    fn old_success_only_input_envelope_cannot_replace_authentic_terminal_capture() {
        assert!(
            input265(
                &json!({"schema":"horizon265-exact-worker-cold-input-qualification-v1",
            "full_accounts_commitment_verified":true,"guard_trips":0})
            )
            .is_err()
        );
        assert!(input265(&json!(PEERS[0].proof())).is_err());
    }
    #[test]
    fn daemon_reload_display_reset_preserves_only_command_identity() {
        for p in PEERS {
            let (u, _, _, _) = fixture(p);
            let mut display = u.clone();
            display["ExecStart"] = json!(format!(
                "{{ path=/test ; argv[]=/test ; ignore_errors=no ; start_time=[x] ; stop_time=[y] ; pid={} ; code=exited ; status=0 }}",
                p.pid
            ));
            terminal_identity(p, &display, &u).unwrap();
            display["ExecStart"] = json!(
                text(&display, "ExecStart")
                    .unwrap()
                    .replace("ignore_errors=no", "ignore_errors=yes")
            );
            assert!(terminal_identity(p, &display, &u).is_err());
        }
    }
}
