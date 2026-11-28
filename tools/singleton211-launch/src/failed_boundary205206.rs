//! Memory-only accounting after the exact failed v135 boundary. The v138
//! retry has a separate booking and its own private tmpfs at the same pathname.
use super::*;
#[path = "failed_boundary205206/retry_memory.rs"]
pub(super) mod retry_memory;

const OLD: &str = "horizon205206-adjacent-boundary-v135-v1.service";
const IID: &str = "c575c1f6415d4f82b9432473f2e94ed1";
const RETRY: &str = "horizon205206-adjacent-boundary-v137-v2.service";
const RETRY_IID: &str = "5c0fb3eb5d594e06981838633f47dfaf";
const BOOT: &str = "3b17d005-5c3a-4a0e-8841-da097e0957b5";
const TMP: &str = "/run/horizon205206-private-tmpfs";
const CAP: u64 = 125_000_000_000;
const ORIGINAL: &str = include_str!("failed_boundary205206/original.json");
const TERMINAL: &str = "/home/ubuntu/.codex/diagnostics/horizon205206-adjacent-boundary-retry-v137-v2/original-terminal.json";
const SHA: &str = "d5f186e10183abdf3c0780825b1e09e080871d64156efd1f4afc20de618930f9";
const FIELD: &str = "failed_boundary205206_memory_release";
const MANAGER: &str = "_PID,_UID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE_ID,EXIT_CODE,EXIT_STATUS,UNIT_RESULT,MESSAGE,__MONOTONIC_TIMESTAMP";
const PROCESS: &str =
    "_PID,_UID,_BOOT_ID,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_EXE,MESSAGE,__MONOTONIC_TIMESTAMP";

fn scope(rows: &[capacity::Reservation], currents: &BTreeMap<String, u64>) -> Result<usize> {
    let lookup = |unit: &str, iid: &str, cap: u64| -> Result<usize> {
        let index = rows
            .iter()
            .position(|r| r.unit == unit)
            .context("missing boundary or park reservation")?;
        let r = &rows[index];
        ensure!(
            r.invocation_id == iid
                && r.maximum_memory_bytes == cap
                && r.remaining_disk_growth_bytes >= 268_435_456
                && r.minimum_free_bytes >= 3_908_104_436_088
                && r.release.is_none(),
            "changed boundary or park booking: {unit}"
        );
        Ok(index)
    };
    let index = lookup(OLD, IID, CAP)?;
    ensure!(
        rows[index].source
            == Bound::new(
                "/var/lib/jetstreamer/horizon-native257-current-bookings-v136-ops-v2/boundary-booking.json",
                "0822f0c792679fd2dec1f0353d429f68150ee6850252d857f61e76c0e00eb850"
            )
            && !currents.contains_key(OLD),
        "original boundary was substituted or charged as active"
    );
    lookup(RETRY, RETRY_IID, CAP)?;
    lookup(
        "horizon223-full-root-private-park-v134-v1.service",
        "47807d55fa6f4a5bb04e228f4a0ee166",
        4_294_967_296,
    )?;
    lookup(
        "horizon223-singleton-park-v137-v1.service",
        "a09f89a2780241c1b6f687d44d109017",
        4_294_967_296,
    )?;
    Ok(index)
}

fn records(n: &mut Native, fields: &str, filters: &[&str]) -> Result<Value> {
    let field_arg = format!("--output-fields={fields}");
    let mut args = vec![
        "--quiet",
        "--no-pager",
        "--output=json",
        field_arg.as_str(),
        "--lines=64",
    ];
    args.extend_from_slice(filters);
    let raw = n.run("/usr/bin/journalctl", &args)?;
    ensure!(raw.len() < 256 << 10, "unexpected journal volume");
    let mut rows = Vec::new();
    for row in serde_json::Deserializer::from_slice(&raw).into_iter::<Value>() {
        let row = row?;
        let mut selected = serde_json::Map::new();
        for k in fields.split(',') {
            if let Some(v) = row.get(k) {
                selected.insert(k.into(), v.clone());
            }
        }
        rows.push(Value::Object(selected));
    }
    Ok(Value::Array(rows))
}

fn properties(n: &mut Native, original: &Value) -> Result<Value> {
    let fields = original
        .as_object()
        .context("original unit")?
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",");
    let raw = n.run(
        "/usr/bin/systemctl",
        &["show", OLD, "--no-pager", "--property", &fields],
    )?;
    let mut values = serde_json::Map::new();
    for l in std::str::from_utf8(&raw)?.lines() {
        let (k, v) = l.split_once('=').context("boundary property")?;
        ensure!(
            values.insert(k.into(), json!(v)).is_none(),
            "duplicate boundary property"
        );
    }
    Ok(Value::Object(values))
}

fn compare_terminal(actual: &Value, original: &Value) -> Result<()> {
    if actual != original {
        // PID1's transient ExecStart history may be cleared by daemon-reload.
        // Keep every other manager property and the independently pinned
        // original exit, fragment and PID1/process journal evidence exact.
        let prefix = text(original, "ExecStart")?
            .split_once(" ; start_time=")
            .context("original boundary command")?
            .0;
        let mut cleared = original.clone();
        cleared["ExecStart"] = json!(format!(
            "{prefix} ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
        ));
        ensure!(
            actual == &cleared,
            "original boundary execution, manager, restart, queue or dependency changed"
        );
    }
    Ok(())
}
fn historical(n: &mut Native, original: &Value) -> Result<()> {
    let manager = records(
        n,
        MANAGER,
        &[
            "_PID=1",
            &format!("UNIT={OLD}"),
            &format!("INVOCATION_ID={IID}"),
        ],
    )?;
    let process = records(
        n,
        PROCESS,
        &[
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
            "--grep=restored and verified|plan must be root-owned|r2-readback-(start|verified)",
        ],
    )?;
    history_matches(original, &manager, &process)
}

fn history_matches(original: &Value, manager: &Value, process: &Value) -> Result<()> {
    ensure!(
        *manager == original["manager"] && *process == original["process"],
        "missing exact PID1 failure, restored whole archive, rehash or plan rejection"
    );
    Ok(())
}

fn unavailable(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!("old boundary resource still present: {}", path.display()),
        Err(e) => Err(e.into()),
    }
}

fn mount_device(raw: &str, retry_device: Option<&str>) -> Result<Option<String>> {
    let mut selected = None;
    for line in raw.lines() {
        let (before, after) = line.split_once(" - ").context("invalid mountinfo")?;
        let fields = before.split_whitespace().collect::<Vec<_>>();
        let options = after.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() >= 6 && options.len() == 3,
            "invalid mount fields"
        );
        let target = fields[4] == TMP;
        let matching_fs =
            options[0] == "tmpfs" && options[2].split(',').any(|o| o == "size=106356736k");
        if target || matching_fs {
            ensure!(
                target && matching_fs && fields[3] == "/" && selected.is_none(),
                "ambiguous/bind-mounted boundary tmpfs"
            );
            if let Some(expected) = retry_device {
                ensure!(expected == fields[2], "another boundary tmpfs remains");
            }
            selected = Some(fields[2].to_owned());
        }
    }
    Ok(selected)
}

fn group(pid: &str) -> Result<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    ensure!(raw.lines().count() == 1, "nonunified boundary cgroup");
    Ok(raw
        .trim()
        .strip_prefix("0::")
        .context("cgroup prefix")?
        .into())
}

fn census(retry: &Value) -> Result<Value> {
    let oldcg = format!("/system.slice/{OLD}");
    let newcg = format!("/system.slice/{RETRY}");
    unavailable(&Path::new("/sys/fs/cgroup").join(oldcg.trim_start_matches('/')))?;
    let host = Path::new(TMP);
    ensure!(
        host.canonicalize()? == host
            && fs::metadata(host)?.dev() == fs::metadata("/run")?.dev()
            && fs::read_dir(host)?.next().is_none(),
        "shared recovery mount or body"
    );
    let active = retry["ActiveState"] == "active";
    let retry_pid = text(retry, "MainPID")?;
    let retry_ns = if active {
        ensure!(
            retry["InvocationID"] == RETRY_IID && group(retry_pid)? == newcg,
            "unexpected retry owner"
        );
        let ns = fs::read_link(format!("/proc/{retry_pid}/ns/mnt"))?;
        let raw = fs::read_to_string(format!("/proc/{retry_pid}/mountinfo"))?;
        Some((
            ns,
            mount_device(&raw, None)?.context("retry private mount missing")?,
        ))
    } else {
        ensure!(
            matches!(retry["ActiveState"].as_str(), Some("inactive" | "failed"))
                && retry["MainPID"] == "0"
                && retry["ControlPID"] == "0"
                && retry["Job"] == "",
            "ambiguous retry phase"
        );
        None
    };
    let mut namespaces = BTreeSet::new();
    for entry in fs::read_dir("/proc")? {
        let e = entry?;
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|v| v.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        let proc = e.path();
        let inspect = || -> Result<(PathBuf, Option<String>)> {
            let cg = group(pid)?;
            ensure!(
                cg != oldcg
                    && !cg.starts_with(&format!("{oldcg}/"))
                    && (retry["LoadState"] != "not-found"
                        || (cg != newcg && !cg.starts_with(&format!("{newcg}/")))),
                "old boundary cgroup member"
            );
            let ns = fs::read_link(proc.join("ns/mnt"))?;
            if retry_ns.as_ref().is_some_and(|(id, _)| id == &ns) {
                ensure!(cg == newcg, "retry namespace outside its booked owner");
            }
            let dev = if namespaces.contains(&ns) {
                None
            } else {
                let mountinfo = fs::read_to_string(proc.join("mountinfo"))?;
                ensure!(mountinfo.len() < 16 << 20, "oversized mountinfo");
                mount_device(&mountinfo, retry_ns.as_ref().map(|(_, d)| d.as_str()))?
            };
            if dev.is_some() {
                ensure!(
                    retry_ns.as_ref().is_some_and(|(id, _)| id == &ns),
                    "unowned private tmpfs"
                );
            }
            ensure!(
                fs::read_link(proc.join("ns/mnt"))? == ns,
                "mount namespace changed during inspection"
            );
            Ok((ns, dev))
        };
        match inspect() {
            Ok((ns, _)) => {
                namespaces.insert(ns);
            }
            Err(_) if !proc.try_exists()? => {}
            Err(err) => {
                // A zombie has released its fd table, memory and namespace.
                let stat = fs::read_to_string(proc.join("stat"))?;
                if !stat
                    .rsplit_once(')')
                    .is_some_and(|(_, s)| s.starts_with(" Z "))
                {
                    return Err(err);
                }
            }
        }
    }
    let refs = native265_growth::tree_references(Path::new("/proc"), host)?;
    for reference in &refs.references {
        let pid = reference
            .strip_prefix("pid ")
            .and_then(|s| s.split_once(' '))
            .context("invalid proc reference")?
            .0;
        // A vanished process holds no remaining reference. Reuse/different scope is denied.
        let p = Path::new("/proc").join(pid);
        if !p.try_exists()? {
            continue;
        }
        let (ns, _) = retry_ns
            .as_ref()
            .context("boundary tmpfs reference survived")?;
        ensure!(
            group(pid)? == newcg && fs::read_link(p.join("ns/mnt"))? == *ns,
            "boundary references outside exact retry"
        );
    }
    Ok(
        json!({"old_cgroup_absent":true,"host_target_empty":true,"mount_namespaces":namespaces.len(),"retry_mount":retry_ns,"process_reference_scan":refs}),
    )
}

const COMPLETED_RETRY: &str = include_str!("failed_boundary205206/completed-retry.json");
const BRIDGE: &str = "/home/ubuntu/.jetstreamer-private/verification-205-current-20261117-v2/boundary/receipts/boundary-205-206.bridge.json";
const BRIDGE_SHA: &str = "901fce3fd550007e36c8cb65875ac27424ada589886b5db6d94b6cd2c05ae9c7";

fn collected_retry(
    n: &mut Native,
    retry: &Value,
    fleet: &Value,
    booking: &capacity::Reservation,
) -> Result<Value> {
    let expected: Value = serde_json::from_str(COMPLETED_RETRY)?;
    ensure!(
        retry == &expected["native"]
            && fleet["unit_census"][RETRY] == expected["fleet"]
            && booking.unit == RETRY
            && booking.invocation_id == RETRY_IID
            && booking.release.is_none()
            && booking.source
                == Bound::new(
                    "/var/lib/jetstreamer/horizon-native257-current-bookings-v138-ops-v1/boundary-booking.json",
                    "834f51f10bf2221ccf5a48465a96c626db778481ce72af6518028c36530f77e6"
                )
            && booking.remaining_disk_growth_bytes == 268435456
            && booking.maximum_memory_bytes == CAP,
        "collected retry state or complete nominal booking changed"
    );
    let manager = records(
        n,
        MANAGER,
        &[
            "_PID=1",
            &format!("UNIT={RETRY}"),
            &format!("INVOCATION_ID={RETRY_IID}"),
        ],
    )?;
    let process = records(
        n,
        PROCESS,
        &[
            &format!("_SYSTEMD_INVOCATION_ID={RETRY_IID}"),
            "--grep=r2-readback-verified|restored and verified|private_receipt_sha256",
        ],
    )?;
    history_matches(&expected, &manager, &process)?;
    unavailable(
        Path::new("/sys/fs/cgroup/system.slice")
            .join(RETRY)
            .as_path(),
    )?;
    unavailable(Path::new("/run/systemd/transient").join(RETRY).as_path())?;
    let bridge = Bound::new(BRIDGE, BRIDGE_SHA);
    let value = bridge.json()?;
    ensure!(
        value["authority"]["boundary_verified"] == true
            && value["bridge"]["verifier_status"] == 0
            && value["left"]["epoch"] == 205
            && value["right"]["epoch"] == 206,
        "completed retry boundary differs"
    );
    let canonical = Bound::new(
        "/home/ubuntu/.jetstreamer-private/verification-205-current-20261117-v2/boundary/receipts/boundary-205-206.ok",
        "369692d6a6bdfbacab0e6b0d51ce4b8b12ffef10b4b53393f1f2f1ed53efa28e",
    );
    ensure!(
        value["canonical_receipt_paths"] == json!([canonical.path])
            && value["canonical_receipt_sha256"] == canonical.sha256,
        "canonical boundary changed"
    );
    canonical.bytes(false)?;
    binding(&value["plan"])?.sealed()?;
    Bound::new(
        "/var/lib/jetstreamer/horizon205206-adjacent-boundary-v137-v2/verify-pair",
        "ee7347fd0801eaa1a5c4c703479067f6db60aaf255dbadfaaff6e9a4f26113c8",
    )
    .artifact()?;
    Ok(
        json!({"unit":RETRY,"invocation_id":RETRY_IID,"manager":manager,"process":process,"bridge":bridge,"canonical":canonical,"released_memory_bytes":0,"released_disk_growth_bytes":0}),
    )
}

pub(super) fn apply(
    n: &mut Native,
    review: &Value,
    fleet: &Value,
    currents: &BTreeMap<String, u64>,
    rows: &mut [capacity::Reservation],
) -> Result<Option<Value>> {
    let Some(value) = review.get(FIELD) else {
        return Ok(None);
    };
    let terminal = binding(value)?;
    ensure!(
        terminal == Bound::new(TERMINAL, SHA) && review["boot_id"] == BOOT,
        "unregistered original boundary transition"
    );
    let index = scope(rows, currents)?;
    let t = terminal.json()?;
    ensure!(
        t["unit"] == OLD
            && t["state"]["InvocationID"] == IID
            && t["no_boundary"] == true
            && t["credited_bytes"] == 0,
        "foreign terminal record"
    );
    Bound::new(
        "/run/systemd/transient/horizon205206-adjacent-boundary-v135-v1.service",
        "02f4fa7fbefddc2ad5461dd4e7156e62d19da0d6a1a543667280fbeab8a7adc7",
    )
    .bytes(false)?;
    Bound::new(
        "/var/lib/jetstreamer/horizon205206-adjacent-boundary-v135-v1/verify-pair",
        "ae5089992fd8afe39f92d67ad7eb9b661794c079cb3f28a9c4f9d674fb7e7db1",
    )
    .artifact()?;
    let original: Value = serde_json::from_str(ORIGINAL)?;
    let first = properties(n, &original["unit"])?;
    compare_terminal(&first, &original["unit"])?;
    live::same_owner(&fleet["unit_census"][OLD], &first)?;
    let retry = n.show(RETRY)?;
    let completed_retry = if retry["LoadState"] == "not-found" {
        ensure!(
            !currents.contains_key(RETRY),
            "collected retry still active"
        );
        let booking = rows
            .iter()
            .find(|r| r.unit == RETRY)
            .context("missing retry")?;
        Some(collected_retry(n, &retry, fleet, booking)?)
    } else {
        live::same_owner(&fleet["unit_census"][RETRY], &retry)?;
        None
    };
    historical(n, &original)?;
    let drainage = census(&retry)?;
    compare_terminal(&properties(n, &original["unit"])?, &original["unit"])?;
    let after = n.show(RETRY)?;
    if completed_retry.is_some() {
        ensure!(after == retry, "collected retry changed during census");
        unavailable(
            Path::new("/sys/fs/cgroup/system.slice")
                .join(RETRY)
                .as_path(),
        )?;
    } else {
        live::same_owner(&retry, &after)?;
    }
    n.check()?;
    // Only this in-memory arithmetic view changes. booked_arithmetic continues
    // to charge this row's full disk growth and floor, and every other owner.
    rows[index].release = Some(terminal.clone());
    Ok(Some(
        json!({"schema":"horizon-exact-failed-boundary205206-memory-release-v1","terminal":terminal,"unit":OLD,"invocation_id":IID,"retry_unit":RETRY,"retry_invocation_id":RETRY_IID,"retry_state":retry,"completed_retry":completed_retry,"original_state":first,"drainage":drainage,"original_ledger_unchanged":true,"released_memory_bytes":CAP,"released_disk_growth_bytes":0,"physical_allocation_credit_bytes":0,"inherited_floor_credit_bytes":0}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_v146_original_boundary_reload_only_clears_exec_history() -> Result<()> {
        let fixture: Value = serde_json::from_str(ORIGINAL)?;
        let original = &fixture["unit"];
        let mut cleared = original.clone();
        cleared["ExecStart"] = json!(
            "{ path=/var/lib/jetstreamer/horizon205206-adjacent-boundary-v135-v1/verify-pair ; argv[]=/var/lib/jetstreamer/horizon205206-adjacent-boundary-v135-v1/verify-pair ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        );
        compare_terminal(&cleared, original)?;
        for (old, new) in [
            ("verify-pair", "other"),
            ("ignore_errors=no", "ignore_errors=yes"),
            ("pid=0", "pid=1989128"),
            ("status=0/0", "status=1"),
        ] {
            let mut bad = cleared.clone();
            bad["ExecStart"] = json!(text(&cleared, "ExecStart")?.replace(old, new));
            assert!(compare_terminal(&bad, original).is_err());
        }
        for field in [
            "InvocationID",
            "ExecMainCode",
            "ExecMainStatus",
            "NRestarts",
            "MainPID",
            "FragmentPath",
        ] {
            let mut bad = cleared.clone();
            bad[field] = json!("changed");
            assert!(compare_terminal(&bad, original).is_err());
        }
        Ok(())
    }

    #[test]
    fn retained_failed_manager_denies_active_replacement_restart_and_pending_work() -> Result<()> {
        let real: Value = serde_json::from_str(ORIGINAL)?;
        let old = &real["unit"];
        compare_terminal(old, old)?;
        for (k, v) in [
            ("InvocationID", RETRY_IID),
            ("MainPID", "101"),
            ("ControlPID", "5"),
            ("Job", "12345"),
            ("ActiveState", "active"),
            ("NRestarts", "1"),
            ("Restart", "on-failure"),
            ("RequiredBy", "different.target"),
            ("TriggeredBy", "other.timer"),
            ("OnFailure", "other.service"),
            ("MemoryMax", "unlimited"),
            ("TemporaryFileSystem", ""),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
        ] {
            let mut wrong = old.clone();
            wrong[k] = json!(v);
            assert!(compare_terminal(&wrong, old).is_err(), "{k}");
        }
        Ok(())
    }

    #[test]
    fn substituted_journal_or_incomplete_restore_fails() -> Result<()> {
        let real: Value = serde_json::from_str(ORIGINAL)?;
        history_matches(&real, &real["manager"], &real["process"])?;
        let mut wrong = real["manager"].clone();
        wrong[0]["INVOCATION_ID"] = json!(RETRY_IID);
        assert!(history_matches(&real, &wrong, &real["process"]).is_err());
        for bad in [json!([]), json!([real["process"][0]]), {
            let mut x = real["process"].clone();
            x[0]["_SYSTEMD_INVOCATION_ID"] = json!(RETRY_IID);
            x
        }] {
            assert!(history_matches(&real, &real["manager"], &bad).is_err());
        }
        Ok(())
    }

    #[test]
    fn foreign_or_shared_boundary_tmpfs_fails() -> Result<()> {
        let sample = "548 546 0:59 / /run/horizon205206-private-tmpfs rw,nosuid,nodev shared:427 - tmpfs tmpfs rw,size=106356736k,nr_inodes=409600,mode=700,inode64";
        assert_eq!(mount_device(sample, Some("0:59"))?.as_deref(), Some("0:59"));
        for wrong in [
            sample.replace("0:59", "0:72"),
            sample.replace(TMP, "/other"),
            sample.replace("106356736k", "1000k"),
            format!("{sample}\n{sample}"),
        ] {
            assert!(mount_device(&wrong, Some("0:59")).is_err());
        }
        assert!(mount_device("broken", None).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires genuine v138 holds, original journal, PID1, and a read-only host census"]
    fn genuine_v138_fit_and_holding_bookings_after_only_original_memory_release() -> Result<()> {
        let fit = Bound::new(
            "/var/lib/jetstreamer/horizon-native257-fit-v138-ops-v2-result/fit.json",
            "d2da3a395bf1d861793f18fa564fcc3854cbd5182265ffc423edd7edb8ac1a4f",
        )
        .sealed()?;
        let mut review = binding(&fit["review"])?.sealed()?;
        let fleet = binding(&fit["fleet"])?.json()?;
        let ledger = binding(&fit["reservation_ledger"])?.sealed()?;
        let before: Vec<capacity::Reservation> =
            serde_json::from_value(ledger["reservations"].clone())?;
        let currents: BTreeMap<String, u64> =
            serde_json::from_value(fit["actual_current_memory"].clone())?;
        ensure!(
            before.len() == 15 && ledger["schema"] == "horizon-native211-retained-reservations-v3",
            "foreign v138 ledger"
        );
        let dir = PathBuf::from(
            std::env::var("HORIZON_BOUNDARY205206_QUALIFICATION_DIRECTORY")
                .context("missing private qualification directory")?,
        );
        ensure!(
            dir.is_absolute()
                && dir.canonicalize()? == dir
                && dir.starts_with("/run")
                && fs::read_dir(&dir)?.next().is_none(),
            "private qualification needs fresh evidence directory"
        );
        let mut n = Native {
            root: dir,
            counter: 0,
            deadline: Some(mono()? + 180_000_000),
        };
        let mut rows = before.clone();
        assert!(apply(&mut n, &review, &fleet, &currents, &mut rows)?.is_none());
        let terminal = Bound::new(TERMINAL, SHA);
        review[FIELD] = json!(terminal);
        let proof = apply(&mut n, &review, &fleet, &currents, &mut rows)?
            .context("missing genuine boundary proof")?;
        assert_eq!(proof["released_memory_bytes"], CAP);
        let index = scope(&before, &currents)?;
        let mut expected = before.clone();
        expected[index].release = Some(terminal);
        assert_eq!(json!(rows), json!(expected));
        let mut active = currents.clone();
        active.insert(OLD.into(), 1);
        assert!(scope(&before, &active).is_err());
        for unit in [
            OLD,
            RETRY,
            "horizon223-full-root-private-park-v134-v1.service",
            "horizon223-singleton-park-v137-v1.service",
        ] {
            let mut wrong = before.clone();
            wrong
                .iter_mut()
                .find(|r| r.unit == unit)
                .unwrap()
                .invocation_id = "0".repeat(32);
            assert!(scope(&wrong, &currents).is_err());
        }
        let mut wrong_review = review.clone();
        wrong_review[FIELD]["sha256"] = json!("0".repeat(64));
        assert!(
            apply(
                &mut n,
                &wrong_review,
                &fleet,
                &currents,
                &mut before.clone()
            )
            .is_err()
        );
        // Use the exact archived physical total and the same effective disk arithmetic
        // as the authentic fit. Relax only the independent disk/available-memory
        // limits in the controlled comparison, and separately test the actual disk.
        let obs = binding(&fit["observer"])?.json()?;
        let total = num(&obs["host_memory"], "total_kib")? * 1024;
        let century = capacity::century(&binding(&review["century"])?.sealed()?, &fleet)?;
        let periodic = ledger["periodic_controls"]["controls"]
            .as_array()
            .context("periodic controls")?
            .iter()
            .try_fold(0, |sum, r| {
                capacity::add(sum, num(r, "maximum_memory_bytes")?)
            })?;
        let overhead = (
            num(&ledger["auxiliary_overhead"], "memory_bytes")?,
            periodic,
        );
        let effective = |rows: &mut [capacity::Reservation]| {
            rows.iter_mut()
                .find(|r| r.unit == "horizon-265-native-input-20261119-v1.service")
                .unwrap()
                .remaining_disk_growth_bytes = 0;
            rows.iter_mut()
                .find(|r| r.unit == UNIT)
                .unwrap()
                .remaining_disk_growth_bytes = fit["full211_growth"]["remaining_disk_growth_bytes"]
                .as_u64()
                .unwrap();
        };
        let mut prior = before;
        effective(&mut prior);
        effective(&mut rows);
        let prior_fit = scenarios(
            (total, total, u64::MAX),
            century,
            &prior,
            &currents,
            overhead,
            0,
        );
        assert_eq!(
            prior_fit["limited_native257_with_booked_full211"]["reason"],
            fit["scenarios"]["limited_native257_with_booked_full211"]["reason"]
        );
        let updated = scenarios(
            (total, total, u64::MAX),
            century,
            &rows,
            &currents,
            overhead,
            0,
        );
        assert_eq!(
            updated["limited_native257_with_booked_full211"]["capacity"]["memory_obligation_after_bytes"],
            1_092_636_631_552u64
        );
        let holding = |rows: &[capacity::Reservation]| {
            capacity::booked_arithmetic(
                (total, total, u64::MAX),
                century,
                rows,
                &currents,
                overhead,
                (0, 63_045_455_286),
            )
        };
        let old = holding(&prior)?;
        let new = holding(&rows)?;
        assert_eq!(
            num(&old, "memory_obligation_after_bytes")?
                - num(&new, "memory_obligation_after_bytes")?,
            CAP
        );
        for k in [
            "protected_existing_floor_bytes",
            "retained_disk_growth_bytes",
            "required_initial_free_bytes",
            "allocation_credit_taken_bytes",
        ] {
            assert_eq!(old[k], new[k]);
        }
        let free = num(&fit["full211_growth"], "conservative_free_bytes")?;
        let untouched = scenarios((total, total, free), century, &rows, &currents, overhead, 0);
        assert_eq!(
            untouched["limited_native257_with_booked_full211"]["fits"],
            false
        );
        assert!(
            untouched["limited_native257_with_booked_full211"]["reason"]
                .as_str()
                .is_some_and(|s| s.contains("exceed disk"))
        );
        save_json(
            &n.root,
            "private-proof.json",
            &json!({"proof":proof,"prior_fit":prior_fit,"updated_memory_only_comparison":updated,"actual_sample_disk":untouched,"old_holding":old,"new_holding":new,"no_admission":true}),
        )?;
        Ok(())
    }
}
