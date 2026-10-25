//! Validation shared by private natural-root prefix adapters.
//! A profile supplies its closed scope; these helpers never grant publication.
use super::*;

pub(super) const DOWNSTREAM: [&str; 12] = [
    "archive_close",
    "assembly",
    "boundary",
    "compatibility_repair",
    "full_verification",
    "native_restart",
    "plugin_verification",
    "prefix_reread",
    "readback",
    "sidecar_commit",
    "suffix",
    "upload",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Estimate {
    pub initialization_allowance_millis: u64,
    pub fallback_slots_per_second: f64,
    pub downstream_allowance_millis: BTreeMap<String, u64>,
}

pub(super) fn iid(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Permit PID1's display-only timestamp/PID reset, while preserving the command
/// and `ignore_errors` decision. Never strip arbitrary command suffixes.
pub(super) fn same_command(value: &Value, expected: &str) -> bool {
    value
        .as_str()
        .and_then(|v| v.split_once(" ; ignore_errors="))
        .is_some_and(|(command, rest)| {
            command == expected && (rest == "no" || rest.starts_with("no ; "))
        })
}

pub(super) fn owner(value: &Value, unit: &str, invocation: &str, command: &str) -> bool {
    iid(invocation)
        && value["Id"] == unit
        && value["InvocationID"] == invocation
        && value["LoadState"] == "loaded"
        && value["NRestarts"] == "0"
        && value["ActiveState"] == "active"
        && value["SubState"] == "running"
        && value["Result"] == "success"
        && value["ExecMainStatus"] == "0"
        && value["ControlGroup"] == format!("/system.slice/{unit}")
        && value["MainPID"]
            .as_str()
            .and_then(|p| p.parse::<u64>().ok())
            .is_some_and(|p| p > 1)
        && same_command(&value["ExecStart"], command)
}

pub(super) fn event_clock(
    sample: u64,
    observed: u64,
    captured: u64,
    now: u64,
    event: bool,
) -> Result<()> {
    ensure!(
        observed <= sample
            && captured <= sample
            && sample <= now
            && now - sample <= 1800
            && (!event || (sample == captured && now - sample <= 300 && sample - observed <= 1800)),
        "private prefix status sample is stale, future, or predates its owner"
    );
    Ok(())
}

/// Reproduce elapsed time from the original PID1 monotonic start, anchored at
/// capture. No poll clock may reset elapsed time. UTC status has second precision.
pub(super) fn elapsed(
    sample_seconds: u64,
    wall_millis: u64,
    monotonic_millis: u64,
    start_us: u64,
) -> Result<u64> {
    ensure!(
        start_us > 0,
        "private prefix original invocation start is absent"
    );
    let age = monotonic_millis
        .checked_sub(start_us / 1000)
        .context("private prefix start is after capture")?;
    let start_wall = wall_millis
        .checked_sub(age)
        .context("private prefix clock anchor underflow")?;
    let sample = sample_seconds
        .checked_mul(1000)
        .context("private prefix sample clock overflow")?;
    ensure!(
        sample.checked_add(999).is_some_and(|s| s >= start_wall),
        "private prefix sample predates the original invocation"
    );
    Ok(sample.saturating_sub(start_wall))
}

fn rate(progress: &Value, bootstrap: u64, terminal: u64) -> Result<Option<f64>> {
    let resets = progress["counter_resets"]
        .as_u64()
        .context("private prefix progress reset count absent")?;
    if progress["sufficient_for_rates"] != true {
        ensure!(
            resets == 0,
            "private prefix counter reset lacks an independent slot window"
        );
        return Ok(None);
    }
    let first = &progress["first"];
    let last = &progress["last"];
    let a = first["slot"]
        .as_u64()
        .context("private prefix first slot absent")?;
    let b = last["slot"]
        .as_u64()
        .context("private prefix last slot absent")?;
    let start = first["realtime_microseconds"]
        .as_u64()
        .context("private prefix first progress clock absent")?;
    let end = last["realtime_microseconds"]
        .as_u64()
        .context("private prefix last progress clock absent")?;
    let duration = end
        .checked_sub(start)
        .filter(|d| *d > 0)
        .context("private prefix progress clock reversed")?;
    let delta = b
        .checked_sub(a)
        .filter(|d| *d > 0)
        .context("private prefix slot progress reversed or empty")?;
    let computed = delta as f64 * 1_000_000.0 / duration as f64;
    let reported = progress["slots_per_second"]
        .as_f64()
        .context("private prefix slot rate absent")?;
    ensure!(
        progress["matching_markers"]
            .as_u64()
            .is_some_and(|n| n >= 2)
            && (bootstrap + 1..=terminal).contains(&a)
            && (bootstrap + 1..=terminal).contains(&b)
            && first["terminal_slot"] == terminal
            && last["terminal_slot"] == terminal
            && progress["slot_delta"] == delta
            && reported.is_finite()
            && reported > 0.0
            && computed.is_finite()
            && (computed - reported).abs() <= (computed * 1e-9).max(1e-12),
        "private prefix measured rate is not an independent monotonic slot window"
    );
    Ok(Some(reported))
}

pub(super) fn estimate(
    progress: &Value,
    elapsed: u64,
    model: &Estimate,
    bootstrap: u64,
    terminal: u64,
) -> Result<(String, u64)> {
    ensure!(
        bootstrap < terminal
            && model.initialization_allowance_millis > 0
            && model.initialization_allowance_millis <= 86_400_000
            && model.fallback_slots_per_second.is_finite()
            && model.fallback_slots_per_second > 0.0
            && model
                .downstream_allowance_millis
                .keys()
                .map(String::as_str)
                .eq(DOWNSTREAM)
            && model
                .downstream_allowance_millis
                .values()
                .all(|n| *n > 0 && *n <= 30 * 86_400_000),
        "private prefix ETA needs a finite rate and every recovery/delivery allowance"
    );
    let downstream = model
        .downstream_allowance_millis
        .values()
        .try_fold(0u64, |n, v| {
            n.checked_add(*v)
                .context("private prefix downstream ETA overflow")
        })?;
    let observed = progress["last"]["slot"].as_u64();
    let current = observed.unwrap_or(bootstrap);
    ensure!(
        (bootstrap..=terminal).contains(&current),
        "private prefix progress escaped its sealed scope"
    );
    let measured = rate(progress, bootstrap, terminal)?;
    if current == terminal {
        return Ok(("verification".into(), downstream));
    }
    let executing = observed.is_some_and(|slot| slot > bootstrap);
    let effective_rate = measured.unwrap_or(model.fallback_slots_per_second);
    let replay = ((terminal - current) as f64 * 1000.0 / effective_rate).ceil();
    ensure!(
        replay.is_finite() && replay >= 0.0 && replay < u64::MAX as f64,
        "private prefix replay ETA overflow"
    );
    let initialization = if executing {
        0
    } else if elapsed < model.initialization_allowance_millis {
        model.initialization_allowance_millis - elapsed
    } else {
        elapsed
            .checked_div(2)
            .and_then(|n| n.checked_add(model.initialization_allowance_millis / 2))
            .context("private prefix overdue initialization ETA overflow")?
    };
    let remaining = (replay as u64)
        .checked_add(initialization)
        .and_then(|n| n.checked_add(downstream))
        .context("private prefix inclusive sidecar ETA overflow")?;
    Ok((
        if executing { "replay" } else { "verification" }.into(),
        remaining,
    ))
}

pub(super) fn private_jet(root: &Path, filename: &str, uid: u32) -> Result<u64> {
    for p in [root.to_path_buf(), root.join("output")] {
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0 && p.canonicalize()? == p,
            "private prefix archive directory is not canonical and owner-private"
        );
    }
    let path = root.join("output").join(filename);
    let first = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let second = fs::symlink_metadata(&path)?;
    ensure!(
        first.is_file()
            && second.is_file()
            && first.uid() == uid
            && second.uid() == uid
            && first.nlink() == 1
            && second.nlink() == 1
            && first.mode() & 0o077 == 0
            && second.mode() & 0o077 == 0
            && first.dev() == second.dev()
            && first.ino() == second.ino()
            && second.len() >= first.len(),
        "private prefix archive was linked, replaced, shrank, or lost private ownership"
    );
    Ok(first.len())
}

/// Preserve every old raw row; only this exact newly captured owner may be
/// removed from the comparison against the admission predecessor.
pub(super) fn capture_census(
    fleet: &Value,
    current: &BTreeMap<String, Value>,
    unit: &str,
    invocation: &str,
    command: &str,
) -> Result<()> {
    let peers = capture_peer_view(fleet, current, unit, invocation, command)?;
    maintenance_capacity::current_owners(fleet, &peers)
}
fn capture_peer_view(
    fleet: &Value,
    current: &BTreeMap<String, Value>,
    unit: &str,
    invocation: &str,
    command: &str,
) -> Result<BTreeMap<String, Value>> {
    let own = current
        .get(unit)
        .context("private prefix actual owner absent from census")?;
    ensure!(
        owner(own, unit, invocation, command),
        "private prefix actual owner changed"
    );
    ensure!(
        fleet["unit_census"]
            .get(unit)
            .is_none_or(|old| old["ActiveState"] != "active" && old["SubState"] != "running"),
        "private prefix admission predecessor already has an active owner"
    );
    let mut peers = current.clone();
    if let Some(old) = fleet["unit_census"].get(unit) {
        peers.insert(unit.into(), old.clone());
    } else {
        peers.remove(unit);
    }
    Ok(peers)
}

pub(super) fn assigned_cpus_available(value: &str) -> Result<()> {
    let mut available = BTreeSet::new();
    for token in value.trim().split(',') {
        let (start, end) = if let Some((a, b)) = token.split_once('-') {
            (a.parse::<u32>()?, b.parse::<u32>()?)
        } else {
            let n = token.parse::<u32>()?;
            (n, n)
        };
        ensure!(
            start <= end && end < 4096,
            "private prefix parent CPU mask is malformed or oversized"
        );
        for cpu in start..=end {
            ensure!(
                available.insert(cpu),
                "private prefix parent CPU mask duplicates a CPU"
            );
        }
    }
    ensure!(
        (8..16).all(|cpu| available.contains(&cpu)),
        "private prefix separately assigned CPUs are unavailable"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn model() -> Estimate {
        Estimate {
            initialization_allowance_millis: 600_000,
            fallback_slots_per_second: 2.0,
            downstream_allowance_millis: DOWNSTREAM.iter().map(|s| (s.to_string(), 1000)).collect(),
        }
    }
    #[test]
    fn elapsed_uses_original_start_and_rejects_prestart_or_future_anchor() {
        assert_eq!(elapsed(1000, 1_000_400, 50_000, 40_000_000).unwrap(), 9600);
        assert_eq!(elapsed(1001, 1_000_400, 50_000, 40_000_000).unwrap(), 10600);
        assert!(elapsed(980, 1_000_400, 50_000, 40_000_000).is_err());
        assert!(elapsed(1000, 1_000_400, 50_000, 60_000_000).is_err());
        assert!(elapsed(1000, 1_000_400, 50_000, 0).is_err());
    }
    #[test]
    fn launch_and_observation_clocks_cannot_be_backdated_or_reset() {
        event_clock(1000, 900, 1000, 1100, true).unwrap();
        event_clock(1200, 1200, 1000, 1250, false).unwrap();
        for args in [
            (900, 900, 1000, 1100, true),
            (1001, 900, 1000, 1100, true),
            (1000, 900, 1000, 1400, true),
            (1500, 1200, 1000, 1400, false),
        ] {
            assert!(event_clock(args.0, args.1, args.2, args.3, args.4).is_err());
        }
    }
    #[test]
    fn warmup_is_execution_and_terminal_still_includes_sidecar_work() {
        let p = model();
        let initial = json!({"last":null,"counter_resets":0,"sufficient_for_rates":false});
        assert_eq!(
            estimate(&initial, 100_000, &p, 100, 500).unwrap(),
            ("verification".into(), 712_000)
        );
        let warm = json!({"last":{"slot":101},"counter_resets":0,"sufficient_for_rates":false});
        assert_eq!(
            estimate(&warm, 100_000, &p, 100, 500).unwrap(),
            ("replay".into(), 211_500)
        );
        let terminal = json!({"last":{"slot":500},"counter_resets":0,"sufficient_for_rates":false});
        assert_eq!(
            estimate(&terminal, 100_000, &p, 100, 500).unwrap(),
            ("verification".into(), 12_000)
        );
        assert!(
            estimate(&initial, 1_200_000, &p, 100, 500).unwrap().1
                > estimate(&initial, 600_000, &p, 100, 500).unwrap().1
        );
    }
    #[test]
    fn reset_accounting_needs_a_reproducible_monotonic_slot_rate() {
        let progress = json!({"counter_resets":2,"sufficient_for_rates":true,"matching_markers":2,
            "first":{"slot":110,"terminal_slot":500,"realtime_microseconds":1_000_000},
            "last":{"slot":210,"terminal_slot":500,"realtime_microseconds":51_000_000},
            "slot_delta":100,"slots_per_second":2.0});
        assert_eq!(
            estimate(&progress, 0, &model(), 100, 500).unwrap(),
            ("replay".into(), 157_000)
        );
        for (path, value) in [
            ("/slot_delta", json!(101)),
            ("/slots_per_second", json!(4.0)),
            ("/matching_markers", json!(1)),
            ("/last/slot", json!(109)),
            ("/last/terminal_slot", json!(501)),
            ("/sufficient_for_rates", json!(false)),
        ] {
            let mut bad = progress.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(estimate(&bad, 0, &model(), 100, 500).is_err(), "{path}");
        }
    }
    #[test]
    fn incomplete_recovery_or_nonfinite_estimates_fail_closed() {
        let progress = json!({"last":null,"counter_resets":0,"sufficient_for_rates":false});
        for missing in [
            "compatibility_repair",
            "suffix",
            "readback",
            "sidecar_commit",
        ] {
            let mut p = model();
            p.downstream_allowance_millis.remove(missing);
            assert!(estimate(&progress, 0, &p, 100, 500).is_err());
        }
        let mut p = model();
        p.fallback_slots_per_second = f64::NAN;
        assert!(estimate(&progress, 0, &p, 100, 500).is_err());
        let mut p = model();
        p.downstream_allowance_millis.insert("suffix".into(), 0);
        assert!(estimate(&progress, 0, &p, 100, 500).is_err());
    }
    #[test]
    fn command_display_normalization_retains_execution_semantics() {
        assert!(same_command(
            &json!("{ path=/sealed ; argv[]=/sealed 233 ; ignore_errors=no ; pid=0 }"),
            "{ path=/sealed ; argv[]=/sealed 233"
        ));
        for value in [
            "{ path=/sealed ; argv[]=/sealed 233 ; ignore_errors=yes",
            "{ path=/sealed ; argv[]=/sealed 234 ; ignore_errors=no",
            "{ path=/sealed ; argv[]=/sealed 233 ; ignore_errors=not-no",
        ] {
            assert!(!same_command(
                &json!(value),
                "{ path=/sealed ; argv[]=/sealed 233"
            ));
        }
    }
    #[test]
    fn captured_peer_view_preserves_raw_peers_and_rejects_a_replacement() {
        let name = "new.service";
        let invocation = "a".repeat(32);
        let command = "{ path=/node ; argv[]=/node 233";
        let own = json!({"Id":name,"InvocationID":invocation,"LoadState":"loaded","NRestarts":"0",
            "ActiveState":"active","SubState":"running","Result":"success","ExecMainStatus":"0",
            "ControlGroup":"/system.slice/new.service","MainPID":"42","ExecStart":format!("{command} ; ignore_errors=no")});
        let peer = json!({"Id":"peer.service","InvocationID":"b".repeat(32),"raw_evidence":{"preserve":true}});
        let current = BTreeMap::from([
            (name.into(), own.clone()),
            ("peer.service".into(), peer.clone()),
        ]);
        let f = json!({"unit_census":{"peer.service":peer}});
        assert_eq!(
            capture_peer_view(&f, &current, name, &invocation, command).unwrap(),
            BTreeMap::from([("peer.service".into(), peer)])
        );
        let mut bad = current.clone();
        bad.get_mut(name).unwrap()["NRestarts"] = json!("1");
        assert!(capture_peer_view(&f, &bad, name, &invocation, command).is_err());
        let mut bad = f;
        bad["unit_census"][name] = own;
        assert!(capture_peer_view(&bad, &current, name, &invocation, command).is_err());
    }
    #[test]
    fn separate_cpu_assignment_is_bound_to_available_parent_cpus() {
        for good in ["0-127", "8-15", "0-7,8-15,16-31"] {
            assigned_cpus_available(good).unwrap();
        }
        for bad in ["0-7", "8-14", "0-7,9-15", "8-15,9", "15-8", "0-1000000"] {
            assert!(assigned_cpus_available(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn private_archive_measurement_accepts_absence_and_rejects_links_or_public_modes() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("output");
        fs::create_dir(&output).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(private_jet(root.path(), "prefix.jet", uid).unwrap(), 0);
        let file = output.join("prefix.jet");
        fs::write(&file, b"partial").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(private_jet(root.path(), "prefix.jet", uid).unwrap(), 7);
        fs::hard_link(&file, output.join("alias")).unwrap();
        assert!(private_jet(root.path(), "prefix.jet", uid).is_err());
        fs::remove_file(output.join("alias")).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_jet(root.path(), "prefix.jet", uid).is_err());
        fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("/outside", &file).unwrap();
        assert!(private_jet(root.path(), "prefix.jet", uid).is_err());
    }
}
