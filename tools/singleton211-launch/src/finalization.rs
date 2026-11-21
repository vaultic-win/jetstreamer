//! Exact original singleton EOF changes phase only; every original obligation remains.
use super::*;
#[derive(Clone, Copy)]
struct Profile {
    epoch: u64,
    unit: &'static str,
    iid: &'static str,
    pid: u64,
    node: &'static str,
    node_sha: &'static str,
    command: &'static str,
    manifest: &'static str,
    manifest_sha: &'static str,
    terminal_slot: u64,
}
const PROFILES: [Profile; 4] = [
    Profile {
        epoch: 248,
        unit: "horizon-qualify-248-reboot-20261117-v1.service",
        iid: "16f84e36b65645a7be7d28d08e3d40cc",
        pid: 74807,
        node: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node",
        node_sha: "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
        command: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 248 /home/ubuntu/.jetstreamer-private/qualification-248-reboot-20261117-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon248-controls2402-v1/preflight-248-target1.json --cohort-manifest-fingerprint=sha256:0d1fff23b95c5b9c462af81387414c13c10a1fdce6699d5a4bd204bcf7719bbf --snapshot-archive=/var/lib/jetstreamer/horizon248-bootstrap-copy2454-work-v1/projection/bootstrap/snapshot-107135393-BvNzVFUVa9kQwGJQxKFyDVPcBd8yVRbVDaN8YLr28i95.tar.zst",
        manifest: "/var/lib/jetstreamer/horizon248-controls2402-v1/preflight-248-target1.json",
        manifest_sha: "81d2f1bed8dd60b2553844c213ce2733c90f3ace94cb5d39a279c2b234178dc0",
        terminal_slot: 107567999,
    },
    Profile {
        epoch: 249,
        unit: "horizon-qualify-249-reboot-20261117-v1.service",
        iid: "dbf4a4d19de84f31b3897da87622156e",
        pid: 86201,
        node: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node",
        node_sha: "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
        command: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 249 /home/ubuntu/.jetstreamer-private/qualification-249-reboot-20261117-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon249-controls2418-v1/preflight-249-target1.json --cohort-manifest-fingerprint=sha256:1eba23638b04526c0ee06e2ddda702eb21c3e9bedb7010729d430b1443d080bc --snapshot-archive=/var/lib/jetstreamer/horizon-contiguous-249-251-current-46b4b4a-v1/snapshot-107567592-DBPics19TxLy8wawfQYvS65d72vKvFGLCW9HZv5q6GeH.tar.zst",
        manifest: "/var/lib/jetstreamer/horizon249-controls2418-v1/preflight-249-target1.json",
        manifest_sha: "7245a95843d5866456f7c9b012e72b60ae8bfa7a7e68be61c1a1bbe29b30dc1b",
        terminal_slot: 107999999,
    },
    Profile {
        epoch: 250,
        unit: "horizon-qualify-250-reboot-20261117-v1.service",
        iid: "a59fe93cc1d443abbb33317600227600",
        pid: 473260,
        node: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node",
        node_sha: "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
        command: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 250 /home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon250-controls2402-v1/preflight-250-target1.json --cohort-manifest-fingerprint=sha256:7517bfa7560d6d353cd7c683b1491195ccb5fec689a57e2e1a6bb099fe3e7bc4 --snapshot-archive=/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/input/snapshot-107999217-4GDh8KkBUc2Yj6Xa3qLWGVkNSm44i4XSk8PXWSN2s274.tar.zst",
        manifest: "/var/lib/jetstreamer/horizon250-controls2402-v1/preflight-250-target1.json",
        manifest_sha: "fa914595e610da263d2d7eb22a4dc2a23eb7ad95665cc277459877bed7215cce",
        terminal_slot: 108431999,
    },
    Profile {
        epoch: 251,
        unit: "horizon-qualify-251-replacement-20261118-v1.service",
        iid: "cd2477bfec7f4e498545762c633e7bb0",
        pid: 760779,
        node: "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/jetstreamer-node",
        node_sha: "02f42f2988dd31437e2c874414f247667200663c874042783406b5517b0d519b",
        command: "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/jetstreamer-node 251 /home/ubuntu/.jetstreamer-private/qualification-251-replacement-20261118-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon251-single-epoch-manifest-20261118-v1/preflight-251-single-epoch.json --cohort-manifest-fingerprint=sha256:e214b640c55cc6ec0e431c66f9cbd0076c4620578c2dea1e6c2324e7f616789e --snapshot-archive=/var/lib/jetstreamer/horizon251-native-input-20261118-v1/snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst",
        manifest: "/var/lib/jetstreamer/horizon251-single-epoch-manifest-20261118-v1/preflight-251-single-epoch.json",
        manifest_sha: "e40e8d0341440d29cff7cd35e79e5f713d7908ce42f3a1c4995e1b2924551f14",
        terminal_slot: 108863999,
    },
];

fn registered(epoch: u64) -> Result<Profile> {
    PROFILES
        .iter()
        .copied()
        .find(|p| p.epoch == epoch)
        .context("unregistered original finalization epoch")
}
fn false_fields(value: &Value, keys: &[&str]) -> Result<()> {
    for k in keys {
        ensure!(value[*k] == false, "finalization cannot authorize {k}");
    }
    Ok(())
}
fn owner(p: Profile, u: &Value) -> Result<()> {
    ensure!(
        u["Id"] == p.unit
            && u["InvocationID"] == p.iid
            && text(u, "MainPID")?.parse::<u64>()? == p.pid
            && u["LoadState"] == "loaded"
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["NRestarts"] == "0"
            && u["Result"] == "success"
            && periodic::stable_command(text(u, "ExecStart")?)?
                == format!(
                    "{{ path={} ; argv[]={} ; ignore_errors=no",
                    p.node, p.command
                ),
        "finalization original owner changed"
    );
    Ok(())
}
fn event(p: Profile, e: &Value, sample: u64, boot: &str, marker: &str) -> Result<u64> {
    ensure!(
        e["_SYSTEMD_UNIT"] == p.unit
            && e["_SYSTEMD_INVOCATION_ID"] == p.iid
            && text(e, "_PID")?.parse::<u64>()? == p.pid
            && e["_UID"] == "1000"
            && e["_EXE"] == p.node
            && e["_CMDLINE"] == p.command
            && e["_BOOT_ID"] == boot.replace('-', "")
            && text(e, "MESSAGE")?.ends_with(marker),
        "finalization journal binding changed"
    );
    let time = text(e, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
    ensure!(
        time > 0
            && time
                <= sample
                    .checked_mul(1_000_000)
                    .context("finalization time overflow")?,
        "finalization future/zero event"
    );
    Ok(time)
}
fn memory_cap(epoch: u64) -> u64 {
    if epoch == 251 {
        128_000_000_000
    } else {
        251_041_591_296
    }
}
fn row(entry: &Value, fleet: &Value, rows: &[capacity::Reservation], boot: &str) -> Result<()> {
    let p = registered(num(entry, "epoch")?)?;
    let r = rows
        .iter()
        .find(|r| r.unit == p.unit && r.invocation_id == p.iid)
        .context("unbooked original finalization owner")?;
    ensure!(
        r.release.is_none()
            && r.maximum_memory_bytes == memory_cap(p.epoch)
            && r.remaining_disk_growth_bytes >= 506_191_984_640,
        "finalization cannot release or reduce original memory/disk"
    );
    ensure!(
        entry["phase"] == "producer-finalization"
            && entry["live"] == true
            && entry["expected_invocation_id"] == p.iid
            && entry["sampled_at_utc"] == fleet["sampled_at_utc"]
            && entry["unit"] == fleet["unit_census"][p.unit],
        "finalization fleet row binding changed"
    );
    false_fields(
        entry,
        &[
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "grants_launch_or_publication_authority",
        ],
    )?;
    owner(p, &entry["unit"])?;
    let proof = &entry["finalization_evidence"];
    ensure!(
        proof["schema"] == "jetstreamer-original-singleton-finalization-events-v1"
            && proof["epoch"] == p.epoch
            && proof["unit"] == p.unit
            && proof["invocation_id"] == p.iid
            && proof["node_sha256"] == p.node_sha
            && proof["manifest_sha256"] == p.manifest_sha
            && proof["terminal_slot"] == p.terminal_slot
            && proof["replay_terminal_observed"] == true,
        "unregistered finalization evidence"
    );
    false_fields(
        proof,
        &[
            "archive_close_observed",
            "producer_terminal_proven",
            "resource_release_authorized",
            "independent_full_verification_passed",
            "publication_authorized",
            "replay_launch_authorized",
            "r2_mutations",
        ],
    )?;
    let sample = num(proof, "sampled_unix_seconds")?;
    fresh(sample, num(fleet, "recorded_unix_seconds")?, 300)?;
    let events = proof["events"].as_array().context("finalization events")?;
    ensure!(events.len() == 2, "finalization event count");
    let a = event(
        p,
        &events[0],
        sample,
        boot,
        &format!("jetstreamer::firehose] processed slot {}", p.terminal_slot),
    )?;
    let b = event(
        p,
        &events[1],
        sample,
        boot,
        "jetstreamer::firehose] 🚒 firehose finished successfully.",
    )?;
    ensure!(a < b, "finalization events out of order");
    Ok(())
}
fn diagnostic(d: &Value, entry: &Value, boot: &str) -> Result<()> {
    let p = registered(num(entry, "epoch")?)?;
    ensure!(
        d["status"] == "observed"
            && d["error"].is_null()
            && d["range"] == format!("{}-{}", p.epoch, p.epoch)
            && d["producer_unit"] == p.unit
            && d["expected_producer_invocation_id"] == p.iid
            && d["post_replay_resource_only"] == true,
        "unregistered finalization diagnostic"
    );
    let denied = [
        "entry_replay",
        "ordinary_replay_claim",
        "publication_authorized",
        "r2_mutations",
        "resource_release_authorized",
        "terminal_completion_proven",
    ];
    false_fields(d, &denied)?;
    let o = &d["observation"];
    false_fields(o, &denied)?;
    ensure!(
        o["range"] == d["range"]
            && o["invocation_binding_stable"] == true
            && o["post_replay_finalization"] == true
            && o["resource_only"] == true
            && o["useful_work"]["entry_progress_observed"] == false
            && o["useful_work"]["sufficient_for_rates"] == false,
        "finalization telemetry authority changed"
    );
    for key in [
        "producer_before",
        "producer_after",
        "controller_before",
        "controller_after",
    ] {
        let v = &o[key];
        ensure!(
            v["unit"] == p.unit
                && v["invocation_id"] == p.iid
                && v["main_pid"] == p.pid
                && v["load_state"] == "loaded"
                && v["active_state"] == "active"
                && v["sub_state"] == "running"
                && v["restarts"] == 0
                && v["result"] == "success"
                && v["control_group"] == format!("/system.slice/{}", p.unit)
                && v["cgroup"]["gauges"]["memory.max"] == memory_cap(p.epoch)
                && v["cgroup"]["gauges"]["memory.swap.max"] == 0,
            "finalization telemetry owner/cap differs"
        );
    }
    let phase = &o["phase_evidence"];
    ensure!(
        phase["epoch"] == p.epoch
            && phase["phase"] == "producer-finalization"
            && phase["sampled_unix_seconds"]
                == entry["finalization_evidence"]["sampled_unix_seconds"],
        "finalization phase clock differs"
    );
    false_fields(
        phase,
        &[
            "ordinary_replay_claim",
            "publication_authorized",
            "resource_release_authorized",
            "terminal_completion_proven",
        ],
    )?;
    event(
        p,
        &phase["event"],
        num(phase, "sampled_unix_seconds")?,
        boot,
        "jetstreamer::firehose] 🚒 firehose finished successfully.",
    )?;
    ensure!(
        phase["event"] == entry["finalization_evidence"]["events"][1],
        "finalization EOF differs between consumers"
    );
    Ok(())
}
pub(super) fn validate(
    fleet: &Value,
    observer: &Value,
    rows: &[capacity::Reservation],
    boot: &str,
) -> Result<()> {
    validate_roster(fleet, observer, rows, boot, false)
}
pub(super) fn validate_roster(
    fleet: &Value,
    observer: &Value,
    rows: &[capacity::Reservation],
    boot: &str,
    full211: bool,
) -> Result<()> {
    ensure!(
        (full211 || fleet["diagnostics"] == json!([]))
            && fleet["auxiliary_diagnostics"] == json!([]),
        "unsupported fleet diagnostic owner"
    );
    native266_peer::validate(fleet, observer, rows, boot)?;
    full265::validate(fleet, observer, rows, boot)?;
    delivery247::validate_roster(fleet, rows)?;
    // Admission independently authenticates both exact native terminal peers.
    let pipelines: Vec<_> = fleet["pipelines"]
        .as_array()
        .context("pipeline census")?
        .iter()
        .filter(|e| !peers::selected(e) && !delivery247::selected(e) && !full265::pipeline(e) && !native266_peer::pipeline(e))
        .collect();
    let observed_diagnostics = observer["diagnostic_replays"]
        .as_array()
        .context("diagnostic observation census")?;
    let mut diagnostics = Vec::new();
    let mut native265_diagnostic_seen = false;
    for d in observed_diagnostics {
        if (full211 && full211_peer::observed(d)) || full265::diagnostic(d) || native266_peer::diagnostic(d) {
            // Already authenticated by the complete full265 cross-census validator.
            continue;
        }
        if peers::terminal_diagnostic(d)? {
            ensure!(
                !native265_diagnostic_seen,
                "duplicate native265 terminal diagnostic"
            );
            native265_diagnostic_seen = true;
        } else {
            diagnostics.push(d);
        }
    }
    ensure!(
        pipelines.len() == diagnostics.len() && pipelines.len() <= 4,
        "missing/unregistered finalization owner"
    );
    let mut seen = BTreeSet::new();
    for &entry in &pipelines {
        row(entry, fleet, rows, boot)?;
        let epoch = num(entry, "epoch")?;
        ensure!(seen.insert(epoch), "duplicate finalization owner");
        let matching: Vec<_> = diagnostics
            .iter()
            .filter(|d| d["range"] == format!("{epoch}-{epoch}"))
            .collect();
        ensure!(matching.len() == 1, "finalization diagnostic coverage");
        diagnostic(matching[0], entry, boot)?;
        let active = fleet["active"].as_array().context("active census")?;
        ensure!(
            active.iter().filter(|a| *a == entry).count() == 1,
            "finalization not represented exactly once in active census"
        );
    }
    for a in fleet["active"].as_array().context("active census")? {
        if (full211 && full211_peer::active(a)) || a["epoch"] == 265 || native266_peer::pipeline(a) {
            // Ordinary or exact post-EOF form validated above; no private promotion.
            continue;
        }
        if delivery247::selected(a) {
            continue;
        }
        if a["phase"] == "producer-finalization" {
            ensure!(
                pipelines.iter().filter(|p| **p == a).count() == 1,
                "unbound active finalization"
            );
        } else {
            ensure!(
                !seen.contains(&num(a, "epoch")?),
                "finalization also counted as ordinary replay"
            );
            ensure!(
                a["phase"] == "replay" && a["producer"].is_object() && a["controller"].is_object(),
                "unsupported active owner shape"
            );
        }
    }
    Ok(())
}
pub(super) fn verify_inputs(fleet: &Value) -> Result<()> {
    full265::verify_inputs(fleet)?;
    for e in fleet["pipelines"].as_array().context("pipeline census")? {
        if delivery247::selected(e) {
            delivery247::verify_inputs(e)?;
            continue;
        }
        if peers::selected(e) || full265::pipeline(e) || native266_peer::pipeline(e) {
            continue;
        }
        let p = registered(num(e, "epoch")?)?;
        Bound::new(p.node, p.node_sha).artifact()?;
        Bound::new(p.manifest, p.manifest_sha).artifact()?;
        let mapped = PathBuf::from(format!("/proc/{}/exe", p.pid));
        ensure!(
            fs::read_link(&mapped)? == Path::new(p.node)
                && metadata_identity(&fs::metadata(&mapped)?) == identity(Path::new(p.node))?,
            "finalization mapped image differs"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_for(p: Profile) -> (Value, Value, Vec<capacity::Reservation>) {
        let boot = "b".repeat(32);
        let event = |msg: String, time: u64| json!({"MESSAGE":msg,"_SYSTEMD_UNIT":p.unit,"_SYSTEMD_INVOCATION_ID":p.iid,"_PID":p.pid.to_string(),"_UID":"1000","_EXE":p.node,"_CMDLINE":p.command,"_BOOT_ID":boot,"__REALTIME_TIMESTAMP":time.to_string()});
        let eof = event(
            "jetstreamer::firehose] 🚒 firehose finished successfully.".into(),
            99_000_000,
        );
        let proof = json!({"schema":"jetstreamer-original-singleton-finalization-events-v1","epoch":p.epoch,"unit":p.unit,"invocation_id":p.iid,"node_sha256":p.node_sha,"manifest_sha256":p.manifest_sha,"terminal_slot":p.terminal_slot,"replay_terminal_observed":true,"archive_close_observed":false,"producer_terminal_proven":false,"resource_release_authorized":false,"independent_full_verification_passed":false,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false,"sampled_unix_seconds":100,"events":[event(format!("jetstreamer::firehose] processed slot {}",p.terminal_slot),98_000_000),eof]});
        let unit = json!({"Id":p.unit,"InvocationID":p.iid,"MainPID":p.pid.to_string(),"LoadState":"loaded","ActiveState":"active","SubState":"running","NRestarts":"0","Result":"success","ExecStart":format!("{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",p.node,p.command)});
        let entry = json!({"epoch":p.epoch,"phase":"producer-finalization","live":true,"expected_invocation_id":p.iid,"sampled_at_utc":"sample","unit":unit,"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"grants_launch_or_publication_authority":false,"finalization_evidence":proof});
        let observed = json!({"unit":p.unit,"invocation_id":p.iid,"main_pid":p.pid,"load_state":"loaded","active_state":"active","sub_state":"running","restarts":0,"result":"success","control_group":format!("/system.slice/{}",p.unit),"cgroup":{"gauges":{"memory.max":memory_cap(p.epoch),"memory.swap.max":0}}});
        let phase = json!({"epoch":p.epoch,"phase":"producer-finalization","sampled_unix_seconds":100,"event":eof,"ordinary_replay_claim":false,"publication_authorized":false,"resource_release_authorized":false,"terminal_completion_proven":false});
        let o = json!({"range":format!("{}-{}",p.epoch,p.epoch),"entry_replay":false,"ordinary_replay_claim":false,"publication_authorized":false,"r2_mutations":false,"resource_release_authorized":false,"terminal_completion_proven":false,"invocation_binding_stable":true,"post_replay_finalization":true,"resource_only":true,"useful_work":{"entry_progress_observed":false,"sufficient_for_rates":false},"producer_before":observed,"producer_after":observed,"controller_before":observed,"controller_after":observed,"phase_evidence":phase});
        let diagnostic = json!({"range":format!("{}-{}",p.epoch,p.epoch),"status":"observed","error":null,"producer_unit":p.unit,"expected_producer_invocation_id":p.iid,"post_replay_resource_only":true,"entry_replay":false,"ordinary_replay_claim":false,"publication_authorized":false,"r2_mutations":false,"resource_release_authorized":false,"terminal_completion_proven":false,"observation":o});
        let fleet = json!({"pipelines":[entry],"diagnostics":[],"auxiliary_diagnostics":[],"active":[entry],"unit_census":{(p.unit):unit},"sampled_at_utc":"sample","recorded_unix_seconds":101});
        let observer = json!({"diagnostic_replays":[diagnostic]});
        let rows = vec![capacity::Reservation {
            unit: p.unit.into(),
            invocation_id: p.iid.into(),
            maximum_memory_bytes: memory_cap(p.epoch),
            remaining_disk_growth_bytes: 506_191_984_640,
            minimum_free_bytes: 2_666_773_615_088,
            source: Bound::new("/unused", "a".repeat(64)),
            release: None,
        }];
        (fleet, observer, rows)
    }
    #[test]
    fn all_original_profiles_keep_their_actual_hard_caps() {
        for p in PROFILES {
            let (fleet, observer, rows) = fixture_for(p);
            validate(&fleet, &observer, &rows, &"b".repeat(32)).unwrap();
            assert_eq!(
                rows[0].maximum_memory_bytes,
                if p.epoch == 251 {
                    128_000_000_000
                } else {
                    251_041_591_296
                }
            );
        }
    }
    #[test]
    fn original_finalization_retains_owner_caps_and_does_not_count_as_replay_or_release() {
        let (fleet, observer, rows) = fixture_for(PROFILES[1]);
        validate(&fleet, &observer, &rows, &"b".repeat(32)).unwrap();
        for pointer in [
            "/pipelines/0/finalization_evidence/producer_terminal_proven",
            "/pipelines/0/finalization_evidence/resource_release_authorized",
            "/pipelines/0/finalization_evidence/publication_authorized",
            "/pipelines/0/ordinary_replay_claim",
        ] {
            let mut bad = fleet.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(true);
            assert!(
                validate(&bad, &observer, &rows, &"b".repeat(32)).is_err(),
                "{pointer}"
            );
        }
        let mut bad = rows.clone();
        bad[0].maximum_memory_bytes -= 1;
        assert!(validate(&fleet, &observer, &bad, &"b".repeat(32)).is_err());
        bad = rows.clone();
        bad[0].release = Some(Bound::new("/release", "a".repeat(64)));
        assert!(validate(&fleet, &observer, &bad, &"b".repeat(32)).is_err());
        let mut bad = observer.clone();
        bad["diagnostic_replays"][0]["observation"]["producer_after"]["invocation_id"] =
            json!("a".repeat(32));
        assert!(validate(&fleet, &bad, &rows, &"b".repeat(32)).is_err());
        let mut bad = fleet.clone();
        bad["active"] = json!([]);
        assert!(validate(&bad, &observer, &rows, &"b".repeat(32)).is_err());
        let mut bad = fleet.clone();
        bad["pipelines"][0]["epoch"] = json!(252);
        assert!(validate(&bad, &observer, &rows, &"b".repeat(32)).is_err());
        assert!(validate(&fleet, &observer, &rows, &"c".repeat(32)).is_err());
    }
    #[test]
    fn unknown_or_unbound_pipeline_and_diagnostic_shapes_fail_closed() {
        let (mut fleet, mut observer, rows) = fixture_for(PROFILES[1]);
        fleet["pipelines"] = json!([]);
        assert!(validate(&fleet, &observer, &rows, &"b".repeat(32)).is_err());
        observer["diagnostic_replays"] = json!([]);
        assert!(validate(&fleet, &observer, &rows, &"b".repeat(32)).is_err());
        fleet["active"] = json!([]);
        validate(&fleet, &observer, &rows, &"b".repeat(32)).unwrap();
        fleet["diagnostics"] = json!([{}]);
        assert!(validate(&fleet, &observer, &rows, &"b".repeat(32)).is_err());
    }
    #[test]
    fn retained_native265_resource_diagnostic_is_exact_and_unique() {
        let (fleet, mut observer, rows) = fixture_for(PROFILES[1]);
        let terminal: Value = serde_json::from_str(include_str!(
            "fixtures/retained-native265-diagnostic-20261119.json"
        ))
        .unwrap();
        observer["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(terminal.clone());
        validate(&fleet, &observer, &rows, &"b".repeat(32)).unwrap();
        observer["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(terminal);
        assert!(validate(&fleet, &observer, &rows, &"b".repeat(32)).is_err());
        observer["diagnostic_replays"].as_array_mut().unwrap().pop();
        observer["diagnostic_replays"][1]["expected_producer_invocation_id"] =
            json!("f".repeat(32));
        assert!(validate(&fleet, &observer, &rows, &"b".repeat(32)).is_err());
    }
}
