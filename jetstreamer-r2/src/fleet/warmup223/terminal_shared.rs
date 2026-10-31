const FLAGS: [&str; 14] = [
    "canonical_prefix_qualified",
    "native_restart_qualified",
    "suffix_qualified",
    "assembly_qualified",
    "full_epoch_qualified",
    "full_plugin_qualified",
    "canonical_sidecar_authorized",
    "publication_authorized",
    "remote_mutations",
    "r2_mutations",
    "runtime_promotion_authorized",
    "ordinary_replay_authorized",
    "replay_launch_authorized",
    "full_cold_epoch_peak_qualified",
];
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn bound(v: &Value) -> Result<BoundFile> {
    Ok(serde_json::from_value(v.clone())?)
}
fn immutable(b: &BoundFile) -> Result<Value> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0,
        "warmup terminal evidence is not immutable"
    );
    bound_json(b)
}
fn claim(origin: &BoundFile, r: &Value) -> Result<PipelineClaim> {
    ensure!(
        origin.path == Path::new(ORIGIN),
        "warmup terminal origin path differs"
    );
    let c = PipelineClaim {
        epoch: 223,
        phase: "private-warmup-reproduction".into(),
        unit: c::UNIT.into(),
        invocation_id: r["invocation_id"]
            .as_str()
            .context("warmup original IID")?
            .into(),
        expected_exec_start: r["expected_exec_start"]
            .as_str()
            .context("warmup original command")?
            .into(),
        evidence: vec![BoundFile {
            path: origin.path.clone(),
            sha256: origin.sha256.clone(),
        }],
    };
    c::validate(&c)?;
    Ok(c)
}
pub(super) fn terminal_shape(u: &Value, iid: &str, command: &str) -> Result<bool> {
    ensure!(
        u["Id"] == c::UNIT
            && u["LoadState"] == "loaded"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && (u["InvocationID"] == "" || u["InvocationID"] == iid)
            && ((u["ActiveState"] == "inactive" && u["SubState"] == "dead")
                || (u["ActiveState"] == "failed" && u["SubState"] == "failed"))
            && u["ExecStart"]
                .as_str()
                .is_some_and(|s| pipeline_status::same_exec_start(command, s)),
        "warmup owner is live, replaced or ambiguous"
    );
    let status = u["ExecMainStatus"]
        .as_str()
        .context("warmup terminal exit status")?
        .parse::<u32>()?;
    let result = u["Result"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("warmup terminal result")?;
    let clean = result == "success" && status == 0;
    Ok(clean)
}
fn event_clock(v: &Value) -> Result<u64> {
    Ok(v["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("warmup journal clock")?
        .parse()?)
}
fn manager(v: &Value) -> bool {
    v["_PID"] == "1" && v["_UID"] == "0" && v["UNIT"] == c::UNIT
}
fn completed_marker(text: &str) -> bool {
    text.split_once(" jetstreamer_node] private epoch223 warmup complete slot=")
        .is_some_and(|(p, t)| {
            p.starts_with('[')
                && p.trim_end().ends_with(" INFO")
                && t.trim() == "96335554 complete=true"
        })
}
fn journal_summary(rows: &[Value], iid: &str, clean: bool, result: &str) -> Result<Value> {
    ensure!(
        !rows.is_empty() && rows.len() <= 65536,
        "warmup terminal journal bounds"
    );
    let own = rows
        .iter()
        .filter(|r| manager(r) && r["INVOCATION_ID"] == iid)
        .collect::<Vec<_>>();
    let starts = own
        .iter()
        .copied()
        .filter(|r| {
            r["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
                && r["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("Started {} -", c::UNIT)))
        })
        .collect::<Vec<_>>();
    ensure!(starts.len() == 1, "warmup requires one exact PID1 start");
    let start = event_clock(starts[0])?;
    let ends = own
        .iter()
        .copied()
        .filter(|r| {
            if clean {
                r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                    && r["MESSAGE"] == format!("{}: Deactivated successfully.", c::UNIT)
            } else {
                r["MESSAGE"] == format!("{}: Failed with result '{result}'.", c::UNIT)
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        ends.len() == 1,
        "warmup requires one exact PID1 terminal event"
    );
    let end = event_clock(ends[0])?;
    ensure!(end >= start, "warmup terminal precedes invocation start");
    for r in rows.iter().filter(|r| manager(r)) {
        let time = event_clock(r)?;
        ensure!(
            time < start || r["INVOCATION_ID"] == iid,
            "warmup has a later replacement invocation"
        );
        if clean && r["INVOCATION_ID"] == iid {
            ensure!(
                !r["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("{}: Failed", c::UNIT)))
                    && !r.get("EXIT_STATUS").is_some_and(|v| v != "0"),
                "warmup clean result has manager failure evidence"
            );
        }
    }
    let markers = rows
        .iter()
        .filter(|r| {
            r["_SYSTEMD_UNIT"] == c::UNIT
                && r["_SYSTEMD_INVOCATION_ID"] == iid
                && r["_UID"] == "1000"
                && r["MESSAGE"].as_str().is_some_and(completed_marker)
        })
        .collect::<Vec<_>>();
    ensure!(
        markers.len() <= 1,
        "duplicate bounded warmup completion marker"
    );
    for r in &markers {
        let time = event_clock(r)?;
        ensure!(
            time >= start && time <= end,
            "warmup marker outside its invocation"
        );
    }
    let boot = starts[0]["_BOOT_ID"]
        .as_str()
        .context("warmup start boot ID")?;
    ensure!(
        !boot.is_empty()
            && ends[0]["_BOOT_ID"] == boot
            && markers.iter().all(|r| r["_BOOT_ID"] == boot),
        "warmup journal crosses boot identity"
    );
    Ok(
        json!({"started_unix_microseconds":start,"terminal_unix_microseconds":end,"bounded_complete_marker":markers.len()==1,"manager_start":starts[0],"manager_terminal":ends[0]}),
    )
}
fn result_shape(r: &Value, iid: &str, kind: &str) -> Result<bool> {
    if REQUIRE_COOPERATIVE {
        ensure!(
            r["target_stop_protocol"] == "cooperative-resume-only",
            "v2 result used the wrong drain protocol"
        );
    }
    ensure!(
        r["schema"] == "jetstreamer-private-epoch223-v1620-warmup-resource-v1"
            && r["epoch"] == 223
            && r["unit"] == c::UNIT
            && r["invocation_id"] == iid
            && r["runner_sha256"] == RUNNER_SHA
            && r["plan"] == json!({"path":PLAN,"sha256":PLAN_SHA})
            && r["node_sha256"]
                == "99f643ff0dbbcd37d1fbc524a1c1088d7273c7fc91330df059d30d51b8b0fcd4"
            && r["worker_sha256"]
                == "52d6c86a8103b8965ca68ead96af471a7899a0a0e6e69c48989b39fd5d922f0c"
            && r["snapshot_sha256"]
                == "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665"
            && r["target_slot"] == 96_335_554u64
            && r["elapsed_millis"].is_u64(),
        "warmup resource/failure output has wrong invocation or inputs"
    );
    let authority = r["authority"]
        .as_object()
        .context("warmup diagnostic authority missing")?;
    ensure!(
        authority.len() == 7
            && [
                "ordinary_replay_authorized",
                "full_cold_epoch_peak_qualified",
                "publication_authorized",
                "runtime_promotion_authorized",
                "canonical_sidecar_authorized",
                "remote_mutations",
                "r2_mutations"
            ]
            .iter()
            .all(|k| authority.get(*k) == Some(&json!(false))),
        "warmup output grants archive authority"
    );
    let passed = r["success"]
        .as_bool()
        .context("warmup result success missing")?;
    ensure!(
        (kind == "resource" && passed) || (kind == "failure" && !passed),
        "warmup output filename/result disagree"
    );
    if passed {
        ensure!(
            r["target_reached"] == true
                && r["observed_slot"] == 96_335_554u64
                && r["external_signal"] == 0
                && r["error"].is_null()
                && matches!(r["child_return_code"].as_u64(), Some(0 | 1)),
            "warmup success lacks completed sixteen-slot capture/drainage"
        );
    }
    Ok(passed)
}
fn preserve(path: &Path, bytes: &[u8]) -> Result<BoundFile> {
    if path.try_exists()? {
        ensure!(
            read_stable_bounded(path, 32 << 20, "preserved warmup evidence")? == bytes,
            "warmup terminal evidence retry differs"
        );
    } else {
        let parent = validate_output_destination(path)?;
        let mut t = tempfile::NamedTempFile::new_in(parent)?;
        use std::os::unix::fs::PermissionsExt;
        t.as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        t.write_all(bytes)?;
        t.as_file().sync_all()?;
        t.persist_noclobber(path)
            .map_err(|e| anyhow!("warmup terminal preserve collision:{e}"))?;
        File::open(parent)?.sync_all()?;
    }
    Ok(serde_json::from_value(private157::file_binding(path)?)?)
}
fn output_binding(root: &Path, iid: &str, clean: bool) -> Result<Value> {
    let mut found = Vec::new();
    for kind in ["resource", "failure"] {
        let source = Path::new(c::ROOT).join(format!("receipts/{kind}.json"));
        match fs::symlink_metadata(&source) {
            Ok(m) => {
                ensure!(
                    m.is_file() && m.uid() == 1000 && m.nlink() == 1 && m.mode() & 0o077 == 0,
                    "warmup result owner/privacy differs"
                );
                let bytes = read_stable_bounded(&source, 16 << 20, "warmup diagnostic result")?;
                let r: Value = serde_json::from_slice(&bytes)?;
                let passed = result_shape(&r, iid, kind)?;
                let saved = preserve(&root.join(format!("{kind}.json")), &bytes)?;
                found.push(json!({"present":true,"kind":kind,"source":{"path":source,"sha256":saved.sha256},"preserved":private157::binding(&saved),"passed":passed}));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    ensure!(
        found.len() <= 1,
        "ambiguous warmup resource and failure outputs"
    );
    if let Some(v) = found.pop() {
        ensure!(
            !clean || v["passed"] == true,
            "clean manager lacks successful warmup output"
        );
        Ok(v)
    } else {
        ensure!(!clean, "clean manager has no warmup result");
        Ok(json!({"present":false,"absence_confirmed_after_terminal":true}))
    }
}
fn preserved_result(v: &Value, iid: &str, clean: bool) -> Result<bool> {
    if v["present"] == false {
        ensure!(
            !clean && v["absence_confirmed_after_terminal"] == true,
            "warmup result absence cannot prove success"
        );
        return Ok(false);
    }
    ensure!(v["present"] == true, "warmup output presence missing");
    let kind = v["kind"]
        .as_str()
        .filter(|k| matches!(*k, "resource" | "failure"))
        .context("warmup output kind")?;
    let source = bound(&v["source"])?;
    let saved = bound(&v["preserved"])?;
    ensure!(
        source.path == Path::new(c::ROOT).join(format!("receipts/{kind}.json"))
            && source.sha256 == saved.sha256
            && saved
                .path
                .file_name()
                .is_some_and(|n| n == format!("{kind}.json").as_str()),
        "warmup preserved output binding differs"
    );
    let passed = result_shape(&immutable(&saved)?, iid, kind)?;
    ensure!(
        v["passed"] == passed && (!clean || passed),
        "warmup preserved outcome differs"
    );
    Ok(passed)
}
fn startup_history() -> Result<Value> {
    let mut bindings = serde_json::Map::new();
    for name in ["failed-attempt.json", "manager.txt", "journal.json"] {
        bindings.insert(
            name.into(),
            private157::file_binding(&Path::new(STARTUP).join(name))?,
        );
    }
    let r = immutable(&bound(&bindings["failed-attempt.json"])?)?;
    ensure!(
        r["schema"] == "jetstreamer-operator-startup-failure-observation-v1"
            && r["epoch"] == 223
            && r["unit"] == STARTUP_UNIT
            && r["invocation_id"] == "4ba44fd7e1b44bdf921790d20f81fedf"
            && r["entry_replay"] == false
            && r["qualification_authorized"] == false
            && r["publication_authorized"] == false
            && r["remote_mutations"] == false
            && r["r2_mutations"] == false,
        "unregistered startup failure history differs"
    );
    if REQUIRE_COOPERATIVE {
        let b = BoundFile {
            path: "/var/lib/jetstreamer/horizon-warmup223-native20-terminal-13a5-v1/proof.json"
                .into(),
            sha256: "15f180fb61563ce762a99924a53a957e12857e90dbd64500d80bf2c64072590e".into(),
        };
        let old = immutable(&b)?;
        let identity = super::terminal::validate(&old)?;
        ensure!(
            identity.0 == STARTUP_UNIT
                && identity.1 == "13a5f755a196442e991c6930b410c04f"
                && old["bounded_warmup_complete"] == false,
            "v2 lost failed v1 warmup history"
        );
        bindings.insert(
            "previous-warmup-terminal-proof".into(),
            private157::binding(&b),
        );
    }
    Ok(Value::Object(bindings))
}
fn journal_rows(b: &BoundFile) -> Result<Vec<Value>> {
    let bytes = read_stable_bounded(&b.path, 32 << 20, "warmup preserved journal")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "warmup journal hash differs"
    );
    Ok(serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
pub(super) fn validate(proof: &Value) -> Result<(String, String)> {
    ensure!(
        proof["schema"] == SCHEMA
            && proof["epoch"] == 223
            && proof["unit"] == c::UNIT
            && proof["entry_replay"] == true
            && proof["resource_samples_taken"] == 0
            && proof["repair_closed"] == false,
        "warmup terminal profile differs"
    );
    for f in FLAGS {
        ensure!(
            proof[f] == false,
            "bounded warmup terminal grants forbidden authority:{f}"
        );
    }
    let spec: Spec = serde_json::from_value(immutable(&bound(&proof["capture_spec"])?)?)?;
    spec_scope(&spec)?;
    ensure!(
        proof["running_origin"] == private157::binding(&spec.running_origin)
            && proof["observer"] == private157::binding(&spec.observer)
            && proof["fleet"] == private157::binding(&spec.fleet)
            && proof["journal"]["path"].as_str()
                == spec.output.parent().unwrap().join("journal.json").to_str(),
        "warmup terminal capture bindings differ"
    );
    if proof["output"]["present"] == true {
        let saved = bound(&proof["output"]["preserved"])?;
        ensure!(
            saved.path.parent() == spec.output.parent(),
            "warmup output escaped terminal preservation directory"
        );
    }
    let origin = bound(&proof["running_origin"])?;
    let r = immutable(&origin)?;
    let claim = claim(&origin, &r)?;
    ensure!(
        proof["invocation_id"] == claim.invocation_id,
        "warmup terminal original IID differs"
    );
    let clean = terminal_shape(
        &proof["terminal_manager"],
        &claim.invocation_id,
        &claim.expected_exec_start,
    )?;
    let rows = journal_rows(&bound(&proof["journal"])?)?;
    let summary = journal_summary(
        &rows,
        &claim.invocation_id,
        clean,
        proof["terminal_manager"]["Result"]
            .as_str()
            .context("warmup terminal result")?,
    )?;
    ensure!(
        proof["journal_summary"] == summary,
        "warmup preserved manager summary differs"
    );
    let passed = preserved_result(&proof["output"], &claim.invocation_id, clean)?;
    let complete = clean && passed && summary["bounded_complete_marker"] == true;
    ensure!(
        !clean || complete,
        "clean warmup lacks verified complete-slot marker"
    );
    ensure!(
        proof["bounded_warmup_complete"] == complete
            && proof["terminal_outcome"]
                == if complete {
                    "bounded-warmup-complete"
                } else {
                    "failed"
                },
        "warmup terminal outcome differs"
    );
    ensure!(
        proof["startup_failure_history"] == startup_history()?,
        "warmup discarded or changed unregistered failed startup history"
    );
    Ok((c::UNIT.into(), claim.invocation_id))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    running_origin: BoundFile,
    observer: BoundFile,
    fleet: BoundFile,
    output: PathBuf,
}
fn spec_scope(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == SPEC_SCHEMA
            && s.output.file_name().is_some_and(|n| n == "proof.json")
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-warmup223-native20-terminal-")),
        "warmup terminal output scope differs"
    );
    Ok(())
}
pub(super) fn capture() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-warmup223-terminal")?;
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == SPEC_SCHEMA
            && s.output.file_name().is_some_and(|n| n == "proof.json")
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-warmup223-native20-terminal-")),
        "warmup terminal output scope differs"
    );
    if s.output.try_exists()? {
        let old = immutable(&bound(&private157::file_binding(&s.output)?)?)?;
        ensure!(
            old["capture_spec"] == private157::binding(&binding)
                && old["capture_helper_sha256"] == self_sha,
            "warmup terminal retry differs"
        );
        validate(&old)?;
        return Ok(());
    }
    let origin = immutable(&s.running_origin)?;
    let owner = claim(&s.running_origin, &origin)?;
    let f = bound_json(&s.fleet)?;
    let o = bound_json(&s.observer)?;
    ensure!(
        f["schema"] == SCHEMA_FLEET
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"],
        "warmup terminal observer/fleet differs"
    );
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"].as_str().context("warmup fleet plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("warmup fleet plan SHA")?
            .into(),
    })?)?;
    ensure!(
        p.pipeline_claims.iter().filter(|c| **c == owner).count() == 1,
        "warmup terminal lacks the original registered claim"
    );
    let before = unit(c::UNIT)?;
    let clean = terminal_shape(&before, &owner.invocation_id, &owner.expected_exec_start)?;
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            c::UNIT,
            "--output=json",
            "--no-pager",
            "--lines=65536",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 32 << 20,
        "warmup terminal journal unavailable/oversized"
    );
    let root = s.output.parent().unwrap();
    let j = preserve(&root.join("journal.json"), &out.stdout)?;
    let rows = journal_rows(&j)?;
    let summary = journal_summary(
        &rows,
        &owner.invocation_id,
        clean,
        before["Result"]
            .as_str()
            .context("warmup terminal result")?,
    )?;
    let output = output_binding(root, &owner.invocation_id, clean)?;
    let complete = clean && output["passed"] == true && summary["bounded_complete_marker"] == true;
    let mut proof = json!({"schema":SCHEMA,"epoch":223,"unit":c::UNIT,"invocation_id":owner.invocation_id,"running_origin":private157::binding(&s.running_origin),"observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"sampled_at_utc":f["sampled_at_utc"],"recorded_unix_seconds":now()?,"terminal_manager":before,"journal":private157::binding(&j),"journal_summary":summary,"output":output,"bounded_warmup_complete":complete,"terminal_outcome":if complete{"bounded-warmup-complete"}else{"failed"},"startup_failure_history":startup_history()?,"capture_spec":private157::binding(&binding),"capture_helper_sha256":self_sha,"resource_samples_taken":0,"entry_replay":true,"repair_closed":false});
    for flag in FLAGS {
        proof[flag] = json!(false);
    }
    validate(&proof)?;
    ensure!(
        unit(c::UNIT)? == before,
        "warmup terminal owner changed during capture"
    );
    private157::immutable_receipt(&s.output, &proof)
}
const SCHEMA_FLEET: &str = "jetstreamer-horizon-campaign-fleet-v1";
pub(super) fn predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    time: u64,
) -> Result<()> {
    let (_, iid) = validate(proof)?;
    let recorded = proof["recorded_unix_seconds"]
        .as_u64()
        .context("warmup terminal capture clock")?;
    ensure!(
        p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && previous["schema"] == SCHEMA_FLEET
            && previous["sampled_at_utc"] == sampled
            && proof["sampled_at_utc"] == sampled
            && proof["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|b| proof["fleet"] == private157::binding(b))
            && recorded <= time
            && time - recorded <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < recorded),
        "warmup terminal event replaced/staled resource history"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"]
            .as_str()
            .context("warmup prior plan")?
            .into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("warmup prior plan SHA")?
            .into(),
    })?)?;
    ensure!(
        old.pipeline_claims
            .iter()
            .filter(|c| c.unit == c::UNIT
                && c.invocation_id == iid
                && c.evidence
                    .first()
                    .is_some_and(|b| private157::binding(b) == proof["running_origin"]))
            .count()
            == 1,
        "warmup terminal proof lacks exact previous owner"
    );
    ensure!(
        p.schema == old.schema
            && p.observer == old.observer
            && p.pipeline_claims == old.pipeline_claims
            && p.tracked_units == old.tracked_units
            && p.status_receipt_directory == old.status_receipt_directory
            && p.runtime_handoff157 == old.runtime_handoff157
            && p.continuation203_runtime_extension == old.continuation203_runtime_extension
            && p.epoch203_ram_auxiliary.is_none()
            && old.epoch203_ram_auxiliary.is_none()
            && p.diagnostics.len() == old.diagnostics.len()
            && old
                .diagnostics
                .iter()
                .all(|d| p.diagnostics.iter().any(|n| n.epoch == d.epoch
                    && n.unit == d.unit
                    && n.invocation_id == d.invocation_id
                    && n.scratch_path == d.scratch_path
                    && n.launch_receipt == d.launch_receipt))
            && p.gates.len() == old.gates.len(),
        "warmup terminal event changed unrelated owners/configuration"
    );
    for (epoch, g) in &old.gates {
        let n = p.gates.get(epoch).context("warmup terminal gate omitted")?;
        ensure!(
            n.state == g.state
                && g.evidence.iter().all(|e| n.evidence.contains(e))
                && (*epoch == 223 || (n.evidence == g.evidence && n.next_action == g.next_action)),
            "warmup terminal changed archive or unrelated gates"
        );
        if *epoch == 223 {
            ensure!(
                n.state == "failed-needs-repair"
                    && n.evidence
                        .iter()
                        .all(|e| g.evidence.contains(e) || p.metadata_event.as_ref() == Some(e)),
                "bounded warmup closed repair or added unrelated evidence"
            );
        }
    }
    Ok(())
}
pub(super) fn census_check(p: &Plan, current: &BTreeMap<String, Value>) -> Result<()> {
    let Some(b) = &p.metadata_event else {
        return Ok(());
    };
    let proof = bound_json(b)?;
    if proof["schema"] != SCHEMA {
        return Ok(());
    }
    let (_, iid) = validate(&proof)?;
    terminal_shape(
        current
            .get(c::UNIT)
            .context("warmup terminal owner omitted")?,
        &iid,
        proof["terminal_manager"]["ExecStart"]
            .as_str()
            .context("warmup terminal command")?,
    )?;
    Ok(())
}
pub(super) fn no_later_invocation(iid: &str, start: u64) -> Result<()> {
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            c::UNIT,
            "_PID=1",
            "--output=json",
            "--no-pager",
            "--lines=128",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1 << 20,
        "warmup current manager history unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.iter()
            .filter(|r| manager(r))
            .any(|r| r["INVOCATION_ID"] == iid && event_clock(r).is_ok_and(|t| t >= start)),
        "warmup current manager history lacks its proved invocation"
    );
    for r in rows.iter().filter(|r| manager(r)) {
        ensure!(
            event_clock(r)? < start || r["INVOCATION_ID"] == iid,
            "warmup owner was replaced after terminal proof"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_terminal_can_never_promote_any_remaining_qualification_or_publication_gate() {
        let mut proof = json!({"schema":SCHEMA,"epoch":223,"unit":c::UNIT,"entry_replay":true,"resource_samples_taken":0,"repair_closed":false});
        for flag in FLAGS {
            proof[flag] = json!(false);
        }
        for flag in FLAGS {
            let mut bad = proof.clone();
            bad[flag] = json!(true);
            assert!(
                validate(&bad)
                    .unwrap_err()
                    .to_string()
                    .contains("forbidden authority"),
                "{flag}"
            );
        }
    }
    fn unit_state(clean: bool) -> Value {
        json!({"Id":c::UNIT,"LoadState":"loaded","ActiveState":if clean{"inactive"}else{"failed"},"SubState":if clean{"dead"}else{"failed"},"MainPID":"0","NRestarts":"0","InvocationID":"","Result":if clean{"success"}else{"exit-code"},"ExecMainStatus":if clean{"0"}else{"1"},"ExecStart":"command"})
    }
    fn rows(clean: bool) -> Vec<Value> {
        let iid = "a".repeat(32);
        let boot = "b".repeat(32);
        let manager = |time: &str, message: String, mid: &str| json!({"_PID":"1","_UID":"0","UNIT":c::UNIT,"INVOCATION_ID":iid,"_BOOT_ID":boot,"MESSAGE_ID":mid,"__REALTIME_TIMESTAMP":time,"MESSAGE":message});
        let start = manager(
            "100000000",
            format!("Started {} - Private native20 warmup.", c::UNIT),
            "39f53479d3a045ac8e11786248231fbf",
        );
        let end = if clean {
            manager(
                "200000000",
                format!("{}: Deactivated successfully.", c::UNIT),
                "7ad2d189f7e94e70a38c781354912448",
            )
        } else {
            manager(
                "200000000",
                format!("{}: Failed with result 'exit-code'.", c::UNIT),
                "failure",
            )
        };
        let mut r = vec![start, end];
        if clean {
            r.push(json!({"_UID":"1000","_SYSTEMD_UNIT":c::UNIT,"_SYSTEMD_INVOCATION_ID":iid,"_BOOT_ID":boot,"__REALTIME_TIMESTAMP":"150000000","MESSAGE":"[2026 INFO  jetstreamer_node] private epoch223 warmup complete slot=96335554 complete=true"}));
        }
        r
    }
    fn resource(passed: bool) -> Value {
        json!({"schema":"jetstreamer-private-epoch223-v1620-warmup-resource-v1","epoch":223,"unit":c::UNIT,"invocation_id":"a".repeat(32),"runner_sha256":RUNNER_SHA,"plan":{"path":PLAN,"sha256":PLAN_SHA},"node_sha256":"99f643ff0dbbcd37d1fbc524a1c1088d7273c7fc91330df059d30d51b8b0fcd4","worker_sha256":"52d6c86a8103b8965ca68ead96af471a7899a0a0e6e69c48989b39fd5d922f0c","snapshot_sha256":"301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665","target_slot":96335554,"elapsed_millis":1000,"target_stop_protocol":"cooperative-resume-only","success":passed,"target_reached":passed,"observed_slot":96335554,"external_signal":0,"error":null,"child_return_code":1,"authority":{"ordinary_replay_authorized":false,"full_cold_epoch_peak_qualified":false,"publication_authorized":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"remote_mutations":false,"r2_mutations":false}})
    }
    #[test]
    fn terminal_success_failure_and_cleared_iid_keep_exact_owner() {
        for clean in [false, true] {
            let u = unit_state(clean);
            assert_eq!(
                terminal_shape(&u, &"a".repeat(32), "command").unwrap(),
                clean
            );
            for (k, v) in [
                ("InvocationID", json!("c".repeat(32))),
                ("MainPID", json!("9")),
                ("NRestarts", json!("1")),
                ("ActiveState", json!("active")),
                ("ExecStart", json!("other")),
            ] {
                let mut bad = u.clone();
                bad[k] = v;
                assert!(
                    terminal_shape(&bad, &"a".repeat(32), "command").is_err(),
                    "{k}"
                );
            }
        }
    }
    #[test]
    fn journal_proves_real_simple_start_end_marker_and_never_hides_replacement() {
        let good = rows(true);
        assert_eq!(
            journal_summary(&good, &"a".repeat(32), true, "success").unwrap()["bounded_complete_marker"],
            true
        );
        let failed = rows(false);
        assert_eq!(
            journal_summary(&failed, &"a".repeat(32), false, "exit-code").unwrap()["bounded_complete_marker"],
            false
        );
        for index in 0..2 {
            let mut bad = good.clone();
            bad.remove(index);
            assert!(journal_summary(&bad, &"a".repeat(32), true, "success").is_err());
            let mut bad = good.clone();
            bad.push(good[index].clone());
            assert!(journal_summary(&bad, &"a".repeat(32), true, "success").is_err());
        }
        let mut later = good.clone();
        let mut replacement = good[0].clone();
        replacement["INVOCATION_ID"] = json!("c".repeat(32));
        replacement["__REALTIME_TIMESTAMP"] = json!("210000000");
        later.push(replacement);
        assert!(journal_summary(&later, &"a".repeat(32), true, "success").is_err());
        let mut prior = good.clone();
        let mut startup = failed[1].clone();
        startup["INVOCATION_ID"] = json!("4ba44fd7e1b44bdf921790d20f81fedf");
        startup["__REALTIME_TIMESTAMP"] = json!("50000000");
        prior.push(startup);
        journal_summary(&prior, &"a".repeat(32), true, "success").unwrap();
        for (index, key) in [(0, "_PID"), (0, "_UID"), (0, "MESSAGE_ID"), (1, "_BOOT_ID")] {
            let mut bad = good.clone();
            bad[index][key] = json!("wrong");
            assert!(journal_summary(&bad, &"a".repeat(32), true, "success").is_err());
        }
    }
    #[test]
    fn resource_or_failure_cannot_borrow_another_invocation_runtime_or_full_prefix() {
        result_shape(&resource(true), &"a".repeat(32), "resource").unwrap();
        result_shape(&resource(false), &"a".repeat(32), "failure").unwrap();
        assert!(result_shape(&resource(true), &"a".repeat(32), "failure").is_err());
        for (k, v) in [
            ("invocation_id", json!("c".repeat(32))),
            (
                "worker_sha256",
                json!("a651b7a6ee3c0d4f8359e1ea6cfcb96becf259d440ee744beb173b264de6af20"),
            ),
            ("target_slot", json!(96767522)),
            ("target_reached", json!(false)),
            ("external_signal", json!(2)),
            ("child_return_code", json!(9)),
        ] {
            let mut bad = resource(true);
            bad[k] = v;
            assert!(
                result_shape(&bad, &"a".repeat(32), "resource").is_err(),
                "{k}"
            );
        }
        let mut bad = resource(true);
        bad["authority"]["publication_authorized"] = json!(true);
        assert!(result_shape(&bad, &"a".repeat(32), "resource").is_err());
        assert!(
            preserved_result(
                &json!({"present":false,"absence_confirmed_after_terminal":true}),
                &"a".repeat(32),
                true
            )
            .is_err()
        );
        assert!(
            !preserved_result(
                &json!({"present":false,"absence_confirmed_after_terminal":true}),
                &"a".repeat(32),
                false
            )
            .unwrap()
        );
    }
}
