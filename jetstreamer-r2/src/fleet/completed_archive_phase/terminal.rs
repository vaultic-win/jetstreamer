//! Successful phase evidence is terminal custody, never a fabricated live launch.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-completed209-phase-terminal-v1";
const ORIGINAL: &str = "7dc89b9bcd1b3391f970f265c698a8eea29ebd19a93ebc8efdac7b163e682ef1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    phase_spec: BoundFile,
    admission: BoundFile,
    startup_release: BoundFile,
    capturer: Program,
    output: PathBuf,
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("completed209 terminal integer absent: {k}"))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("completed209 terminal text absent: {k}"))
}
fn clock(v: &Value) -> Result<u64> {
    Ok(text(v, "__REALTIME_TIMESTAMP")?.parse()?)
}
fn denied() -> Value {
    json!({"live_owner_claimed":false,"replay_launch_authorized":false,"publication_authorized":false,
        "local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false,"archive_body_reads":0})
}
fn full_pins(
    s: &Spec,
    a: &BoundFile,
    spec: &BoundFile,
    b: &BoundFile,
    release: &Value,
) -> Result<()> {
    ensure!(
        s.phase == Phase::Full
            && s.launcher_transition.is_none()
            && spec.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-generic209-full-spec-v12-guards-v2/phase-spec.json"
                )
            && spec.sha256 == "90bdbcd0a831ae5207a36eb4f1569ee5400ff35532987271517cc3007043b296"
            && a.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-generic209-full-admission-v12/admission.json"
                )
            && a.sha256 == "bad7d0f7beaab944dfd1bd1d694770ab0324b1495a606c5a17b48ba89decbf04"
            && b.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-generic209-full-release-v12/release.json"
                )
            && b.sha256 == "f60a748836a15640c45dc0bd848e4efcc4eb7c10d0a5ae790bc46a0029cd2372"
            && s.programs["launcher"].artifact.sha256 == ORIGINAL
            && release["invocation_id"] == "6814e0da70924c9c974cabd3274ffefb"
            && release["process"]["pid"] == 2802657
            && release["process"]["start_ticks"] == 199206966,
        "completed209 terminal bridge escaped the original successful Full pins"
    );
    Ok(())
}
pub(super) fn owner_matches(s: &Spec, release: &Value, u: &Value) -> Result<()> {
    let name = &s.units[s.phase.name()];
    ensure!(
        u["Id"] == *name
            && u["LoadState"] == "loaded"
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0"
            && (u["InvocationID"] == release["invocation_id"] || u["InvocationID"] == "")
            && pipeline_status::same_exec_start(
                text(&release["owner"], "ExecStart")?,
                text(u, "ExecStart")?
            ),
        "completed209 phase is not the unchanged natural-success terminal owner"
    );
    Ok(())
}
fn lifecycle(s: &Spec, release: &Value, rows: &[Value], a: &Value, now: u64) -> Result<Vec<Value>> {
    let name = &s.units[s.phase.name()];
    let iid = text(release, "invocation_id")?;
    let boot = text(&release["process"]["native_start_clock"], "boot_id")?.replace('-', "");
    let mut own = Vec::new();
    let mut last = 0;
    let mut cursors = BTreeSet::new();
    ensure!(
        !rows.is_empty() && rows.len() <= 8192,
        "completed209 complete terminal journal bounds"
    );
    for row in rows {
        let at = clock(row)?;
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == *name
                && row["_BOOT_ID"] == boot
                && at >= last
                && at / 1_000_000 <= now
                && cursors.insert(text(row, "__CURSOR")?.to_owned()),
            "completed209 terminal journal is foreign, repeated or reordered"
        );
        last = at;
        if row["INVOCATION_ID"].is_null() {
            // PID1 can log this unit-file parser warning on daemon-reload after
            // success. Preserve it in full raw evidence; it is no invocation.
            ensure!(
                row["MESSAGE_ID"] == "c772d24e9a884cbeb9ea12625c306c01"
                    && text(row, "MESSAGE")?.starts_with(&format!("/etc/systemd/system/{name}:"))
                    && text(row, "MESSAGE")?.ends_with(
                        ": Support for option CPUAccounting= has been removed and it is ignored"
                    ),
                "completed209 terminal journal contains unbound manager activity"
            );
            continue;
        }
        ensure!(
            row["INVOCATION_ID"] == iid
                && matches!(
                    text(row, "MESSAGE_ID")?,
                    "7d4958e842da4a758f6c1cdc7b36dcc5"
                        | "39f53479d3a045ac8e11786248231fbf"
                        | "7ad2d189f7e94e70a38c781354912448"
                        | "ae8f7b866b0347b9af31fe1c80b127c0"
                ),
            "completed209 phase was stopped, failed or replaced"
        );
        own.push(row.clone());
    }
    let events = singleton209_delivery::terminal_history_for(&own, name, iid)?;
    ensure!(
        events[0]["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
            && events[1]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448",
        "completed209 terminal lifecycle lacks native start and success"
    );
    launch_terminal_order(release, &events, a)?;
    let started = n(
        &release["process"]["native_start_clock"],
        "started_unix_seconds",
    )?;
    ensure!(
        started <= clock(&events[0])? / 1_000_000 && clock(&events[0])? / 1_000_000 - started <= 2,
        "completed209 terminal PID1/native original start clocks differ"
    );
    Ok(events)
}
fn journal(s: &Spec, release: &Value, a: &Value) -> Result<Value> {
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            &s.units[s.phase.name()],
            "_PID=1",
            "--output=json",
            "--no-pager",
            "--since",
            &format!("@{}", n(a, "recorded_unix_seconds")?),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 8 << 20,
        "completed209 terminal complete manager journal unavailable/oversized"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let events = lifecycle(s, release, &rows, a, now)?;
    Ok(
        json!({"raw":std::str::from_utf8(&out.stdout)?,"sha256":hex_lower(&Sha256::digest(&out.stdout)),"rows":rows,"events":events}),
    )
}
fn metadata(path: &Path, uid: u32, private: bool) -> Result<(Vec<u8>, Value)> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == uid
            && m.mode() & if private { 0o077 } else { 0o022 } == 0,
        "completed209 terminal receipt/manifest custody differs"
    );
    let raw = read_stable_bounded(path, 4096, "completed209 terminal receipt/manifest")?;
    ensure!(
        identity(&m) == identity(&fs::symlink_metadata(path)?),
        "completed209 terminal receipt changed"
    );
    let binding = json!({"path":path,"sha256":hex_lower(&Sha256::digest(&raw)),"identity":regular_identity(path)?});
    Ok((raw, binding))
}
fn receipts(s: &Spec, archive: &LocalArchive) -> Result<Value> {
    ensure!(
        matches!(s.phase, Phase::Full | Phase::Plugin),
        "completed209 terminal receipt phase differs"
    );
    let state = s.state_root.join(s.phase.name());
    let path = state
        .join("receipts")
        .join(format!("epoch-209.{}.ok", s.phase.name()));
    let (raw, binding) = metadata(&path, 1000, true)?;
    receipt_words(
        &raw,
        &[
            &archive.sha256_hex,
            &s.tools[s.phase.name()].artifact.sha256,
            &s.programs[s.phase.name()].artifact.sha256,
        ],
    )?;
    let mut result = json!({"phase_receipt":binding});
    if s.phase == Phase::Full {
        let manifest = format!("{}  epoch-209.jet\n", archive.sha256_hex);
        let (actual, m) = metadata(&state.join("archive-manifest.sha256"), 1000, false)?;
        ensure!(
            actual == manifest.as_bytes(),
            "completed209 terminal full manifest differs"
        );
        let (chain, b) = metadata(&state.join("receipts/ordered-chain.ok"), 1000, true)?;
        receipt_words(
            &chain,
            &[
                &hex_lower(&Sha256::digest(manifest.as_bytes())),
                &s.tools["full"].artifact.sha256,
                &s.programs["full"].artifact.sha256,
            ],
        )?;
        result["archive_manifest"] = m;
        result["ordered_chain_receipt"] = b;
    }
    Ok(result)
}
fn source_pair(s: &Spec, a: &Value) -> Result<LocalArchive> {
    let Origin::Singleton209 {
        launch,
        native_input,
        cohort_publication,
    } = &s.origin
    else {
        bail!("completed209 terminal bridge cannot borrow another epoch origin")
    };
    let (_, l) = full209_status::claim(launch)?;
    ensure!(
        l["native_input"] == private157::binding(native_input)
            && read(native_input)?["native_input_qualified"] == true,
        "completed209 terminal native source changed"
    );
    singleton209_delivery::source_terminal(&l)?;
    capped204205_work::empty_terminal_cgroup(singleton209::UNIT)?;
    inactive_status::no_pending_owner_trigger(singleton209::UNIT, false)?;
    let pair = read_local_archive(&Path::new(singleton209::ROOT).join("output"), 209)?;
    singleton209_delivery::cohort(&read(cohort_publication)?, &pair)?;
    ensure!(
        a["archive"] == singleton209_delivery::pair_identity(&pair),
        "completed209 terminal archive/sidecar identity changed"
    );
    Ok(pair)
}
fn inputs(
    spec: &BoundFile,
    admission: &BoundFile,
    startup: &BoundFile,
) -> Result<(Spec, Value, Value)> {
    let s: Spec = serde_json::from_value(read(spec)?)?;
    shape(&s)?;
    ensure!(
        s.epoch == 209 && matches!(s.phase, Phase::Full | Phase::Plugin),
        "completed209 terminal capture scope differs"
    );
    let mut a = read(admission)?;
    a["binding"] = private157::binding(admission);
    ensure!(
        a["schema"] == RECEIPT
            && a["admitted"] == true
            && a["spec"] == private157::binding(spec)
            && a["origin"] == serde_json::to_value(&s.origin)?
            && a["tools"] == serde_json::to_value(&s.tools)?
            && a["programs"] == serde_json::to_value(&s.programs)?
            && a["decoder_capacity"] == serde_json::to_value(&s.decoder_capacity)?
            && a["units"] == serde_json::to_value(&s.units)?
            && a["guard_units"] == serde_json::to_value(&s.guard_units)?
            && a["state_root"] == serde_json::to_value(&s.state_root)?
            && a["interpreter"] == serde_json::to_value(&s.interpreter)?
            && a["unit_file"] == private157::binding(&s.unit_file)
            && a["capacity"]["resource_basis"] == s.resource_basis,
        "completed209 terminal admission changed its exact source/tools/core/capacity bindings"
    );
    let release = barrier::saved_release(&s, startup)?;
    barrier::release_shape(&release, &s, &a)?;
    if s.phase == Phase::Full {
        full_pins(&s, admission, spec, startup, &release)?;
    } else {
        ensure!(
            s.launcher_transition.is_some(),
            "completed209 plugin terminal lacks original Full bridge"
        );
        handoff::validate(&s)?;
    }
    for p in s.programs.values() {
        program(p)?;
    }
    for (role, t) in &s.tools {
        assembly204_recovery::qualified_delivery_tool(role, &t.artifact, &t.qualification)?;
    }
    decoder_capacity::validate(&s, &a["origin_evidence"]["producer"])?;
    Ok((s, a, release))
}
fn execution_shape(p: &BTreeMap<String, String>, release: &Value, events: &[Value]) -> Result<()> {
    let num = |key: &str| -> Result<u64> {
        Ok(p.get(key)
            .with_context(|| format!("completed209 terminal execution field missing: {key}"))?
            .parse()?)
    };
    let (pid, start, exit, code, status) = (
        num("ExecMainPID")?,
        num("ExecMainStartTimestampMonotonic")?,
        num("ExecMainExitTimestampMonotonic")?,
        num("ExecMainCode")?,
        num("ExecMainStatus")?,
    );
    if pid == 0 && start == 0 && exit == 0 && code == 0 && status == 0 {
        return Ok(());
    }
    let hz = n(
        &release["process"]["native_start_clock"],
        "clock_ticks_per_second",
    )?;
    let ticks = n(&release["process"], "start_ticks")?;
    let expected = ticks
        .checked_mul(1_000_000)
        .context("completed209 start ticks overflow")?
        / hz;
    let end: u64 = text(&events[1], "__MONOTONIC_TIMESTAMP")?.parse()?;
    ensure!(
        pid == n(&release["process"], "pid")?
            && code == 1
            && status == 0
            && start > 0
            && start.abs_diff(expected) <= 2_000_000
            && exit >= start
            && end >= exit
            && end - exit <= 5_000_000,
        "completed209 retained terminal execution PID/start/exit differs"
    );
    Ok(())
}
fn effective_same(a: &Value, b: &Value) -> Result<bool> {
    if !pipeline_status::same_exec_start(text(a, "ExecStart")?, text(b, "ExecStart")?) {
        return Ok(false);
    }
    let mut normalized = b.clone();
    normalized["ExecStart"] = a["ExecStart"].clone();
    Ok(*a == normalized)
}
fn terminal_now(s: &Spec, release: &Value, a: &Value) -> Result<Value> {
    let u = unit(&s.units[s.phase.name()])?;
    owner_matches(s, release, &u)?;
    let argv: Vec<String> = serde_json::from_value(a["argv"].clone())?;
    let effective = check_unit(s, &argv)?;
    inactive_status::no_pending_owner_trigger(&s.units[s.phase.name()], false)?;
    let cgroup = capped204205_work::empty_terminal_cgroup(&s.units[s.phase.name()])?;
    let j = journal(s, release, a)?;
    let execution = barrier::properties(
        &s.units[s.phase.name()],
        "ExecMainPID,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic",
    )?;
    execution_shape(
        &execution,
        release,
        j["events"]
            .as_array()
            .context("completed209 terminal events missing")?,
    )?;
    ensure!(
        u == unit(&s.units[s.phase.name()])? && effective == check_unit(s, &argv)?,
        "completed209 terminal owner changed across evidence capture"
    );
    Ok(
        json!({"unit":u,"effective_unit":effective,"cgroup":cgroup,"journal":j,"execution":execution}),
    )
}
pub(super) fn capture() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-completed209-phase-terminal")?;
    let r: Request = serde_json::from_value(read(&binding)?)?;
    ensure!(
        r.schema == "jetstreamer-completed209-phase-terminal-request-v1"
            && r.capturer.artifact.sha256 == self_sha
            && fs::read_link("/proc/self/exe")? == r.capturer.artifact.path,
        "completed209 terminal request/capturer differs"
    );
    program(&r.capturer)?;
    validate_output_destination(&r.output)?;
    let (s, a, release) = inputs(&r.phase_spec, &r.admission, &r.startup_release)?;
    let (pair, original) = origin(&s)?;
    ensure!(
        a["archive"] == singleton209_delivery::pair_identity(&pair),
        "completed209 terminal admitted source changed"
    );
    let result = receipts(&s, &pair)?;
    let state = terminal_now(&s, &release, &a)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let proof = json!({"schema":SCHEMA,"epoch":209,"phase":s.phase,"request":binding,"issuer_sha256":self_sha,
        "capturer":r.capturer,"phase_spec":r.phase_spec,"admission":r.admission,"startup_release":r.startup_release,
        "startup_release_contents":release,"original_invocation_id":release["invocation_id"],"original_process":release["process"],
        "archive":singleton209_delivery::pair_identity(&pair),"origin_evidence":original,"verification":result,"terminal":state,
        "recorded_unix_seconds":now,"authority":denied()});
    validate(&proof)?;
    private157::immutable_receipt(&r.output, &proof)
}
pub(super) fn validate(v: &Value) -> Result<(Spec, Value)> {
    ensure!(
        v["schema"] == SCHEMA && v["epoch"] == 209 && v["authority"] == denied(),
        "completed209 terminal proof schema/authority differs"
    );
    let b: BoundFile = serde_json::from_value(v["request"].clone())?;
    let r: Request = serde_json::from_value(read(&b)?)?;
    ensure!(
        r.schema == "jetstreamer-completed209-phase-terminal-request-v1"
            && v["phase_spec"] == private157::binding(&r.phase_spec)
            && v["admission"] == private157::binding(&r.admission)
            && v["startup_release"] == private157::binding(&r.startup_release)
            && v["capturer"] == serde_json::to_value(&r.capturer)?
            && v["issuer_sha256"] == r.capturer.artifact.sha256,
        "completed209 terminal proof changed sealed input/capturer bindings"
    );
    program(&r.capturer)?;
    let (s, a, release) = inputs(&r.phase_spec, &r.admission, &r.startup_release)?;
    ensure!(
        v["origin_evidence"]["origin"] == serde_json::to_value(&s.origin)?
            && v["origin_evidence"]["producer"] == a["origin_evidence"]["producer"]
            && v["origin_evidence"]["process_reference_census"]["references"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && v["phase"] == s.phase.name()
            && v["startup_release_contents"] == release
            && v["original_invocation_id"] == release["invocation_id"]
            && v["original_process"] == release["process"],
        "completed209 terminal proof changed original waiting PID/IID/boot/start"
    );
    let raw = text(&v["terminal"]["journal"], "raw")?;
    let rows = serde_json::Deserializer::from_str(raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        raw.len() <= 8 << 20
            && v["terminal"]["journal"]["sha256"] == hex_lower(&Sha256::digest(raw.as_bytes()))
            && v["terminal"]["journal"]["rows"] == json!(rows)
            && v["terminal"]["journal"]["events"]
                == json!(lifecycle(
                    &s,
                    &release,
                    &rows,
                    &a,
                    n(v, "recorded_unix_seconds")?
                )?),
        "completed209 terminal raw lifecycle binding changed"
    );
    owner_matches(&s, &release, &v["terminal"]["unit"])?;
    execution_shape(
        &serde_json::from_value(v["terminal"]["execution"].clone())?,
        &release,
        v["terminal"]["journal"]["events"]
            .as_array()
            .context("completed209 terminal saved events absent")?,
    )?;
    let pair = source_pair(&s, &a)?;
    ensure!(
        v["archive"] == singleton209_delivery::pair_identity(&pair)
            && v["verification"] == receipts(&s, &pair)?,
        "completed209 terminal qualification receipts changed"
    );
    let now = terminal_now(&s, &release, &a)?;
    ensure!(
        now["journal"]["events"] == v["terminal"]["journal"]["events"]
            && now["cgroup"] == v["terminal"]["cgroup"]
            && effective_same(&v["terminal"]["effective_unit"], &now["effective_unit"])?,
        "completed209 terminal original invocation/control proof was replaced"
    );
    Ok((s, a))
}
pub(super) fn predecessor(
    v: &Value,
    next: &Spec,
    p: &Prior,
    archive: &LocalArchive,
    self_sha: &str,
) -> Result<Value> {
    let (prior, a) = validate(v)?;
    let request: Request =
        serde_json::from_value(read(&serde_json::from_value(v["request"].clone())?)?)?;
    ensure!(
        request.output == p.launch.path,
        "completed209 terminal evidence moved from its sealed output"
    );
    ensure!(
        prior.phase == p.phase
            && p.phase != Phase::Upload
            && self_sha == next.programs["launcher"].artifact.sha256
            && v["archive"] == singleton209_delivery::pair_identity(archive),
        "completed209 terminal predecessor phase/archive/successor differs"
    );
    handoff::core(&prior, next)?;
    handoff::programs_match(&prior, next)?;
    if p.phase == Phase::Full {
        ensure!(
            handoff::full_terminal(next) == Some(&p.launch),
            "completed209 next phase did not name the original Full terminal bridge"
        );
    }
    Ok(
        json!({"terminal_evidence":private157::binding(&p.launch),"admission":v["admission"],
        "original_invocation_id":v["original_invocation_id"],"terminal":v["terminal"],"verification":v["verification"],
        "archive":a["archive"],"live_owner_claimed":false}),
    )
}

/// Project only positively proved terminal predecessor actors out of the live
/// comparison. The original fleet and complete current census remain untouched.
pub(super) fn previous_view(previous: &Value, next: &Spec) -> Result<(Value, BTreeSet<String>)> {
    handoff::validate(next)?;
    ensure!(
        next.launcher_transition.is_some(),
        "completed209 delivery event lacks launcher transition"
    );
    let mut view = previous.clone();
    let mut guards = BTreeSet::new();
    for p in &next.prior {
        let proof = read(&p.launch)?;
        let (old, _) = validate(&proof)?;
        ensure!(
            old.phase == p.phase,
            "completed209 terminal predecessor view phase differs"
        );
        handoff::core(&old, next)?;
        project_one(&mut view, &proof, &old)?;
        guards.insert(old.guard_units[old.phase.name()].clone());
    }
    Ok((view, guards))
}

pub(super) fn project_one(view: &mut Value, proof: &Value, old: &Spec) -> Result<()> {
    let name = &old.units[old.phase.name()];
    let rows = view["active"]
        .as_array_mut()
        .context("completed209 predecessor active roster missing")?;
    for row in rows
        .iter()
        .filter(|r| r["epoch"] == 209 && r["unit"]["Id"] == *name)
    {
        ensure!(
            row["unit"]["InvocationID"] == proof["original_invocation_id"]
                && row["expected_invocation_id"] == proof["original_invocation_id"],
            "completed209 terminal projection borrowed an unrelated previous invocation"
        );
    }
    rows.retain(|r| !(r["epoch"] == 209 && r["unit"]["Id"] == *name));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Spec, Value, Value, Vec<Value>) {
        let (s, a, l, _) = launch::tests::fixture();
        let release = l["startup_release_contents"].clone();
        let name = &s.units["full"];
        let iid = &release["invocation_id"];
        let boot = text(&release["process"]["native_start_clock"], "boot_id")
            .unwrap()
            .replace('-', "");
        let start = json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"_BOOT_ID":boot,"__CURSOR":"start",
            "MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":format!("Started {name} - fixture."),"__REALTIME_TIMESTAMP":"901000000"});
        let end = json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"_BOOT_ID":boot,"__CURSOR":"end",
            "MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{name}: Deactivated successfully."),"__REALTIME_TIMESTAMP":"2000000000","__MONOTONIC_TIMESTAMP":"1100000000"});
        (s, a, release, vec![start, end])
    }
    #[test]
    fn completed209_terminal_authenticates_original_release_and_natural_success_without_live_owner()
    {
        let (s, a, release, rows) = fixture();
        let events = lifecycle(&s, &release, &rows, &a, 2001).unwrap();
        assert_eq!(events, rows);
        let mut u = json!({"Id":s.units["full"],"LoadState":"loaded","ActiveState":"inactive","SubState":"dead",
            "MainPID":"0","NRestarts":"0","Result":"success","ExecMainStatus":"0","InvocationID":"","ExecStart":"exact retained command"});
        let mut r = release.clone();
        r["owner"]["ExecStart"] = u["ExecStart"].clone();
        owner_matches(&s, &r, &u).unwrap();
        for (key, value) in [
            ("InvocationID", "replaced"),
            ("MainPID", "42"),
            ("Result", "failed"),
            ("LoadState", "not-found"),
            ("NRestarts", "1"),
            ("ExecStart", "foreign"),
        ] {
            let original = u[key].clone();
            u[key] = json!(value);
            assert!(owner_matches(&s, &r, &u).is_err(), "{key}");
            u[key] = original;
        }
        assert_eq!(denied()["live_owner_claimed"], false);
        assert_eq!(denied()["publication_authorized"], false);
    }
    #[test]
    fn completed209_terminal_rejects_stop_failure_replacement_boot_duplicates_and_clock_rewrites() {
        let (s, a, release, rows) = fixture();
        for (index, key, value) in [
            (0, "INVOCATION_ID", json!("0".repeat(32))),
            (1, "MESSAGE_ID", json!("be02cf6855d2428ba40df7e9d022f03d")),
            (1, "_BOOT_ID", json!("0".repeat(32))),
            (1, "__CURSOR", json!("start")),
            (1, "__REALTIME_TIMESTAMP", json!("900000000")),
            (1, "MESSAGE", json!("Stopped by operator")),
        ] {
            let mut bad = rows.clone();
            bad[index][key] = value;
            assert!(lifecycle(&s, &release, &bad, &a, 2001).is_err(), "{key}");
        }
        let mut replaced = rows.clone();
        let mut row = rows[0].clone();
        row["INVOCATION_ID"] = json!("0".repeat(32));
        row["__CURSOR"] = json!("replacement");
        row["__REALTIME_TIMESTAMP"] = json!("2001000000");
        replaced.push(row);
        assert!(lifecycle(&s, &release, &replaced, &a, 2002).is_err());
        let mut bad = release.clone();
        bad["captured_unix_seconds"] = json!(2100);
        assert!(lifecycle(&s, &bad, &rows, &a, 2200).is_err());
    }
    #[test]
    fn completed209_terminal_preserves_only_the_known_noninvocation_reload_warning() {
        let (s, a, release, mut rows) = fixture();
        let warning = json!({"_PID":"1","_UID":"0","UNIT":s.units["full"],"_BOOT_ID":rows[0]["_BOOT_ID"],"__CURSOR":"warning",
            "MESSAGE_ID":"c772d24e9a884cbeb9ea12625c306c01","__REALTIME_TIMESTAMP":"2001000000",
            "MESSAGE":format!("/etc/systemd/system/{}:22: Support for option CPUAccounting= has been removed and it is ignored",s.units["full"])});
        rows.push(warning);
        lifecycle(&s, &release, &rows, &a, 2002).unwrap();
        rows[2]["MESSAGE"] = json!("A new unbound job started");
        assert!(lifecycle(&s, &release, &rows, &a, 2002).is_err());
    }
    #[test]
    fn completed209_terminal_accepts_genuine_cleared_execution_fields_and_rejects_foreign_retained_pid()
     {
        let (_, _, release, rows) = fixture();
        let mut p = BTreeMap::from([
            ("ExecMainPID".into(), "0".into()),
            ("ExecMainCode".into(), "0".into()),
            ("ExecMainStatus".into(), "0".into()),
            ("ExecMainStartTimestampMonotonic".into(), "0".into()),
            ("ExecMainExitTimestampMonotonic".into(), "0".into()),
        ]);
        execution_shape(&p, &release, &rows).unwrap();
        p.insert("ExecMainPID".into(), "42".into());
        p.insert("ExecMainCode".into(), "1".into());
        p.insert("ExecMainStartTimestampMonotonic".into(), "1230000".into());
        p.insert("ExecMainExitTimestampMonotonic".into(), "1099000000".into());
        execution_shape(&p, &release, &rows).unwrap();
        p.insert("ExecMainPID".into(), "999".into());
        assert!(execution_shape(&p, &release, &rows).is_err());
        p.insert("ExecMainPID".into(), "42".into());
        p.insert("ExecMainStatus".into(), "1".into());
        assert!(execution_shape(&p, &release, &rows).is_err());
    }
    #[test]
    fn completed209_terminal_request_cannot_import_skip_or_live_launch_flags() {
        let b = json!({"path":"/sealed/metadata.json","sha256":"a".repeat(64)});
        let mut r = json!({"schema":"jetstreamer-completed209-phase-terminal-request-v1","phase_spec":b,"admission":b,"startup_release":b,
            "capturer":{"artifact":b,"deployment_seal":b},"output":"/private/terminal.json"});
        assert!(serde_json::from_value::<Request>(r.clone()).is_ok());
        for key in [
            "ignore_manager_iid",
            "skip_receipts",
            "live_owner_claimed",
            "publication_authorized",
        ] {
            r[key] = json!(true);
            assert!(serde_json::from_value::<Request>(r.clone()).is_err());
            r.as_object_mut().unwrap().remove(key);
        }
    }
    #[test]
    fn completed209_terminal_projection_removes_only_the_proved_old_invocation_and_retains_raw_source()
     {
        let (s, _, release, _) = fixture();
        let old = json!({"active":[{"epoch":209,"unit":{"Id":s.units["full"],"InvocationID":release["invocation_id"]},"expected_invocation_id":release["invocation_id"]},
            {"epoch":207,"unit":{"Id":"peer.service","InvocationID":"d".repeat(32)}}]});
        let proof = json!({"original_invocation_id":release["invocation_id"]});
        let mut view = old.clone();
        project_one(&mut view, &proof, &s).unwrap();
        assert_eq!(view["active"], json!([old["active"][1]]));
        assert_eq!(old["active"].as_array().unwrap().len(), 2);
        let mut bad = old;
        bad["active"][0]["unit"]["InvocationID"] = json!("0".repeat(32));
        assert!(project_one(&mut bad, &proof, &s).is_err());
    }
}
