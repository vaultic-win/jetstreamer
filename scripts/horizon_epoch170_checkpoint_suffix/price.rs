//! Reprice each phase using the sealed complete-fleet provider and the current 167 reservation.
use super::*;
use std::os::unix::fs::MetadataExt;
const PROVIDERS: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1";
const WRITERS: &str = "/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1";

fn writer(r: &Value) -> Result<Value> {
    let active = bound(&r["active"])?;
    let ready = bound(&active["ready"])?;
    let seal = &r["seal"];
    ensure!(
        Path::new(word(seal, "path")?)
            .parent()
            .and_then(Path::parent)
            == Some(Path::new(WRITERS)),
        "foreign observer package"
    );
    let program = member(seal, "status_cycle.py")?;
    let n = &active["new"];
    let name = word(n, "unit")?;
    let state = props(name, "Id,ActiveState,MainPID,InvocationID,Job")?;
    let pid: u32 = state["MainPID"].parse()?;
    ensure!(
        state["ActiveState"] == "active"
            && state["InvocationID"] == n["invocation_id"]
            && ticks(pid)? == num(n, "start_ticks")?
            && state["Job"].is_empty(),
        "observer changed"
    );
    ensure!(
        Path::new(word(n, "program")?) == program && ready.is_object(),
        "unbound observer image"
    );
    Ok(n.clone())
}
fn validate_fleet(f: &Value, expected: &Value) -> Result<()> {
    let p = Path::new(word(expected, "path")?);
    ensure!(
        p.starts_with("/var/lib/jetstreamer/horizon_runtime_data")
            && p.file_name() == Some(std::ffi::OsStr::new("ROOT_COMPLETE_OPERATIONAL_FLEET.json"))
            && f["current_full146"].is_object(),
        "wrong fleet"
    );
    let next = p.with_file_name("NEXT_DUE.json");
    let due = bound(&reference(&next)?)?;
    let observed = command(
        "/usr/bin/date",
        &["-u", "-d", word(f, "sampled_at_utc")?, "+%s"],
    )?
    .trim()
    .parse::<u64>()?;
    let due_at = command("/usr/bin/date", &["-u", "-d", word(&due, "due")?, "+%s"])?
        .trim()
        .parse::<u64>()?;
    ensure!(
        observed <= now()? && now()? <= due_at + 90 && due_at - observed == 1800,
        "expired or foreign fleet window"
    );
    Ok(())
}
fn guard167_minimum(candidate: &Value) -> Result<u64> {
    let unit = word(&candidate["scope"], "producer_unit")?;
    ensure!(
        unit.starts_with("horizon-qualify-167-checkpoint-bounded-20261127-v"),
        "unsupported 167 candidate"
    );
    let generation = unit
        .trim_end_matches(".service")
        .rsplit_once('-')
        .context("missing 167 generation")?
        .1;
    ensure!(
        matches!(generation, "v1" | "v2"),
        "unsupported 167 generation"
    );
    let root = Path::new(RT).join(format!("epoch167-checkpoint-bounded-20261127-{generation}"));
    if root.join("START_INTENT.json").exists() {
        let intent = bound(&reference(&root.join("START_INTENT.json"))?)?;
        ensure!(intent["producer_unit"] == unit, "167 scope mismatch");
        return num(&intent, "armed_floor");
    }
    Ok(0)
}
pub(super) fn bounds(
    cap: u64,
    physical: u64,
    aggregate: u64,
    armed167: u64,
    growth167: u64,
    offer: u64,
    held: Option<(u64, u64)>,
) -> Result<(u64, u64, u64)> {
    let needed_floor = aggregate.max(armed167).max(8_958_105_897_878);
    let remaining = cap
        .checked_sub(physical)
        .context("170 exceeds original cap")?;
    let (floor, book) = if let Some((floor, book)) = held {
        ensure!(
            floor >= needed_floor && book >= physical && book <= cap,
            "frozen 170 floor or cap no longer sufficient"
        );
        (floor, book)
    } else {
        let floor = needed_floor.checked_add(G).context("floor overflow")?;
        let budget = 40 * G;
        ensure!(
            remaining >= budget,
            "170 retained tree lacks the sealed 40 GiB growth budget"
        );
        (floor, physical + budget)
    };
    let required = floor
        .checked_add(growth167)
        .and_then(|v| v.checked_add(book - physical))
        .context("joint disk projection overflow")?;
    ensure!(
        offer >= required,
        "170 and 167 exceed HOME by {} bytes",
        required.saturating_sub(offer)
    );
    Ok((floor, book, required))
}
pub(super) fn capture(request: &Value, held: Option<&Value>) -> Result<Value> {
    let req = bound(request)?;
    let fleet_ref = &req["fleet"];
    let f = bound(fleet_ref)?;
    validate_fleet(&f, fleet_ref)?;
    let observer = writer(&req["writer"])?;
    if !req["released167"].is_null() {
        return capture_released(request, &req, &f, &observer, held);
    }
    let refpath = Path::new(word(&req["capacity_deployment"], "path")?);
    ensure!(
        refpath.parent().and_then(Path::parent) == Some(Path::new(PROVIDERS)),
        "foreign provider deployment"
    );
    let program = member(&req["capacity_deployment"], "post-stop-fit")?;
    let b = available()?;
    let phys0 = du(LANE)?;
    let mut args = vec![
        "120".to_owned(),
        "/usr/bin/python3".to_owned(),
        "-IB".to_owned(),
        program.to_string_lossy().into_owned(),
        "--full170=retained".to_owned(),
    ];
    for (key, flag) in [
        ("full146_request", "--full146-request"),
        ("joint168_request", "--joint168-request"),
        ("replacement167_request", "--replacement167-request"),
        ("active167_intent", "--bounded167-request"),
        ("active167_first_guard", "--bounded167-first-guard"),
    ] {
        if key.starts_with("active") && req[key].is_null() {
            continue;
        }
        bound(&req[key])?;
        args.extend([
            flag.to_owned(),
            word(&req[key], "path")?.into(),
            word(&req[key], "sha256")?.into(),
        ]);
    }
    args.extend([
        "145".to_owned(),
        word(fleet_ref, "path")?.into(),
        word(fleet_ref, "sha256")?.into(),
    ]);
    let raw = command("/usr/bin/timeout", &args)?;
    let quote: Value = serde_json::from_str(&raw)?;
    let repl = &quote["replacement167_fit"];
    let p = &quote["full146"]["native_successor_quote"];
    ensure!(
        quote["schema"] == "horizon-epoch168-joint-reduced-combined-fit-v1"
            && quote["fleet"] == *fleet_ref
            && p["fleet"] == *fleet_ref
            && p["fits"] == true
            && repl["fits"] == true
            && quote["replay_launch_authorized"] == false
            && repl["resource_credit_bytes"] == 0,
        "complete native provider rejected 167 or retained fleet"
    );
    let when = num(&quote, "recorded_unix_seconds")?;
    ensure!(
        when <= now()? && now()? - when <= 110,
        "stale complete provider"
    );
    ensure!(
        quote["full146"]["retained_185_restore_overlap_bytes"] == 123_350_028_052u64
            && quote["full146"]["retained_185_restore_enlargement_bytes"] == 54_016_054_271u64,
        "185 restore commitments changed"
    );
    let book = &p["bookings"]["170"];
    ensure!(
        book["root"] == LANE && book["cap_bytes"] == 384 * G,
        "original 170 booking changed"
    );
    let phys1 = du(LANE)?;
    let native_physical = num(book, "physical_bytes")?;
    ensure!(
        phys0 == phys1 && native_physical == phys0,
        "unstable 170 tree; reprice"
    );
    let a = available()?;
    let home =
        a.0.min(b.0)
            .min(num(repl, "available_HOME_bytes")?)
            .min(num(&f, "complete_cycle_conservative_available_DATA_bytes")?);
    let ram = a.1.min(b.1).min(num(repl, "available_memory_bytes")?);
    let ram_required = num(repl, "required_available_memory_bytes")?;
    ensure!(
        ram >= ram_required,
        "complete RAM budget exceeds available by {} bytes",
        ram_required.saturating_sub(ram)
    );
    let mem = num(&repl["scope"], "producer_memory_bytes")?;
    ensure!(
        mem >= 42 * G && num(&repl["scope"], "guard_memory_bytes")? >= G,
        "future 167 envelope undercharged"
    );
    let ag = num(repl, "existing_reserved_HOME_bytes")?
        .max(num(
            &repl["candidate_guard_counterfactual"],
            "required_candidate_floor_bytes",
        )?)
        .max(num(repl, "protected_home_floor_bytes")?);
    let armed167 = guard167_minimum(repl)?;
    let growth167 = num(repl, "bounded_growth_remaining_bytes")?;
    let frozen = held
        .map(|v| Ok::<_, anyhow::Error>((num(v, "armed_floor")?, num(v, "bounded_cap_bytes")?)))
        .transpose()?;
    let (floor, cap, required) = bounds(384 * G, phys0, ag, armed167, growth167, home, frozen)?;
    ensure!(
        observer == writer(&req["writer"])? && bound(fleet_ref)? == f && bound(request)? == req,
        "writer or price input changed"
    );
    let populated = quote["joined_native_population"]
        .as_object()
        .context("missing full census")?;
    for (unit, pairs) in populated {
        let state = props(unit, "Id,ActiveState,MainPID,InvocationID,Job")?;
        let rows = pairs.as_array().context("no native operator rows")?;
        ensure!(
            !rows.is_empty()
                && state["ActiveState"] == "active"
                && state["Job"].is_empty()
                && state["MainPID"].parse::<u64>()?
                    == rows[0][0].as_u64().context("incumbent main PID")?,
            "incumbent {unit} changed"
        );
        for row in rows {
            ensure!(
                ticks(u32::try_from(row[0].as_u64().context("pid")?)?)?
                    == row[1].as_u64().context("start ticks")?,
                "incumbent PID recycled"
            )
        }
    }
    Ok(
        json!({"recorded_unix_seconds":when,"fleet":fleet_ref,"writer_binding":req["writer"],"writer":observer,"provider":req["capacity_deployment"],"raw_quote_sha256":digest(raw.as_bytes()),"population":populated,"available_home":home,"required_home":required,"available_ram":ram,"required_ram":ram_required,"existing_floor":ag,"armed_167_floor":armed167,"167_remaining":growth167,"physical":phys0,"armed_floor":floor,"bounded_cap_bytes":cap,"growth_bytes":cap-phys0,"retained_185_overlap":123_350_028_052u64,"retained_185_restore_enlargement":54_016_054_271u64,"retained_170_memory":68*G,"resource_credit_bytes":0}),
    )
}

fn capture_released(
    request: &Value,
    req: &Value,
    fleet: &Value,
    observer: &Value,
    held: Option<&Value>,
) -> Result<Value> {
    ensure!(
        req["capacity_deployment"]["sha256"]
            == "2cbcbe3b3968517734da644588c4dd5dbacfa8750945a881ca81e2297abe88dd"
            && req["native_reference"]["sha256"]
                == "7319e4bc8c2423b8f653c8e84cd64e74287699de13ff5a73cfd2880731055413"
            && req["writer"]["seal"]["sha256"]
                == "d62ac67045ac3162352ba27202dee7aed63521ba7ba50f3fc816b4b9d78d0b33"
            && req["released167"]["sha256"]
                == "73f8574108e0f207b44f91fda555f8ea6311dbf67a5e32d88233a4f46a1ec65f",
        "unregistered released 167 price"
    );
    let adapter = member(&static_package()?, "live_price.py")?;
    let before = available()?;
    let physical = du(LANE)?;
    let native: Value = serde_json::from_str(&command(
        "/usr/bin/python3",
        &[
            "-IB",
            adapter.to_str().context("operator path")?,
            word(request, "path")?,
            word(request, "sha256")?,
            if held.is_some() { "held" } else { "prestart" },
        ],
    )?)?;
    let after = available()?;
    if let Some(intent) = held {
        // The waiting gate writes its readiness and heartbeat to the already-bound append log.
        let log = fs::metadata(Path::new(RUN).join("producer.log"))?;
        let old = num(&native["old170_book"], "physical_bytes")?;
        ensure!(
            log.dev() == num(&intent["append_log"], "device")?
                && log.ino() == num(&intent["append_log"], "inode")?
                && log.len() < 65536
                && old.checked_add(log.blocks() * 512) == Some(physical),
            "unaccounted growth or shrinkage in held epoch 170 tree"
        );
    }
    ensure!(
        native["fleet"] == req["fleet"]
            && native["release"] == req["released167"]
            && native["credit_bytes"] == 0
            && physical == du(LANE)?
            && (held.is_some() || native["old170_book"]["physical_bytes"] == physical)
            && native["old170_book"]["root"] == LANE
            && writer(&req["writer"])? == *observer
            && bound(&req["fleet"])? == *fleet,
        "resource scope changed across released 167 capture"
    );
    let home = before.0.min(after.0).min(num(
        fleet,
        "complete_cycle_conservative_available_DATA_bytes",
    )?);
    let ram = before.1.min(after.1);
    ensure!(ram >= num(&native, "required_ram")?, "RAM shortfall");
    let frozen = held
        .map(|v| Ok::<_, anyhow::Error>((num(v, "armed_floor")?, num(v, "bounded_cap_bytes")?)))
        .transpose()?;
    let (floor, cap, required) = bounds(
        384 * G,
        physical,
        num(&native, "aggregate")?,
        num(&native, "armed167")?,
        num(&native, "growth167")?,
        home,
        frozen,
    )?;
    Ok(
        json!({"recorded_unix_seconds":native["when"],"fleet":req["fleet"],"writer_binding":req["writer"],"writer":observer,
        "provider":req["capacity_deployment"],"released_167":native,"available_home":home,"required_home":required,
        "available_ram":ram,"required_ram":native["required_ram"],"physical":physical,"armed_floor":floor,"bounded_cap_bytes":cap,
        "growth_bytes":cap-physical,"resource_credit_bytes":0}),
    )
}
