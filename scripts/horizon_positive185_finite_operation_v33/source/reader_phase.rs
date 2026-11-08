//! Finite advisory timing gate. The unchanged full reader retains every native
//! authority check; a failed guard is never described as safety coverage here.
use crate::*;
const GUARD: &str = "horizon-guard145-prefix-shared72h-20261107-v8g1.service";
const TIMER: &str = "horizon-guard145-prefix-shared72h-20261107-v8g1.timer";
const TIMER_IID: &str = "f6f2308db2dc47be8f470030fb587b90";
const READER: &str = "horizon-failed4-current-accounting-reader-20261104-v1.service";
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,Job,NRestarts,ExecMainCode,ExecMainStatus,ExecMainExitTimestampMonotonic,Result,Unit,TimersMonotonic,NextElapseUSecMonotonic";
fn mono() -> Result<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } == 0
            && t.tv_sec >= 0
            && t.tv_nsec >= 0,
        "monotonic phase clock"
    );
    (t.tv_sec as u64)
        .checked_mul(1000000)
        .and_then(|v| v.checked_add(t.tv_nsec as u64 / 1000))
        .context("monotonic overflow")
}
fn span(raw: &str) -> Result<u64> {
    let mut sum = 0u64;
    for word in raw.split_whitespace() {
        let i = word
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .context("native phase timespan unit")?;
        let (num, unit) = word.split_at(i);
        let mult = match unit {
            "us" => 1,
            "ms" => 1000,
            "s" => 1000000,
            "min" => 60000000,
            "h" => 3600000000,
            "d" => 86400000000,
            "w" => 604800000000,
            _ => anyhow::bail!("unknown phase timespan unit"),
        };
        let (whole, f) = num.split_once('.').unwrap_or((num, ""));
        ensure!(
            !whole.is_empty() && f.len() <= 6 && f.bytes().all(|x| x.is_ascii_digit()),
            "phase duration decimal"
        );
        let scale = 10u64.pow(f.len() as u32);
        let digits = whole
            .parse::<u64>()?
            .checked_mul(scale)
            .and_then(|v| {
                v.checked_add(if f.is_empty() {
                    0
                } else {
                    f.parse().unwrap_or(u64::MAX)
                })
            })
            .context("phase duration overflow")?;
        let prod = digits.checked_mul(mult).context("phase scale overflow")?;
        ensure!(prod % scale == 0, "nonintegral phase micros");
        sum = sum
            .checked_add(prod / scale)
            .context("phase sum overflow")?;
    }
    ensure!(sum > 0, "empty/zero phase duration");
    Ok(sum)
}
fn query(r: &mut process::Runner<'_>, unit: &str) -> Result<Value> {
    let mut c = Command::new("/usr/bin/systemctl");
    c.args(["show", unit, "--no-pager", &format!("--property={FIELDS}")]);
    let out = r.run("reader-start-phase-native", c, Duration::from_secs(5))?;
    let raw: Vec<u8> = serde_json::from_value(out["stdout_bytes"].clone())?;
    let mut v = json!({});
    let mut events = Vec::new();
    for line in std::str::from_utf8(&raw)?.lines() {
        let (k, x) = line.split_once('=').context("phase native framing")?;
        if k == "TimersMonotonic" {
            events.push(x.to_owned());
        } else {
            ensure!(v.get(k).is_none(), "duplicate phase native scalar");
            v[k] = json!(x);
        }
    }
    v["TimersMonotonic"] = json!(events);
    ensure!(
        v["Id"] == unit
            && v["LoadState"] == "loaded"
            && v["Job"] == ""
            && v["NRestarts"].as_str().is_none_or(|x| x == "0"),
        "phase native identity/job/restart"
    );
    Ok(v)
}
fn timer(t: &Value) -> Result<u64> {
    ensure!(
        t["Id"] == TIMER
            && t["InvocationID"] == TIMER_IID
            && t["ActiveState"] == "active"
            && t["SubState"] == "waiting"
            && t["Unit"] == GUARD,
        "exact existing periodic timer"
    );
    let rows = t["TimersMonotonic"]
        .as_array()
        .context("phase timer entries")?;
    ensure!(rows.len() == 2, "exact phase timer event count");
    let mut parsed = Vec::new();
    for row in rows {
        let s = row.as_str().context("timer entry string")?;
        let s = s
            .strip_prefix("{ ")
            .and_then(|s| s.strip_suffix(" }"))
            .context("timer entry braces")?;
        let (kind, rest) = s.split_once('=').context("timer kind")?;
        let (delay, at) = rest
            .split_once(" ; next_elapse=")
            .context("timer entry delimiter")?;
        parsed.push((kind.to_owned(), span(delay)?, span(at)?));
    }
    parsed.sort_by(|a, b| a.0.cmp(&b.0));
    ensure!(
        parsed.len() == 2
            && parsed[0].0 == "OnActiveUSec"
            && parsed[0].1 == 1000000
            && parsed[1].0 == "OnUnitActiveUSec"
            && parsed[1].1 == 30000000,
        "unchanged periodic timer intervals"
    );
    span(text(t, "NextElapseUSecMonotonic")?)
}
fn terminal_guard(g: &Value) -> Result<Option<u64>> {
    ensure!(
        g["Id"] == GUARD && storage::hex(text(g, "InvocationID")?, 32),
        "phase guard IID"
    );
    if g["ActiveState"] == "active"
        || g["ActiveState"] == "activating"
        || g["ActiveState"] == "deactivating"
    {
        return Ok(None);
    }
    ensure!(
        g["ActiveState"] == "failed"
            && g["SubState"] == "failed"
            && g["Result"] == "exit-code"
            && g["ExecMainCode"] == "1"
            && g["ExecMainStatus"] == "1"
            && g["MainPID"] == "0"
            && g["ControlPID"] == "0"
            && g["ControlGroup"] == "",
        "exact already-terminated145 periodic guard result; no coverage claimed"
    );
    let at = text(g, "ExecMainExitTimestampMonotonic")?.parse::<u64>()?;
    ensure!(at > 0, "original guard completion clock");
    Ok(Some(at))
}
fn phase(now: u64, exit: u64, next: u64) -> bool {
    now.checked_sub(exit)
        .is_some_and(|v| (12000000..=14000000).contains(&v))
        && next.checked_sub(now).is_some_and(|v| v >= 15000000)
}
fn wait_phase(r: &mut process::Runner<'_>) -> Result<Value> {
    let end = Instant::now() + Duration::from_secs(65);
    let mut samples = Vec::new();
    let mut heartbeat = Instant::now();
    while Instant::now() < end {
        let g = query(r, GUARD)?;
        let t = query(r, TIMER)?;
        let now = mono()?;
        if t["SubState"] == "waiting"
            && let Some(exit) = terminal_guard(&g)?
        {
            let next = timer(&t)?;
            if phase(now, exit, next) {
                let gg = query(r, GUARD)?;
                let tt = query(r, TIMER)?;
                let final_now = mono()?;
                ensure!(
                    g == gg && t == tt && phase(final_now, exit, next),
                    "phase consumed or identity changed before original command"
                );
                let evidence = json!({"schema":"horizon-current-reader-advisory-native-start-phase-v1","guard":g,"timer":t,"actual_monotonic_usec":final_now,"guard_exit_monotonic_usec":exit,"next_guard_deadline_monotonic_usec":next,"earlier_metadata_wait_samples":samples,"failed_guard_is_not_safety_coverage":true,"new_resource_samples":0,"no_guard_or_timer_mutation":true,"replay_launch_authorized":false});
                storage::save(r.root, "actual-reader-start-phase.json", &evidence)?;
                return Ok(evidence);
            }
        }
        samples.push(json!({"actual_monotonic_usec":now,"guard":g,"timer":t}));
        ensure!(samples.len() < 140, "finite phase observations");
        if heartbeat.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "reader phase wait: original guard completion/deadline has not reached admitted offset"
            );
            heartbeat = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    anyhow::bail!("no original stable phase within65s; no reader launched")
}
fn persistent_budget(clock: u64, deadline: u64, phase_wait_pending: bool) -> bool {
    clock
        .checked_add(if phase_wait_pending { 305 } else { 240 })
        .is_some_and(|end| end < deadline)
}
pub(crate) fn prepare_persistent_start(
    r: &mut process::Runner<'_>,
    original_setup_deadline: u64,
) -> Result<Value> {
    ensure!(
        persistent_budget(now()?, original_setup_deadline, true),
        "original setup cannot fund65s phase wait and unchanged240s reader/final budget"
    );
    let evidence = wait_phase(r)?;
    validate_persistent_start(r, &evidence, original_setup_deadline)?;
    Ok(evidence)
}
pub(crate) fn validate_persistent_start(
    r: &mut process::Runner<'_>,
    evidence: &Value,
    original_setup_deadline: u64,
) -> Result<()> {
    ensure!(
        persistent_budget(now()?, original_setup_deadline, false),
        "original setup reader/final budget consumed by phase wait"
    );
    let guard = query(r, GUARD)?;
    let timer = query(r, TIMER)?;
    ensure!(
        evidence["failed_guard_is_not_safety_coverage"] == true
            && guard == evidence["guard"]
            && timer == evidence["timer"]
            && phase(
                mono()?,
                n(evidence, "guard_exit_monotonic_usec")?,
                n(evidence, "next_guard_deadline_monotonic_usec")?,
            ),
        "persistent reader original phase consumed or native identity changed"
    );
    Ok(())
}
fn exact_argv(v: &Value, spec: &Bound) -> Result<Vec<String>> {
    let actual: Vec<String> = serde_json::from_value(v.clone())?;
    let mut expected: Vec<String> =
        serde_json::from_str(include_str!("reader-argv-template.json"))?;
    let i = expected
        .iter()
        .position(|s| s == "read-failed4-current-accounting")
        .context("fixed reader command")?;
    expected[i + 1] = spec.path.display().to_string();
    expected[i + 3] = spec.sha256.clone();
    ensure!(
        actual == expected,
        "reader phase transport, properties or exact image differs"
    );
    Ok(actual)
}
pub fn execute(v: &Value, r: &mut process::Runner<'_>) -> Result<()> {
    let sb = binding(&v["reader_spec"])?;
    let spec = storage::json(&sb)?;
    let observer = binding(&spec["captured141_memory_retirement"]["current"]["observer"])?;
    let obs = storage::json(&observer)?;
    let sampled = utc(text(&obs, "recorded_at_utc")?)?;
    ensure!(
        now()?.checked_sub(sampled).is_some_and(|age| age < 1650),
        "original observer cannot fund reader phase and original read"
    );
    let output =
        Path::new("/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1")
            .join(&observer.sha256);
    ensure!(
        spec["output_directory"] == output.to_string_lossy().as_ref() && !output.try_exists()?,
        "exact original reader output namespace must be unused"
    );
    let av = exact_argv(&storage::json(&binding(&v["reader_argv"])?)?, &sb)?;
    let before = r.native(READER)?;
    ensure!(
        before["ActiveState"] == "inactive"
            && before["MainPID"] == "0"
            && before["ControlPID"] == "0"
            && before["Job"] == "",
        "original reader not dormant"
    );
    let evidence = wait_phase(r)?;
    let g = query(r, GUARD)?;
    let t = query(r, TIMER)?;
    ensure!(
        g == evidence["guard"]
            && t == evidence["timer"]
            && phase(
                mono()?,
                n(&evidence, "guard_exit_monotonic_usec")?,
                n(&evidence, "next_guard_deadline_monotonic_usec")?
            ),
        "original launch phase changed"
    );
    let mut c = Command::new(&av[0]);
    c.args(&av[1..]);
    let original = r.run(
        "actual-phase-gated-original-reader",
        c,
        Duration::from_secs(635),
    )?;
    let result = process::stdout_json(&original)?;
    let proof = storage::save(r.root, "original-phase-gated-reader-outer.json", &original)?;
    println!(
        "{}",
        json!({"actual_reader_result":result,"original_reader_outer":proof,"actual_native_start_phase":process::bind_file(&r.root.join("actual-reader-start-phase.json"),4<<20)?,"no_new_observation_or_deadline_extension":true})
    );
    Ok(())
}
pub fn qualify(r: &mut process::Runner<'_>) -> Result<()> {
    let actual = wait_phase(r)?;
    println!(
        "{}",
        json!({"actual_native_phase":process::bind_file(&r.root.join("actual-reader-start-phase.json"),4<<20)?,"actual_timing":actual,"reader_launched":false,"resource_samples":0,"replay_launch_authorized":false})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persistent_wait_and_launch_preserve_the_original_deadline_budget() {
        assert!(!persistent_budget(1000, 1305, true));
        assert!(persistent_budget(1000, 1306, true));
        assert!(!persistent_budget(1065, 1305, false));
        assert!(persistent_budget(1065, 1306, false));
        assert!(!persistent_budget(u64::MAX, u64::MAX, true));
        assert!(!persistent_budget(u64::MAX, u64::MAX, false));
    }
    #[test]
    fn admitted_phase_respects_both_original_clocks() {
        assert!(phase(13000000, 0, 30000000));
        assert!(!phase(11000000, 0, 30000000));
        assert!(!phase(15000000, 0, 30000000));
        assert!(!phase(13000000, 0, 27000000));
        assert!(!phase(1, 2, 3));
    }
    #[test]
    fn native_timespan_preserves_week_and_fraction() {
        assert_eq!(span("4w 12h 16min 6.158186s").unwrap(), 2463366158186);
    }
    #[test]
    fn malformed_or_overflow_phase_span_rejected() {
        for s in [
            "",
            "0s",
            "-1s",
            "infinity",
            "1fortnight",
            "1.0000001s",
            "18446744073709551615w",
        ] {
            assert!(span(s).is_err(), "{s}");
        }
    }
    #[test]
    fn fixed_transport_rejects_extra_properties() {
        let mut av: Vec<String> =
            serde_json::from_str(include_str!("reader-argv-template.json")).unwrap();
        let i = av
            .iter()
            .position(|s| s == "read-failed4-current-accounting")
            .unwrap();
        let spec = Bound {
            path: av[i + 1].clone().into(),
            sha256: av[i + 3].clone(),
        };
        assert!(exact_argv(&json!(av), &spec).is_ok());
        av.push("--collect".into());
        assert!(exact_argv(&json!(av), &spec).is_err());
    }
    #[test]
    fn guard_running_is_not_a_terminal_phase() {
        let g = json!({"Id":GUARD,"InvocationID":"a".repeat(32),"ActiveState":"active"});
        assert!(terminal_guard(&g).unwrap().is_none());
    }
    #[test]
    fn unrecognized_guard_failure_rejected() {
        let g = json!({"Id":GUARD,"InvocationID":"a".repeat(32),"ActiveState":"failed","SubState":"failed","Result":"signal"});
        assert!(terminal_guard(&g).is_err());
    }
}
