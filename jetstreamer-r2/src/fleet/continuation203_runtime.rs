//! One append-only, invocation-bound extension for the already executing 203 assembler.
//! Never restarts a producer, changes resource guards, or permits publication.
use super::continuation203 as c;
use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

const IID: &str = "ddf3ed2de8b040758ee7a0d696159afd";
const LAUNCH: &str =
    "/var/lib/jetstreamer/horizon-continuation203-launch-state-ed66145-v1/launch.json";
const LAUNCH_SHA: &str = "1068823c4c8f71ff78752e7319a2ff3f38c2f82c12c68df0030c98eaae7eb1f0";
const STATE: &str = "/var/lib/jetstreamer/horizon-continuation203-runtime-extension-v1";
const OUTPUT: &str =
    "/var/lib/jetstreamer/horizon-continuation203-runtime-extension-v1/completion.json";
const DROP_DIR: &str =
    "/run/systemd/system/horizon-qualify-203-checkpoint-continuation-ed66145-v1.service.d";
const DROP: &str = "/run/systemd/system/horizon-qualify-203-checkpoint-continuation-ed66145-v1.service.d/90-assembly-runtime.conf";
const CONTENT: &[u8] = b"[Service]\nRuntimeMaxSec=12h\n";
const GUARDS: &str = "/var/lib/jetstreamer/horizon-continuation203-guard-receipts-ed66145-v1";
const FIXTURE: &str = "horizon-runtime-extension-reload-fixture-0510-v1.service";
const FIXTURE_IID: &str = "24bbb578490c4daab0ed7934ab87a5e2";
const OLD213: &str = "horizon-qualify-213-checkpoint-continuation-ae43646-v1.service";
const OLD213_IID: &str = "1dfd29e7ced140b3ba407359cbdc0ee1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    launch: BoundFile,
    output: PathBuf,
}
fn scope(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == "jetstreamer-private203-runtime-extension-spec-v1"
            && s.launch.path == Path::new(LAUNCH)
            && s.launch.sha256 == LAUNCH_SHA
            && s.output == Path::new(OUTPUT),
        "203 extension scope differs"
    );
    Ok(())
}
fn command(args: &[&str]) -> Result<Vec<u8>> {
    let o = ProcessCommand::new(args[0]).args(&args[1..]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 4 << 20,
        "203 extension subprocess failed:{}:{}",
        args[0],
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(o.stdout)
}
fn rows(bytes: &[u8]) -> Result<Vec<Value>> {
    std::str::from_utf8(bytes)?
        .lines()
        .filter(|s| !s.is_empty())
        .map(|s| Ok(serde_json::from_str(s)?))
        .collect()
}
fn journal(unit: &str, grep: &str) -> Result<Vec<Value>> {
    rows(&command(&[
        "journalctl",
        "--unit",
        unit,
        "--no-pager",
        "--output=json",
        "--grep",
        grep,
    ])?)
}
fn event(v: &[Value], iid: &str, marker: &str, manager: bool) -> Result<u64> {
    let matches: Vec<_> = v
        .iter()
        .filter(|r| {
            r[if manager {
                "INVOCATION_ID"
            } else {
                "_SYSTEMD_INVOCATION_ID"
            }] == iid
                && (!manager || r["_PID"] == "1")
                && r["MESSAGE"].as_str().is_some_and(|s| s.contains(marker))
        })
        .collect();
    ensure!(
        matches.len() == 1,
        "missing/ambiguous bound journal event:{marker}"
    );
    Ok(matches[0]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("event time")?
        .parse()?)
}
fn evidence(v: &Value) -> Result<()> {
    let list = |k: &str| v[k].as_array().context("203 missing evidence rows");
    let a = event(
        list("actual203")?,
        IID,
        "private203 native restart barrier passed before any suffix entry",
        false,
    )?;
    let b = event(
        list("actual203")?,
        IID,
        "private203 suffix replay returned",
        false,
    )?;
    ensure!(b > a && b - a < 600_000_000, "203 suffix sequence differs");
    let a = event(
        list("fixture")?,
        FIXTURE_IID,
        "Started horizon-runtime-extension-reload-fixture-0510-v1.service",
        true,
    )?;
    let b = event(
        list("fixture")?,
        FIXTURE_IID,
        "Deactivated successfully.",
        true,
    )?;
    ensure!(
        (79_000_000..=85_000_000).contains(&(b.checked_sub(a).context("fixture time inversion")?)),
        "runtime fixture did not survive original 20s and finish 80s sleep"
    );
    let a = event(
        list("historical213")?,
        OLD213_IID,
        "horizon archive complete:",
        false,
    )?;
    let b = event(
        list("historical213")?,
        OLD213_IID,
        "private epoch213 checkpoint continuation assembled",
        false,
    )?;
    ensure!(
        (27_000_000_000..29_000_000_000)
            .contains(&(b.checked_sub(a).context("213 time inversion")?)),
        "historical 213 assembly evidence differs"
    );
    Ok(())
}
fn owner(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == c::UNIT
            && v["InvocationID"] == IID
            && v["MainPID"] == "3634151"
            && v["NRestarts"] == "0"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["Result"] == "success"
            && v["Type"] == "exec",
        "203 extension lost exact live owner"
    );
    Ok(())
}
fn same_owner(a: &Value, b: &Value) -> Result<()> {
    owner(a)?;
    owner(b)?;
    for key in ["Id", "InvocationID", "MainPID", "NRestarts", "ControlGroup"] {
        ensure!(a[key] == b[key], "203 extension changed live owner:{key}");
    }
    let cmd = |v: &Value| {
        v["ExecStart"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .map(|(s, _)| s.to_owned())
    };
    ensure!(
        cmd(a).is_some() && cmd(a) == cmd(b),
        "203 extension changed command"
    );
    Ok(())
}
fn fresh_guard(v: &Value, now: u64) -> Result<()> {
    let time = v["recorded_unix_seconds"].as_u64().context("guard time")?;
    ensure!(
        time <= now
            && now - time <= 180
            && v["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && v["guard_sha256"] == c::GUARD_SHA
            && v["producer_invocation_id"] == IID
            && v["producer"]["pid"] == 3634151
            && v["producer"]["active"] == "active"
            && v["producer"]["restarts"] == 0
            && v["trip_reason"].is_null()
            && v["worker_observation_error"].is_null()
            && v["maximum_worker_vmas"] == 3500000
            && v["minimum_free_bytes"] == 3_284_969_447_424u64
            && v["available_bytes"]
                .as_u64()
                .is_some_and(|n| n > 3_284_969_447_424)
            && v["workers"].as_array().is_some_and(Vec::is_empty),
        "203 extension requires fresh protected post-suffix guard"
    );
    Ok(())
}
fn guard() -> Result<(BoundFile, Value)> {
    for name in ["stop-intent.json", "stop-completion.json"] {
        ensure!(
            !Path::new(GUARDS).join(name).try_exists()?,
            "203 reserve stop present"
        );
    }
    let mut best: Option<(u64, BoundFile, Value)> = None;
    for entry in fs::read_dir(GUARDS)? {
        let entry = entry?;
        let name = entry.file_name();
        if !name
            .to_str()
            .is_some_and(|s| s.starts_with("sample-") && s.ends_with(".json"))
        {
            continue;
        }
        let b: BoundFile = serde_json::from_value(private157::file_binding(&entry.path())?)?;
        let v = bound_json(&b)?;
        let time = v["recorded_unix_seconds"]
            .as_u64()
            .context("guard sample time")?;
        if best.as_ref().is_none_or(|(t, _, _)| time > *t) {
            best = Some((time, b, v));
        }
    }
    let (_, b, v) = best.context("203 no guard samples")?;
    fresh_guard(&v, SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    Ok((b, v))
}
fn timers() -> Result<BTreeMap<String, Value>> {
    let v: Vec<Value> = serde_json::from_slice(&command(&[
        "systemctl",
        "list-timers",
        "--all",
        "--output=json",
        "--no-pager",
    ])?)?;
    let mut out = BTreeMap::new();
    for timer in v {
        let name = timer["unit"].as_str().context("timer name")?;
        if name.starts_with("horizon-") && timer["next"].as_u64().is_some_and(|n| n > 0) {
            ensure!(out.insert(name.into(), timer).is_none(), "duplicate timer");
        }
    }
    ensure!(
        out.contains_key("horizon-continuation203-guard-ed66145-v1.timer"),
        "203 guard timer absent"
    );
    Ok(out)
}
fn timer_transition(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
) -> Result<()> {
    for (key, a) in before {
        let b = after.get(key).context("reload lost active timer")?;
        let old_next = a["next"].as_u64().context("old next")?;
        let old_last = a["last"].as_u64().context("old last")?;
        let new_next = b["next"].as_u64().context("timer next")?;
        let new_last = b["last"].as_u64().context("timer last")?;
        ensure!(
            a["activates"] == b["activates"]
                && (new_next <= old_next.saturating_add(2_000_000)
                    || (new_last > old_last
                        && new_next
                            <= new_last
                                .saturating_add(old_next.saturating_sub(old_last))
                                .saturating_add(2_000_000))),
            "reload delayed timer without intervening fire:{key}"
        );
    }
    Ok(())
}
pub(super) fn validate_receipt(v: &Value, claim: &DiagnosticClaim, current: &Value) -> Result<()> {
    ensure!(
        claim.unit == c::UNIT
            && claim.invocation_id == IID
            && claim.launch_receipt.path == Path::new(LAUNCH)
            && claim.launch_receipt.sha256 == LAUNCH_SHA
            && v["schema"] == "jetstreamer-private203-runtime-extension-v1"
            && v["unit"] == c::UNIT
            && v["invocation_id"] == IID
            && v["original_runtime_seconds"] == 10800
            && v["extended_runtime_seconds"] == 43200
            && v["restart_performed"] == false
            && v["resource_limits_changed"] == false
            && v["guards_changed"] == false
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false
            && v["remote_mutations"] == false
            && v["canonical_sidecar_authorized"] == false
            && v["completed"] == true,
        "203 invalid runtime extension receipt"
    );
    same_owner(&v["before"], &v["after"])?;
    same_owner(&v["after"], current)?;
    let intent = bound_json(&serde_json::from_value(v["intent"].clone())?)?;
    ensure!(
        intent["schema"] == "jetstreamer-private203-runtime-extension-intent-v1"
            && intent["unit"] == c::UNIT
            && intent["invocation_id"] == IID
            && intent["before"] == v["before"]
            && intent["launch"]["sha256"] == LAUNCH_SHA
            && intent["launch"]["path"] == LAUNCH
            && intent["helper_sha256"] == v["helper_sha256"]
            && canonical_digest(&v["helper_sha256"])
            && intent["spec"] == v["spec"]
            && intent["original_runtime_seconds"] == 10800
            && intent["extended_runtime_seconds"] == 43200
            && intent["publication_authorized"] == false
            && intent["r2_mutations"] == false,
        "203 extension intent differs"
    );
    let spec: Spec =
        serde_json::from_value(bound_json(&serde_json::from_value(v["spec"].clone())?)?)?;
    scope(&spec)?;
    let gb: BoundFile = serde_json::from_value(intent["guard"].clone())?;
    let g = bound_json(&gb)?;
    ensure!(g == intent["guard_sample"], "203 extension guard differs");
    let time = intent["recorded_unix_seconds"]
        .as_u64()
        .context("extension intent time")?;
    fresh_guard(&g, time)?;
    ensure!(
        v["recorded_unix_seconds"]
            .as_u64()
            .is_some_and(|n| n >= time && n - time <= 180),
        "203 extension completion not timely"
    );
    timer_transition(
        &serde_json::from_value(intent["timers_before"].clone())?,
        &serde_json::from_value(v["timers_after"].clone())?,
    )?;
    evidence(&intent["evidence"])?;
    let metadata = fs::symlink_metadata(DROP)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && fs::read(DROP)? == CONTENT,
        "203 runtime drop-in differs"
    );
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        (args.len() == 7 || (args.len() == 8 && args[7] == "--check-only"))
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: extend-continuation203-runtime SPEC --spec-sha256 SHA --self-sha256 SHA [--check-only] (root)"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(&exe)?;
    ensure!(
        m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "203 extension helper unsealed"
    );
    let sb = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let s: Spec = serde_json::from_value(bound_json(&sb)?)?;
    scope(&s)?;
    let before = unit(c::UNIT)?;
    owner(&before)?;
    let claim = DiagnosticClaim {
        epoch: 203,
        unit: c::UNIT.into(),
        invocation_id: IID.into(),
        scratch_path: c::ROOT.into(),
        launch_receipt: BoundFile {
            path: PathBuf::from(LAUNCH),
            sha256: LAUNCH_SHA.into(),
        },
    };
    c::validate_live(&claim, &before, None)?;
    let (gb, gv) = guard()?;
    let evidence = json!({"actual203":journal(c::UNIT,"private203 native restart barrier passed|private203 suffix replay returned")?,
        "fixture":journal(FIXTURE,"Started |Deactivated successfully")?,
        "historical213":journal(OLD213,"horizon archive complete:|private epoch213 checkpoint continuation assembled")?});
    self::evidence(&evidence)?;
    let timers_before = timers()?;
    validate_output_destination(&s.output)?;
    let intent = Path::new(STATE).join("intent.json");
    validate_output_destination(&intent)?;
    ensure!(
        !Path::new(DROP_DIR).try_exists()?,
        "203 existing drop-in directory; preserve it"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if args.len() == 8 {
        println!(
            "{}",
            json!({"schema":"jetstreamer-private203-runtime-extension-preflight-v1",
            "passed":true,"unit":c::UNIT,"invocation_id":IID,"before":before,
            "guard":private157::binding(&gb),"evidence":evidence,"timers_before":timers_before,
            "helper_sha256":args[6],"spec":private157::binding(&sb),"runtime_changed":false,
            "restart_performed":false,"publication_authorized":false,"r2_mutations":false})
        );
        return Ok(());
    }
    private157::immutable_receipt(
        &intent,
        &json!({"schema":"jetstreamer-private203-runtime-extension-intent-v1",
        "unit":c::UNIT,"invocation_id":IID,"before":before,"launch":private157::binding(&s.launch),
        "spec":private157::binding(&sb),"helper_sha256":args[6],"guard":private157::binding(&gb),"guard_sample":gv,
        "evidence":evidence,"timers_before":timers_before,"recorded_unix_seconds":now,
        "original_runtime_seconds":10800,"extended_runtime_seconds":43200,"publication_authorized":false,"r2_mutations":false}),
    )?;
    same_owner(&before, &unit(c::UNIT)?)?;
    fs::DirBuilder::new().mode(0o755).create(DROP_DIR)?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(DROP)?;
    file.write_all(CONTENT)?;
    file.sync_all()?;
    File::open(DROP_DIR)?.sync_all()?;
    File::open("/run/systemd/system")?.sync_all()?;
    command(&["systemctl", "daemon-reload"])?;
    let after = unit(c::UNIT)?;
    same_owner(&before, &after)?;
    c::live_limits_for("12h")?;
    let timers_after = timers()?;
    timer_transition(&timers_before, &timers_after)?;
    let receipt = json!({"schema":"jetstreamer-private203-runtime-extension-v1","unit":c::UNIT,
        "invocation_id":IID,"before":before,"after":after,"intent":private157::file_binding(&intent)?,
        "helper_sha256":args[6],"spec":private157::binding(&sb),"timers_after":timers_after,
        "original_runtime_seconds":10800,"extended_runtime_seconds":43200,"completed":true,
        "restart_performed":false,"resource_limits_changed":false,"guards_changed":false,
        "publication_authorized":false,"r2_mutations":false,"remote_mutations":false,"canonical_sidecar_authorized":false,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()});
    validate_receipt(&receipt, &claim, &after)?;
    private157::immutable_receipt(&s.output, &receipt)?;
    println!(
        "203 assembly runtime extended3h->12h without restart; all other limits/guards unchanged"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unbound_authority_and_foreign_owner_before_side_effects() {
        let mut s = Spec {
            schema: "jetstreamer-private203-runtime-extension-spec-v1".into(),
            launch: BoundFile {
                path: LAUNCH.into(),
                sha256: LAUNCH_SHA.into(),
            },
            output: OUTPUT.into(),
        };
        scope(&s).unwrap();
        s.output = PathBuf::from("/tmp/completion.json");
        assert!(scope(&s).is_err());
        s.output = OUTPUT.into();
        s.launch.sha256 = "f".repeat(64);
        assert!(scope(&s).is_err());
        assert!(owner(&json!({"Id":c::UNIT,"InvocationID":"other"})).is_err());
        assert!(
            serde_json::from_value::<Spec>(json!({"schema":"x","launch":s.launch,
            "output":OUTPUT,"publication_authorized":true}))
            .is_err()
        );
    }
    #[test]
    fn timer_reload_must_not_delay_unfired_deadlines() {
        let a = BTreeMap::from([(
            "timer".into(),
            json!({"next":10000000,"last":0,"activates":"guard.service"}),
        )]);
        let mut b = a.clone();
        b.get_mut("timer").unwrap()["next"] = json!(9000000);
        timer_transition(&a, &b).unwrap();
        b.get_mut("timer").unwrap()["next"] = json!(70000000);
        assert!(timer_transition(&a, &b).is_err());
        b.get_mut("timer").unwrap()["last"] = json!(10000000);
        assert!(timer_transition(&a, &b).is_err()); // A fire does not excuse arbitrary delay.
        b.get_mut("timer").unwrap()["next"] = json!(20000000);
        timer_transition(&a, &b).unwrap();
        assert!(timer_transition(&a, &BTreeMap::new()).is_err());
    }
    #[test]
    fn journal_event_requires_exact_invocation_and_pid1_for_manager() {
        let row = json!({"INVOCATION_ID":FIXTURE_IID,"_PID":"1","MESSAGE":"Started fixture","__REALTIME_TIMESTAMP":"123"});
        assert_eq!(
            event(std::slice::from_ref(&row), FIXTURE_IID, "Started", true).unwrap(),
            123
        );
        assert!(event(std::slice::from_ref(&row), "other", "Started", true).is_err());
        assert!(event(&[row.clone(), row], FIXTURE_IID, "Started", true).is_err());
        assert!(evidence(&json!({"actual203":[],"fixture":[],"historical213":[]})).is_err());
    }
    #[test]
    fn post_suffix_guard_must_be_fresh_and_keep_full_protected_floor() {
        let v = json!({"recorded_unix_seconds":1000,"schema":"jetstreamer-horizon-standalone-guard-sample-v1",
            "guard_sha256":c::GUARD_SHA,"producer_invocation_id":IID,"producer":{"pid":3634151,"active":"active","restarts":0},
            "trip_reason":null,"worker_observation_error":null,"maximum_worker_vmas":3500000,
            "minimum_free_bytes":3284969447424u64,"available_bytes":3500000000000u64,"workers":[]});
        fresh_guard(&v, 1001).unwrap();
        assert!(fresh_guard(&v, 1181).is_err());
        assert!(fresh_guard(&v, 999).is_err());
        for (key, bad) in [
            ("minimum_free_bytes", json!(1)),
            ("workers", json!([[123, 400]])),
            ("trip_reason", json!("reserve")),
            ("worker_observation_error", json!("unreadable")),
        ] {
            let mut w = v.clone();
            w[key] = bad;
            assert!(fresh_guard(&w, 1001).is_err(), "{key}");
        }
    }
}
