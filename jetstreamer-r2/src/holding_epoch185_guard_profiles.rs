//! Native, read-only snapshots of the existing argv-driven adaptive guards.
//! Reuses the already sealed Python guard; does not edit or execute its logic.
use super::*;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Guard {
    pub timer_unit: String,
    pub service_unit: String,
    pub program: Bound,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capture {
    schema: String,
    mapping: Bound,
    fleet: Bound,
    guards: Vec<Guard>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Handoff {
    schema: String,
    mapping: Bound,
    fleet: Bound,
    existing_profile: Value,
    proposed_guard: Guard,
    proposed_argv: Vec<String>,
    capacity_basis: Bound,
}
fn handoff_shape(old: &Value, proposed: &Value) -> Result<()> {
    for key in [
        "schema",
        "program",
        "controller_unit",
        "expected_controller_invocation_id",
        "producer_unit",
        "expected_producer_invocation_id",
        "maximum_worker_vmas",
    ] {
        ensure!(
            old[key] == proposed[key],
            "185 guard handoff changes script, live owner or VMA ceiling: {key}"
        );
    }
    ensure!(
        old["timer_unit"] != proposed["timer_unit"]
            && old["service_unit"] != proposed["service_unit"],
        "185 guard handoff must use new metadata names"
    );
    let old_args: Vec<String> = serde_json::from_value(old["argv"].clone())?;
    let new_args: Vec<String> = serde_json::from_value(proposed["argv"].clone())?;
    for key in ["--intent-receipt=", "--completion-receipt="] {
        let b = new_args
            .iter()
            .find_map(|a| a.strip_prefix(key))
            .context("new guard frontier missing")?;
        ensure!(
            !old_args
                .iter()
                .filter_map(|a| a
                    .strip_prefix("--intent-receipt=")
                    .or_else(|| a.strip_prefix("--completion-receipt=")))
                .any(|a| a == b),
            "185 guard handoff cannot reuse old durable frontier"
        );
    }
    Ok(())
}
pub(super) fn plan_handoff(m: &Mapping, p: &Handoff, spec: &Bound) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-old185-guard-handoff-proposal-plan-v2",
        "185 guard handoff plan schema differs"
    );
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "185 guard handoff mapping differs"
    );
    let fleet = evidence(&p.fleet, false)?;
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200,
        "185 guard handoff needs full fleet evidence"
    );
    // Authenticate the review material, but do not pretend this planner has
    // independently reconstructed its claims or admitted a lower safety floor.
    let _ = bound(&p.capacity_basis)?;
    let old = verify(&p.existing_profile)?;
    restore_owners(&json!({"owners":[
        {"unit":old["controller_unit"],"invocation_id":old["expected_controller_invocation_id"]},
        {"unit":old["producer_unit"],"invocation_id":old["expected_producer_invocation_id"]}
    ]}))?;
    let proposed = normalize(&p.proposed_guard, &p.proposed_argv)?;
    script(&p.proposed_guard.program)?;
    handoff_shape(&old, &proposed)?;
    let path = Path::new(STATE).join("receipts").join(format!(
        "old185-guard-handoff-proposal-{}.json",
        spec.sha256
    ));
    persist(
        &path,
        &json!({"schema":"jetstreamer-horizon-old185-guard-handoff-proposal-v2",
        "spec":spec,"fleet":p.fleet,"capacity_basis":p.capacity_basis,"existing_profile":old,"proposed_profile":proposed,
        "planning_only":true,"capacity_basis_independently_validated":false,
        "required_commit_frontiers":["review fresh all-claims capacity admission and authenticated closure",
            "preserve old raw argv, immutable config and journal outside staged scanner roots",
            "persist hash-bound intent and install new metadata without restarting either live owner",
            "arm new two-minute guard and prove a first native successful healthy fire with unchanged owner IIDs",
            "retire old metadata timer only after durable first-fire evidence and fresh owner race check",
            "write retry-safe completion; preserve both failure frontiers without duplicate capacity credit"],
        "guard_or_replay_mutations":false,"guard_floor_mutations_authorized":false,
        "reservation_disposition_authorized":false,"new_replay_or_restore_authorized":false,"r2_mutations":false}),
    )?;
    println!("{}", path.display());
    Ok(())
}
fn safe_unit(s: &str, suffix: &str) -> bool {
    s.starts_with("jetstreamer-")
        && s.ends_with(suffix)
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
}
fn unit(name: &str) -> Result<Value> {
    ensure!(
        safe_unit(name, ".service") || safe_unit(name, ".timer"),
        "foreign 185 guard unit name"
    );
    let out = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "show",
            name,
            "--all",
            "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,InvocationID,Triggers,Job",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16384,
        "185 guard unit metadata unavailable"
    );
    let mut m = serde_json::Map::new();
    for l in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = l.split_once('=').context("185 guard manager framing")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate 185 guard property"
        );
    }
    Ok(Value::Object(m))
}
fn object(name: &str) -> String {
    let mut p = String::from("/org/freedesktop/systemd1/unit/");
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() {
            p.push(char::from(b));
        } else {
            p.push_str(&format!("_{b:02x}"));
        }
    }
    p
}
fn native_argv(name: &str) -> Result<Vec<String>> {
    let out = std::process::Command::new("/usr/bin/busctl")
        .args([
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            &object(name),
            "org.freedesktop.systemd1.Service",
            "ExecStart",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "185 guard native ExecStart unreadable"
    );
    decode_exec(&serde_json::from_slice(&out.stdout)?)
}
fn decode_exec(v: &Value) -> Result<Vec<String>> {
    ensure!(
        v["type"] == "a(sasbttttuii)",
        "185 guard ExecStart signature differs"
    );
    let rows = v["data"].as_array().context("185 guard ExecStart rows")?;
    ensure!(rows.len() == 1, "185 guard must have one native ExecStart");
    let row = rows[0].as_array().context("185 guard command tuple")?;
    ensure!(
        row.len() == 10 && row[0] == "/usr/bin/python3" && row[2] == false,
        "185 guard interpreter/ignore-errors differs"
    );
    let args: Vec<String> = serde_json::from_value(row[1].clone())?;
    ensure!(
        args.first().is_some_and(|s| s == "/usr/bin/python3"),
        "185 guard argv 0 differs"
    );
    Ok(args)
}
fn script(b: &Bound) -> Result<()> {
    ensure!(
        b.path.starts_with("/usr/local/lib/jetstreamer")
            && b.path
                .file_name()
                .is_some_and(|s| s == "guard-adaptive-replay-reserve.py")
            && digest(&b.sha256),
        "185 guard script scope differs"
    );
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && b.path.canonicalize()? == b.path,
        "185 guard script is not sealed"
    );
    ensure!(
        hex_lower(&Sha256::digest(read_stable_bounded(
            &b.path,
            1 << 20,
            "185 sealed guard script"
        )?)) == b.sha256,
        "185 guard script digest differs"
    );
    Ok(())
}
pub(super) fn normalize(g: &Guard, args: &[String]) -> Result<Value> {
    ensure!(
        safe_unit(&g.timer_unit, ".timer")
            && safe_unit(&g.service_unit, ".service")
            && args.len() == 12
            && args[0] == "/usr/bin/python3"
            && Path::new(&args[1]) == g.program.path,
        "185 guard command is not the existing guard interpreter/script"
    );
    let mut flags = std::collections::BTreeMap::new();
    for arg in &args[2..] {
        let (k, v) = arg
            .split_once('=')
            .context("185 guard needs exact --name=value argv")?;
        ensure!(flags.insert(k, v).is_none(), "duplicate 185 guard flag");
    }
    let names = [
        "--controller-unit",
        "--expected-controller-invocation-id",
        "--producer-unit",
        "--expected-producer-invocation-id",
        "--filesystem",
        "--minimum-free-bytes",
        "--maximum-worker-vmas",
        "--guard-timer",
        "--intent-receipt",
        "--completion-receipt",
    ];
    ensure!(
        flags
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            == names.into_iter().collect()
            && flags["--filesystem"] == "/home/sol"
            && flags["--guard-timer"] == g.timer_unit,
        "185 guard has unknown scope/flags"
    );
    let floor = flags["--minimum-free-bytes"].parse::<u64>()?;
    let vmas = flags["--maximum-worker-vmas"].parse::<u64>()?;
    ensure!(floor > 0 && vmas > 0, "185 guard floor/VMA ceiling missing");
    for key in ["--controller-unit", "--producer-unit"] {
        ensure!(
            safe_unit(flags[key], ".service"),
            "185 guard owner unit malformed"
        );
    }
    for key in [
        "--expected-controller-invocation-id",
        "--expected-producer-invocation-id",
    ] {
        let s = flags[key];
        ensure!(
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "185 guard invocation identity malformed"
        );
    }
    for key in ["--intent-receipt", "--completion-receipt"] {
        ensure!(
            Path::new(flags[key]).is_absolute()
                && flags[key].starts_with("/var/lib/jetstreamer-adaptive-reserve-")
                && flags[key][1..]
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
                && Path::new(flags[key]).components().all(|c| matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )),
            "185 guard receipt namespace differs"
        );
    }
    ensure!(
        flags["--intent-receipt"] != flags["--completion-receipt"],
        "185 guard receipt frontiers collide"
    );
    Ok(
        json!({"schema":"jetstreamer-horizon-existing-adaptive-guard-profile-v2","timer_unit":g.timer_unit,"service_unit":g.service_unit,
        "program":g.program,"argv":args,"controller_unit":flags["--controller-unit"],"expected_controller_invocation_id":flags["--expected-controller-invocation-id"],
        "producer_unit":flags["--producer-unit"],"expected_producer_invocation_id":flags["--expected-producer-invocation-id"],
        "minimum_free_bytes":floor,"maximum_worker_vmas":vmas,"guard_or_replay_mutations":false}),
    )
}
pub(super) fn verify(v: &Value) -> Result<Value> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-existing-adaptive-guard-profile-v2",
        "185 guard snapshot schema differs"
    );
    let g = Guard {
        timer_unit: v["timer_unit"].as_str().context("185 guard timer")?.into(),
        service_unit: v["service_unit"]
            .as_str()
            .context("185 guard service")?
            .into(),
        program: serde_json::from_value(v["program"].clone())?,
    };
    snapshot(&g).and_then(|current| {
        ensure!(current == *v, "185 guard profile/argv changed");
        Ok(current)
    })
}
fn snapshot(g: &Guard) -> Result<Value> {
    script(&g.program)?;
    let before = unit(&g.timer_unit)?;
    ensure!(
        before["Id"] == g.timer_unit
            && before["LoadState"] == "loaded"
            && before["ActiveState"] == "active"
            && matches!(before["SubState"].as_str(), Some("waiting" | "running"))
            && before["Triggers"] == g.service_unit
            && before["Job"] == "",
        "185 guard timer is not armed for exact service"
    );
    let service = unit(&g.service_unit)?;
    ensure!(
        service["LoadState"] == "loaded",
        "185 guard service unavailable"
    );
    let args = native_argv(&g.service_unit)?;
    let value = normalize(g, &args)?;
    let after = unit(&g.timer_unit)?;
    for key in [
        "Id",
        "LoadState",
        "ActiveState",
        "InvocationID",
        "Triggers",
        "Job",
    ] {
        ensure!(
            before[key] == after[key],
            "185 guard timer changed across snapshot"
        );
    }
    ensure!(
        native_argv(&g.service_unit)? == args,
        "185 guard argv changed across snapshot"
    );
    Ok(value)
}
pub(super) fn capture(m: &Mapping, p: &Capture, spec: &Bound) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-old185-survivor-guard-capture-plan-v2"
            && !p.guards.is_empty()
            && p.guards.len() <= 16,
        "185 guard capture scope differs"
    );
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "185 guard capture mapping differs"
    );
    let f = evidence(&p.fleet, false)?;
    ensure!(
        f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200,
        "185 guard capture needs full fleet"
    );
    let mut timers = std::collections::BTreeSet::new();
    let mut services = std::collections::BTreeSet::new();
    let mut profiles = Vec::new();
    for g in &p.guards {
        ensure!(
            timers.insert(g.timer_unit.clone()) && services.insert(g.service_unit.clone()),
            "duplicate 185 guard capture"
        );
        profiles.push(snapshot(g)?);
    }
    let path = Path::new(STATE)
        .join("receipts")
        .join(format!("old185-survivor-guards-{}.json", spec.sha256));
    persist(
        &path,
        &json!({"schema":"jetstreamer-horizon-old185-survivor-guards-v2","host":HOST,"fleet":p.fleet,"profiles":profiles,
        "spec":spec,"new_resource_samples":0,"guard_or_replay_mutations":false,"r2_mutations":false}),
    )?;
    println!("{}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> (Guard, Vec<String>) {
        let g = Guard {
            timer_unit: "jetstreamer-test.timer".into(),
            service_unit: "jetstreamer-test.service".into(),
            program: Bound {
                path: "/usr/local/lib/jetstreamer/old/guard-adaptive-replay-reserve.py".into(),
                sha256: "a".repeat(64),
            },
        };
        let args = vec![
            "/usr/bin/python3".into(),
            g.program.path.to_str().unwrap().into(),
            "--controller-unit=jetstreamer-controller.service".into(),
            "--expected-controller-invocation-id=11111111111111111111111111111111".into(),
            "--producer-unit=jetstreamer-producer.service".into(),
            "--expected-producer-invocation-id=22222222222222222222222222222222".into(),
            "--filesystem=/home/sol".into(),
            "--minimum-free-bytes=3332894621696".into(),
            "--maximum-worker-vmas=800000".into(),
            "--guard-timer=jetstreamer-test.timer".into(),
            "--intent-receipt=/var/lib/jetstreamer-adaptive-reserve-test/intent.json".into(),
            "--completion-receipt=/var/lib/jetstreamer-adaptive-reserve-test/completion.json"
                .into(),
        ];
        (g, args)
    }
    #[test]
    fn normalized_guard_keeps_native_owner_ceiling_and_full_argv() {
        let (g, args) = example();
        let value = normalize(&g, &args).unwrap();
        assert_eq!(value["argv"], json!(args));
        assert_eq!(
            value["expected_producer_invocation_id"],
            "22222222222222222222222222222222"
        );
        assert_eq!(value["maximum_worker_vmas"], 800000);
        assert_eq!(value["minimum_free_bytes"], 3_332_894_621_696u64);
        assert_eq!(value["guard_or_replay_mutations"], false);
    }
    #[test]
    fn rejects_unknown_duplicate_missing_aliased_and_unsafe_argv() {
        let (g, args) = example();
        for (i, replacement) in [
            (0, "/usr/bin/env"),
            (1, "/tmp/guard-adaptive-replay-reserve.py"),
            (2, "--controller-unit=../escape.service"),
            (3, "--expected-controller-invocation-id=bad"),
            (4, "--unknown=jetstreamer-producer.service"),
            (5, "--expected-producer-invocation-id=0"),
            (6, "--filesystem=/"),
            (7, "--minimum-free-bytes=0"),
            (8, "--maximum-worker-vmas=0"),
            (9, "--guard-timer=jetstreamer-foreign.timer"),
            (
                10,
                "--intent-receipt=/var/lib/jetstreamer-adaptive-reserve-test/../../escape",
            ),
            (
                10,
                "--intent-receipt=/var/lib/jetstreamer-adaptive-reserve-test/./intent.json",
            ),
            (
                10,
                "--intent-receipt=/var/lib/jetstreamer-adaptive-reserve-test//intent.json",
            ),
            (11, "--completion-receipt=/tmp/completion.json"),
        ] {
            let mut bad = args.clone();
            bad[i] = replacement.into();
            assert!(normalize(&g, &bad).is_err(), "{i}: {replacement}");
        }
        let mut duplicate = args.clone();
        duplicate[11] = args[10].clone();
        assert!(normalize(&g, &duplicate).is_err());
        let mut missing = args.clone();
        missing.pop();
        assert!(normalize(&g, &missing).is_err());
        let mut extra = args.clone();
        extra.push("--unknown=yes".into());
        assert!(normalize(&g, &extra).is_err());
        let mut collision = args.clone();
        collision[11] =
            "--completion-receipt=/var/lib/jetstreamer-adaptive-reserve-test/intent.json".into();
        assert!(normalize(&g, &collision).is_err());
    }
    #[test]
    fn native_exec_requires_one_complete_nonignored_python_command() {
        let (_, args) = example();
        let valid =
            json!({"type":"a(sasbttttuii)","data":[["/usr/bin/python3",args,false,0,0,0,0,0,0,0]]});
        assert_eq!(decode_exec(&valid).unwrap(), args);
        for (key, value) in [
            ("type", json!("s")),
            ("data", json!([])),
            ("data", json!([["/usr/bin/python3", args, false]])),
            (
                "data",
                json!([["/usr/bin/python3", args, true, 0, 0, 0, 0, 0, 0, 0]]),
            ),
            (
                "data",
                json!([
                    ["/usr/bin/python3", args, false, 0, 0, 0, 0, 0, 0, 0],
                    ["/usr/bin/python3", args, false, 0, 0, 0, 0, 0, 0, 0]
                ]),
            ),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            assert!(decode_exec(&bad).is_err());
        }
    }
    #[test]
    fn handoff_preserves_live_identities_and_uses_disjoint_metadata_frontiers() {
        let (g, args) = example();
        let old = normalize(&g, &args).unwrap();
        let mut new_guard = g.clone();
        new_guard.timer_unit = "jetstreamer-new.timer".into();
        new_guard.service_unit = "jetstreamer-new.service".into();
        let mut new_args = args.clone();
        new_args[7] = "--minimum-free-bytes=3000000000000".into();
        new_args[9] = "--guard-timer=jetstreamer-new.timer".into();
        new_args[10] =
            "--intent-receipt=/var/lib/jetstreamer-adaptive-reserve-new/intent.json".into();
        new_args[11] =
            "--completion-receipt=/var/lib/jetstreamer-adaptive-reserve-new/completion.json".into();
        let proposed = normalize(&new_guard, &new_args).unwrap();
        handoff_shape(&old, &proposed).unwrap();
        for key in [
            "program",
            "expected_controller_invocation_id",
            "expected_producer_invocation_id",
            "maximum_worker_vmas",
        ] {
            let mut bad = proposed.clone();
            bad[key] = json!("changed");
            assert!(handoff_shape(&old, &bad).is_err(), "{key}");
        }
        assert!(handoff_shape(&old, &old).is_err());
        new_args[11] =
            "--completion-receipt=/var/lib/jetstreamer-adaptive-reserve-test/intent.json".into();
        let aliases_old_intent = normalize(&new_guard, &new_args).unwrap();
        assert!(handoff_shape(&old, &aliases_old_intent).is_err());
    }
}
