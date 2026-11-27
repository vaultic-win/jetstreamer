//! Meter the sealed epoch 170 bridge inside its existing host reservation.
mod actor;
mod evidence;
mod price;
use anyhow::{Context, Result, bail, ensure};
use evidence::*;
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    os::unix::{fs::MetadataExt, io::AsRawFd},
    path::{Path, PathBuf},
};
const RT: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-storage-witness-recovery-20261127-v1/suffix-run-v1";
const LANE: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1/suffix-73706460-73879004-v1";
const ALIAS: &str = "/run/horizon-170-checkpoint-suffix-v1";
const UNIT: &str = "horizon-qualify-170-checkpoint-suffix-20261127-v1.service";
const GUARD_UNIT: &str = "horizon-guard-170-checkpoint-suffix-20261127-v1.service";
const TIMER: &str = "horizon-guard-170-checkpoint-suffix-20261127-v1.timer";
const NODE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch167-local-index-successor-20261121-v1/deployment/jetstreamer-node";
const WORKER_SHA: &str = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541";
const GUARD_SHA: &str = "149eb58f52392e67fd87b988014af4b5c9c9f01827a4de373382ccda2cb6e05e";
const G: u64 = 1 << 30;
fn base() -> PathBuf {
    PathBuf::from(BASE)
}
fn r(name: &str) -> Result<Value> {
    reference(&base().join(name))
}
fn row(name: &str) -> Result<Value> {
    bound(&r(name)?)
}
fn save(name: &str, data: &Value) -> Result<Value> {
    receipt(&base().join(name), data)
}
fn interface() -> Result<Value> {
    let b = base();
    let x = r("BRIDGE_ADMISSION_INTERFACE.json")?;
    ensure!(
        x["sha256"] == "3bdb3395dabfcf60c4018618ea77cef2392016818f9268f10fc5e8ebf26da7ac",
        "unreviewed 170 route"
    );
    for (file, sha) in [
        (
            "BRIDGE_NATIVE_PREFLIGHT.json",
            "7e04aee8311bef107784033977fc8289536f9d2d52e26e85a63e14e995f39721",
        ),
        (
            "BRIDGE_LAYOUT_AND_MOUNTS.json",
            "018275dabd8f0c0cf431bf284c2d8260e0ead957854976558d56e078e82422ee",
        ),
        (
            "SHARED_GUARD_SCAN_CPU_QUALIFICATION.json",
            "78b7b52fd5b5116b5fc9ecced093aabc2b8a9d0f23f66d47bf37e03d024801cd",
        ),
    ] {
        ensure!(r(file)?["sha256"] == sha, "qualified 170 packet changed")
    }
    let data = bound(&x)?;
    for name in ["base_unit", "required_unit_overlay", "gate", "guard"] {
        let f = &data[name];
        ensure!(
            reference(Path::new(word(f, "path")?))? == *f,
            "changed 170 member {name}"
        );
    }
    ensure!(
        reference(&b.join("tools/guard"))?["sha256"] == GUARD_SHA,
        "wrong guard"
    );
    let packet = row("BRIDGE_LAYOUT_AND_MOUNTS.json")?;
    let unit = b.join("service-v2").join(UNIT);
    let overlay = b.join("bridge-73726716/bridge.conf");
    let mut checked = 0;
    for bytes in [trusted(&unit)?, trusted(&overlay)?] {
        for line in std::str::from_utf8(&bytes)?.lines() {
            if let Some(v) = line.strip_prefix("BindReadOnlyPaths=") {
                let (src, dst) = v.split_once(':').context("invalid projection")?;
                let m = fs::metadata(src)?;
                let e = &packet["observed_bindings"][dst];
                ensure!(
                    e[0] == m.dev() && e[1] == m.ino() && (e[2].is_null() || e[2] == m.len()),
                    "replaced source {src}"
                );
                checked += 1;
            }
        }
    }
    ensure!(checked == 15, "wrong number of 170 projections");
    Ok(x)
}
fn static_package() -> Result<Value> {
    let path = fs::read_link("/proc/self/exe")?;
    let root = path.parent().context("missing package")?;
    ensure!(
        root.parent() == Some(base().as_path())
            && root
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("operator-v")),
        "invoke sealed 170 operator"
    );
    let seal = reference(&root.join("deployment-seal-receipt.json"))?;
    ensure!(
        member(&seal, "operator")? == path,
        "operator differs from its deployment"
    );
    Ok(seal)
}
fn cleared() -> Result<()> {
    for u in [
        UNIT,
        TIMER,
        GUARD_UNIT,
        "horizon-qualify-170-full-metered-20261124-v1.service",
    ] {
        idle(u)?;
    }
    for p in [
        base().join("barrier/allow"),
        base().join("guard-receipts/stop-intent.json"),
        Path::new(RUN).join("ledger/epoch-170.bridge-73726716.jet"),
    ] {
        ensure!(!p.try_exists()?, "occupied 170 state {}", p.display());
    }
    Ok(())
}
fn anchor() -> Result<Value> {
    let doc = row("START_INTENT.json")?;
    ensure!(
        doc["source"] == interface()?
            && doc["operator_deployment"] == static_package()?
            && doc["producer_unit"] == UNIT
            && doc["archive_publication_authorized"] == false,
        "invalid start intent"
    );
    Ok(doc)
}
fn pre(request: &Value) -> Result<Value> {
    cleared()?;
    let log = Path::new(RUN).join("producer.log");
    ensure!(
        log.metadata()?.len() == 0,
        "170 log already has a generation"
    );
    let cap = price::capture(request, None)?;
    let source = interface()?;
    let layout = row("STATIC_LAYOUT.json")?;
    Ok(
        json!({"schema":"horizon-epoch170-checkpoint-bridge-start-intent-v1","epoch":170,"producer_unit":UNIT,"producer_memory_bytes":48*G,"guard_memory_bytes":G,"source":source,"operator_deployment":static_package()?,"request":request,"prestart":cap,"bounded_cap_bytes":cap["bounded_cap_bytes"],"armed_floor":cap["armed_floor"],"append_log":layout["producer_log"],"required_home":cap["required_home"],"resource_credit_bytes":0,"archive_publication_authorized":false,"replay_launch_authorized":false}),
    )
}
fn register_actor(a: &Value) -> Result<Value> {
    let doc = json!({
        "schema":"horizon-epoch170-bridge-actor-v1", "interface":interface()?,
        "unit":UNIT, "producer_pid":a["producer_pid"], "start_ticks":a["start_ticks"],
        "producer_invocation_id":a["producer_invocation_id"], "boot_id":a["boot_id"],
    });
    stable_record("BRIDGE_ACTOR.json", &doc)
}
fn stable_record(name: &str, doc: &Value) -> Result<Value> {
    if base().join(name).try_exists()? {
        ensure!(row(name)? == *doc, "foreign {name}");
        r(name)
    } else {
        save(name, doc)
    }
}
fn start_argv() -> Result<Vec<String>> {
    let mut args = vec![format!("--unit={UNIT}"), "--service-type=exec".into()];
    let mut command_path = String::new();
    for (name, kind) in [
        (base().join("service-v2").join(UNIT), false),
        (base().join("bridge-73726716/bridge.conf"), true),
    ] {
        let b = trusted(&name)?;
        for line in std::str::from_utf8(&b)?.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k {
                    "Description" => args.push(format!("--description={v}")),
                    "Type" => ensure!(v == "exec", "wrong service type"),
                    "ExecStart" => {
                        if !kind || !v.is_empty() {
                            command_path = v.to_owned()
                        }
                    }
                    _ => args.push(format!("--property={line}")),
                }
            }
        }
    }
    ensure!(
        command_path == format!("{ALIAS}/bridge-gate"),
        "incorrect 170 gate final command"
    );
    // This earlier private audit still projects a writable HOME-backed tree under /run.
    args.push("--property=InaccessiblePaths=/run/jetstreamer-ready-bounds-20261121-v1".into());
    // New host lane mounts must not become writable in an already-released service.
    args.push("--property=MountFlags=private".into());
    // systemd-run checks its first executable outside the private mount namespace.
    // env replaces itself with the sealed gate once the namespace is installed.
    args.extend(["--".into(), "/usr/bin/env".into(), command_path]);
    Ok(args)
}
fn guard_args(plan: &Value) -> Result<Vec<String>> {
    let gp = bound(plan)?;
    ensure!(
        word(&gp, "unit")? == UNIT
            && gp["worker_root"] == LANE
            && gp["filesystem"] == "/home/sol"
            && gp["receipt_directory"] == base().join("guard-receipts").to_string_lossy().as_ref(),
        "wrong guard scope"
    );
    let guard = base().join("tools/guard");
    let argv = vec![
        word(plan, "path")?.to_owned(),
        "--plan-sha256".into(),
        word(plan, "sha256")?.into(),
        "--self-sha256".into(),
        GUARD_SHA.into(),
    ];
    let mut qualify = argv.clone();
    qualify.push("--validate-plan-only".into());
    let result: Value = serde_json::from_str(&command(guard.to_str().unwrap(), &qualify)?)?;
    ensure!(
        result["validated"] == true && result["resource_samples_taken"] == 0,
        "guard static check failed"
    );
    let mut args = vec![
        format!("--unit={}", GUARD_UNIT.trim_end_matches(".service")),
        "--on-active=1s".into(),
        "--on-unit-inactive=10s".into(),
        "--timer-property=AccuracySec=1s".into(),
        "--service-type=oneshot".into(),
    ];
    for prop in [
        "User=root",
        "Group=root",
        "UMask=0077",
        "Restart=no",
        "MemoryMax=1073741824",
        "MemorySwapMax=0",
        "CPUQuota=100%",
        "TasksMax=256",
        "TimeoutStartSec=120",
        "TimeoutStopSec=15",
        "PrivateNetwork=yes",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "PrivateTmp=yes",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
        "AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
        "StandardOutput=journal",
        "StandardError=journal",
    ] {
        args.push(format!("--property={prop}"))
    }
    args.extend([
        format!("--property=ReadWritePaths={BASE}/guard-receipts"),
        "--".into(),
        guard.to_string_lossy().into_owned(),
    ]);
    args.extend(argv);
    Ok(args)
}
fn stage(mode: &str, current: &Value) -> Result<Value> {
    let i = anchor()?;
    let a = actor::actor(true)?;
    ensure!(actor::same(&a, current), "held owner changed");
    let fit = price::capture(&i["request"], Some(&i))?;
    let guard = if mode == "post-guard" {
        actor::guard_sample(&a, &r("ACTUAL_GUARD_PLAN.json")?, false)?
    } else {
        Value::Null
    };
    ensure!(actor::actor(true)? == a, "gate changed during price");
    Ok(
        json!({"schema":"horizon-epoch170-checkpoint-bridge-stage-price-v1","phase":mode,"intent":r("START_INTENT.json")?,"actor":a,"native":fit,"guard_floor_bytes":i["armed_floor"],"bounded_cap_bytes":i["bounded_cap_bytes"],"required_home_bytes":fit["required_home"],"available_home_bytes":fit["available_home"],"first_guard":guard,"resource_credit_bytes":0,"archive_publication_authorized":false}),
    )
}
fn fresh_stamp(v: &Value) -> Result<()> {
    let t = num(v, "recorded_unix_seconds")?;
    let (disk, ram) = available()?;
    ensure!(
        now()? >= t
            && now()? - t <= 110
            && disk >= num(v, "required_home")?
            && ram >= num(v, "required_ram")?,
        "fresh resources no longer cover staged commitments"
    );
    Ok(())
}
fn make_guard() -> Result<Value> {
    let i = anchor()?;
    let h = row("HELD_CAPACITY.json")?;
    let a = actor::actor(true)?;
    ensure!(
        h["actor"] == a && h["intent"] == r("START_INTENT.json")?,
        "held price changed"
    );
    fresh_stamp(&h["native"])?;
    Ok(
        json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":a["producer_invocation_id"],"filesystem":"/home/sol","worker_root":LANE,"receipt_directory":base().join("guard-receipts"),"maximum_worker_vmas":3500000,"minimum_free_bytes":i["armed_floor"],"maximum_root_physical_bytes":i["bounded_cap_bytes"]}),
    )
}
fn release() -> Result<Value> {
    let i = anchor()?;
    let post = row("POST_GUARD_CAPACITY.json")?;
    let first = row("FIRST_GUARD.json")?;
    let actor = actor::actor(true)?;
    let plan = r("ACTUAL_GUARD_PLAN.json")?;
    ensure!(
        post["actor"] == actor
            && first["actor"] == actor
            && post["phase"] == "post-guard"
            && post["intent"] == r("START_INTENT.json")?,
        "crossed release"
    );
    let mut sample = actor::guard_sample(&actor, &plan, false)?;
    ensure!(
        sample["cap"] == i["bounded_cap_bytes"] && sample["floor"] == i["armed_floor"],
        "guard floor or cap differs"
    );
    fresh_stamp(&post["native"])?;
    let record = json!({"schema":"horizon-epoch170-checkpoint-bridge-authorized-release-v1","intent":r("START_INTENT.json")?,"actor":actor,"post_guard_capacity":r("POST_GUARD_CAPACITY.json")?,"guard_sample":sample["sample"],"permit_sha256":digest(word(&actor,"producer_invocation_id")?.as_bytes()),"archive_publication_authorized":false,"resource_credit_bytes":0});
    // Publish the decision before the invocation-bound permit, and verify both the active guard and gate just before the latter.
    let rr = if base().join("AUTHORIZED_RELEASE.json").exists() {
        let old = row("AUTHORIZED_RELEASE.json")?;
        ensure!(
            old["intent"] == record["intent"]
                && old["actor"] == record["actor"]
                && old["post_guard_capacity"] == record["post_guard_capacity"],
            "another release exists"
        );
        r("AUTHORIZED_RELEASE.json")?
    } else {
        save("AUTHORIZED_RELEASE.json", &record)?
    };
    sample = actor::guard_sample(&actor, &plan, false)?;
    ensure!(
        sample["floor"] == i["armed_floor"] && actor::actor(true)? == actor,
        "owner changed"
    );
    fresh_stamp(&post["native"])?;
    let actor_ref = register_actor(&actor)?;
    stable_record(
        "BRIDGE_RELEASE.json",
        &json!({
            "schema":"horizon-epoch170-bridge-release-v1", "interface":interface()?,
            "actor":actor_ref, "producer_invocation_id":actor["producer_invocation_id"],
            "guard_plan":plan, "first_guard_sample":first["sample"],
            "guard_timer_invocation_id":first["timer_invocation_id"], "admission":rr,
            "resource_credit_bytes":0, "archive_publication_authorized":false,
        }),
    )?;
    publish(
        &base().join("barrier/allow"),
        word(&actor, "producer_invocation_id")?.as_bytes(),
        0o444,
    )?;
    Ok(rr)
}
fn run(args: &[String]) -> Result<Value> {
    ensure!(unsafe { libc::geteuid() } == 0, "root custody needed");
    let op = args.first().context("missing stage")?.as_str();
    static_package()?;
    if op == "status" {
        return if !base().join("START_INTENT.json").exists() {
            Ok(json!({"phase":"absent","unit":UNIT}))
        } else if base().join("guard-receipts/stop-completion.json").exists() {
            Ok(
                json!({"phase":"terminal","unit":UNIT,"completion":r("guard-receipts/stop-completion.json")?}),
            )
        } else if base().join("barrier/allow").exists() {
            actor::actor(false)
        } else {
            actor::actor(true)
        };
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(base().join("operator.lock"))?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another 170 transition is running"
    );
    match op {
        "quote" | "prestart" if args.len() == 3 => {
            let request = json!({"path":args[1],"sha256":args[2]});
            let p = pre(&request)?;
            if op == "quote" {
                Ok(p)
            } else {
                save("START_INTENT.json", &p)
            }
        }
        "start" | "recover-start" => {
            let i = if op == "start" {
                let i = anchor()?;
                cleared()?;
                fresh_stamp(&i["prestart"])?;
                i
            } else {
                ensure!(
                    r("START_INTENT.json")?["sha256"]
                        == "d42d139c6dd90189f0bab25732e7332b6a6fdd00f7ea131385aa0bf093b069d3",
                    "different private bridge start intent"
                );
                let i = row("START_INTENT.json")?;
                ensure!(
                    i["operator_deployment"]
                        == reference(&base().join("operator-v3/deployment-seal-receipt.json"))?
                        && i["source"] == interface()?
                        && !base().join("BRIDGE_ACTOR.json").try_exists()?,
                    "prior bridge generation acquired an actor"
                );
                let current = pre(&i["request"])?;
                ensure!(
                    current["armed_floor"] == i["armed_floor"]
                        && current["bounded_cap_bytes"] == i["bounded_cap_bytes"]
                        && current["source"] == i["source"]
                        && current["append_log"] == i["append_log"],
                    "cannot recover the frozen 170 bridge envelope"
                );
                fresh_stamp(&current["prestart"])?;
                let when = num(&current["prestart"], "recorded_unix_seconds")?;
                save(&format!("REPRICE_START_{when}.json"), &current)?;
                i
            };
            let v = start_argv()?;
            command("/usr/bin/systemd-run", &v)?;
            let held = actor::actor(true)?;
            register_actor(&held)?;
            Ok(
                json!({"producer_unit":UNIT,"argv":v,"intent":r("START_INTENT.json")?,"bounded_cap_bytes":i["bounded_cap_bytes"]}),
            )
        }
        "owner" => {
            let held = actor::actor(true)?;
            register_actor(&held)?;
            Ok(held)
        }
        "held" => save("HELD_CAPACITY.json", &stage("held", &actor::actor(true)?)?),
        "guard" => {
            let plan = make_guard()?;
            let pr = save("ACTUAL_GUARD_PLAN.json", &plan)?;
            let v = guard_args(&pr)?;
            idle(TIMER)?;
            idle(GUARD_UNIT)?;
            command("/usr/bin/systemd-run", &v)?;
            Ok(json!({"plan":pr,"argv":v}))
        }
        "first-guard" => {
            let a = actor::actor(true)?;
            let p = r("ACTUAL_GUARD_PLAN.json")?;
            let mut sample = actor::guard_sample(&a, &p, false)?;
            sample["intent"] = r("START_INTENT.json")?;
            sample["actor"] = a;
            sample["plan"] = p;
            save("FIRST_GUARD.json", &sample)
        }
        "post-guard" => {
            let a = actor::actor(true)?;
            ensure!(
                row("FIRST_GUARD.json")?["actor"] == a,
                "missing 170 first guard"
            );
            save("POST_GUARD_CAPACITY.json", &stage("post-guard", &a)?)
        }
        "release" => release(),
        "first-worker" => {
            let a = actor::actor(false)?;
            let release = row("AUTHORIZED_RELEASE.json")?;
            ensure!(
                actor::same(&a, &release["actor"]),
                "foreign released worker"
            );
            let p = actor::progress(&a)?;
            let sample = actor::guard_sample(&a, &r("ACTUAL_GUARD_PLAN.json")?, true)?;
            save(
                "FIRST_PROTECTED_WORKER.json",
                &json!({"schema":"horizon-epoch170-checkpoint-bridge-first-protected-progress-v1","at":now()?,"actor":a,"progress":p,"guard":sample,"release":r("AUTHORIZED_RELEASE.json")?,"archive_publication_authorized":false}),
            )
        }
        _ => bail!("invalid 170 operator stage {op}"),
    }
}
fn main() -> Result<()> {
    println!(
        "{}",
        serde_json::to_string(&run(&std::env::args().skip(1).collect::<Vec<_>>())?)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn joint_reservation_charges_both_live_increments() {
        let (floor, cap, required) =
            price::bounds(384 * G, 250 * G, 9000 * G, 9010 * G, 48 * G, 9100 * G, None).unwrap();
        assert_eq!(floor, 9011 * G);
        assert_eq!(cap, 290 * G);
        assert_eq!(required, 9099 * G);
        assert!(
            price::bounds(384 * G, 250 * G, 9000 * G, 9010 * G, 48 * G, 9093 * G, None).is_err()
        );
    }
    #[test]
    fn held_guard_floor_is_preserved() {
        let f = 9011 * G;
        assert!(
            price::bounds(
                384 * G,
                250 * G,
                9012 * G,
                9010 * G,
                48 * G,
                9200 * G,
                Some((f, 290 * G))
            )
            .is_err()
        );
        assert!(
            price::bounds(
                384 * G,
                250 * G,
                9000 * G,
                9010 * G,
                48 * G,
                9098 * G,
                Some((f, 290 * G))
            )
            .is_err()
        );
    }
}
