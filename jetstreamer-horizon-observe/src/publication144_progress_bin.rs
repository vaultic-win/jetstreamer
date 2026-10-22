//! Read-only exact144 client-child progress/forecast; no status write or R2 call.
#[path = "publication144_progress_eta.rs"]
mod eta;
#[path = "publication144_progress_events.rs"]
mod events;
#[allow(dead_code)]
#[path = "../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
const WORKER: &str = "/usr/local/lib/jetstreamer/horizon-publication144-single-delivery-20261022-v6/jetstreamer-publication144-deliver";
const WORKER_SHA: &str = "506b054c3e644f619df4049d935a75264f0ce1577a98235861d4f725ba86a49a";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch144-progress-20261022-v1";
const PUB: &str = "horizon-publish-144-v4-20261022-v1.service";
const CALIBRATION: &str =
    "/var/lib/jetstreamer/horizon-publication144-calibration-20261022-v1/eta.json";
const CALIBRATION_SHA: &str = "bc2c99fc95e795424cfa9a1f383765d37d34dcc35b35945d7e9cb2943b135dd7";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    delivery_plan: Bound,
    delivery_launch: Bound,
    child_launch: Bound,
    observer: Bound,
    sample_unix_millis: u64,
    output_receipt: PathBuf,
}
fn read(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        16 << 20,
        immutable,
    )?)?)
}
fn epoch_utc(millis: u64) -> Result<String> {
    ensure!(millis.is_multiple_of(1000), "sample must use whole seconds");
    let seconds: libc::time_t = (millis / 1000).try_into()?;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    ensure!(
        !unsafe { libc::gmtime_r(&seconds, tm.as_mut_ptr()) }.is_null(),
        "sample date overflow"
    );
    let t = unsafe { tm.assume_init() };
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.tm_year + 1900,
        t.tm_mon + 1,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec
    ))
}
fn sync_args() -> Vec<String> {
    [
        "sync",
        "/home/sol/horizon",
        "--epochs",
        "144-144",
        "--receipt-directory",
        "/home/sol/.jetstreamer-private/r2-receipts",
        "--legacy-part-size-mib",
        "5",
        "--concurrency",
        "4",
    ]
    .map(str::to_owned)
    .into()
}
fn identity(
    p: &Plan,
    delivery: &Value,
    launch: &Value,
    child: &Value,
    observer: &Value,
) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-exact144-child-progress-plan-v1"
            && p.output_receipt.parent() == Some(Path::new(ROOT))
            && p.output_receipt.file_name().and_then(|n| n.to_str())
                == Some(format!("progress-{}.json", p.sample_unix_millis).as_str()),
        "foreign progress plan/output scope"
    );
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["recorded_at_utc"] == epoch_utc(p.sample_unix_millis)?,
        "progress must bind exact coordinated v2 sample"
    );
    let root = Path::new(
        delivery["output_directory"]
            .as_str()
            .context("delivery output root")?,
    );
    ensure!(
        root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-epoch144-delivery-"))
            && p.delivery_launch.path == root.join("launch.json")
            && p.child_launch.path == root.join("upload-child-launch.json"),
        "foreign delivery capture paths"
    );
    let pb = serde_json::to_value(&p.delivery_plan)?;
    ensure!(
        delivery["schema"] == "jetstreamer-exact144-single-delivery-plan-v1"
            && delivery["client"]["path"] == events::CLIENT
            && delivery["client"]["sha256"] == events::CLIENT_SHA
            && delivery["r2_create_missing_pair_authorized"] == true
            && delivery["r2_overwrite_authorized"] == false
            && delivery["local_retirement_authorized"] == false
            && launch["schema"] == "jetstreamer-exact144-delivery-launch-v1"
            && launch["epoch"] == 144
            && launch["plan"] == pb
            && launch["self_sha256"] == WORKER_SHA
            && launch["claim"]["unit"] == events::UNIT
            && launch["claim"]["phase"] == "upload-readback"
            && launch["claim"]["origin_unit"] == PUB
            && launch["claim"]["invocation_id"] == launch["owner"]["InvocationID"]
            && launch["claim"]["origin_invocation_id"]
                .as_str()
                .is_some_and(hex_id)
            && child["schema"] == "horizon-exact144-delivery-child-launch-v1"
            && child["plan"] == pb
            && child["owner"] == launch["owner"]
            && child["client"] == delivery["client"]
            && child["archive_sync"] == true
            && child["arguments"] == json!(sync_args())
            && child["current_liveness_proven"] == false
            && child["archive_ready"] == false
            && child["local_retirement_authorized"] == false,
        "foreign delivery/client/child lineage"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            launch[flag] == false,
            "capture grants unexpected authority:{flag}"
        );
    }
    Ok(())
}
fn hex_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn fields() -> Result<Value> {
    let o=Command::new("/usr/bin/systemctl").args(["show",events::UNIT,"--property=Id,LoadState,InvocationID,MainPID,NRestarts,ActiveState,SubState,ExecStart,Restart,Type,RemainAfterExit,ControlGroup"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 32768,
        "delivery service unavailable"
    );
    Ok(serde_json::to_value(
        std::str::from_utf8(&o.stdout)?
            .lines()
            .map(|l| l.split_once('=').context("systemd property"))
            .collect::<Result<BTreeMap<_, _>>>()?,
    )?)
}
fn owner(current: &Value, capture: &Value, pb: &Bound) -> Result<()> {
    let expected = format!(
        "{{ path={WORKER} ; argv[]={WORKER} {} --plan-sha256 {} --self-sha256 {WORKER_SHA} --run",
        pb.path.display(),
        pb.sha256
    );
    ensure!(
        current["Id"] == events::UNIT
            && current["LoadState"] == "loaded"
            && current["InvocationID"].as_str().is_some_and(hex_id)
            && current["InvocationID"] == capture["owner"]["InvocationID"]
            && current["NRestarts"] == "0"
            && current["Restart"] == "no"
            && current["Type"] == "oneshot"
            && current["RemainAfterExit"] == "yes"
            && current["ActiveState"] == "activating"
            && current["SubState"] == "start"
            && current["MainPID"] == capture["owner"]["MainPID"]
            && current["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|p| p > 0)
            && current["ExecStart"]
                .as_str()
                .and_then(|s| s.split_once(" ; ignore_errors="))
                .is_some_and(|(a, b)| a == expected && b.starts_with("no ;"))
            && capture["claim"]["expected_exec_start"] == capture["owner"]["ExecStart"],
        "delivery owner is no longer the captured live invocation"
    );
    Ok(())
}
fn proc_identity(pid: u32, parent: u32, group: &str) -> Result<Value> {
    ensure!(
        pid > 0 && parent > 0 && group.starts_with("/system.slice/") && !group.contains('\n'),
        "unsafe process/cgroup identity"
    );
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = fs::read_to_string(root.join("stat"))?;
    let (_, fields) = stat.rsplit_once(") ").context("process stat")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    ensure!(
        fields.len() >= 20
            && !matches!(fields[0], "Z" | "X")
            && fields[1].parse::<u32>()? == parent,
        "child exited or parent changed"
    );
    let start = fields[19].parse::<u64>()?;
    let status = fs::read_to_string(root.join("status"))?;
    let props: BTreeMap<_, _> = status.lines().filter_map(|l| l.split_once(':')).collect();
    for (key, n) in [("Uid", "1001"), ("Gid", "1003")] {
        ensure!(
            props
                .get(key)
                .is_some_and(|s| s.split_whitespace().collect::<Vec<_>>() == vec![n; 4]),
            "child identity not permanently dropped"
        );
    }
    for key in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        ensure!(
            props
                .get(key)
                .is_some_and(|s| s.trim() == "0000000000000000"),
            "child retains capabilities"
        );
    }
    ensure!(
        fs::read_link(root.join("exe"))? == Path::new(events::CLIENT),
        "child executable changed"
    );
    let args: Vec<_> = fs::read(root.join("cmdline"))?
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| std::str::from_utf8(s).map(str::to_owned))
        .collect::<std::result::Result<_, _>>()?;
    let expected: Vec<_> = std::iter::once(events::CLIENT.to_owned())
        .chain(sync_args())
        .collect();
    ensure!(
        args == expected && fs::read_to_string(root.join("cgroup"))? == format!("0::{group}\n"),
        "child command/cgroup changed"
    );
    Ok(
        json!({"pid":pid,"parent_pid":parent,"start_ticks":start,"cgroup":group,"exe":events::CLIENT,"uid":1001,"gid":1003,"capabilities_empty":true}),
    )
}
fn journal(iid: &str, pid: u32, spawned: u64, sample: u64) -> Result<Vec<Value>> {
    let mut child = Command::new("/usr/bin/journalctl")
        .args([
            format!("_SYSTEMD_UNIT={}", events::UNIT),
            format!("_SYSTEMD_INVOCATION_ID={iid}"),
            format!("_PID={pid}"),
            format!("--since=@{}", spawned / 1000),
            format!("--until=@{}", sample / 1000),
            "--output=json".into(),
            "--no-pager".into(),
            "--all".into(),
            "--lines=4096".into(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .context("journal pipe")?
        .take((8 << 20) + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() > 8 << 20 {
        let _ = child.kill();
        let _ = child.wait();
        read?;
        anyhow::bail!("progress journal oversized");
    }
    ensure!(child.wait()?.success(), "progress journal failed");
    let lines: Vec<_> = std::str::from_utf8(&bytes)?.lines().collect();
    ensure!(lines.len() < 4096, "progress journal truncated");
    lines
        .into_iter()
        .map(|l| Ok(serde_json::from_str(l)?))
        .collect()
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 6
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: publication144-progress PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let pb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(read(&pb, true)?)?;
    let delivery = read(&p.delivery_plan, true)?;
    let launch = read(&p.delivery_launch, true)?;
    let child = read(&p.child_launch, false)?;
    let observer = read(&p.observer, false)?;
    identity(&p, &delivery, &launch, &child, &observer)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    ensure!(
        p.sample_unix_millis <= now && now - p.sample_unix_millis <= 300000,
        "progress requires fresh coordinated sample"
    );
    let m = fs::symlink_metadata(ROOT)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o700
            && fs::canonicalize(ROOT)? == Path::new(ROOT),
        "unsafe progress receipt directory"
    );
    ensure!(
        matches!(fs::symlink_metadata(&p.output_receipt),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "progress output occupied or unreadable"
    );
    evidence::bound_file(Path::new(WORKER), WORKER_SHA, 128 << 20, true)?;
    evidence::bound_file(
        Path::new(events::CLIENT),
        events::CLIENT_SHA,
        128 << 20,
        true,
    )?;
    let before = fields()?;
    owner(&before, &launch, &p.delivery_plan)?;
    let pid: u32 = child["child_pid"]
        .as_u64()
        .context("child PID")?
        .try_into()?;
    let parent: u32 = before["MainPID"].as_str().context("worker PID")?.parse()?;
    let group = before["ControlGroup"].as_str().context("worker cgroup")?;
    let proc_before = proc_identity(pid, parent, group)?;
    let spawned = child["spawned_millis"]
        .as_u64()
        .context("child spawn timestamp")?;
    let iid = before["InvocationID"]
        .as_str()
        .context("delivery invocation")?;
    let journal = journal(iid, pid, spawned, p.sample_unix_millis)?;
    let summary = events::summarize(&journal, iid, pid, spawned, p.sample_unix_millis)?;
    let calibration = Bound {
        path: CALIBRATION.into(),
        sha256: CALIBRATION_SHA.into(),
    };
    let forecast = eta::estimate(&summary, &read(&calibration, false)?)?;
    ensure!(
        proc_identity(pid, parent, group)? == proc_before && fields()? == before,
        "delivery child changed during progress observation"
    );
    for b in [
        &p.delivery_plan,
        &p.delivery_launch,
        &p.child_launch,
        &p.observer,
    ] {
        read(
            b,
            b.path == p.delivery_plan.path || b.path == p.delivery_launch.path,
        )?;
    }
    evidence::write_receipt(
        &p.output_receipt,
        &json!({"schema":"jetstreamer-exact144-authenticated-child-progress-v2","epoch":144,
        "plan":pb,"self_sha256":a[5],"observer":p.observer,"delivery_launch":p.delivery_launch,"child_launch":p.child_launch,
        "owner":before,"child_identity":proc_before,"trusted_journal_events":journal,"progress":summary,
        "calibration":calibration,"forecast":forecast,
        "resource_samples_taken":0,"current_sidecar_eta_valid":false,"status_publication_authorized":false,
        "archive_ready_pair_proven":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!(
        "exact144 client progress/forecast recorded; no resource sample, status publication, archive hash or remote access"
    );
    Ok(())
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root sandbox journal credential attribution probe; only disposable test child, no campaign or network access"]
    fn journal_sender_probe() {
        use std::os::unix::process::CommandExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--ignored",
            "--exact",
            "tests::journal_child_probe",
            "--nocapture",
            "--test-threads=1",
        ]);
        unsafe {
            command.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(1003) != 0
                    || libc::setuid(1001) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        println!(
            "horizon144-progress-parent-probe-v1 parent={} child={}",
            std::process::id(),
            child.id()
        );
        assert!(child.wait().unwrap().success());
    }
    #[test]
    #[ignore = "unprivileged child of journal_sender_probe only; fixed marker and two-second lifetime"]
    fn journal_child_probe() {
        assert_eq!(unsafe { libc::geteuid() }, 1001);
        eprintln!("horizon144-progress-live-child-credential-probe-v2");
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    #[test]
    fn utc_is_exact_and_does_not_accept_subsecond_samples() {
        assert_eq!(epoch_utc(1792709880000).unwrap(), "2026-10-22T22:58:00Z");
        assert!(epoch_utc(1792709880001).is_err());
    }
    #[test]
    fn copied_or_restarted_owner_is_not_live_progress() {
        let p = Bound {
            path: "/sealed/plan.json".into(),
            sha256: "b".repeat(64),
        };
        let command = format!(
            "{{ path={WORKER} ; argv[]={WORKER} {} --plan-sha256 {} --self-sha256 {WORKER_SHA} --run ; ignore_errors=no ; start_time=[n/a] }}",
            p.path.display(),
            p.sha256
        );
        let u = json!({"Id":events::UNIT,"LoadState":"loaded","InvocationID":"a".repeat(32),"NRestarts":"0","Restart":"no","Type":"oneshot","RemainAfterExit":"yes","ActiveState":"activating","SubState":"start","MainPID":"123","ExecStart":command});
        let c = json!({"owner":u,"claim":{"expected_exec_start":u["ExecStart"]}});
        owner(&u, &c, &p).unwrap();
        for (k, v) in [
            ("MainPID", "0"),
            ("InvocationID", "foreign"),
            ("Restart", "always"),
            ("NRestarts", "1"),
            ("SubState", "exited"),
            ("ExecStart", "foreign"),
        ] {
            let mut bad = u.clone();
            bad[k] = json!(v);
            assert!(owner(&bad, &c, &p).is_err(), "{k}");
        }
    }
    #[test]
    fn lineage_requires_exact_child_command_plan_and_observer() {
        let b = |path: &str| Bound {
            path: path.into(),
            sha256: "a".repeat(64),
        };
        let p = Plan {
            schema: "jetstreamer-exact144-child-progress-plan-v1".into(),
            delivery_plan: b("/sealed/delivery-plan.json"),
            delivery_launch: b(
                "/var/lib/jetstreamer/horizon-epoch144-delivery-fixture/launch.json",
            ),
            child_launch: b(
                "/var/lib/jetstreamer/horizon-epoch144-delivery-fixture/upload-child-launch.json",
            ),
            observer: b("/sample.json"),
            sample_unix_millis: 1792709880000,
            output_receipt: format!("{ROOT}/progress-1792709880000.json").into(),
        };
        let d = json!({"schema":"jetstreamer-exact144-single-delivery-plan-v1","output_directory":"/var/lib/jetstreamer/horizon-epoch144-delivery-fixture",
            "client":{"path":events::CLIENT,"sha256":events::CLIENT_SHA},"r2_create_missing_pair_authorized":true,"r2_overwrite_authorized":false,"local_retirement_authorized":false});
        let l = json!({"schema":"jetstreamer-exact144-delivery-launch-v1","epoch":144,"plan":p.delivery_plan,"self_sha256":WORKER_SHA,
            "claim":{"unit":events::UNIT,"phase":"upload-readback","origin_unit":PUB,"invocation_id":"b".repeat(32),"origin_invocation_id":"c".repeat(32)},
            "owner":{"InvocationID":"b".repeat(32)},"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let c = json!({"schema":"horizon-exact144-delivery-child-launch-v1","plan":p.delivery_plan,"owner":l["owner"],"client":d["client"],"archive_sync":true,"arguments":sync_args(),"current_liveness_proven":false,"archive_ready":false,"local_retirement_authorized":false});
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-22T22:58:00Z"});
        identity(&p, &d, &l, &c, &o).unwrap();
        for (pointer, value) in [
            ("/client/sha256", json!("b".repeat(64))),
            ("/r2_overwrite_authorized", json!(true)),
            ("/local_retirement_authorized", json!(true)),
            ("/output_directory", json!("/foreign")),
        ] {
            let mut bad = d.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(identity(&p, &bad, &l, &c, &o).is_err(), "{pointer}");
        }
        for pointer in [
            "/claim/invocation_id",
            "/claim/origin_invocation_id",
            "/claim/origin_unit",
            "/self_sha256",
            "/plan/sha256",
            "/r2_mutations",
        ] {
            let mut bad = l.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(identity(&p, &d, &bad, &c, &o).is_err(), "{pointer}");
        }
        for pointer in [
            "/arguments",
            "/owner/InvocationID",
            "/archive_sync",
            "/plan/sha256",
            "/current_liveness_proven",
            "/archive_ready",
        ] {
            let mut bad = c.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(identity(&p, &d, &l, &bad, &o).is_err(), "{pointer}");
        }
        for pointer in ["/schema", "/recorded_at_utc"] {
            let mut bad = o.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(identity(&p, &d, &l, &c, &bad).is_err(), "{pointer}");
        }
    }
}
