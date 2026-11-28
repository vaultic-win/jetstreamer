//! Root-sealed invocation token gate. No compiler or replay is launched here.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type R<T> = Result<T, Box<dyn std::error::Error>>;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-uploader-build-prestart-tools-20261110-v2/gate";
const GATES: &str = "/usr/local/lib/jetstreamer/horizon-uploader-build-gates-20261110-v1";
const PRODUCTION: &str = "horizon-qualify-uploader-image-build-20261110-v1.service";
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Restart,Type,KillMode,Delegate,ControlGroup,MemoryMax,MemorySwapMax,TasksMax,Result,ExecMainStatus,Environment";
fn need(ok: bool, why: &str) -> R<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v[k].as_str().ok_or_else(|| format!("missing {k}").into())
}
fn n(v: &Value, k: &str) -> R<u64> {
    v[k].as_u64()
        .ok_or_else(|| format!("missing number {k}").into())
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn hex(v: &str, len: usize) -> bool {
    v.len() == len
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> Vec<u64> {
    vec![
        m.dev(),
        m.ino(),
        m.mode() as u64,
        m.uid() as u64,
        m.gid() as u64,
        m.nlink(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]
}
fn raw(p: &Path, max: u64, immutable: bool) -> R<Vec<u8>> {
    need(
        p.is_absolute() && p.canonicalize()? == p,
        "canonical non-symlink metadata required",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x80000)
        .open(p)?;
    let m = f.metadata()?;
    need(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && (!immutable || m.mode() & 0o222 == 0)
            && m.len() <= max,
        "unsafe Root metadata",
    )?;
    let mut b = Vec::new();
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut b)?;
    need(
        b.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(p)?),
        "metadata changed",
    )?;
    Ok(b)
}
fn bound(v: &Value, max: u64, immutable: bool) -> R<Value> {
    let b = raw(Path::new(s(v, "path")?), max, immutable)?;
    need(sha(&b) == s(v, "sha256")?, "bound digest mismatch")?;
    Ok(serde_json::from_slice(&b)?)
}
fn native(unit: &str) -> R<Value> {
    need(
        unit.len() < 200
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && (unit.ends_with(".service") || unit.ends_with(".timer")),
        "unit name",
    )?;
    let out = Command::new("/usr/bin/systemctl")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .args(["show", unit, "--no-pager", "-p", FIELDS])
        .output()?;
    need(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() < 65536,
        "native query failed",
    )?;
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').ok_or("native delimiter")?;
        need(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate native field",
        )?;
    }
    Ok(Value::Object(m))
}
fn validate_plan(v: &Value) -> R<()> {
    let unit = s(v, "actor_unit")?;
    let control = v["metadata_control"] == true;
    need(
        v["schema"] == "horizon-uploader-build-prestart-plan-v1"
            && v["owner"] == "/root"
            && v["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53"
            && v["gates_root"] == GATES
            && v["replay_admission_authorized"] == false
            && v["publication_authorized"] == false,
        "Root prestart plan required",
    )?;
    need(
        (!control && unit == PRODUCTION)
            || (control
                && unit.starts_with("horizon-qualify-uploader-prestart-control-")
                && unit.ends_with(".service")),
        "wrong actor purpose",
    )?;
    need(
        v["guard_unit"] == unit.replacen("horizon-qualify-", "horizon-guard-", 1)
            && v["guard_timer"]
                == s(v, "guard_unit")?.trim_end_matches(".service").to_owned() + ".timer",
        "guard role mismatch",
    )?;
    need(
        (5..=180).contains(&n(v, "setup_timeout_seconds")?)
            && n(v, "guard_maximum_age_millis")? == 30000,
        "finite original setup and guard age required",
    )?;
    need(
        n(v, "actor_memory_max_bytes")? == if control { 64u64 << 20 } else { 8u64 << 30 },
        "actor hard cap differs",
    )?;
    need(
        n(v, "minimum_free_bytes")? > 0
            && n(v, "maximum_root_bytes")? > 0
            && hex(s(v, "guard_sha256")?, 64),
        "guard resource bindings required",
    )?;
    Ok(())
}
fn own(plan: &Value, actual: &Value, iid: &str, pid: u32) -> R<()> {
    need(
        !s(actual, "Environment")?
            .split_whitespace()
            .any(|v| v.starts_with("INVOCATION_ID=") || v.starts_with("\"INVOCATION_ID=")),
        "explicit invocation environment override forbidden",
    )?;
    need(
        hex(iid, 32)
            && actual["Id"] == plan["actor_unit"]
            && actual["InvocationID"] == iid
            && actual["LoadState"] == "loaded"
            && actual["ActiveState"] == "activating"
            && actual["SubState"] == "start-pre"
            && actual["MainPID"] == "0"
            && actual["ControlPID"]
                .as_str()
                .and_then(|v| v.parse::<u32>().ok())
                == Some(pid)
            && actual["NRestarts"] == "0"
            && actual["Restart"] == "no"
            && actual["Type"] == "exec"
            && actual["KillMode"] == "control-group"
            && actual["Delegate"] == "no"
            && actual["MemoryMax"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                == Some(n(plan, "actor_memory_max_bytes")?)
            && actual["MemorySwapMax"] == "0",
        "actual immutable start-pre ownership changed",
    )?;
    Ok(())
}
fn token_model(t: &Value, p: &Value, plan_sha: &str, iid: &str, pid: u32) -> R<()> {
    need(
        t["schema"] == "horizon-uploader-build-prestart-token-v1"
            && t["owner"] == "/root"
            && t["actor_unit"] == p["actor_unit"]
            && t["actor_invocation_id"] == iid
            && t["actor_control_pid"] == pid
            && t["plan_sha256"] == plan_sha
            && t["metadata_control"] == p["metadata_control"]
            && t["replay_admission_authorized"] == false
            && t["publication_authorized"] == false,
        "token is not for this exact actor, plan and purpose",
    )?;
    Ok(())
}
fn guard_model(g: &Value, t: &Value, p: &Value, iid: &str, pid: u32, now: u64) -> R<()> {
    need(
        g["schema"] == "jetstreamer-horizon-build-guard-sample-v1"
            && g["unit"] == p["actor_unit"]
            && g["actor_invocation_id"] == iid
            && g["guard_invocation_id"] == t["guard_invocation_id"]
            && g["self_sha256"] == p["guard_sha256"]
            && g["native_MainPID"] == 0
            && g["native_ControlPID"] == pid
            && g["native_NRestarts"] == 0
            && g["native_ActiveState"] == "activating"
            && g["native_SubState"] == "start-pre"
            && g["trip"] == false
            && g["native_owner_stable"] == true
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && g["maximum_root_bytes"] == p["maximum_root_bytes"]
            && g["memory_max_bytes"] == p["actor_memory_max_bytes"]
            && g["memory_swap_max_bytes"] == 0,
        "guard did not genuinely protect this prestart actor and exact resource policy",
    )?;
    let stamp = n(g, "recorded_unix_millis")?;
    need(
        now.checked_sub(stamp).is_some_and(|age| age <= 30000),
        "guard sample expired or future-dated",
    )?;
    Ok(())
}
fn normal_token(dir: &Path) -> R<Value> {
    need(dir.canonicalize()? == dir, "canonical token deployment")?;
    let m = fs::symlink_metadata(dir)?;
    need(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o222 == 0,
        "immutable Root token directory",
    )?;
    let b = raw(&dir.join("token.json"), 65536, true)?;
    let seal: Value = serde_json::from_slice(&raw(
        &dir.join("deployment-seal-receipt.json"),
        65536,
        true,
    )?)?;
    need(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == dir.to_str().ok_or("token directory UTF8")?
            && seal["publication_authorized"] == false
            && seal["replay_launch_authorized"] == false
            && seal["remote_mutations"] == false,
        "normal nonauthorizing token seal required",
    )?;
    let members = seal["members"].as_array().ok_or("seal members")?;
    need(
        members.len() == 1 && members[0]["name"] == "token.json" && members[0]["sha256"] == sha(&b),
        "exact sealed token member",
    )?;
    let sums = raw(&dir.join("SHA256SUMS"), 16384, true)?;
    let expected = format!("{}  token.json", sha(&b));
    need(
        std::str::from_utf8(&sums)?.lines().any(|l| l == expected),
        "normal token checksum inventory",
    )?;
    Ok(serde_json::from_slice(&b)?)
}
fn run() -> R<()> {
    let args: Vec<_> = std::env::args().collect();
    need(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "exact gate argv required",
    )?;
    need(
        fs::read_link("/proc/self/exe")? == Path::new(IMAGE)
            && sha(&raw(Path::new(IMAGE), 32 << 20, true)?) == args[5],
        "normally sealed gate image required",
    )?;
    let p = bound(&json!({"path":args[1],"sha256":args[3]}), 65536, true)?;
    validate_plan(&p)?;
    for k in [
        "HORIZON_INVOCATION_ID",
        "SYSTEMD_INVOCATION_ID",
        "HORIZON_TOKEN_PATH",
        "HORIZON_GUARD_TOKEN",
    ] {
        need(
            std::env::var_os(k).is_none(),
            "environment override forbidden",
        )?;
    }
    let iid = std::env::var("INVOCATION_ID")?;
    let pid = std::process::id();
    let first = native(s(&p, "actor_unit")?)?;
    own(&p, &first, &iid, pid)?;
    need(
        fs::read_to_string("/proc/self/cgroup")? == format!("0::{}\n", s(&first, "ControlGroup")?),
        "gate escaped actual actor cgroup",
    )?;
    let dir = Path::new(GATES).join(&iid);
    let begin = Instant::now();
    let deadline = begin + Duration::from_secs(n(&p, "setup_timeout_seconds")?);
    let mut heartbeat = Instant::now();
    loop {
        need(
            Instant::now() < deadline,
            "original prestart setup deadline expired; no work permitted",
        )?;
        match fs::symlink_metadata(&dir) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if heartbeat.elapsed() >= Duration::from_secs(30) {
            eprintln!(
                "waiting for exact Root-sealed first-guard token iid={iid}, elapsed={}s, no work permitted",
                begin.elapsed().as_secs()
            );
            heartbeat = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let t = normal_token(&dir)?;
    token_model(&t, &p, &args[3], &iid, pid)?;
    let g = bound(&t["guard_receipt"], 65536, false)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    guard_model(&g, &t, &p, &iid, pid, now)?;
    let guard = native(s(&p, "guard_unit")?)?;
    need(
        guard["InvocationID"] == t["guard_invocation_id"]
            && guard["Id"] == p["guard_unit"]
            && guard["MainPID"] == "0"
            && guard["ControlPID"] == "0"
            && guard["NRestarts"] == "0"
            && guard["Result"] == "success"
            && guard["ExecMainStatus"] == "0",
        "first genuine guard completion is not current success",
    )?;
    let timer = native(s(&p, "guard_timer")?)?;
    need(
        timer["Id"] == p["guard_timer"]
            && timer["InvocationID"] == t["guard_timer_invocation_id"]
            && timer["ActiveState"] == "active"
            && (timer["SubState"] == "waiting" || timer["SubState"] == "running"),
        "bound guard timer must remain active",
    )?;
    own(&p, &native(s(&p, "actor_unit")?)?, &iid, pid)?;
    need(
        Instant::now() < deadline,
        "prestart deadline expired before release",
    )?;
    println!(
        "{}",
        json!({"schema":"horizon-uploader-build-prestart-accepted-v1","actor_unit":p["actor_unit"],"actor_invocation_id":iid,"actual_control_pid":pid,"plan_sha256":args[3],"guard_receipt":t["guard_receipt"],"guard_invocation_id":t["guard_invocation_id"],"guard_timer_invocation_id":t["guard_timer_invocation_id"],"metadata_control":p["metadata_control"],"replay_admission_authorized":false,"publication_authorized":false})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("prestart rejected: {e}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p() -> Value {
        json!({"schema":"horizon-uploader-build-prestart-plan-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","actor_unit":PRODUCTION,"guard_unit":"horizon-guard-uploader-image-build-20261110-v1.service","guard_timer":"horizon-guard-uploader-image-build-20261110-v1.timer","gates_root":GATES,"metadata_control":false,"setup_timeout_seconds":180,"guard_maximum_age_millis":30000,"actor_memory_max_bytes":8u64<<30,"minimum_free_bytes":1234,"maximum_root_bytes":4u64<<30,"guard_sha256":"b".repeat(64),"replay_admission_authorized":false,"publication_authorized":false})
    }
    fn t() -> Value {
        json!({"schema":"horizon-uploader-build-prestart-token-v1","owner":"/root","actor_unit":PRODUCTION,"actor_invocation_id":"a".repeat(32),"actor_control_pid":123,"plan_sha256":"c".repeat(64),"metadata_control":false,"replay_admission_authorized":false,"publication_authorized":false,"guard_invocation_id":"d".repeat(32)})
    }
    fn g() -> Value {
        json!({"schema":"jetstreamer-horizon-build-guard-sample-v1","unit":PRODUCTION,"actor_invocation_id":"a".repeat(32),"guard_invocation_id":"d".repeat(32),"self_sha256":"b".repeat(64),"native_MainPID":0,"native_ControlPID":123,"native_NRestarts":0,"native_ActiveState":"activating","native_SubState":"start-pre","trip":false,"native_owner_stable":true,"minimum_free_bytes":1234,"maximum_root_bytes":4u64<<30,"memory_max_bytes":8u64<<30,"memory_swap_max_bytes":0,"recorded_unix_millis":100000})
    }
    #[test]
    fn exact_production_plan_required() {
        assert!(validate_plan(&p()).is_ok());
        let mut v = p();
        v["actor_unit"] = json!("other.service");
        assert!(validate_plan(&v).is_err());
    }
    #[test]
    fn no_replay_or_publication_authority() {
        for k in ["replay_admission_authorized", "publication_authorized"] {
            let mut v = p();
            v[k] = json!(true);
            assert!(validate_plan(&v).is_err());
        }
    }
    #[test]
    fn wrong_cap_or_unbounded_clock_rejected() {
        for (k, n) in [
            ("actor_memory_max_bytes", 16u64 << 30),
            ("setup_timeout_seconds", 1000),
        ] {
            let mut v = p();
            v[k] = json!(n);
            assert!(validate_plan(&v).is_err());
        }
    }
    #[test]
    fn old_token_cannot_authorize_new_invocation() {
        assert!(token_model(&t(), &p(), &"c".repeat(64), &"a".repeat(32), 123).is_ok());
        assert!(token_model(&t(), &p(), &"c".repeat(64), &"e".repeat(32), 123).is_err());
    }
    #[test]
    fn token_cannot_transfer_plan_or_pid() {
        assert!(token_model(&t(), &p(), &"f".repeat(64), &"a".repeat(32), 123).is_err());
        assert!(token_model(&t(), &p(), &"c".repeat(64), &"a".repeat(32), 124).is_err());
    }
    #[test]
    fn control_token_cannot_authorize_compiler() {
        let mut v = t();
        v["metadata_control"] = json!(true);
        assert!(token_model(&v, &p(), &"c".repeat(64), &"a".repeat(32), 123).is_err());
    }
    #[test]
    fn genuine_bound_guard_can_pass() {
        assert!(guard_model(&g(), &t(), &p(), &"a".repeat(32), 123, 100010).is_ok());
    }
    #[test]
    fn expired_or_future_guard_is_rejected() {
        assert!(guard_model(&g(), &t(), &p(), &"a".repeat(32), 123, 130001).is_err());
        assert!(guard_model(&g(), &t(), &p(), &"a".repeat(32), 123, 99999).is_err());
    }
    #[test]
    fn tripped_or_restarted_guard_cannot_release() {
        for (k, v) in [("trip", json!(true)), ("native_NRestarts", json!(1))] {
            let mut x = g();
            x[k] = v;
            assert!(guard_model(&x, &t(), &p(), &"a".repeat(32), 123, 100010).is_err());
        }
    }
    #[test]
    fn running_or_different_pid_guard_is_not_prestart_proof() {
        for (k, v) in [
            ("native_MainPID", json!(123)),
            ("native_ControlPID", json!(124)),
            ("native_SubState", json!("running")),
        ] {
            let mut x = g();
            x[k] = v;
            assert!(guard_model(&x, &t(), &p(), &"a".repeat(32), 123, 100010).is_err());
        }
    }
    #[test]
    fn guard_resource_floor_cannot_change() {
        for (k, v) in [
            ("minimum_free_bytes", json!(1233)),
            ("maximum_root_bytes", json!(8u64 << 30)),
            ("memory_max_bytes", json!(16u64 << 30)),
        ] {
            let mut x = g();
            x[k] = v;
            assert!(guard_model(&x, &t(), &p(), &"a".repeat(32), 123, 100010).is_err());
        }
    }
    #[test]
    fn guard_image_and_invocation_cannot_change() {
        for (k, v) in [
            ("self_sha256", json!("f".repeat(64))),
            ("guard_invocation_id", json!("f".repeat(32))),
        ] {
            let mut x = g();
            x[k] = v;
            assert!(guard_model(&x, &t(), &p(), &"a".repeat(32), 123, 100010).is_err());
        }
    }
}
