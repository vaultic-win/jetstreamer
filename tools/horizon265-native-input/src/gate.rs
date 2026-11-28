//! First-guard proof required before the selected worker can read a snapshot.
//! The root launcher must produce genuine admission/first-guard evidence.
#![allow(clippy::unnecessary_map_or, clippy::too_many_arguments)]
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::profile::*;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn require(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("missing {}", key).into())
}
fn num(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .ok_or_else(|| format!("missing {}", key).into())
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn read_owned(path: &Path, expected: &str, limit: u64, owner: u32) -> Result<Vec<u8>> {
    require(hex(expected, 64), "bad evidence digest")?;
    require(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence",
    )?;
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        require(
            m.is_dir() && m.uid() == owner && m.mode() & 0o022 == 0,
            "untrusted evidence parent",
        )?;
    }
    read_leaf(path, expected, limit, owner)
}
fn read_leaf(path: &Path, expected: &str, limit: u64, owner: u32) -> Result<Vec<u8>> {
    require(
        hex(expected, 64) && path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence leaf",
    )?;
    let before = fs::symlink_metadata(path)?;
    require(
        before.is_file()
            && before.uid() == owner
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= limit,
        "unsafe evidence custody",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    require(
        identity(&before) == identity(&f.metadata()?),
        "evidence replaced before open",
    )?;
    let mut bytes = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() as u64 <= limit
            && digest(&bytes) == expected
            && identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "evidence changed or hash differs",
    )?;
    Ok(bytes)
}
fn bound(v: &Value) -> Result<Value> {
    let path = Path::new(text(v, "path")?);
    require(
        path.starts_with("/var/lib/jetstreamer"),
        "evidence outside sealed namespace",
    )?;
    Ok(serde_json::from_slice(&read_owned(
        path,
        text(v, "sha256")?,
        2 << 20,
        0,
    )?)?)
}
fn monotonic_us() -> Result<u64> {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } == 0,
        "monotonic clock failed",
    )?;
    Ok((t.tv_sec as u64)
        .checked_mul(1_000_000)
        .ok_or("clock overflow")?
        .checked_add(t.tv_nsec as u64 / 1000)
        .ok_or("clock overflow")?)
}
fn clock(plan: &Value, now: u64) -> Result<()> {
    let start = num(plan, "issued_monotonic_us")?;
    let end = num(plan, "expires_monotonic_us")?;
    require(
        start <= now && now < end && end > start && end - start <= 60_000_000,
        "startup deadline expired or invalid",
    )
}
fn plan_valid(
    p: &Value,
    iid: &str,
    pid: u32,
    exe: &Path,
    exe_sha: &str,
    boot: &str,
    now: u64,
) -> Result<()> {
    require(
        p["schema"] == PLAN_SCHEMA
            && p["epoch"] == EPOCH
            && p["unit"] == UNIT
            && p["guard_unit"] == GUARD_UNIT
            && p["worker_root"] == ROOT
            && p["bootstrap_slot"] == SLOT
            && p["snapshot_sha256"] == super::SNAPSHOT_SHA
            && p["worker"]["path"] == super::WORKER
            && p["worker"]["sha256"] == super::WORKER_SHA
            && p["genesis_sha256"] == super::GENESIS_SHA
            && p["input_packet"]["path"] == super::PACKET
            && p["input_packet"]["sha256"] == super::PACKET_SHA
            && p["maximum_root_physical_bytes"] == ROOT_CAP
            && p["maximum_memory_bytes"] == MEMORY
            && p["token_root"] == TOKENS
            && p["boot_id"] == boot
            && harness_allowed(exe)
            && p["harness"]["path"].as_str() == exe.to_str()
            && p["harness"]["sha256"] == exe_sha
            && hex(iid, 32)
            && pid > 1
            && num(p, "minimum_free_bytes")? > 0,
        "startup plan scope differs",
    )?;
    require(
        Path::new(text(&p["guard"], "path")?).starts_with("/var/lib/jetstreamer")
            && hex(text(&p["guard"], "sha256")?, 64),
        "guard pin missing",
    )?;
    clock(p, now)
}
fn token_valid(
    p: &Value,
    plan_sha: &str,
    t: &Value,
    gp: &Value,
    g: &Value,
    j: &Value,
    iid: &str,
    pid: u32,
    now: u64,
    wall: u64,
) -> Result<()> {
    clock(p, now)?;
    require(
        t["schema"] == TOKEN_SCHEMA
            && t["startup_plan_sha256"] == plan_sha
            && t["unit"] == UNIT
            && t["invocation_id"] == iid
            && t["main_pid"] == pid
            && t["harness"] == p["harness"]
            && t["guard"] == p["guard"]
            && t["boot_id"] == p["boot_id"]
            && t["admission"] == p["admission"]
            && num(t, "recorded_monotonic_us")? >= num(p, "issued_monotonic_us")?
            && num(t, "recorded_monotonic_us")? <= now,
        "token owner or original clock differs",
    )?;
    let gid = text(t, "guard_invocation_id")?;
    require(hex(gid, 32) && gid != iid, "invalid guard invocation")?;
    require(
        gp["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && gp["unit"] == UNIT
            && gp["invocation_id"] == iid
            && gp["filesystem"] == FILESYSTEM
            && gp["worker_root"] == ROOT
            && gp["minimum_free_bytes"] == p["minimum_free_bytes"]
            && gp["maximum_root_physical_bytes"] == ROOT_CAP
            && gp["maximum_worker_vmas"] == 3500000
            && gp["native_main"]["main_pid"] == pid
            && gp["native_main"]["executable"] == p["harness"]["path"]
            && gp["native_main"]["sha256"] == p["harness"]["sha256"]
            && gp.get("bounded_measurement").map_or(true, Value::is_null)
            && gp.get("bounded_canary").map_or(true, Value::is_null),
        "first guard plan differs",
    )?;
    require(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["plan"] == t["guard_plan"]["path"]
            && g["plan_sha256"] == t["guard_plan"]["sha256"]
            && g["guard_sha256"] == p["guard"]["sha256"]
            && g["guard_invocation_id"] == gid
            && g["producer_invocation_id"] == iid
            && g["producer"]["invocation_id"] == iid
            && g["producer"]["pid"] == pid
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["result"] == "success"
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer"]["restarts"] == 0
            && g["producer"]["cgroup"] == format!("/system.slice/{}", UNIT)
            && g["producer_stop_enabled"] == true
            && g["native_main"] == gp["native_main"]
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && num(g, "available_bytes")? >= num(p, "minimum_free_bytes")?
            && g["maximum_worker_vmas"] == 3500000
            && g["maximum_root_physical_bytes"] == ROOT_CAP
            && g["root_physical_observation"]["maximum_physical_bytes"] == ROOT_CAP
            && g["root_physical_observation"]["exceeds_budget"] == false
            && num(
                &g["root_physical_observation"],
                "conservative_physical_bytes",
            )? <= ROOT_CAP
            && g["workers"].as_array().map_or(false, |v| v.len() == 1)
            && g["workers"][0][0] == pid
            && g["workers"][0][1]
                .as_u64()
                .map_or(false, |n| n > 0 && n < 3500000)
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error",
                "target_handoff_error",
            ]
            .iter()
            .all(|k| g.get(*k).map_or(false, Value::is_null))
            && g["bounded_measurement"] == false
            && g.get("bounded_canary").map_or(false, Value::is_null)
            && g.get("target_handoff").map_or(false, Value::is_null)
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false
            && num(g, "recorded_unix_seconds")? <= wall
            && wall - num(g, "recorded_unix_seconds")? <= 60,
        "first guard sample is not a genuine no-trip native sample",
    )?;
    let rows = j.as_array().ok_or("PID1 journal must be JSON array")?;
    require(!rows.is_empty() && rows.len() <= 64, "PID1 history bound")?;
    let own: Vec<_> = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == GUARD_UNIT
                && r["INVOCATION_ID"] == gid
                && r["_BOOT_ID"] == text(p, "boot_id").unwrap_or("").replace('-', "")
        })
        .collect();
    let started: Vec<_> = own
        .iter()
        .filter(|r| {
            r["MESSAGE"].as_str().map_or(false, |s| {
                s.starts_with(&format!("Starting {} -", GUARD_UNIT))
            })
        })
        .collect();
    let finished: Vec<_> = own
        .iter()
        .filter(|r| r["MESSAGE"] == format!("{}: Deactivated successfully.", GUARD_UNIT))
        .collect();
    require(
        started.len() == 1 && finished.len() == 1,
        "missing unique first-guard PID1 events",
    )?;
    let ts = |r: &Value| -> Result<u64> { Ok(text(r, "__MONOTONIC_TIMESTAMP")?.parse()?) };
    require(
        ts(started[0])? >= num(p, "issued_monotonic_us")?
            && ts(finished[0])? > ts(started[0])?
            && ts(finished[0])? <= num(t, "recorded_monotonic_us")?,
        "first guard PID1 ordering differs",
    )
}

pub(super) fn admit() -> Result<Value> {
    let plan_path = PathBuf::from(env::var(PLAN_ENV)?);
    let plan_sha = env::var(PLAN_SHA_ENV)?;
    require(
        plan_path.file_name().and_then(|s| s.to_str()) == Some("plan.json")
            && plan_path.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && plan_path
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .map_or(false, |s| s.starts_with(PLAN_PREFIX)),
        "startup plan namespace",
    )?;
    let original = fs::symlink_metadata(&plan_path)?;
    let p: Value = serde_json::from_slice(&read_owned(&plan_path, &plan_sha, 65536, 0)?)?;
    let iid = env::var("INVOCATION_ID")?;
    let pid = std::process::id();
    let exe = env::current_exe()?;
    let exe_sha = text(&p["harness"], "sha256")?;
    read_owned(&exe, exe_sha, 128 << 20, 0)?;
    require(
        identity(&fs::metadata("/proc/self/exe")?) == identity(&fs::symlink_metadata(&exe)?),
        "mapped harness differs",
    )?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    plan_valid(&p, &iid, pid, &exe, exe_sha, boot.trim(), monotonic_us()?)?;
    require(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{}", UNIT),
        "native cgroup differs",
    )?;
    let a = bound(&p["admission"])?;
    require(
        a["schema"] == ADMISSION_SCHEMA
            && a["epoch"] == EPOCH
            && a["mode"] == "native-cold"
            && a["unit"] == UNIT
            && a["maximum_memory_bytes"] == p["maximum_memory_bytes"]
            && a["candidate_incremental_peak_bytes"] == RESERVATION
            && a["protected_existing_floor_bytes"] == p["minimum_free_bytes"]
            && a["harness"] == p["harness"]
            && a["guard"] == p["guard"]
            && a["worker"] == p["worker"]
            && a["input_packet"] == p["input_packet"]
            && a["boot_id"] == p["boot_id"]
            && a["admitted"] == true
            && a["source_publication"].is_object()
            && a["observer"].is_object()
            && a["fleet"].is_object(),
        "root launcher admission binding differs",
    )?;
    let issued = num(&a, "issued_unix_seconds")?;
    let expires = num(&a, "expires_unix_seconds")?;
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    require(
        issued <= wall && wall < expires && expires > issued && expires - issued <= 60,
        "original native admission lease expired or invalid",
    )?;
    for flag in &[
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        require(
            a[*flag] == false,
            "native admission grants unrelated authority",
        )?;
    }
    let token_path = Path::new(TOKENS).join(&iid).join("guard-admission.json");
    println!(
        "epoch{}-startup-gate waiting invocation={} pid={} expires_monotonic_us={}",
        EPOCH,
        iid,
        pid,
        num(&p, "expires_monotonic_us")?
    );
    loop {
        clock(&p, monotonic_us()?)?;
        read_owned(&plan_path, &plan_sha, 65536, 0)?;
        require(
            identity(&original) == identity(&fs::symlink_metadata(&plan_path)?),
            "startup plan replaced",
        )?;
        match fs::symlink_metadata(&token_path) {
            Ok(_) => {
                // Token digest is transported separately in a sealed companion file.
                // Both are root-owned immutable; the launcher's trusted seal is authority.
                let digest_path = token_path.with_file_name("guard-admission.sha256");
                let digest_meta = fs::symlink_metadata(&digest_path)?;
                require(
                    digest_meta.is_file()
                        && digest_meta.uid() == 0
                        && digest_meta.nlink() == 1
                        && digest_meta.mode() & 0o222 == 0
                        && digest_meta.len() == 65
                        && digest_path.canonicalize()? == digest_path,
                    "unsafe token digest",
                )?;
                let digest_bytes = fs::read(&digest_path)?;
                read_owned(&digest_path, &digest(&digest_bytes), 65, 0)?;
                require(
                    identity(&digest_meta) == identity(&fs::symlink_metadata(&digest_path)?),
                    "token digest replaced",
                )?;
                let token_sha = std::str::from_utf8(&digest_bytes)?;
                let t: Value =
                    serde_json::from_slice(&read_owned(&token_path, token_sha.trim(), 65536, 0)?)?;
                let gp = bound(&t["guard_plan"])?;
                let g = bound(&t["guard_sample"])?;
                let j = bound(&t["guard_pid1_journal"])?;
                token_valid(
                    &p,
                    &plan_sha,
                    &t,
                    &gp,
                    &g,
                    &j,
                    &iid,
                    pid,
                    monotonic_us()?,
                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                )?;
                read_owned(&plan_path, &plan_sha, 65536, 0)?;
                require(
                    identity(&original) == identity(&fs::symlink_metadata(&plan_path)?),
                    "startup plan replaced during gate",
                )?;
                require(
                    identity(&fs::metadata("/proc/self/exe")?)
                        == identity(&fs::symlink_metadata(&exe)?),
                    "mapped harness changed during gate",
                )?;
                require(
                    fs::read_to_string("/proc/self/cgroup")?.trim()
                        == format!("0::/system.slice/{}", UNIT),
                    "native cgroup moved",
                )?;
                clock(&p, monotonic_us()?)?;
                require(
                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() < expires,
                    "original admission expired while waiting for first guard",
                )?;
                println!(
                    "epoch{}-startup-gate admitted invocation={} pid={} plan_sha256={} guard_invocation={}",
                    EPOCH,
                    iid,
                    pid,
                    plan_sha,
                    text(&t, "guard_invocation_id")?
                );
                return Ok(
                    serde_json::json!({"startup_plan":{"path":plan_path,"sha256":plan_sha},"token":{"path":token_path,"sha256":token_sha.trim()},"guard_invocation_id":text(&t,"guard_invocation_id")?,"invocation_id":iid,"main_pid":pid}),
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(test)]
pub(super) fn before_snapshot<G, W>(gate: G, snapshot_work: W) -> Result<()>
where
    G: FnOnce() -> Result<()>,
    W: FnOnce(),
{
    gate()?;
    snapshot_work();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn native_gate_evidence_rejects_wrong_owner_changed_writable_or_linked_file() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("proof");
        fs::write(&p, b"proof").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        let owner = unsafe { libc::geteuid() };
        let sha = digest(b"proof");
        read_leaf(&p, &sha, 5, owner).unwrap();
        assert!(read_leaf(&p, &sha, 5, owner + 1).is_err());
        assert!(read_leaf(&p, &"a".repeat(64), 5, owner).is_err());
        assert!(read_leaf(&p, &sha, 4, owner).is_err());
        let link = dir.path().join("link");
        symlink(&p, &link).unwrap();
        assert!(read_leaf(&link, &sha, 5, owner).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&p, &link).unwrap();
        assert!(read_leaf(&p, &sha, 5, owner).is_err());
        fs::remove_file(&link).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_leaf(&p, &sha, 5, owner).is_err());
    }
    fn fixture() -> (Value, Value, Value, Value, Value) {
        let iid = "a".repeat(32);
        let gid = "b".repeat(32);
        let harness = json!({"path":HARNESS,"sha256":"c".repeat(64)});
        let guard = json!({"path":"/var/lib/jetstreamer/guard-test/guard","sha256":"d".repeat(64)});
        let p = json!({"schema":PLAN_SCHEMA,"epoch":EPOCH,"unit":UNIT,"guard_unit":GUARD_UNIT,
            "worker_root":ROOT,"bootstrap_slot":SLOT,"snapshot_sha256":super::super::SNAPSHOT_SHA,
            "worker":{"path":super::super::WORKER,"sha256":super::super::WORKER_SHA},
            "genesis_sha256":super::super::GENESIS_SHA,
            "input_packet":{"path":super::super::PACKET,"sha256":super::super::PACKET_SHA},
            "maximum_root_physical_bytes":ROOT_CAP,"maximum_memory_bytes":MEMORY,
            "token_root":TOKENS,"boot_id":"boot","harness":harness,"guard":guard,
            "minimum_free_bytes":10,"issued_monotonic_us":100,"expires_monotonic_us":200,
            "admission":{"path":"/admission","sha256":"e".repeat(64)}});
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,
            "filesystem":FILESYSTEM,"worker_root":ROOT,"minimum_free_bytes":10,"maximum_root_physical_bytes":ROOT_CAP,
            "maximum_worker_vmas":3500000,"native_main":{"main_pid":42,"executable":harness["path"],"sha256":harness["sha256"]}});
        let t = json!({"schema":TOKEN_SCHEMA,"startup_plan_sha256":"f".repeat(64),
            "unit":UNIT,"invocation_id":iid,"main_pid":42,"harness":harness,"guard":guard,"boot_id":"boot",
            "admission":p["admission"],"recorded_monotonic_us":180,"guard_invocation_id":gid,
            "guard_plan":{"path":"/guardplan","sha256":"9".repeat(64)}});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","plan":"/guardplan","plan_sha256":"9".repeat(64),
            "guard_sha256":guard["sha256"],"guard_invocation_id":gid,"producer_invocation_id":iid,
            "producer":{"invocation_id":iid,"pid":42,"active":"active","sub":"running","restarts":0,
                "load_state":"loaded","result":"success","restart_policy":"no","kill_mode":"control-group","delegated":false,
                "cgroup":format!("/system.slice/{}",UNIT)},"producer_stop_enabled":true,"native_main":gp["native_main"],
            "minimum_free_bytes":10,"available_bytes":20,"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":ROOT_CAP,
            "root_physical_observation":{"maximum_physical_bytes":ROOT_CAP,"exceeds_budget":false,"conservative_physical_bytes":0},
            "workers":[[42,100]],"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,
            "canary_target_error":null,"target_handoff_error":null,"bounded_measurement":false,
            "bounded_canary":null,"target_handoff":null,"remote_mutations":false,"r2_mutations":false,"recorded_unix_seconds":1000});
        let j = json!([
            {"_PID":"1","_UID":"0","_BOOT_ID":"boot","UNIT":GUARD_UNIT,"INVOCATION_ID":gid,"MESSAGE":format!("Starting {} - native",GUARD_UNIT),"__MONOTONIC_TIMESTAMP":"120"},
            {"_PID":"1","_UID":"0","_BOOT_ID":"boot","UNIT":GUARD_UNIT,"INVOCATION_ID":gid,"MESSAGE":format!("{}: Deactivated successfully.",GUARD_UNIT),"__MONOTONIC_TIMESTAMP":"150"}]);
        (p, t, gp, g, j)
    }
    #[test]
    fn native_gate_binds_plan_to_actual_owner_image_boot_and_original_clock() {
        let (p, _, _, _, _) = fixture();
        let check = |v: &Value| {
            plan_valid(
                v,
                &"a".repeat(32),
                42,
                Path::new(HARNESS),
                &"c".repeat(64),
                "boot",
                190,
            )
        };
        check(&p).unwrap();
        for key in p
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| k.as_str() != "admission")
        {
            let mut bad = p.clone();
            bad[key] = Value::Null;
            assert!(check(&bad).is_err(), "{}", key);
        }
        assert!(
            plan_valid(
                &p,
                "bad",
                42,
                Path::new("/wrong"),
                &"c".repeat(64),
                "boot",
                190
            )
            .is_err()
        );
    }
    #[test]
    fn native_gate_rejects_token_rebinding_missing_proof_stale_or_failed_guard() {
        let (p, t, gp, g, j) = fixture();
        let check = |token: &Value, plan: &Value, sample: &Value, journal: &Value| {
            token_valid(
                &p,
                &"f".repeat(64),
                token,
                plan,
                sample,
                journal,
                &"a".repeat(32),
                42,
                190,
                1001,
            )
        };
        check(&t, &gp, &g, &j).unwrap();
        for key in t.as_object().unwrap().keys() {
            let mut bad = t.clone();
            bad[key] = Value::Null;
            assert!(check(&bad, &gp, &g, &j).is_err(), "token {}", key);
        }
        for key in g.as_object().unwrap().keys() {
            let mut bad = g.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(check(&t, &gp, &bad, &j).is_err(), "guard {}", key);
        }
        for (pointer, value) in &[
            ("/producer/pid", json!(43)),
            ("/producer/restarts", json!(1)),
            ("/producer/active", json!("activating")),
            ("/trip_reason", json!("reserve")),
            ("/producer_stop_enabled", json!(false)),
            ("/recorded_unix_seconds", json!(900)),
            ("/recorded_unix_seconds", json!(1002)),
            ("/root_physical_observation/exceeds_budget", json!(true)),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value.clone();
            assert!(check(&t, &gp, &bad, &j).is_err(), "{}", pointer);
        }
        assert!(check(&t, &gp, &g, &json!([])).is_err());
        let mut wrong = j.clone();
        wrong[1]["_PID"] = json!("2");
        assert!(check(&t, &gp, &g, &wrong).is_err());
        wrong = j.clone();
        wrong[1]["_BOOT_ID"] = json!("previous-boot");
        assert!(check(&t, &gp, &g, &wrong).is_err());
        wrong = j.clone();
        wrong[1]["__MONOTONIC_TIMESTAMP"] = json!("119");
        assert!(check(&t, &gp, &g, &wrong).is_err());
        let mut changed = gp.clone();
        changed["native_main"]["main_pid"] = json!(43);
        assert!(check(&t, &changed, &g, &j).is_err());
    }
    #[test]
    fn native_gate_refusal_precedes_snapshot_callback() {
        let (p, t, gp, g, j) = fixture();
        let work = std::cell::Cell::new(false);
        let result = before_snapshot(
            || -> Result<()> {
                token_valid(
                    &p,
                    &"f".repeat(64),
                    &t,
                    &gp,
                    &g,
                    &j,
                    &"a".repeat(32),
                    42,
                    200,
                    1001,
                )
            },
            || work.set(true),
        );
        assert!(result.is_err());
        assert!(!work.get());
    }
    #[test]
    fn native_gate_deadline_never_resets_or_accepts_unbounded_wait() {
        let p = serde_json::json!({"issued_monotonic_us":100,"expires_monotonic_us":200});
        assert!(clock(&p, 100).is_ok());
        assert!(clock(&p, 199).is_ok());
        assert!(clock(&p, 99).is_err());
        assert!(clock(&p, 200).is_err());
        assert!(
            clock(
                &serde_json::json!({"issued_monotonic_us":100,"expires_monotonic_us":60_000_101}),
                100
            )
            .is_err()
        );
    }
}
