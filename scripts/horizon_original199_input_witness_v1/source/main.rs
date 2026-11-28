//! Finite verification only. Never launches replay, changes guards, or releases resources.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Output},
};

const GUARD: &str = "horizon-guard145-prefix-shared72h-20261107-v8g1.service";
const TIMER: &str = "horizon-guard145-prefix-shared72h-20261107-v8g1.timer";
const TIMER_IID: &str = "f6f2308db2dc47be8f470030fb587b90";
const ACTOR: &str = "horizon-extract145-prefix-shared72h-20261107-v8g1.service";
const ACTOR_IID: &str = "f37b155136614e0183ba2e9adb8714ef";
const PRIVATE: &str = "/home/sol/.jetstreamer-private";
const FIELDS: &str = "Id,InvocationID,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,Result,ExecMainCode,ExecMainStatus,NRestarts,Job,Unit,ExecStart,Type,User,Group,Restart,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,TimeoutStartUSec,TimeoutStopUSec,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,KillMode";
const GUARD_PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-tools-20261107-v8/epoch145-prefix-extract";
const GUARD_SHA: &str = "b416b7c932ef781c8d0f863b63b803379dd58cb1affe99dced6a61830a95ad76";
const GUARD_PLAN: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-plan-shared72h-20261107-v8g1/plan.json";
const GUARD_PLAN_SHA: &str = "c1a7b5fcad8aa850be48a811fdfa7f703aa162d615070689fbba68f8f025dcf3";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    output_root: PathBuf,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
impl Identity {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
        }
    }
}
#[derive(Serialize)]
struct Verified {
    binding: Bound,
    identity: Identity,
    complete_bytes_hashed: u64,
}
#[derive(Clone, Copy)]
struct Input {
    path: &'static str,
    digest: &'static str,
    maximum: u64,
    writable_state: bool,
}
const INPUTS: [Input; 5] = [
    Input {
        path: "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/jetstreamer-node",
        digest: "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65",
        maximum: 128 << 20,
        writable_state: false,
    },
    Input {
        path: "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/jetstreamer-historical-worker-v1-6-15",
        digest: "9339aa0ee5c39e91ec446bfa561c0e81280a0ddc474a03cf5bb0ce07a3674893",
        maximum: 128 << 20,
        writable_state: false,
    },
    Input {
        path: "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/preflight-199-with-private-200-tail-v4.json",
        digest: "9a975243f50d37ed71329b5f3cd0f5e4a4c83faf2e8018f6db41ed9170ac1de9",
        maximum: 128 << 20,
        writable_state: false,
    },
    Input {
        path: "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/snapshot-85967282-BQvC7FcQTSguJkWHeLnpkVSFv32ZKRqUbgHKxVF97o3x.tar.zst",
        digest: "d4a74f54f44258fd4b078d8d3304a6cb6a7911a87883160e1579727dafbf9e6d",
        maximum: 8_000_000_000,
        writable_state: false,
    },
    Input {
        path: "/var/lib/jetstreamer-root-sweep-epoch199-backfill-20261102-v1/state.json",
        digest: "051642bf5ff3f1fffb5e7d8b2133ff399a0a0f1947fef50c74976b12858da152",
        maximum: 16 << 20,
        writable_state: true,
    },
];
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn clock(id: libc::clockid_t) -> Result<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        unsafe { libc::clock_gettime(id, &mut t) } == 0 && t.tv_sec >= 0 && t.tv_nsec >= 0,
        "clock unavailable"
    );
    (t.tv_sec as u64)
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(t.tv_nsec as u64 / 1000))
        .context("clock overflow")
}
fn metadata_command(program: &str, args: &[&str]) -> Result<Output> {
    Command::new("/usr/bin/timeout")
        .args(["--signal=TERM", "5", program])
        .args(args)
        .env("LC_ALL", "C")
        .env_remove("SYSTEMD_HOST")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .output()
        .context("bounded native query")
}
fn native(unit: &str) -> Result<Value> {
    let o = metadata_command(
        "/usr/bin/systemctl",
        &["show", unit, "--no-pager", &format!("--property={FIELDS}")],
    )?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() <= 65536,
        "native query failed"
    );
    let mut m = serde_json::Map::new();
    for l in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = l.split_once('=').context("native framing")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate native property"
        );
    }
    ensure!(m.get("Id") == Some(&json!(unit)), "native identity crossed");
    Ok(Value::Object(m))
}
fn guard_idle(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == GUARD
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Job"] == ""
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && v["InvocationID"].as_str().is_some_and(|s| hex(s, 32)),
        "protective guard is not a genuinely successful completed invocation"
    );
    Ok(())
}
fn guard_profile(v: &Value) -> Result<()> {
    let expected = format!(
        "{{ path={GUARD_PROGRAM} ; argv[]={GUARD_PROGRAM} guard {GUARD_PLAN} --plan-sha256 {GUARD_PLAN_SHA} --self-sha256 {GUARD_SHA} ;"
    );
    ensure!(
        v["ExecStart"]
            .as_str()
            .is_some_and(|s| s.starts_with(&expected) && s.matches("argv[]=").count() == 1)
            && v["Type"] == "exec"
            && v["User"] == "root"
            && v["Group"] == "root"
            && v["Restart"] == "no"
            && v["MemoryMax"] == "268435456"
            && v["MemorySwapMax"] == "0"
            && v["CPUQuotaPerSecUSec"] == "1s"
            && v["TasksMax"] == "512"
            && v["ExecMainCode"] == "1",
        "protective guard command or limits changed"
    );
    Ok(())
}
fn checked_cadence(v: &Value) -> Result<()> {
    ensure!(v["type"] == "a(stt)", "timer cadence has wrong D-Bus type");
    let rows = v["data"].as_array().context("timer cadence rows")?;
    ensure!(rows.len() == 2, "timer cadence membership");
    let mut actual = Vec::new();
    for row in rows {
        let a = row.as_array().context("timer cadence row")?;
        ensure!(
            a.len() == 3 && a[2].as_u64().is_some(),
            "timer cadence row shape"
        );
        actual.push((
            a[0].as_str().context("timer kind")?,
            a[1].as_u64().context("timer interval")?,
        ));
    }
    actual.sort_unstable();
    ensure!(
        actual
            == vec![
                ("OnActiveUSec", 1_000_000),
                ("OnUnitActiveUSec", 30_000_000)
            ],
        "timer cadence changed or duplicated"
    );
    Ok(())
}
fn cadence() -> Result<Value> {
    let o = metadata_command(
        "/usr/bin/busctl",
        &[
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/horizon_2dguard145_2dprefix_2dshared72h_2d20261107_2dv8g1_2etimer",
            "org.freedesktop.systemd1.Timer",
            "TimersMonotonic",
        ],
    )?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() <= 4096,
        "typed cadence query failed"
    );
    let v = serde_json::from_slice(&o.stdout)?;
    checked_cadence(&v)?;
    Ok(v)
}
fn timer_next(v: &Value) -> Result<u64> {
    ensure!(
        v["Id"] == TIMER
            && v["InvocationID"] == TIMER_IID
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "waiting"
            && v["Job"] == ""
            && v["Unit"] == GUARD,
        "protective timer changed or is not waiting"
    );
    let o = metadata_command(
        "/usr/bin/busctl",
        &[
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/horizon_2dguard145_2dprefix_2dshared72h_2d20261107_2dv8g1_2etimer",
            "org.freedesktop.systemd1.Timer",
            "NextElapseUSecMonotonic",
        ],
    )?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 128,
        "typed timer query failed"
    );
    let raw = std::str::from_utf8(&o.stdout)?;
    let n = raw
        .strip_prefix("t ")
        .and_then(|s| s.strip_suffix('\n'))
        .context("timer property is not an exact uint64")?;
    ensure!(
        !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()),
        "noncanonical timer integer"
    );
    let n = n.parse::<u64>()?;
    ensure!(n > 0 && n < u64::MAX, "no finite armed timer deadline");
    Ok(n)
}
fn actor(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == ACTOR
            && v["InvocationID"] == ACTOR_IID
            && v["MainPID"] == "2463122"
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Job"] == ""
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MemoryMax"] == "85899345920",
        "live exporter changed"
    );
    Ok(())
}
fn source_metadata(path: &Path, maximum: u64, state: bool) -> Result<fs::Metadata> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "noncanonical source path"
    );
    let mut current = PathBuf::new();
    for c in path.components() {
        current.push(c.as_os_str());
        let m = fs::symlink_metadata(&current)?;
        ensure!(
            m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0 && !m.file_type().is_symlink(),
            "source or ancestor lacks root custody"
        );
        if current != path {
            ensure!(m.is_dir(), "non-directory source ancestor");
        }
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() > 0 && m.len() <= maximum,
        "source shape/size"
    );
    if state {
        ensure!(
            m.mode() & 0o777 == 0o600,
            "only exact quarantined state may retain owner write"
        );
    } else {
        ensure!(m.mode() & 0o222 == 0, "immutable member is writable");
    }
    Ok(m)
}
fn hash_input_at(
    path: &Path,
    digest: &str,
    maximum: u64,
    state: bool,
    deadline: u64,
) -> Result<Verified> {
    ensure!(hex(digest, 64), "malformed expected digest");
    ensure!(
        clock(libc::CLOCK_MONOTONIC)? < deadline,
        "verification deadline reached before source metadata"
    );
    let before = Identity::of(&source_metadata(path, maximum, state)?);
    ensure!(
        clock(libc::CLOCK_MONOTONIC)? < deadline,
        "verification deadline reached before source open"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        Identity::of(&f.metadata()?) == before,
        "source changed at open"
    );
    let mut h = Sha256::new();
    let mut n = 0u64;
    let mut buf = vec![0; 1 << 20];
    loop {
        ensure!(
            clock(libc::CLOCK_MONOTONIC)? < deadline,
            "verification deadline reached before complete hashing"
        );
        let k = f.read(&mut buf)?;
        if k == 0 {
            break;
        }
        n = n.checked_add(k as u64).context("byte counter overflow")?;
        ensure!(n <= maximum, "source grew beyond bound");
        h.update(&buf[..k]);
    }
    ensure!(
        n == before.bytes && format!("{:x}", h.finalize()) == digest,
        "whole-byte digest or size differs"
    );
    ensure!(
        Identity::of(&f.metadata()?) == before
            && Identity::of(&source_metadata(path, maximum, state)?) == before,
        "source identity changed during hashing"
    );
    drop(f);
    Ok(Verified {
        binding: Bound {
            path: path.into(),
            sha256: digest.into(),
        },
        identity: before,
        complete_bytes_hashed: n,
    })
}
fn save(root: &Path, name: &str, v: &Value) -> Result<()> {
    let p = root.join(name);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    serde_json::to_writer_pretty(&mut f, v)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}
fn profile(v: &Value, p: &Plan, iid: &str) -> Result<()> {
    let pid = std::process::id().to_string();
    ensure!(
        v["Id"] == p.unit
            && v["InvocationID"] == iid
            && v["ActiveState"] == "activating"
            && v["SubState"] == "start"
            && v["MainPID"] == pid
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Result"] == "success"
            && v["Restart"] == "no"
            && v["Type"] == "oneshot"
            && v["User"] == "root"
            && v["Group"] == "root"
            && v["MemoryMax"] == "2147483648"
            && v["MemorySwapMax"] == "0"
            && v["CPUQuotaPerSecUSec"] == "1s"
            && v["TasksMax"] == "64"
            && v["TimeoutStartUSec"] == "16s"
            && v["TimeoutStopUSec"] == "1s"
            && v["ProtectSystem"] == "strict"
            && v["ProtectHome"] == "read-only"
            && v["PrivateNetwork"] == "yes"
            && v["NoNewPrivileges"] == "yes"
            && v["KillMode"] == "control-group",
        "finite witness native profile differs"
    );
    Ok(())
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let a = env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 7
            && a[1] == "create-witness"
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256",
        "exact witness command required"
    );
    ensure!(hex(&a[4], 64) && hex(&a[6], 64), "digest syntax");
    let image = fs::read_link("/proc/self/exe")?;
    ensure!(
        image.file_name().is_some_and(|s| s == "input-witness")
            && image.parent().and_then(Path::parent)
                == Some(Path::new("/usr/local/lib/jetstreamer")),
        "witness requires a normal sealed program path"
    );
    let im = source_metadata(&image, 128 << 20, false)?;
    ensure!(
        im.mode() & 0o777 == 0o555,
        "program is not immutable executable"
    );
    let executable = fs::read("/proc/self/exe")?;
    ensure!(
        sha(&executable) == a[6]
            && Identity::of(&im) == Identity::of(&fs::symlink_metadata(&image)?),
        "actual program image digest or identity differs"
    );
    let plan_path = Path::new(&a[2]);
    let meta = source_metadata(plan_path, 1 << 20, false)?;
    let raw = fs::read(plan_path)?;
    ensure!(
        Identity::of(&meta) == Identity::of(&fs::symlink_metadata(plan_path)?) && sha(&raw) == a[4],
        "plan bytes/identity crossed"
    );
    let p: Plan = serde_json::from_slice(&raw)?;
    ensure!(
        p.schema == "horizon-original199-input-verification-witness-plan-v1"
            && p.unit.starts_with("horizon-original199-input-witness-")
            && p.unit.ends_with(".service")
            && p.unit.len() <= 180
            && p.unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "witness scope differs"
    );
    ensure!(
        p.output_root.parent() == Some(Path::new(PRIVATE))
            && p.output_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("original199-input-witness-")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))),
        "unsafe output namespace"
    );
    let om = fs::symlink_metadata(&p.output_root)?;
    ensure!(
        om.is_dir()
            && om.uid() == 0
            && om.gid() == 0
            && om.mode() & 0o777 == 0o700
            && p.output_root.canonicalize()? == p.output_root
            && fs::read_dir(&p.output_root)?.next().is_none(),
        "output is not empty root-private directory"
    );
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        hex(&iid, 32)
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{}", p.unit),
        "witness outside original native invocation"
    );
    let own = native(&p.unit)?;
    profile(&own, &p, &iid)?;
    let gp = fs::read(GUARD_PROGRAM)?;
    ensure!(
        gp.len() <= 128 << 20 && sha(&gp) == GUARD_SHA,
        "actual guard image differs"
    );
    let gp = fs::read(GUARD_PLAN)?;
    ensure!(
        gp.len() <= 1 << 20 && sha(&gp) == GUARD_PLAN_SHA,
        "guard plan differs"
    );
    let gp: Value = serde_json::from_slice(&gp)?;
    ensure!(
        gp["minimum_available_memory_bytes"] == 642177138688u64
            && gp["minimum_free_bytes"] == 5074152197938u64
            && gp["actor_memory_bytes"] == 85899345920u64
            && gp["guard_memory_bytes"] == 268435456u64
            && gp["external_pool_bytes"] == 6442450944u64,
        "guard floors changed"
    );
    let before_actor = native(ACTOR)?;
    actor(&before_actor)?;
    let g = native(GUARD)?;
    guard_idle(&g)?;
    guard_profile(&g)?;
    let t = native(TIMER)?;
    let policy = cadence()?;
    let next = timer_next(&t)?;
    let started = clock(libc::CLOCK_MONOTONIC)?;
    ensure!(
        next.checked_sub(started).is_some_and(|n| n >= 18_000_000),
        "less than eighteen seconds of genuine completed guard window"
    );
    let deadline = started
        .checked_add(15_000_000)
        .context("deadline overflow")?
        .min(
            next.checked_sub(2_000_000)
                .context("timer deadline underflow")?,
        );
    save(
        &p.output_root,
        "intent.json",
        &json!({"schema":"horizon-original199-input-verification-intent-v1","plan":{"path":plan_path,"sha256":a[4]},"program":{"path":image,"sha256":a[6]},"native":own,"guard":g,"timer":t,"timer_policy":policy,"actor":before_actor,"started_monotonic_usec":started,"verification_deadline_usec":deadline,"armed_guard_deadline_usec":next,"replay_launch_authorized":false,"resource_credit_bytes":0,"archive_publication_authorized":false}),
    )?;
    let mut verified = Vec::new();
    for i in INPUTS {
        verified.push(hash_input_at(
            Path::new(i.path),
            i.digest,
            i.maximum,
            i.writable_state,
            deadline,
        )?);
    }
    // Every protected source descriptor has been closed before native rechecks.
    ensure!(
        clock(libc::CLOCK_MONOTONIC)? < deadline,
        "complete verification exceeded its original deadline"
    );
    ensure!(
        native(GUARD)? == g
            && native(TIMER)? == t
            && timer_next(&t)? == next
            && native(ACTOR)? == before_actor,
        "guard/timer/actor changed during finite verification"
    );
    let after_policy = cadence()?;
    let end = clock(libc::CLOCK_MONOTONIC)?;
    ensure!(
        end < next
            .checked_sub(1_000_000)
            .context("stop margin underflow")?,
        "guard margin consumed"
    );
    for (i, v) in INPUTS.into_iter().zip(&verified) {
        ensure!(
            Identity::of(&source_metadata(
                Path::new(i.path),
                i.maximum,
                i.writable_state
            )?) == v.identity,
            "source changed before witness publication"
        );
    }
    save(
        &p.output_root,
        "witness.json",
        &json!({"schema":"horizon-original199-complete-input-verification-witness-v1","plan":{"path":plan_path,"sha256":a[4]},"producer_program":{"path":image,"sha256":a[6]},"producer_unit":p.unit,"producer_invocation_id":iid,"producer_pid":std::process::id(),"verified_inputs":verified,"started_monotonic_usec":started,"completed_monotonic_usec":end,"recorded_unix_seconds":clock(libc::CLOCK_REALTIME)?/1_000_000,"guard":g,"timer":t,"timer_policy_before":policy,"timer_policy_after":after_policy,"actor":before_actor,"all_protected_source_descriptors_closed_before_native_recheck":true,"all_original_sources_fully_hashed":true,"original_guard_actor_timer_unchanged":true,"replay_launch_authorized":false,"resource_credit_bytes":0,"archive_publication_authorized":false,"native_original_completion_and_normal_sealing_still_required":true}),
    )?;
    println!(
        "{}",
        json!({"witness":p.output_root.join("witness.json"),"verified_inputs":verified.len(),"resource_credit_bytes":0})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("original199 input verification witness failed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn fixture(bytes: &[u8], mode: u32) -> PathBuf {
        let root = PathBuf::from(env::var("TMPDIR").expect("qualified Root QA TMPDIR"));
        assert!(
            root.starts_with(
                "/var/lib/jetstreamer/horizon-original199-input-witness-qa-20261107-v1"
            )
        );
        let p = root.join(format!(
            "fixture-{}-{}",
            std::process::id(),
            clock(libc::CLOCK_MONOTONIC).unwrap()
        ));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&p)
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
        drop(f);
        p
    }
    fn has_descriptor(p: &Path) -> bool {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|x| x.ok())
            .any(|e| fs::read_link(e.path()).ok().as_deref() == Some(p))
    }
    #[test]
    fn constants_are_exact_distinct_original_inputs() {
        let mut paths = std::collections::BTreeSet::new();
        for i in INPUTS {
            assert!(hex(i.digest, 64));
            assert!(paths.insert(i.path));
            assert_eq!(i.writable_state, i.path.ends_with("/state.json"));
        }
        assert_eq!(paths.len(), 5);
    }
    #[test]
    fn guard_failure_or_active_state_never_becomes_quiet_proof() {
        let g = json!({"Id":GUARD,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","NRestarts":"0","Job":"","Result":"success","ExecMainStatus":"0","InvocationID":"a".repeat(32)});
        guard_idle(&g).unwrap();
        for (k, v) in [
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("ActiveState", "active"),
            ("Job", "pending"),
            ("MainPID", "123"),
            ("NRestarts", "1"),
        ] {
            let mut bad = g.clone();
            bad[k] = json!(v);
            assert!(guard_idle(&bad).is_err(), "{k}");
        }
    }
    #[test]
    fn identity_changes_are_not_reusable_verification() {
        let a = Identity {
            device: 1,
            inode: 2,
            bytes: 3,
            uid: 0,
            gid: 0,
            mode: 0o100444,
            links: 1,
            mtime: 4,
            mtime_nsec: 5,
            ctime: 6,
            ctime_nsec: 7,
        };
        for field in ["inode", "bytes", "mode", "mtime_nsec", "ctime_nsec"] {
            let mut b = serde_json::to_value(&a).unwrap();
            b[field] = json!(99);
            assert_ne!(a, serde_json::from_value::<Identity>(b).unwrap());
        }
    }
    #[test]
    fn unknown_receipt_identity_and_plan_fields_are_rejected() {
        assert!(
            serde_json::from_value::<Plan>(
                json!({"schema":"x","unit":"x","output_root":"/x","extra":true})
            )
            .is_err()
        );
        let v = json!({"device":1,"inode":2,"bytes":3,"uid":0,"gid":0,"mode":0,"links":1,"mtime":0,"mtime_nsec":0,"ctime":0,"ctime_nsec":0,"digest_only":true});
        assert!(serde_json::from_value::<Identity>(v).is_err());
    }
    #[test]
    fn digest_syntax_is_exact() {
        assert!(hex(&"a".repeat(64), 64));
        for s in ["", "A", "../x", "abc"] {
            assert!(!hex(s, 64));
        }
    }
    #[test]
    fn no_partial_hash_can_match_full_digest() {
        assert_ne!(sha(b"complete input"), sha(b"complete"));
        assert_eq!(
            sha(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn complete_real_source_hash_and_identity_are_bound_and_descriptor_is_closed() {
        let bytes = b"whole independently verified source\n";
        let p = fixture(bytes, 0o444);
        let v = hash_input_at(
            &p,
            &sha(bytes),
            1024,
            false,
            clock(libc::CLOCK_MONOTONIC).unwrap() + 30_000_000,
        )
        .unwrap();
        assert_eq!(v.complete_bytes_hashed, bytes.len() as u64);
        assert_eq!(v.identity, Identity::of(&fs::symlink_metadata(&p).unwrap()));
        assert!(!has_descriptor(&p));
        fs::remove_file(p).unwrap();
    }
    #[test]
    fn failed_digest_does_not_leave_source_descriptor_open() {
        let p = fixture(b"source", 0o444);
        assert!(
            hash_input_at(
                &p,
                &"a".repeat(64),
                1024,
                false,
                clock(libc::CLOCK_MONOTONIC).unwrap() + 30_000_000
            )
            .is_err()
        );
        assert!(!has_descriptor(&p));
        fs::remove_file(p).unwrap();
    }
    #[test]
    fn expired_deadline_aborts_without_complete_witness_or_open_descriptor() {
        let p = fixture(b"source", 0o444);
        assert!(hash_input_at(&p, &sha(b"source"), 1024, false, 0).is_err());
        assert!(!has_descriptor(&p));
        fs::remove_file(p).unwrap();
    }
    #[test]
    fn writable_member_and_alias_are_rejected_before_hashing() {
        let p = fixture(b"source", 0o600);
        assert!(hash_input_at(&p, &sha(b"source"), 1024, false, u64::MAX).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        let alias = p.with_extension("link");
        symlink(&p, &alias).unwrap();
        assert!(hash_input_at(&alias, &sha(b"source"), 1024, false, u64::MAX).is_err());
        fs::remove_file(alias).unwrap();
        fs::remove_file(p).unwrap();
    }
    #[test]
    fn quarantined_state_is_explicit_and_still_requires_full_digest() {
        let p = fixture(b"quarantined", 0o600);
        let v = hash_input_at(&p, &sha(b"quarantined"), 1024, true, u64::MAX).unwrap();
        assert_eq!(v.identity.mode & 0o777, 0o600);
        assert!(hash_input_at(&p, &sha(b"different"), 1024, true, u64::MAX).is_err());
        fs::remove_file(p).unwrap();
    }
    #[test]
    fn body_change_and_replacement_invalidate_recorded_identity() {
        let p = fixture(b"old source", 0o444);
        let old = hash_input_at(&p, &sha(b"old source"), 1024, false, u64::MAX).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&p, b"new source").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        assert_ne!(
            old.identity,
            Identity::of(&fs::symlink_metadata(&p).unwrap())
        );
        fs::remove_file(p).unwrap();
    }
    #[test]
    fn wrong_size_and_empty_body_do_not_verify() {
        let p = fixture(b"source", 0o444);
        assert!(hash_input_at(&p, &sha(b"source"), 2, false, u64::MAX).is_err());
        fs::remove_file(p).unwrap();
        let p = fixture(b"", 0o444);
        assert!(hash_input_at(&p, &sha(b""), 1024, false, u64::MAX).is_err());
        fs::remove_file(p).unwrap();
    }
    #[test]
    fn cadence_accepts_only_the_exact_two_typed_events_in_either_order() {
        let a = json!({"type":"a(stt)","data":[["OnUnitActiveUSec",30000000,99],["OnActiveUSec",1000000,1 ]]});
        checked_cadence(&a).unwrap();
        let b = json!({"type":"a(stt)","data":[["OnActiveUSec",1000000,1],["OnUnitActiveUSec",30000000,99 ]]});
        checked_cadence(&b).unwrap();
        for v in [
            json!({"type":"a(stt)","data":[["OnActiveUSec",1000000,1],["OnActiveUSec",1000000,99 ]]}),
            json!({"type":"a(stt)","data":[["OnActiveUSec",1000000,1],["OnUnitActiveUSec",60000000,99 ]]}),
            json!({"type":"wrong","data":[]}),
        ] {
            assert!(checked_cadence(&v).is_err());
        }
    }
    #[test]
    fn genuine_oneshot_main_process_profile_preserves_every_limit() {
        let mut native: Value =
            serde_json::from_str(include_str!("native-oneshot-profile.json")).unwrap();
        let p = Plan {
            schema: "horizon-original199-input-verification-witness-plan-v1".into(),
            unit: native["Id"].as_str().unwrap().into(),
            output_root: PathBuf::from("/unused-test-output"),
        };
        let iid = native["InvocationID"].as_str().unwrap().to_owned();
        let pid = std::process::id().to_string();
        native["MainPID"] = json!(pid);
        profile(&native, &p, &iid).unwrap();
        for (key, value) in [
            ("TimeoutStartUSec", "17s"),
            ("TimeoutStopUSec", "2s"),
            ("KillMode", "process"),
            ("MemoryMax", "4294967296"),
            ("CPUQuotaPerSecUSec", "2s"),
            ("Restart", "always"),
        ] {
            let mut bad = native.clone();
            bad[key] = json!(value);
            assert!(profile(&bad, &p, &iid).is_err(), "{key}");
        }
        native["MainPID"] = json!("0");
        native["ControlPID"] = json!(pid);
        assert!(profile(&native, &p, &iid).is_err());
    }
    #[test]
    fn actual_typed_busctl_array_layout_is_accepted_without_extra_wrapper() {
        let genuine: Value =
            serde_json::from_str(include_str!("native-timer-cadence.json")).unwrap();
        checked_cadence(&genuine).unwrap();
        let mut wrong = genuine.clone();
        wrong["data"] = json!([genuine["data"].clone()]);
        assert!(checked_cadence(&wrong).is_err());
    }
    #[test]
    fn guard_command_and_full_limits_cannot_be_borrowed() {
        let command = format!(
            "{{ path={GUARD_PROGRAM} ; argv[]={GUARD_PROGRAM} guard {GUARD_PLAN} --plan-sha256 {GUARD_PLAN_SHA} --self-sha256 {GUARD_SHA} ; ignore_errors=no ; start_time=[n/a] }}"
        );
        let g = json!({"ExecStart":command,"Type":"exec","User":"root","Group":"root","Restart":"no","MemoryMax":"268435456","MemorySwapMax":"0","CPUQuotaPerSecUSec":"1s","TasksMax":"512","ExecMainCode":"1"});
        guard_profile(&g).unwrap();
        for (k, v) in [
            ("ExecStart", "/usr/bin/true"),
            ("MemoryMax", "134217728"),
            ("CPUQuotaPerSecUSec", "2s"),
            ("Restart", "always"),
            ("ExecMainCode", "0"),
        ] {
            let mut b = g.clone();
            b[k] = json!(v);
            assert!(guard_profile(&b).is_err(), "{k}");
        }
    }
}
