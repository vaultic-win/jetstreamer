//! Bounded input-only probes and evidence capture. Never starts an epoch replay.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
mod network;
mod probes;
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-265-replacement-20261119-v3";
const NODE: &str = "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node";
const NODE_SHA: &str = "2789f8211dafc4230a084910867db99699e6470b4a08a6fd8cc6dc00bf080f32";
const MANIFEST: &str =
    "/var/lib/jetstreamer/horizon265-singleton-manifest-20261119-v1/preflight-265-singleton.json";
const MANIFEST_SHA: &str = "a269b418dc5bcd508850d0293cf05e64875d7610c402b696cf8d15f9775c5fcf";
const FINGERPRINT: &str = "sha256:a126bce31196effaf656230c7185e92f73db9574e13a45e3976aae1859461e28";
const TEMPLATE: &str = include_str!(
    "../../horizon265-launch/config/horizon-qualify-265-replacement-20261119-v3.service"
);
const PROPS: &str = "Id,LoadState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,NRestarts,ActiveState,SubState,Result,ExecStart,Job,Restart,KillMode,Delegate,ControlGroup,User,Group,UMask,Type,RemainAfterExit,NoNewPrivileges,ProtectSystem,ProtectHome,ProtectControlGroups,PrivateTmp,PrivateNetwork,RestrictAddressFamilies,ReadWritePaths,ReadOnlyPaths,BindReadOnlyPaths,WorkingDirectory,CapabilityBoundingSet,AmbientCapabilities,Environment,UnsetEnvironment,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,RuntimeMaxUSec,TimeoutStartUSec,TimeoutStopUSec,LimitFSIZE,CPUQuotaPerSecUSec,CPUAffinity,OOMPolicy,OOMScoreAdjust,StandardOutput,StandardError";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().context("missing text")
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> Value {
    json!({"dev":m.dev(),"ino":m.ino(),"len":m.len(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"nlink":m.nlink(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()})
}
fn read(p: &Path, uid: u32, limit: u64, immutable: bool) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == p
            && m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.len() <= limit
            && m.mode() & if immutable { 0o222 } else { 0o022 } == 0,
        "unsafe input {}",
        p.display()
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    ensure!(identity(&m) == identity(&f.metadata()?), "open race");
    let mut b = Vec::new();
    Read::by_ref(&mut f).take(limit + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 <= limit
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(p)?),
        "input changed"
    );
    Ok(b)
}
fn bound(b: &Bound) -> Result<Value> {
    let bytes = read(&b.path, 0, 16 << 20, true)?;
    ensure!(
        hex(&b.sha256, 64) && digest(&bytes) == b.sha256,
        "evidence digest"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn put(p: &Path, v: &Value) -> Result<Bound> {
    let parent = p.parent().context("output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        p.is_absolute()
            && parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o022 == 0,
        "unsafe output parent"
    );
    let mut b = serde_json::to_vec_pretty(v)?;
    b.push(b'\n');
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    f.write_all(&b)?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(Bound {
        path: p.into(),
        sha256: digest(&b),
    })
}
fn show(unit: &str) -> Result<Value> {
    ensure!(
        unit.ends_with(".service")
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "unit syntax"
    );
    let o = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--property", PROPS])
        .output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 1 << 20,
        "manager read"
    );
    let mut v = serde_json::Map::new();
    for l in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, s) = l.split_once('=').context("manager framing")?;
        ensure!(v.insert(k.into(), json!(s)).is_none(), "duplicate property");
    }
    Ok(Value::Object(v))
}
fn command(v: &Value, argv: &[String]) -> Result<()> {
    ensure!(
        !argv.is_empty()
            && argv
                .iter()
                .all(|s| !s.contains(['\n', '\r', ';', '{', '}']) && !s.is_empty()),
        "unsafe command framing"
    );
    let prefix = format!(
        "{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=[",
        argv[0],
        argv.join(" ")
    );
    let s = text(v, "ExecStart")?;
    ensure!(
        s.starts_with(&prefix) && s.ends_with(" }") && s.matches("{ path=").count() == 1,
        "actual command differs"
    );
    Ok(())
}
fn terminal(v: &Value, unit: &str, iid: &str, network: bool) -> Result<u64> {
    ensure!(hex(iid, 32), "IID");
    for (k, want) in [
        ("Id", unit),
        ("InvocationID", iid),
        ("LoadState", "loaded"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", if network { "0" } else { "1" }),
        ("Result", if network { "success" } else { "exit-code" }),
        ("ActiveState", if network { "active" } else { "failed" }),
        ("SubState", if network { "exited" } else { "failed" }),
        ("Job", ""),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
    ] {
        ensure!(v[k] == want, "terminal {k}");
    }
    let pid = text(v, "ExecMainPID")?.parse::<u64>()?;
    ensure!(pid > 1, "missing actual terminal PID");
    Ok(pid)
}
fn drained(unit: &str, pid: u64) -> Result<()> {
    ensure!(
        !Path::new(&format!("/proc/{pid}")).try_exists()?,
        "original process remains"
    );
    let root = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}"));
    fn walk(p: &Path, n: &mut usize) -> Result<()> {
        ensure!(*n > 0 && p.canonicalize()? == p, "drain bound/link");
        *n -= 1;
        for k in ["cgroup.procs", "cgroup.threads"] {
            ensure!(
                fs::read_to_string(p.join(k))?.trim().is_empty(),
                "populated cgroup"
            );
        }
        ensure!(
            fs::read_to_string(p.join("cgroup.events"))?
                .lines()
                .any(|l| l == "populated 0"),
            "descendants active"
        );
        for e in fs::read_dir(p)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                walk(&e.path(), n)?;
            }
        }
        Ok(())
    }
    if root.try_exists()? {
        walk(&root, &mut 128)?;
    }
    let group = format!("0::/system.slice/{unit}");
    for e in fs::read_dir("/proc")? {
        let e = e?;
        if !e
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
        {
            continue;
        }
        match fs::read_to_string(e.path().join("cgroup")) {
            Ok(s) => ensure!(
                !s.lines()
                    .any(|l| l == group || l.starts_with(&format!("{group}/"))),
                "remaining owner process"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn journal(unit: &str, iid: &str) -> Result<Vec<Value>> {
    let o = Command::new("/usr/bin/journalctl")
        .args(["--no-pager", "--output=json", "-n", "1001", "--unit", unit])
        .output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() <= 16 << 20,
        "journal capture"
    );
    let all = serde_json::Deserializer::from_slice(&o.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(all.len() < 1001, "journal capture may be truncated");
    let rows: Vec<_> = all
        .into_iter()
        .filter(|r| r["_SYSTEMD_INVOCATION_ID"] == iid || r["INVOCATION_ID"] == iid)
        .collect();
    ensure!(!rows.is_empty(), "no original journal");
    Ok(rows)
}
#[derive(Clone, Copy)]
enum JournalEvidence {
    StrictNode,
    BoundNetworkNative,
}
fn journal_image(row: &Value, argv: &[String], evidence: JournalEvidence) -> bool {
    (row["_EXE"].as_str() == argv.first().map(String::as_str) && row["_CMDLINE"] == argv.join(" "))
        || (matches!(evidence, JournalEvidence::BoundNetworkNative)
            && row.get("_EXE").is_none()
            && row.get("_CMDLINE").is_none())
}
fn journal_owner(
    rows: &[Value],
    unit: &str,
    iid: &str,
    pid: u64,
    argv: &[String],
    marker: &str,
    evidence: JournalEvidence,
) -> Result<()> {
    // Only the network route has a separately authenticated native result with
    // self digest, PID, IID and unchanged PID1 executable/argv. Journald may
    // miss proc metadata when that short-lived process exits before enrichment.
    let success = matches!(evidence, JournalEvidence::BoundNetworkNative);
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let mut found = None;
    let mut exit = None;
    let mut last = 0;
    for (i, r) in rows.iter().enumerate() {
        ensure!(r["_BOOT_ID"] == boot, "journal boot");
        let mono = text(r, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        ensure!(mono >= last, "journal clock rollback");
        last = mono;
        if r["_PID"] == "1" {
            ensure!(
                r["_UID"] == "0" && r["UNIT"] == unit && r["INVOCATION_ID"] == iid,
                "foreign manager journal"
            );
            let msg = text(r, "MESSAGE")?;
            if (success
                && (msg.starts_with("Finished ")
                    || msg == format!("{unit}: Deactivated successfully.")))
                || (!success && msg == format!("{unit}: Failed with result 'exit-code'."))
            {
                exit = Some(i);
            }
        } else if text(r, "MESSAGE")?.contains(marker) {
            ensure!(
                r["_PID"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(pid)
                    && r["_UID"] == "1000"
                    && r["_SYSTEMD_UNIT"] == unit
                    && r["_SYSTEMD_INVOCATION_ID"] == iid
                    && r["_GID"] == "1000"
                    && journal_image(r, argv, evidence),
                "foreign marker"
            );
            ensure!(found.replace(i).is_none(), "duplicate marker");
        }
    }
    ensure!(
        found.context("expected native diagnostic missing")?
            < exit.context("PID1 terminal missing")?,
        "native/PID1 event order"
    );
    Ok(())
}
fn deny(v: &mut Value) {
    for k in [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
        "full_epoch_qualified",
        "resource_release_authorized",
    ] {
        v[k] = json!(false);
    }
}
fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() == 2 && a[1] == "network-run" {
        return network::run();
    }
    ensure!(
        a.len() == 5,
        "usage: network|probes PLAN PLAN_SHA SELF_SHA, or network-run"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root capture required");
    ensure!(
        digest(&fs::read("/proc/self/exe")?) == a[4],
        "self SHA mismatch"
    );
    let b = Bound {
        path: a[2].clone().into(),
        sha256: a[3].clone(),
    };
    let p = bound(&b)?;
    match a[1].as_str() {
        "network" => network::capture(&p, &b, &a[4]),
        "probes" => probes::capture(&p, &b, &a[4]),
        _ => bail!("unknown command"),
    }
}
#[cfg(test)]
mod journal_tests {
    use super::*;
    #[test]
    fn absent_proc_enrichment_is_network_only_and_never_hides_conflicts() {
        let argv = vec!["/sealed/helper".into(), "network-run".into()];
        let missing = json!({"_PID":"1352200","_UID":"1000","_GID":"1000"});
        assert!(journal_image(
            &missing,
            &argv,
            JournalEvidence::BoundNetworkNative
        ));
        assert!(!journal_image(&missing, &argv, JournalEvidence::StrictNode));
        for bad in [
            json!({"_EXE":"/wrong"}),
            json!({"_CMDLINE":"wrong"}),
            json!({"_EXE":null,"_CMDLINE":null}),
        ] {
            assert!(!journal_image(
                &bad,
                &argv,
                JournalEvidence::BoundNetworkNative
            ));
        }
        let exact = json!({"_EXE":"/sealed/helper","_CMDLINE":"/sealed/helper network-run"});
        assert!(journal_image(&exact, &argv, JournalEvidence::StrictNode));
    }
}
