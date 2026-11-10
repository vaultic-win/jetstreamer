//! Retire only the exact distinct closed130 body after independently bound
//! holding, source-owner, indirect-reader and restored-input qualification.
//! No remote mutation, canonical publication, reservation ending or replay launch.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    process::Command,
};
mod atomic_fs;
mod canonical;
mod closure;
mod process_references;
mod transaction;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-cold130-backed-retire-tools-20261110-v4/retire";
const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch130-v1417-production-20260930-v1/lane-a/private/destination-ac17a7c6a33e8f921efc1a4659db0cd6983e67b63879a478b4e22d754a68218e/work/root-cohort-130-130/run-382916-1790762712552279895/archives/epoch-130.jet";
const SHA: &str = "559ddfee24c5d6470f954726b50dd90bdb6db82d13bd9369a3da714023b13961";
const LENGTH: u64 = 83_405_064_152;
const CANONICAL_SHA: &str = "8cb4493da4e67528aea3038915be428b1039218a1dbdaa6a6544a743894475ff";
const OUT: &str = "/var/lib/jetstreamer/cold130-holding-20261110-v4/retirement";
const PRIMARY: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn ident(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn raw(p: &Path, limit: u64, root_only: bool) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "canonical path required"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.len() <= limit
            && m.mode() & 0o022 == 0
            && (!root_only || m.uid() == 0),
        "metadata custody/bound differs"
    );
    let mut b = Vec::new();
    Read::by_ref(&mut f).take(limit + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 == m.len()
            && ident(&m) == ident(&f.metadata()?)
            && ident(&m) == ident(&fs::symlink_metadata(p)?),
        "metadata changed"
    );
    Ok(b)
}
fn bound(v: &Value) -> Result<Value> {
    let b = raw(Path::new(s(v, "path")?), 2 << 20, false)?;
    ensure!(sha(&b) == s(v, "sha256")?, "metadata digest differs");
    Ok(serde_json::from_slice(&b)?)
}
fn scope(p: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "horizon-cold130-backed-private-body-retirement-plan-v2"
            && p["owner"] == "/root"
            && p["primary_thread"] == PRIMARY
            && p["source"] == SOURCE
            && p["sha256"] == SHA
            && p["length"] == LENGTH
            && p["canonical_archive"] == false
            && p["authorizes_only_private_backed_copy_retirement"] == true
            && p["reserve_ending_authorized"] == false
            && p["replay_launch_authorized"] == false
            && p["remote_mutations_authorized"] == false
            && p["source_identity"]
                .as_array()
                .is_some_and(|a| a.len() == 11)
            && p["source_identity"][2] == 1001
            && p["source_identity"][3] == 1003
            && p["source_identity"][4] == 0o100600
            && p["source_identity"][5] == 1
            && p["source_identity"][6] == LENGTH,
        "fixed130 private-body policy differs"
    );
    Ok(())
}
fn custody(c: &Value) -> Result<()> {
    ensure!(
        c["schema"] == "jetstreamer-horizon-holding-custody-v2"
            && c["host"] == "dev-samjohnson"
            && c["bucket"] == "solana-archive-with-accounts-data"
            && c["prefix"] == "node_02/"
            && c["source"] == SOURCE
            && c["length"] == LENGTH
            && c["sha256"] == SHA
            && c["object_key"] == format!("node_02/objects/{SHA}.blob")
            && c["remote_sha256_readback"] == true
            && c["local_source_revalidated"] == true
            && c["canonical_publication_authorized"] == false
            && c["local_retirement_authorized"] == false
            && c["job_resume_authorized"] == false
            && c["runtime_checkpoint_qualified"] == false,
        "genuine distinct130 custody required"
    );
    let m = &c["manifest"];
    ensure!(
        m["sha256"] == SHA
            && m["length"] == LENGTH
            && m["canonical_archive"] == false
            && m["canonical_publication_authorized"] == false
            && sha(&serde_json::to_vec(m)?) == s(c, "manifest_sha256")?
            && c["manifest_key"] == format!("node_02/manifests/{}.json", s(c, "manifest_sha256")?),
        "holding manifest binding differs"
    );
    Ok(())
}
fn lock() -> Result<File> {
    let p = Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock");
    ensure!(p.canonicalize()? == p, "shared lock alias");
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && [0, 1001].contains(&m.uid())
            && m.mode() & 0o777 == 0o600
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "shared local mutation lock unavailable"
    );
    Ok(f)
}
fn own(execute: bool) -> Result<Value> {
    let unit = if execute {
        "horizon-cold130-backed-retire-execute-20261110-v2.service"
    } else {
        "horizon-cold130-backed-retire-check-20261110-v2.service"
    };
    let o=Command::new("/usr/bin/systemctl").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(["show",unit,"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,MemoryMax,MemorySwapMax,TasksMax,RuntimeMaxUSec"]).output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 65536,
        "own native query"
    );
    let mut v = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, x) = line.split_once('=').context("native delimiter")?;
        ensure!(v.insert(k.into(), json!(x)).is_none(), "native duplicate");
    }
    let v = Value::Object(v);
    ensure!(
        v["Id"] == unit
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && s(&v, "MainPID")?.parse::<u32>()? == std::process::id()
            && s(&v, "InvocationID")? == std::env::var("INVOCATION_ID")?
            && v["NRestarts"] == "0"
            && v["ControlPID"] == "0"
            && v["MemorySwapMax"] == "0"
            && v["MemoryMax"] == if execute { "2147483648" } else { "536870912" }
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{unit}"),
        "funded native scope differs"
    );
    Ok(v)
}
fn open_output() -> Result<File> {
    let path = Path::new(OUT);
    let fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = fd.metadata()?;
    ensure!(
        path.canonicalize()? == path && m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "private receipt directory custody differs"
    );
    Ok(fd)
}
fn run(p: &Value, execute: bool) -> Result<()> {
    scope(p)?;
    canonical::validate(p)?;
    ensure!(
        p["custody"]["path"]
            == "/var/lib/jetstreamer/cold130-holding-20261110-v1/receipts/custody-7b0b0c27f95af14975f3ba5c40db87bb81812467dd3311ac471b2577100935ad.json"
            && p["custody"]["sha256"]
                == "29b6bb4e4a8ba713d28fb072f9498cfd5f6eb824a994c8622969ac34a3e0a6b7",
        "genuine holding custody pin differs"
    );
    let c = bound(&p["custody"])?;
    custody(&c)?;
    closure::holding_lineage(p, &c)?;
    let review = bound(&p["indirect_consumers_review"])?;
    closure::validate_review_shape(&review)?;
    let native = own(execute)?;
    let _lock = lock()?;
    transaction::run(p, execute, &native)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 7
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && ["--check-only", "--execute"].contains(&args[6].as_str()),
        "exact argv required"
    );
    let image = fs::read_link("/proc/self/exe")?;
    ensure!(
        unsafe { libc::geteuid() } == 0
            && image == Path::new(IMAGE)
            && sha(&raw(&image, 32 << 20, true)?) == args[5],
        "normally sealed root image required"
    );
    let p = bound(&json!({"path":args[1],"sha256":args[3]}))?;
    run(&p, args[6] == "--execute")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_scope_rejects_foreign_and_canonical_authority() {
        let p = json!({"schema":"horizon-cold130-backed-private-body-retirement-plan-v2","owner":"/root","primary_thread":PRIMARY,"source":SOURCE,"sha256":SHA,"length":LENGTH,"canonical_archive":false,"authorizes_only_private_backed_copy_retirement":true,"reserve_ending_authorized":false,"replay_launch_authorized":false,"remote_mutations_authorized":false,"source_identity":[64512,1,1001,1003,0o100600,1,LENGTH,0,0,0,0]});
        scope(&p).unwrap();
        for (k, v) in [
            ("source", json!("/home/sol/horizon/epoch-130.jet")),
            ("sha256", json!(CANONICAL_SHA)),
            ("reserve_ending_authorized", json!(true)),
            ("remote_mutations_authorized", json!(true)),
        ] {
            let mut q = p.clone();
            q[k] = v;
            assert!(scope(&q).is_err());
        }
    }
}
