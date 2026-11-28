//! Read-only qualification of six obsolete epoch136 snapshot copies. Never unlinks.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
const NAME: &str = "snapshot-59176548-J6ef2VSpLh1ofwD4zXGLAJkNs4i6yZ5JzTr5qG1jBSNN.tar.zst";
const KEEP: &str =
    "/home/sol/.jetstreamer-private/epoch136-hourly-snapshot-input-20261027-v1/transfer/attempt-v1";
fn roots() -> Vec<PathBuf> {
    [2, 3, 4, 5, 7, 8]
        .into_iter()
        .map(|n| {
            PathBuf::from(format!(
                "/home/sol/.jetstreamer-private/epoch136-hourly-suffix-run-parent-20261027-v{n}"
            ))
        })
        .collect()
}
fn identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"allocated_bytes":m.blocks()*512,"uid":m.uid(),"links":m.nlink(),"mode":m.mode(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()})
}
fn snapshot(p: &Path) -> Result<Value> {
    ensure!(p.canonicalize()? == p, "noncanonical snapshot");
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() == 3_170_290_207 && m.mode() & 0o222 == 0,
        "unexpected snapshot identity"
    );
    let before = identity(&m);
    let mut h = Sha256::new();
    let mut b = vec![0; 1024 * 1024];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    ensure!(
        before == identity(&f.metadata()?) && before == identity(&fs::symlink_metadata(p)?),
        "snapshot changed while hashing"
    );
    Ok(json!({"path":p,"identity":before,"sha256":format!("{:x}",h.finalize())}))
}
fn command(args: &[&str]) -> Result<String> {
    let o = Command::new(args[0]).args(&args[1..]).output()?;
    ensure!(o.status.success(), "command failed: {}", args[0]);
    Ok(String::from_utf8(o.stdout)?)
}
fn intersects(s: &str, paths: &[PathBuf]) -> bool {
    paths.iter().any(|p| s.contains(p.to_str().unwrap()))
}
fn process_census(paths: &[PathBuf], ids: &[(u64, u64)]) -> Result<Value> {
    let mut hits = vec![];
    let mut scanned = 0;
    for entry in fs::read_dir("/proc")? {
        let p = entry?.path();
        let Some(pid) = p
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        let stat = match fs::read_to_string(p.join("stat")) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let body = stat.rsplit_once(')').context("proc stat")?.1;
        let start = body
            .split_whitespace()
            .nth(19)
            .context("start ticks")?
            .to_owned();
        let kernel_thread = body
            .split_whitespace()
            .nth(6)
            .context("process flags")?
            .parse::<u64>()?
            & 0x00200000
            != 0;
        let inspect = (|| -> Result<()> {
            for leaf in ["cmdline", "environ", "maps"] {
                let b = match fs::read(p.join(leaf)) {
                    Ok(b) => b,
                    Err(e)
                        if (kernel_thread || body.split_whitespace().next() == Some("Z"))
                            && e.raw_os_error() == Some(libc::ESRCH) =>
                    {
                        Vec::new()
                    }
                    Err(e) => return Err(e.into()),
                };
                let s = String::from_utf8_lossy(&b);
                if intersects(&s, paths) {
                    hits.push(json!({"pid":pid,"start_ticks":start,"reference":leaf}));
                }
            }
            for leaf in ["cwd", "root", "exe"] {
                if let Ok(v) = fs::read_link(p.join(leaf))
                    && paths.iter().any(|r| v.starts_with(r))
                {
                    hits.push(json!({"pid":pid,"start_ticks":start,"reference":leaf,"path":v}));
                }
            }
            for fd in fs::read_dir(p.join("fd"))? {
                let fd = fd?.path();
                match fs::metadata(&fd) {
                    Ok(m) => {
                        if ids.contains(&(m.dev(), m.ino())) {
                            hits.push(json!({"pid":pid,"start_ticks":start,"reference":"fd","identity":[m.dev(),m.ino()]}));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        })();
        if let Err(e) = inspect {
            if p.exists() {
                return Err(e.context(format!("process census PID {pid}")));
            } else {
                continue;
            }
        }
        scanned += 1;
    }
    Ok(json!({"processes_scanned":scanned,"hits":hits}))
}
fn parse_units(raw: &str) -> Vec<BTreeMap<String, String>> {
    raw.split("\n\n")
        .filter_map(|block| {
            let m: BTreeMap<_, _> = block
                .lines()
                .filter_map(|s| s.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
            m.contains_key("Id").then_some(m)
        })
        .collect()
}
fn terminal(m: &BTreeMap<String, String>) -> bool {
    m.get("MainPID").is_none_or(|v| v == "0")
        && m.get("ControlPID").is_none_or(|v| v == "0")
        && m.get("Job").is_none_or(String::is_empty)
        && m.get("SubState")
            .is_some_and(|s| ["dead", "failed", "exited"].contains(&s.as_str()))
}
fn audit(out: &Path, reference_list: &Path) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root census required");
    ensure!(!out.exists(), "output exists");
    let root = roots();
    let paths: Vec<_> = root
        .iter()
        .map(|r| r.join("reproduction/inputs").join(NAME))
        .collect();
    let retained = snapshot(&Path::new(KEEP).join(NAME))?;
    let mut copies = vec![];
    for p in &paths {
        let row = snapshot(p)?;
        ensure!(
            row["sha256"] == retained["sha256"],
            "retained copy hash mismatch"
        );
        copies.push(row);
    }
    let ids: Vec<_> = copies
        .iter()
        .map(|v| {
            (
                v["identity"]["device"].as_u64().unwrap(),
                v["identity"]["inode"].as_u64().unwrap(),
            )
        })
        .collect();
    let before = process_census(&root, &ids)?;
    let raw = command(&[
        "/usr/bin/systemctl",
        "show",
        "*",
        "-pId,ActiveState,SubState,MainPID,ControlPID,InvocationID,Job,Restart,ExecStart,ExecStartPre,ExecStartPost,Environment,WorkingDirectory,RootDirectory,ReadOnlyPaths,ReadWritePaths,BindReadOnlyPaths,BindPaths,FragmentPath,DropInPaths,UnitFileState,Triggers,TriggeredBy",
    ])?;
    let units = parse_units(&raw);
    ensure!(units.len() > 100, "incomplete unit census");
    let refs = fs::read_to_string(reference_list)?;
    let mut references = vec![];
    let mut live_hits = vec![];
    for line in refs.lines() {
        let p = Path::new(line);
        let b = fs::read(p)?;
        ensure!(
            intersects(&String::from_utf8_lossy(&b), &root),
            "reference list changed"
        );
        let mut consumers = vec![];
        for unit in &units {
            if unit.values().any(|v| v.contains(line))
                || unit.get("FragmentPath").is_some_and(|v| v == line)
            {
                consumers.push(json!({"unit":unit["Id"],"terminal":terminal(unit),"native":unit}));
                if !terminal(unit) {
                    live_hits.push(json!({"unit":unit["Id"],"reference":p}));
                }
            }
        }
        references.push(json!({"path":p,"sha256":format!("{:x}",Sha256::digest(&b)),"direct_unit_consumers":consumers}));
    }
    let mut direct = vec![];
    for u in &units {
        if u.values().any(|v| intersects(v, &root)) {
            direct.push(json!({"unit":u,"terminal":terminal(u)}));
            if !terminal(u) {
                live_hits.push(json!({"unit":u["Id"],"direct_candidate_reference":true}));
            }
        }
    }
    let after = process_census(&root, &ids)?;
    for row in &copies {
        let p = Path::new(row["path"].as_str().unwrap());
        ensure!(
            row["identity"] == identity(&fs::symlink_metadata(p)?),
            "copy changed after census"
        );
    }
    ensure!(
        retained["identity"] == identity(&fs::symlink_metadata(Path::new(KEEP).join(NAME))?),
        "retained input changed"
    );
    let bytes: u64 = copies
        .iter()
        .map(|r| r["identity"]["allocated_bytes"].as_u64().unwrap())
        .sum();
    let receipt = json!({"schema":"horizon-six136-snapshot-copy-readonly-audit-v1","retained_hash_verified_input":retained,"candidates":copies,"candidate_allocated_bytes":bytes,"process_before":before,"process_after":after,"unit_count":units.len(),"direct_unit_references":direct,"static_references":references,"live_or_staged_unit_hits":live_hits,"reference_census_limit":"Static references include direct unit consumers only; transitive sealed plans and dormant enabled units require owner review before deletion.","retirement_authorized":false,"deletion_performed":false,"remote_mutations":false});
    let parent = out.parent().context("output parent")?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)?;
    f.write_all(serde_json::to_string_pretty(&receipt)?.as_bytes())?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!(
        "{}",
        json!({"receipt":out,"candidate_allocated_bytes":bytes,"process_hits_before":before["hits"].as_array().unwrap().len(),"process_hits_after":after["hits"].as_array().unwrap().len(),"live_or_staged_unit_hits":live_hits.len(),"retirement_authorized":false})
    );
    Ok(())
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(a.len() == 3, "usage: audit OUTPUT REFERENCE_LIST");
    audit(Path::new(&a[1]), Path::new(&a[2]))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_six_nonretained_paths() {
        let r = roots();
        assert_eq!(r.len(), 6);
        assert!(r.iter().all(|p| !p.starts_with(KEEP)));
        assert!(!intersects(KEEP, &r));
        assert!(intersects(r[0].to_str().unwrap(), &r));
    }
    #[test]
    fn process_or_job_never_terminal() {
        let mut m = BTreeMap::from([
            ("Id".into(), "x.service".into()),
            ("MainPID".into(), "0".into()),
            ("ControlPID".into(), "0".into()),
            ("Job".into(), "".into()),
            ("SubState".into(), "failed".into()),
        ]);
        assert!(terminal(&m));
        for k in ["MainPID", "ControlPID", "Job"] {
            m.insert(k.into(), "1".into());
            assert!(!terminal(&m));
            m.insert(k.into(), if k == "Job" { "" } else { "0" }.into());
        }
    }
}
