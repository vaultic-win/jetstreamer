//! Evict the two closed epoch 157 qualification caches, retaining all four names of the shared index.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, ErrorKind, Read},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

#[allow(dead_code)]
#[path = "../horizon_epoch170_checkpoint_suffix/evidence.rs"]
mod evidence;
#[path = "../../jetstreamer-horizon-observe/src/process_references.rs"]
mod process_references;

const PRIVATE: &str = "/home/sol/.jetstreamer-private";
const RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const DIR: &str = "closed157-qualification-index-retirement-20261128-v1";
const INDEX: &str = "epoch-157-bafyreid3blgkskskfusagrisduht27k5noziwynxglehrw5e7gqocfyape-mainnet-cid-to-offset-and-size.index";
const HASH: &str = "fcb52c21151a74722055960f4407d8afc997e73b2d4525330eb108f9ac3bd544";
const SIZE: u64 = 5_757_171_434;
const RETAINED_INODE: u64 = 118_555_036;
const DEAD: &str = "jetstreamer-holding-scratch185-execute-0946-20261024-v2.service";
const DEAD_HASH: &str = "a0aff45bab4df5b3be53d4eddec3d5d97e2acadfd1ceac9c24e2896e480802a9";
mod lane_cache;

#[derive(Clone, Copy)]
struct Owner {
    name: &'static str,
    destination: &'static str,
    lock_inode: u64,
    index_inode: u64,
}
const OWNERS: [Owner; 6] = [
    Owner {
        name: "epoch157-late-terminal-qualification-v2",
        destination: "dbe43e29c2f42bff98eb25495154649cd39665d9316f517b5a5e24ee09ebe5ad",
        lock_inode: 112590902,
        index_inode: 116006694,
    },
    Owner {
        name: "epoch157-handoff-qualification-v2",
        destination: "50745f972c4b04a4c68de453c43435ffbca439274b928c9c8fed79800e2738f2",
        lock_inode: 108991800,
        index_inode: 110166516,
    },
    Owner {
        name: "epoch157-handoff-qualification-v3-zstd",
        destination: "b94c8c225335bfc81dd1b8f0871c8fdb5156674697c24562081b48ac4a7832c9",
        lock_inode: 118557495,
        index_inode: RETAINED_INODE,
    },
    Owner {
        name: "epoch157-handoff-qualification-v4-zstd",
        destination: "a485754f37ee8f7a82b28d60d471081723a8c7df441876a307def193cbeee16c",
        lock_inode: 93930273,
        index_inode: RETAINED_INODE,
    },
    Owner {
        name: "epoch157-handoff-qualification-v5-zstd",
        destination: "01c2ddf349db07085bfc53a96faa155e97237b786aecccf107a7b445a9ff6bed",
        lock_inode: 93930292,
        index_inode: RETAINED_INODE,
    },
    Owner {
        name: "epoch157-handoff-qualification-v6-zstd",
        destination: "59261148244a575ba7d2ee901b11e55e6e6db240fcf29490892dd496a1af8bca",
        lock_inode: 93930712,
        index_inode: RETAINED_INODE,
    },
];
const PREVIOUS_SEGMENTS: [(&str, &str, u64, u64); 2] = [
    (
        "epoch-157-v158-late-terminal.jet.segment.json",
        "f6b6b7388f80ee06b0c9b23125020d8b616736b89455bf488dadcfe082aab5cf",
        68_249_461,
        6_368,
    ),
    (
        "epoch-157-v156-handoff-qualification.jet.segment.json",
        "71dbc46df4c1a6373ff32b7f927ad11a59284cf78efb9a7d37ef9554979faa64",
        68_137_403,
        2_774,
    ),
];

fn owner_path(owner: &Owner) -> PathBuf {
    Path::new(PRIVATE).join(owner.name)
}
fn index_path(owner: &Owner) -> PathBuf {
    owner_path(owner)
        .join("output/compact-indexes/157")
        .join(INDEX)
}

fn lock(path: &Path, dev: u64, ino: u64) -> Result<File> {
    ensure!(
        path.canonicalize()? == path,
        "indirect lock {}",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let s = f.metadata()?;
    ensure!(
        s.is_file() && s.dev() == dev && s.ino() == ino && s.nlink() == 1,
        "lock identity {}",
        path.display()
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "lock busy {}",
        path.display()
    );
    Ok(f)
}

fn index_stamp(owner: &Owner) -> Result<Value> {
    let p = index_path(owner);
    ensure!(p.canonicalize()? == p, "indirect index");
    let s = fs::symlink_metadata(p)?;
    let kept = owner.index_inode == RETAINED_INODE;
    ensure!(
        s.is_file()
            && (
                s.dev(),
                s.ino(),
                s.nlink(),
                s.len(),
                s.uid(),
                s.gid(),
                s.mode()
            ) == (
                64512,
                owner.index_inode,
                if kept { 4 } else { 1 },
                SIZE,
                1001,
                1003,
                0o100600
            ),
        "index identity {}",
        owner.name
    );
    Ok(json!([
        s.dev(),
        s.ino(),
        s.nlink(),
        s.len(),
        s.blocks(),
        s.mtime(),
        s.mtime_nsec(),
        s.ctime(),
        s.ctime_nsec()
    ]))
}

fn hash_index(owner: &Owner) -> Result<Value> {
    let before = index_stamp(owner)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(index_path(owner))?;
    ensure!(file.metadata()?.ino() == owner.index_inode, "changed open");
    let mut h = Sha256::new();
    let mut bytes = 0;
    let mut buf = vec![0; 1 << 20];
    let mut f = file.take(SIZE + 1);
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        bytes += n as u64;
        if bytes % (32 << 20) == 0 {
            unsafe {
                libc::posix_fadvise(
                    f.get_ref().as_raw_fd(),
                    (bytes - (32 << 20)) as i64,
                    32 << 20,
                    libc::POSIX_FADV_DONTNEED,
                );
            }
        }
    }
    ensure!(
        bytes == SIZE && format!("{:x}", h.finalize()) == HASH && index_stamp(owner)? == before,
        "index content {}",
        owner.name
    );
    Ok(before)
}

fn lineage() -> Result<Vec<Value>> {
    let mut refs = Vec::new();
    for (owner, (name, hash, start, count)) in OWNERS.iter().zip(PREVIOUS_SEGMENTS) {
        let path = owner_path(owner).join("output").join(name);
        ensure!(path.canonicalize()? == path, "indirect segment manifest");
        let bytes = fs::read(&path)?;
        ensure!(
            evidence::digest(&bytes) == hash,
            "different retained segment manifest"
        );
        let v: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            v["epoch"] == 157
                && v["output_slot_start"] == start
                && v["output_slot_count"] == count
                && v["terminal"]["slot"] == start + count - 1,
            "different closed interval"
        );
        refs.push(json!({"path":path,"sha256":hash,"terminal":v["terminal"]["slot"]}));
    }
    Ok(refs)
}

fn staged() -> Result<Value> {
    let mut rg = Command::new("/usr/bin/rg");
    rg.args([
        "--no-config",
        "--files-with-matches",
        "--null",
        "--fixed-strings",
        "--hidden",
        "--no-ignore",
        "--text",
    ]);
    for owner in &OWNERS[..2] {
        rg.args(["-e", owner.name]);
    }
    for path in [
        "/etc/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/home/sol/.config/systemd/user",
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
        "/etc/crontab",
    ] {
        if Path::new(path).try_exists()? {
            rg.arg(path);
        }
    }
    let scan = rg.output()?;
    ensure!(
        matches!(scan.status.code(), Some(0 | 1)),
        "staged definition search failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let mut known = Vec::new();
    for name in scan.stdout.split(|b| *b == 0).filter(|b| !b.is_empty()) {
        let p = Path::new(std::str::from_utf8(name)?);
        ensure!(
            p == Path::new("/run/systemd/transient").join(DEAD)
                && evidence::digest(&fs::read(p)?) == DEAD_HASH,
            "other staged owner {}",
            p.display()
        );
        let state = evidence::props(
            DEAD,
            "Id,ActiveState,SubState,MainPID,ControlPID,Job,TriggeredBy,Restart,InvocationID",
        )?;
        ensure!(
            state["ActiveState"] == "failed"
                && state["MainPID"] == "0"
                && state["ControlPID"] == "0"
                && state["Job"].is_empty()
                && state["TriggeredBy"].is_empty()
                && state["Restart"] == "no"
                && state["InvocationID"] == "551ebb811ccb4b3da1acf9d06f3fbf56",
            "historical binding is runnable"
        );
        known.push(state);
    }
    let mut latest = None;
    for ent in fs::read_dir(RUNTIME)? {
        let entry = ent?;
        if !entry.file_name().as_encoded_bytes().starts_with(b"root") {
            continue;
        }
        let p = entry.path().join("ROOT_COMPLETE_OPERATIONAL_FLEET.json");
        if !p.try_exists()? {
            continue;
        }
        let stamp = p.metadata()?.modified()?;
        if latest.as_ref().is_none_or(|(t, _)| stamp > *t) {
            latest = Some((stamp, p));
        }
    }
    let fleet = latest.context("no campaign fleet")?.1;
    let bytes = evidence::trusted(&fleet)?;
    let d: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        d["owner"] == "/root"
            && d["epochs"]
                .as_array()
                .is_some_and(|r| r.iter().any(|e| e["epoch"] == 157)),
        "wrong fleet"
    );
    let body = std::str::from_utf8(&bytes)?;
    ensure!(
        OWNERS[..2].iter().all(|s| !body.contains(s.name)),
        "current fleet binds qualification inputs"
    );
    Ok(
        json!({"drained_definitions":known,"fleet":{"path":fleet,"sha256":evidence::digest(&bytes)}}),
    )
}

fn kernel(owners: &[Owner; 6], lane_scope: bool) -> Result<Vec<Value>> {
    let mut results = Vec::new();
    for owner in &owners[..2] {
        let root = if lane_scope {
            owner_path(owner).join("output/compact-indexes/157")
        } else {
            owner_path(owner)
        };
        let scan = process_references::scan(Path::new("/proc"), &root)?;
        ensure!(
            scan.references.is_empty(),
            "live owner {}: {:?}",
            owner.name,
            scan.references
        );
        results.push(json!({"root":root,"processes":scan.inspected_processes}));
    }
    // A subdirectory or file bind rooted under a qualification tree can conceal its host path.
    let ids: Vec<PathBuf> = owners[..2]
        .iter()
        .map(|p| {
            let base = owner_path(p);
            let root = if lane_scope {
                base.join("output/compact-indexes/157")
            } else {
                base
            };
            Path::new("/").join(root.strip_prefix("/home/sol").unwrap())
        })
        .collect();
    let mut namespaces = BTreeSet::new();
    for proc in fs::read_dir("/proc")? {
        let p = proc?.path();
        if !p
            .file_name()
            .unwrap()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let census = (|| -> std::io::Result<()> {
            // Inode checks also cover descriptors and mappings reached through a bind of an ancestor.
            for fd in fs::read_dir(p.join("fd"))? {
                match fs::metadata(fd?.path()) {
                    Ok(m)
                        if m.dev() == 64512 && owners.iter().any(|o| o.index_inode == m.ino()) =>
                    {
                        return Err(std::io::Error::other("an epoch 157 index is open"));
                    }
                    Ok(_) => (),
                    Err(e)
                        if e.kind() == ErrorKind::NotFound
                            || e.raw_os_error() == Some(libc::ESRCH) =>
                    {
                        ()
                    }
                    Err(e) => return Err(e),
                }
            }
            let mut maps = BufReader::new(File::open(p.join("maps"))?);
            let mut line = String::new();
            while maps.read_line(&mut line)? > 0 {
                let mut f = line.split_ascii_whitespace();
                if let (Some(device), Some(inode)) = (f.nth(3), f.next()) {
                    if device == "fc:00"
                        && inode
                            .parse::<u64>()
                            .is_ok_and(|i| owners.iter().any(|o| o.index_inode == i))
                    {
                        return Err(std::io::Error::other("an epoch 157 index is mapped"));
                    }
                }
                line.clear();
            }
            let ns = fs::metadata(p.join("ns/mnt"))?.ino();
            if namespaces.contains(&ns) {
                return Ok(());
            }
            let info = fs::read_to_string(p.join("mountinfo"))?;
            for line in info.lines() {
                let mut cols = line.split_ascii_whitespace();
                let f = cols.nth(3).unwrap_or("");
                if ids.iter().any(|id| Path::new(f).starts_with(id)) {
                    return Err(std::io::Error::other(
                        "qualification cache mounted in a namespace",
                    ));
                }
            }
            namespaces.insert(ns);
            Ok(())
        })();
        if let Err(e) = census {
            if e.kind() != ErrorKind::NotFound && e.raw_os_error() != Some(libc::ESRCH) {
                return Err(e.into());
            }
        }
    }
    Ok(results)
}

fn free() -> Result<u64> {
    Ok(evidence::available()?.0)
}
fn run(mode: &str) -> Result<Value> {
    ensure!(
        matches!(mode, "check" | "retire" | "check-lanes" | "retire-lanes")
            && unsafe { libc::geteuid() } == 0,
        "use check or retire through the sealed root operator"
    );
    let lane_scope = matches!(mode, "check-lanes" | "retire-lanes");
    let owners = if lane_scope {
        lane_cache::owners()
    } else {
        OWNERS
    };
    let base = Path::new(RUNTIME).join(if lane_scope { lane_cache::DIR } else { DIR });
    let exe = fs::read_link("/proc/self/exe")?;
    let deployment = if lane_scope {
        let package = exe.parent().context("runtime package")?;
        ensure!(
            package.parent() == Some(base.as_path())
                && package
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.strip_prefix("tools-v"))
                    .and_then(|v| v.parse::<u32>().ok())
                    .is_some_and(|v| v > 0),
            "unsealed lane retirement package"
        );
        package.to_path_buf()
    } else {
        base.join("tools")
    };
    let seal = evidence::reference(&deployment.join("deployment-seal-receipt.json"))?;
    ensure!(
        fs::read_link("/proc/self/exe")? == evidence::member(&seal, "retire")?,
        "use the sealed image"
    );
    let mut locks = vec![
        lock(
            Path::new("/run/horizon-epoch171-to136-g1.operation.lock"),
            26,
            3453440,
        )?,
        lock(
            &Path::new(PRIVATE).join("r2-receipts/local-mutation.lock"),
            64512,
            101135013,
        )?,
    ];
    let fence = if lane_scope {
        Some(lane_cache::Fences::acquire()?)
    } else {
        None
    };
    for owner in &owners {
        let path = owner_path(owner)
            .join(if lane_scope && owner.index_inode != RETAINED_INODE {
                "private"
            } else {
                ".jetstreamer-private"
            })
            .join(format!("destination-{}", owner.destination))
            .join("locks/epoch-157.lock");
        locks.push(lock(&path, 64512, owner.lock_inode)?);
    }
    let manifests = if lane_scope {
        lane_cache::lineage()?
    } else {
        lineage()?
    };
    let checked = base.join("CHECKED.json");
    let done = base.join("COMPLETE.json");
    let retained = hash_index(&owners[2])?;
    for kept in &owners[2..] {
        ensure!(index_stamp(kept)? == retained, "retained aliases changed");
        if lane_scope {
            lane_cache::survey(kept, &retained)?;
        }
    }
    let flag = base.join("INTENT.json");
    if matches!(mode, "check" | "check-lanes") {
        let targets = owners[..2]
            .iter()
            .map(hash_index)
            .collect::<Result<Vec<_>>>()?;
        let definition = if lane_scope {
            for (owner, target) in owners[..2].iter().zip(&targets) {
                lane_cache::survey(owner, target)?;
            }
            lane_cache::staged()?
        } else {
            staged()?
        };
        if let Some(v) = &fence {
            v.check()?;
        }
        let scan = kernel(&owners, lane_scope)?;
        let proof = json!({"operator":seal,"retained":retained,"targets":targets,"sha256":HASH,"closed_segments":manifests,"staged":definition,"kernel":scan});
        if checked.try_exists()? {
            let old = evidence::bound(&evidence::reference(&checked)?)?;
            ensure!(
                old["targets"] == proof["targets"]
                    && old["retained"] == retained
                    && old["operator"] == seal,
                "different check"
            );
        } else {
            evidence::receipt(&checked, &proof)?;
        }
        return evidence::reference(&checked);
    }
    let proof = evidence::bound(&evidence::reference(&checked)?)?;
    ensure!(
        proof["operator"] == seal
            && proof["retained"] == retained
            && proof["closed_segments"].as_array() == Some(&manifests)
            && proof["sha256"] == HASH,
        "invalid prior check"
    );
    let definition = if lane_scope {
        lane_cache::staged()?
    } else {
        staged()?
    };
    if let Some(v) = &fence {
        v.check()?;
    }
    let scan = kernel(&owners, lane_scope)?;
    if done.try_exists()? {
        ensure!(owners[..2].iter().all(|o|matches!(fs::symlink_metadata(index_path(o)),Err(e) if e.kind()==ErrorKind::NotFound)),"recreated target");
        return evidence::reference(&done);
    }
    if !flag.try_exists()? {
        for (i, o) in owners[..2].iter().enumerate() {
            ensure!(
                index_stamp(o)? == proof["targets"][i],
                "changed qualified target"
            );
        }
        evidence::receipt(
            &flag,
            &json!({"checked":evidence::reference(&checked)?,"before":free()?,"staged":definition,"kernel":scan}),
        )?;
    }
    let intent = evidence::bound(&evidence::reference(&flag)?)?;
    ensure!(
        intent["checked"] == evidence::reference(&checked)?,
        "different retirement intent"
    );
    let mut removed = 0;
    for (i, owner) in owners[..2].iter().enumerate() {
        let path = index_path(owner);
        let receipt = base.join(format!("REMOVED_{}.json", owner.index_inode));
        if receipt.try_exists()? {
            ensure!(!path.try_exists()?, "retired target reappeared");
            continue;
        }
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let stamp = index_stamp(owner)?;
                ensure!(stamp == proof["targets"][i], "changed selected inode");
                ensure!(
                    index_stamp(&owners[2])? == retained,
                    "changed retained inode"
                );
                if let Some(v) = &fence {
                    v.check()?;
                }
                let allocation = stamp[4].as_u64().context("blocks")? * 512;
                fs::remove_file(&path)?;
                File::open(path.parent().context("parent")?)?.sync_all()?;
                ensure!(!path.try_exists()?, "retirement did not remove target");
                evidence::receipt(
                    &receipt,
                    &json!({"path":path,"inode":owner.index_inode,"unlinked_allocation":allocation,"intent":evidence::reference(&flag)?}),
                )?;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                evidence::receipt(
                    &receipt,
                    &json!({"path":path,"inode":owner.index_inode,"unlinked_allocation":0,"recovered_absence":true,"intent":evidence::reference(&flag)?}),
                )?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let mut details = Vec::new();
    for o in &owners[..2] {
        let r = evidence::reference(&base.join(format!("REMOVED_{}.json", o.index_inode)))?;
        let row = evidence::bound(&r)?;
        removed += row["unlinked_allocation"].as_u64().context("removal")?;
        details.push(r);
    }
    let after = free()?;
    if lane_scope {
        ensure!(
            manifests == lane_cache::lineage()?,
            "preserved material changed"
        );
        for kept in &owners[2..] {
            ensure!(index_stamp(kept)? == retained, "retained name changed");
        }
    }
    let before = intent["before"].as_u64().context("before")?;
    evidence::receipt(
        &done,
        &json!({"intent":evidence::reference(&flag)?,"removed":details,"retained_paths":owners[2..].iter().map(index_path).collect::<Vec<_>>(),"sha256":HASH,"allocated_bytes_removed":removed,"available_before":before,"available_after":after,"conservative_credit":removed.min(after.saturating_sub(before))}),
    )
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 2,
        "usage: retire check|retire|check-lanes|retire-lanes"
    );
    println!("{}", run(&args[1])?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_evictions_keep_all_four_independent_names_for_the_verified_copy() {
        let names: BTreeSet<_> = OWNERS.iter().map(index_path).collect();
        let dirs: BTreeSet<_> = OWNERS.iter().map(|o| o.destination).collect();
        let locks: BTreeSet<_> = OWNERS.iter().map(|o| o.lock_inode).collect();
        assert_eq!((names.len(), dirs.len(), locks.len()), (6, 6, 6));
        assert_eq!(OWNERS[0].index_inode, 116006694);
        assert_eq!(OWNERS[1].index_inode, 110166516);
        assert!(OWNERS[2..].iter().all(|o| o.index_inode == RETAINED_INODE));
        assert!(
            names
                .iter()
                .all(|p| p.ends_with(Path::new("compact-indexes/157").join(INDEX)))
        );
    }
    #[test]
    fn a_different_lock_inode_is_refused_without_mutating_its_contents() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let s = temp.as_file().metadata().unwrap();
        assert!(lock(temp.path(), s.dev(), s.ino() + 1).is_err());
        assert!(lock(temp.path(), s.dev(), s.ino()).is_ok());
        assert_eq!(temp.as_file().metadata().unwrap().len(), 0);
    }
}
