//! Original epoch 166 cold bootstrap, completed input caches, and stopped-generation evidence.
use super::*;

pub const EPOCH: u64 = 166;
pub const BASE: &str = "epoch166-independent-cold-recovery-20261121-v1";
pub const UNIT: &str = "horizon-qualify-166-independent-recovery-20261121-v1.service";
pub const TIMER: &str = "horizon-guard-166-independent-recovery-20261121-v1.timer";
pub const LANE: &str = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1";
pub const ATTEMPT: &str = "replacement-local3retry10-20261121-v1";
pub const OLD: &str = "epoch166-independent-cold-20261120-v1";
pub const CAP: u64 = 288 << 30;
pub const PREVIOUS_GUARD_ARGV: &str =
    "d9065f60a113cec3b3562aba6717cd0908673546c1c5864332cf6de39d1ef5f2";
const OLD_UNIT: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
const OLD_IID: &str = "fa16ee2f14fe44ecbc37c59e197553ac";
const PREVIOUS: &str = "replacement-local3retry9-20261110-v1";
const PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1";
const INPUTS: &str = "/usr/local/lib/jetstreamer/horizon-standard-local-input166-20261110-v1";
const BOOT: &str = "snapshot-71711708-73JLv83cyRgHUNxtajhwXimfDSH4GUmu6R8LHKPbxu76.tar.zst";
const BOOT_SHA: &str = "1e8fa388737b80a9e2218cd09f2fee43b064e19a65e26e466abda25d5e3688f4";
const MANIFEST_SHA: &str = "c632ae8d95748f563d8c47db587afa9139b165298004c3fa6820332c4d89b6b4";
const FINGERPRINT: &str = "sha256:08b441e89d7c9456aba5026ce206db8e08a14f96cb31cbad94a4a5c5e6e5622b";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const ORIGINAL_ARGV_SHA: &str = "4ef45e34b3a21f03eeda2115d371de1558e8e0e70574f64897f8d5b9be7ff893";
const ROOTS_SHA: &str = "cc7d780afe3d0180de6785cdad4f1e38e70feb82df1c95d21ab342c5974782e2";

struct Index(&'static str, u64, u64, i64, i64, &'static str);
const INDEXES: &[Index] = &[
    Index(
        "165/epoch-165-bafyreibtqc7jzj5pyctcpa5a6cwqm5r3nzbx2nlhesvwau3merpsonx76i-mainnet-slot-to-cid.index",
        95882408,
        15490506,
        1795147200507752811,
        1795147200518752861,
        "ce8778e9da2f309ce9872a1db794b48ab5a31ff6fdf90ee42c657ea8ec29889a",
    ),
    Index(
        "166/epoch-166-bafyreibiiohrh4nfurrukccpyjdwu3c5a5ym4y5nqhkntxez734kdtlafe-mainnet-slot-to-cid.index",
        95882413,
        15281271,
        1795147205066773533,
        1795147205073773565,
        "230bffbd50eac3f7a45d5b60f6f3a260a3cc1e0eb0f9f9a14e7ffa564256658f",
    ),
    Index(
        "166/epoch-166-bafyreibiiohrh4nfurrukccpyjdwu3c5a5ym4y5nqhkntxez734kdtlafe-mainnet-cid-to-offset-and-size.index",
        95882417,
        4196268262,
        1795147238350924786,
        1795147239634930619,
        "faf457fe25a5fcef1451942a6118f91b39d0d352488257b01de8f80b8783b49b",
    ),
];

pub fn node() -> PathBuf {
    Path::new(PACKAGE).join("jetstreamer-node")
}
pub fn worker_image() -> PathBuf {
    Path::new(PACKAGE).join("jetstreamer-historical-worker-v1-5-6")
}
pub fn node_arg() -> String {
    node().display().to_string()
}
fn original() -> PathBuf {
    Path::new(LANE).join(PREVIOUS)
}
fn source_index(i: &Index) -> PathBuf {
    original().join("output/compact-indexes").join(i.0)
}
fn target_index(i: &Index) -> PathBuf {
    run().join("output/compact-indexes").join(i.0)
}

fn cache(i: &Index, full: bool) -> Result<Value> {
    let path = source_index(i);
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let meta = f.metadata()?;
    let key = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime() * 1_000_000_000 + m.mtime_nsec(),
            m.ctime() * 1_000_000_000 + m.ctime_nsec(),
        )
    };
    ensure!(
        path.canonicalize()? == path
            && meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == 1001
            && meta.gid() == 1003
            && key(&meta) == (64512, i.1, i.2, i.3, i.4),
        "different retained compact index {}",
        path.display()
    );
    if full {
        let mut hash = Sha256::new();
        std::io::copy(&mut f, &mut hash)?;
        ensure!(
            format!("{:x}", hash.finalize()) == i.5,
            "compact index digest differs: {}",
            path.display()
        );
    }
    ensure!(
        key(&fs::symlink_metadata(&path)?) == key(&meta) && key(&f.metadata()?) == key(&meta),
        "index changed during validation"
    );
    Ok(json!({"path":path,"identity":key(&meta),"sha256":i.5,"target":target_index(i)}))
}

pub fn profile() -> Result<Value> {
    let (argv, ar) = doc(
        &rt(OLD).join("launch-state/epoch166/ORIGINAL_PRODUCER_ARGV.json"),
        Some(ORIGINAL_ARGV_SHA),
    )?;
    let mut argv: Vec<String> = serde_json::from_value(argv)?;
    let mut changes = 0;
    let before = original().display().to_string();
    let after = run().display().to_string();
    let mut bindings = vec![format!("{PACKAGE}:{PACKAGE}:rbind")];
    bindings.push(format!(
        "{INPUTS}/genesis.tar.bz2:{after}/output/genesis.tar.bz2"
    ));
    for i in INDEXES {
        bindings.push(format!(
            "{}:{}",
            source_index(i).display(),
            target_index(i).display()
        ));
    }
    for a in &mut argv {
        if a == &format!("--unit={OLD_UNIT}") {
            *a = format!("--unit={UNIT}");
            changes += 1;
        } else if a == &format!("--property=ReadWritePaths={LANE}") {
            *a = format!("--property=ReadWritePaths={after}");
            changes += 1;
        } else if a == &format!("--property=BindReadOnlyPaths={PACKAGE}:{PACKAGE}:rbind") {
            *a = format!("--property=BindReadOnlyPaths={}", bindings.join(" "));
            changes += 1;
        } else if a.contains(&before) {
            *a = a.replace(&before, &after);
            changes += 1;
        }
    }
    ensure!(
        changes == 7
            && argv[argv.len() - 8..]
                == [
                    node_arg(),
                    "166".into(),
                    run().join("output").display().to_string(),
                    "--verify".into(),
                    "--root-checkpoint-cohort".into(),
                    format!("--cohort-manifest={PACKAGE}/preflight-166-v4.json"),
                    format!("--cohort-manifest-fingerprint={FINGERPRINT}"),
                    format!("--snapshot-archive={INPUTS}/{BOOT}")
                ],
        "different original producer profile"
    );
    Ok(
        json!({"producer_argv":argv,"source_argv":ar,"fresh_attempt":run(),"indexes":INDEXES.iter().map(|i|cache(i,false)).collect::<Result<Vec<_>>>()?}),
    )
}

pub fn files() -> Result<Value> {
    let (roots, rr) = doc(&base().join("ROOTS_BEFORE_WITNESS.json"), Some(ROOTS_SHA))?;
    let m = fs::symlink_metadata(run())?;
    ensure!(
        run().canonicalize()? == run()
            && m.dev() == 64512
            && m.ino() == 93782017
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o7777 == 0o700
            && roots["root"] == json!(run())
            && roots["replay_launch_authorized"] == false,
        "different permanent recovery root"
    );
    let p = rt(OLD).join("preparation/epoch166/local3retry9/guard-state/receipts");
    let (stop, sr) = doc(
        &p.join("stop-completion.json"),
        Some("21b336b726372a48993ac5d302671aad001f8d41791c29c75be4fd0e465ced04"),
    )?;
    let (intent, ir) = doc(
        &p.join("stop-intent.json"),
        Some("21bee05b4efba487e0005f608c53ccff356131a3b0d32d93eea9ca87221ae81a"),
    )?;
    ensure!(
        intent["producer_invocation_id"] == OLD_IID
            && stop["producer_invocation_id"] == OLD_IID
            && stop["terminal"]["sub"] == "dead"
            && stop["intent"] == ir["path"]
            && intent["reason"] == "DATA-fulfillment-observation-failed"
            && stop["scratch_deleted"] == false,
        "stopped generation differs"
    );
    let old = native(OLD_UNIT)?;
    ensure!(
        old["ActiveState"] == "inactive"
            && old["MainPID"] == "0"
            && old["Job"] == ""
            && members(OLD_UNIT)?.is_empty(),
        "old epoch 166 owner present"
    );
    let (_, manifest) = doc(
        &Path::new(PACKAGE).join("preflight-166-v4.json"),
        Some(MANIFEST_SHA),
    )?;
    let bootstrap = Path::new(INPUTS).join(BOOT);
    let bm = fs::symlink_metadata(&bootstrap)?;
    ensure!(
        bm.uid() == 0
            && bm.mode() & 0o222 == 0
            && bm.len() == 1968014870
            && bootstrap.canonicalize()? == bootstrap,
        "foreign snapshot"
    );
    Ok(
        json!({"predecessor_stop":sr,"predecessor_intent":ir,"stable_roots":rr,"root":{"path":run(),"device":m.dev(),"inode":m.ino()},
        "snapshot":{"path":bootstrap,"device":bm.dev(),"inode":bm.ino(),"length":bm.len(),"ctime":[bm.ctime(),bm.ctime_nsec()],"sha256":BOOT_SHA,"generation":1634787359098769u64},
        "manifest":manifest,"profile":profile()?}),
    )
}

pub fn prepare() -> Result<Value> {
    let baseline = files()?;
    let (manifest, _) = doc(
        &Path::new(PACKAGE).join("preflight-166-v4.json"),
        Some(MANIFEST_SHA),
    )?;
    let e = &manifest["manifest"]["epochs"][0];
    ensure!(
        manifest["manifest_fingerprint"] == FINGERPRINT
            && e["epoch"] == 166
            && e["bootstrap"]["slot"] == 71711708
            && e["post_bootstrap_root_checkpoints"][0]["slot"] == 72143703
            && e["post_bootstrap_root_checkpoints"][0]["accounts_hash"]
                == "CJEQdfn6zGqx4da6wL7CqgDhNAEij9tCPz7CrY9ZWH1a",
        "incorrect full epoch root lineage"
    );
    let receipt = base().join("PREPARED.json");
    if receipt.try_exists()? {
        let (v, r) = doc(&receipt, None)?;
        ensure!(v["baseline"] == baseline, "prepared generation changed");
        return Ok(r);
    }
    ensure!(
        native(UNIT)?["LoadState"] == "not-found" && members(UNIT)?.is_empty(),
        "successor already active"
    );
    for (path, digest) in [
        (node(), NODE_SHA),
        (worker_image(), WORKER_SHA),
        (Path::new(INPUTS).join(BOOT), BOOT_SHA),
        (Path::new(INPUTS).join("genesis.tar.bz2"), GENESIS_SHA),
    ] {
        ensure!(
            file_digest(&path)? == digest,
            "sealed input differs: {}",
            path.display()
        );
    }
    let mut verified = Vec::new();
    for i in INDEXES {
        verified.push(cache(i, true)?);
    }
    let log = run().join("producer.log");
    let log_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log)?;
    let lm = log_fd.metadata()?;
    ensure!(
        lm.dev() == 64512
            && lm.ino() == 93782020
            && lm.is_file()
            && lm.nlink() == 1
            && lm.len() == 0
            && lm.mode() & 0o7777 == 0o600
            && matches!((lm.uid(), lm.gid()), (1001, 1003) | (0, 0))
            && same(
                &log,
                &Path::new("/proc/self/fd").join(log_fd.as_raw_fd().to_string())
            )?,
        "untrusted precreated observer log"
    );
    std::os::unix::fs::fchown(&log_fd, Some(0), Some(0))?;
    log_fd.sync_all()?;
    // Mount destinations exist before PID1 requests the readonly genesis and compact-index projections.
    for dir in [
        "output/compact-indexes",
        "output/compact-indexes/165",
        "output/compact-indexes/166",
    ] {
        let target = run().join(dir);
        if !target.try_exists()? {
            fs::create_dir(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
            File::open(target.parent().unwrap())?.sync_all()?;
        }
        let m = fs::symlink_metadata(&target)?;
        ensure!(
            target.canonicalize()? == target && m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "altered cache directory"
        );
    }
    for target in INDEXES
        .iter()
        .map(target_index)
        .chain(std::iter::once(run().join("output/genesis.tar.bz2")))
    {
        if !target.try_exists()? {
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(&target)?;
            f.set_permissions(fs::Permissions::from_mode(0o444))?;
            f.sync_all()?;
            File::open(target.parent().unwrap())?.sync_all()?;
        }
        let m = fs::symlink_metadata(&target)?;
        ensure!(
            target.canonicalize()? == target
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.len() == 0
                && m.mode() & 0o7777 == 0o444,
            "occupied bind target"
        );
    }
    ensure!(baseline == files()?, "source changed during preparation");
    for d in ["guard-receipts"] {
        let dir = base().join(d);
        if !dir.try_exists()? {
            fs::DirBuilder::new().create(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            File::open(base())?.sync_all()?;
        }
        let dm = dir.symlink_metadata()?;
        ensure!(
            dm.is_dir() && dm.uid() == 0 && dm.mode() & 0o077 == 0 && dir.canonicalize()? == dir,
            "unsafe guard receipts"
        );
    }
    record(
        "PREPARED.json",
        &json!({"schema":"horizon-166-replay-recovery-preparation-v1","epoch":166,"baseline":baseline,
        "indexes":verified,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"original_run_retained":true,"replay_launch_authorized":false}),
    )
}

pub fn ready() -> Result<Value> {
    let (p, r) = doc(&base().join("PREPARED.json"), None)?;
    let m = run().join("producer.log").symlink_metadata()?;
    ensure!(
        p["baseline"] == files()?
            && m.dev() == 64512
            && m.ino() == 93782020
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o600
            && m.len() == 0
            && fs::read_dir(run().join("private"))?.next().is_none(),
        "changed staged namespace or log"
    );
    for target in INDEXES
        .iter()
        .map(target_index)
        .chain(std::iter::once(run().join("output/genesis.tar.bz2")))
    {
        let m = target.symlink_metadata()?;
        ensure!(
            target.canonicalize()? == target
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.len() == 0
                && m.mode() & 0o7777 == 0o444,
            "changed staged mount target"
        );
    }
    Ok(r)
}

pub fn index_selected() -> Result<()> {
    let actor = native(UNIT)?;
    let pid = st(&actor, "MainPID")?.parse::<u64>()?;
    ensure!(pid > 1, "missing actual producer");
    let p = Path::new("/proc").join(pid.to_string());
    let mounts = fs::read_to_string(p.join("mountinfo"))?;
    for (src, target) in INDEXES
        .iter()
        .map(|i| (source_index(i), target_index(i)))
        .chain(std::iter::once((
            Path::new(INPUTS).join("genesis.tar.bz2"),
            run().join("output/genesis.tar.bz2"),
        )))
    {
        let target_in_namespace = p.join("root").join(target.strip_prefix("/")?);
        ensure!(
            same(&src, &target_in_namespace)?
                && mounts.lines().any(|l| {
                    let a: Vec<_> = l.split_whitespace().take(6).collect();
                    a.len() == 6
                        && a[4] == target.to_str().unwrap_or_default()
                        && a[5].split(',').any(|x| x == "ro")
                }),
            "missing original read-only mount in source process: {}",
            target.display()
        );
    }
    ensure!(
        native(UNIT)?["InvocationID"] == actor["InvocationID"],
        "actor changed during projection check"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stopped_epoch166_bound_inputs_and_closed_continuation() {
        let v = files().unwrap();
        assert_eq!(v["root"]["inode"], 93782017);
        assert_eq!(v["snapshot"]["length"], 1968014870);
        assert_eq!(v["profile"]["indexes"].as_array().unwrap().len(), 3);
        assert_eq!(v["profile"]["producer_argv"][0], "/usr/bin/systemd-run");
        assert_eq!(
            node_arg(),
            "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-node"
        );
    }
}

pub fn prepare_log() -> Result<Value> {
    let p = run().join("producer.log");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.dev() == 64512
            && m.ino() == 93782020
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.len() == 0
            && m.mode() & 0o7777 == 0o600
            && same(
                &p,
                &Path::new("/proc/self/fd").join(f.as_raw_fd().to_string())
            )?
            && native(UNIT)?["LoadState"] == "not-found"
            && members(UNIT)?.is_empty(),
        "observer log or cold owner changed"
    );
    let receipt = base().join("OBSERVER_LOG_PREPARED.json");
    let proof = json!({"schema":"horizon-166-root-owned-observer-log-v1","prepared":doc(&base().join("PREPARED.json"),None)?.1,
        "path":p,"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode()&0o7777,"nlink":m.nlink(),"size":m.len()});
    if receipt.try_exists()? {
        let (v, r) = doc(&receipt, None)?;
        ensure!(v == proof, "foreign 166 log receipt");
        return Ok(r);
    }
    record("OBSERVER_LOG_PREPARED.json", &proof)
}
