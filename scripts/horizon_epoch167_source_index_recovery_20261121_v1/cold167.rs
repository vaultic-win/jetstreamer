//! Cold successor on the original 512 GiB booking after the November 22 HOME stop.
use super::*;
use std::collections::BTreeSet;

pub const EPOCH: u64 = 167;
pub const CAP: u64 = 512 << 30;
pub const BASE: &str = "epoch167-source-index-rebook-20261122-v3";
pub const LANE: &str = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1";
pub const ATTEMPT: &str = "replacement-source-index-v1-20261121/cold-source-index-v3-20261122";
pub const OLD: &str = "epoch167-retry8-recovery-20261120-v1";
pub const UNIT: &str = "horizon-qualify-167-source-index-v3-20261122.service";
pub const TIMER: &str = "horizon-guard-167-source-index-v3-20261122.timer";
pub const PREVIOUS_GUARD_ARGV: &str =
    "4fbff52bb7cf7f7443cd7466289494b23c1b32c8c433e6ecf196356f6f8fc76f";
const PREVIOUS: &str = "epoch167-source-index-recovery-20261121-v1";
const ORIGINAL_UNIT: &str = "horizon-qualify-167-source-index-v1-20261121.service";
const PKG: &str = "epoch167-local-index-successor-20261121-v1";
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const PREFIX_FILE: &str = "private/destination-fd90fb412d332b37025714f31125e4cf59dd48685725abdaf0a06d2e1bd1689d/work/root-cohort-167-167/run-3872800-1795261349807636799";
const SNAP: &str = "snapshot-72143703-CJEQdfn6zGqx4da6wL7CqgDhNAEij9tCPz7CrY9ZWH1a.tar.zst";
const SNAP_SHA: &str = "948ca3ec94f7c9c7bc970fa21fef5e388ba2c3357e7d39589de402257ab5b81f";
fn prior() -> PathBuf {
    Path::new(LANE).join("replacement-source-index-v1-20261121")
}
fn bootstrap() -> PathBuf {
    prior()
        .join(PREFIX_FILE)
        .join("scratch/.historical-runtime/jetstreamer-historical-parent-Wve3ED/bound-bootstrap")
        .join(SNAP)
}
pub fn node() -> PathBuf {
    rt(PKG).join("deployment/jetstreamer-node")
}
pub fn worker_image() -> PathBuf {
    rt(PKG).join("deployment/jetstreamer-historical-worker-v1-5-6")
}
pub fn node_arg() -> String {
    "/usr/local/lib/jetstreamer/horizon-independent167-singleton-package-20261109-v1/jetstreamer-node".into()
}
fn sources() -> Result<Value> {
    Ok(doc(
        &rt(PKG).join("successor-profile.json"),
        Some("b161542cd001c85245e115204698650ad0adf9de598f54b957f95f761b54d938"),
    )?
    .0)
}
pub fn profile() -> Result<Value> {
    let mut p = sources()?;
    let old = prior();
    let new = run();
    let mut argv = vec![];
    for v in p["producer_argv"].as_array().context("producer argv")? {
        let a = v.as_str().context("non-string argv")?;
        if a == node_arg() {
            argv.push(format!(
                "--property=BindReadOnlyPaths={}:{}/output/compact-indexes:rbind",
                old.join("output/compact-indexes").display(),
                new.display()
            ));
            argv.push(format!("--property=BindReadOnlyPaths={}:/usr/local/lib/jetstreamer/horizon-standard-local-input167-20261110-v1/{SNAP}",bootstrap().display()));
        }
        argv.push(
            a.replace(old.to_str().unwrap(), new.to_str().unwrap())
                .replace(ORIGINAL_UNIT, UNIT),
        );
    }
    p["producer_argv"] = json!(argv);
    p["producer_unit"] = json!(UNIT);
    p["guard_timer"] = json!(TIMER);
    p["fresh_attempt"] = json!(new);
    p["stage_genesis_to"] = json!(run().join("output/genesis.tar.bz2"));
    Ok(p)
}
fn identity(p: &Path, uid: u32) -> Result<Value> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.dev() == 64512,
        "unsafe retained file {}",
        p.display()
    );
    Ok(
        json!({"path":p,"device":m.dev(),"inode":m.ino(),"length":m.len(),"mtime":[m.mtime(),m.mtime_nsec()],"ctime":[m.ctime(),m.ctime_nsec()]}),
    )
}
fn dirs(p: &Path) -> Result<BTreeSet<String>> {
    fs::read_dir(p)?
        .map(|e| {
            Ok(e?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 member"))?)
        })
        .collect()
}
fn indexes() -> Result<Vec<Value>> {
    let root = prior().join("output/compact-indexes");
    let mut rows = vec![];
    ensure!(
        dirs(&root)? == BTreeSet::from(["166".into(), "167".into()]),
        "cache epochs changed"
    );
    for (ep, car, files) in [
        (
            "166",
            "bafyreibiiohrh4nfurrukccpyjdwu3c5a5ym4y5nqhkntxez734kdtlafe",
            vec![(
                "slot-to-cid",
                15281271u64,
                "230bffbd50eac3f7a45d5b60f6f3a260a3cc1e0eb0f9f9a14e7ffa564256658f",
            )],
        ),
        (
            "167",
            "bafyreienhstqouv46ysqm2r5dqeixnhmil3qem77x76q5hicq4egi3uzhi",
            vec![
                (
                    "slot-to-cid",
                    14777203,
                    "612a7bb5b53a8203900535cd91b7b44643982b1c6f9ff693e7543daf0fd25212",
                ),
                (
                    "cid-to-offset-and-size",
                    4170405634,
                    "213661ab71d1a0b40b5ae208356eaede8ae392a1a675a7775659f5268166f5be",
                ),
            ],
        ),
    ] {
        let mut names = BTreeSet::new();
        for (tag, len, digest) in files {
            let name = format!("epoch-{ep}-{car}-mainnet-{tag}.index");
            let mut row = identity(&root.join(ep).join(&name), 1001)?;
            row["sha256"] = json!(digest);
            ensure!(row["length"] == len, "cache size changed");
            rows.push(row);
            names.insert(name);
        }
        ensure!(dirs(&root.join(ep))? == names, "cache component changed");
    }
    Ok(rows)
}
pub fn files() -> Result<Value> {
    let previous_runtime = rt("epoch167-source-index-rebook-20261122-v1");
    let (failed, failure) = doc(
        &previous_runtime.join("START_FAILURE.json"),
        Some("bf7c9db02f21c189f4bbf479428522ef52a3c5d7f553dc1118dd0edac71533a9"),
    )?;
    let old_node = "horizon-qualify-167-source-index-v2-20261122.service";
    let old_guard = "horizon-guard-167-source-index-v2-20261122.timer";
    ensure!(
        failed["producer_invocation_id"] == "cdcb80c45de340278a07418190d7c3c7"
            && failed["partial_retained"] == true
            && failed["cgroup"] == json!([])
            && failed["intent"] == doc(&previous_runtime.join("START_INTENT.json"), None)?.1
            && native(old_node)?["MainPID"] == "0"
            && members(old_node)?.is_empty()
            && native(old_guard)?["ActiveState"] == "inactive",
        "failed cold predecessor still owns replay or guard"
    );

    let (rr, ret) = doc(
        &rt("epoch167-ancestor-accounts-20261122-v2/RETURN.json"),
        Some("35c7b753caa4db4a4774fae5c716a12003422c84a106e35288b0278981df4ede"),
    )?;
    ensure!(
        rr["lane_cap_bytes"] == CAP && rr["verified_release_bytes"] == 95559610368u64,
        "wrong ancestor handback"
    );
    let (trip, tr) = doc(
        &rt(PREVIOUS).join("guard-receipts/stop-intent.json"),
        Some("ddccaeb84f2fd25f4736a780b7448d4a2add4c22b04544ea4f6bc566346be7d4"),
    )?;
    let (stop, sr) = doc(
        &rt(PREVIOUS).join("guard-receipts/stop-completion.json"),
        Some("50c7f072d70a1e3112c67034e4fc324a8597093871483c7c3af411bb52ea1c64"),
    )?;
    ensure!(
        trip["reason"] == "filesystem-floor"
            && stop["intent"] == tr["path"]
            && stop["producer_invocation_id"] == "0876e9944c784b41afeff1b666539ead"
            && stop["scratch_deleted"] == false,
        "wrong predecessor"
    );
    let m = native(ORIGINAL_UNIT)?;
    ensure!(
        m["MainPID"] == "0" && m["ActiveState"] == "inactive" && members(ORIGINAL_UNIT)?.is_empty(),
        "old worker remains"
    );
    let base = prior().symlink_metadata()?;
    ensure!(
        prior().canonicalize()? == prior() && (base.dev(), base.ino()) == (64512, 107675649),
        "original tree changed"
    );
    let archive = identity(
        &prior().join(PREFIX_FILE).join("archives/epoch-167.jet"),
        1001,
    )?;
    ensure!(
        archive["length"] == 29588857195u64,
        "incomplete prefix identity changed"
    );
    let snapshot = identity(&bootstrap(), 1001)?;
    ensure!(snapshot["length"] == 2022614652u64, "wrong bootstrap");
    let dir = run().symlink_metadata()?;
    ensure!(
        run().canonicalize()? == run()
            && dir.is_dir()
            && dir.dev() == 64512
            && dir.uid() == 1001
            && dir.gid() == 1003
            && dir.mode() & 0o7777 == 0o700,
        "unsafe successor root"
    );
    Ok(
        json!({"previous_cold_failure":failure,"predecessor_stop":sr,"predecessor_sample":tr,"retirement":ret,"root":{"path":run(),"device":dir.dev(),"inode":dir.ino()},"snapshot":snapshot,"retained_prefix":archive,"indexes":indexes()?}),
    )
}
fn owned(p: &Path) -> Result<()> {
    if !p.try_exists()? {
        fs::create_dir(p)?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
        std::os::unix::fs::chown(p, Some(1001), Some(1003))?;
        File::open(p.parent().unwrap())?.sync_all()?;
    }
    let m = p.symlink_metadata()?;
    ensure!(
        p.canonicalize()? == p
            && m.is_dir()
            && m.uid() == 1001
            && m.gid() == 1003
            && m.dev() == 64512
            && m.mode() & 0o7777 == 0o700,
        "invalid successor directory"
    );
    Ok(())
}
pub fn prepare() -> Result<Value> {
    let original = native(ORIGINAL_UNIT)?;
    ensure!(
        original["MainPID"] == "0"
            && original["ActiveState"] == "inactive"
            && native(UNIT)?["LoadState"] == "not-found",
        "existing producer owner"
    );
    if base().join("PREPARED.json").try_exists()? {
        return ready();
    }
    owned(&run())?;
    let baseline = files()?;
    let p = profile()?;
    for member in sources()?["bindings"]
        .as_array()
        .context("source bindings")?
    {
        ensure!(
            file_digest(Path::new(st(member, "path")?))? == st(member, "sha256")?,
            "changed sealed input"
        );
    }
    for row in indexes()? {
        let mut f = File::open(st(&row, "path")?)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut f, &mut hasher)?;
        ensure!(
            format!("{:x}", hasher.finalize()) == row["sha256"],
            "retained index checksum mismatch"
        );
    }
    let mut snap = File::open(bootstrap())?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut snap, &mut hasher)?;
    ensure!(
        format!("{:x}", hasher.finalize()) == SNAP_SHA,
        "home bootstrap digest mismatch"
    );
    for dir in ["private", "config", "output", "output/compact-indexes"] {
        owned(&run().join(dir))?;
    }
    let output = run().join("output/genesis.tar.bz2");
    let genesis = Path::new(
        "/usr/local/lib/jetstreamer/horizon-standard-local-input167-20261110-v1/genesis.tar.bz2",
    );
    ensure!(file_digest(genesis)? == GENESIS, "genesis source changed");
    if !output.try_exists()? {
        let mut out = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o444)
            .open(&output)?;
        out.write_all(&fs::read(genesis)?)?;
        out.sync_all()?;
        File::open(output.parent().unwrap())?.sync_all()?;
    }
    let log = run().join("producer.log");
    if !log.try_exists()? {
        let f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&log)?;
        f.sync_all()?;
        File::open(run())?.sync_all()?;
    }
    let id = identity(&log, 0)?;
    ensure!(
        id["length"] == 0 && baseline == files()?,
        "launch surface changed"
    );
    record(
        "PREPARED.json",
        &json!({"epoch":EPOCH,"baseline":baseline,"profile":p,"append_log":id,"snapshot_sha256":SNAP_SHA,"generation":1634787403577062u64}),
    )
}
pub fn prepare_log() -> Result<Value> {
    ready()
}
pub fn ready() -> Result<Value> {
    let (v, b) = doc(&base().join("PREPARED.json"), None)?;
    ensure!(
        v["baseline"] == files()?
            && v["profile"] == profile()?
            && v["append_log"] == identity(&run().join("producer.log"), 0)?
            && dirs(&run().join("private"))?.is_empty()
            && dirs(&run().join("output"))?
                == BTreeSet::from(["genesis.tar.bz2".into(), "compact-indexes".into()])
            && dirs(&run().join("output/compact-indexes"))?.is_empty()
            && file_digest(&run().join("output/genesis.tar.bz2"))? == GENESIS,
        "source preparation changed"
    );
    Ok(b)
}
pub fn index_selected() -> Result<()> {
    let log = File::open(run().join("producer.log"))?;
    let mut buf = Vec::new();
    log.take(512 << 10).read_to_end(&mut buf)?;
    ensure!(String::from_utf8_lossy(&buf).contains("Using digest-pinned local slot-ranges index for epoch 167: /home/sol/.jetstreamer-private/public-method-20261120/167-source-index/qualified-v1/epoch-167-slot-ranges.raw"),"original pinned index not selected");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn successor_restricts_writes_and_reuses_the_original_node_and_home_inputs() {
        let p = profile().unwrap();
        let args = p["producer_argv"].as_array().unwrap();
        assert!(args.contains(&json!(format!(
            "--property=ReadWritePaths={}",
            run().display()
        ))));
        assert!(args.contains(&json!("--require-local-slot-ranges=167")));
        assert!(args.contains(&json!("--property=CPUQuota=900%")));
        assert!(args.contains(&json!("--property=MemoryMax=73014444032")));
        assert!(args.contains(&json!(format!(
            "--property=BindReadOnlyPaths={}:{}/output/compact-indexes:rbind",
            prior().join("output/compact-indexes").display(),
            run().display()
        ))));
        assert!(args.contains(&json!(format!("--property=BindReadOnlyPaths={}:/usr/local/lib/jetstreamer/horizon-standard-local-input167-20261110-v1/{SNAP}",bootstrap().display()))));
        assert!(args.contains(&json!(format!("--unit={UNIT}"))));
        assert!(!args.contains(&json!(format!("--unit={ORIGINAL_UNIT}"))));
        assert_eq!(p["guard_timer"], TIMER);
        assert_eq!(p["guard_worker_root"], LANE);
    }
}
