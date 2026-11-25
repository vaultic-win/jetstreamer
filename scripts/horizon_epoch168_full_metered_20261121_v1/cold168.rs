//! Generate the successor from the originally admitted metered epoch 168 payload.
use super::*;

pub const EPOCH: u64 = 168;
pub const LANE: &str = "/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1";
pub const OLD: &str = "epoch168-full-metered-20261121-v1";
pub const CAP: u64 = if cfg!(epoch168_cold_retry5) {
    512 << 30
} else {
    288 << 30
};
pub const PREVIOUS_GUARD_ARGV: &str =
    "1b81a271d53f52ea34ead452d578f68326ba9f51b61ddbaa154f7277cfa441bf";
pub const OLD_UNIT: &str = "horizon-qualify-168-full-metered-20261121-v1.service";
const ORIGINAL_ARGV: &str = "39d2e97f8f6962984f1ec9672a4701fe0772e3a63a72465b8d945d59eab7b4fa";
const PAYLOAD: &str = "6c56c0cad87c9d22ca72ad8e2cf97cb0cc0c5e1b4d1d01e4f051dfc01875b240";
const INPUT_SEAL: &str = "e00db5e753a2cc37af403933f54bcb3216594d1fac3d91cc8984623999295a93";
#[cfg(not(epoch168_cold_retry3))]
mod route {
    pub const ATTEMPT: &str = "full-metered-20261121-v1/cold-retry2-20261122";
    pub const BASE: &str = "epoch168-retry2-rebook-20261122-v1";
    pub const UNIT: &str = "horizon-qualify-168-full-metered-cold-v2-20261122.service";
    pub const TIMER: &str = "horizon-guard-168-full-metered-cold-v2-20261122.timer";
    pub const GUARD_SHA: &str = "22cc2f4f49ecd236d1b7c177bc4d2df0a96ebec5c6ef591905ff6ca6ab9e7770";
    pub const GSEAL: &str = "160ffc208db19b9fa23112c028cd9cb80853f10c8abc8f484cb0935adc51a1d2";
    pub const CONTRACT: &str = "f10342c06a7b501b503f6046c56a345880c785c2a5d17f03ab43c4b30526d088";
    pub const CSEAL: &str = "e68fec195ca0f5708ea98fc3013e7080c7a91b8e454f1c79bca51d0c29b14609";
    pub const WITNESS: &str = "7373df4366d2c4ea1fd14cfa063f56fb66ff1fb7997fc6e9245c345fbf3fb217";
    pub const GUARD_BASE: &str = "epoch168-cold-guard-20261122-v2";
    pub const FIT: &str =
        "incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry2-v2/post-stop-fit";
    pub const ROOT: &str = "ec909d6701ce7dcbee72da319bf0179ba375e1cf6e284aa29686e1dd0a3cbecc";
    pub const ALIAS: &str = "/run/horizon-full168-cold-v2";
    pub const STATUS_QUALIFIED: &str = "COLD168_RETRY2_V1_STATUS_QUALIFIED.json";
    pub const STATUS_ACTIVE: &str = "COLD168_RETRY2_V1_STATUS_ACTIVE.json";
    pub const STATUS_SCHEMA: &str = "horizon-168-retry2-v1-status-qualified-v1";
    pub const GUARD_QUALIFIED: &str =
        "bab2140873334dfbab487be91cf044a31a000cbdec525075fe1ea4a086198e2b";
    pub const DESCRIPTION: &str = "--description=guarded-full168-cold-retry2";
    pub const RUN_INO: u64 = 103481350;
    pub const OUTPUT_INO: u64 = 103481354;
    pub const PRIVATE_INO: u64 = 103481352;
    pub const LOG_INO: u64 = 103481356;
    pub const PREPARED: Option<&str> =
        Some("dd1b2296e8cd987eccf90053b999d647cd28c09a43279493fd625c719ed0388a");
}
#[cfg(all(epoch168_cold_retry3, not(epoch168_cold_retry4)))]
mod route {
    pub const ATTEMPT: &str = "full-metered-20261121-v1/cold-retry3-20261123";
    pub const BASE: &str = "epoch168-retry3-rebook-20261123-v1";
    pub const UNIT: &str = "horizon-qualify-168-full-metered-cold-v3-20261123.service";
    pub const TIMER: &str = "horizon-guard-168-full-metered-cold-v3-20261123.timer";
    pub const GUARD_SHA: &str = "426f78a04505ca11cdfd180db9195cbc8ec9e2300842013e4ee5829b34f4089f";
    pub const GSEAL: &str = "830df6654ed3ddb53041f7fbfe699cd7d1a1c61de0f5d73c72d9eed8afac0359";
    pub const CONTRACT: &str = "a5e03bcb30cb96182f1c091b55d1787ee8d3e5c7ce58d9f90c88773986fb231e";
    pub const CSEAL: &str = "77136d519e99d81c90a8ba9e4bb045a4286d15f910a3368d5399fb406bb47683";
    pub const WITNESS: &str = "f7e7fa120e7bb0b5acf736bd2da2c3e8dca2b400161137366ea583153dcc293c";
    pub const GUARD_BASE: &str = "epoch168-cold-guard-20261123-v3";
    pub const FIT: &str =
        "incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry3-v1/post-stop-fit";
    pub const ROOT: &str = "a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4";
    pub const ALIAS: &str = "/run/horizon-full168-cold-v3";
    pub const STATUS_QUALIFIED: &str = "COLD168_RETRY3_V1_STATUS_QUALIFIED.json";
    pub const STATUS_ACTIVE: &str = "COLD168_RETRY3_V1_STATUS_ACTIVE.json";
    pub const STATUS_SCHEMA: &str = "horizon-168-retry3-v1-status-qualified-v1";
    pub const GUARD_QUALIFIED: &str =
        "6fef2fa86ae3011b87d90a6d3c8168cac73ac07b9dd43b705ce664c421a04d62";
    pub const DESCRIPTION: &str = "--description=guarded-full168-cold-retry3";
    pub const RUN_INO: u64 = 103481378;
    pub const OUTPUT_INO: u64 = 103481379;
    pub const PRIVATE_INO: u64 = 103481380;
    pub const LOG_INO: u64 = 103481382;
    pub const PREPARED: Option<&str> = None;
}
#[cfg(all(epoch168_cold_retry4, not(epoch168_cold_retry5)))]
mod route {
    pub const ATTEMPT: &str = "full-metered-20261121-v1/cold-retry4-20261123";
    pub const BASE: &str = "epoch168-retry4-rebook-20261123-v1";
    pub const UNIT: &str = "horizon-qualify-168-full-metered-cold-v4-20261123.service";
    pub const TIMER: &str = "horizon-guard-168-full-metered-cold-v4-20261123.timer";
    pub const GUARD_SHA: &str = "ab12bc9f6258a3382057518e5144b23fb673251b28cd09c0d32ad45baa9da68b";
    pub const GSEAL: &str = "d11870d5dd698182f3fdc1030dcab186ba41e7615ca9c4f6cd8205ffc2c03810";
    pub const CONTRACT: &str = "ddc173a15ae3a886d420083fd6d365a66368bc858f7cef5609d7cfbf672fc848";
    pub const CSEAL: &str = "fca00c6fc6fa4d09e6f57cb899c6ef4fd49caf69b39815f15aa4d4a5a26808fa";
    pub const WITNESS: &str = "c73a105f8566e5a9b93aa4f17e9724c6414b3b0429babd8a6904c7d6c3d366ab";
    pub const GUARD_BASE: &str = "epoch168-cold-guard-20261123-v4";
    pub const FIT: &str =
        "incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry4-v1/post-stop-fit";
    pub const ROOT: &str = "713e94750dd3d430c2f54c1ccb2af7ed708dec802af5cbf210ee4963a992d0f4";
    pub const ALIAS: &str = "/run/horizon-full168-cold-v4";
    pub const STATUS_QUALIFIED: &str = "COLD168_RETRY4_V1_STATUS_QUALIFIED.json";
    pub const STATUS_ACTIVE: &str = "COLD168_RETRY4_V1_STATUS_ACTIVE.json";
    pub const STATUS_SCHEMA: &str = "horizon-168-retry4-v1-status-qualified-v1";
    pub const GUARD_QUALIFIED: &str =
        "685ccacf23985e9f4453a80b5dd71bcf793b94eb18a4d32009c748e8f06fe16d";
    pub const DESCRIPTION: &str = "--description=guarded-full168-cold-retry4";
    pub const RUN_INO: u64 = 103481722;
    pub const OUTPUT_INO: u64 = 103481728;
    pub const PRIVATE_INO: u64 = 103481729;
    pub const LOG_INO: u64 = 103481750;
    pub const PREPARED: Option<&str> = None;
}
#[cfg(epoch168_cold_retry5)]
mod route {
    pub const ATTEMPT: &str = "full-metered-20261121-v1/cold-retry5-20261125";
    pub const BASE: &str = "epoch168-retry5-rebook-20261125-v1";
    pub const UNIT: &str = "horizon-qualify-168-full-metered-cold-v5-20261125.service";
    pub const TIMER: &str = "horizon-guard-168-full-metered-cold-v5-20261125.timer";
    pub const GUARD_SHA: &str = "c183043166b53a93305344775155e9108fc2b2e23c128cc38c1394e4c4650ae5";
    pub const GSEAL: &str = "3f20247a554445ac9a21e3c8938b20f57d705b1db23fdf4534278f289fcbaa5b";
    pub const CONTRACT: &str = "c4ff660c3595f2575574aa801a29d79f100b2ff65f4a3f1c0aa6431e500a0371";
    pub const CSEAL: &str = "bfcdef46e5c2ff3ea39b8293f8f82edd53643f6a6363e2069ec4eb58ef04f2c6";
    pub const WITNESS: &str = "fa3ba73fbc164507e40b76f6653c1394df223b2bea0aa940b815baae16d868fc";
    pub const GUARD_BASE: &str = "epoch168-cold-guard-20261125-v5";
    pub const FIT: &str =
        "incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry5-v2/post-stop-fit";
    pub const ROOT: &str = "4cd544fddda40cd81c94358b8c455feac24247b14f56e8fdb8ede2727c54af25";
    pub const ALIAS: &str = "/run/horizon-full168-cold-v5";
    pub const STATUS_QUALIFIED: &str = "FAILED166_CADENCE_V12_READY.json";
    pub const STATUS_ACTIVE: &str = "FAILED166_CADENCE_V12_ACTIVE.json";
    pub const STATUS_SCHEMA: &str = "horizon-epoch166-cadence-rejoin-ready-v1";
    pub const GUARD_QUALIFIED: &str =
        "e237ca579a8921adaae0081ef71a82b35377e4ff80acaf8539c03cd68e3aa696";
    pub const DESCRIPTION: &str = "--description=guarded-full168-cold-retry5";
    pub const RUN_INO: u64 = 109396827;
    pub const OUTPUT_INO: u64 = 109396829;
    pub const PRIVATE_INO: u64 = 109396828;
    pub const LOG_INO: u64 = 109396830;
    pub const PREPARED: Option<&str> = None;
}
pub use route::*;
const OLD_ALIAS: &str = "/run/horizon-full168-metered";
const NODE: &str = "jetstreamer-node";
const WORKER: &str = "jetstreamer-historical-worker-v1-5-6";
const MANIFEST: &str = "preflight-168-v4.json";
pub const WORKER_SHA: &str = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-independent168-singleton-package-20261109-v1";

pub fn node() -> PathBuf {
    Path::new(PACKAGE).join(NODE)
}
pub fn node_arg() -> String {
    format!("{ALIAS}/{NODE}")
}
pub fn worker_image() -> PathBuf {
    rt("epoch172-full-replay-20261120-v1/inputs-v1").join(WORKER)
}
fn original_payload() -> Result<Value> {
    let path = rt(OLD).join("inputs-v1/payload.json");
    let (payload, _) = doc(&path, Some(PAYLOAD))?;
    member(&path, INPUT_SEAL)?;
    Ok(payload)
}
fn output() -> PathBuf {
    run().join("output")
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    let mut data = serde_json::to_vec_pretty(v)?;
    data.push(b'\n');
    Ok(data)
}

/// Keep the original bank, checkpoints, hashes, worker settings and prior evidence.
fn translate_payload(mut p: Value) -> Result<Value> {
    let before = Path::new(LANE).join("full-metered-20261121-v1");
    let original = &p["regular_node_argv"];
    ensure!(
        p["epoch"] == EPOCH
            && p["producer_unit"] == OLD_UNIT
            && p["range"] == json!([72_576_000, 73_007_999])
            && original.as_array().is_some_and(|a| a.len() == 8)
            && original[0] == json!(before.join("runtime").join(NODE))
            && original[2] == json!(before.join("ledger"))
            && original[5] == format!("--cohort-manifest={}/runtime/{MANIFEST}", before.display())
            && p["members"][NODE][1] == NODE_SHA
            && p["members"][WORKER][1] == WORKER_SHA,
        "foreign original 168 plan"
    );
    #[cfg(epoch168_cold_retry5)]
    {
        p["whole_root_cap"] = json!(CAP);
    }
    p["producer_unit"] = json!(UNIT);
    p["guard_unit"] = json!(TIMER.trim_end_matches(".timer"));
    p["regular_node_argv"][0] = json!(node_arg());
    p["regular_node_argv"][2] = json!(output());
    p["regular_node_argv"][5] = json!(format!("--cohort-manifest={ALIAS}/{MANIFEST}"));
    p["environment"]["JETSTREAMER_PRIVATE_RUN_ROOT"] = json!(run().join("private"));
    p["environment"]["JETSTREAMER_HISTORICAL_WORKER_V1_5_6"] = json!(format!("{ALIAS}/{WORKER}"));
    let indexes = p["indexes"].as_array_mut().context("compact indexes")?;
    ensure!(indexes.len() == 3, "incomplete 168 compact-index roster");
    for index in indexes {
        let target =
            Path::new(st(index, "target")?).strip_prefix(before.join("ledger/compact-indexes"))?;
        index["target"] = json!(output().join("compact-indexes").join(target));
    }
    Ok(p)
}

fn projections(p: &Value) -> Result<Vec<(PathBuf, PathBuf)>> {
    let alias = Path::new(ALIAS);
    let mut binds = Vec::new();
    for name in [NODE, WORKER, MANIFEST] {
        let src = p["members"][name][0].as_str().context("member path")?;
        binds.push((PathBuf::from(src), alias.join(name)));
    }
    for (src, dst) in [
        (base().join("COLD_PAYLOAD.json"), alias.join("payload.json")),
        (base().join("tools/gate.py"), alias.join("gate.py")),
        (base().join("barrier"), alias.join("barrier")),
        (
            PathBuf::from(st(&p["genesis"], "path")?),
            output().join("genesis.tar.bz2"),
        ),
    ] {
        binds.push((src, dst));
    }
    let bank = Path::new(st(&p["bootstrap_file"], "path")?);
    binds.push((bank.into(), bank.into()));
    for row in p["indexes"].as_array().context("compact indexes")? {
        binds.push((
            PathBuf::from(st(&row["source"], "path")?),
            PathBuf::from(st(row, "target")?),
        ));
    }
    Ok(binds)
}

fn translate_argv(old: &[String], p: &Value) -> Result<Vec<String>> {
    let start = old
        .iter()
        .position(|a| a == "/usr/bin/python3")
        .context("original held gate")?;
    ensure!(
        old.first().is_some_and(|a| a == "/usr/bin/systemd-run")
            && old[start + 1] == "-IB"
            && old[start + 2] == format!("{OLD_ALIAS}/gate.py")
            && old[start + 3..].len() == 8,
        "foreign original producer prefix"
    );
    let mut argv = Vec::new();
    let payload_digest = sha(&bytes(p)?);
    for arg in &old[..start] {
        let replacement = if arg == &format!("--unit={OLD_UNIT}") {
            format!("--unit={UNIT}")
        } else if arg.starts_with("--description=") {
            DESCRIPTION.to_owned()
        } else if cfg!(epoch168_cold_retry4)
            && [
                "--property=ReadWritePaths=",
                "--property=ExecPaths=",
                "--property=NoExecPaths=",
            ]
            .iter()
            .any(|prefix| arg.starts_with(prefix))
        {
            // Child mount IDs prevent atomic publication across private and output.
            // The qualified unit drop-in binds the common attempt exactly once.
            let (name, _) = arg
                .strip_prefix("--property=")
                .context("unit property")?
                .split_once('=')
                .context("path property")?;
            format!("--property={name}=")
        } else if arg.starts_with("--property=ExecPaths=") {
            format!(
                "--property=ExecPaths={} {ALIAS}/{NODE}",
                run().join("private").display()
            )
        } else if arg.starts_with("--property=ReadWritePaths=") {
            format!(
                "--property=ReadWritePaths={} {}",
                output().display(),
                run().join("private").display()
            )
        } else if arg.starts_with("--property=BindReadOnlyPaths=") {
            let entries = projections(p)?
                .into_iter()
                .map(|(s, t)| format!("{}:{}", s.display(), t.display()))
                .collect::<Vec<_>>();
            format!("--property=BindReadOnlyPaths={}", entries.join(" "))
        } else if arg.starts_with("--property=WorkingDirectory=") {
            format!("--property=WorkingDirectory={ALIAS}")
        } else if arg.starts_with("--property=StandardOutput=")
            || arg.starts_with("--property=StandardError=")
        {
            format!(
                "{}=append:{}",
                arg.split_once("=append:").context("foreign log")?.0,
                run().join("producer.log").display()
            )
        } else if let Some(env) = arg.strip_prefix("--setenv=") {
            let (key, _) = env.split_once('=').context("environment")?;
            let v = if key == "HORIZON_FULL168_PAYLOAD_SHA256" {
                &payload_digest
            } else {
                st(&p["environment"], key)?
            };
            format!("--setenv={key}={v}")
        } else {
            arg.clone()
        };
        argv.push(replacement);
    }
    argv.extend([
        "/usr/bin/python3".into(),
        "-IB".into(),
        format!("{ALIAS}/gate.py"),
    ]);
    argv.extend(serde_json::from_value::<Vec<String>>(
        p["regular_node_argv"].clone(),
    )?);
    Ok(argv)
}

pub fn profile() -> Result<Value> {
    let payload = translate_payload(original_payload()?)?;
    let (original, original_ref) = doc(
        &rt(OLD).join("SESSION_PRODUCER_ARGV.json"),
        Some(ORIGINAL_ARGV),
    )?;
    let original = serde_json::from_value::<Vec<String>>(original)?;
    let argv = translate_argv(&original, &payload)?;
    Ok(
        json!({"producer_argv":argv,"source_argv":original_ref,"fresh_attempt":run(),"producer_unit":UNIT,
        "guard_timer":TIMER,"guard_worker_root":LANE,"guard_binary_sha256":GUARD_SHA,
        "indexes":payload["indexes"],"readonly_projections":projections(&payload)?,
        "payload_sha256":sha(&bytes(&payload)?),"payload":payload}),
    )
}

fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            File::open(path.parent().context("parent")?)?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_dir()
            && (m.uid(), m.gid(), m.mode() & 0o7777) == (0, 0, mode),
        "unsafe directory {}",
        path.display()
    );
    Ok(())
}
fn placeholder(path: &Path) -> Result<()> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(path)
    {
        Ok(f) => {
            f.set_permissions(fs::Permissions::from_mode(0o444))?;
            f.sync_all()?;
            File::open(path.parent().context("parent")?)?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    validate_placeholder(path)
}
fn validate_placeholder(path: &Path) -> Result<()> {
    let m = path.symlink_metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && (m.uid(), m.gid(), m.nlink(), m.len(), m.mode() & 0o7777) == (0, 0, 1, 0, 0o444),
        "occupied mount target {}",
        path.display()
    );
    Ok(())
}
fn stage_mounts(payload: &Value) -> Result<()> {
    ensure_dir(Path::new(ALIAS), 0o755)?;
    for leaf in [
        "compact-indexes",
        "compact-indexes/167",
        "compact-indexes/168",
    ] {
        ensure_dir(&output().join(leaf), 0o755)?;
    }
    ensure_dir(&base().join("guard-receipts"), 0o700)?;
    ensure_dir(&base().join("barrier"), 0o711)?;
    for (src, dst) in projections(payload)? {
        if src == dst {
            continue;
        }
        if dst == Path::new(ALIAS).join("barrier") {
            ensure_dir(&dst, 0o755)?;
        } else {
            placeholder(&dst)?;
        }
    }
    Ok(())
}
fn retained(path: &Path, identity: &Value, want_sha: Option<&str>) -> Result<()> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let stamp = |m: fs::Metadata| -> Value {
        json!([
            m.dev(),
            m.ino(),
            m.len(),
            i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec())
        ])
    };
    let m = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 1001
            && m.gid() == 1003
            && stamp(m) == *identity,
        "changed retained input {}",
        path.display()
    );
    if let Some(expected) = want_sha {
        let mut h = Sha256::new();
        std::io::copy(&mut f, &mut h)?;
        ensure!(
            format!("{:x}", h.finalize()) == expected,
            "retained input digest {}",
            path.display()
        );
    }
    ensure!(
        stamp(f.metadata()?) == *identity && stamp(path.symlink_metadata()?) == *identity,
        "retained input changed while open {}",
        path.display()
    );
    Ok(())
}
fn retained_inputs(p: &Value, full: bool) -> Result<()> {
    for key in ["bootstrap_file", "genesis"] {
        let row = &p[key];
        retained(
            Path::new(st(row, "path")?),
            &row["identity"],
            if full { Some(st(row, "sha256")?) } else { None },
        )?;
    }
    for index in p["indexes"].as_array().context("indexes")? {
        for key in ["source", "independent_trace_copy"] {
            let row = &index[key];
            retained(Path::new(st(row, "path")?), &row["identity"], None)?;
        }
    }
    Ok(())
}
fn validate_root_directories(root: &Value) -> Result<()> {
    for (key, path, ino) in [
        ("root", run(), RUN_INO),
        ("output", output(), OUTPUT_INO),
        ("private", run().join("private"), PRIVATE_INO),
    ] {
        let m = path.symlink_metadata()?;
        let row = if key == "root" { root } else { &root[key] };
        ensure!(
            path.canonicalize()? == path
                && m.is_dir()
                && (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())
                    == (64512, ino, 1001, 1003, 0o40700)
                && n(row, "inode")? == ino,
            "changed 168 {key}"
        );
    }
    Ok(())
}

#[cfg(not(epoch168_cold_retry5))]
pub fn files() -> Result<Value> {
    let (root, rootref) = doc(&base().join("SUCCESSOR_ROOT.json"), Some(ROOT))?;
    ensure!(
        root["root"] == json!(run())
            && root["worker_launched"] == false
            && root["protected_ancestors_before"] == root["protected_ancestors_after"]
            && root["protected_ancestors_before"]
                .as_object()
                .is_some_and(|rows| rows.len() == 52),
        "different original successor namespace"
    );
    validate_root_directories(&root)?;
    let prior = bound(
        &root["prior_stop"],
        &rt(OLD).join("guard-receipts/stop-completion.json"),
    )?;
    let cleanup = bound(
        &root["initial_cleanup"],
        &rt("epoch168-closed-accounts-20261122-v1/state/full-metered/COMPLETE.json"),
    )?;
    ensure!(
        prior["producer_invocation_id"] == "9cebb1d022124fb08588e93e055d5446"
            && prior["terminal"]["pid"] == 0
            && prior["terminal"]["active"] == "inactive"
            && cleanup["original_iid"] == prior["producer_invocation_id"]
            && cleanup["scope_empty"] == true
            && cleanup["archive_or_snapshot_removed"] == false,
        "predecessor cleanup differs"
    );
    for old in [
        OLD_UNIT,
        "horizon-guard-168-full-metered-20261121-v1.timer",
        "horizon-guard-168-full-metered-20261121-v1.service",
    ] {
        let m = native(old)?;
        ensure!(
            m["ActiveState"] == "inactive" && m["Job"] == "" && members(old)?.is_empty(),
            "old 168 is active"
        );
    }
    #[cfg(all(epoch168_cold_retry3, not(epoch168_cold_retry4)))]
    spent_retry2(&root)?;
    #[cfg(epoch168_cold_retry4)]
    {
        ensure!(
            root["parent_immutable"] == true
                && root["children_immutable"] == false
                && directory_immutable(&run())?
                && !directory_immutable(&output())?
                && !directory_immutable(&run().join("private"))?,
            "changed protection on the epoch 168 publication directory"
        );
        spent_retry3(&root)?;
    }
    let profile = profile()?;
    retained_inputs(&profile["payload"], false)?;
    Ok(
        json!({"root":{"path":run(),"device":64512,"inode":RUN_INO},"stable_roots":rootref,"predecessor_stop":root["prior_stop"],"profile":profile}),
    )
}
#[cfg(epoch168_cold_retry5)]
pub fn files() -> Result<Value> {
    let (root, rootref) = doc(&base().join("SUCCESSOR_ROOT.json"), Some(ROOT))?;
    ensure!(
        root["schema"] == "horizon-epoch168-retry5-successor-root-v1"
            && root["root"] == json!(run())
            && root["worker_launched"] == false
            && root["whole_tree_cap_bytes"] == CAP
            && root["root_immutable"] == true
            && directory_immutable(&run())?
            && !directory_immutable(&output())?
            && !directory_immutable(&run().join("private"))?,
        "different retry5 namespace"
    );
    validate_root_directories(&root)?;
    let (retained, control) = doc(
        &rt(
            "incident-replay-fit-20261121-v1/STOPPED168_RETRY5_RETAINED_SOURCE_CONTROL_20261125.json",
        ),
        Some("488dbd9e630511b97a0ad0704241a0a1fdec71a614caf17c6cd1d3a63b3dc0b2"),
    )?;
    ensure!(
        root["source_control_sha256"] == control["sha256"] && retained["epoch"] == EPOCH,
        "different retained retry4 input control"
    );
    let stop = &retained["stop"];
    let retry4 = rt("epoch168-retry4-rebook-20261123-v1");
    let stopped = bound(
        &stop["terminal"],
        &retry4.join("guard-receipts/stop-completion.json"),
    )?;
    let intent = bound(
        &stop["stop_intent"],
        &retry4.join("guard-receipts/stop-intent.json"),
    )?;
    let prior = bound(
        &stop["admission"],
        &retry4.join("ACTUAL_ADMISSION_AND_PROTECTION.json"),
    )?;
    ensure!(
        stop["producer_invocation_id"] == "913443d7f9f44d7e9d3e0eec420acfab"
            && stopped["producer_invocation_id"] == stop["producer_invocation_id"]
            && prior["producer_invocation_id"] == stop["producer_invocation_id"]
            && intent["producer_invocation_id"] == stop["producer_invocation_id"]
            && intent["reason"] == "root-physical-budget"
            && stopped["scratch_deleted"] == false
            && stop["reservation_ending_bytes"] == 0
            && stop["resource_credit_bytes"] == 0,
        "different stopped retry4 generation"
    );
    for unit in [
        "horizon-qualify-168-full-metered-cold-v4-20261123.service",
        "horizon-guard-168-full-metered-cold-v4-20261123.timer",
        "horizon-guard-168-full-metered-cold-v4-20261123.service",
    ] {
        let state = native(unit)?;
        ensure!(
            state["ActiveState"] == "inactive"
                && state["InvocationID"] == ""
                && state["Job"] == ""
                && members(unit)?.is_empty(),
            "retained retry4 still has an owner"
        );
    }
    let (historical_root, _) = doc(
        &retry4.join("SUCCESSOR_ROOT.json"),
        Some("713e94750dd3d430c2f54c1ccb2af7ed708dec802af5cbf210ee4963a992d0f4"),
    )?;
    let original_stop = &historical_root["prior_stop"];
    let original = bound(
        original_stop,
        &rt(OLD).join("guard-receipts/stop-completion.json"),
    )?;
    ensure!(
        original["producer_invocation_id"] == "9cebb1d022124fb08588e93e055d5446"
            && original["terminal"]["pid"] == 0
            && original["terminal"]["active"] == "inactive",
        "different original HOME stop"
    );
    let profile = profile()?;
    retained_inputs(&profile["payload"], false)?;
    Ok(json!({
        "root":{"path":run(),"device":64512,"inode":RUN_INO},
        "stable_roots":rootref,"predecessor_stop":original_stop,
        "retry4_root_physical_stop":stop,"retained_source_control":control,"profile":profile
    }))
}

#[cfg(all(epoch168_cold_retry3, not(epoch168_cold_retry5)))]
fn spent_retry2(root: &Value) -> Result<()> {
    let prior = rt("epoch168-retry2-rebook-20261122-v1");
    let previous_root = bound(&root["previous_root"], &prior.join("SUCCESSOR_ROOT.json"))?;
    let failure = bound(
        &root["previous_start_failure"],
        &prior.join("RELEASED_NODE_STARTUP_FAILURE_20261123.json"),
    )?;
    validate_previous(root, &previous_root, &failure)?;
    let receipts = &failure["receipts"];
    let authorization = bound(
        &receipts["AUTHORIZED_GATED_PAYLOAD.json"],
        &prior.join("AUTHORIZED_GATED_PAYLOAD.json"),
    )?;
    let held = bound(
        &receipts["ACTUAL_PRODUCER_NATIVE.json"],
        &prior.join("ACTUAL_PRODUCER_NATIVE.json"),
    )?;
    let old_unit = st(&failure["producer"], "Id")?;
    let old_timer = st(&failure["timer"], "Id")?;
    let actor = native(old_unit)?;
    let timer = native(old_timer)?;
    let iid = st(&held, "producer_invocation_id")?;
    let allow = prior.join("barrier/allow");
    ensure!(
        authorization["producer_invocation_id"] == iid
            && authorization["producer_pid"] == held["producer_pid"]
            && authorization["start_ticks"] == held["start_ticks"]
            && failure["producer"]["InvocationID"] == iid
            && receipts["barrier/allow"]["path"] == json!(allow)
            && receipts["barrier/allow"]["sha256"] == file_digest(&allow)?
            && raw(&allow, 32)? == iid.as_bytes()
            && !prior
                .join("ACTUAL_ADMISSION_AND_PROTECTION.json")
                .try_exists()?
            && actor["ActiveState"] == "failed"
            && actor["InvocationID"] == iid
            && actor["Result"] == "exit-code"
            && actor["MainPID"] == "0"
            && actor["ControlPID"] == "0"
            && actor["Job"] == ""
            && actor["NRestarts"] == "0"
            && members(old_unit)?.is_empty()
            && timer["ActiveState"] == "inactive"
            && timer["Job"] == ""
            && members(&old_timer.replace(".timer", ".service"))?.is_empty(),
        "previous epoch 168 permit or stopped owner changed"
    );
    Ok(())
}
#[cfg(epoch168_cold_retry3)]
fn validate_previous(root: &Value, previous: &Value, failure: &Value) -> Result<()> {
    ensure!(
        root["previous_root"]["sha256"]
            == "ec909d6701ce7dcbee72da319bf0179ba375e1cf6e284aa29686e1dd0a3cbecc"
            && root["previous_start_failure"]["sha256"]
                == "a3353dfdbcf5de9320f22229134c9bdcaa70abb40aca0e85dd1ad315c4740643"
            && previous["prior_stop"] == root["prior_stop"]
            && previous["initial_cleanup"] == root["initial_cleanup"]
            && failure["epoch"] == EPOCH
            && failure["permit_consumed"] == true
            && failure["no_admission_record"] == true
            && failure["worker_receipt_absent"] == true
            && failure["private_directory_empty"] == true
            && failure["producer"]["Id"]
                == "horizon-qualify-168-full-metered-cold-v2-20261122.service"
            && failure["timer"]["Id"] == "horizon-guard-168-full-metered-cold-v2-20261122.timer"
            && failure["producer"]["InvocationID"] == "d929652cba0e459cafc75edd05356c83"
            && failure["producer"]["ExecMainStatus"] == "1"
            && failure["producer"]["NRestarts"] == "0",
        "wrong predecessor for epoch 168 retry3"
    );
    Ok(())
}
#[cfg(epoch168_cold_retry4)]
const RETRY3_FAILURE: &str = "cf8ef71b5b000cc4138f726d019c59a107b9b3d45f741b0b4802a6f4f31f1d21";
#[cfg(epoch168_cold_retry4)]
fn validate_exdev(failure: &Value, admitted: &Value) -> Result<()> {
    ensure!(
        failure["schema"] == "horizon-168-released-node-publication-probe-failure-v1"
            && failure["epoch"] == EPOCH
            && failure["permit_consumed"] == true
            && failure["bootstrap_admission"] == true
            && failure["no_admission_record"] == false
            && failure["worker_receipt_absent"] == true
            && failure["worker_in_observed_guard_samples"] == false
            && failure["replay_claimed"] == false
            && failure["r2_mutations"].as_u64() == Some(0)
            && st(failure, "node_error")?.contains(
                "RENAME_NOREPLACE is unavailable: Invalid cross-device link (os error 18)"
            )
            && failure["producer"]["ExecMainStatus"] == "1"
            && failure["producer"]["NRestarts"] == "0"
            && failure["producer"]["InvocationID"] == "032cb7da1929485994cf18b384c93459"
            && admitted["producer_invocation_id"] == failure["producer"]["InvocationID"]
            && admitted["stage"] == "node"
            && admitted["bootstrap_only"] == true
            && admitted["transaction_replay_claimed"] == false
            && admitted["resource_credit_bytes"] == 0
            && admitted["producer_unit"]
                == "horizon-qualify-168-full-metered-cold-v3-20261123.service"
            && admitted["timer_unit"] == "horizon-guard-168-full-metered-cold-v3-20261123.timer"
            && admitted["producer_unit"] == failure["producer"]["Id"]
            && admitted["timer_unit"] == failure["timer"]["Id"],
        "different epoch 168 EXDEV predecessor"
    );
    Ok(())
}
#[cfg(all(epoch168_cold_retry4, not(epoch168_cold_retry5)))]
fn spent_retry3(root: &Value) -> Result<()> {
    let prior = rt("epoch168-retry3-rebook-20261123-v1");
    let prev = bound(&root["previous_root"], &prior.join("SUCCESSOR_ROOT.json"))?;
    ensure!(
        root["previous_root"]["sha256"]
            == "a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4"
            && root["previous_start_failure"]["sha256"] == RETRY3_FAILURE
            && root["initial_cleanup"] == prev["initial_cleanup"]
            && root["prior_stop"] == prev["prior_stop"],
        "different original epoch 168 retry lineage"
    );
    spent_retry2(&prev)?;
    let failure = bound(
        &root["previous_start_failure"],
        &prior.join("RELEASED_NODE_STARTUP_FAILURE_20261123.json"),
    )?;
    let refs = &failure["receipts"];
    let admission = bound(
        &refs["ACTUAL_ADMISSION_AND_PROTECTION.json"],
        &prior.join("ACTUAL_ADMISSION_AND_PROTECTION.json"),
    )?;
    validate_exdev(&failure, &admission)?;
    let (fixture, _) = doc(
        &prior.join("COMMON_MOUNT_REGRESSION/RESULT.json"),
        Some("51b01c0110965a74db73e539dea68b0520f9e9b5ed02cb581f6a7f54be310704"),
    )?;
    ensure!(
        fixture["native_failure"] == root["previous_start_failure"]
            && fixture["visible_qa_worker"]["sha256"] == WORKER_SHA
            && fixture["dropin"]["sha256"]
                == "962785e09604bb61d88ab2eeeedbf2a7f6975e28cd46c4f7c82553125180268e"
            && fixture["canonical_writes"] == 0
            && fixture["physical_campaign_replay"] == false
            && fixture["temporary_filesystems_retired"] == true,
        "different single-mount historical worker qualification"
    );

    let auth = bound(
        &refs["AUTHORIZED_GATED_PAYLOAD.json"],
        &prior.join("AUTHORIZED_GATED_PAYLOAD.json"),
    )?;
    let node = bound(
        &refs["NODE_AFTER_PERMIT.json"],
        &prior.join("NODE_AFTER_PERMIT.json"),
    )?;
    let iid = st(&auth, "producer_invocation_id")?;
    let allow = prior.join("barrier/allow");
    let unit = st(&admission, "producer_unit")?;
    let timer = st(&admission, "timer_unit")?;
    let ctl = native(unit)?;
    let retired_timer = native(timer)?;
    ensure!(
        auth["producer_invocation_id"] == admission["producer_invocation_id"]
            && auth["producer_pid"] == admission["producer_pid"]
            && auth["start_ticks"] == admission["start_ticks"]
            && node["producer_invocation_id"] == iid
            && node["authorization"] == refs["AUTHORIZED_GATED_PAYLOAD.json"]
            && admission["source"] == refs["PREPARED.json"]
            && admission["intent"] == refs["START_INTENT.json"]
            && refs["barrier/allow"]["path"] == json!(allow)
            && refs["barrier/allow"]["sha256"] == file_digest(&allow)?
            && raw(&allow, 32)? == iid.as_bytes()
            && !prior.join("FIRST_PROTECTED_WORKER.json").try_exists()?
            && ctl["ActiveState"] == "failed"
            && ctl["InvocationID"] == iid
            && ctl["Result"] == "exit-code"
            && ctl["MainPID"] == "0"
            && ctl["ControlPID"] == "0"
            && ctl["NRestarts"] == "0"
            && ctl["Job"] == ""
            && members(unit)?.is_empty()
            && retired_timer["ActiveState"] == "inactive"
            && retired_timer["Job"] == ""
            && members(&timer.replace(".timer", ".service"))?.is_empty(),
        "changed prior 168 guard, authorization or native stop"
    );
    Ok(())
}
fn record_once(name: &str, value: &Value) -> Result<Value> {
    let p = base().join(name);
    if p.try_exists()? {
        let (v, r) = doc(&p, None)?;
        ensure!(v == *value, "conflicting {name}");
        Ok(r)
    } else {
        record(name, value)
    }
}
fn logfile() -> Result<File> {
    let p = run().join("producer.log");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&p)?;
    let m = f.metadata()?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && (m.dev(), m.ino(), m.nlink(), m.mode() & 0o7777, m.len())
                == (64512, LOG_INO, 1, 0o600, 0)
            && matches!((m.uid(), m.gid()), (1001, 1003) | (0, 0))
            && same(
                &p,
                &Path::new("/proc/self/fd").join(f.as_raw_fd().to_string())
            )?,
        "untrusted successor log"
    );
    Ok(f)
}
pub fn prepare() -> Result<Value> {
    ensure!(
        std::env::current_exe()? == base().join(COLD168_LAUNCHER),
        "use sealed 168 launcher"
    );
    let clean = files()?;
    let profile = &clean["profile"];
    ensure!(
        native(UNIT)?["LoadState"] == "not-found"
            && native(TIMER)?["LoadState"] == "not-found"
            && !base().join("START_INTENT.json").try_exists()?,
        "already started"
    );
    if base().join("PREPARED.json").try_exists()? {
        return ready();
    }
    let p = &profile["payload"];
    retained_inputs(p, true)?;
    for (name, row) in p["members"].as_object().context("members")? {
        ensure!(
            file_digest(Path::new(row[0].as_str().context("member path")?))?
                == row[1].as_str().context("member hash")?,
            "changed original {name}"
        );
    }
    ensure!(
        fs::read_dir(run().join("private"))?.next().is_none(),
        "private tree occupied"
    );
    let log = logfile()?;
    std::os::unix::fs::fchown(&log, Some(0), Some(0))?;
    log.sync_all()?;
    let payload = record_once("COLD_PAYLOAD.json", p)?;
    ensure!(
        payload["sha256"] == profile["payload_sha256"],
        "payload encoding differs"
    );
    stage_mounts(p)?;
    record("PREPARED.json", &preparation(&clean, &payload))
}
fn preparation(clean: &Value, payload: &Value) -> Value {
    let profile = &clean["profile"];
    json!({"schema":"horizon-168-replay-recovery-preparation-v1","epoch":EPOCH,
        "baseline":clean,"profile":profile,"payload":payload,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,
        "original_run_retained":true,"replay_launch_authorized":false})
}
pub fn prepare_log() -> Result<Value> {
    let m = logfile()?.metadata()?;
    ensure!((m.uid(), m.gid()) == (0, 0), "observer log not root-owned");
    record_once(
        "OBSERVER_LOG_PREPARED.json",
        &json!({"schema":"horizon-168-root-owned-observer-log-v1",
        "prepared":doc(&base().join("PREPARED.json"),None)?.1,"path":run().join("producer.log"),"device":m.dev(),"inode":m.ino(),
        "uid":m.uid(),"gid":m.gid(),"mode":m.mode()&0o7777,"nlink":m.nlink(),"size":m.len()}),
    )
}
pub fn ready() -> Result<Value> {
    let (prep, r) = doc(&base().join("PREPARED.json"), PREPARED)?;
    let clean = files()?;
    let (_, payload) = doc(
        &base().join("COLD_PAYLOAD.json"),
        Some(st(&clean["profile"], "payload_sha256")?),
    )?;
    ensure!(
        prep == preparation(&clean, &payload),
        "different epoch 168 preparation"
    );
    let m = logfile()?.metadata()?;
    ensure!(
        (m.uid(), m.gid()) == (0, 0)
            && prep["baseline"] == clean
            && prep["profile"] == prep["baseline"]["profile"]
            && bound(&prep["payload"], &base().join("COLD_PAYLOAD.json"))?
                == prep["profile"]["payload"]
            && fs::read_dir(run().join("private"))?.next().is_none()
            && fs::read_dir(base().join("barrier"))?.next().is_none(),
        "changed 168 preparation"
    );
    for (src, dst) in projections(&prep["profile"]["payload"])? {
        if src != dst && dst != Path::new(ALIAS).join("barrier") {
            validate_placeholder(&dst)?;
        }
    }
    Ok(r)
}
#[cfg(epoch168_cold_retry4)]
fn directory_immutable(path: &Path) -> Result<bool> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let mut flags: libc::c_long = 0;
    // FS_IOC_GETFLAGS is read-only. FS_IMMUTABLE_FL is bit 4 in linux/fs.h.
    if unsafe { libc::ioctl(f.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(flags & 0x10 != 0)
}
#[cfg(epoch168_cold_retry4)]
fn mount_id(path: &Path) -> Result<u64> {
    let fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?;
    info.lines()
        .find_map(|s| s.strip_prefix("mnt_id:"))
        .context("directory mount ID")?
        .trim()
        .parse()
        .context("invalid mount ID")
}
#[cfg(epoch168_cold_retry4)]
fn publication_mounts(root: &Path) -> Result<()> {
    let attempt = run();
    let inside = |path: &Path| -> Result<PathBuf> { Ok(root.join(path.strip_prefix("/")?)) };
    let parent = inside(&attempt)?;
    let mount = mount_id(&parent)?;
    ensure!(
        directory_immutable(&parent)?,
        "epoch 168 attempt parent lost its immutable flag"
    );
    for (leaf, ino) in [
        (attempt, RUN_INO),
        (output(), OUTPUT_INO),
        (run().join("private"), PRIVATE_INO),
    ] {
        let path = inside(&leaf)?;
        let m = path.symlink_metadata()?;
        ensure!(
            same(&path, &leaf)?
                && (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())
                    == (64512, ino, 1001, 1003, 0o40700)
                && mount_id(&path)? == mount,
            "epoch 168 publication crosses mount at {}",
            leaf.display()
        );
    }
    Ok(())
}

pub fn index_selected() -> Result<()> {
    let m = native(UNIT)?;
    let pid = st(&m, "MainPID")?.parse::<u64>()?;
    ensure!(pid > 1, "no 168 native gate");
    let root = Path::new("/proc").join(pid.to_string());
    #[cfg(epoch168_cold_retry4)]
    publication_mounts(&root.join("root"))?;
    let mountinfo = fs::read_to_string(root.join("mountinfo"))?;
    for (src, dst) in projections(&translate_payload(original_payload()?)?)? {
        let path = root.join("root").join(dst.strip_prefix("/")?);
        ensure!(
            same(&path, &src)?
                && mountinfo.lines().any(|line| {
                    let mut f = line.split_whitespace().skip(4);
                    f.next() == dst.to_str()
                        && f.next().is_some_and(|v| v.split(',').any(|o| o == "ro"))
                }),
            "incorrect sealed mount {}",
            dst.display()
        );
    }
    ensure!(
        native(UNIT)?["InvocationID"] == m["InvocationID"],
        "168 changed during mounts check"
    );
    Ok(())
}

#[cfg(not(epoch168_cold_retry5))]
pub fn funded_guard_floor(price: &Value) -> Result<u64> {
    let c = &price["startup_nonexact_peer_floor"];
    let floor = n(c, "protected_raw_floor_bytes")?;
    let need = n(c, "complete_required_HOME_bytes")?;
    let charged = n(&price["bookings"]["168"], "remaining_bytes")?;
    ensure!(
        c["schema"] == "horizon-168-nonexact-peer-prestart-v1"
            && c["funded"] == true
            && c["occupied172_credit_bytes"] == 0
            && n(c, "full172_cap_bytes")? == 288 << 30
            && n(c, "candidate_remaining_bytes")? == charged
            && floor == n(price, "protected_raw_floor_bytes")?
            && need == n(price, "complete_required_HOME_bytes")?
            && floor.checked_add(charged) == Some(need),
        "incomplete protected 168 booking"
    );
    let spare = n(price, "available_HOME_bytes")?
        .checked_sub(need)
        .context("unfunded 168 floor")?;
    floor
        .checked_add(spare.min(10 << 30))
        .context("168 floor overflow")
}

#[cfg(epoch168_cold_retry5)]
pub fn funded_guard_floor(price: &Value) -> Result<u64> {
    let booking = &price["bookings"]["168"];
    let quote = &price["retry5_complete_booking"];
    let retained = n(quote, "previous_producer_physical_charge_bytes")?;
    let physical = n(booking, "physical_bytes")?;
    let remaining = n(booking, "remaining_bytes")?;
    let floor = n(quote, "protected_raw_floor_bytes")?;
    let required = n(quote, "complete_required_HOME_bytes")?;
    ensure!(
        price["epoch"] == EPOCH
            && price["fits"] == true
            && quote["schema"] == "horizon-168-retry5-complete-booking-v1"
            && quote["funded"] == true,
        "unfunded retry5 quote"
    );
    ensure!(
        n(quote, "producer_cpu_quota_micros")? == 9_000_000
            && n(quote, "producer_memory_bytes")? == (68 << 30)
            && n(quote, "guard_cpu_quota_micros")? == 250_000
            && n(quote, "guard_memory_bytes")? == (1 << 30)
            && n(quote, "producer_swap_bytes")? == 0
            && n(quote, "guard_swap_bytes")? == 0,
        "wrong retry5 producer or guard limits"
    );
    ensure!(
        quote["prior_stop"] == price["stopped_cold168"]["terminal"]
            && quote["prior_stop"]["sha256"]
                == "b0538a4dee05df924a8d04f8562866df701c03996498963552a932059826cdab"
            && quote["retained_source"] == price["retry5_retained_source"]
            && quote["retained_source"]["sha256"]
                == "488dbd9e630511b97a0ad0704241a0a1fdec71a614caf17c6cd1d3a63b3dc0b2"
            && retained >= n(&price["stopped_cold168"], "measured_physical_bytes")?
            && retained <= physical,
        "wrong retry5 predecessor charge"
    );
    ensure!(
        physical.checked_add(remaining) == Some(CAP)
            && n(booking, "cap_bytes")? == CAP
            && booking["root"] == LANE
            && booking["run"] == json!(run())
            && n(quote, "candidate_remaining_bytes")? == remaining,
        "wrong retry5 whole-tree booking"
    );
    ensure!(
        n(quote, "outside_cap_stop_allowance_bytes")? == (8 << 30)
            && quote["retained_base_HOME_bytes"]
                == price["epoch159_donor_cover"]["native_home_required"]
            && n(quote, "retained_base_HOME_bytes")?.checked_add(8 << 30) == Some(floor)
            && floor == n(price, "protected_raw_floor_bytes")?
            && required == n(price, "complete_required_HOME_bytes")?
            && floor.checked_add(remaining) == Some(required),
        "wrong retry5 protected HOME floor"
    );
    let spare = n(price, "available_HOME_bytes")?
        .checked_sub(required)
        .context("unfunded retry5 floor")?;
    floor
        .checked_add(spare.min(10 << 30))
        .context("retry5 floor overflow")
}

pub fn peer_identity(price: &Value) -> Result<Value> {
    let survivors = price["survivors"].as_object().context("survivors")?;
    ensure!(
        survivors.len() == 1 && survivors.contains_key("172"),
        "different original 168 peer population"
    );
    let p = &price["survivors"]["172"];
    let mut ids =
        json!({"172":[p["unit"],p["invocation_id"],p["timer_invocation_id"],p["processes"]]});
    for (k, p) in price["replacements"].as_object().context("replacements")? {
        if k == "168" {
            continue;
        }
        ensure!(
            (k == "167" || !cfg!(epoch168_cold_retry5) && matches!(k.as_str(), "166" | "170"))
                && p["admission"].is_object()
                && p["first_guard"].is_object(),
            "unexpected peer or pending admission"
        );
        ids[k] = json!([
            p["producer_unit"],
            p["producer_invocation_id"],
            p["timer_invocation_id"],
            p["processes"]
        ]);
    }
    ensure!(
        ids.get("167").is_some() && (cfg!(epoch168_cold_retry5) || ids.get("170").is_some()),
        "incomplete live 168 siblings"
    );
    for set in ids.as_object().unwrap().values() {
        ensure!(
            set[0].is_string()
                && set[1].as_str().is_some_and(|s| hex(s, 32))
                && set[2].as_str().is_some_and(|s| hex(s, 32))
                && set[3].as_array().is_some_and(|rows| !rows.is_empty()),
            "incomplete 168 peer identity"
        );
    }
    Ok(ids)
}

pub fn release_gate(held: &Value, plan: &Value, first: &Value, post: &Value) -> Result<Value> {
    ensure!(
        held["stage"] == "held"
            && actor::sample()? == *held
            && members(UNIT)? == vec![n(held, "producer_pid")?],
        "168 gate no longer held"
    );
    let price = bound(post, &base().join("POST_GUARD_CAPACITY.json"))?;
    verify_held_price(held, plan, first, &price)?;
    index_selected()?;
    actor::guard(held, plan)?;
    let ref_auth = record(
        "AUTHORIZED_GATED_PAYLOAD.json",
        &json!({"producer_invocation_id":held["producer_invocation_id"],
        "producer_pid":held["producer_pid"],"start_ticks":held["start_ticks"],"first_guard":first,"actual_guard_plan":plan,
        "post_guard_capacity":post,"transaction_replay_claimed":false}),
    )?;
    let barrier = base().join("barrier");
    let mut f = tempfile::NamedTempFile::new_in(&barrier)?;
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    f.write_all(st(held, "producer_invocation_id")?.as_bytes())?;
    f.as_file().sync_all()?;
    ensure!(actor::sample()? == *held, "different actor at gate release");
    f.persist_noclobber(barrier.join("allow"))?;
    File::open(&barrier)?.sync_all()?;
    let next = await_node(held)?;
    index_selected()?;
    let mut observed = next.clone();
    observed["authorization"] = ref_auth;
    record_once("NODE_AFTER_PERMIT.json", &observed)?;
    Ok(next)
}

fn verify_held_price(held: &Value, plan: &Value, first: &Value, price: &Value) -> Result<()> {
    let provider = member(&rt(FIT), st(&price["provider_seal"], "sha256")?)?;
    let (record, actor) = doc(&base().join("ACTUAL_PRODUCER_NATIVE.json"), None)?;
    ensure!(
        record == *held && held["stage"] == "held",
        "different held 168 receipt"
    );
    checked_quote(price, &provider, &actor, plan, first)?;
    #[cfg(epoch168_cold_retry5)]
    funded_guard_floor(price)?;
    Ok(())
}

fn checked_quote(
    price: &Value,
    provider: &Value,
    actor: &Value,
    plan: &Value,
    first: &Value,
) -> Result<()> {
    let candidate = &price["candidate"];
    ensure!(
        price["fits"] == true
            && price["provider_seal"] == *provider
            && candidate.get("admission") == Some(&Value::Null)
            && candidate["plan"] == *plan
            && candidate["first_guard"] == *first
            && candidate["actor"] == *actor,
        "missing namespace-checked capacity for the held epoch 168 process"
    );
    Ok(())
}

fn await_node(held: &Value) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let m = native(UNIT)?;
        ensure!(
            m["InvocationID"] == held["producer_invocation_id"]
                && m["MainPID"] == held["MainPID"]
                && m["NRestarts"] == "0"
                && m["ActiveState"] == "active",
            "released 168 owner changed"
        );
        let next = match actor::sample() {
            Ok(next) => next,
            Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e),
        };
        for key in [
            "producer_invocation_id",
            "producer_pid",
            "start_ticks",
            "cgroup",
        ] {
            ensure!(
                next[key] == held[key],
                "168 crossed native owner after permit"
            );
        }
        if next["stage"] == "node" {
            return Ok(next);
        }
        ensure!(
            Instant::now() < deadline,
            "original 168 gate has not executed its node"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn finish_released(fleet: &Value, fit_seal: &str) -> Result<Value> {
    let (intent, intent_ref) = doc(&base().join("START_INTENT.json"), None)?;
    let (held, _) = doc(&base().join("ACTUAL_PRODUCER_NATIVE.json"), None)?;
    let (auth, auth_ref) = doc(&base().join("AUTHORIZED_GATED_PAYLOAD.json"), None)?;
    let plan = &auth["actual_guard_plan"];
    let first = &auth["first_guard"];
    let post = &auth["post_guard_capacity"];
    let price = bound(post, &base().join("POST_GUARD_CAPACITY.json"))?;
    verify_held_price(&held, plan, first, &price)?;
    let pre = &intent["prestart"];
    ensure!(
        intent["fleet"] == *fleet
            && intent["producer_unit"] == UNIT
            && intent["timer_unit"] == TIMER
            && pre["provider_seal"]["sha256"] == fit_seal
            && price["provider_seal"] == pre["provider_seal"]
            && price["fleet"] == *fleet
            && price["fits"] == true
            && peer_identity(&price)? == peer_identity(pre)?
            && price["status_registration"] == pre["status_registration"]
            && price["protected_raw_floor_bytes"]
                .as_u64()
                .is_some_and(|v| intent["armed_floor"].as_u64().is_some_and(|f| v <= f))
            && auth["producer_invocation_id"] == held["producer_invocation_id"]
            && auth["producer_pid"] == held["producer_pid"]
            && auth["start_ticks"] == held["start_ticks"]
            && price["candidate"]["producer_invocation_id"] == auth["producer_invocation_id"]
            && price["candidate"]["producer_pid"] == auth["producer_pid"]
            && price["candidate"]["start_ticks"] == auth["start_ticks"],
        "unrelated recorded gate release"
    );
    let permit = base().join("barrier/allow");
    let m = permit.symlink_metadata()?;
    ensure!(
        m.is_file()
            && (m.uid(), m.gid(), m.mode(), m.nlink(), m.len()) == (0, 0, 0o100444, 1, 32)
            && raw(&permit, 32)? == st(&held, "producer_invocation_id")?.as_bytes(),
        "different release permit"
    );
    bound(&intent["prepared"], &base().join("PREPARED.json"))?;
    let first_row = bound(first, &base().join("FIRST_GUARD.json"))?;
    let node = await_node(&held)?;
    index_selected()?;
    let (latest, _) = actor::guard(&node, plan)?;
    ensure!(
        latest["timer"]["InvocationID"] == first_row["timer"]["InvocationID"],
        "original guard changed after permit"
    );
    let mut observed = node.clone();
    observed["authorization"] = auth_ref;
    record_once("NODE_AFTER_PERMIT.json", &observed)?;
    let mut ad = node;
    for (k,v) in json!({"schema":"horizon-168-source-index-admission-protection-v1","epoch":EPOCH,"timer_unit":TIMER,
        "timer_invocation_id":latest["timer"]["InvocationID"],"actual_guard_plan":plan,"first_guard":first,"post_guard_capacity":post,
        "fleet":fleet,"intent":intent_ref,"source":intent["prepared"],"predecessor_stop":intent["predecessor_stop"],
        "stable_root":intent["stable_root"],"bootstrap_only":true,"transaction_replay_claimed":false,"resource_credit_bytes":0}).as_object().unwrap(){ad[k]=v.clone()}
    record_once("ACTUAL_ADMISSION_AND_PROTECTION.json", &ad)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_checked_quote_is_bound_to_this_held_actor_and_guard() {
        let provider = json!({"path":rt(FIT).parent().unwrap().join("deployment-seal-receipt.json"),"sha256":"fixture"});
        let (actor, plan, first) = (
            json!({"path":"held"}),
            json!({"path":"plan"}),
            json!({"path":"first"}),
        );
        let row = json!({"admission": null, "actor":actor, "plan":plan, "first_guard":first});
        let price = json!({"fits":true, "provider_seal":provider, "candidate":row});
        assert!(checked_quote(&price, &provider, &actor, &plan, &first).is_ok());
        for key in ["admission", "actor", "plan", "first_guard"] {
            let mut other = price.clone();
            other["candidate"][key] = json!("different");
            assert!(checked_quote(&other, &provider, &actor, &plan, &first).is_err());
        }
        let mut old = price.clone();
        old["provider_seal"]["path"] = json!(rt(
            "incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry2-v1/deployment-seal-receipt.json"
        ));
        assert!(checked_quote(&old, &provider, &actor, &plan, &first).is_err());
        let mut short = price;
        short["fits"] = json!(false);
        assert!(checked_quote(&short, &provider, &actor, &plan, &first).is_err());
    }
    #[cfg(epoch168_cold_retry3)]
    #[test]
    fn previous_permit_cannot_admit_a_successor() {
        let root = doc(
            &rt("epoch168-retry3-rebook-20261123-v1/SUCCESSOR_ROOT.json"),
            Some("a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4"),
        )
        .unwrap()
        .0;
        let prior = rt("epoch168-retry2-rebook-20261122-v1");
        let prev = bound(&root["previous_root"], &prior.join("SUCCESSOR_ROOT.json")).unwrap();
        let f = bound(
            &root["previous_start_failure"],
            &prior.join("RELEASED_NODE_STARTUP_FAILURE_20261123.json"),
        )
        .unwrap();
        for key in [
            "permit_consumed",
            "no_admission_record",
            "worker_receipt_absent",
            "private_directory_empty",
        ] {
            let mut bad = f.clone();
            bad[key] = json!(false);
            assert!(validate_previous(&root, &prev, &bad).is_err());
        }
        let mut wrong = f;
        wrong["producer"]["InvocationID"] = json!("unrelated");
        assert!(validate_previous(&root, &prev, &wrong).is_err());
    }
    #[cfg(epoch168_cold_retry4)]
    #[test]
    fn require_the_bootstrap_admission_and_actual_rename_error() {
        let d = rt("epoch168-retry3-rebook-20261123-v1");
        let f = doc(
            &d.join("RELEASED_NODE_STARTUP_FAILURE_20261123.json"),
            Some(RETRY3_FAILURE),
        )
        .unwrap()
        .0;
        let a = bound(
            &f["receipts"]["ACTUAL_ADMISSION_AND_PROTECTION.json"],
            &d.join("ACTUAL_ADMISSION_AND_PROTECTION.json"),
        )
        .unwrap();
        assert!(validate_exdev(&f, &a).is_ok());
        for k in [
            "permit_consumed",
            "bootstrap_admission",
            "worker_receipt_absent",
        ] {
            let mut bad = f.clone();
            bad[k] = json!(false);
            assert!(validate_exdev(&bad, &a).is_err());
        }
        for changed in [json!(false), json!(1)] {
            let mut bad = f.clone();
            bad["r2_mutations"] = changed;
            assert!(validate_exdev(&bad, &a).is_err());
        }
        let mut bad = f.clone();
        bad["node_error"] = json!("other");
        assert!(validate_exdev(&bad, &a).is_err());
        let mut wrong = a;
        wrong["transaction_replay_claimed"] = json!(true);
        assert!(validate_exdev(&f, &wrong).is_err());
    }
    #[cfg(epoch168_cold_retry4)]
    #[test]
    fn directory_id_distinguishes_bind_mounts_on_one_filesystem() {
        let proc = Path::new("/proc");
        let irq = Path::new("/proc/irq");
        // Some systemd versions protect individual proc subtrees with read-only binds.
        // /sys and /proc always provide independent real mounts with distinct IDs.
        assert_ne!(
            mount_id(proc).unwrap(),
            mount_id(Path::new("/sys")).unwrap()
        );
        assert_eq!(
            mount_id(proc).unwrap(),
            mount_id(Path::new("/proc/.")).unwrap()
        );
        if fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|l| l.split_whitespace().nth(4) == Some("/proc/irq"))
        {
            assert_eq!(
                proc.metadata().unwrap().dev(),
                irq.metadata().unwrap().dev()
            );
            assert_ne!(mount_id(proc).unwrap(), mount_id(irq).unwrap());
        }
    }
    #[test]
    fn real_original_and_successor_paths_match() {
        let p = profile().unwrap();
        let payload = &p["payload"];
        let argv = p["producer_argv"].as_array().unwrap();
        let start = argv.iter().position(|a| a == "/usr/bin/python3").unwrap();
        assert_eq!(
            &argv[start + 3..],
            payload["regular_node_argv"].as_array().unwrap()
        );
        assert_eq!(p["readonly_projections"].as_array().unwrap().len(), 11);
        assert_eq!(payload["bootstrap"]["generation"], 1634787413893700u64);
        assert_eq!(
            payload["root_checkpoint"]["accounts_hash"],
            "AgJkU9ZTLnhbCHK54yWFCG4N9sxbtLPRgkCZqwpdWF9R"
        );
        #[cfg(not(epoch168_cold_retry4))]
        assert!(argv.contains(&json!(format!(
            "--property=ReadWritePaths={} {}",
            output().display(),
            run().join("private").display()
        ))));
        #[cfg(epoch168_cold_retry4)]
        for key in ["ReadWritePaths", "ExecPaths", "NoExecPaths"] {
            assert!(argv.contains(&json!(format!("--property={key}="))));
            assert!(!argv.iter().any(|v| v.as_str().is_some_and(|x| {
                x.starts_with(&format!("--property={key}=")) && !x.ends_with('=')
            })));
        }
        let roots = files().unwrap();
        assert_eq!(roots["root"]["inode"], RUN_INO);
        #[cfg(epoch168_cold_retry5)]
        {
            assert_eq!(payload["whole_root_cap"], 512u64 << 30);
            assert_eq!(
                roots["retry4_root_physical_stop"]["producer_invocation_id"],
                "913443d7f9f44d7e9d3e0eec420acfab"
            );
            assert_eq!(
                roots["retry4_root_physical_stop"]["reservation_ending_bytes"],
                0
            );
            assert_eq!(
                roots["predecessor_stop"]["sha256"],
                "1fba7a686be4387737b8c7776a5ed92a59bff82c15ced77496e9214c94710f62"
            );
        }
        for (key, val) in [
            ("epoch", json!(167)),
            ("producer_unit", json!(UNIT)),
            ("range", json!([0, 432_000])),
        ] {
            let mut bad = original_payload().unwrap();
            bad[key] = val;
            assert!(translate_payload(bad).is_err());
        }
    }
    #[cfg(epoch168_cold_retry5)]
    #[test]
    fn retry5_price_keeps_the_retained_stop_and_outside_allowance() {
        let (mut price, _) = doc(
            &rt("epoch168-retry5-rebook-20261125-v1/RETRY5_INCREMENTAL_REVIEW_NATIVE.json"),
            None,
        )
        .unwrap();
        let peers = peer_identity(&price).unwrap();
        assert_eq!(peers.as_object().unwrap().len(), 2);
        let stop = price["stopped_cold168"]["terminal"].clone();
        let physical = n(&price["stopped_cold168"], "measured_physical_bytes").unwrap();
        let remaining = CAP - physical;
        let base_home = n(&price["epoch159_donor_cover"], "native_home_required").unwrap();
        let floor = base_home + (8 << 30);
        let required = floor + remaining;
        let source =
            json!({"sha256":"488dbd9e630511b97a0ad0704241a0a1fdec71a614caf17c6cd1d3a63b3dc0b2"});
        price["epoch"] = json!(EPOCH);
        price["protected_raw_floor_bytes"] = json!(floor);
        price["complete_required_HOME_bytes"] = json!(required);
        price["available_HOME_bytes"] = json!(required + 12);
        price["retry5_retained_source"] = source.clone();
        price["bookings"]["168"] = json!({
            "root": LANE, "run": run(), "cap_bytes": CAP, "physical_bytes": physical,
            "remaining_bytes": remaining
        });
        price["retry5_complete_booking"] = json!({
            "schema":"horizon-168-retry5-complete-booking-v1", "funded":true,
            "prior_stop": stop, "retained_source": source,
            "previous_producer_physical_charge_bytes": physical,
            "producer_cpu_quota_micros":9_000_000, "producer_memory_bytes":68u64 << 30,
            "guard_cpu_quota_micros":250_000, "guard_memory_bytes":1u64 << 30,
            "producer_swap_bytes":0, "guard_swap_bytes":0,
            "retained_base_HOME_bytes":base_home, "protected_raw_floor_bytes":floor,
            "complete_required_HOME_bytes":required, "candidate_remaining_bytes":remaining,
            "outside_cap_stop_allowance_bytes":8u64 << 30
        });
        assert_eq!(funded_guard_floor(&price).unwrap(), floor + 12);
        for (key, replacement) in [
            ("outside_cap_stop_allowance_bytes", json!(0)),
            ("guard_cpu_quota_micros", json!(0)),
            (
                "previous_producer_physical_charge_bytes",
                json!(physical - 1),
            ),
            ("prior_stop", json!({})),
        ] {
            let mut bad = price.clone();
            bad["retry5_complete_booking"][key] = replacement;
            assert!(funded_guard_floor(&bad).is_err(), "{key}");
        }
        price["replacements"]["170"] = price["replacements"]["167"].clone();
        assert!(peer_identity(&price).is_err());
        price["available_HOME_bytes"] = json!(required - 1);
        assert!(funded_guard_floor(&price).is_err());
    }

    #[cfg(not(epoch168_cold_retry5))]
    #[test]
    fn actual_three_peer_price_and_caps() {
        let p = rt(
            "incident-replay-fit-20261121-v1/homefloor-qualification/cold168-retry2-firstscreen-20261122/price.stdout",
        );
        let (mut price, _) = doc(&p, None).unwrap();
        let own = peer_identity(&price).unwrap();
        assert_eq!(own.as_object().unwrap().len(), 3);
        let need = n(&price, "complete_required_HOME_bytes").unwrap();
        let floor = n(&price, "protected_raw_floor_bytes").unwrap();
        price["available_HOME_bytes"] = json!(need);
        assert_eq!(funded_guard_floor(&price).unwrap(), floor);
        price["available_HOME_bytes"] = json!(need - 1);
        assert!(funded_guard_floor(&price).is_err());
        price["available_HOME_bytes"] = json!(need + 12);
        assert_eq!(funded_guard_floor(&price).unwrap(), floor + 12);
        for k in ["167", "170"] {
            let mut bad = price.clone();
            bad["replacements"].as_object_mut().unwrap().remove(k);
            assert!(peer_identity(&bad).is_err());
        }
        price["startup_nonexact_peer_floor"]["funded"] = json!(false);
        assert!(funded_guard_floor(&price).is_err());
    }
}

/// Require the sole writer qualified against this prepared lane.
#[cfg(not(epoch168_cold_retry5))]
pub fn status_receiver(price: &Value, prepared: &Value) -> Result<Value> {
    let d = rt("survivor172-cadence-20261122-v1");
    let (q, qr) = doc(&d.join(STATUS_QUALIFIED), None)?;
    let (a, ar) = doc(&d.join(STATUS_ACTIVE), None)?;
    let (_, rr) = doc(&base().join("SUCCESSOR_ROOT.json"), Some(ROOT))?;
    let (_, gr) = doc(
        &rt(GUARD_BASE).join("GUARD_QUALIFIED.json"),
        Some(GUARD_QUALIFIED),
    )?;
    #[cfg(all(epoch168_cold_retry3, not(epoch168_cold_retry4)))]
    {
        let (_, failure_ref) = doc(
            &rt("epoch168-retry2-rebook-20261122-v1/RELEASED_NODE_STARTUP_FAILURE_20261123.json"),
            Some("a3353dfdbcf5de9320f22229134c9bdcaa70abb40aca0e85dd1ad315c4740643"),
        )?;
        ensure!(
            q["failed_retry2"] == failure_ref
                && a["schema"] == "horizon-168-retry3-v1-status-active-v1",
            "different retry3 registration"
        );
    }
    #[cfg(epoch168_cold_retry4)]
    {
        let (_, failure_ref) = doc(
            &rt("epoch168-retry3-rebook-20261123-v1/RELEASED_NODE_STARTUP_FAILURE_20261123.json"),
            Some(RETRY3_FAILURE),
        )?;
        ensure!(
            q["failed_retry3"] == failure_ref
                && a["schema"] == "horizon-168-retry4-v1-status-active-v1",
            "different retry4 writer enrollment"
        );
    }
    let reg = &price["status_registration"];
    let actor = &a["new"];
    ensure!(
        q["schema"] == STATUS_SCHEMA
            && q["epoch"] == 168
            && q["prepared"] == *prepared
            && q["successor_root"] == rr
            && q["guard"] == gr
            && !q["generation"].is_null()
            && q["generation"] == a["generation"]
            && q["package"] == reg["consumer_seal"]
            && a["qualified"] == qr
            && hex(st(&q, "source_commit")?, 40)
            && q["suites"].as_object().is_some_and(|s| !s.is_empty()),
        "unregistered 168 status receiver"
    );
    let seal_path = Path::new(st(&q["package"], "path")?);
    let pkg = seal_path.parent().context("receiver package")?;
    ensure!(
        pkg.parent() == Some(d.as_path())
            && seal_path == pkg.join("deployment-seal-receipt.json")
            && actor["program"] == json!(pkg.join("status_cycle.py")),
        "foreign 168 status package"
    );
    let entry = pkg.join("status_cycle.py");
    ensure!(
        q["entry"]["path"] == json!(entry) && st(&q["entry"], "sha256")? == file_digest(&entry)?,
        "different qualified status program"
    );
    member(&entry, st(&q["package"], "sha256")?)?;
    receiver_lock(actor, reg)?;
    Ok(json!({"qualified":qr,"active":ar,"registration":reg}))
}

#[cfg(epoch168_cold_retry5)]
pub fn status_receiver(price: &Value, prepared: &Value) -> Result<Value> {
    const SEAL: &str = "6899ee7708ca74e9bf2a04cb932ce2fc75dff18e16866149b1dbeea3887496ac";
    let status = rt("survivor172-cadence-20261122-v1");
    let package = status.join("tools-cold168-retry5-failed166-v12-entry146");
    let entry = package.join("status_cycle.py");
    let seal = member(&entry, SEAL)?;
    let marker = package.join("retry5-168-generation.json");
    ensure!(
        member(&marker, SEAL)? == seal,
        "different retry5 generation seal"
    );
    let (generation, generation_ref) = doc(&marker, None)?;
    let (ready, ready_ref) = doc(&status.join(STATUS_QUALIFIED), None)?;
    let (active, active_ref) = doc(&status.join(STATUS_ACTIVE), None)?;
    let previous = bound(
        &ready["old_owner"],
        &status.join("FAILED166_CADENCE_V11_ACTIVE.json"),
    )?;
    let fleet = bound(&ready["fleet"], Path::new(st(&ready["fleet"], "path")?))?;
    let (_, root_ref) = doc(&base().join("SUCCESSOR_ROOT.json"), Some(ROOT))?;
    let (_, guard_ref) = doc(
        &rt(GUARD_BASE).join("GUARD_QUALIFIED.json"),
        Some(GUARD_QUALIFIED),
    )?;
    let registration = &price["status_registration"];
    let actor = &active["new"];
    let lock = &actor["lock"];
    let old = &previous["new"];
    ensure!(
        ready["schema"] == STATUS_SCHEMA
            && ready["package"] == seal
            && registration["consumer_seal"] == seal
            && ready["retry5_generation"] == generation_ref
            && generation["prepared"] == *prepared
            && generation["successor_root"] == root_ref
            && generation["guard_qualification"] == guard_ref
            && generation["retained_source"] == price["retry5_retained_source"]
            && ready["retained_retry4_stop"] == price["stopped_cold168"]["terminal"]
            && ready["config"] == fleet["sole_next_observer"]
            && ready["timer"] == fleet["sole_next_timer"]
            && active["schema"] == "horizon-epoch166-cadence-rejoin-active-v1"
            && active["ready"] == ready_ref
            && active["producer_mutations"] == false
            && active["old"] == *old
            && actor["program"] == json!(entry)
            && actor["invocation_id"] != old["invocation_id"]
            && n(actor, "start_ticks")? > n(old, "start_ticks")?
            && ["path", "device", "inode"]
                .iter()
                .all(|k| lock[*k] == old["lock"][*k]),
        "unregistered retry5 status receiver or cadence handoff"
    );
    receiver_lock(actor, registration)?;
    Ok(json!({"qualified":ready_ref,"active":active_ref,"registration":registration}))
}

fn receiver_lock(actor: &Value, registration: &Value) -> Result<()> {
    ensure!(
        actor["unit"] == "horizon-archive-status-cadence-after172-20261120-v1.service"
            && actor["invocation_id"] == registration["invocation_id"]
            && actor["pid"] == registration["pid"]
            && actor["start_ticks"] == registration["start_ticks"],
        "unregistered 168 status receiver"
    );
    let ctl = native(st(actor, "unit")?)?;
    let pid = n(actor, "pid")?;
    let (_, ticks, group) = proc_row(pid)?;
    ensure!(
        ctl["InvocationID"] == actor["invocation_id"]
            && st(&ctl, "MainPID")?.parse::<u64>()? == pid
            && ctl["ActiveState"] == "active"
            && ctl["NRestarts"] == "0"
            && ticks == n(actor, "start_ticks")?
            && group == format!("0::/system.slice/{}", st(actor, "unit")?),
        "changed 168 status owner"
    );
    let lock = &actor["lock"];
    let original = rt("stable-cadence-controller-20261120-v1/consumer.lock");
    let holder = PathBuf::from(format!("/proc/{pid}/fd/{}", n(lock, "fd")?));
    let m = original.symlink_metadata()?;
    ensure!(
        lock["path"] == json!(original)
            && (m.dev(), m.ino()) == (n(lock, "device")?, n(lock, "inode")?)
            && same(&holder, &original)?,
        "foreign 168 receiver lock"
    );
    let fdinfo = fs::read_to_string(format!("/proc/{pid}/fdinfo/{}", n(lock, "fd")?))?;
    ensure!(
        fdinfo.lines().any(|line| {
            let v: Vec<_> = line.split_whitespace().collect();
            v.len() >= 9
                && v[0] == "lock:"
                && v[2] == "FLOCK"
                && v[4] == "WRITE"
                && v[5] == pid.to_string()
                && v[6].ends_with(&format!(":{}", m.ino()))
        }),
        "status receiver lacks original exclusive lock"
    );
    Ok(())
}

pub fn inventory_record(v: &Value) -> Result<Value> {
    let key = sha(&bytes(v)?);
    record_once(&format!("INVENTORY_PRESTART_{key}.json"), v)
}
