//! Generate the successor from the originally admitted metered epoch 168 payload.
use super::*;

pub const EPOCH: u64 = 168;
pub const LANE: &str = "/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1";
pub const ATTEMPT: &str = "full-metered-20261121-v1/cold-retry2-20261122";
pub const BASE: &str = "epoch168-retry2-rebook-20261122-v1";
pub const OLD: &str = "epoch168-full-metered-20261121-v1";
pub const UNIT: &str = "horizon-qualify-168-full-metered-cold-v2-20261122.service";
pub const TIMER: &str = "horizon-guard-168-full-metered-cold-v2-20261122.timer";
pub const CAP: u64 = 288 << 30;
pub const GUARD_SHA: &str = "22cc2f4f49ecd236d1b7c177bc4d2df0a96ebec5c6ef591905ff6ca6ab9e7770";
pub const GSEAL: &str = "160ffc208db19b9fa23112c028cd9cb80853f10c8abc8f484cb0935adc51a1d2";
pub const CONTRACT: &str = "f10342c06a7b501b503f6046c56a345880c785c2a5d17f03ab43c4b30526d088";
pub const CSEAL: &str = "e68fec195ca0f5708ea98fc3013e7080c7a91b8e454f1c79bca51d0c29b14609";
pub const WITNESS: &str = "7373df4366d2c4ea1fd14cfa063f56fb66ff1fb7997fc6e9245c345fbf3fb217";
pub const PREVIOUS_GUARD_ARGV: &str =
    "1b81a271d53f52ea34ead452d578f68326ba9f51b61ddbaa154f7277cfa441bf";
pub const OLD_UNIT: &str = "horizon-qualify-168-full-metered-20261121-v1.service";
pub const GUARD_BASE: &str = "epoch168-cold-guard-20261122-v2";
const ORIGINAL_ARGV: &str = "39d2e97f8f6962984f1ec9672a4701fe0772e3a63a72465b8d945d59eab7b4fa";
const PAYLOAD: &str = "6c56c0cad87c9d22ca72ad8e2cf97cb0cc0c5e1b4d1d01e4f051dfc01875b240";
const INPUT_SEAL: &str = "e00db5e753a2cc37af403933f54bcb3216594d1fac3d91cc8984623999295a93";
const ROOT: &str = "ec909d6701ce7dcbee72da319bf0179ba375e1cf6e284aa29686e1dd0a3cbecc";
const ALIAS: &str = "/run/horizon-full168-cold-v2";
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
            "--description=guarded-full168-cold-retry2".to_owned()
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
    for (key, path, ino) in [
        ("root", run(), 103481350),
        ("output", output(), 103481354),
        ("private", run().join("private"), 103481352),
    ] {
        let m = path.symlink_metadata()?;
        let row = if key == "root" { &root } else { &root[key] };
        ensure!(
            path.canonicalize()? == path
                && m.is_dir()
                && (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())
                    == (64512, ino, 1001, 1003, 0o40700)
                && n(row, "inode")? == ino,
            "changed 168 {key}"
        );
    }
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
    let profile = profile()?;
    retained_inputs(&profile["payload"], false)?;
    Ok(
        json!({"root":{"path":run(),"device":64512,"inode":103481350},"stable_roots":rootref,"predecessor_stop":root["prior_stop"],"profile":profile}),
    )
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
                == (64512, 103481356, 1, 0o600, 0)
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
        std::env::current_exe()? == base().join("tools/recover168"),
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
    record(
        "PREPARED.json",
        &json!({"schema":"horizon-168-replay-recovery-preparation-v1","epoch":EPOCH,
        "baseline":clean,"profile":profile,"payload":payload,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,
        "original_run_retained":true,"replay_launch_authorized":false}),
    )
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
    let (prep, r) = doc(&base().join("PREPARED.json"), None)?;
    let m = logfile()?.metadata()?;
    ensure!(
        (m.uid(), m.gid()) == (0, 0)
            && prep["baseline"] == files()?
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
pub fn index_selected() -> Result<()> {
    let m = native(UNIT)?;
    let pid = st(&m, "MainPID")?.parse::<u64>()?;
    ensure!(pid > 1, "no 168 native gate");
    let root = Path::new("/proc").join(pid.to_string());
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
            matches!(k.as_str(), "166" | "167" | "170")
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
        ids.get("167").is_some() && ids.get("170").is_some(),
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
        assert!(argv.contains(&json!(format!(
            "--property=ReadWritePaths={} {}",
            output().display(),
            run().join("private").display()
        ))));
        assert_eq!(files().unwrap()["root"]["inode"], 103481350);
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
pub fn status_receiver(price: &Value, prepared: &Value) -> Result<Value> {
    let d = rt("survivor172-cadence-20261122-v1");
    let (q, qr) = doc(&d.join("COLD168_RETRY2_V1_STATUS_QUALIFIED.json"), None)?;
    let (a, ar) = doc(&d.join("COLD168_RETRY2_V1_STATUS_ACTIVE.json"), None)?;
    let (_, rr) = doc(&base().join("SUCCESSOR_ROOT.json"), Some(ROOT))?;
    let (_, gr) = doc(
        &rt(GUARD_BASE).join("GUARD_QUALIFIED.json"),
        Some("bab2140873334dfbab487be91cf044a31a000cbdec525075fe1ea4a086198e2b"),
    )?;
    let reg = &price["status_registration"];
    let actor = &a["new"];
    ensure!(
        q["prepared"] == *prepared
            && q["successor_root"] == rr
            && q["guard"] == gr
            && !q["generation"].is_null()
            && q["generation"] == a["generation"]
            && q["package"] == q["entry"]
            && q["package"] == reg["consumer_seal"]
            && a["qualified"] == qr
            && hex(st(&q, "source_commit")?, 40)
            && q["suites"].as_object().is_some_and(|s| !s.is_empty())
            && actor["unit"] == "horizon-archive-status-cadence-after172-20261120-v1.service"
            && actor["invocation_id"] == reg["invocation_id"]
            && actor["pid"] == reg["pid"]
            && actor["start_ticks"] == reg["start_ticks"],
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
    member(&pkg.join("status_cycle.py"), st(&q["package"], "sha256")?)?;
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
    Ok(json!({"qualified":qr,"active":ar,"registration":reg}))
}

pub fn inventory_record(v: &Value) -> Result<Value> {
    let key = sha(&bytes(v)?);
    record_once(&format!("INVENTORY_PRESTART_{key}.json"), v)
}
