use super::*;
use serde_json::Map;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;

const GOOD: &str = "7ad2d189f7e94e70a38c781354912448";
const FAILED: &str = "d9b373ed55a64feb8242e02dbe79a49c";
const GROUP: &str = "/system.slice/horizon-retained-publish-168-20261128-v1.service";

fn state() -> Result<Value> {
    let out=Command::new("/usr/bin/systemctl").args(["show","--all","-p",
        "Id,ActiveState,SubState,Job,InvocationID,MainPID,ControlPID,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,Result,NRestarts",UNIT]).output()?;
    ensure!(
        matches!(out.status.code(), Some(0 | 4)),
        "systemd unavailable"
    );
    let mut d = Map::new();
    for l in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = l.split_once('=').context("manager state")?;
        d.insert(k.into(), json!(v));
    }
    let d = Value::Object(d);
    ensure!(d["Id"] == UNIT, "different systemd unit");
    Ok(d)
}
fn latest(prefix: &str) -> Result<Option<Bound>> {
    private_directory(&data())?;
    let mut paths = Vec::new();
    for entry in fs::read_dir(data())? {
        let path = entry?.path();
        let n = path
            .file_name()
            .and_then(|v| v.to_str())
            .context("state name")?;
        if let Some(stamp) = n.strip_prefix(prefix).and_then(|s| s.strip_suffix(".json")) {
            ensure!(
                stamp.len() == 19 && stamp.bytes().all(|b| b.is_ascii_digit()),
                "malformed {prefix} receipt"
            );
            paths.push(path);
        }
    }
    paths.sort();
    paths.last().map(|p| bound(p)).transpose()
}
fn valid_iid(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn terminal(iid: &str, boot: &str) -> Result<Value> {
    ensure!(valid_iid(iid) && valid_iid(boot), "bad native invocation");
    let output = command(&[
        "/usr/bin/journalctl",
        "-q",
        "--no-pager",
        "-o",
        "json",
        "_UID=0",
        "_PID=1",
        &format!("UNIT={UNIT}"),
        &format!("_BOOT_ID={boot}"),
        &format!("INVOCATION_ID={iid}"),
        &format!("MESSAGE_ID={GOOD}"),
        &format!("MESSAGE_ID={FAILED}"),
        "MESSAGE_ID=be02cf6855d2428ba40df7e9d022f03d",
    ])?;
    let events: Vec<Value> = output
        .lines()
        .map(serde_json::from_str)
        .collect::<serde_json::Result<_>>()?;
    ensure!(
        events.len() == 1 && events[0]["INVOCATION_ID"] == iid && events[0]["_BOOT_ID"] == boot,
        "no unique 168 terminal event"
    );
    let e = &events[0];
    Ok(
        json!({"invocation":iid,"boot":boot,"id":e["MESSAGE_ID"],"cursor":e["__CURSOR"],"time":e["__REALTIME_TIMESTAMP"]}),
    )
}
fn active_limits(st: &Value) -> Result<u32> {
    let pid = string(st, "MainPID")?.parse::<u32>()?;
    ensure!(
        st["ControlGroup"] == GROUP
            && st["MemoryMax"] == MEMORY.to_string()
            && st["MemorySwapMax"] == "0"
            && st["CPUQuotaPerSecUSec"] == "2s"
            && st["NRestarts"] == "0"
            && pid > 1,
        "publisher kernel limits changed"
    );
    let dir = Path::new("/sys/fs/cgroup").join(GROUP.trim_start_matches('/'));
    let file = |n| -> Result<String> { Ok(fs::read_to_string(dir.join(n))?.trim().into()) };
    let quota = file("cpu.max")?;
    let values: Vec<_> = quota.split_whitespace().collect();
    ensure!(
        values.len() == 2
            && values[0].parse::<u64>()? * 1_000_000 == CPU * values[1].parse::<u64>()?
            && file("memory.max")? == MEMORY.to_string()
            && file("memory.swap.max")? == "0"
            && file("cgroup.procs")?.lines().any(|s| s == pid.to_string()),
        "publisher process/cgroup disagreement"
    );
    Ok(pid)
}
pub(super) fn owner() -> Result<Value> {
    let st = state()?;
    let latest_actor = latest("ACTOR-")?;
    let latest_attempt = latest("ATTEMPT-")?;
    if matches!(
        st["ActiveState"].as_str(),
        Some("active" | "activating" | "deactivating")
    ) || st["Job"] != ""
    {
        ensure!(
            !data().join("CLOSED.json").try_exists()?,
            "publisher present after closure"
        );
        let ar = latest_attempt.context("unbooked publisher unit")?;
        let ad = ar.json()?;
        ensure!(
            ad["unit"] == UNIT && ad["operator"] == serde_json::to_value(own_seal()?)?,
            "different admitted unit"
        );
        if st["MainPID"] == "0" {
            return Ok(json!({"phase":"transition","attempt":ar,"native":st}));
        }
        let pid = active_limits(&st)?;
        let exc = fs::metadata(format!("/proc/{pid}/exe"))?;
        let cmd = fs::read(format!("/proc/{pid}/cmdline"))?;
        let got: Vec<&[u8]> = cmd
            .strip_suffix(b"\0")
            .unwrap_or(&cmd)
            .split(|b| *b == 0)
            .collect();
        let uploader =
            Path::new(RT).join("epoch168-current-anza-reader-20261127-v1/jetstreamer-r2");
        let op = root().join(TOOLS).join(BINARY);
        let same = |p: &Path| -> Result<bool> {
            let m = fs::metadata(p)?;
            Ok((m.dev(), m.ino()) == (exc.dev(), exc.ino()))
        };
        if same(&op)? {
            ensure!(
                got == [
                    op.as_os_str().as_encoded_bytes(),
                    b"enter",
                    ar.path.as_os_str().as_encoded_bytes(),
                    ar.sha256.as_bytes()
                ],
                "different gate invocation"
            );
            return Ok(json!({"phase":"starting","attempt":ar,"native":st}));
        }
        let act = latest_actor.context("unbound native uploader")?;
        let m = act.json()?;
        let expected = ad["arguments"]
            .as_array()
            .context("native argv")?
            .iter()
            .map(|v| v.as_str().context("non-string argument"))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            same(&uploader)?
                && got == expected.iter().map(|v| v.as_bytes()).collect::<Vec<_>>()
                && m["attempt"] == serde_json::to_value(&ar)?
                && m["invocation"] == st["InvocationID"]
                && m["pid"] == pid
                && m["boot"] == boot()?,
            "different live upload or attempt"
        );
        return Ok(json!({"phase":"running","attempt":ar,"actor":act,"native":st}));
    }
    ensure!(
        matches!(st["ActiveState"].as_str(), Some("inactive" | "failed"))
            && st["MainPID"] == "0"
            && st["ControlPID"] == "0"
            && st["Job"] == ""
            && st["ControlGroup"] == ""
            && !Path::new("/sys/fs/cgroup")
                .join(GROUP.trim_start_matches('/'))
                .exists(),
        "publisher has not drained"
    );
    if data().join("CLOSED.json").try_exists()? {
        let close = bound(&data().join("CLOSED.json"))?;
        let result = close.json()?;
        ensure!(
            result["schema"] == "horizon-168-native-publication-close-v1"
                && result["archive_sha256"] == ARCHIVE_SHA
                && result["event"]["id"] == GOOD
                && result["unit"] == UNIT
                && result["actor"] == serde_json::to_value(&latest_actor)?
                && result["verified_native_ready_pair"] == true,
            "different 168 release"
        );
        return Ok(json!({"phase":"closed","closure":close,"credit":0}));
    }
    if let Some(ar) = latest_actor {
        let d = ar.json()?;
        let event = terminal(string(&d, "invocation")?, string(&d, "boot")?)?;
        let phase = if event["id"] == GOOD {
            "awaiting_verified_receipt"
        } else {
            "failed_drained"
        };
        return Ok(json!({"phase":phase,"actor":ar,"attempt":d["attempt"],"event":event}));
    }
    Ok(json!({"phase":"reserved","latest_admission":latest_attempt}))
}

fn can_admit(phase: &Value) -> bool {
    matches!(phase.as_str(), Some("reserved" | "failed_drained"))
}

fn inventory_arguments(inv: &Value) -> Result<Vec<String>> {
    ensure!(
        inv["schema"] == "jetstreamer-horizon-r2-inventory-v1"
            && inv["first_epoch"] == 168
            && inv["last_epoch"] == 168
            && inv["requested_epochs"] == 1
            && inv["ready_pairs"] == 0
            && inv["anomalies"] == 0
            && inv["entries"].as_array().is_some_and(|e| e.len() == 1)
            && inv["entries"][0]["epoch"] == 168,
        "inventory is not a clean singleton"
    );
    let e = &inv["entries"][0];
    match string(e, "state")? {
        "missing"
            if inv["missing"] == 1
                && inv["archive_only"] == 0
                && e["archive_etag"].is_null()
                && e["archive_length"].is_null() =>
        {
            Ok(vec![])
        }
        "archive-only"
            if inv["missing"] == 0
                && inv["archive_only"] == 1
                && e["archive_length"] == LENGTH
                && e["sidecar_sha256"].is_null() =>
        {
            let tag = string(e, "archive_etag")?;
            ensure!(
                !tag.is_empty()
                    && !tag.starts_with("W/")
                    && tag.len() < 256
                    && tag.bytes().all(|b| b.is_ascii_graphic()),
                "strong archive ETag missing"
            );
            ensure!(
                e["archive_metadata_sha256"].is_null()
                    || e["archive_metadata_sha256"] == ARCHIVE_SHA,
                "staged SHA differs"
            );
            Ok(vec![
                "--staged-archive-etag".into(),
                tag.into(),
                "--staged-archive-bytes".into(),
                LENGTH.to_string(),
            ])
        }
        _ => bail!("168 inventory cannot enter ordinary conditional publication"),
    }
}
fn valid_attempt(a: &Bound) -> Result<Value> {
    ensure!(
        a.path.parent() == Some(data().as_path()) && latest("ATTEMPT-")?.as_ref() == Some(a),
        "superseded admission"
    );
    let d = a.json()?;
    ensure!(
        d["unit"] == UNIT
            && d["schema"] == "horizon-168-native-publication-attempt-v1"
            && d["operator"] == serde_json::to_value(own_seal()?)?
            && d["boot"] == boot()?,
        "changed admission"
    );
    Ok(d)
}
fn systemd_args(attempt: &Bound, sock: &Path, repo: &str) -> Vec<String> {
    let dir = root();
    let ad = data();
    let bin = dir.join(TOOLS).join(BINARY);
    let mut v = vec![
        "/usr/bin/systemd-run".into(),
        "--quiet".into(),
        "--service-type=exec".into(),
        format!("--unit={UNIT}"),
        "--slice=system.slice".into(),
    ];
    for p in [
        "User=root",
        "Group=root",
        "CPUQuota=200%",
        "CPUWeight=10",
        "Nice=15",
        "MemoryMax=8G",
        "MemorySwapMax=0",
        "TasksMax=128",
        "LimitCORE=0",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "Restart=no",
        "UMask=0077",
        "StandardOutput=journal",
        "StandardError=journal",
        "EnvironmentFile=/etc/jetstreamer/horizon-r2.env",
    ] {
        v.push(format!("--property={p}"));
    }
    v.push(format!(
        "--property=ReadWritePaths={} {} {} {}",
        dir.join("publication-scratch").display(),
        dir.join("publication-receipts").display(),
        ad.display(),
        repo
    ));
    v.extend([
        format!("--setenv=SSH_AUTH_SOCK={}", sock.display()),
        "--setenv=RAYON_NUM_THREADS=2".into(),
        "--setenv=TOKIO_WORKER_THREADS=2".into(),
        "--setenv=RUST_MIN_STACK=67108864".into(),
        "--".into(),
        bin.display().to_string(),
        "enter".into(),
        attempt.path.display().to_string(),
        attempt.sha256.clone(),
    ]);
    v
}
pub(super) fn admit(p: &Bound, inventory: &Bound, socket: &Path) -> Result<Value> {
    let _guard = lock()?;
    let inputs = scope()?;
    let seal = own_seal()?;
    let dir = root();
    let im = socket.symlink_metadata()?;
    ensure!(
        socket.canonicalize()? == socket && im.file_type().is_socket() && im.uid() == 1001,
        "Anza repository owner's SSH agent required"
    );
    ensure!(
        inventory.path.parent() == Some(&dir)
            && inventory
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("R2_FRESH_")),
        "use root's singleton inventory"
    );
    let extra = inventory_arguments(&inventory.json()?)?;
    let q = price::quote(p)?;
    let owner = &q["whole_roster"]["publication168_allocation"]["owner"];
    ensure!(
        can_admit(&owner["phase"]) && q["fits"] == true,
        "owner or complete fresh 168 fit refused: {} ram {} HOME {}",
        owner["phase"],
        q["ram_margin"],
        q["home_margin"]
    );
    let stamp = nanos()?;
    let mut plan = inputs["plan_before_root_prices_minimum_free_bytes"].clone();
    plan["minimum_free_bytes"] = q["minimum_free_bytes"].clone();
    let first = dir.join("plan.json");
    let plan_ref = if first.try_exists()? {
        let prior = bound(&first)?;
        if prior.json()? == plan {
            prior
        } else {
            write_once(&data().join(format!("PLAN-{stamp}.json")), &plan)?
        }
    } else {
        write_once(&first, &plan)?
    };
    let mut base = inputs["canonical_first_upload_argv"]
        .as_array()
        .context("uploader arguments")?
        .iter()
        .map(|s| s.as_str().map(String::from).context("uploader arg"))
        .collect::<Result<Vec<_>>>()?;
    let idx = base
        .iter()
        .position(|v| v == "--current-reader-plan")
        .context("no plan")?;
    let hash = base
        .iter()
        .position(|v| v == "--current-reader-plan-sha256")
        .context("no plan digest")?;
    base[idx + 1] = plan_ref.path.display().to_string();
    base[hash + 1] = plan_ref.sha256.clone();
    base.extend(extra);
    let quote = write_once(&data().join(format!("QUOTE-{stamp}.json")), &q)?;
    let ad = write_once(
        &data().join(format!("ATTEMPT-{stamp}.json")),
        &json!({"schema":"horizon-168-native-publication-attempt-v1","unit":UNIT,
        "operator":seal,"provider":p,"quote":quote,"inventory":inventory,"plan":plan_ref,"arguments":base,
        "boot":boot()?,"recorded_unix_ns":stamp,"minimum_free_bytes":q["minimum_free_bytes"],"required_ram":q["required_ram"],
        "workspace_sha256":WORKSPACE,"private_reconciliation_sha256":RECONCILED,"local_pair_sha256":PAIR}),
    )?;
    Ok(
        json!({"attempt":ad,"plan":plan_ref,"quote":quote,"root_dispatch_argv":systemd_args(&ad,socket,string(&plan,"repository")?),"starts_publication":false}),
    )
}
pub(super) fn enter(a: &Bound) -> Result<Value> {
    let guard = lock()?;
    let ad = valid_attempt(a)?;
    let s = state()?;
    let pid = active_limits(&s)?;
    ensure!(
        std::env::var("INVOCATION_ID")? == s["InvocationID"]
            && valid_iid(string(&s, "InvocationID")?)
            && pid == std::process::id()
            && fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::{GROUP}"),
        "only the bound systemd entry may execute"
    );
    ensure!(
        !data().join("CLOSED.json").try_exists()?
            && latest("ACTOR-")?
                .map(|v| v.json())
                .transpose()?
                .is_none_or(|v| v["attempt"] != serde_json::to_value(a).unwrap_or(Value::Null)),
        "spent admission"
    );
    let original = reference(&ad, "quote")?.json()?;
    let (disk, ram) = actual()?;
    ensure!(
        original["fits"] == true
            && disk >= num(&ad, "minimum_free_bytes")?
            && ram >= num(&ad, "required_ram")?,
        "entry no longer fits"
    );
    let last = original["whole_roster"]["recorded_unix_seconds"]
        .as_f64()
        .context("quote time")?;
    ensure!(
        (0.0..=240.0).contains(&(nanos()? as f64 / 1e9 - last)),
        "refresh admission before starting"
    );
    let inputs = scope()?;
    let u = reference(&inputs, "uploader")?;
    u.binary()?;
    let plan = reference(&ad, "plan")?.json()?;
    let mut template = inputs["plan_before_root_prices_minimum_free_bytes"].clone();
    template["minimum_free_bytes"] = ad["minimum_free_bytes"].clone();
    ensure!(plan == template, "changed publication plan");
    let inv = reference(&ad, "inventory")?;
    let _ = inventory_arguments(&inv.json()?)?;
    let args = ad["arguments"]
        .as_array()
        .context("missing arguments")?
        .iter()
        .map(|v| v.as_str().context("bad argv"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        args.first() == Some(&u.path.to_str().unwrap()) && args.get(1) == Some(&"sync"),
        "wrong uploader"
    );
    let start = write_once(
        &data().join(format!("ACTOR-{}.json", nanos()?)),
        &json!({"attempt":a,"invocation":s["InvocationID"],"pid":pid,"boot":boot()?,"unit":UNIT,"native":s,"uploader":u,"plan":ad["plan"],"entry_home":disk,"entry_ram":ram}),
    )?;
    eprintln!("epoch 168 admitted native publication {}", start.sha256);
    drop(guard);
    Err(Command::new(&args[0]).args(&args[1..]).exec().into())
}
pub(super) fn root_snapshot(binding: &Bound) -> Result<Value> {
    let (observed, doc) = read_finished(&binding.path, 64 << 20)?;
    ensure!(
        observed == *binding,
        "root snapshot changed: {}",
        binding.path.display()
    );
    Ok(doc)
}

fn read_finished(path: &Path, limit: u64) -> Result<(Bound, Value)> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && before.is_file()
            && before.uid() == 0
            && before.gid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() > 0
            && before.len() <= limit,
        "invalid completed report {} ({} bytes)",
        path.display(),
        before.len()
    );
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = vec![];
    file.read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec()
        ) == (
            after.dev(),
            after.ino(),
            bytes.len() as u64,
            after.ctime(),
            after.ctime_nsec()
        ),
        "completed report changed"
    );
    Ok((
        fixed(path, &custody::digest(&bytes)),
        serde_json::from_slice(&bytes)?,
    ))
}
pub(super) fn finish() -> Result<Value> {
    let _guard = lock()?;
    let v = owner()?;
    if v["phase"] == "closed" {
        return Ok(v);
    }
    ensure!(
        v["phase"] == "awaiting_verified_receipt" && v["event"]["id"] == GOOD,
        "publisher did not exit cleanly"
    );
    let (r, receipt) = read_finished(
        &root().join("publication-receipts/epoch-168.r2.json"),
        4 << 20,
    )?;
    let pr = reference(&receipt, "current_reader_playback")?;
    ensure!(
        pr.path.starts_with(root().join("publication-scratch")),
        "remote report outside the appointed scratch"
    );
    let (rr, report) = read_finished(&pr.path, 4 << 20)?;
    let actor: Bound = serde_json::from_value(v["actor"].clone())?;
    let start = actor.json()?;
    let attempt = reference(&start, "attempt")?.json()?;
    let local = &report["local_playback"];
    let remote = &report["remote_playback"];
    let private = fixed(Path::new(RT).join(RECON), RECONCILED).json()?;
    ensure!(
        receipt["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && receipt["epoch"] == 168
            && receipt["bucket"] == "solana-archive-with-accounts-data"
            && receipt["archive_key"] == "epoch-168.jet"
            && receipt["checksum_key"] == "epoch-168.jet.sha256"
            && receipt["archive_length"] == LENGTH
            && receipt["archive_sha256"] == ARCHIVE_SHA
            && receipt["remote_sha256_readback"] == true
            && rr == pr
            && report["epoch"] == 168
            && report["schema"] == "horizon-r2-current-reader-playback-acceptance-v1"
            && report["reader_plan"] == attempt["plan"]
            && remote["object"]["etag"] == receipt["archive_etag"]
            && remote["object"]["sha256"] == ARCHIVE_SHA
            && remote["object"]["length"] == LENGTH
            && local["process_exit_code"] == 0
            && remote["playback"]["process_exit_code"] == 0
            && local["report"]["full_epoch_verified"] == true
            && local["report"]["report"] == private["counters"]
            && local["report"]["report"] == remote["playback"]["report"]["report"],
        "incomplete or different epoch 168 ready-pair proof"
    );
    let result = json!({"schema":"horizon-168-native-publication-close-v1","unit":UNIT,"actor":actor,"event":v["event"],"attempt":start["attempt"],
        "archive_sha256":ARCHIVE_SHA,"native_receipt":r,"remote_playback":rr,"verified_native_ready_pair":true,"resource_credit_bytes":0});
    Ok(serde_json::to_value(write_once(
        &data().join("CLOSED.json"),
        &result,
    )?)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_the_authenticated_native_fleet_and_writer_permissions() {
        let fixture = tempfile::tempdir().unwrap();
        let p = fixture.path().join("root-fleet.json");
        fs::write(&p, b"{\"owner\":\"/root\"}").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let binding = fixed(&p, &custody::digest(&fs::read(&p).unwrap()));
        assert_eq!(root_snapshot(&binding).unwrap()["owner"], "/root");
        fs::write(&p, b"{}").unwrap();
        assert!(root_snapshot(&binding).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(read_finished(&p, 64 << 20).is_err());
    }

    #[test]
    fn verifies_full_fleet_documents_larger_than_publication_receipts() {
        let fixture = tempfile::tempdir().unwrap();
        let p = fixture.path().join("ROOT_COMPLETE_OPERATIONAL_FLEET.json");
        let data =
            serde_json::to_vec(&json!({"owner":"/root","row":"x".repeat((5<<20)+3)})).unwrap();
        fs::write(&p, &data).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_finished(&p, 4 << 20).is_err());
        assert_eq!(
            root_snapshot(&fixed(&p, &custody::digest(&data))).unwrap()["owner"],
            "/root"
        );
    }

    #[test]
    fn only_a_vacant_or_failed_drained_owner_can_restart() {
        for phase in [
            "transition",
            "starting",
            "running",
            "awaiting_verified_receipt",
            "closed",
        ] {
            assert!(!can_admit(&json!(phase)));
        }
        for phase in ["reserved", "failed_drained"] {
            assert!(can_admit(&json!(phase)));
        }
    }

    #[test]
    fn conditional_inventory() {
        let mut i = json!({"schema":"jetstreamer-horizon-r2-inventory-v1","first_epoch":168,"last_epoch":168,"requested_epochs":1,"ready_pairs":0,"archive_only":0,"missing":1,"anomalies":0,"entries":[{"epoch":168,"state":"missing"}]});
        assert!(inventory_arguments(&i).unwrap().is_empty());
        i["archive_only"] = json!(1);
        i["missing"] = json!(0);
        i["entries"][0] = json!({"epoch":168,"state":"archive-only","archive_etag":"abcd-1815","archive_length":LENGTH});
        assert_eq!(inventory_arguments(&i).unwrap()[1], "abcd-1815");
        i["entries"][0]["archive_length"] = json!(LENGTH - 1);
        assert!(inventory_arguments(&i).is_err());
        i["ready_pairs"] = json!(1);
        assert!(inventory_arguments(&i).is_err());
    }
}
