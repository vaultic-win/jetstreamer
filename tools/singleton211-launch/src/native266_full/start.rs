use super::*;
use std::os::unix::fs::{chown, symlink};
const INDEX: &str = "/var/lib/jetstreamer/horizon266-index-acquire-v1/cache/sealed";
const INDEX_SHA: &str = "1a6d83262359ae23faf0ced210ff6a350b5670366c2df7aa2787e2520177eae1";
const MAN: &str = "preflight-233-301-target4-publish300-46b4b4a.json";
const MAN_SHA: &str = "3c32a5d78e764cb982b246ab123eadf4fddb5eb51b6377f7afbb196aef714b81";
const FINGER: &str = "sha256:9efefd91b7db3aede0e338c3d2766fd7d82392c834faab150fbb5dc6a79ad49d";
fn argpath(p: &Path) -> Result<&str> {
    p.to_str().context("non-UTF8 setup path")
}
fn cmd(n: &mut Native, exe: &str, a: &[&str]) -> Result<()> {
    n.run(exe, a)?;
    Ok(())
}
fn original_plan(p: &Profile, cap: u64, review: &Value) -> Result<Value> {
    if p.lane == Lane::Epoch228 {
        return epoch228::plan(p, cap, review);
    }
    let packet = gate::inputs()?;
    let files = rows(&packet, "files")?;
    let manifest = Bound::new(Path::new(SNAPROOT).join(MAN), MAN_SHA);
    let m = manifest.sealed()?;
    ensure!(m["manifest_fingerprint"] == FINGER, "cohort fingerprint");
    let (node, worker, snapshot) = (
        text(&files[1], "path")?,
        text(&files[2], "path")?,
        text(&files[0], "path")?,
    );
    ensure!(
        node == format!("{SNAPROOT}/jetstreamer-node")
            && files[1]["sha256"]
                == "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1"
            && files[2]["sha256"]
                == "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae",
        "native 1.8.11 binding"
    );
    let (node, worker) = if p.lane.is_bounded() {
        bounded::inputs()?;
        (successor::NODE, bounded::WORKER)
    } else if matches!(p.lane, Lane::Instructions266 | Lane::Turnover266) {
        if p.lane == Lane::Turnover266 {
            successor::writer(review)?;
        } else {
            successor::selected(review)?;
        }
        (successor::NODE, worker)
    } else {
        (node, worker)
    };
    let seal = Bound::new(
        Path::new(INDEX).join("deployment-seal-receipt.json"),
        INDEX_SHA,
    )
    .sealed()?;
    let mut projections = Vec::new();
    for entry in rows(&seal, "members")? {
        let name = text(entry, "name")?;
        let epoch = name.split('-').nth(1).context("epoch")?;
        ensure!(
            matches!(epoch, "265" | "266") && !name.contains('/'),
            "legacy index"
        );
        let source = Path::new(INDEX).join(name);
        let st = fs::symlink_metadata(&source)?;
        ensure!(
            source.canonicalize()? == source
                && st.is_file()
                && st.uid() == 0
                && st.mode() & 0o222 == 0
                && st.len() == num(entry, "bytes")?,
            "legacy index custody"
        );
        projections.push(json!({"source":source,"target":p.root.join("output/compact-indexes").join(epoch).join(name),"sha256":entry["sha256"]}));
    }
    ensure!(projections.len() == 3, "legacy 265/266 inputs");
    projections.push(json!({"source":files[3]["path"],"target":p.root.join("output/genesis.tar.bz2"),"sha256":files[3]["sha256"]}));
    Ok(
        json!({"mode":p.mode,"unit":p.unit,"root":p.root,"root_cap":cap,"projections":projections,"worker":worker,"manifest":manifest,"argv":[node,"266",p.root.join("output"),"--verify","--root-checkpoint-cohort",format!("--cohort-manifest={}",manifest.path.display()),format!("--cohort-manifest-fingerprint={FINGER}"),format!("--snapshot-archive={snapshot}")]}),
    )
}
fn scratch(n: &mut Native, p: &Profile, cap: u64, s: &mut Value) -> Result<()> {
    absent(&p.root)?;
    dir(&p.state, 0o755)?;
    dir(&p.state.join("receipts"), 0o700)?;
    let img = p.state.join("private.ext4");
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&img)?;
    f.set_len(cap)?;
    f.sync_all()?;
    dir(&p.root, 0o700)?;
    ensure!(
        p.root.canonicalize()? == p.root && fs::metadata(&p.root)?.uid() == 0,
        "fresh private mount"
    );
    cmd(
        n,
        "/usr/sbin/mkfs.ext4",
        &[
            "-q",
            "-F",
            "-m",
            "0",
            "-E",
            "nodiscard,lazy_itable_init=1,lazy_journal_init=1",
            argpath(&img)?,
        ],
    )?;
    cmd(
        n,
        "/usr/bin/mount",
        &["-o", "loop,nodev,nosuid", argpath(&img)?, argpath(&p.root)?],
    )?;
    let lp = String::from_utf8(n.run(
        "/usr/bin/findmnt",
        &["-n", "-T", argpath(&p.root)?, "-o", "SOURCE"],
    )?)?;
    let lp = lp.trim();
    let dev = lp.strip_prefix("/dev/loop").context("hard-cap loop")?;
    ensure!(
        !dev.is_empty()
            && dev.bytes().all(|v| v.is_ascii_digit())
            && Path::new(
                fs::read_to_string(format!("/sys/block/loop{dev}/loop/backing_file"))?.trim()
            ) == img,
        "loop backing"
    );
    let target = n.run(
        "/usr/bin/findmnt",
        &["-n", "-T", argpath(&p.root)?, "-o", "TARGET"],
    )?;
    ensure!(
        std::str::from_utf8(&target)?.trim() == argpath(&p.root)?,
        "nested mount"
    );
    chown(&p.root, Some(1000), Some(1000))?;
    fs::set_permissions(&p.root, fs::Permissions::from_mode(0o700))?;
    let dirs: &[&str] = if p.lane == Lane::Epoch228 {
        &[
            "output",
            "ledger",
            "scratch",
            "state",
            "tmp",
            "var-tmp",
            "tmp/isolated-empty-gcloud",
        ]
    } else {
        &[
            "output",
            "state",
            "tmp",
            "var-tmp",
            "tmp/isolated-empty-gcloud",
            "output/compact-indexes",
            "output/compact-indexes/265",
            "output/compact-indexes/266",
        ]
    };
    for rel in dirs {
        let path = p.root.join(rel);
        dir(&path, 0o700)?;
        chown(&path, Some(1000), Some(1000))?;
    }
    for row in rows(s, "projections")? {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(text(row, "target")?)?;
    }
    let meta = fs::metadata(&p.root)?;
    s["root_inode"] = json!(meta.ino());
    s["root_device"] = json!(meta.dev());
    s["loop"] = json!(lp);
    save_json(
        &p.state,
        "mount.json",
        &json!({"loop":lp,"root":p.root,"root_device":meta.dev(),"root_inode":meta.ino(),"backing":img,"bytes":cap}),
    )?;
    Ok(())
}
fn install(p: &Profile, name: &str, source: &str) -> Result<()> {
    let d = Path::new("/run/systemd/system").join(name);
    absent(&d)?;
    absent(&Path::new("/etc/systemd/system").join(name))?;
    let f = save(&p.state, name, source.as_bytes())?;
    symlink(f.path, d)?;
    Ok(())
}
fn static_units(n: &mut Native, p: &Profile, r: &Bound, spec: &Bound, fit: &Value) -> Result<()> {
    let cpus = rows(fit, "cpus")?
        .iter()
        .map(|v| v.as_u64().map(|x| x.to_string()).context("CPU"))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    let image = argpath(&r.path)?;
    let replace = |s: &str| {
        s.replace("@ROOT@", p.root.to_str().unwrap())
            .replace("@STATE@", p.state.to_str().unwrap())
            .replace("@MODE@", &p.mode)
            .replace("@COMMAND@", p.lane.command())
            .replace("@EPOCH@", &p.lane.epoch().to_string())
            .replace("@IMAGE@", image)
            .replace("@GUARD@", &p.guard)
            .replace("@WORKER@", if p.lane.is_bounded() { bounded::WORKER } else { "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-historical-worker-v1-8-11" })
    };
    let template = if p.lane == Lane::Epoch228 {
        include_str!("epoch228.service.in")
    } else {
        include_str!("producer.service.in")
    };
    let producer = replace(template)
        .replace("@MEMORY@", &num(&fit["winner"], "memory")?.to_string())
        .replace("@CPUS@", &cpus)
        .replace("@SPEC@", &spec.sha256);
    let fallback = p.guard.replace(".service", "-failsafe.service");
    let g = replace(include_str!("guard.service.in"));
    install(p, &p.unit, &producer)?;
    install(
        p,
        &p.guard,
        &g.replace("@FAILURE@", &format!("OnFailure={fallback}"))
            .replace("@ROLE@", "guard"),
    )?;
    install(
        p,
        &fallback,
        &g.replace(
            "@FAILURE@",
            &format!("Conflicts={} {}\nAfter={}", p.timer, p.guard, p.guard),
        )
        .replace("@ROLE@", "failsafe"),
    )?;
    install(p, &p.timer, &replace(include_str!("guard.timer.in")))?;
    cmd(n, "/usr/bin/systemctl", &["daemon-reload"])
}
fn first_sample(p: &Profile) -> Result<(Bound, Value)> {
    let receipts = p.state.join("receipts");
    let until = Instant::now() + Duration::from_secs(100);
    loop {
        let paths = fs::read_dir(&receipts)?.collect::<std::io::Result<Vec<_>>>()?;
        let mut evidence = paths
            .iter()
            .map(|e| e.path())
            .filter(|a| {
                let name = a.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if p.mode == "qa-memory" {
                    name == "pressure-stop.json"
                } else {
                    name.starts_with("sample-") && name.ends_with(".json")
                }
            })
            .collect::<Vec<_>>();
        evidence.sort_by_key(|p| fs::metadata(p).and_then(|s| s.modified()).ok());
        if let Some(path) = evidence.first() {
            let b = bound_at(path)?;
            if let Ok(v) = b.json() {
                return Ok((b, v));
            }
        }
        ensure!(Instant::now() < until, "protective first firing missing");
        std::thread::sleep(Duration::from_millis(200));
    }
}
fn wait_state(n: &mut Native, u: &str, desired: &str, secs: u64) -> Result<Value> {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        let m = n.show(u)?;
        if m["ActiveState"] == desired {
            return Ok(m);
        }
        ensure!(
            m["ActiveState"] != "failed" && Instant::now() < end,
            "unit state {u}"
        );
        std::thread::sleep(Duration::from_millis(150));
    }
}
fn guard_journal(n: &mut Native, p: &Profile, iid: &str) -> Result<Value> {
    ensure!(hex(iid, 32), "guard invocation");
    let raw = system(
        n,
        "/usr/bin/journalctl",
        &[
            "-b".into(),
            "-o".into(),
            "json".into(),
            "--no-pager".into(),
            "_UID=0".into(),
            "_PID=1".into(),
            format!("UNIT={}", p.guard),
            format!("INVOCATION_ID={iid}"),
        ],
    )?;
    let list = std::str::from_utf8(&raw)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (a, b) = full211_window::guard_clocks(&list, &BOOT.replace('-', ""), &p.guard, iid)?;
    Ok(json!({"first_monotonic_us":a,"last_monotonic_us":b,"pid1":list}))
}
fn release(
    n: &mut Native,
    p: &Profile,
    r: &Value,
    spec: &Bound,
    image: &Bound,
    fit: &Value,
    owner: &Value,
) -> Result<Value> {
    let iid = text(owner, "InvocationID")?;
    let pid = text(owner, "MainPID")?.parse::<u64>()?;
    let memory = num(&fit["winner"], "memory")?;
    if p.lane != Lane::Epoch266 {
        epoch228::kernel(p, owner, fit)?;
    }
    ensure!(
        hex(iid, 32)
            && pid > 1
            && owner["NRestarts"] == "0"
            && owner["SubState"] == "running"
            && owner["MemorySwapMax"] == "0"
            && text(owner, "MemoryMax")?.parse::<u64>()? == memory,
        "waiting producer"
    );
    ensure!(
        fs::read_link(format!("/proc/{pid}/exe"))? == image.path,
        "held control image"
    );
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))?;
    let argv = cmdline
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        argv == [
            argpath(&image.path)?.as_bytes(),
            p.lane.command().as_bytes(),
            b"wait",
            p.mode.as_bytes(),
            argpath(&spec.path)?.as_bytes(),
            spec.sha256.as_bytes()
        ],
        "held command replaced"
    );
    let cap = if p.mode == "pilot" {
        num(&fit["winner"], "root")? - (8 << 30)
    } else {
        256 << 20
    };
    let floor = if p.mode == "qa-disk" {
        u64::MAX
    } else {
        num(fit, "protected_floor")?
    };
    let (guard_exe, guard_sha) = p.lane.guard();
    let narrow = p.lane == Lane::Epoch228 && p.mode == "pilot";
    let (filesystem, cap) = if narrow {
        ("/", 585_388_447_855u64)
    } else {
        (V, cap)
    };
    let g = save_json(
        &p.state,
        "guard-plan.json",
        &json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":p.unit,"invocation_id":iid,"filesystem":filesystem,"worker_root":p.root,"receipt_directory":p.state.join("receipts"),"minimum_free_bytes":floor,"maximum_root_physical_bytes":cap,"maximum_worker_vmas":3500000}),
    )?;
    let check = n.run(
        guard_exe,
        &[
            argpath(&g.path)?,
            "--plan-sha256",
            &g.sha256,
            "--self-sha256",
            guard_sha,
            "--validate-plan-only",
        ],
    )?;
    let q = serde_json::from_slice::<Value>(&check)?;
    ensure!(
        q["validated"] == true && q["resource_samples_taken"] == 0,
        "qualified standalone guard plan"
    );
    let su = save_json(
        &p.state,
        "supervisor.json",
        &json!({"iid":iid,"unit":p.unit,"memory":memory,"stop_at":if p.mode=="qa-memory"{1}else{memory-(8<<30)},"guard_plan":g}),
    )?;
    save(
        &p.state,
        "guard.env",
        format!("HORIZON266_SUPERVISOR_SHA={}\n", su.sha256).as_bytes(),
    )?;
    cmd(n, "/usr/bin/systemctl", &["start", &p.timer])?;
    let (original, v) = first_sample(p)?;
    let gid = if p.mode == "qa-memory" {
        ensure!(
            v["reason"] == "cgroup-memory-pressure"
                && v["iid"] == iid
                && num(&v["pressure"], "memory")? > 1
                && v["owner"]["MainPID"] == pid.to_string(),
            "real pressure stop"
        );
        text(&v, "guard_iid")?
    } else {
        validate_sample_for(
            guard_sha,
            &v,
            &p.unit,
            iid,
            pid,
            &g,
            if p.mode == "qa-disk" {
                Some("filesystem-floor")
            } else {
                None
            },
        )?;
        text(&v, "guard_invocation_id")?
    };
    wait_state(n, &p.guard, "inactive", 180)?;
    let journal = save_json(
        &p.state,
        "first-guard-pid1.json",
        &guard_journal(n, p, gid)?,
    )?;
    if p.mode != "pilot" {
        let terminal = wait_state(n, &p.unit, "inactive", 30)?;
        live::verify_drained_group(&p.unit)?;
        ensure!(
            terminal["MainPID"] == "0"
                && (terminal["InvocationID"] == iid || terminal["InvocationID"] == "")
                && !p.state.join(format!("token-{iid}.json")).exists(),
            "qualification did not drain original held producer"
        );
        let expected_boot = BOOT.replace('-', "");
        let mut pid1 = Vec::new();
        for mid in [
            "39f53479d3a045ac8e11786248231fbf",
            "7ad2d189f7e94e70a38c781354912448",
        ] {
            let raw = n.run(
                "/usr/bin/journalctl",
                &[
                    "--no-pager",
                    "-b",
                    "-n",
                    "1",
                    "-o",
                    "json",
                    "_UID=0",
                    "_PID=1",
                    &format!("UNIT={}", p.unit),
                    &format!("MESSAGE_ID={mid}"),
                ],
            )?;
            let ev: Value = serde_json::from_slice(&raw)?;
            ensure!(
                ev["INVOCATION_ID"] == iid
                    && ev["_BOOT_ID"] == expected_boot
                    && ev.get("UNIT_RESULT").is_none_or(|v| v == "success"),
                "different original QA manager receipt"
            );
            pid1.push(ev);
        }
        ensure!(
            text(&pid1[0], "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?
                < text(&pid1[1], "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?,
            "QA PID1 event order"
        );
        save_json(&p.state, "producer-terminal-pid1.json", &json!(pid1))?;
        if p.mode == "qa-disk" {
            let rr = p.state.join("receipts");
            let intent = bound_at(&rr.join("stop-intent.json"))?.json()?;
            let native = rr.join("stop-completion.json");
            let end = if native.exists() {
                bound_at(&native)?.json()?
            } else {
                bound_at(&rr.join("manager-stop-completion.json"))?.sealed()?
            };
            ensure!(
                intent["reason"] == "filesystem-floor"
                    && intent["sample"] == v
                    && end["producer_invocation_id"] == iid
                    && end["plan_sha256"] == g.sha256,
                "qualified filesystem trip did not stop"
            );
        }
        cmd(n, "/usr/bin/systemctl", &["stop", &p.timer])?;
        return Ok(
            json!({"schema":format!("horizon{}-native-full-stop-qualification-v1",p.lane.epoch()),"mode":p.mode,"unit":p.unit,"iid":iid,"pid":pid,"spec":spec,"guard":g,"first_guard":original,"guard_pid1":journal,"terminal":terminal,"drained":true,"entry_replay":false,"image":image}),
        );
    }
    let timer = n.show(&p.timer)?;
    ensure!(
        timer["ActiveState"] == "active" && timer["Unit"] == p.guard,
        "guard timer"
    );
    let held = funding::elect(
        p.lane,
        n,
        r,
        Some((p, owner, (memory, num(&fit["winner"], "root")?))),
    )?;
    ensure!(
        held["winner"].is_object()
            && held["cpus"] == fit["cpus"]
            && num(&held, "protected_floor")? <= floor,
        "held re-election changed floor or CPU envelope"
    );
    for leaf in ["stop-intent.json", "pressure-stop.json"] {
        absent(&p.state.join("receipts").join(leaf))?;
    }
    ensure!(
        command_field(n, &p.unit, "InvocationID")? == iid
            && command_field(n, &p.unit, "MainPID")? == pid.to_string()
            && command_field(n, &p.timer, "InvocationID")? == text(&timer, "InvocationID")?,
        "release owner changed"
    );
    if p.lane != Lane::Epoch266 {
        epoch228::kernel(p, &n.show(&p.unit)?, &held)?;
    }
    let h = save_json(&p.state, "held-fit.json", &held)?;
    let token = public(
        &p.state,
        &format!("token-{iid}.json"),
        &json!({"iid":iid,"pid":pid,"unit":p.unit,"spec":spec,"guard":g,"first_guard":original,"held_fit":h,"timer_iid":timer["InvocationID"],"guard_pid1":journal,"expires":now()?+25}),
    )?;
    let until = Instant::now() + Duration::from_secs(25);
    let packet = spec.sealed()?;
    let mapped = Path::new(packet["argv"][0].as_str().context("node argv")?);
    while fs::read_link(format!("/proc/{pid}/exe"))? != mapped {
        ensure!(Instant::now() < until, "native node did not exec");
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(
        json!({"schema":format!("horizon{}-first-full-native-node-handoff-v1",p.lane.epoch()),"unit":p.unit,"iid":iid,"pid":pid,"spec":spec,"timer":timer["InvocationID"],"token":token,"guard":g,"first_guard":original,"held_fit":h,"entry_replay_proven":false,"publication_authorized":false}),
    )
}
pub(super) fn validate_sample_for(
    guard_sha: &str,
    v: &Value,
    u: &str,
    iid: &str,
    pid: u64,
    g: &Bound,
    reason: Option<&str>,
) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && v["guard_sha256"] == guard_sha
            && v["producer_stop_enabled"] == true
            && v["producer_invocation_id"] == iid
            && v["plan_sha256"] == g.sha256
            && v["plan"] == json!(g.path)
            && v["producer"]["pid"] == pid
            && v["producer"]["cgroup"] == format!("/system.slice/{u}")
            && v["producer"]["invocation_id"] == iid
            && v["trip_reason"] == json!(reason)
            && v["worker_observation_error"].is_null()
            && v["root_physical_observation_error"].is_null()
            && v["root_physical_observation"].is_object()
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "unbound real first guard or unexpected stop"
    );
    Ok(())
}
pub(super) fn run(
    lane: Lane,
    n: &mut Native,
    r: &Value,
    review: &Bound,
    image: &Bound,
) -> Result<Value> {
    let (exe, sha) = lane.guard();
    Bound::new(exe, sha).artifact()?;
    for mode in MODES {
        let p = Profile::new(lane, mode)?;
        let output = p.state.join(if mode == "pilot" {
            "handoff.json"
        } else {
            "qualification.json"
        });
        if output.exists() {
            let old = bound_at(&output)?.sealed()?;
            ensure!(
                old["unit"] == p.unit && hex(text(&old, "iid")?, 32),
                "prior result identity"
            );
            if mode != "pilot" {
                ensure!(
                    old["image"] == json!(image) && old["drained"] == true,
                    "prior QA source changed"
                );
                binding(&old["first_guard"])?.json()?;
                binding(&old["guard_pid1"])?.sealed()?;
                live::verify_drained_group(&p.unit)?;
            } else {
                ensure!(
                    command_field(n, &p.unit, "InvocationID")? == text(&old, "iid")?,
                    "different original handoff"
                );
            }
            continue;
        }
        let fit = funding::elect(lane, n, r, None)?;
        ensure!(fit["winner"].is_object(), "no complete finite fit {fit}");
        let cap = if mode == "pilot" {
            num(&fit["winner"], "root")?
        } else {
            256 << 20
        };
        let mut s = original_plan(&p, cap, r)?;
        scratch(n, &p, cap, &mut s)?;
        s["review"] = json!(review);
        let spec = public(&p.state, "spec.json", &s)?;
        save_json(&p.state, "initial-fit.json", &fit)?;
        static_units(n, &p, image, &spec, &fit)?;
        cmd(n, "/usr/bin/systemctl", &["start", "--no-block", &p.unit])?;
        let m = wait_state(n, &p.unit, "active", 20)?;
        match release(n, &p, r, &spec, image, &fit, &m) {
            Ok(v) => {
                save_json(&p.state, output.file_name().unwrap().to_str().unwrap(), &v)?;
            }
            Err(err) => {
                let iid = text(&m, "InvocationID")?;
                if !p.state.join(format!("token-{iid}.json")).exists()
                    && command_field(n, &p.unit, "InvocationID")? == iid
                {
                    let _ = cmd(n, "/usr/bin/systemctl", &["stop", "--no-block", &p.unit]);
                }
                save_json(
                    &p.state,
                    "failure.json",
                    &json!({"reason":format!("{err:#}"),"original_iid":iid,"entry_replay_proven":false}),
                )?;
                return Err(err);
            }
        }
    }
    bound_at(&Profile::new(lane, "pilot")?.state.join("handoff.json"))?.sealed()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixtures() -> Vec<Value> {
        serde_json::from_str(include_str!("original-guard-receipts.json")).unwrap()
    }
    #[test]
    fn actual_standalone_guard_requires_real_first_fire_and_owner() {
        let records = fixtures();
        let s = &records[0]["sample"];
        let peer = funding::OWNERS[1];
        let g = Bound::new(text(s, "plan").unwrap(), text(s, "plan_sha256").unwrap());
        let pid = num(&s["producer"], "pid").unwrap();
        validate_sample_for(GUARD_SHA, s, peer.0, peer.1, pid, &g, None).unwrap();
        let cases = [
            ("guard_sha256", json!("0".repeat(64))),
            ("trip_reason", json!("filesystem-floor")),
            ("producer_stop_enabled", json!(false)),
            ("worker_observation_error", json!("changed")),
        ];
        for (k, v) in cases {
            let mut bad = s.clone();
            bad[k] = v;
            assert!(validate_sample_for(GUARD_SHA, &bad, peer.0, peer.1, pid, &g, None).is_err());
        }
        assert!(validate_sample_for(GUARD_SHA, s, peer.0, peer.1, pid + 1, &g, None).is_err());
        let historical = &records[1]["sample"];
        assert_eq!(historical["trip_reason"], "filesystem-floor");
        assert_ne!(historical["guard_sha256"], GUARD_SHA);
        assert!(
            validate_sample_for(
                GUARD_SHA,
                historical,
                peer.0,
                peer.1,
                pid,
                &g,
                Some("filesystem-floor")
            )
            .is_err()
        );
    }
    #[test]
    #[ignore = "requires the original root-owned historical guard receipts"]
    fn reopens_original_guard_receipts_and_matches_every_retained_field() {
        for row in fixtures() {
            let actual = Bound::new(text(&row, "path").unwrap(), text(&row, "sha256").unwrap())
                .json()
                .unwrap();
            let sample = actual.get("sample").unwrap_or(&actual);
            for key in row["original_fields"].as_array().unwrap() {
                let key = key.as_str().unwrap();
                assert_eq!(sample[key], row["sample"][key]);
            }
        }
    }
}
