//! Admit the existing private holding transfer after the exact 166 custody and retirement.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

// Use the same 166 admission gate as the fourth replay lane, including physical absence checks.
#[allow(dead_code)]
mod predecessor {
    include!("../horizon_epoch167_source_index_recovery_20261121_v1/main.rs");
    pub(super) fn retirement() -> Result<()> {
        source::holding_complete()
    }
    pub(super) const SEALER_SHA: &str = support::SEALER;
    pub(super) fn digest_json(v: &Value) -> Result<String> {
        Ok(support::sha(&serde_json::to_vec(v)?))
    }
    pub(super) mod evidence {
        pub use super::support::{
            bound, command, doc, file_digest, hex, members, n, native, now, proc_row, rt, same, st,
        };
    }
}
use predecessor::evidence::*;

const DIR: &str = "epoch168-full-metered-holding-20261122-v1";
const PREP: &str = "2fa44417d9b239b8e35820c1bed5b6e47d184517e9850cbc7992c7f8b5663c58";
// Each installed operator uses the provider qualified with its status-writer generation.
#[cfg(not(park168_retry4))]
mod deployment {
    pub const TOOLS: &str = "operator-tools";
    pub const FIT_DIR: &str = "incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry2-v1";
    pub const FIT_SEAL: &str = "f2a9679f85940827829e0bc1cd3831e37f33805232e756b2b865df64df2781f7";
    pub const FIT_IMAGE: &str = "00b95053361f71f6523cab55acd876fd3bd7ac44276548ba016ebb54dc2fc788";
}
#[cfg(park168_retry4)]
mod deployment {
    pub const TOOLS: &str = "operator-tools-retry4";
    pub const FIT_DIR: &str = "incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry4-v1";
    pub const FIT_SEAL: &str = "7c7dc6f92cca7fc94388b22261e3b0b15fbfe27587fd56fb61e1951aaf4250e9";
    pub const FIT_IMAGE: &str = "0d9610c5cdb3333f1325d311d17bbb2cd67e35169d72560d60b7d7964b1da7a5";
}
use deployment::{FIT_DIR, FIT_IMAGE, FIT_SEAL};
const UNIT: &str = "horizon-closed168-full-metered-park-20261122-v1.service";
const BEFORE: &str = "horizon-closed166-retry10-park-20261122-v1.service";
const PRIOR_IID: &str = "57146d4b5c9940449cd129433a5acd2b";
const STATE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1";
const LEN: u64 = 51_889_766_680;

fn local(name: &str) -> PathBuf {
    rt(DIR).join(name)
}
fn arguments(prep: &Value) -> Result<Vec<String>> {
    prep["argv"]
        .as_array()
        .context("prepared argv")?
        .iter()
        .map(|v| Ok(v.as_str().context("argument")?.to_owned()))
        .collect()
}
fn source(prep: &Value) -> Result<()> {
    let plan = bound(&prep["plan"], &local("package/plan.json"))?;
    let p = Path::new(st(&plan, "source")?);
    let m = fs::symlink_metadata(p)?;
    let ns = |s: i64, n: i64| i128::from(s) * 1_000_000_000 + i128::from(n);
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && (m.uid(), m.gid(), m.mode() & 0o777, m.nlink()) == (1001, 1003, 0o600, 1)
            && prep["source_identity"]
                == json!([
                    m.dev(),
                    m.ino(),
                    m.len(),
                    ns(m.mtime(), m.mtime_nsec()),
                    ns(m.ctime(), m.ctime_nsec())
                ])
            && m.len() == LEN
            && plan["length"] == LEN
            && plan["sha256"] == prep["source_sha256"],
        "stopped source changed"
    );
    for key in ["holding_image_seal", "seal", "source_cleanup"] {
        let row = &prep[key];
        bound(row, Path::new(st(row, "path")?))?;
    }
    let scan = &prep["digest_receipt"];
    let name = Path::new(st(scan, "path")?);
    let meta = fs::symlink_metadata(name)?;
    ensure!(
        name.canonicalize()? == name
            && meta.is_file()
            && (meta.uid(), meta.mode() & 0o777, meta.nlink()) == (1001, 0o600, 1)
            && meta.len() <= 1 << 20,
        "foreign native prefix scan"
    );
    let bytes = fs::read(name)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == st(scan, "sha256")?,
        "native prefix scan changed"
    );
    let row = &prep["holding_image"];
    ensure!(
        file_digest(Path::new(st(row, "path")?))? == st(row, "sha256")?,
        "holding image changed"
    );
    let argv = arguments(prep)?;
    ensure!(
        argv == [
            st(row, "path")?,
            "holding-park",
            st(&prep["plan"], "path")?,
            "--spec-sha256",
            st(&prep["plan"], "sha256")?,
            "--self-sha256",
            st(row, "sha256")?
        ],
        "wrong holding command"
    );
    Ok(())
}
fn lock(path: &Path, inode: Option<(u64, u64, u32, u32)>) -> Result<File> {
    let mut op = OpenOptions::new();
    op.read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    if inode.is_none() {
        op.write(true).create(true).mode(0o600);
    }
    let file = op.open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o777 == 0o600 && path.canonicalize()? == path,
        "unsafe lock {}",
        path.display()
    );
    if let Some(expected) = inode {
        ensure!(
            (m.dev(), m.ino(), m.uid(), m.gid()) == expected,
            "lock identity changed"
        );
    } else {
        ensure!(m.uid() == 0, "foreign operator lock");
    }
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "busy lock {}",
        path.display()
    );
    Ok(file)
}
fn serial() -> Result<(File, File)> {
    Ok((
        lock(
            &Path::new(STATE).join("transition.lock"),
            Some((64512, 95818311, 0, 0)),
        )?,
        lock(
            Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock"),
            Some((64512, 101135013, 1001, 1003)),
        )?,
    ))
}
fn prior() -> Result<Value> {
    let m = native(BEFORE)?;
    ensure!(
        m["Id"] == BEFORE
            && m["InvocationID"] == PRIOR_IID
            && m["MainPID"] == "0"
            && m["ActiveState"] == "active"
            && m["SubState"] == "exited"
            && m["Result"] == "success"
            && m["Job"] == ""
            && members(BEFORE)?.is_empty(),
        "epoch 166 holding still owns the slot or failed ({}, PID {})",
        m["SubState"],
        m["MainPID"]
    );
    predecessor::retirement()?;
    let state = Path::new(STATE);
    Ok(
        json!({"unit":BEFORE,"invocation_id":PRIOR_IID,"custody":doc(&state.join("receipts/custody-320633267efeb2939e2d8c44c61f992194f78106d060e3611ddb3ed318a8ce2f.json"),None)?.1,
              "retirement":doc(&state.join("retirements/epoch166-retry10-completion.json"),None)?.1}),
    )
}
fn funding(q: &Value, f: &Value, head: &Value, occupied: bool) -> Result<()> {
    let aux = &f["retry9_auxiliary_commitments"];
    ensure!(
        aux["holding_serial"] == true
            && aux["holding_and_build_may_overlap"] == true
            && aux["holding_cpu_quota_micros"] == 2000000
            && aux["holding_memory_bytes"] == 2u64 << 30
            && aux["holding_staging_bytes"] == 0
            && n(aux, "holding_restore_overlap_bytes")? >= LEN,
        "serial holding booking changed"
    );
    ensure!(
        q["schema"] == "horizon-incident-replay-fit-v1"
            && q["epoch"] == 168
            && q["fleet"] == *head
            && q["fits"] == true
            && q["resource_credit_bytes"] == 0
            && q["replay_launch_authorized"] == false
            && n(q, "available_HOME_bytes")? >= n(q, "complete_required_HOME_bytes")?
            && n(q, "available_memory_bytes")? >= n(q, "required_available_memory_bytes")?
            && n(q, "complete_required_HOME_bytes")? > 0
            && n(q, "required_available_memory_bytes")? > 0,
        "whole-host quote failed"
    );
    ensure!(
        ["166", "167", "168", "169", "170"]
            .iter()
            .all(|e| q["bookings"][e]["cap_bytes"]
                .as_u64()
                .is_some_and(|n| n > 0))
            && q["recovery_obligations"]["public_workers"].is_array()
            && q["registered_cold168_holding"].is_null()
            && q["registered_retry11_holding"]["unit"] == BEFORE
            && q["registered_retry11_holding"]["invocation_id"] == PRIOR_IID
            && (occupied || q["registered_retry11_holding"]["stage"] == "completed-copy"),
        "wrong paid actors or missing 166 handback"
    );
    Ok(())
}
fn quote(head: &Value, occupied: bool) -> Result<Value> {
    let path = Path::new(st(head, "path")?);
    let f = bound(head, path)?;
    let provider = rt(FIT_DIR).join("post-stop-fit");
    let (seal, _) = doc(
        &rt(FIT_DIR).join("deployment-seal-receipt.json"),
        Some(FIT_SEAL),
    )?;
    ensure!(
        seal["destination"] == json!(rt(FIT_DIR)) && file_digest(&provider)? == FIT_IMAGE,
        "unqualified fit provider"
    );
    let raw = command(
        "/usr/bin/python3",
        &[
            "-IB",
            provider.to_str().unwrap(),
            "168",
            st(head, "path")?,
            st(head, "sha256")?,
        ],
        300,
    )?;
    let q: Value = serde_json::from_slice(&raw)?;
    funding(&q, &f, head, occupied)?;
    let t = n(&q, "recorded_unix_seconds")?;
    let current = now()?;
    ensure!(
        t <= current && current - t < 120,
        "fresh fleet price required"
    );
    Ok(q)
}
// Idempotently publish identical receipts. Uncertain outcomes preserve the first durable decision.
fn save(name: &str, v: &Value) -> Result<Value> {
    let path = local(name);
    if path.try_exists()? {
        let (old, ref_) = doc(&path, None)?;
        ensure!(old == *v, "conflicting {name}");
        return Ok(ref_);
    }
    let mut f = tempfile::NamedTempFile::new_in(local(""))?;
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(&mut f, v)?;
    f.write_all(b"\n")?;
    f.as_file().sync_all()?;
    f.persist_noclobber(&path)?;
    File::open(local(""))?.sync_all()?;
    Ok(doc(&path, None)?.1)
}
fn dispatch(prep: &Value, fleet: &Value, q: &Value, predecessor: &Value) -> Result<Value> {
    let fit = local("PARK_FIT.json");
    if !fit.try_exists()? {
        save("PARK_FIT.json", q)?;
    }
    let (paid, fitref) = doc(&fit, None)?;
    // A crash after reserving the original fit retains it. Actual dispatch always has a second fresh quote.
    let original = &paid["fleet"];
    let old = bound(original, Path::new(st(original, "path")?))?;
    funding(&paid, &old, original, false)?;
    let admission = json!({"owner":"primary","unit":UNIT,"inputs":doc(&local("PREPARED.json"),Some(PREP))?.1,
       "fit":fitref,"fleet":original,"at":paid["recorded_unix_seconds"],"plan":prep["plan"],"predecessor166":predecessor,
       "cpu":2000000,"memory":2u64<<30,"tasks":256,"restore_overlap_bytes":LEN,"archive_staging_bytes":0,"resource_credit_bytes":0});
    let admitted = save("PARK_ADMISSION.json", &admission)?;
    let live = save(
        &format!("dispatch-fit-{}.json", n(q, "recorded_unix_seconds")?),
        q,
    )?;
    let decision = json!({"schema":"horizon-168-copy-dispatch-v1","unit":UNIT,"argv":prep["argv"],"admission":admitted,"fleet":fleet,
              "price":live,"predecessor166":predecessor});
    let id = predecessor::digest_json(&decision)?;
    save(&format!("dispatch-{id}.json"), &decision)?;
    Ok(json!({"id":id,"admission":admitted}))
}
fn inspect_unit() -> Result<Value> {
    let mut n = native(UNIT)?;
    let extended = command(
        "/usr/bin/systemctl",
        &[
            "show",
            "-p",
            "Description,TasksMax,ExecMainPID,ExecMainStartTimestamp,ExecMainStatus,RemainAfterExit,ExecStart",
            UNIT,
        ],
        10,
    )?;
    for l in std::str::from_utf8(&extended)?.lines() {
        let (k, x) = l.split_once('=').context("manager field")?;
        n[k] = json!(x);
    }
    Ok(n)
}
fn start_argv(prep: &Value, id: &str) -> Result<Vec<String>> {
    let mut a = vec![
        "--no-block".into(),
        format!("--unit={UNIT}"),
        format!("--description=Horizon private holding 168 {id}"),
        "--service-type=oneshot".into(),
        "--remain-after-exit".into(),
    ];
    for prop in [
        "UMask=0077",
        "NoNewPrivileges=yes",
        "ProtectHome=read-only",
        "ProtectSystem=strict",
        "ReadWritePaths=/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1",
        "EnvironmentFile=/var/lib/jetstreamer/r2-chronological-plugin-audit-deployment-20261118-v1/credentials.env",
        "CPUQuota=200%",
        "MemoryMax=2G",
        "MemorySwapMax=0",
        "TasksMax=256",
        "TimeoutStartSec=infinity",
        "Restart=no",
    ] {
        a.extend(["-p".into(), prop.into()]);
    }
    a.extend(arguments(prep)?);
    Ok(a)
}
fn capture(prep: &Value) -> Result<Value> {
    let m = inspect_unit()?;
    let id = st(&m, "Description")?
        .strip_prefix("Horizon private holding 168 ")
        .context("foreign unit description")?;
    ensure!(hex(id, 64), "invalid dispatch identity");
    let (ticket, tr) = doc(&local(&format!("dispatch-{id}.json")), None)?;
    ensure!(
        predecessor::digest_json(&ticket)? == id
            && ticket["unit"] == UNIT
            && ticket["argv"] == prep["argv"],
        "foreign dispatch ticket"
    );
    let (ad, ar) = doc(&local("PARK_ADMISSION.json"), None)?;
    ensure!(
        ticket["admission"] == ar
            && ad["inputs"] == doc(&local("PREPARED.json"), Some(PREP))?.1
            && ad["plan"] == prep["plan"]
            && ticket["predecessor166"] == ad["predecessor166"],
        "different original admission"
    );
    let exact = format!("argv[]={}", arguments(prep)?.join(" "));
    ensure!(
        m["Id"] == UNIT
            && hex(st(&m, "InvocationID")?, 32)
            && m["NRestarts"] == "0"
            && m["MemorySwapMax"] == "0"
            && m["MemoryMax"] == "2147483648"
            && m["CPUQuotaPerSecUSec"] == "2s"
            && m["TasksMax"] == "256"
            && m["RemainAfterExit"] == "yes"
            && st(&m, "ExecStart")?.contains(&(exact + " ;")),
        "wrong original systemd unit"
    );
    let started = local("PARK_START.json");
    let pid: u64 = st(&m, "MainPID")?.parse()?;
    if pid == 0 {
        let (old,ref_)=doc(&started,None).context("worker already drained without original start capture; reconcile retained journal and custody")?;
        ensure!(
            old["dispatch"] == tr
                && old["admission"] == ar
                && old["native"]["InvocationID"] == m["InvocationID"]
                && old["native"]["MainPID"] == m["ExecMainPID"]
                && members(UNIT)?.is_empty()
                && m["ActiveState"] == "active"
                && m["SubState"] == "exited"
                && m["Result"] == "success"
                && m["ExecMainStatus"] == "0",
            "original transfer did not complete successfully"
        );
        return Ok(ref_);
    }
    let image = Path::new(st(&prep["holding_image"], "path")?);
    let proc = Path::new("/proc").join(pid.to_string());
    let (_, ticks, group) = proc_row(pid)?;
    ensure!(
        m["ActiveState"] == "activating"
            && m["SubState"] == "start"
            && members(UNIT)? == [pid]
            && group == format!("0::/system.slice/{UNIT}")
            && m["ControlGroup"] == format!("/system.slice/{UNIT}")
            && same(&proc.join("exe"), image)?
            && fs::read(proc.join("cmdline"))? == (arguments(prep)?.join("\0") + "\0").as_bytes()
            && proc_row(pid)?.1 == ticks,
        "wrong 168 native holding actor"
    );
    if started.try_exists()? {
        let (row, r) = doc(&started, None)?;
        ensure!(
            row["native"]["InvocationID"] == m["InvocationID"]
                && row["native"]["MainPID"] == m["MainPID"]
                && row["start_ticks"] == ticks.to_string()
                && row["admission"] == ar
                && row["dispatch"] == tr,
            "start changed"
        );
        return Ok(r);
    }
    save(
        "PARK_START.json",
        &json!({"at":now()?,"native":m,"start_ticks":ticks.to_string(),"admission":ar,
        "dispatch":tr,"resource_credit_bytes":0}),
    )
}
fn run() -> Result<Value> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().collect();
    let (prep, _) = doc(&local("PREPARED.json"), Some(PREP))?;
    if args.len() == 2 && args[1] == "capture" {
        return capture(&prep);
    }
    ensure!(
        args.len() == 4
            && matches!(args[1].as_str(), "inspect" | "check" | "start")
            && hex(&args[3], 64),
        "inspect|check|start FLEET_PATH FLEET_SHA, or capture"
    );
    let head = json!({"path":args[2],"sha256":args[3]});
    if args[1] == "start" {
        let tools = local(deployment::TOOLS);
        let seal = doc(&tools.join("deployment-seal-receipt.json"), None)?.0;
        let image = tools.join("park168");
        let members = seal["members"]
            .as_array()
            .context("operator seal members")?;
        ensure!(
            seal["destination"] == json!(tools)
                && seal["sealer_sha256"] == predecessor::SEALER_SHA
                && same(&env::current_exe()?, &image)?
                && members.iter().any(|m| m["name"] == "park168"
                    && m["sha256"] == file_digest(&image).unwrap_or_default()),
            "execute the sealed 168 operator"
        );
    }
    let existing = inspect_unit()?;
    if args[1] == "start"
        && (existing["LoadState"] != "not-found" || local("PARK_START.json").try_exists()?)
    {
        return capture(&prep);
    }
    source(&prep)?;
    let dir_lock = (args[1] == "start")
        .then(|| lock(&local("operator.lock"), None))
        .transpose()?;
    let q = quote(&head, true)?;
    if args[1] == "inspect" {
        return Ok(json!({"price":q,"predecessor":native(BEFORE)?,"launch_authorized":false}));
    }
    let before = prior()?;
    funding(&q, &bound(&head, Path::new(&args[2]))?, &head, false)?;
    let locks = serial()?;
    let current = inspect_unit()?;
    ensure!(
        current["LoadState"] == "not-found"
            && current["ActiveState"] == "inactive"
            && current["MainPID"] == "0"
            && current["ControlPID"] == "0"
            && current["Job"] == ""
            && members(UNIT)?.is_empty()
            && !Path::new(st(&prep, "expected_receipt")?).try_exists()?,
        "unit, job or custody already exists; reconcile original"
    );
    if args[1] == "check" {
        return Ok(
            json!({"fits":true,"fleet":head,"predecessor166":before,"source":prep["source_identity"]}),
        );
    }
    let attempt = dispatch(&prep, &head, &q, &before)?;
    source(&prep)?;
    prior()?; // Revalidate after the durable admission, still under the native locks.
    let argv = start_argv(&prep, st(&attempt, "id")?)?;
    drop(locks); // The original holding-park executable takes this same transition flock before touching R2.
    let status = Command::new("/usr/bin/systemd-run").args(argv).status()?;
    ensure!(
        status.success(),
        "systemd submission uncertain; reconcile the original named unit"
    );
    let mut failure = None;
    for _ in 0..60 {
        match capture(&prep) {
            Ok(v) => return Ok(v),
            Err(e) => failure = Some(e),
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    drop(dir_lock);
    Err(failure.context("start capture")?)
}
fn main() {
    match run() {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("{e:#}");
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
mod holding_entry {
    use super::*;
    #[cfg(park168_retry4)]
    #[test]
    fn current_price_joins_the_registered_writer() {
        let quote = doc(
            &local("operator-retry4-price-022839.json"),
            Some("f304c68648a01456d6c6bc29e7c50c778ed552906f1ed29d6d34b94223a18ca0"),
        )
        .unwrap()
        .0;
        let head = &quote["fleet"];
        let fleet = bound(head, Path::new(head["path"].as_str().unwrap())).unwrap();
        funding(&quote, &fleet, head, false).unwrap();
        let registration = &quote["status_registration"];
        let active = doc(
            &rt("survivor172-cadence-20261122-v1/COLD168_RETRY4_V1_STATUS_ACTIVE.json"),
            Some("16cd7406abfd04bee0ae5ad8120e095507eeb7928f3ce670a8bb83328fc414ff"),
        )
        .unwrap()
        .0;
        for field in ["invocation_id", "pid", "start_ticks"] {
            assert_eq!(registration[field], active["new"][field]);
        }
        assert_eq!(quote["candidate"], quote["replacements"]["168"]);
        assert_eq!(quote["candidate"]["processes"].as_array().unwrap().len(), 2);
        assert_eq!(
            file_digest(&rt(FIT_DIR).join("post-stop-fit")).unwrap(),
            FIT_IMAGE
        );
        assert!(doc(&rt("incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry2-v1/deployment-seal-receipt.json"), Some(FIT_SEAL)).is_err());
    }
    #[test]
    fn original_args_and_source() {
        let p = doc(&local("PREPARED.json"), Some(PREP)).unwrap().0;
        source(&p).unwrap();
        let a = start_argv(&p, &"a".repeat(64)).unwrap();
        assert!(a.ends_with(&arguments(&p).unwrap()));
        for v in [
            "CPUQuota=200%",
            "MemoryMax=2G",
            "TasksMax=256",
            "MemorySwapMax=0",
            "Restart=no",
        ] {
            assert!(a.iter().any(|a| a == v));
        }
        assert!(
            source(&{
                let mut bad = p;
                bad["source_identity"][1] = json!(1);
                bad
            })
            .is_err()
        );
    }
    #[test]
    fn genuine_fit_and_handoff_contract() {
        let q = doc(&local("operator-build-price-001757.json"), None)
            .unwrap()
            .0;
        let head = &q["fleet"];
        let f = doc(
            Path::new(st(head, "path").unwrap()),
            Some(st(head, "sha256").unwrap()),
        )
        .unwrap()
        .0;
        funding(&q, &f, head, true).unwrap();
        assert!(funding(&q, &f, head, false).is_err());
        let mut completed = q.clone();
        completed["registered_retry11_holding"]["stage"] = json!("completed-copy");
        funding(&completed, &f, head, false).unwrap();
        for (key, value) in [
            ("fits", json!(false)),
            ("available_HOME_bytes", json!(0)),
            ("available_memory_bytes", json!(0)),
            ("resource_credit_bytes", json!(1)),
            ("registered_cold168_holding", json!({})),
        ] {
            let mut wrong = completed.clone();
            wrong[key] = value;
            assert!(funding(&wrong, &f, head, false).is_err());
        }
        let mut limits = f.clone();
        limits["retry9_auxiliary_commitments"]["holding_cpu_quota_micros"] = json!(3_000_000);
        assert!(funding(&completed, &limits, head, false).is_err());
    }
}
