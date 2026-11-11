//! Root-owned, isolated source prerequisite. No production aliases or remote clients.
#![deny(warnings)]
#[allow(dead_code)]
mod evidence;
mod reader_guards;
use reader_guards::*;
mod root_outer;
use root_outer::*;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{fs::{MetadataExt, OpenOptionsExt, PermissionsExt}, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const UNIT: &str = "horizon-uploader-cap-transition-fixture-20261111-v2.service";
const SLICE: &str = "horizon_uploader_cap_transition_20261111_v2.slice";
const OWN_UNIT: &str = "horizon-uploader-cap-transition-controller-20261111-v2.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-uploader-cap-transition-20261111-v2";
const RUNTIME: &str = "/usr/local/lib/jetstreamer/horizon-uploader-cap-transition-controller-20261111-v4/runner";
const OLD_READER: &str = "/usr/local/lib/jetstreamer/horizon-uploader-cap-transition-uncapped-20261111-v2/census";
const NEW_READER: &str = "/usr/local/lib/jetstreamer/horizon-uploader-cap-transition-capped-20261111-v2/census";
const WAITER: &str = "/usr/local/lib/jetstreamer/horizon-uploader-freeze-fixture-tools-20261103-v1/waiter";
const WAITER_SHA: &str = "a1d7a196a35fb7129b55f9c6604b0fb2d1806ed5f9234d03e84a7078bef82a00";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const FIXTURE_SLICE: &str = "horizon_uploader_cap_transition_20261111_v2-fixture.slice";
const SHARED: u64 = 1 << 30;
const CAP: u64 = 128 << 20;
const OLD_WAITER_ROOT: &str = "/var/lib/jetstreamer/horizon-uploader-freeze-fixture-positive-20261103-v1-waiter-v5";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound { path: PathBuf, sha256: String }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bindings {
    schema: String,
    booking: Bound,
    old_reader: Bound,
    capped_reader: Bound,
    service_template: Bound,
    slice_template: Bound,
    fixture_slice_template: Bound,
    sealer: Bound,
    waiter_source: Bound,
    native16_exclusive_lock: PathBuf,
    compiler_cgroups: Vec<PathBuf>,
    old_reader_acceptance: Bound,
    capped_reader_acceptance: Bound,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan { schema: String, bindings: Bindings, source_freeze: Bound, controller_acceptance: Bound, root_outer: RootOuter, output: PathBuf }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RootOuter { unit: String, invocation_id: String, main_pid: u32, start_ticks: u64, control_group: String }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrivateLog { path: PathBuf, device: u64, inode: u64 }
#[derive(Clone, Debug, PartialEq, Eq)]
struct LogMetadata { regular: bool, device: u64, inode: u64, uid: u32, gid: u32, mode: u32, links: u64, bytes: u64 }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReaderStartIntent { schema: String, unit: String, reader: Bound, plan: Bound, command_line: Vec<String>, expected_control_group: String, stdout: PrivateLog, stderr: PrivateLog, recorded_unix_seconds: u64 }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReaderWitness { schema: String, unit: String, invocation_id: String, start_intent: Bound, native: Value, recorded_unix_seconds: u64 }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity { invocation_id: String, main_pid: u32, start_ticks: u64 }
struct Runner { sequence: u32, deadline: Instant }
fn now() -> Result<u64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()) }
fn root() -> PathBuf { ROOT.into() }
fn unit_path() -> PathBuf { Path::new("/etc/systemd/system").join(UNIT) }
fn own_unit_path() -> PathBuf { Path::new("/etc/systemd/system").join(OWN_UNIT) }
fn slice_path() -> PathBuf { Path::new("/etc/systemd/system").join(SLICE) }
fn cg() -> PathBuf { Path::new("/sys/fs/cgroup").join(SLICE).join(FIXTURE_SLICE).join(UNIT) }
fn fixture_slice_path() -> PathBuf { Path::new("/etc/systemd/system").join(FIXTURE_SLICE) }
fn controls() -> PathBuf { Path::new("/run/systemd/system.control").join(format!("{UNIT}.d")) }
fn phase_destination(name: &str) -> PathBuf {
    Path::new("/usr/local/lib/jetstreamer").join(format!("horizon-uploader-cap-transition-{name}-plan-20261111-v2"))
}
fn bound(path: &Path, maximum: u64, immutable: bool) -> Result<Bound> {
    let raw = bounded(path, maximum)?;
    let b = Bound { path: path.into(), sha256: evidence::sha(&raw) };
    evidence::bound_file(path, &b.sha256, maximum, immutable)?;
    Ok(b)
}
fn bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path)?;
    let mut raw = Vec::new();
    (&mut f).take(max + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() as u64 <= max, "input bound exceeded");
    Ok(raw)
}
fn exact(b: &Bound, max: u64) -> Result<Vec<u8>> { evidence::bound_file(&b.path, &b.sha256, max, true) }
fn json_bound(b: &Bound) -> Result<Value> { Ok(serde_json::from_slice(&exact(b, 4 << 20)?)?) }
fn receipt(name: &str, v: &Value) -> Result<Bound> {
    let path = root().join(name);
    evidence::write_receipt(&path, v)?;
    bound(&path, 4 << 20, false)
}
fn mkdir(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    File::open(path)?.sync_all()?;
    File::open(path.parent().context("parent")?)?.sync_all()?;
    Ok(())
}
fn write_new(path: &Path, raw: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new().create_new(true).write(true).mode(mode).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    f.write_all(raw)?; f.sync_all()?;
    ensure!(f.metadata()?.mode() & 0o777 == mode, "unexpected new file mode");
    File::open(path.parent().context("parent")?)?.sync_all()?;
    Ok(())
}
fn bind_shape(p: &Plan, self_sha: &str) -> Result<()> {
    ensure!(p.schema == "horizon-isolated-cap-transition-plan-v2" && p.output == root().join("RESULT.json"), "foreign run plan");
    let compiled: Bindings = serde_json::from_str(include_str!("compiled-bindings.json"))?;
    ensure!(p.bindings == compiled && compiled.schema == "horizon-isolated-cap-transition-bindings-v1", "actual Root bindings not compiled into runner");
    let b = &p.bindings;
    ensure!(b.waiter_source.sha256 == "4e021521dceea4c3ab535509cc7781cb00d8a1e3a465814f50d0d7ad03e30815", "actual sealed waiter source lineage differs");
    ensure!(b.old_reader.path == Path::new(OLD_READER) && b.capped_reader.path == Path::new(NEW_READER), "foreign reader");
    ensure!(b.sealer.path == Path::new(SEALER) && b.sealer.sha256 == SEALER_SHA, "foreign normal sealer");
    ensure!(!b.compiler_cgroups.is_empty() && b.compiler_cgroups.len() <= 64, "explicit compiler exclusion list required");
    let unique = b.compiler_cgroups.iter().collect::<BTreeSet<_>>();
    ensure!(unique.len() == b.compiler_cgroups.len(), "duplicate compiler cgroup");
    for c in &b.compiler_cgroups {
        ensure!(c.starts_with("/sys/fs/cgroup") && c != Path::new("/sys/fs/cgroup") && !c.components().any(|x| x == std::path::Component::ParentDir), "foreign compiler cgroup");
    }
    for q in [&b.booking, &p.source_freeze, &b.old_reader_acceptance, &b.capped_reader_acceptance, &p.controller_acceptance] { json_bound(q)?; }
    for q in [&b.service_template, &b.slice_template, &b.fixture_slice_template, &b.waiter_source] { exact(q, 65536)?; }
    for q in [&b.old_reader, &b.capped_reader, &b.sealer] { exact(q, 64 << 20)?; }
    evidence::bound_file(Path::new(WAITER), WAITER_SHA, 64 << 20, true)?;
    let booking = json_bound(&b.booking)?;
    validate_transition_booking(&booking,&p.root_outer)?;
    for (q, image) in [(&b.old_reader_acceptance, &b.old_reader), (&b.capped_reader_acceptance, &b.capped_reader)] {
        let a = json_bound(q)?;
        ensure!(a["four_strict_configurations_passed"] == true && a["normal_seal_verified"] == true && a["accepted_image"] == serde_json::to_value(image)?, "reader actual acceptance not bound");
    }
    let a = json_bound(&p.controller_acceptance)?;
    ensure!(a["four_strict_configurations_passed"] == true && a["normal_seal_verified"] == true && a["accepted_image"] == json!({"path":RUNTIME,"sha256":self_sha}) && a["source_freeze"] == serde_json::to_value(&p.source_freeze)?, "controller actual qualification absent");
    let predecessor = json_bound(&b.capped_reader_acceptance)?;
    ensure!(predecessor["actual_fixture_predecessor"] == serde_json::to_value(&b.old_reader)?, "new reader not bound to actual accepted fixture predecessor");
    let source = json_bound(&p.source_freeze)?;
    let files = source["members"].as_array().context("source freeze exact members")?;
    ensure!(!files.is_empty() && files.len() <= 64, "source freeze size");
    let mut seen = BTreeSet::new();
    for f in files {
        let q: Bound = serde_json::from_value(f.clone())?;
        ensure!(seen.insert(q.path.clone()), "duplicate source member");
        exact(&q, 8 << 20)?;
    }
    Ok(())
}
fn lock(p: &Plan) -> Result<File> {
    let path = &p.bindings.native16_exclusive_lock;
    ensure!(path.is_absolute() && path.canonicalize()? == *path, "noncanonical lock");
    let f = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let m = f.metadata()?;
    ensure!(m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o077 == 0, "unsafe retained pool lock");
    ensure!(unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX | libc::LOCK_NB) } == 0, "native16 pool is already in use");
    Ok(f)
}
fn no_compiler(p: &Plan) -> Result<()> {
    for c in &p.bindings.compiler_cgroups {
        if c.try_exists()? {
            ensure!(c.canonicalize()? == *c, "compiler path escape");
            let events = String::from_utf8(bounded(&c.join("cgroup.events"), 65536)?)?;
            ensure!(events.lines().any(|s| s == "populated 0"), "active compiler cgroup");
        }
    }
    Ok(())
}
impl Runner {
    fn new() -> Self { Self { sequence: 0, deadline: Instant::now() + Duration::from_secs(120) } }
    fn command(&mut self, program: &Path, args: &[String], seconds: u64) -> Result<Vec<u8>> {
        ensure!(Instant::now() < self.deadline, "transaction deadline reached");
        self.sequence += 1;
        // Each invocation uses a separate immutable no-clobber command ledger.
        let stem = format!("command-{:03}-{}", self.sequence, unsafe { libc::getpid() });
        receipt(&format!("{stem}-intent.json"), &json!({"program":program,"args":args,"clock":now()?}))?;
        let out_path = root().join(format!("{stem}.stdout"));
        let err_path = root().join(format!("{stem}.stderr"));
        let out = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&out_path)?;
        let err = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&err_path)?;
        let mut child = Command::new(program).args(args).env_clear().env("PATH", "/usr/bin:/bin").env("LANG", "C.UTF-8")
            .process_group(0).stdin(Stdio::null()).stdout(Stdio::from(out)).stderr(Stdio::from(err)).spawn()?;
        let until = self.deadline.min(Instant::now() + Duration::from_secs(seconds));
        let mut timed_out = false;
        let status = loop {
            if let Some(s) = child.try_wait()? { break s; }
            if Instant::now() >= until {
                timed_out = true;
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL); }
                break child.wait()?;
            }
            thread::sleep(Duration::from_millis(10));
        };
        File::open(&out_path)?.sync_all()?; File::open(&err_path)?.sync_all()?;
        let stdout = bounded(&out_path, 1 << 20)?;
        let stderr = bounded(&err_path, 1 << 20)?;
        receipt(&format!("{stem}-result.json"), &json!({"status":status.code(),"timed_out":timed_out,"stdout":bound(&out_path,1<<20,false)?,"stderr":bound(&err_path,1<<20,false)?,"clock":now()?}))?;
        ensure!(!timed_out && status.success(), "child failed or exceeded finite bound: {}", program.display());
        ensure!(stderr.is_empty(), "child emitted stderr; retained in command ledger");
        Ok(stdout)
    }
    fn ctl(&mut self, args: &[&str], seconds: u64) -> Result<Vec<u8>> {
        self.command(Path::new("/usr/bin/systemctl"), &args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(), seconds)
    }
    fn show(&mut self, unit: &str, keys: &str) -> Result<Value> {
        let raw = self.ctl(&["show", unit, "--no-pager", &format!("--property={keys}")], 5)?;
        let mut map = serde_json::Map::new();
        for l in std::str::from_utf8(&raw)?.lines() {
            let (k,v) = l.split_once('=').context("native field")?;
            ensure!(map.insert(k.into(), json!(v)).is_none(), "duplicate native field");
        }
        Ok(map.into())
    }
    fn seal_plan(&mut self, p: &Plan, phase: &str, value: &Value) -> Result<Bound> {
        let input = receipt(&format!("{phase}-plan-source.json"), value)?;
        let dest = phase_destination(phase);
        ensure!(!dest.try_exists()?, "phase deployment already exists");
        let plan = receipt(&format!("{phase}-seal-plan.json"), &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":[{"source":input.path,"name":"plan.json","sha256":input.sha256,"mode":292}]}))?;
        exact(&p.bindings.sealer, 64 << 20)?;
        self.command(&p.bindings.sealer.path, &[plan.path.display().to_string(),"--plan-sha256".into(),plan.sha256.clone(),"--self-sha256".into(),SEALER_SHA.into()], 5)?;
        let result = Bound { path: dest.join("plan.json"), sha256: input.sha256 };
        exact(&result, 65536)?;
        let seal = bound(&dest.join("deployment-seal-receipt.json"), 4 << 20, true)?;
        let actual_seal: Value = serde_json::from_slice(&exact(&seal,4<<20)?)?;
        ensure!(actual_seal["schema"]=="jetstreamer-sealed-deployment-receipt-v1" && actual_seal["plan_sha256"]==plan.sha256 && actual_seal["sealer_sha256"]==SEALER_SHA && actual_seal["destination"]==dest.display().to_string() && actual_seal["members"].as_array().is_some_and(|v|v.len()==1) && actual_seal["members"][0]["sha256"]==result.sha256 && actual_seal["members"][0]["name"]=="plan.json" && actual_seal["members"][0]["mode"]=="0444", "normal seal receipt differs");
        receipt(&format!("{phase}-normal-seal-bound.json"), &json!({"plan":result,"receipt":seal}))?;
        Ok(result)
    }
    fn reader(&mut self, reader: &Bound, plan: &Bound, output: &Path) -> Result<Bound> {
        ensure!(!output.try_exists()?, "reader output collision");
        exact(reader, 64 << 20)?; exact(plan, 65536)?;
        let started = Instant::now();
        let phase=output.file_stem().and_then(|v|v.to_str()).context("reader phase")?;
        ensure!(["old-idle","old-frozen","capped-frozen","capped-idle"].contains(&phase),"foreign reader phase");
        let unit=format!("horizon-uploader-cap-transition-reader-{phase}-20261111-v2.service");
        let stdout=root().join(format!("reader-{phase}.stdout"));
        let stderr=root().join(format!("reader-{phase}.stderr"));
        let intent=ReaderStartIntent{schema:"horizon-isolated-reader-start-intent-v2".into(),unit:unit.clone(),reader:reader.clone(),plan:plan.clone(),command_line:vec![reader.path.display().to_string(),plan.path.display().to_string(),plan.sha256.clone(),reader.sha256.clone()],expected_control_group:format!("/{SLICE}/{unit}"),stdout:new_private_log(&stdout)?,stderr:new_private_log(&stderr)?,recorded_unix_seconds:now()?};
        validate_reader_intent(phase,&intent,reader)?;
        let intent_bound=receipt(&format!("READER-{phase}-START-INTENT.json"),&serde_json::to_value(&intent)?)?;
        let mut args=vec!["--quiet".into(),"--no-block".into(),format!("--unit={unit}"),"--service-type=exec".into(),format!("--slice={SLICE}")];
        for property in ["User=root","Group=root","UMask=0022","MemoryMax=134217728","MemorySwapMax=0","TasksMax=32","Restart=no","RemainAfterExit=yes","RuntimeMaxSec=29s","LimitFSIZE=4194304","LimitCORE=0","NoNewPrivileges=yes","PrivateNetwork=yes","ProtectControlGroups=yes","ProtectSystem=strict","ProtectHome=read-only"] {args.extend(["-p".into(),property.into()]);}
        for property in [format!("ReadWritePaths={ROOT}"),format!("StandardOutput=append:{}",stdout.display()),format!("StandardError=append:{}",stderr.display())] {args.extend(["-p".into(),property]);}
        args.extend([reader.path.display().to_string(),plan.path.display().to_string(),plan.sha256.clone(),reader.sha256.clone()]);
        self.command(Path::new("/usr/bin/systemd-run"), &args, 5)?;
        let keys="Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainCode,ExecMainStatus,Result,NRestarts,MemoryMax,MemorySwapMax,ControlGroup,Job";
        let mut expected_iid:Option<String>=None;
        loop {
            ensure!(started.elapsed()<Duration::from_secs(28),"reader exceeded finite capture deadline");
            let v=self.show(&unit,keys)?;
            ensure!(v["Id"]==unit && v["MemoryMax"]=="134217728" && v["MemorySwapMax"]=="0" && v["NRestarts"]=="0", "reader native envelope differs");
            if let Some(iid)=v["InvocationID"].as_str().filter(|s|s.len()==32) {
                if let Some(expected)=&expected_iid {ensure!(iid==expected.as_str(),"reader invocation changed");}
                else {
                    expected_iid=Some(iid.to_owned());
                    let witness=ReaderWitness{schema:"horizon-isolated-reader-identity-v2".into(),unit:unit.clone(),invocation_id:iid.to_owned(),start_intent:intent_bound.clone(),native:v.clone(),recorded_unix_seconds:now()?};
                    receipt(&format!("READER-{phase}-IDENTITY.json"),&serde_json::to_value(witness)?)?;
                }
            }
            if v["SubState"]=="exited" || v["ActiveState"]=="failed" || v["ActiveState"]=="inactive" {
                receipt(&format!("READER-{phase}-TERMINAL-NATIVE.json"),&json!({"native":v,"clock":now()?}))?;
                ensure_reader_terminated(&v)?; reader_cgroup_empty(&intent)?;
                let stdout_final=sync_private_log(&intent.stdout)?;
                let stderr_final=sync_private_log(&intent.stderr)?;
                receipt(&format!("READER-{phase}-TERMINAL.json"),&json!({"native":v,"stdout":stdout_final,"stderr":stderr_final,"diagnostic_bytes_fsynced_after_termination":true,"clock":now()?}))?;
                ensure!(expected_iid.is_some() && v["ActiveState"]=="active" && v["SubState"]=="exited" && v["Result"]=="success" && v["ExecMainCode"]=="1" && v["ExecMainStatus"]=="0" && v["MainPID"]=="0" && v["ControlPID"]=="0", "reader did not exit successfully");
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        ensure!(started.elapsed()<Duration::from_secs(30),"capture exceeded strict30seconds");
        bound(output, 1 << 20, false)
    }

}
fn own_envelope(r: &mut Runner) -> Result<()> {
    let expected_pid=unsafe{libc::getpid()}.to_string();
    let expected_shared=SHARED.to_string();
    let x = r.show(OWN_UNIT, "Id,ActiveState,SubState,MainPID,ControlGroup,MemoryMax,MemorySwapMax,Restart,NRestarts")?;
    ensure!(x["Id"] == OWN_UNIT && x["ActiveState"] == "active" && x["SubState"] == "running" && x["MainPID"] == expected_pid
        && x["ControlGroup"] == format!("/{SLICE}/{OWN_UNIT}") && x["MemoryMax"] == "536870912" && x["MemorySwapMax"] == "0" && x["Restart"] == "no" && x["NRestarts"] == "0", "controller must run in exact bounded outer slice");
    let s = r.show(SLICE, "Id,ActiveState,MemoryMax,MemorySwapMax")?;
    ensure!(s["Id"] == SLICE && s["ActiveState"] == "active" && s["MemoryMax"] == expected_shared && s["MemorySwapMax"] == "0", "aggregate outer slice not1GiB");
    let raw = String::from_utf8(bounded(Path::new("/proc/self/cgroup"),65536)?)?;
    ensure!(raw.trim() == format!("0::/{SLICE}/{OWN_UNIT}"), "controller kernel cgroup differs");
    let outer = Path::new("/sys/fs/cgroup").join(SLICE);
    ensure!(String::from_utf8(bounded(&outer.join("memory.max"),64)?)?.trim() == SHARED.to_string(), "outer kernel bound differs");
    Ok(())
}
fn start_ticks(pid: u32) -> Result<u64> {
    let raw = String::from_utf8(bounded(&PathBuf::from(format!("/proc/{pid}/stat")),65536)?)?;
    let (_,tail) = raw.rsplit_once(')').context("process birth")?;
    Ok(tail.split_whitespace().nth(19).context("short stat")?.parse()?)
}
fn identity(r: &mut Runner) -> Result<(Identity, Value)> {
    let v = r.show(UNIT, "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,ExecStart,ControlGroup,Restart,RestartUSec,MemoryMax,MemorySwapMax,TasksMax,MemoryAccounting,NoNewPrivileges,ProtectControlGroups,User,Group,OOMPolicy,FragmentPath,DropInPaths,FreezerState")?;
    ensure!(v["Id"] == UNIT && v["LoadState"] == "loaded" && v["ActiveState"] == "active" && v["SubState"] == "running" && v["NRestarts"] == "0" && v["ControlPID"] == "0" && v["ControlGroup"] == format!("/{SLICE}/{FIXTURE_SLICE}/{UNIT}"), "fixture owner differs");
    for (k,w) in [("Restart","on-failure"),("RestartUSec","30s"),("MemorySwapMax","0"),("TasksMax","256"),("MemoryAccounting","yes"),("NoNewPrivileges","yes"),("ProtectControlGroups","yes"),("User","sol"),("Group","horizon"),("OOMPolicy","stop")] { ensure!(v[k] == w,"baseline native property differs:{k}"); }
    ensure!(v["FragmentPath"] == unit_path().display().to_string(), "foreign fixture fragment");
    let main_pid: u32 = v["MainPID"].as_str().context("pid")?.parse()?;
    let invocation_id = v["InvocationID"].as_str().context("iid")?.to_owned();
    ensure!(main_pid > 1 && invocation_id.len() == 32 && invocation_id.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "bad fixture identity");
    Ok((Identity { invocation_id, main_pid, start_ticks:start_ticks(main_pid)? },v))
}
fn assert_identity(r: &mut Runner, expected: &Identity) -> Result<Value> {
    let (actual,v) = identity(r)?; ensure!(&actual == expected, "fixture restarted or process birth changed"); Ok(v)
}
fn installed(p: &Plan) -> Result<()> {
    for (path,b) in [(unit_path(),&p.bindings.service_template),(slice_path(),&p.bindings.slice_template),(fixture_slice_path(),&p.bindings.fixture_slice_template)] {
        evidence::bound_file(&path,&b.sha256,65536,true)?;
    }
    Ok(())
}
fn own_unit_source(plan: &Bound, self_sha: &str) -> Result<Vec<u8>> {
    let path=plan.path.to_str().context("run plan path UTF8")?;
    ensure!(path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)) && evidence::is_sha(&plan.sha256) && evidence::is_sha(self_sha),"unsafe generated controller arguments");
    Ok(include_str!("controller.service.template").replace("ROOT_SEALED_RUN_PLAN",path).replace("ROOT_ACTUAL_RUN_PLAN_SHA",&plan.sha256).replace("ROOT_ACTUAL_SELF_SHA",self_sha).into_bytes())
}
fn prepare(p: &Plan, plan: &Bound, self_sha: &str) -> Result<()> {
    for path in [root(),unit_path(),own_unit_path(),slice_path(),fixture_slice_path(),unit_path().with_extension("service.d"),controls(),Path::new("/run/systemd/system").join(UNIT),Path::new("/run/systemd/transient").join(UNIT),Path::new("/sys/fs/cgroup").join(SLICE)] {
        ensure!(!path.try_exists()?, "new isolated fixture artifact already exists:{}",path.display());
    }
    for phase in ["old-idle","old-frozen","capped-frozen","capped-idle"] { ensure!(!phase_destination(phase).try_exists()?,"phase already published"); }
    // No state exists until all static filesystem collision checks pass.
    mkdir(&root(),0o700)?;
    let mut r = Runner::new();
    let outer=root_outer_envelope(p,&mut r,true)?;
    receipt("ACTUAL-SEPARATE-ROOT-OUTER-PREPARE.json",&outer)?;
    let absent = r.show(UNIT,"Id,LoadState,ActiveState,MainPID,ControlPID,Job")?;
    ensure!(absent["LoadState"] == "not-found" && absent["ActiveState"] == "inactive" && absent["MainPID"] == "0" && absent["ControlPID"] == "0" && absent["Job"] == "", "fixture is already loaded, queued or running");
    let own_absent=r.show(OWN_UNIT,"LoadState,ActiveState,MainPID,ControlPID,Job")?;
    ensure!(own_absent["LoadState"]=="not-found" && own_absent["ActiveState"]=="inactive" && own_absent["MainPID"]=="0" && own_absent["ControlPID"]=="0" && own_absent["Job"]=="","controller already exists before preparation");
    for phase in ["old-idle","old-frozen","capped-frozen","capped-idle"] {
        let name=format!("horizon-uploader-cap-transition-reader-{phase}-20261111-v2.service");
        let reader_absent=r.show(&name,"LoadState,ActiveState,MainPID,ControlPID,Job")?;
        ensure!(reader_absent["LoadState"]=="not-found" && reader_absent["ActiveState"]=="inactive" && reader_absent["MainPID"]=="0" && reader_absent["ControlPID"]=="0" && reader_absent["Job"]=="","named reader already exists");
    }
    no_compiler(p)?;
    receipt("PREPARATION-INTENT.json", &json!({"schema":"horizon-isolated-cap-transition-preparation-v1","plan":plan,"self_sha256":self_sha,"bindings":p.bindings,"absent_before_setup":absent,"clock":now()?}))?;
    mkdir(&root().join("waiter"),0o700)?;
    let c = std::ffi::CString::new(root().join("waiter").as_os_str().as_encoded_bytes())?;
    ensure!(unsafe {libc::chown(c.as_ptr(),1001,1003)} == 0,"fixture waiter ownership");
    File::open(root().join("waiter"))?.sync_all()?;
    for (path,b) in [(unit_path(),&p.bindings.service_template),(slice_path(),&p.bindings.slice_template),(fixture_slice_path(),&p.bindings.fixture_slice_template)] { write_new(&path,&exact(b,65536)?,0o444)?; }
    let own_source=own_unit_source(plan,self_sha)?;
    write_new(&own_unit_path(),&own_source,0o444)?;
    r.ctl(&["daemon-reload"],30)?;
    installed(p)?;
    receipt("PREPARED.json",&json!({"schema":"horizon-isolated-cap-transition-prepared-v1","plan":plan,"self_sha256":self_sha,"bindings":p.bindings,"fixture_started":false,"clock":now()?}))?;
    Ok(())
}
fn authentic_preparation(p: &Plan, plan: &Bound, self_sha: &str) -> Result<()> {
    let b = bound(&root().join("PREPARED.json"),1<<20,false)?;
    let v: Value = serde_json::from_slice(&evidence::bound_file(&b.path,&b.sha256,1<<20,false)?)?;
    ensure!(v["schema"] == "horizon-isolated-cap-transition-prepared-v1" && v["plan"] == serde_json::to_value(plan)? && v["self_sha256"] == self_sha && v["bindings"] == serde_json::to_value(&p.bindings)?,"foreign preparation");
    installed(p)?;
    let expected=evidence::sha(&own_unit_source(plan,self_sha)?);
    evidence::bound_file(&own_unit_path(),&expected,65536,true)?;
    Ok(())
}
fn old_plan(id: &Identity, native: &Value, frozen: bool, predecessor: Option<&Bound>) -> Value {
    json!({"schema":"horizon-uploader-freeze-census-plan-v1","unit":UNIT,"invocation_id":id.invocation_id,"main_pid":id.main_pid,"start_ticks":id.start_ticks,"kind":"coordinator","program":{"path":WAITER,"sha256":WAITER_SHA},"wrapper":{"path":WAITER,"sha256":WAITER_SHA},"command_line":[WAITER,"idle"],"expected_exec_start":native["ExecStart"],"expected_control_group":format!("/{SLICE}/{FIXTURE_SLICE}/{UNIT}"),"memory_max":"infinity","uid":1001,"gid":1003,"sleep_child":null,"frozen":frozen,"pre_freeze_receipt":predecessor,"output":root().join(if frozen {"old-frozen.json"} else {"old-idle.json"}),"source_files":[{"path":unit_path(),"sha256":native["source_sha256"]}]})
}
fn fresh(b: &Bound, max_age: u64) -> Result<()> {
    let v: Value = serde_json::from_slice(&evidence::bound_file(&b.path,&b.sha256,1<<20,false)?)?;
    let t=v["recorded_unix_seconds"].as_u64().context("proof time")?;
    ensure!(now()?.checked_sub(t).is_some_and(|x|x<=max_age),"original frozen evidence too old"); Ok(())
}
fn preserve_controls() -> Result<Vec<Bound>> {
    let mut found=Vec::new();
    if !controls().try_exists()? { return Ok(found); }
    ensure!(controls().canonicalize()? == controls(),"runtime source escape");
    for entry in fs::read_dir(controls())? {
        let path=entry?.path();
        let name=path.file_name().context("runtime file")?.to_str().context("runtime name")?;
        ensure!(["50-MemoryMax.conf","50-MemorySwapMax.conf"].contains(&name),"undeclared runtime property file");
        let b=bound(&path,65536,false)?;
        let saved=root().join(format!("actual-generated-{name}"));
        if saved.try_exists()? { ensure!(bounded(&saved,65536)?==bounded(&path,65536)?,"generated controls changed after retention"); }
        else { write_new(&saved,&bounded(&path,65536)?,0o444)?; }
        found.push(b);
    }
    found.sort_by(|a,b|a.path.cmp(&b.path));
    Ok(found)
}
fn saved(name: &str) -> Result<Value> {
    let b=bound(&root().join(name),1<<20,false)?;
    Ok(serde_json::from_slice(&evidence::bound_file(&b.path,&b.sha256,1<<20,false)?)?)
}
fn drain_readers(p: &Plan, r: &mut Runner) -> Result<Value> {
    let mut rows=Vec::new();
    let mut errors=Vec::new();
    for phase in ["old-idle","old-frozen","capped-frozen","capped-idle"] {
        let intent_path=root().join(format!("READER-{phase}-START-INTENT.json"));
        if !intent_path.try_exists()? {continue;}
        let attempted=(|| -> Result<Value> {
            let intent_bound=bound(&intent_path,1<<20,false)?;
            let intent:ReaderStartIntent=serde_json::from_slice(&evidence::bound_file(&intent_path,&intent_bound.sha256,1<<20,false)?)?;
            let expected_reader=if phase.starts_with("old-"){&p.bindings.old_reader}else{&p.bindings.capped_reader};
            validate_reader_intent(phase,&intent,expected_reader)?;
            exact(&intent.reader,64<<20)?; exact(&intent.plan,65536)?;
            let unit=&intent.unit;
            let before=r.show(unit,"Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,Result,NRestarts,ControlGroup,MemoryMax,MemorySwapMax,Job")?;
            receipt(&format!("READER-{phase}-PRESTOP-{}.json",unsafe{libc::getpid()}),&json!({"native":before,"start_intent":intent_bound,"clock":now()?}))?;
            let witness_path=root().join(format!("READER-{phase}-IDENTITY.json"));
            let witness=if witness_path.try_exists()? {
                let b=bound(&witness_path,1<<20,false)?;
                Some(serde_json::from_slice::<ReaderWitness>(&evidence::bound_file(&b.path,&b.sha256,1<<20,false)?)?)
            }else{None};
            if let Err(error)=validate_reader_cleanup_owner(&before,witness.as_ref(),&intent_bound,&intent) {
                receipt(&format!("READER-{phase}-STOP-REFUSED-{}.json",unsafe{libc::getpid()}),&json!({"native":before,"start_intent":intent_bound,"error":format!("{error:#}"),"reader_stop_authorized":false,"final_logs_bound":false,"clock":now()?}))?;
                return Err(error);
            }
            // No stop is sent before the exact initial witness and typed intent
            // authenticate this IID. Unknown invocations are never recovered by name.
            let after=if before["LoadState"]=="not-found" {before.clone()}else{
                r.ctl(&["stop",unit],5)?;
                r.show(unit,"Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job")?
            };
            ensure!(after["ActiveState"]=="inactive","reader did not become inactive");
            ensure_reader_terminated(&after)?; reader_cgroup_empty(&intent)?;
            // PID1 may append during termination. Sync only after native and
            // kernel drainage, then hash those exact initial private log inodes.
            let stdout=sync_private_log(&intent.stdout)?;
            let stderr=sync_private_log(&intent.stderr)?;
            let final_record=json!({"before":before,"after":after,"start_intent":intent_bound,"stdout":stdout,"stderr":stderr,"diagnostic_bytes_fsynced_after_termination":true,"clock":now()?});
            receipt(&format!("READER-{phase}-DRAINED-{}.json",unsafe{libc::getpid()}),&final_record)?;
            Ok(final_record)
        })();
        match attempted {Ok(v)=>rows.push(v),Err(e)=>errors.push(format!("{phase}: {e:#}"))}
    }
    receipt(&format!("READER-DRAIN-{}.json",unsafe{libc::getpid()}),&json!({"rows":rows,"errors":errors,"clock":now()?}))?;
    ensure!(errors.is_empty(),"reader drainage failed: {}",errors.join("; "));
    Ok(json!(rows))
}

fn cleanup(p: &Plan, r: &mut Runner) -> Result<Value> {
    installed(p)?;
    // Retain actual systemctl-generated bytes even when a later capture fails.
    let retained=preserve_controls();
    let readers=drain_readers(p,r);
    let state=r.show(UNIT,"Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,ExecMainPID,ExecMainCode,ExecMainStatus,Result,ControlGroup,FragmentPath,FreezerState")?;
    receipt(&format!("FIXTURE-PRESTOP-{}.json",unsafe{libc::getpid()}),&json!({"native":state,"clock":now()?}))?;
    if root().join("STARTED-IDENTITY.json").try_exists()? {
        let prior=saved("STARTED-IDENTITY.json")?;
        ensure!(state["InvocationID"]==prior["native"]["InvocationID"] || (state["InvocationID"]=="" && state["MainPID"]=="0" && state["ControlPID"]=="0"),"fixture cleanup crossed invocation");
        if state["MainPID"]!="0" {
            ensure!(state["MainPID"]==prior["native"]["MainPID"],"fixture cleanup PID differs");
            let pid=state["MainPID"].as_str().context("cleanup pid")?.parse()?;
            ensure!(Some(start_ticks(pid)?)==prior["start_ticks"].as_u64(),"fixture cleanup birth differs");
        }
    } else if state["MainPID"]!="0" {
        ensure!(root().join("START-INTENT.json").try_exists()?,"unexpected live fixture without this transaction's start intent");
        let pid=state["MainPID"].as_str().context("recovery pid")?.parse()?;
        ensure!(fs::read_link(format!("/proc/{pid}/exe"))?==Path::new(WAITER),"recovery fixture image differs");
        evidence::bound_file(Path::new(WAITER),WAITER_SHA,64<<20,true)?;
        receipt(&format!("RECOVERED-START-IDENTITY-{}.json",unsafe{libc::getpid()}),&json!({"native":state,"start_ticks":start_ticks(pid)?,"not_accepted_capture_identity":true,"clock":now()?}))?;
    }
    ensure!(state["Id"]==UNIT && state["FragmentPath"]==unit_path().display().to_string(),"foreign cleanup target");
    if state["FreezerState"]=="frozen" { r.ctl(&["thaw",UNIT],5)?; }
    r.ctl(&["stop",UNIT],12)?;
    let after=r.show(UNIT,"Id,ActiveState,MainPID,ControlPID,Job,NRestarts")?;
    ensure!(after["ActiveState"]=="inactive" && after["MainPID"]=="0" && after["ControlPID"]=="0" && after["Job"]=="", "fixture failed to drain");
    if cg().try_exists()? {
        let events=String::from_utf8(bounded(&cg().join("cgroup.events"),65536)?)?;
        ensure!(events.lines().any(|x|x=="populated 0"),"fixture cgroup remains populated");
    }
    r.ctl(&["stop",FIXTURE_SLICE],5)?;
    let parent_after=r.show(FIXTURE_SLICE,"Id,ActiveState")?;
    ensure!(parent_after["Id"]==FIXTURE_SLICE && parent_after["ActiveState"]=="inactive","fixture parent did not drain");
    let actual=retained?;
    let reader_proof=readers?;
    Ok(json!({"schema":"horizon-isolated-cap-transition-drain-v1","reader_drain":reader_proof,"native_after":after,"actual_generated_controls":actual,"only_disposable_fixture_stopped":true,"clock":now()?}))
}
fn transition(p: &Plan, plan: &Bound, self_sha: &str, r: &mut Runner) -> Result<Value> {
    authentic_preparation(p,plan,self_sha)?;
    own_envelope(r)?; no_compiler(p)?;
    receipt("ACTUAL-SEPARATE-ROOT-OUTER-BEFORE.json",&root_outer_envelope(p,r,false)?)?;
    let before=r.show(UNIT,"LoadState,ActiveState,MainPID,ControlPID,Job")?;
    ensure!(before["LoadState"]=="loaded" && before["ActiveState"]=="inactive" && before["MainPID"]=="0" && before["ControlPID"]=="0" && before["Job"]=="", "fixture active before transaction");
    ensure!(!controls().try_exists()?,"runtime controls predate transaction");
    receipt("START-INTENT.json",&json!({"unit":UNIT,"plan":plan,"clock":now()?}))?;
    // Start only the bounded parent first, then prove its kernel ceiling before launching the infinity subject.
    r.ctl(&["start",FIXTURE_SLICE],5)?;
    let parent = Path::new("/sys/fs/cgroup").join(SLICE).join(FIXTURE_SLICE);
    for (file,want) in [("memory.max","268435456"),("memory.swap.max","0"),("pids.max","512")] {
        ensure!(String::from_utf8(bounded(&parent.join(file),64)?)?.trim()==want,"fixture parent not bounded before launch:{file}");
    }
    r.ctl(&["start",UNIT],5)?;
    let launched=r.show(UNIT,"Id,InvocationID,MainPID,ControlPID,NRestarts,ExecMainPID,ExecMainCode,ExecMainStatus,Result,ControlGroup,FragmentPath,ExecStart")?;
    let launched_pid:u32=launched["MainPID"].as_str().context("launched pid")?.parse()?;
    let launched_birth=start_ticks(launched_pid)?;
    receipt("STARTED-IDENTITY.json",&json!({"native":launched,"start_ticks":launched_birth,"clock":now()?}))?;
    let (id,mut native)=identity(r)?;
    ensure!(launched["InvocationID"]==id.invocation_id && launched_pid==id.main_pid && launched_birth==id.start_ticks,"fixture identity changed during initial witness");
    ensure!(native["MemoryMax"]=="infinity" && native["DropInPaths"]=="" && native["FreezerState"]=="running", "baseline is not honestly uncapped idle");
    // The immutable old waiter uses a historical pathname. Only its private mount
    // namespace maps that pathname to the new disposable witness directory.
    let mapped=fs::metadata(Path::new(&format!("/proc/{}/root",id.main_pid)).join(OLD_WAITER_ROOT.trim_start_matches('/')))?;
    let actual=fs::metadata(root().join("waiter"))?;
    ensure!(mapped.dev()==actual.dev() && mapped.ino()==actual.ino(),"old waiter pathname did not map to new witness directory");
    let started=root().join("waiter/started");
    let until=Instant::now()+Duration::from_secs(2);
    while !started.try_exists()? && Instant::now()<until {thread::sleep(Duration::from_millis(10));}
    ensure!(started.try_exists()?,"sealed waiter did not initialize isolated witness");
    native["source_sha256"]=json!(p.bindings.service_template.sha256);
    receipt("ACTUAL-IDENTITY-AND-UNCAPPED-NATIVE.json",&json!({"identity":id,"native":native,"old_waiter_path_namespaced_to_new_directory":true,"clock":now()?}))?;
    let first_plan=r.seal_plan(p,"old-idle",&old_plan(&id,&native,false,None))?;
    no_compiler(p)?;
    let first=r.reader(&p.bindings.old_reader,&first_plan,&root().join("old-idle.json"))?;
    assert_identity(r,&id)?;
    let frozen_plan=r.seal_plan(p,"old-frozen",&old_plan(&id,&native,true,Some(&first)))?;
    r.ctl(&["freeze",UNIT],5)?;
    let frozen_native=assert_identity(r,&id)?;
    ensure!(frozen_native["MemoryMax"]=="infinity" && frozen_native["FreezerState"]=="frozen", "not original uncapped frozen state");
    let retained_clock=Instant::now();
    let frozen=r.reader(&p.bindings.old_reader,&frozen_plan,&root().join("old-frozen.json"))?;
    // Only these two runtime service properties may change during the handoff.
    r.ctl(&["set-property","--runtime",UNIT,&format!("MemoryMax={CAP}"),"MemorySwapMax=0"],5)?;
    let source=preserve_controls()?;
    ensure!(source.len()==2,"actual runtime cap sources incomplete");
    receipt("ACTUAL-GENERATED-CONTROLS.json",&json!({"sources":source,"clock":now()?}))?;
    let caps=|phase:&str,previous:Option<&Bound>|json!({"schema":"horizon-uploader-capped-census-plan-v1","original_frozen_plan":frozen_plan,"original_frozen_proof":frozen,"capped_frozen_proof":previous,"phase":phase,"memory_max_bytes":CAP,"minimum_unused_bytes":64u64<<20,"runtime_cap_dropins":source,"output":root().join(format!("{phase}.json"))});
    let cap_plan=r.seal_plan(p,"capped-frozen",&caps("capped-frozen",None))?;
    fresh(&frozen,60)?; no_compiler(p)?; assert_identity(r,&id)?;
    let cap_frozen=r.reader(&p.bindings.capped_reader,&cap_plan,&root().join("capped-frozen.json"))?;
    fresh(&frozen,60)?;
    let idle_plan=r.seal_plan(p,"capped-idle",&caps("capped-idle",Some(&cap_frozen)))?;
    r.ctl(&["thaw",UNIT],5)?;
    // Polling gives the exact idle census a finite chance after thaw; no work is released.
    let wait_until=Instant::now()+Duration::from_secs(1);
    loop {
        let wchan=bounded(&PathBuf::from(format!("/proc/{}/wchan",id.main_pid)),65536)?;
        if std::str::from_utf8(&wchan)?.trim()=="hrtimer_nanosleep" {break;}
        ensure!(Instant::now()<wait_until,"fixture did not return to exact idle wait");
        thread::sleep(Duration::from_millis(5));
    }
    assert_identity(r,&id)?; no_compiler(p)?;
    let cap_idle=r.reader(&p.bindings.capped_reader,&idle_plan,&root().join("capped-idle.json"))?;
    ensure!(retained_clock.elapsed()<Duration::from_secs(60),"old-frozen handoff exceeded60seconds");
    fresh(&frozen,60)?; assert_identity(r,&id)?; no_compiler(p)?;
    receipt("ACTUAL-SEPARATE-ROOT-OUTER-AFTER.json",&root_outer_envelope(p,r,false)?)?;
    fresh(&frozen,60)?;
    Ok(json!({"schema":"horizon-isolated-cap-transition-captures-v1","identity":id,"old_idle":first,"old_frozen":frozen,"capped_frozen":cap_frozen,"capped_idle":cap_idle,"old_frozen_plan":frozen_plan,"actual_generated_controls":source,"same_invocation_pid_and_birth":true,"zero_restarts":true,"cap_bytes":CAP,"aggregate_limit_bytes":SHARED,"native16_retained":true,"successful_production_upload_under_cap_qualified":false,"all_future_shared_roles_qualified":false,"memory_credit_bytes":0,"replay_admission_authorized":false,"R2_mutations":false,"clock":now()?}))
}
fn run() -> Result<()> {
    ensure!(unsafe{libc::geteuid()}==0,"Root required");
    for k in ["DBUS_SYSTEM_BUS_ADDRESS","SYSTEMD_BUS_ADDRESS"] {ensure!(std::env::var_os(k).is_none(),"native bus override");}
    unsafe{libc::umask(0o022);}
    let a=std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(a.len()==4 && ["prepare","execute","cleanup"].contains(&a[0].as_str()),"usage prepare|execute|cleanup PLAN PLAN_SHA SELF_SHA");
    let exe=fs::read_link("/proc/self/exe")?;
    ensure!(exe==Path::new(RUNTIME),"runner not executing exact normally sealed path");
    evidence::bound_file(&exe,&a[3],64<<20,true)?;
    let plan=Bound{path:a[1].clone().into(),sha256:a[2].clone()};
    let p:Plan=serde_json::from_slice(&exact(&plan,65536)?)?;
    bind_shape(&p,&a[3])?;
    let _pool_lock=lock(&p)?;
    if a[0]=="prepare" {return prepare(&p,&plan,&a[3]);}
    authentic_preparation(&p,&plan,&a[3])?;
    if a[0]=="cleanup" {
        if root().join("DRAINED.json").try_exists()? {return Ok(());}
        let mut r=Runner::new();
        let drained=cleanup(&p,&mut r);
        match drained { Ok(v)=>{receipt("DRAINED.json",&v)?;return Ok(());},Err(e)=>{receipt(&format!("CLEANUP-FAILED-{}.json",unsafe{libc::getpid()}),&json!({"error":format!("{e:#}"),"clock":now()?}))?;return Err(e);} }
    }
    ensure!(!p.output.try_exists()? && !root().join("EXECUTION-INTENT.json").try_exists()?,"transaction already attempted");
    receipt("EXECUTION-INTENT.json",&json!({"plan":plan,"self_sha256":a[3],"clock":now()?}))?;
    let mut r=Runner::new();
    let captures=transition(&p,&plan,&a[3],&mut r);
    // Cleanup gets its own finite deadline even when capture deadline expires.
    r.deadline=Instant::now()+Duration::from_secs(30);
    let drained=cleanup(&p,&mut r);
    let success=captures.is_ok() && drained.is_ok();
    if let Ok(v)=&drained {receipt("DRAINED.json",v)?;}
    let result=json!({"schema":"horizon-isolated-cap-transition-result-v1","plan":plan,"self_sha256":a[3],"success":success,"captures":captures.as_ref().ok(),"capture_error":captures.as_ref().err().map(|e|format!("{e:#}")),"drain":drained.as_ref().ok(),"drain_error":drained.as_ref().err().map(|e|format!("{e:#}")),"production_uploader_mutations":false,"replay_mutations":false,"R2_mutations":false,"resource_credit_bytes":0,"clock":now()?});
    evidence::write_receipt(&p.output,&result)?;
    if !success {bail!("isolated transition or cleanup failed; exact errors retained in RESULT.json");}
    Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("isolated transition rejected: {e:#}");std::process::exit(1);}}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_exec_arguments_reject_directive_and_word_injection() {
        for path in ["/sealed/plan file.json", "/sealed/plan\nExecStart=/bin/false", "/sealed/plan;id", "/sealed/plan%u"] {
            let p=Bound{path:path.into(),sha256:"a".repeat(64)};
            assert!(own_unit_source(&p,&"b".repeat(64)).is_err());
        }
        let p=Bound{path:"/usr/local/lib/jetstreamer/new-plan-20261111-v1/plan.json".into(),sha256:"a".repeat(64)};
        let source=String::from_utf8(own_unit_source(&p,&"b".repeat(64)).unwrap()).unwrap();
        assert!(!source.contains("ROOT_ACTUAL_") && !source.contains("ROOT_SEALED_"));
        assert_eq!(source.lines().filter(|l|l.starts_with("ExecStart=")).count(),1);
        assert_eq!(source.lines().filter(|l|l.starts_with("ExecStopPost=")).count(),1);
    }
    #[test]
    fn original_frozen_plan_keeps_honest_uncapped_scope() {
        let id=Identity{invocation_id:"a".repeat(32),main_pid:23,start_ticks:42};
        let native=json!({"ExecStart":"actual-native-start","source_sha256":"b".repeat(64)});
        let pre=Bound{path:root().join("old-idle.json"),sha256:"c".repeat(64)};
        let mut idle=old_plan(&id,&native,false,None);
        let mut frozen=old_plan(&id,&native,true,Some(&pre));
        assert_eq!(idle["memory_max"],"infinity");
        assert_eq!(frozen["memory_max"],"infinity");
        assert_eq!(frozen["pre_freeze_receipt"],serde_json::to_value(pre).unwrap());
        for v in [&mut idle,&mut frozen] {for k in ["frozen","pre_freeze_receipt","output"] {v.as_object_mut().unwrap().remove(k);}}
        assert_eq!(idle,frozen);
    }
    #[test]
    fn unknown_binding_and_plan_fields_reject() {
        let mut b:Value=serde_json::from_str(include_str!("compiled-bindings.json")).unwrap();
        b["allow_production_unit"]=json!(true);
        assert!(serde_json::from_value::<Bindings>(b).is_err());
        let p=json!({"schema":"horizon-isolated-cap-transition-plan-v2","root_outer":{"unit":"root-outer.service","invocation_id":"a".repeat(32),"main_pid":42,"start_ticks":84,"control_group":"/system.slice/root-outer.service"},"bindings":serde_json::from_str::<Value>(include_str!("compiled-bindings.json")).unwrap(),"source_freeze":{"path":"/source","sha256":"a".repeat(64)},"controller_acceptance":{"path":"/acceptance","sha256":"b".repeat(64)},"output":root().join("RESULT.json"),"skip_freshness":true});
        assert!(serde_json::from_value::<Plan>(p).is_err());
    }
}
