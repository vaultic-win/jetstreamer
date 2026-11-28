//! Post-Main authentication only: wait for an original completed guard and
//! create exactly the Helper34 lifecycle leaf. This never releases/restarts work.
use crate::{n, storage, text};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{fd::{AsRawFd, FromRawFd}, unix::fs::{MetadataExt, OpenOptionsExt}},
    path::{Path, PathBuf},
    time::Instant,
};

pub const LIFECYCLE_ROOT: &str =
    "/var/lib/jetstreamer/horizon-epoch185-native-retained-20261105-v2";

pub fn lifecycle_output(iid: &str) -> Result<PathBuf> {
    ensure!(storage::hex(iid, 32), "lifecycle output requires exact original IID");
    Ok(Path::new(LIFECYCLE_ROOT).join(iid).join("lifecycle.json"))
}

type DirectoryIdentity = (u64, u64, u32, u32, u32);
fn directory_identity(m: &fs::Metadata) -> Result<DirectoryIdentity> {
    ensure!(m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "lifecycle directory is not a Root-owned non-writable directory");
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn open_directory(path: &Path) -> Result<File> {
    OpenOptions::new().read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path).with_context(|| format!("open exact lifecycle directory {}", path.display()))
}

pub struct LifecycleDirectory {
    parent: File,
    leaf: File,
    parent_path: PathBuf,
    path: PathBuf,
    parent_identity: DirectoryIdentity,
    identity: DirectoryIdentity,
}
impl LifecycleDirectory {
    pub fn prepare(iid: &str) -> Result<Self> {
        Self::create_at(Path::new(LIFECYCLE_ROOT), iid)
    }
    fn create_at(parent_path: &Path, iid: &str) -> Result<Self> {
        ensure!(unsafe { libc::geteuid() } == 0 && storage::hex(iid, 32),
            "Root lifecycle custody requires the exact original IID");
        ensure!(parent_path.is_absolute() && parent_path.canonicalize()? == parent_path,
            "lifecycle parent namespace alias");
        let parent = open_directory(parent_path)?;
        let parent_identity = directory_identity(&parent.metadata()?)?;
        ensure!(directory_identity(&fs::symlink_metadata(parent_path)?)? == parent_identity,
            "lifecycle parent changed before exact child creation");
        let name = CString::new(iid)?;
        let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if created != 0 {
            return Err(std::io::Error::last_os_error()).context(
                "fresh exact lifecycle leaf creation; existing names are never reused");
        }
        // No cleanup/unlink on a later error: retain this original charged leaf.
        parent.sync_all()?;
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        ensure!(fd >= 0, "cannot open newly created lifecycle leaf without following aliases");
        let leaf = unsafe { File::from_raw_fd(fd) };
        let identity = directory_identity(&leaf.metadata()?)?;
        ensure!(leaf.metadata()?.mode() & 0o7777 == 0o700 && identity.0 == parent_identity.0,
            "new lifecycle leaf must be exact0700 on its admitted parent filesystem");
        leaf.sync_all()?;
        let result = Self { parent, leaf, parent_path: parent_path.into(),
            path: parent_path.join(iid), parent_identity, identity };
        result.validate()?;
        ensure!(fs::read_dir(&result.path)?.next().is_none(), "fresh lifecycle leaf not empty");
        Ok(result)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.parent_path.canonicalize()? == self.parent_path
            && self.path.canonicalize()? == self.path,
            "lifecycle directory pathname alias or replacement");
        ensure!(directory_identity(&self.parent.metadata()?)? == self.parent_identity
            && directory_identity(&fs::symlink_metadata(&self.parent_path)?)? == self.parent_identity
            && directory_identity(&self.leaf.metadata()?)? == self.identity
            && directory_identity(&fs::symlink_metadata(&self.path)?)? == self.identity
            && self.leaf.metadata()?.mode() & 0o7777 == 0o700,
            "lifecycle directory no longer has the exact prepared Root inode/custody");
        Ok(())
    }
    pub fn writable_path(&self) -> Result<&Path> {
        self.validate()?;
        Ok(&self.path)
    }
    pub fn custody(&self) -> Result<Value> {
        self.validate()?;
        Ok(json!({"path":self.path,"parent":self.parent_path,
            "device":self.identity.0,"inode":self.identity.1,"uid":self.identity.2,
            "gid":self.identity.3,"mode":self.identity.4 & 0o7777,
            "parent_device":self.parent_identity.0,"parent_inode":self.parent_identity.1,
            "fresh_exact_leaf_created_once":true,"no_resource_credit":true}))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MainIdentity {
    pub pid: u64,
    pub start_ticks: u64,
    pub native_start_monotonic_micros: u64,
}
fn parse_stat(raw: &str, pid: u64) -> Result<u64> {
    let (head, fields) = raw.rsplit_once(')').context("MainPID proc stat close")?;
    ensure!(head.split_once('(').context("MainPID proc stat open")?.0.trim().parse::<u64>()? == pid,
        "MainPID proc stat belongs to another PID");
    let ticks = fields.split_whitespace().nth(19).context("MainPID stat start ticks")?.parse::<u64>()?;
    ensure!(ticks > 0, "MainPID stat zero start ticks");
    Ok(ticks)
}
pub fn start_ticks(pid: u64) -> Result<u64> {
    ensure!(pid > 1 && pid <= i32::MAX as u64, "invalid original MainPID");
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let mut f = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(&path)
        .with_context(|| format!("open original MainPID stat {}", path.display()))?;
    let before = f.metadata()?;
    ensure!(before.is_file(), "MainPID proc stat is not a regular kernel entry");
    let mut raw = Vec::new();
    Read::by_ref(&mut f).take(16385).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 16384, "MainPID proc stat exceeded finite bound");
    let ticks = parse_stat(std::str::from_utf8(&raw)?, pid)?;
    let after = f.metadata()?;
    let named = fs::symlink_metadata(&path)?;
    ensure!(before.dev() == after.dev() && before.ino() == after.ino()
        && after.dev() == named.dev() && after.ino() == named.ino() && named.is_file(),
        "original MainPID stat entry changed/disappeared during capture");
    Ok(ticks)
}
pub fn main_identity(native: &Value, actor: &str, iid: &str, ready: &Value) -> Result<MainIdentity> {
    ensure!(native["Id"] == actor && native["InvocationID"] == iid
        && native["ActiveState"] == "active" && native["SubState"] == "running"
        && native["ControlPID"] == "0" && native["NRestarts"] == "0" && native["Job"] == "",
        "post-Main authentication needs exact live unrestarted Main owner");
    let pid = text(native, "MainPID")?.parse::<u64>()?;
    ensure!(pid > 1 && pid != n(ready, "pid")?, "post-Main identity still names prestart ControlPID");
    let main = MainIdentity { pid, start_ticks: start_ticks(pid)?,
        native_start_monotonic_micros: text(native, "ExecMainStartTimestampMonotonic")?.parse()? };
    ensure!(main.native_start_monotonic_micros > 0, "original Main native start clock absent");
    Ok(main)
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiptDecision { WaitPrestart, AcceptMain }
pub struct GuardScope<'a> {
    pub actor: &'a str,
    pub iid: &'a str,
    pub admission: &'a str,
    pub timer: &'a str,
    pub ready: &'a Value,
    pub main: &'a MainIdentity,
}
pub fn receipt_policy(v: &Value, filename: &str, scope: &GuardScope<'_>, at: u64) -> Result<ReceiptDecision> {
    ensure!(v["schema"] == "horizon-epoch185-native-guard-result-v4" && v["epoch"] == 185
        && v["actor_unit"] == scope.actor && v["actor_invocation_id"] == scope.iid
        && v["admission_sha256"] == scope.admission && v["timer_unit"] == scope.timer
        && v["success"] == true && v["timer_driven"] == true
        && v.get("failure") == Some(&Value::Null) && v["capacity_credit_bytes"] == 0,
        "post-Main guard failed or crossed original owner/admission/timer/authority");
    let guard_iid = text(v, "guard_invocation_id")?;
    ensure!(storage::hex(guard_iid, 32) && filename == format!("guard-{guard_iid}.json"),
        "post-Main guard namespace crossed exact original invocation filename");
    let sampled = n(v, "sampled_at")?;
    ensure!(at.checked_sub(sampled).is_some_and(|age| age <= 30),
        "post-Main guard original receipt clock is future/stale");
    let trigger = n(v, "timer_last_trigger_monotonic_micros")?;
    let begin = n(v, "guard_start_monotonic_micros")?;
    ensure!(trigger > 0 && begin.checked_sub(trigger).is_some_and(|delay| delay <= 5_000_000),
        "post-Main receipt lacks unchanged native timer chronology");
    let pid = n(v, "actor_pid")?;
    let ticks = n(v, "actor_start_ticks")?;
    if pid == n(scope.ready, "pid")? && ticks == n(scope.ready, "start_ticks")? {
        return Ok(ReceiptDecision::WaitPrestart);
    }
    ensure!(pid == scope.main.pid && ticks == scope.main.start_ticks
        && begin >= scope.main.native_start_monotonic_micros
        && pid != n(scope.ready, "pid")?,
        "post-Main receipt does not bind the exact live MainPID/start ticks/start clock");
    Ok(ReceiptDecision::AcceptMain)
}

pub fn authentication_until(original: Instant, pool: Instant, at_main: Instant) -> Instant {
    // Exact existing Final4 post-release cap; no renewal after any wait or receipt.
    original.min(pool).min(at_main + std::time::Duration::from_secs(22))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy_fixture() -> (Value, Value, MainIdentity) {
        let ready = json!({"pid":200,"start_ticks":1000});
        let main = MainIdentity { pid:300,start_ticks:2000,native_start_monotonic_micros:2_000_000 };
        let v=json!({"schema":"horizon-epoch185-native-guard-result-v4","epoch":185,
            "actor_unit":"actor.service","actor_invocation_id":"a".repeat(32),"admission_sha256":"c".repeat(64),
            "timer_unit":"guard.timer","guard_invocation_id":"b".repeat(32),"sampled_at":1000,
            "success":true,"failure":null,"timer_driven":true,"capacity_credit_bytes":0,
            "actor_pid":300,"actor_start_ticks":2000,"timer_last_trigger_monotonic_micros":3_000_000,
            "guard_start_monotonic_micros":3_001_000});
        (v,ready,main)
    }
    fn check(v:&Value,ready:&Value,main:&MainIdentity,at:u64)->Result<ReceiptDecision>{
        receipt_policy(v,&format!("guard-{}.json","b".repeat(32)),&GuardScope{
            actor:"actor.service",iid:&"a".repeat(32),admission:&"c".repeat(64),
            timer:"guard.timer",ready,main},at)
    }
    #[test] fn exact_main_receipt_accepts_but_prestart_receipt_only_waits() {
        let (mut v,r,m)=policy_fixture();assert_eq!(check(&v,&r,&m,1000).unwrap(),ReceiptDecision::AcceptMain);
        v["actor_pid"]=r["pid"].clone();v["actor_start_ticks"]=r["start_ticks"].clone();
        assert_eq!(check(&v,&r,&m,1000).unwrap(),ReceiptDecision::WaitPrestart);
    }
    #[test] fn failed_guard_and_missing_failure_field_never_wait_or_capture() {
        let (v,r,m)=policy_fixture();let mut bad=v.clone();bad["success"]=false.into();assert!(check(&bad,&r,&m,1000).is_err());
        let mut bad=v;bad.as_object_mut().unwrap().remove("failure");assert!(check(&bad,&r,&m,1000).is_err());
    }
    #[test] fn main_pid_ticks_and_native_start_clock_cannot_be_crossed() {
        let (v,r,m)=policy_fixture();for (key,value) in [("actor_pid",json!(301)),("actor_start_ticks",json!(2001)),("guard_start_monotonic_micros",json!(1_999_999))] {
            let mut bad=v.clone();bad[key]=value;assert!(check(&bad,&r,&m,1000).is_err());
        }
    }
    #[test] fn namespace_owner_admission_and_timer_crossing_fail_closed() {
        let (v,r,m)=policy_fixture();for key in ["actor_unit","actor_invocation_id","admission_sha256","timer_unit","guard_invocation_id"] {
            let mut bad=v.clone();bad[key]="foreign".into();assert!(check(&bad,&r,&m,1000).is_err());
        }
    }
    #[test] fn stale_future_or_non_native_timer_clock_is_rejected() {
        let (v,r,m)=policy_fixture();assert!(check(&v,&r,&m,999).is_err());assert!(check(&v,&r,&m,1031).is_err());
        for (key,value) in [("timer_last_trigger_monotonic_micros",json!(0)),("guard_start_monotonic_micros",json!(8_000_001))] {
            let mut bad=v.clone();bad[key]=value;assert!(check(&bad,&r,&m,1000).is_err());
        }
    }
    #[test] fn lifecycle_output_uses_helper_root_and_never_registration_root() {
        let iid="a".repeat(32);let output=lifecycle_output(&iid).unwrap();
        assert_eq!(output,Path::new(LIFECYCLE_ROOT).join(&iid).join("lifecycle.json"));
        for invalid in ["../escape","a","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {assert!(lifecycle_output(invalid).is_err());}
        assert!(!output.starts_with("/var/lib/jetstreamer/horizon-epoch185-native-startpre-registrations-20261105-v1"));
    }
    #[test] fn post_main_wait_retains_original22_pool_and600_second_deadlines() {
        let at=Instant::now();let later=at+std::time::Duration::from_secs(600);
        assert_eq!(authentication_until(later,later,at),at+std::time::Duration::from_secs(22));
        assert_eq!(authentication_until(at+std::time::Duration::from_secs(5),later,at),at+std::time::Duration::from_secs(5));
        assert_eq!(authentication_until(later,at+std::time::Duration::from_secs(3),at),at+std::time::Duration::from_secs(3));
    }
    #[test] fn kernel_stat_parser_uses_last_parenthesis_and_exact_pid() {
        let mut fields=vec!["0";20];fields[0]="S";fields[19]="98765";
        let raw=format!("123 (name with ) parentheses) {}",fields.join(" "));
        assert_eq!(parse_stat(&raw,123).unwrap(),98765);assert!(parse_stat(&raw,124).is_err());
    }
}

#[cfg(test)]
#[path="post_main_native_tests.rs"]
mod native_controls;
