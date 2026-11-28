//! Ignored Root filesystem/inotify/proc controls only. Receipt/native unit
//! fields are labelled fixtures; these tests do not qualify an actual actor.
use super::{GuardScope, MainIdentity, LifecycleDirectory, start_ticks};
use crate::{events::Watch, storage};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
struct Sandbox(PathBuf);
impl Sandbox {
    fn new(label: &str) -> Self {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let stamp=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path=std::env::temp_dir().join(format!("final5-postmain-{label}-{}-{stamp}",std::process::id()));
        fs::create_dir(&path).unwrap();fs::set_permissions(&path,fs::Permissions::from_mode(0o700)).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Sandbox {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn fixture() -> (String,String,String,String,Value,MainIdentity,Value) {
    let actor="horizon-qualify-185-capped-cold-final5-isolated-fixture.service".to_owned();
    let iid="a".repeat(32);let admission="c".repeat(64);
    let timer="horizon-guard-185-capped-cold-final5-isolated-fixture.timer".to_owned();
    let pid=u64::from(std::process::id());let ticks=start_ticks(pid).unwrap();
    let main=MainIdentity{pid,start_ticks:ticks,native_start_monotonic_micros:1};
    let ready=json!({"pid":pid+1,"start_ticks":ticks+1});
    let receipt=json!({"schema":"horizon-epoch185-native-guard-result-v4","epoch":185,
        "actor_unit":actor,"actor_invocation_id":iid,"admission_sha256":admission,
        "guard_invocation_id":"b".repeat(32),"timer_unit":timer,"sampled_at":crate::now().unwrap(),
        "success":true,"failure":null,"timer_driven":true,"capacity_credit_bytes":0,
        "actor_pid":pid,"actor_start_ticks":ticks,"timer_last_trigger_monotonic_micros":1000,
        "guard_start_monotonic_micros":2000});
    (actor,iid,admission,timer,ready,main,receipt)
}
fn publish(root:&Path,receipt:&Value) {
    let p=root.join(format!("guard-{}.json",receipt["guard_invocation_id"].as_str().unwrap()));
    let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(p).unwrap();
    serde_json::to_writer(&mut f,receipt).unwrap();f.write_all(b"\n").unwrap();f.sync_all().unwrap();
}
#[test]
#[ignore="Root native inotify/proc fixture, no actor/guard/timer activation"]
fn actual_closed_prestart_receipt_waits_then_closed_main_receipt_accepts() {
    let dir=Sandbox::new("prestart-to-main");
    let watch=Watch::guard_directory(&dir.0).unwrap();
    let(actor,iid,admission,timer,ready,main,mut receipt)=fixture();
    let mut prestart=receipt.clone();prestart["actor_pid"]=ready["pid"].clone();prestart["actor_start_ticks"]=ready["start_ticks"].clone();
    publish(&dir.0,&prestart);
    let root=dir.0.clone();let (tx,rx)=mpsc::channel();
    let consumer=thread::spawn(move||{
        let scope=GuardScope{actor:&actor,iid:&iid,admission:&admission,timer:&timer,ready:&ready,main:&main};
        tx.send(watch.post_main_guard(&root,&scope,Instant::now()+Duration::from_secs(3))).unwrap();
    });
    assert!(matches!(rx.recv_timeout(Duration::from_millis(150)),Err(mpsc::RecvTimeoutError::Timeout)),
        "closed prestart guard must not authorize lifecycle capture");
    receipt["guard_invocation_id"]="d".repeat(32).into();publish(&dir.0,&receipt);
    let(_,actual)=rx.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();consumer.join().unwrap();
    assert_eq!(actual,receipt);
}
#[test]
#[ignore="Root native partial-writer CLOSE_WRITE control; isolated fixture only"]
fn actual_postmain_guard_keeps_close_write_publication_semantics() {
    let dir=Sandbox::new("main-slow-writer");let watch=Watch::guard_directory(&dir.0).unwrap();
    let(actor,iid,admission,timer,ready,main,receipt)=fixture();
    let root=dir.0.clone();let path=root.join(format!("guard-{}.json","b".repeat(32)));
    let mut writer=OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&path).unwrap();
    let bytes=serde_json::to_vec(&receipt).unwrap();let split=bytes.len()/2;
    writer.write_all(&bytes[..split]).unwrap();writer.sync_all().unwrap();
    let(tx,rx)=mpsc::channel();let consumer=thread::spawn(move||{
        let scope=GuardScope{actor:&actor,iid:&iid,admission:&admission,timer:&timer,ready:&ready,main:&main};
        tx.send(watch.post_main_guard(&root,&scope,Instant::now()+Duration::from_secs(3))).unwrap();
    });
    assert!(matches!(rx.recv_timeout(Duration::from_millis(150)),Err(mpsc::RecvTimeoutError::Timeout)));
    writer.write_all(&bytes[split..]).unwrap();writer.write_all(b"\n").unwrap();writer.sync_all().unwrap();drop(writer);
    let(binding,actual)=rx.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();consumer.join().unwrap();
    assert_eq!(actual,receipt);let mut full=bytes;full.push(b'\n');assert_eq!(storage::bytes(&binding,4<<20,false).unwrap(),full);
}
#[test]
#[ignore="Root native failed guard fixture remains a hard error, no actor work"]
fn actual_closed_failed_main_guard_rejects_without_lifecycle_capture() {
    let dir=Sandbox::new("failed-main");let watch=Watch::guard_directory(&dir.0).unwrap();
    let(actor,iid,admission,timer,ready,main,mut receipt)=fixture();
    receipt["success"]=false.into();receipt["failure"]="guard rejected fixture".into();publish(&dir.0,&receipt);
    let scope=GuardScope{actor:&actor,iid:&iid,admission:&admission,timer:&timer,ready:&ready,main:&main};
    let error=watch.post_main_guard(&dir.0,&scope,Instant::now()+Duration::from_secs(1)).unwrap_err();
    assert!(error.to_string().contains("post-Main guard failed"));assert!(!dir.0.join("lifecycle.json").exists());
}
#[test]
#[ignore="Root native fixed deadline expires while only a prestart fixture exists"]
fn actual_prestart_only_wait_expires_without_clock_reset_or_capture() {
    let dir=Sandbox::new("prestart-timeout");let watch=Watch::guard_directory(&dir.0).unwrap();
    let(actor,iid,admission,timer,ready,main,mut receipt)=fixture();
    receipt["actor_pid"]=ready["pid"].clone();receipt["actor_start_ticks"]=ready["start_ticks"].clone();publish(&dir.0,&receipt);
    let scope=GuardScope{actor:&actor,iid:&iid,admission:&admission,timer:&timer,ready:&ready,main:&main};
    let deadline=Instant::now()+Duration::from_millis(150);
    let error=watch.post_main_guard(&dir.0,&scope,deadline).unwrap_err();
    assert!(error.chain().any(|cause|cause.to_string()=="original event deadline expired"),
        "expected original deadline expiry, not a receipt/poll/descriptor/custody failure: {error:#}");
    assert!(Instant::now()>=deadline,"deadline error returned before the original Instant: {error:#}");
    assert!(!dir.0.join("lifecycle.json").exists());
    assert_eq!(start_ticks(main.pid).unwrap(),main.start_ticks);
}
#[test]
#[ignore="Root native expired fixed deadline with queued CLOSE_WRITE; fixture only"]
fn actual_queued_main_receipt_cannot_revive_an_expired_original_deadline() {
    let dir=Sandbox::new("expired-queued-main");let watch=Watch::guard_directory(&dir.0).unwrap();
    let(actor,iid,admission,timer,ready,main,receipt)=fixture();publish(&dir.0,&receipt);
    let scope=GuardScope{actor:&actor,iid:&iid,admission:&admission,timer:&timer,ready:&ready,main:&main};
    let expired=Instant::now().checked_sub(Duration::from_millis(1)).unwrap();
    let error=watch.post_main_guard(&dir.0,&scope,expired).unwrap_err();
    assert!(error.chain().any(|cause|cause.to_string()=="original event deadline expired"),"{error:#}");
    assert!(!dir.0.join("lifecycle.json").exists());
    assert_eq!(start_ticks(main.pid).unwrap(),main.start_ticks);
}
#[test]
#[ignore="Root native exact mkdirat/openat custody fixture, no production paths"]
fn actual_lifecycle_leaf_is0700_stable_and_rejects_alias_reuse_or_mode_change() {
    let dir=Sandbox::new("directory-custody");let iid="a".repeat(32);
    let prepared=LifecycleDirectory::create_at(&dir.0,&iid).unwrap();let before=prepared.identity;
    let output=prepared.writable_path().unwrap().join("lifecycle.json");
    {let mut f=OpenOptions::new().write(true).create_new(true).mode(0o400)
        .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(output).unwrap();f.write_all(b"fixture only\n").unwrap();f.sync_all().unwrap();}
    prepared.validate().unwrap();assert_eq!(before,prepared.identity);
    assert!(LifecycleDirectory::create_at(&dir.0,&iid).is_err());
    let alias="b".repeat(32);symlink(&prepared.path,dir.0.join(&alias)).unwrap();assert!(LifecycleDirectory::create_at(&dir.0,&alias).is_err());
    fs::set_permissions(&prepared.path,fs::Permissions::from_mode(0o755)).unwrap();assert!(prepared.validate().is_err());
}
