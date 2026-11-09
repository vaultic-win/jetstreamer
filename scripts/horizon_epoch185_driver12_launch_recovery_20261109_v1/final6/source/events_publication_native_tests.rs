//! Root-only, ignored native filesystem/inotify controls in an isolated QA
//! directory. Fixtures are not campaign receipts and grant no actor authority.
use super::{Watch, guard_filename, now};
use crate::{process, storage};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
struct Sandbox(PathBuf);
impl Sandbox {
    fn new(label: &str) -> Self {
        assert_eq!(unsafe { libc::geteuid() }, 0, "Root-owned fixture required");
        let stamp=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path=std::env::temp_dir().join(format!("final4-inotify-{label}-{}-{stamp}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Sandbox { fn drop(&mut self) { let _=fs::remove_dir_all(&self.0); } }
fn writer(path: &Path) -> fs::File {
    OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(path).unwrap()
}
fn fixture() -> (String, String, String, Value) {
    let actor="horizon-qualify-185-capped-cold-final4-isolated-inotify-fixture.service".to_owned();
    let iid="a".repeat(32);
    let admission="c".repeat(64);
    let value=json!({"schema":"horizon-epoch185-native-guard-result-v4","epoch":185,
        "actor_unit":actor,"actor_invocation_id":iid,"admission_sha256":admission,
        "guard_invocation_id":"b".repeat(32),"sampled_at":now().unwrap(),
        "success":true,"timer_driven":true,"capacity_credit_bytes":0});
    (actor,iid,admission,value)
}
#[test]
#[ignore = "Root native inotify QA: isolated slow-writing receipt; no campaign units"]
fn actual_slow_writer_old_modify_binds_early_corrected_guard_waits_for_close() {
    let dir=Sandbox::new("slow-writer");
    let (actor,iid,admission,value)=fixture();
    let filename=format!("guard-{}.json", "b".repeat(32));
    let path=dir.0.join(&filename);
    let legacy=Watch::new(&dir.0).unwrap();
    let corrected=Watch::guard_directory(&dir.0).unwrap();
    let bytes=serde_json::to_vec(&value).unwrap();
    let split=bytes.len()/2;
    let prefix=bytes[..split].to_vec();
    let suffix=bytes[split..].to_vec();
    let (opened_tx,opened_rx)=mpsc::channel();
    let (finish_tx,finish_rx)=mpsc::channel();
    let writer_path=path.clone();
    let publisher=thread::spawn(move || {
        let mut f=writer(&writer_path);
        f.write_all(&prefix).unwrap();f.sync_all().unwrap();
        opened_tx.send(()).unwrap();
        finish_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        f.write_all(&suffix).unwrap();f.write_all(b"\n").unwrap();f.sync_all().unwrap();
        // Drop, rather than an invented commit marker, emits native CLOSE_WRITE.
    });
    opened_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    // This is the old production decision against real kernel events: discard
    // masks, select matching filename, bind and parse while writer is held open.
    let early=legacy.events(Instant::now()+Duration::from_secs(2)).unwrap();
    assert!(early.iter().any(|e| e.name==filename && e.mask&libc::IN_MODIFY!=0));
    assert!(early.iter().any(|e| guard_filename(&e.name)));
    let old_binding=process::bind_file(&path,4<<20).unwrap();
    assert!(storage::json(&old_binding).is_err(), "old MODIFY branch read an incomplete receipt");
    assert_eq!(fs::metadata(&path).unwrap().len(),split as u64);
    let expected=value.clone();let root=dir.0.clone();
    let (done_tx,done_rx)=mpsc::channel();
    let consumer=thread::spawn(move || {
        let result=corrected.guard(&root,&actor,&iid,&admission,Instant::now()+Duration::from_secs(3));
        done_tx.send(result).unwrap();
    });
    assert!(matches!(done_rx.recv_timeout(Duration::from_millis(150)),Err(mpsc::RecvTimeoutError::Timeout)),
        "corrected consumer returned before the writer closed");
    finish_tx.send(()).unwrap();publisher.join().unwrap();
    let (binding,actual)=done_rx.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
    consumer.join().unwrap();
    assert_eq!(actual,expected);
    let mut completed=bytes;completed.push(b'\n');
    assert_eq!(storage::bytes(&binding,4<<20,false).unwrap(),completed);
    println!("actual inotify: legacy MODIFY opened incomplete JSON; corrected guard bound exact bytes after CLOSE_WRITE");
}
#[test]
#[ignore = "Root native inotify QA: isolated unqualified rename publisher is rejected"]
fn actual_unqualified_move_to_guard_name_does_not_publish_a_receipt() {
    let dir=Sandbox::new("unqualified-move");
    let (actor,iid,admission,value)=fixture();
    let watch=Watch::new(&dir.0).unwrap();
    let temporary=dir.0.join("unqualified-temporary.json");
    {
        let mut f=writer(&temporary);serde_json::to_writer(&mut f,&value).unwrap();
        f.write_all(b"\n").unwrap();f.sync_all().unwrap();
    }
    let destination=dir.0.join(format!("guard-{}.json","b".repeat(32)));
    fs::rename(&temporary,&destination).unwrap();
    assert!(watch.guard(&dir.0,&actor,&iid,&admission,Instant::now()+Duration::from_millis(200)).is_err());
    assert_eq!(storage::json(&process::bind_file(&destination,4<<20).unwrap()).unwrap(),value);
}
#[test]
#[ignore = "Root native inotify QA: closed but malformed receipt fails original file/JSON gate"]
fn actual_closed_malformed_receipt_is_rejected_without_retry() {
    let dir=Sandbox::new("malformed");
    let (actor,iid,admission,_)=fixture();
    let watch=Watch::guard_directory(&dir.0).unwrap();
    let path=dir.0.join(format!("guard-{}.json","b".repeat(32)));
    {let mut f=writer(&path);f.write_all(b"{incomplete\n").unwrap();f.sync_all().unwrap();}
    let error=watch.guard(&dir.0,&actor,&iid,&admission,Instant::now()+Duration::from_secs(1)).unwrap_err();
    assert!(!error.to_string().contains("timeout"));
}
#[test]
#[ignore = "Root native inotify QA: published failed guard remains a hard rejection"]
fn actual_closed_failed_guard_remains_rejected_after_publication_repair() {
    let dir=Sandbox::new("failed-guard");
    let (actor,iid,admission,mut value)=fixture();
    value["success"]=false.into();
    value["failure"]="No such file or directory (os error 2)".into();
    let watch=Watch::guard_directory(&dir.0).unwrap();
    let path=dir.0.join(format!("guard-{}.json","b".repeat(32)));
    {let mut f=writer(&path);serde_json::to_writer(&mut f,&value).unwrap();f.write_all(b"\n").unwrap();f.sync_all().unwrap();}
    let error=watch.guard(&dir.0,&actor,&iid,&admission,Instant::now()+Duration::from_secs(1)).unwrap_err();
    assert!(error.to_string().contains("genuine matching first guard failed"));
}
