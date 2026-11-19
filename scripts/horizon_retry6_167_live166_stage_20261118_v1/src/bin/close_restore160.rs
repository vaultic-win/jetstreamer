//! Retire only the obsolete inactive bootstrap restore control, preserving its evidence.
use anyhow::{Result, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::Write, os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt}, process::Command};
const UNIT: &str = "horizon-epoch160-bootstrap-restore-20261020-v1.service";
const SOURCE: &str = "/etc/systemd/system/horizon-epoch160-bootstrap-restore-20261020-v1.service";
const SOURCE_SHA: &str = "0132e93ef6d3de2f8461830e252aa9882a6b52487e5f3759a4021c5085174cd8";
const ROOT: &str = "/var/lib/jetstreamer/epoch160-obsolete-restore-custody-20261119-v1";
fn sha(b: &[u8]) -> String { format!("{:x}", Sha256::digest(b)) }
fn run(c: &mut Command) -> Result<Vec<u8>> { let o=c.output()?; ensure!(o.status.success(), "{c:?}: {}", String::from_utf8_lossy(&o.stderr)); Ok(o.stdout) }
fn native() -> Result<Vec<u8>> { run(Command::new("/usr/bin/systemctl").args(["show",UNIT,"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Job,Result,ExecMainStatus,ExecStart,FragmentPath,Triggers,TriggeredBy,UnitFileState"])) }
fn idle(raw: &[u8]) -> Result<()> { let s=std::str::from_utf8(raw)?; for line in ["ActiveState=inactive","SubState=dead","MainPID=0","ControlPID=0","InvocationID=","Job=","Triggers=","TriggeredBy="] { ensure!(s.lines().any(|l|l==line),"control no longer idle: {line}"); } Ok(()) }
fn save(leaf: &str, b: &[u8]) -> Result<String> { let path=format!("{ROOT}/{leaf}"); let mut f=OpenOptions::new().write(true).create_new(true).mode(0o400).custom_flags(libc::O_NOFOLLOW).open(&path)?; f.write_all(b)?; f.sync_all()?; File::open(ROOT)?.sync_all()?; Ok(sha(b)) }
fn main() -> Result<()> {
 ensure!(unsafe {libc::geteuid()}==0,"root required");
 let before=native()?; idle(&before)?;
 let s=std::str::from_utf8(&before)?;
 for l in ["LoadState=loaded","UnitFileState=static","Result=success","ExecMainStatus=0"] { ensure!(s.lines().any(|r|r==l),"unexpected native state {l}"); }
 let md=fs::symlink_metadata(SOURCE)?;
 ensure!(md.is_file() && md.uid()==0 && md.mode()&0o022==0 && md.nlink()==1,"unsafe original fragment");
 let bytes=fs::read(SOURCE)?; ensure!(sha(&bytes)==SOURCE_SHA,"fragment changed");
 fs::DirBuilder::new().mode(0o700).create(ROOT)?;
 save("before-native.txt",&before)?; save("original.service",&bytes)?;
 let receipt="/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1/bootstrap/receipts/snapshot-69119821-restore-receipt-v1.json";
 let restore_sha=save("original-restore-receipt.json",&fs::read(receipt)?)?;
 save("journal.jsonl",&run(Command::new("/usr/bin/journalctl").args(["-u",UNIT,"--no-pager","--all","-o","json"]))?)?;
 save("intent.json",&serde_json::to_vec_pretty(&json!({"unit":UNIT,"source":SOURCE,"source_sha256":SOURCE_SHA,"restore_receipt":receipt,"restore_receipt_sha256":restore_sha,"action":"preserve original fragment, replace obsolete inactive restore definition with /dev/null mask","snapshot_removed":false,"replay_mutations":false,"r2_mutations":false}))?)?;
 ensure!(native()?==before,"control changed during capture");
 let current=fs::symlink_metadata(SOURCE)?;
 ensure!(current.dev()==md.dev() && current.ino()==md.ino() && current.ctime()==md.ctime() && current.ctime_nsec()==md.ctime_nsec() && fs::read(SOURCE)?==bytes,"fragment changed before quarantine");
 fs::rename(SOURCE,format!("{ROOT}/original-fragment-inode.service"))?;
 File::open(ROOT)?.sync_all()?; File::open("/etc/systemd/system")?.sync_all()?;
 std::os::unix::fs::symlink("/dev/null",SOURCE)?;
 File::open("/etc/systemd/system")?.sync_all()?;
 run(Command::new("/usr/bin/systemctl").arg("daemon-reload"))?;
 let after=native()?; idle(&after)?;
 ensure!(std::str::from_utf8(&after)?.lines().any(|l|l=="LoadState=masked"),"restore not masked");
 save("after-native.txt",&after)?;
 save("completion.json",&serde_json::to_vec_pretty(&json!({"unit":UNIT,"original_fragment_sha256":SOURCE_SHA,"masked":true,"inactive":true,"snapshot_removed":false,"replay_mutations":false,"r2_mutations":false}))?)?;
 println!("{ROOT}/completion.json"); Ok(())
}
