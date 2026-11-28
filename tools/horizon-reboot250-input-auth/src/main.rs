//! Exact epoch 250 input custody. No replay or remote mutations.
mod epoch251;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt}, path::Path, time::{SystemTime, UNIX_EPOCH}};

const MANIFEST: (&str,&str) = ("/var/lib/jetstreamer/horizon250-controls2402-v1/preflight-250-target1.json","fa914595e610da263d2d7eb22a4dc2a23eb7ad95665cc277459877bed7215cce");
const NODE: (&str,&str) = ("/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node","362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1");
const WORKER: (&str,&str) = ("/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15","c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4");
const BOOTSTRAP: (&str,&str) = ("/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/input/snapshot-107999217-4GDh8KkBUc2Yj6Xa3qLWGVkNSm44i4XSk8PXWSN2s274.tar.zst","fc1cbc57290f83505b545a9740b21f204606761e851f6dd01c0b02d6e3250eab");
const BOOTSTRAP_RECEIPT: (&str,&str) = ("/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/receipts/bootstrap-restore-v1.json","7f674f402248a2898f8979b69b4d7d526926d58fa8f29170377cd6ff7637a18c");
const FINAL: (&str,&str) = ("/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/input/snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst","b7af2058dd498bdf8c0f7e2a717a0d7c8153c20027eca2c3c2de15351b87b311");
const FINAL_RECEIPT: (&str,&str) = ("/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/receipts/final-root-restore-v1.json","9abaf9434b389828a1b5c9412d539095380846db7eb2f53f2c2eaa3038296d27");
const GENESIS: (&str,&str) = ("/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/output/genesis.tar.bz2","133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945");
const OUT: &str = "/var/lib/jetstreamer/horizon250-reboot-20261117-input-auth-v1";

fn pin((name,expected):(&str,&str)) -> Result<Value> {
    let path=Path::new(name);
    ensure!(path.is_absolute() && path.canonicalize()? == path,"aliased input: {name}");
    let before=fs::symlink_metadata(path)?;
    ensure!(before.is_file() && before.nlink()==1,"input is not a singly linked regular file: {name}");
    let mut file=File::open(path)?;
    let mut h=Sha256::new(); let mut buf=[0u8;1<<20];
    loop { let n=file.read(&mut buf)?; if n==0 {break;} h.update(&buf[..n]); }
    let after=fs::symlink_metadata(path)?;
    ensure!(before.dev()==after.dev() && before.ino()==after.ino() && before.len()==after.len()
        && before.mtime()==after.mtime() && before.mtime_nsec()==after.mtime_nsec()
        && before.ctime()==after.ctime() && before.ctime_nsec()==after.ctime_nsec(),"input changed while hashing: {name}");
    let digest=format!("{:x}",h.finalize());ensure!(digest==expected,"input SHA-256 mismatch: {name}");
    Ok(json!({"path":name,"sha256":digest,"identity":{"dev":before.dev(),"ino":before.ino(),"size":before.len(),
        "blocks":before.blocks(),"uid":before.uid(),"gid":before.gid(),"mode":before.mode(),"nlink":before.nlink(),
        "mtime_ns":before.mtime() as i128*1_000_000_000+before.mtime_nsec() as i128,
        "ctime_ns":before.ctime() as i128*1_000_000_000+before.ctime_nsec() as i128}}))
}

fn restore(receipt:&Value, source:&Value, path:&str, digest:&str) -> Result<()> {
    ensure!(receipt["schema"]=="jetstreamer-bound-gcs-snapshot-restore-v1"
        && receipt["destination"]==path && receipt["source"]=="generation-pinned-download"
        && receipt["file"]["sha256"]==digest && receipt["generation"]==source["generation"]
        && receipt["file"]["size"]==source["size"] && receipt["remote_object"]["size"]==source["size"]
        && receipt["file"]["crc32c_base64"]==source["crc32c"]
        && receipt["file"]["md5_base64"]==source["md5_hash"]
        && receipt["snapshot_slot"]==source["slot"] && receipt["versioned_uri"]==source["versioned_uri"]
        && receipt["remote_object"]["generation"]==source["generation"],"restore receipt/manifest mismatch");
    Ok(())
}

fn run() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("check-251") => return epoch251::run(false),
        Some("check-251-published-node") => return epoch251::run(true),
        _ => {}
    }
    ensure!(std::env::args().len()==1,"no arguments accepted");
    ensure!(unsafe {libc::geteuid()}==0,"root required");
    ensure!(!Path::new(OUT).exists(),"acceptance generation exists");
    let manifest_pin=pin(MANIFEST)?;
    let manifest:Value=serde_json::from_slice(&fs::read(MANIFEST.0)?)?;
    ensure!(manifest["manifest"]["first_epoch"]==250 && manifest["manifest"]["last_epoch"]==250
        && manifest["manifest"]["epochs"][0]["epoch"]==250
        && manifest["manifest"]["epochs"][0]["verification_cohort"]["first_epoch"]==250
        && manifest["manifest"]["epochs"][0]["verification_cohort"]["last_epoch"]==250,"wrong manifest scope");
    let epoch=&manifest["manifest"]["epochs"][0];
    let br=pin(BOOTSTRAP_RECEIPT)?;let fr=pin(FINAL_RECEIPT)?;
    restore(&serde_json::from_slice(&fs::read(BOOTSTRAP_RECEIPT.0)?)?,&epoch["bootstrap"],BOOTSTRAP.0,BOOTSTRAP.1)?;
    restore(&serde_json::from_slice(&fs::read(FINAL_RECEIPT.0)?)?,&epoch["post_bootstrap_root_checkpoints"][0],FINAL.0,FINAL.1)?;
    let bootstrap=pin(BOOTSTRAP)?;let final_root=pin(FINAL)?;let genesis=pin(GENESIS)?;
    ensure!(bootstrap["identity"]["uid"]==1000 && final_root["identity"]["uid"]==1000
        && genesis["identity"]["uid"]==1000,"wrong local input owner");
    let receipt=json!({"schema":"horizon250-reboot-exact-input-custody-v1","epoch":250,
        "manifest":manifest_pin,"node":pin(NODE)?,"worker":pin(WORKER)?,"bootstrap":bootstrap,
        "final_root":final_root,"bootstrap_restore_receipt":br,"final_root_restore_receipt":fr,"genesis":genesis,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "accepted_input_custody":true,"replay_launch_authorized":false,"publication_authorized":false,
        "r2_mutations":false,"remote_mutations":false});
    fs::create_dir(OUT).context("create acceptance generation")?;
    fs::set_permissions(OUT,fs::Permissions::from_mode(0o700))?;
    let dest=Path::new(OUT).join("acceptance.json");
    let mut out=OpenOptions::new().write(true).create_new(true).mode(0o400).open(&dest)?;
    serde_json::to_writer_pretty(&mut out,&receipt)?;out.write_all(b"\n")?;out.sync_all()?;
    File::open(OUT)?.sync_all()?;File::open(Path::new(OUT).parent().context("no parent")?)?.sync_all()?;
    println!("{}",dest.display());Ok(())
}
fn main() {if let Err(e)=run(){eprintln!("Error: {e:#}");std::process::exit(1);}}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn restore_rejects_wrong_generation_or_digest() {
        let m=json!({"generation":7,"size":10,"crc32c":"a","md5_hash":"b","slot":9,"versioned_uri":"gs://x#7"});
        let mut r=json!({"schema":"jetstreamer-bound-gcs-snapshot-restore-v1","destination":"/x","source":"generation-pinned-download",
            "file":{"sha256":"abc","size":10,"crc32c_base64":"a","md5_base64":"b"},"generation":7,"snapshot_slot":9,
            "versioned_uri":"gs://x#7","remote_object":{"generation":7,"size":10}});
        assert!(restore(&r,&m,"/x","abc").is_ok());
        r["generation"]=json!(8);assert!(restore(&r,&m,"/x","abc").is_err());
        r["generation"]=json!(7);r["file"]["sha256"]=json!("wrong");assert!(restore(&r,&m,"/x","abc").is_err());
    }
}
