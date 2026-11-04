//! Shared test-only input checks; exact epoch profiles remain explicit callers.
use super::RuntimeState;
use sha2::{Digest, Sha256};
use solana_sdk::hash::Hash;
use std::{env, fs::{self, OpenOptions}, io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt}, path::Path};

pub(super) struct Profile {
    pub epoch: u64,
    pub package: &'static str,
    pub snapshot: &'static str,
    pub bytes: u64,
    pub snapshot_sha256: &'static str,
    pub slot: u64,
    pub accounts_hash: &'static str,
    pub scratch_environment: &'static str,
    pub scratch_prefix: &'static str,
}
pub(super) const GENESIS_SHA256: &str =
    "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";

fn identity(m: &fs::Metadata) -> (u64,u64,u64,u32,u32,u64,i64,i64,i64,i64) {
    (m.dev(),m.ino(),m.len(),m.uid(),m.mode(),m.nlink(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec())
}
pub(super) fn checked_input(path:&Path, size:u64, digest:&str, owner:u32)->Result<(),String> {
    let check=||->Result<(),Box<dyn std::error::Error>> {
        if !path.is_absolute() || fs::canonicalize(path)?!=path { return Err("noncanonical native input".into()); }
        let before=fs::symlink_metadata(path)?;
        if !before.is_file() || before.uid()!=owner || before.mode()&0o222!=0
            || before.nlink()!=1 || before.len()!=size { return Err("unsafe native input identity".into()); }
        let mut file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(path)?;
        if identity(&file.metadata()?)!=identity(&before) {return Err("native input changed before hashing".into());}
        let mut hash=Sha256::new();let mut buffer=vec![0u8;1024*1024];let mut total=0u64;
        loop {
            let count=file.read(&mut buffer)?;if count==0 {break;}
            total=total.checked_add(count as u64).ok_or("native input byte count overflow")?;
            if total>size {return Err("native input grew".into());}
            hash.input(&buffer[..count]);
        }
        if total!=size || format!("{:x}",hash.result())!=digest
            || identity(&file.metadata()?)!=identity(&before)
            || identity(&fs::symlink_metadata(path)?)!=identity(&before) {
            return Err("native input hash/identity differs".into());
        }
        Ok(())
    };
    check().map_err(|e|e.to_string())
}
pub(super) fn scratch_namespace(p:&Profile,path:&Path)->bool {
    path.file_name().and_then(|n|n.to_str())==Some("scratch")
        && path.parent().and_then(Path::parent)==Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        && path.parent().and_then(Path::file_name).and_then(|n|n.to_str())
            .map_or(false,|n|n.starts_with(p.scratch_prefix))
}

pub(super) fn native_cold(p:&Profile) {
    let scratch=env::var(p.scratch_environment).expect("explicit epoch-specific native scratch required");
    let path=Path::new(&scratch);assert!(scratch_namespace(p,path));
    for directory in &[path.parent().unwrap(),path] {
        let m=fs::symlink_metadata(directory).unwrap();
        assert!(m.is_dir());assert_eq!(m.uid(),unsafe{libc::geteuid()});assert_eq!(m.mode()&0o077,0);
        assert_eq!(fs::canonicalize(directory).unwrap(),*directory);
    }
    assert!(fs::read_dir(path).unwrap().next().is_none());
    checked_input(&Path::new(p.package).join(p.snapshot),p.bytes,p.snapshot_sha256,0).unwrap();
    checked_input(&Path::new(p.package).join("genesis.tar.bz2"),20_144,GENESIS_SHA256,0).unwrap();
    let (mut state,initialized)=RuntimeState::initialize(p.package,
        &jetstreamer_historical_protocol::InitialState::SnapshotArchive {
            archive_path:Path::new(p.package).join(p.snapshot).to_str().unwrap().to_owned(),
        },Some(&scratch)).unwrap();
    assert_eq!(initialized.slot,p.slot);
    let transactions=state.bank.transaction_count();let capitalization=state.bank.capitalization();
    let last_blockhash=state.bank.last_blockhash();let tick_height=state.bank.tick_height();
    let checkpoint=state.freeze_checkpoint(p.slot).unwrap();
    assert!(checkpoint.slot_complete && checkpoint.writes.is_empty());
    assert_eq!(checkpoint.slot,p.slot);assert_eq!(checkpoint.next_write_version,initialized.next_write_version);
    assert_eq!(checkpoint.transaction_count,transactions);assert_eq!(checkpoint.capitalization,capitalization);
    assert_eq!(checkpoint.last_blockhash,last_blockhash.as_ref().to_vec());
    assert_eq!(checkpoint.tick_height,tick_height);
    assert_eq!(Hash::new(&checkpoint.accounts_hash).to_string(),p.accounts_hash);
    println!("epoch{}-v1616-native-input slot={} bank_hash={} accounts_hash={} last_blockhash={} capitalization={} transaction_count={} tick_height={} next_write_version={} replay_entries=0 bootstrap_writes=0",
        p.epoch,checkpoint.slot,Hash::new(&checkpoint.bank_hash),Hash::new(&checkpoint.accounts_hash),
        Hash::new(&checkpoint.last_blockhash),checkpoint.capitalization,checkpoint.transaction_count,
        checkpoint.tick_height,checkpoint.next_write_version);
}

pub(super) fn integrity_regression(p:&Profile) {
    use std::os::unix::fs::{symlink,PermissionsExt};
    let directory=tempfile::tempdir().unwrap();let input=directory.path().join("input");
    fs::write(&input,b"bound native input").unwrap();fs::set_permissions(&input,fs::Permissions::from_mode(0o444)).unwrap();
    let digest=format!("{:x}",Sha256::digest(b"bound native input"));let uid=unsafe{libc::geteuid()};
    checked_input(&input,18,&digest,uid).unwrap();
    assert!(checked_input(&input,19,&digest,uid).is_err());
    assert!(checked_input(&input,18,&"a".repeat(64),uid).is_err());
    assert!(checked_input(&input,18,&digest,uid+1).is_err());
    let link=directory.path().join("link");symlink(&input,&link).unwrap();assert!(checked_input(&link,18,&digest,uid).is_err());
    fs::set_permissions(&input,fs::Permissions::from_mode(0o644)).unwrap();assert!(checked_input(&input,18,&digest,uid).is_err());
    assert!(scratch_namespace(p,Path::new("/home/ubuntu/.jetstreamer-private").join(format!("{}v1/scratch",p.scratch_prefix)).as_path()));
    for epoch in &[207,209,211,212,228] {
        assert!(!scratch_namespace(p,Path::new(&format!("/home/ubuntu/.jetstreamer-private/native-input{}-v1616-capped-v1/scratch",epoch))));
    }
    assert!(!scratch_namespace(p,Path::new("/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1/nested/scratch")));
    assert!(!scratch_namespace(p,Path::new("/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1/output")));
}
