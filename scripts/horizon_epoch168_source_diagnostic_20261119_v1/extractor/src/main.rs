//! Prepared as jetstreamer-firehose/src/bin/epoch168_source_extract/main.rs.
//! The unchanged normal status decoder is source-pinned in this packet.
pub type SharedError = jetstreamer_firehose::SharedError;
pub mod epochs { pub use jetstreamer_firehose::epochs::slot_to_epoch; }
#[path = "normal-source-transaction_status_meta.rs"]
mod source_status;
mod extract;
use extract::{sha, Target, MAX_INPUT};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, ffi::CString, fs::{File, OpenOptions}, io::{Read, Write},
    os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}}},
    path::{Path, PathBuf}};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound { path: PathBuf, sha256: String, bytes: u64 }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    input: Bound,
    acquisition_receipt: Bound,
    output_directory: PathBuf,
    epoch: u64,
    slot: u64,
    entry_index: usize,
    transaction_slot_index: usize,
    signature: String,
}
#[derive(Serialize)]
struct Identity { device: u64, inode: u64, bytes: u64, uid: u32, gid: u32, mode: u32,
    links: u64, mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64 }
fn identity(m: &std::fs::Metadata) -> Identity {
    Identity { device:m.dev(),inode:m.ino(),bytes:m.len(),uid:m.uid(),gid:m.gid(),mode:m.mode(),
        links:m.nlink(),mtime:m.mtime(),mtime_ns:m.mtime_nsec(),ctime:m.ctime(),ctime_ns:m.ctime_nsec() }
}
fn check(ok: bool, message: &str) -> Result<(), String> { if ok {Ok(())} else {Err(message.into())} }
fn valid_sha(s: &str) -> bool { s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn read_bound(bound: &Bound, max: usize) -> Result<(Vec<u8>, Identity), String> {
    check(bound.path.is_absolute() && bound.path.canonicalize().map_err(|e|e.to_string())? == bound.path,
        "bound input path must be absolute and canonical without symlink components")?;
    check(valid_sha(&bound.sha256) && bound.bytes > 0 && bound.bytes <= max as u64, "invalid input size/hash binding")?;
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC)
        .open(&bound.path).map_err(|e|e.to_string())?;
    let before = file.metadata().map_err(|e|e.to_string())?;
    check(before.is_file() && before.len() == bound.bytes && before.nlink() == 1 && before.mode() & 0o222 == 0,
        "input must be bound immutable regular single-link file")?;
    let before_identity = identity(&before);
    let mut bytes = Vec::with_capacity(bound.bytes as usize);
    (&mut file).take(bound.bytes + 1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
    let after_identity = identity(&file.metadata().map_err(|e|e.to_string())?);
    check(serde_json::to_vec(&before_identity).map_err(|e|e.to_string())? == serde_json::to_vec(&after_identity).map_err(|e|e.to_string())?,
        "input identity changed during read")?;
    check(bytes.len() as u64 == bound.bytes && sha(&bytes) == bound.sha256, "input bytes/hash differs")?;
    Ok((bytes,before_identity))
}
fn private_output(path: &Path) -> Result<(File, File), String> {
    check(path.is_absolute(), "output must be absolute")?;
    let parent = path.parent().ok_or("output parent absent")?;
    check(parent.canonicalize().map_err(|e|e.to_string())? == parent, "output parent must be canonical without symlinks")?;
    let parent_file = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)
        .open(parent).map_err(|e|e.to_string())?;
    let meta = parent_file.metadata().map_err(|e|e.to_string())?;
    check(meta.is_dir() && meta.uid() == unsafe{libc::geteuid()} && meta.mode() & 0o077 == 0,
        "output parent must be owned and private mode0700")?;
    let name = path.file_name().ok_or("output name absent")?;
    check(!name.as_bytes().is_empty() && name != "." && name != "..", "invalid output name")?;
    let name = CString::new(name.as_bytes()).map_err(|e|e.to_string())?;
    check(unsafe{libc::mkdirat(parent_file.as_raw_fd(),name.as_ptr(),0o700)} == 0,
        "no-clobber output directory creation failed")?;
    parent_file.sync_all().map_err(|e|e.to_string())?;
    let fd = unsafe{libc::openat(parent_file.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
    check(fd >= 0,"open new private output failed")?;
    let output = unsafe{File::from_raw_fd(fd)};
    let meta = output.metadata().map_err(|e|e.to_string())?;
    check(meta.is_dir() && meta.uid() == unsafe{libc::geteuid()} && meta.mode() & 0o777 == 0o700,
        "new output directory identity/mode differs")?;
    Ok((parent_file,output))
}
fn write_member(directory: &File, name: &str, bytes: &[u8]) -> Result<(), String> {
    check(!name.is_empty() && !name.contains('/') && name != "." && name != "..", "unsafe output member")?;
    let name = CString::new(name).map_err(|e|e.to_string())?;
    let fd = unsafe{libc::openat(directory.as_raw_fd(),name.as_ptr(),
        libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
    check(fd >= 0,"no-clobber private member creation failed")?;
    let mut file = unsafe{File::from_raw_fd(fd)};
    file.write_all(bytes).map_err(|e|e.to_string())?;
    file.sync_all().map_err(|e|e.to_string())?;
    Ok(())
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    check(args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--plan-bytes",
        "usage: epoch168-source-extract ABS_PLAN --plan-sha256 SHA256 --plan-bytes BYTES")?;
    let bound = Bound {path:args[1].clone().into(),sha256:args[3].clone(),bytes:args[5].parse().map_err(|_|"invalid plan byte count")?};
    let (plan_bytes,plan_identity) = read_bound(&bound,65536)?;
    let plan: Plan = serde_json::from_slice(&plan_bytes).map_err(|e|e.to_string())?;
    let target = Target::incident();
    check(plan.schema == "jetstreamer-epoch168-target-source-extract-plan-v1" &&
        plan.epoch == target.epoch && plan.slot == target.slot && plan.entry_index == target.entry &&
        plan.transaction_slot_index == target.transaction && plan.signature == target.signature,
        "plan must bind exact epoch168 incident selector")?;
    let (input,input_identity) = read_bound(&plan.input,MAX_INPUT)?;
    let (acquisition,acquisition_identity) = read_bound(&plan.acquisition_receipt,1<<20)?;
    // Retain Root's genuine acquisition record opaquely: no invented provider schema or authority.
    let mut extraction = extract::extract(&input,&target)?;
    extraction.report["bindings"] = json!({"plan_sha256":bound.sha256,"plan_identity":plan_identity,
        "input_path":plan.input.path,"input_identity":input_identity,
        "acquisition_receipt_path":plan.acquisition_receipt.path,
        "acquisition_receipt_sha256":plan.acquisition_receipt.sha256,"acquisition_identity":acquisition_identity,
        "acquisition_receipt_semantics_authenticated_by_extractor":false});
    extraction.members.insert("acquisition-receipt.json".into(),acquisition);
    extraction.members.insert("extract-plan.json".into(),plan_bytes);
    extraction.members.insert("report.json".into(),serde_json::to_vec_pretty(&extraction.report).map_err(|e|e.to_string())?);
    let (parent,directory) = private_output(&plan.output_directory)?;
    let mut hashes = BTreeMap::new();
    for (name,bytes) in &extraction.members {
        write_member(&directory,name,bytes)?;
        hashes.insert(name,json!({"bytes":bytes.len(),"sha256":sha(bytes)}));
    }
    let receipt = serde_json::to_vec_pretty(&json!({"schema":"jetstreamer-epoch168-source-extract-completion-v1",
        "members":hashes,"diagnostic_only":true,"provider_generation_authenticated":false,
        "canonical_state_proven":false,"replay_launch_authorized":false,"publication_authorized":false,
        "runtime_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false})).map_err(|e|e.to_string())?;
    // Completion is the last member; hash it independently in the enclosing manifest.
    write_member(&directory,"completion.json",&receipt)?;
    let completion_hash = format!("{}  completion.json\n",sha(&receipt));
    write_member(&directory,"COMPLETION.sha256",completion_hash.as_bytes())?;
    directory.sync_all().map_err(|e|e.to_string())?;
    parent.sync_all().map_err(|e|e.to_string())?;
    println!("{}",plan.output_directory.display());
    Ok(())
}
fn main() { if let Err(error) = run() {eprintln!("epoch168 source extraction rejected: {error}");std::process::exit(1);} }

#[cfg(test)]
mod writer_tests {
    use super::*;
    use std::{fs, os::unix::fs::{PermissionsExt, symlink}};
    #[test]
    fn existing_output_directory_cannot_be_reused() {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(),fs::Permissions::from_mode(0o700)).unwrap();
        let output = parent.path().join("evidence");
        fs::create_dir(&output).unwrap();
        assert!(private_output(&output).is_err());
    }
    #[test]
    fn private_member_creation_cannot_clobber_prior_evidence() {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(),fs::Permissions::from_mode(0o700)).unwrap();
        let output = parent.path().join("evidence");
        let (_,directory) = private_output(&output).unwrap();
        write_member(&directory,"member",b"original").unwrap();
        assert!(write_member(&directory,"member",b"replacement").is_err());
        assert_eq!(fs::read(output.join("member")).unwrap(),b"original");
        assert_eq!(fs::metadata(output.join("member")).unwrap().mode() & 0o777,0o600);
    }
    #[test]
    fn input_hash_binding_rejects_same_size_foreign_bytes() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("input");fs::write(&path,b"foreign!").unwrap();
        fs::set_permissions(&path,fs::Permissions::from_mode(0o400)).unwrap();
        let bound = Bound{path,sha256:sha(b"expected"),bytes:8};
        assert!(read_bound(&bound,16).is_err());
    }
    #[test]
    fn symlink_input_cannot_substitute_for_bound_regular_file() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("input");fs::write(&path,b"expected").unwrap();
        fs::set_permissions(&path,fs::Permissions::from_mode(0o400)).unwrap();
        let link = parent.path().join("link");symlink(&path,&link).unwrap();
        let bound = Bound{path:link,sha256:sha(b"expected"),bytes:8};
        assert!(read_bound(&bound,16).is_err());
    }
}
