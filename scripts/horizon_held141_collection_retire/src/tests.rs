use crate::{
    atomic_fs::{AnchoredParent, dir_identity, open_at, private_child, rename_no_replace},
    tree::{Signature, Table, Transaction, signature},
};
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};
use tempfile::TempDir;

struct Fixture {
    _tmp: TempDir,
    root_path: PathBuf,
    state_path: PathBuf,
    parent: AnchoredParent,
    state: AnchoredParent,
    table: Table,
    dir: Signature,
}
fn anchor(p: &Path) -> AnchoredParent {
    let mut chain = p.ancestors().map(|dir| serde_json::json!({"path":dir,"identity":dir_identity(&fs::metadata(dir).unwrap())})).collect::<Vec<_>>();
    chain.reverse();
    AnchoredParent::open(p, &serde_json::json!(chain)).unwrap()
}
impl Fixture {
    fn new() -> Self {
        // Test descriptors under HOME or a private Linux temp mount; permissions and
        // metadata come from real inodes, including after no-replace directory capture.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let loc = root.join("retained");
        let state = tmp.path().join("state");
        fs::create_dir_all(&loc).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("keep"), b"preserved derivative").unwrap();
        let mut table = Table::new();
        for name in ["0001.sst", "CURRENT", "MANIFEST-02"] {
            let file = loc.join(name);
            let value = format!("retained {name}");
            fs::write(&file, &value).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
            table.insert(
                name.into(),
                (
                    signature(&fs::metadata(&file).unwrap()).unwrap(),
                    format!("{:x}", Sha256::digest(value.as_bytes())),
                ),
            );
        }
        let dir = signature(&fs::metadata(&loc).unwrap()).unwrap();
        Self {
            _tmp: tmp,
            root_path: root.clone(),
            state_path: state.clone(),
            parent: anchor(&root),
            state: anchor(&state),
            dir,
            table,
        }
    }
    fn run(&self, gate: impl Fn(&str) -> Result<()>) -> Result<serde_json::Value> {
        Transaction {
            parent: &self.parent,
            state: &self.state,
            table: &self.table,
            dir_id: &self.dir,
            admission: "fixture approval",
            table_sha: "fixture table",
        }
        .retire(gate)
    }
}
#[test]
fn exact_members_only_and_idempotent() {
    let f = Fixture::new();
    let a = f.run(|_| Ok(())).unwrap();
    let b = f
        .run(|_| bail!("completed should not need another gate"))
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(a["removed_members"], 3);
    assert!(!f.root_path.join("retained").exists());
    assert!(f.root_path.join("keep").is_file());
    assert!(!f.state_path.join("captured-rocksdb").exists());
}
#[test]
fn rejected_gate_before_and_after_capture_preserves_bytes() {
    let f = Fixture::new();
    assert!(f.run(|_| bail!("gate rejected")).is_err());
    assert!(f.root_path.join("retained/0001.sst").is_file());
    assert!(
        f.run(|phase| if phase == "after-capture" {
            bail!("consumer holds file")
        } else {
            Ok(())
        })
        .is_err()
    );
    assert!(f.state_path.join("captured-rocksdb/0001.sst").is_file());
    assert!(!f.state_path.join("unlink-authority.json").exists());
    assert!(!f.state_path.join("complete.json").exists());
    assert!(f.run(|_| Ok(())).is_ok());
}
#[test]
fn replaced_member_and_unknown_symlink_preserved() {
    let f = Fixture::new();
    let p = f.root_path.join("retained/0001.sst");
    fs::rename(&p, f.root_path.join("original")).unwrap();
    symlink(f.root_path.join("keep"), &p).unwrap();
    assert!(f.run(|_| Ok(())).is_err());
    assert!(p.is_symlink());
    assert!(f.root_path.join("keep").is_file());
}
#[test]
fn interruption_after_member_capture_rehashes_and_resumes() {
    let f = Fixture::new();
    assert!(
        f.run(|phase| if phase == "after-capture" {
            bail!("injected interruption")
        } else {
            Ok(())
        })
        .is_err()
    );
    let contract =
        serde_json::from_slice(&fs::read(f.state_path.join("intent.json")).unwrap()).unwrap();
    crate::atomic_fs::publish(&f.state.directory, "unlink-authority.json", &contract).unwrap();
    let dir = open_at(
        &f.state.directory,
        "captured-rocksdb",
        libc::O_RDONLY | libc::O_DIRECTORY,
    )
    .unwrap();
    let tomb = private_child(&f.state.directory, "captured-members").unwrap();
    rename_no_replace(&dir, "0001.sst", &tomb, "0001.sst").unwrap();
    dir.sync_all().unwrap();
    tomb.sync_all().unwrap();
    drop(tomb);
    f.run(|_| Ok(())).unwrap();
    assert!(f.root_path.join("keep").exists());
}
#[test]
fn refuses_conflicting_source_after_capture() {
    let f = Fixture::new();
    assert!(
        f.run(|phase| if phase == "after-capture" {
            bail!("injected interruption")
        } else {
            Ok(())
        })
        .is_err()
    );
    fs::create_dir(f.root_path.join("retained")).unwrap();
    File::create(f.root_path.join("retained/foreign")).unwrap();
    assert!(f.run(|_| Ok(())).is_err());
    assert!(f.root_path.join("retained/foreign").is_file());
    assert!(f.state_path.join("captured-rocksdb/CURRENT").is_file());
}

#[test]
fn missing_uncaptured_member_is_never_credited() {
    let f = Fixture::new();
    assert!(
        f.run(|phase| if phase == "after-capture" {
            bail!("stop")
        } else {
            Ok(())
        })
        .is_err()
    );
    let contract =
        serde_json::from_slice(&fs::read(f.state_path.join("intent.json")).unwrap()).unwrap();
    crate::atomic_fs::publish(&f.state.directory, "unlink-authority.json", &contract).unwrap();
    fs::rename(
        f.state_path.join("captured-rocksdb/CURRENT"),
        f.root_path.join("keep-original-current"),
    )
    .unwrap();
    assert!(
        f.run(|_| Ok(()))
            .unwrap_err()
            .to_string()
            .contains("durable capture journal")
    );
    assert!(f.state_path.join("captured-rocksdb/0001.sst").is_file());
    assert!(!f.state_path.join("complete.json").exists());
}
#[test]
fn after_capture_rejects_substituted_member() {
    let f = Fixture::new();
    assert!(
        f.run(|phase| if phase == "after-capture" {
            bail!("stop")
        } else {
            Ok(())
        })
        .is_err()
    );
    let p = f.state_path.join("captured-rocksdb/CURRENT");
    fs::rename(&p, f.root_path.join("retained-current")).unwrap();
    fs::write(p, b"foreign replacement").unwrap();
    assert!(f.run(|_| Ok(())).is_err());
    assert!(!f.state_path.join("complete.json").exists());
}
