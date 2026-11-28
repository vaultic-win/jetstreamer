//! One explicitly reviewed read-only directory anchor, never a worker file or mapping.
//! The private witness can only be constructed by live before/after proc checks.
use crate::{fsutil as f, model::*, validate};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
pub(crate) const TARGET: &str =
    "/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1/lane-a/private";
const REFERENCE: &str = "pid 2467123 fd 9";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    pid: u64,
    invocation_id: String,
    start_ticks: u64,
    fd: u64,
    target: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    flags: u64,
    mount_id: u64,
    position: u64,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Evidence {
    schema: &'static str,
    spec: Spec,
    actual_reference: &'static str,
    actual_fdinfo: String,
    actual_cgroup: String,
    actual_target: PathBuf,
    actual_start_ticks: u64,
    directory_only: bool,
    memory_credit_bytes: u64,
    #[serde(rename = "DATA_credit_bytes")]
    data_credit_bytes: u64,
    replay_launch_authorized: bool,
}
fn validate_spec(s: &Spec, start_ticks: u64) -> Result<()> {
    ensure!(
        s.schema == "terminal199-exact-readonly-controller-directory-anchor-v1"
            && s.pid == CONTROLLER_PID
            && s.invocation_id == CONTROLLER_IID
            && start_ticks > 0
            && s.start_ticks == start_ticks
            && s.fd == 9
            && s.target == Path::new(TARGET)
            && s.device == 64512
            && s.inode == 98372932
            && s.uid == 1001
            && s.gid == 1003
            && s.mode == 0o700
            && s.flags == 0o2700000
            && s.mount_id == 629
            && s.position == 0,
        "unqualified controller directory anchor scope"
    );
    ensure!(
        s.flags & libc::O_ACCMODE as u64 == libc::O_RDONLY as u64
            && s.flags & libc::O_DIRECTORY as u64 != 0,
        "controller anchor is not a read-only directory"
    );
    Ok(())
}
fn from_review(v: &Value, start_ticks: u64) -> Result<Option<Spec>> {
    let Some(raw) = v
        .as_object()
        .context("scope review object")?
        .get("controller_directory_anchor")
    else {
        return Ok(None);
    };
    let s: Spec = serde_json::from_value(raw.clone())?;
    validate_spec(&s, start_ticks)?;
    Ok(Some(s))
}
fn read(path: &Path) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    File::open(path)?.take(65537).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 65536, "bounded anchor proc input");
    Ok(raw)
}
fn ticks(raw: &[u8]) -> Result<u64> {
    Ok(std::str::from_utf8(raw)?
        .rsplit_once(')')
        .context("anchor proc stat framing")?
        .1
        .split_whitespace()
        .nth(19)
        .context("anchor process start ticks")?
        .parse()?)
}
fn fdinfo(raw: &str) -> Result<BTreeMap<String, u64>> {
    let mut rows = BTreeMap::new();
    for line in raw.lines() {
        let (key, value) = line.split_once(':').context("anchor fdinfo framing")?;
        let value = value.trim();
        ensure!(
            !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
            "anchor fdinfo number"
        );
        let n = if key == "flags" {
            u64::from_str_radix(value, 8)?
        } else {
            value.parse()?
        };
        ensure!(
            rows.insert(key.to_owned(), n).is_none(),
            "duplicate anchor fdinfo field"
        );
    }
    ensure!(
        rows.keys().map(String::as_str).collect::<Vec<_>>()
            == vec!["flags", "ino", "mnt_id", "pos"],
        "unqualified anchor fdinfo fields"
    );
    Ok(rows)
}
fn metadata(s: &Spec, m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_dir()
            && m.dev() == s.device
            && m.ino() == s.inode
            && m.uid() == s.uid
            && m.gid() == s.gid
            && m.mode() & 0o7777 == s.mode,
        "anchor is a changed directory or a regular bank file"
    );
    Ok(())
}
fn snapshot(s: &Spec) -> Result<Evidence> {
    let root = PathBuf::from(format!("/proc/{}", s.pid));
    let start = ticks(&read(&root.join("stat"))?)?;
    ensure!(start == s.start_ticks, "controller anchor PID reused");
    let group = String::from_utf8(read(&root.join("cgroup"))?)?;
    ensure!(
        group.trim_end() == format!("0::/system.slice/{CONTROLLER}"),
        "controller anchor cgroup changed"
    );
    let target = fs::read_link(root.join(format!("fd/{}", s.fd)))?;
    ensure!(
        target == s.target && target.canonicalize()? == s.target,
        "controller anchor target changed"
    );
    // No symlink component may redirect the exact reviewed directory.
    let mut prefix = PathBuf::from("/");
    for part in target.components().skip(1) {
        prefix.push(part);
        ensure!(
            fs::symlink_metadata(&prefix)?.is_dir(),
            "anchor directory path contains a symlink"
        );
    }
    metadata(s, &fs::symlink_metadata(&target)?)?;
    metadata(s, &fs::metadata(root.join(format!("fd/{}", s.fd)))?)?;
    let info = String::from_utf8(read(&root.join(format!("fdinfo/{}", s.fd)))?)?;
    let fields = fdinfo(&info)?;
    ensure!(
        fields["flags"] == s.flags
            && fields["ino"] == s.inode
            && fields["mnt_id"] == s.mount_id
            && fields["pos"] == s.position,
        "controller anchor flags/identity changed"
    );
    ensure!(
        ticks(&read(&root.join("stat"))?)? == start,
        "controller changed across anchor snapshot"
    );
    Ok(Evidence {
        schema: "terminal199-actual-controller-directory-anchor-evidence-v1",
        spec: s.clone(),
        actual_reference: REFERENCE,
        actual_fdinfo: info,
        actual_cgroup: group,
        actual_target: target,
        actual_start_ticks: start,
        directory_only: true,
        memory_credit_bytes: 0,
        data_credit_bytes: 0,
        replay_launch_authorized: false,
    })
}
pub(crate) fn observe(p: &Policy, native: &Value) -> Result<Option<Evidence>> {
    let review = f::immutable(&p.census_scope_review)?;
    let Some(s) = from_review(&review, p.controller_start_ticks)? else {
        return Ok(None);
    };
    validate::controller(native)?;
    let a = snapshot(&s)?;
    ensure!(
        a == snapshot(&s)?,
        "controller directory anchor changed across snapshot"
    );
    Ok(Some(a))
}
pub(crate) fn permits(reference: &str, evidence: Option<&Evidence>) -> bool {
    reference == REFERENCE && evidence.is_some_and(|e| e.actual_reference == reference)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn actual() -> Spec {
        Spec {
            schema: "terminal199-exact-readonly-controller-directory-anchor-v1".into(),
            pid: CONTROLLER_PID,
            invocation_id: CONTROLLER_IID.into(),
            start_ticks: 123,
            fd: 9,
            target: TARGET.into(),
            device: 64512,
            inode: 98372932,
            uid: 1001,
            gid: 1003,
            mode: 0o700,
            flags: 0o2700000,
            mount_id: 629,
            position: 0,
        }
    }
    #[test]
    fn exact_observed_shape_requires_explicit_opt_in() {
        assert!(from_review(&serde_json::json!({}), 123).unwrap().is_none());
        assert!(
            from_review(
                &serde_json::json!({"controller_directory_anchor":null}),
                123
            )
            .is_err()
        );
        assert_eq!(
            from_review(
                &serde_json::json!({"controller_directory_anchor":actual()}),
                123
            )
            .unwrap(),
            Some(actual())
        );
        assert!(!permits(REFERENCE, None));
    }
    #[test]
    fn no_foreign_or_changed_scope_can_be_classified() {
        let s = actual();
        let base = serde_json::to_value(&s).unwrap();
        for (key, value) in [
            ("pid", serde_json::json!(2467124)),
            ("fd", serde_json::json!(10)),
            ("inode", serde_json::json!(98372933)),
            ("device", serde_json::json!(64513)),
            ("uid", serde_json::json!(0)),
            ("gid", serde_json::json!(0)),
            ("mode", serde_json::json!(0o755)),
            ("flags", serde_json::json!(0o2700001)),
            ("flags", serde_json::json!(0o2000000)),
            ("mount_id", serde_json::json!(630)),
            ("position", serde_json::json!(1)),
            ("target", serde_json::json!("/tmp")),
            ("invocation_id", serde_json::json!(PRODUCER_IID)),
            ("start_ticks", serde_json::json!(124)),
        ] {
            let mut changed = base.clone();
            changed[key] = value;
            assert!(
                validate_spec(&serde_json::from_value(changed).unwrap(), 123).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn exact_fdinfo_is_required_without_duplicates_or_extra_fields() {
        let actual = "pos:\t0\nflags:\t02700000\nmnt_id:\t629\nino:\t98372932\n";
        assert_eq!(fdinfo(actual).unwrap()["flags"], 0o2700000);
        assert!(fdinfo(&format!("{actual}pos:\t0\n")).is_err());
        assert!(fdinfo("flags: 02800000\npos: 0\nino: 1\nmnt_id: 1\n").is_err());
        assert!(fdinfo(&format!("{actual}other: 1\n")).is_err());
    }
    #[test]
    fn regular_files_and_other_references_remain_rejected() {
        let tmp = tempfile::tempfile().unwrap();
        assert!(metadata(&actual(), &tmp.metadata().unwrap()).is_err());
        let e = Evidence {
            schema: "test",
            spec: actual(),
            actual_reference: REFERENCE,
            actual_fdinfo: String::new(),
            actual_cgroup: String::new(),
            actual_target: TARGET.into(),
            actual_start_ticks: 123,
            directory_only: true,
            memory_credit_bytes: 0,
            data_credit_bytes: 0,
            replay_launch_authorized: false,
        };
        assert!(permits(REFERENCE, Some(&e)));
        for reference in [
            "pid 2467123 fd 10",
            "pid 2467124 fd 9",
            "pid 2467123 maps",
            "pid 2467123 cwd",
            "pid 2467123 root",
        ] {
            assert!(!permits(reference, Some(&e)));
        }
    }
}
