//! Explicit consumption of the genuinely verified original199 inputs.
//! Callers must select a hash-bound policy. This module never discovers a cache,
//! opens an original input body, changes a guard, or grants resource credit.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

const EVIDENCE: &str = "/usr/local/lib/jetstreamer/horizon-original199-input-witness-actual-second-accepted-20261107-v3";
const PRODUCER_PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-original199-input-witness-tools-20261107-v3";
const STATE_PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-original199-quarantined-state-capture-20261107-v1";
const PRODUCER_SHA: &str = "53346c7900eb2a17f8da59897b2dbaf0a22f137f64f0cdfd70376bd1ededc027";
const ACTUAL_UNIT: &str = "horizon-original199-input-witness-actual-second-20261107-v3.service";
const ACTUAL_IID: &str = "dc4c92601a7a41419d485c52f147ceb1";
const STATE: &str = "/var/lib/jetstreamer-root-sweep-epoch199-backfill-20261102-v1/state.json";
const ROSTER: [(&str, &str, u64); 5] = [
    (
        "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/jetstreamer-node",
        "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65",
        128 << 20,
    ),
    (
        "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/jetstreamer-historical-worker-v1-6-15",
        "9339aa0ee5c39e91ec446bfa561c0e81280a0ddc474a03cf5bb0ce07a3674893",
        128 << 20,
    ),
    (
        "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/preflight-199-with-private-200-tail-v4.json",
        "9a975243f50d37ed71329b5f3cd0f5e4a4c83faf2e8018f6db41ed9170ac1de9",
        128 << 20,
    ),
    (
        "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/snapshot-85967282-BQvC7FcQTSguJkWHeLnpkVSFv32ZKRqUbgHKxVF97o3x.tar.zst",
        "d4a74f54f44258fd4b078d8d3304a6cb6a7911a87883160e1579727dafbf9e6d",
        8_000_000_000,
    ),
    (
        STATE,
        "051642bf5ff3f1fffb5e7d8b2133ff399a0a0f1947fef50c74976b12858da152",
        16 << 20,
    ),
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: String,
    original_enrollment: Bound,
    original_context: Bound,
    witness: Bound,
    witness_seal: Bound,
    producer: Bound,
    producer_seal: Bound,
    completion: Bound,
    root_acceptance: Bound,
    state_copy: Bound,
    state_copy_seal: Bound,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
impl Identity {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Member {
    binding: Bound,
    identity: Identity,
    complete_bytes_hashed: u64,
}
/// Private fields ensure only successful full proof validation creates this value.
#[derive(Clone, Debug)]
pub struct SelectedInputs {
    selection: Bound,
    policy: Selection,
    members: Vec<Member>,
}
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn exact(b: &Bound, path: &str, hash: &str) -> Result<()> {
    ensure!(
        b.path == Path::new(path) && b.sha256 == hash,
        "selected input-verification evidence crossed its qualified binding"
    );
    Ok(())
}
fn policy(p: &Selection) -> Result<()> {
    ensure!(
        p.schema == "horizon-original199-explicit-complete-input-witness-selection-v1",
        "unknown input-verification policy"
    );
    exact(
        &p.original_enrollment,
        "/home/sol/.jetstreamer-private/epoch199-backfill-current-preparation-20261102-v1/ACTUAL2258_R2_ENROLLMENT.json",
        "a2313858851adecca3ff2e144cb61d342cf6757c2dd1249ba0ab88f9770f6b80",
    )?;
    exact(
        &p.original_context,
        "/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v2/registry.json",
        "733487fcb07438d603999234b0a0598d62261ba0c1cb0ba6003693260ebc1389",
    )?;
    for (b, root, name, hash) in [
        (
            &p.witness,
            EVIDENCE,
            "witness.json",
            "97faf3d988eb549dc77ce564869f0d36a5ba7a3717073449a2f443330cd086aa",
        ),
        (
            &p.witness_seal,
            EVIDENCE,
            "deployment-seal-receipt.json",
            "00431452162ce572d98446db539ad088756bd5df11974d4c521d8aeb40f3356c",
        ),
        (&p.producer, PRODUCER_PACKAGE, "input-witness", PRODUCER_SHA),
        (
            &p.producer_seal,
            PRODUCER_PACKAGE,
            "deployment-seal-receipt.json",
            "5549020f70bb3e36d116bd534944b75e37a887b0fa6c6c6faf6f36353aa48235",
        ),
        (
            &p.completion,
            EVIDENCE,
            "original-completion.json",
            "aa7741d6bd85aa00193c81ff7287dcdaa56fe0ccee648c1b611f6e805eec3144",
        ),
        (
            &p.root_acceptance,
            EVIDENCE,
            "acceptance.json",
            "c728698afbbb6dac654b3e3c14428622e51c1e58a53392a4f241e2a451312eb2",
        ),
        (&p.state_copy, STATE_PACKAGE, "state.json", ROSTER[4].1),
        (
            &p.state_copy_seal,
            STATE_PACKAGE,
            "deployment-seal-receipt.json",
            "13a332a0b63312f182f9198f36c6eff2a7237b90181e989f20fc2d5d5c547f70",
        ),
    ] {
        exact(b, &format!("{root}/{name}"), hash)?;
    }
    Ok(())
}
/// Metadata traversal deliberately never opens an original body or directory FD.
fn metadata(path: &Path, cap: u64, mutable_state: bool) -> Result<fs::Metadata> {
    ensure!(path.is_absolute(), "nonabsolute verification input");
    let mut prefix = PathBuf::new();
    for c in path.components() {
        ensure!(
            matches!(c, Component::RootDir | Component::Normal(_)),
            "noncanonical verification input"
        );
        prefix.push(c.as_os_str());
        let m = fs::symlink_metadata(&prefix)?;
        ensure!(
            m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0 && !m.file_type().is_symlink(),
            "verification input/ancestor lacks root custody"
        );
        if prefix != path {
            ensure!(m.is_dir(), "non-directory verification ancestor");
        }
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() > 0 && m.len() <= cap,
        "verification input shape or size"
    );
    if mutable_state {
        ensure!(m.mode() & 0o777 == 0o600, "quarantined state mode changed");
    } else {
        ensure!(
            m.mode() & 0o222 == 0,
            "immutable verification evidence is writable"
        );
    }
    Ok(m)
}
fn stable_bytes(b: &Bound, cap: u64) -> Result<Vec<u8>> {
    ensure!(digest(&b.sha256), "invalid verification evidence digest");
    // Original bodies are forbidden even if a caller supplies their right hash.
    ensure!(
        !ROSTER.iter().any(|(p, _, _)| b.path == Path::new(p)),
        "original input bodies cannot be read by a witness consumer"
    );
    let before = Identity::of(&metadata(&b.path, cap, false)?);
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&b.path)?;
    ensure!(
        Identity::of(&f.metadata()?) == before,
        "verification evidence changed at open"
    );
    let mut raw = Vec::new();
    Read::by_ref(&mut f)
        .take(cap.checked_add(1).context("verification cap overflow")?)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == before.bytes
            && sha(&raw) == b.sha256
            && Identity::of(&f.metadata()?) == before
            && Identity::of(&metadata(&b.path, cap, false)?) == before,
        "verification evidence bytes or identity changed"
    );
    Ok(raw)
}
fn read(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&stable_bytes(b, 128 << 10)?)?)
}
fn sealed(seal: &Value, b: &Bound, mode: &str) -> Result<()> {
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1",
        "verification evidence lacks normal deployment seal"
    );
    let root = Path::new(
        seal["destination"]
            .as_str()
            .context("verification seal destination")?,
    );
    ensure!(
        b.path.parent() == Some(root),
        "verification seal belongs to another package"
    );
    let matches = seal["members"]
        .as_array()
        .context("verification seal members")?
        .iter()
        .filter(|m| m["name"].as_str().is_some_and(|n| root.join(n) == b.path))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1
            && matches[0]["sha256"] == b.sha256
            && matches[0]["mode"] == mode
            && matches[0]["bytes"].as_u64().is_some_and(|n| n > 0),
        "verification seal member changed, missing or duplicated"
    );
    Ok(())
}
fn witness(v: &Value, p: &Selection) -> Result<Vec<Member>> {
    ensure!(
        v["schema"] == "horizon-original199-complete-input-verification-witness-v1"
            && v["producer_program"] == serde_json::to_value(&p.producer)?
            && v["producer_unit"] == ACTUAL_UNIT
            && v["producer_invocation_id"] == ACTUAL_IID,
        "verification witness producer differs"
    );
    for k in [
        "all_original_sources_fully_hashed",
        "all_protected_source_descriptors_closed_before_native_recheck",
        "original_guard_actor_timer_unchanged",
    ] {
        ensure!(v[k] == true, "incomplete verification witness: {k}");
    }
    ensure!(
        v["resource_credit_bytes"] == 0
            && v["replay_launch_authorized"] == false
            && v["archive_publication_authorized"] == false,
        "verification witness authority expanded"
    );
    let start = v["started_monotonic_usec"]
        .as_u64()
        .context("verification start")?;
    let end = v["completed_monotonic_usec"]
        .as_u64()
        .context("verification end")?;
    ensure!(
        end > start && end - start < 15_000_000,
        "verification witness exceeded finite source-hash budget"
    );
    let members: Vec<Member> = serde_json::from_value(v["verified_inputs"].clone())?;
    ensure!(
        members.len() == ROSTER.len(),
        "verification witness source census differs"
    );
    for (member, (path, hash, cap)) in members.iter().zip(ROSTER) {
        exact(&member.binding, path, hash)?;
        let id = &member.identity;
        ensure!(
            member.complete_bytes_hashed == id.bytes
                && id.bytes > 0
                && id.bytes <= cap
                && id.uid == 0
                && id.gid == 0
                && id.links == 1
                && id.mode & libc::S_IFMT == libc::S_IFREG
                && id.mode & 0o022 == 0
                && (if path == STATE {
                    id.mode & 0o777 == 0o600
                } else {
                    id.mode & 0o222 == 0
                }),
            "verification witness lacks complete bytes/custody"
        );
    }
    Ok(members)
}
fn completion(v: &Value) -> Result<()> {
    ensure!(
        v["producer_unit"] == ACTUAL_UNIT
            && v["original_IID"] == ACTUAL_IID
            && v["original_cgroup_absent"] == true
            && v["original_process_absent"] == true
            && v["source_identity_metadata_rechecked_without_body_descriptors"] == true,
        "verification original native completion missing"
    );
    let rows = v["PID1"]
        .as_array()
        .context("verification original PID1 journal")?;
    ensure!(
        rows.iter().any(|r| r["_PID"] == "1"
            && r["UNIT"] == ACTUAL_UNIT
            && r["INVOCATION_ID"] == ACTUAL_IID
            && r["JOB_RESULT"] == "done"),
        "verification witness lacks its genuine original successful PID1 completion"
    );
    Ok(())
}
impl SelectedInputs {
    fn load(selection: &Bound) -> Result<Self> {
        let p: Selection = serde_json::from_slice(&stable_bytes(selection, 128 << 10)?)?;
        policy(&p)?;
        let witness_seal = read(&p.witness_seal)?;
        for b in [&p.witness, &p.completion, &p.root_acceptance] {
            sealed(&witness_seal, b, "0444")?;
        }
        sealed(&read(&p.producer_seal)?, &p.producer, "0555")?;
        ensure!(
            stable_bytes(&p.producer, 128 << 20)?.starts_with(b"\x7fELF"),
            "qualified witness producer is not ELF"
        );
        sealed(&read(&p.state_copy_seal)?, &p.state_copy, "0444")?;
        let members = witness(&read(&p.witness)?, &p)?;
        completion(&read(&p.completion)?)?;
        let a = read(&p.root_acceptance)?;
        ensure!(
            a["schema"] == "horizon-original199-complete-input-witness-root-acceptance-v1"
                && a["complete_bytes_hashed"] == 8_054_507_614u64
                && a["resource_credit_bytes"] == 0
                && a["replay_admission_authorized"] == false
                && a["archive_publication_authorized"] == false,
            "qualified witness acceptance differs"
        );
        let out = Self {
            selection: selection.clone(),
            policy: p,
            members,
        };
        out.verify_all_original_identities()?;
        Ok(out)
    }
    /// Selection is supplied by the exact current request/context. A caller
    /// cannot use genuine witness bytes for another enrollment or context.
    pub fn load_for(selection: &Bound, enrollment: &Bound, context: &Bound) -> Result<Self> {
        let out = Self::load(selection)?;
        out.require_context(enrollment, context)?;
        Ok(out)
    }
    pub fn require_context(&self, enrollment: &Bound, context: &Bound) -> Result<()> {
        ensure!(
            self.policy.original_enrollment == *enrollment
                && self.policy.original_context == *context,
            "selected witness crosses the explicit enrollment or original context"
        );
        Ok(())
    }
    pub fn original_enrollment(&self) -> &Bound {
        &self.policy.original_enrollment
    }
    pub fn original_context(&self) -> &Bound {
        &self.policy.original_context
    }
    pub fn selection(&self) -> &Bound {
        &self.selection
    }
    pub fn revalidate(&self) -> Result<()> {
        let current = Self::load(&self.selection)?;
        ensure!(
            current.members == self.members,
            "selected verification witness changed"
        );
        Ok(())
    }
    pub fn verify_all_original_identities(&self) -> Result<()> {
        for (member, (path, _, cap)) in self.members.iter().zip(ROSTER) {
            ensure!(
                Identity::of(&metadata(Path::new(path), cap, path == STATE)?) == member.identity,
                "original input identity changed after genuine whole-byte verification: {path}"
            );
        }
        Ok(())
    }
    pub fn verify_member(&self, binding: &Bound, maximum: u64) -> Result<()> {
        let member = self
            .members
            .iter()
            .find(|m| m.binding == *binding)
            .context("member is outside selected complete verification witness")?;
        ensure!(
            member.identity.bytes <= maximum,
            "selected member exceeds caller's existing bound"
        );
        self.revalidate()
    }
    /// The original mutable state's identity is checked on both sides. Only its
    /// independently rehashed, normally sealed exact-byte copy is opened.
    pub fn read_quarantined_state(&self) -> Result<Vec<u8>> {
        self.revalidate()?;
        let raw = stable_bytes(&self.policy.state_copy, 16 << 20)?;
        self.revalidate()?;
        Ok(raw)
    }
}

/// An explicit normally sealed context wrapper binds the unchanged original
/// terminal registry to this witness selection. It never rewrites the original
/// registry, enrollment, state or historical Frame evidence.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedContext {
    schema: String,
    original_context: Bound,
    input_verification_selection: Bound,
}
pub const CONTEXT_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-original199-witness-context-20261107-v1/context.json";
// Recomputed from the exact context candidate after its selection is frozen.
pub const CONTEXT_SHA: &str = "4d45cbd0e71ca8cf591cfd3c435c4b798178de308faaa80a0b262fa9322374c7";
pub fn is_selected_context(binding: &Bound) -> bool {
    binding.path == Path::new(CONTEXT_PATH) && binding.sha256 == CONTEXT_SHA
}
impl SelectedContext {
    pub fn load(binding: &Bound) -> Result<Self> {
        ensure!(
            is_selected_context(binding),
            "unknown selected witness context"
        );
        let out: Self = serde_json::from_slice(&stable_bytes(binding, 128 << 10)?)?;
        ensure!(
            out.schema == "horizon-original199-explicit-input-witness-context-v1",
            "selected context schema differs"
        );
        exact(
            &out.original_context,
            "/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v2/registry.json",
            "733487fcb07438d603999234b0a0598d62261ba0c1cb0ba6003693260ebc1389",
        )?;
        exact(
            &out.input_verification_selection,
            "/usr/local/lib/jetstreamer/horizon-original199-witness-consumer-selection-20261107-v1/selection.json",
            "ca40ef194019d83ee9a9aae51e5a173591e49c7c612745dd99c68b2543f4a6ec",
        )?;
        Ok(out)
    }
    pub fn original_context(&self) -> &Bound {
        &self.original_context
    }
    pub fn select(&self, enrollment: &Bound) -> Result<SelectedInputs> {
        SelectedInputs::load_for(
            &self.input_verification_selection,
            enrollment,
            &self.original_context,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    #[ignore = "requires the separately sealed actual witness selection/context; metadata and sealed-copy reads only"]
    fn actual_selected_context_loads_without_original_input_bodies() {
        let context = SelectedContext::load(&Bound {
            path: CONTEXT_PATH.into(),
            sha256: CONTEXT_SHA.into(),
        })
        .unwrap();
        let expected = selection();
        let selected = context.select(&expected.original_enrollment).unwrap();
        selected.verify_all_original_identities().unwrap();
        let state = selected.read_quarantined_state().unwrap();
        assert_eq!(state.len(), 960);
        assert_eq!(sha(&state), ROSTER[4].1);
        selected.revalidate().unwrap();
    }
    fn selection() -> Selection {
        serde_json::from_str(include_str!("selection-fixture.json")).unwrap()
    }
    fn actual() -> Value {
        serde_json::from_str(include_str!("witness-fixture.json")).unwrap()
    }
    fn file(bytes: &[u8]) -> (PathBuf, Bound) {
        let root = PathBuf::from(std::env::var("TMPDIR").unwrap());
        assert!(root.starts_with(
            "/var/lib/jetstreamer/horizon-original199-witness-consumer-qa-20261107-v1"
        ));
        let p = root.join(format!(
            "input-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
        drop(f);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        let b = Bound {
            path: p.clone(),
            sha256: sha(bytes),
        };
        (p, b)
    }
    #[test]
    fn genuine_full_witness_and_explicit_policy_are_accepted() {
        policy(&selection()).unwrap();
        assert_eq!(witness(&actual(), &selection()).unwrap().len(), 5);
    }
    #[test]
    fn policy_rejects_unknown_or_implicit_evidence() {
        let mut p = selection();
        p.witness.path = PathBuf::from("/tmp/discovered-witness.json");
        assert!(policy(&p).is_err());
        p = selection();
        p.original_context.sha256 = "b".repeat(64);
        assert!(policy(&p).is_err());
        p = selection();
        p.original_enrollment.sha256 = "a".repeat(64);
        assert!(policy(&p).is_err());
    }
    #[test]
    fn selection_rejects_unknown_fields() {
        let mut p: Value = serde_json::from_str(include_str!("selection-fixture.json")).unwrap();
        p["ambient_cache"] = true.into();
        assert!(serde_json::from_value::<Selection>(p).is_err());
    }
    #[test]
    fn witness_rejects_missing_duplicate_partial_or_wrong_sources() {
        for mode in 0..4 {
            let mut w = actual();
            let a = w["verified_inputs"].as_array_mut().unwrap();
            match mode {
                0 => {
                    a.pop();
                }
                1 => {
                    a[1] = a[0].clone();
                }
                2 => {
                    a[3]["complete_bytes_hashed"] = 1.into();
                }
                _ => {
                    a[3]["binding"]["sha256"] = "a".repeat(64).into();
                }
            };
            assert!(witness(&w, &selection()).is_err());
        }
    }
    #[test]
    fn witness_rejects_unqualified_producer_and_authority() {
        for (k, val) in [
            ("producer_invocation_id", Value::from("f".repeat(32))),
            ("all_original_sources_fully_hashed", false.into()),
            ("resource_credit_bytes", 1.into()),
            ("replay_launch_authorized", true.into()),
        ] {
            let mut w = actual();
            w[k] = val;
            assert!(witness(&w, &selection()).is_err());
        }
    }
    #[test]
    fn overlong_or_reversed_source_hash_interval_is_rejected() {
        for end in [
            0u64,
            actual()["started_monotonic_usec"].as_u64().unwrap() + 15_000_000,
        ] {
            let mut w = actual();
            w["completed_monotonic_usec"] = end.into();
            assert!(witness(&w, &selection()).is_err());
        }
    }
    #[test]
    fn unknown_or_writable_source_identity_is_rejected() {
        let mut w = actual();
        w["verified_inputs"][0]["identity"]["uid"] = 1001.into();
        assert!(witness(&w, &selection()).is_err());
        w = actual();
        w["verified_inputs"][0]["identity"]["mode"] = 0o100644.into();
        assert!(witness(&w, &selection()).is_err());
        w = actual();
        w["verified_inputs"][0]["identity"]["ignored_identity"] = true.into();
        assert!(witness(&w, &selection()).is_err());
    }
    #[test]
    fn changed_identity_never_reuses_verified_bytes() {
        let (p, b) = file(b"original");
        let before = Identity::of(&metadata(&p, 1024, false).unwrap());
        assert_eq!(stable_bytes(&b, 1024).unwrap(), b"original");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&p, b"replacement").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        assert_ne!(before, Identity::of(&metadata(&p, 1024, false).unwrap()));
        assert!(stable_bytes(&b, 1024).is_err());
        fs::remove_file(p).unwrap();
    }
    #[test]
    fn original_bodies_are_denied_before_open_even_with_exact_digest() {
        for (p, s, cap) in ROSTER {
            assert!(
                stable_bytes(
                    &Bound {
                        path: p.into(),
                        sha256: s.into()
                    },
                    cap
                )
                .is_err()
            );
        }
    }
    #[test]
    fn immutable_body_reader_checks_whole_digest_bound_and_symlink() {
        let (p, b) = file(b"full immutable evidence");
        assert_eq!(stable_bytes(&b, 1024).unwrap(), b"full immutable evidence");
        assert!(stable_bytes(&b, 2).is_err());
        let alias = p.with_extension("alias");
        symlink(&p, &alias).unwrap();
        assert!(
            stable_bytes(
                &Bound {
                    path: alias.clone(),
                    sha256: b.sha256.clone()
                },
                1024
            )
            .is_err()
        );
        fs::remove_file(alias).unwrap();
        fs::remove_file(p).unwrap();
    }
    #[test]
    fn completion_requires_the_actual_successful_original_pid1() {
        let mut v = serde_json::json!({"producer_unit":ACTUAL_UNIT,"original_IID":ACTUAL_IID,"original_cgroup_absent":true,"original_process_absent":true,"source_identity_metadata_rechecked_without_body_descriptors":true,"PID1":[{"_PID":"1","UNIT":ACTUAL_UNIT,"INVOCATION_ID":ACTUAL_IID,"JOB_RESULT":"done"}]});
        completion(&v).unwrap();
        v["PID1"][0]["INVOCATION_ID"] = "b".repeat(32).into();
        assert!(completion(&v).is_err());
    }
    #[test]
    fn seal_cannot_borrow_another_member_or_package() {
        let b = selection().state_copy;
        let mut v = serde_json::json!({"schema":"jetstreamer-sealed-deployment-receipt-v1","destination":STATE_PACKAGE,"members":[{"name":"state.json","sha256":b.sha256,"bytes":960,"mode":"0444"}]});
        sealed(&v, &b, "0444").unwrap();
        v["members"][0]["mode"] = "0600".into();
        assert!(sealed(&v, &b, "0444").is_err());
    }
    #[test]
    fn exact_context_candidate_digest_is_frozen_without_selecting_legacy_contexts() {
        assert_eq!(sha(include_bytes!("context-fixture.json")), CONTEXT_SHA);
        let selected = Bound {
            path: CONTEXT_PATH.into(),
            sha256: CONTEXT_SHA.into(),
        };
        assert!(is_selected_context(&selected));
        assert!(!is_selected_context(&selection().original_context));
        let mut other = selected;
        other.sha256 = "0".repeat(64);
        assert!(!is_selected_context(&other));
    }
    #[test]
    fn explicit_context_selection_cannot_cross_enrollment_or_original_registry() {
        let policy = selection();
        let selected = SelectedInputs {
            selection: Bound {
                path: "/unused/selected.json".into(),
                sha256: "a".repeat(64),
            },
            members: witness(&actual(), &policy).unwrap(),
            policy,
        };
        selected
            .require_context(
                &selected.policy.original_enrollment,
                &selected.policy.original_context,
            )
            .unwrap();
        let mut crossed = selected.policy.original_enrollment.clone();
        crossed.sha256 = "b".repeat(64);
        assert!(
            selected
                .require_context(&crossed, &selected.policy.original_context)
                .is_err()
        );
        crossed = selected.policy.original_context.clone();
        crossed.path = "/some/other/context.json".into();
        assert!(
            selected
                .require_context(&selected.policy.original_enrollment, &crossed)
                .is_err()
        );
    }
    #[test]
    fn missing_or_extra_context_wrapper_fields_are_rejected() {
        let candidate: Value = serde_json::from_str(include_str!("context-fixture.json")).unwrap();
        for key in ["schema", "original_context", "input_verification_selection"] {
            let mut value = candidate.clone();
            value.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<SelectedContext>(value).is_err());
        }
        let mut value = candidate;
        value["ambient_selection"] = true.into();
        assert!(serde_json::from_value::<SelectedContext>(value).is_err());
    }
}
