//! Read-only original-slot allocation witnesses. No ending, launch, deletion or signal authority.
//! The caller MUST route every error for a live producer through its existing bound stop path.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) const FLOOR: u64 = 6_264_131_239_730;
pub(super) const DATA: u64 = 6_229_838_610_226;
pub(super) const CAP: u64 = 309_237_645_312;
const MEMORY: u64 = 759_789_531_136;
const MARGIN: u64 = 1 << 30;
const MAXIMUM: u64 = 241_482_399_744;
const HEAD: &str = "/usr/local/lib/jetstreamer/horizon-original154-future-data-current-authority-20261110-v1/authority.json";
const HEAD_SHA: &str = "2f88b7f91cc6df70804cd96027efbd0e18cb6452a48e76d813673b556d727caa";
const ANCESTRY: &str = "/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/original154-future-data-qa-v2/ACTUAL_ORIGINAL154_FUTURE_DATA_CHECK.json";
const ANCESTRY_SHA: &str = "03a9fe761e5ce4aa4d694abc0cdbb59db9c29b898442334e9c2d3c556bfab399";
const MANIFEST: &str = "/usr/local/lib/jetstreamer/horizon-original154-future-data-source-20261110-v2/lineage-manifest.json";
const MANIFEST_SHA: &str = "4906d22bdcc5656c2f28da7a9a28d45496c65ca57fc13cf898382b09a514b505";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const PRIMARY: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub contract: Bound,
    pub deployment_seal: Bound,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Slot {
    pub epoch: u64,
    pub lane_root: PathBuf,
    pub original_booking: Bound,
    pub physical_ledger: Option<Bound>,
    pub members: Vec<PathBuf>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WitnessSet {
    schema: String,
    owner: String,
    primary_thread: String,
    complete_authority: Bound,
    accepted_original154_ancestry: Bound,
    lineage_manifest: Bound,
    raw_minimum_free_bytes: u64,
    #[serde(rename = "complete_DATA_bytes")]
    complete_data_bytes: u64,
    full_original_root_cap_bytes: u64,
    margin_per_credited_slot_bytes: u64,
    maximum_fulfillment_bytes: u64,
    pub slots: Vec<Slot>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    schema: String,
    witness_set: Bound,
    witness_set_deployment_seal: Bound,
    qualified_native_witness: Bound,
    maximum_fulfilled_bytes: u64,
}
#[derive(Debug)]
pub(super) struct Scope<'a> {
    pub unit: &'a str,
    pub invocation_id: &'a str,
    pub filesystem: &'a Path,
    pub worker_root: &'a Path,
    pub raw_floor: u64,
    pub root_cap: Option<u64>,
    pub max_vmas: u64,
    pub special_profile: bool,
    pub initial_available_bytes: u64,
    pub guard_sha256: &'a str,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Ancestor {
    path: PathBuf,
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    // Global ancestors admit unrelated child creation; the owned lane and descendants do not.
    owned_change_times: Option<[i64; 4]>,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Fact {
    epoch: u64,
    path: PathBuf,
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    logical_bytes: u64,
    allocated_blocks512: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    birth_seconds: i64,
    birth_nanoseconds: u32,
    ancestors: Vec<Ancestor>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FreePoint {
    available_bytes: u64,
    device: u64,
    filesystem_magic: i64,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Allocation {
    pub first: Vec<Fact>,
    pub second: Vec<Fact>,
    pub filesystem_before: FreePoint,
    pub filesystem_midpoint: FreePoint,
    pub filesystem_after: FreePoint,
    pub conservative_available_bytes: u64,
    pub per_slot: BTreeMap<u64, u64>,
    pub conservative_fulfilled_bytes: u64,
}
#[derive(Debug, Serialize)]
pub(super) struct Observation {
    pub conservative_available_bytes: u64,
    pub fulfilled_bytes: u64,
    pub available_plus_fulfilled_bytes: u64,
    pub effective_required_free_bytes: u64,
    pub evidence: Value,
}
fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn lower_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn n(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("missing integer {key}"))
}
fn expected(path: &str, sha256: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha256.into(),
    }
}
fn pins() -> Result<Value> {
    Ok(serde_json::from_str(include_str!("PINNED_INPUTS.json"))?)
}
fn stable(m: &fs::Metadata) -> [u64; 12] {
    [
        m.dev(),
        m.ino(),
        m.uid().into(),
        m.gid().into(),
        m.mode().into(),
        m.nlink(),
        m.len(),
        m.blocks(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]
}
fn safe_components(path: &Path) -> Result<Vec<&std::ffi::OsStr>> {
    ensure!(path.is_absolute(), "absolute anchored path required");
    let mut out = Vec::new();
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(s) => out.push(s),
            _ => anyhow::bail!("noncanonical component"),
        }
    }
    ensure!(
        !out.is_empty() && out.len() <= 64,
        "finite non-root path required"
    );
    let rebuilt = out.iter().fold(PathBuf::from("/"), |mut p, c| {
        p.push(c);
        p
    });
    ensure!(
        rebuilt.as_os_str() == path.as_os_str(),
        "noncanonical path spelling"
    );
    Ok(out)
}
fn root_directory() -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?)
}
fn openat(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File> {
    let name = CString::new(name.as_encoded_bytes())?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | if directory {
            libc::O_DIRECTORY
        } else {
            libc::O_NONBLOCK
        };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    ensure!(
        fd >= 0,
        "anchored no-follow open failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn anchored_file(path: &Path) -> Result<File> {
    let parts = safe_components(path)?;
    let mut parent = root_directory()?;
    for part in &parts[..parts.len() - 1] {
        parent = openat(&parent, part, true)?;
    }
    openat(&parent, parts[parts.len() - 1], false)
}
fn metadata_bytes(binding: &Bound, immutable: bool) -> Result<Vec<u8>> {
    ensure!(lower_sha(&binding.sha256), "metadata digest syntax");
    let mut file = anchored_file(&binding.path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= 32 << 20,
        "unsafe Root metadata"
    );
    if immutable {
        ensure!(
            before.mode() & 0o7777 == 0o444,
            "normal immutable member required"
        );
    }
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take((32 << 20) + 1)
        .read_to_end(&mut raw)?;
    let reopened = anchored_file(&binding.path)?;
    ensure!(
        raw.len() as u64 == before.len()
            && stable(&before) == stable(&file.metadata()?)
            && stable(&before) == stable(&reopened.metadata()?)
            && digest(&raw) == binding.sha256,
        "bound metadata changed"
    );
    Ok(raw)
}
#[derive(Serialize)]
#[serde(transparent)]
struct SelectedLedgerEntries(BTreeMap<String, Value>);
impl<'de> Deserialize<'de> for SelectedLedgerEntries {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = SelectedLedgerEntries;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("exact physical ledger entry map")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let p = pins().map_err(serde::de::Error::custom)?;
                let rows = p["retained_file_candidates_from_prior_native_ledgers"]
                    .as_array()
                    .ok_or_else(|| serde::de::Error::custom("compiled members absent"))?;
                let mut selected = BTreeSet::new();
                for row in rows {
                    let epoch = row["epoch"]
                        .as_u64()
                        .ok_or_else(|| serde::de::Error::custom("compiled epoch"))?;
                    let root = format!(
                        "/home/sol/.jetstreamer-private/epoch{epoch}-standard-lane-20261109-v1"
                    );
                    let path = row["path"]
                        .as_str()
                        .ok_or_else(|| serde::de::Error::custom("compiled path"))?;
                    let relative = Path::new(path)
                        .strip_prefix(root)
                        .map_err(serde::de::Error::custom)?
                        .to_str()
                        .ok_or_else(|| serde::de::Error::custom("relative UTF8"))?
                        .to_string();
                    selected.insert(relative);
                }
                let mut out = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if selected.contains(&key) {
                        let value = map.next_value::<Value>()?;
                        if out.insert(key, value).is_some() {
                            return Err(serde::de::Error::custom(
                                "duplicate selected ledger entry",
                            ));
                        }
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(SelectedLedgerEntries(out))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}
#[derive(Deserialize, Serialize)]
struct SelectedLedgerPhysical {
    entries: SelectedLedgerEntries,
}
// Physical ledgers166-168 are genuinely51-54MiB. Authenticate them in a bounded
// streaming pass, then parse only their three header fields while ignoring the large ledger.
// Other Root metadata retains the original32MiB bound.
fn ledger_header(binding: &Bound) -> Result<Value> {
    #[derive(Deserialize, Serialize)]
    struct Header {
        schema: String,
        epoch: u64,
        lane_root: String,
        #[serde(default)]
        physical: Option<SelectedLedgerPhysical>,
    }
    ensure!(lower_sha(&binding.sha256), "ledger digest syntax");
    let mut file = anchored_file(&binding.path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= 128 << 20,
        "unsafe bounded Root physical ledger"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    ensure!(
        format!("{:x}", hash.finalize()) == binding.sha256,
        "physical ledger digest differs"
    );
    file.seek(SeekFrom::Start(0))?;
    let header: Header = serde_json::from_reader(BufReader::with_capacity(65536, &mut file))?;
    let reopened = anchored_file(&binding.path)?;
    ensure!(
        stable(&before) == stable(&file.metadata()?)
            && stable(&before) == stable(&reopened.metadata()?),
        "physical ledger changed while authenticated"
    );
    Ok(serde_json::to_value(header)?)
}
fn bound(binding: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&metadata_bytes(binding, false)?)?)
}
fn sealed(member: &Bound, seal: &Bound, name: &str) -> Result<Value> {
    ensure!(
        member.path.file_name().is_some_and(|s| s == name)
            && seal.path
                == member
                    .path
                    .parent()
                    .context("member parent")?
                    .join("deployment-seal-receipt.json"),
        "normal member/seal namespace"
    );
    let bytes = metadata_bytes(member, true)?;
    let proof = bound(seal)?;
    ensure!(
        proof["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && proof["sealer_sha256"] == SEALER_SHA
            && proof["destination"]
                == member
                    .path
                    .parent()
                    .context("member parent")?
                    .to_str()
                    .context("UTF-8 deployment")?,
        "normal deployment proof required"
    );
    let members = proof["members"].as_array().context("normal seal members")?;
    let selected: Vec<_> = members.iter().filter(|v| v["name"] == name).collect();
    ensure!(
        selected.len() == 1
            && selected[0]["sha256"] == member.sha256
            && selected[0]["mode"] == "0444"
            && proof["replay_launch_authorized"] == false
            && proof["remote_mutations"] == false,
        "seal member or scope differs"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn original_amounts(v: &Value, epoch: u64) -> Result<()> {
    let root = if epoch == 166 {
        n(v, "new_candidate_own_DATA_bytes")?
    } else {
        n(v, "candidate_own_DATA_bytes")?
    };
    let meta = if epoch == 166 {
        n(v, "new_candidate_guard_metadata_bytes")?
    } else if epoch <= 168 {
        n(v, "candidate_guard_metadata_bytes")?
    } else {
        n(v, "candidate_guard_metadata_DATA_bytes")?
    };
    ensure!(
        root == CAP
            && meta == 8 << 30
            && n(v, "previous_complete_DATA_bytes")?
                .checked_add(root)
                .and_then(|n| n.checked_add(meta))
                == Some(n(v, "complete_DATA_bytes")?),
        "original root/metadata booking arithmetic differs"
    );
    ensure!(
        v["owner"] == "/root" && v["primary_thread"] == PRIMARY,
        "original booking owner differs"
    );
    Ok(())
}
fn authority(seed: &WitnessSet) -> Result<Value> {
    ensure!(
        seed.complete_authority == expected(HEAD, HEAD_SHA)
            && seed.accepted_original154_ancestry == expected(ANCESTRY, ANCESTRY_SHA)
            && seed.lineage_manifest == expected(MANIFEST, MANIFEST_SHA),
        "exact qualified original-slot ancestry required"
    );
    let head = bound(&seed.complete_authority)?;
    let check = bound(&seed.accepted_original154_ancestry)?;
    let manifest = bound(&seed.lineage_manifest)?;
    ensure!(
        head["schema"]
            == "horizon-Root-once-only-original154-unused-future-DATA-selection-authority-v1"
            && head["complete_DATA_bytes"] == DATA
            && head["complete_projected_memory_bytes"] == MEMORY
            && head["additional_once_only_ended_unused_future_DATA_bytes"] == 352_187_318_272u64
            && head["previous_complete_DATA_bytes"] == 6_582_025_928_498u64
            && head["effective_retained_original154_DATA_bytes"] == 32u64 << 30
            && head["old154_memory64_ending_reapplied_bytes"] == 0
            && head["physical_retirement_bytes"] == 0
            && head["holding_credit_bytes"] == 0
            && head["genuine_native_check"]
                == serde_json::to_value(&seed.accepted_original154_ancestry)?,
        "selected154 once-only authority differs"
    );
    ensure!(
        check["schema"] == "horizon-original154-future-DATA-check-v1"
            && check["original_invocation_id"] == "edc1d1915dcb4c2785d2cf24cdaa10c2"
            && check["ancestry"]["authenticated_nodes"] == 70
            && check["ancestry"]["authenticated_edges"] == 69
            && check["ancestry"]["positive_delta_sum_bytes"] == 2_084_401_315_840u64
            && check["ancestry"]["negative_delta_sum_bytes"] == -2_301_968_252_928i64
            && check["ancestry"]["manifest"] == serde_json::to_value(&seed.lineage_manifest)?
            && check["current_authority"] == head["previous_complete_authority"]
            && manifest["current_authority"] == head["previous_complete_authority"],
        "genuine native70-node69-equation acceptance differs"
    );
    let nodes = manifest["nodes"].as_array().context("70 nodes")?;
    let edges = manifest["edges"].as_array().context("69 edges")?;
    ensure!(
        nodes.len() == 70 && edges.len() == 69,
        "ancestry census differs"
    );
    let p = pins()?;
    ensure!(
        seed.schema == "horizon-original-slot-DATA-witness-set-v1"
            && seed.owner == "/root"
            && seed.primary_thread == PRIMARY
            && seed.raw_minimum_free_bytes == FLOOR
            && seed.complete_data_bytes == DATA
            && seed.full_original_root_cap_bytes == CAP
            && seed.margin_per_credited_slot_bytes == MARGIN
            && seed.maximum_fulfillment_bytes == MAXIMUM
            && seed.slots.len() == 7,
        "exact unchanged first-generation resource envelope required"
    );
    let mut all = BTreeSet::new();
    let mut represented = 0usize;
    for (index, slot) in seed.slots.iter().enumerate() {
        let epoch = 166 + index as u64;
        let pin = &p["roles"][index];
        let date = if epoch < 171 { "20261109" } else { "20261110" };
        ensure!(
            slot.epoch == epoch
                && slot.original_booking
                    == serde_json::from_value::<Bound>(pin["original_booking"].clone())?
                && slot.lane_root
                    == Path::new(&format!(
                        "/home/sol/.jetstreamer-private/epoch{epoch}-standard-lane-{date}-v1"
                    )),
            "original slot path or booking crossed"
        );
        let original = bound(&slot.original_booking)?;
        original_amounts(&original, epoch)?;
        let binding = serde_json::to_value(&slot.original_booking)?;
        if epoch <= 167 {
            let rows = manifest["base_booking_proof"]["positive_increments"]
                .as_array()
                .context("canonical increments")?;
            let selected: Vec<_> = rows.iter().filter(|r| r["source"] == binding).collect();
            ensure!(
                selected.len() == 1 && selected[0]["bytes"] == CAP + (8 << 30),
                "original canonical166/167 increment absent"
            );
        } else {
            let selected: Vec<_> = nodes
                .iter()
                .enumerate()
                .filter(|(_, r)| r["binding"] == binding)
                .collect();
            ensure!(selected.len() == 1, "original positive lineage slot absent");
            let at = selected[0].0;
            ensure!(
                edges[at]["signed_delta_bytes"] == CAP + (8 << 30)
                    && edges[at]["child_index"] == at,
                "original positive slot edge differs"
            );
        }
        if epoch <= 170 {
            represented += 1;
            let ledger = slot
                .physical_ledger
                .as_ref()
                .context("exact retained original ledger")?;
            let measured = &p["prior_native_ledgers"][index];
            ensure!(
                *ledger == serde_json::from_value::<Bound>(measured["ledger"].clone())?,
                "original physical ledger crossed"
            );
            let recorded = ledger_header(ledger)?;
            ensure!(
                recorded["schema"] == "horizon-standard-replacement-local-physical-ledger-v1"
                    && recorded["epoch"] == epoch
                    && recorded["lane_root"] == slot.lane_root.to_str().context("slot root")?,
                "physical ledger slot differs"
            );
            let expected_members: Vec<PathBuf> =
                p["retained_file_candidates_from_prior_native_ledgers"]
                    .as_array()
                    .context("pinned candidate list")?
                    .iter()
                    .filter(|x| x["epoch"] == epoch)
                    .map(|x| {
                        x["path"]
                            .as_str()
                            .map(PathBuf::from)
                            .context("candidate path")
                    })
                    .collect::<Result<_>>()?;
            let actual: BTreeSet<_> = slot.members.iter().cloned().collect();
            let expected: BTreeSet<_> = expected_members.into_iter().collect();
            ensure!(
                slot.members.len() == 3 && actual.len() == 3 && actual == expected,
                "exact three retained witnesses required"
            );
            for path in &slot.members {
                ensure!(all.insert(path.clone()), "repeated witness path");
                let relative = path
                    .strip_prefix(&slot.lane_root)?
                    .to_str()
                    .context("relative retained path")?;
                let entry = &recorded["physical"]["entries"][relative];
                ensure!(
                    n(entry, "physical_bytes")? >= 1 << 30
                        && entry["identity"][0].as_u64().is_some()
                        && entry["identity"][5] == 1,
                    "original ledger lacks singly linked allocated member"
                );
            }
        } else {
            ensure!(
                slot.physical_ledger.is_none() && slot.members.is_empty(),
                "first generation grants no171/172 witness credit"
            );
        }
    }
    ensure!(
        all.len() == 15 && represented == 5,
        "exact fifteen-file five-role witness set required"
    );
    Ok(
        json!({"complete_authority":seed.complete_authority,"accepted_native70node_ancestry":seed.accepted_original154_ancestry,"full_original_root_caps_preserved_bytes":7*CAP,"guard_metadata_preserved_bytes":7*(8u64<<30),"other_DATA_promises_preserved_bytes":DATA-7*(CAP+(8<<30)),"raw_minimum_free_bytes":FLOOR,"complete_DATA_bytes":DATA,"DATA_ending_bytes":0,"memory_credit_bytes":0}),
    )
}
fn ancestor(path: PathBuf, m: &fs::Metadata, owned_root: &Path) -> Ancestor {
    Ancestor {
        owned_change_times: path.starts_with(owned_root).then_some([
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        ]),
        path,
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
    }
}
fn fact(path: &Path, epoch: u64, root: &Path, held: &mut Vec<File>) -> Result<Fact> {
    ensure!(
        path.starts_with(root) && path != root,
        "witness must be inside its exact original slot"
    );
    let parts = safe_components(path)?;
    let mut parent = root_directory()?;
    held.push(parent.try_clone()?);
    let mut current = PathBuf::from("/");
    let mut ancestors = vec![ancestor(current.clone(), &parent.metadata()?, root)];
    for component in &parts[..parts.len() - 1] {
        parent = openat(&parent, component, true)?;
        held.push(parent.try_clone()?);
        current.push(component);
        let meta = parent.metadata()?;
        ensure!(meta.is_dir(), "non-directory ancestor");
        ancestors.push(ancestor(current.clone(), &meta, root));
    }
    let file = openat(&parent, parts[parts.len() - 1], false)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1,
        "only single-linked regular witnesses qualify"
    );
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    let empty = CString::new("")?;
    ensure!(
        unsafe {
            libc::statx(
                file.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_BASIC_STATS | libc::STATX_BTIME,
                &mut sx,
            )
        } == 0
            && sx.stx_mask & libc::STATX_BTIME != 0,
        "native birthtime proof unavailable"
    );
    ensure!(
        sx.stx_ino == m.ino()
            && u64::from(sx.stx_nlink) == m.nlink()
            && sx.stx_size == m.len()
            && sx.stx_blocks == m.blocks()
            && sx.stx_uid == m.uid()
            && sx.stx_gid == m.gid()
            && u32::from(sx.stx_mode) == m.mode(),
        "stat/statx identity or allocation differs"
    );
    let observed = Fact {
        epoch,
        path: path.into(),
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        nlink: m.nlink(),
        logical_bytes: m.len(),
        allocated_blocks512: m.blocks(),
        mtime: m.mtime(),
        mtime_nsec: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_nsec: m.ctime_nsec(),
        birth_seconds: sx.stx_btime.tv_sec,
        birth_nanoseconds: sx.stx_btime.tv_nsec,
        ancestors,
    };
    ensure!(
        stable(&m) == stable(&file.metadata()?),
        "witness changed while descriptor captured"
    );
    held.push(file);
    Ok(observed)
}
fn free_at(filesystem: &Path) -> Result<FreePoint> {
    let parts = safe_components(filesystem)?;
    let mut dir = root_directory()?;
    for p in parts {
        dir = openat(&dir, p, true)?;
    }
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(dir.as_raw_fd(), &mut sf) } == 0
            && unsafe { libc::fstatvfs(dir.as_raw_fd(), &mut sv) } == 0,
        "native filesystem counters unavailable"
    );
    checked_free(sv.f_bavail, sv.f_frsize, dir.metadata()?.dev(), sf.f_type)
}
fn checked_free(blocks: u64, size: u64, device: u64, magic: i64) -> Result<FreePoint> {
    ensure!(
        magic == 0xEF53 && size > 0,
        "only ext filesystem without shared extents is qualified"
    );
    Ok(FreePoint {
        available_bytes: blocks
            .checked_mul(size)
            .context("filesystem free overflow")?,
        device,
        filesystem_magic: magic,
    })
}
fn capture_all_held(slots: &[Slot], deadline: Instant, held: &mut Vec<File>) -> Result<Vec<Fact>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for s in slots {
        for p in &s.members {
            ensure!(
                Instant::now() < deadline,
                "finite witness observation deadline expired"
            );
            let f = fact(p, s.epoch, &s.lane_root, held)?;
            ensure!(
                seen.insert((f.dev, f.ino)),
                "duplicate physical inode across roles"
            );
            out.push(f);
        }
    }
    Ok(out)
}
#[cfg(test)]
fn capture_all(slots: &[Slot], deadline: Instant) -> Result<Vec<Fact>> {
    capture_all_held(slots, deadline, &mut Vec::new())
}
fn sum_fulfilled(
    facts: &[Fact],
    device: u64,
    cap: u64,
    margin: u64,
) -> Result<(BTreeMap<u64, u64>, u64)> {
    let mut allocations = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for f in facts {
        ensure!(
            f.dev == device && f.nlink == 1 && seen.insert((f.dev, f.ino)),
            "foreign filesystem, alias or hardlink"
        );
        let bytes = f
            .allocated_blocks512
            .checked_mul(512)
            .context("allocated block overflow")?;
        let v = allocations.entry(f.epoch).or_insert(0u64);
        *v = v
            .checked_add(bytes)
            .context("per-slot allocation overflow")?;
        ensure!(
            *v <= cap,
            "witness allocation exceeds unchanged original slot cap"
        );
    }
    let mut total = 0u64;
    for bytes in allocations.values_mut() {
        *bytes = bytes.saturating_sub(margin);
        total = total
            .checked_add(*bytes)
            .context("fulfillment sum overflow")?;
    }
    Ok((allocations, total))
}
fn allocation_using<F, G>(
    seed: &WitnessSet,
    filesystem: &Path,
    midpoint_action: F,
    mut free: G,
) -> Result<Allocation>
where
    F: FnOnce() -> Result<()>,
    G: FnMut(&Path) -> Result<FreePoint>,
{
    let deadline = Instant::now() + Duration::from_secs(5);
    let before = free(filesystem)?;
    // Keep anchored file AND directory descriptors alive across the common midpoint.
    // A closed descriptor permitted immediate inode/birthtime reuse within one clock tick.
    let mut held = Vec::new();
    let first = capture_all_held(&seed.slots, deadline, &mut held)?;
    midpoint_action()?;
    let midpoint = free(filesystem)?;
    let second = capture_all_held(&seed.slots, deadline, &mut held)?;
    let after = free(filesystem)?;
    for descriptor in &held {
        let m = descriptor.metadata()?;
        ensure!(
            m.is_dir() || (m.is_file() && m.nlink() == 1),
            "retained witness was unlinked during common midpoint"
        );
    }
    ensure!(
        first == second
            && before.device == midpoint.device
            && before.device == after.device
            && Instant::now() < deadline,
        "witness/path/ancestor changed across common filesystem midpoint"
    );
    let (per_slot, total) = sum_fulfilled(&first, midpoint.device, CAP, MARGIN)?;
    ensure!(
        total <= seed.maximum_fulfillment_bytes,
        "fulfillment exceeds exact qualified source bound"
    );
    let free = before
        .available_bytes
        .min(midpoint.available_bytes)
        .min(after.available_bytes);
    Ok(Allocation {
        first,
        second,
        filesystem_before: before,
        filesystem_midpoint: midpoint,
        filesystem_after: after,
        conservative_available_bytes: free,
        per_slot,
        conservative_fulfilled_bytes: total,
    })
}
fn allocation_with<F>(
    seed: &WitnessSet,
    filesystem: &Path,
    midpoint_action: F,
) -> Result<Allocation>
where
    F: FnOnce() -> Result<()>,
{
    allocation_using(seed, filesystem, midpoint_action, free_at)
}
fn source_custody(facts: &[Fact]) -> Result<()> {
    let p = pins()?;
    let candidates = p["retained_file_candidates_from_prior_native_ledgers"]
        .as_array()
        .context("pinned original members")?;
    ensure!(facts.len() == 15, "exact original fifteen members required");
    for f in facts {
        let selected: Vec<_> = candidates
            .iter()
            .filter(|v| v["epoch"] == f.epoch && v["path"] == f.path.to_str().unwrap_or(""))
            .collect();
        ensure!(selected.len() == 1, "foreign retained witness");
        let source = selected[0];
        let id = &source["old_identity"];
        ensure!(
            id[0] == f.dev
                && id[1] == f.ino
                && id[2] == f.uid
                && id[3] == f.gid
                && id[4] == f.mode
                && id[5] == f.nlink
                && id[6] == f.logical_bytes
                && source["old_physical_bytes"]
                    == f.allocated_blocks512
                        .checked_mul(512)
                        .context("source blocks overflow")?,
            "original retained inode/custody/length/allocation differs from accepted ledger"
        );
    }
    Ok(())
}
/// Called only by the separately qualified native capture executable. No guard/launch authority.
pub(super) fn qualify(seed_binding: &Bound, seal: &Bound, filesystem: &Path) -> Result<Value> {
    ensure!(
        filesystem == Path::new("/home/sol"),
        "exact qualified filesystem required"
    );
    let seed: WitnessSet = serde_json::from_value(sealed(seed_binding, seal, "witness-set.json")?)?;
    let provenance = authority(&seed)?;
    let allocation = allocation_with(&seed, filesystem, || Ok(()))?;
    source_custody(&allocation.first)?;
    ensure!(
        allocation.conservative_fulfilled_bytes > 0,
        "native qualification provides no allocation fulfillment"
    );
    Ok(
        json!({"schema":"horizon-original-slot-DATA-native-witness-qualification-v1","owner":"/root","primary_thread":PRIMARY,"witness_set":seed_binding,"witness_set_deployment_seal":seal,"source_provenance":provenance,"allocation":allocation,"complete_DATA_bytes":DATA,"raw_minimum_free_bytes":FLOOR,"replay_admission_authorized":false,"guard_handoff_authorized":false,"resource_credit_bytes":0,"DATA_ending_bytes":0,"remote_mutations":false,"producer_mutations":false}),
    )
}
fn scope(s: &Scope<'_>) -> Result<()> {
    let e = s
        .unit
        .strip_prefix("horizon-qualify-")
        .and_then(|v| v.strip_suffix("-replacement-local2-20261110-v1.service"))
        .and_then(|v| v.parse::<u64>().ok())
        .context("exact admitted local2 unit required")?;
    let date = if e < 171 { "20261109" } else { "20261110" };
    ensure!(
        (166..=172).contains(&e)
            && s.unit == format!("horizon-qualify-{e}-replacement-local2-20261110-v1.service")
            && s.worker_root
                == Path::new(&format!(
                    "/home/sol/.jetstreamer-private/epoch{e}-standard-lane-{date}-v1"
                ))
            && s.invocation_id.len() == 32
            && s.invocation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && s.filesystem == Path::new("/home/sol")
            && s.raw_floor == FLOOR
            && s.root_cap == Some(CAP)
            && s.max_vmas == 3_500_000
            && !s.special_profile
            && lower_sha(s.guard_sha256),
        "fulfillment cannot alter original local2 guard scope or limits"
    );
    Ok(())
}
fn point(free: u64, fulfilled: u64, maximum: u64) -> Result<(u64, u64)> {
    ensure!(
        maximum > 0 && maximum <= MAXIMUM && fulfilled > 0 && fulfilled <= maximum,
        "unqualified fulfillment bound"
    );
    let available = free
        .checked_add(fulfilled)
        .context("free plus fulfilled overflow")?;
    let effective = FLOOR
        .checked_sub(fulfilled)
        .context("fulfilled exceeds retained raw floor")?;
    Ok((available, effective))
}
/// Every error must become a guard trip before the caller returns from a live invocation.
pub(super) fn observe(binding: &Value, s: &Scope<'_>) -> Result<Observation> {
    scope(s)?;
    let b: Binding = serde_json::from_value(binding.clone())?;
    let contract: Contract =
        serde_json::from_value(sealed(&b.contract, &b.deployment_seal, "contract.json")?)?;
    ensure!(
        contract.schema == "horizon-original-slot-DATA-guard-contract-v1"
            && contract.maximum_fulfilled_bytes > 0
            && contract.maximum_fulfilled_bytes <= MAXIMUM,
        "exact DATA guard contract required"
    );
    let seed: WitnessSet = serde_json::from_value(sealed(
        &contract.witness_set,
        &contract.witness_set_deployment_seal,
        "witness-set.json",
    )?)?;
    let provenance = authority(&seed)?;
    let original = bound(&contract.qualified_native_witness)?;
    ensure!(
        original["schema"] == "horizon-original-slot-DATA-native-witness-qualification-v1"
            && original["owner"] == "/root"
            && original["primary_thread"] == PRIMARY
            && original["witness_set"] == serde_json::to_value(&contract.witness_set)?
            && original["witness_set_deployment_seal"]
                == serde_json::to_value(&contract.witness_set_deployment_seal)?
            && original["source_provenance"] == provenance
            && original["complete_DATA_bytes"] == DATA
            && original["raw_minimum_free_bytes"] == FLOOR
            && original["DATA_ending_bytes"] == 0
            && original["resource_credit_bytes"] == 0,
        "native witness qualification binding differs"
    );
    ensure!(
        original["native_identity"]["executable_sha256"] == s.guard_sha256
            && original["native_identity"]["executable"]
                == fs::read_link("/proc/self/exe")?
                    .to_str()
                    .context("own executable path")?
            && original["native_identity"]["pid"]
                .as_u64()
                .is_some_and(|p| p > 1)
            && original["native_identity"]["systemd_invocation_id"]
                .as_str()
                .is_some_and(|v| v.len() == 32
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && original["recorded_unix_seconds"].as_u64().is_some_and(|t| t
                <= SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())),
        "actual native qualification image/invocation/clock differs"
    );
    let native: Allocation = serde_json::from_value(original["allocation"].clone())?;
    let (native_slots, native_total) = sum_fulfilled(
        &native.first,
        native.filesystem_midpoint.device,
        CAP,
        MARGIN,
    )?;
    ensure!(
        native.first == native.second
            && native_slots == native.per_slot
            && native_total == native.conservative_fulfilled_bytes
            && native_total >= contract.maximum_fulfilled_bytes
            && native_total <= MAXIMUM,
        "native fulfillment equation differs"
    );
    let current = allocation_with(&seed, s.filesystem, || Ok(()))?;
    source_custody(&current.first)?;
    ensure!(
        current.first == native.first
            && current.conservative_fulfilled_bytes >= contract.maximum_fulfilled_bytes,
        "qualified witness inode/owner/mode/birth/size/blocks/path changed since actual native qualification"
    );
    let fulfilled = current
        .conservative_fulfilled_bytes
        .min(contract.maximum_fulfilled_bytes);
    let conservative_free = current
        .conservative_available_bytes
        .min(s.initial_available_bytes);
    let (available, effective) = point(
        conservative_free,
        fulfilled,
        contract.maximum_fulfilled_bytes,
    )?;
    Ok(Observation {
        conservative_available_bytes: conservative_free,
        fulfilled_bytes: fulfilled,
        available_plus_fulfilled_bytes: available,
        effective_required_free_bytes: effective,
        evidence: json!({"schema":"horizon-original-slot-DATA-guard-observation-v1","contract":b,"qualified_native_witness":contract.qualified_native_witness,"source_provenance":provenance,"allocation":current,"initial_raw_available_bytes":s.initial_available_bytes,"conservative_raw_available_bytes":conservative_free,"fulfilled_bytes":fulfilled,"raw_minimum_free_bytes":FLOOR,"effective_required_free_bytes":effective,"available_plus_fulfilled_bytes":available,"DATA_ending_bytes":0,"resource_credit_bytes":0,"remote_mutations":false,"producer_mutations":false}),
    })
}

/// Explicit bounded qualification subcommand. Writes one new private receipt and never signals.
pub(super) fn run_qualification(args: &[String]) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 13
            && args[1] == "--qualify-data-witness"
            && args[3] == "--seed-sha256"
            && args[5] == "--seal"
            && args[7] == "--seal-sha256"
            && args[9] == "--output"
            && args[11] == "--self-sha256"
            && lower_sha(&args[12]),
        "exact native witness qualification argv required"
    );
    let image = fs::read_link("/proc/self/exe")?;
    let mut executable = File::open("/proc/self/exe")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let n = executable.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    ensure!(
        format!("{:x}", hasher.finalize()) == args[12],
        "native qualification self image differs"
    );
    let iid = std::env::var("INVOCATION_ID")
        .context("native qualification requires real systemd invocation")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "native qualification IID differs"
    );
    let seed = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let seal = Bound {
        path: args[6].clone().into(),
        sha256: args[8].clone(),
    };
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut receipt = qualify(&seed, &seal, Path::new("/home/sol"))?;
    receipt["recorded_unix_seconds"] =
        json!(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    receipt["started_unix_seconds"] = json!(started);
    receipt["native_identity"] = json!({"executable":image,"executable_sha256":args[12],"pid":std::process::id(),"systemd_invocation_id":iid});
    let output = Path::new(&args[10]);
    let parent = output.parent().context("private output parent")?;
    let components = safe_components(parent)?;
    let mut dir = root_directory()?;
    for p in components {
        dir = openat(&dir, p, true)?;
    }
    let dm = dir.metadata()?;
    ensure!(
        dm.is_dir() && dm.uid() == 0 && dm.mode() & 0o7777 == 0o700,
        "Root-private qualification output leaf required"
    );
    let filename = CString::new(
        output
            .file_name()
            .context("output name")?
            .as_encoded_bytes(),
    )?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            filename.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(fd >= 0, "qualification output must be new regular file");
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut bytes = serde_json::to_vec_pretty(&receipt)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    dir.sync_all()?;
    println!(
        "{}",
        json!({"path":output,"sha256":digest(&bytes),"qualified_fulfilled_bytes":receipt["allocation"]["conservative_fulfilled_bytes"],"replay_admission_authorized":false,"guard_handoff_authorized":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Seek, SeekFrom, Write},
        os::unix::fs::{PermissionsExt, symlink},
    };
    fn fixture() -> (tempfile::TempDir, WitnessSet, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("lane");
        fs::create_dir(&root).unwrap();
        let file = root.join("witness");
        fs::write(&file, vec![7; 8192]).unwrap();
        let mut seed: WitnessSet = serde_json::from_str(include_str!("witness-set.json")).unwrap();
        seed.slots = vec![Slot {
            epoch: 166,
            lane_root: root,
            original_booking: expected("/unused", "a".repeat(64).as_str()),
            physical_ledger: None,
            members: vec![file.clone()],
        }];
        (dir, seed, file)
    }
    fn test_free(path: &Path) -> Result<FreePoint> {
        Ok(FreePoint {
            available_bytes: FLOOR,
            device: fs::metadata(path)?.dev(),
            filesystem_magic: 0xEF53,
        })
    }
    fn allocated(seed: &WitnessSet, action: impl FnOnce() -> Result<()>) -> Result<Allocation> {
        allocation_using(seed, &seed.slots[0].lane_root, action, test_free)
    }
    #[test]
    fn real_file_and_ancestors_are_stable_across_common_midpoint() {
        let (_dir, seed, file) = fixture();
        let a = allocated(&seed, || Ok(())).unwrap();
        assert_eq!(a.first, a.second);
        assert_eq!(a.first[0].path, file);
        assert!(!a.first[0].ancestors.is_empty());
        let (_, bytes) = sum_fulfilled(&a.first, a.filesystem_midpoint.device, CAP, 0).unwrap();
        assert_eq!(bytes, fs::metadata(file).unwrap().blocks() * 512);
    }
    #[test]
    fn deletion_during_midpoint_rejects_instead_of_retaining_credit() {
        let (_dir, seed, file) = fixture();
        assert!(
            allocated(&seed, || {
                fs::remove_file(file)?;
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn same_path_replacement_during_midpoint_rejects_inode_or_birth_change() {
        let (_dir, seed, file) = fixture();
        assert!(
            allocated(&seed, || {
                fs::remove_file(&file)?;
                fs::write(&file, vec![7; 8192])?;
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn file_write_during_midpoint_rejects_even_when_length_is_unchanged() {
        let (_dir, seed, file) = fixture();
        assert!(
            allocated(&seed, || {
                std::thread::sleep(Duration::from_millis(20));
                let mut f = OpenOptions::new().write(true).open(file)?;
                f.seek(SeekFrom::Start(0))?;
                f.write_all(&[8])?;
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn mode_change_during_midpoint_rejects_custody_change() {
        let (_dir, seed, file) = fixture();
        assert!(
            allocated(&seed, || {
                fs::set_permissions(file, fs::Permissions::from_mode(0o444))?;
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn ancestor_replacement_cannot_preserve_a_member_by_spelling() {
        let (dir, seed, file) = fixture();
        let old = dir.path().join("moved");
        let root = seed.slots[0].lane_root.clone();
        assert!(
            allocated(&seed, || {
                fs::rename(&root, &old)?;
                fs::create_dir(&root)?;
                fs::write(file, vec![7; 8192])?;
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn ancestor_symlink_and_member_symlink_are_never_followed() {
        let (dir, seed, file) = fixture();
        let target = dir.path().join("target");
        fs::write(&target, vec![1; 8192]).unwrap();
        fs::remove_file(&file).unwrap();
        symlink(&target, &file).unwrap();
        assert!(allocated(&seed, || Ok(())).is_err());
        fs::remove_file(&file).unwrap();
        fs::write(&file, vec![1; 8192]).unwrap();
        let moved = dir.path().join("moved");
        fs::rename(&seed.slots[0].lane_root, &moved).unwrap();
        symlink(&moved, &seed.slots[0].lane_root).unwrap();
        assert!(allocated(&seed, || Ok(())).is_err());
    }
    #[test]
    fn multiply_linked_file_and_repeated_inode_are_rejected() {
        let (dir, mut seed, file) = fixture();
        let link = dir.path().join("outside-link");
        fs::hard_link(&file, &link).unwrap();
        assert!(allocated(&seed, || Ok(())).is_err());
        fs::remove_file(link).unwrap();
        seed.slots[0].members.push(file);
        assert!(allocated(&seed, || Ok(())).is_err());
    }
    #[test]
    fn duplicate_inode_across_claims_cannot_be_counted_twice() {
        let (_dir, mut seed, file) = fixture();
        seed.slots.push(Slot {
            epoch: 167,
            lane_root: seed.slots[0].lane_root.clone(),
            original_booking: expected("/unused", "b".repeat(64).as_str()),
            physical_ledger: None,
            members: vec![file],
        });
        assert!(capture_all(&seed.slots, Instant::now() + Duration::from_secs(5)).is_err());
    }
    #[test]
    fn sparse_apparent_length_never_becomes_allocation_credit() {
        let (_dir, seed, file) = fixture();
        let f = OpenOptions::new().write(true).open(&file).unwrap();
        f.set_len(0).unwrap();
        f.set_len(64u64 << 20).unwrap();
        drop(f);
        let facts = capture_all(&seed.slots, Instant::now() + Duration::from_secs(5)).unwrap();
        let (_, bytes) = sum_fulfilled(&facts, fs::metadata(&file).unwrap().dev(), CAP, 0).unwrap();
        assert_eq!(bytes, fs::metadata(file).unwrap().blocks() * 512);
        assert!(bytes < 64u64 << 20);
    }
    #[test]
    fn per_role_cap_margin_and_device_are_independently_enforced() {
        let (_dir, seed, file) = fixture();
        let facts = capture_all(&seed.slots, Instant::now() + Duration::from_secs(5)).unwrap();
        let dev = fs::metadata(file).unwrap().dev();
        let (_, zero) = sum_fulfilled(&facts, dev, CAP, MARGIN).unwrap();
        assert_eq!(zero, 0);
        assert!(sum_fulfilled(&facts, dev + 1, CAP, 0).is_err());
        assert!(sum_fulfilled(&facts, dev, 1, 0).is_err());
    }
    #[test]
    fn byte_arithmetic_rejects_overflow_and_unqualified_bounds() {
        let (_dir, seed, _file) = fixture();
        let mut facts = capture_all(&seed.slots, Instant::now() + Duration::from_secs(5)).unwrap();
        let dev = facts[0].dev;
        facts[0].allocated_blocks512 = u64::MAX;
        assert!(sum_fulfilled(&facts, dev, CAP, 0).is_err());
        assert!(point(u64::MAX, 1, 1).is_err());
        assert!(point(1, 1, MAXIMUM + 1).is_err());
        assert!(point(1, 0, 1).is_err());
    }
    #[test]
    fn native_filesystem_failure_or_unsupported_sharing_grants_no_witness() {
        let (_dir, seed, _file) = fixture();
        let calls = std::cell::Cell::new(0);
        assert!(
            allocation_using(
                &seed,
                &seed.slots[0].lane_root,
                || Ok(()),
                |p| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        anyhow::bail!("midpoint statfs failed");
                    }
                    test_free(p)
                }
            )
            .is_err()
        );
        assert!(checked_free(1, 4096, 1, 0x9123683e).is_err());
        assert!(checked_free(u64::MAX, 4096, 1, 0xEF53).is_err());
        assert!(checked_free(1, 0, 1, 0xEF53).is_err());
    }
    #[test]
    fn canonical_path_spelling_cannot_borrow_normalized_aliases() {
        for path in [
            "/tmp/../etc/passwd",
            "/tmp/./file",
            "//tmp/file",
            "/tmp//file",
            "relative",
        ] {
            assert!(safe_components(Path::new(path)).is_err(), "{path}");
        }
    }
    #[test]
    fn genuine_large_ledger_is_streamed_and_changed_digest_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("ledger.json");
        let mut f = File::create(&path).unwrap();
        f.write_all(br#"{"schema":"test","epoch":166,"lane_root":"/test","ignored":""#)
            .unwrap();
        let block = [b'x'; 65536];
        for _ in 0..513 {
            f.write_all(&block).unwrap();
        }
        f.write_all(b"\"}").unwrap();
        f.sync_all().unwrap();
        drop(f);
        let raw = fs::read(&path).unwrap();
        let mut b = Bound {
            path,
            sha256: digest(&raw),
        };
        drop(raw);
        assert_eq!(ledger_header(&b).unwrap()["epoch"], 166);
        b.sha256 = "a".repeat(64);
        assert!(ledger_header(&b).is_err());
    }
    #[test]
    fn first_generation_cannot_increase_cap_or_end_another_claim() {
        let correct = json!({"owner":"/root","primary_thread":PRIMARY,"previous_complete_DATA_bytes":1,"complete_DATA_bytes":1+CAP+(8u64<<30),"candidate_own_DATA_bytes":CAP,"candidate_guard_metadata_DATA_bytes":8u64<<30});
        original_amounts(&correct, 170).unwrap();
        let mut changed = correct.clone();
        changed["candidate_own_DATA_bytes"] = json!(CAP + 1);
        assert!(original_amounts(&changed, 170).is_err());
        changed = correct;
        changed["complete_DATA_bytes"] = json!(1 + CAP);
        assert!(original_amounts(&changed, 170).is_err());
    }
    #[test]
    fn qualified_point_retains_raw_floor_and_every_unfulfilled_byte() {
        let (sum, effective) = point(FLOOR - 17, 17, 17).unwrap();
        assert_eq!(sum, FLOOR);
        assert_eq!(effective, FLOOR - 17);
    }
}
