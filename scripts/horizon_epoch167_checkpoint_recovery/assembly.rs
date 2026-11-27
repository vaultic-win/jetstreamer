//! Bind the original epoch 167 replay's post-seam SlotHashes entry to the
//! independently restored Bank. The two executables remain individually named.
use crate::{PrefixView, invalid};
use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{ArchiveProvenance, ArchiveReader, ChainMismatchPolicy, SlotVisitor},
    block_metas::BlockNotification,
    entries::EntryRecord,
    transactions::Transaction,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{Read, Seek},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const FIRST: u64 = 72_144_000;
const SEAM: u64 = 72_509_256;
const PHYSICAL_END: u64 = 72_512_768;
const BOUNDED_END: u64 = 72_515_091;
const END: u64 = 72_576_000;
const TAIL_END: u64 = 72_582_855;
const PREFIX_SHA: &str = "430561d1a97572e727e62e7c8d8991cac5adcfcd33f00e203525e1a7735ebea9";
const OLD_WORKER: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const NEW_WORKER: &str = "07b09d779706a789c668681ad9685e9ad62290a6930667c5f74a099a516d28cc";
const BOUNDED: &str = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/checkpoint-inputs-20261127-v1/bounded-72509256-72515090-v2/output/epoch-167-checkpoint-bounded.jet";
const TAIL: &str = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/checkpoint-inputs-20261127-v1/tail-72509256-72582854-v1/output/epoch-167-checkpoint-tail-private.jet";
const STATE: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const NATIVE_BANK: &str = "CamY5qGDUVSFAVdrMePpUp8Nia6saonBgED7LZTuyeXc";
const SEAM_BLOCK: &str = "1BK4wPkM1ZGbKrVAFdCzyXYWaB8bhPK7vBcfZqN8U1G";
const LAST_BLOCK: &str = "76NscCJt2diYHF8a7vxwiMHMK9A2Tr3wDaMY42WjzVFs";
const SNAP_SHA: &str = "e35c2d247099b5f2edace0d09485fd254f852069681fa09cf39168dbe42c5769";
const SOURCE: &str = super::epoch167::SOURCE;
fn require(check: bool, msg: &'static str) -> Result<()> {
    if check {
        Ok(())
    } else {
        Err(invalid(msg).into())
    }
}
fn open(path: &Path) -> Result<File> {
    require(path.canonicalize()? == path, "indirect source")?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    require(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o022 == 0,
        "unbound source custody",
    )?;
    Ok(f)
}
fn doc(path: &Path, sha: &str, uid: u32) -> Result<Value> {
    let file = open(path)?;
    let m = file.metadata()?;
    require(
        m.uid() == uid && m.len() < 2 << 20,
        "unexpected evidence permissions or extent",
    )?;
    let mut raw = Vec::new();
    file.take(2 << 20).read_to_end(&mut raw)?;
    require(
        format!("{:x}", Sha256::digest(&raw)) == sha,
        "evidence SHA-256 changed",
    )?;
    Ok(serde_json::from_slice(&raw)?)
}
#[derive(Default)]
struct Seen {
    rows: Vec<Value>,
    invalid: bool,
}
impl Seen {
    fn update(&mut self, slot: u64, key: &[u8], owner: &[u8], version: u64, data: &[u8]) {
        let key_text = bs58::encode(key).into_string();
        if key_text != "SysvarS1otHashes111111111111111111111111111" {
            return;
        }
        let count = data
            .get(..8)
            .and_then(|v| v.try_into().ok())
            .map(u64::from_le_bytes);
        let Some(n) = count else {
            self.invalid = true;
            return;
        };
        if n > 512
            || data.len() < 8 + n as usize * 40
            || bs58::encode(owner).into_string() != "Sysvar1111111111111111111111111111111111111"
        {
            self.invalid = true;
            return;
        }
        for item in data[8..8 + n as usize * 40].chunks_exact(40) {
            if u64::from_le_bytes(item[..8].try_into().unwrap()) == SEAM {
                self.rows.push(json!({"observed_slot":slot,"parent_slot":SEAM,"bank_hash":bs58::encode(&item[8..]).into_string(),"raw_write_version":version,"data_sha256":format!("{:x}",Sha256::digest(data))}));
            }
        }
    }
}
impl SlotVisitor for Seen {
    fn on_pre_account_update(&mut self, s: u64, u: &AccountUpdateView<'_>) {
        self.update(
            s,
            u.pubkey.as_ref(),
            u.owner.as_ref(),
            u.write_version,
            u.data,
        );
    }
    fn on_post_account_update(&mut self, s: u64, u: &AccountUpdateView<'_>) {
        self.on_pre_account_update(s, u);
    }
    fn on_transaction(&mut self, s: u64, _: u32, t: &Transaction) {
        for (m, d) in t.iter_account_updates() {
            self.update(s, m.pubkey.as_ref(), m.owner.as_ref(), m.write_version, d)
        }
    }
    fn on_block(&mut self, _: &BlockNotification, _: &[EntryRecord]) {}
}
fn witness<R: Read + Seek>(reader: &mut ArchiveReader<R>, expected_worker: &str) -> Result<Value> {
    let Some(ArchiveProvenance::V2(p)) = reader.provenance()? else {
        return Err(invalid("missing original V2 executable").into());
    };
    require(
        crate::selected_prefix::hex(&p.worker_executable_sha256) == expected_worker
            && reader.header().epoch == 167,
        "unexpected producer",
    )?;
    reader.verify_chain = true;
    reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    let mut seen = Seen::default();
    require(
        reader.read_slots(SEAM + 1, 1, &mut seen)? == 1 && !seen.invalid,
        "bad post-seam state update",
    )?;
    require(
        seen.rows.len() == 1,
        "missing unique first child SlotHashes entry",
    )?;
    Ok(
        json!({"runtime_revision":p.base.runtime_revision,"runtime_profile":p.base.runtime_profile,"runtime_toolchain":p.base.runtime_toolchain,
    "worker_sha256":expected_worker,"generation":p.base.generation_profile,"slot_hashes":seen.rows[0]}),
    )
}
pub(super) fn inspect() -> Result<()> {
    let t = doc(
        &Path::new(STATE).join("epoch167-checkpoint-bounded-20261127-v2/BOUNDED_V2_TERMINAL.json"),
        "402175a4e76a0ccdf0be6aa78f99276f96f6b60bf53f412dea0f730819107fca",
        0,
    )?;
    let m = &t["checkpoint"];
    require(
        m["archive"] == BOUNDED
            && m["bootstrap_checkpoint"]["bank_hash"] == NATIVE_BANK
            && m["bootstrap_checkpoint"]["last_blockhash"] == SEAM_BLOCK,
        "wrong bounded checkpoint",
    )?;
    let o = doc(
        &Path::new(STATE)
            .join("epoch167-bounded-post-retry-overlap-20261127-v1/OVERLAP_VERIFIED.json"),
        "c56a5e517864309e75e238bf3d1b6aa21094cc6f8e4a32223a42bdd46a585fe5",
        0,
    )?;
    require(
        o["report"]["first_slot"] == SEAM + 1 && o["report"]["last_slot"] == PHYSICAL_END - 1,
        "wrong overlap",
    )?;
    let left = open(Path::new(SOURCE))?;
    super::epoch167::original_identity(&left)?;
    let mut p = ArchiveReader::open(PrefixView::open(&left, 167, FIRST, PHYSICAL_END)?)?;
    let right = open(Path::new(BOUNDED))?;
    let id = right.metadata()?;
    require(
        id.ino() == 112853150 && id.dev() == 64512 && id.len() == 1644434452,
        "wrong bounded source",
    )?;
    let mut b = ArchiveReader::open(&right)?;
    let a = witness(&mut p, OLD_WORKER)?;
    let z = witness(&mut b, NEW_WORKER)?;
    require(
        a["slot_hashes"]["bank_hash"] == NATIVE_BANK
            && z["slot_hashes"]["bank_hash"] == NATIVE_BANK
            && a["slot_hashes"]["data_sha256"] == z["slot_hashes"]["data_sha256"],
        "prefix and restart do not witness the same frozen bank",
    )?;
    println!(
        "{}",
        json!({"schema":"horizon-167-assembly-bank-witness-v1","prefix":a,"bounded":z,"crop_fixture":fixture_crop()?,"bootstrap":m["bootstrap_checkpoint"],"source_sha256":PREFIX_SHA,"released_restart_custody":restart_custody()?,"finalized_boundary":finalized_boundary()?,"restart_snapshot_sha256":SNAP_SHA,"start":FIRST,"prefix_end_exclusive":SEAM+1,"tail_end_exclusive":TAIL_END,"epoch_end_exclusive":END,"bounded_end_exclusive":BOUNDED_END,"epoch_terminal_blockhash":LAST_BLOCK,"tail_path":TAIL,"overlap":o["report"],"archive_storage_bytes":0,"publication_authorized":false})
    );
    Ok(())
}

use super::{
    assembly_sources::{SourceLayout, checkpoint_at, digest, segment, source_layout},
    selected_prefix as sel,
};
use jetstreamer_horizon::archive::{
    ArchiveProvenanceV3, ArchiveProvenanceV4, ArchiveWriterConfig, BootstrapStateKind,
    RuntimeHandoffProvenance, RuntimeSegmentSource, StateCommitment, StateCommitmentKind,
    encode_archive_provenance, merge_runtime_segments,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufReader, Write},
    os::unix::fs::PermissionsExt,
    process::Command,
};
const TAIL_UNIT: &str = "horizon-qualify-167-checkpoint-tail-20261127-v1.service";
const TAIL_ID: &str = "fd94e15f60df427c962ed1458f8e7efd";
const SELECT_UNIT: &str = "horizon-167-retained-prefix-selection-20261127-v1.service";
const SELECT_ID: &str = "376e0977c2114f62b082ace7640169b2";
const QUAL_UNIT: &str = "horizon-167-private-source-qualification-20261127-v1.service";
const OUTPUT_UNIT: &str = "horizon-167-private-v3-assembly-20261127-v1.service";
const OUTPUT: &str = "/home/sol/.jetstreamer-private/epoch167-private-assembly-20261127-v1/output";
const ARCHIVE_CAP: u64 = 128 << 30;
const EVIDENCE_CAP: u64 = 64 << 20;
const QMEM: u64 = 4 << 30;
const CAPTURE: &str = "epoch167-checkpoint-tail-20261127-v1/FIRST_PROTECTED_PROGRESS.json";
const CAPTURE_SHA: &str = "753ade79e4e3873c18eb0cec83d17f879d8e0e08fa45b97c740e8f6c3a6a5fe6";
fn strf<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or_else(|| format!("missing {k}").into())
}
fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().ok_or_else(|| format!("missing {k}").into())
}
fn load_bound(v: &Value, uid: u32) -> Result<Value> {
    doc(Path::new(strf(v, "path")?), strf(v, "sha256")?, uid)
}
fn file_id(f: &File) -> Result<Vec<i128>> {
    let m = f.metadata()?;
    Ok(vec![
        m.dev().into(),
        m.ino().into(),
        m.len().into(),
        m.mtime().into(),
        m.mtime_nsec().into(),
        m.ctime().into(),
        m.ctime_nsec().into(),
    ])
}
fn finalized_boundary() -> Result<Value> {
    let path = Path::new(STATE).join(
        "epoch167-source-index-rebook-20261122-v3/POST_EPOCH_FINALIZED_SOURCE_RANGES_20261127.json",
    );
    let sha = "2d535c174f71bd580bf3b9385e5f4362a139cf7d2ae2a5635d3f48699c60c0b1";
    let d = doc(&path, sha, 0)?;
    let last = &d["anchors"]["72575999"]["block"];
    let next = &d["anchors"]["72576000"]["block"];
    require(
        last["blockhash"] == LAST_BLOCK
            && next["parentSlot"] == END - 1
            && next["previousBlockhash"] == LAST_BLOCK
            && d["anchors"]["72509256"]["block"]["blockhash"] == SEAM_BLOCK,
        "finalized epoch or seam identity changed",
    )?;
    Ok(json!({"path":path,"sha256":sha,"last_epoch_block":last,"first_next_epoch_block":next}))
}
const FIRST_BOOT: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
fn success(unit: &str, iid: &str, boot: &str) -> Result<Value> {
    require(
        iid.len() == 32 && iid.bytes().all(|c| c.is_ascii_hexdigit()),
        "bad invocation reference",
    )?;
    let res = Command::new("/usr/bin/journalctl")
        .args([
            "-q",
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={iid}"),
            "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
        ])
        .output()?;
    require(
        res.status.success(),
        "failed to read authoritative process exit",
    )?;
    let events: Vec<Value> = String::from_utf8(res.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    require(
        events.len() == 1 && boot.len() == 32 && events[0]["_BOOT_ID"] == boot,
        "missing exact successful PID1 exit",
    )?;
    Ok(events[0].clone())
}
fn deployed_tool(plan: &Value) -> Result<String> {
    let r = &plan["tool_seal"];
    let seal = load_bound(r, 0)?;
    let dest = Path::new(strf(&seal, "destination")?);
    require(
        dest.join("deployment-seal-receipt.json") == Path::new(strf(r, "path")?)
            && dest == Path::new(STATE).join("epoch167-assembly-20261127-v1/tools"),
        "wrong epoch 167 tool deployment",
    )?;
    let rows: Vec<_> = seal["members"]
        .as_array()
        .ok_or("missing deployment members")?
        .iter()
        .filter(|m| m["name"] == "horizon-167-assembly")
        .collect();
    require(
        rows.len() == 1 && fs::metadata("/proc/self/exe")?.len() == num(rows[0], "bytes")?,
        "wrong assembly executable extent",
    )?;
    let mut f = File::open("/proc/self/exe")?;
    let mut h = Sha256::new();
    io::copy(&mut f, &mut h)?;
    let digest = format!("{:x}", h.finalize());
    require(
        rows[0]["sha256"] == digest,
        "executing a different assembly binary",
    )?;
    Ok(digest)
}
fn stage(plan: &Value, unit: &str, limit: u64) -> Result<String> {
    let iid = std::env::var("INVOCATION_ID")?;
    require(
        iid.len() == 32
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{unit}"),
        "wrong stage execution unit",
    )?;
    let group = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    let cpu = fs::read_to_string(group.join("cpu.max"))?;
    let (quota, period) = cpu.trim().split_once(' ').ok_or("malformed cpu cgroup")?;
    require(
        quota.parse::<u64>()? == period.parse::<u64>()?
            && fs::read_to_string(group.join("memory.max"))?
                .trim()
                .parse::<u64>()?
                == limit
            && fs::read_to_string(group.join("memory.swap.max"))?.trim() == "0",
        "execution resource binding differs",
    )?;
    let fit = load_bound(&plan["admission"], 0)?;
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let budget = if unit == QUAL_UNIT {
        16 << 20
    } else {
        ARCHIVE_CAP + EVIDENCE_CAP
    };
    require(
        fit["epoch"] == 167
            && fit["unit"] == unit
            && fit["fits"] == true
            && fit["maximum_additional_home_bytes"] == budget
            && fit["cpu_quota_us"] == 1_000_000
            && fit["memory_max_bytes"] == limit
            && fit["memory_swap_max_bytes"] == 0
            && fit["available_memory_bytes"]
                .as_u64()
                .zip(fit["required_memory_bytes"].as_u64())
                .is_some_and(|(a, r)| r >= limit && a >= r)
            && num(&fit, "minimum_home_free_bytes")?
                .checked_add(budget)
                .is_some_and(|r| num(&fit, "available_home_bytes").is_ok_and(|a| a >= r))
            && plan["minimum_home_free_bytes"] == fit["minimum_home_free_bytes"]
            && num(plan, "minimum_home_free_bytes")? > 0
            && (at..=at + 600).contains(&num(&fit, "expires_unix_seconds")?),
        "invalid or expired complete stage price",
    )?;
    Ok(iid)
}
fn views(dir: &Path, full_end: u64, cut: u64) -> Result<(File, File, SourceLayout, SourceLayout)> {
    let prefix = open(Path::new(SOURCE))?;
    super::epoch167::original_identity(&prefix)?;
    let suffix = open(dir)?;
    let left = source_layout(
        167,
        ArchiveReader::open(PrefixView::open(&prefix, 167, FIRST, PHYSICAL_END)?)?,
        FIRST,
        SEAM + 1,
        false,
    )?;
    let right = source_layout(
        167,
        ArchiveReader::open(BufReader::new(&suffix))?,
        SEAM + 1,
        cut,
        true,
    )?;
    require(
        left.header.slot_count == END - FIRST
            && right.header.slot_count == full_end - SEAM - 1
            && sel::hex(&left.provenance.worker_executable_sha256) == OLD_WORKER
            && sel::hex(&right.provenance.worker_executable_sha256) == NEW_WORKER
            && left.provenance.base.genesis_hash == right.provenance.base.genesis_hash
            && left.provenance.base.runtime_profile == "solana-v1.5.6"
            && left.provenance.base.runtime_profile == right.provenance.base.runtime_profile
            && left.provenance.base.runtime_revision == right.provenance.base.runtime_revision
            && left.provenance.base.runtime_toolchain == right.provenance.base.runtime_toolchain
            && left.provenance.base.runtime_admission == right.provenance.base.runtime_admission
            && left.provenance.base.transaction_metadata
                == right.provenance.base.transaction_metadata,
        "mixed-runtime sources differ from their recorded metadata policies",
    )?;
    Ok((prefix, suffix, left, right))
}
fn clip(f: &mut File, layout: &SourceLayout, end: u64) -> Result<sel::Layout> {
    let cut = sel::cut(
        f,
        &layout.header,
        ArchiveProvenance::V2(layout.provenance.clone()),
        &layout.buckets,
        end,
    )?;
    sel::boundaries(f, &layout.header, &layout.buckets, &cut, end)?;
    Ok(cut)
}
pub(super) fn fixture_crop() -> Result<Value> {
    let (mut p, mut b, left, right) = views(Path::new(BOUNDED), BOUNDED_END, PHYSICAL_END)?;
    let a = clip(&mut p, &left, SEAM + 1)?;
    let z = clip(&mut b, &right, PHYSICAL_END)?;
    let bounded = doc(
        &Path::new(STATE).join("epoch167-checkpoint-bounded-20261127-v2/BOUNDED_V2_TERMINAL.json"),
        "402175a4e76a0ccdf0be6aa78f99276f96f6b60bf53f412dea0f730819107fca",
        0,
    )?;
    let native = &bounded["checkpoint"]["bootstrap_checkpoint"];
    let v = destination(
        &left,
        &right,
        &json!({"raw_start":52_685_674_982u64,"raw_end_exclusive":52_685_674_983u64}),
        native,
        52_892_210_899..52_892_210_900,
    )?;
    let encoded = encode_archive_provenance(&ArchiveProvenance::V3(v))?;

    Ok(
        json!({"prefix_bytes":a.len(),"bounded_selected_bytes":z.len(),"prefix_slots":SEAM+1-FIRST,
      "bounded_selected_slots":PHYSICAL_END-SEAM-1,"prefix_last_bucket_slots":(SEAM+1-FIRST)%128,"future_tail_last_bucket_slots":(END-SEAM-1)%128,
      "fixture_last_bucket_slots":(PHYSICAL_END-SEAM-1)%128,"source_boundary_records_verified":true,"fixture_only_v3_roundtrip_bytes":encoded.len(),"fixture_only_write_count_per_source":1,"distinct_workers_v4_rejected":true}),
    )
}
fn restart_custody() -> Result<Value> {
    let root = Path::new(STATE).join("epoch167-checkpoint-tail-20261127-v1");
    let first = doc(&Path::new(STATE).join(CAPTURE), CAPTURE_SHA, 0)?;
    let release = load_bound(&first["release"], 0)?;
    let intent = load_bound(&release["intent"], 0)?;
    require(
        release["actor"]["producer_invocation_id"] == TAIL_ID
            && first["start_intent"] == release["intent"]
            && intent["payload"]["path"]
                == root.join("launch-inputs/PAYLOAD.json").to_str().unwrap()
            && intent["payload"]["sha256"]
                == "69be25ebdfeca52e0ae89e5e70d6e19c217054a74c3f4514ae413a522697866f",
        "missing original released snapshot binding",
    )?;
    let payload = load_bound(&intent["payload"], 0)?;
    let preflight = load_bound(&payload["spec"], 0)?;
    let target = "/run/horizon-167-post-epoch-inputs/snapshot-72509256-5QgiqJPdQHGW8XPQofearvgZVmesY99YLHr1n7gVCkBD.tar.zst";
    let snapshots: Vec<_> = payload["files"]
        .as_array()
        .ok_or("missing projected inputs")?
        .iter()
        .filter(|m| m["target"] == target)
        .collect();
    require(
        snapshots.len() == 1
            && snapshots[0]["source"] == preflight["bootstrap"]
            && preflight["bootstrap"]["sha256"] == SNAP_SHA
            && preflight["checkpoints"] == json!([SEAM, 72515090, 72575704, TAIL_END - 1])
            && payload["argv"].as_array().is_some_and(|argv| {
                argv.iter()
                    .any(|v| v.as_str() == Some(&format!("--snapshot-archive={target}")))
            }),
        "bound bootstrap custody changed",
    )?;
    Ok(
        json!({"native_preflight":payload["spec"],"released_payload":intent["payload"],"bootstrap":preflight["bootstrap"]}),
    )
}
fn bound_manifest(t: &Value) -> Result<Value> {
    require(
        strf(t, "path")? == format!("{TAIL}.segment.json"),
        "wrong long-tail manifest path",
    )?;
    let m = load_bound(t, 1001)?;
    restart_custody()?;
    require(
        m["schema_version"] == 1
            && m["epoch"] == 167
            && m["output_slot_start"] == SEAM + 1
            && m["output_slot_count"] == TAIL_END - SEAM - 1
            && m["bootstrap"]["bank_hash"] == NATIVE_BANK
            && m["bootstrap"]["last_blockhash"] == SEAM_BLOCK
            && m["bootstrap"]["write_count"] == 0
            && (m["bootstrap_archive_sha256"].is_null()
                || m["bootstrap_archive_sha256"] == SNAP_SHA)
            && m["worker_executable_sha256"] == NEW_WORKER
            && m["terminal"]["slot"] == TAIL_END - 1
            && m["terminal"]["accounts_hash"] == "8d82jZbtd8gnQH7ygEoFDmbG1VkccCpPh3asYGdhd2Au"
            && m["terminal"]["last_blockhash"] == "ERDqMozqgXqUwpRrte3xjoxGF5RyeJpLp2y57ULxkTnD"
            && m["terminal"]["slot_complete"] == true
            && m["emitted_raw_write_versions"]["start"] == 52_892_210_899u64
            && m["emitted_raw_write_versions"]["end"] == m["terminal"]["next_write_version"],
        "wrong native long-tail manifest",
    )?;
    Ok(m)
}
fn native_tail(manifest: &Value) -> Result<Value> {
    let exit = success(TAIL_UNIT, TAIL_ID, FIRST_BOOT)?;
    let cap = doc(&Path::new(STATE).join(CAPTURE), CAPTURE_SHA, 0)?;
    require(
        cap["actor"]["producer_invocation_id"] == TAIL_ID,
        "foreign long-range invocation",
    )?;
    let log_path = Path::new(strf(&cap["append_log"], "path")?);
    let file = open(log_path)?;
    let initial = file_id(&file)?;
    let m = file.metadata()?;
    require(
        m.len() < 512 << 20
            && m.dev() == num(&cap["append_log"], "device")?
            && m.ino() == num(&cap["append_log"], "inode")?,
        "wrong archive producer log",
    )?;
    let mut raw = Vec::new();
    file.take(512 << 20).read_to_end(&mut raw)?;
    let end = cap["read_range"][1].as_u64().ok_or("missing initial end")? as usize;
    require(
        cap["read_range"][0] == 0
            && raw
                .get(..end)
                .is_some_and(|s| cap["log_read_sha256"] == format!("{:x}", Sha256::digest(s))),
        "original producer log prefix differs",
    )?;
    require(
        file_id(&open(log_path)?)? == initial,
        "closed native producer log changed",
    )?;
    let lines = std::str::from_utf8(&raw)?;
    let bounded = doc(
        &Path::new(STATE).join("epoch167-checkpoint-bounded-20261127-v2/BOUNDED_V2_TERMINAL.json"),
        "402175a4e76a0ccdf0be6aa78f99276f96f6b60bf53f412dea0f730819107fca",
        0,
    )?;
    require(
        manifest["bootstrap"] == bounded["checkpoint"]["bootstrap_checkpoint"],
        "loaded restart checkpoint differs from bounded run",
    )?;
    let mut checks = Vec::new();
    for (slot, accounts, block) in [
        (
            72_515_090,
            "DWgHoJPPD1XaWGLpasfR4RVnAU1CBoKUrjCgtoCfEDPK",
            "EDVRWQ7d8A4BBekGavJWhWaTR3PAMur2pT51KPhKhJYm",
        ),
        (
            72_575_704,
            "Grdro3ninCQfmShQL6ypGv2y1gUzhPPB7xbj9M4UHJnx",
            "HuU7Pmc6ybh23EU33HZtJKaqLjW6JHztgQ8w8iPhPggS",
        ),
        (
            TAIL_END - 1,
            "8d82jZbtd8gnQH7ygEoFDmbG1VkccCpPh3asYGdhd2Au",
            "ERDqMozqgXqUwpRrte3xjoxGF5RyeJpLp2y57ULxkTnD",
        ),
    ] {
        let mut positions = lines
            .lines()
            .filter(|s| s.contains(&format!("] historical checkpoint slot={slot} ")));
        let line = positions.next().ok_or("missing native checkpoint")?;
        let fields: BTreeMap<_, _> = line
            .split_whitespace()
            .filter_map(|s| s.split_once('='))
            .collect();
        require(
            positions.next().is_none()
                && fields.get("accounts_hash") == Some(&accounts)
                && fields.get("last_blockhash") == Some(&block)
                && fields.get("complete") == Some(&"true")
                && lines
                    .lines()
                    .filter(|s| {
                        s.ends_with(&format!("] verified legacy accounts hash at slot {slot}"))
                    })
                    .count()
                    == 1,
            "missing or conflicting accounts checkpoint",
        )?;
        let checkpoint = if slot == 72_515_090 {
            Some(&bounded["checkpoint"]["terminal_checkpoint"])
        } else if slot + 1 == TAIL_END {
            Some(&manifest["terminal"])
        } else {
            None
        };
        if let Some(expected) = checkpoint {
            for (k, v) in expected.as_object().ok_or("missing checkpoint tuple")? {
                let alias = match k.as_str() {
                    "write_count" => "writes",
                    "transaction_count" => "transactions",
                    "slot_complete" => "complete",
                    other => other,
                };
                let want = v
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| v.to_string());
                require(
                    fields.get(alias) == Some(&want.as_str()),
                    "checkpoint tuple differs from native independent receipt",
                )?;
            }
        }
        checks.push(json!(line));
    }
    Ok(json!({"pid1":exit,"checkpoints":checks,"log_sha256":format!("{:x}",Sha256::digest(raw))}))
}
fn prefix_evidence(plan: &Value) -> Result<Value> {
    success(SELECT_UNIT, SELECT_ID, FIRST_BOOT)?;
    let r = &plan["prefix_result"];
    require(
        strf(r, "path")?
            == format!("{STATE}/epoch167-retained-prefix-selection-20261127-v1/RESULT.stdout"),
        "not the retained selector's native output",
    )?;
    let s = load_bound(r, 0)?;
    require(
        s["schema"] == "horizon-epoch167-private-selected-prefix-evidence-v1"
            && s["source_archive_sha256"] == PREFIX_SHA
            && s["first_slot"] == FIRST
            && s["last_slot"] == SEAM
            && s["terminal_blockhash"] == SEAM_BLOCK
            && s["raw_end_exclusive"] == 52_685_674_983u64
            && s["physical_archive_bytes_written"] == 0
            && s["independently_decoded"] == true
            && num(&s, "raw_start")? < num(&s, "raw_end_exclusive")?
            && digest(strf(&s, "selected_semantic_sha256")?)? != [0; 32],
        "invalid independent original prefix selection",
    )?;
    Ok(s)
}
fn destination(
    l: &SourceLayout,
    r: &SourceLayout,
    selected: &Value,
    boot: &Value,
    suffix: std::ops::Range<u64>,
) -> Result<ArchiveProvenanceV3> {
    let native = checkpoint_at(boot, SEAM)?;
    let mut outgoing = native;
    // The old producer independently emitted this exact frozen Bank and last blockhash
    // in its child. The authenticated snapshot supplies the Bank's consensus tuple;
    // bind the original selected prefix's own raw cursor separately.
    outgoing.next_write_version = num(selected, "raw_end_exclusive")?;
    let raw = num(selected, "raw_start")?..outgoing.next_write_version;
    require(
        native.next_write_version == suffix.start
            && outgoing.next_write_version == 52_685_674_983
            && native.bank_hash.to_string() == NATIVE_BANK
            && native.last_blockhash.to_string() == SEAM_BLOCK
            && boot["write_count"] == 0
            && r.provenance.base.bootstrap_slot == SEAM
            && r.provenance.base.bootstrap_state_kind == BootstrapStateKind::SnapshotArchive
            && r.provenance.base.bootstrap_state_hash == native.accounts_hash
            && l.provenance.base.bootstrap_state_kind == BootstrapStateKind::SnapshotArchive,
        "unbound restart cursor or state",
    )?;
    let normalized = raw.end.checked_sub(raw.start).ok_or("invalid raw prefix")?;
    let base = &l.provenance.base;
    let v = ArchiveProvenanceV3 {
        assembly_profile: "jetstreamer-node/epoch167-private-mixed-worker-checkpoint-v1".into(),
        genesis_hash: base.genesis_hash,
        bootstrap_state_kind: base.bootstrap_state_kind,
        bootstrap_state: StateCommitment {
            slot: base.bootstrap_slot,
            kind: StateCommitmentKind::LegacyAccountsHash,
            hash: base.bootstrap_state_hash,
        },
        requested_slot_start: FIRST,
        requested_slot_count: END - FIRST,
        transaction_metadata: base.transaction_metadata.clone(),
        runtime_segments: vec![
            segment(l, SEAM + 1 - FIRST, raw, 0),
            segment(r, END - SEAM - 1, suffix, normalized),
        ],
        handoffs: vec![RuntimeHandoffProvenance {
            boundary_slot: SEAM + 1,
            predecessor: outgoing,
            successor: native,
            successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
            successor_bootstrap_archive_sha256: digest(SNAP_SHA)?,
            successor_bootstrap_write_count: 0,
        }],
    };
    v.validate()?;
    require(
        ArchiveProvenanceV4 { base: v.clone() }.validate().is_err(),
        "unexpected V4 acceptance for distinct source executables",
    )?;
    Ok(v)
}
fn base_plan(path: &str, sha: &str) -> Result<Value> {
    let p = doc(Path::new(path), sha, 0)?;
    require(
        p["schema"] == "horizon-167-checkpoint-assembly-plan-v1"
            && p["epoch"] == 167
            && p["output_directory"] == OUTPUT
            && p["publication_authorized"] == false,
        "wrong assembly scope",
    )?;
    Ok(p)
}
pub(super) fn qualify(path: &str, sha: &str) -> Result<()> {
    let plan = base_plan(path, sha)?;
    let iid = stage(&plan, QUAL_UNIT, QMEM)?;
    let tool_sha = deployed_tool(&plan)?;
    let prefix = prefix_evidence(&plan)?;
    let manifest = bound_manifest(&plan["tail_manifest"])?;
    let native = native_tail(&manifest)?;
    let (mut p, mut f, left, right) = views(Path::new(TAIL), TAIL_END, END)?;
    let id = file_id(&f)?;
    let lp = clip(&mut p, &left, SEAM + 1)?;
    let r = clip(&mut f, &right, END)?;
    require(
        lp.len() == num(&prefix, "selected_archive_bytes")?,
        "original prefix virtual length differs",
    )?;
    let mut original = ArchiveReader::open(PrefixView::open(&p, 167, FIRST, PHYSICAL_END)?)?;
    let old_bank = witness(&mut original, OLD_WORKER)?;
    let mut successor = ArchiveReader::open(&f)?;
    let new_bank = witness(&mut successor, NEW_WORKER)?;
    require(
        old_bank["slot_hashes"]["bank_hash"] == NATIVE_BANK
            && new_bank["slot_hashes"]["bank_hash"] == NATIVE_BANK
            && old_bank["slot_hashes"]["data_sha256"] == new_bank["slot_hashes"]["data_sha256"]
            && old_bank["slot_hashes"]["raw_write_version"] == prefix["raw_end_exclusive"]
            && new_bank["slot_hashes"]["raw_write_version"]
                == manifest["emitted_raw_write_versions"]["start"],
        "native incoming and original outgoing Bank witness differ",
    )?;
    let (full, selected, bytes) = sel::hashes(&mut f, &r)?;
    require(
        sel::hex(&full) == strf(&manifest, "archive_sha256")? && bytes == f.metadata()?.len(),
        "closed tail checksum differs",
    )?;
    let all = sel::semantic_read(BufReader::new(&f), TAIL_END)?;
    require(
        all.last_block == Some(TAIL_END - 1)
            && bs58::encode(all.last_hash).into_string() == manifest["terminal"]["last_blockhash"]
            && all.first_raw == manifest["emitted_raw_write_versions"]["start"].as_u64()
            && all.next_raw == manifest["emitted_raw_write_versions"]["end"].as_u64(),
        "full tail does not match native endpoint",
    )?;
    let part = sel::semantic_read(sel::Selected::new(&f, &r), END)?;
    require(
        part.last_block == Some(END - 1)
            && bs58::encode(part.last_hash).into_string() == LAST_BLOCK
            && part.first_raw == all.first_raw
            && part.next_raw <= all.next_raw,
        "clipped tail differs from finalized epoch boundary",
    )?;
    let start = part.first_raw.ok_or("empty tail cursor")?;
    let end = part.next_raw.ok_or("missing tail cursor")?;
    let v = destination(&left, &right, &prefix, &manifest["bootstrap"], start..end)?;
    let provenance = encode_archive_provenance(&ArchiveProvenance::V3(v))?;
    super::epoch167::original_identity(&p)?;
    require(
        file_id(&f)? == id && file_id(&open(Path::new(TAIL))?)? == id,
        "long source changed during qualification",
    )?;
    println!(
        "{}",
        json!({"schema":"horizon-167-qualified-mixed-worker-sources-v1","unit":QUAL_UNIT,"invocation":iid,"boot":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().replace('-',""),"finalized_boundary":finalized_boundary()?,"tool_sha256":tool_sha,"tool_seal":plan["tool_seal"],"prefix_result":plan["prefix_result"],"tail_manifest":plan["tail_manifest"],"tail_identity":id,"native":native,
        "old_bank":old_bank,"new_bank":new_bank,"seam_consensus_fields_origin":"independently loaded generation-pinned FR2 snapshot of the Bank witnessed by the old and new SlotHashes entries","seam_predecessor_raw_cursor_origin":"independently decoded original selected prefix",
        "full_tail_sha256":sel::hex(&full),"full_tail_semantic":sel::hex(&all.semantic),"full_tail_bytes":bytes,"selected_tail_bytes":r.len(),"selected_tail_sha256":sel::hex(&selected),"selected_tail_semantic":sel::hex(&part.semantic),
        "selected_raw_start":start,"selected_raw_end_exclusive":end,"v3_sha256":format!("{:x}",Sha256::digest(provenance)),"epoch_last_blockhash":LAST_BLOCK,"source_epoch_last":END-1,"post_epoch_slots_excluded":TAIL_END-END,"publication_authorized":false})
    );
    Ok(())
}

pub(super) fn assemble(path: &str, sha: &str) -> Result<()> {
    use crate::assembly_sources::private_assembly::{GuardedOutput, home_floor};
    use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};
    let plan = base_plan(path, sha)?;
    let iid = stage(&plan, OUTPUT_UNIT, 8 << 30)?;
    let tool_sha = deployed_tool(&plan)?;
    let q = load_bound(&plan["qualification"], 0)?;
    require(
        q["schema"] == "horizon-167-qualified-mixed-worker-sources-v1"
            && q["unit"] == QUAL_UNIT
            && q["tool_sha256"] == tool_sha
            && q["tool_seal"] == plan["tool_seal"]
            && q["prefix_result"] == plan["prefix_result"]
            && q["tail_manifest"] == plan["tail_manifest"]
            && q["publication_authorized"] == false,
        "wrong source qualification",
    )?;
    success(QUAL_UNIT, strf(&q, "invocation")?, strf(&q, "boot")?)?;
    let prefix = prefix_evidence(&plan)?;
    let manifest = bound_manifest(&plan["tail_manifest"])?;
    require(
        native_tail(&manifest)? == q["native"],
        "qualified native evidence changed",
    )?;
    // Open the private directory with O_DIRECTORY, so a plain file cannot replace it.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(OUTPUT)?;
    let m = directory.metadata()?;
    require(
        Path::new(OUTPUT).canonicalize()? == Path::new(OUTPUT)
            && m.uid() == 0
            && m.mode() & 0o777 == 0o700
            && m.dev() == fs::metadata("/home/sol")?.dev()
            && unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_NB | libc::LOCK_EX) } == 0
            && fs::read_dir(OUTPUT)?.next().is_none(),
        "output directory not private, empty, HOME-backed and exclusive",
    )?;
    let floor = num(&plan, "minimum_home_free_bytes")?;
    home_floor(&directory, floor, ARCHIVE_CAP + EVIDENCE_CAP)?;
    let (mut left_file, mut right_file, left, right) = views(Path::new(TAIL), TAIL_END, END)?;
    require(
        json!(file_id(&right_file)?) == q["tail_identity"],
        "qualified long source identity changed",
    )?;
    let lp = clip(&mut left_file, &left, SEAM + 1)?;
    let rt = clip(&mut right_file, &right, END)?;
    require(
        lp.len() == num(&prefix, "selected_archive_bytes")?
            && rt.len() == num(&q, "selected_tail_bytes")?,
        "selected extents changed",
    )?;
    let v = destination(
        &left,
        &right,
        &prefix,
        &manifest["bootstrap"],
        num(&q, "selected_raw_start")?..num(&q, "selected_raw_end_exclusive")?,
    )?;
    let encoded = encode_archive_provenance(&ArchiveProvenance::V3(v.clone()))?;
    require(
        format!("{:x}", Sha256::digest(encoded)) == strf(&q, "v3_sha256")?,
        "qualified provenance changed",
    )?;
    let readers = vec![
        RuntimeSegmentSource::new(
            BufReader::new(sel::Selected::new(&left_file, &lp)),
            digest(strf(&prefix, "selected_archive_sha256")?)?,
            SEAM_BLOCK.parse()?,
        ),
        RuntimeSegmentSource::new(
            BufReader::new(sel::Selected::new(&right_file, &rt)),
            digest(strf(&q, "selected_tail_sha256")?)?,
            LAST_BLOCK.parse()?,
        ),
    ];
    let bundle = tempfile::Builder::new()
        .prefix(".pending-167-")
        .tempdir_in(OUTPUT)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(bundle.path().join("epoch-167.jet"))?;
    let writer = GuardedOutput::new(&mut output, &directory, floor, 167);
    let (mut writer, stats) =
        merge_runtime_segments(readers, writer, ArchiveWriterConfig::default(), &v)?;
    writer.flush()?;
    let (bytes, hash) = writer.result();
    output.set_permissions(fs::Permissions::from_mode(0o400))?;
    output.sync_all()?;
    super::epoch167::original_identity(&open(Path::new(SOURCE))?)?;
    require(
        stats.source_archives == 2
            && stats.slots_merged == END - FIRST
            && stats.output.slots == END - FIRST
            && stats.output.epochs == 1
            && stats.output.bytes_written == bytes
            && output.metadata()?.len() == bytes
            && v.runtime_segments[1].write_versions.archive_end_exclusive()
                == Some(stats.account_updates_rebased)
            && json!(file_id(&open(Path::new(TAIL))?)?) == q["tail_identity"],
        "merged source or counters changed",
    )?;
    let report = json!({"schema":"horizon-167-private-mixed-worker-assembly-v1","epoch":167,"unit":OUTPUT_UNIT,"invocation":iid,
        "plan":{"path":path,"sha256":sha},"source_qualification":plan["qualification"],"archive_sha256":hash,"archive_bytes":bytes,
        "first_slot":FIRST,"last_slot":END-1,"slots":stats.output.slots,"transactions":stats.output.transactions,"blocks":stats.output.blocks,
        "normalized_writes":stats.account_updates_rebased,"v3_sha256":q["v3_sha256"],"private_archive":format!("{OUTPUT}/accepted/epoch-167.jet"),"publication_authorized":false});
    let mut receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(bundle.path().join("assembly.json"))?;
    serde_json::to_writer_pretty(&mut receipt, &report)?;
    receipt.write_all(b"\n")?;
    receipt.sync_all()?;
    File::open(bundle.path())?.sync_all()?;
    let name = std::ffi::CString::new(bundle.path().file_name().ok_or("bad stage")?.as_bytes())?;
    if unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            name.as_ptr(),
            directory.as_raw_fd(),
            c"accepted".as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    println!("{}", report);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slot_hash_witness_requires_the_right_sysvar_and_the_exact_parent() {
        let key = bs58::decode("SysvarS1otHashes111111111111111111111111111")
            .into_vec()
            .unwrap();
        let owner = bs58::decode("Sysvar1111111111111111111111111111111111111")
            .into_vec()
            .unwrap();
        let mut data = 1u64.to_le_bytes().to_vec();
        data.extend(SEAM.to_le_bytes());
        data.extend(bs58::decode(NATIVE_BANK).into_vec().unwrap());
        let mut witness = Seen::default();
        witness.update(SEAM + 1, &key, &owner, 52_685_674_983, &data);
        assert_eq!(witness.rows[0]["bank_hash"], NATIVE_BANK);
        assert!(!witness.invalid);
        witness.update(SEAM + 1, &key, &[], 52_685_674_983, &data);
        assert!(witness.invalid);
        let mut other = Seen::default();
        data[8..16].copy_from_slice(&(SEAM - 1).to_le_bytes());
        other.update(SEAM + 1, &key, &owner, 0, &data);
        assert!(other.rows.is_empty());
    }
    #[test]
    fn live_bounded_fixture_cuts_the_same_last_bucket_width_as_the_long_source() {
        assert_eq!((PHYSICAL_END - SEAM - 1) % 128, (END - SEAM - 1) % 128);
        assert_eq!(END - FIRST, 432000);
        assert_eq!(TAIL_END - END, 6855);
    }
}
