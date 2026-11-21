//! A finite protocol peer for the independently guarded epoch 228 worker.
//! Standard input is the worker's reply pipe; standard output is its request
//! pipe. Receipts go to stderr, never into the framed stream.
use anyhow::{Context, Result, ensure};
use jetstreamer_historical_protocol as p;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const WORKER: &str =
    "/var/lib/jetstreamer/horizon228-demotion-bank-9d2fd8d4-v158-v2-qualified/worker";
const SHA: &str = "16d4b15881979bb7d65a0f49408580d4508b451a5953f35cbb60505d2e3cee00";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-228-230-current-46b4b4a-v1/snapshot-98495291-GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq.tar.zst";
const GENESIS: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/genesis.tar.bz2";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input228-v1620-demotion-v1";
const RELEASE: &str = "/run/horizon228-demotion-cold-v1/release.json";
const UNIT: &str = "horizon-native-input-228-demotion-16d4b158-v1.service";
const GUARD: &str = "horizon-native-input-228-demotion-guard-v1.service";
const TIMER: &str = "horizon-native-input-228-demotion-guard-v1.timer";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon228-demotion-cold-guard-receipts-v1";
const SLOT: u64 = 98_495_291;
const CURSOR: u64 = 113_087_684_591;
const ACCOUNTS: &str = "GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq";
const LAST: &str = "9xcoJhnYB4FJjJS3xRGytzb6i8epLY7i3cdzDAFpAwfR";
const BANK: &str = "3bAzCpbDvGKVrLQTP1hwEdibg6j4DYucpkxwQ3FvkCb2";

fn stable(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (a.dev(), a.ino(), a.len(), a.ctime(), a.ctime_nsec())
        == (b.dev(), b.ino(), b.len(), b.ctime(), b.ctime_nsec())
}

fn checked_file(path: &Path, root_writable: bool) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical {}",
        path.display()
    );
    let original = path.symlink_metadata()?;
    ensure!(
        original.is_file()
            && original.uid() == 0
            && original.nlink() == 1
            && (original.mode() & 0o222 == 0
                || (root_writable && original.mode() & 0o777 == 0o600)),
        "unsealed {}",
        path.display()
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        stable(&original, &file.metadata()?),
        "replaced {}",
        path.display()
    );
    Ok(file)
}

fn sealed(path: &Path) -> Result<File> {
    checked_file(path, false)
}

fn hash_file(path: &str, expected: &str, bytes: u64) -> Result<()> {
    let path = Path::new(path);
    let mut f = sealed(path)?;
    let before = f.metadata()?;
    ensure!(before.len() == bytes, "input size {}", path.display());
    let mut hash = Sha256::new();
    ensure!(
        io::copy(&mut f, &mut hash)? == bytes
            && format!("{:x}", hash.finalize()) == expected
            && stable(&before, &f.metadata()?)
            && stable(&before, &path.symlink_metadata()?),
        "input identity {}",
        path.display()
    );
    Ok(())
}

fn document(path: &Path, expected: Option<&str>) -> Result<Value> {
    let mut f = checked_file(path, expected.is_some())?;
    let before = f.metadata()?;
    ensure!(before.len() <= 1 << 20, "oversized control evidence");
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    ensure!(
        stable(&before, &f.metadata()?) && stable(&before, &path.symlink_metadata()?),
        "changed control evidence"
    );
    if let Some(digest) = expected {
        ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == digest,
            "control digest"
        );
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("missing {key}"))
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().with_context(|| format!("missing {key}"))
}
fn reference(v: &Value) -> Result<Value> {
    document(Path::new(field(v, "path")?), Some(field(v, "sha256")?))
}

fn pipe_identity(pid: u32) -> Result<()> {
    ensure!(pid > 1, "worker PID");
    let holder = PathBuf::from(format!("/proc/{pid}"));
    let image = fs::metadata(holder.join("exe"))?;
    ensure!(
        fs::read_link(holder.join("exe"))? == Path::new(WORKER)
            && stable(&image, &sealed(Path::new(WORKER))?.metadata()?),
        "worker image"
    );
    for (our, their) in [(0, 1), (1, 0)] {
        let own = fs::metadata(format!("/proc/self/fd/{our}"))?;
        let other = fs::metadata(holder.join(format!("fd/{their}")))?;
        ensure!(
            own.file_type().is_fifo()
                && other.file_type().is_fifo()
                && (own.dev(), own.ino()) == (other.dev(), other.ino()),
            "worker pipe {their}"
        );
    }
    let a = fs::metadata("/proc/self/fd/0")?;
    let b = fs::metadata("/proc/self/fd/1")?;
    ensure!(
        (a.dev(), a.ino()) != (b.dev(), b.ino()),
        "protocol pipes alias"
    );
    Ok(())
}

fn show(unit: &str, key: &str) -> Result<String> {
    let result = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "-p", key, "--value"])
        .output()?;
    ensure!(result.status.success(), "systemctl {unit} {key}");
    Ok(String::from_utf8(result.stdout)?.trim().to_string())
}
fn ident(iid: &str) -> bool {
    iid.len() == 32
        && iid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn journal(args: &[String]) -> Result<Vec<Value>> {
    let out = Command::new("/usr/bin/journalctl")
        .args(["-b", "--no-pager", "-o", "json"])
        .args(args)
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 4 << 20,
        "journal read"
    );
    out.stdout
        .split(|&b| b == b'\n')
        .filter(|s| !s.is_empty())
        .map(|s| Ok(serde_json::from_slice(s)?))
        .collect()
}

fn positive(sample: &Value, plan: &Value, release: &Value, pid: u32) -> Result<()> {
    let iid = field(release, "producer_iid")?;
    let gid = field(sample, "guard_invocation_id")?;
    ensure!(ident(iid) && ident(gid) && gid != iid, "original IDs");
    ensure!(
        plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["unit"] == UNIT
            && plan["invocation_id"] == iid
            && plan["filesystem"] == "/"
            && plan["worker_root"] == ROOT
            && plan["receipt_directory"] == RECEIPTS
            && plan["maximum_root_physical_bytes"] == 300_000_000_000u64
            && plan["maximum_worker_vmas"] == 3_500_000
            && plan["native_main"] == json!({"executable":WORKER,"sha256":SHA,"main_pid":pid})
            && plan["bounded_measurement"].is_null()
            && plan["bounded_canary"].is_null(),
        "original guard plan"
    );
    let protected = number(plan, "minimum_free_bytes")?;
    ensure!(
        protected > 0
            && release["protected_floor_bytes"] == protected
            && number(release, "required_free_bytes")?
                >= protected
                    .checked_add(300_268_435_456)
                    .context("floor overflow")?,
        "booked envelope"
    );
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["producer_invocation_id"] == iid
            && sample["producer"]["pid"] == pid
            && sample["producer"]["invocation_id"] == iid
            && sample["producer"]["active"] == "active"
            && sample["producer"]["sub"] == "running"
            && sample["producer"]["restarts"] == 0
            && sample["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && sample["producer_stop_enabled"] == true
            && sample["guard_sha256"] == release["guard"]["sha256"]
            && sample["plan_sha256"] == release["plan"]["sha256"]
            && sample["plan"] == release["plan"]["path"]
            && sample["native_main"] == plan["native_main"]
            && sample["minimum_free_bytes"] == protected
            && sample["maximum_root_physical_bytes"] == plan["maximum_root_physical_bytes"]
            && sample["maximum_worker_vmas"] == 3_500_000
            && sample["root_physical_observation"]["exceeds_budget"] == false
            && sample["root_physical_observation_error"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["trip_reason"].is_null(),
        "nonprotective guard"
    );
    let workers = sample["workers"].as_array().context("worker list")?;
    ensure!(
        workers.len() == 1
            && workers[0][0] == pid
            && (1..3_500_000).contains(&workers[0][1].as_u64().context("VMAs")?)
            && number(sample, "available_bytes")? >= number(release, "required_free_bytes")?,
        "worker or free budget"
    );
    Ok(())
}

fn authorize(pid: u32) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "original root controller required"
    );
    let path = Path::new(RELEASE);
    let dir = path.parent().unwrap().symlink_metadata()?;
    ensure!(
        dir.uid() == 0 && dir.is_dir() && dir.mode() & 0o077 == 0,
        "root-only release directory"
    );
    let r = document(path, None)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let issued = number(&r, "issued_unix_seconds")?;
    let until = number(&r, "expires_unix_seconds")?;
    ensure!(
        r["schema"] == "epoch228-demotion-cold-release-v1"
            && r["unit"] == UNIT
            && r["guard_source"] == "f68492a79b280fa58b7526da1a013028c5fdf784"
            && r["worker_sha256"] == SHA
            && r["worker_pid"] == pid
            && issued <= now
            && now < until
            && until - issued <= 300
            && r["host_boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "expired or foreign release"
    );
    let admission = reference(&r["admission"])?;
    let fleet = reference(&admission["fleet"])?;
    let ledger = reference(&admission["reservation_ledger"])?;
    let review = reference(&admission["review"])?;
    let native_fit = reference(&admission["source_fit"])?;
    let initial_fit = reference(&admission["initial_fit"])?;
    let initial_cap = &initial_fit["scenarios"]["cold"]["capacity"];
    ensure!(
        initial_fit["schema"] == "horizon-native228-demotion-current-fit-v1"
            && initial_fit["held"] == false
            && initial_fit["unit"] == UNIT
            && initial_fit["scenarios"]["cold"]["fits"] == true
            && initial_fit["review"] == native_fit["review"]
            && initial_fit["fleet"] == native_fit["fleet"]
            && initial_fit["worker"] == native_fit["worker"]
            && initial_fit["reservation_ledger"] == native_fit["reservation_ledger"]
            && initial_fit["boot_id"] == native_fit["boot_id"]
            && initial_fit["controller"]["InvocationID"]
                == native_fit["controller"]["InvocationID"]
            && number(initial_cap, "protected_existing_floor_bytes")?
                <= number(&r, "protected_floor_bytes")?,
        "original prestart fit"
    );

    ensure!(
        admission["schema"] == "epoch228-demotion-cold-admission-v1"
            && admission["unit"] == UNIT
            && admission["worker_sha256"] == SHA
            && admission["scratch_root"] == ROOT
            && admission["producer_memory_bytes"] == (128_u64 << 30)
            && number(&admission, "required_free_bytes")? == number(&r, "required_free_bytes")?
            && number(&admission, "protected_floor_bytes")? == number(&r, "protected_floor_bytes")?
            && admission["guard"] == r["guard"]
            && admission["host_boot_id"] == r["host_boot_id"]
            && admission["producer_only_no_entries"] == true
            && number(&admission, "issued_unix_seconds")? <= issued
            && until <= number(&admission, "expires_unix_seconds")?,
        "original scoped admission"
    );
    ensure!(
        review["Main_accepted"] == true
            && ledger["Main_accepted"] == true
            && review["reservation_ledger"] == admission["reservation_ledger"]
            && review["fleet"] == admission["fleet"]
            && native_fit["fleet"] == admission["fleet"]
            && native_fit["review"] == admission["review"]
            && native_fit["reservation_ledger"] == admission["reservation_ledger"]
            && ledger["fleet"] == admission["fleet"]
            && ledger["observer"] == review["observer"]
            && ledger["observer"] == native_fit["observer"]
            && native_fit["boot_id"] == r["host_boot_id"],
        "current fleet/review/fit"
    );
    let owner = &native_fit["producer"];
    let original_cap = &native_fit["scenarios"]["cold"]["capacity"];
    ensure!(
        native_fit["schema"] == "horizon-native228-demotion-current-fit-v1"
            && native_fit["held"] == true
            && native_fit["unit"] == UNIT
            && native_fit["cold_root"] == ROOT
            && native_fit["worker"] == json!({"path":WORKER,"sha256":SHA})
            && owner["Id"] == UNIT
            && owner["MainPID"] == pid.to_string()
            && owner["InvocationID"] == r["producer_iid"]
            && native_fit["scenarios"]["cold"]["fits"] == true
            && number(original_cap, "protected_existing_floor_bytes")?
                <= number(&r, "protected_floor_bytes")?
            && number(original_cap, "required_initial_free_bytes")?
                <= number(&r, "required_free_bytes")?
            && native_fit["additional_paired_retry_credit_bytes"] == 0
            && native_fit["holding_reclamation_credit_bytes"] == 0,
        "held epoch 228 funding or producer changed"
    );
    for source in [&fleet, &review, &initial_fit, &native_fit] {
        let stamp = number(source, "recorded_unix_seconds")?;
        ensure!(
            stamp <= now && now - stamp <= 300,
            "expired underlying funding source"
        );
    }
    let guard_path = field(&r["guard"], "path")?;
    let guard_meta = sealed(Path::new(guard_path))?.metadata()?;
    ensure!(guard_meta.len() < 256 << 20, "guard image size");
    hash_file(guard_path, field(&r["guard"], "sha256")?, guard_meta.len())?;
    let sample = reference(&r["first_guard"])?;
    let plan = reference(&r["plan"])?;
    positive(&sample, &plan, &r, pid)?;
    let sampled = number(&sample, "recorded_unix_seconds")?;
    ensure!(
        sampled <= now
            && now - sampled <= 300
            && sampled >= number(&initial_fit, "recorded_unix_seconds")?
            && sampled <= number(&native_fit, "recorded_unix_seconds")?,
        "first sample timing"
    );
    let gid = field(&sample, "guard_invocation_id")?;
    ensure!(
        Path::new(field(&r["first_guard"], "path")?)
            == Path::new(RECEIPTS).join(format!("sample-{gid}.json"))
            && !Path::new(RECEIPTS).join("stop-intent.json").try_exists()?,
        "guard state"
    );
    let gid_manager = journal(&[
        "_PID=1".into(),
        "_UID=0".into(),
        format!("UNIT={GUARD}"),
        format!("INVOCATION_ID={gid}"),
    ])?;
    ensure!(
        gid_manager
            .iter()
            .any(|j| j["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf")
            && gid_manager
                .iter()
                .any(|j| j["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
            && !gid_manager
                .iter()
                .any(|j| j.get("UNIT_RESULT").map_or(false, |v| v != "success")),
        "guard PID 1 terminal"
    );
    let body = journal(&[
        format!("_SYSTEMD_UNIT={GUARD}"),
        format!("_SYSTEMD_INVOCATION_ID={gid}"),
        "_UID=0".into(),
    ])?;
    ensure!(
        body.iter().any(|j| j["_EXE"] == r["guard"]["path"]
            && j["MESSAGE"]
                .as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .as_ref()
                == Some(&sample)),
        "original guard emission"
    );
    ensure!(
        show(TIMER, "ActiveState")? == "active"
            && show(TIMER, "Triggers")?
                .split_whitespace()
                .any(|u| u == GUARD)
            && show(UNIT, "InvocationID")? == field(&r, "producer_iid")?
            && show(UNIT, "MainPID")? == pid.to_string()
            && show(UNIT, "MemoryMax")? == (128_u64 << 30).to_string()
            && show(UNIT, "MemorySwapMax")? == "0"
            && show(UNIT, "NRestarts")? == "0"
            && show(UNIT, "Restart")? == "no",
        "original timer or producer"
    );
    let group = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    ensure!(
        fs::read_to_string(group.join("cgroup.procs"))?
            .split_whitespace()
            .collect::<Vec<_>>()
            == [pid.to_string().as_str()]
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::/system.slice/{UNIT}"),
        "worker escaped or extra producer process"
    );
    pipe_identity(pid)?;
    Ok(r)
}

fn ask<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    id: u64,
    body: p::RequestBody,
) -> Result<p::ResponseBody> {
    p::write_frame(w, &p::Request { id, body })?;
    let reply: p::Response = p::read_frame(r)?.context("worker EOF")?;
    ensure!(reply.request_id == id, "wrong request id");
    Ok(reply.body)
}
fn hello<R: Read, W: Write>(r: &mut R, w: &mut W) -> Result<p::Handshake> {
    let p::ResponseBody::Handshake(h) = ask(
        r,
        w,
        1,
        p::RequestBody::Hello {
            protocol_version: p::PROTOCOL_VERSION,
        },
    )?
    else {
        anyhow::bail!("handshake rejected")
    };
    ensure!(
        h.protocol_version == 5
            && h.backend_id == "solana-v1.6.20-epoch228-called-program-demotion-candidate"
            && h.target == "x86_64-unknown-linux-gnu"
            && h.solana_tag == "v1.6.20"
            && h.solana_commit == "77bdb45d4af61fc687161ec06cc0178ff79726d5"
            && h.rust_toolchain == "rustc 1.51.0 (2fd73fabe 2021-03-23)"
            && h.required_genesis_hash == p::MAINNET_GENESIS_HASH
            && h.qualification == p::BackendQualification::Candidate,
        "foreign handshake"
    );
    Ok(h)
}
fn check_cold(i: &p::Initialized, c: &p::Checkpoint) -> Result<()> {
    let b58 = |v: &[u8]| bs58::encode(v).into_string();
    ensure!(
        i.genesis_hash == p::MAINNET_GENESIS_HASH
            && i.ticks_per_slot == 64
            && i.slot == SLOT
            && i.next_write_version == CURSOR
            && b58(&i.last_blockhash) == LAST
            && matches!(&i.source,p::InitializedSource::SnapshotArchive{archive_path,expected_accounts_hash} if archive_path==SNAPSHOT && b58(expected_accounts_hash)==ACCOUNTS),
        "cold initialization"
    );
    ensure!(
        c.slot == SLOT
            && c.slot_complete
            && c.writes.is_empty()
            && b58(&c.bank_hash) == BANK
            && b58(&c.accounts_hash) == ACCOUNTS
            && c.last_blockhash == i.last_blockhash
            && c.capitalization == 504_915_797_589_943_503
            && c.transaction_count == 29_954_968_857
            && c.tick_height == 6_303_698_688
            && c.next_write_version == i.next_write_version,
        "cold bank tuple"
    );
    Ok(())
}

fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        args.len() == 2 && matches!(args[0].as_str(), "--probe-held" | "--cold-held"),
        "usage: protocol --probe-held|--cold-held WORKER_PID"
    );
    let pid = args[1].parse::<u32>()?;
    pipe_identity(pid)?;
    hash_file(WORKER, SHA, 8_988_704)?;
    let mut reader = io::stdin().lock();
    let mut writer = io::stdout().lock();
    let h = hello(&mut reader, &mut writer)?;
    let mut proof = json!({"worker_pid":pid,"worker_sha256":SHA,"handshake":h,"snapshot_loaded":false,"replay_entries":0,"shutdown_acknowledged":false});
    if args[0] == "--cold-held" {
        let original = authorize(pid)?;
        hash_file(
            GENESIS,
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            20_144,
        )?;
        hash_file(
            SNAPSHOT,
            "da26bd1b4b3b93be74c9dae28d1d982f821474333aa06e87f32dfa83342915f3",
            10_510_540_911,
        )?;
        ensure!(
            authorize(pid)? == original,
            "release changed during input validation"
        );
        let p::ResponseBody::Initialized(i) = ask(
            &mut reader,
            &mut writer,
            2,
            p::RequestBody::Initialize {
                ledger_path: GENESIS.into(),
                initial_state: p::InitialState::SnapshotArchive {
                    archive_path: SNAPSHOT.into(),
                },
                scratch_root: Some(ROOT.into()),
            },
        )?
        else {
            anyhow::bail!("worker init failed")
        };
        let p::ResponseBody::Checkpoint(c) = ask(
            &mut reader,
            &mut writer,
            3,
            p::RequestBody::FreezeCheckpoint { slot: SLOT },
        )?
        else {
            anyhow::bail!("worker freeze failed")
        };
        check_cold(&i, &c)?;
        proof["snapshot_loaded"] = json!(true);
        proof["initialized"] = json!(i);
        proof["checkpoint"] = json!(c);
        proof["release"] = original;
    } else {
        ensure!(
            ask(&mut reader, &mut writer, 2, p::RequestBody::Ping)? == p::ResponseBody::Pong,
            "probe ping failed"
        );
    }
    ensure!(
        ask(&mut reader, &mut writer, 4, p::RequestBody::Shutdown)?
            == p::ResponseBody::ShuttingDown,
        "shutdown failed"
    );
    proof["shutdown_acknowledged"] = json!(true);
    eprintln!("{proof}");
    Ok(())
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn decode(text: &str) -> Vec<u8> {
        bs58::decode(text).into_vec().unwrap()
    }

    #[test]
    fn verifies_entire_original_cold_tuple_and_zero_mutations() {
        let init = p::Initialized {
            genesis_hash: p::MAINNET_GENESIS_HASH.into(),
            source: p::InitializedSource::SnapshotArchive {
                archive_path: SNAPSHOT.into(),
                expected_accounts_hash: decode(ACCOUNTS),
            },
            slot: SLOT,
            last_blockhash: decode(LAST),
            ticks_per_slot: 64,
            next_write_version: CURSOR,
        };
        let c = p::Checkpoint {
            slot: SLOT,
            bank_hash: decode(BANK),
            accounts_hash: decode(ACCOUNTS),
            last_blockhash: decode(LAST),
            capitalization: 504_915_797_589_943_503,
            transaction_count: 29_954_968_857,
            tick_height: 6_303_698_688,
            slot_complete: true,
            writes: vec![],
            next_write_version: CURSOR,
        };
        check_cold(&init, &c).unwrap();
        for (key, x) in [
            ("slot", json!(SLOT + 1)),
            ("bank_hash", json!([])),
            ("accounts_hash", json!([])),
            ("last_blockhash", json!([])),
            ("capitalization", json!(1)),
            ("transaction_count", json!(1)),
            ("tick_height", json!(1)),
            ("slot_complete", json!(false)),
            ("next_write_version", json!(1)),
        ] {
            let mut bad = json!(c);
            bad[key] = x;
            assert!(
                check_cold(&init, &serde_json::from_value(bad).unwrap()).is_err(),
                "{key}"
            );
        }
        let mut i = init.clone();
        i.ticks_per_slot = 0;
        assert!(check_cold(&i, &c).is_err());
        i = init;
        i.source = p::InitializedSource::Genesis;
        assert!(check_cold(&i, &c).is_err());
    }
    #[test]
    fn rejects_absent_worker_guard_even_when_planned_and_funded() {
        let iid = "a".repeat(32);
        let pid = 254u32;
        let native = json!({"executable":WORKER,"sha256":SHA,"main_pid":pid});
        let plan = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":&iid,"filesystem":"/","worker_root":ROOT,"receipt_directory":RECEIPTS,"maximum_root_physical_bytes":300_000_000_000u64,"minimum_free_bytes":800,"maximum_worker_vmas":3_500_000,"native_main":native});
        let r = json!({"producer_iid":&iid,"protected_floor_bytes":800,"required_free_bytes":300_268_436_256u64,"guard":{"sha256":"1".repeat(64)},"plan":{"path":"/private/plan","sha256":"2".repeat(64)}});
        let sample = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","producer_invocation_id":&iid,"guard_invocation_id":"b".repeat(32),"producer":{"pid":pid,"active":"active","sub":"running","invocation_id":&iid,"restarts":0,"cgroup":format!("/system.slice/{UNIT}")},"native_main":native,"producer_stop_enabled":true,"guard_sha256":r["guard"]["sha256"],"plan_sha256":r["plan"]["sha256"],"plan":r["plan"]["path"],"minimum_free_bytes":800,"maximum_root_physical_bytes":300_000_000_000u64,"maximum_worker_vmas":3_500_000,"root_physical_observation":{"exceeds_budget":false},"workers":[[pid,351]],"available_bytes":300_268_436_256u64});
        positive(&sample, &plan, &r, pid).unwrap();
        for (key, x) in [
            ("workers", json!([])),
            ("workers", json!([[pid, 0]])),
            ("workers", json!([[pid, 3_500_000]])),
            ("workers", json!([[pid + 1, 200]])),
            ("native_main", Value::Null),
            ("producer_stop_enabled", json!(false)),
            ("trip_reason", json!("root-physical-budget")),
            ("root_physical_observation_error", json!("changed")),
            ("available_bytes", json!(1)),
            ("guard_sha256", json!("3".repeat(64))),
            ("producer_invocation_id", json!("c".repeat(32))),
        ] {
            let mut bad = sample.clone();
            bad[key] = x;
            assert!(positive(&bad, &plan, &r, pid).is_err(), "{key}");
        }
        let mut old = plan;
        old["worker_root"] =
            json!("/home/ubuntu/.jetstreamer-private/native-input228-v1620-capped-v1");
        assert!(positive(&sample, &old, &r, pid).is_err());
    }
    #[test]
    fn never_accepts_a_foreign_frame_id() {
        let mut wire = Vec::new();
        p::write_frame(
            &mut wire,
            &p::Response {
                request_id: 7,
                body: p::ResponseBody::Pong,
            },
        )
        .unwrap();
        let mut output = Vec::new();
        assert!(ask(&mut wire.as_slice(), &mut output, 3, p::RequestBody::Ping).is_err());
    }
}
