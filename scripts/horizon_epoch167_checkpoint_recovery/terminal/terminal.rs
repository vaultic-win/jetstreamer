//! Capture only the released private epoch 167 worker, its exit and its closed checkpoint.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

#[allow(dead_code)]
#[path = "../../horizon_epoch170_checkpoint_suffix/evidence.rs"]
mod evidence;
use evidence::{
    bound, command, digest, idle, member, now, num, props, receipt, reference, stamp, word,
};

const ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch167-checkpoint-bounded-20261127-v2";
const UNIT: &str = "horizon-qualify-167-checkpoint-bounded-20261127-v2.service";
const TIMER: &str = "horizon-guard-167-checkpoint-bounded-20261127-v2.timer";
const GUARD: &str = "horizon-guard-167-checkpoint-bounded-20261127-v2.service";
const IID: &str = "0d5c8181a13a44ff894d5b9b8df423bc";
const PROOF: &str = "30f64fff84ba178299e9b6d49895c350d4a0792b2ad46ca10494be55fef18329";
const NODE_OK: &str = "7ad2d189f7e94e70a38c781354912448";
const NODE_FAIL: &str = "98e322203f7a4ed290d09fe03c09fe15";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/checkpoint-inputs-20261127-v1/bounded-72509256-72515090-v2";
const BOOT_HASH: &str = "5QgiqJPdQHGW8XPQofearvgZVmesY99YLHr1n7gVCkBD";
const END_HASH: &str = "DWgHoJPPD1XaWGLpasfR4RVnAU1CBoKUrjCgtoCfEDPK";
fn path(name: &str) -> PathBuf {
    Path::new(ROOT).join(name)
}
fn bind(name: &str) -> Result<Value> {
    reference(&path(name))
}
fn startup() -> Result<Value> {
    let r = bind("FIRST_PROTECTED_PROGRESS.json")?;
    ensure!(r["sha256"] == PROOF, "foreign protected startup");
    let j = bound(&r)?;
    let release = bound(&j["release"])?;
    let actor = &j["actor"];
    ensure!(
        release["actor"] == *actor
            && release["intent"] == j["intent"]
            && actor["producer_invocation_id"] == IID
            && actor["producer_unit"] == UNIT
            && fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
                == word(actor, "boot_id")?
            && release["archive_publication_authorized"] == false
            && j["release"] == bind("AUTHORIZED_RELEASE.json")?,
        "wrong bounded replay or boot"
    );
    Ok(j)
}
#[derive(Default)]
struct Log {
    signed: bool,
    verified: Vec<String>,
    checkpoints: Vec<String>,
    tail: std::collections::VecDeque<String>,
}
impl Log {
    fn consume(&mut self, line: String) -> Result<()> {
        if line.starts_with("epoch167 trace ") {
            self.signed = true;
        }
        if line.ends_with("verified legacy accounts hash at slot 72515090") {
            ensure!(self.verified.len() < 2, "duplicate terminal verification");
            self.verified.push(line.clone());
        }
        if line.contains("] historical checkpoint slot=72515090 ") {
            ensure!(self.checkpoints.len() < 2, "duplicate terminal checkpoint");
            self.checkpoints.push(line.clone());
        }
        if self.tail.len() == 20 {
            self.tail.pop_front();
        }
        self.tail.push_back(line);
        Ok(())
    }
}
fn read_log(j: &Value) -> Result<Log> {
    let log = &j["producer_log"];
    let p = Path::new(word(log, "path")?);
    ensure!(
        p == Path::new(RUN).join("producer.log") && p.canonicalize()? == p,
        "foreign append log"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.len() <= 512 << 20
            && m.dev() == num(log, "device")?
            && m.ino() == num(log, "inode")?,
        "replaced or oversize append log"
    );
    let mut read = BufReader::new(f.take(m.len()));
    let mut prefix = vec![0; usize::try_from(num(log, "read_bytes")?)?];
    read.read_exact(&mut prefix)?;
    ensure!(
        log["read_offset_bytes"] == 0 && digest(&prefix) == log["read_sha256"],
        "first protected log changed"
    );
    let mut lines = Log::default();
    let mut reader = BufReader::new(prefix.as_slice().chain(read));
    loop {
        let mut line = String::new();
        let n = (&mut reader).take((1 << 20) + 1).read_line(&mut line)?;
        ensure!(n <= 1 << 20, "oversized native log record");
        if n == 0 || !line.ends_with('\n') {
            break;
        }
        line.pop();
        lines.consume(line)?;
    }
    let after = fs::symlink_metadata(p)?;
    ensure!(
        (m.dev(), m.ino()) == (after.dev(), after.ino()) && after.len() >= m.len(),
        "log moved"
    );
    Ok(lines)
}
fn store(name: &str, doc: &Value) -> Result<Value> {
    let p = path(name);
    if p.try_exists()? {
        let r = reference(&p)?;
        ensure!(bound(&r)? == *doc, "conflicting {name}");
        return Ok(r);
    }
    receipt(&p, doc)
}
fn signed_trace(j: &Value) -> Result<Value> {
    let h = bind("BOUNDED_REPLAY_HANDOFF_20261127T0540.json")?;
    ensure!(
        h["sha256"] == "fd6fd5f5b907c6423f3f1318a3935fbbe7a36b250e78f9ece8af238897f1da1e",
        "foreign handoff"
    );
    let plan = bound(&h)?;
    let reader = member(&plan["trace_comparison"], "horizon-167-signed-trace")?;
    ensure!(
        plan["protected_worker_milestone"] == bind("FIRST_PROTECTED_PROGRESS.json")?
            && plan["release"] == j["release"],
        "foreign trace reader"
    );
    let signed_path = path("SIGNED_TRANSACTION_COMPARISON.json");
    if signed_path.try_exists()? {
        let r = reference(&signed_path)?;
        let s = bound(&r)?;
        ensure!(
            s["producer_invocation_id"] == IID
                && s["first_progress_sha256"] == PROOF
                && s["release"] == j["release"]
                && s["finalized_rpc_sha256"] == plan["finalized_transaction"]["sha256"],
            "foreign signed comparison"
        );
        return Ok(r);
    }
    let args = plan["signed_target_comparator_cli"]
        .as_array()
        .context("missing trace command")?
        .iter()
        .map(|s| s.as_str().context("bad argument"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        args.len() == 4 && Some(args[0]) == reader.to_str(),
        "wrong trace binary"
    );
    let result: Value = serde_json::from_str(&command(args[0], &args[1..])?)?;
    ensure!(
        result["producer_invocation_id"] == IID
            && result["first_progress_sha256"] == PROOF
            && result["release"] == j["release"]
            && result["comparison"]["slot"] == 72512769
            && result["finalized_rpc_sha256"] == plan["finalized_transaction"]["sha256"],
        "different signed transaction result"
    );
    store("SIGNED_TRANSACTION_COMPARISON.json", &result)
}
fn regular(p: &Path) -> Result<(File, Value)> {
    ensure!(p.canonicalize()? == p, "aliased archive or manifest");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    let id = stamp(p)?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 1001
            && m.gid() == 1003
            && m.dev() == id[0]
            && m.ino() == id[1],
        "unexpected artifact owner"
    );
    Ok((f, id))
}
fn checkpoint(lines: &Log, j: &Value) -> Result<Value> {
    let archive = Path::new(RUN).join("output/epoch-167-checkpoint-bounded.jet");
    let manifest = archive.with_extension("jet.segment.json");
    let (f, id) = regular(&manifest)?;
    ensure!(
        id[2].as_u64().unwrap_or(u64::MAX) < 1 << 20,
        "oversized segment manifest"
    );
    let mut raw = Vec::new();
    f.take(1 << 20).read_to_end(&mut raw)?;
    let m: Value = serde_json::from_slice(&raw)?;
    ensure!(
        stamp(&manifest)? == id
            && m["schema_version"] == 1
            && m["epoch"] == 167
            && m["output_slot_start"] == 72509257
            && m["output_slot_count"] == 5834
            && m["bootstrap"]["slot"] == 72509256
            && m["bootstrap"]["accounts_hash"] == BOOT_HASH
            && m["terminal"]["slot"] == 72515090
            && m["terminal"]["accounts_hash"] == END_HASH
            && m["terminal"]["slot_complete"] == true
            && m["worker_executable_sha256"] == j["worker_sha256"],
        "segment does not match the qualified checkpoints, worker or range"
    );
    let verified = &lines.verified;
    let observed = &lines.checkpoints;
    ensure!(
        verified.len() == 1 && observed.len() == 1,
        "missing or duplicate terminal accounts verification or bank summary"
    );
    let fields: BTreeMap<_, _> = observed[0]
        .split_whitespace()
        .filter_map(|s| s.split_once('='))
        .collect();
    for (key, value) in m["terminal"].as_object().context("no terminal")? {
        let k = match key.as_str() {
            "write_count" => "writes",
            "transaction_count" => "transactions",
            "slot_complete" => "complete",
            s => s,
        };
        let expected = value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string());
        ensure!(
            fields.get(k) == Some(&expected.as_str()),
            "manifest differs from native terminal field {key}"
        );
    }
    let (mut file, identity) = regular(&archive)?;
    let mut sha = Sha256::new();
    let len = std::io::copy(&mut file, &mut sha)?;
    let hash = format!("{:x}", sha.finalize());
    ensure!(
        m["archive_sha256"] == hash
            && identity == stamp(&archive)?
            && identity[2] == len
            && len > 0,
        "closed archive failed readback"
    );
    Ok(
        json!({"archive":archive,"archive_bytes":len,"archive_sha256":hash,"identity":identity,"manifest":{"path":manifest,"sha256":digest(&raw)},"terminal_checkpoint":m["terminal"],"bootstrap_checkpoint":m["bootstrap"],"raw_write_versions":m["emitted_raw_write_versions"],"checkpoint_line":observed[0],"verified_line":verified[0]}),
    )
}
fn drained(unit: &str) -> Result<()> {
    idle(unit)?;
    let cg = Path::new("/sys/fs/cgroup/system.slice")
        .join(unit)
        .join("cgroup.procs");
    match fs::read_to_string(cg) {
        Ok(s) => ensure!(s.trim().is_empty(), "occupied {unit}"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn exit_event(j: &Value) -> Result<Value> {
    drained(UNIT)?;
    let boot = word(&j["actor"], "boot_id")?.replace('-', "");
    let raw = command(
        "/usr/bin/journalctl",
        &[
            "-q",
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={IID}"),
        ],
    )?;
    let rows = raw
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut choices = rows.into_iter().filter(|s| {
        s["MESSAGE_ID"] == NODE_OK || (s["MESSAGE_ID"] == NODE_FAIL && s["COMMAND"] == "ExecStart")
    });
    let event = choices.next().context("missing PID1 terminal event")?;
    ensure!(
        choices.next().is_none()
            && event["_BOOT_ID"] == boot
            && event["INVOCATION_ID"] == IID
            && event["UNIT"] == UNIT
            && word(&event, "__REALTIME_TIMESTAMP")?.parse::<u64>()?
                >= num(&j["actor"], "ready_at")? * 1_000_000,
        "foreign PID1 terminal event"
    );
    Ok(event)
}
fn drain_guard(j: &Value) -> Result<()> {
    let s = props(TIMER, "Id,LoadState,ActiveState,InvocationID,Triggers,Job")?;
    if s["ActiveState"] == "active" {
        ensure!(
            s["InvocationID"] == j["guard"]["timer_invocation_id"]
                && s["Triggers"] == GUARD
                && s["Job"].is_empty(),
            "foreign guard timer"
        );
        drained(UNIT)?;
        command("/usr/bin/systemctl", &["stop", TIMER])?;
    }
    for _ in 0..60 {
        if idle(TIMER).is_ok() && drained(GUARD).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    anyhow::bail!("guard did not drain");
}
fn close(j: &Value) -> Result<Value> {
    let event = exit_event(j)?;
    store(
        "PID1_BOUNDED_V2_EXIT.json",
        &json!({"producer_invocation_id":IID,"release":j["release"],
        "first_progress":bind("FIRST_PROTECTED_PROGRESS.json")?,"event":event}),
    )?;
    drain_guard(j)?;
    let lines = read_log(j)?;
    let receipt_path = path("BOUNDED_V2_TERMINAL.json");
    if receipt_path.try_exists()? {
        let r = reference(&receipt_path)?;
        let t = bound(&r)?;
        ensure!(
            t["pid1_terminal_event"] == event
                && t["first_protected_progress"] == bind("FIRST_PROTECTED_PROGRESS.json")?
                && t["release"] == j["release"],
            "foreign existing terminal"
        );
        return Ok(r);
    }
    let signed = if lines.signed {
        signed_trace(j)?
    } else {
        Value::Null
    };
    let mut report = json!({"schema":"horizon-epoch167-bounded-v2-terminal-v1","recorded_unix_seconds":now()?,"producer_invocation_id":IID,
        "release":j["release"],"first_protected_progress":bind("FIRST_PROTECTED_PROGRESS.json")?,"guard_plan":j["guard"]["plan"],
        "guard_timer_invocation_id":j["guard"]["timer_invocation_id"],"guard_drained":true,"pid1_terminal_event":event,"signed_comparison":signed,
        "resource_credit_bytes":0,"reservation_ending_bytes":0,"archive_publication_authorized":false,"private_output_preserved":true});
    if event["MESSAGE_ID"] == NODE_OK {
        report["checkpoint"] = checkpoint(&lines, j)?;
        ensure!(
            !signed.is_null(),
            "bounded success lacks its signed transaction trace"
        );
        report["disposition"] = json!("checkpoint-complete");
    } else {
        report["disposition"] = json!("failed");
        report["diagnostic_tail"] = json!(lines.tail);
        report["independent_complete_archive_verified"] = json!(false);
    }
    drained(UNIT)?;
    store("BOUNDED_V2_TERMINAL.json", &report)
}
fn main() -> Result<()> {
    let mode = std::env::args()
        .nth(1)
        .context("expected prepare, signed, or close")?;
    let j = startup()?;
    let o = match mode.as_str() {
        "prepare" => {
            let log = read_log(&j)?;
            let actor = &j["actor"];
            let u = props(UNIT, "Id,LoadState,ActiveState,InvocationID,MainPID,Job")?;
            ensure!(
                u["ActiveState"] == "active"
                    && u["InvocationID"] == IID
                    && u["MainPID"] == num(actor, "producer_pid")?.to_string()
                    && u["Job"].is_empty(),
                "foreign live actor"
            );
            json!({"invocation":IID,"first_progress":PROOF,"producer_log_bound":!log.tail.is_empty(),"terminal_slot":72515090})
        }
        "signed" => signed_trace(&j)?,
        "close" => close(&j)?,
        _ => anyhow::bail!("unknown mode"),
    };
    println!("{}", serde_json::to_string(&o)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captures_only_the_target_checkpoint_and_keeps_a_bounded_tail() {
        let mut log = Log::default();
        for _ in 0..30 {
            log.consume("] historical checkpoint slot=72509256 bank_hash=abc".into())
                .unwrap();
        }
        log.consume("] historical checkpoint slot=72515090 bank_hash=end".into())
            .unwrap();
        log.consume("] verified legacy accounts hash at slot 72515090".into())
            .unwrap();
        assert_eq!(
            (log.tail.len(), log.verified.len(), log.checkpoints.len()),
            (20, 1, 1)
        );
        assert!(!log.signed);
        log.consume("epoch167 trace slot=72512769".into()).unwrap();
        assert!(log.signed);
    }
}
