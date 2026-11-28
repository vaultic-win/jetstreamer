//! Close the guarded second RAM recording that stopped before its first block.
use super::{evidence, retained_checkpoint};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, io::ErrorKind, path::Path};

pub(super) const ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73760367-ram-20261128-v2";
pub(super) const UNIT: &str = "horizon-qualify-170-from-73760367-ram-20261128-v2.service";
pub(super) const IID: &str = "8a91ae07377042a3b929571f175527b3";
const LOG: &str = "8758ed7c894b35708fce0cab99aa011b07d814efb0b0cdc25d4e1d9c02584588";

fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => anyhow::bail!("unexpected stopped output at {}", path.display()),
    }
}

fn pinned(name: &str, sha: &str) -> Result<(Value, Value)> {
    let reference = json!({"path":Path::new(ROOT).join(name),"sha256":sha});
    Ok((evidence::bound(&reference)?, reference))
}

fn bootstrap_log(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        text.contains("invocation 8a91ae07377042a3b929571f175527b3 released")
            && text.contains("bootstrap 73760367, replay 73760368..=73766969")
            && text
                .lines()
                .filter(|line| line.contains("starting isolated solana-v1.5.6 worker"))
                .count()
                == 1
            && !text.contains("] progress slot ")
            && !text.contains("] historical checkpoint slot=")
            && evidence::digest(bytes) == LOG,
        "different startup log or observed progress"
    );
    Ok(())
}

pub(super) fn report() -> Result<Value> {
    let root = Path::new(ROOT);
    evidence::idle(UNIT)?;
    let (grant, gr) = pinned(
        "SUCCESSOR_RELEASE.json",
        "1b5869841e8bbf498dce09570d10c9cfc7cf003637eec618d12a033b4f4292d8",
    )?;
    let (stop, sr) = pinned(
        "guard-receipts/stop-intent.json",
        "a7075f6e5830b81c73676fa7095ef36a747e6cde4ebd025fc2ae2219e4d9d2e1",
    )?;
    let (ended, er) = pinned(
        "guard-receipts/stop-completion.json",
        "c57fdaebc601ac3b4d1da1f2e8864cfe4c845d7cd20b898f32b302dfef89e23e",
    )?;
    let actor = evidence::bound(&grant["actor"])?;
    let scope = evidence::bound(&grant["interface"])?;
    let plan = evidence::bound(&grant["guard_plan"])?;
    let post = evidence::bound(&grant["post_guard_capacity"])?;
    let sample = &stop["sample"];
    let free = 9_627_125_334_016u64;
    let floor = 9_627_514_457_748u64;
    ensure!(
        grant["producer_invocation_id"] == IID
            && actor["unit"] == UNIT
            && actor["producer_invocation_id"] == IID
            && grant["interface"] == actor["interface"]
            && scope["expected_producer_unit"] == UNIT
            && plan["unit"] == UNIT
            && plan["invocation_id"] == IID
            && plan["minimum_free_bytes"] == floor
            && grant["guard_plan"]["sha256"] == stop["plan_sha256"]
            && ended["plan_sha256"] == stop["plan_sha256"]
            && stop["producer_invocation_id"] == IID
            && ended["producer_invocation_id"] == IID
            && ended["intent"] == sr["path"]
            && stop["reason"] == "filesystem-floor"
            && sample["trip_reason"] == stop["reason"]
            && sample["producer_stop_enabled"] == true
            && sample["producer"]["pid"] == actor["producer_pid"]
            && sample["workers"] == json!([[727358, 56]])
            && sample["available_bytes"] == free
            && sample["minimum_free_bytes"] == floor
            && sample["maximum_root_physical_bytes"] == plan["maximum_root_physical_bytes"]
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && sample["root_physical_observation"]["exceeds_budget"] == false
            && ended["terminal"]["pid"] == 0
            && ended["terminal"]["invocation_id"] == IID
            && ended["scratch_deleted"] == false
            && post["fits"] == true
            && post["home_margin"] == 2_622_411_116u64
            && post["ram_margin"] == 341_048_320u64,
        "wrong second RAM actor, postguard admission or floor stop"
    );
    let (previous, checkpoint) = retained_checkpoint(&grant)?;
    ensure!(
        checkpoint["slot"] == 73_760_367,
        "changed independent bootstrap checkpoint"
    );
    let log = Path::new(evidence::word(&scope, "log")?);
    let run = Path::new(evidence::word(&scope, "run")?);
    let ledger = run.join("ledger");
    ensure!(
        log == run.join("producer.log") && ledger.canonicalize()? == ledger,
        "changed work tree"
    );
    let log_id = evidence::stamp(log)?;
    let data = evidence::trusted(log)?;
    bootstrap_log(&data)?;
    let partial = ledger.join("epoch-170.diagnostic.jet");
    let manifest = partial.with_extension("jet.segment.json");
    let progress = root.join("FIRST_PROTECTED_PROGRESS.json");
    for path in [&partial, &manifest, &progress] {
        absent(path)?;
    }
    let boot = evidence::word(&actor, "boot_id")?.replace('-', "");
    let journal = evidence::command(
        "/usr/bin/journalctl",
        &[
            "-q",
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            "_UID=0",
            &format!("_BOOT_ID={boot}"),
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={IID}"),
            "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
        ],
    )?;
    let mut lines = journal.lines();
    let terminal: Value = serde_json::from_str(lines.next().context("missing PID1 deactivation")?)?;
    ensure!(
        lines.next().is_none()
            && terminal["INVOCATION_ID"] == IID
            && terminal["UNIT"] == UNIT
            && terminal["_BOOT_ID"] == boot
            && evidence::stamp(log)? == log_id,
        "changed manager or retained log"
    );
    evidence::idle(UNIT)?;
    absent(
        &Path::new("/sys/fs/cgroup/system.slice")
            .join(UNIT)
            .join("cgroup.procs"),
    )?;
    for path in [&partial, &manifest, &progress] {
        absent(path)?;
    }
    Ok(
        json!({"schema":"horizon-epoch170-guarded-bootstrap-floor-stop-v1","unit":UNIT,"invocation_id":IID,
        "actor":grant["actor"],"release":gr,"stop_intent":sr,"stop_completion":er,"pid1_deactivation":terminal,
        "log":{"path":log,"identity":log_id,"sha256":LOG},"original_recording":previous,
        "independent_bootstrap_checkpoint":checkpoint,"guard_plan":grant["guard_plan"],
        "post_guard_capacity":grant["post_guard_capacity"],"guard_observed_workers":sample["workers"],
        "free_bytes_at_stop":free,"armed_floor":floor,"shortfall":floor-free,"last_logged_progress":null,
        "partial":null,"partial_path":partial,"segment_manifest_present":false,"closed_segment":false,
        "resource_credit_bytes":0,"publication_authorized":false}),
    )
}
