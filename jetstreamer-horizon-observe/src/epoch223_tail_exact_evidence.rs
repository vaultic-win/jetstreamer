//! Metadata-only correction/capture of an already completed native223 tail.
//! No Bank restore, process observation, archive scan, replay or remote access.
#![recursion_limit = "256"]
#[allow(dead_code)]
#[path = "../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, env, fs, path::PathBuf};

const UNIT: &str = "horizon-qualify-223-v1625-tail-1743245a-v3.service";
const IID: &str = "20dc145d1e8c41fdbc682046b6fe4289";
const PID: &str = "3452507";
const SNAPSHOT: &str = "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1";
const WORKER: &str = "fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c";
const NODE: &str = "4449d7e3ba116c346567996ac5205bd20b05c67bb2c1625f353555a7c0ce445c";
const ARCHIVE: &str = "89470a1b323aa2dd0cd17eb15464f49a2971c44587112b52523e24f8cc4687dc";
const REVISION: &str = "7de8a55b54d3e11058b82f9483bb405d143b455c";
const START: u64 = 107266983592;
const END: u64 = 107268320809;
const MANAGER_TIME: u64 = 1792709375589317;

// Closed evidence set. Plans can select an output, never substitute evidence.
const SOURCES: [(&str, &str); 6] = [
    (
        "/var/lib/jetstreamer/horizon-223-tail-launch-1743245a-v3/launch.json",
        "85f99bf0bbd999d7d5e01d6ab6341c1930ded802d91584bd483f5b0f03cfa083",
    ),
    (
        "/var/lib/jetstreamer/horizon-223-tail-terminal-1743245a-v3/producer.jsonl",
        "deaabb3f7fa543ac7b61f1d6ec59a836db0757eef30cdaec0c177c7d424d7f68",
    ),
    (
        "/var/lib/jetstreamer/horizon-223-tail-terminal-1743245a-v3/segment.json",
        "baf168cdc9f1e87aef1ab41facdfbe130ddec009d9d5f41d39b2a92d5a2572f0",
    ),
    (
        "/var/lib/jetstreamer/horizon-223-tail-independent-validation-1743245a-v3/epoch-223.tail.validation.json",
        "6ddc7d6178f38e7ef6d40a94457c2cbccb256b61c81dad6d47b9d5a7f042521f",
    ),
    (
        "/var/lib/jetstreamer/horizon-223-tail-hardfork-audit-20261022-v1/metadata.json",
        "b56472075e586b61af0e56796e7d91c8fe6a14900bc13fa599a7206cf8dbed75",
    ),
    (
        "/var/lib/jetstreamer/horizon-223-tail-terminal-1743245a-v3/terminal.json",
        "c39fb156441c4ad65e5691e03f62e12d205c2454310db3479bf9d58a509ff457",
    ),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    output: PathBuf,
}

fn tuple(terminal: bool) -> Value {
    if terminal {
        json!({"slot":96767999u64,"bank_hash":"5UXknwBTsQ3joTCQ5855LKtPU9Pc51X5JqP9caCfzEKq",
            "accounts_hash":"44Sa4y57YYjfRjzAf78tnJMMneAbAM2mHWTUdBP3tGF6",
            "last_blockhash":"FoQQ2aee2RRZnc94GSr3KnAWCw3DDshKuAer3HpJDHg",
            "capitalization":504095067970689961u64,"transaction_count":28220025696u64,
            "tick_height":6193152000u64,"slot_complete":true,"write_count":657u64,"next_write_version":END})
    } else {
        json!({"slot":96767522u64,"bank_hash":"EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB",
            "accounts_hash":"3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7",
            "last_blockhash":"GQt4KimbvHnCHhz8qm98dJo91BwNeBakuKCEHYpRvXNM",
            "capitalization":504095069290845150u64,"transaction_count":28219544812u64,
            "tick_height":6193121472u64,"slot_complete":true,"write_count":0u64,"next_write_version":START})
    }
}

fn fields(raw: &str) -> Result<BTreeMap<&str, &str>> {
    let mut found = BTreeMap::new();
    for part in raw.split_whitespace() {
        let (key, value) = part.split_once('=').context("malformed checkpoint field")?;
        ensure!(
            found.insert(key, value).is_none(),
            "duplicate checkpoint field"
        );
    }
    ensure!(found.len() == 10, "incomplete/unexpected checkpoint fields");
    Ok(found)
}

fn checkpoint(message: &str) -> Result<Value> {
    let raw = message
        .split_once("historical checkpoint ")
        .context("checkpoint marker missing")?
        .1;
    let values = fields(raw)?;
    let text =
        |key| -> Result<&str> { values.get(key).copied().context("checkpoint field missing") };
    let number = |key| -> Result<u64> { Ok(text(key)?.parse::<u64>()?) };
    ensure!(text("complete")? == "true", "incomplete checkpoint");
    Ok(
        json!({"slot":number("slot")?,"bank_hash":text("bank_hash")?,
        "accounts_hash":text("accounts_hash")?,"last_blockhash":text("last_blockhash")?,
        "capitalization":number("capitalization")?,"transaction_count":number("transactions")?,
        "tick_height":number("tick_height")?,"slot_complete":true,
        "write_count":number("writes")?,"next_write_version":number("next_write_version")?}),
    )
}

fn raw_evidence(raw: &[u8]) -> Result<Value> {
    let mut initialized = Vec::new();
    let mut bootstrap = Vec::new();
    let mut terminal = Vec::new();
    let mut success = Vec::new();
    for (index, line) in std::str::from_utf8(raw)?.lines().enumerate() {
        ensure!(
            index < 10000 && line.len() <= 65536,
            "journal bounds exceeded"
        );
        let row: Value = serde_json::from_str(line)?;
        let message = row["MESSAGE"].as_str().context("journal message missing")?;
        let init = message.contains("historical worker initialized at slot ");
        let check = message.contains("historical checkpoint ");
        let manager = message.contains("Deactivated successfully.");
        if !init && !check && !manager {
            continue;
        }
        let time: u64 = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("journal clock missing")?
            .parse()?;
        if manager {
            ensure!(
                row["_PID"] == "1"
                    && row["UNIT"] == UNIT
                    && row["INVOCATION_ID"] == IID
                    && message == format!("{UNIT}: Deactivated successfully."),
                "foreign manager success"
            );
            success.push((index + 1, time));
            continue;
        }
        ensure!(
            row["_PID"] == PID && row["_SYSTEMD_INVOCATION_ID"] == IID,
            "foreign producer marker"
        );
        if let Some(unit) = row.get("_SYSTEMD_UNIT") {
            ensure!(unit == UNIT, "foreign producer unit");
        }
        if init {
            let suffix = message
                .split_once("historical worker initialized at slot ")
                .context("initialization marker")?
                .1;
            ensure!(
                suffix
                    == "96767522 (last_blockhash=GQt4KimbvHnCHhz8qm98dJo91BwNeBakuKCEHYpRvXNM, ticks_per_slot=64, next_write_version=107266983592)",
                "wrong initialized slot/hash/ticks/cursor"
            );
            initialized.push((index + 1, time));
        } else {
            let found = checkpoint(message)?;
            match found["slot"].as_u64() {
                Some(96767522) => {
                    ensure!(found == tuple(false), "wrong bootstrap tuple/cursor");
                    bootstrap.push((index + 1, time));
                }
                Some(96767999) => {
                    ensure!(found == tuple(true), "wrong terminal tuple/cursor");
                    terminal.push((index + 1, time));
                }
                _ => anyhow::bail!("unexpected checkpoint slot"),
            }
        }
    }
    ensure!(
        initialized.len() == 1 && bootstrap.len() == 1 && terminal.len() == 1 && success.len() == 1,
        "missing/duplicate journal markers"
    );
    let ordered = [initialized[0], bootstrap[0], terminal[0], success[0]];
    ensure!(
        ordered
            .windows(2)
            .all(|p| p[0].0 < p[1].0 && p[0].1 < p[1].1)
            && success[0].1 == MANAGER_TIME,
        "journal marker order/clock mismatch"
    );
    Ok(
        json!({"initialized":{"line":initialized[0].0,"realtime_micros":initialized[0].1},
        "bootstrap":{"line":bootstrap[0].0,"realtime_micros":bootstrap[0].1},
        "terminal":{"line":terminal[0].0,"realtime_micros":terminal[0].1},
        "manager_success":{"line":success[0].0,"realtime_micros":success[0].1},
        "producer_invocation_id":IID,"producer_pid":PID,"unit":UNIT}),
    )
}

fn deny_authority(scope: &Value) -> Result<()> {
    for key in [
        "canonical_prefix_qualified",
        "canonical_sidecar_authorized",
        "complete_epoch_span_covered",
        "full_cold_epoch_peak_qualified",
        "publication_authorized",
        "r2_mutations",
        "remote_mutations",
        "runtime_promotion_authorized",
        "terminal_canonical_root_independently_known",
    ] {
        ensure!(scope[key] == false, "unexpected {key} authority");
    }
    ensure!(
        scope["tail_comparison_only"] == true,
        "not comparison-only evidence"
    );
    Ok(())
}

fn validate(
    launch: &Value,
    raw: &[u8],
    segment: &Value,
    reread: &Value,
    fork: &Value,
    rounded: &Value,
) -> Result<Value> {
    ensure!(
        launch["schema"] == "jetstreamer-private-epoch223-v1625-tail-launch-v3"
            && launch["launched"] == true
            && launch["epoch"] == 223
            && launch["snapshot_slot"] == 96767522
            && launch["snapshot_sha256"] == SNAPSHOT
            && launch["node_sha256"] == NODE
            && launch["worker_sha256"] == WORKER
            && launch["runtime"] == "solana-v1.6.25"
            && launch["producer_invocation_id"] == IID
            && launch["parent_pid"] == 3452507
            && launch["output_slot_start"] == 96767523
            && launch["terminal_slot"] == 96767999
            && launch["output_slot_count"] == 477
            && launch["restart_policy"] == "no",
        "wrong native25 launch"
    );
    let units = launch["evidence"]["units"]
        .as_array()
        .context("missing launch unit")?;
    ensure!(
        units.len() == 1
            && units[0]["unit"] == UNIT
            && units[0]["invocation_id"] == IID
            && units[0]["main_pid"] == 3452507
            && units[0]["restarts"] == 0,
        "wrong launch identity"
    );
    ensure!(
        segment["schema_version"] == 1
            && segment["epoch"] == 223
            && segment["output_slot_start"] == 96767523
            && segment["output_slot_count"] == 477
            && segment["runtime"]["runtime_profile"] == "solana-v1.6.25"
            && segment["runtime"]["runtime_revision"] == REVISION
            && segment["runtime"]["runtime_admission"] == "candidate"
            && segment["worker_executable_sha256"] == WORKER
            && segment["archive_sha256"] == ARCHIVE
            && segment["bootstrap"] == tuple(false)
            && segment["terminal"] == tuple(true)
            && segment["emitted_raw_write_versions"] == json!({"start":START,"end":END}),
        "wrong exact segment"
    );
    let journal = raw_evidence(raw)?;
    ensure!(
        reread["schema"] == "jetstreamer-focused-qualification-artifact-validation-v1"
            && reread["validation"] == "pass"
            && reread["epoch"] == 223
            && reread["archive_bytes"] == 144030696
            && reread["archive_sha256"] == ARCHIVE
            && reread["bootstrap_slot"] == 96767522
            && reread["output_slot_start"] == 96767523
            && reread["terminal_slot"] == 96767999
            && reread["output_slot_count"] == 477
            && reread["worker_executable_sha256"] == WORKER
            && reread["runtime_profile"] == "solana-v1.6.25"
            && reread["runtime_revision"] == REVISION
            && reread["runtime_admission"] == "candidate"
            && reread["manifest_content_encoding"] == "historical-segment-manifest-serde-json-v1"
            && reread["manifest_content_sha256"]
                == "53693cb81b1cadd9ca8b146ab9b7452c96887780c564f09df98b08850f9a719d"
            && reread["canonical_checksum_sidecar_absent"] == true,
        "wrong independent tail reread"
    );
    deny_authority(&reread["qualification_scope"])?;
    ensure!(
        fork["schema"] == "jetstreamer-private-v1620-snapshot-hard-fork-metadata-v1"
            && fork["slot"] == 96767522
            && fork["parent_slot"] == 96767521
            && fork["bank_hash"] == tuple(false)["bank_hash"]
            && fork["snapshot_sha256"] == SNAPSHOT
            && fork["snapshot_bytes"] == 9705551147u64
            && fork["hard_forks"]
                == json!([[13334463, 1], [53180900, 1], [96542804, 1], [96542805, 1]])
            && fork["accounts_restored"] == false
            && fork["bank_frozen"] == false
            && fork["snapshot_verified"] == false
            && fork["publication_authorized"] == false
            && fork["replay_authorized"] == false
            && fork["remote_mutations"] == false,
        "wrong fork metadata"
    );
    let mut rounded_bootstrap = tuple(false);
    rounded_bootstrap["capitalization"] = json!(504095069290845100u64);
    let mut rounded_terminal = tuple(true);
    rounded_terminal["capitalization"] = json!(504095067970690000u64);
    ensure!(
        rounded["schema"] == "jetstreamer-private-epoch223-tail-terminal-v1"
            && rounded["epoch"] == 223
            && rounded["unit"] == UNIT
            && rounded["invocation_id"] == IID
            && rounded["result"] == "success"
            && rounded["exit_code"] == 0
            && rounded["restarts"] == 0
            && rounded["bootstrap"] == rounded_bootstrap
            && rounded["terminal"] == rounded_terminal
            && rounded["archive_sha256"] == ARCHIVE
            && rounded["segment_manifest_sha256"] == SOURCES[2].1
            && rounded["primary_journal"]["sha256"] == SOURCES[1].1
            && rounded["producer_launch"]["sha256"] == SOURCES[0].1,
        "wrong preserved rounded summary"
    );
    deny_authority(rounded)?;
    Ok(
        json!({"schema":"jetstreamer-epoch223-native25-exact-historical-input-v1","epoch":223,
        "bootstrap":tuple(false),"terminal":tuple(true),"initialized_next_write_version":START,
        "emitted_raw_write_versions":{"start":START,"end":END,"end_exclusive":true},
        "ticks_per_slot":64,"snapshot_sha256":SNAPSHOT,"worker_sha256":WORKER,
        "runtime":"solana-v1.6.25","runtime_revision":REVISION,"archive_sha256":ARCHIVE,
        "archive_bytes":144030696,"output_slot_start":96767523,"output_slot_count":477,
        "journal_markers":journal,"independent_tail_reread_passed":true,
        "preserved_rounded_summary_authoritative_for_tuple":false,
        "corrections":[{"field":"bootstrap.capitalization","preserved":504095069290845100u64,"exact":504095069290845150u64},
            {"field":"terminal.capitalization","preserved":504095067970690000u64,"exact":504095067970689961u64}],
        "correction_basis":"Exact u64 raw producer markers agree with the sealed segment; rounded historical summary is retained unchanged.",
        "source_evidence":SOURCES.iter().map(|(path,sha)|json!({"path":path,"sha256":sha})).collect::<Vec<_>>(),
        "raw_cursor_scope":"Local to this independently restored native25 validator; never equate with a native20 prefix cursor. Normalize emitted ranges separately during checked assembly.",
        "tail_comparison_only":true,"bank_rerun_performed":false,"current_host_observation_performed":false,
        "archive_reread_performed":false,"source_modified":false,"rounded_summary_modified":false,
        "canonical_prefix_qualified":false,"native20_prefix_independently_verified":false,
        "handoff_qualified":false,"cursor_normalization_performed":false,"assembly_authorized":false,
        "complete_epoch_span_covered":false,"full_cold_epoch_peak_qualified":false,
        "terminal_canonical_root_independently_known":false,"runtime_promotion_authorized":false,
        "repair_closed":false,"replay_launch_authorized":false,"canonical_sidecar_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}

fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(args.len() == 3, "usage: PLAN PLAN_SHA256 SELF_SHA256");
    evidence::bound_file(
        &fs::read_link("/proc/self/exe")?,
        &args[2],
        64 * 1024 * 1024,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&evidence::bound_file(
        &PathBuf::from(&args[0]),
        &args[1],
        65536,
        true,
    )?)?;
    ensure!(
        plan.schema == "jetstreamer-epoch223-tail-exact-evidence-plan-v1",
        "wrong plan schema"
    );
    let sources: Vec<Vec<u8>> = SOURCES
        .iter()
        .map(|(path, sha)| evidence::bound_file(&PathBuf::from(path), sha, 4 * 1024 * 1024, true))
        .collect::<Result<_>>()?;
    let parse = |i: usize| -> Result<Value> { Ok(serde_json::from_slice(&sources[i])?) };
    let mut receipt = validate(
        &parse(0)?,
        &sources[1],
        &parse(2)?,
        &parse(3)?,
        &parse(4)?,
        &parse(5)?,
    )?;
    receipt["self_sha256"] = json!(args[2]);
    receipt["plan"] = json!({"path":args[0],"sha256":args[1]});
    evidence::write_receipt(&plan.output, &receipt)?;
    println!(
        "{}",
        json!({"status":"exact-historical-tail-captured","output":plan.output,
        "publication_authorized":false,"bank_rerun_performed":false})
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("epoch223 exact tail evidence refused: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> Vec<Value> {
        let producer = |message: String, time: u64| {
            json!({"MESSAGE":message,"__REALTIME_TIMESTAMP":time.to_string(),
            "_PID":PID,"_SYSTEMD_INVOCATION_ID":IID})
        };
        let checkpoint_message = |t: Value| {
            format!(
                "historical checkpoint slot={} bank_hash={} accounts_hash={} last_blockhash={} capitalization={} transactions={} tick_height={} complete=true writes={} next_write_version={}",
                t["slot"],
                t["bank_hash"].as_str().unwrap(),
                t["accounts_hash"].as_str().unwrap(),
                t["last_blockhash"].as_str().unwrap(),
                t["capitalization"],
                t["transaction_count"],
                t["tick_height"],
                t["write_count"],
                t["next_write_version"]
            )
        };
        vec![producer("historical worker initialized at slot 96767522 (last_blockhash=GQt4KimbvHnCHhz8qm98dJo91BwNeBakuKCEHYpRvXNM, ticks_per_slot=64, next_write_version=107266983592)".into(),MANAGER_TIME-3),
            producer(checkpoint_message(tuple(false)),MANAGER_TIME-2),producer(checkpoint_message(tuple(true)),MANAGER_TIME-1),
            json!({"MESSAGE":format!("{UNIT}: Deactivated successfully."),"__REALTIME_TIMESTAMP":MANAGER_TIME.to_string(),
                "_PID":"1","UNIT":UNIT,"INVOCATION_ID":IID})]
    }
    fn ndjson(rows: &[Value]) -> Vec<u8> {
        rows.iter()
            .map(|r| format!("{}\n", serde_json::to_string(r).unwrap()))
            .collect::<String>()
            .into_bytes()
    }
    fn scope() -> Value {
        json!({"canonical_prefix_qualified":false,"canonical_sidecar_authorized":false,"complete_epoch_span_covered":false,
            "full_cold_epoch_peak_qualified":false,"publication_authorized":false,"r2_mutations":false,
            "remote_mutations":false,"runtime_promotion_authorized":false,
            "terminal_canonical_root_independently_known":false,"tail_comparison_only":true})
    }
    fn inputs() -> [Value; 5] {
        let launch = json!({"schema":"jetstreamer-private-epoch223-v1625-tail-launch-v3","launched":true,
            "epoch":223,"snapshot_slot":96767522,"snapshot_sha256":SNAPSHOT,"node_sha256":NODE,
            "worker_sha256":WORKER,"runtime":"solana-v1.6.25","producer_invocation_id":IID,"parent_pid":3452507,
            "output_slot_start":96767523,"terminal_slot":96767999,"output_slot_count":477,"restart_policy":"no",
            "evidence":{"units":[{"unit":UNIT,"invocation_id":IID,"main_pid":3452507,"restarts":0}]}});
        let segment = json!({"schema_version":1,"epoch":223,"output_slot_start":96767523,"output_slot_count":477,
            "runtime":{"runtime_profile":"solana-v1.6.25","runtime_revision":REVISION,"runtime_admission":"candidate"},
            "worker_executable_sha256":WORKER,"archive_sha256":ARCHIVE,"bootstrap":tuple(false),"terminal":tuple(true),
            "emitted_raw_write_versions":{"start":START,"end":END}});
        let reread = json!({"schema":"jetstreamer-focused-qualification-artifact-validation-v1","validation":"pass",
            "epoch":223,"archive_bytes":144030696,"archive_sha256":ARCHIVE,"bootstrap_slot":96767522,
            "output_slot_start":96767523,"terminal_slot":96767999,"output_slot_count":477,
            "worker_executable_sha256":WORKER,"runtime_profile":"solana-v1.6.25","runtime_revision":REVISION,
            "runtime_admission":"candidate","manifest_content_encoding":"historical-segment-manifest-serde-json-v1",
            "manifest_content_sha256":"53693cb81b1cadd9ca8b146ab9b7452c96887780c564f09df98b08850f9a719d",
            "canonical_checksum_sidecar_absent":true,"qualification_scope":scope()});
        let fork = json!({"schema":"jetstreamer-private-v1620-snapshot-hard-fork-metadata-v1",
            "slot":96767522,"parent_slot":96767521,"bank_hash":tuple(false)["bank_hash"],"snapshot_sha256":SNAPSHOT,
            "snapshot_bytes":9705551147u64,"hard_forks":[[13334463,1],[53180900,1],[96542804,1],[96542805,1]],
            "accounts_restored":false,"bank_frozen":false,"snapshot_verified":false,"publication_authorized":false,
            "replay_authorized":false,"remote_mutations":false});
        let mut rounded = scope();
        rounded.as_object_mut().unwrap().extend(json!({"schema":"jetstreamer-private-epoch223-tail-terminal-v1",
            "epoch":223,"unit":UNIT,"invocation_id":IID,"result":"success","exit_code":0,"restarts":0,
            "bootstrap":tuple(false),"terminal":tuple(true),"archive_sha256":ARCHIVE,"segment_manifest_sha256":SOURCES[2].1,
            "primary_journal":{"sha256":SOURCES[1].1},"producer_launch":{"sha256":SOURCES[0].1}}).as_object().unwrap().clone());
        rounded["bootstrap"]["capitalization"] = json!(504095069290845100u64);
        rounded["terminal"]["capitalization"] = json!(504095067970690000u64);
        [launch, segment, reread, fork, rounded]
    }
    fn capture(input: &[Value; 5], rows: &[Value]) -> Result<Value> {
        validate(
            &input[0],
            &ndjson(rows),
            &input[1],
            &input[2],
            &input[3],
            &input[4],
        )
    }

    #[test]
    fn exact_capture_serializes_large_u64_and_explicit_corrections_without_authority() {
        let receipt = capture(&inputs(), &journal()).unwrap();
        let bytes = serde_json::to_vec(&receipt).unwrap();
        let decoded: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            decoded["bootstrap"]["capitalization"].as_u64(),
            Some(504095069290845150)
        );
        assert_eq!(
            decoded["terminal"]["capitalization"].as_u64(),
            Some(504095067970689961)
        );
        assert_eq!(
            decoded["corrections"][0]["preserved"].as_u64(),
            Some(504095069290845100)
        );
        deny_authority(&decoded).unwrap();
        for k in [
            "handoff_qualified",
            "assembly_authorized",
            "cursor_normalization_performed",
            "repair_closed",
            "bank_rerun_performed",
            "current_host_observation_performed",
            "replay_launch_authorized",
        ] {
            assert_eq!(decoded[k], false, "{k}");
        }
    }
    #[test]
    fn reject_rounded_or_floating_or_missing_segment_numbers() {
        for value in [
            json!(504095069290845100u64),
            json!(504095069290845150f64),
            Value::Null,
            json!("504095069290845150"),
        ] {
            let mut input = inputs();
            input[1]["bootstrap"]["capitalization"] = value;
            assert!(capture(&input, &journal()).is_err());
        }
    }
    #[test]
    fn reject_changed_initialized_cursor_and_checkpoint_cursor() {
        for index in [0, 1] {
            let mut rows = journal();
            rows[index]["MESSAGE"] = json!(
                rows[index]["MESSAGE"]
                    .as_str()
                    .unwrap()
                    .replace("107266983592", "107266983593")
            );
            assert!(capture(&inputs(), &rows).is_err());
        }
    }
    #[test]
    fn reject_foreign_duplicate_missing_or_out_of_order_markers() {
        for index in 0..4 {
            let mut rows = journal();
            rows[index]["_PID"] = json!("999");
            assert!(capture(&inputs(), &rows).is_err());
            let mut rows = journal();
            rows.push(rows[index].clone());
            assert!(capture(&inputs(), &rows).is_err());
            let mut rows = journal();
            rows.remove(index);
            assert!(capture(&inputs(), &rows).is_err());
            let mut rows = journal();
            rows[index]["__REALTIME_TIMESTAMP"] =
                json!(if index < 3 { MANAGER_TIME } else { 1 }.to_string());
            assert!(capture(&inputs(), &rows).is_err());
        }
        let mut rows = journal();
        rows[1]["_SYSTEMD_INVOCATION_ID"] = json!("foreign");
        assert!(capture(&inputs(), &rows).is_err());
    }
    #[test]
    fn reject_changed_fork_worker_runtime_span_and_authority() {
        for (i, pointer, value) in [
            (3, "/hard_forks/2/1", json!(2)),
            (0, "/worker_sha256", json!(NODE)),
            (1, "/runtime/runtime_revision", json!("wrong")),
            (2, "/output_slot_count", json!(476)),
            (
                2,
                "/qualification_scope/publication_authorized",
                json!(true),
            ),
            (4, "/bootstrap/capitalization", json!(504095069290845150u64)),
            (1, "/emitted_raw_write_versions/end", json!(END + 1)),
        ] {
            let mut input = inputs();
            *input[i].pointer_mut(pointer).unwrap() = value;
            assert!(capture(&input, &journal()).is_err(), "{pointer}");
        }
    }
}
