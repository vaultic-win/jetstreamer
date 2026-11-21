//! Recover the parent/worker evidence from two original cold 141 warmups. Both
//! executed the selected 140 suffix before enabling archive recording.
use super::{CUT, END, INDEX_SHA, ROOT, evidence, read_json, str_field};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

const JOURNAL: &str = "/usr/local/lib/jetstreamer/horizon-epoch140-checkpoint-journal-outcome-20261020-v1/observation.json";
const JOURNAL_SHA: &str = "8dfb8d6805d6b4d50ab340899447b90449c66117cc33b1af0ca6537b934a3b13";

struct Capture {
    name: &'static str,
    launch_sha: &'static str,
    journal_name: &'static str,
    journal_sha: &'static str,
    result_sha: &'static str,
}
const CAPTURES: [Capture; 2] = [
    Capture {
        name: "freeze-components",
        launch_sha: "72e68afac690d4ee3dde6ab7e194493cb2dcd1ca142e9529272aa22db8802802",
        journal_name: "freeze-full-journal.jsonl",
        journal_sha: "beb298fb412a8fd7f05ac0d1bcc5b0aad668a2ab411de2e7d27fc01faa0c9340",
        result_sha: "f158bd27bf7c071684f4e2c1d7a49b1ed8c432c2c530f03fd59d4792b47e233d",
    },
    Capture {
        name: "vote-prefix",
        launch_sha: "a92f3345a8c04230c7c6b8453a30dea49ba28fcfd8b81e3ecaabd5c61664a3ec",
        journal_name: "journal.jsonl",
        journal_sha: "e7fbed17e653fe2fc8e5ec2648e3ad9415bbb2c811adae53fd11b3f3faf79af8",
        result_sha: "2947b49f24aaeb731cb7ea102c55726bb065545ffba5e1c585bbddd7dcd06972",
    },
];

fn match_bank(bank: &Value, original: &Value, neighbor: &Value) -> Result<()> {
    ensure!(
        bank["slot"] == END
            && bank["epoch"] == 140
            && bank["clock"]["slot"] == END
            && bank["reconstructed_hash_matches"] == true
            && bank["full_epoch_verified"] == false,
        "wrong frozen native Bank"
    );
    for field in [
        "bank_hash",
        "last_blockhash",
        "capitalization",
        "tick_height",
    ] {
        ensure!(
            original.get(field).is_some() && bank[field] == original[field],
            "frozen terminal differs from original {field}"
        );
    }
    ensure!(
        neighbor["parent_slot"] == END && neighbor["previous_poh_hash"] == bank["last_blockhash"],
        "finalized following parent differs"
    );
    Ok(())
}

fn capture(
    c: &Capture,
    rows: &[Value],
    native: &Value,
    original: &Value,
    neighbor: &Value,
) -> Result<Value> {
    let launch_path = format!(
        "/home/sol/.jetstreamer-private/epoch141-original-entry-{}-20261023-v1/receipts/launch.json",
        c.name
    );
    let root = format!(
        "/usr/local/lib/jetstreamer/horizon-epoch141-{}-result-20261023-v1",
        c.name
    );
    let result_path = Path::new(&root).join("result.json");
    let launch = read_json(Path::new(&launch_path), c.launch_sha, 64 << 10)?;
    let result = read_json(&result_path, c.result_sha, 64 << 10)?;
    let file = Path::new(&root).join(c.journal_name);
    let journal = evidence::bound_file(&file, c.journal_sha, 1 << 20, true)?;
    let iid = str_field(&launch, "invocation_id")?;
    let unit = str_field(&launch, "unit")?;
    ensure!(
        launch["launched"] == true
            && launch["bootstrap_slot"] == CUT
            && launch["replay_start_slot"] == CUT + 1
            && launch["terminal_root_slot"] == ROOT
            && launch["snapshot_sha256"] == native["snapshot_sha256"]
            && launch["original_index_sha256"] == INDEX_SHA
            && result["invocation_id"] == iid
            && result["unit"] == unit
            && result["terminal"]["restarts"] == 0
            && result["terminal"]["main_pid"] == 0
            && result["terminal"]["exit_status"] == 1,
        "wrong warmup launch, result or artifact lineage"
    );
    let guard_ref = &launch["first_guard"];
    let guard_path = Path::new(&launch_path).with_file_name("first-guard.json");
    ensure!(
        guard_ref["path"].as_str() == guard_path.to_str(),
        "wrong original guard path"
    );
    let guard = read_json(&guard_path, str_field(guard_ref, "sha256")?, 64 << 10)?;
    let parent = guard["producer"]["pid"]
        .as_u64()
        .context("missing guarded parent")?;
    let workers = guard["workers"]
        .as_array()
        .context("missing guarded workers")?;
    ensure!(
        workers.len() == 1
            && guard["producer"]["invocation_id"] == iid
            && guard["producer"]["restarts"] == 0,
        "ambiguous warmup worker"
    );
    let worker = workers[0][0]
        .as_u64()
        .context("missing original worker PID")?;
    ensure!(
        parent > 1 && worker > 1 && parent != worker,
        "invalid warmup PIDs"
    );
    let parent = parent.to_string();
    let worker = worker.to_string();
    let parent_exe = str_field(&launch, "expected_exec_start")?
        .strip_prefix("{ path=")
        .and_then(|s| s.split_once(" ;").map(|v| v.0))
        .context("missing parent executable")?;
    let worker_scratch =
        Path::new(str_field(&launch, "run_root")?).join("scratch/.historical-runtime");
    let checkpoint = &native["native_result"]["native_checkpoint"];
    let initialize = format!(
        "historical worker initialized at slot {CUT} (last_blockhash={}, ticks_per_slot=64, next_write_version={})",
        str_field(checkpoint, "last_blockhash")?,
        checkpoint["next_write_version"]
    );
    let mut init_count = 0;
    let mut warmup_count = 0;
    let mut bank = None;
    let mut observed = Vec::new();
    for line in journal
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
    {
        let entry: Value = serde_json::from_slice(line)?;
        if entry["_SYSTEMD_INVOCATION_ID"] != iid || entry["_SYSTEMD_UNIT"] != unit {
            continue;
        }
        let Some(message) = entry["MESSAGE"].as_str() else {
            continue;
        };
        if entry["_COMM"] == "jetstreamer-nod"
            && entry["_PID"] == parent
            && entry["_EXE"] == parent_exe
        {
            let body = message.split_once("] ").map(|(_, body)| body).unwrap_or("");
            if body == initialize {
                init_count += 1;
            }
            if body
                == "warming up replay from slot 60911752 to 60911999 (recording starts at 60912000)"
            {
                warmup_count += 1;
            }
            if let Some(suffix) = body.strip_prefix("qualified original source slot=") {
                let slot: u64 = suffix
                    .split_whitespace()
                    .next()
                    .context("missing matched slot")?
                    .parse()?;
                if (CUT + 1..=END).contains(&slot) {
                    let row = rows
                        .get(observed.len())
                        .context("extra original-entry match in suffix")?;
                    let record = &row["record"];
                    let parent = record["parent_slot"]
                        .as_u64()
                        .context("missing gap parent")?;
                    ensure!(
                        record["slot"] == slot && init_count == 1 && warmup_count == 1,
                        "foreign or reordered warmup target"
                    );
                    let span = slot.checked_sub(parent).context("invalid source parent")?;
                    let expected = format!(
                        "qualified original source slot={slot} transactions={} original_entries={} hidden_boundaries={span} poh_hashes={}",
                        row["transactions"],
                        row["entries"],
                        span * 64 * 12_500
                    );
                    ensure!(
                        body == expected,
                        "native original-entry verification differs at {slot}"
                    );
                    observed.push(
                        json!({"slot":slot,"journal_cursor":entry["__CURSOR"],"message":body}),
                    );
                }
            }
        } else if entry["_COMM"] == "historical-work" && entry["_PID"] == worker {
            if let Some(encoded) = message.strip_prefix("epoch141 frozen-bank components: ") {
                let v: Value = serde_json::from_str(encoded)?;
                if v["slot"] == END {
                    let exe = Path::new(str_field(&entry, "_EXE")?);
                    ensure!(
                        exe.starts_with(&worker_scratch)
                            && exe.ends_with("bound-worker/historical-worker"),
                        "wrong mapped historical worker"
                    );
                    ensure!(
                        bank.is_none() && observed.len() == rows.len(),
                        "duplicate or premature epoch-end frozen Bank"
                    );
                    match_bank(&v, original, neighbor)?;
                    bank = Some(
                        json!({"components":v,"journal_cursor":entry["__CURSOR"],"worker_executable":entry["_EXE"]}),
                    );
                }
            }
        }
    }
    let bank = bank.context("missing actual frozen epoch-end worker")?;
    ensure!(
        init_count == 1 && warmup_count == 1 && observed.len() == rows.len(),
        "incomplete native warmup"
    );
    Ok(
        json!({"launch":{"path":launch_path,"sha256":c.launch_sha},"result":{"path":result_path,"sha256":c.result_sha},
        "journal":{"path":file,"sha256":c.journal_sha},"unit":unit,"invocation_id":iid,"worker_sha256":launch["worker_sha256"],
        "first_guard":guard_ref,"parent_pid":parent,"worker_pid":worker,"parent_sha256":launch["node_sha256"],"source_matches":observed,"frozen_epoch_end":bank,"archive_recording_began_at":END+1}),
    )
}

pub(super) fn qualify(
    rows: &[Value],
    native: &Value,
    edge: &Value,
    neighbor: &Value,
) -> Result<Value> {
    let journal = read_json(Path::new(JOURNAL), JOURNAL_SHA, 64 << 10)?;
    let original = &journal["checkpoints"][1];
    ensure!(
        journal["producer_invocation_id"] == "b907f4e67095443cb02e9c815ee14499"
            && original["slot"] == END
            && original["complete"] == true
            && original["last_blockhash"] == edge["observed_terminal_blockhash"]
            && original["next_write_version"] == edge["observed_terminal_next_write_version"],
        "original terminal checkpoint differs"
    );
    let runs = CAPTURES
        .iter()
        .map(|capture_input| capture(capture_input, rows, native, original, neighbor))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        runs[0]["invocation_id"] != runs[1]["invocation_id"]
            && runs[0]["worker_sha256"] != runs[1]["worker_sha256"],
        "reused warmup witness"
    );
    Ok(
        json!({"original_terminal_observation":{"path":JOURNAL,"sha256":JOURNAL_SHA,"checkpoint":original},
        "captures":runs,"terminal_accounts_hash_independently_observed":false,"terminal_wire_account_update_equivalence_proven":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_bank_and_outgoing_finalized_parent_are_distinct_gates() {
        let bank = json!({"slot":END,"epoch":140,"clock":{"slot":END},"reconstructed_hash_matches":true,"full_epoch_verified":false,
            "bank_hash":"bank","last_blockhash":"poh","capitalization":488588165210800736u64,"tick_height":3898368000u64});
        let neighbor = json!({"parent_slot":END,"previous_poh_hash":"poh"});
        match_bank(&bank, &bank, &neighbor).unwrap();
        for key in [
            "bank_hash",
            "last_blockhash",
            "capitalization",
            "tick_height",
        ] {
            let mut changed = bank.clone();
            changed[key] = Value::Null;
            assert!(match_bank(&bank, &changed, &neighbor).is_err());
        }
        let mut changed = neighbor.clone();
        changed["previous_poh_hash"] = json!("bank");
        assert!(match_bank(&bank, &bank, &changed).is_err());
    }
}
