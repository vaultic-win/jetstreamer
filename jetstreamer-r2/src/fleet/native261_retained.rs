// Verify the completed bootstrap through its first guard drain. Later timer firings
// belong to the retained unit and cannot change the original worker's lifetime.
use super::*;
use std::collections::BTreeMap;

pub(in crate::fleet) fn verify_history() -> Result<()> {
    let root = Path::new("/var/lib/jetstreamer/horizon261-cold-terminal-history-v197-a1");
    let history_ref = BoundFile {
        path: root.join("history.json"),
        sha256: "0a7ec6ad807d910c95082d7d71d348f1b07013f1267150501d9c6714056a48fc".into(),
    };
    let saved = sealed(&history_ref)?;
    let (handoff, admission) = startup(&binding(&saved["handoff"])?)?;
    let manager = properties()?;
    let iid = text(&handoff, "invocation_id")?;
    ensure!(
        iid == "97592a79476446ffa3b0e25ff64ffcf9"
            && saved["manager"]
                .as_object()
                .context("saved manager")?
                .iter()
                .all(|(key, val)| manager.get(key) == Some(val))
            && admission["boot_id"]
                == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "261 historical producer changed"
    );

    let gp = sealed(&binding(&handoff["guard_plan"])?)?;
    let dir = guard::directory(&handoff, &gp)?;
    let result_ref = BoundFile {
        path: root.join("native-result.json"),
        sha256: text(&saved["result"], "sha256")?.into(),
    };
    let result = sealed(&result_ref)?;
    let worker = terminal::native_result(&result, &handoff, &handoff)?;
    let issued = num(
        &sealed(&binding(&handoff["startup_plan"])?)?,
        "issued_monotonic_us",
    )?;
    let producer_journal = terminal::actual_journal(&handoff)?;
    let (clean, _, wall, end) = terminal::decision(
        &producer_journal,
        &manager,
        &handoff,
        text(&admission, "boot_id")?,
        issued,
        None,
    )?;
    ensure!(clean, "epoch 261 native bootstrap failed");

    let mut records = BTreeMap::new();
    for pin in ["root-pin.json", "main-pin.json", "worker-pin.json"] {
        records.insert(pin.to_owned(), guard::record(&dir.join(pin))?);
    }
    let entries = saved["guard_history"]
        .as_array()
        .context("saved guard history")?;
    let last = entries.last().context("empty guard history")?;
    ensure!(
        last["sample"] == saved["terminal_guard"],
        "different terminal guard"
    );
    for entry in entries {
        let b = binding(&entry["sample"])?;
        let name = b
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .context("guard record name")?;
        ensure!(
            b.path.parent() == Some(dir.as_path()),
            "guard record outside original directory"
        );
        let record = guard::record(&b.path)?;
        ensure!(
            record == bound_json(&b)? && records.insert(name.to_owned(), record).is_none(),
            "changed or duplicated guard record"
        );
    }
    // Scan all PID 1 guard invocations in the interval. Looking up only the IDs
    // listed by the saved report would conceal an omitted firing.
    let drain = bound_json(&binding(&last["sample"])?)?;
    let rows = guard::journal(&[
        format!(
            "--since=@{}",
            num(&admission, "issued_unix_seconds")?.saturating_sub(60)
        ),
        format!("--until=@{}", num(&drain, "recorded_unix_seconds")? + 60),
        "_PID=1".into(),
        format!("UNIT={GUARD_UNIT}"),
    ])?;
    let mut journal = Vec::new();
    let cursor = text(last, "finished")?;
    for row in rows {
        if text(&row, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()? < issued {
            continue;
        }
        let at_end = row["__CURSOR"] == cursor;
        journal.push(row);
        if at_end {
            break;
        }
    }
    ensure!(
        journal.last().is_some_and(|r| r["__CURSOR"] == cursor),
        "original terminal cursor missing"
    );
    let evidence = json!({"records":records,"guard_pid1":journal});
    let (_, stop) = history::validate(
        &evidence,
        &handoff,
        &gp,
        issued,
        end,
        &manager,
        true,
        Some(worker),
    )?;
    ensure!(
        stop.is_none(),
        "historical bootstrap guard stopped its producer"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema":"horizon261-verified-bootstrap-history-v1","epoch":261,"bootstrap_slot":SLOT,
            "handoff":saved["handoff"],"history":private157::binding(&history_ref),
            "result":private157::binding(&result_ref),"invocation_id":iid,"worker_pid":worker,
            "terminal_unix_microseconds":wall,"guard_firings_through_first_drain":entries.len(),
            "first_terminal_guard":saved["terminal_guard"],"accounts_hash":ACCOUNTS_HASH,
            "native_input_qualified":true,"full_epoch_qualified":false,"replay_launch_authorized":false,
            "publication_authorized":false,"resource_release_authorized":false
        }))?
    );
    Ok(())
}
