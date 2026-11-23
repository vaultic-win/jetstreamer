//! The stop witness follows the archive writer's counters, including repeated slot notifications.
use super::*;
const TARGET_SLOT: u64 = 114_923_569;
const TARGET_TX: u64 = 18_057_238;

fn target(rows: &[Value], unit: &str, iid: &str, pid: u64, after: u64) -> Result<Option<Value>> {
    let pid = pid.to_string();
    let mut samples = Vec::new();
    let mut cursors = BTreeSet::new();
    for row in rows {
        ensure!(
            row["_BOOT_ID"] == BOOT.replace('-', "")
                && row["_SYSTEMD_UNIT"] == unit
                && row["_SYSTEMD_INVOCATION_ID"] == iid
                && row["_UID"] == "1000"
                && row["_PID"] == pid
                && row["_EXE"] == successor::NODE,
            "foreign bounded progress"
        );
        let (time, slot, tx, accounts) =
            entries::progress(row, 115343999)?.context("expected node progress")?;
        let cursor = text(row, "__CURSOR")?;
        ensure!(
            time > after && slot <= 115343999 && !cursor.is_empty() && cursors.insert(cursor),
            "outside bounded playback"
        );
        samples.push((time, slot, tx, accounts, cursor));
    }
    samples.sort_unstable_by_key(|s| s.0);
    ensure!(
        samples.windows(2).all(|w| {
            let (a, b) = (w[0], w[1]);
            a.0 < b.0 && a.1 <= b.1 && a.2 <= b.2 && a.3 <= b.3
        }),
        "replay counters regressed"
    );
    let Some(last) = samples.last() else {
        return Ok(None);
    };
    if last.1 < TARGET_SLOT || last.2 < TARGET_TX {
        return Ok(None);
    }
    Ok(Some(
        json!({"first":samples.first(),"last":last,"rows":rows}),
    ))
}

pub(in super::super) fn stop_at_target(
    p: &Profile,
    s: &Value,
    owner: &BTreeMap<String, String>,
) -> Result<()> {
    let iid = text(s, "iid")?;
    let pid = owner["MainPID"].parse::<u64>()?;
    let path = p.state.join(format!("token-{iid}.json"));
    if !path.try_exists()? {
        return Ok(());
    }
    let token = bound_at(&path)?.sealed()?;
    ensure!(
        token["pid"] == pid && token["iid"] == iid && token["unit"] == p.unit,
        "wrong guard release"
    );
    let first = binding(&token["guard_pid1"])?.sealed()?;
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "-b",
            "-n",
            "16",
            "-o",
            "json",
            "--grep=progress slot ",
            &format!("_SYSTEMD_UNIT={}", p.unit),
            &format!("_SYSTEMD_INVOCATION_ID={iid}"),
            &format!("_PID={pid}"),
            "_UID=1000",
            &format!("_EXE={}", successor::NODE),
        ])
        .output()?;
    if output.status.code() == Some(1) && output.stdout.is_empty() && output.stderr.is_empty() {
        return Ok(());
    }
    ensure!(
        output.status.success(),
        "bounded progress journal unavailable"
    );
    let rows = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let Some(progress) = target(&rows, &p.unit, iid, pid, num(&first, "last_monotonic_us")?)?
    else {
        return Ok(());
    };
    let tree = entries::tree(p, pid)?;
    ensure!(
        tree[&pid]["image"] == successor::NODE
            && tree[&pid]["role"] == "node"
            && gate::owner_fields(&p.unit)? == *owner,
        "different bounded writer"
    );
    let rr = p.state.join("receipts");
    let intent = save_json(
        &rr,
        "target-stop-intent.json",
        &json!({"unit":p.unit,"iid":iid,"pid":pid,"guard_iid":std::env::var("INVOCATION_ID")?,"token":bound_at(&path)?,"first_guard":token["guard_pid1"],"processes":tree,"progress":progress,"publication_authorized":false}),
    )?;
    ensure!(
        entries::tree(p, pid)? == tree && gate::owner_fields(&p.unit)? == *owner,
        "writer changed before bounded stop"
    );
    ensure!(
        Command::new("/usr/bin/systemctl")
            .args(["stop", &p.unit])
            .status()?
            .success(),
        "bounded producer stop failed"
    );
    finish(p, iid, &intent)?;
    Ok(())
}
pub(in super::super) fn finish(p: &Profile, iid: &str, intent: &Bound) -> Result<Bound> {
    let rr = p.state.join("receipts");
    let record = intent.sealed()?;
    ensure!(
        record["iid"] == iid
            && record["unit"] == p.unit
            && intent.path == rr.join("target-stop-intent.json"),
        "different bounded stop"
    );
    let manager = stopped::checked_terminal(&p.unit, iid)?;
    let done = rr.join("target-stop-completion.json");
    if done.try_exists()? {
        let b = bound_at(&done)?;
        let v = b.sealed()?;
        ensure!(
            v["intent"] == json!(intent) && v["manager"] == manager,
            "different completed bounded stop"
        );
        return Ok(b);
    }
    save_json(
        &rr,
        "target-stop-completion.json",
        &json!({"intent":intent,"manager":manager,"bounded_entry_replay":true,"full_epoch_qualified":false,"publication_authorized":false,"resources_released":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires original trusted Foundation journal"]
    fn real_stopped_writer_requires_both_target_counters_and_its_own_identity() {
        let journal=Bound::new("/home/ubuntu/.codex/diagnostics/horizon266-bounded-input-contract-v207-a2/target-pid1-journal.json","80f0f09d2be263deff802cc021a5cfbe635734f05a4234b46b5f6bbbf6e7a27c").json().unwrap();
        let mut rows = journal.as_array().unwrap().clone();
        let check = |v: &[Value]| {
            target(
                v,
                "horizon-qualify-266-instructions-2789f821-v194.service",
                "41cf6e5a5cd54d57adc5eba3f0c0ecef",
                3215067,
                0,
            )
        };
        assert!(check(&rows[..6]).unwrap().is_none());
        rows.reverse();
        assert!(check(&rows).unwrap().is_some());
        for (key, value) in [
            ("_PID", "42"),
            ("_UID", "0"),
            ("_EXE", "/usr/bin/other"),
            ("_SYSTEMD_INVOCATION_ID", "wrong"),
        ] {
            let mut foreign = rows.clone();
            foreign[0][key] = json!(value);
            assert!(check(&foreign).is_err());
        }
        for (slot, tx) in [
            (TARGET_SLOT - 1, TARGET_TX),
            (TARGET_SLOT, TARGET_TX - 1),
            (TARGET_SLOT, TARGET_TX),
        ] {
            let mut row = rows[0].clone();
            row["MESSAGE"] = json!(format!(
                "progress slot {slot}/115343999 txs={tx} accounts=54325801"
            ));
            assert_eq!(
                check(&[row]).unwrap().is_some(),
                slot == TARGET_SLOT && tx == TARGET_TX
            );
        }
    }
}
