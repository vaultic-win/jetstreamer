//! Complete immutable guard history plus exact standalone worker result.
use super::native265 as c;
use super::*;
pub(super) fn result(v: &Value, origin: &Value, h: &Value) -> Result<u64> {
    result_for(
        v,
        origin,
        h,
        265,
        "horizon265-exact-worker-cold-input-result-v1",
        114_479_281,
        c::ACCOUNTS_HASH,
        c::SNAPSHOT_SHA,
        "/var/lib/jetstreamer/horizon-contiguous-265-265-current-46b4b4a-v1/snapshot-114479281-Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW.tar.zst",
        &c::WORKER_PROFILE,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn result_for(
    v: &Value,
    origin: &Value,
    h: &Value,
    epoch: u64,
    schema: &str,
    slot: u64,
    accounts_hash: &str,
    snapshot_sha: &str,
    snapshot: &str,
    worker: &c::WorkerProfile,
) -> Result<u64> {
    ensure!(
        v["schema"] == schema
            && v["epoch"] == epoch
            && v["worker"] == json!({"path":worker.path,"sha256":worker.sha256})
            && v["bootstrap_sha256"] == snapshot_sha
            && v["genesis_sha256"]
                == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"
            && v["bootstrap_slot"] == slot
            && v["accounts_hash"] == accounts_hash
            && v["full_accounts_commitment_verified"] == true
            && v["worker_shutdown_acknowledged"] == true
            && v["worker_reaped"] == true
            && v["native_terminal_and_guard_history_acceptance_required"] == true
            && v["first_guard"]["startup_plan"] == h["startup_plan"]
            && v["first_guard"]["token"] == h["first_guard_token"]
            && v["first_guard"]["invocation_id"] == origin["invocation_id"]
            && v["first_guard"]["main_pid"] == origin["main_pid"],
        "265 native result identity differs"
    );
    for k in [
        "entry_replay",
        "snapshot_export",
        "downloads",
        "admission_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "full_epoch_qualified",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[k] == false, "265 result grants authority {k}");
    }
    let handshake = &v["handshake"];
    ensure!(
        handshake["protocol_version"] == 5
            && handshake["backend_id"] == worker.backend
            && handshake["qualification"] == "Candidate"
            && handshake["solana_commit"] == worker.solana_commit
            && handshake["required_genesis_hash"] == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        "265 handshake differs"
    );
    let initial = &v["initialized"];
    let checkpoint = &v["checkpoint"];
    let bytes = |v: &Value| -> Result<Vec<u8>> {
        let b: Vec<u8> = serde_json::from_value(v.clone())?;
        ensure!(b.len() == 32, "265 commitment width");
        Ok(b)
    };
    let source = &initial["source"]["SnapshotArchive"];
    ensure!(
        initial["slot"] == slot
            && initial["genesis_hash"] == handshake["required_genesis_hash"]
            && c::num(initial, "ticks_per_slot")? > 0
            && source["archive_path"] == snapshot
            && bs58::encode(bytes(&source["expected_accounts_hash"])?).into_string()
                == accounts_hash
            && checkpoint["slot"] == initial["slot"]
            && checkpoint["slot_complete"] == true
            && checkpoint["writes"] == json!([])
            && checkpoint["next_write_version"] == initial["next_write_version"]
            && bs58::encode(bytes(&checkpoint["accounts_hash"])?).into_string() == accounts_hash,
        "265 canonical checkpoint differs"
    );
    bytes(&initial["last_blockhash"])?;
    bytes(&checkpoint["last_blockhash"])?;
    bytes(&checkpoint["bank_hash"])?;
    for k in [
        "next_write_version",
        "capitalization",
        "transaction_count",
        "tick_height",
    ] {
        c::num(checkpoint, k)?;
    }
    let worker = c::num(v, "worker_pid")?;
    ensure!(
        worker > 1 && worker <= i32::MAX as u64 && v["worker_pid"] != origin["main_pid"],
        "265 worker PID differs"
    );
    Ok(worker)
}
pub(super) fn validate(
    bundle: &Value,
    h: &Value,
    origin: &Value,
    terminal_us: u64,
    worker: u64,
    reader: &impl c::EvidenceReader,
) -> Result<()> {
    ensure!(
        bundle["schema"] == "horizon-native265-complete-guard-history-v1"
            && bundle["guard_plan"] == h["guard_plan"]
            && bundle["producer_invocation_id"] == origin["invocation_id"]
            && bundle["boot_id"] == origin["boot_id"],
        "265 guard history binding"
    );
    let gb = c::binding(&h["guard_plan"])?;
    let gp = reader.json(&gb, true)?;
    let raw = reader.bytes(&c::binding(&bundle["pid1_journal"])?, 16 << 20)?;
    let rows = serde_json::Deserializer::from_slice(&raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut starts = BTreeMap::new();
    let mut ends = BTreeMap::new();
    let mut prior = 0;
    let issued = c::num(
        &reader.json(&c::binding(&h["startup_plan"])?, true)?,
        "issued_monotonic_us",
    )?;
    for r in rows {
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == c::GUARD_UNIT
                && r["_BOOT_ID"] == c::text(origin, "boot_id")?.replace('-', ""),
            "265 foreign guard history row"
        );
        let iid = c::text(&r, "INVOCATION_ID")?;
        let mono = c::text(&r, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            c::hex(iid, 32) && mono >= issued && mono >= prior,
            "265 guard history clock"
        );
        prior = mono;
        let msg = c::text(&r, "MESSAGE")?;
        ensure!(
            !msg.contains("Failed")
                && !msg.contains("Main process exited")
                && !msg.contains("timed out"),
            "265 guard history failure"
        );
        if msg.starts_with(&format!("Starting {} -", c::GUARD_UNIT)) {
            ensure!(
                starts.insert(iid.to_owned(), mono).is_none(),
                "265 duplicate guard start"
            );
        }
        if msg == format!("{}: Deactivated successfully.", c::GUARD_UNIT) {
            ensure!(
                ends.insert(iid.to_owned(), mono).is_none(),
                "265 duplicate guard finish"
            );
        }
    }
    ensure!(
        !starts.is_empty()
            && starts.len() == ends.len()
            && starts.iter().all(|(iid, start)| ends.get(iid).is_some_and(
                |end| end > start && end - start <= native265_protection::MAX_FIRING_MICROS
            )),
        "265 guard history incomplete"
    );
    let records = bundle["records"].as_array().context("265 guard records")?;
    let mut seen = BTreeSet::new();
    let mut terminal_seen = false;
    let mut sample_times = Vec::new();
    for b in records {
        let record = reader.json(&c::binding(b)?, true)?;
        let gid = c::text(&record, "guard_invocation_id")?;
        ensure!(
            seen.insert(gid.to_owned())
                && ends.contains_key(gid)
                && record["plan_sha256"] == gb.sha256
                && record["guard_sha256"] == c::GUARD_SHA
                && record["producer_invocation_id"] == origin["invocation_id"],
            "265 guard record substituted"
        );
        let wall = c::num(&record, "recorded_unix_seconds")?;
        if record["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1" {
            native265_guard::sample_valid(
                &gp,
                &record,
                &h["guard_plan"],
                c::text(origin, "invocation_id")?,
                c::num(origin, "main_pid")?.try_into()?,
                wall,
                0,
            )?;
            sample_times.push(starts[gid]);
        } else {
            ensure!(
                record["schema"] == "horizon265-native-guard-terminal-v1"
                    && record["prior_stop_intent"].is_null()
                    && record["drain_error"].is_null()
                    && record["drain"]["original_processes_gone"] == true
                    && matches!(
                        record["drain"]["kernel_cgroup"].as_str(),
                        Some("absent" | "empty")
                    )
                    && record["terminal"]["pid"] == 0
                    && record["terminal"]["control_pid"] == 0
                    && record["terminal"]["invocation_id"] == origin["invocation_id"]
                    && record["terminal"]["active"] == "inactive"
                    && record["terminal"]["result"] == "success"
                    && starts[gid] >= terminal_us,
                "265 terminal drain history differs"
            );
            let pins = record["drain"]["retained_process_pins"]
                .as_array()
                .context("265 terminal process pins")?;
            ensure!(
                pins.len() == 2
                    && pins.iter().any(|p| p["pid"] == worker
                        && p["parent_pid"] == origin["main_pid"]
                        && p["executable"] == c::WORKER
                        && p["sha256"] == c::WORKER_SHA
                        && p["boot_id"] == origin["boot_id"])
                    && pins.iter().any(|p| p["pid"] == origin["main_pid"]
                        && p["executable"] == c::TEST
                        && p["sha256"] == c::TEST_SHA
                        && p["start_ticks"] == gp["main_start_ticks"]),
                "265 terminal process lineage missing"
            );
            terminal_seen = true;
        }
    }
    sample_times.sort_unstable();
    ensure!(
        seen.len() == ends.len()
            && terminal_seen
            && !sample_times.is_empty()
            && sample_times[0] - issued <= 60_000_000
            && sample_times.windows(2).all(|w| w[1] - w[0] <= 120_000_000)
            && terminal_us.saturating_sub(*sample_times.last().unwrap()) <= 120_000_000,
        "265 guard coverage absent or gapped"
    );
    Ok(())
}
fn root_pin(v: &Value, h: &Value, device: u64, inode: u64, mode: u32) -> Result<()> {
    ensure!(
        v["schema"] == "horizon265-native-guard-root-pin-v1"
            && v["plan_sha256"] == h["guard_plan"]["sha256"]
            && v["producer_invocation_id"] == h["invocation_id"]
            && v["device"] == device
            && v["inode"] == inode
            && v["mode"] == mode
            && v["uid"] == 1000
            && v["gid"] == 1000,
        "265 retained root pin differs"
    );
    Ok(())
}
/// Capture must account for every producer-specific guard artifact, including trips.
pub(super) fn complete_directory(bundle: &Value, h: &Value) -> Result<()> {
    let gp = c::sealed(&c::binding(&h["guard_plan"])?)?;
    let dir = Path::new(c::text(&gp, "receipt_directory")?);
    ensure!(
        dir == Path::new("/var/lib/jetstreamer").join(format!(
            "horizon-native265-guard-receipts-{}",
            c::text(h, "invocation_id")?
        )) && dir.canonicalize()? == dir,
        "265 receipt directory differs"
    );
    let expected = bundle["records"]
        .as_array()
        .context("265 record list")?
        .iter()
        .map(c::binding)
        .collect::<Result<Vec<_>>>()?;
    let mut actual = BTreeSet::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name();
        let name = name.to_str().context("265 guard filename")?;
        if name == "root-pin.json" {
            let path = e.path();
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                path.canonicalize()? == path
                    && metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.nlink() == 1
                    && metadata.mode() & 0o077 == 0,
                "265 root pin custody differs"
            );
            let pin: Value =
                serde_json::from_slice(&read_stable_bounded(&path, 65536, "265 root pin")?)?;
            let root = fs::symlink_metadata(c::ROOT)?;
            ensure!(
                Path::new(c::ROOT).canonicalize()? == Path::new(c::ROOT)
                    && root.is_dir()
                    && root.uid() == 1000
                    && root.gid() == 1000
                    && root.mode() & 0o777 == 0o700,
                "265 retained root custody differs"
            );
            root_pin(&pin, h, root.dev(), root.ino(), root.mode())?;
            continue;
        }
        if matches!(name, "guard.lock" | "main-pin.json" | "worker-pin.json") {
            continue;
        }
        ensure!(
            name.starts_with("sample-") || name.starts_with("terminal-"),
            "265 trip/transition/unknown guard artifact"
        );
        let bytes = read_stable_bounded(&e.path(), 16 << 20, "265 actual guard record")?;
        actual.insert(hex_lower(&Sha256::digest(&bytes)));
    }
    let hashes = expected
        .iter()
        .map(|b| b.sha256.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        actual == hashes && hashes.len() == expected.len(),
        "265 incomplete guard capture"
    );
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    struct Reader {
        values: BTreeMap<PathBuf, Value>,
        journal: Vec<u8>,
    }
    impl c::EvidenceReader for Reader {
        fn json(&self, b: &BoundFile, _immutable: bool) -> Result<Value> {
            self.values
                .get(&b.path)
                .cloned()
                .context("fixture document")
        }
        fn bytes(&self, _b: &BoundFile, _maximum: u64) -> Result<Vec<u8>> {
            Ok(self.journal.clone())
        }
        fn canonical(&self, p: &Path) -> Result<PathBuf> {
            Ok(p.into())
        }
    }
    fn binding(name: &str) -> Value {
        json!({"path":format!("/var/lib/jetstreamer/test/{name}"),"sha256":"9".repeat(64)})
    }
    fn history() -> (Value, Value, Value, Reader) {
        let (p, _t, gp, g, _j) = native265_guard::fixture();
        let origin = json!({"boot_id":"boot","invocation_id":"a".repeat(32),"main_pid":42});
        let gb = json!({"path":"/guardplan","sha256":"9".repeat(64)});
        let h = json!({"startup_plan":binding("startup"),"guard_plan":gb});
        let terminal = json!({"schema":"horizon265-native-guard-terminal-v1","guard_invocation_id":"c".repeat(32),
            "producer_invocation_id":origin["invocation_id"],"plan_sha256":"9".repeat(64),"guard_sha256":c::GUARD_SHA,
            "recorded_unix_seconds":1001,"prior_stop_intent":null,"drain_error":null,
            "terminal":{"pid":0,"control_pid":0,"invocation_id":origin["invocation_id"],"active":"inactive","result":"success"},
            "drain":{"original_processes_gone":true,"kernel_cgroup":"absent","retained_process_pins":[
                {"pid":42,"executable":c::TEST,"sha256":c::TEST_SHA,"start_ticks":5},
                {"pid":43,"parent_pid":42,"executable":c::WORKER,"sha256":c::WORKER_SHA,"boot_id":"boot"}]}});
        let bundle = json!({"schema":"horizon-native265-complete-guard-history-v1","guard_plan":gb,"producer_invocation_id":origin["invocation_id"],"boot_id":"boot","pid1_journal":binding("journal"),"records":[binding("sample"),binding("terminal")]});
        let rows=[("b",110,true),("b",150,false),("c",300,true),("c",310,false)].into_iter().map(|(id,time,start)|json!({"_PID":"1","_UID":"0","UNIT":c::GUARD_UNIT,"_BOOT_ID":"boot","INVOCATION_ID":id.repeat(32),"__MONOTONIC_TIMESTAMP":time.to_string(),"MESSAGE":if start{format!("Starting {} - guard",c::GUARD_UNIT)}else{format!("{}: Deactivated successfully.",c::GUARD_UNIT)}})).collect::<Vec<_>>();
        let journal = rows
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        let mut values = BTreeMap::new();
        for (name, v) in [("startup", p), ("sample", g), ("terminal", terminal)] {
            values.insert(
                PathBuf::from(format!("/var/lib/jetstreamer/test/{name}")),
                v,
            );
        }
        values.insert(PathBuf::from("/guardplan"), gp);
        (bundle, h, origin, Reader { values, journal })
    }
    #[test]
    fn complete_history_requires_every_successful_firing_and_exact_reaped_worker() {
        let (bundle, h, origin, mut reader) = history();
        validate(&bundle, &h, &origin, 250, 43, &reader).unwrap();
        assert!(validate(&bundle, &h, &origin, 250, 44, &reader).is_err());
        let mut omitted = bundle.clone();
        omitted["records"].as_array_mut().unwrap().pop();
        assert!(validate(&omitted, &h, &origin, 250, 43, &reader).is_err());
        let sample = PathBuf::from("/var/lib/jetstreamer/test/sample");
        reader.values.get_mut(&sample).unwrap()["trip_reason"] = json!("filesystem-floor");
        assert!(validate(&bundle, &h, &origin, 250, 43, &reader).is_err());
    }
    #[test]
    fn terminal_history_refuses_manager_failure_and_missing_worker_lineage() {
        let (bundle, h, origin, mut reader) = history();
        let old = reader.journal.clone();
        reader.journal = String::from_utf8(old.clone())
            .unwrap()
            .replace("Deactivated successfully.", "Failed guard.")
            .into_bytes();
        assert!(validate(&bundle, &h, &origin, 250, 43, &reader).is_err());
        reader.journal = old;
        reader
            .values
            .get_mut(Path::new("/var/lib/jetstreamer/test/terminal"))
            .unwrap()["drain"]["retained_process_pins"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(validate(&bundle, &h, &origin, 250, 43, &reader).is_err());
    }
    pub(in crate::fleet) fn result_fixture() -> (Value, Value, Value) {
        let origin = json!({"invocation_id":"a".repeat(32),"main_pid":42});
        let h = json!({"startup_plan":binding("startup"),"first_guard_token":binding("token")});
        let hash = bs58::decode(c::ACCOUNTS_HASH).into_vec().unwrap();
        let v = json!({"schema":"horizon265-exact-worker-cold-input-result-v1","epoch":265,"worker":{"path":c::WORKER,"sha256":c::WORKER_SHA},"bootstrap_sha256":c::SNAPSHOT_SHA,
            "genesis_sha256":"133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945","bootstrap_slot":114479281,"accounts_hash":c::ACCOUNTS_HASH,"full_accounts_commitment_verified":true,"worker_shutdown_acknowledged":true,"worker_reaped":true,"native_terminal_and_guard_history_acceptance_required":true,
            "first_guard":{"startup_plan":h["startup_plan"],"token":h["first_guard_token"],"invocation_id":origin["invocation_id"],"main_pid":42},
            "handshake":{"protocol_version":5,"backend_id":"solana-v1.7.15","qualification":"Candidate","solana_commit":"4892eb4e1ad278d5249b6cda8983f88effb3e98b","required_genesis_hash":"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"},
            "initialized":{"slot":114479281,"genesis_hash":"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d","ticks_per_slot":64,"last_blockhash":vec![0;32],"next_write_version":5,"source":{"SnapshotArchive":{"archive_path":"/var/lib/jetstreamer/horizon-contiguous-265-265-current-46b4b4a-v1/snapshot-114479281-Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW.tar.zst","expected_accounts_hash":hash}}},
            "checkpoint":{"slot":114479281,"slot_complete":true,"writes":[],"next_write_version":5,"accounts_hash":hash,"last_blockhash":vec![0;32],"bank_hash":vec![0;32],"capitalization":1,"transaction_count":2,"tick_height":3},"worker_pid":43,
            "entry_replay":false,"snapshot_export":false,"downloads":false,"admission_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"full_epoch_qualified":false,"remote_mutations":false,"r2_mutations":false});
        (v, origin, h)
    }
    #[test]
    fn standalone_result_binds_worker_commitments_and_gate_to_original_owner() {
        let (v, origin, h) = result_fixture();
        assert_eq!(result(&v, &origin, &h).unwrap(), 43);
        for (pointer, bad) in [
            ("/worker_reaped", json!(false)),
            ("/worker/sha256", json!(c::TEST_SHA)),
            ("/first_guard/main_pid", json!(43)),
            ("/checkpoint/next_write_version", json!(6)),
            ("/checkpoint/writes", json!([{}])),
            ("/worker_pid", json!(42)),
            ("/publication_authorized", json!(true)),
        ] {
            let mut changed = v.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(result(&changed, &origin, &h).is_err(), "{pointer}");
        }
    }
    #[test]
    fn terminal_complete_history_uses_same_sixty_second_bound() {
        let (bundle, h, origin, mut reader) = history();
        let mut rows = serde_json::Deserializer::from_slice(&reader.journal)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        rows[1]["__MONOTONIC_TIMESTAMP"] =
            json!((110 + native265_protection::MAX_FIRING_MICROS).to_string());
        rows[2]["__MONOTONIC_TIMESTAMP"] = json!("60000300");
        rows[3]["__MONOTONIC_TIMESTAMP"] = json!("60000310");
        let encode = |rows: &Vec<Value>| {
            rows.iter()
                .map(|r| serde_json::to_string(r).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes()
        };
        reader.journal = encode(&rows);
        validate(&bundle, &h, &origin, 60_000_250, 43, &reader).unwrap();
        rows[1]["__MONOTONIC_TIMESTAMP"] =
            json!((111 + native265_protection::MAX_FIRING_MICROS).to_string());
        reader.journal = encode(&rows);
        assert!(validate(&bundle, &h, &origin, 60_000_250, 43, &reader).is_err());
    }
    #[test]
    fn retained_root_pin_is_recognized_without_allowing_replaced_scratch() {
        let fixture: Value =
            serde_json::from_str(include_str!("fixtures/native265-terminal-20261119.json"))
                .unwrap();
        let pin = &fixture["data"]["root-pin.json"];
        let h = json!({"invocation_id":pin["producer_invocation_id"],"guard_plan":{"sha256":pin["plan_sha256"]}});
        root_pin(pin, &h, 66305, 95092619, 16832).unwrap();
        assert!(root_pin(pin, &h, 66305, 95092620, 16832).is_err());
        for key in [
            "plan_sha256",
            "producer_invocation_id",
            "uid",
            "gid",
            "mode",
        ] {
            let mut bad = pin.clone();
            bad[key] = Value::Null;
            assert!(root_pin(&bad, &h, 66305, 95092619, 16832).is_err(), "{key}");
        }
    }
}
