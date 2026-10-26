//! Typed completed singleton207 provenance. Natural replay success is not a
//! Full/plugin/upload qualification and never creates a sidecar here.
use super::*;

pub(in crate::fleet) fn manifest_binding() -> BoundFile {
    binding(MANIFEST, MANIFEST_SHA)
}
pub(in crate::fleet) fn claim(b: &BoundFile) -> Result<(DiagnosticClaim, Value)> {
    let l = native209::immutable_json(b)?;
    let iid = l["evidence"]["units"][0]["invocation_id"]
        .as_str()
        .context("207 completed source IID absent")?;
    let c = DiagnosticClaim {
        epoch: 207,
        unit: UNIT.into(),
        invocation_id: iid.into(),
        scratch_path: ROOT.into(),
        launch_receipt: b.clone(),
    };
    bindings(&c, &l)?;
    Ok((c, l))
}
pub(in crate::fleet) fn producer_shape(
    l: &Value,
    native: &Value,
    cohort: &Value,
    manifest: &Value,
    native_binding: &BoundFile,
) -> Result<Value> {
    ensure!(
        l["schema"] == SCHEMA
            && l["epoch"] == 207
            && l["node_sha256"] == NODE_SHA
            && l["worker_sha256"] == WORKER_SHA
            && l["manifest_fingerprint"] == FINGERPRINT
            && l["native_input"] == private157::binding(native_binding)
            && *native_binding == binding(NATIVE, NATIVE_SHA)
            && native["schema"] == native207_terminal::SCHEMA
            && native["epoch"] == 207
            && native["native_input_qualified"] == true
            && manifest["manifest_fingerprint"] == FINGERPRINT
            && cohort["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && cohort["epochs"] == json!([207])
            && cohort["manifest_fingerprint"] == FINGERPRINT
            && cohort["root_checkpoint_gate"]["kind"] == "sealed-root-checkpoint-cohort"
            && cohort["root_checkpoint_gate"]["version"] == 1
            && cohort["outcome"]["kind"] == "committed",
        "207 completed producer/native/cohort/manifest substituted another route"
    );
    Ok(
        json!({"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"manifest_sha256":MANIFEST_SHA,"manifest_fingerprint":FINGERPRINT}),
    )
}
pub(in crate::fleet) fn terminal_manager(u: &Value, iid: &str) -> Result<()> {
    ensure!(
        private_prefix::iid(iid)
            && u["Id"] == UNIT
            && u["LoadState"] == "loaded"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && (u["InvocationID"] == iid || u["InvocationID"] == "")
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0"
            && private_prefix::same_command(&u["ExecStart"], &command()),
        "207 completed producer is live, replaced, restarted, or unsuccessful"
    );
    Ok(())
}
pub(in crate::fleet) fn source_terminal(
    launch_binding: &BoundFile,
    proof_binding: &BoundFile,
) -> Result<Value> {
    let (_, l) = claim(launch_binding)?;
    let proof = native209::immutable_json(proof_binding)?;
    terminal::validate_saved(&proof, launch_binding, &l)?;
    let iid = l["evidence"]["units"][0]["invocation_id"]
        .as_str()
        .context("207 source IID absent")?;
    let before = unit(UNIT)?;
    terminal_manager(&before, iid)?;
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            UNIT,
            "_PID=1",
            "--output=json",
            "--no-pager",
            "--lines=256",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "207 complete manager history unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let events = singleton209_delivery::terminal_history_for(&rows, UNIT, iid)?;
    ensure!(
        before == unit(UNIT)?,
        "207 source manager changed during terminal proof"
    );
    Ok(
        json!({"schema":"jetstreamer-singleton207-delivery-terminal-snapshot-v1","invocation_id":iid,
        "terminal_proof":private157::binding(proof_binding),"manager":before,"events":events,
        "journal_rows":rows,"journal_sha256":hex_lower(&Sha256::digest(&out.stdout))}),
    )
}
pub(in crate::fleet) fn same_terminal(a: &Value, b: &Value) -> Result<()> {
    ensure!(
        a["schema"] == "jetstreamer-singleton207-delivery-terminal-snapshot-v1"
            && b["schema"] == a["schema"],
        "207 terminal comparison borrowed a foreign source"
    );
    for key in [
        "invocation_id",
        "terminal_proof",
        "manager",
        "events",
        "journal_rows",
    ] {
        ensure!(
            !a[key].is_null() && a[key] == b[key],
            "207 complete terminal source changed: {key}"
        );
    }
    Ok(())
}
pub(in crate::fleet) fn custody(
    launch: &BoundFile,
    native: &BoundFile,
    terminal: &BoundFile,
    publication: &BoundFile,
) -> Result<(Value, Value)> {
    let (_, l) = claim(launch)?;
    let n = native209::immutable_json(native)?;
    native207_terminal::validate(&n)?;
    let producer = producer_shape(
        &l,
        &n,
        &native209::immutable_json(publication)?,
        &native209::immutable_json(&manifest_binding())?,
        native,
    )?;
    let terminal = source_terminal(launch, terminal)?;
    capped204205_work::empty_terminal_cgroup(UNIT)?;
    inactive_status::no_pending_owner_trigger(UNIT, false)?;
    Ok((producer, terminal))
}

fn bytes32(s: &str) -> Result<Value> {
    let bytes = bs58::decode(s).into_vec()?;
    ensure!(bytes.len() == 32, "207 consensus hash length differs");
    Ok(serde_json::to_value(bytes)?)
}
pub(in crate::fleet) fn cohort(v: &Value, a: &LocalArchive) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let gate = &v["root_checkpoint_gate"];
    let checkpoints = gate["verified_manifest_checkpoints"]
        .as_array()
        .context("207 verified roots")?;
    let members = gate["members"]
        .as_array()
        .context("207 native terminal members")?;
    let published = v["outcome"]["members"]
        .as_array()
        .context("207 committed cohort members")?;
    for summary in [
        &gate["members"][0]["bootstrap"],
        &gate["members"][0]["terminal"],
    ] {
        for name in [
            "slot",
            "capitalization",
            "transaction_count",
            "tick_height",
            "write_count",
            "next_write_version",
        ] {
            ensure!(
                summary[name].as_u64().is_some(),
                "207 native checkpoint integer missing: {name}"
            );
        }
        for name in ["bank_hash", "accounts_hash", "last_blockhash"] {
            let _: [u8; 32] = serde_json::from_value(summary[name].clone())
                .context("207 incomplete native checkpoint hash")?;
        }
    }
    ensure!(
        v["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && v["manifest_fingerprint"] == FINGERPRINT
            && v["epochs"] == json!([207])
            && gate["kind"] == "sealed-root-checkpoint-cohort"
            && gate["version"] == 1
            && checkpoints.len() == 2
            && checkpoints[0]["slot"] == 89523820u64
            && checkpoints[0]["accounts_hash"]
                == bytes32("7NUvFRrgkc2pc9DPmD7vrrooZkEwc6r8KqUMq5MrG3ik")?
            && checkpoints[1]["slot"] == 89855469u64
            && checkpoints[1]["accounts_hash"]
                == bytes32("9i59TwLmzXvbomizFZNuXgPygtx8zJ3P4nWDQuNxrTxK")?
            && a.epoch == 207
            && members.len() == 1
            && members[0]["epoch"] == 207
            && members[0]["bootstrap"]["slot"] == 89423444u64
            && members[0]["bootstrap"]["accounts_hash"]
                == bytes32("3NVZVHDVwXgMxuTP77gaZF4UBP1oNBQzGScBGyoLx2Px")?
            && members[0]["bootstrap"]["slot_complete"] == true
            && members[0]["terminal"]["slot_complete"] == true
            && members[0]["terminal"]["slot"] == TERMINAL
            && v["outcome"]["kind"] == "committed"
            && published.len() == 1
            && published[0]["epoch"] == 207
            && published[0]["archive_sha256"] == a.sha256_hex
            && v["destination"]["path_base64"]
                == BASE64_STANDARD.encode(
                    a.archive_path
                        .parent()
                        .context("207 committed output parent")?
                        .as_os_str()
                        .as_bytes()
                )
            && published[0]["archive_path_base64"]
                == BASE64_STANDARD.encode(a.archive_path.as_os_str().as_bytes())
            && published[0]["checksum_path_base64"]
                == BASE64_STANDARD.encode(a.sidecar_path.as_os_str().as_bytes())
            && published[0]["committed_archive"]["device"] == a.identity.device
            && published[0]["committed_archive"]["inode"] == a.identity.inode
            && published[0]["committed_archive"]["length"] == a.length,
        "207 cohort receipt does not preserve canonical root, native terminal and exact committed archive"
    );
    let encoded = v["publication_context_base64"]
        .as_str()
        .context("207 bound cohort context")?;
    let raw = BASE64_STANDARD.decode(encoded)?;
    ensure!(
        raw.len() <= 4 << 20 && BASE64_STANDARD.encode(&raw) == encoded,
        "207 cohort context bounds/encoding"
    );
    let context: Value = serde_json::from_slice(&raw)?;
    let fingerprint: Vec<u8> = serde_json::from_value(context["manifest_fingerprint"].clone())?;
    ensure!(
        context["schema"] == "jetstreamer-root-checkpoint-gate-context-v1"
            && context["epochs"] == json!([207])
            && context["gate"] == *gate
            && format!("sha256:{}", hex_lower(&fingerprint)) == FINGERPRINT,
        "207 cohort context lost its exact root/manifest binding"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn singleton207_cohort_requires_both_roots_complete_tail_and_unchanged_archive() {
        let (a, v) = fixture();
        cohort(&v, &a).unwrap();
        for (pointer, bad) in [
            ("/epochs", json!([209])),
            ("/manifest_fingerprint", json!(singleton209::FINGERPRINT)),
            (
                "/root_checkpoint_gate/verified_manifest_checkpoints/1/slot",
                json!(89523820),
            ),
            (
                "/root_checkpoint_gate/verified_manifest_checkpoints/1/accounts_hash",
                json!(vec![0u8; 32]),
            ),
            (
                "/root_checkpoint_gate/members/0/terminal/slot",
                json!(89855469),
            ),
            (
                "/root_checkpoint_gate/members/0/terminal/slot",
                json!(89856000),
            ),
            (
                "/root_checkpoint_gate/members/0/terminal/slot_complete",
                json!(false),
            ),
            ("/outcome/members/0/archive_sha256", json!("b".repeat(64))),
            ("/outcome/members/0/committed_archive/inode", json!(99)),
        ] {
            let mut bad_v = v.clone();
            *bad_v.pointer_mut(pointer).unwrap() = bad;
            assert!(cohort(&bad_v, &a).is_err(), "{pointer}");
        }
    }
    #[test]
    fn source_terminal_cannot_be_live_failed_restarted_or_replaced() {
        let iid = "a".repeat(32);
        let u = json!({"Id":UNIT,"LoadState":"loaded","MainPID":"0","NRestarts":"0","InvocationID":iid,
            "ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainStatus":"0",
            "ExecStart":format!("{} ; ignore_errors=no }}",command())});
        terminal_manager(&u, &iid).unwrap();
        for (key, bad) in [
            ("InvocationID", json!("b".repeat(32))),
            ("MainPID", json!("42")),
            ("NRestarts", json!("1")),
            ("Result", json!("signal")),
            ("Id", json!(singleton209::UNIT)),
        ] {
            let mut changed = u.clone();
            changed[key] = bad;
            assert!(terminal_manager(&changed, &iid).is_err(), "{key}");
        }
        let snapshot = json!({"schema":"jetstreamer-singleton207-delivery-terminal-snapshot-v1","invocation_id":iid,"terminal_proof":{"path":"/sealed/terminal.json","sha256":"a".repeat(64)},"manager":u,"events":[],"journal_rows":[]});
        same_terminal(&snapshot, &snapshot).unwrap();
        let mut changed = snapshot.clone();
        changed["journal_rows"] = json!([{"replacement":true}]);
        assert!(same_terminal(&snapshot, &changed).is_err());
    }
    #[test]
    fn native_producer_pin_cannot_borrow_the_209_route() {
        let mut l = scope();
        l["schema"] = json!(SCHEMA);
        let n =
            json!({"schema":native207_terminal::SCHEMA,"epoch":207,"native_input_qualified":true});
        let (_, cohort) = fixture();
        let m = json!({"manifest_fingerprint":FINGERPRINT});
        let b = binding(NATIVE, NATIVE_SHA);
        let producer = producer_shape(&l, &n, &cohort, &m, &b).unwrap();
        assert_eq!(producer["manifest_sha256"], MANIFEST_SHA);
        for (key, bad) in [
            ("node_sha256", json!(singleton209::NODE_SHA)),
            ("worker_sha256", json!(singleton209::WORKER_SHA)),
            ("manifest_fingerprint", json!(singleton209::FINGERPRINT)),
            ("epoch", json!(209)),
        ] {
            let mut changed = l.clone();
            changed[key] = bad;
            assert!(
                producer_shape(&changed, &n, &cohort, &m, &b).is_err(),
                "{key}"
            );
        }
    }
    fn fixture() -> (LocalArchive, Value) {
        use std::os::unix::ffi::OsStrExt;
        let id = FileIdentity {
            device: 7,
            inode: 8,
            length: 100,
            modified_seconds: 9,
            modified_nanoseconds: 10,
        };
        let a = LocalArchive {
            epoch: 207,
            archive_path: Path::new(ROOT).join("output/epoch-207.jet"),
            sidecar_path: Path::new(ROOT).join("output/epoch-207.jet.sha256"),
            identity: id,
            sidecar_identity: FileIdentity {
                inode: 11,
                length: 80,
                ..id
            },
            length: 100,
            sha256_hex: "a".repeat(64),
            sidecar: Vec::new(),
        };
        let summary = |slot: u64, accounts: Value| json!({"slot":slot,"bank_hash":vec![0u8;32],"accounts_hash":accounts,"last_blockhash":vec![1u8;32],"capitalization":500584876715315613u64,"transaction_count":12,"tick_height":slot*64,"write_count":123,"next_write_version":123,"slot_complete":true});
        let gate = json!({"kind":"sealed-root-checkpoint-cohort","version":1,
            "verified_manifest_checkpoints":[{"slot":89523820u64,"accounts_hash":bytes32("7NUvFRrgkc2pc9DPmD7vrrooZkEwc6r8KqUMq5MrG3ik").unwrap()},{"slot":89855469u64,"accounts_hash":bytes32("9i59TwLmzXvbomizFZNuXgPygtx8zJ3P4nWDQuNxrTxK").unwrap()}],
            "members":[{"epoch":207,"bootstrap":summary(89423444,bytes32("3NVZVHDVwXgMxuTP77gaZF4UBP1oNBQzGScBGyoLx2Px").unwrap()),"terminal":summary(89855999,json!(vec![2u8;32]))}]});
        let hex = FINGERPRINT.strip_prefix("sha256:").unwrap();
        let fingerprint = (0..32)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let context = json!({"schema":"jetstreamer-root-checkpoint-gate-context-v1","manifest_fingerprint":fingerprint,"epochs":[207],"gate":gate});
        let receipt = json!({"schema":"jetstreamer-root-cohort-publication-receipt-v2","manifest_fingerprint":FINGERPRINT,"epochs":[207],"root_checkpoint_gate":gate,
            "publication_context_base64":BASE64_STANDARD.encode(serde_json::to_vec(&context).unwrap()),
            "destination":{"path_base64":BASE64_STANDARD.encode(a.archive_path.parent().unwrap().as_os_str().as_bytes())},
            "outcome":{"kind":"committed","members":[{"epoch":207,"archive_sha256":a.sha256_hex,
                "archive_path_base64":BASE64_STANDARD.encode(a.archive_path.as_os_str().as_bytes()),"checksum_path_base64":BASE64_STANDARD.encode(a.sidecar_path.as_os_str().as_bytes()),
                "committed_archive":{"device":id.device,"inode":id.inode,"length":id.length}}]}});
        (a, receipt)
    }
}
