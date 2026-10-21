//! Exact incident checkpoint qualification, separate from whole-cohort recovery.
//! This module creates no archives/manifests/checksums and grants no import authority.
use super::*;
use serde_json::{Value, json};

const PRIMARY: &str =
    "/var/lib/jetstreamer/horizon-220-prefix-primary-evidence-receipts-v1/evidence.json";
const PRIMARY_SHA: &str = "1c336e5e70aa9844de703db3eae14324f8d79eaed752844bb0e0e7fe26016004";
const PLAN: &str = "/var/lib/jetstreamer/horizon-prefix-recovery-and223-plans-1826-v1/preflight220-222-recovery-planning.json";
const PLAN_SHA: &str = "92ceef11e9ecb8ed6477c7282fdd48c7302904451be94376a25e88e309443d4d";
const FINGERPRINT: &str = "sha256:07c46b1acc5586bb368140323939a8c9b5ef7794b18107cd10592df74a6b0404";
const ROOTS: [u64; 3] = [95471337, 95903534, 96335538];

fn checkpoint(value: &Value) -> Result<cohort_publication::RootCheckpointSummary, String> {
    let fields = value["fields"]
        .as_object()
        .ok_or("checkpoint fields missing")?;
    if fields.len() != 10 || fields.get("complete").and_then(Value::as_str) != Some("true") {
        return Err("incomplete checkpoint tuple".into());
    }
    let number = |name: &str| -> Result<u64, String> {
        let text = fields
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing checkpoint {name}"))?;
        let n = text
            .parse::<u64>()
            .map_err(|e| format!("invalid checkpoint {name}: {e}"))?;
        if n.to_string() != text {
            return Err(format!("noncanonical checkpoint {name}"));
        }
        Ok(n)
    };
    let text = |name: &str| -> Result<String, String> {
        fields
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("missing checkpoint {name}"))
    };
    let summary = UnreceiptedCheckpointSummary {
        slot: number("slot")?,
        bank_hash: text("bank_hash")?,
        accounts_hash: text("accounts_hash")?,
        last_blockhash: text("last_blockhash")?,
        capitalization: number("capitalization")?,
        transaction_count: number("transactions")?,
        tick_height: number("tick_height")?,
        slot_complete: true,
        write_count: number("writes")?,
        next_write_version: number("next_write_version")?,
    };
    let expected_ticks = summary
        .slot
        .checked_add(1)
        .and_then(|n| n.checked_mul(64))
        .ok_or("tick-height overflow")?;
    if summary.tick_height != expected_ticks {
        return Err("checkpoint tick height disagrees with complete historical slot".into());
    }
    let evidence = UnreceiptedCheckpointEvidence {
        kind: "incident-observation".into(),
        epoch: None,
        journal_message: value["message"]
            .as_str()
            .ok_or("checkpoint journal message missing")?
            .into(),
        summary,
    };
    validate_checkpoint_journal_binding(&evidence)?;
    recovery_checkpoint_summary(&evidence.summary)
}

fn gate(
    extracted: &Value,
    plan: &RootCheckpointCohortPlan,
) -> Result<cohort_publication::RootCheckpointGateEvidence, String> {
    if plan.fingerprint != FINGERPRINT
        || plan.bootstrap.slot != 95039516
        || plan.root_checkpoints.len() != 3
        || extracted["failed_slot"] != 96540992u64
    {
        return Err("foreign failed-prefix scope".into());
    }
    let bootstrap = checkpoint(&extracted["bootstrap"])?;
    let expected_bootstrap: Hash = plan
        .bootstrap
        .accounts_hash
        .parse()
        .map_err(|e| format!("bootstrap hash: {e}"))?;
    if bootstrap.slot != plan.bootstrap.slot
        || bootstrap.accounts_hash != expected_bootstrap.to_bytes()
        || bootstrap.write_count != 0
    {
        return Err("bootstrap does not bind original trusted root".into());
    }
    let prefix = extracted["complete_prefix"]
        .as_array()
        .ok_or("prefix missing")?;
    if prefix.len() != 3 {
        return Err("only complete epochs220-222 are eligible".into());
    }
    let mut carried = bootstrap;
    let mut members = Vec::new();
    let mut verified = Vec::new();
    for (index, member) in prefix.iter().enumerate() {
        let epoch = 220 + index as u64;
        let root = checkpoint(&member["observed_root"])?;
        let terminal = checkpoint(&member["terminal"])?;
        let expected = &plan.root_checkpoints[index];
        let expected_hash: Hash = expected
            .accounts_hash
            .parse()
            .map_err(|e| format!("root hash: {e}"))?;
        if member["epoch"] != epoch
            || root.slot != ROOTS[index]
            || expected.slot != root.slot
            || root.accounts_hash != expected_hash.to_bytes()
            || terminal.slot != (epoch + 1) * 432000 - 1
            || root.slot <= carried.slot
            || root.slot >= terminal.slot
            || carried.transaction_count > root.transaction_count
            || root.transaction_count > terminal.transaction_count
            || carried.next_write_version > root.next_write_version
            || root.next_write_version > terminal.next_write_version
        {
            return Err(format!(
                "epoch{epoch} root/terminal scope or progression mismatch"
            ));
        }
        if member["manifest_root"]["slot"] != expected.slot
            || member["manifest_root"]["accounts_hash"] != expected.accounts_hash
        {
            return Err(format!("epoch{epoch} trusted manifest root differs"));
        }
        verified.push(cohort_publication::VerifiedManifestCheckpoint {
            slot: root.slot,
            accounts_hash: root.accounts_hash,
        });
        members.push(cohort_publication::RootCheckpointGateMember {
            epoch,
            bootstrap: carried,
            terminal,
        });
        carried = terminal;
    }
    Ok(cohort_publication::RootCheckpointGateEvidence {
        kind: cohort_publication::ROOT_CHECKPOINT_GATE_KIND.into(),
        version: cohort_publication::ROOT_CHECKPOINT_GATE_VERSION,
        verified_manifest_checkpoints: verified,
        members,
    })
}

pub(super) fn probe() -> Result<Value, String> {
    let (primary, primary_sha) = read_bound_recovery_file(Path::new(PRIMARY), 256 * 1024, true)?;
    if primary_sha != parse_lower_sha256(PRIMARY_SHA, "primary evidence SHA")? {
        return Err("primary evidence changed".into());
    }
    let (plan_bytes, plan_sha) = read_bound_recovery_file(Path::new(PLAN), 16 * 1024 * 1024, true)?;
    if plan_sha != parse_lower_sha256(PLAN_SHA, "planning report SHA")? {
        return Err("planning report changed".into());
    }
    let primary: Value = serde_json::from_slice(&primary).map_err(|e| e.to_string())?;
    if primary["schema"] != "jetstreamer-epoch220-complete-prefix-primary-evidence-v1"
        || primary["publication_authorized"] != false
        || primary["recovery_manifest_created"] != false
    {
        return Err("foreign primary evidence authority".into());
    }
    let selection = root_checkpoint_cohort_runtime(220, 222, true)?;
    let plan = root_checkpoint_cohort_plan_from_report(
        serde_json::from_slice(&plan_bytes).map_err(|e| e.to_string())?,
        FINGERPRINT,
        220,
        222,
        selection,
    )?;
    let candidate = gate(&primary["extracted"], &plan)?;
    Ok(
        json!({"schema":"horizon-failed-prefix220-checkpoint-probe-v1","epochs":[220,222],"primary_evidence_sha256":PRIMARY_SHA,"planning_report_sha256":PLAN_SHA,"manifest_fingerprint":FINGERPRINT,"checkpoint_candidate":candidate,"complete_archive_reread_proven":false,"archive_provenance_qualified":false,"independent_boundary_anchors_proven":false,"archive_mutations":false,"recovery_manifest_created":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}

const ARCHIVES: &str = "/home/ubuntu/.jetstreamer-private/adaptive-220-223-current-9d8e964-v1/lane-a/private/destination-5af206ff1dc2bf937d80da0ea255ab459f3b370f67b1c83ed238da29f1de146e/work/root-cohort-220-223/run-2161856-1791998246210466037/archives";
const READ_IIDS: [&str; 3] = [
    "1536bf6f640d4df280f8bedf86a55094",
    "d82f8375cc184e5283a1694c48009ac4",
    "4a699212c24b43b488c87165ac4ba326",
];
const BYTES: [u64; 3] = [135699623364, 137055363091, 133175903649];
const INODES: [u64; 3] = [2259411, 2259414, 2259426];
fn full_receipt(receipt: &Value, epoch: u64, path: &Path) -> Result<(), String> {
    let index = usize::try_from(epoch.checked_sub(220).ok_or("epoch below prefix")?)
        .map_err(|e| e.to_string())?;
    if index >= 3 {
        return Err("epoch above complete prefix".into());
    }
    if receipt["schema"] != "horizon-private-full-verification-v1"
        || receipt["status"] != "passed"
        || receipt["epoch"] != epoch
        || receipt["archive"]["path"].as_str() != path.to_str()
        || receipt["archive"]["bytes"] != BYTES[index]
        || receipt["archive"]["uid"] != 1000
        || receipt["archive"]["gid"] != 1000
        || receipt["archive"]["mode"] != "0440"
        || receipt["unit"]["invocation_id"] != READ_IIDS[index]
        || receipt["unit"]["name"]
            != format!("horizon-independent-full-read-{epoch}-retained-prefix-v1.service")
        || receipt["unit"]["result"] != "success"
        || receipt["unit"]["exec_main_status"] != 0
        || receipt["unit"]["restarts"] != 0
        || receipt["command"]["full"] != true
        || receipt["command"]["internal_full"] != true
        || receipt["command"]["threads"] != 8
        || receipt["verifier"]["sha256"]
            != "8a3c45b958bf69e6d8463d2e215cbd0ff30ec2c251c4d20ae40193a6cecae9f3"
        || receipt["collector_sha256"]
            != "ed56154c58f939b0f461dd4afc31e88986f994407d12681120e446bed236fecd"
        || receipt["publication_authorized"] != false
        || [
            "archive_mutations",
            "sidecar_created",
            "replay_launch_authorized",
            "remote_mutations",
            "r2_mutations",
        ]
        .iter()
        .any(|key| receipt[*key] != false)
    {
        return Err("private reread receipt does not bind exact original reader/archive".into());
    }
    Ok(())
}
/// Measure the preserved immutable content only after its independent reread.
/// This is a separate hash event, never an alias for a hash-bound full receipt.
pub(super) fn artifact_probe(epoch: u64) -> Result<Value, String> {
    use std::os::unix::fs::MetadataExt;
    let index = usize::try_from(epoch.checked_sub(220).ok_or("epoch below prefix")?)
        .map_err(|e| e.to_string())?;
    if index >= 3 {
        return Err("epoch above prefix".into());
    }
    let path = PathBuf::from(format!("{ARCHIVES}/epoch-{epoch}.jet"));
    let receipt_path = PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-retained220-222-full-results-v1/epoch-{epoch}.json"
    ));
    let (receipt_bytes, receipt_sha) = read_bound_recovery_file(&receipt_path, 1024 * 1024, true)?;
    full_receipt(
        &serde_json::from_slice(&receipt_bytes).map_err(|e| e.to_string())?,
        epoch,
        &path,
    )?;
    let file = jetstreamer_node::archive_checksum::open_regular_nofollow(&path)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    let initial_identity = jetstreamer_node::archive_checksum::archive_file_identity(&file)
        .map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.dev() != 66305
        || before.ino() != INODES[index]
        || before.len() != BYTES[index]
        || before.uid() != 1000
        || before.gid() != 1000
        || before.mode() & 0o777 != 0o440
        || before.nlink() != 1
    {
        return Err("original archive identity changed".into());
    }
    let reader = jetstreamer_horizon::archive::ArchiveReader::open(std::io::BufReader::new(
        file.try_clone().map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    if reader.header().epoch != epoch
        || reader.header().slot_start != epoch * 432000
        || reader.header().slot_count != 432000
    {
        return Err("archive coverage changed".into());
    }
    let provenance = reader
        .provenance()
        .map_err(|e| e.to_string())?
        .ok_or("missing provenance")?;
    let encoded = jetstreamer_horizon::archive::encode_archive_provenance(&provenance)
        .map_err(|e| e.to_string())?;
    let measured = jetstreamer_node::archive_checksum::measure_open_archive(&file)
        .map_err(|e| e.to_string())?;
    if measured.identity != initial_identity
        || !jetstreamer_node::archive_checksum::path_matches_archive_identity(
            &path,
            measured.identity,
        )
        .map_err(|e| e.to_string())?
        || before.dev() != file.metadata().map_err(|e| e.to_string())?.dev()
        || before.ino() != file.metadata().map_err(|e| e.to_string())?.ino()
    {
        return Err("archive changed while measuring".into());
    }
    let (again, again_sha) = read_bound_recovery_file(&receipt_path, 1024 * 1024, true)?;
    if receipt_sha != again_sha || receipt_bytes != again {
        return Err("private reread receipt changed".into());
    }
    let hex = jetstreamer_node::segment_manifest::sha256_hex_string;
    Ok(
        json!({"schema":"horizon-failed-prefix220-artifact-probe-v1","epoch":epoch,"archive":path,"device":before.dev(),"inode":before.ino(),"bytes":before.len(),"sha256":hex(&measured.sha256),"provenance_sha256":hex(&Sha256::digest(&encoded).into()),"provenance_encoded_base64":BASE64_STANDARD.encode(&encoded),"provenance_debug":format!("{provenance:?}"),"prior_internal_reread_receipt":receipt_path,"prior_internal_reread_receipt_sha256":hex(&receipt_sha),"hash_event_separate_from_internal_reread":true,"hash_bound_full_receipt_created":false,"archive_provenance_qualified":false,"archive_mutations":false,"sidecar_created":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observed(slot: u64) -> Value {
        let summary = UnreceiptedCheckpointSummary {
            slot,
            bank_hash: Hash::new_from_array([1; 32]).to_string(),
            accounts_hash: Hash::new_from_array([2; 32]).to_string(),
            last_blockhash: Hash::new_from_array([3; 32]).to_string(),
            capitalization: 100,
            transaction_count: 10,
            tick_height: (slot + 1) * 64,
            slot_complete: true,
            write_count: 0,
            next_write_version: 20,
        };
        json!({"fields":{"slot":slot.to_string(),"bank_hash":summary.bank_hash,"accounts_hash":summary.accounts_hash,"last_blockhash":summary.last_blockhash,"capitalization":"100","transactions":"10","tick_height":summary.tick_height.to_string(),"complete":"true","writes":"0","next_write_version":"20"},"message":format!("[fixture INFO jetstreamer_node::historical_replay] historical checkpoint slot={slot} bank_hash={} accounts_hash={} last_blockhash={} capitalization=100 transactions=10 tick_height={} complete=true writes=0 next_write_version=20",summary.bank_hash,summary.accounts_hash,summary.last_blockhash,summary.tick_height)})
    }
    #[test]
    fn complete_tuple_is_parsed_not_transcribed() {
        let value = observed(95039516);
        let c = checkpoint(&value).unwrap();
        assert_eq!(c.slot, 95039516);
        assert_eq!(c.last_blockhash, [3; 32]);
        assert_eq!(c.next_write_version, 20);
        for name in [
            "bank_hash",
            "last_blockhash",
            "next_write_version",
            "capitalization",
        ] {
            let mut wrong = value.clone();
            wrong["fields"][name] = json!("changed");
            assert!(checkpoint(&wrong).is_err(), "{name}");
        }
    }
    #[test]
    fn incomplete_noncanonical_and_nonmatching_journal_tuples_reject() {
        for (key, new) in [
            ("complete", json!("false")),
            ("slot", json!("095039516")),
            ("tick_height", json!("1")),
            ("extra", json!("unexpected")),
        ] {
            let mut wrong = observed(95039516);
            wrong["fields"][key] = new;
            assert!(checkpoint(&wrong).is_err());
        }
        let mut wrong = observed(95039516);
        wrong["message"] = json!("historical checkpoint incomplete");
        assert!(checkpoint(&wrong).is_err());
    }
    fn fixture() -> (Value, RootCheckpointCohortPlan) {
        let root = |slot| CohortManifestSnapshot {
            accounts_hash: Hash::new_from_array([2; 32]).to_string(),
            anchor_slot: slot,
            crc32c: String::new(),
            extension: String::new(),
            generation: 1,
            md5_hash: Value::Null,
            size: 1,
            slot,
            source: String::new(),
            uri: String::new(),
            versioned_uri: String::new(),
        };
        let plan = RootCheckpointCohortPlan {
            fingerprint: FINGERPRINT.into(),
            bootstrap: root(95039516),
            root_checkpoints: ROOTS.into_iter().map(root).collect(),
        };
        let prefix:Vec<_>=ROOTS.into_iter().enumerate().map(|(i,slot)|json!({"epoch":220+i as u64,"observed_root":observed(slot),"terminal":observed((221+i as u64)*432000-1),"manifest_root":{"slot":slot,"accounts_hash":Hash::new_from_array([2;32]).to_string()}})).collect();
        (
            json!({"bootstrap":observed(95039516),"complete_prefix":prefix,"failed_slot":96540992}),
            plan,
        )
    }
    #[test]
    fn only_three_complete_prefix_members_preserve_carried_tuples() {
        let (value, plan) = fixture();
        let g = gate(&value, &plan).unwrap();
        assert_eq!(g.members.len(), 3);
        assert_eq!(g.verified_manifest_checkpoints.len(), 3);
        assert_eq!(g.members[0].bootstrap.slot, 95039516);
        assert_eq!(g.members[2].terminal.slot, 96335999);
        for pair in g.members.windows(2) {
            assert_eq!(pair[0].terminal, pair[1].bootstrap);
        }
        for (pointer, new) in [
            ("/complete_prefix/1/epoch", json!(223)),
            (
                "/complete_prefix/2/manifest_root/accounts_hash",
                json!(Hash::new_from_array([9; 32]).to_string()),
            ),
            ("/failed_slot", json!(96540991)),
        ] {
            let mut wrong = value.clone();
            *wrong.pointer_mut(pointer).unwrap() = new;
            assert!(gate(&wrong, &plan).is_err(), "{pointer}");
        }
        let mut wrong = value;
        wrong["complete_prefix"].as_array_mut().unwrap().pop();
        assert!(gate(&wrong, &plan).is_err());
    }
    #[test]
    fn changed_trusted_plan_cannot_be_substituted() {
        let (value, mut plan) = fixture();
        plan.fingerprint = "another".into();
        assert!(gate(&value, &plan).is_err());
        plan.fingerprint = FINGERPRINT.into();
        plan.root_checkpoints[1].accounts_hash = Hash::new_from_array([9; 32]).to_string();
        assert!(gate(&value, &plan).is_err());
    }
    #[test]
    fn artifact_measurement_requires_the_exact_successful_private_reader() {
        let path = PathBuf::from(format!("{ARCHIVES}/epoch-220.jet"));
        let value = json!({"schema":"horizon-private-full-verification-v1","status":"passed","epoch":220,"archive":{"path":path,"bytes":BYTES[0],"uid":1000,"gid":1000,"mode":"0440"},"unit":{"invocation_id":READ_IIDS[0],"name":"horizon-independent-full-read-220-retained-prefix-v1.service","result":"success","exec_main_status":0,"restarts":0},"command":{"full":true,"internal_full":true,"threads":8},"verifier":{"sha256":"8a3c45b958bf69e6d8463d2e215cbd0ff30ec2c251c4d20ae40193a6cecae9f3"},"collector_sha256":"ed56154c58f939b0f461dd4afc31e88986f994407d12681120e446bed236fecd","publication_authorized":false,"archive_mutations":false,"sidecar_created":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
        full_receipt(&value, 220, &path).unwrap();
        for (key, new) in [
            ("/unit/invocation_id", json!(READ_IIDS[1])),
            ("/archive/bytes", json!(BYTES[0] - 1)),
            ("/epoch", json!(223)),
            ("/command/internal_full", json!(false)),
            ("/unit/restarts", json!(1)),
            ("/status", json!("failed")),
            ("/publication_authorized", json!(true)),
            ("/r2_mutations", json!(true)),
        ] {
            let mut wrong = value.clone();
            *wrong.pointer_mut(key).unwrap() = new;
            assert!(full_receipt(&wrong, 220, &path).is_err(), "{key}");
        }
        assert!(full_receipt(&value, 223, &path).is_err());
        assert!(full_receipt(&value, 219, &path).is_err());
        assert!(full_receipt(&value, 220, Path::new("/different.jet")).is_err());
    }
    #[test]
    #[ignore = "root-only exact incident evidence qualification; read-only"]
    fn actual_pinned_primary_and_replanned_manifest_bind_three_complete_epochs() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let result = probe().unwrap();
        assert_eq!(result["publication_authorized"], false);
        assert_eq!(
            result["checkpoint_candidate"]["members"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            result["checkpoint_candidate"]["members"][0]["bootstrap"]["slot"],
            95039516u64
        );
        assert_eq!(
            result["checkpoint_candidate"]["members"][2]["terminal"]["slot"],
            96335999u64
        );
        println!("{result}");
    }
}
