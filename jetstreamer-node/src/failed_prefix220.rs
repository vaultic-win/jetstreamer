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
