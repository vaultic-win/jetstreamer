use super::*;

#[derive(Deserialize)]
struct Retired {
    source: PathBuf,
    original_inode: u64,
    completion: Bound,
    custody: Bound,
}
#[derive(Deserialize)]
struct Receipts {
    files: BTreeMap<String, Bound>,
    retired: Vec<Retired>,
    local_segment: OriginalEvidence,
    tail_archive_sha256: String,
}
fn pins() -> Result<Receipts> {
    Ok(serde_json::from_str(include_str!("receipt-pins.json"))?)
}

pub(super) fn archive_custody() -> Result<Value> {
    let a = pins()?;
    for s in &a.retired {
        let c = bound(&s.completion)?;
        let z = bound(&s.custody)?;
        let op = &c["operation"];
        ensure!(
            c["status"] == "complete"
                && c["source_and_quarantine_absent"] == true
                && c["all_other_local_files_preserved"] == true
                && op["source"] == json!(s.source)
                && op["source_body_identity"]["inode"] == s.original_inode
                && op["custody"] == json!(s.custody)
                && z["remote_sha256_readback"] == true
                && z["owner_checked"] == true
                && z["local_source_revalidated"] == true
                && z["sha256"] == op["sha256"]
                && z["object_key"] == op["object_key"]
                && z["object_etag"] == op["object_etag"]
                && z["manifest"]["source"] == op["source"]
                && op["canonical_archive"] == false
                && op["remote_mutations"] == false,
            "retired partial custody or remaining recovery object differs"
        );
        absent(&s.source)?;
        absent(Path::new(
            op["quarantine"].as_str().context("quarantine path")?,
        ))?;
    }
    Ok(json!({"closed_partial_count":a.retired.len(),"segment_manifest":a.local_segment}))
}

pub(super) fn owner(q: &Profile) -> Result<Value> {
    let pins = pins()?;
    let ids = &pins.files;
    let v = original(&q.owner_receipt)?;
    let launch = bound(&q.owner_plan)?;
    if q.selection == "tail-1743245a-v3" {
        ensure!(
            json!(q.owner_plan) == json!(ids["tail_launch"])
                && q.owner_receipt.sha256 == ids["tail_terminal"].sha256
                && v["producer_launch"] == json!(q.owner_plan)
                && v["invocation_id"] == q.owner_invocation
                && v["unit"] == q.owner_unit
                && launch["producer_invocation_id"] == q.owner_invocation
                && v["primary_journal"] == json!(ids["tail_pid1"])
                && v["private_run_root"] == json!(q.attempt_root)
                && launch["private_run_root"] == json!(q.attempt_root)
                && v["archive_closed"] == true
                && v["result"] == "success"
                && v["exit_code"] == 0
                && v["publication_authorized"] == false
                && v["independent_tail_reread_passed"] == false
                && v["complete_epoch_span_covered"] == false,
            "tail producer or captured original authority changed"
        );
        let reread = bound(&ids["tail_independent_reread"])?;
        let admit = bound(&ids["tail_reader_admission"])?;
        let manifest = original(&pins.local_segment)?;
        ensure!(
            manifest == bound(&ids["tail_segment"])?
                && ids["tail_segment"].sha256 == pins.local_segment.sha256
                && admit["producer_terminal"] == json!(ids["tail_terminal"])
                && admit["reader_unit"] == "archive-223-tail-reread-1743245a-v3.service"
                && reread["validation"] == "pass"
                && reread["archive"] == v["archive"]
                && reread["archive_sha256"] == pins.tail_archive_sha256
                && v["archive_sha256"] == manifest["archive_sha256"]
                && manifest["archive_sha256"] == reread["archive_sha256"]
                && reread["manifest"] == json!(pins.local_segment.path)
                && reread["output_slot_count"] == 477
                && reread["terminal_slot"] == 96767999
                && reread["canonical_checksum_sidecar_absent"] == true
                && reread["archive_bytes"] == 144030696,
            "independent original tail reread"
        );
        absent(Path::new(
            reread["canonical_checksum_sidecar"]
                .as_str()
                .context("sidecar")?,
        ))?;
        let j = &ids["tail_pid1"];
        let raw = file_bytes(&j.path, &j.sha256, 0, None, true)?;
        let mut success = false;
        for row in raw.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
            let e: Value = serde_json::from_slice(row)?;
            success |= e["_PID"] == "1"
                && e["INVOCATION_ID"] == q.owner_invocation
                && e["UNIT"] == q.owner_unit
                && e["MESSAGE"] == format!("{}: Deactivated successfully.", q.owner_unit);
        }
        ensure!(success, "tail original manager success missing");
    } else {
        ensure!(
            q.selection == "singleton-223-postcount"
                && json!(q.owner_plan) == json!(ids["singleton_launch"])
                && q.owner_receipt.sha256 == ids["singleton_repair"].sha256
                && launch["unit"] == v["producer_unit"]
                && launch["invocation_id"] == v["producer_invocation_id"]
                && v["producer_invocation_id"] == q.owner_invocation
                && v["producer_unit"] == q.owner_unit
                && launch["producer"]["ExecStart"]
                    .as_str()
                    .context("original singleton command")?
                    .contains(q.attempt_root.to_str().context("original root")?)
                && v["producer_result"] == "exit-code"
                && v["exec_main_status"] == 1
                && v["automatic_restart"] == false
                && v["scratch_retirement_authorized"] == false,
            "singleton original unsuccessful producer"
        );
        let c = bound(&ids["singleton_retirement"])?;
        let a = bound(&ids["singleton_retirement_spec"])?;
        let proof = bound(&ids["singleton_prior_check"])?;
        ensure!(
            a["prior_check"] == json!(ids["singleton_prior_check"])
                && a["custody"] == json!(ids["singleton_custody"])
                && c["operation"]["custody"] == a["custody"]
                && c["operation"]["partial223_prior_check"] == a["prior_check"]
                && proof["original_source_hash_verified"] == true
                && c["operation"]["source"] == v["retained_partial"]
                && c["operation"]["source_body_identity"]["inode"] == 25840814
                && c["operation"]["artifact"] == "singleton-223",
            "singleton original source custody or separate retirement changed"
        );
        let j = &ids["singleton_journal"];
        let raw = file_bytes(&j.path, &j.sha256, 0, None, true)?;
        let mut native = false;
        for row in raw.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
            let e: Value = serde_json::from_slice(row)?;
            native |= e["_SYSTEMD_INVOCATION_ID"] == q.owner_invocation
                && e["_SYSTEMD_CGROUP"] == format!("/system.slice/{}", q.owner_unit);
        }
        ensure!(native, "original singleton journal IID");
    }
    Ok(
        json!({"receipt":q.owner_receipt,"unit":q.owner_unit,"invocation_id":q.owner_invocation,"original_exit_code":q.owner_child_return_code,"launch":q.owner_plan,"retired_archive_custody":archive_custody()?}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_registered_original_targets_preserve_d15_and_both_completed_holds() {
        let first = profile("tail-1743245a-v3").unwrap();
        let second = profile("singleton-223-postcount").unwrap();
        assert_eq!(first.target_identity.ino, 26091826);
        assert_eq!(second.target_identity.ino, 26091548);
        assert_eq!(first.preserved_identity, second.preserved_identity);
        assert_eq!(first.preserved_identity.ino, 2759758);
        assert_eq!(first.owner_invocation, "20dc145d1e8c41fdbc682046b6fe4289");
        assert_eq!(second.owner_invocation, "04ef9d97a36446d49b452d982cb0be46");
        assert_eq!(first.owner_child_return_code, 0);
        assert_eq!(second.owner_child_return_code, 1);
        let p = pins().unwrap();
        assert_eq!(
            p.retired
                .iter()
                .map(|s| s.original_inode)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([25840814, 2759928])
        );
        assert_eq!(
            (first.target_identity.blocks + second.target_identity.blocks) * 512,
            19419303936
        );
        for q in [&first, &second] {
            assert_eq!(q.protected_archives.len(), 7);
            assert!(
                q.protected_archives
                    .iter()
                    .any(|c| c.path == p.local_segment.path)
            );
            assert!(
                p.retired
                    .iter()
                    .all(|s| q.protected_archives.iter().all(|a| a.path != s.source))
            );
        }
    }
}
