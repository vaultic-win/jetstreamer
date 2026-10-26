//! Independent metadata derivation. No live NativeBarrier or producer result is
//! constructed, and the recovered file is never its own expectation source.
use super::*;
use jetstreamer_horizon::archive::{
    AccountsHashKind, ArchiveProvenance, ArchiveProvenanceV3, ArchiveProvenanceV4,
    BootstrapStateKind, RuntimeAdmission, RuntimeHandoffProvenance, RuntimeSegmentProvenance,
    RuntimeStateCheckpoint, StateCommitment, StateCommitmentKind, TransactionMetadataPolicy,
    WriteVersionNormalization, encode_archive_provenance,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    pub slot: u64,
    pub bank_hash: String,
    pub accounts_hash: String,
    pub last_blockhash: String,
    pub capitalization: u64,
    pub transaction_count: u64,
    pub tick_height: u64,
    pub slot_complete: bool,
    pub write_count: u64,
    pub next_write_version: u64,
}
impl Checkpoint {
    fn runtime(&self) -> Result<RuntimeStateCheckpoint> {
        Ok(RuntimeStateCheckpoint {
            slot: self.slot,
            bank_hash: self.bank_hash.parse()?,
            accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
            accounts_hash: self.accounts_hash.parse()?,
            last_blockhash: self.last_blockhash.parse()?,
            capitalization: self.capitalization,
            transaction_count: self.transaction_count,
            tick_height: self.tick_height,
            slot_complete: self.slot_complete,
            next_write_version: self.next_write_version,
        })
    }
    fn consensus(&self, other: &Self) -> bool {
        self.slot == other.slot
            && self.bank_hash == other.bank_hash
            && self.accounts_hash == other.accounts_hash
            && self.last_blockhash == other.last_blockhash
            && self.capitalization == other.capitalization
            && self.transaction_count == other.transaction_count
            && self.tick_height == other.tick_height
            && self.slot_complete
            && other.slot_complete
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Runtime {
    pub generation_profile: String,
    pub runtime_profile: String,
    pub runtime_admission: String,
    pub runtime_revision: String,
    pub runtime_toolchain: String,
    pub runtime_target: String,
    pub genesis_hash: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Versions {
    pub start: u64,
    pub end: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub schema_version: u64,
    pub epoch: u64,
    pub output_slot_start: u64,
    pub output_slot_count: u64,
    pub runtime: Runtime,
    pub worker_executable_sha256: String,
    pub archive_sha256: String,
    pub bootstrap_archive_sha256: Option<String>,
    pub bootstrap: Checkpoint,
    pub terminal: Checkpoint,
    pub emitted_raw_write_versions: Versions,
}
fn digest(raw: &str) -> Result<[u8; 32]> {
    ensure!(is_lower_hex(raw, 64), "205 lineage noncanonical SHA-256");
    let mut result = [0; 32];
    for (i, b) in result.iter_mut().enumerate() {
        *b = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)?;
    }
    Ok(result)
}
fn manifest_scope(m: &Manifest) -> Result<()> {
    ensure!(
        m.schema_version == 1
            && m.epoch == 205
            && m.worker_executable_sha256 == WORKER
            && m.runtime.runtime_profile == "solana-v1.6.16"
            && m.runtime.runtime_admission == "candidate"
            && m.runtime.runtime_revision == "86c26f843276581509c3434acc2efbf4202c44e0"
            && m.runtime.runtime_target == "x86_64-unknown-linux-gnu"
            && m.runtime.genesis_hash == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
            && m.bootstrap.slot_complete
            && m.terminal.slot_complete
            && m.emitted_raw_write_versions.start < m.emitted_raw_write_versions.end
            && m.emitted_raw_write_versions.end == m.terminal.next_write_version,
        "205 source manifest runtime/coverage/write bounds differ"
    );
    digest(&m.archive_sha256)?;
    Ok(())
}
pub(super) struct Expected {
    pub provenance: ArchiveProvenanceV4,
    pub digest: String,
    pub document: Value,
}
pub(super) fn derive(prefix: &Manifest, suffix: &Manifest, proof: &Value) -> Result<Expected> {
    manifest_scope(prefix)?;
    manifest_scope(suffix)?;
    ensure!(
        prefix.output_slot_start == 88_560_000
            && prefix.output_slot_count == 431_051
            && prefix.bootstrap.slot == 88_559_361
            && prefix.bootstrap.write_count == 0
            && prefix.bootstrap.accounts_hash == "83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA"
            && prefix.bootstrap_archive_sha256.is_none()
            && prefix.terminal.slot == 88_991_050
            && prefix.archive_sha256 == PREFIX_SHA
            && suffix.archive_sha256 == SUFFIX_SHA
            && suffix.output_slot_start == 88_991_051
            && suffix.output_slot_count == 949
            && suffix.terminal.slot == 88_991_999
            && suffix.bootstrap.slot == 88_991_050
            && suffix.bootstrap_archive_sha256.as_deref() == Some(SNAPSHOT)
            && suffix.bootstrap.write_count == 0
            && suffix.bootstrap.next_write_version == 85_166_343_051
            && prefix.terminal.consensus(&suffix.bootstrap)
            && prefix.runtime.runtime_toolchain == suffix.runtime.runtime_toolchain
            && prefix.runtime.generation_profile
                == "jetstreamer-node/0.7.0/old-faithful-to-horizon-v2@3de96e71010a8a2f5e629f666227b137483bff7b"
            && suffix.runtime.generation_profile
                == "jetstreamer-node/0.9.0/old-faithful-to-horizon-v2@6a327d89ef7ef7677f66d75bac99e9b0f7baf733",
        "205 source partition, checkpoint or exact generation differs"
    );
    ensure!(
        proof["schema"] == "jetstreamer-capped204205-private-suffix-v1"
            && proof["epoch"] == 205
            && proof["plan_sha256"] == OLD_PLAN
            && proof["producer_invocation_id"] == OLD_IID
            && proof["prefix_sha256"] == PREFIX_SHA
            && proof["worker_sha256"] == WORKER
            && proof["complete_prefix_reread"] == true
            && proof["actual_suffix_native_barrier_passed"] == true
            && proof["provenance_version"] == 4
            && proof["assembly_profile"]
                == "jetstreamer-node/0.9.0/old-faithful-to-horizon-v2@6a327d89ef7ef7677f66d75bac99e9b0f7baf733/epoch205-capped-checkpoint-continuation-v1",
        "205 saved suffix is not the exact genuine completed suffix"
    );
    deny(&proof["authority"])?;
    let native = &proof["native_checkpoint"];
    let initialized = suffix.bootstrap.runtime()?;
    ensure!(
        native["accounts_hash_kind"] == "legacy_accounts_hash"
            && native["slot"] == initialized.slot
            && native["bank_hash"] == initialized.bank_hash.to_string()
            && native["accounts_hash"] == initialized.accounts_hash.to_string()
            && native["last_blockhash"] == initialized.last_blockhash.to_string()
            && native["capitalization"] == initialized.capitalization
            && native["transaction_count"] == initialized.transaction_count
            && native["tick_height"] == initialized.tick_height
            && native["slot_complete"] == true
            && native["next_write_version"] == initialized.next_write_version
            && native["initialized_next_write_version"] == initialized.next_write_version
            && native["bootstrap_write_count"] == 0
            && native["initialized_ticks_per_slot"] == 64
            && native["worker_sha256"] == WORKER,
        "205 saved native consensus/kind/cursor/writes/ticks differ"
    );
    let mut next = 0u64;
    let mut segments = Vec::new();
    for m in [prefix, suffix] {
        let map = WriteVersionNormalization {
            worker_start: m.emitted_raw_write_versions.start,
            worker_end_exclusive: m.emitted_raw_write_versions.end,
            archive_start: next,
        };
        next = map
            .archive_end_exclusive()
            .context("205 normalization overflow")?;
        segments.push(RuntimeSegmentProvenance {
            slot_start: m.output_slot_start,
            slot_count: m.output_slot_count,
            generation_profile: m.runtime.generation_profile.clone(),
            runtime_profile: m.runtime.runtime_profile.clone(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: m.runtime.runtime_revision.clone(),
            runtime_toolchain: m.runtime.runtime_toolchain.clone(),
            worker_executable_sha256: Some(digest(WORKER)?),
            write_versions: map,
        });
    }
    let provenance = ArchiveProvenanceV4 {
        base: ArchiveProvenanceV3 {
            assembly_profile: GENERATION.into(),
            genesis_hash: prefix.runtime.genesis_hash.parse()?,
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_state: StateCommitment {
                slot: prefix.bootstrap.slot,
                kind: StateCommitmentKind::LegacyAccountsHash,
                hash: prefix.bootstrap.accounts_hash.parse()?,
            },
            requested_slot_start: 88_560_000,
            requested_slot_count: 432_000,
            transaction_metadata: TransactionMetadataPolicy::observed(),
            runtime_segments: segments,
            handoffs: vec![RuntimeHandoffProvenance {
                boundary_slot: 88_991_051,
                predecessor: prefix.terminal.runtime()?,
                successor: initialized,
                successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                successor_bootstrap_archive_sha256: digest(SNAPSHOT)?,
                successor_bootstrap_write_count: 0,
            }],
        },
    };
    provenance.validate()?;
    let encoded = encode_archive_provenance(&ArchiveProvenance::V4(provenance.clone()))?;
    let hash = hex_lower(&Sha256::digest(&encoded));
    let document = json!({"epoch":205,"slot_start":88560000,"slot_count":432000,"terminal_slot":88991999,
        "source_archives":2,"prefix_sha256":PREFIX_SHA,"suffix_sha256":SUFFIX_SHA,
        "expected_provenance_sha256":hash,"expected_encoded_bytes":encoded.len(),"assembly_profile":GENERATION,
        "prefix_raw_write_versions":prefix.emitted_raw_write_versions,"suffix_raw_write_versions":suffix.emitted_raw_write_versions,
        "terminal_blockhash":suffix.terminal.last_blockhash,"native_checkpoint":native,"metadata":"observed","logical_write_versions":next});
    Ok(Expected {
        provenance,
        digest: hash,
        document,
    })
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Recipe {
    pub producer_plan: BoundFile,
    pub launch: BoundFile,
    pub terminal: BoundFile,
    pub continuation_result: BoundFile,
    pub prefix_manifest: BoundFile,
    pub suffix_proof: BoundFile,
    pub frame: BoundFile,
}
pub(super) struct Loaded {
    pub expected: Expected,
    pub continuation_result: Value,
    pub terminal: Value,
    pub epoch_started_unix_millis: u64,
}
fn result_scope(
    result: &Value,
    p: &Value,
    l: &Value,
    proof: &Value,
    expected: &Expected,
) -> Result<()> {
    ensure!(
        result["schema"] == "jetstreamer-capped204205-private-continuation-v1"
            && result["epoch"] == 205
            && result["plan_sha256"] == OLD_PLAN
            && result["producer_invocation_id"] == IID
            && result["guard_invocation_id"] == GUARD_IID
            && result["admission_sha256"] == l["admission"]["sha256"]
            && result["source_capture"] == p["source_capture"]
            && result["prefix_archive"] == p["prefix_archive"]
            && result["suffix_manifest"] == proof["suffix_manifest"]
            && result["native_checkpoint"] == proof["native_checkpoint"]
            && result["private_output"] == OUTPUT
            && result["assembly_profile"] == GENERATION
            && result["provenance_version"] == 4
            && result["source_archives"] == 2
            && result["slots_merged"] == 432000
            && result["account_updates_rebased"] == expected.document["logical_write_versions"]
            && result["independent_final_archive_verification_passed"] == false
            && result["current_plugin_verification_passed"] == false
            && result["independent_adjacent_boundary_receipts_still_required"] == true
            && result.get("archive_sha256").is_none()
            && result.get("archive_bytes").is_none(),
        "205 continuation result lost exact lineage or invented final digest/verification"
    );
    deny(&result["authority"])
}
pub(super) fn load_recipe(r: &Recipe) -> Result<Loaded> {
    ensure!(
        r.producer_plan.sha256 == OLD_PLAN
            && r.launch.sha256
                == "31a6fb1f8fbf3264b7cbc2ff72e14af8402bbf3f9df782ea311282d669c0bad1"
            && r.terminal.sha256
                == "39cb0f1630a6fa72240f7522f6d9eeddd7770739de4ecbd897c67ff470e433f5"
            && r.continuation_result.sha256
                == "7e046bf03219cfc7008d99d79ed1444e1bd70aaab9f5340b9c6302b1b6396e20"
            && r.prefix_manifest.sha256
                == "072f491c13dc7082d4715ac515dcb8203449e0d42b9e86a11ee198eb9d03cd85"
            && r.frame.sha256 == "30d31153cf64e498f89a20337f7410892c7d3cef0a2092d4079b4836e84b7bd8"
            && r.suffix_proof.sha256
                == "766882c798f56299f1202d6723954707d3477e69e15fda57a4787cd323576c42",
        "205 recipe differs from actual successful continuation inputs"
    );
    let p = read(&r.producer_plan)?;
    let l = read(&r.launch)?;
    let terminal =
        capped204205_work::validate205_delivery_origin(&r.producer_plan, &r.launch, &r.terminal)?;
    let frame = read(&r.frame)?;
    ensure!(
        frame["schema"] == "jetstreamer-capped204205-work-frame-v1"
            && frame["epoch"] == 205
            && frame["launch"] == private157::binding(&r.launch)
            && frame["terminal_snapshot"] == private157::binding(&r.terminal),
        "205 final metadata frame is not the genuine completion"
    );
    let outputs = frame["generated_archives"]
        .as_array()
        .context("205 final archive metadata absent")?
        .iter()
        .filter(|row| row["path"] == OUTPUT)
        .collect::<Vec<_>>();
    ensure!(
        outputs.len() == 1
            && outputs[0]["bytes"] == BYTES
            && outputs[0]["device"] == 66305
            && outputs[0]["inode"] == 544857
            && outputs[0]["uid"] == 1000
            && outputs[0]["links"] == 1
            && outputs[0]["archive_body_read"] == false,
        "205 actual final output metadata differs"
    );
    ensure!(
        p["epoch"] == 205
            && p["producer_unit"] == UNIT
            && l["invocation_id"] == IID
            && p["node_sha256"]
                == "8e82375e588b46413118ad198fefba618c8db3cbe5f070bbac50fa5d94fc97c3"
            && p["worker"]["sha256"] == WORKER
            && p["restart_snapshot"]["sha256"] == SNAPSHOT
            && p["metadata"]["prefix_manifest"] == private157::binding(&r.prefix_manifest)
            && terminal["continuation_result"] == private157::binding(&r.continuation_result),
        "205 recipe lost genuine owner/native input/prefix/terminal bindings"
    );
    let prefix: Manifest = serde_json::from_value(read(&r.prefix_manifest)?)?;
    let proof = read(&r.suffix_proof)?;
    let suffix: Manifest = serde_json::from_value(proof["suffix_manifest"].clone())?;
    let expected = derive(&prefix, &suffix, &proof)?;
    let continuation_result = read(&r.continuation_result)?;
    result_scope(&continuation_result, &p, &l, &proof, &expected)?;
    Ok(Loaded {
        expected,
        continuation_result,
        terminal,
        epoch_started_unix_millis: n(&l, "epoch_started_unix_millis")?,
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareSpec {
    schema: String,
    recipe: Recipe,
    output: PathBuf,
}
pub(super) fn prepare(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let p: PrepareSpec = serde_json::from_value(v.clone())?;
    ensure!(
        p.schema == "jetstreamer-continuation205-delivery-expectation-spec-v1",
        "205 derive scope differs"
    );
    let loaded = load_recipe(&p.recipe)?;
    write(
        &p.output,
        &json!({"schema":"jetstreamer-continuation205-delivery-expectation-v1","epoch":205,
        "kind":"Continuation205","recipe":p.recipe,"expected":loaded.expected.document,
        "natural_success_terminal":loaded.terminal,"continuation_result":loaded.continuation_result,
        "final_archive_digest":{"state":"unmeasured","first_measurement_requires_guarded_full_copy":true},
        "output_body_reads":0,"source_archive_body_reads":0,"output_tuple_frozen":false,
        "issuer":{"spec":spec,"executable_sha256":self_sha},"authority":denied()}),
    )
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum DownstreamSource {
    Continuation205 { completion: BoundFile },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionSpec {
    schema: String,
    recipe: Recipe,
    output: PathBuf,
}
pub(super) fn capture_completion(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    use std::os::fd::AsRawFd;
    let x: CompletionSpec = serde_json::from_value(v.clone())?;
    ensure!(
        x.schema == "jetstreamer-continuation205-completion-spec-v1",
        "205 completion schema differs"
    );
    let loaded = load_recipe(&x.recipe)?;
    let current = unit(UNIT)?;
    ensure!(
        current["MainPID"] == "0"
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "inactive"
            && current["SubState"] == "dead"
            && current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && (current["InvocationID"] == IID || current["InvocationID"] == "")
            && assembly204_recovery::delivery_command_matches(
                s(&current, "ExecStart")?,
                s(&loaded.terminal["current_unit"], "ExecStart")?
            ),
        "205 source producer is not positively unchanged and naturally inactive"
    );
    inactive_status::no_pending_owner_trigger(UNIT, false)?;
    let cgroup = capped204205_work::empty_terminal_cgroup(UNIT)?;
    let input = custody::open(Path::new(OUTPUT))?;
    let before = custody::Stamp::of(&input.metadata()?);
    ensure!(
        before.device == 66305
            && before.inode == 544857
            && before.bytes == BYTES
            && before.links == 1
            && matches!(before.uid, 0 | 1000),
        "205 output no longer matches genuine terminal metadata"
    );
    let writers = custody::no_writers(Path::new("/proc"), &before)?;
    ensure!(
        unsafe { libc::fchown(input.as_raw_fd(), 0, 0) } == 0,
        "205 source root custody transfer failed"
    );
    input.set_permissions(fs::Permissions::from_mode(0o400))?;
    input.sync_all()?;
    let frozen = custody::Stamp::of(&input.metadata()?);
    frozen.frozen()?;
    let writers_after = custody::no_writers(Path::new("/proc"), &frozen)?;
    ensure!(
        frozen == custody::Stamp::of(&fs::symlink_metadata(OUTPUT)?) && unit(UNIT)? == current,
        "205 source changed during metadata-only freeze"
    );
    // Metadata capture intentionally leaves the final digest unknown.
    write(
        &x.output,
        &json!({"schema":"jetstreamer-continuation205-completion-v1","epoch":205,"kind":"Continuation205",
        "recipe":x.recipe,"private_output":OUTPUT,"archive_bytes":BYTES,"output_identity":frozen,"identity_before_custody":before,
        "expected_lineage":loaded.expected.document,"terminal":loaded.terminal,"current_owner":current,"cgroup":cgroup,
        "epoch_started_unix_millis":loaded.epoch_started_unix_millis,
        "writer_census":writers,"writer_census_after_freeze":writers_after,"final_archive_digest":{"state":"unmeasured"},"source_archive_body_reads":0,"output_body_reads":0,
        "issuer":{"spec":spec,"executable_sha256":self_sha},"authority":denied()}),
    )
}
pub(super) fn load_source(source: &DownstreamSource) -> Result<(Value, Loaded)> {
    let DownstreamSource::Continuation205 { completion } = source;
    let c = read(completion)?;
    ensure!(
        c["schema"] == "jetstreamer-continuation205-completion-v1"
            && c["kind"] == "Continuation205"
            && c["epoch"] == 205
            && c["private_output"] == OUTPUT
            && c["archive_bytes"] == BYTES
            && c["final_archive_digest"]["state"] == "unmeasured"
            && c.get("archive_sha256").is_none(),
        "205 completion invented a final digest or changed scope"
    );
    deny(&c["authority"])?;
    let recipe: Recipe = serde_json::from_value(c["recipe"].clone())?;
    let loaded = load_recipe(&recipe)?;
    ensure!(
        c["expected_lineage"] == loaded.expected.document
            && c["terminal"] == loaded.terminal
            && c["epoch_started_unix_millis"] == loaded.epoch_started_unix_millis,
        "205 completion changed genuine terminal/independent expectation"
    );
    let expected: custody::Stamp = serde_json::from_value(c["output_identity"].clone())?;
    expected.frozen()?;
    ensure!(
        expected == custody::tuple(Path::new(OUTPUT))?,
        "205 frozen source tuple changed"
    );
    Ok((c, loaded))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn inputs() -> (Manifest, Manifest, Value) {
        let prefix = serde_json::from_str(include_str!("fixtures/prefix-manifest.json")).unwrap();
        let proof: Value =
            serde_json::from_str(include_str!("fixtures/suffix-proof.json")).unwrap();
        let suffix = serde_json::from_value(proof["suffix_manifest"].clone()).unwrap();
        (prefix, suffix, proof)
    }
    #[test]
    fn continuation205_v4_keeps_exact949_suffix_and_disjoint_native_cursors() {
        let (prefix, suffix, proof) = inputs();
        let e = derive(&prefix, &suffix, &proof).unwrap();
        assert_eq!(e.document["logical_write_versions"], 673276971);
        assert_eq!(e.provenance.base.runtime_segments[0].slot_count, 431051);
        assert_eq!(e.provenance.base.runtime_segments[1].slot_count, 949);
        assert_eq!(
            e.provenance.base.runtime_segments[1]
                .write_versions
                .archive_start,
            671567529
        );
        assert_eq!(
            e.provenance.base.handoffs[0].predecessor.next_write_version,
            84925575998
        );
        assert_eq!(
            e.provenance.base.handoffs[0].successor.next_write_version,
            85166343051
        );
        assert_eq!(e.provenance.base.requested_slot_start, 88560000);
        assert_eq!(e.document["terminal_slot"], 88991999);
        assert_eq!(e.document["assembly_profile"], GENERATION);
    }
    #[test]
    fn continuation205_rejects204_receipts_native_cursor_fabrication_and_suffix_partition_changes()
    {
        let (prefix, _, proof) = inputs();
        for (pointer, value) in [
            ("/epoch", json!(204)),
            (
                "/producer_invocation_id",
                json!("1989c5fd08084f08ab07dabdf8690e67"),
            ),
            ("/suffix_manifest/output_slot_count", json!(948)),
            (
                "/native_checkpoint/initialized_next_write_version",
                json!(84925575998u64),
            ),
            ("/actual_suffix_native_barrier_passed", json!(false)),
            ("/authority/publication_authorized", json!(true)),
        ] {
            let mut changed = proof.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            let suffix = serde_json::from_value(changed["suffix_manifest"].clone()).unwrap();
            assert!(derive(&prefix, &suffix, &changed).is_err(), "{pointer}");
        }
    }
    #[test]
    fn continuation205_actual_result_has_no_final_digest_or_independent_verification() {
        let (prefix, suffix, proof) = inputs();
        let expected = derive(&prefix, &suffix, &proof).unwrap();
        let result: Value =
            serde_json::from_str(include_str!("fixtures/continuation-result.json")).unwrap();
        let p = json!({"source_capture":result["source_capture"],"prefix_archive":result["prefix_archive"]});
        let l = json!({"admission":{"sha256":result["admission_sha256"]}});
        result_scope(&result, &p, &l, &proof, &expected).unwrap();
        for (key, value) in [
            ("archive_sha256", json!("a".repeat(64))),
            ("archive_bytes", json!(BYTES)),
            ("independent_final_archive_verification_passed", json!(true)),
            ("producer_invocation_id", json!("foreign")),
        ] {
            let mut changed = result.clone();
            changed[key] = value;
            assert!(
                result_scope(&changed, &p, &l, &proof, &expected).is_err(),
                "{key}"
            );
        }
    }
}
