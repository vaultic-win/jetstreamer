//! Independent metadata derivation. No live NativeBarrier or producer result is
//! constructed, and the recovered file is never its own expectation source.
use super::*;
use jetstreamer_horizon::archive::{AccountsHashKind, ArchiveProvenance, ArchiveProvenanceV3,
    ArchiveProvenanceV4, BootstrapStateKind, RuntimeAdmission, RuntimeHandoffProvenance,
    RuntimeSegmentProvenance, RuntimeStateCheckpoint, StateCommitment, StateCommitmentKind,
    TransactionMetadataPolicy, WriteVersionNormalization, encode_archive_provenance};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    pub slot:u64, pub bank_hash:String, pub accounts_hash:String, pub last_blockhash:String,
    pub capitalization:u64, pub transaction_count:u64, pub tick_height:u64,
    pub slot_complete:bool, pub write_count:u64, pub next_write_version:u64,
}
impl Checkpoint {
    fn runtime(&self)->Result<RuntimeStateCheckpoint> {
        Ok(RuntimeStateCheckpoint{slot:self.slot,bank_hash:self.bank_hash.parse()?,
            accounts_hash_kind:AccountsHashKind::LegacyAccountsHash,accounts_hash:self.accounts_hash.parse()?,
            last_blockhash:self.last_blockhash.parse()?,capitalization:self.capitalization,
            transaction_count:self.transaction_count,tick_height:self.tick_height,
            slot_complete:self.slot_complete,next_write_version:self.next_write_version})
    }
    fn consensus(&self,other:&Self)->bool {
        self.slot==other.slot && self.bank_hash==other.bank_hash && self.accounts_hash==other.accounts_hash
            && self.last_blockhash==other.last_blockhash && self.capitalization==other.capitalization
            && self.transaction_count==other.transaction_count && self.tick_height==other.tick_height
            && self.slot_complete && other.slot_complete
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Runtime {
    pub generation_profile:String,pub runtime_profile:String,pub runtime_admission:String,
    pub runtime_revision:String,pub runtime_toolchain:String,pub runtime_target:String,pub genesis_hash:String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Versions { pub start:u64,pub end:u64 }
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub schema_version:u64,pub epoch:u64,pub output_slot_start:u64,pub output_slot_count:u64,
    pub runtime:Runtime,pub worker_executable_sha256:String,pub archive_sha256:String,
    pub bootstrap_archive_sha256:Option<String>,pub bootstrap:Checkpoint,pub terminal:Checkpoint,
    pub emitted_raw_write_versions:Versions,
}
fn digest(raw:&str)->Result<[u8;32]> {
    ensure!(is_lower_hex(raw,64),"204 lineage noncanonical SHA-256");
    let mut result=[0;32];for (i,b) in result.iter_mut().enumerate(){*b=u8::from_str_radix(&raw[i*2..i*2+2],16)?;} Ok(result)
}
fn manifest_scope(m:&Manifest)->Result<()> {
    ensure!(m.schema_version==1 && m.epoch==204 && m.worker_executable_sha256==WORKER
        && m.runtime.runtime_profile=="solana-v1.6.16" && m.runtime.runtime_admission=="candidate"
        && m.runtime.runtime_revision=="86c26f843276581509c3434acc2efbf4202c44e0"
        && m.runtime.runtime_target=="x86_64-unknown-linux-gnu"
        && m.runtime.genesis_hash=="5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
        && m.bootstrap.slot_complete && m.terminal.slot_complete
        && m.emitted_raw_write_versions.start<m.emitted_raw_write_versions.end
        && m.emitted_raw_write_versions.end==m.terminal.next_write_version,
        "204 source manifest runtime/coverage/write bounds differ");
    digest(&m.archive_sha256)?;Ok(())
}
pub(super) struct Expected {
    pub provenance:ArchiveProvenanceV4,pub digest:String,pub document:Value,
}
pub(super) fn derive(prefix:&Manifest,suffix:&Manifest,proof:&Value)->Result<Expected> {
    manifest_scope(prefix)?;manifest_scope(suffix)?;
    ensure!(prefix.output_slot_start==88_128_000 && prefix.output_slot_count==431_362
        && prefix.bootstrap.slot==88_127_580 && prefix.bootstrap.write_count==0
        && prefix.bootstrap.accounts_hash=="4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"
        && prefix.bootstrap_archive_sha256.is_none() && prefix.terminal.slot==88_559_361
        && prefix.archive_sha256==PREFIX_SHA && suffix.archive_sha256==SUFFIX_SHA
        && suffix.output_slot_start==88_559_362 && suffix.output_slot_count==638
        && suffix.terminal.slot==88_559_999 && suffix.bootstrap.slot==88_559_361
        && suffix.bootstrap_archive_sha256.as_deref()==Some(SNAPSHOT)
        && suffix.bootstrap.write_count==0 && suffix.bootstrap.next_write_version==84_252_990_240
        && prefix.terminal.consensus(&suffix.bootstrap)
        && prefix.runtime.runtime_toolchain==suffix.runtime.runtime_toolchain
        && prefix.runtime.generation_profile=="jetstreamer-node/0.7.0/old-faithful-to-horizon-v2@3de96e71010a8a2f5e629f666227b137483bff7b"
        && suffix.runtime.generation_profile=="jetstreamer-node/0.9.0/old-faithful-to-horizon-v2@6a327d89ef7ef7677f66d75bac99e9b0f7baf733",
        "204 source partition, checkpoint or exact generation differs");
    ensure!(proof["schema"]=="jetstreamer-capped204205-private-suffix-v1"
        && proof["epoch"]==204 && proof["plan_sha256"]==OLD_PLAN
        && proof["producer_invocation_id"]==OLD_IID && proof["prefix_sha256"]==PREFIX_SHA
        && proof["worker_sha256"]==WORKER && proof["complete_prefix_reread"]==true
        && proof["actual_suffix_native_barrier_passed"]==true && proof["provenance_version"]==4,
        "204 saved suffix is not the exact genuine completed suffix");deny(&proof["authority"])?;
    let native=&proof["native_checkpoint"];
    let initialized=suffix.bootstrap.runtime()?;
    ensure!(native["accounts_hash_kind"]=="legacy_accounts_hash" && native["slot"]==initialized.slot
        && native["bank_hash"]==initialized.bank_hash.to_string()
        && native["accounts_hash"]==initialized.accounts_hash.to_string()
        && native["last_blockhash"]==initialized.last_blockhash.to_string()
        && native["capitalization"]==initialized.capitalization && native["transaction_count"]==initialized.transaction_count
        && native["tick_height"]==initialized.tick_height && native["slot_complete"]==true
        && native["next_write_version"]==initialized.next_write_version
        && native["initialized_next_write_version"]==initialized.next_write_version
        && native["bootstrap_write_count"]==0 && native["initialized_ticks_per_slot"]==64
        && native["worker_sha256"]==WORKER,"204 saved native consensus/kind/cursor/writes/ticks differ");
    let mut next=0u64;let mut segments=Vec::new();
    for m in [prefix,suffix] {
        let map=WriteVersionNormalization{worker_start:m.emitted_raw_write_versions.start,
            worker_end_exclusive:m.emitted_raw_write_versions.end,archive_start:next};
        next=map.archive_end_exclusive().context("204 normalization overflow")?;
        segments.push(RuntimeSegmentProvenance{slot_start:m.output_slot_start,slot_count:m.output_slot_count,
            generation_profile:m.runtime.generation_profile.clone(),runtime_profile:m.runtime.runtime_profile.clone(),
            runtime_admission:RuntimeAdmission::Candidate,runtime_revision:m.runtime.runtime_revision.clone(),
            runtime_toolchain:m.runtime.runtime_toolchain.clone(),worker_executable_sha256:Some(digest(WORKER)?),write_versions:map});
    }
    let provenance=ArchiveProvenanceV4{base:ArchiveProvenanceV3{assembly_profile:GENERATION.into(),
        genesis_hash:prefix.runtime.genesis_hash.parse()?,bootstrap_state_kind:BootstrapStateKind::SnapshotArchive,
        bootstrap_state:StateCommitment{slot:prefix.bootstrap.slot,kind:StateCommitmentKind::LegacyAccountsHash,
            hash:prefix.bootstrap.accounts_hash.parse()?},requested_slot_start:88_128_000,requested_slot_count:432_000,
        transaction_metadata:TransactionMetadataPolicy::observed(),runtime_segments:segments,
        handoffs:vec![RuntimeHandoffProvenance{boundary_slot:88_559_362,predecessor:prefix.terminal.runtime()?,
            successor:initialized,successor_bootstrap_kind:BootstrapStateKind::SnapshotArchive,
            successor_bootstrap_archive_sha256:digest(SNAPSHOT)?,successor_bootstrap_write_count:0}]}};
    provenance.validate()?;
    let encoded=encode_archive_provenance(&ArchiveProvenance::V4(provenance.clone()))?;
    let hash=hex_lower(&Sha256::digest(&encoded));
    let document=json!({"epoch":204,"slot_start":88128000,"slot_count":432000,"terminal_slot":88559999,
        "source_archives":2,"prefix_sha256":PREFIX_SHA,"suffix_sha256":SUFFIX_SHA,
        "expected_provenance_sha256":hash,"expected_encoded_bytes":encoded.len(),"assembly_profile":GENERATION,
        "prefix_raw_write_versions":prefix.emitted_raw_write_versions,"suffix_raw_write_versions":suffix.emitted_raw_write_versions,
        "native_checkpoint":native,"metadata":"observed","logical_write_versions":next});
    Ok(Expected{provenance,digest:hash,document})
}

/// Only this explicit branch enters the recovery adapters. There is no fallback
/// to a normal OriginalProducerResult and no asserted native-barrier token.
#[derive(Clone,Deserialize,Serialize)]
#[serde(tag="kind",deny_unknown_fields)]
pub(super) enum DownstreamSource {
    AssemblyRecovery204 { completion:BoundFile },
}
#[derive(Clone,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Recipe {
    pub original_plan:BoundFile,pub original_terminal:BoundFile,pub suffix_proof:BoundFile,
    pub source_capture:BoundFile,pub recovery_plan:BoundFile,pub admission:BoundFile,
    pub launch:BoundFile,pub outcome:BoundFile,pub recovery_terminal:BoundFile,
}
pub(super) struct Loaded {
    pub recipe:Recipe,pub old_terminal:Value,pub capture:Value,pub plan:Value,pub admission:Value,
    pub launch:Value,pub outcome:Value,pub terminal:Value,pub expected:Expected,
}
pub(super) fn sources(original:&BoundFile,suffix:&BoundFile)->Result<(Manifest,Manifest,Value)> {
    ensure!(original.sha256==OLD_PLAN && suffix.sha256==SUFFIX_PROOF,"204 source primary digests differ");
    let p=read(original)?;ensure!(p["epoch"]==204 && p["producer_unit"]==OLD_UNIT
        && p["run_root"]==OLD_ROOT && p["prefix_archive"]["sha256"]==PREFIX_SHA
        && p["worker"]["sha256"]==WORKER && p["restart_snapshot"]["sha256"]==SNAPSHOT,
        "204 original plan scope differs");
    let prefix:Manifest=serde_json::from_value(read(&serde_json::from_value(p["metadata"]["prefix_manifest"].clone())?)?)?;
    let proof=read(suffix)?;let tail:Manifest=serde_json::from_value(proof["suffix_manifest"].clone())?;
    derive(&prefix,&tail,&proof)?;Ok((prefix,tail,proof))
}
pub(super) fn load_recipe(recipe:Recipe)->Result<Loaded> {
    let old_terminal=read(&recipe.original_terminal)?;custody::validate_terminal_saved(&old_terminal)?;
    let capture=read(&recipe.source_capture)?;custody::validate_source_capture(&capture,&recipe.original_plan,
        &recipe.original_terminal,&recipe.suffix_proof,n(&old_terminal,"finished_unix_millis")?)?;
    let plan=read(&recipe.recovery_plan)?;custody::plan_scope(&plan)?;
    ensure!(plan["original_plan"]==private157::binding(&recipe.original_plan)
        && plan["original_terminal"]==private157::binding(&recipe.original_terminal)
        && plan["source_capture"]==private157::binding(&recipe.source_capture)
        && plan["suffix_proof"]==private157::binding(&recipe.suffix_proof),"204 recovery plan lost source lineage");
    let admission=read(&recipe.admission)?;capacity::validate_issued(&admission,&recipe.recovery_plan,&plan)?;
    let launch=read(&recipe.launch)?;ownership::validate_launch(&launch,&recipe.recovery_plan,&plan,&recipe.admission)?;
    let outcome=read(&recipe.outcome)?;let terminal=read(&recipe.recovery_terminal)?;
    ownership::validate_success_terminal(&terminal,UNIT,s(&launch,"invocation_id")?)?;
    ensure!(terminal["outcome"]==private157::binding(&recipe.outcome),"204 terminal outcome binding differs");
    let (prefix,suffix,proof)=sources(&recipe.original_plan,&recipe.suffix_proof)?;
    let expected=derive(&prefix,&suffix,&proof)?;
    validate_outcome(&outcome,&recipe,&plan,&launch,&expected)?;
    Ok(Loaded{recipe,old_terminal,capture,plan,admission,launch,outcome,terminal,expected})
}
pub(super) fn validate_outcome(o:&Value,r:&Recipe,p:&Value,l:&Value,e:&Expected)->Result<()> {
    ensure!(o["schema"]=="jetstreamer-epoch204-assembly-only-recovery-outcome-v1"
        && o["epoch"]==204 && o["unit"]==UNIT && o["invocation_id"]==l["invocation_id"]
        && o["guard_unit"]==GUARD && o["guard_invocation_id"]==l["guard_invocation_id"]
        && o["plan_sha256"]==r.recovery_plan.sha256 && o["executable_sha256"]==p["executable_sha256"]
        && o["original_terminal"]==private157::binding(&r.original_terminal)
        && o["original_outcome"]=="failed_or_stopped" && o["original_invocation_id"]==OLD_IID
        && o["suffix_proof"]==private157::binding(&r.suffix_proof)
        && o["source_capture"]==private157::binding(&r.source_capture)
        && o["admission_sha256"]==r.admission.sha256 && o["private_output"]==OUTPUT
        && n(o,"archive_bytes")?>0 && n(o,"archive_bytes")?<=OUTPUT_MAX
        && is_lower_hex(s(o,"archive_sha256")?,64) && o["provenance_version"]==4
        && o["provenance_sha256"]==e.digest && o["assembly_profile"]==GENERATION
        && o["source_archives"]==2 && o["slots_merged"]==432000
        && o["writer"]["zstd_level"]==p["zstd_level"] && o["writer"]["format"]=="V2"
        && o["writer"]["compression"]=="Zstd" && o["writer"]["diff_policy"]=="OuterCompressed"
        && o["writer"]["bucket_slots"]==128 && o["epoch_started_unix_millis"]==ORIGIN
        && o["no_replay"]==true && o["new_native_initialization_performed"]==false
        && o["independent_final_archive_verification_passed"]==false
        && o["current_plugin_verification_passed"]==false,"204 recovery output/lineage/authority differs");
    deny(&o["authority"])
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionSpec { schema:String, recipe:Recipe, output:PathBuf }
pub(super) fn capture_completion(v:&Value,spec:&BoundFile,self_sha:&str)->Result<()> {
    let c:CompletionSpec=serde_json::from_value(v.clone())?;
    ensure!(c.schema=="jetstreamer-epoch204-assembly-recovery-completion-spec-v1","204 completion spec");
    let loaded=load_recipe(c.recipe.clone())?;
    let before=unit(UNIT)?;ensure!(is_idle(&before),"204 recovery still live");
    custody::old_idle()?;
    let path=Path::new(OUTPUT);let file=custody::open_source(path)?;let before_output=custody::FileStamp::of(&file.metadata()?);
    ensure!(before_output.bytes==n(&loaded.outcome,"archive_bytes")? && before_output.uid==0
        && before_output.links==1 && before_output.mode&0o022==0,"204 completed output custody differs");
    file.set_permissions(fs::Permissions::from_mode(0o400))?;file.sync_all()?;
    let frozen=custody::FileStamp::of(&file.metadata()?);no_sidecar(path)?;
    ensure!(unit(UNIT)?==before,"204 recovery terminal owner changed during custody");
    write(&c.output,&json!({"schema":"jetstreamer-epoch204-assembly-recovery-completion-v1","epoch":204,
        "kind":"AssemblyRecovery204","recipe":c.recipe,"issuer":issuer(spec,self_sha),
        "private_output":OUTPUT,"archive_sha256":loaded.outcome["archive_sha256"],
        "archive_bytes":loaded.outcome["archive_bytes"],"output_identity":frozen,
        "expected_lineage":loaded.expected.document,"original_outcome":"failed_or_stopped",
        "recovery_outcome":"natural_success","source_archive_body_reads":0,"output_body_reads":0,
        "authority":denied()}))?;Ok(())
}
pub(super) fn load_source(source:&DownstreamSource)->Result<(Value,Loaded)> {
    let DownstreamSource::AssemblyRecovery204{completion}=source;
    let c=read(completion)?;ensure!(c["schema"]=="jetstreamer-epoch204-assembly-recovery-completion-v1"
        && c["kind"]=="AssemblyRecovery204" && c["epoch"]==204,"204 completion branch differs");
    deny(&c["authority"])?;let loaded=load_recipe(serde_json::from_value(c["recipe"].clone())?)?;
    ensure!(c["archive_sha256"]==loaded.outcome["archive_sha256"] && c["archive_bytes"]==loaded.outcome["archive_bytes"]
        && c["expected_lineage"]==loaded.expected.document,"204 completion tuple differs");
    Ok((c,loaded))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectSpec { schema:String, source:DownstreamSource, output:PathBuf }
pub(super) fn expectation(v:&Value,spec:&BoundFile,self_sha:&str)->Result<()> {
    let e:ExpectSpec=serde_json::from_value(v.clone())?;ensure!(e.schema=="jetstreamer-epoch204-assembly-recovery-expectation-spec-v1","204 expectation spec");
    let (_,loaded)=load_source(&e.source)?;
    write(&e.output,&json!({"schema":"jetstreamer-epoch204-assembly-recovery-provenance-expectation-v1","epoch":204,
        "source":e.source,"expected":loaded.expected.document,"issuer":issuer(spec,self_sha),
        "assembled_target_opened":false,"source_archive_body_reads":0,"authority":denied()}))?;Ok(())
}
