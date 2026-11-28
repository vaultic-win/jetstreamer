//! Separate private profiles for the exact epoch-140 internal-full reread and anchored chain.
//! Neither profile grants legacy recovery-v1, replay, manifest, or publication authority.
use super::*;

pub(super) const PLAN_SCHEMA: &str =
    "jetstreamer-horizon-transient-full-verification-evidence-plan-v2";
pub(super) const CHAIN_PLAN_SCHEMA: &str = "jetstreamer-horizon-anchored-chain-evidence-plan-v3";
const UNIT: &str = "horizon-epoch140-source-bound-full-reread-20261020-v1.service";
const INVOCATION: &str = "6c553218f2d64309935be94785077ccd";
const VERIFIER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-reread-20261019-v4/verify_archive";
const VERIFIER_SHA: &str = "f27caf676a477d77d5e423125d1cb840f53589af09f36ca9b67a8732c35fb9e8";
const SOURCE_SHA: &str = "65d311f5b96b2c1f2b8ff50ecfbe5da29bcf57573b55b39c48282f6d259a6842";
const UNIT_SHA: &str = "681ba1f6302aa1bc8ad764872239494cc3474443fdeb124beec2fe13addd4d42";
const CHAIN_UNIT: &str = "horizon-epoch140-anchored-chain-20261021-v1.service";
const CHAIN_INVOCATION: &str = "447a0183fc71414bb9fba1c5a94a6104";
const CHAIN_UNIT_SHA: &str = "8aa7a3c672cd460203e3490008d1d5178aaf53729b783d48d90e8903a1e56276";
const ANCHOR: &str = "HpCoYsom9ZgNNAyCG9Ct72GyQaSdeUpeQKPJ5sKNSCRG";
const FIRST_HASH: &str = "EJtda2adMQbzSTYJugrrJmweXdAYZc8Uwea3ixne773D";
const FULL_EVIDENCE_SHA: &str = "68a96b3e79a62c23a3b9b246bda9fa5d36b937e4e283e09158dd77cdf7f59aa4";
const FIRST_COMPARISON_SHA: &str =
    "b4f453d1fea580305ceef91e7663971d05488baa999cd77ae9eb481dbce4e8f0";
const CHAIN_RESULT: &str = "CHAIN RESULT: OK: all ordered archives and boundaries verify.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    InternalFull,
    AnchoredChain,
}

impl Mode {
    fn unit(self) -> &'static str {
        match self {
            Self::InternalFull => UNIT,
            Self::AnchoredChain => CHAIN_UNIT,
        }
    }
    fn invocation(self) -> &'static str {
        match self {
            Self::InternalFull => INVOCATION,
            Self::AnchoredChain => CHAIN_INVOCATION,
        }
    }
    fn unit_sha(self) -> &'static str {
        match self {
            Self::InternalFull => UNIT_SHA,
            Self::AnchoredChain => CHAIN_UNIT_SHA,
        }
    }
}

fn mode(plan: &Plan) -> Result<Mode, String> {
    let profile = plan.transient.as_ref().ok_or("missing transient profile")?;
    match (plan.schema.as_str(), profile.anchored_chain.is_some()) {
        (PLAN_SCHEMA, false) => Ok(Mode::InternalFull),
        (CHAIN_PLAN_SCHEMA, true) => Ok(Mode::AnchoredChain),
        _ => Err("schema and explicit anchored-chain bindings disagree".into()),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchoredChain {
    full_verification: Evidence,
    first_block_comparison: Evidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    runtime_fragment: Evidence,
    unit_seal_receipt: Evidence,
    source_sha256: String,
    source_identity: Identity,
    source_ctime_seconds: i64,
    source_ctime_nanoseconds: i64,
    output_metadata: PathBuf,
    #[serde(default)]
    anchored_chain: Option<AnchoredChain>,
}

fn sealed_evidence(evidence: &Evidence, limit: u64) -> Result<Vec<u8>, String> {
    let (bytes, identity) = read_hashed(&evidence.path, &evidence.sha256, limit)?;
    require_root_sealed_file(identity, "transient profile evidence")?;
    Ok(bytes)
}

fn seal_member(seal: &Evidence, member: &Evidence) -> Result<(), String> {
    let bytes = sealed_evidence(seal, MAX_JSON_BYTES)?;
    validate_seal_member(&bytes, member)
}

fn validate_seal_member(bytes: &[u8], member: &Evidence) -> Result<(), String> {
    let receipt: SealReceipt = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid separate deployment seal: {error}"))?;
    if receipt.schema != SEAL_RECEIPT_SCHEMA
        || receipt.publication_authorized
        || receipt.replay_launch_authorized
        || receipt.remote_mutations
        || receipt.r2_mutations
        || member.path.parent() != Some(receipt.destination.as_path())
        || receipt
            .members
            .iter()
            .filter(|entry| {
                Some(OsStr::new(&entry.name)) == member.path.file_name()
                    && entry.sha256 == member.sha256
            })
            .count()
            != 1
    {
        return Err("separate seal does not bind the exact non-authorizing member".into());
    }
    Ok(())
}

fn command_arguments(plan: &Plan) -> Result<Vec<String>, String> {
    Ok(match mode(plan)? {
        Mode::InternalFull => vec![
            plan.verifier.path.to_string_lossy().into_owned(),
            plan.archive.path.to_string_lossy().into_owned(),
            "--full".into(),
            "--internal-full".into(),
            "--threads".into(),
            plan.unit.threads.to_string(),
        ],
        Mode::AnchoredChain => vec![
            plan.verifier.path.to_string_lossy().into_owned(),
            "--chain".into(),
            "--anchor".into(),
            "60479999".into(),
            ANCHOR.into(),
            "--threads".into(),
            plan.unit.threads.to_string(),
            plan.archive.path.to_string_lossy().into_owned(),
        ],
    })
}

fn command_line(plan: &Plan) -> Result<String, String> {
    Ok(command_arguments(plan)?.join(" "))
}

fn quoted_exec_start(plan: &Plan) -> Result<String, String> {
    let values = command_arguments(plan)?;
    if values.iter().any(|value| {
        value
            .chars()
            .any(|c| c.is_control() || ['"', '\\', '%', '$'].contains(&c))
    }) {
        return Err("transient argv requires an unsupported escape".into());
    }
    Ok(format!(
        "ExecStart={}",
        values
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(" ")
    ))
}

fn validate_fragment(plan: &Plan, bytes: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "fragment is not UTF-8")?;
    let commands: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("ExecStart="))
        .collect();
    let expected = quoted_exec_start(plan)?;
    if commands != ["ExecStart=", expected.as_str()] {
        return Err("transient fragment does not have the exact reset and quoted argv".into());
    }
    for directive in [
        "Type=oneshot",
        "RemainAfterExit=yes",
        "Restart=no",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "PrivateNetwork=yes",
    ] {
        let name = directive.split_once('=').expect("literal directive").0;
        let matching: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with(&format!("{name}=")))
            .collect();
        if matching != [directive] {
            return Err(format!("missing or conflicting {name} directive"));
        }
    }
    Ok(())
}

fn runtime_fragment(plan: &Plan, profile: &Profile, immutable: &[u8]) -> Result<(), String> {
    let (bytes, identity) = read_hashed(
        &profile.runtime_fragment.path,
        mode(plan)?.unit_sha(),
        MAX_UNIT_BYTES,
    )?;
    // systemd owns and may write this transient fragment. Never chmod it or call it sealed.
    if identity.uid != 0 || identity.mode & 0o022 != 0 || bytes != immutable {
        return Err("runtime fragment differs from its independently sealed copy".into());
    }
    validate_fragment(plan, &bytes)
}

fn validate_state(
    plan: &Plan,
    fields: &BTreeMap<String, String>,
    check_only: bool,
) -> Result<(), String> {
    let profile = plan.transient.as_ref().ok_or("missing transient profile")?;
    let pid = parse_u64_field(fields, "MainPID")?;
    let terminal = field(fields, "ActiveState")? == "active"
        && field(fields, "SubState")? == "exited"
        && pid == 0;
    let running = check_only
        && field(fields, "ActiveState")? == "activating"
        && field(fields, "SubState")? == "start"
        && pid > 0;
    if field(fields, "LoadState")? != "loaded"
        || !(terminal || running)
        || field(fields, "InvocationID")? != plan.unit.invocation_id
        || field(fields, "Result")? != "success"
        || parse_u64_field(fields, "NRestarts")? != 0
        || parse_u64_field(fields, "ExecMainStatus")? != 0
        || parse_u64_field(fields, "ExecMainCode")? != i32::from(terminal) as u64
        || field(fields, "FragmentPath")? != profile.runtime_fragment.path.to_string_lossy()
        || field(fields, "Type")? != "oneshot"
        || field(fields, "RemainAfterExit")? != "yes"
        || field(fields, "Restart")? != "no"
        || !field(fields, "DropInPaths")?.is_empty()
    {
        return Err("not the exact zero-restart transient invocation in the required state".into());
    }
    let effective = field(fields, "ExecStart")?;
    let expected = format!("argv[]={} ; ignore_errors=no ;", command_line(plan)?);
    if effective.matches("argv[]=").count() != 1 || !effective.contains(&expected) {
        return Err("effective systemd argv differs from the bound verifier command".into());
    }
    if terminal
        && (parse_u64_field(fields, "ExecMainPID")? == 0
            || parse_u64_field(fields, "ExecMainExitTimestampMonotonic")? == 0)
    {
        return Err("terminal verifier PID or exit timestamp is absent".into());
    }
    Ok(())
}

fn state(plan: &Plan, check_only: bool) -> Result<BTreeMap<String, String>, String> {
    let output = Command::new("/usr/bin/systemctl").args([
        "show", &plan.unit.name, "--no-pager",
        "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,ExecMainCode,NRestarts,InvocationID,FragmentPath,MainPID,ExecMainPID,ExecMainExitTimestampMonotonic,Type,RemainAfterExit,Restart,DropInPaths,ExecStart",
    ]).output().map_err(|error| format!("systemctl transient identity: {error}"))?;
    if !output.status.success() {
        return Err("systemctl transient identity failed".into());
    }
    let fields = parse_systemctl_show(&output.stdout)?;
    validate_state(plan, &fields, check_only)?;
    Ok(fields)
}

fn audit_journal(
    plan: &Plan,
    bytes: &[u8],
    plain: &[u8],
    state: &BTreeMap<String, String>,
) -> Result<serde_json::Value, String> {
    let expected_command = command_line(plan)?;
    let mut service_messages = Vec::new();
    let mut pids = BTreeSet::new();
    let mut timestamps = Vec::new();
    let mut finishes = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let record: JournalRecord =
            serde_json::from_slice(line).map_err(|error| format!("journal metadata: {error}"))?;
        let timestamp =
            required_journal_u64(record.realtime_timestamp.as_deref(), "__REALTIME_TIMESTAMP")?;
        if record.systemd_unit.as_deref() == Some(plan.unit.name.as_str()) {
            if record.invocation_id.as_deref() != Some(plan.unit.invocation_id.as_str())
                || record.executable.as_deref() != Some(VERIFIER)
                || record.command_line.as_deref() != Some(expected_command.as_str())
            {
                return Err("journal service executable/argv/invocation mismatch".into());
            }
            pids.insert(required_journal_u64(record.pid.as_deref(), "_PID")?);
            timestamps.push(timestamp);
            service_messages.extend_from_slice(
                record
                    .message
                    .as_deref()
                    .ok_or("missing service MESSAGE")?
                    .as_bytes(),
            );
            service_messages.push(b'\n');
        }
        if record.unit.as_deref() == Some(plan.unit.name.as_str()) {
            if record.pid.as_deref() != Some("1")
                || record.executable.as_deref() != Some("/usr/lib/systemd/systemd")
            {
                return Err("manager journal record lacks exact systemd identity".into());
            }
            let message = record.message.as_deref().ok_or("missing manager MESSAGE")?;
            if message == format!("{}: Deactivated successfully.", plan.unit.name) {
                return Err("RemainAfterExit invocation unexpectedly deactivated".into());
            }
            if message.starts_with(&format!("Finished {} - ", plan.unit.name))
                && record.job_result.as_deref() == Some("done")
            {
                finishes.push(timestamp);
            }
        }
    }
    if timestamps.is_empty()
        || finishes.len() != 1
        || pids.len() != 1
        || !pids.contains(&parse_u64_field(state, "ExecMainPID")?)
        || timestamps.iter().any(|timestamp| *timestamp > finishes[0])
        || service_messages != plain
    {
        return Err(
            "journal does not bind one exact verifier PID, complete log and successful finish"
                .into(),
        );
    }
    successful_result(plan, plain)?;
    Ok(serde_json::json!({
        "pid": pids.first(), "records": timestamps.len(),
        "first_realtime_timestamp_us": timestamps.iter().min(),
        "last_realtime_timestamp_us": timestamps.iter().max(),
        "finished_realtime_timestamp_us": finishes[0],
        "deactivated_realtime_timestamp_us": null,
        "deactivation_observed": false
    }))
}

fn successful_result<'a>(plan: &Plan, bytes: &'a [u8]) -> Result<&'a str, String> {
    if mode(plan)? == Mode::InternalFull {
        return result_line(bytes);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "chain log is not UTF-8")?;
    let results: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("RESULT:"))
        .collect();
    let chains: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("CHAIN RESULT:"))
        .collect();
    if results
        != [
            "RESULT: OK: all buckets checksum-verified, every slot/transaction/update decoded, blockhash chain intact, tallies consistent.",
        ]
        || chains != [CHAIN_RESULT]
        || !text.contains("=== verify summary (")
        || text.contains("=== full PoH verification ===")
        || text.contains("SEGMENT RESULT:")
    {
        return Err("chain journal lacks the exact independent non-full anchored success".into());
    }
    Ok(results[0])
}

fn validate_chain_documents(
    plan: &Plan,
    full: &serde_json::Value,
    comparison: &serde_json::Value,
) -> Result<(), String> {
    if full["schema"] != "horizon-private-transient-full-verification-v2"
        || full["status"] != "passed"
        || full["epoch"] != 140
        || full["archive"]["path"] != plan.archive.path.to_string_lossy().as_ref()
        || full["archive"]["sha256"] != SOURCE_SHA
        || full["archive"]["whole_source_rehashed_after_reread"] != true
        || full["archive"]["identity"]
            != serde_json::to_value(
                plan.transient
                    .as_ref()
                    .ok_or("missing profile")?
                    .source_identity,
            )
            .map_err(|error| error.to_string())?
        || full["initial_anchor_proven"] != false
        || !full["result"]["line"]
            .as_str()
            .is_some_and(|line| line.starts_with("RESULT: OK (internal only):"))
        || full["unit"]["invocation_id"] != INVOCATION
        || full["verifier"]["sha256"] != VERIFIER_SHA
        || comparison["schema"] != "jetstreamer-epoch140-initial-boundary-comparison-v1"
        || comparison["epoch"] != 140
        || comparison["status"] != "matched"
        || comparison["archive"] != plan.archive.path.to_string_lossy().as_ref()
        || comparison["archive_sha256"] != SOURCE_SHA
        || comparison["full_verification"]["sha256"] != FULL_EVIDENCE_SHA
        || comparison["canonical_first_block_comparison_passed"] != true
        || comparison["initial_anchor_proven"] != false
        || comparison["ordered_chain_gate_still_required"] != true
        || comparison["stored_first_block"] != comparison["canonical_first_block"]
        || comparison["canonical_first_block"]["slot"] != 60480000
        || comparison["canonical_first_block"]["parent_slot"] != 60479999
        || comparison["canonical_first_block"]["parent_blockhash"] != ANCHOR
        || comparison["canonical_first_block"]["blockhash"] != FIRST_HASH
    {
        return Err("anchored-chain prerequisites are not the exact independent full and canonical comparison proofs".into());
    }
    for document in [full, comparison] {
        for key in [
            "archive_mutations",
            "sidecar_created",
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            if document[key] != false {
                return Err(format!("chain prerequisite grants or omits {key}"));
            }
        }
    }
    Ok(())
}

fn chain_bindings(plan: &Plan) -> Result<(), String> {
    let profile = plan.transient.as_ref().ok_or("missing transient profile")?;
    if let Some(chain) = &profile.anchored_chain {
        if mode(plan)? != Mode::AnchoredChain
            || chain.full_verification.sha256 != FULL_EVIDENCE_SHA
            || chain.first_block_comparison.sha256 != FIRST_COMPARISON_SHA
        {
            return Err(
                "anchored-chain evidence digests differ from independently recorded proofs".into(),
            );
        }
        let full =
            serde_json::from_slice(&sealed_evidence(&chain.full_verification, MAX_JSON_BYTES)?)
                .map_err(|e| e.to_string())?;
        let comparison = serde_json::from_slice(&sealed_evidence(
            &chain.first_block_comparison,
            MAX_JSON_BYTES,
        )?)
        .map_err(|e| e.to_string())?;
        validate_chain_documents(plan, &full, &comparison)?;
    }
    Ok(())
}

fn source_identity(plan: &Plan, profile: &Profile, file: &File) -> Result<(), String> {
    for metadata in [file.metadata(), fs::symlink_metadata(&plan.archive.path)] {
        let metadata = metadata.map_err(|error| format!("source identity: {error}"))?;
        if !metadata.is_file()
            || identity(&metadata) != profile.source_identity
            || metadata.ctime() != profile.source_ctime_seconds
            || metadata.ctime_nsec() != profile.source_ctime_nanoseconds
        {
            return Err("source identity differs from the pre-reread binding".into());
        }
    }
    let sidecar = PathBuf::from(format!("{}.sha256", plan.archive.path.display()));
    match fs::symlink_metadata(sidecar) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("canonical sidecar must be positively absent".into()),
    }
}

fn validate_profile(plan: &Plan) -> Result<Mode, String> {
    let mode = mode(plan)?;
    let profile = plan
        .transient
        .as_ref()
        .ok_or("requires explicit transient profile")?;
    let expected_fragment = PathBuf::from(format!("/run/systemd/transient/{}", mode.unit()));
    if plan.epoch != 140
        || plan.unit.runtime_unit_link.is_some()
        || plan.unit.name != mode.unit()
        || plan.unit.invocation_id != mode.invocation()
        || plan.unit.threads != 8
        || plan.verifier.path != Path::new(VERIFIER)
        || plan.verifier.sha256 != VERIFIER_SHA
        || profile.source_sha256 != SOURCE_SHA
        || profile.runtime_fragment.path != expected_fragment
        || profile.runtime_fragment.sha256 != mode.unit_sha()
        || plan.unit.installed_file.sha256 != mode.unit_sha()
        || profile.source_identity.device != 64512
        || profile.source_identity.inode != 99811416
        || profile.source_identity.bytes != 103138915297
        || profile.source_identity.mode != 0o440
        || plan.archive.bytes != profile.source_identity.bytes
        || plan.archive.uid != profile.source_identity.uid
        || plan.archive.gid != profile.source_identity.gid
        || plan.archive.mode != "0440"
        || plan.authority.archive_mutations
        || plan.authority.sidecar_created
        || plan.authority.replay_launch_authorized
        || plan.authority.publication_authorized
        || plan.authority.remote_mutations
        || plan.authority.r2_mutations
    {
        return Err(
            "transient profile is restricted to its exact private epoch-140 invocation and source"
                .into(),
        );
    }
    if let Some(chain) = &profile.anchored_chain
        && (chain.full_verification.sha256 != FULL_EVIDENCE_SHA
            || chain.first_block_comparison.sha256 != FIRST_COMPARISON_SHA)
    {
        return Err(
            "anchored-chain prerequisite digests are not the independently recorded proofs".into(),
        );
    }
    Ok(mode)
}

pub(super) fn run(arguments: &Arguments, plan: &Plan) -> Result<(), String> {
    let mode = validate_profile(plan)?;
    let profile = plan.transient.as_ref().ok_or("missing transient profile")?;
    for path in [
        &plan.output_log,
        &profile.output_metadata,
        &plan.output_receipt,
    ] {
        validate_output_path(path, "private v2 output")?;
        if path.parent() != plan.output_receipt.parent() {
            return Err("outputs need one private parent".into());
        }
    }
    if plan.output_log == profile.output_metadata
        || plan.output_log == plan.output_receipt
        || profile.output_metadata == plan.output_receipt
    {
        return Err("private output paths must be distinct".into());
    }
    let current_exe = env::current_exe().map_err(|error| error.to_string())?;
    hash_executable(&current_exe, &arguments.self_sha256)?;
    hash_executable(&plan.verifier.path, VERIFIER_SHA)?;
    let immutable = sealed_evidence(&plan.unit.installed_file, MAX_UNIT_BYTES)?;
    seal_member(&plan.deployment_seal_receipt, &plan.verifier)?;
    seal_member(&profile.unit_seal_receipt, &plan.unit.installed_file)?;
    chain_bindings(plan)?;
    runtime_fragment(plan, profile, &immutable)?;
    let (mut source, _) = open_regular_nofollow(&plan.archive.path, plan.archive.bytes)?;
    source_identity(plan, profile, &source)?;
    let before = state(plan, arguments.check_only)?;
    if arguments.check_only {
        println!(
            "{}",
            serde_json::json!({"outcome":"transient-profile-check-only-passed", "full_reread_result_collected":false, "source_rehashed":false, "publication_authorized":false, "r2_mutations":false})
        );
        return Ok(());
    }
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "--all",
            "--unit",
            &plan.unit.name,
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_JOURNAL_BYTES
    {
        return Err("bounded transient journal query failed".into());
    }
    let plain = collect_journal(&plan.unit.invocation_id)?;
    let audit = audit_journal(plan, &output.stdout, &plain, &before)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 8 * 1024 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| format!("post-reread source hash: {error}"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if hex(&digest.finalize()) != SOURCE_SHA {
        return Err("post-reread whole-source SHA mismatch".into());
    }
    source_identity(plan, profile, &source)?;
    runtime_fragment(plan, profile, &immutable)?;
    chain_bindings(plan)?;
    if state(plan, false)? != before {
        return Err("terminal systemd identity changed during source rehash".into());
    }
    let mut receipt = serde_json::json!({
        "schema":if mode == Mode::InternalFull {"horizon-private-transient-full-verification-v2"} else {"horizon-private-anchored-chain-verification-v3"}, "status":"passed", "epoch":140,
        "archive":{"path":plan.archive.path,"sha256":SOURCE_SHA,"identity":profile.source_identity,
            "ctime_seconds":profile.source_ctime_seconds,"ctime_nanoseconds":profile.source_ctime_nanoseconds,
            "whole_source_rehashed_after_reread":true},
        "verifier":{"path":plan.verifier.path,"sha256":VERIFIER_SHA},
        "unit":{"name":mode.unit(),"invocation_id":mode.invocation(),"effective_properties":before,"journal":audit,
            "runtime_fragment":profile.runtime_fragment.path,"fragment_sha256":mode.unit_sha(),
            "immutable_copy":plan.unit.installed_file.path},
        "log":{"path":plan.output_log,"sha256":hex(&Sha256::digest(&plain))},
        "journal_metadata":{"path":profile.output_metadata,"sha256":hex(&Sha256::digest(&output.stdout))},
        "separate_seals":{"verifier":{"path":plan.deployment_seal_receipt.path,"sha256":plan.deployment_seal_receipt.sha256},
            "unit":{"path":profile.unit_seal_receipt.path,"sha256":profile.unit_seal_receipt.sha256}},
        "plan":{"path":arguments.plan,"sha256":arguments.plan_sha256},"collector_sha256":arguments.self_sha256,
        "result":{"line":successful_result(plan,&plain)?}, "initial_anchor_proven":false,
        "archive_mutations":false,"sidecar_created":false,"replay_launch_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false
    });
    if let Some(chain) = &profile.anchored_chain {
        receipt["archive"]
            .as_object_mut()
            .expect("literal archive object")
            .remove("whole_source_rehashed_after_reread");
        receipt["archive"]["whole_source_rehashed_after_chain"] = true.into();
        receipt["full_verification"] = serde_json::json!({"path":chain.full_verification.path,"sha256":chain.full_verification.sha256});
        receipt["first_block_comparison"] = serde_json::json!({"path":chain.first_block_comparison.path,"sha256":chain.first_block_comparison.sha256});
        receipt["command"] = serde_json::json!({"chain":true,"full":false,"segment":false,"threads":8,"anchor":{"slot":60479999,"blockhash":ANCHOR}});
        receipt["result"]["chain_line"] = CHAIN_RESULT.into();
        receipt["initial_anchor_proven"] = true.into();
        receipt["complete_prefix_qualification_proven"] = false.into();
    }
    write_new(&plan.output_log, &plain)?;
    write_new(&profile.output_metadata, &output.stdout)?;
    source_identity(plan, profile, &source)?;
    let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    write_new(&plan.output_receipt, &bytes)?;
    println!(
        "{}",
        serde_json::json!({"outcome":if mode == Mode::InternalFull {"private-transient-full-evidence-created"} else {"private-anchored-chain-evidence-created"},"receipt":plan.output_receipt,
        "receipt_sha256":hex(&Sha256::digest(&bytes)),"publication_authorized":false,"r2_mutations":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        serde_json::from_value(serde_json::json!({
            "schema":PLAN_SCHEMA,"epoch":140,
            "archive":{"path":"/private/epoch-140.jet","bytes":103138915297_u64,"uid":1001,"gid":1003,"mode":"0440"},
            "verifier":{"path":VERIFIER,"sha256":VERIFIER_SHA},
            "unit":{"name":UNIT,"invocation_id":INVOCATION,"threads":8,
                "installed_file":{"path":format!("/sealed/{UNIT}"),"sha256":UNIT_SHA}},
            "deployment_seal_receipt":{"path":"/verifier/deployment-seal-receipt.json","sha256":"00".repeat(32)},
            "output_log":"/results/scan.log","output_receipt":"/results/receipt.json",
            "authority":{"archive_mutations":false,"sidecar_created":false,"replay_launch_authorized":false,
                "publication_authorized":false,"remote_mutations":false,"r2_mutations":false},
            "transient":{
                "runtime_fragment":{"path":format!("/run/systemd/transient/{UNIT}"),"sha256":UNIT_SHA},
                "unit_seal_receipt":{"path":"/sealed/deployment-seal-receipt.json","sha256":"11".repeat(32)},
                "source_sha256":SOURCE_SHA,"source_identity":{"device":64512,"inode":99811416,
                    "bytes":103138915297_u64,"uid":1001,"gid":1003,"mode":288,"links":1,
                    "mtime_seconds":1792366350_i64,"mtime_nanoseconds":258158104},
                "source_ctime_seconds":1792366350_i64,"source_ctime_nanoseconds":292158293,
                "output_metadata":"/results/journal.jsonl"
            }
        })).unwrap()
    }

    fn fields(plan: &Plan) -> BTreeMap<String, String> {
        parse_systemctl_show(format!(concat!(
            "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\n",
            "ExecMainStatus=0\nExecMainCode=1\nNRestarts=0\nInvocationID={}\n",
            "FragmentPath=/run/systemd/transient/{}\nMainPID=0\nExecMainPID=42\n",
            "ExecMainExitTimestampMonotonic=500\nType=oneshot\nRemainAfterExit=yes\nRestart=no\nDropInPaths=\n",
            "ExecStart={{ path={} ; argv[]={} ; ignore_errors=no ; start_time=x ; stop_time=y ; pid=42 ; code=exited ; status=0 }}\n"
        ), plan.unit.invocation_id, plan.unit.name, VERIFIER, command_line(plan).unwrap()).as_bytes()).unwrap()
    }

    fn journal(plan: &Plan, deactivated: bool) -> (Vec<u8>, Vec<u8>) {
        let plain = if mode(plan).unwrap() == Mode::InternalFull {
            b"=== verify summary (1s) ===\n=== full PoH verification ===\nRESULT: OK (internal only): first block unanchored.\n".to_vec()
        } else {
            format!("=== verify summary (1s) ===\nRESULT: OK: all buckets checksum-verified, every slot/transaction/update decoded, blockhash chain intact, tallies consistent.\n{CHAIN_RESULT}\n").into_bytes()
        };
        let message = std::str::from_utf8(&plain).unwrap().trim_end_matches('\n');
        let mut records = vec![
            serde_json::json!({
                "__REALTIME_TIMESTAMP":"100","MESSAGE":message,"_SYSTEMD_UNIT":plan.unit.name,
                "_SYSTEMD_INVOCATION_ID":plan.unit.invocation_id,"_EXE":VERIFIER,
                "_CMDLINE":command_line(plan).unwrap(),"_PID":"42"
            }),
            serde_json::json!({
                "__REALTIME_TIMESTAMP":"200","MESSAGE":format!("Finished {} - verification.",plan.unit.name),
                "UNIT":plan.unit.name,"_EXE":"/usr/lib/systemd/systemd","_PID":"1","JOB_RESULT":"done"
            }),
        ];
        if deactivated {
            records.push(serde_json::json!({"__REALTIME_TIMESTAMP":"199",
                "MESSAGE":format!("{}: Deactivated successfully.",plan.unit.name),"UNIT":plan.unit.name,
                "_EXE":"/usr/lib/systemd/systemd","_PID":"1"}));
        }
        let bytes = records
            .iter()
            .map(|record| format!("{record}\n"))
            .collect::<String>()
            .into_bytes();
        (bytes, plain)
    }

    #[test]
    fn active_exited_is_honest_terminal_without_deactivation() {
        let plan = plan();
        let state = fields(&plan);
        validate_state(&plan, &state, false).unwrap();
        let (metadata, plain) = journal(&plan, false);
        let audit = audit_journal(&plan, &metadata, &plain, &state).unwrap();
        assert!(audit["deactivated_realtime_timestamp_us"].is_null());
        assert_eq!(audit["deactivation_observed"], false);
        assert_eq!(audit["pid"], 42);
    }

    #[test]
    fn running_is_check_only_never_collection() {
        let plan = plan();
        let mut state = fields(&plan);
        for (key, value) in [
            ("ActiveState", "activating"),
            ("SubState", "start"),
            ("MainPID", "42"),
            ("ExecMainCode", "0"),
        ] {
            state.insert(key.into(), value.into());
        }
        validate_state(&plan, &state, true).unwrap();
        assert!(validate_state(&plan, &state, false).is_err());
    }

    #[test]
    fn rejects_changed_identity_restarts_dropins_and_effective_commands() {
        let plan = plan();
        for (key, value) in [
            ("InvocationID", "foreign"),
            ("NRestarts", "1"),
            ("ExecMainStatus", "1"),
            ("MainPID", "42"),
            ("ExecMainCode", "2"),
            ("DropInPaths", "/etc/override.conf"),
            ("ExecStart", "argv[]=different;"),
            ("ExecMainExitTimestampMonotonic", "0"),
            ("FragmentPath", "/different.service"),
        ] {
            let mut state = fields(&plan);
            state.insert(key.into(), value.into());
            assert!(
                validate_state(&plan, &state, false).is_err(),
                "accepted {key}"
            );
        }
    }

    #[test]
    fn accepts_exact_quoted_reset_and_identical_core_limit_duplicates() {
        let plan = plan();
        let fragment = format!(
            "Type=oneshot\nRemainAfterExit=yes\nRestart=no\nProtectSystem=strict\nProtectHome=read-only\nPrivateNetwork=yes\nLimitCORE=0\nLimitCORE=0\nExecStart=\n{}\n",
            quoted_exec_start(&plan).unwrap()
        );
        validate_fragment(&plan, fragment.as_bytes()).unwrap();
        for changed in [
            fragment.replace("ExecStart=\n", ""),
            format!("{fragment}ExecStart=/bad\n"),
            format!("{fragment}Restart=always\n"),
            fragment.replace("\"--full\"", "\"--partial\""),
        ] {
            assert!(validate_fragment(&plan, changed.as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_unbound_journals_missing_finish_and_wrong_pid() {
        let plan = plan();
        let state = fields(&plan);
        let (metadata, plain) = journal(&plan, false);
        let text = String::from_utf8(metadata).unwrap();
        for changed in [
            text.replace(INVOCATION, "different"),
            text.replace(VERIFIER, "/unsealed"),
            text.replace("\"42\"", "\"43\""),
            text.replace("\"done\"", "\"failed\""),
            text.lines().take(1).collect::<String>(),
            text.replace("\"100\"", "\"300\""),
        ] {
            assert!(audit_journal(&plan, changed.as_bytes(), &plain, &state).is_err());
        }
        let (deactivated, _) = journal(&plan, true);
        assert!(audit_journal(&plan, &deactivated, &plain, &state).is_err());
        assert!(audit_journal(&plan, text.as_bytes(), b"different log", &state).is_err());
    }

    #[test]
    fn escapes_are_not_silently_reinterpreted() {
        let mut plan = plan();
        for path in [
            "/private/%i.jet",
            "/private/$VAR.jet",
            "/private/a\".jet",
            "/private/a\\b.jet",
        ] {
            plan.archive.path = path.into();
            assert!(quoted_exec_start(&plan).is_err());
        }
    }

    #[test]
    fn separate_seals_require_exact_destination_digest_and_single_member() {
        let member = Evidence {
            path: "/sealed/verifier".into(),
            sha256: "aa".repeat(32),
        };
        let good = serde_json::json!({"schema":SEAL_RECEIPT_SCHEMA,"destination":"/sealed",
            "members":[{"name":"verifier","sha256":member.sha256}],
            "publication_authorized":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
        validate_seal_member(&serde_json::to_vec(&good).unwrap(), &member).unwrap();
        for key in [
            "publication_authorized",
            "replay_launch_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = good.clone();
            bad[key] = true.into();
            assert!(validate_seal_member(&serde_json::to_vec(&bad).unwrap(), &member).is_err());
        }
        for (key, value) in [
            ("destination", serde_json::json!("/other")),
            ("members", serde_json::json!([])),
            (
                "members",
                serde_json::json!([{"name":"verifier","sha256":"bb".repeat(32)}]),
            ),
            (
                "members",
                serde_json::json!([good["members"][0].clone(), good["members"][0].clone()]),
            ),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(validate_seal_member(&serde_json::to_vec(&bad).unwrap(), &member).is_err());
        }
    }

    fn chain_plan() -> Plan {
        let mut plan = plan();
        plan.schema = CHAIN_PLAN_SCHEMA.into();
        plan.unit.name = CHAIN_UNIT.into();
        plan.unit.invocation_id = CHAIN_INVOCATION.into();
        plan.unit.installed_file = Evidence {
            path: format!("/sealed/{CHAIN_UNIT}").into(),
            sha256: CHAIN_UNIT_SHA.into(),
        };
        let profile = plan.transient.as_mut().unwrap();
        profile.runtime_fragment = Evidence {
            path: format!("/run/systemd/transient/{CHAIN_UNIT}").into(),
            sha256: CHAIN_UNIT_SHA.into(),
        };
        profile.anchored_chain = Some(AnchoredChain {
            full_verification: Evidence {
                path: "/proof/full.json".into(),
                sha256: FULL_EVIDENCE_SHA.into(),
            },
            first_block_comparison: Evidence {
                path: "/proof/first.json".into(),
                sha256: FIRST_COMPARISON_SHA.into(),
            },
        });
        plan
    }

    fn chain_documents(plan: &Plan) -> (serde_json::Value, serde_json::Value) {
        let first = serde_json::json!({"slot":60480000,"parent_slot":60479999,"parent_blockhash":ANCHOR,"blockhash":FIRST_HASH});
        let authority = serde_json::json!({"archive_mutations":false,"sidecar_created":false,"replay_launch_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let mut full = authority.clone();
        full.as_object_mut().unwrap().extend(serde_json::json!({
            "schema":"horizon-private-transient-full-verification-v2","status":"passed","epoch":140,
            "archive":{"path":plan.archive.path,"sha256":SOURCE_SHA,"whole_source_rehashed_after_reread":true,
                "identity":plan.transient.as_ref().unwrap().source_identity},
            "unit":{"invocation_id":INVOCATION},"verifier":{"sha256":VERIFIER_SHA},"initial_anchor_proven":false,
            "result":{"line":"RESULT: OK (internal only): all stored links verify; the first block is unanchored."}
        }).as_object().unwrap().clone());
        let mut comparison = authority;
        comparison.as_object_mut().unwrap().extend(serde_json::json!({
            "schema":"jetstreamer-epoch140-initial-boundary-comparison-v1","epoch":140,"status":"matched",
            "archive":plan.archive.path,"archive_sha256":SOURCE_SHA,"full_verification":{"sha256":FULL_EVIDENCE_SHA},
            "canonical_first_block_comparison_passed":true,"initial_anchor_proven":false,"ordered_chain_gate_still_required":true,
            "stored_first_block":first,"canonical_first_block":first
        }).as_object().unwrap().clone());
        (full, comparison)
    }

    #[test]
    fn chain_is_distinct_from_unchanged_internal_full_mode() {
        let full = plan();
        let chain = chain_plan();
        assert_eq!(validate_profile(&full).unwrap(), Mode::InternalFull);
        assert_eq!(validate_profile(&chain).unwrap(), Mode::AnchoredChain);
        assert_eq!(command_line(&full).unwrap(), exact_command_line(&full));
        assert_eq!(
            command_line(&chain).unwrap(),
            format!(
                "{VERIFIER} --chain --anchor 60479999 {ANCHOR} --threads 8 /private/epoch-140.jet"
            )
        );
        assert!(
            !command_arguments(&chain)
                .unwrap()
                .iter()
                .any(|arg| arg == "--full" || arg == "--internal-full" || arg == "--segment")
        );
        validate_state(&chain, &fields(&chain), false).unwrap();
        let (metadata, plain) = journal(&chain, false);
        audit_journal(&chain, &metadata, &plain, &fields(&chain)).unwrap();
        assert!(successful_result(&full, &plain).is_err());
        assert!(successful_result(&chain, &journal(&full, false).1).is_err());
    }

    #[test]
    fn schema_and_exact_chain_proof_identity_cannot_be_borrowed() {
        let mut full = plan();
        full.schema = CHAIN_PLAN_SCHEMA.into();
        assert!(validate_profile(&full).is_err());
        let mut chain = chain_plan();
        chain.schema = PLAN_SCHEMA.into();
        assert!(validate_profile(&chain).is_err());
        for mutation in 0..5 {
            let mut chain = chain_plan();
            match mutation {
                0 => chain.unit.invocation_id = INVOCATION.into(),
                1 => chain.unit.name = UNIT.into(),
                2 => chain.unit.installed_file.sha256 = UNIT_SHA.into(),
                3 => {
                    chain
                        .transient
                        .as_mut()
                        .unwrap()
                        .anchored_chain
                        .as_mut()
                        .unwrap()
                        .full_verification
                        .sha256 = "00".repeat(32)
                }
                _ => {
                    chain
                        .transient
                        .as_mut()
                        .unwrap()
                        .anchored_chain
                        .as_mut()
                        .unwrap()
                        .first_block_comparison
                        .sha256 = "00".repeat(32)
                }
            }
            assert!(validate_profile(&chain).is_err());
        }
    }

    #[test]
    fn chain_success_rejects_missing_duplicate_full_or_segment_results() {
        let plan = chain_plan();
        let (_, plain) = journal(&plan, false);
        let good = String::from_utf8(plain).unwrap();
        successful_result(&plan, good.as_bytes()).unwrap();
        for bad in [
            good.replace(CHAIN_RESULT, "CHAIN RESULT: FAIL"),
            good.replace(CHAIN_RESULT, ""),
            format!("{good}{CHAIN_RESULT}\n"),
            format!("{good}=== full PoH verification ===\n"),
            good.replace(
                CHAIN_RESULT,
                "SEGMENT RESULT: OK: outer boundaries deferred.",
            ),
            good.replace(
                "RESULT: OK: all buckets",
                "RESULT: OK (internal only): all buckets",
            ),
        ] {
            assert!(successful_result(&plan, bad.as_bytes()).is_err());
        }
    }

    #[test]
    fn chain_journal_requires_anchored_argv_exact_pid_and_manager_finish() {
        let plan = chain_plan();
        let (metadata, plain) = journal(&plan, false);
        let text = String::from_utf8(metadata).unwrap();
        for bad in [
            text.replace(ANCHOR, FIRST_HASH),
            text.replace(CHAIN_INVOCATION, INVOCATION),
            text.replace("\"42\"", "\"43\""),
            text.replace("\"done\"", "\"failed\""),
            text.lines().take(1).collect::<String>(),
        ] {
            assert!(audit_journal(&plan, bad.as_bytes(), &plain, &fields(&plan)).is_err());
        }
        assert!(audit_journal(&plan, &journal(&plan, true).0, &plain, &fields(&plan)).is_err());
    }

    #[test]
    fn chain_requires_both_independent_matching_proofs() {
        let plan = chain_plan();
        let (full, comparison) = chain_documents(&plan);
        validate_chain_documents(&plan, &full, &comparison).unwrap();
        for pointer in [
            "/schema",
            "/status",
            "/archive/sha256",
            "/archive/identity/inode",
            "/unit/invocation_id",
            "/result/line",
        ] {
            let mut bad = full.clone();
            *bad.pointer_mut(pointer).unwrap() = "substitution".into();
            assert!(
                validate_chain_documents(&plan, &bad, &comparison).is_err(),
                "accepted {pointer}"
            );
        }
        for pointer in [
            "/schema",
            "/status",
            "/archive_sha256",
            "/full_verification/sha256",
            "/canonical_first_block/parent_blockhash",
            "/canonical_first_block/slot",
            "/stored_first_block/blockhash",
        ] {
            let mut bad = comparison.clone();
            *bad.pointer_mut(pointer).unwrap() = "substitution".into();
            assert!(
                validate_chain_documents(&plan, &full, &bad).is_err(),
                "accepted {pointer}"
            );
        }
        for key in [
            "archive_mutations",
            "sidecar_created",
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad_full = full.clone();
            bad_full[key] = true.into();
            assert!(validate_chain_documents(&plan, &bad_full, &comparison).is_err());
            let mut bad_comparison = comparison.clone();
            bad_comparison.as_object_mut().unwrap().remove(key);
            assert!(validate_chain_documents(&plan, &full, &bad_comparison).is_err());
        }
    }

    #[test]
    fn source_binding_rejects_path_replacement_changed_ctime_and_even_dangling_sidecar() {
        let directory = tempfile::tempdir().unwrap();
        let mut plan = plan();
        plan.archive.path = directory.path().join("epoch-140.jet");
        fs::write(&plan.archive.path, b"original").unwrap();
        let file = File::open(&plan.archive.path).unwrap();
        let metadata = file.metadata().unwrap();
        {
            let profile = plan.transient.as_mut().unwrap();
            profile.source_identity = identity(&metadata);
            profile.source_ctime_seconds = metadata.ctime();
            profile.source_ctime_nanoseconds = metadata.ctime_nsec();
        }
        source_identity(&plan, plan.transient.as_ref().unwrap(), &file).unwrap();
        plan.transient.as_mut().unwrap().source_ctime_nanoseconds += 1;
        assert!(source_identity(&plan, plan.transient.as_ref().unwrap(), &file).is_err());
        plan.transient.as_mut().unwrap().source_ctime_nanoseconds -= 1;
        let sidecar = PathBuf::from(format!("{}.sha256", plan.archive.path.display()));
        std::os::unix::fs::symlink(directory.path().join("absent"), &sidecar).unwrap();
        assert!(source_identity(&plan, plan.transient.as_ref().unwrap(), &file).is_err());
        fs::remove_file(sidecar).unwrap();
        let replacement = directory.path().join("replacement.jet");
        fs::write(&replacement, b"original").unwrap();
        fs::rename(replacement, &plan.archive.path).unwrap();
        assert!(source_identity(&plan, plan.transient.as_ref().unwrap(), &file).is_err());
    }
}
