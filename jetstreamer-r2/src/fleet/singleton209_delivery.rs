//! Independent full209 verification receipts and serialized authenticated delivery.
use super::{singleton209 as c, *};
use std::os::fd::AsRawFd;
pub(super) mod admission;
const SCHEMA: &str = "jetstreamer-private-epoch209-singleton-delivery-receipt-v1";
const TOOLS: &str = "/var/lib/jetstreamer/horizon-full209-verification-tools-v1";
const FULL_SHA: &str = "6b757a5549bb6ae5dfb0c880274b54c7fa6e2fd2980c10af3455556a1c174260";
const PLUGIN_SHA: &str = "d542cbefd3ddff4e4d707daed4142039b8a5bb89cbd3f7acca082351c2bc60cf";
const R2_RECEIPTS: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts";
const LOCK: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock";
#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Stage {
    Full,
    Plugin,
    Upload,
}
impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Plugin => "plugin",
            Self::Upload => "upload",
        }
    }
    fn unit(self) -> &'static str {
        match self {
            Self::Full => "horizon-full-verify-209-singleton-v1.service",
            Self::Plugin => "horizon-plugin-verify-209-singleton-v1.service",
            Self::Upload => "horizon-upload-209-singleton-v1.service",
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    stage: Stage,
    launch: BoundFile,
    cohort_publication: BoundFile,
    full_verification: Option<BoundFile>,
    plugin_verification: Option<BoundFile>,
    output_directory: PathBuf,
    r2_receipt_directory: PathBuf,
    upload_lock: PathBuf,
    r2_mutations: bool,
}
fn bytes32(s: &str) -> Result<Value> {
    let decoded = bs58::decode(s)
        .into_vec()
        .map_err(|e| anyhow!("209 invalid consensus hash: {e}"))?;
    ensure!(decoded.len() == 32, "209 consensus hash length differs");
    Ok(serde_json::to_value(decoded)?)
}
pub(super) fn pair_identity(a: &LocalArchive) -> Value {
    json!({"path":a.archive_path,"sha256":a.sha256_hex,"bytes":a.length,
        "device":a.identity.device,"inode":a.identity.inode,"modified_seconds":a.identity.modified_seconds,
        "modified_nanoseconds":a.identity.modified_nanoseconds,"sidecar_device":a.sidecar_identity.device,
        "sidecar_inode":a.sidecar_identity.inode,"sidecar_modified_seconds":a.sidecar_identity.modified_seconds,
        "sidecar_modified_nanoseconds":a.sidecar_identity.modified_nanoseconds})
}
pub(super) fn cohort(v: &Value, a: &LocalArchive) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let gate = &v["root_checkpoint_gate"];
    let checkpoints = gate["verified_manifest_checkpoints"]
        .as_array()
        .context("209 verified roots")?;
    let members = gate["members"]
        .as_array()
        .context("209 native terminal members")?;
    let published = v["outcome"]["members"]
        .as_array()
        .context("209 committed cohort members")?;
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
                "209 native checkpoint integer missing: {name}"
            );
        }
        for name in ["bank_hash", "accounts_hash", "last_blockhash"] {
            let _: [u8; 32] = serde_json::from_value(summary[name].clone())
                .context("209 incomplete native checkpoint hash")?;
        }
    }
    ensure!(
        v["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && v["manifest_fingerprint"] == c::FINGERPRINT
            && v["epochs"] == json!([209])
            && gate["kind"] == "sealed-root-checkpoint-cohort"
            && gate["version"] == 1
            && checkpoints.len() == 1
            && checkpoints[0]["slot"] == 90719638u64
            && checkpoints[0]["accounts_hash"]
                == bytes32("3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ")?
            && members.len() == 1
            && members[0]["epoch"] == 209
            && members[0]["bootstrap"]["slot"] == 90287519u64
            && members[0]["bootstrap"]["accounts_hash"]
                == bytes32("6hSbTbwcGhgRGtxQ6iH2aWBhqRzGwhNBPCVDCBZ1fAxp")?
            && members[0]["bootstrap"]["slot_complete"] == true
            && members[0]["terminal"]["slot_complete"] == true
            && members[0]["terminal"]["slot"]
                .as_u64()
                .is_some_and(|n| (90719638..=90719999).contains(&n))
            && v["outcome"]["kind"] == "committed"
            && published.len() == 1
            && published[0]["epoch"] == 209
            && published[0]["archive_sha256"] == a.sha256_hex
            && v["destination"]["path_base64"]
                == BASE64_STANDARD.encode(
                    a.archive_path
                        .parent()
                        .context("209 committed output parent")?
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
        "209 cohort receipt does not preserve canonical root, native terminal and exact committed archive"
    );
    let encoded = v["publication_context_base64"]
        .as_str()
        .context("209 bound cohort context")?;
    let raw = BASE64_STANDARD.decode(encoded)?;
    ensure!(
        raw.len() <= 4 << 20 && BASE64_STANDARD.encode(&raw) == encoded,
        "209 cohort context bounds/encoding"
    );
    let context: Value = serde_json::from_slice(&raw)?;
    let fingerprint: Vec<u8> = serde_json::from_value(context["manifest_fingerprint"].clone())?;
    ensure!(
        context["schema"] == "jetstreamer-root-checkpoint-gate-context-v1"
            && context["epochs"] == json!([209])
            && context["gate"] == *gate
            && format!("sha256:{}", hex_lower(&fingerprint)) == c::FINGERPRINT,
        "209 cohort context lost its exact root/manifest binding"
    );
    Ok(())
}
pub(super) fn source_terminal(launch: &Value) -> Result<Value> {
    let iid = launch["evidence"]["units"][0]["invocation_id"]
        .as_str()
        .context("209 source IID")?;
    let u = unit(c::UNIT)?;
    ensure!(
        u["Id"] == c::UNIT
            && u["LoadState"] == "loaded"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && (u["InvocationID"] == iid || u["InvocationID"] == "")
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0"
            && c::same_command(&u["ExecStart"]),
        "209 producer is not its exact successful terminal owner"
    );
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            c::UNIT,
            "_PID=1",
            "--output=json",
            "--no-pager",
            "--lines=256",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "209 terminal manager history unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let selected = terminal_history(&rows, iid)?;
    Ok(
        json!({"manager":u,"events":selected,"journal_sha256":hex_lower(&Sha256::digest(&out.stdout))}),
    )
}
fn terminal_history(rows: &[Value], iid: &str) -> Result<Vec<Value>> {
    terminal_history_for(rows, c::UNIT, iid)
}
pub(super) fn terminal_history_for(rows: &[Value], name: &str, iid: &str) -> Result<Vec<Value>> {
    ensure!(
        !rows.is_empty() && rows.len() < 256,
        "209 manager history truncated/empty"
    );
    let own = rows
        .iter()
        .filter(|r| r["_PID"] == "1" && r["_UID"] == "0" && r["UNIT"] == name)
        .collect::<Vec<_>>();
    let starts = own
        .iter()
        .filter(|r| {
            r["INVOCATION_ID"] == iid
                && r["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("Started {} -", name)))
        })
        .collect::<Vec<_>>();
    let ends = own
        .iter()
        .filter(|r| {
            r["INVOCATION_ID"] == iid
                && r["MESSAGE"] == format!("{}: Deactivated successfully.", name)
        })
        .collect::<Vec<_>>();
    ensure!(
        starts.len() == 1 && ends.len() == 1,
        "209 exact PID1 start/clean terminal proof missing or duplicate"
    );
    let clock = |r: &Value| -> Result<u64> {
        Ok(r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("209 manager clock")?
            .parse()?)
    };
    let start = clock(starts[0])?;
    ensure!(
        clock(ends[0])? > start
            && own
                .iter()
                .all(|r| clock(r).is_ok_and(|t| t < start || r["INVOCATION_ID"] == iid)),
        "209 manager outcome reordered or producer replaced"
    );
    Ok(vec![(*starts[0]).clone(), (*ends[0]).clone()])
}
fn stage_owner(stage: Stage, binding: &BoundFile, self_sha: &str) -> Result<Value> {
    let iid =
        env::var("INVOCATION_ID").context("209 delivery must have its own systemd invocation")?;
    ensure!(is_lower_hex(&iid, 32), "209 delivery IID invalid");
    let p = unit(stage.unit())?;
    let exe = env::current_exe()?;
    let command = format!(
        "{{ path={} ; argv[]={} deliver-singleton209-output {} --spec-sha256 {} --self-sha256 {}",
        exe.display(),
        exe.display(),
        binding.path.display(),
        binding.sha256,
        self_sha
    );
    ensure!(
        p["Id"] == stage.unit()
            && p["InvocationID"] == iid
            && p["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok())
                == Some(std::process::id())
            && p["NRestarts"] == "0"
            && p["ActiveState"] == "active"
            && matches!(p["SubState"].as_str(), Some("running" | "start"))
            && p["ExecStart"]
                .as_str()
                .and_then(|s| s.split_once(" ; ignore_errors="))
                .is_some_and(|(s, _)| s == command),
        "209 delivery lacks its actual exact stage owner"
    );
    Ok(p)
}
fn prior(
    binding: Option<&BoundFile>,
    stage: Stage,
    s: &Spec,
    a: &LocalArchive,
    self_sha: &str,
) -> Result<Value> {
    let b = binding.context("209 required independent verification receipt missing")?;
    let v = native209::immutable_json(b)?;
    ensure!(
        v["schema"] == SCHEMA
            && v["stage"] == stage.name()
            && v["epoch"] == 209
            && v["status"] == "passed"
            && v["exit_code"] == 0
            && v["archive"] == pair_identity(a)
            && v["launch"] == private157::binding(&s.launch)
            && v["cohort_publication"] == private157::binding(&s.cohort_publication)
            && v["self_sha256"] == self_sha
            && v["local_retirement_authorized"] == false
            && v["r2_mutations"] == false
            && v["full_slot_coverage"] == 432000,
        "209 independent verification receipt is stale, foreign or incomplete"
    );
    let tools = v["tool_evidence"]
        .as_array()
        .context("209 independent tool receipts missing")?;
    let archive = a
        .archive_path
        .to_str()
        .context("209 archive UTF8")?
        .to_owned();
    let (tool, sha, arguments) = if stage == Stage::Full {
        (
            Path::new(TOOLS).join("verify_archive"),
            FULL_SHA,
            vec![
                vec![
                    archive.clone(),
                    "--full".into(),
                    "--internal-full".into(),
                    "--threads".into(),
                    "8".into(),
                ],
                vec![archive, "--threads".into(), "8".into()],
            ],
        )
    } else {
        ensure!(
            stage == Stage::Plugin
                && v["full_verification"]
                    == s.full_verification
                        .as_ref()
                        .map(private157::binding)
                        .unwrap_or(Value::Null),
            "209 plugin receipt lost exact full-verification handoff"
        );
        (
            Path::new(TOOLS).join("horizon_pipeline"),
            PLUGIN_SHA,
            vec![vec![
                "209:209".into(),
                a.archive_path
                    .parent()
                    .context("209 archive parent")?
                    .to_str()
                    .context("209 parent UTF8")?
                    .into(),
                "--threads".into(),
                "8".into(),
                "--verify-only".into(),
            ]],
        )
    };
    ensure!(
        tools.len() == arguments.len(),
        "209 independent tool receipt count differs"
    );
    for (result, args) in tools.iter().zip(arguments) {
        let log = Path::new(result["log"].as_str().context("209 tool log missing")?);
        ensure!(
            log.parent() == b.path.parent(),
            "209 independent log escaped its receipt directory"
        );
        resource_verify::validate_bound_child(result, &tool, sha, &args)?;
        if stage == Stage::Full {
            full_span(log)?;
        }
    }
    Ok(v)
}
fn hash_pair(a: &LocalArchive) -> Result<()> {
    ensure!(
        regular_identity(&a.archive_path)? == a.identity
            && regular_identity(&a.sidecar_path)? == a.sidecar_identity,
        "209 verification pair changed identity"
    );
    ensure!(
        hash_and_etag(&a.archive_path, a.identity, 64 << 20)?.sha256_hex == a.sha256_hex,
        "209 archive differs from canonical sidecar"
    );
    ensure!(
        read_local_archive(a.archive_path.parent().context("209 archive parent")?, 209)?.sidecar
            == a.sidecar,
        "209 sidecar changed"
    );
    Ok(())
}
fn full_span(log: &Path) -> Result<()> {
    let bytes = read_stable_bounded(log, 64 << 20, "209 verifier full-span log")?;
    let text = std::str::from_utf8(&bytes)?;
    ensure!(
        text.contains("epoch=209 slot_start=90288000 slot_count=432000 "),
        "209 verifier did not scan the complete singleton span"
    );
    Ok(())
}
pub(super) fn lock() -> Result<File> {
    let path = Path::new(LOCK);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o077 == 0 && path.canonicalize()? == path,
        "209 upload lock unsafe"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "209 shared upload lock is busy/unavailable"
    );
    let current = fs::symlink_metadata(path)?;
    ensure!(
        current.dev() == m.dev() && current.ino() == m.ino(),
        "209 upload lock namespace changed"
    );
    Ok(file)
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("deliver-singleton209-output")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch209-singleton-delivery-spec-v1"
            && s.r2_mutations == (s.stage == Stage::Upload)
            && s.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && s.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-209-singleton-delivery-"))
            && s.r2_receipt_directory == Path::new(R2_RECEIPTS)
            && s.upload_lock == Path::new(LOCK),
        "209 delivery spec scope differs"
    );
    let receipt = s.output_directory.join(format!("{}.json", s.stage.name()));
    validate_output_destination(&receipt)?;
    let launch = native209::immutable_json(&s.launch)?;
    let (_, checked_launch) = full209_status::claim(&s.launch)?;
    ensure!(
        checked_launch == launch,
        "209 delivery launch changed while validating its actual first guard"
    );
    let producer = source_terminal(&launch)?;
    let owner = stage_owner(s.stage, &binding, &self_sha)?;
    let output = Path::new(c::ROOT).join("output");
    ensure!(
        output.canonicalize()? == output,
        "209 delivery output redirected"
    );
    let a = read_local_archive(&output, 209)?;
    cohort(&native209::immutable_json(&s.cohort_publication)?, &a)?;
    let mut evidence = Vec::new();
    let mut remote = Value::Null;
    let _upload_lock = if s.stage == Stage::Upload {
        Some(lock()?)
    } else {
        None
    };
    match s.stage {
        Stage::Full => {
            ensure!(
                s.full_verification.is_none() && s.plugin_verification.is_none(),
                "209 full stage borrowed receipts"
            );
            hash_pair(&a)?;
            let tool = Path::new(TOOLS).join("verify_archive");
            for (name, args) in [
                (
                    "full-poh",
                    vec![
                        a.archive_path
                            .to_str()
                            .context("209 archive UTF8")?
                            .to_owned(),
                        "--full".into(),
                        "--internal-full".into(),
                        "--threads".into(),
                        "8".into(),
                    ],
                ),
                (
                    "ordered",
                    vec![
                        a.archive_path
                            .to_str()
                            .context("209 archive UTF8")?
                            .to_owned(),
                        "--threads".into(),
                        "8".into(),
                    ],
                ),
            ] {
                let log = s.output_directory.join(format!("{name}.log"));
                evidence.push(resource_verify::run_bound_child(
                    &tool, FULL_SHA, &args, &log,
                )?);
                full_span(&log)?;
            }
            hash_pair(&a)?;
        }
        Stage::Plugin => {
            ensure!(
                s.plugin_verification.is_none(),
                "209 plugin stage borrowed its own receipt"
            );
            prior(s.full_verification.as_ref(), Stage::Full, &s, &a, &self_sha)?;
            hash_pair(&a)?;
            evidence.push(resource_verify::run_bound_child(
                &Path::new(TOOLS).join("horizon_pipeline"),
                PLUGIN_SHA,
                &[
                    "209:209".into(),
                    output.to_str().context("209 output UTF8")?.into(),
                    "--threads".into(),
                    "8".into(),
                    "--verify-only".into(),
                ],
                &s.output_directory.join("plugin.log"),
            )?);
            hash_pair(&a)?;
        }
        Stage::Upload => {
            prior(s.full_verification.as_ref(), Stage::Full, &s, &a, &self_sha)?;
            prior(
                s.plugin_verification.as_ref(),
                Stage::Plugin,
                &s,
                &a,
                &self_sha,
            )?;
            ensure!(
                regular_identity(&a.archive_path)? == a.identity,
                "209 upload source changed"
            );
            let status = ProcessCommand::new(env::current_exe()?)
                .arg("sync")
                .arg(&output)
                .args([
                    "--epochs",
                    "209-209",
                    "--receipt-directory",
                    R2_RECEIPTS,
                    "--legacy-part-size-mib",
                    "5",
                ])
                .status()?;
            ensure!(
                status.success(),
                "209 authenticated sync failed; preserve local pair and receipts"
            );
            let path = Path::new(R2_RECEIPTS).join("epoch-209.r2.json");
            let bytes = read_stable_bounded(&path, 1 << 20, "209 authenticated delivery receipt")?;
            let r: Receipt = serde_json::from_slice(&bytes)?;
            ensure!(
                r.schema == RECEIPT_SCHEMA
                    && r.epoch == 209
                    && r.archive_key == "epoch-209.jet"
                    && r.checksum_key == "epoch-209.jet.sha256"
                    && r.archive_sha256 == a.sha256_hex
                    && r.archive_length == a.length
                    && r.remote_sha256_readback,
                "209 authenticated receipt lacks complete whole-object readback"
            );
            remote = json!({"path":path,"sha256":hex_lower(&Sha256::digest(&bytes)),"receipt":r});
        }
    }
    ensure!(
        pair_identity(&read_local_archive(&output, 209)?) == pair_identity(&a),
        "209 delivery pair changed"
    );
    source_terminal(&launch)?;
    ensure!(
        owner == stage_owner(s.stage, &binding, &self_sha)?,
        "209 delivery stage owner changed"
    );
    let v = json!({"schema":SCHEMA,"epoch":209,"stage":s.stage.name(),"status":"passed","exit_code":0,"archive":pair_identity(&a),
        "launch":private157::binding(&s.launch),"cohort_publication":private157::binding(&s.cohort_publication),"producer_terminal":producer,"owner":owner,
        "full_verification":s.full_verification.as_ref().map(private157::binding),"plugin_verification":s.plugin_verification.as_ref().map(private157::binding),
        "tool_evidence":evidence,"authenticated_r2":remote,"full_slot_coverage":432000,"canonical_root_slot":90719638u64,"post_root_slot_count":361,
        "spec":private157::binding(&binding),"self_sha256":self_sha,"local_retirement_authorized":false,"archive_mutations":false,"r2_mutations":s.r2_mutations,
        "resource_samples_taken":0,"completed_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()});
    private157::immutable_receipt(&receipt, &v)
}
#[cfg(test)]
mod tests {
    use super::*;
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
            epoch: 209,
            archive_path: Path::new(c::ROOT).join("output/epoch-209.jet"),
            sidecar_path: Path::new(c::ROOT).join("output/epoch-209.jet.sha256"),
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
            "verified_manifest_checkpoints":[{"slot":90719638u64,"accounts_hash":bytes32("3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ").unwrap()}],
            "members":[{"epoch":209,"bootstrap":summary(90287519,bytes32("6hSbTbwcGhgRGtxQ6iH2aWBhqRzGwhNBPCVDCBZ1fAxp").unwrap()),"terminal":summary(90719999,json!(vec![2u8;32]))}]});
        let hex = c::FINGERPRINT.strip_prefix("sha256:").unwrap();
        let fingerprint = (0..32)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let context = json!({"schema":"jetstreamer-root-checkpoint-gate-context-v1","manifest_fingerprint":fingerprint,"epochs":[209],"gate":gate});
        let receipt = json!({"schema":"jetstreamer-root-cohort-publication-receipt-v2","manifest_fingerprint":c::FINGERPRINT,"epochs":[209],"root_checkpoint_gate":gate,
            "publication_context_base64":BASE64_STANDARD.encode(serde_json::to_vec(&context).unwrap()),
            "destination":{"path_base64":BASE64_STANDARD.encode(a.archive_path.parent().unwrap().as_os_str().as_bytes())},
            "outcome":{"kind":"committed","members":[{"epoch":209,"archive_sha256":a.sha256_hex,
                "archive_path_base64":BASE64_STANDARD.encode(a.archive_path.as_os_str().as_bytes()),"checksum_path_base64":BASE64_STANDARD.encode(a.sidecar_path.as_os_str().as_bytes()),
                "committed_archive":{"device":id.device,"inode":id.inode,"length":id.length}}]}});
        (a, receipt)
    }
    #[test]
    fn committed_cohort_requires_its_own_root_native_terminal_context_and_exact_archive() {
        let (a, v) = fixture();
        cohort(&v, &a).unwrap();
        for pointer in [
            "/schema",
            "/manifest_fingerprint",
            "/epochs",
            "/publication_context_base64",
            "/outcome/kind",
            "/outcome/members/0/archive_sha256",
            "/outcome/members/0/committed_archive/inode",
            "/root_checkpoint_gate/verified_manifest_checkpoints/0/slot",
            "/root_checkpoint_gate/verified_manifest_checkpoints/0/accounts_hash",
            "/root_checkpoint_gate/members/0/bootstrap/accounts_hash",
            "/root_checkpoint_gate/members/0/terminal/slot_complete",
            "/root_checkpoint_gate/members/0/terminal/bank_hash",
            "/root_checkpoint_gate/members/0/terminal/next_write_version",
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(cohort(&bad, &a).is_err(), "{pointer}");
        }
        let mut bad = v.clone();
        bad["root_checkpoint_gate"]["members"][0]["terminal"]["slot"] = json!(90719637u64);
        assert!(cohort(&bad, &a).is_err());
    }
    #[test]
    fn pid1_history_requires_one_clean_original_terminal_and_no_later_owner() {
        let iid = "a".repeat(32);
        let event = |time: &str, message: String| json!({"_PID":"1","_UID":"0","UNIT":c::UNIT,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":time,"MESSAGE":message});
        let rows = vec![
            event("100", format!("Started {} - Original singleton.", c::UNIT)),
            event("200", format!("{}: Deactivated successfully.", c::UNIT)),
        ];
        terminal_history(&rows, &iid).unwrap();
        assert!(terminal_history(&rows, &"b".repeat(32)).is_err());
        for i in 0..2 {
            let mut bad = rows.clone();
            bad.remove(i);
            assert!(terminal_history(&bad, &iid).is_err());
        }
        let mut bad = rows.clone();
        bad.push(rows[1].clone());
        assert!(terminal_history(&bad, &iid).is_err());
        let mut bad = rows.clone();
        bad[1]["__REALTIME_TIMESTAMP"] = json!("99");
        assert!(terminal_history(&bad, &iid).is_err());
        let mut bad = rows;
        let mut next = event("300", format!("Started {} - Replacement.", c::UNIT));
        next["INVOCATION_ID"] = json!("b".repeat(32));
        bad.push(next);
        assert!(terminal_history(&bad, &iid).is_err());
    }
    #[test]
    fn span_evidence_cannot_borrow_a_root_only_or_prefix_archive() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("scan.log");
        fs::write(&p,"full PoH verify: epoch=209 slot_start=90288000 slot_count=432000 buckets=3375 threads=8\n").unwrap();
        full_span(&p).unwrap();
        fs::write(&p,"full PoH verify: epoch=209 slot_start=90288000 slot_count=431639 buckets=3373 threads=8\n").unwrap();
        assert!(full_span(&p).is_err());
    }
}
