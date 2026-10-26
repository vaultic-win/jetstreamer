//! Exact immutable parent CLI probes. The absent snapshot gate precedes Bank restore
//! and worker creation; passing this command never admits or starts the replay.
use super::*;
use std::os::unix::process::CommandExt;

const SCHEMA: &str = "jetstreamer-private-bounded228-parent-cli-capability-v1";
const PROBE_ROOT: &str = "/home/ubuntu/.jetstreamer-private/bounded228-parent-capability-v1";
const RECEIPT: &str =
    "/var/lib/jetstreamer/horizon-bounded228-parent-capability-v1/capability.json";
const WORKER: &str = "/var/lib/jetstreamer/horizon-228-capped-candidate-1bfa8d51-v1/jetstreamer-historical-worker-v1-6-20";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    output: PathBuf,
}

fn arguments(foreign: bool) -> Vec<String> {
    vec![
        if foreign { "228-229" } else { "228" }.into(),
        format!("{PROBE_ROOT}/ledger"),
        "--verify".into(),
        format!("--qualification-end-slot={TERMINAL}"),
        format!("--snapshot-archive={PROBE_ROOT}/absent/{SNAPSHOT}"),
        format!("--epoch-hashes={CHECKPOINTS}"),
        format!("--horizon-output={PROBE_ROOT}/output/{ARCHIVE}"),
        format!("--replay-scratch={PROBE_ROOT}/scratch"),
    ]
}

fn validate_log(foreign: bool, exit: i64, log: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(log)?;
    ensure!(log.len() <= 1 << 20, "bounded228 CLI log exceeds its bound");
    let required = if foreign {
        ensure!(exit == 2, "bounded228 foreign range did not fail at CLI");
        vec!["--qualification-end-slot requires one epoch, not 228-229".into()]
    } else {
        ensure!(
            exit == 1,
            "bounded228 exact route did not fail at absent snapshot"
        );
        vec![
            format!(
                "focused qualification requested: epoch 228, bootstrap {BOOTSTRAP}, replay {}..={TERMINAL}",
                BOOTSTRAP + 1
            ),
            format!(
                "epoch 228: selected execution profile solana-v1.6.20 (Candidate) from slots {FIRST}..{}",
                TERMINAL + 1
            ),
            "execution=solana-v1.6.20-epochs-216-232-checkpoint-candidate".into(),
            format!("failed to read snapshot {PROBE_ROOT}/absent/{SNAPSHOT}"),
        ]
    };
    for marker in required {
        ensure!(
            text.contains(&marker),
            "bounded228 exact no-worker gate missing: {marker}"
        );
    }
    for denied in [
        "replaying",
        "progress slot ",
        "historical_worker_native_snapshot",
        "archive finalized",
    ] {
        ensure!(
            !text.to_ascii_lowercase().contains(denied),
            "bounded228 capability unexpectedly executed replay"
        );
    }
    Ok(())
}

fn receipt_scope(v: &Value, helper: &str) -> Result<()> {
    ensure!(
        v["schema"] == SCHEMA
            && v["scope"] == scope()
            && v["parent"] == private157::binding(&binding(NODE, NODE_SHA))
            && v["worker"] == private157::binding(&binding(WORKER, WORKER_SHA))
            && v["intended_exec_start"] == command()
            && v["intended_environment"] == json!(environment())
            && v["probe_root"] == PROBE_ROOT
            && v["helper_sha256"] == helper
            && is_lower_hex(helper, 64)
            && v["invocation_id"].as_str().is_some_and(private_prefix::iid)
            && v["exact_parent_cli_route_observed"] == true
            && v["snapshot_intentionally_absent"] == true
            && v["all_immutable_inputs_rehashed"] == true
            && v["worker_spawned"] == false
            && v["snapshot_restored"] == false
            && v["archive_created"] == false
            && v["producer_started"] == false
            && v["replay_launch_authorized"] == false
            && v["native_input_qualified"] == false
            && v["entry_replay"] == false
            && v["snapshot_schema_or_contents_tested"] == false
            && v["fresh_resource_admission_passed"] == false
            && v["resource_samples_taken"] == 0
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "bounded228 parent capability is foreign or claims execution authority"
    );
    deny_authority(v)
}

pub(super) fn validate(v: &Value, helper: &str) -> Result<()> {
    receipt_scope(v, helper)?;
    let rows = v["probes"]
        .as_array()
        .context("bounded228 CLI probes absent")?;
    ensure!(
        rows.len() == 2,
        "bounded228 needs both exact negative CLI probes"
    );
    for (row, foreign) in rows.iter().zip([true, false]) {
        ensure!(
            row["argv"] == json!(arguments(foreign))
                && row["child_pid"].as_u64().is_some_and(|n| n > 1)
                && row["started_unix_seconds"]
                    .as_u64()
                    .zip(row["exited_unix_seconds"].as_u64())
                    .is_some_and(|(a, b)| a > 0 && b >= a && b - a <= 600),
            "bounded228 actual child command, PID, or bounded lifetime differs"
        );
        let b: BoundFile = serde_json::from_value(row["log"].clone())?;
        let expected = Path::new(RECEIPT).parent().unwrap().join(if foreign {
            "foreign-range.log"
        } else {
            "exact-route.log"
        });
        ensure!(
            b.path == expected,
            "bounded228 CLI log escaped sealed capability tree"
        );
        let m = fs::symlink_metadata(&b.path)?;
        ensure!(
            b.path.canonicalize()? == b.path
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o222 == 0,
            "bounded228 CLI log is not immutable root evidence"
        );
        let bytes = read_stable_bounded(&b.path, 1 << 20, "bounded228 CLI evidence log")?;
        ensure!(
            hex_lower(&Sha256::digest(&bytes)) == b.sha256,
            "bounded228 CLI log changed"
        );
        validate_log(
            foreign,
            row["exit_status"]
                .as_i64()
                .context("bounded228 CLI exit absent")?,
            &bytes,
        )?;
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let raw = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(raw.as_ptr(), 1000, 1000) } == 0,
        "bounded228 probe chown failed"
    );
    File::open(path.parent().context("bounded228 probe parent absent")?)?.sync_all()?;
    Ok(())
}

fn write_log(path: &Path, bytes: &[u8]) -> Result<BoundFile> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("bounded228 log parent absent")?)?.sync_all()?;
    Ok(binding(
        path.to_str().context("bounded228 log UTF8")?,
        &hex_lower(&Sha256::digest(bytes)),
    ))
}

pub(super) fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "bounded228 capability must run as root"
    );
    let (bound, helper) = publication203::parsed_args("probe-bounded228-parent")?;
    let spec: Spec = serde_json::from_value(native209::immutable_json(&bound)?)?;
    ensure!(
        spec.schema == "jetstreamer-bounded228-parent-cli-capability-spec-v1"
            && spec.output == Path::new(RECEIPT),
        "bounded228 capability spec differs"
    );
    if spec.output.try_exists()? {
        let old = native209::immutable_json(&serde_json::from_value(private157::file_binding(
            &spec.output,
        )?)?)?;
        ensure!(
            old["spec"] == private157::binding(&bound),
            "bounded228 capability retry spec differs"
        );
        return validate(&old, &helper);
    }
    validate_output_destination(&spec.output)?;
    let parent = Path::new(PROBE_ROOT).parent().unwrap();
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.is_dir() && m.uid() == 1000 && m.mode() & 0o077 == 0,
        "bounded228 probe parent is not canonical owner-private"
    );
    for (path, sha, bytes) in [
        (PathBuf::from(NODE), NODE_SHA, 48_793_368),
        (PathBuf::from(WORKER), WORKER_SHA, 8_974_448),
        (
            Path::new(PACKAGE).join(SNAPSHOT),
            SNAPSHOT_SHA,
            10_510_540_911,
        ),
        (PathBuf::from(CHECKPOINTS), CHECKPOINTS_SHA, 126),
    ] {
        native209_admission::sealed_file(&path, sha, Some(bytes))?;
    }
    private_directory(Path::new(PROBE_ROOT))?;
    for directory in ["ledger", "scratch", "output", "run-state"] {
        private_directory(&Path::new(PROBE_ROOT).join(directory))?;
    }
    let mut rows = Vec::new();
    for foreign in [true, false] {
        let args = arguments(foreign);
        let started = now()?;
        let mut cmd = ProcessCommand::new(NODE);
        cmd.args(&args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(
                "JETSTREAMER_PRIVATE_RUN_ROOT",
                format!("{PROBE_ROOT}/run-state"),
            );
        for e in environment() {
            let (k, v) = e.split_once('=').context("bounded228 env malformed")?;
            cmd.env(k, v);
        }
        unsafe {
            cmd.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(1000) != 0
                    || libc::setuid(1000) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = cmd.spawn()?;
        let pid = child.id();
        let out = child.wait_with_output()?;
        let exited = now()?;
        let exit = out
            .status
            .code()
            .context("bounded228 CLI probe was signaled")?;
        let length = out
            .stdout
            .len()
            .checked_add(out.stderr.len())
            .context("bounded228 CLI log size overflow")?;
        ensure!(length <= 1 << 20, "bounded228 CLI log exceeded bound");
        let mut bytes = out.stdout;
        bytes.extend_from_slice(&out.stderr);
        validate_log(foreign, i64::from(exit), &bytes)?;
        ensure!(
            exited >= started && exited - started <= 600,
            "bounded228 CLI probe lifetime exceeded"
        );
        for d in ["scratch", "output"] {
            ensure!(
                fs::read_dir(Path::new(PROBE_ROOT).join(d))?
                    .next()
                    .is_none(),
                "bounded228 capability unexpectedly created replay artifacts"
            );
        }
        let log = write_log(
            &spec.output.parent().unwrap().join(if foreign {
                "foreign-range.log"
            } else {
                "exact-route.log"
            }),
            &bytes,
        )?;
        rows.push(json!({"argv":args,"child_pid":pid,"started_unix_seconds":started,"exited_unix_seconds":exited,"exit_status":exit,"log":private157::binding(&log)}));
    }
    let mut receipt = json!({"schema":SCHEMA,"scope":scope(),"parent":private157::binding(&binding(NODE,NODE_SHA)),"worker":private157::binding(&binding(WORKER,WORKER_SHA)),
        "intended_exec_start":command(),"intended_environment":environment(),"probe_root":PROBE_ROOT,
        "helper_sha256":helper,"invocation_id":env::var("INVOCATION_ID")?,"spec":private157::binding(&bound),"probes":rows,
        "exact_parent_cli_route_observed":true,"snapshot_intentionally_absent":true,"all_immutable_inputs_rehashed":true,
        "worker_spawned":false,"snapshot_restored":false,"archive_created":false,"producer_started":false,
        "replay_launch_authorized":false,"native_input_qualified":false,"entry_replay":false,
        "snapshot_schema_or_contents_tested":false,"fresh_resource_admission_passed":false,
        "resource_samples_taken":0,"remote_mutations":false,"r2_mutations":false});
    deny_fields(&mut receipt);
    validate(&receipt, &helper)?;
    private157::immutable_receipt(&spec.output, &receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capability_cannot_borrow_another_parent_worker_or_qualification_scope() {
        let helper = "a".repeat(64);
        let mut v = json!({"schema":SCHEMA,"scope":scope(),"parent":private157::binding(&binding(NODE,NODE_SHA)),
            "worker":private157::binding(&binding(WORKER,WORKER_SHA)),"intended_exec_start":command(),"intended_environment":environment(),
            "probe_root":PROBE_ROOT,"helper_sha256":helper,"invocation_id":"b".repeat(32),
            "exact_parent_cli_route_observed":true,"snapshot_intentionally_absent":true,"all_immutable_inputs_rehashed":true,
            "worker_spawned":false,"snapshot_restored":false,"archive_created":false,"producer_started":false,
            "replay_launch_authorized":false,"native_input_qualified":false,"entry_replay":false,
            "snapshot_schema_or_contents_tested":false,"fresh_resource_admission_passed":false,
            "resource_samples_taken":0,"remote_mutations":false,"r2_mutations":false});
        deny_fields(&mut v);
        receipt_scope(&v, &helper).unwrap();
        for (pointer, bad) in [
            ("/parent/sha256", json!("0".repeat(64))),
            ("/worker/path", json!("/sealed/epoch227-worker")),
            ("/scope/terminal_root_slot", json!(98927999)),
            ("/worker_spawned", json!(true)),
            ("/native_input_qualified", json!(true)),
            ("/fresh_resource_admission_passed", json!(true)),
            ("/replay_launch_authorized", json!(true)),
            ("/helper_sha256", json!("c".repeat(64))),
        ] {
            let mut changed = v.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(receipt_scope(&changed, &helper).is_err(), "{pointer}");
        }
    }
    #[test]
    fn exact_parent_requires_actual_candidate_route_and_snapshot_gate() {
        let text = format!(
            "focused qualification requested: epoch 228, bootstrap {BOOTSTRAP}, replay {}..={TERMINAL}\nepoch 228: selected execution profile solana-v1.6.20 (Candidate) from slots {FIRST}..{}\nexecution=solana-v1.6.20-epochs-216-232-checkpoint-candidate\nfailed to read snapshot {PROBE_ROOT}/absent/{SNAPSHOT}",
            BOOTSTRAP + 1,
            TERMINAL + 1
        );
        validate_log(false, 1, text.as_bytes()).unwrap();
        for bad in [
            text.replace("solana-v1.6.20 (Candidate)", "solana-v1.6.25 (Candidate)"),
            text.replace("98928279", "98927999"),
            format!("{text}\nprogress slot 98496001/98928278"),
        ] {
            assert!(validate_log(false, 1, bad.as_bytes()).is_err());
        }
        assert!(validate_log(false, 0, text.as_bytes()).is_err());
        validate_log(
            true,
            2,
            b"--qualification-end-slot requires one epoch, not 228-229",
        )
        .unwrap();
        assert!(
            validate_log(
                true,
                1,
                b"--qualification-end-slot requires one epoch, not 228-229"
            )
            .is_err()
        );
    }
}
