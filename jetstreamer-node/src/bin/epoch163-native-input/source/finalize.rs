//! Original restore owner must already have completed and drained. No scan or replay.
#[allow(dead_code)]
mod epoch141_ledger_common;
use anyhow::{Context, Result, ensure};
use epoch141_ledger_common::{bound_file, sha, write_receipt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
const UNIT: &str = "horizon-epoch163-native-input-20261106-v1.service";
const PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,ExecStart,Type,User,Restart,RemainAfterExit,KillMode,MemoryMax,MemorySwapMax";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    native_plan: Bound,
    native_outcome: Bound,
    acceptance: PathBuf,
    original_completion: PathBuf,
}
fn command(args: &[&str]) -> Result<Vec<u8>> {
    let o = Command::new("/usr/bin/timeout")
        .args(["--signal=TERM", "--kill-after=2s", "8s"])
        .args(args)
        .env_remove("SYSTEMD_HOST")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env("LC_ALL", "C")
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 1 << 20 && o.stderr.len() <= 1 << 20,
        "bounded native completion query failed"
    );
    Ok(o.stdout)
}
fn native() -> Result<Vec<u8>> {
    command(&[
        "/usr/bin/systemctl",
        "show",
        UNIT,
        &format!("--property={PROPERTIES}"),
    ])
}
fn completed(raw: &[u8], iid: &str) -> Result<()> {
    let fields = std::str::from_utf8(raw)?
        .lines()
        .map(|s| s.split_once('=').context("native framing"))
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        fields.keys().copied().collect::<Vec<_>>()
            == PROPERTIES
                .split(',')
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
            && std::str::from_utf8(raw)?.lines().count() == fields.len(),
        "native completion field census"
    );
    for (k, v) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("InvocationID", iid),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ControlGroup", ""),
        ("Type", "exec"),
        ("User", "root"),
        ("Restart", "no"),
        ("RemainAfterExit", "yes"),
        ("KillMode", "control-group"),
        ("MemoryMax", "137438953472"),
        ("MemorySwapMax", "0"),
    ] {
        ensure!(
            fields.get(k) == Some(&v),
            "original completion property {k}"
        );
    }
    Ok(())
}
fn original_command(raw: &[u8], program: &Bound, plan: &Bound) -> Result<()> {
    let text = std::str::from_utf8(raw)?;
    let commands = text
        .lines()
        .filter_map(|line| line.strip_prefix("ExecStart="))
        .collect::<Vec<_>>();
    ensure!(commands.len() == 1, "one original native command required");
    let (command, suffix) = commands[0]
        .split_once(" ; ignore_errors=")
        .context("native command framing")?;
    let image = program.path.to_str().context("native image UTF-8")?;
    let plan_path = plan.path.to_str().context("native plan UTF-8")?;
    ensure!(
        program.path.is_absolute()
            && plan.path.is_absolute()
            && !image.chars().any(char::is_whitespace)
            && !plan_path.chars().any(char::is_whitespace)
            && program.sha256.len() == 64
            && plan.sha256.len() == 64,
        "bounded native command paths and digests"
    );
    let expected = format!(
        "{{ path={image} ; argv[]={image} {plan_path} --plan-sha256 {} --self-sha256 {}",
        plan.sha256, program.sha256
    );
    ensure!(
        command == expected && suffix.starts_with("no ; "),
        "original native command or error policy crossed"
    );
    Ok(())
}
fn admission_lineage(admission: &Value, original: &Value, plan: &Bound, iid: &str) -> Result<()> {
    ensure!(
        admission["schema"] == "epoch163-native-input-admission-v2"
            && admission["admitted"] == true
            && admission["plan"] == json!({"path":plan.path,"sha256":plan.sha256})
            && admission["program"] == original["program"]
            && admission["issuer"] == original["admission_program"]
            && admission["worker"] == original["worker"]
            && admission["download"] == original["download"]
            && admission["actor_invocation_id"] == iid
            && admission["actor_pid"].as_u64().is_some_and(|pid| pid > 1)
            && admission["actor_memory_bytes"] == 128u64 << 30
            && admission["native_restore_only"] == true
            && admission["replay_launch_authorized"] == false
            && admission["publication_authorized"] == false
            && admission["remote_mutations"] == false
            && admission["r2_mutations"] == false,
        "original admitted native lineage required"
    );
    Ok(())
}
// Recover only a complete byte-identical receipt after revalidating the same
// original owner. Partial or conflicting files are preserved and fail closed.
fn write_or_recover(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    let directory = fs::symlink_metadata(parent)?;
    ensure!(
        path.is_absolute()
            && parent.canonicalize()? == parent
            && directory.is_dir()
            && directory.uid() == 0
            && directory.mode() & 0o077 == 0,
        "receipt recovery requires canonical Root-private parent"
    );
    let mut expected = serde_json::to_vec_pretty(value)?;
    expected.push(b'\n');
    ensure!(expected.len() <= 1 << 20, "receipt recovery size ceiling");
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return write_receipt(path, value);
        }
        Err(error) => return Err(error.into()),
    };
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o777 == 0o600
            && before.len() == expected.len() as u64,
        "unsafe or partial existing receipt"
    );
    let mut actual = Vec::new();
    Read::by_ref(&mut file)
        .take((1 << 20) + 1)
        .read_to_end(&mut actual)?;
    ensure!(
        actual == expected
            && epoch141_ledger_common::identity(&before)
                == epoch141_ledger_common::identity(&file.metadata()?)
            && epoch141_ledger_common::identity(&before)
                == epoch141_ledger_common::identity(&fs::symlink_metadata(path)?),
        "existing receipt differs or changed; preserve it"
    );
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn retired_identity(expected: u64, observed: Option<u64>) -> Result<()> {
    ensure!(
        expected > 0 && observed != Some(expected),
        "original worker identity still exists"
    );
    Ok(())
}
fn original_worker_retired(outcome: &Value) -> Result<()> {
    let pid = outcome["worker_pid"]
        .as_u64()
        .context("original worker PID")?;
    let ticks = outcome["worker_start_ticks"]
        .as_u64()
        .context("original worker ticks")?;
    ensure!(
        (2..=i32::MAX as u64).contains(&pid),
        "original worker PID bounds"
    );
    let observed = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(raw) => Some(
            raw.rsplit_once(") ")
                .context("current worker stat framing")?
                .1
                .split_whitespace()
                .nth(19)
                .context("current worker start ticks")?
                .parse::<u64>()?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    retired_identity(ticks, observed)?;
    eprintln!(
        "original worker identity retired: pid={pid} original_start_ticks={ticks} observed_start_ticks={observed:?}; not a replay resource observation"
    );
    Ok(())
}
fn run() -> Result<()> {
    let a = env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 6
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "Root finalizer exact CLI"
    );
    bound_file(
        &Path::new("/proc/self/exe").read_link()?,
        &a[5],
        64 << 20,
        true,
    )?;
    let p: Plan = serde_json::from_slice(&bound_file(Path::new(&a[1]), &a[3], 1 << 20, true)?)?;
    ensure!(
        p.schema == "epoch163-native-input-finalization-plan-v1"
            && p.acceptance != p.original_completion,
        "finalization exact scope"
    );
    let original: Value = serde_json::from_slice(&bound_file(
        &p.native_plan.path,
        &p.native_plan.sha256,
        1 << 20,
        true,
    )?)?;
    ensure!(
        original["schema"] == "epoch163-native-input-plan-v3",
        "original native plan"
    );
    let outcome_bytes = bound_file(
        &p.native_outcome.path,
        &p.native_outcome.sha256,
        1 << 20,
        false,
    )?;
    let v: Value = serde_json::from_slice(&outcome_bytes)?;
    ensure!(
        v["schema"] == "epoch163-native-input-outcome-v3"
            && v["plan"] == json!({"path":p.native_plan.path,"sha256":p.native_plan.sha256})
            && v["bootstrap_generation"] == 1634787272998262u64
            && v["bootstrap_slot"] == 70415741
            && v["snapshot_integrity_verified"] == true
            && v["mapped_worker_image_verified"] == true
            && v["vma_guards_enforced"] == true
            && v["source_mounts_read_only"] == true
            && v["mapped_worker_sha256"]
                == "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819"
            && v["worker_shutdown_acknowledged"] == true
            && v["worker_shutdown_and_reap_passed"] == false
            && v["replay_entries_sent"] == 0
            && v["original_capability_actor_drained"] == false
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false,
        "genuine native successful outcome required"
    );
    let iid = v["actor_invocation_id"].as_str().context("original IID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "IID shape"
    );
    let before = native()?;
    completed(&before, iid)?;
    original_worker_retired(&v)?;
    let program: Bound = serde_json::from_value(original["program"].clone())?;
    bound_file(&program.path, &program.sha256, 256 << 20, true)?;
    original_command(&before, &program, &p.native_plan)?;
    let admission: Bound = serde_json::from_value(v["admission"].clone())?;
    ensure!(
        original["admission"] == json!(admission.path),
        "original admission pathname crossed"
    );
    let admission_bytes = bound_file(&admission.path, &admission.sha256, 4 << 20, true)?;
    let admitted: Value = serde_json::from_slice(&admission_bytes)?;
    admission_lineage(&admitted, &original, &p.native_plan, iid)?;
    let issuer: Bound = serde_json::from_value(original["admission_program"].clone())?;
    bound_file(&issuer.path, &issuer.sha256, 256 << 20, true)?;
    let iid_filter = format!("INVOCATION_ID={iid}");
    let unit_filter = format!("UNIT={UNIT}");
    let journal = command(&[
        "/usr/bin/journalctl",
        "--all",
        "--no-pager",
        "-o",
        "json",
        "-n",
        "2",
        "_PID=1",
        "_UID=0",
        &unit_filter,
        &iid_filter,
        "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
    ])?;
    let rows = std::str::from_utf8(&journal)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !rows.is_empty()
            && rows.iter().all(|r| r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == UNIT
                && r["INVOCATION_ID"] == iid
                && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"),
        "original PID1 success journal"
    );
    ensure!(
        native()? == before
            && bound_file(&admission.path, &admission.sha256, 4 << 20, true)? == admission_bytes
            && bound_file(
                &p.native_outcome.path,
                &p.native_outcome.sha256,
                1 << 20,
                false
            )? == outcome_bytes,
        "owner/outcome changed"
    );
    original_worker_retired(&v)?;
    let completion = json!({"schema":"epoch163-native-input-original-completion-v1","unit":UNIT,"invocation_id":iid,"original_native_properties":std::str::from_utf8(&before)?,"original_program":program,"original_admission":{"path":admission.path,"sha256":admission.sha256},"PID1":rows,"native_outcome":{"path":p.native_outcome.path,"sha256":p.native_outcome.sha256},"worker_shutdown_and_reap_passed":true,"original_worker_pid":v["worker_pid"],"original_worker_start_ticks":v["worker_start_ticks"],"original_worker_identity_retired":true,"original_capability_actor_drained":true,"original_cgroup_empty":true,"publication_authorized":false,"r2_mutations":false});
    write_or_recover(&p.original_completion, &completion)?;
    let completion_raw = std::fs::read(&p.original_completion)?;
    write_or_recover(
        &p.acceptance,
        &json!({"schema":"epoch163-first-output128-input-capability-v1","bootstrap_generation":1634787272998262u64,"bootstrap_slot":70415741,"snapshot_integrity_verified":true,"mapped_worker_sha256":v["mapped_worker_sha256"],"original_capability_actor_drained":true,"original_completion":{"path":p.original_completion,"sha256":sha(&completion_raw)},"native_outcome":{"path":p.native_outcome.path,"sha256":p.native_outcome.sha256},"publication_authorized":false,"r2_mutations":false}),
    )?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("epoch163 original capability finalization failed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> String {
        format!(
            "Id={UNIT}\nLoadState=loaded\nActiveState=active\nSubState=exited\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nMainPID=0\nControlPID=0\nNRestarts=0\nResult=success\nExecMainStatus=0\nControlGroup=\nExecStart=checked separately\nType=exec\nUser=root\nRestart=no\nRemainAfterExit=yes\nKillMode=control-group\nMemoryMax=137438953472\nMemorySwapMax=0\n"
        )
    }
    #[test]
    fn exact_terminal_owner_and_empty_scope_are_required() {
        let iid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let good = fixture();
        completed(good.as_bytes(), iid).unwrap();
        for (a, b) in [
            ("SubState=exited", "SubState=running"),
            ("MainPID=0", "MainPID=2"),
            ("ControlPID=0", "ControlPID=3"),
            ("NRestarts=0", "NRestarts=1"),
            ("Result=success", "Result=exit-code"),
            ("ExecMainStatus=0", "ExecMainStatus=1"),
            ("ControlGroup=\n", "ControlGroup=/system.slice/live\n"),
            ("LoadState=loaded", "LoadState=not-found"),
            ("User=root", "User=sol"),
            ("Type=exec", "Type=oneshot"),
            ("Restart=no", "Restart=always"),
            ("RemainAfterExit=yes", "RemainAfterExit=no"),
            ("KillMode=control-group", "KillMode=process"),
            ("MemoryMax=137438953472", "MemoryMax=infinity"),
            ("MemorySwapMax=0", "MemorySwapMax=infinity"),
        ] {
            assert!(
                completed(good.replace(a, b).as_bytes(), iid).is_err(),
                "{a}"
            );
        }
        assert!(completed(good.as_bytes(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").is_err());
    }
    #[test]
    fn duplicate_or_missing_completion_properties_never_establish_drain() {
        let iid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(completed(format!("{}MainPID=0\n", fixture()).as_bytes(), iid).is_err());
        assert!(completed(fixture().replace("ControlGroup=\n", "").as_bytes(), iid).is_err());
    }
    fn tool() -> Bound {
        Bound {
            path: "/usr/local/lib/jetstreamer/test-native/native".into(),
            sha256: "a".repeat(64),
        }
    }
    fn original_plan() -> Bound {
        Bound {
            path: "/usr/local/lib/jetstreamer/test-plan/plan.json".into(),
            sha256: "b".repeat(64),
        }
    }
    #[test]
    fn completion_binds_exact_original_image_plan_arguments_and_error_policy() {
        let program = tool();
        let plan = original_plan();
        let good = format!(
            "ExecStart={{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ; start_time=actual ; stop_time=actual ; pid=99 ; code=exited ; status=0 }}\n",
            program.path.display(),
            program.path.display(),
            plan.path.display(),
            plan.sha256,
            program.sha256
        );
        original_command(good.as_bytes(), &program, &plan).unwrap();
        for changed in [
            good.replace("/test-native/native", "/test-native/foreign"),
            good.replace("/test-plan/plan.json", "/test-plan/other.json"),
            good.replace(&plan.sha256, &"c".repeat(64)),
            good.replace(&program.sha256, &"d".repeat(64)),
            good.replace("ignore_errors=no", "ignore_errors=yes"),
            good.replace("--plan-sha256", "--another-option"),
            format!("{good}{good}"),
            String::new(),
        ] {
            assert!(original_command(changed.as_bytes(), &program, &plan).is_err());
        }
        // Display-only timestamps and historic PID do not alter the command identity.
        original_command(good.replace("pid=99", "pid=0").as_bytes(), &program, &plan).unwrap();
    }
    #[test]
    fn admission_lineage_cannot_be_borrowed_from_another_program_or_invocation() {
        let iid = "e".repeat(32);
        let plan = original_plan();
        let original = json!({"program":tool(),"admission_program":{"path":"/sealed/issuer","sha256":"f".repeat(64)},"worker":{"path":"/sealed/worker","sha256":"1".repeat(64)},"download":{"path":"/sealed/download","sha256":"2".repeat(64)}});
        let good = json!({"schema":"epoch163-native-input-admission-v2","admitted":true,"plan":plan,"program":original["program"],"issuer":original["admission_program"],"worker":original["worker"],"download":original["download"],"actor_invocation_id":iid,"actor_pid":999,"actor_memory_bytes":128u64<<30,"native_restore_only":true,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        admission_lineage(&good, &original, &plan, &iid).unwrap();
        for key in [
            "plan",
            "program",
            "issuer",
            "worker",
            "download",
            "actor_invocation_id",
            "actor_pid",
            "actor_memory_bytes",
            "native_restore_only",
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = good.clone();
            bad[key] = Value::Null;
            assert!(
                admission_lineage(&bad, &original, &plan, &iid).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn exact_receipt_recovery_preserves_inode_and_conflicting_evidence() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "custody test requires admitted Root test actor"
        );
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("receipt.json");
        let value = json!({"original_invocation":"a".repeat(32),"complete":true});
        write_or_recover(&path, &value).unwrap();
        let identity = fs::metadata(&path).unwrap().ino();
        let bytes = fs::read(&path).unwrap();
        write_or_recover(&path, &value).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().ino(), identity);
        assert!(write_or_recover(&path, &json!({"complete":false})).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    #[test]
    fn recovery_rejects_partial_symlink_and_hardlinked_receipts() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "custody test requires admitted Root test actor"
        );
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let value = json!({"complete":true});
        let partial = directory.path().join("partial");
        fs::write(&partial, b"{").unwrap();
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(write_or_recover(&partial, &value).is_err());
        assert_eq!(fs::read(&partial).unwrap(), b"{");
        let symlink = directory.path().join("symlink");
        std::os::unix::fs::symlink(&partial, &symlink).unwrap();
        assert!(write_or_recover(&symlink, &value).is_err());
        let source = directory.path().join("source");
        write_or_recover(&source, &value).unwrap();
        let hardlink = directory.path().join("hardlink");
        fs::hard_link(&source, &hardlink).unwrap();
        assert!(write_or_recover(&hardlink, &value).is_err());
    }
    #[test]
    fn shutdown_acknowledgement_cannot_substitute_for_original_worker_retirement() {
        assert!(retired_identity(123, Some(123)).is_err());
        retired_identity(123, None).unwrap();
        retired_identity(123, Some(456)).unwrap();
        assert!(retired_identity(0, None).is_err());
    }
}
