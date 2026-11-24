//! One-shot transition from the original frozen 145 recovery into post-full and guarded 136.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(feature = "registered-post")]
mod boundary;
mod events;
mod incident;
mod outcome;
#[allow(dead_code)]
#[path = "../horizon_public_audit_v14_cutover_20261121_v1/platform.rs"]
mod platform;
#[cfg(feature = "registered-post")]
mod terminal136;
use platform::{bound, from_ref, pinned, read, text};
const RT: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const E: &str = "horizon-holding-export145-20261121-v1.service";
const W: &str = "horizon-admit-136-actual-20261120-g1.service";
const REC: &str = "5dfb817906f74b73a27f61a386751d75";
const ORIGINAL: &str = "de6780b860b3467bae21fbd19176ca14";
const WRITER: &str = "epoch136-joint-writer-20261121-v4";
const PROVIDER: &str = "epoch145-publication-20261121-v1/joint-tools-v3";
const PARENT: &str = "epoch136-closed168-registration-20261121-v1/parent-package";
const SEALER: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn rt(p: &str) -> PathBuf {
    Path::new(RT).join(p)
}
fn valid_iid(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn check_member(package: &Path, seal_sha: &str, name: &str) -> Result<PathBuf> {
    let seal = pinned(&package.join("deployment-seal-receipt.json"), seal_sha)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(package)
            && seal["sealer_sha256"] == SEALER,
        "foreign deployment"
    );
    let path = package.join(name);
    let file = bound(&path)?;
    let members = seal["members"].as_array().context("deployment members")?;
    ensure!(
        fs::symlink_metadata(&path)?.mode() & 0o777 == 0o555
            && members
                .iter()
                .filter(|r| r["name"] == name
                    && r["mode"] == "0555"
                    && r["sha256"] == file["sha256"])
                .count()
                == 1,
        "unbound {name}"
    );
    Ok(path)
}
fn native(unit: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "-p",
            "Id,ActiveState,SubState,ControlGroup,Job,NRestarts,MainPID,InvocationID,LoadState",
        ])
        .output()?;
    let mut v = json!({});
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, s) = line.split_once('=').context("unit field")?;
        v[k] = s.into();
    }
    ensure!(
        v["Id"] == unit
            && (out.status.success()
                || (out.status.code() == Some(4) && v["LoadState"] == "not-found")),
        "cannot identify {unit}"
    );
    Ok(v)
}
fn stable(v: &Value, unit: &str) -> Result<(i32, String)> {
    let pid = text(&v["MainPID"])?.parse::<i32>()?;
    let iid = text(&v["InvocationID"])?;
    ensure!(
        pid > 1
            && valid_iid(iid)
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["Job"] == ""
            && v["NRestarts"] == "0"
            && v["ControlGroup"] == format!("/system.slice/{unit}")
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::/system.slice/{unit}"),
        "changing original actor"
    );
    Ok((pid, iid.into()))
}
fn drained(v: &Value, unit: &str) -> Result<()> {
    ensure!(
        v["ActiveState"] == "inactive"
            && v["MainPID"] == "0"
            && v["Job"] == ""
            && platform::group_members(&format!("/system.slice/{unit}"))?.is_empty(),
        "fixed service {unit} still owns work"
    );
    Ok(())
}
fn command(path: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new(path).args(args).output()?;
    ensure!(
        out.status.success(),
        "{} {}: {}",
        path.display(),
        args.first().unwrap_or(&""),
        String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(1800)])
    );
    Ok(out.stdout)
}
fn aspath(v: &Value) -> Result<&Path> {
    Ok(Path::new(text(&v["path"])?))
}
fn validate_terminal(d: &Value, c: &Value) -> Result<()> {
    ensure!(
        d["iid"] == REC
            && d["recovered_from"] == ORIGINAL
            && d["r2_mutations"] == false
            && c["actor_iid"] == REC
            && c["original_export"] == ORIGINAL
            && c["schema"] == "horizon-epoch145-guarded-private-prefix-completion-v1"
            && c["archive_publication_authorized"] == false
            && c["r2_mutations"] == false,
        "foreign terminal completion"
    );
    Ok(())
}
fn completed() -> Result<Value> {
    let dir = rt(&format!("epoch145-guarded-export-20261121-v1/state/{REC}"));
    ensure!(
        !dir.join("failed.json").try_exists()?,
        "original 145 reported failure"
    );
    let d = bound(&dir.join("complete.json"))?;
    let v = from_ref(&d)?;
    ensure!(
        v["receipt"] == bound(&dir.join("extraction-complete.json"))?,
        "crossed full extraction"
    );
    let cc = from_ref(&v["receipt"])?;
    validate_terminal(&v, &cc)?;
    ensure!(
        cc["recovery_evidence"] == bound(&dir.join("recovery-started.json"))?
            && cc["verified_frozen"] == bound(&dir.join("verified-frozen.json"))?,
        "unbound recovery"
    );
    Ok(d)
}
const STATE: &str = "epoch145-recovery-handoff-20261121-v1/state";
fn guard_instance(dir: &Path) -> Result<fs::File> {
    let m = fs::symlink_metadata(dir)?;
    ensure!(
        m.is_dir() && dir.canonicalize()? == dir && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "unexpected handoff state directory"
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("controller.lock"))?;
    let st = file.metadata()?;
    ensure!(
        st.is_file()
            && st.uid() == 0
            && st.nlink() == 1
            && st.mode() & 0o077 == 0
            && unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another or untrusted handoff owner"
    );
    Ok(file)
}
fn original_peers(f: &Value) -> Result<()> {
    let terminal = from_ref(&f["terminal168_trace_mismatch"])?;
    let mut epochs = std::collections::BTreeSet::new();
    for key in [
        "actual_active_bootstraps",
        "actual_executing_replays",
        "actual_active_private_diagnostics",
    ] {
        for r in f[key].as_array().context("fleet owner class")? {
            let e = r["epoch"].as_u64().context("epoch")?;
            let original = &terminal["live_original_owners"][e.to_string()];
            ensure!(
                epochs.insert(e)
                    && original["Id"].is_string()
                    && original["Id"] == r["unit"]["Id"]
                    && original["InvocationID"] == r["unit"]["InvocationID"],
                "replacement fleet requires a successor provider"
            );
        }
    }
    ensure!(
        epochs == std::collections::BTreeSet::from([166, 167, 169, 170, 172]),
        "different live topology"
    );
    Ok(())
}
fn required_environment() -> Result<()> {
    for key in [
        "HORIZON_S3_ENDPOINT",
        "HORIZON_ACCESS_KEY_ID",
        "HORIZON_SECRET_ACCESS_KEY",
    ] {
        ensure!(
            std::env::var_os(key).is_some_and(|v| !v.is_empty()),
            "registration input {key} is missing"
        );
    }
    Ok(())
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root operator");
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if let [mode, iid, after] = args.as_slice()
        && mode == "inspect-native-stop"
    {
        println!("{}", events::inspect_native_stop(E, iid, after.parse()?)?);
        return Ok(());
    }
    #[cfg(feature = "fixture-post")]
    ensure!(
        matches!(args.as_slice(), [mode] if incident::handles(mode))
            || (args.len() == 7 && Path::new(&args[0]) == boundary::ready_path()),
        "expected inspect-v5f, follow-v5f, or the registered inspector arguments"
    );
    #[cfg(feature = "registered-post")]
    if args.len() == 7 && Path::new(&args[0]) == boundary::ready_path() {
        return boundary::inspect(&args);
    }
    if let [mode] = args.as_slice() {
        if incident::handles(mode) {
            return incident::run(mode);
        }
        return outcome::run(mode);
    }
    let [mode, seed, sha, parent_dir, parent_sha] = args.as_slice() else {
        bail!("follow145 inspect|follow FLEET SHA PARENT_PACKAGE SEAL_SHA")
    };
    ensure!(matches!(mode.as_str(), "inspect" | "follow"), "mode");
    let pkg = Path::new(parent_dir);
    ensure!(
        pkg == rt(PARENT) || pkg == rt("epoch166-post168-cadence-20261121-v1/parent-package"),
        "parent deployment namespace"
    );
    let parent = check_member(pkg, parent_sha, "parent136")?;
    let plan = rt(WRITER).join("production-plan.json");
    let p = bound(&plan)?;
    ensure!(
        p["sha256"] == "247df45a52f40c208f22567334a3af82b0c93a5b96779148bb743109436d253a",
        "changed writer plan"
    );
    let doc = from_ref(&p)?;
    let ws = &doc["controller_deployment"];
    check_member(
        &rt(WRITER).join("controller"),
        text(&ws["sha256"])?,
        "admit136",
    )?;
    let post = check_member(
        &rt(PROVIDER),
        text(&doc["joint_fit_145"]["seal"]["sha256"])?,
        "run-post",
    )?;
    let provider = check_member(
        &rt(PROVIDER),
        text(&doc["joint_fit_145"]["seal"]["sha256"])?,
        "export145",
    )?;
    let launcher = rt("epoch136-current-registration-20261121-v1/run-writer");
    ensure!(
        bound(&launcher)?["sha256"]
            == "aaa01f259ffae1734cd7cbf0ae65e53ef6dea2eba298c329305e9faff7cd932a",
        "writer launcher"
    );
    let head = || -> Result<Value> {
        let v: Value = serde_json::from_slice(&command(&parent, &["inspect-status", seed, sha])?)?;
        let f = from_ref(&v["fleet"])?;
        ensure!(
            f["owner"] == "/root"
                && f["terminal168_trace_mismatch"]["sha256"]
                    == "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2"
                && f["terminal166_local_commit"].is_null()
                && f["all_reservation_ending_bytes"] == 0,
            "fleet requires a new provider"
        );
        original_peers(&f)?;
        Ok(v["fleet"].clone())
    };
    let initial = native(E)?;
    let prod = pinned(
        &rt("epoch145-partial-recovery-20261121-v1/PRODUCTIVE.json"),
        "c5a09b3cb7263da3e1b9a29ff4ff07e43a665524920702f2383e32714230d85b",
    )?;
    let live = initial["InvocationID"] == REC && initial["ActiveState"] == "active";
    if live {
        let (pid, iid) = stable(&initial, E)?;
        ensure!(
            prod["invocation"] == iid
                && prod["supervisor"] == json!([pid, platform::ticks(pid)?])
                && platform::proc_exe(pid)?
                    == rt("epoch145-partial-recovery-20261121-v1/tools/export145"),
            "crossed 145 recovery"
        );
    }
    if mode == "inspect" {
        println!(
            "{}",
            json!({"original_145":initial,"verified_recovery":live,"fleet":head()?,"post":post,"parent":parent,"launch":false})
        );
        return Ok(());
    }
    let state = rt(STATE);
    let _lock = guard_instance(&state)?;
    required_environment()?;
    ensure!(
        !state.join("136-dispatched.json").try_exists()?,
        "original handoff already completed"
    );
    let native_exit = events::manager(E, REC).inspect_err(|error| {
        // A failed original recovery has its independent continuity path.
        eprintln!("145 recovery {REC} needs continuity inspection: {error:#}");
    })?;
    let completion = completed()?;
    let first = native(E)?;
    if first["ActiveState"] != "active" {
        drained(&first, E)?;
        let f = head()?;
        // An existing submission intent with a drained service is ambiguous. Preserve
        // its journal and receipts instead of launching a second expensive post verifier.
        platform::save(
            &state.join("post-submission.json"),
            &json!({"owner":REC,"manager":native_exit,"completion":completion,"fleet":f,"launcher":bound(&post)?}),
        )?;
        command(&post, &[text(&f["path"])?])?;
    }
    let (pid, iid) = stable(&native(E)?, E)?;
    let a = fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(
        platform::proc_exe(pid)? == provider
            && a.split(|b| *b == 0).nth(1) == Some(b"post-full".as_slice()),
        "foreign post actor"
    );
    let path = events::started(
        &rt(&format!("epoch145-publication-20261121-v1/full-{iid}")),
        pid,
        &iid,
    )?;
    let start: Value = serde_json::from_slice(&read(&path)?)?;
    ensure!(
        start["completion"] == completion
            && start["fit"]["joint136_enabled"] == true
            && start["fit"]["terminal168"]["resource_credit_bytes"] == 0,
        "ineligible post start"
    );
    let current = head()?;
    let fleet = text(&current["path"])?;
    let digest = text(&current["sha256"])?;
    let planpath = platform::string_path(&plan)?;
    let planhash = text(&p["sha256"])?;
    let sp = platform::string_path(aspath(ws)?)?;
    let sh = text(&ws["sha256"])?;
    command(&parent, &["inspect", planpath, planhash, sp, sh])?;
    drained(&native(W)?, W)?;
    let request = Path::new(
        "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1/parent-launch-request.json",
    );
    ensure!(!request.try_exists()?, "another admission exists");
    let mirror = rt("epoch136-parent-handoff-20261121-v1");
    if !mirror.try_exists()? {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&mirror)?;
    }
    command(&parent, &["prepare-inputs", fleet, digest])?;
    platform::save(
        &state.join("136-submission.json"),
        &json!({"post":bound(&path)?,"fleet":current,"writer_plan":p,"parent":bound(&parent)?}),
    )?;
    // session rechecks the full live fit before any donor fence and after every handoff.
    command(&launcher, &["session", planpath, planhash, fleet, digest])?;
    let (_, wid) = stable(&native(W)?, W)?;
    println!(
        "{}",
        json!({"completed":completion,"manager":native_exit,"post":bound(&path)?,"writer":wid,"fleet":current})
    );
    let status = Command::new(&parent)
        .args(["dispatch", &wid, planpath, planhash, sp, sh])
        .status()?;
    ensure!(status.success(), "136 registration handoff failed");
    platform::save(
        &state.join("136-dispatched.json"),
        &json!({"writer_invocation":wid,"post":iid,"fleet":current,"status_parent":bound(&parent)?}),
    )?;
    Ok(())
}
fn main() -> Result<()> {
    run()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_recovery_only() {
        let d = json!({"iid":REC,"recovered_from":ORIGINAL,"r2_mutations":false});
        let mut c = json!({"actor_iid":REC,"original_export":ORIGINAL,"schema":"horizon-epoch145-guarded-private-prefix-completion-v1","archive_publication_authorized":false,"r2_mutations":false});
        assert!(validate_terminal(&d, &c).is_ok());
        c["actor_iid"] = ORIGINAL.into();
        assert!(validate_terminal(&d, &c).is_err());
    }
}
