//! Exact local-publication ownership receipts; no replay or archive mutations.
#[allow(dead_code)]
#[path = "../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};
const TOOL: &str = "/usr/local/lib/jetstreamer/horizon-epoch144-publisher-candidate-20261022-v6/jetstreamer-epoch144-publish";
const TOOL_SHA: &str = "4274f83c6d84a2bc2014b30122a38406b6498045f543ba170598baa8369a7efa";
const UNIT: &str = "horizon-publish-144-v4-20261022-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-publication144-owner-20261022-v1";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    publisher_plan: Bound,
    capability: Bound,
}
fn read(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        4 << 20,
        immutable,
    )?)?)
}
fn receipt(path: &Path) -> Result<(Bound, Value)> {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 4 << 20,
        "unsafe publisher receipt"
    );
    let mut bytes = Vec::new();
    (&mut f).take((4 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && evidence::identity(&m) == evidence::identity(&f.metadata()?)
            && evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(path)?),
        "publisher receipt changed"
    );
    let b = Bound {
        path: path.into(),
        sha256: evidence::sha(&bytes),
    };
    let v = read(&b, false)?;
    Ok((b, v))
}
fn durable(path: &Path, v: &Value) -> Result<()> {
    evidence::write_receipt(path, v)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    fs::File::open(path)?.sync_all()?;
    fs::File::open(path.parent().context("receipt parent")?)?.sync_all()?;
    Ok(())
}
fn shape(p: &Plan, v: &Value, c: &Value) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-exact144-publication-owner-plan-v1"
            && p.publisher_plan.path.parent().is_some_and(|d| d.parent()
                == Some(Path::new("/usr/local/lib/jetstreamer"))
                && d.file_name().is_some_and(|n| n
                    .to_string_lossy()
                    .starts_with("horizon-epoch144-publication-plan-")))
            && p.publisher_plan
                .path
                .file_name()
                .is_some_and(|n| n == "plan.json")
            && v["schema"] == "jetstreamer-exact144-v4-publication-plan-v2"
            && v["artifact_publication_authorized"] == true
            && v["runtime_registry_promotion_authorized"] == false
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false
            && v["refreshed_capacity"]["schema"]
                == "jetstreamer-exact144-delivery-capacity-refresh-v3"
            && v["refreshed_capacity"]["growth_claims"]
                .as_array()
                .is_some_and(|a| a.len() == 3)
            && v["refreshed_capacity"]["epoch160_handoff"].is_null()
            && v["refreshed_capacity"]["epoch160_public_delivery"]["path"]
                == "/var/lib/jetstreamer/horizon-epoch160-public-observation-20261022-v1/proof.json"
            && v["refreshed_capacity"]["epoch160_public_delivery"]["sha256"]
                == "c54ede068b3cfd743259f52b93a98847910abe4fac6ff50ab88c4bbcae5e9008"
            && v["evidence"]["sha256"]
                == "5196699c86959e9704269ae7dbfc1c9432ebc82eb40f305dca6dd56ded891f64",
        "foreign exact 144 publication owner plan"
    );
    for (field, parent, prefix) in [
        (
            "work_directory",
            "/home/sol/.jetstreamer-private",
            "epoch144-publication-work-",
        ),
        (
            "receipt_directory",
            "/var/lib/jetstreamer",
            "horizon-epoch144-publication-",
        ),
    ] {
        let path = Path::new(v[field].as_str().context("publication directory")?);
        ensure!(
            path.parent() == Some(Path::new(parent))
                && path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(prefix)),
            "foreign publication directory"
        );
    }
    ensure!(
        c["schema"] == "jetstreamer-exact144-publication-capability-v1"
            && c["publisher_sha256"] == TOOL_SHA
            && c["diagnostic_fixture"] == true
            && c["filesystem_transaction_passed"] == true
            && c["outside_write_denied"] == true
            && c["effective_uid"] == 1001
            && c["effective_gid"] == 1003
            && c["root_receipt_fd_survives_permanent_privilege_drop"] == true
            && c["artifact_publication_authorized"] == false
            && c["runtime_registry_promotion_authorized"] == false
            && c["r2_mutations"] == false
            && c["remote_mutations"] == false,
        "missing exact publisher kernel capability"
    );
    Ok(())
}
fn owner() -> Result<Value> {
    let o=Command::new("/usr/bin/systemctl").args(["show",UNIT,"--property=Id,LoadState,InvocationID,MainPID,NRestarts,ExecStart,ExecMainStatus,Result,ActiveState,SubState,Type,Restart,RemainAfterExit,TimeoutStartUSec,User,Group,DynamicUser,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ProtectHome,ProtectSystem,PrivateTmp,PrivateNetwork,NoNewPrivileges,ReadWritePaths,CapabilityBoundingSet,AmbientCapabilities"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 32768,
        "publisher owner query failed"
    );
    let fields: std::collections::BTreeMap<_, _> = std::str::from_utf8(&o.stdout)?
        .lines()
        .map(|s| s.split_once('=').context("malformed owner properties"))
        .collect::<Result<_>>()?;
    Ok(serde_json::to_value(fields)?)
}
fn limits(u: &Value, p: &Plan, v: &Value) -> Result<()> {
    for (key, value) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("Type", "oneshot"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("RemainAfterExit", "yes"),
        ("TimeoutStartUSec", "6h"),
        ("DynamicUser", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "1073741824"),
        ("MemoryMax", "2147483648"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "2s"),
        ("TasksMax", "512"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("PrivateTmp", "yes"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        (
            "CapabilityBoundingSet",
            "cap_chown cap_dac_override cap_setgid cap_setuid",
        ),
        (
            "AmbientCapabilities",
            "cap_chown cap_dac_override cap_setgid cap_setuid",
        ),
    ] {
        ensure!(u[key] == value, "publisher sandbox changed:{key}");
    }
    ensure!(
        matches!(u["User"].as_str(), Some("" | "root"))
            && matches!(u["Group"].as_str(), Some("" | "root")),
        "foreign publisher credentials"
    );
    let expected = format!(
        "{{ path={TOOL} ; argv[]={TOOL} {} --plan-sha256 {} --self-sha256 {TOOL_SHA}",
        p.publisher_plan.path.display(),
        p.publisher_plan.sha256
    );
    ensure!(
        u["ExecStart"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .is_some_and(|(a, b)| a == expected && b.starts_with("no ;")),
        "publisher command differs"
    );
    let rw = format!(
        "/home/sol {}",
        v["receipt_directory"].as_str().context("receipt path")?
    );
    ensure!(
        u["ReadWritePaths"] == rw,
        "publisher writable mounts differ"
    );
    let iid = u["InvocationID"].as_str().context("publisher invocation")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid publisher invocation"
    );
    Ok(())
}
fn live(u: &Value) -> bool {
    ((u["ActiveState"] == "activating" && u["SubState"] == "start")
        || (u["ActiveState"] == "active" && u["SubState"] == "running"))
        && u["MainPID"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|n| n > 0)
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 7
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && matches!(a[6].as_str(), "--check-only" | "--capture" | "--terminal")
            && unsafe { libc::geteuid() } == 0,
        "usage: publication144-track PLAN --plan-sha256 SHA --self-sha256 SHA --check-only|--capture|--terminal"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let pb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(read(&pb, true)?)?;
    let v = read(&p.publisher_plan, true)?;
    let c = read(&p.capability, false)?;
    shape(&p, &v, &c)?;
    evidence::bound_file(Path::new(TOOL), TOOL_SHA, 256 << 20, true)?;
    let root = Path::new(ROOT);
    let m = fs::symlink_metadata(root)?;
    ensure!(
        root.canonicalize()? == root && m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "unsafe publication tracker directory"
    );
    if a[6] == "--check-only" {
        println!(
            "exact publisher tracking inputs valid; no unit start, observation, copy or receipt"
        );
        return Ok(());
    }
    let before = owner()?;
    limits(&before, &p, &v)?;
    let path = root.join("launch.json");
    if a[6] == "--capture" {
        ensure!(live(&before), "capture requires actual live publisher");
        let receipt_dir = Path::new(v["receipt_directory"].as_str().unwrap());
        let intent = receipt_dir.join("intent.json");
        let (ib, i) = receipt(&intent)?;
        ensure!(
            i["schema"] == "jetstreamer-exact144-v4-publication-context-v1"
                && i["plan"] == serde_json::to_value(&p.publisher_plan)?
                && i["publisher_sha256"] == TOOL_SHA
                && i["admission"]["refreshed_capacity"]["protected_bytes"] == 3984782679494u64,
            "publisher intent lacks qualified admission"
        );
        ensure!(owner()? == before, "publisher changed during capture");
        let claim = json!({"epoch":144,"phase":"local-publication","unit":UNIT,"invocation_id":before["InvocationID"],"expected_exec_start":before["ExecStart"]});
        durable(
            &path,
            &json!({"schema":"jetstreamer-exact144-publication-launch-v1","epoch":144,"launched":true,"claim":claim,"publisher_plan":p.publisher_plan,"tracker_plan":pb,"tracker_sha256":a[5],"publisher_sha256":TOOL_SHA,"capability":p.capability,"intent":ib,"owner":before,"evidence":{"units":[{"unit":UNIT,"invocation_id":before["InvocationID"]}]},"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false,"remote_mutations":false}),
        )?;
    } else {
        let (lb, l) = receipt(&path)?;
        ensure!(
            l["schema"] == "jetstreamer-exact144-publication-launch-v1"
                && l["publisher_plan"] == serde_json::to_value(&p.publisher_plan)?
                && before["InvocationID"] == l["claim"]["invocation_id"]
                && before["MainPID"] == "0"
                && !live(&before)
                && matches!(
                    before["ActiveState"].as_str(),
                    Some("active" | "failed" | "inactive")
                ),
            "publisher not exact terminal owner"
        );
        let success = before["Result"] == "success" && before["ExecMainStatus"] == "0";
        ensure!(owner()? == before, "terminal publisher changed");
        durable(
            &root.join("terminal.json"),
            &json!({"schema":"jetstreamer-exact144-publication-terminal-v1","epoch":144,"launch":lb,"owner":before,"service_success":success,"archive_verification_or_ready_pair_proven":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false,"remote_mutations":false}),
        )?;
    }
    println!("exact144 owner receipt durable; no launch, archive or remote mutation");
    Ok(())
}
fn main() -> Result<()> {
    run()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Plan, Value, Value) {
        let p = Plan {
            schema: "jetstreamer-exact144-publication-owner-plan-v1".into(),
            publisher_plan: Bound {
                path: "/usr/local/lib/jetstreamer/horizon-epoch144-publication-plan-test/plan.json"
                    .into(),
                sha256: "a".repeat(64),
            },
            capability: Bound {
                path: "/sealed/capability.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let v = json!({"schema":"jetstreamer-exact144-v4-publication-plan-v2","artifact_publication_authorized":true,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false,"refreshed_capacity":{"schema":"jetstreamer-exact144-delivery-capacity-refresh-v3","growth_claims":[{},{},{}],"epoch160_public_delivery":{"path":"/var/lib/jetstreamer/horizon-epoch160-public-observation-20261022-v1/proof.json","sha256":"c54ede068b3cfd743259f52b93a98847910abe4fac6ff50ab88c4bbcae5e9008"}},"evidence":{"sha256":"5196699c86959e9704269ae7dbfc1c9432ebc82eb40f305dca6dd56ded891f64"},"work_directory":"/home/sol/.jetstreamer-private/epoch144-publication-work-test","receipt_directory":"/var/lib/jetstreamer/horizon-epoch144-publication-test"});
        let c = json!({"schema":"jetstreamer-exact144-publication-capability-v1","publisher_sha256":TOOL_SHA,"diagnostic_fixture":true,"filesystem_transaction_passed":true,"outside_write_denied":true,"effective_uid":1001,"effective_gid":1003,"root_receipt_fd_survives_permanent_privilege_drop":true,"artifact_publication_authorized":false,"runtime_registry_promotion_authorized":false,"r2_mutations":false,"remote_mutations":false});
        (p, v, c)
    }
    #[test]
    fn tracker_cannot_borrow_generic_publication_or_unqualified_kernel_proof() {
        let (p, v, c) = fixture();
        shape(&p, &v, &c).unwrap();
        for (pointer, value) in [
            (
                "/schema",
                json!("jetstreamer-exact144-v4-publication-plan-v1"),
            ),
            ("/artifact_publication_authorized", json!(false)),
            ("/runtime_registry_promotion_authorized", json!(true)),
            ("/remote_mutations", json!(true)),
            ("/r2_mutations", json!(true)),
            ("/work_directory", json!("/home/sol")),
            ("/receipt_directory", json!("/var/lib/jetstreamer")),
            ("/evidence/sha256", json!("a".repeat(64))),
            (
                "/refreshed_capacity/schema",
                json!("jetstreamer-exact144-delivery-capacity-refresh-v1"),
            ),
            ("/refreshed_capacity/growth_claims", json!([{}, {}, {}, {}])),
            (
                "/refreshed_capacity/epoch160_public_delivery/sha256",
                json!("f".repeat(64)),
            ),
        ] {
            let mut wrong = v.clone();
            *wrong.pointer_mut(pointer).unwrap() = value;
            assert!(shape(&p, &wrong, &c).is_err(), "{pointer}");
        }
        for (pointer, value) in [
            ("/publisher_sha256", json!("b".repeat(64))),
            ("/effective_uid", json!(0)),
            ("/effective_gid", json!(0)),
            ("/filesystem_transaction_passed", json!(false)),
            ("/outside_write_denied", json!(false)),
            ("/artifact_publication_authorized", json!(true)),
            ("/r2_mutations", json!(true)),
        ] {
            let mut wrong = c.clone();
            *wrong.pointer_mut(pointer).unwrap() = value;
            assert!(shape(&p, &v, &wrong).is_err(), "{pointer}");
        }
    }
    #[test]
    #[ignore = "explicit root disposable receipt persistence/no-clobber test"]
    fn receipt_writer_is_no_clobber_private_and_immutable() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = t.path().join("receipt.json");
        durable(&path, &json!({"fixture":true})).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
        assert!(receipt(&path).unwrap().1["fixture"] == true);
        assert!(durable(&path, &json!({"fixture":false})).is_err());
    }
    #[test]
    fn active_exited_is_terminal_not_a_live_publication() {
        assert!(!live(
            &json!({"ActiveState":"active","SubState":"exited","MainPID":"0"})
        ));
        assert!(live(
            &json!({"ActiveState":"activating","SubState":"start","MainPID":"12"})
        ));
        assert!(!live(
            &json!({"ActiveState":"activating","SubState":"start","MainPID":"0"})
        ));
    }
}
