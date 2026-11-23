//! Evidence expected from the bounded-reader uploader after both prior owners drain.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};

pub const UNIT: &str = "horizon-upload-247-staged-fadfe2d4-v1.service";
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon247-public-images-fadfe2d4-v1/jetstreamer-r2";
pub const IMAGE_SHA: &str = "bc1255740a761743221838383816272966580a79d752e589ccafb31664fedd77";
pub const PLAN: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-fadfe2d4-v1/epoch-247-plan.json";
pub const PLAN_SHA: &str = "bc8252dbbf21f5396a3669313835787c79a7da46919d6243dbc3f29ff9064fe8";
pub const RECOVERY: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-fadfe2d4-v1/staged247-recovery.json";
pub const RECOVERY_SHA: &str = "f40250678635a011051e043b44d8e1247096491a99f48e3cc5d89b0d7b936dee";
const READER: &str = "fadfe2d4a3784ba0f955d1b7a26a15f57ff593e0";
const UPLOADER: &str = "ff6005f4b59f9e8e91925e680481acb21de5bd01";
const ACCEPTANCE: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-fadfe2d4-v1/main-acceptance.json";
const SOURCE: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-fadfe2d4-v1/source-acceptance.json";
pub const PRIOR_UNIT: &str = "horizon-upload-247-staged-680e1173-v1.service";
pub const PRIOR_IID: &str = "3e08307874db424886cd8c46b3ecfba6";
pub const ORIGINAL: &str = "horizon-upload-247-singleton-20261119-v1.service";
pub const ORIGINAL_IID: &str = "69218e2e0924497ea595a1227a6c31db";
pub const ROOT: &str = "/home/ubuntu/.codex/diagnostics/horizon-upload-247-staged-fadfe2d4-v1";
pub const PRIOR: &str =
    "/var/lib/jetstreamer/horizon247-public-images-fadfe2d4-v1/prior-staged-owner.json";
pub const PRIOR_SHA: &str = "b53133a0d9f828a5543dece1f343dd39828c96de618dc65095e471ba9ce2cef2";
pub const FIRST: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-fadfe2d4-v1/original-uploader-terminal.json";
pub const FIRST_SHA: &str = "c8c3f9f09e84a11c13887628f9bc207bb5eac53c58328f4055b32ba8bb0643d0";
pub const HARD: u64 = 10 << 30;
pub const BOOKED: u64 = HARD + (512 << 20);
pub const DISK: u64 = 1 << 30;
pub const FLOOR: u64 = 3_908_104_436_088;

pub fn binding(path: &str, sha: &str) -> Value {
    json!({"path":path,"sha256":sha})
}
fn doc(reference: &Value, path: &Path) -> Result<Value> {
    ensure!(
        reference["path"].as_str() == path.to_str()
            && path.is_absolute()
            && path.canonicalize()? == path,
        "247 evidence path changed"
    );
    let f = fs::File::open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 1 << 20,
        "247 evidence custody"
    );
    let mut bytes = Vec::new();
    f.take((1 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1 << 20 && reference["sha256"] == format!("{:x}", Sha256::digest(&bytes)),
        "247 evidence bytes changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
pub struct Owner {
    pub iid: String,
    pub pid: u32,
    pub argv: Value,
    pub proof: Value,
    pub command: String,
}
pub fn graph(
    claim: &Value,
    booking: &Value,
    launch: &Value,
    recovery: &Value,
    previous: &Value,
) -> Result<()> {
    let iid = claim["invocation_id"].as_str().context("successor IID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && iid != PRIOR_IID
            && iid != ORIGINAL_IID,
        "foreign successor invocation"
    );
    ensure!(
        claim["unit"] == UNIT
            && claim["epoch"] == 247
            && claim["phase"] == "upload-readback"
            && launch["unit"]["Id"] == UNIT
            && launch["unit"]["InvocationID"] == iid
            && launch["unit"]["NRestarts"] == "0"
            && claim["expected_exec_start"] == launch["unit"]["ExecStart"]
            && launch["unit"]["MemoryMax"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == Some(HARD)
            && launch["unit"]["MemorySwapMax"] == "0"
            && booking["unit"] == UNIT
            && booking["argv"] == recovery["recovery_argv"]
            && booking["approved_plan"] == binding(PLAN, PLAN_SHA)
            && booking["capacity_credit"] == 0
            && booking["local_reclamation_credit"] == 0
            && booking["additional_memory_reserve"] == BOOKED
            && booking["disk_reserve"] == DISK
            && recovery["prior_staged_owner"] == binding(PRIOR, PRIOR_SHA)
            && recovery["original_invocation"] == ORIGINAL_IID
            && recovery["historical_terminal"] == binding(FIRST, FIRST_SHA)
            && recovery["current_reader_plan"] == binding(PLAN, PLAN_SHA)
            && recovery["uploader"] == binding(IMAGE, IMAGE_SHA)
            && recovery["prior_staged_terminal_and_drain_required"] == true
            && recovery["fresh_authenticated_sha256_and_byte_comparison_required"] == true
            && recovery["prior_staged_reservations_released"] == false
            && previous["unit"] == PRIOR_UNIT
            && previous["invocation_id"] == PRIOR_IID,
        "successor claim or historical graph differs"
    );
    let argv = booking["argv"]
        .as_array()
        .context("247 activation argv")?
        .iter()
        .map(|v| v.as_str().context("argv member"))
        .collect::<Result<Vec<_>>>()?;
    let command = claim["expected_exec_start"]
        .as_str()
        .context("247 command")?
        .split_once(" ; start_time=")
        .context("247 manager command history")?
        .0;
    ensure!(
        argv.first() == Some(&IMAGE)
            && command
                == format!(
                    "{{ path={IMAGE} ; argv[]={0} ; ignore_errors=no",
                    argv.join(" ")
                ),
        "247 activation command differs"
    );
    Ok(())
}
pub fn reader_source(plan: &Value, acceptance: &Value, source: &Value) -> Result<()> {
    ensure!(
        plan["schema"] == "horizon-current-reader-plan-v1"
            && plan["reader_commit"] == READER
            && acceptance["schema"] == "horizon-current-reader-main-acceptance-v1"
            && acceptance["reader_commit"] == READER
            && acceptance["pipeline"] == plan["pipeline"]
            && acceptance["full_verifier"] == plan["full_verifier"]
            && acceptance["source_artifact_correspondence_accepted"] == true
            && acceptance["full_and_plugin_capabilities_accepted"] == true
            && source["reader_commit"] == READER
            && source["uploader_commit"] == UPLOADER
            && source["published_head"] == "8ced4c9cf3b0d96bd466dc5dbee397128914917e"
            && source["complete_fixture_reports"] == true,
        "epoch 247 bounded reader or uploader build differs"
    );
    Ok(())
}
pub fn load(reference: &Value) -> Result<Owner> {
    let root = Path::new(ROOT);
    let c = doc(reference, &root.join("pipeline-claim.json"))?;
    let refs = c["evidence"]
        .as_array()
        .context("two successor claim bindings")?;
    ensure!(refs.len() == 2, "successor claim evidence scope");
    let booking = doc(&refs[0], &root.join("booking.json"))?;
    let launch = doc(&refs[1], &root.join("launch.json"))?;
    ensure!(launch["booking"] == refs[0], "different successor booking");
    let recovery_ref = binding(RECOVERY, RECOVERY_SHA);
    let recovery = doc(&recovery_ref, Path::new(RECOVERY))?;
    let previous = doc(&recovery["prior_staged_owner"], Path::new(PRIOR))?;
    let first = doc(&recovery["historical_terminal"], Path::new(FIRST))?;
    ensure!(
        first["source_uploader_invocation"] == ORIGINAL_IID
            && first["observed_failed_and_empty_cgroup_in_fleet"] == true,
        "first owner proof differs"
    );
    for (key, file) in [
        ("booking", "booking.json"),
        ("launch", "launch.json"),
        ("claim", "pipeline-claim.json"),
    ] {
        doc(
            &previous["evidence"][key],
            &Path::new("/home/ubuntu/.codex/diagnostics/horizon-upload-247-staged-680e1173-v1")
                .join(file),
        )?;
    }
    let plan = doc(&recovery["current_reader_plan"], Path::new(PLAN))?;
    let acceptance = doc(&plan["qualification"], Path::new(ACCEPTANCE))?;
    let mut sources = acceptance["source_build_evidence"]
        .as_array()
        .context("reader build evidence")?
        .iter()
        .filter(|entry| entry["path"] == SOURCE);
    let source_ref = sources.next().context("bounded reader source acceptance")?;
    ensure!(sources.next().is_none(), "ambiguous bounded reader source");
    ensure!(source_ref == &binding(SOURCE, "4e0437e3505376711e576fc39dba367792c7154c24cddb9d0270c20ce1565eca"), "published reader source proof changed");
    let source = doc(source_ref, Path::new(SOURCE))?;
    reader_source(&plan, &acceptance, &source)?;
    graph(&c, &booking, &launch, &recovery, &previous)?;
    let pid = launch["unit"]["MainPID"]
        .as_str()
        .context("successor launch pid")?
        .parse::<u32>()?;
    ensure!(pid > 1, "successor PID is invalid");
    Ok(Owner {
        iid: c["invocation_id"].as_str().context("iid")?.into(),
        pid,
        argv: booking["argv"].clone(),
        command: c["expected_exec_start"]
            .as_str()
            .context("successor command")?
            .into(),
        proof: json!({"claim":reference,"booking":refs[0],"launch":refs[1],"admission":booking["admission"],"recovery":recovery_ref,"bounded_reader_source":source_ref,"previous":recovery["prior_staged_owner"],"original":recovery["historical_terminal"]}),
    })
}
/// Bound the old PID 1 failures to the current boot before reporting the successor.
pub fn verify_drains() -> Result<()> {
    verify_registered_drains(None)
}

pub fn verify_registered_drains(additional: Option<(&str, &str)>) -> Result<()> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(
        boot == "3b17d0055c3a4a0e8841da097e0957b5",
        "247 boot changed"
    );
    for (name, iid) in [(ORIGINAL, ORIGINAL_IID), (PRIOR_UNIT, PRIOR_IID)]
        .into_iter()
        .chain(additional)
    {
        let cgroup = Path::new("/sys/fs/cgroup/system.slice").join(name);
        match fs::symlink_metadata(cgroup) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => anyhow::bail!("historical 247 cgroup remains"),
        }
        let output = std::process::Command::new("/usr/bin/journalctl")
            .args([
                "--boot=0",
                "--no-pager",
                "--output=json",
                "--lines=2",
                "_UID=0",
                "_PID=1",
                &format!("UNIT={name}"),
                &format!("INVOCATION_ID={iid}"),
                "MESSAGE_ID=d9b373ed55a64feb8242e02dbe79a49c",
                "UNIT_RESULT=exit-code",
            ])
            .output()?;
        ensure!(
            output.status.success() && output.stdout.len() <= 32768,
            "247 failure journal unavailable"
        );
        let events = std::str::from_utf8(&output.stdout)?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let [event] = events.as_slice() else {
            anyhow::bail!("ambiguous or absent historical failure for {name}")
        };
        ensure!(
            event["_BOOT_ID"] == boot
                && event["_UID"] == "0"
                && event["_PID"] == "1"
                && event["UNIT"] == name
                && event["INVOCATION_ID"] == iid
                && event["UNIT_RESULT"] == "exit-code"
                && event["MESSAGE_ID"] == "d9b373ed55a64feb8242e02dbe79a49c",
            "foreign 247 failure"
        );
    }
    Ok(())
}
pub fn terminal(unit: &Value, name: &str, iid: &str) -> Result<()> {
    ensure!(
        unit["Id"] == name
            && unit["InvocationID"] == iid
            && unit["ActiveState"] == "failed"
            && unit["SubState"] == "failed"
            && unit["MainPID"] == "0"
            && unit["NRestarts"] == "0"
            && unit["Result"] == "exit-code"
            && unit["ExecMainStatus"]
                .as_str()
                .is_some_and(|s| s.parse::<u16>().is_ok_and(|n| n > 0)),
        "historical 247 failure changed"
    );
    Ok(())
}

pub fn historical_claims(fleet: &Value) -> Result<()> {
    let prior = doc(&binding(PRIOR, PRIOR_SHA), Path::new(PRIOR))?;
    validate_history(fleet, &prior)
}

pub fn validate_history(fleet: &Value, prior: &Value) -> Result<()> {
    let claims = fleet["pipelines"].as_array().context("247 pipelines")?;
    let active = fleet["active"].as_array().context("247 active owners")?;
    for r in claims.iter().chain(active) {
        if r["epoch"] == 247 && r["phase"] == "upload-readback" {
            ensure!(
                matches!(r["unit"]["Id"].as_str(), Some(ORIGINAL | PRIOR_UNIT | UNIT)),
                "epoch 247 has an unregistered uploader"
            );
        }
    }
    let second = &prior["evidence"];
    for (unit, iid, evidence) in [
        (
            PRIOR_UNIT,
            PRIOR_IID,
            json!([second["booking"], second["launch"]]),
        ),
        (
            ORIGINAL,
            ORIGINAL_IID,
            json!([
                binding(
                    "/var/lib/jetstreamer/horizon247-delivery-admission-20261119-v1/review.json",
                    "e246fbcd736561f926d3d998b6ad25ba189e829e6852c781b4f286234e9b500a"
                ),
                binding(
                    "/home/ubuntu/.codex/diagnostics/horizon-fleet-cycle0010-20261120-v1/delivery247-initial-owner.json",
                    "52f5c892af9acef8d2cb273ec6a2a5737facfb504e0d9e2f71f4434720a7a3f9"
                )
            ]),
        ),
    ] {
        let mut found = claims
            .iter()
            .filter(|r| r["unit"]["Id"] == unit || r["expected_invocation_id"] == iid);
        let r = found.next().context("missing original 247 claim")?;
        ensure!(
            found.next().is_none()
                && r["epoch"] == 247
                && r["phase"] == "upload-readback"
                && r["unit"]["Id"] == unit
                && r["expected_invocation_id"] == iid
                && r["evidence"] == evidence
                && r["live"] == false
                && r["unit"] == fleet["unit_census"][unit]
                && !active
                    .iter()
                    .any(|r| r["unit"]["Id"] == unit || r["expected_invocation_id"] == iid),
            "historical 247 claim changed or active"
        );
        terminal(&r["unit"], unit, iid)?;
    }
    Ok(())
}
