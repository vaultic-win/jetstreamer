//! Private full/plugin stages stay qualification-blocked, never delivery/ETA.
use super::*;
const FULL_UNIT: &str = "horizon-private144-full-verification-20261022-v1.service";
const PLUGIN_UNIT: &str = "horizon-private144-plugin-verification-20261022-v1.service";
const RUNNER: &str = "/usr/local/lib/jetstreamer/horizon-epoch144-private-scan-tools-20261022-v1/jetstreamer-epoch144-private-verify";
const RUNNER_SHA: &str = "6d46519f639818d2dffd0529e2db21d8da71cf57f870c224f57e241b19aaa194";
const ASSEMBLY_FULL_UNIT: &str = "horizon-assembly144-full-verification-20261022-v1.service";
const ASSEMBLY_PLUGIN_UNIT: &str = "horizon-assembly144-plugin-verification-20261022-v1.service";
const ASSEMBLY_RUNNER: &str = "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-scan-tools-20261022-v1/jetstreamer-epoch144-private-verify";
const ASSEMBLY_RUNNER_SHA: &str =
    "7dfe0fdabbee8e5f79b131c2b7cece49dbebe489168fe195a9086ab25f0b8810";
fn recovery(unit: &str) -> bool {
    matches!(unit, ASSEMBLY_FULL_UNIT | ASSEMBLY_PLUGIN_UNIT)
}
fn stage(unit: &str) -> &'static str {
    if matches!(unit, FULL_UNIT | ASSEMBLY_FULL_UNIT) {
        "full"
    } else {
        "plugin"
    }
}
fn state_root(unit: &str) -> &'static str {
    if recovery(unit) {
        "/var/lib/jetstreamer/horizon-epoch144-assembly-only-verification-20261022-v1"
    } else {
        "/var/lib/jetstreamer/horizon-epoch144-private-verification-20261022-v1"
    }
}
pub(super) fn unit_name(unit: &str) -> bool {
    matches!(
        unit,
        FULL_UNIT | PLUGIN_UNIT | ASSEMBLY_FULL_UNIT | ASSEMBLY_PLUGIN_UNIT
    )
}
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    matches!(
        (phase, unit),
        ("private-full-verification", FULL_UNIT)
            | ("private-plugin-verification", PLUGIN_UNIT)
            | ("private-full-verification", ASSEMBLY_FULL_UNIT)
            | ("private-plugin-verification", ASSEMBLY_PLUGIN_UNIT)
    )
}
fn checked(c: &PipelineClaim, r: &Value, p: &Value, o: &Value) -> Result<()> {
    if recovery(&c.unit) || r["schema"] == "jetstreamer-private144-assembly-only-scan-launch-v1" {
        return checked_recovery(c, r, p, o);
    }
    ensure!(
        c.epoch == 144
            && scope(&c.phase, &c.unit)
            && r["schema"] == "jetstreamer-private144-scan-launch-v2"
            && r["epoch"] == 144
            && r["unit"] == c.unit
            && r["invocation_id"] == c.invocation_id
            && r["expected_exec_start"] == c.expected_exec_start
            && r["runner_sha256"] == RUNNER_SHA
            && r["private_verification_only"] == true,
        "foreign private144scan launch"
    );
    for key in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(r[key] == false, "private144scan grants authority:{key}");
    }
    let stage = if c.unit == FULL_UNIT {
        "full"
    } else {
        "plugin"
    };
    let pb: BoundFile = serde_json::from_value(r["scan_plan"].clone())?;
    ensure!(
        pb.path
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-epoch144-private-scan-plan-20261022-v1"
            )
            .join(format!("{stage}.json"))
            && canonical_digest(&r["scan_plan"]["sha256"])
            && p["schema"] == "jetstreamer-private144-verification-plan-v2"
            && p["stage"] == stage
            && p["state_directory"]
                == format!(
                    "/var/lib/jetstreamer/horizon-epoch144-private-verification-20261022-v1/{stage}"
                )
            && p["producer_outcome"] == r["producer_outcome"],
        "private144scan plan/source differs"
    );
    let command = format!(
        "{{ path={RUNNER} ; argv[]={RUNNER} {} --plan-sha256 {} --self-sha256 {RUNNER_SHA}",
        pb.path.display(),
        pb.sha256
    );
    ensure!(
        c.expected_exec_start
            .split_once(" ; ignore_errors=")
            .map(|(s, _)| s)
            == Some(command.as_str()),
        "private144scan command substituted"
    );
    ensure!(
        p["verifier"]["sha256"]
            == if stage == "full" {
                "41c03e493daa309ab7cffd9760b4e6cfe2195b3af0bb13a17f19508eb929d6e7"
            } else {
                "73e7535b9cedc7e565a92735ca6e07c7efb8e66755a6d5272ed16649b4d8cee9"
            },
        "unqualified private144 verifier"
    );
    ensure!(
        o["schema"] == "jetstreamer-private-epoch144-checkpoint-continuation-v2"
            && o["producer_unit"] == continuation144::UNIT
            && o["producer_invocation_id"] == "8fddd3ef045c4fe5b12c7d25f43a4b73"
            && o["node_sha256"] == continuation144::NODE_SHA
            && o["plan"]["sha256"]
                == "7d03772b0cbb865822eec517d3e856f0c28cbd7bbcb7e24ae58ed708647cf8df"
            && o["assembly"]["slots_merged"] == 432000
            && o["assembly"]["provenance_version"] == 4
            && o["fresh_prefix_full_validation_passed"] == true
            && o["fresh_native_checkpoint_matches"] == true
            && o["publication_authorized"] == false
            && o["canonical_sidecar_authorized"] == false
            && o["r2_mutations"] == false,
        "private144scan requires genuine complete assembly"
    );
    Ok(())
}
fn checked_recovery(c: &PipelineClaim, r: &Value, p: &Value, o: &Value) -> Result<()> {
    let stage = stage(&c.unit);
    ensure!(
        c.epoch == 144
            && recovery(&c.unit)
            && scope(&c.phase, &c.unit)
            && r["schema"] == "jetstreamer-private144-assembly-only-scan-launch-v1"
            && r["epoch"] == 144
            && r["unit"] == c.unit
            && r["invocation_id"] == c.invocation_id
            && r["expected_exec_start"] == c.expected_exec_start
            && r["runner_sha256"] == ASSEMBLY_RUNNER_SHA
            && r["private_verification_only"] == true,
        "foreign assembly-only scan launch"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(r[flag] == false, "assembly scan grants authority:{flag}");
    }
    let pb: BoundFile = serde_json::from_value(r["scan_plan"].clone())?;
    ensure!(
        pb.path
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-scan-plan-20261022-v1"
            )
            .join(format!("{stage}.json"))
            && canonical_digest(&r["scan_plan"]["sha256"])
            && p["schema"] == "jetstreamer-private144-assembly-only-verification-plan-v1"
            && p["stage"] == stage
            && p["state_directory"] == format!("{}/{stage}", state_root(&c.unit))
            && p["producer_outcome"] == r["producer_outcome"]
            && p["assembly_launch"]["path"]
                == "/var/lib/jetstreamer/horizon-assembly144-launch-20261022-v1/launch.json"
            && p["assembly_launch"]["sha256"]
                == "f601ec77e6b697192f2032b5afd0d04d8bcb870fc163f341ec00f24d41594a4e",
        "assembly scan plan/source differs"
    );
    let expected = format!(
        "{{ path={ASSEMBLY_RUNNER} ; argv[]={ASSEMBLY_RUNNER} {} --plan-sha256 {} --self-sha256 {ASSEMBLY_RUNNER_SHA}",
        pb.path.display(),
        pb.sha256
    );
    ensure!(
        c.expected_exec_start
            .split_once(" ; ignore_errors=")
            .map(|(s, _)| s)
            == Some(expected.as_str()),
        "assembly scan command differs"
    );
    ensure!(
        p["verifier"]["sha256"]
            == if stage == "full" {
                "41c03e493daa309ab7cffd9760b4e6cfe2195b3af0bb13a17f19508eb929d6e7"
            } else {
                "73e7535b9cedc7e565a92735ca6e07c7efb8e66755a6d5272ed16649b4d8cee9"
            },
        "unqualified assembly verifier"
    );
    ensure!(
        o["schema"] == "jetstreamer-private144-assembly-only-v1"
            && o["epoch"] == 144
            && o["unit"] == assembly144::UNIT
            && o["invocation_id"] == "00ca9bfb862549f6b99117b1ce590365"
            && o["assembler_sha256"] == assembly144::TOOL_SHA
            && o["plan"]["path"] == assembly144::PLAN
            && o["plan"]["sha256"]
                == "fe01e2fe674c1ad72a5f00f28861b970f7fcb3ed78363ad4e685387e499caccd"
            && o["source_archives"] == 2
            && o["slots_merged"] == 432000
            && o["provenance_version"] == 4
            && o["assembly_profile"] == "jetstreamer-epoch144-assembly-only-v1"
            && o["no_replay"] == true
            && o["private_output"]
                == format!("{}/epoch-144-assembly-only-v4.jet", assembly144::ROOT)
            && canonical_digest(&o["archive_sha256"])
            && o["archive_bytes"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 112u64 << 30)
            && o["independent_final_archive_verification_passed"] == false
            && o["current_plugin_verification_passed"] == false
            && o["canonical_sidecar_authorized"] == false
            && o["publication_authorized"] == false
            && o["r2_mutations"] == false,
        "not genuine complete assembly-only source"
    );
    assembly144_admission::check_retained_timeout(&o["original_terminal"])?;
    Ok(())
}
pub(super) fn validate(c: &PipelineClaim) -> Result<()> {
    ensure!(
        c.evidence.len() == 1,
        "private144scan requires one exact launch receipt"
    );
    let r = bound_json(&c.evidence[0])?;
    validate_bound(c, &r)
}
fn validate_bound(c: &PipelineClaim, r: &Value) -> Result<()> {
    let pb: BoundFile = serde_json::from_value(r["scan_plan"].clone())?;
    let ob: BoundFile = serde_json::from_value(r["producer_outcome"].clone())?;
    let p = bound_json(&pb)?;
    checked(c, r, &p, &bound_json(&ob)?)?;
    if recovery(&c.unit) {
        let lb: BoundFile = serde_json::from_value(p["assembly_launch"].clone())?;
        let l = bound_json(&lb)?;
        let assembler = DiagnosticClaim {
            epoch: 144,
            unit: assembly144::UNIT.into(),
            invocation_id: l["invocation_id"].as_str().context("assembler iid")?.into(),
            scratch_path: assembly144::ROOT.into(),
            launch_receipt: lb,
        };
        assembly144::launch(&l, &assembler)?;
    }
    Ok(())
}
pub(super) fn validate_live(c: &PipelineClaim, current: &Value) -> Result<()> {
    validate(c)?;
    live_limits(c, current)
}
fn live_limits(c: &PipelineClaim, current: &Value) -> Result<()> {
    ensure!(
        current["Type"] == "exec"
            && current["InvocationID"] == c.invocation_id
            && current["NRestarts"] == "0",
        "private144scan owner changed"
    );
    let o=ProcessCommand::new("systemctl").args(["show",&c.unit,"--property=User,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,RuntimeMaxUSec"]).output()?;
    ensure!(o.status.success(), "private144scan limits unreadable");
    let text = std::str::from_utf8(&o.stdout)?;
    let fields: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
    for (k, v) in [
        ("User", "root"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "34359738368"),
        ("MemoryMax", "68719476736"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("TasksMax", "512"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", "cap_dac_override"),
        ("AmbientCapabilities", "cap_dac_override"),
    ] {
        ensure!(
            fields.get(k) == Some(&v),
            "private144scan sandbox differs:{k}"
        );
    }
    let stage = stage(&c.unit);
    if recovery(&c.unit) {
        ensure!(
            fields.get("RuntimeMaxUSec") == Some(&"1d"),
            "assembly scan runtime bound differs"
        );
    }
    ensure!(
        fields.get("ReadWritePaths") == Some(&format!("{}/{stage}", state_root(&c.unit)).as_str()),
        "private144scan writable paths differ"
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureSpec {
    schema: String,
    stage: String,
    scan_plan: BoundFile,
}
fn capture_unit(s: &CaptureSpec) -> Result<&'static str> {
    ensure!(
        s.schema == "jetstreamer-private144-assembly-only-scan-capture-spec-v1",
        "foreign assembly scan capture spec"
    );
    let unit = match s.stage.as_str() {
        "full" => ASSEMBLY_FULL_UNIT,
        "plugin" => ASSEMBLY_PLUGIN_UNIT,
        _ => anyhow::bail!("unknown private scan stage"),
    };
    ensure!(
        s.scan_plan.path
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-scan-plan-20261022-v1"
            )
            .join(format!("{}.json", s.stage)),
        "foreign assembly scan plan path"
    );
    Ok(unit)
}
fn capture_owner(v: &Value, unit: &str) -> Result<String> {
    let iid = v["InvocationID"]
        .as_str()
        .context("scan invocation missing")?;
    ensure!(
        v["Id"] == unit
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|p| p > 0)
            && v["NRestarts"] == "0"
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "scan capture needs an exact live zero-restart owner"
    );
    Ok(iid.into())
}
fn completed_assembler(v: &Value) -> Result<()> {
    for (key, expected) in [
        ("Id", assembly144::UNIT),
        ("LoadState", "loaded"),
        ("Type", "exec"),
        ("InvocationID", "00ca9bfb862549f6b99117b1ce590365"),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
    ] {
        ensure!(
            v[key] == expected,
            "assembler not exact clean terminal:{key}"
        );
    }
    Ok(())
}
fn sealed_input(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && path.canonicalize()? == path,
        "unsealed scan input"
    );
    Ok(())
}
/// Observe an independently launched scanner; never launch or admit one.
pub(super) fn capture_launch() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7 && args[3] == "--spec-sha256" && args[5] == "--self-sha256",
        "usage: capture-assembly144-scan-launch SPEC --spec-sha256 SHA --self-sha256 SHA"
    );
    continuation144::sealed_self(&args[6])?;
    let sb = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let sm = fs::symlink_metadata(&sb.path)?;
    ensure!(
        sm.is_file() && sm.uid() == 0 && sm.nlink() == 1 && sm.mode() & 0o222 == 0,
        "unsealed scan capture spec"
    );
    let s: CaptureSpec = serde_json::from_value(bound_json(&sb)?)?;
    let name = capture_unit(&s)?;
    sealed_input(&s.scan_plan.path)?;
    let p = bound_json(&s.scan_plan)?;
    let outcome: BoundFile = serde_json::from_value(p["producer_outcome"].clone())?;
    sealed_input(&outcome.path)?;
    let assembler = unit(assembly144::UNIT)?;
    completed_assembler(&assembler)?;
    let original = assembly144_admission::timeout_properties()?;
    let before = unit(name)?;
    let iid = capture_owner(&before, name)?;
    let mut r = json!({"schema":"jetstreamer-private144-assembly-only-scan-launch-v1",
        "epoch":144,"unit":name,"invocation_id":iid,"expected_exec_start":before["ExecStart"],
        "runner_sha256":ASSEMBLY_RUNNER_SHA,"scan_plan":private157::binding(&s.scan_plan),
        "producer_outcome":p["producer_outcome"],"private_verification_only":true,
        "capture_spec":private157::binding(&sb),"capture_self_sha256":args[6],
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()});
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
        "replay_launch_authorized",
        "local_retirement_authorized",
    ] {
        r[flag] = json!(false);
    }
    let c = PipelineClaim {
        epoch: 144,
        phase: format!("private-{}-verification", s.stage),
        unit: name.into(),
        invocation_id: iid,
        expected_exec_start: before["ExecStart"].as_str().context("scan command")?.into(),
        evidence: vec![],
    };
    validate_bound(&c, &r)?;
    live_limits(&c, &before)?;
    let executable = fs::symlink_metadata(ASSEMBLY_RUNNER)?;
    ensure!(
        executable.is_file()
            && executable.uid() == 0
            && executable.nlink() == 1
            && executable.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read(ASSEMBLY_RUNNER)?)) == ASSEMBLY_RUNNER_SHA,
        "scan runner changed"
    );
    ensure!(
        unit(name)? == before
            && unit(assembly144::UNIT)? == assembler
            && assembly144_admission::timeout_properties()? == original,
        "scan or source owner changed during capture"
    );
    let root = Path::new("/var/lib/jetstreamer/horizon-assembly144-scan-launches-20261022-v1")
        .join(&s.stage);
    // The root parent is precreated by the operator; each stage is no-clobber.
    let parent = root.parent().context("scan capture parent")?;
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        pm.is_dir() && pm.uid() == 0 && pm.mode() & 0o077 == 0 && parent.canonicalize()? == parent,
        "unsafe scan capture parent"
    );
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    File::open(parent)?.sync_all()?;
    private157::immutable_receipt(&root.join("launch.json"), &r)?;
    println!("private assembly scan owner captured; no launch, admission or publication authority");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_requires_exact_stage_and_live_owner() {
        for (stage, unit) in [
            ("full", ASSEMBLY_FULL_UNIT),
            ("plugin", ASSEMBLY_PLUGIN_UNIT),
        ] {
            let mut s = CaptureSpec { schema:"jetstreamer-private144-assembly-only-scan-capture-spec-v1".into(),
                stage:stage.into(), scan_plan:BoundFile {path:format!("/usr/local/lib/jetstreamer/horizon-epoch144-assembly-scan-plan-20261022-v1/{stage}.json").into(), sha256:"a".repeat(64)} };
            assert_eq!(capture_unit(&s).unwrap(), unit);
            let v = json!({"Id":unit,"LoadState":"loaded","ActiveState":"active","SubState":"running",
                "MainPID":"123","InvocationID":"c".repeat(32),"NRestarts":"0"});
            assert_eq!(capture_owner(&v, unit).unwrap(), "c".repeat(32));
            for (key, bad) in [
                ("Id", json!(FULL_UNIT)),
                ("LoadState", json!("not-found")),
                ("ActiveState", json!("failed")),
                ("SubState", json!("exited")),
                ("MainPID", json!("0")),
                ("InvocationID", json!("C".repeat(32))),
                ("NRestarts", json!("1")),
            ] {
                let mut changed = v.clone();
                changed[key] = bad;
                assert!(capture_owner(&changed, unit).is_err(), "{key}");
            }
            s.scan_plan.path = "/tmp/substituted.json".into();
            assert!(capture_unit(&s).is_err());
        }
        assert!(
            serde_json::from_value::<CaptureSpec>(json!({"schema":"x","stage":"full",
            "scan_plan":{"path":"/tmp/x","sha256":"a".repeat(64)},"publication_authorized":true}))
            .is_err()
        );
    }
    #[test]
    fn scan_capture_rejects_running_failed_or_replaced_assembler() {
        let v = json!({"Id":assembly144::UNIT,"LoadState":"loaded","Type":"exec",
            "InvocationID":"00ca9bfb862549f6b99117b1ce590365","MainPID":"0","NRestarts":"0",
            "Result":"success","ExecMainStatus":"0","ActiveState":"active","SubState":"exited"});
        completed_assembler(&v).unwrap();
        for (key, bad) in [
            ("MainPID", "123"),
            ("SubState", "running"),
            ("Result", "timeout"),
            ("InvocationID", "8fddd3ef045c4fe5b12c7d25f43a4b73"),
            ("NRestarts", "1"),
            ("ExecMainStatus", "15"),
        ] {
            let mut changed = v.clone();
            changed[key] = json!(bad);
            assert!(completed_assembler(&changed).is_err(), "{key}");
        }
    }
    fn fixture() -> (PipelineClaim, Value, Value, Value) {
        let plan = json!({"path":"/usr/local/lib/jetstreamer/horizon-epoch144-private-scan-plan-20261022-v1/full.json","sha256":"a".repeat(64)});
        let ob = json!({"path":"/sealed/outcome.json","sha256":"b".repeat(64)});
        let command = format!(
            "{{ path={RUNNER} ; argv[]={RUNNER} {} --plan-sha256 {} --self-sha256 {RUNNER_SHA} ; ignore_errors=no }}",
            plan["path"].as_str().unwrap(),
            plan["sha256"].as_str().unwrap()
        );
        let c = PipelineClaim {
            epoch: 144,
            phase: "private-full-verification".into(),
            unit: FULL_UNIT.into(),
            invocation_id: "c".repeat(32),
            expected_exec_start: command.clone(),
            evidence: vec![],
        };
        let mut r = json!({"schema":"jetstreamer-private144-scan-launch-v2","epoch":144,"unit":FULL_UNIT,"invocation_id":c.invocation_id,"expected_exec_start":command,
            "runner_sha256":RUNNER_SHA,"scan_plan":plan,"producer_outcome":ob,"private_verification_only":true});
        for k in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[k] = json!(false);
        }
        let p = json!({"schema":"jetstreamer-private144-verification-plan-v2","stage":"full","state_directory":"/var/lib/jetstreamer/horizon-epoch144-private-verification-20261022-v1/full",
            "producer_outcome":ob,"verifier":{"sha256":"41c03e493daa309ab7cffd9760b4e6cfe2195b3af0bb13a17f19508eb929d6e7"}});
        let o = json!({"schema":"jetstreamer-private-epoch144-checkpoint-continuation-v2","producer_unit":continuation144::UNIT,"producer_invocation_id":"8fddd3ef045c4fe5b12c7d25f43a4b73",
            "node_sha256":continuation144::NODE_SHA,"plan":{"sha256":"7d03772b0cbb865822eec517d3e856f0c28cbd7bbcb7e24ae58ed708647cf8df"},"assembly":{"slots_merged":432000,"provenance_version":4},
            "fresh_prefix_full_validation_passed":true,"fresh_native_checkpoint_matches":true,"publication_authorized":false,"canonical_sidecar_authorized":false,"r2_mutations":false});
        (c, r, p, o)
    }
    fn recovery_fixture(plugin: bool) -> (PipelineClaim, Value, Value, Value) {
        let unit = if plugin {
            ASSEMBLY_PLUGIN_UNIT
        } else {
            ASSEMBLY_FULL_UNIT
        };
        let stage = stage(unit);
        let pb = json!({"path":format!("/usr/local/lib/jetstreamer/horizon-epoch144-assembly-scan-plan-20261022-v1/{stage}.json"),"sha256":"a".repeat(64)});
        let ob = json!({"path":"/sealed/assembly-outcome","sha256":"b".repeat(64)});
        let cmd = format!(
            "{{ path={ASSEMBLY_RUNNER} ; argv[]={ASSEMBLY_RUNNER} {} --plan-sha256 {} --self-sha256 {ASSEMBLY_RUNNER_SHA} ; ignore_errors=no }}",
            pb["path"].as_str().unwrap(),
            pb["sha256"].as_str().unwrap()
        );
        let c = PipelineClaim {
            epoch: 144,
            phase: format!("private-{stage}-verification"),
            unit: unit.into(),
            invocation_id: "c".repeat(32),
            expected_exec_start: cmd.clone(),
            evidence: vec![],
        };
        let mut r = json!({"schema":"jetstreamer-private144-assembly-only-scan-launch-v1","epoch":144,"unit":unit,"invocation_id":c.invocation_id,
            "expected_exec_start":cmd,"runner_sha256":ASSEMBLY_RUNNER_SHA,"private_verification_only":true,"scan_plan":pb,"producer_outcome":ob});
        for key in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[key] = json!(false);
        }
        let p = json!({"schema":"jetstreamer-private144-assembly-only-verification-plan-v1","stage":stage,
            "state_directory":format!("{}/{stage}",state_root(unit)),"producer_outcome":ob,
            "assembly_launch":{"path":"/var/lib/jetstreamer/horizon-assembly144-launch-20261022-v1/launch.json","sha256":"f601ec77e6b697192f2032b5afd0d04d8bcb870fc163f341ec00f24d41594a4e"},
            "verifier":{"sha256":if plugin {"73e7535b9cedc7e565a92735ca6e07c7efb8e66755a6d5272ed16649b4d8cee9"} else {"41c03e493daa309ab7cffd9760b4e6cfe2195b3af0bb13a17f19508eb929d6e7"}}});
        let o = json!({"schema":"jetstreamer-private144-assembly-only-v1","epoch":144,"unit":assembly144::UNIT,"invocation_id":"00ca9bfb862549f6b99117b1ce590365",
            "assembler_sha256":assembly144::TOOL_SHA,"plan":{"path":assembly144::PLAN,"sha256":"fe01e2fe674c1ad72a5f00f28861b970f7fcb3ed78363ad4e685387e499caccd"},
            "source_archives":2,"slots_merged":432000,"provenance_version":4,"assembly_profile":"jetstreamer-epoch144-assembly-only-v1","no_replay":true,
            "private_output":format!("{}/epoch-144-assembly-only-v4.jet",assembly144::ROOT),"archive_sha256":"d".repeat(64),"archive_bytes":109000000000u64,
            "independent_final_archive_verification_passed":false,"current_plugin_verification_passed":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"r2_mutations":false,
            "original_terminal":{"InvocationID":"8fddd3ef045c4fe5b12c7d25f43a4b73","MainPID":"0","NRestarts":"0","Restart":"no","Result":"timeout","ActiveState":"failed","SubState":"failed","RuntimeMaxUSec":"2h","ExecMainStatus":"15"}});
        (c, r, p, o)
    }
    #[test]
    fn assembly_scans_are_distinct_private_stages_not_aliases_or_delivery() {
        for plugin in [false, true] {
            let (c, r, p, o) = recovery_fixture(plugin);
            checked(&c, &r, &p, &o).unwrap();
            assert_eq!(pipeline_unit_range(&c.phase, &c.unit).unwrap(), 144..=144);
            assert!(pipeline_unit_range("full-verification", &c.unit).is_err());
            assert!(assembly144_admission::check_timeout(&o["original_terminal"]).is_err());
            assembly144_admission::check_retained_timeout(&o["original_terminal"]).unwrap();
            for (key, v) in [
                ("schema", json!("jetstreamer-private144-scan-launch-v2")),
                ("runner_sha256", json!(RUNNER_SHA)),
                ("publication_authorized", json!(true)),
            ] {
                let mut bad = r.clone();
                bad[key] = v;
                assert!(checked(&c, &bad, &p, &o).is_err(), "{key}");
            }
            let mut bad = o.clone();
            bad["original_terminal"]["Result"] = json!("success");
            assert!(checked(&c, &r, &p, &bad).is_err());
            let mut bad = o;
            bad["schema"] = json!("jetstreamer-private-epoch144-checkpoint-continuation-v2");
            assert!(checked(&c, &r, &p, &bad).is_err());
        }
    }
    #[test]
    fn private_stages_have_exact_scope_not_delivery_authority() {
        let (c, r, p, o) = fixture();
        checked(&c, &r, &p, &o).unwrap();
        assert_eq!(pipeline_unit_range(&c.phase, &c.unit).unwrap(), 144..=144);
        assert!(pipeline_unit_range("full-verification", &c.unit).is_err());
        for (k, v) in [
            ("publication_authorized", json!(true)),
            ("current_sidecar_eta_valid", json!(true)),
            ("runner_sha256", json!("d".repeat(64))),
        ] {
            let mut bad = r.clone();
            bad[k] = v;
            assert!(checked(&c, &bad, &p, &o).is_err());
        }
        let mut bad = p.clone();
        bad["stage"] = json!("plugin");
        assert!(checked(&c, &r, &bad, &o).is_err());
        let mut bad = o;
        bad["assembly"]["slots_merged"] = json!(431999);
        assert!(checked(&c, &r, &p, &bad).is_err());
    }
}
