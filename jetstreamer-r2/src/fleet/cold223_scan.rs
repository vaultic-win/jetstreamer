//! Closed observational owner of the admitted cold snapshot tests, never delivery.
use super::*;
#[path = "native223_v1620_event.rs"]
mod native20_event;
#[path = "native223_v1620_input_capture.rs"]
mod native20_input_capture;
pub(super) use native20_event::{
    event_census as native20_event_census, event_predecessor as native20_event_predecessor,
    terminal_census as native20_terminal_census,
    terminal_predecessor as native20_terminal_predecessor, terminal_status_identity,
};
pub(super) use native20_input_capture::run as capture_native20_input;
pub(super) const UNIT: &str = "archive-223-cold-snapshot-test-actual-v1.service";
const BINARY: &str = "/var/lib/jetstreamer/horizon-223-cold-snapshot-supervisor-294d2330-v1/jetstreamer-horizon-ram-snapshot-test";
const PLAN: &str = "/var/lib/jetstreamer/horizon-223-cold-snapshot-actual-plan-2330-v1/plan.json";
const PLAN_SHA: &str = "73dbfebae627bc2fe8b57c70ec32904d6ff1912fa7909ea9864967d0da63eca2";
const SELF_SHA: &str = "01050839a5804e6004d42a4d9fa218e507c3818ed3ffaf1841f43fbb6ba90ca1";
const STATE: &str =
    "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-cold-actual-v1";
struct Profile {
    unit: &'static str,
    binary: &'static str,
    plan: &'static str,
    plan_sha: &'static str,
    self_sha: &'static str,
    state: &'static str,
    test_sha: &'static str,
    intent_schema: &'static str,
    plan_schema: &'static str,
}
const OLD: Profile = Profile {
    unit: UNIT,
    binary: BINARY,
    plan: PLAN,
    plan_sha: PLAN_SHA,
    self_sha: SELF_SHA,
    state: STATE,
    test_sha: "d685cbbe8ad720e1bff567ebbcfbd92d92e47f16d798e74783c06e0114c0b92f",
    intent_schema: "jetstreamer-private-epoch223-cold-v1625-ram-snapshot-intent-v1",
    plan_schema: "jetstreamer-private-epoch223-cold-ram-snapshot-test-plan-v1",
};
const WARMUP: Profile = Profile {
    unit: "archive-223-warmup-snapshot-actual-v1.service",
    binary: "/var/lib/jetstreamer/horizon-223-warmup-native-supervisor-f9d60b79-v1/jetstreamer-horizon-ram-snapshot-test",
    plan: "/var/lib/jetstreamer/horizon-223-warmup-native-actual-plan312-v1/plan.json",
    plan_sha: "314b247ae34e31124c53619350ae08bb0d18064c65911d55417ea77fb91e4e8a",
    self_sha: "ee11783c692f16761f656161ec3ae47323e21f517d75634fc2929b260d8c0523",
    state: "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-warmup-actual-v1",
    test_sha: "647665f8abc11570f40d0fac45c4e17dbe7c1c86a0a91da5700fe03fc3f4ab67",
    intent_schema: "jetstreamer-private-epoch223-warmup-v1625-ram-snapshot-intent-v1",
    plan_schema: "jetstreamer-private-epoch223-warmup-native-input-plan-v1",
};
const NATIVE20: Profile = Profile {
    unit: "archive-223-v1620-native-input-actual-v1.service",
    binary: "/var/lib/jetstreamer/horizon-223-v1620-native-supervisor-v1/jetstreamer-horizon-ram-snapshot-test",
    plan: "/var/lib/jetstreamer/horizon-223-v1620-native-actual-plan-v1/plan.json",
    plan_sha: "395262f95e2dc504300b3174542936aaf5996684060e2f9c804f66d4ed13f87d",
    self_sha: "8768a500512a36a3f1d887f4383c6b7c42feb4924cd4f32e8b237ad02d65ae85",
    state: "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-v1620-actual-v1",
    test_sha: "01e69e4a5a1ec30d5ad9055c60aa5f1dc98e7fddc93001cd2db389937e78079a",
    intent_schema: "jetstreamer-private-epoch223-native-v1620-ram-snapshot-intent-v1",
    plan_schema: "jetstreamer-private-epoch223-v1620-native-input-plan-v1",
};
const NATIVE20_RELEASE: Profile = Profile {
    unit: "archive-223-v1620-native-input-release-actual-v1.service",
    binary: "/var/lib/jetstreamer/horizon-223-v1620-native-release-supervisor-v1/jetstreamer-horizon-ram-snapshot-test",
    plan: "/var/lib/jetstreamer/horizon-223-v1620-native-release-actual-plan-v1/plan.json",
    plan_sha: "c4f0f7b97bf648ca3e7370b73bf5d0d03319d0c50f91d180136576ed6faad2f7",
    self_sha: "bd4f1bc15e2a63c37e6d26f6ae91a51a4c5fa27ca03d8b893ac4d50e4a976fd9",
    state: "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-v1620-release-actual-v1",
    test_sha: "526448fac7ff1db52450947cdbb0acab46cacf96d356ff36325b7b87c0596486",
    intent_schema: "jetstreamer-private-epoch223-native-v1620-ram-snapshot-intent-v1",
    plan_schema: "jetstreamer-private-epoch223-v1620-native-input-plan-v1",
};
fn profile(unit: &str) -> Result<&'static Profile> {
    match unit {
        UNIT => Ok(&OLD),
        n if n == WARMUP.unit => Ok(&WARMUP),
        n if n == NATIVE20.unit => Ok(&NATIVE20),
        n if n == NATIVE20_RELEASE.unit => Ok(&NATIVE20_RELEASE),
        _ => anyhow::bail!("unknown223nativeinput owner"),
    }
}
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == "private-cold-snapshot-verification" && profile(unit).is_ok()
}
#[cfg(test)]
fn command() -> String {
    profile_command(&OLD)
}
fn profile_command(p: &Profile) -> String {
    format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {}",
        p.binary, p.binary, p.plan, p.plan_sha, p.self_sha
    )
}
fn checked(c: &PipelineClaim, intent: &Value) -> Result<()> {
    let p = profile(&c.unit)?;
    ensure!(
        c.epoch == 223
            && scope(&c.phase, &c.unit)
            && c.expected_exec_start
                .split_once(" ; ignore_errors=")
                .map(|(s, _)| s)
                == Some(profile_command(p).as_str())
            && intent["schema"] == p.intent_schema
            && intent["invocation_id"] == c.invocation_id
            && intent["plan_sha256"] == p.plan_sha
            && intent["self_sha256"] == p.self_sha
            && intent["test_sha256"] == p.test_sha
            && intent["snapshot_sha256"]
                == "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665"
            && intent["genesis_sha256"]
                == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"
            && intent["maximum_memory_bytes"] == 128u64 << 30
            && intent["tmpfs_bytes"] == 512u64 << 30
            && intent["entry_replay"] == false
            && intent["publication_authorized"] == false
            && intent["remote_mutations"] == false
            && intent["r2_mutations"] == false,
        "private223 cold snapshot owner differs from the exact admitted test intent"
    );
    Ok(())
}
pub(super) fn validate(c: &PipelineClaim) -> Result<()> {
    let p = profile(&c.unit)?;
    ensure!(
        c.evidence.len() == 1 && c.evidence[0].path == Path::new(p.state).join("intent.json"),
        "private223 cold snapshot needs its exact durable supervisor intent"
    );
    checked(c, &bound_json(&c.evidence[0])?)?;
    let plan = bound_json(&BoundFile {
        path: p.plan.into(),
        sha256: p.plan_sha.into(),
    })?;
    ensure!(
        plan["mode"] == "snapshot-tests"
            && plan["unit"] == p.unit
            && plan["schema"] == p.plan_schema,
        "private223 cold snapshot plan differs"
    );
    Ok(())
}
pub(super) fn validate_live(c: &PipelineClaim, current: &Value) -> Result<()> {
    validate(c)?;
    let p = profile(&c.unit)?;
    ensure!(
        current["Type"] == "oneshot",
        "private223 cold snapshot must be oneshot"
    );
    let out = ProcessCommand::new("systemctl").args(["show", &c.unit, "--property=User,Group,DynamicUser,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ProtectSystem,ProtectHome,ProtectControlGroups,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,TimeoutStartUSec,TemporaryFileSystem,OOMPolicy,OOMScoreAdjust"]).output()?;
    ensure!(
        out.status.success(),
        "private223 cold snapshot sandbox unreadable"
    );
    let text = std::str::from_utf8(&out.stdout)?;
    let fields: BTreeMap<_, _> = text.lines().filter_map(|l| l.split_once('=')).collect();
    for (key, expected) in [
        ("User", "root"),
        ("Group", "root"),
        ("DynamicUser", "no"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "120259084288"),
        ("MemoryMax", "137438953472"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("TasksMax", "512"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("ProtectControlGroups", "yes"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        (
            "CapabilityBoundingSet",
            "cap_dac_override cap_kill cap_setgid cap_setuid",
        ),
        (
            "AmbientCapabilities",
            "cap_dac_override cap_kill cap_setgid cap_setuid",
        ),
        ("ReadWritePaths", p.state),
        ("TimeoutStartUSec", "35min"),
        (
            "TemporaryFileSystem",
            "/tmp:rw,size=512G,nr_inodes=1048576,nosuid,nodev,mode=1777",
        ),
        ("OOMPolicy", "kill"),
        ("OOMScoreAdjust", "1000"),
    ] {
        ensure!(
            fields.get(key) == Some(&expected),
            "private223 cold snapshot sandbox differs:{key}"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native20_owner_cannot_borrow_the_v1625_harness_or_entry_authority() {
        for selected in [&NATIVE20, &NATIVE20_RELEASE] {
            let c = PipelineClaim {
                epoch: 223,
                phase: "private-cold-snapshot-verification".into(),
                unit: selected.unit.into(),
                invocation_id: "c".repeat(32),
                expected_exec_start: format!("{} ; ignore_errors=no }}", profile_command(selected)),
                evidence: vec![],
            };
            let intent = json!({"schema":selected.intent_schema,"invocation_id":c.invocation_id,
            "plan_sha256":selected.plan_sha,"self_sha256":selected.self_sha,"test_sha256":selected.test_sha,
            "snapshot_sha256":"301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665",
            "genesis_sha256":"133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            "maximum_memory_bytes":128u64<<30,"tmpfs_bytes":512u64<<30,"entry_replay":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
            checked(&c, &intent).unwrap();
            assert_eq!(pipeline_unit_range(&c.phase, &c.unit).unwrap(), 223..=223);
            for (key, value) in [
                ("schema", json!(WARMUP.intent_schema)),
                ("test_sha256", json!(WARMUP.test_sha)),
                ("plan_sha256", json!(WARMUP.plan_sha)),
                ("entry_replay", json!(true)),
                ("maximum_memory_bytes", json!(256u64 << 30)),
            ] {
                let mut bad = intent.clone();
                bad[key] = value;
                assert!(checked(&c, &bad).is_err(), "{key}");
            }
            assert!(!scope(
                &c.phase,
                "archive-223-v1620-native-input-capability-v1.service"
            ));
            assert!(pipeline_unit_range("upload-readback", &c.unit).is_err());
        }
    }
    #[test]
    fn warmup_input_owner_retains_its_own_plan_worker_and_no_entry_authority() {
        let c = PipelineClaim {
            epoch: 223,
            phase: "private-cold-snapshot-verification".into(),
            unit: WARMUP.unit.into(),
            invocation_id: "b".repeat(32),
            expected_exec_start: format!("{} ; ignore_errors=no }}", profile_command(&WARMUP)),
            evidence: vec![],
        };
        let intent = json!({"schema":WARMUP.intent_schema,"invocation_id":c.invocation_id,
            "plan_sha256":WARMUP.plan_sha,"self_sha256":WARMUP.self_sha,"test_sha256":WARMUP.test_sha,
            "snapshot_sha256":"301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665",
            "genesis_sha256":"133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            "maximum_memory_bytes":128u64<<30,"tmpfs_bytes":512u64<<30,"entry_replay":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        checked(&c, &intent).unwrap();
        assert_eq!(pipeline_unit_range(&c.phase, &c.unit).unwrap(), 223..=223);
        for (key, value) in [
            ("plan_sha256", json!(OLD.plan_sha)),
            ("self_sha256", json!(OLD.self_sha)),
            ("test_sha256", json!(OLD.test_sha)),
            ("entry_replay", json!(true)),
        ] {
            let mut bad = intent.clone();
            bad[key] = value;
            assert!(checked(&c, &bad).is_err());
        }
        assert!(!scope(
            &c.phase,
            "archive-223-warmup-snapshot-capability-v1.service"
        ));
        assert!(pipeline_unit_range("upload-readback", &c.unit).is_err());
    }
    #[test]
    fn exact_cold_snapshot_owner_cannot_borrow_tail_or_delivery_authority() {
        let c = PipelineClaim {
            epoch: 223,
            phase: "private-cold-snapshot-verification".into(),
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: format!("{} ; ignore_errors=no }}", command()),
            evidence: vec![],
        };
        let intent = json!({"schema":"jetstreamer-private-epoch223-cold-v1625-ram-snapshot-intent-v1",
            "invocation_id":c.invocation_id,"plan_sha256":PLAN_SHA,"self_sha256":SELF_SHA,
            "test_sha256":"d685cbbe8ad720e1bff567ebbcfbd92d92e47f16d798e74783c06e0114c0b92f",
            "snapshot_sha256":"301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665",
            "genesis_sha256":"133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            "maximum_memory_bytes":128u64<<30,"tmpfs_bytes":512u64<<30,"entry_replay":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        checked(&c, &intent).unwrap();
        assert_eq!(pipeline_unit_range(&c.phase, &c.unit).unwrap(), 223..=223);
        assert!(pipeline_unit_range("full-verification", UNIT).is_err());
        assert!(pipeline_unit_range("private-tail-verification", UNIT).is_err());
        assert!(
            pipeline_unit_range(&c.phase, "archive-223-cold-snapshot-test-other.service").is_err()
        );
        for key in intent.as_object().unwrap().keys() {
            let mut bad = intent.clone();
            bad[key] = Value::Null;
            assert!(checked(&c, &bad).is_err(), "{key}");
        }
        assert_eq!(
            private_qualification_inventory_state("failed-needs-repair"),
            "failed-needs-repair"
        );
    }
}
