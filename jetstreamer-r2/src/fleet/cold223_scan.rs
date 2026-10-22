//! Closed observational owner of the admitted cold snapshot tests, never delivery.
use super::*;
pub(super) const UNIT: &str = "archive-223-cold-snapshot-test-actual-v1.service";
const BINARY: &str = "/var/lib/jetstreamer/horizon-223-cold-snapshot-supervisor-294d2330-v1/jetstreamer-horizon-ram-snapshot-test";
const PLAN: &str = "/var/lib/jetstreamer/horizon-223-cold-snapshot-actual-plan-2330-v1/plan.json";
const PLAN_SHA: &str = "73dbfebae627bc2fe8b57c70ec32904d6ff1912fa7909ea9864967d0da63eca2";
const SELF_SHA: &str = "01050839a5804e6004d42a4d9fa218e507c3818ed3ffaf1841f43fbb6ba90ca1";
const STATE: &str =
    "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-cold-actual-v1";
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == "private-cold-snapshot-verification" && unit == UNIT
}
fn command() -> String {
    format!(
        "{{ path={BINARY} ; argv[]={BINARY} {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {SELF_SHA}"
    )
}
fn checked(c: &PipelineClaim, intent: &Value) -> Result<()> {
    ensure!(
        c.epoch == 223
            && scope(&c.phase, &c.unit)
            && c.expected_exec_start
                .split_once(" ; ignore_errors=")
                .map(|(s, _)| s)
                == Some(command().as_str())
            && intent["schema"] == "jetstreamer-private-epoch223-cold-v1625-ram-snapshot-intent-v1"
            && intent["invocation_id"] == c.invocation_id
            && intent["plan_sha256"] == PLAN_SHA
            && intent["self_sha256"] == SELF_SHA
            && intent["test_sha256"]
                == "d685cbbe8ad720e1bff567ebbcfbd92d92e47f16d798e74783c06e0114c0b92f"
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
    ensure!(
        c.evidence.len() == 1 && c.evidence[0].path == Path::new(STATE).join("intent.json"),
        "private223 cold snapshot needs its exact durable supervisor intent"
    );
    checked(c, &bound_json(&c.evidence[0])?)?;
    let plan = bound_json(&BoundFile {
        path: PLAN.into(),
        sha256: PLAN_SHA.into(),
    })?;
    ensure!(
        plan["mode"] == "snapshot-tests"
            && plan["unit"] == UNIT
            && plan["schema"] == "jetstreamer-private-epoch223-cold-ram-snapshot-test-plan-v1",
        "private223 cold snapshot plan differs"
    );
    Ok(())
}
pub(super) fn validate_live(c: &PipelineClaim, current: &Value) -> Result<()> {
    validate(c)?;
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
        ("ReadWritePaths", STATE),
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
