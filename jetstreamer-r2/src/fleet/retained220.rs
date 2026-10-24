//! Observational registration of the three exact preserved-prefix rereads.
//! No replay, canonical import, sidecar, ETA or publication authority.
use super::*;

pub(super) const SCHEMA: &str = "jetstreamer-private-retained220-prefix-reread-launch-v1";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-retained220-222-full-prepared-v1";
const ARCHIVES: &str = "/home/ubuntu/.jetstreamer-private/adaptive-220-223-current-9d8e964-v1/lane-a/private/destination-5af206ff1dc2bf937d80da0ea255ab459f3b370f67b1c83ed238da29f1de146e/work/root-cohort-220-223/run-2161856-1791998246210466037/archives";

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    (220..=222).contains(&c.epoch)
        && c.unit
            == format!(
                "horizon-independent-full-read-{}-retained-prefix-v1.service",
                c.epoch
            )
}

fn command(epoch: u64) -> String {
    format!(
        "{{ path={PACKAGE}/verify_archive ; argv[]={PACKAGE}/verify_archive {ARCHIVES}/epoch-{epoch}.jet --full --internal-full --threads 8"
    )
}

fn immutable_command(value: &Value) -> Option<&str> {
    value
        .as_str()?
        .split_once(" ; ignore_errors=")
        .map(|(a, _)| a)
}

pub(super) fn live(current: &Value) -> bool {
    current["Type"] == "oneshot"
        && current["ActiveState"] == "activating"
        && current["SubState"] == "start"
        && current["MainPID"]
            .as_str()
            .and_then(|v| v.parse::<u32>().ok())
            .is_some_and(|p| p > 0)
}

pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    ensure!(
        namespace(c)
            && live(current)
            && current["Id"] == c.unit
            && current["InvocationID"] == c.invocation_id
            && current["NRestarts"] == "0"
            && current["Result"] == "success"
            && immutable_command(&current["ExecStart"]) == Some(command(c.epoch).as_str()),
        "retained-prefix reader is not the exact live read-only invocation"
    );
    Ok(())
}

pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    let bytes = match c.epoch {
        220 => 135699623364u64,
        221 => 137055363091,
        222 => 133175903649,
        _ => 0,
    };
    ensure!(
        namespace(c)
            && c.invocation_id.len() == 32
            && c.invocation_id.bytes().all(|b| b.is_ascii_hexdigit())
            && c.scratch_path == Path::new(ARCHIVES)
            && r["schema"] == SCHEMA
            && r["epoch"] == c.epoch
            && r["launched"] == true
            && r["unit"] == c.unit
            && r["invocation_id"] == c.invocation_id
            && r["archive_path"] == format!("{ARCHIVES}/epoch-{}.jet", c.epoch)
            && r["archive_bytes"] == bytes
            && r["verifier_sha256"]
                == "8a3c45b958bf69e6d8463d2e215cbd0ff30ec2c251c4d20ae40193a6cecae9f3"
            && r["package_seal_sha256"]
                == "7b2a8be69a8567ca0eaca79d475efa6e87cbf536f06e329dea7681a52d8c4b22"
            && r["admission"]["path"]
                == "/var/lib/jetstreamer/horizon-retained-reread-admission-1837-v1/admission.json"
            && r["admission"]["sha256"]
                == "e78368db87f44dccf2231da88147b1f2f1cec9dbcdb08afd8eff9379a0544e30"
            && r["original_primary_evidence_sha256"]
                == "1c336e5e70aa9844de703db3eae14324f8d79eaed752844bb0e0e7fe26016004"
            && immutable_command(&r["expected_exec_start"]) == Some(command(c.epoch).as_str())
            && [
                "archive_mutations",
                "ordinary_replay_authorized",
                "recovery_import_authorized",
                "canonical_sidecar_authorized",
                "publication_authorized",
                "local_retirement_authorized",
                "remote_mutations",
                "r2_mutations"
            ]
            .iter()
            .all(|k| r[*k] == false),
        "retained-prefix reader launch is not the exact non-authorizing profile"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root-only read-only exact launch and live command qualification for retained220-222"]
    fn root_exact_sealed_launches_match_current_private_readers() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        for (epoch, id, digest) in [
            (
                220,
                "1536bf6f640d4df280f8bedf86a55094",
                "29f2cb8216dec87d2be79ad453aa59e30d176d20306a8e4b7529f7a45f870fcc",
            ),
            (
                221,
                "d82f8375cc184e5283a1694c48009ac4",
                "5904fb70b71aa00f62cfc8781fc1c51f818f79167c63de794ce67d49e030da09",
            ),
            (
                222,
                "4a699212c24b43b488c87165ac4ba326",
                "0772393f7f8bc14150d8a6bfd2caf13a584f5aa8ea8468a9d57d20a713957afb",
            ),
        ] {
            let c = DiagnosticClaim {epoch,unit:format!("horizon-independent-full-read-{epoch}-retained-prefix-v1.service"),invocation_id:id.into(),scratch_path:ARCHIVES.into(),launch_receipt:BoundFile {path:format!("/var/lib/jetstreamer/horizon-retained220-222-reread-launch-1837-v1/epoch-{epoch}.json").into(),sha256:digest.into()}};
            checked_diagnostic_launch(&c).unwrap();
            validate_live(&c, &unit(&c.unit).unwrap()).unwrap();
        }
    }

    #[test]
    fn launch_never_grants_replay_import_or_publication() {
        let c = DiagnosticClaim {
            epoch: 220,
            unit: "horizon-independent-full-read-220-retained-prefix-v1.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: ARCHIVES.into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let r = json!({"schema":SCHEMA,"epoch":220,"launched":true,"unit":c.unit,"invocation_id":c.invocation_id,"archive_path":format!("{ARCHIVES}/epoch-220.jet"),"archive_bytes":135699623364u64,"verifier_sha256":"8a3c45b958bf69e6d8463d2e215cbd0ff30ec2c251c4d20ae40193a6cecae9f3","package_seal_sha256":"7b2a8be69a8567ca0eaca79d475efa6e87cbf536f06e329dea7681a52d8c4b22","admission":{"path":"/var/lib/jetstreamer/horizon-retained-reread-admission-1837-v1/admission.json","sha256":"e78368db87f44dccf2231da88147b1f2f1cec9dbcdb08afd8eff9379a0544e30"},"original_primary_evidence_sha256":"1c336e5e70aa9844de703db3eae14324f8d79eaed752844bb0e0e7fe26016004","expected_exec_start":format!("{} ; ignore_errors=no }}",command(220)),"archive_mutations":false,"ordinary_replay_authorized":false,"recovery_import_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        validate_diagnostic_launch(&r, &c).unwrap();
        for key in [
            "archive_mutations",
            "ordinary_replay_authorized",
            "recovery_import_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "local_retirement_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = r.clone();
            bad[key] = json!(true);
            assert!(validate_diagnostic_launch(&bad, &c).is_err(), "{key}");
        }
        for (key, value) in [
            ("archive_bytes", json!(1)),
            ("verifier_sha256", json!("c".repeat(64))),
            ("package_seal_sha256", json!("c".repeat(64))),
            ("epoch", json!(221)),
            (
                "expected_exec_start",
                json!(format!("{} ; ignore_errors=no }}", command(221))),
            ),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &c).is_err(), "{key}");
        }
    }

    #[test]
    fn exact_live_oneshot_never_borrows_other_reader_or_phase() {
        let c = DiagnosticClaim {
            epoch: 220,
            unit: "horizon-independent-full-read-220-retained-prefix-v1.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: ARCHIVES.into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let r = json!({"Id":c.unit,"InvocationID":c.invocation_id,"Type":"oneshot","ActiveState":"activating","SubState":"start","MainPID":"123","NRestarts":"0","Result":"success","ExecStart":format!("{} ; ignore_errors=no ; pid=123 }}",command(220))});
        validate_live(&c, &r).unwrap();
        for (key, value) in [
            ("Type", json!("simple")),
            ("MainPID", json!("0")),
            ("ActiveState", json!("inactive")),
            ("SubState", json!("start-pre")),
            ("InvocationID", json!("c".repeat(32))),
            ("NRestarts", json!("1")),
            (
                "ExecStart",
                json!(format!("{} ; ignore_errors=no }}", command(221))),
            ),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(validate_live(&c, &bad).is_err(), "{key}");
        }
        assert!(!namespace(&DiagnosticClaim { epoch: 223, ..c }));
    }
}
