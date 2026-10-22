use std::process::Command;

fn rejected(args: &[&str], expected: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_jetstreamer-node"))
        .args(args)
        .env("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1")
        .env_remove("HORIZON_S3_ENDPOINT")
        .env_remove("HORIZON_ACCESS_KEY_ID")
        .env_remove("HORIZON_SECRET_ACCESS_KEY")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(expected), "{stderr}");
}

#[test]
#[cfg(feature = "epoch223-v1-6-25-qualification")]
fn actual_entrypoint_rejects_maintenance_before_accessing_the_plan() {
    rejected(
        &[
            "--failed-prefix220-recover",
            "/absent/epoch223-must-not-read.json",
            "invalid",
            "invalid",
        ],
        "epoch223 private build accepts only focused epoch223",
    );
    rejected(
        &[
            "--failed-prefix220-recovery-preflight",
            "/absent/epoch223-must-not-read.json",
            "invalid",
            "invalid",
        ],
        "epoch223 private build accepts only focused epoch223",
    );
    rejected(
        &["--failed-prefix220-artifact-probe=220"],
        "epoch223 private build accepts only focused epoch223",
    );
    rejected(
        &["224"],
        "epoch223 private build accepts only focused epoch223",
    );
}

#[test]
#[cfg(feature = "epoch223-v1-6-25-qualification")]
fn actual_focused_gate_precedes_destination_creation_and_snapshot_access() {
    let t = tempfile::tempdir().unwrap();
    let ledger = t.path().join("ledger");
    let output = t.path().join("epoch-223.jet");
    let scratch = t.path().join("scratch");
    let checkpoint = t.path().join("absent-epoch-hashes.txt");
    let snapshot = t
        .path()
        .join("snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst");
    rejected(
        &["223", ledger.to_str().unwrap()],
        "epoch223-v1-6-25-qualification requires",
    );
    let snapshot_arg = format!("--snapshot-archive={}", snapshot.display());
    let checkpoint_arg = format!("--epoch-hashes={}", checkpoint.display());
    let output_arg = format!("--horizon-output={}", output.display());
    let scratch_arg = format!("--replay-scratch={}", scratch.display());
    rejected(
        &[
            "223",
            ledger.to_str().unwrap(),
            "--verify",
            "--qualification-end-slot=96767999",
            &snapshot_arg,
            &checkpoint_arg,
            &output_arg,
            &scratch_arg,
        ],
        "epoch223 paths require one isolated qualification-223-v1625 private root",
    );
    assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 0);
}

#[test]
#[cfg(not(feature = "epoch223-v1-6-25-qualification"))]
fn default_binary_cannot_enable_comparison_or_preflight() {
    for flag in ["--epoch223-tail-comparison", "--epoch223-tail-preflight"] {
        rejected(&["223", flag], "tail flags require the isolated");
    }
}

#[test]
#[cfg(feature = "epoch223-v1-6-25-qualification")]
fn comparison_flags_are_not_repeatable() {
    for flag in ["--epoch223-tail-comparison", "--epoch223-tail-preflight"] {
        rejected(&["223", flag, flag], "duplicate");
    }
}
