use super::*;

const JOINT_RAW_START: u64 = 53_555_937_580;
const RETRY4_END: u64 = 53_665_783_877;
const RETRY4_START: u64 = JOINT_RAW_START + (RETRY4_END - JOINT_CURSOR);
const AFTER_COUNT: u64 = 14_450_000;
const ARCHIVE: &str = "aaaa000000000000000000000000000000000000000000000000000000000000";
const PRE_DIGEST: &str = "bbbb000000000000000000000000000000000000000000000000000000000000";
const POST_DIGEST: &str = "cccc000000000000000000000000000000000000000000000000000000000000";
const ORDINARY_BLOCK: &str = "fixture-root-block";
const COMPARISON_IID: &str = "12121212121212121212121212121212";
const COMPARISON_UNIT: &str = "horizon-epoch168-joint-compare-tests.service";

fn observed_checkpoints() -> (Value, Value) {
    let intermediate = json!({
        "schema": "horizon-epoch168-private-intermediate-checkpoint-comparison-v1",
        "producer_invocation_id": JOINT_IID,
        "ordinary_root_slot": ROOT,
        "matched_consensus_fields": CONSENSUS,
        "joint_raw_next_write_version": JOINT_CURSOR,
        "joint_checkpoint_write_count": 44,
        "retry6_raw_next_write_version": RETRY6_CURSOR,
        "retry6_bootstrap_write_count": 0,
        "archive_publication_authorized": false,
        "closed_joint_archive_comparison_pending": true,
        "enrollment": {"path":"fixture-enrollment","sha256":PRE_DIGEST},
        "verified_line": "[2026-11-27T01:47:33.424827576Z INFO  jetstreamer_node] verified legacy accounts hash at slot 72994766",
        "checkpoint_line": concat!(
            "[2026-11-27T01:47:33.424846496Z INFO  jetstreamer_node::historical_replay] ",
            "historical checkpoint slot=72994766 bank_hash=7e4MCdE5TfDsSZgeq5mQ3N98Sfc6Vka83XRFivd1TD2f ",
            "accounts_hash=B9ETcpnA6DWUEweDVfBTjqJjXML6GmHdbtXWZKBZEZ6J ",
            "last_blockhash=5mMqY7Po42u2cB3L2X6VVvLFkbvPXiZXH2sYMnZiLpnU capitalization=492619716086027476 ",
            "transactions=15087870872 tick_height=4671665088 complete=true writes=44 next_write_version=53560733485"
        ),
    });
    let retry6 = json!({
        "bootstrap": {
            "slot":72994766, "bank_hash":"7e4MCdE5TfDsSZgeq5mQ3N98Sfc6Vka83XRFivd1TD2f",
            "accounts_hash":"B9ETcpnA6DWUEweDVfBTjqJjXML6GmHdbtXWZKBZEZ6J",
            "last_blockhash":"5mMqY7Po42u2cB3L2X6VVvLFkbvPXiZXH2sYMnZiLpnU",
            "capitalization":492619716086027476u64, "transaction_count":15087870872u64,
            "tick_height":4671665088u64, "slot_complete":true, "write_count":0,
            "next_write_version":53573751636u64,
        },
        "emitted_raw_write_versions": { "start": 53573751636u64, "end": 53603087785u64 },
    });
    (intermediate, retry6)
}

fn pid1(unit: &str, iid: &str, time: u64) -> Value {
    json!({
        "_PID":"1", "_UID":"0", "_BOOT_ID":JOINT_BOOT_ID,
        "UNIT":unit, "INVOCATION_ID":iid, "MESSAGE_ID":SUCCESS,
        "__REALTIME_TIMESTAMP":time.to_string(),
    })
}

fn closed_joint(intermediate: &Value) -> (Value, Value) {
    let terminal = json!({
        "schema":"horizon-epoch168-joint-reduced-terminal-v1",
        "enrollment":intermediate["enrollment"],
        "producer_invocation_id":JOINT_IID,
        "producer_pid":JOINT_PID,
        "producer_start_ticks":JOINT_START,
        "disposition":"checkpoint-complete",
        "private_output_preserved":true,
        "independent_archive_scan_pending":true,
        "resource_credit_bytes":0,
        "archive_publication_authorized":false, "remote_mutations":false,
        "pid1_terminal_event":pid1(JOINT_UNIT, JOINT_IID, JOINT_READY_US),
    });
    let manifest = json!({
        "schema_version":1, "epoch":168, "output_slot_start":BOOTSTRAP+1,
        "output_slot_count":ROOT-BOOTSTRAP, "worker_executable_sha256":WORKER,
        "archive_sha256":ARCHIVE,
        "bootstrap":{
            "slot":BOOTSTRAP, "accounts_hash":"ByNZCiixM5iveRZh2urjzgFDEwCenqnpDL4okbBCf2WH",
            "last_blockhash":"AcNuUz2ZRmkco618BioYzFNGYuUYh78W6PqD6oHxRXwk",
            "slot_complete":true,"write_count":0,"next_write_version":JOINT_RAW_START,
        },
        "terminal":{
            "slot":ROOT, "accounts_hash":ORDINARY_ACCOUNTS, "last_blockhash":ORDINARY_BLOCK,
            "slot_complete":true, "next_write_version": JOINT_CURSOR+AFTER_COUNT,
        },
        "emitted_raw_write_versions":{"start":JOINT_RAW_START, "end":JOINT_CURSOR+AFTER_COUNT},
    });
    (terminal, manifest)
}

fn selected_prefix() -> Value {
    json!({
        "schema":"horizon-epoch168-private-selected-prefix-evidence-v1",
        "source_archive_sha256":RETRY4_SHA,
        "selected_archive_sha256":PRE_DIGEST,
        "selected_semantic_sha256":POST_DIGEST,
        "first_slot":FIRST, "last_slot":SEAM, "terminal_blockhash":SEAM_BLOCK,
        "independently_decoded":true,
        "raw_start":53_087_000_000u64, "raw_end_exclusive":RETRY4_END,
    })
}

fn prior_overlap() -> Value {
    json!({
        "schema":"horizon-epoch168-normalized-overlap-acceptance-v1",
        "compared_first_slot":SEAM+1, "compared_last_slot":72_998_911,
        "suffix_first_write_version":RETRY6_CURSOR, "write_version_delta":RETRY4_DELTA,
    })
}

fn stdout() -> String {
    format!(
        "predecessor_overlap first_slot={} last_slot={SEAM} normalized_sha256={PRE_DIGEST} terminal_blockhash={SEAM_BLOCK} source_raw_start={RETRY4_START} source_raw_end_exclusive={RETRY4_END} joint_raw_start={JOINT_RAW_START} joint_raw_end_exclusive={JOINT_CURSOR}\n\
         successor_overlap first_slot={} last_slot={ROOT} normalized_sha256={POST_DIGEST} terminal_blockhash={ORDINARY_BLOCK} source_raw_start={RETRY6_CURSOR} source_raw_end_exclusive={} joint_raw_start={JOINT_CURSOR} joint_raw_end_exclusive={}\n\
         comparison_complete epoch=168 seam={SEAM} ordinary_root={ROOT} joint_sha256={ARCHIVE}\n",
        BOOTSTRAP + 1,
        SEAM + 1,
        RETRY6_CURSOR + AFTER_COUNT,
        JOINT_CURSOR + AFTER_COUNT,
    )
}

fn native_records() -> (Value, Value, PathBuf, Value) {
    let directory = Path::new(JOINT_STATE).join("continuity-tools");
    let comparator = directory.join("horizon-168-joint-compare");
    let manifest_ref = fixed_ref(&joint_path().with_extension("jet.segment.json"), PRE_DIGEST);
    let rows: Vec<_> = stdout()
        .lines()
        .enumerate()
        .map(|(i, line)| {
            json!({
                "_PID":"50000", "_UID":"1001", "_BOOT_ID":JOINT_BOOT_ID,
                "_SYSTEMD_INVOCATION_ID":COMPARISON_IID, "_SYSTEMD_UNIT":COMPARISON_UNIT,
                "_EXE":comparator, "_TRANSPORT":"stdout", "MESSAGE":line,
                "__REALTIME_TIMESTAMP":(JOINT_READY_US+1+i as u64).to_string(),
            })
        })
        .collect();
    let native = json!({
        "schema":"horizon-epoch168-private-joint-comparison-native-v1",
        "invocation_id":COMPARISON_IID, "unit":COMPARISON_UNIT, "uid":"1001",
        "argv":[comparator, "--compare-joint", ARCHIVE], "executable_sha256":COMPARATOR_SHA,
        "sources":comparison_sources(ARCHIVE), "joint_manifest":manifest_ref,
        "stdout":rows,
        "pid1_event":pid1(COMPARISON_UNIT, COMPARISON_IID, JOINT_READY_US+10),
    });
    let seal = json!({
        "schema":"jetstreamer-sealed-deployment-receipt-v1", "destination":directory,
        "members":[{"name":"horizon-168-joint-compare","sha256":COMPARATOR_SHA,"mode":"0555"}],
    });
    (native, seal, comparator, manifest_ref)
}

#[test]
fn real_native_checkpoints_match_and_preserve_raw_coordinates() {
    let (intermediate, mut retry6) = observed_checkpoints();
    let checkpoint = validate_intermediate(&intermediate, &retry6).unwrap();
    assert_eq!(checkpoint["next_write_version"], JOINT_CURSOR);
    assert_eq!(checkpoint["write_count"], 44);
    assert_eq!(retry6["bootstrap"]["next_write_version"], RETRY6_CURSOR);
    assert_eq!(retry6["bootstrap"]["write_count"], 0);
    for key in CONSENSUS {
        assert_eq!(checkpoint[key], retry6["bootstrap"][key]);
        let original = retry6["bootstrap"][key].take();
        assert!(
            validate_intermediate(&intermediate, &retry6).is_err(),
            "missing consensus field {key} passed"
        );
        retry6["bootstrap"][key] = original;
    }
}

#[test]
fn native_stdout_requires_the_exact_comparator_invocation_and_sources() {
    let (native, seal, comparator, manifest_ref) = native_records();
    let validate = |record: &Value| {
        comparison_report(
            record,
            &seal,
            &comparator,
            &manifest_ref,
            ARCHIVE,
            JOINT_READY_US,
        )
    };
    assert_eq!(validate(&native).unwrap(), stdout());

    for (path, value) in [
        ("/executable_sha256", json!(PRE_DIGEST)),
        ("/invocation_id", json!(JOINT_IID)),
        ("/argv/2", json!(PRE_DIGEST)),
        ("/sources/retry4/sha256", json!(PRE_DIGEST)),
        ("/sources/retry6/path", json!(RETRY4_PATH)),
        ("/sources/joint/sha256", json!(PRE_DIGEST)),
        ("/joint_manifest/sha256", json!(POST_DIGEST)),
        ("/pid1_event/MESSAGE_ID", json!("foreign")),
        (
            "/pid1_event/__REALTIME_TIMESTAMP",
            json!(JOINT_READY_US.to_string()),
        ),
        ("/stdout/0/_SYSTEMD_INVOCATION_ID", json!(JOINT_IID)),
        ("/stdout/1/_EXE", json!("/foreign")),
        ("/stdout/1/_PID", json!("50001")),
        ("/stdout/1/_UID", json!("0")),
        ("/stdout/2/_BOOT_ID", json!(COMPARISON_IID)),
        (
            "/stdout/2/__REALTIME_TIMESTAMP",
            json!((JOINT_READY_US + 11).to_string()),
        ),
        ("/stdout/2/_TRANSPORT", json!("journal")),
        ("/stdout/2/MESSAGE", json!("fake\nrow")),
    ] {
        let mut mutated = native.clone();
        *mutated.pointer_mut(path).unwrap() = value;
        assert!(validate(&mutated).is_err(), "{path} unexpectedly passed");
    }

    let mut mutated = native.clone();
    mutated["stdout"].as_array_mut().unwrap().pop();
    assert!(validate(&mutated).is_err());
    let mut mutated = native.clone();
    mutated["stdout"][0]["_CMDLINE"] = json!("/foreign --wrong");
    assert!(validate(&mutated).is_err());
}

#[test]
fn closed_joint_requires_the_clean_producer_and_exact_manifest_scope() {
    let (intermediate, _) = observed_checkpoints();
    let (terminal, manifest) = closed_joint(&intermediate);
    validate_closed_joint(&terminal, &manifest, &intermediate).unwrap();
    for (path, value) in [
        ("/disposition", json!("failed")),
        ("/producer_start_ticks", json!(JOINT_START + 1)),
        ("/enrollment/sha256", json!(POST_DIGEST)),
        ("/pid1_terminal_event/_PID", json!("2")),
        ("/pid1_terminal_event/INVOCATION_ID", json!(COMPARISON_IID)),
        (
            "/pid1_terminal_event/__REALTIME_TIMESTAMP",
            json!((JOINT_READY_US - 1).to_string()),
        ),
    ] {
        let mut mutated = terminal.clone();
        *mutated.pointer_mut(path).unwrap() = value;
        assert!(
            validate_closed_joint(&mutated, &manifest, &intermediate).is_err(),
            "{path}"
        );
    }
    let mut manifest = manifest;
    manifest["output_slot_count"] = json!(ROOT - BOOTSTRAP - 1);
    assert!(validate_closed_joint(&terminal, &manifest, &intermediate).is_err());
}

#[test]
fn translates_only_against_the_retry4_selection_and_both_closed_comparisons() {
    let (intermediate, retry6) = observed_checkpoints();
    let checkpoint = validate_intermediate(&intermediate, &retry6).unwrap();
    let (_, manifest) = closed_joint(&intermediate);
    let selected = selected_prefix();
    let overlap = prior_overlap();
    let report = stdout();
    let validate = |stdout: &str, joint: &Value, prefix: &Value, prior: &Value| {
        bind_selected(stdout, joint, prefix, &retry6, prior, &checkpoint)
    };
    let binding = validate(&report, &manifest, &selected, &overlap).unwrap();
    assert_eq!(binding["joint_native_seam_checkpoint"], checkpoint);
    assert_eq!(binding["retry6_native_bootstrap"], retry6["bootstrap"]);
    let translated = &binding["translated_v4_predecessor"];
    assert_eq!(translated["next_write_version"], RETRY4_END);
    assert_eq!(translated["accounts_hash_kind"], "legacy_accounts_hash");
    for key in CONSENSUS {
        assert_eq!(translated[key], checkpoint[key]);
    }
    assert_eq!(binding["joint_to_retry4_cursor_offset"], 105_050_392);
    assert_eq!(binding["joint_to_retry6_cursor_offset"], 13_018_151);
    assert_eq!(binding["assembly_authorized"], false);
    assert_eq!(binding["publication_authorized"], false);

    for (source, replacement) in [
        (
            format!("last_slot={SEAM}"),
            format!("last_slot={}", SEAM - 1),
        ),
        (
            format!("source_raw_end_exclusive={RETRY4_END}"),
            format!("source_raw_end_exclusive={}", RETRY4_END - 1),
        ),
        (
            format!("source_raw_start={RETRY6_CURSOR}"),
            format!("source_raw_start={}", RETRY6_CURSOR + 1),
        ),
        (
            format!("ordinary_root={ROOT}"),
            format!("ordinary_root={}", ROOT - 1),
        ),
        (
            format!("joint_sha256={ARCHIVE}"),
            format!("joint_sha256={PRE_DIGEST}"),
        ),
    ] {
        let mutated = report.replace(&source, &replacement);
        assert!(
            bind_selected(
                &mutated,
                &manifest,
                &selected,
                &retry6,
                &overlap,
                &checkpoint
            )
            .is_err(),
            "{source}"
        );
    }
    assert!(
        bind_selected(
            report.split("comparison_complete").next().unwrap(),
            &manifest,
            &selected,
            &retry6,
            &overlap,
            &checkpoint
        )
        .is_err()
    );

    let mut foreign_root = manifest.clone();
    foreign_root["terminal"]["accounts_hash"] = json!("foreign");
    assert!(validate(&report, &foreign_root, &selected, &overlap).is_err());
    let mut wrong_overlap = overlap.clone();
    wrong_overlap["write_version_delta"] = json!(RETRY4_DELTA + 1);
    assert!(validate(&report, &manifest, &selected, &wrong_overlap).is_err());

    for (field, value) in [
        ("source_archive_sha256", json!(PRE_DIGEST)),
        ("raw_end_exclusive", json!(RETRY4_END + 1)),
        ("independently_decoded", json!(false)),
    ] {
        let mut mutated = selected.clone();
        mutated[field] = value;
        assert!(
            validate(&report, &manifest, &mutated, &overlap).is_err(),
            "{field}"
        );
    }
}
