//! Synthetic predicates do not fabricate production proof objects or receipts.
use super::*;

fn fixture(epoch: u64) -> (Profile, Sources) {
    let p = profile(epoch).unwrap();
    let command = format!(
        "{{ path=/synthetic/runner-{epoch} ; argv[]=/synthetic/runner-{epoch} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
    );
    let launch = json!({"schema":format!("jetstreamer-private-epoch{epoch}-capped-root-prefix-launch-v1"),"epoch":epoch,"launched":true,"private_run_root":p.root,"node_sha256":NODE,"worker_sha256":WORKER,"runner_sha256":p.runner,"plan_sha256":p.resource,"snapshot_sha256":p.snapshot,"bootstrap_slot":p.bootstrap,"output_slot_start":p.start,"output_slot_count":p.restart-p.start+1,"terminal_root_slot":p.restart,"natural_parent_completion_required":true,"expected_exec_start":command});
    let manifest = json!({"epoch":epoch,"bootstrap":{"slot":p.bootstrap},"output_slot_start":p.start,"output_slot_count":p.restart-p.start+1,"terminal":{"slot":p.restart,"slot_complete":true},"archive_sha256":p.archive,"worker_executable_sha256":WORKER,"runtime":{"runtime_profile":"solana-v1.6.16","runtime_revision":"86c26f843276581509c3434acc2efbf4202c44e0"}});
    let result = json!({"schema":format!("jetstreamer-private-epoch{epoch}-shrink-root-prefix-resource-v1"),"epoch":epoch,"unit":p.unit,"invocation_id":p.iid,"success":true,"error":null,"child_return_code":0,"external_signal":0,"natural_parent_completion_required":true,"node_sha256":NODE,"worker_sha256":WORKER,"runner_sha256":p.runner,"plan":{"sha256":p.resource},"snapshot_sha256":p.snapshot,"archive_length":p.bytes,"producer_segment_manifest_sha256":p.hashes[4],"producer_segment_manifest":manifest,"target_slot":p.restart,"terminal_root_slot":p.restart,"producer_canonical_root_prefix_present":true,"authority":(["canonical_prefix_independently_qualified","full_cold_epoch_peak_qualified","ordinary_replay_authorized","runtime_promotion_authorized","canonical_sidecar_authorized","publication_authorized","remote_mutations","r2_mutations"].into_iter().map(|k|(k,false)).collect::<BTreeMap<_,_>>())});
    let terminal = json!({"Id":p.unit,"Type":"exec","LoadState":"loaded","MainPID":"0","NRestarts":"0","ActiveState":"inactive","SubState":"dead","ControlGroup":"","Result":"success","ExecMainStatus":"0","InvocationID":"","ExecMainPID":"0","ExecMainCode":"0","Restart":"no","Triggers":"","TriggeredBy":"","ExecStart":command});
    let archive = format!("{}/output/epoch-{epoch}-prefix.jet", p.root);
    let reader = json!({"schema":"jetstreamer-focused-qualification-artifact-validation-v1","validation":"pass","epoch":epoch,"archive":archive,"manifest":format!("{archive}.segment.json"),"archive_sha256":p.archive,"archive_bytes":p.bytes,"output_slot_start":p.start,"output_slot_count":p.restart-p.start+1,"bootstrap_slot":p.bootstrap,"terminal_slot":p.restart,"worker_executable_sha256":WORKER,"runtime_profile":"solana-v1.6.16","runtime_revision":manifest["runtime"]["runtime_revision"],"runtime_admission":"candidate","canonical_checksum_sidecar_absent":true});
    let rows = [
        json!({"_PID":"1","_UID":"0","UNIT":p.unit,"INVOCATION_ID":p.iid,"_BOOT_ID":"a".repeat(32),"__CURSOR":"first","__REALTIME_TIMESTAMP":"1000000","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":format!("Started {} - Synthetic predicate fixture.",p.unit)}),
        json!({"_PID":"1","_UID":"0","UNIT":p.unit,"INVOCATION_ID":p.iid,"_BOOT_ID":"a".repeat(32),"__CURSOR":"last","__REALTIME_TIMESTAMP":"2000000","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{}: Deactivated successfully.",p.unit)}),
    ];
    let journal = rows
        .iter()
        .map(|r| serde_json::to_string(r).unwrap() + "\n")
        .collect::<String>()
        .into_bytes();
    (
        p,
        Sources {
            launch,
            result,
            terminal,
            manifest,
            reader,
            journal,
        },
    )
}
#[test]
fn exact_profiles_accept_honest_collected_display_without_relaxing_generic_idle() {
    for epoch in [204, 205] {
        let (p, s) = fixture(epoch);
        let current = s.terminal.clone();
        let proof = verify(p, s).unwrap();
        assert_eq!((proof.started_ms, proof.ended_seconds), (1000, 2));
        terminal_shape(p, &proof.launch, &current, false).unwrap();
        assert!(capped204205_admission::original_idle(&current, epoch).is_err());
        assert!(idle_for_plan(&current, &json!({"epoch":epoch})).is_err());
        let mut collected = current.clone();
        collected["LoadState"] = json!("not-found");
        collected["ExecStart"] = json!("");
        terminal_shape(p, &proof.launch, &collected, false).unwrap();
        let mut retained = current;
        retained["InvocationID"] = json!(p.iid);
        retained["ExecMainPID"] = json!(p.pid.to_string());
        retained["ExecMainCode"] = json!("1");
        terminal_shape(p, &proof.launch, &retained, true).unwrap();
    }
}
#[test]
fn cleared_display_never_accepts_live_foreign_failed_or_forged_terminal_fields() {
    let (p, s) = fixture(204);
    terminal_shape(p, &s.launch, &s.terminal, true).unwrap();
    for (field, value) in [
        ("Id", json!("foreign.service")),
        ("MainPID", json!("44")),
        ("InvocationID", json!("e".repeat(32))),
        ("NRestarts", json!("1")),
        ("ActiveState", json!("active")),
        ("Result", json!("exit-code")),
        ("ExecMainStatus", json!("1")),
        ("ExecMainPID", json!("1")),
        ("ExecMainCode", json!("1")),
        ("ControlGroup", json!("/live")),
        ("Triggers", json!("new.service")),
        ("TriggeredBy", json!("new.timer")),
        ("ExecStart", json!("different")),
    ] {
        let mut bad = s.terminal.clone();
        bad[field] = value;
        assert!(terminal_shape(p, &s.launch, &bad, true).is_err(), "{field}");
    }
}
#[test]
fn every_exact_primary_digest_is_mandatory_and_mirrors_keep_original_digest() {
    for epoch in [204, 205] {
        let p = profile(epoch).unwrap();
        let keys = [
            "original_launch",
            "producer_result",
            "terminal_properties",
            "manager_journal",
            "prefix_manifest",
            "prefix_validation",
        ];
        let v = json!(
            keys.into_iter()
                .zip(p.hashes)
                .map(|(k, s)| (k, json!({"path":format!("/synthetic/{k}"),"sha256":s})))
                .collect::<BTreeMap<_, _>>()
        );
        let m: Metadata = serde_json::from_value(v.clone()).unwrap();
        m.check(p).unwrap();
        let mut mirror = v.clone();
        mirror["original_launch"]["path"] = json!("/different/readable/mirror.json");
        serde_json::from_value::<Metadata>(mirror)
            .unwrap()
            .check(p)
            .unwrap();
        for key in keys {
            let mut bad = v.clone();
            bad[key]["sha256"] = json!("f".repeat(64));
            assert!(
                serde_json::from_value::<Metadata>(bad)
                    .unwrap()
                    .check(p)
                    .is_err(),
                "{key}"
            );
        }
        let mut extra = v;
        extra["asserted_success"] = json!(true);
        assert!(serde_json::from_value::<Metadata>(extra).is_err());
    }
}
#[test]
fn primary_result_reader_manifest_and_source_profiles_cannot_be_substituted() {
    for case in 0..8 {
        let (p, mut s) = fixture(205);
        match case {
            0 => s.launch["worker_sha256"] = json!("f".repeat(64)),
            1 => s.result["external_signal"] = json!(15),
            2 => s.result["invocation_id"] = json!("f".repeat(32)),
            3 => s.reader["archive_sha256"] = json!("f".repeat(64)),
            4 => s.reader["archive_bytes"] = json!(1),
            5 => s.reader["canonical_checksum_sidecar_absent"] = json!(false),
            6 => s.manifest["terminal"]["slot"] = json!(p.restart + 1),
            _ => s.result["authority"]["publication_authorized"] = json!(true),
        }
        assert!(verify(p, s).is_err(), "case {case}");
    }
}
#[test]
fn manager_proof_rejects_forged_identity_boot_cursor_clock_stop_and_new_invocation() {
    for case in 0..9 {
        let (p, s) = fixture(204);
        let mut rows = s
            .journal
            .split(|b| *b == b'\n')
            .filter(|r| !r.is_empty())
            .map(|r| serde_json::from_slice::<Value>(r).unwrap())
            .collect::<Vec<_>>();
        match case {
            0 => rows[1]["_PID"] = json!("7"),
            1 => rows[1]["_UID"] = json!("1000"),
            2 => rows[1]["_BOOT_ID"] = json!("b".repeat(32)),
            3 => rows[1]["__CURSOR"] = json!("first"),
            4 => rows[1]["__REALTIME_TIMESTAMP"] = json!("500000"),
            5 => rows[1]["INVOCATION_ID"] = json!("f".repeat(32)),
            6 => rows[1]["MESSAGE"] = json!("Stopped original"),
            7 => rows[1]["EXIT_STATUS"] = json!("1"),
            _ => {
                let mut r = rows[0].clone();
                r["__CURSOR"] = json!("new");
                r["__REALTIME_TIMESTAMP"] = json!("3000000");
                r["INVOCATION_ID"] = json!("f".repeat(32));
                rows.push(r);
            }
        }
        let bytes = rows
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect::<String>();
        assert!(journal(p, bytes.as_bytes()).is_err(), "case {case}");
    }
}
#[test]
fn live_or_ambiguous_same_epoch_repair_probe_guard_and_continuation_block_cleanup() {
    let names = [
        "horizon-capped204205-resource-probe-204-e506-rss-v1.service",
        "horizon-capped204205-resource-probe-204-e506-rss-v1-producer.service",
        "horizon-capped204-e506-rss-probe-retention-pin-v1.service",
        "horizon-qualify-204-capped-continuation-new.service",
        "horizon-guard-204-capped-continuation-new.service",
        "horizon-repair-204-new.service",
        "horizon-import-204-new.service",
    ];
    for name in names {
        let current = BTreeMap::from([(
            name.into(),
            json!({"MainPID":"42","ActiveState":"active","SubState":"running"}),
        )]);
        assert!(no_replacement(204, &current).is_err(), "{name}");
    }
    let other = BTreeMap::from([(
        "horizon-qualify-205-capped-continuation-actual.service".into(),
        json!({"MainPID":"42","ActiveState":"active","SubState":"running"}),
    )]);
    no_replacement(204, &other).unwrap();
    assert!(repair_unit(names[0], 201, 300));
    assert!(!repair_unit(names[0], 101, 200));
    assert!(!repair_unit(
        "horizon-capped204205-resource-probe-2040-foreign.service",
        201,
        300
    ));
}
#[test]
fn foreign_and_assertion_only_terminal_wrapper_never_authorize_cleanup() {
    assert!(
        terminal_time(204, &json!({"schema":"different"}))
            .unwrap()
            .is_none()
    );
    let e = json!({"schema":SCHEMA,"epoch":204,"metadata":{},"archive_completion_claimed":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    assert!(terminal_time(204, &e).is_err());
    let mut wrong = e;
    wrong["publication_authorized"] = json!(true);
    assert!(terminal_evidence(204, &wrong).is_err());
}

#[test]
#[ignore = "exact sealed small original 204/205 primary metadata only; no service, resource, status, archive/snapshot body or remote reads"]
fn actual_preserved_metadata_validates_both_loaded_collected_profiles_without_runtime_queries() {
    let metadata = |epoch: u64| {
        let p = profile(epoch).unwrap();
        let paths = if epoch == 204 {
            [
                "/var/lib/jetstreamer/horizon-capped204-runtime-launch-mirror-e506-v1/original-launch.json",
                "/var/lib/jetstreamer/horizon-capped204-original-terminal-and-reader-launch-v1/producer-result.json",
                "/var/lib/jetstreamer/horizon-capped204-original-terminal-and-reader-launch-v1/terminal-manager-explicit.json",
                "/var/lib/jetstreamer/horizon-capped204-original-terminal-and-reader-launch-v1/terminal-complete-pid1-journal.jsonl",
                "/var/lib/jetstreamer/horizon-capped204-original-terminal-and-reader-launch-v1/prefix.segment.json",
                "/var/lib/jetstreamer/horizon-capped204-independent-reader-terminal-v1/epoch-204.validation.json",
            ]
        } else {
            [
                "/var/lib/jetstreamer/horizon-capped205-runtime-launch-mirror-e506-v1/original-launch.json",
                "/var/lib/jetstreamer/horizon-capped205-original-terminal-and-reader-launch-v1/producer-result.json",
                "/var/lib/jetstreamer/horizon-epoch205-explicit-terminal-native-properties-v1/manager-explicit.json",
                "/var/lib/jetstreamer/horizon-capped205-original-terminal-and-reader-launch-v1/complete-pid1-journal.jsonl",
                "/var/lib/jetstreamer/horizon-capped205-evidence-cf7d-v1/prefix.segment.json",
                "/var/lib/jetstreamer/horizon-capped205-independent-reader-terminal-v1/epoch-205.validation.json",
            ]
        };
        json!(
            [
                "original_launch",
                "producer_result",
                "terminal_properties",
                "manager_journal",
                "prefix_manifest",
                "prefix_validation"
            ]
            .into_iter()
            .zip(paths)
            .zip(p.hashes)
            .map(|((k, path), sha)| (k, json!({"path":path,"sha256":sha})))
            .collect::<BTreeMap<_, _>>()
        )
    };
    for epoch in [204, 205] {
        let m = metadata(epoch);
        let proof = authenticate(epoch, &m).unwrap();
        let t: BoundFile = serde_json::from_value(m["terminal_properties"].clone()).unwrap();
        let current: Value = serde_json::from_slice(&bytes(&t).unwrap()).unwrap();
        idle_for_plan(&current, &json!({"epoch":epoch,"metadata":m})).unwrap();
        assert!(proof.started_ms > 0 && proof.ended_seconds > proof.started_ms / 1000);
    }
}
