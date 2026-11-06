//! Authored source only until Root separately admits compilation/native QA.
use super::*;

// A fixture hash, never qualification of the old compiler-only guard profile.
const GUARD_SHA: &str = "85bceee62984c7cecd032c9ce4553df707c43c3f2d3cd7c8d2965c52d09c734e";

fn bound(path: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: "0".repeat(64),
    }
}
fn plans() -> (RetirePlan, Plan, Plan, Value) {
    let old = crate::scan203_retention::tests::plan();
    let mut c = old.clone();
    let p = RetirePlan {
        schema: "jetstreamer-scan203-retirement-plan-v1".into(),
        inspection_plan: bound("/inspection-plan.json"),
        inspection: bound("/inspection.json"),
        closure_plan: bound("/closure.json"),
        state_identity: Parent {
            device: 66305,
            inode: 2,
            uid: 0,
            gid: 0,
            mode: 0o700,
        },
        guard_directory_identity: Parent {
            device: 66305,
            inode: 3,
            uid: 0,
            gid: 0,
            mode: 0o700,
        },
        lock_identity: Stamp {
            device: 66305,
            inode: 4,
            length: 0,
            uid: 1000,
            gid: 1000,
            mode: 0o600,
            links: 1,
            mtime_ns: 0,
            ctime_ns: 0,
        },
        guard_binary: Bound {
            path: "/sealed/guard".into(),
            sha256: GUARD_SHA.into(),
        },
        guard_recipe: bound(&format!("/etc/systemd/system/{GUARD_UNIT}")),
        guard_timer_recipe: bound(&format!("/etc/systemd/system/{GUARD_TIMER}")),
        minimum_free_bytes: 1_000_000,
    };
    c.executor_recipe = bound(&format!("/etc/systemd/system/{RETIRE_UNIT}"));
    c.historical_recipes.push(old.executor_recipe.clone());
    c.actors.insert(
        UNIT.into(),
        Actor {
            invocation_id: "b".repeat(32),
            original_terminal: p.inspection.clone(),
        },
    );
    let prior = json!({"schema":"jetstreamer-scan203-retention-inspection-v1","plan":p.inspection_plan,
        "source_identity":old.source_identity,"retained204_identity":old.retained204_identity,
        "retirement_authorized":false,"archive_body_opened":false,"recorded_unix_seconds":1000,
        "executor":{"unit":UNIT,"invocation_id":"b".repeat(32)}});
    (p, old, c, prior)
}
fn sample(p: &RetirePlan) -> Value {
    json!({"schema":"jetstreamer-horizon-build-guard-sample-v1","unit":RETIRE_UNIT,
    "actor_invocation_id":"a".repeat(32),"self_sha256":GUARD_SHA,"guard_invocation_id":"c".repeat(32),
    "native_MainPID":1234,"native_ControlPID":0,"native_NRestarts":0,"native_Type":"exec",
    "native_ActiveState":"active","native_SubState":"running","native_owner_stable":true,"trip":false,
    "root":STATE,"root_uid":0,"root_device":p.state_identity.device,"root_inode":p.state_identity.inode,
    "minimum_free_bytes":p.minimum_free_bytes,"maximum_root_bytes":METADATA_CAP,"memory_max_bytes":MEMORY,
    "memory_swap_max_bytes":0,"tasks_max":512,"cpu_quota_usec":2_000_000,"maximum_run_usec":7_200_000_000u64,
    "available_bytes":p.minimum_free_bytes,"conservative_physical_bytes":64,"recorded_unix_millis":1_000_000})
}
fn receipt(length: u64, sha: &str, etag: &str) -> Receipt {
    Receipt {
        schema: RECEIPT_SCHEMA.into(),
        bucket: "fixture".into(),
        epoch: 203,
        archive_key: "epoch-203.jet".into(),
        checksum_key: "epoch-203.jet.sha256".into(),
        archive_length: length,
        archive_sha256: sha.into(),
        archive_etag: etag.into(),
        r2_composite_sha256: None,
        remote_sha256_readback: true,
        multipart_part_size: DEFAULT_PART_SIZE,
        verified_unix_seconds: 1000,
    }
}

#[test]
fn scan203_retirement_every_crash_window_has_an_exact_lifecycle() {
    let valid = [
        (1, 0, 0, 0, 0, 0, 0),
        (1, 0, 1, 0, 0, 0, 0),
        (0, 1, 1, 0, 0, 0, 0),
        (0, 1, 1, 1, 0, 0, 0),
        (0, 1, 1, 1, 1, 0, 0),
        (0, 1, 1, 1, 1, 1, 0),
        (0, 0, 1, 1, 1, 1, 0),
        (0, 0, 1, 1, 1, 1, 1),
    ];
    for bits in 0u8..128 {
        let v = (0..7)
            .map(|n| u8::from(bits & (1 << n) != 0))
            .collect::<Vec<_>>();
        let result = lifecycle(
            v[0] != 0,
            v[1] != 0,
            v[2] != 0,
            v[3] != 0,
            v[4] != 0,
            v[5] != 0,
            v[6] != 0,
        );
        assert_eq!(
            result.is_ok(),
            valid.contains(&(v[0], v[1], v[2], v[3], v[4], v[5], v[6])),
            "bits={bits}"
        );
    }
}
#[test]
fn scan203_retirement_intent_alone_never_proves_disappearance() {
    assert!(lifecycle(false, false, true, false, false, false, false).is_err());
    assert_eq!(
        lifecycle(false, false, true, true, true, true, false).unwrap(),
        Phase::Unlinked
    );
    assert!(lifecycle(true, false, true, true, true, true, true).is_err());
}
#[test]
fn scan203_retirement_has_only_two_fixed_child_names_and_five_record_names() {
    assert!(child(SOURCE_NAME).is_ok());
    assert!(child(QUARANTINE_NAME).is_ok());
    for s in [
        "epoch-204.jet",
        "../epoch-203.jet",
        "/home/ubuntu/horizon/epoch-203.jet",
        ".",
        "",
    ] {
        assert!(child(s).is_err());
    }
    assert!(record_path("completion").is_ok());
    assert!(record_path("../source").is_err());
}
#[test]
fn scan203_retirement_continuation_preserves_prior_source_reader_and_recipe() {
    let (p, old, mut c, prior) = plans();
    assert!(plan_scope(&p, &c).is_ok());
    assert!(continuation(&old, &c, &p.inspection, &prior).is_ok());
    c.historical_recipes.clear();
    assert!(continuation(&old, &c, &p.inspection, &prior).is_err());
}
#[test]
fn scan203_retirement_cannot_drop_a_stage_spec_or_borrow_another_inspection() {
    let (p, old, mut c, mut prior) = plans();
    c.dependency_metadata.remove(0);
    assert!(continuation(&old, &c, &p.inspection, &prior).is_err());
    let (_, _, c, _) = plans();
    prior["executor"]["invocation_id"] = json!("d".repeat(32));
    assert!(continuation(&old, &c, &p.inspection, &prior).is_err());
}
#[test]
fn scan203_retirement_cannot_replace_retained204_or_ignore_parent_custody() {
    let (mut p, _, mut c, _) = plans();
    c.retained204_identity.inode = 510665;
    assert!(plan_scope(&p, &c).is_err());
    let (_, _, c, _) = plans();
    p.state_identity.mode = 0o755;
    assert!(plan_scope(&p, &c).is_err());
}
#[test]
fn scan203_retirement_initial_inspection_has_an_unreset_clock() {
    let (_, _, _, v) = plans();
    assert!(fresh_inspection(&v, 1900).is_ok());
    assert!(fresh_inspection(&v, 1901).is_err());
    assert!(fresh_inspection(&v, 999).is_err());
}
#[test]
fn scan203_retirement_guard_nonce_pid_clock_caps_and_trip_are_mandatory() {
    let (p, _, _, _) = plans();
    let v = sample(&p);
    assert!(guard_sample(&v, &p, &"a".repeat(32), 1234, 1180).is_ok());
    assert!(guard_sample(&v, &p, &"a".repeat(32), 1234, 1181).is_err());
    assert!(guard_sample(&v, &p, &"a".repeat(32), 1235, 1000).is_err());
    assert!(guard_sample(&v, &p, &"b".repeat(32), 1234, 1000).is_err());
    for (field, value) in [
        ("trip", json!(true)),
        ("native_owner_stable", json!(false)),
        ("root_inode", json!(99)),
        ("memory_max_bytes", json!(MEMORY + 1)),
        ("available_bytes", json!(p.minimum_free_bytes - 1)),
        ("maximum_root_bytes", json!(METADATA_CAP + 1)),
        ("native_ControlPID", json!(9)),
        ("native_Type", json!("oneshot")),
    ] {
        let mut bad = v.clone();
        bad[field] = value;
        assert!(
            guard_sample(&bad, &p, &"a".repeat(32), 1234, 1000).is_err(),
            "accepted {field}"
        );
    }
}
#[test]
fn scan203_retirement_same_body_ignores_only_rename_ctime() {
    let (_, _, c, _) = plans();
    let a = c.source_identity;
    let mut b = a.clone();
    b.ctime_ns += 1;
    assert!(same_body(&a, &b));
    b.mtime_ns += 1;
    assert!(!same_body(&a, &b));
    b = a.clone();
    b.uid = 1000;
    assert!(!same_body(&a, &b));
}
#[test]
fn scan203_retirement_shared_body_predicate_preserves_sha_etag_and_whole_object_gates() {
    let proof = LocalProof {
        sha256_hex: SHA203.into(),
        multipart_etag: "etag-1".into(),
        composite_sha256: "composite".into(),
    };
    let mut r = receipt(LENGTH203, SHA203, "etag-1");
    assert!(validate_retirement_body_proof(203, LENGTH203, SHA203, &proof, &r).is_ok());
    r.remote_sha256_readback = false;
    assert!(validate_retirement_body_proof(203, LENGTH203, SHA203, &proof, &r).is_err());
    r.remote_sha256_readback = true;
    r.archive_etag = "other".into();
    assert!(validate_retirement_body_proof(203, LENGTH203, SHA203, &proof, &r).is_err());
    r.archive_etag = "etag-1".into();
    assert!(validate_retirement_body_proof(204, LENGTH203, SHA203, &proof, &r).is_err());
    assert!(validate_retirement_body_proof(203, LENGTH203, SHA204, &proof, &r).is_err());
}
#[test]
fn scan203_retirement_exact_writer_scope_cannot_broaden_to_a_parent() {
    let iid = "a".repeat(32);
    let args = vec!["/sealed/tool".into(), "retire-scan203".into()];
    let mut m = BTreeMap::new();
    for (k, v) in [
        ("Id", RETIRE_UNIT),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", iid.as_str()),
        ("MainPID", "1234"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "no"),
        ("NoNewPrivileges", "yes"),
        ("MemoryMax", "4294967296"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "2s"),
        ("RuntimeMaxUSec", "2h"),
    ] {
        m.insert(k.into(), v.into());
    }
    for k in [
        "Job",
        "Triggers",
        "TriggeredBy",
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecStop",
        "ExecStopPost",
        "ExecReload",
        "OnSuccess",
        "OnFailure",
    ] {
        m.insert(k.into(), String::new());
    }
    m.insert("ReadWritePaths".into(), format!("{ROOT} {STATE} {LOCK}"));
    m.insert(
        "ExecStart".into(),
        format!("{{ path=/sealed/tool ; argv[]={} ; }}", args.join(" ")),
    );
    assert!(executor_properties(&m, &args, &iid, 1234, false).is_ok());
    m.insert("ReadWritePaths".into(), format!("/var/lib {STATE} {LOCK}"));
    assert!(executor_properties(&m, &args, &iid, 1234, false).is_err());
}
#[test]
fn scan203_retirement_predecessor_hash_cannot_borrow_a_neighboring_operation() {
    let b = bound("/verified.json");
    let v = json!({"data":{"verified":b}});
    assert!(predecessor(&v, "verified", &b).is_ok());
    let mut changed = b.clone();
    changed.sha256 = "1".repeat(64);
    assert!(predecessor(&v, "verified", &changed).is_err());
}

#[test]
fn scan203_retirement_guard_recipe_can_freeze_before_actual_actor_iid() {
    let (p, _, _, _) = plans();
    let template = guard_command(&p, "${HORIZON_SCAN203_ACTOR_IID}");
    let iid = "a".repeat(32);
    assert_eq!(
        template.replace("${HORIZON_SCAN203_ACTOR_IID}", &iid),
        guard_command(&p, &iid)
    );
    assert!(!template.contains(&iid));
}

#[test]
fn scan203_retirement_unlinked_recovery_requires_real_recorded_body_proof() {
    let (_, _, c, _) = plans();
    let v = json!({"data":{"quarantine_identity":c.source_identity,"body_sha256":SHA203,"multipart_etag":ETAG203}});
    assert!(recorded_body(&v, &c.source_identity).is_ok());
    let mut bad = v.clone();
    bad["data"]["body_sha256"] = json!(SHA204);
    assert!(recorded_body(&bad, &c.source_identity).is_err());
    let mut bad = v;
    bad["data"]["quarantine_identity"]["inode"] = json!(510665);
    assert!(recorded_body(&bad, &c.source_identity).is_err());
}

fn root_fixture() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "separately admitted Root native fixture required"
    );
}
fn tiny(dir: &Path) -> (PathBuf, Stamp, Receipt) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(SOURCE_NAME);
    fs::write(&path, b"tiny public fixture\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let stamp = Stamp::of(&fs::metadata(&path).unwrap());
    let proof = hash_and_etag(&path, regular_identity(&path).unwrap(), DEFAULT_PART_SIZE).unwrap();
    let r = receipt(stamp.length, &proof.sha256_hex, &proof.multipart_etag);
    (path, stamp, r)
}
fn dir_file(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .unwrap()
}

#[test]
#[ignore = "tiny native rename/hash/unlink fixture requires Root admission"]
fn scan203_retirement_native_one_parent_descriptor_survives_rename_and_preserves204() {
    root_fixture();
    let d = tempfile::tempdir().unwrap();
    let (_p, stamp, r) = tiny(d.path());
    let retained = d.path().join("epoch-204.jet");
    fs::write(&retained, b"retained").unwrap();
    let before = Stamp::of(&fs::metadata(&retained).unwrap());
    let dir = dir_file(d.path());
    body_at(&dir, SOURCE_NAME, &stamp, true, &r).unwrap();
    move_child(&dir).unwrap();
    body_at(&dir, QUARANTINE_NAME, &stamp, false, &r).unwrap();
    unlink_child(&dir).unwrap();
    assert!(!d.path().join(SOURCE_NAME).exists());
    assert!(!d.path().join(QUARANTINE_NAME).exists());
    assert_eq!(before, Stamp::of(&fs::metadata(&retained).unwrap()));
    assert_eq!(fs::read(retained).unwrap(), b"retained");
}
#[test]
#[ignore = "tiny native no-clobber fixture requires Root admission"]
fn scan203_retirement_native_quarantine_collision_preserves_both_files() {
    root_fixture();
    let d = tempfile::tempdir().unwrap();
    tiny(d.path());
    fs::write(d.path().join(QUARANTINE_NAME), b"existing").unwrap();
    assert!(move_child(&dir_file(d.path())).is_err());
    assert_eq!(
        fs::read(d.path().join(QUARANTINE_NAME)).unwrap(),
        b"existing"
    );
    assert!(d.path().join(SOURCE_NAME).exists());
}
#[test]
#[ignore = "tiny native symlink/replacement fixture requires Root admission"]
fn scan203_retirement_native_replacement_or_symlink_cannot_borrow_original_proof() {
    use std::os::unix::fs::symlink;
    root_fixture();
    let d = tempfile::tempdir().unwrap();
    let (source, stamp, r) = tiny(d.path());
    let dir = dir_file(d.path());
    fs::rename(&source, d.path().join("kept")).unwrap();
    fs::write(&source, b"replacement").unwrap();
    assert!(body_at(&dir, SOURCE_NAME, &stamp, true, &r).is_err());
    fs::remove_file(&source).unwrap();
    symlink(d.path().join("kept"), &source).unwrap();
    assert!(body_at(&dir, SOURCE_NAME, &stamp, true, &r).is_err());
}
#[test]
#[ignore = "tiny native durable-record fixture requires Root admission"]
fn scan203_retirement_native_record_publication_is_durable_and_no_clobber() {
    root_fixture();
    let d = tempfile::tempdir().unwrap();
    let dir = dir_file(d.path());
    let path = d.path().join("intent.json");
    let first = json!({"intent":"original"});
    let b = publish_at(&path, &first, &dir).unwrap();
    assert_eq!(saved(&b).unwrap(), first);
    assert!(publish_at(&path, &json!({"intent":"replacement"}), &dir).is_err());
    assert_eq!(saved(&b).unwrap(), first);
}
#[test]
#[ignore = "tiny native interrupted-lifecycle fixture requires Root admission"]
fn scan203_retirement_native_crash_after_move_requires_original_quarantine_identity() {
    root_fixture();
    let d = tempfile::tempdir().unwrap();
    let (_source, stamp, r) = tiny(d.path());
    let dir = dir_file(d.path());
    move_child(&dir).unwrap();
    assert_eq!(
        lifecycle(false, true, true, false, false, false, false).unwrap(),
        Phase::Moved
    );
    body_at(&dir, QUARANTINE_NAME, &stamp, false, &r).unwrap();
    fs::rename(
        d.path().join(QUARANTINE_NAME),
        d.path().join("original-kept"),
    )
    .unwrap();
    fs::write(d.path().join(QUARANTINE_NAME), b"replacement").unwrap();
    assert!(body_at(&dir, QUARANTINE_NAME, &stamp, false, &r).is_err());
    assert!(d.path().join("original-kept").exists());
}

#[test]
#[ignore = "tiny native unlink/completion-gap fixture requires Root admission"]
fn scan203_retirement_native_durable_unlink_intent_survives_completion_gap() {
    root_fixture();
    let d = tempfile::tempdir().unwrap();
    let (_source, stamp, r) = tiny(d.path());
    let dir = dir_file(d.path());
    let state = tempfile::tempdir().unwrap();
    let receipts = dir_file(state.path());
    let intent = publish_at(
        &state.path().join("intent.json"),
        &json!({"fixture":"intent"}),
        &receipts,
    )
    .unwrap();
    move_child(&dir).unwrap();
    body_at(&dir, QUARANTINE_NAME, &stamp, false, &r).unwrap();
    let verified = publish_at(
        &state.path().join("verified.json"),
        &json!({"intent":intent,"source_identity":stamp}),
        &receipts,
    )
    .unwrap();
    let unlink = publish_at(
        &state.path().join("unlink-intent.json"),
        &json!({"verified":verified}),
        &receipts,
    )
    .unwrap();
    unlink_child(&dir).unwrap();
    assert_eq!(
        lifecycle(false, false, true, true, true, true, false).unwrap(),
        Phase::Unlinked
    );
    assert!(saved(&unlink).is_ok());
    assert!(saved(&verified).is_ok());
    assert!(!state.path().join("completion.json").exists());
    assert!(!d.path().join(QUARANTINE_NAME).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "loopback-only signed S3 fixture requires separately admitted native sandbox"]
async fn scan203_retirement_native_s3_protocol_is_read_only_and_sidecar_gated() {
    use std::{net::TcpListener, thread};
    root_fixture();
    for bad_sidecar in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let r = receipt(21, SHA203, "fixture-etag-1");
        let sidecar = if bad_sidecar {
            b"wrong\n".to_vec()
        } else {
            canonical_sidecar(&r)
        };
        let count = if bad_sidecar { 2 } else { 3 };
        let server = thread::spawn(move || -> Result<Vec<String>> {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut lines = vec![];
            for request in 0..count {
                let (mut socket, _) = loop {
                    match listener.accept() {
                        Ok(v) => break v,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            ensure!(Instant::now() < deadline, "fixture request deadline");
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => return Err(e.into()),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                let mut bytes = vec![];
                let mut chunk = [0u8; 2048];
                while !bytes.windows(4).any(|v| v == b"\r\n\r\n") {
                    let n = socket.read(&mut chunk)?;
                    ensure!(n > 0, "fixture request truncated");
                    bytes.extend_from_slice(&chunk[..n]);
                    ensure!(bytes.len() <= 16384, "fixture header bound");
                }
                let text = std::str::from_utf8(&bytes)?;
                let line = text
                    .lines()
                    .next()
                    .context("fixture request line")?
                    .to_string();
                ensure!(
                    text.lines().any(|v| v
                        .to_ascii_lowercase()
                        .starts_with("authorization: aws4-hmac-sha256")),
                    "S3 request was not signed"
                );
                let get = request == 1;
                ensure!(
                    line.starts_with(if get { "GET " } else { "HEAD " }),
                    "unexpected mutating/noncanonical S3 method"
                );
                let uri = line
                    .split_whitespace()
                    .nth(1)
                    .context("fixture request URI")?;
                ensure!(
                    uri.split('?').next()
                        == Some(if get {
                            "/fixture/epoch-203.jet.sha256"
                        } else {
                            "/fixture/epoch-203.jet"
                        }),
                    "wrong fixture object"
                );
                let body = if get { sidecar.as_slice() } else { &[] };
                let length = if get { body.len() } else { 21 };
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nETag: \"fixture-etag-1\"\r\nConnection: close\r\n\r\n"
                )?;
                socket.write_all(body)?;
                socket.flush()?;
                lines.push(line);
            }
            Ok(lines)
        });
        let cfg = R2Config {
            endpoint,
            bucket: "fixture".into(),
            access_key: "fixture-key".into(),
            secret_key: "fixture-secret".into(),
        };
        let result = remote(&s3_client(&cfg), &cfg, &r).await;
        assert_eq!(result.is_err(), bad_sidecar);
        assert_eq!(server.join().unwrap().unwrap().len(), count);
    }
}

#[test]
fn scan203_retirement_guard_artifact_must_be_exactly_bound_and_nonzero() {
    let (mut p, _, c, _) = plans();
    let mut v = sample(&p);
    p.guard_binary.sha256 = "d".repeat(64);
    assert!(plan_scope(&p, &c).is_ok());
    assert!(guard_sample(&v, &p, &"a".repeat(32), 1234, 1000).is_err());
    v["self_sha256"] = json!(p.guard_binary.sha256);
    assert!(guard_sample(&v, &p, &"a".repeat(32), 1234, 1000).is_ok());
    assert!(
        guard_command(&p, &"a".repeat(32))
            .contains(&format!("--self-sha256 {}", p.guard_binary.sha256))
    );
    for invalid in ["0".repeat(64), "D".repeat(64), "short".into()] {
        p.guard_binary.sha256 = invalid;
        assert!(plan_scope(&p, &c).is_err());
    }
}
