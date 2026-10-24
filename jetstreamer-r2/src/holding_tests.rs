use super::*;

fn large_campaign_fleet_fixture() -> Vec<u8> {
    let mut value = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1",
        "first_epoch":101,"last_epoch":200,"unit_census":{},"epochs":[],"active":[],"padding":""});
    let overhead = serde_json::to_vec(&value).unwrap().len();
    value["padding"] = json!("x".repeat(1_578_015 - overhead));
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(bytes.len(), 1_578_015);
    bytes
}

#[test]
fn complete_fleet_above_one_mib_is_accepted_only_with_campaign_policy() {
    let path =
        Path::new("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-fixture.json");
    let bytes = large_campaign_fleet_fixture();
    let sha = hex_lower(&Sha256::digest(&bytes));
    let limit = fleet_evidence_limit(path).unwrap();
    let value = evidence_payload(&bytes, &sha, limit, path).unwrap();
    fleet_evidence_shape(&value).unwrap();
    assert!(value["padding"].as_str().unwrap().len() > 1 << 20);
    let error = evidence_payload(&bytes, &sha, 1 << 20, path)
        .unwrap_err()
        .to_string();
    assert!(error.contains(&format!("path={}", path.display())));
    assert!(error.contains("actual_bytes=1578015"));
    assert!(error.contains("allowed_bytes=1048576"));
}

#[test]
fn fleet_large_bound_cannot_select_other_receipts_or_namespaces() {
    for path in [
        "/var/lib/jetstreamer/receipt.json",
        "/tmp/fleet.json",
        "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/nested/fleet.json",
        "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/../fleet.json",
        "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet.txt",
    ] {
        assert!(fleet_evidence_limit(Path::new(path)).is_err(), "{path}");
    }
}

#[test]
fn complete_fleet_reader_stays_bounded_and_digest_bound() {
    let path =
        Path::new("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-fixture.json");
    let limit = fleet_evidence_limit(path).unwrap();
    let excessive = vec![b' '; limit as usize + 1];
    let sha = hex_lower(&Sha256::digest(&excessive));
    let error = evidence_payload(&excessive, &sha, limit, path)
        .unwrap_err()
        .to_string();
    assert!(error.contains("actual_bytes=16777217"));
    assert!(error.contains("allowed_bytes=16777216"));
    let bytes = large_campaign_fleet_fixture();
    assert!(evidence_payload(&bytes, &"0".repeat(64), limit, path).is_err());
}

#[test]
fn large_allowance_never_promotes_foreign_fleet_schema_or_epoch_range() {
    for value in [
        json!({"schema":"ordinary-receipt-v2","first_epoch":101,"last_epoch":200}),
        json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":201,"last_epoch":300}),
        json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":"101","last_epoch":200}),
    ] {
        assert!(fleet_evidence_shape(&value).is_err());
    }
}

fn approved_mapping() -> Mapping {
    Mapping {
        schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
        host: HOST.into(),
        prefix: "fixture-approved/".into(),
        user_provided_prefix: true,
        authorization_reference: "isolated test fixture; no production authorization".into(),
    }
}
fn park_fixture() -> Park {
    Park {
        schema: "jetstreamer-horizon-holding-park-plan-v2".into(),
        mapping: Bound {
            path: "/sealed/map.json".into(),
            sha256: "a".repeat(64),
        },
        eligibility: Bound {
            path: "/sealed/eligibility.json".into(),
            sha256: "b".repeat(64),
        },
        source: "/home/sol/.jetstreamer-private/closed/epoch-136.jet".into(),
        length: 42,
        sha256: "c".repeat(64),
    }
}
fn eligibility(p: &Park) -> Value {
    json!({"schema":"jetstreamer-horizon-holding-eligibility-v2","host":HOST,
        "source":p.source,"length":p.length,"sha256":p.sha256,"closed":true,
        "content_class":"public-chain-artifact","credentials_config_and_logs_excluded":true,
        "canonical_archive":false,"local_retirement_authorized":false})
}
fn custody_fixture(m: &Mapping) -> Value {
    let p = park_fixture();
    let key = object_key(m, &p.sha256).unwrap();
    let manifest = manifest_bytes(m, &p, &key, 1001, 1003, 0o600).unwrap();
    let manifest_sha = hex_lower(&Sha256::digest(&manifest));
    json!({"schema":"jetstreamer-horizon-holding-custody-v2","host":HOST,"bucket":BUCKET,
        "prefix":m.prefix,"object_key":key,"length":p.length,"sha256":p.sha256,"object_etag":"fixture-1",
        "manifest_key":format!("{}manifests/{manifest_sha}.json",m.prefix),"manifest_sha256":manifest_sha,
        "manifest":serde_json::from_slice::<Value>(&manifest).unwrap(),
        "remote_sha256_readback":true,"local_source_revalidated":true,
        "local_retirement_authorized":false,"canonical_publication_authorized":false,
        "runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false})
}

#[test]
fn prefix_requires_explicit_matching_host_and_unambiguous_relative_namespace() {
    let mut m = approved_mapping();
    mapping(&m).unwrap();
    for value in [
        "", "/", "../", "a/../b/", "a//b/", "a/./", "/host/", "a\\b/", "a%2fb/", "a?b/", "a b/",
        "a", "é/",
    ] {
        m.prefix = value.into();
        assert!(mapping(&m).is_err(), "{value:?}");
    }
    m = approved_mapping();
    m.user_provided_prefix = false;
    assert!(mapping(&m).is_err());
    m = approved_mapping();
    m.host = "another-host".into();
    assert!(mapping(&m).is_err());
    m = approved_mapping();
    m.authorization_reference.clear();
    assert!(mapping(&m).is_err());
    m = approved_mapping();
    m.prefix = "a".repeat(161) + "/";
    assert!(mapping(&m).is_err());
    let key = object_key(&approved_mapping(), &"c".repeat(64)).unwrap();
    assert!(key.starts_with("fixture-approved/objects/"));
    assert!(key.ends_with(".blob"));
    assert!(object_key(&approved_mapping(), "../epoch-136.jet").is_err());
}

#[test]
fn source_eligibility_does_not_borrow_canonical_or_sensitive_artifact_authority() {
    let p = park_fixture();
    source_scope(&p, &eligibility(&p)).unwrap();
    for (field, value) in [
        ("closed", json!(false)),
        ("canonical_archive", json!(true)),
        ("local_retirement_authorized", json!(true)),
        ("credentials_config_and_logs_excluded", json!(false)),
        ("sha256", json!("d".repeat(64))),
        ("content_class", json!("private-logs")),
    ] {
        let mut e = eligibility(&p);
        e[field] = value;
        assert!(source_scope(&p, &e).is_err(), "{field}");
    }
    for name in [
        "/home/sol/horizon/epoch-136.jet",
        "/home/sol/.jetstreamer-private/closed/../secret.key",
        "/home/sol/.jetstreamer-private/logs/output.json",
        "/home/sol/.jetstreamer-private/credentials/state.json",
        "/home/sol/.jetstreamer-private/closed/key.PEM",
        "/home/sol/.jetstreamer-private/closed/epoch-136.jet.sha256",
    ] {
        let mut p = park_fixture();
        p.source = name.into();
        assert!(source_scope(&p, &eligibility(&p)).is_err(), "{name}");
    }
}

#[test]
fn custody_rejects_cross_prefix_content_or_authority_changes() {
    let m = approved_mapping();
    let c = custody_fixture(&m);
    custody(&c, &m).unwrap();
    for (field, value) in [
        ("prefix", json!("another-host/")),
        ("object_key", json!("epoch-136.jet")),
        ("sha256", json!("d".repeat(64))),
        ("remote_sha256_readback", json!(false)),
        ("local_source_revalidated", json!(false)),
        ("local_retirement_authorized", json!(true)),
        ("canonical_publication_authorized", json!(true)),
        ("replay_launch_authorized", json!(true)),
        ("job_resume_authorized", json!(true)),
    ] {
        let mut bad = c.clone();
        bad[field] = value;
        assert!(custody(&bad, &m).is_err(), "{field}");
    }
    let mut bad = c.clone();
    bad["manifest"]["length"] = json!(43);
    assert!(custody(&bad, &m).is_err());
    // Even a rehashed manifest cannot change the host binding.
    bad = c;
    bad["manifest"]["host"] = json!("another-host");
    let hash = hex_lower(&Sha256::digest(
        serde_json::to_vec(&bad["manifest"]).unwrap(),
    ));
    bad["manifest_sha256"] = json!(hash);
    bad["manifest_key"] = json!(format!("{}manifests/{hash}.json", m.prefix));
    assert!(custody(&bad, &m).is_err());
}

#[test]
fn native_composite_evidence_cannot_contradict_verified_content() {
    let proof = LocalProof {
        sha256_hex: "a".repeat(64),
        multipart_etag: "fixture-1".into(),
        composite_sha256: BASE64_STANDARD.encode([7u8; 32]),
    };
    let mut remote = RemoteArchive {
        length: 42,
        etag: proof.multipart_etag.clone(),
        metadata_sha256: Some(proof.sha256_hex.clone()),
        composite_sha256: None,
        checksum_type: None,
        multipart_part_size: Some(DEFAULT_PART_SIZE),
    };
    native_checksum(&remote, &proof, 42).unwrap();
    remote.composite_sha256 = Some(format!("{}-1", proof.composite_sha256));
    remote.checksum_type = Some(ChecksumType::Composite);
    native_checksum(&remote, &proof, 42).unwrap();
    remote.composite_sha256 = Some(BASE64_STANDARD.encode([8u8; 32]));
    assert!(native_checksum(&remote, &proof, 42).is_err());
    remote.composite_sha256 = Some(proof.composite_sha256.clone());
    remote.checksum_type = Some(ChecksumType::FullObject);
    assert!(native_checksum(&remote, &proof, 42).is_err());
}

#[test]
fn private_receipts_are_idempotent_but_conflicting_custody_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("custody.json");
    let mut value = custody_fixture(&approved_mapping());
    value["reference_census_before"] = json!({"inspected_processes":10,"references":[]});
    persist(&path, &value).unwrap();
    let original = fs::read(&path).unwrap();
    value["reference_census_before"] = json!({"inspected_processes":11,"references":[]});
    persist(&path, &value).unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    value["sha256"] = json!("d".repeat(64));
    assert!(persist(&path, &value).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn restore_commit_and_floor_never_overwrite_or_consume_the_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let partial = dir.path().join("partial");
    let final_path = dir.path().join("restored");
    fs::write(&partial, b"restored bytes").unwrap();
    fs::write(&final_path, b"existing").unwrap();
    assert!(rename_noreplace(&partial, &final_path).is_err());
    assert_eq!(fs::read(&final_path).unwrap(), b"existing");
    assert_eq!(fs::read(&partial).unwrap(), b"restored bytes");
    fs::remove_file(&final_path).unwrap();
    rename_noreplace(&partial, &final_path).unwrap();
    assert!(!partial.exists());
    assert_eq!(fs::read(&final_path).unwrap(), b"restored bytes");
    let mut file = File::create(dir.path().join("guarded")).unwrap();
    let mut guarded = FloorWriter {
        file: &mut file,
        directory: dir.path(),
        minimum_free_bytes: u64::MAX,
    };
    assert!(guarded.write_all(b"must not write").is_err());
    assert_eq!(file.metadata().unwrap().len(), 0);
}

#[test]
fn restore_admission_cannot_omit_private_growth_owners_or_bind_a_stale_fleet() {
    let ordinary = json!({"Id":"production.service","InvocationID":"a".repeat(32),"ActiveState":"active","SubState":"running","NRestarts":"0"});
    let private = json!({"Id":"private.service","InvocationID":"b".repeat(32),"ActiveState":"active","SubState":"running","NRestarts":"0"});
    let f = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,
        "sampled_at_utc":"2026-10-23T15:56:00Z","observer_receipt":"/accepted.json","observer_sha256":"c".repeat(64),
        "active":[{"producer":ordinary,"controller":ordinary}],"diagnostics":[{"live":true,"unit":private}]});
    let c = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","sampled_at_utc":f["sampled_at_utc"],
        "observer":{"path":f["observer_receipt"],"sha256":f["observer_sha256"]},
        "capacity_decision":{"capped186_budget":{"valid":true,"all_current_protected_bytes":BASE_RESERVE+512*(1u64<<30)}}});
    let a = json!({"owners":[{"unit":"production.service","invocation_id":"a".repeat(32)},
        {"unit":"private.service","invocation_id":"b".repeat(32)}]});
    let now = fleet::utc_seconds("2026-10-23T15:57:00Z").unwrap();
    restore_basis(&a, &c, &f, BASE_RESERVE + 512 * (1u64 << 30), now).unwrap();
    assert!(restore_basis(&a, &c, &f, BASE_RESERVE, now).is_err());
    let mut missing = a.clone();
    missing["owners"].as_array_mut().unwrap().pop();
    assert!(restore_basis(&missing, &c, &f, BASE_RESERVE + 512 * (1u64 << 30), now).is_err());
    assert!(restore_basis(&a, &c, &f, BASE_RESERVE + 512 * (1u64 << 30), now + 1800).is_err());
    let mut different = f.clone();
    different["observer_sha256"] = json!("d".repeat(64));
    assert!(restore_basis(&a, &c, &different, BASE_RESERVE + 512 * (1u64 << 30), now).is_err());
}

#[test]
fn restore_admission_requires_the_entire_restore_above_complete_protection() {
    assert_eq!(
        admission_bytes(BASE_RESERVE, 42, BASE_RESERVE + 42).unwrap(),
        BASE_RESERVE + 42
    );
    assert!(admission_bytes(BASE_RESERVE, 42, BASE_RESERVE + 41).is_err());
    assert!(admission_bytes(BASE_RESERVE - 1, 42, u64::MAX).is_err());
    assert!(admission_bytes(BASE_RESERVE, 0, u64::MAX).is_err());
    assert!(admission_bytes(u64::MAX, 42, u64::MAX).is_err());
    // The lower five-lane baseline cannot conceal the remaining private 141 claim.
    let protected = BASE_RESERVE + (512u64 << 30);
    assert!(admission_bytes(protected, 20144, BASE_RESERVE + 20144).is_err());
}

#[test]
fn separate_os_volume_probe_cannot_select_a_job_or_change_its_reserve() {
    let c = json!({"sha256":GENESIS_PROBE_SHA,"length":20144,
        "source":"/home/sol/.jetstreamer-private/holding-public-genesis-fixture-20261023-v1/genesis.tar.bz2"});
    genesis_probe_scope(&c, GENESIS_PROBE_FLOOR).unwrap();
    for (key, value) in [
        ("sha256", json!("a".repeat(64))),
        ("length", json!(20145)),
        (
            "source",
            json!("/home/sol/.jetstreamer-private/job/epoch-136.jet"),
        ),
    ] {
        let mut bad = c.clone();
        bad[key] = value;
        assert!(
            genesis_probe_scope(&bad, GENESIS_PROBE_FLOOR).is_err(),
            "{key}"
        );
    }
    assert!(genesis_probe_scope(&c, 0).is_err());
    assert!(genesis_probe_scope(&c, GENESIS_PROBE_FLOOR - 1).is_err());
}

#[test]
fn admission_owner_derivation_deduplicates_cohorts_and_keeps_private_diagnostics() {
    let unit = |name: &str, id: char| {
        json!({"Id":name,"InvocationID":id.to_string().repeat(32),
        "ActiveState":"active","SubState":"running","NRestarts":"0"})
    };
    let ordinary = unit("ordinary.service", 'a');
    let private = unit("private.service", 'b');
    let f = json!({"active":[{"producer":ordinary,"controller":ordinary},
        {"producer":ordinary,"controller":ordinary}],
        "diagnostics":[{"live":true,"unit":private},{"live":false,"unit":{}}]});
    let owners = fleet_owners(&f).unwrap();
    assert_eq!(owners.len(), 2);
    assert_eq!(owners["private.service"], "b".repeat(32));
    let mut changed = f.clone();
    changed["active"][1]["producer"]["InvocationID"] = json!("c".repeat(32));
    assert!(fleet_owners(&changed).is_err());
    changed = f;
    changed["diagnostics"][0]["unit"]["NRestarts"] = json!("1");
    assert!(fleet_owners(&changed).is_err());
    assert!(fleet_owners(&json!({"active":[],"diagnostics":[]})).is_err());
    let controllerless = json!({"active":[{"producer":private,"ordinary_replay_claim":false}],
        "diagnostics":[{"live":true,"unit":private}]});
    assert_eq!(fleet_owners(&controllerless).unwrap().len(), 1);
    let mut missing = controllerless.clone();
    missing["diagnostics"] = json!([]);
    assert!(fleet_owners(&missing).is_err());
    missing = controllerless;
    missing["active"][0]["ordinary_replay_claim"] = json!(true);
    assert!(fleet_owners(&missing).is_err());
    assert!(fleet_owners(&json!({"active":[{}],"diagnostics":[]})).is_err());
    assert!(
        serde_json::from_value::<RestoreAdmission>(json!({
            "schema":"jetstreamer-horizon-holding-restore-admission-plan-v2",
            "mapping":{"path":"/sealed/map","sha256":"a".repeat(64)},
            "custody":{"path":"/sealed/custody","sha256":"b".repeat(64)},
            "capacity_completion":{"path":"/accepted/completion.json","sha256":"c".repeat(64)},
            "minimum_free_bytes":0
        }))
        .is_err()
    );
}

#[test]
#[ignore = "root exact accepted 16:26 fleet; read-only native evidence, no sampling or remote access"]
fn actual_accepted_fleet_includes_all_five_controllers_producers_and_private141() {
    let fleet = Bound {
        path: "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261023T162600Z.json"
            .into(),
        sha256: "c2520b7705df263e74aef11b20c81c2bf9375eec262868f87a0c9582988c0a85".into(),
    };
    let f = evidence(&fleet, false).unwrap();
    let owners = fleet_owners(&f).unwrap();
    assert_eq!(owners.len(), 11);
    assert_eq!(
        owners["horizon-qualify-141-original-entry-capped-root-20261023-v1.service"],
        "e639f007d482464f8a251455659d2ede"
    );
}

fn accept(listener: &std::net::TcpListener) -> std::net::TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "fixture request never arrived");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("fixture accept failed: {error}"),
        }
    }
}
fn request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        headers.push(byte[0]);
        assert!(headers.len() < 32 * 1024);
    }
    let headers = String::from_utf8(headers).unwrap();
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then_some(value)
        })
        .unwrap_or("0")
        .trim()
        .parse::<usize>()
        .unwrap();
    assert!(length < 16 * 1024);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    (headers, body)
}
fn respond(stream: &mut std::net::TcpStream, status: &str, headers: &str, body: &[u8]) {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
}

#[tokio::test]
async fn shared_transport_keeps_canonical_and_holding_uploads_conditional_and_fully_hashed() {
    const BODY: &[u8] = b"shared byte transport fixture";
    for canonical in [true, false] {
        let sha = hex_lower(&Sha256::digest(BODY));
        let part_md5 = Md5::digest(BODY).to_vec();
        let part_hex = hex_lower(&part_md5);
        let expected_etag = multipart_etag(std::slice::from_ref(&part_md5));
        let key = if canonical {
            "epoch-144.jet".into()
        } else {
            format!("fixture-approved/objects/{sha}.blob")
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let server_key = key.clone();
        let server_etag = expected_etag.clone();
        let server_sha = sha.clone();
        let server = std::thread::spawn(move || {
            for step in 0..4 {
                let mut stream = accept(&listener);
                let (raw_headers, body) = request(&mut stream);
                let headers = raw_headers.to_ascii_lowercase();
                let request = headers.lines().next().unwrap();
                assert!(
                    request.split_whitespace().nth(1).unwrap().split('?').next()
                        == Some(format!("/fixture/{server_key}").as_str())
                );
                match step {
                    0 => {
                        assert!(request.starts_with("post ") && request.contains("uploads"));
                        assert!(headers.contains(&format!("x-amz-meta-sha256: {server_sha}\r\n")));
                        let format = if canonical { "jet" } else { "cold-holding-v2" };
                        assert!(
                            headers.contains(&format!("x-amz-meta-horizon-format: {format}\r\n"))
                        );
                        let xml = format!(
                            "<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>fixture</Bucket><Key>{server_key}</Key><UploadId>fixture-upload</UploadId></InitiateMultipartUploadResult>"
                        );
                        respond(
                            &mut stream,
                            "200 OK",
                            "Content-Type: application/xml\r\n",
                            xml.as_bytes(),
                        );
                    }
                    1 => {
                        assert!(request.starts_with("put ") && request.contains("partnumber=1"));
                        assert_eq!(body, BODY);
                        let actual_md5 = raw_headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-md5")
                                .then_some(value.trim())
                        });
                        assert_eq!(actual_md5, Some(BASE64_STANDARD.encode(&part_md5).as_str()));
                        respond(
                            &mut stream,
                            "200 OK",
                            &format!("ETag: \"{part_hex}\"\r\n"),
                            b"",
                        );
                    }
                    2 => {
                        assert!(
                            request.starts_with("post ")
                                && request.contains("uploadid=fixture-upload")
                        );
                        assert!(
                            headers.contains("if-none-match: *\r\n"),
                            "every create must remain no-clobber"
                        );
                        let xml = format!(
                            "<CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>fixture</Bucket><Key>{server_key}</Key><ETag>\"{server_etag}\"</ETag></CompleteMultipartUploadResult>"
                        );
                        respond(
                            &mut stream,
                            "200 OK",
                            "Content-Type: application/xml\r\n",
                            xml.as_bytes(),
                        );
                    }
                    _ => {
                        assert!(request.starts_with("get "));
                        assert!(headers.contains(&format!("if-match: \"{server_etag}\"\r\n")));
                        respond(
                            &mut stream,
                            "206 Partial Content",
                            &format!(
                                "ETag: \"{server_etag}\"\r\nContent-Range: bytes 0-{}/{}\r\n",
                                BODY.len() - 1,
                                BODY.len()
                            ),
                            BODY,
                        );
                    }
                }
            }
        });
        let client = s3_client(&R2Config {
            endpoint,
            bucket: "fixture".into(),
            access_key: "fixture".into(),
            secret_key: "fixture".into(),
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.bytes");
        fs::write(&path, BODY).unwrap();
        let identity = regular_identity(&path).unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            let (etag, _) = if canonical {
                let local = LocalArchive {
                    epoch: 144,
                    archive_path: path.clone(),
                    sidecar_path: dir.path().join("unused.sidecar"),
                    identity,
                    sidecar_identity: identity,
                    length: BODY.len() as u64,
                    sha256_hex: sha.clone(),
                    sidecar: vec![],
                };
                upload_archive(&client, "fixture", &local, DEFAULT_PART_SIZE, 2, false)
                    .await
                    .unwrap()
            } else {
                upload_object(
                    &client,
                    "fixture",
                    ObjectUpload {
                        key: &key,
                        epoch: None,
                        path: &path,
                        identity,
                        length: BODY.len() as u64,
                        sha256: &sha,
                        format: "cold-holding-v2",
                    },
                    DEFAULT_PART_SIZE,
                    2,
                    false,
                )
                .await
                .unwrap()
            };
            assert_eq!(etag, expected_etag);
            verify_remote_sha256(&client, "fixture", &key, &etag, BODY.len() as u64, &sha, 2)
                .await
                .unwrap();
        })
        .await
        .expect("transport fixture timed out");
        server.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), BODY);
    }
}
