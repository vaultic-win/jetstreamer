//! Verify the guarded private export with native, independently anchored full
//! playback. Keep the actual verifier and both hashes inside the existing
//! shared holding allowance. No local or remote readiness marker is written.
use super::*;
use std::os::unix::fs::PermissionsExt;

const EXPORT: &str = "de6780b860b3467bae21fbd19176ca14";
const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1";
const VERIFIER: &str = "2f0546bcf253a0f21740ff1e297fb18f7a62e37c2df7d72806c433cddf4cd57b";
const ANCHORS: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch145-independent-boundary-metadata-20261106-v1";
const PARENT: &str = "Fnoa95TKZ1U419CubZrxYDtFnqadRmvM554FFi2xSizB";
const TERMINAL: &str = "4zqmYpqcustpx2BQ2gB6y7v1HsvZpPGeyaRKFEsbThum";

fn digest(v: &Value, key: &str) -> Result<String> {
    let hash = v[key].as_str().context("absent SHA-256")?;
    ensure!(custody::hex(hash, 64), "invalid {key} SHA-256");
    Ok(hash.to_owned())
}
fn extraction(e: &Value, archive: &Path) -> Result<()> {
    ensure!(
        e["schema"] == "jetstreamer-private-epoch145-canonical-prefix-extraction-v1"
            && e["epoch"] == 145
            && e["archive"] == archive.to_str().unwrap()
            && e["archive_bytes"] == BYTES
            && e["output_slot_start"] == 62_640_000
            && e["output_slot_count"] == 432000
            && e["source_archive"] == SOURCE
            && e["source_archive_sha256"] == SOURCE_SHA
            && e["source_manifest_sha256"] == MANIFEST_SHA
            && e["worker_sha256"]
                == "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"
            && e["source_canonical_checkpoint_slot"] == 63_072_070
            && e["source_canonical_accounts_hash"]
                == "DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p"
            && e["retained_verification_tail_slots"] == 71
            && e["independent_output_reread_passed"] == true
            && e["source_must_be_retained"] == true
            && [
                "current_plugin_verification_passed",
                "canonical_sidecar_authorized",
                "publication_authorized",
                "retirement_authorized",
                "r2_mutations"
            ]
            .iter()
            .all(|k| e[*k] == false),
        "private extraction range, source, authority or identity changed"
    );
    for key in [
        "archive_sha256",
        "output_semantic_sha256",
        "expected_output_provenance_sha256",
    ] {
        digest(e, key)?;
    }
    Ok(())
}
fn bound(path: &Path, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn immutable_copy(path: &Path, bytes: &[u8]) -> Result<Bound> {
    let parent = path.parent().context("copy parent")?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    let b = bound(path, &custody::sha(bytes));
    custody::bytes(&b, 8 << 20, true)?;
    Ok(b)
}
pub(super) fn terminal(iid: &str) -> Result<()> {
    let rows = capacity::run(
        "/usr/bin/journalctl",
        &[
            "--no-pager",
            "-ojson",
            "--output-fields=UNIT,INVOCATION_ID,MESSAGE_ID",
            "_PID=1",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={iid}"),
            "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
        ],
        "15",
    )?;
    ensure!(
        rows.lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .any(|v| v["UNIT"] == UNIT
                && v["INVOCATION_ID"] == iid
                && v["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"),
        "missing successful export termination"
    );
    Ok(())
}
fn run_child(
    command: &mut Command,
    fit: &capacity::Fit,
    lease: &source_lease::ReadLease,
) -> Result<()> {
    fit.await_topology()?;
    fit.await_current(0)?;
    lease.check()?;
    let parent = std::process::id();
    command.stdin(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() as u32 != parent
            {
                return Err(std::io::Error::other("lost full verifier guard"));
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let result = (|| -> Result<()> {
        let pid = child.id();
        let ticks = native::ticks(pid)?;
        let mut last = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                ensure!(
                    status.success(),
                    "native verification child failed: {status}"
                );
                return lease.check();
            }
            lease.check()?;
            let wait = match fit.current(0) {
                Ok(_) => false,
                Err(e) if e.is::<capacity::GuardInFlight>() => true,
                Err(e) => return Err(e),
            };
            if wait || last.elapsed() >= Duration::from_secs(30) {
                if let Err(e) = freeze(pid) {
                    if child.try_wait()?.is_some_and(|s| s.success()) {
                        return lease.check();
                    }
                    return Err(e);
                }
                let sample =
                    while_stopped(pid, ticks, Instant::now() + Duration::from_secs(90), || {
                        lease.check()?;
                        fit.topology()?;
                        fit.current(0)
                    })?;
                ensure!(
                    unsafe { libc::kill(pid.try_into()?, libc::SIGCONT) } == 0,
                    "resume guarded verifier"
                );
                println!("{} epoch145 verification guard {}", custody::now()?, sample);
                last = Instant::now();
            }
            thread::sleep(Duration::from_secs(3));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
fn archive_hash(
    tag: &str,
    archive: &Path,
    expected: &str,
    state: &Path,
    fit: &capacity::Fit,
    lease: &source_lease::ReadLease,
) -> Result<()> {
    let out = state.join(tag);
    let f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&out)?;
    run_child(
        Command::new("/usr/bin/sha256sum")
            .arg("--")
            .arg(archive)
            .stdout(Stdio::from(f)),
        fit,
        lease,
    )?;
    let report = fs::read_to_string(&out)?;
    ensure!(
        report == format!("{expected}  {}\n", archive.display()),
        "independent archive hash {tag} differs"
    );
    File::open(out)?.sync_all()?;
    Ok(())
}
pub(super) fn plugin_counts(report: &Value, argv: &[String]) -> Result<()> {
    let r = &report["report"];
    ensure!(
        report["schema"] == "jetstreamer-horizon-plugin-playback-v1"
            && report["full_epoch_verified"] == true
            && report["invocation"] == json!(argv)
            && report["source"] == OUTPUT
            && report["expected_first_slot"] == 62640000
            && report["expected_last_slot"] == 63071999
            && r["epoch"] == 145
            && r["first_slot"] == 62640000
            && r["last_slot"] == 63071999
            && r["slots"] == 432000
            && r["worker_count"] == 1
            && r["blocks"]
                .as_u64()
                .zip(r["skipped"].as_u64())
                .and_then(|(a, b)| a.checked_add(b))
                == Some(432000)
            && [
                "entries",
                "transactions",
                "transaction_updates",
                "orphan_updates",
                "epoch_updates",
                "account_data_bytes"
            ]
            .iter()
            .all(|k| r[*k].is_u64())
            && r["stream_digest"].as_array().is_some_and(
                |a| a.len() == 32 && a.iter().all(|n| n.as_u64().is_some_and(|b| b <= 255))
            ),
        "incomplete epoch 145 plugin coverage, source, counters or digest"
    );
    Ok(())
}
fn native_tools(root: &Path, state: &Path) -> Result<(Bound, Bound, Bound)> {
    let full = bound(&root.join("verifier-tools/verify_archive"), VERIFIER);
    let seal = bound(
        &root.join("verifier-tools/deployment-seal-receipt.json"),
        "57b517db3333aa6abe2cd4f4dae001d27cc79e884b79b046a05a39b9c1a9e488",
    );
    let built = bound(
        &root.join("verifier-tools/build-proof.json"),
        "28a6f5a2c841256cb7e537d6c6b18a9f7481cb9c296fcfe0e8280944c85dfe9a",
    );
    let test = bound(
        &root.join("recovery-ab3bdc4fd1df4d43b3afcefe4177c550/fixtures/native-results.json"),
        "54bafc619501c938d209661ef52593ccd21ecdf920bdee1711f036f3888178e3",
    );
    let current = bound(
        &Path::new(capacity::RUNTIME)
            .join("public-reader-refresh-20261121-v1/CURRENT_READER_EQUIVALENCE.json"),
        "8f4a045a212e7e20d7cbaa4dcaf9f1d2a9ced828ded1b0a44fb9084b812235c1",
    );
    let proof = custody::json(&current, true)?;
    ensure!(
        proof["branch_commit"] == "ee55f614012585bc99e4ed7398a56758bde2664e",
        "current pipeline build"
    );
    let pipe: Bound = serde_json::from_value(proof["pipeline"].clone())?;
    ensure!(
        pipe.sha256 == "30251e917ca0eb103aebd586556e235150e396a7354bb670b7bc1a44b83faa51",
        "unqualified plugin"
    );
    for key in ["actual_current_build", "seal"] {
        custody::json(&serde_json::from_value(proof[key].clone())?, true)?;
    }
    ensure!(
        custody::json(&seal, true)?["members"]
            .as_array()
            .is_some_and(|r| r
                .iter()
                .any(|v| v["name"] == "verify_archive" && v["sha256"] == VERIFIER))
            && custody::json(&built, true)?["artifact_sha256"] == VERIFIER,
        "full verifier seal or actual build changed"
    );
    let fixture = custody::evidence(&test)?;
    ensure!(
        fixture["schema"] == "horizon-current-reader-native-qualification-v1"
            && fixture["remote_mutations"] == false
            && fixture["checks"].as_array().is_some_and(|r| r
                .iter()
                .any(|v| v["sha256"] == VERIFIER && v["exit_code"] == 0)
                && r.iter()
                    .any(|v| v["sha256"] == pipe.sha256 && v["exit_code"] == 0)),
        "native fixtures changed"
    );
    custody::bytes(&full, 16 << 20, true)?;
    let m = custody::frozen_identity(&pipe.path)?;
    let mut f = File::open(&pipe.path)?;
    let mut h = sha2::Sha256::default();
    let count = std::io::copy(&mut f, &mut h)?;
    use sha2::Digest;
    ensure!(
        count == m.bytes
            && format!("{:x}", h.finalize()) == pipe.sha256
            && custody::frozen_identity(&pipe.path)? == m,
        "pipeline image differs"
    );
    let frozen_fixture = immutable_copy(
        &state.join("native-fixture-evidence.json"),
        &custody::bytes(&test, 8 << 20, false)?,
    )?;
    let compiler = custody::json(&built, true)?;
    let args = compiler["compiler"]
        .as_str()
        .context("actual full verifier command")?
        .split_whitespace()
        .collect::<Vec<_>>();
    let flags = args
        .windows(2)
        .filter(|w| w[0] == "-C")
        .map(|w| w[1])
        .collect::<Vec<_>>();
    ensure!(
        flags.contains(&"opt-level=1"),
        "unexpected verifier optimization"
    );
    let accepted = json!({"schema":"horizon-current-reader-main-acceptance-v1","reader_commit":proof["branch_commit"],"pipeline":pipe,"full_verifier":full,
        "cargo_features":["horizon_pipeline --no-default-features","verify_archive features=[]"],"rustc_flags":flags,"minimum_thread_stack_bytes":67108864u64,
        "source_build_evidence":[current,proof["actual_current_build"],proof["seal"],built,seal,frozen_fixture],
        "source_artifact_correspondence_accepted":true,"full_and_plugin_capabilities_accepted":true});
    let qualified = immutable_copy(
        &state.join("reader-qualification.json"),
        &serde_json::to_vec_pretty(&accepted)?,
    )?;
    Ok((full, pipe, qualified))
}

pub fn full(fleet: Bound, sha: &str, joint: bool) -> Result<()> {
    let image = if joint {
        joint::IMAGE.into()
    } else {
        Path::new(ROOT).join("post-tools/export145")
    };
    check_image(sha, &image)?;
    if joint {
        joint::route(sha)?;
    }
    let iid = verify_cgroup()?;
    let _lock = lock()?;
    pending()?;
    source_identity()?;
    terminal(EXPORT)?;
    let completed = Path::new(BASE).join("state").join(EXPORT);
    let done = custody::binding(&completed.join("complete.json"))?;
    let d = custody::evidence(&done)?;
    ensure!(
        d["iid"] == EXPORT
            && d["r2_mutations"] == false
            && !completed.join("failed.json").try_exists()?,
        "export incomplete or failed"
    );
    let cc: Bound = serde_json::from_value(d["receipt"].clone())?;
    ensure!(
        cc.path == completed.join("extraction-complete.json"),
        "wrong export receipt"
    );
    let raw = custody::bytes(&cc, 8 << 20, false)?;
    let c: Value = serde_json::from_slice(&raw)?;
    ensure!(
        c["schema"] == "horizon-epoch145-guarded-private-prefix-completion-v1"
            && c["actor_iid"] == EXPORT
            && c["r2_mutations"] == false,
        "export completion changed"
    );
    let archive = Path::new(OUTPUT).join("epoch-145.jet");
    let e = &c["extraction"];
    extraction(e, &archive)?;
    let expected = digest(e, "archive_sha256")?;
    let provenance = digest(e, "expected_output_provenance_sha256")?;
    let identity = custody::frozen_identity(&archive)?;
    let alloc = custody::evidence(&custody::binding(&completed.join("allocated.json"))?)?;
    ensure!(
        identity.device == 64512
            && identity.inode == 103237059
            && identity.bytes == BYTES
            && alloc["iid"] == EXPORT
            && alloc["inode"] == identity.inode
            && alloc["device"] == identity.device,
        "unbound canonical inode"
    );
    ensure!(
        !archive.with_extension("jet.sha256").try_exists()?,
        "unexpected readiness marker"
    );
    let fit = capacity::capture_phase(&fleet, joint)?;
    fit.await_topology()?;
    let first = fit.await_current(0)?;
    source_lease::arm_break_signal()?;
    let lease = source_lease::ReadLease::acquire(
        &archive,
        source_lease::FileIdentity::from(&fs::symlink_metadata(&archive)?),
    )?;
    let state = Path::new(ROOT).join(format!("full-{iid}"));
    fs::DirBuilder::new().mode(0o700).create(&state)?;
    let sealed_completion = immutable_copy(&state.join("export-completion.json"), &raw)?;
    let mut refs = vec![sealed_completion];
    for (name, hash) in [
        (
            "incoming-62639999-source.json",
            "5fd04d4f501d77f9866b469f33e3ac729d44187979e6937e9856e880de401ede",
        ),
        (
            "terminal-63071999-response.json",
            "0c0adba08c80831f2cfcbf98ba6a0ad5e4d0cc537f7570c2c0414dce755860c7",
        ),
    ] {
        let a = bound(&Path::new(ANCHORS).join(name), hash);
        custody::bytes(&a, 8 << 20, true)?;
        refs.push(a);
    }
    let expectation = json!({"schema":"horizon-current-reader-epoch-expectation-v1","epoch":145,"parent_slot":62639999,"parent_blockhash":PARENT,"terminal_slot":63071999,"terminal_blockhash":TERMINAL,"provenance_sha256":provenance,"independent_evidence":refs});
    let eb = immutable_copy(
        &state.join("expectation.json"),
        &serde_json::to_vec_pretty(&expectation)?,
    )?;
    let (reader, pipeline, qualified) = native_tools(Path::new(ROOT), &state)?;
    let scratch = state.join("delivery");
    fs::DirBuilder::new().mode(0o700).create(&scratch)?;
    let plan = json!({"schema":"horizon-current-reader-plan-v1","repository":"/home/sol/workspace/jetstreamer",
      "origin_url":"git@github-matt-vaultic:vaultic-win/jetstreamer.git","reader_commit":"ee55f614012585bc99e4ed7398a56758bde2664e",
      "pipeline":pipeline,"full_verifier":reader,"qualification":qualified,"scratch_directory":scratch,"threads":1,
      "maximum_archive_bytes":BYTES,"minimum_free_bytes":first["protected_bytes"],"epoch_expectations":{"145":eb}});
    let plan_binding = immutable_copy(
        &state.join("delivery-plan.json"),
        &serde_json::to_vec_pretty(&plan)?,
    )?;
    let fullargs = [
        archive.to_str().context("archive")?,
        "--full",
        "--threads",
        "1",
        "--anchor",
        "62639999",
        PARENT,
        "--expected-terminal",
        "63071999",
        TERMINAL,
        "--expected-provenance-sha256",
        &provenance,
    ];
    custody::write_new(
        &state.join("started.json"),
        &json!({"invocation":iid,"fleet":fleet,"fit":fit.evidence,"initial":first,"archive":identity,"completion":done,"verifier":reader,"argv":fullargs,"expectation":eb}),
    )?;
    archive_hash("before.sha256", &archive, &expected, &state, &fit, &lease)?;
    run_child(
        Command::new(&reader.path)
            .args(fullargs)
            .env("RUST_MIN_STACK", "67108864")
            .env("RAYON_NUM_THREADS", "1")
            .env("TOKIO_WORKER_THREADS", "1"),
        &fit,
        &lease,
    )?;
    archive_hash("after.sha256", &archive, &expected, &state, &fit, &lease)?;
    ensure!(
        custody::frozen_identity(&archive)? == identity,
        "archive changed"
    );
    custody::bytes(&reader, 16 << 20, true)?;
    lease.check()?;
    let record = json!({"schema":"horizon-145-current-native-full-acceptance-v1","epoch":145,"invocation":iid,"at_unix_seconds":custody::now()?,"archive":archive,"archive_identity":identity,"archive_bytes":BYTES,"archive_sha256":expected,"verifier":reader,"argv":fullargs,"exit_code":0,"incoming_slot":62639999,"terminal_slot":63071999,"expected_slot_count":432000,"expectation":eb,"delivery_plan":plan_binding,"export_completion":cc,"independent_pre_post_hashes_match":true,"r2_mutations":false});
    immutable_copy(
        &state.join("verified.json"),
        &serde_json::to_vec_pretty(&record)?,
    )?;
    let report_path = state.join("plugin-report.json");
    let argv = vec![
        pipeline.path.to_str().context("pipeline path")?.to_string(),
        "145".into(),
        OUTPUT.into(),
        "--verify-only".into(),
        "--threads".into(),
        "1".into(),
        "--verification-report".into(),
        report_path.to_str().context("report path")?.to_string(),
    ];
    run_child(
        Command::new(&pipeline.path)
            .args(&argv[1..])
            .env("RUST_MIN_STACK", "67108864")
            .env("RAYON_NUM_THREADS", "1")
            .env("TOKIO_WORKER_THREADS", "1"),
        &fit,
        &lease,
    )?;
    let report_binding = custody::binding(&report_path)?;
    let report = custody::evidence(&report_binding)?;
    plugin_counts(&report, &argv)?;
    archive_hash(
        "after-plugin.sha256",
        &archive,
        &expected,
        &state,
        &fit,
        &lease,
    )?;
    ensure!(
        custody::frozen_identity(&archive)? == identity,
        "archive changed after plugin"
    );
    lease.check()?;
    immutable_copy(
        &state.join("verified-plugin.json"),
        &serde_json::to_vec_pretty(&json!({
        "schema":"horizon-145-current-native-plugin-acceptance-v1","epoch":145,"invocation":iid,"archive":archive,
        "archive_identity":identity,"archive_sha256":expected,"pipeline":pipeline,"report":report_binding,"argv":argv,"exit_code":0,
        "current_branch_qualification":"8f4a045a212e7e20d7cbaa4dcaf9f1d2a9ced828ded1b0a44fb9084b812235c1","r2_mutations":false}))?,
    )?;
    fit.await_topology()?;
    fit.await_current(0)?;
    lease.check()?;
    // Publish the canonical checksum privately only after the full and plugin scans.
    immutable_copy(
        &archive.with_extension("jet.sha256"),
        format!("{expected}  epoch-145.jet\n").as_bytes(),
    )?;
    println!("{}", state.join("verified.json").display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_plugin_requires_all_slots_bound_source_and_stream_digest() {
        let argv = vec!["/native/pipeline".into(), "145".into()];
        let v = json!({"schema":"jetstreamer-horizon-plugin-playback-v1","full_epoch_verified":true,
            "invocation":argv,"source":OUTPUT,"expected_first_slot":62640000,"expected_last_slot":63071999,
            "report":{"epoch":145,"first_slot":62640000,"last_slot":63071999,"slots":432000,"worker_count":1,
                "blocks":400000,"skipped":32000,"entries":10,"transactions":1,"transaction_updates":3,"orphan_updates":2,
                "epoch_updates":1,"account_data_bytes":32,"stream_digest":vec![0;32]}});
        plugin_counts(&v, &argv).unwrap();
        for (key, wrong) in [
            ("slots", json!(432071)),
            ("skipped", json!(31999)),
            ("stream_digest", json!([])),
            ("worker_count", json!(2)),
        ] {
            let mut r = v.clone();
            r["report"][key] = wrong;
            assert!(plugin_counts(&r, &argv).is_err());
        }
        let mut r = v;
        r["source"] = json!("another-directory");
        assert!(plugin_counts(&r, &argv).is_err());
    }
    #[test]
    fn qualification_only_cannot_qualify_an_archive() {
        assert!(
            extraction(
                &json!({"schema":"horizon-current-reader-native-qualification-v1"}),
                Path::new(OUTPUT)
            )
            .is_err()
        );
    }
}
