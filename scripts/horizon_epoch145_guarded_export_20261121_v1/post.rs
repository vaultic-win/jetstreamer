//! Verify the guarded private export with native, independently anchored full
//! playback. Keep the actual verifier and both hashes inside the existing
//! shared holding allowance. No local or remote readiness marker is written.
use super::*;
use std::os::unix::fs::PermissionsExt;

#[cfg(not(incident_timeout_post145_only))]
pub(super) const INCIDENT_POST_IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v7/export145";
#[cfg(incident_fixture_post145_only)]
pub(super) const INCIDENT_POST_IMAGE: &str = if cfg!(incident_v5r_136_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13l/export145"
} else if cfg!(incident_v5q_136_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13k/export145"
} else if cfg!(incident_v5o_136_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13j/export145"
} else if cfg!(incident_v5n_136_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13i/export145"
} else if cfg!(incident_v5n_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13h/export145"
} else if cfg!(incident_v5m_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13g/export145"
} else if cfg!(incident_v5k_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13f/export145"
} else if cfg!(incident_v5j_retry1_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13e/export145"
} else if cfg!(incident_v5j_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13d/export145"
} else if cfg!(incident_v7c_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13c/export145"
} else if cfg!(incident_v7b_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13b/export145"
} else {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v13/export145"
};
#[cfg(all(
    incident_registered136_post145_only,
    not(incident_fixture_post145_only)
))]
pub(super) const INCIDENT_POST_IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v12/export145";
#[cfg(all(incident_timer_post145_only, not(incident_registered136_post145_only)))]
pub(super) const INCIDENT_POST_IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v11/export145";
#[cfg(all(incident_retry_post145_only, not(incident_timer_post145_only)))]
pub(super) const INCIDENT_POST_IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v10/export145";
#[cfg(all(incident_focused_post145_only, not(incident_retry_post145_only)))]
pub(super) const INCIDENT_POST_IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v9/export145";
#[cfg(all(incident_timeout_post145_only, not(incident_focused_post145_only)))]
pub(super) const INCIDENT_POST_IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v8/export145";
const EXPORT: &str = "de6780b860b3467bae21fbd19176ca14";
const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1";
#[cfg(not(incident_post145_only))]
pub(super) const VERIFIER: &str =
    "2f0546bcf253a0f21740ff1e297fb18f7a62e37c2df7d72806c433cddf4cd57b";
#[cfg(incident_post145_only)]
pub(super) const VERIFIER: &str =
    "eec3a8093b52f7dd3a87d508b3b09e34680f2a5d887343cf12df70621d99f8a0";
#[cfg(not(incident_post145_only))]
pub(super) const PIPELINE: &str =
    "30251e917ca0eb103aebd586556e235150e396a7354bb670b7bc1a44b83faa51";
#[cfg(incident_timer_post145_only)]
pub(super) const PIPELINE: &str =
    "0f29fd116ef54668698089c01f8cd50ffcf729b430e311bb90b989f4d5ad8e94";
#[cfg(all(incident_timeout_post145_only, not(incident_timer_post145_only)))]
pub(super) const PIPELINE: &str =
    "56bf2bf0937f1b90de8de0519c0a572b06a8ed62cb9e14bf9e9f0fa8021ed916";
#[cfg(all(incident_post145_only, not(incident_timeout_post145_only)))]
pub(super) const PIPELINE: &str =
    "8822f0ba8391ea0be3a5f6cb0970dd264352dcfe0b075efc536d915d2763787e";
#[cfg(not(incident_post145_only))]
const READER_COMMIT: &str = "ee55f614012585bc99e4ed7398a56758bde2664e";
#[cfg(incident_timer_post145_only)]
const READER_COMMIT: &str = "58709604dfa4c97336c2e1f6fac53b862ed6f17f";
#[cfg(all(incident_timeout_post145_only, not(incident_timer_post145_only)))]
const READER_COMMIT: &str = "eba5d1b596cd454811c466fde7a25a2ecb4b19ef";
#[cfg(all(incident_post145_only, not(incident_timeout_post145_only)))]
const READER_COMMIT: &str = "907c5b3c26837c75c5c62f76bb124ff4fd8fe642";
const ANCHORS: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch145-independent-boundary-metadata-20261106-v1";
const PARENT: &str = "Fnoa95TKZ1U419CubZrxYDtFnqadRmvM554FFi2xSizB";
const TERMINAL: &str = "4zqmYpqcustpx2BQ2gB6y7v1HsvZpPGeyaRKFEsbThum";

fn digest(v: &Value, key: &str) -> Result<String> {
    let hash = v[key].as_str().context("absent SHA-256")?;
    ensure!(custody::hex(hash, 64), "invalid {key} SHA-256");
    Ok(hash.to_owned())
}
pub(super) fn extraction(e: &Value, archive: &Path) -> Result<()> {
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
    terminal_for(UNIT, iid)
}
pub(super) fn terminal_for(unit: &str, iid: &str) -> Result<()> {
    let rows = capacity::run(
        "/usr/bin/journalctl",
        &[
            "--no-pager",
            "-ojson",
            "--output-fields=UNIT,INVOCATION_ID,MESSAGE_ID",
            "_PID=1",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={iid}"),
            "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
        ],
        "15",
    )?;
    ensure!(
        rows.lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .any(|v| v["UNIT"] == unit
                && v["INVOCATION_ID"] == iid
                && v["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"),
        "missing successful export termination"
    );
    Ok(())
}
pub(super) trait VerificationGuard {
    fn topology(&self) -> Result<()>;
    fn current(&self, needed: u64) -> Result<Value>;
    fn current_stopped(&self, needed: u64) -> Result<Value>;
    fn await_topology(&self) -> Result<()>;
    fn await_current(&self, needed: u64) -> Result<Value>;
}
macro_rules! implement_guard {
    ($guard:ty, $current_stopped:ident) => {
        impl VerificationGuard for $guard {
            fn topology(&self) -> Result<()> {
                <$guard>::topology(self)
            }
            fn current(&self, n: u64) -> Result<Value> {
                <$guard>::current(self, n)
            }
            fn current_stopped(&self, n: u64) -> Result<Value> {
                <$guard>::$current_stopped(self, n)
            }
            fn await_topology(&self) -> Result<()> {
                <$guard>::await_topology(self)
            }
            fn await_current(&self, n: u64) -> Result<Value> {
                <$guard>::await_current(self, n)
            }
        }
    };
}
implement_guard!(capacity::Fit, current);
#[cfg(incident145_only)]
implement_guard!(crate::incident_fit::Fit, current_stopped);
#[path = "lease_startup.rs"]
pub(super) mod lease_startup;

pub(super) fn run_child(
    command: &mut Command,
    fit: &impl VerificationGuard,
    lease: &source_lease::ReadLease,
) -> Result<()> {
    run_child_with_startup(command, fit, lease, false)
}

pub(super) fn run_child_with_startup(
    command: &mut Command,
    fit: &impl VerificationGuard,
    lease: &source_lease::ReadLease,
    waits_for_lease_census: bool,
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
        let sample_and_resume = |deadline| -> Result<()> {
            let sample = while_stopped(pid, ticks, deadline, || {
                lease.check()?;
                fit.topology()?;
                fit.current_stopped(0)
            })?;
            ensure!(
                unsafe { libc::kill(pid.try_into()?, libc::SIGCONT) } == 0,
                "resume guarded verifier"
            );
            println!("{} epoch145 verification guard {}", custody::now()?, sample);
            Ok(())
        };
        if waits_for_lease_census {
            let deadline = Instant::now() + Duration::from_secs(90);
            lease_startup::wait_for_lease_stop(&child, deadline)?;
            sample_and_resume(deadline)?;
        }
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
            // A scheduled refresh freezes the child and checks a fresh fit
            // before resuming it. Skip the redundant live census on that tick.
            let wait = last.elapsed() >= Duration::from_secs(30)
                || match fit.current(0) {
                    Ok(_) => false,
                    Err(e)
                        if e.is::<capacity::GuardInFlight>()
                            || e.is::<capacity::Reprice>()
                            || (cfg!(continuity145_only) && e.is::<peer_terminal::Pending>()) =>
                    {
                        true
                    }
                    Err(e) => return Err(e),
                };
            if wait {
                if let Err(e) = freeze(pid) {
                    if child.try_wait()?.is_some_and(|s| s.success()) {
                        return lease.check();
                    }
                    return Err(e);
                }
                sample_and_resume(Instant::now() + Duration::from_secs(90))?;
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
    fit: &impl VerificationGuard,
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
    #[cfg(not(incident_post145_only))]
    let (full, seal, built, test, current) = {
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
        (full, seal, built, test, current)
    };
    #[cfg(incident_post145_only)]
    let (full, seal, built, test, current) = (
        bound(
            &root.join("current-reader-tools-v2/verify_archive"),
            "eec3a8093b52f7dd3a87d508b3b09e34680f2a5d887343cf12df70621d99f8a0",
        ),
        bound(
            &root.join("current-reader-tools-v2/deployment-seal-receipt.json"),
            "ea311a5af72af43e09d092bcd4a02582106bbc5e678bb2173cbbb8e0d7dd24fc",
        ),
        bound(
            &root.join("current-reader-tools-v2/build-proof.json"),
            "5a28798a19f694028b748fec0f222cf654b3e2de464706d24e7c106259cccbd4",
        ),
        if cfg!(incident_timer_post145_only) {
            bound(&Path::new(capacity::RUNTIME).join("fast-range-residency-20261121-v1/archive-publication-58709604/native-results.json"),
                  "d1a49d01c795a48728005fa72b1a4c9ab578977159a1e0f8c3b4fc3f44f13b9b")
        } else if cfg!(incident_timeout_post145_only) {
            bound(&Path::new(capacity::RUNTIME).join("public-rseek-reconnect-20261121-v1/archive-reader-1d1c4ea175b049c8a6487bc2cb3d1bde/fixtures/native-results.json"),"2e4f273f8fa04cf3438af5fdc23c19c1e3032c2619493e0e318d2ad21d83157a")
        } else {
            bound(
                &root.join("current-reader-tools-v2/native-results.json"),
                "eff17d9c60a6a2fdfacd750841a78f4f7eeddde7c3687b961bfb5b862b6a7019",
            )
        },
        if cfg!(incident_timer_post145_only) {
            bound(&Path::new(capacity::RUNTIME).join("fast-range-residency-20261121-v1/archive-publication-58709604/ARCHIVE_QUALIFIED.json"),
                  "8c233be38a9f6943bbf9efb4eb861e8d80fbb0c3b685d2ff6b08f746dce52989")
        } else if cfg!(incident_timeout_post145_only) {
            bound(&Path::new(capacity::RUNTIME).join("public-rseek-reconnect-20261121-v1/archive-reader-1d1c4ea175b049c8a6487bc2cb3d1bde/ARCHIVE_QUALIFIED.json"),"433a9607c0e8d56461709caecf2a112aa75048ca5ac085bb2923af842e15115b")
        } else {
            bound(
                &root.join("current-reader-tools-v2/reader-equivalence.json"),
                "bf45b73e14acd383d23ac4088b28c94db98c0fee095d83d9be06c766bbbe1f61",
            )
        },
    );
    let proof = custody::json(&current, true)?;
    let (commit, build_key, seal_key) = if cfg!(incident_timeout_post145_only) {
        (
            "source_commit",
            "new_pipeline_evidence",
            "new_pipeline_seal",
        )
    } else {
        ("branch_commit", "actual_current_build", "seal")
    };
    ensure!(proof[commit] == READER_COMMIT, "current pipeline build");
    #[cfg(incident_timeout_post145_only)]
    ensure!(
        proof["schema"] == "horizon-shared-current-archive-reader-transition-v1"
            && proof["remote_mutations"] == false
            && proof["full_verifier"] == json!(full)
            && proof["complete_build_evidence"] == json!(built)
            && proof["native_fixture"] == json!(test),
        "current release and full verifier artifacts changed"
    );
    let pipe: Bound = serde_json::from_value(proof["pipeline"].clone())?;
    ensure!(pipe.sha256 == PIPELINE, "unqualified plugin");
    for key in [build_key, seal_key] {
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
    #[cfg(incident_post145_only)]
    let qualified = {
        let (directory, package, proof) = if cfg!(incident_timer_post145_only) {
            (
                "fast-range-residency-20261121-v1/production-reader-v1",
                "082893fdc45288721911818fd77f8b8db043122b27dd0b4fe596eb274213f42d",
                "c715952c42ac45b2ebce0a104fee239ff0e5374e18ca2613a569a8f4e91bc36a",
            )
        } else if cfg!(incident_timeout_post145_only) {
            (
                "public-rseek-reconnect-20261121-v1/production-reader-v1",
                "b76a3860a7c7d890e7405417a0848cc62575d7b501bdc5789502ef29b570af07",
                "432f57f077e6b82632d3bae94b000bd9a42751c9a3bab7ee20cb69c3b73fd471",
            )
        } else {
            (
                "epoch166-retry10-delivery-20261121-v1/qualified-reader",
                "25106ce6590af4022c0d0c4e25a50762c178215bd797973b719b68059cd8e3e0",
                "89dba1fa9e7d73581e0c1e81ef2d12a8c7bd9bc98f4259943f79caa6197a9486",
            )
        };
        let directory = Path::new(capacity::RUNTIME).join(directory);
        let seal = bound(&directory.join("deployment-seal-receipt.json"), package);
        let item = bound(&directory.join("qualification.json"), proof);
        let deployment = custody::json(&seal, true)?;
        let accepted = custody::json(&item, true)?;
        ensure!(
            deployment["destination"] == json!(directory)
                && deployment["members"]
                    .as_array()
                    .is_some_and(|entries| entries
                        .iter()
                        .any(|m| m["name"] == "qualification.json" && m["sha256"] == item.sha256))
                && accepted["schema"] == "horizon-current-reader-main-acceptance-v1"
                && accepted["reader_commit"] == READER_COMMIT
                && accepted["pipeline"] == json!(pipe)
                && accepted["full_verifier"] == json!(full)
                && accepted["minimum_thread_stack_bytes"] == 67_108_864
                && accepted["source_artifact_correspondence_accepted"] == true
                && accepted["full_and_plugin_capabilities_accepted"] == true,
            "shared full reader acceptance changed"
        );
        #[cfg(incident_timer_post145_only)]
        {
            let pair = bound(
                &Path::new(capacity::RUNTIME).join("fast-range-residency-20261121-v1/archive-publication-58709604/ordinary/QUALIFIED.json"),
                "cd357ec5b130887d41961aa7803acb50e833bdbc2dd1f8ebba23252a87b5d3a4",
            );
            let paired = custody::json(&pair, true)?;
            ensure!(
                paired["reader"] == json!(item)
                    && paired["threads"] == 1
                    && paired["slot_count"] == 432000
                    && paired["uploader"]
                        == json!({"path":root.join("uploader-tools/jetstreamer-r2"), "sha256":super::publication::UPLOADER}),
                "paid archive reader and uploader fixture changed"
            );
        }
        item
    };
    #[cfg(not(incident_post145_only))]
    let qualified = {
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
        qualified
    };
    Ok((full, pipe, qualified))
}

#[cfg(incident_v5j_post145_only)]
pub(super) use v5j_publication::semantic_owner as fixture_semantic_owner;

#[cfg(all(incident_fixture_post145_only, not(incident_v5j_post145_only)))]
pub(super) fn fixture_semantic_owner(export: &str) -> Result<()> {
    let package = Path::new(INCIDENT_POST_IMAGE).parent().unwrap();
    let (_, seal) = publication::frozen_json(&package.join("deployment-seal-receipt.json"))?;
    let (proof, build) = publication::frozen_json(&package.join("build-proof.json"))?;
    ensure!(
        seal["destination"] == json!(package)
            && seal["members"].as_array().is_some_and(|members| members
                .iter()
                .any(|m| m["name"] == "build-proof.json"
                    && m["mode"] == "0444"
                    && m["sha256"] == proof.sha256)),
        "post build is outside the sealed deployment"
    );
    let progress: Bound = serde_json::from_value(build["prior_phase"].clone())?;
    ensure!(
        progress.path
            == package
                .parent()
                .unwrap()
                .join(if cfg!(incident_v7c_post145_only) {
                    "V5F_RETRY1_ACTUAL_ADVANCING_WORKER.json"
                } else {
                    "V5F_ACTUAL_ADVANCING_WORKER.json"
                }),
        "different semantic worker proof"
    );
    let worker = custody::json(&progress, true)?;
    let state = Path::new(BASE).join("state");
    if cfg!(incident_v7c_post145_only) {
        let failed = "50af3d8ab5da47e8bdc2828feab53908";
        ensure!(
            export != failed
                && build["retry_failure"] == json!({"path":state.join(failed).join("failed.json"),
                    "sha256":"38d828362fed1910cc60c605200380576c165168738dbf00520ce2b2522a0fcd"})
                && build["retry_start"] == json!({"path":state.join(failed).join("recovery-started.json"),
                    "sha256":"3dd15e821b9972e3f7f69f787d585bbe86fd9898ec1df5e8e5d08cab14231bb8"}),
            "different V5F same-image retry predecessor"
        );
    }
    ensure!(
        custody::hex(export, 32)
            && export != "a99ed8b51e8a482b805b8a36a11b2700"
            && worker["invocation_id"] == export
            && worker["start"] == build["semantic_start"]
            && worker["manager"] == build["semantic_manager"]
            && worker["start"]["path"] == json!(state.join(export).join("recovery-started.json"))
            && build["old_failure"]
                == json!({"path":state.join("a99ed8b51e8a482b805b8a36a11b2700/failed.json"),
                "sha256":"da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43"}),
        "promoted epoch does not belong to the sealed V5F generation"
    );
    Ok(())
}

pub fn full(fleet: Bound, sha: &str, joint: bool) -> Result<()> {
    let image = if cfg!(incident_post145_only) {
        PathBuf::from(INCIDENT_POST_IMAGE)
    } else if joint {
        joint::IMAGE.into()
    } else if cfg!(materialized145_only) {
        PathBuf::from(materialized::IMAGE)
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
    let export = if cfg!(materialized145_only) {
        materialized::completion_owner()?
    } else {
        EXPORT.into()
    };
    if joint && cfg!(partial145_only) {
        ensure!(
            export == joint::RECOVERY,
            "unexpected recovered export owner"
        );
    }
    #[cfg(incident_fixture_post145_only)]
    fixture_semantic_owner(&export)?;
    terminal(&export)?;
    let completed = Path::new(BASE).join("state").join(&export);
    let done = custody::binding(&completed.join("complete.json"))?;
    let d = custody::evidence(&done)?;
    ensure!(
        d["iid"] == export
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
            && c["actor_iid"] == export
            && c["r2_mutations"] == false,
        "export completion changed"
    );
    let archive = Path::new(OUTPUT).join("epoch-145.jet");
    let e = &c["extraction"];
    extraction(e, &archive)?;
    let expected = digest(e, "archive_sha256")?;
    let provenance = digest(e, "expected_output_provenance_sha256")?;
    let identity = custody::frozen_identity(&archive)?;
    let alloc = custody::evidence(&custody::binding(
        &Path::new(BASE)
            .join("state")
            .join(EXPORT)
            .join("allocated.json"),
    )?)?;
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
    #[cfg(not(incident_post145_only))]
    let (fit, first) = {
        let fit = capacity::capture_phase(&fleet, joint || cfg!(continuity145_only))?;
        fit.await_topology()?;
        let first = fit.await_current(0)?;
        (fit, first)
    };
    source_lease::arm_break_signal()?;
    let lease = source_lease::ReadLease::acquire(
        &archive,
        source_lease::FileIdentity::from(&fs::symlink_metadata(&archive)?),
    )?;
    #[cfg(incident_post145_only)]
    let (fit, first) = {
        let fit = incident_fit::Fit::capture(&fleet)?;
        fit.await_topology()?;
        let first = fit.await_current(0)?;
        (fit, first)
    };
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
      "origin_url":"git@github-matt-vaultic:vaultic-win/jetstreamer.git","reader_commit":READER_COMMIT,
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
        "current_branch_qualification":qualified.sha256,"r2_mutations":false}))?,
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
    #[cfg(incident_post145_only)]
    #[test]
    #[ignore = "requires the native root-owned current reader and its positive/negative fixtures"]
    fn current_full_and_plugin_use_the_same_qualified_plan_as_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let (full, plugin, plan) = native_tools(Path::new(ROOT), dir.path()).unwrap();
        assert_eq!(full.sha256, VERIFIER);
        assert_eq!(plugin.sha256, PIPELINE);
        assert_eq!(
            plan.sha256,
            if cfg!(incident_timer_post145_only) {
                "c715952c42ac45b2ebce0a104fee239ff0e5374e18ca2613a569a8f4e91bc36a"
            } else if cfg!(incident_timeout_post145_only) {
                "432f57f077e6b82632d3bae94b000bd9a42751c9a3bab7ee20cb69c3b73fd471"
            } else {
                "89dba1fa9e7d73581e0c1e81ef2d12a8c7bd9bc98f4259943f79caa6197a9486"
            }
        );
    }
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

#[cfg(incident_v5j_post145_only)]
#[path = "v5j_publication.rs"]
mod v5j_publication;
