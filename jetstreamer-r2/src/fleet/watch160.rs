//! Exact 160 child ownership in existing watchers, never a coordinator-as-worker claim.
use super::*;
pub(crate) const FULL: &str = "jetstreamer-horizon-audit-epochs101-181-v4.service";
pub(crate) const PLUGIN: &str =
    "jetstreamer-horizon-plugin-receipt-watcher-shard-c-v4-fsync.service";
pub(crate) const UPLOAD: &str = watch198::UPLOAD;
fn profile(
    phase: &str,
    unit: &str,
) -> Option<(
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
)> {
    match (phase, unit) {
        ("full-verification", FULL) => Some((
            "2612e3bb8fe4415b804532ee87d46ea3",
            "199885",
            "/usr/local/lib/jetstreamer/horizon-parallel-audit-20260926-v6/verify_horizon_range.sh",
            "a64fed21248715b2214292ea961a82afc5367a34b337d35afdbbc48d62c04bed",
            "/usr/local/lib/jetstreamer/horizon-parallel-audit-20260926-v6/verify_archive",
            "51bb4a90dcac0a2475b46b2820470c3a53a0a541720a233dac288934cc864336",
        )),
        ("plugin-verification", PLUGIN) => Some((
            "89b072dea9cd4167881d060c571be6cf",
            "200268",
            "/usr/local/lib/jetstreamer/horizon-plugin-receipt-watcher-20261001-v1/watch_horizon_plugin_progressive.sh",
            "2b0202515b166ccdf131e86dc66a26b3e461805d56352fe02c5e9bd28be18890",
            "/usr/local/lib/jetstreamer/horizon-plugin-merged-main-20260930-v1/horizon_pipeline",
            "9f4abe27011b04d0c33cb3e24d0d9bc14dbce9f46528f22c4bde367af97a7070",
        )),
        ("upload-readback", UPLOAD) => Some((
            "e4e455fbd455483282107652ca37b83d",
            "3283422",
            "/usr/local/lib/jetstreamer/horizon-epoch198-uploader-transition-20261021-v1/upload-progressive.zsh",
            "a0b1fba9a9e456532da9a73e121fd0b4eb7c3e7bc0c8923393b6b3d611419150",
            "/usr/local/lib/jetstreamer/horizon-r2-rust-20261017-v3-auth-only/jetstreamer-r2",
            "7b21414c1c105cefb18f5bf3ca8bb96759c14c529ea42232a70835bdc864b990",
        )),
        _ => None,
    }
}
pub(crate) fn namespace(phase: &str, unit: &str) -> bool {
    profile(phase, unit).is_some()
}
fn matches(phase: &str, exe: &str, args: &[&str], worker: &str) -> bool {
    let archive = "/home/sol/horizon/epoch-160.jet";
    if exe == "/usr/bin/sha256sum" {
        return phase != "upload-readback"
            && args.len() == 3
            && args[1] == "--"
            && args[2] == archive;
    }
    if exe != worker {
        return false;
    }
    match phase {
        "full-verification" => {
            args == [
                worker,
                archive,
                "--full",
                "--internal-full",
                "--threads",
                "10",
            ]
        }
        "plugin-verification" => {
            args == [
                worker,
                "160:160",
                "/home/sol/horizon",
                "--threads",
                "16",
                "--verify-only",
            ]
        }
        "upload-readback" => {
            args == [
                worker,
                "sync",
                "/home/sol/horizon",
                "--epochs",
                "160-160",
                "--receipt-directory",
                "/home/sol/.jetstreamer-private/r2-receipts",
                "--legacy-part-size-mib",
                "5",
                "--concurrency",
                "4",
            ]
        }
        _ => false,
    }
}
pub(crate) fn child_start(phase: &str, current: &Value) -> Result<Option<u64>> {
    let name = current["Id"].as_str().context("160 watcher unit")?;
    let (iid, pid, script, script_sha, worker, worker_sha) =
        profile(phase, name).context("foreign 160 watcher")?;
    ensure!(
        current["InvocationID"] == iid
            && current["MainPID"] == pid
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["ExecStart"]
                .as_str()
                .is_some_and(|s| s.contains(script)),
        "160 watcher owner changed"
    );
    watch198::immutable(script, script_sha)?;
    let legacy = phase == "plugin-verification";
    if legacy {
        // Observe the unchanged, already-running legacy deployment without
        //chmod/restart. A new immutable byte-identical witness plus stable
        //root-owned0755 source hashes bracket the process-identity scan. This
        //is metadata ownership evidence, never runtime/publication promotion.
        watch198::immutable(
            "/usr/local/lib/jetstreamer/horizon-epoch160-public-fleet-reader-20261022-v2/legacy-horizon-pipeline",
            worker_sha,
        )?;
        legacy_pipeline(worker, worker_sha)?;
    } else {
        watch198::immutable(worker, worker_sha)?;
    }
    let found = watch198::scan_children(phase, current, worker, matches)?;
    if legacy {
        legacy_pipeline(worker, worker_sha)?;
    }
    Ok(found)
}
fn legacy_pipeline(path: &str, sha: &str) -> Result<()> {
    ensure!(
        path == "/usr/local/lib/jetstreamer/horizon-plugin-merged-main-20260930-v1/horizon_pipeline"
            && sha == "9f4abe27011b04d0c33cb3e24d0d9bc14dbce9f46528f22c4bde367af97a7070",
        "foreign legacy 160 pipeline"
    );
    let p = Path::new(path);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o755
            && p.canonicalize()? == p,
        "legacy 160 pipeline ownership changed"
    );
    // Use the bounded streaming executable hasher, not a JSON-sized buffer.
    watch198::legacy160_member(path, sha)?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationPlan {
    schema: String,
    output: PathBuf,
    not_before_unix_seconds: u64,
    expires_unix_seconds: u64,
}
pub(crate) fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        (a.len() == 7 || (a.len() == 8 && a[7] == "--check-only"))
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: observe-public-160 PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    for (path, sha, limit) in [
        (fs::read_link("/proc/self/exe")?, a[6].as_str(), 128 << 20),
        (PathBuf::from(&a[2]), a[4].as_str(), 1 << 20),
    ] {
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o222 == 0
                && path.canonicalize()? == path,
            "unsealed 160 public observer input"
        );
        ensure!(
            hex_lower(&Sha256::digest(read_stable_bounded(
                &path,
                limit,
                "160 public observer"
            )?)) == sha,
            "160 public observer hash differs"
        );
    }
    let p: ObservationPlan = serde_json::from_slice(&read_stable_bounded(
        Path::new(&a[2]),
        1 << 20,
        "160 public plan",
    )?)?;
    ensure!(
        p.schema == "jetstreamer-epoch160-public-observation-plan-v1"
            && p.output
                == Path::new(
                    "/var/lib/jetstreamer/horizon-epoch160-public-observation-20261022-v1/proof.json"
                )
            && p.not_before_unix_seconds > 0
            && p.expires_unix_seconds
                .checked_sub(p.not_before_unix_seconds)
                .is_some_and(|n| n > 0 && n <= 1800),
        "foreign 160 public observation plan"
    );
    super::super::resource_audit::private_directory(p.output.parent().unwrap())?;
    ensure!(!p.output.try_exists()?, "160 public observation exists");
    if a.len() == 8 {
        println!(
            "160 public observation inputs valid; no sample, ownership capture, archive or R2 mutation"
        );
        return Ok(());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        (p.not_before_unix_seconds..=p.expires_unix_seconds).contains(&now),
        "160 public observation outside window"
    );
    let receipt = "/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1-import/destination-ae2f530244e391ea343ca338abe7f4673c52fd4bc8814369fd5234d07a8db1e1/evidence/archive-batches/destination-000000000000fc00-0000000011520001/batch-1d55b64d3ba6c3e284b16ffe07ddd1ff6ecec09f7f0e6b85452b5520c3676ad3.json";
    let bytes = read_stable_bounded(Path::new(receipt), 1 << 20, "160 canonical import")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes))
            == "628e3525ec55ecaf7bcbade1c5a26d4afe6fe948a203f73de28a571a6bf40815",
        "160 canonical import receipt changed"
    );
    let imported: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        imported["epochs"] == json!([160]) && imported["outcome"]["kind"] == "committed",
        "160 canonical import uncommitted"
    );
    let m = fs::symlink_metadata("/home/sol/horizon/epoch-160.jet")?;
    ensure!(
        m.is_file()
            && m.uid() == 1001
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() == 148095631232
            && m.ino() == 99942496
            && m.dev() == 64512,
        "160 canonical archive identity differs"
    );
    let sidecar = read_stable_bounded(
        Path::new("/home/sol/horizon/epoch-160.jet.sha256"),
        256,
        "160 canonical checksum",
    )?;
    ensure!(
        sidecar
            == b"35897b5dcd00c2b36d143a21fe759be7ef5315f0912eb530dc36acad6013cdcc  epoch-160.jet\n",
        "160 canonical checksum differs"
    );
    let mut owners = Vec::new();
    let mut actual = 0;
    for (phase, name) in [
        ("full-verification", FULL),
        ("plugin-verification", PLUGIN),
        ("upload-readback", UPLOAD),
    ] {
        let before = unit(name)?;
        let start = child_start(phase, &before)?;
        ensure!(unit(name)? == before, "160 watcher changed during capture");
        actual += usize::from(start.is_some());
        owners.push(json!({"phase":phase,"unit":before,"actual_child_start_millis":start}));
    }
    ensure!(
        actual > 0,
        "160 has no actual verifier/upload child yet; no active claim fabricated"
    );
    super::super::cohort198_finalization::write_observation(
        &p.output,
        &json!({"schema":"jetstreamer-epoch160-public-observation-v1","observed_unix_seconds":now,"observer_sha256":a[6],"plan":a[2],"plan_sha256":a[4],"import_receipt":receipt,"import_receipt_sha256":"628e3525ec55ecaf7bcbade1c5a26d4afe6fe948a203f73de28a571a6bf40815","archive_path":"/home/sol/horizon/epoch-160.jet","archive_bytes":m.len(),"archive_inode":m.ino(),"owners":owners,"archive_hash_performed":false,"new_resource_samples":0,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false}),
    )?;
    println!("{}", p.output.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn other_epochs_or_live_coordinators_cannot_borrow160_children() {
        for (phase, unit) in [
            ("full-verification", FULL),
            ("plugin-verification", PLUGIN),
            ("upload-readback", UPLOAD),
        ] {
            let worker = profile(phase, unit).unwrap().4;
            assert!(!matches(phase, "/usr/bin/bash", &[worker], worker));
            assert!(!matches(
                phase,
                "/usr/bin/sha256sum",
                &["sha256sum", "--", "/home/sol/horizon/epoch-198.jet"],
                worker
            ));
        }
        let worker = profile("full-verification", FULL).unwrap().4;
        assert!(matches(
            "full-verification",
            worker,
            &[
                worker,
                "/home/sol/horizon/epoch-160.jet",
                "--full",
                "--internal-full",
                "--threads",
                "10"
            ],
            worker
        ));
        assert!(matches(
            "plugin-verification",
            "/usr/bin/sha256sum",
            &["sha256sum", "--", "/home/sol/horizon/epoch-160.jet"],
            "other"
        ));
        assert!(!namespace("upload-readback", FULL));
        assert!(!matches(
            "upload-readback",
            "/usr/bin/sha256sum",
            &["sha256sum", "--", "/home/sol/horizon/epoch-160.jet"],
            worker
        ));
    }
}
