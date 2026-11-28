//! Closed native input telemetry. No entry progress or qualification evidence.
use super::*;

const VERIFY_226_UNIT: &str = "foundation-226-assembly-read-verification-v1.service";
const VERIFY_226_ROOT: &str = "/var/lib/jetstreamer/horizon226-postassembly-verification-v1";
const VERIFY_226_RUNNER: &str = "/var/lib/jetstreamer/horizon226-verification-fleet-v1/jetstreamer-r2";
const VERIFY_226_RELEASE: &str = "/var/lib/jetstreamer/horizon226-verification-fleet-v1/acceptance.json";

fn verification226_digest() -> Result<String> {
    let path = Path::new(VERIFY_226_RELEASE);
    let file = path.symlink_metadata()?;
    ensure!(
        path.canonicalize()? == path
            && file.is_file()
            && file.uid() == 0
            && file.nlink() == 1
            && file.mode() & 0o222 == 0
            && file.len() <= 64 * 1024,
        "unsafe epoch 226 verification resource release"
    );
    let release: Value = serde_json::from_reader(File::open(path)?)?;
    let runner = &release["runner"];
    ensure!(
        release["schema"] == "foundation-epoch226-verification-fleet-release-v1"
            && release["publication_authorized"] == false
            && runner["path"] == VERIFY_226_RUNNER,
        "foreign epoch 226 verification resource release"
    );
    let hash = runner["sha256"].as_str().context("missing epoch 226 verifier image digest")?;
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid epoch 226 verifier image digest"
    );
    Ok(hash.into())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeConfig {
    epoch: u64,
    unit: String,
    expected_invocation_id: String,
    main_pid: u32,
    scratch_path: PathBuf,
    executable: PathBuf,
    executable_sha256: String,
}
impl NativeConfig {
    fn validate(&self) -> Result<()> {
        if self.epoch == 288 {
            return holding288::validate(self);
        }
        let verifier_digest;
        let tuple = match self.epoch {
            226 if self.unit == VERIFY_226_UNIT => {
                verifier_digest = verification226_digest()?;
                (VERIFY_226_UNIT, VERIFY_226_ROOT, VERIFY_226_RUNNER, verifier_digest.as_str())
            }
            207 => (
                "archive-207-v1616-native-input-actual-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input207-v1616-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-207-native-input-optimized-3a2a-v1/native-input-test",
                "3a2a21e2987ee7c66785bfc64f1caaf4dfc000871ef692278ed83b3f63c65948",
            ),
            209 => (
                "archive-209-v1616-native-input-actual-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input209-v1616-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-209-native-input-optimized-v1/native-input-test",
                "5276276827aab0ccc809d123ebc8bf78cc7bfc36e6def550566059e70a8d4842",
            ),
            210 if self.unit == "archive-210-v1616-native-input-small-v2.service" => (
                "archive-210-v1616-native-input-small-v2.service",
                "/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-small-v2/scratch",
                "/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test",
                "2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6",
            ),
            210 => (
                "archive-210-v1616-native-input-actual-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test",
                "2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6",
            ),
            226 => (
                "horizon-qualify-226-checkpoint-continuation-assemble-v1.service",
                "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-226-assemble-v1",
                "/run/foundation-epoch226-release.y35rokj7/jetstreamer-node",
                "7e17105ad9429fccbeb53dcd38650adb3f469bc1d3fe797360afff2cc7379ded",
            ),
            257 => (
                "horizon-257-native-input-20261120-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1",
                "/var/lib/jetstreamer/horizon257-native-input-limited-20261120-v1/horizon257-native-input",
                "b8f52e2de7bf4f6232ea66137bb148bb6fb5b3342ce354379f4c237c70c39fce",
            ),
            266 if self.unit==capped266::UNIT => (
                capped266::UNIT,capped266::ROOT,capped266::HARNESS,capped266::HARNESS_SHA,
            ),
            266 => (
                "horizon-266-native-input-20261121-v1.service",
                "/run/horizon266-native-cold-v1",
                "/var/lib/jetstreamer/horizon266-native-input-tmpfs-20261121-v1/horizon266-native-input",
                "0c8aa52ede6067b16991e7d79d3c97f0aacf4de6158d5023c3114e39a40c1397",
            ),

            212 => (
                "horizon-212-native-input-20261120-v1.service",
                "/run/horizon212-native-cold-v1",
                "/var/lib/jetstreamer/horizon212-native-input-tmpfs-20261120-v1/horizon212-native-input",
                "73f93411831428c4f6cce9c625b817fb12a9746ca4901312ea0d8d820fc6ae9b",
            ),
            261 => (
                "horizon-261-native-input-20261120-v1.service",
                "/run/horizon261-native-cold-v1",
                "/var/lib/jetstreamer/horizon261-native-input-tmpfs-20261120-v1/horizon261-native-input",
                "b657cbaa98f543bb40fd9d01786ae0747ef30f4d2ed4727d81469461ea02d899",
            ),
            262 => (
                "horizon-262-native-input-20261126-v1.service",
                cold262::ROOT,
                "/var/lib/jetstreamer/horizon262-native-input-tmpfs-20261126-v1/horizon262-native-input",
                "6b14b1ec1a5a5db6b3fb4d216cb75d882366a77ef7bd913ce1926eda97939a72",
            ),
            265 => (
                "horizon-265-native-input-20261119-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1",
                "/var/lib/jetstreamer/horizon265-native-input-daa786c0-20261119-v1/horizon265-native-input",
                "0dbcd28e231f7158b88701666bff89cbdf36cc2033c0e5e826e54a8c87db76e9",
            ),
            211 => (
                "archive-211-v1616-native-input-actual-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input211-v1616-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-211-native-input-gated-20261119-v1/native-input-test",
                "2b1c0dd8b8cfcf0bbb80e52864c4b78a8348b1bc96dc97cbdfc4fee1094b8773",
            ),
            227 if self.unit == "horizon-native-input-227-v1625-small-v2.service" => (
                "horizon-native-input-227-v1625-small-v2.service",
                "/home/ubuntu/.jetstreamer-private/native-input227-v1625-full-small-v2/scratch",
                "/var/lib/jetstreamer/horizon-227-v1625-qualification-tests-df338451-v1/test-runner",
                "df3384519a64629e99aafadee46833ad2889a9c60c3255ac939bd444965578ef",
            ),
            227 if self.unit == "horizon-native-input-227-v1625-7a831420-v1.service" => (
                "horizon-native-input-227-v1625-7a831420-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input227-v1625-full-v1/scratch",
                "/var/lib/jetstreamer/horizon-227-v1625-qualification-tests-df338451-v1/test-runner",
                "df3384519a64629e99aafadee46833ad2889a9c60c3255ac939bd444965578ef",
            ),
            227 => (
                "horizon-native-input-227-capped-710f6523-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input227-v1620-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-227-native-test-optimized-v1/native-input-test",
                "1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3",
            ),
            228 if self.unit == "horizon-native-input-228-demotion-16d4b158-v1.service" => (
                "horizon-native-input-228-demotion-16d4b158-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input228-v1620-demotion-v1",
                "/var/lib/jetstreamer/horizon228-demotion-bank-9d2fd8d4-v158-v2-qualified/worker",
                "16d4b15881979bb7d65a0f49408580d4508b451a5953f35cbb60505d2e3cee00",
            ),
            228 => (
                "horizon-native-input-228-capped-1bfa8d51-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input228-v1620-capped-v1/scratch",
                "/var/lib/jetstreamer/horizon-228-native-test-optimized-d3fe9c72-v1/native-input-test",
                "d3fe9c72d542237c97504e0b680fe51e2eb4365b8a9343a631f9bc7512529827",
            ),
            _ => return Err(anyhow!("unknown native input telemetry profile")),
        };
        ensure!(
            self.unit == tuple.0
                && self.scratch_path == Path::new(tuple.1)
                && self.executable == Path::new(tuple.2)
                && self.executable_sha256 == tuple.3
                && self.main_pid > 1
                && self.main_pid <= i32::MAX as u32
                && is_invocation_id(&self.expected_invocation_id),
            "native input telemetry tuple differs"
        );
        Ok(())
    }
}
pub(super) fn validate(config: &Config) -> Result<()> {
    let mut epochs = std::collections::BTreeSet::new();
    for n in &config.native_input_diagnostics {
        n.validate()?;
        ensure!(
            epochs.insert(n.epoch),
            "duplicate native input telemetry owner"
        );
        for r in config.replays.iter().chain(&config.diagnostic_replays) {
            let (first, last) = r.range.split_once('-').unwrap_or((&r.range, &r.range));
            let (first, last) = (first.parse::<u64>()?, last.parse::<u64>()?);
            ensure!(
                !(first..=last).contains(&n.epoch)
                    && r.producer_unit != n.unit
                    && r.controller_unit != n.unit
                    && !n.scratch_path.starts_with(&r.scratch_path)
                    && !r.scratch_path.starts_with(&n.scratch_path),
                "native input telemetry overlaps replay owner"
            );
        }
    }
    Ok(())
}
fn identity(u: &UnitObservation, n: &NativeConfig) -> Result<()> {
    ensure!(
        u.main_pid == u64::from(n.main_pid)
            && u.unit == n.unit
            && u.invocation_id == n.expected_invocation_id
            && u.control_group == Path::new(&format!("/system.slice/{}", n.unit)),
        "native input MainPID/cgroup changed"
    );
    let rss = serde_json::to_value(&u.rss)?;
    if n.epoch == 288 {
        return holding288::processes(&rss, n);
    }
    ensure!(
        rss["census_stable"] == true
            && rss["error"].is_null()
            && rss["processes"].as_array().is_some_and(|v| {
                if n.unit == VERIFY_226_UNIT || matches!(n.epoch, 212 | 257 | 261 | 262 | 265 | 266) {
                    (1..=2).contains(&v.len())
                        && v.iter().filter(|p| p["pid"] == n.main_pid).count() == 1
                } else {
                    v.len() == 1 && v[0]["pid"] == n.main_pid
                }
            }),
        "native input RSS owner census changed"
    );
    Ok(())
}
fn mapped_at(n: &NativeConfig, proc_root: &Path, trusted_uid: u32) -> Result<Value> {
    mapped_image_at(
        &n.executable,
        &n.executable_sha256,
        n.main_pid,
        proc_root,
        trusted_uid,
    )
}
pub(super) fn mapped_image_at(
    executable: &Path,
    executable_sha256: &str,
    main_pid: u32,
    proc_root: &Path,
    trusted_uid: u32,
) -> Result<Value> {
    let expected = fs::symlink_metadata(executable)?;
    ensure!(
        executable.canonicalize()? == executable
            && expected.is_file()
            && expected.uid() == trusted_uid
            && expected.nlink() == 1
            && expected.mode() & 0o222 == 0
            && expected.len() <= 256 << 20,
        "unsafe native input executable"
    );
    let proc = proc_root.join(main_pid.to_string());
    ensure!(
        fs::read_link(proc.join("exe"))? == executable,
        "native input mapped path changed"
    );
    let mut exe = File::open(proc.join("exe"))?;
    let opened = exe.metadata()?;
    ensure!(
        expected.dev() == opened.dev() && expected.ino() == opened.ino(),
        "native input mapped inode differs"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut bytes = 0u64;
    loop {
        let count = exe.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        ensure!(bytes <= 256 << 20, "native input executable grew");
        hash.update(&buffer[..count]);
    }
    let after = fs::symlink_metadata(executable)?;
    ensure!(
        bytes == expected.len()
            && sha256_equal(&format!("{:x}", hash.finalize()), executable_sha256)
            && same_file(&expected, &after)
            && same_file(&expected, &exe.metadata()?)
            && fs::read_link(proc.join("exe"))? == executable,
        "native input executable changed"
    );
    let maps = fs::read_to_string(proc.join("maps"))?;
    let vmas = maps.lines().count();
    ensure!(vmas > 0 && vmas <= 3_500_000, "native input VMA bound");
    Ok(
        serde_json::json!({"pid":main_pid,"executable":executable,"sha256":executable_sha256,"vmas":vmas,"mapped_inode":expected.ino(),"mapped_device":expected.dev(),"historical_worker_claim":false}),
    )
}
fn sha256_equal(actual: &str, expected: &str) -> bool {
    actual == expected
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
}
fn bootstrap_child(n: &NativeConfig, u: &UnitObservation) -> Result<Value> {
    if n.unit != VERIFY_226_UNIT && !matches!(n.epoch, 212 | 257 | 261 | 262 | 265 | 266) {
        return Ok(Value::Null);
    }
    let rss = serde_json::to_value(&u.rss)?;
    let rows = rss["processes"]
        .as_array()
        .context("bootstrap process census")?;
    let mut children = rows.iter().filter(|p| p["pid"] != n.main_pid);
    let Some(child) = children.next() else {
        return Ok(Value::Null);
    };
    ensure!(children.next().is_none(), "bootstrap multiple children");
    let pid = u32::try_from(child["pid"].as_u64().context("bootstrap child PID")?)?;
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let before = fs::read_to_string(proc.join("stat"))?;
    let (_, tail) = before.rsplit_once(')').context("bootstrap child stat")?;
    let fields: Vec<_> = tail.split_whitespace().collect();
    ensure!(
        fields.len() >= 20
            && fields[1].parse::<u32>()? == n.main_pid
            && fields[19].parse::<u64>()?
                == child["start_ticks"]
                    .as_u64()
                    .context("bootstrap child start")?
            && fs::read_to_string(proc.join("cgroup"))?.trim()
                == format!("0::/system.slice/{}", n.unit),
        "bootstrap foreign child parent/start/cgroup"
    );
    let (worker, sha) = if n.unit == VERIFY_226_UNIT {
        match fs::read_link(proc.join("exe"))?.to_str() {
            Some("/var/lib/jetstreamer/horizon-public-images-f14f41d9-v1/verify_archive") => (
                "/var/lib/jetstreamer/horizon-public-images-f14f41d9-v1/verify_archive",
                "6848c44a949221f87312ed250b66f908e6e06e5f35e487b9ed7dad7333e1d773",
            ),
            Some("/var/lib/jetstreamer/horizon-public-images-f14f41d9-v1/horizon_pipeline") => (
                "/var/lib/jetstreamer/horizon-public-images-f14f41d9-v1/horizon_pipeline",
                "e6af181f8271836ce30655ff4bc8646761a882528ccd38d63d1113a6d31b095b",
            ),
            _ => return Err(anyhow!("unknown epoch 226 verification child image")),
        }
    } else if n.epoch == 212 {
        (
            "/var/lib/jetstreamer/horizon-singleton211-production-worker-1c89b6a214f9487b-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget",
            "1c89b6a214f9487babfd9dc121ade06037b371fbfcc3243f0e6ec67b6b961c41",
        )
    } else if n.epoch == 266 && n.unit==capped266::UNIT {
        (capped266::WORKER,capped266::WORKER_SHA)
    } else if n.epoch == 266 {
        ("/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-historical-worker-v1-8-11", "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae")
    } else {
        (
            "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15",
            "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4",
        )
    };
    let mut image = mapped_image_at(Path::new(worker), sha, pid, Path::new("/proc"), 0)?;
    // Stat includes changing resource counters; only parent and start identify the process.
    let after = fs::read_to_string(proc.join("stat"))?;
    let (_, tail) = after
        .rsplit_once(')')
        .context("bootstrap child stat after")?;
    let after_fields: Vec<_> = tail.split_whitespace().collect();
    ensure!(
        after_fields.len() >= 20
            && after_fields[1] == fields[1]
            && after_fields[19] == fields[19]
            && fs::read_to_string(proc.join("cgroup"))?.trim()
                == format!("0::/system.slice/{}", n.unit),
        "bootstrap child reused"
    );
    image["parent_pid"] = serde_json::json!(n.main_pid);
    image["start_ticks"] = child["start_ticks"].clone();
    Ok(image)
}
#[allow(dead_code)]
#[path="../../tools/horizon266-native-input/src/capped_site.rs"]
mod capped_site;
mod capped266 {
    use super::capped_site as site;
    pub(super) use site::{UNIT,ROOT,HARNESS,WORKER,WORKER_SHA};
    pub(super) const HARNESS_SHA:&str="72f04be574d9f81a0d0e610392ae9b53aed171029c2ea0e81bfd34a4919f9bac";
    mod profile {
        pub(super) use super::site::ROOT;
        pub(super) const FILESYSTEM:&str="/var/lib/jetstreamer";
    }
    mod tmpfs {
        pub(crate) const BYTES:u64=128<<30;
        pub(crate) const INODES:u64=1_048_576;
        const SOURCE:&str="horizon266-capped-native-cold";
        include!("../../tools/horizon261-native-input/src/mount.rs");
    }
    const ROOT_CAP:u64=124<<30;
    include!("native_tmpfs_sample.rs");
}

mod cold266 {
    mod profile {
        pub(super) const ROOT: &str = "/run/horizon266-native-cold-v1";
        pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
    }
    mod tmpfs {
        include!("../../tools/horizon266-native-input/src/original_tmpfs.rs");
    }
    const ROOT_CAP: u64 = 124 << 30;
    include!("native_tmpfs_sample.rs");
}

mod cold212 {
    mod profile {
        pub(super) const ROOT: &str = "/run/horizon212-native-cold-v1";
        pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
    }
    mod tmpfs {
        include!("../../tools/horizon212-native-input/src/tmpfs.rs");
    }
    const ROOT_CAP: u64 = 44 << 30;
    include!("native_tmpfs_sample.rs");
}
mod cold261 {
    mod profile {
        pub(super) const ROOT: &str = "/run/horizon261-native-cold-v1";
        pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
    }
    mod tmpfs {
        include!("../../tools/horizon261-native-input/src/tmpfs.rs");
    }
    const ROOT_CAP: u64 = 124 << 30;
    include!("native_tmpfs_sample.rs");
}
mod cold262 {
    pub(super) use profile::ROOT;
    mod profile {
        pub(crate) const ROOT: &str = "/run/horizon262-native-cold-v1";
        pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
    }
    mod tmpfs {
        include!("../../tools/horizon262-native-input/src/tmpfs.rs");
    }
    const ROOT_CAP: u64 = 124 << 30;
    include!("native_tmpfs_sample.rs");
}
fn scratch_sample(n: &NativeConfig) -> Result<(Value, u64)> {
    match n.epoch {
        266 if n.unit==capped266::UNIT => return capped266::sample(n),
        266 => return cold266::sample(n),
        212 => return cold212::sample(n),
        261 => return cold261::sample(n),
        262 => return cold262::sample(n),
        _ => (),
    }
    let scan = scan_scratch(&n.scratch_path)?;
    let used = scan.physical_bytes;
    Ok((serde_json::to_value(scan)?, used))
}
fn observe(n: &NativeConfig) -> Result<Value> {
    n.validate()?;
    let before = observe_unit(&n.unit, &n.expected_invocation_id)?;
    identity(&before, n)?;
    let mapped_before = mapped_at(n, Path::new("/proc"), 0)?;
    let child_before = bootstrap_child(n, &before)?;
    ensure!(
        n.scratch_path.canonicalize()? == n.scratch_path,
        "native input scratch noncanonical"
    );
    let root = fs::symlink_metadata(&n.scratch_path)?;
    let scratch_uid = if n.epoch == 288 { 0 } else { 1000 };
    ensure!(
        root.is_dir() && root.uid() == scratch_uid && root.mode() & 0o077 == 0,
        "native input scratch owner/mode differs"
    );
    let (first, first_bytes) = scratch_sample(n)?;
    let (second, second_bytes) = scratch_sample(n)?;
    let after = observe_unit(&n.unit, &n.expected_invocation_id)?;
    identity(&after, n)?;
    let mapped_after = mapped_at(n, Path::new("/proc"), 0)?;
    let child_after = bootstrap_child(n, &after)?;
    let end = fs::symlink_metadata(&n.scratch_path)?;
    ensure!(
        root.dev() == end.dev()
            && root.ino() == end.ino()
            && n.scratch_path.canonicalize()? == n.scratch_path
            && stable_unit(&before, &after)
            && before.main_pid == after.main_pid,
        "native input owner/root changed during sample"
    );
    let b = serde_json::to_value(&before.rss)?;
    let a = serde_json::to_value(&after.rss)?;
    let starts = |v: &Value| -> Result<std::collections::BTreeMap<u64, u64>> {
        v["processes"]
            .as_array()
            .context("native process census")?
            .iter()
            .map(|p| {
                Ok((
                    p["pid"].as_u64().context("native PID")?,
                    p["start_ticks"].as_u64().context("native start")?,
                ))
            })
            .collect()
    };
    ensure!(
        starts(&b)? == starts(&a)?
            && mapped_before["mapped_inode"] == mapped_after["mapped_inode"]
            && mapped_before["mapped_device"] == mapped_after["mapped_device"]
            && child_before["pid"] == child_after["pid"]
            && child_before["mapped_inode"] == child_after["mapped_inode"]
            && child_before["mapped_device"] == child_after["mapped_device"],
        "native process identity changed"
    );
    Ok(
        serde_json::json!({"range":format!("{}-{}",n.epoch,n.epoch),"resource_only":true,"native_input_diagnostic":true,
        "controller_before":before,"producer_before":before,"controller_after":after,"producer_after":after,
        "native_main_before":mapped_before,"native_main_after":mapped_after,"native_child_before":child_before,"native_child_after":child_after,"scratch_path":n.scratch_path,
        "scratch_measurement_method":if matches!(n.epoch, 212 | 261 | 262 | 266) {"dedicated tmpfs superblock"} else {"two race-tolerant non-symlink-following physical-block scans"},
        "scratch_pass_1":first,"scratch_pass_2":second,"conservative_observed_physical_bytes":first_bytes.max(second_bytes),
        "invocation_binding_stable":true,"useful_work":{"sufficient_for_rates":false,"entry_progress_observed":false},
        "entry_replay":false,"native_input_qualified":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}

#[path = "native_input_holding288.rs"]
mod holding288;
fn row(n: &NativeConfig, result: Result<Value>) -> Value {
    let (status, observation, error) = match result {
        Ok(v) => ("observed", Some(v), None),
        Err(e) => ("unavailable", None, Some(format!("{e:#}"))),
    };
    serde_json::json!({"range":format!("{}-{}",n.epoch,n.epoch),"producer_unit":n.unit,"expected_producer_invocation_id":n.expected_invocation_id,
        "scratch_path":n.scratch_path,"native_resource_only":true,"status":status,"observation":observation,"error":error,
        "ordinary_replay_claim":false,"entry_replay":false,"publication_authorized":false,"r2_mutations":false})
}
pub(super) fn sample(configs: &[NativeConfig]) -> Vec<Value> {
    configs.iter().map(|n| row(n, observe(n))).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn config() -> NativeConfig {
        serde_json::from_value(serde_json::json!({"epoch":227,"unit":"horizon-native-input-227-capped-710f6523-v1.service","expected_invocation_id":"a".repeat(32),"main_pid":42,"scratch_path":"/home/ubuntu/.jetstreamer-private/native-input227-v1620-capped-v1/scratch","executable":"/var/lib/jetstreamer/horizon-227-native-test-optimized-v1/native-input-test","executable_sha256":"1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3"})).unwrap()
    }
    #[test]
    fn epoch226_assembly_accepts_only_the_workerless_assembler_tuple() {
        let mut n = config();
        n.epoch = 226;
        n.unit = "horizon-qualify-226-checkpoint-continuation-assemble-v1.service".into();
        n.scratch_path = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-226-assemble-v1".into();
        n.executable = "/run/foundation-epoch226-release.y35rokj7/jetstreamer-node".into();
        n.executable_sha256 = "7e17105ad9429fccbeb53dcd38650adb3f469bc1d3fe797360afff2cc7379ded".into();
        n.validate().unwrap();
        let unavailable = row(&n, Err(anyhow!("assembler ended")));
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["ordinary_replay_claim"], false);
        n.unit = "horizon-qualify-226-checkpoint-continuation-extract-v3.service".into();
        assert!(n.validate().is_err());
    }
    #[test]
    fn native257_owns_only_its_registered_bootstrap_tuple() {
        let good = json!({"epoch":257,"unit":"horizon-257-native-input-20261120-v1.service","expected_invocation_id":"a".repeat(32),
            "main_pid":42,"scratch_path":"/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1",
            "executable":"/var/lib/jetstreamer/horizon257-native-input-limited-20261120-v1/horizon257-native-input",
            "executable_sha256":"b8f52e2de7bf4f6232ea66137bb148bb6fb5b3342ce354379f4c237c70c39fce"});
        let n: NativeConfig = serde_json::from_value(good.clone()).unwrap();
        n.validate().unwrap();
        for (key, value) in [
            ("epoch", json!(265)),
            ("unit", json!("other")),
            ("main_pid", json!(1)),
            ("expected_invocation_id", json!("")),
            ("scratch_path", json!("/tmp")),
            ("executable", json!("/worker")),
            ("executable_sha256", json!("c".repeat(64))),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        let unavailable = row(&n, Err(anyhow!("owner unavailable")));
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["entry_replay"], false);
        assert_eq!(unavailable["ordinary_replay_claim"], false);
    }
    #[test]
    fn capped_epoch266_keeps_its_own_worker_root_and_harness() {
        let mut row:NativeConfig=serde_json::from_value(json!({"epoch":266,"unit":capped266::UNIT,"expected_invocation_id":"a".repeat(32),"main_pid":42,"scratch_path":capped266::ROOT,"executable":capped266::HARNESS,"executable_sha256":capped266::HARNESS_SHA})).unwrap();
        row.validate().unwrap();
        row.scratch_path="/run/horizon266-native-cold-v1".into();
        assert!(row.validate().is_err());
        row.scratch_path=capped266::ROOT.into();
        row.unit="horizon-266-native-input-20261121-v1.service".into();
        assert!(row.validate().is_err());
    }

    #[test]
    fn native266_owns_only_its_registered_bootstrap_tuple() {
        let good = json!({"epoch":266,"unit":"horizon-266-native-input-20261121-v1.service","expected_invocation_id":"a".repeat(32),
            "main_pid":42,"scratch_path":"/run/horizon266-native-cold-v1",
            "executable":"/var/lib/jetstreamer/horizon266-native-input-tmpfs-20261121-v1/horizon266-native-input",
            "executable_sha256":"0c8aa52ede6067b16991e7d79d3c97f0aacf4de6158d5023c3114e39a40c1397"});
        let n: NativeConfig = serde_json::from_value(good.clone()).unwrap();
        n.validate().unwrap();
        for (key, value) in [
            ("epoch", json!(265)),
            ("unit", json!("other")),
            ("main_pid", json!(1)),
            ("expected_invocation_id", json!("")),
            ("scratch_path", json!("/tmp")),
            ("executable", json!("/worker")),
            ("executable_sha256", json!("c".repeat(64))),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        let unavailable = row(&n, Err(anyhow!("owner unavailable")));
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["entry_replay"], false);
        assert_eq!(unavailable["ordinary_replay_claim"], false);
    }

    #[test]
    fn native212_owns_only_its_registered_bootstrap_tuple() {
        let good = json!({"epoch":212,"unit":"horizon-212-native-input-20261120-v1.service","expected_invocation_id":"a".repeat(32),
            "main_pid":42,"scratch_path":"/run/horizon212-native-cold-v1",
            "executable":"/var/lib/jetstreamer/horizon212-native-input-tmpfs-20261120-v1/horizon212-native-input",
            "executable_sha256":"73f93411831428c4f6cce9c625b817fb12a9746ca4901312ea0d8d820fc6ae9b"});
        let n: NativeConfig = serde_json::from_value(good.clone()).unwrap();
        n.validate().unwrap();
        for (key, value) in [
            ("epoch", json!(265)),
            ("unit", json!("other")),
            ("main_pid", json!(1)),
            ("expected_invocation_id", json!("")),
            ("scratch_path", json!("/tmp")),
            ("executable", json!("/worker")),
            ("executable_sha256", json!("c".repeat(64))),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        let unavailable = row(&n, Err(anyhow!("owner unavailable")));
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["entry_replay"], false);
        assert_eq!(unavailable["ordinary_replay_claim"], false);
    }
    #[test]
    fn native261_owns_only_its_registered_bootstrap_tuple() {
        let good = json!({"epoch":261,"unit":"horizon-261-native-input-20261120-v1.service","expected_invocation_id":"a".repeat(32),
            "main_pid":42,"scratch_path":"/run/horizon261-native-cold-v1",
            "executable":"/var/lib/jetstreamer/horizon261-native-input-tmpfs-20261120-v1/horizon261-native-input",
            "executable_sha256":"b657cbaa98f543bb40fd9d01786ae0747ef30f4d2ed4727d81469461ea02d899"});
        let n: NativeConfig = serde_json::from_value(good.clone()).unwrap();
        n.validate().unwrap();
        for (key, value) in [
            ("epoch", json!(265)),
            ("unit", json!("other")),
            ("main_pid", json!(1)),
            ("expected_invocation_id", json!("")),
            ("scratch_path", json!("/tmp")),
            ("executable", json!("/worker")),
            ("executable_sha256", json!("c".repeat(64))),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        let unavailable = row(&n, Err(anyhow!("owner unavailable")));
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["entry_replay"], false);
        assert_eq!(unavailable["ordinary_replay_claim"], false);
    }

    #[test]
    fn native262_uses_its_own_bootstrap_tuple() {
        let mut config = serde_json::from_value::<NativeConfig>(json!({
            "epoch": 262,
            "unit": "horizon-262-native-input-20261126-v1.service",
            "expected_invocation_id": "a".repeat(32),
            "main_pid": 42,
            "scratch_path": "/run/horizon262-native-cold-v1",
            "executable": "/var/lib/jetstreamer/horizon262-native-input-tmpfs-20261126-v1/horizon262-native-input",
            "executable_sha256": "6b14b1ec1a5a5db6b3fb4d216cb75d882366a77ef7bd913ce1926eda97939a72"
        }))
        .unwrap();
        config.validate().unwrap();
        let unavailable = row(&config, Err(anyhow!("epoch 262 bootstrap inactive")));
        assert_eq!(unavailable["range"], "262-262");
        assert_eq!(unavailable["ordinary_replay_claim"], false);
        config.scratch_path = "/run/horizon261-native-cold-v1".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn native265_tuple_is_closed_and_unavailable_never_claims_replay() {
        let good = json!({"epoch":265,"unit":"horizon-265-native-input-20261119-v1.service","expected_invocation_id":"a".repeat(32),"main_pid":42,
            "scratch_path":"/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1",
            "executable":"/var/lib/jetstreamer/horizon265-native-input-daa786c0-20261119-v1/horizon265-native-input",
            "executable_sha256":"0dbcd28e231f7158b88701666bff89cbdf36cc2033c0e5e826e54a8c87db76e9"});
        let native: NativeConfig = serde_json::from_value(good.clone()).unwrap();
        native.validate().unwrap();
        for (key, value) in [
            ("epoch", json!(211)),
            ("main_pid", json!(1)),
            ("unit", json!("archive-265.service")),
            ("executable_sha256", json!("0".repeat(64))),
            ("scratch_path", json!("/tmp")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        let unavailable = row(&native, Err(anyhow!("native265 completed")));
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["ordinary_replay_claim"], false);
        assert_eq!(unavailable["entry_replay"], false);
    }
    #[test]
    fn native211_requires_gated_harness_and_its_own_complete_owner() {
        let good = json!({"epoch":211,"unit":"archive-211-v1616-native-input-actual-v1.service",
            "expected_invocation_id":"a".repeat(32),"main_pid":42,
            "scratch_path":"/home/ubuntu/.jetstreamer-private/native-input211-v1616-capped-v1/scratch",
            "executable":"/var/lib/jetstreamer/horizon-211-native-input-gated-20261119-v1/native-input-test",
            "executable_sha256":"2b1c0dd8b8cfcf0bbb80e52864c4b78a8348b1bc96dc97cbdfc4fee1094b8773"});
        let native: NativeConfig = serde_json::from_value(good.clone()).unwrap();
        native.validate().unwrap();
        for (key, value) in [
            ("epoch", json!(210)),
            (
                "unit",
                json!("archive-210-v1616-native-input-actual-v1.service"),
            ),
            (
                "scratch_path",
                json!("/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1/scratch"),
            ),
            (
                "executable",
                json!(
                    "/var/lib/jetstreamer/horizon-211-native-input-9b29f0ac-20261119-v1/native-input-test"
                ),
            ),
            (
                "executable_sha256",
                json!("b0b1185584680eae2b644c38a0c7d3f4240e0f4af392caa8e419300f2ac17df5"),
            ),
            ("main_pid", json!(1)),
            ("expected_invocation_id", json!("invalid")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        let unavailable = row(&native, Err(anyhow!("native211 owner terminated")));
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["observation"], Value::Null);
        for field in [
            "ordinary_replay_claim",
            "entry_replay",
            "publication_authorized",
            "r2_mutations",
        ] {
            assert_eq!(unavailable[field], false);
        }
    }
    #[test]
    fn epoch227_v1625_full_runner_never_borrows_v1620_or_diagnostic_telemetry() {
        let old = config();
        old.validate().unwrap();
        let mut new = config();
        new.unit = "horizon-native-input-227-v1625-7a831420-v1.service".into();
        new.scratch_path =
            "/home/ubuntu/.jetstreamer-private/native-input227-v1625-full-v1/scratch".into();
        new.executable =
            "/var/lib/jetstreamer/horizon-227-v1625-qualification-tests-df338451-v1/test-runner"
                .into();
        new.executable_sha256 =
            "df3384519a64629e99aafadee46833ad2889a9c60c3255ac939bd444965578ef".into();
        new.validate().unwrap();
        for (key, value) in [
            ("unit", json!(old.unit)),
            ("scratch_path", json!(old.scratch_path)),
            ("executable", json!(old.executable)),
            ("executable_sha256", json!(old.executable_sha256)),
            ("epoch", json!(210)),
            (
                "executable_sha256",
                json!("f9ca164d16ec78429293effeba083da122c1ae36c4de45ffc2ddba537b652400"),
            ),
        ] {
            let mut bad = serde_json::to_value(&new).unwrap();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn config_pins_complete_native_tuple_and_keeps_unavailable_rows_non_authorizing() {
        let n = config();
        n.validate().unwrap();
        for (key, value) in [
            ("epoch", serde_json::json!(207)),
            ("main_pid", serde_json::json!(1)),
            ("executable_sha256", serde_json::json!("a".repeat(64))),
            ("unit", serde_json::json!("other.service")),
        ] {
            let mut bad = serde_json::to_value(&n).unwrap();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        let r = row(&n, Err(anyhow!("native owner terminated")));
        assert_eq!(r["status"], "unavailable");
        assert_eq!(r["observation"], Value::Null);
        assert_eq!(r["entry_replay"], false);
    }
    #[test]
    fn native209_requires_its_own_complete_sealed_tuple() {
        let mut value = serde_json::to_value(config()).unwrap();
        value["epoch"] = serde_json::json!(209);
        value["unit"] = serde_json::json!("archive-209-v1616-native-input-actual-v1.service");
        value["scratch_path"] = serde_json::json!(
            "/home/ubuntu/.jetstreamer-private/native-input209-v1616-capped-v1/scratch"
        );
        value["executable"] = serde_json::json!(
            "/var/lib/jetstreamer/horizon-209-native-input-optimized-v1/native-input-test"
        );
        value["executable_sha256"] =
            serde_json::json!("5276276827aab0ccc809d123ebc8bf78cc7bfc36e6def550566059e70a8d4842");
        serde_json::from_value::<NativeConfig>(value.clone())
            .unwrap()
            .validate()
            .unwrap();
        let original = serde_json::to_value(config()).unwrap();
        for field in [
            "epoch",
            "unit",
            "scratch_path",
            "executable",
            "executable_sha256",
        ] {
            let mut wrong = value.clone();
            wrong[field] = original[field].clone();
            assert!(
                serde_json::from_value::<NativeConfig>(wrong)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn small_native_generations_preserve_closed_original_tuples() {
        for (epoch, unit, old_unit, root, executable, sha) in [
            (
                210,
                "archive-210-v1616-native-input-small-v2.service",
                "archive-210-v1616-native-input-actual-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-small-v2/scratch",
                "/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test",
                "2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6",
            ),
            (
                227,
                "horizon-native-input-227-v1625-small-v2.service",
                "horizon-native-input-227-v1625-7a831420-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input227-v1625-full-small-v2/scratch",
                "/var/lib/jetstreamer/horizon-227-v1625-qualification-tests-df338451-v1/test-runner",
                "df3384519a64629e99aafadee46833ad2889a9c60c3255ac939bd444965578ef",
            ),
        ] {
            let good = serde_json::json!({"epoch":epoch,"unit":unit,"expected_invocation_id":"a".repeat(32),
                "main_pid":42,"scratch_path":root,"executable":executable,"executable_sha256":sha});
            serde_json::from_value::<NativeConfig>(good.clone())
                .unwrap()
                .validate()
                .unwrap();
            for (field, value) in [
                ("unit", serde_json::json!(old_unit)),
                ("scratch_path", serde_json::json!("/different/scratch")),
                ("executable_sha256", serde_json::json!("a".repeat(64))),
                ("main_pid", serde_json::json!(1)),
            ] {
                let mut bad = good.clone();
                bad[field] = value;
                assert!(
                    serde_json::from_value::<NativeConfig>(bad)
                        .unwrap()
                        .validate()
                        .is_err(),
                    "{field}"
                );
            }
        }
    }
    #[test]
    fn native210_resource_registration_is_closed_to_its_own_harness_and_scratch() {
        let good = serde_json::json!({"epoch":210,"unit":"archive-210-v1616-native-input-actual-v1.service",
            "expected_invocation_id":"a".repeat(32),"main_pid":42,
            "scratch_path":"/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1/scratch",
            "executable":"/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test",
            "executable_sha256":"2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6"});
        let native: NativeConfig = serde_json::from_value(good.clone()).unwrap();
        native.validate().unwrap();
        for (key, value) in [
            ("epoch", serde_json::json!(209)),
            (
                "unit",
                serde_json::json!("archive-209-v1616-native-input-actual-v1.service"),
            ),
            (
                "scratch_path",
                serde_json::json!(
                    "/home/ubuntu/.jetstreamer-private/native-input209-v1616-capped-v1/scratch"
                ),
            ),
            (
                "executable",
                serde_json::json!(
                    "/var/lib/jetstreamer/horizon-209-native-input-optimized-v1/native-input-test"
                ),
            ),
            (
                "executable_sha256",
                serde_json::json!(
                    "5276276827aab0ccc809d123ebc8bf78cc7bfc36e6def550566059e70a8d4842"
                ),
            ),
            ("main_pid", serde_json::json!(1)),
            ("expected_invocation_id", serde_json::json!("invalid")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                serde_json::from_value::<NativeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        let unavailable = row(&native, Err(anyhow!("exact owner terminated")));
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["observation"], Value::Null);
        for field in [
            "ordinary_replay_claim",
            "entry_replay",
            "publication_authorized",
            "r2_mutations",
        ] {
            assert_eq!(unavailable[field], false);
        }
    }
    #[test]
    fn native228_demotion_requires_original_worker_and_scratch() {
        let mut n: NativeConfig = serde_json::from_value(serde_json::json!({
            "epoch":228,"unit":"horizon-native-input-228-demotion-16d4b158-v1.service",
            "expected_invocation_id":"a".repeat(32),"main_pid":42,
            "scratch_path":"/home/ubuntu/.jetstreamer-private/native-input228-v1620-demotion-v1",
            "executable":"/var/lib/jetstreamer/horizon228-demotion-bank-9d2fd8d4-v158-v2-qualified/worker",
            "executable_sha256":"16d4b15881979bb7d65a0f49408580d4508b451a5953f35cbb60505d2e3cee00"
        })).unwrap();
        n.validate().unwrap();
        n.unit="horizon-native-input-228-capped-1bfa8d51-v1.service".into();
        assert!(n.validate().is_err());
    }
    #[test]
    fn native228_cannot_use_the_neighboring_native_harness() {
        let mut n: NativeConfig = serde_json::from_value(serde_json::json!({
            "epoch":228,"unit":"horizon-native-input-228-capped-1bfa8d51-v1.service",
            "expected_invocation_id":"a".repeat(32),"main_pid":42,
            "scratch_path":"/home/ubuntu/.jetstreamer-private/native-input228-v1620-capped-v1/scratch",
            "executable":"/var/lib/jetstreamer/horizon-228-native-test-optimized-d3fe9c72-v1/native-input-test",
            "executable_sha256":"d3fe9c72d542237c97504e0b680fe51e2eb4365b8a9343a631f9bc7512529827"
        })).unwrap();
        n.validate().unwrap();
        let neighbor = config();
        n.executable = neighbor.executable;
        n.executable_sha256 = neighbor.executable_sha256;
        assert!(n.validate().is_err());
    }
    #[test]
    fn mapped_process_requires_exact_inode_hash_and_owner_without_worker_impersonation() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("native-input-test");
        fs::write(&exe, b"native").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o555)).unwrap();
        let proc = dir.path().join("proc/42");
        fs::create_dir_all(&proc).unwrap();
        symlink(&exe, proc.join("exe")).unwrap();
        fs::write(proc.join("maps"), "mapping\n").unwrap();
        let mut n = config();
        n.executable = exe;
        n.executable_sha256 = sha256(b"native");
        let uid = fs::metadata(&n.executable).unwrap().uid();
        assert_eq!(
            mapped_at(&n, &dir.path().join("proc"), uid).unwrap()["historical_worker_claim"],
            false
        );
        assert!(mapped_at(&n, &dir.path().join("proc"), uid + 1).is_err());
        n.executable_sha256 = "0".repeat(64);
        assert!(mapped_at(&n, &dir.path().join("proc"), uid).is_err());
    }
}
