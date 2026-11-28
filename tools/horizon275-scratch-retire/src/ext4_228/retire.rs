//! Release the exact original image after independent authenticated restoration.
use super::*;
use crate::selective_accounts::record;
use std::ffi::CString;
use std::time::{SystemTime, UNIX_EPOCH};

const STATE: &str = "/var/lib/jetstreamer/horizon228-original-ext4-retirement-v1";
const ISSUER: &str = "/run/horizon292-300-finite-v205-a1/issuer.lock";
const LOOP_BACKING: &str = "/sys/class/block/loop6/loop/backing_file";
const CUSTODY_KEY_INODE: u64 = 98_094_588;
const PRODUCER_FILE: &str =
    "/run/systemd/system/horizon-qualify-228-demotion-root-tail-16d4b158-v1.service";
const PRODUCER_SHA: &str = "9c208b277b1d9f1b37f1e4387e5c42c60905bacaf9a721e06bf664a7cd9ae3bf";
const SPEC: &str = "/var/lib/jetstreamer/horizon228-native-root-tail-v166-a1/pilot/spec.json";
const SPEC_SHA: &str = "1fec8637c4dade8953caf503eaecb8230db84bb27971ac4772ff548766b40363";
const IMAGE_SCOPE: &str = "/var/lib/jetstreamer/horizon228-native-root-tail-v166-a1";
const ROUND_TRIP_UNIT: &str = "foundation-228-sparse-round-trip-v329.service";
const ROUND_TRIP_FILE: &str =
    "/run/systemd/transient/foundation-228-sparse-round-trip-v329.service";
const ROUND_TRIP_SHA: &str = "74f47b6ba10b5e79c45b6ab4e2797ee7e6d7a803a8722229e704c4da03ead4b9";

fn drained(unit: &str, required: &[&str]) -> Result<()> {
    let result = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "-p",
            "ActiveState,MainPID,ControlPID,ControlGroup,InvocationID,Result,Job,Restart,NRestarts,Triggers,TriggeredBy,RequiredBy,WantedBy,PartOf,BoundBy",
        ])
        .output()?;
    let stdout = std::str::from_utf8(&result.stdout)?;
    ensure!(
        result.status.success()
            && [
                "Job=",
                "Restart=no",
                "NRestarts=0",
                "MainPID=0",
                "ControlPID=0",
                "ControlGroup=",
                "Triggers=",
                "TriggeredBy=",
                "RequiredBy=",
                "WantedBy=",
                "PartOf=",
                "BoundBy="
            ]
            .iter()
            .chain(required)
            .all(|field| stdout.lines().any(|line| line == *field)),
        "{unit} is active, changed identity, or can be triggered"
    );
    Ok(())
}

fn no_readers() -> Result<Value> {
    closed()?;
    drained(UNIT, &["ActiveState=inactive"])?;
    let mut schedules = BTreeMap::new();
    for (scope, path) in [(TARGET, TARGET), (IMAGE_SCOPE, IMAGE), (LOOP, LOOP)] {
        let schedule = scheduled_census(Path::new(scope), Path::new(path))?;
        for entry in schedule["remaining"]
            .as_array()
            .context("invalid scheduled reference report")?
        {
            if path == IMAGE
                && entry["origin"] == ROUND_TRIP_FILE
                && entry["chain"] == json!([])
                && entry["sha256"] == ROUND_TRIP_SHA
                && entry["targets"] == json!([IMAGE])
            {
                drained(
                    ROUND_TRIP_UNIT,
                    &[
                        "ActiveState=failed",
                        "InvocationID=07fe215075a44c94884a4030e9911462",
                        "Result=exit-code",
                    ],
                )?;
                continue;
            }
            ensure!(
                entry["origin"] == PRODUCER_FILE
                    && entry["targets"] == json!([path])
                    && ((entry["chain"] == json!([]) && entry["sha256"] == PRODUCER_SHA)
                        || (entry["chain"] == json!([SPEC]) && entry["sha256"] == SPEC_SHA)),
                "unexpected scheduled epoch 228 reference: {entry}"
            );
        }
        schedules.insert(path, schedule);
    }
    let processes = references()?;
    ensure!(
        processes
            .values()
            .all(|scan| scan.inspected_processes > 0 && scan.references.is_empty()),
        "live image, mount, or loop consumer"
    );
    Ok(json!({"scheduled":schedules,"processes":processes}))
}

fn evidence(self_sha: &str, fit_sha: &str, remote_sha: &str) -> Result<(Value, u64, u64)> {
    let state = Path::new(STATE);
    let fit_ref = Binding {
        path: state.join("apply-fit.json"),
        sha256: fit_sha.into(),
    };
    let remote_ref = Binding {
        path: state.join("remote-recheck.json"),
        sha256: remote_sha.into(),
    };
    let fit: Value = read_bound(&fit_ref.path, &fit_ref.sha256, JSON_LIMIT)?;
    let remote: Value = read_bound(&remote_ref.path, &remote_ref.sha256, JSON_LIMIT)?;
    let original = value(&fit["report"])?;
    let fleet_path = fit["fleet"]["path"]
        .as_str()
        .context("missing current fleet path")?;
    let fleet_sha = fit["fleet"]["sha256"]
        .as_str()
        .context("missing current fleet hash")?;
    ensure!(
        Path::new(fleet_path).starts_with("/home/ubuntu/.codex/diagnostics")
            && Path::new(fleet_path)
                .file_name()
                .is_some_and(|name| name == "fleet.json"),
        "foreign capacity fleet path"
    );
    let fleet: Value = read_bound(Path::new(fleet_path), fleet_sha, JSON_LIMIT)?;
    let protected_bytes = fit["protected_disk_bytes"]
        .as_u64()
        .context("missing disk reservations")?;
    let sampled = fit["sampled_unix_seconds"]
        .as_u64()
        .context("missing capacity sample time")?;
    ensure!(
        fleet["first_epoch"] == 201
            && fleet["last_epoch"] == 300
            && fleet["inventory"]["anomalies"] == 0
            && fit["schema"] == "foundation-epoch228-current-fleet-no-extent-credit-v1"
            && fit["epoch"] == 228
            && fit["original_228_extent_credit_bytes"] == 0
            && fit["local_reclamation_credit_bytes"] == 0
            && fit["binary"]["sha256"] == self_sha
            && fit["available_now_bytes"]
                .as_u64()
                .context("missing available disk")?
                >= protected_bytes
            && fit["local_retirement_authorized"] == false
            && original["schema"] == "foundation-epoch228-ext4-retirement-precheck-v1"
            && original["image"] == IMAGE
            && original["image_stamp"]["inode"] == INODE
            && original["key_inode"] == CUSTODY_KEY_INODE,
        "no-extent-credit capacity proof differs"
    );
    let restore = clean_restore()?;
    let receipt = value(&restore["receipt"])?;
    let custody = value(&receipt["custody"])?;
    ensure!(
        remote["schema"] == "foundation-epoch228-ext4-authenticated-identity-recheck-v1"
            && remote["epoch"] == 228
            && remote["custody"] == receipt["custody"]
            && remote["object_key"] == receipt["object_key"]
            && remote["object_head"]["ContentLength"] == custody["manifest"]["length"]
            && remote["object_head"]["sha256"] == custody["manifest"]["sha256"]
            && remote["object_head"]["ETag"]
                == format!(
                    "\"{}\"",
                    custody["object_etag"].as_str().context("custody ETag")?
                )
            && remote["manifest_key"] == custody["manifest_key"]
            && remote["manifest_sha256"] == custody["manifest_sha256"]
            && remote["remote_mutations"] == false,
        "fresh authenticated holding identity differs from the restore"
    );
    Ok((
        json!({"fit":fit_ref,"remote_recheck":remote_ref,"restore":restore["receipt"],"image_stamp":original["image_stamp"]}),
        sampled,
        protected_bytes,
    ))
}

fn path_absent(path: &Path) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

pub(in crate::ext4_228) fn run(self_sha: &str, fit_sha: &str, remote_sha: &str) -> Result<()> {
    let issuer = open_regular(Path::new(ISSUER))?;
    let mode = issuer.metadata()?;
    ensure!(
        mode.uid() == 0
            && mode.gid() == 0
            && mode.mode() & 0o777 == 0o644
            && unsafe { libc::flock(issuer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "unsafe or busy replay issuer lock"
    );
    let _cycle = lock(CYCLE_LOCK)?;
    let _local = lock(LOCAL_LOCK)?;
    let state = Path::new(STATE);
    let meta = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o777 == 0o700,
        "unsafe epoch 228 retirement state"
    );
    let image = Path::new(IMAGE);
    let parent = image.parent().context("missing original image directory")?;
    let key = key_identity()?;
    ensure!(
        key.ino() == CUSTODY_KEY_INODE,
        "original proven custody key inode differs"
    );
    let (anchor, sampled, protected_bytes) = evidence(self_sha, fit_sha, remote_sha)?;
    let intent_path = state.join("retirement-intent.json");
    let done_path = state.join("retirement-completion.json");
    let pending = snapshot288::lookup_receipt(&intent_path)?;
    if let Some((_, prior)) = &pending {
        ensure!(
            prior["evidence"] == anchor && prior["image"] == IMAGE,
            "conflicting retirement intent"
        );
    }
    if let Some((reference, done)) = snapshot288::lookup_receipt(&done_path)? {
        ensure!(
            pending.is_some() && done["evidence"] == anchor && path_absent(image)?,
            "epoch 228 retirement receipt disagrees with local state"
        );
        println!("{}", serde_json::to_string(&reference)?);
        return Ok(());
    }
    let host_table = fs::read_to_string("/proc/1/mountinfo")?;
    let still_mounted = inherited_mount(&host_table, None)?.is_some();
    let mounts = mount_census(still_mounted)?;
    let consumers = no_readers()?;
    if !path_absent(image)? {
        ensure!(
            serde_json::to_value(Stamp::of(&image_identity()?)?)? == anchor["image_stamp"],
            "original image stamp differs"
        );
    } else {
        ensure!(
            pending.is_some() && !still_mounted && path_absent(Path::new(LOOP_BACKING))?,
            "original image absent before retirement"
        );
    }
    let intent = if let Some((prior, _)) = pending {
        prior
    } else {
        ensure!(
            still_mounted,
            "original host mount absent before retirement"
        );
        bound_loop()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let free = available(parent)?;
        ensure!(
            now.checked_sub(sampled).is_some_and(|age| age < 1800) && free >= protected_bytes,
            "reprice the fleet without crediting the source image before retirement"
        );
        record(
            &intent_path,
            &json!({
                "schema":"foundation-epoch228-ext4-retirement-intent-v1","epoch":228,
                "image":IMAGE,"loop":LOOP,"evidence":anchor,"self_sha256":self_sha,
                "mount_census":mounts,"consumers":consumers,"available_before_bytes":free,
                "original_extent_credit_bytes":0,"remote_mutations":false,"publication_authorized":false
            }),
        )?
    };

    if still_mounted {
        bound_loop()?;
        let target = CString::new(TARGET)?;
        if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error())
                .context("unmount the original host loop6 mount");
        }
    }
    let after_mounts = mount_census(false)?;
    ensure!(
        references()?
            .values()
            .all(|scan| scan.references.is_empty()),
        "a consumer acquired the old loop or backing image after unmount"
    );
    if !path_absent(Path::new(LOOP_BACKING))? {
        bound_loop()?;
        let detached = Command::new("/usr/sbin/losetup")
            .args(["--detach", LOOP])
            .output()?;
        ensure!(
            detached.status.success(),
            "loop detach failed: {}",
            String::from_utf8_lossy(&detached.stderr)
        );
    }
    ensure!(
        path_absent(Path::new(LOOP_BACKING))?,
        "loop detach did not release its backing"
    );
    mount_census(false)?;
    ensure!(
        identity(&key) == identity(&key_identity()?),
        "durable key changed"
    );
    if !path_absent(image)? {
        ensure!(
            serde_json::to_value(Stamp::of(&image_identity()?)?)? == anchor["image_stamp"],
            "original image changed before unlink"
        );
        fs::remove_file(image)?;
        File::open(parent)?.sync_all()?;
    }
    let before: Value = read_bound(&intent.path, &intent.sha256, JSON_LIMIT)?;
    let receipt = record(
        &done_path,
        &json!({
            "schema":"foundation-epoch228-ext4-retirement-completion-v1","epoch":228,
            "intent":intent,"evidence":anchor,"image":IMAGE,"loop_detached":true,
            "mount_census_after":after_mounts,"verified_allocated_bytes_removed":ALLOCATED,
            "available_before_bytes":before["available_before_bytes"],"available_after_bytes":available(parent)?,
            "recovery_key_retained":true,"original_extent_credit_bytes":0,
            "remote_mutations":false,"publication_authorized":false
        }),
    )?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}
