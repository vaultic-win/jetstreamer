//! Exact-tree local retirement after an authenticated reserve stop. This path
//! cannot publish, delete an archive, launch replay, or contact remote storage.
use super::*;
use serde_json::json;
use std::{collections::BTreeMap, os::unix::ffi::OsStrExt};

type Bound = reserve_stop::Bound;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    run_uid: u32,
    run_directory: PathBuf,
    scratch: PathBuf,
    guard: reserve_stop::Evidence,
    fleet: Bound,
    node: Bound,
    bootstrap: Bound,
    preparation: Bound,
    node_build: Bound,
    operator_review: Bound,
    check_receipt: PathBuf,
    intent: PathBuf,
    completion: PathBuf,
    local_scratch_retirement_authorized: bool,
    preserve_partial_archive_and_inputs: bool,
    replay_launch_authorized: bool,
    archive_deletion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).context("cannot establish no-follow absence"),
    }
}

fn available_bytes(path: &Path) -> Result<u64> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut result = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), result.as_mut_ptr()) } == 0,
        "retirement statvfs failed"
    );
    let result = unsafe { result.assume_init() };
    result
        .f_bavail
        .checked_mul(result.f_frsize)
        .context("retirement free-space overflow")
}

fn bound_json(bound: &Bound) -> Result<Value> {
    let m = fs::symlink_metadata(&bound.path)?;
    ensure!(
        bound.path.is_absolute()
            && bound.path.canonicalize()? == bound.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0,
        "unsafe retirement evidence"
    );
    let b = read_stable_bounded(&bound.path, 4 * 1024 * 1024, "retirement evidence")?;
    ensure!(
        is_lower_hex(&bound.sha256, 64) && hex_lower(&Sha256::digest(&b)) == bound.sha256,
        "retirement evidence digest changed"
    );
    Ok(serde_json::from_slice(&b)?)
}

fn directory_for_uid(path: &Path, uid: u32) -> Result<fs::Metadata> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == uid
            && m.mode() & 0o077 == 0,
        "unsafe private directory: {}",
        path.display()
    );
    Ok(m)
}

fn directory_identity(path: &Path, uid: u32) -> Result<Value> {
    let m = directory_for_uid(path, uid)?;
    Ok(
        json!({"path":path,"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode() & 0o7777}),
    )
}

fn validate_scope(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-reserve-scratch-retirement-plan-v1"
            && p.epoch == p.guard.epoch
            && p.epoch > 0
            && p.local_scratch_retirement_authorized
            && p.preserve_partial_archive_and_inputs
            && !p.replay_launch_authorized
            && !p.archive_deletion_authorized
            && !p.remote_mutations
            && !p.r2_mutations,
        "invalid retirement scope or authority"
    );
    let relative = p
        .run_directory
        .strip_prefix("/home/sol/.jetstreamer-private")?;
    ensure!(
        p.scratch
            .as_os_str()
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(b)),
        "noncanonical scratch spelling"
    );
    let components: Vec<_> = relative.components().collect();
    ensure!(
        components.len() == 7
            && components[0]
                .as_os_str()
                .to_string_lossy()
                .starts_with(&format!("epoch{}-singleton-", p.epoch))
            && components[1].as_os_str() == "lane-a"
            && components[2].as_os_str() == "private"
            && components[3]
                .as_os_str()
                .to_string_lossy()
                .starts_with("destination-")
            && components[4].as_os_str() == "work"
            && components[5].as_os_str() == format!("root-cohort-{}-{}", p.epoch, p.epoch).as_str()
            && p.scratch == p.run_directory.join("scratch"),
        "not an exact singleton scratch layout"
    );
    let name = components[6]
        .as_os_str()
        .to_str()
        .context("invalid run name")?;
    let fields: Vec<_> = name.split('-').collect();
    ensure!(
        fields.len() == 3
            && fields[0] == "run"
            && fields[1..]
                .iter()
                .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
        "invalid run identity"
    );
    let outputs = [&p.check_receipt, &p.intent, &p.completion];
    ensure!(
        outputs
            .iter()
            .all(|v| v.is_absolute() && !v.starts_with(&p.run_directory))
            && outputs[0] != outputs[1]
            && outputs[1] != outputs[2]
            && outputs[0] != outputs[2]
            && outputs.iter().all(|v| v.parent() == p.intent.parent()),
        "unsafe retirement receipt paths"
    );
    Ok(())
}

fn validate_plan(p: &Plan) -> Result<()> {
    validate_scope(p)?;
    directory_for_uid(p.intent.parent().context("receipt parent missing")?, 0)?;
    Ok(())
}

fn file_proof(path: &Path, immutable: bool, uid: u32) -> Result<Value> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && (!immutable || m.mode() & 0o222 == 0),
        "unsafe retained file"
    );
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 8 * 1024 * 1024];
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    ensure!(
        identity(&m) == identity(&f.metadata()?) && regular_identity(path)? == identity(&m),
        "retained file changed while hashing"
    );
    Ok(
        json!({"path":path,"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"mode":m.mode() & 0o7777,
        "uid":m.uid(),"gid":m.gid(),"sha256":hex_lower(&hash.finalize())}),
    )
}

fn validate_run_owner(p: &Plan, intent: &Value, review: &Value, state_bytes: &[u8]) -> Result<()> {
    let producer_pid = intent["producer_sample"]["main_pid"]
        .as_u64()
        .context("original producer PID missing")?;
    let run_pid = p
        .run_directory
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.split('-').nth(1))
        .context("run PID missing")?
        .parse::<u64>()?;
    ensure!(
        producer_pid > 0
            && run_pid == producer_pid
            && review["run_directory"].as_str() == p.run_directory.to_str()
            && review["scratch"].as_str() == p.scratch.to_str()
            && review["cohort_state_sha256"] == hex_lower(&Sha256::digest(state_bytes)),
        "scratch generation is not the reviewed original stopped producer run"
    );
    Ok(())
}

fn preserved(p: &Plan) -> Result<Value> {
    let state_path = p.run_directory.join("cohort-state.json");
    let state_bytes = read_stable_bounded(&state_path, 65536, "cohort state")?;
    let state: Value = serde_json::from_slice(&state_bytes)?;
    let review = bound_json(&p.operator_review)?;
    let stop_intent = bound_json(&p.guard.intent)?;
    validate_run_owner(p, &stop_intent, &review, &state_bytes)?;
    ensure!(
        state
            == json!({"schema":"jetstreamer-root-cohort-run-v1","status":"running-private",
        "start_epoch":p.epoch,"end_epoch":p.epoch,"manifest_fingerprint":state["manifest_fingerprint"]})
            && state["manifest_fingerprint"].as_str().is_some_and(|v| v
                .strip_prefix("sha256:")
                .is_some_and(|s| is_lower_hex(s, 64)))
            && fs::symlink_metadata(&state_path)?.mode() & 0o777 == 0o600,
        "not an exact cursor-free cohort state"
    );
    let expected: BTreeSet<_> = ["archives", "inputs", "scratch", "cohort-state.json"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let actual: BTreeSet<_> = fs::read_dir(&p.run_directory)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow!("invalid run entry"))
        })
        .collect::<Result<_>>()?;
    ensure!(
        actual.is_subset(&expected)
            && ["archives", "inputs", "cohort-state.json"]
                .iter()
                .all(|n| actual.contains(*n)),
        "unexpected run member"
    );
    let archive_dir = p.run_directory.join("archives");
    let input_dir = p.run_directory.join("inputs");
    directory_for_uid(&archive_dir, p.run_uid)?;
    directory_for_uid(&input_dir, p.run_uid)?;
    let mut files = vec![file_proof(&state_path, false, p.run_uid)?];
    for directory in [&archive_dir, &input_dir] {
        let mut members: Vec<_> = fs::read_dir(directory)?
            .map(|e| Ok(e?.path()))
            .collect::<Result<_>>()?;
        members.sort();
        ensure!(
            members.len() <= 16,
            "retained artifact census exceeds bound"
        );
        if *directory == archive_dir {
            ensure!(
                members == vec![archive_dir.join(format!("epoch-{}.jet", p.epoch))],
                "not one partial singleton archive"
            );
        }
        for member in members {
            files.push(file_proof(&member, false, p.run_uid)?);
        }
    }
    let prep = bound_json(&p.preparation)?;
    let build = bound_json(&p.node_build)?;
    let node = file_proof(&p.node.path, true, 0)?;
    let bootstrap = file_proof(&p.bootstrap.path, true, 0)?;
    let package = p.node.path.parent().context("node package missing")?;
    let metadata = fs::symlink_metadata(package)?;
    ensure!(
        package.canonicalize()? == package
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0,
        "input package is not immutable"
    );
    let manifest_name = Path::new(
        prep["manifest"]["path"]
            .as_str()
            .context("preparation manifest missing")?,
    )
    .file_name()
    .context("manifest basename missing")?;
    let manifest = file_proof(&package.join(manifest_name), true, 0)?;
    let sums_path = package.join("SHA256SUMS");
    let sums_metadata = fs::symlink_metadata(&sums_path)?;
    ensure!(
        sums_metadata.uid() == 0 && sums_metadata.mode() & 0o222 == 0,
        "unsafe package checksum list"
    );
    let sums = read_stable_bounded(&sums_path, 65536, "package checksums")?;
    let mut hashes = BTreeMap::new();
    for line in std::str::from_utf8(&sums)?.lines() {
        let (sha, name) = line
            .split_once("  ")
            .context("malformed package checksum")?;
        ensure!(
            is_lower_hex(sha, 64)
                && !name.is_empty()
                && !name.contains('/')
                && hashes.insert(name, sha).is_none(),
            "unsafe or duplicate package checksum"
        );
    }
    for bound in [&p.node, &p.bootstrap, &p.preparation] {
        ensure!(
            hashes.get(
                bound
                    .path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("package name missing")?
            ) == Some(&bound.sha256.as_str()),
            "package checksum binding differs"
        );
    }
    ensure!(
        node["sha256"] == p.node.sha256
            && bootstrap["sha256"] == p.bootstrap.sha256
            && p.node.path.parent() == p.preparation.path.parent()
            && p.bootstrap.path.parent() == p.node.path.parent()
            && prep["schema"] == "jetstreamer-horizon-independent-singleton-preparation-v1"
            && prep["epoch"] == p.epoch
            && prep["parent"]["sha256"] == p.node.sha256
            && prep["bootstrap"]["sha256"] == p.bootstrap.sha256
            && prep["bootstrap"]["size"] == bootstrap["bytes"]
            && manifest["sha256"] == prep["manifest"]["sha256"]
            && prep["manifest"]["fingerprint"] == state["manifest_fingerprint"]
            && prep["replay_launch_authorized"] == false
            && prep["remote_mutations"] == false
            && prep["r2_mutations"] == false
            && build["schema"] == "jetstreamer-horizon-production-boundary-probe-build-v1"
            && build["source_commit"]
                .as_str()
                .is_some_and(|s| is_lower_hex(s, 40))
            && build["node_sha256"] == p.node.sha256
            && build["build"]["exit_code"] == 0
            && build["tests"]["failed"] == 0
            && build["tests"]["passed"].as_u64().is_some_and(|n| n > 0)
            && review["schema"] == "jetstreamer-reserve-bootstrap-restart-review-v1"
            && review["epoch"] == p.epoch
            && review["node_sha256"] == p.node.sha256
            && review["run_uid"] == p.run_uid
            && review["source_commit"] == build["source_commit"]
            && review["scratch_contains_replay_cursor"] == false
            && review["restarts_from_sealed_bootstrap"] == true
            && review["preserve_partial_archive_and_inputs"] == true,
        "bootstrap/node/review do not establish cursor-free restart"
    );
    Ok(
        json!({"run":directory_identity(&p.run_directory, p.run_uid)?,"archives_directory":directory_identity(&archive_dir, p.run_uid)?,
        "inputs_directory":directory_identity(&input_dir, p.run_uid)?,"files":files,"node":node,"bootstrap":bootstrap,
        "preparation":p.preparation,"node_build":p.node_build,"operator_review":p.operator_review}),
    )
}

fn census(p: &Plan) -> Result<BTreeMap<String, Value>> {
    let fleet = bound_json(&p.fleet)?;
    let recorded = fleet["recorded_unix_seconds"]
        .as_u64()
        .context("fleet time missing")?;
    let time = now()?;
    let sample = fleet::utc_seconds(
        fleet["sampled_at_utc"]
            .as_str()
            .context("fleet sample missing")?,
    )?;
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && sample <= recorded
            && recorded <= time
            && time - sample <= 1800
            && fleet["epochs"]
                .as_array()
                .context("fleet epochs missing")?
                .iter()
                .any(|e| e["epoch"] == p.epoch && e["state"] == "failed-needs-repair")
            && !fleet["active"]
                .as_array()
                .context("fleet active missing")?
                .iter()
                .any(|e| e["epoch"] == p.epoch),
        "fleet is stale or retirement epoch is active"
    );
    let names = fleet["unit_census"]
        .as_object()
        .context("fleet census missing")?
        .keys()
        .cloned()
        .collect();
    let current = fleet::census(
        &names,
        fleet["first_epoch"]
            .as_u64()
            .context("first epoch missing")?,
        fleet["last_epoch"].as_u64().context("last epoch missing")?,
    )?;
    ensure!(
        serde_json::to_value(&current)? == fleet["unit_census"],
        "fleet changed before scratch retirement"
    );
    p.guard.validate(&current, 0, time)?;
    for (name, _) in p.guard.owners() {
        inactive_status::no_pending_owner_trigger(
            &name,
            current[&name]["LoadState"] == "not-found",
        )?;
    }
    Ok(current)
}

fn boundary_reference(bytes: &[u8], target: &Path) -> bool {
    let needle = target.as_os_str().as_bytes();
    bytes.windows(needle.len()).enumerate().any(|(i, w)| {
        w == needle
            && (i + needle.len() == bytes.len()
                || b"/\0\n\r\t '\";|&()<>[]{}".contains(&bytes[i + needle.len()]))
    })
}

fn scan_references(root: &Path, target: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        for name in ["cmdline", "maps"] {
            match fs::read(entry.path().join(name)) {
                Ok(bytes) => ensure!(
                    !boundary_reference(&bytes, target),
                    "pid {pid} retains scratch in {name}"
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e).context("incomplete scratch process scan"),
            }
        }
        let mut links = vec![
            entry.path().join("cwd"),
            entry.path().join("root"),
            entry.path().join("exe"),
        ];
        match fs::read_dir(entry.path().join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    links.push(fd?.path());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e).context("incomplete scratch descriptor census"),
        }
        for link in links {
            match fs::read_link(link) {
                Ok(value) => {
                    let text = value.as_os_str().as_bytes();
                    let text = text.strip_suffix(b" (deleted)").unwrap_or(text);
                    ensure!(
                        !boundary_reference(text, target),
                        "pid {pid} retains scratch link"
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e).context("incomplete scratch process link scan"),
            }
        }
    }
    Ok(())
}

pub(crate) fn tree(path: &Path, uid: u32) -> Result<Value> {
    validate_mounts(&fs::read_to_string("/proc/self/mountinfo")?, path)?;
    let root = directory_for_uid(path, uid)?;
    let mut pending = vec![path.to_path_buf()];
    let (mut bytes, mut files, mut dirs) = (0u64, 0u64, 0u64);
    while let Some(path) = pending.pop() {
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.dev() == root.dev()
                && m.uid() == uid
                && (m.is_dir() || m.is_file())
                && (!m.is_file() || m.nlink() == 1),
            "scratch contains foreign filesystem, owner, link or special file"
        );
        bytes = bytes
            .checked_add(m.blocks().checked_mul(512).context("block overflow")?)
            .context("tree size overflow")?;
        if m.is_dir() {
            dirs += 1;
            for e in fs::read_dir(&path)? {
                pending.push(e?.path());
            }
        } else {
            files += 1;
        }
    }
    Ok(
        json!({"identity":directory_identity(path, uid)?,"physical_bytes":bytes,"regular_files":files,"directories":dirs}),
    )
}

fn validate_mounts(mountinfo: &str, target: &Path) -> Result<()> {
    for line in mountinfo.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() >= 10, "malformed mountinfo");
        // The exact approved target is ASCII without whitespace or backslashes;
        // escaped descendant names still have its unescaped directory prefix.
        ensure!(
            !Path::new(fields[4]).starts_with(target),
            "scratch contains a mount point"
        );
    }
    Ok(())
}

fn lifecycle_matches(prior: &Value, schema: &str, common: &Value, scratch: &Value) -> Result<()> {
    ensure!(
        prior["schema"] == schema && prior["common"] == *common && prior["scratch"] == *scratch,
        "retirement lifecycle binding changed"
    );
    Ok(())
}

fn read_receipt(path: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o077 == 0,
        "unsafe retirement receipt"
    );
    Ok(serde_json::from_slice(&read_stable_bounded(
        path,
        4 * 1024 * 1024,
        "retirement receipt",
    )?)?)
}

// A new fleet receipt can reconcile interruption recovery, but no destructive
// target, owner, preserved input, output path or authority bit may change.
fn scope_sha256(p: &Plan) -> Result<String> {
    let mut value = serde_json::to_value(p)?;
    value
        .as_object_mut()
        .context("plan is not an object")?
        .remove("fleet");
    Ok(hex_lower(&Sha256::digest(serde_json::to_vec(&value)?)))
}

fn validate_prior_plan(receipt: &Value, p: &Plan) -> Result<()> {
    let bound: Bound = serde_json::from_value(receipt["plan"].clone())?;
    let prior: Plan = serde_json::from_value(bound_json(&bound)?)?;
    ensure!(
        scope_sha256(&prior)? == scope_sha256(p)?,
        "prior plan changed destructive scope rather than only fresh fleet evidence"
    );
    Ok(())
}

pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        (args.len() == 7 || args.len() == 8 && args[7] == "--check-only")
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256",
        "usage: jetstreamer-r2 reserve-retire-scratch PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "scratch retirement requires root"
    );
    let mut exe = File::open("/proc/self/exe")?;
    let mut hash = Sha256::new();
    let mut b = vec![0u8; 1024 * 1024];
    loop {
        let n = exe.read(&mut b)?;
        if n == 0 {
            break;
        }
        hash.update(&b[..n]);
    }
    ensure!(
        is_lower_hex(&args[6], 64) && hex_lower(&hash.finalize()) == args[6],
        "retirement executable digest differs"
    );
    let bound = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let p: Plan = serde_json::from_value(bound_json(&bound)?)?;
    validate_plan(&p)?;
    let units = census(&p)?;
    let retained = preserved(&p)?;
    let common = json!({"scope_sha256":scope_sha256(&p)?,"tool_sha256":args[6],"epoch":p.epoch,"preserved":retained,"guard":p.guard,
        "replay_launch_authorized":false,"archive_deletion_authorized":false,"remote_mutations":false,"r2_mutations":false});
    if args.len() == 8 {
        ensure!(
            !present(&p.intent)? && !present(&p.completion)?,
            "retirement already has lifecycle evidence"
        );
        let measured = tree(&p.scratch, p.run_uid)?;
        scan_references(Path::new("/proc"), &p.scratch)?;
        ensure!(
            census(&p)? == units,
            "claims changed during check-only scan"
        );
        fleet::persist(
            &p.check_receipt,
            &json!({"schema":"jetstreamer-reserve-scratch-check-v1","plan":bound,"fleet":p.fleet,"common":common,
            "scratch":measured,"available_bytes":available_bytes(&p.run_directory)?,
            "recorded_unix_seconds":now()?,"check_only":true,"scratch_deleted":false}),
        )?;
        println!("{}", p.check_receipt.display());
        return Ok(());
    }
    let checked = read_receipt(&p.check_receipt)?;
    validate_prior_plan(&checked, &p)?;
    ensure!(
        checked["schema"] == "jetstreamer-reserve-scratch-check-v1"
            && checked["common"] == common
            && checked["check_only"] == true
            && checked["scratch_deleted"] == false,
        "check-only evidence changed"
    );
    if present(&p.completion)? {
        let completed = read_receipt(&p.completion)?;
        validate_prior_plan(&completed, &p)?;
        lifecycle_matches(
            &completed,
            "jetstreamer-reserve-scratch-completion-v1",
            &common,
            &checked["scratch"],
        )?;
        let intent = read_receipt(&p.intent)?;
        validate_prior_plan(&intent, &p)?;
        lifecycle_matches(
            &intent,
            "jetstreamer-reserve-scratch-intent-v1",
            &common,
            &checked["scratch"],
        )?;
        let intent_hash = hex_lower(&Sha256::digest(read_stable_bounded(
            &p.intent,
            4 * 1024 * 1024,
            "retirement intent",
        )?));
        ensure!(
            completed["scratch_deleted"] == true
                && completed["intent"].as_str() == p.intent.to_str()
                && completed["intent_sha256"] == intent_hash
                && !present(&p.scratch)?,
            "invalid prior completion"
        );
        println!("{}", p.completion.display());
        return Ok(());
    }
    if present(&p.intent)? {
        let intent = read_receipt(&p.intent)?;
        validate_prior_plan(&intent, &p)?;
        lifecycle_matches(
            &intent,
            "jetstreamer-reserve-scratch-intent-v1",
            &common,
            &checked["scratch"],
        )?;
    } else {
        ensure!(
            tree(&p.scratch, p.run_uid)? == checked["scratch"],
            "scratch changed after check-only evidence"
        );
        fleet::persist(
            &p.intent,
            &json!({"schema":"jetstreamer-reserve-scratch-intent-v1","plan":bound,"fleet":p.fleet,"common":common,
            "scratch":checked["scratch"],"available_bytes_before":available_bytes(&p.run_directory)?,"recorded_unix_seconds":now()?}),
        )?;
    }
    if present(&p.scratch)? {
        ensure!(
            directory_identity(&p.scratch, p.run_uid)? == checked["scratch"]["identity"],
            "scratch directory was replaced"
        );
        tree(&p.scratch, p.run_uid)?;
        scan_references(Path::new("/proc"), &p.scratch)?;
        ensure!(census(&p)? == units, "claims changed before deletion");
        ensure!(
            directory_identity(&p.scratch, p.run_uid)? == checked["scratch"]["identity"],
            "scratch directory was replaced before deletion"
        );
        fs::remove_dir_all(&p.scratch)?;
        File::open(&p.run_directory)?.sync_all()?;
    }
    ensure!(
        !present(&p.scratch)? && preserved(&p)? == retained && census(&p)? == units,
        "retained work or claims changed during retirement"
    );
    fleet::persist(
        &p.completion,
        &json!({"schema":"jetstreamer-reserve-scratch-completion-v1","plan":bound,"fleet":p.fleet,"common":common,
        "scratch":checked["scratch"],"intent":p.intent,
        "intent_sha256":hex_lower(&Sha256::digest(read_stable_bounded(&p.intent,4*1024*1024,"retirement intent")?)),
        "available_bytes_before":read_receipt(&p.intent)?["available_bytes_before"],
        "available_bytes_after":available_bytes(&p.run_directory)?,
        "recorded_unix_seconds":now()?,"scratch_deleted":true}),
    )?;
    println!("{}", p.completion.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        let bound = json!({"path":"/evidence.json","sha256":"a".repeat(64)});
        json!({"schema":"jetstreamer-reserve-scratch-retirement-plan-v1","epoch":185,"run_uid":1001,
            "run_directory":"/home/sol/.jetstreamer-private/epoch185-singleton-20261020-v1/lane-a/private/destination-abc/work/root-cohort-185-185/run-123-456",
            "scratch":"/home/sol/.jetstreamer-private/epoch185-singleton-20261020-v1/lane-a/private/destination-abc/work/root-cohort-185-185/run-123-456/scratch",
            "guard":{"epoch":185,"controller_unit":"controller.service","controller_invocation_id":"a".repeat(32),
                "producer_unit":"producer.service","producer_invocation_id":"b".repeat(32),"intent":bound,"completion":bound},
            "fleet":bound,"node":bound,"bootstrap":bound,"preparation":bound,"node_build":bound,"operator_review":bound,
            "check_receipt":"/var/lib/retire-test/check.json","intent":"/var/lib/retire-test/intent.json",
            "completion":"/var/lib/retire-test/completion.json","local_scratch_retirement_authorized":true,
            "preserve_partial_archive_and_inputs":true,"replay_launch_authorized":false,"archive_deletion_authorized":false,
            "remote_mutations":false,"r2_mutations":false})
    }

    #[test]
    fn guard_pid_and_review_pin_the_exact_scratch_generation_not_another_epoch_run() {
        let p: Plan = serde_json::from_value(fixture()).unwrap();
        let state = b"state";
        let intent = json!({"producer_sample":{"main_pid":123}});
        let review = json!({"run_directory":p.run_directory,"scratch":p.scratch,
            "cohort_state_sha256":hex_lower(&Sha256::digest(state))});
        validate_run_owner(&p, &intent, &review, state).unwrap();
        assert!(
            validate_run_owner(
                &p,
                &json!({"producer_sample":{"main_pid":124}}),
                &review,
                state
            )
            .is_err()
        );
        assert!(validate_run_owner(&p, &intent, &review, b"changed").is_err());
        for key in ["run_directory", "scratch", "cohort_state_sha256"] {
            let mut changed = review.clone();
            changed[key] = json!("other");
            assert!(validate_run_owner(&p, &intent, &changed, state).is_err());
        }
        let mut other: Plan = serde_json::from_value(fixture()).unwrap();
        other.run_directory.set_file_name("run-123-789");
        other.scratch = other.run_directory.join("scratch");
        assert!(validate_run_owner(&other, &intent, &review, state).is_err());
    }

    #[test]
    fn scope_is_an_exact_private_singleton_not_an_archive_or_broad_directory() {
        let good = fixture();
        validate_scope(&serde_json::from_value(good.clone()).unwrap()).unwrap();
        for (pointer, value) in [
            ("/scratch", json!("/home/sol")),
            ("/scratch", good["run_directory"].clone()),
            ("/epoch", json!(186)),
            ("/schema", json!("unqualified")),
            ("/run_directory", json!("/home/sol/.jetstreamer-private")),
            ("/run_directory", json!("/home/sol/horizon/run-123-456")),
            ("/intent", good["scratch"].clone()),
            ("/intent", good["completion"].clone()),
            ("/completion", json!("/different-parent/completion.json")),
        ] {
            let mut changed = good.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_scope(&serde_json::from_value(changed).unwrap()).is_err(),
                "{pointer}"
            );
        }
        let mut unknown = good;
        unknown["ignore_live_owner"] = json!(true);
        assert!(serde_json::from_value::<Plan>(unknown).is_err());
    }

    #[test]
    fn retirement_cannot_grant_other_mutation_or_replay_authority() {
        let good = fixture();
        for key in [
            "local_scratch_retirement_authorized",
            "preserve_partial_archive_and_inputs",
            "replay_launch_authorized",
            "archive_deletion_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut changed = good.clone();
            changed[key] = json!(!good[key].as_bool().unwrap());
            assert!(
                validate_scope(&serde_json::from_value(changed).unwrap()).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn process_references_distinguish_siblings_from_real_descendants() {
        let target = Path::new("/safe/scratch");
        for bytes in [
            b"/safe/scratch".as_slice(),
            b"/safe/scratch/file",
            b"x\0/safe/scratch\0",
            b"/safe/scratch (deleted)",
        ] {
            assert!(boundary_reference(bytes, target));
        }
        for bytes in [
            b"/safe/scratch-store8/file".as_slice(),
            b"/safe/scratch2",
            b"elsewhere",
        ] {
            assert!(!boundary_reference(bytes, target));
        }
    }

    #[test]
    fn nested_bind_mounts_and_malformed_mountinfo_block_retirement() {
        let target = Path::new("/safe/scratch");
        validate_mounts("1 2 0:1 / /safe rw - ext4 disk rw\n", target).unwrap();
        validate_mounts("1 2 0:1 / /safe/scratch-store8 rw - ext4 disk rw\n", target).unwrap();
        for text in [
            "1 2 0:1 / /safe/scratch rw - ext4 disk rw\n",
            "1 2 0:1 / /safe/scratch/child\\040name rw - ext4 disk rw\n",
            "malformed",
        ] {
            assert!(validate_mounts(text, target).is_err());
        }
    }

    #[test]
    fn synthetic_process_census_catches_commands_maps_descriptors_and_incomplete_reads() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("12345");
        fs::create_dir(&pid).unwrap();
        fs::create_dir(pid.join("fd")).unwrap();
        fs::write(pid.join("cmdline"), b"reader\0/safe/scratch/file\0").unwrap();
        fs::write(pid.join("maps"), b"").unwrap();
        let target = Path::new("/safe/scratch");
        assert!(scan_references(dir.path(), target).is_err());
        fs::write(pid.join("cmdline"), b"reader\0/safe/scratch-store8/file\0").unwrap();
        scan_references(dir.path(), target).unwrap();
        fs::write(pid.join("maps"), b"1234-5678 /safe/scratch/data\n").unwrap();
        assert!(scan_references(dir.path(), target).is_err());
        fs::write(pid.join("maps"), b"").unwrap();
        symlink("/safe/scratch/data", pid.join("fd/3")).unwrap();
        assert!(scan_references(dir.path(), target).is_err());
        fs::remove_file(pid.join("fd/3")).unwrap();
        symlink("/safe/scratch (deleted)", pid.join("cwd")).unwrap();
        assert!(scan_references(dir.path(), target).is_err());
        fs::remove_file(pid.join("cwd")).unwrap();
        fs::remove_file(pid.join("cmdline")).unwrap();
        fs::create_dir(pid.join("cmdline")).unwrap();
        assert!(scan_references(dir.path(), target).is_err());
    }

    #[test]
    fn a_dangling_symlink_is_not_successful_scratch_absence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scratch");
        assert!(!present(&path).unwrap());
        std::os::unix::fs::symlink("/missing-reserve-retirement-test-target", &path).unwrap();
        assert!(present(&path).unwrap());
        assert!(tree(&path, 0).is_err());
    }

    #[test]
    fn only_fresh_fleet_evidence_can_change_in_an_interrupted_retirement_plan() {
        let first: Plan = serde_json::from_value(fixture()).unwrap();
        let mut fresh = fixture();
        fresh["fleet"]["path"] = json!("/new-fleet.json");
        fresh["fleet"]["sha256"] = json!("b".repeat(64));
        assert_eq!(
            scope_sha256(&first).unwrap(),
            scope_sha256(&serde_json::from_value(fresh).unwrap()).unwrap()
        );
        for (pointer, value) in [
            ("/run_uid", json!(0)),
            ("/node/sha256", json!("c".repeat(64))),
            ("/intent", json!("/other-intent.json")),
            ("/guard/controller_invocation_id", json!("f".repeat(32))),
            ("/operator_review/sha256", json!("d".repeat(64))),
            ("/local_scratch_retirement_authorized", json!(false)),
        ] {
            let mut changed = fixture();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert_ne!(
                scope_sha256(&first).unwrap(),
                scope_sha256(&serde_json::from_value(changed).unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn interrupted_lifecycle_requires_the_exact_original_plan_tool_and_preserved_work() {
        let common = json!({"plan_sha256":"a".repeat(64),"tool_sha256":"b".repeat(64),"archive_deletion_authorized":false});
        let scratch = json!({"identity":{"device":1,"inode":2},"physical_bytes":4096});
        let intent = json!({"schema":"intent","common":common,"scratch":scratch});
        lifecycle_matches(&intent, "intent", &common, &scratch).unwrap();
        for (pointer, value) in [
            ("/common/plan_sha256", json!("c".repeat(64))),
            ("/common/tool_sha256", json!("d".repeat(64))),
            ("/scratch/identity/inode", json!(3)),
            ("/common/archive_deletion_authorized", json!(true)),
            ("/schema", json!("completion")),
        ] {
            let mut changed = intent.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(lifecycle_matches(&changed, "intent", &common, &scratch).is_err());
        }
    }

    #[test]
    #[ignore = "root-only exact file and scratch ownership qualification"]
    fn root_tree_audit_binds_identity_and_rejects_symlinks_without_deleting_anything() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "requires root");
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.path().join("appendvec");
        fs::write(&file, b"state").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let first = tree(dir.path(), 0).unwrap();
        assert_eq!(first["regular_files"], 1);
        assert_eq!(fs::read(&file).unwrap(), b"state");
        let proof = file_proof(&file, false, 0).unwrap();
        assert_eq!(proof["bytes"], 5);
        symlink("/tmp", dir.path().join("foreign")).unwrap();
        assert!(tree(dir.path(), 0).is_err());
        fs::remove_file(dir.path().join("foreign")).unwrap();
        fs::hard_link(&file, dir.path().join("alias")).unwrap();
        assert!(tree(dir.path(), 0).is_err());
    }
}
