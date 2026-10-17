use {
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        ffi::{CString, OsStr},
        fs::{self, File, OpenOptions},
        io::{self, Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
        path::{Path, PathBuf},
        process,
        time::{SystemTime, UNIX_EPOCH},
    },
};

const PLAN_SCHEMA: &str = "jetstreamer-sealed-deployment-plan-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-sealed-deployment-receipt-v1";
const MAX_PLAN_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    destination: PathBuf,
    members: Vec<MemberPlan>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberPlan {
    source: PathBuf,
    name: String,
    sha256: String,
    mode: u32,
}

#[derive(Debug)]
struct Arguments {
    plan: PathBuf,
    plan_sha256: String,
    self_sha256: String,
}

#[derive(Debug, Serialize)]
struct MemberReceipt {
    source: String,
    name: String,
    sha256: String,
    bytes: u64,
    mode: String,
}

#[derive(Debug, Serialize)]
struct Receipt {
    schema: &'static str,
    plan_sha256: String,
    sealer_sha256: String,
    destination: String,
    members: Vec<MemberReceipt>,
    created_unix_seconds: u64,
    publication_authorized: bool,
    replay_launch_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

fn usage(program: &str) -> String {
    format!("usage: {program} PLAN.json --plan-sha256 HEX --self-sha256 HEX")
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "jetstreamer-seal-deployment".to_string());
    let plan = arguments.next().ok_or_else(|| usage(&program))?;
    let flag = arguments.next().ok_or_else(|| usage(&program))?;
    if flag != OsStr::new("--plan-sha256") {
        return Err(usage(&program));
    }
    let plan_sha256 = arguments
        .next()
        .ok_or_else(|| usage(&program))?
        .into_string()
        .map_err(|_| "plan SHA-256 is not valid UTF-8".to_string())?;
    let self_flag = arguments.next().ok_or_else(|| usage(&program))?;
    if self_flag != OsStr::new("--self-sha256") {
        return Err(usage(&program));
    }
    let self_sha256 = arguments
        .next()
        .ok_or_else(|| usage(&program))?
        .into_string()
        .map_err(|_| "sealer SHA-256 is not valid UTF-8".to_string())?;
    if arguments.next().is_some() {
        return Err(usage(&program));
    }
    Ok(Arguments {
        plan: PathBuf::from(plan),
        plan_sha256,
        self_sha256,
    })
}

fn lowercase_sha256(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must contain 64 lowercase hex digits"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn identity(metadata: &fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

fn validate_member_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || matches!(
            name,
            "." | ".." | "SHA256SUMS" | "deployment-seal-receipt.json"
        )
    {
        return Err(format!("invalid deployment member name {name:?}"));
    }
    Ok(())
}

fn validate_plan(plan: &Plan) -> Result<(), String> {
    if plan.schema != PLAN_SCHEMA {
        return Err(format!("unsupported plan schema {:?}", plan.schema));
    }
    if !plan.destination.is_absolute() {
        return Err("destination must be absolute".to_string());
    }
    let leaf = plan
        .destination
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "destination must have a UTF-8 leaf name".to_string())?;
    validate_member_name(leaf)?;
    if plan.members.is_empty() {
        return Err("plan has no members".to_string());
    }
    let mut names = BTreeSet::new();
    for member in &plan.members {
        if !member.source.is_absolute() {
            return Err(format!("member source must be absolute: {}", member.name));
        }
        validate_member_name(&member.name)?;
        if !names.insert(member.name.as_str()) {
            return Err(format!(
                "duplicate deployment member name {:?}",
                member.name
            ));
        }
        lowercase_sha256(&member.sha256, &format!("{} SHA-256", member.name))?;
        if !matches!(member.mode, 0o444 | 0o555) {
            return Err(format!("member {} mode must be 0444 or 0555", member.name));
        }
    }
    Ok(())
}

fn open_regular_nofollow(path: &Path, max_bytes: Option<u64>) -> Result<(File, Identity), String> {
    let before =
        fs::symlink_metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
    if !before.is_file() || before.nlink() == 0 {
        return Err(format!("not a regular file: {}", path.display()));
    }
    if let Some(max_bytes) = max_bytes
        && before.size() > max_bytes
    {
        return Err(format!("file is too large: {}", path.display()));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("canonicalize {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!("path is not canonical: {}", path.display()));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("fstat {}: {error}", path.display()))?;
    if identity(&before) != identity(&opened) {
        return Err(format!("file changed while opening: {}", path.display()));
    }
    Ok((file, identity(&opened)))
}

fn read_plan(path: &Path, expected_sha256: &str) -> Result<(Plan, String), String> {
    lowercase_sha256(expected_sha256, "plan SHA-256")?;
    let (mut file, before) = open_regular_nofollow(path, Some(MAX_PLAN_BYTES))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read plan {}: {error}", path.display()))?;
    let observed = hex(&Sha256::digest(&bytes));
    if observed != expected_sha256 {
        return Err(format!(
            "plan SHA-256 mismatch: expected {expected_sha256}, observed {observed}"
        ));
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("restat plan {}: {error}", path.display()))?;
    if identity(&after) != before {
        return Err(format!("plan changed while reading: {}", path.display()));
    }
    let plan: Plan = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode plan {}: {error}", path.display()))?;
    validate_plan(&plan)?;
    Ok((plan, observed))
}

fn verify_running_executable(expected_sha256: &str) -> Result<String, String> {
    lowercase_sha256(expected_sha256, "sealer SHA-256")?;
    let mut executable = File::open("/proc/self/exe")
        .map_err(|error| format!("open running executable: {error}"))?;
    let metadata = executable
        .metadata()
        .map_err(|error| format!("fstat running executable: {error}"))?;
    if !metadata.is_file() {
        return Err("running executable is not a regular file".to_string());
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = executable
            .read(&mut buffer)
            .map_err(|error| format!("read running executable: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let observed = hex(&digest.finalize());
    if observed != expected_sha256 {
        return Err(format!(
            "sealer SHA-256 mismatch: expected {expected_sha256}, observed {observed}"
        ));
    }
    Ok(observed)
}

fn validate_parent(parent: &Path, expected_uid: u32, full_ancestry: bool) -> Result<(), String> {
    let mut current = parent;
    loop {
        let metadata = fs::symlink_metadata(current)
            .map_err(|error| format!("stat destination ancestry {}: {error}", current.display()))?;
        if !metadata.is_dir()
            || current
                .canonicalize()
                .map_err(|error| format!("canonicalize destination ancestry: {error}"))?
                != current
            || metadata.uid() != expected_uid
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(format!(
                "destination ancestry must be canonical, expected-owner, and nonwritable: {}",
                current.display()
            ));
        }
        if !full_ancestry || current == Path::new("/") {
            return Ok(());
        }
        current = current
            .parent()
            .ok_or_else(|| "destination ancestry has no root".to_string())?;
    }
}

fn copy_member(
    member: &MemberPlan,
    stage: &Path,
    expected_uid: u32,
) -> Result<MemberReceipt, String> {
    let (mut source, source_identity) = open_regular_nofollow(&member.source, None)?;
    let destination = stage.join(&member.name);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&destination)
        .map_err(|error| format!("create {}: {error}", destination.display()))?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", member.source.display()))?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| format!("write {}: {error}", destination.display()))?;
        digest.update(&buffer[..read]);
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| format!("byte count overflow for {}", member.name))?;
    }
    let observed = hex(&digest.finalize());
    if observed != member.sha256 || bytes != source_identity.size {
        return Err(format!(
            "source proof mismatch for {}: expected {}, observed {} ({} bytes)",
            member.name, member.sha256, observed, bytes
        ));
    }
    let path_after = fs::symlink_metadata(&member.source)
        .map_err(|error| format!("restat {}: {error}", member.source.display()))?;
    let fd_after = source
        .metadata()
        .map_err(|error| format!("fstat {}: {error}", member.source.display()))?;
    if identity(&path_after) != source_identity || identity(&fd_after) != source_identity {
        return Err(format!(
            "source changed while copying: {}",
            member.source.display()
        ));
    }
    output
        .set_permissions(fs::Permissions::from_mode(member.mode))
        .map_err(|error| format!("chmod {}: {error}", destination.display()))?;
    output
        .sync_all()
        .map_err(|error| format!("fsync {}: {error}", destination.display()))?;
    let installed = output
        .metadata()
        .map_err(|error| format!("fstat {}: {error}", destination.display()))?;
    if !installed.is_file()
        || installed.uid() != expected_uid
        || installed.nlink() != 1
        || installed.permissions().mode() & 0o7777 != member.mode
        || installed.size() != bytes
    {
        return Err(format!(
            "unsafe installed member: {}",
            destination.display()
        ));
    }
    Ok(MemberReceipt {
        source: member.source.display().to_string(),
        name: member.name.clone(),
        sha256: observed,
        bytes,
        mode: format!("{:04o}", member.mode),
    })
}

fn write_generated_file(path: &Path, bytes: &[u8], expected_uid: u32) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("fsync {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("fstat {}: {error}", path.display()))?;
    if metadata.uid() != expected_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o444
        || metadata.size() != bytes.len() as u64
    {
        return Err(format!("unsafe generated member: {}", path.display()));
    }
    Ok(hex(&Sha256::digest(bytes)))
}

fn rename_noreplace(source: &Path, destination: &Path) -> Result<(), String> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| "stage path contains NUL".to_string())?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| "destination path contains NUL".to_string())?;
    #[cfg(target_os = "macos")]
    // SAFETY: Both C strings remain alive for the call and contain no interior NUL.
    let result =
        unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
    #[cfg(not(target_os = "macos"))]
    // SAFETY: Both C strings remain alive for the syscall and contain no interior NUL.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(format!(
            "publish deployment {}: {}",
            destination.to_string_lossy(),
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn seal(
    plan: &Plan,
    plan_sha256: &str,
    sealer_sha256: &str,
    expected_uid: u32,
    full_ancestry: bool,
) -> Result<Receipt, String> {
    let parent = plan
        .destination
        .parent()
        .ok_or_else(|| "destination has no parent".to_string())?;
    validate_parent(parent, expected_uid, full_ancestry)?;
    match fs::symlink_metadata(&plan.destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(format!(
                "refusing to replace existing destination: {}",
                plan.destination.display()
            ));
        }
        Err(error) => {
            return Err(format!(
                "inspect destination {}: {error}",
                plan.destination.display()
            ));
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("clock before Unix epoch: {error}"))?;
    let leaf = plan
        .destination
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "destination has no UTF-8 leaf".to_string())?;
    let stage = parent.join(format!(
        ".{leaf}.stage-{}-{}",
        process::id(),
        now.as_nanos()
    ));
    fs::create_dir(&stage).map_err(|error| format!("create stage {}: {error}", stage.display()))?;
    if let Err(error) = fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)) {
        let _ = fs::remove_dir(&stage);
        return Err(format!("secure stage {}: {error}", stage.display()));
    }
    let outcome = (|| {
        let stage_metadata = fs::symlink_metadata(&stage)
            .map_err(|error| format!("stat stage {}: {error}", stage.display()))?;
        if !stage_metadata.is_dir()
            || stage_metadata.uid() != expected_uid
            || stage_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(format!(
                "unsafe stage directory: {} (directory={}, uid={}, expected_uid={}, mode={:04o})",
                stage.display(),
                stage_metadata.is_dir(),
                stage_metadata.uid(),
                expected_uid,
                stage_metadata.permissions().mode() & 0o7777,
            ));
        }
        let mut member_receipts = Vec::with_capacity(plan.members.len());
        let mut sums = BTreeMap::new();
        for member in &plan.members {
            let receipt = copy_member(member, &stage, expected_uid)?;
            sums.insert(receipt.name.clone(), receipt.sha256.clone());
            member_receipts.push(receipt);
        }
        let receipt = Receipt {
            schema: RECEIPT_SCHEMA,
            plan_sha256: plan_sha256.to_string(),
            sealer_sha256: sealer_sha256.to_string(),
            destination: plan.destination.display().to_string(),
            members: member_receipts,
            created_unix_seconds: now.as_secs(),
            publication_authorized: false,
            replay_launch_authorized: false,
            remote_mutations: false,
            r2_mutations: false,
        };
        let mut receipt_bytes = serde_json::to_vec_pretty(&receipt)
            .map_err(|error| format!("serialize deployment receipt: {error}"))?;
        receipt_bytes.push(b'\n');
        let receipt_sha256 = write_generated_file(
            &stage.join("deployment-seal-receipt.json"),
            &receipt_bytes,
            expected_uid,
        )?;
        sums.insert("deployment-seal-receipt.json".to_string(), receipt_sha256);
        let mut sums_bytes = Vec::new();
        for (name, digest) in &sums {
            writeln!(&mut sums_bytes, "{digest}  {name}")
                .map_err(|error| format!("format SHA256SUMS: {error}"))?;
        }
        write_generated_file(&stage.join("SHA256SUMS"), &sums_bytes, expected_uid)?;
        File::open(&stage)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync stage {}: {error}", stage.display()))?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o555))
            .map_err(|error| format!("seal stage {}: {error}", stage.display()))?;
        File::open(&stage)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync sealed stage {}: {error}", stage.display()))?;
        rename_noreplace(&stage, &plan.destination)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync destination parent {}: {error}", parent.display()))?;
        Ok(receipt)
    })();
    if let Err(original_error) = &outcome
        && stage.exists()
    {
        let _ = fs::set_permissions(&stage, fs::Permissions::from_mode(0o700));
        if let Err(error) = fs::remove_dir_all(&stage) {
            return Err(format!(
                "{}; additionally failed to remove private stage {}: {error}",
                original_error,
                stage.display()
            ));
        }
    }
    outcome
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    if unsafe { libc::geteuid() } != 0 {
        return Err("deployment sealing requires effective UID 0".to_string());
    }
    let sealer_sha256 = verify_running_executable(&arguments.self_sha256)?;
    let (plan, plan_sha256) = read_plan(&arguments.plan, &arguments.plan_sha256)?;
    let receipt = seal(&plan, &plan_sha256, &sealer_sha256, 0, true)?;
    println!(
        "{}",
        serde_json::json!({
            "outcome": "created",
            "destination": receipt.destination,
            "plan_sha256": receipt.plan_sha256,
            "sealer_sha256": receipt.sealer_sha256,
            "member_count": receipt.members.len(),
            "publication_authorized": false,
            "replay_launch_authorized": false,
            "remote_mutations": false,
            "r2_mutations": false,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_source(path: &Path, bytes: &[u8], mode: u32) -> String {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        hex(&Sha256::digest(bytes))
    }

    fn test_plan(parent: &Path, source: &Path, digest: String) -> Plan {
        Plan {
            schema: PLAN_SCHEMA.to_string(),
            destination: parent.join("sealed-v1"),
            members: vec![MemberPlan {
                source: source.to_path_buf(),
                name: "payload.bin".to_string(),
                sha256: digest,
                mode: 0o444,
            }],
        }
    }

    #[test]
    fn rename_noreplace_preserves_existing_empty_directory() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("stage");
        let destination = directory.path().join("published");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("payload"), b"staged").unwrap();
        fs::create_dir(&destination).unwrap();

        assert!(rename_noreplace(&source, &destination).is_err());
        assert_eq!(fs::read(source.join("payload")).unwrap(), b"staged");
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
    }

    #[test]
    fn rename_noreplace_allows_only_one_concurrent_publisher() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("published");
        let stages = [
            directory.path().join("first"),
            directory.path().join("second"),
        ];
        for (index, stage) in stages.iter().enumerate() {
            fs::create_dir(stage).unwrap();
            fs::write(stage.join("payload"), [index as u8]).unwrap();
        }
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let handles = stages
                .iter()
                .map(|stage| {
                    let barrier = &barrier;
                    let destination = &destination;
                    scope.spawn(move || {
                        barrier.wait();
                        rename_noreplace(stage, destination)
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let winner = results.iter().position(Result::is_ok).unwrap();
        let loser = 1 - winner;
        assert_eq!(
            fs::read(destination.join("payload")).unwrap(),
            [winner as u8]
        );
        assert!(!stages[winner].exists());
        assert_eq!(
            fs::read(stages[loser].join("payload")).unwrap(),
            [loser as u8]
        );
    }

    #[test]
    fn seals_members_receipt_and_canonical_sums_without_clobbering() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let source = directory.path().join("source.bin");
        let digest = write_source(&source, b"immutable payload", 0o600);
        let plan = test_plan(directory.path(), &source, digest.clone());
        validate_plan(&plan).unwrap();
        let uid = unsafe { libc::geteuid() };
        let receipt = seal(&plan, &"a".repeat(64), &"c".repeat(64), uid, false).unwrap();
        assert_eq!(receipt.members.len(), 1);
        assert_eq!(
            fs::read(plan.destination.join("payload.bin")).unwrap(),
            b"immutable payload"
        );
        let destination_metadata = fs::symlink_metadata(&plan.destination).unwrap();
        assert_eq!(destination_metadata.permissions().mode() & 0o7777, 0o555);
        let payload_metadata = fs::symlink_metadata(plan.destination.join("payload.bin")).unwrap();
        assert_eq!(payload_metadata.permissions().mode() & 0o7777, 0o444);
        assert_eq!(payload_metadata.nlink(), 1);
        let sums = fs::read_to_string(plan.destination.join("SHA256SUMS")).unwrap();
        assert!(sums.contains(&format!("{digest}  payload.bin\n")));
        assert!(sums.contains("  deployment-seal-receipt.json\n"));
        let error = seal(&plan, &"a".repeat(64), &"c".repeat(64), uid, false).unwrap_err();
        assert!(error.contains("refusing to replace existing destination"));
    }

    #[test]
    fn rejects_source_digest_mismatch_and_removes_private_stage() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let source = directory.path().join("source.bin");
        write_source(&source, b"payload", 0o600);
        let plan = test_plan(directory.path(), &source, "b".repeat(64));
        let uid = unsafe { libc::geteuid() };
        let error = seal(&plan, &"a".repeat(64), &"c".repeat(64), uid, false).unwrap_err();
        assert!(error.contains("source proof mismatch"));
        assert!(!plan.destination.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn plan_validation_rejects_writable_or_reserved_members() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let mut plan = test_plan(directory.path(), &source, "a".repeat(64));
        plan.members[0].mode = 0o644;
        assert!(validate_plan(&plan).unwrap_err().contains("0444 or 0555"));
        plan.members[0].mode = 0o444;
        plan.members[0].name = "SHA256SUMS".to_string();
        assert!(
            validate_plan(&plan)
                .unwrap_err()
                .contains("invalid deployment member")
        );
    }
}
