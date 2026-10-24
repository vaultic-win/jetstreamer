//! Reusable exact old213 prefix review. No R2, retirement, resource sample or services.
use {
    anyhow::{Context, Result, bail, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        env,
        fs::{self, File, Metadata, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    },
};

pub const HOST: &str = "horizon-vaultic";
pub const PREFIX: &str = "foundation_node_01/";
pub const MAPPING: &str =
    "/var/lib/jetstreamer/horizon-r2-holding-foundation-node-01-user-mapping-v1/mapping.json";
pub const MAPPING_SHA: &str = "50736c4c6633b4a97f4a717a1ba5f83374b4e2af4b7ef22c90ed4e007cad35b6";
pub const SOURCE: &str = "/home/ubuntu/.jetstreamer-private/qualification-213/diagnostic-output-selected-store8-v2/epoch-213-through-92447542.jet";
pub const SOURCE_SHA: &str = "e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9";
pub const LENGTH: u64 = 125_316_500_795;
pub const SEGMENT_SHA: &str = "1d74158c418f67443837b01ae3d218ace43c1e9998e6a91c4d3ead6e2b5e0581";
pub const CONTINUATION: &str =
    "/var/lib/jetstreamer/horizon-213-checkpoint-continuation-ae43646-v1/continuation-plan.json";
pub const CONTINUATION_SHA: &str =
    "83eeb441502e39510ad7610ae6dac9165d9f5a6f32afaeab1f19205e9ab6f144";
const CANONICAL_SHA: &str = "953e8c9efbdfc0dc49e4f066d30046e3b44e1a13e065b340a5bcc7b093632261";
const PRODUCER: &str = "horizon-qualify-213-selected-store8-v2.service";
const IID: &str = "331a5c69fd0a4f2e8dd35f7ace0f51a4";
const UNITS: &[&str] = &[
    PRODUCER,
    "horizon-independent-verify-213-recovered-v1.service",
    "horizon-independent-verify-213-selected-store8-v2.service",
    "horizon-independent-verify-213-selected-store8-v2-recovery-16384.service",
    "horizon-independent-full-read-213-recovered-v1.service",
    "horizon-independent-full-read-213-recovered-v2.service",
    "horizon-retire-scratch-213-selected-store8-v2.service",
    "horizon-qualify-213-checkpoint-continuation-ae43646-v1.service",
    "horizon-qualify-213-private-verification-78d8c53-v3.service",
    "horizon-upload-213-exact-v4-a4de434-v1.service",
];
const ROOTS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/home/ubuntu/.jetstreamer-private/systemd-staging",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
    accepted_fleet: Bound,
    rehash_source: bool,
    output: PathBuf,
}

fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.nlink() == b.nlink()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.mode() == b.mode()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn small(path: &Path, digest: &str, root_only: bool) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "aliased evidence path"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.len() <= 4 << 20
            && before.mode() & 0o022 == 0
            && (before.uid() == 0 || (!root_only && before.uid() == 1000)),
        "untrusted/oversized evidence file"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        same(&before, &file.metadata()?),
        "evidence replaced before read"
    );
    let mut bytes = Vec::new();
    (&mut file).take((4 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && hex(&bytes) == digest
            && same(&before, &file.metadata()?)
            && same(&before, &fs::symlink_metadata(path)?),
        "evidence identity/digest changed"
    );
    Ok(bytes)
}
fn fixed(path: &str, sha: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&small(
        Path::new(path),
        sha,
        false,
    )?)?)
}
fn mapping(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-r2-holding-user-mapping-v1"
            && v["host"] == HOST
            && v["user_provided_directory"] == "foundation_node_01"
            && v["key_prefix"] == PREFIX
            && v["authorization_source"]
                == "User: directory name for this server will be foundation_node_01"
            && v["authorized_operations"]
                == json!([
                    "append-only parking of eligible closed files",
                    "authenticated restoration"
                ])
            && v["remote_overwrite_authorized"] == false
            && v["remote_deletion_authorized"] == false
            && v["live_replay_offloading_authorized"] == false,
        "Foundation user mapping differs; node02 is a different host"
    );
    Ok(())
}
fn source(path: &Path) -> Result<Metadata> {
    ensure!(
        path == Path::new(SOURCE) && path.canonicalize()? == path,
        "foreign source"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.len() == LENGTH
            && m.dev() == 66305
            && m.ino() == 18063496
            && m.nlink() == 1
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o7777 == 0o600
            && m.mtime() == 1791629969
            && m.ctime() == 1791629969,
        "old213 source differs from preserved failure/validation identity"
    );
    for sidecar in [
        format!("{SOURCE}.sha256"),
        SOURCE.replace(".jet", ".sha256"),
    ] {
        ensure!(
            fs::symlink_metadata(&sidecar).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "old prefix has a checksum sidecar or unreadable sidecar path"
        );
    }
    Ok(m)
}
fn digest_source(before: &Metadata) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(SOURCE)?;
    ensure!(
        same(before, &file.metadata()?),
        "source replaced before hashing"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .context("source length overflow")?;
        ensure!(total <= LENGTH, "source grew while hashing");
        hash.update(&buffer[..count]);
    }
    let sha = format!("{:x}", hash.finalize());
    ensure!(
        total == LENGTH
            && sha == SOURCE_SHA
            && same(before, &file.metadata()?)
            && same(before, &source(Path::new(SOURCE))?),
        "source bytes changed"
    );
    Ok(sha)
}
fn self_bound(expected: &str) -> Result<()> {
    let path = fs::read_link("/proc/self/exe")?;
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "aliased running executable"
    );
    let before = fs::symlink_metadata(&path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= 128 << 20,
        "review executable is not sealed"
    );
    let mut file = File::open("/proc/self/exe")?;
    ensure!(
        same(&before, &file.metadata()?),
        "mapped review executable differs"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .context("review executable size overflow")?;
        ensure!(total <= 128 << 20, "review executable grew");
        hash.update(&buffer[..n]);
    }
    ensure!(
        total == before.len()
            && format!("{:x}", hash.finalize()) == expected
            && same(&before, &file.metadata()?)
            && same(&before, &fs::symlink_metadata(path)?),
        "running review executable hash/identity differs"
    );
    Ok(())
}
fn lineage(
    failure: &Value,
    validation: &Value,
    segment: &Value,
    publication: &Value,
    fleet: &Value,
) -> Result<()> {
    ensure!(
        failure["epoch"] == 213
            && failure["producer"]["unit"] == PRODUCER
            && failure["producer"]["invocation_id"] == IID
            && failure["producer"]["result"] == "timeout"
            && failure["producer"]["exec_main_status"] == 9
            && failure["archive_completion"]["archive"] == SOURCE
            && failure["archive_completion"]["bytes"] == LENGTH
            && validation["schema"] == "jetstreamer-focused-qualification-artifact-validation-v1"
            && validation["validation"] == "pass"
            && validation["epoch"] == 213
            && validation["archive"] == SOURCE
            && validation["archive_bytes"] == LENGTH
            && validation["archive_sha256"] == SOURCE_SHA
            && validation["output_slot_count"] == 431543
            && validation["canonical_checksum_sidecar_absent"] == true
            && segment["epoch"] == 213
            && segment["archive_sha256"] == SOURCE_SHA
            && segment["output_slot_start"] == 92016000
            && segment["output_slot_count"] == 431543
            && segment["terminal"]["slot"] == 92447542
            && segment["terminal"]["slot_complete"] == true
            && publication["schema"] == "jetstreamer-exact-epoch213-v4-publication-receipt-v1"
            && publication["epoch"] == 213
            && publication["committed"] == true
            && publication["archive_sha256"] == CANONICAL_SHA
            && publication["archive_bytes"] == 125368013231u64
            && publication["original_assembly_preserved"] == true
            && publication["retirement_authorized"] == false,
        "old213 lineage or canonical preservation evidence differs"
    );
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 201
            && fleet["last_epoch"] == 300
            && fleet["inventory"]["anomalies"] == 0
            && fleet["epochs"]
                .as_array()
                .context("fleet epochs")?
                .iter()
                .filter(|e| e["epoch"] == 213 && e["state"] == "remote-ready")
                .count()
                == 1
            && fleet["inventory"]["entries"]
                .as_array()
                .context("fleet inventory")?
                .iter()
                .filter(|e| e["epoch"] == 213
                    && e["state"] == "ready-pair"
                    && e["sidecar_sha256"] == CANONICAL_SHA
                    && e["archive_metadata_sha256"] == CANONICAL_SHA
                    && e["archive_length"] == 125368013231u64)
                .count()
                == 1
            && !fleet["active"]
                .as_array()
                .context("fleet active")?
                .iter()
                .any(|r| r["epoch"] == 213),
        "accepted fleet does not show the completed independent213 archive"
    );
    Ok(())
}
fn terminal(name: &str, v: &Value) -> Result<()> {
    let expected_success = match name {
        PRODUCER => "horizon-independent-verify-213-selected-store8-v2.service",
        "horizon-independent-verify-213-selected-store8-v2.service" => {
            "horizon-retire-scratch-213-selected-store8-v2.service"
        }
        _ => "",
    };
    ensure!(
        UNITS.contains(&name)
            && v["Id"] == name
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Job"] == ""
            && v["Triggers"] == ""
            && v["TriggeredBy"] == ""
            && v["OnFailure"] == ""
            && v["OnSuccess"] == expected_success
            && matches!(v["LoadState"].as_str(), Some("loaded" | "not-found"))
            && matches!(
                (v["ActiveState"].as_str(), v["SubState"].as_str()),
                (Some("inactive"), Some("dead")) | (Some("failed"), Some("failed"))
            ),
        "213 owner is live, changed or has an automatic retry path"
    );
    if name == PRODUCER {
        ensure!(
            v["InvocationID"] == IID && v["Result"] == "timeout" && v["ExecMainStatus"] == "9",
            "original213 failed invocation was replaced/cleared"
        );
    }
    Ok(())
}
fn continuation(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch213-checkpoint-continuation-plan-v1"
            && v["epoch"] == 213
            && v["producer_unit"]
                == "horizon-qualify-213-checkpoint-continuation-ae43646-v1.service"
            && v["prefix_archive"] == json!({"path":SOURCE,"sha256":SOURCE_SHA})
            && v["prefix_manifest"]["sha256"] == SEGMENT_SHA
            && v["run_root"]
                == "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-213-ae43646-v1",
        "old213 continuation restoration dependency changed"
    );
    Ok(())
}
fn units() -> Result<BTreeMap<String, Value>> {
    let mut result = BTreeMap::new();
    for name in UNITS {
        let out = Command::new("/usr/bin/systemctl").args(["show",name,"--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,Job,Triggers,TriggeredBy,OnFailure,OnSuccess,Result,ExecMainStatus,FragmentPath,DropInPaths"]).output()?;
        ensure!(
            out.status.success() && out.stdout.len() <= 16384,
            "unit metadata unavailable"
        );
        let fields = std::str::from_utf8(&out.stdout)?
            .lines()
            .map(|line| {
                let (key, value) = line.split_once('=').context("unit property shape")?;
                Ok((key.to_owned(), json!(value)))
            })
            .collect::<Result<serde_json::Map<_, _>>>()?;
        let value = Value::Object(fields);
        terminal(name, &value)?;
        result.insert((*name).to_owned(), value);
    }
    Ok(result)
}
fn staged_file(path: &Path, owner: u32) -> Result<(String, bool)> {
    let real = path.canonicalize()?;
    if real == Path::new("/dev/null") {
        return Ok(("masked-dev-null".into(), false));
    }
    let before = fs::symlink_metadata(&real)?;
    ensure!(
        before.is_file()
            && before.len() <= 4 << 20
            && before.nlink() > 0
            && (before.uid() == 0 || before.uid() == owner)
            && before.mode() & 0o022 == 0,
        "untrusted/oversized staged metadata"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&real)?;
    ensure!(
        same(&before, &file.metadata()?),
        "staged file changed before read"
    );
    let mut data = Vec::new();
    (&mut file).take((4 << 20) + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 == before.len()
            && same(&before, &file.metadata()?)
            && same(&before, &fs::symlink_metadata(&real)?),
        "staged metadata changed"
    );
    let needle = Path::new(SOURCE)
        .parent()
        .unwrap()
        .as_os_str()
        .as_encoded_bytes();
    Ok((hex(&data), data.windows(needle.len()).any(|w| w == needle)))
}
fn staged(root: &Path, owner: u32) -> Result<BTreeMap<String, (String, bool)>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![(root.to_path_buf(), 0)];
    let mut count = 0;
    while let Some((directory, depth)) = pending.pop() {
        ensure!(depth <= 12, "staged tree exceeds depth bound");
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            count += 1;
            ensure!(count <= 20000, "staged tree exceeds entry bound");
            let path = entry.path();
            let kind = fs::symlink_metadata(&path)?.file_type();
            if kind.is_dir() {
                pending.push((path, depth + 1));
            } else if kind.is_file() || kind.is_symlink() {
                // A directory alias could hide an unscanned subtree. Preserve it
                // as a blocker instead of silently following or ignoring it.
                if path.is_dir() {
                    result.insert(path.display().to_string(), ("directory-alias".into(), true));
                } else {
                    result.insert(
                        path.display().to_string(),
                        staged_file(&path, owner)
                            .with_context(|| format!("staged metadata {}", path.display()))?,
                    );
                }
            } else {
                bail!("special staged metadata object");
            }
        }
    }
    Ok(result)
}
fn historical_reference(root: &str, path: &str) -> bool {
    if !matches!(root, "/etc/systemd/system" | "/run/systemd/system")
        || !Path::new(path).starts_with(root)
        || path.contains(".wants/")
        || path.contains(".requires/")
    {
        return false;
    }
    let path = Path::new(path);
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| UNITS.contains(&name))
        || path
            .ancestors()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .any(|name| {
                name.strip_suffix(".d")
                    .is_some_and(|unit| UNITS.contains(&unit))
            })
}
pub fn validate_host_mapping() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && fs::read_to_string("/etc/hostname")?.trim() == HOST,
        "Foundation review requires this root host"
    );
    mapping(&serde_json::from_slice(&small(
        Path::new(MAPPING),
        MAPPING_SHA,
        true,
    )?)?)
}
pub fn segment_bytes() -> Result<Vec<u8>> {
    let path = PathBuf::from(format!("{SOURCE}.segment.json"));
    let before = fs::symlink_metadata(&path)?;
    ensure!(
        before.uid() == 0
            && before.gid() == 0
            && before.mode() & 0o7777 == 0o600
            && before.len() == 1809,
        "raw prefix segment original metadata differs"
    );
    let bytes = small(&path, SEGMENT_SHA, true)?;
    ensure!(
        same(&before, &fs::symlink_metadata(&path)?),
        "raw prefix segment metadata changed"
    );
    Ok(bytes)
}
/// Reusable exact-artifact gate. Never takes a resource sample or creates a
/// custody/retirement proof; the transport independently verifies every byte.
pub fn inspect(fleet_path: &Path, fleet_sha: &str, rehash_source: bool) -> Result<Value> {
    validate_host_mapping()?;
    ensure!(
        fleet_path.starts_with("/var/lib/jetstreamer/horizon-campaign-fleet")
            && fleet_path
                .file_name()
                .is_some_and(|n| n == "fleet-ledger.json"),
        "foreign accepted fleet"
    );
    let fleet: Value = serde_json::from_slice(&small(fleet_path, fleet_sha, true)?)?;
    review_data(&fleet, fleet_path, fleet_sha, rehash_source)
}
pub fn run_cli() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 6
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256",
        "usage: REVIEW PLAN --plan-sha256 SHA --self-sha256 SHA (root)"
    );
    ensure!(
        fs::read_to_string("/etc/hostname")?.trim() == HOST,
        "wrong host"
    );
    self_bound(&args[5])?;
    let plan: Plan = serde_json::from_slice(&small(Path::new(&args[1]), &args[3], true)?)?;
    ensure!(
        plan.schema == "jetstreamer-foundation-holding-review213-plan-v1"
            && plan.mapping.path == Path::new(MAPPING)
            && plan.mapping.sha256 == MAPPING_SHA
            && plan
                .accepted_fleet
                .path
                .starts_with("/var/lib/jetstreamer/horizon-campaign-fleet")
            && plan
                .accepted_fleet
                .path
                .file_name()
                .is_some_and(|n| n == "fleet-ledger.json"),
        "foreign plan/mapping/fleet"
    );
    mapping(&serde_json::from_slice(&small(
        &plan.mapping.path,
        &plan.mapping.sha256,
        true,
    )?)?)?;
    let fleet: Value = serde_json::from_slice(&small(
        &plan.accepted_fleet.path,
        &plan.accepted_fleet.sha256,
        true,
    )?)?;
    let mut report = review_data(
        &fleet,
        &plan.accepted_fleet.path,
        &plan.accepted_fleet.sha256,
        plan.rehash_source,
    )?;
    report["plan_sha256"] = json!(args[3]);
    report["self_sha256"] = json!(args[5]);
    write_report(&plan.output, &report)
}
fn review_data(
    fleet: &Value,
    fleet_path: &Path,
    fleet_sha: &str,
    rehash_source: bool,
) -> Result<Value> {
    let failure = fixed(
        "/home/ubuntu/.jetstreamer-private/epoch213-postarchive-shutdown-failure-corrected-20261010T1124Z.json",
        "9ec83e6dbd570d2e7ae21f372404d924c9ba6d6faa333f29fa744de32cc72c97",
    )?;
    let validation = fixed(
        "/home/ubuntu/.jetstreamer-private/qualification-validation-receipts/epoch213-selected-store8-v2.json",
        "e7adb91a8808b9fa106398486f02cc814880b08ca00bac2a10d708a88fc25b93",
    )?;
    let segment = fixed(
        &format!("{SOURCE}.segment.json"),
        "1d74158c418f67443837b01ae3d218ace43c1e9998e6a91c4d3ead6e2b5e0581",
    )?;
    let publication = fixed(
        "/var/lib/jetstreamer/horizon-213-published-artifact-20261020-v1/publication/publication.json",
        "ca4e69c11ce11bcc9bbb45b5ad3feeee97f834d94a19dc733fe6a32d7b1612f0",
    )?;
    lineage(&failure, &validation, &segment, &publication, fleet)?;
    continuation(&fixed(CONTINUATION, CONTINUATION_SHA)?)?;
    segment_bytes()?;
    let before = source(Path::new(SOURCE))?;
    let owner_before = units()?;
    let references_before =
        crate::process_references::scan(Path::new("/proc"), Path::new(SOURCE).parent().unwrap())?;
    let staged_before = ROOTS
        .iter()
        .map(|r| Ok((r.to_string(), staged(Path::new(r), 1000)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let rehashed = if rehash_source {
        Some(digest_source(&before)?)
    } else {
        None
    };
    let references_after =
        crate::process_references::scan(Path::new("/proc"), Path::new(SOURCE).parent().unwrap())?;
    let staged_after = ROOTS
        .iter()
        .map(|r| Ok((r.to_string(), staged(Path::new(r), 1000)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        staged_before == staged_after
            && units()? == owner_before
            && same(&before, &source(Path::new(SOURCE))?),
        "source/owner/staged metadata changed during review"
    );
    let mut blockers = Vec::new();
    let mut historical = Vec::new();
    for (root, tree) in &staged_after {
        for (path, (sha, matched)) in tree {
            if !matched {
                continue;
            }
            if sha != "directory-alias" && historical_reference(root, path) {
                historical.push(json!({"path":path,"sha256":sha,"disposition":"closed-historical-consumer; restore required before reuse"}));
            } else {
                blockers.push(json!({"path":path,"sha256":sha,"disposition":"staged-reference-review-required"}));
            }
        }
    }
    let closed = references_before.references.is_empty() && references_after.references.is_empty();
    let mut report = json!({"schema":"jetstreamer-foundation-holding-review213-v1","host":HOST,"prefix":PREFIX,
        "mapping":{"path":MAPPING,"sha256":MAPPING_SHA},"accepted_fleet":{"path":fleet_path,"sha256":fleet_sha},
        "inventory_sampled_at_utc":fleet["sampled_at_utc"],
        "source":SOURCE,"expected_sha256":SOURCE_SHA,"source_sha256":rehashed,"source_body_rehashed":rehash_source,
        "length":before.len(),"physical_bytes":before.blocks().checked_mul(512).context("block overflow")?,"device":before.dev(),"inode":before.ino(),
        "uid":before.uid(),"gid":before.gid(),"mode":before.mode()&0o7777,"mtime":before.mtime(),"mtime_ns":before.mtime_nsec(),
        "ctime":before.ctime(),"ctime_ns":before.ctime_nsec(),"closed_reference_census_passed":closed,"owners":owner_before,
        "reference_census_before":references_before,"reference_census_after":references_after,
        "staged_metadata_files":staged_after.values().map(|tree|tree.len()).sum::<usize>(),"staged_reference_blockers":blockers,
        "closed_historical_references":historical,"historical_references_require_restore_before_reuse":true});
    let scope = json!({
        "lineage_and_remote_ready_evidence_validated":true,"raw_segment_restore_required":true,
        "completed_continuation_restore_dependency":{"path":CONTINUATION,"sha256":CONTINUATION_SHA},
        "staged_references_cleared":blockers.is_empty(),"eligible_for_custody_copy":closed && rehash_source && blockers.is_empty(),
        "eligible_for_local_retirement":false,"qualified_custody":false,"qualified_byte_restoration":false,"reclaimable_bytes":0,
        "public_canonical_and_original_v4_assembly_preserved":true,"resource_samples_taken":0,"replay_launch_authorized":false,
        "local_retirement_authorized":false,"canonical_publication_authorized":false,"services_changed":false,"r2_mutations":false,"remote_mutations":false,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()});
    report
        .as_object_mut()
        .unwrap()
        .extend(scope.as_object().unwrap().clone());
    Ok(report)
}
fn write_report(output: &Path, report: &Value) -> Result<()> {
    ensure!(
        output.is_absolute()
            && output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-foundation-holding-review213-")),
        "review output namespace differs"
    );
    let parent = output.parent().unwrap();
    let md = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && md.is_dir() && md.uid() == 0 && md.mode() & 0o077 == 0,
        "review parent not root-private"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foundation_mapping_never_borrows_node02_or_remote_cleanup_authority() {
        let good = json!({"schema":"horizon-r2-holding-user-mapping-v1","host":HOST,"key_prefix":PREFIX,
            "user_provided_directory":"foundation_node_01","authorization_source":"User: directory name for this server will be foundation_node_01",
            "authorized_operations":["append-only parking of eligible closed files","authenticated restoration"],
            "remote_overwrite_authorized":false,"remote_deletion_authorized":false,"live_replay_offloading_authorized":false});
        mapping(&good).unwrap();
        for (key, value) in [
            ("host", json!("dev-samjohnson")),
            ("key_prefix", json!("node_02/")),
            ("remote_deletion_authorized", json!(true)),
            ("live_replay_offloading_authorized", json!(true)),
            ("authorization_source", json!("")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(mapping(&bad).is_err(), "{key}");
        }
    }
    #[test]
    fn original_failed_owner_cannot_be_restarted_replaced_or_relabelled() {
        let good = json!({"Id":PRODUCER,"MainPID":"0","NRestarts":"0","Restart":"no","Job":"","Triggers":"","TriggeredBy":"",
            "OnFailure":"","OnSuccess":"horizon-independent-verify-213-selected-store8-v2.service","LoadState":"loaded","ActiveState":"failed","SubState":"failed",
            "InvocationID":IID,"Result":"timeout","ExecMainStatus":"9"});
        terminal(PRODUCER, &good).unwrap();
        for (key, value) in [
            ("InvocationID", json!("")),
            ("MainPID", json!("1")),
            ("NRestarts", json!("1")),
            ("Job", json!("queued")),
            ("TriggeredBy", json!("retry.timer")),
            ("OnFailure", json!("retry.service")),
            ("OnSuccess", json!("new-repair.service")),
            ("Restart", json!("on-failure")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(terminal(PRODUCER, &bad).is_err(), "{key}");
        }
        assert!(terminal("other.service", &good).is_err());
    }
    #[test]
    fn metadata_census_finds_parent_path_references_and_detects_changes() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let unit = root.path().join("staged.service");
        fs::write(&unit, format!("ExecStart=reader {SOURCE}\n")).unwrap();
        fs::set_permissions(&unit, fs::Permissions::from_mode(0o640)).unwrap();
        let owner = unsafe { libc::geteuid() };
        let first = staged(root.path(), owner).unwrap();
        assert!(first[&unit.display().to_string()].1);
        fs::write(&unit, "ExecStart=other\n").unwrap();
        let second = staged(root.path(), owner).unwrap();
        assert_ne!(first, second);
        assert!(!second[&unit.display().to_string()].1);
    }
    #[test]
    fn closed_history_is_not_a_new_staged_or_boot_enabled_input() {
        let file = format!("/etc/systemd/system/{PRODUCER}");
        assert!(historical_reference("/etc/systemd/system", &file));
        let dropin = format!("/etc/systemd/system/{PRODUCER}.d/40-validator.conf");
        assert!(historical_reference("/etc/systemd/system", &dropin));
        let pending = format!("/home/ubuntu/.jetstreamer-private/systemd-staging/{PRODUCER}");
        assert!(!historical_reference(
            "/home/ubuntu/.jetstreamer-private/systemd-staging",
            &pending
        ));
        let enabled = format!("/etc/systemd/system/multi-user.target.wants/{PRODUCER}");
        assert!(!historical_reference("/etc/systemd/system", &enabled));
        assert!(!historical_reference(
            "/etc/systemd/system",
            "/etc/systemd/system/new-repair.service"
        ));
    }
    #[test]
    fn plan_cannot_select_another_artifact_or_request_mutation() {
        let b = json!({"path":"/sealed/receipt.json","sha256":"a".repeat(64)});
        let mut plan = json!({"schema":"jetstreamer-foundation-holding-review213-plan-v1","mapping":b,"accepted_fleet":b,
            "rehash_source":false,"output":"/var/lib/jetstreamer/horizon-foundation-holding-review213-fixture/review.json"});
        assert!(serde_json::from_value::<Plan>(plan.clone()).is_ok());
        for key in ["delete_local", "overwrite", "source", "prefix"] {
            plan[key] = json!(true);
            assert!(serde_json::from_value::<Plan>(plan.clone()).is_err());
            plan.as_object_mut().unwrap().remove(key);
        }
        assert!(source(Path::new("/home/ubuntu/horizon/epoch-213.jet")).is_err());
    }
    #[test]
    fn prefix_lineage_cannot_borrow_the_canonical_digest_or_an_active_job() {
        let failure = json!({"epoch":213,"producer":{"unit":PRODUCER,"invocation_id":IID,"result":"timeout","exec_main_status":9},
            "archive_completion":{"archive":SOURCE,"bytes":LENGTH}});
        let validation = json!({"schema":"jetstreamer-focused-qualification-artifact-validation-v1","validation":"pass","epoch":213,
            "archive":SOURCE,"archive_bytes":LENGTH,"archive_sha256":SOURCE_SHA,"output_slot_count":431543,"canonical_checksum_sidecar_absent":true});
        let segment = json!({"epoch":213,"archive_sha256":SOURCE_SHA,"output_slot_start":92016000,"output_slot_count":431543,
            "terminal":{"slot":92447542,"slot_complete":true}});
        let publication = json!({"schema":"jetstreamer-exact-epoch213-v4-publication-receipt-v1","epoch":213,"committed":true,
            "archive_sha256":CANONICAL_SHA,"archive_bytes":125368013231u64,"original_assembly_preserved":true,"retirement_authorized":false});
        let fleet = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":201,"last_epoch":300,
            "inventory":{"anomalies":0,"entries":[{"epoch":213,"state":"ready-pair","sidecar_sha256":CANONICAL_SHA,
                "archive_metadata_sha256":CANONICAL_SHA,"archive_length":125368013231u64}]},
            "epochs":[{"epoch":213,"state":"remote-ready"}],"active":[]});
        lineage(&failure, &validation, &segment, &publication, &fleet).unwrap();
        let mut wrong = validation.clone();
        wrong["archive_sha256"] = json!(CANONICAL_SHA);
        assert!(lineage(&failure, &wrong, &segment, &publication, &fleet).is_err());
        wrong = validation.clone();
        wrong["archive_bytes"] = json!(0);
        assert!(lineage(&failure, &wrong, &segment, &publication, &fleet).is_err());
        let mut active = fleet.clone();
        active["active"] = json!([{"epoch":213}]);
        assert!(lineage(&failure, &validation, &segment, &publication, &active).is_err());
        let mut bad = publication.clone();
        bad["retirement_authorized"] = json!(true);
        assert!(lineage(&failure, &validation, &segment, &bad, &fleet).is_err());
    }
    #[test]
    fn completed_continuation_remains_an_exact_restore_dependency() {
        let good = json!({"schema":"jetstreamer-private-epoch213-checkpoint-continuation-plan-v1","epoch":213,
            "producer_unit":"horizon-qualify-213-checkpoint-continuation-ae43646-v1.service",
            "prefix_archive":{"path":SOURCE,"sha256":SOURCE_SHA},"prefix_manifest":{"sha256":SEGMENT_SHA},
            "run_root":"/home/ubuntu/.jetstreamer-private/checkpoint-continuation-213-ae43646-v1"});
        continuation(&good).unwrap();
        for pointer in [
            "/epoch",
            "/producer_unit",
            "/prefix_archive/path",
            "/prefix_archive/sha256",
            "/prefix_manifest/sha256",
            "/run_root",
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(continuation(&bad).is_err(), "{pointer}");
        }
    }
}
