//! Validate the closed epoch 168 seam evidence without opening archive bodies.
use std::{
    fs::{self, Metadata, OpenOptions},
    io::{self, Read},
    ops::Range,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIRST: u64 = 72_576_000;
const BOOTSTRAP: u64 = 72_991_436;
const SEAM: u64 = 72_994_766;
const ROOT: u64 = 73_007_829;
const TAIL_END: u64 = 73_015_142;
const JOINT_CURSOR: u64 = 53_560_733_485;
const RETRY6_CURSOR: u64 = 53_573_751_636;
const RETRY4_DELTA: u64 = 92_032_241;
const WORKER: &str = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541";
const JOINT_IID: &str = "31c1503cecaf4edbb9a78a0c19c0ac9d";
const JOINT_UNIT: &str = "horizon-qualify-168-joint-checkpoint-reduced-20261126-v1.service";
const JOINT_PID: u64 = 3932422;
const JOINT_START: u64 = 408835521;
const JOINT_BOOT_ID: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
const JOINT_READY_US: u64 = 1_795_741_694_000_000;
const SUCCESS: &str = "7ad2d189f7e94e70a38c781354912448";
const ORDINARY_ACCOUNTS: &str = "AgJkU9ZTLnhbCHK54yWFCG4N9sxbtLPRgkCZqwpdWF9R";
const SEAM_BLOCK: &str = "5mMqY7Po42u2cB3L2X6VVvLFkbvPXiZXH2sYMnZiLpnU";
// The sealed comparator checks the retained archive's exact file identity.
const RETRY4_PATH: &str = "/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1/full-metered-20261121-v1/cold-retry4-20261123/private/destination-ab320aeb1bd39ca9218ae95ef9e9b04e92f493e106c9a0e0b70582f6f568f51e/work/root-cohort-168-168/run-916123-1795399774038214572/archives/epoch-168.jet";
const RETRY4_SHA: &str = "cdde7f4da26d0d608f9546883aba787c903e093fc800bd570288e803c0aefc3d";
const RETRY6_SHA: &str = "4a3356c72e2216a8f0a76d0f4ce3d9272d98dadf66deba46e40fa8396e170cea";
const EPOCH_HOME: &str =
    "/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1/full-metered-20261121-v1";
const JOINT_STATE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-joint-checkpoint-reduced-run-20261126-v1";
const RETRY6_STATE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-retry6-rebook-20261126-v1";
const COMPARATOR_SHA: &str = "bfe14ac703ed4f5e256fab9d6a24526f1540cdd5bda1bd544ab62b70643deed4";
const COMPARATOR_SEAL_SHA: &str =
    "55b98899587fc5409787cc83981810cc1266d396918906d445a3ceedb2a35c8e";
const INTERMEDIATE_SHA: &str = "0f9afa2565daad22574cca510277a7c5ff826d337e8b6182e7f945cd854fb7f3";
const RETRY6_MANIFEST_SHA: &str =
    "896f141f6fc5ad0ecde9f974074b7df91b56739a214a47e9db45a47930bb4e30";
const RETRY6_TERMINAL_SHA: &str =
    "5e67a984da9df5350bfce86060557a18603dbac5a18a06747c272922d14b7b71";
const OVERLAP_SHA: &str = "bd4f7980a3653c393832640fb7bbead7b62f0543aa66846baa456f4de0a63c20";
const MAX_EVIDENCE: u64 = 1 << 20;

fn require(test: bool, reason: &'static str) -> io::Result<()> {
    if !test {
        return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
    }
    Ok(())
}

fn field<'a>(value: &'a Value, name: &str) -> io::Result<&'a str> {
    value[name]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {name}")))
}

fn hexadecimal(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

fn number(value: &str) -> io::Result<u64> {
    let n = value.parse::<u64>().map_err(io::Error::other)?;
    require(n.to_string() == value, "noncanonical unsigned integer")?;
    Ok(n)
}

fn metadata_matches(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn read_bound(path: &Path, sha: &str, owner: u32, limit: u64) -> io::Result<Vec<u8>> {
    require(hexadecimal(sha, 64), "invalid evidence digest")?;
    require(
        path.is_absolute() && path.canonicalize()? == path,
        "indirect evidence path",
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    require(
        before.is_file()
            && before.uid() == owner
            && before.mode() & 0o022 == 0
            && before.nlink() == 1
            && before.len() <= limit,
        "untrusted evidence file",
    )?;
    let mut bytes = Vec::new();
    (&file).take(limit + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() as u64 == before.len()
            && metadata_matches(&before, &file.metadata()?)
            && metadata_matches(&before, &fs::symlink_metadata(path)?)
            && format!("{:x}", Sha256::digest(&bytes)) == sha,
        "evidence changed or digest differs",
    )?;
    Ok(bytes)
}

fn fixed_ref(path: &Path, sha: &str) -> Value {
    json!({"path":path,"sha256":sha})
}

fn json_bound(reference: &Value, owner: u32) -> io::Result<Value> {
    let data = read_bound(
        Path::new(field(reference, "path")?),
        field(reference, "sha256")?,
        owner,
        MAX_EVIDENCE,
    )?;
    serde_json::from_slice(&data).map_err(io::Error::other)
}

fn fixed_json(path: &Path, sha: &str, owner: u32) -> io::Result<Value> {
    json_bound(&fixed_ref(path, sha), owner)
}

fn parse_fields<'a, const N: usize>(
    line: &'a str,
    label: &str,
    keys: [&str; N],
) -> io::Result<[&'a str; N]> {
    let mut words = line.split(' ');
    require(words.next() == Some(label), "unexpected evidence row label")?;
    let mut result = [""; N];
    for (i, key) in keys.iter().enumerate() {
        let pair = words.next().and_then(|entry| entry.split_once('='));
        let Some((actual, value)) = pair else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing evidence field",
            ));
        };
        require(
            actual == *key && !value.is_empty(),
            "out-of-schema evidence field",
        )?;
        result[i] = value;
    }
    require(words.next().is_none(), "extra evidence field")?;
    Ok(result)
}

fn checkpoint_line(line: &str) -> io::Result<Value> {
    let (_, fields) = line.split_once("] historical ").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing native checkpoint record",
        )
    })?;
    // The log itself is an authenticated byte range. Keep its actual raw cursor.
    let [
        slot,
        bank,
        accounts,
        block,
        cap,
        tx,
        tick,
        complete,
        writes,
        raw,
    ] = parse_fields(
        fields,
        "checkpoint",
        [
            "slot",
            "bank_hash",
            "accounts_hash",
            "last_blockhash",
            "capitalization",
            "transactions",
            "tick_height",
            "complete",
            "writes",
            "next_write_version",
        ],
    )?;
    require(complete == "true", "native seam slot was incomplete")?;
    Ok(json!({
        "slot":number(slot)?, "bank_hash":bank, "accounts_hash":accounts,
        "last_blockhash":block, "capitalization":number(cap)?, "transaction_count":number(tx)?,
        "tick_height":number(tick)?, "slot_complete":true, "write_count":number(writes)?,
        "next_write_version":number(raw)?,
    }))
}

const CONSENSUS: [&str; 8] = [
    "slot",
    "bank_hash",
    "accounts_hash",
    "last_blockhash",
    "capitalization",
    "tick_height",
    "transaction_count",
    "slot_complete",
];

fn validate_intermediate(intermediate: &Value, retry6: &Value) -> io::Result<Value> {
    let checkpoint = checkpoint_line(field(intermediate, "checkpoint_line")?)?;
    let bootstrap = &retry6["bootstrap"];
    require(
        intermediate["schema"] == "horizon-epoch168-private-intermediate-checkpoint-comparison-v1"
            && intermediate["producer_invocation_id"] == JOINT_IID
            && intermediate["ordinary_root_slot"] == ROOT
            && intermediate["matched_consensus_fields"] == json!(CONSENSUS)
            && intermediate["joint_raw_next_write_version"] == JOINT_CURSOR
            && intermediate["joint_checkpoint_write_count"] == 44
            && intermediate["retry6_raw_next_write_version"] == RETRY6_CURSOR
            && intermediate["retry6_bootstrap_write_count"] == 0
            && intermediate["archive_publication_authorized"] == false
            && intermediate["closed_joint_archive_comparison_pending"] == true
            && field(intermediate, "verified_line")?
                .ends_with("] verified legacy accounts hash at slot 72994766")
            && checkpoint["slot"] == SEAM
            && checkpoint["last_blockhash"] == SEAM_BLOCK
            && checkpoint["next_write_version"] == JOINT_CURSOR
            && checkpoint["write_count"] == 44
            && bootstrap["next_write_version"] == RETRY6_CURSOR
            && bootstrap["write_count"] == 0
            && CONSENSUS
                .iter()
                .all(|key| !checkpoint[*key].is_null() && checkpoint[*key] == bootstrap[*key]),
        "native joint and retry6 checkpoints differ",
    )?;
    Ok(checkpoint)
}

#[derive(Debug)]
struct ComparisonRow<'a> {
    first: u64,
    last: u64,
    digest: &'a str,
    block: &'a str,
    source: Range<u64>,
    joint: Range<u64>,
}

fn comparison_row<'a>(line: &'a str, label: &str) -> io::Result<ComparisonRow<'a>> {
    let [
        first,
        last,
        digest,
        block,
        src_lo,
        src_hi,
        joint_lo,
        joint_hi,
    ] = parse_fields(
        line,
        label,
        [
            "first_slot",
            "last_slot",
            "normalized_sha256",
            "terminal_blockhash",
            "source_raw_start",
            "source_raw_end_exclusive",
            "joint_raw_start",
            "joint_raw_end_exclusive",
        ],
    )?;
    let source = number(src_lo)?..number(src_hi)?;
    let joint = number(joint_lo)?..number(joint_hi)?;
    require(
        hexadecimal(digest, 64)
            && source.start < source.end
            && joint.start < joint.end
            && source.end - source.start == joint.end - joint.start,
        "ordered-event comparison raw ranges differ",
    )?;
    Ok(ComparisonRow {
        first: number(first)?,
        last: number(last)?,
        digest,
        block,
        source,
        joint,
    })
}

fn bind_selected(
    report: &str,
    closed_joint: &Value,
    selected: &Value,
    retry6: &Value,
    overlap: &Value,
    joint_checkpoint: &Value,
) -> io::Result<Value> {
    let mut lines = report.lines();
    let pre = comparison_row(lines.next().unwrap_or_default(), "predecessor_overlap")?;
    let post = comparison_row(lines.next().unwrap_or_default(), "successor_overlap")?;
    let [epoch, seam, root, archive] = parse_fields(
        lines.next().unwrap_or_default(),
        "comparison_complete",
        ["epoch", "seam", "ordinary_root", "joint_sha256"],
    )?;
    let joint_terminal = &closed_joint["terminal"];
    let selected_start = selected["raw_start"].as_u64().unwrap_or_default();
    let selected_end = selected["raw_end_exclusive"].as_u64().unwrap_or_default();
    let retry4_end = RETRY6_CURSOR + RETRY4_DELTA;
    require(
        lines.next().is_none()
            && epoch == "168"
            && number(seam)? == SEAM
            && number(root)? == ROOT
            && hexadecimal(archive, 64)
            && closed_joint["archive_sha256"] == archive,
        "comparison lacks the exact closed joint archive completion",
    )?;
    require(
        selected["schema"] == "horizon-epoch168-private-selected-prefix-evidence-v1"
            && selected["source_archive_sha256"] == RETRY4_SHA
            && hexadecimal(field(selected, "selected_archive_sha256")?, 64)
            && hexadecimal(field(selected, "selected_semantic_sha256")?, 64)
            && selected["first_slot"] == FIRST
            && selected["last_slot"] == SEAM
            && selected["terminal_blockhash"] == SEAM_BLOCK
            && selected["independently_decoded"] == true
            && selected_start > 0
            && selected_start < pre.source.start
            && selected_end == retry4_end
            && selected_end == pre.source.end
            && overlap["schema"] == "horizon-epoch168-normalized-overlap-acceptance-v1"
            && overlap["compared_first_slot"] == SEAM + 1
            && overlap["compared_last_slot"] == 72_998_911
            && overlap["suffix_first_write_version"] == RETRY6_CURSOR
            && overlap["write_version_delta"] == RETRY4_DELTA
            && (pre.first, pre.last, pre.block) == (BOOTSTRAP + 1, SEAM, SEAM_BLOCK)
            && pre.joint.end == JOINT_CURSOR
            && pre.joint.start == 53_555_937_580
            && pre.joint.start == closed_joint["emitted_raw_write_versions"]["start"]
            && pre.source.start.checked_sub(pre.joint.start)
                == selected_end.checked_sub(JOINT_CURSOR),
        "retry4 selection does not agree with the joint predecessor comparison",
    )?;
    require(
        (post.first, post.last) == (SEAM + 1, ROOT)
            && joint_terminal["slot"] == ROOT
            && joint_terminal["slot_complete"] == true
            && joint_terminal["accounts_hash"] == ORDINARY_ACCOUNTS
            && joint_terminal["last_blockhash"] == post.block
            && post.source.start == RETRY6_CURSOR
            && post.joint.start == JOINT_CURSOR
            && post.source.start == retry6["emitted_raw_write_versions"]["start"]
            && retry6["emitted_raw_write_versions"]["end"]
                .as_u64()
                .is_some_and(|end| post.source.end <= end)
            && post.joint.end == joint_terminal["next_write_version"]
            && post.joint.end == closed_joint["emitted_raw_write_versions"]["end"],
        "retry6 selection or ordinary root differs from the joint successor comparison",
    )?;
    let translated = CONSENSUS
        .iter()
        .map(|key| ((*key).to_owned(), joint_checkpoint[*key].clone()));
    let mut predecessor: serde_json::Map<String, Value> = translated.collect();
    predecessor.insert("accounts_hash_kind".into(), json!("legacy_accounts_hash"));
    predecessor.insert("next_write_version".into(), json!(selected_end));
    Ok(json!({
        "schema":"horizon-epoch168-private-joint-lineage-binding-v1",
        "epoch":168, "seam":SEAM, "ordinary_root_slot":ROOT,
        "retry4_source_sha256":RETRY4_SHA,
        "retry4_selected_archive_sha256":selected["selected_archive_sha256"],
        "retry4_selected_semantic_sha256":selected["selected_semantic_sha256"],
        "retry4_selected_raw_start":selected_start,
        "retry4_selected_raw_end_exclusive":selected_end,
        "joint_archive_sha256":archive, "joint_native_seam_checkpoint":joint_checkpoint,
        "retry6_source_sha256":RETRY6_SHA, "retry6_native_bootstrap":retry6["bootstrap"],
        "translated_v4_predecessor":predecessor,
        "joint_to_retry4_cursor_offset":selected_end - JOINT_CURSOR,
        "joint_to_retry6_cursor_offset":RETRY6_CURSOR - JOINT_CURSOR,
        "predecessor_normalized_sha256":pre.digest, "successor_normalized_sha256":post.digest,
        "ordinary_root_checkpoint":joint_terminal,
        "publication_authorized":false, "assembly_authorized":false,
    }))
}

fn clean_pid1(event: &Value, unit: &str, iid: &str) -> bool {
    event["_PID"] == "1"
        && event["_UID"] == "0"
        && event["UNIT"] == unit
        && event["INVOCATION_ID"] == iid
        && event["MESSAGE_ID"] == SUCCESS
}

fn validate_closed_joint(
    terminal: &Value,
    manifest: &Value,
    intermediate: &Value,
) -> io::Result<()> {
    let event = &terminal["pid1_terminal_event"];
    require(
        terminal["schema"] == "horizon-epoch168-joint-reduced-terminal-v1"
            && terminal["enrollment"] == intermediate["enrollment"]
            && terminal["producer_invocation_id"] == JOINT_IID
            && terminal["producer_pid"] == JOINT_PID
            && terminal["producer_start_ticks"] == JOINT_START
            && terminal["disposition"] == "checkpoint-complete"
            && terminal["private_output_preserved"] == true
            && terminal["independent_archive_scan_pending"] == true
            && terminal["resource_credit_bytes"] == 0
            && terminal["archive_publication_authorized"] == false
            && terminal["remote_mutations"] == false
            && clean_pid1(event, JOINT_UNIT, JOINT_IID)
            && event["_BOOT_ID"] == JOINT_BOOT_ID
            && number(field(event, "__REALTIME_TIMESTAMP")?)? >= JOINT_READY_US,
        "joint producer lacks its bound clean terminal event",
    )?;
    require(
        manifest["schema_version"] == 1
            && manifest["epoch"] == 168
            && manifest["output_slot_start"] == BOOTSTRAP + 1
            && manifest["output_slot_count"] == ROOT - BOOTSTRAP
            && manifest["worker_executable_sha256"] == WORKER
            && manifest["bootstrap"]["slot"] == BOOTSTRAP
            && manifest["bootstrap"]["accounts_hash"]
                == "ByNZCiixM5iveRZh2urjzgFDEwCenqnpDL4okbBCf2WH"
            && manifest["bootstrap"]["last_blockhash"]
                == "AcNuUz2ZRmkco618BioYzFNGYuUYh78W6PqD6oHxRXwk"
            && manifest["bootstrap"]["slot_complete"] == true
            && manifest["bootstrap"]["write_count"] == 0
            && manifest["bootstrap"]["next_write_version"] == 53_555_937_580u64,
        "closed joint segment lost its scope or authenticated bootstrap",
    )?;
    Ok(())
}

fn joint_path() -> PathBuf {
    Path::new(EPOCH_HOME)
        .join("joint-checkpoint-reduced-20261126-v1/output/epoch-168-joint-checkpoints.jet")
}

fn retry6_path() -> PathBuf {
    Path::new(EPOCH_HOME).join("cold-retry6-20261126/output/epoch-168-tail.jet")
}

fn comparison_sources(joint_digest: &str) -> Value {
    json!({
        "retry4": fixed_ref(Path::new(RETRY4_PATH), RETRY4_SHA),
        "retry6": fixed_ref(&retry6_path(), RETRY6_SHA),
        "joint": fixed_ref(&joint_path(), joint_digest),
    })
}

fn comparison_report(
    native: &Value,
    seal: &Value,
    comparator: &Path,
    joint_manifest: &Value,
    joint_digest: &str,
    joint_event_time: u64,
) -> io::Result<String> {
    let event = &native["pid1_event"];
    let iid = field(native, "invocation_id")?;
    let unit = field(native, "unit")?;
    let boot = field(event, "_BOOT_ID")?;
    let event_time = number(field(event, "__REALTIME_TIMESTAMP")?)?;
    let executable = comparator
        .to_str()
        .ok_or_else(|| io::Error::other("binary path"))?;
    let uid = field(native, "uid")?;
    require(
        native["schema"] == "horizon-epoch168-private-joint-comparison-native-v1"
            && hexadecimal(iid, 32)
            && iid != JOINT_IID
            && unit.ends_with(".service")
            && native["argv"] == json!([executable, "--compare-joint", joint_digest])
            && native["executable_sha256"] == COMPARATOR_SHA
            && native["sources"] == comparison_sources(joint_digest)
            && native["joint_manifest"] == *joint_manifest
            && clean_pid1(event, unit, iid)
            && hexadecimal(boot, 32)
            && event_time > joint_event_time
            && matches!(uid, "0" | "1001")
            && seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"]
                == comparator
                    .parent()
                    .and_then(Path::to_str)
                    .ok_or_else(|| io::Error::other("seal path"))?
            && seal["members"].as_array().is_some_and(|members| {
                members.iter().any(|m| {
                    m["name"] == "horizon-168-joint-compare"
                        && m["sha256"] == COMPARATOR_SHA
                        && m["mode"] == "0555"
                })
            }),
        "comparison was not completed by the exact sealed native decoder",
    )?;
    let [first, second, last] = native["stdout"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
    else {
        return Err(io::Error::other(
            "expected three native comparator stdout records",
        ));
    };
    let pid = field(first, "_PID")?;
    require(number(pid)? > 1, "invalid native comparator PID")?;
    let cmdline = format!("{executable} --compare-joint {joint_digest}");
    let mut time = joint_event_time;
    let mut report = String::new();
    for row in [first, second, last] {
        let next = number(field(row, "__REALTIME_TIMESTAMP")?)?;
        let message = field(row, "MESSAGE")?;
        require(
            row["_TRANSPORT"] == "stdout"
                && row["_SYSTEMD_INVOCATION_ID"] == iid
                && row["_SYSTEMD_UNIT"] == unit
                && row["_PID"] == pid
                && row["_UID"] == uid
                && row["_EXE"] == executable
                && row["_BOOT_ID"] == boot
                && row.get("_CMDLINE").is_none_or(|value| value == &cmdline)
                && next > joint_event_time
                && next >= time
                && next <= event_time
                && !message.contains(['\n', '\r']),
            "comparison stdout is outside its native invocation",
        )?;
        report.push_str(message);
        report.push('\n');
        time = next;
    }
    Ok(report)
}

fn bind(plan: &Value) -> io::Result<Value> {
    require(
        plan["schema"] == "horizon-epoch168-private-joint-lineage-plan-v1",
        "wrong private lineage plan",
    )?;
    let state = Path::new(JOINT_STATE);
    let intermediate_path = state.join("INTERMEDIATE_CHECKPOINT_COMPARISON.json");
    let retry6_manifest_path = retry6_path().with_extension("jet.segment.json");
    let retry6_terminal_path = Path::new(RETRY6_STATE).join("FOCUSED_TERMINAL.json");
    let intermediate = fixed_json(&intermediate_path, INTERMEDIATE_SHA, 0)?;
    let retry6 = fixed_json(&retry6_manifest_path, RETRY6_MANIFEST_SHA, 1001)?;
    let retry6_terminal = fixed_json(&retry6_terminal_path, RETRY6_TERMINAL_SHA, 0)?;
    require(
        intermediate["retry6_manifest"] == fixed_ref(&retry6_manifest_path, RETRY6_MANIFEST_SHA)
            && intermediate["retry6_terminal"]
                == fixed_ref(&retry6_terminal_path, RETRY6_TERMINAL_SHA)
            && retry6_terminal["schema"] == "horizon-epoch168-focused-retry6-terminal-v1"
            && retry6_terminal["producer_invocation_id"] == "b693b39f54df4e5a9c65f5be75ad5fd2"
            && retry6_terminal["clean_exit"] == true
            && retry6_terminal["producer_cgroup_drained"] == true
            && retry6_terminal["output"]["archive"] == retry6_path().to_string_lossy().as_ref()
            && retry6_terminal["output"]["manifest"] == intermediate["retry6_manifest"]
            && retry6_terminal["output"]["archive_sha256_reported"] == RETRY6_SHA
            && retry6["schema_version"] == 1
            && retry6["epoch"] == 168
            && retry6["output_slot_start"] == SEAM + 1
            && retry6["output_slot_count"] == TAIL_END - SEAM - 1
            && retry6["archive_sha256"] == RETRY6_SHA
            && retry6["worker_executable_sha256"] == WORKER,
        "retry6 terminal/manifest lineage differs",
    )?;
    let checkpoint = validate_intermediate(&intermediate, &retry6)?;

    let terminal = &plan["joint_terminal"];
    let manifest = &plan["joint_manifest"];
    require(
        Path::new(field(terminal, "path")?) == state.join("TERMINAL.json")
            && Path::new(field(manifest, "path")?)
                == joint_path().with_extension("jet.segment.json"),
        "foreign closed joint path",
    )?;
    let terminal_record = json_bound(terminal, 0)?;
    let closed_joint = json_bound(manifest, 1001)?;
    validate_closed_joint(&terminal_record, &closed_joint, &intermediate)?;
    let joint_digest = field(&closed_joint, "archive_sha256")?;
    require(hexadecimal(joint_digest, 64), "invalid closed joint digest")?;

    let native = json_bound(&plan["comparison"], 0)?;
    let comparator = state.join("continuity-tools/horizon-168-joint-compare");
    let seal_path = comparator.with_file_name("deployment-seal-receipt.json");
    let seal = fixed_json(&seal_path, COMPARATOR_SEAL_SHA, 0)?;
    let report = comparison_report(
        &native,
        &seal,
        &comparator,
        manifest,
        joint_digest,
        number(field(
            &terminal_record["pid1_terminal_event"],
            "__REALTIME_TIMESTAMP",
        )?)?,
    )?;
    let selected = json_bound(&plan["selected_prefix"], 0)?;
    let prior_overlap_path = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch168-normalized-overlap-acceptance-20261126-v1/NORMALIZED_OVERLAP_ACCEPTED.json",
    );
    let overlap = fixed_json(prior_overlap_path, OVERLAP_SHA, 0)?;
    let mut output = bind_selected(
        &report,
        &closed_joint,
        &selected,
        &retry6,
        &overlap,
        &checkpoint,
    )?;
    output["evidence"] = json!({
        "independent_seam":fixed_ref(&intermediate_path,INTERMEDIATE_SHA),
        "retry6_manifest":fixed_ref(&retry6_manifest_path,RETRY6_MANIFEST_SHA),
        "retry6_terminal":fixed_ref(&retry6_terminal_path,RETRY6_TERMINAL_SHA),
        "prior_normalized_overlap":fixed_ref(prior_overlap_path,OVERLAP_SHA),
        "joint_terminal":terminal, "joint_manifest":manifest, "selected_prefix":plan["selected_prefix"],
        "comparison_native":plan["comparison"],
        "comparison_stdout_sha256":format!("{:x}", Sha256::digest(report.as_bytes())),
        "comparison_deployment":fixed_ref(&seal_path,COMPARATOR_SEAL_SHA),
    });
    Ok(output)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [path, digest] = args.as_slice() else {
        return Err("usage: horizon-168-joint-lineage PLAN PLAN_SHA256".into());
    };
    let bytes = read_bound(Path::new(path), digest, 0, MAX_EVIDENCE)?;
    let plan = serde_json::from_slice(&bytes)?;
    let mut result = bind(&plan)?;
    result["plan"] = fixed_ref(Path::new(path), digest);
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

#[cfg(test)]
#[path = "joint_lineage_tests.rs"]
mod tests;
