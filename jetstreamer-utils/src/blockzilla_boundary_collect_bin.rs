use {
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        ffi::OsString,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process,
        time::{SystemTime, UNIX_EPOCH},
    },
};

const AUDIT_SCHEMA: &str = "jetstreamer-private-epoch208-full-skipped-slot-audit-v1";
const EXTRACTION_SCHEMA: &str = "jetstreamer-blockzilla-poh-targets-v1";
const OUTPUT_SCHEMA: &str = "jetstreamer-epoch208-decoded-gap-boundaries-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-epoch208-recovered-gap-boundaries-v1";
const EXPECTED_TICKS_PER_SLOT: u64 = 64;
const EXPECTED_GAP_RUNS: usize = 25;
const EXPECTED_SKIPPED_SLOTS: u64 = 71;
const EXPECTED_TOTAL_BOUNDARIES: u64 = 96;
const MAX_AUDIT_BYTES: u64 = 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EXTRACTION_BYTES: u64 = 16 * 1024 * 1024;

// (previous present slot, first post-gap block, skipped slots, boundaries)
const EXPECTED_GAPS: [(u64, u64, u64, u64); EXPECTED_GAP_RUNS] = [
    (89_856_115, 89_856_117, 1, 2),
    (89_856_119, 89_856_121, 1, 2),
    (89_856_127, 89_856_129, 1, 2),
    (89_856_171, 89_856_176, 4, 5),
    (89_856_223, 89_856_225, 1, 2),
    (89_856_227, 89_856_229, 1, 2),
    (89_856_231, 89_856_233, 1, 2),
    (89_856_235, 89_856_240, 4, 5),
    (89_856_283, 89_856_285, 1, 2),
    (89_856_295, 89_856_300, 4, 5),
    (89_856_303, 89_856_312, 8, 9),
    (89_856_371, 89_856_373, 1, 2),
    (89_856_391, 89_856_396, 4, 5),
    (89_856_403, 89_856_405, 1, 2),
    (89_856_415, 89_856_422, 6, 7),
    (89_856_427, 89_856_429, 1, 2),
    (89_856_431, 89_856_433, 1, 2),
    (89_856_463, 89_856_468, 4, 5),
    (89_856_471, 89_856_476, 4, 5),
    (89_856_479, 89_856_482, 2, 3),
    (89_856_491, 89_856_496, 4, 5),
    (89_856_527, 89_856_532, 4, 5),
    (89_856_547, 89_856_552, 4, 5),
    (89_856_555, 89_856_560, 4, 5),
    (89_856_575, 89_856_580, 4, 5),
];

const EXPECTED_FINAL_BLOCKHASHES: [(u64, &str); EXPECTED_GAP_RUNS] = [
    (89_856_117, "FQjwC1FQU3ZRZLbMpywW7FWLyPP9v1XqyBRhk2FgwomW"),
    (89_856_121, "6nqhS9CEhmvSRKYEVReEVYm7D8Y9cB7fLHz3viqKqc4X"),
    (89_856_129, "7FksRp5DoPTQiV4aPNxyfiki9qEwHYsdb5vqdXoFbk8n"),
    (89_856_176, "DTKrDextCoY4UGFRrgLNkoN18qCQMbj7yQhQAtKER418"),
    (89_856_225, "9rZe97pE6pQuAUDMxFsCqFScsHbESDsnTCs3CjoqpUX2"),
    (89_856_229, "DUPGW3t1c7LNGEo6Uv6drJXNTpkc9MUK1CFjjzxARD66"),
    (89_856_233, "RortUbJeW7rftg9iu7LtkcDB5X5ToduYutywKExMZzz"),
    (89_856_240, "2g4uV3QsNB9zDxoCrUfUjGgAyWUEJzWnreV9TtF46rEA"),
    (89_856_285, "9MvsKvyFXQ4WHDrwrt2vizXmzKidxSZUCY4NNwfGraL7"),
    (89_856_300, "EopokmUBgCLdTMcQZeicv26WPh1VWZfFBnFiLadquDJF"),
    (89_856_312, "qfMNnS939kZVNVcK6Qd94oPa5NLugMNe4NJR3u2F2ak"),
    (89_856_373, "68nir1Yq9hSeT9Ld7gvpRTkrSd6mKhgmUnBMFN1g4Qs"),
    (89_856_396, "8s4BqT66w3uSDUFZzyeKQ4bPaUrneDfisnRnmP2xVVfg"),
    (89_856_405, "4ReJ8KL63nPhcvhnmC6he1JMLTNV4keXpPVY45pDjPDs"),
    (89_856_422, "DWmWSYxoZ1HMjVobeyBjDrpzaPuKh7GvQzE6oZuUd4w6"),
    (89_856_429, "DUGRJhxVwBajPu8xsZCb6M2PaBSVZHPtqn2561gqCGTb"),
    (89_856_433, "3oQCtrkYoum24Kgn1zbNShshCwxVLoBVnYX6tcHD2kWZ"),
    (89_856_468, "9kzUtEEmpFfbWi7oZar4q84z9b6MY8Ver7dcf6wVYr8c"),
    (89_856_476, "FEfwMmPZjREAiXBfcy1E8ZCmZNSsn1bioUiXS3rtQoD8"),
    (89_856_482, "HxyNeeKBtjo5qVTL2qcxk9hjgdrQ9dGW6hBvkNqk2E7Y"),
    (89_856_496, "J1kkRLhyCAmL6oYqioGGNk4GcSTSmhfnNbRk9iY3BtE8"),
    (89_856_532, "9pTF4qKNPm5Vv6gMbRaZG7ERsuGCBseptci9cbyUWHTX"),
    (89_856_552, "2K4Y7qAc6X8fGKLMcg13Y9SJ8wV3Ms5nhMWoDobf5H4c"),
    (89_856_560, "HzSLfaNJ74QFMijVu9q791fy9M7ZLschXnoQR16yp8Hx"),
    (89_856_580, "98ijWmbJ4PkwnUsQQA7YrFuB9ziRu97wRTnyLLJFuzpH"),
];

#[derive(Debug)]
struct Arguments {
    extraction: PathBuf,
    extraction_sha256: String,
    gap_audit: PathBuf,
    gap_audit_sha256: String,
    block_metadata: PathBuf,
    block_metadata_sha256: String,
    ticks_per_slot: u64,
    output: PathBuf,
    receipt: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GapAudit {
    schema: String,
    summary: GapSummary,
    gaps: Vec<Gap>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GapSummary {
    gap_runs: usize,
    skipped_slots: u64,
    post_gap_blocks_requiring_original_entries: usize,
    total_boundaries_in_post_gap_blocks: u64,
    hidden_intermediate_boundaries: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Gap {
    previous_present: u64,
    post_gap_block: u64,
    skipped: u64,
    boundaries: u64,
    key_prefix: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RpcResponse {
    jsonrpc: String,
    id: u64,
    result: Option<BlockMetadata>,
    error: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BlockMetadata {
    blockhash: String,
    parent_slot: u64,
    previous_blockhash: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FormatSchema {
    Current,
    LegacyNoSignatureCount,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Extraction {
    schema: String,
    format_schema: FormatSchema,
    input: ExtractionInput,
    ticks_per_slot: u64,
    target_count: usize,
    records: Vec<TargetRecord>,
    publication_authorized: bool,
    runtime_route_promotion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExtractionInput {
    path: String,
    bytes: u64,
    sha256: String,
    device: u64,
    inode: u64,
    links: u64,
    uid: u32,
    gid: u32,
    mode: String,
    modified_unix_seconds: i64,
    modified_nanoseconds: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TargetRecord {
    slot: u64,
    block_id: u32,
    frame_index: u64,
    frame_offset: u64,
    frame_length: usize,
    entry_count: usize,
    tick_entry_count: u64,
    transaction_entry_count: u64,
    transaction_count: u64,
    signature_count: Option<u64>,
    total_num_hashes: u64,
    expected_boundaries: u64,
    boundaries: Vec<Boundary>,
    final_entry_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Boundary {
    tick_ordinal: u64,
    entry_index: usize,
    hash: String,
    hash_hex: String,
}

#[derive(Debug, Serialize)]
struct BoundaryOutput<'a> {
    schema: &'static str,
    slots: &'a [TargetRecord],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct BlockzillaInputBinding {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ReceiptSlot {
    previous_present: u64,
    post_gap_block: u64,
    skipped: u64,
    boundaries: u64,
    key_prefix: String,
    boundary_tick_ordinals: Vec<u64>,
    hidden_boundary_hashes: Vec<String>,
    canonical_final_blockhash: String,
    canonical_final_blockhash_match: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Receipt {
    schema: String,
    gap_audit: String,
    gap_audit_sha256: String,
    block_metadata: String,
    block_metadata_sha256: String,
    extraction: String,
    extraction_sha256: String,
    format_schema: FormatSchema,
    blockzilla_input: BlockzillaInputBinding,
    ticks_per_slot: u64,
    output: String,
    output_sha256: String,
    gap_runs: usize,
    skipped_slots: u64,
    total_boundaries: u64,
    hidden_intermediate_boundaries: u64,
    canonical_final_blockhash_matches: bool,
    hidden_intermediate_boundaries_distinct: bool,
    all_boundary_hashes_distinct: bool,
    source_kind: String,
    recorded_at_unix_seconds: u64,
    slots: Vec<ReceiptSlot>,
    publication_authorized: bool,
    runtime_route_promotion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Debug)]
struct SealedBytes {
    bytes: Vec<u8>,
    sha256: String,
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} --extraction ABSOLUTE_JSON --extraction-sha256 HEX \\\n         --gap-audit ABSOLUTE_JSON --gap-audit-sha256 HEX \\\n         --block-metadata ABSOLUTE_JSON --block-metadata-sha256 HEX \\\n         --ticks-per-slot 64 --output ABSOLUTE_JSON --receipt ABSOLUTE_JSON"
    )
}

fn next_value(
    arguments: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> Result<OsString, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_u64(value: OsString, label: &str) -> Result<u64, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{label} is not valid UTF-8"))?
        .parse()
        .map_err(|error| format!("invalid {label}: {error}"))
}

fn parse_sha256(value: OsString, label: &str) -> Result<String, String> {
    let value = value
        .into_string()
        .map_err(|_| format!("{label} is not valid UTF-8"))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be 64 lowercase hexadecimal digits"));
    }
    Ok(value)
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "jetstreamer-blockzilla-boundary-collect".to_string());
    let mut extraction = None;
    let mut extraction_sha256 = None;
    let mut gap_audit = None;
    let mut gap_audit_sha256 = None;
    let mut block_metadata = None;
    let mut block_metadata_sha256 = None;
    let mut ticks_per_slot = None;
    let mut output = None;
    let mut receipt = None;
    while let Some(option) = arguments.next() {
        let option = option
            .to_str()
            .ok_or_else(|| "option is not valid UTF-8".to_string())?;
        macro_rules! one_path {
            ($target:ident) => {{
                let value = PathBuf::from(next_value(&mut arguments, option)?);
                if $target.replace(value).is_some() {
                    return Err(format!("{option} was supplied more than once"));
                }
            }};
        }
        macro_rules! one_sha {
            ($target:ident, $label:literal) => {{
                let value = parse_sha256(next_value(&mut arguments, option)?, $label)?;
                if $target.replace(value).is_some() {
                    return Err(format!("{option} was supplied more than once"));
                }
            }};
        }
        match option {
            "--extraction" => one_path!(extraction),
            "--extraction-sha256" => one_sha!(extraction_sha256, "extraction SHA-256"),
            "--gap-audit" => one_path!(gap_audit),
            "--gap-audit-sha256" => one_sha!(gap_audit_sha256, "gap-audit SHA-256"),
            "--block-metadata" => one_path!(block_metadata),
            "--block-metadata-sha256" => {
                one_sha!(block_metadata_sha256, "block-metadata SHA-256")
            }
            "--ticks-per-slot" => {
                let value = parse_u64(next_value(&mut arguments, option)?, "ticks per slot")?;
                if ticks_per_slot.replace(value).is_some() {
                    return Err("--ticks-per-slot was supplied more than once".into());
                }
            }
            "--output" => one_path!(output),
            "--receipt" => one_path!(receipt),
            value => return Err(format!("unknown option {value:?}\n{}", usage(&program))),
        }
    }
    let result = Arguments {
        extraction: extraction.ok_or_else(|| usage(&program))?,
        extraction_sha256: extraction_sha256.ok_or_else(|| usage(&program))?,
        gap_audit: gap_audit.ok_or_else(|| usage(&program))?,
        gap_audit_sha256: gap_audit_sha256.ok_or_else(|| usage(&program))?,
        block_metadata: block_metadata.ok_or_else(|| usage(&program))?,
        block_metadata_sha256: block_metadata_sha256.ok_or_else(|| usage(&program))?,
        ticks_per_slot: ticks_per_slot.ok_or_else(|| usage(&program))?,
        output: output.ok_or_else(|| usage(&program))?,
        receipt: receipt.ok_or_else(|| usage(&program))?,
    };
    if result.ticks_per_slot != EXPECTED_TICKS_PER_SLOT {
        return Err(format!(
            "epoch 208 requires exactly {EXPECTED_TICKS_PER_SLOT} ticks per slot"
        ));
    }
    let paths = [
        &result.extraction,
        &result.gap_audit,
        &result.block_metadata,
        &result.output,
        &result.receipt,
    ];
    for path in paths {
        if !path.is_absolute() {
            return Err(format!("path must be absolute: {}", path.display()));
        }
    }
    for (index, path) in paths.iter().enumerate() {
        if paths[..index].contains(path) {
            return Err(format!("paths must be distinct: {}", path.display()));
        }
    }
    Ok(result)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn stable_metadata(path: &Path, before: &fs::Metadata, after: &fs::Metadata) -> Result<(), String> {
    let identity = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mode(),
            metadata.uid(),
            metadata.gid(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.nlink(),
        )
    };
    if identity(before) != identity(after) {
        return Err(format!(
            "sealed input changed while reading: {}",
            path.display()
        ));
    }
    Ok(())
}

fn read_sealed(path: &Path, expected_sha256: &str, maximum: u64) -> Result<SealedBytes, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("resolve sealed input {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!(
            "sealed input path is not canonical: {}",
            path.display()
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open sealed input {}: {error}", path.display()))?;
    let before = file
        .metadata()
        .map_err(|error| format!("stat sealed input {}: {error}", path.display()))?;
    if !before.is_file() || before.nlink() != 1 {
        return Err(format!(
            "sealed input is not a singly linked regular file: {}",
            path.display()
        ));
    }
    if before.permissions().mode() & 0o022 != 0 {
        return Err(format!(
            "sealed input is group- or world-writable: {}",
            path.display()
        ));
    }
    if before.len() == 0 || before.len() > maximum {
        return Err(format!(
            "sealed input {} has {} bytes, expected 1..={maximum}",
            path.display(),
            before.len()
        ));
    }
    let capacity = usize::try_from(before.len()).map_err(|_| {
        format!(
            "sealed input is too large for this platform: {}",
            path.display()
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read sealed input {}: {error}", path.display()))?;
    let after_fd = file
        .metadata()
        .map_err(|error| format!("restat sealed input {}: {error}", path.display()))?;
    let after_path = fs::symlink_metadata(path)
        .map_err(|error| format!("restat sealed input path {}: {error}", path.display()))?;
    stable_metadata(path, &before, &after_fd)?;
    stable_metadata(path, &before, &after_path)?;
    if bytes.len() as u64 != before.len() {
        return Err(format!("sealed input length changed: {}", path.display()));
    }
    let sha256 = hex(&Sha256::digest(&bytes));
    if sha256 != expected_sha256 {
        return Err(format!("sealed input SHA-256 differs: {}", path.display()));
    }
    Ok(SealedBytes { bytes, sha256 })
}

fn parse_json<T: for<'de> Deserialize<'de>>(input: &SealedBytes, label: &str) -> Result<T, String> {
    serde_json::from_slice(&input.bytes).map_err(|error| format!("parse {label} JSON: {error}"))
}

fn validate_hash(value: &str, label: &str) -> Result<[u8; 32], String> {
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|error| format!("{label} is not base58: {error}"))?;
    decoded
        .try_into()
        .map_err(|decoded: Vec<u8>| format!("{label} has {} bytes, expected 32", decoded.len()))
}

fn validate_audit(audit: &GapAudit) -> Result<(), String> {
    if audit.schema != AUDIT_SCHEMA {
        return Err("gap audit has the wrong schema".into());
    }
    if audit.gaps.len() != EXPECTED_GAP_RUNS {
        return Err(format!(
            "gap audit has {} gaps, expected {EXPECTED_GAP_RUNS}",
            audit.gaps.len()
        ));
    }
    for (index, (gap, expected)) in audit.gaps.iter().zip(EXPECTED_GAPS).enumerate() {
        let tuple = (
            gap.previous_present,
            gap.post_gap_block,
            gap.skipped,
            gap.boundaries,
        );
        if tuple != expected {
            return Err(format!(
                "gap audit entry {index} is {tuple:?}, expected {expected:?}"
            ));
        }
        if gap.post_gap_block.checked_sub(gap.previous_present + 1) != Some(gap.skipped)
            || gap.boundaries != gap.skipped + 1
        {
            return Err(format!(
                "gap arithmetic is invalid for slot {}",
                gap.post_gap_block
            ));
        }
        if gap.key_prefix != format!("{:016X}", gap.post_gap_block) {
            return Err(format!(
                "gap key prefix is invalid for slot {}",
                gap.post_gap_block
            ));
        }
    }
    let summary = &audit.summary;
    if summary.gap_runs != EXPECTED_GAP_RUNS
        || summary.skipped_slots != EXPECTED_SKIPPED_SLOTS
        || summary.post_gap_blocks_requiring_original_entries != EXPECTED_GAP_RUNS
        || summary.total_boundaries_in_post_gap_blocks != EXPECTED_TOTAL_BOUNDARIES
        || summary.hidden_intermediate_boundaries != EXPECTED_SKIPPED_SLOTS
    {
        return Err("gap-audit summary does not match the fixed epoch-208 census".into());
    }
    Ok(())
}

fn validate_metadata(
    responses: Vec<RpcResponse>,
    gaps: &[Gap],
) -> Result<BTreeMap<u64, String>, String> {
    if responses.len() != EXPECTED_GAP_RUNS {
        return Err(format!(
            "block metadata has {} responses, expected {EXPECTED_GAP_RUNS}",
            responses.len()
        ));
    }
    let expected: BTreeMap<u64, &Gap> = gaps.iter().map(|gap| (gap.post_gap_block, gap)).collect();
    let expected_blockhashes: BTreeMap<u64, &str> =
        EXPECTED_FINAL_BLOCKHASHES.into_iter().collect();
    let mut result = BTreeMap::new();
    for response in responses {
        if response.jsonrpc != "2.0" || response.error.is_some() {
            return Err(format!(
                "block metadata RPC response {} is invalid",
                response.id
            ));
        }
        let metadata = response
            .result
            .ok_or_else(|| format!("block metadata RPC response {} has no result", response.id))?;
        let gap = expected
            .get(&response.id)
            .ok_or_else(|| format!("block metadata contains unexpected slot {}", response.id))?;
        if metadata.parent_slot != gap.previous_present
            || response.id.checked_sub(metadata.parent_slot + 1) != Some(gap.skipped)
        {
            return Err(format!(
                "canonical parent-slot arithmetic differs for slot {}",
                response.id
            ));
        }
        validate_hash(
            &metadata.blockhash,
            &format!("slot {} blockhash", response.id),
        )?;
        if expected_blockhashes.get(&response.id).copied() != Some(&metadata.blockhash) {
            return Err(format!(
                "block metadata differs from the fixed canonical blockhash for slot {}",
                response.id
            ));
        }
        validate_hash(
            &metadata.previous_blockhash,
            &format!("slot {} previous blockhash", response.id),
        )?;
        if result.insert(response.id, metadata.blockhash).is_some() {
            return Err(format!("block metadata repeats slot {}", response.id));
        }
    }
    if result.len() != expected.len() || result.keys().ne(expected.keys()) {
        return Err("block metadata does not exactly cover the epoch-208 gaps".into());
    }
    Ok(result)
}

fn validate_extraction(
    extraction: &Extraction,
    gaps: &[Gap],
    blockhashes: &BTreeMap<u64, String>,
) -> Result<Vec<ReceiptSlot>, String> {
    if extraction.schema != EXTRACTION_SCHEMA
        || extraction.ticks_per_slot != EXPECTED_TICKS_PER_SLOT
        || extraction.target_count != EXPECTED_GAP_RUNS
        || extraction.records.len() != EXPECTED_GAP_RUNS
    {
        return Err("Blockzilla extraction header does not match epoch 208".into());
    }
    if extraction.publication_authorized
        || extraction.runtime_route_promotion_authorized
        || extraction.remote_mutations
        || extraction.r2_mutations
    {
        return Err("Blockzilla extraction unexpectedly grants authority".into());
    }
    if !Path::new(&extraction.input.path).is_absolute()
        || extraction.input.bytes == 0
        || extraction.input.links != 1
    {
        return Err("Blockzilla extraction input identity is invalid".into());
    }
    let input_mode = u32::from_str_radix(&extraction.input.mode, 8)
        .map_err(|error| format!("Blockzilla input mode is invalid: {error}"))?;
    if input_mode & 0o222 != 0 {
        return Err("Blockzilla extraction was not produced from a read-only input".into());
    }
    parse_sha256(
        OsString::from(&extraction.input.sha256),
        "Blockzilla input SHA-256",
    )?;
    let expected: BTreeMap<u64, &Gap> = gaps.iter().map(|gap| (gap.post_gap_block, gap)).collect();
    let mut seen_slots = BTreeSet::new();
    let mut all_hashes = BTreeSet::new();
    let mut receipt_slots = Vec::with_capacity(EXPECTED_GAP_RUNS);
    let mut total_boundaries = 0_u64;
    let mut hidden_boundaries = 0_u64;
    let mut previous_slot = None;
    for record in &extraction.records {
        if let Some(previous) = previous_slot
            && record.slot <= previous
        {
            return Err("Blockzilla extraction records are not in strict slot order".into());
        }
        previous_slot = Some(record.slot);
        if !seen_slots.insert(record.slot) {
            return Err(format!(
                "Blockzilla extraction repeats slot {}",
                record.slot
            ));
        }
        let gap = expected.get(&record.slot).ok_or_else(|| {
            format!(
                "Blockzilla extraction contains unexpected slot {}",
                record.slot
            )
        })?;
        if record.expected_boundaries != gap.boundaries
            || record.boundaries.len() as u64 != gap.boundaries
            || record.tick_entry_count
                != gap
                    .boundaries
                    .checked_mul(EXPECTED_TICKS_PER_SLOT)
                    .ok_or_else(|| format!("slot {} tick count overflow", record.slot))?
        {
            return Err(format!("boundary count differs for slot {}", record.slot));
        }
        let canonical = blockhashes
            .get(&record.slot)
            .ok_or_else(|| format!("canonical blockhash is missing for slot {}", record.slot))?;
        let mut hashes = Vec::with_capacity(record.boundaries.len());
        let mut ordinals = Vec::with_capacity(record.boundaries.len());
        let mut previous_entry = None;
        for (index, boundary) in record.boundaries.iter().enumerate() {
            let expected_ordinal = EXPECTED_TICKS_PER_SLOT * (index as u64 + 1);
            if boundary.tick_ordinal != expected_ordinal {
                return Err(format!(
                    "boundary ordinal differs for slot {} index {index}",
                    record.slot
                ));
            }
            if let Some(previous) = previous_entry
                && boundary.entry_index <= previous
            {
                return Err(format!(
                    "boundary entry indexes are not increasing for slot {}",
                    record.slot
                ));
            }
            if boundary.entry_index >= record.entry_count {
                return Err(format!(
                    "boundary entry index is outside slot {} record",
                    record.slot
                ));
            }
            previous_entry = Some(boundary.entry_index);
            let decoded = validate_hash(
                &boundary.hash,
                &format!("slot {} boundary {index}", record.slot),
            )?;
            if boundary.hash_hex != hex(&decoded) {
                return Err(format!(
                    "base58 and hexadecimal boundary hashes differ for slot {} index {index}",
                    record.slot
                ));
            }
            if !all_hashes.insert(boundary.hash.clone()) {
                return Err(format!(
                    "PoH boundary hash repeats across epoch-208 targets at slot {} index {index}",
                    record.slot
                ));
            }
            hashes.push(boundary.hash.clone());
            ordinals.push(boundary.tick_ordinal);
        }
        if hashes.last() != Some(canonical) || record.final_entry_hash.as_ref() != Some(canonical) {
            return Err(format!(
                "recovered final boundary differs from canonical blockhash for slot {}",
                record.slot
            ));
        }
        let hidden = hashes[..hashes.len() - 1].to_vec();
        if hidden.len() as u64 != gap.skipped {
            return Err(format!(
                "hidden-boundary count differs for slot {}",
                record.slot
            ));
        }
        total_boundaries += gap.boundaries;
        hidden_boundaries += gap.skipped;
        receipt_slots.push(ReceiptSlot {
            previous_present: gap.previous_present,
            post_gap_block: gap.post_gap_block,
            skipped: gap.skipped,
            boundaries: gap.boundaries,
            key_prefix: gap.key_prefix.clone(),
            boundary_tick_ordinals: ordinals,
            hidden_boundary_hashes: hidden,
            canonical_final_blockhash: canonical.clone(),
            canonical_final_blockhash_match: true,
        });
    }
    if seen_slots.len() != expected.len()
        || seen_slots.iter().ne(expected.keys())
        || total_boundaries != EXPECTED_TOTAL_BOUNDARIES
        || hidden_boundaries != EXPECTED_SKIPPED_SLOTS
        || all_hashes.len() as u64 != EXPECTED_TOTAL_BOUNDARIES
    {
        return Err(
            "Blockzilla extraction does not exactly cover the fixed epoch-208 census".into(),
        );
    }
    Ok(receipt_slots)
}

fn output_parent(path: &Path) -> Result<&Path, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", path.display()))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("stat output parent {}: {error}", parent.display()))?;
    let canonical = fs::canonicalize(parent)
        .map_err(|error| format!("resolve output parent {}: {error}", parent.display()))?;
    if canonical != parent {
        return Err(format!(
            "output parent path is not canonical: {}",
            parent.display()
        ));
    }
    if !metadata.is_dir() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(format!(
            "output parent is not a trusted non-writable directory: {}",
            parent.display()
        ));
    }
    Ok(parent)
}

fn install_no_clobber(path: &Path, bytes: &[u8]) -> Result<&'static str, String> {
    let parent = output_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(format!(
                    "existing output is not a singly linked regular file: {}",
                    path.display()
                ));
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(format!(
                    "existing output is not private: {}",
                    path.display()
                ));
            }
            let existing = read_existing(path, &metadata)?;
            if existing == bytes {
                return Ok("already-present-identical");
            }
            return Err(format!(
                "refusing to overwrite different output: {}",
                path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect output {}: {error}", path.display())),
    }
    let filename = path
        .file_name()
        .ok_or_else(|| format!("output has no filename: {}", path.display()))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{filename}.{}.tmp", process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("create temporary output {}: {error}", temporary.display()))?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("fsync {}: {error}", temporary.display()))?;
        fs::hard_link(&temporary, path)
            .map_err(|error| format!("publish {}: {error}", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync output parent {}: {error}", parent.display()))?;
        Ok("created")
    })();
    drop(file);
    if let Err(error) = fs::remove_file(&temporary)
        && result.is_ok()
    {
        return Err(format!(
            "output was published but temporary cleanup failed for {}: {error}",
            temporary.display()
        ));
    }
    result
}

fn read_existing(path: &Path, before: &fs::Metadata) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open existing output {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read existing output {}: {error}", path.display()))?;
    let after = file
        .metadata()
        .map_err(|error| format!("restat existing output {}: {error}", path.display()))?;
    let after_path = fs::symlink_metadata(path)
        .map_err(|error| format!("restat existing output path {}: {error}", path.display()))?;
    stable_metadata(path, before, &after)?;
    stable_metadata(path, before, &after_path)?;
    Ok(bytes)
}

fn same_receipt_identity(left: &Receipt, right: &Receipt) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.recorded_at_unix_seconds = 0;
    right.recorded_at_unix_seconds = 0;
    left == right
}

fn install_receipt(path: &Path, receipt: &Receipt) -> Result<&'static str, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(format!(
                    "existing receipt is not a private regular file: {}",
                    path.display()
                ));
            }
            let bytes = read_existing(path, &metadata)?;
            let existing: Receipt = serde_json::from_slice(&bytes)
                .map_err(|error| format!("parse existing receipt {}: {error}", path.display()))?;
            if same_receipt_identity(&existing, receipt) {
                return Ok("already-present-identical");
            }
            return Err(format!(
                "refusing to overwrite different receipt: {}",
                path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect receipt {}: {error}", path.display())),
    }
    let mut bytes = serde_json::to_vec_pretty(receipt)
        .map_err(|error| format!("serialize receipt: {error}"))?;
    bytes.push(b'\n');
    install_no_clobber(path, &bytes)
}

fn collect(arguments: &Arguments) -> Result<serde_json::Value, String> {
    let audit_bytes = read_sealed(
        &arguments.gap_audit,
        &arguments.gap_audit_sha256,
        MAX_AUDIT_BYTES,
    )?;
    let metadata_bytes = read_sealed(
        &arguments.block_metadata,
        &arguments.block_metadata_sha256,
        MAX_METADATA_BYTES,
    )?;
    let extraction_bytes = read_sealed(
        &arguments.extraction,
        &arguments.extraction_sha256,
        MAX_EXTRACTION_BYTES,
    )?;
    let audit: GapAudit = parse_json(&audit_bytes, "gap audit")?;
    validate_audit(&audit)?;
    let responses: Vec<RpcResponse> = parse_json(&metadata_bytes, "block metadata")?;
    let blockhashes = validate_metadata(responses, &audit.gaps)?;
    let extraction: Extraction = parse_json(&extraction_bytes, "Blockzilla extraction")?;
    let receipt_slots = validate_extraction(&extraction, &audit.gaps, &blockhashes)?;

    let mut output_bytes = serde_json::to_vec_pretty(&BoundaryOutput {
        schema: OUTPUT_SCHEMA,
        slots: &extraction.records,
    })
    .map_err(|error| format!("serialize boundary output: {error}"))?;
    output_bytes.push(b'\n');
    let output_sha256 = hex(&Sha256::digest(&output_bytes));
    let receipt = Receipt {
        schema: RECEIPT_SCHEMA.to_string(),
        gap_audit: arguments.gap_audit.display().to_string(),
        gap_audit_sha256: audit_bytes.sha256,
        block_metadata: arguments.block_metadata.display().to_string(),
        block_metadata_sha256: metadata_bytes.sha256,
        extraction: arguments.extraction.display().to_string(),
        extraction_sha256: extraction_bytes.sha256,
        format_schema: extraction.format_schema,
        blockzilla_input: BlockzillaInputBinding {
            path: extraction.input.path,
            bytes: extraction.input.bytes,
            sha256: extraction.input.sha256,
        },
        ticks_per_slot: arguments.ticks_per_slot,
        output: arguments.output.display().to_string(),
        output_sha256,
        gap_runs: EXPECTED_GAP_RUNS,
        skipped_slots: EXPECTED_SKIPPED_SLOTS,
        total_boundaries: EXPECTED_TOTAL_BOUNDARIES,
        hidden_intermediate_boundaries: EXPECTED_SKIPPED_SLOTS,
        canonical_final_blockhash_matches: true,
        hidden_intermediate_boundaries_distinct: true,
        all_boundary_hashes_distinct: true,
        source_kind: "blockzilla-compact-v2-poh".to_string(),
        recorded_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
            .as_secs(),
        slots: receipt_slots,
        publication_authorized: false,
        runtime_route_promotion_authorized: false,
        remote_mutations: false,
        r2_mutations: false,
    };
    let output_outcome = install_no_clobber(&arguments.output, &output_bytes)?;
    let receipt_outcome = install_receipt(&arguments.receipt, &receipt)?;
    Ok(serde_json::json!({
        "outcome": if output_outcome == "created" || receipt_outcome == "created" {
            "collected"
        } else {
            "already-collected"
        },
        "output": arguments.output,
        "output_sha256": receipt.output_sha256,
        "receipt": arguments.receipt,
        "gap_runs": EXPECTED_GAP_RUNS,
        "total_boundaries": EXPECTED_TOTAL_BOUNDARIES,
        "hidden_intermediate_boundaries": EXPECTED_SKIPPED_SLOTS,
        "publication_authorized": false,
        "runtime_route_promotion_authorized": false,
        "remote_mutations": false,
        "r2_mutations": false,
    }))
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    let result = collect(&arguments)?;
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|error| format!("serialize result: {error}"))?
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

    fn hash_bytes(value: u64) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes[8] = 1;
        bytes
    }

    fn test_audit() -> GapAudit {
        let gaps = EXPECTED_GAPS
            .iter()
            .map(
                |&(previous_present, post_gap_block, skipped, boundaries)| Gap {
                    previous_present,
                    post_gap_block,
                    skipped,
                    boundaries,
                    key_prefix: format!("{post_gap_block:016X}"),
                },
            )
            .collect();
        GapAudit {
            schema: AUDIT_SCHEMA.to_string(),
            summary: GapSummary {
                gap_runs: EXPECTED_GAP_RUNS,
                skipped_slots: EXPECTED_SKIPPED_SLOTS,
                post_gap_blocks_requiring_original_entries: EXPECTED_GAP_RUNS,
                total_boundaries_in_post_gap_blocks: EXPECTED_TOTAL_BOUNDARIES,
                hidden_intermediate_boundaries: EXPECTED_SKIPPED_SLOTS,
            },
            gaps,
        }
    }

    fn test_evidence() -> (GapAudit, BTreeMap<u64, String>, Extraction) {
        let audit = test_audit();
        let mut serial = 1_u64;
        let mut blockhashes = BTreeMap::new();
        let mut records = Vec::new();
        for gap in &audit.gaps {
            let mut boundaries = Vec::new();
            for index in 0..gap.boundaries {
                let bytes = if index + 1 == gap.boundaries {
                    validate_hash(
                        EXPECTED_FINAL_BLOCKHASHES
                            .iter()
                            .find_map(|(slot, hash)| (*slot == gap.post_gap_block).then_some(*hash))
                            .unwrap(),
                        "test canonical blockhash",
                    )
                    .unwrap()
                } else {
                    let bytes = hash_bytes(serial);
                    serial += 1;
                    bytes
                };
                boundaries.push(Boundary {
                    tick_ordinal: EXPECTED_TICKS_PER_SLOT * (index + 1),
                    entry_index: index as usize,
                    hash: bs58::encode(bytes).into_string(),
                    hash_hex: hex(&bytes),
                });
            }
            let final_hash = boundaries.last().unwrap().hash.clone();
            blockhashes.insert(gap.post_gap_block, final_hash.clone());
            records.push(TargetRecord {
                slot: gap.post_gap_block,
                block_id: 1,
                frame_index: records.len() as u64,
                frame_offset: 10,
                frame_length: 100,
                entry_count: boundaries.len(),
                tick_entry_count: gap.boundaries * EXPECTED_TICKS_PER_SLOT,
                transaction_entry_count: 0,
                transaction_count: 0,
                signature_count: Some(0),
                total_num_hashes: 10,
                expected_boundaries: gap.boundaries,
                boundaries,
                final_entry_hash: Some(final_hash),
            });
        }
        let extraction = Extraction {
            schema: EXTRACTION_SCHEMA.to_string(),
            format_schema: FormatSchema::Current,
            input: ExtractionInput {
                path: "/immutable/epoch-208/poh.wincode".to_string(),
                bytes: 100,
                sha256: "11".repeat(32),
                device: 1,
                inode: 2,
                links: 1,
                uid: 0,
                gid: 0,
                mode: "0444".to_string(),
                modified_unix_seconds: 1,
                modified_nanoseconds: 0,
            },
            ticks_per_slot: EXPECTED_TICKS_PER_SLOT,
            target_count: EXPECTED_GAP_RUNS,
            records,
            publication_authorized: false,
            runtime_route_promotion_authorized: false,
            remote_mutations: false,
            r2_mutations: false,
        };
        (audit, blockhashes, extraction)
    }

    fn test_metadata(audit: &GapAudit, blockhashes: &BTreeMap<u64, String>) -> Vec<RpcResponse> {
        audit
            .gaps
            .iter()
            .enumerate()
            .map(|(index, gap)| RpcResponse {
                jsonrpc: "2.0".to_string(),
                id: gap.post_gap_block,
                result: Some(BlockMetadata {
                    blockhash: blockhashes[&gap.post_gap_block].clone(),
                    parent_slot: gap.previous_present,
                    previous_blockhash: bs58::encode(hash_bytes(10_000 + index as u64))
                        .into_string(),
                }),
                error: None,
            })
            .collect()
    }

    fn json_bytes(value: &impl Serialize) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn accepts_exact_epoch208_census() {
        let (audit, blockhashes, extraction) = test_evidence();
        validate_audit(&audit).unwrap();
        let receipt_slots = validate_extraction(&extraction, &audit.gaps, &blockhashes).unwrap();
        assert_eq!(receipt_slots.len(), EXPECTED_GAP_RUNS);
        assert_eq!(
            receipt_slots
                .iter()
                .map(|slot| slot.hidden_boundary_hashes.len() as u64)
                .sum::<u64>(),
            EXPECTED_SKIPPED_SLOTS
        );
    }

    #[test]
    fn rejects_a_different_slot_even_with_matching_totals() {
        let mut audit = test_audit();
        audit.gaps[0].post_gap_block += 1;
        audit.gaps[0].key_prefix = format!("{:016X}", audit.gaps[0].post_gap_block);
        assert!(validate_audit(&audit).unwrap_err().contains("entry 0"));
    }

    #[test]
    fn rejects_wrong_canonical_final_hash() {
        let (audit, mut blockhashes, extraction) = test_evidence();
        let slot = audit.gaps[0].post_gap_block;
        blockhashes.insert(slot, bs58::encode(hash_bytes(999)).into_string());
        assert!(
            validate_extraction(&extraction, &audit.gaps, &blockhashes)
                .unwrap_err()
                .contains("canonical blockhash")
        );
    }

    #[test]
    fn rejects_wrong_canonical_parent_arithmetic() {
        let (audit, blockhashes, _) = test_evidence();
        let mut metadata = test_metadata(&audit, &blockhashes);
        metadata[0].result.as_mut().unwrap().parent_slot -= 1;
        assert!(
            validate_metadata(metadata, &audit.gaps)
                .unwrap_err()
                .contains("parent-slot arithmetic")
        );
    }

    #[test]
    fn rejects_substituted_canonical_metadata_blockhash() {
        let (audit, blockhashes, _) = test_evidence();
        let mut metadata = test_metadata(&audit, &blockhashes);
        metadata[0].result.as_mut().unwrap().blockhash =
            bs58::encode(hash_bytes(99_999)).into_string();
        assert!(
            validate_metadata(metadata, &audit.gaps)
                .unwrap_err()
                .contains("fixed canonical blockhash")
        );
    }

    #[test]
    fn rejects_boundary_hash_repeated_across_slots() {
        let (audit, blockhashes, mut extraction) = test_evidence();
        extraction.records[1].boundaries[0].hash = extraction.records[0].boundaries[0].hash.clone();
        extraction.records[1].boundaries[0].hash_hex =
            extraction.records[0].boundaries[0].hash_hex.clone();
        assert!(
            validate_extraction(&extraction, &audit.gaps, &blockhashes)
                .unwrap_err()
                .contains("repeats across")
        );
    }

    #[test]
    fn no_clobber_output_is_private_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let output = directory.path().join("output.json");
        assert_eq!(install_no_clobber(&output, b"one\n").unwrap(), "created");
        assert_eq!(
            install_no_clobber(&output, b"one\n").unwrap(),
            "already-present-identical"
        );
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(install_no_clobber(&output, b"two\n").is_err());
    }

    #[test]
    fn complete_collection_is_private_idempotent_and_non_authorizing() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (audit, blockhashes, extraction) = test_evidence();
        let metadata = test_metadata(&audit, &blockhashes);
        let audit_path = directory.path().join("audit.json");
        let metadata_path = directory.path().join("metadata.json");
        let extraction_path = directory.path().join("extraction.json");
        let output = directory.path().join("boundaries.json");
        let receipt = directory.path().join("receipt.json");
        let audit_bytes = json_bytes(&audit);
        let metadata_bytes = json_bytes(&metadata);
        let extraction_bytes = json_bytes(&extraction);
        write_private(&audit_path, &audit_bytes);
        write_private(&metadata_path, &metadata_bytes);
        write_private(&extraction_path, &extraction_bytes);
        let arguments = Arguments {
            extraction: extraction_path,
            extraction_sha256: hex(&Sha256::digest(&extraction_bytes)),
            gap_audit: audit_path,
            gap_audit_sha256: hex(&Sha256::digest(&audit_bytes)),
            block_metadata: metadata_path,
            block_metadata_sha256: hex(&Sha256::digest(&metadata_bytes)),
            ticks_per_slot: EXPECTED_TICKS_PER_SLOT,
            output: output.clone(),
            receipt: receipt.clone(),
        };
        let first = collect(&arguments).unwrap();
        assert_eq!(first["outcome"], "collected");
        let second = collect(&arguments).unwrap();
        assert_eq!(second["outcome"], "already-collected");
        let receipt: Receipt = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        assert_eq!(receipt.total_boundaries, EXPECTED_TOTAL_BOUNDARIES);
        assert!(receipt.all_boundary_hashes_distinct);
        assert!(!receipt.publication_authorized);
        assert!(!receipt.runtime_route_promotion_authorized);
        assert!(!receipt.remote_mutations);
        assert!(!receipt.r2_mutations);
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
