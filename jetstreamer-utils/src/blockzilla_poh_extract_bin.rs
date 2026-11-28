use {
    serde::Serialize,
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        ffi::OsString,
        fs::{self, File, OpenOptions},
        io::{self, BufReader, Cursor, Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
        path::{Path, PathBuf},
        process,
    },
};

const MAX_FRAME_BYTES: usize = 256 * 1024 * 1024;
const MAX_ENTRIES_PER_BLOCK: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Schema {
    Current,
    LegacyNoSignatureCount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    num_hashes: u64,
    hash: [u8; 32],
    tx_count: u32,
    signature_count: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    block_id: u32,
    slot: u64,
    entries: Vec<Entry>,
}

#[derive(Debug)]
struct Arguments {
    input: PathBuf,
    output: PathBuf,
    ticks_per_slot: u64,
    targets: BTreeMap<u64, u64>,
}

#[derive(Debug, Serialize)]
struct FileIdentity {
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

#[derive(Debug, Serialize)]
struct Boundary {
    tick_ordinal: u64,
    entry_index: usize,
    hash: String,
    hash_hex: String,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
struct Output {
    schema: &'static str,
    format_schema: Schema,
    input: FileIdentity,
    ticks_per_slot: u64,
    target_count: usize,
    records: Vec<TargetRecord>,
    publication_authorized: bool,
    runtime_route_promotion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

struct HashingReader<R> {
    inner: R,
    digest: Sha256,
    bytes_read: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes_read: 0,
        }
    }

    fn position(&self) -> u64 {
        self.bytes_read
    }

    fn finish(self) -> String {
        hex(&self.digest.finalize())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.digest.update(&buffer[..read]);
        self.bytes_read = self
            .bytes_read
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("input byte count overflow"))?;
        Ok(read)
    }
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} INPUT --ticks-per-slot N --target SLOT:BOUNDARIES \\\n+         [--target SLOT:BOUNDARIES ...] --output ABSOLUTE_JSON"
    )
}

fn parse_u64(value: &OsString, field: &str) -> Result<u64, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{field} is not valid UTF-8"))?
        .parse::<u64>()
        .map_err(|error| format!("invalid {field}: {error}"))
}

fn parse_target(value: &OsString) -> Result<(u64, u64), String> {
    let text = value
        .to_str()
        .ok_or_else(|| "target is not valid UTF-8".to_string())?;
    let (slot, boundaries) = text
        .split_once(':')
        .ok_or_else(|| format!("target {text:?} must be SLOT:BOUNDARIES"))?;
    let slot = slot
        .parse::<u64>()
        .map_err(|error| format!("invalid target slot {slot:?}: {error}"))?;
    let boundaries = boundaries
        .parse::<u64>()
        .map_err(|error| format!("invalid target boundary count {boundaries:?}: {error}"))?;
    if boundaries == 0 {
        return Err(format!("target slot {slot} has zero expected boundaries"));
    }
    Ok((slot, boundaries))
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "jetstreamer-blockzilla-poh-extract".to_string());
    let input = arguments.next().ok_or_else(|| usage(&program))?;
    if input.as_os_str().as_bytes().starts_with(b"-") {
        return Err(usage(&program));
    }
    let input = PathBuf::from(input);
    let mut output = None;
    let mut ticks_per_slot = None;
    let mut targets = BTreeMap::new();
    while let Some(option) = arguments.next() {
        match option.to_str() {
            Some("--output") => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--output requires a path".to_string())?;
                if output.replace(PathBuf::from(value)).is_some() {
                    return Err("--output was supplied more than once".into());
                }
            }
            Some("--ticks-per-slot") => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--ticks-per-slot requires a value".to_string())?;
                if ticks_per_slot
                    .replace(parse_u64(&value, "ticks per slot")?)
                    .is_some()
                {
                    return Err("--ticks-per-slot was supplied more than once".into());
                }
            }
            Some("--target") => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--target requires SLOT:BOUNDARIES".to_string())?;
                let (slot, boundaries) = parse_target(&value)?;
                if targets.insert(slot, boundaries).is_some() {
                    return Err(format!("target slot {slot} was supplied more than once"));
                }
            }
            Some(value) => return Err(format!("unknown option {value:?}\n{}", usage(&program))),
            None => return Err("an option is not valid UTF-8".into()),
        }
    }
    let output = output.ok_or_else(|| "--output is required".to_string())?;
    let ticks_per_slot =
        ticks_per_slot.ok_or_else(|| "--ticks-per-slot is required".to_string())?;
    if ticks_per_slot == 0 {
        return Err("--ticks-per-slot must be positive".into());
    }
    if targets.is_empty() {
        return Err("at least one --target is required".into());
    }
    for (field, path) in [("input", &input), ("output", &output)] {
        if !path.is_absolute() {
            return Err(format!("{field} path must be absolute: {}", path.display()));
        }
    }
    if input == output {
        return Err("input and output paths must differ".into());
    }
    Ok(Arguments {
        input,
        output,
        ticks_per_slot,
        targets,
    })
}

fn read_uleb128<R: Read>(reader: &mut R, bits: u32, eof_ok: bool) -> Result<Option<u128>, String> {
    let max_bytes = bits.div_ceil(7) as usize;
    let max_value = if bits == 128 {
        u128::MAX
    } else {
        (1_u128 << bits) - 1
    };
    let mut value = 0_u128;
    for index in 0..max_bytes {
        let mut byte = [0_u8; 1];
        match reader.read_exact(&mut byte) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && index == 0 && eof_ok => {
                return Ok(None);
            }
            Err(error) => return Err(format!("truncated LEB128 integer: {error}")),
        }
        let payload = u128::from(byte[0] & 0x7f);
        let shift = (index * 7) as u32;
        if payload > (u128::MAX >> shift) {
            return Err("LEB128 integer overflow".into());
        }
        value |= payload << shift;
        if byte[0] & 0x80 == 0 {
            if value > max_value {
                return Err("LEB128 integer exceeds field width".into());
            }
            if index != 0 && payload == 0 {
                return Err("non-minimal LEB128 integer".into());
            }
            return Ok(Some(value));
        }
    }
    Err("LEB128 integer overflow".into())
}

fn required_uleb128<R: Read>(reader: &mut R, bits: u32, field: &str) -> Result<u128, String> {
    read_uleb128(reader, bits, false)?.ok_or_else(|| format!("missing {field}"))
}

fn parse_record(bytes: &[u8], schema: Schema) -> Result<Record, String> {
    let mut cursor = Cursor::new(bytes);
    let block_id = u32::try_from(required_uleb128(&mut cursor, 32, "block_id")?)
        .map_err(|_| "block_id overflow".to_string())?;
    let slot = u64::try_from(required_uleb128(&mut cursor, 64, "slot")?)
        .map_err(|_| "slot overflow".to_string())?;
    let count_u64 = u64::try_from(required_uleb128(&mut cursor, 64, "entries length")?)
        .map_err(|_| "entries length overflow".to_string())?;
    let count =
        usize::try_from(count_u64).map_err(|_| "entries length exceeds usize".to_string())?;
    if count > MAX_ENTRIES_PER_BLOCK {
        return Err(format!(
            "entries length {count} exceeds {MAX_ENTRIES_PER_BLOCK}"
        ));
    }
    let mut entries = Vec::with_capacity(count.min(1024));
    for index in 0..count {
        let num_hashes = u64::try_from(required_uleb128(&mut cursor, 64, "num_hashes")?)
            .map_err(|_| format!("entry {index} num_hashes overflow"))?;
        let mut hash = [0_u8; 32];
        cursor
            .read_exact(&mut hash)
            .map_err(|error| format!("entry {index} truncated hash: {error}"))?;
        let tx_count = u32::try_from(required_uleb128(&mut cursor, 32, "tx_count")?)
            .map_err(|_| format!("entry {index} tx_count overflow"))?;
        let signature_count = match schema {
            Schema::Current => Some(
                u32::try_from(required_uleb128(&mut cursor, 32, "signature_count")?)
                    .map_err(|_| format!("entry {index} signature_count overflow"))?,
            ),
            Schema::LegacyNoSignatureCount => None,
        };
        entries.push(Entry {
            num_hashes,
            hash,
            tx_count,
            signature_count,
        });
    }
    if cursor.position() != bytes.len() as u64 {
        return Err(format!(
            "record has {} trailing bytes",
            bytes.len() as u64 - cursor.position()
        ));
    }
    Ok(Record {
        block_id,
        slot,
        entries,
    })
}

fn decode_record(bytes: &[u8], known_schema: Option<Schema>) -> Result<(Record, Schema), String> {
    if let Some(schema) = known_schema {
        return parse_record(bytes, schema).map(|record| (record, schema));
    }
    let current = parse_record(bytes, Schema::Current);
    let legacy = parse_record(bytes, Schema::LegacyNoSignatureCount);
    match (current, legacy) {
        (Ok(current), Err(_)) => Ok((current, Schema::Current)),
        (Err(_), Ok(legacy)) => Ok((legacy, Schema::LegacyNoSignatureCount)),
        (Ok(current), Ok(_)) if current.entries.is_empty() => Ok((current, Schema::Current)),
        (Ok(_), Ok(_)) => Err("record is schema-ambiguous".into()),
        (Err(current_error), Err(legacy_error)) => Err(format!(
            "record failed current ({current_error}) and legacy ({legacy_error}) decoding"
        )),
    }
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

fn extract_target(
    record: &Record,
    frame_index: u64,
    frame_offset: u64,
    frame_length: usize,
    ticks_per_slot: u64,
    expected_boundaries: u64,
) -> Result<TargetRecord, String> {
    let expected_ticks = expected_boundaries
        .checked_mul(ticks_per_slot)
        .ok_or_else(|| format!("slot {} expected tick count overflow", record.slot))?;
    let mut tick_ordinal = 0_u64;
    let mut transaction_entry_count = 0_u64;
    let mut transaction_count = 0_u64;
    let mut signature_count = Some(0_u64);
    let mut total_num_hashes = 0_u64;
    let mut boundaries = Vec::new();
    for (entry_index, entry) in record.entries.iter().enumerate() {
        total_num_hashes = total_num_hashes
            .checked_add(entry.num_hashes)
            .ok_or_else(|| format!("slot {} PoH hash count overflow", record.slot))?;
        if entry.tx_count == 0 {
            tick_ordinal = tick_ordinal
                .checked_add(1)
                .ok_or_else(|| format!("slot {} tick count overflow", record.slot))?;
            if tick_ordinal.is_multiple_of(ticks_per_slot) {
                boundaries.push(Boundary {
                    tick_ordinal,
                    entry_index,
                    hash: bs58::encode(entry.hash).into_string(),
                    hash_hex: hex(&entry.hash),
                });
            }
        } else {
            transaction_entry_count = transaction_entry_count
                .checked_add(1)
                .ok_or_else(|| format!("slot {} transaction entry count overflow", record.slot))?;
            transaction_count = transaction_count
                .checked_add(u64::from(entry.tx_count))
                .ok_or_else(|| format!("slot {} transaction count overflow", record.slot))?;
        }
        signature_count = match (signature_count, entry.signature_count) {
            (Some(total), Some(count)) => Some(
                total
                    .checked_add(u64::from(count))
                    .ok_or_else(|| format!("slot {} signature count overflow", record.slot))?,
            ),
            _ => None,
        };
    }
    if tick_ordinal != expected_ticks {
        return Err(format!(
            "slot {} has {tick_ordinal} tick entries, expected {expected_ticks} for {expected_boundaries} boundaries at {ticks_per_slot} ticks per slot",
            record.slot
        ));
    }
    if boundaries.len() != expected_boundaries as usize {
        return Err(format!(
            "slot {} yielded {} boundaries, expected {expected_boundaries}",
            record.slot,
            boundaries.len()
        ));
    }
    Ok(TargetRecord {
        slot: record.slot,
        block_id: record.block_id,
        frame_index,
        frame_offset,
        frame_length,
        entry_count: record.entries.len(),
        tick_entry_count: tick_ordinal,
        transaction_entry_count,
        transaction_count,
        signature_count,
        total_num_hashes,
        expected_boundaries,
        boundaries,
        final_entry_hash: record
            .entries
            .last()
            .map(|entry| bs58::encode(entry.hash).into_string()),
    })
}

fn stable_metadata(path: &Path, before: &fs::Metadata, after: &fs::Metadata) -> Result<(), String> {
    let before_identity = (
        before.dev(),
        before.ino(),
        before.len(),
        before.mode(),
        before.uid(),
        before.gid(),
        before.mtime(),
        before.mtime_nsec(),
        before.nlink(),
    );
    let after_identity = (
        after.dev(),
        after.ino(),
        after.len(),
        after.mode(),
        after.uid(),
        after.gid(),
        after.mtime(),
        after.mtime_nsec(),
        after.nlink(),
    );
    if before_identity != after_identity {
        return Err(format!(
            "input identity changed while reading: {}",
            path.display()
        ));
    }
    Ok(())
}

fn scan(arguments: &Arguments) -> Result<Output, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&arguments.input)
        .map_err(|error| format!("open {}: {error}", arguments.input.display()))?;
    let before = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", arguments.input.display()))?;
    if !before.is_file() {
        return Err(format!(
            "{} is not a regular file",
            arguments.input.display()
        ));
    }
    if before.nlink() != 1 {
        return Err(format!(
            "{} has {} links, expected exactly one",
            arguments.input.display(),
            before.nlink()
        ));
    }
    if before.permissions().mode() & 0o222 != 0 {
        return Err(format!("{} is writable", arguments.input.display()));
    }

    let mut reader = HashingReader::new(BufReader::with_capacity(8 * 1024 * 1024, file));
    let mut schema = None;
    let mut found = BTreeSet::new();
    let mut previous_slot = None;
    let mut frame_index = 0_u64;
    let mut records = Vec::new();
    loop {
        let frame_offset = reader.position();
        let Some(frame_len_raw) = read_uleb128(&mut reader, 32, true)? else {
            break;
        };
        let frame_len =
            usize::try_from(frame_len_raw).map_err(|_| "frame length exceeds usize".to_string())?;
        if frame_len > MAX_FRAME_BYTES {
            return Err(format!(
                "frame {frame_index} at offset {frame_offset} has {frame_len} bytes, above {MAX_FRAME_BYTES}"
            ));
        }
        let mut bytes = vec![0_u8; frame_len];
        reader.read_exact(&mut bytes).map_err(|error| {
            format!("frame {frame_index} at offset {frame_offset} is truncated: {error}")
        })?;
        let (record, record_schema) = decode_record(&bytes, schema)
            .map_err(|error| format!("frame {frame_index} at offset {frame_offset}: {error}"))?;
        if !record.entries.is_empty() {
            match schema {
                Some(known) if known != record_schema => {
                    return Err(format!(
                        "frame {frame_index} changes schema from {known:?} to {record_schema:?}"
                    ));
                }
                None => schema = Some(record_schema),
                Some(_) => {}
            }
        }
        if let Some(previous) = previous_slot
            && record.slot <= previous
        {
            return Err(format!(
                "slot order is not strictly increasing: {previous} then {}",
                record.slot
            ));
        }
        previous_slot = Some(record.slot);
        if let Some(expected_boundaries) = arguments.targets.get(&record.slot) {
            found.insert(record.slot);
            records.push(extract_target(
                &record,
                frame_index,
                frame_offset,
                frame_len,
                arguments.ticks_per_slot,
                *expected_boundaries,
            )?);
        }
        frame_index = frame_index
            .checked_add(1)
            .ok_or_else(|| "frame index overflow".to_string())?;
    }
    if reader.position() != before.len() {
        return Err(format!(
            "read {} bytes but input length is {}",
            reader.position(),
            before.len()
        ));
    }
    let input_sha256 = reader.finish();
    let after = fs::symlink_metadata(&arguments.input)
        .map_err(|error| format!("restat {}: {error}", arguments.input.display()))?;
    stable_metadata(&arguments.input, &before, &after)?;
    let missing: Vec<u64> = arguments
        .targets
        .keys()
        .copied()
        .filter(|slot| !found.contains(slot))
        .collect();
    if !missing.is_empty() {
        return Err(format!("target slots not found: {missing:?}"));
    }
    records.sort_by_key(|record| record.slot);
    let format_schema = schema
        .ok_or_else(|| "input contains no nonempty record to identify its schema".to_string())?;
    Ok(Output {
        schema: "jetstreamer-blockzilla-poh-targets-v1",
        format_schema,
        input: FileIdentity {
            path: arguments.input.display().to_string(),
            bytes: before.len(),
            sha256: input_sha256,
            device: before.dev(),
            inode: before.ino(),
            links: before.nlink(),
            uid: before.uid(),
            gid: before.gid(),
            mode: format!("{:04o}", before.mode() & 0o7777),
            modified_unix_seconds: before.mtime(),
            modified_nanoseconds: before.mtime_nsec(),
        },
        ticks_per_slot: arguments.ticks_per_slot,
        target_count: arguments.targets.len(),
        records,
        publication_authorized: false,
        runtime_route_promotion_authorized: false,
        remote_mutations: false,
        r2_mutations: false,
    })
}

fn install_no_clobber(path: &Path, bytes: &[u8]) -> Result<&'static str, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", path.display()))?;
    let parent_metadata = fs::metadata(parent)
        .map_err(|error| format!("stat output parent {}: {error}", parent.display()))?;
    if !parent_metadata.is_dir() {
        return Err(format!(
            "output parent is not a directory: {}",
            parent.display()
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(format!(
                    "existing output is not a singly linked regular file: {}",
                    path.display()
                ));
            }
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(format!(
                    "existing output is group- or world-writable: {}",
                    path.display()
                ));
            }
            let mut existing = Vec::new();
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .and_then(|mut file| file.read_to_end(&mut existing))
                .map_err(|error| format!("read existing output {}: {error}", path.display()))?;
            let after = fs::symlink_metadata(path)
                .map_err(|error| format!("restat existing output {}: {error}", path.display()))?;
            stable_metadata(path, &metadata, &after)?;
            if existing == bytes {
                return Ok("already-present-identical");
            }
            return Err(format!(
                "refusing to overwrite different output: {}",
                path.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "inspect existing output {}: {error}",
                path.display()
            ));
        }
    }
    let filename = path
        .file_name()
        .ok_or_else(|| format!("output has no filename: {}", path.display()))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{filename}.{}.tmp", process::id()));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("create temporary output {}: {error}", temporary.display()))?;
    let result = (|| {
        output
            .write_all(bytes)
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        output
            .sync_all()
            .map_err(|error| format!("fsync {}: {error}", temporary.display()))?;
        fs::hard_link(&temporary, path)
            .map_err(|error| format!("publish {}: {error}", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync output parent {}: {error}", parent.display()))?;
        Ok("created")
    })();
    drop(output);
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

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    let output = scan(&arguments)?;
    let mut bytes =
        serde_json::to_vec_pretty(&output).map_err(|error| format!("serialize output: {error}"))?;
    bytes.push(b'\n');
    let outcome = install_no_clobber(&arguments.output, &bytes)?;
    println!(
        "{}",
        serde_json::json!({
            "outcome": outcome,
            "output": arguments.output,
            "output_sha256": hex(&Sha256::digest(&bytes)),
            "target_count": output.target_count,
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
    use std::os::unix::fs::symlink;

    fn uleb(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                return bytes;
            }
        }
    }

    fn current_record(slot: u64, entries: &[(u64, u8, u32, u32)]) -> Vec<u8> {
        let mut bytes = uleb(7);
        bytes.extend(uleb(slot));
        bytes.extend(uleb(entries.len() as u64));
        for (num_hashes, hash_byte, tx_count, signatures) in entries {
            bytes.extend(uleb(*num_hashes));
            bytes.extend([*hash_byte; 32]);
            bytes.extend(uleb(u64::from(*tx_count)));
            bytes.extend(uleb(u64::from(*signatures)));
        }
        bytes
    }

    #[test]
    fn parses_current_record_and_extracts_slot_boundaries() {
        let entries = [
            (3, 1, 0, 0),
            (4, 2, 1, 2),
            (5, 3, 0, 0),
            (6, 4, 0, 0),
            (7, 5, 2, 3),
            (8, 6, 0, 0),
        ];
        let bytes = current_record(89_856_117, &entries);
        let record = parse_record(&bytes, Schema::Current).unwrap();
        let target = extract_target(&record, 0, 0, bytes.len(), 2, 2).unwrap();
        assert_eq!(target.tick_entry_count, 4);
        assert_eq!(target.transaction_entry_count, 2);
        assert_eq!(target.transaction_count, 3);
        assert_eq!(target.signature_count, Some(5));
        assert_eq!(target.boundaries.len(), 2);
        assert_eq!(target.boundaries[0].tick_ordinal, 2);
        assert_eq!(target.boundaries[0].entry_index, 2);
        assert_eq!(target.boundaries[1].tick_ordinal, 4);
        assert_eq!(target.boundaries[1].entry_index, 5);
        assert_eq!(
            target.final_entry_hash,
            Some(bs58::encode([6_u8; 32]).into_string())
        );
    }

    #[test]
    fn rejects_wrong_boundary_count() {
        let bytes = current_record(9, &[(1, 1, 0, 0), (1, 2, 0, 0)]);
        let record = parse_record(&bytes, Schema::Current).unwrap();
        let error = extract_target(&record, 0, 0, bytes.len(), 2, 2).unwrap_err();
        assert!(error.contains("has 2 tick entries, expected 4"));
    }

    #[test]
    fn rejects_nonminimal_uleb128() {
        let error = read_uleb128(&mut Cursor::new([0x80, 0x00]), 64, false).unwrap_err();
        assert_eq!(error, "non-minimal LEB128 integer");
    }

    #[test]
    fn rejects_trailing_record_bytes() {
        let mut bytes = current_record(9, &[]);
        bytes.push(1);
        assert!(
            parse_record(&bytes, Schema::Current)
                .unwrap_err()
                .contains("trailing bytes")
        );
    }

    #[test]
    fn no_clobber_output_is_idempotent_but_rejects_changes() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.json");
        assert_eq!(install_no_clobber(&output, b"one\n").unwrap(), "created");
        assert_eq!(
            install_no_clobber(&output, b"one\n").unwrap(),
            "already-present-identical"
        );
        assert!(
            install_no_clobber(&output, b"two\n")
                .unwrap_err()
                .contains("refusing to overwrite")
        );
        assert_eq!(fs::read(output).unwrap(), b"one\n");
    }

    #[test]
    fn no_clobber_output_rejects_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, b"one\n").unwrap();
        let output = directory.path().join("output.json");
        symlink(&target, &output).unwrap();
        assert!(
            install_no_clobber(&output, b"one\n")
                .unwrap_err()
                .contains("not a singly linked regular file")
        );
    }
}
