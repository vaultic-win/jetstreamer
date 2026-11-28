//! Assemble the admitted private epoch 168 output from two qualified virtual archives.
use super::{
    EPOCH_END, INPUT, RETRY6, Result, SEAM, Selected, digest, hex, identity, invalid, number, open,
    open_sources, provenance, read_doc, require, selection, source_evidence, string,
};
use jetstreamer_horizon::archive::{
    ArchiveProvenance, ArchiveProvenanceV4, ArchiveWriterConfig, RuntimeSegmentSource,
    encode_archive_provenance, merge_checkpoint_restart_segments,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::{self, BufReader, Write},
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;

const UNIT: &str = "horizon-assemble-168-private-20261127-v1.service";
const SOURCE_UNIT: &str = "horizon-168-assembly-sources-20261127-v1.service";
const ORIGINAL_SOURCE_UNIT: &str = "horizon-qualify-168-assembly-sources-20261127-v1.service";
const SOURCE_TOOL_SHA: &str = "7569e2c958c4b478173af76c524d349c52198511d729affea4b980fbd6ccfb43";
const SOURCE_SEAL_SHA: &str = "72e025e7ce4bba74f5d6d744c7dcacae84f6eeb309e29d276588f14e783e268f";
const OUTPUT: &str = "/home/sol/.jetstreamer-private/epoch168-private-assembly-20261127-v1/output";
const ARCHIVE_CAP: u64 = 128 << 30;
const EVIDENCE_CAP: u64 = 64 << 20;

fn bound_doc(reference: &Value) -> Result<Value> {
    read_doc(
        Path::new(string(reference, "path")?),
        string(reference, "sha256")?,
        0,
    )
}

pub(crate) fn home_floor(directory: &File, minimum: u64, next: u64) -> io::Result<()> {
    let mut info = MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    let block = info.f_frsize;
    let aligned = next.div_ceil(block).saturating_mul(block);
    require(
        info.f_bavail.saturating_mul(block).saturating_sub(aligned) >= minimum,
        "output would cross the admitted HOME floor",
    )
}

pub(crate) struct GuardedOutput<'a> {
    epoch: u64,
    file: &'a mut File,
    directory: &'a File,
    floor: u64,
    written: u64,
    sha256: Sha256,
    last_progress: Instant,
}

impl<'a> GuardedOutput<'a> {
    pub(crate) fn new(file: &'a mut File, directory: &'a File, floor: u64, epoch: u64) -> Self {
        Self {
            file,
            directory,
            floor,
            epoch,
            written: 0,
            sha256: Sha256::new(),
            last_progress: Instant::now(),
        }
    }
    pub(crate) fn result(self) -> (u64, String) {
        (self.written, hex(&self.sha256.finalize()))
    }
}

impl Write for GuardedOutput<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        require(
            data.len() as u64 <= ARCHIVE_CAP - self.written,
            "archive exceeds its admitted allocation",
        )?;
        home_floor(self.directory, self.floor, data.len() as u64)?;
        let written = self.file.write(data)?;
        self.written += written as u64;
        self.sha256.update(&data[..written]);
        if self.last_progress.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "epoch {} private assembly wrote {} bytes",
                self.epoch, self.written
            );
            self.last_progress = Instant::now();
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn plan(path: &str, sha256: &str) -> Result<Value> {
    let plan = read_doc(Path::new(path), sha256, 0)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expires = number(&plan, "admission_expires_unix_seconds")?;
    require(
        plan["schema"] == "horizon-epoch168-private-assembly-plan-v1"
            && plan["unit"] == UNIT
            && plan["output_directory"] == OUTPUT
            && plan["maximum_archive_bytes"] == ARCHIVE_CAP
            && plan["evidence_allowance_bytes"] == EVIDENCE_CAP
            && plan["publication_authorized"] == false
            && number(&plan, "minimum_home_free_bytes")? > 0
            && number(&plan, "memory_max_bytes")? > 0
            && number(&plan, "cpu_quota_micros")? > 0
            && (now..=now + 600).contains(&expires),
        "epoch 168 assembly plan has a foreign scope or expired admission",
    )?;
    Ok(plan)
}

fn admission(plan: &Value) -> Result<Value> {
    let fit = bound_doc(&plan["admission"])?;
    let floor = number(plan, "minimum_home_free_bytes")?;
    let required = floor
        .checked_add(ARCHIVE_CAP + EVIDENCE_CAP)
        .ok_or_else(|| invalid("epoch 168 planned HOME charge overflows"))?;
    require(
        fit["schema"] == "horizon-epoch168-private-v4-assembly-admission-v1"
            && fit["epoch"] == 168
            && fit["unit"] == UNIT
            && fit["output_directory"] == OUTPUT
            && fit["qualification"] == plan["qualification"]
            && fit["minimum_home_free_bytes"] == floor
            && fit["maximum_archive_bytes"] == ARCHIVE_CAP
            && fit["evidence_allowance_bytes"] == EVIDENCE_CAP
            && fit["required_available_home_bytes"] == required
            && number(&fit, "available_home_bytes")? >= required
            && fit["booked_assembly_home_bytes"] == ARCHIVE_CAP + EVIDENCE_CAP
            && fit["memory_max_bytes"] == plan["memory_max_bytes"]
            && number(&fit, "required_available_memory_bytes")?
                >= number(plan, "memory_max_bytes")?
            && number(&fit, "available_memory_bytes")?
                >= number(&fit, "required_available_memory_bytes")?
            && number(&fit, "complete_cpu_quota_micros")? >= number(plan, "cpu_quota_micros")?
            && number(&fit, "complete_cpu_quota_micros")? <= 64_000_000
            && fit["cpu_quota_micros"] == plan["cpu_quota_micros"]
            && fit["admission_expires_unix_seconds"] == plan["admission_expires_unix_seconds"]
            && fit["swap_bytes"] == 0
            && fit["resource_credit_bytes"] == 0
            && fit["all_existing_commitments_retained"] == true
            && fit["fits"] == true
            && fit["publication_authorized"] == false,
        "epoch 168 plan does not preserve the fresh admitted resource envelope",
    )?;
    let basis = bound_doc(&fit["capacity_basis"])?;
    require(
        basis["resource_credit_bytes"] == 0,
        "epoch 168 fit uses unissued resource credit",
    )?;
    Ok(fit)
}

fn source_unit_matches(native: &Value, event: &Value) -> bool {
    matches!(
        native["unit"].as_str(),
        Some(SOURCE_UNIT | ORIGINAL_SOURCE_UNIT)
    ) && event["UNIT"] == native["unit"]
}

fn source_qualification(plan: &Value) -> Result<Value> {
    let native = bound_doc(&plan["qualification_native"])?;
    let event = &native["pid1_terminal_event"];
    require(
        native["schema"] == "horizon-epoch168-assembly-source-native-acceptance-v1"
            && source_unit_matches(&native, event)
            && native["source_tool_sha256"] == SOURCE_TOOL_SHA
            && native["source_tool_deployment"]["sha256"] == SOURCE_SEAL_SHA
            && native["qualified_report"] == plan["qualification"]
            && native["lineage"] == plan["lineage"]
            && event["INVOCATION_ID"] == native["invocation_id"]
            && event["_PID"] == "1"
            && event["_UID"] == "0"
            && event["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && native["archive_bytes_written"] == 0
            && native["publication_authorized"] == false,
        "epoch 168 source qualification lacks the exact completed native invocation",
    )?;
    let report = bound_doc(&plan["qualification"])?;
    require(
        report["schema"] == "horizon-epoch168-private-assembly-sources-v1"
            && report["epoch"] == 168
            && report["seam"] == SEAM
            && report["lineage"] == plan["lineage"]
            && report["boundary_decoder_run"] == true
            && report["physical_archive_bytes_written"] == 0
            && report["assembly_authorized"] == false
            && report["publication_authorized"] == false,
        "epoch 168 plan requires the exact successful source qualification",
    )?;
    Ok(report)
}

pub(in super::super) fn check_plan(path: &str, sha256: &str) -> Result<()> {
    let plan = plan(path, sha256)?;
    admission(&plan)?;
    source_qualification(&plan)?;
    bound_doc(&plan["lineage"])?;
    println!(
        "{}",
        json!({"schema":"horizon-epoch168-private-assembly-plan-checked-v1",
               "plan_sha256":sha256,"archive_bytes_written":0,"publication_authorized":false})
    );
    Ok(())
}

fn invocation(plan: &Value) -> Result<String> {
    let id = std::env::var("INVOCATION_ID")?;
    let group = format!("system.slice/{UNIT}");
    let cgroup = Path::new("/sys/fs/cgroup").join(&group);
    let cpu = fs::read_to_string(cgroup.join("cpu.max"))?;
    let mut values = cpu.split_whitespace();
    let quota = values
        .next()
        .ok_or_else(|| invalid("missing CPU quota"))?
        .parse::<u64>()?;
    let period = values
        .next()
        .ok_or_else(|| invalid("missing CPU period"))?
        .parse::<u64>()?;
    require(
        id.len() == 32
            && id.bytes().all(|byte| byte.is_ascii_hexdigit())
            && id.bytes().any(|byte| byte != b'0')
            && fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/{group}")
            && fs::read_to_string(cgroup.join("memory.max"))?.trim()
                == number(plan, "memory_max_bytes")?.to_string()
            && fs::read_to_string(cgroup.join("memory.swap.max"))?.trim() == "0"
            && quota.checked_mul(1_000_000)
                == period.checked_mul(number(plan, "cpu_quota_micros")?)
            && quota > 0
            && period > 0,
        "epoch 168 assembler is outside its admitted native invocation or limits",
    )?;
    Ok(id)
}

pub(in super::super) fn assemble(path: &str, sha256: &str) -> Result<()> {
    let plan = plan(path, sha256)?;
    let invocation = invocation(&plan)?;
    admission(&plan)?;
    let qualification = source_qualification(&plan)?;
    let lineage = bound_doc(&plan["lineage"])?;
    let (_, prefix_bytes) = source_evidence(&lineage)?;
    let selected = &qualification["selection"];

    let output_root = Path::new(OUTPUT);
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(output_root)?;
    let meta = directory.metadata()?;
    require(
        output_root.canonicalize()? == output_root
            && meta.uid() == 0
            && meta.mode() & 0o777 == 0o700
            && meta.dev() == fs::metadata("/home/sol")?.dev()
            && unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0
            && fs::read_dir(output_root)?.next().is_none(),
        "epoch 168 output directory is not empty, exclusive, root-owned, and HOME-backed",
    )?;
    let floor = number(&plan, "minimum_home_free_bytes")?;
    home_floor(&directory, floor, ARCHIVE_CAP + EVIDENCE_CAP)?;

    let mut sources = open_sources()?;
    let prefix_identity = identity(&sources.prefix)?;
    let suffix_identity = identity(&sources.suffix)?;
    let left = selection::cut(
        &mut sources.prefix,
        &sources.left.header,
        ArchiveProvenance::V2(sources.left.provenance.clone()),
        &sources.left.buckets,
        SEAM + 1,
    )?;
    let right = selection::cut(
        &mut sources.suffix,
        &sources.right.header,
        ArchiveProvenance::V2(sources.right.provenance.clone()),
        &sources.right.buckets,
        EPOCH_END,
    )?;
    require(
        left.len() == prefix_bytes
            && left.len() == number(selected, "selected_retry4_archive_bytes")?
            && right.len() == number(selected, "selected_retry6_archive_bytes")?,
        "reconstructed epoch 168 views differ from qualified byte extents",
    )?;
    let v4: ArchiveProvenanceV4 = provenance(
        &sources.left,
        &sources.right,
        &lineage,
        number(selected, "retry6_raw_start")?..number(selected, "retry6_raw_end_exclusive")?,
    )?;
    let encoded = encode_archive_provenance(&ArchiveProvenance::V4(v4.clone()))?;
    let provenance_sha = hex(&Sha256::digest(encoded));
    require(
        selected["v4_provenance_sha256"] == provenance_sha,
        "epoch 168 V4 provenance differs from the qualified bytes",
    )?;
    let source_readers = vec![
        RuntimeSegmentSource::new(
            BufReader::new(Selected::new(&mut sources.prefix, &left)),
            digest(string(&lineage, "retry4_selected_archive_sha256")?)?,
            string(&lineage["translated_v4_predecessor"], "last_blockhash")?.parse()?,
        ),
        RuntimeSegmentSource::new(
            BufReader::new(Selected::new(&mut sources.suffix, &right)),
            digest(string(selected, "selected_retry6_archive_sha256")?)?,
            string(selected, "retry6_last_blockhash")?.parse()?,
        ),
    ];
    let mut output = NamedTempFile::new_in(output_root)?;
    let sink = GuardedOutput::new(output.as_file_mut(), &directory, floor, 168);
    eprintln!("epoch 168 verifying selected source digests and assembling the V4 archive");
    let (mut sink, stats) = merge_checkpoint_restart_segments(
        source_readers,
        sink,
        ArchiveWriterConfig::default(),
        &v4,
    )?;
    sink.flush()?;
    let (bytes, archive_sha) = sink.result();
    output
        .as_file()
        .set_permissions(Permissions::from_mode(0o400))?;
    output.as_file().sync_all()?;
    require(
        stats.source_archives == 2
            && stats.slots_merged == 432_000
            && stats.output.slots == stats.slots_merged
            && stats.output.epochs == 1
            && stats.output.bytes_written == bytes
            && output.as_file().metadata()?.len() == bytes
            && v4.base.runtime_segments[1]
                .write_versions
                .archive_end_exclusive()
                == Some(stats.account_updates_rebased)
            && prefix_identity == identity(&sources.prefix)?
            && prefix_identity == identity(&open(Path::new(INPUT))?)?
            && suffix_identity == identity(&sources.suffix)?
            && suffix_identity == identity(&open(Path::new(RETRY6))?)?,
        "assembled count, output bytes, or source identities changed",
    )?;

    let archive_path = output_root.join("epoch-168.jet");
    let receipt_path = output_root.join("assembly.json");
    let receipt_bytes = serde_json::to_vec(&json!({
        "schema":"horizon-epoch168-private-v4-assembly-v1", "epoch":168,
        "unit":UNIT, "invocation_id":invocation, "plan":{"path":path,"sha256":sha256},
        "qualification":plan["qualification"], "lineage":plan["lineage"],
        "admission":plan["admission"], "qualification_native":plan["qualification_native"],
        "archive_path":archive_path, "archive_sha256":archive_sha, "archive_bytes":bytes,
        "provenance_sha256":provenance_sha, "slots":stats.slots_merged,
        "blocks":stats.output.blocks, "transactions":stats.output.transactions,
        "normalized_writes":stats.account_updates_rebased, "minimum_home_free_bytes":floor,
        "maximum_archive_bytes":ARCHIVE_CAP, "independent_verification_pending":true,
        "publication_authorized":false
    }))?;
    home_floor(&directory, floor, EVIDENCE_CAP)?;
    let mut receipt = NamedTempFile::new_in(output_root)?;
    receipt.write_all(&receipt_bytes)?;
    receipt.write_all(b"\n")?;
    receipt
        .as_file()
        .set_permissions(Permissions::from_mode(0o400))?;
    receipt.as_file().sync_all()?;
    let current = output_root.symlink_metadata()?;
    require(
        (meta.dev(), meta.ino()) == (current.dev(), current.ino()),
        "epoch 168 private output directory changed",
    )?;
    output.persist_noclobber(&archive_path)?;
    directory.sync_all()?;
    receipt.persist_noclobber(&receipt_path)?;
    directory.sync_all()?;
    println!("{}", receipt_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_receipt_and_manager_event_must_name_the_same_qualified_unit() {
        for unit in [SOURCE_UNIT, ORIGINAL_SOURCE_UNIT] {
            assert!(source_unit_matches(
                &json!({"unit":unit}),
                &json!({"UNIT":unit})
            ));
        }
        assert!(!source_unit_matches(
            &json!({"unit":SOURCE_UNIT}),
            &json!({"UNIT":ORIGINAL_SOURCE_UNIT})
        ));
        assert!(!source_unit_matches(
            &json!({"unit":"unrelated.service"}),
            &json!({"UNIT":"unrelated.service"})
        ));
    }

    #[test]
    fn output_checks_cap_and_floor_before_writing() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        let mut output = NamedTempFile::new_in(root.path()).unwrap();
        let mut writer = GuardedOutput {
            epoch: 168,
            file: output.as_file_mut(),
            directory: &directory,
            floor: 0,
            written: ARCHIVE_CAP - 1,
            sha256: Sha256::new(),
            last_progress: Instant::now(),
        };
        assert!(writer.write_all(b"too large").is_err());
        writer.written = 0;
        writer.floor = u64::MAX;
        assert!(writer.write_all(b"below floor").is_err());
        assert_eq!(writer.file.metadata().unwrap().len(), 0);
        writer.floor = 0;
        writer.write_all(b"admitted").unwrap();
        assert_eq!(writer.written, 8);
        assert_eq!(writer.sha256.finalize(), Sha256::digest(b"admitted"));
    }
}
