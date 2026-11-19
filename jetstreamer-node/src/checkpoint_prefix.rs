//! Convert an exactly closed source into a private dense prefix without altering it.
//! A semantic reread is not a native restore, canonical-root or publication receipt.
use crate::archive_checksum::{
    archive_file_identity, measure_open_archive, open_regular_nofollow,
    path_matches_archive_identity, rebind_validated_after_rename,
};
use jetstreamer_horizon::archive::{
    ArchiveReader, ArchiveWriterConfig, SemanticDigest, reencode_closed_checkpoint_prefix,
};
use solana_hash::Hash;
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Arc, Mutex, mpsc},
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct ProgressState {
    epoch: u64,
    phase: &'static str,
    started: Instant,
    last_progress: Instant,
}

impl ProgressState {
    fn log(&self, heartbeat: bool) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "operation=closed_checkpoint_prefix epoch={} phase={} timestamp_unix_millis={} elapsed_millis={} since_progress_millis={} heartbeat={} observational_only=true",
            self.epoch,
            self.phase,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            self.started.elapsed().as_millis(),
            self.last_progress.elapsed().as_millis(),
            heartbeat
        );
    }
}

/// Emits only phase/elapsed-time observations; it reads no resources or archive
/// bytes and never advances the progress clock merely for a heartbeat.
struct Progress {
    state: Arc<Mutex<ProgressState>>,
    stop: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
    complete: bool,
}

impl Progress {
    fn new(epoch: u64) -> Self {
        let now = Instant::now();
        let state = Arc::new(Mutex::new(ProgressState {
            epoch,
            phase: "measure_source",
            started: now,
            last_progress: now,
        }));
        let observed = state.clone();
        let (stop, receiver) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("prefixProgress".into())
            .spawn(move || {
                while matches!(
                    receiver.recv_timeout(Duration::from_secs(60)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    if let Ok(state) = observed.lock() {
                        state.log(true);
                    }
                }
            })
            .ok();
        if let Ok(state) = state.lock() {
            state.log(false);
        }
        Self {
            state,
            stop,
            thread,
            complete: false,
        }
    }
    fn phase(&self, name: &'static str) {
        if let Ok(mut state) = self.state.lock() {
            state.phase = name;
            state.last_progress = Instant::now();
            state.log(false);
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if !self.complete {
            if let Ok(mut state) = self.state.lock() {
                state.phase = "failed";
                state.log(false);
            }
        }
    }
}

pub struct ClosedPrefixRange {
    pub epoch: u64,
    pub first_slot: u64,
    pub intended_terminal: u64,
    pub selected_terminal: u64,
    pub terminal_blockhash: Hash,
}

pub struct ConvertedPrefix {
    pub source_sha256: [u8; 32],
    pub prefix_sha256: [u8; 32],
    pub semantic_sha256: [u8; 32],
    pub slot_count: u64,
}

/// Caller retains exclusive custody and the stopped producer's native evidence.
/// Output must be new in an owned private directory. Original bytes are retained
/// and remeasured; successful output receives a complete semantic reread before
/// no-clobber publication. Segment/native validation remains independent.
pub fn convert_closed_prefix(
    source_path: &Path,
    prefix_path: &Path,
    range: &ClosedPrefixRange,
) -> Result<ConvertedPrefix, String> {
    let io = |e: std::io::Error| e.to_string();
    let parent = prefix_path.parent().ok_or("prefix has no parent")?;
    if !source_path.is_absolute()
        || source_path.canonicalize().map_err(io)? != source_path
        || !prefix_path.is_absolute()
        || parent.canonicalize().map_err(io)? != parent
        || prefix_path.file_name().is_none()
        || range.first_slot > range.selected_terminal
        || range.selected_terminal >= range.intended_terminal
        || range.intended_terminal == u64::MAX
        || range.terminal_blockhash == Hash::default()
    {
        return Err("invalid closed checkpoint paths or proper-prefix range".into());
    }
    let parent_metadata = fs::symlink_metadata(parent).map_err(io)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err("checkpoint prefix requires an owned private directory".into());
    }
    match fs::symlink_metadata(prefix_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
        Ok(_) => return Err("checkpoint prefix destination already exists".into()),
    }
    let source = open_regular_nofollow(source_path).map_err(io)?;
    let mut progress = Progress::new(range.epoch);
    let before = measure_open_archive(&source).map_err(io)?;
    let mut header_reader =
        ArchiveReader::open(source.try_clone().map_err(io)?).map_err(|e| e.to_string())?;
    let expected_count = range.intended_terminal - range.first_slot + 1;
    let prefix_count = range.selected_terminal - range.first_slot + 1;
    if header_reader.header().epoch != range.epoch
        || header_reader.header().slot_start != range.first_slot
        || header_reader.header().slot_count != expected_count
        || header_reader
            .has_complete_slot_coverage()
            .map_err(|e| e.to_string())?
    {
        return Err("closed source differs from intended incomplete replay range".into());
    }
    drop(header_reader);
    progress.phase("convert_source");
    let temporary = tempfile::Builder::new()
        .prefix(".checkpoint-prefix-")
        .tempfile_in(parent)
        .map_err(io)?;
    let (_, transformed) = reencode_closed_checkpoint_prefix(
        source.try_clone().map_err(io)?,
        temporary.as_file(),
        ArchiveWriterConfig::default(),
        prefix_count,
        range.terminal_blockhash,
    )
    .map_err(|e| e.to_string())?;
    temporary.as_file().sync_all().map_err(io)?;
    progress.phase("semantic_reread");
    let mut reader =
        ArchiveReader::open(temporary.reopen().map_err(io)?).map_err(|e| e.to_string())?;
    let mut semantic = SemanticDigest::new();
    if !reader
        .has_complete_slot_coverage()
        .map_err(|e| e.to_string())?
        || reader
            .read_slots(range.first_slot, prefix_count, &mut semantic)
            .map_err(|e| e.to_string())?
            != prefix_count
        || semantic.finish().map_err(|e| e.to_string())? != transformed.output_semantic_sha256
    {
        return Err("converted checkpoint prefix failed complete semantic reread".into());
    }
    drop(reader);
    progress.phase("remeasure_and_revalidate");
    let prefix = measure_open_archive(temporary.as_file()).map_err(io)?;
    let after = measure_open_archive(&source).map_err(io)?;
    if after.identity != before.identity
        || after.sha256 != before.sha256
        || !path_matches_archive_identity(source_path, before.identity).map_err(io)?
    {
        return Err("closed checkpoint source changed during conversion".into());
    }
    progress.phase("publish_private_prefix");
    let file = temporary
        .persist_noclobber(prefix_path)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(io)?;
    File::open(parent).and_then(|f| f.sync_all()).map_err(io)?;
    let prefix = rebind_validated_after_rename(&file, prefix).map_err(io)?;
    let final_parent = fs::symlink_metadata(parent).map_err(io)?;
    if !path_matches_archive_identity(prefix_path, prefix.identity).map_err(io)?
        || file.metadata().map_err(io)?.nlink() != 1
        || archive_file_identity(&source).map_err(io)? != before.identity
        || !path_matches_archive_identity(source_path, before.identity).map_err(io)?
        || final_parent.dev() != parent_metadata.dev()
        || final_parent.ino() != parent_metadata.ino()
        || final_parent.mode() != parent_metadata.mode()
        || final_parent.uid() != parent_metadata.uid()
        || final_parent.gid() != parent_metadata.gid()
    {
        return Err("converted checkpoint prefix changed at publication".into());
    }
    progress.phase("complete");
    progress.complete = true;
    Ok(ConvertedPrefix {
        source_sha256: before.sha256,
        prefix_sha256: prefix.sha256,
        semantic_sha256: transformed.output_semantic_sha256,
        slot_count: prefix_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn range() -> ClosedPrefixRange {
        ClosedPrefixRange {
            epoch: 0,
            first_slot: 1,
            intended_terminal: 3,
            selected_terminal: 1,
            terminal_blockhash: Hash::new_from_array([1; 32]),
        }
    }

    #[test]
    fn retained_output_and_source_alias_are_rejected_without_writes() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.path().join("closed.jet");
        let output = root.path().join("prefix.jet");
        fs::write(&source, b"retained source").unwrap();
        fs::write(&output, b"retained output").unwrap();
        assert!(convert_closed_prefix(&source, &output, &range()).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"retained output");
        let alias = root.path().join("alias.jet");
        symlink(&source, &alias).unwrap();
        let new_output = root.path().join("new.jet");
        assert!(convert_closed_prefix(&alias, &new_output, &range()).is_err());
        assert!(!new_output.exists());
        assert_eq!(fs::read(&source).unwrap(), b"retained source");
    }

    #[test]
    fn prefix_requires_private_parent_and_a_proper_range_before_decoding() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("closed.jet");
        let output = root.path().join("prefix.jet");
        fs::write(&source, b"retained source").unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(convert_closed_prefix(&source, &output, &range()).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut full = range();
        full.selected_terminal = full.intended_terminal;
        assert!(convert_closed_prefix(&source, &output, &full).is_err());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}
