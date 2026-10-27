//! Opt-in fixed 136 gate. No worker Initialize can precede supervisor release.
use super::*;
use std::os::{
    fd::AsRawFd,
    unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
};
#[path = "../../jetstreamer-utils/src/epoch136_suffix_scope.rs"]
mod scope;

fn invalid(message: impl Into<String>) -> HistoricalRuntimeError {
    HistoricalRuntimeError::Io(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}
fn required(ok: bool, message: &str) -> Result<(), HistoricalRuntimeError> {
    if ok { Ok(()) } else { Err(invalid(message)) }
}

/// Called before binding/copying the archive. The existing descriptor copy
/// performs the full compressed SHA/size check; its second copy is in ROOT.
pub(super) fn bind_if_enabled(
    profile: WorkerProfile,
    initialization: &mut HistoricalInitialization,
) -> Result<bool, HistoricalRuntimeError> {
    let Some(socket) = env::var_os(scope::SOCKET_ENV) else {
        return Ok(false);
    };
    bind_scope(profile, initialization, Path::new(&socket))?;
    Ok(true)
}
fn bind_scope(
    profile: WorkerProfile,
    initialization: &mut HistoricalInitialization,
    socket: &Path,
) -> Result<(), HistoricalRuntimeError> {
    required(
        socket == Path::new(scope::ROOT).join("entry.sock"),
        "foreign 136 gate socket",
    )?;
    required(
        profile.backend_id == "solana-v1.4.25",
        "136 gate backend differs",
    )?;
    let HistoricalInitialization::SnapshotArchive(s) = initialization else {
        return Err(invalid("136 gate forbids genesis initialization"));
    };
    let root = Path::new(scope::ROOT);
    let accounts = "J6ef2VSpLh1ofwD4zXGLAJkNs4i6yZ5JzTr5qG1jBSNN"
        .parse::<solana_hash::Hash>()
        .map_err(|_| invalid("136 compiled accounts hash"))?
        .to_bytes();
    required(
        s.archive_path == root.join("inputs").join(scope::SNAPSHOT_NAME)
            && s.ledger_path == root.join("ledger")
            && s.scratch_parent.as_deref()
                == Some(worker_scratch_parent(&root.join("scratch")).as_path())
            && s.expected_slot == scope::BOOTSTRAP
            && s.expected_accounts_hash == accounts,
        "136 gate initialization scope differs",
    )?;
    let digest = hex_digest(scope::SNAPSHOT_SHA)?;
    required(
        s.expected_archive_size
            .is_none_or(|v| v == scope::SNAPSHOT_BYTES)
            && s.expected_archive_sha256.is_none_or(|v| v == digest),
        "136 gate conflicting archive binding",
    )?;
    s.expected_archive_size = Some(scope::SNAPSHOT_BYTES);
    s.expected_archive_sha256 = Some(digest);
    Ok(())
}

fn hex_digest(s: &str) -> Result<[u8; 32], HistoricalRuntimeError> {
    required(
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "136 digest syntax/length",
    )?;
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| invalid("136 digest syntax"))?;
    }
    Ok(out)
}

pub(super) fn before_initialize(
    worker_pid: u32,
    digest: [u8; 32],
) -> Result<(), HistoricalRuntimeError> {
    required(
        digest == hex_digest(scope::WORKER_SHA)?,
        "136 gate worker digest differs",
    )?;
    let status = fs::read_to_string("/proc/self/status")?;
    let field = |key: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .unwrap_or("")
            .trim()
    };
    required(
        field("Uid:") == "1001\t1001\t1001\t1001"
            && field("Gid:") == "1003\t1003\t1003\t1003"
            && field("Groups:").is_empty()
            && field("NoNewPrivs:") == "1"
            && ["CapEff:", "CapPrm:", "CapAmb:"]
                .iter()
                .all(|k| field(k) == "0000000000000000"),
        "136 gate requires irreversible replay credentials",
    )?;
    let socket = Path::new(scope::ROOT).join("entry.sock");
    let m = fs::symlink_metadata(&socket)?;
    required(
        m.file_type().is_socket() && m.uid() == 0 && m.nlink() == 1,
        "136 socket is not root-custodied",
    )?;
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(180)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    required(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } == 0,
        "136 supervisor peer credentials unavailable",
    )?;
    let expected_pid = env::var(scope::SUPERVISOR_ENV)
        .map_err(|_| invalid("136 supervisor missing"))?
        .parse::<u32>()
        .map_err(|_| invalid("136 supervisor PID syntax"))?;
    required(
        cred.uid == 0 && cred.pid > 1 && cred.pid as u32 == expected_pid,
        "136 gate peer is not exact root supervisor",
    )?;
    let request = format!(
        "{} {} {}\n",
        scope::BARRIER_VERSION,
        std::process::id(),
        worker_pid
    );
    stream.write_all(request.as_bytes())?;
    await_release(&mut stream)
}
fn await_release(stream: &mut impl Read) -> Result<(), HistoricalRuntimeError> {
    let mut answer = [0u8; 1];
    stream.read_exact(&mut answer)?;
    required(answer == *b"R", "136 restore release denied")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_digest_rejects_truncated_or_wrong_text() {
        assert!(hex_digest("f").is_err());
        assert!(hex_digest(&"z".repeat(64)).is_err());
        assert_eq!(hex_digest(scope::SNAPSHOT_SHA).unwrap().len(), 32);
    }
    #[test]
    fn hourly_range_is_exact_and_failure_is_inside_it() {
        assert_eq!(scope::END - scope::FIRST + 1, scope::COUNT);
        assert_eq!(scope::FAILURE_SLOT - scope::FIRST + 1, 6549);
        assert_eq!(59_183_999 - scope::END, 55);
    }
    #[test]
    fn scope_forces_compressed_binding_and_rejects_foreign_initialization() {
        let root = Path::new(scope::ROOT);
        let mut state = HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
            ledger_path: root.join("ledger"),
            archive_path: root.join("inputs").join(scope::SNAPSHOT_NAME),
            expected_slot: scope::BOOTSTRAP,
            expected_accounts_hash: "J6ef2VSpLh1ofwD4zXGLAJkNs4i6yZ5JzTr5qG1jBSNN"
                .parse::<solana_hash::Hash>()
                .unwrap()
                .to_bytes(),
            expected_archive_size: None,
            expected_archive_sha256: None,
            scratch_parent: Some(worker_scratch_parent(&root.join("scratch"))),
        });
        bind_scope(
            SOLANA_V1_4_25_CANDIDATE,
            &mut state,
            &root.join("entry.sock"),
        )
        .unwrap();
        let HistoricalInitialization::SnapshotArchive(ref mut s) = state else {
            panic!()
        };
        assert_eq!(s.expected_archive_size, Some(scope::SNAPSHOT_BYTES));
        assert_eq!(
            s.scratch_parent,
            Some(root.join("scratch/.historical-runtime"))
        );
        assert_eq!(
            s.expected_archive_sha256,
            Some(hex_digest(scope::SNAPSHOT_SHA).unwrap())
        );
        s.scratch_parent = Some(root.join("scratch"));
        assert!(
            bind_scope(
                SOLANA_V1_4_25_CANDIDATE,
                &mut state,
                &root.join("entry.sock")
            )
            .is_err()
        );
        let HistoricalInitialization::SnapshotArchive(ref mut s) = state else {
            panic!()
        };
        s.scratch_parent = Some(worker_scratch_parent(&root.join("scratch")));
        s.expected_archive_size = Some(1);
        assert!(
            bind_scope(
                SOLANA_V1_4_25_CANDIDATE,
                &mut state,
                &root.join("entry.sock")
            )
            .is_err()
        );
        assert!(
            bind_scope(
                SOLANA_V1_4_25_CANDIDATE,
                &mut state,
                Path::new("/tmp/entry.sock")
            )
            .is_err()
        );
    }
    #[test]
    fn disconnected_or_denied_supervisor_never_releases_initialize() {
        assert!(await_release(&mut &b""[..]).is_err());
        assert!(await_release(&mut &b"D"[..]).is_err());
        await_release(&mut &b"R"[..]).unwrap();
    }
}
