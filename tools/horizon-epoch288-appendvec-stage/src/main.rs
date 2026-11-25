//! Prepare local, bounded custody staging for the closed 288 AccountsDb.
use {
    anyhow::{Context, Result, ensure},
    serde_json::json,
    sha2::{Digest, Sha256},
    std::{
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
        path::Path,
        process::{Command, Stdio},
    },
};

#[path = "../../../jetstreamer-horizon-observe/src/process_references.rs"]
mod process_references;

const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-288-root-v303";
const SOURCE_RELATIVE: &str = concat!(
    "state/destination-d74e6d937b9bc41c08f39b1e2981ab6797e3709ece54bd59e4db12fbfce5571f/",
    "work/root-cohort-288-288/run-750660-1795547371821978162/scratch/.historical-runtime/",
    "jetstreamer-historical-parent-wIfdSb/jetstreamer-historical-v1.8.11-y3aKJ1/accounts-state"
);
const TMPFS: &str = "/home/ubuntu/.jetstreamer-private/epoch288-appendvec-stage-tmpfs-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon288-closed-appendvec-study-v1";
const TERMINAL: &str = "/var/lib/jetstreamer/horizon288-full-v303/terminal.json";
const PRODUCER: &str = "horizon-qualify-288-root-singleton-v303.service";
const TIMER: &str = "horizon-288-full-protective-v303.timer";
const UNIT: &str = "foundation-288-appendvec-stage-v2.service";
const FILE: &str = "epoch-288-closed-appendvecs.pax.zst";
const CAP: u64 = 96 << 30;
const SAMPLE_SHA: &str = "5c07a84b6b2c7fd38dd5c3eb74db191b826d53b8827b5b9735d5c214188d6272";
const CENSUS_SHA: &str = "287f5bd0fa48f9d32b38198704762d462b9975702c9b64c5233944d8e19d8931";
const MEMBERS: usize = 178_655;
const TAR: &str = "/usr/bin/tar";
const ZSTD: &str = "/usr/bin/zstd";
const TAR_SHA: &str = "6ab7a3e80cfd4ab35650bf11f48b662f616cd622c1f67d367d0341bc2f9c2245";
const ZSTD_SHA: &str = "35bfa0d33c03bc1d74ade24ceae006098fa2d5e7c9addc7be45640832f9384d6";

fn hash_file(path: &Path) -> Result<String> {
    let mut hash = Sha256::new();
    std::io::copy(&mut File::open(path)?, &mut hash)?;
    Ok(format!("{:x}", hash.finalize()))
}

fn closed() -> Result<process_references::Scan> {
    for unit in [PRODUCER, TIMER] {
        let state = Command::new("/usr/bin/systemctl")
            .args(["show", "-p", "ActiveState", "--value", unit])
            .output()?;
        ensure!(
            state.status.success() && state.stdout == b"inactive\n",
            "live predecessor {unit}"
        );
    }
    ensure!(
        !Path::new("/sys/fs/cgroup/system.slice")
            .join(PRODUCER)
            .try_exists()?,
        "predecessor control group still exists"
    );
    let scan = process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        scan.references.is_empty(),
        "live predecessor references: {:?}",
        scan.references
    );
    Ok(scan)
}

fn no_xattrs(path: &Path) -> Result<()> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    let size = unsafe { libc::llistxattr(name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| path.display().to_string());
    }
    ensure!(
        size == 0,
        "unexpected extended attributes at {}",
        path.display()
    );
    Ok(())
}

fn census(source: &Path, members: &mut impl Write) -> Result<String> {
    ensure!(source.canonicalize()? == source, "aliased AccountsDb");
    let mut shards = fs::read_dir(source)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    shards.sort_unstable();
    ensure!(
        shards == ["0", "1", "2", "3"],
        "unexpected AccountsDb shards"
    );
    let device = source.metadata()?.dev();
    no_xattrs(source)?;
    for shard in &shards {
        let directory = source.join(shard);
        let metadata = directory.symlink_metadata()?;
        ensure!(
            metadata.is_dir() && metadata.dev() == device,
            "aliased AccountsDb shard"
        );
        no_xattrs(&directory)?;
    }
    let output = Command::new("/usr/bin/find")
        .env("LC_ALL", "C")
        .current_dir(source)
        .args([
            "0",
            "1",
            "2",
            "3",
            "-xdev",
            "-mindepth",
            "1",
            "-maxdepth",
            "1",
            "-printf",
            "%p\t%y\t%n\t%U\t%G\t%m\t%D\t%i\t%s\t%b\t%T@\t%C@\n",
        ])
        .output()?;
    ensure!(output.status.success(), "AccountsDb census failed");
    let mut rows: Vec<_> = output
        .stdout
        .split_inclusive(|byte| *byte == b'\n')
        .collect();
    ensure!(rows.len() == MEMBERS, "AccountsDb member count differs");
    rows.sort_unstable();
    let mut digest = Sha256::new();
    for row in rows {
        let mut columns = row.splitn(2, |byte| *byte == b'\t');
        let name = columns.next().context("missing census filename")?;
        let stat = columns.next().context("missing census metadata")?;
        ensure!(
            stat.starts_with(b"f\t1\t"),
            "unexpected AccountsDb inode type"
        );
        no_xattrs(&source.join(std::ffi::OsStr::from_bytes(name)))?;
        digest.update(row);
        members.write_all(name)?;
        members.write_all(b"\0")?;
    }
    let hash = format!("{:x}", digest.finalize());
    ensure!(hash == CENSUS_SHA, "AccountsDb census differs: {hash}");
    Ok(hash)
}

fn check_mount(directory: &Path, source: &Path) -> Result<()> {
    let metadata = directory.symlink_metadata()?;
    ensure!(
        directory.canonicalize()? == directory
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o777 == 0o700
            && metadata.dev() != source.metadata()?.dev(),
        "invalid private staging mount"
    );
    let name = CString::new(directory.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    ensure!(
        unsafe { libc::statfs(name.as_ptr(), stat.as_mut_ptr()) } == 0,
        "staging statfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    ensure!(
        stat.f_type == libc::TMPFS_MAGIC
            && stat.f_blocks * stat.f_bsize as u64 == CAP
            && stat.f_bavail == stat.f_blocks,
        "staging tmpfs size or availability differs"
    );
    Ok(())
}

fn guarded_invocation() -> Result<String> {
    let group = format!("/system.slice/{UNIT}");
    ensure!(
        fs::read_to_string("/proc/self/cgroup")? == format!("0::{group}\n"),
        "staging must run under its admitted systemd unit"
    );
    let cgroup = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    for (file, expected) in [
        ("memory.max", (98_u64 << 30).to_string()),
        ("memory.swap.max", "0".to_string()),
        ("cpuset.cpus.effective", "112".to_string()),
    ] {
        ensure!(
            fs::read_to_string(cgroup.join(file))?.trim() == expected,
            "staging cgroup setting differs: {file}"
        );
    }
    let io_limit = fs::read_to_string(cgroup.join("io.max"))?;
    ensure!(
        io_limit.lines().any(|line| line.starts_with("259:0 ")
            && line
                .split_ascii_whitespace()
                .any(|field| field == "rbps=134217728")),
        "staging source bandwidth limit differs: {io_limit}"
    );
    let invocation = std::env::var("INVOCATION_ID")?;
    ensure!(
        invocation.len() == 32 && invocation.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "missing systemd invocation identity"
    );
    Ok(invocation)
}

fn compress(source: &Path, members: &Path, output: &mut File) -> Result<(u64, String)> {
    let mut tar = Command::new(TAR)
        .current_dir(source)
        .env("LC_ALL", "C")
        .args([
            "--format=pax",
            "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
            "--atime-preserve=system",
            "--sparse",
            "--no-recursion",
            "--null",
            "--verbatim-files-from",
            "-T",
        ])
        .arg(members)
        .args(["-cf", "-"])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut zstd = match Command::new(ZSTD)
        .args(["-q", "-T1", "-3", "-c"])
        .stdin(tar.stdout.take().context("missing tar stdout")?)
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let _ = tar.kill();
            let _ = tar.wait();
            return Err(error.into());
        }
    };
    let result = (|| {
        let mut stream = zstd.stdout.take().context("missing compressor stdout")?;
        let mut buffer = vec![0; 1 << 20];
        let mut length = 0u64;
        let mut digest = Sha256::new();
        loop {
            let bytes = stream.read(&mut buffer)?;
            if bytes == 0 {
                break;
            }
            length += bytes as u64;
            ensure!(
                length < CAP,
                "compressed output exceeded admitted tmpfs size"
            );
            output.write_all(&buffer[..bytes])?;
            digest.update(&buffer[..bytes]);
        }
        ensure!(length > 0, "empty compressed bundle");
        Ok((length, format!("{:x}", digest.finalize())))
    })();
    if result.is_err() {
        let _ = zstd.kill();
        let _ = tar.kill();
    }
    let compressor_exit = zstd.wait()?;
    let tar_exit = tar.wait()?;
    let proof = result?;
    ensure!(
        compressor_exit.success() && tar_exit.success(),
        "archive pipeline failed"
    );
    Ok(proof)
}

fn run() -> Result<()> {
    let action = std::env::args().nth(1).context("use check or stage")?;
    ensure!(
        matches!(action.as_str(), "check" | "stage") && std::env::args().len() == 2,
        "use check or stage"
    );
    let state = Path::new(STATE);
    let sample = fs::read(state.join("sample-qualification.json"))?;
    ensure!(
        format!("{:x}", Sha256::digest(&sample)) == SAMPLE_SHA,
        "sample binding differs"
    );
    let sample: serde_json::Value = serde_json::from_slice(&sample)?;
    let source = Path::new(ROOT).join(SOURCE_RELATIVE);
    let terminal_sha = hash_file(Path::new(TERMINAL))?;
    ensure!(
        sample["source"].as_str() == source.to_str()
            && sample["stopped_predecessor"]["sha256"].as_str() == Some(&terminal_sha),
        "closed predecessor binding differs"
    );
    for (path, sha) in [(TAR, TAR_SHA), (ZSTD, ZSTD_SHA)] {
        ensure!(
            hash_file(Path::new(path))? == sha,
            "staging tool changed: {path}"
        );
    }
    let before = closed()?;
    let mut members = tempfile::NamedTempFile::new()?;
    let census_sha = census(&source, &mut members)?;
    if action == "check" {
        println!(
            "{}",
            json!({"epoch":288,"census_sha256":census_sha,"process_scan":before})
        );
        return Ok(());
    }

    let invocation = guarded_invocation()?;
    let directory = Path::new(TMPFS);
    check_mount(directory, &source)?;
    let bundle = directory.join(FILE);
    let part = directory.join(format!("{FILE}.part"));
    let receipt = state.join("staging-body.json");
    ensure!(
        !bundle.try_exists()? && !receipt.try_exists()?,
        "stage already exists"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&part)?;
    let (length, sha256) = compress(&source, members.path(), &mut file)?;
    file.sync_all()?;
    ensure!(
        file.metadata()?.len() == length && hash_file(&part)? == sha256,
        "bundle readback differs"
    );
    census(&source, &mut std::io::sink())?;
    let after = closed()?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    fs::hard_link(&part, &bundle)?;
    fs::remove_file(&part)?;
    File::open(directory)?.sync_all()?;

    let mut output = tempfile::NamedTempFile::new_in(state)?;
    output
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(
        &mut output,
        &json!({
            "schema":"foundation-epoch288-appendvec-staging-body-v1","epoch":288,
            "invocation_id":invocation,"unit":UNIT,"pid":std::process::id(),
            "sample_sha256":SAMPLE_SHA,"source":source,"source_census_sha256":census_sha,
            "terminal_sha256":terminal_sha,"process_references_before":before,"process_references_after":after,
            "path":bundle,"length":length,"sha256":sha256,"members":MEMBERS,
            "local_retirement_authorized":false,"remote_mutations":false
        }),
    )?;
    writeln!(output)?;
    output.as_file().sync_all()?;
    output.persist_noclobber(receipt)?;
    File::open(state)?.sync_all()?;
    println!("staged {length} bytes with SHA-256 {sha256}");
    Ok(())
}

fn main() -> Result<()> {
    run()
}
