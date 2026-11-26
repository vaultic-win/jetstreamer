//! Dispatch the prepared epoch 145 build or admission after its predecessor receipt.
use std::{
    env, fs, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{Duration, SystemTime},
};

const RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const FLEET: &str = "ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const MAX_FLEET_AGE: Duration = Duration::from_secs(2_400);
const COMPLETION: &str = if cfg!(epoch145_v10_completion) {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/v10-census-name-handoff/SEMANTIC_COMPLETION.json"
} else {
    "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/v9-census-name-handoff/SEMANTIC_COMPLETION.json"
};

fn private_root_file(path: &Path, mode: u32) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || path.canonicalize()? != path
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != mode
    {
        return Err(io::Error::other(format!(
            "unexpected custody for {}",
            path.display()
        )));
    }
    Ok(metadata)
}

fn latest_fleet() -> io::Result<PathBuf> {
    let mut latest = None;
    for entry in fs::read_dir(RUNTIME)? {
        let entry = entry?;
        if !entry.file_name().as_encoded_bytes().starts_with(b"root")
            || !entry.file_type()?.is_dir()
        {
            continue;
        }
        let path = entry.path().join(FLEET);
        let modified = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata.modified()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if latest.as_ref().is_none_or(|(time, _)| modified > *time) {
            latest = Some((modified, path));
        }
    }
    let (modified, path) = latest.ok_or_else(|| io::Error::other("no accepted fleet receipt"))?;
    if SystemTime::now()
        .duration_since(modified)
        .map_or(true, |age| age > MAX_FLEET_AGE)
        || private_root_file(&path, 0o600)?.modified()? != modified
    {
        return Err(io::Error::other("latest fleet receipt is stale or changed"));
    }
    Ok(path)
}

fn file_digest(path: &Path) -> io::Result<String> {
    let output = Command::new("/usr/bin/sha256sum")
        .arg("--")
        .arg(path)
        .output()?;
    let digest = output
        .stdout
        .split(|byte| byte.is_ascii_whitespace())
        .next()
        .unwrap_or_default();
    if !output.status.success()
        || digest.len() != 64
        || !digest
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(io::Error::other(format!(
            "could not hash {}",
            path.display()
        )));
    }
    Ok(String::from_utf8_lossy(digest).into_owned())
}

fn run() -> io::Result<()> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let (launcher, deployment) = match arguments.as_slice() {
        [argument] if argument == "--inspect" => (None, None),
        [launcher] => (Some(Path::new(launcher)), None),
        [launcher, deployment] if cfg!(epoch145_v10_completion) => {
            (Some(Path::new(launcher)), Some(Path::new(deployment)))
        }
        _ => {
            return Err(io::Error::other(
                "expected --inspect, a build launcher, or an admission launcher and deployment receipt",
            ));
        }
    };
    if let Some(launcher) = launcher {
        private_root_file(Path::new(COMPLETION), 0o600)?;
        private_root_file(launcher, 0o400)?;
    }
    let fleet = latest_fleet()?;
    let digest = file_digest(&fleet)?;
    println!("{}  {}", digest, fleet.display());
    if let Some(launcher) = launcher {
        let mut command = Command::new("/usr/bin/python3");
        command.arg("-IB").arg(launcher).arg(fleet).arg(digest);
        if let Some(deployment) = deployment {
            private_root_file(deployment, 0o600)?;
            command.arg(file_digest(deployment)?);
        }
        let result = command.status()?;
        if !result.success() {
            return Err(io::Error::other(format!(
                "prepared epoch 145 launcher exited with {result}"
            )));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
