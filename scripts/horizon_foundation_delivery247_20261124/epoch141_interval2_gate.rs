//! Hold the systemd MainPID until root seals this invocation's first guard sample.
use std::{
    env, fs, io,
    os::{unix::fs::MetadataExt, unix::process::CommandExt},
    path::PathBuf,
    process::{Command, ExitCode},
    thread,
    time::{Duration, Instant},
};

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
}

fn release_digest<'a>(body: &'a str, invocation: &str) -> Option<&'a str> {
    let (bound, rest) = body.split_once('\n')?;
    let digest = rest.strip_suffix('\n')?;
    (bound == invocation && lower_hex(digest, 64)).then_some(digest)
}

fn run() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let control = args
        .next()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| io::Error::other("expected absolute release directory"))?;
    let program = args
        .next()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| io::Error::other("expected absolute payload executable"))?;
    let directory = fs::symlink_metadata(&control)?;
    if !directory.is_dir()
        || directory.uid() != 0
        || directory.mode() & 0o022 != 0
        || control.canonicalize()? != control
    {
        return Err(io::Error::other(
            "release directory is outside root custody",
        ));
    }
    let invocation = env::var("INVOCATION_ID").map_err(io::Error::other)?;
    if !lower_hex(&invocation, 32) {
        return Err(io::Error::other("missing systemd invocation identity"));
    }
    let token = control.join(format!("{invocation}.release"));
    let expires = Instant::now() + Duration::from_secs(90);
    while Instant::now() < expires {
        match fs::symlink_metadata(&token) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o7777 != 0o444
                    || metadata.nlink() != 1
                    || metadata.len() != 98
                {
                    return Err(io::Error::other("unsafe guard release"));
                }
                let body = fs::read_to_string(&token)?;
                let digest = release_digest(&body, &invocation)
                    .ok_or_else(|| io::Error::other("guard release binds another invocation"))?;
                eprintln!(
                    "epoch 141 held invocation {invocation} released with guard sample {digest}"
                );
                return Err(Command::new(program).args(args).exec());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("first guard release did not arrive"))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("epoch 141 prestart: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_is_bound_to_one_invocation_and_one_guard_digest() {
        let iid = "7".repeat(32);
        let digest = "a".repeat(64);
        let token = format!("{iid}\n{digest}\n");
        assert_eq!(release_digest(&token, &iid), Some(digest.as_str()));
        assert!(release_digest(&token, &"8".repeat(32)).is_none());
        assert!(release_digest(&format!("{iid}\n{digest}\nextra\n"), &iid).is_none());
    }
}
