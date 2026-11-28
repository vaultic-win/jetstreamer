//! Positive evidence for two observed first-level shared release compiler outputs.
//! Names alone never exempt a checkpoint from the existing protected-name gate.
use super::*;
use std::io::Read;
const RESTORE: &str = "jetstreamer_checkpoint_restore_probe";
const JOURNAL: &str = "jetstreamer_epoch140_checkpoint_journal";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    DepInfo,
    EmptyMetadata,
    Elf,
}
fn name(value: &str) -> Option<(&str, &str, Kind)> {
    let (value, kind) = if let Some(s) = value
        .strip_prefix("lib")
        .and_then(|s| s.strip_suffix(".rmeta"))
    {
        (s, Kind::EmptyMetadata)
    } else if let Some(s) = value.strip_suffix(".d") {
        (s, Kind::DepInfo)
    } else {
        (value, Kind::Elf)
    };
    let (crate_name, id) = value.rsplit_once('-')?;
    (matches!(crate_name, RESTORE | JOURNAL)
        && id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some((crate_name, id, kind))
}
fn sources(crate_name: &str) -> Option<(&'static str, &'static str)> {
    match crate_name {
        RESTORE => Some((
            "jetstreamer-node/src/bin/jetstreamer-checkpoint-restore-probe.rs",
            "jetstreamer-node/src/bin/../historical.rs",
        )),
        JOURNAL => Some((
            "jetstreamer-utils/src/epoch140_checkpoint_journal_bin.rs",
            "jetstreamer-utils/src/epoch141_ledger_common.rs",
        )),
        _ => None,
    }
}
fn depinfo(crate_name: &str, id: &str, metadata: bool) -> String {
    let (primary, secondary) = sources(crate_name).expect("closed compiler crate");
    let stem = format!("{crate_name}-{id}");
    let root = Path::new(RELEASE_DEPS);
    let output = if metadata {
        root.join(format!("lib{stem}.rmeta"))
    } else {
        root.join(&stem)
    };
    let cargo = if metadata { " Cargo.toml" } else { "" };
    let ending = if metadata {
        "Cargo.toml:\n\n# env-dep:CLIPPY_ARGS=-D__CLIPPY_HACKERY__warnings__CLIPPY_HACKERY__\n# env-dep:CLIPPY_CONF_DIR\n"
    } else {
        ""
    };
    format!(
        "{}: {primary} {secondary}{cargo}\n\n{}: {primary} {secondary}{cargo}\n\n{primary}:\n{secondary}:\n{ending}",
        root.join(format!("{stem}.d")).display(),
        output.display()
    )
}
fn read_regular(path: &Path, maximum: u64, prefix_only: bool) -> Result<(Node, Vec<u8>)> {
    let before = node(path)?;
    ensure!(
        before.kind == "file",
        "compiler evidence must be a regular file: {}",
        path.display()
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        opened.dev() == before.device
            && opened.ino() == before.inode
            && opened.len() == before.size
            && opened.uid() == before.uid,
        "compiler evidence identity changed while opened: {}",
        path.display()
    );
    ensure!(
        prefix_only || before.size <= maximum,
        "compiler evidence exceeds bound: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(maximum).read_to_end(&mut bytes)?;
    ensure!(
        node(path)? == before,
        "compiler evidence changed while read: {}",
        path.display()
    );
    Ok((before, bytes))
}
fn elf64_x86_64(bytes: &[u8], size: u64) -> bool {
    if bytes.len() != 64 {
        return false;
    }
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    let phnum = u64::from(u16::from_le_bytes([bytes[56], bytes[57]]));
    let shnum = u64::from(u16::from_le_bytes([bytes[60], bytes[61]]));
    size >= 64
        && phoff >= 64
        && shoff >= 64
        && phoff.checked_add(phnum * 56).is_some_and(|end| end <= size)
        && shoff.checked_add(shnum * 64).is_some_and(|end| end <= size)
        && bytes[..16] == *b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        && u16::from_le_bytes([bytes[16], bytes[17]]) == 3
        && u16::from_le_bytes([bytes[18], bytes[19]]) == 62
        && u32::from_le_bytes(bytes[20..24].try_into().unwrap()) == 1
        && u16::from_le_bytes([bytes[52], bytes[53]]) == 64
        && u16::from_le_bytes([bytes[54], bytes[55]]) == 56
        && u16::from_le_bytes([bytes[56], bytes[57]]) > 0
        && u16::from_le_bytes([bytes[58], bytes[59]]) == 64
        && u16::from_le_bytes([bytes[60], bytes[61]]) > 0
}
pub(super) fn qualified(
    policy_root: &Path,
    actual_root: &Path,
    path: &Path,
    expected: &Node,
) -> Result<bool> {
    if policy_root != Path::new(RELEASE_DEPS)
        || path.parent() != Some(actual_root)
        || expected.kind != "file"
    {
        return Ok(false);
    }
    let Some((crate_name, id, kind)) = path.file_name().and_then(|n| n.to_str()).and_then(name)
    else {
        return Ok(false);
    };
    let stem = format!("{crate_name}-{id}");
    let (d_identity, d) = read_regular(&actual_root.join(format!("{stem}.d")), 4096, false)?;
    let expected_metadata = depinfo(crate_name, id, true);
    // Both complete generated records were observed in this fixed cache.
    // No other Clippy argument, source, output or environment line is accepted.
    let no_deps_metadata = expected_metadata.replace(
        "# env-dep:CLIPPY_ARGS=-D",
        "# env-dep:CLIPPY_ARGS=--no-deps__CLIPPY_HACKERY__-D",
    );
    let metadata = d == expected_metadata.as_bytes() || d == no_deps_metadata.as_bytes();
    let executable = d == depinfo(crate_name, id, false).as_bytes();
    ensure!(
        metadata || executable,
        "compiler dep-info does not bind the exact known crate and output: {}",
        path.display()
    );
    if kind == Kind::DepInfo {
        ensure!(
            node(path)? == *expected && node(&actual_root.join(format!("{stem}.d")))? == d_identity,
            "compiler dep-info identity changed during qualification: {}",
            path.display()
        );
        return Ok(true);
    }
    if (kind == Kind::EmptyMetadata && !metadata) || (kind == Kind::Elf && !executable) {
        return Ok(false);
    }
    let output = if metadata {
        actual_root.join(format!("lib{stem}.rmeta"))
    } else {
        actual_root.join(&stem)
    };
    let (output_identity, bytes) = read_regular(&output, if metadata { 0 } else { 64 }, !metadata)?;
    ensure!(
        if metadata {
            output_identity.size == 0
        } else {
            output_identity.mode & 0o111 != 0 && elf64_x86_64(&bytes, output_identity.size)
        },
        "compiler output lacks its observed empty metadata or ELF container: {}",
        output.display()
    );
    ensure!(
        node(&actual_root.join(format!("{stem}.d")))? == d_identity
            && node(&output)? == output_identity
            && node(path)? == *expected,
        "compiler pair identity changed during qualification: {}",
        path.display()
    );
    Ok(true)
}
pub(super) fn defer_depinfo(relative: &Path) -> bool {
    relative.components().count() == 1
        && relative
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(name)
            .is_some_and(|(_, _, kind)| kind == Kind::DepInfo)
}
#[cfg(test)]
mod tests;
