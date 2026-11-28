use super::*;
pub(super) fn reject_incremental_mounts(bytes: &[u8], target: &Path) -> Result<()> {
    ensure!(bytes.len() <= 4 << 20, "mount census exceeded bound");
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let fields: Vec<_> = line
            .split(|b| *b == b' ')
            .filter(|s| !s.is_empty())
            .collect();
        ensure!(
            fields.len() >= 10 && fields.contains(&b"-".as_slice()),
            "invalid mount census row"
        );
        let raw = fields[4];
        let mut decoded = Vec::new();
        let mut at = 0;
        while at < raw.len() {
            if raw[at] == b'\\' {
                ensure!(
                    at + 3 < raw.len()
                        && raw[at + 1..=at + 3]
                            .iter()
                            .all(|b| (b'0'..=b'7').contains(b)),
                    "invalid escaped mount path"
                );
                let value = (raw[at + 1] - b'0') as u16 * 64
                    + (raw[at + 2] - b'0') as u16 * 8
                    + (raw[at + 3] - b'0') as u16;
                ensure!(value > 0 && value <= 255, "invalid mount path byte");
                decoded.push(value as u8);
                at += 4;
            } else {
                decoded.push(raw[at]);
                at += 1;
            }
        }
        let mounted = Path::new(std::ffi::OsStr::from_bytes(&decoded));
        ensure!(mounted.is_absolute(), "nonabsolute mount path");
        ensure!(
            mounted != target && !mounted.starts_with(target),
            "selected incremental cache contains a mount/bind alias"
        );
    }
    Ok(())
}
pub(super) fn incremental_mounts(target: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    File::open("/proc/self/mountinfo")?
        .take((4 << 20) + 1)
        .read_to_end(&mut bytes)?;
    reject_incremental_mounts(&bytes, target)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

pub(super) fn census() -> Result<Vec<String>> {
    TARGETS
        .iter()
        .map(|(path, _, _, _)| incremental_mounts(Path::new(path)))
        .collect()
}
