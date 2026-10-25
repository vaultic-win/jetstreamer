//! Read the current heartbeat from the sealed recovery guard configuration.
//! Historical frame snapshots remain immutable; live freshness is checked now.
use super::*;

pub(super) struct Heartbeat {
    pub(super) bytes: Vec<u8>,
    pub(super) value: Value,
    binding: BoundFile,
    checked_unix_millis: u64,
}

fn heartbeat_path(spec: &Value, plan: &Value) -> Result<PathBuf> {
    ensure!(
        spec["schema"] == "jetstreamer-epoch204-assembly-recovery-guard-spec-v1"
            && spec["epoch"] == 204
            && spec["executable_sha256"] == plan["executable_sha256"]
            && spec["producer_unit"] == UNIT
            && spec["guard_unit"] == GUARD
            && spec["output_root"] == ROOT
            && spec["maximum_millis"] == DURATION
            && spec["maximum_output_bytes"] == OUTPUT_MAX
            && spec["maximum_memory_bytes"] == MEMORY
            && spec["producer_stop_enabled"] == true,
        "204 live guard configuration differs"
    );
    deny(&spec["authority"])?;
    Ok(Path::new(s(spec, "output_root")?).join("guard-heartbeat.json"))
}

fn file_custody(stamp: &custody::FileStamp) -> Result<()> {
    ensure!(
        stamp.mode & libc::S_IFMT == libc::S_IFREG
            && stamp.uid == 0
            && stamp.links == 1
            && stamp.mode & 0o022 == 0
            && stamp.bytes <= 1 << 20,
        "204 live guard heartbeat custody"
    );
    Ok(())
}

impl Heartbeat {
    fn decode(
        path: PathBuf,
        bytes: Vec<u8>,
        plan: &Value,
        binding: &BoundFile,
        launch: &Value,
        now: u64,
    ) -> Result<Self> {
        ensure!(
            path == Path::new(ROOT).join("guard-heartbeat.json") && bytes.len() <= 1 << 20,
            "204 current heartbeat path or size differs"
        );
        let value: Value = serde_json::from_slice(&bytes)?;
        guard_shape(&value, plan, binding, launch, now)?;
        Ok(Self {
            binding: BoundFile {
                path,
                sha256: hex_lower(&Sha256::digest(&bytes)),
            },
            bytes,
            value,
            checked_unix_millis: now,
        })
    }

    pub(super) fn evidence(&self) -> Result<Value> {
        Ok(json!({"binding":private157::binding(&self.binding),
            "recorded_unix_millis":self.value["recorded_unix_millis"],
            "checked_unix_millis":self.checked_unix_millis,
            "raw_json":std::str::from_utf8(&self.bytes)?,"heartbeat":self.value}))
    }
}

pub(super) fn load(plan: &Value, binding: &BoundFile, launch: &Value) -> Result<Heartbeat> {
    let spec: BoundFile = serde_json::from_value(plan["guard_spec"].clone())?;
    let path = heartbeat_path(&read(&spec)?, plan)?;
    let root = path.parent().context("204 heartbeat parent")?;
    let root_before = fs::symlink_metadata(root)?;
    ensure!(
        root.is_absolute()
            && root.canonicalize()? == root
            && root_before.is_dir()
            && root_before.uid() == 0
            && root_before.mode() & 0o777 == 0o700
            && path.canonicalize()? == path,
        "204 live guard root is not exact canonical root-private custody"
    );
    let before = custody::FileStamp::of(&fs::symlink_metadata(&path)?);
    file_custody(&before)?;
    let bytes = read_stable_bounded(&path, 1 << 20, "204 actual live guard heartbeat")?;
    let after = custody::FileStamp::of(&fs::symlink_metadata(&path)?);
    let root_after = fs::symlink_metadata(root)?;
    ensure!(
        before == after
            && root_before.dev() == root_after.dev()
            && root_before.ino() == root_after.ino()
            && root_before.uid() == root_after.uid()
            && root_before.mode() == root_after.mode()
            && root.canonicalize()? == root
            && path.canonicalize()? == path,
        "204 live guard heartbeat/root changed during read"
    );
    Heartbeat::decode(path, bytes, plan, binding, launch, now_millis()?)
}

#[cfg(test)]
pub(super) fn fixture_heartbeat(
    value: &Value,
    plan: &Value,
    binding: &BoundFile,
    launch: &Value,
    now: u64,
) -> Result<Heartbeat> {
    Heartbeat::decode(
        Path::new(ROOT).join("guard-heartbeat.json"),
        serde_json::to_vec(value)?,
        plan,
        binding,
        launch,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_guard_configuration_cannot_redirect_the_current_heartbeat() {
        let plan = json!({"executable_sha256":"a".repeat(64)});
        let spec = json!({"schema":"jetstreamer-epoch204-assembly-recovery-guard-spec-v1","epoch":204,
            "executable_sha256":plan["executable_sha256"],"producer_unit":UNIT,"guard_unit":GUARD,
            "output_root":ROOT,"maximum_millis":DURATION,"maximum_output_bytes":OUTPUT_MAX,
            "maximum_memory_bytes":MEMORY,"producer_stop_enabled":true,"authority":denied()});
        assert_eq!(
            heartbeat_path(&spec, &plan).unwrap(),
            Path::new(ROOT).join("guard-heartbeat.json")
        );
        for (key, value) in [
            (
                "output_root",
                json!("/var/lib/jetstreamer/another-recovery"),
            ),
            ("executable_sha256", json!("b".repeat(64))),
            ("producer_unit", json!(OLD_UNIT)),
            ("guard_unit", json!(OLD_GUARD)),
            ("maximum_millis", json!(DURATION + 1)),
            ("maximum_memory_bytes", json!(MEMORY + 1)),
            ("producer_stop_enabled", json!(false)),
            ("authority", json!({"remote_mutations":true})),
        ] {
            let mut changed = spec.clone();
            changed[key] = value;
            assert!(heartbeat_path(&changed, &plan).is_err(), "accepted {key}");
        }
    }
    #[test]
    fn current_heartbeat_requires_bounded_root_owned_single_link_regular_custody() {
        let file = custody::FileStamp {
            device: 1,
            inode: 2,
            bytes: 1024,
            uid: 0,
            gid: 0,
            mode: libc::S_IFREG | 0o600,
            links: 1,
            mtime: 1,
            mtime_nanos: 0,
            ctime: 1,
            ctime_nanos: 0,
        };
        file_custody(&file).unwrap();
        for changed in [
            custody::FileStamp {
                uid: 1000,
                ..file.clone()
            },
            custody::FileStamp {
                links: 2,
                ..file.clone()
            },
            custody::FileStamp {
                mode: libc::S_IFLNK | 0o600,
                ..file.clone()
            },
            custody::FileStamp {
                mode: libc::S_IFREG | 0o620,
                ..file.clone()
            },
            custody::FileStamp {
                bytes: (1 << 20) + 1,
                ..file.clone()
            },
        ] {
            assert!(file_custody(&changed).is_err());
        }
    }
}
