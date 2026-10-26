//! In-process proof of actual independent input hashing, never a caller flag.
//! Retained descriptors and full metadata tuples prevent changing a prehashed
//! source while moving guard selection after the expensive validation step.
use super::*;
use std::os::unix::fs::OpenOptionsExt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_nanos: i64,
    ctime: i64,
    ctime_nanos: i64,
}
impl Stamp {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            length: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            mtime: m.mtime(),
            mtime_nanos: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nanos: m.ctime_nsec(),
        }
    }
    fn safe(&self, executable: bool, maximum: u64) -> Result<()> {
        ensure!(
            self.mode & libc::S_IFMT == libc::S_IFREG
                && self.links == 1
                && self.uid == 0
                && self.gid == 0
                && self.mode & 0o222 == 0
                && (self.mode & 0o111 != 0) == executable
                && self.length > 0
                && self.length <= maximum,
            "210 prehashed input custody is mutable, redirected or outside its profile"
        );
        Ok(())
    }
}
fn unchanged_namespace(path: &Path, file: &File, stamp: &Stamp) -> Result<()> {
    ensure!(
        path.canonicalize()? == path
            && *stamp == Stamp::of(&file.metadata()?)
            && *stamp == Stamp::of(&fs::symlink_metadata(path)?),
        "210 independently prehashed input changed identity, content metadata, owner or mode"
    );
    Ok(())
}
struct FrozenInput {
    binding: BoundFile,
    file: File,
    stamp: Stamp,
    executable: bool,
    maximum: u64,
}
impl FrozenInput {
    fn capture(binding: BoundFile, executable: bool, maximum: u64) -> Result<Self> {
        ensure!(
            binding.path.is_absolute()
                && binding.path.canonicalize()? == binding.path
                && is_lower_hex(&binding.sha256, 64),
            "210 prehash input path/digest differs"
        );
        let before = Stamp::of(&fs::symlink_metadata(&binding.path)?);
        before.safe(executable, maximum)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&binding.path)?;
        let stamp = Stamp::of(&file.metadata()?);
        stamp.safe(executable, maximum)?;
        ensure!(
            stamp == before,
            "210 prehash input changed between regular-file stat and open"
        );
        ensure!(
            stamp == Stamp::of(&fs::symlink_metadata(&binding.path)?),
            "210 prehash input namespace changed"
        );
        Ok(Self {
            binding,
            file,
            stamp,
            executable,
            maximum,
        })
    }
    fn revalidate(&self) -> Result<()> {
        self.stamp.safe(self.executable, self.maximum)?;
        unchanged_namespace(&self.binding.path, &self.file, &self.stamp)?;
        Ok(())
    }
    fn evidence(&self) -> Value {
        json!({"binding":self.binding,"identity":self.stamp,"retained_descriptor":true})
    }
}
// No Deserialize, public fields, saved-token constructor or reuse across exec.
// Only validate_inputs returns this value, after all original hash/native gates.
pub(super) struct ValidatedInputs {
    files: Vec<FrozenInput>,
    capability: BoundFile,
    native_input: BoundFile,
    resource_plan: BoundFile,
}
impl ValidatedInputs {
    pub(super) fn capture(s: &Spec) -> Result<Self> {
        let mut files = Vec::new();
        for (path, sha, executable, maximum) in [
            (PathBuf::from(c::NODE), c::NODE_SHA, true, 256 << 20),
            (PathBuf::from(c::WORKER), c::WORKER_SHA, true, 256 << 20),
            (
                PathBuf::from(c::PREFLIGHT),
                c::PREFLIGHT_SHA,
                false,
                1 << 20,
            ),
            (
                Path::new(c::INPUT).join(c::SNAPSHOT),
                c::SNAPSHOT_SHA,
                false,
                8_579_041_139,
            ),
            (
                Path::new(c::INPUT).join("genesis.tar.bz2"),
                c::GENESIS_SHA,
                false,
                20_144,
            ),
        ] {
            files.push(FrozenInput::capture(
                BoundFile {
                    path,
                    sha256: sha.into(),
                },
                executable,
                maximum,
            )?);
        }
        for binding in [&s.capability, &s.native_input, &s.resource_plan] {
            files.push(FrozenInput::capture(binding.clone(), false, 8 << 20)?);
        }
        Ok(Self {
            files,
            capability: s.capability.clone(),
            native_input: s.native_input.clone(),
            resource_plan: s.resource_plan.clone(),
        })
    }
    pub(super) fn revalidate(&self, s: &Spec) -> Result<()> {
        ensure!(
            s.capability == self.capability
                && s.native_input == self.native_input
                && s.resource_plan == self.resource_plan,
            "210 prehash token borrowed by different input spec"
        );
        for file in &self.files {
            file.revalidate()?;
        }
        Ok(())
    }
    pub(super) fn evidence(&self) -> Value {
        json!({"schema":"jetstreamer-full210-independent-input-custody-v1",
            "actual_original_input_validators_passed":true,"original_input_validator_executions":1,
            "retained_input_descriptors":self.files.iter().map(FrozenInput::evidence).collect::<Vec<_>>(),
            "reused_across_processes":false,"caller_supplied_validation_flag":false})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Stamp {
        Stamp {
            device: 1,
            inode: 2,
            length: 4,
            uid: 0,
            gid: 0,
            mode: libc::S_IFREG | 0o444,
            links: 1,
            mtime: 1,
            mtime_nanos: 2,
            ctime: 3,
            ctime_nanos: 4,
        }
    }
    #[test]
    fn full210_prehashed_tuple_covers_content_identity_custody_and_exact_mode() {
        let a = good();
        a.safe(false, 4).unwrap();
        for field in [
            "inode",
            "length",
            "mtime",
            "mtime_nanos",
            "ctime",
            "ctime_nanos",
            "mode",
            "uid",
            "gid",
            "links",
        ] {
            let mut b = a.clone();
            match field {
                "inode" => b.inode += 1,
                "length" => b.length += 1,
                "mtime" => b.mtime += 1,
                "mtime_nanos" => b.mtime_nanos += 1,
                "ctime" => b.ctime += 1,
                "ctime_nanos" => b.ctime_nanos += 1,
                "mode" => b.mode = libc::S_IFREG | 0o400,
                "uid" => b.uid = 1000,
                "gid" => b.gid = 1000,
                "links" => b.links = 2,
                _ => unreachable!(),
            };
            assert_ne!(a, b, "{field}");
        }
        for mode in [
            libc::S_IFLNK | 0o444,
            libc::S_IFREG | 0o644,
            libc::S_IFREG | 0o555,
        ] {
            let mut b = a.clone();
            b.mode = mode;
            assert!(b.safe(false, 4).is_err());
        }
    }
    #[test]
    fn full210_prehashed_descriptor_cannot_hide_path_replacement_or_mode_change() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("input");
        fs::write(&p, b"body").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&p)
            .unwrap();
        let stamp = Stamp::of(&f.metadata().unwrap());
        unchanged_namespace(&p, &f, &stamp).unwrap();
        fs::rename(&p, d.path().join("old")).unwrap();
        fs::write(&p, b"body").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(stamp.inode, Stamp::of(&f.metadata().unwrap()).inode);
        assert!(unchanged_namespace(&p, &f, &stamp).is_err());
        let next = File::open(&p).unwrap();
        let before = Stamp::of(&next.metadata().unwrap());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(unchanged_namespace(&p, &next, &before).is_err());
    }
    #[test]
    fn full210_prehashed_input_changed_through_preexisting_writer_is_rejected() {
        use std::os::unix::fs::{FileExt, PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("input");
        fs::write(&p, b"body").unwrap();
        let writer = OpenOptions::new().write(true).open(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        let reader = File::open(&p).unwrap();
        let stamp = Stamp::of(&reader.metadata().unwrap());
        unchanged_namespace(&p, &reader, &stamp).unwrap();
        writer.write_all_at(b"changed", 0).unwrap();
        writer.sync_all().unwrap();
        assert!(unchanged_namespace(&p, &reader, &stamp).is_err());
    }
}
