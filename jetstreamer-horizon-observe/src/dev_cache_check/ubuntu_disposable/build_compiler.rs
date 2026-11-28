//! Exact observed RocksDB compiler objects, not historical runtime checkpoints.
//! The protected-name exception binds the complete bytes and fixed cache path;
//! a similar name, another build generation, or changed object is not accepted.
use super::*;

fn expected(policy_root: &Path, relative: &Path) -> Option<&'static str> {
    match (policy_root.to_str()?, relative.to_str()?) {
        (
            DEBUG_BUILD | DEMOTION_DEBUG_BUILD,
            "librocksdb-sys-37eeae80f930ac01/out/bfe5d317b023d6cf-checkpoint_impl.o"
            | "librocksdb-sys-718199d3bc47b9d1/out/bfe5d317b023d6cf-checkpoint_impl.o",
        ) => Some("f53c0f2b84b90ab5423f2923bf2da073bdb15661b24457e7c34cd4a4263a42e8"),
        (
            RELEASE_BUILD,
            "librocksdb-sys-a545a441747427e1/out/bfe5d317b023d6cf-checkpoint_impl.o"
            | "librocksdb-sys-a53c016568a6018c/out/bfe5d317b023d6cf-checkpoint_impl.o",
        ) => Some("e6bf6a5539b644378595cd72bb03c103d485419bb753c44f8441448f58ac4d65"),
        (
            DEMOTION_NODE_RELEASE_BUILD | HOLDING_RELEASE_BUILD,
            "librocksdb-sys-a53c016568a6018c/out/bfe5d317b023d6cf-checkpoint_impl.o",
        ) => Some("e6bf6a5539b644378595cd72bb03c103d485419bb753c44f8441448f58ac4d65"),
        _ => None,
    }
}

pub(super) fn qualified(
    policy_root: &Path,
    actual_root: &Path,
    path: &Path,
    original: &Node,
) -> Result<bool> {
    if original.kind != "file" {
        return Ok(false);
    }
    let Some(sha) = path
        .strip_prefix(actual_root)
        .ok()
        .and_then(|p| expected(policy_root, p))
    else {
        return Ok(false);
    };
    // These complete digests were independently measured from x86-64 ELF
    // relocatable objects. Keep all ordinary custody/identity/consumer gates.
    ensure!(
        node(path)? == *original,
        "build object changed before hashing"
    );
    ensure!(
        hash_file(path, 64 << 20)?.0 == sha,
        "known RocksDB compiler object differs"
    );
    ensure!(
        node(path)? == *original,
        "build object changed while hashing"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_name_does_not_grant_a_build_object_exception() {
        let relative =
            Path::new("librocksdb-sys-37eeae80f930ac01/out/bfe5d317b023d6cf-checkpoint_impl.o");
        assert!(expected(Path::new(DEBUG_BUILD), relative).is_some());
        assert!(expected(Path::new(DEMOTION_DEBUG_BUILD), relative).is_some());
        assert!(expected(Path::new(DEMOTION_DEBUG_DEPS), relative).is_none());
        assert!(expected(Path::new(RELEASE_BUILD), relative).is_none());
        assert!(expected(Path::new(RELEASE_DEPS), relative).is_none());
        let release_object =
            Path::new("librocksdb-sys-a53c016568a6018c/out/bfe5d317b023d6cf-checkpoint_impl.o");
        let other_release_object =
            Path::new("librocksdb-sys-a545a441747427e1/out/bfe5d317b023d6cf-checkpoint_impl.o");
        for root in [DEMOTION_NODE_RELEASE_BUILD, HOLDING_RELEASE_BUILD] {
            assert_eq!(
                expected(Path::new(root), release_object),
                expected(Path::new(RELEASE_BUILD), release_object)
            );
            assert!(expected(Path::new(root), release_object).is_some());
            assert!(expected(Path::new(root), other_release_object).is_none());
            assert!(expected(Path::new(root), relative).is_none());
        }
        for name in [
            "checkpoint_impl.o",
            "snapshot-42.tar.zst",
            "epoch-1.jet",
            "Cargo.lock",
            "librocksdb-sys-0000000000000000/out/bfe5d317b023d6cf-checkpoint_impl.o",
        ] {
            assert!(expected(Path::new(DEBUG_BUILD), Path::new(name)).is_none());
        }
        if unsafe { libc::geteuid() } != 1000 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join(relative);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(
            &file,
            b"checkpoint data must not be deleted as a compiler object",
        )
        .unwrap();
        let original = node(&file).unwrap();
        assert!(qualified(Path::new(DEBUG_BUILD), root.path(), &file, &original).is_err());
        assert_eq!(
            fs::read(&file).unwrap(),
            b"checkpoint data must not be deleted as a compiler object"
        );
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(
            !qualified(
                Path::new(DEBUG_BUILD),
                root.path(),
                &file,
                &node(&link).unwrap()
            )
            .unwrap()
        );
    }
}
