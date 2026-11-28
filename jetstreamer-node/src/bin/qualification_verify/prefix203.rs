//! Exact worker/path admission for a private epoch-203 prefix reread.
//!
//! This only selects the existing canonical checkpoint checks. It does not
//! qualify the worker, extend the prefix to the epoch end, or grant publication.

use std::path::Path;

const ORIGINAL_WORKER: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
const CAPPED_SHRINK_WORKER: &str =
    "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const SHRINK_ROOT_PREFIX: &str = "shrink-root-prefix-resource-203-";

pub(super) fn worker_matches(private_root: &Path, archive: &Path, worker: &str) -> bool {
    match worker {
        // Retain the original reader contract without relabeling its digest.
        ORIGINAL_WORKER => true,
        CAPPED_SHRINK_WORKER => {
            private_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
                && private_root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.strip_prefix(SHRINK_ROOT_PREFIX)
                            .is_some_and(|suffix| !suffix.is_empty())
                    })
                && archive == private_root.join("output/epoch-203-prefix.jet")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str =
        "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-203-f9fc5a0-v1";

    #[test]
    fn capped_worker_requires_the_separate_private_root_and_exact_output() {
        let root = Path::new(ROOT);
        let archive = root.join("output/epoch-203-prefix.jet");
        assert!(worker_matches(root, &archive, CAPPED_SHRINK_WORKER));
        for changed in [
            "/private/shrink-root-prefix-resource-203-test",
            "/home/ubuntu/horizon/shrink-root-prefix-resource-203-test",
            "/home/ubuntu/.jetstreamer-private/root-prefix-resource-203-test",
            "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-test",
            "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-203-",
            "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-203-test/nested",
        ] {
            let changed = Path::new(changed);
            assert!(!worker_matches(
                changed,
                &changed.join("output/epoch-203-prefix.jet"),
                CAPPED_SHRINK_WORKER,
            ));
        }
        for name in [
            "epoch-203-prefix.jet",
            "output/epoch-203.jet",
            "output/epoch-204-prefix.jet",
            "other/epoch-203-prefix.jet",
        ] {
            assert!(!worker_matches(
                root,
                &root.join(name),
                CAPPED_SHRINK_WORKER
            ));
        }
        assert!(!worker_matches(
            root,
            &archive,
            "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cd",
        ));
    }

    #[test]
    fn original_worker_contract_and_digest_remain_distinct() {
        let root = Path::new("/private");
        let archive = root.join("epoch-203-prefix.jet");
        assert!(worker_matches(root, &archive, ORIGINAL_WORKER));
        assert!(!worker_matches(root, &archive, CAPPED_SHRINK_WORKER));
        assert!(!worker_matches(root, &archive, &"a".repeat(64)));
    }
}
