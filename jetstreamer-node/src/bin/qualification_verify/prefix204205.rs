//! Closed independent reread profiles for the two existing capped prefixes.
//! No native restart, archive assembly or canonical publication authority.
use std::path::Path;

const WORKER: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const REVISION: &str = "86c26f843276581509c3434acc2efbf4202c44e0";
const GENERATION: &str =
    "jetstreamer-node/0.7.0/old-faithful-to-horizon-v2@3de96e71010a8a2f5e629f666227b137483bff7b";

#[derive(Clone, Copy)]
pub(super) struct Scope<'a> {
    pub private_root: &'a Path,
    pub archive: &'a Path,
    pub epoch: u64,
    pub start: u64,
    pub bootstrap: u64,
    pub terminal: u64,
    pub runtime: &'a str,
    pub worker: &'a str,
    pub conflict: bool,
}
#[derive(Clone, Copy)]
struct Profile {
    epoch: u64,
    root: &'static str,
    name: &'static str,
    start: u64,
    bootstrap: u64,
    terminal: u64,
    bootstrap_accounts: &'static str,
    terminal_accounts: &'static str,
}
const PROFILES: [Profile; 2] = [
    Profile {
        epoch: 204,
        root: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1",
        name: "epoch-204-prefix.jet",
        start: 88_128_000,
        bootstrap: 88_127_580,
        terminal: 88_559_361,
        bootstrap_accounts: "4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf",
        terminal_accounts: "83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA",
    },
    Profile {
        epoch: 205,
        root: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1",
        name: "epoch-205-prefix.jet",
        start: 88_560_000,
        bootstrap: 88_559_361,
        terminal: 88_991_050,
        bootstrap_accounts: "83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA",
        terminal_accounts: "BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp",
    },
];
pub(super) fn namespace(root: &Path) -> bool {
    root.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| {
            name.starts_with("shrink-root-prefix-resource-204")
                || name.starts_with("shrink-root-prefix-resource-205")
        })
}
fn profile(scope: Scope<'_>) -> Option<Profile> {
    PROFILES.into_iter().find(|p| p.epoch == scope.epoch)
}
pub(super) fn matches(scope: Scope<'_>) -> bool {
    profile(scope).is_some_and(|p| {
        scope.private_root == Path::new(p.root)
            && scope.archive == Path::new(p.root).join("output").join(p.name)
            && scope.start == p.start
            && scope.bootstrap == p.bootstrap
            && scope.terminal == p.terminal
            && scope.runtime == "solana-v1.6.16"
            && scope.worker == WORKER
            && !scope.conflict
    })
}
pub(super) fn validate_roots(
    scope: Scope<'_>,
    bootstrap_accounts: &str,
    terminal_accounts: &str,
    revision: &str,
    generation: &str,
) -> Result<(), String> {
    if namespace(scope.private_root)
        && (!matches(scope)
            || profile(scope).is_none_or(|p| {
                bootstrap_accounts != p.bootstrap_accounts
                    || terminal_accounts != p.terminal_accounts
                    || revision != REVISION
                    || generation != GENERATION
            }))
    {
        return Err("capped 204/205 prefix reread requires its exact private scope, canonical snapshot accounts roots and runtime revision".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_actual_scopes_cover_the_prefix_and_leave_the_real_suffix() {
        for (p, count, suffix) in [(PROFILES[0], 431_362, 638), (PROFILES[1], 431_051, 949)] {
            let archive = Path::new(p.root).join("output").join(p.name);
            let scope = Scope {
                private_root: Path::new(p.root),
                archive: &archive,
                epoch: p.epoch,
                start: p.start,
                bootstrap: p.bootstrap,
                terminal: p.terminal,
                runtime: "solana-v1.6.16",
                worker: WORKER,
                conflict: false,
            };
            assert!(matches(scope));
            assert!(namespace(scope.private_root));
            assert_eq!(p.terminal - p.start + 1, count);
            assert_eq!((p.epoch + 1) * 432_000 - 1 - p.terminal, suffix);
            assert!(
                validate_roots(
                    scope,
                    p.bootstrap_accounts,
                    p.terminal_accounts,
                    REVISION,
                    GENERATION
                )
                .is_ok()
            );
            for changed in [
                Scope {
                    epoch: 223,
                    ..scope
                },
                Scope {
                    start: p.start + 1,
                    ..scope
                },
                Scope {
                    bootstrap: p.bootstrap + 1,
                    ..scope
                },
                Scope {
                    terminal: (p.epoch + 1) * 432_000 - 1,
                    ..scope
                },
                Scope {
                    runtime: "solana-v1.6.20",
                    ..scope
                },
                Scope {
                    worker: "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a",
                    ..scope
                },
                Scope {
                    conflict: true,
                    ..scope
                },
            ] {
                assert!(!matches(changed));
                assert!(
                    validate_roots(
                        changed,
                        p.bootstrap_accounts,
                        p.terminal_accounts,
                        REVISION,
                        GENERATION
                    )
                    .is_err()
                );
            }
            for (cold, root, revision, generation) in [
                ("foreign", p.terminal_accounts, REVISION, GENERATION),
                (p.bootstrap_accounts, "foreign", REVISION, GENERATION),
                (
                    p.bootstrap_accounts,
                    p.terminal_accounts,
                    "foreign",
                    GENERATION,
                ),
                (
                    p.bootstrap_accounts,
                    p.terminal_accounts,
                    REVISION,
                    "foreign",
                ),
            ] {
                assert!(validate_roots(scope, cold, root, revision, generation).is_err());
            }
        }
    }
    #[test]
    fn public_nested_cross_epoch_and_generic_filename_fallbacks_are_not_admitted() {
        let p = PROFILES[0];
        let archive = Path::new(p.root).join("output").join(p.name);
        let scope = Scope {
            private_root: Path::new(p.root),
            archive: &archive,
            epoch: p.epoch,
            start: p.start,
            bootstrap: p.bootstrap,
            terminal: p.terminal,
            runtime: "solana-v1.6.16",
            worker: WORKER,
            conflict: false,
        };
        for root in [
            "/home/ubuntu/horizon/shrink-root-prefix-resource-204-fcbf3992-v1",
            "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-other",
            "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1",
        ] {
            assert!(!matches(Scope {
                private_root: Path::new(root),
                ..scope
            }));
        }
        for name in [
            "output/epoch-204-through-88559361.jet",
            "output/epoch-204.jet",
            "output/epoch-205-prefix.jet",
            "nested/output/epoch-204-prefix.jet",
        ] {
            assert!(!matches(Scope {
                archive: &Path::new(p.root).join(name),
                ..scope
            }));
        }
        for malformed in [
            "shrink-root-prefix-resource-204",
            "shrink-root-prefix-resource-205evil",
        ] {
            assert!(namespace(Path::new(malformed)));
        }
    }
}
