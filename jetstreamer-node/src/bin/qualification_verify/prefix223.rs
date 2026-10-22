//! Independent private known-root prefix reread; no restart or publication authority.
use super::*;

const PREFIX: &str = "qualification-223-v1625-prefix-";
const WORKER: &str = "fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c";
const REVISION: &str = "7de8a55b54d3e11058b82f9483bb405d143b455c";
const COLD_ACCOUNTS: &str = "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE";
const COLD_BANK: &str = "8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F";
const ROOT_ACCOUNTS: &str = "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7";
const ROOT_BANK: &str = "EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB";

pub(super) fn namespace(a: &Arguments) -> bool {
    a.private_root
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.starts_with("qualification-223-v1625-prefix"))
}

pub(super) fn matches(a: &Arguments) -> bool {
    a.private_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        && a.private_root
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix(PREFIX))
            .is_some_and(|s| {
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        && a.archive == a.private_root.join("output/epoch-223.jet")
        && a.expected_epoch == 223
        && a.expected_output_start_slot == 96_336_000
        && a.expected_bootstrap_slot == 96_335_538
        && a.expected_terminal_slot == 96_767_522
        && a.expected_runtime_profile == "solana-v1.6.25"
        && a.expected_worker_sha256 == WORKER
        && a.expected_conflict.is_none()
}

pub(super) fn validate_roots(
    a: &Arguments,
    bootstrap_accounts: &str,
    bootstrap_bank: &str,
    terminal_accounts: &str,
    terminal_bank: &str,
    revision: &str,
) -> Result<(), String> {
    if namespace(a)
        && (!matches(a)
            || bootstrap_accounts != COLD_ACCOUNTS
            || bootstrap_bank != COLD_BANK
            || terminal_accounts != ROOT_ACCOUNTS
            || terminal_bank != ROOT_BANK
            || revision != REVISION)
    {
        return Err("epoch223 prefix must bind both independent canonical checkpoint identities and the exact v1.6.25 worker".into());
    }
    Ok(())
}

pub(super) fn annotate(a: &Arguments, receipt: &mut serde_json::Value) {
    if matches(a) {
        receipt["qualification_scope"] = json!({
            "known_root_prefix_reread":true,
            "complete_epoch_span_covered":false,
            "canonical_prefix_qualified":false,
            "full_cold_epoch_peak_qualified":false,
            "native_restart_qualified":false,
            "assembly_qualified":false,
            "terminal_canonical_root_independently_known":true,
            "runtime_promotion_authorized":false,
            "canonical_sidecar_authorized":false,
            "publication_authorized":false,
            "remote_mutations":false,
            "r2_mutations":false
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Arguments {
        let root =
            PathBuf::from("/home/ubuntu/.jetstreamer-private/qualification-223-v1625-prefix-test");
        Arguments {
            archive: root.join("output/epoch-223.jet"),
            private_root: root,
            receipt: None,
            expected_epoch: 223,
            expected_output_start_slot: 96_336_000,
            expected_bootstrap_slot: 96_335_538,
            expected_terminal_slot: 96_767_522,
            expected_runtime_profile: "solana-v1.6.25".into(),
            expected_worker_sha256: WORKER.into(),
            expected_conflict: None,
        }
    }
    #[test]
    fn exact_prefix_worker_and_span_cannot_escape_into_generic_through_slot_name() {
        let good = args();
        assert!(matches(&good));
        assert_eq!(
            good.expected_terminal_slot - good.expected_output_start_slot + 1,
            431_523
        );
        validate_archive_name(&good, &good.archive).unwrap();
        for change in 0..8 {
            let mut a = args();
            match change {
                0 => a.expected_epoch = 224,
                1 => a.expected_output_start_slot += 1,
                2 => a.expected_bootstrap_slot += 1,
                3 => a.expected_terminal_slot = 96_767_999,
                4 => a.expected_runtime_profile = "solana-v1.6.20".into(),
                5 => a.expected_worker_sha256 = "0".repeat(64),
                6 => a.private_root = a.private_root.with_file_name(PREFIX),
                _ => {
                    a.private_root = a
                        .private_root
                        .with_file_name("qualification-223-v1625-prefix-bad_name")
                }
            }
            a.archive = a.private_root.join(format!(
                "epoch-{}-through-{}.jet",
                a.expected_epoch, a.expected_terminal_slot
            ));
            assert!(!matches(&a));
            assert!(validate_archive_name(&a, &a.archive).is_err(), "{change}");
        }
        let mut public = args();
        public.private_root = "/home/ubuntu/horizon".into();
        public.archive = public.private_root.join("epoch-223.jet");
        assert!(!matches(&public));
        assert!(validate_archive_name(&public, &public.archive).is_err());
    }
    #[test]
    fn both_checkpoint_commitments_and_bank_hashes_are_mandatory() {
        let a = args();
        let values = [COLD_ACCOUNTS, COLD_BANK, ROOT_ACCOUNTS, ROOT_BANK, REVISION];
        validate_roots(&a, values[0], values[1], values[2], values[3], values[4]).unwrap();
        for i in 0..values.len() {
            let mut bad = values;
            bad[i] = "wrong";
            assert!(
                validate_roots(&a, bad[0], bad[1], bad[2], bad[3], bad[4]).is_err(),
                "{i}"
            );
        }
    }
    #[test]
    fn reread_scope_never_grants_full_epoch_restart_assembly_peak_or_publication() {
        let mut receipt = json!({});
        annotate(&args(), &mut receipt);
        let scope = &receipt["qualification_scope"];
        assert_eq!(scope["known_root_prefix_reread"], true);
        assert_eq!(scope["terminal_canonical_root_independently_known"], true);
        for key in [
            "complete_epoch_span_covered",
            "canonical_prefix_qualified",
            "full_cold_epoch_peak_qualified",
            "native_restart_qualified",
            "assembly_qualified",
            "runtime_promotion_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            assert_eq!(scope[key], false, "{key}");
        }
        let mut generic = args();
        generic.expected_epoch = 224;
        let mut receipt = json!({});
        annotate(&generic, &mut receipt);
        assert!(receipt.get("qualification_scope").is_none());
    }
}
