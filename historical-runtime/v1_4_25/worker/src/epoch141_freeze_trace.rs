//! Read-only frozen-Bank evidence for one cold 141 diagnostic generation.
use serde_json::{json, Value};
use solana_runtime::bank::Bank;
use solana_sdk::hash::{extend_and_hash, hash, hashv, Hash};
use std::collections::BTreeMap;

const BOOTSTRAP: u64 = 60_911_751;
const PRE_BOUNDARY: u64 = 60_911_999;
#[cfg(not(feature = "epoch141-vote-prefix-diagnostic"))]
pub(crate) const TERMINAL: u64 = 60_912_004;
#[cfg(feature = "epoch141-vote-prefix-diagnostic")]
pub(crate) const TERMINAL: u64 = 60_912_005;

pub(crate) fn bootstrap(slot: u64) -> Result<(), String> {
    if slot != BOOTSTRAP {
        return Err(format!(
            "freeze-component diagnostic requires cold bootstrap{}; got{}",
            BOOTSTRAP, slot
        ));
    }
    Ok(())
}

pub(crate) fn transition(from: u64, to: u64) -> Result<(), String> {
    if from > TERMINAL || (to > TERMINAL && from != TERMINAL) {
        return Err(format!("freeze-component diagnostic cannot skip or execute past{}", TERMINAL));
    }
    Ok(())
}

pub(crate) fn terminal(slot: u64) -> bool {
    slot == TERMINAL
}

fn frozen(bank: &Bank) -> Result<Value, String> {
    if !bank.is_complete() || bank.hash() == Hash::default() {
        return Err("freeze-component evidence requires a complete frozen Bank".to_string());
    }
    let parent = bank
        .parent()
        .ok_or("freeze-component evidence requires the unsquashed parent")?;
    let info = bank.accounts().bank_hash_info_at(bank.slot());
    let signature_count = bank.signature_count().to_le_bytes();
    let parent_hash = parent.hash();
    let last_blockhash = bank.last_blockhash();
    let base = hashv(&[
        parent_hash.as_ref(),
        info.hash.as_ref(),
        &signature_count,
        last_blockhash.as_ref(),
    ]);
    let hard_forks = bank.hard_forks();
    let forks = hard_forks.read().map_err(|_| "hard-fork lock poisoned")?;
    let extension = forks.get_hash_data(bank.slot(), bank.parent_slot());
    let reconstructed = match extension {
        Some(bytes) => extend_and_hash(&base, &bytes),
        None => base,
    };
    if reconstructed != bank.hash() {
        return Err(
            "freeze-component reconstruction differs from the frozen Bank hash".to_string(),
        );
    }
    let rewards = bank.rewards.read().map_err(|_| "reward lock poisoned")?;
    if rewards.len() > 1_000_000 {
        return Err("freeze-component reward census exceeds its bound".to_string());
    }
    let mut ordered = rewards.clone();
    ordered.sort_by_key(|(key, reward)| {
        (
            *key,
            reward.reward_type as u8,
            reward.lamports,
            reward.post_balance,
        )
    });
    let mut totals = BTreeMap::<String, i64>::new();
    for (_, reward) in &ordered {
        let total = totals.entry(reward.reward_type.to_string()).or_insert(0);
        *total = total
            .checked_add(reward.lamports)
            .ok_or("reward total overflow")?;
    }
    let reward_bytes = bincode::serialize(&ordered).map_err(|e| e.to_string())?;
    Ok(json!({
        "schema":"jetstreamer-private-epoch141-frozen-bank-components-v2",
        "worker_entry_terminal_slot":TERMINAL,
        "vote_prefix_diagnostic":cfg!(feature="epoch141-vote-prefix-diagnostic"),
        "slot":bank.slot(),"epoch":bank.epoch(),"parent_slot":bank.parent_slot(),"parent_epoch":parent.epoch(),
        "bank_hash":bank.hash().to_string(),"parent_hash":parent_hash.to_string(),
        "accounts_delta_hash":info.hash.to_string(),"accounts_delta_stats":info.stats,
        "signature_count":bank.signature_count(),"last_blockhash":last_blockhash.to_string(),
        "hard_fork_extension_bytes":extension,"registered_hard_forks":forks.iter().cloned().collect::<Vec<_>>(),
        "reconstructed_hash_matches":true,"collector_id":bank.collector_id().to_string(),
        "capitalization":bank.capitalization(),"tick_height":bank.tick_height(),"max_tick_height":bank.max_tick_height(),
        "clock":bank.clock(),"reward_count":ordered.len(),"reward_totals_lamports":totals,
        "reward_list_hash_base58":hash(&reward_bytes).to_string(),
        "reward_hash_encoding":"bincode1.3.1 Vec<(Pubkey,RewardInfo)> sorted by (Pubkey,RewardType,lamports,post_balance), SHA256, base58",
        "ordinary_replay_claim":false,"full_epoch_verified":false,"publication_authorized":false,
        "runtime_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false
    }))
}

pub(crate) fn record(bank: &Bank) -> Result<(), String> {
    if bank.slot() == PRE_BOUNDARY || bank.slot() == 60_912_004 || bank.slot() == TERMINAL {
        eprintln!("epoch141 frozen-bank components: {}", frozen(bank)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_runtime::genesis_utils::create_genesis_config;
    use solana_sdk::pubkey::Pubkey;
    use std::sync::Arc;

    fn bank(fork: bool) -> (Bank, tempfile::TempDir) {
        let genesis = create_genesis_config(1_000_000_000);
        let root = crate::snapshot::private_state_dir(None).unwrap();
        let paths = crate::snapshot::private_account_paths(&root).unwrap();
        let parent = Arc::new(Bank::new_with_paths(
            &genesis.genesis_config,
            paths,
            &[],
            None,
            None,
            std::collections::HashSet::new(),
        ));
        while !parent.is_complete() {
            parent.register_tick(&Hash::new_unique());
        }
        parent.freeze();
        let bank = Bank::new_from_parent(&parent, &Pubkey::new_unique(), 1);
        while !bank.is_complete() {
            bank.register_tick(&Hash::new_unique());
        }
        if fork {
            bank.hard_forks().write().unwrap().register(1);
        }
        bank.freeze();
        (bank, root)
    }

    #[test]
    fn frozen_components_reconstruct_the_real_bank_without_writes() {
        let (bank, _root) = bank(false);
        let cursor = bank.accounts().accounts_db.next_write_version();
        let before = bank.hash();
        let first = frozen(&bank).unwrap();
        assert_eq!(first, frozen(&bank).unwrap());
        assert_eq!(bank.hash(), before);
        assert_eq!(bank.accounts().accounts_db.next_write_version(), cursor);
        assert_eq!(first["bank_hash"], json!(before.to_string()));
        assert_eq!(first["reconstructed_hash_matches"], json!(true));
        assert_eq!(first["publication_authorized"], json!(false));
    }

    #[test]
    fn hard_fork_extension_is_included_in_the_independent_reconstruction() {
        let (bank, _root) = bank(true);
        let first = frozen(&bank).unwrap();
        assert_eq!(first["reconstructed_hash_matches"], json!(true));
        assert_eq!(
            first["hard_fork_extension_bytes"],
            json!([1, 0, 0, 0, 0, 0, 0, 0])
        );
        // Registering after freeze cannot change its already committed hash.
        // A changed hash input must be rejected instead of misreported.
        bank.hard_forks().write().unwrap().register(1);
        assert!(frozen(&bank).unwrap_err().contains("differs"));
    }

    #[test]
    fn legacy_reward_encoding_has_a_fixed_cross_tool_fixture() {
        use solana_runtime::bank::{RewardInfo, RewardType};
        let rewards = vec![(
            Pubkey::new_from_array([7; 32]),
            RewardInfo {
                reward_type: RewardType::Rent,
                lamports: -2,
                post_balance: 9,
            },
        )];
        let mut expected = 1u64.to_le_bytes().to_vec();
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&(-2i64).to_le_bytes());
        expected.extend_from_slice(&9u64.to_le_bytes());
        assert_eq!(bincode::serialize(&rewards).unwrap(), expected);
    }

    #[test]
    #[ignore = "requires the separately sealed release freeze-component worker; protocol only, no Bank initialization"]
    fn sealed_release_worker_stdio_capability() {
        use jetstreamer_historical_protocol::{
            read_frame, write_frame, BackendQualification, Request, RequestBody, Response,
            ResponseBody, PROTOCOL_VERSION,
        };
        use sha2::{Digest, Sha256};
        use std::{
            fs,
            os::unix::fs::MetadataExt,
            path::Path,
            process::{Command, Stdio},
        };
        let profile = std::env::var("SEALED_WORKER_PROFILE").unwrap_or_default();
        let selected = match profile.as_str() {
            "corrected-default" => "/usr/local/lib/jetstreamer/horizon-v1425-corrected-default-candidate-20261023-v1/jetstreamer-historical-worker-v1-4-25",
            "capped" => "/usr/local/lib/jetstreamer/horizon-v1425-capped-candidate-20261023-v1/jetstreamer-historical-worker-v1-4-25",
            "" if cfg!(feature = "epoch141-vote-prefix-diagnostic") => {
            "/usr/local/lib/jetstreamer/horizon-epoch141-vote-prefix-worker-20261023-v1/jetstreamer-historical-worker-v1-4-25"
            },
            "" => {
            "/usr/local/lib/jetstreamer/horizon-epoch141-freeze-worker-20261023-v1/jetstreamer-historical-worker-v1-4-25"
            },
            _ => panic!("unknown sealed worker protocol-only profile"),
        };
        let path = Path::new(selected);
        let expected = std::env::var("FREEZE_WORKER_SHA256").expect("explicit release worker hash");
        let before = fs::symlink_metadata(path).unwrap();
        assert!(
            before.is_file()
                && before.uid() == 0
                && before.nlink() == 1
                && before.mode() & 0o222 == 0
                && before.len() < 128 << 20
        );
        assert_eq!(path.canonicalize().unwrap(), path);
        assert_eq!(
            format!("{:x}", Sha256::digest(&fs::read(path).unwrap())),
            expected
        );
        let mut child = Command::new(path)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = child.stdout.take().unwrap();
        write_frame(
            &mut input,
            &Request {
                id: 1,
                body: RequestBody::Hello {
                    protocol_version: PROTOCOL_VERSION,
                },
            },
        )
        .unwrap();
        let response: Response = read_frame(&mut output).unwrap().unwrap();
        assert_eq!(response.request_id, 1);
        match response.body {
            ResponseBody::Handshake(h) => {
                assert_eq!(h.backend_id, "solana-v1.4.25");
                assert_eq!(h.qualification, BackendQualification::Candidate);
                assert_eq!(h.solana_commit, "893cc7647248a3536fb6e6d0b5e51c71446b862d");
                assert_eq!(h.rust_toolchain, "rustc 1.46.0 (04488afe3 2020-08-24)");
            }
            _ => panic!("unexpected HELLO response"),
        }
        for (id, body) in vec![(2, RequestBody::Ping), (3, RequestBody::Shutdown)] {
            write_frame(&mut input, &Request { id, body }).unwrap();
            let r: Response = read_frame(&mut output).unwrap().unwrap();
            assert_eq!(r.request_id, id);
            assert!(match r.body {
                ResponseBody::Pong => id == 2,
                ResponseBody::ShuttingDown => id == 3,
                _ => false,
            });
        }
        drop(input);
        assert!(child.wait().unwrap().success());
        let after = fs::symlink_metadata(path).unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime_nsec(),
                before.ctime_nsec()
            ),
            (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime_nsec(),
                after.ctime_nsec()
            )
        );
        println!("sealed freeze worker{} HELLO/PING/SHUTDOWN passed; no Bank initialized; no replay or publication authority",expected);
    }

    #[test]
    fn cold_bootstrap_and_worker_transition_bound_are_closed() {
        bootstrap(BOOTSTRAP).unwrap();
        assert!(bootstrap(BOOTSTRAP - 1).is_err());
        transition(PRE_BOUNDARY, TERMINAL).unwrap();
        transition(TERMINAL, TERMINAL + 1000).unwrap(); // freeze, record, then stop; never construct this child
        assert!(transition(PRE_BOUNDARY, TERMINAL + 1).is_err());
        assert!(transition(TERMINAL + 1, TERMINAL + 2).is_err());
        assert!(terminal(TERMINAL));
    }
}
