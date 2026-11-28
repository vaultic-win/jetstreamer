//! Epoch 266 exact-worker bootstrap harness.
#![recursion_limit = "256"]
#[cfg(feature = "capped-worker")]
mod capped;
#[cfg(feature = "capped-worker")]
#[path = "capped_site.rs"]
mod capped_site;
#[path = "../../horizon265-native-input/src/gate.rs"]
mod first_guard;
#[path = "../../horizon261-native-input/src/gate.rs"]
mod gate;
mod profile;
mod tmpfs;

fn main() {
    if std::env::args_os()
        .skip(1)
        .eq([std::ffi::OsString::from("--validate-inputs")])
    {
        finish(validate_inputs());
    } else {
        finish(run_with::<Checks>());
    }
}

fn validate_inputs() -> Result<()> {
    inputs()?;
    println!(
        "{}",
        json!({"schema":"horizon266-sealed-input-validation-v1",
      "input_packet_sha256":PACKET_SHA,"snapshot_sha256":SNAPSHOT_SHA,
      "bootstrap_slot":SLOT,"measured_identities_accepted":true,"worker_started":false,
      "native_runtime_qualified":false,"replay_launch_authorized":false,"remote_mutations":false})
    );
    Ok(())
}
#[cfg(not(feature = "capped-worker"))]
const WORKER: &str = "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-historical-worker-v1-8-11";
#[cfg(not(feature = "capped-worker"))]
const WORKER_SHA: &str = "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae";
#[cfg(feature = "capped-worker")]
use capped_site::{WORKER, WORKER_SHA};
const GENESIS: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/genesis.tar.bz2";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const BACKEND: &str = "solana-v1.8.11";
const SOLANA_COMMIT: &str = "423a4d65461e36fefb371a2f164c20c4e7ed5afa";
const WORKER_BYTES: u64 = 6_491_264;
include!("../../horizon265-native-input/src/session.rs");

struct Checks;

impl RuntimeChecks for Checks {
    const DEADLINE_SECS: u64 = 7200;

    #[cfg(feature = "capped-worker")]
    fn match_original(packet: &Value, initial: &Initialized, bank: &Checkpoint) -> Result<()> {
        capped::match_original(packet, initial, bank)
    }
    fn fingerprint(h: &Handshake) -> Result<()> {
        ensure!(
            h.solana_tag == "v1.8.11"
                && h.rust_toolchain == "rustc 1.52.1 (9bc8c42bb 2021-05-09)"
                && h.target == "x86_64-unknown-linux-gnu",
            "v1.8.11 build fingerprint differs"
        );
        Ok(())
    }
    fn initialized(i: &Initialized) -> Result<()> {
        ensure!(i.ticks_per_slot == 64, "mainnet tick rate differs");
        Ok(())
    }
    fn frozen(i: &Initialized, c: &Checkpoint) -> Result<()> {
        ensure!(
            c.last_blockhash == i.last_blockhash,
            "frozen last blockhash changed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod exact_tests {
    use super::*;
    #[test]
    fn exact_266_worker_checks_refuse_foreign_tag_compiler_target_tick_rate_and_blockhash() {
        let h = Handshake {
            protocol_version: PROTOCOL_VERSION,
            backend_id: BACKEND.into(),
            qualification: BackendQualification::Candidate,
            solana_tag: "v1.8.11".into(),
            solana_commit: SOLANA_COMMIT.into(),
            rust_toolchain: "rustc 1.52.1 (9bc8c42bb 2021-05-09)".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            required_genesis_hash: MAINNET_GENESIS_HASH.into(),
        };
        Checks::fingerprint(&h).unwrap();
        for field in ["tag", "compiler", "target"] {
            let mut wrong = h.clone();
            match field {
                "tag" => wrong.solana_tag.clear(),
                "compiler" => wrong.rust_toolchain.clear(),
                _ => wrong.target.clear(),
            }
            assert!(Checks::fingerprint(&wrong).is_err());
        }
        let mut i = Initialized {
            genesis_hash: MAINNET_GENESIS_HASH.into(),
            source: InitializedSource::Genesis,
            slot: SLOT,
            last_blockhash: vec![7; 32],
            ticks_per_slot: 64,
            next_write_version: 15,
        };
        Checks::initialized(&i).unwrap();
        i.ticks_per_slot = 1;
        assert!(Checks::initialized(&i).is_err());
        let mut c = Checkpoint {
            slot: SLOT,
            bank_hash: vec![1; 32],
            accounts_hash: vec![1; 32],
            last_blockhash: i.last_blockhash.clone(),
            capitalization: 1,
            transaction_count: 0,
            tick_height: 1,
            slot_complete: true,
            writes: vec![],
            next_write_version: 15,
        };
        Checks::frozen(&i, &c).unwrap();
        c.last_blockhash[0] ^= 1;
        assert!(Checks::frozen(&i, &c).is_err());
    }
}
