use super::{BOOTSTRAP_SLOT, OUTPUT_END_SLOT, verify_checkpoints, verify_rooted_tables};
use crate::{BankHashExpectation, SlotPresenceState, build_slot_presence_map};
use jetstreamer_firehose::{
    epochs::fetch_epoch_stream,
    index::{SlotOffsetIndexError, slot_to_range},
    node::Node,
    node_reader::NodeReader,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

#[test]
fn all_three_accounts_roots_are_required() {
    let mut expected = BTreeMap::new();
    for (slot, hash) in [
        (
            BOOTSTRAP_SLOT,
            "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7",
        ),
        (97_199_617, "HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi"),
        (
            OUTPUT_END_SLOT,
            "EXCmpk8xjtzsow8EH56CQJzQncMgiF6D1s9DJ3pw9q8d",
        ),
    ] {
        expected.insert(
            slot,
            BankHashExpectation::LegacyAccountsHash(hash.parse().unwrap()),
        );
    }
    verify_checkpoints(&expected).unwrap();
    for slot in [BOOTSTRAP_SLOT, 97_199_617, OUTPUT_END_SLOT] {
        let mut changed = expected.clone();
        changed.remove(&slot);
        assert!(verify_checkpoints(&changed).is_err());
        changed.insert(
            slot,
            BankHashExpectation::LegacyAccountsHash(Default::default()),
        );
        assert!(verify_checkpoints(&changed).is_err());
    }
}

/// The mirror serves the authentic CAR headers and the bounded gap bodies in the
/// sealed repair receipt. The private fixture ledger contains only slot-to-CID files.
#[tokio::test]
#[ignore = "requires the sealed epoch 224/225 tables, three compact indexes and loopback CAR ranges"]
async fn scheduler_and_car_reader_use_the_repaired_ranges() {
    let base =
        reqwest::Url::parse(&env::var("JETSTREAMER_COMPACT_INDEX_BASE_URL").unwrap()).unwrap();
    assert_eq!(base.scheme(), "http");
    assert_eq!(base.host_str(), Some("127.0.0.1"));
    assert_eq!(jetstreamer_firehose::archive::car_location().url(), &base);
    assert_eq!(
        jetstreamer_firehose::index::get_index_base_url().unwrap(),
        base
    );
    let ledger = PathBuf::from(env::var_os("HORIZON224_QUALIFIED_LEDGER").unwrap());
    for epoch in 223..=225 {
        let names: Vec<_> = fs::read_dir(ledger.join(format!("compact-indexes/{epoch}")))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1);
        assert!(names[0].to_str().unwrap().ends_with("-slot-to-cid.index"));
    }
    verify_rooted_tables().await.unwrap();
    assert!(
        crate::epoch199200_presence::RootedSlotPresence::configured(223)
            .await
            .unwrap()
            .is_none()
    );
    let manifest = PathBuf::from(env::var_os("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST").unwrap());
    let sealed = manifest.parent().unwrap();
    let repair = fs::read(sealed.join("repair.json")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&repair)),
        "c1061e21faacdaac1e839a3f392ec2a11f4557afe322c8a09b2f5529bdee284c"
    );
    let repair: serde_json::Value = serde_json::from_slice(&repair).unwrap();
    let map = build_slot_presence_map(
        BOOTSTRAP_SLOT + 1,
        OUTPUT_END_SLOT,
        Arc::new(AtomicBool::new(false)),
        &ledger,
        224,
    )
    .await
    .unwrap();
    let mut next_present = None;
    for epoch in (223..=225).rev() {
        let raw = if epoch == 223 {
            let raw = fs::read(env::var_os("HORIZON224_WARMUP_RAW").unwrap()).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&raw)),
                "a831dbf86140a50269412bc1600da9a05b2f377d82db3e5ec78ab21a410aa8a9"
            );
            raw
        } else {
            fs::read(sealed.join(format!("epoch-{epoch}-slot-ranges.repaired.raw"))).unwrap()
        };
        let start = (epoch * 432_000).max(BOOTSTRAP_SLOT + 1);
        let end = ((epoch + 1) * 432_000 - 1).min(OUTPUT_END_SLOT);
        for slot in (start..=end).rev() {
            let pos = (slot % 432_000) as usize * 12 + 8;
            let present = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) != 0;
            let state = if present {
                SlotPresenceState::Present
            } else {
                SlotPresenceState::Missing
            };
            assert_eq!(map.state(slot), Some(state), "scheduler slot {slot}");
            assert_eq!(
                map.next_present_after(slot),
                next_present,
                "scheduler successor of {slot}"
            );
            if present {
                next_present = Some(slot);
            }
        }
    }
    let mut verified = 0;
    for row in repair["outputs"].as_array().unwrap() {
        let epoch = row["epoch"].as_u64().unwrap();
        let mut reader = NodeReader::new(fetch_epoch_stream(epoch, &reqwest::Client::new()).await);
        let skips = row["noncanonical_compact_only_slots"].as_array().unwrap();
        let gaps = row["gaps"].as_array().unwrap();
        assert_eq!(skips.len(), gaps.len());
        for (skip, gap) in skips.iter().zip(gaps) {
            let skip = skip.as_u64().unwrap();
            let slot = gap["slot"].as_u64().unwrap();
            let parent = gap["parent"].as_u64().unwrap();
            assert!(parent < skip && skip < slot);
            assert_eq!(map.next_present_after(skip), Some(slot));
            assert!(
                matches!(slot_to_range(skip).await, Err(SlotOffsetIndexError::SlotNotFound(s, url)) if s == skip && url.scheme() == "file")
            );
            let range = (
                gap["offset"].as_u64().unwrap(),
                gap["length"].as_u64().unwrap(),
            );
            assert_eq!(slot_to_range(slot).await.unwrap(), range);
            reader.seek_to_slot(skip).await.unwrap();
            let records = gap["records"].as_u64().unwrap();
            for index in 1..=records {
                let raw = reader.next().await.unwrap();
                assert_eq!(raw.cid.hash().code(), 0x12);
                assert_eq!(raw.cid.hash().digest(), &Sha256::digest(&raw.data)[..]);
                if let Node::Block(block) = raw.parse().unwrap() {
                    assert_eq!(index, records);
                    assert_eq!(raw.cid.to_string(), gap["block_cid"].as_str().unwrap());
                    let observed = (block.slot, block.meta.parent_slot);
                    assert_eq!(observed, (slot, parent));
                    verified += 1;
                }
            }
        }
    }
    assert_eq!(verified, 15);
}
