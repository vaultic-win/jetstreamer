use super::*;
use jetstreamer_horizon::{
    archive::{
        ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveWriter, ArchiveWriterConfig,
        BootstrapStateKind, RuntimeAdmission, TransactionMetadataPolicy, reencode_archive_prefix,
    },
    block_metas::BlockMeta,
};
use solana_address::Address;
use solana_signature::Signature;
use std::io::{self, Cursor};

const FIRST: u64 = 62_640_000;
const ALL: u64 = 205;
const KEEP: u64 = 192;

fn provenance(count: u64) -> ArchiveProvenance {
    ArchiveProvenance::V2(ArchiveProvenanceV2 {
        base: ArchiveProvenanceV1 {
            generation_profile: "jetstreamer-node/historical-replay-v1".into(),
            runtime_profile: "solana-v1.4.25".into(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: "893cc7647248a3536fb6e6d0b5e51c71446b862d".into(),
            runtime_toolchain: "rustc1.46.0".into(),
            genesis_hash: Hash::new_from_array([5; 32]),
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_slot: FIRST - 11,
            bootstrap_state_hash: Hash::new_from_array([9; 32]),
            requested_slot_start: FIRST,
            requested_slot_count: count,
            transaction_metadata: TransactionMetadataPolicy::runtime_reconstructed(),
        },
        worker_executable_sha256: [57; 32],
    })
}
fn config() -> ArchiveWriterConfig {
    ArchiveWriterConfig {
        bucket_slots: 64,
        compression: Compression::Zstd,
        ..Default::default()
    }
}
fn fixture(epoch_count: u64, duplicate: bool) -> Vec<u8> {
    let mut w =
        ArchiveWriter::new_with_provenance(Vec::new(), 145, FIRST, ALL, config(), &provenance(ALL))
            .unwrap();
    let mut parent = Hash::new_from_array([7; 32]);
    let mut parent_slot = FIRST - 1;
    w.preserve_initial_poh_anchor(FIRST, parent).unwrap();
    for offset in 0..ALL {
        let slot = FIRST + offset;
        if ![1, 72, KEEP - 1, ALL - 1].contains(&offset) {
            w.write_skipped_slot(slot).unwrap();
            continue;
        }
        w.begin_slot(slot).unwrap();
        let mut update = AccountUpdateView {
            pubkey: Address::new_from_array([7; 32]),
            owner: Address::new_from_array([8; 32]),
            executable: false,
            data: b"retained exactly",
            lamports: offset,
            rent_epoch: 5,
            write_version: (1 << 54) + offset * 10,
        };
        if offset == 1 || duplicate && offset == 72 {
            let mut e = EpochMeta::new_boxed();
            e.epoch = 145;
            e.start_slot = FIRST;
            e.slot_count = epoch_count;
            e.first_block_slot = slot;
            e.num_reward_partitions = Some(17);
            e.updates.push(&update).unwrap();
            w.write_epoch_meta(&e).unwrap();
            update.write_version += 1;
        }
        w.write_orphan_update(&update).unwrap();
        update.write_version += 1;
        let mut tx = Transaction::new_boxed();
        tx.signatures.push(Signature::default());
        tx.push_account_update(&update).unwrap();
        w.write_transaction(&tx).unwrap();
        update.write_version += 1;
        w.write_orphan_update(&update).unwrap();
        let mut block = BlockMeta::new_boxed();
        block.slot = slot;
        block.parent_slot = parent_slot;
        block.parent_blockhash = parent;
        block.blockhash = Hash::new_from_array([offset as u8; 32]);
        block.executed_transaction_count = 1;
        block.entry_count = 1;
        w.end_slot(
            &block,
            &[EntryRecord {
                num_hashes: 1,
                tx_count: 1,
            }],
        )
        .unwrap();
        parent = block.blockhash;
        parent_slot = slot;
    }
    w.finish().unwrap().0
}
fn buckets(bytes: &[u8]) -> Vec<BucketIndexEntry> {
    ArchiveReader::open(Cursor::new(bytes))
        .unwrap()
        .bucket_index()
        .to_vec()
}
#[test]
fn aligns_with_independent_reencoder_and_raw_interior_buckets() {
    let src = fixture(ALL, false);
    let mut dst = Vec::new();
    let digest = copy_aligned_prefix(Cursor::new(&src), &mut dst, KEEP, &provenance(KEEP)).unwrap();
    let (_, reference) =
        reencode_archive_prefix(Cursor::new(&src), Vec::new(), config(), KEEP).unwrap();
    assert_eq!(digest, reference.output_semantic_sha256);
    assert_ne!(digest, reference.source_semantic_sha256);
    let mut actual = ArchiveReader::open(Cursor::new(&dst)).unwrap();
    actual.verify_chain = true;
    assert!(actual.has_complete_slot_coverage().unwrap());
    assert_eq!(actual.provenance().unwrap(), Some(provenance(KEEP)));
    assert_eq!(actual.header().slot_count, KEEP);
    let mut observed = SemanticDigest::new();
    assert_eq!(
        actual.read_slots(FIRST, KEEP + 1, &mut observed).unwrap(),
        KEEP
    );
    assert_eq!(observed.finish().unwrap(), digest);
    let original = buckets(&src);
    assert_eq!(actual.bucket_count(), 3);
    for (&s, &d) in original.iter().zip(actual.bucket_index()).skip(1) {
        let range = |x: BucketIndexEntry| x.offset as usize..(x.offset + x.len) as usize;
        assert_eq!(src[range(s)], dst[range(d)]);
    }
}
#[test]
fn rejects_invalid_evidence_and_incomplete_writes() {
    let rejects = |src: &[u8], count: u64, expected: ArchiveProvenance| {
        assert!(copy_aligned_prefix(Cursor::new(src), io::sink(), count, &expected).is_err());
    };
    rejects(&fixture(ALL - 1, false), KEEP, provenance(KEEP));
    rejects(&fixture(ALL, true), KEEP, provenance(KEEP));
    let mut src = fixture(ALL, false);
    rejects(&src, KEEP - 1, provenance(KEEP - 1));
    let ArchiveProvenance::V2(mut foreign) = provenance(KEEP) else {
        unreachable!()
    };
    foreign.worker_executable_sha256[0] ^= 1;
    rejects(&src, KEEP, ArchiveProvenance::V2(foreign));
    rejects(&src[..src.len() - 10], KEEP, provenance(KEEP));
    let mut short = [0; 512];
    assert!(
        copy_aligned_prefix(Cursor::new(&src), &mut short[..], KEEP, &provenance(KEEP)).is_err()
    );
    let idx = buckets(&src);
    let second = idx[1];
    let mut cursor = lencode::io::Cursor::new(&src[second.offset as usize..]);
    let mut header = BucketHeader::decode_ext(&mut cursor, None).unwrap();
    let header_len = cursor.position();
    header.poh_start_hash = Hash::new_from_array([57; 32]);
    let mut serialized = Vec::new();
    header.encode_ext(&mut serialized, None).unwrap();
    assert_eq!(serialized.len(), header_len);
    let mut wrong_anchor = src.clone();
    let start = second.offset as usize;
    wrong_anchor[start..start + header_len].copy_from_slice(&serialized);
    rejects(&wrong_anchor, KEEP, provenance(KEEP));
    for i in [0, 1] {
        let byte = (idx[i].offset + idx[i].len - 1) as usize;
        src[byte] ^= 1;
        rejects(&src, KEEP, provenance(KEEP));
        src[byte] ^= 1;
    }
}

#[test]
fn assembly_for_recovery_matches_the_strict_export_byte_for_byte() {
    let source = fixture(ALL, false);
    let mut strict = Vec::new();
    copy_aligned_prefix(Cursor::new(&source), &mut strict, KEEP, &provenance(KEEP)).unwrap();
    let mut output = Vec::new();
    write_frames(
        Cursor::new(source),
        &mut output,
        KEEP,
        &provenance(KEEP),
        |_, _, _, _, _| Ok(()),
    )
    .unwrap();
    assert_eq!(output, strict);
}
