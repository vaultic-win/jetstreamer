//! Offline deterministic prefix-export benchmark. No network or real archives.
use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{
        ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveReader, ArchiveWriter,
        ArchiveWriterConfig, BootstrapStateKind, Compression, EpochMeta, RuntimeAdmission,
        SemanticDigest, TransactionMetadataPolicy, reencode_archive_prefix,
    },
    block_metas::BlockMeta,
};
use lencode::Encode;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_hash::Hash;
use std::{hint::black_box, io::Cursor, time::Instant};

fn source() -> Vec<u8> {
    let count = 64;
    let provenance = ArchiveProvenanceV2 {
        base: ArchiveProvenanceV1 {
            generation_profile: "offline-semantic-prefix-benchmark".into(),
            runtime_profile: "synthetic".into(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: "offline".into(),
            runtime_toolchain: "offline".into(),
            genesis_hash: Hash::new_from_array([5; 32]),
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_slot: 431999,
            bootstrap_state_hash: Hash::new_from_array([9; 32]),
            requested_slot_start: 432000,
            requested_slot_count: count,
            transaction_metadata: TransactionMetadataPolicy::observed(),
        },
        worker_executable_sha256: [0x42; 32],
    };
    let mut writer = ArchiveWriter::new_with_provenance(
        Vec::new(),
        1,
        432000,
        count,
        ArchiveWriterConfig {
            bucket_slots: 4,
            compression: Compression::Lz4,
            ..Default::default()
        },
        &provenance.into(),
    )
    .unwrap();
    let mut parent = Hash::new_from_array([0xa5; 32]);
    writer.preserve_initial_poh_anchor(432000, parent).unwrap();
    let mut data = vec![0x42; 4 << 20];
    for i in 0..count {
        let slot = 432000 + i;
        data[(i as usize * 7919) % (4 << 20)] = (i as u8).wrapping_mul(17);
        writer.begin_slot(slot).unwrap();
        if i == 0 {
            let mut epoch = EpochMeta::new_boxed();
            epoch.epoch = 1;
            epoch.start_slot = 432000;
            epoch.slot_count = count;
            epoch.first_block_slot = slot;
            writer.write_epoch_meta(&epoch).unwrap();
        }
        writer
            .write_orphan_update(&AccountUpdateView {
                pubkey: Address::new_from_array([7; 32]),
                lamports: i,
                owner: Address::new_from_array([8; 32]),
                executable: false,
                rent_epoch: u64::MAX,
                write_version: 9_007_199_254_740_993 + i,
                data: &data,
            })
            .unwrap();
        let mut block = BlockMeta::new_boxed();
        block.slot = slot;
        block.parent_slot = slot - 1;
        block.parent_blockhash = parent;
        block.blockhash = Hash::new_from_array([i as u8 + 1; 32]);
        writer.end_slot(&block, &[]).unwrap();
        parent = block.blockhash;
    }
    writer.finish().unwrap().0
}
fn main() {
    let source = source();
    let mut expected = None;
    for run in 0..7 {
        let start = Instant::now();
        let (output, stats) = reencode_archive_prefix(
            Cursor::new(&source),
            Vec::new(),
            ArchiveWriterConfig {
                bucket_slots: 4,
                compression: Compression::Lz4,
                ..Default::default()
            },
            63,
        )
        .unwrap();
        let export_nanos = start.elapsed().as_nanos();
        assert_eq!(stats.slots_reencoded, 63);
        let start = Instant::now();
        let mut reader = ArchiveReader::open(Cursor::new(&output)).unwrap();
        let mut digest = SemanticDigest::new();
        assert_eq!(reader.read_slots(432000, 63, &mut digest).unwrap(), 63);
        assert_eq!(digest.finish().unwrap(), stats.output_semantic_sha256);
        let reread_nanos = start.elapsed().as_nanos();
        let sha = format!("{:x}", Sha256::digest(&output));
        // Normalize only the creation timestamp for the deterministic byte
        // comparison. The independent reread uses the real archive bytes.
        let mut header = reader.header().clone();
        let mut original_header = Vec::new();
        header.encode_ext(&mut original_header, None).unwrap();
        header.meta.created_unix_ms = 0;
        let mut normalized_header = Vec::new();
        header.encode_ext(&mut normalized_header, None).unwrap();
        let mut payload = Sha256::new();
        payload.update(&normalized_header);
        payload.update(&output[original_header.len()..]);
        let payload_sha = format!("{:x}", payload.finalize());
        if let Some(before) = &expected {
            assert_eq!(before, &payload_sha)
        } else {
            expected = Some(payload_sha.clone())
        }
        black_box(&output);
        println!(
            "{{\"run\":{run},\"export_nanos\":{export_nanos},\"reread_nanos\":{reread_nanos},\"archive_bytes\":{},\"archive_sha256\":\"{sha}\",\"normalized_payload_sha256\":\"{payload_sha}\",\"source_semantic_sha256\":\"{}\",\"output_semantic_sha256\":\"{}\"}}",
            output.len(),
            stats
                .source_semantic_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            stats
                .output_semantic_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
}
