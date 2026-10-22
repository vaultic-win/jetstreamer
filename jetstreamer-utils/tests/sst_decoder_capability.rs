//! Proves why point-prefix scans cannot by themselves establish RocksDB live state.
use jetstreamer_utils::{
    horizon_ledger_bzip::collect_bound_bzip2,
    horizon_ledger_tar::{CollectionLimits, collect_rocksdb_tar},
    horizon_legacy_poh::PohExpectation,
    horizon_legacy_recovery::{
        ResolvedLegacyRecord, plan_v1_4_25_shred_queries, recover_v1_4_25_records,
    },
};

// Synthetic exact-layout records, shared by the crash-shaped writer and reader.
// These are not epoch141 records or independently authenticated real anchors.
fn legacy_gap_fixture() -> Vec<(PohExpectation, Vec<u8>, Vec<u8>)> {
    let mut hash = [9; 32];
    (0..11u64)
        .map(|index| {
            let parent_slot = 100 + index * 3;
            let slot = parent_slot + 3;
            let parent_hash = hash;
            let mut entries = 6u64.to_le_bytes().to_vec();
            for _ in 0..6 {
                for _ in 0..3 {
                    hash = Sha256::digest(hash).into();
                }
                entries.extend_from_slice(&3u64.to_le_bytes());
                entries.extend_from_slice(&hash);
                entries.extend_from_slice(&0u64.to_le_bytes());
            }
            let meta = bincode::serialize(&(
                slot,
                1u64,
                1u64,
                123u64,
                0u64,
                parent_slot,
                Vec::<u64>::new(),
                true,
                vec![0u32],
            ))
            .unwrap();
            let mut shred = vec![0; 1228];
            shred[64] = 0xa5;
            shred[65..73].copy_from_slice(&slot.to_le_bytes());
            shred[77..79].copy_from_slice(&1234u16.to_le_bytes());
            shred[83..85].copy_from_slice(&3u16.to_le_bytes());
            shred[85] = 0xc0;
            shred[86..88].copy_from_slice(&((88 + entries.len()) as u16).to_le_bytes());
            shred[88..88 + entries.len()].copy_from_slice(&entries);
            (
                PohExpectation {
                    parent_slot,
                    slot,
                    parent_hash,
                    final_hash: hash,
                    ticks_per_slot: 2,
                    hashes_per_tick: 3,
                },
                meta,
                shred,
            )
        })
        .collect()
}
use rocksdb::{ColumnFamilyDescriptor, DB, DBCompressionType, Options};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{Cursor, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
};

// A separate process exits without dropping DB, leaving acknowledged, synced
// writes in the WAL rather than turning the fixture into an SST-only test.
#[test]
#[ignore = "fixture subprocess for native_readonly_resolves_manifest_and_wal"]
fn native_readonly_wal_fixture_child() {
    let Some(path) = env::var_os("JETSTREAMER_NATIVE_WAL_FIXTURE") else {
        return;
    };
    let mut options = Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    options.set_disable_auto_compactions(true);
    options.set_compression_type(DBCompressionType::Lz4);
    let families = [
        "default",
        "data_shred",
        "meta",
        "root",
        "dead_slots",
        "orphans",
    ]
    .map(|name| ColumnFamilyDescriptor::new(name, options.clone()));
    let database = DB::open_cf_descriptors(&options, path, families).unwrap();
    let cf = database.cf_handle("data_shred").unwrap();
    let slot = 60912004_u64;
    let key = |index: u64| [slot.to_be_bytes(), index.to_be_bytes()].concat();
    for index in 0..=2 {
        database.put_cf(cf, key(index), b"old-sst-value").unwrap();
    }
    database.flush_cf(cf).unwrap();
    let before_slot = [(slot - 1).to_be_bytes(), 0_u64.to_be_bytes()].concat();
    database.delete_range_cf(cf, before_slot, key(1)).unwrap();
    database.delete_cf(cf, key(1)).unwrap();
    database.put_cf(cf, key(2), b"new-wal-value").unwrap();
    database.put_cf(cf, key(3), b"wal-only-value").unwrap();
    let meta_cf = database.cf_handle("meta").unwrap();
    // Complete, explicitly disconnected metadata shaped like the first actual
    // epoch141 rejection. Synthetic bytes, not historical-source evidence.
    database
        .put_cf(
            meta_cf,
            60_911_776u64.to_be_bytes(),
            bincode::serialize(&(
                60_911_776u64,
                1u64,
                1u64,
                123u64,
                0u64,
                60_911_771u64,
                Vec::<u64>::new(),
                false,
                vec![0u32],
            ))
            .unwrap(),
        )
        .unwrap();
    database
        .put_cf(
            cf,
            [60_911_776u64.to_be_bytes(), 0u64.to_be_bytes()].concat(),
            vec![7u8; 1228],
        )
        .unwrap();
    database
        .put_cf(meta_cf, 60_911_771u64.to_be_bytes(), b"raw-parent-metadata")
        .unwrap();
    database
        .put_cf(
            database.cf_handle("root").unwrap(),
            60_911_776u64.to_be_bytes(),
            [1],
        )
        .unwrap();
    database
        .put_cf(
            database.cf_handle("orphans").unwrap(),
            60_911_771u64.to_be_bytes(),
            [1],
        )
        .unwrap();
    for (scope, meta, shred) in legacy_gap_fixture() {
        database
            .put_cf(meta_cf, scope.slot.to_be_bytes(), meta)
            .unwrap();
        database
            .put_cf(
                cf,
                [scope.slot.to_be_bytes(), 0u64.to_be_bytes()].concat(),
                shred,
            )
            .unwrap();
    }
    database.flush_wal(true).unwrap();
    // Do not run DB's Drop/close: that could flush the memtable and invalidate
    // the deliberately crash-shaped, generation-stable backup fixture.
    std::process::exit(0);
}

#[test]
#[ignore = "explicit native RocksDB qualification; isolated disposable databases only"]
fn native_readonly_resolves_manifest_and_wal() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("complete-db");
    let child = Command::new(env::current_exe().unwrap())
        .args(["--ignored", "--exact", "native_readonly_wal_fixture_child"])
        .env("JETSTREAMER_NATIVE_WAL_FIXTURE", &path)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "fixture failed: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    let files: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(files.iter().any(|p| p.file_name().unwrap() == "CURRENT"));
    assert!(files.iter().any(|p| {
        p.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("MANIFEST-")
    }));
    assert!(
        files
            .iter()
            .any(|p| p.extension().is_some_and(|e| e == "sst"))
    );
    assert!(
        files
            .iter()
            .any(|p| p.extension().is_some_and(|e| e == "log"))
    );
    let input_hashes: Vec<_> = files
        .iter()
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy();
            name == "CURRENT"
                || name.starts_with("MANIFEST-")
                || p.extension().is_some_and(|e| e == "sst" || e == "log")
        })
        .map(|p| (p, Sha256::digest(fs::read(p).unwrap())))
        .collect();
    let options = Options::default();
    let families = DB::list_cf(&options, &path).unwrap();
    assert_eq!(families.len(), 6);
    // Read-only RocksDB may permit a subset; the recovery policy must compare
    // its requested families against the full authenticated manifest census.
    if let Ok(partial) = DB::open_cf_for_read_only(&options, &path, ["data_shred"], false) {
        assert!(partial.cf_handle("meta").is_none());
        assert!(families.iter().any(|family| family == "meta"));
        println!("native read-only subset open is possible: complete CF census is a separate gate");
    }
    // Strict log rejection cannot substitute for recovery of the present WAL.
    assert!(DB::open_cf_for_read_only(&options, &path, &families, true).is_err());
    let database = DB::open_cf_for_read_only(&options, &path, &families, false).unwrap();
    let cf = database.cf_handle("data_shred").unwrap();
    let slot = 60912004_u64;
    let key = |index: u64| [slot.to_be_bytes(), index.to_be_bytes()].concat();
    assert_eq!(database.get_cf(cf, key(0)).unwrap(), None);
    assert_eq!(database.get_cf(cf, key(1)).unwrap(), None);
    assert_eq!(
        database.get_cf(cf, key(2)).unwrap().as_deref(),
        Some(b"new-wal-value".as_slice())
    );
    assert_eq!(
        database.get_cf(cf, key(3)).unwrap().as_deref(),
        Some(b"wal-only-value".as_slice())
    );
    drop(database);
    for (path, before) in input_hashes {
        assert_eq!(
            before,
            Sha256::digest(fs::read(path).unwrap()),
            "native read-only open changed a manifest/WAL/SST input"
        );
    }

    // Exercise the bounded collector against the entire real native fixture,
    // not selected SSTs. Its census retains WALs and every CF's table files.
    // This is still a disposable fixture, not a historical ledger generation.
    let mut archive = tar::Builder::new(Vec::new());
    let mut source_files: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|item| item.unwrap().path())
        .collect();
    source_files.sort();
    for source in &source_files {
        assert!(source.is_file());
        archive
            .append_file(
                Path::new("rocksdb").join(source.file_name().unwrap()),
                &mut fs::File::open(source).unwrap(),
            )
            .unwrap();
    }
    let bytes = archive.into_inner().unwrap();
    let collected = root.path().join("collected-db");
    fs::create_dir(&collected).unwrap();
    fs::set_permissions(&collected, fs::Permissions::from_mode(0o700)).unwrap();
    let census = collect_rocksdb_tar(
        Cursor::new(&bytes),
        Path::new("rocksdb"),
        &collected,
        CollectionLimits {
            maximum_files: 128,
            maximum_file_bytes: 16 * 1024 * 1024,
            maximum_total_bytes: 64 * 1024 * 1024,
            maximum_trailer_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    // Bind the same complete crash-shaped database through compressed input as
    // well, including a bzip2 member boundary inside the tar. Native resolution
    // below consumes this second, independently collected private generation.
    let mut compressed = Vec::new();
    for chunk in [&bytes[..777], &bytes[777..]] {
        let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        encoder.write_all(chunk).unwrap();
        compressed.extend(encoder.finish().unwrap());
    }
    let compressed_path = root.path().join("complete-db.tar.bz2");
    fs::write(&compressed_path, &compressed).unwrap();
    fs::set_permissions(&compressed_path, fs::Permissions::from_mode(0o444)).unwrap();
    let compressed_sha256 = format!("{:x}", Sha256::digest(&compressed));
    let direct_census = census;
    let collected = root.path().join("collected-bzip-db");
    fs::create_dir(&collected).unwrap();
    fs::set_permissions(&collected, fs::Permissions::from_mode(0o700)).unwrap();
    let bound = collect_bound_bzip2(
        &compressed_path,
        compressed.len() as u64,
        &compressed_sha256,
        64 * 1024 * 1024,
        Path::new("rocksdb"),
        &collected,
        CollectionLimits {
            maximum_files: 128,
            maximum_file_bytes: 16 * 1024 * 1024,
            maximum_total_bytes: 64 * 1024 * 1024,
            maximum_trailer_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    assert!(!bound.cloud_generation_authenticated && !bound.resource_admission_proven);
    assert!(!bound.publication_authorized);
    assert_eq!(bound.compressed_sha256, compressed_sha256);
    let census = bound.collection;
    assert_eq!(
        serde_json::to_value(direct_census).unwrap(),
        serde_json::to_value(&census).unwrap()
    );
    assert_eq!(fs::read(&compressed_path).unwrap(), compressed);
    assert_eq!(census.files.len(), source_files.len());
    assert!(!census.wal_files.is_empty());
    assert!(!census.source_completeness_proven && !census.live_state_resolved);
    assert!(!census.publication_authorized);
    for source in &source_files {
        assert_eq!(
            fs::read(source).unwrap(),
            fs::read(collected.join(source.file_name().unwrap())).unwrap()
        );
    }
    // Isolate any native diagnostic log output from the immutable input census.
    let log_path = root.path().join("collected-readonly-logs");
    fs::create_dir(&log_path).unwrap();
    let mut collected_options = Options::default();
    collected_options.set_db_log_dir(&log_path);
    let collected_families = DB::list_cf(&collected_options, &collected).unwrap();
    assert_eq!(collected_families, families);
    let collected_db =
        DB::open_cf_for_read_only(&collected_options, &collected, &collected_families, false)
            .unwrap();
    let collected_cf = collected_db.cf_handle("data_shred").unwrap();
    assert_eq!(collected_db.get_cf(collected_cf, key(0)).unwrap(), None);
    assert_eq!(collected_db.get_cf(collected_cf, key(1)).unwrap(), None);
    assert_eq!(
        collected_db
            .get_cf(collected_cf, key(2))
            .unwrap()
            .as_deref(),
        Some(b"new-wal-value".as_slice())
    );
    assert_eq!(
        collected_db
            .get_cf(collected_cf, key(3))
            .unwrap()
            .as_deref(),
        Some(b"wal-only-value".as_slice())
    );
    let live_files = collected_db.live_files().unwrap();
    assert!(!live_files.is_empty());
    for live in live_files {
        let name = live.name.trim_start_matches('/');
        assert!(
            census
                .files
                .iter()
                .any(|file| file.name == name && file.bytes == live.size as u64)
        );
        assert!(collected_families.contains(&live.column_family_name));
    }
    drop(collected_db);
    // Exercise the reusable diagnostic core against the same complete native
    // crash-shaped fixture, not against manually selected SST candidates.
    let resolution_logs = root.path().join("resolution-logs");
    fs::create_dir(&resolution_logs).unwrap();
    fs::set_permissions(&resolution_logs, fs::Permissions::from_mode(0o700)).unwrap();
    let queries: Vec<_> = (0..=3)
        .map(
            |index| jetstreamer_utils::horizon_ledger_native::NativeQuery {
                family: "data_shred".into(),
                key: key(index),
            },
        )
        .collect();
    let result = jetstreamer_utils::horizon_ledger_native::resolve_native_candidates(
        &collected,
        &census,
        &resolution_logs,
        &families,
        &queries,
        || Ok(()),
    )
    .unwrap();
    assert!(result.complete_census_revalidated);
    assert!(
        !result.source_completeness_proven
            && !result.live_state_proven
            && !result.publication_authorized
    );
    assert_eq!(result.candidates[0].value, None);
    assert_eq!(result.candidates[1].value, None);
    assert_eq!(
        result.candidates[2].value.as_deref(),
        Some(b"new-wal-value".as_slice())
    );
    assert_eq!(
        result.candidates[3].value.as_deref(),
        Some(b"wal-only-value".as_slice())
    );
    // Stream bounded batches through one native open. Old SST values and WAL
    // tombstones must resolve exactly as in the one-shot API, including repeated
    // cross-batch keys used by a two-stage metadata/shred consumer.
    use jetstreamer_utils::horizon_ledger_native::{NativeReadBudget, with_native_read_session};
    let batch_logs = |name: &str| {
        let logs = root.path().join(name);
        fs::create_dir(&logs).unwrap();
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
        logs
    };
    let budget = NativeReadBudget {
        batches: 3,
        queries: 8,
        value_bytes: 1024,
    };
    let (values, summary) = with_native_read_session(
        &collected,
        &census,
        &batch_logs("session-logs"),
        &families,
        budget,
        &mut || Ok(()),
        |reader, guard| {
            let mut values = reader.read_candidates(&queries[..2], guard)?;
            values.extend(reader.read_candidates(&queries[2..], guard)?);
            let repeated = reader.read_candidates(&queries[2..], guard)?;
            assert_eq!(repeated[0].value, values[2].value);
            Ok(values)
        },
    )
    .unwrap();
    assert_eq!(summary.batches, 3);
    assert_eq!(summary.queries, 6);
    assert_eq!(
        summary.value_bytes,
        2 * (b"new-wal-value".len() + b"wal-only-value".len()) as u64
    );
    assert!(summary.complete_census_revalidated);
    assert!(
        !summary.source_completeness_proven
            && !summary.live_state_proven
            && !summary.publication_authorized
    );
    for (actual, original) in values.iter().zip(&result.candidates) {
        assert_eq!(actual.family, original.family);
        assert_eq!(actual.key, original.key);
        assert_eq!(actual.value, original.value);
    }
    // Returning a planner rejection as data must close and rehash the DB before
    // exposing final diagnostic evidence. Never suppress native/guard failures.
    let disconnected_query = [jetstreamer_utils::horizon_ledger_native::NativeQuery {
        family: "meta".into(),
        key: 60_911_776u64.to_be_bytes().to_vec(),
    }];
    for mutate in [false, true] {
        let diagnostic = with_native_read_session(
            &collected,
            &census,
            &batch_logs(if mutate {
                "rejection-mutated"
            } else {
                "rejection-revalidated"
            }),
            &families,
            budget,
            &mut || Ok(()),
            |reader, guard| {
                let raw = reader.read_candidates(&disconnected_query, guard)?;
                let records = [ResolvedLegacyRecord {
                    family: &raw[0].family,
                    key: &raw[0].key,
                    value: raw[0].value.as_deref(),
                }];
                let scope = jetstreamer_utils::horizon_legacy_recovery::LegacySlotScope {
                    slot: 60_911_776,
                    parent_slot: 60_911_771,
                };
                let rejection =
                    jetstreamer_utils::horizon_legacy_recovery::plan_v1_4_25_scope_queries(
                        &records,
                        &[scope],
                    )
                    .unwrap_err();
                assert_eq!(rejection, "target SlotMeta is not connected");
                if mutate {
                    fs::write(collected.join("unexpected-after-rejection"), b"new member")?;
                }
                Ok((raw, rejection))
            },
        );
        if mutate {
            assert!(
                diagnostic.is_err(),
                "typed rejection bypassed post-close census"
            );
            fs::remove_file(collected.join("unexpected-after-rejection")).unwrap();
        } else {
            let ((raw, rejection), summary) = diagnostic.unwrap();
            assert_eq!(summary.batches, 1);
            assert_eq!(summary.queries, 1);
            assert!(summary.complete_census_revalidated);
            assert!(
                !summary.source_completeness_proven
                    && !summary.live_state_proven
                    && !summary.publication_authorized
            );
            assert!(raw[0].value.is_some());
            assert_eq!(rejection, "target SlotMeta is not connected");
        }
    }
    // A disconnected target can be acquired as raw diagnostic data without
    // relaxing the recovery planner. The complete native close/rehash remains
    // mandatory even when both bounded query batches already succeeded.
    for mutate in [false, true] {
        let acquired = with_native_read_session(
            &collected,
            &census,
            &batch_logs(if mutate {
                "acquisition-mutated"
            } else {
                "acquisition-revalidated"
            }),
            &families,
            NativeReadBudget {
                batches: 2,
                queries: 16,
                value_bytes: 16 * 1024,
            },
            &mut || Ok(()),
            |reader, guard| {
                fn borrowed(
                    r: &jetstreamer_utils::horizon_ledger_native::NativeCandidate,
                ) -> ResolvedLegacyRecord<'_> {
                    ResolvedLegacyRecord {
                        family: &r.family,
                        key: &r.key,
                        value: r.value.as_deref(),
                    }
                }
                let first = reader.read_candidates(&disconnected_query, guard)?;
                let records: Vec<_> = first.iter().map(borrowed).collect();
                let scope = jetstreamer_utils::horizon_legacy_recovery::LegacySlotScope {
                    slot: 60_911_776,
                    parent_slot: 60_911_771,
                };
                assert!(
                    jetstreamer_utils::horizon_legacy_recovery::plan_v1_4_25_scope_queries(
                        &records,
                        &[scope]
                    )
                    .is_err()
                );
                let plan=jetstreamer_utils::horizon_legacy_acquisition::plan_v1_4_25_acquisition_queries(&records,scope).unwrap();
                let queries: Vec<_> = plan
                    .queries
                    .iter()
                    .map(|q| jetstreamer_utils::horizon_ledger_native::NativeQuery {
                        family: q.family.into(),
                        key: q.key.clone(),
                    })
                    .collect();
                let full = reader.read_candidates(&queries, guard)?;
                let full_records: Vec<_> = full.iter().map(borrowed).collect();
                let summary=jetstreamer_utils::horizon_legacy_acquisition::validate_v1_4_25_acquisition_records(&records,scope,&full_records).unwrap();
                assert!(!summary.recorded_is_connected);
                assert_eq!(summary.expected_data_shreds, 1);
                assert!(
                    summary.missing_data_shred_indexes.is_empty()
                        && summary.unexpected_data_shred_length_indexes.is_empty()
                );
                assert_eq!(full[1].value.as_deref(), Some([1].as_slice()));
                assert!(full[2].value.is_none() && full[3].value.is_none());
                assert_eq!(
                    full[4].value.as_deref(),
                    Some(b"raw-parent-metadata".as_slice())
                );
                assert_eq!(full[7].value.as_deref(), Some([1].as_slice()));
                if mutate {
                    fs::write(
                        collected.join("unexpected-after-acquisition"),
                        b"new member",
                    )?;
                }
                Ok(summary)
            },
        );
        if mutate {
            assert!(
                acquired.is_err(),
                "acquisition bypassed post-close source revalidation"
            );
            fs::remove_file(collected.join("unexpected-after-acquisition")).unwrap();
        } else {
            let (_, session) = acquired.unwrap();
            assert_eq!(session.batches, 2);
            assert_eq!(session.queries, 10);
            assert!(session.complete_census_revalidated);
            assert!(
                !session.source_completeness_proven
                    && !session.live_state_proven
                    && !session.publication_authorized
            );
        }
    }
    let mutated = with_native_read_session(
        &collected,
        &census,
        &batch_logs("session-mutated-after-read"),
        &families,
        budget,
        &mut || Ok(()),
        |reader, guard| {
            reader.read_candidates(&queries, guard)?;
            fs::write(collected.join("unexpected-after-read"), b"new member")?;
            Ok(())
        },
    );
    assert!(
        mutated.is_err(),
        "post-read input change produced final success"
    );
    fs::remove_file(collected.join("unexpected-after-read")).unwrap();
    for case in 0..8 {
        let mut limited = budget;
        match case {
            0 => limited.batches = 1,
            1 => limited.queries = 3,
            2 => limited.value_bytes = 1,
            _ => (),
        }
        let rejected = with_native_read_session(
            &collected,
            &census,
            &batch_logs(&format!("session-rejected-{case}")),
            &families,
            limited,
            &mut || Ok(()),
            |reader, guard| {
                match case {
                    0..=2 => {
                        reader.read_candidates(&queries, guard)?;
                        reader.read_candidates(&queries, guard)?;
                    }
                    3 => {
                        // Suppressing an invalid batch cannot produce a final
                        // success or allow a subsequent successful read.
                        assert!(reader.read_candidates(&[], guard).is_err());
                        assert!(reader.read_candidates(&queries, guard).is_err());
                    }
                    4 => { /* empty session must fail */ }
                    5 => {
                        reader.read_candidates(&queries, guard)?;
                        anyhow::bail!("consumer failed after provisional output");
                    }
                    6 => {
                        assert!(
                            reader
                                .read_candidates(&queries, &mut || anyhow::bail!("guard trip"))
                                .is_err()
                        );
                    }
                    _ => {
                        let duplicate = [
                            jetstreamer_utils::horizon_ledger_native::NativeQuery {
                                family: "data_shred".into(),
                                key: key(2),
                            },
                            jetstreamer_utils::horizon_ledger_native::NativeQuery {
                                family: "data_shred".into(),
                                key: key(2),
                            },
                        ];
                        assert!(reader.read_candidates(&duplicate, guard).is_err());
                    }
                }
                Ok(())
            },
        );
        assert!(rejected.is_err(), "accepted invalid session {case}");
    }
    // Bind the complete two-stage logical query set through all eleven
    // synthetic chains, with full census rehashing around each native read.
    use jetstreamer_utils::horizon_ledger_native::{
        NativeQuery, NativeResolution, resolve_native_candidates,
    };
    let scopes: Vec<_> = legacy_gap_fixture()
        .into_iter()
        .map(|(scope, _, _)| scope)
        .collect();
    let metadata_queries: Vec<_> = scopes
        .iter()
        .map(|scope| NativeQuery {
            family: "meta".into(),
            key: scope.slot.to_be_bytes().to_vec(),
        })
        .collect();
    let resolve = |queries: &[NativeQuery], name: &str| {
        let logs = root.path().join(name);
        fs::create_dir(&logs).unwrap();
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
        resolve_native_candidates(&collected, &census, &logs, &families, queries, || Ok(()))
            .unwrap()
    };
    fn records(result: &NativeResolution) -> Vec<ResolvedLegacyRecord<'_>> {
        result
            .candidates
            .iter()
            .map(|r| ResolvedLegacyRecord {
                family: &r.family,
                key: &r.key,
                value: r.value.as_deref(),
            })
            .collect()
    }
    let first = resolve(&metadata_queries, "gap-metadata-logs");
    let first_records = records(&first);
    let query_plan = plan_v1_4_25_shred_queries(&first_records, &scopes).unwrap();
    let full_queries: Vec<_> = query_plan
        .iter()
        .map(|q| NativeQuery {
            family: q.family.into(),
            key: q.key.clone(),
        })
        .collect();
    let complete = resolve(&full_queries, "gap-complete-logs");
    let chains =
        recover_v1_4_25_records(&first_records, &records(&complete), &scopes, 198, || Ok(()))
            .unwrap();
    assert_eq!(chains.len(), 11);
    assert_eq!(chains.iter().map(|c| c.boundaries.len()).sum::<usize>(), 33);
    assert!(
        chains
            .iter()
            .all(|c| !c.source_completeness_proven && !c.publication_authorized)
    );
    // The full-census driver uses two bounded reads per target, not one giant
    // query/value allocation. Exercise that exact topology through entry/PoH
    // decoding too; final results exist only after session revalidation.
    let (batched_chains, accounting) = with_native_read_session(
        &collected,
        &census,
        &batch_logs("per-target-session"),
        &families,
        NativeReadBudget {
            batches: 22,
            queries: 100,
            value_bytes: 1024 * 1024,
        },
        &mut || Ok(()),
        |reader, guard| {
            let mut recovered = Vec::new();
            for scope in &scopes {
                let first = reader.read_candidates(
                    &[NativeQuery {
                        family: "meta".into(),
                        key: scope.slot.to_be_bytes().to_vec(),
                    }],
                    guard,
                )?;
                let first_records: Vec<_> = first
                    .iter()
                    .map(|r| ResolvedLegacyRecord {
                        family: &r.family,
                        key: &r.key,
                        value: r.value.as_deref(),
                    })
                    .collect();
                let queries: Vec<_> =
                    plan_v1_4_25_shred_queries(&first_records, std::slice::from_ref(scope))
                        .map_err(anyhow::Error::msg)?
                        .into_iter()
                        .map(|q| NativeQuery {
                            family: q.family.into(),
                            key: q.key,
                        })
                        .collect();
                let complete = reader.read_candidates(&queries, guard)?;
                let complete_records: Vec<_> = complete
                    .iter()
                    .map(|r| ResolvedLegacyRecord {
                        family: &r.family,
                        key: &r.key,
                        value: r.value.as_deref(),
                    })
                    .collect();
                recovered.extend(
                    recover_v1_4_25_records(
                        &first_records,
                        &complete_records,
                        std::slice::from_ref(scope),
                        18,
                        || guard().map_err(|e| e.to_string()),
                    )
                    .map_err(anyhow::Error::msg)?,
                );
            }
            Ok(recovered)
        },
    )
    .unwrap();
    assert_eq!(accounting.batches, 22);
    assert_eq!(accounting.queries, 33);
    assert_eq!(batched_chains.len(), chains.len());
    for (batched, original) in batched_chains.iter().zip(&chains) {
        assert_eq!(batched.boundaries, original.boundaries);
        assert_eq!(batched.executed_hashes, original.executed_hashes);
        assert_eq!(
            batched.source_completeness_proven,
            original.source_completeness_proven
        );
        assert_eq!(
            batched.publication_authorized,
            original.publication_authorized
        );
    }
    let rejected_logs = root.path().join("rejected-resolution-logs");
    fs::create_dir(&rejected_logs).unwrap();
    fs::set_permissions(&rejected_logs, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        jetstreamer_utils::horizon_ledger_native::resolve_native_candidates(
            &collected,
            &census,
            &rejected_logs,
            &["default".into(), "data_shred".into()],
            &queries,
            || Ok(())
        )
        .is_err()
    );
    for member in &census.files {
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(fs::read(collected.join(&member.name)).unwrap())
            ),
            member.sha256,
            "native resolution changed collected input {}",
            member.name
        );
    }
    let mut after_names: Vec<_> = fs::read_dir(&collected)
        .unwrap()
        .map(|item| item.unwrap().file_name().into_string().unwrap())
        .collect();
    after_names.sort();
    assert_eq!(
        after_names,
        census
            .files
            .iter()
            .map(|file| file.name.clone())
            .collect::<Vec<_>>()
    );

    // A successful native open is not by itself proof that a backup is complete.
    // Preserve every file except WALs in a second disposable database and show
    // that omitted-WAL evidence must be rejected, even if RocksDB can open it.
    let incomplete = root.path().join("missing-wal-db");
    fs::create_dir(&incomplete).unwrap();
    for file in &files {
        if file.is_file() && file.extension().is_none_or(|e| e != "log") {
            fs::copy(file, incomplete.join(file.file_name().unwrap())).unwrap();
        }
    }
    match DB::open_cf_for_read_only(&options, &incomplete, &families, false) {
        Ok(incomplete_db) => {
            let incomplete_cf = incomplete_db.cf_handle("data_shred").unwrap();
            assert_eq!(
                incomplete_db
                    .get_cf(incomplete_cf, key(0))
                    .unwrap()
                    .as_deref(),
                Some(b"old-sst-value".as_slice())
            );
            assert_eq!(
                incomplete_db
                    .get_cf(incomplete_cf, key(2))
                    .unwrap()
                    .as_deref(),
                Some(b"old-sst-value".as_slice())
            );
            assert_eq!(incomplete_db.get_cf(incomplete_cf, key(3)).unwrap(), None);
            println!(
                "missing WAL silently resurrects SST values: authenticated complete file census is mandatory"
            );
        }
        Err(error) => println!("native decoder rejected incomplete WAL set: {error}"),
    }
    println!(
        "native read-only resolution honored outside-prefix range tombstone, point deletion, latest WAL version, WAL-only value, and the complete CF set"
    );
}

#[test]
#[ignore = "requires separately pinned JETSTREAMER_SST_DUMP_TEST_BIN"]
fn native_sst_prefix_reader_exposes_versions_but_needs_range_tombstones() {
    let binary = env::var_os("JETSTREAMER_SST_DUMP_TEST_BIN")
        .expect("set the exact candidate sst_dump path");
    for compression in [DBCompressionType::None, DBCompressionType::Lz4] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("db");
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        options.set_disable_auto_compactions(true);
        options.set_compression_type(compression);
        let families = [
            ColumnFamilyDescriptor::new("default", options.clone()),
            ColumnFamilyDescriptor::new("data_shred", options.clone()),
        ];
        let database = DB::open_cf_descriptors(&options, &path, families).unwrap();
        let cf = database.cf_handle("data_shred").unwrap();
        let slot = 60912004_u64;
        let key = |index: u64| [slot.to_be_bytes(), index.to_be_bytes()].concat();
        database.put_cf(cf, key(0), b"older").unwrap();
        database.flush_cf(cf).unwrap();
        database.put_cf(cf, key(0), b"latest").unwrap();
        database.put_cf(cf, key(1), b"point-delete").unwrap();
        database.flush_cf(cf).unwrap();
        database.delete_cf(cf, key(1)).unwrap();
        // Start outside the selected slot prefix: a prefix-only scan cannot
        // discover this covering range tombstone by its start key.
        let range_start = [(slot - 1).to_be_bytes(), 0_u64.to_be_bytes()].concat();
        database.delete_range_cf(cf, range_start, key(1)).unwrap();
        database.flush_cf(cf).unwrap();
        assert!(database.get_cf(cf, key(0)).unwrap().is_none());
        assert!(database.get_cf(cf, key(1)).unwrap().is_none());

        let mut scans = String::new();
        let mut properties = String::new();
        let mut ssts = 0;
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "sst")
            {
                continue;
            }
            ssts += 1;
            let output = Command::new(&binary)
                .arg(format!("--file={}", entry.path().display()))
                .args(["--command=identify", "--show_properties"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "identify failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            properties.push_str(&String::from_utf8(output.stdout).unwrap());
            properties.push_str(&String::from_utf8(output.stderr).unwrap());
            let output = Command::new(&binary)
                .arg(format!("--file={}", entry.path().display()))
                .arg(format!("--prefix=0x{slot:016X}"))
                .args([
                    "--command=scan",
                    "--input_key_hex",
                    "--output_hex",
                    "--verify_checksum",
                ])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "scan failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            scans.push_str(&String::from_utf8(output.stdout).unwrap());
        }
        assert!(
            ssts >= 3,
            "fixture needs separate internal versions and tombstones"
        );
        assert!(scans.contains("6F6C646572"), "old value absent: {scans}");
        assert!(
            scans.contains("6C6174657374"),
            "newer point value absent: {scans}"
        );
        assert!(scans.contains("type:0"), "point tombstone absent: {scans}");
        assert!(
            properties.contains("data_shred"),
            "column family absent: {properties}"
        );
        assert!(
            properties
                .lines()
                .any(|line| line.contains("range deletions")
                    && line.split(':').next_back().is_some_and(|v| v.trim() == "1")),
            "range tombstone property absent: {properties}"
        );
        // The greatest point version of key(0) exists in the scan while the native
        // logical read returns None: selecting point sequence numbers alone is wrong.
        println!(
            "{compression:?}: native decoding passed; range tombstone demonstrably overrides point-prefix results"
        );
    }
}
