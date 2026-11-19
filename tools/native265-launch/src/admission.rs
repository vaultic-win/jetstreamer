//! One fresh, complete current-fleet decision. No fixed historical peer count.
use super::*;
fn prestart(lifecycle: &Value, review: &Value, self_sha: &str) -> Result<()> {
    no_authority(lifecycle)?;
    ensure!(
        lifecycle["schema"] == "horizon-native265-prestart-qualification-v1"
            && lifecycle["harness"] == json!(Bound::new(HARNESS, HARNESS_SHA))
            && lifecycle["guard"] == review["guard"]
            && lifecycle["source_publication"] == review["source_publication"]
            && lifecycle["observer_complete_tuple_accepted"] == true
            && lifecycle["fleet_running_and_terminal_accepted"] == true
            && lifecycle["inactive_status_exact_owner_accepted"] == true
            && lifecycle["terminal_retention_accepted"] == true
            && lifecycle["pre_restore_gate_tests_accepted"] == true
            && lifecycle["actual_first_guard_required_before_snapshot"] == true
            && lifecycle["actual_native_startup_qualified"] == false
            && lifecycle["launcher_artifact_sha256"] == self_sha,
        "epoch265 pre-start consumers or gate enforcement not qualified"
    );
    if review["operation"] != "qualify-guard" {
        qualification::accepted(&binding(&lifecycle["protective_stop_qualification"])?.sealed()?)?;
    }
    Ok(())
}
const BOOKING_FIELDS: [&str; 5] = [
    "unit",
    "invocation_id",
    "maximum_memory_bytes",
    "remaining_disk_growth_bytes",
    "minimum_free_bytes",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldSource {
    document: Bound,
    pointer: String,
}
fn booking_source(
    source: &Value,
    reservation: &capacity::Reservation,
    mut load: impl FnMut(&Bound) -> Result<Value>,
) -> Result<()> {
    ensure!(
        source["Main_accepted"] == true
            && source["unit"] == reservation.unit
            && source["invocation_id"] == reservation.invocation_id
            && source["maximum_memory_bytes"] == reservation.maximum_memory_bytes
            && source["remaining_disk_growth_bytes"] == reservation.remaining_disk_growth_bytes
            && source["minimum_free_bytes"] == reservation.minimum_free_bytes,
        "existing booking differs"
    );
    match source["schema"].as_str() {
        Some("horizon-native265-existing-booking-v1") => {
            ensure!(
                source.get("field_sources").is_none(),
                "ambiguous legacy booking source"
            );
            let original = load(&binding(&source["original_admission_or_handoff"])?)?;
            for key in BOOKING_FIELDS {
                let pointer = text(&source["original_field_pointers"], key)?;
                ensure!(
                    original.pointer(pointer) == Some(&source[key]),
                    "booking not derived from original evidence {key}"
                );
            }
        }
        Some("horizon-native265-existing-booking-v2") => {
            ensure!(
                source.get("original_admission_or_handoff").is_none()
                    && source.get("original_field_pointers").is_none(),
                "ambiguous per-field booking source"
            );
            let fields: BTreeMap<String, FieldSource> =
                serde_json::from_value(source["field_sources"].clone())?;
            ensure!(
                fields.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    == BTreeSet::from(BOOKING_FIELDS),
                "incomplete/unexpected original booking fields"
            );
            let mut documents = BTreeMap::new();
            for key in BOOKING_FIELDS {
                let field = &fields[key];
                ensure!(
                    field.pointer.starts_with('/') && hex(&field.document.sha256, 64),
                    "invalid original field binding"
                );
                let identity = (field.document.path.clone(), field.document.sha256.clone());
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    documents.entry(identity.clone())
                {
                    entry.insert(load(&field.document)?);
                }
                ensure!(
                    documents[&identity].pointer(&field.pointer) == Some(&source[key]),
                    "booking not derived from original field evidence {key}"
                );
            }
        }
        _ => bail!("unregistered booking source schema"),
    }
    Ok(())
}
const AUXILIARY_BYTES: u64 = 2_640_509_440;
const AUXILIARY_SOURCE_PATH: &str = "/home/ubuntu/.codex/diagnostics/horizon-hard-memory-accounting-20261119-v1/capacity-correction.json";
const AUXILIARY_SOURCE_SHA: &str =
    "64456f938ab522c91848a8c93a32f95e1eeedef97f0e1cdd143923895f090631";
fn auxiliary_overhead(
    ledger: &Value,
    previous: &Value,
    mut load: impl FnMut(&Bound) -> Result<Value>,
) -> Result<u64> {
    match ledger["schema"].as_str() {
        Some("horizon-native265-retained-reservations-v1") => {
            ensure!(
                previous["schema"] == "horizon-native265-prior-host-booking-v1"
                    && ledger.get("auxiliary_overhead").is_none()
                    && previous.get("auxiliary_overhead").is_none(),
                "legacy ledger cannot silently discard overhead"
            );
            Ok(0)
        }
        Some(
            "horizon-native265-retained-reservations-v2"
            | "horizon-native265-retained-reservations-v3",
        ) => {
            ensure!(
                previous["schema"]
                    == if ledger["schema"] == "horizon-native265-retained-reservations-v3" {
                        "horizon-native265-prior-host-booking-v3"
                    } else {
                        "horizon-native265-prior-host-booking-v2"
                    }
                    && previous["auxiliary_overhead"] == ledger["auxiliary_overhead"],
                "previous auxiliary booking changed or omitted"
            );
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Overhead {
                schema: String,
                memory_bytes: u64,
                source: Bound,
                source_field_pointer: String,
            }
            let overhead: Overhead = serde_json::from_value(ledger["auxiliary_overhead"].clone())?;
            ensure!(
                overhead.schema == "horizon-native265-fixed-auxiliary-overhead-v1"
                    && overhead.memory_bytes == AUXILIARY_BYTES
                    && overhead.source == Bound::new(AUXILIARY_SOURCE_PATH, AUXILIARY_SOURCE_SHA)
                    && overhead.source_field_pointer == "/auxiliary_envelope_bytes",
                "auxiliary source or full fixed envelope differs"
            );
            let original = load(&overhead.source)?;
            ensure!(
                original["schema"] == "horizon-capacity-accounting-correction-v1"
                    && original.pointer(&overhead.source_field_pointer)
                        == Some(&json!(overhead.memory_bytes)),
                "auxiliary overhead not derived from original accounting"
            );
            Ok(overhead.memory_bytes)
        }
        _ => bail!("unknown retained booking schema"),
    }
}
pub(super) fn reservations(
    review: &Value,
) -> Result<(Vec<capacity::Reservation>, u64, Vec<periodic::Control>)> {
    let ledger = binding(&review["reservation_ledger"])?.sealed()?;
    ensure!(
        matches!(
            ledger["schema"].as_str(),
            Some(
                "horizon-native265-retained-reservations-v1"
                    | "horizon-native265-retained-reservations-v2"
                    | "horizon-native265-retained-reservations-v3"
            )
        ) && ledger["Main_accepted"] == true
            && ledger["all_active_and_dormant_obligations_preserved"] == true
            && ledger["fleet"] == review["fleet"]
            && ledger["observer"] == review["observer"],
        "reservation ledger binding"
    );
    no_authority(&ledger)?;
    let rows: Vec<capacity::Reservation> = serde_json::from_value(ledger["reservations"].clone())?;
    ensure!(
        !rows.is_empty() && rows.len() <= 128,
        "reservation census bounds"
    );
    let mut names = BTreeSet::new();
    for r in &rows {
        ensure!(
            names.insert(&r.unit) && hex(&r.invocation_id, 32),
            "duplicate/invalid reservation owner"
        );
        // Per-owner booking is a separately accepted immutable extraction, retaining
        // its original admission/handoff; it cannot be replaced by an unbound number.
        let s = r.source.sealed()?;
        booking_source(&s, r, Bound::json)?;
    }
    // Supplied predecessor is the accepted host booking, not a caller-selected subset.
    let previous = binding(&ledger["previous_accepted_booking"])?.sealed()?;
    ensure!(
        matches!(
            previous["schema"].as_str(),
            Some(
                "horizon-native265-prior-host-booking-v1"
                    | "horizon-native265-prior-host-booking-v2"
                    | "horizon-native265-prior-host-booking-v3"
            )
        ) && previous["Main_accepted"] == true
            && previous["complete_host_booking"] == true,
        "missing prior complete host booking"
    );
    let overhead = auxiliary_overhead(&ledger, &previous, Bound::json)?;
    let prior = previous["reservations"]
        .as_array()
        .context("prior bookings")?;
    ensure!(!prior.is_empty(), "empty prior host booking");
    for p in prior {
        let unit = text(p, "unit")?;
        let r = rows
            .iter()
            .find(|r| r.unit == unit)
            .context("silently dropped historical reservation")?;
        ensure!(
            p["invocation_id"] == r.invocation_id
                && p["maximum_memory_bytes"] == r.maximum_memory_bytes
                && num(p, "remaining_disk_growth_bytes")? <= r.remaining_disk_growth_bytes
                && num(p, "minimum_free_bytes")? <= r.minimum_free_bytes,
            "historical booking lowered without separate qualified transition"
        );
    }
    let periodic = periodic::booking(&ledger, &previous, &rows)?;
    Ok((rows, overhead, periodic))
}
pub(super) fn validate(
    n: &mut Native,
    review: &Value,
    review_ref: &Bound,
    self_sha: &str,
    candidate: bool,
) -> Result<Value> {
    ensure!(
        review["schema"] == "horizon-native265-current-fleet-review-v1"
            && review["epoch"] == 265
            && review["Main_accepted"] == true
            && review["single_campaign_controller_confirmed"] == true,
        "unaccepted current-fleet review"
    );
    no_authority(review)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    ensure!(review["boot_id"] == boot, "review belongs to another boot");
    fresh(num(review, "recorded_unix_seconds")?, now()?, 300)?;
    let owner_pid = num(review, "main_controller_pid")?;
    let stat = fs::read_to_string(format!("/proc/{owner_pid}/stat"))?;
    let ticks = stat
        .rsplit_once(')')
        .context("controller stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("controller start ticks")?
        .parse::<u64>()?;
    ensure!(
        review["main_controller_start_ticks"] == ticks,
        "campaign controller replaced"
    );
    let guard = binding(&review["guard"])?;
    guard.artifact()?;
    ensure!(
        guard == Bound::new(GUARD, GUARD_SHA),
        "guard deployment differs from qualified gated image"
    );
    let source = binding(&review["source_publication"])?.sealed()?;
    if !candidate {
        publication::validate(n, &source, &guard, self_sha)?;
    }
    // Admission may start the exact harness only into its internal waiting gate.
    // The current invocation's first native guard proof cannot exist yet: launch
    // must capture and validate it before publishing the restore token.
    let lifecycle = binding(&review["prestart_qualification"])?.sealed()?;
    prestart(&lifecycle, review, self_sha)?;
    binding(&lifecycle["qualification_evidence"])?.json()?;
    let fleet = binding(&review["fleet"])?.json()?;
    let observer = binding(&review["observer"])?.json()?;
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["observer_receipt"] == review["observer"]["path"]
            && fleet["observer_sha256"] == review["observer"]["sha256"]
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && fleet["memory_target"]["valid"] == true,
        "fleet/observer binding"
    );
    fresh(num(&fleet, "recorded_unix_seconds")?, now()?, 300)?;
    ensure!(
        observer["cadence"]["routine_minimum_interval_enforced"] == true
            && num(&observer["cadence"], "observed_interval_seconds")? >= 1800,
        "complete cadence observation required"
    );
    let (rows, overhead, periodic) = reservations(review)?;
    finalization::validate(&fleet, &observer, &rows, &boot)?;
    finalization::verify_inputs(&fleet)?;
    let currents = live::census(n, review, &fleet, &rows, &periodic, candidate)?;
    let (total, available, disk) = live::resources()?;
    let obs_total = num(&observer["host_memory"], "total_kib")?
        .checked_mul(1024)
        .context("memory overflow")?;
    ensure!(total == obs_total, "host memory changed");
    let century = capacity::century(&binding(&review["century"])?.sealed()?, &fleet)?;
    let cap = capacity::arithmetic(
        total,
        available,
        disk,
        century,
        &rows,
        &currents,
        (overhead, periodic::total(&periodic)?),
    )?;
    let issued = now()?;
    let mut admission = json!({"schema":"horizon-native265-current-fleet-admission-v1","epoch":265,"mode":"native-cold","unit":UNIT,
        "private_run_root":ROOT,"maximum_memory_bytes":MEMORY,"candidate_incremental_peak_bytes":SCRATCH,
        "protected_existing_floor_bytes":cap["protected_existing_floor_bytes"],"harness":Bound::new(HARNESS,HARNESS_SHA),
        "guard":guard,"worker":Bound::new(WORKER,WORKER_SHA),"input_packet":Bound::new(PACKET,PACKET_SHA),"issued_unix_seconds":issued,"boot_id":boot,"admitted":true,"review":review_ref,"source_publication":review["source_publication"],
        "observer":review["observer"],"fleet":review["fleet"],"reservation_ledger":review["reservation_ledger"],
        "capacity":cap,"actual_current_memory":currents,"recorded_unix_seconds":issued,"expires_unix_seconds":issued.checked_add(60).context("clock overflow")?});
    deny_authority(&mut admission);
    Ok(admission)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn booking_fixture() -> (capacity::Reservation, Value, BTreeMap<PathBuf, Value>) {
        let reservation = capacity::Reservation {
            unit: "original.service".into(),
            invocation_id: "a".repeat(32),
            maximum_memory_bytes: 100,
            remaining_disk_growth_bytes: 200,
            minimum_free_bytes: 300,
            source: Bound::new("/source", "b".repeat(64)),
            release: None,
        };
        let owner = Bound::new("/owner", "1".repeat(64));
        let admission = Bound::new("/admission", "2".repeat(64));
        let guard = Bound::new("/guard", "3".repeat(64));
        let source = json!({"schema":"horizon-native265-existing-booking-v2","Main_accepted":true,
        "unit":reservation.unit,"invocation_id":reservation.invocation_id,"maximum_memory_bytes":100,
        "remaining_disk_growth_bytes":200,"minimum_free_bytes":300,
        "field_sources":{
            "unit":{"document":owner,"pointer":"/producer/unit"},
            "invocation_id":{"document":owner,"pointer":"/producer/iid"},
            "maximum_memory_bytes":{"document":admission,"pointer":"/memory"},
            "remaining_disk_growth_bytes":{"document":admission,"pointer":"/root"},
            "minimum_free_bytes":{"document":guard,"pointer":"/floor"}
        }});
        let docs = BTreeMap::from([
            (
                owner.path,
                json!({"producer":{"unit":reservation.unit,"iid":reservation.invocation_id}}),
            ),
            (admission.path, json!({"memory":100,"root":200})),
            (guard.path, json!({"floor":300})),
        ]);
        (reservation, source, docs)
    }
    #[test]
    fn per_field_booking_authenticates_original_documents_and_deduplicates_reads() {
        let (r, s, docs) = booking_fixture();
        let mut reads = 0;
        booking_source(&s, &r, |b| {
            reads += 1;
            docs.get(&b.path).cloned().context("missing original")
        })
        .unwrap();
        assert_eq!(reads, 3);
        let mut legacy = s.clone();
        legacy["schema"] = json!("horizon-native265-existing-booking-v1");
        legacy.as_object_mut().unwrap().remove("field_sources");
        legacy["original_admission_or_handoff"] = json!(Bound::new("/original", "4".repeat(64)));
        legacy["original_field_pointers"] = json!({"unit":"/unit","invocation_id":"/invocation_id","maximum_memory_bytes":"/maximum_memory_bytes","remaining_disk_growth_bytes":"/remaining_disk_growth_bytes","minimum_free_bytes":"/minimum_free_bytes"});
        booking_source(&legacy, &r, |_| Ok(s.clone())).unwrap();
        legacy["field_sources"] = s["field_sources"].clone();
        assert!(booking_source(&legacy, &r, |_| Ok(s.clone())).is_err());
    }
    #[test]
    fn per_field_booking_rejects_missing_mutated_or_ambiguous_evidence() {
        let (r, s, docs) = booking_fixture();
        for key in BOOKING_FIELDS {
            let mut bad = s.clone();
            bad["field_sources"].as_object_mut().unwrap().remove(key);
            assert!(
                booking_source(&bad, &r, |b| Ok(docs[&b.path].clone())).is_err(),
                "missing {key}"
            );
            let mut bad = s.clone();
            bad["field_sources"][key]["pointer"] = json!("/missing");
            assert!(
                booking_source(&bad, &r, |b| Ok(docs[&b.path].clone())).is_err(),
                "pointer {key}"
            );
            let mut bad = s.clone();
            bad[key] = json!(0);
            assert!(
                booking_source(&bad, &r, |b| Ok(docs[&b.path].clone())).is_err(),
                "value {key}"
            );
        }
        for value in [json!(false), Value::Null] {
            let mut bad = s.clone();
            bad["Main_accepted"] = value;
            assert!(booking_source(&bad, &r, |b| Ok(docs[&b.path].clone())).is_err());
        }
        let mut bad = s.clone();
        bad["field_sources"]["extra"] = s["field_sources"]["unit"].clone();
        assert!(booking_source(&bad, &r, |b| Ok(docs[&b.path].clone())).is_err());
        let mut bad = s.clone();
        bad["field_sources"]["unit"]["document"]["sha256"] = json!("invalid");
        assert!(booking_source(&bad, &r, |b| Ok(docs[&b.path].clone())).is_err());
        let mut bad = s.clone();
        bad["original_admission_or_handoff"] = json!({});
        assert!(booking_source(&bad, &r, |b| Ok(docs[&b.path].clone())).is_err());
        assert!(booking_source(&s, &r, |_| bail!("original digest mismatch")).is_err());
        let mut changed = docs.clone();
        changed.get_mut(&PathBuf::from("/admission")).unwrap()["memory"] = json!(99);
        assert!(booking_source(&s, &r, |b| Ok(changed[&b.path].clone())).is_err());
    }
    fn overhead_fixture() -> (Value, Value, Value) {
        let overhead = json!({"schema":"horizon-native265-fixed-auxiliary-overhead-v1","memory_bytes":AUXILIARY_BYTES,
            "source":Bound::new(AUXILIARY_SOURCE_PATH,AUXILIARY_SOURCE_SHA),"source_field_pointer":"/auxiliary_envelope_bytes"});
        (
            json!({"schema":"horizon-native265-retained-reservations-v2","auxiliary_overhead":overhead}),
            json!({"schema":"horizon-native265-prior-host-booking-v2","auxiliary_overhead":overhead}),
            json!({"schema":"horizon-capacity-accounting-correction-v1","auxiliary_envelope_bytes":AUXILIARY_BYTES}),
        )
    }
    #[test]
    fn fixed_auxiliary_envelope_is_source_bound_preserved_and_never_a_fake_owner() {
        let (ledger, previous, original) = overhead_fixture();
        let mut reads = 0;
        assert_eq!(
            auxiliary_overhead(&ledger, &previous, |b| {
                reads += 1;
                assert_eq!(*b, Bound::new(AUXILIARY_SOURCE_PATH, AUXILIARY_SOURCE_SHA));
                Ok(original.clone())
            })
            .unwrap(),
            AUXILIARY_BYTES
        );
        assert_eq!(reads, 1);
        for key in ["schema", "memory_bytes", "source", "source_field_pointer"] {
            let mut bad = ledger.clone();
            bad["auxiliary_overhead"][key] = Value::Null;
            let mut prior = previous.clone();
            prior["auxiliary_overhead"] = bad["auxiliary_overhead"].clone();
            assert!(
                auxiliary_overhead(&bad, &prior, |_| Ok(original.clone())).is_err(),
                "{key}"
            );
        }
        let mut lowered = ledger.clone();
        lowered["auxiliary_overhead"]["memory_bytes"] = json!(AUXILIARY_BYTES - 1);
        assert!(auxiliary_overhead(&lowered, &previous, |_| Ok(original.clone())).is_err());
        let mut prior = previous.clone();
        prior["auxiliary_overhead"] = lowered["auxiliary_overhead"].clone();
        assert!(auxiliary_overhead(&lowered, &prior, |_| Ok(original.clone())).is_err());
        let mut substituted = ledger.clone();
        substituted["auxiliary_overhead"]["source"]["sha256"] = json!("a".repeat(64));
        prior["auxiliary_overhead"] = substituted["auxiliary_overhead"].clone();
        assert!(auxiliary_overhead(&substituted, &prior, |_| Ok(original.clone())).is_err());
        let mut bad = original.clone();
        bad["auxiliary_envelope_bytes"] = json!(0);
        assert!(auxiliary_overhead(&ledger, &previous, |_| Ok(bad.clone())).is_err());
        assert!(
            auxiliary_overhead(&ledger, &previous, |_| bail!("changed source digest")).is_err()
        );
        let old = json!({"schema":"horizon-native265-retained-reservations-v1"});
        let old_prior = json!({"schema":"horizon-native265-prior-host-booking-v1"});
        assert_eq!(
            auxiliary_overhead(&old, &old_prior, |_| bail!(
                "legacy must not read auxiliary source"
            ))
            .unwrap(),
            0
        );
        assert!(auxiliary_overhead(&old, &previous, |_| Ok(original.clone())).is_err());
        let mut old_with_overhead = old;
        old_with_overhead["auxiliary_overhead"] = ledger["auxiliary_overhead"].clone();
        assert!(
            auxiliary_overhead(&old_with_overhead, &old_prior, |_| Ok(original.clone())).is_err()
        );
    }
    #[test]
    fn prestart_acceptance_requires_live_first_guard_without_claiming_it_already_happened() {
        let review = json!({"operation":"qualify-guard","guard":Bound::new(GUARD,GUARD_SHA),"source_publication":{"path":"/var/lib/jetstreamer/source/proof.json","sha256":"a".repeat(64)}});
        let mut accepted = json!({"schema":"horizon-native265-prestart-qualification-v1",
            "harness":Bound::new(HARNESS,HARNESS_SHA),"guard":review["guard"],"source_publication":review["source_publication"],
            "observer_complete_tuple_accepted":true,"fleet_running_and_terminal_accepted":true,
            "inactive_status_exact_owner_accepted":true,"terminal_retention_accepted":true,
            "pre_restore_gate_tests_accepted":true,"actual_first_guard_required_before_snapshot":true,
            "actual_native_startup_qualified":false,"launcher_artifact_sha256":"b".repeat(64)});
        deny_authority(&mut accepted);
        prestart(&accepted, &review, &"b".repeat(64)).unwrap();
        for (key, value) in [
            (
                "schema",
                json!("horizon-native265-lifecycle-qualification-v1"),
            ),
            ("actual_first_guard_required_before_snapshot", json!(false)),
            ("actual_native_startup_qualified", json!(true)),
            ("pre_restore_gate_tests_accepted", json!(false)),
            ("fleet_running_and_terminal_accepted", json!(false)),
        ] {
            let mut bad = accepted.clone();
            bad[key] = value;
            assert!(prestart(&bad, &review, &"b".repeat(64)).is_err(), "{key}");
        }
    }
}
