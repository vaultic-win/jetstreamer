//! Reuse the following interval's exact inputs while keeping its original launch evidence intact.
use super::{
    HASHES, IID, PROGRESS_SHA, RELEASE_SHA, ROOT, SIGNED_CHECKPOINTS, SLOTS, UNIT, evidence,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt, path::Path};

const FOLLOWING: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-20261127-v1";
const HANDOFF: &str = "46e2fafd22badb25aaee9d8150fed8624dafd5a2e95be6111c0cc34820ca4b18";
const INTERFACE: &str = "6b0e1674cb45059761c95b312fbbb478a80ed1a0ab22dcee22a55cbfc03efb40";
const CHECKPOINTS: [u64; 4] = [73_766_969, 73_773_645, 73_780_397, 73_787_145];

fn pinned(root: &Path, name: &str, hash: &str) -> Value {
    json!({"path": root.join(name), "sha256": hash})
}

fn continuous(previous: u64, profile: &Value) -> Result<()> {
    let last = CHECKPOINTS[3];
    ensure!(
        previous == CHECKPOINTS[0]
            && profile["bootstrap"] == previous
            && profile["first"] == previous + 1
            && profile["last"] == last
            && profile["positions"] == last - previous,
        "prepared interval has a gap, overlap or different endpoint"
    );
    Ok(())
}

fn local_inputs(service: &Value, namespace: &Value) -> Result<BTreeMap<String, Value>> {
    let unit = evidence::trusted(Path::new(evidence::word(service, "path")?))?;
    ensure!(
        evidence::digest(&unit) == service["sha256"],
        "service changed"
    );
    let originals = namespace["report"]["readonly_bindings"]
        .as_object()
        .context("missing native projections")?;
    let mut local = BTreeMap::new();
    for line in std::str::from_utf8(&unit)?
        .lines()
        .filter_map(|s| s.strip_prefix("BindReadOnlyPaths="))
    {
        let (from, to) = line
            .split_once(':')
            .context("unrecognized source mapping")?;
        let path = Path::new(from);
        ensure!(
            path.is_absolute() && path.canonicalize()? == path,
            "indirect input {from}"
        );
        let st = fs::symlink_metadata(path)?;
        let identity = if st.is_dir() {
            json!([st.dev(), st.ino()])
        } else {
            ensure!(st.is_file() && st.nlink() == 1, "changed input file {from}");
            json!([
                st.dev(),
                st.ino(),
                st.len(),
                st.mtime() * 1_000_000_000 + st.mtime_nsec(),
                st.ctime() * 1_000_000_000 + st.ctime_nsec()
            ])
        };
        ensure!(
            originals.get(to) == Some(&identity),
            "input {from} differs from namespace qualification"
        );
        ensure!(
            local
                .insert(to.to_owned(), json!({"source":from,"identity":identity}))
                .is_none(),
            "duplicate projection"
        );
    }
    ensure!(
        local.len() == originals.len(),
        "incomplete read-only projection list"
    );
    Ok(local)
}

pub(super) fn prepare() -> Result<Value> {
    let root = Path::new(ROOT);
    let next = Path::new(FOLLOWING);
    let release_ref = pinned(root, "SUCCESSOR_RELEASE.json", RELEASE_SHA);
    let first_ref = pinned(root, "FIRST_PROTECTED_PROGRESS.json", PROGRESS_SHA);
    let release = evidence::bound(&release_ref)?;
    let first = evidence::bound(&first_ref)?;
    let actor = evidence::bound(&release["actor"])?;
    let prior = evidence::bound(&release["interface"])?;
    ensure!(
        release["producer_invocation_id"] == IID
            && actor["unit"] == UNIT
            && actor["producer_invocation_id"] == IID
            && actor["interface"] == release["interface"]
            && first["release"] == release_ref
            && first["actor"] == release["actor"]
            && first["scope"] == release["interface"]
            && first["producer_invocation_id"] == IID
            && first["worker"]["sha256"] == prior["profile"]["worker"]
            && prior["first_new_slot"] == SLOTS[0] + 1
            && prior["last"] == SLOTS[1],
        "incorrect RAM predecessor"
    );
    let handoff_ref = pinned(next, "NEXT_HANDOFF.json", HANDOFF);
    let interface_ref = pinned(next, "BOUNDED_SUCCESSOR_WRITER_INTERFACE.json", INTERFACE);
    let handoff = evidence::bound(&handoff_ref)?;
    let issued = evidence::bound(&interface_ref)?;
    let profile = &handoff["profile"];
    continuous(evidence::num(&prior, "last")?, profile)?;
    ensure!(
        issued["profile"] == *profile
            && issued["old_release"] == handoff["original_release"]
            && issued["old_actor"] == handoff["live_owner"]
            && issued["old_actor"] != release["actor"]
            && issued["source_preflight"] == handoff["native_preflight"]
            && profile["worker"] == prior["profile"]["worker"]
            && profile["node"] == prior["profile"]["node"],
        "different staged runtime or original lineage"
    );
    let package = &profile["sealed_package"];
    let checks = evidence::member(package, "epoch-hashes.txt")?;
    let checks_text = fs::read_to_string(checks)?;
    let names: Vec<_> = checks_text.lines().collect();
    let source = evidence::bound(&handoff["source_packet"])?;
    let votes = source["independently_verified_votes"]
        .as_array()
        .context("missing votes")?;
    ensure!(
        names.len() == CHECKPOINTS.len()
            && votes.len() == names.len()
            && source["range"] == json!([CHECKPOINTS[0] + 1, CHECKPOINTS[3]])
            && source["bootstrap_slot"] == CHECKPOINTS[0]
            && source["predecessor_invocation"]
                == evidence::bound(&handoff["original_release"])?["producer_invocation_id"]
            && prior["profile"]["checkpoints"] == json!([names[0]])
            && names[0] == format!("snapshot-{}-{}.tar.zst", CHECKPOINTS[0], HASHES[1])
            && profile["checkpoints"] == json!(names[1..]),
        "different independent checkpoint list"
    );
    let mut checkpoints = Vec::new();
    for ((&slot, vote), &name) in CHECKPOINTS.iter().zip(votes).zip(&names) {
        let vote_path = evidence::member(package, &format!("reference-{slot}.json"))?;
        let meta_path = evidence::member(package, &format!("metadata-{slot}.json"))?;
        let signed = evidence::reference(&vote_path)?;
        let metadata = evidence::reference(&meta_path)?;
        let reference = evidence::bound(&signed)?;
        let meta = evidence::bound(&metadata)?;
        ensure!(
            vote["slot"] == slot
                && vote["name"] == name
                && signed["sha256"] == vote["vote"]["sha256"]
                && metadata["sha256"] == vote["gcs"]["sha256"]
                && reference["slot"] == slot
                && reference["bank_hash"] == vote["bank_hash"]
                && reference["last_blockhash"] == vote["blockhash"]
                && evidence::word(&meta, "name")?.rsplit('/').next() == Some(name)
                && (slot != CHECKPOINTS[0] || signed["sha256"] == SIGNED_CHECKPOINTS[1].1),
            "snapshot and signed checkpoint disagree at {slot}"
        );
        checkpoints.push(json!({"slot":slot,"snapshot":name,"generation":meta["generation"],
            "accounts_hash":name.trim_end_matches(".tar.zst").rsplit('-').next(),"bank_hash":vote["bank_hash"],
            "last_blockhash":vote["blockhash"],"signed_reference":signed,"gcs_metadata":metadata}));
    }
    let ingress = evidence::bound(&handoff["following_input"])?;
    let custody = evidence::bound(&ingress["custody"])?;
    let file = evidence::member(package, "bootstrap-custody.json")?;
    ensure!(
        evidence::reference(&file)?["sha256"] == ingress["native"]["sha256"],
        "bootstrap custody copy differs"
    );
    let saved: Value = serde_json::from_slice(&evidence::trusted(&file)?)?;
    let dest = Path::new(evidence::word(&ingress, "destination")?);
    let metadata = fs::symlink_metadata(dest)?;
    ensure!(
        ingress["single_copy"] == true
            && custody["receipt"] == ingress["native"]
            && saved["versioned_uri"] == ingress["versioned_uri"]
            && saved["snapshot_slot"] == CHECKPOINTS[0]
            && saved["generation"] == 1_634_787_457_734_196u64
            && saved["file"]["size"] == 2_149_673_902u64
            && saved["file"]["sha256"] == ingress["archive_sha256"]
            && custody["actual_sha256"] == ingress["archive_sha256"]
            && saved["destination"] == ingress["destination"]
            && dest.canonicalize()? == dest
            && metadata.is_file()
            && metadata.nlink() == 1
            && saved["file"]["device"] == metadata.dev()
            && saved["file"]["inode"] == metadata.ino()
            && saved["file"]["size"] == metadata.len(),
        "single-copy bootstrap changed"
    );
    let layout = evidence::bound(&profile["namespace"])?;
    let preflight = evidence::bound(&handoff["native_preflight"])?;
    ensure!(
        preflight["route_accepted"] == true && preflight["worker_executed"] == false,
        "native route did not pass"
    );
    let local = local_inputs(&preflight["service"], &layout)?;
    ensure!(
        local
            .values()
            .any(|v| v["source"] == ingress["destination"]),
        "custodied snapshot is outside native route"
    );
    let budget_ref = pinned(
        Path::new("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73726716-20261127-v1"),
        "BOUNDED_GROWTH_FROM_ORIGINAL_170.json",
        "04bb488a00b2cb853d6e21cb0b4ee3b12f4033fd9ff4fb7fbbe9ace1ad68a911",
    );
    let budget = evidence::bound(&budget_ref)?;
    ensure!(
        budget["bounded_growth_limit"] == (36u64 << 30)
            && prior["profile"]["new_home_total_bytes"] == (8u64 << 30)
            && prior["profile"]["scratch_noswap_tmpfs_bytes"] == (40u64 << 30)
            && profile["producer_memory_bytes"] == (48u64 << 30)
            && profile["guard_memory_bytes"] == (1u64 << 30),
        "changed working-set envelope"
    );
    Ok(
        json!({"schema":"horizon-170-third-ram-prepared-following-v1","predecessor_invocation":IID,
        "predecessor_actor":release["actor"],"predecessor_release":release_ref,"predecessor_scope":release["interface"],
        "first_protected_progress":first_ref,"registered_handoff":handoff_ref,"registered_interface":interface_ref,
        "original_predecessor":issued["old_actor"],"profile":profile,"source_packet":handoff["source_packet"],
        "private_bootstrap":handoff["following_input"],"bootstrap_sha256":ingress["archive_sha256"],
        "bootstrap_bytes":metadata.len(),"inputs_already_resident":local,"checkpoints":checkpoints,
        "native_preflight":handoff["native_preflight"],
        "rotation":{"additional_input_transfer_bytes":0,"additional_input_copy_bytes":0,"input_retirement_bytes":0,
            "prior_output_retained":true,"prior_scope":release["interface"],"next_prequalified_layout":layout["layout"],
            "prior_home_limit_bytes":prior["profile"]["new_home_total_bytes"],
            "prior_private_scratch_bytes":prior["profile"]["scratch_noswap_tmpfs_bytes"],
            "historical_following_growth_bytes":budget["bounded_growth_limit"],"historical_growth_evidence":budget_ref,
            "fresh_candidate_admission_required":true,"authorized_deletion_or_offload_bytes":0,
            "staged_writer_still_binds_original_predecessor":true,
            "terminal_comparison":"closed","pid1_capture_directory":super::CAPTURE_DIR},
        "admission_granted":false,"predecessor_segment_verified":false,"canonical_publication_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_adjacent_range_only() {
        let mut p =
            json!({"bootstrap":73_766_969,"first":73_766_970,"last":73_787_145,"positions":20_176});
        assert!(continuous(73_766_969, &p).is_ok());
        assert!(continuous(73_760_367, &p).is_err());
        p["first"] = json!(73_766_971);
        assert!(continuous(73_766_969, &p).is_err());
        p["first"] = json!(73_766_969);
        assert!(continuous(73_766_969, &p).is_err());
    }
}
