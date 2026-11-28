//! Optional, qualified old native265 future-growth transition. Original ledger
//! rows and all memory/floor/live-v3 reservations remain untouched.
use super::*;
mod pins;
mod runtime;
pub(crate) use runtime::process_references::scan as tree_references;
pub(crate) use runtime::scratch_ownership;
const OLD_UNIT: &str = "horizon-265-native-input-20261119-v1.service";
const OLD_IID: &str = "ce5f66a82fdd4c0e93ca99f27b925112";
const OLD_ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1";
const OLD_GROWTH: u64 = 506_191_984_640;
const STATE: &str = "/var/lib/jetstreamer/horizon-native265-scratch-retirement-20261120-v2";
const HELPER: &str =
    "/var/lib/jetstreamer/horizon-native265-scratch-retirer-20261120-v2/native265-scratch-retire";
const RELEASE: &str =
    "/var/lib/jetstreamer/horizon-native265-runtime-growth-release-20261120-v2/release.json";
const TERMINAL: &str =
    "/var/lib/jetstreamer/horizon-native265-terminal-proof-2048-20261119-v1/proof.json";
const TERMINAL_SHA: &str = "62d7d71ee1a9c7215c4fffa7d5fec49ef449bb6be24de3e450432217a3efa519";

fn denied(v: &Value, fields: &[&str]) -> Result<()> {
    for k in fields {
        ensure!(v[*k] == false, "native265 unexpected/missing authority {k}");
    }
    Ok(())
}
fn local_only(v: &Value) -> Result<()> {
    denied(
        v,
        &[
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ],
    )
}
fn exact_ref(v: &Value, path: impl AsRef<Path>) -> Result<Bound> {
    let b = binding(v)?;
    ensure!(
        b.path == path.as_ref() && hex(&b.sha256, 64),
        "native265 receipt path/digest differs"
    );
    Ok(b)
}
fn booking(v: &Value, plan: &Value, phase_at: u64) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-native265-runtime-retirement-booking-v1"
            && v["Main_accepted"] == true
            && v["plan"] == *plan
            && v["maximum_memory_bytes"] == 268435456
            && v["maximum_metadata_bytes"] == 16777216
            && v["maximum_wall_seconds"] == 120
            && v["future_growth_credit_taken_bytes"] == 0,
        "native265 phase booking differs"
    );
    let issue = num(v, "recorded_unix_seconds")?;
    let expiry = num(v, "expires_unix_seconds")?;
    ensure!(
        issue <= phase_at
            && phase_at < expiry
            && expiry <= issue.checked_add(600).context("booking clock overflow")?,
        "native265 phase was outside its booking"
    );
    Ok(())
}
fn scope(v: &Value, rows: &[capacity::Reservation]) -> Result<usize> {
    ensure!(
        v["schema"] == "horizon-native265-retired-runtime-growth-release-v1"
            && v["unit"] == OLD_UNIT
            && v["invocation_id"] == OLD_IID
            && v["original_remaining_disk_growth_bytes"] == OLD_GROWTH
            && v["remaining_future_growth_bytes"] == 0
            && v["released_memory_bytes"] == 0
            && v["physical_allocation_credit_bytes"] == 0
            && v["inherited_floor_credit_bytes"] == 0
            && v["Main_accepted"] == true,
        "native265 growth-only release scope"
    );
    no_authority(v)?;
    let selected: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.unit == OLD_UNIT)
        .collect();
    ensure!(
        selected.len() == 1,
        "missing/duplicate original native265 reservation"
    );
    let (index, r) = selected[0];
    ensure!(
        r.invocation_id == OLD_IID
            && r.maximum_memory_bytes == 128_000_000_000
            && r.remaining_disk_growth_bytes == OLD_GROWTH
            && r.minimum_free_bytes >= 3_216_541_534_488
            && r.release.is_none()
            && v["original_reservation_source"] == json!(r.source),
        "native265 original booking changed/released"
    );
    Ok(index)
}
fn effective(rows: &[capacity::Reservation], index: usize) -> Vec<capacity::Reservation> {
    let mut result = rows.to_vec();
    result[index].remaining_disk_growth_bytes = 0;
    result
}

/// Pure authenticated-document graph validation; no filesystem or runtime authority.
fn graph(
    release: &Value,
    boot: &str,
    helper_sha: &str,
    qualification_ref: &Bound,
    mut load: impl FnMut(&Bound) -> Result<Value>,
) -> Result<Value> {
    ensure!(
        hex(helper_sha, 64) && hex(&qualification_ref.sha256, 64),
        "unqualified native265 retirement image/receipt"
    );
    ensure!(release["boot_id"] == boot, "native265 release boot differs");
    let terminal_ref = Bound::new(TERMINAL, TERMINAL_SHA);
    ensure!(
        release["terminal_proof"] == json!(terminal_ref)
            && release["retirement_qualification"] == json!(qualification_ref),
        "native265 original proof/qualification changed"
    );
    let terminal = load(&terminal_ref)?;
    ensure!(
        terminal["schema"] == "jetstreamer-private-epoch265-native-terminal-proof-v1"
            && terminal["unit"] == OLD_UNIT
            && terminal["invocation_id"] == OLD_IID
            && terminal["main_pid"] == 1307638
            && terminal["native_input_qualified"] == true
            && terminal["boot_id"] == boot,
        "native265 original terminal identity differs"
    );
    no_authority(&terminal)?;
    let qualification = load(qualification_ref)?;
    ensure!(
        qualification["schema"] == "horizon-native265-scratch-source-qualification-v2"
            && qualification["source_commit"] == pins::SOURCE_COMMIT
            && qualification["image_sha256"] == helper_sha
            && qualification["remote_containment"] == true
            && qualification["all_compilation_inputs_equal_committed_bytes"] == true
            && qualification["source_input_count"] == 7
            && qualification["tests_passed"] == pins::TEST_COUNT
            && qualification["strict_all_target_clippy"] == true
            && qualification["release_build"] == true
            && qualification["build_used_memory_backed_tmpfs"] == true
            && qualification["source_only_qualification"] == true
            && qualification["physical_reclamation_credit_bytes"] == 0
            && qualification["admission_credit_bytes"] == 0,
        "native265 unqualified retirement source/image"
    );
    let seal_ref = Bound::new(pins::SEAL_PATH, pins::SEAL_SHA);
    ensure!(
        release["retirement_deployment_seal"] == json!(seal_ref),
        "native265 deployment seal changed"
    );
    let seal = load(&seal_ref)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == Path::new(HELPER).parent().unwrap().to_str().unwrap()
            && seal["sealer_sha256"] == SEALER_SHA,
        "native265 deployment custody differs"
    );
    local_only(&seal)?;
    let members = seal["members"]
        .as_array()
        .context("retirement deployment members")?;
    ensure!(
        members.len() == pins::MEMBERS.len(),
        "native265 deployment membership changed"
    );
    for (name, sha, bytes, mode) in pins::MEMBERS {
        let matches: Vec<_> = members.iter().filter(|m| m["name"] == *name).collect();
        ensure!(
            matches.len() == 1,
            "missing/duplicate sealed retirement member"
        );
        let m = matches[0];
        ensure!(
            m["sha256"] == *sha && m["bytes"] == *bytes && m["mode"] == *mode,
            "retirement sealed artifact identity changed"
        );
    }
    let cr = exact_ref(
        &release["retirement_check"],
        Path::new(STATE).join("check.json"),
    )?;
    let ir = exact_ref(
        &release["retirement_intent"],
        Path::new(STATE).join("intent.json"),
    )?;
    let rr = exact_ref(
        &release["retirement_completion"],
        Path::new(STATE).join("completion.json"),
    )?;
    let ar = exact_ref(
        &release["retirement_absence"],
        Path::new(STATE).join("absence-v1.json"),
    )?;
    let check = load(&cr)?;
    let intent = load(&ir)?;
    let complete = load(&rr)?;
    let absence = load(&ar)?;
    ensure!(
        check["schema"] == "horizon-native265-empty-scratch-retirement-check-v1"
            && intent["schema"] == "horizon-native265-empty-scratch-retirement-intent-v1"
            && complete["schema"] == "horizon-native265-empty-scratch-retirement-completion-v1"
            && absence["schema"] == "horizon-native265-empty-scratch-absence-v1",
        "native265 incompatible retirement schema"
    );
    let plan_ref = binding(&check["plan"])?;
    let plan = load(&plan_ref)?;
    ensure!(
        plan.as_object().context("retirement plan")?.len() == 4
            && plan["schema"] == "horizon-native265-empty-scratch-retirement-plan-v1"
            && plan["main_accepted"] == true
            && plan["exclusive_campaign_mutation_owner"] == true
            && plan["no_staged_scratch_consumers_confirmed"] == true,
        "native265 retirement plan scope differs"
    );
    let mut prior_time =
        num(&terminal, "recorded_unix_seconds")?.max(num(&seal, "created_unix_seconds")?);
    for phase in [&check, &intent, &complete, &absence] {
        local_only(phase)?;
        ensure!(
            phase["plan"] == json!(plan_ref)
                && phase["helper_sha256"] == helper_sha
                && phase["preserved"] == check["preserved"]
                && phase["terminal"] == check["terminal"],
            "native265 lifecycle plan/image/preserved owner changed"
        );
        let at = num(phase, "recorded_unix_seconds")?;
        ensure!(prior_time <= at, "native265 lifecycle clock regressed");
        prior_time = at;
        booking(&load(&binding(&phase["booking"])?)?, &phase["plan"], at)?;
    }
    ensure!(
        num(release, "recorded_unix_seconds")? >= prior_time,
        "native265 release predates absence"
    );
    denied(
        &check,
        &["retirement_performed", "resource_release_authorized"],
    )?;
    denied(&intent, &["resource_release_authorized"])?;
    for phase in [&complete, &absence] {
        denied(
            phase,
            &[
                "memory_release_authorized",
                "future_growth_release_authorized",
            ],
        )?;
        ensure!(
            phase["physical_reclamation_credit_bytes"] == 0 && phase["scratch_absent"] == true,
            "native265 phantom reclamation/absence"
        );
    }
    ensure!(
        check["scratch_already_empty"] == true
            && intent["only_empty_scratch_directory_removal_authorized"] == true
            && intent["check"] == json!(cr)
            && intent["scratch"] == check["scratch"]
            && complete["check"] == json!(cr)
            && complete["intent"] == json!(ir)
            && absence["completion"] == json!(rr)
            && complete["unit"] == OLD_UNIT
            && complete["invocation_id"] == OLD_IID
            && complete["retired_paths"] == json!([format!("{OLD_ROOT}/scratch")])
            && complete["scratch_was_already_empty"] == true
            && complete["ledger_tmp_result_stderr_and_input_cache_preserved"] == true
            && complete["original_root_preserved"] == true
            && complete["live_v3_not_read_or_changed"] == true,
        "native265 partial/overbroad retirement chain"
    );
    let proofs = &check["proofs"];
    ensure!(
        complete["proofs"] == *proofs
            && proofs["terminal_proof"] == json!(terminal_ref)
            && proofs["original_evidence"] == terminal,
        "native265 original evidence graph changed"
    );
    for k in [
        "native_result",
        "guard_history",
        "startup_handoff",
        "capture_spec",
        "consumer_transition",
    ] {
        load(&binding(&terminal[k])?)?;
    }
    // The runtime capture independently hashes these original objects and validates
    // original input packet metadata, sentinel, all preserved siblings and owners.
    Ok(
        json!({"proofs":proofs,"terminal":complete["terminal"],"preserved":complete["preserved"],
        "check":cr,"intent":ir,"completion":rr,"absence":ar,"qualification":qualification_ref}),
    )
}

pub(super) fn arithmetic_view(
    n: &mut Native,
    review: &Value,
    rows: &[capacity::Reservation],
    boot: &str,
) -> Result<(Vec<capacity::Reservation>, Option<Value>)> {
    let Some(value) = review.get("native265_runtime_growth_release") else {
        return Ok((rows.to_vec(), None));
    };
    ensure!(
        hex(pins::HELPER_SHA, 64) && hex(pins::QUALIFICATION_SHA, 64),
        "native265 retirement helper and qualification have not been registered"
    );
    let release_ref = exact_ref(value, RELEASE)?;
    let release = release_ref.sealed()?;
    let index = scope(&release, rows)?;
    ensure!(
        num(&release, "recorded_unix_seconds")? <= now()?,
        "future native265 growth release"
    );
    let qualification_ref = Bound::new(pins::QUALIFICATION_PATH, pins::QUALIFICATION_SHA);
    for (name, sha, bytes, mode) in pins::MEMBERS {
        let artifact = Bound::new(
            Path::new(HELPER)
                .parent()
                .context("helper package")?
                .join(name),
            *sha,
        );
        artifact.artifact()?;
        let metadata = fs::symlink_metadata(&artifact.path)?;
        ensure!(
            metadata.len() == *bytes && metadata.mode() & 0o7777 == u32::from_str_radix(mode, 8)?,
            "retirement package member changed"
        );
    }
    let evidence = graph(
        &release,
        boot,
        pins::HELPER_SHA,
        &qualification_ref,
        Bound::sealed,
    )?;
    let current = runtime::capture(n)?;
    for k in ["proofs", "terminal", "preserved"] {
        ensure!(
            current[k] == evidence[k],
            "native265 current state differs from retired evidence {k}"
        );
    }
    let original_growth = rows.iter().try_fold(0u64, |sum, r| {
        capacity::add(sum, r.remaining_disk_growth_bytes)
    })?;
    Ok((
        effective(rows, index),
        Some(json!({"release":release_ref,"retirement_evidence":evidence,
        "current_scope":current,"original_retained_growth_bytes":original_growth,
        "released_native265_future_growth_bytes":OLD_GROWTH,
        "remaining_retained_growth_bytes":original_growth.checked_sub(OLD_GROWTH).context("growth underflow")?,
        "original_ledger_and_bookings_unchanged":true,"released_memory_bytes":0,
        "physical_allocation_credit_bytes":0,"inherited_floor_credit_bytes":0})),
    ))
}
#[cfg(test)]
mod tests;
