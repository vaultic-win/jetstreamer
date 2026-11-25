//! Birth and terminal evidence for the paid semantic successor, before local or public playback.
use super::*;

const V5N_PREDECESSOR: &str = "dba04d40f1b046b4875d7e27e0ff224a";
const V5N_READER: &str = "d6bc752180c265f6d680464ffec7ac2cc6bc4125440ef6ac1bb43534f3db2c34";
const V5N_REVIEW: &str = "73439c7bff8fbd6ab806ab70f7e8953dae890c8e3b783ab7b8d7c3e270de18ff";
const V5N_DISPATCH: &str = "080e95f9c7be162980589d1513c25ff2a4638d9e00d163a60e12c6d2475a5308";

fn guard_walk_start(base: &Path, started: &Value, intent: &Value) -> Result<()> {
    let post = base.join(if cfg!(incident_v5n_136_post145_only) {
        "tools-v13i"
    } else {
        "tools-v13h"
    });
    let (_, seal) = publication::frozen_json(&post.join("deployment-seal-receipt.json"))?;
    let (proof, build) = publication::frozen_json(&post.join("build-proof.json"))?;
    let (binding, family) = publication::frozen_json(&base.join("V5N_RUNTIME_BINDINGS.json"))?;
    ensure!(
        seal["destination"] == json!(post)
            && seal["members"].as_array().is_some_and(|members| members
                .iter()
                .any(|m| m["name"] == "build-proof.json"
                    && m["mode"] == "0444"
                    && m["sha256"] == proof.sha256))
            && build["schema"] == "horizon-145-v5j-post-build-v1"
            && binding.sha256 == "e96a2cbf5ef5d8e5ddd70fc40acdb47b843c75970671d6fe381035480458f560"
            && build["guard_walk_binding"] == json!(binding)
            && family["schema"] == "horizon-145-qualified-v5n-runtime-v1"
            && build["semantic_image"] == family["reader"]
            && build["semantic_dispatch"] == family["dispatcher"],
        "post build is outside the qualified V5n runtime family"
    );
    let worker_proof: Bound = serde_json::from_value(family["build"].clone())?;
    let review_ref: Bound = serde_json::from_value(family["review"].clone())?;
    let worker = custody::json(&worker_proof, true)?;
    let review = custody::json(&review_ref, true)?;
    let window = &started["fresh_fit"]["phase145"]["window"];
    ensure!(
        family["reader"] == json!({"path":base.join("tools-v5n/export145"),"sha256":V5N_READER})
            && review_ref.sha256 == V5N_REVIEW
            && family["dispatcher"]["sha256"] == V5N_DISPATCH
            && worker["source_commit"] == family["source_commit"]
            && worker["build_iid"] == family["build_iid"]
            && worker["capacity_provider"] == family["prior_stopped"]
            && worker["verifier_sha256"] == V5N_READER
            && review["reader"] == family["reader"]
            && review["seal"] == family["worker"]
            && review["provider"] == family["provider"]
            && review["old_manager"]["InvocationID"] == V5N_PREDECESSOR
            && started["image"] == V5N_READER
            && intent["review_sha256"] == V5N_REVIEW
            && intent["preflight"]["quote_provider"] == family["dispatcher"]
            && window["continuity_seal"] == family["worker"]
            && window["guard_walk_failure"] == worker["guard_walk_failure"]
            && window["guard_walk_failure"] == review["failed_phase"]["failure"]
            && window["guard_walk_failure"]["sha256"]
                == "8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010"
            && window["rejected_guard"] == worker["rejected_guard"]
            && window["rejected_guard"]["sha256"]
                == "6800d34a8bb71f468d2f06daf6a29cf9016d972f4cc1ef60d915600e8085ad1f"
            && window["registered_guard_clock"] == worker["registered_guard_clock"]
            && window["registered_guard_clock"]["sha256"]
                == "119fdd9c0246b71fa188007daad510adc377bc002a110dda3e1074bb06d0819d",
        "unbound V5n worker, dispatcher, or failed guard generation"
    );
    Ok(())
}

fn pinned_semantic_owner(export: &str) -> Result<()> {
    let (iid, handoff, key, family_name, family_hash) = if cfg!(incident_v5r_136_post145_only) {
        (
            "8f2b9c06b62147babe83c9ade7271cd3",
            "v5r-name-handoff",
            "encoded_prefix_custody",
            "v5r-name-handoff/ACTUAL_ADVANCING_AND_136_CUSTODY.json",
            "1343de96384e52ff061262a2d80c217d187a1fc8b0ce0e07e32940ee88e89b3b",
        )
    } else if cfg!(incident_v5q_136_post145_only) {
        (
            "cbacb5a17e6347509640846eccb95cb0",
            "v5q-name-handoff",
            "audit_turnover_binding",
            "V5Q_RUNTIME_BINDINGS.json",
            "a5dc1d9973d950d36f7302b800f0b10421066e135e0912750fd92b98521cadc4",
        )
    } else {
        (
            "f3474dfad55f4a05a64431421881db29",
            "v5o-name-handoff",
            "donor_pressure_binding",
            "V5O_RUNTIME_BINDINGS.json",
            "d571da98684079bc937a2ddeed52dbcd457eb0a74010519171b851e3e5297137",
        )
    };
    ensure!(export == iid, "foreign pinned semantic export");
    let post = Path::new(INCIDENT_POST_IMAGE)
        .parent()
        .context("V13j package")?;
    let base = post.parent().context("V5o runtime family")?;
    let (_, seal) = publication::frozen_json(&post.join("deployment-seal-receipt.json"))?;
    let (build_ref, build) = publication::frozen_json(&post.join("build-proof.json"))?;
    let members = seal["members"].as_array().context("V13j members")?;
    let checker = members
        .iter()
        .find(|member| member["name"] == "post-inputs" && member["mode"] == "0555")
        .context("V13j inputs checker")?;
    let path = post.join("post-inputs");
    let binding = Bound {
        path: path.clone(),
        sha256: checker["sha256"]
            .as_str()
            .context("V13j checker hash")?
            .into(),
    };
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(post)
            && seal["sealer_sha256"]
                == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
            && seal["remote_mutations"] == false
            && members
                .iter()
                .any(|member| member["name"] == "build-proof.json"
                    && member["mode"] == "0444"
                    && member["sha256"] == build_ref.sha256)
            && build["schema"] == "horizon-145-v5j-post-build-v1"
            && build[key]
                == json!({
                    "path":base.join(family_name),
                    "sha256":family_hash
                }),
        "post build is outside the qualified V5o runtime family"
    );
    custody::bytes(&binding, 1 << 20, true)?;
    let output = capacity::run(
        path.to_str().context("V13j checker path")?,
        &["inspect-semantic"],
        "20",
    )?;
    let report: Value = serde_json::from_str(&output)?;
    let (_, captured) =
        publication::frozen_json(&base.join(handoff).join("semantic-completion.json"))?;
    ensure!(
        report == captured && report["invocation_id"] == export,
        "different captured V5o completion"
    );
    terminal(export)
}

#[cfg(incident_v5u_post145_only)]
fn v5u_semantic_owner(export: &str) -> Result<()> {
    ensure!(export == "8452dba9df42437b9874b35cb44d059f", "foreign V5u semantic export");
    let package = Path::new(INCIDENT_POST_IMAGE).parent().context("V5u post package")?;
    let helper = package.join("v5u-post-evidence.py");
    let (_, seal) = publication::frozen_json(&package.join("deployment-seal-receipt.json"))?;
    let member = seal["members"].as_array().context("V5u post members")?.iter()
        .find(|m| m["name"] == "v5u-post-evidence.py" && m["mode"] == "0444")
        .context("V5u semantic checker outside deployment seal")?;
    ensure!(
        seal["destination"] == json!(package)
            && seal["sealer_sha256"] == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
            && seal["remote_mutations"] == false,
        "foreign V5u post package"
    );
    let bound = Bound {
        path: helper.clone(),
        sha256: member["sha256"].as_str().context("V5u semantic checker digest")?.into(),
    };
    custody::bytes(&bound, 128 << 10, true)?;
    let report = capacity::run(
        "/usr/bin/python3",
        &["-IB", helper.to_str().context("V5u semantic checker path")?],
        "45",
    )?;
    let result: Value = serde_json::from_str(&report)?;
    ensure!(
        result["schema"] == "horizon-epoch145-v5u-semantic-completion-v1"
            && result["invocation_id"] == export
            && result["archive_publication_authorized"] == false,
        "foreign V5u semantic completion"
    );
    // The checker independently proved the ordered PID1 startup/exit.
    terminal(export)
}

#[cfg(all(incident_v5w_post145_only, not(incident_v5x_post145_only)))]
fn v5w_semantic_owner(export: &str) -> Result<()> {
    ensure!(export == "97bd2045ebe449e3ae77330c7e4ec7b4", "foreign V5w semantic export");
    let family = Path::new(RUNTIME).join("epoch145-semantic-continuity-20261121-v1");
    let authority = family.join("tools-v5w");
    let helper = authority.join("v5v_semantic_completion.py");
    let helper_hash = "42118f1624e540ed5973d37e358ad4a9f0ba68e3c8c2100c9f777e01c0f2a9bf";
    let (seal_ref, seal) = publication::frozen_json(&authority.join("deployment-seal-receipt.json"))?;
    ensure!(
        seal_ref.sha256 == "8768935daed0a99dd01d467da957dabdb218c3741c04f6597cf663dbcf36314e"
            && seal["destination"] == json!(authority)
            && seal["remote_mutations"] == false
            && seal["members"].as_array().is_some_and(|entries| entries.iter().any(|member|
                member["name"] == "v5v_semantic_completion.py"
                    && member["sha256"] == helper_hash && member["mode"] == "0444")),
        "V5w checker differs from the accepted seal"
    );
    custody::bytes(&Bound{path:helper.clone(),sha256:helper_hash.into()}, 128 << 10, true)?;
    let handoff = family.join("v5w-name-handoff");
    let start = handoff.join("START_RESULT.json");
    let report = capacity::run("/usr/bin/python3",
        &["-IB", helper.to_str().context("V5w semantic checker")?,
          start.to_str().context("V5w start result")?,
          "5671b19df2e673656d4ddca27c6218b60a7f5b60f4e9bea72f69792a0af5c379"], "45")?;
    let result: Value = serde_json::from_str(&report)?;
    let (_, captured) = publication::frozen_json(&handoff.join("SEMANTIC_COMPLETION.json"))?;
    ensure!(
        result == captured
            && result["schema"] == "horizon-epoch145-v5v-custody-successor-semantic-completion-v1"
            && result["invocation_id"] == export && result["publication_authorized"] == false
            && result["r2_mutations"] == false,
        "different accepted V5w semantic completion"
    );
    terminal(export)
}

#[cfg(incident_v5x_post145_only)]
fn v5x_semantic_owner(export: &str) -> Result<()> {
    ensure!(
        custody::hex(export, 32) && export != "97bd2045ebe449e3ae77330c7e4ec7b4",
        "foreign V5x semantic export"
    );
    let family = Path::new(RUNTIME).join("epoch145-semantic-continuity-20261121-v1");
    let authority = family.join("tools-v5x");
    let helper = authority.join("v5v_semantic_completion.py");
    let (seal_ref, seal) =
        publication::frozen_json(&authority.join("deployment-seal-receipt.json"))?;
    let (build_ref, build) = publication::frozen_json(&authority.join("build-proof.json"))?;
    let members = seal["members"]
        .as_array()
        .context("missing V5x deployment members")?;
    let member = members
        .iter()
        .find(|row| row["name"] == "v5v_semantic_completion.py")
        .context("missing V5x semantic checker")?;
    let binding = Bound {
        path: helper.clone(),
        sha256: member["sha256"]
            .as_str()
            .context("missing V5x checker digest")?
            .to_owned(),
    };
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(authority)
            && seal["sealer_sha256"]
                == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
            && seal["remote_mutations"] == false
            && seal["r2_mutations"] == false
            && member["mode"] == "0444"
            && build["semantic_checker"] == json!(binding)
            && members.iter().any(|row| row["name"] == "build-proof.json"
                && row["sha256"] == build_ref.sha256
                && row["mode"] == "0444"),
        "foreign V5x semantic package"
    );
    custody::bytes(&binding, 128 << 10, true)?;
    let handoff = family.join("v5x-name-handoff");
    let (start, _) = publication::frozen_json(&handoff.join("START_RESULT.json"))?;
    let report = capacity::run(
        "/usr/bin/python3",
        &[
            "-IB",
            helper.to_str().context("V5x semantic checker")?,
            start.path.to_str().context("V5x start result")?,
            &start.sha256,
        ],
        "45",
    )?;
    let result: Value = serde_json::from_str(&report)?;
    let (_, captured) = publication::frozen_json(&handoff.join("SEMANTIC_COMPLETION.json"))?;
    ensure!(
        result == captured
            && result["schema"] == "horizon-epoch145-v5x-donor-successor-semantic-completion-v1"
            && result["invocation_id"] == export
            && result["publication_authorized"] == false
            && result["r2_mutations"] == false
            && result["startup_evidence"]["submission_result"] == json!(start)
            && result["startup_evidence"]["worker_build"] == json!(build_ref)
            && result["startup_evidence"]["worker_seal"] == json!(seal_ref)
            && result["startup_evidence"]["predecessor_terminal"] == build["guard_terminal"],
        "different accepted V5x semantic completion"
    );
    terminal(export)
}

pub(crate) fn semantic_owner(export: &str) -> Result<()> {
    #[cfg(incident_v5x_post145_only)]
    return v5x_semantic_owner(export);

    #[cfg(all(incident_v5w_post145_only, not(incident_v5x_post145_only)))]
    return v5w_semantic_owner(export);

    #[cfg(all(incident_v5u_post145_only, not(incident_v5w_post145_only)))]
    return v5u_semantic_owner(export);

    #[cfg(not(any(incident_v5u_post145_only, incident_v5w_post145_only)))]
    legacy_semantic_owner(export)
}

#[cfg(not(incident_v5u_post145_only))]
fn legacy_semantic_owner(export: &str) -> Result<()> {
    if cfg!(any(
        incident_v5r_136_post145_only,
        incident_v5q_136_post145_only,
        incident_v5o_136_post145_only
    )) {
        return pinned_semantic_owner(export);
    }
    let (handoff_name, old, image_name, image_sha, dispatch) = if cfg!(incident_v5n_post145_only) {
        (
            "v5n-name-handoff",
            V5N_PREDECESSOR,
            "tools-v5n/export145",
            V5N_READER,
            Some((V5N_REVIEW, V5N_DISPATCH)),
        )
    } else if cfg!(incident_v5m_post145_only) {
        (
            "v5m-name-handoff",
            "ff597d64ad37400ea5c6836336fb6706",
            "tools-v5m/export145",
            "9068d5ac9ccd4d35481cbf2882faf67a97b0926133663a2e4885917e714bdc21",
            Some((
                "28540e178ace196165ea892f924001a72b59396708b8269fb3a057a2627b132f",
                "2c582f4c5a0d400cadd35e37710aa126b8b2ae8c09bab7bdfcc08f1ecfc5aaea",
            )),
        )
    } else if cfg!(incident_v5k_post145_only) {
        (
            "v5k-name-handoff",
            "f2afc696a63a4e6aa6812451cf3559e5",
            "tools-v5k/export145",
            "02c9a1ad332fbea43e4b552561fc01e503f1dedcec6347e541db4cf9de56f571",
            Some((
                "1a7f7bce208d97831963c66c462bbac28b7f9b84e990d09fa5da7e5efa56d150",
                "f69f462cecb76fc586799d36f358e61b1880f99d0c024b0c76dd27d3a2f9637e",
            )),
        )
    } else if cfg!(incident_v5j_retry1_post145_only) {
        (
            "v5j-name-handoff-retry1",
            "48ad7b2234d74e74b0498e7110e0aee3",
            "tools-v5j/export145",
            "52d2dd991c69b24079308fafefd054af9aa4fe1d095d0469ec3d90ef851f1cc4",
            Some((
                "38774819c4dbbe1246851585afb57ba65df4919cbf457fb6a04b75ef2e77fc07",
                "1b98fea46cef7beefe2c3f250da7fe524e0e07f78b6ffb61a575a552b2a1b1ee",
            )),
        )
    } else {
        (
            "v5j-name-handoff",
            "afcf6cdd1ec0400ea2757f81472987b3",
            "tools-v5j/export145",
            "52d2dd991c69b24079308fafefd054af9aa4fe1d095d0469ec3d90ef851f1cc4",
            None,
        )
    };
    let base = Path::new(INCIDENT_POST_IMAGE)
        .parent()
        .and_then(Path::parent)
        .context("145 semantic package")?;
    let handoff = base.join(handoff_name);
    let image = base.join(image_name);
    let (selected, report) = publication::frozen_json(&handoff.join("semantic-completion.json"))?;
    let (_, submission) = publication::frozen_json(&handoff.join("submission-result.json"))?;
    let (_, intent) = publication::frozen_json(&handoff.join("submission-intent.json"))?;
    let argv = submission["argv"]
        .as_array()
        .context("original semantic argv")?;
    let state = Path::new(BASE).join("state").join(export);
    let start: Bound = serde_json::from_value(report["start"].clone())?;
    let started = custody::evidence(&start)?;
    let done: Bound = serde_json::from_value(report["completion"].clone())?;
    let complete = custody::evidence(&done)?;
    if cfg!(incident_v5n_post145_only) || cfg!(incident_v5m_post145_only) {
        let fit = &started["fresh_fit"];
        let window = &fit["phase145"]["window"];
        ensure!(
            fit["phase145"]["invocation_id"] == export
                && fit["phase145"]["stage"] == "controller"
                && fit["fits"] == true
                && fit["fleet"] == intent["fleet"]
                && window["missed_clock_failure"]["sha256"]
                    == "04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6"
                && fit["epoch159_donor_cover"]["fleet"] == intent["fleet"]
                && fit["epoch159_donor_cover"]["credited_retirement_bytes"] == 0,
            "unbound missed-clock recovery or paid donor"
        );
        if cfg!(incident_v5n_post145_only) {
            guard_walk_start(base, &started, &intent)?;
        } else {
            ensure!(
                window["continuity_seal"]["sha256"]
                    == "db422be5b246aa3aef2457fd9325f6b8cca739e3e4c63d2e4794ae30c527f6c4",
                "unbound V5m worker seal"
            );
        }
    }
    ensure!(
        custody::hex(export, 32)
            && export != old
            && report["schema"] == "horizon-145-v5j-semantic-completion-v1"
            && report["invocation_id"] == export
            && submission["invocation_id"] == export
            && intent["original"]["INVOCATION_ID"] == old
            && dispatch.map_or(true, |(review, seal)| {
                intent["review_sha256"] == review
                    && intent["preflight"]["quote_provider"]["sha256"] == seal
            })
            && intent["argv"] == submission["argv"]
            && argv.len() >= 5
            && argv[argv.len() - 5..]
                == [
                    json!(image),
                    json!("recover-full-output"),
                    intent["fleet"]["path"].clone(),
                    intent["fleet"]["sha256"].clone(),
                    json!(image_sha)
                ]
            && start.path == state.join("recovery-started.json")
            && done.path == state.join("complete.json")
            && started["iid"] == export
            && started["image"] == image_sha
            && started["r2_mutations"] == false
            && started["fresh_fit"]["serial_145_holding_handback"]
                == intent["preflight"]["serial_handback"]
            && complete["iid"] == export
            && complete["r2_mutations"] == false
            && complete["receipt"] == report["extraction"]
            && report["archive"] == json!(Path::new(OUTPUT).join("epoch-145.jet"))
            && report["archive_bytes"] == BYTES
            && !state.join("failed.json").try_exists()?,
        "different paid semantic generation or incomplete v5j handoff: {selected:?}"
    );
    terminal(export)
}
