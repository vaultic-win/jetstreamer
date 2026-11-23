//! Birth and terminal evidence for the paid semantic successor, before local or public playback.
use super::*;

pub(crate) fn semantic_owner(export: &str) -> Result<()> {
    let (handoff_name, old, image_name, image_sha, dispatch) = if cfg!(incident_v5m_post145_only) {
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
    if cfg!(incident_v5m_post145_only) {
        let fit = &started["fresh_fit"];
        let window = &fit["phase145"]["window"];
        ensure!(
            fit["phase145"]["invocation_id"] == export
                && fit["phase145"]["stage"] == "controller"
                && fit["fits"] == true
                && fit["fleet"] == intent["fleet"]
                && window["continuity_seal"]["sha256"]
                    == "db422be5b246aa3aef2457fd9325f6b8cca739e3e4c63d2e4794ae30c527f6c4"
                && window["missed_clock_failure"]["sha256"]
                    == "04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6"
                && fit["epoch159_donor_cover"]["fleet"] == intent["fleet"]
                && fit["epoch159_donor_cover"]["credited_retirement_bytes"] == 0,
            "unbound missed-clock recovery or paid donor"
        );
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
