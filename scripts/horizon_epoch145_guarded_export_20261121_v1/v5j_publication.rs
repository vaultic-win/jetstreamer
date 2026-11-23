//! Birth and terminal evidence for the paid semantic successor, before local or public playback.
use super::*;

pub(crate) fn semantic_owner(export: &str) -> Result<()> {
    let retry = cfg!(incident_v5j_retry1_post145_only);
    let handoff = Path::new(INCIDENT_POST_IMAGE)
        .parent()
        .and_then(Path::parent)
        .context("145 semantic package")?
        .join(if retry {
            "v5j-name-handoff-retry1"
        } else {
            "v5j-name-handoff"
        });
    let (selected, report) = publication::frozen_json(&handoff.join("semantic-completion.json"))?;
    let (_, submission) = publication::frozen_json(&handoff.join("submission-result.json"))?;
    let (_, intent) = publication::frozen_json(&handoff.join("submission-intent.json"))?;
    let old = if retry {
        "48ad7b2234d74e74b0498e7110e0aee3"
    } else {
        "afcf6cdd1ec0400ea2757f81472987b3"
    };
    let image_sha = "52d2dd991c69b24079308fafefd054af9aa4fe1d095d0469ec3d90ef851f1cc4";
    let image = handoff
        .parent()
        .context("semantic package")?
        .join("tools-v5j/export145");
    let argv = submission["argv"]
        .as_array()
        .context("original semantic argv")?;
    let state = Path::new(BASE).join("state").join(export);
    let start: Bound = serde_json::from_value(report["start"].clone())?;
    let started = custody::evidence(&start)?;
    let done: Bound = serde_json::from_value(report["completion"].clone())?;
    let complete = custody::evidence(&done)?;
    ensure!(
        custody::hex(export, 32)
            && export != old
            && report["schema"] == "horizon-145-v5j-semantic-completion-v1"
            && report["invocation_id"] == export
            && submission["invocation_id"] == export
            && intent["original"]["INVOCATION_ID"] == old
            && (!retry
                || (intent["review_sha256"]
                    == "38774819c4dbbe1246851585afb57ba65df4919cbf457fb6a04b75ef2e77fc07"
                    && intent["preflight"]["quote_provider"]["sha256"]
                        == "1b98fea46cef7beefe2c3f250da7fe524e0e07f78b6ffb61a575a552b2a1b1ee"))
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
