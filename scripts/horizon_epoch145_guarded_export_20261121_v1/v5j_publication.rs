//! Birth and terminal evidence for the paid semantic successor, before local or public playback.
use super::*;

pub(crate) fn semantic_owner(export: &str) -> Result<()> {
    let handoff = Path::new(INCIDENT_POST_IMAGE)
        .parent()
        .and_then(Path::parent)
        .context("145 semantic package")?
        .join("v5j-name-handoff");
    let (selected, report) = publication::frozen_json(&handoff.join("semantic-completion.json"))?;
    let (_, submission) = publication::frozen_json(&handoff.join("submission-result.json"))?;
    let (_, intent) = publication::frozen_json(&handoff.join("submission-intent.json"))?;
    let old = "afcf6cdd1ec0400ea2757f81472987b3";
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
