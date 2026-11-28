use crate::{
    pin,
    scope::{Inputs, git_status},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

const EXAMPLE: &str = "jetstreamer-horizon/examples/compare_first_bucket.rs";
const EXAMPLE_BLOB: &str = "c609fd27b80d3a2b5a7e70a9f30d211642dd2b9f";
const REVIEWED: &str = "960f5c7f21697f2036a166602db4ab2b4382d44f";
const HEAD: &str = "refs/remotes/origin/account-updates";
const PREP: &str =
    "/home/sol/.jetstreamer-private/epoch168-publication-preparation-20261128.oG1BHix1/evidence";

fn reviewed_change(diff: &str) -> Result<()> {
    let expected = format!(
        ":000000 100644 {} {EXAMPLE_BLOB} A\t{EXAMPLE}",
        "0".repeat(40)
    );
    ensure!(
        diff == expected,
        "reader difference exceeds the reviewed standalone example"
    );
    Ok(())
}

pub fn review(tip: &str, inputs: &Inputs) -> Result<Value> {
    ensure!(
        tip.len() == 40
            && tip.bytes().all(|c| c.is_ascii_hexdigit())
            && git_status(&["rev-parse", HEAD])? == tip,
        "expected the current fetched account-updates tip"
    );
    let review = pin(
        Path::new(PREP).join("SOURCE_EQUIVALENCE.json"),
        "c24c95dcb4fbd527070ea8558d398abb11c8415a803103bbcb8eaf6d41565190",
    );
    let source = review.json()?;
    let build = crate::custody::reference(&source, "build_evidence")?;
    let actual = build.json()?;
    let manifest = &inputs.scope.reader_equivalence;
    let recorded = manifest.json()?;
    ensure!(
        source["fetched_commit"] == REVIEWED
            && source["reader_manifest"] == json!(manifest)
            && source["changed_reader_compiled_paths"] == json!([])
            && source["uncompiled_conservative_scope_differences"][EXAMPLE] == EXAMPLE_BLOB
            && !actual["compiled_inputs"]
                .as_object()
                .context("compiler depfiles")?
                .contains_key(EXAMPLE)
            && source["package"] == json!(inputs.scope.package),
        "wrong build or example review"
    );
    let rebased = pin(
        Path::new(PREP).join("current-reader-main-acceptance.json"),
        "5a1ce320a88c1c5d228e151252c6a9ce5fc8663bb9be13ca847303e6bb0e723e",
    );
    let q = rebased.json()?;
    ensure!(
        q["reader_commit"] == REVIEWED
            && q["pipeline"] == json!(inputs.pipeline)
            && q["full_verifier"] == json!(inputs.verifier)
            && q["source_artifact_correspondence_accepted"] == true
            && q["minimum_thread_stack_bytes"] == 67108864
            && git_status(&["remote", "get-url", "origin"])?
                == source["origin"].as_str().context("recorded origin")?,
        "changed reader artifacts or origin"
    );
    git_status(&["merge-base", "--is-ancestor", REVIEWED, tip])?;
    let original = recorded["original_commit"]
        .as_str()
        .context("original source commit")?;
    git_status(&["merge-base", "--is-ancestor", original, REVIEWED])?;
    let scopes = recorded["compared_paths"]
        .as_array()
        .context("compiled paths and build inputs")?;
    let paths = scopes
        .iter()
        .map(|v| v.as_str().context("reader input"))
        .collect::<Result<Vec<_>>>()?;
    let mut args = vec![
        "diff",
        "--raw",
        "--no-abbrev",
        "--no-renames",
        original,
        tip,
        "--",
    ];
    args.extend_from_slice(&paths);
    let delta = git_status(&args)?;
    reviewed_change(&delta)?;
    args[4] = REVIEWED;
    ensure!(
        git_status(&args)?.is_empty(),
        "source or build inputs changed after qualification"
    );
    ensure!(
        git_status(&["rev-parse", HEAD])? == tip,
        "account-updates changed during comparison"
    );
    Ok(
        json!({"tip":tip,"reader_manifest":manifest,"build":build,"original_review":review,
        "qualified_reader":rebased,"pipeline":inputs.pipeline,"full_verifier":inputs.verifier,
        "original_commit":original,"compiled_inputs":recorded["compiled_file_count"],"original_difference":delta,
        "post_qualification_differences":[],"private_source_check":true,"publication_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_reviewed_example_blob_and_mode_can_differ() {
        let delta = format!(
            ":000000 100644 {} {EXAMPLE_BLOB} A\t{EXAMPLE}",
            "0".repeat(40)
        );
        assert!(reviewed_change(&delta).is_ok());
        for d in [
            "".to_owned(),
            delta.replace("100644", "100755"),
            delta.replace(EXAMPLE_BLOB, &"e".repeat(40)),
            format!("{delta}\n{delta}"),
            delta.replace(EXAMPLE, "src/bin/horizon_pipeline.rs"),
        ] {
            assert!(reviewed_change(&d).is_err());
        }
    }
}
