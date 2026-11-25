//! Select a qualified archive reader from the fetched publication branch.
use super::*;
use std::process::{Output, Stdio};

const REPO: &str = "/home/sol/workspace/jetstreamer";
const ORIGIN: &str = "git@github-matt-vaultic:vaultic-win/jetstreamer.git";
const BRANCH: &str = "refs/remotes/origin/account-updates";
pub(super) const PREVIOUS_PATH: &str =
    "epoch166-retry10-delivery-20261121-v1/qualified-reader/qualification.json";
pub(super) const PREVIOUS_SHA: &str =
    "89dba1fa9e7d73581e0c1e81ef2d12a8c7bd9bc98f4259943f79caa6197a9486";
const PREVIOUS: &str = "907c5b3c26837c75c5c62f76bb124ff4fd8fe642";
const RECONNECT: &str = "eba5d1b596cd454811c466fde7a25a2ecb4b19ef";
const BOUNDED: &str = "58709604dfa4c97336c2e1f6fac53b862ed6f17f";
const HTTP_RETRY: &str = "e15f71a2a84c9f256c6fc3d5da34e9354430e702";
const HTTP_RETRY_PACKAGE: &str = "ready-audit-http500-candidate-e15f71a2a84c-20261125-v1";
const HTTP_RETRY_SEAL_SHA: &str =
    "3fa6c503626b68fb91455aa8b2a117c5baedf7c65a08f09a96bc9b09c74fbaca";
pub(super) const HTTP_RETRY_READER_SHA: &str =
    "e932eb960f91977ee95707793d11c988be923184aec3f76dfbf42d31fdd32ac0";
const HTTP_RETRY_PAIR_SHA: &str =
    "55cc1f7e0decc7dd19ef57ec1346112e5d4e13a76674d0667646597379d6d33f";
const HTTP_RETRY_COMPARISON_SHA: &str =
    "ee5c719a81408c531f478c6aebc92cc1233f497c61aa6f3e88311321e56f2966";
const HTTP_RETRY_SCOPES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    ".cargo",
    "src",
    "jetstreamer-firehose",
    "jetstreamer-horizon",
    "jetstreamer-plugin",
    "jetstreamer-utils",
    "vendor",
    "build.rs",
    "rust-toolchain",
    "rust-toolchain.toml",
    "historical-runtime/v1_0_8/worker/src/poh_backend.rs",
];

fn git(args: &[&str]) -> Result<Output> {
    let owner = fs::metadata(REPO)?;
    Ok(Command::new("/usr/bin/git")
        .uid(owner.uid())
        .gid(owner.gid())
        .arg("-C")
        .arg(REPO)
        .args(args)
        .stdin(Stdio::null())
        .output()?)
}
fn checked(args: &[&str]) -> Result<String> {
    let out = git(args)?;
    ensure!(
        out.status.success(),
        "reader Git command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}
fn ancestor(commit: &str, head: &str) -> Result<bool> {
    let out = git(&["merge-base", "--is-ancestor", commit, head])?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => anyhow::bail!(
            "cannot resolve reader ancestry: {}",
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

fn http_retry_compatible(head: &str) -> Result<bool> {
    if !ancestor(HTTP_RETRY, head)? {
        return Ok(false);
    }
    let mut args = vec!["diff", "--quiet", "--no-ext-diff", HTTP_RETRY, head, "--"];
    args.extend(HTTP_RETRY_SCOPES);
    let diff = git(&args)?;
    match diff.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => anyhow::bail!(
            "cannot compare HTTP retry reader inputs: {}",
            String::from_utf8_lossy(&diff.stderr),
        ),
    }
}

pub(super) fn http_retry_pair(qpath: &Path, qualification: &Value) -> Result<Value> {
    let package = rt(HTTP_RETRY_PACKAGE);
    ensure!(
        qpath == package.join("qualification.json"),
        "wrong HTTP retry reader path"
    );
    let seal = document(
        &package.join("deployment-seal-receipt.json"),
        HTTP_RETRY_SEAL_SHA,
        false,
    )?;
    let members = seal["members"]
        .as_array()
        .context("HTTP retry deployment members")?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(package)
            && seal["publication_authorized"] == false
            && seal["r2_mutations"] == false
            && seal["remote_mutations"] == false
            && members.len() == 4,
        "different HTTP retry reader deployment"
    );
    for (name, digest) in [
        ("qualification.json", HTTP_RETRY_READER_SHA),
        ("ordinary-pair.json", HTTP_RETRY_PAIR_SHA),
        ("READER_INPUT_COMPARISON.json", HTTP_RETRY_COMPARISON_SHA),
    ] {
        ensure!(
            members
                .iter()
                .filter(|entry| entry["name"] == name
                    && entry["sha256"] == digest
                    && entry["mode"] == "0444")
                .count()
                == 1,
            "HTTP retry deployment member differs"
        );
    }
    let pair = document(
        &package.join("ordinary-pair.json"),
        HTTP_RETRY_PAIR_SHA,
        false,
    )?;
    let comparison_path = package.join("READER_INPUT_COMPARISON.json");
    let comparison = document(&comparison_path, HTTP_RETRY_COMPARISON_SHA, false)?;
    ensure!(
        qualification["schema"] == "horizon-current-reader-main-acceptance-v1"
            && qualification["reader_commit"] == HTTP_RETRY
            && qualification["source_artifact_correspondence_accepted"] == true
            && qualification["full_and_plugin_capabilities_accepted"] == true
            && qualification["minimum_thread_stack_bytes"] == 67_108_864
            && qualification["source_build_evidence"]
                .as_array()
                .is_some_and(|evidence| {
                    evidence.contains(
                        &json!({"path":comparison_path,"sha256":HTTP_RETRY_COMPARISON_SHA}),
                    )
                })
            && comparison["local_candidate_merge"] == HTTP_RETRY
            && comparison["changed_compiler_inputs"] == json!([])
            && comparison["qualified_binary"] == qualification["pipeline"]
            && pair["schema"] == "horizon-staged-ordinary-uploader-http-retry-pair-v1"
            && pair["local_candidate_merge"] == HTTP_RETRY
            && pair["qualification"] == json!({"path":qpath,"sha256":HTTP_RETRY_READER_SHA})
            && pair["pipeline"] == qualification["pipeline"]
            && pair["full_verifier"] == qualification["full_verifier"]
            && pair["uploader"] == json!({"path":rt(UPLOADER),"sha256":ELF})
            && pair["fixture_threads"] == 1
            && pair["fixture_slot_count"] == 432_000
            && pair["wrong_etag_refused"] == true
            && pair["archive_publication_authorized"] == false
            && pair["production_r2_mutations"] == false,
        "HTTP retry reader and ordinary uploader qualification differ"
    );
    Ok(pair)
}

pub(super) fn current() -> Result<(PathBuf, &'static str, Value)> {
    ensure!(
        checked(&["remote", "get-url", "origin"])? == ORIGIN,
        "reader repository origin changed"
    );
    #[cfg(not(publisher_fixture))]
    checked(&[
        "fetch",
        "origin",
        "refs/heads/account-updates:refs/remotes/origin/account-updates",
    ])?;
    let revision = BRANCH;
    #[cfg(publisher_fixture)]
    let fixture_revision = env::var("FIXTURE_READER_REVISION").ok();
    #[cfg(publisher_fixture)]
    let revision = fixture_revision.as_deref().unwrap_or(revision);
    let head = checked(&["rev-parse", "--verify", &format!("{revision}^{{commit}}")])?;
    ensure!(hex(&head, 40), "invalid fetched reader revision");
    ensure!(
        PROFILE.reader == PREVIOUS_PATH && PROFILE.reader_sha == PREVIOUS_SHA,
        "unqualified previous reader binding"
    );
    let forced_fixture =
        cfg!(publisher_fixture) && env::var_os("FIXTURE_QUALIFIED_READER").is_some();
    if !forced_fixture && http_retry_compatible(&head)? {
        let path = rt(HTTP_RETRY_PACKAGE).join("qualification.json");
        let qualified = document(&path, HTTP_RETRY_READER_SHA, false)?;
        return Ok((path, HTTP_RETRY_READER_SHA, qualified));
    }
    let release = if ancestor(BOUNDED, &head)? {
        BOUNDED
    } else if ancestor(RECONNECT, &head)? {
        RECONNECT
    } else {
        PREVIOUS
    };
    #[cfg(publisher_fixture)]
    let release = match env::var("FIXTURE_QUALIFIED_READER").as_deref() {
        Ok("previous") => PREVIOUS,
        Ok("candidate") => RECONNECT,
        Ok("bounded") => BOUNDED,
        Err(_) => release,
        _ => anyhow::bail!("unknown qualification fixture"),
    };
    let (path, digest, manifest) = match release {
        BOUNDED => (
            "fast-range-residency-20261121-v1/production-reader-v1/qualification.json",
            BOUNDED_READER_SHA,
            "sources.json",
        ),
        RECONNECT => (
            "public-rseek-reconnect-20261121-v1/production-reader-v1/qualification.json",
            "432f57f077e6b82632d3bae94b000bd9a42751c9a3bab7ee20cb69c3b73fd471",
            "source-members.json",
        ),
        _ => (PROFILE.reader, PROFILE.reader_sha, "sources.json"),
    };
    let path = rt(path);
    let qual = document(&path, digest, false)?;
    ensure!(
        qual["reader_commit"] == release && ancestor(release, &head)?,
        "reader revision is outside the publication branch"
    );
    let evidence = qual["source_build_evidence"]
        .as_array()
        .context("reader build evidence")?;
    let mut matching = evidence.iter().filter(|entry| {
        entry["path"]
            .as_str()
            .and_then(|p| Path::new(p).file_name())
            .is_some_and(|name| name == manifest)
    });
    let inputs = bound(matching.next().context("missing reader input manifest")?)?;
    ensure!(matching.next().is_none(), "ambiguous reader input manifest");
    let members = inputs["members"]
        .as_object()
        .context("reader source members")?;
    ensure!(
        members.contains_key("Cargo.lock")
            && members.contains_key("jetstreamer-firehose/src/firehose_horizon.rs")
            && members.iter().all(|(name, digest)| !name.is_empty()
                && Path::new(name)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)))
                && digest.as_str().is_some_and(|s| hex(s, 64))),
        "invalid qualified reader inputs"
    );
    let mut diff = vec![
        "diff",
        "--quiet",
        "--no-ext-diff",
        release,
        &head,
        "--",
        "historical-runtime/v1_0_8/worker/src/poh_backend.rs",
    ];
    diff.extend(members.keys().map(String::as_str));
    ensure!(
        git(&diff)?.status.success(),
        "qualified reader inputs differ from the publication branch"
    );
    Ok((path, digest, qual))
}
