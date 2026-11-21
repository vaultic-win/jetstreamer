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
