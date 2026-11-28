//! Fresh fetched branch containment plus exact source and artifact bindings.
use super::*;
pub(super) fn validate(n: &mut Native, proof: &Value, guard: &Bound, self_sha: &str) -> Result<()> {
    ensure!(
        proof["schema"] == "horizon265-source-publication-v1"
            && proof["remote_ref"] == "refs/heads/account-updates",
        "source publication schema/ref"
    );
    fresh(num(proof, "fetched_unix_seconds")?, now()?, 1800)?;
    let head = text(proof, "remote_head")?;
    ensure!(hex(head, 40), "source head");
    let git = |n: &mut Native, args: &[&str]| -> Result<Vec<u8>> {
        let mut argv = vec![
            "-c",
            "safe.directory=/home/ubuntu/workspace/jetstreamer",
            "-C",
            "/home/ubuntu/workspace/jetstreamer",
        ];
        argv.extend_from_slice(args);
        n.run("/usr/bin/git", &argv)
    };
    ensure!(
        std::str::from_utf8(&git(
            n,
            &["rev-parse", "refs/remotes/origin/account-updates"]
        )?)?
        .trim()
            == head,
        "fetched head changed"
    );
    for k in [
        "all_required_dependencies_in_remote",
        "exact_deployed_source_provenance_reviewed",
        "no_untracked_required_source",
    ] {
        ensure!(proof[k] == true, "missing publication review {k}");
    }
    let artifacts = proof["artifacts"]
        .as_array()
        .context("publication artifacts")?;
    let mut roles = BTreeSet::new();
    for r in artifacts {
        let role = text(r, "role")?;
        ensure!(roles.insert(role), "duplicate artifact role");
        let artifact = binding(&r["artifact"])?;
        artifact.artifact()?;
        let commit = text(r, "source_commit")?;
        ensure!(hex(commit, 40), "source commit");
        git(n, &["merge-base", "--is-ancestor", commit, head])?;
        let provenance = binding(&r["provenance"])?.sealed()?;
        ensure!(
            provenance["schema"] == "horizon265-exact-artifact-provenance-v1"
                && provenance["artifact"] == r["artifact"]
                && provenance["source_commit"] == commit
                && provenance["all_source_dependencies_enumerated"] == true,
            "artifact provenance missing/different"
        );
        let sources = provenance["source_files"]
            .as_array()
            .context("source files")?;
        ensure!(!sources.is_empty(), "empty source provenance");
        let mut seen = BTreeSet::new();
        for source in sources {
            let path = text(source, "repository_path")?;
            ensure!(
                !path.starts_with('/') && !path.split('/').any(|s| s == "..") && seen.insert(path),
                "unsafe/duplicate source path"
            );
            let bytes = git(n, &["show", &format!("{commit}:{path}")])?;
            ensure!(
                digest(&bytes) == text(source, "sha256")?,
                "committed source differs from artifact input"
            );
        }
        match role {
            "node" => ensure!(artifact == Bound::new(NODE, NODE_SHA), "node role mismatch"),
            "guard" => ensure!(&artifact == guard, "guard role mismatch"),
            "sealer" => ensure!(
                artifact == Bound::new(SEALER, SEALER_SHA),
                "sealer role mismatch"
            ),
            "launcher" => ensure!(
                artifact.path == fs::canonicalize("/proc/self/exe")? && artifact.sha256 == self_sha,
                "launcher role mismatch"
            ),
            "worker" => ensure!(
                artifact
                    == Bound::new(
                        WORKER,
                        "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4"
                    ),
                "worker role mismatch"
            ),
            "fleet" | "observer" | "inactive-status" | "delivery" | "input-packet" => (),
            _ => bail!("unregistered source artifact role {role}"),
        }
    }
    ensure!(
        roles
            == BTreeSet::from([
                "node",
                "worker",
                "delivery",
                "input-packet",
                "guard",
                "sealer",
                "launcher",
                "fleet",
                "observer",
                "inactive-status"
            ]),
        "incomplete source role coverage"
    );
    Ok(())
}
