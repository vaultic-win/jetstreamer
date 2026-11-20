//! Fresh fetched branch containment plus exact source and artifact bindings.
use super::*;
pub(super) fn validate(
    n: &mut Native,
    proof: &Value,
    guard: &Bound,
    self_sha: &str,
    prepare_only: bool,
) -> Result<()> {
    ensure!(
        proof["schema"] == "horizon-native257-source-publication-v1"
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
            provenance["schema"] == "horizon-native257-exact-artifact-provenance-v1"
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
            "harness" => ensure!(
                artifact == Bound::new(HARNESS, HARNESS_SHA),
                "harness role mismatch"
            ),
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
                artifact == Bound::new(WORKER, WORKER_SHA),
                "worker role mismatch"
            ),
            "fleet" | "observer" | "inactive-status" => (),
            _ => bail!("unregistered source artifact role {role}"),
        }
    }
    ensure!(
        (prepare_only && roles == BTreeSet::from(["harness", "guard", "launcher"]))
            || roles
                == BTreeSet::from([
                    "harness",
                    "worker",
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

/// A prepared unit binds its launcher, harness and guard. A later fetch can carry
/// new consumer proof while these exact executable/source tuples remain identical.
pub(super) fn prepared_artifacts(proof: &Value) -> Result<BTreeMap<String, Value>> {
    let mut pins = BTreeMap::new();
    for row in proof["artifacts"]
        .as_array()
        .context("publication artifact rows")?
    {
        let role = text(row, "role")?;
        if matches!(role, "launcher" | "guard" | "harness") {
            ensure!(pins.insert(role.to_owned(),json!({"artifact":binding(&row["artifact"])?,"source_commit":text(row,"source_commit")?})).is_none(),"duplicate prepared role");
        }
    }
    ensure!(pins.len() == 3, "missing prepared artifact role");
    Ok(pins)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_accepts_a_later_fetch_and_rejects_changed_executables() {
        let rows:Vec<_>=["harness","guard","launcher"].into_iter().map(|name|json!({"role":name,"artifact":Bound::new(format!("/var/lib/{name}"),"a".repeat(64)),"source_commit":"b".repeat(40)})).collect();
        let a = json!({"artifacts":rows,"remote_head":"1".repeat(40)});
        let mut b = a.clone();
        b["artifacts"].as_array_mut().unwrap().reverse();
        b["remote_head"] = json!("2".repeat(40));
        b["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"role":"observer"}));
        assert_eq!(
            prepared_artifacts(&a).unwrap(),
            prepared_artifacts(&b).unwrap()
        );
        b["artifacts"][1]["artifact"]["sha256"] = json!("c".repeat(64));
        assert_ne!(
            prepared_artifacts(&a).unwrap(),
            prepared_artifacts(&b).unwrap()
        );
    }
}
