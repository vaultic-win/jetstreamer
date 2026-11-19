use super::*;

// Current committed reproduction sources are retained. The original compiler
// cache revision is not inferred from current HEAD; fingerprints/depfiles survive.
const SOURCE_ROOTS: [&str; 5] = [
    "jetstreamer-r2",
    "jetstreamer-horizon-observe",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
];
pub(super) fn git(repo: &str, args: &[&str]) -> Result<Vec<u8>> {
    let o = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["-c", &format!("safe.directory={repo}"), "-C", repo])
        .args(args)
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 16 << 20,
        "source reproduction command failed"
    );
    Ok(o.stdout)
}
fn source_paths(roots: &[&str]) -> Result<Vec<String>> {
    let mut args = vec!["ls-files", "-z", "--"];
    args.extend_from_slice(roots);
    let bytes = git(REPO, &args)?;
    let mut paths = BTreeSet::new();
    for path in bytes.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let path = std::str::from_utf8(path)?;
        ensure!(
            !Path::new(path).is_absolute()
                && Path::new(path)
                    .components()
                    .all(|p| matches!(p, std::path::Component::Normal(_)))
                && paths.insert(path.to_owned()),
            "unsafe or duplicate tracked source path"
        );
    }
    ensure!(
        !paths.is_empty() && paths.len() <= 4096,
        "source path bound"
    );
    Ok(paths.into_iter().collect())
}
fn committed_sources(roots: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut args = vec!["status", "--porcelain", "--untracked-files=all", "--"];
    args.extend_from_slice(roots);
    ensure!(
        git(REPO, &args)?.is_empty(),
        "uncommitted reproduction source"
    );
    let mut sources = BTreeMap::new();
    let mut total = 0u64;
    for path in source_paths(roots)? {
        let full = Path::new(REPO).join(&path);
        ensure!(
            full.canonicalize()? == full && !TARGETS.iter().any(|t| full.starts_with(t.0)),
            "source aliases or overlaps selected output"
        );
        let (digest, md) = hash_file(&full, 16 << 20)?;
        total = total
            .checked_add(md.len())
            .context("source size overflow")?;
        ensure!(
            total <= 128 << 20 && md.uid() == 1001 && md.gid() == 1001 && md.mode() & 0o7002 == 0,
            "source custody or total size differs"
        );
        ensure!(
            sha(&git(REPO, &["show", &format!("HEAD:{path}")])?) == digest,
            "source differs from committed reproduction"
        );
        sources.insert(path, digest);
    }
    Ok(sources)
}
fn deployment(p: &Plan) -> Result<Value> {
    let root = Path::new(IMAGE).parent().context("deployment directory")?;
    let proof_path = root.join("artifact-proof.json");
    let (proof_sha, proof_md) = hash_file(&proof_path, 2 << 20)?;
    ensure!(
        proof_md.uid() == 0 && proof_md.mode() & 0o222 == 0,
        "mutable artifact proof"
    );
    let proof = bound_json(&Bound {
        path: proof_path,
        sha256: proof_sha.clone(),
    })?;
    let seal_path = root.join("deployment-seal-receipt.json");
    let (seal_sha, seal_md) = hash_file(&seal_path, 2 << 20)?;
    ensure!(
        seal_md.uid() == 0 && seal_md.mode() & 0o222 == 0,
        "mutable deployment seal"
    );
    let seal = bound_json(&Bound {
        path: seal_path,
        sha256: seal_sha.clone(),
    })?;
    let image = hash_file(Path::new(IMAGE), 32 << 20)?.0;
    ensure!(
        proof["source_commit"] == p.source_commit
            && proof["production_sha256"] == image
            && proof["tests_passed"] == 38
            && proof["clippy_all_targets_passed"] == true,
        "artifact provenance differs"
    );
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(root)
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|m| m["name"] == "cleanup" && m["sha256"] == image && m["mode"] == "0555")
                && rows.iter().any(|m| m["name"] == "artifact-proof.json"
                    && m["sha256"] == proof_sha
                    && m["mode"] == "0444")),
        "normal deployment seal differs"
    );
    let sources = committed_sources(&[PACKAGE])?;
    ensure!(
        sources.len() >= 10 && proof["sources"] == json!(sources),
        "exact artifact source closure differs"
    );
    Ok(
        json!({"artifact_proof_sha256":proof_sha,"deployment_seal_sha256":seal_sha,"production_sha256":image,"sources":sources}),
    )
}
pub(super) fn proof(p: &Plan) -> Result<Value> {
    ensure!(
        git(REPO, &["rev-parse", "HEAD"])? == format!("{}\n", p.source_commit).as_bytes(),
        "current cleanup source revision differs"
    );
    git(
        REPO,
        &[
            "merge-base",
            "--is-ancestor",
            &p.source_commit,
            "origin/account-updates",
        ],
    )?;
    let sources = committed_sources(&SOURCE_ROOTS)?;
    ensure!(
        sources.get("Cargo.lock") == Some(&p.cargo_lock_sha256),
        "workspace lock differs"
    );
    let sealed =
        "/usr/local/lib/jetstreamer/horizon-holding169-retirement-20261119-v1/jetstreamer-r2";
    let (sealed_sha, md) = hash_file(Path::new(sealed), 256 << 20)?;
    ensure!(
        sealed_sha == "21626fcb1f2b5ca43ef678d4a19e1409b87db40cb5ee3cae33da2614904e9296"
            && md.uid() == 0
            && md.mode() & 0o222 == 0,
        "retained sealed image changed"
    );
    let top = Path::new("/tmp/holding141-target/debug/jetstreamer-r2");
    let top_md = fs::symlink_metadata(top)?;
    ensure!(
        top_md.is_file() && top_md.dev() == 2304 && top_md.ino() == 6714227 && top_md.nlink() == 2,
        "preserved working image changed"
    );
    let successor = "/usr/local/lib/jetstreamer/horizon-holding166-retry6-retirement-20261119-v1/jetstreamer-r2";
    let (successor_sha, successor_md) = hash_file(Path::new(successor), 256 << 20)?;
    ensure!(
        successor_sha == "cedb4ac0d62af1d2c9f7d90368348bbc094e6a12934c6b743f5c6bf82a18cf6d"
            && successor_md.uid() == 0
            && successor_md.mode() & 0o222 == 0
            && evidence::hash_working_image()?.0 == successor_sha,
        "working successor lacks its independent sealed copy"
    );
    let retained = json!({"sealed_image":sealed,"sealed_sha256":sealed_sha,"top_level_image":top,
        "sealed_successor":successor,"sealed_successor_sha256":successor_sha,
        "top_level_identity":evidence::identity(&top_md)});
    let deployed = deployment(p)?;
    Ok(
        json!({"cleanup_source_commit":p.source_commit,"deployment":deployed,
        "current_committed_reproduction_sources":sources,"retained_executable":retained,
        "original_cache_build_revision_claimed":false,"all_cached_dependency_manifests_and_fingerprints_preserved":true}),
    )
}
