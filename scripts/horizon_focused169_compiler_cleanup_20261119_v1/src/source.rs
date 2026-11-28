use super::*;
const BASE: &str = "01a0ef21d311c5094f7395b4d38ec434bed9cc0f";
const BASE_TREE: &str = "81bef707dc6eeee32b26309d155104e94c1fef7b";
const PUBLISHED_LINEAGE: &str = "9498953f33500675a7203c0f73cd6836a9f63f49";
const REBASE_DELTA: &str = "723eb0aa923d134fe733b37bd5e9ce3dbe4160aa130198963ab312b8632b5377";
const PATCH: &str = "cea888c75ff1c2c14e77a02289056f23e0574f421c2c47a4d01dac24935c0c39";
const SOURCE_SEAL: &str = "/usr/local/lib/jetstreamer/horizon-epoch169-focused-source-20261118-v2";
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
fn sealed(path: &Path, expected: &str) -> Result<Value> {
    let (digest, m) = hash_file(path, 2 << 20)?;
    ensure!(
        digest == expected && m.uid() == 0 && m.mode() & 0o222 == 0,
        "sealed source provenance changed"
    );
    Ok(json!({"path":path,"sha256":digest,"identity":evidence::identity(&m)}))
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
            && proof["tests_passed"] == 31
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
    let paths = String::from_utf8(git(REPO, &["ls-files", "--", PACKAGE])?)?;
    let mut actual = BTreeMap::new();
    for path in paths.lines() {
        let bytes = fs::read(Path::new(REPO).join(path))?;
        ensure!(
            bytes.len() <= 2 << 20 && git(REPO, &["show", &format!("HEAD:{path}")])? == bytes,
            "deployed source no longer committed"
        );
        actual.insert(path.to_owned(), sha(&bytes));
    }
    ensure!(
        actual.len() >= 9 && proof["sources"] == json!(actual),
        "exact artifact source closure differs"
    );
    Ok(
        json!({"artifact_proof_sha256":proof_sha,"deployment_seal_sha256":seal_sha,"production_sha256":image,"sources":actual}),
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
    ensure!(
        git(
            REPO,
            &[
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--",
                PACKAGE
            ]
        )?
        .is_empty(),
        "cleanup source not committed"
    );
    let lock = hash_file(&Path::new(REPO).join("Cargo.lock"), 16 << 20)?;
    ensure!(
        lock.0 == p.cargo_lock_sha256,
        "workspace reproduction lock differs"
    );
    ensure!(
        git(REPO, &["show", "HEAD:Cargo.lock"])? == fs::read(Path::new(REPO).join("Cargo.lock"))?,
        "workspace Cargo.lock not committed"
    );
    ensure!(
        git(FIXTURE, &["rev-parse", "HEAD"])? == format!("{BASE}\n").as_bytes(),
        "fixture base differs"
    );
    git(
        REPO,
        &[
            "merge-base",
            "--is-ancestor",
            PUBLISHED_LINEAGE,
            "origin/account-updates",
        ],
    )?;
    // This is reproduction of a retained historical test cache, not admission
    // of its fixture as current production code. Preserve the exact old tree
    // and patch. Bind the published rebased lineage and its entire observed
    // delta; never silently call the two different source trees identical.
    ensure!(
        git(FIXTURE, &["rev-parse", &format!("{BASE}^{{tree}}")])?
            == format!("{BASE_TREE}\n").as_bytes()
            && sha(&git(
                REPO,
                &["diff", "--no-ext-diff", "--binary", BASE, PUBLISHED_LINEAGE]
            )?) == REBASE_DELTA,
        "retained fixture tree or published rebase delta differs"
    );
    let patch = git(FIXTURE, &["diff", "--no-ext-diff", "--binary", "HEAD"])?;
    ensure!(
        sha(&patch) == PATCH,
        "fixture differs from retained source patch"
    );
    ensure!(
        git(FIXTURE, &["ls-files", "--others", "--exclude-standard"])?.is_empty(),
        "untracked fixture source"
    );
    let mut locks = vec![];
    for (rel, digest) in [
        (
            "Cargo.lock",
            "d4da280a40a29b75ada6d1fdfc14759d75b4ca28d6a40b10a9179e0da3777614",
        ),
        (
            "historical-runtime/v1_4_25/Cargo.lock",
            "039f82f6f484f133fec7c7acd561ed46feee81ec9bdae0f589a37c23c8d40998",
        ),
        (
            "historical-runtime/v1_5_8/Cargo.lock",
            "0272e05559084d266b4be54394a1f6f28e9a70cfc27356ac79cd8fee4eb5609e",
        ),
    ] {
        let path = Path::new(FIXTURE).join(rel);
        let (got, md) = hash_file(&path, 2 << 20)?;
        ensure!(
            got == digest && md.uid() == 1001 && md.gid() == 1001 && md.mode() & 0o7002 == 0,
            "fixture lock custody differs"
        );
        locks.push(json!({"path":path,"sha256":got,"identity":evidence::identity(&md)}));
    }
    let patch_proof = sealed(
        &Path::new(SOURCE_SEAL).join("EPOCH169-FOCUSED-SOURCE.patch"),
        PATCH,
    )?;
    let basis = sealed(
        &Path::new(SOURCE_SEAL).join("EPOCH169-SOURCE-BASIS.json"),
        "6ff767eccc7c3c3ff0d76e0495b58829977af3fd93b7a74e85bcdb09e95efae0",
    )?;
    let deployed = deployment(p)?;
    Ok(
        json!({"cleanup_source_commit":p.source_commit,"deployment":deployed,"workspace_lock_sha256":lock.0,"workspace_lock_identity":evidence::identity(&lock.1),"fixture_base":BASE,"fixture_base_tree":BASE_TREE,"published_rebased_lineage":PUBLISHED_LINEAGE,"rebase_delta_sha256":REBASE_DELTA,"fixture_admission_authorized":false,"fixture_diff_sha256":PATCH,"fixture_locks":locks,"retained_source_patch":patch_proof,"retained_source_basis":basis}),
    )
}
