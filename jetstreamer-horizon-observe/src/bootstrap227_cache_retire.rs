//! One-case retirement of a redundant compressed input, not a replay artifact.
//! The independent immutable package, acquisition receipt and capability remain.
use {
    crate::{
        dev_cache_check, process_references,
        ram_artifact_retention::{self as evidence, Bound},
    },
    anyhow::{Context, Result, ensure},
    serde_json::{Value, json},
    std::{
        collections::BTreeSet,
        env,
        fs::{self, File, OpenOptions},
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
    },
};
const NAME: &str = "snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst";
const CACHE_ROOT: &str =
    "/var/lib/jetstreamer/horizon-bootstrap227-compressed-stage-v1/attempt-045716-v1";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon-bootstrap227-cache-retirement-v1";
const UNIT: &str = "horizon-bootstrap227-transfer-045716-v2.service";
const IID: &str = "619ef291b26244e2b4d53901c84cc86d";
const SHA: &str = "77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07";
const SIZE: u64 = 10_261_480_487;
const ACQUISITION_SHA: &str = "0a20b1881dfc6103171a6c236019b25be54972491345f07eac688a542ec8b284";
const SEAL_SHA: &str = "31ef0b2c10b02e6e66d1e30a9bbdb38dd5ceabb9cc4b673e8de1bc85e1100ccd";
const SUMS_SHA: &str = "e0896d85d55239ac12075a353ff13a08897e608d6e0c449de6d3eaa33299858b";
const CAPABILITY: &str =
    "/var/lib/jetstreamer/horizon-stage227-bootstrap-capability-0538-v1/capability.json";
const CAPABILITY_SHA: &str = "e0a768f31956567536f8a66a55fa94794815e678ebcf7e85c72a180f88ab2d36";

pub(crate) fn bound(path: PathBuf, sha256: &str) -> Bound {
    Bound {
        path,
        sha256: sha256.into(),
    }
}
pub(crate) fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
pub(crate) fn absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
pub(crate) fn available_bytes() -> Result<u64> {
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c"/var/lib/jetstreamer".as_ptr(), stat.as_mut_ptr()) } == 0,
        "free-space read failed"
    );
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .context("free-space overflow")
}
pub(crate) fn private_dir(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path && m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "unsafe private receipt/cache directory"
    );
    Ok(())
}
pub(crate) fn persist(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    private_dir(parent)?;
    let mut f = tempfile::NamedTempFile::new_in(parent)?;
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer(&mut f, value)?;
    f.write_all(b"\n")?;
    f.as_file().sync_all()?;
    f.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("occupied receipt: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn validate_acquisition(a: &Value, cache: &Path) -> Result<()> {
    ensure!(
        a["schema"] == "horizon-epoch227-bootstrap-prepared-v1"
            && a["epoch"] == 227
            && a["path"].as_str() == cache.to_str()
            && a["generation"] == "1632781197930817"
            && a["size"] == SIZE
            && a["sha256"] == SHA
            && a["crc32c_base64"] == "1B+EYQ=="
            && a["md5_base64"] == "OZLsTULdemOCogrGldWj5Q=="
            && a["invocation_id"] == IID
            && a["compressed_input_verified"] == true
            && a["uri"]
                == format!("gs://mainnet-beta-ledger-us-ny5/98063464/{NAME}#1632781197930817"),
        "wrong exact acquisition"
    );
    for flag in [
        "native_restore_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(a[flag] == false, "acquisition has unexpected authority");
    }
    Ok(())
}
fn validate_capability(c: &Value) -> Result<()> {
    ensure!(
        c["schema"] == "jetstreamer-private-epoch227-sealed-bootstrap-node-capability-v1"
            && c["epoch"] == 227
            && c["package"] == PACKAGE
            && c["package_seal_receipt_sha256"] == SEAL_SHA
            && c["package_sha256sums_sha256"] == SUMS_SHA
            && c["assurance_scope"]["exact_new_package_cli_cache_argument_and_manifest_decode_gates_passed"]
                == true
            && c["assurance_scope"]["prior_full_snapshot_verification_sha256"] == ACQUISITION_SHA
            && c["probes"]["fingerprint"]["matched"] == true
            && c["probes"]["schema"]["matched"] == true,
        "new-package capability gate missing"
    );
    for flag in [
        "resource_admission_passed",
        "full_peak_qualified",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(c[flag] == false, "capability scope changed");
    }
    Ok(())
}
fn owner_state() -> Result<Value> {
    let p = evidence::properties(
        UNIT,
        "Id,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,Result,ExecMainStatus,RemainAfterExit,Type,FragmentPath",
    )?;
    for (k, v) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("MainPID", "0"),
        ("InvocationID", IID),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("RemainAfterExit", "yes"),
        ("Type", "exec"),
    ] {
        ensure!(
            p.get(k).map(String::as_str) == Some(v),
            "terminal acquisition owner changed: {k}"
        );
    }
    ensure!(
        p.get("FragmentPath").map(String::as_str)
            == Some("/run/systemd/transient/horizon-bootstrap227-transfer-045716-v2.service"),
        "wrong terminal owner fragment"
    );
    Ok(serde_json::to_value(p)?)
}
fn package_proof() -> Result<Value> {
    let package = Path::new(PACKAGE);
    let m = fs::symlink_metadata(package)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o222 == 0 && package.canonicalize()? == package,
        "mutable package"
    );
    let seal = evidence::bound_json(&bound(
        package.join("deployment-seal-receipt.json"),
        SEAL_SHA,
    ))?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == PACKAGE,
        "wrong package seal"
    );
    let (sum_sha, sums) = evidence::hash_file(&package.join("SHA256SUMS"), 65536)?;
    ensure!(
        sum_sha == SUMS_SHA && sums.uid() == 0 && sums.mode() & 0o222 == 0,
        "package sums changed"
    );
    let members = seal["members"].as_array().context("missing seal members")?;
    ensure!(members.len() == 6, "wrong member census");
    let mut names = BTreeSet::from([
        "SHA256SUMS".to_string(),
        "deployment-seal-receipt.json".to_string(),
    ]);
    let mut proof = Vec::new();
    for member in members {
        let name = member["name"].as_str().context("member name")?;
        ensure!(
            !name.is_empty()
                && !name.contains('/')
                && !matches!(name, "." | "..")
                && names.insert(name.into()),
            "unsafe/duplicate member"
        );
        let (sha, m) = evidence::hash_file(&package.join(name), SIZE)?;
        ensure!(
            sha == member["sha256"]
                && m.len() == member["bytes"]
                && m.uid() == 0
                && m.mode() & 0o222 == 0,
            "package member mismatch"
        );
        proof.push(json!({"name":name,"sha256":sha,"identity":identity(&m)}));
    }
    let actual = fs::read_dir(package)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("nonUTF8 member"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        actual == names && names.contains(NAME),
        "package member set mismatch"
    );
    Ok(json!(proof))
}
fn prove(cache_required: bool) -> Result<Value> {
    let cache = Path::new(CACHE_ROOT).join(NAME);
    private_dir(Path::new(CACHE_ROOT))?;
    let owner = owner_state()?;
    let acquisition = evidence::bound_json(&bound(
        Path::new(PACKAGE).join("bootstrap-prepared.json"),
        ACQUISITION_SHA,
    ))?;
    validate_acquisition(&acquisition, &cache)?;
    let capability = evidence::bound_json(&bound(CAPABILITY.into(), CAPABILITY_SHA))?;
    validate_capability(&capability)?;
    let package = package_proof()?;
    let (_, copy) = evidence::hash_file(&Path::new(PACKAGE).join(NAME), SIZE)?;
    ensure!(copy.len() == SIZE, "copy size differs");
    let mut physical_bytes = 0;
    let cache_identity = if !absent(&cache)? {
        let (sha, m) = evidence::hash_file(&cache, SIZE)?;
        ensure!(
            sha == SHA
                && m.len() == SIZE
                && m.uid() == 0
                && m.mode() & 0o7777 == 0o400
                && identity(&m) == acquisition["file_identity"]
                && (m.dev(), m.ino()) != (copy.dev(), copy.ino()),
            "cache identity/content differs"
        );
        physical_bytes = m
            .blocks()
            .checked_mul(512)
            .context("cache blocks overflow")?;
        identity(&m)
    } else {
        ensure!(!cache_required, "cache absent without retirement intent");
        Value::Null
    };
    let scan = process_references::scan(Path::new("/proc"), &cache)?;
    ensure!(
        scan.references.is_empty(),
        "live process references: {:?}",
        scan.references
    );
    let mut missing = Vec::new();
    let staged = dev_cache_check::staged_references_exact(
        &[
            Path::new("/etc/systemd/system"),
            Path::new("/run/systemd/system"),
            Path::new("/run/systemd/transient"),
        ],
        &cache,
        &mut missing,
        &BTreeSet::new(),
    )?;
    ensure!(staged.is_empty(), "staged cache references: {staged:?}");
    ensure!(owner_state()? == owner, "owner changed during proof");
    Ok(
        json!({"cache":cache,"cache_identity":cache_identity,"cache_physical_bytes":physical_bytes,"filesystem_available_bytes":available_bytes()?,"preserved_copy":Path::new(PACKAGE).join(NAME),"preserved_identity":identity(&copy),"package":package,"acquisition_sha256":ACQUISITION_SHA,"capability_sha256":CAPABILITY_SHA,"owner":owner,"process_scan":scan,"staged_references":staged,"missing_unit_aliases":missing}),
    )
}
pub(crate) fn lock(root: &Path) -> Result<File> {
    private_dir(root)?;
    let p = root.join("retirement.lock");
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o077 == 0,
        "unsafe retirement lock"
    );
    ensure!(
        unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&f),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } == 0,
        "retirement already owned"
    );
    Ok(f)
}
pub(crate) fn unlink_exact(
    cache: &Path,
    expected: &Value,
    preserved: &Path,
    preserved_identity: &Value,
) -> Result<()> {
    ensure!(
        identity(&fs::symlink_metadata(cache)?) == *expected,
        "cache changed before unlink"
    );
    ensure!(
        identity(&fs::symlink_metadata(preserved)?) == *preserved_identity,
        "preserved copy changed before unlink"
    );
    fs::remove_file(cache)?;
    File::open(cache.parent().context("cache parent")?)?.sync_all()?;
    ensure!(
        absent(cache)? && identity(&fs::symlink_metadata(preserved)?) == *preserved_identity,
        "retirement postcondition differs"
    );
    Ok(())
}
pub fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(
        matches!(args.len(), 2 | 3),
        "usage: BIN SELF_SHA256 --check-only | BIN SELF_SHA256 --retire CHECK_SHA256"
    );
    let self_path = fs::read_link("/proc/self/exe")?;
    let (self_sha, m) = evidence::hash_file(&self_path, 256 << 20)?;
    ensure!(
        self_sha == args[0]
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && identity(&m) == identity(&fs::metadata("/proc/self/exe")?),
        "unsealed/wrong executable"
    );
    let root = Path::new(RECEIPTS);
    let _lock = lock(root)?;
    let check = root.join("check.json");
    let intent = root.join("intent.json");
    let completion = root.join("completion.json");
    ensure!(absent(&completion)?, "retirement already complete");
    if args[1] == "--check-only" && args.len() == 2 {
        ensure!(absent(&intent)?, "retirement intent already exists");
        let proof = prove(true)?;
        persist(
            &check,
            &json!({"schema":"jetstreamer-bootstrap227-cache-retire-check-v1","self_sha256":self_sha,"proof":proof,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
        println!("{}", check.display());
        return Ok(());
    }
    ensure!(args[1] == "--retire" && args.len() == 3, "unsupported mode");
    let prior = evidence::bound_json(&bound(check.clone(), &args[2]))?;
    ensure!(
        prior["schema"] == "jetstreamer-bootstrap227-cache-retire-check-v1"
            && prior["self_sha256"] == self_sha,
        "wrong preflight"
    );
    let has_intent = !absent(&intent)?;
    let proof = prove(!has_intent)?;
    let auth = json!({"schema":"jetstreamer-bootstrap227-cache-retire-intent-v1","self_sha256":self_sha,"check_sha256":args[2],"cache":prior["proof"]["cache"],"cache_identity":prior["proof"]["cache_identity"],"preserved_identity":prior["proof"]["preserved_identity"],"acquisition_sha256":ACQUISITION_SHA,"capability_sha256":CAPABILITY_SHA});
    ensure!(
        proof["preserved_identity"] == prior["proof"]["preserved_identity"],
        "preserved identity differs from preflight"
    );
    if has_intent {
        let (sha, _) = evidence::hash_file(&intent, 1 << 20)?;
        ensure!(
            evidence::bound_json(&bound(intent.clone(), &sha))? == auth,
            "foreign/inconsistent intent"
        );
    } else {
        persist(&intent, &auth)?;
    }
    let cache = Path::new(CACHE_ROOT).join(NAME);
    if !absent(&cache)? {
        ensure!(
            proof["cache_identity"] == prior["proof"]["cache_identity"],
            "cache changed after preflight"
        );
        unlink_exact(
            &cache,
            &proof["cache_identity"],
            &Path::new(PACKAGE).join(NAME),
            &proof["preserved_identity"],
        )?;
    }
    persist(
        &completion,
        &json!({"schema":"jetstreamer-bootstrap227-cache-retired-v1","self_sha256":self_sha,"check_sha256":args[2],"intent":auth,"proof":proof,"cache_absent":absent(&cache)?,"retired_cache_bytes":SIZE,"filesystem_available_bytes_after":available_bytes()?,"preserved_copy_unchanged":true,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("{}", completion.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_acquisition_never_authorizes_retirement() {
        let cache = Path::new(CACHE_ROOT).join(NAME);
        let a = json!({"schema":"horizon-epoch227-bootstrap-prepared-v1","epoch":227,"path":cache,"generation":"1632781197930817","size":SIZE,"sha256":SHA,"crc32c_base64":"1B+EYQ==","md5_base64":"OZLsTULdemOCogrGldWj5Q==","invocation_id":IID,"compressed_input_verified":true,"uri":format!("gs://mainnet-beta-ledger-us-ny5/98063464/{NAME}#1632781197930817"),"native_restore_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        validate_acquisition(&a, &cache).unwrap();
        for (key, val) in [
            ("epoch", json!(205)),
            ("generation", json!("wrong")),
            ("size", json!(SIZE - 1)),
            ("sha256", json!("0".repeat(64))),
            ("invocation_id", json!("other")),
            ("compressed_input_verified", json!(false)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = a.clone();
            bad[key] = val;
            assert!(validate_acquisition(&bad, &cache).is_err(), "{key}");
        }
        assert!(validate_acquisition(&a, Path::new("/other")).is_err());
    }
    #[test]
    fn capability_is_separately_required_and_never_launch_authority() {
        let c = json!({"schema":"jetstreamer-private-epoch227-sealed-bootstrap-node-capability-v1","epoch":227,"package":PACKAGE,"package_seal_receipt_sha256":SEAL_SHA,"package_sha256sums_sha256":SUMS_SHA,"assurance_scope":{"exact_new_package_cli_cache_argument_and_manifest_decode_gates_passed":true,"prior_full_snapshot_verification_sha256":ACQUISITION_SHA},"probes":{"fingerprint":{"matched":true},"schema":{"matched":true}},"resource_admission_passed":false,"full_peak_qualified":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        validate_capability(&c).unwrap();
        for key in [
            "epoch",
            "package",
            "package_seal_receipt_sha256",
            "probes",
            "assurance_scope",
            "replay_launch_authorized",
        ] {
            let mut bad = c.clone();
            bad[key] = Value::Null;
            assert!(validate_capability(&bad).is_err(), "{key}");
        }
    }
    #[test]
    fn exact_unlink_preserves_independent_copy_and_rejects_changed_identity() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let copy = root.path().join("copy");
        fs::write(&cache, b"same").unwrap();
        fs::write(&copy, b"same").unwrap();
        let ci = identity(&fs::symlink_metadata(&cache).unwrap());
        let pi = identity(&fs::symlink_metadata(&copy).unwrap());
        assert!(unlink_exact(&cache, &Value::Null, &copy, &pi).is_err());
        assert!(cache.exists());
        assert!(unlink_exact(&cache, &ci, &copy, &Value::Null).is_err());
        assert!(cache.exists());
        unlink_exact(&cache, &ci, &copy, &pi).unwrap();
        assert!(!cache.exists());
        assert_eq!(fs::read(copy).unwrap(), b"same");
    }
    #[test]
    fn absent_distinguishes_symlink_from_missing() {
        let root = tempfile::tempdir().unwrap();
        let p = root.path().join("missing");
        assert!(absent(&p).unwrap());
        std::os::unix::fs::symlink("/nonexistent", &p).unwrap();
        assert!(!absent(&p).unwrap());
    }

    #[test]
    fn hashing_rejects_symlink_hardlink_and_changed_cache_content() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("cache");
        let alias = root.path().join("alias");
        fs::write(&file, b"same").unwrap();
        std::os::unix::fs::symlink(&file, &alias).unwrap();
        assert!(evidence::hash_file(&alias, 10).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&file, &alias).unwrap();
        assert!(evidence::hash_file(&file, 10).is_err());
        fs::remove_file(&alias).unwrap();
        let old = identity(&fs::symlink_metadata(&file).unwrap());
        fs::write(&file, b"different").unwrap();
        let copy = root.path().join("copy");
        fs::write(&copy, b"same").unwrap();
        let preserved = identity(&fs::symlink_metadata(&copy).unwrap());
        assert!(unlink_exact(&file, &old, &copy, &preserved).is_err());
        assert!(file.exists() && copy.exists());
    }
}
