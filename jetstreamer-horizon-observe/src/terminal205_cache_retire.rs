//! Fixed redundant compressed terminal-205 input lifecycle, never native restore.
use {
    crate::{
        bootstrap227_cache_retire::{
            absent, available_bytes, bound, identity, lock, persist, private_dir, unlink_exact,
        },
        dev_cache_check, process_references, ram_artifact_retention as evidence,
    },
    anyhow::{Context, Result, ensure},
    serde_json::{Value, json},
    std::{collections::BTreeSet, env, fs, os::unix::fs::MetadataExt, path::Path},
};
const NAME: &str = "snapshot-88991050-BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp.tar.zst";
const CACHE_ROOT: &str =
    "/var/lib/jetstreamer/horizon-terminal205-compressed-stage-v1/attempt-0743-v1";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-terminal205-input-e94ae66-v1";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon-terminal205-cache-retirement-v1";
const UNIT: &str = "horizon-terminal205-compressed-transfer-0743-v2.service";
const IID: &str = "0b04142f5357430b93f13ac51e3ad3e5";
const SHA: &str = "1b2a41f022847dc2ba9609e5a13aadc0e79b213b5245166b06954bf8c6d9042f";
const SIZE: u64 = 8_407_269_066;
const ACQUISITION_SHA: &str = "e77598aa1b1d732a160da33a68b95474afd012eeba2218c1036156095a9fd5d4";
const SEAL_SHA: &str = "39e2195becc258f5fd519d8a638a69d92db535c30728b00930353b292238d36b";
const SUMS_SHA: &str = "84d0b373551f7c10bd3733c81cc495cafd41e929f91d54fd813c3b67e3246918";
const PREPARATION: &str =
    "/var/lib/jetstreamer/horizon-native205-restore-prepared-d0780f0-v1/preparation.json";
const PREPARATION_SHA: &str = "0d0e3f475bde6badd7475b29efe68f361d39251afa2d1e16714be41353dc7daf";

fn validate_acquisition(a: &Value) -> Result<()> {
    ensure!(
        a["schema"] == "horizon-epoch205-terminal-snapshot-prepared-v1"
            && a["epoch"] == 205
            && a["path"].as_str() == Path::new(CACHE_ROOT).join(NAME).to_str()
            && a["generation"] == "1634790073611030"
            && a["size"] == SIZE
            && a["sha256"] == SHA
            && a["crc32c_base64"] == "9/mUyw=="
            && a["md5_base64"] == "fBpHLn3nugSP8+TvNmpB1Q=="
            && a["invocation_id"] == IID
            && a["compressed_input_verified"] == true
            && a["uri"]
                == format!("gs://mainnet-beta-ledger-us-ny5/88991050/{NAME}#1634790073611030"),
        "wrong terminal205 acquisition"
    );
    for f in [
        "native_restore_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(a[f] == false, "unexpected acquisition authority");
    }
    Ok(())
}
fn validate_preparation(p: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-private-epoch205-native-restore-preparation-v1"
            && p["epoch"] == 205
            && p["fixed_scope"]["snapshot"].as_str() == Path::new(PACKAGE).join(NAME).to_str()
            && p["fixed_scope"]["snapshot_sha256"] == SHA
            && p["fixed_scope"]["snapshot_size"] == SIZE
            && p["fixed_scope"]["terminal_slot"] == 88991050
            && p["fixed_scope"]["uncovered_suffix_slots"] == 949,
        "future input binding differs"
    );
    for f in [
        "probe_executed",
        "snapshot_restored",
        "replay_launch_authorized",
        "suffix_execution_authorized",
        "assembly_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            p[f] == false,
            "preparation is not execution/retirement authority"
        );
    }
    Ok(())
}
fn validate_collected(p: &std::collections::BTreeMap<String, String>) -> Result<()> {
    for (k, v) in [
        ("Id", UNIT),
        ("LoadState", "not-found"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("InvocationID", ""),
        ("NRestarts", "0"),
        ("Triggers", ""),
        ("TriggeredBy", ""),
    ] {
        ensure!(
            p.get(k).map(String::as_str) == Some(v),
            "collected acquisition identity changed: {k}"
        );
    }
    for k in [
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
        "ExecCondition",
        "ExecStop",
        "ExecStopPost",
        "ExecReload",
    ] {
        ensure!(
            p.get(k).is_none_or(String::is_empty),
            "collected unit retains command"
        );
    }
    Ok(())
}
fn owner() -> Result<std::collections::BTreeMap<String, String>> {
    let p = evidence::properties(
        UNIT,
        "Id,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,Triggers,TriggeredBy,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,ExecStop,ExecStopPost,ExecReload",
    )?;
    validate_collected(&p)?;
    Ok(p)
}
fn package_proof() -> Result<Value> {
    let root = Path::new(PACKAGE);
    let m = fs::symlink_metadata(root)?;
    ensure!(
        root.canonicalize()? == root && m.is_dir() && m.uid() == 0 && m.mode() & 0o222 == 0,
        "unsafe immutable input bundle"
    );
    let seal = evidence::bound_json(&bound(root.join("deployment-seal-receipt.json"), SEAL_SHA))?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == PACKAGE,
        "wrong input seal"
    );
    let (sha, m) = evidence::hash_file(&root.join("SHA256SUMS"), 65536)?;
    ensure!(
        sha == SUMS_SHA && m.uid() == 0 && m.mode() & 0o222 == 0,
        "input sums changed"
    );
    let expected = BTreeSet::from([
        NAME,
        "compressed-input-receipt.json",
        "terminal-input.md",
        "SHA256SUMS",
        "deployment-seal-receipt.json",
    ]);
    let actual = fs::read_dir(root)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("nonUTF8 input member"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        actual.iter().map(String::as_str).collect::<BTreeSet<_>>() == expected,
        "input member set differs"
    );
    let members = seal["members"]
        .as_array()
        .context("missing input members")?;
    ensure!(members.len() == 3, "input member count differs");
    let mut names = BTreeSet::new();
    let mut proof = Vec::new();
    for member in members {
        let name = member["name"].as_str().context("member name")?;
        ensure!(
            [NAME, "compressed-input-receipt.json", "terminal-input.md"].contains(&name)
                && names.insert(name),
            "foreign/duplicate input member"
        );
        let (sha, m) = evidence::hash_file(&root.join(name), SIZE)?;
        ensure!(
            sha == member["sha256"]
                && m.len() == member["bytes"]
                && m.uid() == 0
                && m.mode() & 0o222 == 0,
            "input member mismatch"
        );
        if name == NAME {
            ensure!(sha == SHA && m.len() == SIZE, "snapshot differs");
        }
        proof.push(json!({"name":name,"sha256":sha,"identity":identity(&m)}));
    }
    Ok(json!(proof))
}
fn prove(require_cache: bool) -> Result<Value> {
    let cache = Path::new(CACHE_ROOT).join(NAME);
    let copy = Path::new(PACKAGE).join(NAME);
    private_dir(Path::new(CACHE_ROOT))?;
    let before = owner()?;
    let a = evidence::bound_json(&bound(
        Path::new(PACKAGE).join("compressed-input-receipt.json"),
        ACQUISITION_SHA,
    ))?;
    validate_acquisition(&a)?;
    let prep = evidence::bound_json(&bound(PREPARATION.into(), PREPARATION_SHA))?;
    validate_preparation(&prep)?;
    let members = package_proof()?;
    let copy_meta = fs::symlink_metadata(&copy)?;
    let mut physical = 0;
    let cache_identity = if !absent(&cache)? {
        let (sha, m) = evidence::hash_file(&cache, SIZE)?;
        ensure!(
            sha == SHA
                && m.len() == SIZE
                && m.uid() == 0
                && m.mode() & 0o7777 == 0o400
                && identity(&m) == a["file_identity"]
                && (m.dev(), m.ino()) != (copy_meta.dev(), copy_meta.ino()),
            "cache identity differs"
        );
        physical = m
            .blocks()
            .checked_mul(512)
            .context("cache block overflow")?;
        identity(&m)
    } else {
        ensure!(!require_cache, "cache absent without intent");
        Value::Null
    };
    let scan = process_references::scan(Path::new("/proc"), &cache)?;
    ensure!(
        scan.references.is_empty(),
        "live cache references: {:?}",
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
    ensure!(
        staged.is_empty() && owner()? == before,
        "staged references or changed acquisition owner"
    );
    ensure!(
        identity(&copy_meta) == identity(&fs::symlink_metadata(&copy)?),
        "preserved copy changed"
    );
    Ok(
        json!({"cache":cache,"cache_identity":cache_identity,"cache_physical_bytes":physical,"preserved_copy":copy,"preserved_identity":identity(&copy_meta),"members":members,"acquisition_sha256":ACQUISITION_SHA,"preparation_sha256":PREPARATION_SHA,"owner_now":before,"original_successful_acquisition_invocation_id":IID,"terminal_receipt_proves_acquisition_not_default_manager_exit_status":true,"process_scan":scan,"staged_references":staged,"missing_unit_aliases":missing,"filesystem_available_bytes":available_bytes()?}),
    )
}
pub fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(
        matches!(args.len(), 2 | 3),
        "usage: BIN SELF_SHA --check-only | BIN SELF_SHA --retire CHECK_SHA"
    );
    let (self_sha, m) = evidence::hash_file(&fs::read_link("/proc/self/exe")?, 256 << 20)?;
    ensure!(
        self_sha == args[0]
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && identity(&m) == identity(&fs::metadata("/proc/self/exe")?),
        "unsealed executable"
    );
    let root = Path::new(RECEIPTS);
    let _lock = lock(root)?;
    let check = root.join("check.json");
    let intent = root.join("intent.json");
    let completion = root.join("completion.json");
    ensure!(absent(&completion)?, "retirement already complete");
    if args[1] == "--check-only" && args.len() == 2 {
        ensure!(absent(&intent)?, "intent already exists");
        let proof = prove(true)?;
        persist(
            &check,
            &json!({"schema":"jetstreamer-terminal205-cache-retire-check-v1","self_sha256":self_sha,"proof":proof,"native_restore_authorized":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
        println!("{}", check.display());
        return Ok(());
    }
    ensure!(args[1] == "--retire" && args.len() == 3, "unsupported mode");
    let prior = evidence::bound_json(&bound(check, &args[2]))?;
    ensure!(
        prior["schema"] == "jetstreamer-terminal205-cache-retire-check-v1"
            && prior["self_sha256"] == self_sha,
        "wrong preflight"
    );
    let has_intent = !absent(&intent)?;
    let proof = prove(!has_intent)?;
    let auth = json!({"schema":"jetstreamer-terminal205-cache-retire-intent-v1","self_sha256":self_sha,"check_sha256":args[2],"cache":prior["proof"]["cache"],"cache_identity":prior["proof"]["cache_identity"],"preserved_identity":prior["proof"]["preserved_identity"],"acquisition_sha256":ACQUISITION_SHA,"preparation_sha256":PREPARATION_SHA});
    ensure!(
        proof["preserved_identity"] == prior["proof"]["preserved_identity"],
        "preserved copy changed after preflight"
    );
    if has_intent {
        let (sha, _) = evidence::hash_file(&intent, 1 << 20)?;
        ensure!(
            evidence::bound_json(&bound(intent.clone(), &sha))? == auth,
            "foreign intent"
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
        &json!({"schema":"jetstreamer-terminal205-cache-retired-v1","self_sha256":self_sha,"check_sha256":args[2],"intent":auth,"proof":proof,"cache_absent":absent(&cache)?,"retired_cache_bytes":SIZE,"preserved_copy_unchanged":true,"filesystem_available_bytes_after":available_bytes()?,"native_restore_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("{}", completion.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn acquisition() -> Value {
        json!({"schema":"horizon-epoch205-terminal-snapshot-prepared-v1","epoch":205,"path":Path::new(CACHE_ROOT).join(NAME),"generation":"1634790073611030","size":SIZE,"sha256":SHA,"crc32c_base64":"9/mUyw==","md5_base64":"fBpHLn3nugSP8+TvNmpB1Q==","invocation_id":IID,"compressed_input_verified":true,"uri":format!("gs://mainnet-beta-ledger-us-ny5/88991050/{NAME}#1634790073611030"),"native_restore_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})
    }
    #[test]
    fn terminal205_is_not_bootstrap205_or_bootstrap227() {
        let a = acquisition();
        validate_acquisition(&a).unwrap();
        for (key, val) in [
            ("schema", json!("horizon-epoch227-bootstrap-prepared-v1")),
            ("epoch", json!(227)),
            ("generation", json!("1632781197930817")),
            ("size", json!(SIZE - 1)),
            ("path", json!("/other")),
            ("sha256", json!("0".repeat(64))),
            ("compressed_input_verified", json!(false)),
            ("native_restore_authorized", json!(true)),
        ] {
            let mut bad = a.clone();
            bad[key] = val;
            assert!(validate_acquisition(&bad).is_err(), "{key}");
        }
    }
    #[test]
    fn independent_input_preparation_is_not_restore_execution() {
        let p = json!({"schema":"jetstreamer-private-epoch205-native-restore-preparation-v1","epoch":205,"fixed_scope":{"snapshot":Path::new(PACKAGE).join(NAME),"snapshot_sha256":SHA,"snapshot_size":SIZE,"terminal_slot":88991050,"uncovered_suffix_slots":949},"probe_executed":false,"snapshot_restored":false,"replay_launch_authorized":false,"suffix_execution_authorized":false,"assembly_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        validate_preparation(&p).unwrap();
        for field in [
            "epoch",
            "fixed_scope",
            "snapshot_restored",
            "replay_launch_authorized",
            "r2_mutations",
        ] {
            let mut bad = p.clone();
            bad[field] = Value::Null;
            assert!(validate_preparation(&bad).is_err());
        }
    }
    #[test]
    fn collected_handle_is_not_a_success_claim_and_must_not_retain_launches() {
        let mut p = std::collections::BTreeMap::from_iter(
            [
                ("Id", UNIT),
                ("LoadState", "not-found"),
                ("ActiveState", "inactive"),
                ("SubState", "dead"),
                ("MainPID", "0"),
                ("InvocationID", ""),
                ("NRestarts", "0"),
                ("Triggers", ""),
                ("TriggeredBy", ""),
            ]
            .map(|(k, v)| (k.into(), v.into())),
        );
        validate_collected(&p).unwrap();
        for (key, val) in [
            ("ActiveState", "active"),
            ("MainPID", "123"),
            ("InvocationID", IID),
            ("Triggers", "launcher.service"),
            ("ExecStart", "anything"),
        ] {
            let old = p.insert(key.into(), val.into());
            assert!(validate_collected(&p).is_err());
            if let Some(v) = old {
                p.insert(key.into(), v);
            } else {
                p.remove(key);
            }
        }
    }
}
