//! Normalize the accepted 29-epoch floor and five subsequent verified deliveries.
//! Metadata only: no archive reads, unit mutations, R2 writes or launch authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

const PRIOR: &str =
    "/var/lib/jetstreamer/horizon2451-ready243-century-floor-Main-v1/century-floor.json";
const PRIOR_SHA: &str = "4908ed6b4f3f0630fb63777255ac1627289ab00c486e20db62fae3aaba324cfa";
const FULL: &str = "6ff8a6be80712b258577c027bf3512274a9c7d9f326b77a5cb07906205125302";
const PLUGIN: &str = "853c8a3f7448a75afbeea1fdf6b6e6e4f0001e970162bc2ad3b05e01d29f3c5b";
const RUNNER: &str = "ad8ab9a04394797ae4ee4ff7b65297bd3c75e4997d32be0948757f43ddbc8dfe";
const NEW: [(u64, &str); 5] = [
    (205, "verification-205-current-20261117-v2"),
    (210, "verification-210-current-20261117-v1"),
    (239, "verification-239-current-20261117-v2"),
    (244, "verification-244-current-20261117-v1"),
    (246, "verification-246-current-20261117-v2"),
];
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing {k}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing {k}"))
}
fn read(p: &Path) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "noncanonical path"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && [0, 1000].contains(&m.uid())
            && m.mode() & 0o022 == 0
            && m.nlink() == 1
            && m.len() <= 4 << 20,
        "unsafe metadata {}",
        p.display()
    );
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    let after = f.metadata()?;
    ensure!(
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec()
        ) == (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        ),
        "changed metadata"
    );
    Ok(b)
}
fn binding(p: &Path, b: &[u8]) -> Value {
    json!({"path":p,"sha256":digest(b)})
}
fn bound(p: &Path, sha: &str) -> Result<Value> {
    ensure!(
        fs::symlink_metadata(p)?.uid() == 0,
        "bound authority must be root-owned"
    );
    let b = read(p)?;
    ensure!(digest(&b) == sha, "digest mismatch {}", p.display());
    Ok(serde_json::from_slice(&b)?)
}
fn write(root: &Path, name: &str, v: &Value) -> Result<Value> {
    let p = root.join(name);
    let b = serde_json::to_vec_pretty(v)?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    f.write_all(&b)?;
    f.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(binding(&p, &b))
}
fn receipt(r: &Value, entry: &Value) -> Result<()> {
    let e = number(entry, "epoch")?;
    ensure!(
        r["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && r["epoch"] == e
            && r["remote_sha256_readback"] == true,
        "foreign/unverified remote receipt"
    );
    ensure!(
        r["archive_length"] == entry["archive_length"]
            && r["archive_sha256"] == entry["sidecar_sha256"]
            && entry["archive_metadata_sha256"] == entry["sidecar_sha256"],
        "remote digest/length mismatch"
    );
    ensure!(
        r["archive_key"] == format!("epoch-{e}.jet")
            && r["checksum_key"] == format!("epoch-{e}.jet.sha256"),
        "noncanonical keys"
    );
    ensure!(
        number(r, "archive_length")? > 0 && valid_sha(string(r, "archive_sha256")?),
        "invalid archive identity"
    );
    Ok(())
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn raw_gate(bytes: &[u8], archive: &str, verifier: &str) -> Result<()> {
    let s = std::str::from_utf8(bytes)?;
    let tokens: Vec<_> = s.split_whitespace().collect();
    ensure!(
        tokens == [archive, verifier, RUNNER],
        "verification receipt identity differs"
    );
    Ok(())
}
fn inventory(v: &Value, first: u64, last: u64) -> Result<Vec<Value>> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-r2-inventory-v1"
            && v["first_epoch"] == first
            && v["last_epoch"] == last
            && v["anomalies"] == 0
            && v["archive_only"] == 0,
        "incomplete/anomalous inventory"
    );
    let entries = v["entries"].as_array().context("inventory entries")?;
    let mut seen = BTreeSet::new();
    let mut ready = Vec::new();
    for e in entries {
        let n = number(e, "epoch")?;
        ensure!(
            (first..=last).contains(&n) && seen.insert(n),
            "foreign/duplicate epoch"
        );
        match string(e, "state")? {
            "ready-pair" => ready.push(e.clone()),
            "missing" => {}
            _ => anyhow::bail!("incomplete pair"),
        }
    }
    ensure!(
        seen.len() as u64 == last - first + 1
            && number(v, "ready_pairs")? == ready.len() as u64
            && number(v, "missing")? + ready.len() as u64 == seen.len() as u64,
        "incomplete census/count mismatch"
    );
    Ok(ready)
}
fn floor(lengths: impl IntoIterator<Item = u64>) -> Result<(u64, u64, u64)> {
    let mut sum = 0u64;
    let mut count = 0u64;
    for n in lengths {
        ensure!(n > 0, "zero length");
        sum = sum.checked_add(n).context("sum overflow")?;
        count += 1;
    }
    ensure!(count > 0, "empty floor");
    Ok((
        count,
        sum,
        sum.checked_mul(2)
            .context("floor overflow")?
            .div_ceil(count),
    ))
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 7,
        "usage: century FLEET FLEET_SHA INVENTORY200 INVENTORY200_SHA OUTPUT SELF_SHA"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        digest(&fs::read("/proc/self/exe")?) == a[6],
        "self mismatch"
    );
    let fleet = bound(Path::new(&a[1]), &a[2])?;
    let inv200 = bound(Path::new(&a[3]), &a[4])?;
    ensure!(
        inventory(&inv200, 200, 200)?.is_empty(),
        "new epoch200 requires gate adjudication"
    );
    let entries = inventory(&fleet["inventory"], 201, 300)?;
    let prior = bound(Path::new(PRIOR), PRIOR_SHA)?;
    ensure!(
        prior["schema"] == "horizon-century-ready-mean-floor-v1",
        "prior floor schema"
    );
    let lengths = prior["ready_lengths"]
        .as_object()
        .context("prior lengths")?;
    let (count, sum, old_floor) = floor(lengths.values().map(|n| n.as_u64().unwrap_or(0)))?;
    ensure!(
        count == 29
            && prior["count"] == count
            && prior["sum_bytes"] == sum
            && prior["floor_bytes"] == old_floor
            && entries.len() == 34,
        "changed accepted floor or inventory"
    );
    let expected: BTreeSet<_> = lengths
        .keys()
        .map(|k| k.parse::<u64>())
        .collect::<std::result::Result<_, _>>()?;
    let actual: BTreeSet<_> = entries
        .iter()
        .map(|e| number(e, "epoch"))
        .collect::<Result<_>>()?;
    ensure!(
        actual
            == expected
                .union(&NEW.iter().map(|r| r.0).collect())
                .copied()
                .collect(),
        "missing/extra ready epochs"
    );
    // Validate every source before writing any normalized result.
    let mut inputs = Vec::new();
    for e in &entries {
        let epoch = number(e, "epoch")?;
        let rp = if epoch == 204 {
            "/var/lib/jetstreamer/horizon-204-assembly-upload-full3-output-v2/epoch-204.r2.json"
                .to_owned()
        } else {
            format!("/home/ubuntu/.jetstreamer-private/r2-receipts/epoch-{epoch}.r2.json")
        };
        let raw = read(Path::new(&rp))?;
        let mut r: Value = serde_json::from_slice(&raw)?;
        receipt(&r, e)?;
        let remote = binding(Path::new(&rp), &raw);
        r["original_receipt"] = remote.clone();
        r["original_receipt_uid"] = json!(fs::symlink_metadata(&rp)?.uid());
        let mut gates = Vec::new();
        for (role, verifier) in [("full", FULL), ("plugin", PLUGIN)] {
            let mut doc = json!({"schema":"horizon251-normalized-canonical-gate-v1","epoch":epoch,"role":role,"canonical_jet_bytes":e["archive_length"],"archive_sha256":e["sidecar_sha256"],"remote_readback":remote});
            if let Some((_, root)) = NEW.iter().find(|r| r.0 == epoch) {
                let p = format!(
                    "/home/ubuntu/.jetstreamer-private/{root}/{role}/receipts/epoch-{epoch}.{role}.ok"
                );
                let raw = read(Path::new(&p))?;
                raw_gate(&raw, string(e, "sidecar_sha256")?, verifier)?;
                doc["basis"] = json!("exact full/plugin receipt and canonical remote identity");
                doc["raw_receipt"] = binding(Path::new(&p), &raw);
                doc["verifier_sha256"] = json!(verifier);
                doc["runner_sha256"] = json!(RUNNER);
            } else {
                ensure!(
                    lengths[&epoch.to_string()] == e["archive_length"],
                    "inherited canonical length changed"
                );
                doc["basis"] = json!(
                    "inherited Main-accepted qualified 29-epoch floor; no new verification claimed"
                );
                doc["accepted_prior_floor"] = json!({"path":PRIOR,"sha256":PRIOR_SHA});
            }
            gates.push(doc);
        }
        inputs.push((e.clone(), r, gates));
    }
    let root = Path::new(&a[5]);
    ensure!(root.is_absolute(), "absolute output required");
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    ensure!(root.canonicalize()? == root, "noncanonical output");
    let mut rows = Vec::new();
    for (e, remote_receipt, mut gates) in inputs {
        let epoch = number(&e, "epoch")?;
        let remote = write(root, &format!("epoch-{epoch}.remote.json"), &remote_receipt)?;
        for gate in &mut gates {
            gate["remote_readback"] = remote.clone();
        }
        let full = write(root, &format!("epoch-{epoch}.full.json"), &gates[0])?;
        let plugin = write(root, &format!("epoch-{epoch}.plugin.json"), &gates[1])?;
        rows.push(json!({"epoch":epoch,"canonical_jet_bytes":e["archive_length"],"archive_sha256":e["sidecar_sha256"],"normal_full_plugin_and_remote_gates_accepted":true,"full_verification":full,"current_plugin":plugin,"remote_readback":remote}));
    }
    let (count, sum, current_floor) = floor(
        entries
            .iter()
            .map(|e| e["archive_length"].as_u64().unwrap_or(0)),
    )?;
    let doc = json!({"schema":"horizon251-qualified-century-census-v1","first_epoch":200,"last_epoch":300,"source_fleet":{"path":a[1],"sha256":a[2]},"epoch200_inventory":{"path":a[3],"sha256":a[4]},"accepted_prior_floor":{"path":PRIOR,"sha256":PRIOR_SHA},"count":count,"sum_bytes":sum,"floor_bytes":current_floor,"century_floor_census":rows,"new_verification_claimed_for_inherited_epochs":false,"latest_account_updates_reader_compatibility_proven":false,"replay_launch_authorized":false,"remote_mutations":false});
    println!("{}", write(root, "century-floor.json", &doc)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_receipt_identity_required() {
        let a = "a".repeat(64);
        let raw = format!("{a} {FULL} {RUNNER}\n");
        raw_gate(raw.as_bytes(), &a, FULL).unwrap();
        assert!(raw_gate(raw.as_bytes(), &a, PLUGIN).is_err());
        assert!(raw_gate(format!("{raw} extra").as_bytes(), &a, FULL).is_err());
        assert!(raw_gate(raw.as_bytes(), &"b".repeat(64), FULL).is_err());
    }
    #[test]
    fn complete_inventory_required() {
        let mut v = json!({"schema":"jetstreamer-horizon-r2-inventory-v1","first_epoch":200,"last_epoch":201,"anomalies":0,"archive_only":0,"ready_pairs":1,"missing":1,"entries":[{"epoch":200,"state":"missing"},{"epoch":201,"state":"ready-pair"}]});
        assert_eq!(inventory(&v, 200, 201).unwrap().len(), 1);
        v["entries"][1]["epoch"] = json!(200);
        assert!(inventory(&v, 200, 201).is_err());
        v["entries"][1]["epoch"] = json!(202);
        assert!(inventory(&v, 200, 201).is_err());
        v["entries"] = json!([]);
        assert!(inventory(&v, 200, 201).is_err());
    }
    #[test]
    fn floor_rounds_up_and_rejects_overflow() {
        assert_eq!(floor([1, 2, 2]).unwrap(), (3, 5, 4));
        assert!(floor([]).is_err());
        assert!(floor([0]).is_err());
        assert!(floor([u64::MAX]).is_err());
    }
    #[test]
    fn remote_presence_does_not_replace_readback() {
        let e = json!({"epoch":205,"archive_length":100,"sidecar_sha256":"a".repeat(64),"archive_metadata_sha256":"a".repeat(64)});
        let mut r = json!({"schema":"jetstreamer-horizon-r2-receipt-v1","epoch":205,"archive_length":100,"archive_sha256":"a".repeat(64),"remote_sha256_readback":true,"archive_key":"epoch-205.jet","checksum_key":"epoch-205.jet.sha256"});
        receipt(&r, &e).unwrap();
        r["remote_sha256_readback"] = json!(false);
        assert!(receipt(&r, &e).is_err());
        r["remote_sha256_readback"] = json!(true);
        r["archive_length"] = json!(101);
        assert!(receipt(&r, &e).is_err());
    }
}
