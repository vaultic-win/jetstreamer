//! Read-only admission evidence for the exact completed epoch 144 assembly.
//! No copy, chown, sidecar, .ok gate, public import, or network access.
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod evidence;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch144-assembly-only-20261022-v2/epoch-144-assembly-only-v4.jet";
const VIEW: &str = "/run/horizon-epoch144-assembly-only-verification-20261022-v1/epoch-144.jet";
const STATE: &str = "/var/lib/jetstreamer/horizon-epoch144-assembly-only-verification-20261022-v1";
const RUNNER: &str = "7dfe0fdabbee8e5f79b131c2b7cece49dbebe489168fe195a9086ab25f0b8810";
const ARCHIVE: &str = "153d3e5e5b7cbdc31bb4229315786000b84442a75b3b83cf4a50184b20b84a33";
const LENGTH: u64 = 109177480876;
const PROVENANCE: &str = "170dec96fb56881135293366ef1c85d8d790918f51a2c9d2fc4fbbc6beced819";
const ASSEMBLY: &str = "horizon-qualify-144-assembly-only-recovery-20261022-v1.service";
const ORIGINAL: &str = "horizon-qualify-144-checkpoint-continuation-20261022-v1.service";
const ASSEMBLY_IID: &str = "00ca9bfb862549f6b99117b1ce590365";
const ORIGINAL_IID: &str = "8fddd3ef045c4fe5b12c7d25f43a4b73";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    full: Bound,
    plugin: Bound,
    output: PathBuf,
}

fn bound(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn read(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        4 << 20,
        immutable,
    )?)?)
}
fn linked(v: &Value, key: &str) -> Result<Bound> {
    Ok(serde_json::from_value(v[key].clone())?)
}
fn pinned(v: &Value, key: &str, path: &str, sha: &str) -> Result<Bound> {
    let b = linked(v, key)?;
    ensure!(b == bound(path, sha), "foreign {key} binding");
    Ok(b)
}
fn scan_plan(stage: &str) -> Bound {
    bound(
        &format!(
            "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-scan-plan-20261022-v1/{stage}.json"
        ),
        if stage == "full" {
            "5f7aac2e313dc61f54f0fe8fc88b126a3a11583e2493af63d33d75ad459cca8b"
        } else {
            "c0206e2bd72d9bcc21aa8a2783537333ba6580cbeaeba8954245078b2dccabfa"
        },
    )
}
fn verifier(stage: &str) -> Bound {
    bound(
        if stage == "full" {
            "/usr/local/lib/jetstreamer/horizon-epoch144-private-verification-tools-20261022-v1/verify_archive"
        } else {
            "/usr/local/lib/jetstreamer/horizon-epoch144-private-scan-tools-20261022-v1/horizon_pipeline"
        },
        if stage == "full" {
            "41c03e493daa309ab7cffd9760b4e6cfe2195b3af0bb13a17f19508eb929d6e7"
        } else {
            "73e7535b9cedc7e565a92735ca6e07c7efb8e66755a6d5272ed16649b4d8cee9"
        },
    )
}
fn arguments(stage: &str) -> Value {
    if stage == "full" {
        json!([
            VIEW,
            "--full",
            "--anchor",
            "62207999",
            "6XkxRpAhiXkxqFfD4nqgydUUYAanNfoFLWwWYgq4zvMT",
            "--expected-terminal",
            "62639999",
            "Fnoa95TKZ1U419CubZrxYDtFnqadRmvM554FFi2xSizB",
            "--threads",
            "8",
            "--expected-provenance-sha256",
            PROVENANCE
        ])
    } else {
        json!([
            "144:144",
            Path::new(VIEW).parent().unwrap(),
            "--threads",
            "8",
            "--verify-only"
        ])
    }
}
fn validate_owner(v: &Value, timeout: bool) -> Result<()> {
    for (key, expected) in [
        (
            "InvocationID",
            if timeout { ORIGINAL_IID } else { ASSEMBLY_IID },
        ),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Type", "exec"),
        ("Result", if timeout { "timeout" } else { "success" }),
        ("ActiveState", if timeout { "failed" } else { "active" }),
        ("SubState", if timeout { "failed" } else { "exited" }),
        ("RuntimeMaxUSec", if timeout { "2h" } else { "1d" }),
    ] {
        ensure!(v[key] == expected, "producer terminal differs:{key}");
    }
    ensure!(
        if timeout {
            matches!(v["ExecMainStatus"].as_str(), Some("1" | "9" | "15"))
        } else {
            v["ExecMainStatus"] == "0"
        },
        "producer exit differs"
    );
    Ok(())
}
fn validate_scan(v: &Value, stage: &str) -> Result<()> {
    ensure!(matches!(stage, "full" | "plugin"), "unknown scan stage");
    ensure!(
        v["schema"] == "jetstreamer-private144-assembly-only-independent-scan-v1"
            && v["epoch"] == 144
            && v["stage"] == stage
            && v["runner_sha256"] == RUNNER
            && v["exit_code"] == 0
            && v["elapsed_millis"].as_u64().is_some_and(|n| n > 0)
            && v["archive_path"] == SOURCE
            && v["canonical_view"] == VIEW
            && v["archive_sha256"] == ARCHIVE
            && v["copy_performed"] == false
            && v["arguments"] == arguments(stage),
        "wrong exact independent scan"
    );
    ensure!(
        linked(v, "plan")? == scan_plan(stage) && linked(v, "verifier")? == verifier(stage),
        "foreign plan/verifier"
    );
    // Keep the scanner's array identity intact; it is not epoch 213's struct.
    let id = v["archive_identity"]
        .as_array()
        .context("archive identity")?;
    ensure!(
        id.len() == 10
            && id[0].as_u64().is_some_and(|n| n > 0)
            && id[1].as_u64().is_some_and(|n| n > 0)
            && id[2] == LENGTH
            && id[3] == 0
            && id[4] == 0o100600
            && id[5] == 1
            && id[6].as_i64().is_some()
            && id[8].as_i64().is_some()
            && id[7].as_u64().is_some_and(|n| n < 1_000_000_000)
            && id[9].as_u64().is_some_and(|n| n < 1_000_000_000),
        "unsafe exact source identity"
    );
    for flag in [
        "runtime_admission_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(
            v[flag] == false,
            "private scanner acquired authority:{flag}"
        );
    }
    validate_owner(&v["producer_terminal"]["assembly"], false)?;
    validate_owner(&v["producer_terminal"]["original_timeout"], true)?;
    pinned(
        v,
        "producer_outcome",
        "/usr/local/lib/jetstreamer/horizon-assembly144-outcome-evidence-20261022-v1/assembly.json",
        "11cd3172f6cd5e26b98a3446205cb7ef1732bdfc56138cc30caed0f2c0e496ea",
    )?;
    pinned(
        v,
        "provenance_expectation",
        "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-verification-evidence-20261022-v1/provenance.json",
        "d67420b4f06834aac15c959ede61db4b027bdb82f5584a2dafd32f4f2c379e72",
    )?;
    pinned(
        v,
        "boundaries",
        "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-verification-evidence-20261022-v1/finalized-boundaries.json",
        "5fd04d4f501d77f9866b469f33e3ac729d44187979e6937e9856e880de401ede",
    )?;
    Ok(())
}
fn observe(unit: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl").args(["show",unit,"--property=InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ActiveState,SubState,Type,RuntimeMaxUSec"]).output()?;
    ensure!(out.status.success(), "terminal observation failed");
    let fields: std::collections::BTreeMap<_, _> = std::str::from_utf8(&out.stdout)?
        .lines()
        .filter_map(|s| s.split_once('='))
        .collect();
    Ok(json!(fields))
}
fn scan_owner(stage: &str, v: &Value) -> Result<()> {
    ensure!(
        v["InvocationID"]
            == if stage == "full" {
                "4f892edb6bfc48deb8148c3cebddd9dc"
            } else {
                "e65e914f152f452c815c1b510dc66e07"
            }
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && v["ActiveState"] == "active"
            && v["SubState"] == "exited"
            && v["Type"] == "exec",
        "scan not exact terminal success"
    );
    Ok(())
}
fn validate_pair(full: &Value, plugin: &Value) -> Result<()> {
    validate_scan(full, "full")?;
    validate_scan(plugin, "plugin")?;
    for key in [
        "archive_identity",
        "producer_outcome",
        "producer_terminal",
        "provenance_expectation",
        "boundaries",
    ] {
        ensure!(full[key] == plugin[key], "scan pair differs:{key}");
    }
    Ok(())
}
fn source(v: &Value) -> Result<File> {
    let path = Path::new(SOURCE);
    ensure!(path.canonicalize()? == path, "noncanonical source");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        f.metadata()?.is_file()
            && json!(evidence::identity(&f.metadata()?)) == v["archive_identity"]
            && json!(evidence::identity(&fs::symlink_metadata(path)?)) == v["archive_identity"],
        "retained source changed"
    );
    ensure!(
        matches!(fs::symlink_metadata(path.with_extension("jet.sha256")),Err(e)if e.kind()==std::io::ErrorKind::NotFound),
        "private source sidecar appeared"
    );
    Ok(f)
}
fn collect(p: &Plan) -> Result<Value> {
    ensure!(
        p.schema == "jetstreamer-private144-publication-evidence-plan-v1",
        "wrong evidence plan"
    );
    for (stage, b) in [("full", &p.full), ("plugin", &p.plugin)] {
        ensure!(
            b.path == Path::new(STATE).join(stage).join("verification.json"),
            "foreign scan receipt path"
        );
    }
    let full = read(&p.full, false)?;
    let plugin = read(&p.plugin, false)?;
    validate_pair(&full, &plugin)?;
    evidence::bound_file(
        Path::new(
            "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-scan-tools-20261022-v1/jetstreamer-epoch144-private-verify",
        ),
        RUNNER,
        128 << 20,
        true,
    )?;
    let retained = source(&full)?;
    let mut scan_units = json!({});
    let mut logs = json!({});
    for (stage, v) in [("full", &full), ("plugin", &plugin)] {
        let unit = format!("horizon-assembly144-{stage}-verification-20261022-v1.service");
        let owner = observe(&unit)?;
        scan_owner(stage, &owner)?;
        scan_units[stage] = json!({"unit":unit,"state":owner});
        let sp = read(&scan_plan(stage), true)?;
        ensure!(
            sp["stage"] == stage
                && sp["schema"] == "jetstreamer-private144-assembly-only-verification-plan-v1",
            "foreign scan plan"
        );
        for key in [
            "producer_outcome",
            "provenance_expectation",
            "boundaries",
            "verifier",
        ] {
            ensure!(sp[key] == v[key], "plan/receipt differs:{key}");
        }
        let tool = verifier(stage);
        evidence::bound_file(&tool.path, &tool.sha256, 512 << 20, true)?;
        let launch = pinned(
            &sp,
            "assembly_launch",
            "/var/lib/jetstreamer/horizon-assembly144-launch-20261022-v1/launch.json",
            "f601ec77e6b697192f2032b5afd0d04d8bcb870fc163f341ec00f24d41594a4e",
        )?;
        read(&launch, false)?;
        let log = Path::new(STATE).join(stage).join("scan.log");
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&log)?;
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && m.len() > 0
                && m.len() <= 64 << 20,
            "unsafe scan log"
        );
        let mut bytes = Vec::new();
        (&mut file).take((64 << 20) + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == m.len()
                && evidence::identity(&m) == evidence::identity(&file.metadata()?),
            "scan log changed or oversized"
        );
        let b = Bound {
            path: log,
            sha256: evidence::sha(&bytes),
        };
        evidence::bound_file(&b.path, &b.sha256, 64 << 20, false)?;
        logs[stage] = serde_json::to_value(b)?;
    }
    let outcome = read(&linked(&full, "producer_outcome")?, true)?;
    let expectation = read(&linked(&full, "provenance_expectation")?, true)?;
    read(&linked(&full, "boundaries")?, true)?;
    for key in ["prefix_manifest", "suffix_manifest"] {
        read(&linked(&outcome, key)?, true)?;
    }
    read(&linked(&outcome, "plan")?, true)?;
    ensure!(
        expectation["expected_provenance_sha256"] == PROVENANCE,
        "provenance differs"
    );
    let assembly = observe(ASSEMBLY)?;
    let original = observe(ORIGINAL)?;
    validate_owner(&assembly, false)?;
    validate_owner(&original, true)?;
    ensure!(
        full["producer_terminal"] == json!({"assembly":assembly,"original_timeout":original}),
        "producer history changed"
    );
    // This auditor deliberately does not claim a new archive hash. The later
    // importer must copy/hash and revalidate the original inode independently.
    ensure!(
        json!(evidence::identity(&retained.metadata()?)) == full["archive_identity"],
        "source fd changed"
    );
    source(&full)?;
    read(&p.full, false)?;
    read(&p.plugin, false)?;
    for stage in ["full", "plugin"] {
        let unit = scan_units[stage]["unit"].as_str().unwrap();
        ensure!(
            observe(unit)? == scan_units[stage]["state"],
            "scanner identity changed during audit"
        );
    }
    Ok(
        json!({"schema":"jetstreamer-private144-publication-evidence-v1","epoch":144,"full":p.full,"plugin":p.plugin,"scan_units":scan_units,"logs":logs,
        "archive_path":SOURCE,"archive_sha256":ARCHIVE,"archive_bytes":LENGTH,"archive_identity":full["archive_identity"],
        "producer_outcome":full["producer_outcome"],"provenance_expectation":full["provenance_expectation"],"boundaries":full["boundaries"],"expected_provenance_sha256":PROVENANCE,
        "independent_full_and_plugin_receipts_validated":true,"fresh_archive_hash_performed":false,"copy_performed":false,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let check = a.len() == 7 && a[6] == "--check-only";
    ensure!(
        (a.len() == 6 || check)
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: publication-evidence PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&a[1]),
        &a[3],
        1 << 20,
        true,
    )?)?;
    ensure!(
        p.output.file_name().is_some_and(|n| n == "evidence.json")
            && p.output.parent().is_some_and(|d| d.parent()
                == Some(Path::new("/var/lib/jetstreamer"))
                && d.file_name().is_some_and(|n| n
                    .to_string_lossy()
                    .starts_with("horizon-epoch144-publication-evidence-"))),
        "wrong output namespace"
    );
    let mut result = collect(&p)?;
    if check {
        println!("exact144 evidence validated; no writes, archive hash, copy or publication");
        return Ok(());
    }
    result["plan"] = json!({"path":a[1],"sha256":a[3]});
    result["tool_sha256"] = json!(a[5]);
    evidence::write_receipt(&p.output, &result)?;
    println!("{}", p.output.display());
    Ok(())
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner(timeout: bool) -> Value {
        json!({"InvocationID":if timeout{ORIGINAL_IID}else{ASSEMBLY_IID},"MainPID":"0","NRestarts":"0","Restart":"no","Type":"exec","Result":if timeout{"timeout"}else{"success"},"ActiveState":if timeout{"failed"}else{"active"},"SubState":if timeout{"failed"}else{"exited"},"RuntimeMaxUSec":if timeout{"2h"}else{"1d"},"ExecMainStatus":if timeout{"15"}else{"0"}})
    }
    fn fixture(stage: &str) -> Value {
        json!({"schema":"jetstreamer-private144-assembly-only-independent-scan-v1","epoch":144,"stage":stage,"runner_sha256":RUNNER,"exit_code":0,"elapsed_millis":1,"archive_path":SOURCE,"canonical_view":VIEW,"archive_sha256":ARCHIVE,"copy_performed":false,"arguments":arguments(stage),"plan":scan_plan(stage),"verifier":verifier(stage),"archive_identity":[1,2,LENGTH,0,0o100600,1,1,0,1,0],"producer_terminal":{"assembly":owner(false),"original_timeout":owner(true)},
            "producer_outcome":bound("/usr/local/lib/jetstreamer/horizon-assembly144-outcome-evidence-20261022-v1/assembly.json","11cd3172f6cd5e26b98a3446205cb7ef1732bdfc56138cc30caed0f2c0e496ea"),
            "provenance_expectation":bound("/usr/local/lib/jetstreamer/horizon-epoch144-assembly-verification-evidence-20261022-v1/provenance.json","d67420b4f06834aac15c959ede61db4b027bdb82f5584a2dafd32f4f2c379e72"),
            "boundaries":bound("/usr/local/lib/jetstreamer/horizon-epoch144-assembly-verification-evidence-20261022-v1/finalized-boundaries.json","5fd04d4f501d77f9866b469f33e3ac729d44187979e6937e9856e880de401ede"),
            "runtime_admission_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false})
    }
    #[test]
    fn exact_pair_required_and_every_trust_field_rejected_on_mutation() {
        validate_pair(&fixture("full"), &fixture("plugin")).unwrap();
        for stage in ["full", "plugin"] {
            for (pointer, value) in [
                (
                    "/schema",
                    json!("jetstreamer-private-epoch213-verification-v1"),
                ),
                ("/epoch", json!(213)),
                ("/stage", json!("other")),
                ("/runner_sha256", json!(ARCHIVE)),
                ("/exit_code", json!(1)),
                ("/elapsed_millis", json!(0)),
                ("/archive_path", json!("/tmp/source")),
                ("/canonical_view", json!(SOURCE)),
                ("/archive_sha256", json!(PROVENANCE)),
                ("/copy_performed", json!(true)),
                ("/arguments", json!(["--internal-full"])),
                ("/archive_identity/2", json!(1)),
                ("/archive_identity/3", json!(1001)),
                ("/archive_identity/4", json!(0o100666)),
                ("/archive_identity/5", json!(2)),
                ("/plan/sha256", json!(ARCHIVE)),
                ("/verifier/sha256", json!(ARCHIVE)),
                ("/boundaries/sha256", json!(ARCHIVE)),
                ("/producer_outcome/sha256", json!(ARCHIVE)),
                ("/provenance_expectation/sha256", json!(ARCHIVE)),
                (
                    "/producer_terminal/assembly/InvocationID",
                    json!(ORIGINAL_IID),
                ),
                (
                    "/producer_terminal/original_timeout/Result",
                    json!("success"),
                ),
                ("/runtime_admission_authorized", json!(true)),
                ("/canonical_sidecar_authorized", json!(true)),
                ("/publication_authorized", json!(true)),
                ("/retirement_authorized", json!(true)),
                ("/r2_mutations", json!(true)),
            ] {
                let mut changed = fixture(stage);
                *changed.pointer_mut(pointer).unwrap() = value;
                assert!(validate_scan(&changed, stage).is_err(), "{stage}:{pointer}");
            }
        }
    }
    #[test]
    fn individually_valid_scans_must_bind_the_same_source_inode() {
        let full = fixture("full");
        let mut plugin = fixture("plugin");
        plugin["archive_identity"][1] = json!(3);
        validate_scan(&plugin, "plugin").unwrap();
        assert!(validate_pair(&full, &plugin).is_err());
    }
    #[test]
    fn absent_and_nonterminal_owners_are_not_completion() {
        assert!(scan_owner("plugin", &json!({})).is_err());
        for pointer in [
            "/MainPID",
            "/NRestarts",
            "/ActiveState",
            "/Result",
            "/RuntimeMaxUSec",
        ] {
            let mut v = owner(false);
            *v.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(validate_owner(&v, false).is_err());
        }
    }
    #[test]
    #[ignore = "explicit root read-only validation of the actual retained full144 receipt"]
    fn retained_full144_receipt_passes() {
        let v = read(
            &bound(
                &format!("{STATE}/full/verification.json"),
                "2cb07f659579e603e4d7bf13399349e9a59fe639ba89bc76c4de79d1ebef687e",
            ),
            false,
        )
        .unwrap();
        validate_scan(&v, "full").unwrap();
        source(&v).unwrap();
        read(&scan_plan("full"), true).unwrap();
        for key in ["producer_outcome", "provenance_expectation", "boundaries"] {
            read(&linked(&v, key).unwrap(), true).unwrap();
        }
        let tool = verifier("full");
        evidence::bound_file(&tool.path, &tool.sha256, 512 << 20, true).unwrap();
    }
}
