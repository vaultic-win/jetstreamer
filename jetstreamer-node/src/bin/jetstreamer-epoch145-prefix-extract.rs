//! Held, separately admitted private canonical145 extraction. No sidecar,
//! runtime promotion, import, retirement or R2 authority is implemented here.
#[path = "epoch145_prefix_extract/contract.rs"]
mod contract;
#[path = "epoch145_prefix_extract/native.rs"]
mod native;
#[path = "epoch145_prefix_extract/receipt.rs"]
mod receipt;
#[path = "epoch213_publish/write_scope.rs"]
mod write_scope;
use anyhow::{Result, ensure};
use contract::{Admission, Bound, Plan, Release};
use jetstreamer_node::epoch145_extract::{PINNED_WORKER_SHA256, PinnedSource};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

fn digest(raw: &str) -> Result<[u8; 32]> {
    ensure!(contract::hex(raw, 64), "invalid SHA256");
    let mut bytes = [0; 32];
    for (i, pair) in raw.as_bytes().chunks_exact(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(bytes)
}
fn terminal(value: &Value) -> Result<()> {
    ensure!(
        value["schema"] == "horizon-cached145-authenticated-original-terminal-and-segment-v1"
            && value["epoch"] == 145
            && value["original_IID"] == contract::ORIGINAL_IID
            && value["original_PID1_success_event"]["_PID"] == "1"
            && value["original_PID1_success_event"]["_UID"] == "0"
            && value["original_PID1_success_event"]["INVOCATION_ID"] == contract::ORIGINAL_IID
            && value["original_PID1_success_event"]["MESSAGE_ID"]
                == "7ad2d189f7e94e70a38c781354912448"
            && value["producer_recorded_archive_sha256"] == contract::SOURCE_SHA
            && value["archive"]["bytes"] == contract::SOURCE_BYTES
            && value["producer_segment_manifest"]["sha256"] == contract::MANIFEST_SHA
            && value["manifest"]["output_slot_start"] == 62_640_000u64
            && value["manifest"]["output_slot_count"] == 432_071
            && value["manifest"]["terminal"]["slot"] == 63_072_070u64
            && value["resource_credit_or_retirement_authorized"] == false,
        "wrong original completed source witness"
    );
    Ok(())
}
fn once(path: &Path, value: &Value) -> Result<()> {
    if path.try_exists()? {
        ensure!(
            receipt::private_json(path)? == *value,
            "existing extraction receipt differs"
        );
        Ok(())
    } else {
        receipt::persist(path, value)
    }
}
fn wait_release(plan: &Plan, iid: &str) -> Result<Release> {
    let path = plan.state().join(format!("release-{iid}.json"));
    let start = Instant::now();
    loop {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let release: Release = serde_json::from_value(receipt::private_json(&path)?)?;
                ensure!(
                    release.schema == "horizon-epoch145-prefix-extraction-release-v1",
                    "foreign held release"
                );
                return Ok(release);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        ensure!(
            start.elapsed().as_secs() < plan.hold_seconds,
            "held extraction admission expired without archive access"
        );
        thread::sleep(Duration::from_secs(1));
    }
}
fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 7
            && args[1] == "hold"
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256",
        "usage: hold PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    let pb = Bound {
        path: PathBuf::from(&args[2]),
        sha256: args[4].clone(),
    };
    let plan: Plan = serde_json::from_value(receipt::bound(&pb)?)?;
    plan.validate()?;
    ensure!(
        args[6] == plan.program.sha256 && receipt::hash_file(&plan.program.path)? == args[6],
        "extractor self artifact differs"
    );
    use std::os::unix::fs::MetadataExt;
    let mapped = fs::metadata("/proc/self/exe")?;
    let image = fs::metadata(&plan.program.path)?;
    ensure!(
        mapped.dev() == image.dev()
            && mapped.ino() == image.ino()
            && image.uid() == 0
            && image.nlink() == 1
            && image.mode() & 0o222 == 0,
        "mapped extractor is not sealed program"
    );
    let command = fs::read("/proc/self/cmdline")?;
    let own_args = command
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| std::str::from_utf8(b).map(str::to_owned))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(own_args == args, "extractor process argv differs");
    terminal(&receipt::bound(&plan.original_terminal)?)?;
    let owner = native::capture(&plan)?;
    receipt::directory(&plan.state())?;
    receipt::directory(&plan.work())?;
    // Reuse the already qualified write-confinement primitive before any decoder
    // thread starts. The original archive and manifest are outside this scope.
    let confinement = write_scope::confine(&[&plan.state(), &plan.work()])?;
    receipt::persist(
        &plan
            .state()
            .join(format!("owner-start-{}.json", owner.invocation_id)),
        &json!({"schema":"horizon-epoch145-prefix-extraction-held-owner-v1","plan":pb,"owner":owner,"write_scope":confinement,"archive_opened":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let release = wait_release(&plan, &owner.invocation_id)?;
    let admission: Admission = serde_json::from_value(receipt::bound(&release.admission)?)?;
    let budget = contract::admit(
        &plan,
        &pb,
        &owner,
        &admission,
        native::now()?,
        receipt::bound,
        native::utc_seconds,
    )?;
    ensure!(
        receipt::available(&plan.work())? >= budget.required_initial_free,
        "initial frozen-copy/output reservation does not fit"
    );
    let mut guard = native::Watch::new(&plan, &admission, budget)?;
    // No campaign archive descriptor is opened above this point.
    guard.check(true)?;
    let source_file = receipt::open(&plan.source)?;
    receipt::unchanged(&plan.source, &source_file, &plan.source_identity)?;
    let manifest_file = receipt::open(&plan.manifest.path)?;
    receipt::unchanged(&plan.manifest.path, &manifest_file, &plan.manifest_identity)?;
    let frozen_root = plan.work().join("frozen-source");
    receipt::directory(&frozen_root)?;
    write_scope::same_mount(&[&plan.work(), &frozen_root])?;
    let frozen_source = frozen_root.join("epoch-145-focused.jet");
    let frozen_manifest = frozen_root.join("epoch-145-focused.jet.segment.json");
    let source_copy = receipt::frozen_copy(
        &plan.source,
        &plan.source_identity,
        contract::SOURCE_SHA,
        &frozen_source,
        || guard.check(false),
    )?;
    let manifest_copy = receipt::frozen_copy(
        &plan.manifest.path,
        &plan.manifest_identity,
        contract::MANIFEST_SHA,
        &frozen_manifest,
        || guard.check(false),
    )?;
    once(
        &plan.state().join("source-copy.json"),
        &json!({"schema":"horizon-epoch145-separate-frozen-source-copy-v1","plan":pb,
        "original_archive":plan.source,"original_archive_identity":plan.source_identity,"original_manifest":plan.manifest,
        "original_manifest_identity":plan.manifest_identity,"frozen_archive":frozen_source,"frozen_archive_identity":source_copy,
        "frozen_manifest":frozen_manifest,"frozen_manifest_identity":manifest_copy,"archive_sha256":contract::SOURCE_SHA,
        "manifest_sha256":contract::MANIFEST_SHA,"original_custody_changed":false,"tail_slots_retained":71,"resource_credit_bytes":0,"publication_authorized":false,"r2_mutations":false}),
    )?;
    guard.check(true)?;
    let mut source = PinnedSource::open(
        &frozen_source,
        &frozen_manifest,
        digest(contract::MANIFEST_SHA)?,
        PINNED_WORKER_SHA256,
    )?;
    guard.check(true)?;
    let extraction =
        source.extract_private(&plan.work(), contract::OUTPUT, |bytes| guard.output(bytes))?;
    guard.check(true)?;
    receipt::unchanged(&plan.source, &source_file, &plan.source_identity)?;
    receipt::unchanged(&plan.manifest.path, &manifest_file, &plan.manifest_identity)?;
    receipt::persist(
        &plan
            .state()
            .join(format!("outcome-{}.json", owner.invocation_id)),
        &json!({
        "schema":"horizon-epoch145-guarded-private-prefix-outcome-v1","plan":pb,"admission":release.admission,
        "owner":owner,"recorded_unix_seconds":native::now()?,"extraction":extraction,
        "frozen_source_mapping":plan.state().join("source-copy.json"),"original_archive_unchanged":true,
        "original_manifest_unchanged":true,"original_tail_retained":true,"canonical_sidecar_authorized":false,
        "publication_authorized":false,"retirement_authorized":false,"runtime_registry_promoted":false,"r2_mutations":false}),
    )?;
    Ok(())
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if let Err(error) = run(&args) {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entry_point_has_no_direct_unheld_extraction_or_publication_mode() {
        assert!(run(&["runner".into(), "extract".into()]).is_err());
        assert!(run(&["runner".into(), "publish".into()]).is_err());
    }
    #[test]
    fn digest_requires_exact_lowercase_sha256() {
        assert_eq!(digest(&"a".repeat(64)).unwrap(), [0xaa; 32]);
        assert!(digest(&"A".repeat(64)).is_err());
    }
}
