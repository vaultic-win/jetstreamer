//! Fixed, read-only finalized RPC collection for epoch 223 canonical boundaries.
//! No archive scan, replay, runtime admission, sidecar, import or R2 operation.
#[allow(dead_code)]
#[path = "../../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[path = "epoch223_assembly/boundaries.rs"]
mod boundaries;
use boundaries::{ENDPOINT, ROLES, derive, request};
const MAX_BYTES: usize = 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    output_directory: PathBuf,
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("metadata output parent")?;
    let mut out = tempfile::NamedTempFile::new_in(parent)?;
    out.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    out.write_all(bytes)?;
    out.as_file().sync_all()?;
    out.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("canonical metadata output occupied: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn binding(path: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o400
            && m.len() <= MAX_BYTES as u64,
        "unsafe existing canonical metadata"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        evidence::identity(&m) == evidence::identity(&file.metadata()?),
        "canonical metadata changed before opening"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_BYTES
            && bytes.len() as u64 == m.len()
            && evidence::identity(&m) == evidence::identity(&file.metadata()?)
            && evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(path)?),
        "canonical metadata changed during bounded read"
    );
    Ok(json!({"path":path,"sha256":evidence::sha(&bytes)}))
}
async fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "canonical metadata collector requires root"
    );
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(args.len() == 3, "usage: PLAN PLAN_SHA256 SELF_SHA256");
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &args[2], 128 << 20, true)?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&args[0]),
        &args[1],
        65536,
        true,
    )?)?;
    ensure!(
        p.schema == "jetstreamer-epoch223-canonical-boundary-collection-plan-v1"
            && p.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-223-canonical-metadata-")),
        "canonical metadata output scope differs"
    );
    let d = &p.output_directory;
    let m = fs::symlink_metadata(d)?;
    ensure!(
        d.canonicalize()? == *d && m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "canonical metadata directory must be root-private"
    );
    let intent_path = d.join("collection-intent.json");
    let intent = json!({"schema":"jetstreamer-epoch223-canonical-boundary-collection-intent-v1",
        "collector_sha256":args[2],"plan":{"path":args[0],"sha256":args[1]},"endpoint":ENDPOINT,
        "output_directory":d,"remote_mutations":false,"r2_mutations":false});
    if intent_path.try_exists()? {
        let b = binding(&intent_path)?;
        let old: Value = serde_json::from_slice(&evidence::bound_file(
            &intent_path,
            b["sha256"].as_str().unwrap(),
            MAX_BYTES as u64,
            true,
        )?)?;
        ensure!(
            old == intent,
            "canonical metadata operation identity changed"
        );
    } else {
        ensure!(
            fs::read_dir(d)?.next().is_none(),
            "new canonical metadata collection must start in an empty private directory"
        );
        write(&intent_path, &serde_json::to_vec_pretty(&intent)?)?;
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut requests = BTreeMap::new();
    let mut responses = BTreeMap::new();
    let mut rows = BTreeMap::new();
    let mut network_requests = 0u64;
    for (role, slot) in ROLES {
        let wanted = serde_json::to_vec(&request(slot))?;
        let rq = d.join(format!("{role}.request.json"));
        let rp = d.join(format!("{role}.response.json"));
        if rq.try_exists()? {
            let b = binding(&rq)?;
            ensure!(
                b["sha256"] == evidence::sha(&wanted),
                "existing canonical request differs"
            );
        } else {
            write(&rq, &wanted)?;
        }
        if !rp.try_exists()? {
            let mut response = client
                .post(ENDPOINT)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(wanted)
                .send()
                .await?;
            ensure!(
                response.status().is_success()
                    && response
                        .content_length()
                        .is_none_or(|n| n <= MAX_BYTES as u64),
                "canonical RPC HTTP response failed/oversized"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    bytes
                        .len()
                        .checked_add(chunk.len())
                        .is_some_and(|n| n <= MAX_BYTES),
                    "canonical RPC response exceeds bounded metadata size"
                );
                bytes.extend_from_slice(&chunk);
            }
            // Preserve actual error/null bytes too. A rerun never overwrites them.
            write(&rp, &bytes)?;
            network_requests += 1;
        }
        let rb = binding(&rp)?;
        let raw =
            evidence::bound_file(&rp, rb["sha256"].as_str().unwrap(), MAX_BYTES as u64, true)?;
        rows.insert(role.into(), serde_json::from_slice(&raw)?);
        requests.insert(role, binding(&rq)?);
        responses.insert(role, rb);
    }
    let derived = derive(&rows)?;
    let receipt = json!({"schema":"jetstreamer-private-epoch223-boundary-metadata-v1","epoch":223,"endpoint":ENDPOINT,
        "collector_sha256":args[2],"plan":{"path":args[0],"sha256":args[1]},"requests":requests,"responses":responses,
        "derived":derived,"finalized_commitment_requested":true,"redirects_permitted":false,"raw_rpc_responses_rehashed":true,
        "network_requests_this_invocation":network_requests,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "archive_opened":false,"archive_initial_boundary_verified":false,"complete_coverage_verified":false,"independent_full_poh_verified":false,
        "runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let output = d.join("candidate.json");
    if output.try_exists()? {
        let b = binding(&output)?;
        let old: Value = serde_json::from_slice(&evidence::bound_file(
            &output,
            b["sha256"].as_str().unwrap(),
            MAX_BYTES as u64,
            true,
        )?)?;
        for key in [
            "schema",
            "epoch",
            "endpoint",
            "collector_sha256",
            "plan",
            "requests",
            "responses",
            "derived",
        ] {
            ensure!(
                old[key] == receipt[key],
                "existing canonical candidate conflicts:{key}"
            );
        }
    } else {
        let mut bytes = serde_json::to_vec_pretty(&receipt)?;
        bytes.push(b'\n');
        write(&output, &bytes)?;
    }
    println!(
        "canonical epoch 223 metadata preserved; independent V3 full/plugin/import gates remain closed"
    );
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}
