//! Closed191–194 native metadata custody. Never creates a ready/archive receipt.
use super::*;
use serde_json::json;
use std::{collections::BTreeMap, process::Command};
pub(super) const UNIT: &str =
    "jetstreamer-root-sweep-e191-194-t5-20261016-v2-r2-e191-194-lane-a-1.service";
pub(super) const IID: &str = "ea93199ed2fa470d99de248c2a10b246";
pub(super) const CONTROLLER: &str = "jetstreamer-epochs191-194-target5-controller-v2-r2.service";
pub(super) const CID: &str = "c741f57764384e07a08484e6451f8f0c";
const DEPLOY: &str = "/usr/local/lib/jetstreamer/deploy-epochs191-194-target5-20261016-v1";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const MANIFEST_SHA: &str = "8e16ef3a6f8ae1b2ea3614fbafcb18be34136a8c976e63a386c0fc7c176ce6d0";
const FINGERPRINT: &str = "sha256:0294b1813c7d9cdd3266af2705602e1e2a8920d2159944e0a26b498f58f653f9";
const SCRIPT: &str = "/usr/local/lib/jetstreamer/controller-epochs191-194-target5-20261016-v2/adaptive-root-cohort-sweep.py";
const SCRIPT_SHA: &str = "62592209a3fc2b659ea4bfb924bbcf34435b4228c87e56232eb6b962b907023e";
const REBIND: &str =
    "/usr/local/lib/jetstreamer/horizon-controller-rebind-proof-20261023-v1/unit-bindings.json";
const REBIND_SHA: &str = "a4ce1f8dd91853e8837fb8bf17b923fa4874c726ed551e84dc7b4ae720f2fab2";
const LANE: &str = "/home/sol/.jetstreamer-private/epochs-191-194-v4-20261009-v1/lane-a";
const RUN: &str = "/home/sol/.jetstreamer-private/epochs-191-194-v4-20261009-v1/lane-a/private/destination-a1c8ba888df3256ab55ded6e75ce724aba84a1ed586599353a73fa1d60696cfa/work/root-cohort-191-194/run-2189644-1792144444502274289";
const STATE: &str = "/var/lib/jetstreamer-root-sweep-epochs191-194-target5-20261016-v2/state.json";
const IMPORT_ROOT: &str = "/home/sol/.jetstreamer-private/epochs191-194-target5-20261016-v2-import";
pub(super) const EVENT_SCHEMA: &str = "jetstreamer-cohort191-delivery-event-v2";
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Claim {
    pub epoch: u64,
    pub phase: String,
    pub unit: String,
    pub invocation_id: String,
    pub expected_exec_start: String,
    pub program: Option<Bound>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    schema: String,
    observer: Bound,
    forecast: Bound,
    origins: BTreeMap<u64, Bound>,
    claims: Vec<Claim>,
    source_batch: Option<Bound>,
    public_batch: Option<Bound>,
    gate_receipts: BTreeMap<u64, BTreeMap<String, Bound>>,
    output: PathBuf,
}
pub(super) fn bound(b: &Bound, sealed: bool) -> Result<Value> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && (!sealed || m.mode() & 0o222 == 0),
        "unsafe191 bound evidence"
    );
    let bytes = read_stable_bounded(&b.path, 16 << 20, "191 evidence")?;
    ensure!(
        is_lower_hex(&b.sha256, 64) && hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "191 evidence changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn member(path: &Path, digest: &str) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0,
        "unsealed191 tool"
    );
    ensure!(
        hex_lower(&Sha256::digest(read_stable_bounded(
            path,
            256 << 20,
            "191 pinned tool"
        )?)) == digest,
        "191 tool digest differs"
    );
    Ok(())
}
fn inputs() -> Result<Value> {
    member(&Path::new(DEPLOY).join("jetstreamer-node"), NODE_SHA)?;
    member(
        &Path::new(DEPLOY).join("preflight-191-194-v4.json"),
        MANIFEST_SHA,
    )?;
    member(Path::new(SCRIPT), SCRIPT_SHA)?;
    bound(
        &Bound {
            path: REBIND.into(),
            sha256: REBIND_SHA.into(),
        },
        true,
    )
}
fn prefix(v: &Value) -> Option<&str> {
    v.as_str()?
        .split_once(" ; ignore_errors=")
        .map(|(a, b)| if b.starts_with("no ;") { a } else { "" })
}
fn live(v: &Value, c: &Claim) -> Result<()> {
    ensure!(
        v["Id"] == c.unit
            && v["InvocationID"] == c.invocation_id
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["MainPID"]
                .as_str()
                .is_some_and(|s| s.parse::<u64>().is_ok_and(|n| n > 0))
            && pipeline_status::same_exec_start(
                &c.expected_exec_start,
                v["ExecStart"].as_str().unwrap_or("")
            ),
        "191 owner changed or not active"
    );
    Ok(())
}
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    (phase == "producer-finalization" && unit == UNIT)
        || (phase == "controller-import-handoff" && unit == CONTROLLER)
}
pub(super) fn binding(unit: &str, iid: &str, origin: &str, oid: &str) -> bool {
    unit == CONTROLLER && iid == CID && origin == UNIT && oid == IID
}
pub(super) fn origin(epoch: u64, unit: &str, iid: &str) -> bool {
    (191..=194).contains(&epoch) && unit == UNIT && iid == IID
}
pub(super) fn archives(epoch: u64, phase: &str) -> PathBuf {
    match phase {
        "producer-finalization" => Path::new(RUN).join(format!("archives/epoch-{epoch}.jet")),
        "controller-import-handoff" => Path::new(LANE).join(format!("output/epoch-{epoch}.jet")),
        _ => Path::new("/home/sol/horizon").join(format!("epoch-{epoch}.jet")),
    }
}
fn roots(records: &[Value], cutoff: u64) -> Result<Value> {
    let r = records
        .iter()
        .filter(|r| {
            r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.contains("historical checkpoint slot=84239250 "))
        })
        .collect::<Vec<_>>();
    ensure!(r.len() == 1, "191 final canonical root absent or ambiguous");
    for row in records {
        ensure!(
            row["_SYSTEMD_UNIT"] == UNIT
                && row["_SYSTEMD_INVOCATION_ID"] == IID
                && row["_PID"] == "2189644"
                && row["_UID"] == "1001",
            "191 native journal owner differs"
        );
        let t = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("191 journal timestamp")?
            .parse::<u64>()?;
        ensure!(
            t > 0
                && t <= cutoff
                    .checked_mul(1_000_000)
                    .context("191 cutoff overflow")?,
            "191 event after cutoff"
        );
    }
    cohort198_finalization::checkpoint(r[0]["MESSAGE"].as_str().unwrap(), 84239250)?;
    let f = cohort198_finalization::fields(
        r[0]["MESSAGE"].as_str().unwrap(),
        "historical checkpoint ",
    )?;
    ensure!(
        f["accounts_hash"] == "GCANVakrcunYu9VRe1WdNd7xAPKGdoZNFgpQbagdB9zq",
        "191 manifest root mismatch"
    );
    let mut closes = records
        .iter()
        .filter(|r| {
            r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.contains("horizon archive complete:"))
        })
        .collect::<Vec<_>>();
    closes.sort_by_key(|r| {
        r["__REALTIME_TIMESTAMP"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
    });
    ensure!(
        closes.len() == 4,
        "191 complete cohort archive closes absent/ambiguous"
    );
    for row in &closes {
        let f = cohort198_finalization::fields(
            row["MESSAGE"].as_str().unwrap(),
            "horizon archive complete: ",
        )?;
        ensure!(
            cohort198_finalization::integer(&f, "slots")? == 432000
                && cohort198_finalization::integer(&f, "epochs")? == 1
                && cohort198_finalization::integer(&f, "buckets")? == 3375
                && cohort198_finalization::integer(&f, "bytes")? > 0,
            "191 archive close scope differs"
        );
    }
    ensure!(
        r[0]["__REALTIME_TIMESTAMP"]
            .as_str()
            .unwrap()
            .parse::<u64>()?
            < closes[3]["__REALTIME_TIMESTAMP"]
                .as_str()
                .unwrap()
                .parse::<u64>()?,
        "191 final archive precedes trusted root"
    );
    Ok(
        json!({"trusted_root_slot":84239250,"archive_terminal_slot":84239999,"root":r[0],"closes":closes}),
    )
}
fn native_events(cutoff: u64) -> Result<Value> {
    let out = Command::new("/usr/bin/journalctl")
        .args([
            &format!("_SYSTEMD_UNIT={UNIT}"),
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
            "--grep=historical checkpoint slot=84239250 |horizon archive complete:",
            "--no-pager",
            "-n",
            "32",
            "-o",
            "json",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "191 native journal failed"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    roots(&rows, cutoff)
}
fn manager_terminal(cutoff: u64) -> Result<Value> {
    let out = Command::new("/usr/bin/journalctl")
        .args([
            "_PID=1",
            "_UID=0",
            &format!("UNIT={UNIT}"),
            "--no-pager",
            "-n",
            "64",
            "-o",
            "json",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "191 terminal manager unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let own = rows
        .iter()
        .filter(|r| {
            r["UNIT"] == UNIT
                && r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["INVOCATION_ID"].as_str().is_some_and(|s| !s.is_empty())
        })
        .collect::<Vec<_>>();
    ensure!(
        own.last().is_some_and(|r| r["INVOCATION_ID"] == IID),
        "191 producer replaced since original invocation"
    );
    let end = own
        .iter()
        .rposition(|r| {
            r["INVOCATION_ID"] == IID
                && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                && r["MESSAGE"] == format!("{UNIT}: Deactivated successfully.")
        })
        .context("191 clean manager terminal missing")?;
    ensure!(
        !own[end + 1..].iter().any(|r| r["MESSAGE"]
            .as_str()
            .is_some_and(|s| s.starts_with("Starting ") || s.starts_with("Started "))),
        "191 producer restarted"
    );
    ensure!(
        own[end]["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("191 terminal time")?
            .parse::<u64>()?
            <= cutoff
                .checked_mul(1_000_000)
                .context("191 cutoff overflow")?,
        "191 terminal after sample"
    );
    Ok(own[end].clone())
}
fn state_bytes() -> Result<(Vec<u8>, Value)> {
    let m = fs::symlink_metadata(STATE)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o077 == 0,
        "unsafe191 controller state"
    );
    let bytes = read_stable_bounded(Path::new(STATE), 2 << 20, "191 state")?;
    let v: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        v["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3",
        "191 state schema changed"
    );
    Ok((bytes, v))
}
fn decoded_path(v: &Value) -> Result<PathBuf> {
    Ok(String::from_utf8(BASE64_STANDARD.decode(v.as_str().context("191 encoded path")?)?)?.into())
}
fn batch(b: &Bound, public: bool) -> Result<Value> {
    let allowed = if public { PathBuf::from(IMPORT_ROOT) } else { Path::new(LANE).join("private") };
    ensure!(
        b.path.starts_with(&allowed)
            && b.path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("batch-") && s.ends_with(".json")),
        "191 foreign batch receipt"
    );
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        m.is_file() && m.uid() == 1001 && m.nlink() == 1 && m.mode() & 0o022 == 0,
        "191 batch ownership differs"
    );
    let bytes = read_stable_bounded(&b.path, 4 << 20, "191 native committed batch")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "191 batch digest changed"
    );
    let v: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        v["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && v["epochs"] == json!([191, 192, 193, 194])
            && v["manifest_fingerprint"] == FINGERPRINT
            && v["outcome"]["kind"] == "committed"
            && v["root_checkpoint_gate"]["kind"] == "sealed-root-checkpoint-cohort"
            && v["root_checkpoint_gate"]["members"]
                .as_array()
                .is_some_and(|a| a
                    .iter()
                    .map(|m| m["epoch"].as_u64())
                    .eq((191..=194).map(Some)))
            && v["outcome"]["members"].as_array().is_some_and(|a| a
                .iter()
                .map(|m| m["epoch"].as_u64())
                .eq((191..=194).map(Some))),
        "191 native batch scope/commit gate differs"
    );
    let destination = if public {
        PathBuf::from("/home/sol/horizon")
    } else {
        Path::new(LANE).join("output")
    };
    ensure!(
        decoded_path(&v["destination"]["path_base64"])? == destination,
        "191 batch destination changed"
    );
    for row in v["outcome"]["members"].as_array().unwrap() {
        let epoch = row["epoch"].as_u64().unwrap();
        let path = destination.join(format!("epoch-{epoch}.jet"));
        ensure!(
            decoded_path(&row["archive_path_base64"])? == path
                && is_lower_hex(row["archive_sha256"].as_str().unwrap_or(""), 64),
            "191 batch archive binding differs"
        );
        let i = regular_identity(&path)?;
        ensure!(
            row["committed_archive"]["device"] == i.device
                && row["committed_archive"]["inode"] == i.inode
                && row["committed_archive"]["length"] == i.length,
            "191 batch artifact changed"
        );
        let checksum = read_stable_bounded(
            &destination.join(format!("epoch-{epoch}.jet.sha256")),
            512,
            "191 sidecar",
        )?;
        ensure!(
            parse_canonical_sidecar(epoch, &checksum).as_deref() == row["archive_sha256"].as_str(),
            "191 local sidecar changed"
        );
    }
    Ok(v)
}
fn phase_scope(c: &Claim) -> Result<()> {
    ensure!(
        (191..=194).contains(&c.epoch) && is_lower_hex(&c.invocation_id, 32),
        "foreign191 claim"
    );
    if scope(&c.phase, &c.unit) {
        ensure!(
            (c.unit == UNIT && c.invocation_id == IID)
                || (c.unit == CONTROLLER && c.invocation_id == CID),
            "191 fixed owner mismatch"
        );
    } else {
        ensure!(
            matches!(
                c.phase.as_str(),
                "local-publication"
                    | "full-verification"
                    | "plugin-verification"
                    | "upload-readback"
            ) && fleet::pipeline_unit_range_for_epoch(&c.phase, &c.unit, c.epoch)?
                .contains(&c.epoch),
            "foreign191 stage"
        );
        if c.phase == "local-publication" {
            ensure!(
                c.unit
                    .starts_with("jetstreamer-root-import-e191-194-t5-20261016-v2-r2-e191-194-"),
                "191 importer owner differs"
            );
        } else {
            ensure!(
                c.program.is_some(),
                "191 downstream stage lacks pinned native program"
            );
        }
    }
    Ok(())
}
fn program(c: &Claim, u: &Value) -> Result<()> {
    if let Some(b) = &c.program {
        ensure!(
            b.path.starts_with("/usr/local/lib/jetstreamer"),
            "191 downstream program is not deployed"
        );
        member(&b.path, &b.sha256)?;
        let pid = u["MainPID"].as_str().context("191 downstream PID")?;
        ensure!(
            fs::read_link(format!("/proc/{pid}/exe"))? == b.path,
            "191 watcher wrapper is not its actual native verifier/uploader"
        );
    }
    Ok(())
}
pub(super) fn validate_event(v: &Value, cutoff: u64) -> Result<()> {
    ensure!(
        v["schema"] == EVENT_SCHEMA
            && v["first_epoch"] == 191
            && v["last_epoch"] == 194
            && v["sample_unix_seconds"] == cutoff
            && v["resource_samples"] == 0,
        "191 event scope/time changed"
    );
    for flag in [
        "publication_authorized",
        "replay_launch_authorized",
        "r2_mutations",
        "archive_readiness_claimed",
    ] {
        ensure!(v[flag] == false, "191 event grants {flag}");
    }
    let claims: Vec<Claim> = serde_json::from_value(v["claims"].clone())?;
    ensure!(
        claims.iter().map(|c| c.epoch).eq(191..=194),
        "191 event omits/reorders cohort"
    );
    for c in &claims {
        phase_scope(c)?;
    }
    Ok(())
}
fn capture(p: &Capture) -> Result<Value> {
    let o = bound(&p.observer, false)?;
    let sample = o["recorded_at_utc"]
        .as_str()
        .context("191 coordinated sample")?;
    let cutoff = fleet::utc_seconds(sample)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        p.schema == "jetstreamer-cohort191-delivery-capture-plan-v2"
            && cutoff <= now
            && now - cutoff <= 1800
            && p.origins.keys().copied().eq(191..=194)
            && p.claims.iter().map(|c| c.epoch).eq(191..=194),
        "191 capture scope/staleness"
    );
    let history = inputs()?;
    let events = native_events(cutoff)?;
    let forecast: jetstreamer_horizon_observe::cohort191_delivery_model::Plan =
        serde_json::from_value(bound(&p.forecast, true)?)?;
    let eta = jetstreamer_horizon_observe::cohort191_delivery_model::forecast(&forecast)?;
    let mut census = BTreeMap::new();
    for c in &p.claims {
        phase_scope(c)?;
        let u = fleet::unit(&c.unit)?;
        live(&u, c)?;
        program(c, &u)?;
        census.insert(c.unit.clone(), u);
    }
    let producer = fleet::unit(UNIT)?;
    let controller = fleet::unit(CONTROLLER)?;
    ensure!(
        prefix(&controller["ExecStart"])
            == prefix(&history["current_units"][CONTROLLER]["ExecStart"]),
        "191 controller command/rebind changed"
    );
    let all_final = p.claims.iter().all(|c| c.phase == "producer-finalization");
    let state = if all_final {
        ensure!(
            producer["MainPID"] == "2189644"
                && prefix(&producer["ExecStart"])
                    == prefix(&history["current_units"][UNIT]["ExecStart"]),
            "191 original parent changed"
        );
        for (i, row) in events["closes"].as_array().unwrap().iter().enumerate() {
            let f = cohort198_finalization::fields(
                row["MESSAGE"].as_str().unwrap(),
                "horizon archive complete: ",
            )?;
            ensure!(
                regular_identity(&archives(191 + i as u64, "producer-finalization"))?.length
                    == cohort198_finalization::integer(&f, "bytes")?,
                "191 closing file changed"
            );
        }
        Value::Null
    } else {
        let terminal = manager_terminal(cutoff)?;
        ensure!(
            producer["MainPID"] == "0"
                && matches!(producer["ActiveState"].as_str(), Some("inactive"))
                && (producer["InvocationID"] == IID
                    || (producer["LoadState"] == "not-found" && producer["InvocationID"] == "")),
            "191 producer not cleanly terminal"
        );
        let (bytes, s) = state_bytes()?;
        let a = &s["assignments"]["lane-a"];
        let source = batch(
            p.source_batch
                .as_ref()
                .context("191 source batch required")?,
            false,
        )?;
        if p.claims.iter().any(|c| {
            matches!(
                c.phase.as_str(),
                "controller-import-handoff" | "local-publication"
            )
        }) {
            ensure!(
                a["first_epoch"] == 191
                    && a["last_epoch"] == 194
                    && a["unit"] == UNIT
                    && a["pid"] == 2189644
                    && a["source_recovery"] != true
                    && a["failure"].is_null()
                    && a["receipt"].as_str() == p.source_batch.as_ref().unwrap().path.to_str()
                    && matches!(a["phase"].as_str(), Some("staged" | "importing")),
                "191 pending/import assignment changed"
            );
            for c in &p.claims {
                if c.phase == "local-publication" {
                    ensure!(
                        a["phase"] == "importing"
                            && a["import_unit"] == c.unit
                            && s["import_owner"] == "lane-a",
                        "191 actual importer missing from root state"
                    );
                    let expected = format!(
                        "{{ path={DEPLOY}/jetstreamer-node ; argv[]={DEPLOY}/jetstreamer-node 191-194 /home/sol/horizon --verify --recover-staged-cohort-only --cohort-manifest={DEPLOY}/preflight-191-194-v4.json --cohort-manifest-fingerprint={FINGERPRINT} --source-cohort-receipt={} --publish-through-epoch=194",
                        p.source_batch.as_ref().unwrap().path.display()
                    );
                    ensure!(
                        prefix(&Value::String(c.expected_exec_start.clone()))
                            == Some(expected.as_str()),
                        "191 importer command differs"
                    );
                }
            }
        } else {
            let public = batch(
                p.public_batch
                    .as_ref()
                    .context("191 imported public batch required")?,
                true,
            )?;
            let complete = &s["completed"]["191-194"];
            ensure!(
                complete["receipt"].as_str() == p.public_batch.as_ref().unwrap().path.to_str()
                    && complete["receipt_sha256"] == p.public_batch.as_ref().unwrap().sha256,
                "191 public root attestation missing"
            );
            for n in 0..4 {
                ensure!(
                    source["outcome"]["members"][n]["archive_sha256"]
                        == public["outcome"]["members"][n]["archive_sha256"],
                    "191 import semantics changed"
                );
            }
            for name in [
                ".jetstreamer-archive-batch",
                ".jetstreamer-archive-batch-outcome",
            ] {
                ensure!(
                    fs::symlink_metadata(Path::new("/home/sol/horizon").join(name))
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "191 public transaction pending"
                );
            }
        }
        ensure!(
            read_stable_bounded(Path::new(STATE), 2 << 20, "191 state recheck")? == bytes,
            "191 controller assignment changed"
        );
        json!({"state":s,"sha256":hex_lower(&Sha256::digest(&bytes)),"producer_terminal":terminal})
    };
    for c in &p.claims {
        ensure!(
            fleet::unit(&c.unit)? == census[&c.unit],
            "191 owner changed during capture"
        );
    }
    let v = json!({"schema":EVENT_SCHEMA,"first_epoch":191,"last_epoch":194,"sampled_at_utc":sample,"sample_unix_seconds":cutoff,
        "observer":p.observer,"origins":p.origins,"forecast":p.forecast,"estimated_remaining_millis":eta,"claims":p.claims,"unit_census":census,
        "native_events":events,"controller":controller,"producer":producer,"controller_handoff":state,"source_batch":p.source_batch,"public_batch":p.public_batch,
        "gate_receipts":p.gate_receipts,"resource_samples":0,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false,"archive_readiness_claimed":false});
    validate_event(&v, cutoff)?;
    Ok(v)
}
pub(super) fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        (a.len() == 7 || (a.len() == 8 && a[7] == "--check-only"))
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "observe-delivery-191 PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    member(&fs::read_link("/proc/self/exe")?, &a[6])?;
    let b = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let p: Capture = serde_json::from_value(bound(&b, true)?)?;
    ensure!(
        p.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-cohort191-delivery-")),
        "191 output namespace differs"
    );
    let mut v = capture(&p)?;
    v["capture_plan"] = json!(b);
    v["capture_self_sha256"] = json!(a[6]);
    if a.len() == 8 {
        println!("191 capture preflight passed; no writes");
        return Ok(());
    }
    fleet::persist(&p.output, &v)?;
    println!("{}", p.output.display());
    Ok(())
}

pub(super) fn fleet_proof(
    epoch: u64,
    phase: &str,
    unit: &str,
    iid: &str,
    evidence: &Value,
    census: &BTreeMap<String, Value>,
    sample: u64,
) -> Result<Option<Value>> {
    if !(191..=194).contains(&epoch) || evidence["schema"] != EVENT_SCHEMA {
        return Ok(None);
    }
    validate_event(evidence, sample)?;
    let claims: Vec<Claim> = serde_json::from_value(evidence["claims"].clone())?;
    let c = claims
        .iter()
        .find(|c| c.epoch == epoch)
        .context("191 claim missing")?;
    ensure!(
        c.phase == phase
            && c.unit == unit
            && c.invocation_id == iid
            && evidence["unit_census"][unit] == census[unit],
        "191 event/live fleet differs"
    );
    live(&census[unit], c)?;
    program(c, &census[unit])?;
    Ok(Some(evidence.clone()))
}
