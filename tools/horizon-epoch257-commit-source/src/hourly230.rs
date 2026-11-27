//! Collect local terminal evidence for the admitted 39,349-slot epoch 230 window.
use super::{command, identity, one_event, read_bound, sha256};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt, path::Path};

const UNIT: &str = "horizon-qualify-230-middle-hourly-first-v1.service";
const INVOCATION: &str = "763d461014f042f7bc4591a3b8ec9ac5";
const NODE: &str =
    "/var/lib/jetstreamer/horizon230-continuation-stock-10eaffb0-v1/jetstreamer-node";
const ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/qualification-230-middle-hourly-first-v1/work/output/epoch-230-slots-99437434-99476782.jet";
const START: u64 = 99_437_434;
const END: u64 = 99_476_782;
const WORKER: &str = "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c";
const LAUNCH: (&str, &str) = (
    "/var/lib/jetstreamer/horizon230-middle-hourly-first-runtime-v1/cadence-registration.json",
    "42cada1d0f0e983922c93aeadac872fb00585b04ac43964568c1c115fb3b4dfd",
);
const PREDECESSOR: (&str, &str) = (
    "/var/lib/jetstreamer/horizon230-vote-boundary-sealed-segment-v1/epoch-230-vote-boundary-demotion-diagnostic.jet.segment.json",
    "8351f40f31fd5b2ddae0b0b924e226c52094d00dd0e66eacd6ad0856ec376de3",
);
const EDGES: (&str, &str) = (
    "/var/lib/jetstreamer/horizon230-hourly-first-finalized-edges-v1/edges.json",
    "374c2320b38985f518545054fe6aa51fffc87c85d5ee2a408af89f77e978ec52",
);
const GCS: (&str, &str) = (
    "/var/lib/jetstreamer/horizon230-middle-hourly-first-runtime-v1/terminal-gcs-metadata.json",
    "69b26aab7fa68435f857e9c0285804efec538f75cebd0a1d68ba637c52c33570",
);
const ACCOUNTS: &str = "26wibqVauVjaet3eM6o8hssvaXi4awt7ndjwCaYJZyPK";

fn pinned((path, digest): (&str, &str)) -> Result<Value> {
    let (raw, _) = read_bound(Path::new(path), 1 << 20, 0)?;
    ensure!(sha256(&raw) == digest, "hourly evidence changed: {path}");
    Ok(serde_json::from_slice(&raw)?)
}

fn reference((path, sha256): (&str, &str)) -> Value {
    json!({"path": path, "sha256": sha256})
}

fn state() -> Result<BTreeMap<String, String>> {
    let output = command(
        "/usr/bin/systemctl",
        &[
            "show",
            UNIT,
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "InvocationID",
            "-p",
            "MainPID",
            "-p",
            "ControlPID",
            "-p",
            "NRestarts",
            "-p",
            "Result",
            "-p",
            "ExecMainStatus",
            "-p",
            "ControlGroup",
            "-p",
            "Job",
        ],
    )?;
    Ok(std::str::from_utf8(&output)?
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect())
}

fn timestamp(event: &Value) -> Result<u64> {
    Ok(event["__MONOTONIC_TIMESTAMP"]
        .as_str()
        .context("missing journal monotonic timestamp")?
        .parse()?)
}

fn native(pid: &str, marker: &str, manager: &Value) -> Result<Value> {
    let event = one_event(&[
        &format!("_PID={pid}"),
        &format!("_SYSTEMD_INVOCATION_ID={INVOCATION}"),
        &format!("--grep={marker}"),
    ])?;
    ensure!(
        event["_EXE"] == NODE
            && event["_SYSTEMD_UNIT"] == UNIT
            && event["_BOOT_ID"] == manager["_BOOT_ID"]
            && timestamp(&event)? <= timestamp(manager)?,
        "epoch 230 journal event is outside the admitted invocation"
    );
    Ok(event)
}

fn checkpoint_message(terminal: &Value) -> Result<String> {
    let text = |key: &str| terminal[key].as_str().context("missing checkpoint hash");
    let number = |key: &str| terminal[key].as_u64().context("missing checkpoint counter");
    Ok(format!(
        "historical checkpoint slot={END} bank_hash={} accounts_hash={} last_blockhash={} capitalization={} transactions={} tick_height={} complete=true writes={} next_write_version={}",
        text("bank_hash")?,
        text("accounts_hash")?,
        text("last_blockhash")?,
        number("capitalization")?,
        number("transaction_count")?,
        number("tick_height")?,
        number("write_count")?,
        number("next_write_version")?,
    ))
}

fn validate_segment(
    manifest: &Value,
    prior: &Value,
    edges: &Value,
    metadata: &Value,
    checkpoint: &Value,
) -> Result<()> {
    let bootstrap = &manifest["bootstrap"];
    let terminal = &manifest["terminal"];
    for name in [
        "slot",
        "bank_hash",
        "accounts_hash",
        "last_blockhash",
        "capitalization",
        "transaction_count",
        "tick_height",
        "slot_complete",
    ] {
        ensure!(
            !bootstrap[name].is_null() && bootstrap[name] == prior["terminal"][name],
            "hourly bootstrap differs from the verified predecessor at {name}"
        );
    }
    ensure!(
        manifest["schema_version"] == 1
            && manifest["epoch"] == 230
            && manifest["output_slot_start"] == START
            && manifest["output_slot_count"] == END - START + 1
            && manifest["worker_executable_sha256"] == WORKER
            && manifest["runtime"]["runtime_profile"] == "solana-v1.6.20"
            && bootstrap["slot"] == START - 1
            && bootstrap["slot_complete"] == true
            && edges["bootstrap"]["slot"] == START - 1
            && edges["bootstrap"]["blockhash"] == bootstrap["last_blockhash"]
            && terminal["slot"] == END
            && terminal["slot_complete"] == true
            && edges["terminal"]["slot"] == END
            && edges["terminal"]["blockhash"] == terminal["last_blockhash"]
            && metadata["slot"] == END
            && metadata["metadata"]["generation"] == "1633495975351467"
            && metadata["uri"]
                .as_str()
                .is_some_and(|uri| uri.ends_with(&format!(
                    "snapshot-{END}-{ACCOUNTS}.tar.zst#1633495975351467"
                )))
            && terminal["accounts_hash"] == ACCOUNTS,
        "hourly segment differs from its pinned range, worker, finalized edges or accounts checkpoint"
    );
    ensure!(
        checkpoint["MESSAGE"]
            .as_str()
            .context("checkpoint message")?
            .ends_with(&checkpoint_message(terminal)?),
        "hourly journal differs from the checkpoint manifest"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_evidence_binds_the_predecessor_and_both_canonical_identities() -> Result<()> {
        let bootstrap = json!({"slot":START-1,"bank_hash":"left bank","accounts_hash":"left accounts",
            "last_blockhash":"left block","capitalization":5,"transaction_count":3,
            "tick_height":12,"slot_complete":true});
        let terminal = json!({"slot":END,"bank_hash":"right-bank","accounts_hash":ACCOUNTS,
            "last_blockhash":"right-block","capitalization":5,"transaction_count":23,
            "tick_height":35,"slot_complete":true,"write_count":6,"next_write_version":13});
        let manifest = json!({"schema_version":1,"epoch":230,"output_slot_start":START,
            "output_slot_count":END-START+1,"runtime":{"runtime_profile":"solana-v1.6.20"},
            "worker_executable_sha256":WORKER,"bootstrap":bootstrap,"terminal":terminal});
        let prior = json!({"terminal":bootstrap});
        let edges = json!({"bootstrap":{"slot":START-1,"blockhash":"left block"},
            "terminal":{"slot":END,"blockhash":"right-block"}});
        let metadata = json!({"slot":END,"metadata":{"generation":"1633495975351467"},
            "uri":format!("gs://bucket/snapshot-{END}-{ACCOUNTS}.tar.zst#1633495975351467")});
        let message = json!({"MESSAGE":format!("[node] {}", checkpoint_message(&terminal)?)});
        validate_segment(&manifest, &prior, &edges, &metadata, &message)?;
        for (path, value) in [
            ("/bootstrap/bank_hash", json!("other bank")),
            ("/output_slot_count", json!(END - START)),
            ("/terminal/last_blockhash", json!("other block")),
            ("/terminal/transaction_count", json!(24)),
        ] {
            let mut changed = manifest.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(
                validate_segment(&changed, &prior, &edges, &metadata, &message).is_err(),
                "{path}"
            );
        }
        let mut changed_metadata = metadata.clone();
        changed_metadata["metadata"]["generation"] = json!("123");
        assert!(validate_segment(&manifest, &prior, &edges, &changed_metadata, &message).is_err());
        Ok(())
    }
}

pub(super) fn collect() -> Result<Value> {
    let launch = pinned(LAUNCH)?;
    let pid = launch["main_pid"]
        .as_u64()
        .context("missing admitted producer PID")?
        .to_string();
    ensure!(
        launch["unit"] == UNIT
            && launch["invocation_id"] == INVOCATION
            && launch["node_path"] == NODE
            && launch["worker"]["sha256"] == WORKER
            && launch["launched"] == true
            && launch["canonical_epoch_publication_authorized"] == false,
        "hourly launch claim changed"
    );
    let edges = pinned(EDGES)?;
    let metadata = pinned(GCS)?;
    let before = state()?;
    let field = |key: &str| before.get(key).map(String::as_str);
    if field("ActiveState") == Some("active") {
        ensure!(
            field("InvocationID") == Some(INVOCATION)
                && field("MainPID") == Some(&pid)
                && field("SubState") == Some("running")
                && field("NRestarts") == Some("0"),
            "hourly producer changed"
        );
        return Ok(
            json!({"epoch":230,"state":"replay-active","unit":UNIT,"invocation_id":INVOCATION,
            "launch":reference(LAUNCH),"finalized_edges":reference(EDGES),"terminal_gcs":reference(GCS),
            "publication_authorized":false}),
        );
    }
    ensure!(
        (
            field("ActiveState"),
            field("Result"),
            field("MainPID"),
            field("ControlPID"),
            field("ControlGroup"),
            field("Job"),
            field("ExecMainStatus"),
            field("NRestarts")
        ) == (
            Some("inactive"),
            Some("success"),
            Some("0"),
            Some("0"),
            Some(""),
            Some(""),
            Some("0"),
            Some("0")
        ) && matches!(field("InvocationID"), Some("" | INVOCATION))
            && !Path::new("/sys/fs/cgroup/system.slice").join(UNIT).exists(),
        "hourly producer has not drained cleanly"
    );
    let manager = one_event(&[
        "_PID=1",
        &format!("UNIT={UNIT}"),
        &format!("INVOCATION_ID={INVOCATION}"),
        r"--grep=Deactivated successfully\.",
    ])?;
    ensure!(
        manager["MESSAGE"] == format!("{UNIT}: Deactivated successfully."),
        "foreign manager terminal"
    );
    let checkpoint = native(
        &pid,
        &format!("historical checkpoint slot={END} "),
        &manager,
    )?;
    let snapshot = native(&pid, "snapshot verification complete", &manager)?;
    let reported = native(
        &pid,
        "published verified historical segment evidence ",
        &manager,
    )?;
    let segment_path = format!("{ARCHIVE}.segment.json");
    ensure!(
        timestamp(&checkpoint)? <= timestamp(&snapshot)?
            && timestamp(&snapshot)? <= timestamp(&reported)?
            && reported["MESSAGE"]
                .as_str()
                .is_some_and(|message| message.ends_with(&format!(
                    "published verified historical segment evidence {segment_path}"
                ))),
        "hourly checkpoint, verification and segment publication events differ"
    );
    let segment = Path::new(&segment_path);
    let (raw, segment_identity) = read_bound(segment, 1 << 20, 1000)?;
    let manifest: Value = serde_json::from_slice(&raw)?;
    validate_segment(
        &manifest,
        &pinned(PREDECESSOR)?,
        &edges,
        &metadata,
        &checkpoint,
    )?;
    let archive = Path::new(ARCHIVE);
    let meta = fs::symlink_metadata(archive)?;
    let digest = manifest["archive_sha256"]
        .as_str()
        .context("missing archive digest")?;
    ensure!(
        archive.canonicalize()? == archive
            && meta.is_file()
            && meta.uid() == 1000
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() > 0
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "unsafe hourly archive identity"
    );
    ensure!(
        before == state()?
            && segment_identity == identity(&fs::symlink_metadata(segment)?)
            && identity(&meta) == identity(&fs::symlink_metadata(archive)?),
        "hourly terminal evidence changed"
    );
    Ok(
        json!({"schema":"foundation-epoch230-hourly-first-terminal-source-v1","epoch":230,
        "state":"local-segment-committed","unit":UNIT,"invocation_id":INVOCATION,"launch":reference(LAUNCH),
        "archive":{"path":archive,"native_sha256":digest,"identity":identity(&meta)},
        "segment_manifest":{"path":segment,"sha256":sha256(&raw)},"finalized_edges":reference(EDGES),
        "terminal_gcs":reference(GCS),"predecessor":reference(PREDECESSOR),"producer":before,
        "checkpoint_event":checkpoint,"snapshot_event":snapshot,"segment_event":reported,"manager_event":manager,
        "first_slot":START,"last_slot":END,"independent_archive_playback_complete":false,
        "guard_drained":false,"publication_authorized":false}),
    )
}
