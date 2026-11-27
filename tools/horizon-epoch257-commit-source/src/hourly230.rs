//! Collect local terminal evidence for admitted epoch 230 hourly windows.
use super::{command, identity, one_event, read_bound, sha256};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt, path::Path};

type BoundFile = (&'static str, &'static str);

enum Bootstrap {
    AdjacentSegment(BoundFile),
    Snapshot {
        restore: BoundFile,
        uri: &'static str,
        accounts: &'static str,
        sha256: &'static str,
    },
}

struct Window {
    schema: &'static str,
    unit: &'static str,
    invocation: &'static str,
    archive: &'static str,
    first: u64,
    last: u64,
    launch: BoundFile,
    edges: BoundFile,
    terminal_gcs: BoundFile,
    terminal_generation: &'static str,
    terminal_accounts: &'static str,
    bootstrap: Bootstrap,
}

const NODE: &str =
    "/var/lib/jetstreamer/horizon230-continuation-stock-10eaffb0-v1/jetstreamer-node";
const WORKER: &str = "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c";

const FIRST: Window = Window {
    schema: "foundation-epoch230-hourly-first-terminal-source-v1",
    unit: "horizon-qualify-230-middle-hourly-first-v1.service",
    invocation: "763d461014f042f7bc4591a3b8ec9ac5",
    archive: "/home/ubuntu/.jetstreamer-private/qualification-230-middle-hourly-first-v1/work/output/epoch-230-slots-99437434-99476782.jet",
    first: 99_437_434,
    last: 99_476_782,
    launch: (
        "/var/lib/jetstreamer/horizon230-middle-hourly-first-runtime-v1/cadence-registration.json",
        "42cada1d0f0e983922c93aeadac872fb00585b04ac43964568c1c115fb3b4dfd",
    ),
    edges: (
        "/var/lib/jetstreamer/horizon230-hourly-first-finalized-edges-v1/edges.json",
        "374c2320b38985f518545054fe6aa51fffc87c85d5ee2a408af89f77e978ec52",
    ),
    terminal_gcs: (
        "/var/lib/jetstreamer/horizon230-middle-hourly-first-runtime-v1/terminal-gcs-metadata.json",
        "69b26aab7fa68435f857e9c0285804efec538f75cebd0a1d68ba637c52c33570",
    ),
    terminal_generation: "1633495975351467",
    terminal_accounts: "26wibqVauVjaet3eM6o8hssvaXi4awt7ndjwCaYJZyPK",
    bootstrap: Bootstrap::AdjacentSegment((
        "/var/lib/jetstreamer/horizon230-vote-boundary-sealed-segment-v1/epoch-230-vote-boundary-demotion-diagnostic.jet.segment.json",
        "8351f40f31fd5b2ddae0b0b924e226c52094d00dd0e66eacd6ad0856ec376de3",
    )),
};

const SECOND: Window = Window {
    schema: "foundation-epoch230-hourly-second-terminal-source-v1",
    unit: "horizon-qualify-230-middle-hourly-second-v1.service",
    invocation: "a0a94d2d42984804877c1a80fc934585",
    archive: "/home/ubuntu/.jetstreamer-private/qualification-230-middle-hourly-second-v1/work/output/epoch-230-slots-99476783-99516304.jet",
    first: 99_476_783,
    last: 99_516_304,
    launch: (
        "/var/lib/jetstreamer/horizon230-middle-hourly-second-runtime-v1/cadence-registration.json",
        "c2aea886494f66ed6e2077422894abf68f644a346181da989ac869d9aba43cac",
    ),
    edges: (
        "/var/lib/jetstreamer/horizon230-hourly-second-finalized-edges-v1/edges.json",
        "3988f80b818e5c2c04d4f73b18fffaf6c18fff35d74570f6408154f0dac2a7ef",
    ),
    terminal_gcs: (
        "/var/lib/jetstreamer/horizon230-next-hourly-inputs-v1/terminal.json",
        "7028279c348d8dc9cfeb082d9788f2e874b1b59bf166c8c027039ce8171c5ea2",
    ),
    terminal_generation: "1633495975217451",
    terminal_accounts: "CCpNXjpMvVkXW2xNzBHSfNSRc8efttNr3bB3ejex4Q8u",
    bootstrap: Bootstrap::Snapshot {
        restore: (
            "/var/lib/jetstreamer/horizon230-next-hourly-input-stage-v1/stage.log",
            "732d0c0e12fdcf021926fa1c73f41bc7a55ee8aa5655861035fb5dcd76988d7b",
        ),
        uri: "gs://mainnet-beta-ledger-europe-fr2/99359376/hourly/snapshot-99476782-26wibqVauVjaet3eM6o8hssvaXi4awt7ndjwCaYJZyPK.tar.zst#1633495975351467",
        accounts: "26wibqVauVjaet3eM6o8hssvaXi4awt7ndjwCaYJZyPK",
        sha256: "82e04448803996e9d2924d177acd6c66998bfaf183f29aaf43af3026669b8114",
    },
};

fn pinned((path, digest): (&str, &str)) -> Result<Value> {
    let (raw, _) = read_bound(Path::new(path), 1 << 20, 0)?;
    ensure!(sha256(&raw) == digest, "hourly evidence changed: {path}");
    Ok(serde_json::from_slice(&raw)?)
}

fn reference((path, sha256): (&str, &str)) -> Value {
    json!({"path": path, "sha256": sha256})
}

fn state(unit: &str) -> Result<BTreeMap<String, String>> {
    let output = command(
        "/usr/bin/systemctl",
        &[
            "show",
            unit,
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

fn native(window: &Window, pid: &str, marker: &str, manager: &Value) -> Result<Value> {
    let event = one_event(&[
        &format!("_PID={pid}"),
        &format!("_SYSTEMD_INVOCATION_ID={}", window.invocation),
        &format!("--grep={marker}"),
    ])?;
    ensure!(
        event["_EXE"] == NODE
            && event["_SYSTEMD_UNIT"] == window.unit
            && event["_BOOT_ID"] == manager["_BOOT_ID"]
            && timestamp(&event)? <= timestamp(manager)?,
        "epoch 230 journal event is outside the admitted invocation"
    );
    Ok(event)
}

fn checkpoint_message(slot: u64, terminal: &Value) -> Result<String> {
    let text = |key: &str| terminal[key].as_str().context("missing checkpoint hash");
    let number = |key: &str| terminal[key].as_u64().context("missing checkpoint counter");
    Ok(format!(
        "historical checkpoint slot={slot} bank_hash={} accounts_hash={} last_blockhash={} capitalization={} transactions={} tick_height={} complete=true writes={} next_write_version={}",
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
    window: &Window,
    manifest: &Value,
    edges: &Value,
    metadata: &Value,
    checkpoint: &Value,
) -> Result<()> {
    let bootstrap = &manifest["bootstrap"];
    let terminal = &manifest["terminal"];
    let terminal_name = format!(
        "snapshot-{}-{}.tar.zst",
        window.last, window.terminal_accounts
    );
    let terminal_metadata_matches = match window.bootstrap {
        Bootstrap::AdjacentSegment(_) => {
            metadata["slot"] == window.last
                && metadata["metadata"]["generation"] == window.terminal_generation
                && metadata["uri"].as_str().is_some_and(|uri| {
                    uri.ends_with(&format!("/{terminal_name}#{}", window.terminal_generation))
                })
        }
        Bootstrap::Snapshot { .. } => {
            metadata["generation"] == window.terminal_generation
                && metadata["name"]
                    .as_str()
                    .is_some_and(|name| name.ends_with(&format!("/{terminal_name}")))
        }
    };
    ensure!(
        manifest["schema_version"] == 1
            && manifest["epoch"] == 230
            && manifest["output_slot_start"] == window.first
            && manifest["output_slot_count"] == window.last - window.first + 1
            && manifest["worker_executable_sha256"] == WORKER
            && manifest["runtime"]["runtime_profile"] == "solana-v1.6.20"
            && bootstrap["slot"] == window.first - 1
            && bootstrap["slot_complete"] == true
            && edges["bootstrap"]["slot"] == window.first - 1
            && edges["bootstrap"]["blockhash"] == bootstrap["last_blockhash"]
            && terminal["slot"] == window.last
            && terminal["slot_complete"] == true
            && edges["terminal"]["slot"] == window.last
            && edges["terminal"]["blockhash"] == terminal["last_blockhash"]
            && terminal_metadata_matches
            && terminal["accounts_hash"] == window.terminal_accounts,
        "hourly segment differs from its pinned range, worker, finalized edges or accounts checkpoint"
    );
    ensure!(
        checkpoint["MESSAGE"]
            .as_str()
            .context("checkpoint message")?
            .ends_with(&checkpoint_message(window.last, terminal)?),
        "hourly journal differs from the checkpoint manifest"
    );
    Ok(())
}

fn validate_predecessor(bootstrap: &Value, predecessor: &Value) -> Result<()> {
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
            !bootstrap[name].is_null() && bootstrap[name] == predecessor["terminal"][name],
            "hourly bootstrap differs from the verified predecessor at {name}"
        );
    }
    Ok(())
}

fn validate_bootstrap_checkpoint(
    window: &Window,
    bootstrap: &Value,
    digest: &str,
    checkpoint: &Value,
) -> Result<()> {
    let Bootstrap::Snapshot {
        accounts, sha256, ..
    } = window.bootstrap
    else {
        anyhow::bail!("hourly window has no bootstrap snapshot proof");
    };
    ensure!(
        digest == sha256 && bootstrap["accounts_hash"] == accounts,
        "hourly bootstrap does not match the generation-pinned snapshot"
    );
    ensure!(
        checkpoint["MESSAGE"]
            .as_str()
            .context("bootstrap checkpoint message")?
            .ends_with(&checkpoint_message(window.first - 1, bootstrap)?),
        "hourly bootstrap journal differs from the checkpoint manifest"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_evidence_binds_the_predecessor_and_both_canonical_identities() -> Result<()> {
        let (first, last, accounts) = (FIRST.first, FIRST.last, FIRST.terminal_accounts);
        let bootstrap = json!({"slot":first-1,"bank_hash":"left bank","accounts_hash":"left accounts",
            "last_blockhash":"left block","capitalization":5,"transaction_count":3,
            "tick_height":12,"slot_complete":true});
        let terminal = json!({"slot":last,"bank_hash":"right-bank","accounts_hash":accounts,
            "last_blockhash":"right-block","capitalization":5,"transaction_count":23,
            "tick_height":35,"slot_complete":true,"write_count":6,"next_write_version":13});
        let manifest = json!({"schema_version":1,"epoch":230,"output_slot_start":first,
            "output_slot_count":last-first+1,"runtime":{"runtime_profile":"solana-v1.6.20"},
            "worker_executable_sha256":WORKER,"bootstrap":bootstrap,"terminal":terminal});
        let prior = json!({"terminal":bootstrap});
        let edges = json!({"bootstrap":{"slot":first-1,"blockhash":"left block"},
            "terminal":{"slot":last,"blockhash":"right-block"}});
        let metadata = json!({"slot":last,"metadata":{"generation":"1633495975351467"},
            "uri":format!("gs://bucket/snapshot-{last}-{accounts}.tar.zst#1633495975351467")});
        let message = json!({"MESSAGE":format!("[node] {}", checkpoint_message(last, &terminal)?)});
        validate_predecessor(&manifest["bootstrap"], &prior)?;
        validate_segment(&FIRST, &manifest, &edges, &metadata, &message)?;
        let mut changed = manifest["bootstrap"].clone();
        changed["bank_hash"] = json!("other bank");
        assert!(validate_predecessor(&changed, &prior).is_err());
        for (path, value) in [
            ("/output_slot_count", json!(last - first)),
            ("/terminal/last_blockhash", json!("other block")),
            ("/terminal/transaction_count", json!(24)),
        ] {
            let mut changed = manifest.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(
                validate_segment(&FIRST, &changed, &edges, &metadata, &message).is_err(),
                "{path}"
            );
        }
        let mut changed_metadata = metadata.clone();
        changed_metadata["metadata"]["generation"] = json!("123");
        assert!(validate_segment(&FIRST, &manifest, &edges, &changed_metadata, &message).is_err());
        Ok(())
    }

    #[test]
    fn second_window_binds_the_bootstrap_snapshot_to_its_worker_checkpoint() -> Result<()> {
        let Bootstrap::Snapshot {
            accounts, sha256, ..
        } = SECOND.bootstrap
        else {
            panic!("missing second bootstrap snapshot");
        };
        let slot = SECOND.first - 1;
        let bootstrap = json!({"slot":slot,"bank_hash":"left bank","accounts_hash":accounts,
            "last_blockhash":"left block","capitalization":5,"transaction_count":3,
            "tick_height":12,"slot_complete":true,"write_count":0,"next_write_version":42});
        let event = json!({"MESSAGE":checkpoint_message(slot, &bootstrap)?});
        validate_bootstrap_checkpoint(&SECOND, &bootstrap, sha256, &event)?;
        assert!(validate_bootstrap_checkpoint(&SECOND, &bootstrap, "different", &event).is_err());
        let mut changed = bootstrap;
        changed["bank_hash"] = json!("other bank");
        assert!(validate_bootstrap_checkpoint(&SECOND, &changed, sha256, &event).is_err());
        Ok(())
    }
}

pub(super) fn collect(second: bool) -> Result<Value> {
    let window = if second { &SECOND } else { &FIRST };
    let launch = pinned(window.launch)?;
    let pid = launch["main_pid"]
        .as_u64()
        .context("missing admitted producer PID")?
        .to_string();
    ensure!(
        launch["unit"] == window.unit
            && launch["invocation_id"] == window.invocation
            && launch["node_path"] == NODE
            && launch["worker"]["sha256"] == WORKER
            && launch["launched"] == true
            && launch["canonical_epoch_publication_authorized"] == false,
        "hourly launch claim changed"
    );
    let edges = pinned(window.edges)?;
    let metadata = pinned(window.terminal_gcs)?;
    let before = state(window.unit)?;
    let field = |key: &str| before.get(key).map(String::as_str);
    if field("ActiveState") == Some("active") {
        ensure!(
            field("InvocationID") == Some(window.invocation)
                && field("MainPID") == Some(&pid)
                && field("SubState") == Some("running")
                && field("NRestarts") == Some("0"),
            "hourly producer changed"
        );
        return Ok(
            json!({"epoch":230,"state":"replay-active","unit":window.unit,"invocation_id":window.invocation,
            "launch":reference(window.launch),"finalized_edges":reference(window.edges),"terminal_gcs":reference(window.terminal_gcs),
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
        ) && matches!(field("InvocationID"), Some(invocation) if invocation.is_empty() || invocation == window.invocation)
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(window.unit)
                .exists(),
        "hourly producer has not drained cleanly"
    );
    let manager = one_event(&[
        "_PID=1",
        &format!("UNIT={}", window.unit),
        &format!("INVOCATION_ID={}", window.invocation),
        r"--grep=Deactivated successfully\.",
    ])?;
    ensure!(
        manager["MESSAGE"] == format!("{}: Deactivated successfully.", window.unit),
        "foreign manager terminal"
    );
    let checkpoint = native(
        window,
        &pid,
        &format!("historical checkpoint slot={} ", window.last),
        &manager,
    )?;
    let snapshot = native(window, &pid, "snapshot verification complete", &manager)?;
    let reported = native(
        window,
        &pid,
        "published verified historical segment evidence ",
        &manager,
    )?;
    let segment_path = format!("{}.segment.json", window.archive);
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
    validate_segment(window, &manifest, &edges, &metadata, &checkpoint)?;
    let archive = Path::new(window.archive);
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
    let mut receipt = json!({"schema":window.schema,"epoch":230,
        "state":"local-segment-committed","unit":window.unit,"invocation_id":window.invocation,"launch":reference(window.launch),
        "archive":{"path":archive,"native_sha256":digest,"identity":identity(&meta)},
        "segment_manifest":{"path":segment,"sha256":sha256(&raw)},"finalized_edges":reference(window.edges),
        "terminal_gcs":reference(window.terminal_gcs),"producer":before,
        "checkpoint_event":checkpoint,"snapshot_event":snapshot,"segment_event":reported,"manager_event":manager,
        "first_slot":window.first,"last_slot":window.last,"independent_archive_playback_complete":false,
        "guard_drained":false,"publication_authorized":false});
    match window.bootstrap {
        Bootstrap::AdjacentSegment(predecessor) => {
            validate_predecessor(&manifest["bootstrap"], &pinned(predecessor)?)?;
            receipt["predecessor"] = reference(predecessor);
        }
        Bootstrap::Snapshot { restore, uri, .. } => {
            let staged = pinned(restore)?;
            ensure!(
                staged["snapshot_slot"] == window.first - 1
                    && staged["source"] == "generation-pinned-download"
                    && staged["versioned_uri"] == uri
                    && staged["remote_object"]["versioned_uri"] == uri,
                "hourly bootstrap restore receipt changed"
            );
            let bootstrap = native(
                window,
                &pid,
                &format!("historical checkpoint slot={} ", window.first - 1),
                &manager,
            )?;
            ensure!(
                timestamp(&bootstrap)? < timestamp(&checkpoint)?,
                "hourly bootstrap checkpoint follows the terminal checkpoint"
            );
            validate_bootstrap_checkpoint(
                window,
                &manifest["bootstrap"],
                staged["file"]["sha256"]
                    .as_str()
                    .context("bootstrap snapshot digest")?,
                &bootstrap,
            )?;
            receipt["bootstrap_snapshot_restore"] = reference(restore);
            receipt["bootstrap_checkpoint_event"] = bootstrap;
        }
    }
    ensure!(
        before == state(window.unit)?
            && segment_identity == identity(&fs::symlink_metadata(segment)?)
            && identity(&meta) == identity(&fs::symlink_metadata(archive)?),
        "hourly terminal evidence changed"
    );
    Ok(receipt)
}
