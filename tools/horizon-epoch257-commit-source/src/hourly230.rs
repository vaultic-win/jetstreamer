//! Collect local terminal evidence for admitted epoch 230 hourly windows.
use super::{command, identity, one_event, read_bound, sha256};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

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

#[derive(Clone, Copy)]
enum Edges {
    Packet(BoundFile),
    ReusedBootstrap {
        prior: BoundFile,
        terminal_rpc: BoundFile,
    },
}

const FIRST_EDGES: BoundFile = (
    "/var/lib/jetstreamer/horizon230-hourly-first-finalized-edges-v1/edges.json",
    "374c2320b38985f518545054fe6aa51fffc87c85d5ee2a408af89f77e978ec52",
);
const FIRST_PREDECESSOR: BoundFile = (
    "/var/lib/jetstreamer/horizon230-vote-boundary-sealed-segment-v1/epoch-230-vote-boundary-demotion-diagnostic.jet.segment.json",
    "8351f40f31fd5b2ddae0b0b924e226c52094d00dd0e66eacd6ad0856ec376de3",
);
const FIRST_7871_RECHECK: BoundFile = (
    "/var/lib/jetstreamer/horizon230-first-7871-runtime-v1/bootstrap-recheck.json",
    "f9b0e12266baf8ab0fd20aeb521df33121926e9915eb3e3aa708991bfe86ee52",
);
const FIRST_STOCK_PROGRESS: BoundFile = (
    "/var/lib/jetstreamer/horizon230-first-7871-preflight-v1/prior-end-slot.json",
    "8ebfafbaa338361326465e1dc85e8ae877725891403e2f3d43b3a4c10202af86",
);
const FIRST_7871_BANK: &str = "F1C6Qe59yaHMBNyf4RUbzmTeqbEzM8QYzzQKKwYMSr1f";

pub(super) struct Window {
    schema: &'static str,
    unit: &'static str,
    invocation: &'static str,
    archive: &'static str,
    first: u64,
    last: u64,
    launch: BoundFile,
    edges: Edges,
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
    edges: Edges::Packet(FIRST_EDGES),
    terminal_gcs: (
        "/var/lib/jetstreamer/horizon230-middle-hourly-first-runtime-v1/terminal-gcs-metadata.json",
        "69b26aab7fa68435f857e9c0285804efec538f75cebd0a1d68ba637c52c33570",
    ),
    terminal_generation: "1633495975351467",
    terminal_accounts: "26wibqVauVjaet3eM6o8hssvaXi4awt7ndjwCaYJZyPK",
    bootstrap: Bootstrap::AdjacentSegment(FIRST_PREDECESSOR),
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
    edges: Edges::Packet((
        "/var/lib/jetstreamer/horizon230-hourly-second-finalized-edges-v1/edges.json",
        "3988f80b818e5c2c04d4f73b18fffaf6c18fff35d74570f6408154f0dac2a7ef",
    )),
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

const FIRST_7871: Window = Window {
    schema: "foundation-epoch230-first-7871-terminal-source-v1",
    unit: "horizon-qualify-230-first-7871-v1.service",
    invocation: "02b7dd1683d24efbabf6b5c2f8ff6a43",
    archive: "/home/ubuntu/.jetstreamer-private/qualification-230-first-7871-v1/work/output/epoch-230-slots-99437434-99445304.jet",
    first: 99_437_434,
    last: 99_445_304,
    launch: (
        "/var/lib/jetstreamer/horizon230-first-7871-runtime-v1/cadence-registration.json",
        "837bca79f370c14e6345fa1f36af77ec43e8575c111bdacbfab111b1a96d7b0e",
    ),
    edges: Edges::ReusedBootstrap {
        prior: FIRST_EDGES,
        terminal_rpc: (
            "/var/lib/jetstreamer/horizon230-first-7871-preflight-v1/terminal-finalized-block.json",
            "38324d0486c4de2fc30f709867edeca0bb60bb65310ab8f2981babf88ad8378b",
        ),
    },
    terminal_gcs: (
        "/var/lib/jetstreamer/horizon230-first-7871-preflight-v1/terminal-gcs.json",
        "23c20ce8cc38742c27e609ee4e4eed26ffd6f939274421e71a6b116dab8d9c6c",
    ),
    terminal_generation: "1633495970251676",
    terminal_accounts: "2pNDSLmCHAnK2eLvMHmEBnfUmjnSDfqcQ45zak3VR9kc",
    bootstrap: Bootstrap::AdjacentSegment(FIRST_PREDECESSOR),
};

fn pinned((path, digest): (&str, &str)) -> Result<Value> {
    let (raw, _) = read_bound(Path::new(path), 1 << 20, 0)?;
    ensure!(sha256(&raw) == digest, "hourly evidence changed: {path}");
    Ok(serde_json::from_slice(&raw)?)
}

fn reference((path, sha256): (&str, &str)) -> Value {
    json!({"path": path, "sha256": sha256})
}

fn same_start_progress() -> Result<Value> {
    let earlier = pinned(FIRST_STOCK_PROGRESS)?;
    let marker = format!("progress slot {}/{} ", FIRST_7871.last, FIRST.last);
    ensure!(
        earlier["_SYSTEMD_INVOCATION_ID"] == FIRST.invocation
            && earlier["_EXE"] == NODE
            && earlier["_PID"] == validate_launch(&FIRST, &pinned(FIRST.launch)?)?
            && earlier["MESSAGE"]
                .as_str()
                .is_some_and(|message| message.contains(&marker)),
        "prior same-start hourly replay did not record the expected position"
    );
    Ok(reference(FIRST_STOCK_PROGRESS))
}

fn finalized_edges(window: &Window) -> Result<(Value, Value)> {
    match window.edges {
        Edges::Packet(file) => Ok((pinned(file)?, reference(file))),
        Edges::ReusedBootstrap {
            prior,
            terminal_rpc,
        } => {
            let previous = pinned(prior)?;
            let response = pinned(terminal_rpc)?;
            ensure!(
                previous["bootstrap"]["slot"] == window.first - 1
                    && response["id"] == format!("foundation-epoch230-bounded-{}", window.last)
                    && response["result"]["parentSlot"] == window.last - 1
                    && response["result"]["blockhash"]
                        == "AP7s2cdR2WsmPDjLnKus4dkNzABrMotKuoFh1d2kCNeC",
                "first-window finalized block evidence differs"
            );
            Ok((
                json!({"bootstrap": previous["bootstrap"], "terminal": {
                    "slot": window.last, "blockhash": response["result"]["blockhash"]}}),
                json!({"bootstrap_packet": reference(prior), "terminal_rpc": reference(terminal_rpc)}),
            ))
        }
    }
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
            && event["_PID"] == pid
            && event["_SYSTEMD_INVOCATION_ID"] == window.invocation
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
    let object_name = format!("99359376/hourly/{terminal_name}");
    let cloud_object = metadata.get("metadata").unwrap_or(metadata);
    let terminal_metadata_matches = cloud_object["bucket"] == "mainnet-beta-ledger-europe-fr2"
        && cloud_object["generation"] == window.terminal_generation
        && cloud_object["name"] == object_name
        && (metadata.get("metadata").is_none()
            || (metadata["slot"] == window.last
                && metadata["uri"]
                    == format!(
                        "gs://mainnet-beta-ledger-europe-fr2/{object_name}#{}",
                        window.terminal_generation
                    )));
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
            && terminal["accounts_hash"] == window.terminal_accounts
            && (window.unit != FIRST_7871.unit || terminal["bank_hash"] == FIRST_7871_BANK),
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

pub(super) fn select(flag: &str) -> Option<&'static Window> {
    match flag {
        "--epoch230-hourly" => Some(&FIRST),
        "--epoch230-hourly-second" => Some(&SECOND),
        "--epoch230-first-7871" => Some(&FIRST_7871),
        _ => None,
    }
}

fn validate_clean_exit(
    window: &Window,
    state: &BTreeMap<String, String>,
    cgroup_exists: bool,
) -> Result<()> {
    let field = |key: &str| state.get(key).map(String::as_str);
    ensure!(
        (
            field("ActiveState"),
            field("Result"),
            field("MainPID"),
            field("ControlPID"),
            field("ControlGroup"),
            field("Job"),
            field("ExecMainStatus"),
            field("NRestarts"),
            field("SubState")
        ) == (
            Some("inactive"),
            Some("success"),
            Some("0"),
            Some("0"),
            Some(""),
            Some(""),
            Some("0"),
            Some("0"),
            Some("dead")
        ) && matches!(field("InvocationID"), Some(invocation) if invocation.is_empty() || invocation == window.invocation)
            && !cgroup_exists,
        "hourly producer has not drained cleanly"
    );
    Ok(())
}

fn validate_manager(window: &Window, manager: &Value) -> Result<()> {
    ensure!(
        manager["MESSAGE"] == format!("{}: Deactivated successfully.", window.unit)
            && manager["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && manager["_PID"] == "1"
            && manager["_UID"] == "0"
            && manager["UNIT"] == window.unit
            && manager["INVOCATION_ID"] == window.invocation
            && manager["_BOOT_ID"]
                .as_str()
                .is_some_and(|id| id.len() == 32)
            && manager
                .get("UNIT_RESULT")
                .is_none_or(|result| result == "success"),
        "foreign manager terminal"
    );
    Ok(())
}

fn validate_launch(window: &Window, launch: &Value) -> Result<String> {
    ensure!(
        launch["unit"] == window.unit
            && launch["invocation_id"] == window.invocation
            && launch["node_path"] == NODE
            && launch["worker"]["sha256"] == WORKER
            && launch["epoch"] == 230
            && launch["launched"] == true
            && launch["canonical_epoch_publication_authorized"] == false,
        "hourly launch claim changed"
    );
    let pid = launch["main_pid"]
        .as_u64()
        .context("missing admitted producer PID")?;
    ensure!(pid > 1, "invalid hourly producer PID");
    Ok(pid.to_string())
}

fn verify_archive_hash(source: &mut impl Read, length: u64, expected: &str) -> Result<()> {
    let mut hasher = Sha256::new();
    let bytes = std::io::copy(source, &mut hasher)?;
    ensure!(
        bytes == length && format!("{:x}", hasher.finalize()) == expected,
        "first-window archive length or SHA-256 differs from its committed manifest"
    );
    Ok(())
}

pub(super) fn collect(window: &Window) -> Result<Value> {
    let launch = pinned(window.launch)?;
    let pid = validate_launch(window, &launch)?;
    let (edges, edges_ref) = finalized_edges(window)?;
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
            "launch":reference(window.launch),"finalized_edges":edges_ref,"terminal_gcs":reference(window.terminal_gcs),
            "publication_authorized":false}),
        );
    }
    validate_clean_exit(
        window,
        &before,
        Path::new("/sys/fs/cgroup/system.slice")
            .join(window.unit)
            .exists(),
    )?;
    let manager = one_event(&[
        "_PID=1",
        &format!("UNIT={}", window.unit),
        &format!("INVOCATION_ID={}", window.invocation),
        r"--grep=Deactivated successfully\.",
    ])?;
    validate_manager(window, &manager)?;
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
        "segment_manifest":{"path":segment,"sha256":sha256(&raw)},"finalized_edges":edges_ref,
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
    if window.unit == FIRST_7871.unit {
        let held = pinned(FIRST_7871_RECHECK)?;
        let bootstrap = native(
            window,
            &pid,
            &format!("historical checkpoint slot={} ", window.first - 1),
            &manager,
        )?;
        ensure!(
            held["bootstrap"]["sha256"]
                == "3f93d04ff105ceca127a3c0464beec7e980eeb81b4a2e52a352f5d545614bef0"
                && manifest["bootstrap"]["accounts_hash"]
                    == "eAarFVYbpioWaBvd5S9RMHo1AyLbixgaTsBWLxYUaDr"
                && timestamp(&bootstrap)? < timestamp(&checkpoint)?
                && bootstrap["MESSAGE"]
                    .as_str()
                    .context("bootstrap checkpoint message")?
                    .ends_with(&checkpoint_message(
                        window.first - 1,
                        &manifest["bootstrap"]
                    )?),
            "first-window historical bootstrap differs from its held snapshot and adjacent checkpoint"
        );
        let mut source = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(archive)?;
        let archive_identity = identity(&meta);
        ensure!(
            identity(&source.metadata()?) == archive_identity,
            "first-window archive changed before reading"
        );
        verify_archive_hash(&mut source, meta.len(), digest)?;
        ensure!(
            identity(&source.metadata()?) == archive_identity,
            "first-window archive changed while reading"
        );
        receipt["archive"]["independent_sha256"] = json!(digest);
        receipt["slot_count"] = json!(window.last - window.first + 1);
        receipt["prior_same_start_progress"] = same_start_progress()?;
        receipt["bootstrap_recheck"] = reference(FIRST_7871_RECHECK);
        receipt["bootstrap_checkpoint_event"] = bootstrap;
        receipt["terminal_bank_votes"] = json!({
            "slot":window.last,"voted_bank_hash":FIRST_7871_BANK,"vote_block":99445305,
            "preparation_verified_vote_count":10,"rpc":"https://api.mainnet-beta.solana.com",
            "reference_sha256":"80630842221af76643d7be43d3d2811cd6072757c4357129ffd13a3d9d3aa267",
            "raw_block_sha256":"ee939697e23567dd75e7501e1970d156bd78d589f7e7dc27182cf403096eb28d"});
    }
    ensure!(
        before == state(window.unit)?
            && segment_identity == identity(&fs::symlink_metadata(segment)?)
            && identity(&meta) == identity(&fs::symlink_metadata(archive)?),
        "hourly terminal evidence changed"
    );
    Ok(receipt)
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
        let metadata = json!({"slot":last,"metadata":{"generation":"1633495975351467",
            "bucket":"mainnet-beta-ledger-europe-fr2","name":format!("99359376/hourly/snapshot-{last}-{accounts}.tar.zst")},
            "uri":format!("gs://mainnet-beta-ledger-europe-fr2/99359376/hourly/snapshot-{last}-{accounts}.tar.zst#1633495975351467")});
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
    #[test]
    fn first_7871_terminal_selects_the_dedicated_window_and_keeps_the_signed_bank() -> Result<()> {
        let window = select("--epoch230-first-7871").unwrap();
        assert_eq!(window.invocation, "02b7dd1683d24efbabf6b5c2f8ff6a43");
        assert_eq!(window.last - window.first + 1, 7_871);
        assert_eq!(select("--epoch230-hourly").unwrap().first, window.first);
        assert_ne!(select("--epoch230-hourly").unwrap().last, window.last);
        assert!(select("--epoch230-first-78710").is_none());
        let mut claim = json!({"unit": window.unit, "epoch":230, "invocation_id":window.invocation,
            "node_path":NODE, "main_pid":2836642,"launched":true, "worker":{"sha256":WORKER},
            "canonical_epoch_publication_authorized":false});
        assert_eq!(validate_launch(window, &claim)?, "2836642");
        assert!(validate_launch(&FIRST, &claim).is_err());
        claim["invocation_id"] = json!(FIRST.invocation);
        assert!(validate_launch(window, &claim).is_err());

        let terminal = json!({"slot":window.last,"slot_complete":true,"bank_hash":FIRST_7871_BANK,
            "accounts_hash":window.terminal_accounts,"last_blockhash":"end-block",
            "capitalization":5,"transaction_count":12,"tick_height":31,"write_count":1,"next_write_version":63});
        let manifest = json!({"epoch":230,"schema_version":1,"output_slot_start":window.first,
            "output_slot_count":7871,"runtime":{"runtime_profile":"solana-v1.6.20"},"worker_executable_sha256":WORKER,
            "bootstrap":{"slot":window.first-1,"slot_complete":true,"last_blockhash":"start-block"},
            "terminal":terminal});
        let edges = json!({"bootstrap":{"slot":window.first-1,"blockhash":"start-block"},
            "terminal":{"slot":window.last,"blockhash":"end-block"}});
        let gcs = json!({"bucket":"mainnet-beta-ledger-europe-fr2","generation":window.terminal_generation,
            "name":format!("99359376/hourly/snapshot-{}-{}.tar.zst",window.last,window.terminal_accounts)});
        let event = json!({"MESSAGE":checkpoint_message(window.last,&terminal)?});
        validate_segment(window, &manifest, &edges, &gcs, &event)?;
        assert!(validate_segment(&FIRST, &manifest, &edges, &gcs, &event).is_err());
        for (key, altered) in [
            ("bank_hash", "unvoted-bank"),
            ("accounts_hash", "other-root"),
            ("last_blockhash", "other-block"),
        ] {
            let mut changed = manifest.clone();
            changed["terminal"][key] = json!(altered);
            let changed_event =
                json!({"MESSAGE":checkpoint_message(window.last,&changed["terminal"])?});
            assert!(
                validate_segment(window, &changed, &edges, &gcs, &changed_event).is_err(),
                "{key}"
            );
        }
        let mut other_generation = gcs;
        other_generation["generation"] = json!(SECOND.terminal_generation);
        assert!(validate_segment(window, &manifest, &edges, &other_generation, &event).is_err());
        Ok(())
    }

    #[test]
    fn first_7871_requires_a_clean_exit_and_matching_archive_bytes() -> Result<()> {
        let window = &FIRST_7871;
        let mut state: BTreeMap<String, String> = [
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("Result", "success"),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("ControlGroup", ""),
            ("Job", ""),
            ("ExecMainStatus", "0"),
            ("NRestarts", "0"),
            ("InvocationID", window.invocation),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        validate_clean_exit(window, &state, false)?;
        assert!(validate_clean_exit(window, &state, true).is_err());
        for (key, bad) in [
            ("Result", "failed"),
            ("ExecMainStatus", "1"),
            ("NRestarts", "1"),
            ("Job", "17"),
            ("InvocationID", FIRST.invocation),
            ("ControlPID", "99"),
            ("SubState", "stop-sigterm"),
        ] {
            let mut changed = state.clone();
            changed.insert(key.into(), bad.into());
            assert!(
                validate_clean_exit(window, &changed, false).is_err(),
                "{key}"
            );
        }
        let manager = json!({"MESSAGE":format!("{}: Deactivated successfully.",window.unit),
            "UNIT":window.unit,"INVOCATION_ID":window.invocation,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448",
            "_UID":"0","_PID":"1","_BOOT_ID":"b".repeat(32)});
        validate_manager(window, &manager)?;
        for (field, value) in [
            ("INVOCATION_ID", FIRST.invocation),
            ("UNIT", SECOND.unit),
            ("_PID", "42"),
            ("UNIT_RESULT", "failed"),
        ] {
            let mut changed = manager.clone();
            changed[field] = json!(value);
            assert!(
                validate_manager(window, &changed).is_err(),
                "manager {field}"
            );
        }
        state.insert("InvocationID".into(), String::new());
        validate_clean_exit(window, &state, false)?;
        let archive = b"private terminal bytes";
        let fingerprint = sha256(archive);
        verify_archive_hash(&mut &archive[..], archive.len() as u64, &fingerprint)?;
        assert!(
            verify_archive_hash(&mut &archive[..], archive.len() as u64, &"0".repeat(64)).is_err()
        );
        assert!(verify_archive_hash(&mut &archive[..], 1, &fingerprint).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires the sealed Foundation host inputs"]
    fn first_7871_reads_the_accepted_source_and_predecessor() -> Result<()> {
        let window = &FIRST_7871;
        let launch = pinned(window.launch)?;
        assert_eq!(validate_launch(window, &launch)?, "2836642");
        let (edges, _) = finalized_edges(window)?;
        let previous = pinned(FIRST_PREDECESSOR)?;
        assert_eq!(previous["terminal"]["slot"], window.first - 1);
        assert_eq!(
            previous["terminal"]["last_blockhash"],
            edges["bootstrap"]["blockhash"]
        );
        assert_eq!(edges["terminal"]["slot"], window.last);
        assert_eq!(
            pinned(window.terminal_gcs)?["generation"],
            window.terminal_generation
        );
        assert_eq!(
            pinned(FIRST_7871_RECHECK)?["bootstrap"]["sha256"],
            "3f93d04ff105ceca127a3c0464beec7e980eeb81b4a2e52a352f5d545614bef0"
        );
        assert_eq!(same_start_progress()?, reference(FIRST_STOCK_PROGRESS));
        let old_evidence = pinned((
            "/var/lib/jetstreamer/horizon230-middle-hourly-second-runtime-v1/terminal-source.json",
            "c71379d81af249babc60df5914ebd8a844fbcd42f1481aaa90d3e2ea631a4271",
        ))?;
        let old_manifest = Path::new(SECOND.archive).with_extension("jet.segment.json");
        let (old_bytes, _) = read_bound(&old_manifest, 1 << 20, 1000)?;
        ensure!(
            sha256(&old_bytes) == old_evidence["segment_manifest"]["sha256"],
            "prior hour segment changed"
        );
        let old_state = serde_json::from_value(old_evidence["producer"].clone())?;
        validate_clean_exit(&SECOND, &old_state, false)?;
        validate_manager(&SECOND, &old_evidence["manager_event"])?;
        validate_segment(
            &SECOND,
            &serde_json::from_slice(&old_bytes)?,
            &finalized_edges(&SECOND)?.0,
            &pinned(SECOND.terminal_gcs)?,
            &old_evidence["checkpoint_event"],
        )?;
        Ok(())
    }
}
