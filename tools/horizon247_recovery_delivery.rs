//! Observational custody for the staged 58709604 delivery. No launch, capacity release or publication.
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon_observe::{staged247_rss, successor247 as old};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};

pub const UNIT: &str = "horizon-upload-247-staged-58709604-v1.service";
pub const V221_UNIT: &str = "horizon-upload-247-staged-58709604-v221.service";
const V221_ROOT: &str = "/home/ubuntu/.codex/diagnostics/horizon-upload-247-staged-58709604-v221";
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon247-public-images-58709604-v1/jetstreamer-r2";
pub const IMAGE_SHA: &str = "c1e99ad4b2e7f3fe56235f42a722bbe93e3f13af2003d0eb5a150553ae0a660e";
const ROOT: &str = "/home/ubuntu/.codex/diagnostics/horizon-upload-247-staged-58709604-v1";
const PLAN: &str = "/var/lib/jetstreamer/horizon247-public-reader-58709604-v1/epoch-247-plan.json";
const PLAN_SHA: &str = "b876747ff936dbabc96ad433d382af6e2dfd5ce233d0681909cd14962a2542de";
const RECOVERY: &str =
    "/var/lib/jetstreamer/horizon247-public-reader-58709604-v1/staged247-recovery.json";
const RECOVERY_SHA: &str = "632d775eaca96dcce169b3f4a3fc9a1389095c7bb6b19544e692e9c3f5e31a73";
pub const OLD: &str = "e434de7095a5407f80353b8f1df5eea8";
const BOOT: &str = "3b17d0055c3a4a0e8841da097e0957b5";
const LEDGER: &str =
    "/var/lib/jetstreamer/horizon247-staged-owner-v165-fadfe2d4-v1/current-ledger.json";
const LEDGER_SHA: &str = "7beddd086fb5c8a5d602ab0cb51b1dd3dad2db87e2c0ef96c7e6c933e152e26d";
const OLD_EVENT: &str =
    "/var/lib/jetstreamer/horizon247-staged-owner-v165-fadfe2d4-v1/running-event.json";
const OLD_EVENT_SHA: &str = "bcc72204b8e30fd76e006c86086645b05c050d172fc6391f53928553cb7d5ea8";
const PILOT: &str =
    "/var/lib/jetstreamer/horizon266-instructions-2789f821-v169-control/pilot/handoff.json";
const PILOT_SHA: &str = "1fb061652df4a0e1d656b0c4a4df5d54810c8bf6517224e1940c29f284bd1c6d";
const STOP: &str = "/var/lib/jetstreamer/horizon266-instructions-2789f821-v169-control/pilot/receipts/manager-stop-completion.json";
const STOP_SHA: &str = "95c4635f0cce38ec8f936ff508289340f4151099fe4fdce12a2560394b9a1ed9";
const CORRECTION: &str =
    "/home/ubuntu/.codex/diagnostics/horizon266-instruction-scratch-stop-v171-a1/completion.json";
const CORRECTION_SHA: &str = "10a21a0f0e513ba241fab3d9dc0994f3d5968d42913aac10b97c700b29293f68";
const STOPPED_IID: &str = "cad28704afe54672a6993db729227149";
const PEERS: [(&str, &str); 3] = [
    (
        "horizon-singleton-211-capped-4aeca563-v1.service",
        "49ea83a3a5e94e99af51153d2fd79e92",
    ),
    (
        "horizon-qualify-228-demotion-root-tail-16d4b158-v1.service",
        "5566869f329b46309aa8a2ea8f46047a",
    ),
    (
        "horizon-qualify-265-replacement-20261119-v3.service",
        "182de64d33674f95b7758d410eb1812b",
    ),
];

const POST228_TERM: &str =
    "/home/ubuntu/.codex/diagnostics/horizon228-private-scratch-stop-v176-a1/terminal.json";
const POST228_SHA: &str = "51cc6b025cc91653d592f4788afaa1ffa3ff3b7a3ba086f6e4ac6147916919af";
const POST228_STATUS: &str =
    "/home/ubuntu/.codex/diagnostics/horizon228-private-scratch-stop-v176-a1/completion.json";
const POST228_STATUS_SHA: &str = "3dabfdfba258b624ec83f3f71aa9d14c94751fbbdcc5e39a2180046f1562baa7";
const F177: &str =
    "/home/ubuntu/.codex/diagnostics/horizon-fleet-takeover-v177-20261120-v1/fleet-v1.json";
const F177_SHA: &str = "9a39f161db4adc0ab33319408e18fc063edc711994fd59ce7b754003cdb6652f";
const COLD266: &str =
    "/home/ubuntu/.codex/diagnostics/horizon266-postclosure-capacity-v173-a1/result.json";
const COLD266_SHA: &str = "d400bf947d870e7e878ccea832c3717264ce947fac64027254d9c7b5b47005c6";

fn post228_profile(cap: &Value) -> Result<()> {
    let stopped = &cap["stopped228"];
    ensure!(
        stopped["unit"] == PEERS[1].0
            && stopped["iid"] == PEERS[1].1
            && stopped["terminal"] == old::binding(POST228_TERM, POST228_SHA)
            && stopped["status"] == old::binding(POST228_STATUS, POST228_STATUS_SHA)
            && stopped["root"] == 112u64 << 30
            && stopped["memory_retained"] == 120000000000u64
            && stopped["released_memory"] == 0
            && stopped["released_disk"] == 0
            && cap["v177"] == old::binding(F177, F177_SHA)
            && cap["readonly266"]["snapshot"] == old::binding(COLD266, COLD266_SHA),
        "post-228 original custody"
    );
    let peers = cap["live_owners"].as_object().context("two live peers")?;
    ensure!(
        peers.len() == 2
            && [(PEERS[0], "1962046"), (PEERS[2], "1581654")]
                .iter()
                .all(|((u, i), pid)| {
                    let row = &cap["live_owners"][*u];
                    row["Id"] == *u
                        && row["InvocationID"] == *i
                        && row["ActiveState"] == "active"
                        && row["MainPID"] == *pid
                }),
        "two original surviving 211/265 owners"
    );
    Ok(())
}

fn post228_accounting(cap: &Value) -> Result<()> {
    let fit = &cap["fit"];
    let extra = cap["retained_auxiliary"]["additional_bytes"]
        .as_u64()
        .context("outstanding finite bytes")?;
    let hard = fit["hard_after"]
        .as_u64()
        .context("registered hard obligations")?;
    ensure!(
        cap["retained_auxiliary"]["issue_current"] == true
            && fit["auxiliary_bytes"] == extra
            && fit["entire_hard_after_auxiliary"].as_u64() == hard.checked_add(extra)
            && ["hard_margin", "growth_margin", "disk_margin"]
                .iter()
                .all(|k| fit[*k].as_i64().is_some_and(|v| v >= 0))
            && fit["fits"] == true,
        "post-228 complete resource margins"
    );
    Ok(())
}
fn post228_receipts(term: &Value, status: &Value, fleet: &Value, cold: &Value) -> Result<()> {
    let events = term["pid1"]
        .as_array()
        .context("original terminal events")?;
    ensure!(
        term["producer_drained"] == true
            && term["full_epoch_qualified"] == false
            && term["resource_release_authorized"] == false
            && term["guard_reason"] == "private-filesystem-floor"
            && term["partial_archive"]["size"] == 7559756149u64
            && events.iter().any(|e| e["_UID"] == "0"
                && e["_PID"] == "1"
                && e["UNIT"] == PEERS[1].0
                && e["INVOCATION_ID"] == PEERS[1].1
                && e["_BOOT_ID"] == BOOT
                && e["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
            && status["authenticated_exact_byte_readback"] == true
            && status["key"] == "epoch-228.epoch-status.json"
            && fleet["observer_sha256"]
                == "a4d4adb852725cbf7fe3e72f9788acca5e5fad8396a5dabb208c37aee6110a69"
            && fleet["unit_census"][PEERS[1].0]["ActiveState"] == "inactive"
            && cold["installed_loop_readonly"] == true
            && cold["after"] == 1770889216u64
            && cold["old_memory_release"] == 0,
        "original 228 terminal, stopped roster and 266 read-only proof"
    );
    Ok(())
}

pub(super) fn read(reference: &Value, path: &Path) -> Result<Value> {
    ensure!(
        reference["path"].as_str() == path.to_str()
            && path.is_absolute()
            && path.canonicalize()? == path,
        "fourth 247 evidence path"
    );
    let mut file = fs::File::open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == 0
            && meta.gid() == 0
            && meta.mode() & 0o022 == 0
            && meta.len() <= 16 << 20,
        "fourth 247 evidence owner/length"
    );
    let mut bytes = Vec::new();
    file.by_ref().take((16 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == meta.len()
            && reference["sha256"] == format!("{:x}", Sha256::digest(&bytes)),
        "fourth 247 evidence digest"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn claim_path() -> std::path::PathBuf {
    Path::new(ROOT).join("pipeline-claim.json")
}
pub fn selected_unit(reference: &Value) -> Option<&'static str> {
    let path = Path::new(reference["path"].as_str()?);
    // Compare the literal paths. Path component normalization must not select an alias.
    if path.as_os_str() == claim_path().as_os_str() {
        Some(UNIT)
    } else if path.as_os_str() == Path::new(V221_ROOT).join("pipeline-claim.json").as_os_str() {
        Some(V221_UNIT)
    } else {
        None
    }
}
pub fn is_fourth(owner: &old::Owner) -> bool {
    selected_unit(&owner.proof["claim"]).is_some()
}
pub fn unit(owner: &old::Owner) -> &'static str {
    selected_unit(&owner.proof["claim"]).unwrap_or(old::UNIT)
}

fn identity(
    claim: &Value,
    launch: &Value,
    book: &Value,
    recipe: &Value,
) -> Result<(String, u32, u64, String)> {
    let u = &launch["unit"];
    let iid = claim["invocation_id"]
        .as_str()
        .context("fourth 247 invocation")?;
    let pid = u["MainPID"]
        .as_str()
        .context("fourth 247 main pid")?
        .parse::<u32>()?;
    let ticks = launch["pid_start_ticks"]
        .as_str()
        .context("fourth 247 start ticks")?
        .parse::<u64>()?;
    let cmd = claim["expected_exec_start"]
        .as_str()
        .context("fourth 247 command")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && ![old::ORIGINAL_IID, old::PRIOR_IID, OLD].contains(&iid)
            && pid > 1
            && ticks > 0
            && launch["boot_id"] == BOOT
            && u["Id"] == UNIT
            && u["InvocationID"] == iid
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["NRestarts"] == "0"
            && u["ControlGroup"] == format!("/system.slice/{UNIT}")
            && u["MemoryMax"] == "10737418240"
            && u["MemorySwapMax"] == "0"
            && u["ExecStart"] == cmd
            && claim["epoch"] == 247
            && claim["unit"] == UNIT
            && claim["phase"] == "upload-readback",
        "fourth 247 original identity"
    );
    let argv = recipe["recovery_argv"]
        .as_array()
        .context("registered recovery command")?
        .iter()
        .map(|v| v.as_str().context("247 argv"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        argv.first() == Some(&IMAGE)
            && argv.last() == Some(&"--recover-staged-247")
            && book["unit"] == UNIT
            && book["argv"] == recipe["recovery_argv"]
            && cmd.split_once(" ; start_time=").map(|v| v.0)
                == Some(
                    format!(
                        "{{ path={IMAGE} ; argv[]={} ; ignore_errors=no",
                        argv.join(" ")
                    )
                    .as_str()
                ),
        "fourth 247 registered argv"
    );
    Ok((iid.to_owned(), pid, ticks, cmd.to_owned()))
}

fn allocation(cap: &Value, ledger: &Value, reg: &Value, closure: &Value) -> Result<()> {
    let oldrows = ledger["reservations"]
        .as_array()
        .context("retained reservations")?;
    let rows = cap["original_predecessors"]
        .as_array()
        .context("three retained 247 rows")?;
    let ids = [old::ORIGINAL_IID, old::PRIOR_IID, OLD];
    ensure!(
        rows.len() == 3
            && oldrows.len() == 22
            && rows.iter().zip(ids).all(|(r, id)| r["invocation_id"] == id
                && r.get("release") == Some(&Value::Null)
                && oldrows.iter().filter(|entry| *entry == r).count() == 1)
            && oldrows.last() == rows.last(),
        "247 reservation lineage"
    );
    let delta = &cap["transfer"];
    let orig = &closure["original_event"];
    ensure!(
        cap["fit"]["fits"] == true
            && cap["fit"]["preexisting_hard"] == 1_211_435_323_392u64
            && cap["fit"]["hard_after"] == 1_211_972_194_304u64
            && cap["fit"]["exclusive_e434_payload"] == old::HARD
            && cap["nominal_reservations"] == 22
            && cap["capacity_credit"] == 0
            && cap["physical_credit"] == 0
            && cap["retained_ledger"] == old::binding(LEDGER, LEDGER_SHA)
            && delta["source"] == rows[2]
            && delta["exclusive_successor"] == UNIT
            && delta["exclusive_payload_bytes"] == old::HARD
            && delta["retained_old_controller_bytes"] == 512 << 20
            && delta["new_additive_controller_bytes"] == 512 << 20
            && delta["retained_old_disk"] == old::DISK
            && delta["new_additive_disk"] == old::DISK
            && delta["old_rows_released"] == json!([])
            && delta["old_nonrecurring"]["LoadState"] == "not-found"
            && cap["stopped266"]["handoff"] == old::binding(PILOT, PILOT_SHA)
            && cap["stopped266"]["manager_stop"] == old::binding(STOP, STOP_SHA)
            && cap["stopped266"]["status"] == old::binding(CORRECTION, CORRECTION_SHA)
            && cap["stopped266"]["iid"] == STOPPED_IID
            && cap["stopped266"]["root"] == 128u64 << 30
            && cap["stopped266"]["memory_retained"] == 176000000000u64
            && cap["stopped266"]["released_memory"] == 0
            && cap["stopped266"]["released_disk"] == 0,
        "fourth 247 exclusive funding"
    );
    if cap.get("stopped228").is_some() {
        post228_profile(cap)?;
    } else {
        let peers = cap["live_owners"].as_object().context("247 peer roster")?;
        ensure!(
            peers.len() == 3
                && PEERS
                    .iter()
                    .all(
                        |(name, iid)| peers.get(*name).is_some_and(|p| p["Id"] == *name
                            && p["InvocationID"] == *iid
                            && p["ActiveState"] == "active"
                            && p["MainPID"]
                                .as_str()
                                .and_then(|x| x.parse::<u32>().ok())
                                .is_some_and(|n| n > 1))
                    ),
            "247 original 211/228/265 roster after 266 scratch stop"
        );
    }
    ensure!(
        reg["claim"] == closure["claim"]
            && reg["booking"] == closure["booking"]
            && closure["ledger"] == cap["retained_ledger"]
            && closure["row"] == rows[2]
            && orig["INVOCATION_ID"] == OLD
            && orig["UNIT"] == old::UNIT
            && orig["_BOOT_ID"] == BOOT
            && orig["_UID"] == "0"
            && orig["_PID"] == "1"
            && orig["MESSAGE_ID"] == "d9b373ed55a64feb8242e02dbe79a49c"
            && orig["UNIT_RESULT"].as_str().is_some_and(|v| matches!(
                v,
                "exit-code"
                    | "signal"
                    | "core-dump"
                    | "timeout"
                    | "oom-kill"
                    | "watchdog"
                    | "resources"
                    | "protocol"
            )),
        "old e434 original failure"
    );
    Ok(())
}

const V221_CLAIM_SHA: &str = "2bbaea3660fbac6ed235bb64baf2ba50064cf6dd8db5568286384ea42b79d951";

fn load_v221(reference: &Value) -> Result<old::Owner> {
    // The original claim authenticates the ordered booking and launch, which in turn
    // authenticate the admission, predecessor receipts and recorded reader comparison.
    ensure!(
        reference["sha256"] == V221_CLAIM_SHA,
        "different v221 claim"
    );
    let root = Path::new(V221_ROOT);
    let claim = read(reference, &root.join("pipeline-claim.json"))?;
    let evidence = claim["evidence"]
        .as_array()
        .context("v221 claim evidence")?;
    let [book_ref, launch_ref] = evidence.as_slice() else {
        anyhow::bail!("v221 booking and launch required")
    };
    let book = read(book_ref, &root.join("booking.json"))?;
    let launch = read(launch_ref, &root.join("launch.json"))?;
    let admission = read(&book["admission"], &root.join("admission.json"))?;
    let source = &book["source"];
    let history = &source["terminal_evidence"];
    let binding_doc = |r: &Value| {
        read(
            r,
            Path::new(r["path"].as_str().context("missing bound path")?),
        )
    };
    let recipe_ref = old::binding(RECOVERY, RECOVERY_SHA);
    let recipe = binding_doc(&recipe_ref)?;
    let plan_ref = old::binding(PLAN, PLAN_SHA);
    let plan = binding_doc(&plan_ref)?;
    let scope = binding_doc(&admission["source_scope"]["comparison"])?;
    let registration = binding_doc(&history["registration"])?;
    let ledger = binding_doc(&history["ledger"])?;
    ensure!(
        launch["booking"] == *book_ref
            && claim["epoch"] == 247
            && claim["phase"] == "upload-readback"
            && book["unit"] == V221_UNIT
            && source["plan"] == plan_ref
            && book["plan"] == plan_ref
            && recipe["current_reader_plan"] == plan_ref
            && recipe["uploader"] == old::binding(IMAGE, IMAGE_SHA)
            && recipe["uploader"] == source["uploader"]
            && book["argv"] == recipe["recovery_argv"]
            && source["argv"] == book["argv"]
            && plan["threads"] == 2
            && scope["staged_epoch"] == 247
            && scope["sidecar_authorized"] == false
            && ["reader", "compiled reader"].iter().all(|name| {
                let row = &scope["compared"][*name];
                row["base"] == plan["reader_commit"] && row["changed_paths"] == json!([])
            })
            && history["registration"] == old::binding(OLD_EVENT, OLD_EVENT_SHA)
            && history["ledger"] == old::binding(LEDGER, LEDGER_SHA)
            && registration["booking"] == history["booking"]
            && registration["launch"] == history["launch"]
            && registration["claim"] == history["claim"]
            && registration["retained_ledger"] == history["ledger"]
            && history["outcome"] == "failed"
            && history["original_process"]["boot_id"] == BOOT
            && recipe["required_predecessor_invocations"]
                == json!([old::ORIGINAL_IID, old::PRIOR_IID, OLD]),
        "v221 staged delivery lineage"
    );
    let reservations = ledger["reservations"]
        .as_array()
        .context("247 reservations")?;
    for (index, (name, iid)) in [
        (old::ORIGINAL, old::ORIGINAL_IID),
        (old::PRIOR_UNIT, old::PRIOR_IID),
        (old::UNIT, OLD),
    ]
    .iter()
    .enumerate()
    {
        let row = &history["predecessors"][index];
        let saved = &history["terminals"][index];
        let e = &saved["event"];
        let drain = &saved["drain"];
        ensure!(
            row["invocation_id"] == *iid
                && row.get("release") == Some(&Value::Null)
                && reservations.iter().filter(|r| *r == row).count() == 1
                && e["UNIT"] == *name
                && e["INVOCATION_ID"] == *iid
                && e["_BOOT_ID"] == BOOT
                && e["_UID"] == "0"
                && e["_PID"] == "1"
                && e["UNIT_RESULT"] == "exit-code"
                && e["MESSAGE_ID"] == "d9b373ed55a64feb8242e02dbe79a49c"
                && drain["Id"] == *name
                && drain["InvocationID"] == *iid
                && drain["MainPID"] == "0"
                && drain["ControlPID"] == "0"
                && drain["Job"] == ""
                && drain["ActiveState"] == "failed"
                && drain["Restart"] == "no",
            "v221 predecessor reservation or terminal evidence"
        );
    }
    let staged = &history["initial_object"];
    let remote = &book["remote"];
    ensure!(
        source["original_replay_iid"] == "d091bb68ff2648159c76f690b3b7fee3"
            && staged["key"] == "epoch-247.jet"
            && remote["key"] == staged["key"]
            && staged["length"] == source["bytes"]
            && remote["length"] == staged["length"]
            && source["source_sidecar_digest"] == staged["sha256"]
            && remote["sha256"] == staged["sha256"]
            && remote["etag"] == format!("\"{}\"", staged["etag"].as_str().context("staged ETag")?)
            && staged["sidecar_absent"] == true,
        "v221 original staged body"
    );
    let fit = binding_doc(&admission["fit"])?;
    let number = |v: &Value| v.as_u64().context("v221 original capacity value");
    let credit = number(&admission["resident_anon_credit"])?;
    let memory = number(&fit["required_available_memory_bytes"])?
        .checked_add(old::BOOKED)
        .and_then(|v| v.checked_sub(credit))
        .context("v221 memory threshold")?;
    let disk = number(&fit["required_initial_free_bytes"])?
        .checked_add(old::DISK)
        .context("v221 disk threshold")?;
    for when in ["before", "after"] {
        let snapshot = &admission[when];
        let anon = snapshot["anon"].as_object().context("v221 peer memory")?;
        let total = anon.values().try_fold(0u64, |n, v| {
            n.checked_add(number(v)?).context("v221 peer memory total")
        })?;
        ensure!(
            anon.len() == 3
                && total == credit
                && number(&snapshot["available"])? >= memory
                && number(&snapshot["free"])? >= disk,
            "v221 admission snapshot"
        );
    }
    ensure!(
        fit["fits"] == true
            && admission["required_available"] == memory
            && admission["required_free"] == disk,
        "v221 original fit"
    );
    for (i, epoch) in [250, 251].into_iter().enumerate() {
        let holding = binding_doc(&admission["holding_readbacks"][i])?;
        ensure!(
            holding["source_retained"] == true
                && holding["resource_credit"] == 0
                && holding["result"]["operation"] == "verify"
                && holding["result"]["epoch"] == epoch,
            "v221 retained holding evidence"
        );
    }
    let donor = binding_doc(&admission["donor"])?;
    let reservation = binding_doc(&admission["reservation257"])?;
    let terminal = binding_doc(&admission["terminal257"])?;
    ensure!(
        admission["gross"] == old::BOOKED
            && admission["additional_disk"] == old::DISK
            && admission["prior_reservations_released"] == false
            && donor["other_reservations_retained"] == true
            && donor["same_reservation_only"] == true
            && reservation["donor"] == admission["donor"]
            && reservation["automatic_release"] == false
            && terminal["qualified"] == true
            && terminal["full_replay"] == false,
        "v221 original funding"
    );
    let u = &launch["unit"];
    let iid = claim["invocation_id"].as_str().context("v221 invocation")?;
    let command = claim["expected_exec_start"]
        .as_str()
        .context("v221 command")?;
    let pid = u["MainPID"].as_str().context("v221 PID")?.parse::<u32>()?;
    // The immutable launch captured systemd monotonic microseconds on this 100 Hz host.
    let micros = u["ExecMainStartTimestampMonotonic"]
        .as_str()
        .context("v221 launch time")?
        .parse::<u64>()?;
    let ticks = micros / 10_000;
    ensure!(
        claim["unit"] == V221_UNIT
            && u["Id"] == V221_UNIT
            && u["InvocationID"] == iid
            && u["ExecStart"] == command
            && pid > 1
            && ticks > 0
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["Job"] == ""
            && u["NRestarts"] == "0"
            && u["Restart"] == "no"
            && u["MemorySwapMax"] == "0"
            && u["MemoryMax"] == "10737418240",
        "v221 launch identity"
    );
    let proof = json!({"claim":reference,"booking":book_ref,"launch":launch_ref,"admission":book["admission"],
        "plan":plan_ref,"recovery":recipe_ref,"start_ticks":ticks,"prior":history["registration"],
        "old_claim_evidence":[history["booking"],history["launch"]],"retained_ledger":history["ledger"],
        "source_scope":admission["source_scope"],"donor":admission["donor"],"reservation257":admission["reservation257"],"terminal257":admission["terminal257"]});
    Ok(old::Owner {
        iid: iid.to_owned(),
        pid,
        argv: book["argv"].clone(),
        command: command.to_owned(),
        proof,
    })
}

pub fn predecessor_spent(u: &Value, current: &str) -> bool {
    (u["LoadState"] == "not-found"
        && u["ActiveState"] == "inactive"
        && u["MainPID"] == "0"
        && (current != V221_UNIT
            || (u["SubState"] == "dead" && u["InvocationID"].as_str().unwrap_or("").is_empty())))
        || (current == V221_UNIT
            && u["LoadState"] == "loaded"
            && old::terminal(u, old::UNIT, OLD).is_ok())
}

pub fn load(reference: &Value) -> Result<old::Owner> {
    match selected_unit(reference) {
        Some(V221_UNIT) => return load_v221(reference),
        Some(UNIT) => (),
        _ => return old::load(reference),
    }
    let root = Path::new(ROOT);
    let c = read(reference, &claim_path())?;
    let evidence = c["evidence"]
        .as_array()
        .context("fourth 247 claim evidence")?;
    ensure!(
        evidence.len() == 2,
        "fourth 247 booking and launch required"
    );
    let b = read(&evidence[0], &root.join("booking.json"))?;
    let l = read(&evidence[1], &root.join("launch.json"))?;
    let a = read(&b["admission"], &root.join("admission.json"))?;
    let cap = &a["complete_capacity"];
    let recovery = old::binding(RECOVERY, RECOVERY_SHA);
    let recipe = read(&recovery, Path::new(RECOVERY))?;
    let p = old::binding(PLAN, PLAN_SHA);
    let plan = read(&p, Path::new(PLAN))?;
    let regref = old::binding(OLD_EVENT, OLD_EVENT_SHA);
    let reg = read(&regref, Path::new(OLD_EVENT))?;
    let ledger = read(&reg["retained_ledger"], Path::new(LEDGER))?;
    let close = read(
        &cap["transfer"]["close"],
        &Path::new(old::ROOT).join("postterminal-58709604-close.json"),
    )?;
    ensure!(
        l["booking"] == evidence[0]
            && b["approved_plan"] == p
            && b["staged_recovery"] == recovery
            && b["requested_memory"] == old::BOOKED
            && b["disk_reserve"] == old::DISK
            && b["capacity_credit"] == 0
            && a["unit"] == UNIT
            && a["terminal"]["registration"] == regref
            && a["terminal"]["outcome"] == "failed"
            && a["terminal"]["predecessors"] == cap["original_predecessors"]
            && b["retained_ledger"] == cap["retained_ledger"]
            && reg["retained_ledger"] == old::binding(LEDGER, LEDGER_SHA)
            && recipe["current_reader_plan"] == p
            && recipe["uploader"] == old::binding(IMAGE, IMAGE_SHA)
            && plan["threads"] == 2
            && plan["reader_commit"] == "58709604dfa4c97336c2e1f6fac53b862ed6f17f"
            && recipe["required_predecessor_invocations"]
                == json!([old::ORIGINAL_IID, old::PRIOR_IID, OLD]),
        "fourth 247 qualification graph"
    );
    // Every new fourth launch must prove both closed producers even when a previous
    // three-peer fixture is replayed to check historical allocation arithmetic.
    post228_profile(cap)?;
    post228_accounting(cap)?;
    post228_receipts(
        &read(&cap["stopped228"]["terminal"], Path::new(POST228_TERM))?,
        &read(&cap["stopped228"]["status"], Path::new(POST228_STATUS))?,
        &read(&cap["v177"], Path::new(F177))?,
        &read(&cap["readonly266"]["snapshot"], Path::new(COLD266))?,
    )?;
    allocation(cap, &ledger, &reg, &close)?;
    let stop = read(&cap["stopped266"]["manager_stop"], Path::new(STOP))?;
    let corrected = read(&cap["stopped266"]["status"], Path::new(CORRECTION))?;
    ensure!(
        stop["producer_invocation_id"] == STOPPED_IID
            && stop["reason"] == "root-physical-budget"
            && stop["manager"]["drained"] == true
            && stop["manager"]["terminal"]["MainPID"] == "0"
            && stop["manager"]["terminal"]["ActiveState"] == "inactive"
            && corrected["key"] == "epoch-266.epoch-status.json"
            && corrected["authenticated_exact_byte_readback"] == true,
        "unproved stopped 266"
    );
    let (iid, pid, ticks, command) = identity(&c, &l, &b, &recipe)?;
    let proof = json!({"claim":reference,"booking":evidence[0],"launch":evidence[1],"admission":b["admission"],"recovery":recovery,"plan":p,"start_ticks":ticks,"prior":regref,"old_close":cap["transfer"]["close"],"old_claim_evidence":[reg["booking"],reg["launch"]],"retained_ledger":reg["retained_ledger"],"stopped266":cap["stopped266"]["manager_stop"],"status266":cap["stopped266"]["status"],"stopped228":cap["stopped228"]["terminal"],"status228":cap["stopped228"]["status"],"v177":cap["v177"],"readonly266":cap["readonly266"]["snapshot"]});
    Ok(old::Owner {
        iid,
        pid,
        argv: b["argv"].clone(),
        command,
        proof,
    })
}

pub fn validate_sample(row: &Value, owner: &old::Owner) -> Result<()> {
    if !is_fourth(owner) {
        return staged247_rss::validate_sample(row, owner);
    }
    ensure!(
        row["successor_owner"] == owner.proof
            && row["terminal_completion_proven"] == false
            && row["resource_release_authorized"] == false
            && row["publication_authorized"] == false,
        "fourth 247 RSS proof"
    );
    staged247_rss::validate_endpoints(
        row,
        &staged247_rss::Endpoint {
            unit: unit(owner),
            iid: &owner.iid,
            pid: owner.pid,
            ticks: owner.proof["start_ticks"]
                .as_u64()
                .context("registered fourth 247 original ticks")?,
            image: IMAGE,
            image_sha: IMAGE_SHA,
            cap: old::HARD,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_v221_and_planned_fourth_have_distinct_history() {
        let mut u = json!({"Id":old::UNIT,"InvocationID":OLD,"LoadState":"loaded","ActiveState":"failed",
            "SubState":"failed","MainPID":"0","NRestarts":"0","Result":"exit-code","ExecMainStatus":"1"});
        assert!(predecessor_spent(&u, V221_UNIT));
        assert!(!predecessor_spent(&u, UNIT));
        u["InvocationID"] = json!(old::PRIOR_IID);
        assert!(!predecessor_spent(&u, V221_UNIT));
        assert_eq!(
            selected_unit(&json!({"path":Path::new(V221_ROOT).join("pipeline-claim.json")})),
            Some(V221_UNIT)
        );
        assert_eq!(selected_unit(&json!({"path":claim_path()})), Some(UNIT));
        assert_eq!(
            selected_unit(&json!({"path":format!("{V221_ROOT}//pipeline-claim.json")})),
            None
        );
    }
    #[test]
    fn fourth_claim_never_accepts_an_old_iid_or_another_image() {
        let argv = json!([IMAGE, "sync", "/private/fixed", "--recover-staged-247"]);
        let command = format!(
            "{{ path={IMAGE} ; argv[]={IMAGE} sync /private/fixed --recover-staged-247 ; ignore_errors=no ; start_time=[n/a] }}"
        );
        let iid = "00112233445566778899aabbccddeeff";
        let claim = json!({"epoch":247,"phase":"upload-readback","unit":UNIT,"invocation_id":iid,"expected_exec_start":command});
        let mut launch = json!({"boot_id":BOOT,"pid_start_ticks":"123","unit":{"Id":UNIT,"InvocationID":iid,"MainPID":"42","ActiveState":"active","SubState":"running","NRestarts":"0","MemoryMax":"10737418240","MemorySwapMax":"0","ControlGroup":format!("/system.slice/{UNIT}"),"ExecStart":command}});
        let book = json!({"unit":UNIT,"argv":argv});
        let recipe = json!({"recovery_argv":argv});
        assert_eq!(identity(&claim, &launch, &book, &recipe).unwrap().2, 123);
        for id in [old::ORIGINAL_IID, old::PRIOR_IID, OLD] {
            let mut other = claim.clone();
            launch["unit"]["InvocationID"] = json!(id);
            other["invocation_id"] = json!(id);
            assert!(identity(&other, &launch, &book, &recipe).is_err());
        }
        launch["unit"]["InvocationID"] = json!(iid);
        let bad = json!({"unit":UNIT,"argv":["/tmp/other","sync"]});
        assert!(identity(&claim, &launch, &bad, &recipe).is_err());
        launch["pid_start_ticks"] = json!("0");
        assert!(identity(&claim, &launch, &book, &recipe).is_err());
    }

    #[test]
    fn fourth_fit_requires_three_peers_retained_266_and_only_e434_payload() {
        let row = |id| json!({"invocation_id":id,"release":null});
        let rows = json!([row(old::ORIGINAL_IID), row(old::PRIOR_IID), row(OLD)]);
        let mut retained = vec![Value::Null; 19];
        retained.extend(rows.as_array().unwrap().clone());
        let ledger = json!({"reservations":retained});
        let lr = old::binding(LEDGER, LEDGER_SHA);
        let reg =
            json!({"claim":old::binding("/old/claim","a"),"booking":old::binding("/old/book","b")});
        let closure = json!({"claim":reg["claim"],"booking":reg["booking"],"ledger":lr,"row":rows[2],"original_event":{"INVOCATION_ID":OLD,"UNIT":old::UNIT,"_BOOT_ID":BOOT,"_UID":"0","_PID":"1","MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c","UNIT_RESULT":"exit-code"}});
        let mut peers = json!({});
        for (unit, iid) in PEERS {
            peers[unit] =
                json!({"Id":unit,"InvocationID":iid,"ActiveState":"active","MainPID":"42"});
        }
        let cap = json!({"original_predecessors":rows,"nominal_reservations":22,"capacity_credit":0,"physical_credit":0,"retained_ledger":lr,"stopped266":{"handoff":old::binding(PILOT,PILOT_SHA),"manager_stop":old::binding(STOP,STOP_SHA),"status":old::binding(CORRECTION,CORRECTION_SHA),"iid":STOPPED_IID,"root":128u64<<30,"memory_retained":176000000000u64,"released_memory":0,"released_disk":0},"live_owners":peers,"fit":{"fits":true,"preexisting_hard":1_211_435_323_392u64,"hard_after":1_211_972_194_304u64,"exclusive_e434_payload":old::HARD},"transfer":{"source":rows[2],"exclusive_successor":UNIT,"exclusive_payload_bytes":old::HARD,"retained_old_controller_bytes":536870912,"new_additive_controller_bytes":536870912,"retained_old_disk":old::DISK,"new_additive_disk":old::DISK,"old_rows_released":[],"old_nonrecurring":{"LoadState":"not-found"}}});
        allocation(&cap, &ledger, &reg, &closure).unwrap();
        for (name, _) in PEERS {
            let mut missing = cap.clone();
            missing["live_owners"].as_object_mut().unwrap().remove(name);
            assert!(allocation(&missing, &ledger, &reg, &closure).is_err());
        }
        let mut bad = cap.clone();
        bad["stopped266"]["released_memory"] = json!(176000000000u64);
        assert!(allocation(&bad, &ledger, &reg, &closure).is_err());
        let mut live = cap.clone();
        live["live_owners"]["horizon-qualify-266-instructions-2789f821-v169.service"] =
            json!({"InvocationID":STOPPED_IID});
        assert!(allocation(&live, &ledger, &reg, &closure).is_err());
        let mut double = cap.clone();
        double["transfer"]["exclusive_payload_bytes"] = json!(old::BOOKED);
        assert!(allocation(&double, &ledger, &reg, &closure).is_err());
        let mut anticipated = closure.clone();
        anticipated["original_event"]["UNIT_RESULT"] = json!("success");
        assert!(allocation(&cap, &ledger, &reg, &anticipated).is_err());
    }
    #[test]
    fn two_surviving_peers_require_original_228_custody() {
        let mut cap = json!({"v177":old::binding(F177,F177_SHA),"readonly266":{"snapshot":old::binding(COLD266,COLD266_SHA)},
            "stopped228":{"unit":PEERS[1].0,"iid":PEERS[1].1,"terminal":old::binding(POST228_TERM,POST228_SHA),"status":old::binding(POST228_STATUS,POST228_STATUS_SHA),
            "root":112u64<<30,"memory_retained":120000000000u64,"released_memory":0,"released_disk":0},"live_owners":{}});
        for ((u, i), pid) in [(PEERS[0], "1962046"), (PEERS[2], "1581654")] {
            cap["live_owners"][u] =
                json!({"Id":u,"InvocationID":i,"ActiveState":"active","MainPID":pid});
        }
        let mut funding = json!({"retained_auxiliary":{"additional_bytes":7,"issue_current":true},
            "fit":{"hard_after":101,"auxiliary_bytes":7,"entire_hard_after_auxiliary":108,
            "hard_margin":1,"growth_margin":2,"disk_margin":0,"fits":true}});
        post228_accounting(&funding).unwrap();
        funding["fit"]["disk_margin"] = json!(-1);
        assert!(post228_accounting(&funding).is_err());
        post228_profile(&cap).unwrap();
        for key in [
            "root",
            "memory_retained",
            "released_memory",
            "released_disk",
            "terminal",
            "status",
            "iid",
        ] {
            let mut v = cap.clone();
            v["stopped228"][key] = json!(1);
            assert!(post228_profile(&v).is_err());
        }
        let mut missing = cap.clone();
        missing["live_owners"]
            .as_object_mut()
            .unwrap()
            .remove(PEERS[0].0);
        assert!(post228_profile(&missing).is_err());
        cap["live_owners"][PEERS[1].0] = json!({"Id":PEERS[1].0});
        assert!(post228_profile(&cap).is_err());
    }
    #[test]
    fn stopped_peer_proof_rejects_other_pid1_and_266_release() {
        let t = json!({"producer_drained":true,"full_epoch_qualified":false,"resource_release_authorized":false,
            "guard_reason":"private-filesystem-floor","partial_archive":{"size":7559756149u64},"pid1":[{"_PID":"1","_UID":"0","UNIT":PEERS[1].0,"INVOCATION_ID":PEERS[1].1,"_BOOT_ID":BOOT,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"}]});
        let status =
            json!({"authenticated_exact_byte_readback":true,"key":"epoch-228.epoch-status.json"});
        let mut f = json!({"observer_sha256":"a4d4adb852725cbf7fe3e72f9788acca5e5fad8396a5dabb208c37aee6110a69","unit_census":{}});
        f["unit_census"][PEERS[1].0] = json!({"ActiveState":"inactive"});
        let mut c =
            json!({"installed_loop_readonly":true,"after":1770889216u64,"old_memory_release":0});
        post228_receipts(&t, &status, &f, &c).unwrap();
        let mut other = t.clone();
        other["pid1"][0]["_PID"] = json!("99");
        assert!(post228_receipts(&other, &status, &f, &c).is_err());
        c["old_memory_release"] = json!(1);
        assert!(post228_receipts(&t, &status, &f, &c).is_err());
    }
}
