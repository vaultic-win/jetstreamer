//! Observational custody for the staged 58709604 delivery. No launch, capacity release or publication.
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon_observe::{staged247_rss, successor247 as old};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};

pub const UNIT: &str = "horizon-upload-247-staged-58709604-v1.service";
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

fn read(reference: &Value, path: &Path) -> Result<Value> {
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
pub fn selected(reference: &Value) -> bool {
    reference["path"].as_str() == claim_path().to_str()
}
pub fn is_fourth(owner: &old::Owner) -> bool {
    selected(&owner.proof["claim"])
}
pub fn unit(owner: &old::Owner) -> &'static str {
    if is_fourth(owner) { UNIT } else { old::UNIT }
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
    let peers = cap["live_owners"].as_object().context("247 peer roster")?;
    ensure!(
        peers.len() == 3
            && PEERS.iter().all(
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

pub fn load(reference: &Value) -> Result<old::Owner> {
    if !selected(reference) {
        return old::load(reference);
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
    let proof = json!({"claim":reference,"booking":evidence[0],"launch":evidence[1],"admission":b["admission"],"recovery":recovery,"plan":p,"start_ticks":ticks,"prior":regref,"old_close":cap["transfer"]["close"],"old_claim_evidence":[reg["booking"],reg["launch"]],"retained_ledger":reg["retained_ledger"],"stopped266":cap["stopped266"]["manager_stop"],"status266":cap["stopped266"]["status"]});
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
            unit: UNIT,
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
}
