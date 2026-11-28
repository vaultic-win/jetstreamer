//! Accept the exact closed assembler and drain only its bound guard.
use super::*;

const INTENT: &str = "foundation-epoch226-assembly-drain-intent-v1";
const COMPLETE: &str = "foundation-epoch226-assembly-terminal-v1";

fn result_receipt(destination: &Path) -> Result<(Value, Value)> {
    let info = destination.symlink_metadata()?;
    ensure!(
        destination.canonicalize()? == destination
            && info.is_file()
            && info.uid() == 1000
            && info.mode() & 0o077 == 0,
        "epoch 226 assembler receipt owner or scope"
    );
    let raw = read_stable_bounded(destination, 1 << 20, "epoch 226 assembler receipt")?;
    ensure!(
        identity(&info) == regular_identity(destination)?,
        "epoch 226 assembler receipt changed"
    );
    Ok((
        suffix::reference(destination, &raw),
        serde_json::from_slice(&raw)?,
    ))
}

fn assembled_result(
    owner: &Value,
    result: &Value,
    result_ref: &Value,
    launch: &Value,
    archive: &Value,
) -> Result<()> {
    ensure!(
        owner["producer_unit"] == spec::UNIT
            && owner["invocation_id"] == launch["invocation_id"]
            && owner["plan"] == launch["plan"]
            && owner["operation"] == "assemble"
            && owner["receipt"] == result_ref["path"]
            && owner["receipt_sha256"] == result_ref["sha256"]
            && owner["source_must_be_retained"] == true
            && owner["publication_authorized"] == false
            && owner["r2_mutations"] == false
            && result["schema"] == "jetstreamer-private-epoch226-explicit-worker-handoff-v1"
            && result["epoch"] == 226
            && result["output"] == archive["path"]
            && canonical_digest(&result["archive_sha256"])
            && result["provenance_version"] == 3
            && result["source_slots"] == json!([431465, 535])
            && result["assembled_slots"] == 432000
            && result["source_must_be_retained"] == true
            && result["independent_final_archive_verification_passed"] == false
            && result["current_plugin_verification_passed"] == false
            && result["artifact_specific_import_qualification_required"] == true
            && result["canonical_sidecar_authorized"] == false
            && result["publication_authorized"] == false
            && result["retirement_authorized"] == false
            && result["r2_mutations"] == false,
        "epoch 226 assembled receipt does not match the exact private invocation"
    );
    Ok(())
}

fn guard_state(launch: &Value) -> Result<(Value, Value)> {
    let timer = drain::show(spec::TIMER)?;
    let guard = drain::show(spec::GUARD_SERVICE)?;
    ensure!(
        timer["Job"] == ""
            && (timer["ActiveState"] == "inactive"
                || (timer["ActiveState"] == "active"
                    && timer["Unit"] == spec::GUARD_SERVICE
                    && timer["InvocationID"] == launch["launch_token"]["guard_timer_invocation"])),
        "epoch 226 assembly timer owner changed"
    );
    if guard["LoadState"] != "not-found" {
        let plan_hash = launch["guard_plan"]["sha256"]
            .as_str()
            .context("assembly guard plan SHA-256")?;
        let expected = format!(
            "argv[]={0} {1}/guard-plan.json --plan-sha256 {plan_hash} --self-sha256 {GUARD_SHA} ;",
            drain::GUARD_IMAGE,
            spec::STATE
        );
        ensure!(
            guard["ExecStart"]
                .as_str()
                .is_some_and(|start| start.contains(&expected))
                && guard["Restart"] == "no",
            "epoch 226 assembly guard command changed"
        );
    } else {
        ensure!(
            drain::quiet_service(spec::GUARD_SERVICE, &guard),
            "missing epoch 226 assembly guard has live state"
        );
    }
    Ok((timer, guard))
}

pub(crate) fn run() -> Result<()> {
    let arguments: Vec<_> = env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && arguments.len() == 3
            && matches!(arguments[2].as_str(), "--check" | "--apply"),
        "usage: jetstreamer-r2 finish-epoch226-assembly --check|--apply"
    );
    let apply = arguments[2] == "--apply";
    if apply {
        ensure!(
            env::var("CODEX_THREAD_ID").as_deref() == Ok(suffix::THREAD),
            "Foundation controller changed"
        );
    }
    let _lock = suffix::cadence_lock()?;
    let registration_path = path("cadence-registration.json");
    let launch_ref = private157::file_binding(&registration_path)?;
    let launch = sealed_json(&launch_ref, &registration_path)?;
    let invocation = launch["invocation_id"]
        .as_str()
        .context("assembly invocation")?;
    let claim = DiagnosticClaim {
        epoch: 226,
        unit: spec::UNIT.into(),
        invocation_id: invocation.into(),
        scratch_path: spec::ROOT.into(),
        launch_receipt: serde_json::from_value(launch_ref.clone())?,
    };
    validate_launch(&claim, &launch)?;
    let (producer, pid1_exit) = drain::clean_success(spec::UNIT, invocation)?;
    let root = Path::new(spec::ROOT);
    let (owner_ref, owner) = result_receipt(&root.join("receipts/owner.json"))?;
    let (result_ref, result) = result_receipt(&root.join("receipts/assemble.json"))?;
    let archive = archive_identity()?.context("epoch 226 assembled archive missing")?;
    ensure!(
        !root
            .join(ARCHIVE)
            .with_extension("jet.sha256")
            .try_exists()?
            && archive["identity"]["length"]
                .as_u64()
                .is_some_and(|len| len > 0),
        "epoch 226 private assembled archive is empty or has a readiness sidecar"
    );
    assembled_result(&owner, &result, &result_ref, &launch, &archive)?;
    let (timer, guard) = guard_state(&launch)?;
    if !apply {
        let drained =
            timer["ActiveState"] == "inactive" && drain::quiet_service(spec::GUARD_SERVICE, &guard);
        println!(
            "{}",
            json!({"epoch":226,"guard_drained":drained,"producer":producer,
            "pid1_exit":pid1_exit,"archive":archive,"result_receipt":result_ref,
            "publication_authorized":false})
        );
        return Ok(());
    }

    let fixed = json!({"launch":launch_ref,"pid1_exit":pid1_exit,"owner":owner_ref,
        "result":result_ref,"archive":archive,"archive_sha256":result["archive_sha256"]});
    let intent_path = path("terminal-drain-intent.json");
    if !intent_path.try_exists()? {
        ensure!(
            timer["ActiveState"] == "active",
            "assembly timer already drained without an intent"
        );
        suffix::record(
            &intent_path,
            &json!({"schema":INTENT,"scope":fixed,"guard":guard,
            "timer":timer,"publication_authorized":false}),
        )?;
    }
    let intent = suffix::document(&intent_path)?;
    ensure!(
        intent["schema"] == INTENT && intent["scope"] == fixed,
        "foreign assembly drain intent"
    );
    if timer["ActiveState"] == "active" {
        drain::stop(spec::TIMER)?;
    }
    let (timer_after, _) = guard_state(&launch)?;
    ensure!(
        timer_after["ActiveState"] == "inactive",
        "assembly timer still active"
    );
    let guard_after = suffix::wait(15, "assembly guard drain", || {
        let (_, guard) = guard_state(&launch)?;
        Ok(drain::quiet_service(spec::GUARD_SERVICE, &guard).then_some(guard))
    })?;
    let (producer_after, event_after) = drain::clean_success(spec::UNIT, invocation)?;
    ensure!(
        event_after == pid1_exit
            && archive_identity()?.as_ref() == Some(&archive)
            && result_receipt(&root.join("receipts/owner.json"))?.0 == owner_ref
            && result_receipt(&root.join("receipts/assemble.json"))?.0 == result_ref,
        "epoch 226 archive or terminal evidence changed during guard drain"
    );
    let terminal_path = path("terminal.json");
    if !terminal_path.try_exists()? {
        suffix::record(
            &terminal_path,
            &json!({"schema":COMPLETE,"epoch":226,"launch":launch_ref,
            "scope":fixed,"intent":private157::file_binding(&intent_path)?,
            "producer":producer_after,"timer_after":timer_after,"guard_after":guard_after,
            "guard_drained":true,"independent_full_verified":false,"plugin_verified":false,
            "publication_authorized":false}),
        )?;
    }
    let complete = suffix::document(&terminal_path)?;
    ensure!(
        complete["schema"] == COMPLETE
            && complete["scope"] == fixed
            && complete["guard_drained"] == true,
        "foreign assembly terminal completion"
    );
    println!("{}", private157::file_binding(&terminal_path)?);
    Ok(())
}
