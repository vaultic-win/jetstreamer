// Root captures genuine completed bracket evidence; never runs a worker.
use super::*;
mod checks {
    include!("../../historical-runtime/epoch223_bracket_proof.rs");
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    issuer_unit: String,
    task: BoundFile,
    result: BoundFile,
    journal: BoundFile,
    origin_clock: BoundFile,
    role_qualification: BoundFile,
    output: PathBuf,
}
pub(super) fn validate(binding: &BoundFile) -> Result<()> {
    let proof: Value = read_bound(binding)?;
    let get = |key: &str| -> Result<BoundFile> { Ok(serde_json::from_value(proof[key].clone())?) };
    let task: Value = read_bound(&get("task")?)?;
    let result: Value = read_bound(&get("result")?)?;
    let journal = bound_bytes(&get("journal")?, 0, 16 << 20)?;
    let qualification: Value = read_bound(&get("role_qualification")?)?;
    let spec: Value = read_bound(&get("capture_spec")?)?;
    let origin: OriginClock = read_bound(&get("origin_clock")?)?;
    validate_origin(&origin, millis()?)?;
    validate_origin_journal(&origin)?;
    let issuer: Actor = serde_json::from_value(proof["issuer"].clone())?;
    verify_reference(&issuer.executable)?;
    ensure!(
        issuer.unit == spec["issuer_unit"]
            && issuer.expected_exec_start
                == exact_helper_command(
                    &issuer,
                    "capture-epoch223-full-root-demotion-bracket-proof",
                    &get("capture_spec")?,
                    "--spec-sha256"
                ),
        "prior bracket capture is not bound to its actual issuer command"
    );
    checks::validate(&proof, &task, &result, &journal, &qualification, &spec)
        .map_err(anyhow::Error::msg)
}
pub(super) fn capture(binding: &BoundFile, executable: &BoundFile) -> Result<()> {
    let s: Spec = read_bound(binding)?;
    ensure!(
        s.schema == "jetstreamer-epoch223-full-root-prior-bracket-capture-spec-v1",
        "prior bracket capture schema"
    );
    let issuer = roles::own_role(
        &s.issuer_unit,
        "capture-epoch223-full-root-demotion-bracket-proof",
        binding,
        executable,
    )?;
    let task: Value = read_bound(&s.task)?;
    let actor: Actor = serde_json::from_value(task["actor"].clone())?;
    let qualification: Value = read_bound(&s.role_qualification)?;
    let result: Value = read_bound(&s.result)?;
    let journal = bound_bytes(&s.journal, 0, 16 << 20)?;
    let origin: OriginClock = read_bound(&s.origin_clock)?;
    validate_origin(&origin, millis()?)?;
    validate_origin_journal(&origin)?;
    let keys = "Id,InvocationID,NRestarts,MainPID,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,Type,User,Restart,ExecStart";
    let terminal = properties_with(&actor.unit, keys)?;
    let proof = json!({"schema":"jetstreamer-epoch223-full-root-prior-bracket-proof-v1","capture_spec":binding,
        "issuer":issuer,"task":s.task,"result":s.result,"journal":s.journal,"origin_clock":s.origin_clock,
        "role_qualification":s.role_qualification,"terminal_manager":terminal,"captured_unix_millis":millis()?,
        "original_start_unix_millis":origin.original_start_unix_millis,"publication_authorized":false,"r2_mutations":false});
    let spec: Value = read_bound(binding)?;
    checks::validate(&proof, &task, &result, &journal, &qualification, &spec)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        properties_with(&actor.unit, keys)? == terminal,
        "prior bracket manager changed during proof capture"
    );
    observe(&issuer)?;
    issuance::published(&s.output, &proof)?;
    Ok(())
}
