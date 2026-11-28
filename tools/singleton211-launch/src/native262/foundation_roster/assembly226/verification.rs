//! Bind the verification owner independently of the closed assembly.
use super::*;

pub(super) fn registration() -> Result<(Bound, Value)> {
    let state = Path::new(VERIFY_STATE);
    let path = state.join("cadence-registration.json");
    let reference = Bound::new(&path, hash(&path)?);
    let row = reference.sealed()?;
    let plan = binding(&row["plan"])?;
    let prepared = plan.sealed()?;
    let roster = binding(&row["roster"])?;
    let quote = roster.sealed()?;
    let image = binding(&row["image"])?;
    let release = Bound::new(VERIFY_RELEASE, hash(Path::new(VERIFY_RELEASE))?).sealed()?;
    ensure!(
        row["schema"] == VERIFY_LAUNCH
            && row["epoch"] == 226
            && row["publication_authorized"] == false
            && row["archive_copy_bytes"] == 0
            && row["actual"]["Id"] == VERIFY_UNIT
            && hex(text(&row["actual"], "InvocationID")?, 32)
            && plan.path == state.join("plan.json")
            && prepared["schema"] == VERIFY_PLAN
            && prepared["epoch"] == 226
            && roster.path == state.join("roster.json")
            && prepared["roster"] == json!(roster)
            && prepared["terminal"] == row["terminal"]
            && quote["schema"] == VERIFY_SCHEMA
            && quote["capacity"]["fits"] == true
            && quote["assembly_226_verification_quote"]["terminal"] == row["terminal"]
            && image.path == Path::new(VERIFY_IMAGE)
            && release["schema"] == "foundation-epoch226-verification-fleet-release-v1"
            && release["runner"] == json!(image),
        "epoch 226 verifier is outside its admitted invocation"
    );
    Ok((reference, row))
}

pub(in super::super) fn live(n: &mut Native) -> Result<AuxiliaryOwner> {
    let (launch, row) = registration()?;
    let owner = n.show_fields(VERIFY_UNIT, OWNER_FIELDS)?;
    live::same_owner(&row["actual"], &owner)?;
    let iid = text(&row["actual"], "InvocationID")?;
    let memory = live::finite_owner(&owner, VERIFY_UNIT, iid, VERIFY_MEMORY)?;
    let image = binding(&row["image"])?;
    image.artifact()?;
    let pid = text(&owner, "MainPID")?.parse()?;
    let ticks = process_ticks(pid)?;
    let plan = binding(&row["plan"])?;
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let exe = proc.join("exe");
    let expected = [
        VERIFY_IMAGE,
        "verify-epoch226-assembly",
        plan.path.to_str().context("verifier plan path")?,
        "--plan-sha256",
        &plan.sha256,
        "--self-sha256",
        &image.sha256,
    ]
    .join("\0")
        + "\0";
    ensure!(
        owner["AllowedCPUs"] == CPUS
            && fs::read_link(&exe)? == image.path
            && metadata_identity(&fs::metadata(&exe)?) == identity(&image.path)?
            && fs::read(proc.join("cmdline"))? == expected.as_bytes()
            && process_ticks(pid)? == ticks,
        "epoch 226 verifier live scope changed"
    );
    Ok(AuxiliaryOwner {
        launch,
        owner,
        memory,
        ticks,
    })
}

pub(in super::super) fn account_observation(
    n: &mut Native,
    rows: &mut Vec<Value>,
    active: Option<&AuxiliaryOwner>,
) -> Result<()> {
    let mut matches = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row["phase"] == VERIFY_PHASE || row["unit"]["Id"] == VERIFY_UNIT);
    let Some((index, observed)) = matches.next() else {
        // The fresh owner census still charges the verifier between its launch and its first sample.
        return Ok(());
    };
    let (launch, record) = registration()?;
    ensure!(
        matches.next().is_none()
            && observed["phase"] == VERIFY_PHASE
            && observed["epoch"] == 226
            && observed["unit"]["Id"] == VERIFY_UNIT
            && observed["evidence"] == json!([launch, record["plan"]]),
        "foreign or duplicate epoch 226 verification observation"
    );
    live::same_owner(&observed["unit"], &record["actual"])?;
    if let Some(owner) = active {
        live::same_owner(&observed["unit"], &owner.owner)?;
    } else {
        let fields = "Id,ActiveState,SubState,MainPID,ControlPID,ControlGroup,Job,Result,ExecMainStatus,NRestarts";
        let current = n.show_fields(VERIFY_UNIT, fields)?;
        ensure!(
            current["ActiveState"] == "inactive"
                && current["SubState"] == "dead"
                && current["MainPID"] == "0"
                && current["ControlPID"] == "0"
                && current["ControlGroup"] == ""
                && current["Job"] == ""
                && current["Result"] == "success"
                && current["ExecMainStatus"] == "0"
                && current["NRestarts"] == "0"
                && !Path::new("/sys/fs/cgroup/system.slice")
                    .join(VERIFY_UNIT)
                    .exists(),
            "epoch 226 verifier has not proved a clean drain"
        );
        let iid = text(&record["actual"], "InvocationID")?;
        let events = n.run(
            "/usr/bin/journalctl",
            &[
                "-b",
                "--no-pager",
                "-o",
                "json",
                "_PID=1",
                "_UID=0",
                &format!("UNIT={VERIFY_UNIT}"),
                &format!("INVOCATION_ID={iid}"),
                "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
            ],
        )?;
        let event: Value =
            serde_json::from_slice(&events).context("epoch 226 verifier PID 1 exit")?;
        ensure!(
            event["INVOCATION_ID"] == iid && event["UNIT"] == VERIFY_UNIT,
            "epoch 226 verifier terminal owner differs"
        );
    }
    rows.remove(index);
    Ok(())
}
