//! Accept the separately recovered 266 launch inventory without reissuing its admission.
use super::*;
use native265::{EvidenceReader, FsEvidence, binding, num, sealed, text};
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch266-recovered-input-v1";
const IID: &str = "de754f74bbac40b9877d3b912af14886";
const REPORT: &str =
    "/var/lib/jetstreamer/horizon266-original-census-v160-de754f74-v1/recovery.json";
const REPORT_SHA: &str = "cd903100511486d20f4d8972d97943b825d20b94d8edead4a27574f0860ad1c6";
const ORIGINAL: &str = "/home/ubuntu/.codex/diagnostics/horizon266-capture-v160-original-census";
const HAND_SHA: &str = "5479bc3f98e609aa49158ea812482ed018dfb0d88290481c735b95f19eecbb24";
const CONTROL: &str = "horizon-265-replacement-20261119-protective-v3.service";
const CLOCK: u64 = 1795229218;
const TRANSITION: &str =
    "/var/lib/jetstreamer/horizon266-successor-consumer-v161-v1/transition.json";
fn report_ref() -> BoundFile {
    BoundFile {
        path: REPORT.into(),
        sha256: REPORT_SHA.into(),
    }
}
fn checked_report() -> Result<Value> {
    let r = sealed(&report_ref())?;
    ensure!(
        r["original_capture_clock"] == CLOCK
            && r["native_handoff"]["sha256"] == HAND_SHA
            && r["manager_rows"] == 238
            && r["invocation_id"] == IID
            && r["native_unit"] == native266::UNIT
            && r["running_origin_written_by_original_helper"] == false,
        "different original capture"
    );
    let source = Path::new(ORIGINAL);
    let dir = fs::symlink_metadata(source)?;
    use std::os::unix::fs::MetadataExt;
    ensure!(
        dir.is_dir()
            && source.canonicalize()? == source
            && dir.uid() == 0
            && dir.mode() & 0o077 == 0,
        "original census private custody"
    );
    for (name, row) in r["source_files"]
        .as_object()
        .context("original capture members")?
    {
        let b = binding(row)?;
        let m = fs::symlink_metadata(&b.path)?;
        ensure!(
            b.path == source.join(name)
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o077 == 0,
            "private original {} changed",
            name
        );
        let bytes = read_stable_bounded(&b.path, 4 << 20, "original private census")?;
        ensure!(
            hex_lower(&Sha256::digest(bytes)) == b.sha256,
            "original private {} digest",
            name
        );
    }
    for g in r["guard_265_history"]
        .as_array()
        .context("original 265 rotation")?
    {
        let s = bound_json(&binding(&g["sample"])?)?;
        ensure!(
            s["guard_invocation_id"] == g["iid"]
                && s["plan_sha256"] == r["guard_265"]["guard_plan"]["sha256"]
                && s["trip_reason"].is_null(),
            "265 original sample changed"
        );
    }
    for g in r["native_266_bracket"]
        .as_array()
        .context("original native guard bracket")?
    {
        let s = bound_json(&binding(&g["sample"])?)?;
        ensure!(
            s["producer_invocation_id"] == IID
                && s["process_observation"]["processes"] == g["processes"]
                && s["trip_reason"].is_null(),
            "266 original sample changed"
        );
    }
    Ok(r)
}
pub(super) fn recovered(h: &Value, a: &Value, wall: u64) -> Result<Value> {
    let r = checked_report()?;
    ensure!(
        r["native_admission"] == h["admission"]
            && r["fleet"] == a["fleet"]
            && r["observer"] == a["observer"]
            && r["ledger"] == a["reservation_ledger"]
            && h["invocation_id"] == IID
            && h["main_pid"] == 2563315
            && num(h, "recorded_unix_seconds")?
                .checked_add(300)
                .is_some_and(|limit| CLOCK <= limit)
            && wall > CLOCK
            && wall <= native266::now()?,
        "266 recovery chronology"
    );
    let mut v = json!({"schema":SCHEMA,"epoch":266,"unit":native266::UNIT,"invocation_id":IID,"main_pid":h["main_pid"],"expected_exec_start":h["producer"]["ExecStart"],"private_run_root":native266::ROOT,
        "bootstrap_slot":114910768,"startup_handoff":r["native_handoff"],"admission":h["admission"],"original_capture_spec":r["original_spec"],"retained_evidence":private157::binding(&report_ref()),"observed_unix_seconds":CLOCK,
        "recorded_unix_seconds":wall,"sampled_at_utc":publication203::utc(wall)?,"observer":a["observer"],"fleet":a["fleet"],"boot_id":a["boot_id"],"peer_window":h["peer_window"],
        "replay_entries":0,"resource_samples_taken":0,"native_input_qualified":false,"ordinary_replay_claim":false,"original_native_capture_succeeded":false});
    native265::deny(&mut v);
    Ok(v)
}
pub(super) fn claim(c: &PipelineClaim, v: &Value) -> Result<()> {
    let (h, a) = native266::startup(&binding(&v["startup_handoff"])?)?;
    ensure!(
        v == &recovered(&h, &a, num(v, "recorded_unix_seconds")?)?
            && c.epoch == 266
            && c.phase == native266::PHASE
            && c.unit == native266::UNIT
            && c.invocation_id == IID
            && v["expected_exec_start"] == c.expected_exec_start,
        "different recovered native owner"
    );
    Ok(())
}
/// Revalidate the successor build and its Main-approved evidence-only transition.
/// The original role stays authoritative for every normal capture and launch.
pub(super) fn successor(a: &Value, actor: &str, actual: bool) -> Result<()> {
    let tb = binding(&private157::file_binding(Path::new(TRANSITION))?)?;
    let t = sealed(&tb)?;
    ensure!(
        t["schema"] == "horizon-native266-consumer-transition-v1"
            && t["original_handoff"]["sha256"] == HAND_SHA
            && t["original_publication"] == a["source_publication"]
            && t["original_helper"]["sha256"]
                == "185de79a143dc027161c0b855d2d838f03d5bdd939d9987f6c92dbefd171b913"
            && t["Main_accepted"] == true
            && t["source_only_consumer_change"] == true
            && t["remote_ref"] == "refs/heads/account-updates"
            && t["successor"]["sha256"] == actor
            && native265::hex(actor, 64),
        "unqualified 266 successor"
    );
    let pubn = sealed(&binding(&a["source_publication"])?)?;
    let roles = pubn["artifacts"].as_array().context("original roles")?;
    let old = roles
        .iter()
        .find(|r| r["role"] == "fleet")
        .context("original fleet")?;
    ensure!(
        old["artifact"] == t["original_helper"] && old["provenance"] == t["original_provenance"],
        "original source lineage"
    );
    let image = binding(&t["successor"])?;
    let p = sealed(&binding(&t["successor_provenance"])?)?;
    let q = sealed(&binding(&t["qualification"])?)?;
    ensure!(
        p["artifact"] == t["successor"]
            && p["all_source_dependencies_enumerated"] == true
            && p["source_commit"] == t["source_commit"]
            && native265::hex(text(&t, "source_commit")?, 40)
            && q["source_commit"] == t["source_commit"]
            && q["image"] == t["successor"]
            && q["remote_containment_verified"] == true
            && q["qualified"] == true
            && q["remote_mutations"] == false,
        "successor build evidence"
    );
    if actual {
        ensure!(
            std::env::current_exe()?.canonicalize()? == image.path && image.sha256 == actor,
            "wrong successor execution"
        );
        let _ = FsEvidence.bytes(&image, 128 << 20)?;
    }
    Ok(())
}
/// The only recurring control allowed to rotate is the admitted 265 protective
/// oneshot. Reopen its exact receipt and root manager start/terminal first.
pub(super) fn peers(
    previous: &Value,
    current: &BTreeMap<String, Value>,
    exclude: &str,
) -> Result<()> {
    let old = &previous["unit_census"][CONTROL];
    let next = current.get(CONTROL).context("missing recorded 265 guard")?;
    if old["InvocationID"] == next["InvocationID"] {
        return native265_capture::peers(previous, current, exclude);
    }
    let report = checked_report()?;
    let ctl = &report["guard_265"];
    for k in ["executable", "service_source", "timer_source", "guard_plan"] {
        let b = binding(&ctl[k])?;
        let _ = FsEvidence.bytes(&b, 4 << 20)?;
    }
    let gp = sealed(&binding(&ctl["guard_plan"])?)?;
    for row in [old, next] {
        let iid = text(row, "InvocationID")?;
        ensure!(
            native265::hex(iid, 32)
                && row["Id"] == CONTROL
                && row["MainPID"] == "0"
                && row["SubState"] == "dead"
                && row["ActiveState"] == "inactive"
                && row["Result"] == "success",
            "265 timer not at drained boundary"
        );
        let p = Path::new(text(&gp, "receipt_directory")?).join(format!("sample-{iid}.json"));
        let s = bound_json(&binding(&private157::file_binding(&p)?)?)?;
        ensure!(
            s["guard_invocation_id"] == iid
                && s["guard_sha256"] == ctl["executable"]["sha256"]
                && s["plan_sha256"] == ctl["guard_plan"]["sha256"]
                && s["producer_invocation_id"] == gp["invocation_id"]
                && s["trip_reason"].is_null(),
            "unbound actual 265 firing"
        );
        let out = ProcessCommand::new("journalctl")
            .args([
                "-b",
                "--no-pager",
                "-o",
                "json",
                "_UID=0",
                "_PID=1",
                &format!("UNIT={CONTROL}"),
                &format!("INVOCATION_ID={iid}"),
            ])
            .output()?;
        ensure!(out.status.success(), "265 timer journal");
        let events = serde_json::Deserializer::from_slice(&out.stdout)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in [
            "7d4958e842da4a758f6c1cdc7b36dcc5",
            "7ad2d189f7e94e70a38c781354912448",
        ] {
            ensure!(
                events
                    .iter()
                    .filter(|v| v["_PID"] == "1"
                        && v["_UID"] == "0"
                        && v["INVOCATION_ID"] == iid
                        && v["UNIT"] == CONTROL
                        && v["MESSAGE_ID"] == id)
                    .count()
                    == 1,
                "ambiguous 265 firing"
            );
        }
    }
    let mut adjusted = previous.clone();
    adjusted["unit_census"][CONTROL]["InvocationID"] = next["InvocationID"].clone();
    native265_capture::peers(&adjusted, current, exclude)
}
