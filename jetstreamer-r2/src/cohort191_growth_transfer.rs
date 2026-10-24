//! Exact original191 future replay allocation -> retained read-only delivery.
//! Metadata only. No source byte, guard, archive gate or execution is changed.
use super::*;
use std::os::fd::AsRawFd;

const PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-node02-original191-growth-transfer-20261024-v2/jetstreamer-r2";
const ROOT: &str = "/var/lib/jetstreamer/horizon-original191-growth-transfer-20261024-v1";
const FLEETS: &str = "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1";
const AUTHORITY: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-full-admission-20261023-v2/admission-manifest.json";
const AUTHORITY_SHA: &str = "c2074a168945f30e2a9a83464f8d07e94e835bbb504e0a84c5cdf91323a71cb9";
const TERMINAL: &str =
    "/var/lib/jetstreamer/horizon-cohort191-terminal-cache-transition-20261024-v1/terminal.json";
const TERMINAL_SHA: &str = "245bf9b4d180f64af8775e9e119e00058d492d57d7043fb42e8318f96ceb14ed";
const SOURCE: &str = "/home/sol/.jetstreamer-private/epochs-191-194-v4-20261009-v1/lane-a/private/destination-a1c8ba888df3256ab55ded6e75ce724aba84a1ed586599353a73fa1d60696cfa/evidence/archive-batches/destination-000000000000fc00-0000000006400013/batch-327bf71b16adde942ec67c0dffa6edad2f9413fdc0147e4471f0625688f1e5d7.json";
const SOURCE_SHA: &str = "52a8ddc2be6c8301404f4cd2ad058faab49d28aefb8e30ee64563e8a23ead746";
const PUBLIC: &str = "/home/sol/.jetstreamer-private/epochs191-194-target5-20261016-v2-import/destination-ae2f530244e391ea343ca338abe7f4673c52fd4bc8814369fd5234d07a8db1e1/evidence/archive-batches/destination-000000000000fc00-0000000011520001/batch-5be8b8f097d5dd899591f6220944d985ac1a77f39ab49d8ce9405e54c09f3eb7.json";
const PUBLIC_SHA: &str = "44e92a931165f5144cafc8ce1aaa0cfe34ac3f91d95436443378ef98864f0ca6";
const OS_TRANSFER: &str =
    "/usr/local/lib/jetstreamer/horizon-cohort191-os-claim-transfer-20261024-v1/transfer.json";
const OS_SHA: &str = "1f697f633f8c231ac1fa236f1181fb80fef0ffa02986dae85cca800ef95542c6";
const GROWTH: u64 = 824_633_720_832;
const ORIGINAL185: &str = "0de9498a3c2f4c6dbd7350d052fc7e02";
const CLOSED185: &str =
    "/var/lib/jetstreamer/horizon-old185-attempt-growth-closure-20261024-v1/closure.json";
const CLOSED185_SHA: &str = "7a57f946c5e6cb08bc9a99e8a6b76a6ed33fffb013a673715924192a327d0553";
const ORIGINAL141: &str = "e639f007d482464f8a251455659d2ede";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Row {
    claim_key: String,
    epoch: u64,
    producer_invocation_id: String,
    outstanding_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    program: Bound,
    original_reservation: Bound,
    terminal: Bound,
    source_batch: Bound,
    public_batch: Bound,
    fleet: Bound,
    delivery_event: Bound,
    delivery_policy: Bound,
    census: Bound,
    transfer_authorized: bool,
    prior_check: Option<Bound>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadPlan {
    schema: String,
    program: Bound,
    transfer: Bound,
    reservation_rows: Vec<Row>,
}

pub(super) fn native_context() -> Result<bool> {
    Ok(unsafe { libc::geteuid() } == 0
        && fs::read_link("/proc/self/exe")? == Path::new(PROGRAM)
        && matches!(
            env::args().nth(1).as_deref(),
            Some("check-original191-growth" | "transfer-original191-growth")
        ))
}
fn subject() -> Value {
    json!({"host":"dev-samjohnson","first_epoch":191,"last_epoch":194,
        "producer":UNIT,"producer_invocation_id":IID,"controller":CONTROLLER,"controller_invocation_id":CID,
        "original_replay_future_growth_bytes":GROWTH,"new_replay_future_growth_bytes":0,
        "retained_source_public_scratch_and_inputs":true,"physical_free_space_credit_bytes":0,
        "original141_whole_root_cap_bytes":549_755_813_888u64})
}
fn exact(b: &Bound, path: &str, sha: &str) -> Result<()> {
    ensure!(
        b.path == Path::new(path) && b.sha256 == sha,
        "foreign191 transfer authority/batch binding"
    );
    Ok(())
}
fn scope(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-original191-growth-transfer-plan-v2"
            && p.program.path == Path::new(PROGRAM),
        "foreign191 transfer plan/program"
    );
    exact(&p.original_reservation, AUTHORITY, AUTHORITY_SHA)?;
    exact(&p.terminal, TERMINAL, TERMINAL_SHA)?;
    exact(&p.source_batch, SOURCE, SOURCE_SHA)?;
    exact(&p.public_batch, PUBLIC, PUBLIC_SHA)?;
    let a = bound(&p.original_reservation, true)?;
    ensure!(
        a["schema"] == "jetstreamer-historical-performance-admission-v1"
            && a["filesystem"] == "/home/sol"
            && a["minimum_free_bytes"] == 4_328_380_063_174u64
            && a["comment"].as_str().is_some_and(|s| s
                .contains("Full768GiB own and every older external worker")
                && s.contains("four older growth claims"))
            && a["expected_units"].as_array().is_some_and(|rows| rows
                .iter()
                .filter(|r| r["unit"] == UNIT
                    && r["invocation_id"] == IID
                    && r["restarts"] == 0
                    && r["main_pid"] == 2_189_644)
                .count()
                == 1),
        "191 original768GiB protection authority/producer binding differs"
    );
    Ok(())
}
fn protected141(rows: &[Row]) -> Result<()> {
    let key = format!("epoch141/{ORIGINAL141}");
    let found: Vec<_> = rows
        .iter()
        .filter(|r| r.producer_invocation_id == ORIGINAL141)
        .collect();
    ensure!(
        found.len() == 1
            && found[0].claim_key == key
            && found[0].epoch == 141
            && found[0].outstanding_bytes == 549_755_813_888,
        "191 transfer must preserve original141 full whole-root cap"
    );
    Ok(())
}
fn protected185(rows: &[Row]) -> Result<()> {
    let key = format!("epoch185/{ORIGINAL185}");
    let found: Vec<_> = rows
        .iter()
        .filter(|r| r.producer_invocation_id == ORIGINAL185)
        .collect();
    ensure!(
        found.len() == 1
            && found[0].claim_key == key
            && found[0].epoch == 185
            && found[0].outstanding_bytes == 0,
        "191 transfer must preserve the authenticated original185 closure at zero"
    );
    Ok(())
}
fn project(rows: &[Row]) -> Result<(Vec<Row>, u64)> {
    protected141(rows)?;
    protected185(rows)?;
    let key = format!("epoch191/{IID}");
    let mut keys = BTreeSet::new();
    let mut found = false;
    let mut removed = 0;
    let mut out = rows.to_vec();
    for row in &mut out {
        ensure!(
            !row.claim_key.is_empty() && keys.insert(row.claim_key.clone()),
            "duplicate/empty191 projection claim key"
        );
        if row.claim_key == key {
            ensure!(
                row.epoch == 191
                    && row.producer_invocation_id == IID
                    && matches!(row.outstanding_bytes, 0 | GROWTH),
                "foreign/partial original191 reservation disposition"
            );
            found = true;
            removed = row.outstanding_bytes;
            row.outstanding_bytes = 0;
        } else {
            ensure!(
                row.producer_invocation_id != IID,
                "original191 invocation aliased under another claim key"
            );
        }
    }
    ensure!(
        found,
        "191 projection needs its explicit original claim row"
    );
    Ok((out, removed))
}
fn policy_shape(v: &Value) -> Result<(Bound, u64)> {
    ensure!(
        v["schema"] == "jetstreamer-original191-readonly-delivery-policy-v2"
            && v["host"] == "dev-samjohnson"
            && v["epochs"] == json!([191, 192, 193, 194])
            && v["source_and_public_materialized"] == true
            && v["source_and_public_retirement_authorized"] == false
            && v["new_replay_authorized"] == false
            && v["restore_authorized"] == false
            && v["guard_floor_changes_authorized"] == false
            && v["publication_authorized"] == false
            && v["physical_free_space_credit_bytes"] == 0
            && v["data_metadata_allowance_bytes"]
                .as_u64()
                .is_some_and(|n| ((16 << 20)..=(64 << 20)).contains(&n))
            && v["verifier_memory_bytes"] == 64u64 << 30
            && v["queue_memory_bytes"] == 2u64 << 30
            && v["serial_uploader_memory_bytes"] == 2u64 << 30
            && v["shared_compiler_memory_bytes"] == 16u64 << 30
            && v["shared_compiler_counted_once"] == true
            && v["os_log_evidence_bytes"] == 520u64 << 20
            && v["boundary_obligations"]
                == json!(["190-191", "191-192", "192-193", "193-194", "194-195"]),
        "191 readonly delivery policy drops data/OS/memory/boundary obligations or acquires authority"
    );
    let os: Bound = serde_json::from_value(v["os_claim_transfer"].clone())?;
    exact(&os, OS_TRANSFER, OS_SHA)?;
    let other = v["other_pending_os_growth_bytes"]
        .as_u64()
        .context("191 preserved other OS claims")?;
    ensure!(other >= 23_505_223_680, "191 other OS promises dropped");
    Ok((os, other))
}
fn census_shape(c: &Value, f: &Value, p: &Plan, now: u64) -> Result<Vec<Row>> {
    let at = c["recorded_unix_seconds"]
        .as_u64()
        .context("191 claim census clock")?;
    let sample = fleet::utc_seconds(f["sampled_at_utc"].as_str().context("191 fleet clock")?)?;
    ensure!(
        c["schema"] == "jetstreamer-original191-growth-census-v2"
            && c["subject"] == subject()
            && c["fleet"] == json!(p.fleet)
            && c["delivery_event"] == json!(p.delivery_event)
            && c["delivery_policy"] == json!(p.delivery_policy)
            && c["sampled_at_utc"] == f["sampled_at_utc"]
            && f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && sample <= now
            && now - sample <= 1800
            && at >= sample
            && at <= now
            && now - at <= 900
            && c["all_other_reservations_unchanged"] == true
            && c["all_retained_bytes_preserved"] == true
            && c["all_restore_and_boundary_claims_preserved"] == true
            && c["previously_disposed_original191_bytes"] == 0
            && c["physical_free_space_credit_bytes"] == 0
            && c["new_execution_authorized"] == false
            && c["guard_changes_authorized"] == false
            && c["other_claim_evidence"]
                .as_array()
                .is_some_and(|a| !a.is_empty()),
        "191 transfer needs fresh complete independent all-claims census"
    );
    let rows: Vec<Row> = serde_json::from_value(c["reservation_rows"].clone())?;
    ensure!(
        project(&rows)?.1 == GROWTH,
        "191 first transfer census must retain the entire original promise"
    );
    for key in ["active", "diagnostics", "pipelines"] {
        for row in f[key].as_array().context("191 full owner census")? {
            if key == "active" || row["live"] == true {
                for field in ["producer", "unit", "controller"] {
                    ensure!(
                        row[field]["InvocationID"] != IID && row[field]["InvocationID"] != CID,
                        "original191 replay/controller still owns live work"
                    );
                }
            }
            if key == "active"
                && row["ordinary_replay_claim"] != false
                && row["producer"].is_object()
            {
                let iid = row["producer"]["InvocationID"]
                    .as_str()
                    .context("191 other replay owner")?;
                ensure!(
                    rows.iter()
                        .any(|r| r.producer_invocation_id == iid && r.outstanding_bytes >= GROWTH),
                    "191 transfer omits another live replay reservation"
                );
            }
        }
    }
    Ok(rows)
}
fn latest_fleet(selected: &Bound, f: &Value) -> Result<()> {
    ensure!(
        selected.path.parent() == Some(Path::new(FLEETS)),
        "foreign191 campaign fleet directory"
    );
    let at = fleet::utc_seconds(
        f["sampled_at_utc"]
            .as_str()
            .context("191 selected fleet clock")?,
    )?;
    let event = f["recorded_unix_seconds"]
        .as_u64()
        .context("191 selected event clock")?;
    for entry in fs::read_dir(FLEETS)? {
        let path = entry?.path();
        if path == selected.path || path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let v: Value =
            serde_json::from_slice(&read_stable_bounded(&path, 16 << 20, "191 latest fleet")?)
                .with_context(|| format!("191 latest fleet JSON {}", path.display()))?;
        if v["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && v["first_epoch"] == 101
            && v["last_epoch"] == 200
        {
            let t = fleet::utc_seconds(
                v["sampled_at_utc"]
                    .as_str()
                    .context("191 candidate fleet clock")?,
            )?;
            ensure!(
                t < at
                    || (t == at
                        && v["recorded_unix_seconds"]
                            .as_u64()
                            .context("191 candidate event clock")?
                            < event),
                "newer accepted fleet/phase event invalidates191 growth census"
            );
        }
    }
    Ok(())
}
fn routes(unit: &str) -> Result<Value> {
    let out=Command::new("/usr/bin/systemctl").args(["show",unit,"--all","--no-pager",
        "--property=Id,LoadState,ActiveState,SubState,MainPID,NRestarts,ControlGroup,Job,Restart,Triggers,TriggeredBy,OnSuccess,OnFailure,UnitFileState,Result,ExecMainStatus,ExecMainCode,RequiredBy,WantedBy,RequisiteOf,BoundBy,UpheldBy,PartOf,ConsistsOf,StartLimitAction,FailureAction,SuccessAction"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16384,
        "191 native launch-route metadata unavailable"
    );
    let mut fields = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("191 route property framing")?;
        ensure!(
            fields.insert(k.into(), json!(v)).is_none(),
            "duplicate191 route property"
        );
    }
    let v = Value::Object(fields);
    routes_shape(&v, unit)?;
    Ok(v)
}
fn routes_shape(v: &Value, unit: &str) -> Result<()> {
    let inert = v["ActiveState"] == "inactive"
        && v["SubState"] == "dead"
        && v["MainPID"] == "0"
        && v["NRestarts"] == "0"
        && v["ControlGroup"] == ""
        && no_manager_job(&v["Job"])
        && [
            "Triggers",
            "TriggeredBy",
            "OnSuccess",
            "OnFailure",
            "RequiredBy",
            "WantedBy",
            "RequisiteOf",
            "BoundBy",
            "UpheldBy",
            "PartOf",
            "ConsistsOf",
        ]
        .iter()
        .all(|k| v[*k] == "");
    let absent = v["LoadState"] == "not-found" && matches!(v["Restart"].as_str(), Some("" | "no"));
    // The separately authenticated collected terminal proof establishes the
    // natural successful exit. An inert static controller's on-failure policy
    // cannot restart it without a new start job or dependency/trigger route.
    let dormant_success = unit == CONTROLLER
        && v["UnitFileState"] == "static"
        && v["Restart"] == "on-failure"
        && v["Result"] == "success"
        && v["ExecMainStatus"] == "0"
        && v["ExecMainCode"] == "0";
    let actions_inert = ["StartLimitAction", "FailureAction", "SuccessAction"]
        .iter()
        .all(|key| v[*key] == "none");
    let installed = v["LoadState"] == "loaded"
        && (v["Restart"] == "no" || dormant_success)
        && actions_inert
        && matches!(v["UnitFileState"].as_str(), Some("disabled" | "static"));
    ensure!(
        matches!(unit, UNIT | CONTROLLER) && v["Id"] == unit && inert && (absent || installed),
        "191 original automatic launch route is not positively fenced; independent metadata action needed"
    );
    Ok(())
}
fn no_queued_entries(v: &Value, names: &BTreeSet<String>) -> Result<()> {
    ensure!(
        v["type"] == "a(usssoo)",
        "191 native ListJobs signature differs"
    );
    let returns = v["data"]
        .as_array()
        .context("191 native ListJobs returns")?;
    ensure!(returns.len() == 1, "191 native ListJobs return arity");
    let mut ids = BTreeSet::new();
    for job in returns[0].as_array().context("191 native jobs array")? {
        let row = job.as_array().context("191 native job tuple")?;
        ensure!(row.len() == 6, "191 native job tuple arity");
        let id = row[0]
            .as_u64()
            .filter(|n| *n > 0 && *n <= u64::from(u32::MAX))
            .context("191 native job ID")?;
        let name = row[1].as_str().context("191 native job unit")?;
        let mut unit_object = String::from("/org/freedesktop/systemd1/unit/");
        for byte in name.bytes() {
            if byte.is_ascii_alphanumeric() {
                unit_object.push(char::from(byte));
            } else {
                unit_object.push_str(&format!("_{byte:02x}"));
            }
        }
        ensure!(
            ids.insert(id)
                && row[2].as_str().is_some_and(|s| !s.is_empty())
                && matches!(row[3].as_str(), Some("waiting" | "running"))
                && !name.is_empty()
                && name.len() <= 255
                && !name
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                && row[4] == format!("/org/freedesktop/systemd1/job/{id}")
                && row[5] == unit_object,
            "191 native job identity/state differs"
        );
        let entry = name.starts_with("jetstreamer-root-sweep-")
            || name.starts_with("horizon-controller-")
            || name.starts_with("horizon-perf-")
            || name.starts_with("horizon-qualify-")
            || (name.starts_with("jetstreamer-") && name.contains("controller"));
        let downstream = name.contains("191")
            && (name.starts_with("horizon-full-verify-")
                || name.starts_with("horizon-plugin-verify-")
                || name.starts_with("horizon-cohort191-"));
        ensure!(
            !entry && (!downstream || names.contains(name)),
            "queued replay/unbound downstream job invalidates191 transfer"
        );
    }
    Ok(())
}
fn fresh(p: &Plan) -> Result<Value> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let f = bound(&p.fleet, false)?;
    let c = bound(&p.census, true)?;
    let rows = census_shape(&c, &f, p, now)?;
    latest_fleet(&p.fleet, &f)?;
    for item in c["other_claim_evidence"].as_array().unwrap() {
        bound(&serde_json::from_value::<Bound>(item.clone())?, false)?;
    }
    let policy = bound(&p.delivery_policy, true)?;
    ensure!(c["other_claim_evidence"].as_array().unwrap().iter().any(|b|
        b["path"]=="/var/lib/jetstreamer/horizon-original141-capped-root-admission-20261023-v1/admission.json"
        && b["sha256"]=="945561bbf6dc282cbc0375cb84d777abace765956f61e8cd1e35863056ca5b3b"),
        "191 all-claims census omits actual original141 cap binding");
    ensure!(
        c["other_claim_evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["path"] == CLOSED185 && b["sha256"] == CLOSED185_SHA),
        "191 census omits authenticated original185 closure overlay"
    );
    let closure = bound(
        &Bound {
            path: CLOSED185.into(),
            sha256: CLOSED185_SHA.into(),
        },
        false,
    )?;
    ensure!(
        closure["schema"] == "jetstreamer-horizon-old185-attempt-growth-closed-v2"
            && closure["descriptor"]["subject"]["producer_invocation_id"] == ORIGINAL185
            && closure["closed_original_reservation_bytes"] == GROWTH
            && closure["physical_space_credit_bytes"] == 0
            && closure["archive_or_scratch_removed"] == false
            && closure["guard_floor_mutations_authorized"] == false
            && closure["new_replay_or_restore_authorized"] == false,
        "191 census changed original185 closure authority"
    );
    let (os, other) = policy_shape(&policy)?;
    let budget = crate::cohort191_dispatch::growth_transfer_delivery_budget(&os, other)?;
    let terminal =
        terminal_transition::growth_terminal(&p.terminal, &p.source_batch, &p.public_batch, now)?;
    let old_producer = routes(UNIT)?;
    let old_controller = routes(CONTROLLER)?;
    let members = BTreeSet::from([191, 192, 193, 194]);
    let import = dispatch_import_check(&p.source_batch, &p.public_batch, &members)?;
    // Native import relocated each committed source archive into the public
    // destination. Authenticate the original inode there; do not require a
    // second copy at the historical source path or a stale run directory.
    let source = batch(&p.source_batch, false, &BTreeSet::new())?;
    let public = batch(&p.public_batch, true, &members)?;
    let relocation = relocated_archives(&source, &public)?;
    let mut retained_layout = Vec::new();
    for path in [
        PathBuf::from(LANE),
        Path::new(LANE).join("private"),
        Path::new(LANE).join("config"),
        Path::new(LANE).join("output"),
        PathBuf::from(IMPORT_ROOT),
        PathBuf::from("/home/sol/horizon"),
    ] {
        let md = fs::symlink_metadata(&path)?;
        ensure!(
            md.is_dir() && path.canonicalize()? == path,
            "191 retained layout disappeared/aliased"
        );
        retained_layout.push(json!({"path":path,"device":md.dev(),"inode":md.ino()}));
    }
    let private_refs =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), Path::new(LANE))?;
    ensure!(
        private_refs.references.is_empty(),
        "191 private replay namespace still has a consumer; separately qualify any readonly exception"
    );
    let event = bound(&p.delivery_event, false)?;
    let sample = fleet::utc_seconds(
        f["sampled_at_utc"]
            .as_str()
            .context("191 accepted sample")?,
    )?;
    validate_event(&event, sample)?;
    ensure!(
        event["source_batch"] == json!(p.source_batch)
            && event["public_batch"] == json!(p.public_batch)
            && event["native_terminal_proof"] == json!(p.terminal),
        "191 current delivery event borrows different terminal/import"
    );
    let names: BTreeSet<String> = f["unit_census"]
        .as_object()
        .context("191 full unit census")?
        .keys()
        .cloned()
        .collect();
    let current = fleet::census(&names, 101, 200)?;
    let mut stable = BTreeMap::new();
    for (name, u) in &current {
        let old = &f["unit_census"][name];
        if old["MainPID"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n > 0)
            || old["ActiveState"] == "activating"
            || u["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
            || u["ActiveState"] == "activating"
        {
            for key in [
                "Id",
                "LoadState",
                "InvocationID",
                "MainPID",
                "NRestarts",
                "ActiveState",
                "SubState",
            ] {
                ensure!(
                    old[key] == u[key],
                    "191 full live owner changed:{name}/{key}"
                );
            }
            ensure!(u["NRestarts"] == "0", "191 live owner restarted");
            stable.insert(name.clone(), u.clone());
        }
    }
    let claims: Vec<Claim> = serde_json::from_value(event["claims"].clone())?;
    ensure!(
        !claims.is_empty()
            && claims.iter().all(|q| (191..=194).contains(&q.epoch)
                && matches!(
                    q.phase.as_str(),
                    "cohort191-delivery"
                        | "full-verification"
                        | "plugin-verification"
                        | "upload-readback"
                )),
        "191 current delivery has no bounded readonly owner"
    );
    for claim in &claims {
        phase_scope(claim)?;
        let u = current
            .get(&claim.unit)
            .context("191 current delivery owner missing from full fleet")?;
        live(u, claim)?;
        program(claim, u)?;
        ensure!(
            event["unit_census"][&claim.unit] == *u,
            "191 event/current owner changed"
        );
    }
    let allowance = policy["data_metadata_allowance_bytes"].as_u64().unwrap();
    ensure!(
        rows.iter()
            .any(|r| r.claim_key == "cohort191/readonly-data-metadata"
                && r.epoch == 191
                && r.outstanding_bytes >= allowance
                && claims
                    .iter()
                    .any(|c| c.invocation_id == r.producer_invocation_id)),
        "191 transfer omits separately owned bounded data receipt/status allowance"
    );
    let jobs = Command::new("/usr/bin/busctl")
        .args([
            "--system",
            "--json=short",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "ListJobs",
        ])
        .output()?;
    ensure!(
        jobs.status.success() && jobs.stdout.len() <= 1 << 20,
        "191 native job census unavailable"
    );
    no_queued_entries(&serde_json::from_slice(&jobs.stdout)?, &names)?;
    ensure!(
        routes(UNIT)? == old_producer && routes(CONTROLLER)? == old_controller,
        "191 original launch routes changed across proof"
    );
    let (projected, delta) = project(&rows)?;
    Ok(
        json!({"fleet":p.fleet,"census":p.census,"event":p.delivery_event,"stable_live_owners":stable,
        "original_producer_routes":old_producer,"original_controller_routes":old_controller,
        "terminal":terminal,"import":import,"source_members":source["outcome"]["members"],"archive_relocation_lineage":relocation,
        "retained_top_level_layout":retained_layout,"retention_scope":"original archive inodes authenticated at current public destination; all existing lane/private/output/config and import namespaces retained read-only; no historical run existence or whole-tree rehash claimed",
        "private_reference_census":private_refs,
        "delivery_policy":p.delivery_policy,"delivery_budget":budget,"rows_before":rows,"rows_after":projected,
        "original191_disposition_bytes":delta,"data_metadata_allowance_bytes":policy["data_metadata_allowance_bytes"],
        "retained_physical_bytes_credited":0,"new_resource_samples":0}),
    )
}
fn relocated_archives(source: &Value, public: &Value) -> Result<Vec<Value>> {
    let before = source["outcome"]["members"]
        .as_array()
        .context("191 original committed members")?;
    let after = public["outcome"]["members"]
        .as_array()
        .context("191 public committed members")?;
    ensure!(
        before.len() == 4 && after.len() == 4,
        "191 relocation lost a cohort member"
    );
    let mut lineage = Vec::new();
    for ((old, current), epoch) in before.iter().zip(after).zip(191..=194) {
        ensure!(
            old["epoch"] == epoch
                && current["epoch"] == epoch
                && old["archive_sha256"] == current["archive_sha256"]
                && [
                    "device",
                    "inode",
                    "length",
                    "modified_seconds",
                    "modified_nanoseconds"
                ]
                .iter()
                .all(|key| old["committed_archive"][*key].is_number()
                    && old["committed_archive"][*key] == current["committed_archive"][*key]),
            "191 import did not retain the original archive inode/content identity"
        );
        lineage.push(json!({"epoch":epoch,"source_historical_path_base64":old["archive_path_base64"],
            "current_public_path_base64":current["archive_path_base64"],"original_archive_identity":old["committed_archive"],
            "public_archive_identity":current["committed_archive"],"archive_sha256":old["archive_sha256"],
            "same_retained_archive_inode":true,"duplicate_private_copy_required":false,"physical_free_space_credit_bytes":0}));
    }
    Ok(lineage)
}
fn descriptor(p: &Plan) -> Value {
    json!({"subject":subject(),"original_reservation":p.original_reservation,"terminal":p.terminal,
        "source_batch":p.source_batch,"public_batch":p.public_batch,"delivery_policy":p.delivery_policy,
        "controller_rebind":{"path":REBIND,"sha256":REBIND_SHA}})
}
fn ledger_shape(v: &Value, desc: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-original191-growth-transfer-v2"
            && v["descriptor"] == *desc
            && v["closed_original191_replay_future_growth_bytes"] == GROWTH
            && v["new_original191_replay_future_growth_bytes"] == 0
            && v["all_source_public_scratch_inputs_retained"] == true
            && v["all_other_reservations_unchanged"] == true
            && v["physical_free_space_credit_bytes"] == 0
            && v["guard_changes_authorized"] == false
            && v["restore_authorized"] == false
            && v["retirement_authorized"] == false
            && v["publication_authorized"] == false
            && v["new_replay_authorized"] == false
            && v["new_execution_authorized"] == false
            && v["r2_mutations"] == false,
        "191 transfer ledger has foreign scope, duplicate credit or execution/removal authority"
    );
    Ok(())
}
fn recorded(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => {
            let bytes = read_stable_bounded(path, 16 << 20, "191 transfer record")?;
            Ok(Some(bound(
                &Bound {
                    path: path.into(),
                    sha256: hex_lower(&Sha256::digest(&bytes)),
                },
                false,
            )?))
        }
    }
}
fn bind_record(path: &Path) -> Result<Bound> {
    Ok(Bound {
        path: path.into(),
        sha256: hex_lower(&Sha256::digest(read_stable_bounded(
            path,
            16 << 20,
            "191 transfer binding",
        )?)),
    })
}
fn intent_shape(v: &Value, desc: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-original191-growth-transfer-intent-v2"
            && v["descriptor"] == *desc
            && v["check"].is_object()
            && v["census"].is_object()
            && v["physical_free_space_credit_bytes"] == 0
            && v["new_execution_authorized"] == false,
        "191 growth transfer intent is foreign or incomplete"
    );
    Ok(())
}
fn intent_basis(v: &Value, check: &Bound, census: &Bound) -> Result<()> {
    ensure!(
        v["check"] == json!(check) && v["census"] == json!(census),
        "191 existing intent belongs to another check/census; preserve it for explicit reconciliation"
    );
    Ok(())
}
fn projection_basis(rows: &[Row], recorded: &[Row]) -> Result<(Vec<Row>, u64)> {
    let (out, delta) = project(rows)?;
    let (expected, _) = project(recorded)?;
    let map = |rows: Vec<Row>| {
        rows.into_iter()
            .map(|row| (row.claim_key.clone(), row))
            .collect::<BTreeMap<_, _>>()
    };
    ensure!(
        map(out.clone()) == map(expected),
        "191 reader changed another recorded reservation"
    );
    Ok((out, delta))
}
fn same_frontier(a: &Value, b: &Value) -> bool {
    [
        "fleet",
        "census",
        "event",
        "stable_live_owners",
        "original_producer_routes",
        "original_controller_routes",
        "terminal",
        "import",
        "source_members",
        "archive_relocation_lineage",
        "retained_top_level_layout",
        "delivery_policy",
        "delivery_budget",
        "rows_before",
        "rows_after",
        "original191_disposition_bytes",
        "data_metadata_allowance_bytes",
    ]
    .iter()
    .all(|k| a.get(*k).is_some() && a.get(*k) == b.get(*k))
        && a["private_reference_census"]["references"] == json!([])
        && b["private_reference_census"]["references"] == json!([])
}
fn transferred(p: &Plan, spec: &Bound, check: bool) -> Result<()> {
    scope(p)?;
    let desc = descriptor(p);
    let root = Path::new(ROOT);
    let intent = root.join("intent.json");
    let receipt = root.join("transfer.json");
    if let Some(v) = recorded(&receipt)? {
        ledger_shape(&v, &desc)?;
        let b: Bound = serde_json::from_value(v["intent"].clone())?;
        ensure!(b.path == intent, "191 transfer intent namespace differs");
        intent_shape(&bound(&b, false)?, &desc)?;
        authenticate_transfer(&v, &desc)?;
        println!("{}", receipt.display());
        return Ok(());
    }
    let before = fresh(p)?;
    if check {
        ensure!(
            p.prior_check.is_none() && !p.transfer_authorized,
            "191 CHECK cannot borrow authority/check"
        );
        let path = root.join(format!("check-{}.json", spec.sha256));
        fleet::persist(
            &path,
            &json!({"schema":"jetstreamer-original191-growth-check-v2","descriptor":desc,
            "spec":spec,"census":p.census,"native":before,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "checked":true,"reservation_transferred":false,"physical_free_space_credit_bytes":0,"new_execution_authorized":false}),
        )?;
        println!("{}", path.display());
        return Ok(());
    }
    ensure!(
        p.transfer_authorized,
        "191 transfer needs separately reviewed explicit plan authority"
    );
    let prior = p
        .prior_check
        .as_ref()
        .context("191 transfer needs successful sealed CHECK binding")?;
    let old = bound(prior, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        old["schema"] == "jetstreamer-original191-growth-check-v2"
            && old["descriptor"] == desc
            && old["census"] == json!(p.census)
            && old["checked"] == true
            && old["reservation_transferred"] == false
            && old["physical_free_space_credit_bytes"] == 0
            && same_frontier(&old["native"], &before)
            && old["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
        "191 CHECK is stale/foreign or already grants transfer"
    );
    if let Some(v) = recorded(&intent)? {
        intent_shape(&v, &desc)?;
        intent_basis(&v, prior, &p.census)?;
    } else {
        fleet::persist(
            &intent,
            &json!({"schema":"jetstreamer-original191-growth-transfer-intent-v2","descriptor":desc,
            "check":prior,"census":p.census,"physical_free_space_credit_bytes":0,"new_execution_authorized":false}),
        )?;
    }
    let after = fresh(p)?;
    ensure!(
        same_frontier(&before, &after),
        "191 owner/import/claim basis changed across metadata commit"
    );
    let value = json!({"schema":"jetstreamer-original191-growth-transfer-v2","descriptor":desc,"intent":bind_record(&intent)?,
        "acceptance_spec":spec,"acceptance_check":prior,"acceptance_census":p.census,"native":after,
        "closed_original191_replay_future_growth_bytes":GROWTH,"new_original191_replay_future_growth_bytes":0,
        "all_source_public_scratch_inputs_retained":true,"all_other_reservations_unchanged":true,"physical_free_space_credit_bytes":0,
        "guard_changes_authorized":false,"restore_authorized":false,"retirement_authorized":false,"publication_authorized":false,
        "new_replay_authorized":false,"new_execution_authorized":false,"r2_mutations":false});
    ledger_shape(&value, &desc)?;
    authenticate_transfer(&value, &desc)?;
    fleet::persist(&receipt, &value)?;
    println!("{}", receipt.display());
    Ok(())
}
fn authenticate_transfer(v: &Value, desc: &Value) -> Result<()> {
    let spec: Bound = serde_json::from_value(v["acceptance_spec"].clone())?;
    let accepted: Plan = serde_json::from_value(bound(&spec, true)?)?;
    scope(&accepted)?;
    member(&accepted.program.path, &accepted.program.sha256)?;
    ensure!(
        accepted.transfer_authorized
            && descriptor(&accepted) == *desc
            && v["acceptance_census"] == json!(accepted.census),
        "191 transfer lacks its actual authorized acceptance plan"
    );
    let check = accepted
        .prior_check
        .as_ref()
        .context("191 accepted check missing")?;
    ensure!(
        v["acceptance_check"] == json!(check),
        "191 transfer accepted another check"
    );
    let checked = bound(check, false)?;
    let intent: Bound = serde_json::from_value(v["intent"].clone())?;
    let iv = bound(&intent, false)?;
    intent_shape(&iv, desc)?;
    intent_basis(&iv, check, &accepted.census)?;
    let check_spec: Bound = serde_json::from_value(checked["spec"].clone())?;
    let checked_plan: Plan = serde_json::from_value(bound(&check_spec, true)?)?;
    scope(&checked_plan)?;
    member(&checked_plan.program.path, &checked_plan.program.sha256)?;
    ensure!(
        !checked_plan.transfer_authorized
            && checked_plan.prior_check.is_none()
            && descriptor(&checked_plan) == *desc
            && checked_plan.census.path == accepted.census.path
            && checked_plan.census.sha256 == accepted.census.sha256
            && checked["schema"] == "jetstreamer-original191-growth-check-v2"
            && checked["descriptor"] == *desc
            && checked["checked"] == true
            && checked["reservation_transferred"] == false
            && checked["physical_free_space_credit_bytes"] == 0
            && same_frontier(&checked["native"], &v["native"]),
        "191 transfer lacks its genuine matching successful CHECK basis"
    );
    let census = bound(&accepted.census, true)?;
    ensure!(
        v["native"]["rows_before"] == census["reservation_rows"]
            && v["native"]["fleet"] == json!(accepted.fleet)
            && v["native"]["census"] == json!(accepted.census)
            && v["native"]["event"] == json!(accepted.delivery_event),
        "191 transfer changed its accepted census/owner basis"
    );
    let before: Vec<Row> = serde_json::from_value(v["native"]["rows_before"].clone())?;
    let (after, delta) = project(&before)?;
    ensure!(
        delta == GROWTH
            && v["native"]["rows_after"] == json!(after)
            && v["native"]["original191_disposition_bytes"] == GROWTH,
        "191 transfer projection is incomplete or counted more than once"
    );
    Ok(())
}
fn read(p: &ReadPlan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-original191-growth-read-plan-v2"
            && p.transfer.path == Path::new(ROOT).join("transfer.json")
            && p.program.path == Path::new(PROGRAM)
            && is_lower_hex(&p.program.sha256, 64),
        "foreign191 transfer read scope"
    );
    let value = bound(&p.transfer, false)?;
    let desc = &value["descriptor"];
    ensure!(
        desc["subject"] == subject()
            && desc["original_reservation"] == json!({"path":AUTHORITY,"sha256":AUTHORITY_SHA})
            && desc["terminal"] == json!({"path":TERMINAL,"sha256":TERMINAL_SHA})
            && desc["source_batch"] == json!({"path":SOURCE,"sha256":SOURCE_SHA})
            && desc["public_batch"] == json!({"path":PUBLIC,"sha256":PUBLIC_SHA}),
        "foreign191 original principal/import in transfer reader"
    );
    ensure!(
        desc["controller_rebind"] == json!({"path":REBIND,"sha256":REBIND_SHA}),
        "191 reader controller rebind authority differs"
    );
    policy_shape(&bound(
        &serde_json::from_value::<Bound>(desc["delivery_policy"].clone())?,
        true,
    )?)?;
    ledger_shape(&value, desc)?;
    let intent: Bound = serde_json::from_value(value["intent"].clone())?;
    ensure!(
        intent.path == Path::new(ROOT).join("intent.json"),
        "191 reader intent namespace differs"
    );
    intent_shape(&bound(&intent, false)?, desc)?;
    authenticate_transfer(&value, desc)?;
    let recorded: Vec<Row> = serde_json::from_value(value["native"]["rows_before"].clone())?;
    let (rows, delta) = projection_basis(&p.reservation_rows, &recorded)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"schema":"jetstreamer-original191-growth-reservation-view-v2","transfer":p.transfer,
        "subject":subject(),"projected_reservation_rows":rows,"applied_disposition_bytes":delta,"physical_free_space_credit_bytes":0,
        "reservation_disposition_is_not_additive_free_space":true,"closed_original191_replay_future_growth_bytes":GROWTH,
        "retained_materials_and_downstream_obligations_unchanged":true,"new_admission_required":true,
        "delivery_policy":desc["delivery_policy"],"delivery_budget":value["native"]["delivery_budget"],
        "guard_changes_authorized":false,"retirement_authorized":false,"new_execution_authorized":false})
        )?
    );
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && a.len() == 7
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && fs::read_link("/proc/self/exe")? == Path::new(PROGRAM),
        "original191 growth command needs exact sealed root program/plan"
    );
    member(Path::new(PROGRAM), &a[6])?;
    let spec = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let v = bound(&spec, true)?;
    let program: Bound = serde_json::from_value(v["program"].clone())?;
    ensure!(
        program.path == Path::new(PROGRAM) && program.sha256 == a[6],
        "191 transfer plan/self program binding differs"
    );
    if a[1] == "read-original191-growth" {
        return read(&serde_json::from_value(v)?);
    }
    ensure!(native_context()?, "unrecognized191 transfer native command");
    let md = fs::symlink_metadata(ROOT)?;
    ensure!(
        md.is_dir()
            && md.uid() == 0
            && md.mode() & 0o777 == 0o700
            && Path::new(ROOT).canonicalize()? == Path::new(ROOT),
        "unsafe191 transfer ledger root"
    );
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(ROOT).join("transition.lock"))?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o600
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "191 transfer lock occupied/unsafe"
    );
    transferred(
        &serde_json::from_value(v)?,
        &spec,
        a[1] == "check-original191-growth",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(key: &str, epoch: u64, iid: &str, n: u64) -> Row {
        Row {
            claim_key: key.into(),
            epoch,
            producer_invocation_id: iid.into(),
            outstanding_bytes: n,
        }
    }
    fn rows() -> Vec<Row> {
        vec![
            row(&format!("epoch191/{IID}"), 191, IID, GROWTH),
            row(
                &format!("epoch141/{ORIGINAL141}"),
                141,
                ORIGINAL141,
                549_755_813_888,
            ),
            row(&format!("epoch185/{ORIGINAL185}"), 185, ORIGINAL185, 0),
            row("epoch152/live", 152, "152-live", GROWTH),
            row("os/shared-pool", 0, "", 4 << 30),
            row("191/readonly-owner", 191, "replacement-readonly", 16 << 20),
        ]
    }
    #[test]
    fn only_original191_promise_changes_and_repeated_projection_is_zero() {
        let initial = rows();
        let (out, delta) = project(&initial).unwrap();
        assert_eq!(delta, GROWTH);
        assert_eq!(out[0].outstanding_bytes, 0);
        assert_eq!(out[1..], initial[1..]);
        let (again, delta) = project(&out).unwrap();
        assert_eq!(delta, 0);
        assert_eq!(again, out);
        let mut old185_live = initial.clone();
        old185_live[2].outstanding_bytes = GROWTH;
        assert!(project(&old185_live).is_err());
    }
    #[test]
    fn projection_rejects_aliases_partial_disposition_foreign_principal_and141_credit() {
        for n in [1, GROWTH - 1, GROWTH + 1] {
            let mut bad = rows();
            bad[0].outstanding_bytes = n;
            assert!(project(&bad).is_err());
        }
        let mut bad = rows();
        bad.remove(0);
        assert!(project(&bad).is_err());
        let mut duplicate = rows();
        duplicate.push(duplicate[0].clone());
        assert!(project(&duplicate).is_err());
        let mut alias = rows();
        alias.push(row("foreign-original191", 191, IID, GROWTH));
        assert!(project(&alias).is_err());
        let mut foreign = rows();
        foreign[0].epoch = 192;
        assert!(project(&foreign).is_err());
        let mut reduced = rows();
        reduced[1].outstanding_bytes = 513_768_747_008;
        assert!(project(&reduced).is_err());
        let mut no141 = rows();
        no141.remove(1);
        assert!(project(&no141).is_err());
    }
    #[test]
    fn reader_projection_preserves_every_recorded_non191_row() {
        let initial = rows();
        projection_basis(&initial, &initial).unwrap();
        let (closed, _) = project(&initial).unwrap();
        assert_eq!(projection_basis(&closed, &initial).unwrap().1, 0);
        for index in [1, 2, 3, 4, 5] {
            let mut bad = initial.clone();
            bad[index].outstanding_bytes += 1;
            assert!(projection_basis(&bad, &initial).is_err());
        }
        let mut missing = initial.clone();
        missing.remove(3);
        assert!(projection_basis(&missing, &initial).is_err());
        let mut reordered = initial.clone();
        reordered.reverse();
        projection_basis(&reordered, &initial).unwrap();
    }
    #[test]
    fn interrupted_intent_cannot_switch_its_check_or_census() {
        let check = Bound {
            path: "/check".into(),
            sha256: "a".repeat(64),
        };
        let census = Bound {
            path: "/census".into(),
            sha256: "b".repeat(64),
        };
        let original = json!({"check":check,"census":census});
        intent_basis(&original, &check, &census).unwrap();
        let other = Bound {
            path: "/other".into(),
            sha256: "c".repeat(64),
        };
        assert!(intent_basis(&original, &other, &census).is_err());
        assert!(intent_basis(&original, &check, &other).is_err());
    }
    #[test]
    fn dormant_on_failure_policy_needs_the_exact_successful_static_controller() {
        let mut terminal = inert(CONTROLLER);
        terminal["Restart"] = json!("on-failure");
        terminal["UnitFileState"] = json!("static");
        routes_shape(&terminal, CONTROLLER).unwrap();
        for (key, value) in [
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("ActiveState", "activating"),
            ("WantedBy", "another.service"),
            ("RequiredBy", "another.target"),
            ("UpheldBy", "keeper.service"),
            ("SuccessAction", "reboot"),
        ] {
            let mut bad = terminal.clone();
            bad[key] = json!(value);
            assert!(routes_shape(&bad, CONTROLLER).is_err());
        }
        terminal["Id"] = json!(UNIT);
        assert!(routes_shape(&terminal, UNIT).is_err());
    }
    #[test]
    fn relocated_source_archives_keep_the_original_inode_without_a_duplicate_copy() {
        let rows: Vec<_> = (191..=194).map(|epoch|json!({"epoch":epoch,"archive_path_base64":"historical-path",
            "archive_sha256":"a".repeat(64),"committed_archive":{"device":10,"inode":epoch,"length":100,
            "modified_seconds":20,"modified_nanoseconds":30,"changed_seconds":40}})).collect();
        let source = json!({"outcome":{"members":rows}});
        let mut public = source.clone();
        for row in public["outcome"]["members"].as_array_mut().unwrap() {
            row["archive_path_base64"] = json!("current-public-path");
            row["committed_archive"]["changed_seconds"] = json!(99);
        }
        let proof = relocated_archives(&source, &public).unwrap();
        assert_eq!(proof.len(), 4);
        for key in [
            "inode",
            "length",
            "device",
            "modified_seconds",
            "modified_nanoseconds",
        ] {
            let mut bad = public.clone();
            bad["outcome"]["members"][0]["committed_archive"][key] = json!(999);
            assert!(relocated_archives(&source, &bad).is_err());
        }
        let mut changed = public.clone();
        changed["outcome"]["members"][0]["archive_sha256"] = json!("b".repeat(64));
        assert!(relocated_archives(&source, &changed).is_err());
        changed = public;
        changed["outcome"]["members"].as_array_mut().unwrap().pop();
        assert!(relocated_archives(&source, &changed).is_err());
    }
    fn policy() -> Value {
        json!({"schema":"jetstreamer-original191-readonly-delivery-policy-v2","host":"dev-samjohnson",
            "epochs":[191,192,193,194],"source_and_public_materialized":true,"source_and_public_retirement_authorized":false,
            "new_replay_authorized":false,"restore_authorized":false,"guard_floor_changes_authorized":false,
            "publication_authorized":false,"physical_free_space_credit_bytes":0,"data_metadata_allowance_bytes":16<<20,
            "verifier_memory_bytes":64u64<<30,"queue_memory_bytes":2u64<<30,"serial_uploader_memory_bytes":2u64<<30,
            "shared_compiler_memory_bytes":16u64<<30,"shared_compiler_counted_once":true,"os_log_evidence_bytes":520u64<<20,
            "boundary_obligations":["190-191","191-192","192-193","193-194","194-195"],
            "os_claim_transfer":{"path":OS_TRANSFER,"sha256":OS_SHA},"other_pending_os_growth_bytes":23_505_223_680u64})
    }
    #[test]
    fn delivery_policy_keeps_memory_os_data_metadata_and_all_boundaries_separate() {
        policy_shape(&policy()).unwrap();
        for (key, value) in [
            ("verifier_memory_bytes", json!(0)),
            ("queue_memory_bytes", json!(0)),
            ("shared_compiler_counted_once", json!(false)),
            ("os_log_evidence_bytes", json!(0)),
            ("other_pending_os_growth_bytes", json!(23_505_223_679u64)),
            ("data_metadata_allowance_bytes", json!(0)),
            ("source_and_public_retirement_authorized", json!(true)),
            ("guard_floor_changes_authorized", json!(true)),
            ("new_replay_authorized", json!(true)),
            ("restore_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("physical_free_space_credit_bytes", json!(1)),
            ("boundary_obligations", json!(["191-192"])),
            (
                "os_claim_transfer",
                json!({"path":OS_TRANSFER,"sha256":"f".repeat(64)}),
            ),
        ] {
            let mut bad = policy();
            bad[key] = value;
            assert!(policy_shape(&bad).is_err(), "{key}");
        }
    }
    fn inert(unit: &str) -> Value {
        json!({"Id":unit,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0",
            "NRestarts":"0","ControlGroup":"","Job":"","Restart":"no","Triggers":"","TriggeredBy":"",
            "OnSuccess":"","OnFailure":"","UnitFileState":"disabled","Result":"success","ExecMainStatus":"0","ExecMainCode":"0",
            "RequiredBy":"","WantedBy":"","RequisiteOf":"","BoundBy":"","UpheldBy":"","PartOf":"","ConsistsOf":"",
            "StartLimitAction":"none","FailureAction":"none","SuccessAction":"none"})
    }
    #[test]
    fn original_launch_fence_never_confuses_terminal_pid_with_no_automatic_route() {
        for name in [UNIT, CONTROLLER] {
            routes_shape(&inert(name), name).unwrap();
            for (key, value) in [
                ("MainPID", "9"),
                ("NRestarts", "1"),
                ("Job", "123"),
                ("ControlGroup", "/system.slice/old"),
                ("Restart", "always"),
                ("Restart", "on-failure"),
                ("TriggeredBy", "old.timer"),
                ("OnFailure", "repair.service"),
                ("Triggers", "replacement.service"),
                ("UnitFileState", "enabled"),
            ] {
                let mut bad = inert(name);
                bad[key] = json!(value);
                assert!(routes_shape(&bad, name).is_err(), "{name}/{key}");
            }
        }
        let mut absent = inert(UNIT);
        absent["LoadState"] = json!("not-found");
        absent["Restart"] = json!("");
        routes_shape(&absent, UNIT).unwrap();
    }
    fn job(name: &str, path: &str) -> Value {
        json!({"type":"a(usssoo)","data":[[[42,name,"start","running","/org/freedesktop/systemd1/job/42",path]]]})
    }
    #[test]
    fn native_jobs_reject_new_replay_and_require_bound_downstream_ownership() {
        let names = BTreeSet::new();
        no_queued_entries(&json!({"type":"a(usssoo)","data":[[]]}), &names).unwrap();
        let queued = job(
            UNIT,
            "/org/freedesktop/systemd1/unit/jetstreamer_2droot_2dsweep_2de191_2d194_2dt5_2d20261016_2dv2_2dr2_2de191_2d194_2dlane_2da_2d1_2eservice",
        );
        assert!(no_queued_entries(&queued, &BTreeSet::from([UNIT.into()])).is_err());
        let unit = "horizon-full-verify-191-native191-20261023-v1.service";
        let actual = job(
            unit,
            "/org/freedesktop/systemd1/unit/horizon_2dfull_2dverify_2d191_2dnative191_2d20261023_2dv1_2eservice",
        );
        assert!(no_queued_entries(&actual, &names).is_err());
        no_queued_entries(&actual, &BTreeSet::from([unit.into()])).unwrap();
        let mut wrong = actual.clone();
        wrong["data"][0][0][5] = json!("/org/freedesktop/systemd1/unit/foreign");
        assert!(no_queued_entries(&wrong, &BTreeSet::from([unit.into()])).is_err());
        assert!(no_queued_entries(&json!({"type":"a(usssoo)","data":[]}), &names).is_err());
    }
    #[test]
    fn ledger_and_intent_cannot_grant_physical_credit_or_reuse185_authority() {
        let desc = json!({"subject":subject()});
        let valid = json!({"schema":"jetstreamer-original191-growth-transfer-v2","descriptor":desc,
            "closed_original191_replay_future_growth_bytes":GROWTH,"new_original191_replay_future_growth_bytes":0,
            "all_source_public_scratch_inputs_retained":true,"all_other_reservations_unchanged":true,
            "physical_free_space_credit_bytes":0,"guard_changes_authorized":false,"restore_authorized":false,
            "retirement_authorized":false,"publication_authorized":false,"new_replay_authorized":false,
            "new_execution_authorized":false,"r2_mutations":false});
        ledger_shape(&valid, &desc).unwrap();
        for (key, value) in [
            ("physical_free_space_credit_bytes", json!(1)),
            (
                "closed_original191_replay_future_growth_bytes",
                json!(GROWTH * 2),
            ),
            ("guard_changes_authorized", json!(true)),
            ("retirement_authorized", json!(true)),
            ("new_replay_authorized", json!(true)),
            ("restore_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("all_source_public_scratch_inputs_retained", json!(false)),
            ("descriptor", json!({"epoch":185})),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            assert!(ledger_shape(&bad, &desc).is_err(), "{key}");
        }
        let intent = json!({"schema":"jetstreamer-original191-growth-transfer-intent-v2","descriptor":desc,
            "check":{},"census":{},"physical_free_space_credit_bytes":0,"new_execution_authorized":false});
        intent_shape(&intent, &desc).unwrap();
        let mut incomplete = intent.clone();
        incomplete.as_object_mut().unwrap().remove("check");
        assert!(intent_shape(&incomplete, &desc).is_err());
    }
}
