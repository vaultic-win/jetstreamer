//! Exact old185-attempt reservation fence. No physical retirement, guard change,
//! epoch readiness, or new replay/restore admission follows from this receipt.
use super::*;

const ROOT: &str = "/var/lib/jetstreamer/horizon-old185-attempt-growth-closure-20261024-v1";
const ADMISSION: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-full-admission-20261023-v2/admission-manifest.json";
const ADMISSION_SHA: &str = "c2074a168945f30e2a9a83464f8d07e94e835bbb504e0a84c5cdf91323a71cb9";
const ELIGIBILITY: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-epoch185-eligibility-20261024-v1/eligibility.json";
const ELIGIBILITY_SHA: &str = "1d30782e77ac3c9425f018cb563c48c65ad99ed6e563ccae026e47ebc2014505";
const ARTIFACT_SHA: &str = "e5a86339195f77f353177876f268b63bb4c48dfd3100fc4273c76efcc08d9037";
const RECONCILIATION: &str =
    "/var/lib/jetstreamer/horizon-terminal185-staged-reconciliation-20261024-v1/completion.json";
const RECONCILIATION_SHA: &str = "456bbd724fe5702e712c724b4d03f65c68cebe98eb9e19935f9a22c7e4efa1f6";
const RESERVATION: u64 = 824_633_720_832;
const OLD_FLOOR: u64 = 3_503_746_342_342;
const SURVIVOR_FLOOR: u64 = 3_332_894_621_696;
const FLEET_ROOT: &str = "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Close {
    schema: String,
    mapping: Bound,
    original_admission: Bound,
    reconciliation: Bound,
    eligibility: Bound,
    custody: Bound,
    deployment: Bound,
    census: Bound,
    closure_authorized: bool,
    prior_check: Option<Bound>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReservationRow {
    claim_key: String,
    epoch: u64,
    producer_invocation_id: String,
    outstanding_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadClosure {
    schema: String,
    mapping: Bound,
    closure: Bound,
    reservation_rows: Vec<ReservationRow>,
}
fn subject() -> Value {
    json!({"epoch":185,"controller":CONTROLLER,"controller_invocation_id":CONTROLLER_ID,
        "producer":PRODUCER,"producer_invocation_id":PRODUCER_ID,"source":SOURCE,"length":LENGTH,
        "original_admission":{"path":ADMISSION,"sha256":ADMISSION_SHA},"original_reservation_bytes":RESERVATION,
        "old_guard_floor_bytes":OLD_FLOOR,"physical_space_credit_bytes":0,"epoch_repair_open":true})
}
fn record(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(m) => {
            ensure!(
                m.is_file()
                    && m.uid() == 0
                    && m.nlink() == 1
                    && m.mode() & 0o222 == 0
                    && path.canonicalize()? == path,
                "unsafe185 growth ledger record"
            );
            Ok(Some(serde_json::from_slice(&read_stable_bounded(
                path,
                1 << 20,
                "185 growth ledger",
            )?)?))
        }
    }
}
fn snapshot_bindings(
    p: &Close,
    m: &Mapping,
    e: &Value,
    c: &Value,
    a: &Value,
    d: &Value,
    r: &Value,
) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-old185-attempt-growth-close-plan-v2"
            && m.host == HOST
            && m.prefix == "node_02/"
            && p.original_admission.path == Path::new(ADMISSION)
            && p.original_admission.sha256 == ADMISSION_SHA
            && p.eligibility.path == Path::new(ELIGIBILITY)
            && p.eligibility.sha256 == ELIGIBILITY_SHA
            && p.reconciliation.path == Path::new(RECONCILIATION)
            && p.reconciliation.sha256 == RECONCILIATION_SHA
            && p.deployment.path == Path::new(DEPLOYMENT)
            && p.deployment.sha256 == DEPLOYMENT_SHA,
        "foreign old185 reservation subject"
    );
    ensure!(
        a["schema"] == "jetstreamer-historical-performance-admission-v1"
            && a["filesystem"] == "/home/sol"
            && a["minimum_free_bytes"]
                .as_u64()
                .and_then(|n| n.checked_sub(OLD_FLOOR))
                == Some(RESERVATION),
        "old185 original incremental reservation differs"
    );
    let (_, etag, sha, length) = custody(c, m)?;
    ensure!(
        sha == ARTIFACT_SHA
            && length == LENGTH
            && c["source"] == SOURCE
            && c["mapping"] == serde_json::to_value(&p.mapping)?
            && c["eligibility"] == serde_json::to_value(&p.eligibility)?
            && e["schema"] == "jetstreamer-horizon-holding-eligibility-v2"
            && e["epoch"] == 185
            && e["source"] == SOURCE
            && e["length"] == LENGTH
            && e["sha256"] == sha
            && e["multipart_etag"] == etag
            && e["closed"] == true
            && e["interrupted_container_unvalidated"] == true
            && e["valid_prefix_established"] == false
            && e["canonical_archive"] == false
            && e["failure_repaired"] == false
            && e["job_resume_authorized"] == false
            && e["runtime_checkpoint_qualified"] == false
            && e["publication_authorized"] == false,
        "old185 closure requires exact preserved failed bytes and authenticated whole-readback custody"
    );
    ensure!(
        r["schema"] == "jetstreamer-terminal185-staged-reconciliation-v2"
            && r["host"] == HOST
            && r["all8metadata_jobs_collected"] == true
            && r["original_controller_masked"] == true
            && r["staged_after"]["references"] == json!([])
            && r["staged_after"]["terminal_fragment_exclusions"] == json!([])
            && r["growth_claims_released"] == false
            && r["replay_data_removed"] == false,
        "old185 launch-route reconciliation differs"
    );
    ensure!(
        d["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && d["destination"] == Path::new(DEPLOYMENT).parent().unwrap().to_str().unwrap(),
        "old185 input deployment differs"
    );
    Ok(())
}
fn no_replacement(f: &Value) -> Result<()> {
    let rows = f["epochs"].as_array().context("185 closure epoch census")?;
    let rows: Vec<_> = rows.iter().filter(|r| r["epoch"] == 185).collect();
    ensure!(
        rows.len() == 1
            && matches!(
                rows[0]["state"].as_str(),
                Some("failed-needs-repair" | "blocked-qualification")
            ),
        "185 repair is not open or already has a production/delivery owner"
    );
    for key in ["active", "diagnostics", "pipelines"] {
        for row in f[key]
            .as_array()
            .context("185 closure complete owner census")?
        {
            let scope = row["scope_first_epoch"]
                .as_u64()
                .zip(row["scope_last_epoch"].as_u64())
                .is_some_and(|(a, b)| a <= 185 && b >= 185);
            ensure!(
                !((row["epoch"] == 185 || scope) && (key == "active" || row["live"] == true)),
                "185 replacement, repair experiment or downstream owner exists"
            );
        }
    }
    Ok(())
}
fn census_shape(c: &Value, f: &Value, now: u64) -> Result<()> {
    let at = c["recorded_unix_seconds"]
        .as_u64()
        .context("185 closure census clock")?;
    let sampled = fleet::utc_seconds(
        f["sampled_at_utc"]
            .as_str()
            .context("185 closure fleet sample")?,
    )?;
    ensure!(
        c["schema"] == "jetstreamer-horizon-old185-attempt-growth-census-v2"
            && c["host"] == HOST
            && c["subject"] == subject()
            && c["sampled_at_utc"] == f["sampled_at_utc"]
            && c["outstanding_original185_reservation_bytes"] == RESERVATION
            && c["previously_closed_bytes"] == 0
            && c["all_other_claims_preserved"] == true
            && c["all_retained_restore_and_post_replay_obligations_preserved"] == true
            && c["physical_space_credit_bytes"] == 0
            && c["guard_floor_mutations_authorized"] == false
            && c["fresh_cold_restart_admission_required"] == true
            && c["old_attempt_resume_authorized"] == false
            && c["epoch185_repair_open"] == true
            && c["other_claim_evidence"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
            && f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && sampled >= 1792801959
            && sampled <= now
            && now - sampled <= 1800
            && at >= sampled
            && at <= now
            && now - at <= 900,
        "185 closure lacks fresh complete unchanged-other-claims census"
    );
    no_replacement(f)
}
fn guard_coverage(f: &Value, profiles: &[Value], gb: &Bound) -> Result<(u64, Vec<Value>)> {
    let mut owners = std::collections::BTreeMap::new();
    for row in f["active"].as_array().context("185 guard owner census")? {
        // Qualifications retain their own independent admission envelopes.
        if !row["producer"].is_object() || row["ordinary_replay_claim"] == false {
            continue;
        }
        let producer = &row["producer"];
        let controller = &row["controller"];
        let unit = producer["Id"]
            .as_str()
            .context("185 guard producer unit")?
            .to_owned();
        let identity = (
            producer["InvocationID"]
                .as_str()
                .context("185 guard producer IID")?
                .to_owned(),
            controller["Id"]
                .as_str()
                .context("185 guard controller unit")?
                .to_owned(),
            controller["InvocationID"]
                .as_str()
                .context("185 guard controller IID")?
                .to_owned(),
        );
        if let Some(old) = owners.insert(unit, identity.clone()) {
            ensure!(old == identity, "conflicting survivor owner census");
        }
    }
    ensure!(
        !owners.is_empty(),
        "185 closure has no surviving replay owners"
    );
    let mut covered = std::collections::BTreeSet::new();
    let mut max = 0;
    let mut values = Vec::new();
    for g in profiles {
        let floor = g["minimum_free_bytes"]
            .as_u64()
            .context("185 inherited guard floor")?;
        let unit = g["producer_unit"].as_str().context("185 guard producer")?;
        let iid = g["expected_producer_invocation_id"]
            .as_str()
            .context("185 guard producer IID")?;
        if let Some((expected, controller, controller_iid)) = owners.get(unit) {
            ensure!(
                expected == iid
                    && g["controller_unit"] == *controller
                    && g["expected_controller_invocation_id"] == *controller_iid
                    && covered.insert(unit.to_owned()),
                "185 guard owner duplicate or changed"
            );
            max = max.max(floor);
        }
        ensure!(
            g["maximum_worker_vmas"].as_u64().is_some_and(|n| n > 0),
            "185 guard VMA ceiling absent"
        );
        values.push(json!({"guard_set":gb,"minimum_free_bytes":floor,"producer_unit":unit,"producer_invocation_id":iid}));
    }
    ensure!(
        covered == owners.keys().cloned().collect() && max >= SURVIVOR_FLOOR,
        "185 closure omits a survivor guard or lowers recorded surviving floor"
    );
    Ok((max, values))
}
fn guard_profiles(c: &Value, f: &Value) -> Result<(u64, Vec<Value>)> {
    let gb: Bound = serde_json::from_value(c["survivor_guards"].clone())?;
    let guard_set = bound(&gb)?;
    ensure!(
        guard_set["schema"] == "jetstreamer-horizon-old185-survivor-guards-v2"
            && guard_set["host"] == HOST
            && guard_set["fleet"] == c["fleet"],
        "185 survivor guard set differs from current census"
    );
    let profiles = guard_set["profiles"]
        .as_array()
        .context("185 survivor guard profiles")?
        .iter()
        .map(guards::verify)
        .collect::<Result<Vec<_>>>()?;
    guard_coverage(f, &profiles, &gb)
}
fn latest_fleet(b: &Bound, f: &Value) -> Result<()> {
    let sampled = fleet::utc_seconds(f["sampled_at_utc"].as_str().context("185 fleet cutoff")?)?;
    let recorded = f["recorded_unix_seconds"]
        .as_u64()
        .context("185 fleet ledger clock")?;
    for entry in fs::read_dir(FLEET_ROOT)? {
        let path = entry?.path();
        if path == b.path || path.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let v: Value =
            serde_json::from_slice(&read_stable_bounded(&path, 16 << 20, "185 latest fleet")?)?;
        if v["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && v["first_epoch"] == 101
            && v["last_epoch"] == 200
        {
            let at = fleet::utc_seconds(
                v["sampled_at_utc"]
                    .as_str()
                    .context("185 candidate fleet clock")?,
            )?;
            ensure!(
                at < sampled
                    || (at == sampled
                        && v["recorded_unix_seconds"]
                            .as_u64()
                            .context("185 candidate event clock")?
                            < recorded),
                "newer fleet invalidates old185 closure census"
            );
        }
    }
    Ok(())
}
fn no_queued_entry_jobs(jobs: &Value) -> Result<()> {
    for job in jobs.as_array().context("185 native queued-job census")? {
        let unit = job["unit"].as_str().context("185 native queued-job unit")?;
        // Entry jobs are not capacity owners until observed. Reject queued or
        // running start jobs rather than treating absence of a PID as capacity.
        let entry = unit.starts_with("jetstreamer-root-sweep-")
            || unit.starts_with("horizon-controller-")
            || unit.starts_with("horizon-qualify-")
            || unit.starts_with("horizon-perf-")
            || unit.starts_with("jetstreamer-epoch185-")
            || (unit.starts_with("horizon-") && unit.contains("185"))
            || (unit.starts_with("jetstreamer-") && unit.contains("controller"));
        ensure!(
            !entry,
            "queued campaign entry job invalidates185 closure: {unit}"
        );
    }
    Ok(())
}
fn queued_entry_check() -> Result<()> {
    let out = std::process::Command::new("/usr/bin/busctl")
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
        out.status.success() && out.stdout.len() <= 1 << 20,
        "185 queued-job census unavailable"
    );
    no_queued_entry_jobs(&decode_native_jobs(
        &serde_json::from_slice(&out.stdout).context("185 native ListJobs JSON framing")?,
    )?)
}
fn decode_native_jobs(v: &Value) -> Result<Value> {
    ensure!(
        v["type"] == "a(usssoo)",
        "185 native ListJobs signature differs"
    );
    let returns = v["data"]
        .as_array()
        .context("185 native ListJobs method returns")?;
    ensure!(
        returns.len() == 1,
        "185 native ListJobs return count differs"
    );
    let jobs = returns[0]
        .as_array()
        .context("185 native ListJobs job array")?;
    let mut rows = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for value in jobs {
        let job = value.as_array().context("185 native ListJobs tuple")?;
        ensure!(job.len() == 6, "185 native ListJobs tuple arity differs");
        let id = job[0]
            .as_u64()
            .filter(|id| *id > 0 && *id <= u64::from(u32::MAX))
            .context("185 native ListJobs job ID")?;
        let unit = job[1]
            .as_str()
            .filter(|unit| {
                !unit.is_empty()
                    && unit.len() <= 255
                    && !unit
                        .bytes()
                        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            })
            .context("185 native ListJobs unit")?;
        let mut unit_object = String::from("/org/freedesktop/systemd1/unit/");
        for b in unit.bytes() {
            if b.is_ascii_alphanumeric() {
                unit_object.push(char::from(b));
            } else {
                unit_object.push_str(&format!("_{b:02x}"));
            }
        }
        ensure!(
            ids.insert(id)
                && job[2].as_str().is_some_and(|s| !s.is_empty())
                && matches!(job[3].as_str(), Some("waiting" | "running"))
                && job[4] == format!("/org/freedesktop/systemd1/job/{id}")
                && job[5] == unit_object,
            "185 native ListJobs identity, state or object path differs"
        );
        rows.push(json!({"unit":unit}));
    }
    Ok(Value::Array(rows))
}
fn fresh(p: &Close) -> Result<Value> {
    let c = bound(&p.census)?;
    let fb: Bound = serde_json::from_value(c["fleet"].clone())?;
    ensure!(
        fb.path.parent() == Some(Path::new(FLEET_ROOT)),
        "foreign185 closure fleet"
    );
    let f = evidence(&fb, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    census_shape(&c, &f, now)?;
    latest_fleet(&fb, &f)?;
    for value in c["other_claim_evidence"].as_array().unwrap() {
        let b: Bound = serde_json::from_value(value.clone())?;
        let _ = evidence(&b, false)?;
    }
    let owners: Vec<_> = fleet_owners(&f)?
        .into_iter()
        .map(|(unit, invocation_id)| json!({"unit":unit,"invocation_id":invocation_id}))
        .collect();
    restore_owners(&json!({"owners":owners}))?;
    let names = f["unit_census"]
        .as_object()
        .context("185 complete unit census")?
        .keys()
        .cloned()
        .collect();
    let current = fleet::census(&names, 101, 200)?;
    queued_entry_check()?;
    for (name, unit) in &current {
        if unit["ActiveState"] == "activating"
            || unit["MainPID"]
                .as_str()
                .and_then(|p| p.parse::<u32>().ok())
                .is_some_and(|p| p > 0)
        {
            let old = &f["unit_census"][name];
            ensure!(
                old["InvocationID"] == unit["InvocationID"]
                    && old["MainPID"] == unit["MainPID"]
                    && old["NRestarts"] == unit["NRestarts"]
                    && unit["NRestarts"] == "0",
                "185 closure owner census changed"
            );
        }
    }
    let (floor, guards) = guard_profiles(&c, &f)?;
    let lifecycle = staged::fenced_for_growth()?;
    let (_, source) = retained_source()?;
    let run = Path::new(SOURCE).parent().unwrap().parent().unwrap();
    let mut retained = Vec::new();
    for path in [
        run.to_path_buf(),
        run.join("scratch"),
        run.join("inputs"),
        run.join("cohort-state.json"),
    ] {
        let md = fs::symlink_metadata(&path)?;
        ensure!(
            !md.file_type().is_symlink() && path.canonicalize()? == path,
            "185 retained attempt path aliased"
        );
        retained.push(json!({"path":path,"device":md.dev(),"inode":md.ino(),"length":md.len(),"is_directory":md.is_dir()}));
    }
    Ok(
        json!({"census":p.census,"fleet":fb,"current_unit_census":current,"survivor_guards":guards,
        "minimum_inherited_guard_floor_bytes":floor,"lifecycle":lifecycle,"source_identity":source,
        "retained_top_level_paths":retained,"retention_scope":"top-level metadata, not whole-tree integrity or Bank-resume proof"}),
    )
}
fn descriptor(p: &Close) -> Value {
    json!({"subject":subject(),"mapping":p.mapping,"original_admission":p.original_admission,
        "reconciliation":p.reconciliation,"eligibility":p.eligibility,"custody":p.custody,"deployment":p.deployment})
}
fn ledger_scope(v: &Value, desc: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-old185-attempt-growth-closed-v2"
            && v["descriptor"] == *desc
            && v["closed_original_reservation_bytes"] == RESERVATION
            && v["old_attempt_fenced"] == true
            && v["epoch185_repair_open_at_closure"] == true
            && v["physical_space_credit_bytes"] == 0
            && v["minimum_inherited_guard_floor_bytes"]
                .as_u64()
                .is_some_and(|n| n >= SURVIVOR_FLOOR)
            && v["guard_floor_mutations_authorized"] == false
            && v["new_replay_or_restore_authorized"] == false
            && v["archive_or_scratch_removed"] == false
            && v["r2_mutations"] == false,
        "old185 closure ledger has foreign scope, duplicate credit or mutation authority"
    );
    Ok(())
}
fn intent_scope(v: &Value, desc: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-old185-attempt-growth-intent-v2"
            && v["descriptor"] == *desc
            && v["physical_space_credit_bytes"] == 0
            && v["new_replay_or_restore_authorized"] == false
            && v["first_check"].is_object()
            && v["first_census"].is_object(),
        "185 closure intent conflict or missing acceptance lineage"
    );
    Ok(())
}
pub(super) fn run(m: &Mapping, p: &Close, spec: &Bound, check: bool) -> Result<()> {
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "185 closure mapping changed"
    );
    let e = bound(&p.eligibility)?;
    let c = bound(&p.custody)?;
    snapshot_bindings(
        p,
        m,
        &e,
        &c,
        &bound(&p.original_admission)?,
        &bound(&p.deployment)?,
        &bound(&p.reconciliation)?,
    )?;
    let desc = descriptor(p);
    let closure = Path::new(ROOT).join("closure.json");
    let intent = Path::new(ROOT).join("intent.json");
    if let Some(old) = record(&closure)? {
        ledger_scope(&old, &desc)?;
        let ib: Bound = serde_json::from_value(old["intent"].clone())?;
        ensure!(ib.path == intent, "185 closure intent path differs");
        intent_scope(&bound(&ib)?, &desc)?;
        println!("{}", closure.display());
        return Ok(());
    }
    let first = fresh(p)?;
    if check {
        ensure!(
            p.prior_check.is_none(),
            "185 growth check cannot borrow another check"
        );
        let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let path = Path::new(STATE)
            .join("receipts")
            .join(format!("old185-growth-check-{}.json", spec.sha256));
        persist(
            &path,
            &json!({"schema":"jetstreamer-horizon-old185-attempt-growth-check-v2","descriptor":desc,
            "census":p.census,"native_evidence":first,"recorded_unix_seconds":at,"checked":true,
            "reservation_closed":false,"physical_space_credit_bytes":0,"r2_mutations":false}),
        )?;
        println!("{}", path.display());
        return Ok(());
    }
    ensure!(
        p.closure_authorized,
        "old185 closure requires reviewed explicit plan authority"
    );
    let previous = bound(
        p.prior_check
            .as_ref()
            .context("185 closure requires sealed successful check")?,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        previous["schema"] == "jetstreamer-horizon-old185-attempt-growth-check-v2"
            && previous["checked"] == true
            && previous["descriptor"] == desc
            && previous["census"] == serde_json::to_value(&p.census)?
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
        "185 closure check stale or foreign"
    );
    private(Path::new(ROOT))?;
    if let Some(old) = record(&intent)? {
        intent_scope(&old, &desc)?;
    } else {
        persist(
            &intent,
            &json!({"schema":"jetstreamer-horizon-old185-attempt-growth-intent-v2","descriptor":desc,
        "first_check":p.prior_check,"first_census":p.census,"physical_space_credit_bytes":0,"new_replay_or_restore_authorized":false}),
        )?;
    }
    let after = fresh(p)?;
    ensure!(
        first["current_unit_census"] == after["current_unit_census"]
            && first["survivor_guards"] == after["survivor_guards"]
            && first["source_identity"] == after["source_identity"],
        "185 closure live basis changed across commit"
    );
    let ib = Bound {
        path: intent.clone(),
        sha256: hex_lower(&Sha256::digest(read_stable_bounded(
            &intent,
            1 << 20,
            "185 closure intent",
        )?)),
    };
    let value = json!({"schema":"jetstreamer-horizon-old185-attempt-growth-closed-v2","descriptor":desc,"intent":ib,
        "acceptance_check":p.prior_check,"acceptance_census":p.census,"acceptance_spec":spec,"native_before":first,"native_after":after,
        "closed_original_reservation_bytes":RESERVATION,"old_attempt_fenced":true,"epoch185_repair_open_at_closure":true,
        "minimum_inherited_guard_floor_bytes":after["minimum_inherited_guard_floor_bytes"],
        "physical_space_credit_bytes":0,"guard_floor_mutations_authorized":false,"new_replay_or_restore_authorized":false,
        "archive_or_scratch_removed":false,"r2_mutations":false});
    ledger_scope(&value, &desc)?;
    persist(&closure, &value)?;
    println!("{}", closure.display());
    Ok(())
}
fn project_reservations(rows: &[ReservationRow]) -> Result<(Vec<ReservationRow>, u64)> {
    let key = format!("epoch185/{PRODUCER_ID}");
    let mut seen = std::collections::BTreeSet::new();
    let mut found = false;
    let mut delta = 0;
    let mut projected = rows.to_vec();
    for row in &mut projected {
        ensure!(
            seen.insert(row.claim_key.clone()),
            "duplicate reservation key would double-apply old185 disposition"
        );
        if row.claim_key == key {
            ensure!(
                row.epoch == 185
                    && row.producer_invocation_id == PRODUCER_ID
                    && matches!(row.outstanding_bytes, 0 | RESERVATION),
                "old185 projection has foreign owner or unexplained partial disposition"
            );
            found = true;
            delta = row.outstanding_bytes;
            row.outstanding_bytes = 0;
        } else {
            ensure!(
                row.producer_invocation_id != PRODUCER_ID,
                "original185 owner appears under a second claim key"
            );
        }
    }
    ensure!(
        found,
        "old185 projection must include its explicit original claim row"
    );
    Ok((projected, delta))
}
pub(super) fn read(m: &Mapping, p: &ReadClosure) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-old185-attempt-growth-read-plan-v2"
            && p.closure.path == Path::new(ROOT).join("closure.json"),
        "foreign185 closure reader scope"
    );
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "185 closure reader mapping changed"
    );
    let v = bound(&p.closure)?;
    let desc = &v["descriptor"];
    ensure!(
        desc["subject"] == subject()
            && desc["mapping"] == serde_json::to_value(&p.mapping)?
            && desc["original_admission"] == json!({"path":ADMISSION,"sha256":ADMISSION_SHA})
            && desc["eligibility"] == json!({"path":ELIGIBILITY,"sha256":ELIGIBILITY_SHA})
            && desc["reconciliation"] == json!({"path":RECONCILIATION,"sha256":RECONCILIATION_SHA})
            && desc["deployment"] == json!({"path":DEPLOYMENT,"sha256":DEPLOYMENT_SHA}),
        "185 closure reader subject changed"
    );
    ledger_scope(&v, desc)?;
    let ib: Bound = serde_json::from_value(v["intent"].clone())?;
    ensure!(
        ib.path == Path::new(ROOT).join("intent.json"),
        "185 reader intent path differs"
    );
    intent_scope(&bound(&ib)?, desc)?;
    let (rows, delta) = project_reservations(&p.reservation_rows)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"schema":"jetstreamer-horizon-old185-closed-reservation-view-v2",
        "closure":p.closure,"subject":subject(),"closed_original_reservation_bytes":RESERVATION,
        "applied_reservation_disposition_bytes":delta,"projected_reservation_rows":rows,
        "reservation_disposition_is_not_additive_free_space":true,
        "physical_space_credit_bytes":0,"minimum_inherited_guard_floor_bytes":v["minimum_inherited_guard_floor_bytes"],
        "new_flexible_owner_census_and_cold_admission_required":true,"old_five_owner_formula_validated":false,
        "guard_handoff_required_before_any_lower_floor":true,"new_replay_or_restore_authorized":false})
        )?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closure_requires_exact_custody_and_keeps_failed_bytes_unqualified() {
        let b = |path: &str, sha: &str| Bound {
            path: path.into(),
            sha256: sha.into(),
        };
        let p = Close {
            schema: "jetstreamer-horizon-old185-attempt-growth-close-plan-v2".into(),
            mapping: b("/sealed/mapping.json", &"a".repeat(64)),
            original_admission: b(ADMISSION, ADMISSION_SHA),
            reconciliation: b(RECONCILIATION, RECONCILIATION_SHA),
            eligibility: b(ELIGIBILITY, ELIGIBILITY_SHA),
            custody: b("/sealed/custody.json", &"b".repeat(64)),
            deployment: b(DEPLOYMENT, DEPLOYMENT_SHA),
            census: b("/sealed/census.json", &"c".repeat(64)),
            closure_authorized: false,
            prior_check: None,
        };
        let m = Mapping {
            schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
            host: HOST.into(),
            prefix: "node_02/".into(),
            user_provided_prefix: true,
            authorization_reference: "fixture".into(),
        };
        let key = object_key(&m, ARTIFACT_SHA).unwrap();
        let manifest = json!({"schema":"jetstreamer-horizon-holding-manifest-v2","host":HOST,
            "prefix":m.prefix,"object_key":key,"sha256":ARTIFACT_SHA,"length":LENGTH,"canonical_archive":false});
        let manifest_sha = hex_lower(&Sha256::digest(serde_json::to_vec(&manifest).unwrap()));
        let c = json!({"schema":"jetstreamer-horizon-holding-custody-v2","host":HOST,"bucket":BUCKET,
            "prefix":m.prefix,"mapping":p.mapping,"eligibility":p.eligibility,"source":SOURCE,
            "object_key":key,"length":LENGTH,"sha256":ARTIFACT_SHA,"object_etag":"fixture-838",
            "manifest_key":format!("node_02/manifests/{manifest_sha}.json"),"manifest_sha256":manifest_sha,"manifest":manifest,
            "remote_sha256_readback":true,"local_source_revalidated":true,"local_retirement_authorized":false,
            "canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,
            "replay_launch_authorized":false});
        let e = json!({"schema":"jetstreamer-horizon-holding-eligibility-v2","epoch":185,"source":SOURCE,"length":LENGTH,
            "sha256":ARTIFACT_SHA,"multipart_etag":"fixture-838","closed":true,"interrupted_container_unvalidated":true,
            "valid_prefix_established":false,"canonical_archive":false,"failure_repaired":false,"job_resume_authorized":false,
            "runtime_checkpoint_qualified":false,"publication_authorized":false});
        let a = json!({"schema":"jetstreamer-historical-performance-admission-v1","filesystem":"/home/sol",
            "minimum_free_bytes":OLD_FLOOR+RESERVATION});
        let d = json!({"schema":"jetstreamer-sealed-deployment-receipt-v1","destination":Path::new(DEPLOYMENT).parent().unwrap()});
        let r = json!({"schema":"jetstreamer-terminal185-staged-reconciliation-v2","host":HOST,"all8metadata_jobs_collected":true,
            "original_controller_masked":true,"staged_after":{"references":[],"terminal_fragment_exclusions":[]},
            "growth_claims_released":false,"replay_data_removed":false});
        snapshot_bindings(&p, &m, &e, &c, &a, &d, &r).unwrap();
        for key in ["remote_sha256_readback", "local_source_revalidated"] {
            let mut bad = c.clone();
            bad[key] = json!(false);
            assert!(
                snapshot_bindings(&p, &m, &e, &bad, &a, &d, &r).is_err(),
                "{key}"
            );
        }
        for (key, value) in [
            ("source", json!("/different/source")),
            ("valid_prefix_established", json!(true)),
            ("canonical_archive", json!(true)),
            ("failure_repaired", json!(true)),
            ("job_resume_authorized", json!(true)),
            ("runtime_checkpoint_qualified", json!(true)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = e.clone();
            bad[key] = value;
            assert!(
                snapshot_bindings(&p, &m, &bad, &c, &a, &d, &r).is_err(),
                "{key}"
            );
        }
    }
    fn old_row(n: u64) -> ReservationRow {
        ReservationRow {
            claim_key: format!("epoch185/{PRODUCER_ID}"),
            epoch: 185,
            producer_invocation_id: PRODUCER_ID.into(),
            outstanding_bytes: n,
        }
    }
    #[test]
    fn projection_applies_once_and_preserves_every_other_owner() {
        let mut new185 = old_row(RESERVATION);
        new185.claim_key = "epoch185/replacement".into();
        new185.producer_invocation_id = "11111111111111111111111111111111".into();
        let mut other = new185.clone();
        other.epoch = 141;
        other.claim_key = "epoch141/repair".into();
        other.outstanding_bytes = 513_768_747_008;
        let rows = vec![old_row(RESERVATION), new185, other];
        let (projected, delta) = project_reservations(&rows).unwrap();
        assert_eq!(delta, RESERVATION);
        assert_eq!(projected[0].outstanding_bytes, 0);
        assert_eq!(projected[1..], rows[1..]);
        let (twice, delta) = project_reservations(&projected).unwrap();
        assert_eq!(delta, 0);
        assert_eq!(twice, projected);
    }
    #[test]
    fn projection_rejects_ambiguous_partial_foreign_and_missing_rows() {
        assert!(project_reservations(&[]).is_err());
        assert!(project_reservations(&[old_row(1)]).is_err());
        assert!(project_reservations(&[old_row(RESERVATION), old_row(RESERVATION)]).is_err());
        let mut foreign = old_row(RESERVATION);
        foreign.epoch = 186;
        assert!(project_reservations(&[foreign]).is_err());
        let mut alias = old_row(RESERVATION);
        alias.claim_key = "foreign-alias".into();
        assert!(project_reservations(&[old_row(RESERVATION), alias]).is_err());
    }
    fn ledger(desc: &Value) -> Value {
        json!({"schema":"jetstreamer-horizon-old185-attempt-growth-closed-v2",
            "descriptor":desc,"closed_original_reservation_bytes":RESERVATION,
            "old_attempt_fenced":true,"epoch185_repair_open_at_closure":true,
            "physical_space_credit_bytes":0,"minimum_inherited_guard_floor_bytes":SURVIVOR_FLOOR,
            "guard_floor_mutations_authorized":false,"new_replay_or_restore_authorized":false,
            "archive_or_scratch_removed":false,"r2_mutations":false})
    }
    #[test]
    fn ledger_never_grants_physical_guard_or_replay_authority() {
        let desc = json!({"subject":subject()});
        let valid = ledger(&desc);
        ledger_scope(&valid, &desc).unwrap();
        for (key, value) in [
            ("physical_space_credit_bytes", json!(1)),
            ("closed_original_reservation_bytes", json!(RESERVATION * 2)),
            (
                "minimum_inherited_guard_floor_bytes",
                json!(SURVIVOR_FLOOR - 1),
            ),
            ("guard_floor_mutations_authorized", json!(true)),
            ("new_replay_or_restore_authorized", json!(true)),
            ("archive_or_scratch_removed", json!(true)),
            ("r2_mutations", json!(true)),
            ("epoch185_repair_open_at_closure", json!(false)),
            ("descriptor", json!({"foreign":true})),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            assert!(ledger_scope(&bad, &desc).is_err(), "{key}");
        }
    }
    #[test]
    fn intent_requires_exact_scope_and_explicit_no_authority() {
        let desc = json!({"subject":subject()});
        let valid = json!({"schema":"jetstreamer-horizon-old185-attempt-growth-intent-v2",
            "descriptor":desc,"first_check":{},"first_census":{},
            "physical_space_credit_bytes":0,"new_replay_or_restore_authorized":false});
        intent_scope(&valid, &desc).unwrap();
        for key in [
            "schema",
            "descriptor",
            "first_check",
            "first_census",
            "physical_space_credit_bytes",
            "new_replay_or_restore_authorized",
        ] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(intent_scope(&missing, &desc).is_err(), "{key}");
        }
    }
    #[test]
    fn repair_owner_and_downstream_cannot_disappear_from_census() {
        let valid = json!({"epochs":[{"epoch":185,"state":"failed-needs-repair"}],"active":[],"diagnostics":[],"pipelines":[]});
        no_replacement(&valid).unwrap();
        for key in ["active", "diagnostics", "pipelines"] {
            let mut bad = valid.clone();
            bad[key] = json!([{"scope_first_epoch":183,"scope_last_epoch":186,"live":true}]);
            assert!(no_replacement(&bad).is_err(), "{key}");
        }
        for state in ["ready", "replaying", "uploading"] {
            let mut bad = valid.clone();
            bad["epochs"][0]["state"] = json!(state);
            assert!(no_replacement(&bad).is_err());
        }
        let mut duplicate = valid.clone();
        duplicate["epochs"]
            .as_array_mut()
            .unwrap()
            .push(valid["epochs"][0].clone());
        assert!(no_replacement(&duplicate).is_err());
    }
    #[test]
    fn census_rejects_stale_future_foreign_and_lost_obligations() {
        let sampled = "2026-10-24T04:00:00Z";
        let at = fleet::utc_seconds(sampled).unwrap();
        let f = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,
            "sampled_at_utc":sampled,"epochs":[{"epoch":185,"state":"failed-needs-repair"}],
            "active":[],"diagnostics":[],"pipelines":[]});
        let c = json!({"schema":"jetstreamer-horizon-old185-attempt-growth-census-v2","host":HOST,
            "subject":subject(),"sampled_at_utc":sampled,"recorded_unix_seconds":at,
            "outstanding_original185_reservation_bytes":RESERVATION,"previously_closed_bytes":0,
            "all_other_claims_preserved":true,"all_retained_restore_and_post_replay_obligations_preserved":true,
            "physical_space_credit_bytes":0,"guard_floor_mutations_authorized":false,
            "fresh_cold_restart_admission_required":true,"old_attempt_resume_authorized":false,
            "epoch185_repair_open":true,"other_claim_evidence":[{}]});
        census_shape(&c, &f, at).unwrap();
        assert!(census_shape(&c, &f, at + 901).is_err());
        assert!(census_shape(&c, &f, at - 1).is_err());
        for (key, value) in [
            ("host", json!("other-node")),
            ("subject", json!({})),
            ("all_other_claims_preserved", json!(false)),
            (
                "all_retained_restore_and_post_replay_obligations_preserved",
                json!(false),
            ),
            ("other_claim_evidence", json!([])),
            ("physical_space_credit_bytes", json!(1)),
            ("previously_closed_bytes", json!(RESERVATION)),
            ("old_attempt_resume_authorized", json!(true)),
        ] {
            let mut bad = c.clone();
            bad[key] = value;
            assert!(census_shape(&bad, &f, at).is_err(), "{key}");
        }
        let mut incomplete = f.clone();
        incomplete.as_object_mut().unwrap().remove("pipelines");
        assert!(census_shape(&c, &incomplete, at).is_err());
    }
    #[test]
    fn queued_entries_are_not_mistaken_for_unclaimed_capacity() {
        no_queued_entry_jobs(&json!([])).unwrap();
        no_queued_entry_jobs(&json!([{"unit":"jetstreamer-holding-close185.service"}])).unwrap();
        for unit in [
            "jetstreamer-root-sweep-e185-185-lane-new.service",
            "jetstreamer-epoch185-full-controller.service",
            "horizon-controller-185.service",
            "horizon-qualify-185-replacement.service",
            "horizon-perf-epoch185-export@trial.service",
            "jetstreamer-epoch185-repair.service",
            "horizon-epoch185-native-export.service",
        ] {
            assert!(no_queued_entry_jobs(&json!([{"unit":unit}])).is_err());
        }
        assert!(no_queued_entry_jobs(&json!([{}])).is_err());
    }
    #[test]
    fn native_job_method_return_preserves_empty_and_running_queue_semantics() {
        let empty = json!({"type":"a(usssoo)","data":[[]]});
        assert_eq!(decode_native_jobs(&empty).unwrap(), json!([]));
        let row = json!([
            16313068,
            "horizon-old185-listjobs-format-proof.service",
            "start",
            "running",
            "/org/freedesktop/systemd1/job/16313068",
            "/org/freedesktop/systemd1/unit/horizon_2dold185_2dlistjobs_2dformat_2dproof_2eservice"
        ]);
        let valid = json!({"type":"a(usssoo)","data":[[row]]});
        let decoded = decode_native_jobs(&valid).unwrap();
        no_queued_entry_jobs(&decoded).unwrap();
        let mut entry = valid.clone();
        entry["data"][0][0][1] = json!("jetstreamer-root-sweep-e185-replacement.service");
        entry["data"][0][0][5] = json!(
            "/org/freedesktop/systemd1/unit/jetstreamer_2droot_2dsweep_2de185_2dreplacement_2eservice"
        );
        assert!(no_queued_entry_jobs(&decode_native_jobs(&entry).unwrap()).is_err());
        for bad in [
            json!({"type":"a(usssoo)","data":[]}),
            json!({"type":"a(usssoo)","data":[row]}),
            json!({"type":"wrong","data":[[]]}),
            json!({"type":"a(usssoo)","data":[[row,row]]}),
        ] {
            assert!(decode_native_jobs(&bad).is_err());
        }
        for (i, value) in [
            (0, json!(0)),
            (1, json!("")),
            (2, json!(false)),
            (3, json!("unknown")),
            (4, json!("/org/freedesktop/systemd1/job/1")),
            (5, json!("/foreign/object")),
        ] {
            let mut bad = valid.clone();
            bad["data"][0][0][i] = value;
            assert!(decode_native_jobs(&bad).is_err(), "field{i}");
        }
        assert!(
            serde_json::from_str::<Value>(
                "16313068 horizon-old185-listjobs-format-proof.service start running\n"
            )
            .is_err()
        );
    }
    #[test]
    fn guards_cover_exact_live_replay_owners_without_relabelling_private_work() {
        let owner = json!({"producer":{"Id":"producer.service","InvocationID":"producer-iid"},
            "controller":{"Id":"controller.service","InvocationID":"controller-iid"}});
        let private = json!({"producer":{"Id":"private141.service"},"ordinary_replay_claim":false});
        let f = json!({"active":[owner,private]});
        let g = json!({"producer_unit":"producer.service","expected_producer_invocation_id":"producer-iid",
            "controller_unit":"controller.service","expected_controller_invocation_id":"controller-iid",
            "minimum_free_bytes":SURVIVOR_FLOOR,"maximum_worker_vmas":800000});
        let gb = Bound {
            path: "/sealed/guards.json".into(),
            sha256: "a".repeat(64),
        };
        guard_coverage(&f, std::slice::from_ref(&g), &gb).unwrap();
        assert!(guard_coverage(&f, &[], &gb).is_err());
        assert!(guard_coverage(&f, &[g.clone(), g.clone()], &gb).is_err());
        for (key, value) in [
            ("expected_producer_invocation_id", json!("foreign")),
            ("expected_controller_invocation_id", json!("foreign")),
            ("controller_unit", json!("foreign.service")),
            ("minimum_free_bytes", json!(SURVIVOR_FLOOR - 1)),
            ("maximum_worker_vmas", json!(0)),
        ] {
            let mut bad = g.clone();
            bad[key] = value;
            assert!(guard_coverage(&f, &[bad], &gb).is_err(), "{key}");
        }
        let mut conflicting = f.clone();
        let mut changed = owner.clone();
        changed["producer"]["InvocationID"] = json!("changed");
        conflicting["active"].as_array_mut().unwrap().push(changed);
        assert!(guard_coverage(&conflicting, &[g], &gb).is_err());
    }
}
