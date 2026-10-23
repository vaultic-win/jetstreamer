//! Fresh admission and metadata-only handoffs for the exact completed203 scan.
//! Never starts/stops jobs, opens archive bytes, or mutates R2.
use super::*;
pub(super) const SCAN: &str = "horizon-full-verify-203-private-v4-af051b90-v1.service";
const SCAN_IID: &str = "96ce64ec90e24b399da3d4c1138f636d";
pub(super) const PUBLISH: &str = "horizon-publish-203-v4-20261023-v1.service";
pub(super) const UPLOAD: &str = "horizon-upload-203-v4-20261023-v1.service";
const RUNNER: &str = "5ae7edd93d29636fd959b40698bff0897e4cb3b87245054b67636d61cc8f3be9";
const PUBLISHER: &str = "/var/lib/jetstreamer/horizon-203-artifact-publisher-independent-v1/jetstreamer-epoch203-publish";
const PUBLISHER_SHA: &str = "5c100177222feabe7ece1bd971402c6558b79186bbfd9e97dbcd02e71c24c0ee";
const VERIFICATION: &str =
    "/var/lib/jetstreamer/horizon-203-private-scan-20261023-v1/verification.json";
const ANCHOR: &str =
    "/var/lib/jetstreamer/horizon-203-boundary-metadata-collected-f597924c-v1/candidate.json";
const ANCHOR_SHA: &str = "67c39d1471cca1e831c3cf3b840e7de19aac2ede2bfc83146cc6f0b0ef603ff4";
const REPLAYS: [(&str, &str); 3] = [
    (
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
        "4cd76ae1353a4411885b997f04306402",
    ),
    (
        "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        "373359a11aef4993a1a949e19ff617c3",
    ),
    (
        "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        "448da7f2a3a34217afe7e115120b3cea",
    ),
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionSpec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    floor: BoundFile,
    verification: BoundFile,
    publisher: BoundFile,
    capability: BoundFile,
    guards: Vec<BoundFile>,
    output_directory: PathBuf,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn utc(time: u64) -> Result<String> {
    let time: libc::time_t = time.try_into()?;
    let mut t = std::mem::MaybeUninit::<libc::tm>::uninit();
    ensure!(
        !unsafe { libc::gmtime_r(&time, t.as_mut_ptr()) }.is_null(),
        "203 event UTC conversion"
    );
    let t = unsafe { t.assume_init() };
    let value = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.tm_year + 1900,
        t.tm_mon + 1,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec
    );
    ensure!(is_canonical_utc(&value), "203 event UTC outside range");
    Ok(value)
}
fn self_check(sha: &str) -> Result<()> {
    let m = fs::metadata("/proc/self/exe")?;
    ensure!(
        unsafe { libc::geteuid() } == 0
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && is_lower_hex(sha, 64)
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == sha,
        "203 control helper must be sealed and self-bound"
    );
    Ok(())
}
fn parsed_args(command: &str) -> Result<(BoundFile, String)> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7 && args[3] == "--spec-sha256" && args[5] == "--self-sha256",
        "usage: {command} SPEC --spec-sha256 HEX --self-sha256 HEX"
    );
    self_check(&args[6])?;
    let m = fs::symlink_metadata(&args[2])?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && Path::new(&args[2]).canonicalize()? == Path::new(&args[2]),
        "203 control spec is unsealed"
    );
    Ok((
        BoundFile {
            path: args[2].clone().into(),
            sha256: args[4].clone(),
        },
        args[6].clone(),
    ))
}
fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700 && path.canonicalize()? == path,
        "203 control output must be canonical root-private"
    );
    Ok(())
}
fn executable(bound: &BoundFile, expected: &str, sha: &str) -> Result<()> {
    ensure!(
        bound.path == Path::new(expected) && bound.sha256 == sha,
        "203 publisher binding differs"
    );
    let m = fs::symlink_metadata(&bound.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= 256 << 20
            && bound.path.canonicalize()? == bound.path
            && hex_lower(&Sha256::digest(fs::read(&bound.path)?)) == sha,
        "203 publisher binary changed"
    );
    Ok(())
}
fn verification(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch203-verification-v1"
            && v["epoch"] == 203
            && v["runner_sha256"] == RUNNER
            && v["archive_path"]
                == "/var/lib/jetstreamer/horizon-203-private-scan-20261023-v1/epoch-203.jet"
            && v["expected_provenance_sha256"]
                == "84ec677139274d012a8d5d180e51cbe81d4f0843ca416956b8c1cfd45a9e4f03"
            && v["boundary_metadata"]["sha256"] == ANCHOR_SHA
            && v["independent_final_archive_verification_passed"] == true
            && v["current_plugin_verification_passed"] == true
            && v["full"]["exit_code"] == 0
            && v["plugin"]["exit_code"] == 0
            && v["full"]["binary"]["sha256"]
                == "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9"
            && v["plugin"]["binary"]["sha256"]
                == "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547"
            && canonical_digest(&v["archive_sha256"])
            && v["archive_identity"]["len"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 128u64 << 30),
        "203 publication resource admission requires actual complete independent verification"
    );
    for k in [
        "runtime_admission_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(v[k] == false, "203 private verification acquired authority");
    }
    Ok(())
}
fn terminal(name: &str, iid: &str) -> Result<Value> {
    let u = unit(name)?;
    ensure!(
        u["MainPID"] == "0"
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["NRestarts"] == "0"
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0"
            && (u["InvocationID"] == iid || u["InvocationID"] == ""),
        "203 prior stage is not clean terminal"
    );
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args(["--unit", name, "--output=json", "--no-pager", "--lines=256"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 4 << 20,
        "203 terminal journal unavailable"
    );
    let mut found = None;
    for line in out.stdout.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let v: Value = serde_json::from_slice(line)?;
        if v["UNIT"] == name
            && v["INVOCATION_ID"] == iid
            && v["_PID"] == "1"
            && v["_EXE"] == "/usr/lib/systemd/systemd"
            && v["MESSAGE"] == format!("{name}: Deactivated successfully.")
        {
            ensure!(found.replace(v).is_none(), "duplicated203 terminal event");
        }
    }
    Ok(
        json!({"unit":u,"manager_completion":found.context("203 exact PID1 completion missing")?,"journal_sha256":hex_lower(&Sha256::digest(&out.stdout))}),
    )
}
fn protected(f: &Value, c: &BTreeMap<String, Value>) -> Result<()> {
    let mut view = f.clone();
    let rows = view["active"]
        .as_array_mut()
        .context("203 prior active census")?;
    ensure!(
        rows.iter()
            .filter(|r| r["unit"]["Id"] == SCAN && r["epoch"] == 203)
            .count()
            == 1,
        "203 admission must follow the actual scanner owner"
    );
    rows.retain(|r| r["unit"]["Id"] != SCAN);
    ensure!(
        rows.len() == 3,
        "203 publication admission has unaccounted older work"
    );
    let mut live = c.clone();
    for (name, iid) in REPLAYS {
        let u = live.get_mut(name).context("203 protected replay missing")?;
        ensure!(
            u["InvocationID"] == iid
                && u["MainPID"]
                    .as_str()
                    .and_then(|p| p.parse::<u64>().ok())
                    .is_some_and(|p| p > 0)
                && u["ActiveState"] == "active"
                && u["SubState"] == "running"
                && u["NRestarts"] == "0",
            "203 protected replay identity changed"
        );
        let prior = &f["unit_census"][name]["ExecStart"];
        ensure!(
            pipeline_status::same_exec_start(
                prior.as_str().context("203 prior command")?,
                u["ExecStart"].as_str().context("203 current command")?
            ),
            "203 protected command changed"
        );
        u["ExecStart"] = prior.clone();
    }
    snapshot144::check_owners(&view, &live)?;
    for (name, u) in c {
        ensure!(
            !diagnostic_stage_running(u) || REPLAYS.iter().any(|(n, _)| *n == name),
            "203 unaccounted live work:{name}"
        );
    }
    Ok(())
}
fn guard(g: &Value, index: usize, sampled: u64, time: u64) -> Result<()> {
    let (name, iid) = REPLAYS[index];
    let (sha, plan) = match index {
        0 => (
            "cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560",
            "831f3eae5d4326d04ae399b4046532cda5cceb32e8e3f89b87a1de0b299a3d22",
        ),
        1 => (
            prefix204::GUARD_SHA,
            "2b639357a4754b914ad9f4af949fb7c38085a37b9cac7aa0b2c519950ee963e7",
        ),
        2 => (
            prefix204::GUARD_SHA,
            "dfa45f5f8de36fab51fff7a669ceff8e0089bde058bf60be53fcfa7f02a4cd7d",
        ),
        _ => anyhow::bail!("203 guard index"),
    };
    let stamp = g["recorded_unix_seconds"]
        .as_u64()
        .context("203 guard clock")?;
    ensure!(
        stamp >= sampled
            && stamp <= time
            && time - stamp <= 1800
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == sha
            && g["plan_sha256"] == plan
            && g["producer_invocation_id"] == iid
            && g["producer"]["invocation_id"] == iid
            && g["producer"]["cgroup"] == format!("/system.slice/{name}")
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["restarts"] == 0
            && g["workers"].as_array().is_some_and(|a| a.len() == 1)
            && g["maximum_worker_vmas"] == 3500000
            && g.get("trip_reason").is_some_and(Value::is_null)
            && g.get("worker_observation_error")
                .is_some_and(Value::is_null)
            && g["r2_mutations"] == false
            && g["remote_mutations"] == false,
        "203 guard stale,tripped or foreign"
    );
    if index > 0 {
        ensure!(
            g["producer_stop_enabled"] == true
                && g["maximum_root_physical_bytes"] == 300_000_000_000u64
                && g.get("root_physical_observation_error")
                    .is_some_and(Value::is_null),
            "203 root guard differs"
        );
    }
    let timer = match index {
        0 => "horizon-ownroot225-protective-v1.timer",
        1 => "horizon-prefix205-protective-v1.timer",
        _ => "horizon-prefix204-protective-v1.timer",
    };
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "show",
            timer,
            "--property=ActiveState",
            "--value",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout == b"active\n",
        "203 older protective timer inactive"
    );
    Ok(())
}
fn sample(s: &AdmissionSpec, o: &Value, f: &Value, time: u64) -> Result<u64> {
    let stamp = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("203 observation clock")?,
    )?;
    ensure!(
        stamp <= time
            && time - stamp <= 1800
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0,
        "203 publication admission requires a fresh accepted fleet/sample"
    );
    let rows = f["inventory"]["entries"]
        .as_array()
        .context("203 remote inventory")?;
    ensure!(
        rows.iter()
            .filter(|r| r["epoch"] == 203 && r["state"] == "missing")
            .count()
            == 1,
        "203 remote pair already present/staged or inventory incomplete"
    );
    Ok(stamp)
}
pub(super) fn admit() -> Result<()> {
    let (binding, self_sha) = parsed_args("admit-publication203")?;
    let s: AdmissionSpec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-exact203-publication-admission-spec-v1"
            && s.verification.path == Path::new(VERIFICATION)
            && s.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && s.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-publication203-admission-"))
            && s.guards.len() == 3,
        "203 publication admission scope differs"
    );
    private_directory(&s.output_directory)?;
    let output = s.output_directory.join("admission.json");
    if output.try_exists()? {
        let v = bound_json(&serde_json::from_value(private157::file_binding(&output)?)?)?;
        ensure!(
            v["schema"] == "jetstreamer-exact203-publication-admission-v1"
                && v["spec"]["sha256"] == binding.sha256
                && v["self_sha256"] == self_sha
                && v["admitted"] == true,
            "203 prior admission conflicts"
        );
        println!("Exact203 admission already exists; original freshness still applies");
        return Ok(());
    }
    let v = bound_json(&s.verification)?;
    verification(&v)?;
    let done = terminal(SCAN, SCAN_IID)?;
    executable(&s.publisher, PUBLISHER, PUBLISHER_SHA)?;
    let cap = bound_json(&s.capability)?;
    ensure!(
        s.capability.sha256 == "6480f3ed4ebc25381d53e98a33e0f9976a40a674eba1624999c8d924391b388c"
            && cap["publisher_sha256"] == PUBLISHER_SHA
            && cap["filesystem_transaction_passed"] == true
            && cap["outside_write_denied"] == true
            && cap["root_receipt_fd_survives_permanent_privilege_drop"] == true,
        "203 exact publisher capability missing"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let time = now()?;
    let sampled = sample(&s, &o, &f, time)?;
    let floor = continuation203_admission::floor(&bound_json(&s.floor)?, &f)?;
    let protected_bytes = floor
        .checked_add(640u64 << 30)
        .and_then(|n| n.checked_add(600_000_000_000))
        .context("203 protected disk overflow")?;
    let guards = s
        .guards
        .iter()
        .map(bound_json)
        .collect::<Result<Vec<_>>>()?;
    for (i, g) in guards.iter().enumerate() {
        guard(g, i, sampled, time)?;
    }
    let names = f["unit_census"]
        .as_object()
        .context("203 fleet census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 201, 300)?;
    protected(&f, &before)?;
    let path = std::ffi::CString::new("/")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "203 statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    let free = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .context("203 free overflow")?;
    let memory = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
        })
        .context("203 available memory")?
        .checked_mul(1024)
        .context("203 memory overflow")?;
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("203 total memory")?
        .checked_mul(1024)
        .context("203 memory total overflow")?;
    ensure!(
        free >= protected_bytes + (64 << 20) && memory >= total / 10 + (16u64 << 30),
        "203 local publication resource admission failed"
    );
    let after = census(&names, 201, 300)?;
    protected(&f, &after)?;
    terminal(SCAN, SCAN_IID)?;
    sample(&s, &o, &f, now()?)?;
    let plan = json!({"schema":"jetstreamer-private-epoch203-v4-publication-plan-v1","verification":private157::binding(&s.verification),
        "initial_anchor":{"path":ANCHOR,"sha256":ANCHOR_SHA},"archive_sha256":v["archive_sha256"],"archive_bytes":v["archive_identity"]["len"],
        "publication_stage":"/var/lib/jetstreamer/horizon-203-publication-work-20261023-v1/stage",
        "receipt_directory":"/var/lib/jetstreamer/horizon-203-published-artifact-20261023-v1/publication",
        "full_receipt_directory":"/var/lib/jetstreamer/horizon-203-published-artifact-20261023-v1/full/receipts",
        "plugin_receipt_directory":"/var/lib/jetstreamer/horizon-203-published-artifact-20261023-v1/plugin/receipts",
        "artifact_publication_authorized":true,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let plan_path = s.output_directory.join("publication-plan.json");
    if plan_path.try_exists()? {
        ensure!(
            bound_json(&serde_json::from_value(private157::file_binding(
                &plan_path
            )?)?)?
                == plan,
            "203 interrupted plan conflicts"
        );
    } else {
        private157::immutable_receipt(&plan_path, &plan)?;
    }
    private157::immutable_receipt(
        &output,
        &json!({"schema":"jetstreamer-exact203-publication-admission-v1","epoch":203,"admitted":true,
        "spec":private157::binding(&binding),"self_sha256":self_sha,"verification":private157::binding(&s.verification),"scanner_terminal":done,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"floor":private157::binding(&s.floor),
        "guards":s.guards,"publisher":s.publisher,"capability":s.capability,"publication_plan":private157::file_binding(&plan_path)?,
        "unit_census_before":before,"unit_census_after":after,"protected_free_bytes":protected_bytes,"available_disk_bytes":free,"available_memory_bytes":memory,
        "maximum_new_disk_bytes":64u64<<20,"maximum_memory_bytes":16u64<<30,"recorded_unix_seconds":now()?,"maximum_launch_delay_seconds":900,
        "resource_samples_taken":0,"producer_mutations":false,"replay_launch_authorized":false,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("Exact203 publication admitted; no archive or remote mutation performed");
    Ok(())
}

const PUBLICATION_PLAN: &str =
    "/var/lib/jetstreamer/horizon-publication203-plan-20261023-v1/plan.json";
const PUBLICATION_RECEIPT: &str =
    "/var/lib/jetstreamer/horizon-203-published-artifact-20261023-v1/publication/publication.json";
const EVENT_DIRECTORY: &str = "/var/lib/jetstreamer/horizon-publication203-events-v1";
const PROGRESSIVE: &str =
    "/var/lib/jetstreamer/horizon-213-r2-delivery-6a340e2-v1/jetstreamer-r2-progressive";
const UPLOADER: &str =
    "/var/lib/jetstreamer/horizon-prefix204-tools-reload-aware-v2/jetstreamer-r2";
fn upload_command() -> String {
    format!(
        "{{ path={PROGRESSIVE} ; argv[]={PROGRESSIVE} {UPLOADER} /home/ubuntu/horizon /home/ubuntu/.jetstreamer-private/r2-receipts 203 203 --poll-seconds=1800 --concurrency=16 --legacy-part-size-mib=64 --full-receipt-directory=/var/lib/jetstreamer/horizon-203-published-artifact-20261023-v1/full/receipts --full-verifier-sha256=067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9 --full-verifier-script-sha256={RUNNER} --plugin-receipt-directory=/var/lib/jetstreamer/horizon-203-published-artifact-20261023-v1/plugin/receipts --plugin-pipeline-sha256=167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547 --plugin-verifier-script-sha256={RUNNER} --boundary-receipt-directory=/var/lib/jetstreamer/horizon-203-published-artifact-20261023-v1/boundary/receipts --boundary-verifier-sha256=0ef9f58029a96a56d21e8eb8c68708722b5c45e29ef36121fd82750c860804f8 --boundary-verifier-script-sha256=b24fb16b83eddb168d2c3d05fba66f8bd5fae818bb977a92418edfc786e7af37 --defer-epochs=203-203"
    )
}
fn publication_command(plan_sha: &str) -> String {
    format!(
        "{{ path={PUBLISHER} ; argv[]={PUBLISHER} {PUBLICATION_PLAN} --plan-sha256 {plan_sha} --self-sha256 {PUBLISHER_SHA}"
    )
}
fn command_matches(actual: &Value, expected: &str) -> bool {
    actual
        .as_str()
        .and_then(|s| s.split_once(" ; ignore_errors="))
        .is_some_and(|(command, tail)| command == expected && tail.starts_with("no ; start_time="))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventSpec {
    schema: String,
    phase: String,
    observer: BoundFile,
    fleet: BoundFile,
    source: BoundFile,
    publication_plan: BoundFile,
    #[serde(default)]
    origin: Option<BoundFile>,
    output: PathBuf,
}
fn publication_receipt(v: &Value, plan: &BoundFile) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-exact-epoch203-v4-publication-receipt-v1"
            && v["epoch"] == 203
            && v["committed"] == true
            && v["archive_path"] == "/home/ubuntu/horizon/epoch-203.jet"
            && v["checksum_path"] == "/home/ubuntu/horizon/epoch-203.jet.sha256"
            && v["context"]["publisher_sha256"] == PUBLISHER_SHA
            && v["context"]["plan"]["sha256"] == plan.sha256
            && v["private_runner_sha256"] == RUNNER
            && v["original_assembly_preserved"] == true
            && v["runtime_registry_promoted"] == false
            && v["retirement_authorized"] == false
            && v["r2_mutations"] == false,
        "203 upload handoff lacks actual local publication"
    );
    Ok(())
}
fn event_scope(s: &EventSpec) -> Result<&'static str> {
    ensure!(
        s.schema == "jetstreamer-exact203-handoff-capture-spec-v1"
            && s.publication_plan.path == Path::new(PUBLICATION_PLAN)
            && is_lower_hex(&s.publication_plan.sha256, 64)
            && s.output.parent() == Some(Path::new(EVENT_DIRECTORY)),
        "203 handoff capture scope differs"
    );
    let (name, file) = match s.phase.as_str() {
        "local-publication" => (PUBLISH, "publication-launch.json"),
        "upload-readback" => (UPLOAD, "upload-launch.json"),
        _ => anyhow::bail!("unsupported203 handoff phase"),
    };
    ensure!(
        s.output.file_name().and_then(|n| n.to_str()) == Some(file),
        "203 handoff output differs"
    );
    Ok(name)
}
fn validate_phase_limits(name: &str, p: &BTreeMap<String, String>) -> Result<()> {
    let (high, max, tasks, system, home, network, rw) = if name == PUBLISH {
        ("8589934592", "17179869184", "512", "full", "no", "yes", "")
    } else {
        ensure!(name == UPLOAD, "203 unknown phase sandbox");
        (
            "4294967296",
            "8589934592",
            "1024",
            "strict",
            "read-only",
            "no",
            "/home/ubuntu/.jetstreamer-private/r2-receipts",
        )
    };
    for (key, value) in [
        ("Type", "oneshot"),
        ("User", "root"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("MemoryHigh", high),
        ("MemoryMax", max),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("TasksMax", tasks),
        ("ProtectSystem", system),
        ("ProtectHome", home),
        ("PrivateNetwork", network),
        ("NoNewPrivileges", "yes"),
        ("ReadWritePaths", rw),
        ("UMask", "0077"),
    ] {
        ensure!(
            p.get(key).map(String::as_str) == Some(value),
            "203 phase sandbox differs:{key}"
        );
    }
    Ok(())
}
fn phase_limits(name: &str) -> Result<Value> {
    let out=ProcessCommand::new("/usr/bin/systemctl").args(["show",name,"--no-pager",
        "--property=Type,User,Restart,KillMode,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,UMask"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 32768,
        "203 phase sandbox unreadable"
    );
    let mut p = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("203 phase property syntax")?;
        ensure!(
            p.insert(key.to_owned(), value.to_owned()).is_none(),
            "duplicate203 phase property"
        );
    }
    // systemctl omits empty list printers; verify the empty publication write
    // mount list through DBus when needed rather than infer absence from text.
    if name == PUBLISH && !p.contains_key("ReadWritePaths") {
        let out=ProcessCommand::new("/usr/bin/busctl").args(["--system","--json=short","--timeout=10s","get-property","org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/horizon_2dpublish_2d203_2dv4_2d20261023_2dv1_2eservice","org.freedesktop.systemd1.Service","ReadWritePaths"]).output()?;
        ensure!(
            out.status.success(),
            "203 publication write mounts unavailable"
        );
        let v: Value = serde_json::from_slice(&out.stdout)?;
        ensure!(
            v["type"] == "as" && v["data"].as_array().is_some_and(Vec::is_empty),
            "203 publisher has split write mounts"
        );
        p.insert("ReadWritePaths".into(), String::new());
    }
    validate_phase_limits(name, &p)?;
    Ok(json!(p))
}
pub(super) fn capture() -> Result<()> {
    let (binding, self_sha) = parsed_args("capture-handoff203")?;
    let s: EventSpec = serde_json::from_value(bound_json(&binding)?)?;
    let name = event_scope(&s)?;
    if s.output.try_exists()? {
        let old = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["schema"] == "jetstreamer-exact203-phase-handoff-v1"
                && old["capture_spec"]["sha256"] == binding.sha256
                && old["self_sha256"] == self_sha,
            "203 prior handoff conflicts"
        );
        println!("Exact203 handoff already captured; no duplicate action");
        return Ok(());
    }
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let p = bound_json(&s.publication_plan)?;
    ensure!(
        p["schema"] == "jetstreamer-private-epoch203-v4-publication-plan-v1"
            && p["artifact_publication_authorized"] == true,
        "203 handoff lost exact publication plan"
    );
    let source = bound_json(&s.source)?;
    let time = now()?;
    let (expected, prior) = if name == PUBLISH {
        ensure!(
            s.origin.is_none()
                && source["schema"] == "jetstreamer-exact203-publication-admission-v1"
                && source["admitted"] == true
                && source["publication_plan"]["sha256"] == s.publication_plan.sha256
                && source["fleet"] == private157::binding(&s.fleet)
                && source["observer"] == private157::binding(&s.observer)
                && source["recorded_unix_seconds"]
                    .as_u64()
                    .is_some_and(|n| n <= time && time - n <= 900),
            "203 publication launch lacks fresh admission"
        );
        (
            publication_command(&s.publication_plan.sha256),
            terminal(SCAN, SCAN_IID)?,
        )
    } else {
        ensure!(
            s.source.path == Path::new(PUBLICATION_RECEIPT),
            "203 upload receipt namespace differs"
        );
        publication_receipt(&source, &s.publication_plan)?;
        let origin = bound_json(
            s.origin
                .as_ref()
                .context("203 upload lacks actual publisher launch")?,
        )?;
        ensure!(
            origin["schema"] == "jetstreamer-exact203-phase-handoff-v1"
                && origin["phase"] == "local-publication"
                && origin["owner"]["Id"] == PUBLISH
                && origin["publication_plan"] == private157::binding(&s.publication_plan),
            "203 upload lost actual publisher lineage"
        );
        (
            upload_command(),
            terminal(
                PUBLISH,
                origin["owner"]["InvocationID"]
                    .as_str()
                    .context("203 publication invocation")?,
            )?,
        )
    };
    let u = unit(name)?;
    ensure!(
        u["LoadState"] == "loaded"
            && u["NRestarts"] == "0"
            && ((u["ActiveState"] == "active" && u["SubState"] == "running")
                || (u["ActiveState"] == "activating" && u["SubState"] == "start"))
            && u["MainPID"]
                .as_str()
                .and_then(|p| p.parse::<u64>().ok())
                .is_some_and(|p| p > 0)
            && u["InvocationID"]
                .as_str()
                .is_some_and(|n| is_lower_hex(n, 32))
            && command_matches(&u["ExecStart"], &expected),
        "203 new phase is not the exact live command/invocation"
    );
    let stamp = o["recorded_at_utc"]
        .as_str()
        .context("203 event observer clock")?;
    ensure!(
        f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["sampled_at_utc"] == stamp
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && time >= utc_seconds(stamp)?
            && time - utc_seconds(stamp)? <= 1800,
        "203 handoff resource evidence stale or foreign"
    );
    let after = unit(name)?;
    let sandbox = phase_limits(name)?;
    for k in [
        "InvocationID",
        "MainPID",
        "ActiveState",
        "SubState",
        "NRestarts",
    ] {
        ensure!(u[k] == after[k], "203 handoff owner changed");
    }
    let claim = json!({"epoch":203,"phase":s.phase,"unit":name,"invocation_id":u["InvocationID"],"expected_exec_start":u["ExecStart"],
        "evidence":[private157::binding(&s.source),private157::binding(&s.publication_plan)]});
    private157::immutable_receipt(
        &s.output,
        &json!({"schema":"jetstreamer-exact203-phase-handoff-v1","epoch":203,"phase":s.phase,
        "sampled_at_utc":utc(time)?,"observer":private157::binding(&s.observer),"previous_fleet":private157::binding(&s.fleet),
        "source":private157::binding(&s.source),"publication_plan":private157::binding(&s.publication_plan),"origin":s.origin,
        "owner":u,"sandbox":sandbox,"prior_stage_terminal":prior,"claim":claim,"capture_spec":private157::binding(&binding),"self_sha256":self_sha,
        "resource_samples_taken":0,"phase_handoff_event":true,"grants_publication_or_upload_authority":false,"producer_mutations":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("Exact203 phase handoff recorded without a resource poll or remote mutation");
    Ok(())
}

pub(super) fn event_predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    time: u64,
) -> Result<()> {
    ensure!(
        p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && previous["schema"] == SCHEMA
            && previous["first_epoch"] == 201
            && previous["last_epoch"] == 300
            && previous["sampled_at_utc"] == sampled
            && previous["observer_receipt"].as_str() == p.observer.path.to_str()
            && previous["observer_sha256"] == p.observer.sha256
            && proof["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|b| proof["previous_fleet"] == private157::binding(b))
            && proof["schema"] == "jetstreamer-exact203-phase-handoff-v1"
            && proof["epoch"] == 203
            && proof["phase_handoff_event"] == true
            && proof["resource_samples_taken"] == 0
            && proof["producer_mutations"] == false
            && proof["remote_mutations"] == false
            && proof["r2_mutations"] == false,
        "203 event must retain the exact accepted resource sample and predecessor"
    );
    let event = utc_seconds(
        proof["sampled_at_utc"]
            .as_str()
            .context("203 event clock")?,
    )?;
    ensure!(
        event > utc_seconds(sampled)?
            && event <= time
            && time - event <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < event),
        "203 event clock stale or non-advancing"
    );
    let expected: PipelineClaim = serde_json::from_value(proof["claim"].clone())?;
    ensure!(
        expected.epoch == 203
            && proof["phase"] == expected.phase
            && matches!(
                (expected.phase.as_str(), expected.unit.as_str()),
                ("local-publication", PUBLISH) | ("upload-readback", UPLOAD)
            )
            && proof["owner"]["InvocationID"] == expected.invocation_id
            && proof["owner"]["Id"] == expected.unit
            && proof["owner"]["ExecStart"] == expected.expected_exec_start,
        "203 event claim differs from actual owner"
    );
    let plan_binding: BoundFile = serde_json::from_value(proof["publication_plan"].clone())?;
    ensure!(
        plan_binding.path == Path::new(PUBLICATION_PLAN)
            && is_lower_hex(&plan_binding.sha256, 64)
            && command_matches(
                &proof["owner"]["ExecStart"],
                &if expected.unit == PUBLISH {
                    publication_command(&plan_binding.sha256)
                } else {
                    upload_command()
                }
            )
            && canonical_digest(&proof["self_sha256"])
            && canonical_digest(&proof["capture_spec"]["sha256"]),
        "203 handoff owner command or immutable capture binding differs"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"]
            .as_str()
            .context("203 predecessor plan")?
            .into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("203 predecessor plan digest")?
            .into(),
    })?)?;
    let mut tracks = old
        .tracked_units
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    tracks.insert(expected.unit.as_str());
    ensure!(
        p.tracked_units
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == tracks,
        "203 event cannot hide an additional tracked owner"
    );
    ensure!(
        p.pipeline_claims.len() == old.pipeline_claims.len() + 1
            && old
                .pipeline_claims
                .iter()
                .all(|c| p.pipeline_claims.contains(c))
            && !old.pipeline_claims.iter().any(|c| c.unit == expected.unit)
            && p.pipeline_claims.contains(&expected)
            && p.diagnostics.len() == old.diagnostics.len()
            && old
                .diagnostics
                .iter()
                .all(|d| p.diagnostics.iter().any(|n| n.epoch == d.epoch
                    && n.unit == d.unit
                    && n.invocation_id == d.invocation_id
                    && n.scratch_path == d.scratch_path
                    && n.launch_receipt == d.launch_receipt))
            && old
                .tracked_units
                .iter()
                .all(|n| p.tracked_units.contains(n)),
        "203 metadata event cannot drop history or add unrelated owners"
    );
    let event_binding = p
        .metadata_event
        .as_ref()
        .context("203 event binding missing")?;
    ensure!(
        event_binding.path.parent() == Some(Path::new(EVENT_DIRECTORY))
            && event_binding.path.file_name().and_then(|n| n.to_str())
                == Some(if expected.unit == PUBLISH {
                    "publication-launch.json"
                } else {
                    "upload-launch.json"
                })
            && expected.evidence.len() == 2
            && expected.evidence[0]
                == serde_json::from_value::<BoundFile>(proof["source"].clone())?
            && expected.evidence[1]
                == serde_json::from_value::<BoundFile>(proof["publication_plan"].clone())?,
        "203 event evidence lineage differs"
    );
    Ok(())
}

pub(super) fn event_census(p: &Plan, c: &BTreeMap<String, Value>) -> Result<()> {
    let Some(binding) = &p.metadata_event else {
        return Ok(());
    };
    let event = bound_json(binding)?;
    if event["schema"] != "jetstreamer-exact203-phase-handoff-v1" {
        return Ok(());
    }
    let prior = if event["phase"] == "local-publication" {
        SCAN
    } else {
        PUBLISH
    };
    let u = c
        .get(prior)
        .context("203 prior handoff owner absent from complete census")?;
    ensure!(
        u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0"
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead",
        "203 handoff overlaps or follows a failed prior stage"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn verified() -> Value {
        let mut v = json!({"schema":"jetstreamer-private-epoch203-verification-v1","epoch":203,"runner_sha256":RUNNER,
            "archive_path":"/var/lib/jetstreamer/horizon-203-private-scan-20261023-v1/epoch-203.jet",
            "expected_provenance_sha256":"84ec677139274d012a8d5d180e51cbe81d4f0843ca416956b8c1cfd45a9e4f03",
            "boundary_metadata":{"sha256":ANCHOR_SHA},"independent_final_archive_verification_passed":true,
            "current_plugin_verification_passed":true,"full":{"exit_code":0,"binary":{"sha256":"067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9"}},
            "plugin":{"exit_code":0,"binary":{"sha256":"167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547"}},"archive_sha256":"a".repeat(64),"archive_identity":{"len":100}});
        for k in [
            "runtime_admission_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "retirement_authorized",
            "r2_mutations",
        ] {
            v[k] = json!(false);
        }
        v
    }
    #[test]
    fn publication_needs_both_actual_scans_and_its_own_runner_and_provenance() {
        verification(&verified()).unwrap();
        for (key, value) in [
            ("/current_plugin_verification_passed", json!(false)),
            ("/plugin/exit_code", json!(1)),
            ("/full/binary/sha256", json!(RUNNER)),
            ("/runner_sha256", json!(PUBLISHER_SHA)),
            ("/epoch", json!(213)),
            ("/archive_identity/len", json!(0)),
            ("/publication_authorized", json!(true)),
        ] {
            let mut v = verified();
            *v.pointer_mut(key).unwrap() = value;
            assert!(verification(&v).is_err(), "{key}");
        }
    }
    #[test]
    fn commands_cannot_change_epoch_allowlists_or_retirement_policy() {
        let expected = upload_command();
        let good = json!(format!(
            "{expected} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
        ));
        assert!(command_matches(&good, &expected));
        for (from, to) in [
            (" 203 203 ", " 203 204 "),
            ("--defer-epochs=203-203", "--defer-epochs=204-204"),
            (RUNNER, PUBLISHER_SHA),
            ("ignore_errors=no", "ignore_errors=yes"),
        ] {
            assert!(!command_matches(
                &json!(good.as_str().unwrap().replace(from, to)),
                &expected
            ));
        }
    }
    #[test]
    fn publisher_and_delivery_caps_are_distinct_and_cannot_be_unbounded() {
        let mut p = BTreeMap::from(
            [
                ("Type", "oneshot"),
                ("User", "root"),
                ("Restart", "no"),
                ("KillMode", "control-group"),
                ("MemoryHigh", "8589934592"),
                ("MemoryMax", "17179869184"),
                ("MemorySwapMax", "0"),
                ("CPUQuotaPerSecUSec", "8s"),
                ("TasksMax", "512"),
                ("ProtectSystem", "full"),
                ("ProtectHome", "no"),
                ("PrivateNetwork", "yes"),
                ("NoNewPrivileges", "yes"),
                ("ReadWritePaths", ""),
                ("UMask", "0077"),
            ]
            .map(|(k, v)| (k.to_owned(), v.to_owned())),
        );
        validate_phase_limits(PUBLISH, &p).unwrap();
        assert!(validate_phase_limits(UPLOAD, &p).is_err());
        p.insert("MemoryMax".into(), "infinity".into());
        assert!(validate_phase_limits(PUBLISH, &p).is_err());
        p.insert("MemoryMax".into(), "17179869184".into());
        p.insert("ReadWritePaths".into(), "/home/ubuntu/horizon".into());
        assert!(validate_phase_limits(PUBLISH, &p).is_err());
    }
    #[test]
    fn event_clock_round_trips_and_capture_scope_cannot_expand() {
        let stamp = "2026-10-23T10:30:00Z";
        assert_eq!(utc(utc_seconds(stamp).unwrap()).unwrap(), stamp);
        let b = || BoundFile {
            path: "/private/evidence".into(),
            sha256: "a".repeat(64),
        };
        let mut s = EventSpec {
            schema: "jetstreamer-exact203-handoff-capture-spec-v1".into(),
            phase: "local-publication".into(),
            observer: b(),
            fleet: b(),
            source: b(),
            publication_plan: BoundFile {
                path: PUBLICATION_PLAN.into(),
                sha256: "b".repeat(64),
            },
            origin: None,
            output: Path::new(EVENT_DIRECTORY).join("publication-launch.json"),
        };
        assert_eq!(event_scope(&s).unwrap(), PUBLISH);
        s.phase = "upload-readback".into();
        assert!(event_scope(&s).is_err());
        s.output = Path::new(EVENT_DIRECTORY).join("upload-launch.json");
        assert_eq!(event_scope(&s).unwrap(), UPLOAD);
        s.publication_plan.path = "/private/epoch-213-plan.json".into();
        assert!(event_scope(&s).is_err());
    }
    #[test]
    fn metadata_event_preserves_history_and_never_fakes_a_resource_sample() {
        let temp = tempfile::tempdir().unwrap();
        let old_plan = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,
            "observer":{"path":"/observer","sha256":"a".repeat(64)},"output":"/old-output","status_receipt_directory":"/receipts",
            "gates":{},"tracked_units":[SCAN],"pipeline_claims":[{"epoch":203,"phase":"full-verification","unit":SCAN,
                "invocation_id":SCAN_IID,"expected_exec_start":"exact-scan","evidence":[{"path":"/scan","sha256":"b".repeat(64)}]}]});
        let path = temp.path().join("old-plan.json");
        fs::write(&path, serde_json::to_vec(&old_plan).unwrap()).unwrap();
        let old_binding = private157::file_binding(&path).unwrap();
        let sampled = "2026-10-23T10:16:31Z";
        let event = "2026-10-23T10:31:00Z";
        let time = utc_seconds(event).unwrap();
        let plan_binding = json!({"path":PUBLICATION_PLAN,"sha256":"c".repeat(64)});
        let source = json!({"path":"/admission","sha256":"d".repeat(64)});
        let command = format!(
            "{} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=123 ; code=(null) ; status=0/0 }}",
            publication_command(&"c".repeat(64))
        );
        let claim = json!({"epoch":203,"phase":"local-publication","unit":PUBLISH,"invocation_id":"e".repeat(32),"expected_exec_start":command,"evidence":[source,plan_binding]});
        let mut next = old_plan.clone();
        next["previous_fleet"] = json!({"path":"/previous","sha256":"f".repeat(64)});
        next["metadata_event"] = json!({"path":format!("{EVENT_DIRECTORY}/publication-launch.json"),"sha256":"1".repeat(64)});
        next["pipeline_claims"]
            .as_array_mut()
            .unwrap()
            .push(claim.clone());
        next["tracked_units"]
            .as_array_mut()
            .unwrap()
            .push(json!(PUBLISH));
        let p: Plan = serde_json::from_value(next.clone()).unwrap();
        let previous = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"sampled_at_utc":sampled,"observer_receipt":"/observer",
            "observer_sha256":"a".repeat(64),"recorded_unix_seconds":time-60,"plan":path,"plan_sha256":old_binding["sha256"]});
        let proof = json!({"schema":"jetstreamer-exact203-phase-handoff-v1","epoch":203,"phase":"local-publication","phase_handoff_event":true,
            "observer":{"path":"/observer","sha256":"a".repeat(64)},"previous_fleet":next["previous_fleet"],"sampled_at_utc":event,
            "owner":{"Id":PUBLISH,"InvocationID":"e".repeat(32),"ExecStart":command},"claim":claim,"source":source,"publication_plan":plan_binding,
            "self_sha256":"2".repeat(64),"capture_spec":{"sha256":"3".repeat(64)},"resource_samples_taken":0,"producer_mutations":false,"remote_mutations":false,"r2_mutations":false});
        event_predecessor(&previous, &p, &proof, sampled, time + 1).unwrap();
        for (key, value) in [
            ("resource_samples_taken", json!(1)),
            ("phase", json!("upload-readback")),
            ("r2_mutations", json!(true)),
            ("epoch", json!(213)),
        ] {
            let mut bad = proof.clone();
            bad[key] = value;
            assert!(
                event_predecessor(&previous, &p, &bad, sampled, time + 1).is_err(),
                "{key}"
            );
        }
        let mut dropped = next;
        dropped["pipeline_claims"].as_array_mut().unwrap().remove(0);
        assert!(
            event_predecessor(
                &previous,
                &serde_json::from_value(dropped).unwrap(),
                &proof,
                sampled,
                time + 1
            )
            .is_err()
        );
        assert!(event_predecessor(&previous, &p, &proof, sampled, time + 301).is_err());
    }
    #[test]
    fn handoff_census_requires_the_prior_stage_to_be_cleanly_terminal() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("event.json");
        fs::write(&path,serde_json::to_vec(&json!({"schema":"jetstreamer-exact203-phase-handoff-v1","phase":"local-publication"})).unwrap()).unwrap();
        let p:Plan=serde_json::from_value(json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,
            "observer":{"path":"/observer","sha256":"a".repeat(64)},"output":"/out","status_receipt_directory":"/receipts",
            "gates":{},"tracked_units":[SCAN],"metadata_event":private157::file_binding(&path).unwrap()})).unwrap();
        let u = json!({"MainPID":"0","NRestarts":"0","Result":"success","ExecMainStatus":"0","ActiveState":"inactive","SubState":"dead"});
        let mut census = BTreeMap::from([(SCAN.to_owned(), u)]);
        event_census(&p, &census).unwrap();
        census.get_mut(SCAN).unwrap()["MainPID"] = json!("123");
        assert!(event_census(&p, &census).is_err());
        census.get_mut(SCAN).unwrap()["MainPID"] = json!("0");
        census.get_mut(SCAN).unwrap()["Result"] = json!("exit-code");
        assert!(event_census(&p, &census).is_err());
    }
}
