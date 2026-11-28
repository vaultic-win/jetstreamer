//! Explicit new DATA route with the common independently authenticated guard reader.
use super::*;
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistrationBinding {
    path: PathBuf,
    sha256: String,
    deployment_seal: Bound,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub guard_registration: RegistrationBinding,
    pub data_fulfillment: data_witness::Binding,
}
fn shared<T>(r: data_guard_reader::R<T>) -> Result<T> {
    r.map_err(|e| anyhow::anyhow!("DATA guard reader: {e}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("DATA admission integer {k}"))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("DATA admission text {k}"))
}
pub(super) fn registered_runtime(binding: &RegistrationBinding) -> Result<Bound> {
    let registered = shared(data_guard_reader::registration(
        &serde_json::to_value(binding)?,
        now()?,
    ))?;
    Ok(serde_json::from_value(registered.runtime)?)
}
fn equation(raw: u64, fulfilled: u64, minimum: u64) -> Result<(u64, u64)> {
    ensure!(
        minimum >= FLOOR && fulfilled > 0 && fulfilled <= 241_482_399_744,
        "DATA fulfillment/raw floor bound"
    );
    let available = raw
        .checked_add(fulfilled)
        .context("DATA addition overflow")?;
    let effective = minimum
        .checked_sub(fulfilled)
        .context("DATA effective floor underflow")?;
    ensure!(
        available >= minimum,
        "fresh DATA/inode fit failed after authenticated fulfillment"
    );
    Ok((available, effective))
}
pub(super) fn fresh(
    request: &Request,
    p: &Plan,
    fleet: &Value,
    initial: u64,
    minimum: u64,
) -> Result<Value> {
    ensure!(
        p.attempt == "local2",
        "DATA route only qualified for exact local2 producer namespace"
    );
    let registration = serde_json::to_value(&request.guard_registration)?;
    let registered = shared(data_guard_reader::registration(&registration, now()?))?;
    let b = serde_json::to_value(&request.data_fulfillment)?;
    ensure!(
        b == json!({"contract":registered.registration["contract"],"deployment_seal":registered.registration["contract_deployment_seal"]}),
        "candidate DATA contract differs from registered new guard"
    );
    let owners = p
        .resident_memory
        .as_ref()
        .context("DATA admission requires complete genuine resident-owner mapping")?;
    let handoffs = resident_memory::data_handoffs(owners, fleet, p.epoch, &registration, &b)?;
    let image: Bound = serde_json::from_value(registered.runtime)?;
    let observed = data_witness::observe(
        &b,
        &data_witness::Scope {
            unit: &p.producer_unit,
            filesystem: Path::new("/home/sol"),
            worker_root: Path::new(profile(p.epoch)?.lane),
            raw_floor: FLOOR,
            root_cap: Some(ROOT_CAP),
            max_vmas: 3_500_000,
            special_profile: false,
            initial_available_bytes: initial,
            guard_image: &image.path,
            guard_sha256: &image.sha256,
        },
    )?;
    let (available, effective) = equation(
        observed.conservative_available_bytes,
        observed.fulfilled_bytes,
        minimum,
    )?;
    ensure!(
        observed.available_plus_fulfilled_bytes
            == observed
                .conservative_available_bytes
                .checked_add(observed.fulfilled_bytes)
                .context("DATA equation overflow")?
            && observed.effective_required_free_bytes == FLOOR - observed.fulfilled_bytes,
        "witness DATA base equation changed"
    );
    Ok(
        json!({"schema":"horizon-original-slot-DATA-admission-fit-v1","guard_registration":request.guard_registration,"guard_runtime":image,"complete_DATA_bytes":DATA,"raw_minimum_free_bytes":FLOOR,"minimum_initial_available_data_bytes":minimum,"raw_conservative_available_bytes":observed.conservative_available_bytes,"fulfilled_existing_DATA_bytes":observed.fulfilled_bytes,"available_plus_fulfilled_bytes":available,"effective_required_initial_available_data_bytes":effective,"fresh_witness":observed.evidence,"complete_live_owner_handoffs":handoffs,"resource_credit_bytes":0,"DATA_ending_bytes":0,"remote_mutations":false,"producer_mutations":false}),
    )
}
fn properties(unit: &str, fields: &str) -> Result<Value> {
    ensure!(
        unit_name(unit, ".service") || unit_name(unit, ".timer"),
        "DATA native unit spelling"
    );
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--no-pager", "-p", fields])
        .output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty() && output.stdout.len() <= 65536,
        "DATA native query failed"
    );
    let mut result = serde_json::Map::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("DATA native field")?;
        ensure!(
            result.insert(key.into(), json!(value)).is_none(),
            "duplicate DATA native field"
        );
    }
    Ok(Value::Object(result))
}
fn command_identity(actual: &str, path: &str, argv: &[String]) -> Result<()> {
    let inner = actual
        .strip_prefix("{ ")
        .and_then(|v| v.strip_suffix(" }"))
        .context("single DATA native command")?;
    let mut fields = BTreeMap::new();
    for member in inner.split(" ; ") {
        let (k, v) = member
            .split_once('=')
            .context("DATA native command field")?;
        ensure!(
            fields.insert(k, v).is_none(),
            "duplicate DATA native command field"
        );
    }
    let expected = BTreeSet::from([
        "path",
        "argv[]",
        "ignore_errors",
        "start_time",
        "stop_time",
        "pid",
        "code",
        "status",
    ]);
    ensure!(
        fields.keys().copied().collect::<BTreeSet<_>>() == expected
            && fields["path"] == path
            && fields["ignore_errors"] == "no"
            && fields["argv[]"]
                .split_whitespace()
                .eq(argv.iter().map(String::as_str)),
        "exact actual DATA native executable/argv required"
    );
    Ok(())
}
fn old_drained(original: &Value) -> Result<()> {
    for (key, service) in [("timer_unit", false), ("guard_unit", true)] {
        let v = properties(
            text(original, key)?,
            "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,NRestarts,ControlGroup,Job",
        )?;
        ensure!(
            v["Id"] == original[key]
                && matches!(v["LoadState"].as_str(), Some("loaded" | "not-found"))
                && v["ActiveState"] == "inactive"
                && v["SubState"] == "dead"
                && v["Job"] == "",
            "original guard is not natively drained"
        );
        ensure!(
            !service
                || (v["MainPID"] == "0"
                    && v["ControlPID"] == "0"
                    && v["NRestarts"] == "0"
                    && v["ControlGroup"] == ""),
            "original guard still owns native work"
        );
    }
    Ok(())
}
pub(super) fn peer_handoff(
    binding: &Bound,
    original: &Bound,
    epoch: u64,
    unit: &str,
    iid: &str,
    pid: u64,
    start_unix: u64,
) -> Result<data_guard_reader::Accepted> {
    let original_binding = serde_json::to_value(original)?;
    let context = data_guard_reader::Context {
        epoch,
        unit,
        iid,
        pid,
        start: start_unix,
        original_protection: &original_binding,
    };
    let accepted = shared(data_guard_reader::load_handoff(
        &serde_json::to_value(binding)?,
        &context,
        now()?,
    ))?;
    old_drained(&bound(original)?)?;
    Ok(accepted)
}

fn process_start(pid: u64) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    ensure!(
        stat.split_whitespace().next() == Some(pid.to_string().as_str()),
        "DATA current PID differs"
    );
    Ok(stat
        .rsplit_once(')')
        .context("DATA process stat comm")?
        .1
        .split_whitespace()
        .nth(19)
        .context("DATA process start")?
        .parse()?)
}
fn guard_completed(p: &Value, unit: &str, pid: u64, start_ticks: u64) -> Result<Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    let fields = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,Job,Restart,MemoryMax,MemorySwapMax,ExecStart";
    loop {
        ensure!(
            process_start(pid)? == start_ticks,
            "DATA peer PID reused during actual guard capture"
        );
        let service = properties(text(p, "guard_unit")?, fields)?;
        let producer = properties(
            unit,
            "Id,InvocationID,MainPID,ControlPID,NRestarts,ActiveState,SubState,Job",
        )?;
        ensure!(
            service["Id"] == p["guard_unit"]
                && service["LoadState"] == "loaded"
                && service["Restart"] == "no"
                && service["NRestarts"] == "0"
                && service["MemoryMax"] == "1073741824"
                && service["MemorySwapMax"] == "0"
                && producer["InvocationID"] == p["producer_invocation_id"]
                && producer["MainPID"].as_str().and_then(|v|v.parse::<u64>().ok()) == Some(pid)
                && producer["NRestarts"] == "0"
                && producer["ActiveState"] == "active"
                && producer["SubState"] == "running"
                && producer["ControlPID"] == "0"
                && producer["Job"] == "",
            "DATA peer guard profile or producer changed"
        );
        if service["ActiveState"] == "inactive" && service["SubState"] == "dead" {
            ensure!(
                service["MainPID"] == "0"
                    && service["ControlPID"] == "0"
                    && service["Job"] == ""
                    && service["Result"] == "success"
                    && service["ExecMainStatus"] == "0",
                "DATA guard has no actual successful completion"
            );
            return Ok(service);
        }
        ensure!(
            (service["ActiveState"] == "activating"
                && matches!(service["SubState"].as_str(), Some("start" | "start-pre")))
                || (service["ActiveState"] == "active" && service["SubState"] == "running"),
            "unknown DATA guard transition"
        );
        ensure!(
            std::time::Instant::now() < deadline,
            "bounded actual DATA guard completion deadline expired"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
#[expect(clippy::too_many_arguments)]
pub(super) fn current_guard(
    a: &data_guard_reader::Accepted,
    original: &Bound,
    epoch: u64,
    unit: &str,
    iid: &str,
    pid: u64,
    start_ticks: u64,
    start_unix: u64,
) -> Result<Value> {
    let original_binding = serde_json::to_value(original)?;
    let context = data_guard_reader::Context {
        epoch,
        unit,
        iid,
        pid,
        start: start_unix,
        original_protection: &original_binding,
    };
    old_drained(&bound(original)?)?;
    let p = &a.protection;
    let service = guard_completed(p, unit, pid, start_ticks)?;
    let image = text(&a.runtime, "path")?;
    let image_sha = text(&a.runtime, "sha256")?;
    fixed(image, image_sha, 64 << 20)?;
    let argv = vec![
        image.into(),
        text(&p["plan"], "path")?.into(),
        "--plan-sha256".into(),
        text(&p["plan"], "sha256")?.into(),
        "--self-sha256".into(),
        image_sha.into(),
    ];
    command_identity(text(&service, "ExecStart")?, image, &argv)?;
    let guard_iid = text(&service, "InvocationID")?;
    ensure!(lower_hex(guard_iid, 32), "DATA actual guard IID malformed");
    let directory = Path::new(text(&a.plan, "receipt_directory")?);
    let _ = super::directory(directory)?;
    ensure!(
        !directory.join("stop-intent.json").try_exists()?
            && !directory.join("stop-completion.json").try_exists()?,
        "DATA guard stop lifecycle began"
    );
    let receipt = directory.join(format!("sample-{guard_iid}.json"));
    let bytes = raw(&receipt, 32 << 20, false)?;
    let sample: Value = serde_json::from_slice(&bytes)?;
    shared(data_guard_reader::sample(
        a,
        &sample,
        &context,
        now()?,
        true,
    ))?;
    let timer = properties(
        text(p, "timer_unit")?,
        "Id,LoadState,ActiveState,SubState,InvocationID,Triggers,Job",
    )?;
    let producer = properties(
        unit,
        "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Job",
    )?;
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "--all",
            "--no-pager",
            "-ojson",
            "-u",
            text(p, "guard_unit")?,
            "_PID=1",
            &format!("INVOCATION_ID={guard_iid}"),
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty() && output.stdout.len() <= 1 << 20,
        "DATA actual PID1 journal query failed"
    );
    let journal = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let observed =
        json!({"guard_service":service,"timer":timer,"actual_producer":producer,"journal":journal});
    shared(data_guard_reader::proof(a, &observed, &sample, &context))?;
    ensure!(
        properties(
            text(p, "guard_unit")?,
            "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,Job,Restart,MemoryMax,MemorySwapMax,ExecStart"
        )? == service
            && process_start(pid)? == start_ticks,
        "DATA guard rolled or peer PID reused during actual native proof"
    );
    old_drained(&bound(original)?)?;
    Ok(
        json!({"native":observed,"receipt":{"path":receipt,"sha256":digest(&bytes)},"recorded_unix_seconds":number(&sample,"recorded_unix_seconds")?}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fulfilled_allocation_preserves_raw_floor_and_extra_overlap_growth() {
        let fulfilled = 128u64 << 30;
        let minimum = FLOOR + (64 << 20);
        let raw = minimum - fulfilled;
        assert_eq!(equation(raw, fulfilled, minimum).unwrap(), (minimum, raw));
        assert!(equation(raw - 1, fulfilled, minimum).is_err());
        assert!(equation(raw, fulfilled, FLOOR - 1).is_err());
        assert!(equation(u64::MAX, 1, FLOOR).is_err());
        assert!(equation(FLOOR, 0, FLOOR).is_err());
        assert!(equation(FLOOR, 241_482_399_745, FLOOR).is_err());
    }
    #[test]
    fn registration_binding_retains_its_separate_normal_deployment_seal() {
        let b = json!({"path":"/sealed/registration.json","sha256":"a".repeat(64),"deployment_seal":{"path":"/sealed/deployment-seal-receipt.json","sha256":"b".repeat(64)}});
        let parsed: RegistrationBinding = serde_json::from_value(b.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), b);
        let mut bad = b;
        bad["normalize_guard_sha256"] = json!(true);
        assert!(serde_json::from_value::<RegistrationBinding>(bad).is_err());
    }
    #[test]
    fn native_guard_command_cannot_substitute_old_sha_or_other_plan() {
        let args = vec![
            "/qualified/guard".into(),
            "/qualified/guard-plan.json".into(),
            "--plan-sha256".into(),
            "a".repeat(64),
            "--self-sha256".into(),
            "b".repeat(64),
        ];
        let command = format!(
            "{{ path=/qualified/guard ; argv[]={args} ; ignore_errors=no ; start_time= ; stop_time= ; pid=1 ; code=exited ; status=0 }}",
            args = args.join(" ")
        );
        command_identity(&command, "/qualified/guard", &args).unwrap();
        assert!(
            command_identity(
                &command.replace(&"b".repeat(64), GUARD_SHA),
                "/qualified/guard",
                &args
            )
            .is_err()
        );
        assert!(
            command_identity(
                &command.replace("guard-plan.json", "other.json"),
                "/qualified/guard",
                &args
            )
            .is_err()
        );
    }
}
