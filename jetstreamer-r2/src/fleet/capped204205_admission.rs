//! A future real, fresh complete-fleet admission; never starts a continuation.
//! Static plans and missing capability evidence cannot produce a positive receipt.
use super::*;
mod inputs;
mod sample;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    producer_plan: BoundFile,
    resource_proposal: BoundFile,
    resource_capability: BoundFile,
    source_closure: BoundFile,
    producer: BoundFile,
    control: BoundFile,
    observer: BoundFile,
    fleet: BoundFile,
    fleet_observation_readable_mirror: PathBuf,
    protected_guards: BTreeMap<String, BoundFile>,
    output: PathBuf,
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("capped admission missing integer:{key}"))
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("capped admission missing string:{key}"))
}
fn original(epoch: u64) -> Result<(&'static str, &'static str)> {
    Ok(match epoch {
        204 => (
            "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
            "448da7f2a3a34217afe7e115120b3cea",
        ),
        205 => (
            "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
            "373359a11aef4993a1a949e19ff617c3",
        ),
        _ => bail!("only original capped 204/205 continuations may be admitted"),
    })
}
fn denied(v: &Value) -> Result<()> {
    for key in [
        "ordinary_replay_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "capped admission grants unrelated authority:{key}"
        );
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ancestor {
    path: PathBuf,
    uid: u32,
    gid: u32,
    mode: u32,
    dev: u64,
    ino: u64,
}
fn ancestry(path: &Path) -> Result<Vec<Ancestor>> {
    let mut result = Vec::new();
    let mut current = path.parent();
    while let Some(path) = current {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_dir(),
            "capped receipt ancestor is not a real directory"
        );
        result.push(Ancestor {
            path: path.into(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode() & 0o7777,
            dev: m.dev(),
            ino: m.ino(),
        });
        current = path.parent();
    }
    Ok(result)
}
fn established_observer_ancestry(path: &Path, ancestors: &[Ancestor]) -> bool {
    const ROOT: &str = "/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness";
    if path.parent() != Some(Path::new(ROOT))
        || !path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("horizon-live-resource-sample-") && s.ends_with(".json"))
    {
        return false;
    }
    let expected = [
        (ROOT, 1000, 1000, 0o775),
        (
            "/home/ubuntu/workspace/jetstreamer/.codex",
            1000,
            1000,
            0o775,
        ),
        ("/home/ubuntu/workspace/jetstreamer", 1000, 1000, 0o775),
        ("/home/ubuntu/workspace", 1000, 1000, 0o775),
        ("/home/ubuntu", 1000, 1000, 0o750),
        ("/home", 0, 0, 0o755),
        ("/", 0, 0, 0o755),
    ];
    ancestors.len() == expected.len()
        && ancestors
            .iter()
            .zip(expected)
            .all(|(a, (p, uid, gid, mode))| {
                a.path == Path::new(p) && a.uid == uid && a.gid == gid && a.mode == mode
            })
}
fn campaign_bytes_role(b: &BoundFile, owner: u32, observer: bool) -> Result<Vec<u8>> {
    ensure!(
        b.path.is_absolute() && b.path.canonicalize()? == b.path,
        "capped campaign receipt path is not canonical"
    );
    let before = fs::symlink_metadata(&b.path)?;
    ensure!(
        before.is_file()
            && before.uid() == owner
            && before.nlink() == 1
            && before.mode() & 0o022 == 0,
        "capped campaign receipt has unsafe ownership/links/group-or-other writes"
    );
    let original_ancestry = ancestry(&b.path)?;
    let private = original_ancestry
        .iter()
        .any(|a| a.uid == owner && a.mode & 0o077 == 0);
    ensure!(
        private
            || (observer
                && owner == 0
                && established_observer_ancestry(&b.path, &original_ancestry)),
        "capped campaign receipt lacks its exact trusted ancestry profile"
    );
    let bytes = read_stable_bounded(&b.path, 16 << 20, "capped accepted campaign receipt")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "capped campaign receipt digest differs"
    );
    let after = fs::symlink_metadata(&b.path)?;
    ensure!(
        identity(&before) == identity(&after)
            && before.uid() == after.uid()
            && before.mode() == after.mode()
            && after.nlink() == 1
            && b.path.canonicalize()? == b.path
            && ancestry(&b.path)? == original_ancestry,
        "capped campaign receipt changed while authenticated"
    );
    Ok(bytes)
}
fn campaign_bytes_owned(b: &BoundFile, owner: u32) -> Result<Vec<u8>> {
    campaign_bytes_role(b, owner, false)
}
fn campaign_receipt_owned(b: &BoundFile, owner: u32) -> Result<Value> {
    Ok(serde_json::from_slice(&campaign_bytes_owned(b, owner)?)?)
}
fn campaign_receipt(b: &BoundFile) -> Result<Value> {
    campaign_receipt_owned(b, 0)
}
fn observer_receipt(b: &BoundFile) -> Result<Value> {
    Ok(serde_json::from_slice(&campaign_bytes_role(b, 0, true)?)?)
}
fn output_destination(path: &Path) -> Result<&Path> {
    ensure!(
        path.is_absolute(),
        "capped admission output must be absolute"
    );
    let parent = path
        .parent()
        .context("capped admission output parent missing")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && m.mode() & 0o005 == 0o005
            && parent.canonicalize()? == parent,
        "capped admission output must have a trusted canonical root-owned parent"
    );
    traversable(parent)?;
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("capped admission output already exists"),
        Err(e) => return Err(e.into()),
    }
    Ok(parent)
}
fn publish(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= 4 << 20,
        "capped admission exceeds consumer4MiB bound"
    );
    publish_bytes(path, &bytes)
}
fn publish_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = output_destination(path)?;
    let before = fs::symlink_metadata(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file_mut().write_all(bytes)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    file.as_file().sync_all()?;
    let after = fs::symlink_metadata(parent)?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.uid() == after.uid()
            && before.mode() == after.mode()
            && parent.canonicalize()? == parent,
        "capped admission output parent changed"
    );
    file.persist_noclobber(path)
        .map_err(|e| anyhow!("capped admission no-clobber publication failed:{e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn readable(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "capped runtime input is not canonical"
    );
    let file = fs::symlink_metadata(path)?;
    ensure!(
        file.is_file()
            && file.uid() == 0
            && file.nlink() == 1
            && file.mode() & 0o222 == 0
            && file.mode() & 0o004 != 0,
        "capped runtime input is not root-immutable and UID1000 readable"
    );
    traversable(
        path.parent()
            .context("capped readable input parent missing")?,
    )
}
fn traversable(directory: &Path) -> Result<()> {
    let mut parent = Some(directory);
    while let Some(path) = parent {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_dir() && (m.mode() & 0o001 != 0 || (m.uid() == 1000 && m.mode() & 0o100 != 0)),
            "capped runtime input has unreadable UID1000 ancestry"
        );
        parent = path.parent();
    }
    Ok(())
}
fn runtime_inputs(s: &Spec, p: &Value) -> Result<()> {
    for path in [
        &s.producer_plan.path,
        &s.resource_proposal.path,
        &s.producer.path,
    ] {
        readable(path)?;
    }
    ensure!(
        fs::metadata(&s.producer.path)?.mode() & 0o001 != 0,
        "capped exact producer is not UID1000 executable"
    );
    for key in [
        "source_capture",
        "prefix_archive",
        "restart_snapshot",
        "worker",
        "genesis_archive",
    ] {
        readable(Path::new(string(&p[key], "path")?))?;
    }
    ensure!(
        fs::metadata(string(&p["worker"], "path")?)?.mode() & 0o001 != 0,
        "capped exact worker is not UID1000 executable"
    );
    for member in p["metadata"]
        .as_object()
        .context("capped original metadata inputs missing")?
        .values()
    {
        readable(Path::new(string(member, "path")?))?;
    }
    Ok(())
}
fn fresh_root(p: &Value) -> Result<()> {
    let root = Path::new(string(p, "run_root")?);
    let before = fs::symlink_metadata(root)?;
    ensure!(
        root.canonicalize()? == root
            && before.is_dir()
            && before.uid() == 1000
            && before.mode() & 0o077 == 0
            && before.mode() & 0o700 == 0o700
            && fs::read_dir(root)?.next().is_none(),
        "capped continuation root is not fresh, empty and owner-private"
    );
    let after = fs::symlink_metadata(root)?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.uid() == after.uid()
            && before.mode() == after.mode(),
        "capped fresh root changed during validation"
    );
    Ok(())
}
fn mirror(s: &Spec) -> Result<BoundFile> {
    ensure!(
        s.fleet_observation_readable_mirror
            == s.output
                .parent()
                .context("capped output parent")?
                .join("fleet-observation.json")
            && s.fleet_observation_readable_mirror != s.fleet.path,
        "capped mirror must be a separate explicit runtime input"
    );
    let bytes = campaign_bytes_owned(&s.fleet, 0)?;
    let b = BoundFile {
        path: s.fleet_observation_readable_mirror.clone(),
        sha256: s.fleet.sha256.clone(),
    };
    match fs::symlink_metadata(&b.path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => publish_bytes(&b.path, &bytes)?,
        Ok(_) => {}
        Err(e) => return Err(e.into()),
    }
    readable(&b.path)?;
    native209_admission::sealed_file(&b.path, &b.sha256, Some(bytes.len() as u64))?;
    mirror_integrity(
        &s.fleet,
        &b,
        &bytes,
        &read_stable_bounded(&b.path, 16 << 20, "capped readable fleet mirror")?,
    )?;
    Ok(b)
}
fn mirror_integrity(original: &BoundFile, copy: &BoundFile, a: &[u8], b: &[u8]) -> Result<()> {
    ensure!(
        original.path != copy.path
            && original.sha256 == copy.sha256
            && hex_lower(&Sha256::digest(a)) == original.sha256
            && a == b,
        "capped runtime mirror is not an exact-byte same-digest separate input"
    );
    Ok(())
}
fn dormant(unit: &Value, name: &str) -> Result<()> {
    ensure!(
        unit["Id"] == name
            && unit["MainPID"] == "0"
            && unit["NRestarts"] == "0"
            && unit["ControlGroup"] == ""
            && (unit["LoadState"] == "loaded" || unit["LoadState"] == "not-found")
            && (unit["ActiveState"] == "inactive" || unit["ActiveState"] == "failed")
            && (unit["SubState"] == "dead" || unit["SubState"] == "failed"),
        "capped source/candidate is not positively dormant:{name}"
    );
    Ok(())
}
fn candidate_idle(p: &Value, census: &BTreeMap<String, Value>) -> Result<()> {
    let (old, _) = original(number(p, "epoch")?)?;
    for name in [old, string(p, "producer_unit")?, string(p, "guard_unit")?] {
        dormant(
            census
                .get(name)
                .context("capped idle census omitted a required owner")?,
            name,
        )?;
    }
    original_idle(&census[old], number(p, "epoch")?)?;
    output_credit204205::maintenance_current(census)
}
pub(super) fn original_idle(unit: &Value, epoch: u64) -> Result<()> {
    let (old, iid) = original(epoch)?;
    dormant(unit, old)?;
    ensure!(
        unit["ActiveState"] == "inactive" && unit["SubState"] == "dead",
        "capped original source is not cleanly terminal/collected"
    );
    if unit["LoadState"] == "loaded" {
        ensure!(
            unit["InvocationID"] == iid
                && unit["Result"] == "success"
                && unit["ExecMainStatus"] == "0",
            "capped loaded original source lost its natural successful invocation"
        );
    } else {
        ensure!(
            unit["InvocationID"]
                .as_str()
                .is_some_and(|s| s.is_empty() || s == "0".repeat(32)),
            "capped collected source has an unexpected invocation"
        );
    }
    Ok(())
}
fn current(p: &Value, f: &Value, census: &BTreeMap<String, Value>) -> Result<()> {
    candidate_idle(p, census)?;
    native210_peer_history::current(f, census)?;
    prefix223_live_peer::current(f, census)?;
    singleton227_admission::owners(f, census)
}
fn guards(f: &Value, bounds: &BTreeMap<String, BoundFile>, sample: u64, now: u64) -> Result<Value> {
    ensure!(
        prefix223_live_peer::roster(f)? == bounds.keys().cloned().collect(),
        "capped guard set omits or adds a protected owner"
    );
    let mut evidence = BTreeMap::new();
    for (name, b) in bounds {
        let (unit, dir) = if name == prefix223_native20::UNIT {
            (
                prefix223_native20::PROTECTIVE,
                prefix223_native20::GUARD_RECEIPTS,
            )
        } else {
            prefix223_native20_admission::guard_selector(name)?
        };
        let directory = if name == singleton209::UNIT || name == canary227::UNIT {
            let parent = b.path.parent().context("capped guard directory missing")?;
            ensure!(
                parent.starts_with("/var/lib/jetstreamer"),
                "capped guard escaped evidence namespace"
            );
            parent
        } else {
            Path::new(dir)
        };
        let completed = warmup223::completed_guard_binding(unit, directory, sample, now)?;
        ensure!(
            completed["binding"] == private157::binding(b),
            "capped guard is not latest completed fire:{name}"
        );
        let timer = singleton227_capture::properties(
            &unit.replace(".service", ".timer"),
            "ActiveState,SubState",
        )?;
        ensure!(
            timer.get("ActiveState").map(String::as_str) == Some("active")
                && timer.get("SubState").map(String::as_str) == Some("waiting"),
            "capped protective timer not waiting:{name}"
        );
        evidence.insert(name.clone(), json!({"completed":completed,"timer":timer}));
    }
    Ok(json!(evidence))
}
fn memory_requirement(
    f: &Value,
    o: &Value,
    proposal: &Value,
    auxiliary: u64,
    evidence: &[Value],
) -> Result<(u64, Value)> {
    let total = number(&o["host_memory"], "total_kib")?
        .checked_mul(1024)
        .context("capped total memory overflow")?;
    let policy = canary227_peer::memory_floor(f, total)?;
    let top_up = number(&policy, "memory_floor_top_up_bytes")?;
    let mut accounted = 0u64;
    let mut accounted_seen = false;
    for e in evidence {
        if let Some(n) = e.get("memory_floor_top_up_bytes") {
            ensure!(
                e["unit"] == canary227::UNIT && !accounted_seen,
                "duplicate/unmodeled memory floor top-up"
            );
            accounted = n
                .as_u64()
                .context("capped existing memory top-up malformed")?;
            accounted_seen = true;
        }
    }
    ensure!(
        accounted <= top_up,
        "capped auxiliary memory floor inconsistent"
    );
    let candidate = number(&proposal["kernel_limits"], "requested_memory_max_bytes")?
        .checked_add(number(proposal, "guard_memory_max_bytes")?)
        .context("capped candidate memory overflow")?;
    let required = total
        .div_ceil(10)
        .checked_add(candidate)
        .and_then(|n| n.checked_add(auxiliary))
        .and_then(|n| n.checked_add(top_up - accounted))
        .context("capped protected memory arithmetic overflow")?;
    Ok((
        required,
        json!({"floor_policy":policy,"floor_top_up_already_in_auxiliary_bytes":accounted,
        "additional_floor_top_up_bytes":top_up-accounted,"candidate_cache_inclusive_hard_memory_bytes":candidate,
        "protected_remaining_hard_memory_and_floor_bytes":auxiliary,"required_available_memory_bytes":required}),
    ))
}
fn disk_requirement(p: &Value, protected: u64) -> Result<u64> {
    ensure!(
        number(p, "protected_existing_floor_bytes")? >= protected,
        "capped plan under-reserves protected disk floor"
    );
    number(p, "protected_existing_floor_bytes")?
        .checked_add(number(p, "candidate_incremental_peak_bytes")?)
        .context("capped required disk overflow")
}
fn metadata_requirement(proposal: &Value, fleet_bytes: u64) -> Result<()> {
    let required = (20u64 << 20)
        .checked_add(fleet_bytes)
        .context("capped mirror/control metadata overflow")?;
    ensure!(
        number(proposal, "external_control_metadata_bytes")? >= required,
        "capped external metadata envelope omits exact runtime mirror and bounded receipt staging"
    );
    Ok(())
}
fn actual_memory(o: &Value) -> Result<u64> {
    let total = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemTotal:")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
        })
        .context("capped actual host memory total missing")?;
    ensure!(
        total == number(&o["host_memory"], "total_kib")?,
        "capped host memory total changed since accepted sample"
    );
    native209_admission::actual_memory()
}

pub(super) fn run() -> Result<()> {
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let (spec_binding, self_sha) = publication203::parsed_args("admit-capped204205-continuation")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&spec_binding)?)?;
    ensure!(
        s.schema == "jetstreamer-capped204205-continuation-admission-spec-v1"
            && unsafe { libc::geteuid() } == 0,
        "capped admission requires root and exact spec schema"
    );
    let p = native209::immutable_json(&s.producer_plan)?;
    let proposal = native209::immutable_json(&s.resource_proposal)?;
    inputs::proposal(&s, &p, &proposal)?;
    inputs::source_closure(&s, &p)?;
    let capability = inputs::capability(&s, &p, &proposal)?;
    runtime_inputs(&s, &p)?;
    fresh_root(&p)?;
    ensure!(
        s.output.as_os_str() == string(&p, "admission_receipt")?
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output.file_name().is_some_and(|n| n == "admission.json"),
        "capped admission output differs from frozen plan"
    );
    output_destination(&s.output)?; // No successful receipt exists before every future check below passes.
    let f = campaign_receipt(&s.fleet)?;
    let o = observer_receipt(&s.observer)?;
    metadata_requirement(&proposal, fs::metadata(&s.fleet.path)?.len())?;
    native210_peer_history::validate(&f)?;
    output_credit204205::maintenance_idle(&f)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let t = sample::validate(&s, &p, &proposal, &o, &f, now)?;
    let policy_before = inputs::validate_plan(&s, &p)?;
    let mut names = f["unit_census"]
        .as_object()
        .context("capped raw owner census missing")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let (old, _) = original(number(&p, "epoch")?)?;
    for name in [old, string(&p, "producer_unit")?, string(&p, "guard_unit")?] {
        names.insert(name.into());
    }
    let before = census(&names, 201, 300)?;
    current(&p, &f, &before)?;
    let caps = prefix223_live_peer::limits(&f)?;
    let free_before = singleton227_admission::disk_free()?;
    let memory_before = actual_memory(&o)?;
    let guard_before = guards(&f, &s.protected_guards, t, now)?;
    let (growth, growth_evidence) = prefix223_live_peer::disk(&f, &o, &s.protected_guards, t, now)?;
    let century = singleton227_admission::century_floor_for(&f, number(&p, "epoch")?)?;
    let (protected, existing_guard_floor) =
        native228_admission::protected_floor(century, growth, &s.protected_guards)?;
    let required = disk_requirement(&p, protected)?;
    let (auxiliary, memory_evidence) = prefix223_live_peer::memory(&f)?;
    let (required_memory, memory_policy) =
        memory_requirement(&f, &o, &proposal, auxiliary, &memory_evidence)?;
    let sampled_free = number(&o["filesystem"], "conservative_available_bytes")?;
    let sampled_memory = number(&o["host_memory"], "conservative_available_kib")?
        .checked_mul(1024)
        .context("capped sampled memory overflow")?;
    ensure!(
        free_before.min(sampled_free) >= required
            && memory_before.min(sampled_memory) >= required_memory,
        "capped complete restore/suffix/assembly envelope does not fit"
    );
    ensure!(
        fs::read_to_string("/proc/sys/vm/max_map_count")?
            .trim()
            .parse::<u64>()?
            >= 4194304,
        "capped actual VMA ceiling unavailable"
    );
    let policy_after = inputs::validate_plan(&s, &p)?;
    inputs::stable_policies(&policy_before, &policy_after)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample::validate(&s, &p, &proposal, &o, &f, now)?;
    let after = census(&names, 201, 300)?;
    current(&p, &f, &after)?;
    let after_guard = guards(&f, &s.protected_guards, t, now)?;
    let (after_growth, after_growth_evidence) =
        prefix223_live_peer::disk(&f, &o, &s.protected_guards, t, now)?;
    let (after_auxiliary, after_memory_evidence) = prefix223_live_peer::memory(&f)?;
    let (after_required_memory, after_memory_policy) =
        memory_requirement(&f, &o, &proposal, after_auxiliary, &after_memory_evidence)?;
    let free = free_before.min(singleton227_admission::disk_free()?);
    let memory = memory_before.min(actual_memory(&o)?);
    ensure!(
        before == after
            && caps == prefix223_live_peer::limits(&f)?
            && after_growth <= growth
            && after_auxiliary <= auxiliary
            && after_required_memory <= required_memory
            && free >= required
            && memory >= required_memory,
        "capped mutable owner/resource envelope changed during admission"
    );
    let recorded = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let recorded = u64::try_from(recorded).context("capped admission clock overflow")?;
    ensure!(
        u128::from(recorded)
            .checked_sub(started)
            .is_some_and(|age| age <= 900_000),
        "capped admission transaction exceeded its fresh evidence window"
    );
    sample::validate(&s, &p, &proposal, &o, &f, recorded / 1000)?;
    let readable_mirror = mirror(&s)?;
    let free = free.min(singleton227_admission::disk_free()?);
    let memory = memory.min(actual_memory(&o)?);
    ensure!(
        free >= required && memory >= required_memory,
        "capped resources no longer fit after exact runtime mirror staging"
    );
    let mut receipt = json!({"schema":"jetstreamer-capped204205-continuation-admission-v1","admitted":true,
        "epoch":p["epoch"],"plan_sha256":s.producer_plan.sha256,"producer_plan":private157::binding(&s.producer_plan),
        "node_sha256":p["node_sha256"],"source_capture_sha256":p["source_capture"]["sha256"],
        "prefix_sha256":p["prefix_archive"]["sha256"],"snapshot_sha256":p["restart_snapshot"]["sha256"],"worker_sha256":p["worker"]["sha256"],
        "producer_unit":p["producer_unit"],"guard_unit":p["guard_unit"],"guard_sha256":p["guard_sha256"],
        "protected_existing_floor_bytes":p["protected_existing_floor_bytes"],"candidate_incremental_peak_bytes":p["candidate_incremental_peak_bytes"],
        "maximum_root_physical_bytes":p["maximum_root_physical_bytes"],"maximum_process_rss_bytes":p["maximum_process_rss_bytes"],"maximum_worker_vmas":p["maximum_worker_vmas"],
        "resource_proposal":private157::binding(&s.resource_proposal),"kernel_limits":proposal["kernel_limits"],"resource_capability":private157::binding(&s.resource_capability)});
    let details = json!({
        "source_closure":private157::binding(&s.source_closure),"capability_evidence":capability,
        "policy_before":policy_before,"policy_after":policy_after,"source_idle_censuses_taken":2,"resource_samples_taken":0,
        "available_bytes":free,"available_memory_bytes":memory,"recorded_unix_millis":recorded,
        "complete_fleet_and_effective_guards_protected":true,"restore_suffix_validation_and_assembly_overlap_included":true,
        "fleet_observation":private157::binding(&s.fleet),"fleet_observation_readable_mirror":private157::binding(&readable_mirror),
        "readable_mirror_is_same_host_runtime_input_not_new_accepted_fleet":true,
        "observer":private157::binding(&s.observer),"protected_guards":s.protected_guards,
        "century_floor_bytes":century,"protected_remaining_growth_bytes":growth,"computed_protected_floor_bytes":protected,"maximum_existing_guard_floor_bytes":existing_guard_floor});
    let audit = json!({
        "guard_evidence_before":guard_before,"guard_evidence_after":after_guard,"growth_before":growth_evidence,"growth_after":after_growth_evidence,
        "memory_before":memory_evidence,"memory_after":after_memory_evidence,"memory_policy_before":memory_policy,"memory_policy_after":after_memory_policy,
        "unit_census_before":before,"unit_census_after":after,"protected_memory_limits":caps,"spec_sha256":spec_binding.sha256,"self_sha256":self_sha,
        "raw_fleet_and_failure_history_preserved":true,"original_native_tuple_and_cursor_rules_preserved":true,
        "ordinary_replay_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,
        "retirement_authorized":false,"remote_mutations":false,"r2_mutations":false,"producer_started":false,"native_initialized":false});
    if let Value::Object(details) = details {
        receipt
            .as_object_mut()
            .context("capped receipt object missing")?
            .extend(details);
    }
    if let Value::Object(audit) = audit {
        receipt
            .as_object_mut()
            .context("capped receipt object missing")?
            .extend(audit);
    }
    denied(&receipt)?;
    // Rehash sealed inputs again. Never silently retain a stale successful receipt on retry.
    ensure!(
        native209::immutable_json(&s.producer_plan)? == p
            && native209::immutable_json(&s.resource_proposal)? == proposal,
        "capped immutable plan/proposal changed before publication"
    );
    native209::immutable_json(&s.source_closure)?;
    native209::immutable_json(&s.resource_capability)?;
    campaign_receipt(&s.fleet)?;
    observer_receipt(&s.observer)?;
    runtime_inputs(&s, &p)?;
    fresh_root(&p)?;
    readable(&readable_mirror.path)?;
    publish(&s.output, &receipt)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn actual_campaign_receipt_modes_are_hash_bound_without_chmod_or_copied_lineage() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = unsafe { libc::geteuid() };
        for mode in [0o600, 0o644] {
            let path = root.path().join(format!("receipt-{mode}.json"));
            let bytes = b"{\"accepted\":true}";
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let b = BoundFile {
                path: path.clone(),
                sha256: hex_lower(&Sha256::digest(bytes)),
            };
            assert_eq!(campaign_receipt_owned(&b, owner).unwrap()["accepted"], true);
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, mode);
            assert!(campaign_receipt_owned(&b, owner + 1).is_err());
            for unsafe_mode in [0o620, 0o602, 0o666] {
                fs::set_permissions(&path, fs::Permissions::from_mode(unsafe_mode)).unwrap();
                assert!(campaign_receipt_owned(&b, owner).is_err());
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let alias = root.path().join(format!("alias-{mode}"));
            fs::hard_link(&path, &alias).unwrap();
            assert!(campaign_receipt_owned(&b, owner).is_err());
            fs::remove_file(alias).unwrap();
            let alias = root.path().join(format!("link-{mode}"));
            symlink(&path, &alias).unwrap();
            let linked = BoundFile {
                path: alias,
                sha256: b.sha256.clone(),
            };
            assert!(campaign_receipt_owned(&linked, owner).is_err());
            fs::write(&path, b"{\"accepted\":false}").unwrap();
            assert!(campaign_receipt_owned(&b, owner).is_err());
        }
    }
    #[test]
    fn readable_mirror_preserves_exact_accepted_bytes_and_original_binding() {
        let bytes = b"{\"accepted\":true}\n";
        let sha = hex_lower(&Sha256::digest(bytes));
        let original = BoundFile {
            path: "/private/accepted/fleet.json".into(),
            sha256: sha.clone(),
        };
        let mut copy = BoundFile {
            path: "/readable/fleet-observation.json".into(),
            sha256: sha.clone(),
        };
        mirror_integrity(&original, &copy, bytes, bytes).unwrap();
        assert!(mirror_integrity(&original, &copy, bytes, b"{ \"accepted\": true }\n").is_err());
        copy.path = original.path.clone();
        assert!(mirror_integrity(&original, &copy, bytes, bytes).is_err());
        copy.path = "/readable/fleet-observation.json".into();
        copy.sha256 = "b".repeat(64);
        assert!(mirror_integrity(&original, &copy, bytes, bytes).is_err());
        assert_eq!(original.sha256, sha);
    }
    #[test]
    fn established359_observer_profile_is_exact_and_does_not_generalize_ancestry() {
        let path = Path::new(
            "/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness/horizon-live-resource-sample-fixture.json",
        );
        let directories = [
            (
                "/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness",
                1000,
                1000,
                0o775,
            ),
            (
                "/home/ubuntu/workspace/jetstreamer/.codex",
                1000,
                1000,
                0o775,
            ),
            ("/home/ubuntu/workspace/jetstreamer", 1000, 1000, 0o775),
            ("/home/ubuntu/workspace", 1000, 1000, 0o775),
            ("/home/ubuntu", 1000, 1000, 0o750),
            ("/home", 0, 0, 0o755),
            ("/", 0, 0, 0o755),
        ];
        let profile = directories
            .into_iter()
            .map(|(p, uid, gid, mode)| Ancestor {
                path: p.into(),
                uid,
                gid,
                mode,
                dev: 1,
                ino: 2,
            })
            .collect::<Vec<_>>();
        assert!(established_observer_ancestry(path, &profile));
        assert!(!established_observer_ancestry(
            Path::new("/other/horizon-live-resource-sample-fixture.json"),
            &profile
        ));
        assert!(!established_observer_ancestry(
            &path.with_file_name("arbitrary.json"),
            &profile
        ));
        for i in 0..profile.len() {
            let mut changed = profile.clone();
            changed[i].mode ^= 0o002;
            assert!(!established_observer_ancestry(path, &changed));
            let mut changed = profile.clone();
            changed[i].uid += 1;
            assert!(!established_observer_ancestry(path, &changed));
        }
    }
    fn memory_fixture() -> (Value, Value, Value) {
        let f = json!({"active":[],"unit_census":{}});
        let o = json!({"host_memory":{"total_kib":1_000_000_000u64}});
        let proposal = json!({"kernel_limits":{"requested_memory_max_bytes":225_000_000_000u64},"guard_memory_max_bytes":1<<30});
        (f, o, proposal)
    }
    #[test]
    fn candidate_memory_keeps_native223_floor_once_with_canary_or_without() {
        let (mut f, o, p) = memory_fixture();
        let (base, _) = memory_requirement(&f, &o, &p, 123, &[]).unwrap();
        assert_eq!(base, 102_400_000_000 + 225_000_000_000 + (1 << 30) + 123);
        let row = prefix223_live_peer::fixture_row();
        let owner = singleton227_admission::active_owner(&row).unwrap().clone();
        f["unit_census"][prefix223_native20::UNIT] = owner;
        f["active"].as_array_mut().unwrap().push(row);
        let (with_native, _) = memory_requirement(&f, &o, &p, 123, &[]).unwrap();
        assert_eq!(
            with_native,
            (480u64 << 30) + 225_000_000_000 + (1 << 30) + 123
        );
        let top_up = (480u64 << 30) - 102_400_000_000;
        let e = json!({"unit":canary227::UNIT,"memory_floor_top_up_bytes":top_up});
        assert_eq!(
            memory_requirement(&f, &o, &p, 123 + top_up, std::slice::from_ref(&e))
                .unwrap()
                .0,
            with_native
        );
        assert!(memory_requirement(&f, &o, &p, 123 + top_up, &[e.clone(), e]).is_err());
        assert!(memory_requirement(&f, &o, &p, u64::MAX, &[]).is_err());
    }
    #[test]
    fn pending_or_missing_original_and_candidate_owners_block_current_admission() {
        let (old, _) = original(204).unwrap();
        let p = json!({"epoch":204,"producer_unit":"new.service","guard_unit":"guard.service"});
        let idle = |name: &str| json!({"Id":name,"InvocationID":"","LoadState":"not-found","MainPID":"0","NRestarts":"0","ControlGroup":"","ActiveState":"inactive","SubState":"dead"});
        let park = "horizon-foundation-prefix213-park348-v2.service";
        let maintenance = "horizon-foundation-holding213-maintenance-v1.service";
        let mut census = BTreeMap::from([
            (old.into(), idle(old)),
            ("new.service".into(), idle("new.service")),
            ("guard.service".into(), idle("guard.service")),
            (park.into(), idle(park)),
            (maintenance.into(), idle(maintenance)),
        ]);
        candidate_idle(&p, &census).unwrap();
        let mut missing = census.clone();
        missing.remove(old);
        assert!(candidate_idle(&p, &missing).is_err());
        census.get_mut(old).unwrap()["ActiveState"] = json!("activating");
        assert!(candidate_idle(&p, &census).is_err());
    }
    #[test]
    fn disk_floor_and_exact_mirror_staging_cannot_be_underreserved_or_overflow() {
        let mut p =
            json!({"protected_existing_floor_bytes":1000,"candidate_incremental_peak_bytes":2000});
        assert_eq!(disk_requirement(&p, 1000).unwrap(), 3000);
        assert!(disk_requirement(&p, 1001).is_err());
        p["protected_existing_floor_bytes"] = json!(u64::MAX);
        assert!(disk_requirement(&p, 1000).is_err());
        let r = json!({"external_control_metadata_bytes":(20u64<<20)+123});
        metadata_requirement(&r, 123).unwrap();
        assert!(metadata_requirement(&r, 124).is_err());
        assert!(metadata_requirement(&r, u64::MAX).is_err());
    }
}
