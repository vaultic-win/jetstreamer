//! Fixed readonly-ledger native163 v7 restore admission. No replay, launch,
//! credentials, transport, service control, status publication or R2 operations.
//! Additive SOURCE-ONLY issuer for the current full-reader witness graph.
//! Existing native v7 consumer/finalizer bytes remain independently qualified.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd};
mod held;
mod provenance;
mod reader_handoff;

pub(in crate::fleet) const ACTOR: &str = "horizon-epoch163-native-input-20261106-v1.service";
pub(in crate::fleet) const ISSUER: &str =
    "horizon-epoch163-native-input-admission-20261107-v1.service";
const NATIVE_IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch163-native-input-tools-20261106-v7/native-input";
const NATIVE_SHA: &str = "9e9de6bdcb149d08d17cc53ce4322577e4a1aab164a1ac848b04ae8426205850";
const WORKER: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const MEMORY: u64 = 128 << 30;
const SCRATCH: u64 = 40 << 30;
const INODES: u64 = 131072;
const VMA: u64 = 1048576;
const EXPORT: u64 = 642177138688;
const DATA_FLOOR: u64 = 5114649588372;
const NORMAL_POOL: u64 = 6 << 30;
const MEM_FLOOR: u64 = EXPORT + MEMORY + (2 << 30) + (512 << 20) + (8 << 30);
const R24: &str = "/home/sol/.jetstreamer-private/epoch163-native-input-qa-20261106-v7/RESOURCE_PHASES_R24_NATIVE163_QA_DATA_BOOKED.json";
const R24_SHA: &str = "0d95b4cfe5cde644d3b9105c32116598a8a7a449c14b9003f48e380bf6ad96da";
const NATIVE_QA: &str = "/home/sol/.jetstreamer-private/epoch163-native-input-qa-20261106-v7/ROOT_ACTUAL76_TESTS_ALL15_ORIGINAL_DRAINS_COMPLETE.json";
const NATIVE_QA_SHA: &str = "c18047cf99c9b3eebde4016d35961f4d1cb2f869d82e2903622650389a165f1e";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativePlan {
    schema: String,
    program: Bound,
    worker: Bound,
    genesis: Bound,
    download: Bound,
    admission_program: Bound,
    admission: PathBuf,
    snapshot: PathBuf,
    ledger: PathBuf,
    scratch: PathBuf,
    protected_filesystem: PathBuf,
    state: PathBuf,
    minimum_free_bytes: u64,
    minimum_available_memory_bytes: u64,
    maximum_runtime_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSpec {
    schema: String,
    native_plan: Bound,
    native_booking: Bound,
    current_phase_ledger: Bound,
    memory_request: memory::model::Request,
    memory_receipt: Bound,
    memory_completion: Bound,
    data_receipt: Bound,
    data_completion: Bound,
    data_policy: Bound,
    data_policy_seal: Bound,
    resource_accounting: Value,
    download_plan: Bound,
    download_unit: String,
    #[serde(default)]
    current_reader_before: Option<Bound>,
}
fn fixed(path: &str, sha256: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha256.into(),
    }
}
fn same(a: &Bound, b: &Bound) -> bool {
    json!(a) == json!(b)
}
fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o700,
        "native issuer Root-private canonical directory"
    );
    Ok(())
}
fn plan(sb: &Bound, issuer: &Bound) -> Result<NativePlan> {
    let p: NativePlan = serde_json::from_value(immutable(sb)?)?;
    ensure!(
        p.schema == "epoch163-native-input-plan-v3"
            && same(&p.program, &fixed(NATIVE_IMAGE, NATIVE_SHA))
            && p.worker.sha256 == WORKER
            && p.genesis.sha256 == GENESIS
            && same(&p.admission_program, issuer)
            && p.admission == p.state.join("admission.json")
            && p.genesis.path == p.ledger.join("genesis.tar.bz2")
            && p.protected_filesystem == Path::new("/home/sol")
            && p.minimum_available_memory_bytes >= MEM_FLOOR
            && p.minimum_free_bytes >= DATA_FLOOR + SCRATCH
            && (60..=7200).contains(&p.maximum_runtime_seconds),
        "native exact v7 prepared plan/profile"
    );
    for root in [
        p.ledger.as_path(),
        p.scratch.as_path(),
        p.state.as_path(),
        p.snapshot.parent().context("snapshot parent")?,
    ] {
        private(root)?;
    }
    for (i, a) in [&p.ledger, &p.scratch, &p.state].iter().enumerate() {
        ensure!(
            !p.snapshot.starts_with(a),
            "snapshot overlaps mutable native namespace"
        );
        for b in [&p.ledger, &p.scratch, &p.state].iter().skip(i + 1) {
            ensure!(
                !a.starts_with(b) && !b.starts_with(a),
                "native namespaces overlap"
            );
        }
    }
    ensure!(
        p.snapshot.is_absolute()
            && p.snapshot.canonicalize()? == p.snapshot
            && p.snapshot.file_name().and_then(|s| s.to_str())
                == Some("snapshot-70415741-2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY.tar.zst")
            && !p.ledger.join("genesis.bin").try_exists()?
            && !p.admission.try_exists()?
            && !p.state.join("initial-guard.json").try_exists()?
            && !p.state.join("outcome.json").try_exists()?,
        "fresh native state/canonical snapshot/genesis"
    );
    // Metadata and small immutable source reads only; snapshot body is never opened.
    for b in [&p.program, &p.worker, &p.admission_program] {
        storage::bytes(b, 256 << 20, true)?;
    }
    storage::bytes(&p.genesis, 10 << 20, true)?;
    protected(&fixed(NATIVE_QA, NATIVE_QA_SHA))?;
    Ok(p)
}
fn self_actor(sb: &Bound, sha: &str) -> Result<Bound> {
    ensure!(
        unsafe { libc::geteuid() } == 0
            && !env::vars_os().any(|(k, _)| k.to_string_lossy().starts_with("LD_")
                || k == "GLIBC_TUNABLES"
                || k == "SYSTEMD_HOST"),
        "native issuer identity/loader override"
    );
    let image = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: sha.into(),
    };
    storage::bytes(&image, 256 << 20, true)?;
    let mapped = fs::metadata("/proc/self/exe")?;
    let named = fs::metadata(&image.path)?;
    ensure!(
        (mapped.dev(), mapped.ino()) == (named.dev(), named.ino())
            && image.path.parent().and_then(Path::parent)
                == Some(Path::new("/usr/local/lib/jetstreamer")),
        "native issuer actual sealed mapped image"
    );
    let n = held::native(ISSUER)?;
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        storage::hex(&iid, 32)
            && n["Id"] == ISSUER
            && n["InvocationID"] == iid
            && n["MainPID"].as_str() == Some(std::process::id().to_string().as_str())
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["Type"] == "exec"
            && n["User"] == "root"
            && n["MemoryAccounting"] == "yes"
            && n["MemoryMax"].as_str() == Some((2u64 << 30).to_string().as_str())
            && n["MemorySwapMax"] == "0"
            && n["NoNewPrivileges"] == "yes"
            && n["PrivateNetwork"] == "no"
            && n["EnvironmentFiles"] == "/etc/jetstreamer/horizon-r2.env (ignore_errors=no)"
            && n["CPUQuotaPerSecUSec"] == "1s"
            && n["TasksMax"] == "512"
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["Job"] == ""
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{ISSUER}"),
        "exact actual2GiB native issuer service"
    );
    // Complete accounting authenticates remote floor pairs with GET/HEAD.
    // Fail missing/invalid R2 configuration before any held actor capture.
    let _readonly_r2 = r2_config_from_env()?;
    let args = vec![
        image.path.to_string_lossy().into_owned(),
        "admit-native163".into(),
        sb.path.to_string_lossy().into_owned(),
        "--spec-sha256".into(),
        sb.sha256.clone(),
        "--self-sha256".into(),
        sha.into(),
    ];
    held::command(&n, &image.path, &args)?;
    held::mapped(std::process::id(), &image, &args)?;
    Ok(image)
}
fn booking(s: &NativeSpec) -> Result<Value> {
    let b = immutable(&s.native_booking)?;
    let phase = provenance::phases(s)?;
    ensure!(
        b["schema"] == "epoch163-native-restore-fixed128-phase-booking-v2"
            && b["native_plan"] == json!(s.native_plan)
            && b["previous_phase_ledger"] == json!(s.current_phase_ledger)
            && b["legacy_phase_anchor"] == json!(fixed(R24, R24_SHA))
            && b["visible_thread_takeover"] == json!(provenance::takeover_binding())
            && b["primary_thread_id"] == provenance::PRIMARY
            && b["actor_unit"] == ACTOR
            && b["issuer_unit"] == ISSUER
            && b["actor_memory_bytes"] == MEMORY
            && b["issuer_memory_within_normal_pool_bytes"] == 2u64 << 30
            && b["normal_pool_bytes"] == NORMAL_POOL
            && b["candidate_incremental_DATA_bytes"] == SCRATCH
            && b["protected_existing_DATA_bytes"] == phase["protected_existing_DATA_bytes"]
            && b["minimum_available_memory_bytes"] == phase["minimum_available_memory_bytes"]
            && b["minimum_existing_memory_bytes"] == phase["minimum_existing_memory_bytes"]
            && b["retained145"] == phase["retained145"]
            && b["extra_full_reader_QA_memory_bytes"] == 0
            && b["all_original_memory_and_DATA_promises_retained"] == true
            && b["no_release_or_idle_credit"] == true
            && b["native_restore_only"] == true
            && b["replay_launch_authorized"] == false
            && b["publication_authorized"] == false
            && b["remote_mutations"] == false
            && b["r2_mutations"] == false,
        "native fixed candidate must have Root-issued immutable phase booking; arbitrary totals rejected"
    );
    Ok(b)
}
fn prepared_phase_fit(p: &NativePlan, phase: &Value) -> Result<()> {
    ensure!(p.minimum_free_bytes >= n(phase, "protected_existing_DATA_bytes")?
            .checked_add(SCRATCH).context("native phase DATA overflow")?
        && p.minimum_available_memory_bytes >= n(phase, "minimum_available_memory_bytes")?,
        "native prepared plan predates current whole phase obligations");
    Ok(())
}
fn resource_floor(existing_data: u64, inherited: u64) -> Result<u64> {
    existing_data
        .max(inherited)
        .max(DATA_FLOOR)
        .checked_add(SCRATCH)
        .context("native disk arithmetic overflow")
}
fn fit(
    p: &NativePlan,
    memory: &memory::VerifiedParentMemory,
    data: &data::VerifiedData,
    raw: &Value,
    a: &Value,
    b: &Value,
    phase: &Value,
) -> Result<u64> {
    ensure!(
        memory.selected_parent_retirement_bytes() == 192u64 << 30
            && memory.selected_cached145_parent_retirement_bytes() == 192u64 << 30
            && data.evidence()["current"] == memory.evidence()["request"]["current"],
        "native distinct genuine typed memory/DATA views"
    );
    ensure!(
        memory.effective_total_bytes() >= n(phase, "minimum_existing_memory_bytes")?
            && p.minimum_available_memory_bytes >= n(phase, "minimum_available_memory_bytes")?,
        "native current phase retained memory promises/fresh physical floor"
    );
    let observer = storage::json(&to_bound(
        &memory.evidence()["request"]["current"]["observer"],
    )?)?;
    let total = observer["host_memory"]["total_kib"]
        .as_u64()
        .and_then(|x| x.checked_mul(1024))
        .context("native original host memory")?;
    ensure!(
        memory
            .effective_total_bytes()
            .checked_add(MEMORY)
            .and_then(|x| x.checked_add(NORMAL_POOL))
            .is_some_and(|x| x <= total),
        "native retained full hard commitments exceed host"
    );
    let disk = resource_floor(
        data.effective_protected_bytes(),
        n(raw, "inherited_live_guard_maximum_bytes")?
            .max(n(phase, "protected_existing_DATA_bytes")?),
    )?;
    ensure!(
        p.minimum_free_bytes >= disk,
        "prepared native guard omits current retained DATA/floor"
    );
    for v in [a, b] {
        ensure!(
            n(v, "free_bytes")? >= p.minimum_free_bytes
                && n(v, "available_memory_bytes")? >= p.minimum_available_memory_bytes
                && n(v, "free_inodes")? >= INODES
                && n(v, "vm_max_map_count")? > VMA,
            "native current adjacent memory/DATA/inode/VMA physical fit"
        );
    }
    let elapsed = n(b, "sampled_unix_micros")?
        .checked_sub(n(a, "sampled_unix_micros")?)
        .context("native pressure clock regressed")?;
    ensure!(
        (1000..=90000000).contains(&elapsed),
        "native adjacent pressure window"
    );
    for (key, fraction) in [("cpu", 500u64), ("memory", 100), ("io", 100)] {
        let delta = b["pressure_total_usec"][key]
            .as_u64()
            .and_then(|x| x.checked_sub(a["pressure_total_usec"][key].as_u64()?))
            .context("native pressure regressed")?;
        ensure!(
            u128::from(delta) * 1000 <= u128::from(elapsed) * u128::from(fraction),
            "native physical pressure {key}"
        );
    }
    let owners = raw["current_unique_owner_census"]
        .as_array()
        .context("native complete raw owner census")?;
    ensure!(
        !owners
            .iter()
            .any(|v| v["first_epoch"].as_u64().is_some_and(|n| n <= 163)
                && v["last_epoch"].as_u64().is_some_and(|n| n >= 163)),
        "overlapping epoch163 live claim"
    );
    // Actor itself has CPUQuota=800%; issuer1CPU plus one conservative 3CPU allowance.
    let cpu = n(raw, "current_replay_cpu_quota_micros")?
        .checked_add(12000000)
        .context("native CPU overflow")?;
    ensure!(
        n(a, "available_logical_cpus")? == n(b, "available_logical_cpus")?
            && n(b, "available_logical_cpus")?
                .checked_mul(1000000)
                .is_some_and(|n| cpu <= n),
        "native CPU affinity/retained quota fit"
    );
    Ok(disk)
}
/// Atomic visibility: the consumer must never see a partially written admission.
fn publish(parent: &Path, value: &Value, nonce: &str) -> Result<()> {
    publish_named(parent, value, nonce, "admission.json", 4 << 20).map(|_| ())
}
fn publish_named(
    parent: &Path,
    value: &Value,
    nonce: &str,
    name: &str,
    cap: usize,
) -> Result<Bound> {
    private(parent)?;
    ensure!(storage::hex(nonce, 32), "native publication nonce");
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let before = dir.metadata()?;
    let tmp = std::ffi::CString::new(format!(".admission-{nonce}.staged"))?;
    ensure!(
        name == "admission.json" || name == format!("issuer-resource-proof-{nonce}.json"),
        "native receipt exact leaf namespace"
    );
    let target = std::ffi::CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            tmp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o400,
        )
    };
    ensure!(
        fd >= 0,
        "native no-clobber staged receipt: {}",
        std::io::Error::last_os_error()
    );
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= cap, "native receipt size bound");
    f.write_all(&bytes)?;
    f.sync_all()?;
    let named = fs::symlink_metadata(parent)?;
    ensure!(
        (before.dev(), before.ino()) == (named.dev(), named.ino()),
        "native receipt parent replaced"
    );
    ensure!(
        unsafe {
            libc::renameat2(
                dir.as_raw_fd(),
                tmp.as_ptr(),
                dir.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "native final admission exists/conflicts: {}",
        std::io::Error::last_os_error()
    );
    dir.sync_all()?;
    Ok(Bound {
        path: parent.join(name),
        sha256: storage::sha(&bytes),
    })
}
/// Opt-in uses the original successful full reader as an explicitly historical
/// bracket, after the genuine opaque memory constructor authenticated its
/// complete raw before/after, qualification, original completion and freshness.
/// A fresh complete raw pass and both adjacent physical snapshots remain below.
fn exact_reader_before_binding(selected: &Bound, current_reader: &memory::model::Bound) -> Result<()> {
    ensure!(json!(selected)==json!(current_reader),"native original before reader differs from actual memory request");
    Ok(())
}
fn original_reader_before(selected: Option<&Bound>, request: &memory::model::Request, view: &memory::VerifiedParentMemory, clock: u64) -> Result<Option<(Value, Value)>> {
    let Some(selected) = selected else { return Ok(None); };
    exact_reader_before_binding(selected, &request.current_reader)?;
    ensure!(view.evidence()["request"]["current_reader"]==json!(selected),"opaque memory before reader crossed");
    let original=immutable(selected)?;
    let at=original["recorded_unix_seconds"].as_u64().context("native original reader clock")?;
    ensure!(at<=clock && clock-at<=300
        && original["schema"]=="failed4-current-complete-accounting-reader-proof-v1"
        && original["raw_history_preserved"]==true
        && original["all_DATA_promises_preserved"]==true
        && original["terminal_legacy_minimum_already_applied_once"]==true
        && original["memory_budget_credit_applied_bytes"]==0
        && original["DATA_credit_bytes"]==0 && original["physical_credit_bytes"]==0
        && original["replay_launch_authorized"]==false,
        "native original successful reader scope/freshness differs");
    let accounting=to_bound(&original["accounting"])?;
    let before=immutable(&accounting)?;
    ensure!(view.evidence()["raw_accounting_serde_json_sha256"]
        ==hex_lower(&sha2::Sha256::digest(serde_json::to_vec(&before)?)),
        "native original before does not match genuine typed memory report");
    Ok(Some((before,json!({"kind":"original-successful-full-reader-after-accounting",
        "reader":selected,"accounting":accounting,"original_reader_recorded_unix_seconds":at,
        "not_a_new_raw_capture":true,"genuine_opaque_memory_constructor_authenticated":true}))))
}
pub(in crate::fleet) async fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 7
            && args[1] == "admit-native163"
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && storage::hex(&args[4], 64)
            && storage::hex(&args[6], 64),
        "exact native issuer CLI"
    );
    let sb = fixed(&args[2], &args[4]);
    let image = self_actor(&sb, &args[6])?;
    let s: NativeSpec = serde_json::from_value(immutable(&sb)?)?;
    ensure!(
        s.schema == "epoch163-native-restore-issuer-spec-v1",
        "native issuer spec schema"
    );
    let p = plan(&s.native_plan, &image)?;
    let phase = provenance::phases(&s)?;
    let booked = booking(&s)?;
    prepared_phase_fit(&p, &phase)?;
    let download = provenance::download(&s, &p)?;
    let first = held::capture(&p, &s.native_plan)?;
    let start = now()?;
    let m = immutable(&s.memory_receipt)?;
    let d = immutable(&s.data_receipt)?;
    original_selection(
        &m,
        &immutable(&s.memory_completion)?,
        &s.memory_receipt,
        "memory",
    )?;
    original_selection(&d, &immutable(&s.data_completion)?, &s.data_receipt, "DATA")?;
    ensure!(
        m["selection"]["request"] == json!(s.memory_request)
            && d["memory_selection"] == json!(s.memory_receipt),
        "native crossed original selector lineage"
    );
    let view = memory::admission_bridge::from_current_reader(&s.memory_request, start)?;
    let selected = data::select(&view, &s.data_policy, &s.data_policy_seal, start)?;
    let current = &view.evidence()["request"]["current"];
    ensure!(
        selected.evidence()["projection"] == d["data_selection"]["projection"]
            && s.resource_accounting["observer"] == current["observer"]
            && s.resource_accounting["fleet"] == current["fleet"]
            && s.resource_accounting["fleet_plan"] == current["fleet_plan"]
            && s.resource_accounting["phase_events"][1]["source"] == current["frame"],
        "native full genuine current reader/fleet/four-family chain crossed"
    );
    pressures(&storage::json(&to_bound(&current["observer"])?)?)?;
    let historical=s.current_reader_before.as_ref().map(|reader|
        reader_handoff::Handoff::load(reader,&s.memory_request,&view,&s.resource_accounting,now()?)).transpose()?;
    let (before,before_origin)=if let Some(handoff)=&historical {
        (handoff.before().clone(),handoff.origin().clone())
    } else {
        (epoch186::accounting::protected_data_basis(&s.resource_accounting,now()?).await?,
            json!({"kind":"new-complete-current-raw-builder-before-held-admission"}))
    };
    let a=physical()?;
    let after=epoch186::accounting::protected_data_basis(&s.resource_accounting,now()?).await?;
    let b=physical()?;
    let (semantic_after,comparison_after)=if let Some(handoff)=&historical {
        handoff.project(&after)?
    } else { (after.clone(),after.clone()) };
    epoch186::accounting::stable_guard_basis(&s.resource_accounting,&before,&comparison_after)?;
    unchanged_claims(&before,&comparison_after)?;
    let original=immutable(&s.memory_request.current_reader)?;
    unchanged_claims(&immutable(&to_bound(&original["accounting"])?)?,&comparison_after)?;
    let disk=fit(&p,&view,&selected,&semantic_after,&a,&b,&phase)?;
    let end = now()?;
    ensure!(
        end.checked_sub(start).is_some_and(|n| n <= 90),
        "native held resource transaction deadline"
    );
    let end_view = memory::admission_bridge::from_current_reader(&s.memory_request, end)?;
    let end_data = data::select(&end_view, &s.data_policy, &s.data_policy_seal, end)?;
    ensure!(
        end_view.effective_total_bytes() == view.effective_total_bytes()
            && end_data.evidence()["projection"] == selected.evidence()["projection"],
        "native final complete typed evidence changed"
    );
    if let Some(handoff)=&historical {
        handoff.revalidate(&s.memory_request,&end_view,now()?)?;
        let (end_semantic,end_comparison)=handoff.project(&after)?;
        ensure!(end_semantic==semantic_after && end_comparison==comparison_after,
            "native historical semantic comparison changed before publication");
    }
    ensure!(
        plan(&s.native_plan, &image)?.minimum_free_bytes == p.minimum_free_bytes
            && provenance::phases(&s)? == phase
            && booking(&s)? == booked
            && provenance::download(&s, &p)? == download,
        "native immutable profile/phase/downloader changed"
    );
    let last = held::capture(&p, &s.native_plan)?;
    ensure!(first == last, "original held actor/ready/namespace changed");
    self_actor(&sb, &args[6])?;
    ensure!(now()?.checked_sub(start).is_some_and(|age|age<=90),"native original transaction expired before resource publication");
    let nonce = env::var("INVOCATION_ID")?;
    let resource_proof = publish_named(
        &p.state,
        &json!({"schema":"epoch163-native-original-resource-evidence-v1",
        "issuer_spec":sb,"fixed_booking":s.native_booking,"resource_phase_ledger":s.current_phase_ledger,"legacy_phase_anchor":fixed(R24,R24_SHA),"visible_thread_takeover":provenance::takeover_binding(),
        "actual_held_actor":last,"original_download":download,"memory":view.evidence(),"DATA":selected.evidence(),
        "raw_before":before,"raw_before_origin":before_origin,"raw_after":after,
        "semantic_after_retention_serde_sha256":storage::sha(&serde_json::to_vec(&semantic_after)?),
        "historical_comparison_after_serde_sha256":storage::sha(&serde_json::to_vec(&comparison_after)?),
        "historical_handoff":historical.as_ref().map(|h|h.evidence()),
        "historical_comparison_only_not_raw_replacement":historical.is_some(),"physical_before":a,"physical_after":b,
        "admission_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        &nonce,
        &format!("issuer-resource-proof-{nonce}.json"),
        32 << 20,
    )?;
    ensure!(
        held::capture(&p, &s.native_plan)? == last,
        "native actor changed before final publication"
    );
    ensure!(now()?.checked_sub(start).is_some_and(|age|age<=90),"native original transaction expired before admission publication");
    let record = json!({"schema":"epoch163-native-input-admission-v2","admitted":true,"issuer":image,
        "plan":s.native_plan,"program":p.program,"download":p.download,"worker":p.worker,
        "actor_invocation_id":last["iid"],"actor_pid":last["pid"],"actor_start_ticks":last["start_ticks"],
        "native_restore_only":true,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
        "recorded_unix_seconds":now()?,"actor_memory_bytes":MEMORY,"protected_existing_DATA_bytes":disk-SCRATCH,
        "candidate_incremental_DATA_bytes":SCRATCH,"minimum_available_memory_bytes":p.minimum_available_memory_bytes,
        "minimum_free_bytes":p.minimum_free_bytes,"protected_filesystem":p.protected_filesystem,
        "scratch_maximum_bytes":SCRATCH,"scratch_maximum_inodes":INODES,"vma_stop":VMA,
        "mapped_worker_image_required":true,"read_only_input_namespace_required":true,
        "mapped_worker_not_yet_started_or_verified":true,"snapshot_body_opened_by_issuer":false,
        "issuer_spec":sb,"fixed_booking":s.native_booking,"resource_phase_ledger":s.current_phase_ledger,"legacy_phase_anchor":fixed(R24,R24_SHA),"visible_thread_takeover":provenance::takeover_binding(),
        "actual_held_actor":last,"original_download":download,"full_resource_evidence":resource_proof,
        "effective_existing_memory_bytes":view.effective_total_bytes(),"effective_existing_DATA_bytes":selected.effective_protected_bytes(),
        "no_raw_memory_or_DATA_release_credit":true});
    publish(&p.state, &record, env::var("INVOCATION_ID")?.as_str())?;
    Ok(())
}
/// Discovery exemption is tied to the actual issuer and reauthenticates the held
/// actor. It is NOT an exemption from the fixed additive128GiB/40GiB fit above.
pub(in crate::fleet) fn covered_held(
    name: &str,
    helper_name: &str,
    native: &Value,
) -> Result<bool> {
    if name != ACTOR {
        return Ok(false);
    }
    ensure!(
        helper_name == ISSUER,
        "native restore held actor cannot be ignored by another helper"
    );
    let a = env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 7 && a[1] == "admit-native163",
        "native discovery issuer command"
    );
    let sb = fixed(&a[2], &a[4]);
    let issuer = self_actor(&sb, &a[6])?;
    let s: NativeSpec = serde_json::from_value(immutable(&sb)?)?;
    let p = plan(&s.native_plan, &issuer)?;
    let booked = booking(&s)?;
    prepared_phase_fit(&p, &booked)?;
    let captured = held::capture(&p, &s.native_plan)?;
    for key in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "Restart",
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainStatus",
        "ControlGroup",
        "ExecStart",
        "MemoryAccounting",
        "MemoryMax",
        "MemorySwapMax",
        "CPUQuotaPerSecUSec",
        "TasksMax",
        "User",
        "Type",
    ] {
        ensure!(
            native.get(key).is_some() && captured["native"][key] == native[key],
            "native discovery changed between reads: {key}"
        );
    }
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Root-only isolated no-clobber/fsync/immutable publication control; requires booked exact test actor"]
    fn root_atomic_publication_never_replaces_an_existing_admission() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let parent = PathBuf::from(format!("/tmp/native163-publish-{}", std::process::id()));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let first = json!({"source_control":true,"admitted":false});
        publish(&parent, &first, &"1".repeat(32)).unwrap();
        let actual = fs::read(parent.join("admission.json")).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&actual).unwrap(), first);
        assert_eq!(
            fs::metadata(parent.join("admission.json")).unwrap().mode() & 0o777,
            0o400
        );
        assert!(publish(&parent, &json!({"admitted":true}), &"2".repeat(32)).is_err());
        assert_eq!(fs::read(parent.join("admission.json")).unwrap(), actual);
        assert!(publish(&parent, &first, "../escape").is_err());
        fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn resource_floor_keeps_each_original_floor_once_and_adds_fixed_peak() {
        assert_eq!(resource_floor(1, 2).unwrap(), DATA_FLOOR + SCRATCH);
        assert_eq!(
            resource_floor(DATA_FLOOR + 123, DATA_FLOOR + 456).unwrap(),
            DATA_FLOOR + 456 + SCRATCH
        );
        assert!(resource_floor(u64::MAX, 1).is_err());
    }
    #[test]
    fn native_schema_cannot_take_arbitrary_resource_totals() {
        assert!(serde_json::from_value::<NativeSpec>(json!({"schema":"epoch163-native-restore-issuer-spec-v1","available_memory_bytes":u64::MAX,"free_bytes":u64::MAX})).is_err());
    }
    #[test]
    fn native_memory_profile_is_distinct_from_replay128() {
        assert_eq!(MEMORY, 137438953472);
        assert_eq!(SCRATCH, 42949672960);
        assert_eq!(MEM_FLOOR, 790890381312);
        assert_ne!(SCRATCH, 768u64 << 30);
        assert_ne!(ACTOR, "jetstreamer-root-sweep-e163-first-output128-20261106-v1.service");
    }
    #[test]
    fn native_discovery_is_not_a_foreign_namespace_exemption() {
        assert!(!covered_held("other.service", ISSUER, &json!({})).unwrap());
        assert!(covered_held(ACTOR, "other.service", &json!({})).is_err());
    }
}

#[cfg(test)]
mod original_reader_before_tests {
    use super::*;
    #[test]
    #[ignore = "Root must bind actual immutable successful witness memory selector receipt; no held actor/admission"]
    fn actual_typed_memory_original_before_is_exact_and_cannot_refresh_its_clock() -> Result<()> {
        let receipt:Bound=serde_json::from_str(&env::var("HORIZON_NATIVE_READER_BEFORE_MEMORY_RECEIPT_BINDING")?)?;
        let original=immutable(&receipt)?;
        ensure!(original["capability_only"]==false && original["schema"]=="terminal199-parent-memory-selector-original-execution-v1","genuine original selector required");
        let request:memory::model::Request=serde_json::from_value(original["selection"]["request"].clone())?;
        let clock=n(&original,"recorded_unix_seconds")?;
        let view=memory::admission_bridge::from_current_reader(&request,clock)?;
        let selected:Bound=serde_json::from_value(json!(request.current_reader))?;
        ensure!(original_reader_before(None,&request,&view,clock)?.is_none(),"legacy route changed");
        let (before,origin)=original_reader_before(Some(&selected),&request,&view,clock)?.context("original before absent")?;
        let proof=immutable(&selected)?;
        ensure!(before==immutable(&to_bound(&proof["accounting"])?)? && origin["not_a_new_raw_capture"]==true,"original raw binding or origin changed");
        ensure!(origin["original_reader_recorded_unix_seconds"]==proof["recorded_unix_seconds"],"original clock changed");
        let mut crossed=selected.clone();crossed.sha256="0".repeat(64);
        ensure!(original_reader_before(Some(&crossed),&request,&view,clock).is_err(),"crossed reader accepted");
        ensure!(original_reader_before(Some(&selected),&request,&view,n(&proof,"recorded_unix_seconds")?+301).is_err(),"stale original bracket accepted");
        Ok(())
    }
    #[test]
    fn exact_optional_original_reader_binding_rejects_crossed_path_or_digest() {
        let selected=fixed("/original/reader.json",&"a".repeat(64));
        let current:memory::model::Bound=serde_json::from_value(json!(selected)).unwrap();
        exact_reader_before_binding(&selected,&current).unwrap();
        let mut crossed=selected.clone();crossed.sha256="b".repeat(64);
        assert!(exact_reader_before_binding(&crossed,&current).is_err());
        crossed=selected;crossed.path="/another/reader.json".into();
        assert!(exact_reader_before_binding(&crossed,&current).is_err());
    }
}

#[cfg(test)]
mod closed_native_original_inputs {
    use super::*;
    #[test]
    #[ignore = "Root-only genuine normally sealed native spec and original completed downloader; no actor/admission"]
    fn actual_closed_original_inputs_pass_all_native_plan_phase_and_download_gates_before_a_hold() -> Result<()> {
        let binding: Bound = serde_json::from_str(&env::var("HORIZON_CLOSED_NATIVE_ORIGINAL_SPEC_BINDING")?)?;
        let s: NativeSpec = serde_json::from_value(immutable(&binding)?)?;
        ensure!(s.schema == "epoch163-native-restore-issuer-spec-v1", "actual native issuer spec");
        let value=immutable(&s.native_plan)?;
        let issuer=to_bound(&value["admission_program"])?;
        let p=plan(&s.native_plan,&issuer)?;
        let phase=provenance::phases(&s)?;
        let _booked=booking(&s)?;
        prepared_phase_fit(&p,&phase)?;
        let download=provenance::download(&s,&p)?;
        ensure!(download["snapshot_body_not_opened"]==true,"closed input metadata only");
        ensure!(!p.admission.exists() && !p.state.join("initial-guard.json").exists() && !p.state.join("outcome.json").exists(),"no native admission/restore produced by static preflight");
        Ok(())
    }
}
