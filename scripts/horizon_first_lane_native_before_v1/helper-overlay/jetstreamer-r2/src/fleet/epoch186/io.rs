//! Bounded native/file/S3 IO. There is no start, stop, signal or remote-write API.
use super::*;
use serde::de::{MapAccess, SeqAccess, Visitor};
use std::fmt;
#[path = "io_cached145_continuous.rs"]
pub(in crate::fleet::epoch186) mod cached145_continuous;
#[path = "io_current_census_composition.rs"]
mod current_census_composition;
#[path = "io_epoch199_append.rs"]
pub(in crate::fleet::epoch186) mod epoch199_append;
#[path = "io_terminal152_guard.rs"]
pub(in crate::fleet::epoch186) mod terminal152_guard;
#[path = "io_uploader183_owner.rs"]
mod uploader183_owner;

struct UniqueJson(Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((name, UniqueJson(value))) =
                    map.next_entry::<String, UniqueJson>()?
                {
                    if values.insert(name, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON field"));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

pub(super) fn unique_json(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let UniqueJson(value) = UniqueJson::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

type FileIdentity = (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64);
fn identity(m: &fs::Metadata) -> FileIdentity {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

pub(super) fn sealed(path: &Path) -> Result<fs::Metadata> {
    sealed_inner(path)
        .with_context(|| format!("sealed evidence: {}", accounting::evidence_path(path)))
}
fn sealed_inner(path: &Path) -> Result<fs::Metadata> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence pathname"
    );
    let m = fs::symlink_metadata(path)?;
    let parent = fs::symlink_metadata(path.parent().context("evidence parent")?)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && parent.is_dir()
            && parent.uid() == 0
            && parent.mode() & 0o022 == 0,
        "evidence lacks root custody, single-link immutability, or safe parent"
    );
    Ok(m)
}

pub(super) fn read(b: &BoundFile) -> Result<Value> {
    let before = sealed(&b.path)?;
    ensure!(
        before.len() <= 16 << 20 && digest(&b.sha256, 64),
        "evidence exceeds bound or digest malformed"
    );
    let bytes = read_stable_bounded(&b.path, 16 << 20, "epoch 186 sealed evidence")?;
    ensure!(
        identity(&before) == identity(&sealed(&b.path)?)
            && hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "evidence changed or digest differs"
    );
    unique_json(&bytes)
}

/// Hash through one no-follow descriptor; check FD and pathname metadata again.
/// A bound length limits CPU and IO and detects growth while streaming.
pub(super) fn immutable(b: &BoundFile, bytes: u64) -> Result<()> {
    immutable_inner(b, bytes)
        .with_context(|| format!("immutable evidence: {}", accounting::evidence_path(&b.path)))
}
fn immutable_inner(b: &BoundFile, bytes: u64) -> Result<()> {
    let before = sealed(&b.path)?;
    ensure!(
        before.len() == bytes && bytes > 0 && bytes <= 16u64 << 30 && digest(&b.sha256, 64),
        "immutable input length/digest outside reviewed bound"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    ensure!(
        identity(&before) == identity(&f.metadata()?),
        "immutable input replaced before open"
    );
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut count = 0u64;
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .context("immutable hash length overflow")?;
        ensure!(count <= bytes, "immutable input grew while hashing");
        hash.update(&buffer[..n]);
    }
    ensure!(
        count == bytes
            && identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&sealed(&b.path)?)
            && hex_lower(&hash.finalize()) == b.sha256,
        "immutable input changed or SHA differs"
    );
    Ok(())
}

pub(super) fn read_only_mount(path: &Path) -> Result<()> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut raw = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), raw.as_mut_ptr()) } == 0,
        "immutable input mount observation failed"
    );
    let raw = unsafe { raw.assume_init() };
    ensure!(
        raw.f_flag & libc::ST_RDONLY != 0,
        "immutable source is not mounted read-only in admission sandbox"
    );
    Ok(())
}

pub(super) fn properties(name: &str) -> Result<Value> {
    if crate::fleet::recovery199_contract::FAMILY.contains(&name) {
        return crate::fleet::recovery199_contract::unit(name);
    }
    native_properties(name, false)
}
fn guard_properties(name: &str) -> Result<Value> {
    if name == crate::fleet::recovery199_contract::GUARD {
        return crate::fleet::recovery199_contract::unit(name);
    }
    if crate::fleet::ordinary199_census_settle::candidate(name) {
        let full = crate::fleet::ordinary199_census_settle::observe(name)?;
        crate::fleet::ordinary199_census_settle::completed(&full)?;
        let narrow = native_properties(name, true)?;
        return epoch199_guard_projection(&full, narrow);
    }
    if crate::fleet::cached145_census_settle::candidate(name) {
        let full = crate::fleet::cached145_census_settle::observe(name)?;
        crate::fleet::cached145_census_rollover::completed(&full)?;
        return cached145_guard_projection(&full);
    }
    native_properties(name, true)
}
// Preserve the exact pre-existing guard-property shape. Fleet unit() does not
// request all these fields for epoch199; read the real original view separately.
fn epoch199_guard_projection(full: &Value, narrow: Value) -> Result<Value> {
    ensure!(
        full["Id"] == crate::fleet::ordinary199::GUARD
            && full["Type"] == "oneshot"
            && narrow["TimeoutStartUSec"] == "5min",
        "epoch199 completed guard scope/timeout differs"
    );
    for key in GUARD_NATIVE_FIELDS.split(',') {
        if key == "Unit" && narrow.get(key).is_none() {
            continue;
        }
        let value = narrow
            .get(key)
            .with_context(|| format!("epoch199 native field missing: {key}"))?;
        ensure!(
            value.is_string(),
            "epoch199 native field is not a string: {key}"
        );
        if let Some(prior) = full.get(key) {
            ensure!(
                value == prior,
                "epoch199 completed native views differ: {key}"
            );
        }
    }
    ensure!(
        narrow.as_object().is_some_and(|o| o
            .keys()
            .all(|key| GUARD_NATIVE_FIELDS.split(',').any(|want| want == key))),
        "epoch199 narrow view contains an unknown field"
    );
    Ok(narrow)
}
#[cfg(test)]
mod epoch199_guard_projection_tests {
    use super::*;
    #[test]
    fn epoch199_real_guard_views_supply_missing_static_fields_without_synthesis_or_rebinding() {
        let full = json!({"Id":crate::fleet::ordinary199::GUARD,"Type":"oneshot","InvocationID":"11111111111111111111111111111111","MemoryMax":"536870912","ExecStart":"actual"});
        assert!(full.get("TimeoutStartUSec").is_none());
        let mut values = serde_json::Map::new();
        for key in GUARD_NATIVE_FIELDS.split(',') {
            if key != "Unit" {
                values.insert(
                    key.into(),
                    full.get(key).cloned().unwrap_or_else(|| json!("")),
                );
            }
        }
        values.insert("TimeoutStartUSec".into(), json!("5min"));
        values.insert(
            "TriggeredBy".into(),
            json!(crate::fleet::ordinary199::TIMER),
        );
        let good = Value::Object(values);
        assert_eq!(
            epoch199_guard_projection(&full, good.clone()).unwrap(),
            good
        );
        for (key, value) in [
            ("InvocationID", "22222222222222222222222222222222"),
            ("ExecStart", "foreign"),
            ("MemoryMax", "1073741824"),
            ("TimeoutStartUSec", "infinity"),
        ] {
            let mut bad = good.clone();
            bad[key] = value.into();
            assert!(epoch199_guard_projection(&full, bad).is_err(), "{key}");
        }
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("TriggeredBy");
        assert!(epoch199_guard_projection(&full, missing).is_err());
        let mut extra = good;
        extra["unexpected"] = "x".into();
        assert!(epoch199_guard_projection(&full, extra).is_err());
    }
}

fn cached145_guard_projection(full: &Value) -> Result<Value> {
    ensure!(
        full["Id"]
            .as_str()
            .is_some_and(crate::fleet::cached145_census_settle::candidate)
            && full["Type"] == "oneshot",
        "cached145 guard projection requires the exact guard service role"
    );
    let mut projection = serde_json::Map::new();
    for key in GUARD_NATIVE_FIELDS.split(',') {
        // PID1's Unit property belongs to timer objects. The ordinary service
        // reader requests it but PID1 omits it for a service. Preserve that
        // genuine shape without inventing a value; timer validation is separate.
        if key == "Unit" && full.get(key).is_none() {
            continue;
        }
        let value = full
            .get(key)
            .with_context(|| format!("cached145 native field missing: {key}"))?;
        ensure!(
            value.is_string(),
            "cached145 native field is not a string: {key}"
        );
        projection.insert(key.into(), value.clone());
    }
    Ok(Value::Object(projection))
}
const GUARD_NATIVE_FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ExecMainCode,ControlGroup,ExecStart,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,TriggeredBy,Triggers,Unit,User,Type,TimeoutStartUSec";
fn native_properties(name: &str, guard_policy: bool) -> Result<Value> {
    ensure!(
        (name.ends_with(".service") || name.ends_with(".timer"))
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.@".contains(&c)),
        "invalid native unit name"
    );
    let fields = if guard_policy {
        "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ExecMainCode,ControlGroup,ExecStart,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,TriggeredBy,Triggers,Unit,User,Type,TimeoutStartUSec"
    } else {
        "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ExecMainCode,ControlGroup,ExecStart,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,TriggeredBy,Triggers,Unit,User,Type"
    };
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args(["show", name, "--no-pager", fields])
        .output()?;
    ensure!(
        out.stdout.len() <= 1 << 20,
        "native property output bound exceeded"
    );
    let mut values = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("invalid native property line: {line:?}"))?;
        ensure!(
            values.insert(key.into(), json!(value)).is_none(),
            "duplicate native property"
        );
    }
    let value = Value::Object(values);
    ensure!(
        value["Id"] == name
            && (out.status.success()
                || (value["LoadState"] == "not-found" && value["MainPID"] == "0")),
        "native unit query failed"
    );
    Ok(value)
}

pub(super) fn start_ticks(pid: u64) -> Result<u64> {
    let path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(&path)
        .with_context(|| format!("read live launch process identity: {path}"))?;
    ensure!(
        stat.len() <= 65536 && stat.starts_with(&format!("{pid} (")),
        "process identity differs"
    );
    let tail = stat.rsplit_once(')').context("process comm missing")?.1;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    ensure!(
        !matches!(fields.first().copied(), Some("Z" | "X" | "x")),
        "process is terminal"
    );
    fields
        .get(19)
        .context("process start ticks missing")?
        .parse()
        .map_err(Into::into)
}

/// A native MainPID is a canonical unsigned decimal string. Historical
/// capture receipts also use JSON integers; neither form accepts zero, signs,
/// padding, floats, overflow or an arbitrary truthy value.
fn captured_pid(raw: &Value) -> Result<u64> {
    let pid = if let Some(pid) = raw.as_u64() {
        pid
    } else {
        let decimal = raw
            .as_str()
            .context("captured PID is neither integer nor native decimal")?;
        let pid = decimal
            .parse::<u64>()
            .context("invalid captured native PID")?;
        ensure!(
            decimal == pid.to_string(),
            "captured native PID is noncanonical"
        );
        pid
    };
    ensure!(pid > 1, "captured PID is not a running service process");
    Ok(pid)
}

fn retained141_launch_identity(
    value: &Value,
    name: &str,
    iid: &str,
    pid: u64,
    start: u64,
) -> Result<()> {
    const UNIT: &str = "horizon-repair-141-floor-20261024-v1.service";
    if name != UNIT && value["schema"] != "jetstreamer-epoch141-repair-owner-capture-v2" {
        return Ok(());
    }
    let manager = &value["manager"];
    ensure!(
        name == UNIT
            && value["schema"] == "jetstreamer-epoch141-repair-owner-capture-v2"
            && value["epoch"] == 141
            && value["unit"] == UNIT
            && value["invocation_id"] == iid
            && manager["Id"] == UNIT
            && manager["InvocationID"] == iid
            && captured_pid(&manager["MainPID"])? == pid
            && value["process_start_ticks"] == start
            && manager["ActiveState"] == "active"
            && manager["SubState"] == "running"
            && manager["NRestarts"] == "0"
            && manager["ControlGroup"] == format!("/system.slice/{UNIT}"),
        "retained epoch 141 launch differs from actual same-unit/IID/PID/start identity"
    );
    for flag in [
        "ordinary_replay_claim",
        "publication_authorized",
        "r2_mutations",
        "replay_launch_authorized",
    ] {
        ensure!(
            value[flag] == false,
            "retained epoch 141 repair launch asserts authority: {flag}"
        );
    }
    Ok(())
}

/// Reject historical or terminal launch identities before any /proc read.
/// This is diagnostic validation only: no terminal allocation or credit is inferred.
fn launch_start_ticks(
    native: &Value,
    name: &str,
    iid: &str,
    pid: u64,
    read_start: impl FnOnce(u64) -> Result<u64>,
) -> Result<u64> {
    ensure!(
        native["Id"] == name
            && native["InvocationID"] == iid
            && native["MainPID"].as_str() == Some(pid.to_string().as_str())
            && native["NRestarts"] == "0"
            && native["ActiveState"] == "active"
            && native["SubState"] == "running"
            && native["MemoryAccounting"] == "yes",
        "bound launch is not live before process read: unit={name}, iid={iid}, pid={pid}, native={native}"
    );
    read_start(pid)
        .with_context(|| format!("bound launch process read: unit={name}, iid={iid}, pid={pid}"))
}

pub(super) fn launch_owner(
    value: &Value,
    selected: &EventOwner,
    selectors: &LaunchPointers,
) -> Result<core::Owner> {
    let name = string(value, &selectors.unit)?;
    let iid = string(value, &selectors.invocation_id)?;
    let pid = captured_pid(
        value
            .pointer(&selectors.pid)
            .context("captured launch PID missing")?,
    )?;
    ensure!(
        pid > 1 && digest(iid, 32),
        "captured launch IID/PID differs"
    );
    let native = properties(name).with_context(|| {
        format!("bound launch native properties: unit={name}, iid={iid}, pid={pid}")
    })?;
    let start = launch_start_ticks(&native, name, iid, pid, start_ticks)?;
    let owner = core::Owner {
        unit: name.into(),
        iid: iid.into(),
        pid,
        start_ticks: start,
        role: selected.role.clone(),
        first_epoch: selected.first_epoch,
        last_epoch: selected.last_epoch,
        restarts: 0,
        identity_stable: true,
        has_memory_accounting: true,
        guard_required: matches!(
            selected.role,
            core::Role::ReplayProducer
                | core::Role::ReplayController
                | core::Role::DiagnosticReplay
        ),
    };
    let qualified_successor = uploader183_owner::launch(value, &owner, &native)?;
    ensure!(
        pid > 1
            && digest(iid, 32)
            && native["InvocationID"] == iid
            && native["MainPID"].as_str() == Some(pid.to_string().as_str())
            && native["NRestarts"] == "0"
            && (native["Restart"] == "no" || qualified_successor)
            && native["ActiveState"] == "active"
            && native["SubState"] == "running"
            && native["MemoryAccounting"] == "yes",
        "bound launch event is not the exact live native invocation/PID"
    );
    retained141_launch_identity(value, name, iid, pid, start)?;
    ensure!(
        properties(name)? == native && start_ticks(pid)? == start,
        "launch owner changed during identity/start read"
    );
    Ok(owner)
}

fn native(s: &Spec, own: &str) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && digest(own, 64),
        "root sealed native admission required"
    );
    let executable = BoundFile {
        path: fs::read_link("/proc/self/exe")?,
        sha256: own.into(),
    };
    let size = sealed(&executable.path)?.len();
    immutable(&executable, size)?;
    let time = now()?;
    ensure!(
        s.native.not_before_unix_seconds <= time
            && time < s.native.expires_unix_seconds
            && s.native.expires_unix_seconds - s.native.not_before_unix_seconds <= 900
            && s.native.pid == u64::from(std::process::id())
            && start_ticks(s.native.pid)? == s.native.start_ticks
            && digest(&s.native.invocation_id, 32)
            && env::var("INVOCATION_ID")? == s.native.invocation_id,
        "admission native identity or finite execution window differs"
    );
    let value = properties(&s.native.unit)?;
    ensure!(
        value["InvocationID"] == s.native.invocation_id
            && value["MainPID"].as_str() == Some(s.native.pid.to_string().as_str())
            && value["NRestarts"] == "0"
            && value["Restart"] == "no"
            && value["ActiveState"] == "active"
            && value["SubState"] == "running"
            && matches!(value["User"].as_str(), Some("" | "root")),
        "native root service identity differs"
    );
    let cgroup = fs::read_to_string("/proc/self/cgroup")?;
    ensure!(
        cgroup
            .lines()
            .any(|l| l.strip_prefix("0::") == value["ControlGroup"].as_str()),
        "admission process is outside the declared native control group"
    );
    let command = string(&value, "/ExecStart")?;
    ensure!(
        command.contains(
            executable
                .path
                .to_str()
                .context("self executable path UTF-8")?
        ) && command.contains("admit-epoch186-current-census")
            && command.contains(own),
        "native ExecStart does not bind this exact admission executable/command"
    );
    Ok(value)
}

fn load(s: &Spec) -> Result<Bundle> {
    let q: Qualification = serde_json::from_value(read(&s.qualification_acceptance)?)?;
    Ok(Bundle {
        observer: read(&s.observer)?,
        fleet: read(&s.fleet)?,
        fleet_plan: read(&s.fleet_plan)?,
        completion: read(&s.completion)?,
        parent: read(&s.resource_parent)?,
        events: s
            .phase_events
            .iter()
            .map(|e| read(&e.source))
            .collect::<Result<_>>()?,
        reader: read(&s.reader191)?,
        transfer: read(&s.transfer191)?,
        correction: read(&s.correction191)?,
        closed185: read(&s.closed185)?,
        standing: read(&s.standing)?,
        floor: read(&s.floor)?,
        plan: read(&s.candidate_plan)?,
        package_seal: read(&s.package_seal)?,
        input: read(&s.input_capability)?,
        runtime: read(&q.runtime)?,
        resource: read(&q.resource)?,
        first_guard: read(&q.first_guard)?,
        candidate_guard_plan: read(&q.guard_plan)?,
        qualification: q,
    })
}

pub(super) fn absent(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "no-clobber path is occupied or unreadable"
    );
    Ok(())
}

fn dormant(b: &Bundle) -> Result<Value> {
    let name = string(&b.plan, "/unit")?;
    ensure!(
        name.starts_with("horizon-qualify-186-current-census-") && name.ends_with(".service"),
        "candidate unit is outside isolated epoch 186 namespace"
    );
    let value = properties(name)?;
    ensure!(
        value["MainPID"] == "0"
            && value["NRestarts"] == "0"
            && matches!(value["ActiveState"].as_str(), Some("inactive" | "failed"))
            && matches!(value["Restart"].as_str(), Some("no" | ""))
            && matches!(value["TriggeredBy"].as_str(), Some(""))
            && matches!(value["Triggers"].as_str(), Some("")),
        "candidate is live, restarting or triggered"
    );
    let root = Path::new(string(&b.plan, "/run_root")?);
    ensure!(
        root.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && root
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("epoch186-current-census-")),
        "candidate isolated run root differs"
    );
    absent(root)?;
    Ok(value)
}

pub(super) fn latest(s: &accounting::SpecView<'_>, b: &accounting::BundleView<'_>) -> Result<()> {
    latest_fleet(s.fleet, b.fleet)?;
    // No global phase registry exists. Bind all explicitly selected events and
    // forbid unaccounted live owners in the complete native census. No release
    // is inferred from an absent/terminal event or an unsearched directory.
    revalidate_phase_events(s.phase_events, b.events)
}

pub(super) fn latest_fleet(fleet: &BoundFile, value: &Value) -> Result<()> {
    ensure!(
        fleet.path.parent() == Some(Path::new(FLEET_ROOT)),
        "foreign complete fleet root"
    );
    let selected = (
        utc_seconds(string(value, "/sampled_at_utc")?)?,
        number(value, "/recorded_unix_seconds")?,
    );
    let mut count = 0usize;
    for item in fs::read_dir(FLEET_ROOT)? {
        count += 1;
        ensure!(count <= 65536, "fleet directory bound exceeded");
        let path = item?.path();
        if path == fleet.path || path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let bytes = read_stable_bounded(&path, 16 << 20, "epoch 186 fleet freshness")?;
        let value = unique_json(&bytes)?;
        if value["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && value["first_epoch"] == 101
            && value["last_epoch"] == 200
        {
            let other = (
                utc_seconds(string(&value, "/sampled_at_utc")?)?,
                number(&value, "/recorded_unix_seconds")?,
            );
            ensure!(
                other < selected,
                "newer or tied complete fleet supersedes admission basis"
            );
        }
    }
    Ok(())
}


/// Rehash the same explicit events, under the same exact policy as Loaded.
/// Split only to allow a bounded local root regression without a fleet/native scan.
pub(super) fn revalidate_phase_events(events: &[EventBinding], values: &[Value]) -> Result<()> {
    ensure!(
        events.len() == values.len(),
        "phase freshness event count differs"
    );
    for (event, value) in events.iter().zip(values) {
        ensure!(
            accounting::phase_event_source(&event.source)? == *value,
            "phase event changed during admission: {}",
            accounting::evidence_path(&event.source.path)
        );
    }
    Ok(())
}

type NativeCensus = (Vec<core::Owner>, BTreeMap<String, Value>, u64);
pub(super) fn completed_coordinator_basis(
    s: &accounting::SpecView<'_>,
    b: &accounting::BundleView<'_>,
    current: &BTreeMap<String, Value>,
) -> Result<Value> {
    let expected = b.fleet["unit_census"]
        .as_object()
        .context("complete accepted fleet census")?;
    completed_coordinator_basis_from_authenticated_comparison(s, b, current, expected)
}

/// The full accounting builder alone supplies its already authenticated narrow
/// live145 comparison. Every unrelated accepted row and membership stays exact.
pub(super) fn completed_coordinator_basis_from_authenticated_comparison(
    s: &accounting::SpecView<'_>,
    b: &accounting::BundleView<'_>,
    current: &BTreeMap<String, Value>,
    expected: &serde_json::Map<String, Value>,
) -> Result<Value> {
    let raw = b.fleet["unit_census"].as_object().context("raw accepted fleet census")?;
    ensure!(raw.keys().eq(expected.keys()), "authenticated145 comparison changes census membership");
    for (name, row) in raw {
        if !matches!(name.as_str(),
            "horizon-guard145-prefix-shared72h-20261107-v8g1.service" |
            "horizon-guard145-prefix-shared72h-20261107-v8g1.timer") {
            ensure!(expected[name] == *row, "authenticated145 comparison changes unrelated accepted row: {name}");
        }
    }
    let current = crate::completed_coordinator::accepted_subset(expected, current)?;
    // Compose independent enrolled guard changes as comparison views. Historical
    // completion receipts retain their own original fleet/plan/observer lineage.
    let before = expected
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let (comparison, epoch199) =
        current_census_composition::epoch199_view(s.guards, b.fleet, &before, &current)?;
    let plan: Plan = serde_json::from_value(b.fleet_plan.clone())?;
    current_census_composition::finish(
        epoch199,
        || {
            // The accepted current fleet was authenticated before this call.
            // Exact equality needs no historical coordinator transition and
            // must not manufacture service-only fields on either live timer.
            if comparison == before {
                return Ok(Value::Null);
            }
            ensure!(
                plan.diagnostics
                    .iter()
                    .any(super::super::cached145::namespace),
                "no current cached145 diagnostic rollover declared"
            );
            let proof =
                super::super::cached145_census_rollover::rollover(&plan, &before, &comparison)?;
            super::super::cached145_rollover_sources::authenticate(
                &json!({"cached145_guard_census_rollover":proof}),
            )?;
            Ok(proof)
        },
        || {
            crate::completed_coordinator::compare_census(
                &jetstreamer_horizon_observe::trial186::Bound {
                    path: s.completion.path.clone(),
                    sha256: s.completion.sha256.clone(),
                },
                b.completion,
                &jetstreamer_horizon_observe::trial186::Bound {
                    path: s.fleet.path.clone(),
                    sha256: s.fleet.sha256.clone(),
                },
                b.fleet,
                expected,
                &comparison,
            )
        },
    )
}
pub(super) fn observed(
    expected: &[core::Owner],
    names: &BTreeSet<String>,
    fleet: &Value,
) -> Result<NativeCensus> {
    observed_with_policy(expected, names, fleet, false)
}

/// Independent accounting observes the two existing historical controller
/// policies without changing them. Full candidate admission remains strict.
pub(super) fn observed_accounting(
    expected: &[core::Owner],
    names: &BTreeSet<String>,
    fleet: &Value,
) -> Result<NativeCensus> {
    observed_with_policy(expected, names, fleet, true)
}

fn normalized_command(value: &Value) -> Result<&str> {
    Ok(string(value, "/ExecStart")?
        .split_once(" ; ignore_errors=")
        .context("native command encoding differs")?
        .0)
}

fn historical_controller_policy(
    owner: &core::Owner,
    current: &Value,
    previous: Option<&Value>,
) -> bool {
    matches!(owner.role, core::Role::ReplayController)
        && matches!(
            (owner.unit.as_str(), owner.iid.as_str()),
            (
                "jetstreamer-epochs152-153-target3-controller-v1-r2.service",
                "4b6e30004fcf4d34a2d6b98568f3ab1a"
            ) | (
                "jetstreamer-epochs155-156-target3-controller-v1-r2.service",
                "5c0c6dc3faa14a6d8a639af8a1c76774"
            )
        )
        && current["Restart"] == "on-failure"
        && previous.is_some_and(|saved| {
            saved["Id"] == owner.unit
                && saved["InvocationID"] == owner.iid
                && saved["MainPID"].as_str() == Some(owner.pid.to_string().as_str())
                && saved["NRestarts"] == "0"
                && normalized_command(saved)
                    .ok()
                    .is_some_and(|command| normalized_command(current).ok() == Some(command))
        })
}

pub(super) fn validate_observed_owner(
    owner: &core::Owner,
    value: &Value,
    previous: Option<&Value>,
    actual_start_ticks: u64,
    accounting_only: bool,
) -> Result<()> {
    let qualified_successor =
        uploader183_owner::observed(owner, value, previous, actual_start_ticks)?;
    if owner.unit == super::super::direct163::first128::PARENT128 {
        super::super::direct163::first128::raw_profile(value)?;
    }
    if owner.unit == super::super::direct163::UNIT {
        super::super::direct163::raw_profile(value)?;
    }

    ensure!(
        value["Id"] == owner.unit
            && value["InvocationID"] == owner.iid
            && value["MainPID"].as_str() == Some(owner.pid.to_string().as_str())
            && owner.restarts == 0
            && value["NRestarts"] == "0"
            && value["ActiveState"] == "active"
            && value["SubState"] == "running"
            && value["MemoryAccounting"] == "yes"
            && (value["Restart"] == "no"
                || qualified_successor
                || (accounting_only && historical_controller_policy(owner, value, previous)))
            && actual_start_ticks == owner.start_ticks,
        "actual native owner differs: unit={} role={:?} expected_iid={} actual_iid={} expected_pid={} actual_pid={} expected_start_ticks={} actual_start_ticks={} restarts={} state={}/{} memory_accounting={} restart_policy={} accounting_only={}",
        owner.unit,
        owner.role,
        owner.iid,
        value["InvocationID"],
        owner.pid,
        value["MainPID"],
        owner.start_ticks,
        actual_start_ticks,
        value["NRestarts"],
        value["ActiveState"],
        value["SubState"],
        value["MemoryAccounting"],
        value["Restart"],
        accounting_only
    );
    if let Some(saved) = previous {
        ensure!(
            saved["InvocationID"] == owner.iid
                && normalized_command(saved)? == normalized_command(value)?,
            "native command or invocation differs from accepted fleet: unit={} expected_iid={} actual_iid={}",
            owner.unit,
            owner.iid,
            value["InvocationID"]
        );
    }
    Ok(())
}

fn observed_with_policy(
    expected: &[core::Owner],
    names: &BTreeSet<String>,
    fleet: &Value,
    accounting_only: bool,
) -> Result<NativeCensus> {
    let census = census(names, 101, 200)?;
    let mut result = Vec::new();
    let mut quota = 0u64;
    for owner in expected {
        let value = properties(&owner.unit)?;
        validate_observed_owner(
            owner,
            &value,
            fleet["unit_census"].get(&owner.unit),
            start_ticks(owner.pid).with_context(|| {
                format!(
                    "native start identity unreadable: unit={} pid={}",
                    owner.unit, owner.pid
                )
            })?,
            accounting_only,
        )?;
        if matches!(
            owner.role,
            core::Role::ReplayProducer | core::Role::DiagnosticReplay
        ) {
            let raw = string(&value, "/CPUQuotaPerSecUSec")?;
            let micros =
                unit_micros(raw).context("every replay cgroup needs its exact finite CPU quota")?;
            quota = quota
                .checked_add(micros)
                .context("complete replay CPU sum overflow")?;
        } else {
            // Existing policy reserves eight cores once for authenticated
            // lightweight controllers, repairs, delivery and park transport.
            let command = string(&value, "/ExecStart")?;
            ensure!(
                !command.contains("jetstreamer-node ")
                    && !command.contains("jetstreamer-historical-worker"),
                "unfamiliar compute payload cannot borrow the lightweight other-work reserve"
            );
            if string(&value, "/CPUQuotaPerSecUSec")? != "infinity" {
                ensure!(
                    unit_micros(string(&value, "/CPUQuotaPerSecUSec")?)? <= 8_000_000,
                    "non-replay owner exceeds existing other-work CPU reserve"
                );
            }
        }
        result.push(owner.clone());
    }
    // The shared discovery covers replay, diagnostic and publication namespaces.
    // Include cold transport namespaces as well.
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running,activating",
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16 << 20,
        "complete native discovery failed"
    );
    let units = unique_json(&out.stdout)?;
    for item in units.as_array().context("native discovery array")? {
        let name = string(item, "/unit")?;
        if !names.contains(name)
            && (name.starts_with("horizon-") || name.starts_with("jetstreamer-"))
        {
            let native = properties(name)?;
            let command = string(&native, "/ExecStart")?;
            let payload = [
                "jetstreamer-node",
                "jetstreamer-r2-progressive",
                "jetstreamer-r2 ",
                "jetstreamer-qualification-verify",
                "jetstreamer-historical-worker",
                "jetstreamer-horizon-import",
            ]
            .iter()
            .any(|part| command.contains(part));
            let named = [
                "horizon-cold-",
                "jetstreamer-cold-",
                "horizon-publish-",
                "horizon-upload-",
                "horizon-full-verify-",
                "horizon-plugin-verify-",
                "horizon-independent-full-read-",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix));
            ensure!(
                !payload && !named,
                "unbound active replay, diagnostic, repair or delivery owner"
            );
        }
    }
    Ok((result, census, quota))
}

/// Parse integer systemd display durations, including compound native values.
/// Preserve exact microsecond arithmetic and reject infinite or fractional caps.
pub(super) fn unit_micros(raw: &str) -> Result<u64> {
    super::super::charge136_retry0002::contract::native_duration_micros(raw)
        .context("native duration must be finite unsigned integer components")
}

pub(super) fn guards(
    s: &accounting::SpecView<'_>,
    expected: &[core::Owner],
    time: u64,
) -> Result<Vec<core::Guard>> {
    Ok(accounting_guards(s, expected, time)?.0)
}
/// The immutable native command digest already binds every token. Accept the
/// two real argparse encodings without changing their exact path values.
fn exact_guard_option(command: &str, option: &str, want: &Path) -> Result<()> {
    let (_, argv) = command
        .split_once(" ; argv[]=")
        .context("adaptive guard native argv framing")?;
    let tokens = argv.split_whitespace().collect::<Vec<_>>();
    let mut matches = Vec::new();
    let equals = format!("{option}=");
    for (index, token) in tokens.iter().enumerate() {
        if *token == option {
            matches.push(
                *tokens
                    .get(index + 1)
                    .context("adaptive guard option lacks value")?,
            );
        } else if let Some(value) = token.strip_prefix(&equals) {
            matches.push(value);
        }
    }
    ensure!(
        matches == [want.to_str().context("guard trip path UTF8")?],
        "adaptive guard trip path missing, changed or duplicated"
    );
    Ok(())
}
#[cfg(test)]
mod exact_adaptive_guard_path_tests {
    use super::*;
    #[test]
    fn actual_split_and_historical_equals_trip_paths_are_equivalent_and_exact() {
        for tail in [
            "--intent-receipt=/private/intent.json",
            "--intent-receipt /private/intent.json",
        ] {
            exact_guard_option(
                &format!(
                    "{{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /sealed/guard.py {tail}"
                ),
                "--intent-receipt",
                Path::new("/private/intent.json"),
            )
            .unwrap();
        }
        for tail in [
            "--intent-receipt /private/other.json",
            "--intent-receipt=/private/intent.json.sibling",
            "--intent-receipt /private/intent.json --intent-receipt=/private/intent.json",
            "--intent-receipt= --intent-receipt /private/intent.json",
            "--intent-receipt",
            "--completion-receipt=/private/intent.json",
        ] {
            assert!(
                exact_guard_option(
                    &format!(
                        "{{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /sealed/guard.py {tail}"
                    ),
                    "--intent-receipt",
                    Path::new("/private/intent.json")
                )
                .is_err(),
                "{tail}"
            );
        }
    }
}
pub(super) fn accounting_guards(
    s: &accounting::SpecView<'_>,
    expected: &[core::Owner],
    time: u64,
) -> Result<(Vec<core::Guard>, Vec<Value>)> {
    let mut result = Vec::new();
    let mut native_rows = Vec::new();
    for g in s.guards {
        let guard = guard_properties(&g.unit)?;
        let timer = properties(&g.timer)?;
        immutable(&g.binary, sealed(&g.binary.path)?.len())?;
        let command = string(&guard, "/ExecStart")?
            .split_once(" ; ignore_errors=")
            .context("guard command encoding differs")?
            .0;
        ensure!(
            hex_lower(&Sha256::digest(command.as_bytes())) == g.command_sha256
                && command.contains(g.binary.path.to_str().context("guard path UTF-8")?)
                && timer["ActiveState"] == "active"
                && timer["Unit"] == g.unit
                && guard["NRestarts"] == "0"
                && guard["Result"] == "success"
                && guard["ExecMainStatus"] == "0",
            "guard command, binary, timer or native outcome differs"
        );
        absent(&g.stop_intent)?;
        absent(&g.stop_completion)?;
        if matches!(g.kind, GuardKind::Epoch199Append) {
            let current_plan = read(s.fleet_plan)?;
            if let Some(selected) = current_plan
                .get(crate::fleet::ordinary199::TERMINAL_FIELD)
                .filter(|v| !v.is_null())
            {
                let binding = serde_json::from_value(selected.clone())?;
                let retained = epoch199_append::retained_snapshot(g, &guard, &binding)?;
                epoch199_append::validate_retained_snapshot(g, &retained)?;
                let iid = string(&guard, "/InvocationID")?.to_owned();
                native_rows.push(json!({"unit":g.unit,"native":guard,"timer":timer,
                    "retained_terminal_199":true,"terminal_guard_snapshot":retained}));
                result.push(core::Guard {
                    unit: g.unit.clone(),
                    iid,
                    protected_owners: Vec::new(),
                    minimum_free_bytes: 4_202_184_371_152,
                    currently_armed: false,
                    retained_terminal_152: false,
                    retained_terminal_199: true,
                    no_trip: true,
                    command_and_binary_bound: true,
                    receipt_fresh: true,
                });
                continue;
            }
        }
        let mut retained_terminal_152 = false;
        let mut cached145_proof = None;
        let mut epoch199_proof = None;
        let mut recovery199_proof = None;
        let (sample, guard_iid) = match g.kind {
            GuardKind::AdaptiveController => {
                ensure!(
                    g.plan.is_none() && g.sample.is_none(),
                    "adaptive guard uses current authenticated journal, not a fabricated static sample"
                );
                exact_guard_option(command, "--intent-receipt", &g.stop_intent)?;
                exact_guard_option(command, "--completion-receipt", &g.stop_completion)?;
                let out = ProcessCommand::new("/usr/bin/journalctl")
                    .args([
                        "--unit",
                        &g.unit,
                        "--output=json",
                        "--no-pager",
                        "--lines=24",
                    ])
                    .output()?;
                ensure!(
                    out.status.success() && out.stdout.len() <= 1 << 20,
                    "adaptive guard journal failed"
                );
                let mut selected = None;
                for line in std::str::from_utf8(&out.stdout)?.lines().rev() {
                    let entry = unique_json(line.as_bytes())?;
                    if entry["_SYSTEMD_UNIT"] == g.unit
                        && entry["MESSAGE"]
                            .as_str()
                            .is_some_and(|m| m.starts_with('{'))
                    {
                        let payload = unique_json(string(&entry, "/MESSAGE")?.as_bytes())?;
                        selected = Some(
                            if g.unit == core::TERMINAL_152_GUARD_UNIT && payload["armed"] == false
                            {
                                let verified =
                                    terminal152_guard::sample(&entry, g, &guard, time, expected)?;
                                retained_terminal_152 = true;
                                verified
                            } else {
                                adaptive_guard_sample(&entry, g, &guard, time)?
                            },
                        );
                        break;
                    }
                }
                selected.context("fresh adaptive guard journal sample missing")?
            }
            GuardKind::Epoch199Http500Append => {
                use crate::fleet::recovery199_contract as r;
                let plan = read(s.fleet_plan)?;
                let p =
                    r::load_plan(&plan)?.context("recovery199 guard lacks exact enrolled owner")?;
                ensure!(
                    p.terminal.is_none()
                        && g.unit == r::GUARD
                        && g.timer == r::TIMER
                        && g.plan
                            .as_ref()
                            .is_some_and(|b| json!(b) == json!(p.binding))
                        && g.sample.is_none()
                        && g.binary.path
                            == Path::new(
                                "/usr/local/lib/jetstreamer/horizon-epoch199-backfill-controller-guard-20261102-v1/guard_adaptive_replay_reserve.py"
                            )
                        && g.binary.sha256
                            == "b62e58f5be764935a679408e1fcc446a9768170109a6639c87fd01571b9f2b62",
                    "recovery199 guard declaration changes authority/source or claims armed terminal guard"
                );
                ensure!(
                    g.stop_intent
                        == Path::new(
                            "/var/lib/jetstreamer/epoch199-http500-recovery-20261105-v1/guard/reserve-stop-intent.json"
                        )
                        && g.stop_completion
                            == Path::new(
                                "/var/lib/jetstreamer/epoch199-http500-recovery-20261105-v1/guard/reserve-stop-completion.json"
                            ),
                    "recovery199 guard stop scope changed"
                );
                let proof = r::guard::capture(&p, now()?)?;
                ensure!(
                    proof["full_family"][r::GUARD]["InvocationID"] == guard["InvocationID"],
                    "recovery199 guard capture crossed invocation"
                );
                let sample = proof["log"]["payload"].clone();
                let iid = string(&guard, "/InvocationID")?.to_owned();
                recovery199_proof = Some(proof);
                (sample, iid)
            }
            GuardKind::Epoch199Append => {
                // Bind freshness to dispatch after this exact guard was observed,
                // rather than the earlier clock for the whole guard batch.
                let (sample, iid, proof) = epoch199_append::load(g, &guard, expected, now()?)?;
                epoch199_proof = Some(proof);
                (sample, iid)
            }
            GuardKind::Cached145Continuous => {
                let (sample, iid, proof) = cached145_continuous::load(g, &guard, expected, time)?;
                cached145_proof = Some(proof);
                (sample, iid)
            }
            GuardKind::Standalone => {
                let binding = g.plan.as_ref().context("standalone guard plan missing")?;
                let plan = read(binding)?;
                let mut sample = read(
                    g.sample
                        .as_ref()
                        .context("standalone guard sample missing")?,
                )?;
                let at = number(&sample, "/recorded_unix_seconds")?;
                ensure!(
                    at <= time
                        && time - at <= 180
                        && sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                        && sample["guard_sha256"] == g.binary.sha256
                        && sample["plan_sha256"] == binding.sha256
                        && sample["guard_invocation_id"] == guard["InvocationID"]
                        && sample["producer_invocation_id"] == plan["invocation_id"]
                        && sample["producer"]["cgroup"]
                            == format!("/system.slice/{}", string(&plan, "/unit")?)
                        && sample["minimum_free_bytes"] == plan["minimum_free_bytes"]
                        && sample["trip_reason"].is_null()
                        && sample["worker_observation_error"].is_null(),
                    "standalone guard first-fire/plan/native identity differs"
                );
                // The actual standalone Unit shape records a cgroup, not a
                // unit-name field. Derive the unit only after matching that
                // cgroup and the invocation-bound immutable plan.
                sample["producer"]["unit"] = plan["unit"].clone();
                (sample, string(&guard, "/InvocationID")?.to_owned())
            }
        };
        let mut protected = Vec::new();
        for role in ["producer", "controller"] {
            if retained_terminal_152 {
                continue;
            }
            let Some(native) = sample.get(role) else {
                continue;
            };
            let name = string(native, "/unit")?;
            let iid = string(native, "/invocation_id")?;
            let owner = expected
                .iter()
                .find(|o| o.unit == name && o.iid == iid)
                .context("guard protects foreign owner")?;
            ensure!(
                native["restarts"] == 0
                    && (native["active_state"] == "active" || native["active"] == "active")
                    && (native["sub_state"] == "running" || native["sub"] == "running"),
                "guard-protected owner is not stable and running"
            );
            protected.push((owner.unit.clone(), owner.iid.clone()));
        }
        let floor = number(&sample, "/minimum_free_bytes")?;
        ensure!(
            floor > 0 && number(&sample, "/available_bytes")? >= floor,
            "protected guard floor breached"
        );
        let mut native_row = json!({"unit":g.unit,"native":guard,"timer":timer});
        if let Some(proof) = cached145_proof {
            native_row["cached145_continuity"] = proof;
        }
        if let Some(proof) = recovery199_proof {
            native_row["epoch199_http500_append_continuity"] = proof;
        }
        if let Some(proof) = epoch199_proof {
            native_row["epoch199_append_continuity"] = proof;
        }
        if retained_terminal_152 {
            native_row["retained_terminal_152"] = json!(true);
            native_row["terminal_guard_sample"] = sample.clone();
        }
        native_rows.push(native_row);
        result.push(core::Guard {
            unit: g.unit.clone(),
            iid: guard_iid,
            protected_owners: protected,
            minimum_free_bytes: floor,
            currently_armed: !retained_terminal_152,
            retained_terminal_152,
            retained_terminal_199: false,
            no_trip: true,
            command_and_binary_bound: true,
            receipt_fresh: true,
        });
    }
    Ok((result, native_rows))
}

pub(super) fn adaptive_guard_sample(
    entry: &Value,
    g: &GuardSpec,
    guard: &Value,
    time: u64,
) -> Result<(Value, String)> {
    ensure!(
        entry["_SYSTEMD_UNIT"] == g.unit,
        "adaptive guard sample unit differs"
    );
    ensure!(
        entry["_UID"] == "0",
        "adaptive guard journal custody differs"
    );
    let at = string(entry, "/__REALTIME_TIMESTAMP")?.parse::<u64>()? / 1_000_000;
    ensure!(
        at <= time && time - at <= 180,
        "adaptive guard fire is stale or future"
    );
    let iid = string(entry, "/_SYSTEMD_INVOCATION_ID")?.to_owned();
    ensure!(
        digest(&iid, 32) && guard["InvocationID"] == iid,
        "adaptive guard native invocation differs"
    );
    let sample = unique_json(string(entry, "/MESSAGE")?.as_bytes())?;
    ensure!(
        sample["armed"] == true
            && sample["trip"] == false
            && sample["maximum_worker_vmas"] == 800_000
            && sample["producer"]["worker_count"] == 1
            && sample["producer"]["worker_vmas"]
                .as_u64()
                .is_some_and(|v| v > 0 && v < 800_000),
        "adaptive guard is unarmed, tripped or outside worker envelope"
    );
    Ok((sample, iid))
}

fn inputs(s: &Spec, b: &Bundle) -> Result<()> {
    let required = [
        "node",
        "worker",
        "snapshot",
        "genesis",
        "checkpoints",
        "ledger-fingerprint",
    ];
    let roles = s
        .immutable_inputs
        .iter()
        .map(|i| i.role.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        roles == BTreeSet::from(required) && roles.len() == s.immutable_inputs.len(),
        "immutable input list missing a role or contains duplicates"
    );
    ensure!(
        b.package_seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && b.plan["package_seal"] == binding(&s.package_seal),
        "exact immutable deployment seal differs"
    );
    let members = b.package_seal["members"]
        .as_array()
        .context("sealed deployment members")?;
    let package = Path::new(string(&b.package_seal, "/destination")?);
    for input in &s.immutable_inputs {
        immutable(&input.file, input.bytes)?;
        read_only_mount(&input.file.path)?;
        let key = match input.role.as_str() {
            "node" => "node",
            "worker" => "worker",
            "snapshot" => "snapshot",
            "genesis" => "genesis",
            "checkpoints" => "checkpoints",
            "ledger-fingerprint" => "ledger_fingerprint",
            _ => anyhow::bail!("unknown immutable input role"),
        };
        ensure!(
            b.plan["immutable_inputs"][key] == binding(&input.file),
            "candidate input binding differs"
        );
        if input.role != "ledger-fingerprint" {
            let name = input
                .file
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .context("input basename")?;
            ensure!(
                input.file.path.parent() == Some(package)
                    && members
                        .iter()
                        .filter(|m| m["name"] == name
                            && m["sha256"] == input.file.sha256
                            && m["bytes"] == input.bytes)
                        .count()
                        == 1,
                "input is outside exact sealed package membership"
            );
        }
        let pinned = match input.role.as_str() {
            "node" => Some(NODE),
            "worker" => Some(WORKER),
            "snapshot" => Some(SNAPSHOT),
            "genesis" => Some("133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"),
            "checkpoints" => {
                Some("71df68fa46e108d9a9ae905654796ca73255a058e662578accb1695ea44932c4")
            }
            "ledger-fingerprint" => Some(b.qualification.ledger_fingerprint_sha256.as_str()),
            _ => None,
        };
        ensure!(
            pinned.is_none_or(|sha| input.file.sha256 == sha),
            "immutable input belongs to another package"
        );
    }
    immutable(
        &b.qualification.qualification_binary,
        sealed(&b.qualification.qualification_binary.path)?.len(),
    )?;
    immutable(
        &b.qualification.guard_binary,
        sealed(&b.qualification.guard_binary.path)?.len(),
    )?;
    let guard_native = properties(&b.qualification.guard_unit)?;
    ensure!(
        guard_native["InvocationID"] == b.first_guard["guard_invocation_id"]
            && guard_native["MainPID"] == "0"
            && guard_native["NRestarts"] == "0"
            && guard_native["Result"] == "success"
            && guard_native["ExecMainStatus"] == "0",
        "first-fire capability does not retain exact successful native guard invocation"
    );
    let guard_command = string(&guard_native, "/ExecStart")?;
    ensure!(
        guard_command.contains(
            b.qualification
                .guard_binary
                .path
                .to_str()
                .context("guard executable path UTF-8")?
        ) && guard_command.contains(&b.qualification.guard_binary.sha256)
            && guard_command.contains(&b.qualification.guard_plan.sha256),
        "first-fire native command does not bind exact guard binary/plan"
    );
    let terminal = properties(&b.qualification.qualification_unit)?;
    ensure!(
        terminal["InvocationID"] == b.qualification.qualification_invocation_id
            && terminal["MainPID"] == "0"
            && terminal["NRestarts"] == "0"
            && terminal["Restart"] == "no"
            && terminal["Result"] == "success"
            && terminal["ExecMainStatus"] == "0"
            && terminal["SubState"] == "exited",
        "exact current-worker qualification lacks retained native terminal success"
    );
    let command = string(&terminal, "/ExecStart")?;
    ensure!(
        b.qualification
            .qualification_unit
            .starts_with("horizon-qualify-186-current-worker-capability-")
            && command.contains(
                b.qualification
                    .qualification_binary
                    .path
                    .to_str()
                    .context("qualification executable path UTF-8")?
            )
            && command.contains(&b.qualification.qualification_binary.sha256),
        "native terminal success does not authenticate the distinct qualification executable"
    );
    Ok(())
}

fn output(path: &Path) -> Result<()> {
    ensure!(
        path.parent() == Some(Path::new(OUTPUT_ROOT))
            && path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n
                .starts_with("admission-")
                && n.ends_with(".json")
                && n.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))),
        "admission receipt is outside private no-clobber namespace"
    );
    let parent = Path::new(OUTPUT_ROOT);
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0,
        "admission output parent is not private root custody"
    );
    absent(path)
}

fn receipt(path: &Path, value: &Value) -> Result<()> {
    output(path)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(&bytes)?;
    f.write_all(b"\n")?;
    f.set_permissions(fs::Permissions::from_mode(0o400))?;
    f.sync_all()?;
    File::open(path.parent().context("receipt parent")?)?.sync_all()?;
    Ok(())
}

pub(super) async fn admit() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    let check = args.len() == 8 && args[7] == "--check-only";
    ensure!(
        (args.len() == 7 || check) && args[3] == "--spec-sha256" && args[5] == "--self-sha256",
        "usage: admit-epoch186-current-census SPEC --spec-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    let bound = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let spec: Spec = serde_json::from_value(read(&bound)?)?;
    ensure!(
        spec.schema == "jetstreamer-epoch186-current-census-admission-spec-v2",
        "epoch 186 admission spec schema differs"
    );
    let native_before = native(&spec, &args[6])?;
    let bundle = load(&spec)?;
    let accounting_spec = accounting::SpecView::from(&spec);
    let accounting_bundle = accounting::BundleView::from(&bundle);
    let sample = evidence::accepted(&spec, &bundle, now()?)?;
    latest(&accounting_spec, &accounting_bundle)?;
    let expected = evidence::owners(&spec, &bundle)?;
    let candidate = evidence::candidate(&spec, &bundle)?;
    evidence::pressure_and_progress(&bundle)?;
    inputs(&spec, &bundle)?;
    output(&spec.output)?;
    let candidate_before = dormant(&bundle)?;
    let mut names = bundle.fleet["unit_census"]
        .as_object()
        .context("complete fleet manager census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.extend(expected.iter().map(|o| o.unit.clone()));
    names.insert(candidate.unit.clone());
    names.insert(spec.native.unit.clone());
    names.extend(spec.guards.iter().map(|g| g.unit.clone()));
    let (before, census_before, cpu_before) = observed(&expected, &names, &bundle.fleet)?;
    let coordinator_before =
        completed_coordinator_basis(&accounting_spec, &accounting_bundle, &census_before)?;
    let guard_before = guards(&accounting_spec, &expected, now()?)?;
    let floor = snapshot144::floor(&bundle.floor)?;
    let (rows, dispositions) = evidence::obligations(&spec, &bundle, floor)?;
    let r2 = r2_config_from_env()?;
    ensure!(
        r2.bucket == "solana-archive-with-accounts-data",
        "foreign authenticated inventory"
    );
    let client = s3_client(&r2);
    let mut floor_proof_bindings = Vec::new();
    for proof in bundle.floor["samples"]
        .as_array()
        .context("floor samples")?
    {
        for (path, sha) in [
            ("r2_receipt", "r2_receipt_sha256"),
            (
                "private_resource_verification",
                "private_resource_verification_sha256",
            ),
        ] {
            let binding = BoundFile {
                path: string(proof, &format!("/{path}"))?.into(),
                sha256: string(proof, &format!("/{sha}"))?.into(),
            };
            read(&binding)?;
            floor_proof_bindings.push(super::binding(&binding));
        }
    }
    let floor_inventory =
        assembly144_admission::remote_floor_inventory(&client, &r2, &bundle.floor).await?;
    let candidate_inventory = inventory_epoch(&client, &r2, 186).await?;
    ensure!(
        candidate_inventory.state == InventoryState::Missing,
        "epoch 186 has remote archive/status readiness; reconcile existing work first"
    );
    let live = bundle.observer["replays"]
        .as_array()
        .context("replay lanes")?
        .len();
    let private = expected
        .iter()
        .filter(|o| matches!(o.role, core::Role::DiagnosticReplay))
        .count();
    let memory = jetstreamer_horizon_observe::routine_memory_target::report_for_century(
        &bundle.observer,
        live,
        private,
        100,
    );
    ensure!(
        memory["valid"] == true,
        "complete host resident memory calculation failed"
    );
    let (after, census_after, cpu_after) = observed(&expected, &names, &bundle.fleet)?;
    let coordinator_after =
        completed_coordinator_basis(&accounting_spec, &accounting_bundle, &census_after)?;
    ensure!(
        census_before == census_after,
        "complete native census changed across epoch 186 admission"
    );
    ensure!(
        cpu_before == cpu_after,
        "active CPU contracts changed during admission"
    );
    let actual_free = snapshot144::free_bytes()?;
    let (host_total, available_memory) = live_memory()?;
    ensure!(
        host_total == number(&memory, "/host_total_bytes")?
            && fs::read_to_string("/proc/sys/vm/max_map_count")?
                .trim()
                .parse::<u64>()?
                >= 4_194_304,
        "live host memory or VMA capability changed"
    );
    let mut affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut affinity)
        } == 0,
        "CPU affinity observation failed"
    );
    let cpus = u64::try_from(unsafe { libc::CPU_COUNT(&affinity) })?;
    let expanded = if let Some(binding) = &spec.expanded_point {
        let proof = read(binding)?;
        ensure!(
            proof["schema"] == "jetstreamer-epoch186-expanded-point-acceptance-v2"
                && proof["observer"] == binding_value(&spec.observer)
                && proof["fleet"] == binding_value(&spec.fleet)
                && number(&proof, "/proven_lanes")?
                    > expected
                        .iter()
                        .filter(|o| matches!(
                            o.role,
                            core::Role::ReplayProducer | core::Role::DiagnosticReplay
                        ))
                        .count() as u64,
            "expanded-point proof does not bind this clean complete sample"
        );
        true
    } else {
        false
    };
    let model = core::Model {
        first_epoch: 101,
        last_epoch: 200,
        expected: expected.clone(),
        observed_before: before,
        observed_after: after,
        exact_inherited_guard_maximum: guard_before
            .iter()
            .map(|g| g.minimum_free_bytes)
            .max()
            .context("guard maximum missing")?,
        guards: guard_before,
        obligation_rows: rows,
        dispositions,
        confirmed_data_floor_bytes: DATA_FLOOR,
        latest_verified_century_floor_bytes: floor,
        century_maximum_observed_lane_rss_bytes: number(
            &memory,
            "/century_maximum_observed_lane_rss_bytes",
        )?,
        scheduling_reservation_bytes: number(&memory, "/reservation_ceiling_bytes")?,
        other_retained_memory_reservations_bytes: number(
            &bundle.reader,
            "/delivery_budget/memory_envelope_bytes",
        )?
        .checked_sub(core::NATIVE_POOL)
        .context("shared compiler pool absent from retained delivery promise")?,
        desired_memory_target_lanes: number(&memory, "/desired_lanes")?,
        host_total_memory_bytes: host_total,
        host_resident_planning_bytes: number(&memory, "/host_resident_planning_bytes")?,
        target_percent: 90,
        reserved_native_pool_bytes: core::NATIVE_POOL,
        park_suballocation_bytes: core::PARK_SUBALLOCATION,
        sampled_free_bytes: number(&bundle.observer, "/filesystem/conservative_available_bytes")?,
        actual_free_bytes: actual_free,
        available_logical_cpus: cpus,
        current_quota_micros: cpu_after,
        reserved_other_cpu_micros: 8_000_000,
        all_growth_obligations_complete: true,
        complete_owner_and_guard_census: true,
        all_pressure_counters_clean: true,
        replay_progress_sufficient: true,
        observer_fleet_frame_and_events_fresh: true,
        no_newer_fleet_or_event: true,
        latest_century_floor_authenticated: true,
        candidate_namespace_dormant: true,
        proven_operating_point_lanes: 5,
        expanded_point_qualified: expanded,
        candidate,
    };
    let decision = core::evaluate(&model)?;
    ensure!(
        decision.math_fit,
        "epoch 186 disk/memory/CPU envelope does not fit"
    );
    // Repeat the same finite transaction's owner/guard/latest/dormancy/resource
    // checks. This is admission, not another autonomous replay observer cadence.
    let final_guards = guards(&accounting_spec, &expected, now()?)?;
    ensure!(
        serde_json::to_value(&final_guards)? == serde_json::to_value(&model.guards)?,
        "guard invocation/floor/coverage changed during admission"
    );
    latest(&accounting_spec, &accounting_bundle)?;
    evidence::accepted(&spec, &bundle, now()?)?;
    ensure!(
        dormant(&bundle)? == candidate_before && native(&spec, &args[6])? == native_before,
        "candidate or admission native owner changed before receipt"
    );
    ensure!(
        snapshot144::free_bytes()? >= decision.required_initial_free_bytes,
        "free disk fell below exact required floor before receipt"
    );
    let (final_owners, final_census, final_cpu) = observed(&expected, &names, &bundle.fleet)?;
    let coordinator_final =
        completed_coordinator_basis(&accounting_spec, &accounting_bundle, &final_census)?;
    ensure!(
        census_after == final_census,
        "complete native census changed immediately before epoch 186 receipt"
    );
    ensure!(
        final_owners == model.observed_after && final_cpu == cpu_after,
        "complete native owner census changed immediately before receipt"
    );
    let (final_total, final_available) = live_memory()?;
    let memory_promises = decision
        .scheduling_reservation_bytes
        .checked_add(core::NATIVE_POOL)
        .and_then(|n| n.checked_add(model.other_retained_memory_reservations_bytes))
        .context("memory promises overflow")?;
    ensure!(
        final_total == host_total
            && available_memory >= memory_promises
            && final_available >= memory_promises,
        "live available memory lacks scheduling/pool reservation"
    );
    if check {
        println!(
            "epoch 186 admission checks passed; native and authenticated read-only checks, no receipt or launch"
        );
        return Ok(());
    }
    let value = json!({"schema":"jetstreamer-epoch186-current-census-admission-v2","admitted":true,
        "spec":binding(&bound),"self_sha256":args[6],"native_before":native_before,
        "observer":binding(&spec.observer),"fleet":binding(&spec.fleet),"fleet_plan":binding(&spec.fleet_plan),
        "completion":binding(&spec.completion),"resource_parent":binding(&spec.resource_parent),
        "phase_events":spec.phase_events.iter().map(|e| binding(&e.source)).collect::<Vec<_>>(),
        "candidate_plan":binding(&spec.candidate_plan),"qualification_acceptance":binding(&spec.qualification_acceptance),
        "package_seal":binding(&spec.package_seal),
        "runtime_capability":binding(&bundle.qualification.runtime),"resource_capability":binding(&bundle.qualification.resource),
        "first_guard":binding(&bundle.qualification.first_guard),"input_capability":binding(&spec.input_capability),
        "floor":binding(&spec.floor),"floor_proof_bindings":floor_proof_bindings,
        "authenticated_floor_inventory":floor_inventory,"authenticated_candidate_inventory":candidate_inventory,
        "correction191":binding(&spec.correction191),
        "complete_model":model,"decision":decision,"census_before":census_before,"census_after":census_after,"final_census":final_census,
        "completed_coordinator_before":coordinator_before,"completed_coordinator_after":coordinator_after,
        "completed_coordinator_final":coordinator_final,
        "sample_unix_seconds":sample,"recorded_unix_seconds":now()?,"expires_unix_seconds":spec.native.expires_unix_seconds,
        "full_cold_epoch_peak_qualified":false,"ordinary_replay_claim":false,"canonical_sidecar_authorized":false,
        "publication_authorized":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
    receipt(&spec.output, &value)?;
    println!("private epoch 186 admission written; separate exact launch remains required");
    Ok(())
}

fn binding_value(value: &BoundFile) -> Value {
    binding(value)
}

pub(super) fn live_memory() -> Result<(u64, u64)> {
    let text = fs::read_to_string("/proc/meminfo")?;
    ensure!(text.len() <= 65536, "live memory output bound exceeded");
    let bytes = |key: &str| -> Result<u64> {
        text.lines()
            .find_map(|l| {
                l.strip_prefix(key)
                    .and_then(|s| s.split_whitespace().next())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .context("live memory field missing")?
            .checked_mul(1024)
            .context("live memory overflow")
    };
    Ok((bytes("MemTotal:")?, bytes("MemAvailable:")?))
}

#[cfg(test)]
mod custody_tests {
    use super::*;

    #[test]
    fn claimed_root_custody_does_not_replace_actual_filesystem_checks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fabricated.json");
        let bytes = br#"{"uid":0,"singly_linked":true,"immutable":true,"qualified":true}"#;
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        // Even when the test itself is root, a writable evidence parent cannot
        // turn claimed JSON custody into accepted filesystem custody.
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let binding = BoundFile {
            path,
            sha256: hex_lower(&Sha256::digest(bytes)),
        };
        assert!(read(&binding).is_err());
    }

    #[test]
    fn no_follow_reader_rejects_symlink_even_with_matching_digest() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.json");
        let link = directory.path().join("alias.json");
        fs::write(&source, b"{}").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o444)).unwrap();
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(
            read(&BoundFile {
                path: link,
                sha256: hex_lower(&Sha256::digest(b"{}"))
            })
            .is_err()
        );
    }
}

#[cfg(test)]
mod captured_launch_tests {
    use super::*;
    #[test]
    fn captured_native_pid_accepts_only_canonical_positive_process_ids() {
        assert_eq!(captured_pid(&json!(1391716)).unwrap(), 1391716);
        assert_eq!(captured_pid(&json!("1391716")).unwrap(), 1391716);
        for raw in [
            json!("01391716"),
            json!("+1391716"),
            json!(" 1391716"),
            json!("1391716 "),
            json!("-1"),
            json!("0"),
            json!(1),
            json!(0),
            json!(1.5),
            json!(true),
            json!(null),
            json!("18446744073709551616"),
        ] {
            assert!(captured_pid(&raw).is_err());
        }
    }
    #[test]
    fn real_retained_repair_shape_requires_both_manager_and_recorded_start_identity() {
        let unit = "horizon-repair-141-floor-20261024-v1.service";
        let iid = "a".repeat(32);
        let good = json!({"schema":"jetstreamer-epoch141-repair-owner-capture-v2","epoch":141,"unit":unit,
            "invocation_id":iid,"process_start_ticks":114864592,
            "manager":{"Id":unit,"InvocationID":iid,"MainPID":"1391716","ActiveState":"active","SubState":"running",
                "NRestarts":"0","ControlGroup":format!("/system.slice/{unit}")},
            "ordinary_replay_claim":false,"publication_authorized":false,"r2_mutations":false,"replay_launch_authorized":false});
        retained141_launch_identity(&good, unit, &iid, 1391716, 114864592).unwrap();
        for (pointer, value) in [
            ("/manager/MainPID", json!("1391717")),
            ("/process_start_ticks", json!(114864593)),
            ("/manager/InvocationID", json!("b".repeat(32))),
            ("/unit", json!("foreign.service")),
            ("/replay_launch_authorized", json!(true)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(retained141_launch_identity(&bad, unit, &iid, 1391716, 114864592).is_err());
        }
        assert!(retained141_launch_identity(&good, unit, &iid, 1391717, 114864592).is_err());
        assert!(retained141_launch_identity(&good, unit, &iid, 1391716, 114864593).is_err());
    }
}

#[cfg(test)]
mod accounting_controller_policy_tests {
    use super::*;

    fn fixture(epoch: u64) -> (core::Owner, Value, Value) {
        let (unit, iid) = match epoch {
            152 => (
                "jetstreamer-epochs152-153-target3-controller-v1-r2.service",
                "4b6e30004fcf4d34a2d6b98568f3ab1a",
            ),
            155 => (
                "jetstreamer-epochs155-156-target3-controller-v1-r2.service",
                "5c0c6dc3faa14a6d8a639af8a1c76774",
            ),
            _ => unreachable!(),
        };
        let owner = core::Owner {
            unit: unit.into(),
            iid: iid.into(),
            pid: 42,
            start_ticks: 123,
            role: core::Role::ReplayController,
            first_epoch: epoch,
            last_epoch: epoch + 1,
            restarts: 0,
            identity_stable: true,
            guard_required: true,
            has_memory_accounting: true,
        };
        let native = json!({"Id":unit,"InvocationID":iid,"MainPID":"42","NRestarts":"0",
            "ActiveState":"active","SubState":"running","MemoryAccounting":"yes",
            "Restart":"on-failure","ExecStart":"{ path=/sealed/controller ; argv[]=/sealed/controller --bound-plan ; ignore_errors=no ; pid=42 }"});
        (owner, native.clone(), native)
    }

    #[test]
    fn only_accounting_accepts_both_exact_existing_controller_policies() {
        for epoch in [152, 155] {
            let (owner, current, saved) = fixture(epoch);
            assert!(validate_observed_owner(&owner, &current, Some(&saved), 123, true).is_ok());
            assert!(validate_observed_owner(&owner, &current, Some(&saved), 123, false).is_err());
            let mut strict = current.clone();
            strict["Restart"] = json!("no");
            assert!(validate_observed_owner(&owner, &strict, Some(&saved), 123, false).is_ok());
        }
    }

    #[test]
    fn historical_policy_requires_same_accepted_owner_command_and_zero_restarts() {
        for epoch in [152, 155] {
            let (owner, current, saved) = fixture(epoch);
            assert!(validate_observed_owner(&owner, &current, None, 123, true).is_err());
            assert!(validate_observed_owner(&owner, &current, Some(&saved), 124, true).is_err());
            for (key, value) in [
                ("Id", json!("foreign.service")),
                ("InvocationID", json!("a".repeat(32))),
                ("MainPID", json!("43")),
                ("NRestarts", json!("1")),
                ("ActiveState", json!("activating")),
                ("SubState", json!("auto-restart")),
                ("MemoryAccounting", json!("no")),
                ("Restart", json!("always")),
                (
                    "ExecStart",
                    json!("{ path=/foreign ; argv[]=/foreign ; ignore_errors=no }"),
                ),
            ] {
                let mut bad = current.clone();
                bad[key] = value;
                assert!(
                    validate_observed_owner(&owner, &bad, Some(&saved), 123, true).is_err(),
                    "{key}"
                );
            }
            for key in ["Id", "InvocationID", "MainPID", "NRestarts", "ExecStart"] {
                let mut bad = saved.clone();
                bad[key] = json!("foreign");
                assert!(
                    validate_observed_owner(&owner, &current, Some(&bad), 123, true).is_err(),
                    "saved {key}"
                );
            }
            for role in [
                core::Role::ReplayProducer,
                core::Role::Repair,
                core::Role::Delivery,
                core::Role::NativePark,
                core::Role::DiagnosticReplay,
            ] {
                let mut bad = owner.clone();
                bad.role = role;
                assert!(validate_observed_owner(&bad, &current, Some(&saved), 123, true).is_err());
            }
            let mut bad = owner.clone();
            bad.restarts = 1;
            assert!(validate_observed_owner(&bad, &current, Some(&saved), 123, true).is_err());
            let mut bad = owner.clone();
            bad.iid = "b".repeat(32);
            let mut replacement = current.clone();
            replacement["InvocationID"] = json!(bad.iid);
            assert!(
                validate_observed_owner(&bad, &replacement, Some(&replacement), 123, true).is_err()
            );
            let mut bad = owner.clone();
            bad.unit =
                "jetstreamer-epochs183-184-readerfix-full-20261023-controller-v2-r2.service".into();
            let mut foreign = current.clone();
            foreign["Id"] = json!(bad.unit);
            assert!(validate_observed_owner(&bad, &foreign, Some(&foreign), 123, true).is_err());
        }
    }

    #[test]
    fn failure_details_identify_owner_policy_without_exposing_commands() {
        let (owner, current, saved) = fixture(152);
        let error = validate_observed_owner(&owner, &current, Some(&saved), 123, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains(&owner.unit));
        assert!(error.contains(&owner.iid));
        assert!(error.contains("on-failure"));
        assert!(!error.contains("--bound-plan"));
    }
}

#[cfg(test)]
mod native_duration_display_regression {
    use super::unit_micros;

    #[test]
    fn actual_retry0002_admission_runtime_display_keeps_its_exact_budget() {
        // PID 1 reports RuntimeMaxSec=150 as the compound value below.
        assert_eq!(unit_micros("2min 30s").unwrap(), 150_000_000);
        assert_eq!(unit_micros("1min 30s").unwrap(), 90_000_000);
        assert_eq!(unit_micros("6h 2min").unwrap(), 21_720_000_000);
    }

    #[test]
    fn existing_scalar_native_durations_keep_their_exact_values() {
        for (raw, expected) in [
            ("1us", 1),
            ("10ms", 10_000),
            ("1s", 1_000_000),
            ("5min", 300_000_000),
            ("1h", 3_600_000_000),
            ("0s", 0),
        ] {
            assert_eq!(unit_micros(raw).unwrap(), expected, "{raw}");
        }
    }

    #[test]
    fn compound_runtime_cannot_hide_seconds_above_the_accounting_ceiling() {
        let accounting_ceiling = 900_000_000;
        assert_eq!(unit_micros("15min").unwrap(), accounting_ceiling);
        for raw in ["15min 1s", "16min", "1h 1s"] {
            assert!(unit_micros(raw).unwrap() > accounting_ceiling, "{raw}");
        }
    }

    #[test]
    fn invalid_and_overflowing_displays_never_become_finite_caps() {
        for raw in [
            "",
            " ",
            "infinity",
            "-1s",
            "+1s",
            "1.5s",
            "2min 0.5s",
            "1s garbage",
            "1s1s",
            "18446744073709551615s",
            "18446744073709551615us 1us",
        ] {
            assert!(unit_micros(raw).is_err(), "{raw}");
        }
    }
}

pub(super) fn drain_queued_cached145_guard(name: &str) -> Result<Value> {
    cached145_continuous::drain_queued_job(name)
}

#[cfg(test)]
mod cached145_projection_tests {
    use super::*;
    #[test]
    fn cached145_settle_projection_preserves_all_exact_native_fields() {
        let mut full = serde_json::Map::new();
        for key in GUARD_NATIVE_FIELDS.split(',') {
            full.insert(key.into(), json!(format!("exact-{key}")));
        }
        full.insert(
            "Id".into(),
            json!("horizon-qualify-145-cached-b2a09f57de39c384-guard.service"),
        );
        full.insert("Type".into(), json!("oneshot"));
        full.insert("ControlPID".into(), json!("0"));
        let projected = cached145_guard_projection(&Value::Object(full.clone())).unwrap();
        assert_eq!(
            projected.as_object().unwrap().len(),
            GUARD_NATIVE_FIELDS.split(',').count()
        );
        for key in GUARD_NATIVE_FIELDS.split(',') {
            assert_eq!(projected[key], full[key]);
        }
        assert!(projected.get("ControlPID").is_none());
    }
    #[test]
    fn cached145_settle_projection_never_synthesizes_missing_or_malformed_fields() {
        let mut full = serde_json::Map::new();
        for key in GUARD_NATIVE_FIELDS.split(',') {
            full.insert(key.into(), json!("exact"));
        }
        full.insert(
            "Id".into(),
            json!("horizon-qualify-145-cached-b2a09f57de39c384-guard.service"),
        );
        full.insert("Type".into(), json!("oneshot"));
        assert!(cached145_guard_projection(&Value::Object(full.clone())).is_ok());
        for key in GUARD_NATIVE_FIELDS.split(',') {
            let mut bad = full.clone();
            bad.remove(key);
            let projected = cached145_guard_projection(&Value::Object(bad));
            if key == "Unit" {
                assert!(projected.unwrap().get("Unit").is_none());
            } else {
                assert!(projected.is_err(), "{key}");
            }
            let mut bad = full.clone();
            bad.insert(key.into(), json!(0));
            assert!(
                cached145_guard_projection(&Value::Object(bad)).is_err(),
                "{key}"
            );
        }
    }
}

#[cfg(test)]
mod cached145_guard_service_projection_regression {
    use super::*;
    fn actual_service_shape() -> Value {
        let mut full = serde_json::Map::new();
        for key in GUARD_NATIVE_FIELDS.split(',').filter(|key| *key != "Unit") {
            full.insert(key.to_owned(), json!(""));
        }
        full.insert(
            "Id".to_owned(),
            json!("horizon-qualify-145-cached-b2a09f57de39c384-guard.service"),
        );
        full.insert("Type".to_owned(), json!("oneshot"));
        Value::Object(full)
    }
    #[test]
    fn service_retains_the_genuine_pid1_absence_of_timer_only_unit_property() {
        let full = actual_service_shape();
        let projected = cached145_guard_projection(&full).unwrap();
        assert_eq!(projected, full);
        assert!(projected.get("Unit").is_none());
    }
    #[test]
    fn service_still_rejects_missing_required_or_nontext_native_fields() {
        for key in GUARD_NATIVE_FIELDS.split(',').filter(|key| *key != "Unit") {
            let mut missing = actual_service_shape();
            missing.as_object_mut().unwrap().remove(key);
            assert!(cached145_guard_projection(&missing).is_err(), "{key}");
            let mut wrong_type = actual_service_shape();
            wrong_type[key] = json!(0);
            assert!(cached145_guard_projection(&wrong_type).is_err(), "{key}");
        }
    }
    #[test]
    fn omission_is_scoped_to_the_exact_oneshot_guard_service() {
        for unit in [
            "horizon-qualify-145-cached-b2a09f57de39c384-guard.timer",
            "foreign.service",
        ] {
            let mut full = actual_service_shape();
            full["Id"] = json!(unit);
            assert!(cached145_guard_projection(&full).is_err());
        }
        let mut full = actual_service_shape();
        full["Type"] = json!("simple");
        assert!(cached145_guard_projection(&full).is_err());
    }
}

#[cfg(test)]
mod cached145_actual_native_projection_capability {
    use super::*;
    #[test]
    #[ignore = "requires the exact current host guard; invoke separately in the admitted root sandbox"]
    fn genuine_completed_guard_projection_matches_ordinary_pid1_service_shape() -> Result<()> {
        let name = "horizon-qualify-145-cached-b2a09f57de39c384-guard.service";
        let full = crate::fleet::cached145_census_settle::observe(name)?;
        crate::fleet::cached145_census_rollover::completed(&full)?;
        let projected = cached145_guard_projection(&full)?;
        let actual = native_properties(name, true)?;
        ensure!(
            full["InvocationID"] == actual["InvocationID"],
            "actual capability crossed a guard fire"
        );
        ensure!(
            projected == actual,
            "settled projection differs from actual ordinary PID1 service fields"
        );
        ensure!(
            projected.get("Unit").is_none(),
            "timer-only Unit unexpectedly appeared on the service"
        );
        Ok(())
    }
}

#[cfg(test)]
mod launch_process_read_order_tests {
    use super::*;
    const UNIT: &str = "horizon-qualify-145-cached-b2a09f57de39c384.service";
    const IID: &str = "15ddd220e2144aaa8d7418f73f60768f";
    const PID: u64 = 965009;
    fn live() -> Value {
        json!({"Id":UNIT,"InvocationID":IID,"MainPID":PID.to_string(),
            "NRestarts":"0","ActiveState":"active","SubState":"running",
            "MemoryAccounting":"yes"})
    }
    #[test]
    fn live_owner_reads_exact_pid_and_preserves_start_ticks() {
        let mut seen = None;
        let ticks = launch_start_ticks(&live(), UNIT, IID, PID, |pid| {
            seen = Some(pid);
            Ok(187947130)
        })
        .unwrap();
        assert_eq!(seen, Some(PID));
        assert_eq!(ticks, 187947130);
    }
    #[test]
    fn terminal_cached145_never_reads_vanished_process() {
        for active in ["inactive", "failed"] {
            let mut native = live();
            native["ActiveState"] = json!(active);
            native["SubState"] = json!("dead");
            native["MainPID"] = json!("0");
            let mut called = false;
            let result = launch_start_ticks(&native, UNIT, IID, PID, |_| {
                called = true;
                Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
            });
            assert!(!called);
            let message = result.unwrap_err().to_string();
            assert!(message.contains("not live before process read"));
            assert!(message.contains(UNIT));
        }
    }
    #[test]
    fn changed_identity_or_unaccounted_owner_never_reads_process() {
        for (key, value) in [
            ("Id", "other.service"),
            ("InvocationID", "ffffffffffffffffffffffffffffffff"),
            ("MainPID", "965010"),
            ("NRestarts", "1"),
            ("MemoryAccounting", "no"),
            ("ActiveState", "activating"),
            ("SubState", "start"),
        ] {
            let mut native = live();
            native[key] = json!(value);
            assert!(
                launch_start_ticks(&native, UNIT, IID, PID, |_| {
                    panic!("process read before rejecting {key}")
                })
                .is_err()
            );
        }
    }
    #[test]
    fn live_process_disappearance_retains_path_and_unit_context() {
        let result = launch_start_ticks(&live(), UNIT, IID, PID, |pid| {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
                .with_context(|| format!("read live launch process identity: /proc/{pid}/stat"))
        });
        let error = result.unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        let error = format!("{error:#}");
        assert!(error.contains(UNIT));
        assert!(error.contains("/proc/965009/stat"));
    }
}
