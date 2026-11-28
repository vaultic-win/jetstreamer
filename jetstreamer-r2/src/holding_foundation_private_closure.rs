//! Fresh closed-consumer/reference proof for fixed private byte artifacts.
use super::*;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
    os::unix::ffi::OsStrExt,
    process::Command,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Closure {
    schema: String,
    artifact: Artifact,
    source: PathBuf,
    recorded_unix_seconds: u64,
    original_metadata: Vec<Bound>,
    terminal_units: BTreeMap<String, String>,
    historical_recipes: Vec<Bound>,
    private_closed_generation: bool,
    restore_required_before_historical_consumer_reuse: bool,
    canonical_archive: bool,
    local_retirement_authorized: bool,
}
fn shape(c: &Closure, a: Artifact, entry: u64) -> Result<()> {
    ensure!(
        c.schema == "jetstreamer-foundation-closed-private-closure-plan-v1"
            && c.artifact == a
            && c.source == a.source()
            && c.private_closed_generation
            && c.restore_required_before_historical_consumer_reuse
            && !c.canonical_archive
            && !c.local_retirement_authorized
            && c.recorded_unix_seconds <= entry
            && entry - c.recorded_unix_seconds <= 1800,
        "stale/foreign private generation closure"
    );
    let unit = a.producer().context("unregistered original producer")?;
    ensure!(
        !c.original_metadata.is_empty()
            && c.original_metadata.len() <= 32
            && c.terminal_units.len() <= 256
            && c.historical_recipes.len() <= 4096
            && c.terminal_units.contains_key(unit),
        "original producer/evidence omitted"
    );
    for (name, iid) in &c.terminal_units {
        ensure!(
            (name.ends_with(".service") || name.ends_with(".timer"))
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
                && ((iid.is_empty() && name != unit)
                    || (iid.len() == 32
                        && iid
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))),
            "invalid closed consumer identity"
        );
    }
    if partial223::applies(a) {
        partial223::closure_requirements(a, &c.terminal_units, &c.original_metadata)?;
    }
    if a == Artifact::Checkpoint203 {
        checkpoint203::closure_requirements(&c.terminal_units, &c.original_metadata)?;
    }
    if a == Artifact::OldV2237 {
        old237::closure_requirements(&c.terminal_units, &c.original_metadata)?;
    }
    if a == Artifact::FailedV5234 {
        failed234::closure_requirements(&c.terminal_units, &c.original_metadata)?;
    }
    Ok(())
}
fn collected(v: &Value, unit: &str) -> bool {
    let common = v["Id"] == unit
        && v["LoadState"] == "not-found"
        && v["ActiveState"] == "inactive"
        && v["SubState"] == "dead"
        && v["Job"] == ""
        && v["InvocationID"] == "";
    let inert = [
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
    ];
    common
        && if unit.ends_with(".service") {
            inert.iter().all(|(name, expected)| v[*name] == *expected)
        } else if unit.ends_with(".timer") {
            // Timer replies need not expose Service-interface properties.
            // If supplied, those values still must be explicitly inert.
            inert.iter().all(|(name, expected)| {
                v.get(*name)
                    .is_none_or(|value| value.as_str() == Some(*expected))
            })
        } else {
            false
        }
}
fn historical_pair(v: &Value, unit: &str, iid: &str) -> bool {
    let paired = [
        ("unit", "invocation_id"),
        ("Id", "InvocationID"),
        ("UNIT", "INVOCATION_ID"),
        ("_SYSTEMD_UNIT", "_SYSTEMD_INVOCATION_ID"),
    ]
    .iter()
    .any(|(u, i)| v[*u] == unit && v[*i] == iid);
    if paired && (!iid.is_empty() || collected(v, unit)) {
        return true;
    }
    match v {
        Value::Object(m) => m.values().any(|v| historical_pair(v, unit, iid)),
        Value::Array(a) => a.iter().any(|v| historical_pair(v, unit, iid)),
        _ => false,
    }
}
fn parse_properties(
    unit: &str,
    iid: &str,
    pinned_history: bool,
    code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Value> {
    ensure!(
        stdout.len() <= 65536 && stderr.len() <= 16384,
        "oversized closed consumer manager reply"
    );
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(stdout)?.lines() {
        let (k, v) = line.split_once('=').context("unit metadata shape")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate scalar closed consumer property"
        );
    }
    let v = Value::Object(m);
    if v["LoadState"] == "not-found" {
        let error = std::str::from_utf8(stderr)?.trim();
        let known_not_found = error.is_empty()
            || error == format!("Unit {unit} could not be found.")
            || error == format!("Failed to get properties: Unit {unit} not found.");
        ensure!(
            pinned_history
                && collected(&v, unit)
                && matches!(code, Some(0 | 1 | 4))
                && known_not_found,
            "collected consumer requires complete genuine not-found state and exact pinned history"
        );
    } else {
        ensure!(code == Some(0), "closed consumer inspection failed");
    }
    ensure!(
        v["Id"] == unit && (v["InvocationID"] == iid || v["InvocationID"] == ""),
        "closed consumer IID replaced or missing"
    );
    if v["InvocationID"] == "" && !iid.is_empty() {
        ensure!(
            pinned_history,
            "cleared consumer IID lacks exact pinned history"
        );
    }
    ensure!(
        ((v["ActiveState"] == "inactive" && v["SubState"] == "dead")
            || (v["ActiveState"] == "failed" && v["SubState"] == "failed"))
            && v["Job"] == "",
        "closed consumer is live or queued"
    );
    if unit.ends_with(".service") {
        ensure!(
            v["MainPID"] == "0"
                && v["ControlPID"] == "0"
                && v["NRestarts"] == "0"
                && v["Restart"] == "no",
            "closed service has missing/live process or restart fields"
        );
    }
    Ok(v)
}
pub(super) fn properties(unit: &str, iid: &str, pinned_history: bool) -> Result<Value> {
    let o=Command::new("/usr/bin/systemctl").args(["show",unit,"--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Restart,Job,Result,ExecMainStatus"]).output()?;
    parse_properties(
        unit,
        iid,
        pinned_history,
        o.status.code(),
        &o.stdout,
        &o.stderr,
    )
}
fn actors(c: &Closure, history: &BTreeSet<String>) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for (name, iid) in &c.terminal_units {
        let u = properties(name, iid, history.contains(name))?;
        ensure!(
            u["Id"] == *name
                && matches!(u["ActiveState"].as_str(), Some("inactive" | "failed"))
                && u["MainPID"].as_str().is_none_or(|s| s == "0")
                && u["ControlPID"].as_str().is_none_or(|s| s == "0")
                && u["NRestarts"].as_str().is_none_or(|s| s == "0")
                && u["Job"].as_str().is_none_or(str::is_empty),
            "consumer is live/restarting/queued"
        );
        ensure!(
            u["InvocationID"] == *iid || u["InvocationID"] == "" || u["InvocationID"].is_null(),
            "historical consumer IID reused"
        );
        if name.ends_with(".service") && u["LoadState"] != "not-found" {
            ensure!(u["Restart"] == "no", "consumer has retry policy");
        }
        result.insert(name.clone(), u);
    }
    let jobs = Command::new("/usr/bin/systemctl")
        .args(["list-jobs", "--no-legend", "--plain"])
        .output()?;
    ensure!(jobs.status.success(), "cannot inspect queued consumers");
    ensure!(
        !std::str::from_utf8(&jobs.stdout)?
            .split_whitespace()
            .any(|word| c.terminal_units.contains_key(word)),
        "closed consumer has pending job"
    );
    Ok(Value::Object(result))
}
fn maps_identity(bytes: &[u8], id: &Stamp) -> Result<bool> {
    let fields = std::str::from_utf8(bytes)?
        .split_whitespace()
        .take(5)
        .collect::<Vec<_>>();
    ensure!(fields.len() == 5, "malformed proc maps row");
    let (major, minor) = fields[3].split_once(':').context("maps device")?;
    Ok(
        u64::from_str_radix(major, 16)? == u64::from(libc::major(id.device))
            && u64::from_str_radix(minor, 16)? == u64::from(libc::minor(id.device))
            && fields[4].parse::<u64>()? == id.inode,
    )
}
fn inode_references(a: Artifact) -> Result<()> {
    let id = a.expected();
    for e in fs::read_dir("/proc")? {
        let e = e?;
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        if pid.parse::<u32>()? == std::process::id() {
            continue;
        }
        let p = e.path();
        match File::open(p.join("maps")) {
            Ok(f) => {
                let mut reader = BufReader::new(f);
                let mut row = Vec::new();
                let mut total = 0u64;
                loop {
                    row.clear();
                    let n = reader.by_ref().take(65537).read_until(b'\n', &mut row)?;
                    if n == 0 {
                        break;
                    }
                    total = total.checked_add(n as u64).context("maps scan overflow")?;
                    ensure!(n <= 65536 && total <= 1 << 30, "maps scan bound");
                    ensure!(
                        !maps_identity(&row, &id)?,
                        "private artifact still mmap-backed via alias by pid {pid}"
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        match fs::read_dir(p.join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    let fd = fd?;
                    match fs::metadata(fd.path()) {
                        Ok(m) => ensure!(
                            !(m.dev() == id.device && m.ino() == id.inode),
                            "private artifact still open via alias by pid {pid}"
                        ),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn recipe_reference(bytes: &[u8], a: Artifact, c: &Closure) -> bool {
    std::iter::once(a.root().as_os_str().as_bytes())
        .chain(c.terminal_units.keys().map(|n| n.as_bytes()))
        .any(|needle| bytes.windows(needle.len()).any(|w| w == needle))
}
fn recipe(path: &Path) -> Result<Vec<u8>> {
    let mut p = path.to_path_buf();
    let mut visited = BTreeSet::new();
    for _ in 0..8 {
        ensure!(visited.insert(p.clone()), "cyclic staged symlink");
        let m = fs::symlink_metadata(&p)?;
        if m.file_type().is_symlink() {
            let link = fs::read_link(&p)?;
            p = if link.is_absolute() {
                link
            } else {
                p.parent().unwrap().join(link)
            };
            continue;
        }
        if p == Path::new("/dev/null")
            && m.mode() & libc::S_IFMT == libc::S_IFCHR
            && m.rdev() == libc::makedev(1, 3)
            && m.uid() == 0
        {
            return Ok(Vec::new());
        }
        ensure!(
            m.is_file() && m.len() <= MAX_METADATA,
            "uninspected oversized/nonregular staged recipe"
        );
        return read_stable_bounded(&p, MAX_METADATA, "private historical recipe");
    }
    bail!("staged symlink chain exceeds bound")
}
fn staged(a: Artifact, c: &Closure) -> Result<Value> {
    let allowed = c
        .historical_recipes
        .iter()
        .map(|b| (b.path.clone(), b.sha256.clone()))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        allowed.len() == c.historical_recipes.len(),
        "duplicate historical recipe binding"
    );
    let mut seen = BTreeMap::new();
    let mut pending = vec![];
    for root in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/home/ubuntu/.jetstreamer-private/systemd-staging",
    ] {
        match fs::symlink_metadata(root) {
            Ok(m) => {
                ensure!(
                    m.is_dir() && !m.file_type().is_symlink(),
                    "aliased staged root"
                );
                pending.push((PathBuf::from(root), 0));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let mut files = 0;
    while let Some((root, depth)) = pending.pop() {
        ensure!(depth <= 16, "staged nesting bound");
        for e in fs::read_dir(root)? {
            let e = e?;
            let p = e.path();
            let m = fs::symlink_metadata(&p)?;
            if m.is_dir() {
                pending.push((p, depth + 1));
                continue;
            }
            files += 1;
            ensure!(files <= 65536, "staged file count bound");
            if m.file_type().is_symlink() {
                let target = fs::read_link(&p)?;
                let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("");
                ensure!(
                    !((p.parent()
                        .is_some_and(|d| d.to_string_lossy().ends_with(".wants")
                            || d.to_string_lossy().ends_with(".requires")))
                        && c.terminal_units.contains_key(name)),
                    "historical consumer remains enabled"
                );
            }
            let bytes = recipe(&p)?;
            if !recipe_reference(&bytes, a, c) {
                continue;
            }
            if let Some(name) = p
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|n| n.ends_with(".service") || n.ends_with(".timer"))
            {
                ensure!(
                    c.terminal_units.contains_key(name),
                    "referencing staged actor lacks its own terminal identity"
                );
            }
            let sha = hex_lower(&Sha256::digest(&bytes));
            ensure!(
                allowed.get(&p) == Some(&sha),
                "new/unreviewed staged private consumer: {}",
                p.display()
            );
            seen.insert(p, sha);
        }
    }
    ensure!(
        seen == allowed,
        "historical recipe closure changed or contains unobserved recipe"
    );
    Ok(serde_json::to_value(seen)?)
}
pub(super) fn inspect(a: Artifact, b: &Bound, entry: u64, source_present: bool) -> Result<Value> {
    let c: Closure = serde_json::from_value(saved(b)?)?;
    shape(&c, a, entry)?;
    if source_present {
        source(a)?;
    } else {
        canonical_exclusion(a)?;
    }
    let mut provenance = Vec::new();
    let producer = a.producer().unwrap();
    let mut history = BTreeSet::new();
    if partial223::applies(a) {
        partial223::preservation(a)?;
        history.insert(producer.to_owned());
        if a == Artifact::Adaptive223 {
            history.insert("horizon-controller-220-223-current-v1.service".to_owned());
        }
    }
    if a == Artifact::OldV2237 {
        // The fixed accepted scratch-retirement chain, original review and
        // stop sample jointly bind this exact original unit/cgroup/PID/IID.
        // They do not reuse the other, already-retired v1 epoch 237 lineage.
        old237::preservation()?;
        history.insert(producer.to_owned());
    }
    if a == Artifact::Checkpoint203 {
        checkpoint203::preservation()?;
        history.insert(producer.to_owned());
    }
    if a == Artifact::FailedV5234 {
        failed234::preservation()?;
        history.insert(producer.to_owned());
    }
    for raw in &c.original_metadata {
        let value = saved(raw)?;
        for (name, iid) in &c.terminal_units {
            if historical_pair(&value, name, iid) {
                history.insert(name.clone());
            }
        }
        provenance.push(json!({"binding":raw,"raw_evidence_preserved_locally":true}));
    }
    ensure!(
        history.contains(producer),
        "original producer IID is not present in retained bound raw provenance"
    );
    let before = actors(&c, &history)?;
    let staged_before = staged(a, &c)?;
    let paths =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), a.root())?;
    ensure!(
        paths.references.is_empty(),
        "private generation still has path references"
    );
    inode_references(a)?;
    let staged_after = staged(a, &c)?;
    let after = actors(&c, &history)?;
    ensure!(
        before == after && staged_before == staged_after,
        "consumer/reference closure changed during review"
    );
    if source_present {
        source(a)?;
    }
    Ok(
        json!({"closure":b,"original_metadata":provenance,"terminal_units":before,"staged_historical_recipes":staged_after,
        "process_reference_census":paths,"maps_and_fds_device_inode_checked":true,"source_identity_checked":source_present,
        "historical_consumers_require_restore_before_reuse":true,"canonical_archive":false,"local_retirement_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn collected_stdout(unit: &str) -> Vec<u8> {
        format!("Id={unit}\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nNRestarts=0\nJob=\nInvocationID=\nRestart=no\nResult=success\nExecMainStatus=0\n").into_bytes()
    }
    #[test]
    fn genuine_nonzero_collected_reply_requires_complete_state_and_pinned_history() {
        let unit = Artifact::ThroughRoot206.producer().unwrap();
        let bytes = collected_stdout(unit);
        let iid = "a".repeat(32);
        for code in [0, 1, 4] {
            assert_eq!(
                parse_properties(unit, &iid, true, Some(code), &bytes, b"").unwrap()["LoadState"],
                "not-found"
            );
        }
        assert!(parse_properties(unit, &iid, false, Some(4), &bytes, b"").is_err());
        for code in [None, Some(2), Some(3), Some(127)] {
            assert!(parse_properties(unit, &iid, true, code, &bytes, b"").is_err());
        }
        assert!(
            parse_properties(
                unit,
                &iid,
                true,
                Some(1),
                &bytes,
                b"Failed to connect to bus: Permission denied"
            )
            .is_err()
        );
        let loaded = String::from_utf8(bytes.clone())
            .unwrap()
            .replace("LoadState=not-found", "LoadState=loaded");
        assert!(parse_properties(unit, &iid, true, Some(1), loaded.as_bytes(), b"").is_err());
        assert!(parse_properties(unit, &iid, true, Some(0), loaded.as_bytes(), b"").is_ok());
        assert!(parse_properties(unit, &iid, false, Some(0), loaded.as_bytes(), b"").is_err());
        let duplicate = [bytes.clone(), b"MainPID=0\n".to_vec()].concat();
        assert!(parse_properties(unit, &iid, true, Some(4), &duplicate, b"").is_err());
        for field in [
            "MainPID=0\n",
            "ControlPID=0\n",
            "NRestarts=0\n",
            "Job=\n",
            "InvocationID=\n",
        ] {
            let short = String::from_utf8(bytes.clone()).unwrap().replace(field, "");
            assert!(parse_properties(unit, &iid, true, Some(4), short.as_bytes(), b"").is_err());
        }
        for (old, new) in [
            ("MainPID=0", "MainPID=9"),
            ("ControlPID=0", "ControlPID=9"),
            ("NRestarts=0", "NRestarts=1"),
            ("Job=\n", "Job=12\n"),
            (
                "InvocationID=\n",
                "InvocationID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
            ),
        ] {
            let bad = String::from_utf8(bytes.clone()).unwrap().replace(old, new);
            assert!(parse_properties(unit, &iid, true, Some(4), bad.as_bytes(), b"").is_err());
        }
    }
    #[test]
    fn collected_timer_accepts_genuine_inert_shape_without_service_properties() {
        let unit = "horizon-closed-private-fixture.timer";
        let iid = "a".repeat(32);
        let common = format!(
            "Id={unit}\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nJob=\nInvocationID=\n"
        );
        for code in [0, 1, 4] {
            assert!(parse_properties(unit, &iid, true, Some(code), common.as_bytes(), b"").is_ok());
        }
        let full = collected_stdout(unit);
        assert!(parse_properties(unit, &iid, true, Some(4), &full, b"").is_ok());
        assert!(parse_properties(unit, &iid, false, Some(4), common.as_bytes(), b"").is_err());
        for field in [
            "Id=",
            "LoadState=",
            "ActiveState=",
            "SubState=",
            "Job=",
            "InvocationID=",
        ] {
            let short = common
                .lines()
                .filter(|line| !line.starts_with(field))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(parse_properties(unit, &iid, true, Some(4), short.as_bytes(), b"").is_err());
        }
        for (old, new) in [
            ("ActiveState=inactive", "ActiveState=active"),
            ("SubState=dead", "SubState=waiting"),
            ("Job=\n", "Job=12\n"),
            (
                "InvocationID=\n",
                "InvocationID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
            ),
        ] {
            let bad = common.replace(old, new);
            assert!(parse_properties(unit, &iid, true, Some(4), bad.as_bytes(), b"").is_err());
        }
        for bad in [
            "MainPID=7",
            "ControlPID=7",
            "NRestarts=1",
            "Restart=always",
            "Result=failed",
            "ExecMainStatus=1",
        ] {
            let bad = format!("{common}{bad}\n");
            assert!(parse_properties(unit, &iid, true, Some(4), bad.as_bytes(), b"").is_err());
        }
        assert!(parse_properties(unit, &iid, true, Some(2), common.as_bytes(), b"").is_err());
        assert!(
            parse_properties(
                unit,
                &iid,
                true,
                Some(4),
                common.as_bytes(),
                b"Failed to connect to bus: Permission denied"
            )
            .is_err()
        );
        let service = common.replace(unit, "horizon-closed-private-fixture.service");
        assert!(
            parse_properties(
                "horizon-closed-private-fixture.service",
                &iid,
                true,
                Some(4),
                service.as_bytes(),
                b""
            )
            .is_err()
        );
    }
    #[test]
    fn history_requires_an_exact_unit_iid_pair_not_incidental_text() {
        let unit = Artifact::ThroughRoot206.producer().unwrap();
        let iid = "a".repeat(32);
        assert!(historical_pair(
            &json!({"producer":{"unit":unit,"invocation_id":iid}}),
            unit,
            &iid
        ));
        assert!(!historical_pair(
            &json!({"log":format!("{unit} {iid}")}),
            unit,
            &iid
        ));
        assert!(!historical_pair(
            &json!({"unit":unit,"invocation_id":"b".repeat(32)}),
            unit,
            &iid
        ));
        let wrong = collected_stdout(unit);
        let wrong = String::from_utf8(wrong).unwrap().replace(
            "InvocationID=\n",
            "InvocationID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        );
        assert!(parse_properties(unit, &iid, true, Some(0), wrong.as_bytes(), b"").is_err());
    }
    #[test]
    fn inode_census_catches_mapped_bind_alias_without_a_descriptor() {
        let a = Artifact::Singleton207;
        let id = a.expected();
        let line = format!(
            "1000-2000 r--p 00000000 {:x}:{:x} {} /mnt/unrelated-alias.blob\n",
            libc::major(id.device),
            libc::minor(id.device),
            id.inode
        );
        assert!(maps_identity(line.as_bytes(), &id).unwrap());
        let mut other = id.clone();
        other.inode += 1;
        assert!(!maps_identity(line.as_bytes(), &other).unwrap());
        assert!(maps_identity(b"malformed\n", &id).is_err());
    }
    #[test]
    fn foreign_recipe_actor_reference_does_not_need_the_original_path() {
        let a = Artifact::ThroughRoot206;
        let mut units = BTreeMap::new();
        units.insert(a.producer().unwrap().into(), "a".repeat(32));
        let c = Closure {
            schema: "jetstreamer-foundation-closed-private-closure-plan-v1".into(),
            artifact: a,
            source: a.source(),
            recorded_unix_seconds: 100,
            original_metadata: vec![Bound {
                path: "/bound/origin.json".into(),
                sha256: "a".repeat(64),
            }],
            terminal_units: units,
            historical_recipes: vec![],
            private_closed_generation: true,
            restore_required_before_historical_consumer_reuse: true,
            canonical_archive: false,
            local_retirement_authorized: false,
        };
        shape(&c, a, 100).unwrap();
        assert!(recipe_reference(
            format!("[Timer]\nUnit={}\n", a.producer().unwrap()).as_bytes(),
            a,
            &c
        ));
        assert!(shape(&c, a, 1901).is_err());
    }
    #[test]
    fn external_symlink_recipes_are_bounded_and_inspected() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let p = external.path().join("timer");
        fs::write(&p, b"[Timer]\nUnit=original.service\n").unwrap();
        let link = root.path().join("alias");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(recipe(&link).unwrap(), b"[Timer]\nUnit=original.service\n");
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&link, &link).unwrap();
        assert!(recipe(&link).is_err());
        let huge = root.path().join("large");
        File::create(&huge)
            .unwrap()
            .set_len(MAX_METADATA + 1)
            .unwrap();
        assert!(recipe(&huge).is_err());
    }
}
