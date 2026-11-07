use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
enum RecipeRole {
    PriorCheck,
    ReceiptProjection,
    MetadataOnly,
    Publication,
    ReadOnlyProbe,
    CompletedProducer,
}
include!("fixed_recipes.rs");
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
enum InputKind {
    Executable,
    Script,
    Json,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
enum JsonType {
    CanonicalR2Receipt,
    PublicationV2,
    PreflightV4,
    PriorIndexPlan,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    binding: Evidence,
    kind: InputKind,
    json_type: Option<JsonType>,
    // Exact paths of transitively consumed executable/script/metadata children.
    children: Vec<PathBuf>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Recipe {
    installed: PathBuf,
    original: Evidence,
    role: RecipeRole,
    terminal_actor: Actor,
    readset_review: Evidence,
    inputs: Vec<Input>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Operation {
    unit: String,
    installed: PathBuf,
    recipe: Evidence,
    binary: Evidence,
    plan_path: PathBuf,
    digest_transport: PathBuf,
    check_only: bool,
    // Exact actual argv, with literal `env` at --plan-sha256 (no hash cycle).
    argv: Vec<String>,
    // All native sandbox sets use semantic comparison, never order normalization
    // of commands, paths, identities or invocation IDs.
    expected_read_only_paths: Vec<PathBuf>,
    expected_bind_read_only_paths: String,
}
fn ordinary_path(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}
pub(super) fn direct_installed_path(path: &Path, unit: &str) -> bool {
    path.file_name().and_then(|s| s.to_str()) == Some(unit)
        && path
            .parent()
            .and_then(Path::to_str)
            .is_some_and(|s| UNIT_ROOTS.contains(&s))
}
fn fixed_role(installed: &Path, digest: &str, unit: &str, role: RecipeRole) -> bool {
    FIXED_RECIPES
        .iter()
        .any(|(p, h, u, r)| installed == Path::new(p) && digest == *h && unit == *u && role == *r)
}
fn safe_input(i: &Input) -> bool {
    (i.kind == InputKind::Json) == i.json_type.is_some()
        && ordinary_path(&i.binding.path)
        && valid_sha(&i.binding.sha256)
        && [0, 1000].contains(&i.binding.uid)
        && !matches!(
            i.binding.path.extension().and_then(|s| s.to_str()),
            Some("jet" | "index" | "car" | "sst" | "zst" | "bz2")
        )
        && i.children.iter().all(|p| ordinary_path(p))
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    let mut installed = BTreeSet::new();
    for r in &p.typed_recipes {
        ensure!(
            fixed_role(
                &r.installed,
                &r.original.sha256,
                &r.terminal_actor.unit,
                r.role
            ) && direct_installed_path(&r.installed, &r.terminal_actor.unit)
                && ordinary_path(&r.original.path)
                && r.original.path.starts_with("/var/lib/jetstreamer")
                && r.original.path.file_name() == r.installed.file_name()
                && r.original.uid == 0
                && r.terminal_actor.invocation_id.len() == 32
                && r.terminal_actor
                    .invocation_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && installed.insert(r.installed.clone()),
            "unknown/duplicate historical typed recipe"
        );
        ensure!(
            r.readset_review.uid == 0
                && valid_sha(&r.readset_review.sha256)
                && !r.inputs.is_empty()
                && r.inputs.len() <= 128,
            "missing typed transitive readset"
        );
        let paths: BTreeSet<_> = r.inputs.iter().map(|i| i.binding.path.clone()).collect();
        ensure!(
            paths.len() == r.inputs.len()
                && r.inputs.iter().all(safe_input)
                && r.inputs.iter().all(|i| i
                    .children
                    .iter()
                    .all(|p| paths.contains(p) && p != &i.binding.path)),
            "incomplete/aliased readset graph"
        );
        // Cycles cannot be declared as proof of a finite complete readset.
        let mut done = BTreeSet::new();
        for node in &r.inputs {
            graph_walk(
                &node.binding.path,
                &r.inputs,
                &mut BTreeSet::new(),
                &mut done,
            )?;
        }
    }
    if let Some(o) = &p.current_operation {
        if p.owners
            .iter()
            .any(|owner| owner.imported_canonical.is_some())
        {
            ensure!(
                p.inert_recipes.is_empty() && complete_fixed_registry(&installed),
                "imported current operation requires typed historical recipes, not legacy inert allowances"
            );
        }
        ensure!(
            [
                "horizon-235237-index939-check-only-v1.service",
                "horizon-235237-index939-retire-v1.service"
            ]
            .contains(&o.unit.as_str())
                && o.check_only == o.unit.contains("check-only")
                && direct_installed_path(&o.installed, &o.unit)
                && o.recipe.uid == 0
                && o.binary.uid == 0
                && o.binary.path.starts_with("/var/lib/jetstreamer")
                && valid_sha(&o.recipe.sha256)
                && valid_sha(&o.binary.sha256)
                && o.recipe.path.starts_with("/var/lib/jetstreamer")
                && o.recipe.path.file_name() == o.installed.file_name()
                && ordinary_path(&o.plan_path)
                && ordinary_path(&o.digest_transport)
                && o.digest_transport.starts_with("/var/lib/jetstreamer")
                && !o.digest_transport.starts_with(&p.state)
                && !installed.contains(&o.installed),
            "unknown current operation scope"
        );
        let mut argv = vec![
            o.binary.path.to_string_lossy().into_owned(),
            "--plan".into(),
            o.plan_path.to_string_lossy().into_owned(),
            "--plan-sha256".into(),
            "env".into(),
            "--self-sha256".into(),
            o.binary.sha256.clone(),
        ];
        if o.check_only {
            argv.push("--check-only".into());
        }
        ensure!(
            o.argv == argv,
            "current operation argv differs from narrow CLI"
        );
        ensure!(
            o.expected_read_only_paths.iter().all(|p| ordinary_path(p)),
            "invalid readonly path binding"
        );
    }
    Ok(())
}
fn complete_fixed_registry(installed: &BTreeSet<PathBuf>) -> bool {
    installed.len() == FIXED_RECIPES.len()
        && FIXED_RECIPES
            .iter()
            .all(|(p, _, _, _)| installed.contains(Path::new(p)))
}
fn graph_walk(
    path: &Path,
    inputs: &[Input],
    visiting: &mut BTreeSet<PathBuf>,
    done: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    if done.contains(path) {
        return Ok(());
    }
    ensure!(
        done.len() <= 128 && visiting.len() <= 128,
        "readset traversal budget"
    );
    ensure!(
        visiting.insert(path.to_path_buf()),
        "cyclic transitive readset"
    );
    let node = inputs
        .iter()
        .find(|i| i.binding.path == path)
        .context("missing readset node")?;
    for child in &node.children {
        graph_walk(child, inputs, visiting, done)?;
    }
    visiting.remove(path);
    done.insert(path.to_path_buf());
    Ok(())
}
fn artifact(i: &Input) -> Result<Vec<u8>> {
    ensure!(safe_input(i), "unsafe transitive input");
    let path = &i.binding.path;
    ensure!(path.canonicalize()? == *path, "transitive input alias");
    let mut f = open_read(path)?;
    let first = f.metadata()?;
    let limit = if i.kind == InputKind::Executable {
        128 << 20
    } else {
        LIMIT
    };
    ensure!(
        first.is_file()
            && first.uid() == i.binding.uid
            && first.nlink() == 1
            && first.mode() & 0o022 == 0
            && first.len() <= limit,
        "transitive custody/size changed"
    );
    let mut h = Sha256::new();
    let mut prefix = Vec::new();
    let mut total = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(total <= limit, "transitive input grew");
        h.update(&buf[..n]);
        if i.kind != InputKind::Executable {
            prefix.extend_from_slice(&buf[..n]);
        } else if prefix.is_empty() {
            prefix.extend_from_slice(&buf[..n.min(4)]);
        }
    }
    let last = f.metadata()?;
    let at = fs::symlink_metadata(path)?;
    ensure!(
        identity(&first) == identity(&last)
            && identity(&first) == identity(&at)
            && first.ctime() == last.ctime()
            && first.ctime_nsec() == last.ctime_nsec()
            && first.ctime() == at.ctime()
            && first.ctime_nsec() == at.ctime_nsec()
            && total == first.len()
            && format!("{:x}", h.finalize()) == i.binding.sha256,
        "transitive input changed"
    );
    match i.kind {
        InputKind::Executable => ensure!(
            prefix == b"\x7fELF",
            "non-ELF executable needs a typed script readset"
        ),
        InputKind::Script => {
            std::str::from_utf8(&prefix)?;
        }
        InputKind::Json => {
            let v: Value = serde_json::from_slice(&prefix)?;
            match i.json_type.context("missing typed JSON role")? {
                JsonType::CanonicalR2Receipt => {
                    let epoch = v["epoch"].as_u64().context("canonical epoch")?;
                    ensure!([235, 237].contains(&epoch), "foreign canonical receipt");
                    canonical_receipt(&v, epoch)?;
                }
                JsonType::PublicationV2 => ensure!(
                    v["schema"] == "jetstreamer-root-cohort-publication-receipt-v2",
                    "untyped publication receipt"
                ),
                JsonType::PreflightV4 => ensure!(
                    v["manifest"]["schema"] == "jetstreamer-gcs-snapshot-preflight-v4"
                        && v["manifest_fingerprint"]
                            == "sha256:3f0e03105ba1e6b166091d3519e1aea1f432d81e51044c3a35f49fb3e8991970",
                    "foreign preflight input"
                ),
                JsonType::PriorIndexPlan => {
                    let old: Plan = serde_json::from_value(v)?;
                    validate_plan(&old)?;
                    ensure!(
                        old.current_operation.is_none() && old.typed_recipes.is_empty(),
                        "historical plan references new operation"
                    );
                }
            }
        }
    }
    Ok(prefix)
}
fn installed_bytes(installed: &Path, original: &Evidence) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(installed)?;
    ensure!(m.uid() == 0, "installed recipe not Root-owned");
    if m.file_type().is_symlink() {
        ensure!(
            fs::read_link(installed)? == original.path,
            "installed symlink is not exact original direct recipe"
        );
    } else {
        ensure!(
            m.is_file() && m.mode() & 0o022 == 0,
            "unsafe installed regular recipe"
        );
    }
    let b = evidence(original)?;
    ensure!(
        reviewed::staged_body(installed)? == b,
        "installed and original recipe differ"
    );
    Ok(b)
}
fn props(text: &str) -> Result<BTreeMap<&str, &str>> {
    let mut m = BTreeMap::new();
    for l in text.lines() {
        let (k, v) = l.split_once('=').context("malformed native property")?;
        ensure!(m.insert(k, v).is_none(), "duplicate native property");
    }
    Ok(m)
}
fn no_triggers(m: &BTreeMap<&str, &str>) -> Result<()> {
    ensure!(
        [
            "Triggers",
            "TriggeredBy",
            "OnSuccess",
            "OnFailure",
            "DropInPaths"
        ]
        .iter()
        .all(|k| m.get(k) == Some(&""))
            && m.get("Job").is_some_and(|v| v.is_empty() || *v == "0"),
        "recipe has trigger/dropin/queued job"
    );
    Ok(())
}
fn historical_native(r: &Recipe, jobs: &str) -> Result<Value> {
    let a = &r.terminal_actor;
    let out = native_output(
        "/usr/bin/systemctl",
        &[
            "show",
            &a.unit,
            "--all",
            "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,InvocationID,NRestarts,Restart,Job,Triggers,TriggeredBy,OnSuccess,OnFailure,DropInPaths,FragmentPath",
        ],
    )?;
    ensure!(
        out.stdout.len() as u64 <= LIMIT && out.stderr.len() as u64 <= LIMIT,
        "native historical query oversized"
    );
    let text = std::str::from_utf8(&out.stdout)?;
    let m = props(text)?;
    no_triggers(&m)?;
    ensure!(
        m.get("Id") == Some(&a.unit.as_str())
            && m.get("ControlGroup") == Some(&"")
            && !jobs.split_whitespace().any(|w| w == a.unit),
        "typed historical unit not closed"
    );
    if m.get("LoadState") == Some(&"loaded") {
        ensure!(
            m.get("FragmentPath") == Some(&r.installed.to_str().context("installed UTF8")?),
            "historical FragmentPath changed"
        );
    }
    let h = a
        .historical_provenance
        .as_ref()
        .map(|h| -> Result<Value> { Ok(serde_json::from_slice(&evidence(&h.evidence)?)?) })
        .transpose()?;
    actor_state(a, text, out.status.code(), h.as_ref())
}
fn review_readset(r: &Recipe, body: &[u8]) -> Result<()> {
    let review: Value = serde_json::from_slice(&evidence(&r.readset_review)?)?;
    ensure!(
        review["schema"] == "horizon-terminal-index-typed-readset-review-v1"
            && review["installed_recipe"] == r.installed.to_string_lossy().as_ref()
            && review["original_recipe_sha256"] == r.original.sha256
            && review["role"] == serde_json::to_value(r.role)?
            && review["inputs"] == serde_json::to_value(&r.inputs)?
            && review["terminal_actor"] == serde_json::to_value(&r.terminal_actor)?
            && review["complete_transitive_executable_and_metadata_readset_reviewed"] == true,
        "readset lacks exact independent typed source review"
    );
    for i in &r.inputs {
        let bytes = artifact(i)?;
        for child in &i.children {
            ensure!(
                path_reference(&bytes, child.as_os_str().as_bytes())
                    || i.kind == InputKind::Executable,
                "declared child not present in typed metadata/script"
            );
        }
    }
    // Each direct Exec command must name a bound input. Shell/Python and node
    // argument semantics remain part of the exact independently bound review.
    let text = std::str::from_utf8(body)?;
    for line in text
        .lines()
        .filter(|s| s.starts_with("ExecStart=") || s.starts_with("ExecStartPre="))
    {
        let cmd = line
            .split_once('=')
            .unwrap()
            .1
            .trim_start_matches('"')
            .split([' ', '"'])
            .next()
            .context("empty command")?;
        ensure!(
            r.inputs.iter().any(|i| i.binding.path == Path::new(cmd))
                || Path::new(cmd)
                    .canonicalize()
                    .ok()
                    .is_some_and(|canonical| r.inputs.iter().any(|i| i.binding.path == canonical)),
            "unbound direct executable in typed readset"
        );
    }
    for line in text
        .lines()
        .filter(|s| s.starts_with("ExecStart=") || s.starts_with("ExecStartPre="))
    {
        for token in line.split(|c: char| c.is_ascii_whitespace() || c == '"' || c == '=') {
            let path = Path::new(token);
            if path.is_absolute()
                && matches!(
                    path.extension().and_then(|e| e.to_str()),
                    Some("json" | "sh" | "py")
                )
                && !token.contains("${")
            {
                ensure!(
                    r.inputs.iter().any(|i| i.binding.path == path),
                    "unbound indirect metadata/script command argument"
                );
            }
        }
    }
    Ok(())
}
pub(super) fn historical(p: &Plan, jobs: &str) -> Result<Vec<Value>> {
    let mut states = Vec::new();
    for r in &p.typed_recipes {
        let bytes = installed_bytes(&r.installed, &r.original)?;
        review_readset(r, &bytes)?;
        states.push(historical_native(r, jobs)?);
    }
    Ok(states)
}
pub(super) fn staged(p: &Plan, path: &Path, bytes: &[u8], jobs: &str) -> Result<bool> {
    if let Some(r) = p.typed_recipes.iter().find(|r| r.installed == path) {
        ensure!(
            direct_installed_path(path, &r.terminal_actor.unit) && hash(bytes) == r.original.sha256,
            "changed direct typed recipe"
        );
        historical_native(r, jobs)?;
        return Ok(true);
    }
    if let Some(o) = &p.current_operation {
        if o.installed == path {
            ensure!(hash(bytes) == o.recipe.sha256, "changed current recipe");
            authenticate_current(p)?;
            return Ok(true);
        }
    }
    // Enabled aliases/dependencies remain blockers even when original recipe is
    // correctly terminal. An exact original direct installation is not enablement.
    if recipe_reference(bytes, p)
        || p.typed_recipes.iter().any(|r| {
            bytes
                .windows(r.terminal_actor.unit.len())
                .any(|w| w == r.terminal_actor.unit.as_bytes())
        })
    {
        ensure!(
            !path.components().any(|c| c
                .as_os_str()
                .to_str()
                .is_some_and(|s| s.ends_with(".wants") || s.ends_with(".requires"))),
            "enabled wants/requires reference to terminal owner"
        );
    }
    Ok(false)
}
pub(super) fn recipe_mentions(bytes: &[u8], p: &Plan) -> bool {
    p.typed_recipes.iter().any(|r| {
        bytes
            .windows(r.terminal_actor.unit.len().max(1))
            .any(|w| w == r.terminal_actor.unit.as_bytes())
    }) || indirect_reference(bytes, p)
}
fn consumer_input(i: &Input) -> bool {
    i.kind == InputKind::Script
        || matches!(
            i.json_type,
            Some(JsonType::PriorIndexPlan | JsonType::PublicationV2)
        )
}
pub(super) fn indirect_reference(bytes: &[u8], p: &Plan) -> bool {
    p.typed_recipes
        .iter()
        .flat_map(|r| {
            r.inputs
                .iter()
                .filter(|i| consumer_input(i))
                .map(|i| &i.binding.path)
        })
        .any(|path| path_reference(bytes, path.as_os_str().as_bytes()))
}
pub(super) fn indirect_inodes(p: &Plan) -> Result<BTreeSet<(u64, u64)>> {
    p.typed_recipes
        .iter()
        .flat_map(|r| r.inputs.iter().filter(|i| consumer_input(i)))
        .map(|i| {
            let m = fs::metadata(&i.binding.path)?;
            Ok((m.dev(), m.ino()))
        })
        .collect()
}
pub(super) fn process_ticks(text: &str) -> Result<u64> {
    start_ticks(text)
}
fn start_ticks(stat: &str) -> Result<u64> {
    stat.rsplit_once(") ")
        .context("malformed process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing process start ticks")?
        .parse()
        .context("invalid process start ticks")
}
fn set_paths(text: &str) -> Result<BTreeSet<PathBuf>> {
    text.split_whitespace()
        .map(|s| {
            let p = PathBuf::from(s);
            ensure!(ordinary_path(&p), "unexpected systemd path formatting");
            Ok(p)
        })
        .collect()
}
fn mount_access<'a>(text: &'a str, path: &Path) -> Result<&'a str> {
    let mut best: Option<(&str, &str)> = None;
    for line in text.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        ensure!(f.len() >= 10, "malformed mount row");
        let at = f[4];
        ensure!(!at.contains('\\'), "escaped mount path unsupported");
        if path.starts_with(at) && best.is_none_or(|(prior, _)| at.len() > prior.len()) {
            best = Some((at, f[5]));
        }
    }
    let options = best.context("no current mount for path")?.1;
    if options.split(',').any(|s| s == "ro") {
        Ok("ro")
    } else if options.split(',').any(|s| s == "rw") {
        Ok("rw")
    } else {
        anyhow::bail!("mount lacks explicit readonly/write flag")
    }
}
fn parse_commands(bytes: &[u8]) -> Result<Vec<(String, Vec<String>, bool)>> {
    let v: Value = serde_json::from_slice(bytes)?;
    ensure!(
        v["type"] == "a(sasbttttuii)",
        "wrong native command array type"
    );
    let data = v["data"]
        .as_array()
        .context("missing command property data")?;
    ensure!(data.len() == 1, "ambiguous command property values");
    let rows = data[0]
        .as_array()
        .context("command property is not an array")?;
    let mut out = Vec::new();
    for row in rows {
        let fields = row.as_array().context("command row not a struct")?;
        ensure!(fields.len() == 10, "wrong command struct width");
        let path = fields[0].as_str().context("command path")?.to_owned();
        let argv = fields[1]
            .as_array()
            .context("command argv")?
            .iter()
            .map(|x| Ok(x.as_str().context("command argument type")?.to_owned()))
            .collect::<Result<Vec<_>>>()?;
        let ignore = fields[2].as_bool().context("command ignore_errors type")?;
        ensure!(
            fields[3..8].iter().all(|v| v.as_u64().is_some())
                && fields[8..10].iter().all(|v| v.as_i64().is_some()),
            "invalid native command numeric fields"
        );
        out.push((path, argv, ignore));
    }
    Ok(out)
}
pub(super) fn authenticate_current(p: &Plan) -> Result<Value> {
    let o = p
        .current_operation
        .as_ref()
        .context("missing exact current operation identity")?;
    validate(p)?;
    let own = std::process::id();
    let before = fs::read_to_string("/proc/self/stat")?;
    let ticks = start_ticks(&before)?;
    let iid = std::env::var("INVOCATION_ID").context("missing native current IID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid current IID"
    );
    let native = systemctl(&[
        "show",
        &o.unit,
        "--all",
        "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,NRestarts,Restart,KillMode,Delegate,Job,Triggers,TriggeredBy,OnSuccess,OnFailure,DropInPaths,FragmentPath,User,Group,Type,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,TimeoutStartUSec,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,ReadOnlyPaths,BindReadOnlyPaths,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,EnvironmentFiles,CapabilityBoundingSet,AmbientCapabilities",
    ])?;
    let m = props(&native)?;
    no_triggers(&m)?;
    for (k, v) in [
        ("Id", o.unit.as_str()),
        ("LoadState", "loaded"),
        ("InvocationID", iid.as_str()),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("User", "root"),
        ("Group", "root"),
        ("Type", "oneshot"),
        ("MemoryMax", "2147483648"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "2s"),
        ("TasksMax", "512"),
        ("TimeoutStartUSec", "3min"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
    ] {
        ensure!(m.get(k) == Some(&v), "current operation native {k} differs");
    }
    ensure!(
        m.get("ActiveState") == Some(&"activating")
            && m.get("SubState") == Some(&"start")
            && [m.get("MainPID"), m.get("ControlPID")]
                .into_iter()
                .any(|p| p.is_some_and(|p| p.parse::<u32>().ok() == Some(own))),
        "current payload PID is not native owner"
    );
    let expected_group = format!("/system.slice/{}", o.unit);
    ensure!(
        m.get("ControlGroup") == Some(&expected_group.as_str())
            && fs::read_to_string("/proc/self/cgroup")? == format!("0::{expected_group}\n"),
        "current operation cgroup mismatch"
    );
    ensure!(
        m.get("FragmentPath") == Some(&o.installed.to_str().context("installed UTF8")?),
        "current FragmentPath differs"
    );
    installed_bytes(&o.installed, &o.recipe)?;
    let binary = Input {
        binding: o.binary.clone(),
        kind: InputKind::Executable,
        json_type: None,
        children: Vec::new(),
    };
    artifact(&binary)?;
    ensure!(
        fs::read_link("/proc/self/exe")? == o.binary.path,
        "current binary path differs"
    );
    let argv: Vec<_> = fs::read("/proc/self/cmdline")?
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| String::from_utf8(b.to_vec()))
        .collect::<std::result::Result<_, _>>()?;
    ensure!(argv == o.argv, "current actual argv mismatch");
    let transport = small(&o.digest_transport, 0)?;
    let digest = std::str::from_utf8(&transport)?
        .strip_prefix("HORIZON_INDEX_PLAN_SHA256=")
        .and_then(|s| s.strip_suffix('\n'))
        .context("noncanonical digest transport")?;
    ensure!(
        valid_sha(digest)
            && std::env::var("HORIZON_INDEX_PLAN_SHA256")? == digest
            && hash(&small(&o.plan_path, 0)?) == digest,
        "current digest transport/plan mismatch"
    );
    ensure!(
        m.get("EnvironmentFiles")
            == Some(&format!("{} (ignore_errors=no)", o.digest_transport.display()).as_str()),
        "current EnvironmentFile changed"
    );
    let mut writable = BTreeSet::from([p.state.clone()]);
    for i in &p.indexes {
        writable.insert(i.path.parent().context("index parent")?.to_path_buf());
    }
    ensure!(
        set_paths(m.get("ReadWritePaths").context("missing writablepaths")?)? == writable
            && set_paths(m.get("ReadOnlyPaths").context("missing readonlypaths")?)?
                == o.expected_read_only_paths.iter().cloned().collect()
            && m.get("BindReadOnlyPaths") == Some(&o.expected_bind_read_only_paths.as_str()),
        "current sandbox path sets changed"
    );
    let object = format!(
        "/org/freedesktop/systemd1/unit/{}",
        o.unit
            .bytes()
            .map(|b| if b.is_ascii_alphanumeric() {
                char::from(b).to_string()
            } else {
                format!("_{b:02x}")
            })
            .collect::<String>()
    );
    for property in [
        "ExecStart",
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
    ] {
        let out = native_output(
            "/usr/bin/busctl",
            &[
                "--json=short",
                "--timeout=2s",
                "get-property",
                "org.freedesktop.systemd1",
                &object,
                "org.freedesktop.systemd1.Service",
                property,
            ],
        )?;
        ensure!(
            out.status.success(),
            "current command array native query failed"
        );
        let commands = parse_commands(&out.stdout)?;
        if property == "ExecStart" {
            ensure!(
                commands.len() == 1
                    && commands[0].0 == o.binary.path.to_string_lossy()
                    && commands[0].1 == o.argv
                    && !commands[0].2,
                "current ExecStart is not exactly one bound command"
            );
        } else {
            ensure!(
                commands.is_empty(),
                "unexpected current condition/hook/reload command"
            );
        }
    }
    ensure!(
        start_ticks(&fs::read_to_string("/proc/self/stat")?)? == ticks,
        "current process changed during authentication"
    );
    let caps = BTreeSet::from(["cap_dac_override", "cap_sys_ptrace"]);
    for key in ["CapabilityBoundingSet", "AmbientCapabilities"] {
        let got: BTreeSet<_> = m
            .get(key)
            .context("missing capability set")?
            .split_whitespace()
            .collect();
        ensure!(got == caps, "current capability set differs");
    }
    let status = fs::read_to_string("/proc/self/status")?;
    ensure!(
        status
            .lines()
            .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["Uid:", "0", "0", "0", "0"])
            && status.lines().any(|l| l == "NoNewPrivs:\t1")
            && status.lines().any(|l| l == "CapEff:\t0000000000080002"),
        "current UID/no-new-privileges differs"
    );
    let cg = PathBuf::from(format!("/sys/fs/cgroup{expected_group}"));
    ensure!(
        fs::read_to_string(cg.join("memory.max"))?.trim() == "2147483648"
            && fs::read_to_string(cg.join("memory.swap.max"))?.trim() == "0"
            && fs::read_to_string(cg.join("pids.max"))?.trim() == "512",
        "current kernel resource policy differs"
    );
    let cpu = fs::read_to_string(cg.join("cpu.max"))?;
    let cp: Vec<_> = cpu.split_whitespace().collect();
    ensure!(
        cp.len() == 2 && Some(cp[0].parse::<u64>()?) == cp[1].parse::<u64>()?.checked_mul(2),
        "current kernel CPU policy differs"
    );
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    for path in &writable {
        ensure!(
            mount_access(&mountinfo, path)? == "rw",
            "current mutation mount is not writable"
        );
    }
    for path in [
        &o.binary.path,
        &o.recipe.path,
        &o.plan_path,
        &o.digest_transport,
    ] {
        ensure!(
            mount_access(&mountinfo, path)? == "ro",
            "current authority input is not read-only"
        );
    }
    let last = systemctl(&[
        "show",
        &o.unit,
        "--all",
        "--property=Id,InvocationID,MainPID,ControlPID,ActiveState,SubState,NRestarts,ControlGroup",
    ])?;
    let last = props(&last)?;
    for k in [
        "Id",
        "InvocationID",
        "MainPID",
        "ControlPID",
        "ActiveState",
        "SubState",
        "NRestarts",
        "ControlGroup",
    ] {
        ensure!(
            last.get(k) == m.get(k),
            "current native owner changed during authentication"
        );
    }
    Ok(
        json!({"process_status":status,"mountinfo_sha256":hash(mountinfo.as_bytes()),"pid":own,"start_ticks":ticks,"invocation_id":iid,"unit":o.unit,"argv":argv,"native":m,"self_source_recipe":o.recipe,"plan_sha256":digest}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ev(path: &str) -> Evidence {
        Evidence {
            path: path.into(),
            sha256: "a".repeat(64),
            uid: 0,
        }
    }
    fn input(path: &str, children: &[&str]) -> Input {
        Input {
            binding: ev(path),
            kind: InputKind::Json,
            json_type: Some(JsonType::PriorIndexPlan),
            children: children.iter().map(PathBuf::from).collect(),
        }
    }
    fn recipe() -> Recipe {
        let (installed, sha, unit, role) = FIXED_RECIPES[0];
        Recipe {
            installed: installed.into(),
            original: Evidence {
                sha256: sha.into(),
                ..ev(&format!("/var/lib/jetstreamer/retained/{unit}"))
            },
            role,
            terminal_actor: Actor {
                unit: unit.into(),
                invocation_id: "a".repeat(32),
                historical_provenance: None,
            },
            readset_review: ev("/var/lib/jetstreamer/readset.json"),
            inputs: vec![input("/var/lib/jetstreamer/helper.json", &[])],
        }
    }
    #[test]
    fn exact_historical_role_registry_rejects_renamed_rehashed_or_retyped_recipes() {
        assert_eq!(FIXED_RECIPES.len(), 12);
        for (p, h, u, r) in FIXED_RECIPES {
            assert!(fixed_role(Path::new(p), h, u, *r));
            assert!(!fixed_role(Path::new(p), &"0".repeat(64), u, *r));
            assert!(!fixed_role(Path::new(p), h, "foreign.service", *r));
        }
        let mut p = crate::tests::plan();
        p.typed_recipes.push(recipe());
        validate(&p).unwrap();
        p.typed_recipes[0].role = RecipeRole::Publication;
        assert!(validate(&p).is_err());
        p.typed_recipes[0] = recipe();
        p.typed_recipes[0].installed = "/etc/systemd/system/another.service".into();
        assert!(validate(&p).is_err());
    }
    #[test]
    fn direct_installation_is_distinct_from_enabled_dependencies_or_alias_paths() {
        let u = "horizon-235237-index923-check-only-v1.service";
        assert!(direct_installed_path(
            &Path::new("/etc/systemd/system").join(u),
            u
        ));
        assert!(!direct_installed_path(
            &Path::new("/etc/systemd/system/multi-user.target.wants").join(u),
            u
        ));
        assert!(!direct_installed_path(
            &Path::new("/run/systemd/system/foreign.service.requires").join(u),
            u
        ));
        assert!(!direct_installed_path(
            Path::new("/etc/systemd/system/alias.service"),
            u
        ));
        let mut p = crate::tests::plan();
        p.typed_recipes.push(recipe());
        let body = format!("[Service]\nExecStart=/bin/true\n# {u}\n");
        assert!(
            staged(
                &p,
                &Path::new("/etc/systemd/system/foreign.target.wants").join(u),
                body.as_bytes(),
                ""
            )
            .is_err()
        );
    }
    #[test]
    fn transitive_graph_missing_children_cycles_duplicates_and_payload_nodes_reject() {
        let mut p = crate::tests::plan();
        p.typed_recipes.push(recipe());
        p.typed_recipes[0].inputs = vec![input(
            "/var/lib/jetstreamer/a.json",
            &["/var/lib/jetstreamer/missing.json"],
        )];
        assert!(validate(&p).is_err());
        p.typed_recipes[0].inputs = vec![
            input(
                "/var/lib/jetstreamer/a.json",
                &["/var/lib/jetstreamer/b.json"],
            ),
            input(
                "/var/lib/jetstreamer/b.json",
                &["/var/lib/jetstreamer/a.json"],
            ),
        ];
        assert!(validate(&p).is_err());
        p.typed_recipes[0].inputs = vec![
            input("/var/lib/jetstreamer/a.json", &[]),
            input("/var/lib/jetstreamer/a.json", &[]),
        ];
        assert!(validate(&p).is_err());
        for name in [
            "epoch-235.jet",
            "epoch-235.index",
            "payload.car",
            "state.sst",
            "snapshot.zst",
        ] {
            assert!(!safe_input(&input(
                &format!("/var/lib/jetstreamer/{name}"),
                &[]
            )));
        }
        assert!(!safe_input(&input(
            "/var/lib/jetstreamer/../escape.json",
            &[]
        )));
    }
    #[test]
    fn current_operation_without_real_identity_cannot_gain_a_self_pid_exemption() {
        let p = crate::tests::plan();
        assert!(authenticate_current(&p).is_err());
    }
    #[test]
    fn indirect_spec_commands_remain_live_references_between_file_opens() {
        let mut p = crate::tests::plan();
        p.typed_recipes.push(recipe());
        let path = "/var/lib/jetstreamer/helper.json";
        assert!(indirect_reference(
            format!("helper\0--plan={path}\0").as_bytes(),
            &p
        ));
        assert!(!indirect_reference(
            format!("helper\0--plan={path}-different\0").as_bytes(),
            &p
        ));
        assert!(recipe_mentions(
            p.typed_recipes[0].terminal_actor.unit.as_bytes(),
            &p
        ));
    }
    #[test]
    fn native_terminal_recipe_triggers_dropins_and_jobs_require_explicit_absence() {
        let clean = "Triggers=\nTriggeredBy=\nOnSuccess=\nOnFailure=\nDropInPaths=\nJob=\n";
        no_triggers(&props(clean).unwrap()).unwrap();
        for (old, new) in [
            ("Triggers=\n", "Triggers=another.service\n"),
            ("TriggeredBy=\n", "TriggeredBy=another.timer\n"),
            ("DropInPaths=\n", "DropInPaths=/etc/override.conf\n"),
            ("Job=\n", "Job=42\n"),
        ] {
            assert!(no_triggers(&props(&clean.replace(old, new)).unwrap()).is_err());
        }
        assert!(no_triggers(&props("Job=\n").unwrap()).is_err());
        assert!(props(&format!("{clean}Job=\n")).is_err());
    }
    #[test]
    fn process_start_ticks_parser_handles_spaces_and_parentheses_in_comm() {
        let row = format!(
            "42 (worker (with space)) S {}",
            (1..=25)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert_eq!(start_ticks(&row).unwrap(), 19);
        assert!(start_ticks("42 broken process stat").is_err());
    }
    #[test]
    fn unchanged_transitive_json_hash_custody_and_type_are_all_required() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("spec.json");
        fs::write(&p,serde_json::to_vec(&json!({"schema":"jetstreamer-horizon-r2-receipt-v1","epoch":235,"bucket":"solana-archive-with-accounts-data","archive_key":"epoch-235.jet","checksum_key":"epoch-235.jet.sha256","remote_sha256_readback":true,"archive_length":1,"archive_sha256":"a".repeat(64)})).unwrap()).unwrap();
        let mut i = Input {
            binding: Evidence {
                path: p.clone(),
                sha256: hash(&fs::read(&p).unwrap()),
                uid: fs::metadata(&p).unwrap().uid(),
            },
            kind: InputKind::Json,
            json_type: Some(JsonType::CanonicalR2Receipt),
            children: Vec::new(),
        };
        artifact(&i).unwrap();
        fs::write(&p, b"{\"schema\":\"changed\"}").unwrap();
        assert!(artifact(&i).is_err());
        i.binding.sha256 = hash(&fs::read(&p).unwrap());
        i.kind = InputKind::Executable;
        i.json_type = None;
        assert!(artifact(&i).is_err());
        i.kind = InputKind::Json;
        i.json_type = Some(JsonType::CanonicalR2Receipt);
        fs::write(&p, b"not JSON").unwrap();
        i.binding.sha256 = hash(&fs::read(&p).unwrap());
        assert!(artifact(&i).is_err());
    }
    #[test]
    fn operations_use_acyclic_env_digest_transport_and_exact_narrow_cli() {
        let mut p = crate::tests::plan();
        let bin = ev("/var/lib/jetstreamer/sealed/retire-index");
        let o = Operation {
            unit: "horizon-235237-index939-check-only-v1.service".into(),
            installed: "/etc/systemd/system/horizon-235237-index939-check-only-v1.service".into(),
            recipe: ev(
                "/var/lib/jetstreamer/operation/horizon-235237-index939-check-only-v1.service",
            ),
            binary: bin.clone(),
            plan_path: "/var/lib/jetstreamer/operation/plan.json".into(),
            digest_transport: "/var/lib/jetstreamer/operation/digest.env".into(),
            check_only: true,
            argv: vec![
                bin.path.display().to_string(),
                "--plan".into(),
                "/var/lib/jetstreamer/operation/plan.json".into(),
                "--plan-sha256".into(),
                "env".into(),
                "--self-sha256".into(),
                bin.sha256,
                "--check-only".into(),
            ],
            expected_read_only_paths: Vec::new(),
            expected_bind_read_only_paths: String::new(),
        };
        p.current_operation = Some(o);
        validate(&p).unwrap();
        p.current_operation.as_mut().unwrap().argv[4] = "a".repeat(64);
        assert!(validate(&p).is_err());
        p.current_operation.as_mut().unwrap().argv[4] = "env".into();
        p.current_operation.as_mut().unwrap().check_only = false;
        assert!(validate(&p).is_err());
    }
}
#[cfg(test)]
mod additional_tests {
    use super::*;
    #[test]
    fn effective_mount_uses_longest_path_and_keeps_separate_source_state_bindings() {
        let m = "1 0 8:1 / / ro - ext4 /dev/x ro\n2 1 8:1 /source /source rw - ext4 /dev/x rw\n3 1 8:1 /state /state rw - ext4 /dev/x rw\n";
        assert_eq!(
            mount_access(m, Path::new("/source/member.index")).unwrap(),
            "rw"
        );
        assert_eq!(
            mount_access(m, Path::new("/source-sibling/member.index")).unwrap(),
            "ro"
        );
        assert_eq!(
            mount_access(m, Path::new("/state/receipt.json")).unwrap(),
            "rw"
        );
        assert!(mount_access("bad row", Path::new("/state")).is_err());
    }
    #[test]
    fn convergent_dag_is_verified_once_per_node_instead_of_path_expansion() {
        let inputs: Vec<_> = (0..100)
            .map(|n| Input {
                binding: Evidence {
                    path: format!("/var/lib/n{n}.json").into(),
                    sha256: "a".repeat(64),
                    uid: 0,
                },
                kind: InputKind::Json,
                json_type: Some(JsonType::CanonicalR2Receipt),
                children: ((n + 1)..(n + 3).min(100))
                    .map(|k| PathBuf::from(format!("/var/lib/n{k}.json")))
                    .collect(),
            })
            .collect();
        let mut done = BTreeSet::new();
        graph_walk(
            &inputs[0].binding.path,
            &inputs,
            &mut BTreeSet::new(),
            &mut done,
        )
        .unwrap();
        assert_eq!(done.len(), 100);
    }
}
#[cfg(test)]
mod command_tests {
    use super::*;
    #[test]
    fn typed_native_command_array_preserves_single_sequence_argv_and_ignore_errors() {
        let row = json!([
            "/sealed/tool",
            ["/sealed/tool", "--plan", "/sealed/plan.json"],
            false,
            0,
            0,
            0,
            0,
            42,
            0,
            0
        ]);
        let v = json!({"type":"a(sasbttttuii)","data":[[row.clone()]]});
        let commands = parse_commands(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0].1,
            vec!["/sealed/tool", "--plan", "/sealed/plan.json"]
        );
        assert!(!commands[0].2);
        let two = json!({"type":"a(sasbttttuii)","data":[[row.clone(),row]]});
        assert_eq!(
            parse_commands(&serde_json::to_vec(&two).unwrap())
                .unwrap()
                .len(),
            2
        );
        assert!(parse_commands(br#"{"type":"as","data":[[]]}"#).is_err());
        assert!(parse_commands(br#"{"type":"a(sasbttttuii)","data":[]}"#).is_err());
        assert!(
            parse_commands(
                &serde_json::to_vec(&json!({"type":"a(sasbttttuii)","data":[[["tool",[],false]]]}))
                    .unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn shared_preflight_provenance_is_not_a_selected_cache_consumer() {
        let path = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/preflight-233-301-target1-offline-publish300.json";
        let input = Input {
            binding: Evidence {
                path: path.into(),
                sha256: "a".repeat(64),
                uid: 0,
            },
            kind: InputKind::Json,
            json_type: Some(JsonType::PreflightV4),
            children: vec![],
        };
        assert!(!consumer_input(&input));
        let mut p = crate::tests::plan();
        let (pth, h, unit, role) = FIXED_RECIPES[0];
        p.typed_recipes.push(Recipe {
            installed: pth.into(),
            original: Evidence {
                path: "/var/lib/jetstreamer/old.service".into(),
                sha256: h.into(),
                uid: 0,
            },
            role,
            terminal_actor: Actor {
                unit: unit.into(),
                invocation_id: "a".repeat(32),
                historical_provenance: None,
            },
            readset_review: Evidence {
                path: "/var/lib/jetstreamer/review.json".into(),
                sha256: "b".repeat(64),
                uid: 0,
            },
            inputs: vec![input],
        });
        for epoch in [236, 241, 245] {
            let argv = format!(
                "/sealed/jetstreamer-node\0{epoch}\0/home/ubuntu/.jetstreamer-private/qualification-{epoch}/output\0--cohort-manifest={path}\0"
            );
            assert!(!indirect_reference(argv.as_bytes(), &p));
        }
        let mut script = p.typed_recipes[0].inputs[0].clone();
        script.kind = InputKind::Script;
        script.json_type = None;
        script.binding.path = "/sealed/namespace-probe.sh".into();
        p.typed_recipes[0].inputs.push(script);
        assert!(indirect_reference(
            b"/bin/sh\0/sealed/namespace-probe.sh\0",
            &p
        ));
        assert!(recipe_reference(
            format!("node\0235\0{}/output\0", p.owners[0].root.display()).as_bytes(),
            &p
        ));
    }
}
#[cfg(test)]
mod coverage_tests {
    use super::*;
    #[test]
    fn current_imported_profile_requires_all_known_recipe_roles_not_optional_subsets() {
        let all: BTreeSet<_> = FIXED_RECIPES
            .iter()
            .map(|(p, _, _, _)| PathBuf::from(p))
            .collect();
        assert!(complete_fixed_registry(&all));
        assert!(!complete_fixed_registry(&BTreeSet::new()));
        for (p, _, _, _) in FIXED_RECIPES {
            let mut missing = all.clone();
            missing.remove(Path::new(p));
            assert!(!complete_fixed_registry(&missing));
        }
    }
}
