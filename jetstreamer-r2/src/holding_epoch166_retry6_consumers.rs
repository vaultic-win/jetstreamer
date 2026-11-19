//! Bounded reverse reference graph plus separately evidenced native/dynamic
//! reader review. A direct empty source census does not satisfy this gate.
use super::*;
use std::collections::BTreeSet;

const SEALED: &str = "/usr/local/lib/jetstreamer";
// The native host inventory contains 104,491 metadata files / 15,425,505,635
// bytes, including a 66,027,261-byte historical frame. Execution requires a
// separately admitted 32 GiB census envelope, not the 4 GiB compiler envelope.
const CENSUS_BYTES: u64 = 20 << 30;
const METADATA_BYTES: u64 = 64 << 20;
const ROOTS: [&str; 15] = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/run/systemd/transient",
    "/usr/lib/systemd/system",
    "/run/systemd/generator",
    "/run/systemd/generator.early",
    "/run/systemd/generator.late",
    "/home/sol/.config/systemd/user",
    "/etc/crontab",
    "/etc/cron.d",
    "/var/spool/cron/crontabs",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];
const CLASSES: [&str; 7] = [
    "producer-controller",
    "libraries-and-relative-inputs",
    "sealed-launch-plans",
    "timer-path-cron",
    "future-builds",
    "recovery",
    "live-accounting-and-witness-roots",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    file: Bound,
    edges: Vec<PathBuf>,
    disposition: String,
    owner_units: Vec<String>,
    semantic_evidence: Vec<Bound>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Compiled {
    image: Bound,
    reviewed_source: Vec<Bound>,
    owner_units: Vec<String>,
    no_local_partial_required: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    schema: String,
    owner: String,
    source: PathBuf,
    sha256: String,
    length: u64,
    inspection: Bound,
    park_plan: Bound,
    park_terminal: Bound,
    recorded_unix_seconds: u64,
    sealed_metadata_root: PathBuf,
    definition_roots: Vec<PathBuf>,
    sealed_metadata_census_sha256: String,
    definition_census_sha256: String,
    nodes: Vec<Node>,
    compiled_consumers: Vec<Compiled>,
    classes: Vec<Value>,
    unresolved_edges: Vec<Value>,
    complete_transitive_consumer_graph_qualified: bool,
    dynamic_native_and_future_consumers_reviewed: bool,
    no_reopening_until_retirement_complete: bool,
    resource_promises_and_live_witness_ancestors_preserved: bool,
}
#[derive(Clone)]
struct Artifact {
    sha256: String,
    bytes: Vec<u8>,
    definition: bool,
}
fn literal_edges_raw(
    bytes: &[u8],
    corpus: &BTreeMap<PathBuf, Artifact>,
    targets: &BTreeSet<PathBuf>,
    aliases: &BTreeMap<PathBuf, PathBuf>,
) -> BTreeSet<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut edges = BTreeSet::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'/' {
            at += 1;
            continue;
        }
        let mut end = at + 1;
        while end < bytes.len() && !b"\0\n\r\t '\";|&()<>[]{},:\\".contains(&bytes[end]) {
            end += 1;
        }
        if end - at <= 4096 {
            let path = Path::new(std::ffi::OsStr::from_bytes(&bytes[at..end]));
            for candidate in path.ancestors() {
                if targets.contains(candidate) || corpus.contains_key(candidate) {
                    edges.insert(candidate.to_owned());
                }
                if let Some(canonical) = aliases.get(candidate)
                    && let Ok(suffix) = path.strip_prefix(candidate)
                {
                    let resolved = canonical.join(suffix);
                    for target in resolved.ancestors() {
                        if targets.contains(target) || corpus.contains_key(target) {
                            edges.insert(target.to_owned());
                        }
                    }
                }
            }
        }
        at = end;
    }
    edges
}
fn literal_edges(
    bytes: &[u8],
    corpus: &BTreeMap<PathBuf, Artifact>,
    targets: &BTreeSet<PathBuf>,
    aliases: &BTreeMap<PathBuf, PathBuf>,
) -> BTreeSet<PathBuf> {
    let mut edges = literal_edges_raw(bytes, corpus, targets, aliases);
    // Decode bounded valid JSON too: escaped separators must not hide paths.
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        let mut pending = vec![value];
        while let Some(value) = pending.pop() {
            match value {
                Value::String(text) => {
                    edges.extend(literal_edges_raw(text.as_bytes(), corpus, targets, aliases))
                }
                Value::Array(values) => pending.extend(values),
                Value::Object(values) => {
                    for (key, value) in values {
                        edges.extend(literal_edges_raw(key.as_bytes(), corpus, targets, aliases));
                        pending.push(value);
                    }
                }
                _ => (),
            }
        }
    }
    edges
}
fn read_artifact(b: &Bound, max: u64, immutable: bool) -> Result<Vec<u8>> {
    ensure!(
        b.path.is_absolute()
            && b.path != Path::new(SOURCE)
            && b.path != Path::new(QUARANTINE)
            && digest(&b.sha256),
        "unsafe consumer artifact binding"
    );
    let md = fs::symlink_metadata(&b.path)?;
    ensure!(
        md.is_file()
            && md.nlink() == 1
            && md.uid() == 0
            && md.mode() & if immutable { 0o222 } else { 0o022 } == 0
            && md.len() <= max
            && b.path.canonicalize()? == b.path,
        "consumer artifact not in required custody"
    );
    let bytes = read_stable_bounded(&b.path, max, "retry6 consumer artifact")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "transitive consumer artifact changed"
    );
    Ok(bytes)
}
fn metadata_candidate(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()).is_some_and(|s| {
        [
            "json", "py", "sh", "rs", "toml", "conf", "service", "timer", "path", "socket", "txt",
            "md",
        ]
        .contains(&s)
    })
}
fn masked(path: &Path) -> Result<bool> {
    let md = fs::symlink_metadata(path)?;
    let unit = path.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
        [
            ".service",
            ".timer",
            ".socket",
            ".path",
            ".target",
            ".scope",
            ".slice",
            ".mount",
            ".automount",
            ".swap",
        ]
        .iter()
        .any(|end| s.ends_with(end))
    });
    Ok(unit
        && md.uid() == 0
        && md.file_type().is_symlink()
        && fs::read_link(path)? == Path::new("/dev/null"))
}
fn canonical_metadata_path(path: &Path, definition: bool) -> Result<PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) => {
            // Existing generated relative alias is resolved by PID1 to the
            // distribution fragment, as in the qualified compiler cleaner.
            let alias = Path::new(
                "/run/systemd/generator/multi-user.target.wants/systemd-networkd.service",
            );
            let fragment = Path::new("/usr/lib/systemd/system/systemd-networkd.service");
            ensure!(
                definition
                    && path == alias
                    && fs::symlink_metadata(path)?.uid() == 0
                    && fs::read_link(path)? == Path::new("../systemd-networkd.service"),
                "transitive census contains an unresolved alias: {}: {error}",
                path.display()
            );
            let row = native("systemd-networkd.service")?;
            ensure!(row["Id"] == "systemd-networkd.service" && row["LoadState"] == "loaded"
                && row["FragmentPath"] == fragment.to_str().unwrap() && row["DropInPaths"] == ""
                && row["ExecStart"].as_str().is_some_and(|s| s.starts_with("{ path=/usr/lib/systemd/systemd-networkd ; argv[]=/usr/lib/systemd/systemd-networkd ; ignore_errors=no ;")),
                "generated network alias native resolution changed");
            let md = fs::symlink_metadata(fragment)?;
            let bytes = read_stable_bounded(fragment, 1 << 20, "network fragment")?;
            ensure!(
                md.is_file()
                    && md.uid() == 0
                    && md.gid() == 0
                    && md.mode() & 0o022 == 0
                    && hex_lower(&Sha256::digest(bytes))
                        == "38ab8b44491353e11502b1eab3a8e67cd1845845397ae09db36e211a6d8bfce7",
                "distribution network fragment changed"
            );
            Ok(fragment.to_owned())
        }
    }
}
fn census_walk(
    path: &Path,
    definition: bool,
    depth: usize,
    seen: &mut BTreeSet<PathBuf>,
    out: &mut BTreeMap<PathBuf, Artifact>,
    budget: &mut (usize, u64),
    aliases: &mut BTreeMap<PathBuf, PathBuf>,
) -> Result<()> {
    budget.0 += 1;
    ensure!(
        depth <= 32 && budget.0 <= 200_000 && budget.1 <= CENSUS_BYTES,
        "transitive metadata census exceeded admitted bound"
    );
    if path.starts_with(LIFECYCLE) {
        return Ok(());
    }
    let link = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if definition && masked(path)? {
        out.insert(
            path.to_owned(),
            Artifact {
                sha256: hex_lower(&Sha256::digest(b"root-owned mask /dev/null")),
                bytes: vec![],
                definition,
            },
        );
        return Ok(());
    }
    let canonical = canonical_metadata_path(path, definition)?;
    ensure!(
        !canonical.starts_with(LIFECYCLE),
        "external staged alias into retirement package requires explicit closure"
    );
    if path != canonical {
        aliases.insert(path.to_owned(), canonical.clone());
    }
    if !seen.insert(canonical.clone()) {
        return Ok(());
    }
    let md = fs::metadata(&canonical)?;
    if md.is_dir() {
        for entry in fs::read_dir(path)? {
            census_walk(
                &entry?.path(),
                definition,
                depth + 1,
                seen,
                out,
                budget,
                aliases,
            )?;
        }
    } else if md.is_file() {
        if !definition && !metadata_candidate(path) {
            return Ok(());
        }
        ensure!(
            [0, 1001].contains(&md.uid())
                && md.nlink() == 1
                && md.mode() & 0o022 == 0
                && md.len() <= METADATA_BYTES,
            "unsafe or oversized transitive metadata: {}",
            path.display()
        );
        if !definition {
            ensure!(
                md.uid() == 0 && !link.file_type().is_symlink(),
                "installed metadata must remain root-controlled"
            );
        }
        let bytes = read_stable_bounded(&canonical, METADATA_BYTES, "transitive metadata")?;
        budget.1 = budget
            .1
            .checked_add(bytes.len() as u64)
            .context("consumer census byte overflow")?;
        ensure!(
            budget.1 <= CENSUS_BYTES,
            "consumer census byte bound exceeded"
        );
        out.insert(
            canonical,
            Artifact {
                sha256: hex_lower(&Sha256::digest(&bytes)),
                bytes,
                definition,
            },
        );
    } else {
        bail!("unexpected transitive metadata type: {}", path.display());
    }
    Ok(())
}
fn corpus_digest(corpus: &BTreeMap<PathBuf, Artifact>) -> Result<String> {
    let rows: BTreeMap<_, _> = corpus
        .iter()
        .map(|(path, item)| (path, &item.sha256))
        .collect();
    Ok(hex_lower(&Sha256::digest(serde_json::to_vec(&rows)?)))
}
fn reverse_graph(
    corpus: &BTreeMap<PathBuf, Artifact>,
    aliases: &BTreeMap<PathBuf, PathBuf>,
) -> Result<BTreeMap<PathBuf, BTreeSet<PathBuf>>> {
    let targets = BTreeSet::from([
        PathBuf::from(SOURCE),
        PathBuf::from(RUN),
        PathBuf::from(DESTINATION),
    ]);
    // Parse each text body once. Repeated full-corpus substring searches for
    // every newly discovered node are prohibitively expensive on this host.
    let mut all_edges = BTreeMap::new();
    let mut readers: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
    let mut edge_count = 0usize;
    for (path, item) in corpus {
        let edges = literal_edges(&item.bytes, corpus, &targets, aliases);
        edge_count = edge_count
            .checked_add(edges.len())
            .context("reader edge overflow")?;
        ensure!(
            edge_count <= 2_000_000,
            "literal reader graph exceeds bound"
        );
        for target in &edges {
            readers
                .entry(target.clone())
                .or_default()
                .insert(path.clone());
        }
        all_edges.insert(path.clone(), edges);
    }
    let mut selected = BTreeSet::new();
    let mut queue: Vec<_> = targets.iter().cloned().collect();
    while let Some(target) = queue.pop() {
        if let Some(incoming) = readers.get(&target) {
            for reader in incoming {
                if selected.insert(reader.clone()) {
                    queue.push(reader.clone());
                }
            }
        }
        ensure!(
            selected.len() <= 4096,
            "transitive reader graph exceeds bound"
        );
    }
    let mut graph = BTreeMap::new();
    for path in &selected {
        graph.insert(
            path.clone(),
            all_edges[path]
                .iter()
                .filter(|target| targets.contains(*target) || selected.contains(*target))
                .cloned()
                .collect(),
        );
    }
    Ok(graph)
}
fn review_shape(r: &Review, p: &Retire, now: u64) -> Result<()> {
    ensure!(
        r.schema == "horizon-closed166-retry6-transitive-consumer-closure-v1"
            && r.owner == "/root"
            && r.source == Path::new(SOURCE)
            && r.sha256 == SHA
            && r.length == LENGTH
            && same_bound(&r.inspection, &p.inspection)
            && same_bound(&r.park_plan, &binding(PARK_PLAN, PARK_PLAN_SHA))
            && same_bound(&r.park_terminal, &p.park_terminal)
            && r.recorded_unix_seconds <= now
            && now - r.recorded_unix_seconds <= 1800
            && r.sealed_metadata_root == Path::new(SEALED)
            && r.definition_roots
                == ROOTS
                    .iter()
                    .map(|root| PathBuf::from(*root))
                    .collect::<Vec<_>>()
            && r.complete_transitive_consumer_graph_qualified
            && r.dynamic_native_and_future_consumers_reviewed
            && r.no_reopening_until_retirement_complete
            && r.resource_promises_and_live_witness_ancestors_preserved
            && r.unresolved_edges.is_empty()
            && !r.nodes.is_empty()
            && r.nodes.len() <= 4096,
        "genuine fresh complete retry6 transitive reader graph required"
    );
    let classes: BTreeSet<_> = r
        .classes
        .iter()
        .map(|row| row["class"].as_str().context("consumer class"))
        .collect::<Result<_>>()?;
    ensure!(
        r.classes.len() == CLASSES.len() && classes == CLASSES.into_iter().collect(),
        "incomplete native/dynamic reader classes"
    );
    for row in &r.classes {
        ensure!(
            row["no_local_archive_required"] == true
                && row["reason"].as_str().is_some_and(|s| !s.trim().is_empty())
                && row["inspected_inputs"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty() && items.len() <= 64),
            "consumer class has no concrete reviewed evidence"
        );
    }
    ensure!(
        r.compiled_consumers.len() >= 2 && r.compiled_consumers.len() <= 128,
        "compiled consumer review missing"
    );
    Ok(())
}
fn owner_units(units: &[String], p: &Retire) -> Result<()> {
    ensure!(
        !units.is_empty() && units.len() <= 32,
        "consumer has no terminal owner binding"
    );
    for unit in units {
        ensure!(
            !unit.starts_with('-')
                && !unit.contains('/')
                && unit.len() <= 255
                && unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.@\\".contains(&b)),
            "unsafe consumer owner name"
        );
        if unit == PARK {
            park(p)?;
        } else {
            closed(&native(unit)?, unit)?;
        }
    }
    Ok(())
}
fn graph_matches(
    r: &Review,
    corpus: &BTreeMap<PathBuf, Artifact>,
    graph: &BTreeMap<PathBuf, BTreeSet<PathBuf>>,
) -> Result<()> {
    let mut found = BTreeSet::new();
    for node in &r.nodes {
        ensure!(
            found.insert(node.file.path.clone()),
            "duplicate reviewed consumer node"
        );
        let artifact = corpus
            .get(&node.file.path)
            .context("reviewed consumer absent from fresh census")?;
        let edges: BTreeSet<_> = node.edges.iter().cloned().collect();
        ensure!(
            node.file.sha256 == artifact.sha256
                && edges.len() == node.edges.len()
                && graph.get(&node.file.path) == Some(&edges),
            "transitive consumer bytes or dependency edges changed"
        );
        ensure!(
            !node.semantic_evidence.is_empty() && node.semantic_evidence.len() <= 32,
            "consumer disposition lacks real source/evidence bindings"
        );
        match node.disposition.as_str() {
            "closed-consumer" => {
                ensure!(!node.owner_units.is_empty(), "closed consumer has no owner")
            }
            "retained-nonexecuting-evidence" => ensure!(
                !artifact.definition && node.owner_units.is_empty(),
                "executable definition cannot be waived as inert evidence"
            ),
            _ => bail!("unqualified transitive consumer disposition"),
        }
    }
    ensure!(
        found == graph.keys().cloned().collect(),
        "transitive closure omits discovered consumers"
    );
    Ok(())
}
struct Corpus {
    all: BTreeMap<PathBuf, Artifact>,
    graph: BTreeMap<PathBuf, BTreeSet<PathBuf>>,
    sealed_sha: String,
    definitions_sha: String,
    entries: usize,
    bytes: u64,
}
fn collect() -> Result<Corpus> {
    let mut sealed = BTreeMap::new();
    let mut definitions = BTreeMap::new();
    let mut budget = (0, 0);
    let mut aliases = BTreeMap::new();
    census_walk(
        Path::new(SEALED),
        false,
        0,
        &mut BTreeSet::new(),
        &mut sealed,
        &mut budget,
        &mut aliases,
    )?;
    let mut seen = BTreeSet::new();
    for root in ROOTS {
        census_walk(
            Path::new(root),
            true,
            0,
            &mut seen,
            &mut definitions,
            &mut budget,
            &mut aliases,
        )?;
    }
    let mut corpus = sealed;
    corpus.extend(definitions);
    let graph = reverse_graph(&corpus, &aliases)?;
    // Stable-read every installed file to discover dependencies, including
    // old root-writable tools. Such a tool cannot enter an accepted relevant
    // closure unless its metadata is immutable; unrelated installed tools do
    // not constitute an archive dependency.
    for path in graph.keys().filter(|path| !corpus[*path].definition) {
        ensure!(
            fs::symlink_metadata(path)?.mode() & 0o222 == 0,
            "relevant metadata is writable: {}",
            path.display()
        );
    }
    // Re-enumerate the entire bounded corpus on every gate, but bind only the
    // discovered reverse closure. Unrelated new services/packages (including
    // this lifecycle's own check/execute unit) do not invalidate the proof.
    // Any new direct or transitive reader joins `graph` and must be reviewed.
    let relevant_sealed = corpus
        .iter()
        .filter(|(path, item)| !item.definition && graph.contains_key(*path))
        .map(|(path, item)| (path.clone(), item.clone()))
        .collect();
    let relevant_definitions = corpus
        .iter()
        .filter(|(path, item)| item.definition && graph.contains_key(*path))
        .map(|(path, item)| (path.clone(), item.clone()))
        .collect();
    let sealed_sha = corpus_digest(&relevant_sealed)?;
    let definitions_sha = corpus_digest(&relevant_definitions)?;
    Ok(Corpus {
        all: corpus,
        graph,
        sealed_sha,
        definitions_sha,
        entries: budget.0,
        bytes: budget.1,
    })
}
pub(super) fn inspect(spec: &Bound) -> Result<()> {
    ensure!(
        same_bound(spec, &binding(PARK_PLAN, PARK_PLAN_SHA))
            && fs::read_link("/proc/self/exe")?.parent() == Some(Path::new(LIFECYCLE)),
        "retry6 consumer census requires the exact existing park plan and sealed lifecycle tool"
    );
    let plan: Park = serde_json::from_value(bound(spec)?)?;
    source_scope(&plan, &bound(&plan.eligibility)?)?;
    ensure!(
        plan.source == Path::new(SOURCE) && plan.sha256 == SHA && plan.length == LENGTH,
        "foreign consumer census target"
    );
    let c = collect()?;
    let nodes: Vec<_> = c
        .graph
        .iter()
        .map(|(path, edges)| {
            json!({"file":{"path":path,"sha256":c.all[path].sha256},
        "definition":c.all[path].definition,"edges":edges})
        })
        .collect();
    let receipt = json!({"schema":"horizon-closed166-retry6-transitive-consumer-census-v1","source":SOURCE,"sha256":SHA,"length":LENGTH,
        "park_plan":spec,"sealed_metadata_root":SEALED,"definition_roots":ROOTS,
        "sealed_metadata_census_sha256":c.sealed_sha,"definition_census_sha256":c.definitions_sha,
        "nodes":nodes,"censused_entries":c.entries,"censused_bytes":c.bytes,
        "excluded_exact_lifecycle_package":LIFECYCLE,"compiled_dynamic_future_consumers_qualified":false,
        "complete_transitive_consumer_graph_qualified":false,"local_retirement_authorized":false,
        "data_removed":false,"remote_mutations":false,"resource_credit_bytes":0,
        "recorded_unix_seconds":clock()?});
    ensure!(
        serde_json::to_vec(&receipt)?.len() <= 1 << 20,
        "consumer census receipt exceeds bound; do not truncate graph"
    );
    let path = Path::new(STATE).join("receipts").join(format!(
        "retire166-retry6-consumer-census-{}.json",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    persist(&path, &receipt)?;
    println!("{}", path.display());
    Ok(())
}
pub(super) fn verify(p: &Retire) -> Result<Value> {
    let value = evidence_with_limit(&p.consumer_closure, true, 16 << 20)?;
    let r: Review = serde_json::from_value(value)?;
    review_shape(&r, p, clock()?)?;
    let c = collect()?;
    let sealed_sha = c.sealed_sha;
    let definitions_sha = c.definitions_sha;
    ensure!(
        sealed_sha == r.sealed_metadata_census_sha256
            && definitions_sha == r.definition_census_sha256,
        "metadata/staged-definition corpus changed since transitive review"
    );
    let graph = c.graph;
    graph_matches(&r, &c.all, &graph)?;
    for node in &r.nodes {
        for proof in &node.semantic_evidence {
            read_artifact(proof, 128 << 20, true)?;
        }
        if node.disposition == "closed-consumer" {
            owner_units(&node.owner_units, p)?;
            if c.all[&node.file.path].definition {
                let mut actual_owner = false;
                for unit in &node.owner_units {
                    let row = native(unit)?;
                    actual_owner |= row["FragmentPath"]
                        .as_str()
                        .is_some_and(|path| same_definition(path, &node.file.path))
                        || row["DropInPaths"].as_str().is_some_and(|paths| {
                            paths
                                .split_whitespace()
                                .any(|path| same_definition(path, &node.file.path))
                        });
                }
                ensure!(
                    actual_owner,
                    "staged definition was attributed to an unrelated terminal unit"
                );
            }
        }
    }
    let park_proof = bound(&p.park_terminal)?;
    let park_helper: Bound = serde_json::from_value(park_proof["helper"].clone())?;
    let mut old_node = false;
    let mut park_image = false;
    for item in &r.compiled_consumers {
        ensure!(
            item.no_local_partial_required
                && !item.reviewed_source.is_empty()
                && item.reviewed_source.len() <= 64,
            "compiled reader has unresolved archive dependency"
        );
        read_artifact(&item.image, 128 << 20, true)?;
        for proof in &item.reviewed_source {
            read_artifact(proof, 128 << 20, true)?;
        }
        owner_units(&item.owner_units, p)?;
        old_node |= item.image.path
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-node",
            )
            && item.image.sha256
                == "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65"
            && item.owner_units.iter().any(|u| u == PRODUCER);
        park_image |=
            same_bound(&item.image, &park_helper) && item.owner_units.iter().any(|u| u == PARK);
    }
    ensure!(
        old_node && park_image,
        "actual original node and actual park image are missing from compiled closure"
    );
    for row in &r.classes {
        let inputs: Vec<Bound> = serde_json::from_value(row["inspected_inputs"].clone())?;
        for proof in inputs {
            read_artifact(&proof, 128 << 20, true)?;
        }
    }
    Ok(
        json!({"schema":"horizon-retry6-transitive-consumer-gate-v1","review":p.consumer_closure,
        "sealed_metadata_census_sha256":sealed_sha,"definition_census_sha256":definitions_sha,
        "nodes":graph.len(),"edges":graph.values().map(BTreeSet::len).sum::<usize>(),
        "compiled_consumers":r.compiled_consumers.len(),"censused_entries":c.entries,"censused_bytes":c.bytes,
        "complete_transitive_consumer_graph_qualified":true}),
    )
}

fn same_definition(path: &str, canonical: &Path) -> bool {
    Path::new(path).is_absolute() && Path::new(path).canonicalize().is_ok_and(|p| p == canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn artifact(bytes: &str, definition: bool) -> Artifact {
        Artifact {
            sha256: hex_lower(&Sha256::digest(bytes.as_bytes())),
            bytes: bytes.as_bytes().to_vec(),
            definition,
        }
    }
    #[test]
    fn reverse_graph_follows_definition_wrapper_and_plan_instead_of_only_direct_source_hits() {
        let plan = PathBuf::from("/sealed/plan.json");
        let wrapper = PathBuf::from("/sealed/wrapper.sh");
        let unit = PathBuf::from("/etc/systemd/system/old.service");
        let corpus = BTreeMap::from([
            (plan.clone(), artifact(&format!("source={SOURCE}"), false)),
            (wrapper.clone(), artifact("reader /sealed/plan.json", false)),
            (unit.clone(), artifact("ExecStart=/sealed/wrapper.sh", true)),
            (
                PathBuf::from("/sealed/independent.json"),
                artifact(&format!("path={DESTINATION}-retry8"), false),
            ),
        ]);
        let graph = reverse_graph(&corpus, &BTreeMap::new()).unwrap();
        assert_eq!(graph.len(), 3);
        assert!(graph[&unit].contains(&wrapper));
        assert!(graph[&wrapper].contains(&plan));
        assert!(graph[&plan].contains(Path::new(SOURCE)));
    }
    #[test]
    fn corpus_digest_detects_an_added_or_modified_staged_definition() {
        let mut corpus = BTreeMap::from([(
            PathBuf::from("/unit.service"),
            artifact("ExecStart=/bin/true", true),
        )]);
        let first = corpus_digest(&corpus).unwrap();
        corpus.insert(
            PathBuf::from("/new.timer"),
            artifact("Unit=old.service", true),
        );
        assert_ne!(first, corpus_digest(&corpus).unwrap());
        corpus.remove(Path::new("/new.timer"));
        corpus.insert(
            PathBuf::from("/unit.service"),
            artifact("ExecStart=/sealed/wrapper.sh", true),
        );
        assert_ne!(first, corpus_digest(&corpus).unwrap());
    }
    #[test]
    fn censused_file_and_directory_aliases_cannot_hide_transitive_consumers() {
        let plan = PathBuf::from("/sealed/plan.json");
        let wrapper = PathBuf::from("/sealed/wrapper.sh");
        let unit = PathBuf::from("/etc/systemd/system/reader.service");
        let corpus = BTreeMap::from([
            (plan.clone(), artifact(&format!("source={SOURCE}"), false)),
            (
                wrapper.clone(),
                artifact("reader /input-alias/plan.json", false),
            ),
            (unit.clone(), artifact("ExecStart=/wrapper-alias", true)),
        ]);
        let aliases = BTreeMap::from([
            (PathBuf::from("/input-alias"), PathBuf::from("/sealed")),
            (PathBuf::from("/wrapper-alias"), wrapper.clone()),
        ]);
        let graph = reverse_graph(&corpus, &aliases).unwrap();
        assert_eq!(graph.len(), 3);
        assert!(graph[&unit].contains(&wrapper));
        assert!(graph[&wrapper].contains(&plan));
        let mut changed = aliases;
        changed.insert("/wrapper-alias".into(), "/other-image".into());
        assert_ne!(graph, reverse_graph(&corpus, &changed).unwrap());

        let dir = tempfile::tempdir().unwrap();
        let definition = dir.path().join("reader.service");
        let alias = dir.path().join("alias.service");
        fs::write(&definition, "ExecStart=/bin/true").unwrap();
        std::os::unix::fs::symlink(&definition, &alias).unwrap();
        assert!(same_definition(alias.to_str().unwrap(), &definition));
        assert!(!same_definition(
            alias.to_str().unwrap(),
            Path::new("/other.service")
        ));
    }
    #[test]
    fn json_escaping_and_colon_separated_bind_paths_do_not_hide_consumers() {
        let plan = PathBuf::from("/sealed/plan.json");
        let unit = PathBuf::from("/etc/systemd/system/reader.service");
        let corpus = BTreeMap::from([
            (
                plan.clone(),
                artifact(
                    &format!("{{\"source\":\"{}\"}}", SOURCE.replace('/', "\\/")),
                    false,
                ),
            ),
            (
                unit.clone(),
                artifact(
                    "BindReadOnlyPaths=/sealed/plan.json:/inputs/plan.json",
                    true,
                ),
            ),
        ]);
        let graph = reverse_graph(&corpus, &BTreeMap::new()).unwrap();
        assert!(graph[&plan].contains(Path::new(SOURCE)));
        assert!(graph[&unit].contains(&plan));
    }
    fn review(nodes: Vec<Node>) -> Review {
        Review {
            schema: "horizon-closed166-retry6-transitive-consumer-closure-v1".into(),
            owner: "/root".into(),
            source: SOURCE.into(),
            sha256: SHA.into(),
            length: LENGTH,
            inspection: binding("/sealed/inspection.json", INSPECTION_SHA),
            park_plan: binding(PARK_PLAN, PARK_PLAN_SHA),
            park_terminal: binding("/sealed/terminal.json", &"a".repeat(64)),
            recorded_unix_seconds: 100,
            sealed_metadata_root: SEALED.into(),
            definition_roots: ROOTS.iter().map(|p| PathBuf::from(*p)).collect(),
            sealed_metadata_census_sha256: "b".repeat(64),
            definition_census_sha256: "c".repeat(64),
            nodes,
            compiled_consumers: vec![],
            classes: vec![],
            unresolved_edges: vec![],
            complete_transitive_consumer_graph_qualified: true,
            dynamic_native_and_future_consumers_reviewed: true,
            no_reopening_until_retirement_complete: true,
            resource_promises_and_live_witness_ancestors_preserved: true,
        }
    }
    #[test]
    fn a_partial_graph_or_a_definition_disguised_as_inert_evidence_is_rejected() {
        let plan = PathBuf::from("/sealed/plan.json");
        let unit = PathBuf::from("/etc/systemd/system/consumer.service");
        let corpus = BTreeMap::from([
            (plan.clone(), artifact(&format!("source={SOURCE}"), false)),
            (
                unit.clone(),
                artifact("ExecStart=reader /sealed/plan.json", true),
            ),
        ]);
        let graph = reverse_graph(&corpus, &BTreeMap::new()).unwrap();
        let node = |path: &PathBuf, definition: bool| Node {
            file: binding(path.to_str().unwrap(), &corpus[path].sha256),
            edges: graph[path].iter().cloned().collect(),
            disposition: if definition {
                "closed-consumer"
            } else {
                "retained-nonexecuting-evidence"
            }
            .into(),
            owner_units: if definition {
                vec!["consumer.service".into()]
            } else {
                vec![]
            },
            semantic_evidence: vec![binding("/sealed/review.json", &"d".repeat(64))],
        };
        let mut r = review(vec![node(&plan, false)]);
        assert!(graph_matches(&r, &corpus, &graph).is_err());
        r.nodes.push(node(&unit, true));
        graph_matches(&r, &corpus, &graph).unwrap();
        r.nodes[1].disposition = "retained-nonexecuting-evidence".into();
        r.nodes[1].owner_units.clear();
        assert!(graph_matches(&r, &corpus, &graph).is_err());
        r.nodes[1] = node(&unit, true);
        r.nodes[0].edges.clear();
        assert!(graph_matches(&r, &corpus, &graph).is_err());
    }
}
