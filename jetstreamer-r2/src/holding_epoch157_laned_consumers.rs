//! Bounded reverse reference graph plus separately evidenced native/dynamic
//! reader review. A direct empty source census does not satisfy this gate.
use super::*;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{borrow::Cow, collections::BTreeSet};

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
struct CensusBudget {
    entries: usize,
    bytes: u64,
    started: std::time::Instant,
    last_report: std::time::Instant,
}
impl CensusBudget {
    fn report(&mut self) -> Result<()> {
        if self.last_report.elapsed() >= std::time::Duration::from_secs(60) {
            let at = clock()?;
            eprintln!(
                "{}",
                json!({"at":at,"epoch":157,"phase":"consumer-census-progress",
                "metadata_entries":self.entries,"metadata_bytes":self.bytes,
                "elapsed_seconds":self.started.elapsed().as_secs(),"last_substantive_progress_unix":at,
                "complete_transitive_consumer_graph_qualified":false})
            );
            self.last_report = std::time::Instant::now();
        }
        Ok(())
    }
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
    // Unescaped JSON strings have already been scanned byte-for-byte above.
    // A valid JSON document without backslashes cannot contribute new paths.
    if bytes.contains(&b'\\') {
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let strings = JsonEdges {
            corpus,
            targets,
            aliases,
        };
        // Retain the previous all-or-nothing JSON rule: neither a valid prefix
        // nor strings visited before an invalid escape/trailing token count.
        if let Ok(decoded) = strings.deserialize(&mut decoder)
            && decoder.end().is_ok()
        {
            edges.extend(decoded);
        }
    }
    edges
}

// Visit JSON without constructing a Value tree or copying ordinary strings.
// serde_json still owns syntax, UTF-8, escape/surrogate and depth validation.
// Only strings decoded into its scratch buffer need another raw-path scan.
#[derive(Clone, Copy)]
struct JsonEdges<'a> {
    corpus: &'a BTreeMap<PathBuf, Artifact>,
    targets: &'a BTreeSet<PathBuf>,
    aliases: &'a BTreeMap<PathBuf, PathBuf>,
}
impl<'de> DeserializeSeed<'de> for JsonEdges<'_> {
    type Value = BTreeSet<PathBuf>;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for JsonEdges<'_> {
    type Value = BTreeSet<PathBuf>;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, _: &'de str) -> Result<Self::Value, E> {
        // With Deserializer::from_slice, borrowed strings contain no escapes.
        Ok(BTreeSet::new())
    }
    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
        Ok(literal_edges_raw(
            text.as_bytes(),
            self.corpus,
            self.targets,
            self.aliases,
        ))
    }
    fn visit_string<E: serde::de::Error>(self, text: String) -> Result<Self::Value, E> {
        self.visit_str(&text)
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(BTreeSet::new())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(BTreeSet::new())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(BTreeSet::new())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(BTreeSet::new())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(BTreeSet::new())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut array: A) -> Result<Self::Value, A::Error> {
        let mut edges = BTreeSet::new();
        while let Some(value) = array.next_element_seed(self)? {
            edges.extend(value);
        }
        Ok(edges)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
        let mut edges = BTreeSet::new();
        // Value keeps the last value of duplicate decoded keys. Retain only
        // values with decoded edges, but let a later empty value remove them.
        // This preserves that rule without storing unrelated JSON data/keys.
        let mut values: BTreeMap<Cow<'de, str>, BTreeSet<PathBuf>> = BTreeMap::new();
        while let Some(key) = object.next_key_seed(JsonKey)? {
            if let Cow::Owned(text) = &key {
                edges.extend(literal_edges_raw(
                    text.as_bytes(),
                    self.corpus,
                    self.targets,
                    self.aliases,
                ));
            }
            let value = object.next_value_seed(self)?;
            if value.is_empty() {
                values.remove(key.as_ref());
            } else {
                values.insert(key, value);
            }
        }
        for value in values.into_values() {
            edges.extend(value);
        }
        Ok(edges)
    }
}

struct JsonKey;
impl<'de> DeserializeSeed<'de> for JsonKey {
    type Value = Cow<'de, str>;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_str(self)
    }
}
impl<'de> Visitor<'de> for JsonKey {
    type Value = Cow<'de, str>;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object key")
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, text: &'de str) -> Result<Self::Value, E> {
        Ok(Cow::Borrowed(text))
    }
    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
        Ok(Cow::Owned(text.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, text: String) -> Result<Self::Value, E> {
        Ok(Cow::Owned(text))
    }
}
pub(super) fn read_artifact(b: &Bound, max: u64, immutable: bool) -> Result<Vec<u8>> {
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
    let bytes = read_stable_bounded(&b.path, max, "laned consumer artifact")?;
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
    budget: &mut CensusBudget,
    aliases: &mut BTreeMap<PathBuf, PathBuf>,
) -> Result<()> {
    budget.entries += 1;
    ensure!(
        depth <= 32 && budget.entries <= 200_000 && budget.bytes <= CENSUS_BYTES,
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
        budget.bytes = budget
            .bytes
            .checked_add(bytes.len() as u64)
            .context("consumer census byte overflow")?;
        ensure!(
            budget.bytes <= CENSUS_BYTES,
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
        budget.report()?;
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
    // Each invocation has one fixed corpus and alias map. Every file was
    // independently stable-read and hashed above; only parsing may be reused.
    // Digests select candidates, never establish equality: compare the actual
    // bytes before borrowing a representative's edges. Retain references into
    // the corpus, rather than another copy of the metadata bodies.
    let mut representatives: BTreeMap<(&str, usize), Vec<&PathBuf>> = BTreeMap::new();
    let mut all_edges: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
    let mut readers: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
    let mut edge_count = 0usize;
    let started = std::time::Instant::now();
    let mut last_report = started;
    let mut processed_bytes = 0u64;
    let mut parsed_bodies = 0usize;
    let mut reused_bodies = 0usize;
    for (index, (path, item)) in corpus.iter().enumerate() {
        let candidates = representatives
            .entry((item.sha256.as_str(), item.bytes.len()))
            .or_default();
        let matching = candidates
            .iter()
            .copied()
            .find(|candidate| corpus[*candidate].bytes == item.bytes);
        let edges = if let Some(representative) = matching {
            reused_bodies += 1;
            all_edges[representative].clone()
        } else {
            candidates.push(path);
            parsed_bodies += 1;
            literal_edges(&item.bytes, corpus, &targets, aliases)
        };
        // Count and insert every path, including byte-identical definitions.
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
        processed_bytes = processed_bytes
            .checked_add(item.bytes.len() as u64)
            .context("reader parsing byte overflow")?;
        if last_report.elapsed() >= std::time::Duration::from_secs(60) {
            let at = clock()?;
            eprintln!(
                "{}",
                json!({"at":at,"epoch":157,"phase":"consumer-graph-progress",
                "metadata_entries":index+1,"metadata_bytes":processed_bytes,
                "parsed_bodies":parsed_bodies,"reused_bodies":reused_bodies,"literal_edges":edge_count,
                "elapsed_seconds":started.elapsed().as_secs(),"last_substantive_progress_unix":at,
                "complete_transitive_consumer_graph_qualified":false})
            );
            last_report = std::time::Instant::now();
        }
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
fn review_freshness(recorded: u64, now: u64) -> Result<()> {
    ensure!(
        now.checked_sub(recorded).is_some_and(|age| age <= 1800),
        "laned transitive consumer review is stale or future-dated"
    );
    Ok(())
}
fn review_shape(r: &Review, p: &Retire, now: u64) -> Result<()> {
    review_freshness(r.recorded_unix_seconds, now)?;
    ensure!(
        r.schema == "horizon-closed157-laned-transitive-consumer-closure-v1"
            && r.owner == "/root"
            && r.source == Path::new(SOURCE)
            && r.sha256 == p.archive_sha256
            && r.length == LENGTH
            && same_bound(&r.inspection, &p.inspection)
            && same_bound(&r.park_plan, &p.park_plan)
            && same_bound(&r.park_terminal, &p.park_terminal)
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
        "genuine fresh complete laned transitive reader graph required"
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
        } else if unit == INSPECTOR {
            inspector_provenance(p)?;
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
    let started = std::time::Instant::now();
    let mut budget = CensusBudget {
        entries: 0,
        bytes: 0,
        started,
        last_report: started,
    };
    eprintln!(
        "{}",
        json!({"at":clock()?,"epoch":157,"phase":"consumer-census-start",
        "metadata_byte_limit":CENSUS_BYTES,"complete_transitive_consumer_graph_qualified":false})
    );
    let mut sealed = BTreeMap::new();
    let mut definitions = BTreeMap::new();
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
    eprintln!(
        "{}",
        json!({"at":clock()?,"epoch":157,"phase":"consumer-census-complete",
        "metadata_entries":budget.entries,"metadata_bytes":budget.bytes,"graph_nodes":graph.len(),
        "elapsed_seconds":started.elapsed().as_secs(),"complete_transitive_consumer_graph_qualified":false})
    );
    Ok(Corpus {
        all: corpus,
        graph,
        sealed_sha,
        definitions_sha,
        entries: budget.entries,
        bytes: budget.bytes,
    })
}
pub(super) fn inspect(spec: &Bound) -> Result<()> {
    ensure!(
        spec.path == Path::new(PARK_PLAN)
            && digest(&spec.sha256)
            && fs::read_link("/proc/self/exe")?.parent() == Some(Path::new(LIFECYCLE)),
        "laned consumer census requires the exact existing park plan and sealed lifecycle tool"
    );
    let plan: Park = serde_json::from_value(bound(spec)?)?;
    source_scope(&plan, &bound(&plan.eligibility)?)?;
    ensure!(
        plan.source == Path::new(SOURCE)
            && digest(&plan.sha256)
            && plan.length == LENGTH
            && same_bound(&plan.mapping, &binding(MAPPING, MAPPING_SHA))
            && plan.eligibility.path == Path::new(ELIGIBILITY),
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
    let receipt = json!({"schema":"horizon-closed157-laned-transitive-consumer-census-v1","source":SOURCE,"sha256":plan.sha256,"length":LENGTH,
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
        "retire157-laned-consumer-census-{}.json",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    persist(&path, &receipt)?;
    println!("{}", path.display());
    Ok(())
}
pub(super) fn preflight(p: &Retire) -> Result<()> {
    let value = evidence_with_limit(&p.consumer_closure, true, 16 << 20)?;
    let r: Review = serde_json::from_value(value)?;
    review_shape(&r, p, clock()?)
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
    let mut inspector_image = false;
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
        inspector_image |= same_bound(&item.image, &p.inspector_image)
            && item
                .reviewed_source
                .iter()
                .any(|b| same_bound(b, &p.inspector_provenance))
            && item.owner_units.iter().any(|u| u == INSPECTOR);
        park_image |=
            same_bound(&item.image, &park_helper) && item.owner_units.iter().any(|u| u == PARK);
    }
    ensure!(
        inspector_image && park_image,
        "actual successful inspector and park image are missing from compiled closure"
    );
    for row in &r.classes {
        let inputs: Vec<Bound> = serde_json::from_value(row["inspected_inputs"].clone())?;
        for proof in inputs {
            read_artifact(&proof, 128 << 20, true)?;
        }
    }
    // Collection and native/source verification can consume much of the
    // review window. Freshness at entry must not authorize an expired result.
    review_freshness(r.recorded_unix_seconds, clock()?)?;
    Ok(
        json!({"schema":"horizon-laned-transitive-consumer-gate-v1","review":p.consumer_closure,
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
    // Independent decoder oracle: retain the former Value-tree implementation
    // in tests so string streaming must preserve its actual edge semantics.
    fn value_tree_edges(
        bytes: &[u8],
        corpus: &BTreeMap<PathBuf, Artifact>,
        targets: &BTreeSet<PathBuf>,
        aliases: &BTreeMap<PathBuf, PathBuf>,
    ) -> BTreeSet<PathBuf> {
        let mut edges = literal_edges_raw(bytes, corpus, targets, aliases);
        if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
            let mut pending = vec![value];
            while let Some(value) = pending.pop() {
                match value {
                    Value::String(text) => {
                        edges.extend(literal_edges_raw(text.as_bytes(), corpus, targets, aliases));
                    }
                    Value::Array(values) => pending.extend(values),
                    Value::Object(values) => {
                        for (key, value) in values {
                            edges.extend(literal_edges_raw(
                                key.as_bytes(),
                                corpus,
                                targets,
                                aliases,
                            ));
                            pending.push(value);
                        }
                    }
                    _ => (),
                }
            }
        }
        edges
    }
    // Independent small-corpus oracle: parse every body and find the reverse
    // closure by fixed-point expansion rather than the production cache/queue.
    fn uncached_graph(
        corpus: &BTreeMap<PathBuf, Artifact>,
        aliases: &BTreeMap<PathBuf, PathBuf>,
    ) -> BTreeMap<PathBuf, BTreeSet<PathBuf>> {
        let targets = [SOURCE, RUN, DESTINATION]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let edges: BTreeMap<_, _> = corpus
            .iter()
            .map(|(path, item)| {
                (
                    path.clone(),
                    value_tree_edges(&item.bytes, corpus, &targets, aliases),
                )
            })
            .collect();
        let mut selected = BTreeSet::new();
        loop {
            let before = selected.len();
            for (path, outgoing) in &edges {
                if outgoing
                    .iter()
                    .any(|target| targets.contains(target) || selected.contains(target))
                {
                    selected.insert(path.clone());
                }
            }
            if before == selected.len() {
                break;
            }
        }
        selected
            .iter()
            .map(|path| {
                (
                    path.clone(),
                    edges[path]
                        .iter()
                        .filter(|target| targets.contains(*target) || selected.contains(*target))
                        .cloned()
                        .collect(),
                )
            })
            .collect()
    }
    #[test]
    fn identical_bodies_preserve_every_path_and_full_uncached_graph() {
        let mut corpus = BTreeMap::from([
            ("/sealed/plan.json".into(), artifact(SOURCE, false)),
            ("/sealed/other.json".into(), artifact("{}", false)),
            ("/sealed/é/🦀.json".into(), artifact(SOURCE, false)),
        ]);
        let bodies = [
            "ExecStart=/sealed/plan.json",
            r#"{"v":"\u002finput\u002fplan.json"}"#,
            r#"{"\u002fsealed\u002f\u00e9\u002f\ud83e\udd80.json":null}"#,
            r#"{"k":"\u002fsealed\u002fplan.json","k":null}"#,
            r#"{"k":null,"k":"\u002fsealed\u002fplan.json"}"#,
            r#"["\u002fsealed\u002fplan.json"] trailing"#,
            r#"{"raw":"/sealed/plan.json","bad":"\q"}"#,
            "reader /readers/0/0.json",
        ];
        for (index, body) in bodies.iter().enumerate() {
            for copy in 0..3 {
                corpus.insert(
                    format!("/readers/{index}/{copy}.json").into(),
                    artifact(body, copy == 1),
                );
            }
        }
        let aliases = BTreeMap::from([("/input".into(), "/sealed".into())]);
        let observed = reverse_graph(&corpus, &aliases).unwrap();
        assert_eq!(observed, uncached_graph(&corpus, &aliases));
        for copy in 0..3 {
            assert!(observed.contains_key(Path::new(&format!("/readers/0/{copy}.json"))));
            assert!(observed.contains_key(Path::new(&format!("/readers/1/{copy}.json"))));
            assert!(observed.contains_key(Path::new(&format!("/readers/7/{copy}.json"))));
            assert!(!observed.contains_key(Path::new(&format!("/readers/3/{copy}.json"))));
            assert!(!observed.contains_key(Path::new(&format!("/readers/5/{copy}.json"))));
        }
    }
    #[test]
    fn equal_digest_and_length_require_exact_bytes_before_edge_reuse() {
        let mut corpus = BTreeMap::from([
            ("/sealed/a.json".into(), artifact(SOURCE, false)),
            ("/sealed/b.json".into(), artifact("{}", false)),
        ]);
        for (reader, target) in [("a", "a"), ("b", "b"), ("c", "b"), ("d", "a")] {
            let mut item = artifact(&format!("/sealed/{target}.json"), false);
            // An injected collision exercises the exact-byte guard without
            // needing or pretending to possess a real SHA-256 collision.
            item.sha256 = "0".repeat(64);
            corpus.insert(format!("/readers/{reader}").into(), item);
        }
        let aliases = BTreeMap::new();
        let graph = reverse_graph(&corpus, &aliases).unwrap();
        assert_eq!(graph, uncached_graph(&corpus, &aliases));
        assert!(graph.contains_key(Path::new("/readers/a")));
        assert!(graph.contains_key(Path::new("/readers/d")));
        assert!(!graph.contains_key(Path::new("/readers/b")));
        assert!(!graph.contains_key(Path::new("/readers/c")));
    }
    #[test]
    fn parsing_reuse_is_scoped_to_the_current_corpus_and_aliases() {
        let mut corpus = BTreeMap::from([
            ("/sealed/plan.json".into(), artifact(SOURCE, false)),
            ("/reader-a".into(), artifact("/input/plan.json", true)),
            ("/reader-b".into(), artifact("/input/plan.json", true)),
            ("/future-reader".into(), artifact("/later/plan.json", true)),
        ]);
        let mut aliases = BTreeMap::from([("/input".into(), "/sealed".into())]);
        let first = reverse_graph(&corpus, &aliases).unwrap();
        assert!(first.contains_key(Path::new("/reader-a")));
        assert!(first.contains_key(Path::new("/reader-b")));
        assert!(!first.contains_key(Path::new("/future-reader")));

        aliases.insert("/input".into(), "/unused".into());
        let changed_alias = reverse_graph(&corpus, &aliases).unwrap();
        assert_eq!(changed_alias, uncached_graph(&corpus, &aliases));
        assert!(!changed_alias.contains_key(Path::new("/reader-a")));
        assert!(!changed_alias.contains_key(Path::new("/reader-b")));

        corpus.insert("/later/plan.json".into(), artifact(SOURCE, false));
        let changed_corpus = reverse_graph(&corpus, &aliases).unwrap();
        assert_eq!(changed_corpus, uncached_graph(&corpus, &aliases));
        assert!(changed_corpus.contains_key(Path::new("/future-reader")));
    }
    #[test]
    fn identical_reader_paths_still_count_toward_graph_limit() {
        let corpus = (0..4097)
            .map(|index| {
                (
                    PathBuf::from(format!("/readers/{index}")),
                    artifact(SOURCE, true),
                )
            })
            .collect();
        let error = reverse_graph(&corpus, &BTreeMap::new()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("transitive reader graph exceeds bound")
        );
    }
    #[test]
    fn review_expiring_during_verification_is_rejected_at_completion() {
        let recorded = 100;
        review_freshness(recorded, recorded).unwrap();
        review_freshness(recorded, recorded + 1800).unwrap();
        assert!(review_freshness(recorded, recorded + 1801).is_err());
        assert!(review_freshness(recorded, recorded - 1).is_err());
        assert!(review_freshness(u64::MAX, 0).is_err());
        review_freshness(u64::MAX, u64::MAX).unwrap();
    }
    struct EdgeFixture {
        corpus: BTreeMap<PathBuf, Artifact>,
        targets: BTreeSet<PathBuf>,
        aliases: BTreeMap<PathBuf, PathBuf>,
    }
    impl EdgeFixture {
        fn new() -> Self {
            Self {
                corpus: [
                    "/sealed/plan.json",
                    "/sealed/wrapper.sh",
                    "/sealed/é/🦀.json",
                ]
                .into_iter()
                .map(|path| (path.into(), artifact("", false)))
                .collect(),
                targets: [SOURCE, RUN, DESTINATION]
                    .into_iter()
                    .map(PathBuf::from)
                    .collect(),
                aliases: BTreeMap::from([
                    ("/input-alias".into(), "/sealed".into()),
                    ("/unicode-alias".into(), "/sealed/é".into()),
                ]),
            }
        }
        fn compare(&self, bytes: &[u8]) -> BTreeSet<PathBuf> {
            let observed = literal_edges(bytes, &self.corpus, &self.targets, &self.aliases);
            let expected = value_tree_edges(bytes, &self.corpus, &self.targets, &self.aliases);
            assert_eq!(
                observed,
                expected,
                "input={}",
                String::from_utf8_lossy(bytes)
            );
            observed
        }
    }
    #[test]
    fn streaming_json_preserves_keys_unicode_surrogates_aliases_and_nested_paths() {
        let fixture = EdgeFixture::new();
        let cases: &[(&str, &[&str])] = &[
            (r#"{"v":"\/sealed\/plan.json"}"#, &["/sealed/plan.json"]),
            (
                r#"{"v":"\u002Fsealed\u002fpl\u0061n.json"}"#,
                &["/sealed/plan.json"],
            ),
            (
                r#"{"\u002fsealed\u002fplan.json":null}"#,
                &["/sealed/plan.json"],
            ),
            (
                r#""\u002fsealed\u002f\u00e9\u002f\ud83e\udd80.json""#,
                &["/sealed/é/🦀.json"],
            ),
            (
                r#"{"\u002funicode-alias\u002f\ud83e\udd80.json":false}"#,
                &["/sealed/é/🦀.json"],
            ),
            (
                r#"["\u002finput-alias\u002fplan.json",{"v":["\/sealed\/wrapper.sh"]}]"#,
                &["/sealed/plan.json", "/sealed/wrapper.sh"],
            ),
            (
                r#"["no\\path",null,true,false,0,-1,-9223372036854775808,18446744073709551615,1.25,1e-300]"#,
                &[],
            ),
        ];
        for (body, expected) in cases {
            assert!(serde_json::from_str::<Value>(body).is_ok());
            assert_eq!(
                fixture.compare(body.as_bytes()),
                expected.iter().map(PathBuf::from).collect()
            );
        }
    }
    #[test]
    fn streaming_json_preserves_every_raw_separator_after_decoding() {
        let fixture = EdgeFixture::new();
        for separator in "\0\n\r\t '\";|&()<>[]{},:\\".chars() {
            let text = format!("/input-alias/plan.json{separator}/sealed/wrapper.sh");
            let encoded = serde_json::to_string(&text)
                .unwrap()
                .replace('/', "\\u002f");
            assert!(serde_json::from_str::<Value>(&encoded).is_ok());
            let expected = ["/sealed/plan.json", "/sealed/wrapper.sh"]
                .into_iter()
                .map(PathBuf::from)
                .collect();
            assert_eq!(
                fixture.compare(encoded.as_bytes()),
                expected,
                "separator={separator:?}"
            );
        }
    }
    #[test]
    fn streaming_json_keeps_the_last_value_of_duplicate_decoded_keys() {
        let fixture = EdgeFixture::new();
        let cases: &[(&str, &[&str])] = &[
            (r#"{"k":"\u002fsealed\u002fplan.json","k":null}"#, &[]),
            (
                r#"{"k":null,"\u006b":"\/sealed\/plan.json"}"#,
                &["/sealed/plan.json"],
            ),
            (
                r#"{"\u006b":"\/sealed\/plan.json","k":"\/sealed\/wrapper.sh"}"#,
                &["/sealed/wrapper.sh"],
            ),
            (r#"{"k":{"\u002fsealed\u002fplan.json":true},"k":[]}"#, &[]),
            (
                r#"{"a":{"k":"\/sealed\/plan.json"},"b":{"k":"\/sealed\/wrapper.sh"}}"#,
                &["/sealed/plan.json", "/sealed/wrapper.sh"],
            ),
            (
                r#"{"\/sealed\/plan.json":"\/sealed\/wrapper.sh","\u002fsealed\u002fplan.json":null}"#,
                &["/sealed/plan.json"],
            ),
        ];
        for (body, expected) in cases {
            assert!(serde_json::from_str::<Value>(body).is_ok());
            assert_eq!(
                fixture.compare(body.as_bytes()),
                expected.iter().map(PathBuf::from).collect()
            );
        }
    }
    #[test]
    fn streaming_json_discards_decoded_edges_for_invalid_documents_without_losing_raw_edges() {
        let fixture = EdgeFixture::new();
        let mut cases: Vec<Vec<u8>> = [
            r#""\u002fsealed\u002fplan.json" trailing"#,
            r#"["\u002fsealed\u002fplan.json"] null"#,
            r#"{"v":"\u002fsealed\u002fplan.json""#,
            r#"["\u002fsealed\u002fplan.json","\q"]"#,
            r#"["\u002fsealed\u002fplan.json","\uD800"]"#,
            r#"["\u002fsealed\u002fplan.json","\uDC00"]"#,
            r#"["\u002fsealed\u002fplan.json","\uD800\u0041"]"#,
            r#"{"v":"\u002fsealed\u002fplan.json","n":01}"#,
            r#"{"v":"\u002fsealed\u002fplan.json","n":1e9999}"#,
            r#"{"raw":"/sealed/wrapper.sh","v":"\u002fsealed\u002fplan.json","bad":true,}"#,
        ]
        .into_iter()
        .map(|text| text.as_bytes().to_vec())
        .collect();
        let mut invalid_utf8 = br#"["\u002fsealed\u002fplan.json",""#.to_vec();
        invalid_utf8.extend_from_slice(&[0xff, b'"', b']']);
        cases.push(invalid_utf8);
        cases.push(
            format!(
                "{}\"\\u002fsealed\\u002fplan.json\"{}",
                "[".repeat(130),
                "]".repeat(130)
            )
            .into_bytes(),
        );
        for bytes in cases {
            assert!(serde_json::from_slice::<Value>(&bytes).is_err());
            let raw =
                literal_edges_raw(&bytes, &fixture.corpus, &fixture.targets, &fixture.aliases);
            let observed = fixture.compare(&bytes);
            assert_eq!(observed, raw);
            assert!(!observed.contains(Path::new("/sealed/plan.json")));
        }
    }
    #[test]
    fn streaming_json_matches_value_tree_across_encodings_and_path_length_gates() {
        use std::fmt::Write as _;
        let fixture = EdgeFixture::new();
        let mut texts = vec![
            SOURCE.to_owned(),
            format!("{RUN}/scratch/item"),
            "/sealed/plan.json".into(),
            "/sealed/plan.json-extra".into(),
            "/sealed/é/🦀.json".into(),
            "bind=/input-alias/plan.json:/sealed/wrapper.sh".into(),
            "quoted=\"/sealed/plan.json\";other=\\/sealed/wrapper.sh".into(),
        ];
        for length in [4095, 4096, 4097] {
            let prefix = "/sealed/plan.json/";
            texts.push(format!("{prefix}{}", "x".repeat(length - prefix.len())));
        }
        for text in texts {
            let ordinary = serde_json::to_string(&text).unwrap();
            let mut utf16 = String::new();
            for unit in text.encode_utf16() {
                write!(utf16, "\\u{unit:04x}").unwrap();
            }
            for encoded in [
                ordinary.clone(),
                ordinary.replace('/', "\\/"),
                format!("\"{utf16}\""),
            ] {
                for document in [
                    encoded.clone(),
                    format!("{{{encoded}:[{{\"v\":{encoded}}},null,true,23,-0.5]}}"),
                    format!("[{{\"k\":{encoded},\"k\":null}},{encoded}]"),
                ] {
                    assert!(serde_json::from_str::<Value>(&document).is_ok());
                    fixture.compare(document.as_bytes());
                }
            }
        }
        for body in [
            "/sealed/plan.json:/sealed/wrapper.sh",
            "invalid \\q /sealed/plan.json",
            "{\"v\":\"/sealed/é/🦀.json\"}",
        ] {
            fixture.compare(body.as_bytes());
        }
    }
    #[test]
    #[ignore = "bounded in-memory comparison; run only in the admitted test envelope"]
    fn streaming_json_value_tree_benchmark() {
        let fixture = EdgeFixture::new();
        let ordinary = br#"{"path":"/unrelated/metadata.json","phase":"complete","epoch":166,"ready":true,"notes":["retained",null,0]}"#;
        let escaped = br#"{"ref":"\u002finput-alias\u002fplan.json","unicode":"\u002fsealed\u002f\u00e9\u002f\ud83e\udd80.json"}"#;
        let mut bytes = vec![b'['];
        for index in 0..50_000 {
            if index != 0 {
                bytes.push(b',');
            }
            bytes.extend_from_slice(if index % 1024 == 0 { escaped } else { ordinary });
        }
        bytes.push(b']');
        let start = std::time::Instant::now();
        let before = value_tree_edges(&bytes, &fixture.corpus, &fixture.targets, &fixture.aliases);
        let value_tree_seconds = start.elapsed().as_secs_f64();
        let start = std::time::Instant::now();
        let after = literal_edges(&bytes, &fixture.corpus, &fixture.targets, &fixture.aliases);
        let streaming_seconds = start.elapsed().as_secs_f64();
        assert_eq!(after, before);
        assert_eq!(after.len(), 2);
        eprintln!(
            "{}",
            json!({
                "fixture_bytes":bytes.len(),"value_tree_seconds":value_tree_seconds,
                "streaming_seconds":streaming_seconds,"edges_equal":true,
                "native_host_census_qualified":false
            })
        );
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
            schema: "horizon-closed157-laned-transitive-consumer-closure-v1".into(),
            owner: "/root".into(),
            source: SOURCE.into(),
            sha256: "1".repeat(64),
            length: LENGTH,
            inspection: binding("/sealed/inspection.json", &"2".repeat(64)),
            park_plan: binding(PARK_PLAN, &"3".repeat(64)),
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
    fn semantic_review_binds_actual157_digest_and_plan_without_borrowing166_proofs() {
        let plan = super::super::tests::fixture_plan();
        let mut r = review(vec![Node {
            file: binding("/sealed/reader.json", &"d".repeat(64)),
            edges: vec![SOURCE.into()],
            disposition: "retained-nonexecuting-evidence".into(),
            owner_units: vec![],
            semantic_evidence: vec![binding("/sealed/review.json", &"e".repeat(64))],
        }]);
        r.inspection = plan.inspection.clone();
        r.park_plan = plan.park_plan.clone();
        r.park_terminal = plan.park_terminal.clone();
        r.classes = CLASSES
            .into_iter()
            .map(|class| {
                json!({"class":class,
            "no_local_archive_required":true,"reason":"synthetic test only",
            "inspected_inputs":[binding("/sealed/review.json", &"e".repeat(64))]})
            })
            .collect();
        r.compiled_consumers = [PRODUCER, PARK]
            .into_iter()
            .map(|unit| Compiled {
                image: binding("/sealed/image", &"f".repeat(64)),
                reviewed_source: vec![binding("/sealed/source", &"e".repeat(64))],
                owner_units: vec![unit.into()],
                no_local_partial_required: true,
            })
            .collect();
        review_shape(&r, &plan, 100).unwrap();
        r.sha256 = "0".repeat(64);
        assert!(review_shape(&r, &plan, 100).is_err());
        r.sha256 = plan.archive_sha256.clone();
        r.park_plan.sha256 = "0".repeat(64);
        assert!(review_shape(&r, &plan, 100).is_err());
        r.park_plan = plan.park_plan.clone();
        assert!(review_shape(&r, &plan, 1901).is_err());
        r.no_reopening_until_retirement_complete = false;
        assert!(review_shape(&r, &plan, 100).is_err());
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
