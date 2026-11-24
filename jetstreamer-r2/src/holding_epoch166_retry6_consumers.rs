// Bounded reverse reference graph plus separately evidenced native/dynamic
// reader review. A direct empty source census does not satisfy this gate.
use super::*;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet},
    ffi::OsStr,
};

mod generated {
    include!("holding_epoch166_generated_definitions.rs");
}

mod reviewed_managers {
    include!("holding_epoch166_reviewed_managers.rs");
}

const SEALED: &str = "/usr/local/lib/jetstreamer";
// The native host inventory contains 104,491 metadata files / 15,425,505,635
// bytes, including a 66,027,261-byte historical frame. This is a total I/O
// bound. Bodies are hashed and released individually.
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
    body: Body,
    definition: bool,
}
// A pass may outlive edits to a staged definition. Bind both the original
// namespace entry and its contents, including for an empty file or a mask.
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileStamp {
    identity: FileIdentity,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
}
impl FileStamp {
    fn new(md: &fs::Metadata) -> Self {
        Self {
            identity: identity(md),
            changed_seconds: md.ctime(),
            changed_nanoseconds: md.ctime_nsec(),
            mode: md.mode(),
            uid: md.uid(),
            gid: md.gid(),
            links: md.nlink(),
        }
    }
    fn check(self, path: &Path) -> Result<()> {
        ensure!(
            FileStamp::new(
                &fs::symlink_metadata(path)
                    .with_context(|| format!("read consumer inventory stamp {}", path.display()))?
            ) == self,
            "transitive metadata changed since inventory: {}",
            path.display()
        );
        Ok(())
    }
}
#[derive(Clone)]
enum Body {
    File(FileStamp),
    Generated(FileStamp),
    Mask(FileStamp),
    #[cfg(test)]
    Fixture(Vec<u8>),
}
impl Artifact {
    fn check_entry(&self, path: &Path) -> Result<()> {
        match self.body {
            Body::File(stamp) => stamp.check(path),
            Body::Generated(stamp) => generated::check(path, stamp, &self.sha256),
            Body::Mask(stamp) => {
                stamp.check(path)?;
                ensure!(masked(path)?, "systemd mask changed: {}", path.display());
                Ok(())
            }
            #[cfg(test)]
            Body::Fixture(_) => Ok(()),
        }
    }
    fn read(&self, path: &Path) -> Result<Cow<'_, [u8]>> {
        self.check_entry(path)?;
        match &self.body {
            Body::File(_) | Body::Generated(_) => {
                let bytes = read_stable_bounded(path, METADATA_BYTES, "transitive metadata")?;
                self.check_entry(path)?;
                ensure!(
                    hex_lower(&Sha256::digest(&bytes)) == self.sha256,
                    "transitive metadata digest changed: {}",
                    path.display()
                );
                Ok(Cow::Owned(bytes))
            }
            Body::Mask(_) => Ok(Cow::Borrowed(&[])),
            #[cfg(test)]
            Body::Fixture(bytes) => Ok(Cow::Borrowed(bytes)),
        }
    }
}

#[derive(Default)]
struct EdgeEntry<'a> {
    id: Option<usize>,
    alias: Option<&'a Path>,
}

// Keep Path's component-aware equality for every match. Most literal
// ancestors have a directory name that never appears as an inventory member
// or alias. Checking that one component avoids hashing the entire prefix.
struct EdgeIndex<'a> {
    entries: HashMap<&'a Path, EdgeEntry<'a>>,
    endings: HashSet<Option<&'a OsStr>>,
    member_count: usize,
}

impl<'a> EdgeIndex<'a> {
    fn new(
        corpus: &'a BTreeMap<PathBuf, Artifact>,
        targets: &'a BTreeSet<PathBuf>,
        aliases: &'a BTreeMap<PathBuf, PathBuf>,
    ) -> Self {
        let mut entries = HashMap::<&Path, EdgeEntry>::with_capacity(
            corpus.len() + targets.len() + aliases.len(),
        );
        let mut member_count = 0;
        for path in corpus.keys().chain(targets) {
            let entry = entries.entry(path).or_default();
            if entry.id.is_none() {
                entry.id = Some(member_count);
                member_count += 1;
            }
        }
        for (alias, canonical) in aliases {
            entries.entry(alias).or_default().alias = Some(canonical);
        }
        let endings = entries
            .keys()
            .copied()
            .map(|p| p.components().next_back().map(|c| c.as_os_str()))
            .collect();
        Self {
            entries,
            endings,
            member_count,
        }
    }

    fn get(&self, path: &Path) -> Option<&EdgeEntry<'a>> {
        let ending = path
            .components()
            .next_back()
            .map(|component| component.as_os_str());
        if self.endings.contains(&ending) {
            self.entries.get(path)
        } else {
            None
        }
    }
}

fn indexed_edges_raw(bytes: &[u8], index: &EdgeIndex) -> BTreeSet<PathBuf> {
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
                let Some(entry) = index.get(candidate) else {
                    continue;
                };
                if entry.id.is_some() {
                    edges.insert(candidate.to_owned());
                }
                if let Some(canonical) = entry.alias
                    && let Ok(suffix) = path.strip_prefix(candidate)
                {
                    let resolved = canonical.join(suffix);
                    for target in resolved.ancestors() {
                        if index.get(target).is_some_and(|entry| entry.id.is_some()) {
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
fn indexed_edges(bytes: &[u8], index: &EdgeIndex) -> BTreeSet<PathBuf> {
    let mut edges = indexed_edges_raw(bytes, index);
    // Unescaped JSON strings have already been scanned byte-for-byte above.
    // A valid JSON document without backslashes cannot contribute new paths.
    if bytes.contains(&b'\\') {
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let strings = JsonEdges { index };
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
struct JsonEdges<'a, 'paths> {
    index: &'a EdgeIndex<'paths>,
}
impl<'de> DeserializeSeed<'de> for JsonEdges<'_, '_> {
    type Value = BTreeSet<PathBuf>;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for JsonEdges<'_, '_> {
    type Value = BTreeSet<PathBuf>;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, _: &'de str) -> Result<Self::Value, E> {
        // With Deserializer::from_slice, borrowed strings contain no escapes.
        Ok(BTreeSet::new())
    }
    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
        Ok(indexed_edges_raw(text.as_bytes(), self.index))
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
                edges.extend(indexed_edges_raw(text.as_bytes(), self.index));
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
    let bytes = read_stable_bounded(&b.path, max, "epoch 166 consumer artifact")?;
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
                body: Body::Mask(FileStamp::new(&link)),
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
            let child = entry?.path();
            census_walk(&child, definition, depth + 1, seen, out, budget, aliases)
                .with_context(|| format!("inventory consumer metadata {}", child.display()))?;
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
        let stamp = FileStamp::new(&md);
        let bytes = read_stable_bounded(&canonical, METADATA_BYTES, "transitive metadata")?;
        stamp.check(&canonical)?;
        budget.1 = budget
            .1
            .checked_add(bytes.len() as u64)
            .context("consumer census byte overflow")?;
        ensure!(
            budget.1 <= CENSUS_BYTES,
            "consumer census byte bound exceeded"
        );
        let sha256 = hex_lower(&Sha256::digest(&bytes));
        let body = if definition && generated::qualified(&canonical, &sha256, stamp) {
            Body::Generated(stamp)
        } else {
            Body::File(stamp)
        };
        out.insert(
            canonical,
            Artifact {
                sha256,
                body,
                definition,
            },
        );
    } else {
        bail!("unexpected transitive metadata type: {}", path.display());
    }
    Ok(())
}
fn revalidate_aliases(aliases: &BTreeMap<PathBuf, PathBuf>) -> Result<()> {
    for (path, canonical) in aliases {
        // The sole permitted unresolved generated unit alias is validated by
        // canonical_metadata_path against the actual PID1 fragment and digest.
        ensure!(
            canonical_metadata_path(path, true)
                .with_context(|| format!("revalidate consumer alias {}", path.display()))?
                == *canonical,
            "consumer alias changed: {}",
            path.display()
        );
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
    // Keep one numeric reader ID per edge. A graph with two million edges
    // must not retain two million copies of potentially long absolute paths.
    // Targets get IDs even when their paths are absent from the metadata corpus.
    let paths: Vec<&Path> = corpus.keys().map(PathBuf::as_path).collect();
    let index = EdgeIndex::new(corpus, &targets, aliases);
    let mut target_ids = Vec::new();
    for target in &targets {
        target_ids.push(
            index.entries[target.as_path()]
                .id
                .context("target outside census index")?,
        );
    }
    let mut readers = vec![Vec::<usize>::new(); index.member_count];
    let mut count = 0usize;
    for (reader, (path, item)) in corpus.iter().enumerate() {
        let body = item
            .read(path)
            .with_context(|| format!("scan consumer metadata {}", path.display()))?;
        let edges = indexed_edges(&body, &index);
        count = count
            .checked_add(edges.len())
            .context("reader edge overflow")?;
        ensure!(count <= 2_000_000, "literal reader graph exceeds bound");
        for edge in edges {
            let target = index
                .entries
                .get(edge.as_path())
                .and_then(|entry| entry.id)
                .context("edge outside census and targets")?;
            readers[target].push(reader);
        }
    }
    let mut selected = BTreeSet::new();
    let mut queue = target_ids;
    while let Some(target) = queue.pop() {
        for reader in &readers[target] {
            if selected.insert(*reader) {
                ensure!(
                    selected.len() <= 4096,
                    "transitive reader graph exceeds bound"
                );
                queue.push(*reader);
            }
        }
    }
    drop(readers);
    // Re-read only the selected bodies to emit the original path spellings.
    // Looking up an edge ID alone would normalize equivalent spellings such
    // as a double separator in a staged definition, changing the receipt bytes.
    let mut graph = BTreeMap::new();
    let mut emitted_path_bytes = 0usize;
    for &reader in &selected {
        let path = paths[reader];
        let body = corpus[path]
            .read(path)
            .with_context(|| format!("emit consumer edges for {}", path.display()))?;
        let mut edges = indexed_edges(&body, &index);
        edges.retain(|target| {
            targets.contains(target)
                || index.entries[target.as_path()]
                    .id
                    .is_some_and(|id| selected.contains(&id))
        });
        for target in &edges {
            emitted_path_bytes = emitted_path_bytes
                .checked_add(target.as_os_str().len())
                .context("review edge lengths overflow")?;
        }
        // Every accepted review includes each path in its node edges, and
        // the raw input review is bounded to 16 MiB by verify().
        ensure!(
            emitted_path_bytes <= 16 << 20,
            "transitive reader edges exceed maximum review size"
        );
        graph.insert(path.to_owned(), edges);
    }
    // Catch changes that occurred after a file's edge scan as well.
    for (path, item) in corpus {
        item.check_entry(path)
            .with_context(|| format!("revalidate consumer inventory entry {}", path.display()))?;
    }
    Ok(graph)
}
fn review_shape(r: &Review, p: &Retire, now: u64) -> Result<()> {
    ensure!(
        r.schema == profile!(epoch "horizon-closed", "-transitive-consumer-closure-v1")
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
        "genuine fresh complete epoch 166 transitive reader graph required"
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
fn owner_units(units: &[String], p: &Retire, registered: &reviewed_managers::Registered) -> Result<()> {
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
        } else if !registered.terminal(unit) {
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
            "retired-observer-drop-in" => ensure!(
                artifact.definition && reviewed_managers::Registered::profile(PARK)?.dropin(node),
                "unrecognized retired observer definition or owner"
            ),
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
// Starting with retries 7 and 8, sealed tools and plans also live on HOME.
// Search root-owned package containers, including new ones installed since the
// previous review. Leave sol-owned replay inputs and writable audit data alone.
fn runtime_packages(
    path: &Path,
    ancestors: &mut BTreeSet<(u64, u64)>,
    entries: &mut usize,
    packages: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let md = fs::symlink_metadata(path)
        .with_context(|| format!("inspect runtime package directory {}", path.display()))?;
    if !md.is_dir() || md.uid() != 0 || path == Path::new(LIFECYCLE) {
        return Ok(());
    }
    let id = (md.dev(), md.ino());
    ensure!(
        ancestors.len() < 32 && ancestors.insert(id),
        "runtime package directory cycle or depth bound"
    );
    if md.mode() & 0o222 == 0 && path.join("deployment-seal-receipt.json").try_exists()? {
        packages.insert(path.to_owned());
    } else {
        for entry in fs::read_dir(path)
            .with_context(|| format!("list runtime package directory {}", path.display()))?
        {
            let entry = entry
                .with_context(|| format!("read runtime package member in {}", path.display()))?;
            *entries += 1;
            ensure!(
                *entries <= 500_000,
                "runtime package inventory exceeded its entry bound"
            );
            if entry
                .file_type()
                .with_context(|| {
                    format!("classify runtime package member {}", entry.path().display())
                })?
                .is_dir()
            {
                runtime_packages(&entry.path(), ancestors, entries, packages)?;
            }
        }
    }
    ancestors.remove(&id);
    Ok(())
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
    if let Some(root) = RUNTIME_PACKAGE_ROOT {
        let mut packages = BTreeSet::new();
        runtime_packages(Path::new(root), &mut BTreeSet::new(), &mut 0, &mut packages)?;
        ensure!(
            packages.contains(Path::new(PARK_PLAN).parent().context("park package")?),
            "original sealed park package missing from HOME census"
        );
        for package in packages {
            census_walk(
                &package,
                false,
                0,
                &mut BTreeSet::new(),
                &mut sealed,
                &mut budget,
                &mut aliases,
            )?;
        }
    }
    let generator = generated::inventory()?;
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
    revalidate_aliases(&aliases)?;
    let graph = reverse_graph(&corpus, &aliases)?;
    revalidate_aliases(&aliases)?;
    if let Some(before) = generator {
        ensure!(
            generated::inventory()?.as_ref() == Some(&before),
            "systemd generator namespace changed across consumer census"
        );
        // A selected definition always retains its exact original inode and stamps.
        for path in graph.keys() {
            if let Body::Generated(original) = corpus[path].body {
                original.check(path)?;
            }
        }
    }
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
        "epoch 166 consumer census requires the exact existing park plan and sealed lifecycle tool"
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
    let receipt = json!({"schema":profile!(epoch "horizon-closed", "-transitive-consumer-census-v1"),"source":SOURCE,"sha256":SHA,"length":LENGTH,
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
        "{}-{}.json",
        profile!(epoch "retire", "-consumer-census"),
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
    let registered = reviewed_managers::Registered::profile(PARK)?;
    for node in &r.nodes {
        for proof in &node.semantic_evidence {
            read_artifact(proof, 128 << 20, true)?;
        }
        if node.disposition == "closed-consumer" {
            owner_units(&node.owner_units, p, &registered)?;
            if c.all[&node.file.path].definition {
                let mut actual_owner = false;
                for unit in &node.owner_units {
                    // The registered terminal proof checks ExecStart separately.
                    // Definition attribution only needs the scalar path fields.
                    let row = native_fields(
                        std::process::Command::new("/usr/bin/systemctl")
                            .args(["show", unit, "-p", "Id,FragmentPath,DropInPaths"]),
                    )?;
                    ensure!(row["Id"] == *unit, "different definition owner");
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
    let mut additional = BTreeSet::new();
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
        owner_units(&item.owner_units, p, &registered)?;
        for &(path, sha, unit) in ADDITIONAL_COMPILED {
            if item.image.path == Path::new(path) && item.image.sha256 == sha && item.owner_units.iter().any(|owner| owner == unit) {
                additional.insert(path);
            }
        }
        old_node |= item.image.path == Path::new(ORIGINAL_NODE.0)
            && item.image.sha256 == ORIGINAL_NODE.1
            && item.owner_units.iter().any(|u| u == PRODUCER);
        park_image |=
            same_bound(&item.image, &park_helper) && item.owner_units.iter().any(|u| u == PARK);
    }
    ensure!(
        old_node && park_image && additional.len() == ADDITIONAL_COMPILED.len(),
        "compiled closure is missing an original image and its terminal owner"
    );
    for row in &r.classes {
        let inputs: Vec<Bound> = serde_json::from_value(row["inspected_inputs"].clone())?;
        for proof in inputs {
            read_artifact(&proof, 128 << 20, true)?;
        }
    }
    registered.verify()?;
    Ok(
        json!({"schema":profile!("horizon-", "-transitive-consumer-gate-v1"),"review":p.consumer_closure,
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
            body: Body::Fixture(bytes.as_bytes().to_vec()),
            definition,
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
        indexed_edges(bytes, &EdgeIndex::new(corpus, targets, aliases))
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
    fn indexed_paths_preserve_raw_spelling_and_alias_ancestor_matches() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let raw_path = |bytes: &[u8]| PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec()));
        let mut fixture = EdgeFixture::new();
        for name in [
            b"/sealed//alternate/./plan".as_slice(),
            b"/sealed/../literal",
            b"/sealed/\xff",
            b"/",
        ] {
            fixture.corpus.insert(raw_path(name), artifact("", false));
        }
        fixture
            .aliases
            .insert("/sealed/alternate/plan".into(), "/sealed".into());
        fixture
            .aliases
            .insert("/sealed/alternate".into(), "/sealed/..".into());
        let index = EdgeIndex::new(&fixture.corpus, &fixture.targets, &fixture.aliases);
        let spellings = |edges: BTreeSet<PathBuf>| {
            edges
                .into_iter()
                .map(|p| p.into_os_string().into_vec())
                .collect::<Vec<_>>()
        };
        let token = b"/sealed/alternate//./plan";
        let first = [token.as_slice(), b"/sealed/alternate/plan/"].concat();
        for bytes in [
            first.as_slice(),
            b"/sealed/alternate//./plan/../literal",
            b"/sealed/alternate/plan/plan.json",
            b"///sealed/\xff//tail/./",
            b"/sealed/../literal/",
            b"//",
            b"/unlisted/filename.json",
            br#"{"a":"\u002fsealed\/alternate//plan/plan.json","b":"\/sealed\/..\/literal"}"#,
        ] {
            assert_eq!(
                spellings(indexed_edges(bytes, &index)),
                spellings(value_tree_edges(
                    bytes,
                    &fixture.corpus,
                    &fixture.targets,
                    &fixture.aliases
                ))
            );
        }
        assert!(
            indexed_edges_raw(b"/sealed/alternate//./plan", &index)
                .iter()
                .any(|p| p.as_os_str().as_bytes() == token)
        );
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
    fn original_reverse_graph(
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
            let edges = value_tree_edges(&item.read(path)?, corpus, &targets, aliases);
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
    fn disk_artifact(path: &Path, definition: bool) -> Artifact {
        let bytes = fs::read(path).unwrap();
        Artifact {
            definition,
            sha256: hex_lower(&Sha256::digest(bytes)),
            body: Body::File(FileStamp::new(&fs::symlink_metadata(path).unwrap())),
        }
    }
    #[test]
    fn streamed_disk_graph_matches_original_receipt_bytes_for_cycles_aliases_and_spelling() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let p = dir.join("p.json");
        let q = dir.join("q.service");
        let mask = dir.join("masked.service");
        let idle = dir.join("noise");
        let alias = dir.join("alias");
        fs::write(&p, format!("{} {}", SOURCE, q.display())).unwrap();
        // Deliberately non-normalized path in the old output.
        let repeated = format!("{}//p.json", dir.display());
        fs::write(
            &q,
            format!(
                "{repeated} {} {}",
                alias.display(),
                SOURCE.replace('/', "\\/")
            ),
        )
        .unwrap();
        fs::write(&idle, b"irrelevant").unwrap();
        std::os::unix::fs::symlink("/dev/null", &mask).unwrap();
        let mut corpus = BTreeMap::from([
            (p.clone(), disk_artifact(&p, false)),
            (q.clone(), disk_artifact(&q, true)),
            (idle.clone(), disk_artifact(&idle, false)),
        ]);
        // Native staged masks require uid 0. Match the fixture oracle on any uid.
        if fs::symlink_metadata(&mask).unwrap().uid() == 0 {
            corpus.insert(
                mask.clone(),
                Artifact {
                    definition: true,
                    sha256: hex_lower(&Sha256::digest(b"root-owned mask /dev/null")),
                    body: Body::Mask(FileStamp::new(&fs::symlink_metadata(&mask).unwrap())),
                },
            );
        }
        let aliases = BTreeMap::from([(alias, p.clone())]);
        let expected = original_reverse_graph(&corpus, &aliases).unwrap();
        let actual = reverse_graph(&corpus, &aliases).unwrap();
        assert_eq!(
            serde_json::to_vec(&actual).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
        assert!(actual.contains_key(&p) && actual.contains_key(&q) && !actual.contains_key(&idle));
        for definition in [false, true] {
            let hash = |graph: &BTreeMap<PathBuf, BTreeSet<PathBuf>>| {
                let rows = corpus
                    .iter()
                    .filter(|(k, a)| a.definition == definition && graph.contains_key(*k))
                    .map(|(k, a)| (k.clone(), a.clone()))
                    .collect();
                corpus_digest(&rows).unwrap()
            };
            assert_eq!(hash(&actual), hash(&expected));
        }
    }
    #[test]
    fn streaming_refuses_rewritten_unrelated_metadata_replaced_inodes_and_retargeted_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("p.json");
        fs::write(&p, b"one").unwrap();
        let mut corpus = BTreeMap::from([(p.clone(), disk_artifact(&p, false))]);
        fs::write(&p, b"two").unwrap();
        assert!(reverse_graph(&corpus, &BTreeMap::new()).is_err());
        corpus.insert(p.clone(), disk_artifact(&p, false));
        let replacement = tmp.path().join("replacement");
        fs::write(&replacement, b"two").unwrap();
        fs::rename(&replacement, &p).unwrap();
        assert!(reverse_graph(&corpus, &BTreeMap::new()).is_err());
        let alias = tmp.path().join("link");
        std::os::unix::fs::symlink(&p, &alias).unwrap();
        let aliases = BTreeMap::from([(alias.clone(), p.clone())]);
        revalidate_aliases(&aliases).unwrap();
        fs::remove_file(&alias).unwrap();
        fs::write(&replacement, b"two").unwrap();
        std::os::unix::fs::symlink(&replacement, &alias).unwrap();
        assert!(revalidate_aliases(&aliases).is_err());
        let mut mismatched = disk_artifact(&p, false);
        mismatched.sha256 = "a".repeat(64);
        assert!(mismatched.read(&p).is_err());
    }
    #[test]
    fn disappearing_consumer_metadata_names_the_file_and_graph_pass() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scheduled-observer.service");
        fs::write(&path, SOURCE).unwrap();
        let corpus = BTreeMap::from([(path.clone(), disk_artifact(&path, true))]);
        fs::remove_file(&path).unwrap();
        let err = reverse_graph(&corpus, &BTreeMap::new()).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains(&format!("scan consumer metadata {}", path.display())));
        assert!(err.chain().any(|c| {
            c.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        }));
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
            schema: profile!(epoch "horizon-closed", "-transitive-consumer-closure-v1").into(),
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
