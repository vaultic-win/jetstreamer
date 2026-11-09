use super::*;
use std::collections::BTreeMap;
pub struct Fixture {
    pub(super) files: BTreeMap<String, ReadFile>,
    pub(super) answers: BTreeMap<String, Reply>,
    pub(super) directories: BTreeMap<String, Vec<String>>,
    queries: usize,
}
pub(super) fn key(q: &Request) -> String {
    format!("{} {:?}", q.program, q.argv)
}
impl Backend for Fixture {
    fn read(&mut self, p: &Pin) -> Result<ReadFile> {
        self.files
            .get(&p.path)
            .cloned()
            .context("fixture missing fixed input")
    }
    fn query(&mut self, q: &Request) -> Result<Reply> {
        self.queries += 1;
        self.answers
            .get(&key(q))
            .cloned()
            .context("fixture unknown native request")
    }
    fn directory_names(&mut self, d: &str) -> Result<Option<Vec<String>>> {
        Ok(self.directories.get(d).cloned())
    }
}
pub(super) fn file(p: &Pin, bytes: Vec<u8>) -> ReadFile {
    let m = Stamp {
        dev: 66305,
        ino: u64::from_le_bytes(Sha256::digest(p.path.as_bytes())[..8].try_into().unwrap()),
        uid: p.uid,
        gid: p.gid,
        mode: p.mode,
        bytes: bytes.len() as u64,
        nlink: 1,
        mtime: 1,
        mtime_nsec: 2,
        ctime: 3,
        ctime_nsec: 4,
    };
    ReadFile {
        bytes,
        before: m.clone(),
        after: m.clone(),
        named: m,
        canonical: p.canonical.clone(),
    }
}
fn response(v: Value) -> Reply {
    Reply {
        code: 0,
        stdout: v.to_string(),
        stderr: String::new(),
    }
}
fn set_bus(f: &mut Fixture, s: &Spec, interface: &str, p: &str, v: Value) {
    f.answers
        .insert(key(&bus(&s.unit, interface, p)), response(v));
}
pub(super) fn native(f: &mut Fixture, s: &Spec, iid: &str) {
    let mut p = PROPERTIES
        .split(',')
        .map(|k| (k.to_owned(), String::new()))
        .collect::<BTreeMap<_, _>>();
    for (k, v) in [
        ("Id", s.unit.as_str()),
        ("Names", s.unit.as_str()),
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("FragmentPath", s.recipe.path.as_str()),
        ("Transient", "no"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainCode", "0"),
        ("ExecMainStatus", "0"),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
    ] {
        p.insert(k.into(), v.into());
    }
    p.insert(
        "DropInPaths".into(),
        s.dropins
            .iter()
            .map(|p| p.path.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    );
    p.insert("InvocationID".into(), iid.into());
    f.answers.insert(
        key(&show(&s.unit)),
        Reply {
            code: 0,
            stdout: p.iter().map(|(k, v)| format!("{k}={v}\n")).collect(),
            stderr: String::new(),
        },
    );
    for hook in COMMANDS {
        let rows = if hook == "ExecStart" {
            json!([[
                s.expected_start[0],
                s.expected_start,
                false,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]])
        } else {
            json!([])
        };
        set_bus(
            f,
            s,
            "org.freedesktop.systemd1.Service",
            hook,
            json!({"type":"a(sasbttttuii)","data":rows}),
        );
    }
    let rows = s
        .expected_conditions
        .iter()
        .map(|(k, t, n, p)| json!([k, t, n, p, 0]))
        .collect::<Vec<_>>();
    set_bus(
        f,
        s,
        "org.freedesktop.systemd1.Unit",
        "Conditions",
        json!({"type":"a(sbbsi)","data":rows}),
    );
    set_bus(
        f,
        s,
        "org.freedesktop.systemd1.Service",
        "Environment",
        json!({"type":"as","data":s.expected_environment}),
    );
    set_bus(
        f,
        s,
        "org.freedesktop.systemd1.Service",
        "UnsetEnvironment",
        json!({"type":"as","data":s.expected_unset}),
    );
    set_bus(
        f,
        s,
        "org.freedesktop.systemd1.Service",
        "EnvironmentFiles",
        json!({"type":"a(sb)","data":[]}),
    );
    set_bus(
        f,
        s,
        "org.freedesktop.systemd1.Service",
        "PassEnvironment",
        json!({"type":"as","data":[]}),
    );
}
pub(super) fn setup() -> (Fixture, ReviewBinding, Vec<Spec>) {
    let mut specs = specs().unwrap();
    let mut f = Fixture {
        files: BTreeMap::new(),
        answers: BTreeMap::new(),
        directories: BTreeMap::new(),
        queries: 0,
    };
    let mut rows = Vec::new();
    let fixtures: BTreeMap<String, Vec<u8>> =
        serde_json::from_slice(include_bytes!("../fixture-bytes.json")).unwrap();
    for (index, s) in specs.iter_mut().enumerate() {
        for p in std::iter::once(&mut s.recipe)
            .chain(s.dropins.iter_mut())
            .chain(s.dependencies.iter_mut())
        {
            // Genuine captured source/metadata bytes; small synthetic ELF TRANSPORT only.
            // The same production custody/hash reader is exercised; no real image claim.
            let b = if p.kind == "Executable" {
                let b = b"\x7fELFexplicit-test-artifact-transport".to_vec();
                p.sha256 = digest(&b);
                p.bytes = b.len() as u64;
                b
            } else {
                fixtures[p.fixture.as_ref().unwrap()].clone()
            };
            f.files.insert(p.path.clone(), file(p, b));
        }
        for p in &s.dropins {
            f.directories
                .entry(Path::new(&p.path).parent().unwrap().display().to_string())
                .or_default()
                .push(
                    Path::new(&p.path)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
        }
        let original_iid = format!("{:032x}", index + 1);
        let history = json!({"unit":s.unit,"original_iid":original_iid});
        let b = history.to_string().into_bytes();
        let p = Pin {
            path: format!("/var/lib/jetstreamer/test-original-{index}.json"),
            canonical: format!("/var/lib/jetstreamer/test-original-{index}.json"),
            sha256: digest(&b),
            kind: "History".into(),
            uid: 0,
            gid: 0,
            mode: libc::S_IFREG | 0o444,
            bytes: b.len() as u64,
            single_link: true,
            fixture: None,
        };
        f.files.insert(p.path.clone(), file(&p, b));
        let interpreter = if s.role == "BootstrapRestoreNotSelected" {
            let b = b"\x7fELFtest-python-transport".to_vec();
            let p = Pin {
                path: "/home/linuxbrew/.linuxbrew/bin/python3".into(),
                canonical: "/home/linuxbrew/.linuxbrew/Cellar/python@3.15/3.15.1/bin/python3.15"
                    .into(),
                sha256: digest(&b),
                kind: "Executable".into(),
                uid: 1000,
                gid: 1000,
                mode: libc::S_IFREG | 0o755,
                bytes: b.len() as u64,
                single_link: true,
                fixture: None,
            };
            f.files.insert(p.path.clone(), file(&p, b));
            Some(p)
        } else {
            None
        };
        rows.push(RowReview {
            unit: s.unit.clone(),
            role: s.role.clone(),
            origin: Origin {
                evidence: p,
                unit_pointer: "/unit".into(),
                iid_pointer: "/original_iid".into(),
                original_iid: original_iid.clone(),
            },
            bootstrap_interpreter: interpreter,
            complete_selected_cache_readset_reviewed: true,
        });
        native(&mut f, s, "");
    }
    let r = Review {
        schema: "horizon-old220-peers1012-independent-readsets-v1".into(),
        source_specs_sha256: digest(SPEC_BYTES),
        selected_owner: OWNER.into(),
        selected_epoch: 220,
        selected_inodes: vec![20581075, 20582466],
        rows,
        data_retirement_authorized: false,
        global_alias_closure_qualified: false,
    };
    let bytes = serde_json::to_vec(&r).unwrap();
    let binding = ReviewBinding {
        sha256: digest(&bytes),
        bytes: bytes.len() as u64,
    };
    let pin = review_pin(&binding).unwrap();
    f.files.insert(REVIEW.into(), file(&pin, bytes));
    (f, binding, specs)
}
fn rewrite_review(f: &mut Fixture, b: &mut ReviewBinding, change: impl FnOnce(&mut Value)) {
    let mut v: Value = serde_json::from_slice(&f.files[REVIEW].bytes).unwrap();
    change(&mut v);
    let bytes = serde_json::to_vec(&v).unwrap();
    b.sha256 = digest(&bytes);
    b.bytes = bytes.len() as u64;
    let p = review_pin(b).unwrap();
    f.files.insert(REVIEW.into(), file(&p, bytes));
}

/// Dev-only opaque fixture; production capture remains fixed to compiled specs.
pub struct CaptureFixture {
    backend: Fixture,
    binding: ReviewBinding,
    specs: Vec<Spec>,
}
impl CaptureFixture {
    pub fn new() -> Self {
        let (backend, binding, specs) = setup();
        Self {
            backend,
            binding,
            specs,
        }
    }
    pub fn binding(&self) -> ReviewBinding {
        self.binding.clone()
    }
    pub fn capture(&mut self, jobs: &str) -> Result<ValidatedPeers> {
        capture_specs(&mut self.backend, &self.binding, jobs, &self.specs)
    }
    pub fn fragment(&self, raw: usize) -> (String, Vec<u8>) {
        let p = &self.specs[raw].recipe;
        (p.path.clone(), self.backend.files[&p.path].bytes.clone())
    }
    pub fn change_native(&mut self, raw: usize, property: &str, value: &str) {
        let q = show(&self.specs[raw].unit);
        let answer = self.backend.answers.get_mut(&key(&q)).unwrap();
        let mut fields = props(&answer.stdout).unwrap();
        fields.insert(property.into(), value.into());
        answer.stdout = fields
            .into_iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect();
    }
    pub fn exclusive_identities(&mut self, proof: &ValidatedPeers) -> Result<BTreeSet<(u64, u64)>> {
        proof.exclusive_identities(&mut self.backend)
    }
    pub fn exclusive_path(&self) -> String {
        self.specs
            .iter()
            .flat_map(|s| &s.dependencies)
            .find(|p| matches!(p.kind.as_str(), "Script" | "PublicationV2"))
            .unwrap()
            .path
            .clone()
    }
    pub fn shared_sdk_path(&self) -> String {
        self.specs
            .iter()
            .flat_map(|s| &s.dependencies)
            .find(|p| p.kind == "BootstrapSourceProvenance")
            .unwrap()
            .path
            .clone()
    }
    pub fn change_input_stamp(&mut self, path: &str) {
        self.backend.files.get_mut(path).unwrap().named.ino += 1;
    }
}

impl Backend for CaptureFixture {
    fn read(&mut self, p: &Pin) -> Result<ReadFile> {
        self.backend.read(p)
    }
    fn query(&mut self, q: &Request) -> Result<Reply> {
        self.backend.query(q)
    }
    fn directory_names(&mut self, p: &str) -> Result<Option<Vec<String>>> {
        self.backend.directory_names(p)
    }
}

// Peer-unit tests only; never a normal production constructor or selectable spec.
#[cfg(test)]
pub(super) fn condition_blocked_setup() -> (Fixture, ReviewBinding, Vec<Spec>) {
    setup()
}
