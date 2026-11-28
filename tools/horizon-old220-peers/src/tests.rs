use super::*;
use std::collections::BTreeMap;
struct Fixture {
    files: BTreeMap<String, ReadFile>,
    answers: BTreeMap<String, Reply>,
    directories: BTreeMap<String, Vec<String>>,
    queries: usize,
}
fn key(q: &Request) -> String {
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
fn file(p: &Pin, bytes: Vec<u8>) -> ReadFile {
    let m = Stamp {
        dev: 66305,
        ino: 42,
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
fn native(f: &mut Fixture, s: &Spec, iid: &str) {
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
fn setup() -> (Fixture, ReviewBinding, Vec<Spec>) {
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
#[test]
fn same_capture_core_accepts_genuine_sources_and_all_five_roles_without_authority() {
    let (mut f, b, s) = setup();
    let p = capture_specs(&mut f, &b, "", &s).unwrap();
    assert_eq!(p.rows.len(), 5);
    assert_eq!(f.queries, 70);
    let v = p.summary();
    assert_eq!(v["data_retirement_authorized"], false);
    assert_eq!(v["global_alias_closure_qualified"], false);
    assert_eq!(v["capacity_credit_bytes"], 0);
}
#[test]
fn missing_reordered_foreign_and_unreviewed_fifth_role_fail() {
    for case in 0..5 {
        let (mut f, mut b, s) = setup();
        rewrite_review(&mut f, &mut b, |v| match case {
            0 => {
                v["rows"].as_array_mut().unwrap().pop();
            }
            1 => v["rows"].as_array_mut().unwrap().swap(0, 1),
            2 => v["rows"][4]["unit"] = json!("arbitrary.service"),
            3 => v["rows"][4]["role"] = json!("SharedGcloudMetadataScript"),
            _ => v["rows"][4]["complete_selected_cache_readset_reviewed"] = json!(false),
        });
        assert!(capture_specs(&mut f, &b, "", &s).is_err());
    }
}
#[test]
fn profile_cannot_expand_owner_epoch_targets_or_authority() {
    for field in [
        "selected_owner",
        "selected_epoch",
        "selected_inodes",
        "source_specs_sha256",
        "data_retirement_authorized",
        "global_alias_closure_qualified",
    ] {
        let (mut f, mut b, s) = setup();
        rewrite_review(&mut f, &mut b, |v| {
            v[field] = match field {
                "selected_owner" => json!("/other"),
                "selected_epoch" => json!(241),
                "selected_inodes" => json!([20581075]),
                "source_specs_sha256" => json!("a".repeat(64)),
                _ => json!(true),
            }
        });
        assert!(capture_specs(&mut f, &b, "", &s).is_err());
    }
}
#[test]
fn changed_native_hooks_callback_environment_gate_and_argv_fail() {
    for case in 0..8 {
        let (mut f, b, s) = setup();
        let z = &s[4];
        match case {
            0 => {
                f.answers
                    .get_mut(&key(&show(&z.unit)))
                    .unwrap()
                    .stdout
                    .push_str("OnSuccess=foreign.service\n");
            }
            1 => set_bus(
                &mut f,
                z,
                "org.freedesktop.systemd1.Service",
                "ExecStopPost",
                json!({"type":"a(sasbttttuii)","data":[["/bin/sh",["/bin/sh","evil"],false,0,0,0,0,0,0,0]]}),
            ),
            2 => set_bus(
                &mut f,
                z,
                "org.freedesktop.systemd1.Service",
                "Environment",
                json!({"type":"as","data":["CLOUDSDK_CONFIG=/other"]}),
            ),
            3 => set_bus(
                &mut f,
                z,
                "org.freedesktop.systemd1.Unit",
                "Conditions",
                json!({"type":"a(sbbsi)","data":[]}),
            ),
            4 => {
                let mut argv = z.expected_start.clone();
                argv.push("--minimum-free-bytes=0".into());
                set_bus(
                    &mut f,
                    z,
                    "org.freedesktop.systemd1.Service",
                    "ExecStart",
                    json!({"type":"a(sasbttttuii)","data":[[argv[0],argv,false,0,0,0,0,0,0,0]]}),
                );
            }
            5 => set_bus(
                &mut f,
                z,
                "org.freedesktop.systemd1.Service",
                "EnvironmentFiles",
                json!({"type":"a(sb)","data":[["/arbitrary",true]]}),
            ),
            6 => set_bus(
                &mut f,
                z,
                "org.freedesktop.systemd1.Service",
                "PassEnvironment",
                json!({"type":"as","data":["LD_PRELOAD"]}),
            ),
            _ => {
                let r = f.answers.get_mut(&key(&show(&z.unit))).unwrap();
                r.stdout = r.stdout.replace(
                    "InvocationID=\n",
                    &format!("InvocationID={}\n", "f".repeat(32)),
                );
            }
        }
        assert!(capture_specs(&mut f, &b, "", &s).is_err(), "case{case}");
    }
}
#[test]
fn bootstrap_sixty_seventy_sources_directory_and_floor_cannot_change() {
    for case in 0..4 {
        let (mut f, b, s) = setup();
        let z = &s[4];
        match case {
            0 | 1 => {
                let p = &z.dropins[case];
                f.files.get_mut(&p.path).unwrap().bytes.push(b' ');
            }
            2 => {
                f.directories
                    .get_mut(&format!("/etc/systemd/system/{}.d", z.unit))
                    .unwrap()
                    .push("99-extra.conf".into());
            }
            _ => {
                f.directories
                    .remove(&format!("/etc/systemd/system/{}.d", z.unit));
            }
        }
        assert!(capture_specs(&mut f, &b, "", &s).is_err());
    }
}
#[test]
fn sources_batches_custody_and_named_identity_are_reopened() {
    for case in 0..5 {
        let (mut f, b, s) = setup();
        let p = &s[0].dependencies[3];
        let r = f.files.get_mut(&p.path).unwrap();
        match case {
            0 => r.bytes[0] ^= 1,
            1 => r.named.ino += 1,
            2 => r.after.ctime_nsec += 1,
            3 => r.before.uid = 0,
            _ => r.canonical = "/alias".into(),
        };
        assert!(capture_specs(&mut f, &b, "", &s).is_err());
    }
}
#[test]
fn queued_peer_and_access_query_errors_never_mean_absence() {
    let (mut f, b, s) = setup();
    assert!(capture_specs(&mut f, &b, &s[0].unit, &s).is_err());
    let (mut f, b, s) = setup();
    f.answers.get_mut(&key(&show(&s[0].unit))).unwrap().code = 1;
    assert!(capture_specs(&mut f, &b, "", &s).is_err());
}
#[test]
fn direct_only_staged_sources_never_allow_enabled_aliases_or_changed_bytes() {
    let (mut f, b, s) = setup();
    let p = capture_specs(&mut f, &b, "", &s).unwrap();
    let src = &s[4].recipe;
    let bytes = &f.files[&src.path].bytes;
    assert!(p.staged(Path::new(&src.path), bytes, "").unwrap());
    assert!(!p
        .staged(
            Path::new(&format!(
                "/etc/systemd/system/multi-user.target.wants/{}",
                s[4].unit
            )),
            bytes,
            ""
        )
        .unwrap());
    assert!(p.staged(Path::new(&src.path), b"changed", "").is_err());
    assert!(p.staged(Path::new(&src.path), bytes, &s[4].unit).is_err());
}
#[test]
fn native_tuple_width_signature_ignore_and_numeric_types_fail() {
    for raw in [
        json!({"type":"a(sasbttttuii)","data":[["/a",["/a"],false]]}),
        json!({"type":"as","data":[]}),
        json!({"type":"a(sasbttttuii)","data":[["/a",["/a"],false,-1,0,0,0,0,0,0]]}),
    ] {
        assert!(commands(&raw.to_string()).is_err());
    }
}
#[test]
fn altered_original_history_and_missing_interpreter_fail() {
    for case in 0..3 {
        let (mut f, mut b, s) = setup();
        rewrite_review(&mut f, &mut b, |v| match case {
            0 => v["rows"][0]["origin"]["original_iid"] = json!("f".repeat(32)),
            1 => v["rows"][0]["origin"]["iid_pointer"] = json!("/other"),
            _ => v["rows"][4]["bootstrap_interpreter"] = Value::Null,
        });
        assert!(capture_specs(&mut f, &b, "", &s).is_err());
    }
}
#[test]
fn batch_semantics_reject_wrong_epoch_and_uncommitted_outcome_in_actual_parser() {
    let (f, _, s) = setup();
    let spec = &s[0];
    let pin = spec
        .dependencies
        .iter()
        .find(|p| p.kind == "PublicationV2")
        .unwrap();
    let bytes = &f.files[&pin.path].bytes;
    json_input(spec, pin, bytes).unwrap();
    for case in 0..3 {
        let mut v: Value = serde_json::from_slice(bytes).unwrap();
        match case {
            0 => v["epochs"] = json!([220]),
            1 => v["outcome"]["kind"] = json!("prepared"),
            _ => v["schema"] = json!("generic"),
        };
        assert!(json_input(spec, pin, &serde_json::to_vec(&v).unwrap()).is_err());
    }
}
#[test]
fn every_fd_named_identity_field_is_compared_and_canonical_aliases_reject() {
    let (mut f, _, s) = setup();
    let p = &s[0].recipe;
    let original = f.files.remove(&p.path).unwrap();
    verify_file(p, original.clone()).unwrap();
    for field in 0..11 {
        let mut changed = original.clone();
        match field {
            0 => changed.named.dev += 1,
            1 => changed.named.ino += 1,
            2 => changed.named.uid += 1,
            3 => changed.named.gid += 1,
            4 => changed.named.mode ^= 1,
            5 => changed.named.bytes += 1,
            6 => changed.named.nlink += 1,
            7 => changed.named.mtime += 1,
            8 => changed.named.mtime_nsec += 1,
            9 => changed.named.ctime += 1,
            _ => changed.named.ctime_nsec += 1,
        };
        assert!(verify_file(p, changed).is_err());
    }
}
