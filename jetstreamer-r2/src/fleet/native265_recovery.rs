//! Evidence-consumer succession for the original native265 owner. No new admission.
use super::native265::{self as c, num, text};
use super::*;

const OLD_HELPER: &str =
    "/var/lib/jetstreamer/horizon-native265-consumers-57fbf500-20261119-v1/jetstreamer-r2";
const OLD_SHA: &str = "43c70fa88aa68f21a0bb09db716964fb18a00f82a924ce17a111c9962e8db3b0";
const ORIGINAL_IID: &str = "ce5f66a82fdd4c0e93ca99f27b925112";
const ORIGINAL_PID: u64 = 1307638;
const ORIGINAL_BOOT: &str = "3b17d005-5c3a-4a0e-8841-da097e0957b5";
pub(super) struct Source {
    pub startup_handoff: BoundFile,
    pub consumer_transition: BoundFile,
}
fn original(h: &Value, a: &Value) -> Result<()> {
    ensure!(
        h["invocation_id"] == ORIGINAL_IID
            && h["main_pid"] == ORIGINAL_PID
            && a["boot_id"] == ORIGINAL_BOOT
            && h["recorded_unix_seconds"] == 1795118095u64
            && h["admission"]["sha256"]
                == "a9d20936213c3eb0c875726d896aae24b18827210d7adedddfad0f67dbb5bb00"
            && h["guard_plan"]["sha256"]
                == "d6aa8d26f07c17ce85705f4cb4cd554b4a64d56fcb3fd02726a87fe7b04983ea",
        "265 successor is not the original retained owner"
    );
    Ok(())
}
fn sources(p: &Value) -> Result<BTreeMap<String, String>> {
    let rows = p["source_files"]
        .as_array()
        .context("265 successor source files")?;
    ensure!(!rows.is_empty() && rows.len() <= 16384, "265 source bounds");
    let mut map = BTreeMap::new();
    for row in rows {
        let path = text(row, "repository_path")?;
        let sha = text(row, "sha256")?;
        ensure!(
            !path.is_empty()
                && !path.starts_with('/')
                && path
                    .split('/')
                    .all(|p| !p.is_empty() && p != "." && p != "..")
                && c::hex(sha, 64)
                && map.insert(path.into(), sha.into()).is_none(),
            "265 successor unsafe/duplicate source"
        );
    }
    Ok(map)
}
/// Validate sealed source lineage independently at every downstream read. Capture
/// additionally verifies the actual local fetched Git objects and running image.
pub(super) fn transition(
    s: &Source,
    h: &Value,
    a: &Value,
    helper: &str,
    wall: u64,
    reader: &impl c::EvidenceReader,
) -> Result<Value> {
    original(h, a)?;
    ensure!(
        s.startup_handoff.sha256
            == "896c9678b442fb31f0eb679d457c425423f24e0afd3fbc1ea3432fb318e8a208",
        "265 exact original handoff required"
    );
    let t = reader.json(&s.consumer_transition, true)?;
    c::no_authority(&t)?;
    ensure!(
        t["schema"] == "horizon-native265-consumer-transition-v1"
            && t["startup_handoff"] == private157::binding(&s.startup_handoff)
            && t["original_source_publication"] == a["source_publication"]
            && t["original_helper"] == json!({"path":OLD_HELPER,"sha256":OLD_SHA})
            && t["successor_helper"]["sha256"] == helper
            && helper != OLD_SHA
            && c::hex(helper, 64)
            && t["Main_accepted"] == true
            && t["consumer_only"] == true
            && t["original_launch_authority_unchanged"] == true
            && t["remote_ref"] == "refs/heads/account-updates"
            && c::hex(text(&t, "remote_head")?, 40)
            && c::hex(text(&t, "source_commit")?, 40)
            && num(&t, "fetched_unix_seconds")? <= wall
            && wall - num(&t, "fetched_unix_seconds")? <= 1800,
        "265 successor transition scope/freshness"
    );
    let publication = reader.json(&c::binding(&a["source_publication"])?, true)?;
    let roles = publication["artifacts"]
        .as_array()
        .context("265 original artifacts")?;
    let fleet = roles
        .iter()
        .filter(|r| r["role"] == "fleet")
        .collect::<Vec<_>>();
    ensure!(
        fleet.len() == 1
            && fleet[0]["artifact"] == t["original_helper"]
            && fleet[0]["provenance"] == t["original_provenance"],
        "265 original helper lineage"
    );
    let old = reader.json(&c::binding(&t["original_provenance"])?, true)?;
    let new = reader.json(&c::binding(&t["successor_provenance"])?, true)?;
    for (p, artifact) in [
        (&old, &t["original_helper"]),
        (&new, &t["successor_helper"]),
    ] {
        ensure!(
            p["schema"] == "horizon-native265-exact-artifact-provenance-v1"
                && p["artifact"] == *artifact
                && p["all_source_dependencies_enumerated"] == true
                && p["Main_accepted"] == true,
            "265 successor provenance identity"
        );
    }
    ensure!(
        new["source_commit"] == t["source_commit"]
            && old["source_commit"] == fleet[0]["source_commit"],
        "265 successor source commit substitution"
    );
    let old_sources = sources(&old)?;
    let new_sources = sources(&new)?;
    let changed = old_sources
        .keys()
        .chain(new_sources.keys())
        .filter(|p| old_sources.get(*p) != new_sources.get(*p))
        .cloned()
        .collect::<BTreeSet<_>>();
    let reviewed = t["reviewed_source_changes"]
        .as_array()
        .context("265 reviewed changes")?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).context("265 changed path"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        !changed.is_empty() && changed == reviewed,
        "265 unreviewed source difference"
    );
    for path in &changed {
        // The already-qualified full211 dependency added these exact manifest
        // bytes. Registry inputs and all predecessor externs remain pinned below.
        let qualified_manifest = match path.as_str() {
            "Cargo.toml" => {
                Some("d3b7eb14a1f207bf97b510552462c74656526b451d1f83cc5f4b0553636edd7d")
            }
            "Cargo.lock" => {
                Some("fe97cb3d9d7fa670a50430e8c864bef07492971e24ea9ab1f25c4bc9a4af377c")
            }
            "jetstreamer-r2/Cargo.toml" => {
                Some("ea125c870832f48ba370e900e96922b22bc14e345404bfd0f2b551418ff06457")
            }
            _ => None,
        };
        ensure!(
            new_sources.contains_key(path)
                && (path.starts_with("jetstreamer-r2/src/")
                    || qualified_manifest.is_some_and(|sha| new_sources[path] == sha)
                    // account-updates removed only the stale, unused tempfile
                    // edge for full211. Its compiled library is unchanged.
                    || (path == "Cargo.lock" && new_sources[path]
                        == "f1fefe40d58914edf4b4c3bce551fa78b1b4c2f9e9b8675e442062a66bb9fff9")),
            "265 successor changed producer/dependency or removed source"
        );
    }
    // Preserve every exact predecessor extern; only the already qualified
    // full211 consumer library addition is independently registered below.
    let old_closure = reader.json(&c::binding(&old["build_dependency_closure"])?, true)?;
    let closure = reader.json(&c::binding(&new["build_dependency_closure"])?, true)?;
    ensure!(
        closure["schema"] == "horizon-native265-build-dependency-closure-v1"
            && closure["role"] == "fleet"
            && closure["artifact"] == t["successor_helper"]
            && closure["source_commit"] == t["source_commit"]
            && closure["unresolved_dependencies"] == json!([])
            && old_closure["unresolved_dependencies"] == json!([])
            && closure["linked_local_library"] == old_closure["linked_local_library"]
            && closure["locked_registry_dependencies"]
                == old_closure["locked_registry_dependencies"]
            && closure["transitive_cargo_fingerprints"]
                == old_closure["transitive_cargo_fingerprints"],
        "265 successor dependency closure differs"
    );
    let original_externs = old_closure["actual_externs"]
        .as_array()
        .context("265 predecessor externs")?;
    let successor_externs = closure["actual_externs"]
        .as_array()
        .context("265 successor externs")?;
    ensure!(
        successor_externs.len() == original_externs.len() + 1
            && original_externs
                .iter()
                .all(|old| successor_externs.contains(old)),
        "265 predecessor actual extern changed or lost"
    );
    let added = successor_externs
        .iter()
        .filter(|e| !original_externs.contains(e))
        .collect::<Vec<_>>();
    ensure!(
        added.len() == 1
            && added[0]["crate"] == "horizon_singleton211_launch"
            && added[0]["path"]
                == "/home/ubuntu/.jetstreamer-private/full211-consumers-build-20261119-v1/libhorizon_singleton211_launch.rlib"
            && added[0]["sha256"]
                == "d41a703fcf07393c44948e93af4170bdc57267d8a7fe1176345274365ea4675f",
        "265 unqualified new consumer dependency"
    );
    let qualified = BoundFile {
        path:
            "/var/lib/jetstreamer/horizon-full211-consumers-e8198ad8-20261119-v1/qualification.json"
                .into(),
        sha256: "d368a2a76d4c8ddd476581adfab6f7cf80270915b40188692a72803930a44c39".into(),
    };
    ensure!(
        closure["full211_dependency_qualification"] == private157::binding(&qualified),
        "265 full211 qualification substitution"
    );
    let q = reader.json(&qualified, true)?;
    ensure!(
        q["schema"] == "horizon-full211-r2-source-qualification-v1"
            && q["source_commit"] == "e8198ad8bebe566f9c064a5d5ae7df431b2afa10"
            && q["remote_containment_verified"] == true
            && q["strict_test_clippy"] == true
            && q["production_build"] == true
            && q["library_extern"]["path"] == added[0]["path"]
            && q["library_extern"]["sha256"] == added[0]["sha256"]
            && q["replay_launch_authorized"] == false
            && q["actual_full211_runtime_qualified"] == false,
        "265 full211 source-only dependency qualification differs"
    );
    let argv = closure["actual_rustc_argv"]
        .as_array()
        .context("265 actual rustc argv")?
        .iter()
        .map(|v| v.as_str().context("265 rustc arg"))
        .collect::<Result<Vec<_>>>()?;
    let invocation = reader.bytes(
        &c::binding(&closure["actual_rustc_argv_evidence"])?,
        1 << 20,
    )?;
    ensure!(
        serde_json::from_slice::<Vec<String>>(&invocation)? == argv,
        "265 actual argv evidence differs"
    );
    ensure!(
        !argv
            .iter()
            .any(|a| a.starts_with("--extern=") || a.starts_with("--cfg=")),
        "265 unsupported joined build flags"
    );
    ensure!(
        argv.last()
            .is_none_or(|s| !matches!(*s, "--extern" | "--cfg")),
        "265 dangling rustc binding flag"
    );
    let mut externs = BTreeSet::new();
    let mut features = BTreeSet::new();
    for pair in argv.windows(2) {
        if pair[0] == "--extern" {
            ensure!(externs.insert(pair[1]), "265 duplicate extern");
        }
        if pair[0] == "--cfg" && pair[1].starts_with("feature=") {
            features.insert(pair[1]);
        }
    }
    let required = closure["actual_externs"]
        .as_array()
        .context("265 extern manifest")?
        .iter()
        .map(|v| Ok(format!("{}={}", text(v, "crate")?, text(v, "path")?)))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        !required.is_empty()
            && externs
                .iter()
                .map(|s| s.to_string())
                .collect::<BTreeSet<_>>()
                == required
            && t["actual_features"] == closure["actual_features"]
            && t["preserved_predecessor_features"] == true,
        "265 actual build feature/extern bindings differ"
    );
    let feature_names = features
        .iter()
        .map(|s| {
            s.strip_prefix("feature=\"")
                .and_then(|s| s.strip_suffix('"'))
                .map(str::to_owned)
                .context("265 feature syntax")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let declared_features = closure["actual_features"]
        .as_array()
        .context("265 actual features")?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).context("265 feature name"))
        .collect::<Result<BTreeSet<_>>>()?;
    let original_command = text(&old_closure, "recorded_build_command")?;
    ensure!(
        feature_names == declared_features,
        "265 actual feature list differs from argv"
    );
    for feature in original_command.split("feature=\"").skip(1) {
        let name = feature
            .split('"')
            .next()
            .context("265 old feature syntax")?;
        ensure!(feature_names.contains(name), "265 predecessor feature lost");
    }
    let qualification = reader.json(&c::binding(&new["qualification_evidence"])?, true)?;
    ensure!(
        qualification["schema"] == "horizon-native265-successor-consumer-qualification-v1"
            && qualification["artifact"] == t["successor_helper"]
            && qualification["source_commit"] == t["source_commit"]
            && qualification["actual_features"] == closure["actual_features"]
            && qualification["genuine_original_startup_graph_passed"] == true
            && qualification["successor_outer_terminal_event_tests_passed"] == true
            && qualification["predecessor_consumers_preserved"] == true
            && qualification["guard60_boundary_tests_passed"] == true,
        "265 successor actual qualification absent"
    );
    for key in [
        "build_command_evidence",
        "accepted_source_manifest",
        "accepted_source_archive",
    ] {
        let b = c::binding(&closure[key])?;
        // Archive bytes are bounded separately; none is runtime authority.
        reader.bytes(
            &b,
            if key == "accepted_source_archive" {
                128 << 20
            } else {
                4 << 20
            },
        )?;
    }
    Ok(t)
}
fn git(args: &[&str]) -> Result<Vec<u8>> {
    let out = ProcessCommand::new("/usr/bin/git")
        .args([
            "-c",
            "safe.directory=/home/ubuntu/workspace/jetstreamer",
            "-C",
            "/home/ubuntu/workspace/jetstreamer",
        ])
        .args(args)
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16 << 20,
        "265 successor git proof unavailable"
    );
    Ok(out.stdout)
}
pub(super) fn publication(s: &Source, h: &Value, a: &Value, helper: &str, wall: u64) -> Result<()> {
    let t = transition(s, h, a, helper, wall, &c::FsEvidence)?;
    let path = std::env::current_exe()?;
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        path.starts_with("/var/lib/jetstreamer")
            && path.canonicalize()? == path
            && metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && metadata.len() <= 128 << 20,
        "265 successor artifact custody differs"
    );
    ensure!(
        t["successor_helper"]["path"].as_str() == path.to_str()
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == helper,
        "265 successor running artifact differs"
    );
    let head = text(&t, "remote_head")?;
    ensure!(
        std::str::from_utf8(&git(&["rev-parse", "refs/remotes/origin/account-updates"])?)?.trim()
            == head,
        "265 successor fetched head changed"
    );
    let commit = text(&t, "source_commit")?;
    git(&["merge-base", "--is-ancestor", commit, head])?;
    git(&[
        "merge-base",
        "--is-ancestor",
        "e8198ad8bebe566f9c064a5d5ae7df431b2afa10",
        head,
    ])?;
    let provenance = c::sealed(&c::binding(&t["successor_provenance"])?)?;
    for (path, sha) in sources(&provenance)? {
        ensure!(
            hex_lower(&Sha256::digest(git(&[
                "show",
                &format!("{commit}:{path}")
            ])?))
                == sha,
            "265 successor published source differs"
        );
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use c::EvidenceReader;
    pub(crate) struct Reader {
        pub(crate) values: BTreeMap<PathBuf, Value>,
        pub(crate) bytes: BTreeMap<PathBuf, Vec<u8>>,
    }
    impl c::EvidenceReader for Reader {
        fn json(&self, b: &BoundFile, _immutable: bool) -> Result<Value> {
            self.values.get(&b.path).cloned().context("fixture JSON")
        }
        fn bytes(&self, b: &BoundFile, maximum: u64) -> Result<Vec<u8>> {
            let bytes = self.bytes.get(&b.path).context("fixture bytes")?;
            ensure!(bytes.len() as u64 <= maximum, "fixture bound");
            Ok(bytes.clone())
        }
        fn canonical(&self, p: &Path) -> Result<PathBuf> {
            for h in self.values.values() {
                if h["schema"] == "horizon-native265-guarded-startup-v1"
                    && h["producer"]["FragmentPath"].as_str() == p.to_str()
                {
                    return Ok(c::binding(&h["unit_file"])?.path);
                }
            }
            Ok(p.into())
        }
    }
    pub(crate) fn retained() -> (BoundFile, Reader) {
        let fixture: Value =
            serde_json::from_str(include_str!("fixtures/native265-startup-20261119.json")).unwrap();
        let values = fixture["values"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(p, v)| (PathBuf::from(p), v.clone()))
            .collect();
        let bytes = fixture["raws"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(p, v)| (PathBuf::from(p), v.as_str().unwrap().as_bytes().to_vec()))
            .collect();
        (
            c::binding(&fixture["startup_handoff"]).unwrap(),
            Reader { values, bytes },
        )
    }
    pub(crate) fn b(name: &str) -> Value {
        json!({"path":format!("/var/lib/jetstreamer/fixture/{name}"),"sha256":"a".repeat(64)})
    }
    pub(crate) fn put(reader: &mut Reader, name: &str, v: Value) -> Value {
        let bound = b(name);
        reader.values.insert(c::binding(&bound).unwrap().path, v);
        bound
    }
    #[test]
    fn genuine_original_startup_graph_remains_historical_and_rejects_reissued_token() {
        let (hb, mut reader) = retained();
        let (h, a) = c::startup_read(&hb, &reader).unwrap();
        original(&h, &a).unwrap();
        let token = c::binding(&h["first_guard_token"]).unwrap();
        let p = c::binding(&h["startup_plan"]).unwrap();
        let expiry = num(&reader.values[&p.path], "expires_monotonic_us").unwrap();
        reader.values.get_mut(&token.path).unwrap()["recorded_monotonic_us"] = json!(expiry + 1);
        assert!(c::startup_read(&hb, &reader).is_err());
    }
    pub(crate) fn successor_source(
        hb: &BoundFile,
        reader: &mut Reader,
        _h: &Value,
        a: &Value,
        wall: u64,
    ) -> (Source, String) {
        let helper = "b".repeat(64);
        let commit = "c".repeat(40);
        let source = reader
            .json(&c::binding(&a["source_publication"]).unwrap(), true)
            .unwrap();
        let fleet = source["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["role"] == "fleet")
            .unwrap();
        let artifact =
            json!({"path":"/var/lib/jetstreamer/fixture/jetstreamer-r2","sha256":helper});
        let features = json!([]);
        let argv = json!([
            "rustc",
            "--extern",
            "anyhow=/var/lib/jetstreamer/fixture/libanyhow.rlib",
            "--extern",
            "horizon_singleton211_launch=/home/ubuntu/.jetstreamer-private/full211-consumers-build-20261119-v1/libhorizon_singleton211_launch.rlib"
        ]);
        let argv_b = b("argv");
        reader.bytes.insert(
            c::binding(&argv_b).unwrap().path,
            serde_json::to_vec(&argv).unwrap(),
        );
        for key in ["build-command", "manifest", "archive"] {
            reader
                .bytes
                .insert(c::binding(&b(key)).unwrap().path, Vec::new());
        }
        let old_closure = json!({"unresolved_dependencies":[],"actual_externs":[{"crate":"anyhow","path":"/var/lib/jetstreamer/fixture/libanyhow.rlib","sha256":"d".repeat(64)}],"linked_local_library":{},"locked_registry_dependencies":{},"transitive_cargo_fingerprints":[],"recorded_build_command":"rustc"});
        let old_closure_b = put(reader, "old-closure", old_closure.clone());
        let mut closure = old_closure;
        closure["actual_externs"].as_array_mut().unwrap().push(json!({"crate":"horizon_singleton211_launch","path":"/home/ubuntu/.jetstreamer-private/full211-consumers-build-20261119-v1/libhorizon_singleton211_launch.rlib","sha256":"d41a703fcf07393c44948e93af4170bdc57267d8a7fe1176345274365ea4675f"}));
        let q: Value = serde_json::from_str(include_str!(
            "fixtures/native265-full211-dependency-20261119.json"
        ))
        .unwrap();
        let qb = json!({"path":"/var/lib/jetstreamer/horizon-full211-consumers-e8198ad8-20261119-v1/qualification.json","sha256":"d368a2a76d4c8ddd476581adfab6f7cf80270915b40188692a72803930a44c39"});
        reader.values.insert(c::binding(&qb).unwrap().path, q);
        closure["full211_dependency_qualification"] = qb;
        closure["schema"] = json!("horizon-native265-build-dependency-closure-v1");
        closure["role"] = json!("fleet");
        closure["artifact"] = artifact.clone();
        closure["source_commit"] = json!(commit);
        closure["actual_rustc_argv"] = argv;
        closure["actual_rustc_argv_evidence"] = argv_b;
        closure["actual_features"] = features.clone();
        closure["build_command_evidence"] = b("build-command");
        closure["accepted_source_manifest"] = b("manifest");
        closure["accepted_source_archive"] = b("archive");
        let closure_b = put(reader, "closure", closure);
        let qualification = json!({"schema":"horizon-native265-successor-consumer-qualification-v1","artifact":artifact,"source_commit":commit,"actual_features":features,"genuine_original_startup_graph_passed":true,"successor_outer_terminal_event_tests_passed":true,"predecessor_consumers_preserved":true,"guard60_boundary_tests_passed":true});
        let qualification_b = put(reader, "qualification", qualification);
        let old = json!({"schema":"horizon-native265-exact-artifact-provenance-v1","artifact":fleet["artifact"],"source_commit":fleet["source_commit"],"all_source_dependencies_enumerated":true,"Main_accepted":true,"source_files":[{"repository_path":"jetstreamer-r2/src/fleet/native265_capture.rs","sha256":"a".repeat(64)}],"build_dependency_closure":old_closure_b});
        reader
            .values
            .insert(c::binding(&fleet["provenance"]).unwrap().path, old.clone());
        let mut new = old;
        new["artifact"] = artifact.clone();
        new["source_commit"] = json!(commit);
        new["source_files"][0]["sha256"] = json!("b".repeat(64));
        new["build_dependency_closure"] = closure_b;
        new["qualification_evidence"] = qualification_b;
        let new_b = put(reader, "provenance", new);
        let mut transition = json!({"schema":"horizon-native265-consumer-transition-v1","startup_handoff":private157::binding(hb),"original_source_publication":a["source_publication"],"original_helper":fleet["artifact"],"successor_helper":artifact,"Main_accepted":true,"consumer_only":true,"original_launch_authority_unchanged":true,"remote_ref":"refs/heads/account-updates","remote_head":commit,"source_commit":commit,"fetched_unix_seconds":wall,"original_provenance":fleet["provenance"],"successor_provenance":new_b,"reviewed_source_changes":["jetstreamer-r2/src/fleet/native265_capture.rs"],"actual_features":features,"preserved_predecessor_features":true});
        c::deny(&mut transition);
        let transition_b = put(reader, "transition", transition);
        (
            Source {
                startup_handoff: hb.clone(),
                consumer_transition: c::binding(&transition_b).unwrap(),
            },
            helper,
        )
    }

    #[test]
    fn full211_manifest_registration_accepts_only_the_qualified_bytes() {
        let (hb, mut reader) = retained();
        let (h, a) = c::startup_read(&hb, &reader).unwrap();
        let wall = num(&h, "recorded_unix_seconds").unwrap() + 900;
        let (source, helper) = successor_source(&hb, &mut reader, &h, &a, wall);
        let t = reader.values[&source.consumer_transition.path].clone();
        let p = c::binding(&t["successor_provenance"]).unwrap();
        reader.values.get_mut(&p.path).unwrap()["source_files"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "repository_path":"Cargo.toml",
                "sha256":"d3b7eb14a1f207bf97b510552462c74656526b451d1f83cc5f4b0553636edd7d"
            }));
        reader
            .values
            .get_mut(&source.consumer_transition.path)
            .unwrap()["reviewed_source_changes"]
            .as_array_mut()
            .unwrap()
            .push(json!("Cargo.toml"));
        transition(&source, &h, &a, &helper, wall, &reader).unwrap();
        reader.values.get_mut(&p.path).unwrap()["source_files"][1]["sha256"] =
            json!("f".repeat(64));
        assert!(transition(&source, &h, &a, &helper, wall, &reader).is_err());
    }
}
