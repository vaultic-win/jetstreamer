//! A distinct read-only proof for five exact, condition-blocked legacy peers.
//! Original specs/histories/argv/env/conditions remain authoritative. No source
//! constructor converts this proof into the older full semantic-review scope.
use super::*;
use std::path::PathBuf;

const REVIEW: &str = "/var/lib/jetstreamer/horizon-old220-peers1060-review-v1/review.json";
const REVIEW_SCHEMA: &str = "horizon-old220-peers1060-condition-blocked-review-v1";
const SUMMARY_SCHEMA: &str = "horizon-old220-peers1060-exact-five-condition-blocked-v1";
const SCOPE: &str =
    "potential-declared-program-inputs-separate-from-condition-blocked-admitted-reads";
const GUARD: &str = "99-snapshot92447542-nonlaunchable.conf";
const MARKER: &str = "snapshot92447542-nonlaunchable-marker.json";
const SEALER: &str = "f77e62124cf79a39a27706025d3e36e62d90fba8aadbee3e2bf4f68fb4f23d98";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GuardBinding {
    guard: Pin,
    marker: Pin,
    seal: Pin,
    sums: Pin,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Row {
    unit: String,
    role: String,
    origin: Origin,
    bootstrap_interpreter: Option<Pin>,
    potential_program_review: Pin,
    condition_blocked_guard: GuardBinding,
    historical_loader_execution_qualified: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Review {
    schema: String,
    scope: String,
    source_specs_sha256: String,
    selected_owner: String,
    selected_epoch: u64,
    selected_inodes: Vec<u64>,
    rows: Vec<Row>,
    data_retirement_authorized: bool,
    global_alias_closure_qualified: bool,
    historical_loader_execution_qualified: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PotentialReview {
    schema: String,
    unit: String,
    role: String,
    original_specs_sha256: String,
    original_spec_sha256: String,
    selected_owner: String,
    selected_epoch: u64,
    selected_inodes: Vec<u64>,
    scope: String,
    application_review: String,
    unresolved_historical_loader_inputs: Vec<String>,
    historical_loader_execution_qualified: bool,
    data_retirement_authorized: bool,
    global_alias_closure_qualified: bool,
}
fn root_pin(pin: &Pin, maximum: u64, kind: &str) -> Result<()> {
    ensure!(
        pin.kind == kind
            && pin.uid == 0
            && pin.gid == 0
            && pin.mode == (libc::S_IFREG | 0o444)
            && pin.single_link
            && pin.bytes > 0
            && pin.bytes <= maximum
            && pin.fixture.is_none()
            && pin.path == pin.canonical
            && ordinary(&pin.path)
            && sha(&pin.sha256),
        "guard/review input is not exact Root444 single-link evidence"
    );
    Ok(())
}
fn guard_directory(spec: &Spec, guard: &GuardBinding) -> Result<PathBuf> {
    root_pin(&guard.guard, 16384, "ConditionGuard")?;
    root_pin(&guard.marker, 65536, "ConditionMarker")?;
    root_pin(&guard.seal, 1 << 20, "GuardDeploymentSeal")?;
    root_pin(&guard.sums, 16384, "GuardSHA256SUMS")?;
    let path = Path::new(&guard.guard.path);
    let directory = path.parent().context("guard parent missing")?;
    ensure!(
        ["/etc/systemd/system", "/run/systemd/system"]
            .iter()
            .any(|root| directory == Path::new(root).join(format!("{}.d", spec.unit)))
            && path.file_name().is_some_and(|n| n == GUARD),
        "guard is not the exact registered unit's system drop-in"
    );
    for (pin, name) in [
        (&guard.marker, MARKER),
        (&guard.seal, "deployment-seal-receipt.json"),
        (&guard.sums, "SHA256SUMS"),
    ] {
        ensure!(
            Path::new(&pin.path) == directory.join(name),
            "foreign guard package member"
        );
    }
    ensure!(
        !spec.dropins.iter().any(|p| p.path == guard.guard.path),
        "guard cannot replace an original drop-in"
    );
    Ok(directory.into())
}
fn guard_files(
    backend: &mut impl Backend,
    budget: &mut Budget,
    spec: &Spec,
    guard: &GuardBinding,
) -> Result<()> {
    let directory = guard_directory(spec, guard)?;
    let bytes = budget.read(backend, &guard.guard)?;
    ensure!(
        bytes == format!("[Unit]\nConditionPathExists=!{}\n", guard.marker.path).as_bytes(),
        "guard resets or adds an unreviewed directive"
    );
    let marker: Value = serde_json::from_slice(&budget.read(backend, &guard.marker)?)?;
    ensure!(
        marker["unit"] == spec.unit,
        "marker belongs to another unit"
    );
    let seal: Value = serde_json::from_slice(&budget.read(backend, &guard.seal)?)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == directory.to_str().context("guard directory UTF8")?
            && seal["sealer_sha256"] == SEALER
            && seal["publication_authorized"] == false
            && seal["replay_launch_authorized"] == false
            && seal["remote_mutations"] == false
            && seal["r2_mutations"] == false,
        "guard deployment seal scope differs"
    );
    let members = seal["members"]
        .as_array()
        .context("guard seal members missing")?;
    ensure!(members.len() == 2, "guard seal has unknown payload members");
    let mut declared = BTreeSet::new();
    for member in members {
        let name = member["name"].as_str().context("guard member name")?;
        ensure!(declared.insert(name), "duplicate guard seal member");
        let pin = match name {
            GUARD => &guard.guard,
            MARKER => &guard.marker,
            _ => anyhow::bail!("unrecognized guard seal member"),
        };
        ensure!(
            member["sha256"] == pin.sha256
                && member["bytes"] == pin.bytes
                && member["mode"] == "0444",
            "guard seal payload binding differs"
        );
    }
    let sums = budget.read(backend, &guard.sums)?;
    let mut expected = BTreeMap::new();
    expected.insert(GUARD, guard.guard.sha256.as_str());
    expected.insert(MARKER, guard.marker.sha256.as_str());
    expected.insert("deployment-seal-receipt.json", guard.seal.sha256.as_str());
    let exact = expected
        .iter()
        .map(|(name, hash)| format!("{hash}  {name}\n"))
        .collect::<String>();
    ensure!(sums == exact.as_bytes(), "guard SHA256SUMS differs");
    Ok(())
}
fn directories(backend: &mut impl Backend, spec: &Spec, guard: &GuardBinding) -> Result<()> {
    let guarded = guard_directory(spec, guard)?;
    for root in ROOTS {
        let directory = format!("{root}/{}.d", spec.unit);
        let mut expected = spec
            .dropins
            .iter()
            .filter(|pin| Path::new(&pin.path).parent() == Some(Path::new(&directory)))
            .map(|pin| {
                Path::new(&pin.path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        if Path::new(&directory) == guarded {
            expected.extend(
                [GUARD, MARKER, "deployment-seal-receipt.json", "SHA256SUMS"]
                    .into_iter()
                    .map(str::to_owned),
            );
        }
        match backend.directory_names(&directory)? {
            None => ensure!(
                expected.is_empty(),
                "required original/guard drop-in directory missing"
            ),
            Some(names) => ensure!(
                !expected.is_empty() && set(&names)? == set(&expected)?,
                "new/missing/unknown member in original or guarded unit.d"
            ),
        }
    }
    Ok(())
}
fn guarded_spec(spec: &Spec, guard: &GuardBinding) -> Result<Spec> {
    guard_directory(spec, guard)?;
    let mut derived = spec.clone();
    derived.dropins.push(guard.guard.clone());
    derived.expected_conditions.push((
        "ConditionPathExists".into(),
        false,
        true,
        guard.marker.path.clone(),
    ));
    Ok(derived)
}
fn potential_review(
    backend: &mut impl Backend,
    budget: &mut Budget,
    spec: &Spec,
    pin: &Pin,
) -> Result<()> {
    root_pin(pin, 1 << 20, "PotentialProgramReview")?;
    ensure!(
        pin.path
            .starts_with("/var/lib/jetstreamer/horizon-old220-peers1060-")
            && pin.path.ends_with(".json"),
        "potential-input review has unregistered custody scope"
    );
    let review: PotentialReview = serde_json::from_slice(&budget.read(backend, pin)?)?;
    ensure!(
        review.schema == "horizon-old220-peer1060-potential-declared-inputs-v1"
            && review.unit == spec.unit
            && review.role == spec.role
            && review.original_specs_sha256 == digest(SPEC_BYTES)
            && review.original_spec_sha256 == digest(&serde_json::to_vec(spec)?)
            && review.selected_owner == OWNER
            && review.selected_epoch == 220
            && review.selected_inodes == vec![20581075, 20582466]
            && review.scope == "fixed-declared-program-inputs-with-unqualified-historical-loader"
            && !review.application_review.trim().is_empty()
            && !review.unresolved_historical_loader_inputs.is_empty()
            && review
                .unresolved_historical_loader_inputs
                .iter()
                .all(|s| !s.trim().is_empty())
            && !review.historical_loader_execution_qualified
            && !review.data_retirement_authorized
            && !review.global_alias_closure_qualified,
        "potential program evidence overclaims or belongs to another selection/spec"
    );
    Ok(())
}
/// Requirements only. This does not read files/native state or qualify a review.
pub fn condition_blocked_requirements() -> Result<Value> {
    let specs = specs()?;
    Ok(
        json!({"schema":"horizon-old220-peers1060-source-requirements-v1",
        "review_path":REVIEW,"review_schema":REVIEW_SCHEMA,"scope":SCOPE,
        "original_specs_sha256":digest(SPEC_BYTES),"selected_owner":OWNER,
        "selected_epoch":220,"selected_inodes":[20581075u64,20582466u64],
        "roles":specs.iter().map(|s| json!({"unit":s.unit,"role":s.role,
            "original_spec_sha256":digest(&serde_json::to_vec(s).expect("serialize compiled spec")),
            "original_spec":s})).collect::<Vec<_>>(),
        "historical_loader_execution_qualified":false,"data_retirement_authorized":false,
        "global_alias_closure_qualified":false}),
    )
}

/// No public constructor or Deserialize; the original ValidatedPeers is private
/// within this wrapper and is never returned as the older semantic proof.
pub struct ConditionBlockedPeers {
    inner: ValidatedPeers,
    guard_rows: Vec<Row>,
}
pub fn capture_condition_blocked(
    backend: &mut impl Backend,
    binding: &ReviewBinding,
    jobs: &str,
) -> Result<ConditionBlockedPeers> {
    capture_condition_blocked_specs(backend, binding, jobs, &specs()?)
}
fn capture_condition_blocked_specs(
    backend: &mut impl Backend,
    binding: &ReviewBinding,
    jobs: &str,
    original: &[Spec],
) -> Result<ConditionBlockedPeers> {
    let review_pin = Pin {
        path: REVIEW.into(),
        canonical: REVIEW.into(),
        sha256: binding.sha256.clone(),
        kind: "RootReview".into(),
        uid: 0,
        gid: 0,
        mode: libc::S_IFREG | 0o444,
        bytes: binding.bytes,
        single_link: true,
        fixture: None,
    };
    root_pin(&review_pin, 1 << 20, "RootReview")?;
    let mut budget = Budget {
        opens: 0,
        bytes: 0,
        reads: Vec::new(),
    };
    let review: Review = serde_json::from_slice(&budget.read(backend, &review_pin)?)?;
    ensure!(
        original.len() == 5
            && review.schema == REVIEW_SCHEMA
            && review.scope == SCOPE
            && review.source_specs_sha256 == digest(SPEC_BYTES)
            && review.selected_owner == OWNER
            && review.selected_epoch == 220
            && review.selected_inodes == vec![20581075, 20582466]
            && review.rows.len() == 5
            && !review.data_retirement_authorized
            && !review.global_alias_closure_qualified
            && !review.historical_loader_execution_qualified,
        "foreign, incomplete or overclaiming condition-blocked review"
    );
    let mut allowed = Vec::new();
    let mut exclusive = Vec::new();
    let mut rows = Vec::new();
    let mut derived = Vec::new();
    for (spec, row) in original.iter().zip(&review.rows) {
        ensure!(
            row.unit == spec.unit
                && row.role == spec.role
                && !row.historical_loader_execution_qualified,
            "unknown/reordered peer role or historical-loader overclaim"
        );
        verify_origin(backend, &mut budget, spec, &row.origin)?;
        for pin in std::iter::once(&spec.recipe).chain(&spec.dropins) {
            budget.read(backend, pin)?;
            allowed.push(pin.clone());
        }
        for pin in &spec.dependencies {
            let bytes = budget.read(backend, pin)?;
            json_input(spec, pin, &bytes)?;
            if matches!(pin.kind.as_str(), "Script" | "PublicationV2") {
                exclusive.push(pin.clone());
            }
        }
        if spec.role == "BootstrapRestoreNotSelected" {
            let p = row
                .bootstrap_interpreter
                .as_ref()
                .context("current bootstrap interpreter missing")?;
            ensure!(
                p.kind == "Executable"
                    && p.uid == 1000
                    && p.gid == 1000
                    && p.single_link
                    && p.path == "/home/linuxbrew/.linuxbrew/bin/python3"
                    && p.canonical
                        .starts_with("/home/linuxbrew/.linuxbrew/Cellar/python@")
                    && Path::new(&p.canonical)
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("python3")),
                "bootstrap current interpreter is not the exact declared login artifact"
            );
            budget.read(backend, p)?;
        } else {
            ensure!(
                row.bootstrap_interpreter.is_none(),
                "foreign bootstrap role"
            );
        }
        potential_review(backend, &mut budget, spec, &row.potential_program_review)?;
        guard_files(backend, &mut budget, spec, &row.condition_blocked_guard)?;
        directories(backend, spec, &row.condition_blocked_guard)?;
        let current = guarded_spec(spec, &row.condition_blocked_guard)?;
        rows.push(check_native(backend, &current, &row.origin, jobs)?);
        for pin in [
            &row.condition_blocked_guard.guard,
            &row.condition_blocked_guard.marker,
            &row.condition_blocked_guard.seal,
            &row.condition_blocked_guard.sums,
        ] {
            allowed.push(pin.clone());
        }
        derived.push(current);
    }
    // Keep guard files/rosters and all current native bindings stable across the
    // whole five-peer capture, not just one unit's immediate metadata queries.
    for (spec, row) in original.iter().zip(&review.rows) {
        guard_files(backend, &mut budget, spec, &row.condition_blocked_guard)?;
        directories(backend, spec, &row.condition_blocked_guard)?;
    }
    for (position, row) in review.rows.iter().enumerate() {
        ensure!(
            check_native(backend, &derived[position], &row.origin, jobs)? == rows[position],
            "peer current envelope changed during complete five-role capture"
        );
    }
    Ok(ConditionBlockedPeers {
        inner: ValidatedPeers {
            rows,
            allowed,
            exclusive,
            review_sha256: binding.sha256.clone(),
            reads: budget.reads,
            specs: derived,
            origins: review.rows.iter().map(|r| r.origin.clone()).collect(),
        },
        guard_rows: review.rows,
    })
}
impl ConditionBlockedPeers {
    pub fn summary(&self) -> Value {
        let mut value = self.inner.summary();
        value["schema"] = SUMMARY_SCHEMA.into();
        value["scope"] = SCOPE.into();
        value["condition_blocked_guards"] =
            serde_json::to_value(&self.guard_rows).expect("serialize checked guard bindings");
        value["historical_loader_execution_qualified"] = false.into();
        value["currently_admitted_selected_cache_reads"] = json!([]);
        value
    }
    pub fn staged(&self, path: &Path, bytes: &[u8], jobs: &str) -> Result<bool> {
        self.inner.staged(path, bytes, jobs)
    }
    pub fn exclusive_inputs(&self) -> impl Iterator<Item = &Pin> {
        self.inner.exclusive_inputs()
    }
    pub fn exclusive_identities(&self, b: &mut impl Backend) -> Result<BTreeSet<(u64, u64)>> {
        self.inner.exclusive_identities(b)
    }
    pub fn staged_reference(&self, bytes: &[u8], f: impl FnMut(&[u8], &[u8]) -> bool) -> bool {
        self.inner.staged_reference(bytes, f)
    }
    pub fn indirect_reference(&self, bytes: &[u8], f: impl FnMut(&[u8], &[u8]) -> bool) -> bool {
        self.inner.indirect_reference(bytes, f)
    }
    pub fn validate_predecessor_summary(&self, value: &Value) -> Result<()> {
        let current = self.summary();
        ensure!(
            value
                .as_object()
                .context("summary object")?
                .keys()
                .collect::<BTreeSet<_>>()
                == current.as_object().unwrap().keys().collect::<BTreeSet<_>>(),
            "guarded predecessor fields differ"
        );
        for key in [
            "schema",
            "scope",
            "condition_blocked_guards",
            "historical_loader_execution_qualified",
            "currently_admitted_selected_cache_reads",
        ] {
            ensure!(
                value[key] == current[key],
                "guarded predecessor scope/input changed: {key}"
            );
        }
        let mut legacy_transport = value.clone();
        let object = legacy_transport.as_object_mut().unwrap();
        for key in [
            "scope",
            "condition_blocked_guards",
            "historical_loader_execution_qualified",
            "currently_admitted_selected_cache_reads",
        ] {
            object.remove(key);
        }
        object.insert(
            "schema".into(),
            "horizon-old220-peers1016-exact-five-current-v2".into(),
        );
        // Reuse the COMPLETE original native replay/input/history validator after
        // the new scope and guard bindings were checked, never a leaf allowlist.
        self.inner.validate_predecessor_summary(&legacy_transport)
    }
}

#[cfg(test)]
mod tests;
