//! Explicit retained-terminal context for the original 199–200 producer.
//! This context recognizes hash-bound historical evidence while current
//! membership still rejects replacement or live original producers. It releases
//! no memory, DATA, archive, replay, or publication obligation.
use anyhow::{Context as _, Result, ensure};
use original199_input_witness_consumer as witness;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
const REGISTRY_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v1/registry.json";
const REGISTRY_SHA: &str = "7744abca94e34c4531a9b439a85810f86784ecf1823276c72fc360e2f70013d5";
const REGISTRY_V2_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v2/registry.json";
const REGISTRY_V2_SHA: &str = "733487fcb07438d603999234b0a0598d62261ba0c1cb0ba6003693260ebc1389";
const PRODUCER: &str = "jetstreamer-root-sweep-e199-backfill-20261102-v1-e199-200-lane-a-1.service";
const CONTROLLER: &str = "jetstreamer-epoch199-backfill-20261102-controller-v1-r2.service";
const PRODUCER_IID: &str = "2a1c51f557a64cd1ad691281cbb77c94";
const CONTROLLER_IID: &str = "dbf49bb1b72c42c584f2d3ac94259cb8";
const TOOL_SHA: &str = "24acf143a137acf8eeae43f8bdf7a9616338ac48aaeaaa8264516f0ba0feb619";
const RECEIPT_SHA: &str = "a107a8b31fa550fca233fedf0509d19771d9413f353b21834755e4a16021be9a";
const RECEIPT_PATH: &str =
    "/var/lib/jetstreamer/horizon-original199-terminal-custody-v1/terminal.json";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    schema: String,
    original_enrollment: Bound,
    terminal_custody: Bound,
    native_capability: Bound,
    historical_sources: Vec<Bound>,
}
#[derive(Clone)]
pub struct Retained {
    selector: Bound,
    selected_inputs: Option<witness::SelectedInputs>,
    original_enrollment: Bound,
    terminal_custody: Bound,
    native_capability: Bound,
    historical_values: BTreeSet<[u8; 32]>,
    historical_native: BTreeSet<[u8; 32]>,
    historical_producer_roles: BTreeSet<[u8; 32]>,
    historical_worker_rows: BTreeSet<[u8; 32]>,
}
fn digest(v: &Value) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(v)?).into())
}
fn raw(b: &Bound, cap: u64) -> Result<Vec<u8>> {
    ensure!(
        b.path.is_absolute()
            && b.sha256.len() == 64
            && b.sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "invalid bound input"
    );
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= cap
            && b.path.canonicalize()? == b.path,
        "input custody or bounds changed"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    let before = f.metadata()?;
    ensure!(
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec()
        ) == (
            before.dev(),
            before.ino(),
            before.len(),
            before.mode(),
            before.uid(),
            before.gid(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec()
        ),
        "input descriptor differs"
    );
    let mut bytes = Vec::new();
    (&mut f).take(cap + 1).read_to_end(&mut bytes)?;
    let after = f.metadata()?;
    ensure!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec()
        ) == (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        ),
        "input changed during read"
    );
    ensure!(
        bytes.len() as u64 == before.len() && format!("{:x}", Sha256::digest(&bytes)) == b.sha256,
        "input digest differs"
    );
    Ok(bytes)
}
fn read(b: &Bound, cap: u64) -> Result<Value> {
    Ok(serde_json::from_slice(&raw(b, cap)?)?)
}
fn validate_receipt(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-original199-terminal-custody-retained-promises-v1"
            && v["self_sha256"] == TOOL_SHA
            && v["original_producer_invocation_id"] == PRODUCER_IID,
        "terminal receipt generation differs"
    );
    ensure!(
        v["original_cgroup_empty"] == true && v["original_producer_gone"] == true,
        "original terminal custody missing"
    );
    for field in [
        "replay_launch_authorized",
        "publication_authorized",
        "archive_verified",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[field] == false, "terminal authority expanded: {field}");
    }
    for (field, n) in [
        ("parent_memory_bytes_retained", 192u64 << 30),
        ("controller_memory_bytes_retained", 512u64 << 20),
        ("guard_memory_bytes_retained", 512u64 << 20),
        ("DATA_bytes_retained", 768u64 << 30),
        ("memory_credit_bytes", 0),
        ("DATA_credit_bytes", 0),
    ] {
        ensure!(v[field] == n, "terminal promise changed: {field}");
    }
    Ok(())
}
fn selector_binding(binding: &Bound) -> Result<()> {
    ensure!(
        (binding.path == Path::new(REGISTRY_PATH) && binding.sha256 == REGISTRY_SHA)
            || (binding.path == Path::new(REGISTRY_V2_PATH) && binding.sha256 == REGISTRY_V2_SHA),
        "terminal context requires the exact sealed registry path and digest"
    );
    Ok(())
}
fn witness_bound(binding: &Bound) -> witness::Bound {
    witness::Bound {
        path: binding.path.clone(),
        sha256: binding.sha256.clone(),
    }
}
fn local_bound(binding: &witness::Bound) -> Bound {
    Bound {
        path: binding.path.clone(),
        sha256: binding.sha256.clone(),
    }
}
fn original_native(census: &Value) -> bool {
    census[PRODUCER]["Id"] == PRODUCER
        && census[PRODUCER]["InvocationID"] == PRODUCER_IID
        && census[PRODUCER]["MainPID"] == "2467217"
        && census[CONTROLLER]["Id"] == CONTROLLER
        && census[CONTROLLER]["InvocationID"] == CONTROLLER_IID
        && census[CONTROLLER]["MainPID"] == "2467123"
}
fn original_worker_row(row: &Value) -> bool {
    row["range"] == "199-200"
        && row["invocation_binding_stable"] == true
        && ["before", "after"].into_iter().all(|end| {
            let producer = &row[format!("producer_{end}")];
            let controller = &row[format!("controller_{end}")];
            let worker = &row[format!("worker_{end}")];
            producer["unit"] == PRODUCER
                && producer["invocation_id"] == PRODUCER_IID
                && producer["main_pid"] == 2_467_217u64
                && producer["restarts"] == 0
                && controller["unit"] == CONTROLLER
                && controller["invocation_id"] == CONTROLLER_IID
                && controller["main_pid"] == 2_467_123u64
                && controller["restarts"] == 0
                && worker["pid"] == 2_467_614u64
                && worker["matching_workers"] == 1
                && worker["executable_beneath_bound_scratch"] == true
                && worker["executable"] == row["worker_before"]["executable"]
        })
}
fn claims_original(row: &Value) -> Result<bool> {
    let scope = row["range"]
        .as_str()
        .context("ordinary or diagnostic range missing")?;
    let (first, last) = scope.split_once('-').unwrap_or((scope, scope));
    ensure!(
        !first.is_empty()
            && !last.is_empty()
            && first.bytes().all(|c| c.is_ascii_digit())
            && last.bytes().all(|c| c.is_ascii_digit()),
        "replay range is not a bounded numeric scope"
    );
    let first: u64 = first.parse()?;
    let last: u64 = last.parse()?;
    ensure!(first <= last, "replay range is reversed");
    if first <= 200 && last >= 199 {
        return Ok(true);
    }
    for key in ["producer_unit", "controller_unit"] {
        if row[key] == PRODUCER || row[key] == CONTROLLER {
            return Ok(true);
        }
    }
    for key in [
        "expected_producer_invocation_id",
        "expected_controller_invocation_id",
    ] {
        if row[key] == PRODUCER_IID || row[key] == CONTROLLER_IID {
            return Ok(true);
        }
    }
    for role in [
        "producer_before",
        "producer_after",
        "controller_before",
        "controller_after",
    ] {
        let native = &row[role];
        if native["unit"] == PRODUCER
            || native["unit"] == CONTROLLER
            || native["invocation_id"] == PRODUCER_IID
            || native["invocation_id"] == CONTROLLER_IID
        {
            return Ok(true);
        }
    }
    Ok(false)
}
impl Retained {
    /// Load only through the current plan's explicit sealed selector. Merely
    /// finding an existing terminal receipt never activates a context.
    pub fn load(binding: &Bound) -> Result<Self> {
        let selected_context = if witness::is_selected_context(&witness_bound(binding)) {
            Some(witness::SelectedContext::load(&witness_bound(binding))?)
        } else {
            None
        };
        let original_binding = selected_context
            .as_ref()
            .map(|context| local_bound(context.original_context()))
            .unwrap_or_else(|| binding.clone());
        // The wrapper never broadens the original registry allowlist.
        selector_binding(&original_binding)?;
        let selector: Selector = serde_json::from_value(read(&original_binding, 1 << 20)?)?;
        ensure!(
            selector.schema == "horizon-original199-retained-terminal-context-v1"
                && selector.terminal_custody.path == Path::new(RECEIPT_PATH)
                && selector.terminal_custody.sha256 == RECEIPT_SHA,
            "selector generation differs"
        );
        let receipt = read(&selector.terminal_custody, 1 << 20)?;
        validate_receipt(&receipt)?;
        ensure!(
            receipt["original_enrollment"] == serde_json::to_value(&selector.original_enrollment)?,
            "original enrollment crossed"
        );
        let native = read(&selector.native_capability, 2 << 20)?;
        ensure!(
            native["program"]["sha256"] == TOOL_SHA
                && native["terminal_custody_receipt"]
                    == serde_json::to_value(&selector.terminal_custody)?
                && native["original_native_group_outer_drained"] == true
                && native["memory_credit_bytes"] == 0
                && native["DATA_credit_bytes"] == 0,
            "genuine native capability differs"
        );
        let enrollment = read(&selector.original_enrollment, 1 << 20)?;
        ensure!(
            enrollment["producer"]["unit"] == PRODUCER
                && enrollment["producer"]["invocation_id"] == PRODUCER_IID
                && enrollment["controller"]["invocation_id"] == CONTROLLER_IID,
            "original enrollment identity differs"
        );
        let selected_inputs = selected_context
            .as_ref()
            .map(|context| context.select(&witness_bound(&selector.original_enrollment)))
            .transpose()?;
        let mut out = Self {
            selector: original_binding,
            selected_inputs,
            original_enrollment: selector.original_enrollment,
            terminal_custody: selector.terminal_custody,
            native_capability: selector.native_capability,
            historical_values: BTreeSet::new(),
            historical_native: BTreeSet::new(),
            historical_producer_roles: BTreeSet::new(),
            historical_worker_rows: BTreeSet::new(),
        };
        ensure!(
            !selector.historical_sources.is_empty() && selector.historical_sources.len() <= 1024,
            "historical source census outside bounds"
        );
        let mut total = 0u64;
        let mut unique = BTreeSet::new();
        for b in selector.historical_sources {
            ensure!(unique.insert(b.path.clone()), "duplicate historical source");
            let bytes = raw(&b, 32 << 20)?;
            total = total
                .checked_add(bytes.len() as u64)
                .context("historical size overflow")?;
            ensure!(
                total <= 512u64 << 20,
                "historical graph exceeds byte budget"
            );
            let v: Value = serde_json::from_slice(&bytes)?;
            out.collect(&v)?;
        }
        ensure!(
            !out.historical_values.is_empty()
                && !out.historical_native.is_empty()
                && !out.historical_worker_rows.is_empty(),
            "historical evidence graph is incomplete"
        );
        Ok(out)
    }
    fn collect(&mut self, v: &Value) -> Result<()> {
        // Only complete operational roots authenticated by the exact registry
        // are eligible. Never recursively enroll arbitrary descendant values.
        let native_keys: &[&str] = match v["schema"].as_str() {
            Some("jetstreamer-horizon-campaign-fleet-v1") => {
                ensure!(
                    v["first_epoch"] == 101
                        && v["last_epoch"] == 200
                        && v["unit_census"].is_object(),
                    "historical fleet scope differs"
                );
                &["unit_census"]
            }
            Some("jetstreamer-horizon-campaign-fleet-plan-v1") => {
                ensure!(
                    v["first_epoch"] == 101
                        && v["last_epoch"] == 200
                        && v["tracked_units"].is_array(),
                    "historical plan scope differs"
                );
                &[]
            }
            Some("jetstreamer-horizon-recovered-resource-frame-v1") => {
                ensure!(
                    v["accepted_resource_lineage"] == true
                        && v["bindings"].is_object()
                        && v["native_census_before"].is_object()
                        && v["native_census_after"].is_object(),
                    "historical Frame scope differs"
                );
                &["native_census_before", "native_census_after"]
            }
            Some("jetstreamer-horizon-live-resource-sample-v2") => {
                ensure!(
                    v["replays"].is_array() && v["diagnostic_replays"].is_array(),
                    "historical observer scope differs"
                );
                &[]
            }
            _ => anyhow::bail!("historical source is not an authenticated operational scope"),
        };
        self.historical_values.insert(digest(v)?);
        for key in native_keys {
            let native = &v[*key];
            if original_native(native) {
                self.historical_native.insert(digest(native)?);
                self.historical_producer_roles
                    .insert(digest(&native[PRODUCER])?);
            }
        }
        if v["schema"] == "jetstreamer-horizon-live-resource-sample-v2" {
            for row in v["replays"]
                .as_array()
                .context("historical ordinary rows absent")?
            {
                if original_worker_row(row) {
                    self.historical_worker_rows.insert(digest(row)?);
                }
            }
        }
        Ok(())
    }
    pub fn revalidate_inputs(&self) -> Result<()> {
        selector_binding(&self.selector)?;
        if let Some(selected) = &self.selected_inputs {
            let wrapper = witness::SelectedContext::load(&witness::Bound {
                path: witness::CONTEXT_PATH.into(),
                sha256: witness::CONTEXT_SHA.into(),
            })?;
            ensure!(
                wrapper.original_context() == selected.original_context(),
                "selected context wrapper crossed original registry"
            );
            selected.require_context(
                &witness_bound(&self.original_enrollment),
                &witness_bound(&self.selector),
            )?;
            selected.revalidate()?;
        }
        read(&self.selector, 1 << 20)?;
        read(&self.original_enrollment, 1 << 20)?;
        let v = read(&self.terminal_custody, 1 << 20)?;
        validate_receipt(&v)?;
        read(&self.native_capability, 2 << 20)?;
        let state: Bound = serde_json::from_value(v["quarantined_controller_state"].clone())?;
        let s = if let Some(selected) = &self.selected_inputs {
            ensure!(
                state.path
                    == Path::new(
                        "/var/lib/jetstreamer-root-sweep-epoch199-backfill-20261102-v1/state.json"
                    )
                    && state.sha256
                        == "051642bf5ff3f1fffb5e7d8b2133ff399a0a0f1947fef50c74976b12858da152",
                "terminal receipt crossed original quarantined state"
            );
            selected.verify_member(&witness_bound(&state), 1 << 20)?;
            let raw = selected.read_quarantined_state()?;
            ensure!(
                raw.len() <= 1 << 20,
                "quarantined state exceeds retained reader bound"
            );
            serde_json::from_slice(&raw)?
        } else {
            read(&state, 1 << 20)?
        };
        ensure!(
            s["assignments"]["lane-a"]["phase"] == "failed"
                && s["assignments"]["lane-a"]["unit"] == PRODUCER
                && s["attempts"]["199-200"] == 1,
            "controller no longer quarantines original attempt"
        );
        Ok(())
    }
    /// Explicit selection carried by value; callers cannot activate it by discovery.
    pub fn selected_inputs(&self) -> Option<&witness::SelectedInputs> {
        self.selected_inputs.as_ref()
    }
    pub fn original_context(&self) -> &Bound {
        &self.selector
    }
    pub fn original_enrollment(&self) -> &Bound {
        &self.original_enrollment
    }
    pub fn historical_value(&self, v: &Value) -> Result<bool> {
        Ok(self.historical_values.contains(&digest(v)?))
    }
    pub fn historical_native(&self, v: &Value) -> Result<bool> {
        Ok(self.historical_native.contains(&digest(v)?))
    }
    pub fn historical_producer_image(&self, v: &Value) -> Result<bool> {
        Ok(self.historical_producer_roles.contains(&digest(v)?))
    }
    pub fn historical_worker(&self, v: &Value) -> Result<bool> {
        Ok(self.historical_worker_rows.contains(&digest(v)?))
    }
    /// This is membership validation only. Callers must also retain all
    /// original cap, guard, command and numeric promise validators.
    pub fn validate_current_membership(&self, census: &Value) -> Result<()> {
        self.revalidate_inputs()?;
        let controller = &census[CONTROLLER];
        let producer = &census[PRODUCER];
        ensure!(
            controller["Id"] == CONTROLLER
                && controller["LoadState"] == "loaded"
                && controller["ControlPID"] == "0"
                && controller["Job"] == ""
                && controller["Result"] == "success"
                && controller["ExecMainStatus"] == "0"
                && controller["InvocationID"] == CONTROLLER_IID
                && controller["MainPID"] == "2467123"
                && controller["ActiveState"] == "active"
                && controller["SubState"] == "running"
                && controller["NRestarts"] == "0",
            "current original controller changed"
        );
        for (k, value) in [
            ("Id", PRODUCER),
            ("LoadState", "not-found"),
            ("InvocationID", ""),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("NRestarts", "0"),
            ("Job", ""),
        ] {
            ensure!(
                producer[k] == value,
                "current original producer is live, queued, replaced, or ambiguous: {k}"
            );
        }
        Ok(())
    }
    pub fn validate_current_observer(&self, observer: &Value) -> Result<()> {
        let ordinary = observer["replays"]
            .as_array()
            .context("current ordinary rows absent")?;
        for row in ordinary {
            ensure!(
                !claims_original(row)?,
                "terminal context cannot hide an original 199 ordinary claim"
            );
        }
        let rows = observer["diagnostic_replays"]
            .as_array()
            .context("terminal diagnostics absent")?;
        let mut original = Vec::new();
        for row in rows {
            if claims_original(row)? {
                original.push(row);
            }
        }
        ensure!(
            original.len() == 1
                && original[0]["range"] == "199-200"
                && original[0]["producer_unit"] == PRODUCER
                && original[0]["status"] == "unavailable"
                && original[0]["observation"].is_null()
                && original[0]["ordinary_replay_claim"] == false
                && original[0]["replay_launch_authorized"] == false
                && original[0]["publication_authorized"] == false
                && original[0]["r2_mutations"] == false
                && original[0]["expected_producer_invocation_id"] == PRODUCER_IID,
            "original terminal diagnostic crossed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn context() -> Retained {
        Retained::load(&Bound {
            path: REGISTRY_PATH.into(),
            sha256: REGISTRY_SHA.into(),
        })
        .unwrap()
    }
    fn registry() -> Selector {
        serde_json::from_value(
            read(
                &Bound {
                    path: REGISTRY_PATH.into(),
                    sha256: REGISTRY_SHA.into(),
                },
                1 << 20,
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn terminal_observer() -> Value {
        read(&Bound {
            path: "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261104T175809Z-postcompletion154-v1.json".into(),
            sha256: "ff39a3a95b44d833c3d63f44333c184e0077ff887108ee5b71a0b961cf0ba9b2".into(),
        }, 2 << 20).unwrap()
    }
    #[test]
    fn exact_sealed_selector_path_and_digest_accept_without_component_prefix_bug() {
        selector_binding(&Bound {
            path: REGISTRY_PATH.into(),
            sha256: REGISTRY_SHA.into(),
        })
        .unwrap();
        for path in [
            "/usr/local/lib/jetstreamer/horizon-original199-terminal-context-",
            "/usr/local/lib/jetstreamer/horizon-original199-terminal-context-foreign/registry.json",
            "/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v1/other.json",
            "/tmp/registry.json",
        ] {
            assert!(
                selector_binding(&Bound {
                    path: path.into(),
                    sha256: REGISTRY_SHA.into()
                })
                .is_err()
            );
        }
        assert!(
            selector_binding(&Bound {
                path: REGISTRY_PATH.into(),
                sha256: "0".repeat(64)
            })
            .is_err()
        );
    }
    #[test]
    fn genuine_complete_registered_history_recognizes_only_roots_and_exact_roles() {
        let c = context();
        let mut original_native_count = 0;
        let mut worker_count = 0;
        let selector = registry();
        assert_eq!(selector.historical_sources.len(), 67);
        for bound in selector.historical_sources {
            let value = read(&bound, 32 << 20).unwrap();
            assert!(c.historical_value(&value).unwrap());
            assert!(!c.historical_value(&value["schema"]).unwrap());
            assert!(!c.historical_value(&value["bindings"]).unwrap());
            for key in ["unit_census", "native_census_before", "native_census_after"] {
                if original_native(&value[key]) {
                    assert!(c.historical_native(&value[key]).unwrap());
                    assert!(c.historical_producer_image(&value[key][PRODUCER]).unwrap());
                    original_native_count += 1;
                }
            }
            if value["schema"] == "jetstreamer-horizon-live-resource-sample-v2" {
                for row in value["replays"].as_array().unwrap() {
                    if original_worker_row(row) {
                        assert!(c.historical_worker(row).unwrap());
                        worker_count += 1;
                    }
                }
            }
        }
        assert!(original_native_count > 0 && worker_count == 2);
        c.revalidate_inputs().unwrap();
    }
    #[test]
    fn genuine_terminal_membership_and_observer_keep_every_original_promise() {
        let c = context();
        let receipt = read(&c.terminal_custody, 1 << 20).unwrap();
        let mut native = serde_json::Map::new();
        native.insert(CONTROLLER.into(), receipt["actual_controller"].clone());
        native.insert(
            PRODUCER.into(),
            receipt["actual_producer_after_collection"].clone(),
        );
        c.validate_current_membership(&Value::Object(native))
            .unwrap();
        c.validate_current_observer(&terminal_observer()).unwrap();
        validate_receipt(&receipt).unwrap();
        assert_eq!(receipt["memory_credit_bytes"], 0);
        assert_eq!(receipt["DATA_credit_bytes"], 0);
    }
    #[test]
    fn unrelated_current_ordinary_owner_is_allowed_but_original_aliases_reject() {
        let c = context();
        let mut observer = terminal_observer();
        // TEST ONLY: this is a membership-unit example, never live replay proof.
        observer["replays"] = json!([{"range":"185", "producer_after": {
            "unit":"test-only-unrelated185.service", "invocation_id":"a".repeat(32)
        }}]);
        c.validate_current_observer(&observer).unwrap();
        for scope in ["199", "200", "199-200", "198-201"] {
            let mut bad = observer.clone();
            bad["replays"][0]["range"] = json!(scope);
            assert!(c.validate_current_observer(&bad).is_err());
        }
        for (field, value) in [("unit", PRODUCER), ("invocation_id", PRODUCER_IID)] {
            let mut bad = observer.clone();
            bad["replays"][0]["producer_after"][field] = json!(value);
            assert!(c.validate_current_observer(&bad).is_err());
        }
    }
    #[test]
    fn unknown_descendants_mutated_native_and_worker_values_are_never_historical() {
        let c = context();
        let selector = registry();
        let bound = selector
            .historical_sources
            .iter()
            .find(|b| {
                b.path
                    .to_string_lossy()
                    .ends_with("sample-20261104T165809Z-postcompletion154-v1.json")
            })
            .unwrap();
        let observer = read(bound, 2 << 20).unwrap();
        let row = &observer["replays"][0];
        assert!(c.historical_worker(row).unwrap());
        assert!(!c.historical_value(row).unwrap());
        for key in ["producer_before", "worker_before", "cross_sample"] {
            assert!(!c.historical_value(&row[key]).unwrap());
        }
        let mut changed = row.clone();
        changed["worker_after"]["pid"] = json!(1);
        assert!(!c.historical_worker(&changed).unwrap());
        let mut changed = observer.clone();
        changed["unrelated_extension"] = json!(true);
        assert!(!c.historical_value(&changed).unwrap());
        let bound = selector
            .historical_sources
            .iter()
            .find(|b| {
                b.path
                    .to_string_lossy()
                    .ends_with("frame20261104T165809-canonical-v5-actual-native-20261104-v1.json")
            })
            .unwrap();
        let frame = read(bound, 32 << 20).unwrap();
        let native = &frame["native_census_before"];
        assert!(c.historical_native(native).unwrap());
        assert!(c.historical_producer_image(&native[PRODUCER]).unwrap());
        let mut changed = native.clone();
        changed[PRODUCER]["InvocationID"] = json!("0".repeat(32));
        assert!(!c.historical_native(&changed).unwrap());
        let mut role = native[PRODUCER].clone();
        role["MemoryMax"] = json!("0");
        assert!(!c.historical_producer_image(&role).unwrap());
    }
    #[test]
    fn original_live_queued_replaced_or_duplicate_diagnostic_is_rejected() {
        let c = context();
        for mode in 0..5 {
            let mut observer = terminal_observer();
            let index = observer["diagnostic_replays"]
                .as_array()
                .unwrap()
                .iter()
                .position(|r| r["range"] == "199-200")
                .unwrap();
            match mode {
                0 => observer["diagnostic_replays"][index]["status"] = json!("observed"),
                1 => observer["diagnostic_replays"][index]["observation"] = json!({"live":true}),
                2 => {
                    observer["diagnostic_replays"][index]["expected_producer_invocation_id"] =
                        json!("0".repeat(32))
                }
                3 => observer["diagnostic_replays"][index]["ordinary_replay_claim"] = json!(true),
                _ => {
                    let copy = observer["diagnostic_replays"][index].clone();
                    observer["diagnostic_replays"]
                        .as_array_mut()
                        .unwrap()
                        .push(copy);
                }
            }
            assert!(c.validate_current_observer(&observer).is_err());
        }
        let receipt = read(&c.terminal_custody, 1 << 20).unwrap();
        for (key, value) in [
            ("MainPID", "2467217"),
            ("InvocationID", PRODUCER_IID),
            ("Job", "99"),
            ("LoadState", "loaded"),
        ] {
            let mut census = json!({CONTROLLER:receipt["actual_controller"], PRODUCER:receipt["actual_producer_after_collection"]});
            census[PRODUCER][key] = json!(value);
            assert!(c.validate_current_membership(&census).is_err());
        }
    }
    #[test]
    fn promise_and_authority_mutations_never_become_terminal_credit() {
        let c = context();
        let receipt = read(&c.terminal_custody, 1 << 20).unwrap();
        for field in [
            "parent_memory_bytes_retained",
            "controller_memory_bytes_retained",
            "guard_memory_bytes_retained",
            "DATA_bytes_retained",
        ] {
            let mut changed = receipt.clone();
            changed[field] = json!(0);
            assert!(validate_receipt(&changed).is_err());
        }
        for field in ["memory_credit_bytes", "DATA_credit_bytes"] {
            let mut changed = receipt.clone();
            changed[field] = json!(1);
            assert!(validate_receipt(&changed).is_err());
        }
        for field in [
            "replay_launch_authorized",
            "publication_authorized",
            "archive_verified",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut changed = receipt.clone();
            changed[field] = json!(true);
            assert!(validate_receipt(&changed).is_err());
        }
    }
}

#[cfg(test)]
mod additive_accepted1658_tests {
    use super::*;
    fn binding_v2() -> Bound {
        Bound {
            path: REGISTRY_V2_PATH.into(),
            sha256: REGISTRY_V2_SHA.into(),
        }
    }
    fn accepted_frame() -> Value {
        read(&Bound {
            path: "/var/lib/jetstreamer/horizon-recovered-resource-frames-20261029-v1/frame20261104T165809-cached145-retained-private154-delivery-terminal-retained-g6-g7-debt-helperv4-additive199-buffered-v5.json".into(),
            sha256: "d5803f43eade6336db94d951ab689610909e082cda5740f4b326278437a25625".into(),
        }, 32 << 20).unwrap()
    }
    #[test]
    fn genuine_final1658_frame_reproduces_old_failure_and_projects_only_with_new_registry() {
        let old = Retained::load(&Bound {
            path: REGISTRY_PATH.into(),
            sha256: REGISTRY_SHA.into(),
        })
        .unwrap();
        let current = Retained::load(&binding_v2()).unwrap();
        let frame = accepted_frame();
        assert!(
            !old.historical_native(&frame["native_census_before"])
                .unwrap()
        );
        assert!(super::super::ordinary199::project_frame_retained(&frame, &old).is_err());
        assert!(current.historical_value(&frame).unwrap());
        let projected =
            super::super::ordinary199::project_frame_retained(&frame, &current).unwrap();
        assert!(projected.get("epoch199_enrollment").is_none());
        assert!(projected.get("epoch199_promises").is_none());
        assert!(projected["native_census_before"].get(PRODUCER).is_none());
        assert_eq!(
            frame["epoch199_promises"]["parent_memory_bytes"],
            192u64 << 30
        );
        assert_eq!(frame["epoch199_promises"]["DATA_bytes"], 768u64 << 30);
    }
    #[test]
    fn both_registry_generations_keep_every_original_root_and_crossed_selectors_reject() {
        let old = Retained::load(&Bound {
            path: REGISTRY_PATH.into(),
            sha256: REGISTRY_SHA.into(),
        })
        .unwrap();
        let current = Retained::load(&binding_v2()).unwrap();
        let original = read(
            &Bound {
                path: REGISTRY_PATH.into(),
                sha256: REGISTRY_SHA.into(),
            },
            1 << 20,
        )
        .unwrap();
        for bound in original["historical_sources"].as_array().unwrap() {
            let value = read(&serde_json::from_value(bound.clone()).unwrap(), 32 << 20).unwrap();
            assert!(old.historical_value(&value).unwrap());
            assert!(current.historical_value(&value).unwrap());
        }
        for binding in [
            Bound { path: REGISTRY_PATH.into(), sha256: REGISTRY_V2_SHA.into() },
            Bound { path: REGISTRY_V2_PATH.into(), sha256: REGISTRY_SHA.into() },
            Bound { path: "/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v3/registry.json".into(), sha256: REGISTRY_V2_SHA.into() },
        ] { assert!(Retained::load(&binding).is_err()); }
    }
    #[test]
    fn new_historical_native_never_becomes_current_live_or_descendant_authority() {
        let current = Retained::load(&binding_v2()).unwrap();
        let frame = accepted_frame();
        let native = &frame["native_census_before"];
        assert!(current.historical_native(native).unwrap());
        assert!(current.validate_current_membership(native).is_err());
        assert!(!current.historical_value(native).unwrap());
        let mut changed = native.clone();
        changed[PRODUCER]["MainPID"] = serde_json::json!("2467218");
        assert!(!current.historical_native(&changed).unwrap());
        assert!(current.validate_current_membership(&changed).is_err());
    }
    #[test]
    fn mutated_accepted_root_or_original_role_does_not_inherit_historical_acceptance() {
        let current = Retained::load(&binding_v2()).unwrap();
        let mut frame = accepted_frame();
        frame["publication_authorized"] = serde_json::json!(true);
        assert!(!current.historical_value(&frame).unwrap());
        let mut role = frame["native_census_before"][PRODUCER].clone();
        role["MemoryMax"] = serde_json::json!("1");
        assert!(!current.historical_producer_image(&role).unwrap());
        current.revalidate_inputs().unwrap();
    }
}

#[cfg(test)]
mod explicit_witness_selector_tests {
    use super::*;
    #[test]
    fn legacy_registries_never_implicitly_select_a_witness() {
        for (path, sha256) in [
            (REGISTRY_PATH, REGISTRY_SHA),
            (REGISTRY_V2_PATH, REGISTRY_V2_SHA),
        ] {
            let binding = Bound {
                path: path.into(),
                sha256: sha256.into(),
            };
            selector_binding(&binding).unwrap();
            assert!(!witness::is_selected_context(&witness_bound(&binding)));
        }
    }
    #[test]
    fn wrapper_is_exact_and_does_not_expand_original_registry_allowlist() {
        let selected = Bound {
            path: witness::CONTEXT_PATH.into(),
            sha256: witness::CONTEXT_SHA.into(),
        };
        assert!(witness::is_selected_context(&witness_bound(&selected)));
        assert!(selector_binding(&selected).is_err());
        for crossed in [
            Bound {
                path: REGISTRY_V2_PATH.into(),
                sha256: witness::CONTEXT_SHA.into(),
            },
            Bound {
                path: witness::CONTEXT_PATH.into(),
                sha256: REGISTRY_V2_SHA.into(),
            },
            Bound {
                path: "/tmp/context.json".into(),
                sha256: witness::CONTEXT_SHA.into(),
            },
        ] {
            assert!(!witness::is_selected_context(&witness_bound(&crossed)));
            assert!(selector_binding(&crossed).is_err());
        }
    }
}
