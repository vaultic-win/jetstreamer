//! Accounting-only current DATA and native-pool reconstruction.
//!
//! This deliberately has no candidate plan, runtime qualification or launch
//! authority. The production admission still loads and verifies its independent
//! qualification bundle before evaluating any candidate.
use super::*;
mod artifact154_peers;
pub(in crate::fleet) mod cold185;
pub(in crate::fleet) mod cold185_rollover;
mod guard_continuity;
mod historical_generated;
mod memory96_guard_pool;
mod metadata159_pool;
#[path = "accounting/process_references_fast.rs"]
pub(in crate::fleet) mod process_references_fast;
mod recovered_memory96_guard_pool;
mod retained136_growth;
mod retained_cached145_guard;
mod live145_prefix;
mod retained136_v2_growth;
mod retained136_v3_growth;
mod retained136_v7_growth;
mod retained_closure_read_namespace;
pub(super) mod retained_suffix136;
pub(super) mod retained_suffix136_v2;
pub(super) mod retained_suffix136_v3;
pub(super) mod retained_suffix136_v4;
pub(super) mod retained_suffix136_v5;
pub(super) mod retained_suffix136_v7;
pub(super) mod retained_suffix136_v8;
mod terminal152153_growth;
mod terminal155156_growth;
pub(super) mod trace136_guard_renewal;
pub(super) mod trial_descriptor;
mod trial_guard_pool;
pub(super) mod trial_peer;
pub(super) mod trial_recovered_memory96_peer;
pub(super) mod trial_root128_memory96_peer;
pub(super) mod trial_root128_peer;

const SOURCE_SCHEMA: &str = "jetstreamer-current-protected-data-accounting-spec-v1";
const ADMIT136: &str = "horizon-epoch136-hourly-input-admission-20261027-v1.service";
const ADMIT186: &str = "horizon-epoch186-bounded-worker-trial-admission-20261027-v1.service";
const ADMIT154: &str = "horizon-qualify-154-native-admission-20261028-v1.service";
const ADMIT186_ROOT128: &str =
    "horizon-epoch186-root128-bounded-worker-trial-admission-20261028-v1.service";
const ADMIT186_ROOT128_MEMORY96: &str =
    "horizon-epoch186-root128-memory96-bounded-worker-trial-admission-20261028-v1.service";
const ADMIT186_RECOVERED_MEMORY96: &str =
    "horizon-epoch186-recovered-memory96-admission-20261030-v1.service";
const HELPER_MEMORY: u64 = 512 << 20;
const FRONTIER_PROOF_ACTOR: &str = "horizon-prove-original141-frontier-20261028-v1.service";
const TERMINAL152153_PROOF_ACTOR: &str =
    "horizon-prove-terminal152153-frontier-20261101-v1.service";
const RETAINED144: &str = "horizon-qualify-144-assembly-only-recovery-20261022-v1.service";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sources {
    #[serde(default)]
    retained_cached145_guard: Option<retained_cached145_guard::Selector>,
    #[serde(default)]
    live145_prefix_export: Option<live145_prefix::Selector>,
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    fleet_plan: BoundFile,
    completion: BoundFile,
    resource_parent: BoundFile,
    phase_events: Vec<EventBinding>,
    #[serde(default)]
    metadata159_native_pool: Option<metadata159_pool::Selector>,
    #[serde(default)]
    epoch137_input_pool: Option<super::super::epoch137_input::pool::Selector>,
    reader191: BoundFile,
    transfer191: BoundFile,
    correction191: BoundFile,
    closed185: BoundFile,
    standing: BoundFile,
    #[serde(default)]
    original141_growth_closure: Option<BoundFile>,
    #[serde(default)]
    terminal155156_growth_closure: Option<BoundFile>,
    #[serde(default)]
    terminal152153_growth_closure: Option<BoundFile>,
    floor: BoundFile,
    guards: Vec<GuardSpec>,
    #[serde(default)]
    retained_trial186: Option<trial_peer::RetainedSources>,
    #[serde(default)]
    retained_suffix136: Option<retained_suffix136::RetainedSources>,
    #[serde(default)]
    retained_suffix136_growth_closure: Option<retained136_growth::Selector>,
    #[serde(default)]
    retained_suffix136_v2_growth_closure: Option<retained136_v2_growth::Selector>,
    #[serde(default)]
    retained_suffix136_v2: Option<retained_suffix136_v2::RetainedSources>,
    #[serde(default)]
    retained_suffix136_v3: Option<retained_suffix136_v3::RetainedSources>,
    #[serde(default)]
    retained_suffix136_v3_growth_closure: Option<retained136_v3_growth::Selector>,
    #[serde(default)]
    retained_suffix136_v4: Option<retained_suffix136_v4::RetainedSources>,
    #[serde(default)]
    retained_suffix136_v5: Option<retained_suffix136_v5::RetainedSources>,
    #[serde(default)]
    retained_suffix136_v7: Option<retained_suffix136_v7::RetainedSources>,
    #[serde(default)]
    retained_suffix136_v8: Option<retained_suffix136_v8::RetainedSources>,
    #[serde(default)]
    retained_suffix136_v7_growth_closure: Option<retained136_v7_growth::Selector>,
}

/// Borrowed accounting selectors: no dummy qualification or permission flags.
/// The terminal exception is chosen by code, never accepted from a caller.
pub(super) struct SpecView<'a> {
    pub observer: &'a BoundFile,
    pub fleet: &'a BoundFile,
    pub fleet_plan: &'a BoundFile,
    pub completion: &'a BoundFile,
    pub resource_parent: &'a BoundFile,
    pub phase_events: &'a [EventBinding],
    pub reader191: &'a BoundFile,
    pub transfer191: &'a BoundFile,
    pub correction191: &'a BoundFile,
    pub closed185: &'a BoundFile,
    pub guards: &'a [GuardSpec],
    pub allow_retained144_terminal: bool,
}

impl<'a> From<&'a Spec> for SpecView<'a> {
    fn from(s: &'a Spec) -> Self {
        Self {
            observer: &s.observer,
            fleet: &s.fleet,
            fleet_plan: &s.fleet_plan,
            completion: &s.completion,
            resource_parent: &s.resource_parent,
            phase_events: &s.phase_events,
            reader191: &s.reader191,
            transfer191: &s.transfer191,
            correction191: &s.correction191,
            closed185: &s.closed185,
            guards: &s.guards,
            allow_retained144_terminal: false,
        }
    }
}

impl<'a> From<&'a Sources> for SpecView<'a> {
    fn from(s: &'a Sources) -> Self {
        Self {
            observer: &s.observer,
            fleet: &s.fleet,
            fleet_plan: &s.fleet_plan,
            completion: &s.completion,
            resource_parent: &s.resource_parent,
            phase_events: &s.phase_events,
            reader191: &s.reader191,
            transfer191: &s.transfer191,
            correction191: &s.correction191,
            closed185: &s.closed185,
            guards: &s.guards,
            allow_retained144_terminal: true,
        }
    }
}

pub(super) struct BundleView<'a> {
    pub observer: &'a Value,
    pub fleet: &'a Value,
    pub fleet_plan: &'a Value,
    pub completion: &'a Value,
    pub parent: &'a Value,
    pub events: &'a [Value],
    pub reader: &'a Value,
    pub transfer: &'a Value,
    pub correction: &'a Value,
    pub closed185: &'a Value,
    pub standing: &'a Value,
}

impl<'a> From<&'a Bundle> for BundleView<'a> {
    fn from(b: &'a Bundle) -> Self {
        Self {
            observer: &b.observer,
            fleet: &b.fleet,
            fleet_plan: &b.fleet_plan,
            completion: &b.completion,
            parent: &b.parent,
            events: &b.events,
            reader: &b.reader,
            transfer: &b.transfer,
            correction: &b.correction,
            closed185: &b.closed185,
            standing: &b.standing,
        }
    }
}

#[derive(PartialEq)]
struct Loaded {
    observer: Value,
    fleet: Value,
    fleet_plan: Value,
    completion: Value,
    parent: Value,
    events: Vec<Value>,
    reader: Value,
    transfer: Value,
    correction: Value,
    closed185: Value,
    standing: Value,
    floor: Value,
}

// Bounded pathname-only context; never include JSON values or credentials.
pub(super) fn evidence_path(path: &Path) -> String {
    let display = path.to_string_lossy();
    let mut chars = display.chars();
    let mut result = chars.by_ref().take(256).collect::<String>();
    if chars.next().is_some() {
        result.push_str("...");
    }
    result
}
fn read_source(
    label: &str,
    b: &BoundFile,
    reader: fn(&BoundFile) -> Result<Value>,
) -> Result<Value> {
    reader(b).with_context(|| format!("accounting {label}: {}", evidence_path(&b.path)))
}

/// The one exact phase reader for initial accounting and freshness revalidation.
pub(super) fn phase_event_source(b: &BoundFile) -> Result<Value> {
    read_source("phase event", b, historical_generated::phase_event)
}

impl Loaded {
    fn read(s: &Sources) -> Result<Self> {
        Ok(Self {
            observer: read_source("observer", &s.observer, protected_generated)?,
            fleet: read_source("fleet", &s.fleet, protected_generated)?,
            fleet_plan: read_source("fleet plan", &s.fleet_plan, io::read)?,
            completion: read_source("completion", &s.completion, protected_generated)?,
            parent: read_source("resource parent", &s.resource_parent, io::read)?,
            events: s
                .phase_events
                .iter()
                .map(|e| phase_event_source(&e.source))
                .collect::<Result<_>>()?,
            reader: read_source("reader 191", &s.reader191, io::read)?,
            transfer: read_source(
                "transfer 191",
                &s.transfer191,
                historical_generated::transfer191,
            )?,
            correction: read_source("correction 191", &s.correction191, io::read)?,
            closed185: read_source("closed 185", &s.closed185, io::read)?,
            standing: read_source("standing promises", &s.standing, io::read)?,
            floor: read_source("floor table", &s.floor, io::read)?,
        })
    }

    fn view(&self) -> BundleView<'_> {
        BundleView {
            observer: &self.observer,
            fleet: &self.fleet,
            fleet_plan: &self.fleet_plan,
            completion: &self.completion,
            parent: &self.parent,
            events: &self.events,
            reader: &self.reader,
            transfer: &self.transfer,
            correction: &self.correction,
            closed185: &self.closed185,
            standing: &self.standing,
        }
    }
}

/// Generated frame receipts remain root protected at their original paths.
/// Accept owner writes only for exact bound JSON, never for executables or static
/// policy. Stable bounded reads, custody and a second hash-bound read guard races.
pub(in crate::fleet) fn protected_generated(b: &BoundFile) -> Result<Value> {
    let metadata = |path: &Path| -> Result<fs::Metadata> {
        ensure!(
            path.is_absolute() && path.canonicalize()? == path,
            "generated evidence is noncanonical"
        );
        let m = fs::symlink_metadata(path)?;
        let parent = fs::symlink_metadata(path.parent().context("generated evidence parent")?)?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && m.len() <= 16 << 20
                && parent.is_dir()
                && parent.uid() == 0
                && parent.mode() & 0o022 == 0,
            "generated evidence lacks protected root custody"
        );
        Ok(m)
    };
    let before = metadata(&b.path)?;
    ensure!(
        digest(&b.sha256, 64),
        "generated evidence digest is malformed"
    );
    let bytes = read_stable_bounded(&b.path, 16 << 20, "protected accounting evidence")?;
    let after = metadata(&b.path)?;
    ensure!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mode(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec()
        ) == (
            after.dev(),
            after.ino(),
            after.len(),
            after.mode(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        ) && hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "generated evidence identity or bytes changed"
    );
    io::unique_json(&bytes)
}

fn retained_terminal_native(fleet: &Value) -> Result<Option<Value>> {
    let Some(saved) = fleet["unit_census"].get(RETAINED144) else {
        return Ok(None);
    };
    if !retained144_terminal(RETAINED144, saved) {
        return Ok(None);
    }
    let current = io::properties(RETAINED144)?;
    ensure!(
        retained144_terminal(RETAINED144, &current)
            && current["Restart"] == "no"
            && current["InvocationID"] == saved["InvocationID"],
        "retained epoch 144 success or empty native state changed"
    );
    Ok(Some(current))
}

/// A retained successful oneshot is not a resource-owning replay. Preserve the
/// exact existing unit and require every positive terminal condition; failed,
/// restarting, populated or merely inactive units cannot borrow this exception.
pub(super) fn retained144_terminal(unit: &str, native: &Value) -> bool {
    unit == RETAINED144
        && native["Id"] == RETAINED144
        && native["ActiveState"] == "active"
        && native["SubState"] == "exited"
        && native["MainPID"] == "0"
        && native["ControlGroup"] == ""
        && native["NRestarts"] == "0"
        && native["Result"] == "success"
        && native["ExecMainStatus"] == "0"
        && native["InvocationID"]
            .as_str()
            .is_some_and(|iid| digest(iid, 32))
}

fn source_bindings(s: &Sources) -> Vec<Value> {
    let mut result = [
        &s.observer,
        &s.fleet,
        &s.fleet_plan,
        &s.completion,
        &s.resource_parent,
        &s.reader191,
        &s.transfer191,
        &s.correction191,
        &s.closed185,
        &s.standing,
        &s.floor,
    ]
    .into_iter()
    .map(binding)
    .collect::<Vec<_>>();
    result.extend(s.phase_events.iter().map(|e| binding(&e.source)));
    if let Some(control) = &s.epoch137_input_pool {
        result.extend(super::super::epoch137_input::pool::bindings(control));
    }
    if let Some(metadata) = &s.metadata159_native_pool {
        result.extend(metadata159_pool::bindings(metadata));
    }
    if let Some(closure) = &s.original141_growth_closure {
        result.push(binding(closure));
    }
    if let Some(closure) = &s.terminal155156_growth_closure {
        result.push(binding(closure));
    }
    if let Some(closure) = &s.terminal152153_growth_closure {
        result.push(binding(closure));
    }
    if let Some(retained) = &s.retained_trial186 {
        result.push(binding(&retained.failure));
        result.push(binding(&retained.stop));
    }
    if let Some(retained) = &s.retained_suffix136 {
        result.push(binding(&retained.terminal));
        result.push(binding(&retained.inactive));
    }
    if let Some(closure) = &s.retained_suffix136_growth_closure {
        result.push(binding(&closure.spec));
        result.push(binding(&closure.receipt));
    }
    if let Some(closure) = &s.retained_suffix136_v2_growth_closure {
        result.push(binding(&closure.spec));
        result.push(binding(&closure.receipt));
    }
    if let Some(retained) = &s.retained_suffix136_v2 {
        result.push(binding(&retained.terminal));
        result.push(binding(&retained.inactive));
    }
    if let Some(retained) = &s.retained_suffix136_v3 {
        result.push(binding(&retained.terminal));
        result.push(binding(&retained.inactive));
        result.push(binding(&retained.owner));
    }
    if let Some(closure) = &s.retained_suffix136_v3_growth_closure {
        result.push(binding(&closure.spec));
        result.push(binding(&closure.receipt));
    }
    if let Some(retained) = &s.retained_suffix136_v4 {
        result.push(binding(&retained.terminal));
        result.push(binding(&retained.inactive));
        result.push(binding(&retained.owner));
    }
    if let Some(retained) = &s.retained_suffix136_v5 {
        result.push(binding(&retained.terminal));
        result.push(binding(&retained.inactive));
        result.push(binding(&retained.owner));
    }
    if let Some(retained) = &s.retained_suffix136_v7 {
        result.push(binding(&retained.terminal));
        result.push(binding(&retained.inactive));
        result.push(binding(&retained.owner));
    }
    if let Some(retained) = &s.retained_suffix136_v8 {
        result.push(binding(&retained.terminal));
        result.push(binding(&retained.inactive));
        result.push(binding(&retained.owner));
    }
    if let Some(closure) = &s.retained_suffix136_v7_growth_closure {
        result.push(binding(&closure.spec));
        result.push(binding(&closure.receipt));
    }
    for g in &s.guards {
        result.push(binding(&g.binary));
        result.extend(g.plan.iter().map(binding));
        result.extend(g.sample.iter().map(binding));
    }
    result
}

fn guard_coverage(expected: &[core::Owner], guards: &[core::Guard]) -> Result<u64> {
    let mut units = BTreeSet::new();
    for guard in guards {
        ensure!(
            units.insert(&guard.unit) && guard.protection_shape(),
            "duplicate or empty inherited guard"
        );
        ensure!(
            guard.protection_shape()
                && guard.retained_scope_clear(expected)
                && guard.no_trip
                && guard.command_and_binary_bound
                && guard.receipt_fresh,
            "unqualified inherited guard"
        );
    }
    for owner in expected.iter().filter(|o| o.guard_required) {
        ensure!(
            guards.iter().any(|g| g
                .protected_owners
                .iter()
                .any(|(u, i)| u == &owner.unit && i == &owner.iid)),
            "current owner has no exact live guard coverage: {}",
            owner.unit
        );
    }
    guards
        .iter()
        .map(|g| g.minimum_free_bytes)
        .max()
        .context("inherited live guard floor missing")
}

fn helper_subcommand(name: &str) -> Result<&'static str> {
    Ok(match name {
        super::super::recovery199::ADMIT => "admit-http500-recovery199",
        super::super::recovery199::ENROLL => "enroll-http500-recovery199",
        super::super::recovery199::AUDIT => "audit-http500-recovery199",
        super::super::recovery199::TERMINAL_ACTOR => "capture-http500-recovery199-terminal",
        super::super::direct163::ADMIT => "admit-direct163",
        super::super::direct163::ENROLL => "enroll-direct163",
        unit if super::super::cached145::admission_unit(unit) => "admit-cached145",
        unit if super::super::cached145::enrollment_unit(unit) => "enroll-cached145",
        "horizon-epoch137-root-snapshot-input-admission-20261031-g1.service" => {
            "admit-snapshot137-root-input"
        }
        "horizon-epoch137-real-transfer-admission-20261103-g3.service" => {
            "admit-snapshot137-root-input"
        }
        "horizon-epoch137-real-transfer-trial-admission-20261103-g3.service" => {
            "qualify-snapshot137-root-input-admission"
        }
        ADMIT136 => "admit-hourly136-input",
        "horizon-epoch161-snapshot-input-admission-20261028-v1.service" => {
            "admit-snapshot161-input"
        }
        "horizon-epoch161-snapshot-input-admission-20261029-g4.service" => {
            "admit-snapshot161-retry4-input"
        }
        "horizon-epoch161-snapshot-input-admission-20261030-g5.service" => {
            "admit-snapshot161-retry5-input"
        }
        "horizon-epoch161-snapshot-input-admission-20261031-g7.service" => {
            "admit-snapshot161-retry7-input"
        }
        "horizon-epoch161-snapshot-input-admission-20261030-g6.service" => {
            "admit-snapshot161-retry6-input"
        }
        unit if unit == super::super::suffix136::contract::scope::ADMIT_UNIT => {
            "admit-hourly136-suffix"
        }
        unit if unit == super::super::charge136::contract::scope::ADMIT_UNIT => {
            "admit-hourly136-charge-trace"
        }
        unit if unit == super::super::charge136_retry0002::contract::scope::ADMIT_UNIT => {
            "admit-hourly136-charge-trace-retry-0002"
        }
        unit if unit == super::super::charge136_retry0003::contract::scope::ADMIT_UNIT => {
            "admit-hourly136-charge-trace-retry-0003"
        }
        unit if unit == super::super::charge136_retry0004::contract::scope::ADMIT_UNIT => {
            "admit-hourly136-charge-trace-retry-0004"
        }
        unit if unit == super::super::charge136_retry0005::contract::scope::ADMIT_UNIT => {
            "admit-hourly136-charge-trace-retry-0005"
        }
        unit if unit == super::super::suffix154_admission::contract::ADMIT => "admit-suffix154",
        unit if unit == super::super::durable_prefix141::ADMIT => "admit-durable-prefix141",
        unit if unit == super::super::private154_admission::UNIT => "admit-private154-scans",
        unit if unit == super::super::artifact154_admission::UNIT => "admit-private154-artifact",
        unit if unit == super::super::failed4_current_accounting_reader::UNIT => {
            "read-failed4-current-accounting"
        }
        unit if unit == super::super::terminal_legacy_current_memory_proof::UNIT => {
            "prove-terminal-legacy-current-memory"
        }
        ADMIT154 => "admit-native154",
        ADMIT186_RECOVERED_MEMORY96 => "admit-epoch186-recovered-memory96",
        ADMIT186 | ADMIT186_ROOT128 | ADMIT186_ROOT128_MEMORY96 => {
            "admit-epoch186-bounded-worker-trial"
        }
        FRONTIER_PROOF_ACTOR => "prove-original141-data-frontier",
        TERMINAL152153_PROOF_ACTOR => "prove-terminal152153-data-frontier",
        retained136_growth::ACTOR => "close-retained136-v1-growth",
        retained136_v2_growth::ACTOR => "close-retained136-v2-growth",
        retained136_v3_growth::ACTOR => "close-retained136-v3-growth",
        retained136_v7_growth::ACTOR => "close-retained136-v7-growth",
        _ => anyhow::bail!("unsupported accounting helper native unit"),
    })
}

fn validate_helper_arguments(name: &str, subcommand: &str, args: &[String]) -> Result<()> {
    let check_only = name == "horizon-epoch161-snapshot-input-admission-20261031-g7.service"
        && subcommand == "admit-snapshot161-retry7-input"
        && args.len() == 8
        && args[7] == "--check-only";
    ensure!(
        (args.len() == 7 || check_only)
            && args[1] == subcommand
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && digest(&args[4], 64)
            && digest(&args[6], 64),
        "accounting helper command is not exact"
    );
    Ok(())
}

/// The one read-only failed4 reader has an exact 2 GiB native slot. Other
/// previously qualified helpers retain their existing 512 MiB profiles.
/// No source selector or caller argument can request a different cap.
fn helper_memory_bytes(name: &str, native: &Value) -> Result<u64> {
    helper_subcommand(name)?;
    let expected = if name == super::super::failed4_current_accounting_reader::UNIT
        || name == super::super::direct163::ADMIT
        || name == super::super::direct163::ENROLL
        || [
            super::super::recovery199::ADMIT,
            super::super::recovery199::ENROLL,
            super::super::recovery199::AUDIT,
            super::super::recovery199::TERMINAL_ACTOR,
        ]
        .contains(&name)
    {
        2u64 << 30
    } else {
        HELPER_MEMORY
    };
    let expected_text = expected.to_string();
    ensure!(
        native["MemoryMax"].as_str() == Some(expected_text.as_str()),
        "accounting helper exact scoped cap differs"
    );
    Ok(expected)
}

/// Authenticate only the actual caller's fixed native helper slot. A source
/// selector never supplies a unit list, byte allowance or namespace exemption.
fn helper_allocation() -> Result<Value> {
    let raw = fs::read_to_string("/proc/self/cgroup")?;
    let name = raw
        .trim()
        .strip_prefix("0::/system.slice/")
        .context("accounting caller is outside an exact native helper")?;
    let subcommand = helper_subcommand(name)?;
    let args = env::args().collect::<Vec<_>>();
    validate_helper_arguments(name, subcommand, &args)?;
    let executable = fs::read_link("/proc/self/exe")?;
    let bytes = io::sealed(&executable)?.len();
    ensure!(
        bytes <= 256 << 20,
        "accounting helper executable bound exceeded"
    );
    io::immutable(
        &BoundFile {
            path: executable.clone(),
            sha256: args[6].clone(),
        },
        bytes,
    )?;
    let native = io::properties(name)?;
    let own_memory = helper_memory_bytes(name, &native)?;
    let pid = u64::from(std::process::id());
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        native["Id"] == name
            && native["InvocationID"] == iid
            && digest(&iid, 32)
            && native["MainPID"].as_str() == Some(pid.to_string().as_str())
            && native["ActiveState"] == "active"
            && native["SubState"] == "running"
            && native["NRestarts"] == "0"
            && native["Restart"] == "no"
            && native["User"] == "root"
            && native["MemoryAccounting"] == "yes"
            && native["MemorySwapMax"] == "0"
            && io::unit_micros(string(&native, "/CPUQuotaPerSecUSec")?)? == 1_000_000
            && io::unit_micros(string(&native, "/RuntimeMaxUSec")?)? <= 900_000_000,
        "accounting helper identity or finite pool contract differs"
    );
    let command = string(&native, "/ExecStart")?;
    ensure!(
        command.contains(executable.to_str().context("helper path UTF-8")?)
            && command.contains(subcommand)
            && command.contains(&args[4])
            && command.contains(&args[6]),
        "accounting helper native command differs"
    );
    Ok(
        json!({"unit":name,"invocation_id":iid,"pid":pid,"start_ticks":io::start_ticks(pid)?,
        "memory_max_bytes":own_memory,"data_reservation_bytes":0,"native":native,
        "source_bindings":[{"path":executable,"sha256":args[6]}],"nonoverlapping_successor_slot":true}),
    )
}

fn pool_rows(
    expected: &[core::Owner],
    helper: &Value,
    peer: Option<&Value>,
    suffix_guard: Option<&Value>,
    memory96_guard: Option<&Value>,
) -> Result<Vec<Value>> {
    pool_rows_with_additional(expected, helper, peer, suffix_guard, memory96_guard, || {
        Ok([
            super::super::charge136::guard_allocation()?,
            super::super::charge136::supervisor_allocation()?,
            super::super::charge136_retry0002::guard_allocation()?,
            super::super::charge136_retry0002::supervisor_allocation()?,
            crate::charge136_retry0002_lifecycle::joint_startup::allocation()?,
            crate::charge136_retry0002_lifecycle::joint_startup::fixture_allocation()?,
            super::super::charge136_retry0003::guard_allocation()?,
            super::super::charge136_retry0003::supervisor_allocation()?,
            crate::charge136_retry0003_lifecycle::joint_startup::allocation()?,
            crate::charge136_retry0003_lifecycle::joint_startup::fixture_allocation()?,
            super::super::charge136_retry0004::guard_allocation()?,
            super::super::charge136_retry0005::guard_allocation()?,
            super::super::charge136_retry0004::supervisor_allocation()?,
            super::super::charge136_retry0005::supervisor_allocation()?,
            crate::charge136_retry0004_lifecycle::joint_startup::allocation()?,
            crate::charge136_retry0005_lifecycle::joint_startup::allocation()?,
            crate::charge136_retry0004_lifecycle::joint_startup::fixture_allocation()?,
            crate::charge136_retry0005_lifecycle::joint_startup::fixture_allocation()?,
            super::super::input161_retry6::atomic::allocation()?,
            super::super::input161_retry7::atomic::allocation()?,
            super::super::suffix154::control_allocation()?,
            super::super::suffix154::guard_allocation()?,
        ]
        .into_iter()
        .flatten()
        .collect())
    })
}

fn pool_rows_with_additional(
    expected: &[core::Owner],
    helper: &Value,
    peer: Option<&Value>,
    suffix_guard: Option<&Value>,
    memory96_guard: Option<&Value>,
    read_additional: impl FnOnce() -> Result<Vec<Value>>,
) -> Result<Vec<Value>> {
    let mut rows = vec![helper.clone()];
    for owner in expected
        .iter()
        .filter(|o| matches!(o.role, core::Role::NativePark))
    {
        let native = io::properties(&owner.unit)?;
        let memory = string(&native, "/MemoryMax")?.parse::<u64>()?;
        ensure!(
            native["InvocationID"] == owner.iid
                && memory > 0
                && memory <= core::PARK_SUBALLOCATION
                && native["MemoryAccounting"] == "yes"
                && native["MemorySwapMax"] == "0",
            "native park lacks exact finite retained-pool allocation"
        );
        rows.push(
            json!({"unit":owner.unit,"invocation_id":owner.iid,"pid":owner.pid,
            "start_ticks":owner.start_ticks,"memory_max_bytes":memory,"native":native,
            "source_bindings":[]}),
        );
    }
    if let Some(peer) = peer
        && number(peer, "/memory_max_bytes")? > 0
    {
        rows.push(peer.clone());
    }
    if let Some(guard) = suffix_guard {
        rows.push(guard.clone());
    }
    if let Some(guard) = memory96_guard {
        rows.push(guard.clone());
    }
    for row in read_additional()? {
        rows.push(row);
    }
    validate_pool(&rows)?;
    rows.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    Ok(rows)
}

fn validate_pool(rows: &[Value]) -> Result<u64> {
    let mut units = BTreeSet::new();
    let mut invocations = BTreeSet::new();
    let mut sum = 0u64;
    for row in rows {
        let unit = string(row, "/unit")?;
        let iid = string(row, "/invocation_id")?;
        let bytes = number(row, "/memory_max_bytes")?;
        ensure!(
            !unit.is_empty()
                && digest(iid, 32)
                && units.insert(unit)
                && invocations.insert(iid)
                && bytes > 0,
            "ambiguous or unbounded native pool allocation"
        );
        sum = sum
            .checked_add(bytes)
            .context("native pool allocation overflow")?;
    }
    ensure!(
        sum <= core::NATIVE_POOL,
        "actual native allocations exceed the single retained pool"
    );
    Ok(sum)
}

#[cfg(test)]
mod real137_trial_dispatch_tests {
    use super::*;
    #[test]
    fn native_trial_and_production_callers_keep_disjoint_exact_commands() {
        assert_eq!(
            helper_subcommand("horizon-epoch137-real-transfer-trial-admission-20261103-g3.service")
                .unwrap(),
            "qualify-snapshot137-root-input-admission"
        );
        for unit in [
            "horizon-epoch137-root-snapshot-input-admission-20261031-g1.service",
            "horizon-epoch137-real-transfer-admission-20261103-g3.service",
        ] {
            assert_eq!(
                helper_subcommand(unit).unwrap(),
                "admit-snapshot137-root-input"
            );
        }
        assert!(
            helper_subcommand("horizon-epoch137-first-entry-fixture-owner-20261103-v2.service")
                .is_err()
        );
    }
}

#[cfg(test)]
fn protect(
    original: &[core::Obligation],
    standing: u64,
    guard: u64,
    peers: &[Value],
) -> Result<(Vec<core::Obligation>, u64)> {
    protect_with_growth(original, standing, guard, peers, None)
}
#[cfg(test)]
fn protect_with_growth(
    original: &[core::Obligation],
    standing: u64,
    guard: u64,
    peers: &[Value],
    closure: Option<&retained136_growth::Validated>,
) -> Result<(Vec<core::Obligation>, u64)> {
    // Preserve the existing v1-only interface and private token unchanged.
    protect_with_growth_v2(original, standing, guard, peers, closure, None)
}
#[cfg(test)]
fn protect_with_growth_v2(
    original: &[core::Obligation],
    standing: u64,
    guard: u64,
    peers: &[Value],
    closure: Option<&retained136_growth::Validated>,
    closure_v2: Option<&retained136_v2_growth::Validated>,
) -> Result<(Vec<core::Obligation>, u64)> {
    protect_with_growth_v3(original, standing, guard, peers, closure, closure_v2, None)
}
#[cfg(test)]
fn protect_with_growth_v3(
    original: &[core::Obligation],
    standing: u64,
    guard: u64,
    peers: &[Value],
    closure: Option<&retained136_growth::Validated>,
    closure_v2: Option<&retained136_v2_growth::Validated>,
    closure_v3: Option<&retained136_v3_growth::Validated>,
) -> Result<(Vec<core::Obligation>, u64)> {
    protect_with_growth_v7(
        original,
        standing,
        guard,
        peers,
        closure,
        closure_v2,
        (closure_v3, None),
    )
}
fn protect_with_growth_v7(
    original: &[core::Obligation],
    standing: u64,
    guard: u64,
    peers: &[Value],
    closure: Option<&retained136_growth::Validated>,
    closure_v2: Option<&retained136_v2_growth::Validated>,
    closures: (
        Option<&retained136_v3_growth::Validated>,
        Option<&retained136_v7_growth::Validated>,
    ),
) -> Result<(Vec<core::Obligation>, u64)> {
    let (closure_v3, closure_v7) = closures;
    let mut inherited_native141_guard = 0u64;
    let mut rows = original.to_vec();
    let mut extra = 0u64;
    let mut closure_used = false;
    let mut closure_v2_used = false;
    let mut closure_v3_used = false;
    let mut closure_v7_used = false;
    let mut units = BTreeSet::new();
    let mut iids = BTreeSet::new();
    for peer in peers {
        let bytes = number(peer, "/data_reservation_bytes")?;
        let unit = string(peer, "/unit")?;
        if super::super::recovery199_contract::FAMILY.contains(&unit) {
            super::super::recovery199::accounting::peer(peer)?;
            if unit == super::super::recovery199_contract::PRODUCER {
                let iid = string(peer, "/invocation_id")?;
                ensure!(
                    rows.iter()
                        .filter(|r| r.epoch == 199
                            && r.producer_invocation_id == iid
                            && r.outstanding_bytes == 768u64 << 30)
                        .count()
                        == 1,
                    "recovery199 peer lacks its single complete typed growth row"
                );
            }
            continue;
        }
        if [
            super::super::direct163::GUARD,
            super::super::direct163::STOP,
        ]
        .contains(&unit)
        {
            ensure!(
                bytes == 0
                    && peer["memory_max_bytes"] == 0
                    && peer["included_once_in_direct163_parent_claim"] == true
                    && peer["direct163_registration"]["path"]
                        == "/var/lib/jetstreamer/horizon-direct163-enrollment-20261105-v1/enrollment.json",
                "direct163 auxiliary reservation must remain in its one parent claim"
            );
            continue;
        }
        let (epoch, prefix) = if unit == live145_prefix::ACTOR {
            live145_prefix::peer_shape(peer)?;
            (145, "live145-prefix-export")
        } else if !peer["cold185_registration"].is_null() {
            if !cold185::peer_data(peer)? {
                // The exact guard memory is charged by its separate peer row;
                // only the actor contributes the source-bound DATA obligation.
                continue;
            }
            (185, "cold185-startpre")
        } else if unit == super::super::direct163::UNIT {
            ensure!(
                peer["direct163_registration"]["path"]
                    == "/var/lib/jetstreamer/horizon-direct163-enrollment-20261105-v1/enrollment.json"
                    && bytes == 768u64 << 30,
                "direct163 peer DATA scope"
            );
            (163, "direct163")
        } else if unit == super::super::input161::UNIT {
            ensure!(
                bytes == super::super::input161::RESERVE,
                "161 peer DATA differs"
            );
            (161, "input161")
        } else if unit == super::super::input161_retry7::UNIT {
            ensure!(
                bytes == super::super::input161_retry7::RESERVE,
                "generation5 DATA differs"
            );
            (161, "input161-retry7")
        } else if unit == super::super::input161_retry6::UNIT {
            ensure!(
                bytes == super::super::input161_retry6::RESERVE,
                "generation5 DATA differs"
            );
            (161, "input161-retry6")
        } else if unit == super::super::input161_retry5::UNIT {
            ensure!(
                bytes == super::super::input161_retry5::RESERVE,
                "generation5 DATA differs"
            );
            (161, "input161-retry5")
        } else if unit == super::super::input161_retry4::UNIT {
            ensure!(
                bytes == super::super::input161_retry4::RESERVE,
                "retry4 peer DATA differs"
            );
            (161, "input161-retry4")
        } else if unit == super::super::input136::UNIT {
            ensure!(bytes == 3_308_702_239, "input 136 peer DATA differs");
            (136, "input136")
        } else if unit == retained_suffix136_v8::UNIT {
            ensure!(
                bytes == retained_suffix136_v8::DATA,
                "retained epoch 136 v8 DATA differs"
            );
            (136, "suffix136-retained-v8")
        } else if [
            super::super::suffix154_admission::contract::UNIT,
            super::super::suffix154_admission::contract::CONTROL,
        ]
        .contains(&unit)
        {
            ensure!(
                bytes == super::super::suffix154_admission::contract::DATA,
                "154 suffix DATA differs"
            );
            (154, "suffix154")
        } else if unit == super::super::charge136_retry0003::contract::scope::UNIT {
            ensure!(
                bytes == super::super::charge136_retry0003::contract::scope::DATA,
                "retry-0003 peer DATA differs"
            );
            (136, "charge136-retry-0003")
        } else if unit == super::super::charge136_retry0004::contract::scope::UNIT {
            ensure!(
                bytes == super::super::charge136_retry0004::contract::scope::DATA,
                "retry-0004 peer DATA differs"
            );
            (136, "charge136-retry-0004")
        } else if unit == super::super::charge136_retry0005::contract::scope::UNIT {
            ensure!(
                bytes == super::super::charge136_retry0005::contract::scope::DATA,
                "retry-0004 peer DATA differs"
            );
            (136, "charge136-retry-0004")
        } else if unit == super::super::charge136_retry0002::contract::scope::UNIT {
            ensure!(
                bytes == super::super::charge136_retry0002::contract::scope::DATA,
                "retry-0002 peer DATA differs"
            );
            (136, "charge136-retry-0002")
        } else if unit == super::super::charge136::contract::scope::UNIT {
            ensure!(
                bytes == super::super::charge136::contract::scope::DATA,
                "new charge136 peer DATA differs"
            );
            (136, "charge136")
        } else if unit == super::super::durable_prefix141::UNIT {
            ensure!(
                bytes == super::super::durable_prefix141::DATA,
                "native141 fresh DATA reservation differs"
            );
            let floor = number(peer, "/inherited_guard_minimum_free_bytes")?;
            if floor > 0 {
                inherited_native141_guard = floor
                    .checked_add(bytes)
                    .context("native141 live guard plus protected remaining DATA overflow")?;
            }
            (141, "durable-prefix141")
        } else if unit == super::super::suffix136::contract::scope::UNIT {
            ensure!(bytes == 72u64 << 30, "136 suffix peer DATA differs");
            (136, "suffix136")
        } else if unit == retained_suffix136::UNIT {
            ensure!(
                bytes == retained_suffix136::DATA,
                "retained epoch 136 v1 DATA differs"
            );
            (136, "suffix136-retained-v1")
        } else if unit == retained_suffix136_v2::UNIT {
            ensure!(
                bytes == retained_suffix136_v2::DATA,
                "retained epoch 136 v2 DATA differs"
            );
            (136, "suffix136-retained-v2")
        } else if unit == retained_suffix136_v3::UNIT {
            ensure!(
                bytes == retained_suffix136_v3::DATA,
                "retained epoch 136 v3 DATA differs"
            );
            (136, "suffix136-retained-v3")
        } else if unit == retained_suffix136_v4::UNIT {
            ensure!(
                bytes == retained_suffix136_v4::DATA,
                "retained epoch 136 v4 DATA differs"
            );
            (136, "suffix136-retained-v4")
        } else if unit == retained_suffix136_v5::UNIT {
            ensure!(
                bytes == retained_suffix136_v5::DATA,
                "retained epoch 136 v5 DATA differs"
            );
            (136, "suffix136-retained-v5")
        } else if unit == retained_suffix136_v7::UNIT {
            ensure!(
                bytes == retained_suffix136_v7::DATA,
                "retained epoch 136 v7 DATA differs"
            );
            (136, "suffix136-retained-v7")
        } else if unit == trial_descriptor::RECOVERED_MEMORY96.unit {
            ensure!(
                bytes
                    == trial_descriptor::RECOVERED_MEMORY96
                        .limits()
                        .parent_bytes
                        .checked_add(
                            jetstreamer_horizon_observe::trial186::recovered::PUBLICATION_COPY
                        )
                        .context("recovered trial and copy hold overflow")?,
                "recovered memory96 trial DATA differs"
            );
            (186, "trial186-recovered-memory96")
        } else if unit == trial_descriptor::ROOT128_MEMORY96.unit {
            ensure!(
                bytes == trial_descriptor::ROOT128_MEMORY96.limits().parent_bytes,
                "memory96 trial parent DATA differs"
            );
            (186, "trial186-root128-memory96")
        } else if unit == trial_descriptor::ROOT128.unit {
            ensure!(
                bytes == trial_descriptor::ROOT128.limits().parent_bytes,
                "root128 trial parent DATA differs"
            );
            (186, "trial186-root128")
        } else if let Some(role) = [
            crate::fleet::private154_downstream_roles_pure::Role::Collect,
            crate::fleet::private154_downstream_roles_pure::Role::Import,
            crate::fleet::private154_downstream_roles_pure::Role::Deliver,
        ]
        .into_iter()
        .find(|role| role.unit() == unit)
        {
            ensure!(
                bytes == role.copy()
                    && peer["memory_max_bytes"] == role.memory()
                    && peer["native_pool_suballocation"] == true,
                "artifact154 peer changed conservative DATA/native pool shape"
            );
            (154, role.name())
        } else if super::super::cached145_allocation::scope_unit(unit) {
            super::super::cached145_allocation::peer_shape(peer)?;
            (145, "cached145")
        } else if unit == trial_peer::UNIT {
            ensure!(
                bytes == trial_peer::PARENT_BYTES,
                "trial 186 peer DATA differs"
            );
            (186, "trial186")
        } else {
            anyhow::bail!("unsupported peer DATA allocation");
        };
        let iid = string(peer, "/invocation_id")?;
        ensure!(
            digest(iid, 32) && units.insert(unit) && iids.insert(iid),
            "duplicate peer DATA allocation"
        );
        let key = format!("{prefix}/{iid}");
        ensure!(
            !rows.iter().any(|r| r.claim_key == key),
            "peer DATA already charged in original source"
        );
        // Retain historical DATA; each private attempt token only closes its own growth.
        let growth = if unit == retained_suffix136::UNIT {
            if let Some(validated) = closure {
                closure_used = true;
                validated.growth_for(peer)?
            } else {
                bytes
            }
        } else if unit == retained_suffix136_v2::UNIT {
            if let Some(validated) = closure_v2 {
                closure_v2_used = true;
                validated.growth_for(peer)?
            } else {
                bytes
            }
        } else if unit == retained_suffix136_v3::UNIT {
            if let Some(validated) = closure_v3 {
                closure_v3_used = true;
                validated.growth_for(peer)?
            } else {
                bytes
            }
        } else if unit == retained_suffix136_v7::UNIT {
            if let Some(validated) = closure_v7 {
                closure_v7_used = true;
                validated.growth_for(peer)?
            } else {
                bytes
            }
        } else {
            bytes
        };
        rows.push(core::Obligation {
            claim_key: key,
            epoch,
            producer_invocation_id: iid.into(),
            outstanding_bytes: growth,
        });
        extra = extra
            .checked_add(growth)
            .context("actual peer DATA sum overflow")?;
    }
    ensure!(
        closure.is_none() || closure_used,
        "validated v1 closure omitted its retained peer"
    );
    ensure!(
        closure_v2.is_none() || closure_v2_used,
        "validated v2 closure omitted its retained peer"
    );
    ensure!(
        closure_v3.is_none() || closure_v3_used,
        "validated v3 closure omitted its retained peer"
    );
    ensure!(
        closure_v7.is_none() || closure_v7_used,
        "validated v7 closure omitted its retained peer"
    );
    let sum = rows.iter().try_fold(0u64, |n, r| {
        n.checked_add(r.outstanding_bytes)
            .context("protected DATA sum overflow")
    })?;
    let standing = standing
        .checked_add(extra)
        .context("standing DATA plus actual peers overflow")?;
    let confirmed = DATA_FLOOR
        .checked_add(extra)
        .context("confirmed DATA plus actual peers overflow")?;
    Ok((
        rows,
        sum.max(standing)
            .max(guard)
            .max(confirmed)
            .max(inherited_native141_guard),
    ))
}

fn requires_typed_allocation(name: &str, command: &str) -> bool {
    let payload = [
        "epoch185-guarded-cold",
        "epoch145-prefix-extract",
        "jetstreamer-node",
        "jetstreamer-historical-worker",
        "jetstreamer-r2-progressive",
        "jetstreamer-r2 ",
        "jetstreamer-qualification-verify",
        "jetstreamer-horizon-import",
        "jetstreamer-epoch186-current-worker-trial",
        "jetstreamer-epoch186-root128-trial",
        "jetstreamer-epoch186-root128-memory96-trial",
        "jetstreamer-epoch186-root128-memory96-guard",
        "jetstreamer-epoch136-hourly-snapshot-download",
        "jetstreamer-epoch161-snapshot-download",
        "jetstreamer-epoch136-hourly-suffix",
        "jetstreamer-epoch136-hourly-charge-trace",
        "jetstreamer-charge136-recovered-supervisor",
        "jetstreamer-charge136-retry-0002-supervisor",
        "jetstreamer-charge136-retry-0003-supervisor",
        "jetstreamer-native154-suffix-control",
        "jetstreamer-epoch154-artifact",
        "jetstreamer-epoch141-durable-prefix-lifecycle",
        "/cargo ",
        "/rustc ",
    ]
    .iter()
    .any(|needle| command.contains(needle));
    let named = [
        "horizon-extract145-prefix-",
        "horizon-guard145-prefix-",
        "horizon-cold-",
        "jetstreamer-cold-",
        "horizon-publish-",
        "horizon-upload-",
        "horizon-full-verify-",
        "horizon-plugin-verify-",
        "horizon-independent-full-read-",
        "horizon-qualify-186-current-worker-capability-root128-",
        "horizon-qualify-186-current-worker-capability-recovered-memory96-",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix));
    payload
        || named
        || name == super::super::input161::UNIT
        || name == super::super::input161_retry4::UNIT
        || name == super::super::input161_retry5::UNIT
        || name == super::super::input161_retry6::UNIT
        || name == super::super::input161_retry7::UNIT
        || name == super::super::input161_retry6::atomic::CONTROL
        || name == super::super::input161_retry7::atomic::CONTROL
        || name == crate::charge136_retry0002_lifecycle::joint_startup::UNIT
        || name == crate::charge136_retry0002_lifecycle::joint_startup::FIXTURE_UNIT
        || name == crate::charge136_retry0003_lifecycle::joint_startup::UNIT
        || name == crate::charge136_retry0003_lifecycle::joint_startup::FIXTURE_UNIT
        || name == crate::charge136_retry0004_lifecycle::joint_startup::UNIT
        || name == crate::charge136_retry0005_lifecycle::joint_startup::UNIT
        || name == crate::charge136_retry0004_lifecycle::joint_startup::FIXTURE_UNIT
        || name == crate::charge136_retry0005_lifecycle::joint_startup::FIXTURE_UNIT
        || name == metadata159_pool::UNIT
        || command.contains(metadata159_pool::IMAGE)
        || name == trial_descriptor::ROOT128_MEMORY96.guard_unit
        || name == trial_descriptor::RECOVERED_MEMORY96.guard_unit
}

#[cfg(test)]
#[test]
fn root128_discovery_requires_allocation_even_under_a_different_service_name() {
    assert!(requires_typed_allocation(
        "private-fixture.service",
        "/sealed/jetstreamer-epoch186-root128-trial /sealed/plan.json"
    ));
    assert!(requires_typed_allocation(
        "horizon-qualify-186-current-worker-capability-root128-memory160-20261028-v1.service",
        "/unknown-payload"
    ));
    assert!(requires_typed_allocation(
        "legacy-fixture.service",
        "/sealed/jetstreamer-epoch186-current-worker-trial /sealed/plan.json"
    ));
    assert!(!requires_typed_allocation(
        "unrelated.service",
        "/usr/bin/unrelated"
    ));
}

fn discovered_owner_authenticated(
    expected: &[core::Owner],
    helper_name: &str,
    helper: &Value,
    peers: &[Value],
    supervisor: Option<&Value>,
    name: &str,
    iid: &str,
) -> bool {
    expected.iter().any(|o| o.unit == name && o.iid == iid)
        || supervisor.is_some_and(|p| p["unit"] == name && p["invocation_id"] == iid)
        || (name == helper_name && helper["invocation_id"] == iid)
        || peers
            .iter()
            .any(|p| p["unit"] == name && p["invocation_id"] == iid)
}

// Only the successfully authenticated discovery result reaches this boundary.
// Keep its exact current actors in both native scans without inventing claims.
fn include_authenticated_discovery_names(
    names: &mut BTreeSet<String>,
    discovery: &Value,
) -> Result<()> {
    names.extend(
        discovery
            .as_object()
            .context("authenticated workload discovery census")?
            .keys()
            .cloned(),
    );
    Ok(())
}

/// Discover active transport, input, compilation and replay workloads even when
/// their names were already present in the old complete fleet. Membership in a
/// selected namespace never exempts an unfamiliar payload from accounting.
fn complete_workload_discovery(
    expected: &[core::Owner],
    helper: &Value,
    peers: &[Value],
    memory96_guard: Option<&Value>,
    metadata159: Option<&Value>,
    cold185_current: Option<&Value>,
    live145_current: Option<&Value>,
) -> Result<(Value, Vec<Value>)> {
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running,activating",
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16 << 20,
        "accounting native discovery failed"
    );
    let discovered = io::unique_json(&out.stdout)?;
    let mut observed = BTreeMap::new();
    let mut cold185_guards = Vec::new();
    let helper_name = string(helper, "/unit")?;
    for row in discovered
        .as_array()
        .context("complete workload discovery array")?
    {
        let name = string(row, "/unit")?;
        if trial_guard_pool::discovered(name, memory96_guard)? {
            continue;
        }
        let native = io::properties(name)?;
        let command = string(&native, "/ExecStart")?;
        if live145_prefix::guard_discovered(name, &native, live145_current)? {
            observed.insert(name.to_owned(), native);
            continue;
        }
        if let Some(current) = cold185_current
            && let Some(proof) = crate::fleet::cold185::native::authenticate_guard_discovery(
                current,
                name,
                &native,
                now()?,
            )?
        {
            cold185_guards.push(proof);
            observed.insert(name.to_owned(), native);
            continue;
        }
        if super::super::durable_prefix141::covered(name, peers, &native)? {
            observed.insert(name.to_owned(), native);
            continue;
        }
        if !(requires_typed_allocation(name, command) || name == helper_name) {
            continue;
        }
        let iid = string(&native, "/InvocationID")?;
        let startup_supervisor =
            if name == crate::charge136_retry0004_lifecycle::joint_startup::UNIT {
                crate::charge136_retry0004_lifecycle::joint_startup::allocation()?
            } else if name == crate::charge136_retry0005_lifecycle::joint_startup::UNIT {
                crate::charge136_retry0005_lifecycle::joint_startup::allocation()?
            } else if name == crate::charge136_retry0003_lifecycle::joint_startup::UNIT {
                crate::charge136_retry0003_lifecycle::joint_startup::allocation()?
            } else if name == crate::charge136_retry0003_lifecycle::joint_startup::FIXTURE_UNIT {
                crate::charge136_retry0003_lifecycle::joint_startup::fixture_allocation()?
            } else if name == crate::charge136_retry0004_lifecycle::joint_startup::FIXTURE_UNIT {
                crate::charge136_retry0004_lifecycle::joint_startup::fixture_allocation()?
            } else if name == crate::charge136_retry0005_lifecycle::joint_startup::FIXTURE_UNIT {
                crate::charge136_retry0005_lifecycle::joint_startup::fixture_allocation()?
            } else if name == crate::charge136_retry0002_lifecycle::joint_startup::UNIT {
                crate::charge136_retry0002_lifecycle::joint_startup::allocation()?
            } else if name == crate::charge136_retry0002_lifecycle::joint_startup::FIXTURE_UNIT {
                crate::charge136_retry0002_lifecycle::joint_startup::fixture_allocation()?
            } else {
                None
            };
        let supervisor = if name == super::super::charge136::admission::FOREMAN {
            super::super::charge136::supervisor_allocation()?
        } else if name == super::super::charge136_retry0003::admission::FOREMAN {
            super::super::charge136_retry0003::supervisor_allocation()?
        } else if name == super::super::charge136_retry0004::admission::FOREMAN {
            super::super::charge136_retry0004::supervisor_allocation()?
        } else if name == super::super::charge136_retry0005::admission::FOREMAN {
            super::super::charge136_retry0005::supervisor_allocation()?
        } else if name == super::super::charge136_retry0002::admission::FOREMAN {
            super::super::charge136_retry0002::supervisor_allocation()?
        } else if name == super::super::input161_retry7::atomic::CONTROL {
            super::super::input161_retry7::atomic::allocation()?
        } else if name == super::super::input161_retry6::atomic::CONTROL {
            super::super::input161_retry6::atomic::allocation()?
        } else if name == super::super::suffix154_admission::contract::CONTROL {
            super::super::suffix154::control_allocation()?
        } else {
            None
        };
        let supervisor = startup_supervisor.or(supervisor).or_else(|| {
            metadata159
                .filter(|p| p["unit"] == name && p["invocation_id"] == iid)
                .cloned()
        });
        let authenticated = discovered_owner_authenticated(
            expected,
            helper_name,
            helper,
            peers,
            supervisor.as_ref(),
            name,
            iid,
        );
        ensure!(
            authenticated,
            "unsupported actual workload requires an exact typed allocation: {name}"
        );
        observed.insert(name.to_owned(), native);
    }
    // A periodic fire must not change discovery membership. Both raw states
    // survive in the report; only authenticated comparison views vary.
    if live145_current.is_some() && !observed.contains_key(live145_prefix::GUARD) {
        let native = io::properties(live145_prefix::GUARD)?;
        ensure!(live145_prefix::guard_discovered(live145_prefix::GUARD, &native, live145_current)?,
            "live145 periodic guard lacks its typed live owner");
        observed.insert(live145_prefix::GUARD.to_owned(), native);
    }
    Ok((serde_json::to_value(observed)?, cold185_guards))
}

// Keep full native limit evidence separate from the legacy fleet census, whose
// exact row shape remains an independently authenticated compatibility boundary.
fn owner_hard_limits(expected: &[core::Owner]) -> Result<BTreeMap<String, Value>> {
    let mut rows = BTreeMap::new();
    for owner in expected {
        let native = io::properties(&owner.unit)?;
        ensure!(
            native["Id"] == owner.unit
                && native["InvocationID"] == owner.iid
                && native["MainPID"]
                    .as_str()
                    .context("hard-limit native PID")?
                    == owner.pid.to_string()
                && native["NRestarts"] == "0"
                && native["MemoryMax"].is_string()
                && native["MemorySwapMax"].is_string(),
            "current hard-limit owner identity or native fields changed: {}",
            owner.unit
        );
        ensure!(
            rows.insert(owner.unit.clone(), native).is_none(),
            "duplicate hard-limit owner"
        );
    }
    Ok(rows)
}

/// Derive a current source-bound DATA/pool view. Two finite native passes and
/// source revalidation are part of this transaction, not a new observer cadence.
/// This returns facts only; the caller must independently admit its exact task.
pub(crate) async fn protected_data_basis(spec: &Value, now_unix_seconds: u64) -> Result<Value> {
    protected_data_basis_inner(spec, now_unix_seconds, None).await
}
pub(super) async fn protected_data_basis_trace136(
    spec: &Value,
    clock: u64,
    saved: &jetstreamer_horizon_observe::trace136_saved_overlap::SavedTrace136Overlap,
) -> Result<Value> {
    protected_data_basis_inner(spec, clock, Some(saved)).await
}
async fn protected_data_basis_inner(
    spec: &Value,
    now_unix_seconds: u64,
    trace: Option<&jetstreamer_horizon_observe::trace136_saved_overlap::SavedTrace136Overlap>,
) -> Result<Value> {
    let s: Sources = serde_json::from_value(spec.clone())?;
    ensure!(
        s.schema == SOURCE_SCHEMA,
        "accounting source-selector schema differs"
    );
    let current_time = now()?;
    ensure!(
        now_unix_seconds <= current_time && current_time - now_unix_seconds <= 30,
        "accounting transaction clock is stale or future"
    );
    let loaded = Loaded::read(&s)?;
    if let Some(trace) = trace {
        let b = |v: &BoundFile| jetstreamer_horizon_observe::trial186::Bound {
            path: v.path.clone(),
            sha256: v.sha256.clone(),
        };
        trace.require_frame(
            &b(&s.observer),
            &b(&s.fleet),
            &b(&s.completion),
            &b(&s.resource_parent),
        )?;
    }
    let view = SpecView::from(&s);
    let bundle = loaded.view();
    let terminal199_context = crate::fleet::ordinary199::terminal_context(&loaded.fleet_plan)?;
    let original199_native_before = terminal199_context
        .as_ref()
        .map(crate::fleet::terminal199_memory::current_native)
        .transpose()?;
    let original199_discovery_before = original199_native_before
        .as_ref()
        .map(crate::fleet::terminal199_memory::discovery);
    let cold185_before = cold185::actual(&loaded.fleet_plan, now()?)?;
    let cold185_peers_before = cold185::peers(cold185_before.as_ref())?;
    let sampled = cold185::accepted_basis(&view, &bundle, cold185_before.as_ref(), current_time)?;
    io::latest(&view, &bundle)?;
    let expected = evidence::owners_basis(&view, &bundle)?;
    let terminal_before = retained_terminal_native(&loaded.fleet)?;
    let helper_before = helper_allocation()?;
    let metadata159_before = metadata159_pool::actual(s.metadata159_native_pool.as_ref())?;
    let epoch137_before =
        super::super::epoch137_input::pool::actual(s.epoch137_input_pool.as_ref())?;
    let peer_before = super::super::input136::actual_allocation(&loaded.fleet)?;
    let peer161_retry5_before = super::super::input161_retry5::actual_allocation(&loaded.fleet)?;
    let peer161_retry6_before = super::super::input161_retry6::actual_allocation(&loaded.fleet)?;
    let peer161_retry7_before = super::super::input161_retry7::actual_allocation(&loaded.fleet)?;
    let cached145_before = super::super::cached145_allocation::allocations(&loaded.fleet)?;
    let live145_before = live145_prefix::actual(s.live145_prefix_export.as_ref(), now()?)?;
    live145_prefix::disjoint(live145_before.as_ref(), &expected, &s.guards)?;
    live145_prefix::candidate_fit(cold185_before.as_ref(), live145_before.as_ref(), &loaded.observer)?;
    let live145_peers_before = live145_prefix::peers(live145_before.as_ref());
    let retained145_guard_before = retained_cached145_guard::actual(
        s.retained_cached145_guard.as_ref(),
        &s.guards,
        &s.phase_events,
        &loaded.fleet,
        &loaded.observer,
        &cached145_before,
        &expected,
    )?;
    let direct163_before = super::super::direct163::allocation(&loaded.fleet_plan)?;
    let recovery199_before =
        super::super::recovery199::accounting::allocations(&loaded.fleet_plan)?;
    let input137_before = super::super::epoch137_input::retained::actual()?;
    let (peer161_before, peer161_retry4_before) =
        super::super::input161_retry4::retry::allocations(&loaded.fleet)?;
    let trial_before = trial_peer::actual(
        &loaded.fleet,
        &loaded.fleet_plan,
        s.retained_trial186.as_ref(),
    )?;
    let root128_before = trial_root128_peer::actual(&loaded.fleet_plan)?;
    let root96_before = trial_root128_memory96_peer::actual(&loaded.fleet_plan)?;
    let recovered96_before = trial_recovered_memory96_peer::actual(&loaded.fleet_plan)?;
    let memory96_guard_before =
        trial_guard_pool::actual(root96_before.as_ref(), recovered96_before.as_ref())?;
    let suffix_before = super::super::suffix136::actual()?;
    let charge_before = super::super::charge136::actual()?;
    let retry0002_before = super::super::charge136_retry0002::actual()?;
    let retry0003_before = super::super::charge136_retry0003::actual()?;
    let retry0004_before = super::super::charge136_retry0004::actual()?;
    let retry0005_before = super::super::charge136_retry0005::actual()?;
    let suffix154_before = super::super::suffix154::actual()?;
    let durable141_before = super::super::durable_prefix141::allocation()?;
    let artifact154_before = artifact154_peers::actual(&loaded.fleet)?;
    let retained_before = retained136_growth::accounted(
        s.retained_suffix136.as_ref(),
        s.retained_suffix136_growth_closure.as_ref(),
    )?;
    let retained_v2_before = retained136_v2_growth::accounted(
        s.retained_suffix136_v2.as_ref(),
        s.retained_suffix136_v2_growth_closure.as_ref(),
    )?;
    let retained_v3_before = retained136_v3_growth::accounted(
        s.retained_suffix136_v3.as_ref(),
        s.retained_suffix136_v3_growth_closure.as_ref(),
    )?;
    let retained_v4_before = retained_suffix136_v4::actual(s.retained_suffix136_v4.as_ref())?;
    let retained_v5_before = retained_suffix136_v5::actual(s.retained_suffix136_v5.as_ref())?;
    let retained_v7_before = retained136_v7_growth::accounted(
        s.retained_suffix136_v7.as_ref(),
        s.retained_suffix136_v7_growth_closure.as_ref(),
    )?;
    let retained_v8_before = retained_suffix136_v8::actual(s.retained_suffix136_v8.as_ref())?;
    let suffix_before = disjoint_current_suffix(suffix_before, retained_v8_before.as_ref())?;
    let peers_before = peer_before
        .iter()
        .chain(peer161_before.iter())
        .chain(peer161_retry4_before.iter())
        .chain(peer161_retry5_before.iter())
        .chain(peer161_retry6_before.iter())
        .chain(peer161_retry7_before.iter())
        .chain(cached145_before.iter())
        .chain(live145_peers_before.iter())
        .chain(direct163_before.iter())
        .chain(cold185_peers_before.iter())
        .chain(recovery199_before.iter())
        .chain(input137_before.iter())
        .chain(trial_before.iter())
        .chain(root128_before.iter())
        .chain(root96_before.iter())
        .chain(recovered96_before.iter())
        .chain(suffix_before.iter())
        .chain(charge_before.iter())
        .chain(retry0002_before.iter())
        .chain(retry0003_before.iter())
        .chain(retry0004_before.iter())
        .chain(retry0005_before.iter())
        .chain(suffix154_before.iter())
        .chain(durable141_before.iter())
        .chain(artifact154_before.iter())
        .chain(retained_before.row.iter())
        .chain(retained_v2_before.row.iter())
        .chain(retained_v3_before.row.iter())
        .chain(retained_v4_before.iter())
        .chain(retained_v5_before.iter())
        .chain(retained_v7_before.row.iter())
        .chain(retained_v8_before.iter())
        .cloned()
        .collect::<Vec<_>>();
    let guard_policy =
        guard_continuity::Policy::new(&s.guards, &expected, &helper_before, &peers_before)?;
    let mut original199_discovery_peers_before = peers_before.clone();
    original199_discovery_peers_before.extend(original199_discovery_before.iter().cloned());
    let (discovery_before, cold185_discovery_before) = complete_workload_discovery(
        &expected,
        &helper_before,
        &original199_discovery_peers_before,
        memory96_guard_before.as_ref(),
        metadata159_before.as_ref(),
        cold185_before.as_ref(),
        live145_before.as_ref(),
    )?;
    let mut names = loaded.fleet["unit_census"]
        .as_object()
        .context("complete accepted native census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.extend(expected.iter().map(|o| o.unit.clone()));
    names.extend(s.guards.iter().map(|g| g.unit.clone()));
    names.insert(string(&helper_before, "/unit")?.into());
    for peer in &peers_before {
        names.insert(string(peer, "/unit")?.into());
    }
    if let Some(guard) = &memory96_guard_before {
        names.insert(string(guard, "/unit")?.into());
    }
    include_authenticated_discovery_names(&mut names, &discovery_before)?;
    if live145_before.is_some() {
        names.insert(live145_prefix::GUARD.into());
        names.insert(live145_prefix::TIMER.into());
    }
    let (owners_before, mut native_before, cpu_before) =
        io::observed_accounting(&expected, &names, &loaded.fleet)?;
    let cpu_before = cpu_before
        .checked_add(cold185::cpu_quota(cold185_before.as_ref())?)
        .and_then(|n| n.checked_add(live145_prefix::cpu(live145_before.as_ref())))
        .context("cold185 complete replay CPU sum overflow")?;
    let hard_limits_before = owner_hard_limits(&expected)?;
    let coordinator_before =
        super::super::charge136::admission::terminal_legacy_memory::compare_then_enrich_native_census(
            &mut native_before,
            |ordinary| io::completed_coordinator_basis(&view, &bundle, ordinary),
        )?;
    let (guards_before, guard_native_before) = io::accounting_guards(&view, &expected, now()?)?;
    let guard_maximum = guard_coverage(&expected, &guards_before)?
        .max(super::super::direct163::guard_floor(&direct163_before)?)
        .max(cold185::guard_floor(cold185_before.as_ref())?)
        .max(
            retained145_guard_before
                .as_ref()
                .map(|v| v.floor_bytes)
                .unwrap_or(0),
        )
        .max(super::super::recovery199::accounting::guard_floor(
            &recovery199_before,
        )?)
        .max(
            memory96_guard_before
                .as_ref()
                .map(|guard| number(guard, "/floor_bytes"))
                .transpose()?
                .unwrap_or(0),
        );
    let guard_maximum = guard_maximum.max(live145_prefix::guard_floor(live145_before.as_ref()));
    let floor_bytes = snapshot144::floor(&loaded.floor)?;
    let (rows, dispositions) = evidence::obligations_basis(&view, &bundle, floor_bytes)?;
    let (mut rows, _) = core::project_obligations(&rows, &dispositions)?;
    let original_standing = number(&loaded.standing, "/retained_promises/initial_total_bytes")?;
    let closure141 = s
        .original141_growth_closure
        .as_ref()
        .map(|b| crate::original141_growth_closure::select(&b.path, &b.sha256))
        .transpose()?;
    let (mut standing, mut confirmed) = if let Some(validated) = &closure141 {
        let mut selected = 0usize;
        for row in &mut rows {
            if validated.close_claim(
                &row.claim_key,
                row.epoch,
                &row.producer_invocation_id,
                row.outstanding_bytes,
            )? {
                row.outstanding_bytes = 0;
                selected += 1;
            }
        }
        ensure!(
            selected == 1,
            "original 141 closure omitted or duplicated its claim"
        );
        (
            validated.frontier(original_standing)?,
            validated.frontier(DATA_FLOOR)?,
        )
    } else {
        (original_standing, DATA_FLOOR)
    };
    let closure155156 = s
        .terminal155156_growth_closure
        .as_ref()
        .map(|b| terminal155156_growth::select(&b.path, &b.sha256))
        .transpose()?;
    if let Some(validated) = &closure155156 {
        let mut selected = 0usize;
        for row in &mut rows {
            if validated.close_claim(
                &row.claim_key,
                row.epoch,
                &row.producer_invocation_id,
                row.outstanding_bytes,
            )? {
                row.outstanding_bytes = 0;
                selected += 1;
            }
        }
        ensure!(
            selected == 1,
            "terminal155156 closure omitted or duplicated its exact claim"
        );
        standing = validated.frontier(standing)?;
        confirmed = validated.frontier(confirmed)?;
    }
    let closure152153 = s
        .terminal152153_growth_closure
        .as_ref()
        .map(|b| terminal152153_growth::select(&b.path, &b.sha256))
        .transpose()?;
    if let Some(validated) = &closure152153 {
        let mut selected = 0usize;
        for row in &mut rows {
            if validated.close_claim(
                &row.claim_key,
                row.epoch,
                &row.producer_invocation_id,
                row.outstanding_bytes,
            )? {
                row.outstanding_bytes = 0;
                selected += 1;
            }
        }
        ensure!(
            selected == 1,
            "terminal152153 closure omitted or duplicated its exact claim"
        );
        standing = validated.frontier(standing)?;
        confirmed = validated.frontier(confirmed)?;
    }
    let (projected, original_protected) = protect_with_growth_v7(
        &rows,
        standing,
        guard_maximum,
        &peers_before,
        retained_before.validated.as_ref(),
        retained_v2_before.validated.as_ref(),
        (
            retained_v3_before.validated.as_ref(),
            retained_v7_before.validated.as_ref(),
        ),
    )?;
    let protected = if closure141.is_some() || closure155156.is_some() || closure152153.is_some() {
        adjusted_protection(&rows, &projected, standing, confirmed, guard_maximum)?
    } else {
        original_protected
    };
    let protected = live145_prefix::retained_data_floor(protected, live145_before.as_ref())?;
    let mut bindings = source_bindings(&s);
    for proof in loaded.floor["samples"]
        .as_array()
        .context("century floor sample proofs")?
    {
        for (path, sha) in [
            ("r2_receipt", "r2_receipt_sha256"),
            (
                "private_resource_verification",
                "private_resource_verification_sha256",
            ),
        ] {
            let file = BoundFile {
                path: string(proof, &format!("/{path}"))?.into(),
                sha256: string(proof, &format!("/{sha}"))?.into(),
            };
            read_source(
                "floor sample proof",
                &file,
                historical_generated::floor_proof,
            )?;
            bindings.push(binding(&file));
        }
    }
    let r2 = r2_config_from_env()?;
    ensure!(
        r2.bucket == "solana-archive-with-accounts-data",
        "foreign accounting floor inventory"
    );
    let client = s3_client(&r2);
    let floor_inventory =
        assembly144_admission::remote_floor_inventory(&client, &r2, &loaded.floor).await?;
    let mut pool_before = pool_rows(
        &expected,
        &helper_before,
        peer_before.as_ref(),
        super::super::suffix136::guard_allocation()?.as_ref(),
        memory96_guard_before.as_ref(),
    )?;
    pool_before.extend(artifact154_before.iter().cloned());
    pool_before.extend(metadata159_before.iter().cloned());
    pool_before.extend(input137_before.iter().cloned());
    pool_before.extend(epoch137_before.iter().cloned());
    validate_pool(&pool_before)?;
    pool_before.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    if let Some(peer) = &peer161_before
        && number(peer, "/memory_max_bytes")? > 0
    {
        pool_before.push(peer.clone());
        validate_pool(&pool_before)?;
        pool_before.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    }
    if let Some(peer) = &peer161_retry4_before
        && number(peer, "/memory_max_bytes")? > 0
    {
        pool_before.push(peer.clone());
        validate_pool(&pool_before)?;
        pool_before.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    }
    if let Some(peer) = &peer161_retry7_before
        && number(peer, "/memory_max_bytes")? > 0
    {
        pool_before.push(peer.clone());
        validate_pool(&pool_before)?;
        pool_before.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    }
    if let Some(peer) = &peer161_retry6_before
        && number(peer, "/memory_max_bytes")? > 0
    {
        pool_before.push(peer.clone());
        validate_pool(&pool_before)?;
        pool_before.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    }
    if let Some(peer) = &peer161_retry5_before
        && number(peer, "/memory_max_bytes")? > 0
    {
        pool_before.push(peer.clone());
        validate_pool(&pool_before)?;
        pool_before.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    }
    let committed = validate_pool(&pool_before)?;
    for peer in &peers_before {
        bindings.extend(
            peer["source_bindings"]
                .as_array()
                .context("authenticated peer source bindings")?
                .iter()
                .cloned(),
        );
    }
    bindings.extend(cold185::guard_sources(cold185_before.as_ref())?);
    if let Some(retained) = &retained145_guard_before {
        bindings.extend(retained.sources.iter().cloned());
    }
    if let Some(guard) = &memory96_guard_before {
        bindings.extend(
            guard["source_bindings"]
                .as_array()
                .context("memory96 qualified guard sources")?
                .iter()
                .cloned(),
        );
    }
    // Re-read every byte-bound source, not just a caller-supplied completeness flag.
    let reread = Loaded::read(&s)?;
    ensure!(reread == loaded, "bound accounting source changed");
    for file in bindings
        .iter()
        .filter(|v| v["path"].as_str().is_some_and(|p| p.ends_with(".json")))
    {
        let bound: BoundFile = serde_json::from_value(file.clone())?;
        protected_generated(&bound)?;
    }
    let again = reread.view();
    if let Some(bound) = &s.original141_growth_closure {
        crate::original141_growth_closure::select(&bound.path, &bound.sha256)?;
    }
    if let Some(bound) = &s.terminal155156_growth_closure {
        terminal155156_growth::select(&bound.path, &bound.sha256)?;
    }
    if let Some(bound) = &s.terminal152153_growth_closure {
        terminal152153_growth::select(&bound.path, &bound.sha256)?;
    }
    let cold185_after = cold185::actual(&reread.fleet_plan, now()?)?;
    cold185::stable(cold185_before.as_ref(), cold185_after.as_ref())?;
    let cold185_peers_after = cold185::peers(cold185_after.as_ref())?;
    cold185::accepted_basis(&view, &again, cold185_after.as_ref(), now()?)?;
    io::latest(&view, &again)?;
    let owners_after = evidence::owners_basis(&view, &again)?;
    ensure!(
        owners_after == expected,
        "source-derived owner census changed"
    );
    let terminal_after = retained_terminal_native(&reread.fleet)?;
    let helper_after = helper_allocation()?;
    let metadata159_after = metadata159_pool::actual(s.metadata159_native_pool.as_ref())?;
    let epoch137_after =
        super::super::epoch137_input::pool::actual(s.epoch137_input_pool.as_ref())?;
    let peer_after = super::super::input136::actual_allocation(&reread.fleet)?;
    let peer161_retry5_after = super::super::input161_retry5::actual_allocation(&reread.fleet)?;
    let peer161_retry6_after = super::super::input161_retry6::actual_allocation(&reread.fleet)?;
    let peer161_retry7_after = super::super::input161_retry7::actual_allocation(&reread.fleet)?;
    let cached145_after = super::super::cached145_allocation::allocations(&reread.fleet)?;
    let live145_after = live145_prefix::actual(s.live145_prefix_export.as_ref(), now()?)?;
    live145_prefix::stable(live145_before.as_ref(), live145_after.as_ref())?;
    live145_prefix::candidate_fit(cold185_after.as_ref(), live145_after.as_ref(), &reread.observer)?;
    let live145_peers_after = live145_prefix::peers(live145_after.as_ref());
    let retained145_guard_after = retained_cached145_guard::actual(
        s.retained_cached145_guard.as_ref(),
        &s.guards,
        &s.phase_events,
        &reread.fleet,
        &reread.observer,
        &cached145_after,
        &expected,
    )?;
    ensure!(
        retained145_guard_before == retained145_guard_after,
        "retained cached145 guard/floor/source/native changed during accounting"
    );
    let direct163_after = super::super::direct163::allocation(&reread.fleet_plan)?;
    let recovery199_after = super::super::recovery199::accounting::allocations(&reread.fleet_plan)?;
    let input137_after = super::super::epoch137_input::retained::actual()?;
    let (peer161_after, peer161_retry4_after) =
        super::super::input161_retry4::retry::allocations(&reread.fleet)?;
    let trial_after = trial_peer::actual(
        &reread.fleet,
        &reread.fleet_plan,
        s.retained_trial186.as_ref(),
    )?;
    let root128_after = trial_root128_peer::actual(&reread.fleet_plan)?;
    let root96_after = trial_root128_memory96_peer::actual(&reread.fleet_plan)?;
    let recovered96_after = trial_recovered_memory96_peer::actual(&reread.fleet_plan)?;
    let memory96_guard_after =
        trial_guard_pool::actual(root96_after.as_ref(), recovered96_after.as_ref())?;
    let suffix_after = super::super::suffix136::actual()?;
    let charge_after = super::super::charge136::actual()?;
    let retry0002_after = super::super::charge136_retry0002::actual()?;
    let retry0003_after = super::super::charge136_retry0003::actual()?;
    let retry0004_after = super::super::charge136_retry0004::actual()?;
    let retry0005_after = super::super::charge136_retry0005::actual()?;
    let suffix154_after = super::super::suffix154::actual()?;
    let durable141_after = super::super::durable_prefix141::allocation()?;
    let artifact154_after = artifact154_peers::actual(&reread.fleet)?;
    let retained_after = retained136_growth::accounted(
        s.retained_suffix136.as_ref(),
        s.retained_suffix136_growth_closure.as_ref(),
    )?;
    let retained_v2_after = retained136_v2_growth::accounted(
        s.retained_suffix136_v2.as_ref(),
        s.retained_suffix136_v2_growth_closure.as_ref(),
    )?;
    let retained_v3_after = retained136_v3_growth::accounted(
        s.retained_suffix136_v3.as_ref(),
        s.retained_suffix136_v3_growth_closure.as_ref(),
    )?;
    let retained_v4_after = retained_suffix136_v4::actual(s.retained_suffix136_v4.as_ref())?;
    let retained_v5_after = retained_suffix136_v5::actual(s.retained_suffix136_v5.as_ref())?;
    let retained_v7_after = retained136_v7_growth::accounted(
        s.retained_suffix136_v7.as_ref(),
        s.retained_suffix136_v7_growth_closure.as_ref(),
    )?;
    let retained_v8_after = retained_suffix136_v8::actual(s.retained_suffix136_v8.as_ref())?;
    let suffix_after = disjoint_current_suffix(suffix_after, retained_v8_after.as_ref())?;
    let original199_native_after = terminal199_context
        .as_ref()
        .map(crate::fleet::terminal199_memory::current_native)
        .transpose()?;
    let original199_discovery_after = original199_native_after
        .as_ref()
        .map(crate::fleet::terminal199_memory::discovery);
    let peers_after = peer_after
        .iter()
        .chain(peer161_after.iter())
        .chain(peer161_retry4_after.iter())
        .chain(peer161_retry5_after.iter())
        .chain(peer161_retry6_after.iter())
        .chain(peer161_retry7_after.iter())
        .chain(cached145_after.iter())
        .chain(live145_peers_after.iter())
        .chain(direct163_after.iter())
        .chain(cold185_peers_after.iter())
        .chain(recovery199_after.iter())
        .chain(input137_after.iter())
        .chain(trial_after.iter())
        .chain(root128_after.iter())
        .chain(root96_after.iter())
        .chain(recovered96_after.iter())
        .chain(suffix_after.iter())
        .chain(charge_after.iter())
        .chain(retry0002_after.iter())
        .chain(retry0003_after.iter())
        .chain(retry0004_after.iter())
        .chain(retry0005_after.iter())
        .chain(suffix154_after.iter())
        .chain(durable141_after.iter())
        .chain(artifact154_after.iter())
        .chain(retained_after.row.iter())
        .chain(retained_v2_after.row.iter())
        .chain(retained_v3_after.row.iter())
        .chain(retained_v4_after.iter())
        .chain(retained_v5_after.iter())
        .chain(retained_v7_after.row.iter())
        .chain(retained_v8_after.iter())
        .cloned()
        .collect::<Vec<_>>();
    let mut original199_discovery_peers_after = peers_after.clone();
    original199_discovery_peers_after.extend(original199_discovery_after.iter().cloned());
    let (discovery_after, cold185_discovery_after) = complete_workload_discovery(
        &owners_after,
        &helper_after,
        &original199_discovery_peers_after,
        memory96_guard_after.as_ref(),
        metadata159_after.as_ref(),
        cold185_after.as_ref(),
        live145_after.as_ref(),
    )?;
    let mut pool_after = pool_rows(
        &owners_after,
        &helper_after,
        peer_after.as_ref(),
        super::super::suffix136::guard_allocation()?.as_ref(),
        memory96_guard_after.as_ref(),
    )?;
    pool_after.extend(artifact154_after.iter().cloned());
    pool_after.extend(metadata159_after.iter().cloned());
    pool_after.extend(input137_after.iter().cloned());
    pool_after.extend(epoch137_after.iter().cloned());
    validate_pool(&pool_after)?;
    pool_after.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    if let Some(peer) = &peer161_after
        && number(peer, "/memory_max_bytes")? > 0
    {
        pool_after.push(peer.clone());
        validate_pool(&pool_after)?;
        pool_after.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    }
    if let Some(peer) = &peer161_retry4_after
        && number(peer, "/memory_max_bytes")? > 0
    {
        pool_after.push(peer.clone());
        validate_pool(&pool_after)?;
        pool_after.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    }
    if let Some(peer) = &peer161_retry7_after
        && number(peer, "/memory_max_bytes")? > 0
    {
        pool_after.push(peer.clone());
        validate_pool(&pool_after)?;
        pool_after.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    }
    if let Some(peer) = &peer161_retry6_after
        && number(peer, "/memory_max_bytes")? > 0
    {
        pool_after.push(peer.clone());
        validate_pool(&pool_after)?;
        pool_after.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    }
    if let Some(peer) = &peer161_retry5_after
        && number(peer, "/memory_max_bytes")? > 0
    {
        pool_after.push(peer.clone());
        validate_pool(&pool_after)?;
        pool_after.sort_by(|a, b| a["unit"].as_str().cmp(&b["unit"].as_str()));
    }
    let (observed_after, mut native_after, cpu_after) =
        io::observed_accounting(&expected, &names, &reread.fleet)?;
    let cpu_after = cpu_after
        .checked_add(cold185::cpu_quota(cold185_after.as_ref())?)
        .and_then(|n| n.checked_add(live145_prefix::cpu(live145_after.as_ref())))
        .context("cold185 complete replay CPU sum overflow")?;
    let hard_limits_after = owner_hard_limits(&expected)?;
    let coordinator_after =
        super::super::charge136::admission::terminal_legacy_memory::compare_then_enrich_native_census(
            &mut native_after,
            |ordinary| io::completed_coordinator_basis(&view, &again, ordinary),
        )?;
    let (guards_after, guard_native_after) = io::accounting_guards(&view, &expected, now()?)?;
    let memory96_guard_renewal = trial_guard_pool::compare(
        memory96_guard_before.as_ref(),
        memory96_guard_after.as_ref(),
    )?;
    let pool_compare_before =
        trial_guard_pool::without_pool(&pool_before, memory96_guard_before.as_ref())?;
    let pool_compare_after =
        trial_guard_pool::without_pool(&pool_after, memory96_guard_after.as_ref())?;
    let native_compare_before =
        trial_guard_pool::without_native(&json!(native_before), memory96_guard_before.as_ref())?;
    let native_compare_after =
        trial_guard_pool::without_native(&json!(native_after), memory96_guard_after.as_ref())?;
    // The trace96 candidate path cannot already contain the candidate's own
    // live guard. Generic later accounting handles its independently typed row.
    ensure!(
        trace.is_none() || memory96_guard_before.is_none(),
        "trace96 candidate already has an installed memory96 guard"
    );
    let renewal = trace
        .map(|_| {
            trace136_guard_renewal::compare(
                &json!(peers_before),
                &json!(peers_after),
                &json!(pool_before),
                &json!(pool_after),
            )
        })
        .transpose()?;
    let (comparison_before, comparison_after) = if trace.is_some() {
        trace136_guard_renewal::native_census(
            &native_compare_before,
            &native_compare_after,
            &json!(pool_before),
            &json!(pool_after),
        )?
    } else {
        (native_compare_before, native_compare_after)
    };
    let (comparison_before, comparison_after) = super::super::direct163::comparison_census(
        &loaded.fleet_plan,
        &comparison_before,
        &comparison_after,
    )?;
    let (comparison_before, comparison_after) = cold185_rollover::comparison_census(
        cold185_before.as_ref(),
        cold185_after.as_ref(),
        &comparison_before,
        &comparison_after,
    )?;
    let comparison_before = live145_prefix::comparison(&comparison_before, live145_before.as_ref())?;
    let comparison_after = live145_prefix::comparison(&comparison_after, live145_after.as_ref())?;
    let guard_result = guard_policy.compare(
        &serde_json::to_value(&guards_before)?,
        &serde_json::to_value(&guards_after)?,
        &json!(guard_native_before),
        &json!(guard_native_after),
        &comparison_before,
        &comparison_after,
    );
    let discovery_comparison_before = cold185_rollover::discovery_view(
        &discovery_before,
        cold185_before.as_ref(),
        &cold185_discovery_before,
    )?;
    let discovery_comparison_after = cold185_rollover::discovery_view(
        &discovery_after,
        cold185_after.as_ref(),
        &cold185_discovery_after,
    )?;
    let discovery_comparison_before = live145_prefix::comparison(&discovery_comparison_before, live145_before.as_ref())?;
    let discovery_comparison_after = live145_prefix::comparison(&discovery_comparison_after, live145_after.as_ref())?;
    guard_continuity::components(&[
        ("owners", owners_before == observed_after),
        ("native_and_guards", guard_result.is_ok()),
        ("hard_limits", hard_limits_before == hard_limits_after),
        ("cpu_quota", cpu_before == cpu_after),
        ("terminal144", terminal_before == terminal_after),
        ("helper", helper_before == helper_after),
        ("epoch137_input_control", epoch137_before == epoch137_after),
        (
            "retained136_token",
            retained_before.validated == retained_after.validated,
        ),
        (
            "retained136_v2_token",
            retained_v2_before.validated == retained_v2_after.validated,
        ),
        (
            "peers",
            renewal.is_some()
                || super::super::recovery199::accounting::peers_equal(&peers_before, &peers_after)?,
        ),
        (
            "retained136_v3_token",
            retained_v3_before.validated == retained_v3_after.validated,
        ),
        (
            "retained136_v7_token",
            retained_v7_before.validated == retained_v7_after.validated,
        ),
        (
            "discovery",
            discovery_comparison_before == discovery_comparison_after,
        ),
        (
            "pool",
            renewal.is_some() || pool_compare_before == pool_compare_after,
        ),
    ])
    .with_context(|| {
        guard_result
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "accounting component equality".into())
    })?;
    guard_coverage(&expected, &guards_after)?;
    // Retain both original successful guard receipt bindings in the complete
    // output. They are separate from the stable actor peer custody, and both
    // were authenticated by the exact rollover comparison above.
    bindings.extend(cold185::guard_sources(cold185_after.as_ref())?);
    let mut report = json!({"schema":"jetstreamer-current-protected-data-accounting-v1",
        "observer":binding(&s.observer),"fleet":binding(&s.fleet),"completion":binding(&s.completion),
        "resource_parent":binding(&s.resource_parent),"recorded_unix_seconds":now()?,"sample_unix_seconds":sampled,
        "projected_obligations":projected,"standing_frontier_bytes":standing,
        "inherited_live_guard_maximum_bytes":guard_maximum,"confirmed_DATA_floor_bytes":confirmed,
        "protected_existing_DATA_bytes":protected,"native_pool_bytes":core::NATIVE_POOL,
        "native_pool_suballocations":pool_after,"native_pool_committed_bytes":committed,
        "current_unique_owner_census":observed_after,"native_before":native_before,"native_after":native_after,
        "current_owner_hard_limits":hard_limits_after,
        "retained144_terminal_native":terminal_after,
        "completed_coordinator_before":coordinator_before,"completed_coordinator_after":coordinator_after,
        "source_bindings":bindings,"authenticated_floor_inventory":floor_inventory,
        "current_replay_cpu_quota_micros":cpu_after,"guards":guards_after,
        "guard_native":guard_native_after,
        "retained136_v1_growth_reference_checks":{"before":retained_before.scans,"after":retained_after.scans},
        "retained136_v2_growth_reference_checks":{"before":retained_v2_before.scans,"after":retained_v2_after.scans},
        "retained136_v3_growth_reference_checks":{"before":retained_v3_before.scans,"after":retained_v3_after.scans},
        "retained136_v7_growth_reference_checks":{"before":retained_v7_before.scans,"after":retained_v7_after.scans},
        "retained136_v5_terminal_reference":{"before":retained_v5_before,"after":retained_v5_after},
        "active_peer_allocations":peers_after,"workload_discovery_before":discovery_before,"workload_discovery_after":discovery_after,
        "new_allocation_authorized":false,"physical_retirement_credit_bytes":0,
        "runtime_qualification_claimed":false,"replay_launch_authorized":false,"remote_mutations":false});
    report["live145_prefix_export_before"] = json!(live145_before);
    report["live145_prefix_export_after"] = json!(live145_after);
    report["live145_minimum_available_memory_bytes"] = json!(if live145_after.is_some() { live145_prefix::MEMORY_FLOOR } else { 0 });
    if let Some(actual) = &cold185_after {
        report["cold185_exact_inflight_guard_discovery_before"] = json!(cold185_discovery_before);
        report["cold185_exact_inflight_guard_discovery_after"] = json!(cold185_discovery_after);
        report["cold185_startpre_native_task_before"] =
            cold185_before.clone().context("cold185 before task")?;
        report["cold185_startpre_native_task_after"] = actual.clone();
        report["cold185_current_complete_reader_only"] = json!({
            "registration":actual["registration"],
            "genuine_task_and_native_before_after_revalidated":true,
            "all_original_accounting_families_preserved":true,
            "memory_or_DATA_credit_bytes":0,
            "replay_launch_authorized":false,"publication_authorized":false});
    }
    if let Some(context) = &terminal199_context {
        let selector = loaded.fleet_plan[crate::fleet::ordinary199::TERMINAL_FIELD].clone();
        report["original199_terminal_context"] = selector.clone();
        report["epoch199_promises"] = loaded.fleet["epoch199_promises"].clone();
        report["original199_terminal_native_before"] =
            original199_native_before.context("terminal199 before census")?;
        report["original199_terminal_native_after"] =
            original199_native_after.context("terminal199 after census")?;
        crate::fleet::terminal199_memory::append(
            &mut report,
            &loaded.observer,
            &serde_json::from_value(selector)?,
        )?;
        context.revalidate_inputs()?;
    }
    if let Some(renewal) = renewal {
        let mut proof = renewal.audit();
        proof["native_census_before"] = json!(native_before);
        proof["native_census_after"] = json!(native_after);
        report["trace136_guard_renewal"] = proof;
    }
    if !memory96_guard_renewal.is_null() {
        report["memory96_guard_pool_renewal"] = memory96_guard_renewal;
    }
    report["retained136_v8_terminal_reference"] =
        json!({"before":retained_v8_before,"after":retained_v8_after});
    report["active_trial_memory_promises_bytes"] = json!(active_trial_memory_promises(&[
        live145_peers_after.first(),
        recovery199_after
            .iter()
            .find(|row| row["unit"] == super::super::recovery199_contract::PRODUCER),
        direct163_after
            .iter()
            .find(|row| row["unit"] == super::super::direct163::UNIT),
        trial_after.as_ref(),
        root128_after.as_ref(),
        root96_after.as_ref(),
        recovered96_after.as_ref(),
        suffix_after.as_ref(),
        charge_after.as_ref(),
        retry0002_after.as_ref(),
        retry0003_after.as_ref(),
        retry0004_after.as_ref(),
        retry0005_after.as_ref(),
        suffix154_after.as_ref(),
    ])?);
    if let Some(p) = super::super::recovery199_contract::load_plan(&loaded.fleet_plan)? {
        report[super::super::recovery199_contract::FIELD] = json!(p.binding);
        report[super::super::recovery199_contract::PROMISES_FIELD] = p.accounting();
        if let Some(t) = &p.terminal {
            report[super::super::recovery199_contract::TERMINAL_FIELD] = json!(t.binding);
        }
    }
    report["retained_cached145_guard"] =
        json!({"before":retained145_guard_before,"after":retained145_guard_after});
    report["original_standing_frontier_bytes"] = json!(original_standing);
    report["original_confirmed_DATA_frontier_bytes"] = json!(DATA_FLOOR);
    report["original141_growth_closure"] =
        json!(s.original141_growth_closure.as_ref().map(binding));
    report["terminal155156_growth_closure"] =
        json!(s.terminal155156_growth_closure.as_ref().map(binding));
    report["terminal152153_growth_closure"] =
        json!(s.terminal152153_growth_closure.as_ref().map(binding));
    Ok(report)
}

fn frontier_scope_matches(
    helper: &str,
    schema: &str,
    output: &Path,
    has141: bool,
    has152153: bool,
) -> bool {
    has141
        && ((helper == FRONTIER_PROOF_ACTOR
            && schema == "jetstreamer-original141-frontier-proof-plan-v1"
            && output
                == Path::new(
                    "/var/lib/jetstreamer/horizon-original141-frontier-proof-20261028-v1/proof.json",
                ))
            || (helper == TERMINAL152153_PROOF_ACTOR
                && schema == "jetstreamer-terminal152153-frontier-proof-plan-v1"
                && output
                    == Path::new(
                        "/var/lib/jetstreamer/horizon-terminal152153-frontier-proof-20261101-v1/proof.json",
                    )
                && has152153))
}
#[cfg(test)]
mod terminal152153_frontier_scope_tests {
    use super::*;
    #[test]
    fn terminal152153_frontier_scope_is_bound_to_actor_output_and_both_selectors() {
        let new = Path::new(
            "/var/lib/jetstreamer/horizon-terminal152153-frontier-proof-20261101-v1/proof.json",
        );
        let old = Path::new(
            "/var/lib/jetstreamer/horizon-original141-frontier-proof-20261028-v1/proof.json",
        );
        let schema = "jetstreamer-terminal152153-frontier-proof-plan-v1";
        assert!(frontier_scope_matches(
            TERMINAL152153_PROOF_ACTOR,
            schema,
            new,
            true,
            true
        ));
        for (actor, path, a, b) in [
            (FRONTIER_PROOF_ACTOR, new, true, true),
            (TERMINAL152153_PROOF_ACTOR, old, true, true),
            (TERMINAL152153_PROOF_ACTOR, new, false, true),
            (TERMINAL152153_PROOF_ACTOR, new, true, false),
        ] {
            assert!(!frontier_scope_matches(actor, schema, path, a, b));
        }
        assert!(!frontier_scope_matches(
            TERMINAL152153_PROOF_ACTOR,
            "foreign",
            new,
            true,
            true
        ));
        assert!(frontier_scope_matches(
            FRONTIER_PROOF_ACTOR,
            "jetstreamer-original141-frontier-proof-plan-v1",
            old,
            true,
            false
        ));
        assert_eq!(
            helper_subcommand(TERMINAL152153_PROOF_ACTOR).unwrap(),
            "prove-terminal152153-data-frontier"
        );
    }
}

/// One read-only native accounting qualification, never an admission or launch.
pub(crate) async fn prove_original141_frontier() -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Plan {
        schema: String,
        resource_accounting: Value,
        output: PathBuf,
    }
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "frontier proof requires root"
    );
    let helper = helper_allocation()?;
    ensure!(
        helper["unit"] == FRONTIER_PROOF_ACTOR || helper["unit"] == TERMINAL152153_PROOF_ACTOR,
        "frontier proof has another helper role"
    );
    let bound = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let m = io::sealed(&bound.path)?;
    io::immutable(&bound, m.len())?;
    let p: Plan = serde_json::from_value(io::read(&bound)?)?;
    ensure!(
        frontier_scope_matches(
            helper["unit"].as_str().unwrap_or(""),
            &p.schema,
            &p.output,
            p.resource_accounting
                .get("original141_growth_closure")
                .is_some_and(|v| !v.is_null()),
            p.resource_accounting
                .get("terminal152153_growth_closure")
                .is_some_and(|v| !v.is_null())
        ),
        "frontier proof scope differs"
    );
    let basis = protected_data_basis(&p.resource_accounting, now()?).await?;
    ensure!(
        helper_allocation()? == helper,
        "frontier proof helper changed"
    );
    let parent = p.output.parent().context("frontier proof parent")?;
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && pm.is_dir() && pm.uid() == 0 && pm.mode() & 0o077 == 0,
        "frontier proof output is not root private"
    );
    let proof_schema = if helper["unit"] == TERMINAL152153_PROOF_ACTOR {
        "jetstreamer-terminal152153-native-frontier-proof-v1"
    } else {
        "jetstreamer-original141-native-frontier-proof-v1"
    };
    let proof = json!({"schema":proof_schema,
        "plan":binding(&bound),"helper":helper,"accounting":basis,"recorded_unix_seconds":now()?,
        "frontier_handoff_qualified":true,"admission_authorized":false,"replay_launch_authorized":false,
        "archive_mutations":false,"guard_changes":false,"r2_mutations":false,"new_resource_samples":0});
    let bytes = serde_json::to_vec_pretty(&proof)?;
    ensure!(
        bytes.len() <= 8 << 20,
        "frontier proof output exceeds bound"
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p.output)?;
    std::io::Write::write_all(&mut file, &bytes)?;
    file.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn adjusted_protection(
    original: &[core::Obligation],
    projected: &[core::Obligation],
    standing: u64,
    confirmed: u64,
    guard: u64,
) -> Result<u64> {
    ensure!(
        projected.starts_with(original),
        "closure changed another original obligation"
    );
    let sum = |items: &[core::Obligation]| {
        items.iter().try_fold(0u64, |n, row| {
            n.checked_add(row.outstanding_bytes)
                .context("closure protected sum overflow")
        })
    };
    let peers = sum(&projected[original.len()..])?;
    Ok(sum(projected)?
        .max(
            standing
                .checked_add(peers)
                .context("closure standing overflow")?,
        )
        .max(
            confirmed
                .checked_add(peers)
                .context("closure confirmed frontier overflow")?,
        )
        .max(guard))
}

#[cfg(test)]
mod original141_frontier_tests {
    use super::*;
    fn row(key: &str, bytes: u64) -> core::Obligation {
        core::Obligation {
            claim_key: key.into(),
            epoch: 0,
            producer_invocation_id: String::new(),
            outstanding_bytes: bytes,
        }
    }
    #[test]
    fn closing_one_claim_never_reduces_guard_or_omits_peer_and_standing_promises() {
        let original = vec![row("retained", 10)];
        let projected = vec![row("retained", 10), row("peer", 20)];
        assert_eq!(
            adjusted_protection(&original, &projected, 50, 60, 100).unwrap(),
            100
        );
        assert_eq!(
            adjusted_protection(&original, &projected, 100, 60, 50).unwrap(),
            120
        );
        assert_eq!(
            adjusted_protection(&original, &projected, 50, 100, 50).unwrap(),
            120
        );
        assert!(adjusted_protection(&original, &[row("retained", 0)], 50, 60, 100).is_err());
        assert!(adjusted_protection(&original, &projected, u64::MAX, 60, 100).is_err());
    }
}

/// Compare actual accounting bases across suffix admission's two full passes.
/// Typed rollover paths reopen their original authenticated evidence; caller
/// JSON alone never becomes a live guard or new allocation proof.
pub(crate) fn stable_guard_basis(spec: &Value, a: &Value, b: &Value) -> Result<()> {
    let s: Sources = serde_json::from_value(spec.clone())?;
    ensure!(s.schema == SOURCE_SCHEMA, "guard_continuity.source_schema");
    let direct163_peers_match = match (
        a["active_peer_allocations"].as_array(),
        b["active_peer_allocations"].as_array(),
    ) {
        (Some(left), Some(right)) => {
            super::super::recovery199::accounting::peers_equal(left, right)?
        }
        _ => false,
    };
    guard_continuity::components(&[
        (
            "guard_resource_owners",
            a.get("current_unique_owner_census").is_some()
                && a["current_unique_owner_census"] == b["current_unique_owner_census"],
        ),
        (
            "guard_resource_peers",
            a.get("active_peer_allocations").is_some() && direct163_peers_match,
        ),
        (
            "guard_resource_pool",
            a.get("native_pool_suballocations").is_some()
                && a["native_pool_suballocations"] == b["native_pool_suballocations"],
        ),
    ])?;
    let owners: Vec<core::Owner> =
        serde_json::from_value(a["current_unique_owner_census"].clone())?;
    let peers: Vec<Value> = serde_json::from_value(a["active_peer_allocations"].clone())?;
    let pool = a["native_pool_suballocations"]
        .as_array()
        .context("guard_continuity.pool_array")?;
    let helper = pool
        .iter()
        .find(|v| v["nonoverlapping_successor_slot"] == true)
        .context("guard_continuity.helper_absent")?;
    ensure!(
        pool.iter()
            .filter(|v| v["nonoverlapping_successor_slot"] == true)
            .count()
            == 1,
        "guard_continuity.helper_ambiguous"
    );
    let policy = guard_continuity::Policy::new(&s.guards, &owners, helper, &peers)?;
    let has_direct = a["active_peer_allocations"].as_array().is_some_and(|rows| {
        rows.iter()
            .any(|r| r["unit"] == super::super::direct163::UNIT)
    });
    let (ca, cb) = if has_direct {
        let plan = protected_generated(&s.fleet_plan)?;
        super::super::direct163::comparison_census(&plan, &a["native_after"], &b["native_after"])?
    } else {
        (a["native_after"].clone(), b["native_after"].clone())
    };
    let (ca, cb) = cold185_rollover::comparison_census(
        a.get("cold185_startpre_native_task_after"),
        b.get("cold185_startpre_native_task_after"),
        &ca,
        &cb,
    )?;
    let live_a = a.get("live145_prefix_export_after").filter(|v| !v.is_null());
    let live_b = b.get("live145_prefix_export_after").filter(|v| !v.is_null());
    let live_now = if live145_prefix::comparison_scope(
        s.live145_prefix_export.is_some(), live_a, live_b,
    )? {
        live145_prefix::actual(s.live145_prefix_export.as_ref(), now()?)?
    } else {
        None
    };
    live145_prefix::stable(live_a, live_b)?;
    live145_prefix::stable(live_b, live_now.as_ref())?;
    let ca = live145_prefix::comparison(&ca, live_a)?;
    let cb = live145_prefix::comparison(&cb, live_b)?;
    policy.compare(
        &a["guards"],
        &b["guards"],
        &a["guard_native"],
        &b["guard_native"],
        &ca,
        &cb,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(bytes: u64) -> core::Obligation {
        core::Obligation {
            claim_key: "standing/frontier".into(),
            epoch: 0,
            producer_invocation_id: String::new(),
            outstanding_bytes: bytes,
        }
    }
    #[test]
    fn planned_trial_creates_no_phantom_data_or_second_pool() {
        let (_, bytes) = protect(&[row(DATA_FLOOR - 1)], DATA_FLOOR, DATA_FLOOR - 2, &[]).unwrap();
        assert_eq!(bytes, DATA_FLOOR);
        assert_eq!(validate_pool(&[]).unwrap(), 0);
    }
    #[test]
    fn retained_terminal_trial_charges_full_data_once_without_live_memory() {
        let retained = json!({"unit":trial_peer::UNIT,"invocation_id":"430bab1325d04a538f86284aeeb3e1ca",
            "data_reservation_bytes":trial_peer::PARENT_BYTES,"memory_max_bytes":0});
        let (rows, protected) = protect(
            &[row(DATA_FLOOR)],
            DATA_FLOOR,
            DATA_FLOOR,
            std::slice::from_ref(&retained),
        )
        .unwrap();
        assert_eq!(protected, DATA_FLOOR + 79_456_894_976);
        assert_eq!(
            rows.iter()
                .filter(|r| r.claim_key == "trial186/430bab1325d04a538f86284aeeb3e1ca")
                .count(),
            1
        );
        assert!(
            protect(
                &rows,
                DATA_FLOOR,
                DATA_FLOOR,
                std::slice::from_ref(&retained)
            )
            .is_err()
        );
        assert!(
            protect(
                &[row(DATA_FLOOR)],
                DATA_FLOOR,
                DATA_FLOOR,
                &[retained.clone(), retained]
            )
            .is_err()
        );
    }
    #[test]
    fn actual_peer_data_is_charged_once_and_never_releases_the_frontier() {
        let peer = json!({"unit":super::super::super::input136::UNIT,"invocation_id":"a".repeat(32),"data_reservation_bytes":3308702239u64});
        let (rows, protected) = protect(
            &[row(DATA_FLOOR)],
            DATA_FLOOR,
            DATA_FLOOR,
            std::slice::from_ref(&peer),
        )
        .unwrap();
        assert_eq!(protected, DATA_FLOOR + 3_308_702_239);
        assert!(protect(&rows, DATA_FLOOR, DATA_FLOOR, std::slice::from_ref(&peer)).is_err());
        assert!(
            protect(
                &[row(u64::MAX)],
                DATA_FLOOR,
                DATA_FLOOR,
                std::slice::from_ref(&peer)
            )
            .is_err()
        );
        let (_, protected) = protect(
            &[row(DATA_FLOOR)],
            DATA_FLOOR,
            DATA_FLOOR + 100_000_000_000,
            std::slice::from_ref(&peer),
        )
        .unwrap();
        assert_eq!(protected, DATA_FLOOR + 100_000_000_000);
    }
    #[test]
    fn duplicate_pool_iid_unit_and_overflow_are_rejected() {
        let a = json!({"unit":"one.service","invocation_id":"a".repeat(32),"memory_max_bytes":512u64<<20});
        assert_eq!(
            validate_pool(std::slice::from_ref(&a)).unwrap(),
            512u64 << 20
        );
        assert!(validate_pool(&[a.clone(), a.clone()]).is_err());
        let mut b = a.clone();
        b["unit"] = json!("two.service");
        assert!(validate_pool(&[a.clone(), b.clone()]).is_err());
        b["invocation_id"] = json!("b".repeat(32));
        b["memory_max_bytes"] = json!(core::NATIVE_POOL);
        assert!(validate_pool(&[a, b]).is_err());
    }
    #[test]
    fn only_positive_empty_retained144_success_is_terminal() {
        let mut n = json!({"Id":RETAINED144,"ActiveState":"active","SubState":"exited","MainPID":"0",
            "ControlGroup":"","NRestarts":"0","Restart":"no","Result":"success","ExecMainStatus":"0","InvocationID":"a".repeat(32)});
        assert!(retained144_terminal(RETAINED144, &n));
        for (field, value) in [
            ("MainPID", "42"),
            ("ControlGroup", "/system.slice/occupied"),
            ("Result", "failed"),
            ("NRestarts", "1"),
            ("SubState", "running"),
        ] {
            let saved = n[field].clone();
            n[field] = json!(value);
            assert!(!retained144_terminal(RETAINED144, &n));
            n[field] = saved;
        }
        assert!(!retained144_terminal("another.service", &n));
    }
    #[test]
    fn source_selector_accepts_no_qualification_or_authority_flag() {
        let value =
            json!({"schema":SOURCE_SCHEMA,"qualified":true,"all_growth_obligations_complete":true});
        assert!(serde_json::from_value::<Sources>(value).is_err());
    }
}

#[cfg(test)]
mod completed_input_allocation_tests {
    use super::*;
    #[test]
    fn additional_native_owners_are_counted_once_and_capture_errors_fail_closed() {
        let helper =
            json!({"unit":ADMIT186,"invocation_id":"a".repeat(32),"memory_max_bytes":512u64<<20});
        let control = json!({"unit":"suffix-control.service","invocation_id":"b".repeat(32),"memory_max_bytes":512u64<<20});
        let guard = json!({"unit":"suffix-guard.service","invocation_id":"c".repeat(32),"memory_max_bytes":512u64<<20});
        let rows = pool_rows_with_additional(&[], &helper, None, None, None, || {
            Ok(vec![control.clone(), guard])
        })
        .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(validate_pool(&rows).unwrap(), 1536u64 << 20);
        assert!(
            pool_rows_with_additional(&[], &helper, None, None, None, || {
                Ok(vec![helper.clone()])
            })
            .is_err()
        );
        assert!(
            pool_rows_with_additional(&[], &helper, None, None, None, || {
                anyhow::bail!("native capture failed")
            })
            .is_err()
        );
        let mut oversized = control;
        oversized["memory_max_bytes"] = json!(16u64 << 30);
        assert!(
            pool_rows_with_additional(&[], &helper, None, None, None, || { Ok(vec![oversized]) })
                .is_err()
        );
    }

    #[test]
    fn completed_input_keeps_data_once_and_has_no_native_pool_memory_slot() {
        let original = vec![core::Obligation {
            claim_key: "standing/frontier".into(),
            epoch: 0,
            producer_invocation_id: String::new(),
            outstanding_bytes: DATA_FLOOR,
        }];
        let peer = json!({"unit":crate::fleet::input136::UNIT,
            "invocation_id":"87a7a1bba8f34dbd8ae373bf0193cd70","state":"completed-retained-input",
            "memory_max_bytes":0,"data_reservation_bytes":3308702239u64});
        let helper =
            json!({"unit":ADMIT186,"invocation_id":"b".repeat(32),"memory_max_bytes":512u64<<20});
        let rows = pool_rows_with_additional(&[], &helper, Some(&peer), None, None, || Ok(vec![]))
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(validate_pool(&rows).unwrap(), 512u64 << 20);
        let guard = json!({"unit":super::super::suffix136::contract::scope::GUARD_UNIT,
            "invocation_id":"c".repeat(32),"memory_max_bytes":512u64<<20});
        let guarded =
            pool_rows_with_additional(&[], &helper, Some(&peer), Some(&guard), None, || Ok(vec![]))
                .unwrap();
        assert_eq!(guarded.len(), 2);
        assert_eq!(validate_pool(&guarded).unwrap(), 1024u64 << 20);
        assert!(
            pool_rows_with_additional(&[], &helper, Some(&peer), Some(&helper), None, || Ok(
                vec![]
            ),)
            .is_err()
        );
        let (projected, floor) = protect(
            &original,
            DATA_FLOOR,
            DATA_FLOOR,
            std::slice::from_ref(&peer),
        )
        .unwrap();
        assert_eq!(floor, DATA_FLOOR + 3_308_702_239);
        assert_eq!(projected.iter().filter(|r| r.epoch == 136).count(), 1);
        assert!(
            protect(
                &projected,
                DATA_FLOOR,
                DATA_FLOOR,
                std::slice::from_ref(&peer)
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod retained_suffix136_accounting_tests {
    use super::*;
    #[test]
    fn retained_v1_v2_and_new_v3_keep_all_data_claims() {
        let old = json!({"unit":retained_suffix136::UNIT,"invocation_id":"e9c4496109e84ad1b5fcf0b0ecfc7698","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let new = json!({"unit":super::super::super::suffix136::contract::scope::UNIT,"invocation_id":"b".repeat(32),"data_reservation_bytes":72u64<<30,"memory_max_bytes":68u64<<30});
        let input = json!({"unit":super::super::super::input136::UNIT,"invocation_id":"87a7a1bba8f34dbd8ae373bf0193cd70","data_reservation_bytes":3308702239u64,"memory_max_bytes":0});
        let retained_v2 = json!({"unit":retained_suffix136_v2::UNIT,"invocation_id":"f734495913134114abbcf5ee07b2089b","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let (rows, floor) = protect(
            &[],
            DATA_FLOOR,
            DATA_FLOOR,
            &[old.clone(), retained_v2.clone(), new, input],
        )
        .unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows.iter().filter(|r| r.epoch == 136).count(), 4);
        assert_eq!(floor, DATA_FLOOR + (216u64 << 30) + 3308702239);
        assert!(protect(&rows, DATA_FLOOR, DATA_FLOOR, &[retained_v2]).is_err());
        assert!(protect(&rows, DATA_FLOOR, DATA_FLOOR, &[old]).is_err());
    }
}

#[cfg(test)]
mod retained_suffix136_v3_accounting_tests {
    use super::*;
    #[test]
    fn input_trial186_and_three_failed_suffixes_stay_distinct_before_new_v4() {
        let peers = vec![
            json!({"unit":super::super::super::input136::UNIT,"invocation_id":"1".repeat(32),"data_reservation_bytes":3308702239u64,"memory_max_bytes":0}),
            json!({"unit":trial_peer::UNIT,"invocation_id":"2".repeat(32),"data_reservation_bytes":74u64<<30,"memory_max_bytes":0}),
            json!({"unit":retained_suffix136::UNIT,"invocation_id":"3".repeat(32),"data_reservation_bytes":72u64<<30,"memory_max_bytes":0}),
            json!({"unit":retained_suffix136_v2::UNIT,"invocation_id":"4".repeat(32),"data_reservation_bytes":72u64<<30,"memory_max_bytes":0}),
            json!({"unit":retained_suffix136_v3::UNIT,"invocation_id":"5".repeat(32),"data_reservation_bytes":72u64<<30,"memory_max_bytes":0}),
        ];
        let (rows, floor) = protect(&[], DATA_FLOOR, DATA_FLOOR, &peers).unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows.iter().filter(|r| r.epoch == 136).count(), 4);
        assert_eq!(floor, DATA_FLOOR + (290u64 << 30) + 3308702239);
        let mut with_candidate = peers.clone();
        assert_eq!(
            super::super::super::suffix136::contract::scope::UNIT,
            "horizon-qualify-136-hourly-suffix-reproduction-20261028-v1.service",
            "this source revision must be qualified with the separately owned v7 scope"
        );
        with_candidate.push(json!({"unit":super::super::super::suffix136::contract::scope::UNIT,
            "invocation_id":"6".repeat(32),"data_reservation_bytes":72u64<<30,"memory_max_bytes":68u64<<30}));
        let (candidate_rows, candidate_floor) =
            protect(&[], DATA_FLOOR, DATA_FLOOR, &with_candidate).unwrap();
        assert_eq!(candidate_rows.len(), 6);
        assert_eq!(candidate_floor, floor + (72u64 << 30));
        let keys = rows.iter().map(|r| &r.claim_key).collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), 5);
        for peer in &peers {
            assert!(protect(&rows, DATA_FLOOR, DATA_FLOOR, std::slice::from_ref(peer)).is_err());
        }
        let mut duplicate = peers.clone();
        duplicate.push(peers[4].clone());
        assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, &duplicate).is_err());
    }
}

#[cfg(test)]
mod retained_suffix136_v4_accounting_tests {
    use super::*;
    #[test]
    fn four_failed_attempts_keep_full_data_before_separate_v5_candidate() {
        let mut peers = [
            retained_suffix136::UNIT,
            retained_suffix136_v2::UNIT,
            retained_suffix136_v3::UNIT,
            retained_suffix136_v4::UNIT,
        ]
        .iter()
        .enumerate()
        .map(|(i, unit)| {
            json!({
                "unit":unit,"invocation_id":format!("{:032x}",i+1),
                "data_reservation_bytes":72u64<<30,"memory_max_bytes":0
            })
        })
        .collect::<Vec<_>>();
        let (rows, floor) = protect(&[], DATA_FLOOR, DATA_FLOOR, &peers).unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(floor, DATA_FLOOR + (288u64 << 30));
        assert!(
            rows.iter()
                .any(|r| r.claim_key == "suffix136-retained-v4/00000000000000000000000000000004")
        );
        for amount in [0, 71u64 << 30, 73u64 << 30] {
            let mut bad = peers.clone();
            bad[3]["data_reservation_bytes"] = json!(amount);
            assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, &bad).is_err());
        }
        let mut duplicate = peers.clone();
        duplicate.push(peers[3].clone());
        assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, &duplicate).is_err());
        assert!(protect(&rows, DATA_FLOOR, DATA_FLOOR, &peers).is_err());
        peers.push(json!({"unit":super::super::super::suffix136::contract::scope::UNIT,
            "invocation_id":"5".repeat(32),"data_reservation_bytes":72u64<<30,"memory_max_bytes":68u64<<30}));
        let (_, with_candidate) = protect(&[], DATA_FLOOR, DATA_FLOOR, &peers).unwrap();
        assert_eq!(with_candidate, floor + (72u64 << 30));
    }
}

pub(crate) async fn close_retained136_v1_growth() -> Result<()> {
    retained136_growth::capture().await
}

#[cfg(test)]
mod retained136_v1_growth_accounting_tests {
    use super::*;
    fn peers() -> Vec<Value> {
        vec![
            json!({"unit":retained_suffix136::UNIT,"invocation_id":"e9c4496109e84ad1b5fcf0b0ecfc7698","data_reservation_bytes":72u64<<30,"historical_data_reservation_bytes":72u64<<30,"remaining_growth_bytes":0,"memory_max_bytes":0}),
            json!({"unit":retained_suffix136_v2::UNIT,"invocation_id":"2".repeat(32),"data_reservation_bytes":72u64<<30,"memory_max_bytes":0}),
            json!({"unit":retained_suffix136_v3::UNIT,"invocation_id":"3".repeat(32),"data_reservation_bytes":72u64<<30,"memory_max_bytes":0}),
            json!({"unit":retained_suffix136_v4::UNIT,"invocation_id":"4".repeat(32),"data_reservation_bytes":72u64<<30,"memory_max_bytes":0}),
            json!({"unit":super::super::super::suffix136::contract::scope::UNIT,"invocation_id":"5".repeat(32),"data_reservation_bytes":72u64<<30,"memory_max_bytes":68u64<<30}),
            json!({"unit":trial_peer::UNIT,"invocation_id":"6".repeat(32),"data_reservation_bytes":74u64<<30,"memory_max_bytes":0}),
            json!({"unit":super::super::super::input136::UNIT,"invocation_id":"7".repeat(32),"data_reservation_bytes":3308702239u64,"memory_max_bytes":0}),
        ]
    }
    #[test]
    fn only_typed_v1_growth_closes_and_all_other_data_stays_exact() {
        let p = peers();
        assert_eq!(
            super::super::super::suffix136::contract::scope::UNIT,
            "horizon-qualify-136-hourly-suffix-reproduction-20261028-v1.service"
        );
        let (default_rows, default_floor) = protect(&[], DATA_FLOOR, DATA_FLOOR, &p).unwrap();
        assert_eq!(default_floor, DATA_FLOOR + (434u64 << 30) + 3308702239);
        assert_eq!(default_rows[0].outstanding_bytes, 72u64 << 30); // Caller state/zero-growth field alone grants nothing.
        let token = retained136_growth::test_token(p[0].clone());
        let (rows, floor) =
            protect_with_growth(&[], DATA_FLOOR, DATA_FLOOR, &p, Some(&token)).unwrap();
        assert_eq!(rows.len(), 7);
        assert_eq!(
            rows[0].claim_key,
            "suffix136-retained-v1/e9c4496109e84ad1b5fcf0b0ecfc7698"
        );
        assert_eq!(rows[0].outstanding_bytes, 0);
        assert_eq!(floor, DATA_FLOOR + (362u64 << 30) + 3308702239);
        assert_eq!(p[0]["data_reservation_bytes"], 72u64 << 30);
        for row in rows.iter().skip(1) {
            let old = default_rows
                .iter()
                .find(|r| r.claim_key == row.claim_key)
                .unwrap();
            assert_eq!(row.outstanding_bytes, old.outstanding_bytes);
        }
        let inherited_guard = DATA_FLOOR + (512u64 << 30);
        assert_eq!(
            protect_with_growth(&[], DATA_FLOOR, inherited_guard, &p, Some(&token))
                .unwrap()
                .1,
            inherited_guard
        );
    }
    #[test]
    fn zero_data_foreign_peer_missing_claim_duplicate_or_overflow_never_borrows_closure() {
        let p = peers();
        let token = retained136_growth::test_token(p[0].clone());
        for index in 0..5 {
            let mut bad = p.clone();
            bad[index]["data_reservation_bytes"] = json!(0);
            assert!(
                protect_with_growth(&[], DATA_FLOOR, DATA_FLOOR, &bad, Some(&token)).is_err(),
                "{index}"
            );
        }
        let mut duplicate = p.clone();
        duplicate.push(p[0].clone());
        assert!(
            protect_with_growth(&[], DATA_FLOOR, DATA_FLOOR, &duplicate, Some(&token)).is_err()
        );
        assert!(protect_with_growth(&[], DATA_FLOOR, DATA_FLOOR, &p[1..], Some(&token)).is_err());
        let mut changed = p.clone();
        changed[0]["invocation_id"] = json!("f".repeat(32));
        assert!(protect_with_growth(&[], DATA_FLOOR, DATA_FLOOR, &changed, Some(&token)).is_err());
        let (rows, _) = protect_with_growth(&[], DATA_FLOOR, DATA_FLOOR, &p, Some(&token)).unwrap();
        assert!(protect_with_growth(&rows, DATA_FLOOR, DATA_FLOOR, &p, Some(&token)).is_err());
        assert!(protect_with_growth(&[], u64::MAX, DATA_FLOOR, &p, Some(&token)).is_err());
    }
}

/// Separate exact v2 capture; no v1 token or selectors are widened.
pub(crate) async fn close_retained136_v2_growth() -> Result<()> {
    retained136_v2_growth::capture().await
}
pub(crate) async fn close_retained136_v3_growth() -> Result<()> {
    retained136_v3_growth::capture().await
}

#[cfg(test)]
mod independent_v3_growth_tests {
    use super::*;
    #[test]
    fn only_exact_v3_token_closes_its_growth_without_releasing_other_attempts() {
        let p = json!({"unit":retained_suffix136_v3::UNIT,"invocation_id":"4378e42c7bb84b58ad53d2d013c51263","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let other = json!({"unit":retained_suffix136_v4::UNIT,"invocation_id":"f64a11fd8c02483a9b1613928e1f6826","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let token = retained136_v3_growth::test_token(p.clone());
        let peers = vec![p.clone(), other.clone()];
        let (rows, protected) = protect_with_growth_v3(
            &[],
            DATA_FLOOR,
            DATA_FLOOR,
            &peers,
            None,
            None,
            Some(&token),
        )
        .unwrap();
        assert_eq!(protected, DATA_FLOOR + (72u64 << 30));
        assert_eq!(rows.iter().filter(|r| r.outstanding_bytes == 0).count(), 1);
        assert_eq!(p["data_reservation_bytes"], 72u64 << 30);
        assert!(
            protect_with_growth_v3(
                &[],
                DATA_FLOOR,
                DATA_FLOOR,
                &[other],
                None,
                None,
                Some(&token)
            )
            .is_err()
        );
        let (_, unclosed) =
            protect_with_growth_v3(&[], DATA_FLOOR, DATA_FLOOR, &peers, None, None, None).unwrap();
        assert_eq!(unclosed, DATA_FLOOR + (144u64 << 30));
    }
}

#[cfg(test)]
mod independent_v1_v2_growth_tests {
    use super::*;
    fn peers() -> Vec<Value> {
        vec![
            json!({"unit":retained_suffix136::UNIT,"invocation_id":"e9c4496109e84ad1b5fcf0b0ecfc7698","data_reservation_bytes":72u64<<30,"memory_max_bytes":0}),
            json!({"unit":retained_suffix136_v2::UNIT,"invocation_id":"f734495913134114abbcf5ee07b2089b","data_reservation_bytes":72u64<<30,"memory_max_bytes":0}),
            json!({"unit":retained_suffix136_v3::UNIT,"invocation_id":"4378e42c7bb84b58ad53d2d013c51263","data_reservation_bytes":72u64<<30,"memory_max_bytes":0}),
            json!({"unit":retained_suffix136_v4::UNIT,"invocation_id":"f64a11fd8c02483a9b1613928e1f6826","data_reservation_bytes":72u64<<30,"memory_max_bytes":0}),
            json!({"unit":trial_peer::UNIT,"invocation_id":"8".repeat(32),"data_reservation_bytes":74u64<<30,"memory_max_bytes":0}),
        ]
    }
    #[test]
    fn defaults_charge_both_and_distinct_tokens_only_close_their_own_growth() {
        let p = peers();
        let v1 = retained136_growth::test_token(p[0].clone());
        let v2 = retained136_v2_growth::test_token(p[1].clone());
        for (a, b, extra) in [
            (None, None, 362u64),
            (Some(&v1), None, 290),
            (None, Some(&v2), 290),
            (Some(&v1), Some(&v2), 218),
        ] {
            let (rows, protected) =
                protect_with_growth_v2(&[], DATA_FLOOR, DATA_FLOOR, &p, a, b).unwrap();
            assert_eq!(rows.len(), 5);
            assert_eq!(protected, DATA_FLOOR + (extra << 30));
            assert_eq!(
                rows[0].outstanding_bytes,
                if a.is_some() { 0 } else { 72u64 << 30 }
            );
            assert_eq!(
                rows[1].outstanding_bytes,
                if b.is_some() { 0 } else { 72u64 << 30 }
            );
            assert_eq!(rows[2].outstanding_bytes, 72u64 << 30);
            assert_eq!(rows[3].outstanding_bytes, 72u64 << 30);
            assert_eq!(rows[4].outstanding_bytes, 74u64 << 30);
            assert_eq!(p[0]["data_reservation_bytes"], 72u64 << 30);
            assert_eq!(p[1]["data_reservation_bytes"], 72u64 << 30);
        }
        let (rows, _) =
            protect_with_growth_v2(&[], DATA_FLOOR, DATA_FLOOR, &p, Some(&v1), Some(&v2)).unwrap();
        assert_eq!(
            rows[0].claim_key,
            "suffix136-retained-v1/e9c4496109e84ad1b5fcf0b0ecfc7698"
        );
        assert_eq!(
            rows[1].claim_key,
            "suffix136-retained-v2/f734495913134114abbcf5ee07b2089b"
        );
        assert!(
            protect_with_growth_v2(&rows, DATA_FLOOR, DATA_FLOOR, &p, Some(&v1), Some(&v2))
                .is_err()
        );
        let guard = DATA_FLOOR + (500u64 << 30);
        assert_eq!(
            protect_with_growth_v2(&[], DATA_FLOOR, guard, &p, Some(&v1), Some(&v2))
                .unwrap()
                .1,
            guard
        );
    }
    #[test]
    fn v1_v2_mixups_omissions_and_caller_zero_rows_never_grant_growth_credit() {
        let mut p = peers();
        let v1 = retained136_growth::test_token(p[0].clone());
        let v2 = retained136_v2_growth::test_token(p[1].clone());
        let wrong_v2 = retained136_v2_growth::test_token(p[0].clone());
        let wrong_v1 = retained136_growth::test_token(p[1].clone());
        assert!(
            protect_with_growth_v2(&[], DATA_FLOOR, DATA_FLOOR, &p, Some(&wrong_v1), Some(&v2))
                .is_err()
        );
        assert!(
            protect_with_growth_v2(&[], DATA_FLOOR, DATA_FLOOR, &p, Some(&v1), Some(&wrong_v2))
                .is_err()
        );
        assert!(
            protect_with_growth_v2(&[], DATA_FLOOR, DATA_FLOOR, &p[1..], Some(&v1), Some(&v2))
                .is_err()
        );
        let mut omitted = p.clone();
        omitted.remove(1);
        assert!(
            protect_with_growth_v2(&[], DATA_FLOOR, DATA_FLOOR, &omitted, Some(&v1), Some(&v2))
                .is_err()
        );
        p[1]["remaining_growth_bytes"] = json!(0);
        p[1]["remaining_growth_released"] = json!(true);
        assert_eq!(
            protect_with_growth_v2(&[], DATA_FLOOR, DATA_FLOOR, &p, None, None)
                .unwrap()
                .0[1]
                .outstanding_bytes,
            72u64 << 30
        );
        p[1]["data_reservation_bytes"] = json!(0);
        assert!(protect_with_growth_v2(&[], DATA_FLOOR, DATA_FLOOR, &p, None, None).is_err());
        assert!(
            protect_with_growth_v2(&[], u64::MAX, DATA_FLOOR, &peers(), Some(&v1), Some(&v2))
                .is_err()
        );
    }
}

#[cfg(test)]
mod retained_suffix136_v5_accounting_tests {
    use super::*;
    #[test]
    fn closed_v5_keeps_full_72_gib_data_without_growth_closure_or_credit() {
        let peer = json!({
            "unit": retained_suffix136_v5::UNIT,
            "invocation_id": "e47627c5475548f0ac47578e55772fdf",
            "data_reservation_bytes": 72u64 << 30,
            "memory_max_bytes": 0,
            "remaining_growth_released": false,
            "physical_reclamation_credit_bytes": 0
        });
        let (rows, floor) =
            protect(&[], DATA_FLOOR, DATA_FLOOR, std::slice::from_ref(&peer)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outstanding_bytes, 72u64 << 30);
        assert_eq!(floor, DATA_FLOOR + (72u64 << 30));
        assert!(protect_with_growth_v2(&[], DATA_FLOOR, DATA_FLOOR, &[peer], None, None).is_ok());
        let mut bad = rows;
        bad[0].outstanding_bytes = 0;
        assert!(bad[0].outstanding_bytes != 72u64 << 30);
    }
    #[test]
    fn v5_cannot_alias_v4_or_a_growth_selector() {
        let mut peer = json!({"unit":retained_suffix136_v5::UNIT,"invocation_id":"e47627c5475548f0ac47578e55772fdf","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, std::slice::from_ref(&peer)).is_ok());
        peer["unit"] = json!(retained_suffix136_v4::UNIT);
        peer["invocation_id"] = json!("f64a11fd8c02483a9b1613928e1f6826");
        assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, std::slice::from_ref(&peer)).is_ok());
        peer["invocation_id"] = json!("bad");
        assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, std::slice::from_ref(&peer)).is_err());
    }
}

#[cfg(test)]
mod retained_suffix136_v7_accounting_tests {
    use super::*;
    #[test]
    fn failed_v7_keeps_full_data_beside_successor_without_growth_credit() {
        let retained = json!({"unit":retained_suffix136_v7::UNIT,
            "invocation_id":"3f20af3ebf7648ffbc2c5e6847958eda",
            "data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let (rows, floor) =
            protect(&[], DATA_FLOOR, DATA_FLOOR, std::slice::from_ref(&retained)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outstanding_bytes, 72u64 << 30);
        assert_eq!(floor, DATA_FLOOR + (72u64 << 30));
        assert!(rows[0].claim_key.starts_with("suffix136-retained-v7/"));
        assert!(
            protect(
                &[],
                DATA_FLOOR,
                DATA_FLOOR,
                &[retained.clone(), retained.clone()]
            )
            .is_err()
        );
        let mut bad = retained.clone();
        bad["data_reservation_bytes"] = json!(0);
        assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, &[bad]).is_err());
        let mut bad = retained.clone();
        bad["invocation_id"] = json!("bad");
        assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, &[bad]).is_err());
        // Apply together with scope8: current v7 must first become retained.
        let current = super::super::super::suffix136::contract::scope::UNIT;
        assert_ne!(current, retained_suffix136_v7::UNIT);
        let live = json!({"unit":current,"invocation_id":"a".repeat(32),
            "data_reservation_bytes":72u64<<30,"memory_max_bytes":68u64<<30});
        let (rows, floor) = protect(&[], DATA_FLOOR, DATA_FLOOR, &[retained, live]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0].claim_key, rows[1].claim_key);
        assert_eq!(floor, DATA_FLOOR + (144u64 << 30));
    }
}

#[cfg(test)]
mod retained_suffix136_v7_growth_isolation_tests {
    use super::*;
    #[test]
    fn previous_attempt_growth_tokens_never_close_failed_v7() {
        let v1 = json!({"unit":retained_suffix136::UNIT,"invocation_id":"e9c4496109e84ad1b5fcf0b0ecfc7698","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let v2 = json!({"unit":retained_suffix136_v2::UNIT,"invocation_id":"f734495913134114abbcf5ee07b2089b","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let v3 = json!({"unit":retained_suffix136_v3::UNIT,"invocation_id":"4378e42c7bb84b58ad53d2d013c51263","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let v7 = json!({"unit":retained_suffix136_v7::UNIT,"invocation_id":"3f20af3ebf7648ffbc2c5e6847958eda","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let a = retained136_growth::test_token(v1.clone());
        let b = retained136_v2_growth::test_token(v2.clone());
        let c = retained136_v3_growth::test_token(v3.clone());
        let (rows, protected) = protect_with_growth_v3(
            &[],
            DATA_FLOOR,
            DATA_FLOOR,
            &[v1, v2, v3, v7.clone()],
            Some(&a),
            Some(&b),
            Some(&c),
        )
        .unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[3].outstanding_bytes, 72u64 << 30);
        assert_eq!(protected, DATA_FLOOR + (72u64 << 30));
        assert!(a.growth_for(&v7).is_err());
        assert!(b.growth_for(&v7).is_err());
        assert!(c.growth_for(&v7).is_err());
        assert_eq!(v7["data_reservation_bytes"], 72u64 << 30);
    }
}

pub(crate) async fn close_retained136_v7_growth() -> Result<()> {
    retained136_v7_growth::capture().await
}
#[cfg(test)]
mod independent_v7_growth_tests {
    use super::*;
    #[test]
    fn v7_token_closes_only_its_own_growth_and_retains_historical_data() {
        let v7 = json!({"unit":retained_suffix136_v7::UNIT,"invocation_id":"3f20af3ebf7648ffbc2c5e6847958eda","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let old = json!({"unit":retained_suffix136_v5::UNIT,"invocation_id":"e47627c5475548f0ac47578e55772fdf","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let token = retained136_v7_growth::test_token(v7.clone());
        let peers = [old, v7.clone()];
        let (rows, charged) = protect_with_growth_v7(
            &[],
            DATA_FLOOR,
            DATA_FLOOR,
            &peers,
            None,
            None,
            (None, None),
        )
        .unwrap();
        assert_eq!(charged, DATA_FLOOR + (144u64 << 30));
        assert_eq!(rows[1].outstanding_bytes, 72u64 << 30);
        let (rows, closed) = protect_with_growth_v7(
            &[],
            DATA_FLOOR,
            DATA_FLOOR,
            &peers,
            None,
            None,
            (None, Some(&token)),
        )
        .unwrap();
        assert_eq!(closed, DATA_FLOOR + (72u64 << 30));
        assert_eq!(rows[0].outstanding_bytes, 72u64 << 30);
        assert_eq!(rows[1].outstanding_bytes, 0);
        assert_eq!(v7["data_reservation_bytes"], 72u64 << 30);
        assert!(
            protect_with_growth_v7(
                &[],
                DATA_FLOOR,
                DATA_FLOOR,
                &peers[..1],
                None,
                None,
                (None, Some(&token))
            )
            .is_err()
        );
        let mut wrong = peers.to_vec();
        wrong[1]["invocation_id"] = json!("b".repeat(32));
        assert!(
            protect_with_growth_v7(
                &[],
                DATA_FLOOR,
                DATA_FLOOR,
                &wrong,
                None,
                None,
                (None, Some(&token))
            )
            .is_err()
        );
        assert!(
            protect_with_growth_v7(
                &rows,
                DATA_FLOOR,
                DATA_FLOOR,
                &peers,
                None,
                None,
                (None, Some(&token))
            )
            .is_err()
        );
    }
}

// Sum every independently authenticated trial once. Missing numeric evidence is
// an error; a new generation must never silently become a zero memory promise.
fn active_trial_memory_promises(peers: &[Option<&Value>]) -> Result<u64> {
    let mut units = BTreeSet::new();
    peers.iter().flatten().try_fold(0u64, |sum, peer| {
        ensure!(
            units.insert(string(peer, "/unit")?),
            "duplicate active trial memory promise"
        );
        sum.checked_add(number(peer, "/memory_max_bytes")?)
            .context("active trial memory promise overflow")
    })
}
#[cfg(test)]
mod root128_independent_accounting_tests {
    use super::*;
    #[test]
    fn old_retained74_and_fresh138_are_distinct_without_credit_or_double_charge() {
        let old = json!({"unit":trial_peer::UNIT,"invocation_id":"a".repeat(32),"data_reservation_bytes":74u64<<30,"memory_max_bytes":0});
        let fresh = json!({"unit":trial_descriptor::ROOT128.unit,"invocation_id":"b".repeat(32),"data_reservation_bytes":138u64<<30,"memory_max_bytes":160u64<<30});
        let peers = [old.clone(), fresh.clone()];
        let (rows, floor) = protect(&[], DATA_FLOOR, DATA_FLOOR, &peers).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].outstanding_bytes, 74u64 << 30);
        assert_eq!(rows[1].outstanding_bytes, 138u64 << 30);
        assert_eq!(floor, DATA_FLOOR + (212u64 << 30));
        assert_ne!(rows[0].claim_key, rows[1].claim_key);
        assert!(rows[0].claim_key.starts_with("trial186/"));
        assert!(rows[1].claim_key.starts_with("trial186-root128/"));
        assert!(protect(&rows, DATA_FLOOR, DATA_FLOOR, &peers).is_err());
        let mut bad = fresh.clone();
        bad["data_reservation_bytes"] = json!(74u64 << 30);
        assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, &[old.clone(), bad]).is_err());
        assert_eq!(
            active_trial_memory_promises(&[Some(&old), Some(&fresh), None]).unwrap(),
            160u64 << 30
        );
        let mut ended = fresh.clone();
        ended["memory_max_bytes"] = json!(0);
        assert_eq!(
            active_trial_memory_promises(&[Some(&old), Some(&ended)]).unwrap(),
            0
        );
        let (_, still_reserved) = protect(&[], DATA_FLOOR, DATA_FLOOR, &[old, ended]).unwrap();
        assert_eq!(still_reserved, floor);
    }
    #[test]
    fn trial_memory_census_rejects_missing_duplicate_or_overflow() {
        let a = json!({"unit":trial_descriptor::ROOT128.unit,"memory_max_bytes":160u64<<30});
        assert!(active_trial_memory_promises(&[Some(&a), Some(&a)]).is_err());
        let missing = json!({"unit":trial_descriptor::ROOT128.unit});
        assert!(active_trial_memory_promises(&[Some(&missing)]).is_err());
        let a = json!({"unit":"one","memory_max_bytes":u64::MAX});
        let b = json!({"unit":"two","memory_max_bytes":1});
        assert!(active_trial_memory_promises(&[Some(&a), Some(&b)]).is_err());
    }
}

#[cfg(test)]
mod root128_memory96_independent_accounting_tests {
    use super::*;
    #[test]
    fn old_retained74_and_fresh138_are_distinct_without_credit_or_double_charge() {
        let old = json!({"unit":trial_peer::UNIT,"invocation_id":"a".repeat(32),"data_reservation_bytes":74u64<<30,"memory_max_bytes":0});
        let fresh = json!({"unit":trial_descriptor::ROOT128_MEMORY96.unit,"invocation_id":"b".repeat(32),"data_reservation_bytes":138u64<<30,"memory_max_bytes":96u64<<30});
        let peers = [old.clone(), fresh.clone()];
        let (rows, floor) = protect(&[], DATA_FLOOR, DATA_FLOOR, &peers).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].outstanding_bytes, 74u64 << 30);
        assert_eq!(rows[1].outstanding_bytes, 138u64 << 30);
        assert_eq!(floor, DATA_FLOOR + (212u64 << 30));
        assert_ne!(rows[0].claim_key, rows[1].claim_key);
        assert!(rows[0].claim_key.starts_with("trial186/"));
        assert!(rows[1].claim_key.starts_with("trial186-root128-memory96/"));
        assert!(protect(&rows, DATA_FLOOR, DATA_FLOOR, &peers).is_err());
        let mut bad = fresh.clone();
        bad["data_reservation_bytes"] = json!(74u64 << 30);
        assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, &[old.clone(), bad]).is_err());
        assert_eq!(
            active_trial_memory_promises(&[Some(&old), Some(&fresh), None]).unwrap(),
            96u64 << 30
        );
        let mut ended = fresh.clone();
        ended["memory_max_bytes"] = json!(0);
        assert_eq!(
            active_trial_memory_promises(&[Some(&old), Some(&ended)]).unwrap(),
            0
        );
        let (_, still_reserved) = protect(&[], DATA_FLOOR, DATA_FLOOR, &[old, ended]).unwrap();
        assert_eq!(still_reserved, floor);
    }
    #[test]
    fn trial_memory_census_rejects_missing_duplicate_or_overflow() {
        let a =
            json!({"unit":trial_descriptor::ROOT128_MEMORY96.unit,"memory_max_bytes":96u64<<30});
        assert!(active_trial_memory_promises(&[Some(&a), Some(&a)]).is_err());
        let missing = json!({"unit":trial_descriptor::ROOT128_MEMORY96.unit});
        assert!(active_trial_memory_promises(&[Some(&missing)]).is_err());
        let a = json!({"unit":"one","memory_max_bytes":u64::MAX});
        let b = json!({"unit":"two","memory_max_bytes":1});
        assert!(active_trial_memory_promises(&[Some(&a), Some(&b)]).is_err());
    }
}

// The legacy dynamic scope8 reader and the new explicit historical selector can
// attest the same incarnation during an additive transition. Authenticate both,
// but reserve exactly once; a changed identity is not a deduplication candidate.
fn disjoint_current_suffix(
    current: Option<Value>,
    historical: Option<&Value>,
) -> Result<Option<Value>> {
    if let (Some(current), Some(historical)) = (&current, historical)
        && current["unit"] == historical["unit"]
    {
        ensure!(
            current["unit"] == retained_suffix136_v8::UNIT
                && current["invocation_id"] == historical["invocation_id"]
                && current["memory_max_bytes"] == 0
                && historical["memory_max_bytes"] == 0
                && current["data_reservation_bytes"] == retained_suffix136_v8::DATA
                && historical["data_reservation_bytes"] == retained_suffix136_v8::DATA,
            "historical v8 conflicts with current suffix owner"
        );
        return Ok(None);
    }
    Ok(current)
}
#[cfg(test)]
mod retained_suffix136_v8_accounting_tests {
    use super::*;
    fn peer() -> Value {
        json!({"unit":retained_suffix136_v8::UNIT,"invocation_id":"c0c214c5b7c440449298bdb90d3f3bd3","data_reservation_bytes":72u64<<30,"memory_max_bytes":0})
    }
    #[test]
    fn entered_failed_v8_retains_full_data_with_all_prior_growth_tokens() {
        let v8 = peer();
        let v1 = json!({"unit":retained_suffix136::UNIT,"invocation_id":"e9c4496109e84ad1b5fcf0b0ecfc7698","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let v2 = json!({"unit":retained_suffix136_v2::UNIT,"invocation_id":"f734495913134114abbcf5ee07b2089b","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let v3 = json!({"unit":retained_suffix136_v3::UNIT,"invocation_id":"4378e42c7bb84b58ad53d2d013c51263","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let v7 = json!({"unit":retained_suffix136_v7::UNIT,"invocation_id":"3f20af3ebf7648ffbc2c5e6847958eda","data_reservation_bytes":72u64<<30,"memory_max_bytes":0});
        let a = retained136_growth::test_token(v1.clone());
        let b = retained136_v2_growth::test_token(v2.clone());
        let c = retained136_v3_growth::test_token(v3.clone());
        let d = retained136_v7_growth::test_token(v7.clone());
        let peers = [v1, v2, v3, v7, v8.clone()];
        let (rows, protected) = protect_with_growth_v7(
            &[],
            DATA_FLOOR,
            DATA_FLOOR,
            &peers,
            Some(&a),
            Some(&b),
            (Some(&c), Some(&d)),
        )
        .unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[4].outstanding_bytes, 72u64 << 30);
        assert!(rows[4].claim_key.starts_with("suffix136-retained-v8/"));
        assert_eq!(protected, DATA_FLOOR + (72u64 << 30));
        assert!(a.growth_for(&v8).is_err());
        assert!(b.growth_for(&v8).is_err());
        assert!(c.growth_for(&v8).is_err());
        assert!(d.growth_for(&v8).is_err());
        assert!(
            protect_with_growth_v7(
                &[],
                DATA_FLOOR,
                DATA_FLOOR,
                &[v8.clone(), v8],
                None,
                None,
                (None, None)
            )
            .is_err()
        );
    }
    #[test]
    fn additive_legacy_reader_deduplicates_only_exact_drained_identity() {
        let historical = peer();
        assert!(
            disjoint_current_suffix(Some(historical.clone()), Some(&historical))
                .unwrap()
                .is_none()
        );
        for (key, value) in [
            ("invocation_id", json!("a".repeat(32))),
            ("memory_max_bytes", json!(68u64 << 30)),
            ("data_reservation_bytes", json!(0)),
        ] {
            let mut bad = historical.clone();
            bad[key] = value;
            assert!(
                disjoint_current_suffix(Some(bad), Some(&historical)).is_err(),
                "{key}"
            );
        }
        let mut successor = historical.clone();
        successor["unit"] = json!("fresh-trace.service");
        successor["memory_max_bytes"] = json!(68u64 << 30);
        assert_eq!(
            disjoint_current_suffix(Some(successor.clone()), Some(&historical)).unwrap(),
            Some(successor)
        );
        assert_eq!(
            disjoint_current_suffix(Some(historical.clone()), None).unwrap(),
            Some(historical)
        );
    }
}

#[cfg(test)]
mod root128_admission_actor_tests {
    use super::*;
    #[test]
    fn exact_old_and_new_trial_slots_keep_the_same_closed_cli() {
        assert_ne!(ADMIT186, ADMIT186_ROOT128);
        assert_eq!(
            helper_subcommand(ADMIT186).unwrap(),
            "admit-epoch186-bounded-worker-trial"
        );
        assert_eq!(
            helper_subcommand(ADMIT186_ROOT128).unwrap(),
            "admit-epoch186-bounded-worker-trial"
        );
        assert_eq!(
            helper_subcommand(FRONTIER_PROOF_ACTOR).unwrap(),
            "prove-original141-data-frontier"
        );
        assert_eq!(
            trial_descriptor::ROOT128.admission_actor().unwrap(),
            ADMIT186_ROOT128
        );
        assert_eq!(
            trial_descriptor::SMALL64.admission_actor().unwrap(),
            ADMIT186
        );
    }
    #[test]
    fn variants_or_paths_are_never_accounting_helper_slots() {
        for name in [
            format!("{ADMIT186_ROOT128}/child"),
            format!("/system.slice/{ADMIT186_ROOT128}"),
            format!("/{ADMIT186_ROOT128}"),
            ADMIT186_ROOT128.replace("-v1.", "-v01."),
            ADMIT186_ROOT128.replace("-v1.", "-v2."),
            ADMIT186_ROOT128.replace(".service", ".timer"),
            ADMIT186_ROOT128.to_uppercase(),
            format!("{ADMIT186_ROOT128} extra"),
        ] {
            assert!(helper_subcommand(&name).is_err(), "{name}");
        }
    }
}

#[cfg(test)]
mod actual_parent_foreman_discovery_census_tests {
    use super::*;

    #[test]
    fn actual_parent_and_foreman_enter_both_scans_only_after_exact_authentication() {
        let helper_name =
            "horizon-epoch136-hourly-charge-trace-retry-0002-admission-20261030-v1.service";
        let helper = json!({"unit":helper_name,"invocation_id":"4c13d52256504fa0a9dbf4d3e56ef7b4"});
        let parent = json!({"unit":"horizon-charge136-retry-0002-parent-startup-20261030-v1.service",
            "invocation_id":"61d61e0790d643d0a0fe11b8a9e4ff5c"});
        let foreman = json!({"unit":"horizon-charge136-retry-0002-supervisor-20261030-v1.service",
            "invocation_id":"a115d960f7634b6db4728db9b82fb580"});
        let mut names = BTreeSet::from([helper_name.to_owned()]);
        let mut authenticated = serde_json::Map::new();
        for actor in [&parent, &foreman] {
            let name = actor["unit"].as_str().unwrap();
            let iid = actor["invocation_id"].as_str().unwrap();
            assert!(
                !names.contains(name),
                "genuine prior fleet lacks the new actor"
            );
            assert!(discovered_owner_authenticated(
                &[],
                helper_name,
                &helper,
                &[],
                Some(actor),
                name,
                iid,
            ));
            assert!(!discovered_owner_authenticated(
                &[],
                helper_name,
                &helper,
                &[],
                Some(actor),
                name,
                &"f".repeat(32),
            ));
            assert!(!discovered_owner_authenticated(
                &[],
                helper_name,
                &helper,
                &[],
                None,
                name,
                iid,
            ));
            authenticated.insert(name.into(), actor.clone());
        }
        let unknown = "horizon-unregistered-replay.service";
        assert!(!discovered_owner_authenticated(
            &[],
            helper_name,
            &helper,
            &[],
            None,
            unknown,
            &"b".repeat(32),
        ));
        include_authenticated_discovery_names(&mut names, &Value::Object(authenticated)).unwrap();
        let before_scan_names = names.clone();
        let after_scan_names = names;
        for actor in [&parent, &foreman] {
            let name = actor["unit"].as_str().unwrap();
            assert!(before_scan_names.contains(name) && after_scan_names.contains(name));
        }
        assert!(!before_scan_names.contains(unknown) && !after_scan_names.contains(unknown));
        assert_eq!(before_scan_names.len(), 3);
    }

    #[test]
    fn malformed_discovery_does_not_add_namespace_names() {
        let mut names = BTreeSet::from(["original.service".to_owned()]);
        let original = names.clone();
        assert!(include_authenticated_discovery_names(&mut names, &json!([])).is_err());
        assert_eq!(names, original);
    }
}

#[cfg(test)]
mod artifact154_closed_actor_tests {
    use super::*;
    #[test]
    fn exact_artifact_writer_is_one_finite_slot_in_the_existing_native_pool() {
        let unit = super::super::super::artifact154_admission::UNIT;
        assert_eq!(
            helper_subcommand(unit).unwrap(),
            "admit-private154-artifact"
        );
        let helper =
            json!({"unit":unit,"invocation_id":"a".repeat(32),"memory_max_bytes":HELPER_MEMORY});
        let rows =
            pool_rows_with_additional(&[], &helper, None, None, None, || Ok(vec![])).unwrap();
        assert_eq!(rows, vec![helper.clone()]);
        assert_eq!(validate_pool(&rows).unwrap(), 512u64 << 20);
        assert_eq!(core::NATIVE_POOL, 16u64 << 30);
        let mut duplicate = rows;
        duplicate.push(helper);
        assert!(validate_pool(&duplicate).is_err());
        for alias in [
            format!("{unit}/child"),
            format!("/system.slice/{unit}"),
            unit.replace(".service", ".timer"),
            unit.replace("-v4.", "-v3."),
            unit.replace("-v4.", "-v5."),
            unit.replace("-v4.", "-v1."),
            unit.to_uppercase(),
        ] {
            assert_ne!(
                alias, unit,
                "rejection fixture must change the admitted actor"
            );
            assert!(helper_subcommand(&alias).is_err(), "{alias}");
        }
    }
    #[test]
    fn current_terminal_memory_proof_is_a_separate_exact_read_only_pool_actor() {
        let unit = super::super::super::terminal_legacy_current_memory_proof::UNIT;
        assert_eq!(
            helper_subcommand(unit).unwrap(),
            "prove-terminal-legacy-current-memory"
        );
        assert_ne!(unit, super::super::super::artifact154_admission::UNIT);
        let helper =
            json!({"unit":unit,"invocation_id":"b".repeat(32),"memory_max_bytes":HELPER_MEMORY});
        let rows =
            pool_rows_with_additional(&[], &helper, None, None, None, || Ok(vec![])).unwrap();
        assert_eq!(validate_pool(&rows).unwrap(), 512u64 << 20);
        for alias in [
            format!("{unit}/child"),
            format!("/system.slice/{unit}"),
            unit.replace(".service", ".timer"),
            unit.replace("-v2.", "-v1."),
            unit.replace("-v2.", "-v3."),
            unit.to_uppercase(),
        ] {
            assert_ne!(
                alias, unit,
                "rejection fixture must change the admitted actor"
            );
            assert!(helper_subcommand(&alias).is_err(), "{alias}");
        }
    }
}

#[cfg(test)]
mod root128_memory96_actor_and_census_tests {
    use super::*;
    #[test]
    fn same_epoch_and_data_do_not_merge_independent_memory_promises() {
        let a = json!({"unit":trial_descriptor::ROOT128.unit,"invocation_id":"a".repeat(32),"data_reservation_bytes":138u64<<30,"memory_max_bytes":160u64<<30});
        let b = json!({"unit":trial_descriptor::ROOT128_MEMORY96.unit,"invocation_id":"b".repeat(32),"data_reservation_bytes":138u64<<30,"memory_max_bytes":96u64<<30});
        let (rows, floor) = protect(&[], DATA_FLOOR, DATA_FLOOR, &[a.clone(), b.clone()]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0].claim_key, rows[1].claim_key);
        assert_eq!(floor, DATA_FLOOR + (276u64 << 30));
        assert_eq!(
            active_trial_memory_promises(&[Some(&a), Some(&b)]).unwrap(),
            256u64 << 30
        );
    }
    #[test]
    fn memory96_admission_actor_is_exact_and_independent() {
        assert_ne!(ADMIT186_ROOT128_MEMORY96, ADMIT186_ROOT128);
        assert_eq!(
            helper_subcommand(ADMIT186_ROOT128_MEMORY96).unwrap(),
            "admit-epoch186-bounded-worker-trial"
        );
        for alias in [
            format!("/{ADMIT186_ROOT128_MEMORY96}"),
            format!("{ADMIT186_ROOT128_MEMORY96}/child"),
            ADMIT186_ROOT128_MEMORY96.replace("-v1.", "-v01."),
            ADMIT186_ROOT128_MEMORY96.replace(".service", ".timer"),
        ] {
            assert!(helper_subcommand(&alias).is_err());
        }
        assert!(requires_typed_allocation(
            "unrelated.service",
            "/sealed/jetstreamer-epoch186-root128-memory96-trial /sealed/plan.json"
        ));
    }
}

#[cfg(test)]
#[test]
fn native183_verifiers_are_visible_to_complete_allocation_census() {
    for epoch in [183, 184] {
        for stage in ["full", "plugin"] {
            assert!(requires_typed_allocation(
                &format!("horizon-{stage}-verify-{epoch}-native183-20261029-v1.service"),
                "/usr/local/lib/jetstreamer/horizon-cohort183-delivery-tools-20261029-v1/jetstreamer-horizon-verify-pair /sealed/plan.json SHA 2cc5b4a6b073200c8de051992eea6dc78e21b41c5f46f9e7573b9c94be4536a2"
            ));
        }
    }
}

#[cfg(test)]
mod input161_retry5_retry6_native_helper_tests {
    use super::*;
    #[test]
    fn input161_exact_generation4_5_and6_helpers_keep_distinct_finite_native_slots() {
        assert_eq!(
            helper_subcommand("horizon-epoch161-snapshot-input-admission-20261030-g5.service")
                .unwrap(),
            "admit-snapshot161-retry5-input"
        );
        assert_eq!(
            helper_subcommand("horizon-epoch161-snapshot-input-admission-20261030-g6.service")
                .unwrap(),
            "admit-snapshot161-retry6-input"
        );
        assert_eq!(
            helper_subcommand("horizon-epoch161-snapshot-input-admission-20261029-g4.service")
                .unwrap(),
            "admit-snapshot161-retry4-input"
        );
        for name in [
            "horizon-epoch161-snapshot-input-admission-20261030-g05.service",
            "horizon-epoch161-snapshot-input-admission-20261030-g06.service",
            "horizon-epoch161-snapshot-input-admission-20261030-g7.service",
            "horizon-epoch161-snapshot-input-admission-20261029-g5.service",
        ] {
            assert!(helper_subcommand(name).is_err());
        }
    }
}

#[cfg(test)]
mod generation7_check_only_helper_arguments_tests {
    use super::*;
    fn argv() -> Vec<String> {
        [
            "/sealed/helper",
            "admit-snapshot161-retry7-input",
            "/sealed/spec",
            "--spec-sha256",
            &"a".repeat(64),
            "--self-sha256",
            &"b".repeat(64),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    const UNIT: &str = "horizon-epoch161-snapshot-input-admission-20261031-g7.service";
    #[test]
    fn exact_generation7_accepts_normal_and_check_only_commands() {
        let mut args = argv();
        assert!(validate_helper_arguments(UNIT, &args[1], &args).is_ok());
        args.push("--check-only".into());
        assert!(validate_helper_arguments(UNIT, &args[1], &args).is_ok());
    }
    #[test]
    fn check_only_does_not_broaden_other_generations_or_flags() {
        let mut args = argv();
        args.push("--check-only".into());
        for unit in [
            "horizon-epoch161-snapshot-input-admission-20261030-g6.service",
            "unrelated.service",
        ] {
            assert!(validate_helper_arguments(unit, &args[1], &args).is_err());
        }
        args[7] = "--execute".into();
        assert!(validate_helper_arguments(UNIT, &args[1], &args).is_err());
        args[7] = "--check-only".into();
        args.push("--extra".into());
        assert!(validate_helper_arguments(UNIT, &args[1], &args).is_err());
    }
    #[test]
    fn check_only_preserves_exact_subcommand_digest_and_flag_bindings() {
        let mut args = argv();
        args.push("--check-only".into());
        for index in [1, 3, 4, 5, 6] {
            let mut bad = args.clone();
            bad[index] = "wrong".into();
            assert!(
                validate_helper_arguments(UNIT, "admit-snapshot161-retry7-input", &bad).is_err()
            );
        }
        assert!(validate_helper_arguments(UNIT, "admit-snapshot161-retry6-input", &args).is_err());
    }
}

#[cfg(test)]
mod cached145_data_peer_tests {
    use super::*;
    fn row() -> Value {
        let promise = json!({"schema":"jetstreamer-epoch145-cached-independent-resource-promise-v1",
            "process_hard_limit_protected_bytes":192u64<<30,"DATA_retained_bytes":337u64<<30,"memory_or_DATA_credit_bytes":0});
        let promise = crate::fleet::cached145_allocation::with_guard_promise(&promise).unwrap();
        json!({"unit":"horizon-qualify-145-cached-0123456789abcdef.service","invocation_id":"a".repeat(32),
            "memory_max_bytes":(192u64<<30)+(512u64<<20),"parent_memory_max_bytes":192u64<<30,
            "guard_memory_max_bytes":512u64<<20,"data_reservation_bytes":337u64<<30,
            "native_pool_suballocation":false,"credit_bytes":0,"resource_release_qualified":false,
            "cached145_resource_promise":promise})
    }
    #[test]
    fn cached145_data_peer_charges_the_complete_retained_promise() {
        let p = row();
        let (rows, floor) =
            protect_with_growth_v7(&[], 0, 0, &[p], None, None, (None, None)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].epoch, 145);
        assert_eq!(rows[0].claim_key, format!("cached145/{}", "a".repeat(32)));
        assert_eq!(rows[0].outstanding_bytes, 337u64 << 30);
        assert!(floor >= DATA_FLOOR + (337u64 << 30));
    }
    #[test]
    fn cached145_data_peer_rejects_partial_promises_credit_and_duplicate_owners() {
        for (key, value) in [
            ("memory_max_bytes", json!(192u64 << 30)),
            ("parent_memory_max_bytes", json!(0)),
            ("guard_memory_max_bytes", json!(0)),
            ("data_reservation_bytes", json!((337u64 << 30) - 1)),
            ("native_pool_suballocation", json!(true)),
            ("credit_bytes", json!(1)),
            ("resource_release_qualified", json!(true)),
            (
                "unit",
                json!("horizon-qualify-145-cached-0123456789abcdeF.service"),
            ),
        ] {
            let mut p = row();
            p[key] = value;
            assert!(
                protect_with_growth_v7(&[], 0, 0, &[p], None, None, (None, None)).is_err(),
                "{key}"
            );
        }
        let p = row();
        assert!(
            protect_with_growth_v7(&[], 0, 0, &[p.clone(), p], None, None, (None, None)).is_err()
        );
    }
    #[test]
    #[ignore = "read-only root audit of genuine retained cached145 capture"]
    fn actual_cached145_terminal_data_debt_is_retained_after_failed_unreleased_startup() {
        let fleet:Value=serde_json::from_slice(&std::fs::read("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261101T071809Z-postcompletion154-original-policy-C4-v1.json").unwrap()).unwrap();
        let peers = crate::fleet::cached145_allocation::allocations(&fleet).unwrap();
        let original = peers
            .iter()
            .filter(|p| p["invocation_id"] == "8b62edc45bb54d7e958c524a9afeb1b2")
            .collect::<Vec<_>>();
        assert_eq!(original.len(), 1);
        let peer = original[0];
        assert_eq!(peer["invocation_id"], "8b62edc45bb54d7e958c524a9afeb1b2");
        assert_eq!(
            peer["cached145_resource_promise"]["DATA_retained_bytes"],
            337u64 << 30
        );
        let (rows, _) =
            protect_with_growth_v7(&[], 0, 0, &peers, None, None, (None, None)).unwrap();
        let expected = if peer["resource_release_qualified"] == true {
            assert_eq!(peer["state"], "closed-unreleased-private-cached145");
            assert_eq!(peer["unreleased_closure"]["parent_never_released"], true);
            0
        } else {
            337u64 << 30
        };
        let matching = rows
            .iter()
            .filter(|r| r.claim_key == "cached145/8b62edc45bb54d7e958c524a9afeb1b2")
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].outstanding_bytes, expected);
    }
}

#[cfg(test)]
mod cached145_unreleased_native_test {
    use super::*;
    #[test]
    #[ignore = "requires the separately sealed main closure policy and genuine terminal scope"]
    fn actual_cached145_unreleased_closure_releases_only_unused_future_promises() {
        let fleet:Value=serde_json::from_slice(&std::fs::read("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261101T074809Z-postcompletion154-original-policy-C4-v1.json").unwrap()).unwrap();
        let peers = crate::fleet::cached145_allocation::allocations(&fleet).unwrap();
        assert_eq!(
            crate::fleet::cached145_allocation::allocations(&fleet).unwrap(),
            peers,
            "genuine repeated terminal allocation must have identical semantic evidence"
        );
        let original = peers
            .iter()
            .filter(|p| p["invocation_id"] == "8b62edc45bb54d7e958c524a9afeb1b2")
            .collect::<Vec<_>>();
        assert_eq!(original.len(), 1);
        let p = original[0];
        let sources = p["source_bindings"]
            .as_array()
            .expect("common accounting source ABI");
        assert!(sources.len() >= 9);
        for key in ["policy", "layout", "terminal_evidence"] {
            assert!(sources.contains(&p["unreleased_closure"][key]), "{key}");
        }

        assert_eq!(p["state"], "closed-unreleased-private-cached145");
        assert_eq!(p["invocation_id"], "8b62edc45bb54d7e958c524a9afeb1b2");
        assert_eq!(p["memory_max_bytes"], 0);
        assert_eq!(p["data_reservation_bytes"], 0);
        assert_eq!(p["credit_bytes"], 337u64 << 30);
        assert_eq!(p["physical_retirement_credit_bytes"], 0);
        assert_eq!(
            p["cached145_resource_promise"]["DATA_retained_bytes"],
            337u64 << 30
        );
        assert_eq!(
            p["unreleased_closure"]["future_memory_reservation_released_bytes"],
            (192u64 << 30) + (512u64 << 20)
        );
        let (rows, floor) =
            protect_with_growth_v7(&[], 0, 0, &peers, None, None, (None, None)).unwrap();
        let matching = rows
            .iter()
            .filter(|r| r.claim_key == "cached145/8b62edc45bb54d7e958c524a9afeb1b2")
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].outstanding_bytes, 0);
        let others = peers
            .iter()
            .filter(|p| p["invocation_id"] != "8b62edc45bb54d7e958c524a9afeb1b2")
            .cloned()
            .collect::<Vec<_>>();
        let (_, other_floor) =
            protect_with_growth_v7(&[], 0, 0, &others, None, None, (None, None)).unwrap();
        assert_eq!(
            floor, other_floor,
            "original never-released closure cannot erase another attempt reserve"
        );
    }
}

#[cfg(test)]
mod admission_generation_route_tests {
    use super::*;
    #[test]
    fn each_actual_retry_admission_caller_accepts_only_its_matching_generation() {
        let routes = [
            (
                super::super::super::charge136_retry0002::contract::scope::ADMIT_UNIT,
                "admit-hourly136-charge-trace-retry-0002",
            ),
            (
                super::super::super::charge136_retry0003::contract::scope::ADMIT_UNIT,
                "admit-hourly136-charge-trace-retry-0003",
            ),
            (
                super::super::super::charge136_retry0004::contract::scope::ADMIT_UNIT,
                "admit-hourly136-charge-trace-retry-0004",
            ),
            (
                super::super::super::charge136_retry0005::contract::scope::ADMIT_UNIT,
                "admit-hourly136-charge-trace-retry-0005",
            ),
        ];
        for (unit, actual_command) in routes {
            let expected = helper_subcommand(unit).unwrap();
            assert_eq!(expected, actual_command, "actual caller generation {unit}");
            let mut args = vec![
                "/immutable/jetstreamer-r2".into(),
                actual_command.into(),
                "/immutable/spec.json".into(),
                "--spec-sha256".into(),
                "a".repeat(64),
                "--self-sha256".into(),
                "b".repeat(64),
            ];
            validate_helper_arguments(unit, expected, &args).unwrap();
            for (_, foreign_command) in routes {
                if foreign_command == actual_command {
                    continue;
                }
                args[1] = foreign_command.into();
                assert!(
                    validate_helper_arguments(unit, expected, &args).is_err(),
                    "caller {unit} accepted {foreign_command}"
                );
            }
        }
    }
}

#[cfg(test)]
mod failed4_current_reader_dispatch_tests {
    use super::*;
    #[test]
    fn exact_read_only_actor_has_one_command_and_no_check_only_or_neighbor_namespace() {
        let unit = super::super::super::failed4_current_accounting_reader::UNIT;
        assert_eq!(
            helper_subcommand(unit).unwrap(),
            "read-failed4-current-accounting"
        );
        for other in [
            "horizon-failed4-current-accounting-reader-20261104-v1.timer",
            "horizon-failed4-current-accounting-reader-20261104-v2.service",
            "horizon-failed4-current-accounting-reader-20261104-v1-fake.service",
        ] {
            assert!(helper_subcommand(other).is_err());
        }
        let args = vec![
            "/reader".into(),
            "read-failed4-current-accounting".into(),
            "/spec".into(),
            "--spec-sha256".into(),
            "a".repeat(64),
            "--self-sha256".into(),
            "b".repeat(64),
        ];
        validate_helper_arguments(unit, "read-failed4-current-accounting", &args).unwrap();
        let mut extra = args.clone();
        extra.push("--check-only".into());
        assert!(
            validate_helper_arguments(unit, "read-failed4-current-accounting", &extra).is_err()
        );
        let mut wrong = args;
        wrong[1] = "admit-hourly136-charge-trace-retry-0005".into();
        assert!(
            validate_helper_arguments(unit, "read-failed4-current-accounting", &wrong).is_err()
        );
    }
}

#[cfg(test)]
mod failed4_exact_2gib_helper_accounting_tests {
    use super::*;
    #[test]
    fn exact_reader_charges_two_gib_and_rejects_old_512mib_or_broader_caps() {
        let unit = super::super::super::failed4_current_accounting_reader::UNIT;
        assert_eq!(
            helper_memory_bytes(unit, &json!({"MemoryMax":"2147483648"})).unwrap(),
            2u64 << 30
        );
        for cap in [
            "536870912",
            "1073741824",
            "4294967296",
            "infinity",
            "02147483648",
        ] {
            assert!(
                helper_memory_bytes(unit, &json!({"MemoryMax":cap})).is_err(),
                "{cap}"
            );
        }
        assert!(helper_memory_bytes(unit, &json!({"MemoryMax":2147483648u64})).is_err());
        for other in [
            super::super::super::artifact154_admission::UNIT,
            super::super::super::terminal_legacy_current_memory_proof::UNIT,
            ADMIT186,
        ] {
            assert_eq!(
                helper_memory_bytes(other, &json!({"MemoryMax":"536870912"})).unwrap(),
                HELPER_MEMORY
            );
            assert!(helper_memory_bytes(other, &json!({"MemoryMax":"2147483648"})).is_err());
        }
        for alias in [
            "horizon-failed4-current-accounting-reader-20261104-v2.service",
            "horizon-failed4-current-accounting-reader-20261104-v1.timer",
            "foreign.service",
        ] {
            assert!(helper_memory_bytes(alias, &json!({"MemoryMax":"2147483648"})).is_err());
        }
    }
    #[test]
    fn own_exact_two_gib_row_enters_pool_once_without_changing_other_claims_or_pool_ceiling() {
        let unit = super::super::super::failed4_current_accounting_reader::UNIT;
        let bytes = helper_memory_bytes(unit, &json!({"MemoryMax":"2147483648"})).unwrap();
        let own = json!({"unit":unit,"invocation_id":"a".repeat(32),"memory_max_bytes":bytes});
        let other = json!({"unit":"unrelated-existing-pool.service","invocation_id":"b".repeat(32),"memory_max_bytes":HELPER_MEMORY});
        let rows =
            pool_rows_with_additional(&[], &own, None, None, None, || Ok(vec![other.clone()]))
                .unwrap();
        assert_eq!(validate_pool(&rows).unwrap(), (2u64 << 30) + HELPER_MEMORY);
        assert!(rows.contains(&other));
        assert!(rows.contains(&own));
        assert_eq!(core::NATIVE_POOL, 16u64 << 30);
        let mut duplicate = rows;
        duplicate.push(own);
        assert!(validate_pool(&duplicate).is_err());
    }
}

#[cfg(test)]
mod direct163_accounting_tests {
    use super::*;
    #[test]
    fn direct_parent_and_auxiliaries_remain_exact_peers_without_namespace_exemptions() {
        let unit = super::super::super::direct163::UNIT;
        let guard = super::super::super::direct163::GUARD;
        let iid = "a".repeat(32);
        let peers = vec![
            json!({"unit":unit,"invocation_id":iid}),
            json!({"unit":guard,"invocation_id":"b".repeat(32)}),
        ];
        assert!(discovered_owner_authenticated(
            &[],
            "helper.service",
            &json!({}),
            &peers,
            None,
            unit,
            &iid
        ));
        assert!(!discovered_owner_authenticated(
            &[],
            "helper.service",
            &json!({}),
            &peers,
            None,
            unit,
            &"c".repeat(32)
        ));
        assert!(!discovered_owner_authenticated(
            &[],
            "helper.service",
            &json!({}),
            &peers,
            None,
            "horizon-direct163-foreign.service",
            &iid
        ));
    }
    #[test]
    fn direct_parent_full_data_and_memory_charge_once_with_zero_charged_auxiliary_rows() {
        let parent = super::super::super::direct163::UNIT;
        let registration = json!({"path":"/var/lib/jetstreamer/horizon-direct163-enrollment-20261105-v1/enrollment.json","sha256":"d".repeat(64)});
        let mut peers = vec![
            json!({"unit":parent,"invocation_id":"a".repeat(32),"memory_max_bytes":197768759296u64,
            "data_reservation_bytes":768u64<<30,"direct163_registration":registration}),
        ];
        for (unit, iid) in [
            (super::super::super::direct163::GUARD, "b".repeat(32)),
            (super::super::super::direct163::STOP, String::new()),
        ] {
            peers.push(json!({"unit":unit,"invocation_id":iid,"memory_max_bytes":0,"data_reservation_bytes":0,
                "included_once_in_direct163_parent_claim":true,"direct163_registration":registration}));
        }
        let (rows, protected) = protect(&[], DATA_FLOOR, DATA_FLOOR, &peers).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outstanding_bytes, 768u64 << 30);
        assert_eq!(protected, DATA_FLOOR + (768u64 << 30));
        assert_eq!(
            active_trial_memory_promises(&[Some(&peers[0])]).unwrap(),
            197768759296
        );
        assert!(protect(&rows, DATA_FLOOR, DATA_FLOOR, &peers).is_err());
        peers[2]["data_reservation_bytes"] = json!(1);
        assert!(protect(&[], DATA_FLOOR, DATA_FLOOR, &peers).is_err());
    }
}

#[cfg(test)]
mod recovery199_discovery_tests {
    use super::*;
    #[test]
    fn recovery199_native_discovery_needs_the_exact_enrolled_invocation() {
        let helper = json!({"unit":"existing-helper.service","invocation_id":"f".repeat(32)});
        let peers = crate::fleet::recovery199_contract::FAMILY[..3]
            .iter()
            .enumerate()
            .map(|(i, u)| json!({"unit":u,"invocation_id":(i+1).to_string().repeat(32)}))
            .collect::<Vec<_>>();
        for peer in &peers {
            let unit = peer["unit"].as_str().unwrap();
            let iid = peer["invocation_id"].as_str().unwrap();
            assert!(discovered_owner_authenticated(
                &[],
                "existing-helper.service",
                &helper,
                &peers,
                None,
                unit,
                iid
            ));
            assert!(!discovered_owner_authenticated(
                &[],
                "existing-helper.service",
                &helper,
                &peers,
                None,
                unit,
                &"e".repeat(32)
            ));
        }
        assert!(!discovered_owner_authenticated(
            &[],
            "existing-helper.service",
            &helper,
            &peers,
            None,
            "foreign-recovery.service",
            &"1".repeat(32)
        ));
    }
}

#[cfg(test)]
mod cold185_discovery_tests {
    use super::*;
    #[test]
    fn unknown_epoch185_driver_is_a_workload_and_needs_exact_typed_owner() {
        let command = "/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v10/epoch185-guarded-cold prestart";
        assert!(requires_typed_allocation(
            "unfamiliar-name.service",
            command
        ));
        assert!(!discovered_owner_authenticated(
            &[],
            "reader.service",
            &json!({}),
            &[],
            None,
            "unfamiliar-name.service",
            &"a".repeat(32)
        ));
    }
    #[test]
    fn genuine_exact_peer_identity_does_not_cover_neighbor_or_restarted_actor() {
        let iid = "a".repeat(32);
        let rows =
            vec![json!({"unit":"horizon-qualify-185-capped-cold-v8.service", "invocation_id":iid})];
        assert!(discovered_owner_authenticated(
            &[],
            "reader.service",
            &json!({}),
            &rows,
            None,
            "horizon-qualify-185-capped-cold-v8.service",
            &iid
        ));
        assert!(!discovered_owner_authenticated(
            &[],
            "reader.service",
            &json!({}),
            &rows,
            None,
            "horizon-qualify-185-capped-cold-v9.service",
            &iid
        ));
        assert!(!discovered_owner_authenticated(
            &[],
            "reader.service",
            &json!({}),
            &rows,
            None,
            "horizon-qualify-185-capped-cold-v8.service",
            &"b".repeat(32)
        ));
    }
}

#[cfg(test)]
#[test]
fn live145_exporter_and_guard_cannot_be_ignored_or_borrow_an_unrelated_name() {
    assert!(requires_typed_allocation("horizon-extract145-prefix-any.service", "/foreign"));
    assert!(requires_typed_allocation("horizon-guard145-prefix-any.service", "/foreign"));
    assert!(requires_typed_allocation("unrelated.service", "/sealed/epoch145-prefix-extract extract /plan"));
    assert!(!requires_typed_allocation("unrelated.service", "/usr/bin/unrelated"));
}
