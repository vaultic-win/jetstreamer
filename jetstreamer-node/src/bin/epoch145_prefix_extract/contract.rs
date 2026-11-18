//! Closed operational contract for the original cached145 canonical prefix.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf};

pub(super) const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch145-cached-b2a09f57de39c384/work/diagnostic/epoch-145-through-63072070.jet";
pub(super) const SOURCE_SHA: &str =
    "cb8ac0bc47919c22dc7898e068fb43ffac80aceadcacac3ff8f24ef32d3b3353";
pub(super) const SOURCE_BYTES: u64 = 105_633_748_687;
pub(super) const MANIFEST_SHA: &str =
    "a101b885c5d60a13b8567d3968acd0e5177ec4f04669b91333cb9b3c5ca4b96a";
pub(super) const TERMINAL_PATH: &str = "/home/sol/.jetstreamer-private/cached145-postreplay-handoff-20261105-v1/ROOT_ACTUAL145_CLEAN_TERMINAL_AND_VERIFIED_SEGMENT.json";
pub(super) const TERMINAL_SHA: &str =
    "8fe99753332d62254da147dcf1324bf4834a78d595d55c853228ce3fb469cd9d";
pub(super) const ORIGINAL_IID: &str = "15ddd220e2144aaa8d7418f73f60768f";
pub(super) const GUARD_PATH: &str = "/usr/local/lib/jetstreamer/horizon-native154-retained-stop-guard-tools-20261029-v3/jetstreamer-horizon-standalone-guard";
pub(super) const GUARD_SHA: &str =
    "65e818ad93b0066ac5fb4213d31c1899a4f5c1b255c1e1cd84b9a6652ddfc229";
pub(super) const MEMORY: u64 = 64 << 30;
pub(super) const GUARD_MEMORY: u64 = 512 << 20;
pub(super) const OUTPUT: u64 = 160 << 30;
pub(super) const METADATA: u64 = 1 << 30;
// A real separate frozen source copy is charged in addition to the private prefix.
pub(super) const EXTRA_DATA: u64 = SOURCE_BYTES + OUTPUT + METADATA;
pub(super) const OLD_FLOOR: u64 = 4_202_184_371_152;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub links: u64,
    pub mtime: i64,
    pub mtime_ns: i64,
    pub ctime: i64,
    pub ctime_ns: i64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub schema: String,
    pub attempt: String,
    pub program: Bound,
    pub source: PathBuf,
    pub source_identity: Identity,
    pub manifest: Bound,
    pub manifest_identity: Identity,
    pub original_terminal: Bound,
    pub hold_seconds: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Owner {
    pub unit: String,
    pub invocation_id: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub cgroup: String,
    pub started_unix_seconds: u64,
    pub program_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Release {
    pub schema: String,
    pub admission: Bound,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inputs {
    pub frontier: Bound,
    pub observer: Bound,
    pub fleet: Bound,
    pub frame: Bound,
    pub reader: Bound,
    pub memory: Bound,
    pub data: Bound,
    pub completion: Bound,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Guard {
    pub program: Bound,
    pub plan: Bound,
    pub receipt_directory: PathBuf,
    pub first_sample: Bound,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Admission {
    pub schema: String,
    pub plan: Bound,
    pub owner: Owner,
    pub inputs: Inputs,
    pub booking: Bound,
    pub guard: Guard,
    pub not_before: u64,
    pub expires: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    key: String,
    memory_bytes: u64,
    data_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Booking {
    schema: String,
    plan: Bound,
    owner: Owner,
    inputs: Inputs,
    other_claims: Vec<Claim>,
    maximum_runtime_seconds: u64,
    extractor_memory_bytes: u64,
    guard_memory_bytes: u64,
    #[serde(rename = "additional_DATA_bytes")]
    additional_data_bytes: u64,
}
#[derive(Clone, Copy)]
pub(super) struct Budget {
    pub floor: u64,
    pub required_initial_free: u64,
}
pub(super) fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
impl Plan {
    pub fn unit(&self) -> String {
        format!(
            "horizon-qualify-145-prefix-extract-{}.service",
            self.attempt
        )
    }
    pub fn work(&self) -> PathBuf {
        PathBuf::from(format!(
            "/home/sol/.jetstreamer-private/epoch145-prefix-extract-{}",
            self.attempt
        ))
    }
    pub fn state(&self) -> PathBuf {
        PathBuf::from(format!(
            "/var/lib/jetstreamer/horizon-epoch145-prefix-extract-{}",
            self.attempt
        ))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "horizon-epoch145-prefix-extraction-plan-v1" && hex(&self.attempt, 16),
            "wrong extraction plan scope"
        );
        ensure!(
            self.source == PathBuf::from(SOURCE)
                && self.manifest.path == PathBuf::from(format!("{SOURCE}.segment.json"))
                && self.manifest.sha256 == MANIFEST_SHA
                && self.original_terminal.path == PathBuf::from(TERMINAL_PATH)
                && self.original_terminal.sha256 == TERMINAL_SHA,
            "extraction plan changes original archive, manifest or terminal witness"
        );
        ensure!(
            self.source_identity.bytes == SOURCE_BYTES
                && self.source_identity.links == 1
                && self.source_identity.mode == 0o600
                && self.source_identity.uid == 1001
                && self.manifest_identity.bytes <= 1 << 20
                && self.manifest_identity.links == 1
                && self.manifest_identity.mode == 0o600
                && self.manifest_identity.uid == 1001,
            "original writable identities must be preserved; only a separate copy may be frozen"
        );
        ensure!(
            (1..=1800).contains(&self.hold_seconds)
                && hex(&self.program.sha256, 64)
                && self.program.path.is_absolute()
                && self.program.path.starts_with("/usr/local/lib/jetstreamer"),
            "program or held lifetime differs"
        );
        Ok(())
    }
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .context("extraction admission arithmetic overflow")
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("missing extraction resource integer {k}"))
}
fn equals(v: &Value, b: &Bound) -> Result<bool> {
    Ok(*v == serde_json::to_value(b)?)
}

/// Independently reconnect actual completed reader/memory/DATA proofs and a root
/// booking to this held owner. There is deliberately no caller approval Boolean.
pub(super) fn admit(
    plan: &Plan,
    plan_bound: &Bound,
    owner: &Owner,
    a: &Admission,
    now: u64,
    mut read: impl FnMut(&Bound) -> Result<Value>,
    clock: impl Fn(&str) -> Result<u64>,
) -> Result<Budget> {
    plan.validate()?;
    ensure!(
        a.schema == "horizon-epoch145-prefix-extraction-admission-v1"
            && a.plan == *plan_bound
            && a.owner == *owner
            && owner.unit == plan.unit()
            && owner.program_sha256 == plan.program.sha256
            && owner.pid > 1
            && owner.start_ticks > 0
            && hex(&owner.invocation_id, 32)
            && owner.cgroup == format!("/system.slice/{}", owner.unit)
            && a.not_before <= now
            && now <= a.expires
            && a.expires >= a.not_before
            && a.expires - a.not_before <= 900,
        "admission does not bind this actual held owner and finite release"
    );
    let booking: Booking = serde_json::from_value(read(&a.booking)?)?;
    ensure!(
        booking.schema == "horizon-epoch145-prefix-extraction-booking-v1"
            && booking.plan == *plan_bound
            && booking.owner == *owner
            && serde_json::to_value(&booking.inputs)? == serde_json::to_value(&a.inputs)?
            && booking.extractor_memory_bytes == MEMORY
            && booking.guard_memory_bytes == GUARD_MEMORY
            && booking.additional_data_bytes == EXTRA_DATA
            && booking.maximum_runtime_seconds == 86400,
        "booking omits the real frozen copy, output, lifetime or hard memory limits"
    );
    let f = read(&a.inputs.frontier)?;
    let o = read(&a.inputs.observer)?;
    let fleet = read(&a.inputs.fleet)?;
    let frame = read(&a.inputs.frame)?;
    let reader = read(&a.inputs.reader)?;
    let memory = read(&a.inputs.memory)?;
    let data = read(&a.inputs.data)?;
    let completion = read(&a.inputs.completion)?;
    ensure!(
        f["schema"] == "horizon-root-completed-native-frontier-and-next-admission-handoff-v1"
            && equals(&f["full_current_reader"], &a.inputs.reader)?
            && equals(&f["actual_memory_selection"], &a.inputs.memory)?
            && equals(&f["actual_DATA_selection"], &a.inputs.data)?
            && equals(
                &f["DATA_original_completion_normal_seal"],
                &a.inputs.completion
            )?
            && f["raw_memory_DATA_obligations_and_all_guards_preserved"] == true
            && f["original199_controller_PID_and_FD9_preserved"] == true,
        "not the actual complete frontier with retained original owners and guards"
    );
    let current = json!({"observer":a.inputs.observer,"fleet":a.inputs.fleet,
        "fleet_plan":data["data_selection"]["current"]["fleet_plan"],"frame":a.inputs.frame});
    ensure!(
        memory["schema"] == "terminal199-parent-memory-selector-original-execution-v1"
            && memory["actual_native_capability_passed"] == true
            && memory["capability_only"] == false
            && memory["selection"]["request"]["current"] == current
            && equals(
                &memory["selection"]["request"]["current_reader"],
                &a.inputs.reader
            )?
            && data["schema"] == "epoch183-native-ended-DATA-selector-original-execution-v1"
            && data["actual_native_capability_passed"] == true
            && data["data_selection"]["current"] == current
            && equals(&data["memory_selection"], &a.inputs.memory)?
            && reader["schema"] == "failed4-current-complete-accounting-reader-proof-v1"
            && reader["raw_history_preserved"] == true
            && reader["all_DATA_promises_preserved"] == true,
        "unqualified or crossed current memory/DATA/reader components"
    );
    let reader_spec: Bound = serde_json::from_value(reader["spec"].clone())?;
    let reader_spec = read(&reader_spec)?;
    ensure!(
        reader_spec["resource_accounting"]["observer"] == current["observer"]
            && reader_spec["resource_accounting"]["fleet"] == current["fleet"]
            && reader_spec["resource_accounting"]["fleet_plan"] == current["fleet_plan"]
            && reader_spec["captured141_memory_retirement"]["current"] == current
            && reader["physical_credit_bytes"] == 0
            && reader["DATA_credit_bytes"] == 0
            && reader["memory_budget_credit_applied_bytes"] == 0,
        "reader metadata does not bind the same complete tuple without new credits"
    );
    ensure!(
        data["physical_credit_bytes"] == 0
            && data["memory_credit_bytes"] == 0
            && data["archive_retirement_authorized"] == false
            && memory["selection"]["guards_changed"] == false
            && memory["selection"]["physical_credit_bytes"] == 0,
        "extraction may not create another resource or retirement credit"
    );
    ensure!(
        frame["schema"] == "jetstreamer-horizon-recovered-resource-frame-v1"
            && frame["accepted_resource_lineage"] == true
            && equals(&frame["bindings"]["observer"], &a.inputs.observer)?
            && equals(&frame["bindings"]["fleet"], &a.inputs.fleet)?
            && frame["bindings"]["fleet_plan"] == current["fleet_plan"]
            && fleet["observer_receipt"] == serde_json::to_value(&a.inputs.observer.path)?
            && fleet["observer_sha256"] == a.inputs.observer.sha256
            && completion["actual_DATA_selection"] == serde_json::to_value(&a.inputs.data)?,
        "frame/fleet/completed DATA chain does not bind the actual current tuple"
    );
    for proof in [&reader, &memory, &data, &frame] {
        ensure!(
            proof["r2_mutations"] == false && proof["replay_launch_authorized"] == false,
            "resource component acquires unrelated authority"
        );
    }
    let at = clock(o["recorded_at_utc"].as_str().context("observer clock")?)?;
    let finished = clock(
        o["completed_at_utc"]
            .as_str()
            .context("observer completion clock")?,
    )?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && at <= finished
            && finished <= owner.started_unix_seconds
            && at <= now
            && now - at <= 1800
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && fleet["sampled_at_utc"] == o["recorded_at_utc"],
        "stale tuple or held actor already ambiguously included in its base sample"
    );
    let existing = n(
        &memory["selection"],
        "effective_total_memory_promises_bytes",
    )?;
    let floor = n(&data, "effective_protected_DATA_bytes")?;
    ensure!(
        existing == n(&data, "memory_effective_total_bytes")?
            && existing == n(&f, "effective_existing_memory_bytes")?
            && floor == n(&f, "effective_existing_DATA_bytes")?
            && floor >= OLD_FLOOR
            && memory["selection"]["retained_original199_controller_bytes"] == (512u64 << 20)
            && memory["selection"]["retained_original199_guard_bytes"] == (512u64 << 20)
            && memory["selection"]["all_DATA_promises_preserved"] == true
            && memory["selection"]["controller_stopped"] == false,
        "admission drops retained memory/DATA/controller/guard obligations"
    );
    let external = n(&f, "normal_external_pool_bytes")?;
    ensure!(external >= (6u64 << 30), "normal external pool was reduced");
    let mut mem = add(add(existing, external)?, MEMORY + GUARD_MEMORY)?;
    let mut required = add(floor, EXTRA_DATA)?;
    let mut retained_data = 0u64;
    let mut seen = BTreeSet::new();
    for claim in booking.other_claims {
        ensure!(
            !claim.key.is_empty() && seen.insert(claim.key),
            "duplicate extra resource claim"
        );
        mem = add(mem, claim.memory_bytes)?;
        required = add(required, claim.data_bytes)?;
        retained_data = add(retained_data, claim.data_bytes)?;
    }
    ensure!(
        retained_data >= (16u64 << 30),
        "booking omitted the retained source/build/seal DATA phases"
    );
    let total = n(&o["host_memory"], "total_kib")?
        .checked_mul(1024)
        .context("host memory overflow")?;
    ensure!(
        mem <= total && required <= n(&o["filesystem"], "conservative_available_bytes")?,
        "full original obligations plus frozen copy/extraction do not fit"
    );
    ensure!(
        a.guard.program.path == PathBuf::from(GUARD_PATH)
            && a.guard.program.sha256 == GUARD_SHA
            && a.guard.receipt_directory == plan.state().join("guard"),
        "unqualified or foreign lifetime guard"
    );
    Ok(Budget {
        floor: required
            .checked_sub(EXTRA_DATA)
            .context("remaining allocation floor underflow")?,
        required_initial_free: required,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    fn b(name: &str) -> Bound {
        Bound {
            path: PathBuf::from(format!("/test/{name}.json")),
            sha256: "a".repeat(64),
        }
    }
    pub(crate) fn fixture() -> (Plan, Bound, Owner, Admission, BTreeMap<PathBuf, Value>) {
        let id = Identity {
            device: 1,
            inode: 2,
            bytes: SOURCE_BYTES,
            uid: 1001,
            gid: 1001,
            mode: 0o600,
            links: 1,
            mtime: 10,
            mtime_ns: 0,
            ctime: 10,
            ctime_ns: 0,
        };
        let mut mi = id.clone();
        mi.bytes = 1809;
        mi.inode = 3;
        let p = Plan {
            schema: "horizon-epoch145-prefix-extraction-plan-v1".into(),
            attempt: "0123456789abcdef".into(),
            program: Bound {
                path: "/usr/local/lib/jetstreamer/extractor/runner".into(),
                sha256: "c".repeat(64),
            },
            source: SOURCE.into(),
            source_identity: id,
            manifest: Bound {
                path: format!("{SOURCE}.segment.json").into(),
                sha256: MANIFEST_SHA.into(),
            },
            manifest_identity: mi,
            original_terminal: Bound {
                path: TERMINAL_PATH.into(),
                sha256: TERMINAL_SHA.into(),
            },
            hold_seconds: 300,
        };
        let pb = b("plan");
        let owner = Owner {
            unit: p.unit(),
            invocation_id: "d".repeat(32),
            pid: 123,
            start_ticks: 400,
            cgroup: format!("/system.slice/{}", p.unit()),
            started_unix_seconds: 1020,
            program_sha256: p.program.sha256.clone(),
        };
        let inputs = Inputs {
            frontier: b("frontier"),
            observer: b("observer"),
            fleet: b("fleet"),
            frame: b("frame"),
            reader: b("reader"),
            memory: b("memory"),
            data: b("data"),
            completion: b("completion"),
        };
        let a = Admission {
            schema: "horizon-epoch145-prefix-extraction-admission-v1".into(),
            plan: pb.clone(),
            owner: owner.clone(),
            inputs: inputs.clone(),
            booking: b("booking"),
            guard: Guard {
                program: Bound {
                    path: GUARD_PATH.into(),
                    sha256: GUARD_SHA.into(),
                },
                plan: b("guard-plan"),
                receipt_directory: p.state().join("guard"),
                first_sample: b("first-sample"),
            },
            not_before: 1030,
            expires: 1100,
        };
        let current = json!({"observer":inputs.observer,"fleet":inputs.fleet,"frame":inputs.frame,"fleet_plan":b("fleet-plan")});
        let frontier = json!({"schema":"horizon-root-completed-native-frontier-and-next-admission-handoff-v1","sampled_at_utc":"sample",
            "full_current_reader":inputs.reader,"actual_memory_selection":inputs.memory,"actual_DATA_selection":inputs.data,
            "DATA_original_completion_normal_seal":inputs.completion,"raw_memory_DATA_obligations_and_all_guards_preserved":true,
            "original199_controller_PID_and_FD9_preserved":true,"effective_existing_memory_bytes":500u64<<30,"effective_existing_DATA_bytes":OLD_FLOOR,"normal_external_pool_bytes":6u64<<30});
        let memory = json!({"schema":"terminal199-parent-memory-selector-original-execution-v1","actual_native_capability_passed":true,"capability_only":false,
            "r2_mutations":false,"replay_launch_authorized":false,"selection":{"request":{"current":current,"current_reader":inputs.reader},"effective_total_memory_promises_bytes":500u64<<30,
                "retained_original199_controller_bytes":512u64<<20,"retained_original199_guard_bytes":512u64<<20,"all_DATA_promises_preserved":true,"controller_stopped":false,"guards_changed":false,"physical_credit_bytes":0}});
        let data = json!({"schema":"epoch183-native-ended-DATA-selector-original-execution-v1","actual_native_capability_passed":true,"data_selection":{"current":current},
            "memory_selection":inputs.memory,"memory_effective_total_bytes":500u64<<30,"effective_protected_DATA_bytes":OLD_FLOOR,"r2_mutations":false,"replay_launch_authorized":false,"physical_credit_bytes":0,"memory_credit_bytes":0,"archive_retirement_authorized":false});
        let values = BTreeMap::from([
            (inputs.frontier.path.clone(), frontier),
            (inputs.memory.path.clone(), memory),
            (inputs.data.path.clone(), data),
            (
                inputs.observer.path.clone(),
                json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"sample","completed_at_utc":"finished","host_memory":{"total_kib":800u64<<20},"filesystem":{"conservative_available_bytes":OLD_FLOOR+EXTRA_DATA+(32u64<<30)}}),
            ),
            (
                inputs.fleet.path.clone(),
                json!({"observer_receipt":inputs.observer.path,"observer_sha256":inputs.observer.sha256,"sampled_at_utc":"sample"}),
            ),
            (
                inputs.frame.path.clone(),
                json!({"schema":"jetstreamer-horizon-recovered-resource-frame-v1","accepted_resource_lineage":true,"bindings":current,"r2_mutations":false,"replay_launch_authorized":false}),
            ),
            (
                inputs.reader.path.clone(),
                json!({"schema":"failed4-current-complete-accounting-reader-proof-v1","raw_history_preserved":true,"all_DATA_promises_preserved":true,"r2_mutations":false,"replay_launch_authorized":false,"spec":b("reader-spec"),"physical_credit_bytes":0,"DATA_credit_bytes":0,"memory_budget_credit_applied_bytes":0}),
            ),
            (
                b("reader-spec").path,
                json!({"resource_accounting":{"observer":current["observer"],"fleet":current["fleet"],"fleet_plan":current["fleet_plan"]},"captured141_memory_retirement":{"current":current}}),
            ),
            (
                inputs.completion.path.clone(),
                json!({"actual_DATA_selection":inputs.data}),
            ),
            (
                a.booking.path.clone(),
                json!({"schema":"horizon-epoch145-prefix-extraction-booking-v1","plan":pb,"owner":owner,"inputs":inputs,
                "other_claims":[{"key":"retained-builds","memory_bytes":0,"data_bytes":16u64<<30}],"maximum_runtime_seconds":86400,
                "extractor_memory_bytes":MEMORY,"guard_memory_bytes":GUARD_MEMORY,"additional_DATA_bytes":EXTRA_DATA}),
            ),
        ]);
        (p, pb, owner, a, values)
    }
    fn check(
        p: &Plan,
        pb: &Bound,
        owner: &Owner,
        a: &Admission,
        values: &BTreeMap<PathBuf, Value>,
        now: u64,
    ) -> Result<Budget> {
        admit(
            p,
            pb,
            owner,
            a,
            now,
            |b| {
                values
                    .get(&b.path)
                    .cloned()
                    .context("missing bound fixture")
            },
            |s| match s {
                "sample" => Ok(1000),
                "finished" => Ok(1010),
                _ => anyhow::bail!("invalid fixture UTC"),
            },
        )
    }
    #[test]
    fn actual_components_and_held_owner_are_joined_before_numeric_allocation() {
        let (p, pb, o, a, v) = fixture();
        let budget = check(&p, &pb, &o, &a, &v, 1040).unwrap();
        assert_eq!(budget.floor, OLD_FLOOR + (16u64 << 30));
        assert_eq!(budget.required_initial_free, budget.floor + EXTRA_DATA);
    }
    #[test]
    fn stale_release_wrong_owner_and_actor_preexisting_in_sample_reject() {
        let (p, pb, o, a, mut v) = fixture();
        assert!(check(&p, &pb, &o, &a, &v, 2801).is_err());
        let mut stale = a.clone();
        stale.not_before = 2800;
        stale.expires = 2900;
        assert!(check(&p, &pb, &o, &stale, &v, 2801).is_err());
        let mut bad = a.clone();
        bad.owner.pid += 1;
        assert!(check(&p, &pb, &o, &bad, &v, 1040).is_err());
        let mut early = o.clone();
        early.started_unix_seconds = 1005;
        let mut bad = a.clone();
        bad.owner = early.clone();
        v.get_mut(&a.booking.path).unwrap()["owner"] = serde_json::to_value(&early).unwrap();
        assert!(check(&p, &pb, &early, &bad, &v, 1040).is_err());
    }
    #[test]
    fn crossed_reader_and_unallocated_retained_phases_cannot_pass_numeric_booking() {
        let (p, pb, o, a, mut v) = fixture();
        v.get_mut(&b("reader-spec").path).unwrap()["resource_accounting"]["observer"] =
            json!(b("different-sample"));
        assert!(check(&p, &pb, &o, &a, &v, 1040).is_err());
        let (p, pb, o, a, mut v) = fixture();
        v.get_mut(&a.booking.path).unwrap()["other_claims"] = json!([]);
        assert!(check(&p, &pb, &o, &a, &v, 1040).is_err());
        let (p, pb, o, a, mut v) = fixture();
        v.get_mut(&a.inputs.frontier.path).unwrap()["normal_external_pool_bytes"] = json!(0);
        assert!(check(&p, &pb, &o, &a, &v, 1040).is_err());
    }
    #[test]
    fn changing_parent_guard_or_data_obligations_does_not_create_capacity() {
        for path in [
            "/selection/retained_original199_controller_bytes",
            "/selection/retained_original199_guard_bytes",
        ] {
            let (p, pb, o, a, mut v) = fixture();
            *v.get_mut(&a.inputs.memory.path)
                .unwrap()
                .pointer_mut(path)
                .unwrap() = json!(0);
            assert!(check(&p, &pb, &o, &a, &v, 1040).is_err());
        }
        let (p, pb, o, a, mut v) = fixture();
        v.get_mut(&a.inputs.data.path).unwrap()["effective_protected_DATA_bytes"] = json!(0);
        assert!(check(&p, &pb, &o, &a, &v, 1040).is_err());
    }
    #[test]
    fn omitted_real_copy_allocation_and_duplicate_extra_claims_reject() {
        let (p, pb, o, a, mut v) = fixture();
        v.get_mut(&a.booking.path).unwrap()["additional_DATA_bytes"] = json!(OUTPUT + METADATA);
        assert!(check(&p, &pb, &o, &a, &v, 1040).is_err());
        let (p, pb, o, a, mut v) = fixture();
        let claims = v.get_mut(&a.booking.path).unwrap()["other_claims"]
            .as_array_mut()
            .unwrap();
        claims.push(claims[0].clone());
        assert!(check(&p, &pb, &o, &a, &v, 1040).is_err());
    }
    #[test]
    fn crossed_tuple_and_insufficient_full_free_space_reject() {
        let (p, pb, o, a, mut v) = fixture();
        v.get_mut(&a.inputs.frame.path).unwrap()["bindings"]["observer"] = json!(b("wrong"));
        assert!(check(&p, &pb, &o, &a, &v, 1040).is_err());
        let (p, pb, o, a, mut v) = fixture();
        v.get_mut(&a.inputs.observer.path).unwrap()["filesystem"]["conservative_available_bytes"] =
            json!(OLD_FLOOR + OUTPUT);
        assert!(check(&p, &pb, &o, &a, &v, 1040).is_err());
    }
    #[test]
    fn plan_never_authorizes_original_chmod_or_a_different_epoch_source() {
        let (mut p, _, _, _, _) = fixture();
        p.source_identity.mode = 0o400;
        assert!(p.validate().is_err());
        let (mut p, _, _, _, _) = fixture();
        p.source = "/other/epoch-146.jet".into();
        assert!(p.validate().is_err());
    }
    #[test]
    fn separate_frozen_copy_is_real_additional_data_not_retired_source_credit() {
        assert_eq!(EXTRA_DATA, 278_506_182_351);
        assert!(EXTRA_DATA > OUTPUT + METADATA);
    }
    #[test]
    fn ordinary_approval_boolean_cannot_deserialize_as_release_or_admission() {
        assert!(serde_json::from_value::<Release>(json!({"approved":true})).is_err());
        assert!(serde_json::from_value::<Admission>(json!({"admitted":true})).is_err());
    }
    #[test]
    fn invalid_names_and_overflow_cannot_create_capacity() {
        assert!(hex("0123456789abcdef", 16));
        assert!(!hex("0123456789abcde/", 16));
        assert!(add(u64::MAX, 1).is_err());
    }
}
