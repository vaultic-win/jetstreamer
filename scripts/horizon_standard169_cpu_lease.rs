//! Source contract for borrowing the standard epoch 169 CPU reservation.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, io::ErrorKind, path::Path};

pub const OPERATION_LOCK: &str = "/run/horizon-epoch171-to136-g1.operation.lock";
pub const REGISTRY_136: &str = "/run/horizon-epoch171-exclusive-to136-g1";
// The legacy dispatcher checks this directory name under OPERATION_LOCK.
pub const REGISTRY_171: &str = "/run/horizon-standard169-cpu-lease-to171-v1";
pub const STANDARD169_PLAN: (&str, &str) = (
    "retry3-peer169-native-operation-20261113-v2/epoch169/epoch169-PREPARE_PLAN.json",
    "6251beb7e726ce4cc395b4c7034a72d0a2e6311a2ce206de0f6a2c148b8acbd8",
);
pub const STANDARD169_CPU: u64 = 9_000_000;
pub const PRODUCER_171_CPU: u64 = 3_000_000;
pub const GUARD_171_CPU: u64 = 1_000_000;
pub const BORROW_171_CPU: u64 = PRODUCER_171_CPU + GUARD_171_CPU;
pub const RETAIN_STANDARD169_CPU: u64 = STANDARD169_CPU - BORROW_171_CPU;

const COHORT_CONTROLLER: &str = "e159-173-t1-20261016-v1-r2";
const DEDICATED_PREFIXES: &[&str] = &[
    "horizon-qualify-169-",
    "horizon-guard-169-",
    "horizon-guard-replacement-169-",
    "horizon-replacement-169-",
    "horizon-local-replacement169-",
];

/// Hold OPERATION_LOCK across this check and the dependent mutation.
/// A partially created directory, foreign node or dangling symlink reserves the slot.
pub fn require_unclaimed(registry: &Path) -> Result<()> {
    match fs::symlink_metadata(registry) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", registry.display())),
        Ok(_) => anyhow::bail!("occupied or partial CPU lease at {}", registry.display()),
    }
}

fn dedicated_standard169(name: &str) -> bool {
    let base = name
        .strip_suffix(".service")
        .or_else(|| name.strip_suffix(".timer"));
    base.is_some_and(|name| {
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && !name.starts_with("horizon-qualify-169-focused-")
            && !name.starts_with("horizon-guard-169-focused-")
            && (DEDICATED_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
                || name.strip_prefix("horizon-retry").is_some_and(|rest| {
                    rest.split_once("-peer169-")
                        .is_some_and(|(generation, suffix)| {
                            !generation.is_empty() && !suffix.is_empty()
                        })
                }))
    })
}

/// Identify CPU-bearing children of the shared legacy controller. A malformed
/// name in its namespace is an error so a census cannot silently skip it.
pub fn legacy_child_overlaps_169(unit: &str) -> Result<bool> {
    for kind in ["sweep", "source-recovery", "import"] {
        let prefix = format!("jetstreamer-root-{kind}-{COHORT_CONTROLLER}-");
        let Some(rest) = unit.strip_prefix(&prefix) else {
            continue;
        };
        let name = rest
            .strip_prefix('e')
            .and_then(|name| name.strip_suffix(".service"))
            .context("invalid legacy cohort child")?;
        let mut fields = name.splitn(3, '-');
        let mut bound = || -> Result<u64> {
            let raw = fields.next().context("missing legacy cohort bound")?;
            let n: u64 = raw.parse().context("invalid legacy cohort bound")?;
            ensure!(n.to_string() == raw, "noncanonical legacy cohort bound");
            Ok(n)
        };
        let first = bound()?;
        let last = bound()?;
        let suffix = fields
            .next()
            .context("missing legacy cohort child suffix")?;
        ensure!(
            159 <= first
                && first <= last
                && last <= 173
                && suffix.split('-').all(|field| {
                    !field.is_empty()
                        && field
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                }),
            "invalid legacy cohort child scope"
        );
        return Ok(first <= 169 && 169 <= last);
    }
    Ok(false)
}

fn hex_id(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().any(|b| b != b'0')
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn intent_171(boot_id: &str, generation: &str) -> Result<Value> {
    let groups: Vec<_> = boot_id.split('-').collect();
    ensure!(
        groups.iter().map(|group| group.len()).eq([8, 4, 4, 4, 12])
            && hex_id(&groups.concat(), 32)
            && hex_id(generation, 32),
        "invalid 171 lease boot or generation"
    );
    Ok(json!({
        "schema":"horizon-standard169-cpu-lease-171-intent-v1",
        "boot_id":boot_id,
        "generation":generation,
        "standard_route":{
            "path":Path::new("/var/lib/jetstreamer").join(STANDARD169_PLAN.0),
            "sha256":STANDARD169_PLAN.1,
        },
        "producer_cpu_micros":PRODUCER_171_CPU,
        "guard_cpu_micros":GUARD_171_CPU,
        "retained_standard169_cpu_micros":RETAIN_STANDARD169_CPU,
    }))
}

/// Fields from the current independently checked mask, producer and timer.
/// The caller obtains these under the shared operation lock and authenticates
/// the route inventory, mask links and unit states before comparing receipts.
pub struct Lease171Evidence<'a> {
    pub boot_id: &'a str,
    pub generation: &'a str,
    pub mask_anchor: (u64, u64),
    pub dedicated_masks: &'a BTreeSet<String>,
    pub producer_iid: &'a str,
    pub guard_timer_iid: &'a str,
}

impl Lease171Evidence<'_> {
    pub fn committed(&self) -> Result<Value> {
        ensure!(
            self.mask_anchor.1 != 0
                && !self.dedicated_masks.is_empty()
                && self
                    .dedicated_masks
                    .iter()
                    .all(|name| dedicated_standard169(name))
                && hex_id(self.producer_iid, 32)
                && hex_id(self.guard_timer_iid, 32)
                && self.producer_iid != self.guard_timer_iid,
            "invalid 171 owned fence or protected invocations"
        );
        Ok(json!({
            "schema":"horizon-standard169-cpu-lease-171-committed-v1",
            "intent":intent_171(self.boot_id, self.generation)?,
            "mask_device":self.mask_anchor.0,
            "mask_inode":self.mask_anchor.1,
            "dedicated_standard169_masks":self.dedicated_masks,
            "producer_invocation_id":self.producer_iid,
            "guard_timer_invocation_id":self.guard_timer_iid,
        }))
    }

    pub fn verify(&self, intent: Option<&Value>, committed: Option<&Value>) -> Result<()> {
        ensure!(
            intent == Some(&intent_171(self.boot_id, self.generation)?)
                && committed == Some(&self.committed()?),
            "partial or mismatched 171 CPU lease"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "12345678-0000-4000-8000-000000000000";
    const GENERATION: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn legacy_parser_includes_each_cpu_bearing_entry_and_excludes_other_epochs() {
        for kind in ["sweep", "source-recovery", "import"] {
            for (tail, overlaps) in [
                ("e167-170-lane-a-1.service", true),
                ("e167-170-2.service", true),
                ("e169-169-3.service", true),
                ("e169-173-r3.service", true),
                ("e159-162-lane-a-1.service", false),
                ("e171-173-1.service", false),
            ] {
                let unit = format!("jetstreamer-root-{kind}-{COHORT_CONTROLLER}-{tail}");
                assert_eq!(
                    legacy_child_overlaps_169(&unit).unwrap(),
                    overlaps,
                    "{unit}"
                );
            }
            for tail in [
                "e167-17O-1.service",
                "e167-0170-1.service",
                "e170-167-1.service",
                "e167-174-1.service",
                "e167-170-.service",
                "e167-170-../1.service",
                "e167-170-1.timer",
            ] {
                let unit = format!("jetstreamer-root-{kind}-{COHORT_CONTROLLER}-{tail}");
                assert!(legacy_child_overlaps_169(&unit).is_err(), "{unit}");
            }
        }
        assert!(
            !legacy_child_overlaps_169("horizon-qualify-169-focused-hourly-20261123-v1.service")
                .unwrap()
        );
        assert!(
            !legacy_child_overlaps_169("jetstreamer-root-import-other-e167-170-1.service").unwrap()
        );
    }

    #[test]
    fn a_registry_blocks_rivals_from_its_first_filesystem_entry() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        require_unclaimed(&registry).unwrap();
        fs::create_dir(&registry).unwrap();
        assert!(require_unclaimed(&registry).is_err());
        fs::remove_dir(&registry).unwrap();
        std::os::unix::fs::symlink("missing", &registry).unwrap();
        assert!(require_unclaimed(&registry).is_err());
    }

    #[test]
    fn a_complete_lease_matches_its_generation_quota_and_live_fence() {
        assert_eq!(
            (BORROW_171_CPU, RETAIN_STANDARD169_CPU),
            (4_000_000, 5_000_000)
        );
        let routes = BTreeSet::from(["horizon-qualify-169-standard-20261109-v1.service".into()]);
        let mut evidence = Lease171Evidence {
            boot_id: BOOT,
            generation: GENERATION,
            mask_anchor: (26, 110),
            dedicated_masks: &routes,
            producer_iid: "11111111111111111111111111111111",
            guard_timer_iid: "22222222222222222222222222222222",
        };
        let intent = intent_171(BOOT, GENERATION).unwrap();
        let committed = evidence.committed().unwrap();
        evidence.verify(Some(&intent), Some(&committed)).unwrap();
        assert!(evidence.verify(Some(&intent), None).is_err());
        assert!(evidence.verify(None, Some(&committed)).is_err());
        for key in [
            "producer_cpu_micros",
            "guard_cpu_micros",
            "retained_standard169_cpu_micros",
        ] {
            let mut wrong = intent.clone();
            wrong[key] = json!(0);
            assert!(evidence.verify(Some(&wrong), Some(&committed)).is_err());
        }
        for key in [
            "intent",
            "mask_inode",
            "producer_invocation_id",
            "guard_timer_invocation_id",
        ] {
            let mut wrong = committed.clone();
            wrong.as_object_mut().unwrap().remove(key);
            assert!(evidence.verify(Some(&intent), Some(&wrong)).is_err());
        }
        evidence.generation = "33333333333333333333333333333333";
        assert!(evidence.verify(Some(&intent), Some(&committed)).is_err());
        evidence.generation = GENERATION;
        evidence.boot_id = "22345678-0000-4000-8000-000000000000";
        assert!(evidence.verify(Some(&intent), Some(&committed)).is_err());
        assert!(intent_171(BOOT, "00000000000000000000000000000000").is_err());
        assert!(intent_171("12345678000040008000000000000000", GENERATION).is_err());
    }

    #[test]
    fn dedicated_masks_exclude_hourly_and_shared_routes() {
        for name in [
            "horizon-qualify-169-focused-hourly-20261123-v1.service",
            "horizon-guard-169-focused-hourly-20261123-v1.timer",
            "horizon-169-hourly-terminal-20261123-v1.service",
            "jetstreamer-epochs159-173-target1-controller-v1-r2.service",
            "jetstreamer-root-import-e159-173-t1-20261016-v1-r2-e167-170-2.service",
            "horizon-admit-136-actual-20261120-g1.service",
            "horizon-qualify-167-standard-20261109-v1.service",
        ] {
            assert!(!dedicated_standard169(name), "{name}");
        }
        assert!(dedicated_standard169(
            "horizon-retry3-peer169-native-operation-20261113-v2.service"
        ));
    }
}
