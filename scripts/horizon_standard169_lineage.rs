//! Pinned standard epoch 169 CPU booking and historical launch routes.
use crate::standard169_cpu_lease::STANDARD169_PLAN as STANDARD;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};

pub const MEASURE: (&str, &str) = (
    "local3-preparation-operation-20261112-v2/MEASURE_CONTROL.json",
    "08389bfc34aa5863439c778bc1c91c10a641867fc4898fdaa489bb87d4e3b3bf",
);
const TEMPLATE: (&str, &str) = (
    "local2-scratch-retirement-source-preparation-20261112-v1/local3/ROOT_CONTROL.SOURCE_TEMPLATE.json",
    "d9c18548f50a1cc7ec742f0d9657d84415ec0b2e84c9a40277611dd0f38d591c",
);
const NATIVE: (&str, &str) = (
    "retry3-peer169-guarded-launch-20261113-v1/epoch169/ACTUAL_PRODUCER_NATIVE.json",
    "f9af27b04da8f30c6601205ae9f41bab916819097da99c8fb77b29347fd764b4",
);
const ARGV: (&str, &str) = (
    "retry3-peer169-guarded-launch-20261113-v1/epoch169/ORIGINAL_PRODUCER_ARGV.json",
    "9510a75208becd7a7a7b2987cc2df22f795adc890c68f590f58a23ef43103ac3",
);

pub fn focused_family(name: &str) -> bool {
    name.starts_with("horizon-qualify-169-focused-")
        || name.starts_with("horizon-guard-169-focused-")
}

pub fn standard_names(route: &Value, discovered: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let mut fixed: BTreeSet<String> = serde_json::from_value(route["closed_units"].clone())?;
    let actor = route["producer_unit"]
        .as_str()
        .context("standard 169 unit")?;
    ensure!(
        fixed.len() == 27
            && fixed.contains(actor)
            && fixed.contains("jetstreamer-epochs159-173-target1-controller-v1-r2.service")
            && route["closed_units"]
                .as_array()
                .is_some_and(|v| v.len() == fixed.len())
            && fixed.iter().all(|v| !focused_family(v)),
        "original 169 closure changed"
    );
    // Prepare helpers from the actual retry3 operation may already have been collected by PID 1.
    for u in [
        "horizon-local-replacement169-check-only-retry3-peer169-20261113-v1.service",
        "horizon-local-replacement169-check-only-retry3-peer169-20261113-v2.service",
        "horizon-local-replacement169-measure-only-retry3-peer169-20261113-v2.service",
        "horizon-local-replacement169-prepare-retry3-peer169-20261113-v2.service",
        "horizon-local-replacement169-prepare-local2-r2-20261110-v11.service",
        "horizon-retry3-peer169-native-operation-20261113-v1.service",
        "horizon-retry3-peer169-native-operation-20261113-v2.service",
    ] {
        fixed.insert(u.to_owned());
    }
    fixed.extend(discovered.iter().filter(|u| !focused_family(u)).cloned());
    Ok(fixed)
}

pub fn standard_source(root: &Path, read: impl Fn(&Path, &str) -> Result<Value>) -> Result<Value> {
    let control = read(&root.join(MEASURE.0), MEASURE.1)?;
    let template = read(&root.join(TEMPLATE.0), TEMPLATE.1)?;
    ensure!(
        control["measure_plans"]
            .as_object()
            .context("historical plans")?
            .keys()
            .map(String::as_str)
            .eq(["166", "167", "169", "170"])
            && template["complete_booked_cpu_quota_micros"]
                == "UNRESOLVED_ACTUAL_COMPLETE_CPU_QUOTA_INCLUDING_ALL4",
        "43-core booking does not bind four actors"
    );
    for (epoch, review_sha, native_sha) in [
        (
            166,
            "fb4169614881856fd54b34ac2bba7084835ddaabf8d09839aae1f24e17c69687",
            "c180951c9190a2e036f6c5e631549f1f080ee930919d0571bc4318ffcf6548f9",
        ),
        (
            167,
            "9dfadb367f4e1c5753f4fb7400710d0572f5aa4898be7b86c2732ee0e8bc0570",
            "d99f578a9c7a5e8959b9c9428e5b5d2dc67d789cf28c20632971b69a3f3b3c5b",
        ),
        (
            169,
            "22af8f0473bcbafacb1b917f23ff689247c2bba2550a6b25396f9dcca07ecfff",
            "c640be6087639116e530f2d3d22b09d4741694ef5b2a7557aade34c3b87b8721",
        ),
        (
            170,
            "22a7b8125f818038fe8912e63a2b2c4a9555cb0407d75f2401e1547801f5e5c7",
            "74f722daeecb30e4d1540fdedd6be4e5a9ec6c3b2b9cefd5c3a23fe9894c5ba8",
        ),
    ] {
        let review = read(&root.join(format!("local3-preparation-operation-20261112-v3/epoch{epoch}/epoch{epoch}-PRELAUNCH_REVIEW.json")), review_sha)?;
        let native = read(
            &root.join(format!(
                "local3-guarded-launch-20261112-v2/epoch{epoch}/ACTUAL_PRODUCER_NATIVE.json"
            )),
            native_sha,
        )?;
        ensure!(
            review["epoch"] == epoch
                && review["complete_booked_cpu_quota_micros"]
                    == control["complete_booked_cpu_quota_micros"]
                && review["all_prior_promises_retained"] == true
                && review["exclusive_original_slot_replacement"] == true
                && native["Id"]
                    == format!("horizon-qualify-{epoch}-replacement-local3-20261110-v1.service")
                && native["ActiveState"] == "active"
                && native["CPUQuotaPerSecUSec"] == "9s",
            "historical epoch {epoch} does not bind its portion of the common CPU booking"
        );
    }
    let route = read(&root.join(STANDARD.0), STANDARD.1)?;
    let native = read(&root.join(NATIVE.0), NATIVE.1)?;
    let argv: Vec<String> = serde_json::from_value(read(&root.join(ARGV.0), ARGV.1)?)?;
    let review = &route["review"];
    let path = Path::new(review["path"].as_str().context("retry3 review path")?);
    let rev = read(
        path,
        review["sha256"].as_str().context("retry3 review digest")?,
    )?;
    ensure!(
        route["epoch"] == 169
            && rev["epoch"] == 169
            && rev["exclusive_original_slot_replacement"] == true
            && rev["complete_booked_cpu_quota_micros"]
                == control["complete_booked_cpu_quota_micros"]
            && native["CPUQuotaPerSecUSec"] == "9s"
            && native["ActiveState"] == "active"
            && native["Id"] == route["producer_unit"]
            && argv.contains(&format!(
                "--unit={}",
                native["Id"].as_str().context("original unit")?
            ))
            && argv.contains(&"--property=CPUQuota=900%".into()),
        "retry3 CPU ownership changed"
    );
    Ok(route)
}
