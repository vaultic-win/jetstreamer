//! Optional host-wide evidence, never an admission decision or a second sampler.
use anyhow::{Context, Result, anyhow, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path, time::SystemTime};

fn bounded_text(path: &Path) -> Result<String> {
    let mut text = String::new();
    File::open(path)?.take(4097).read_to_string(&mut text)?;
    ensure!(text.len() <= 4096, "host pressure input exceeds bound");
    Ok(text)
}

fn totals(text: &str, resource: &str) -> Result<BTreeMap<String, u64>> {
    let mut counters = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let class = fields.next().ok_or_else(|| anyhow!("empty PSI line"))?;
        ensure!(matches!(class, "some" | "full"), "unknown PSI class");
        let mut total = None;
        for field in fields {
            if let Some(value) = field.strip_prefix("total=") {
                ensure!(total.is_none(), "duplicate PSI total");
                total = Some(value.parse::<u64>().context("invalid PSI total")?);
            }
        }
        let total = total.ok_or_else(|| anyhow!("missing PSI total"))?;
        ensure!(
            counters
                .insert(format!("{resource}.{class}_total_usec"), total)
                .is_none(),
            "duplicate PSI class"
        );
    }
    ensure!(
        counters.contains_key(&format!("{resource}.some_total_usec")),
        "missing PSI some"
    );
    // Older kernels legitimately omit CPU full; memory and I/O require both.
    ensure!(
        resource == "cpu" || counters.contains_key(&format!("{resource}.full_total_usec")),
        "missing PSI full"
    );
    Ok(counters)
}

pub fn capture(proc_root: &Path) -> Value {
    let result = (|| -> Result<Value> {
        let boot_id = bounded_text(&proc_root.join("sys/kernel/random/boot_id"))?;
        let boot_id = boot_id.trim();
        ensure!(
            boot_id.len() == 36
                && boot_id.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                }),
            "invalid boot ID"
        );
        let mut counters = BTreeMap::new();
        for resource in ["cpu", "memory", "io"] {
            counters.extend(totals(
                &bounded_text(&proc_root.join("pressure").join(resource))?,
                resource,
            )?);
        }
        let sampled_unix_millis = u64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis(),
        )?;
        Ok(
            json!({"status": "observed", "boot_id": boot_id, "sampled_unix_millis": sampled_unix_millis, "counters": counters}),
        )
    })();
    match result {
        Ok(value) => value,
        Err(error) => json!({"status": "unavailable", "error": format!("{error:#}")}),
    }
}

pub fn delta(previous: &Value, current: &Value) -> Value {
    let result = (|| -> Result<Value> {
        ensure!(
            previous["status"] == "observed" && current["status"] == "observed",
            "host PSI endpoint unavailable or predecessor absent"
        );
        ensure!(
            previous["boot_id"] == current["boot_id"] && current["boot_id"].is_string(),
            "host boot changed"
        );
        let before = previous["sampled_unix_millis"]
            .as_u64()
            .ok_or_else(|| anyhow!("missing previous timestamp"))?;
        let after = current["sampled_unix_millis"]
            .as_u64()
            .ok_or_else(|| anyhow!("missing current timestamp"))?;
        let elapsed = after
            .checked_sub(before)
            .filter(|v| *v > 0)
            .ok_or_else(|| anyhow!("non-increasing host PSI timestamp"))?;
        let before = previous["counters"]
            .as_object()
            .ok_or_else(|| anyhow!("missing previous counters"))?;
        let after = current["counters"]
            .as_object()
            .ok_or_else(|| anyhow!("missing current counters"))?;
        ensure!(
            before.keys().eq(after.keys()) && !after.is_empty(),
            "host PSI counter set changed"
        );
        let mut deltas = BTreeMap::new();
        for (key, value) in after {
            let old = before[key]
                .as_u64()
                .ok_or_else(|| anyhow!("invalid previous counter"))?;
            let new = value
                .as_u64()
                .ok_or_else(|| anyhow!("invalid current counter"))?;
            deltas.insert(
                key,
                new.checked_sub(old)
                    .ok_or_else(|| anyhow!("host PSI counter decreased"))?,
            );
        }
        Ok(json!({"status": "observed", "elapsed_millis": elapsed, "counter_delta_usec": deltas}))
    })();
    match result {
        Ok(value) => value,
        Err(error) => json!({"status": "unavailable", "error": format!("{error:#}")}),
    }
}

pub fn report(before: Value, after: Value, previous_after: &Value) -> Value {
    json!({
        "scope": "host-global-proc-pressure",
        "before": before,
        "after": after,
        "within_observation": delta(&before, &after),
        "cross_sample": delta(previous_after, &after),
        "admission_authorized": false,
        "cgroup_pressure_is_host_pressure": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_cpu_without_full_but_not_missing_memory_full() {
        assert_eq!(
            totals("some avg10=0.00 total=12\n", "cpu").unwrap()["cpu.some_total_usec"],
            12
        );
        assert!(totals("some total=12\n", "memory").is_err());
        assert!(totals("some total=12\nfull total=3\n", "io").is_ok());
    }

    #[test]
    fn rejects_malformed_or_ambiguous_counters() {
        for text in [
            "",
            "some total=1 total=2",
            "some total=-1",
            "some total=18446744073709551616",
            "some avg10=0",
            "some total=1\nsome total=2",
            "other total=1",
        ] {
            assert!(totals(text, "cpu").is_err(), "{text}");
        }
    }

    fn endpoint(time: u64, total: u64) -> Value {
        json!({"status": "observed", "boot_id": "same", "sampled_unix_millis": time, "counters": {"memory.full_total_usec": total}})
    }

    #[test]
    fn cross_sample_requires_same_boot_monotonic_time_and_counters() {
        let before = endpoint(1000, 7);
        let after = endpoint(1801000, 17);
        let result = delta(&before, &after);
        assert_eq!(result["elapsed_millis"], 1800000);
        assert_eq!(result["counter_delta_usec"]["memory.full_total_usec"], 10);
        for invalid in [
            endpoint(1000, 17),
            endpoint(999, 17),
            endpoint(1801000, 6),
            Value::Null,
            json!({"status": "unavailable"}),
        ] {
            assert_eq!(delta(&before, &invalid)["status"], "unavailable");
        }
        let mut changed = after.clone();
        changed["boot_id"] = json!("different");
        assert_eq!(delta(&before, &changed)["status"], "unavailable");
        changed = after;
        changed["counters"]["cpu.some_total_usec"] = json!(1);
        assert_eq!(delta(&before, &changed)["status"], "unavailable");
    }

    #[test]
    fn missing_or_oversized_proc_input_is_explicitly_unavailable() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(capture(root.path())["status"], "unavailable");
        let path = root.path().join("oversized");
        std::fs::write(&path, "x".repeat(4097)).unwrap();
        assert!(bounded_text(&path).is_err());
    }

    #[test]
    fn captures_all_three_resources_from_bounded_fixture() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("sys/kernel/random")).unwrap();
        std::fs::create_dir(root.path().join("pressure")).unwrap();
        let boot = root.path().join("sys/kernel/random/boot_id");
        std::fs::write(&boot, "12345678-1234-1234-1234-123456789abc\n").unwrap();
        for resource in ["cpu", "memory", "io"] {
            std::fs::write(
                root.path().join("pressure").join(resource),
                "some avg10=0.00 total=41\nfull avg10=0.00 total=3\n",
            )
            .unwrap();
        }
        let sample = capture(root.path());
        assert_eq!(sample["status"], "observed");
        assert_eq!(sample["counters"].as_object().unwrap().len(), 6);
        assert_eq!(sample["counters"]["memory.full_total_usec"], 3);
        std::fs::write(&boot, "invalid").unwrap();
        assert_eq!(capture(root.path())["status"], "unavailable");
    }

    #[test]
    fn report_never_grants_admission_or_substitutes_cgroup_evidence() {
        let report = report(endpoint(1000, 7), endpoint(2000, 8), &Value::Null);
        assert_eq!(report["cross_sample"]["status"], "unavailable");
        assert_eq!(report["within_observation"]["status"], "observed");
        assert_eq!(report["admission_authorized"], false);
        assert_eq!(report["cgroup_pressure_is_host_pressure"], false);
    }
}
