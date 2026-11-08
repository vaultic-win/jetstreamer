//! Exact finite R4-equivalent reload audit. Calendar jitter is limited to named
//! OS timers and their unchanged actual RandomizedDelayUSec/source policies.
use crate::*;
use std::collections::BTreeMap;
const RANDOMIZED: &[&str] = &[
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    "motd-news.timer",
    "e2scrub_all.timer",
    "update-notifier-motd.timer",
    "rotate-console-password.timer",
    "fwupd-refresh.timer",
    "certbot.timer",
    "man-db.timer",
    "mdmonitor-oneshot.timer",
    "fstrim.timer",
    "mdcheck_start.timer",
    "mdcheck_continue.timer",
    "snapd.snap-repair.timer",
    "ua-timer.timer",
];
const PROTECTIVE: &[&str] = &[
    "horizon-guard145-prefix-shared72h-20261107-v8g1.timer",
    "horizon-guard145-prefix-real1328-20261106-v1.timer",
    "jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.timer",
    "jetstreamer-adaptive-reserve-controller-rebind-183-184-20261023-v1.timer",
    "jetstreamer-adaptive-reserve-memory152-recovery-20261024-v1.timer",
    "jetstreamer-adaptive-reserve-controller-rebind-155-156-20261023-v1.timer",
    "jetstreamer-adaptive-reserve-package-rebind-198-20261021-v1.timer",
];
fn call(r: &mut process::Runner<'_>, label: &str, args: &[&str]) -> Result<Vec<u8>> {
    let mut c = Command::new("/usr/bin/systemctl");
    c.args(args);
    let x = r.run(label, c, Duration::from_secs(10))?;
    Ok(serde_json::from_value(x["stdout_bytes"].clone())?)
}
pub fn capture(r: &mut process::Runner<'_>, side: &str) -> Result<Value> {
    capture_selected(r, side, None)
}
pub fn capture_after(r: &mut process::Runner<'_>, side: &str, before: &Value) -> Result<Value> {
    capture_selected(r, side, Some(before))
}
fn capture_selected(
    r: &mut process::Runner<'_>,
    side: &str,
    before: Option<&Value>,
) -> Result<Value> {
    let rows: Value = serde_json::from_slice(&call(
        r,
        &format!("timers-{side}"),
        &["list-timers", "--all", "--no-pager", "--output=json"],
    )?)?;
    let mut policies = json!({});
    for row in rows.as_array().context("real list-timers JSON")? {
        // Only pending deadlines participate in reload validation. Keep all raw
        // rows, including elapsed/stopped timers, without opening their sources.
        if n_or_zero(row, "next")? == 0
            && before.is_none_or(|v| v["policies"].get(text(row, "unit").unwrap_or("")).is_none())
        {
            continue;
        }
        let name = text(row, "unit")?;
        ensure!(
            unit_name(name) && name.ends_with(".timer"),
            "timer identity"
        );
        let raw = call(
            r,
            &format!("timer-policy-{side}"),
            &[
                "show",
                name,
                "--no-pager",
                "--property=Id,LoadState,FragmentPath,DropInPaths,RandomizedDelayUSec,FixedRandomDelay,AccuracyUSec,Unit,Persistent,RemainAfterElapse,WakeSystem",
            ],
        )?;
        let mut native = json!({});
        for line in std::str::from_utf8(&raw)?.lines() {
            let (k, v) = line.split_once('=').context("timer policy framing")?;
            ensure!(native.get(k).is_none(), "duplicate timer policy");
            native[k] = json!(v);
        }
        ensure!(
            native["Id"] == name
                && native["LoadState"] == "loaded"
                && native["Unit"] == row["activates"],
            "exact native timer trigger"
        );
        let mut sources = Vec::new();
        let paths = std::iter::once(text(&native, "FragmentPath")?)
            .chain(text(&native, "DropInPaths")?.split_whitespace());
        for p in paths {
            sources.push(timer_source(Path::new(p))?);
        }
        policies[name] = json!({"native":native,"sources":sources});
    }
    Ok(json!({"rows":rows,"policies":policies}))
}
fn timer_source(path: &Path) -> Result<Value> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_symlink() {
        return Ok(json!({"declared_path":path,"source":process::bind_file(path,131072)?}));
    }
    ensure!(
        before.uid() == 0 && before.nlink() == 1 && path.starts_with("/etc/systemd/system"),
        "timer alias custody/namespace"
    );
    let target = fs::read_link(path)?;
    ensure!(
        target.is_absolute()
            && target.starts_with("/usr/local/lib/jetstreamer")
            && target.canonicalize()? == target,
        "timer alias normal destination"
    );
    let member = process::bind_file(&target, 131072)?;
    let seal_bound = process::bind_file(
        &target.with_file_name("deployment-seal-receipt.json"),
        16 << 20,
    )?;
    let seal = storage::json(&seal_bound)?;
    let leaf = target.file_name().context("timer leaf")?.to_string_lossy();
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"]
                == target
                    .parent()
                    .context("timer member parent")?
                    .to_string_lossy()
                    .as_ref()
            && seal["members"]
                .as_array()
                .context("timer normal members")?
                .iter()
                .filter(|m| m["name"] == leaf.as_ref()
                    && m["sha256"] == member.sha256
                    && m["mode"] == "0444")
                .count()
                == 1,
        "timer alias exact normally sealed member"
    );
    let after = fs::symlink_metadata(path)?;
    ensure!(
        fs::read_link(path)? == target
            && (
                before.dev(),
                before.ino(),
                before.uid(),
                before.mode(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ) == (
                after.dev(),
                after.ino(),
                after.uid(),
                after.mode(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            ),
        "timer alias changed"
    );
    Ok(
        json!({"declared_path":path,"source":member,"normal_seal":seal_bound,"alias_identity":{"dev":before.dev(),"ino":before.ino(),"uid":before.uid(),"mode":before.mode(),"mtime":before.mtime(),"mtime_nsec":before.mtime_nsec(),"ctime":before.ctime(),"ctime_nsec":before.ctime_nsec()}}),
    )
}
fn n_or_zero(v: &Value, k: &str) -> Result<u64> {
    if v[k].is_null() { Ok(0) } else { n(v, k) }
}
fn span(raw: &str) -> Result<u64> {
    let mut total = 0u64;
    for part in raw.split_whitespace() {
        let at = part
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .context("duration units")?;
        let (num, u) = part.split_at(at);
        let mult = match u {
            "us" => 1,
            "ms" => 1000,
            "s" => 1000000,
            "min" => 60000000,
            "h" => 3600000000,
            "d" => 86400000000,
            "w" => 604800000000,
            _ => anyhow::bail!("unqualified timespan unit"),
        };
        let (whole, fraction) = num.split_once('.').unwrap_or((num, ""));
        ensure!(
            fraction.len() <= 6 && fraction.bytes().all(|b| b.is_ascii_digit()),
            "duration fractional spelling"
        );
        let scale = 10u64.pow(fraction.len() as u32);
        let bits = whole
            .parse::<u64>()?
            .checked_mul(scale)
            .and_then(|x| {
                x.checked_add(if fraction.is_empty() {
                    0
                } else {
                    fraction.parse().unwrap_or(u64::MAX)
                })
            })
            .context("duration overflow")?;
        let product = bits.checked_mul(mult).context("duration overflow")?;
        ensure!(product % scale == 0, "nonintegral native microseconds");
        total = total
            .checked_add(product / scale)
            .context("duration sum overflow")?;
    }
    ensure!(total > 0, "positive random delay");
    Ok(total)
}
pub fn validate(before: &Value, after: &Value) -> Result<Value> {
    let index = |v: &Value| -> Result<BTreeMap<String, Value>> {
        let mut x = BTreeMap::new();
        for row in v["rows"].as_array().context("timer rows")? {
            ensure!(
                x.insert(text(row, "unit")?.into(), row.clone()).is_none(),
                "duplicate timer row"
            );
        }
        Ok(x)
    };
    let a = index(after)?;
    let mut results = Vec::new();
    for (name, old) in index(before)? {
        let next = n_or_zero(&old, "next")?;
        if next == 0 {
            continue;
        }
        let new = a.get(&name).context("pending timer disappeared")?;
        let nn = n_or_zero(new, "next")?;
        let fired = n_or_zero(new, "last")? > n_or_zero(&old, "last")?;
        ensure!(
            old["activates"] == new["activates"]
                && before["policies"][&name] == after["policies"][&name],
            "pending timer native source/policy/trigger changed"
        );
        let reason = if PROTECTIVE.contains(&name.as_str()) {
            ensure!(
                (nn > 0 && nn <= next) || fired,
                "protective timer deadline delayed without real fire"
            );
            "protective-unchanged-or-fired"
        } else if name.to_ascii_lowercase().contains("horizon")
            || name.to_ascii_lowercase().contains("jetstreamer")
        {
            ensure!(
                nn == next || fired,
                "campaign deadline changed without genuine fire"
            );
            "campaign-exact-or-fired"
        } else if (nn > 0 && nn <= next.saturating_add(1000000)) || fired {
            "unchanged-earlier-or-fired"
        } else {
            ensure!(
                RANDOMIZED.contains(&name.as_str()) && nn > next,
                "unqualified unrelated timer deadline shift"
            );
            let d = span(text(
                &before["policies"][&name]["native"],
                "RandomizedDelayUSec",
            )?)?;
            ensure!(
                nn - next <= d,
                "OS randomized shift exceeds actual native bound"
            );
            "named-OS-randomization-within-bound"
        };
        results.push(json!({"unit":name,"before":old,"after":new,"reason":reason}));
    }
    Ok(
        json!({"schema":"horizon-positive185-finite-original-reload-timer-audit-v1","all_existing_pending_deadlines_unchanged_or_qualified_original_events":true,"results":results,"no_timer_mutation_or_reset":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_timespan_is_exact() {
        assert_eq!(span("1h 2.5s").unwrap(), 3602500000);
        assert!(span("infinity").is_err());
        assert!(span("0").is_err());
        assert!(span("0.1us").is_err());
    }
}
