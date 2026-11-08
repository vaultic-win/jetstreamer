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
fn parse_clocks(raw: &[u8]) -> Result<Value> {
    let rows = std::str::from_utf8(raw)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(rows.len() == 3, "exact three native timer clocks");
    let mut result = json!({});
    for (name, row) in [
        "next_monotonic_usec",
        "next_realtime_usec",
        "last_trigger_monotonic_usec",
    ]
    .into_iter()
    .zip(rows)
    {
        ensure!(
            row.as_object().is_some_and(|v| v.len() == 2) && row["type"] == "t",
            "typed uint64 native timer clock"
        );
        result[name] = json!(row["data"].as_u64().context("native uint64 timer clock")?);
    }
    Ok(result)
}
fn native_clocks(r: &mut process::Runner<'_>, unit: &str, side: &str) -> Result<Value> {
    let mut object = String::from("/org/freedesktop/systemd1/unit/");
    for byte in unit.bytes() {
        if byte.is_ascii_alphanumeric() {
            object.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(object, "_{byte:02x}")?;
        }
    }
    let mut command = Command::new("/usr/bin/busctl");
    command.args([
        "--system",
        "--json=short",
        "get-property",
        "org.freedesktop.systemd1",
        &object,
        "org.freedesktop.systemd1.Timer",
        "NextElapseUSecMonotonic",
        "NextElapseUSecRealtime",
        "LastTriggerUSecMonotonic",
    ]);
    let result = r.run(
        &format!("timer-clocks-{side}"),
        command,
        Duration::from_secs(5),
    )?;
    parse_clocks(&serde_json::from_value::<Vec<u8>>(
        result["stdout_bytes"].clone(),
    )?)
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
    let mut clocks = json!({});
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
                "--property=Id,LoadState,InvocationID,FragmentPath,DropInPaths,RandomizedDelayUSec,FixedRandomDelay,AccuracyUSec,Unit,Persistent,RemainAfterElapse,WakeSystem",
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
                && storage::hex(text(&native, "InvocationID")?, 32)
                && native["Unit"] == row["activates"],
            "exact native timer trigger"
        );
        clocks[name] = native_clocks(r, name, side)?;
        let mut sources = Vec::new();
        let paths = std::iter::once(text(&native, "FragmentPath")?)
            .chain(text(&native, "DropInPaths")?.split_whitespace());
        for p in paths {
            sources.push(timer_source(Path::new(p))?);
        }
        policies[name] = json!({"native":native,"sources":sources});
    }
    Ok(json!({"rows":rows,"policies":policies,"native_clocks":clocks}))
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
        let old_clocks = &before["native_clocks"][&name];
        let new_clocks = &after["native_clocks"][&name];
        let old_mono = n(old_clocks, "next_monotonic_usec")?;
        let new_mono = n(new_clocks, "next_monotonic_usec")?;
        let old_real = n(old_clocks, "next_realtime_usec")?;
        let new_real = n(new_clocks, "next_realtime_usec")?;
        let old_last = n(old_clocks, "last_trigger_monotonic_usec")?;
        let new_last = n(new_clocks, "last_trigger_monotonic_usec")?;
        ensure!(
            old_mono > 0 || old_real > 0,
            "pending timer requires actual native deadline"
        );
        ensure!(
            new_last >= old_last,
            "native timer fire clock moved backward"
        );
        let fired = new_last > old_last;
        let unchanged_or_earlier = (old_mono == new_mono || (new_mono > 0 && new_mono < old_mono))
            && (old_real == new_real || (new_real > 0 && new_real < old_real));
        ensure!(
            old["activates"] == new["activates"]
                && before["policies"][&name] == after["policies"][&name],
            "pending timer native source/policy/trigger changed"
        );
        let reason = if PROTECTIVE.contains(&name.as_str()) {
            ensure!(
                unchanged_or_earlier || fired,
                "protective timer deadline delayed without real fire"
            );
            "protective-unchanged-or-fired"
        } else if name.to_ascii_lowercase().contains("horizon")
            || name.to_ascii_lowercase().contains("jetstreamer")
        {
            ensure!(
                (old_mono == new_mono && old_real == new_real) || fired,
                "campaign deadline changed without genuine fire"
            );
            "campaign-exact-or-fired"
        } else if unchanged_or_earlier || fired {
            "unchanged-earlier-or-fired"
        } else {
            let mono_increase = new_mono.saturating_sub(old_mono);
            let real_increase = new_real.saturating_sub(old_real);
            ensure!(
                RANDOMIZED.contains(&name.as_str())
                    && (old_mono == 0) == (new_mono == 0)
                    && (old_real == 0) == (new_real == 0)
                    && mono_increase.max(real_increase) > 0,
                "unqualified unrelated timer deadline shift"
            );
            let d = span(text(
                &before["policies"][&name]["native"],
                "RandomizedDelayUSec",
            )?)?;
            ensure!(
                mono_increase.max(real_increase) <= d,
                "OS randomized shift exceeds actual native bound"
            );
            "named-OS-randomization-within-bound"
        };
        results.push(json!({"unit":name,"before":old,"after":new,"before_native_clocks":old_clocks,"after_native_clocks":new_clocks,"reason":reason}));
    }
    Ok(
        json!({"schema":"horizon-positive185-finite-original-reload-timer-audit-v1","all_existing_pending_deadlines_unchanged_or_qualified_original_events":true,"results":results,"no_timer_mutation_or_reset":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn captured(name: &str, display_next: u64, mono: u64, real: u64, last: u64) -> Value {
        json!({"rows":[{"unit":name,"activates":"fixture.service","next":display_next,"last":100}],
            "policies":{name:{"native":{"InvocationID":"a".repeat(32),"RandomizedDelayUSec":"30s"},"sources":[]}},
            "native_clocks":{name:{"next_monotonic_usec":mono,"next_realtime_usec":real,"last_trigger_monotonic_usec":last}}})
    }
    #[test]
    fn overdue_display_can_advance_only_with_unchanged_authoritative_deadlines() {
        let name = PROTECTIVE[0];
        let before = captured(name, 1794126883780535, 1000, 0, 900);
        let after = captured(name, 1794126892358899, 1000, 0, 900);
        assert!(validate(&before, &after).is_ok());
        assert!(validate(&before, &captured(name, 1794126892358899, 1001, 0, 900)).is_err());
        assert!(validate(&before, &captured(name, 1794126892358899, 0, 0, 900)).is_err());
        assert!(validate(&before, &captured(name, 1794126892358899, 1001, 0, 901)).is_ok());
        assert!(validate(&before, &captured(name, 1794126892358899, 1000, 0, 899)).is_err());
    }
    #[test]
    fn native_timer_clocks_reject_missing_wrong_types_and_extra_properties() {
        let raw = b"{\"type\":\"t\",\"data\":1000}\n{\"type\":\"t\",\"data\":0}\n{\"type\":\"t\",\"data\":900}\n";
        assert_eq!(parse_clocks(raw).unwrap()["next_monotonic_usec"], 1000);
        let text = std::str::from_utf8(raw).unwrap();
        for changed in [
            text.replace("\"t\"", "\"s\""),
            text.replace("1000", "\"1000\""),
            text.replace("1000", "-1"),
            text.replace("1000", "1000,\"extra\":true"),
            text.lines().take(2).collect::<Vec<_>>().join("\n"),
        ] {
            assert!(parse_clocks(changed.as_bytes()).is_err());
        }
        let mut missing = captured(PROTECTIVE[0], 100, 1000, 0, 900);
        missing.as_object_mut().unwrap().remove("native_clocks");
        assert!(validate(&missing, &missing).is_err());
    }
    #[test]
    fn calendar_campaign_native_deadline_and_invocation_are_exact() {
        let name = "horizon-fixture-observer.timer";
        let before = captured(name, 10000, 0, 10000, 0);
        assert!(validate(&before, &captured(name, 10001, 0, 10000, 0)).is_ok());
        assert!(validate(&before, &captured(name, 10000, 0, 10001, 0)).is_err());
        let mut changed = before.clone();
        changed["policies"][name]["native"]["InvocationID"] = json!("b".repeat(32));
        assert!(validate(&before, &changed).is_err());
    }
    #[test]
    fn os_randomization_requires_named_unchanged_policy_and_native_bound() {
        for (mono, real) in [(1000, 0), (0, 1000)] {
            let before = captured("apt-daily.timer", 1000, mono, real, 100);
            let after = captured(
                "apt-daily.timer",
                2000,
                if mono > 0 { mono + 1000 } else { 0 },
                if real > 0 { real + 1000 } else { 0 },
                100,
            );
            assert!(validate(&before, &after).is_ok());
            let mut too_late = after.clone();
            too_late["native_clocks"]["apt-daily.timer"][if mono > 0 {
                "next_monotonic_usec"
            } else {
                "next_realtime_usec"
            }] = json!(31001000u64);
            assert!(validate(&before, &too_late).is_err());
        }
        assert!(
            validate(
                &captured("unknown.timer", 1000, 0, 1000, 100),
                &captured("unknown.timer", 1000, 0, 2000, 100)
            )
            .is_err()
        );
    }
    #[test]
    fn native_timespan_is_exact() {
        assert_eq!(span("1h 2.5s").unwrap(), 3602500000);
        assert!(span("infinity").is_err());
        assert!(span("0").is_err());
        assert!(span("0.1us").is_err());
    }
}
