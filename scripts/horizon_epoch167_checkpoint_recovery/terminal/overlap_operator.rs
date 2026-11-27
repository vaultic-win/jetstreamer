//! Price the epoch 167 read-only comparison inside its original producer booking.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
#[allow(dead_code)]
#[path = "../../horizon_epoch170_checkpoint_suffix/evidence.rs"]
mod evidence;
use evidence::{bound, command, idle, member, now, num, props, receipt, reference, word};

const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const CLOSE: &str = "epoch167-checkpoint-bounded-20261127-v2";
const OUT: &str = "epoch167-bounded-post-retry-overlap-20261127-v1";
const UNIT: &str = "horizon-167-checkpoint-independent-overlap-20261127-v1.service";
const REPLAY: &str = "horizon-qualify-167-checkpoint-bounded-20261127-v2.service";
const IID: &str = "0d5c8181a13a44ff894d5b9b8df423bc";
const SOURCE_SHA: &str = "430561d1a97572e727e62e7c8d8991cac5adcfcd33f00e203525e1a7735ebea9";
const SUCCESS: &str = "7ad2d189f7e94e70a38c781354912448";
const TOOL: &str = "horizon-167-bounded-overlap";
const RUN_READER: &str = "/run/horizon-167-overlap-reader";
const BRIDGE: &str = "epoch170-storage-witness-recovery-20261127-v1/suffix-run-v1";
const PREFIX: &str = "epoch167-retained-prefix-selection-20261127-v1";

fn root(dir: &str, name: &str) -> PathBuf {
    Path::new(ROOT).join(dir).join(name)
}
fn get(dir: &str, name: &str, hash: &str) -> Result<Value> {
    let r = reference(&root(dir, name))?;
    ensure!(r["sha256"] == hash, "changed qualified {dir}/{name}");
    Ok(r)
}
fn tool() -> Result<(Value, PathBuf)> {
    let seal = get(
        OUT,
        "tools/deployment-seal-receipt.json",
        "2fe73e7504a7ff3866c7ebf0167d0dbeae08de9952b28690cd3e042850560d23",
    )?;
    let bin = member(&seal, TOOL)?;
    ensure!(
        reference(&bin)?["sha256"]
            == "6de4f2bbb9652ee2adbe5865bbe9b6c591fabd51bf9e12253d0a9832fd5bc991",
        "wrong reader"
    );
    Ok((seal, bin))
}
fn archive() -> Result<(Value, Value)> {
    let r = reference(&root(CLOSE, "BOUNDED_V2_TERMINAL.json"))?;
    let t = bound(&r)?;
    let e = &t["pid1_terminal_event"];
    ensure!(
        e["_PID"] == "1"
            && e["MESSAGE_ID"] == SUCCESS
            && e["INVOCATION_ID"] == IID
            && t["disposition"] == "checkpoint-complete"
            && t["first_protected_progress"]["sha256"]
                == "30f64fff84ba178299e9b6d49895c350d4a0792b2ad46ca10494be55fef18329"
            && t["guard_drained"] == true
            && !t["signed_comparison"].is_null()
            && t["archive_publication_authorized"] == false,
        "missing original bounded checkpoint"
    );
    for u in [
        REPLAY,
        "horizon-guard-167-checkpoint-bounded-20261127-v2.timer",
        "horizon-guard-167-checkpoint-bounded-20261127-v2.service",
    ] {
        idle(u)?;
    }
    Ok((r, t["checkpoint"].clone()))
}

// Reuse the 143 price's PID1/cgroup, guard and physical accounting on this same host.
#[allow(dead_code)]
mod price {
    include!("../../horizon_epoch143_bounded_entry_20261126_v1/launcher/src/bin/price_entry143.rs");
    pub(super) fn fit(fleet_ref: &Value, terminal: &Value) -> Result<Value> {
        let (disk0, ram0) = usage()?;
        let fleet = read(fleet_ref)?;
        let when = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        ensure!(
            when.abs_diff(number(&fleet["recorded_unix_seconds"])?) < 2100
                && fleet["all_reservation_ending_bytes"] == 0
                && fleet["resource_credit_bytes"] == 0
                && fleet["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true,
            "stale or changed fleet"
        );
        let prior = super::get(
            super::BRIDGE,
            "POST_GUARD_CAPACITY.json",
            "691f6fbdb859597b760ebc29067d5db903298c0e38411591285d0ec61a79277d",
        )?;
        let q = read(&prior)?;
        let n = &q["native"];
        let original = read(&n["fleet"])?;
        for key in [
            "complete_projected_memory_bytes",
            "complete_DATA_bytes",
            "active_serial_holding_authority",
        ] {
            ensure!(fleet[key] == original[key], "fleet booking changed {key}");
        }
        for key in [
            "additional_memory_bytes",
            "additional_cpu_quota_micros",
            "maximum_output_allocation_bytes",
        ] {
            ensure!(
                fleet["active_ready_range_audit_obligation"][key]
                    == original["active_ready_range_audit_obligation"][key],
                "audit obligation changed {key}"
            );
        }
        let holding = read(&fleet["epoch185_lanel_holding"])?;
        let h = &holding["result"]["holding_reservation"];
        ensure!(
            h["restore_overlap_bytes"] == 123_350_028_052u64
                && h["serial_restore_enlargement_bytes"] == 54_016_054_271u64,
            "changed 185 booking"
        );
        let b = &n["released_167"];
        let first = read(&super::get(
            super::BRIDGE,
            "FIRST_PROTECTED_WORKER.json",
            "289289ccd5dc7c30542d961dfcec2f1e29708944797f53e5d1c66c39b8212ca4",
        )?)?;
        let mut guards = BTreeMap::new();
        let mut peers = BTreeSet::new();
        let mut resident = 0;
        let mut extra = 0;
        for peer in fleet["actual_executing_replays"]
            .as_array()
            .context("missing full workers")?
        {
            let u = string(&peer["unit"]["Id"])?;
            ensure!(peers.insert(u), "duplicate incumbent");
            let anchor = &b["checked_samples"][u];
            let (r, used, mem) = protected(
                &anchor["sample"],
                &b["tracked_processes"][u],
                &peer["guard_timer"]["InvocationID"],
                when,
            )?;
            resident += mem;
            extra += number(&anchor["lower"])?.saturating_sub(used);
            guards.insert(u, r);
        }
        ensure!(peers.len() == 2, "expected 146 and 172 full worker guards");
        let u = string(&first["actor"]["unit"])?;
        let g = &q["first_guard"];
        let (r, used170, _) = protected(
            &g["sample"],
            &first["actor"]["processes"],
            &g["timer_invocation_id"],
            when,
        )?;
        peers.insert(u);
        guards.insert(u, r);
        let actual = command(&[
            "list-units",
            "--type=service",
            "--state=running,activating,deactivating",
            "--plain",
            "--no-legend",
            "horizon-qualify-*",
        ])?;
        ensure!(
            actual
                .lines()
                .filter_map(|s| s.split_ascii_whitespace().next())
                .collect::<BTreeSet<_>>()
                == peers,
            "replay population changed"
        );
        let remaining170 = number(&g["cap"])?
            .checked_sub(used170)
            .context("170 above cap")?;
        let guard167 = read(&terminal["guard_plan"])?;
        let run = string(&guard167["worker_root"])?;
        let allocated = || -> Result<u64> {
            let result = super::command(
                "/usr/bin/du",
                &[
                    "--summarize",
                    "--one-file-system",
                    "--block-size=1",
                    "--",
                    run,
                ],
            )?;
            let (size, path) = result.trim_end().split_once('\t').context("du format")?;
            ensure!(path == run, "unexpected 167 tree");
            Ok(size.parse()?)
        };
        let closed_a = allocated()?;
        let closed_b = allocated()?;
        ensure!(closed_a == closed_b, "stopped 167 tree changed");
        let remaining167 = number(&guard167["maximum_root_physical_bytes"])?
            .checked_sub(closed_a)
            .context("bounded 167 above cap")?;
        let selector = super::props(
            SELECTOR,
            "Id,LoadState,MainPID,InvocationID,ActiveState,Job,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec",
        )?;
        ensure!(
            property(&selector, "ActiveState")? != "active"
                || (property(&selector, "MemoryMax")? == (4 * GIB).to_string()
                    && property(&selector, "MemorySwapMax")? == "0"
                    && property(&selector, "CPUQuotaPerSecUSec")? == "1s"),
            "changed selector"
        );
        let entry = super::props(
            UNIT,
            "Id,LoadState,MainPID,InvocationID,ActiveState,Job,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec",
        )?;
        if property(&entry, "ActiveState")? == "active" {
            let lease: Value = serde_json::from_slice(&fs::read(LEASE)?)?;
            ensure!(
                property(&entry, "MemoryMax")? == (192 * MIB).to_string()
                    && property(&entry, "CPUQuotaPerSecUSec")? == "250ms"
                    && property(&entry, "MemorySwapMax")? == "0"
                    && entry["InvocationID"] == string(&lease["invocation_id"])?
                    && entry["MainPID"] == number(&lease["pid"])?.to_string()
                    && ticks(number(&lease["pid"])?)? == number(&lease["start_ticks"])?,
                "changed 143 bounded entry"
            );
        }
        let booking = read(&super::get(
            super::CLOSE,
            "START_INTENT.json",
            "421e9ac00698b4427791108f61db5e1d4aa953404c637209c3e6f1a99de92b7d",
        )?)?;
        ensure!(
            booking["producer_memory_bytes"] == 42 * GIB
                && booking["producer_unit"] == super::REPLAY,
            "wrong retained producer booking"
        );
        let baseline = 782_740_762_624 + 6 * GIB;
        // The temporary reader stays inside the 42 GiB lease. Retain the full predecessor
        // requirement and all 185 capacity, including disk growth of the stopped 167 tree.
        let ram = baseline - resident + 4 * GIB + 192 * MIB + 8 * MIB;
        let home = number(&n["armed_floor"])?
            + extra
            + remaining167
            + remaining170
            + 16 * MIB
            + 8 * MIB
            + 2 * MIB;
        let (disk1, ram1) = usage()?;
        Ok(
            json!({"fleet":fleet_ref,"prior_170_postguard":prior,"holding_185":h,
            "available_home_bytes":disk0.min(disk1),"required_home_bytes":home,
            "available_memory_bytes":ram0.min(ram1),"required_memory_bytes":ram,"fit":disk0.min(disk1)>=home&&ram0.min(ram1)>=ram,
            "recorded_unix_seconds":when,"protected_guards":guards,"original_167_producer_memory_max":42*GIB,
            "original_167_postexit_allocation":closed_a,"stopped_167_future_growth_bytes":remaining167,
            "remaining_170":remaining170,"other_guard_shrinkage_allowance":extra,"resident_lower_bound":resident,
            "selector167":selector,"bounded143":entry,"reader_memory_max":3*GIB,"cpu_quota_us":500_000,
            "archive_scratch_bytes":0,"metadata_allowance":2*MIB,"reservation_ending_bytes":0}),
        )
    }
}

fn argv(bin: &Path, check: &Value, source: &str) -> Result<Vec<String>> {
    let mount = format!(
        "BindReadOnlyPaths={} {} {}:{RUN_READER}",
        source,
        word(check, "archive")?,
        bin.display()
    );
    let mut args = vec![
        format!("--unit={UNIT}"),
        "--quiet".into(),
        "--service-type=exec".into(),
    ];
    for p in [
        "User=sol",
        "Group=horizon",
        "PrivateMounts=yes",
        "MountFlags=private",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "TemporaryFileSystem=/home/sol:ro,nosuid,noexec,nodev,mode=0755,size=1M",
        &mount,
        "PrivateNetwork=yes",
        "PrivateDevices=yes",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "RestrictAddressFamilies=AF_UNIX",
        "InaccessiblePaths=/tmp /var/tmp",
        "Restart=no",
        "MemoryMax=3G",
        "MemorySwapMax=0",
        "CPUQuota=50%",
        "IOWeight=10",
        "Nice=10",
        "TasksMax=32",
        "RuntimeMaxSec=2h",
        "LimitCORE=0",
        "WorkingDirectory=/",
        "StandardOutput=journal",
        "StandardError=journal",
    ] {
        args.push(format!("--property={p}"));
    }
    args.extend([
        "--".into(),
        "/usr/bin/env".into(),
        RUN_READER.into(),
        num(check, "archive_bytes")?.to_string(),
        word(check, "archive_sha256")?.into(),
    ]);
    Ok(args)
}
fn start(fleet: &Path) -> Result<Value> {
    let (terminal, checkpoint) = archive()?;
    let (seal, bin) = tool()?;
    idle(UNIT)?;
    let selector = bound(&reference(&root(PREFIX, "START_INTENT.json"))?)?;
    ensure!(selector["source"]["sha256"] == SOURCE_SHA, "wrong source");
    let arguments = argv(&bin, &checkpoint, word(&selector["source"], "path")?)?;
    let fit = price::fit(&reference(fleet)?, &bound(&terminal)?)?;
    ensure!(fit["fit"] == true, "postexit fit failed {fit}");
    let intent = receipt(
        &root(OUT, "START_INTENT.json"),
        &json!({"terminal":terminal,"reader_seal":seal,"fit":fit,"argv":arguments,"recorded_unix_seconds":now()?}),
    )?;
    command("/usr/bin/systemd-run", &arguments)?;
    let a = props(
        UNIT,
        "Id,LoadState,ActiveState,InvocationID,ControlGroup,MainPID,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,NRestarts,Job",
    )?;
    ensure!(
        a["ActiveState"] == "active"
            && a["Id"] == UNIT
            && a["MemoryMax"] == "3221225472"
            && a["MemorySwapMax"] == "0"
            && a["CPUQuotaPerSecUSec"] == "500ms"
            && a["NRestarts"] == "0"
            && a["Job"].is_empty(),
        "unexpected running comparison"
    );
    receipt(
        &root(OUT, "ACTIVE.json"),
        &json!({"intent":intent,"unit":a,"boot":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),"recorded_unix_seconds":now()?}),
    )
}
fn records(args: &[&str]) -> Result<Vec<Value>> {
    command("/usr/bin/journalctl", args)?
        .lines()
        .map(|s| Ok(serde_json::from_str(s)?))
        .collect()
}
fn report(lines: &[&str], retry: &str) -> Result<Value> {
    let [norm, complete] = lines else {
        anyhow::bail!("unexpected comparison output")
    };
    let expected = format!(
        "comparison_complete epoch=167 seam=72509256 raw_cursor_delta=206535916 source_archive_sha256={SOURCE_SHA} retry_archive_sha256={retry}"
    );
    ensure!(
        *complete == expected,
        "terminal comparison identity differs"
    );
    let parts: Vec<_> = norm.split_ascii_whitespace().collect();
    ensure!(
        parts.len() == 9
            && parts[0] == "epoch167_bounded_retry_overlap"
            && parts[1] == "first_slot=72509257"
            && parts[2] == "last_slot=72512767"
            && parts[4] == "terminal_blockhash=rHfcRAZeWMTKGpbcnHRTxKHcoLUR8p6XhbsCcSSWsuA"
            && parts[5..]
                == [
                    "source_raw_start=52685674983",
                    "source_raw_end_exclusive=52690685155",
                    "retry_raw_start=52892210899",
                    "retry_raw_end_exclusive=52897221071"
                ],
        "incorrect overlap window or native cursor"
    );
    let sha = parts[3]
        .strip_prefix("normalized_sha256=")
        .context("missing normalized result")?;
    ensure!(
        sha.len() == 64
            && sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "bad normalized digest"
    );
    Ok(
        json!({"normalized_sha256":sha,"first_slot":72509257,"last_slot":72512767,"normalized_report":norm,"comparison_complete":complete}),
    )
}
fn finish() -> Result<Value> {
    let (terminal, checkpoint) = archive()?;
    let active = reference(&root(OUT, "ACTIVE.json"))?;
    let a = bound(&active)?;
    let intent = bound(&a["intent"])?;
    let u = &a["unit"];
    ensure!(
        u["Id"] == UNIT && intent["terminal"] == terminal && intent["reader_seal"] == tool()?.0,
        "foreign comparison"
    );
    idle(UNIT)?;
    let iid = word(u, "InvocationID")?;
    let boot = word(&a, "boot")?.replace('-', "");
    let events = records(&[
        "-q",
        "--no-pager",
        "-o",
        "json",
        "_PID=1",
        "_UID=0",
        &format!("UNIT={UNIT}"),
        &format!("INVOCATION_ID={iid}"),
        &format!("_BOOT_ID={boot}"),
    ])?;
    let choices: Vec<_> = events
        .iter()
        .filter(|v| {
            v["MESSAGE_ID"] == SUCCESS
                || (v["MESSAGE_ID"] == "98e322203f7a4ed290d09fe03c09fe15"
                    && v["COMMAND"] == "ExecStart")
        })
        .collect();
    let [event] = choices.as_slice() else {
        anyhow::bail!("missing unique PID1 terminal event")
    };
    let native = records(&[
        "-q",
        "--no-pager",
        "-o",
        "json",
        &format!("_SYSTEMD_UNIT={UNIT}"),
        &format!("_SYSTEMD_INVOCATION_ID={iid}"),
        &format!("_BOOT_ID={boot}"),
        &format!("_PID={}", word(u, "MainPID")?),
    ])?;
    let lines: Vec<_> = native
        .iter()
        .filter_map(|v| v["MESSAGE"].as_str())
        .collect();
    let mut result = json!({"schema":"horizon-167-independent-bounded-overlap-v1","active":active,"terminal":terminal,"reader_seal":intent["reader_seal"],
        "private":true,"archive_publication_authorized":false,"resource_credit_bytes":0,"pid1":event,"native_invocation":iid,"native_lines":lines});
    if event["MESSAGE_ID"] != SUCCESS {
        return receipt(&root(OUT, "OVERLAP_FAILED.json"), &result);
    }
    let output: Vec<_> = lines
        .into_iter()
        .filter(|s| {
            s.starts_with("epoch167_bounded_retry_overlap ")
                || s.starts_with("comparison_complete ")
        })
        .collect();
    result["report"] = report(&output, word(&checkpoint, "archive_sha256")?)?;
    receipt(&root(OUT, "OVERLAP_VERIFIED.json"), &result)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let res = match args.as_slice() {
        [m] if m == "prepare" => {
            let (s, b) = tool()?;
            json!({"reader_seal":s,"reader":b,"producer_invocation":IID,"reader_unit":UNIT,"archive_scratch_bytes":0})
        }
        [m, f] if m == "start" => start(Path::new(f))?,
        [m] if m == "finish" => finish()?,
        _ => anyhow::bail!("expected prepare, start FLEET, or finish"),
    };
    println!("{}", serde_json::to_string(&res)?);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_the_complete_normalized_window_in_both_coordinates() {
        let normalized = "epoch167_bounded_retry_overlap first_slot=72509257 last_slot=72512767 normalized_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa terminal_blockhash=rHfcRAZeWMTKGpbcnHRTxKHcoLUR8p6XhbsCcSSWsuA source_raw_start=52685674983 source_raw_end_exclusive=52690685155 retry_raw_start=52892210899 retry_raw_end_exclusive=52897221071";
        let c = format!(
            "comparison_complete epoch=167 seam=72509256 raw_cursor_delta=206535916 source_archive_sha256={SOURCE_SHA} retry_archive_sha256={SOURCE_SHA}"
        );
        assert!(report(&[normalized, &c], SOURCE_SHA).is_ok());
        assert!(
            report(
                &[
                    &normalized.replace("last_slot=72512767", "last_slot=72512766"),
                    &c
                ],
                SOURCE_SHA
            )
            .is_err()
        );
        assert!(report(&[normalized], SOURCE_SHA).is_err());
    }
}
