//! Observe the exact closed lane-l holding transfer. This command only reads host state.
mod lanek;
mod replay_price;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};

const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanel-holding-20261125-v1";
const REVIEW: &str = "e4d66a382ce1e98b44946a51cb2233f8c53b50e63a47edd37eef1aa53a108ae0";
const UNIT: &str = "horizon-closed185-lanel-park-20261125-v1.service";
const MANIFEST: &str = "97ab4ad60aa6617bcdbbbceb2b91c8e4ade6c9fc69d0b66d171dc1865b79863f";
const STATE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1";
const LENGTH: u64 = 123_350_028_052;
const GROUP: &str = "/system.slice/horizon-closed185-lanel-park-20261125-v1.service";

struct HoldingLane {
    root: &'static str,
    unit: &'static str,
    group: &'static str,
    review: &'static str,
    manifest: &'static str,
    length: u64,
    schema: &'static str,
}

const LANE_L: HoldingLane = HoldingLane {
    root: ROOT,
    unit: UNIT,
    group: GROUP,
    review: REVIEW,
    manifest: MANIFEST,
    length: LENGTH,
    schema: "horizon-epoch185-lanel-holding-observation-v1",
};

fn ref_for(path: &Path, digest: &str) -> Value {
    json!({"path":path, "sha256":digest})
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("missing {key}"))
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn stamp(m: &fs::Metadata) -> (u64, u64, u64, i64, i64) {
    (m.dev(), m.ino(), m.len(), m.ctime(), m.ctime_nsec())
}
fn trusted(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        path.canonicalize()? == path,
        "indirect path {}",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o022 == 0
            && m.nlink() == 1
            && m.len() <= 32 << 20,
        "unexpected custody {}",
        path.display()
    );
    let mut bytes = Vec::new();
    f.take(m.len() + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len() && stamp(&m) == stamp(&path.symlink_metadata()?),
        "unstable {}",
        path.display()
    );
    Ok(bytes)
}
fn read_bound(r: &Value) -> Result<Value> {
    let data = trusted(Path::new(text(r, "path")?))?;
    ensure!(
        r["sha256"] == digest(&data),
        "evidence changed: {}",
        r["path"]
    );
    Ok(serde_json::from_slice(&data)?)
}
fn optional(path: &Path) -> Result<Option<(Value, Value)>> {
    match path.symlink_metadata() {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => {
            let data = trusted(path)?;
            Ok(Some((
                serde_json::from_slice(&data)?,
                ref_for(path, &digest(&data)),
            )))
        }
    }
}
fn manager(unit: &str) -> Result<Value> {
    let out=Command::new("/usr/bin/systemctl").args(["show",unit,"--property=Id,LoadState,ActiveState,SubState,InvocationID,Job,MainPID,ControlPID,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainStatus,Result,NRestarts,ControlGroup,FragmentPath,DropInPaths,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,Restart,Type,RemainAfterExit"]).output()?;
    // systemctl may exit 4 for a missing unit with properties printed.
    ensure!(
        (out.status.success() || out.status.code() == Some(4)) && out.stderr.is_empty(),
        "systemctl show failed"
    );
    let mut result = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("manager property")?;
        ensure!(
            result.insert(k.into(), json!(v)).is_none(),
            "duplicate property {k}"
        );
    }
    let m = Value::Object(result);
    ensure!(
        m["Id"] == unit && (out.status.success() || m["LoadState"] == "not-found"),
        "unbound manager query"
    );
    Ok(m)
}
fn members(group: &str) -> Result<Vec<u32>> {
    let p = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    match fs::read_to_string(p.join("cgroup.procs")) {
        Ok(rows) => {
            // Delegated subgroups would escape a direct-only member census.
            for child in fs::read_dir(p)? {
                ensure!(!child?.file_type()?.is_dir(), "unexpected holding subgroup");
            }
            Ok(rows.lines().map(str::parse).collect::<Result<_, _>>()?)
        }
        Err(e) if e.kind() == ErrorKind::NotFound && !p.try_exists()? => Ok(vec![]),
        Err(e) => Err(e.into()),
    }
}
fn custody(lane: &HoldingLane, v: &Value, plan: &Value) -> Result<()> {
    let object = format!("node_02/objects/{}.blob", text(plan, "sha256")?);
    ensure!(
        v["schema"] == "jetstreamer-horizon-holding-custody-v2"
            && v["host"] == "dev-samjohnson"
            && v["bucket"] == "solana-archive-with-accounts-data"
            && v["prefix"] == "node_02/"
            && v["source"] == plan["source"]
            && v["mapping"] == plan["mapping"]
            && v["eligibility"] == plan["eligibility"]
            && v["length"] == lane.length
            && v["sha256"] == plan["sha256"]
            && v["object_key"] == object
            && !text(v, "object_etag")?.is_empty()
            && v["manifest_sha256"] == lane.manifest
            && v["manifest_key"] == format!("node_02/manifests/{}.json", lane.manifest)
            && digest(&serde_json::to_vec(&v["manifest"])?) == lane.manifest
            && v["manifest"]["object_key"] == object
            && v["remote_sha256_readback"] == true
            && v["local_source_revalidated"] == true
            && v["canonical_publication_authorized"] == false
            && v["local_retirement_authorized"] == false,
        "unbound holding custody"
    );
    Ok(())
}
fn iid_valid(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}
fn check_loaded(unit: &str, m: &Value, review: &Value) -> Result<()> {
    let path = Path::new(text(m, "FragmentPath")?);
    ensure!(
        [
            Path::new("/etc/systemd/system").join(unit),
            Path::new("/run/systemd/system").join(unit)
        ]
        .contains(&path.to_owned())
            && digest(&trusted(path)?) == review["draft"]["sha256"]
            && m["DropInPaths"] == ""
            && m["LoadState"] == "loaded"
            && m["CPUQuotaPerSecUSec"] == "2s"
            && m["MemoryMax"] == "2147483648"
            && m["MemorySwapMax"] == "0"
            && m["TasksMax"] == "256"
            && m["Type"] == "oneshot"
            && m["Restart"] == "no"
            && m["RemainAfterExit"] == "yes"
            && m["NRestarts"] == "0"
            && m["ControlPID"] == "0",
        "foreign holding service or configuration"
    );
    Ok(())
}
fn worker(group: &str, pid: u32, argv: &Value) -> Result<u64> {
    let proc = Path::new("/proc").join(pid.to_string());
    let args = argv.as_array().context("park argv")?;
    let expected = args
        .iter()
        .map(|v| v.as_str().context("argv string"))
        .collect::<Result<Vec<_>>>()?;
    let image = Path::new(expected.first().context("empty argv")?);
    let exe = proc.join("exe");
    ensure!(
        exe.read_link()? == image
            && stamp(&exe.metadata()?) == stamp(&image.metadata()?)
            && fs::read(proc.join("cmdline"))? == format!("{}\0", expected.join("\0")).as_bytes()
            && fs::read_to_string(proc.join("cgroup"))?.trim_end() == format!("0::{group}"),
        "wrong holding process"
    );
    let stat = fs::read_to_string(proc.join("stat"))?;
    Ok(stat
        .rsplit_once(") ")
        .context("process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("process ticks")?
        .parse()?)
}
fn observe(lane: &HoldingLane) -> Result<Value> {
    let root = Path::new(lane.root);
    let review_ref = ref_for(
        &root.join("transfer-review/TRANSFER_REVIEW.json"),
        lane.review,
    );
    let review = read_bound(&review_ref)?;
    let prepared = read_bound(&review["prepared"])?;
    let plan = read_bound(&prepared["plan"])?;
    ensure!(
        plan["length"] == lane.length,
        "different prepared generation"
    );
    let cp = Path::new(STATE).join(format!("receipts/custody-{}.json", lane.manifest));
    let m = manager(lane.unit)?;
    let pids = members(lane.group)?;
    let receipt = optional(&cp)?;
    if let Some((v, _)) = &receipt {
        custody(lane, v, &plan)?;
    }
    let mut ticks = None;
    let stage = match (text(&m, "ActiveState")?, text(&m, "SubState")?) {
        ("inactive", "dead") => {
            ensure!(
                pids.is_empty()
                    && m["Job"] == ""
                    && m["MainPID"] == "0"
                    && m["ControlPID"] == "0"
                    && m["InvocationID"] == ""
                    && receipt.is_none(),
                "unreconciled inactive holding transfer"
            );
            if m["LoadState"] == "loaded" {
                check_loaded(lane.unit, &m, &review)?;
            } else {
                ensure!(
                    m["LoadState"] == "not-found"
                        && m["FragmentPath"] == ""
                        && m["DropInPaths"] == "",
                    "foreign absent unit"
                );
            }
            "vacant"
        }
        ("activating", "start") | ("active", "running") => {
            check_loaded(lane.unit, &m, &review)?;
            let pid = text(&m, "MainPID")?.parse::<u32>()?;
            ensure!(
                pid > 0
                    && pids == [pid]
                    && m["ExecMainPID"] == m["MainPID"]
                    && m["ControlGroup"] == lane.group
                    && iid_valid(text(&m, "InvocationID")?),
                "ambiguous live transfer"
            );
            ensure!(
                digest(&trusted(Path::new(text(&review["image"], "path")?))?)
                    == review["image"]["sha256"],
                "holding image changed"
            );
            ticks = Some(worker(lane.group, pid, &review["park_argv"])?);
            "copying"
        }
        ("active", "exited") => {
            check_loaded(lane.unit, &m, &review)?;
            ensure!(
                pids.is_empty()
                    && m["Job"] == ""
                    && m["MainPID"] == "0"
                    && m["Result"] == "success"
                    && m["ExecMainStatus"] == "0"
                    && text(&m, "ExecMainPID")?.parse::<u32>()? > 0
                    && iid_valid(text(&m, "InvocationID")?)
                    && receipt.is_some(),
                "incomplete transfer terminal"
            );
            "custody-recorded"
        }
        _ => bail!(
            "holding service requires reconciliation: {} {} {}",
            m["ActiveState"],
            m["SubState"],
            m["Result"]
        ),
    };
    ensure!(
        manager(lane.unit)? == m && members(lane.group)? == pids && optional(&cp)? == receipt,
        "holding changed during observation"
    );
    if let Some(before) = ticks {
        ensure!(
            worker(lane.group, pids[0], &review["park_argv"])? == before,
            "holding PID reused"
        );
    }
    Ok(
        json!({"schema":lane.schema,"stage":stage,"unit":lane.unit,"native":m,
        "start_ticks":ticks,"custody":receipt.map(|(_,r)|r),"plan":prepared["plan"],"transfer_review":review_ref,
        "resource_credit_bytes":0,"local_retirement_authorized":false,"replay_launch_authorized":false}),
    )
}
// The start capture joins PID1 to the physical worker. Keep its invocation bound through
// custody, including when systemd retains only ExecMainPID on the exited oneshot.
fn generation(lane: &HoldingLane, observed: &Value, start: &Value) -> Result<()> {
    let m = &observed["native"];
    let n = &start["native"];
    for k in [
        "Id",
        "InvocationID",
        "ExecMainPID",
        "ExecMainStartTimestampMonotonic",
    ] {
        ensure!(
            text(n, k)? == text(m, k)?,
            "different start generation: {k}"
        );
    }
    ensure!(
        n["Id"] == lane.unit
            && n["ControlGroup"] == lane.group
            && n["ControlPID"] == "0"
            && n["MainPID"] == n["ExecMainPID"]
            && text(n, "MainPID")?.parse::<u32>()? > 0
            && text(n, "ExecMainStartTimestampMonotonic")?.parse::<u64>()? > 0
            && iid_valid(text(n, "InvocationID")?)
            && start["start_ticks"].as_u64().is_some_and(|n| n > 0)
            && ((n["ActiveState"] == "activating" && n["SubState"] == "start")
                || (n["ActiveState"] == "active" && n["SubState"] == "running"))
            && (observed["stage"] != "copying" || observed["start_ticks"] == start["start_ticks"]),
        "foreign park start"
    );
    Ok(())
}
fn amount(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("missing unsigned {k}"))
}
// This comparison retains the baseline HOME floor and enlarges the historical serial
// restore reservation. A fresh comparison does not establish transport handback.
fn rotation_cost(q: &Value, f: &Value, review: &Value) -> Result<Value> {
    let prior = &f["retry9_auxiliary_commitments"];
    ensure!(
        q["schema"] == "horizon-incident-replay-fit-v1"
            && q["fits"] == true
            && q["replay_launch_authorized"] == false
            && q["resource_credit_bytes"] == 0
            && q.get("bounded_qualification") == Some(&Value::Null)
            && q.get("candidate") == Some(&Value::Null)
            && prior["holding_serial"] == true
            && prior["holding_cpu_quota_micros"] == 2_000_000
            && prior["holding_memory_bytes"] == 2u64 << 30
            && prior["holding_staging_bytes"] == 0
            && f["active_serial_holding_authority"] == review["historical_serial"]
            && q["registered_retry11_holding"]["stage"] == "completed-copy"
            && q["registered_cold168_holding"]["stage"] == "completed-copy",
        "unbound serial price"
    );
    let prior_bytes = amount(prior, "holding_restore_overlap_bytes")?;
    let extra = LENGTH.saturating_sub(prior_bytes);
    let metadata = amount(review, "metadata_allowance_bytes")?;
    let additional = extra
        .checked_add(metadata)
        .context("restore allowance overflow")?;
    let donor = &q["epoch159_donor_cover"];
    let base =
        amount(donor, "native_home_required")?.max(amount(q, "complete_required_HOME_bytes")?);
    let required = base
        .checked_add(additional)
        .context("HOME requirement overflow")?;
    let available = amount(q, "available_HOME_bytes")?;
    let donor_space = amount(donor, "remaining_home_bytes")?;
    Ok(
        json!({"native_fleet":q["fleet"],"native_recorded_unix_seconds":q["recorded_unix_seconds"],
        "phase145":q["phase145"]["stage"],"prior_serial_restore_bytes":prior_bytes,
        "serial_restore_enlargement_bytes":extra,"metadata_allowance_bytes":metadata,
        "required_home_bytes":required,"available_home_bytes":available,"remaining_donor_bytes":donor_space,
        "fits_after_serial_handback":available>=required && donor_space>=additional,
        "transfer_authorized":false,"resource_credit_bytes":0}),
    )
}
fn reconcile(lane: &HoldingLane, observed: &Value) -> Result<Value> {
    let root = Path::new(lane.root);
    let a = optional(&root.join("PARK_ADMISSION.json"))?;
    let s = optional(&root.join("PARK_START.json"))?;
    if a.is_none() {
        ensure!(
            observed["stage"] == "vacant" && s.is_none(),
            "unbooked holding generation"
        );
        return Ok(
            json!({"active_transfer":null,"holding_reservation":null,"observation":observed}),
        );
    }
    let (booking, ar) = a.context("booking disappeared")?;
    let review = read_bound(&observed["transfer_review"])?;
    ensure!(
        booking["owner"] == "primary"
            && booking["unit"] == lane.unit
            && booking["inputs"] == review["prepared"]
            && booking["plan"] == observed["plan"]
            && booking["cpu"] == 2_000_000
            && booking["memory"] == 2u64 << 30
            && booking["tasks"] == 256
            && booking["archive_staging_bytes"] == 0
            && booking["restore_overlap_bytes"] == lane.length
            && booking["resource_credit_bytes"] == 0,
        "foreign holding booking"
    );
    let native_fit = read_bound(&booking["fit"])?;
    let fleet = read_bound(&booking["fleet"])?;
    let cost = if lane.unit == lanek::LANE.unit {
        lanek::booking_cost(&booking, &native_fit, &fleet, &review, observed)?
    } else {
        rotation_cost(&native_fit, &fleet, &review)?
    };
    let extra = &cost["serial_restore_enlargement_bytes"];
    let metadata = &cost["metadata_allowance_bytes"];
    ensure!(
        native_fit["fleet"] == booking["fleet"]
            && cost["fits_after_serial_handback"] == true
            && booking["serial_restore_enlargement_bytes"] == *extra
            && booking["metadata_allowance_bytes"] == *metadata
            && amount(&booking, "at")?
                .checked_sub(amount(&native_fit, "recorded_unix_seconds")?)
                .is_some_and(|age| age <= 120),
        "unfunded or stale booking"
    );
    let stage = text(observed, "stage")?;
    let start_ref = if let Some((start, sr)) = s {
        ensure!(
            start["admission"] == ar && stage != "vacant",
            "holding generation lost"
        );
        generation(lane, observed, &start)?;
        Some(sr)
    } else {
        ensure!(stage == "vacant", "holding start capture pending");
        None
    };
    let reservation = json!({"unit":lane.unit,"invocation_id":observed["native"]["InvocationID"],"admission":ar,"start":start_ref,"cpu_quota_micros":2_000_000,"memory_bytes":2u64<<30,
        "restore_overlap_bytes":lane.length,"serial_restore_enlargement_bytes":extra,"metadata_allowance_bytes":metadata,"resource_credit_bytes":0});
    Ok(
        json!({"active_transfer":if stage=="copying" {Some(&reservation)} else {None},
        "holding_reservation":reservation,"observation":observed}),
    )
}
fn stable_reconciliation(lane: &HoldingLane) -> Result<Value> {
    let first = observe(lane)?;
    let r = reconcile(lane, &first)?;
    ensure!(
        observe(lane)? == first && reconcile(lane, &first)? == r,
        "holding changed during reconciliation"
    );
    Ok(r)
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "expected root");
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [op] if op == "observe" => observe(&LANE_L)?,
        [op] if op == "reconcile" => stable_reconciliation(&LANE_L)?,
        [op] if op == "reconcile-k" => stable_reconciliation(&lanek::LANE)?,
        [op, lane] if op == "replay-price" => replay_price::apply(lane)?,
        [op, path, sha] if op == "cost" => {
            let qr = ref_for(Path::new(path), sha);
            let q = read_bound(&qr)?;
            let f = read_bound(&q["fleet"])?;
            let review = read_bound(&ref_for(
                &Path::new(ROOT).join("transfer-review/TRANSFER_REVIEW.json"),
                REVIEW,
            ))?;
            read_bound(&review["historical_serial"])?;
            let mut cost = rotation_cost(&q, &f, &review)?;
            cost["native_price"] = qr;
            cost
        }
        _ => bail!("expected observe, reconcile, cost NATIVE_PRICE SHA256, or replay-price LANE"),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binds_the_same_start_across_copy_and_custody() {
        let native = json!({"Id":UNIT,"InvocationID":"a12dd506a77b4b18810129a4de84a831",
            "MainPID":"32","ExecMainPID":"32","ControlGroup":GROUP,"ControlPID":"0",
            "ExecMainStartTimestampMonotonic":"123456","ActiveState":"activating","SubState":"start"});
        let start = json!({"native":native,"start_ticks":77});
        let mut obs = json!({"native":native,"stage":"copying","start_ticks":77});
        generation(&LANE_L, &obs, &start).unwrap();
        obs["start_ticks"] = json!(78);
        assert!(generation(&LANE_L, &obs, &start).is_err());
        obs["stage"] = json!("custody-recorded");
        obs["start_ticks"] = Value::Null;
        obs["native"]["MainPID"] = json!("0");
        obs["native"]["SubState"] = json!("exited");
        generation(&LANE_L, &obs, &start).unwrap();
        for key in [
            "InvocationID",
            "ExecMainPID",
            "ExecMainStartTimestampMonotonic",
        ] {
            let mut foreign = obs.clone();
            foreign["native"][key] = json!("different");
            assert!(generation(&LANE_L, &foreign, &start).is_err());
        }
    }
    #[test]
    fn restore_delta_must_fit_both_physical_and_donor_space() {
        let f = json!({"active_serial_holding_authority":{"sha256":"serial"},"retry9_auxiliary_commitments":{
            "holding_serial":true,"holding_cpu_quota_micros":2000000,"holding_memory_bytes":2u64<<30,
            "holding_staging_bytes":0,"holding_restore_overlap_bytes":LENGTH-40}});
        let review = json!({"historical_serial":f["active_serial_holding_authority"],"metadata_allowance_bytes":2});
        let mut q = json!({"schema":"horizon-incident-replay-fit-v1","fits":true,"resource_credit_bytes":0,
            "replay_launch_authorized":false,"bounded_qualification":null,"candidate":null,"registered_retry11_holding":{"stage":"completed-copy"},
            "registered_cold168_holding":{"stage":"completed-copy"},"complete_required_HOME_bytes":990,"available_HOME_bytes":1042,
            "epoch159_donor_cover":{"native_home_required":1000,"remaining_home_bytes":42}});
        let price = rotation_cost(&q, &f, &review).unwrap();
        assert_eq!(price["required_home_bytes"], 1042);
        assert_eq!(price["fits_after_serial_handback"], true);
        assert_eq!(price["transfer_authorized"], false);
        q["available_HOME_bytes"] = json!(1041);
        assert_eq!(
            rotation_cost(&q, &f, &review).unwrap()["fits_after_serial_handback"],
            false
        );
        q["available_HOME_bytes"] = json!(1042);
        q["epoch159_donor_cover"]["remaining_home_bytes"] = json!(41);
        assert_eq!(
            rotation_cost(&q, &f, &review).unwrap()["fits_after_serial_handback"],
            false
        );
        q["registered_cold168_holding"]["stage"] = json!("copy-only");
        assert!(rotation_cost(&q, &f, &review).is_err());
    }
}
