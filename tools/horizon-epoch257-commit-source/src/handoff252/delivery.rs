//! Turn the verified epoch 252 handoff and a fresh fleet quote into one uploader.
use super::*;
use std::{collections::BTreeSet, mem::MaybeUninit, os::unix::fs::FileTypeExt, time::SystemTime};

const STATE: &str = "/var/lib/jetstreamer/horizon252-current-reader-delivery-v1";
const UNIT: &str = "horizon-upload-252-current-reader-v1.service";
const PROFILE: &str =
    "/var/lib/jetstreamer/horizon252-delivery-service-preparation-v1/service-profile.json";
const PROFILE_SHA: &str = "1910d51429d25490591b775af11bcfd94eb3c5bac957480c0838727f9f2cfca2";
const RELEASE: &str = "/var/lib/jetstreamer/horizon252-delivery-fleet-v1/acceptance.json";
const FILESYSTEM: &str = "/var/lib/jetstreamer";
const CONTROLLER: &str = "/var/lib/jetstreamer/horizon-seven-publication-controller-v222";
const RUN: &str = "/usr/bin/systemd-run";
const AUTH: &str = "EnvironmentFile=/etc/jetstreamer/horizon-r2-upload.env";
const LOCKS: [&str; 2] = [
    "/run/horizon292-300-finite-v205-a1/issuer.lock",
    "/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock",
];
const OWNER_FIELDS: &str = "Id,InvocationID,ActiveState,SubState,Job,MainPID,ControlGroup,ExecStart,MemoryMax,MemorySwapMax,AllowedCPUs,NRestarts";

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .with_context(|| format!("missing {field}"))
}

fn number(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .with_context(|| format!("invalid {field}"))
}

fn strings(value: &Value) -> Result<Vec<&str>> {
    value
        .as_array()
        .context("expected argument array")?
        .iter()
        .map(|item| item.as_str().context("non-string argument"))
        .collect()
}

fn write_json(path: &Path, value: &Value) -> Result<Value> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if path.try_exists()? {
        ensure!(
            read_bound(path, 1 << 20, 0)?.0 == bytes,
            "conflicting delivery evidence at {}",
            path.display()
        );
    } else {
        persist(path, &bytes)?;
    }
    Ok(json!({"path":path,"sha256":sha256(&bytes)}))
}

fn process_ticks(pid: u32) -> Result<u64> {
    ensure!(pid > 1, "missing delivery process");
    Ok(fs::read_to_string(format!("/proc/{pid}/stat"))?
        .rsplit_once(')')
        .context("process start ticks")?
        .1
        .split_whitespace()
        .nth(19)
        .context("process start ticks")?
        .parse()?)
}

fn check_deployment(reader: &Value) -> Result<Value> {
    let (bytes, _) = read_bound(Path::new(RELEASE), 1 << 20, 0)?;
    let release: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        release["schema"] == "foundation-epoch252-delivery-fleet-release-v1"
            && release["reader_plan"] == *reader,
        "epoch 252 fleet deployment is missing or bound to a different reader plan"
    );
    for (field, filename) in [
        ("observer", "jetstreamer-horizon-observe"),
        ("fleet", "jetstreamer-r2"),
        ("launcher", "horizon-epoch257-commit-source"),
        ("roster", "horizon-native262-foundation-roster"),
    ] {
        let reference = &release[field];
        let path = Path::new(text(reference, "path")?);
        ensure!(
            path.parent() == Path::new(RELEASE).parent()
                && path.file_name().is_some_and(|name| name == filename),
            "unexpected epoch 252 deployed {field}"
        );
        ensure!(
            sha256(&read_bound(path, 128 << 20, 0)?.0) == text(reference, "sha256")?,
            "epoch 252 deployed {field} changed"
        );
        if field == "launcher" {
            ensure!(
                fs::read_link("/proc/self/exe")? == path,
                "use the sealed epoch 252 launcher"
            );
        }
    }
    for filename in [
        "cycle.py",
        "native_binding_replays.py",
        "delivery261.py",
        "publication_handoff.py",
    ] {
        let path = Path::new(CONTROLLER).join(filename);
        ensure!(
            sha256(&read_bound(&path, 1 << 20, 0)?.0)
                == text(&release["controller_sha256"], filename)?,
            "epoch 252 cadence integration is missing or changed at {filename}"
        );
    }
    Ok(json!({"path":RELEASE,"sha256":sha256(&bytes)}))
}

fn recheck_fit(quote: &Value) -> Result<()> {
    let age = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs()
        .checked_sub(number(quote, "recorded_unix_seconds")?)
        .context("future fleet quote")?;
    let fit = &quote["capacity"];
    ensure!(
        age <= 90 && fit["fits"] == true,
        "stale or unfunded epoch 252 delivery quote"
    );
    let mut required = number(fit, "required_remaining_memory_bytes")?;
    let owners = quote["owners"].as_object().context("quoted peers")?;
    let guards = quote["periodic_guards"]
        .as_object()
        .context("quoted peer guards")?;
    let guard_units = guards
        .values()
        .map(|row| text(row, "unit"))
        .collect::<Result<BTreeSet<_>>>()?;
    let census = command(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=running,activating",
            "--plain",
            "--no-legend",
            "--no-pager",
        ],
    )?;
    let live = std::str::from_utf8(&census)?
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|unit| {
            ["horizon-", "foundation-", "archive-", "jetstreamer-"]
                .iter()
                .any(|prefix| unit.starts_with(prefix))
                && !guard_units.contains(unit)
        })
        .collect::<BTreeSet<_>>();
    let expected = owners.keys().map(String::as_str).collect::<BTreeSet<_>>();
    ensure!(
        live == expected,
        "epoch 252 fleet changed: {:?}",
        live.symmetric_difference(&expected).collect::<Vec<_>>()
    );
    for (unit, row) in owners {
        let fields = "Id,ActiveState,SubState,InvocationID,MainPID,ControlGroup,AllowedCPUs,MemoryMax,MemoryCurrent,Job";
        let current = properties(unit, fields)?;
        for key in [
            "Id",
            "ActiveState",
            "SubState",
            "InvocationID",
            "MainPID",
            "ControlGroup",
            "AllowedCPUs",
            "MemoryMax",
        ] {
            ensure!(
                current[key] == row["systemd"][key],
                "booked epoch 252 peer {unit} changed {key}"
            );
        }
        ensure!(
            current["Job"] == ""
                && process_ticks(text(&current, "MainPID")?.parse()?)?
                    == number(row, "process_start_ticks")?,
            "epoch 252 peer {unit} has a queued job or a different process"
        );
        required = required
            .checked_add(
                number(row, "memory_current_bytes")?
                    .saturating_sub(text(&current, "MemoryCurrent")?.parse()?),
            )
            .context("memory growth overflow")?;
    }
    for row in guards.values() {
        ensure!(
            properties(text(row, "timer")?, "ActiveState,InvocationID,Unit")?
                == json!({
                    "ActiveState":"active","InvocationID":row["timer_invocation_id"],"Unit":row["unit"]
                }),
            "booked epoch 252 peer guard changed"
        );
    }
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|line| line.split_whitespace().next())
        .context("missing available memory")?
        .parse::<u64>()?;
    let mut disk = MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        fs::metadata(FILESYSTEM)?.dev() == number(quote, "filesystem_device")?
            && fs::metadata(EPOCH_252.run)?.dev() == number(quote, "filesystem_device")?
            && unsafe { libc::statvfs(c"/var/lib/jetstreamer".as_ptr(), disk.as_mut_ptr()) } == 0,
        "cannot bind the epoch 252 filesystem"
    );
    let disk = unsafe { disk.assume_init() };
    ensure!(
        disk.f_bavail.saturating_mul(disk.f_frsize) >= number(fit, "required_disk_bytes")?
            && kib.saturating_mul(1024) >= required
            && number(fit, "required_hard_memory_bytes")?
                <= number(fit, "host_total_memory_bytes")?,
        "epoch 252 live storage or memory changed"
    );
    Ok(())
}

pub(crate) fn launch(quote_path: &Path, quote_sha: &str) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "epoch 252 delivery requires root"
    );
    ensure!(
        quote_path
            .parent()
            .is_some_and(|p| p.parent() == Some(Path::new("/var/lib/jetstreamer"))
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("horizon262-foundation-roster-")))
            && quote_path.file_name().is_some_and(|n| n == "roster.json"),
        "unexpected epoch 252 quote path"
    );
    let _locks = LOCKS
        .iter()
        .map(|path| {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            let meta = file.metadata()?;
            ensure!(
                meta.is_file()
                    && meta.uid() == 0
                    && meta.mode() & 0o022 == 0
                    && unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "epoch 252 launch lock is unavailable"
            );
            Ok(file)
        })
        .collect::<Result<Vec<_>>>()?;
    let quote = pinned_json(
        quote_path.to_str().context("quote path encoding")?,
        quote_sha,
    )?;
    let fit = &quote["capacity"];
    ensure!(
        quote["schema"] == "foundation-epoch252-delivery-roster-binding-v1"
            && quote["epoch"] == 252
            && quote["admission_issued"] == false
            && quote["candidate_held"] == false
            && fit["cpus"] == "24 25 26 27 28 29 30 31"
            && fit["candidate_disk_bytes"] == (1u64 << 30)
            && quote["delivery_quote"]["delivery_memory_max_bytes"] == (64u64 << 30),
        "invalid epoch 252 delivery quote"
    );
    let reference = &quote["delivery_quote"]["handoff"];
    ensure!(
        reference["path"] == format!("{DIRECTORY}/completion.json"),
        "different epoch 252 handoff"
    );
    let handoff = pinned_json(text(reference, "path")?, text(reference, "sha256")?)?;
    let profile = pinned_json(PROFILE, PROFILE_SHA)?;
    ensure!(
        profile["epoch"] == 252
            && profile["unit"] == UNIT
            && profile["reader_plan"] == handoff["read_plan"]
            && profile["ordinary_uploader"] == handoff["uploader"]
            && handoff["publication_authorized"] == false,
        "epoch 252 delivery profile or handoff changed"
    );
    let terminal = collect(&EPOCH_252)?;
    ensure!(
        terminal == handoff["terminal"] && terminal["state"] == "local-cohort-committed",
        "epoch 252 replay is still active or the archive changed"
    );
    ensure!(
        properties(TIMER, "ActiveState,Job")? == json!({"ActiveState":"inactive","Job":""})
            && guard_drained(&properties(
                GUARD,
                "ActiveState,MainPID,ControlPID,ControlGroup,Job"
            )?),
        "epoch 252 guard is still active"
    );
    let deployment = check_deployment(&profile["reader_plan"])?;
    let args = strings(&profile["argv"])?;
    let uploader = &profile["ordinary_uploader"];
    let (image, _) = read_bound(Path::new(text(uploader, "path")?), 128 << 20, 0)?;
    ensure!(
        args.first().copied() == Some(text(uploader, "path")?)
            && sha256(&image) == text(uploader, "sha256")?,
        "epoch 252 uploader changed"
    );
    let socket = text(&profile["planned_environment"], "SSH_AUTH_SOCK")?;
    let meta = fs::symlink_metadata(socket)?;
    ensure!(
        meta.file_type().is_socket() && meta.uid() == 1000,
        "epoch 252 reader SSH agent changed"
    );
    let profile_props = strings(&profile["planned_properties"])?;
    let writable = profile_props
        .iter()
        .find_map(|field| field.strip_prefix("ReadWritePaths="))
        .context("epoch 252 writable paths missing")?;
    let state = Path::new(STATE);
    let _output = receipt_lock(state)?;
    if state.join("booking.json").try_exists()? {
        let path = state.join("booking.json");
        let (bytes, _) = read_bound(&path, 1 << 20, 0)?;
        let prior: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            prior["schema"] == "foundation-epoch252-delivery-booking-v1"
                && prior["deployment"] == deployment
                && prior["drain"] == *reference
                && prior["storage_quote"] == json!({"path":quote_path,"sha256":quote_sha}),
            "different epoch 252 booking already exists"
        );
        return register(state, json!({"path":path,"sha256":sha256(&bytes)}), &args);
    }
    let manager = properties(UNIT, "LoadState,ActiveState,MainPID,Job")?;
    ensure!(
        manager == json!({"LoadState":"not-found","ActiveState":"inactive","MainPID":"0","Job":""}),
        "epoch 252 uploader already exists"
    );
    recheck_fit(&quote)?;
    let auth = format!("--property={AUTH}");
    let inventory: Value = serde_json::from_slice(&command(
        RUN,
        &[
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--unit=foundation-252-delivery-inventory",
            "--property=Type=exec",
            &auth,
            "--setenv=TOKIO_WORKER_THREADS=2",
            "--",
            args[0],
            "inventory",
            text(&profile, "source_directory")?,
            "--epochs",
            "252-252",
        ],
    )?)?;
    ensure!(
        inventory["schema"] == "jetstreamer-horizon-r2-inventory-v1"
            && inventory["entries"]
                .as_array()
                .is_some_and(|a| a.len() == 1)
            && inventory["entries"][0]["epoch"] == 252
            && inventory["entries"][0]["state"] == "missing"
            && inventory["anomalies"] == 0,
        "epoch 252 canonical pair is no longer missing"
    );
    recheck_fit(&quote)?;
    let log = state.join("operation.log");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&log)?
        .sync_all()?;
    let mut properties = profile_props
        .iter()
        .filter(|p| !p.starts_with("ReadWritePaths="))
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    properties.extend([
        "AllowedCPUs=24-31".into(),
        format!("ReadWritePaths={writable} {}", log.display()),
        format!("StandardOutput=append:{}", log.display()),
        "StandardError=inherit".into(),
    ]);
    let closed = write_json(&state.join("producer-terminal.json"), &terminal)?;
    let inventory = write_json(&state.join("authenticated-missing-pair.json"), &inventory)?;
    let booking = write_json(
        &state.join("booking.json"),
        &json!({
            "schema":"foundation-epoch252-delivery-booking-v1","epoch":252,"unit":UNIT,
            "closed_producer":closed,"drain":reference,"profile":{"path":PROFILE,"sha256":PROFILE_SHA},
            "storage_quote":{"path":quote_path,"sha256":quote_sha},"reader_plan":profile["reader_plan"],
            "uploader":uploader,"authenticated_missing_pair":inventory,"staging_copy_required":false,
            "launch_properties":properties,"deployment":deployment,
        }),
    )?;
    let mut start = vec![
        format!("--unit={UNIT}"),
        format!("--setenv=SSH_AUTH_SOCK={socket}"),
    ];
    start.extend(properties.iter().map(|entry| format!("--property={entry}")));
    start.push("--".into());
    start.extend(args.iter().map(|arg| arg.to_string()));
    recheck_fit(&quote)?;
    command(RUN, &start.iter().map(String::as_str).collect::<Vec<_>>())?;
    register(state, booking, &args)
}

fn register(state: &Path, booking: Value, args: &[&str]) -> Result<Value> {
    let owner = super::properties(UNIT, OWNER_FIELDS)?;
    let pid: u32 = text(&owner, "MainPID")?.parse()?;
    let proc = Path::new("/proc").join(pid.to_string());
    let ticks = process_ticks(pid)
        .context("booked epoch 252 uploader is no longer running; inspect its terminal evidence")?;
    ensure!(
        ticks > 0
            && owner["ActiveState"] == "active"
            && owner["SubState"] == "running"
            && owner["AllowedCPUs"] == "24-31"
            && owner["NRestarts"] == "0"
            && owner["MemoryMax"] == (64u64 << 30).to_string()
            && owner["MemorySwapMax"] == "0"
            && owner["Job"] == ""
            && fs::read_link(proc.join("exe"))? == Path::new(args[0])
            && fs::read(proc.join("cmdline"))? == (args.join("\0") + "\0").as_bytes()
            && properties(UNIT, OWNER_FIELDS)? == owner
            && process_ticks(pid)? == ticks,
        "epoch 252 running uploader identity differs"
    );
    let launched = write_json(
        &state.join("launch.json"),
        &json!({
            "schema":"foundation-epoch252-current-reader-delivery-launch-v1","booking":booking,"owner":owner,"process_start_ticks":ticks,"argv":args,
        }),
    )?;
    write_json(
        &state.join("pipeline-claim.json"),
        &json!({
            "epoch":252,"phase":"upload-readback","unit":UNIT,"invocation_id":owner["InvocationID"],
            "expected_exec_start":owner["ExecStart"],"evidence":[booking,launched],
        }),
    )
}
