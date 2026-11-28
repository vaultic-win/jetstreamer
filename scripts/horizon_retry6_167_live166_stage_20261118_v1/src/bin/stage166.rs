//! Exact retry8 deployment and preparation; replay launch remains a separate command.
use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job,Triggers,TriggeredBy,ExecStart,CPUQuotaPerSecUSec,MemoryMax";

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read_bound(path: &Path, expected: &str) -> Result<Value> {
    let bytes = fs::read(path)?;
    ensure!(
        sha(&bytes) == expected,
        "binding mismatch: {}",
        path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn binding(path: &Path) -> Result<Value> {
    Ok(json!({"path":path,"sha256":sha(&fs::read(path)?)}))
}
fn bound(value: &Value) -> Result<Value> {
    let path = Path::new(value["path"].as_str().context("bound path")?);
    read_bound(path, value["sha256"].as_str().context("bound SHA")?)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn utc_now() -> Result<String> {
    let seconds = libc::time_t::try_from(now()?)?;
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    ensure!(
        !unsafe { libc::gmtime_r(&seconds, &mut tm) }.is_null(),
        "UTC conversion"
    );
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}
fn write(root: &Path, name: &str, value: &Value) -> Result<PathBuf> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let path = root.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&bytes)?;
    if name.ends_with("PLAN.json") {
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
    }
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(path)
}
fn output(command: &mut Command) -> Result<String> {
    let result = command.output()?;
    ensure!(
        result.status.success(),
        "command failed: {:?}: {}",
        command,
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}
fn unit_names(previous: &Value, template: &Value) -> Result<BTreeSet<String>> {
    let list = output(Command::new("/usr/bin/systemctl").args([
        "list-units",
        "--all",
        "--type=service",
        "--type=timer",
        "--no-legend",
        "--plain",
        "--no-pager",
    ]))?;
    let mut names: BTreeSet<String> = list
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.ends_with(".service") || name.ends_with(".timer"))
        .map(str::to_owned)
        .collect();
    for key in previous["complete_metadata_unit_census"]
        .as_object()
        .context("old full census")?
        .keys()
    {
        names.insert(key.clone());
    }
    for value in template["closed_units"]
        .as_array()
        .context("closed units")?
    {
        names.insert(value.as_str().context("closed unit name")?.to_owned());
    }
    names.insert(
        template["producer_unit"]
            .as_str()
            .context("producer unit")?
            .to_owned(),
    );
    for suffix in ["service", "timer"] {
        names.insert(format!(
            "horizon-guard-replacement-166-local3retry6-20261110-v1.{suffix}"
        ));
    }
    for epoch in [166, 167, 169, 170] {
        names.insert(format!(
            "horizon-qualify-{epoch}-replacement-local3retry3-20261110-v1.service"
        ));
    }
    for epoch in [166, 167, 170] {
        names.insert(format!(
            "horizon-qualify-{epoch}-replacement-local3retry4-20261110-v1.service"
        ));
    }
    names.insert("horizon-qualify-166-replacement-local3retry5-20261110-v1.service".to_owned());
    Ok(names)
}
fn native(names: &BTreeSet<String>) -> Result<BTreeMap<String, Value>> {
    let names: Vec<_> = names.iter().collect();
    let mut rows = BTreeMap::new();
    for chunk in names.chunks(100) {
        let mut command = Command::new("/usr/bin/systemctl");
        command
            .arg("show")
            .arg(format!("-p{PROPERTIES}"))
            .arg("--")
            .args(chunk);
        let text = output(&mut command)?;
        for (id, row) in parse_blocks(&text)? {
            ensure!(
                rows.insert(id.clone(), row).is_none(),
                "duplicate native unit: {id}"
            );
        }
    }
    ensure!(
        names.iter().all(|name| rows.contains_key(name.as_str())),
        "incomplete native unit census"
    );
    Ok(rows)
}
fn parse_blocks(text: &str) -> Result<BTreeMap<String, Value>> {
    let mut rows = BTreeMap::new();
    for block in text.trim().split("\n\n") {
        let mut row = Map::new();
        for line in block.lines() {
            if let Some((key, value)) = line.split_once('=') {
                row.insert(key.to_owned(), Value::String(value.to_owned()));
            }
        }
        let Some(id) = row.get("Id").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        if id.ends_with(".timer") {
            let mut absent = Vec::new();
            for key in ["MainPID", "ControlPID"] {
                if !row.contains_key(key) {
                    row.insert(key.to_owned(), Value::String("0".to_owned()));
                    absent.push(key);
                }
            }
            row.insert(
                "native_timer_absent_PID_properties_interpreted_as_zero".to_owned(),
                json!(absent),
            );
        }
        ensure!(
            rows.insert(id.clone(), Value::Object(row)).is_none(),
            "duplicate native unit: {id}"
        );
    }
    Ok(rows)
}
fn closed(row: &Value) -> bool {
    matches!(row["ActiveState"].as_str(), Some("inactive" | "failed"))
        && row["Job"] == ""
        && row["MainPID"] == "0"
        && row["ControlPID"] == "0"
}
fn process_claims() -> Result<Vec<Value>> {
    let images = [
        "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-node",
        "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-historical-worker-v1-5-6",
    ];
    let mut claims = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let path = entry.path();
        let Ok(exe) = fs::read_link(path.join("exe")) else {
            continue;
        };
        let Ok(args) = fs::read(path.join("cmdline")) else {
            continue;
        };
        let exe = exe.to_string_lossy().to_string();
        let argv: Vec<String> = args
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).to_string())
            .collect();
        if images.contains(&exe.as_str()) || argv.iter().any(|arg| images.contains(&arg.as_str())) {
            claims.push(json!({"pid":pid,"executable":exe,"argv":argv}));
        }
    }
    Ok(claims)
}

const REPO: &str = "/home/sol/workspace/jetstreamer";
const PACKAGE: &str = "scripts/horizon_retry8_166_20261119_v1";
const SELF_SOURCE: &str =
    "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/stage166.rs";
const ROOT: &str = "/var/lib/jetstreamer/retry8-166-stage-20261119-v1";
const SELF_IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-retry8-166-stage-20261119-v1/stage166";
const BUILD_ROOT: &str =
    "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release";
const GUARD: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch166-retry8-original-slot-guard-20261119-v1/guard";
const GUARD_SHA: &str = "8a13e521a01cb0b58b582ab574d47336a45e20cc75d5dc0f95a43d5ab44588f7";
const PREPARER: &str = "/usr/local/lib/jetstreamer/horizon-retry8-166-prepare-20261119-v1/prepare";
const PREPARER_SHA: &str = "633f5a2f6944e5fda39f39d85682738211c95da17f1d78cf03c95c1cbd456c7d";
const LAUNCHER: &str =
    "/usr/local/lib/jetstreamer/horizon-retry8-single166-launch-20261119-v1/launch";
const LAUNCHER_SHA: &str = "c0bacc1ca7b685fd6cc5bd72eb5ce1d9295330c8c73fe56951843594d7c6dfdb";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const PRIOR_PLAN: &str = "/var/lib/jetstreamer/root1841-zeroowner-census-20261118-v1/operation-v1/epoch166-PREPARE_PLAN.json";
const PRIOR_PLAN_SHA: &str = "5863df282762295c99bf63b381e85dd07402f6e1ef296e4eb4a6996e897e2b99";
const COMPLETE_DATA: u64 = 6_794_761_027_378;
const RAW_FLOOR: u64 = 6_829_053_656_882;
const CAP: u64 = 309_237_645_312;

fn b(path: &str) -> Result<Value> {
    binding(Path::new(path))
}
fn read(path: &str) -> Result<Value> {
    bound(&b(path)?)
}
fn private(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => File::open(path.parent().context("parent")?)?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_dir() && md.uid() == 0 && md.mode() & 0o7777 == 0o700 && path.canonicalize()? == path,
        "unsafe private root"
    );
    Ok(())
}
fn git(args: &[&str]) -> Result<String> {
    output(Command::new("git").args(["-C", REPO]).args(args))
}
fn source_commit() -> Result<String> {
    let commit = git(&["rev-parse", "HEAD"])?;
    git(&[
        "merge-base",
        "--is-ancestor",
        commit.trim(),
        "origin/account-updates",
    ])?;
    ensure!(
        git(&[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            PACKAGE,
            SELF_SOURCE
        ])?
        .is_empty(),
        "required source is not clean/committed"
    );
    Ok(commit.trim().into())
}
fn seal(root: &Path, name: &str, destination: &Path, members: Value) -> Result<()> {
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    let plan = write(
        root,
        name,
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,"members":members}),
    )?;
    output(Command::new(SEALER).arg(&plan).args([
        "--plan-sha256",
        &sha(&fs::read(&plan)?),
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    Ok(())
}
fn member(path: &Path, name: &str, mode: u32) -> Result<Value> {
    Ok(json!({"source":path,"name":name,"sha256":sha(&fs::read(path)?),"mode":mode}))
}
fn execution(root: &Path, unit: &str, tests: Option<u64>) -> Result<Value> {
    let native=output(Command::new("systemctl").args(["show",unit,"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Result,ExecMainStatus,ExecStart,Environment,MemoryMax,CPUQuotaPerSecUSec"]))?;
    for required in [
        "LoadState=loaded",
        "ActiveState=active",
        "SubState=exited",
        "MainPID=0",
        "ControlPID=0",
        "Result=success",
        "ExecMainStatus=0",
        "MemoryMax=2147483648",
        "CPUQuotaPerSecUSec=2s",
    ] {
        ensure!(
            native.lines().any(|s| s == required),
            "qualification {unit} lacks {required}"
        );
    }
    let iid = native
        .lines()
        .find_map(|s| s.strip_prefix("InvocationID="))
        .context("IID")?;
    ensure!(iid.len() == 32, "invocation absent");
    let journal = output(Command::new("journalctl").args([
        "--no-pager",
        "--all",
        "-o",
        "cat",
        &format!("_SYSTEMD_INVOCATION_ID={iid}"),
    ]))?;
    if let Some(count) = tests {
        ensure!(
            journal.contains(&format!(
                "test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
            )),
            "incomplete tests: {unit}"
        );
    }
    let path = write(
        root,
        &format!("{unit}.json"),
        &json!({"unit":unit,"native":native,"journal":journal,"observed_at":now()?}),
    )?;
    binding(&path)
}
fn deploy() -> Result<()> {
    let commit = source_commit()?;
    let root = Path::new(ROOT).join("deployment");
    private(&root)?;
    for (label, artifact, dest, digest, build, test, count, features) in [
        (
            "guard",
            "guard",
            GUARD,
            GUARD_SHA,
            "horizon-retry8-166-guard-build-20261119-v3.service",
            "horizon-retry8-166-guard-test-root-20261119-v1.service",
            98,
            vec![],
        ),
        (
            "prepare",
            "prepare",
            PREPARER,
            PREPARER_SHA,
            "horizon-retry8-166-prepare-release-20261119-v1.service",
            "horizon-retry8-166-prepare-test-root-20261119-v1.service",
            216,
            vec!["preparation"],
        ),
        (
            "launch",
            "horizon-retry8-single166-launch-v3",
            LAUNCHER,
            LAUNCHER_SHA,
            "horizon-retry8-166-launch-release-20261119-v1.service",
            "horizon-retry8-166-launch-test-20261119-v2.service",
            7,
            vec![],
        ),
    ] {
        let dir = root.join(label);
        private(&dir)?;
        let image = Path::new(BUILD_ROOT).join(artifact);
        ensure!(
            sha(&fs::read(&image)?) == digest,
            "production image changed"
        );
        let build = execution(&dir, build, None)?;
        let test = execution(&dir, test, Some(count))?;
        let paths = git(&["ls-files", "--", &format!("{PACKAGE}/{label}")])?;
        let mut sources = Map::new();
        // Launcher source lives in launch; the other labels also match directory names.
        for path in paths.lines() {
            sources.insert(
                path.into(),
                json!(sha(&fs::read(Path::new(REPO).join(path))?)),
            );
        }
        ensure!(!sources.is_empty(), "source closure missing");
        let proof = write(
            &dir,
            "artifact-proof.json",
            &json!({"schema":if label=="guard" {"horizon-epoch166-retry8-original-slot-guard-artifact-proof-v1"}else{"horizon-epoch166-retry8-artifact-proof-v1"},
            "epoch":166,"attempt":"local3retry8","owner":"/root","primary_thread":THREAD,"source_commit":commit,"source_files":sources,
            "production":{"path":dest,"sha256":digest,"feature_flags":features},"tests":{"passed":count,"failed":0},"executions":{"production":build,"tests":test},
            "replay_launch_authorized":false,"remote_mutations":false}),
        )?;
        seal(
            &dir,
            "SEAL_PLAN.json",
            Path::new(dest).parent().unwrap(),
            json!([
                member(
                    &image,
                    Path::new(dest).file_name().unwrap().to_str().unwrap(),
                    0o555
                )?,
                member(&proof, "artifact-proof.json", 0o444)?
            ]),
        )?;
    }
    Ok(())
}
fn roots_proof() -> Result<Value> {
    let mut roots = Vec::new();
    for (epoch, attempt, inode) in [
        (166, "local3retry8", 104792636u64),
        (167, "local3retry7", 106109752),
        (170, "local3retry6", 107746436),
    ] {
        let p = PathBuf::from(format!(
            "/home/sol/.jetstreamer-private/epoch{epoch}-standard-lane-20261109-v1/replacement-{attempt}-20261110-v1"
        ));
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            p.canonicalize()? == p
                && m.is_dir()
                && m.uid() == 1001
                && m.mode() & 0o7777 == 0o700
                && m.ino() == inode
                && m.dev() == 64512,
            "precreated root changed"
        );
        ensure!(fs::read_dir(&p)?.next().is_none(), "next root is not empty");
        roots.push(json!({"path":p,"device":m.dev(),"inode":m.ino()}));
    }
    let p = write(
        Path::new(ROOT),
        "PRECREATED_ROOTS.json",
        &json!({"schema":"horizon-three-next-roots-before-witness-v1","owner":"/root","primary_thread":THREAD,"recorded_unix_seconds":now()?,"roots":roots,"remote_mutations":false}),
    )?;
    binding(&p)
}
fn own_witness(root: &Path, tag: &str) -> Result<Value> {
    ensure!(sha(&fs::read(GUARD)?) == GUARD_SHA, "guard changed");
    let witness = root.join("NATIVE_WITNESS.json");
    output(Command::new("systemd-run").args(["--unit",&format!("horizon-retry8-166-witness-{tag}-20261119-v1"),"--property=Type=oneshot","--property=RemainAfterExit=yes","--property=CPUQuota=200%","--property=MemoryMax=4G","--property=TasksMax=128","--property=LimitNOFILE=1048576",
        GUARD,"--qualify-data-witness","/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/witness-set.json","--seed-sha256","8eb041519cba5c3f6368cb1432be9e289489ce1acdc28aa8b49f3d6ec7f382ee","--seal","/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/deployment-seal-receipt.json","--seal-sha256","611c29b18c52e02fce0be67314cdaae4ff780bea72b0e8e6c22a7dd248dfc24f","--output",witness.to_str().unwrap(),"--self-sha256",GUARD_SHA]))?;
    let w = read(witness.to_str().unwrap())?;
    ensure!(
        w["native_identity"]["executable"] == GUARD
            && w["native_identity"]["executable_sha256"] == GUARD_SHA,
        "wrong witness image"
    );
    let mut c = read("/var/lib/jetstreamer/epoch166-retry7-guard-20261118-v1/contract-v4.json")?;
    c["qualified_native_witness"] = binding(&witness)?;
    let p = write(root, "contract.json", &c)?;
    let dest = format!("/usr/local/lib/jetstreamer/horizon-retry8-166-contract-{tag}-20261119-v1");
    seal(
        root,
        "CONTRACT_SEAL_PLAN.json",
        Path::new(&dest),
        json!([member(&p, "contract.json", 0o444)?]),
    )?;
    Ok(
        json!({"contract":b(&format!("{dest}/contract.json"))?,"deployment_seal":b(&format!("{dest}/deployment-seal-receipt.json"))?}),
    )
}
fn measured(m: &Value) -> Result<u64> {
    let t = m["recorded_unix_seconds"]
        .as_u64()
        .context("measurement time")?;
    let bytes = m["physical"]["physical_bytes"]
        .as_u64()
        .context("physical bytes")?;
    ensure!(
        m["epoch"] == 166
            && m["read_only"] == true
            && m["resource_credit_bytes"] == 0
            && m["lane_root"]
                == "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1"
            && t <= now()?
            && now()? - t <= 1800
            && bytes > 0
            && bytes < CAP,
        "fresh complete166 physical ledger required"
    );
    Ok(bytes)
}
fn review(root: &Path, plan: &mut Value, census: &Path, measurement: &Path) -> Result<()> {
    let m = read(measurement.to_str().context("measurement path")?)?;
    let retained = measured(&m)?;
    let mut input = bound(&plan["input_proof"])?;
    input["recorded_unix_seconds"] = json!(now()?);
    plan["input_proof"] = binding(&write(root, "LOCAL_INPUT_REQUEST.json", &input)?)?;
    let mut r = bound(&plan["review"])?;
    r["attempt"] = plan["attempt"].clone();
    r["recorded_unix_seconds"] = json!(now()?);
    for (to, from) in [
        ("source_fleet", "fleet"),
        ("source_inventory", "inventory"),
        ("input_proof", "input_proof"),
        ("cleanup_completion", "cleanup_completion"),
        ("data_fulfillment", "data_fulfillment"),
    ] {
        r[to] = plan[from].clone();
    }
    r["full_current_proc_and_unit_census"] = binding(census)?;
    r["current_budget"]["additional_data_bytes"] = json!(COMPLETE_DATA - 6_229_838_610_226u64);
    r["current_budget"]["complete_data_bytes"] = json!(COMPLETE_DATA);
    r["current_budget"]["raw_floor_bytes"] = json!(RAW_FLOOR);
    let growth = CAP - retained;
    r["retained_lane_physical_bytes"] = json!(retained);
    for key in [
        "candidate_remaining_growth_bytes",
        "existing_original_slot_future_growth_bytes",
        "proposed_fresh_working_maximum_bytes",
    ] {
        r[key] = json!(growth);
    }
    r["additional_growth_not_covered_by_existing_promise_bytes"] = json!(0);
    r["minimum_initial_available_data_bytes"] =
        json!(RAW_FLOOR + growth + (10u64 << 30) + (64u64 << 20));
    let slot = json!({"schema":"horizon-standard-replacement-exclusive-slot-mapping-v1","owner":"/root","epoch":166,"recorded_unix_seconds":now()?,"physical_ledger":binding(measurement)?,"retained_lane_physical_bytes":retained,"combined_original_lane_cap_bytes":CAP,"old_remaining_future_promise_bytes":growth,"proposed_fresh_working_maximum_bytes":growth,"additional_DATA_bytes":0,"all_original_promises_retained":true,"guard_root_remains_whole_original_lane":true,"original_stop":m["original_stop"],"replay_launch_authorized":false});
    r["exact_slot_mapping_and_physical_ledger"] =
        binding(&write(root, "EXCLUSIVE_SLOT_MAPPING.json", &slot)?)?;
    let working = json!({"schema":"horizon-retry3-concurrent-working-set-v1","owner":"/root","recorded_unix_seconds":now()?,"fleet":plan["fleet"],"forecast_offloads_credited_bytes":0,"retained_promises_released_bytes":0,"immutable_raw_guard_floor_bytes":RAW_FLOOR,"unrelated_growth_margin_bytes":10u64<<30,"lanes":[{"epoch":166,"state":"candidate","producer_unit":plan["producer_unit"],"retained_lane_physical_bytes":retained,"remaining_growth_bytes":growth}]});
    plan["retry3"]["concurrent_working_set"] =
        binding(&write(root, "WORKING_SET.json", &working)?)?;
    plan["review"] = binding(&write(root, "PRELAUNCH_REVIEW.json", &r)?)?;
    Ok(())
}
fn stage(tag: &str, fleet_path: &Path, measurement: Option<&Path>) -> Result<()> {
    ensure!(
        tag.len() == 4 && tag.bytes().all(|b| b.is_ascii_digit()),
        "four-digit unique tag required"
    );
    let root = Path::new(ROOT).join(tag);
    ensure!(!root.exists(), "attempt exists");
    private(&root)?;
    let mut fleet = read(fleet_path.to_str().context("fleet path")?)?;
    ensure!(
        fleet["complete_DATA_bytes"] == COMPLETE_DATA
            && fleet["complete_projected_memory_bytes"] == 761_131_708_416u64
            && fleet["active_producer_count"] == 0,
        "exact stopped complete fleet required"
    );
    let observer = bound(&fleet["observer"])?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["replays"] == json!([])
            && utc_now()?.as_str()
                < observer["cadence"]["next_routine_observation_not_before_utc"]
                    .as_str()
                    .context("observer deadline")?,
        "fresh zero-owner sample required"
    );
    let mut plan = read_bound(Path::new(PRIOR_PLAN), PRIOR_PLAN_SHA)?;
    plan["attempt"] = json!("local3retry8");
    plan["producer_unit"] =
        json!("horizon-qualify-166-replacement-local3retry8-20261110-v1.service");
    plan["guard_base"] = json!("horizon-guard-replacement-166-local3retry8-20261110-v1");
    plan["fresh_subtree"] = json!(
        "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1"
    );
    plan["retry8_precreated_roots"] = b(&format!("{ROOT}/PRECREATED_ROOTS.json"))?;
    plan["resident_memory"]["observer"] = fleet["observer"].clone();
    plan["resident_memory"]["owners"] = json!([]);
    for (e, a) in [(166, "local3retry8"), (167, "local3retry6")] {
        for u in [
            format!("horizon-qualify-{e}-replacement-{a}-20261110-v1.service"),
            format!("horizon-guard-replacement-{e}-{a}-20261110-v1.service"),
            format!("horizon-guard-replacement-{e}-{a}-20261110-v1.timer"),
        ] {
            let rows = plan["closed_units"]
                .as_array_mut()
                .context("closed units")?;
            if !rows.contains(&json!(u)) {
                rows.push(json!(u));
            }
        }
    }
    let contract = own_witness(&root, tag)?;
    plan["data_fulfillment"] = json!({"runtime":b(GUARD)?,"runtime_seal":binding(&Path::new(GUARD).parent().unwrap().join("deployment-seal-receipt.json"))?,"qualification":binding(&Path::new(GUARD).parent().unwrap().join("artifact-proof.json"))?,"contract":contract});
    let previous = bound(&fleet["full_current_proc_and_unit_census"])?;
    let names = unit_names(&previous, &plan)?;
    let before = native(&names)?;
    for u in plan["closed_units"].as_array().unwrap() {
        let u = u.as_str().unwrap();
        ensure!(closed(&before[u]), "not closed: {u}");
    }
    ensure!(process_claims()?.is_empty(), "166 process remains");
    let after = native(&names)?;
    for u in plan["closed_units"].as_array().unwrap() {
        let u = u.as_str().unwrap();
        ensure!(
            before[u] == after[u] && closed(&after[u]),
            "closed owner changed: {u}"
        );
    }
    ensure!(process_claims()?.is_empty(), "166 process appeared");
    let raw = write(&root, "CURRENT_NATIVE_RAW.json", &json!(before))?;
    let census = write(
        &root,
        "CURRENT_CENSUS.json",
        &json!({"schema":"horizon-standard-replacement-Root-current-unit-and-proc-census-v1","owner":"/root","sole_primary_thread":THREAD,"recorded_unix_seconds":now()?,"complete_metadata_unit_census":before,"full_raw_native_metadata_census":binding(&raw)?,"exact_selected_node_and_worker_process_claims":[],"no_new_target_owner_or_queued_launch":true}),
    )?;
    fleet["previous_Root_operational_review"] = binding(fleet_path)?;
    fleet["full_current_proc_and_unit_census"] = binding(&census)?;
    fleet["metadata_unit_census"] = json!(before);
    fleet["recorded_unix_seconds"] = json!(now()?);
    plan["fleet"] = binding(&write(
        &root,
        "ROOT_COMPLETE_OPERATIONAL_FLEET.json",
        &fleet,
    )?)?;
    plan["inventory"] = fleet["authenticated_inventory"].clone();
    if let Some(m) = measurement {
        review(&root, &mut plan, &census, m)?;
    }
    let p = write(
        &root,
        if measurement.is_some() {
            "PREPARE_PLAN.json"
        } else {
            "MEASURE_PLAN.json"
        },
        &plan,
    )?;
    let out = Path::new("/var/lib/jetstreamer/retry8-preparation-20261119-v1");
    private(out)?;
    private(&out.join("epoch166"))?;
    private(&out.join("epoch166/local3retry8"))?;
    ensure!(
        sha(&fs::read(PREPARER)?) == PREPARER_SHA,
        "preparer changed"
    );
    output(Command::new("systemd-run").args([
        "--unit",
        &format!("horizon-retry8-166-prepare-{tag}-20261119-v1"),
        "--property=Type=oneshot",
        "--property=RemainAfterExit=yes",
        "--property=CPUQuota=200%",
        "--property=MemoryMax=4G",
        "--property=TasksMax=128",
        "--property=LimitNOFILE=1048576",
        PREPARER,
        p.to_str().unwrap(),
        "--plan-sha256",
        &sha(&fs::read(&p)?),
        "--self-sha256",
        PREPARER_SHA,
        if measurement.is_some() {
            "--prepare"
        } else {
            "--measure-only"
        },
    ]))?;
    println!("{}", binding(&p)?);
    Ok(())
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() >= 2,
        "seal | deploy | roots | measure TAG FLEET | prepare TAG FLEET MEASUREMENT"
    );
    let commit = source_commit()?;
    private(Path::new(ROOT))?;
    if a[1] == "seal" {
        ensure!(a.len() == 2, "arguments");
        let root = Path::new(ROOT).join("self-seal");
        private(&root)?;
        let evidence = execution(
            &root,
            "horizon-retry8-166-stage-tests-20261119-v2.service",
            Some(1),
        )?;
        let build = execution(
            &root,
            "horizon-retry8-166-stage-build-20261119-v1.service",
            None,
        )?;
        let proof = write(
            &root,
            "artifact-proof.json",
            &json!({"source_commit":commit,"tests":evidence,"build":build,"source":b(&format!("{REPO}/{SELF_SOURCE}"))?,"replay_launch_authorized":false}),
        )?;
        return seal(
            &root,
            "SELF_SEAL_PLAN.json",
            Path::new(SELF_IMAGE).parent().unwrap(),
            json!([
                member(&fs::read_link("/proc/self/exe")?, "stage166", 0o555)?,
                member(&proof, "artifact-proof.json", 0o444)?
            ]),
        );
    }
    ensure!(
        fs::read_link("/proc/self/exe")? == Path::new(SELF_IMAGE),
        "sealed stage image required"
    );
    match a[1].as_str() {
        "deploy" if a.len() == 2 => deploy(),
        "roots" if a.len() == 2 => {
            println!("{}", roots_proof()?);
            Ok(())
        }
        "measure" if a.len() == 4 => stage(&a[2], Path::new(&a[3]), None),
        "prepare" if a.len() == 5 => stage(&a[2], Path::new(&a[3]), Some(Path::new(&a[4]))),
        _ => anyhow::bail!("unsupported arguments"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_closed_states_reject_work_and_timer_normalization_is_explicit() {
        let r = parse_blocks("Id=x.timer\nActiveState=inactive\nJob=\n").unwrap();
        assert!(closed(&r["x.timer"]));
        let mut v = r["x.timer"].clone();
        v["ActiveState"] = json!("active");
        assert!(!closed(&v));
        v["ActiveState"] = json!("inactive");
        v["Job"] = json!("1");
        assert!(!closed(&v));
    }
}
