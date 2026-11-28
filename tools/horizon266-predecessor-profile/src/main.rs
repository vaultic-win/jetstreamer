//! Stage and qualify the exact private predecessor scope without replaying it.
#![recursion_limit = "256"]
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, chown},
    path::{Path, PathBuf},
    process::Command,
};

const V: &str = "/var/lib/jetstreamer";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-266-original-predecessor-v1";
const STATE: &str = "horizon266-original-predecessor-runtime-v1";
const PACKAGE: &str = "horizon266-original-predecessor-static-v1";
const TOKENS: &str = "horizon266-original-predecessor-tokens-v1";
const UNIT: &str = "horizon-qualify-266-original-predecessor-v1.service";
const GUARD_UNIT: &str = "horizon-266-original-predecessor-protective-v1.service";
const PREPARATION: &str =
    "/var/lib/jetstreamer/horizon266-predecessor-focused-preparation-v1/preparation.json";
const PREPARATION_SHA: &str = "9c8e67688a2fe4c3abc5603e54f7dec02da24516bab30b6762c93152443dcc48";
const OVERLAP: &str =
    "/var/lib/jetstreamer/horizon266-hourly-overlap-114929697-runtime-v1/profile.json";
const OVERLAP_SHA: &str = "494849a05eb8b63f1770c5ae54dc63a1cc1dfadbd09b235c3938ee28393d08ea";
const SEALER: &str =
    "/var/lib/jetstreamer/horizon251-published-sealer-20261118-v1/horizon251-sealer";
const SEALER_SHA: &str = "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a";
const HOOK: &str = "/var/lib/jetstreamer/horizon230-final-tail-tokens-v1/pre-start.sh";
const HOOK_SHA: &str = "14c316bf3fc8ff28800c9b7bb673f42f95995a2a2b1ac0b9654c36c0a83832e0";
const INDEX_265_SEAL_SHA: &str = "425b847ba91fdbfe840dd211d543a23333fb064f3a4bb6e2b43d80ef7cccc7cf";
const INDEX_266_SEAL_SHA: &str = "1a6d83262359ae23faf0ced210ff6a350b5670366c2df7aa2787e2520177eae1";
const BOOT: u64 = 114_910_768;
const FIRST_OUTPUT: u64 = 114_912_000;
const LAST: u64 = 114_923_430;
const EXECUTION_SLOTS: u64 = LAST - BOOT;
const OUTPUT_SLOTS: u64 = LAST - FIRST_OUTPUT + 1;
const MEMORY: u64 = 256 << 30;
const TMPFS: u64 = 128 << 30;
const HOME: u64 = 16 << 30;
const RECEIPTS: u64 = 256 << 20;
const FLOOR: u64 = 3_770_104_987_645;
const MAX_SMALL_INPUT: u64 = 64 << 20;

fn val_text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .with_context(|| format!("missing {field}"))
}

fn path(value: &Value, field: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(val_text(value, field)?))
}

fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn reference(path: &Path, sha256: &str) -> Value {
    json!({"path": path, "sha256": sha256})
}

fn identity(meta: &fs::Metadata) -> Value {
    json!({
        "device": meta.dev(), "inode": meta.ino(), "bytes": meta.len(),
        "mtime": [meta.mtime(), meta.mtime_nsec()], "ctime": [meta.ctime(), meta.ctime_nsec()],
    })
}

fn open(path: &Path, sealed: bool) -> Result<(File, Value)> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "indirect path {}",
        path.display()
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1,
        "unsafe file {}",
        path.display()
    );
    ensure!(
        !sealed || (meta.uid() == 0 && meta.mode() & 0o222 == 0),
        "unsealed root file {}",
        path.display()
    );
    Ok((file, identity(&meta)))
}

fn read_bound(binding: &Value, sealed: bool) -> Result<Vec<u8>> {
    let path = path(binding, "path")?;
    let (file, before) = open(&path, sealed)?;
    let length = before["bytes"].as_u64().context("missing file length")?;
    ensure!(
        length <= MAX_SMALL_INPUT,
        "oversized evidence {}",
        path.display()
    );
    let mut data = Vec::new();
    (&file).take(length + 1).read_to_end(&mut data)?;
    ensure!(
        digest(&data) == binding["sha256"]
            && data.len() as u64 == length
            && identity(&file.metadata()?) == before
            && open(&path, sealed)?.1 == before,
        "changed evidence {}",
        path.display()
    );
    Ok(data)
}

fn read_json(binding: &Value, sealed: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&read_bound(binding, sealed)?)?)
}

fn json_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<Value> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.set_permissions(Permissions::from_mode(mode))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(reference(path, &digest(data)))
}

fn write_json(path: &Path, value: &Value) -> Result<Value> {
    write_file(path, &json_bytes(value)?, 0o400)
}

fn mkdir(path: &Path, mode: u32, ubuntu: bool) -> Result<()> {
    DirBuilder::new().mode(mode).create(path)?;
    fs::set_permissions(path, Permissions::from_mode(mode))?;
    if ubuntu {
        chown(path, Some(1000), Some(1000))?;
    }
    Ok(())
}

fn checked(command: &mut Command) -> Result<Vec<u8>> {
    let result = command.env_clear().env("LC_ALL", "C").output()?;
    ensure!(
        result.status.success(),
        "{:?} exited {}: {}",
        command.get_program(),
        result.status,
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(result.stdout)
}

fn prep_facts(prep: &Value) -> Result<()> {
    ensure!(
        prep["schema"] == "foundation-epoch266-original-predecessor-focused-preparation-v1"
            && prep["epoch"] == 266
            && prep["bootstrap_slot"] == BOOT
            && prep["replay_first_slot"] == BOOT + 1
            && prep["output_first_slot"] == FIRST_OUTPUT
            && prep["checkpoint_slot"] == LAST
            && prep["expected_executed_positions"] == EXECUTION_SLOTS
            && prep["expected_output_positions"] == OUTPUT_SLOTS
            && prep["future_root"] == ROOT
            && prep["intake"]["stage_peak_bytes"] == 16_843_111_566u64
            && prep["intake"]["source_bytes"] == 16_826_334_350u64
            && prep["intake"]["simultaneous_payload_copies"] == 1
            && prep["launch_authorized"] == false
            && prep["publication_authorized"] == false,
        "preparation does not bind the selected replay and intake"
    );
    let quote = &prep["resource_projection"];
    ensure!(
        quote["combined_ram_bytes"] == MEMORY + (2 << 30)
            && quote["tmpfs_inside_producer_bytes"] == TMPFS
            && quote["replay_home_peak_bytes"] == HOME + RECEIPTS
            && quote["replay_cpus"] == "32-39"
            && quote["guard_cpu"] == 30
            && quote["close_230_drain_required"] == true,
        "preparation resource scope differs"
    );
    Ok(())
}

fn fixture(prep: &Value, checkpoint_names: &str, argv: &[String]) -> Result<()> {
    let proof = &prep["qualification"];
    ensure!(
        proof["namespace_has_no_network"] == true
            && proof["original_payload_present"] == false
            && proof["resource_limits"]["file_bytes"] == 2 << 20
            && proof["resource_limits"]["memory_bytes"] == 1 << 30,
        "unbounded CLI fixture"
    );
    let args: Vec<String> = serde_json::from_slice(&read_bound(&proof["command"], false)?)?;
    let (options, observed) = args.split_at(
        args.iter()
            .position(|arg| arg == "--")
            .context("missing CLI boundary")?,
    );
    for option in [
        "--property=PrivateNetwork=yes",
        "--property=RestrictAddressFamilies=AF_UNIX",
        "--property=MemoryMax=1G",
        "--property=LimitFSIZE=2M",
    ] {
        ensure!(
            options.iter().any(|actual| actual == option),
            "fixture lacks {option}"
        );
    }
    let fixture_root = path(&proof["command"], "path")?
        .parent()
        .context("missing CLI fixture root")?
        .to_owned();
    let root_text = fixture_root.to_str().context("non-UTF8 fixture root")?;
    ensure!(
        observed[1..].iter().zip(argv).count() == argv.len() && observed.len() == argv.len() + 1,
        "CLI fixture has a different argument count"
    );
    for (actual, expected) in observed[1..].iter().zip(argv) {
        let relocated = if actual == &format!("--epoch-hashes={root_text}/epoch-hashes.txt") {
            format!("--epoch-hashes={V}/{PACKAGE}/epoch-hashes.txt")
        } else {
            actual.replace(root_text, ROOT)
        };
        ensure!(
            &relocated == expected,
            "CLI argument differs after relocation: {actual}"
        );
    }
    let (copy, _) = open(&fixture_root.join("epoch-hashes.txt"), false)?;
    let mut copy_text = String::new();
    (&copy).take(2048).read_to_string(&mut copy_text)?;
    ensure!(
        copy_text == checkpoint_names,
        "fixture used different checkpoint names"
    );
    let log = String::from_utf8(read_bound(&proof["log"], false)?)?;
    ensure!(
        log.contains(&format!("bootstrap {BOOT}, replay {}..={LAST}", BOOT + 1))
            && log.contains(&format!("selected execution profile solana-v1.8.11 (Candidate) from slots {FIRST_OUTPUT}..{}", LAST + 1))
            && log.contains("execution=solana-v1.8.11-epochs-266-301-checkpoint-candidate output=HorizonV2")
            && log.contains("snapshot override must name a non-empty regular file"),
        "fixture did not reach the expected bounded bootstrap gate"
    );
    Ok(())
}

fn index_seal(source: &Path) -> Result<Value> {
    let parent = source.parent().context("index without a seal directory")?;
    let sha = match parent.to_str() {
        Some("/var/lib/jetstreamer/horizon265-index-20261119-v1") => INDEX_265_SEAL_SHA,
        Some("/var/lib/jetstreamer/horizon266-index-acquire-v1/cache/sealed") => INDEX_266_SEAL_SHA,
        _ => bail!("unexpected index seal directory {}", parent.display()),
    };
    let seal = reference(&parent.join("deployment-seal-receipt.json"), sha);
    let receipt = read_json(&seal, true)?;
    ensure!(
        receipt["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && receipt["destination"] == json!(parent),
        "different index seal"
    );
    Ok(json!({"seal": seal, "members": receipt["members"]}))
}

fn input_bindings(prep: &Value, run: &Path) -> Result<Vec<Value>> {
    let mut bindings = Vec::new();
    let inputs = prep["existing_readonly_inputs"]
        .as_array()
        .context("missing projected input list")?;
    ensure!(
        inputs.len() == 5,
        "expected genesis and four compact indexes"
    );
    for input in inputs {
        let source = path(input, "path")?;
        let target = path(input, "destination")?;
        let name = source.file_name().context("missing input name")?;
        ensure!(
            target.starts_with(run.join("work/output")) && target.file_name() == Some(name),
            "incorrect projection for {}",
            source.display()
        );
        let observed = open(&source, true)?.1;
        ensure!(
            observed["bytes"] == input["bytes"] && observed["inode"] == input["inode"],
            "input no longer matches its preparation identity: {}",
            source.display()
        );
        let mut binding = input.clone();
        binding["identity"] = observed;
        if name == "genesis.tar.bz2" {
            read_bound(input, true)?;
            binding["whole_file_sha256_rechecked"] = json!(true);
        } else {
            let seal = index_seal(&source)?;
            let valid = seal["members"]
                .as_array()
                .context("missing index seal members")?
                .iter()
                .any(|member| {
                    member["name"].as_str() == name.to_str()
                        && member["sha256"] == input["sha256"]
                        && member["bytes"] == input["bytes"]
                        && member["mode"] == "0444"
                });
            ensure!(
                valid,
                "index is foreign to the authenticated seal: {}",
                source.display()
            );
            binding["deployment_seal"] = seal["seal"].clone();
            binding["whole_file_sha256_rechecked"] = json!(false);
        }
        bindings.push(binding);
    }
    Ok(bindings)
}

fn mount_options(path: &Path, table: &str) -> Result<(String, String, String)> {
    let mut matches = table.lines().filter_map(|row| {
        let fields: Vec<_> = row.split_whitespace().collect();
        (fields.get(4).copied() == path.to_str()).then_some(fields)
    });
    let fields = matches
        .next()
        .with_context(|| format!("missing exact mount {}", path.display()))?;
    ensure!(matches.next().is_none(), "stacked mount {}", path.display());
    let sep = fields
        .iter()
        .position(|field| *field == "-")
        .context("invalid mountinfo")?;
    Ok((
        fields[5].to_owned(),
        fields[sep + 1].to_owned(),
        fields[sep + 3].to_owned(),
    ))
}

fn probe(token: &Path, boot_name: &str, targets: &[String]) -> Result<Value> {
    ensure!(unsafe { libc::geteuid() } == 1000, "wrong namespace user");
    let run = Path::new(ROOT);
    let work = run.join("work");
    let scratch = work.join("scratch");
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let (options, kind, superoptions) = mount_options(&scratch, &mounts)?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let location = std::ffi::CString::new(scratch.as_os_str().as_encoded_bytes())?;
    // SAFETY: both the null-terminated path and the writable stat buffer are valid.
    ensure!(
        unsafe { libc::statvfs(location.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    // SAFETY: successful statvfs initialized the buffer.
    let stat = unsafe { stat.assume_init() };
    ensure!(
        kind == "tmpfs"
            && superoptions.split(',').any(|opt| opt == "noswap")
            && options.split(',').any(|opt| opt == "rw")
            && stat.f_blocks * stat.f_frsize == TMPFS
            && stat.f_files == 1_048_576
            && fs::metadata(&scratch)?.dev() != fs::metadata(run)?.dev()
            && fs::metadata(work.join("output"))?.dev() == fs::metadata(run)?.dev(),
        "scratch or persistent output is on the wrong mount"
    );
    let mut projected = Vec::new();
    let boot = run.join("input").join(boot_name);
    for target in targets
        .iter()
        .map(Path::new)
        .chain(std::iter::once(boot.as_path()))
    {
        let (options, _, _) = mount_options(target, &mounts)?;
        ensure!(
            options.split(',').any(|option| option == "ro"),
            "projection is not read-only"
        );
        let (file, observed) = open(target, true)?;
        let mut first = [0; 1];
        (&file).read_exact(&mut first)?;
        projected.push(observed);
    }
    for directory in [scratch, work.join("output"), work.join("state")] {
        let marker = directory.join(".static-namespace-probe");
        write_file(&marker, b"probe", 0o600)?;
        fs::remove_file(marker)?;
    }
    let network = fs::read_to_string("/proc/net/dev")?;
    let interfaces: Vec<_> = network
        .lines()
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect();
    ensure!(
        interfaces == ["lo"],
        "namespace can see external network interfaces"
    );
    let result = Command::new("/usr/bin/bash")
        .args([HOOK, "0"])
        .arg(token)
        .env_clear()
        .env("INVOCATION_ID", "qualification")
        .status()?;
    ensure!(
        result.success(),
        "sealed prestart cannot see its projected token"
    );
    Ok(
        json!({"source_identities": projected, "scratch_tmpfs_bytes": TMPFS, "scratch_tmpfs_inodes": 1048576,
        "scratch_noswap": true, "host_backed_output": true, "readonly_binds": true,
        "isolated_network": true, "unprivileged_token_hook_reached": true, "worker_executed": false}),
    )
}

fn runtime_properties(overlap: &Value, run: &Path) -> Result<Value> {
    let mut properties = overlap["properties"].clone();
    for (property, expected) in [
        ("AllowedCPUs", "32-39"),
        ("CPUAffinity", "32-39"),
        ("MemoryMax", "274877906944"),
        ("RuntimeMaxSec", "7200"),
        ("MemorySwapMax", "0"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Type", "exec"),
    ] {
        ensure!(
            properties[property] == expected,
            "overlap profile changed {property}"
        );
    }
    let scratch = run.join("work/scratch");
    properties["WorkingDirectory"] = json!(run);
    properties["ReadWritePaths"] = json!(run.join("work"));
    properties["TemporaryFileSystem"] = json!(format!(
        "{}:rw,size={TMPFS},nr_inodes=1048576,mode=0700,uid=1000,gid=1000,nosuid,nodev,exec,noswap",
        scratch.display()
    ));
    properties["UnsetEnvironment"] = json!(
        "HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY HORIZON_PUBLIC_BASE_URL"
    );
    properties["Delegate"] = json!("no");
    Ok(properties)
}

fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => bail!("path already exists {}", path.display()),
    }
}

fn append_property(command: &mut Command, properties: &Value, skip: &[&str]) -> Result<()> {
    for (field, value) in properties
        .as_object()
        .context("missing service properties")?
    {
        if !skip.contains(&field.as_str()) {
            let value = value.as_str().context("service property is not text")?;
            command.arg(format!("--property={field}={value}"));
        }
    }
    Ok(())
}

fn render_unit(profile: &Value, units: &Path) -> Result<Value> {
    let mut text =
        String::from("[Unit]\nDescription=Private epoch 266 predecessor diagnostic\n[Service]\n");
    for (key, value) in profile["properties"]
        .as_object()
        .context("missing profile properties")?
    {
        text.push_str(&format!(
            "{key}={}\n",
            value.as_str().context("non-text unit property")?
        ));
    }
    for (key, value) in profile["environment"]
        .as_object()
        .context("missing profile environment")?
    {
        text.push_str(&format!(
            "Environment={key}={}\n",
            value.as_str().context("non-text environment")?
        ));
    }
    text.push_str(&format!(
        "ExecStartPre=/usr/bin/bash {HOOK} 60 {V}/{TOKENS}\n"
    ));
    let argv: Vec<String> = serde_json::from_value(profile["argv"].clone())?;
    text.push_str(&format!("ExecStart={}\n", argv.join(" ")));
    write_file(&units.join(UNIT), text.as_bytes(), 0o400)
}

fn prepare(executable_sha: &str, stage: bool) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "static preparation requires root"
    );
    let current = fs::read_link("/proc/self/exe")?;
    let current_ref = reference(&current, executable_sha);
    read_bound(&current_ref, false)?;
    let prep_ref = reference(Path::new(PREPARATION), PREPARATION_SHA);
    let prep = read_json(&prep_ref, true)?;
    prep_facts(&prep)?;
    let overlap_ref = reference(Path::new(OVERLAP), OVERLAP_SHA);
    let overlap = read_json(&overlap_ref, true)?;
    ensure!(
        prep["node"] == overlap["node"] && prep["worker"] == overlap["worker"],
        "predecessor depends on a different node or worker"
    );
    for binding in [
        &prep["node"],
        &prep["worker"],
        &overlap["guard"],
        &reference(Path::new(HOOK), HOOK_SHA),
        &reference(Path::new(SEALER), SEALER_SHA),
    ] {
        read_bound(binding, true)?;
    }
    let checkpoint = read_bound(&prep["epoch_hashes"], true)?;
    let checkpoint_names = std::str::from_utf8(&checkpoint)?;
    let input = path(&prep["intake"], "destination")?;
    let boot_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .context("missing bootstrap name")?;
    let checkpoint_lines: Vec<_> = checkpoint_names.lines().collect();
    ensure!(
        checkpoint_lines
            == [
                boot_name,
                "snapshot-114923430-CerCifViM5MVzUYPWQm4jRk5zt1dHdFciiR7jrzSjyPj.tar.zst"
            ],
        "checkpoint filename pair changed"
    );
    let expected = read_json(&prep["expected_checkpoint"], true)?;
    ensure!(
        expected["slot"] == LAST
            && expected["slot_complete"] == true
            && expected["snapshot_generation"] == 1641767192954871u64
            && expected["accounts_hash"] == "CerCifViM5MVzUYPWQm4jRk5zt1dHdFciiR7jrzSjyPj"
            && expected["capitalization"] == 512823375441850375u64
            && expected["next_write_version"] == 187129398665u64,
        "terminal restore tuple changed"
    );
    read_json(&prep["metadata"], true)?;
    read_json(&prep["predecessor_reference"], true)?;

    let root = Path::new(ROOT);
    let work = root.join("work");
    let output = work.join("output");
    let scratch = work.join("scratch");
    let archive = output.join(format!("epoch-266-through-{LAST}.jet"));
    let manifest = archive.with_extension("jet.segment.json");
    let boot_target = root.join("input").join(boot_name);
    let root_state = Path::new(V).join(STATE);
    let package = Path::new(V).join(PACKAGE);
    let tokens = Path::new(V).join(TOKENS);
    let hashes = package.join("epoch-hashes.txt");
    let argv = vec![
        val_text(&prep["node"], "path")?.to_owned(),
        "266".to_owned(),
        output.display().to_string(),
        "--verify".to_owned(),
        format!("--snapshot-archive={}", boot_target.display()),
        format!("--epoch-hashes={}", hashes.display()),
        format!("--qualification-end-slot={LAST}"),
        format!("--horizon-output={}", archive.display()),
        format!("--replay-scratch={}", scratch.display()),
    ];
    fixture(&prep, checkpoint_names, &argv)?;
    let mut bindings = input_bindings(&prep, root)?;
    let sources = bindings.clone();
    bindings.push(json!({"path":input, "destination":boot_target,
        "sha256":prep["intake"]["expected_sha256"], "bytes":prep["intake"]["source_bytes"],
        "generation": 1641767242524970u64, "pending_custody":true
    }));
    let projected = bindings
        .iter()
        .map(|row| path(row, "destination"))
        .collect::<Result<Vec<_>>>()?;
    let projects = |fixture_bootstrap: bool| -> Result<String> {
        let mut rows = Vec::new();
        for (i, binding) in bindings.iter().enumerate() {
            let source = if fixture_bootstrap && i == bindings.len() - 1 {
                hashes.clone()
            } else {
                path(binding, "path")?
            };
            rows.push(format!("{}:{}", source.display(), projected[i].display()));
        }
        Ok(rows.join(" "))
    };

    let mut properties = runtime_properties(&overlap, root)?;
    properties["BindReadOnlyPaths"] = json!(projects(false)?);
    properties["ReadOnlyPaths"] = json!(tokens);
    let mut environment = overlap["environment"].clone();
    environment["TMPDIR"] = json!(scratch);
    environment["JETSTREAMER_PRIVATE_RUN_ROOT"] = json!(work.join("state"));
    environment["CLOUDSDK_CONFIG"] = json!(scratch.join("isolated-empty-gcloud"));
    let guard_path = root_state.join("static-guard-plan.json");
    let guard_unit_plan = json!({
        "schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,
        "invocation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","filesystem":"/",
        "minimum_free_bytes":FLOOR,"worker_root":root,"maximum_worker_vmas":3500000,
        "maximum_root_physical_bytes":HOME,"receipt_directory":root_state.join("guard-receipts")
    });
    let guard_ref = reference(&guard_path, &digest(&json_bytes(&guard_unit_plan)?));
    let guard_properties = json!({
        "Type":"oneshot","User":"root","UMask":"0077","Restart":"no",
        "AllowedCPUs":"30","MemoryMax":"1073741824","MemorySwapMax":"0","CPUQuota":"100%",
        "TasksMax":"256","TimeoutStartSec":"90","ProtectSystem":"strict","ProtectHome":"read-only",
        "PrivateNetwork":"yes","NoNewPrivileges":"yes",
        "CapabilityBoundingSet":"CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
        "AmbientCapabilities":"CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
        "ReadWritePaths":root_state.join("guard-receipts")
    });
    let mut profile = json!({
        "schema":"foundation-epoch266-original-predecessor-runtime-profile-v1",
        "epoch":266, "unit":UNIT, "guard_unit":GUARD_UNIT, "run_root":root,
        "bootstrap_slot":BOOT, "first_replay_slot":BOOT+1, "first_output_slot":FIRST_OUTPUT, "last_slot":LAST,
        "expected_executed_positions":EXECUTION_SLOTS, "expected_output_positions":OUTPUT_SLOTS,
        "persistent_archive":archive, "persistent_segment_manifest":manifest, "node":prep["node"],
        "worker":prep["worker"], "guard":overlap["guard"], "static_guard_plan":guard_ref,
        "prestart_hook":reference(Path::new(HOOK), HOOK_SHA),
        "producer_memory_bytes":MEMORY, "non_tmpfs_producer_memory_bytes":MEMORY-TMPFS,
        "scratch_tmpfs_bytes":TMPFS, "scratch_tmpfs_inodes":1048576, "guard_memory_bytes":1u64<<30,
        "control_memory_bytes":1u64<<30, "combined_memory_bytes":MEMORY+(2u64<<30),
        "protected_cpus":[30,32,33,34,35,36,37,38,39,94,96,97,98,99,100,101,102,103],
        "guard_cpu":30, "guarded_whole_tree_cap_bytes":HOME, "receipt_disk_bytes":RECEIPTS,
        "guard_properties":guard_properties,
        "guard_timer_properties":{"OnActiveSec":"1s","OnUnitInactiveSec":"60s",
            "AccuracySec":"1s","RandomizedDelaySec":"0"},
         "guard_floor_bytes":FLOOR, "bootstrap":bindings.last(), "intake":prep["intake"],
        "bootstrap_metadata":prep["metadata"],
        "terminal_reference":prep["expected_checkpoint"], "predecessor_reference":prep["predecessor_reference"],
        "epoch_hashes":reference(&hashes, &digest(&checkpoint)), "readonly_bindings":bindings,
        "argv":argv,"properties":properties,"environment":environment,
        "diagnostic_only":true,"publication_authorized":false,
    });
    profile["replay_launch_authorized"] = json!(false);

    // Static path initialization has no producer or guard side effects.
    for target in [
        root,
        root_state.as_path(),
        package.as_path(),
        tokens.as_path(),
        input.as_path(),
    ] {
        absent(target)?;
    }
    for target in [&root_state, &package, &tokens] {
        ensure!(
            target
                .parent()
                .context("missing package parent")?
                .canonicalize()?
                == Path::new(V),
            "indirect package parent"
        );
    }
    let scope = checked(Command::new("/usr/bin/systemctl").args([
        "--system",
        "show",
        "--no-pager",
        "-p",
        "LoadState",
        "-p",
        "ActiveState",
        "-p",
        "Job",
        UNIT,
        GUARD_UNIT,
        "horizon-266-original-predecessor-protective-v1.timer",
    ]))?;
    let scope = std::str::from_utf8(&scope)?;
    ensure!(
        scope.split("\n\n").count() == 3
            && scope.lines().filter(|line| !line.is_empty()).all(|line| [
                "LoadState=not-found",
                "ActiveState=inactive",
                "Job="
            ]
            .contains(&line)),
        "a producer or guard already exists at the proposed scope"
    );
    if !stage {
        return Ok(json!({
            "preparation":prep_ref,"profile_sha256":digest(&json_bytes(&profile)?),
            "static_guard_plan_sha256":guard_ref["sha256"],"sources":sources,
            "original_bootstrap_present":false,"replay_launch_authorized":false,
        }));
    }
    mkdir(root, 0o700, true)?;
    for item in [
        "input",
        "work",
        "work/scratch",
        "work/state",
        "work/output",
        "work/output/compact-indexes",
        "work/output/compact-indexes/265",
        "work/output/compact-indexes/266",
    ] {
        mkdir(&root.join(item), 0o700, true)?;
    }
    for target in &projected {
        write_file(target, b"", 0o444)?;
    }
    mkdir(&root_state, 0o700, false)?;
    mkdir(&root_state.join("guard-receipts"), 0o700, false)?;
    mkdir(&tokens, 0o755, false)?;
    mkdir(&tokens.join("qualification"), 0o755, false)?;
    write_json(
        &tokens.join("qualification/guard-admission.json"),
        &json!({"qualification_only":true}),
    )?;
    mkdir(&root_state.join("static-files"), 0o700, false)?;
    let staged = root_state.join("static-files");
    let epoch_hashes = write_file(&staged.join("epoch-hashes.txt"), &checkpoint, 0o400)?;
    let built_profile = write_json(&staged.join("profile.json"), &profile)?;
    let rendered = render_unit(&profile, &staged)?;
    ensure!(
        write_json(&guard_path, &guard_unit_plan)? == guard_ref,
        "guard plan bytes changed"
    );
    let members = [
        (&current_ref, "namespace-probe", 0o555u32),
        (&epoch_hashes, "epoch-hashes.txt", 0o444),
        (&built_profile, "profile.json", 0o444),
        (&rendered, UNIT, 0o444),
    ].into_iter().map(|(asset,name,mode)| json!({"source":asset["path"],"name":name,"mode":mode,"sha256":asset["sha256"]})).collect::<Vec<_>>();
    let seal_plan = write_json(
        &root_state.join("static-package-seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":package,"members":members}),
    )?;
    let sealed = checked(Command::new(SEALER).arg(path(&seal_plan, "path")?).args([
        "--plan-sha256",
        val_text(&seal_plan, "sha256")?,
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    let seal: Value = serde_json::from_slice(&sealed)?;
    let seal_path = package.join("deployment-seal-receipt.json");
    let seal_hash = digest(&fs::read(&seal_path)?);
    let seal_ref = reference(&seal_path, &seal_hash);
    let disk_seal = read_json(&seal_ref, true)?;
    ensure!(
        disk_seal["destination"] == json!(package)
            && disk_seal["plan_sha256"] == seal_plan["sha256"]
            && seal["plan_sha256"] == seal_plan["sha256"],
        "sealer returned foreign receipt"
    );
    let final_profile = reference(
        &package.join("profile.json"),
        val_text(&built_profile, "sha256")?,
    );
    read_bound(&final_profile, true)?;
    let final_unit = reference(&package.join(UNIT), val_text(&rendered, "sha256")?);
    read_bound(&final_unit, true)?;
    checked(
        Command::new("/usr/bin/systemd-analyze")
            .args(["verify", "--man=no", "--generators=no"])
            .arg(path(&final_unit, "path")?),
    )?;
    let guard: Value = serde_json::from_slice(&checked(
        Command::new(path(&overlap["guard"], "path")?)
            .arg(&guard_path)
            .args([
                "--plan-sha256",
                val_text(&guard_ref, "sha256")?,
                "--self-sha256",
                val_text(&overlap["guard"], "sha256")?,
                "--validate-plan-only",
            ]),
    )?)?;
    ensure!(
        guard["validated"] == true
            && guard["plan_sha256"] == guard_ref["sha256"]
            && guard["unit"] == UNIT
            && guard["resource_samples_taken"] == 0
            && guard["protective_guard_proven"] == false,
        "guard validation differs"
    );
    let guard_validation = write_json(&root_state.join("static-guard-validation.json"), &guard)?;

    let mut command = Command::new("/usr/bin/systemd-run");
    command.args([
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--unit=foundation-266-predecessor-namespace-probe-v1",
    ]);
    append_property(
        &mut command,
        &properties,
        &[
            "AllowedCPUs",
            "CPUAffinity",
            "CPUQuota",
            "MemoryMax",
            "RuntimeMaxSec",
            "BindReadOnlyPaths",
            "RestrictAddressFamilies",
            "TasksMax",
        ],
    )?;
    command.args([
        "--property=AllowedCPUs=28",
        "--property=CPUAffinity=28",
        "--property=CPUQuota=100%",
        "--property=MemoryMax=1G",
        "--property=RuntimeMaxSec=30",
        "--property=TasksMax=64",
        "--property=LimitFSIZE=2M",
        "--property=PrivateNetwork=yes",
        "--property=RestrictAddressFamilies=AF_UNIX",
    ]);
    command
        .arg(format!("--property=BindReadOnlyPaths={}", projects(true)?))
        .arg(package.join("namespace-probe"))
        .args(["--probe"])
        .arg(&tokens)
        .arg(boot_name)
        .args(projected.iter().take(sources.len()));
    let mut namespace: Value = serde_json::from_slice(&checked(&mut command)?)?;
    let mut observed = sources
        .iter()
        .map(|row| row["identity"].clone())
        .collect::<Vec<_>>();
    observed.push(open(&hashes, true)?.1);
    ensure!(
        namespace["source_identities"] == json!(observed),
        "projected source identity differs"
    );
    for (target, input) in projected.iter().zip(&bindings) {
        ensure!(
            fs::symlink_metadata(target)?.len() == 0,
            "host placeholder retained bytes"
        );
        if !input["pending_custody"].as_bool().unwrap_or(false) {
            ensure!(
                open(&path(input, "path")?, true)?.1 == input["identity"],
                "source changed during namespace probe"
            );
        }
    }
    absent(&input)?;
    ensure!(
        fs::read_dir(&scratch)?.next().is_none(),
        "host scratch changed"
    );
    namespace["profile"] = final_profile.clone();
    namespace["host_placeholders_empty"] = json!(true);
    namespace["original_bootstrap_present"] = json!(false);
    namespace["fixture_bootstrap_sha256"] = profile["epoch_hashes"]["sha256"].clone();
    namespace["fixture_cpu"] = json!(28);
    namespace["fixture_memory_max_bytes"] = json!(1u64 << 30);
    let namespace_ref = write_json(&root_state.join("namespace.json"), &namespace)?;
    let preflight = json!({
        "schema":"foundation-epoch266-original-predecessor-static-preflight-v1",
        "epoch":266,"replay_first_slot":BOOT+1,"output_first_slot":FIRST_OUTPUT,"last_slot":LAST,
        "preparation":prep_ref,"overlap_profile":overlap_ref,"profile":final_profile,"static_unit":final_unit,
        "package_seal":seal_ref,"namespace":namespace_ref,"static_guard_plan":guard_ref,"static_guard_validation":guard_validation,
        "cli_fixture":prep["qualification"],"original_bootstrap_present":false,"intake_authorized":false,
        "replay_admitted":false,"replay_launch_authorized":false,"publication_authorized":false,
        "remaining_gates":["epoch 230 turnover and drained resource evidence", "fresh complete roster admission for exact GCS intake",
            "generation/size/CRC32C/MD5/SHA-256 bootstrap custody and actual source projection",
            "fresh replay admission including exact CPU/sibling and HOME/guard-floor fit",
            "source containment and sealed provenance for the dispatcher and scope",
            "real invocation guard sample and prestart token before release"],
        "full_prefix_poh_comparison_still_required":true,
    });
    let receipt = write_json(&root_state.join("preflight.json"), &preflight)?;
    File::open(&root_state)?.sync_all()?;
    Ok(receipt)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let output = match args.as_slice() {
        [mode, sha] if mode == "--prepare" || mode == "--check" => {
            prepare(sha, mode == "--prepare")?
        }
        [mode, token, boot, targets @ ..] if mode == "--probe" => {
            probe(Path::new(token), boot, targets)?
        }
        _ => bail!("expected --check SELF_SHA256, --prepare SELF_SHA256 or internal --probe"),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_and_emitted_archive_scopes_are_distinct() {
        assert_eq!(EXECUTION_SLOTS, 12_662);
        assert_eq!(OUTPUT_SLOTS, 11_431);
        assert_eq!(FIRST_OUTPUT - BOOT - 1, 1_231);
    }

    #[test]
    fn mount_flags_require_exact_unique_projection() {
        let row = "150 23 0:92 / /some/path ro,nosuid - ext4 /dev/test rw,relatime";
        assert_eq!(
            mount_options(Path::new("/some/path"), row).unwrap().0,
            "ro,nosuid"
        );
        assert!(mount_options(Path::new("/some"), row).is_err());
        assert!(mount_options(Path::new("/some/path"), &format!("{row}\n{row}")).is_err());
    }
}
