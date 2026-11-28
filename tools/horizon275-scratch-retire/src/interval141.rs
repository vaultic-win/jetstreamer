//! Release a registered private epoch 141 tmpfs after segment custody.
use super::{
    appendvec288::lock_issuer, selective_accounts::record, snapshot288::lookup_receipt, *,
};
use std::ffi::CString;

struct Interval {
    fixed_mounts: Option<FixedMounts>,
    assignment: Option<Assignment>,
    terminal_accounts_hash: &'static str,
    ram: &'static str,
    alias: &'static str,
    first: u64,
    last: u64,
    targets: u64,
    output: &'static str,
}

struct Assignment {
    handoff_sha: &'static str,
    scope_sha: &'static str,
}

struct FixedMounts {
    invocation: &'static str,
    launch_sha: &'static str,
    device: u64,
    ram_id: &'static str,
    alias_id: &'static str,
}

struct Mounts<'a> {
    device: u64,
    major_minor: String,
    ram_id: &'a str,
    alias_id: &'a str,
}

const SECOND: Interval = Interval {
    assignment: None,
    terminal_accounts_hash: "7jmzVuomxUeE3WeR1XStbdiH1EDVR61Kz44km6J2jwv2",
    fixed_mounts: Some(FixedMounts {
        invocation: "94e2a4715b3a454eb3e7b0462863515e",
        launch_sha: "50d12a9f19b0532f2f5abc8c8381e6b52e8fcc4043e7c4d39cb0b850ca31d589",
        device: 177,
        ram_id: "447",
        alias_id: "652",
    }),
    ram: "/run/horizon141-foundation-interval2-ram-v4",
    alias: "/home/sol/.jetstreamer-private/epoch141-second-hourly",
    first: 60_921_283,
    last: 60_928_493,
    targets: 288,
    output: "epoch-141-second-hourly",
};

const FOURTH: Interval = Interval {
    assignment: None,
    terminal_accounts_hash: "EMsXJsestzPAfJtGfNdQdeji3JmuvaCKDAMPcD8hW3ZT",
    fixed_mounts: Some(FixedMounts {
        invocation: "e8ddd3cf18c64dba954e84604afc70b1",
        launch_sha: "0c45c79d402d137f058ba10486fecffa54dfd482f5413e935fa13c8da464579d",
        device: 164,
        ram_id: "117",
        alias_id: "441",
    }),
    ram: "/run/horizon141-foundation-interval4-ram-v1",
    alias: "/home/sol/.jetstreamer-private/epoch141-fourth-hourly-20261127-v1",
    first: 60_935_311,
    last: 60_942_184,
    targets: 340,
    output: "epoch-141-fourth-hourly",
};

const THIRD: Interval = Interval {
    assignment: Some(Assignment {
        handoff_sha: "dda2a0a0f919c7c277281f43d46d8ed2c2b6fab71ee4b08c466d1c6db4069e18",
        scope_sha: "d0007aef065d1bc9af56f14fc22c63edf1f87cdf9b35f3f9b702b44f969acbfa",
    }),
    terminal_accounts_hash: "FU1VdL2RPr4Ubn2SGE727jU8TQscWYn1gWbBE6peiC6r",
    fixed_mounts: None,
    ram: "/run/horizon141-foundation-interval3-ram-v1",
    alias: "/home/sol/.jetstreamer-private/epoch141-third-hourly-20261127-v1",
    first: 60_928_494,
    last: 60_935_310,
    targets: 330,
    output: "epoch-141-third-hourly",
};

const FIFTH: Interval = Interval {
    assignment: Some(Assignment {
        handoff_sha: "c024321f48da115b98ed2a25a91a81655aab4ca74728a4517aa4b8d4976a6455",
        scope_sha: "9188755bc441de30ed4e7c646c2c80889872b4d0cfb8a8f0c34c67847866337e",
    }),
    terminal_accounts_hash: "2EsJDSWGzZUaPKtjefUMfFnE2TWAn8ba5hAvDZbGaFfa",
    fixed_mounts: None,
    ram: "/run/horizon141-foundation-interval5-ram-v1",
    alias: "/home/sol/.jetstreamer-private/epoch141-fifth-hourly-20261127-v1",
    first: 60_942_185,
    last: 60_948_885,
    targets: 307,
    output: "epoch-141-fifth-hourly",
};

fn text_field<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row[key].as_str().with_context(|| format!("missing {key}"))
}

fn bind_recorded_mounts<'a>(
    held: &'a Value,
    interval: &Interval,
    ordinal: u8,
    state: &Path,
    unit: &str,
    invocation: &str,
) -> Result<Mounts<'a>> {
    let expected = interval
        .assignment
        .as_ref()
        .context("missing interval assignment")?;
    let scope: Binding = serde_json::from_value(held["runtime_scope"].clone())?;
    let mount = &held["host_mounts"];
    let ram = &mount["ram"];
    let alias = &mount["alias"];
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let device = ram["device"].as_u64().context("missing tmpfs device")?;
    let major_minor = text_field(ram, "major_minor")?;
    let ram_id = text_field(ram, "mount_id")?;
    let alias_id = text_field(alias, "mount_id")?;
    ensure!(
        held["schema"] == format!("foundation-epoch141-interval{ordinal}-held-namespace-v1")
            && held["unit"] == unit
            && held["producer"]["InvocationID"] == invocation
            && held["boot_id"] == boot.trim()
            && scope.path == state.join("runtime-scope.json")
            && scope.sha256 == expected.scope_sha
            && ram["path"] == interval.ram
            && alias["path"] == interval.alias
            && alias["device"] == device
            && alias["major_minor"] == major_minor
            && ram_id != alias_id,
        "foreign interval held mount evidence"
    );
    let _: Value = read_bound(&scope.path, &scope.sha256, JSON_LIMIT)?;
    Ok(Mounts {
        device,
        major_minor: major_minor.to_owned(),
        ram_id,
        alias_id,
    })
}

fn mounts(scope: &Interval, bound: &Mounts) -> Result<(bool, bool)> {
    let mut ram = false;
    let mut alias = false;
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let columns: Vec<_> = line.split_ascii_whitespace().collect();
        ensure!(columns.len() >= 10, "malformed mount identity");
        let target = Path::new(columns[4]);
        let is_ram = target == Path::new(scope.ram);
        let is_alias = target == Path::new(scope.alias);
        if columns[2] != bound.major_minor
            && !target.starts_with(scope.ram)
            && !target.starts_with(scope.alias)
        {
            continue;
        }
        ensure!(
            columns[2] == bound.major_minor
                && columns[3] == "/"
                && line.contains(" - tmpfs tmpfs ")
                && ((is_ram && columns[0] == bound.ram_id && !ram)
                    || (is_alias && columns[0] == bound.alias_id && !alias)),
            "foreign epoch 141 mount or alias"
        );
        let info = fs::metadata(target)?;
        ensure!(
            info.dev() == bound.device
                && info.ino() == 1
                && info.uid() == 1000
                && info.gid() == 1000
                && info.mode() & 0o7777 == 0o700,
            "epoch 141 tmpfs root identity changed"
        );
        ram |= is_ram;
        alias |= is_alias;
    }
    Ok((ram, alias))
}

fn unmount(path: &str) -> Result<()> {
    let path = CString::new(path)?;
    if unsafe { libc::umount2(path.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error()).context("unmount exact closed epoch 141 tmpfs");
    }
    Ok(())
}

pub(super) fn drain(ordinal: u8, terminal_sha: &str) -> Result<()> {
    let scope = match ordinal {
        2 => &SECOND,
        3 => &THIRD,
        4 => &FOURTH,
        5 => &FIFTH,
        _ => anyhow::bail!("unknown epoch 141 drain scope"),
    };
    let _issuer = lock_issuer()?;
    let _cycle = lock(CYCLE_LOCK)?;
    let unit = format!("horizon-qualify-141-foundation-interval{ordinal}-v1.service");
    let guard = format!("horizon-141-foundation-interval{ordinal}-guard-v1.service");
    let timer = format!("horizon-141-foundation-interval{ordinal}-guard-v1.timer");
    for actor in [&unit, &guard, &timer] {
        terminal_unit(actor)?;
        ensure!(
            !Path::new("/sys/fs/cgroup/system.slice")
                .join(actor)
                .exists(),
            "{actor} retains a cgroup"
        );
    }
    let state = PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon141-foundation-interval{ordinal}-runtime-v1"
    ));
    let terminal_path = state.join("replay-terminal.json");
    let terminal: Value = read_bound(&terminal_path, terminal_sha, JSON_LIMIT)?;
    let native = &terminal["native_terminal"];
    let private = &terminal["private_custody"];
    let container: Binding = serde_json::from_value(private["container"].clone())?;
    let launch_ref: Binding = serde_json::from_value(terminal["launch"].clone())?;
    ensure!(
        launch_ref.path == state.join("replay-launch.json"),
        "foreign epoch 141 launch path"
    );
    let launch: Value = read_bound(&launch_ref.path, &launch_ref.sha256, JSON_LIMIT)?;
    let invocation = text_field(&launch, "invocation_id")?;
    let held;
    let bound = if let Some(fixed) = &scope.fixed_mounts {
        ensure!(
            invocation == fixed.invocation && launch_ref.sha256 == fixed.launch_sha,
            "foreign epoch 141 launch identity"
        );
        Mounts {
            device: fixed.device,
            major_minor: format!("0:{}", fixed.device),
            ram_id: fixed.ram_id,
            alias_id: fixed.alias_id,
        }
    } else {
        let expected = scope
            .assignment
            .as_ref()
            .context("missing interval assignment")?;
        let admission: Binding = serde_json::from_value(launch["admission"].clone())?;
        let held_ref: Binding = serde_json::from_value(launch["held_namespace"].clone())?;
        ensure!(
            held_ref.path == state.join("held-namespace.json")
                && admission.path == state.join("replay-admission.json"),
            "foreign interval launch bindings"
        );
        let admission: Value = read_bound(&admission.path, &admission.sha256, JSON_LIMIT)?;
        ensure!(
            admission["handoff"]["sha256"] == expected.handoff_sha
                && admission["canonical_publication_authorized"] == false,
            "foreign interval assignment"
        );
        held = read_bound(&held_ref.path, &held_ref.sha256, JSON_LIMIT)?;
        bind_recorded_mounts(&held, scope, ordinal, &state, &unit, invocation)?
    };
    // Newer units capture the native exit before PID1 can unload the unit.
    let exit_ok = if ordinal >= 3 {
        let exit: Binding = serde_json::from_value(terminal["native_exit"].clone())?;
        ensure!(
            exit.path == state.join("terminal-evidence/native-exit.json"),
            "foreign epoch 141 native exit path"
        );
        let exit: Value = read_bound(&exit.path, &exit.sha256, JSON_LIMIT)?;
        exit["schema"] == format!("foundation-epoch141-interval{ordinal}-native-exit-v1")
            && exit["unit"] == unit
            && exit["invocation_id"] == invocation
            && exit["launch"] == terminal["launch"]
            && exit["native_properties"]["Id"] == unit
            && exit["native_properties"]["InvocationID"] == invocation
            && exit["native_properties"]["ExecMainCode"] == "1"
            && exit["native_properties"]["ExecMainStatus"] == "0"
            && exit["service_result"] == "success"
            && exit["exit_code"] == "exited"
            && exit["exit_status"] == "0"
            && terminal["terminal_checkpoint"]["slot_complete"] == true
            && terminal["terminal_checkpoint"]["accounts_hash"] == scope.terminal_accounts_hash
            && terminal["guard_drained"] == true
    } else {
        native["InvocationID"] == invocation
            && native["ExecMainCode"] == "1"
            && native["ExecMainStatus"] == "0"
            && native["Result"] == "success"
    };
    ensure!(
        exit_ok
            && terminal["schema"] == format!("foundation-epoch141-interval{ordinal}-terminal-v1")
            && terminal["invocation_id"] == invocation
            && launch["unit"] == unit
            && native["Id"] == unit
            && native["ActiveState"] == "inactive"
            && (native["InvocationID"] == "" || native["InvocationID"] == invocation)
            && terminal["terminal_checkpoint"]["slot"] == scope.last
            && terminal["output_slot_start"] == scope.first
            && terminal["output_slot_count"] == scope.last - scope.first + 1
            && terminal["original_entry_slots_verified"] == scope.targets
            && private["no_clobber"] == true
            && private["one_home_inode"] == true
            && private["tmpfs_source_preserved_through_readback"] == true
            && private["member_sha256"][format!("{}.jet", scope.output)]
                == terminal["archive_sha256"]
            && container.path == state.join(format!("post-exit-output/{}.tar", scope.output))
            && terminal["canonical_publication_authorized"] == false,
        "epoch 141 terminal and durable output custody do not match"
    );
    let mut file = open_regular(&container.path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == 0o400
            && metadata.dev() == fs::metadata(&state)?.dev()
            && metadata.len() > 0
            && metadata.len() <= 4 << 30
            && metadata.len() == private["bytes"]
            && digest(&mut file)? == container.sha256
            && identity(&file.metadata()?) == identity(&metadata)
            && identity(&container.path.symlink_metadata()?) == identity(&metadata),
        "epoch 141 durable output container changed"
    );
    let terminal_ref = Binding {
        path: terminal_path,
        sha256: terminal_sha.to_owned(),
    };
    let evidence =
        json!({"terminal":terminal_ref,"container":container,"invocation_id":invocation});
    let intent_path = state.join("post-custody-drain-intent.json");
    let done_path = state.join("post-custody-drain.json");
    let prior = lookup_receipt(&intent_path)?;
    if let Some((_, document)) = &prior {
        ensure!(
            document["evidence"] == evidence,
            "epoch 141 drain intent differs"
        );
    }
    let initial = mounts(scope, &bound)?;
    if let Some((binding, document)) = lookup_receipt(&done_path)? {
        ensure!(
            prior.is_some()
                && initial == (false, false)
                && document["terminal"] == evidence["terminal"],
            "epoch 141 drain completion conflicts with mount state"
        );
        println!("{}", serde_json::to_string(&binding)?);
        return Ok(());
    }
    let intent = match prior {
        Some((binding, _)) => {
            ensure!(
                !initial.1 || initial.0,
                "epoch 141 alias unexpectedly outlived the root"
            );
            binding
        }
        None => {
            ensure!(
                initial == (true, true),
                "expected both original epoch 141 mounts"
            );
            record(
                &intent_path,
                &json!({"evidence":evidence,"ram_mount_id":bound.ram_id,"alias_mount_id":bound.alias_id}),
            )?
        }
    };
    if initial.1 {
        unmount(scope.alias)?;
    }
    if initial.0 {
        ensure!(
            mounts(scope, &bound)? == (true, false),
            "epoch 141 aliases changed before drain"
        );
        unmount(scope.ram)?;
    }
    ensure!(
        mounts(scope, &bound)? == (false, false),
        "epoch 141 tmpfs remains mounted"
    );
    let done = record(
        &done_path,
        &json!({
            "schema":format!("foundation-epoch141-interval{ordinal}-post-custody-drain-v1"),
            "invocation_id":invocation,"terminal":terminal_ref,"intent":intent,"container":container,
            "guard_drained":true,"tmpfs_drained":true,"canonical_publication_authorized":false
        }),
    )?;
    println!("{}", serde_json::to_string(&done)?);
    Ok(())
}
