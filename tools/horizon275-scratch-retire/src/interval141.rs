//! Release a registered private epoch 141 tmpfs after segment custody.
use super::{
    appendvec288::lock_issuer, selective_accounts::record, snapshot288::lookup_receipt, *,
};
use std::ffi::CString;

struct Interval {
    invocation: &'static str,
    launch_sha: &'static str,
    ram: &'static str,
    alias: &'static str,
    device: u64,
    ram_mount: &'static str,
    alias_mount: &'static str,
    first: u64,
    last: u64,
    targets: u64,
    output: &'static str,
}

const SECOND: Interval = Interval {
    invocation: "94e2a4715b3a454eb3e7b0462863515e",
    launch_sha: "50d12a9f19b0532f2f5abc8c8381e6b52e8fcc4043e7c4d39cb0b850ca31d589",
    ram: "/run/horizon141-foundation-interval2-ram-v4",
    alias: "/home/sol/.jetstreamer-private/epoch141-second-hourly",
    device: 177,
    ram_mount: "447",
    alias_mount: "652",
    first: 60_921_283,
    last: 60_928_493,
    targets: 288,
    output: "epoch-141-second-hourly",
};

const FOURTH: Interval = Interval {
    invocation: "e8ddd3cf18c64dba954e84604afc70b1",
    launch_sha: "0c45c79d402d137f058ba10486fecffa54dfd482f5413e935fa13c8da464579d",
    ram: "/run/horizon141-foundation-interval4-ram-v1",
    alias: "/home/sol/.jetstreamer-private/epoch141-fourth-hourly-20261127-v1",
    device: 164,
    ram_mount: "117",
    alias_mount: "441",
    first: 60_935_311,
    last: 60_942_184,
    targets: 340,
    output: "epoch-141-fourth-hourly",
};

fn mounts(scope: &Interval) -> Result<(bool, bool)> {
    let device = format!("0:{}", scope.device);
    let mut ram = false;
    let mut alias = false;
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let columns: Vec<_> = line.split_ascii_whitespace().collect();
        ensure!(columns.len() >= 10, "malformed mount identity");
        let target = Path::new(columns[4]);
        let is_ram = target == Path::new(scope.ram);
        let is_alias = target == Path::new(scope.alias);
        if columns[2] != device
            && !target.starts_with(scope.ram)
            && !target.starts_with(scope.alias)
        {
            continue;
        }
        ensure!(
            columns[2] == device
                && columns[3] == "/"
                && line.contains(" - tmpfs tmpfs ")
                && ((is_ram && columns[0] == scope.ram_mount && !ram)
                    || (is_alias && columns[0] == scope.alias_mount && !alias)),
            "foreign epoch 141 mount or alias"
        );
        let info = fs::metadata(target)?;
        ensure!(
            info.dev() == scope.device
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
        4 => &FOURTH,
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
    let launch_path = state.join("replay-launch.json");
    let launch: Value = read_bound(&launch_path, scope.launch_sha, JSON_LIMIT)?;
    // The fourth unit captures the native exit before PID1 can unload the unit.
    // Interval two instead retains its full terminal properties in PID1.
    let exit_ok = if ordinal == 4 {
        let exit: Binding = serde_json::from_value(terminal["native_exit"].clone())?;
        ensure!(
            exit.path == state.join("terminal-evidence/native-exit.json"),
            "foreign epoch 141 native exit path"
        );
        let exit: Value = read_bound(&exit.path, &exit.sha256, JSON_LIMIT)?;
        exit["schema"] == "foundation-epoch141-interval4-native-exit-v1"
            && exit["unit"] == unit
            && exit["invocation_id"] == scope.invocation
            && exit["launch"] == terminal["launch"]
            && exit["native_properties"]["Id"] == unit
            && exit["native_properties"]["InvocationID"] == scope.invocation
            && exit["native_properties"]["ExecMainCode"] == "1"
            && exit["native_properties"]["ExecMainStatus"] == "0"
            && exit["service_result"] == "success"
            && exit["exit_code"] == "exited"
            && exit["exit_status"] == "0"
            && terminal["terminal_checkpoint"]["slot_complete"] == true
            && terminal["terminal_checkpoint"]["accounts_hash"]
                == "EMsXJsestzPAfJtGfNdQdeji3JmuvaCKDAMPcD8hW3ZT"
            && terminal["guard_drained"] == true
    } else {
        native["InvocationID"] == scope.invocation
            && native["ExecMainCode"] == "1"
            && native["ExecMainStatus"] == "0"
            && native["Result"] == "success"
    };
    ensure!(
        exit_ok
            && terminal["schema"] == format!("foundation-epoch141-interval{ordinal}-terminal-v1")
            && terminal["invocation_id"] == scope.invocation
            && terminal["launch"]["path"] == json!(launch_path)
            && terminal["launch"]["sha256"] == scope.launch_sha
            && launch["unit"] == unit
            && launch["invocation_id"] == scope.invocation
            && native["Id"] == unit
            && native["ActiveState"] == "inactive"
            && (native["InvocationID"] == "" || native["InvocationID"] == scope.invocation)
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
        json!({"terminal":terminal_ref,"container":container,"invocation_id":scope.invocation});
    let intent_path = state.join("post-custody-drain-intent.json");
    let done_path = state.join("post-custody-drain.json");
    let prior = lookup_receipt(&intent_path)?;
    if let Some((_, document)) = &prior {
        ensure!(
            document["evidence"] == evidence,
            "epoch 141 drain intent differs"
        );
    }
    let initial = mounts(scope)?;
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
                &json!({"evidence":evidence,"ram_mount_id":scope.ram_mount,"alias_mount_id":scope.alias_mount}),
            )?
        }
    };
    if initial.1 {
        unmount(scope.alias)?;
    }
    if initial.0 {
        ensure!(
            mounts(scope)? == (true, false),
            "epoch 141 aliases changed before drain"
        );
        unmount(scope.ram)?;
    }
    ensure!(
        mounts(scope)? == (false, false),
        "epoch 141 tmpfs remains mounted"
    );
    let done = record(
        &done_path,
        &json!({
            "schema":format!("foundation-epoch141-interval{ordinal}-post-custody-drain-v1"),
            "invocation_id":scope.invocation,"terminal":terminal_ref,"intent":intent,"container":container,
            "guard_drained":true,"tmpfs_drained":true,"canonical_publication_authorized":false
        }),
    )?;
    println!("{}", serde_json::to_string(&done)?);
    Ok(())
}
