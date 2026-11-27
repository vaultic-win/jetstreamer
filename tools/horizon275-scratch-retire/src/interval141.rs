//! Release interval two's dedicated tmpfs after private segment custody.
use super::{
    appendvec288::lock_issuer, selective_accounts::record, snapshot288::lookup_receipt, *,
};
use std::ffi::CString;

const STATE: &str = "/var/lib/jetstreamer/horizon141-foundation-interval2-runtime-v1";
const UNIT: &str = "horizon-qualify-141-foundation-interval2-v1.service";
const GUARD: &str = "horizon-141-foundation-interval2-guard-v1.service";
const TIMER: &str = "horizon-141-foundation-interval2-guard-v1.timer";
const INVOCATION: &str = "94e2a4715b3a454eb3e7b0462863515e";
const LAUNCH_SHA: &str = "50d12a9f19b0532f2f5abc8c8381e6b52e8fcc4043e7c4d39cb0b850ca31d589";
const RAM: &str = "/run/horizon141-foundation-interval2-ram-v4";
const ALIAS: &str = "/home/sol/.jetstreamer-private/epoch141-second-hourly";
const DEVICE: &str = "0:177";
const RAM_MOUNT: &str = "447";
const ALIAS_MOUNT: &str = "652";

fn mounts() -> Result<(bool, bool)> {
    let mut ram = false;
    let mut alias = false;
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let columns: Vec<_> = line.split_ascii_whitespace().collect();
        ensure!(columns.len() >= 10, "malformed mount identity");
        let target = Path::new(columns[4]);
        let is_ram = target == Path::new(RAM);
        let is_alias = target == Path::new(ALIAS);
        if columns[2] != DEVICE && !target.starts_with(RAM) && !target.starts_with(ALIAS) {
            continue;
        }
        ensure!(
            columns[2] == DEVICE
                && columns[3] == "/"
                && line.contains(" - tmpfs tmpfs ")
                && ((is_ram && columns[0] == RAM_MOUNT && !ram)
                    || (is_alias && columns[0] == ALIAS_MOUNT && !alias)),
            "foreign epoch 141 mount or alias"
        );
        let info = fs::metadata(target)?;
        ensure!(
            info.dev() == 177
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

pub(super) fn drain(terminal_sha: &str) -> Result<()> {
    let _issuer = lock_issuer()?;
    let _cycle = lock(CYCLE_LOCK)?;
    for actor in [UNIT, GUARD, TIMER] {
        terminal_unit(actor)?;
        ensure!(
            !Path::new("/sys/fs/cgroup/system.slice")
                .join(actor)
                .exists(),
            "{actor} retains a cgroup"
        );
    }
    let state = Path::new(STATE);
    let terminal_path = state.join("replay-terminal.json");
    let terminal: Value = read_bound(&terminal_path, terminal_sha, JSON_LIMIT)?;
    let native = &terminal["native_terminal"];
    let private = &terminal["private_custody"];
    let container: Binding = serde_json::from_value(private["container"].clone())?;
    ensure!(
        terminal["schema"] == "foundation-epoch141-interval2-terminal-v1"
            && terminal["invocation_id"] == INVOCATION
            && terminal["launch"]["sha256"] == LAUNCH_SHA
            && native["Id"] == UNIT
            && native["InvocationID"] == INVOCATION
            && native["ActiveState"] == "inactive"
            && native["ExecMainCode"] == "1"
            && native["ExecMainStatus"] == "0"
            && native["Result"] == "success"
            && terminal["terminal_checkpoint"]["slot"] == 60_928_493
            && terminal["output_slot_start"] == 60_921_283
            && terminal["output_slot_count"] == 7211
            && terminal["original_entry_slots_verified"] == 288
            && private["no_clobber"] == true
            && private["one_home_inode"] == true
            && private["tmpfs_source_preserved_through_readback"] == true
            && private["member_sha256"]["epoch-141-second-hourly.jet"]
                == terminal["archive_sha256"]
            && container.path == state.join("post-exit-output/epoch-141-second-hourly.tar")
            && terminal["canonical_publication_authorized"] == false,
        "epoch 141 terminal and durable output custody do not match"
    );
    let mut file = open_regular(&container.path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == 0o400
            && metadata.dev() == fs::metadata(state)?.dev()
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
        json!({"terminal":terminal_ref,"container":container,"invocation_id":INVOCATION});
    let intent_path = state.join("post-custody-drain-intent.json");
    let done_path = state.join("post-custody-drain.json");
    let prior = lookup_receipt(&intent_path)?;
    if let Some((_, document)) = &prior {
        ensure!(
            document["evidence"] == evidence,
            "epoch 141 drain intent differs"
        );
    }
    let initial = mounts()?;
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
                &json!({"evidence":evidence,"ram_mount_id":RAM_MOUNT,"alias_mount_id":ALIAS_MOUNT}),
            )?
        }
    };
    if initial.1 {
        unmount(ALIAS)?;
    }
    if initial.0 {
        ensure!(
            mounts()? == (true, false),
            "epoch 141 aliases changed before drain"
        );
        unmount(RAM)?;
    }
    ensure!(
        mounts()? == (false, false),
        "epoch 141 tmpfs remains mounted"
    );
    let done = record(
        &done_path,
        &json!({
            "schema":"foundation-epoch141-interval2-post-custody-drain-v1",
            "invocation_id":INVOCATION,"terminal":terminal_ref,"intent":intent,"container":container,
            "guard_drained":true,"tmpfs_drained":true,"canonical_publication_authorized":false
        }),
    )?;
    println!("{}", serde_json::to_string(&done)?);
    Ok(())
}
