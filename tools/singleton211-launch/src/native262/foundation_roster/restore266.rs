//! Bind the Foundation checkpoint-only restore while admitting disjoint work.
use super::*;

pub(super) const UNIT: &str = "horizon-qualify-266-hourly-checkpoint-restore-v1.service";
pub(super) const RECEIPT_DISK: u64 = 64 << 20;
pub(super) const ADDITIONAL_MEMORY: u64 = 2 << 30;
const MEMORY: u64 = 192_000_000_000;
const BINARY: &str = "/var/lib/jetstreamer/horizon266-hourly-restore-probe-v1/probe";
const BINARY_SHA: &str = "4d14c33f1a5e9ba373a2e474bbe1926812140f7ec8586da68a67ad3cf7c7740a";
const STATE: &str = "/var/lib/jetstreamer/horizon266-hourly-checkpoint-runtime-v1";

fn match_owner(launch: &Value, owner: &Value) -> Result<()> {
    ensure!(
        launch["unit"] == UNIT
            && launch["checkpoint_slot"] == 114_923_430
            && launch["probe_sha256"] == BINARY_SHA
            && launch["entry_replay"] == false
            && launch["publication_authorized"] == false
            && launch["invocation_id"] == owner["InvocationID"]
            && num(launch, "main_pid")? == text(owner, "MainPID")?.parse::<u64>()?
            && launch["exec_start"] == owner["ExecStart"]
            && owner["AllowedCPUs"] == "32-39",
        "epoch 266 hourly restore ownership changed"
    );
    Ok(())
}

pub(super) fn active(n: &mut Native) -> Result<AuxiliaryOwner> {
    let root = Path::new(STATE);
    let launch = Bound::new(
        root.join("launch.json"),
        "043d95bac6243a26eb4d9156fe90e8967b516ef16c76a0d662b9bc246c18f36c",
    );
    let body = launch.sealed()?;
    let owner = n.show_fields(UNIT, OWNER_FIELDS)?;
    match_owner(&body, &owner)?;
    let admission = binding(&body["admission"])?;
    ensure!(
        admission.path == root.join("admission.json")
            && admission.sha256
                == "02ffc95da54757c1e5827a1e267a2901219ec2157c0377e80e9af784b9718e1e",
        "foreign checkpoint admission"
    );
    let fit = admission.sealed()?;
    ensure!(
        fit["unit"] == UNIT
            && fit["maximum_memory_bytes"] == MEMORY
            && fit["combined_charge_bytes"] == MEMORY + ADDITIONAL_MEMORY
            && fit["additional_home_allowance_bytes"] == RECEIPT_DISK
            && fit["noswap_tmpfs_bytes"] == 128u64 << 30
            && fit["temporary_compressed_snapshot_copy_bytes"] == 15_477_812_146u64,
        "checkpoint reservations differ"
    );
    let memory = live::finite_owner(&owner, UNIT, text(&body, "invocation_id")?, MEMORY)?;
    Bound::new(BINARY, BINARY_SHA).artifact()?;
    let pid = num(&body, "main_pid")?.try_into()?;
    let ticks = process_ticks(pid)?;
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let exe = proc.join("exe");
    ensure!(
        fs::read_link(&exe)? == Path::new(BINARY)
            && metadata_identity(&fs::metadata(exe)?) == identity(Path::new(BINARY))?
            && fs::read(proc.join("cmdline"))? == format!("{BINARY}\0--epoch266\0").as_bytes()
            && process_ticks(pid)? == ticks,
        "epoch 266 restore executable changed"
    );
    Ok(AuxiliaryOwner {
        launch,
        owner,
        memory,
        ticks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fails_on_new_pid_cpu_or_invocation_even_with_the_same_image() -> Result<()> {
        let launch = json!({"unit":UNIT, "probe_sha256":BINARY_SHA, "checkpoint_slot":114923430,
            "main_pid":123, "exec_start":"restore", "invocation_id":"original",
            "entry_replay":false, "publication_authorized":false});
        let owner = json!({"MainPID":"123", "ExecStart":"restore", "InvocationID":"original", "AllowedCPUs":"32-39"});
        match_owner(&launch, &owner)?;
        for field in ["MainPID", "ExecStart", "InvocationID", "AllowedCPUs"] {
            let mut changed = owner.clone();
            changed[field] = json!("other");
            assert!(match_owner(&launch, &changed).is_err());
        }
        Ok(())
    }
}
