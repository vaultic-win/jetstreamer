//! Transfer the old 228 worker's scratch allowance only to its bounded 228 successor.
use super::*;
use std::os::fd::AsRawFd;

const ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input228-v1620-demotion-v1";
const SOURCE_BYTES: u64 = 300_000_000_000;
const CONTROL_BYTES: u64 = 256 << 20;
const OLD_WORKER: &str = "horizon-native-input-228-demotion-16d4b158-v1.service";
const OLD_CONTROLLER: &str = "horizon228-demotion-cold-control-v164-a1.service";
const IMMUTABLE: libc::c_long = 0x10;

fn custody() -> Bound {
    Bound::new(
        "/home/ubuntu/.codex/diagnostics/horizon228-original-cold-custody-v168-a1/completion.json",
        "36b0b86da1a0683b212abd07c7b56d4f810230de3eba2dc2edd8ad505f8467ab",
    )
}

fn immutable_tree(base: &Path, manifest: &Value) -> Result<()> {
    let members = manifest.as_object().context("file custody entries")?;
    ensure!(members.len() == 9191, "original 228 custody count");
    let mut pending = vec![base.to_owned()];
    let mut seen = BTreeSet::new();
    let mut files = 0;
    while let Some(path) = pending.pop() {
        let relative = path.strip_prefix(base)?.to_str().context("228 path")?;
        let key = if relative.is_empty() { "." } else { relative };
        let row = members.get(key).context("unrecorded 228 inode")?;
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let m = f.metadata()?;
        let mut flags: libc::c_long = 0;
        // FS_IOC_GETFLAGS writes one filesystem flag word on this x86_64 host.
        ensure!(
            unsafe { libc::ioctl(f.as_raw_fd(), 0x80086601, &mut flags) } == 0
                && flags & IMMUTABLE != 0
                && row[8] == flags
                && m.dev() == 66305
                && row[0] == m.dev()
                && row[1] == m.ino()
                && row[2] == m.mode()
                && row[3] == m.uid()
                && row[4] == m.gid()
                && row[5] == m.nlink()
                && row[6] == m.size()
                && seen.insert(m.ino()),
            "changed or writable 228 custody member {key}"
        );
        if m.is_dir() {
            for e in fs::read_dir(&path)? {
                pending.push(e?.path());
            }
        } else {
            ensure!(
                m.is_file() && m.nlink() == 1,
                "shared or special 228 member"
            );
            files += 1;
        }
    }
    ensure!(
        seen.len() == members.len() && files == 9179,
        "incomplete original 228 tree"
    );
    Ok(())
}

pub(super) fn assignment(n: &mut Native, book: &Value, peer: &Value) -> Result<Value> {
    let receipt = custody();
    let c = receipt.json()?;
    let witness = binding(&c["terminal"])?.json()?;
    let candidate = binding(&c["source"])?.json()?;
    let original = binding(&candidate["original_capacity"])?.sealed()?;
    let upload = binding(&candidate["unadjusted_uploader"])?.json()?;
    let pilot = binding(&peer["held_fit"])?.sealed()?;
    ensure!(
        c["root"] == ROOT
            && c["immutable_all"] == true
            && c["root_inode"] == 98097657
            && c["byte_identical"] == true
            && witness["worker_drained"] == true
            && witness["controller_exit_code"] == 1
            && original["source_fit"] == book["epoch228_held_fit"]
            && pilot["epoch228_held_fit"] == original["source_fit"]
            && book["epoch228_full_nominal_disk"] == SOURCE_BYTES + CONTROL_BYTES
            && upload["complete_capacity"]["required_free"] == book["required_free"]
            && upload["protected_existing_floor_bytes"] == original["required_free_bytes"]
            && upload["booked_disk_growth_bytes"] == 1u64 << 30
            && num(&original, "protected_floor_bytes")?.checked_add(SOURCE_BYTES + CONTROL_BYTES)
                == original["required_free_bytes"].as_u64()
            && num(&original, "required_free_bytes")?.checked_add(1 << 30)
                == book["required_free"].as_u64()
            && peer["original_floor"] == book["required_free"]
            && peer["readonly_loop"].is_object(),
        "different original 228 reservation or aggregate floor"
    );
    for name in [OLD_WORKER, OLD_CONTROLLER] {
        let m = n.show(name)?;
        let old = &witness["original_terminal_units"][name]["manager"];
        for key in [
            "Id",
            "Job",
            "ActiveState",
            "SubState",
            "MainPID",
            "ControlPID",
            "InvocationID",
            "ControlGroup",
            "NRestarts",
            "Result",
        ] {
            ensure!(
                old[key].is_string() && m[key] == old[key],
                "old 228 owner changed: {name} {key}"
            );
        }
        live::verify_drained_group(name)?;
    }
    immutable_tree(Path::new(ROOT), &binding(&c["after"])?.json()?)?;
    Ok(
        json!({"custody":receipt,"epoch":228,"source_worker":OLD_WORKER,"assigned_to":Profile::new(Lane::Epoch228,"pilot")?.unit,
        "assigned_scratch_bytes":epoch228::ROOT_BYTES,"retained_scratch_bytes":SOURCE_BYTES-epoch228::ROOT_BYTES,
        "retained_control_bytes":CONTROL_BYTES,"source_floor":original["protected_floor_bytes"],"memory_credit_bytes":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the closed 228 tree from the original failed controller"]
    fn closed_scratch_requires_original_immutable_members() {
        let c = custody().json().unwrap();
        let mut m = binding(&c["after"]).unwrap().json().unwrap();
        immutable_tree(Path::new(ROOT), &m).unwrap();
        m["."][8] = json!(0);
        assert!(immutable_tree(Path::new(ROOT), &m).is_err());
        m.as_object_mut().unwrap().remove(".");
        assert!(immutable_tree(Path::new(ROOT), &m).is_err());
    }
}
