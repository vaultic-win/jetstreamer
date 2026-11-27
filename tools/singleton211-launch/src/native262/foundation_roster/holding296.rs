//! Enroll encrypted epoch 296 custody in the protected Foundation capacity.
use super::*;

pub(super) const UNIT: &str = "foundation-296-closed-retry-custody-v1.service";
pub(super) const RECEIPT_DISK: u64 = 64 << 20;
const MEMORY: u64 = 80 << 30;
const CPUS: &str = "34-35";
const ROOT: &str = "/var/lib/jetstreamer/horizon296-closed-first-retry-custody-v1";
const BINARY: &str = "/var/lib/jetstreamer/horizon296-closed-retry-custody-tools-v1/jetstreamer-r2";
const BINARY_SHA: &str = "4eed9a5d5707136eb082e54ce7c7531050ecdc39b13ae9c8c696c14776ef0de9";
const SPEC_SHA: &str = "8be4b0651537f67c86af335852972c03150535b88164b5fb9855cdcd8e3212c4";

fn match_launch(launch: &Value, owner: &Value) -> Result<()> {
    ensure!(
        launch["schema"] == "foundation-epoch296-encrypted-custody-launch-v1"
            && launch["credentials_loaded_by_manager"] == true
            && launch["canonical_publication_authorized"] == false
            && launch["retirement_authorized"] == false,
        "foreign epoch 296 custody launch"
    );
    let recorded = &launch["actual"];
    for key in [
        "Id",
        "InvocationID",
        "MainPID",
        "AllowedCPUs",
        "MemoryMax",
        "MemorySwapMax",
    ] {
        ensure!(
            recorded[key] == owner[key] && !owner[key].is_null(),
            "epoch 296 custody launch changed {key}"
        );
    }
    Ok(())
}

fn match_admission(admission: &Value) -> Result<()> {
    let properties = &admission["properties"];
    ensure!(
        admission["schema"] == "foundation-epoch296-encrypted-custody-admission-v1"
            && admission["unit"] == UNIT
            && admission["binary"] == json!(Bound::new(BINARY, BINARY_SHA))
            && admission["spec"] == json!(Bound::new(Path::new(ROOT).join("park.json"), SPEC_SHA))
            && admission["native_offline_check"]["identity_matches"] == true
            && admission["native_offline_check"]["remote_mutations"] == false
            && admission["disk_booking_bytes"] == RECEIPT_DISK
            && admission["canonical_publication_authorized"] == false
            && admission["retirement_authorized"] == false
            && properties["AllowedCPUs"] == CPUS
            && properties["MemoryMax"] == MEMORY.to_string()
            && properties["MemorySwapMax"] == "0"
            && properties["TemporaryFileSystem"]
                == "/tmp/foundation-296-closed-custody:rw,size=45097156608,mode=0700,uid=0,gid=0,nosuid,nodev,noexec,noswap",
        "epoch 296 custody admission differs from its qualified envelope"
    );
    Ok(())
}

pub(super) struct Active {
    pub(super) launch: Bound,
    pub(super) owner: Value,
    pub(super) memory: u64,
    pub(super) ticks: u64,
}

pub(super) fn active(n: &mut Native) -> Result<Active> {
    let owner = n.show_fields(UNIT, OWNER_FIELDS)?;
    let invocation = text(&owner, "InvocationID")?;
    let memory = live::finite_owner(&owner, UNIT, invocation, MEMORY)?;
    ensure!(
        owner["AllowedCPUs"] == CPUS,
        "epoch 296 custody CPU set changed"
    );
    let mut matched = None;
    for attempt in [1, 2] {
        let path = Path::new(ROOT).join(format!("park-launch-v{attempt}.json"));
        if !path.try_exists()? {
            continue;
        }
        let launch = Bound::new(&path, hash(&path)?);
        let body = launch.sealed()?;
        if body["actual"]["InvocationID"] != invocation {
            continue;
        }
        ensure!(
            matched.is_none(),
            "duplicate launch for epoch 296 custody invocation"
        );
        match_launch(&body, &owner)?;
        let admission = binding(&body["admission"])?;
        ensure!(
            admission.path == Path::new(ROOT).join(format!("park-admission-v{attempt}.json")),
            "foreign epoch 296 custody admission path"
        );
        match_admission(&admission.sealed()?)?;
        matched = Some(launch);
    }
    let launch = matched.context("no sealed launch for live epoch 296 custody invocation")?;
    Bound::new(BINARY, BINARY_SHA).artifact()?;
    let pid = text(&owner, "MainPID")?.parse()?;
    let ticks = process_ticks(pid)?;
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let exe = proc.join("exe");
    let spec = Path::new(ROOT).join("park.json");
    let expected = [
        BINARY,
        "holding-foundation-296-failed-retry-park",
        spec.to_str().context("non-UTF-8 park specification")?,
        "--spec-sha256",
        SPEC_SHA,
        "--self-sha256",
        BINARY_SHA,
    ]
    .join("\0")
        + "\0";
    ensure!(
        fs::read_link(&exe)? == Path::new(BINARY)
            && metadata_identity(&fs::metadata(&exe)?) == identity(Path::new(BINARY))?
            && fs::read(proc.join("cmdline"))? == expected.as_bytes()
            && process_ticks(pid)? == ticks,
        "live epoch 296 custody image or command differs"
    );
    Ok(Active {
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
    fn live_admission_requires_the_exact_encryption_resource_envelope() -> Result<()> {
        let mut admission = json!({
            "schema":"foundation-epoch296-encrypted-custody-admission-v1",
            "unit":UNIT,"binary":Bound::new(BINARY,BINARY_SHA),
            "spec":Bound::new(Path::new(ROOT).join("park.json"), SPEC_SHA),
            "native_offline_check":{"identity_matches":true,"remote_mutations":false},
            "disk_booking_bytes":RECEIPT_DISK,
            "canonical_publication_authorized":false,"retirement_authorized":false,
            "properties":{"AllowedCPUs":CPUS,"MemoryMax":MEMORY.to_string(),"MemorySwapMax":"0",
                "TemporaryFileSystem":"/tmp/foundation-296-closed-custody:rw,size=45097156608,mode=0700,uid=0,gid=0,nosuid,nodev,noexec,noswap"}
        });
        match_admission(&admission)?;
        admission["disk_booking_bytes"] = json!(0);
        assert!(match_admission(&admission).is_err());
        admission["disk_booking_bytes"] = json!(RECEIPT_DISK);
        admission["properties"]["MemorySwapMax"] = json!("1");
        assert!(match_admission(&admission).is_err());
        Ok(())
    }
}
