//! Price the prepared 257 restore inside the drained 266 allocation.
use super::*;

const ACCOUNTING: &str = "/home/ubuntu/.codex/diagnostics/horizon-bounded265-residual-horizon257-delivery-rss-fleet-selection-v217/assignment.json";
const ACCOUNTING_SHA: &str = "761fa3765f0c4da775b8b531ea55061ae616e3c8fc68e60096e6d0544e828bc9";
const PREPARATION: &str =
    "/home/ubuntu/.codex/diagnostics/horizon257-closed266-native-prepare-a1/intent.json";
const RETRY_LAUNCH: &str =
    "/home/ubuntu/.codex/diagnostics/horizon-upload-265-ordinary-retry-v216/launch.json";
const RELEASE: &str = "/var/lib/jetstreamer/horizon266-v210-closed-growth-v215/release.json";
const SCRATCH257: &str = "/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1";
const CONTROL: u64 = 256 << 20;
const GUARD: u64 = 1 << 30;

// Restore all past resident credits before comparing with live MemAvailable.
// Book the entire remaining finite-work pool plus the largest serialized build.
// Other claims already included in the frozen ledger retain their full amounts.
fn budget(a: &Value, release: &Value, delivery: &Value) -> Result<(u64, u64)> {
    let donor = num(release, "producer")?;
    let candidate = capacity::add(native257_fit::NATIVE257_MEMORY, CONTROL + GUARD)?;
    ensure!(
        candidate <= num(delivery, "reserve_after")?
            && capacity::add(num(delivery, "reserve_after")?, num(delivery, "gross")?)? == donor,
        "257 and 265 exceed their donor"
    );
    let uploader = delivery247::SUCCESSOR_UNIT;
    let resident = ["before", "middle", "after"]
        .into_iter()
        .map(|k| num(&a[k], uploader))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .min()
        .context("missing uploader bracket")?;
    let mut gross = capacity::add(num(a, "growth")?, resident)?;
    for credit in a["resident_anonymous_credit"]
        .as_object()
        .context("anonymous credits")?
        .values()
    {
        gross = capacity::add(gross, credit.as_u64().context("anonymous credit")?)?;
    }
    // The historical growth and floor already include all preceding awards.
    // Include this receipt's retained bytes and all subsequently assignable bytes.
    let pool = capacity::add(num(a, "remaining_265")?, num(a, "retained")?)?;
    ensure!(
        pool <= num(a, "from_265")?,
        "residual pool exceeds original allocation"
    );
    let memory = gross
        .checked_sub(donor)
        .context("donor exceeds retained growth")?;
    let memory = capacity::add(
        capacity::add(memory, candidate)?,
        capacity::add(pool, 6400 << 20)?,
    )?;
    let floor = num(a, "protected_floor")?
        .checked_sub(num(release, "replaced_future_growth_bytes")?)
        .context("closed extent exceeds floor")?;
    let floor = capacity::add(
        capacity::add(floor, num(release, "qa_bytes")?)?,
        capacity::add(num(delivery, "disk")?, pool)?,
    )?;
    Ok((memory, floor))
}

fn closed_loop(release: &Value, scratch_dev: u64) -> Result<()> {
    let identity = &release["current"]["identity"];
    let image = Path::new(text(identity, "image")?);
    let md = fs::symlink_metadata(image)?;
    let name = Path::new(text(identity, "loop")?)
        .file_name()
        .context("loop device")?;
    let sys = Path::new("/sys/block").join(name);
    ensure!(
        image.canonicalize()? == image
            && md.is_file()
            && md.dev() == scratch_dev
            && md.dev() == num(identity, "device")?
            && md.ino() == num(identity, "inode")?
            && md.len() == num(identity, "cap")?
            && md.blocks().checked_mul(512) == Some(num(release, "retained_backing_bytes")?)
            && fs::read_to_string(sys.join("ro"))?.trim() == "1"
            && Path::new(fs::read_to_string(sys.join("loop/backing_file"))?.trim()) == image,
        "closed loop backing changed: {}",
        image.display()
    );
    Ok(())
}

fn owners() -> Result<BTreeMap<String, Value>> {
    let preparation = Bound::new(
        PREPARATION,
        "3ef8c93fb4caee74ed7bfef9bd1fa2dd8bf7ec061efbc0c6c739a526d572c880",
    );
    // The prepare receipt predates the independent 265 retry.
    let mut peers: BTreeMap<String, Value> =
        serde_json::from_value(preparation.json()?["allocation"]["live_peers"].clone())?;
    let retry = Bound::new(
        RETRY_LAUNCH,
        "5f60b1235a828fcec320ccc1933364106f8bb3027a03be3337f6f1e6b6fad937",
    )
    .json()?;
    let mut owner = retry["unit"].clone();
    let unit = text(&owner, "Id")?.to_owned();
    ensure!(
        peers.len() == 5 && !peers.contains_key(&unit),
        "unexpected preparation cohort"
    );
    owner["cpus"] = json!([10, 11]);
    peers.insert(unit, owner);
    Ok(peers)
}

fn census(
    n: &mut Native,
    fleet: &Value,
    controller: &str,
    owners: &BTreeMap<String, Value>,
) -> Result<()> {
    let mut expected: BTreeSet<_> = owners.keys().cloned().collect();
    ensure!(
        expected.insert(controller.to_owned()) && funding::manager_units(n)? == expected,
        "live service roster changed"
    );
    let active = rows(fleet, "active")?;
    ensure!(active.len() == 4, "unexpected fleet width");
    let mut deliveries = BTreeSet::new();
    for row in active {
        let u = &row["unit"];
        let name = text(u, "Id")?;
        let epoch = num(row, "epoch")?;
        let owner = owners.get(name).context("unpriced delivery")?;
        ensure!(
            name.starts_with(&format!("horizon-upload-{epoch}-"))
                && deliveries.insert(epoch)
                && row["phase"] == "upload-readback"
                && row["live"] == true
                && row["expected_invocation_id"] == owner["InvocationID"]
                && u["InvocationID"] == owner["InvocationID"]
                && u["MainPID"] == owner["MainPID"],
            "delivery claim changed"
        );
    }
    ensure!(
        deliveries == BTreeSet::from([247, 248, 249, 265]),
        "delivery epochs changed"
    );
    for (name, owner) in owners {
        let cap = if name.starts_with("horizon-upload-") {
            10 << 30
        } else {
            512 << 20
        };
        let now=n.show_fields(name,"Id,LoadState,ActiveState,SubState,InvocationID,NRestarts,Result,Job,Restart,KillMode,Delegate,ControlGroup,MainPID,MemoryMax,MemorySwapMax")?;
        live::finite_owner(&now, name, text(owner, "InvocationID")?, cap)?;
        ensure!(now["MainPID"] == owner["MainPID"], "replaced peer process");
        let pid = text(owner, "MainPID")?.parse::<u32>()?;
        let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
        let mask = funding::cpus(
            status
                .lines()
                .find_map(|s| s.strip_prefix("Cpus_allowed_list:"))
                .context("process CPU mask")?
                .trim(),
        )?;
        let expected: BTreeSet<u32> = serde_json::from_value(owner["cpus"].clone())?;
        ensure!(
            mask == expected && mask.iter().all(|c| *c >= 8),
            "peer CPU booking changed"
        );
    }
    Ok(())
}

pub(crate) fn assess(n: &mut Native, f: &Bound, controller: &str, held: bool) -> Result<Value> {
    ensure!(!held, "assessment requires an unstarted candidate");
    original_boot()?;
    let fleet = peer261::latest(f)?;
    let a = Bound::new(ACCOUNTING, ACCOUNTING_SHA).json()?;
    let release_ref = Bound::new(
        RELEASE,
        "c2112c2cf4d97797dbf9d1d2c347c2e00c954c14eedba5572b621aa22e7588af",
    );
    let release = release_ref.sealed()?;
    let delivery = binding(&a["closed265_delivery"])?.sealed()?;
    ensure!(
        a["boot"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
            && release["terminal"] == a["closed266"]
            && release["original"] == a["issued"]
            && release["current"]["identity"] == a["extent"]["identity"]
            && release["remaining_original_growth"] == 0
            && delivery["donor"] == json!(release_ref)
            && delivery["automatic_release"] == false,
        "donor binding changed"
    );
    let predecessor = binding(&a["closed_guest"])?.sealed()?;
    let scratch = Path::new(SCRATCH257);
    let device = fs::metadata(scratch)?.dev();
    ensure!(
        scratch.canonicalize()? == scratch && fs::read_dir(scratch)?.next().is_none(),
        "257 scratch is occupied"
    );
    let peers = owners()?;
    let sample = |n: &mut Native| -> Result<(u64, u64, u64)> {
        census(n, &fleet, controller, &peers)?;
        closed_loop(&release, device)?;
        closed_loop(&predecessor, device)?;
        live::resources_at(scratch)
    };
    let first = sample(n)?;
    let (growth, floor) = budget(&a, &release, &delivery)?;
    let last = sample(n)?;
    let available = first.1.min(last.1);
    let free = first.2.min(last.2);
    let required = capacity::add(floor, native257_fit::NATIVE257_DISK)?;
    ensure!(
        first.0 == last.0 && first.0 >= num(&a, "total_hard")? && f.json()? == fleet,
        "host or fleet changed"
    );
    Ok(
        json!({"fleet":f,"accounting":Bound::new(ACCOUNTING,ACCOUNTING_SHA),"release":release_ref,
        "owners":peers.keys().collect::<Vec<_>>(),"candidate_memory_bytes":native257_fit::NATIVE257_MEMORY,
        "candidate_control_memory_bytes":CONTROL+GUARD,"candidate_disk_bytes":native257_fit::NATIVE257_DISK,
        "required_available_memory_bytes":growth,"observed_available_memory_bytes":available,
        "protected_existing_floor_bytes":floor,"required_initial_free_bytes":required,"observed_available_bytes":free,
        "fits":available>=growth && free>=required,"admission_authorized":false,"producer_started":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conserved_donor_and_preexisting_growth() -> Result<()> {
        let anchor = |rss| json!({delivery247::SUCCESSOR_UNIT:rss});
        let accounting = json!({"growth":250000000000u64,"before":anchor(20),"middle":anchor(21),"after":anchor(15),
            "resident_anonymous_credit":{"peer":30},"remaining_265":900,"retained":100,"from_265":2000,
            "protected_floor":100000});
        let release =
            json!({"producer":192000000000u64,"replaced_future_growth_bytes":80000,"qa_bytes":500});
        let mut delivery =
            json!({"gross":11000000000u64,"reserve_after":181000000000u64,"disk":2500});
        let (ram, floor) = budget(&accounting, &release, &delivery)?;
        assert_eq!(
            ram,
            58000000000u64
                + native257_fit::NATIVE257_MEMORY
                + CONTROL
                + GUARD
                + (6400 << 20)
                + 1045
        );
        assert_eq!(floor, 24000);
        delivery["reserve_after"] = json!(192000000000u64);
        assert!(budget(&accounting, &release, &delivery).is_err());
        Ok(())
    }
}
