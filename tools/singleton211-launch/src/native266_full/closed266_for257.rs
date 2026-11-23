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

// Both original private transfers finished. Their reservations remain in the
// frozen budget while the same two slots perform independent readback.
fn holding_readers(peers: &mut BTreeMap<String, Value>) -> Result<()> {
    for (base, cpu, park_sha, start_sha) in [
        (
            "horizon250-private-holding-v203-a1",
            56,
            "1404721cf236c2849a607d6c175789c713c26503c128ff9d4b7ea0bc51400342",
            "0b93872b69e2e5aa40cc42d4fb6bda6340b2ad8bafbf6ec0422276ede446b3f4",
        ),
        (
            "horizon251-private-holding-v205-a1",
            41,
            "a88b2bf3322ae5b442168c52927b15dd4d3bd85192e0f75afea45d07b859a31b",
            "e732fb3f9aa67692ae21339d8447a9e619a1451f21b259f1b4c312b92d3ca4f8",
        ),
    ] {
        let diag = Path::new("/home/ubuntu/.codex/diagnostics");
        let park_name = format!("{base}-park.service");
        let verify_name = format!("{base}-verify.service");
        let park_ref = Bound::new(diag.join(format!("{base}-park/completion.json")), park_sha);
        let park = park_ref.json()?;
        let previous = peers
            .remove(&park_name)
            .context("missing original holding owner")?;
        ensure!(
            park["invocation_id"] == previous["InvocationID"]
                && park["source_retained"] == true
                && park["resource_credit"] == 0
                && !Path::new("/sys/fs/cgroup/system.slice")
                    .join(park_name)
                    .try_exists()?,
            "original holding transfer has not drained"
        );
        let dir = diag.join(format!("{base}-verify"));
        let start = Bound::new(dir.join("running.json"), start_sha).json()?;
        let book = binding(&start["booking"])?.json()?;
        ensure!(
            book["original"] == park["original"]
                && book["prior"] == json!(park_ref)
                && book["operation"] == "verify"
                && book["unit"] == verify_name
                && book["service_bytes"] == (512u64 << 20)
                && book["retirement"] == false,
            "independent holding readback booking changed"
        );
        let mut owner = start["owner"].clone();
        let finished = dir.join("completion.json");
        if finished.try_exists()? {
            let result = bound_at(&finished)?.json()?;
            let mut expected = park["result"].clone();
            expected["operation"] = json!("verify");
            let manager = binding(&result["manager"])?.json()?;
            ensure!(
                result["booking"] == start["booking"]
                    && result["invocation_id"] == owner["InvocationID"]
                    && result["source_retained"] == true
                    && result["resource_credit"] == 0
                    && result["original"] == book["original"]
                    && result["result"] == expected
                    && binding(&result["process"])?.json()?["exit"] == 0
                    && manager
                        .as_array()
                        .is_some_and(|events| events.iter().any(|r| r["_PID"] == "1"
                            && r["_UID"] == "0"
                            && r["UNIT"] == verify_name
                            && r["INVOCATION_ID"] == owner["InvocationID"]
                            && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                            && r.get("UNIT_RESULT").is_none_or(|v| v == "success")))
                    && !Path::new("/sys/fs/cgroup/system.slice")
                        .join(&verify_name)
                        .try_exists()?,
                "incomplete private holding readback"
            );
        } else {
            let pid = text(&owner, "MainPID")?.parse::<u32>()?;
            ensure!(
                fs::read_link(format!("/proc/{pid}/exe"))? == binding(&book["image"])?.path
                    && owner["AllowedCPUs"] == cpu.to_string(),
                "private readback owner changed"
            );
            owner["cpus"] = json!([cpu]);
            peers.insert(verify_name, owner);
        }
    }
    Ok(())
}

pub(crate) fn confirmed_census(values: &Value) -> Result<bool> {
    let expected = owners()?;
    Ok(values
        .as_object()
        .is_some_and(|m| m.len() == expected.len() && expected.keys().all(|k| m.contains_key(k))))
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
    holding_readers(&mut peers)?;
    Ok(peers)
}

fn peer_cap(name: &str) -> u64 {
    if name.starts_with("horizon-upload-") {
        10 << 30
    } else {
        512 << 20
    }
}

// memory.current may briefly exceed memory.max during reclaim. Retain the raw
// sample and charge the excess on top of the fully reserved peer envelopes.
fn peer_excess(current: &BTreeMap<String, u64>) -> Result<u64> {
    current.iter().try_fold(0, |sum, (name, bytes)| {
        capacity::add(sum, bytes.saturating_sub(peer_cap(name)))
    })
}

fn census(
    n: &mut Native,
    fleet: &Value,
    controller: &str,
    owners: &BTreeMap<String, Value>,
    held: bool,
) -> Result<BTreeMap<String, u64>> {
    let mut expected: BTreeSet<_> = owners.keys().cloned().collect();
    if held {
        let actor = n.show(native257::UNIT)?;
        let iid = text(&actor, "InvocationID")?;
        live::finite_owner(
            &actor,
            native257::UNIT,
            iid,
            native257_fit::NATIVE257_MEMORY,
        )?;
        crate::gate::held_image(
            text(&actor, "MainPID")?.parse()?,
            iid,
            native257::UNIT,
            native257::HARNESS,
        )?;
        expected.insert(native257::UNIT.to_owned());
    }
    ensure!(
        expected.insert(controller.to_owned()),
        "controller overlaps a booked owner"
    );
    let mut active_units = funding::manager_units(n)?;
    // The original 266 guard periodically wakes even after its producer drained.
    // Only accept a complete census after that actual firing has finished.
    let guard = "horizon-266-general-protective-v1.service";
    if active_units.contains(guard)
        && active_units
            .difference(&expected)
            .eq(std::iter::once(&guard.to_owned()))
    {
        let timer = n.show_fields(
            "horizon-266-general-protective-v1.timer",
            "InvocationID,ActiveState,Triggers",
        )?;
        ensure!(
            timer["InvocationID"] == "eeb81e1dee8544a88b44feb1d38ec9d7"
                && timer["ActiveState"] == "active"
                && timer["Triggers"] == guard,
            "unknown periodic guard"
        );
        std::thread::sleep(Duration::from_millis(250));
        active_units = funding::manager_units(n)?;
    }
    ensure!(active_units == expected, "live service roster changed");
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
    let mut memory = BTreeMap::new();
    for (name, owner) in owners {
        let cap = peer_cap(name);
        let now=n.show_fields(name,"Id,LoadState,ActiveState,SubState,InvocationID,NRestarts,Result,Job,Restart,KillMode,Delegate,ControlGroup,MainPID,MemoryMax,MemorySwapMax")?;
        memory.insert(
            name.clone(),
            live::peer_memory_current(&now, name, text(owner, "InvocationID")?, cap)?,
        );
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
    Ok(memory)
}

pub(crate) fn assess(n: &mut Native, f: &Bound, controller: &str, held: bool) -> Result<Value> {
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
    let sample = |n: &mut Native| -> Result<_> {
        let current = census(n, &fleet, controller, &peers, held)?;
        closed_loop(&release, device)?;
        closed_loop(&predecessor, device)?;
        Ok((live::resources_at(scratch)?, current))
    };
    let (first, prior_current) = sample(n)?;
    let (growth, floor) = budget(&a, &release, &delivery)?;
    let (last, current) = sample(n)?;
    let excess = peer_excess(&prior_current)?.max(peer_excess(&current)?);
    let growth = capacity::add(growth, excess)?;
    let available = first.1.min(last.1);
    let free = first.2.min(last.2);
    let required = capacity::add(floor, native257_fit::NATIVE257_DISK)?;
    ensure!(
        first.0 == last.0 && first.0 >= num(&a, "total_hard")? && f.json()? == fleet,
        "host or fleet changed"
    );
    Ok(
        json!({"fleet":f,"accounting":Bound::new(ACCOUNTING,ACCOUNTING_SHA),"release":release_ref,
        "first_peer_memory":prior_current,"charged_peer_overage_bytes":excess,"actual_current_memory":current,"owners":peers.keys().collect::<Vec<_>>(),"candidate_memory_bytes":native257_fit::NATIVE257_MEMORY,
        "candidate_control_memory_bytes":CONTROL+GUARD,"candidate_disk_bytes":native257_fit::NATIVE257_DISK,
        "required_available_memory_bytes":growth,"observed_available_memory_bytes":available,
        "protected_existing_floor_bytes":floor,"required_initial_free_bytes":required,"observed_available_bytes":free,
        "fits":available>=growth && free>=required,"admission_authorized":false,"producer_started":false}),
    )
}

const BOOK: &str = "/var/lib/jetstreamer/horizon257-closed266-reservation-v217/assignment.json";
const BOOK_SHA: &str = "c28b7b8e77ad679827338f883e5496c42f2d2de6a3a25cc44c7d3f38cf2862cb";

pub(crate) fn booking(review: &Value) -> Result<Value> {
    let award = Bound::new(BOOK, BOOK_SHA);
    ensure!(
        review["closed266_booking"] == json!(award)
            && review["epoch"] == 257
            && matches!(
                review["operation"].as_str(),
                Some("native-cold" | "qualify-guard")
            ),
        "different closed 266 booking or restore"
    );
    let book = award.sealed()?;
    let closure = Bound::new(
        "/home/ubuntu/.codex/diagnostics/horizon257-v16-retention-closure-v220/completion.json",
        "2858c894467c83a7e0f81efac6f6ea9c2782aa47247a72feedbb18ebccd7ad7c",
    );
    let closed = closure.json()?;
    let terminal = binding(&closed["terminal"])?.sealed()?;
    let handoff = binding(&closed["startup"])?.sealed()?;
    let intent = binding(&closed["intent"])?.json()?;
    let next = binding(&review["preparation"])?.sealed()?;
    let prepare_review = binding(&next["review"])?.sealed()?;
    let requested = (review["operation"].as_str(), review["attempt"].as_str());
    ensure!(
        matches!(
            requested,
            (Some("qualify-guard"), Some("guard-reap-closed266-v220"))
                | (Some("native-cold"), Some("cold-reap-closed266-v220"))
        ) && next["attempt"] == review["attempt"]
            && next["operation"] == review["operation"]
            && next["cpu_affinity"] == book["cpu"]
            && next["guard"] == review["guard"]
            && prepare_review["previous_preparation"] == intent["preparation"]
            && prepare_review["closed266_booking"] == json!(award)
            && prepare_review["previous_closure"] == json!(closure)
            && review["previous_closure"] == json!(closure)
            && closed["reservation"] == json!(award)
            && closed["resources_released"] == false
            && closed["all_four_links_removed"] == true
            && closed["original_token_preserved"] == true
            && closed["original_processes_gone"] == true
            && closed["token"] == handoff["first_guard_token"]
            && terminal["invocation_id"] == handoff["invocation_id"]
            && terminal["native_input_qualified"] == false
            && terminal["resource_release_authorized"] == false,
        "fresh preparation must inherit the original reservation from the closed cold restore"
    );
    ensure!(
        review["cpu_affinity"] == book["cpu"]
            && book["memory"] == native257_fit::NATIVE257_MEMORY + CONTROL + GUARD
            && book["disk"] == native257_fit::NATIVE257_DISK
            && book["automatic_release"] == false,
        "257 booking differs from prepared envelope"
    );
    let charge = Bound::new(
        "/home/ubuntu/.codex/diagnostics/horizon257-closed266-reservation-v217/completion.json",
        "555b31358b0c0c16948e67409fbdba1228e5d088be94ebfcbb9491ea2433c38b",
    )
    .json()?;
    ensure!(
        charge["reservation"] == json!(award)
            && binding(&charge["readback"])?.json()?["reservation257"] == json!(award),
        "issuer has not charged the booking"
    );
    // The reservation predates the two holding readbacks and the retained
    // terminal clock. Check the original pricing bytes at their archived path
    // and the live issuer at the version that carries this same reservation.
    let original = binding(&charge["source_control"])?;
    Bound::new(
        "/home/ubuntu/.codex/diagnostics/horizon257-v16-operator-registration/horizon266-bounded-tools-v208-retry_fit.py",
        original.sha256,
    )
    .bytes(true)?;
    let deployment = Bound::new(
        "/home/ubuntu/.codex/diagnostics/horizon257-original-terminal-manager-v220/completion.json",
        "ea519b5bfe1a626303bce5b1b161da7b1a206c706e7a5ba1dc9dcfb8e8eba20c",
    )
    .json()?;
    let changes: Vec<Bound> = serde_json::from_value(deployment["changes"].clone())?;
    let current = changes
        .iter()
        .find(|change| change.path == original.path)
        .context("deployment lacks the epoch 257 pricing script")?;
    ensure!(
        binding(&deployment["debit"])?.json()?["reservation257"] == json!(award),
        "pricing deployment charged a different epoch 257 reservation"
    );
    current.artifact()?;
    bounded::issuer_lock(review)?;
    Ok(book)
}

pub(crate) fn current(n: &mut Native, review: &Value, held: bool) -> Result<(Value, Value)> {
    let book = booking(review)?;
    let controller = text(review, "controller_unit")?;
    let iid = std::env::var("INVOCATION_ID")?;
    let owner = n.show(controller)?;
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{controller}")
            && text(&owner, "MainPID")?.parse::<u32>()? == std::process::id(),
        "different 257 launch controller"
    );
    live::finite_owner(&owner, controller, &iid, CONTROL)?;
    let f = binding(&review["fleet"])?;
    let current = f.json()?;
    let money = &current["memory_target"];
    ensure!(
        review["observer"]
            == json!(Bound::new(
                text(&current, "observer_receipt")?,
                text(&current, "observer_sha256")?
            ))
            && money["valid"] == true
            && money["executing_lanes"] == 0
            && num(money, "desired_lanes")? > 0
            && money["sampled_at_utc"] == current["sampled_at_utc"],
        "current fleet RSS target or observer differs"
    );
    let fit = assess(n, &f, controller, held)?;
    ensure!(
        fit["fits"] == true && fit["release"] == book["donor"],
        "reserved 257 no longer fits"
    );
    let after = n.show(controller)?;
    live::same_owner(&owner, &after)?;
    bounded::issuer_lock(review)?;
    let cap = json!({"protected_existing_floor_bytes":fit["protected_existing_floor_bytes"],
       "actual_current_memory":fit["actual_current_memory"],"closed266_booking":review["closed266_booking"],
       "capacity":fit});
    Ok((fit, cap))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn charges_all_peer_overages_without_resident_credit() {
        let samples = BTreeMap::from([
            (
                "horizon250-private-holding.service".into(),
                (512 << 20) + 4096,
            ),
            ("horizon-upload-247.service".into(), (10 << 30) + 8192),
            ("horizon251-private-holding.service".into(), 0),
        ]);
        assert_eq!(peer_excess(&samples).unwrap(), 12288);
    }

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
