//! Admit the capped archive writer only inside the separately issued donor reservation.
use super::*;
mod progress;
pub(super) use progress::{finish, stop_at_target};
pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon266-capped-bounded-v207-control";
pub(super) const CONTROLLER: &str = "horizon266-capped-bounded-v207-control.service";
pub(super) const RETRY_STATE: &str = "/var/lib/jetstreamer/horizon266-capped-bounded-v210-control";
pub(super) const RETRY_CONTROLLER: &str = "horizon266-capped-bounded-v210-control.service";
pub(super) const MEMORY: u64 = 192_000_000_000;
const ROOT_BYTES: u64 = 344_997_011_456;
const FLOOR: u64 = 4_290_366_117_888;
pub(super) const WORKER: &str = "/var/lib/jetstreamer/horizon266-capped-worker-package-v199-a1/jetstreamer-historical-worker-v1-8-11";
pub(super) const WORKER_SHA: &str =
    "763f1aff1f752f0d9886f0f2324a73c9c66a154269d28931575744316bb2f220";
const PACKET: &str = "/var/lib/jetstreamer/horizon266-capped-cold-inputs-v200-a2/inputs.json";
const PACKET_SHA: &str = "124212ab9f62ae6ea30998b02955a0530b2b56de3c2a1339a3b5204b6fe53a8a";
pub(super) fn inputs() -> Result<Value> {
    let packet = Bound::new(PACKET, PACKET_SHA).sealed()?;
    let files = rows(&packet, "files")?;
    ensure!(
        files.len() == 4
            && files[0]["path"] == WORKER
            && files[0]["sha256"] == WORKER_SHA
            && files[3]["path"] == successor::NODE,
        "capped worker input binding"
    );
    for row in files {
        let path = Path::new(text(row, "path")?);
        let m = fs::symlink_metadata(path)?;
        let pin = &row["identity"];
        ensure!(
            m.is_file()
                && path.canonicalize()? == path
                && m.nlink() == 1
                && m.uid() == 0
                && m.mode() & 0o222 == 0
                && m.dev() == num(pin, "device")?
                && m.ino() == num(pin, "inode")?
                && m.len() == num(pin, "bytes")?
                && m.ctime() == num(pin, "ctime")? as i64
                && m.ctime_nsec() == num(pin, "ctime_nsec")? as i64,
            "changed capped input {}",
            path.display()
        );
    }
    Bound::new(WORKER, WORKER_SHA).artifact()?;
    Bound::new(successor::NODE, text(&files[3], "sha256")?).artifact()?;
    Ok(packet)
}
pub(super) fn payload(p: &Profile, s: &Value) -> Result<()> {
    let packet = inputs()?;
    let f = rows(&packet, "files")?;
    let manifest = Bound::new(
        Path::new(SNAPROOT).join("preflight-233-301-target4-publish300-46b4b4a.json"),
        "3c32a5d78e764cb982b246ab123eadf4fddb5eb51b6377f7afbb196aef714b81",
    );
    let m = manifest.sealed()?;
    let args = json!([
        successor::NODE,
        "266",
        p.root.join("output"),
        "--verify",
        "--root-checkpoint-cohort",
        format!("--cohort-manifest={}", manifest.path.display()),
        format!(
            "--cohort-manifest-fingerprint={}",
            text(&m, "manifest_fingerprint")?
        ),
        format!("--snapshot-archive={}", text(&f[1], "path")?)
    ]);
    ensure!(
        s["worker"] == WORKER
            && s["manifest"] == json!(manifest)
            && s["argv"] == args
            && std::env::var("JETSTREAMER_HISTORICAL_WORKER_V1_8_11")? == WORKER,
        "capped replay command or environment differs"
    );
    Ok(())
}

const PARK250: &str = "horizon250-private-holding-v203-a1-park.service";
const PARK251: &str = "horizon251-private-holding-v205-a1-park.service";
const HARD: u64 = 1_212_131_577_856;
const FROM_228: u64 = 76_000_000_000;
const FROM_265: u64 = MEMORY + GUARD_MEM + CONTROL_MEM - FROM_228;
pub(super) fn issuer_lock(r: &Value) -> Result<()> {
    let pid = num(r, "issuer_pid")?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    ensure!(
        stat.rsplit_once(") ")
            .and_then(|(_, s)| s.split_whitespace().nth(19))
            == r["issuer_ticks"].as_str(),
        "bounded issuer changed"
    );
    let lock = fs::metadata("/run/horizon292-300-finite-v205-a1/issuer.lock")?;
    let key = format!(
        "{:02x}:{:02x}:{}",
        libc::major(lock.dev()),
        libc::minor(lock.dev()),
        lock.ino()
    );
    ensure!(
        fs::read_to_string("/proc/locks")?.lines().any(|l| l
            .split_whitespace()
            .skip(1)
            .take(5)
            .eq(["FLOCK", "ADVISORY", "WRITE", &pid.to_string(), &key])),
        "bounded reservation issuer released its lock"
    );
    Ok(())
}
pub(super) fn runtime_image(r: &Value) -> Result<Bound> {
    let original = Bound::new(
        "/var/lib/jetstreamer/horizon266-capped-bounded-v208-a1-qualified/native-fit",
        "79be3c4ba91dc629ca3efc0cfe07286873acd2667bd9c9925ba038d4cccf26e2",
    );
    original.artifact()?;
    let seal = Bound::new(
        original.path.with_file_name("deployment-seal-receipt.json"),
        "03794517affb047ae6f24f2272cc92db4becaedafe0e0d7c14c3130fe9abdb50",
    )
    .sealed()?;
    ensure!(
        r["runtime_image"] == json!(original)
            && rows(&seal, "members")?
                .iter()
                .any(|m| m["name"] == "native-fit" && m["sha256"] == original.sha256),
        "different qualified runtime"
    );
    Ok(original)
}
// The previous loop stays sealed. Only the existing reservation transfers to this attempt.
fn retry_limits(booking: &Bound, assessment: &Value, fleet: &Bound) -> Result<(u64, u64)> {
    let closure = Bound::new(
        "/var/lib/jetstreamer/horizon266-v207-closed-growth-v210/release.json",
        "a4c097ded324c48c3c591c46c90f7baf6cb816405c1f6200ad0d1bcd3813600c",
    );
    let released = closure.sealed()?;
    let observed = binding(&assessment["successor_fit"])?.sealed()?;
    let old = Profile::new(Lane::Bounded266, "pilot")?;
    let mount = bound_at(&old.state.join("mount.json"))?.sealed()?;
    let image = fs::symlink_metadata(old.state.join("private.ext4"))?;
    ensure!(
        assessment["closed_predecessor"] == json!(closure)
            && released["original"] == json!(booking)
            && released["remaining_original_growth"] == 0
            && observed["issued"] == json!(booking)
            && observed["fleet"] == json!(fleet)
            && observed["terminal"] == released["terminal"]
            && observed["other_reservations_retained"] == true
            && mount["loop"] == "/dev/loop15"
            && fs::read_to_string("/sys/block/loop15/ro")?.trim() == "1"
            && image.dev() == 66305
            && image.ino() == 6025749
            && image.len() == ROOT_BYTES
            && image.blocks() * 512 == num(&released, "retained_backing_bytes")?,
        "bounded predecessor closure or reservation changed"
    );
    live::verify_drained_group(&old.unit)?;
    let disk = num(assessment, "successor_floor")?;
    let extent = &observed["extent"];
    let expected = num(&observed, "protected_floor")?
        .checked_sub(num(extent, "remaining")?)
        .and_then(|n| n.checked_add(num(&observed, "disk").ok()?))
        .context("successor disk floor")?;
    ensure!(
        disk == expected
            && disk >= num(&released, "floor")?
            && extent["identity"] == released["current"]["identity"]
            && extent["first"]["map_sha256"] == released["current"]["first"]["map_sha256"]
            && extent["second"]["map_sha256"] == released["current"]["second"]["map_sha256"],
        "unfunded bounded successor"
    );
    Ok((
        disk.checked_add(num(&released, "qa_bytes")?)
            .context("QA floor")?,
        num(&observed, "growth")?,
    ))
}
pub(super) fn elect(
    lane: Lane,
    n: &mut Native,
    r: &Value,
    held: Option<(&Profile, &Value, (u64, u64))>,
) -> Result<Value> {
    issuer_lock(r)?;
    let booking = binding(&r["reservation"])?;
    ensure!(
        booking.path == Path::new(STATE).join("reservation.json"),
        "different bounded reservation"
    );
    let b = booking.sealed()?;
    ensure!(
        b["issued"] == true
            && booking.sha256 == "273f914d9cfaf6078076998ba1eb7a49b1b50a33a561db4eebe9ebf12ed45bc8"
            && r["previous_review"]
                == json!(Bound::new(
                    Path::new(STATE).join("review.json"),
                    "f3dfae7a9e0d7263c51c82043d03a69c40f70a310abdb5398554e8961f073e57"
                ))
            && b["from_228"] == FROM_228
            && b["from_265"] == FROM_265
            && b["publication_authorized"] == false,
        "bounded reservation not issued for this controller"
    );
    let previous = binding(&r["previous_review"])?.sealed()?;
    ensure!(
        previous["reservation"] == json!(booking)
            && previous["issuer_pid"] == b["issuer_pid"]
            && !Path::new(&format!("/proc/{}", num(&b, "issuer_pid")?)).try_exists()?,
        "original reservation issuer still exists"
    );
    let price = binding(&r["fresh_assessment"])?.json()?;
    let fit = &price["fit"];
    ensure!(
        price["fits"] == true
            && price["other_reservations_fully_retained"] == true
            && price["hard"] == HARD
            && price["from_265"] == FROM_265
            && price["from_228"] == FROM_228
            && price["remaining_228"] == 121731072
            && price["additional_hard_bytes"] == 0
            && price["protected_floor"] == FLOOR
            && price["loop_capacity"] == ROOT_BYTES
            && price["maximum_root_physical_bytes"] == ROOT_BYTES - (8 << 30)
            && price["cpu"] == json!([0, 1, 2, 3, 4, 5, 6, 7]),
        "incomplete bounded funding"
    );
    let release = binding(&price["closed_growth"])?;
    ensure!(
        release.sha256 == "42e3aec8a1fd914e79a6455e2da81765429da2bb29e0023b1fdb7fb433f274b4"
            && release.sealed()?["remaining_disk_growth_bytes"] == 0
            && fs::read_to_string("/sys/block/loop12/ro")?.trim() == "1",
        "old guest growth not closed"
    );
    let fleet = binding(&fit["fleet"])?;
    let f = funding::anchor(&fleet)?;
    ensure!(
        rows(&f, "active")?
            .iter()
            .map(|a| num(a, "epoch"))
            .collect::<Result<Vec<_>>>()?
            == [247],
        "booked fleet changed"
    );
    let mut allowed = BTreeSet::from([lane.controller().to_owned()]);
    let mut uploader_current = 0;
    for (unit, iid, pid, cap, mask) in [
        (
            funding::OWNERS[2].0,
            funding::OWNERS[2].1,
            2774321,
            10u64 << 30,
            "48-55",
        ),
        (
            PARK250,
            "179e129e82aa4f4db14b97c80ac5bd63",
            3375961,
            512 << 20,
            "56",
        ),
        (
            PARK251,
            "93fcaa47db5f4c7aba270738f598dc42",
            3391444,
            512 << 20,
            "41",
        ),
    ] {
        let until = Instant::now() + Duration::from_secs(4);
        let (m, current) = loop {
            let mut m = json!(gate::owner_fields(unit)?);
            m["Job"] = json!(command_field(n, unit, "Job")?);
            match live::finite_owner(&m, unit, iid, cap) {
                Ok(current) => break (m, current),
                Err(e)
                    if e.to_string() == "kernel memory exceeds cap" && Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(e) => return Err(e.context(format!("bounded peer {unit}"))),
            }
        };
        ensure!(
            text(&m, "MainPID")?.parse::<u64>()? == pid
                && funding::cpus(&fs::read_to_string(format!(
                    "/sys/fs/cgroup/system.slice/{unit}/cpuset.cpus.effective"
                ))?)?
                    == funding::cpus(mask)?,
            "changed peer {unit}"
        );
        allowed.insert(unit.to_owned());
        if unit == funding::OWNERS[2].0 {
            uploader_current = current;
        }
    }
    for (unit, iid) in [
        (funding::OWNERS[0].0, funding::OWNERS[0].1),
        (funding::OWNERS[1].0, funding::OWNERS[1].1),
        (
            "horizon-261-native-input-20261120-v1.service",
            "97592a79476446ffa3b0e25ff64ffcf9",
        ),
        (
            "horizon-266-capped-native-input-v1.service",
            "13bb836506974dd68a45aa6b2ebce5b8",
        ),
        (
            "horizon-qualify-266-instructions-2789f821-v194.service",
            "41cf6e5a5cd54d57adc5eba3f0c0ecef",
        ),
    ] {
        let m = n.show(unit)?;
        ensure!(
            matches!(m["ActiveState"].as_str(), Some("inactive" | "failed"))
                && m["MainPID"] == "0"
                && (m["InvocationID"] == iid || m["InvocationID"] == ""),
            "donor or retained producer active {unit}"
        );
        live::verify_drained_group(unit)?;
    }
    if let Some((p, o, pair)) = held {
        ensure!(
            p.mode == "pilot" && pair == (MEMORY, ROOT_BYTES),
            "different held candidate"
        );
        live::same_owner(o, &n.show(&p.unit)?)?;
        epoch228::kernel(
            p,
            o,
            &json!({"cpus":price["cpu"],"winner":{"memory":MEMORY}}),
        )?;
        allowed.insert(p.unit.clone());
        allowed.insert(p.guard.clone());
    }
    let services = funding::manager_units(n)?;
    ensure!(
        services.is_subset(&allowed),
        "unpriced services {:?}",
        services.difference(&allowed).collect::<Vec<_>>()
    );
    let (total, available, free) = live::resources_at(Path::new(V))?;
    let original = binding(&fit["drained_266"]["allocation"])?;
    ensure!(
        original.sha256 == "dddfa399c33267ad6dcb67ff66d556017f03a16ddf330cd72f1bc9cb979d7666",
        "incorrect original donor accounting"
    );
    let w = &original.sealed()?["winner"];
    let growth = HARD
        .checked_sub(
            num(w, "retained_211")? + num(w, "retained_265")? - FROM_265 + uploader_current,
        )
        .context("growth accounting")?;
    let (floor, growth) = if lane == Lane::BoundedRetry266 {
        let (disk, retained_growth) = retry_limits(&booking, &price, &fleet)?;
        (disk, growth.max(retained_growth))
    } else {
        (FLOOR, growth)
    };
    ensure!(
        HARD <= total && growth <= available && floor + ROOT_BYTES <= free,
        "capped replay no longer fits"
    );
    issuer_lock(r)?;
    Ok(
        json!({"reservation":booking,"fleet":fleet,"cpus":price["cpu"],"protected_floor":floor,"services":services,"winner":{"fits":true,"root":ROOT_BYTES,"memory":MEMORY,"hard":HARD,"growth":growth,"required_free":floor+ROOT_BYTES},"free":free,"available":available}),
    )
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    #[test]
    fn retry_has_its_own_workers_guards_and_receipts() {
        for mode in MODES {
            let old = Profile::new(Lane::Bounded266, mode).unwrap();
            let retry = Profile::new(Lane::BoundedRetry266, mode).unwrap();
            assert_ne!(old.unit, retry.unit);
            assert_ne!(old.root, retry.root);
            assert_ne!(old.state, retry.state);
            assert_ne!(old.timer, retry.timer);
            assert_ne!(old.guard, retry.guard);
            assert!(retry.lane.is_bounded());
        }
    }
}
