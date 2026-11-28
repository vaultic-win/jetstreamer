//! Count only current, identity-stable native allocations. Keep the historical
//! declarations open across both observations; changing files receive no credit.
use super::{n, peer, sum};
use anyhow::{Context, Result, ensure};
use guard168::{CAP, LANE};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, Metadata, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const PREP: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry8-recovery-20261120-v1/preparation/epoch170/local3retry8/prepared.json";
const PREP_SHA: &str = "b79fec2618d318d5ece6b7b4e61051fb0742103c2a45355c0379af2948036423";
const WIT: &str = "/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/witness-set.json";
const WIT_SHA: &str = "8eb041519cba5c3f6368cb1432be9e289489ce1acdc28aa8b49f3d6ec7f382ee";
const BOOK_SHA: &str = "8d733e8fd750052fb050726a0b930fe9d213ebf4edc174ba2eb7711878255913";
const RET: &str =
    "/var/lib/jetstreamer/local2-mismatch168-retirement-20261114-v1/epoch168/completion.json";

fn identity(m: &Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.blocks(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn canonical(p: &Path) -> Result<Metadata> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "noncanonical {}",
        p.display()
    );
    Ok(fs::symlink_metadata(p)?)
}
fn array<'a>(v: &'a Value, k: &str) -> Result<&'a Vec<Value>> {
    v[k].as_array()
        .with_context(|| format!("missing array {k}"))
}
fn path(v: &Value) -> Result<&Path> {
    Ok(Path::new(v["path"].as_str().context("path")?))
}
fn membership(prep: &Value) -> Result<Value> {
    let wit = peer::bound(&peer::pair(WIT, WIT_SHA))?;
    let slot = array(&wit, "slots")?
        .iter()
        .find(|r| r["epoch"] == 168)
        .context("168 witness membership")?;
    ensure!(
        slot["lane_root"] == LANE && slot["original_booking"]["sha256"] == BOOK_SHA,
        "168 lineage"
    );
    let booking = peer::bound(&slot["original_booking"])?;
    ensure!(
        booking["candidate_own_DATA_bytes"] == CAP
            && booking["candidate_guard_metadata_bytes"] == (8u64 << 30)
            && booking["complete_projected_memory_bytes"] == 708_249_923_584u64
            && booking["complete_DATA_bytes"] == 6_567_664_631_602u64,
        "168 retained booking"
    );
    let terminal = peer::bound(&peer::pair(
        "/var/lib/jetstreamer/terminal168-historical-mismatch-20261111-v1/ROOT168_TERMINAL_CLASSIFICATION_AND_RECOVERY_OWNER.json",
        "617e583c3a4ba1cb33e87797aaeb8d16b3e5b6bdec7f65d5e0a6f80042f45047",
    ))?;
    let stop = peer::bound(&peer::pair(
        "/var/lib/jetstreamer/terminal168-historical-mismatch-20261111-v1/TERMINAL168_GUARD_TIMER_STOP_COMPLETED.json",
        "44c6e09ac34927564f6fb64a6257f48846c323930cdd1c0bb174fc7c489bac8f",
    ))?;
    let scratch = peer::bound(&peer::pair(
        "/var/lib/jetstreamer/standard168-scratch-retirement-20261110-backfill-v1/completion.json",
        "e3544bbcdfca22fc36f26df9d57ebfe46c1bc8ccab0b7e6b0e8a354b21e5e7e7",
    ))?;
    ensure!(
        terminal["original_IID"] == "28c71c8287714cd2bec606a0ee463c9d"
            && terminal["no_memory_DATA_or_slot_promise_ending"] == true
            && stop["memory_DATA_native_promise_ending_bytes"] == 0
            && stop["original_producer_cgroup_and_children_absent"] == true
            && scratch["scratch_empty"] == true
            && scratch["resource_promise_ending_authorized"] == false,
        "168 terminal lineage"
    );
    let retirement = peer::bound(&peer::pair(
        RET,
        "02fa4339d22d77b7c1cfa97dcc1519a1f31ac190275e85cddc4dcd5568aff0a9",
    ))?;
    let scope = &retirement["scope"];
    ensure!(
        scope["epoch"] == 168
            && retirement["source_name_absent"] == true
            && retirement["hard_promises_released_bytes"] == 0
            && retirement["resource_credit_bytes"] == 0,
        "local2 retirement"
    );
    for k in [
        "custody",
        "holding_original_completion",
        "holding_transport_qualification",
        "indirect_consumers_review",
        "inspection",
        "park_spec",
    ] {
        peer::bound(&scope[k])?;
    }
    for row in array(scope, "source_ancestor_identities")? {
        let m = canonical(path(row)?)?;
        let i = &row["identity"];
        ensure!(
            m.is_dir()
                && i["device"] == m.dev()
                && i["inode"] == m.ino()
                && i["uid"] == m.uid()
                && i["gid"] == m.gid()
                && i["mode"] == m.mode(),
            "retired source ancestor changed"
        );
    }
    let src = scope["source"].as_str().context("retired path")?;
    ensure!(
        matches!(fs::symlink_metadata(src),Err(e) if e.kind()==io::ErrorKind::NotFound),
        "retired original restored"
    );
    let obs =
        &prep["resource_checks"]["data_accounting"]["original_witness_observation"]["allocation"];
    let mut members = BTreeSet::new();
    for row in array(obs, "first")?.iter().filter(|r| r["epoch"] == 168) {
        let p = path(row)?;
        let m = canonical(p)?;
        ensure!(
            p.starts_with(LANE)
                && members.insert(p)
                && identity(&m)
                    == json!([
                        row["dev"],
                        row["ino"],
                        row["uid"],
                        row["gid"],
                        row["mode"],
                        row["nlink"],
                        row["logical_bytes"],
                        row["allocated_blocks512"],
                        row["mtime"],
                        row["mtime_nsec"],
                        row["ctime"],
                        row["ctime_nsec"]
                    ]),
            "original member changed {}",
            p.display()
        );
        for a in array(row, "ancestors")? {
            let am = canonical(path(a)?)?;
            ensure!(
                am.is_dir()
                    && a["dev"] == am.dev()
                    && a["ino"] == am.ino()
                    && a["uid"] == am.uid()
                    && a["gid"] == am.gid()
                    && a["mode"] == am.mode()
                    && (a["owned_change_times"].is_null()
                        || a["owned_change_times"]
                            == json!([am.mtime(), am.mtime_nsec(), am.ctime(), am.ctime_nsec()])),
                "historical witness ancestor {}",
                path(a)?.display()
            );
        }
    }
    ensure!(
        members.len() == 3
            && array(slot, "members")?.len() == members.len()
            && array(slot, "members")?
                .iter()
                .all(|p| p.as_str().is_some_and(|s| members.contains(Path::new(s)))),
        "original 168 witness membership incomplete"
    );
    Ok(
        json!({"original_booking":slot["original_booking"],"witness_set":peer::pair(WIT,WIT_SHA),"retirement":RET,"guard_metadata_bytes":8u64<<30}),
    )
}
struct Held {
    epoch: u64,
    path: PathBuf,
    id: Value,
    file: File,
}
fn hold(prep: &Value, dev: u64) -> Result<Vec<Held>> {
    let mut held = Vec::new();
    for row in array(&prep["resource_checks"]["data_accounting"], "native_files")? {
        let epoch = n(row, "epoch")?;
        ensure!(
            [166, 167, 169, 170].contains(&epoch),
            "unexpected peer root"
        );
        let id = &row["identity"];
        if id[6].as_u64().context("file length")? < 64 << 20 {
            continue;
        }
        let p = path(row)?;
        let root = format!("/home/sol/.jetstreamer-private/epoch{epoch}-standard-lane-20261109-v1");
        ensure!(p.starts_with(&root), "foreign native file");
        let Ok(m) = canonical(p) else { continue };
        if !m.is_file() || m.dev() != dev || m.nlink() != 1 || identity(&m) != *id {
            continue;
        }
        let f = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(p)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if identity(&f.metadata()?) == *id {
            held.push(Held {
                epoch,
                path: p.to_owned(),
                id: id.clone(),
                file: f,
            });
        }
    }
    Ok(held)
}
pub(super) fn free() -> Result<u64> {
    let p = CString::new("/home/sol")?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(p.as_ptr(), st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let st = unsafe { st.assume_init() };
    st.f_frsize
        .checked_mul(st.f_bavail)
        .context("HOME free bytes")
}
fn whole_custody() -> Result<()> {
    let m = canonical(Path::new(LANE))?;
    let home = canonical(Path::new("/home/sol"))?;
    ensure!(
        m.dev() == home.dev()
            && m.ino() == 103878482
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() == 0o40700,
        "whole 168 lane changed"
    );
    let local = canonical(&Path::new(LANE).join("replacement-local1-20261110-v1"))?;
    ensure!(
        local.dev() == home.dev() && local.ino() == 103874598 && local.is_dir(),
        "nested destination ancestor"
    );
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    ensure!(
        !mounts
            .lines()
            .filter_map(|l| l.split_whitespace().nth(4))
            .any(|s| Path::new(s).starts_with(LANE)),
        "submount inside allocated lane"
    );
    Ok(())
}
#[path = "whole_du.rs"]
mod whole_du;
fn whole() -> Result<u64> {
    whole_du::scan(|| {
        whole_custody()?;
        let output = Command::new("/usr/bin/timeout")
            .env("LC_ALL", "C")
            .env("QUOTING_STYLE", "shell-always")
            .args([
                "--kill-after=1s",
                "6s",
                "/usr/bin/du",
                "-s",
                "-x",
                "-B1",
                "--",
                LANE,
            ])
            .output()
            .context("starting timed whole 168 du")?;
        whole_custody()?;
        Ok(output)
    })
}
pub(super) fn measure() -> Result<Value> {
    let prep = peer::bound(&peer::pair(PREP, PREP_SHA))?;
    let ancestry = membership(&prep)?;
    let dev = canonical(Path::new("/home/sol"))?.dev();
    let fsinfo = Command::new("/usr/bin/findmnt")
        .args(["-n", "-o", "FSTYPE", "-T", "/home/sol"])
        .output()?;
    ensure!(
        fsinfo.status.success() && fsinfo.stdout == b"ext4\n",
        "physical identity accounting requires HOME ext4"
    );
    let held = hold(&prep, dev)?;
    let a = whole()?;
    let b = whole()?;
    membership(&prep)?;
    let mut seen = BTreeSet::new();
    let mut credit = BTreeMap::<u64, u64>::new();
    for h in held {
        let Ok(m) = canonical(&h.path) else { continue };
        if identity(&m) != h.id
            || identity(&h.file.metadata()?) != h.id
            || !seen.insert((m.dev(), m.ino()))
        {
            continue;
        }
        let value = credit.entry(h.epoch).or_default();
        *value = sum(*value, m.blocks().checked_mul(512).context("blocks")?)?;
    }
    let mut growth = 0;
    for (epoch, cap) in [(166, CAP), (167, 512u64 << 30), (169, CAP), (170, CAP)] {
        growth = sum(
            growth,
            cap.checked_sub(*credit.get(&epoch).unwrap_or(&0))
                .context("peer cap exceeded")?,
        )?;
    }
    ensure!(
        a.max(b) <= CAP && CAP - a.max(b) >= 2_029_219_745,
        "candidate snapshot copy exceeds its whole-lane headroom"
    );
    Ok(
        json!({"peer_remaining_growth_bytes":growth,"standard_peer_realized_bytes":credit,"native_membership":peer::pair(PREP,PREP_SHA),"standard_root_allocated_bytes":a.min(b),"remaining_standard_root_bytes":CAP-a.min(b),"root_cap_bytes":CAP,"retained168":ancestry}),
    )
}

#[cfg(test)]
mod whole_tree_tests {
    #[test]
    #[ignore = "real HOME epoch168 lane, requires full read custody"]
    fn two_complete_live_scans() {
        let first = super::whole().unwrap();
        let second = super::whole().unwrap();
        assert!(first > 0 && second > 0);
        eprintln!("first={first} second={second}");
    }
}
