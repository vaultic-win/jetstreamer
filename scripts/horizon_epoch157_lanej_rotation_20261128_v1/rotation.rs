//! Single-copy custody, local retirement and original-path restoration of lane-j's closed 157 segment.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
#[allow(dead_code)]
#[path = "../horizon_epoch170_checkpoint_suffix/evidence.rs"]
mod evidence;
use evidence::{
    available, bound, command, digest, member, now, num, props, receipt, reference, word,
};
mod consumers;
mod transport;
const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch157-lanej-rotation-20261128-v1";
const HOLD: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1";
const SRC: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j/output/.epoch-157.jet.runtime-segments/epoch-157.segment-00-67824000-68140177.jet";
const HASH: &str = "4a4d4403a4fe92bd24c8406cebb93eccbc614e8cb746dda9dcbf8b17eeeddadf";
const LENGTH: u64 = 122_406_562_427;
const ALLOC: u64 = 122_406_727_680;
const META: u64 = 16 << 20;
const BOOT: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
const PARK: &str = "horizon-closed157-park-lanej-1795850620491935487.service";
const PARKID: &str = "798967206e06452184ca244eb585a064";
const VUNIT: &str = "horizon-qualify-157-private-verification-20261021-v1.service";
const CONTROLLER: &str = "jetstreamer-epoch157-target3-controller-v1-r2.service";
const OTHER: &str = "jetstreamer-epochs155-156-target3-controller-v1-r2.service";
const OLD: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch186-closed-partial-rotation-20261127-v1/m12-tools-v2";
const SNAP: &str = "/usr/local/lib/jetstreamer/deploy-epochs155-157-runtime-boundaries-md5-20261012-v1/snapshot-67823809-2mfgWDcrXmDMRrPtUJtJgE1oJ9jKgRZ9ETru9XjsdmuF.tar.zst";
const GLOBAL: &str = "/run/horizon-epoch171-to136-g1.operation.lock";
const ELOCK: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j/private/destination-67fe8253649bb21cdfcde32bbdba73b67debf3c2a0cc74384f9a2ff472807c61/locks/epoch-157.lock";
const OK: &str = "7ad2d189f7e94e70a38c781354912448";
const FAIL: &str = "be02cf6855d2428ba40df7e9d022f03d";
fn root(p: &str) -> PathBuf {
    Path::new(ROOT).join(p)
}
fn package(p: &str) -> PathBuf {
    root("turnover-tools-v1").join(p)
}
fn pinned(p: &Path, sha: &str) -> Value {
    json!({"path":p,"sha256":sha})
}
fn stable(p: &Path, v: &Value) -> Result<Value> {
    if p.try_exists()? {
        let x = reference(p)?;
        ensure!(bound(&x)? == *v, "conflicting evidence {}", p.display());
        Ok(x)
    } else {
        receipt(p, v)
    }
}
fn ours() -> Result<Value> {
    let s = reference(&package("deployment-seal-receipt.json"))?;
    let p = member(&s, "rotation")?;
    let m = fs::metadata(p)?;
    let a = fs::metadata("/proc/self/exe")?;
    ensure!(
        (m.dev(), m.ino()) == (a.dev(), a.ino()),
        "use sealed 157 operator"
    );
    Ok(s)
}
fn identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"allocated":m.blocks()*512,"length":m.len(),"gid":m.gid(),"uid":m.uid(),"mode":m.mode()&0o7777,"links":m.nlink(),"mtime_ns":m.mtime() as i128*1000000000+m.mtime_nsec() as i128,"ctime_ns":m.ctime() as i128*1000000000+m.ctime_nsec() as i128})
}
fn screen() -> Result<Value> {
    let v = bound(&pinned(
        &root("SOURCE_SCREEN.json"),
        "10edd861e0292c5f63cbae6be36010d27be0b3f1b1dac35e1ecbf0cffc8181fd",
    ))?;
    ensure!(
        v["source"] == SRC
            && v["archive_sha256"] == HASH
            && v["source_stat"]["inode"] == 102301753
            && v["source_stat"]["allocated"] == ALLOC
            && v["source_stat"]["length"] == LENGTH,
        "expected 157 intermediate"
    );
    Ok(v)
}
fn expected() -> Result<Value> {
    let v = bound(&pinned(
        &root("park-package-v1/expected.json"),
        "c4c24a560270605e2c0151ae802f64574785ea25a4592aa6e7b0b475160732e0",
    ))?;
    ensure!(
        v["source"] == SRC
            && v["sha256"] == HASH
            && v["source_identity"] == screen()?["source_stat"]
            && v["length"] == LENGTH,
        "expected holding binding"
    );
    Ok(v)
}
fn preserved() -> Result<Value> {
    let s = screen()?;
    let m = Path::new(word(&s["manifest"], "path")?);
    ensure!(
        m.canonicalize()? == m && identity(&fs::symlink_metadata(m)?) == s["manifest_stat"],
        "manifest inode changed"
    );
    let raw = fs::read(m)?;
    let doc: Value = serde_json::from_slice(&raw)?;
    ensure!(
        digest(&raw) == s["manifest"]["sha256"]
            && doc["archive_sha256"] == HASH
            && doc["output_slot_count"] == 316177
            && doc["terminal"]["slot"] == 68140176
            && doc["bootstrap"]["slot"] == 67823809,
        "wrong segment manifest"
    );
    let validation = bound(&s["validated_prefix"])?;
    let launch = bound(&s["validation_launch"])?;
    ensure!(
        validation["validation"] == "pass"
            && validation["archive"] == SRC
            && validation["archive_sha256"] == HASH
            && launch["unit"] == VUNIT
            && launch["invocation_id"] == "9768a460a5284f5a8ebfd422e437e8b6",
        "different original validator"
    );
    let snap = fs::symlink_metadata(SNAP)?;
    ensure!(
        Path::new(SNAP).canonicalize()? == Path::new(SNAP)
            && snap.dev() == 2304
            && snap.ino() == 6160461
            && snap.uid() == 0
            && snap.mode() & 0o777 == 0o444
            && snap.len() == 1663314014
            && snap.mtime() == 1791777449
            && snap.ctime() == 1791777449,
        "bootstrap changed"
    );
    Ok(
        json!({"manifest":s["manifest"],"validation":s["validated_prefix"],"launch":s["validation_launch"],"bootstrap":{"path":SNAP,"identity":identity(&snap)}}),
    )
}
fn terminal(unit: &str, id: &str) -> Result<Value> {
    let p = props(unit, "Id,ActiveState,MainPID,ControlPID,Job,ControlGroup")?;
    ensure!(
        p["Id"] == unit
            && p["ActiveState"] == "inactive"
            && p["MainPID"] == "0"
            && p["ControlPID"] == "0"
            && p["Job"].is_empty()
            && p["ControlGroup"].is_empty()
            && !Path::new("/sys/fs/cgroup/system.slice").join(unit).exists(),
        "native unit has not drained: {unit}"
    );
    let text = command(
        "/usr/bin/journalctl",
        &[
            "-q",
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={id}"),
            &format!("_BOOT_ID={BOOT}"),
            &format!("MESSAGE_ID={OK}"),
            &format!("MESSAGE_ID={FAIL}"),
        ],
    )?;
    let all = text
        .lines()
        .map(serde_json::from_str)
        .collect::<serde_json::Result<Vec<Value>>>()?;
    ensure!(
        all.len() == 1 && all[0]["MESSAGE_ID"] == OK && all[0]["INVOCATION_ID"] == id,
        "no unique successful native closure for {unit}"
    );
    Ok(all[0].clone())
}
fn custody() -> Result<Value> {
    let s = screen()?;
    let e = expected()?;
    let start = bound(&pinned(
        &root("PARK_START_1795850620491935487.json"),
        "bbc8e41b51ed9537437a430d9e53eeb8163f6e86cce070068cc0f190f5c44c2a",
    ))?;
    ensure!(
        start["unit"] == PARK
            && start["invocation"] == PARKID
            && start["source_identity"] == s["source_stat"]
            && start["command"][3] == "--spec-sha256"
            && start["command"][4] == e["park"]["sha256"],
        "different park"
    );
    let event = terminal(PARK, PARKID)?;
    let path = transport::custody_file(&e)?;
    let c = bound(&reference(&path)?)?;
    for k in [
        "manifest",
        "manifest_key",
        "manifest_sha256",
        "source",
        "length",
        "object_key",
        "sha256",
    ] {
        ensure!(c[k] == e[k], "custody mismatch {k}")
    }
    ensure!(
        c["remote_sha256_readback"] == true
            && c["local_source_revalidated"] == true
            && c["local_retirement_authorized"] == false
            && c["canonical_publication_authorized"] == false,
        "incomplete whole readback"
    );
    let remote = transport::remote(&e, None, 0, None)?;
    let fixed = json!({"park_start":pinned(&root("PARK_START_1795850620491935487.json"),"bbc8e41b51ed9537437a430d9e53eeb8163f6e86cce070068cc0f190f5c44c2a"),"native_terminal":event,"native_custody":reference(&path)?,"object_key":e["object_key"],"length":LENGTH,"object_etag":c["object_etag"],"manifest_sha256":e["manifest_sha256"],"whole_remote_readback":true});
    stable(&root("PARK_CUSTODY.json"), &fixed)?;
    Ok(json!({"custody":reference(&root("PARK_CUSTODY.json"))?,"authenticated_remote":remote}))
}
fn locked(p: &Path, dev: u64, ino: u64) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        p.canonicalize()? == p
            && m.nlink() == 1
            && (m.dev(), m.ino()) == (dev, ino)
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "mutation lock busy or changed {}",
        p.display()
    );
    Ok(f)
}
fn global() -> Result<File> {
    let p = Path::new(GLOBAL);
    let m = fs::symlink_metadata(p)?;
    ensure!(m.uid() == 0, "global owner");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    ensure!(
        f.metadata()?.ino() == m.ino() && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0,
        "global operation lock changed"
    );
    Ok(f)
}
fn local_locks() -> Result<Vec<File>> {
    Ok(vec![
        locked(Path::new(ELOCK), 64512, 100408634)?,
        locked(
            Path::new(
                "/var/lib/jetstreamer-root-sweep-epoch157-target3-20261014-v1/controller.lock",
            ),
            2304,
            2758491,
        )?,
        locked(
            Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock"),
            64512,
            101135013,
        )?,
        locked(&Path::new(HOLD).join("transition.lock"), 64512, 95818311)?,
    ])
}
fn check_hash(f: &mut File, expected: &str) -> Result<()> {
    use io::Seek;
    f.rewind()?;
    let mut h = Sha256::new();
    io::copy(f, &mut h)?;
    ensure!(
        format!("{:x}", h.finalize()) == expected,
        "local hash differs"
    );
    Ok(())
}
fn role() -> Result<(String, String)> {
    let group = fs::read_to_string("/proc/self/cgroup")?;
    let unit = group
        .trim()
        .rsplit('/')
        .next()
        .context("cgroup")?
        .to_string();
    let id = std::env::var("INVOCATION_ID")?;
    ensure!(id.len() == 32, "invocation");
    Ok((unit, id))
}
fn profile(phase: &str) -> Result<Value> {
    let (unit, id) = role()?;
    let r = bound(&pinned(
        &root(&format!("{}_ADMISSION.json", phase.to_uppercase())),
        &std::env::var("HORIZON157_ADMISSION_SHA")?,
    ))?;
    ensure!(
        r["unit"] == unit
            && r["phase"] == phase
            && r["operator_seal"] == ours()?
            && r["fits"] == true
            && r["resource_credit_bytes"] == 0
            && r["canonical_publication"] == false,
        "unmatched local admission"
    );
    let age = now()? as f64 - r["issued"].as_f64().context("issuance time")?;
    ensure!((0.0..=300.0).contains(&age), "stale entry");
    let c = fs::read_to_string("/proc/self/cgroup")?;
    let g =
        Path::new("/sys/fs/cgroup").join(c.trim().strip_prefix("0::/").context("kernel cgroup")?);
    ensure!(
        fs::read_to_string(g.join("memory.max"))?.trim() == num(&r, "memory_max")?.to_string()
            && fs::read_to_string(g.join("memory.swap.max"))?.trim() == "0",
        "bad memory cap"
    );
    let quota = fs::read_to_string(g.join("cpu.max"))?;
    let p = quota
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        p.len() == 2 && p[0] * 1_000_000 == num(&r, "cpu_micros")? * p[1],
        "bad CPU cap"
    );
    stable(
        &root(&format!("{}_NATIVE_ENTRY_{id}.json", phase.to_uppercase())),
        &json!({"unit":unit,"invocation":id,"admission":reference(&root(&format!("{}_ADMISSION.json",phase.to_uppercase())))?,"command":std::env::args().collect::<Vec<_>>(),"price":r["provider"]}),
    )?;
    Ok(r)
}
fn stamp_bound(p: &Path, original: &Value, renamed: bool) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    let mut v = identity(&m);
    if renamed {
        v["ctime_ns"] = original["ctime_ns"].clone();
    }
    ensure!(
        v == *original && m.is_file() && p.canonicalize()? == p,
        "changed original inode {}",
        p.display()
    );
    Ok(())
}
fn move_exact(a: &Path, b: &Path) -> Result<()> {
    let x = CString::new(a.as_os_str().as_encoded_bytes())?;
    let y = CString::new(b.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                x.as_ptr(),
                libc::AT_FDCWD,
                y.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "rename: {}",
        io::Error::last_os_error()
    );
    File::open(a.parent().context("parent")?)?.sync_all()?;
    Ok(())
}
fn retire() -> Result<Value> {
    let fit = profile("retire")?;
    let (unit, iid) = role()?;
    let s = screen()?;
    let e = expected()?;
    let fc = bound(&reference(&root("RESTORE_QUALIFICATION.json"))?)?;
    ensure!(
        fc["passed"] == true && fc["target"] == SRC && fc["operator_seal"] == ours()?,
        "missing qualified restore route"
    );
    let remote = custody()?;
    let _locks = local_locks()?;
    let src = Path::new(SRC);
    let q = src.with_file_name(".epoch157-lanej-retiring-4a4d4403");
    let original = &s["source_stat"];
    let retire = root("RETIRED.json");
    if retire.exists() {
        return reference(&retire);
    }
    let prior = preserved()?;
    let guard_before = consumers::census(Some(&unit))?;
    let intent = root("MOVE_INTENT.json");
    if !intent.exists() {
        stamp_bound(src, original, false)?;
        ensure!(!q.exists(), "quarantine occupied");
        receipt(
            &intent,
            &json!({"source":SRC,"sha256":HASH,"target":q,"before":available()?.0,"preserved":prior,"custody":remote["custody"],"entry":reference(&root(&format!("RETIRE_NATIVE_ENTRY_{iid}.json")))?}),
        )?;
    }
    let iref = reference(&intent)?;
    let i = bound(&iref)?;
    ensure!(
        i["source"] == SRC
            && i["target"] == json!(q)
            && i["sha256"] == HASH
            && i["custody"] == remote["custody"],
        "conflicting retirement intent"
    );
    let unlink = root("UNLINK_INTENT.json");
    if src.try_exists()? || q.try_exists()? {
        let (p, renamed) = if src.try_exists()? {
            ensure!(
                !q.try_exists()? && !unlink.try_exists()?,
                "ambiguous pending move"
            );
            (src, false)
        } else {
            (q.as_path(), true)
        };
        stamp_bound(p, original, renamed)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NOATIME)
            .open(p)?;
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "source file busy"
        );
        check_hash(&mut file, HASH)?;
        stamp_bound(p, original, renamed)?;
        // Serialize the last reference census and namespace transition with fleet launches.
        let _op = global()?;
        let last = consumers::census(Some(&unit))?;
        ensure!(preserved()? == prior, "preserved identities changed");
        if !renamed {
            move_exact(src, &q)?
        }
        stamp_bound(&q, original, true)?;
        let check = consumers::kernel(Some(&unit))?;
        ensure!(
            !src.try_exists()? && file.metadata()?.ino() == fs::symlink_metadata(&q)?.ino(),
            "different quarantine"
        );
        if !unlink.try_exists()? {
            receipt(
                &unlink,
                &json!({"intent":iref,"native":iid,"rechecked":last,"kernel_after_move":check,"source_hash":HASH,"post_rename_identity":identity(&file.metadata()?)}),
            )?;
        }
        ensure!(
            bound(&reference(&unlink)?)?["intent"] == iref,
            "conflicting unlink marker"
        );
        stamp_bound(&q, original, true)?;
        fs::remove_file(&q)?;
        File::open(src.parent().context("source parent")?)?.sync_all()?;
        ensure!(file.metadata()?.nlink() == 0, "retired inode still linked");
        drop(file);
    }
    ensure!(
        !src.try_exists()?
            && !q.try_exists()?
            && bound(&reference(&unlink)?)?["intent"] == iref
            && preserved()? == prior,
        "ambiguous removal"
    );
    let after = available()?.0;
    let before = num(&i, "before")?;
    receipt(
        &retire,
        &json!({"epoch":157,"source":SRC,"sha256":e["sha256"],"removed_original_inode":original["inode"],"allocated_bytes_removed":ALLOC,"available_before":before,"available_after":after,"measured_net_free_bytes":i128::from(after)-i128::from(before),"conservative_capacity_bytes":ALLOC.min(after.saturating_sub(before)),"admission":fit["provider"],"move":iref,"unlink":reference(&unlink)?,"restoration":reference(&root("RESTORE_QUALIFICATION.json"))?,"custody":remote["custody"],"initial_census":guard_before,"preserved":prior,"canonical_publication":false}),
    )
}
fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let result = match a.as_slice() {
        [c] if c == "fixture" => {
            let f = profile("fixture")?;
            transport::fixture(&f)?
        }
        [c] if c == "census" => {
            let _ = profile("census")?;
            consumers::census(None)?
        }
        [c] if c == "custody" => {
            let _ = ours()?;
            custody()?
        }
        [c] if c == "retire" => retire()?,
        [c] if c == "restore" => {
            let q = profile("restore")?;
            let _ = local_locks()?;
            ensure!(root("RETIRED.json").is_file(), "missing private retirement");
            let e = expected()?;
            let _ = preserved()?;
            let _ = custody()?;
            let v = transport::restore_file(Path::new(SRC), &e, num(&q, "floor")?)?;
            stable(&root("RESTORED.json"), &v)?
        }
        _ => anyhow::bail!("expected fixture | census | custody | retire | restore"),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
