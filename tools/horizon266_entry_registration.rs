//! Read-only bridge from the original finite 266 controller to campaign consumers.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
pub const HANDOFF_SHA: &str = "1fd365a05f8f74c1456b1bfaf44199fd006afd6785d0161afca34fdf20e262d5";
const IID: &str = "09dcaaddbbc34f3eb5f81c0a4f8a909e";
const PID: u64 = 2791171;
pub const UNIT: &str = "horizon-qualify-266-general-v1.service";
pub const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-266-general-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon266-native-full-v165-a2";
const GUARD: &str = "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d";
pub const SCHEMA: &str = "horizon266-first-useful-native-entry-replay-v1";
pub const NODE: &str =
    "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-node";
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("266 registration {k}"))
}
fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("266 registration {k}"))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn read(b: &Value, loc: &Path, immutable: bool) -> Result<Value> {
    let p = Path::new(text(b, "path")?);
    let digest = text(b, "sha256")?;
    ensure!(
        p == loc
            && p.starts_with("/var/lib/jetstreamer")
            && p.canonicalize()? == p
            && hex(digest, 64),
        "266 proof path"
    );
    for a in p.ancestors().skip(1) {
        let m = fs::symlink_metadata(a)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "266 proof parent"
        );
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    let id = |m: fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.uid(),
            m.mode(),
            m.nlink(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let m = f.metadata()?;
    let current = id(fs::symlink_metadata(p)?);
    ensure!(
        m.is_file()
            && id(m) == current
            && current.2 <= 16 << 20
            && current.3 == 0
            && current.4 & (if immutable { 0o222 } else { 0o022 }) == 0
            && current.5 == 1,
        "266 proof custody"
    );
    let mut bytes = Vec::new();
    (&f).take((16 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == current.2
            && id(f.metadata()?) == current
            && id(fs::symlink_metadata(p)?) == current
            && format!("{:x}", Sha256::digest(&bytes)) == digest,
        "266 proof changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn tuple(iid: &str) -> Result<Value> {
    ensure!(hex(iid, 32), "invalid 266 pilot IID");
    Ok(
        json!({"range":"266-266","controller_unit":UNIT,"expected_controller_invocation_id":iid,
        "producer_unit":UNIT,"expected_producer_invocation_id":iid,"scratch_path":ROOT,"worker_executable_basename":"historical-worker"}),
    )
}
fn markers(v: &Value) -> Result<()> {
    let point = |k: &str| -> Result<([u64; 4], &str)> {
        let p = &v[k];
        let a = p[0].as_array().context("266 progress counters")?;
        let cur = p[1]
            .as_str()
            .filter(|s| !s.is_empty())
            .context("266 progress cursor")?;
        ensure!(a.len() == 4, "266 counter width");
        let mut n = [0; 4];
        for (out, src) in n.iter_mut().zip(a) {
            *out = src.as_u64().context("266 progress integer")?;
        }
        Ok((n, cur))
    };
    let (a, ca) = point("first")?;
    let (b, cb) = point("last")?;
    ensure!(
        ca != cb
            && a[0] < b[0]
            && 114910768 < a[1]
            && a[1] < b[1]
            && b[1] <= 115343999
            && a[2] < b[2]
            && a[3] <= b[3],
        "unproven epoch 266 replay"
    );
    Ok(())
}
pub fn validate(b: &Value) -> Result<Value> {
    let path = Path::new(text(b, "path")?);
    let state = Path::new(STATE);
    ensure!(
        path.file_name().is_some_and(|n| n == "first-entries.json")
            && path.parent().and_then(Path::parent) == Some(state),
        "266 first-entry namespace"
    );
    let e = read(b, path, true)?;
    let iid = text(&e, "iid")?;
    let pid = num(&e, "pid")?;
    ensure!(
        iid == IID
            && pid == PID
            && e["schema"] == SCHEMA
            && e["unit"] == UNIT
            && e["entry_replay_proven"] == true
            && e["publication_authorized"] == false
            && e["full_epoch_qualified"] == false,
        "266 entry witness"
    );
    markers(&e)?;
    let proc = e["processes"].as_object().context("266 mapped replay")?;
    let parent = proc
        .get(&pid.to_string())
        .context("266 original process missing")?;
    ensure!(
        (2..=8).contains(&proc.len())
            && parent["role"] == "node"
            && parent["parent"] == 1
            && parent["image"] == NODE
            && proc.values().filter(|r| r["role"] == "worker").count() == 1,
        "266 entry tree"
    );
    let mut registration = original(&e["handoff"])?;
    ensure!(
        num(&registration, "guard_end_us")?
            < e["first"][0][0].as_u64().context("first replay clock")?,
        "entries preceded original guard release"
    );
    registration["entries"] = b.clone();
    Ok(registration)
}
fn original(b: &Value) -> Result<Value> {
    let state = Path::new(STATE);
    let pilot = state.join("pilot");
    let iid = IID;
    let pid = PID;
    ensure!(b["sha256"] == HANDOFF_SHA, "another 266 handoff");
    let h = read(b, &pilot.join("handoff.json"), true)?;
    ensure!(
        h["schema"] == "horizon266-first-full-native-node-handoff-v1"
            && h["iid"] == iid
            && h["unit"] == UNIT
            && h["pid"] == pid
            && h["entry_replay_proven"] == false
            && h["publication_authorized"] == false,
        "266 original handoff"
    );
    let s = read(&h["spec"], &pilot.join("spec.json"), true)?;
    let rpath = Path::new(text(&s["review"], "path")?);
    let review = read(&s["review"], rpath, true)?;
    let fit = read(&h["held_fit"], &pilot.join("held-fit.json"), true)?;
    let token = read(&h["token"], &pilot.join(format!("token-{iid}.json")), true)?;
    let journal = read(
        &token["guard_pid1"],
        &pilot.join("first-guard-pid1.json"),
        true,
    )?;
    let gp = read(&h["guard"], &pilot.join("guard-plan.json"), true)?;
    let gid = journal["pid1"]
        .get(0)
        .and_then(|r| r["INVOCATION_ID"].as_str())
        .context("266 guard IID")?;
    ensure!(hex(gid, 32), "266 first guard IID");
    let sample = read(
        &h["first_guard"],
        &pilot.join("receipts").join(format!("sample-{gid}.json")),
        false,
    )?;
    ensure!(
        s["root"] == ROOT
            && s["unit"] == UNIT
            && s["mode"] == "pilot"
            && s["argv"][0] == NODE
            && review["Main_accepted"] == true
            && review["root"] == STATE
            && review["producer_epoch"] == 266
            && review["publication_authorized"] == false
            && review["schema"] == "horizon266-first-entry-native-review-v1"
            && fit["fleet"] == review["fleet"]
            && fit["schema"] == "horizon266-native-full-capacity-election-v1"
            && fit["winner"]["fits"] == true
            && fit["winner"]["root"] == s["root_cap"]
            && gp["worker_root"] == ROOT
            && gp["unit"] == UNIT
            && gp["invocation_id"] == iid
            && num(&gp, "minimum_free_bytes")? >= num(&fit, "protected_floor")?
            && token["iid"] == iid
            && token["pid"] == pid
            && token["timer_iid"] == h["timer"]
            && hex(text(&h, "timer")?, 32)
            && ["spec", "guard", "first_guard", "held_fit"]
                .iter()
                .all(|k| token[*k] == h[*k])
            && sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["producer"]["pid"] == pid
            && sample["producer_invocation_id"] == iid
            && sample["guard_invocation_id"] == gid
            && sample["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && sample["guard_sha256"] == GUARD
            && sample["plan_sha256"] == h["guard"]["sha256"]
            && sample["plan"] == h["guard"]["path"]
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && sample["root_physical_observation"].is_object(),
        "266 original admission, first firing or release"
    );
    for (mode, sha) in [
        (
            "qa-disk",
            "7c1433602af9934b792c3ea1e2ae190d69573c83625940e84ec77011200e47af",
        ),
        (
            "qa-memory",
            "2dc8c837ca301d494f936762472690b71ac0ee44dbbfb401be04bf53e4f77086",
        ),
    ] {
        let qp = state.join(mode).join("qualification.json");
        let qb = json!({"path":qp,"sha256":sha});
        let q = read(&qb, &qp, true)?;
        ensure!(
            q["schema"] == "horizon266-native-full-stop-qualification-v1"
                && q["mode"] == mode
                && q["drained"] == true
                && q["entry_replay"] == false
                && q["iid"] != iid
                && q["image"] == review["controller_image"]
                && hex(text(&q, "iid")?, 32),
            "266 missing pressure qualification {mode}"
        );
        let sample_path = Path::new(text(&q["first_guard"], "path")?);
        ensure!(
            sample_path.parent() == Some(state.join(mode).join("receipts").as_path()),
            "266 QA firing path"
        );
        let firing = read(&q["first_guard"], sample_path, mode == "qa-memory")?;
        ensure!(
            (mode == "qa-disk"
                && firing["trip_reason"] == "filesystem-floor"
                && firing["guard_sha256"] == GUARD
                && firing["producer_invocation_id"] == q["iid"])
                || (mode == "qa-memory"
                    && firing["reason"] == "cgroup-memory-pressure"
                    && firing["iid"] == q["iid"]),
            "wrong 266 first pressure stop"
        );
    }
    let image = text(&review["controller_image"], "path")?;
    let target = pilot.join("spec.json");
    let exec = format!(
        "{{ path={image} ; argv[]={image} epoch266-full wait pilot {} {}",
        target.display(),
        text(&h["spec"], "sha256")?
    );
    Ok(
        json!({"guard_end_us":num(&journal,"last_monotonic_us")?,"tuple":tuple(iid)?,"pid":pid,"iid":iid,"handoff":b,"guard":h["first_guard"],"plan":h["guard"],
        "fleet":review["fleet"],"spec":h["spec"],"timer":h["timer"],"cpus":fit["cpus"],"memory":fit["winner"]["memory"],
        "root_cap":s["root_cap"],"release_time":num(&token,"expires")?.checked_sub(25).context("266 release clock")?,"expected_command":exec}),
    )
}
pub fn mapped_node(pid: u64) -> Result<()> {
    let p = PathBuf::from(format!("/proc/{pid}/exe"));
    let actual = fs::metadata(&p)?;
    let expected = fs::symlink_metadata(NODE)?;
    ensure!(
        fs::read_link(p)? == Path::new(NODE)
            && actual.dev() == expected.dev()
            && actual.ino() == expected.ino()
            && expected.uid() == 0
            && expected.mode() & 0o222 == 0
            && expected.is_file(),
        "266 node image replaced"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "original epoch 266 native handoff and both retained pressure qualifications"]
    fn authentic_original_guard_release_and_both_pressure_qualifications() {
        let p = Path::new(STATE).join("pilot/handoff.json");
        let mut b = json!({"path":p,"sha256":HANDOFF_SHA});
        let r = original(&b).unwrap();
        assert_eq!(r["pid"], PID);
        assert_eq!(r["iid"], IID);
        assert_eq!(r["memory"], 176000000000u64);
        assert_eq!(r["root_cap"], 112u64 << 30);
        assert_eq!(
            r["fleet"]["sha256"],
            "8be8c0b73a88aad4935817e5787161a857d008194d54b11cfb7900639b562241"
        );
        b["sha256"] = json!("0".repeat(64));
        assert!(original(&b).is_err());
    }
    #[test]
    fn requires_actual_progress_and_distinct_receipts() {
        let mut v =
            json!({"first":[[124,114911100,52,11],"first"],"last":[[226,114911207,63,15],"last"]});
        markers(&v).unwrap();
        v["last"][1] = json!("first");
        assert!(markers(&v).is_err());
        v["last"][1] = json!("last");
        v["last"][0][2] = json!(52);
        assert!(markers(&v).is_err());
        assert!(tuple("not an invocation id").is_err());
    }
}
