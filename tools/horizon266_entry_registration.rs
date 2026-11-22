//! Bind finite epoch 228 and 266 replays to their original startup receipts.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
pub struct Pilot {
    pub epoch: u64,
    pub unit: &'static str,
    pub root: &'static str,
    pub schema: &'static str,
    pub node: &'static str,
    state: &'static str,
    guard: &'static str,
    iid: &'static str,
    pid: u64,
    handoff_sha: &'static str,
    bootstrap: u64,
    target: u64,
    qa_disk: &'static str,
    qa_memory: &'static str,
}
pub const FULL266: Pilot = Pilot {
    epoch: 266,
    unit: "horizon-qualify-266-general-v1.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-266-general-v1",
    schema: "horizon266-first-useful-native-entry-replay-v1",
    node: "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-node",
    state: "/var/lib/jetstreamer/horizon266-native-full-v165-a2",
    guard: "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d",
    iid: "09dcaaddbbc34f3eb5f81c0a4f8a909e",
    pid: 2791171,
    handoff_sha: "1fd365a05f8f74c1456b1bfaf44199fd006afd6785d0161afca34fdf20e262d5",
    bootstrap: 114910768,
    target: 115343999,
    qa_disk: "7c1433602af9934b792c3ea1e2ae190d69573c83625940e84ec77011200e47af",
    qa_memory: "2dc8c837ca301d494f936762472690b71ac0ee44dbbfb401be04bf53e4f77086",
};
pub const FULL228: Pilot = Pilot {
    epoch: 228,
    unit: "horizon-qualify-228-demotion-root-tail-16d4b158-v1.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-228-demotion-root-tail-v1",
    schema: "horizon228-first-useful-native-entry-replay-v1",
    node: "/var/lib/jetstreamer/horizon228-demotion-parent-natural-f797454e-v165-v1-qualified/parent",
    state: "/var/lib/jetstreamer/horizon228-native-root-tail-v166-a1",
    guard: "98ae85499fd21fa294104a1ff05c21dc155c9aa14ea10a70a0b29302d853dbfb",
    iid: "5566869f329b46309aa8a2ea8f46047a",
    pid: 2819393,
    handoff_sha: "da3fdea0fa6f6682daa741e4c72d5f3a81d6bd420743d5df70c46d40b6319752",
    bootstrap: 98495291,
    target: 98928278,
    qa_disk: "7601c423f259baf6e9cddbe5417c77288566d383bb739bc2b3a78eedda320c0c",
    qa_memory: "be6b2fa7dde8ec4242766ce6e3844c78313ef1973ae62295083c330f6d563f7e",
};
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("entry registration {k}"))
}
fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("entry registration {k}"))
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
        "entry proof path"
    );
    for a in p.ancestors().skip(1) {
        let m = fs::symlink_metadata(a)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "entry proof parent"
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
        "entry proof custody"
    );
    let mut bytes = Vec::new();
    (&f).take((16 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == current.2
            && id(f.metadata()?) == current
            && id(fs::symlink_metadata(p)?) == current
            && format!("{:x}", Sha256::digest(&bytes)) == digest,
        "entry proof changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
impl Pilot {
    pub fn tuple(&self, iid: &str) -> Result<Value> {
        ensure!(hex(iid, 32), "invalid pilot invocation");
        Ok(
            json!({"range":format!("{0}-{0}",self.epoch),"controller_unit":self.unit,"expected_controller_invocation_id":iid,
        "producer_unit":self.unit,"expected_producer_invocation_id":iid,"scratch_path":self.root,"worker_executable_basename":"historical-worker"}),
        )
    }
    fn markers(&self, v: &Value) -> Result<()> {
        let point = |k: &str| -> Result<([u64; 4], &str)> {
            let p = &v[k];
            let a = p[0].as_array().context("pilot progress counters")?;
            let cur = p[1]
                .as_str()
                .filter(|s| !s.is_empty())
                .context("pilot progress cursor")?;
            ensure!(a.len() == 4, "pilot counter width");
            let mut n = [0; 4];
            for (out, src) in n.iter_mut().zip(a) {
                *out = src.as_u64().context("pilot progress integer")?;
            }
            Ok((n, cur))
        };
        let (a, ca) = point("first")?;
        let (b, cb) = point("last")?;
        ensure!(
            ca != cb
                && a[0] < b[0]
                && self.bootstrap < a[1]
                && a[1] < b[1]
                && b[1] <= self.target
                && (self.epoch != 228 || a[2] > 0)
                && a[2] < b[2]
                && a[3] <= b[3],
            "unproven epoch pilot replay"
        );
        Ok(())
    }
    pub fn validate(&self, b: &Value) -> Result<Value> {
        let path = Path::new(text(b, "path")?);
        let state = Path::new(self.state);
        ensure!(
            path.file_name().is_some_and(|n| n == "first-entries.json")
                && path.parent().and_then(Path::parent) == Some(state),
            "pilot first-entry namespace"
        );
        let e = read(b, path, true)?;
        let iid = text(&e, "iid")?;
        let pid = num(&e, "pid")?;
        ensure!(
            iid == self.iid
                && pid == self.pid
                && e["schema"] == self.schema
                && e["unit"] == self.unit
                && e["entry_replay_proven"] == true
                && e["publication_authorized"] == false
                && e["full_epoch_qualified"] == false,
            "pilot entry witness"
        );
        self.markers(&e)?;
        let proc = e["processes"].as_object().context("pilot mapped replay")?;
        let parent = proc
            .get(&pid.to_string())
            .context("pilot original process missing")?;
        ensure!(
            (2..=8).contains(&proc.len())
                && (self.epoch != 228 || proc.len() == 2)
                && parent["role"] == "node"
                && parent["parent"] == 1
                && parent["image"] == self.node
                && proc.values().filter(|r| r["role"] == "worker").count() == 1,
            "pilot entry tree"
        );
        if self.epoch == 228 {
            let worker = proc
                .get("2819639")
                .context("original epoch 228 Bank worker missing")?;
            let image = Path::new(text(worker, "image")?);
            ensure!(
                worker["role"] == "worker"
                    && worker["parent"] == self.pid
                    && image.starts_with(Path::new(self.root).join("scratch"))
                    && image.ends_with("bound-worker/historical-worker")
                    && num(parent, "device")? > 0
                    && num(parent, "inode")? > 0
                    && num(worker, "device")? > 0
                    && num(worker, "inode")? > 0
                    && num(worker, "start_ticks")? >= num(parent, "start_ticks")?,
                "wrong epoch 228 Bank child"
            );
        }
        let mut registration = self.original(&e["handoff"])?;
        ensure!(
            num(&registration, "guard_end_us")?
                < e["first"][0][0].as_u64().context("first replay clock")?,
            "entries preceded original guard release"
        );
        registration["entries"] = b.clone();
        Ok(registration)
    }
    fn original(&self, b: &Value) -> Result<Value> {
        let state = Path::new(self.state);
        let pilot = state.join("pilot");
        let iid = self.iid;
        let pid = self.pid;
        ensure!(b["sha256"] == self.handoff_sha, "another pilot handoff");
        let h = read(b, &pilot.join("handoff.json"), true)?;
        ensure!(
            h["schema"] == format!("horizon{}-first-full-native-node-handoff-v1", self.epoch)
                && h["iid"] == iid
                && h["unit"] == self.unit
                && h["pid"] == pid
                && h["entry_replay_proven"] == false
                && h["publication_authorized"] == false,
            "pilot original handoff"
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
            .context("pilot guard invocation")?;
        ensure!(hex(gid, 32), "pilot first guard invocation");
        let sample = read(
            &h["first_guard"],
            &pilot.join("receipts").join(format!("sample-{gid}.json")),
            false,
        )?;
        ensure!(
            s["root"] == self.root
                && s["unit"] == self.unit
                && s["mode"] == "pilot"
                && s["argv"][0] == self.node
                && review["Main_accepted"] == true
                && review["root"] == self.state
                && review["producer_epoch"] == self.epoch
                && review["publication_authorized"] == false
                && review["schema"]
                    == format!("horizon{}-first-entry-native-review-v1", self.epoch)
                && fit["fleet"] == review["fleet"]
                && fit["schema"]
                    == format!("horizon{}-native-full-capacity-election-v1", self.epoch)
                && fit["winner"]["fits"] == true
                && fit["winner"]["root"] == s["root_cap"]
                && gp["worker_root"] == self.root
                && gp["unit"] == self.unit
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
                && sample["producer"]["cgroup"] == format!("/system.slice/{}", self.unit)
                && sample["guard_sha256"] == self.guard
                && sample["plan_sha256"] == h["guard"]["sha256"]
                && sample["plan"] == h["guard"]["path"]
                && sample["producer_stop_enabled"] == true
                && sample["trip_reason"].is_null()
                && sample["root_physical_observation"].is_object(),
            "pilot original admission, first firing or release"
        );
        for (mode, sha) in [("qa-disk", self.qa_disk), ("qa-memory", self.qa_memory)] {
            let qp = state.join(mode).join("qualification.json");
            let qb = json!({"path":qp,"sha256":sha});
            let q = read(&qb, &qp, true)?;
            ensure!(
                q["schema"] == format!("horizon{}-native-full-stop-qualification-v1", self.epoch)
                    && q["mode"] == mode
                    && q["drained"] == true
                    && q["entry_replay"] == false
                    && q["iid"] != iid
                    && q["image"] == review["controller_image"]
                    && hex(text(&q, "iid")?, 32),
                "pilot missing pressure qualification {mode}"
            );
            let sample_path = Path::new(text(&q["first_guard"], "path")?);
            ensure!(
                sample_path.parent() == Some(state.join(mode).join("receipts").as_path()),
                "pilot QA firing path"
            );
            let firing = read(&q["first_guard"], sample_path, mode == "qa-memory")?;
            ensure!(
                (mode == "qa-disk"
                    && firing["trip_reason"] == "filesystem-floor"
                    && firing["guard_sha256"] == self.guard
                    && firing["producer_invocation_id"] == q["iid"])
                    || (mode == "qa-memory"
                        && firing["reason"] == "cgroup-memory-pressure"
                        && firing["iid"] == q["iid"]),
                "wrong pilot first pressure stop"
            );
        }
        let image = text(&review["controller_image"], "path")?;
        let target = pilot.join("spec.json");
        let exec = format!(
            "{{ path={image} ; argv[]={image} epoch{}-full wait pilot {} {}",
            self.epoch,
            target.display(),
            text(&h["spec"], "sha256")?
        );
        Ok(
            json!({"guard_end_us":num(&journal,"last_monotonic_us")?,"tuple":self.tuple(iid)?,"pid":pid,"iid":iid,"handoff":b,"guard":h["first_guard"],"plan":h["guard"],
        "fleet":review["fleet"],"spec":h["spec"],"timer":h["timer"],"cpus":fit["cpus"],"memory":fit["winner"]["memory"],
        "root_cap":s["root_cap"],"release_time":num(&token,"expires")?.checked_sub(25).context("pilot release clock")?,"expected_command":exec}),
        )
    }
    pub fn mapped_node(&self, pid: u64) -> Result<()> {
        let p = PathBuf::from(format!("/proc/{pid}/exe"));
        let actual = fs::metadata(&p)?;
        let expected = fs::symlink_metadata(self.node)?;
        ensure!(
            fs::read_link(p)? == Path::new(self.node)
                && actual.dev() == expected.dev()
                && actual.ino() == expected.ino()
                && expected.uid() == 0
                && expected.mode() & 0o222 == 0
                && expected.is_file(),
            "pilot node image replaced"
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "original epoch 266 native handoff and both retained pressure qualifications"]
    fn authentic_original_guard_release_and_both_pressure_qualifications() {
        let p = Path::new(FULL266.state).join("pilot/handoff.json");
        let mut b = json!({"path":p,"sha256":FULL266.handoff_sha});
        let r = FULL266.original(&b).unwrap();
        assert_eq!(r["pid"], FULL266.pid);
        assert_eq!(r["iid"], FULL266.iid);
        assert_eq!(r["memory"], 176000000000u64);
        assert_eq!(r["root_cap"], 112u64 << 30);
        assert_eq!(
            r["fleet"]["sha256"],
            "8be8c0b73a88aad4935817e5787161a857d008194d54b11cfb7900639b562241"
        );
        b["sha256"] = json!("0".repeat(64));
        assert!(FULL266.original(&b).is_err());
    }
    #[test]
    #[ignore = "requires the original root-owned epoch 228 pilot QA, release and handoff"]
    fn original_228_guard_and_terminal_qa() {
        let b = json!({"path":Path::new(FULL228.state).join("pilot/handoff.json"),"sha256":FULL228.handoff_sha});
        let r = FULL228.original(&b).unwrap();
        assert_eq!(r["pid"], 2819393);
        assert_eq!(r["memory"], 120000000000u64);
        assert_eq!(r["root_cap"], 112u64 << 30);
        assert_eq!(
            r["fleet"]["sha256"],
            "ed624ffec8cfe447b9830aab6bd62bb1a0b1e6ff58a0776397d61cc48e8ba7c0"
        );
        assert!(FULL266.original(&b).is_err());
    }
    #[test]
    fn registered_228_requires_positive_original_entry_delta_and_bounded_slots() {
        let mut e = json!({"first":[[420,98496001,70,100],"a"],"last":[[440,98496020,82,101],"b"]});
        FULL228.markers(&e).unwrap();
        assert!(FULL266.markers(&e).is_err());
        e["last"][0][2] = json!(70);
        assert!(FULL228.markers(&e).is_err());
        e["last"][0][2] = json!(82);
        e["last"][0][1] = json!(98928279);
        assert!(FULL228.markers(&e).is_err());
    }
    #[test]
    fn requires_actual_progress_and_distinct_receipts() {
        let mut v =
            json!({"first":[[124,114911100,52,11],"first"],"last":[[226,114911207,63,15],"last"]});
        FULL266.markers(&v).unwrap();
        v["last"][1] = json!("first");
        assert!(FULL266.markers(&v).is_err());
        v["last"][1] = json!("last");
        v["last"][0][2] = json!(52);
        assert!(FULL266.markers(&v).is_err());
        assert!(FULL266.tuple("not an invocation id").is_err());
    }
}
