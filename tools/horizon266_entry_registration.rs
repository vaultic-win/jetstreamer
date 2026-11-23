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
#[derive(Copy, Clone)]
struct Pins<'a> {
    iid: &'a str,
    pid: u64,
    handoff_sha: &'a str,
    qa_disk: &'a str,
    qa_memory: &'a str,
}
pub struct Pilot {
    pub epoch: u64,
    pub unit: &'static str,
    pub root: &'static str,
    pub schema: &'static str,
    pub node: &'static str,
    state: &'static str,
    guard: &'static str,
    bootstrap: u64,
    target: u64,
    fixed: Option<Pins<'static>>,
}
pub const FULL266: Pilot = Pilot {
    epoch: 266,
    unit: "horizon-qualify-266-general-v1.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-266-general-v1",
    schema: "horizon266-first-useful-native-entry-replay-v1",
    node: "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-node",
    state: "/var/lib/jetstreamer/horizon266-native-full-v165-a2",
    guard: "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d",
    bootstrap: 114910768,
    target: 115343999,

    fixed: Some(Pins {
        iid: "09dcaaddbbc34f3eb5f81c0a4f8a909e",
        pid: 2791171,
        handoff_sha: "1fd365a05f8f74c1456b1bfaf44199fd006afd6785d0161afca34fdf20e262d5",
        qa_disk: "7c1433602af9934b792c3ea1e2ae190d69573c83625940e84ec77011200e47af",
        qa_memory: "2dc8c837ca301d494f936762472690b71ac0ee44dbbfb401be04bf53e4f77086",
    }),
};
pub const FULL228: Pilot = Pilot {
    epoch: 228,
    unit: "horizon-qualify-228-demotion-root-tail-16d4b158-v1.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-228-demotion-root-tail-v1",
    schema: "horizon228-first-useful-native-entry-replay-v1",
    node: "/var/lib/jetstreamer/horizon228-demotion-parent-natural-f797454e-v165-v1-qualified/parent",
    state: "/var/lib/jetstreamer/horizon228-native-root-tail-v166-a1",
    guard: "98ae85499fd21fa294104a1ff05c21dc155c9aa14ea10a70a0b29302d853dbfb",
    bootstrap: 98495291,
    target: 98928278,

    fixed: Some(Pins {
        iid: "5566869f329b46309aa8a2ea8f46047a",
        pid: 2819393,
        handoff_sha: "da3fdea0fa6f6682daa741e4c72d5f3a81d6bd420743d5df70c46d40b6319752",
        qa_disk: "7601c423f259baf6e9cddbe5417c77288566d383bb739bc2b3a78eedda320c0c",
        qa_memory: "be6b2fa7dde8ec4242766ce6e3844c78313ef1973ae62295083c330f6d563f7e",
    }),
};
pub const SUCCESSOR266: Pilot = Pilot {
    epoch: 266,
    unit: "horizon-qualify-266-instructions-2789f821-v169.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v169",
    schema: "horizon266-instruction-successor-entry-registration-v1",
    node: "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node",
    state: "/var/lib/jetstreamer/horizon266-instructions-2789f821-v169-control",
    guard: FULL266.guard,
    bootstrap: 114910768,
    target: 115343999,
    fixed: None,
};
pub const TURNOVER266: Pilot = Pilot {
    unit: "horizon-qualify-266-instructions-2789f821-v194.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v194",
    state: "/var/lib/jetstreamer/horizon266-instructions-2789f821-v194-control",
    ..SUCCESSOR266
};

pub const BOUNDED266: Pilot = Pilot {
    unit: "horizon-qualify-266-capped-bounded-v207.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-266-capped-bounded-v207",
    state: "/var/lib/jetstreamer/horizon266-capped-bounded-v207-control",
    node: SUCCESSOR266.node,
    fixed: Some(Pins {
        iid: "39999fd278dd40c18310a3d6c10c4e21",
        pid: 3451480,
        handoff_sha: "28ce08fdee6af90959a2df6b5495ec6092384d0b973bdf90755dbc8baf4d9b04",
        qa_disk: "d41f93ca8633c11f1544c1d1fc0a0e69664d937f7a1b47ce2c88b8e6129c113e",
        qa_memory: "908f96e9757593520ef43b5321d45fc8cedb45d3d37ea843c5f7ccbc78d3095a",
    }),
    ..FULL266
};
pub const BOUNDED_RETRY266: Pilot = Pilot {
    unit: "horizon-qualify-266-capped-bounded-v210.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-266-capped-bounded-v210",
    state: "/var/lib/jetstreamer/horizon266-capped-bounded-v210-control",
    fixed: Some(Pins {
        iid: "1dd482d1481448debb4e9de11f2dc1f6",
        pid: 3483521,
        handoff_sha: "bc83d344e4537cc1c88245ff5dc76e973770c9891c6a1b5ffadf165f2dfad76c",
        qa_disk: "115a49820210a3d1ded3783a6697e20a0fc82adb653a60fcd30c3f8ca6767bf8",
        qa_memory: "8274396bed81b662e7ff29b6ff34f721e60cff14a5965a56cadde306f5db343f",
    }),
    ..BOUNDED266
};

pub fn instruction_profile(receipt: &Path) -> &'static Pilot {
    if receipt.starts_with(BOUNDED_RETRY266.state) {
        &BOUNDED_RETRY266
    } else if receipt.starts_with(BOUNDED266.state) {
        &BOUNDED266
    } else if receipt.starts_with(TURNOVER266.state) {
        &TURNOVER266
    } else {
        &SUCCESSOR266
    }
}
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
    Ok(serde_json::from_slice(&receipt_bytes(b, loc, immutable)?)?)
}
fn receipt_bytes(b: &Value, loc: &Path, immutable: bool) -> Result<Vec<u8>> {
    let p = Path::new(text(b, "path")?);
    let digest = text(b, "sha256")?;
    ensure!(p == loc && hex(digest, 64), "entry proof binding");
    let bytes = owned_bytes(p, immutable)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == digest,
        "entry proof digest"
    );
    Ok(bytes)
}
fn owned_bytes(p: &Path, immutable: bool) -> Result<Vec<u8>> {
    ensure!(
        p.starts_with("/var/lib/jetstreamer") && p.canonicalize()? == p,
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
            && id(fs::symlink_metadata(p)?) == current,
        "entry proof changed"
    );
    Ok(bytes)
}
impl Pilot {
    fn is_bounded(&self) -> bool {
        self.unit == BOUNDED266.unit || self.unit == BOUNDED_RETRY266.unit
    }

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
                && (self.fixed.is_some() || b[1] > 114912038)
                && (self.epoch != 228 || a[2] > 0)
                && a[2] < b[2]
                && a[3] <= b[3],
            "unproven epoch pilot replay"
        );
        Ok(())
    }
    pub fn validate(&self, b: &Value) -> Result<Value> {
        if let Some(pins) = self.fixed {
            return self.entries(b, pins);
        }
        let path = Path::new(text(b, "path")?);
        let dir = path
            .parent()
            .context("missing successor capture directory")?;
        ensure!(
            dir.parent() == Some(Path::new(self.state))
                && path.file_name().is_some_and(|n| n == "registration.json")
                && dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|s| s.strip_prefix("first-entries-"))
                    .is_some_and(|s| !s.starts_with('0') && s.parse::<u32>().is_ok_and(|n| n > 0)),
            "wrong successor registration location"
        );
        let r = read(b, path, true)?;
        ensure!(
            r["schema"] == self.schema
                && r["unit"] == self.unit
                && r["entry_replay_proven"] == true
                && r["publication_authorized"] == false
                && r["full_epoch_qualified"] == false
                && Path::new(text(&r["entries"], "path")?) == dir.join("first-entries.json"),
            "different successor receipt"
        );
        for (key, mode) in [("qa_disk", "qa-disk"), ("qa_memory", "qa-memory")] {
            ensure!(
                Path::new(text(&r[key], "path")?)
                    == Path::new(self.state).join(mode).join("qualification.json"),
                "different pressure receipt"
            );
        }
        let pins = Pins {
            iid: text(&r, "iid")?,
            pid: num(&r, "pid")?,
            handoff_sha: text(&r["handoff"], "sha256")?,
            qa_disk: text(&r["qa_disk"], "sha256")?,
            qa_memory: text(&r["qa_memory"], "sha256")?,
        };
        ensure!(
            hex(pins.iid, 32)
                && pins.iid != FULL266.fixed.context("original 266 registration")?.iid
                && pins.pid > 1,
            "different successor owner"
        );
        let native = read(&r["entries"], &dir.join("first-entries.json"), true)?;
        let journal = receipt_bytes(&r["journal"], &dir.join("command-0002.stdout"), false)?;
        self.original_progress(&native, &journal, pins)?;
        let proof = self.entries(&r["entries"], pins)?;
        ensure!(
            proof["handoff"] == r["handoff"],
            "substituted successor handoff"
        );
        Ok(proof)
    }
    fn original_progress(&self, e: &Value, raw: &[u8], pins: Pins<'_>) -> Result<()> {
        let mut matched = [false; 2];
        for line in std::str::from_utf8(raw)?.lines() {
            let row: Value = serde_json::from_str(line)?;
            for (n, key) in ["first", "last"].iter().enumerate() {
                let point = &e[*key];
                if row["__CURSOR"] != point[1] {
                    continue;
                }
                let stamp = text(&row, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
                let message = text(&row, "MESSAGE")?
                    .split_once("progress slot ")
                    .context("original progress row")?
                    .1;
                let (slot, target) = message
                    .split_whitespace()
                    .next()
                    .context("missing progress range")?
                    .split_once('/')
                    .context("invalid progress range")?;
                let counter = |k: &str| -> Result<u64> {
                    let mut hits = message.split_whitespace().filter_map(|w| w.strip_prefix(k));
                    let v = hits.next().context("missing progress count")?.parse()?;
                    ensure!(hits.next().is_none(), "repeated progress count");
                    Ok(v)
                };
                ensure!(
                    !matched[n]
                        && row["_BOOT_ID"] == "3b17d0055c3a4a0e8841da097e0957b5"
                        && row["_SYSTEMD_UNIT"] == self.unit
                        && row["_SYSTEMD_INVOCATION_ID"] == pins.iid
                        && row["_UID"] == "1000"
                        && text(&row, "_PID")?.parse::<u64>()? == pins.pid
                        && row["_EXE"] == self.node
                        && target.parse::<u64>()? == self.target
                        && point[0]
                            == json!([
                                stamp,
                                slot.parse::<u64>()?,
                                counter("txs=")?,
                                counter("accounts=")?
                            ]),
                    "different original progress source"
                );
                matched[n] = true;
            }
        }
        ensure!(matched == [true, true], "missing original progress cursors");
        Ok(())
    }
    fn entries(&self, b: &Value, pins: Pins<'_>) -> Result<Value> {
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
            iid == pins.iid
                && pid == pins.pid
                && e["schema"]
                    == format!("horizon{}-first-useful-native-entry-replay-v1", self.epoch)
                && e["unit"] == self.unit
                && e["entry_replay_proven"] == true
                && e["publication_authorized"] == false
                && e["full_epoch_qualified"] == false,
            "pilot entry witness"
        );
        self.markers(&e)?;
        if self.is_bounded() {
            let dir = state.join("bounded-first-entries");
            ensure!(
                path == dir.join("first-entries.json"),
                "different bounded capture"
            );
            let journal = dir.join("command-0002.stdout");
            self.original_progress(&e, &owned_bytes(&journal, false)?, pins)?;
        }
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
                    && worker["parent"] == pins.pid
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
        if self.fixed.is_none() || self.is_bounded() {
            let (_, worker) = proc
                .iter()
                .find(|(_, v)| v["role"] == "worker")
                .context("missing historical worker")?;
            let image = Path::new(text(worker, "image")?);
            ensure!(
                image.starts_with(Path::new(self.root).join("state"))
                    && image.ends_with("bound-worker/historical-worker")
                    && num(worker, "device")? > 0
                    && num(worker, "inode")? > 0
                    && num(parent, "device")? > 0
                    && num(parent, "inode")? > 0,
                "different successor worker mapping"
            );
        }
        let mut registration = self.original(&e["handoff"], pins)?;
        ensure!(
            num(&registration, "guard_end_us")?
                < e["first"][0][0].as_u64().context("first replay clock")?,
            "entries preceded original guard release"
        );
        registration["entries"] = b.clone();
        Ok(registration)
    }
    fn original(&self, b: &Value, pins: Pins<'_>) -> Result<Value> {
        let bounded = self.is_bounded();
        let retry = self.unit == BOUNDED_RETRY266.unit;
        let turnover = self.unit == TURNOVER266.unit;
        let election_schema = if turnover {
            "horizon266-closed-singleton-capacity-election-v1".to_owned()
        } else {
            format!("horizon{}-native-full-capacity-election-v1", self.epoch)
        };
        let state = Path::new(self.state);
        let pilot = state.join("pilot");
        let iid = pins.iid;
        let pid = pins.pid;
        ensure!(b["sha256"] == pins.handoff_sha, "another pilot handoff");
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
                && (if bounded {
                    h["held_fit"]["sha256"]
                        == if retry {
                            "d7f0b9e5b7cf032644c6f236ded65241b1a6db458e4ab8eaee203c42c469a0a4"
                        } else {
                            "c1f90f8f82ca19ee6679c9a30ce03c8296d8d4e450a16ab58b749bf5eb5ac47b"
                        }
                } else {
                    fit["schema"] == election_schema
                })
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
        let runtime = if bounded && !retry {
            &review["runtime_image"]
        } else {
            &review["controller_image"]
        };
        if bounded {
            ensure!(
                review["reservation"] == fit["reservation"]
                    && fit["reservation"]["sha256"]
                        == "273f914d9cfaf6078076998ba1eb7a49b1b50a33a561db4eebe9ebf12ed45bc8"
                    && fit["winner"]["root"] == 344997011456u64
                    && fit["winner"]["memory"] == 192000000000u64
                    && runtime["sha256"]
                        == if retry {
                            "0a583cccb8901d092984a0981791daace98acf7294378e3c3dbb9d4c5b0c1c29"
                        } else {
                            "79be3c4ba91dc629ca3efc0cfe07286873acd2667bd9c9925ba038d4cccf26e2"
                        }
                    && s["worker"]
                        == "/var/lib/jetstreamer/horizon266-capped-worker-package-v199-a1/jetstreamer-historical-worker-v1-8-11",
                "different bounded allocation or deployed worker"
            );
            if retry {
                let reservation = read(
                    &fit["reservation"],
                    &Path::new(BOUNDED266.state).join("reservation.json"),
                    true,
                )?;
                let assessment = state.join("successor-fit-2.json");
                let assessed = read(
                    &json!({"path":assessment,"sha256":"34cef8be9188fb133c626eeaa58014375487e6fbd72116f01b6b95295e1b16d8"}),
                    &assessment,
                    true,
                )?;
                let release = Path::new(
                    "/var/lib/jetstreamer/horizon266-v207-closed-growth-v210/release.json",
                );
                let closed = read(
                    &json!({"path":release,"sha256":"a4c097ded324c48c3c591c46c90f7baf6cb816405c1f6200ad0d1bcd3813600c"}),
                    release,
                    true,
                )?;
                ensure!(
                    rpath == state.join("review-2.json")
                        && reservation["issued"] == true
                        && assessed["issued"] == fit["reservation"]
                        && assessed["fleet"] == review["fleet"]
                        && assessed["terminal"] == closed["terminal"]
                        && closed["original"] == fit["reservation"]
                        && closed["same_reservation_only"] == true,
                    "bounded retry requires the closed original allocation and its reviewed assessment"
                );
            }
        } else if turnover {
            ensure!(
                pins.handoff_sha
                    == "fcab517e7281c8c1dde68c9e7f56cbabc294eff2154c181bdb72b1742170a4df"
                    && pins.qa_disk
                        == "a2f5a56df4c758d0c21e796de02b80d6516cd2de50b180eac41ead82d69d2cbf"
                    && pins.qa_memory
                        == "cb75f9c28e2c3ae53a013a9f0bbe58a10b118aea65a95d49a3443f8c1f504903"
                    && pins.iid == "41cf6e5a5cd54d57adc5eba3f0c0ecef"
                    && pins.pid == 3215067
                    && fit["capacity_basis"] == review["capacity_basis"]
                    && fit["winner"]["assigned_211"] == 177342177280u64
                    && fit["winner"]["retained_265"] == 128000000000u64
                    && fit["winner"]["root"] == 320u64 << 30,
                "different epoch 266 turnover award or release"
            );
        } else if self.fixed.is_none() {
            validate_successor(self, &review, &fit, &s)?;
        }
        for (mode, sha) in [("qa-disk", pins.qa_disk), ("qa-memory", pins.qa_memory)] {
            let qp = state.join(mode).join("qualification.json");
            let qb = json!({"path":qp,"sha256":sha});
            let q = read(&qb, &qp, true)?;
            ensure!(
                q["schema"] == format!("horizon{}-native-full-stop-qualification-v1", self.epoch)
                    && q["mode"] == mode
                    && q["drained"] == true
                    && q["entry_replay"] == false
                    && q["iid"] != iid
                    && q["image"] == *runtime
                    && hex(text(&q, "iid")?, 32),
                "pilot missing pressure qualification {mode}"
            );
            if self.fixed.is_none() {
                let suffix = if mode == "qa-disk" {
                    "qa-disk-a2"
                } else {
                    "qa-memory"
                };
                let generation = if turnover { "v194" } else { "v169" };
                ensure!(
                    q["unit"]
                        == format!(
                            "horizon-qualify-266-instructions-2789f821-{suffix}-{generation}.service"
                        )
                        && q["terminal"]["MainPID"] == "0"
                        && q["terminal"]["ControlGroup"] == ""
                        && q["terminal"]["NRestarts"] == "0",
                    "different successor pressure stop"
                );
            }
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
        let image = text(runtime, "path")?;
        let target = pilot.join("spec.json");
        let command = if retry {
            "epoch266-bounded-retry".to_owned()
        } else if bounded {
            "epoch266-bounded".to_owned()
        } else if turnover {
            "epoch266-turnover".to_owned()
        } else if self.fixed.is_none() {
            "epoch266-instructions".to_owned()
        } else {
            format!("epoch{}-full", self.epoch)
        };
        let exec = format!(
            "{{ path={image} ; argv[]={image} {command} wait pilot {} {}",
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
fn validate_successor(p: &Pilot, review: &Value, fit: &Value, spec: &Value) -> Result<()> {
    let old = FULL266.fixed.context("missing original 266 registration")?;
    let peer = FULL228.fixed.context("missing original 228 registration")?;
    let original = json!({"path":Path::new(FULL266.state).join("pilot/handoff.json"),"sha256":old.handoff_sha});
    let peer_hand = json!({"path":Path::new(FULL228.state).join("pilot/handoff.json"),"sha256":peer.handoff_sha});
    let assignment = json!({"from_original_invocation":old.iid,"assigned_to":p.unit,"producer_bytes":176000000000u64,
        "new_guard_bytes":1u64<<30,"new_controller_bytes":256u64<<20,"old_guard_retained":1u64<<30,
        "old_controller_retained":256u64<<20,"original_cold_residual":64u64<<20,"disk_credit":0});
    ensure!(
        review["controller_image"]
            == json!({"path":"/var/lib/jetstreamer/horizon266-instruction-controller-build-v169-a1-qualified/native-fit",
            "sha256":"c1891a419df5b5f6ed74912f3760c52bad383e93088ff5414932e28220a57ca4"})
            && review["qualified_build"]
                == json!({"path":"/home/ubuntu/.codex/diagnostics/horizon266-instruction-controller-build-v169-a1/completion.json","sha256":"7dd5b650da5a33e6fd1187fe34c0eb95d9b451edc469ba94c77158b561b6cde6"})
            && review["published_commit"] == "acbd2eb0833eebc6ee01f2948924ffbdf5ac28df"
            && review["selected_producer"]
                == json!({"path":"/home/ubuntu/.codex/diagnostics/horizon266-selected-producer-capability-v167-a2/qualification.json","sha256":"18c0e334c7c0c6861344b07c34d2fb982325f0d2605c640b55d72b4f31fb3618"})
            && review["bounded266_handoff"] == original
            && review["epoch228_handoff"] == peer_hand
            && review["epoch266_reassignment"] == assignment
            && fit["new_266_assignment"] == assignment
            && fit["concurrent_266"]["handoff"] == original
            && fit["concurrent_266"]["iid"] == old.iid
            && fit["concurrent_266"]["terminal_failure"]
                == json!({"path":"/home/ubuntu/.codex/diagnostics/horizon266-instruction-repair-v166-a1/terminal.json","sha256":"7445122e9ca61f7a7c46d7ca47140c63edb174c7e2fb97b56bff35bb7dd554ff"})
            && fit["live_228"]["handoff"] == peer_hand
            && fit["live_228"]["iid"] == peer.iid
            && fit["live_228"]["pid"] == peer.pid
            && fit["publication_authorized"] == false
            && fit["winner"]["memory"] == 176000000000u64
            && [128u64 << 30, 320u64 << 30].contains(&num(&fit["winner"], "root")?)
            && fit["cpus"] == json!([32, 33, 34, 35, 36, 37, 38, 39])
            && spec["argv"][0] == p.node,
        "successor review, failed original generation, peer or held award differs"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "reads the original bounded launch and both stopped QA workers"]
    fn bounded_writer_reopens_its_runtime_and_issued_booking() {
        for (pilot, command) in [
            (&BOUNDED266, "epoch266-bounded"),
            (&BOUNDED_RETRY266, "epoch266-bounded-retry"),
        ] {
            let p = instruction_profile(
                &Path::new(pilot.state).join("bounded-first-entries/first-entries.json"),
            );
            assert_eq!(p.unit, pilot.unit);
            let pins = p.fixed.unwrap();
            let h = json!({"path":Path::new(p.state).join("pilot/handoff.json"),"sha256":pins.handoff_sha});
            let proof = p.original(&h, pins).unwrap();
            assert_eq!(proof["memory"], 192000000000u64);
            assert!(
                proof["expected_command"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("{command} wait pilot"))
            );
            assert!(
                p.original(
                    &h,
                    Pins {
                        pid: pins.pid + 1,
                        ..pins
                    }
                )
                .is_err()
            );
            assert!(
                p.original(
                    &h,
                    Pins {
                        qa_disk: pins.qa_memory,
                        ..pins
                    }
                )
                .is_err()
            );
        }
    }
    #[test]
    #[ignore = "original admitted 320 GiB epoch 266 worker and stopped QA owners"]
    fn turnover_266_requires_its_original_owner_and_pressure_stops() {
        let pins = Pins {
            iid: "41cf6e5a5cd54d57adc5eba3f0c0ecef",
            pid: 3215067,
            handoff_sha: "fcab517e7281c8c1dde68c9e7f56cbabc294eff2154c181bdb72b1742170a4df",
            qa_disk: "a2f5a56df4c758d0c21e796de02b80d6516cd2de50b180eac41ead82d69d2cbf",
            qa_memory: "cb75f9c28e2c3ae53a013a9f0bbe58a10b118aea65a95d49a3443f8c1f504903",
        };
        let path = Path::new(TURNOVER266.state).join("pilot/handoff.json");
        let handoff = json!({"path":path,"sha256":pins.handoff_sha});
        let pilot = instruction_profile(&path);
        let accepted = pilot.original(&handoff, pins).unwrap();
        assert_eq!(accepted["root_cap"], 320u64 << 30);
        assert_eq!(accepted["pid"], pins.pid);
        assert!(SUCCESSOR266.original(&handoff, pins).is_err());
        assert!(
            pilot
                .original(
                    &handoff,
                    Pins {
                        qa_disk: pins.qa_memory,
                        ..pins
                    }
                )
                .is_err()
        );
    }
    #[test]
    #[ignore = "original epoch 266 native handoff and both retained pressure qualifications"]
    fn authentic_original_guard_release_and_both_pressure_qualifications() {
        let p = Path::new(FULL266.state).join("pilot/handoff.json");
        let mut b = json!({"path":p,"sha256":FULL266.fixed.unwrap().handoff_sha});
        let r = FULL266.original(&b, FULL266.fixed.unwrap()).unwrap();
        assert_eq!(r["pid"], FULL266.fixed.unwrap().pid);
        assert_eq!(r["iid"], FULL266.fixed.unwrap().iid);
        assert_eq!(r["memory"], 176000000000u64);
        assert_eq!(r["root_cap"], 112u64 << 30);
        assert_eq!(
            r["fleet"]["sha256"],
            "8be8c0b73a88aad4935817e5787161a857d008194d54b11cfb7900639b562241"
        );
        b["sha256"] = json!("0".repeat(64));
        assert!(FULL266.original(&b, FULL266.fixed.unwrap()).is_err());
    }
    #[test]
    #[ignore = "requires the original root-owned epoch 228 pilot QA, release and handoff"]
    fn original_228_guard_and_terminal_qa() {
        let b = json!({"path":Path::new(FULL228.state).join("pilot/handoff.json"),"sha256":FULL228.fixed.unwrap().handoff_sha});
        let r = FULL228.original(&b, FULL228.fixed.unwrap()).unwrap();
        assert_eq!(r["pid"], 2819393);
        assert_eq!(r["memory"], 120000000000u64);
        assert_eq!(r["root_cap"], 112u64 << 30);
        assert_eq!(
            r["fleet"]["sha256"],
            "ed624ffec8cfe447b9830aab6bd62bb1a0b1e6ff58a0776397d61cc48e8ba7c0"
        );
        assert!(FULL266.original(&b, FULL266.fixed.unwrap()).is_err());
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
    fn successor_requires_progress_beyond_original_writer_failure() {
        let mut v = json!({"first":[[100,114912000,10,20],"a"],"last":[[101,114912038,11,21],"b"]});
        assert!(SUCCESSOR266.markers(&v).is_err());
        v["last"][0][1] = json!(114912039);
        SUCCESSOR266.markers(&v).unwrap();
        assert_ne!(SUCCESSOR266.unit, FULL266.unit);
        assert_ne!(SUCCESSOR266.schema, FULL266.schema);
    }
    #[test]
    fn instruction_successor_reopens_two_original_parent_cursors() {
        let pins = Pins {
            iid: "1234567890abcdef1234567890abcdef",
            pid: 123,
            qa_disk: "",
            qa_memory: "",
            handoff_sha: "",
        };
        let proof = json!({"first":[[10,114912035,50,8],"a"],"last":[[20,114912039,51,10],"b"]});
        let raw = |pid: &str| {
            ["first","last"].map(|k|{let v=&proof[k][0]; json!({"__CURSOR":proof[k][1],"__MONOTONIC_TIMESTAMP":v[0].to_string(),
                "_BOOT_ID":"3b17d0055c3a4a0e8841da097e0957b5","_SYSTEMD_UNIT":SUCCESSOR266.unit,"_SYSTEMD_INVOCATION_ID":pins.iid,
                "_UID":"1000","_PID":pid,"_EXE":SUCCESSOR266.node,"MESSAGE":format!("progress slot {}/115343999 (1%) txs={} accounts={}",v[1],v[2],v[3])}).to_string()}).join("\n")
        };
        SUCCESSOR266
            .original_progress(&proof, raw("123").as_bytes(), pins)
            .unwrap();
        assert!(
            SUCCESSOR266
                .original_progress(&proof, raw("124").as_bytes(), pins)
                .is_err()
        );
        let changed = raw("123").replace("114912039/115343999", "114912038/115343999");
        assert!(
            SUCCESSOR266
                .original_progress(&proof, changed.as_bytes(), pins)
                .is_err()
        );
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
