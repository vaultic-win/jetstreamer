#![recursion_limit = "256"]
//! Closed epoch211 full replay, held before node exec until a genuine protective guard fires.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
mod admission;
mod capacity;
mod delivery247;
mod finalization;
mod full211_peer;
mod full211_window;
mod full265;
// Reuse the exact observer consumer, including its semantic startup/token checks.
pub mod foundation_holding_capacity;
#[path = "../../../jetstreamer-horizon-observe/src/full265.rs"]
pub mod full265_owner;
mod gate;
mod inputs;
mod launch;
mod lifecycle;
mod live;
pub mod native257;
pub mod native257_fit;
pub mod native228_demotion_fit;
pub mod native212;
pub mod native266;
pub mod native266_capped;
pub mod native266_full;
pub mod native261;
pub mod native262;
mod native265_growth;
mod peer_window;
mod peers;
mod native266_peer;
mod periodic;
mod prepare;
mod publication;
mod qualification;

const UNIT: &str = "horizon-singleton-211-capped-4aeca563-v1.service";
const GUARD_UNIT: &str = "horizon-singleton211-protective-v1.service";
const TIMER: &str = "horizon-singleton211-protective-v1.timer";
const RETENTION: &str = "horizon-singleton211-terminal-retention.target";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-211-singleton-capped-v1";
const TOKENS: &str = "/var/lib/jetstreamer/horizon-singleton211-startup-tokens";
const GATE: &str =
    "/var/lib/jetstreamer/horizon-singleton211-launch-20261120-v4/horizon-singleton211-launch";
const NODE: &str = "/var/lib/jetstreamer/horizon-singleton211-production-node-c17619b16d5d20f0-v1/jetstreamer-node";
const NODE_SHA: &str = "c17619b16d5d20f0d7aefc6e62ce99e68cc8b2bc88153f82183ebb0d4c5ede1d";
const WORKER: &str = "/var/lib/jetstreamer/horizon-singleton211-production-worker-1c89b6a214f9487b-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget";
const WORKER_SHA: &str = "1c89b6a214f9487babfd9dc121ade06037b371fbfcc3243f0e6ec67b6b961c41";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon-211-singleton-main-guard-20261119-v1/horizon-standalone-guard";
const INPUT: &str = "/var/lib/jetstreamer/horizon-focused-211-complete-span-store8-ca2e38b-v1";
const SNAPSHOT: &str = "snapshot-91151575-xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx.tar.zst";
const SNAPSHOT_SHA: &str = "958a8e5aad2423350f04470dffbd90fd8d7e458f7f8e774e15dd86d43291b5fb";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const PREFLIGHT: &str = "/var/lib/jetstreamer/horizon-singletons209-212-metadata-0d2856e7-v1/preflight211-singleton.json";
const PREFLIGHT_SHA: &str = "eaf7f9fa4df1ae57303b655dd727c8bc5d7786d2f1fafeebb5832843133e7086";
const FINGERPRINT: &str = "sha256:d00f6c8ff2d66ec302aea39267ace8c28931d2602c9f5185c913eb5c96ab667b";
const NATIVE_PROOF: &str =
    "/var/lib/jetstreamer/horizon-native211-terminal-proof-1836-v1/proof.json";
const NATIVE_PROOF_SHA: &str = "97b3ae139f81af08fed1f0e94ccd9606b838d742fb679939969dd79e0ae357e5";
const SEALER: &str =
    "/var/lib/jetstreamer/horizon251-published-sealer-20261118-v1/horizon251-sealer";
const SEALER_SHA: &str = "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a";
const MEMORY: u64 = 225_000_000_000;
const SCRATCH: u64 = 471_798_691_840;
const HOST: u64 = 68_719_476_736;
const CONTROL: u64 = 1_610_612_736;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
impl Bound {
    fn new(path: impl Into<PathBuf>, sha256: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            sha256: sha256.into(),
        }
    }
    fn bytes(&self, immutable: bool) -> Result<Vec<u8>> {
        ensure!(hex(&self.sha256, 64), "invalid SHA256");
        let before = identity(&self.path)?;
        ensure!(before.2 <= 16 << 20 && before.3 == 0, "evidence size/owner");
        ensure!(
            before.4 & if immutable { 0o222 } else { 0o022 } == 0,
            "evidence writable"
        );
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)?;
        ensure!(
            metadata_identity(&f.metadata()?) == before,
            "evidence open race"
        );
        let mut bytes = Vec::new();
        (&mut f).take((16 << 20) + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 16 << 20
                && digest(&bytes) == self.sha256
                && metadata_identity(&f.metadata()?) == before
                && identity(&self.path)? == before,
            "evidence changed or digest mismatch"
        );
        Ok(bytes)
    }
    fn json(&self) -> Result<Value> {
        Ok(serde_json::from_slice(&self.bytes(false)?)?)
    }
    fn sealed(&self) -> Result<Value> {
        ensure!(
            self.path.starts_with("/var/lib/jetstreamer"),
            "sealed namespace"
        );
        trusted_parents(&self.path)?;
        Ok(serde_json::from_slice(&self.bytes(true)?)?)
    }
    fn artifact(&self) -> Result<()> {
        trusted_parents(&self.path)?;
        let before = identity(&self.path)?;
        ensure!(
            before.3 == 0 && before.4 & 0o222 == 0 && before.2 <= 256 << 20,
            "artifact custody"
        );
        ensure!(
            hash(&self.path)? == self.sha256 && identity(&self.path)? == before,
            "artifact changed"
        );
        Ok(())
    }
}
type Identity = (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64);
fn metadata_identity(m: &fs::Metadata) -> Identity {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn identity(p: &Path) -> Result<Identity> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute() && p.canonicalize()? == p && m.is_file() && m.nlink() == 1,
        "unsafe file {}",
        p.display()
    );
    Ok(metadata_identity(&m))
}
fn trusted_parents(p: &Path) -> Result<()> {
    for p in p.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted parent {}",
            p.display()
        );
    }
    Ok(())
}
/// Search the exact bytes of live maps and unit recipes. These inputs can be
/// non-UTF8 and the controller also runs in unoptimized qualification builds.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    assert!(!needle.is_empty());
    if needle.len() > haystack.len() {
        return None;
    }
    // SAFETY: both pointers refer to the stated readable slices. GNU memmem
    // returns null or the first matching address within the haystack.
    let found = unsafe {
        libc::memmem(
            haystack.as_ptr().cast(),
            haystack.len(),
            needle.as_ptr().cast(),
            needle.len(),
        )
    };
    (!found.is_null()).then(|| found.addr() - haystack.as_ptr().addr())
}

fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn hash(p: &Path) -> Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut b = [0; 131072];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing number {k}"))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn binding(v: &Value) -> Result<Bound> {
    Ok(serde_json::from_value(v.clone())?)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn mono() -> Result<u64> {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } == 0,
        "monotonic clock"
    );
    (t.tv_sec as u64)
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(t.tv_nsec as u64 / 1000))
        .context("clock overflow")
}
fn fresh(t: u64, clock: u64, age: u64) -> Result<()> {
    ensure!(t <= clock && clock - t <= age, "stale/future evidence");
    Ok(())
}
fn no_authority(v: &Value) -> Result<()> {
    for k in [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[k] == false, "unexpected/missing authority flag {k}");
    }
    Ok(())
}
fn deny_authority(v: &mut Value) {
    for k in [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        v[k] = json!(false);
    }
}
fn save(root: &Path, leaf: &str, bytes: &[u8]) -> Result<Bound> {
    ensure!(!leaf.is_empty() && !leaf.contains('/'), "unsafe leaf");
    let p = root.join(leaf);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(Bound::new(p, digest(bytes)))
}
fn save_json(root: &Path, leaf: &str, value: &Value) -> Result<Bound> {
    save(root, leaf, &serde_json::to_vec_pretty(value)?)
}
fn absent(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("already exists {}", p.display()),
    }
}

/// Every subprocess is bounded; its actual stdout/stderr are retained, never synthesized.
struct Native {
    root: PathBuf,
    counter: u32,
    deadline: Option<u64>,
}
impl Native {
    fn check(&self) -> Result<()> {
        if let Some(d) = self.deadline {
            ensure!(mono()? < d, "original startup clock expired");
        }
        Ok(())
    }
    fn run(&mut self, exe: &str, args: &[&str]) -> Result<Vec<u8>> {
        self.check()?;
        self.counter += 1;
        let out = self
            .root
            .join(format!("command-{:04}.stdout", self.counter));
        let err = self
            .root
            .join(format!("command-{:04}.stderr", self.counter));
        let make = |p: &Path| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(p)
        };
        let mut child = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(make(&out)?)
            .stderr(make(&err)?)
            .spawn()?;
        let limit = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(s) = child.try_wait()? {
                ensure!(s.success(), "command failed: {exe}; see {}", err.display());
                break;
            }
            if Instant::now() >= limit || self.check().is_err() {
                let _ = child.kill();
                let _ = child.wait();
                bail!("command deadline {exe}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.check()?;
        ensure!(
            fs::metadata(&out)?.len() <= 16 << 20,
            "native output oversized"
        );
        Ok(fs::read(out)?)
    }
    fn show(&mut self, unit: &str) -> Result<Value> {
        ensure!(
            (unit.ends_with(".service") || unit.ends_with(".timer") || unit.ends_with(".target"))
                && unit.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
            "unit suffix"
        );
        let properties = if matches!(
            unit,
            native212::UNIT | native261::UNIT | native262::UNIT | native266::UNIT | native266_capped::UNIT
        ) {
            format!(
                "{},PrivateDevices,WorkingDirectory,ProtectControlGroups,RestrictAddressFamilies,OOMPolicy,OOMScoreAdjust,AmbientCapabilities,InaccessiblePaths",
                live::PROPS
            )
        } else if matches!(unit, delivery247::UNIT247 | delivery247::STAGED_UNIT | delivery247::SUCCESSOR_UNIT) {
            // The admitted uploaders have private credentials in Environment.
            let properties = live::PROPS
                .split(',')
                .filter(|k| *k != "Environment")
                .collect::<Vec<_>>()
                .join(",");
            format!("{properties},ExecMainExitTimestampMonotonic,AllowedCPUs")
        } else {
            live::PROPS.to_owned()
        };
        self.show_fields(unit, &properties)
    }
    fn show_fields(&mut self, unit: &str, properties: &str) -> Result<Value> {
        let bytes = self.run(
            "/usr/bin/systemctl",
            &["show", unit, "--no-pager", "--property", properties],
        )?;
        let mut v = serde_json::Map::new();
        for line in std::str::from_utf8(&bytes)?.lines() {
            let (k, val) = line.split_once('=').context("systemd property framing")?;
            ensure!(
                v.insert(k.into(), json!(val)).is_none(),
                "duplicate native property"
            );
        }
        Ok(Value::Object(v))
    }
    fn seal(&mut self, destination: &Path, members: &[(&str, Bound)]) -> Result<()> {
        Bound::new(SEALER, SEALER_SHA).artifact()?;
        let members: Vec<_> = members
            .iter()
            .map(|(name, b)| json!({"source":b.path,"sha256":b.sha256,"name":name,"mode":292}))
            .collect();
        let p = save_json(
            &self.root,
            &format!("seal-{}.json", self.counter),
            &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,"members":members}),
        )?;
        let old = unsafe { libc::umask(0o022) };
        let result = self.run(
            SEALER,
            &[
                p.path.to_str().context("plan path")?,
                "--plan-sha256",
                &p.sha256,
                "--self-sha256",
                SEALER_SHA,
            ],
        );
        unsafe { libc::umask(old) };
        result?;
        Ok(())
    }
}
/// Read-only API: validates the exact persisted startup graph; never observes or mutates runtime.
pub fn validate_saved_handoff(path: &Path, sha256: &str, launcher_sha256: &str) -> Result<Value> {
    let b = Bound::new(path, sha256);
    let v = b.sealed()?;
    ensure!(
        v["launcher_sha256"] == launcher_sha256 && hex(launcher_sha256, 64),
        "lifecycle launcher binding differs"
    );
    lifecycle::validate_handoff(&v)?;
    Ok(v)
}
pub fn run_from_environment() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).is_some_and(|s| s == "gate") {
        return gate::run(&args);
    }
    if args.get(1).is_some_and(|s| s == "inputs") {
        return inputs::run(&args);
    }
    if args.get(1).is_some_and(|s| s == "validate-handoff") {
        return lifecycle::run(&args);
    }
    ensure!(
        args.len() == 6
            && matches!(
                args[1].as_str(),
                "prepare" | "admit" | "launch" | "qualify-guard" | "retire-qualification"
            ),
        "usage: horizon-singleton211-launch prepare|admit|launch|qualify-guard|retire-qualification REVIEW_OR_CAPTURE SHA256 SELF_SHA256 NEW_EVIDENCE_DIRECTORY"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        hex(&args[4], 64) && hash(Path::new("/proc/self/exe"))? == args[4],
        "launcher image differs"
    );
    ensure!(
        fs::canonicalize("/proc/self/exe")? == Path::new(GATE),
        "sealed launcher path differs"
    );
    let review_ref = Bound::new(&args[2], &args[3]);
    let review = review_ref.sealed()?;
    let root = PathBuf::from(&args[5]);
    ensure!(
        root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("horizon-singleton211-execution-")),
        "execution namespace"
    );
    absent(&root)?;
    trusted_parents(&root)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let mut n = Native {
        root,
        counter: 0,
        deadline: None,
    };
    let result = (|| {
        if args[1] == "retire-qualification" {
            return qualification::retire_attempt(&mut n, &review_ref, &review, &args[4]);
        }
        qualification::operation(&review)?;
        ensure!(
            matches!(args[1].as_str(), "prepare" | "admit")
                || (args[1] == "qualify-guard") == (review["operation"] == "qualify-guard"),
            "operation/review mismatch"
        );
        let a = admission::validate(&mut n, &review, &review_ref, &args[4], false)?;
        if args[1] == "prepare" {
            return prepare::run(&mut n, &review, &review_ref, &args[4]);
        }
        if args[1] == "admit" {
            let b = save_json(&n.root, "admission.json", &a)?;
            println!("{}", serde_json::to_string(&b)?);
        } else {
            launch::run(&mut n, &review, &review_ref, &args[4], &a)?;
        }
        Ok(())
    })();
    if let Err(ref e) = result {
        let _ = save_json(
            &n.root,
            "failure.json",
            &json!({"schema":"horizon-singleton211-launch-failure-v1","error":format!("{e:#}"),"automatic_retry":false,"recorded_unix_seconds":now().ok(),"remote_mutations":false}),
        );
    }
    result
}

#[cfg(test)]
mod offline_fixture;
