#![recursion_limit = "256"]
//! One-shot epoch 251 fifth-lane adapter. No R2 or archive mutation commands.
//! Preparation and launch require a separate fresh, Main-accepted admission.
mod capacity;
mod live;
mod admission_source;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const CAP: u64 = 506191984640;
const HIGH: u64 = 100000000000;
const MAX: u64 = 128000000000;
const CONTROL: u64 = 1610612736;
// Four retained hard ceilings plus the candidate, host reserve and control plane.
const LIVE_MAX: u64 = 251041591296;
const HOST_RESERVE: u64 = 64 * 1024 * 1024 * 1024;
const RETAINED_MEMORY_OBLIGATION: u64 = 4 * LIVE_MAX + MAX + HOST_RESERVE + CONTROL;
const RETAINED_ROOT_OBLIGATION: u64 = 2666773615088;
const UNIT: &str = "horizon-qualify-251-replacement-20261118-v1.service";
const GUARD_UNIT: &str = "horizon-251-replacement-20261118-protective-v1.service";
const TIMER: &str = "horizon-251-replacement-20261118-protective-v1.timer";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-251-replacement-20261118-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon251-fifth-20261118-state-v1";
const STATIC: &str = "/var/lib/jetstreamer/horizon251-fifth-20261118-static-v3";
const LAUNCHER: &str = "/var/lib/jetstreamer/horizon251-fifth-20261118-launcher-v2/horizon251-launch5";
const BOUND: &str = "/var/lib/jetstreamer/horizon251-replacement-20261118-guard-v1";
const TOKENS: &str = "/var/lib/jetstreamer/horizon251-replacement-20261118-tokens-v1";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon251-replacement-20261118-receipts-v1";
const NODE: &str =
    "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/jetstreamer-node";
const NODE_SHA: &str = "02f42f2988dd31437e2c874414f247667200663c874042783406b5517b0d519b";
const WORKER: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15";
const MANIFEST: &str = "/var/lib/jetstreamer/horizon251-single-epoch-manifest-20261118-v1/preflight-251-single-epoch.json";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon251-native-input-20261118-v1/snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst";
const INPUT: &str = "/var/lib/jetstreamer/horizon251-native-input-20261118-v1";
const NETWORK: &str = "/home/ubuntu/.codex/diagnostics/horizon251-network-proof-20261118-v1.json";
const NETWORK_SHA: &str = "8e3e1b71f18e31eba24fb18d6ae90fcc9bc9fe91ca85e0cb5709b589aad192bb";
const GENESIS: &str = "/var/lib/jetstreamer/horizon251-native-input-20261118-v1/genesis.tar.bz2";
const AUTH: &str =
    "/home/ubuntu/.codex/diagnostics/horizon251-captured-node-input-20261118-v1/acceptance.json";
const AUTH_SHA: &str = "02227422d85616cb060bce6a001dab5ee104c0ff39a0f7d554b67466344b83f7";
const NODE_PROBES: &str = "/var/lib/jetstreamer/horizon251-captured-node-probe-acceptance-20261118-v1/main-review.json";
const NODE_PROBES_SHA: &str = "26b1a2a123fb5848e42e241758e1fda264baa5ee3b528ad0f7ad19d89e10099a";
const CACHE: &str = "/var/lib/jetstreamer/horizon251-index-cache-20261118-v1";
const CACHE_RECEIPT_SHA: &str = "ad854d8f62068240efcccb68cbfa334da47b786ea93a701c5742663de28a5a9f";
const STATIC_RECEIPT_SHA: &str = "e51f372e7d499a9a1b8e972fcb731726d8138e204564b26867eb2117a8f41d83";
const SEALER: &str =
    "/var/lib/jetstreamer/horizon251-published-sealer-20261118-v1/horizon251-sealer";
const SEALER_SHA: &str = "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a";
const GUARD: &str = "/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard";
const GUARD_SHA: &str = "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d";
// Retained owners keep their exact original image and invocation-bound receipts.
const RETAINED_GUARD_SHA: &str = "044ccba70304c6d5690d2628c1ca08586462efdcc2d9f278903ee8bab0da6b3f";
const LIVE247_UNIT: &str = "horizon-qualify-247-reboot-20261117-v2.service";
const LIVE247_IID: &str = "d091bb68ff2648159c76f690b3b7fee3";
const LIVE247_HANDOFF: &str = "/var/lib/jetstreamer/horizon247-reboot-20261117-state-v2/launch-v2/guarded-startup-handoff.json";
const LIVE247_HANDOFF_SHA: &str =
    "9d1c29837689891335cd45328ec23686f77fffbde348d74e745a3834a283ce3a";
const LIVE247_GUARD: &str = "horizon-247-reboot-20261117-protective-v2.service";
const LIVE247_TIMER: &str = "horizon-247-reboot-20261117-protective-v2.timer";
const LIVE248_UNIT: &str = "horizon-qualify-248-reboot-20261117-v1.service";
const LIVE248_GUARD: &str = "horizon-248-reboot-20261117-protective-v1.service";
const LIVE248_TIMER: &str = "horizon-248-reboot-20261117-protective-v1.timer";
const LIVE248_IID: &str = "16f84e36b65645a7be7d28d08e3d40cc";
const LIVE248_HANDOFF: &str = "/var/lib/jetstreamer/horizon248-reboot-20261117-state-v1/launch-v1/guarded-startup-handoff.json";
const LIVE248_HANDOFF_SHA: &str =
    "ef937eac2be928256e4e8301e101f8469a66a310a67d953a2a125c9727bf4c9e";
const LIVE249_UNIT: &str = "horizon-qualify-249-reboot-20261117-v1.service";
const LIVE249_GUARD: &str = "horizon-249-reboot-20261117-protective-v1.service";
const LIVE249_TIMER: &str = "horizon-249-reboot-20261117-protective-v1.timer";
const LIVE249_IID: &str = "dbf4a4d19de84f31b3897da87622156e";
const LIVE249_HANDOFF: &str = "/var/lib/jetstreamer/horizon249-reboot-20261117-state-v1/launch-v1/guarded-startup-handoff.json";
const LIVE249_HANDOFF_SHA: &str =
    "6000c8f7461dbc1143fc76ac87ca2801f7e3796708e8aaac9687ac58ff90ca86";
const BASE_PROPS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainCode,ExecMainStatus,Job,FragmentPath,DropInPaths,Restart,KillMode,Delegate,ControlGroup";
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing number {k}"))
}
fn yes(v: &Value, k: &str) -> Result<()> {
    ensure!(v[k] == true, "required {k}");
    Ok(())
}
fn hash_bytes(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn hash(p: &Path) -> Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn identity(p: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && p.canonicalize()? == p,
        "unsafe regular file {}",
        p.display()
    );
    Ok(
        json!({"dev":m.dev(),"ino":m.ino(),"bytes":m.len(),"mtime_ns":m.mtime() as i128*1000000000+m.mtime_nsec() as i128,"ctime_ns":m.ctime() as i128*1000000000+m.ctime_nsec() as i128,"mode":m.mode(),"uid":m.uid(),"gid":m.gid(),"nlink":m.nlink()}),
    )
}
fn small(p: &Path) -> Result<Vec<u8>> {
    let before = identity(p)?;
    ensure!(number(&before, "bytes")? <= 4 << 20, "oversized metadata");
    let b = fs::read(p)?;
    ensure!(identity(p)? == before, "metadata changed");
    Ok(b)
}
fn bound(v: &Value) -> Result<Value> {
    let p = Path::new(text(v, "path")?);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o022 == 0,
        "mutable/unowned binding"
    );
    let b = small(p)?;
    ensure!(
        hash_bytes(&b) == text(v, "sha256")?,
        "bound digest mismatch {}",
        p.display()
    );
    Ok(serde_json::from_slice(&b)?)
}
fn pin(p: &Path) -> Result<Value> {
    Ok(json!({"path":p,"sha256":hash(p)?}))
}
fn absent(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("already exists {}", p.display()),
    }
}
fn directory(p: &Path, uid: u32, mode: u32) -> Result<()> {
    absent(p)?;
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))?;
    let s = std::ffi::CString::new(p.as_os_str().as_bytes())?;
    ensure!(
        unsafe { libc::chown(s.as_ptr(), uid, uid) } == 0,
        "chown failed"
    );
    File::open(p)?.sync_all()?;
    File::open(p.parent().context("no parent")?)?.sync_all()?;
    Ok(())
}
fn save_at(root: &Path, name: &str, b: &[u8]) -> Result<Value> {
    ensure!(!name.contains('/') && !name.is_empty(), "unsafe leaf");
    let p = root.join(name);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    f.write_all(b)?;
    f.sync_all()?;
    File::open(root)?.sync_all()?;
    pin(&p)
}
struct Native {
    deadline: Option<Instant>,
    counter: u32,
    root: PathBuf,
}
impl Native {
    fn new(root: PathBuf) -> Self {
        Self {
            deadline: None,
            counter: 0,
            root,
        }
    }
    fn check(&self) -> Result<()> {
        if let Some(d) = self.deadline {
            ensure!(
                Instant::now() < d,
                "original 50-second startup deadline expired"
            );
        }
        Ok(())
    }
    fn run(&mut self, exe: &str, args: &[&str]) -> Result<Vec<u8>> {
        self.check()?;
        self.counter += 1;
        let stem = format!("command-{:03}", self.counter);
        let stdout = self.root.join(format!("{stem}.stdout"));
        let stderr = self.root.join(format!("{stem}.stderr"));
        let out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stdout)?;
        let err = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stderr)?;
        let started = Instant::now();
        let limit = self
            .deadline
            .map(|x| x.min(started + Duration::from_secs(15)))
            .unwrap_or(started + Duration::from_secs(15));
        let mut child = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .spawn()?;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() >= limit {
                let _ = child.kill();
                let _ = child.wait();
                bail!("native metadata command deadline expired: {exe}")
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        self.check()?;
        ensure!(
            status.success(),
            "native command failed {exe} {:?}: {}",
            args,
            String::from_utf8_lossy(&small(&stderr)?)
        );
        small(&stdout)
    }
    fn show(&mut self, u: &str, extra: &str) -> Result<(BTreeMap<String, String>, Vec<u8>)> {
        let props = format!(
            "{BASE_PROPS}{}{}",
            if extra.is_empty() { "" } else { "," },
            extra
        );
        let raw = self.run(
            "/usr/bin/systemctl",
            &["show", u, "--no-pager", &format!("--property={props}")],
        )?;
        let s = String::from_utf8(raw.clone())?;
        let rows = s
            .lines()
            .filter_map(|s| s.split_once('='))
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        Ok((rows, raw))
    }
    fn seal(&mut self, dest: &str, members: Vec<Value>, name: &str) -> Result<Value> {
        let p = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":members});
        let r = save_at(&self.root, name, &serde_json::to_vec_pretty(&p)?)?;
        let previous_mask = unsafe { libc::umask(0o022) };
        let seal_result = self.run(
            SEALER,
            &[
                text(&r, "path")?,
                "--plan-sha256",
                text(&r, "sha256")?,
                "--self-sha256",
                SEALER_SHA,
            ],
        );
        unsafe {
            libc::umask(previous_mask);
        }
        seal_result?;
        pin(&Path::new(dest).join("deployment-seal-receipt.json"))
    }
}
fn row<'a>(v: &'a BTreeMap<String, String>, k: &str) -> Result<&'a str> {
    v.get(k)
        .map(String::as_str)
        .with_context(|| format!("missing native property {k}"))
}
fn closed(v: &BTreeMap<String, String>) -> Result<()> {
    let absent_service_properties =
        row(v, "LoadState")? == "not-found" || row(v, "Id")?.ends_with(".timer");
    for (key, zero) in [
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("ControlGroup", ""),
    ] {
        ensure!(
            v.get(key).map(String::as_str) == Some(zero)
                || (absent_service_properties && !v.contains_key(key)),
            "unit has live or unknown {key}"
        );
    }
    ensure!(
        matches!(row(v, "ActiveState")?, "inactive" | "failed") && row(v, "Job")?.is_empty(),
        "unit not drained"
    );
    Ok(())
}
fn iid(v: &str) -> bool {
    v.len() == 32
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn pre(v: &BTreeMap<String, String>, expected: &str) -> Result<u32> {
    ensure!(
        iid(expected)
            && row(v, "InvocationID")? == expected
            && row(v, "ActiveState")? == "activating"
            && row(v, "SubState")? == "start-pre"
            && row(v, "MainPID")? == "0"
            && row(v, "NRestarts")? == "0"
            && row(v, "Restart")? == "no"
            && row(v, "KillMode")? == "control-group"
            && row(v, "Delegate")? == "no",
        "producer left admitted start-pre"
    );
    Ok(row(v, "ControlPID")?.parse()?)
}
fn check_inputs() -> Result<Value> {
    let b = small(Path::new(AUTH))?;
    ensure!(hash_bytes(&b) == AUTH_SHA, "251 input receipt changed");
    let v: Value = serde_json::from_slice(&b)?;
    ensure!(
        v["schema"] == "horizon251-captured-node-input-custody-v2"
            && v["epoch"] == 251
            && v["accepted_input_custody"] == true
            && v["replay_launch_authorized"] == false,
        "foreign input receipt"
    );
    for (key, path, digest) in [
        (
            "node",
            NODE,
            NODE_SHA,
        ),
        (
            "worker",
            WORKER,
            "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4",
        ),
        (
            "manifest",
            MANIFEST,
            "e40e8d0341440d29cff7cd35e79e5f713d7908ce42f3a1c4995e1b2924551f14",
        ),
        (
            "bootstrap",
            SNAPSHOT,
            "b7af2058dd498bdf8c0f7e2a717a0d7c8153c20027eca2c3c2de15351b87b311",
        ),
        (
            "genesis",
            GENESIS,
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        ),
    ] {
        let record = &v[key];
        ensure!(
            record["path"] == path && record["sha256"] == digest,
            "wrong {key} input binding"
        );
        let actual = identity(Path::new(path))?;
        for field in [
            "dev", "ino", "mode", "uid", "gid", "nlink", "mtime_ns", "ctime_ns",
        ] {
            ensure!(
                record["identity"][field] == actual[field],
                "{key} identity changed: {field}"
            );
        }
        ensure!(
            record["identity"]["size"] == actual["bytes"],
            "{key} size changed"
        );
    }
    validate_node_probes(&bound(&json!({"path":NODE_PROBES,"sha256":NODE_PROBES_SHA}))?)?;
    check_network()?;
    check_cache()?;
    check_static()?;
    ensure!(
        hash(Path::new(SEALER))? == SEALER_SHA && hash(Path::new(GUARD))? == GUARD_SHA,
        "sealed tool changed"
    );
    Ok(v)
}
fn validate_node_probes(v: &Value) -> Result<()> {
    ensure!(v["schema"] == "horizon251-main-captured-node-input-probes-v1"
        && v["node"]["path"] == NODE && v["node"]["sha256"] == NODE_SHA
        && v["manifest"]["path"] == MANIFEST
        && v["manifest"]["sha256"] == "e40e8d0341440d29cff7cd35e79e5f713d7908ce42f3a1c4995e1b2924551f14",
        "foreign node capability binding");
    for key in ["Main_accepted", "candidate_runtime_opt_in", "fingerprint_rejection_passed",
        "manifest_decoded_before_snapshot_filename_rejection", "output_and_work_directories_empty"] {
        yes(v, key)?;
    }
    for (key, expected_iid) in [("fingerprint_terminal", "63db3d36523447ca88013139029db22d"),
        ("schema_terminal", "a720df223e724318a8fe18369e97adfb")] {
        let t = &v[key];
        ensure!(t["ActiveState"] == "failed" && t["Result"] == "exit-code"
            && t["ExecMainCode"] == "1" && t["ExecMainStatus"] == "1"
            && t["InvocationID"] == expected_iid && t["MainPID"] == "0"
            && t["ControlPID"] == "0" && t["ControlGroup"] == ""
            && t["NRestarts"] == "0", "node probe did not reach its expected terminal gate");
    }
    Ok(())
}
fn check_cache() -> Result<()> {
    let receipt_path = Path::new(CACHE).join("deployment-seal-receipt.json");
    ensure!(
        hash(&receipt_path)? == CACHE_RECEIPT_SHA,
        "index cache seal changed"
    );
    let receipt: Value = serde_json::from_slice(&small(&receipt_path)?)?;
    ensure!(
        receipt["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && receipt["destination"] == CACHE
            && receipt["replay_launch_authorized"] == false
            && receipt["remote_mutations"] == false,
        "foreign index cache receipt"
    );
    let expected = [
        (
            "epoch-250-bafyreihxzahaxjzity5i4dvz5cqunbm645w3xddx23fxe2fg6lyd3v26fa-mainnet-slot-to-cid.index",
            "233dd69d874a13f9bcf025ac877fd2cca14b3c9d5668095e699b41c98927cb91",
            15576774,
        ),
        (
            "epoch-251-bafyreietccmsxuqxvbfnonzcjq4cphznuuy7lnehfa6kejpmz27ditutn4-mainnet-slot-to-cid.index",
            "72e12b51baa55f08f94f212e4a23c885bab9dcb413e5640084b1d33531de5acb",
            15666061,
        ),
        (
            "epoch-251-bafyreietccmsxuqxvbfnonzcjq4cphznuuy7lnehfa6kejpmz27ditutn4-mainnet-cid-to-offset-and-size.index",
            "1f946a290b09cf28610958876d91090c212740e9b0dd86a3e5ae5519e89a2d5c",
            10554622710u64,
        ),
    ];
    let members = receipt["members"]
        .as_array()
        .context("index cache members")?;
    ensure!(members.len() == expected.len(), "index cache member count");
    for (name, sha, bytes) in expected {
        ensure!(
            members.iter().any(|m| m["name"] == name
                && m["sha256"] == sha
                && m["bytes"] == bytes
                && m["mode"] == "0444"),
            "index cache member seal differs: {name}"
        );
        let p = Path::new(CACHE).join(name);
        let id = identity(&p)?;
        ensure!(
            id["bytes"] == bytes
                && id["uid"] == 0
                && id["gid"] == 0
                && number(&id, "mode")? & 0o777 == 0o444
                && hash(&p)? == sha,
            "index cache file changed: {name}"
        );
    }
    Ok(())
}
fn check_static() -> Result<()> {
    let receipt_path = Path::new(STATIC).join("deployment-seal-receipt.json");
    ensure!(
        hash(&receipt_path)? == STATIC_RECEIPT_SHA,
        "251 static seal changed"
    );
    let receipt: Value = serde_json::from_slice(&small(&receipt_path)?)?;
    ensure!(
        receipt["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && receipt["destination"] == STATIC
            && receipt["replay_launch_authorized"] == false,
        "foreign 251 static seal"
    );
    for (name, sha) in [
        (
            UNIT,
            "de90bece06921e385b4e75ab8250632cee0a304cca8a11c1efc3f96f3d62a9e0",
        ),
        (
            GUARD_UNIT,
            "f43b122b8b3c6e36ca3350d8845baf57b0d306f7b320881c64fe8fe7ded52f99",
        ),
        (
            TIMER,
            "7125309e78b87fe55dfc8dbf3d3f7208d472be7711a99f44bcb4fbe26ac1fe89",
        ),
        (
            "source-plan.json",
            "4c18ca26374dda8f0d87226c1ddc68938cae81b88a8340aadaefdef99f30beed",
        ),
        (
            "capacity-assessment.json",
            "a4affcfccd15e7b99575307dbca98f7363f03e2bdbed984d574f6b8d7f595eb3",
        ),
    ] {
        ensure!(
            receipt["members"].as_array().is_some_and(|members| members
                .iter()
                .any(|m| m["name"] == name && m["sha256"] == sha && m["mode"] == "0444")),
            "missing static member {name}"
        );
        ensure!(
            hash(&Path::new(STATIC).join(name))? == sha,
            "static member changed: {name}"
        );
    }
    Ok(())
}
fn check_network() -> Result<()> {
    let proof = bound(&json!({"path":NETWORK,"sha256":NETWORK_SHA}))?;
    ensure!(
        proof["schema"] == "horizon251-service-effective-car-header-proof-v1"
            && proof["http_status"] == 206
            && proof["expected_root_cid"]
                == "bafyreietccmsxuqxvbfnonzcjq4cphznuuy7lnehfa6kejpmz27ditutn4"
            && proof["car_header_accepted"] == true
            && proof["replay_launch_authorized"] == false,
        "network evidence differs"
    );
    for name in ["headers", "body"] {
        let path = Path::new(ROOT).join("network-proof").join(name);
        ensure!(
            proof[name]["path"] == path.to_str().context("path encoding")?
                && hash(&path)? == text(&proof[name], "sha256")?
                && identity(&path)?["bytes"] == proof[name]["identity"]["bytes"],
            "network artifact changed"
        );
    }
    Ok(())
}
fn admission_values(a: &Value, clock: u64) -> Result<()> {
    ensure!(
        a["schema"] == "horizon251-reboot-main-admission-five-v1" && a["candidate_epoch"] == 251,
        "foreign admission"
    );
    for k in [
        "Main_accepted",
        "complete_native_census_reviewed",
        "all_other_obligations_preserved",
        "fifth_lane_experiment_accepted",
        "fifth_lane_fit_proven",
        "clean_1800_second_observer",
        "current_guard_receipts_verified",
        "no_overlapping_campaign_controller",
        "first_guard_before_useful_work_required",
    ] {
        yes(a, k)?;
    }
    for o in &live::OWNERS {
        ensure!(
            a[format!("live{}_unit", o.epoch)] == o.unit
                && a[format!("live{}_invocation_id", o.epoch)] == o.iid,
            "live identity changed"
        );
    }
    let issued = number(a, "issued_unix_seconds")?;
    let expiry = number(a, "expires_unix_seconds")?;
    ensure!(
        issued <= clock && clock < expiry && expiry <= issued + 300,
        "expired/future admission"
    );
    ensure!(
        number(a, "observer_unix_seconds")? <= issued
            && clock - number(a, "observer_unix_seconds")? < 1800,
        "stale resource observer"
    );
    ensure!(
        number(a, "candidate_memory_max_bytes")? == MAX
            && number(a, "candidate_memory_high_bytes")? == HIGH
            && number(a, "candidate_root_cap_bytes")? == CAP
            && number(a, "candidate_control_memory_bytes")? == CONTROL,
        "resource envelope differs"
    );
    ensure!(
        number(a, "required_initial_free_bytes")?
            == number(a, "guard_minimum_free_bytes")?
                .checked_add(CAP)
                .context("overflow")?
            && number(a, "guard_minimum_free_bytes")? >= number(a, "century_floor_bytes")?
            && number(a, "guard_minimum_free_bytes")? >= RETAINED_ROOT_OBLIGATION
            && number(a, "century_floor_bytes")? > 0,
        "disk booking/floor differs"
    );
    ensure!(
        number(a, "memory_obligation_after_bytes")? >= RETAINED_MEMORY_OBLIGATION
            && number(a, "memory_obligation_after_bytes")? <= number(a, "host_memory_total_bytes")?,
        "memory booking exceeds host"
    );
    ensure!(
        a["actual_executing_before"] == 4
            && a["initializing_before"] == 0
            && a["proposed_replay_lanes"] == 5
            && a["proven_operating_count"] == 4
            && a["desired_replay_lanes"].as_u64().is_some_and(|n| n >= 5)
            && a["live247_unit"] == LIVE247_UNIT
            && a["live247_invocation_id"] == LIVE247_IID
            && a["live248_unit"] == LIVE248_UNIT
            && a["live248_invocation_id"] == LIVE248_IID
            && a["live249_unit"] == LIVE249_UNIT
            && a["live249_invocation_id"] == LIVE249_IID,
        "not a qualified fifth replay experiment"
    );
    ensure!(
        a["worker_root"] == ROOT
            && a["producer_unit"] == UNIT
            && a["guard_unit"] == GUARD_UNIT
            && a["timer_unit"] == TIMER
            && a["coexisting_services"]
                .as_array()
                .is_some_and(|items| items.len() <= 16),
        "namespace differs"
    );
    Ok(())
}
fn live_handoff_values(v: &Value, schema: &str, unit: &str, invocation_id: &str) -> Result<()> {
    ensure!(
        v["schema"] == schema
            && v["producer"]["Id"] == unit
            && v["producer"]["InvocationID"] == invocation_id
            && v["first_fire_token"]["path"].as_str().is_some()
            && v["first_fire_token"]["sha256"].as_str().is_some(),
        "unqualified live replay handoff: {unit}"
    );
    Ok(())
}
fn validate_admission(a: &Value, plan: &Value) -> Result<()> {
    admission_values(a, now()?)?;
    ensure!(
        a["launch_plan"] == *plan,
        "admission does not bind exact launch plan"
    );
    let mut documents = BTreeMap::new();
    for k in ["owner", "observer", "fleet", "capacity", "census"] {
        documents.insert(k.to_string(), bound(&a[k])?);
    }
    evidence_claims(a, &documents)?;
    capacity::validate(a, &documents)?;
    ensure!(
        a["coexisting_services"] == documents["census"]["coexisting_services"],
        "coexisting service census differs"
    );
    live::handoffs(a)?;
    ensure!(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == text(a, "boot_id")?,
        "boot changed"
    );
    let pid = number(a, "main_controller_pid")?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .collect();
    ensure!(
        fields.get(19).context("start ticks")?.parse::<u64>()?
            == number(a, "main_controller_start_ticks")?,
        "main controller changed"
    );
    // system.slice has no cpuset controller on this host; its effective set is
    // inherited from the cgroup root. The producer's narrower CPU binding is
    // checked independently against its loaded unit before launch.
    let cpus = fs::read_to_string("/sys/fs/cgroup/cpuset.cpus.effective")?;
    let online = fs::read_to_string("/sys/devices/system/cpu/online")?;
    ensure!(
        cpus.trim() == "0-127" && online.trim() == "0-127",
        "CPU topology differs from qualified route"
    );
    Ok(())
}
// Main selects JSON pointers in the real source schemas, but cannot omit any required
// cross-check or point to a different evidence document for a given claim.
fn evidence_fields() -> [(&'static str, &'static [&'static str]); 5] {
    [
        (
            "owner",
            &[
                "boot_id",
                "main_controller_pid",
                "main_controller_start_ticks",
            ][..],
        ),
        (
            "observer",
            &[
                "observer_unix_seconds",
                "host_memory_total_bytes",
                "observed_available_bytes",
            ][..],
        ),
        (
            "fleet",
            &[
                "actual_executing_before",
                "initializing_before",
                "proven_operating_count",
            ][..],
        ),
        (
            "capacity",
            &[
                "candidate_memory_max_bytes",
                "candidate_memory_high_bytes",
                "candidate_root_cap_bytes",
                "candidate_control_memory_bytes",
                "memory_obligation_after_bytes",
                "required_initial_free_bytes",
                "guard_minimum_free_bytes",
                "century_floor_bytes",
                "proposed_replay_lanes",
                "desired_replay_lanes",
                "fifth_lane_fit_proven",
                "clean_1800_second_observer",
                "current_guard_receipts_verified",
            ][..],
        ),
        (
            "census",
            &["actual_executing_before", "initializing_before", "boot_id"][..],
        ),
    ]
}
fn evidence_claims(a: &Value, documents: &BTreeMap<String, Value>) -> Result<()> {
    for (source, fields) in evidence_fields() {
        for field in fields {
            let pointer = text(&a["evidence_claims"][source], field)?;
            ensure!(
                pointer.starts_with('/') && !pointer.is_empty(),
                "invalid evidence pointer"
            );
            let observed = documents
                .get(source)
                .context("missing bound evidence")?
                .pointer(pointer)
                .context("missing source claim")?;
            ensure!(
                a.get(*field) == Some(observed),
                "{source} evidence contradicts {field}"
            );
        }
    }
    ensure!(
        number(a, "observed_available_bytes")? >= number(a, "required_initial_free_bytes")?,
        "observer disk booking does not fit"
    );
    Ok(())
}
fn templates() -> Result<(String, String, String)> {
    check_static()?;
    let producer = String::from_utf8(small(&Path::new(STATIC).join(UNIT))?)?;
    let guard = String::from_utf8(small(&Path::new(STATIC).join(GUARD_UNIT))?)?;
    let timer = String::from_utf8(small(&Path::new(STATIC).join(TIMER))?)?;
    ensure!(producer.contains(&format!("--snapshot-archive={SNAPSHOT}"))
        && producer.contains(&format!("--cohort-manifest={MANIFEST}"))
        && producer.contains("--cohort-manifest-fingerprint=sha256:e214b640c55cc6ec0e431c66f9cbd0076c4620578c2dea1e6c2324e7f616789e")
        && producer.contains(&format!("{CACHE}:{ROOT}/output/compact-indexes/250"))
        && producer.contains(&format!("{CACHE}:{ROOT}/output/compact-indexes/251"))
        && guard.contains("@ACTUAL_SEALED_PLAN_SHA256@")
        && timer.contains(&format!("Unit={GUARD_UNIT}")), "sealed source route differs");
    Ok((producer, guard, timer))
}
fn guard_plan(a: &Value, invocation: &str) -> Result<Value> {
    ensure!(iid(invocation), "bad guard IID");
    Ok(
        json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":invocation,"filesystem":"/","minimum_free_bytes":number(a,"guard_minimum_free_bytes")?,"worker_root":ROOT,"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":CAP,"receipt_directory":RECEIPTS}),
    )
}
fn root_pristine() -> Result<()> {
    let expected = [
        (ROOT, vec!["output", "state", "tmp", "network-proof"]),
        (
            &format!("{ROOT}/output"),
            vec!["genesis.tar.bz2", "compact-indexes"],
        ),
        (
            &format!("{ROOT}/output/compact-indexes"),
            vec!["250", "251"],
        ),
        (&format!("{ROOT}/output/compact-indexes/250"), vec![]),
        (&format!("{ROOT}/output/compact-indexes/251"), vec![]),
        (&format!("{ROOT}/state"), vec![]),
        (&format!("{ROOT}/tmp"), vec!["isolated-empty-gcloud"]),
        (&format!("{ROOT}/tmp/isolated-empty-gcloud"), vec![]),
        (&format!("{ROOT}/network-proof"), vec!["headers", "body"]),
    ];
    for (path, names) in expected {
        let p = Path::new(path);
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir()
                && m.uid() == 1000
                && m.gid() == 1000
                && m.mode() & 0o777 == 0o700
                && p.canonicalize()? == p,
            "bad fresh root custody"
        );
        let actual: BTreeSet<_> = fs::read_dir(p)?
            .map(|r| r.map(|x| x.file_name().to_string_lossy().into_owned()))
            .collect::<std::io::Result<_>>()?;
        ensure!(
            actual == names.into_iter().map(str::to_string).collect(),
            "fresh root is not pristine"
        );
    }
    let placeholder = identity(&Path::new(ROOT).join("output/genesis.tar.bz2"))?;
    ensure!(
        placeholder["bytes"] == 0
            && placeholder["uid"] == 1000
            && placeholder["gid"] == 1000
            && number(&placeholder, "mode")? & 0o777 == 0o400,
        "genesis mount placeholder changed"
    );
    check_network()?;
    Ok(())
}
fn scope_census(n: &mut Native, a: &Value, allow_candidate: bool) -> Result<()> {
    live::census(n, a, allow_candidate)
}
fn prepare(n: &mut Native, a: &Value, plan: &Value, admission: &Value) -> Result<()> {
    validate_admission(a, plan)?;
    check_inputs()?;
    scope_census(n, a, false)?;
    for p in [BOUND, TOKENS, RECEIPTS] {
        absent(Path::new(p))?;
    }
    root_pristine()?;
    check_static()?;
    for u in [UNIT, GUARD_UNIT, TIMER] {
        absent(&Path::new("/run/systemd/system").join(u))?;
        let (v, _) = n.show(u, "")?;
        closed(&v)?;
        ensure!(
            row(&v, "LoadState")? == "not-found",
            "attempt unit name already consumed"
        );
    }
    directory(Path::new(TOKENS), 0, 0o755)?;
    directory(Path::new(RECEIPTS), 0, 0o700)?;
    root_pristine()?;
    templates()?;
    let validation = save_at(
        &n.root,
        "guard-validation-plan.json",
        &serde_json::to_vec_pretty(&guard_plan(a, &"0".repeat(32))?)?,
    )?;
    n.run(
        GUARD,
        &[
            text(&validation, "path")?,
            "--plan-sha256",
            text(&validation, "sha256")?,
            "--self-sha256",
            GUARD_SHA,
            "--validate-plan-only",
        ],
    )?;
    symlink(
        Path::new(STATIC).join(UNIT),
        Path::new("/run/systemd/system").join(UNIT),
    )?;
    n.run("/usr/bin/systemctl", &["daemon-reload"])?;
    save_at(
        &n.root,
        "prepared.json",
        &serde_json::to_vec_pretty(
            &json!({"schema":"horizon251-reboot-prepared-v1","plan":plan,"admission":admission,"input_auth":pin(Path::new(AUTH))?,"accepted_inputs_preserved":true,"worker_root":ROOT,"unit":UNIT,"replay_started":false}),
        )?,
    )?;
    Ok(())
}
fn prestart_headers(raw: &[u8]) -> Result<Vec<(String, String, String)>> {
    let raw = std::str::from_utf8(raw)?;
    let mut out = Vec::new();
    for line in raw.lines().filter_map(|s| s.strip_prefix("ExecStartPre=")) {
        ensure!(line.starts_with("{ path="), "malformed ExecStartPre");
        for entry in line.split("{ path=").skip(1) {
            let (path, tail) = entry.split_once(" ; argv[]=").context("prestart path")?;
            let (argv, tail) = tail
                .split_once(" ; ignore_errors=")
                .context("prestart argv")?;
            let (ignore, _) = tail.split_once(" ;").context("prestart ignore")?;
            out.push((path.to_string(), argv.to_string(), ignore.to_string()));
        }
    }
    Ok(out)
}
fn validate_loaded(v: &BTreeMap<String, String>, raw: &[u8]) -> Result<()> {
    for (k, want) in [
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("DropInPaths", ""),
        ("MemoryMax", "128000000000"),
        ("MemoryHigh", "100000000000"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("RuntimeMaxUSec", "5d"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("AllowedCPUs", "0-15"),
        ("CPUAffinity", "0-15"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
        ("EnvironmentFiles", ""),
        ("PassEnvironment", ""),
        ("Slice", "system.slice"),
    ] {
        // This systemd build omits EnvironmentFiles entirely when the unit
        // has none. A configured file is emitted (as for ssh.service here).
        // The unchanged sealed source template must also omit the directive.
        if k == "EnvironmentFiles" && !v.contains_key(k) {
            ensure!(
                !templates()?
                    .0
                    .lines()
                    .any(|line| line.starts_with("EnvironmentFile=")),
                "missing native property {k}"
            );
            continue;
        }
        ensure!(row(v, k)? == want, "loaded {k} differs");
    }
    let index_root = format!("{ROOT}/output/compact-indexes");
    let read_only: BTreeSet<_> = row(v, "ReadOnlyPaths")?.split_whitespace().collect();
    ensure!(
        row(v, "FragmentPath")? == format!("/run/systemd/system/{UNIT}")
            && row(v, "ReadWritePaths")? == ROOT
            && read_only == BTreeSet::from([TOKENS, index_root.as_str(), INPUT]),
        "loaded namespace differs"
    );
    let cache = CACHE;
    let binds: Vec<_> = row(v, "BindReadOnlyPaths")?.split_whitespace().collect();
    ensure!(binds.len() == 3, "wrong number of cached index mounts");
    for epoch in [250, 251] {
        let expected = format!("{cache}:{ROOT}/output/compact-indexes/{epoch}");
        ensure!(
            binds.iter().any(|actual| {
                actual
                    .strip_prefix(&expected)
                    .is_some_and(|tail| tail.is_empty() || tail == ":rbind")
            }),
            "cached index mount differs for {epoch}"
        );
    }
    let genesis_bind = format!("{GENESIS}:{ROOT}/output/genesis.tar.bz2");
    ensure!(
        binds.iter().any(|b| b
            .strip_prefix(&genesis_bind)
            .is_some_and(|tail| tail.is_empty() || tail == ":rbind")),
        "genesis bind differs"
    );
    let token = format!("{TOKENS}/${{INVOCATION_ID}}/guard-admission.json");
    ensure!(
        prestart_headers(raw)?
            == vec![
                (
                    "/usr/bin/sleep".into(),
                    "/usr/bin/sleep 60".into(),
                    "no".into()
                ),
                (
                    "/usr/bin/test".into(),
                    format!("/usr/bin/test -f {token}"),
                    "no".into()
                ),
                (
                    "/usr/bin/test".into(),
                    format!("/usr/bin/test ! -L {token}"),
                    "no".into()
                )
            ],
        "native prestart gate differs"
    );
    let source = templates()?.0;
    let exec = source
        .lines()
        .find_map(|s| s.strip_prefix("ExecStart="))
        .context("source command")?;
    ensure!(
        row(v, "ExecStart")?.contains(&format!(
            "{{ path={NODE} ; argv[]={exec} ; ignore_errors=no ;"
        )),
        "native replay command differs"
    );
    let expected: BTreeSet<_> = source
        .lines()
        .filter_map(|s| s.strip_prefix("Environment="))
        .map(|s| s.trim_matches('"').to_string())
        .collect();
    let actual: BTreeSet<_> = row(v, "Environment")?
        .split_whitespace()
        .map(|s| s.trim_matches('"').to_string())
        .collect();
    ensure!(actual == expected, "native environment differs");
    ensure!(
        !row(v, "UnsetEnvironment")?
            .split_whitespace()
            .any(|s| s == "INVOCATION_ID"),
        "manager invocation stripped"
    );
    Ok(())
}
fn property(status: &str, key: &str) -> Result<String> {
    let prefix = format!("{key}:");
    Ok(status
        .lines()
        .find_map(|s| s.strip_prefix(&prefix))
        .context("missing proc property")?
        .trim()
        .to_string())
}
fn mount_options(mountinfo: &str, path: &str) -> Result<BTreeSet<String>> {
    let mut selected = None;
    for row in mountinfo.lines() {
        let f: Vec<_> = row.split_whitespace().collect();
        ensure!(f.len() >= 7, "bad mountinfo");
        let m = f[4];
        if (path == m || path.starts_with(&format!("{}/", m.trim_end_matches('/'))))
            && selected.as_ref().is_none_or(|(len, _)| *len < m.len())
        {
            selected = Some((m.len(), f[5].split(',').map(str::to_string).collect()));
        }
    }
    Ok(selected.context("no applicable mount")?.1)
}
fn capture_namespace(n: &mut Native, id: &str, cp: u32) -> Result<()> {
    let expiry = Instant::now() + Duration::from_secs(2);
    loop {
        n.check()?;
        let (v, _) = n.show(UNIT, "")?;
        ensure!(pre(&v, id)? == cp, "control PID changed");
        let dir = PathBuf::from(format!("/proc/{cp}"));
        let read = || -> Result<(String, String, PathBuf)> {
            Ok((
                fs::read_to_string(dir.join("mountinfo"))?,
                fs::read_to_string(dir.join("status"))?,
                fs::canonicalize(dir.join("exe"))?,
            ))
        };
        if let Ok((mounts, status, exe)) = read() {
            let (v, _) = n.show(UNIT, "")?;
            ensure!(
                pre(&v, id)? == cp,
                "control PID changed after namespace read"
            );
            if exe == Path::new("/usr/bin/sleep").canonicalize()?
                && property(&status, "Uid")?
                    .split_whitespace()
                    .all(|x| x == "1000")
            {
                ensure!(
                    property(&status, "CapEff")? == "0000000000000000"
                        && property(&status, "Cpus_allowed_list")? == "0-15",
                    "setup process capability/CPU differs"
                );
                ensure!(
                    fs::canonicalize(dir.join("exe"))? == exe,
                    "setup executable changed"
                );
                for (p, opt) in [
                    (ROOT, "rw"),
                    (&format!("{ROOT}/tmp/isolated-empty-gcloud"), "rw"),
                    (TOKENS, "ro"),
                    (&format!("{ROOT}/output/compact-indexes/250"), "ro"),
                    (&format!("{ROOT}/output/compact-indexes/251"), "ro"),
                    ("/home/ubuntu/workspace", "ro"),
                    (SNAPSHOT, "ro"),
                    (&format!("{ROOT}/output/genesis.tar.bz2"), "ro"),
                ] {
                    ensure!(
                        mount_options(&mounts, p)?.contains(opt),
                        "bad setup mount {p}"
                    );
                }
                ensure!(
                    Instant::now() <= expiry,
                    "namespace readiness exceeded original two-second deadline"
                );
                save_at(&n.root, "setup-mountinfo.txt", mounts.as_bytes())?;
                save_at(&n.root, "setup-status.txt", status.as_bytes())?;
                return Ok(());
            }
        }
        ensure!(
            Instant::now() < expiry,
            "same setup child not ready within two seconds"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn validate_first_sample(
    s: &Value,
    a: &Value,
    id: &str,
    gid: &str,
    plan_sha: &str,
    started: u64,
) -> Result<()> {
    ensure!(
        s["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && s["producer_invocation_id"] == id
            && s["guard_invocation_id"] == gid
            && s["producer_stop_enabled"] == true,
        "guard owner/stop policy mismatch"
    );
    ensure!(
        s["plan"] == format!("{BOUND}/guard-plan.json")
            && s["plan_sha256"] == plan_sha
            && s["guard_sha256"] == GUARD_SHA,
        "guard provenance differs"
    );
    ensure!(
        s["minimum_free_bytes"] == a["guard_minimum_free_bytes"]
            && s["maximum_root_physical_bytes"] == CAP
            && s["maximum_worker_vmas"] == 3500000,
        "guard envelope differs"
    );
    for k in [
        "trip_reason",
        "worker_observation_error",
        "root_physical_observation_error",
        "target_handoff_error",
        "canary_target_error",
    ] {
        ensure!(s.get(k) == Some(&Value::Null), "guard reported {k}");
    }
    ensure!(
        s["workers"] == json!([])
            && s["root_physical_observation"].is_null()
            && s["producer"]["pid"] == 0
            && s["producer"]["active"] == "activating"
            && s["producer"]["sub"] == "start-pre",
        "guard sampled useful work before token"
    );
    ensure!(
        number(s, "available_bytes")? >= number(a, "required_initial_free_bytes")?
            && number(s, "recorded_unix_seconds")? >= started,
        "guard free space/freshness failed"
    );
    Ok(())
}
fn guard_journal(raw: &[u8], id: &str) -> Result<Vec<Value>> {
    let rows: Vec<Value> = std::str::from_utf8(raw)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        !rows.is_empty() && rows.len() < 16,
        "guard PID1 journal count"
    );
    for r in &rows {
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == GUARD_UNIT
                && r["INVOCATION_ID"] == id,
            "foreign guard journal identity"
        );
    }
    ensure!(
        rows.iter().any(|r| r["JOB_TYPE"] == "start"
            && r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with("Starting ")))
            && rows.iter().any(|r| r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.ends_with("Deactivated successfully.")))
            && rows.iter().any(|r| r["JOB_RESULT"] == "done"),
        "missing genuine PID1 guard lifecycle"
    );
    Ok(rows)
}
fn monotonic_us() -> Result<u64> {
    let mut v = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, v.as_mut_ptr()) } == 0,
        "monotonic clock"
    );
    let v = unsafe { v.assume_init() };
    Ok(v.tv_sec as u64 * 1000000 + v.tv_nsec as u64 / 1000)
}
fn timer_deadline(bytes: &[u8], clock: u64) -> Result<u64> {
    let s = std::str::from_utf8(bytes)?;
    let words: Vec<_> = s.split_whitespace().collect();
    ensure!(
        words.len() == 2 && words[0] == "t",
        "wrong typed timer deadline"
    );
    let next = words[1].parse::<u64>()?;
    ensure!(
        next > clock + 5000000,
        "timer next fire lacks required budget"
    );
    Ok(next)
}
fn preflight_launch(n: &mut Native, a: &Value, plan: &Value) -> Result<Vec<u8>> {
    validate_admission(a, plan)?;
    check_inputs()?;
    root_pristine()?;
    scope_census(n, a, false)?;
    for (p, mode) in [(TOKENS, 0o755), (RECEIPTS, 0o700)] {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir()
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o777 == mode
                && fs::read_dir(p)?.next().is_none(),
            "consumed or unsafe startup directory"
        );
    }
    absent(Path::new(BOUND))?;
    let prepared: Value = serde_json::from_slice(&small(&Path::new(STATE).join("prepared.json"))?)?;
    ensure!(
        prepared["schema"] == "horizon251-reboot-prepared-v1"
            && prepared["plan"] == *plan
            && prepared["worker_root"] == ROOT
            && prepared["replay_started"] == false,
        "invalid preparation"
    );
    ensure!(
        Path::new("/run/systemd/system").join(UNIT).read_link()? == Path::new(STATIC).join(UNIT),
        "producer link changed"
    );
    let extra = "ExecStart,ExecStartPre,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment,ReadWritePaths,ReadOnlyPaths,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,AllowedCPUs,CPUAffinity,TasksMax,RuntimeMaxUSec,PrivateNetwork,ProtectHome,ProtectSystem,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,Slice,BindReadOnlyPaths";
    let (v, raw) = n.show(UNIT, extra)?;
    validate_loaded(&v, &raw)?;
    for u in [GUARD_UNIT, TIMER] {
        absent(&Path::new("/run/systemd/system").join(u))?;
        let (v, _) = n.show(u, "")?;
        closed(&v)?;
        ensure!(row(&v, "LoadState")? == "not-found", "guard name consumed");
    }
    Ok(raw)
}
fn launch(n: &mut Native, a: &Value, plan: &Value, admission: &Value) -> Result<()> {
    let raw = preflight_launch(n, a, plan)?;
    save_at(&n.root, "producer-loaded.txt", &raw)?;
    // All setup and prerequisite checks finish before this single original clock.
    let started = now()?;
    n.deadline = Some(Instant::now() + Duration::from_secs(50));
    n.run("/usr/bin/systemctl", &["start", "--no-block", UNIT])?;
    let (v, raw) = n.show(UNIT, "")?;
    let id = row(&v, "InvocationID")?.to_string();
    let cp = pre(&v, &id)?;
    ensure!(cp > 0, "missing setup child");
    save_at(&n.root, "producer-initial.txt", &raw)?;
    capture_namespace(n, &id, cp)?;
    let gp = guard_plan(a, &id)?;
    let gr = save_at(&n.root, "guard-plan.json", &serde_json::to_vec_pretty(&gp)?)?;
    let (_, guard, timer) = templates()?;
    ensure!(
        guard.matches("@ACTUAL_SEALED_PLAN_SHA256@").count() == 1,
        "guard placeholder count"
    );
    let guard = guard.replace("@ACTUAL_SEALED_PLAN_SHA256@", text(&gr, "sha256")?);
    let sr = save_at(&n.root, "guard.service", guard.as_bytes())?;
    let tr = save_at(&n.root, "guard.timer", timer.as_bytes())?;
    n.seal(
        BOUND,
        vec![
            json!({"source":gr["path"],"name":"guard-plan.json","sha256":gr["sha256"],"mode":292}),
            json!({"source":sr["path"],"name":"guard.service","sha256":sr["sha256"],"mode":292}),
            json!({"source":tr["path"],"name":"guard.timer","sha256":tr["sha256"],"mode":292}),
        ],
        "guard-seal-plan.json",
    )?;
    n.run(
        GUARD,
        &[
            &format!("{BOUND}/guard-plan.json"),
            "--plan-sha256",
            text(&gr, "sha256")?,
            "--self-sha256",
            GUARD_SHA,
            "--validate-plan-only",
        ],
    )?;
    symlink(
        Path::new(BOUND).join("guard.service"),
        Path::new("/run/systemd/system").join(GUARD_UNIT),
    )?;
    symlink(
        Path::new(BOUND).join("guard.timer"),
        Path::new("/run/systemd/system").join(TIMER),
    )?;
    n.run("/usr/bin/systemctl", &["daemon-reload"])?;
    let (g, _) = n.show(GUARD_UNIT, "ExecStart")?;
    let (t, _) = n.show(TIMER, "Unit,NextElapseUSecMonotonic")?;
    ensure!(
        row(&g, "LoadState")? == "loaded"
            && row(&t, "LoadState")? == "loaded"
            && row(&g, "DropInPaths")?.is_empty()
            && row(&t, "DropInPaths")?.is_empty()
            && row(&g, "ExecStart")?.contains(text(&gr, "sha256")?)
            && row(&t, "Unit")? == GUARD_UNIT,
        "loaded guard graph differs"
    );
    pre(&n.show(UNIT, "")?.0, &id)?;
    n.run("/usr/bin/systemctl", &["start", TIMER])?;
    std::thread::sleep(Duration::from_secs(3));
    n.check()?;
    let (g, gb) = n.show(GUARD_UNIT, "ExecStart")?;
    let (t, tb) = n.show(TIMER, "Unit,NextElapseUSecMonotonic")?;
    let gid = row(&g, "InvocationID")?.to_string();
    ensure!(
        iid(&gid)
            && row(&g, "ActiveState")? == "inactive"
            && row(&g, "Result")? == "success"
            && row(&g, "ExecMainStatus")? == "0"
            && row(&g, "MainPID")? == "0"
            && row(&g, "ControlPID")? == "0"
            && row(&g, "Job")?.is_empty(),
        "first guard did not finish successfully"
    );
    ensure!(
        row(&t, "ActiveState")? == "active"
            && row(&t, "SubState")? == "waiting"
            && row(&t, "Unit")? == GUARD_UNIT
            && row(&t, "Job")?.is_empty()
            && iid(row(&t, "InvocationID")?),
        "timer not armed"
    );
    let sample = Path::new(RECEIPTS).join(format!("sample-{gid}.json"));
    let m = fs::symlink_metadata(&sample)?;
    ensure!(
        m.uid() == 0 && m.gid() == 0 && m.len() < 1 << 20,
        "unsafe first guard receipt"
    );
    let sb = small(&sample)?;
    let s: Value = serde_json::from_slice(&sb)?;
    validate_first_sample(&s, a, &id, &gid, text(&gr, "sha256")?, started)?;
    ensure!(
        !fs::read_dir(RECEIPTS)?
            .any(|r| r.is_ok_and(|x| x.file_name().to_string_lossy().contains("stop"))),
        "guard stop evidence exists"
    );
    let journal = n.run(
        "/usr/bin/journalctl",
        &[
            "--all",
            "--no-pager",
            "--output=json",
            &format!("--since=@{}", started.saturating_sub(1)),
            "_PID=1",
            &format!("UNIT={GUARD_UNIT}"),
            &format!("INVOCATION_ID={gid}"),
        ],
    )?;
    let journal_rows = guard_journal(&journal, &gid)?;
    let object = format!(
        "/org/freedesktop/systemd1/unit/{}",
        TIMER
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("_{:02x}", c as u32)
            })
            .collect::<String>()
    );
    let typed = n.run(
        "/usr/bin/busctl",
        &[
            "get-property",
            "org.freedesktop.systemd1",
            &object,
            "org.freedesktop.systemd1.Timer",
            "NextElapseUSecMonotonic",
        ],
    )?;
    timer_deadline(&typed, monotonic_us()?)?;
    let (v, pb) = n.show(UNIT, "")?;
    pre(&v, &id)?;
    let mut evidence = Vec::new();
    for (name, bytes) in [
        ("first-guard.txt", gb.as_slice()),
        ("first-timer.txt", tb.as_slice()),
        ("first-guard-PID1.jsonl", journal.as_slice()),
        ("timer-next.txt", typed.as_slice()),
        ("producer-before-token.txt", pb.as_slice()),
        ("actual-first-guard-sample.json", sb.as_slice()),
    ] {
        evidence.push(save_at(&n.root, name, bytes)?);
    }
    let token = json!({"schema":"horizon251-reboot-real-first-timer-guard-admission-v1","actual_invocation_id":id,"admission":admission,"first_guard_invocation_id":gid,"guard_sample":s,"guard_plan_sha256":gr["sha256"],"guard_sha256":GUARD_SHA,"native_evidence":evidence,"native_guard_events":journal_rows,"input_custody":pin(Path::new(AUTH))?,"actual_timer_invocation_id":row(&t,"InvocationID")?,"producer_before_and_after_first_guard_zero_restart_start_pre":true,"publication_authorized":false,"archive_mutations":false,"remote_mutations":false,"r2_mutations":false});
    let token_ref = save_at(
        &n.root,
        "guard-admission.json",
        &serde_json::to_vec_pretty(&token)?,
    )?;
    let token_dest = format!("{TOKENS}/{id}");
    absent(Path::new(&token_dest))?;
    validate_admission(a, plan)?;
    pre(&n.show(UNIT, "")?.0, &id)?;
    n.seal(&token_dest,vec![json!({"source":token_ref["path"],"name":"guard-admission.json","sha256":token_ref["sha256"],"mode":292})],"token-seal-plan.json")?;
    let (v, raw) = n.show(UNIT, "")?;
    pre(&v, &id)?;
    save_at(&n.root, "producer-after-token.txt", &raw)?;
    validate_admission(a, plan)?;
    n.check()?;
    let handoff = json!({"schema":"horizon251-reboot-guarded-startup-v2","recorded_unix_seconds":now()?,"producer":v,"guard_invocation_id":gid,"timer":t,"plan":plan,"admission":admission,"guard_plan":{"path":format!("{BOUND}/guard-plan.json"),"sha256":gr["sha256"]},"first_fire_token":{"path":format!("{token_dest}/guard-admission.json"),"sha256":token_ref["sha256"]},"remaining_original_setup_millis":n.deadline.unwrap().saturating_duration_since(Instant::now()).as_millis(),"transaction_replay_observed":false,"fifth_lane_experiment_accepted":true,"fifth_lane_fit_proven":true,"clean_1800_second_observer":true,"current_guard_receipts_verified":true,"remote_mutations":false});
    let r = save_at(
        &n.root,
        "guarded-startup-handoff.json",
        &serde_json::to_vec_pretty(&handoff)?,
    )?;
    n.check()?;
    println!(
        "{}",
        json!({"guarded_startup":r,"unit":UNIT,"invocation_id":id,"useful_replay_not_yet_observed":true})
    );
    Ok(())
}
fn plan_validate(p: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "horizon251-reboot-launch-plan-five-v1"
            && p["candidate_epoch"] == 251
            && p["worker_root"] == ROOT
            && p["state_directory"] == STATE
            && p["producer_unit"] == UNIT
            && p["guard_unit"] == GUARD_UNIT
            && p["timer_unit"] == TIMER
            && p["setup_seconds"] == 60
            && p["operator_deadline_seconds"] == 50
            && p["maximum_root_physical_bytes"] == CAP
            && p["memory_high_bytes"] == HIGH
            && p["memory_max_bytes"] == MAX
            && p["maximum_worker_vmas"] == 3500000
            && p["input_auth"] == pin(Path::new(AUTH))?
            && p["node_capability"] == json!({"path":NODE_PROBES,"sha256":NODE_PROBES_SHA})
            && p["static_seal"] == pin(&Path::new(STATIC).join("deployment-seal-receipt.json"))?
            && p["fifth_lane_experiment_required"] == true
            && p["fifth_lane_fit_proven"] == false,
        "unsupported launch plan"
    );
    ensure!(
        p["remote_mutations"] == false
            && p["archive_retirement_authorized"] == false
            && p["reuse_original_invocation_authorized"] == false,
        "foreign authority"
    );
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 5 && args[1] == "capture-admission" {
        return admission_source::capture(&args[2], &args[3], &args[4]);
    }
    if args.len() == 3 && args[1] == "emit-source-templates" {
        let root = Path::new(&args[2]);
        absent(root)?;
        fs::create_dir(root)?;
        let p = json!({"schema":"horizon251-reboot-launch-plan-five-v1","candidate_epoch":251,"worker_root":ROOT,"state_directory":STATE,"producer_unit":UNIT,"guard_unit":GUARD_UNIT,"timer_unit":TIMER,"setup_seconds":60,"operator_deadline_seconds":50,"maximum_root_physical_bytes":CAP,"memory_high_bytes":HIGH,"memory_max_bytes":MAX,"maximum_worker_vmas":3500000,"input_auth":{"path":AUTH,"sha256":AUTH_SHA},"node_capability":{"path":NODE_PROBES,"sha256":NODE_PROBES_SHA},"static_seal":{"path":format!("{STATIC}/deployment-seal-receipt.json"),"sha256":STATIC_RECEIPT_SHA},"fifth_lane_experiment_required":true,"fifth_lane_fit_proven":false,"remote_mutations":false,"archive_retirement_authorized":false,"reuse_original_invocation_authorized":false});
        let pref = save_at(root, "launch-plan.json", &serde_json::to_vec_pretty(&p)?)?;
        let executable = fs::canonicalize("/proc/self/exe")?;
        let deployment = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":Path::new(LAUNCHER).parent().context("launcher parent")?,"members":[{"source":executable,"name":"horizon251-launch5","sha256":hash(&executable)?,"mode":365},{"source":pref["path"],"name":"launch-plan.json","sha256":pref["sha256"],"mode":292}]});
        save_at(
            root,
            "deployment-plan.json",
            &serde_json::to_vec_pretty(&deployment)?,
        )?;
        let mut a = json!({"schema":"horizon251-reboot-main-admission-five-v1","candidate_epoch":251,"Main_accepted":false,"complete_native_census_reviewed":false,"all_other_obligations_preserved":false,"fifth_lane_experiment_accepted":false,"fifth_lane_fit_proven":false,"clean_1800_second_observer":false,"current_guard_receipts_verified":false,"no_overlapping_campaign_controller":false,"first_guard_before_useful_work_required":true,"issued_unix_seconds":0,"expires_unix_seconds":0,"observer_unix_seconds":0,"candidate_memory_max_bytes":MAX,"candidate_memory_high_bytes":HIGH,"candidate_root_cap_bytes":CAP,"candidate_control_memory_bytes":CONTROL,"guard_minimum_free_bytes":null,"required_initial_free_bytes":null,"century_floor_bytes":null,"memory_obligation_after_bytes":null,"host_memory_total_bytes":null,"observed_available_bytes":null,"actual_executing_before":4,"coexisting_services":[],"initializing_before":0,"proposed_replay_lanes":5,"proven_operating_count":4,"desired_replay_lanes":8,"live247_unit":LIVE247_UNIT,"live247_invocation_id":LIVE247_IID,"live247_handoff":{"path":LIVE247_HANDOFF,"sha256":LIVE247_HANDOFF_SHA},"live248_unit":LIVE248_UNIT,"live248_invocation_id":LIVE248_IID,"live248_handoff":{"path":LIVE248_HANDOFF,"sha256":LIVE248_HANDOFF_SHA},"live249_unit":LIVE249_UNIT,"live249_invocation_id":LIVE249_IID,"live250_unit":live::OWNERS[3].unit,"live250_invocation_id":live::OWNERS[3].iid,"live250_handoff":{"path":live::OWNERS[3].handoff,"sha256":live::OWNERS[3].handoff_sha},"live249_handoff":{"path":LIVE249_HANDOFF,"sha256":LIVE249_HANDOFF_SHA},"worker_root":ROOT,"producer_unit":UNIT,"guard_unit":GUARD_UNIT,"timer_unit":TIMER,"launch_plan":pref,"launcher_unit":"REPLACE_WITH_EXACT_LAUNCHER_UNIT.service","boot_id":"REPLACE","main_controller_pid":0,"main_controller_start_ticks":0,"evidence_claims":{}});
        for (source, fields) in evidence_fields() {
            a[source] = json!({"path":"REPLACE_WITH_ROOT_OWNED_EVIDENCE_PATH","sha256":"REPLACE_WITH_SHA256"});
            for field in fields {
                a["evidence_claims"][source][*field] = json!(format!("/{field}"));
            }
        }

        save_at(
            root,
            "admission-NOT-ACCEPTED.json",
            &serde_json::to_vec_pretty(&a)?,
        )?;
        println!(
            "{}",
            json!({"source_templates":root,"launch_authorized":false})
        );
        return Ok(());
    }
    ensure!(
        args.len() == 5 || args.len() == 7,
        "usage: horizon251-launch5 inspect|prepare|launch PLAN PLAN_SHA256 SELF_SHA256 [ADMISSION ADMISSION_SHA256]"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    ensure!(
        hash(Path::new("/proc/self/exe"))? == args[4],
        "self hash mismatch"
    );
    let plan_ref = json!({"path":args[2],"sha256":args[3]});
    let plan = bound(&plan_ref)?;
    plan_validate(&plan)?;
    check_inputs()?;
    templates()?;
    if args[1] == "inspect" {
        ensure!(args.len() == 5, "unexpected admission");
        root_pristine()?;
        println!(
            "{}",
            json!({"plan":plan_ref,"inputs_unchanged":true,"source_templates_unchanged":true,"no_units_changed":true,"launch_authorized":false})
        );
        return Ok(());
    }
    ensure!(
        args.len() == 7 && ["prepare", "preflight-launch", "launch"].contains(&args[1].as_str()),
        "unsupported command"
    );
    let admission_ref = json!({"path":args[5],"sha256":args[6]});
    let a = bound(&admission_ref)?;
    validate_admission(&a, &plan_ref)?;
    let lock_path = Path::new("/var/lib/jetstreamer/horizon251-fifth-20261118-launch.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path)?;
    ensure!(
        lock.metadata()?.uid() == 0
            && lock.metadata()?.nlink() == 1
            && lock.metadata()?.mode() & 0o077 == 0,
        "unsafe launch lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "launch lock busy"
    );
    if args[1] == "prepare" {
        directory(Path::new(STATE), 0, 0o700)?;
        directory(&Path::new(STATE).join("prepare"), 0, 0o700)?;
        let mut n = Native::new(Path::new(STATE).join("prepare"));
        prepare(&mut n, &a, &plan_ref, &admission_ref)?;
        // Publish the preparation envelope once at its stable parent location.
        let b = small(&n.root.join("prepared.json"))?;
        save_at(Path::new(STATE), "prepared.json", &b)?;
        println!("prepared fresh root and inactive producer; no replay launched");
    } else if args[1] == "preflight-launch" {
        directory(&Path::new(STATE).join("preflight-v1"), 0, 0o700)?;
        let mut n = Native::new(Path::new(STATE).join("preflight-v1"));
        preflight_launch(&mut n, &a, &plan_ref)?;
        println!("prepared state and loaded producer passed read-only preflight");
    } else {
        directory(&Path::new(STATE).join("launch-v1"), 0, 0o700)?;
        let mut n = Native::new(Path::new(STATE).join("launch-v1"));
        if let Err(error) = launch(&mut n, &a, &plan_ref, &admission_ref) {
            let _ = save_at(
                &n.root,
                "failure.json",
                &serde_json::to_vec(
                    &json!({"error":format!("{error:#}"),"original_attempt_not_retried":true,"token_may_be_absent":true,"automatic_retry_authorized":false}),
                )?,
            );
            return Err(error);
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captured_node_probes_reject_early_failure_or_changed_artifact() {
        let accepted: Value = serde_json::from_str(include_str!("../config-v3/node-input-probes.json")).unwrap();
        validate_node_probes(&accepted).unwrap();
        for pointer in ["/node/sha256", "/manifest/sha256", "/candidate_runtime_opt_in",
            "/fingerprint_rejection_passed", "/manifest_decoded_before_snapshot_filename_rejection",
            "/output_and_work_directories_empty", "/schema_terminal/ExecMainStatus",
            "/schema_terminal/InvocationID", "/fingerprint_terminal/InvocationID"] {
            let mut changed = accepted.clone();
            *changed.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(validate_node_probes(&changed).is_err(), "{pointer}");
        }
    }
    fn admission() -> Value {
        json!({"schema":"horizon251-reboot-main-admission-five-v1","candidate_epoch":251,"Main_accepted":true,"complete_native_census_reviewed":true,"all_other_obligations_preserved":true,"fifth_lane_experiment_accepted":true,"fifth_lane_fit_proven":true,"clean_1800_second_observer":true,"current_guard_receipts_verified":true,"no_overlapping_campaign_controller":true,"first_guard_before_useful_work_required":true,"issued_unix_seconds":1000,"expires_unix_seconds":1200,"observer_unix_seconds":900,"candidate_memory_max_bytes":MAX,"candidate_memory_high_bytes":HIGH,"candidate_root_cap_bytes":CAP,"candidate_control_memory_bytes":CONTROL,"guard_minimum_free_bytes":3000000000000u64,"required_initial_free_bytes":3000000000000u64+CAP,"century_floor_bytes":200000000000u64,"memory_obligation_after_bytes":RETAINED_MEMORY_OBLIGATION,"host_memory_total_bytes":1212136964096u64,"actual_executing_before":4,"coexisting_services":[],"initializing_before":0,"proposed_replay_lanes":5,"proven_operating_count":4,"desired_replay_lanes":8,"live247_unit":LIVE247_UNIT,"live247_invocation_id":LIVE247_IID,"live247_handoff":{"path":LIVE247_HANDOFF,"sha256":LIVE247_HANDOFF_SHA},"live248_unit":LIVE248_UNIT,"live248_invocation_id":LIVE248_IID,"live249_unit":LIVE249_UNIT,"live249_invocation_id":LIVE249_IID,"live250_unit":live::OWNERS[3].unit,"live250_invocation_id":live::OWNERS[3].iid,"live250_handoff":{"path":live::OWNERS[3].handoff,"sha256":live::OWNERS[3].handoff_sha},"worker_root":ROOT,"producer_unit":UNIT,"guard_unit":GUARD_UNIT,"timer_unit":TIMER})
    }
    #[test]
    fn accepted_envelope() {
        admission_values(&admission(), 1100).unwrap();
    }
    #[test]
    fn each_live_handoff_must_bind_its_actual_invocation_and_guard_token() {
        for (schema, unit, invocation) in [
            (
                "horizon247-reboot-guarded-startup-v1",
                LIVE247_UNIT,
                LIVE247_IID,
            ),
            (
                "horizon248-reboot-guarded-startup-v1",
                LIVE248_UNIT,
                LIVE248_IID,
            ),
            (
                "horizon249-reboot-guarded-startup-v1",
                LIVE249_UNIT,
                LIVE249_IID,
            ),
        ] {
            let v = json!({"schema":schema,"producer":{"Id":unit,"InvocationID":invocation},"first_fire_token":{"path":"/sealed/token.json","sha256":"a".repeat(64)}});
            live_handoff_values(&v, schema, unit, invocation).unwrap();
            for (field, value) in [
                ("schema", json!("wrong")),
                ("producer", json!({"Id":unit,"InvocationID":"old"})),
                ("first_fire_token", json!({"path":"/sealed/token.json"})),
            ] {
                let mut changed = v.clone();
                changed[field] = value;
                assert!(live_handoff_values(&changed, schema, unit, invocation).is_err());
            }
        }
    }
    #[test]
    fn restored_251_recipe_keeps_both_sealed_index_mounts_and_read_only_input() {
        let (producer, guard, timer) = templates().unwrap();
        assert!(producer.contains("AllowedCPUs=0-15"));
        assert!(producer.contains(&format!("--snapshot-archive={SNAPSHOT}")));
        for epoch in [250, 251] {
            assert!(producer.contains(&format!("{CACHE}:{ROOT}/output/compact-indexes/{epoch}")));
        }
        assert!(producer.contains(&format!(
            "ReadOnlyPaths={TOKENS} {ROOT}/output/compact-indexes {INPUT}"
        )));
        assert!(!producer.contains("qualification-249-general-shrink-debt-budget506-e3f15eb2-v1"));
        assert!(guard.contains(&format!("{BOUND}/guard-plan.json")));
        assert!(timer.contains(GUARD_UNIT));
    }
    #[test]
    fn fifth_lane_requires_four_live_predecessors_and_bookings() {
        for (field, value) in [
            ("actual_executing_before", json!(0)),
            ("fifth_lane_experiment_accepted", json!(false)),
            ("fifth_lane_fit_proven", json!(false)),
            ("clean_1800_second_observer", json!(false)),
            ("current_guard_receipts_verified", json!(false)),
            ("proposed_replay_lanes", json!(1)),
            ("desired_replay_lanes", json!(3)),
            ("proven_operating_count", json!(5)),
            ("live247_invocation_id", json!("wrong")),
            ("live248_invocation_id", json!("wrong")),
            ("live249_invocation_id", json!("wrong")),
            ("live250_invocation_id", json!("wrong")),
            (
                "memory_obligation_after_bytes",
                json!(RETAINED_MEMORY_OBLIGATION - 1),
            ),
            (
                "guard_minimum_free_bytes",
                json!(RETAINED_ROOT_OBLIGATION - 1),
            ),
        ] {
            let mut a = admission();
            a[field] = value;
            if field == "guard_minimum_free_bytes" {
                a["required_initial_free_bytes"] = json!(RETAINED_ROOT_OBLIGATION - 1 + CAP);
            }
            assert!(admission_values(&a, 1100).is_err(), "{field}");
        }
    }
    #[test]
    fn no_stale_or_unaccepted_admission() {
        let mut a = admission();
        assert!(admission_values(&a, 1300).is_err());
        assert!(admission_values(&a, 999).is_err());
        a["Main_accepted"] = json!(false);
        assert!(admission_values(&a, 1100).is_err());
    }
    #[test]
    fn accounting_fail_closed() {
        for k in [
            "candidate_memory_max_bytes",
            "candidate_root_cap_bytes",
            "required_initial_free_bytes",
            "memory_obligation_after_bytes",
            "proposed_replay_lanes",
            "operator_deadline_seconds",
        ] {
            if k == "operator_deadline_seconds" {
                continue;
            }
            let mut a = admission();
            a[k] = json!(0);
            assert!(admission_values(&a, 1100).is_err(), "{k}");
        }
    }
    #[test]
    fn strict_native_prestart_sequence() {
        let raw=b"ExecStartPre={ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep 60 ; ignore_errors=no ; pid=0 }\nExecStartPre={ path=/usr/bin/test ; argv[]=/usr/bin/test -f /token ; ignore_errors=no ; pid=0 }";
        assert_eq!(prestart_headers(raw).unwrap().len(), 2);
        assert!(prestart_headers(b"ExecStartPre=unknown").is_err());
    }
    #[test]
    fn mount_selection_is_most_specific() {
        let raw = "1 0 8:0 / / ro - x x ro\n2 1 8:0 / /home rw - x x rw\n3 2 8:0 / /home/token ro - x x ro";
        assert!(mount_options(raw, "/home/root").unwrap().contains("rw"));
        assert!(mount_options(raw, "/home/token/id").unwrap().contains("ro"));
    }
    #[test]
    fn typed_timer_budget() {
        assert_eq!(timer_deadline(b"t 16000000", 10000000).unwrap(), 16000000);
        assert!(timer_deadline(b"s 16000000", 10000000).is_err());
        assert!(timer_deadline(b"t 15000000", 10000000).is_err());
    }
    fn sample() -> Value {
        json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","producer_invocation_id":"a".repeat(32),"guard_invocation_id":"b".repeat(32),"producer_stop_enabled":true,"plan":format!("{BOUND}/guard-plan.json"),"plan_sha256":"c".repeat(64),"guard_sha256":GUARD_SHA,"minimum_free_bytes":3000000000000u64,"maximum_root_physical_bytes":CAP,"maximum_worker_vmas":3500000,"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"target_handoff_error":null,"canary_target_error":null,"workers":[],"root_physical_observation":null,"producer":{"pid":0,"active":"activating","sub":"start-pre"},"available_bytes":4000000000000u64,"recorded_unix_seconds":1100})
    }
    #[test]
    fn genuine_first_sample() {
        validate_first_sample(
            &sample(),
            &admission(),
            &"a".repeat(32),
            &"b".repeat(32),
            &"c".repeat(64),
            1100,
        )
        .unwrap();
    }
    #[test]
    fn reject_old_owner_trip_early_worker_and_missing_checks() {
        for k in [
            "producer_invocation_id",
            "guard_invocation_id",
            "trip_reason",
            "root_physical_observation",
            "worker_observation_error",
        ] {
            let mut s = sample();
            s[k] = json!("wrong");
            assert!(
                validate_first_sample(
                    &s,
                    &admission(),
                    &"a".repeat(32),
                    &"b".repeat(32),
                    &"c".repeat(64),
                    1100
                )
                .is_err(),
                "{k}"
            );
        }
        let mut s = sample();
        s["producer"]["pid"] = json!(123);
        assert!(
            validate_first_sample(
                &s,
                &admission(),
                &"a".repeat(32),
                &"b".repeat(32),
                &"c".repeat(64),
                1100
            )
            .is_err()
        );
    }
    #[test]
    fn deadline_expiration_prevents_command() {
        let mut n = Native::new(PathBuf::from("/nonexistent"));
        n.deadline = Some(Instant::now() - Duration::from_secs(1));
        assert!(n.run("/usr/bin/true", &[]).is_err());
    }
    #[test]
    fn closed_timer_allows_only_absent_service_properties() {
        let mut v: BTreeMap<String, String> = [
            ("Id", "unused.timer"),
            ("LoadState", "loaded"),
            ("ActiveState", "inactive"),
            ("Job", ""),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        closed(&v).unwrap();
        v.insert("MainPID".into(), "2".into());
        assert!(closed(&v).is_err());
        v.remove("MainPID");
        v.insert("ActiveState".into(), "active".into());
        assert!(closed(&v).is_err());
        v.insert("ActiveState".into(), "inactive".into());
        v.insert("Id".into(), "unused.service".into());
        assert!(closed(&v).is_err());
        v.insert("LoadState".into(), "not-found".into());
        closed(&v).unwrap();
    }
    #[test]
    fn start_pre_rejects_changed_owner_and_started_worker() {
        let id = "a".repeat(32);
        let mut v: BTreeMap<String, String> = [
            ("InvocationID", id.as_str()),
            ("ActiveState", "activating"),
            ("SubState", "start-pre"),
            ("MainPID", "0"),
            ("ControlPID", "123"),
            ("NRestarts", "0"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        assert_eq!(pre(&v, &id).unwrap(), 123);
        assert!(pre(&v, &"b".repeat(32)).is_err());
        v.insert("MainPID".into(), "456".into());
        assert!(pre(&v, &id).is_err());
    }
    #[test]
    fn journal_requires_actual_pid1_complete_guard_lifecycle() {
        let id = "b".repeat(32);
        let rows = [
            json!({"_PID":"1","_UID":"0","UNIT":GUARD_UNIT,"INVOCATION_ID":id,"JOB_TYPE":"start","MESSAGE":"Starting guard"}),
            json!({"_PID":"1","_UID":"0","UNIT":GUARD_UNIT,"INVOCATION_ID":id,"MESSAGE":"guard: Deactivated successfully."}),
            json!({"_PID":"1","_UID":"0","UNIT":GUARD_UNIT,"INVOCATION_ID":id,"JOB_RESULT":"done"}),
        ];
        let encode = |rs: &[Value]| {
            rs.iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        };
        guard_journal(encode(&rows).as_bytes(), &id).unwrap();
        assert!(guard_journal(encode(&rows[..2]).as_bytes(), &id).is_err());
        let mut bad = rows.clone();
        bad[0]["_PID"] = json!("2");
        assert!(guard_journal(encode(&bad).as_bytes(), &id).is_err());
        assert!(guard_journal(encode(&rows).as_bytes(), &"c".repeat(32)).is_err());
    }
    #[test]
    fn admission_evidence_must_agree_with_each_numeric_claim() {
        let mut a = admission();
        a["observed_available_bytes"] = json!(4000000000000u64);
        a["boot_id"] = json!("test-boot");
        a["main_controller_pid"] = json!(100);
        a["main_controller_start_ticks"] = json!(1000);
        let mut docs = BTreeMap::new();
        for (source, fields) in evidence_fields() {
            let mut d = json!({});
            for field in fields {
                d[*field] = a[*field].clone();
                a["evidence_claims"][source][*field] = json!(format!("/{field}"));
            }
            docs.insert(source.to_string(), d);
        }
        evidence_claims(&a, &docs).unwrap();
        docs.get_mut("capacity").unwrap()["memory_obligation_after_bytes"] = json!(1);
        assert!(evidence_claims(&a, &docs).is_err());
    }
}
