//! Metadata-only qualification of one obsolete Full204 anchor replica.
//!
//! This command never opens archive bodies, locks, contacts R2, creates receipts
//! or retires anything. It reports current retention/consumer gates for a later
//! independently qualified executor. Historical Full/Plugin/boundary receipts
//! remain mandatory. In particular, scan204 is a retained Full205 dependency.
use super::*;
use serde_json::json;
use std::{
    collections::BTreeMap,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    process::Command as Process,
};

#[path = "scan203_retirement.rs"]
pub(super) mod retirement;

#[cfg(test)]
#[path = "scan203_retention_tests.rs"]
mod tests;

const ROOT: &str = "/var/lib/jetstreamer/horizon-204-assembly-full-attempt-3-scan-v1";
const SOURCE: &str =
    "/var/lib/jetstreamer/horizon-204-assembly-full-attempt-3-scan-v1/epoch-203.jet";
const RETAINED: &str =
    "/var/lib/jetstreamer/horizon-204-assembly-full-attempt-3-scan-v1/epoch-204.jet";
const SHA203: &str = "7efb3b28b2761cd646d20fa282d87c508249488fd0fb27ce8e033a1aed7d39ad";
const SHA204: &str = "6287d3ec1f56a3fbcba279f284279b36f0aa5d474dcc17e1fd1ea921b8413a0a";
const LENGTH203: u64 = 103_802_397_352;
const LENGTH204: u64 = 114_228_848_867;
const UNIT: &str = "horizon-scan203-retention-inspect-v1.service";
const MAX_METADATA: u64 = 8 << 20;
const ACTORS: [&str; 4] = [
    "horizon-full-verify-204-assembly-recovery-v2-attempt-3.service",
    "horizon-plugin-verify-204-assembly-recovery-v2.service",
    "horizon-import-204-assembly-recovery-v2.service",
    "horizon-upload-204-assembly-recovery-v2.service",
];
const ORIGINALS: [(&str, &str, &str); 4] = [
    (
        "955395745a2449d783f492cb874bb0e8",
        "/var/lib/jetstreamer/horizon-204-assembly-full-attempt-3-terminal-v1/terminal.json",
        "697711d84f8cfeff7272066b4f55c9f32aa8d876cba29c539d48f1e5341cd851",
    ),
    (
        "7a53366ef6444f92912deb0e1abab4e4",
        "/var/lib/jetstreamer/horizon-204-assembly-plugin-full3-terminal-v3/terminal.json",
        "04408b8866eadcd8499a4005a96e167788285d5c7d5538f84b6a0d92d287203e",
    ),
    (
        "7100265316ee4f499f5a3a94232e3d37",
        "/var/lib/jetstreamer/horizon-204-assembly-import-full3-terminal-v4/terminal.json",
        "dc478f77cce9035d63c56027dace3c7dabca697458a84fa56de5790d250ce492",
    ),
    (
        "a7a3965b4c834be48237333a6cfd114e",
        "/var/lib/jetstreamer/horizon-204-assembly-upload-full3-terminal-v2/terminal.json",
        "eec7268f4cc2b85b35d700aa92070f9132b73d3e2658dd26e2b44bf9b6f3f253",
    ),
];
const DEPENDENCIES: [(&str, &str); 6] = [
    (
        "/var/lib/jetstreamer/horizon-204-assembly-full-attempt-3-spec-v1/stage-spec.json",
        "b05ee39cea593c79922d97cb5721bcac649381e4b385559c4725fdd0f99d22bf",
    ),
    (
        "/var/lib/jetstreamer/horizon-204-assembly-plugin-full3-spec-v3/stage-spec.json",
        "3c81a1f3db9fd30b5924a483b16ada0b9c801da8072af49ce5d50f4d85085c8f",
    ),
    (
        "/var/lib/jetstreamer/horizon-204-assembly-import-full3-spec-v4/stage-spec.json",
        "54189d9e50403308f455754f7844c3d36286ade810216b53787065c37c8e0918",
    ),
    (
        "/var/lib/jetstreamer/horizon-204-assembly-upload-full3-spec-v2/stage-spec.json",
        "668dabb99feab88759380b9b31cb8b88de315edee46cad7c2f6e88bacfd5fce2",
    ),
    (
        "/var/lib/jetstreamer/horizon-205-delivery-full-spec-v3/stage-spec.json",
        "80503a825c2fb51fb5eee124695e1c995345ee9c6f7aa2a828803e2794636e34",
    ),
    (
        "/var/lib/jetstreamer/horizon-205-delivery-full-retry-spec-v5/stage-spec.json",
        "563287a0bcc72fc052b00b75048717dd53266b151038f78f93bc4c71f2c5c887",
    ),
];

type Bound = reserve_stop::Bound;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Parent {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

fn parent(expected: &Parent) -> Result<()> {
    let path = Path::new(ROOT);
    ensure!(path.canonicalize()? == path, "scan parent alias");
    let m = fs::symlink_metadata(path)?;
    let actual = Parent {
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
    };
    ensure!(
        m.is_dir() && actual == *expected && actual.uid == 0 && actual.mode & 0o022 == 0,
        "scan parent identity/custody changed"
    );
    Ok(())
}
impl Stamp {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            length: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode() & 0o7777,
            links: m.nlink(),
            mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            ctime_ns: i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
        }
    }
    fn fixed(&self, inode: u64, length: u64) -> Result<()> {
        ensure!(
            self.inode == inode
                && self.length == length
                && self.uid == 0
                && self.mode == 0o400
                && self.links == 1
                && self.device > 0,
            "foreign scan replica identity/custody"
        );
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    invocation_id: String,
    original_terminal: Bound,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    parent_identity: Parent,
    source_identity: Stamp,
    retained204_identity: Stamp,
    normal203_gates: Bound,
    normal203_completion: Bound,
    verification203: Bound,
    publication203: Bound,
    remote_receipt203: Bound,
    full204_outcome: Bound,
    // The exact current recipe is separate from terminal historical consumers.
    executor_recipe: Bound,
    actors: BTreeMap<String, Actor>,
    historical_recipes: Vec<Bound>,
    // Include indirectly named stage plans/specs. These bindings are retained,
    // never unlinked or rewritten to make the staged scan appear closed.
    dependency_metadata: Vec<Bound>,
}

fn scope(p: &Plan) -> Result<()> {
    scope_for(p, UNIT)
}

fn scope_for(p: &Plan, executor_unit: &str) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-scan203-retention-inspection-plan-v1",
        "foreign inspection profile"
    );
    p.source_identity.fixed(10_796_937, LENGTH203)?;
    p.retained204_identity.fixed(10_796_926, LENGTH204)?;
    ensure!(
        p.source_identity.device == p.retained204_identity.device
            && p.parent_identity.device == p.source_identity.device
            && p.parent_identity.uid == 0
            && p.parent_identity.mode & 0o022 == 0
            && p.source_identity.inode != p.retained204_identity.inode,
        "scan replicas alias or filesystem changed"
    );
    ensure!(
        p.actors.len() <= 256
            && ACTORS.iter().all(|u| p.actors.contains_key(*u))
            && !p.actors.contains_key(executor_unit)
            && p.historical_recipes.len() <= 4096
            && p.dependency_metadata.len() <= 4096,
        "incomplete or excessive historical consumer scope"
    );
    for (name, actor) in &p.actors {
        ensure!(
            unit_name(name) && is_lower_hex(&actor.invocation_id, 32),
            "invalid historical consumer identity"
        );
    }
    for (index, name) in ACTORS.iter().enumerate() {
        let (iid, path, sha) = ORIGINALS[index];
        let actor = &p.actors[*name];
        ensure!(
            actor.invocation_id == iid
                && actor.original_terminal.path == Path::new(path)
                && actor.original_terminal.sha256 == sha,
            "original Full3 downstream terminal changed"
        );
    }
    let dependencies = p
        .dependency_metadata
        .iter()
        .map(|b| (b.path.clone(), b.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        dependencies.len() == p.dependency_metadata.len()
            && DEPENDENCIES
                .iter()
                .all(|(path, sha)| dependencies.get(Path::new(path)) == Some(sha)),
        "original Full204/Full205 dependency metadata omitted or changed"
    );
    ensure!(
        p.executor_recipe.path == Path::new("/etc/systemd/system").join(executor_unit),
        "executor recipe must be the exact installed inspection service"
    );
    Ok(())
}

fn unit_name(s: &str) -> bool {
    s.len() <= 255
        && (s.ends_with(".service") || s.ends_with(".timer"))
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
}

fn metadata_bytes(b: &Bound) -> Result<Vec<u8>> {
    ensure!(
        b.path.is_absolute() && b.path.canonicalize()? == b.path && is_lower_hex(&b.sha256, 64),
        "aliased/invalid metadata binding"
    );
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= MAX_METADATA,
        "unsafe/oversized retention metadata"
    );
    let before = Stamp::of(&m);
    let bytes = read_stable_bounded(&b.path, MAX_METADATA, "scan203 retention metadata")?;
    ensure!(
        Stamp::of(&fs::symlink_metadata(&b.path)?) == before
            && hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "retention metadata changed"
    );
    Ok(bytes)
}
fn saved(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&metadata_bytes(b)?)?)
}
fn fixed(b: &Bound, path: &str, sha: &str) -> Result<Value> {
    ensure!(
        b.path == Path::new(path) && b.sha256 == sha,
        "foreign historical gate binding"
    );
    saved(b)
}

fn gate_words(value: &Value, expected: &[&str]) -> Result<()> {
    let b: Bound = serde_json::from_value(json!({"path":value["path"],"sha256":value["sha256"]}))?;
    let bytes = metadata_bytes(&b)?;
    ensure!(
        std::str::from_utf8(&bytes)?
            .split_whitespace()
            .collect::<Vec<_>>()
            == expected,
        "historical full/plugin/boundary receipt words differ"
    );
    ensure!(
        value["words"] == json!(expected),
        "historical gate summary differs from receipt"
    );
    Ok(())
}

fn gates(p: &Plan) -> Result<Value> {
    let g = fixed(
        &p.normal203_gates,
        "/var/lib/jetstreamer/horizon-canonical203-legacy-boundary-v1/normal-retirement-gates.json",
        "013a6eb306fecb90812ca5460a1bfb5d97781c8a40bd0b18cdab3d0b646076fb",
    )?;
    let completion = fixed(
        &p.normal203_completion,
        "/var/lib/jetstreamer/horizon-canonical203-legacy-boundary-v1/completion.json",
        "bab43bb9c79afe399ccb6f8fb0734da65e536450ae0d1a2e53907cce11fa0aaa",
    )?;
    let v = fixed(
        &p.verification203,
        "/var/lib/jetstreamer/horizon-203-private-scan-20261023-v1/verification.json",
        "0217aaeacae219a0808fadf9182b10859ff53a7b4411ccfacc31005c6942dc1b",
    )?;
    let publication = fixed(
        &p.publication203,
        "/var/lib/jetstreamer/horizon-203-published-artifact-20261023-v1/publication/publication.json",
        "03ec7af11d336bee4f24adb68f4f87e43630c070e117093c3bdade6ff800853f",
    )?;
    let r2 = fixed(
        &p.remote_receipt203,
        "/home/ubuntu/.jetstreamer-private/r2-receipts/epoch-203.r2.json",
        "d4222cd99f521700c12bb8227722d1cbecf90c5c1f48d66a22b7bb65f20d26c4",
    )?;
    let full204 = fixed(
        &p.full204_outcome,
        "/var/lib/jetstreamer/horizon-204-assembly-full-attempt-3-output-v1/outcome.json",
        "bf85c87ba20bc6e0bad11b917bee9f1fe5055bc87b4c16f790035281a8d1f9c1",
    )?;
    ensure!(
        p.full204_outcome.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-204-assembly-full-attempt-3-output-v1/outcome.json"
            )
            && full204["stage"] == "full"
            && full204["passed"] == true
            && full204["archive_sha256"] == SHA204
            && full204["archive_bytes"] == LENGTH204
            && full204["commands"][0]["arguments"] == json!([SOURCE])
            && full204["commands"][0]["exit_code"] == 0,
        "original203 anchor decoding/strict204 Full lineage differs"
    );
    ensure!(
        g["schema"] == "canonical203-normal-retirement-actual-gates-v1"
            && completion["schema"] == "canonical203-normal-local-retirement-completed-v1"
            && completion["epoch"] == 203
            && completion["all_remote_objects_preserved"] == true
            && v["epoch"] == 203
            && v["archive_sha256"] == SHA203
            && v["current_plugin_verification_passed"] == true
            && v["independent_final_archive_verification_passed"] == true
            && publication["committed"] == true
            && publication["epoch"] == 203
            && publication["archive_sha256"] == SHA203
            && publication["archive_bytes"] == LENGTH203
            && r2["schema"] == RECEIPT_SCHEMA
            && r2["epoch"] == 203
            && r2["archive_sha256"] == SHA203
            && r2["archive_length"] == LENGTH203
            && r2["remote_sha256_readback"] == true,
        "completed203 publication/verification/remote evidence differs"
    );
    let entries = &g["normal_full_plugin_both_adjacent_boundaries_match"];
    gate_words(
        &entries["full"],
        &[
            SHA203,
            "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9",
            "5ae7edd93d29636fd959b40698bff0897e4cb3b87245054b67636d61cc8f3be9",
        ],
    )?;
    gate_words(
        &entries["plugin"],
        &[
            SHA203,
            "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547",
            "5ae7edd93d29636fd959b40698bff0897e4cb3b87245054b67636d61cc8f3be9",
        ],
    )?;
    gate_words(
        &entries["left"],
        &[
            "c586af905a9c2b844879ac026fd4c345587f612467228a0d3b23d6a8a7a275a2",
            SHA203,
            "0ef9f58029a96a56d21e8eb8c68708722b5c45e29ef36121fd82750c860804f8",
            "759303845dff560ea6e26c50dbcab16ff0e8527dd5f2c5a331d180d3d7ebe27c",
        ],
    )?;
    gate_words(
        &entries["right"],
        &[
            SHA203,
            SHA204,
            "9af8147955915740e64705b8cea2685c342f921e44c6cff7aa726e3ad1d8f23e",
            "b24fb16b83eddb168d2c3d05fba66f8bd5fae818bb977a92418edfc786e7af37",
        ],
    )?;
    // Absence of an already normally retired canonical203 is expected. Never
    // restore a103GB archive merely to satisfy this metadata-only inspection.
    for suffix in ["", ".sha256"] {
        absent(Path::new(&format!(
            "/home/ubuntu/horizon/epoch-203.jet{suffix}"
        )))?;
    }
    Ok(
        json!({"normal_gates":p.normal203_gates,"normal_completion":p.normal203_completion,
        "verification":p.verification203,"publication":p.publication203,
        "remote_receipt":p.remote_receipt203,"fresh_remote_observation":false,
        "cleanup_authority":"horizon-r2 mandatory local cleanup after completion; last dependency must end",
        "old_scope_preservation_was_not_a_permanent_user_retention_request":true}),
    )
}

fn absent(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("unexpected canonical203 replacement; reconcile its consumers first"),
    }
}

fn replica(path: &Path, expected: &Stamp) -> Result<()> {
    ensure!(path.canonicalize()? == path, "replica path alias");
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && Stamp::of(&m) == *expected,
        "replica tuple changed"
    );
    Ok(())
}

fn historical_pair(v: &Value, unit: &str, iid: &str) -> bool {
    let direct = [
        ("unit", "invocation_id"),
        ("Id", "InvocationID"),
        ("UNIT", "INVOCATION_ID"),
    ]
    .iter()
    .any(|(u, i)| v[*u] == unit && v[*i] == iid);
    direct
        || match v {
            Value::Object(m) => m.values().any(|v| historical_pair(v, unit, iid)),
            Value::Array(a) => a.iter().any(|v| historical_pair(v, unit, iid)),
            _ => false,
        }
}

fn properties(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    ensure!(bytes.len() <= 131072, "manager reply bound");
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let (k, v) = line.split_once('=').context("manager scalar shape")?;
        ensure!(
            result.insert(k.to_string(), v.to_string()).is_none(),
            "duplicate manager property"
        );
    }
    Ok(result)
}

fn manager_capture(label: &str) -> Result<File> {
    use std::os::fd::FromRawFd;
    let name = std::ffi::CString::new(label)?;
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    ensure!(
        fd >= 0,
        "manager metadata capture failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn typed_empty_commands(bytes: &[u8]) -> Result<()> {
    let v: Value = serde_json::from_slice(bytes)?;
    ensure!(
        v == json!({"type":"a(sasbttttuii)","data":[]}),
        "missing command property has no exact typed empty-array proof"
    );
    Ok(())
}

fn empty_manager_command(unit: &str, property: &str) -> Result<String> {
    ensure!(
        unit_name(unit) && unit.ends_with(".service"),
        "invalid service"
    );
    ensure!(
        [
            "ExecCondition",
            "ExecStartPre",
            "ExecStartPost",
            "ExecStop",
            "ExecStopPost",
            "ExecReload"
        ]
        .contains(&property),
        "unsupported empty command property"
    );
    let object = format!(
        "/org/freedesktop/systemd1/unit/{}",
        unit.bytes()
            .map(|b| if b.is_ascii_alphanumeric() {
                char::from(b).to_string()
            } else {
                format!("_{b:02x}")
            })
            .collect::<String>()
    );
    let mut out = manager_capture("scan203-empty-command")?;
    let status = Process::new("/usr/bin/timeout")
        .args([
            "--signal=KILL",
            "5s",
            "/usr/bin/busctl",
            "--timeout=2s",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            &object,
            "org.freedesktop.systemd1.Service",
            property,
        ])
        .stdout(out.try_clone()?)
        .stderr(std::process::Stdio::null())
        .status()?;
    ensure!(
        status.success(),
        "typed empty command request failed: {unit} {property}"
    );
    out.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    (&out).take(16385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16384, "typed command proof bound");
    typed_empty_commands(&bytes)?;
    Ok(String::from_utf8(bytes)?)
}

fn manager(unit: &str) -> Result<BTreeMap<String, String>> {
    ensure!(unit_name(unit), "unsafe manager unit");
    // timeout also bounds a wedged PID1 request. Small fixed property selection;
    // Anonymous memory files avoid pipe deadlocks and writable-mount exceptions.
    let mut stdout = manager_capture("scan203-manager-stdout")?;
    let mut stderr = manager_capture("scan203-manager-stderr")?;
    let status = Process::new("/usr/bin/timeout").args(["--signal=KILL","5s","/usr/bin/systemctl",
        "show",unit,"--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Restart,Job,Result,ExecMainStatus,ControlGroup,Triggers,TriggeredBy,ExecStart,ExecCondition,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,ExecReload,OnSuccess,OnFailure,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,RuntimeMaxUSec"])
        .stdout(stdout.try_clone()?).stderr(stderr.try_clone()?).status()?;
    ensure!(
        matches!(status.code(), Some(0 | 1 | 4)),
        "manager command failed/timed out"
    );
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut out = Vec::new();
    (&stdout).take(131073).read_to_end(&mut out)?;
    let mut err = Vec::new();
    (&stderr).take(16385).read_to_end(&mut err)?;
    ensure!(err.len() <= 16384, "manager stderr bound");
    let mut p = properties(&out)?;
    if !status.success() {
        let e = std::str::from_utf8(&err)?.trim();
        ensure!(
            p.get("LoadState").map(String::as_str) == Some("not-found")
                && (e.is_empty()
                    || e == format!("Unit {unit} could not be found.")
                    || e == format!("Failed to get properties: Unit {unit} not found.")),
            "manager failure is not genuine not-found"
        );
    }
    if unit.ends_with(".service") && p.get("LoadState").map(String::as_str) == Some("loaded") {
        for key in [
            "ExecCondition",
            "ExecStartPre",
            "ExecStartPost",
            "ExecStop",
            "ExecStopPost",
            "ExecReload",
        ] {
            if !p.contains_key(key) {
                // systemctl omits empty complex arrays. Preserve a real typed
                // D-Bus proof; absence alone never becomes an empty command.
                let proof = empty_manager_command(unit, key)?;
                p.insert(format!("NativeEmptyCommandProof:{key}"), proof);
                p.insert(key.into(), String::new());
            }
        }
    }
    Ok(p)
}

fn terminal(p: &BTreeMap<String, String>, name: &str, iid: &str) -> Result<()> {
    let get = |k| p.get(k).map(String::as_str);
    ensure!(
        get("Id") == Some(name)
            && matches!(
                (get("ActiveState"), get("SubState")),
                (Some("inactive"), Some("dead")) | (Some("failed"), Some("failed"))
            )
            && matches!(get("LoadState"), Some("loaded" | "not-found"))
            && (get("InvocationID") == Some("") || get("InvocationID") == Some(iid))
            && if name.ends_with(".service") {
                ["MainPID", "ControlPID", "NRestarts"]
                    .iter()
                    .all(|k| get(k) == Some("0"))
                    && get("Restart") == Some("no")
            } else {
                ["MainPID", "ControlPID", "NRestarts"]
                    .iter()
                    .all(|k| get(k).is_none_or(|s| s == "0"))
                    && get("Restart").is_none_or(|s| s == "no")
            }
            && [
                "Job",
                "ControlGroup",
                "Triggers",
                "TriggeredBy",
                "OnSuccess",
                "OnFailure"
            ]
            .iter()
            .all(|k| get(k) == Some("")),
        "historical consumer is live, replaced, queued, triggered, restarting or incompletely observed: {name}"
    );
    Ok(())
}

fn actor_census(p: &Plan) -> Result<Value> {
    let mut out = serde_json::Map::new();
    for (name, actor) in &p.actors {
        ensure!(
            historical_pair(
                &saved(&actor.original_terminal)?,
                name,
                &actor.invocation_id
            ),
            "missing exact historical consumer IID/terminal pair"
        );
        let current = manager(name)?;
        terminal(&current, name, &actor.invocation_id)?;
        out.insert(name.clone(), serde_json::to_value(current)?);
    }
    Ok(Value::Object(out))
}

fn executor_properties(
    m: &BTreeMap<String, String>,
    args: &[String],
    iid: &str,
    pid: u32,
) -> Result<()> {
    ensure!(is_lower_hex(iid, 32), "invalid actual inspection IID");
    let get = |k| m.get(k).map(String::as_str);
    ensure!(
        get("Id") == Some(UNIT)
            && get("ActiveState") == Some("active")
            && get("SubState") == Some("running")
            && get("InvocationID") == Some(iid)
            && get("MainPID") == Some(pid.to_string().as_str())
            && get("ControlPID") == Some("0")
            && get("NRestarts") == Some("0")
            && get("Restart") == Some("no")
            && get("ProtectSystem") == Some("strict")
            && get("ProtectHome") == Some("read-only")
            && get("PrivateNetwork") == Some("yes")
            && get("NoNewPrivileges") == Some("yes")
            && [
                "Job",
                "Triggers",
                "TriggeredBy",
                "ExecCondition",
                "ExecStartPre",
                "ExecStartPost",
                "ExecStop",
                "ExecStopPost",
                "ExecReload",
                "OnSuccess",
                "OnFailure",
                "ReadWritePaths"
            ]
            .iter()
            .all(|k| get(k) == Some("")),
        "foreign or overprivileged current inspection executor"
    );
    ensure!(
        get("ExecStart").is_some_and(|s| s.matches("argv[]=").count() == 1
            && (s.contains(&format!("argv[]={};", args.join(" ")))
                || s.contains(&format!("argv[]={} ;", args.join(" "))))),
        "executor command differs"
    );
    Ok(())
}

fn executor(p: &Plan, args: &[String]) -> Result<Value> {
    let iid =
        env::var("INVOCATION_ID").context("inspection requires its actual systemd invocation")?;
    let m = manager(UNIT)?;
    executor_properties(&m, args, &iid, std::process::id())?;
    let recipe = metadata_bytes(&p.executor_recipe)?;
    Ok(
        json!({"unit":UNIT,"invocation_id":iid,"pid":std::process::id(),
        "recipe":p.executor_recipe,"recipe_bytes":recipe.len(),"properties":m}),
    )
}

fn references(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && bytes.windows(needle.len()).enumerate().any(|(i, w)| {
            w == needle
                && (i == 0 || b"/\0\n\r\t '\"=;:()[]{}".contains(&bytes[i - 1]))
                && (i + needle.len() == bytes.len()
                    || b"/\0\n\r\t '\";:()[]{}".contains(&bytes[i + needle.len()]))
        })
}

fn directory_argument(bytes: &[u8], directory: &Path) -> bool {
    let needle = directory.as_os_str().as_bytes();
    if needle.is_empty() {
        return false;
    }
    bytes.windows(needle.len()).enumerate().any(|(i, w)| {
        w == needle && (i == 0 || b"\0\n\r\t '\"=;:()[]{}".contains(&bytes[i - 1])) && {
            let mut end = i + needle.len();
            while bytes.get(end) == Some(&b'/') {
                end += 1;
            }
            end == bytes.len() || b"\0\n\r\t '\";:()[]{}".contains(&bytes[end])
        }
    })
}
/// Classify the only admitted indirect reader recipes. Full204 owns its scan
/// directory; Full205 preserves204 as its explicit anchor. This classification
/// does not discover arbitrary wrappers: callers must still supply the complete
/// reviewed inbound readset, and unknown reader profiles fail closed.
#[derive(Debug, PartialEq, Eq)]
enum DependencyReader {
    ScanDirectory204,
    RetainedAnchor205,
}
fn dependency_reader(value: &Value) -> Result<DependencyReader> {
    match value["schema"].as_str() {
        Some("jetstreamer-epoch204-assembly-recovery-stage-spec-v1") => {
            ensure!(
                value["scan_directory"] == ROOT
                    && matches!(
                        value["stage"].as_str(),
                        Some("full" | "plugin" | "import" | "upload")
                    )
                    && value["source"]["kind"] == "AssemblyRecovery204",
                "unclassified204 reader semantics"
            );
            Ok(DependencyReader::ScanDirectory204)
        }
        Some("jetstreamer-continuation205-delivery-stage-spec-v1") => {
            ensure!(
                value["stage"] == "full"
                    && value["source"]["kind"] == "Continuation205"
                    && value["scan_directory"].as_str().is_some_and(|p| p != ROOT)
                    && value["neighbors"].as_array().is_some_and(|neighbors| {
                        neighbors.len() == 1
                            && neighbors[0]["epoch"] == 204
                            && neighbors[0]["archive"]["path"] == RETAINED
                            && neighbors[0]["archive"]["sha256"] == SHA204
                            && neighbors[0]["bytes"] == LENGTH204
                    }),
                "unclassified205 reader semantics or retained204 anchor changed"
            );
            Ok(DependencyReader::RetainedAnchor205)
        }
        _ => bail!("unknown indirect reader profile; complete reviewed readset required"),
    }
}

fn recipe_references(bytes: &[u8], p: &Plan) -> bool {
    references(bytes, ROOT.as_bytes())
        || references(bytes, SOURCE.as_bytes())
        || p.actors.keys().any(|n| references(bytes, n.as_bytes()))
        || p.dependency_metadata
            .iter()
            .any(|b| references(bytes, b.path.as_os_str().as_bytes()))
}

fn recipe(path: &Path) -> Result<Vec<u8>> {
    let mut path = path.to_path_buf();
    let mut seen = BTreeSet::new();
    for _ in 0..8 {
        ensure!(seen.insert(path.clone()), "cyclic recipe link");
        let m = fs::symlink_metadata(&path)?;
        if m.file_type().is_symlink() {
            let link = fs::read_link(&path)?;
            path = if link.is_absolute() {
                link
            } else {
                path.parent().context("recipe parent")?.join(link)
            };
            continue;
        }
        if path == Path::new("/dev/null")
            && m.uid() == 0
            && m.mode() & libc::S_IFMT == libc::S_IFCHR
            && m.rdev() == libc::makedev(1, 3)
        {
            return Ok(vec![]);
        }
        ensure!(
            m.is_file() && m.len() <= MAX_METADATA,
            "uninspected/oversized staged recipe"
        );
        return read_stable_bounded(&path, MAX_METADATA, "staged retention recipe");
    }
    bail!("recipe link depth bound")
}

fn staged(p: &Plan) -> Result<Value> {
    staged_for(p, &[(UNIT, &p.executor_recipe)], &[])
}

fn staged_for(p: &Plan, current: &[(&str, &Bound)], extra_references: &[&Path]) -> Result<Value> {
    let roots = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/home/ubuntu/.jetstreamer-private/systemd-staging",
    ];
    let allowed = p
        .historical_recipes
        .iter()
        .map(|b| (b.path.clone(), b.sha256.clone()))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        allowed.len() == p.historical_recipes.len()
            && current.iter().all(|(_, b)| !allowed.contains_key(&b.path)),
        "duplicate/foreign executor historical recipe"
    );
    for b in &p.dependency_metadata {
        // These are executable reader specifications, not merely arbitrary
        // historical JSON bindings. Unknown schemas are deliberately refused.
        dependency_reader(&saved(b)?)?;
    }
    let expected_current = current
        .iter()
        .map(|(_, b)| Ok((b.path.clone(), metadata_bytes(b)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        expected_current.len() == current.len(),
        "duplicate current actor recipe"
    );
    let mut seen = BTreeMap::new();
    let mut current_seen = BTreeMap::new();
    let mut files = 0;
    let mut pending = roots
        .iter()
        .map(|s| (PathBuf::from(s), 0))
        .collect::<Vec<_>>();
    while let Some((root, depth)) = pending.pop() {
        ensure!(depth <= 16, "staged nesting bound");
        let m = match fs::symlink_metadata(&root) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        ensure!(
            m.is_dir() && !m.file_type().is_symlink(),
            "aliased staged root"
        );
        for e in fs::read_dir(root)? {
            let e = e?;
            let path = e.path();
            let m = fs::symlink_metadata(&path)?;
            if m.is_dir() {
                pending.push((path, depth + 1));
                continue;
            }
            files += 1;
            ensure!(files <= 65536, "staged count bound");
            if m.file_type().is_symlink() {
                let link = fs::read_link(&path)?;
                let name = link.file_name().and_then(|v| v.to_str()).unwrap_or("");
                ensure!(
                    !(path
                        .parent()
                        .is_some_and(|v| v.to_string_lossy().ends_with(".wants")
                            || v.to_string_lossy().ends_with(".requires"))
                        && (p.actors.contains_key(name)
                            || current.iter().any(|(n, _)| *n == name))),
                    "referencing actor remains enabled"
                );
            }
            let bytes = recipe(&path)?;
            if let Some(expected) = expected_current.get(&path) {
                ensure!(
                    !current_seen.contains_key(&path) && bytes == *expected,
                    "executor recipe changed"
                );
                current_seen.insert(path, bytes);
                continue;
            }
            if !(recipe_references(&bytes, p)
                || current
                    .iter()
                    .any(|(name, _)| references(&bytes, name.as_bytes()))
                || extra_references
                    .iter()
                    .any(|path| references(&bytes, path.as_os_str().as_bytes())))
            {
                continue;
            }
            if let Some(name) = path
                .file_name()
                .and_then(|v| v.to_str())
                .filter(|n| unit_name(n))
            {
                ensure!(
                    p.actors.contains_key(name),
                    "referencing staged actor lacks terminal identity: {name}"
                );
            }
            let sha = hex_lower(&Sha256::digest(&bytes));
            ensure!(
                allowed.get(&path) == Some(&sha),
                "new/unreviewed referencing staged recipe: {}",
                path.display()
            );
            seen.insert(path, sha);
        }
    }
    ensure!(
        current_seen == expected_current && seen == allowed,
        "historical recipe set or executor visibility changed"
    );
    Ok(serde_json::to_value(seen)?)
}

fn maps_identity(row: &[u8], id: &Stamp) -> Result<bool> {
    let f = std::str::from_utf8(row)?
        .split_whitespace()
        .take(5)
        .collect::<Vec<_>>();
    ensure!(f.len() == 5, "malformed process maps row");
    let (major, minor) = f[3].split_once(':').context("maps device")?;
    Ok(
        u64::from_str_radix(major, 16)? == u64::from(libc::major(id.device))
            && u64::from_str_radix(minor, 16)? == u64::from(libc::minor(id.device))
            && f[4].parse::<u64>()? == id.inode,
    )
}

fn process_references(
    proc_root: &Path,
    target: &Path,
    id: &Stamp,
    own_pid: u32,
    dependencies: &[Bound],
) -> Result<()> {
    use std::io::{BufRead, BufReader};
    let parent = fs::metadata(target.parent().context("reference target parent")?)?;
    for e in fs::read_dir(proc_root)? {
        let e = e?;
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        let root = e.path();
        let before = match fs::read(root.join("stat")) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let start = process_start(&before)?;
        let inspect = || -> Result<()> {
            let command = read_stable_bounded(&root.join("cmdline"), 1 << 20, "process command")?;
            ensure!(
                !references(&command, target.as_os_str().as_bytes())
                    && !directory_argument(&command, target.parent().unwrap())
                    && !dependencies.iter().any(|b| {
                        references(&command, b.path.as_os_str().as_bytes())
                            || b.path
                                .parent()
                                .is_some_and(|parent| directory_argument(&command, parent))
                    }),
                "pid {pid} retains203 command/path"
            );
            let f = File::open(root.join("maps"))?;
            let mut reader = BufReader::new(f);
            let mut row = Vec::new();
            let mut total = 0u64;
            loop {
                row.clear();
                let n = reader.by_ref().take(65537).read_until(b'\n', &mut row)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                ensure!(n <= 65536 && total <= 1 << 30, "process maps bound");
                ensure!(
                    !maps_identity(&row, id)?,
                    "pid {pid} maps203 inode through an alias"
                );
            }
            let mut links = vec![root.join("cwd"), root.join("root"), root.join("exe")];
            for fd in fs::read_dir(root.join("fd"))? {
                links.push(fd?.path());
            }
            for link in links {
                let value = match fs::read_link(&link) {
                    Ok(value) => value,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                };
                let bytes = value.as_os_str().as_bytes();
                let bytes = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
                ensure!(
                    !references(bytes, target.as_os_str().as_bytes()),
                    "pid {pid} retains203 path link"
                );
                ensure!(
                    !(link.file_name().is_some_and(|n| n == "cwd")
                        && bytes == target.parent().unwrap().as_os_str().as_bytes()),
                    "pid {pid} can reopen203 through its current working directory"
                );
                match fs::metadata(&link) {
                    Ok(m) => {
                        ensure!(
                            !(m.dev() == id.device && m.ino() == id.inode),
                            "pid {pid} retains203 inode FD/alias"
                        );
                        ensure!(
                            !(m.is_dir()
                                && m.dev() == parent.dev()
                                && m.ino() == parent.ino()
                                && (link.file_name().is_some_and(|n| n == "cwd")
                                    || link.parent().is_some_and(|p| p
                                        .file_name()
                                        .is_some_and(|n| n == "fd")))),
                            "pid {pid} can reopen203 through an aliased parent-directory handle"
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        };
        let result = inspect();
        match fs::read(root.join("stat")) {
            Ok(after) => {
                ensure!(
                    process_start(&after)? == start,
                    "pid reused during reference scan"
                );
                result?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn process_start(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes)?;
    let (_, tail) = text.rsplit_once(") ").context("process stat shape")?;
    tail.split_whitespace()
        .nth(19)
        .context("process start omitted")?
        .parse()
        .context("process start ticks")
}

pub(super) fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 5 && args[1] == "inspect-scan203-retention" && args[3] == "--self-sha256",
        "usage: inspect-scan203-retention PLAN --self-sha256 SHA; Root EnvironmentFile supplies HORIZON_SCAN203_PLAN_SHA256"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "retention inspection requires Root reader"
    );
    let executable = fs::read("/proc/self/exe")?;
    ensure!(
        is_lower_hex(&args[4], 64) && hex_lower(&Sha256::digest(&executable)) == args[4],
        "running executable differs"
    );
    let binding = Bound {
        path: args[2].clone().into(),
        // Keep the plan digest out of its own hash-bound unit recipe. A separate
        // Root EnvironmentFile is populated only after plan and recipe freeze.
        sha256: env::var("HORIZON_SCAN203_PLAN_SHA256")
            .context("Root plan digest transport missing")?,
    };
    let p: Plan = serde_json::from_value(saved(&binding)?)?;
    scope(&p)?;
    parent(&p.parent_identity)?;
    replica(Path::new(SOURCE), &p.source_identity)?;
    replica(Path::new(RETAINED), &p.retained204_identity)?;
    let proof = gates(&p)?;
    let owner = executor(&p, &args)?;
    let before = actor_census(&p)?;
    let recipes = staged(&p)?;
    process_references(
        Path::new("/proc"),
        Path::new(SOURCE),
        &p.source_identity,
        std::process::id(),
        &p.dependency_metadata,
    )?;
    let after = actor_census(&p)?;
    ensure!(
        before == after && recipes == staged(&p)?,
        "consumer/recipe closure changed"
    );
    replica(Path::new(SOURCE), &p.source_identity)?;
    replica(Path::new(RETAINED), &p.retained204_identity)?;
    ensure!(owner == executor(&p, &args)?, "current executor changed");
    parent(&p.parent_identity)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"schema":"jetstreamer-scan203-retention-inspection-v1",
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "plan":binding,"parent_identity":p.parent_identity,"source":SOURCE,"source_identity":p.source_identity,"retained204":RETAINED,
        "retained204_identity":p.retained204_identity,"source_sha256_expected_not_rehashed":SHA203,
        "historical_gates":proof,"executor":owner,"consumer_census":after,"historical_recipes":recipes,
        "archive_body_opened":false,"remote_requests":0,"locks_acquired":0,"local_archive_mutations":0,
        "retirement_authorized":false,"space_credit_bytes":0,
        "remaining_gates":["qualified Rust retirement executor and native fixtures","independent review of indirect-reader/dependency metadata coverage",
            "fresh shared-lock/action admission and consumer recheck",
            "local whole-body SHA256/ETag and authenticated current remote-pair revalidation","durable intent/quarantine/completion and post-action accounting"]})
        )?
    );
    Ok(())
}
