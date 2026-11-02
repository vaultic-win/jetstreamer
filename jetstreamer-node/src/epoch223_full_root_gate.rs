// Independent parent consumption of the distinct root issuer's real permission.
// No command here issues, renews, fabricates or publishes a permission.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
mod causal_checks {
    include!("../../historical-runtime/epoch223_continuous_causal_basis.rs");
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    path: PathBuf,
    sha256: String,
}
fn check(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn bytes(b: &Binding, limit: u64) -> Result<Vec<u8>, String> {
    digest(&b.sha256)?;
    check(
        b.path.is_absolute() && b.path.canonicalize().map_err(|e| e.to_string())? == b.path,
        "root metadata path redirected",
    )?;
    let before = fs::symlink_metadata(&b.path).map_err(|e| e.to_string())?;
    check(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= limit,
        "root metadata is not immutable single-link root-owned input",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&b.path)
        .map_err(|e| e.to_string())?;
    let opened = f.metadata().map_err(|e| e.to_string())?;
    check(
        (before.dev(), before.ino()) == (opened.dev(), opened.ino()),
        "root metadata changed at open",
    )?;
    let mut out = Vec::new();
    f.by_ref()
        .take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    let after = fs::symlink_metadata(&b.path).map_err(|e| e.to_string())?;
    check(
        out.len() as u64 <= limit
            && (
                before.dev(),
                before.ino(),
                before.len(),
                before.mode(),
                before.mtime(),
                before.mtime_nsec(),
            ) == (
                after.dev(),
                after.ino(),
                after.len(),
                after.mode(),
                after.mtime(),
                after.mtime_nsec(),
            )
            && format!("{:x}", Sha256::digest(&out)) == b.sha256,
        "root metadata bytes or identity differ",
    )?;
    Ok(out)
}
fn value(b: &Binding) -> Result<Value, String> {
    serde_json::from_slice(&bytes(b, 16 << 20)?).map_err(|e| e.to_string())
}
fn binding(v: &Value) -> Result<Binding, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}
fn bound(v: &Value) -> Result<Value, String> {
    value(&binding(v)?)
}
fn actor(a: &Value) -> Result<(), String> {
    let pid = a["pid"]
        .as_u64()
        .filter(|n| *n > 1)
        .ok_or("root actor PID absent")?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .ok_or("root actor stat")?
        .1
        .split_whitespace()
        .collect();
    let ticks = fields
        .get(19)
        .ok_or("root actor lifetime")?
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    let exe = binding(&a["executable"])?;
    check(
        Some(ticks) == a["start_ticks"].as_u64()
            && fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| e.to_string())? == exe.path
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))
                .map_err(|e| e.to_string())?
                .trim()
                == format!("0::{}", a["cgroup"].as_str().ok_or("root actor cgroup")?)
            && fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|e| e.to_string())?
                .trim()
                == a["boot_id"].as_str().ok_or("root actor boot")?,
        "root actor replaced/reused",
    )?;
    bytes(&exe, 256 << 20)?;
    Ok(())
}
fn causal_basis(v: &Value) -> Result<(), String> {
    let b = binding(v)?;
    check(b.sha256 == causal_checks::DIAGNOSIS_SHA256,
        "continuous root canonical diagnosis digest differs")?;
    causal_checks::validate(&value(&b)?)
}
struct Accepted {
    runtime: Binding,
    token: Binding,
    grant: Binding,
    runner: Value,
    guard: Value,
    plan: Value,
}
static ACCEPTED: OnceLock<Accepted> = OnceLock::new();
fn live(a: &Accepted) -> Result<(), String> {
    let runtime = value(&a.runtime)?;
    check(
        runtime["mode"] == "full-root" && runtime["plan"] == a.plan,
        "full-root runtime changed",
    )?;
    let token = value(&a.token)?;
    let grant = value(&a.grant)?;
    check(
        token["grant"] == json!(a.grant) && grant["runner"] == a.runner,
        "full-root permission changed",
    )?;
    actor(&a.runner)?;
    actor(&a.guard)?;
    let self_stat = fs::read_to_string("/proc/self/stat").map_err(|e| e.to_string())?;
    let parent = self_stat
        .rsplit_once(')')
        .ok_or("parent stat")?
        .1
        .split_whitespace()
        .nth(1)
        .ok_or("parent PID")?
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    check(
        a.runner["pid"].as_u64() == Some(parent)
            && fs::read_to_string("/proc/self/cgroup")
                .map_err(|e| e.to_string())?
                .trim()
                == format!("0::{}", a.runner["cgroup"].as_str().ok_or("runner cgroup")?),
        "full-root parent was not spawned by the genuinely admitted runner",
    )?;
    let group = Path::new("/sys/fs/cgroup").join(
        a.runner["cgroup"]
            .as_str()
            .ok_or("runner cgroup")?
            .trim_start_matches('/'),
    );
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    check(page > 0 && page.is_power_of_two(), "full-root page size")?;
    for (name, n) in [
        ("memory.high", 150_000_000_000 / page * page),
        ("memory.max", 225_000_000_000 / page * page),
        ("memory.swap.max", 0),
    ] {
        check(
            fs::read_to_string(group.join(name))
                .map_err(|e| e.to_string())?
                .trim()
                .parse::<u64>()
                .map_err(|e| e.to_string())?
                == n,
            "full-root actual kernel allocation differs",
        )?;
    }
    Ok(())
}
fn spawn_shape(ready: &Value, grant: &Value, runtime: &Binding, now: u64) -> Result<(), String> {
    check(
        ready["schema"] == "jetstreamer-epoch223-full-root-demotion-spawn-ready-v1"
            && ready["runtime_plan"] == json!(runtime)
            && grant["schema"] == "jetstreamer-epoch223-full-root-demotion-spawn-grant-v1"
            && grant["runtime_plan"] == json!(runtime)
            && grant["native_execution_authorized"] == true
            && grant["ordinary_replay_authorized"] == false
            && grant["publication_authorized"] == false
            && grant["r2_mutations"] == false
            && grant["recorded_unix_millis"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= now && now - n <= 120000)
            && grant["runner"] == ready["runner"]
            && grant["request"] == ready["request"],
        "full-root spawn is foreign, stale or not separately issued",
    )
}
pub(super) fn authorize() -> Result<(), String> {
    if let Some(accepted) = ACCEPTED.get() {
        return live(accepted);
    }
    let runtime = Binding {
        path: std::env::var_os("JETSTREAMER_EPOCH223_FULL_ROOT_PLAN")
            .ok_or("full-root runtime binding missing")?
            .into(),
        sha256: std::env::var("JETSTREAMER_EPOCH223_FULL_ROOT_PLAN_SHA256")
            .map_err(|e| e.to_string())?,
    };
    let r = value(&runtime)?;
    check(
        r["schema"] == "jetstreamer-epoch223-continuous-root-demotion-runtime-plan-v4"
            && r["mode"] == "full-root"
            && r["plan"]["target_slot"] == END
            && r["plan"]["terminal_slot"] == END
            && r["plan"]["schema"] == "jetstreamer-private-epoch223-full-root-demotion-plan-v1",
        "foreign root runtime/plan/mode",
    )?;
    causal_basis(&r["canonical_diagnosis"])?;
    let p = &r["plan"];
    let x = &r["prerequisites"];
    let own = binding(&p["node"])?;
    bytes(&own, 256 << 20)?;
    check(
        fs::read_link("/proc/self/exe").map_err(|e| e.to_string())? == own.path,
        "root parent executable differs",
    )?;
    let root = PathBuf::from(p["run_root"].as_str().ok_or("root private directory")?);
    check(
        root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("qualification-223-full-root-demotion-")),
        "root private namespace differs",
    )?;
    let token_path = root.join("receipts/spawn-ready.json");
    let token_metadata = fs::symlink_metadata(&token_path).map_err(|e| e.to_string())?;
    check(
        token_metadata.is_file()
            && token_metadata.uid() == 0
            && token_metadata.nlink() == 1
            && token_metadata.mode() & 0o222 == 0
            && token_metadata.len() <= 16 << 20,
        "root ready marker metadata unsafe",
    )?;
    let mut token_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&token_path)
        .map_err(|e| e.to_string())?;
    let mut token_bytes = Vec::new();
    token_file
        .by_ref()
        .take((16 << 20) + 1)
        .read_to_end(&mut token_bytes)
        .map_err(|e| e.to_string())?;
    let token = Binding {
        path: token_path,
        sha256: format!("{:x}", Sha256::digest(&token_bytes)),
    };
    let ready = value(&token)?;
    let grant_binding = binding(&ready["grant"])?;
    let grant = value(&grant_binding)?;
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis(),
    )
    .map_err(|e| e.to_string())?;
    spawn_shape(&ready, &grant, &runtime, now)?;
    let control = bound(&grant["control_grant"])?;
    check(
        control["schema"] == "jetstreamer-epoch223-full-root-demotion-control-grant-v1"
            && control["runner"] == grant["runner"]
            && control["parent_sha256"] == own.sha256
            && control["worker_sha256"] == WORKER_SHA
            && control["native_input"] == x["native_input"]
            && control["origin_clock"] == x["origin_clock"],
        "root spawn borrows a bracket/foreign control",
    )?;
    let native = bound(&x["native_input"])?;
    check(
        native["schema"] == "jetstreamer-epoch223-full-root-demotion-native-input-proof-v1"
            && native["worker_sha256"] == WORKER_SHA
            && native["success"] == true
            && native["bootstrap_slot"] == BOOTSTRAP
            && native["bootstrap_writes"] == 0
            && native["replay_entries"] == 0,
        "root native input is unqualified/borrowed",
    )?;
    let origin = bound(&x["origin_clock"])?;
    check(
        origin["original_start_unix_millis"] == 1792806478075u64
            && origin["repair_closed"] == false,
        "root original epoch clock differs",
    )?;
    let guard = bound(&grant["guard"])?;
    check(
        guard["schema"] == "jetstreamer-epoch223-full-root-demotion-guard-ready-v1"
            && guard["watched_runner"] == grant["runner"]
            && guard["worker_sha256"] == WORKER_SHA
            && guard["target_slot"] == END
            && guard["producer_stop_enabled"] == true,
        "root independent guard differs",
    )?;
    let issue = bound(&grant["issuer_spec"])?;
    let basis = bound(&issue["accounting_basis"])?;
    let issuer_q = bound(&basis["driver_qualification"])?;
    check(
        issuer_q["schema"] == "jetstreamer-epoch223-full-root-demotion-role-qualification-v1"
            && issuer_q["executable_sha256"] == grant["issuer"]["executable"]["sha256"]
            && issuer_q["producer_roles_qualified"] == true,
        "root issuer lacks exact qualified artifact",
    )?;
    let allocation = bound(&grant["allocation_proof"])?;
    let capacity = bound(&allocation["capacity_result"])?;
    check(
        allocation["schema"] == "jetstreamer-epoch223-full-root-demotion-allocation-proof-v1"
            && allocation["runner"] == grant["runner"]
            && capacity["schema"] == "jetstreamer-epoch223-full-root-demotion-capacity-result-v1"
            && capacity["context"]["job_kind"] == "full-root"
            && capacity["context"]["runtime_plan"] == json!(runtime)
            && capacity["capacity"]["all_live_growth_and_century_floor_protected"] == true,
        "root actual allocation lacks fresh complete root admission",
    )?;
    let status = bound(&grant["status_task"])?;
    check(
        status["schema"] == "jetstreamer-epoch223-full-root-demotion-active-task-v1"
            && status["actor"] == grant["runner"]
            && status["runtime_plan"] == json!(runtime)
            && status["original_start_unix_millis"] == 1792806478075u64,
        "root spawn lacks genuine current status ownership",
    )?;
    let accepted = Accepted {
        runtime,
        token,
        grant: grant_binding,
        runner: grant["runner"].clone(),
        guard: guard["actor"].clone(),
        plan: p.clone(),
    };
    live(&accepted)?;
    ACCEPTED
        .set(accepted)
        .map_err(|_| "root parent tried to replace its consumed permission".to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_root_spawn_cannot_borrow_bracket_control_or_expired_or_future_permission() {
        let runtime = Binding {
            path: "/sealed/source-fixture-root-plan".into(),
            sha256: "a".repeat(64),
        };
        let ready = json!({"schema":"jetstreamer-epoch223-full-root-demotion-spawn-ready-v1","runtime_plan":runtime,"runner":{"pid":12},"request":{"path":"/sealed/source-fixture-post-hash","sha256":"b".repeat(64)}});
        let grant = json!({"schema":"jetstreamer-epoch223-full-root-demotion-spawn-grant-v1","runtime_plan":runtime,"runner":ready["runner"],"request":ready["request"],
            "native_execution_authorized":true,"ordinary_replay_authorized":false,"publication_authorized":false,"r2_mutations":false,"recorded_unix_millis":1000});
        spawn_shape(&ready, &grant, &runtime, 1001).unwrap();
        assert!(spawn_shape(&ready, &grant, &runtime, 121001).is_err());
        assert!(spawn_shape(&ready, &grant, &runtime, 999).is_err());
        for (key, value) in [
            (
                "schema",
                json!("jetstreamer-epoch223-demotion-spawn-grant-v1"),
            ),
            (
                "schema",
                json!("jetstreamer-epoch223-full-root-demotion-control-grant-v1"),
            ),
            ("recorded_unix_millis", json!(0)),
            ("native_execution_authorized", json!(false)),
            ("ordinary_replay_authorized", json!(true)),
            ("runner", json!({"pid":13})),
            (
                "request",
                json!({"path":"/sealed/other","sha256":"b".repeat(64)}),
            ),
        ] {
            let mut bad = grant.clone();
            bad[key] = value;
            assert!(spawn_shape(&ready, &bad, &runtime, 1001).is_err(), "{key}");
        }
    }
}
