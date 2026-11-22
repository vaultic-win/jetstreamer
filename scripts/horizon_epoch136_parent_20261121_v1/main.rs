//! The parent owns the admitted actor's systemd envelope and conditional status publication.
mod actor;
mod dispatch;
#[cfg(feature = "fixture-semantic")]
#[path = "../horizon_epoch136_donor171_20261120_v1/fixture_plan.rs"]
mod fixture_plan;
mod status;
// Reuse the campaign's no-follow, root-custody reads, exclusive fsynced receipt writes and native clock helpers.
#[allow(dead_code)]
#[path = "../horizon_public_audit_v14_cutover_20261121_v1/platform.rs"]
mod platform;
use anyhow::{Context, Result, ensure};
use platform::*;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
const BASE: &str = "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1";
const HOME: &str = "/home/sol";
const ACTOR: &str = "horizon-qualify-136-actual-20261120-g1.service";
const WRITER: &str = "horizon-admit-136-actual-20261120-g1.service";
const GUARD: &str = "horizon-guard-136-actual-20261120-g1";
const HELPER_SHA: &str = "93162c6910f01149cb50eccdfa742e5a732658dd8ac17865a5f2eaef526c0594";
const TOOLS_SEAL_SHA: &str = "5a4176a52fa18d69e247d0f42a0900163fecce5c7b1c516310fb6c69376ecf17";
const OUT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch136-parent-handoff-20261121-v1";
const STATUS_ROOT: &str = "/home/sol/.jetstreamer-private/r2-status-receipts";
const SEALER: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
#[path = "../horizon_epoch136_actual_20261120_v1/scope.rs"]
mod payload_scope;
fn at(p: &str) -> PathBuf {
    Path::new(BASE).join(p)
}
fn receipts() -> PathBuf {
    at("reproduction/receipts")
}
fn immutable(r: &Value) -> Result<Value> {
    let p = Path::new(text(&r["path"])?);
    ensure!(
        fs::symlink_metadata(p)?.mode() & 0o222 == 0 && r.as_object().is_some_and(|v| v.len() == 2),
        "unsealed evidence {}",
        p.display()
    );
    from_ref(r)
}
fn protect_json(p: &Path, v: &Value) -> Result<Value> {
    if p.try_exists()? {
        let b = bound(p)?;
        ensure!(
            immutable(&b)? == *v,
            "existing evidence differs at {}",
            p.display()
        );
        return Ok(b);
    }
    let mut bytes = serde_json::to_vec_pretty(v)?;
    bytes.push(b'\n');
    create(p, &bytes, 0o400)?;
    bound(p)
}
fn native(u: &str) -> Result<Value> {
    show(
        u,
        "Id,ActiveState,SubState,MainPID,InvocationID,ControlGroup,Job,NRestarts",
    )
}
fn require_iid(v: &Value) -> Result<&str> {
    let s = text(v)?;
    ensure!(
        s.len() == 32
            && s.bytes()
                .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
            && s.bytes().any(|x| x != b'0'),
        "invalid invocation ID"
    );
    Ok(s)
}
fn open_dir(p: &Path) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        fs::canonicalize(p)? == p
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0
            && m.dev() == fs::metadata(HOME)?.dev(),
        "unsafe HOME evidence directory"
    );
    Ok(())
}
fn same_inode(a: &Path, b: &Path) -> Result<bool> {
    let x = fs::metadata(a)?;
    let y = fs::metadata(b)?;
    Ok((x.dev(), x.ino()) == (y.dev(), y.ino()))
}
fn trusted_dir(parent: &Path, name: &str) -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    open_dir(parent)?;
    let d = parent.join(name);
    match fs::DirBuilder::new().mode(0o700).create(&d) {
        Ok(()) => fs::File::open(parent)?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    open_dir(&d)?;
    Ok(d)
}
pub struct Input {
    writer_plan: Value,
    full: Value,
    package: PathBuf,
    package_seal: Value,
    admission: Value,
    admitted: Value,
    fleet: Value,
    request: Value,
    request_ref: Value,
    writer_pid: i32,
    writer_ticks: u64,
}
fn qualified_package(args: &[String]) -> Result<(Value, Value, PathBuf, Value)> {
    ensure!(
        args.len() == 4,
        "expected immutable WRITER_PLAN SHA and CONTROLLER_SEAL SHA"
    );
    let writer_plan = json!({"path":args[0],"sha256":args[1]});
    let package_seal = json!({"path":args[2],"sha256":args[3]});
    let full = immutable(&writer_plan)?;
    #[cfg(feature = "fixture-semantic")]
    fixture_plan::validate(&full)?;
    ensure!(
        full["controller_deployment"] == package_seal,
        "incorrect writer-plan deployment"
    );
    let package = Path::new(&args[2])
        .parent()
        .context("controller package")?
        .to_owned();
    ensure!(
        Path::new(&args[2]).file_name().and_then(|s| s.to_str())
            == Some("deployment-seal-receipt.json")
            && package.starts_with("/var/lib/jetstreamer/horizon_runtime_data"),
        "unexpected writer package"
    );
    let dep = immutable(&package_seal)?;
    ensure!(
        dep["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && dep["sealer_sha256"] == SEALER
            && dep["destination"] == json!(package)
            && dep["remote_mutations"] == false,
        "wrong normal writer deployment"
    );
    let hash = &full["controller"]["sha256"];
    ensure!(
        dep["members"]
            .as_array()
            .context("controller members")?
            .iter()
            .any(|m| m["name"] == "admit136" && m["mode"] == "0555" && m["sha256"] == *hash)
            && bound(&package.join("admit136"))?["sha256"] == *hash,
        "writer image differs from selected seal"
    );
    Ok((writer_plan, full, package, package_seal))
}
impl Input {
    pub fn load(args: &[String]) -> Result<Self> {
        let (writer_plan, full, package, package_seal) = qualified_package(args)?;
        let request_ref = bound(&at("parent-launch-request.json"))
            .context("waiting for the genuine writer parent-launch-request.json")?;
        let request = immutable(&request_ref)?;
        let admission = request["admission"].clone();
        let admitted = immutable(&admission)?;
        let payload = immutable(&request["plan"])?;
        let denial_path = "/var/lib/jetstreamer/horizon_runtime_data/epoch136-preinit-image-custody-20261120-v1/probe/PASS.json";
        ensure!(
            request["native_denial"]
                == json!({"path":denial_path,"sha256":"235ef6e5deaf79576a56a8bfbab6fe4b9fece3dda7bb0148f7fe1c791e6f044b"}),
            "different pre-Initialize denial"
        );
        let denial = immutable(&request["native_denial"])?;
        ensure!(
            denial["worker_reaped"] == true
                && denial["initialize_release_sent"] == false
                && denial["actual_worker_guard_qualified"] == false
                && denial["node_sha256"] == full["node"]["sha256"]
                && denial["worker_sha256"] == full["worker"]["sha256"],
            "denial receipt or images changed"
        );
        shape(&full, &payload, &request, &admitted, &writer_plan)?;
        ensure!(
            admission["path"] == json!(at("admission.json"))
                && full["helper"] == bound(&at("tools/epoch136-actual-payload"))?
                && full["tools_seal"] == bound(&at("tools/deployment-seal-receipt.json"))?,
            "wrong live tools or admission"
        );
        let account = immutable(&admitted["resource_accounting"])?;
        ensure!(
            account["writer_plan"] == writer_plan
                && account["payload_plan"] == request["plan"]
                && account["exclusive_handoff_receipt"] == request["donor"],
            "capacity and request plans differ"
        );
        let row = native(WRITER)?;
        let writer_pid: i32 = text(&row["MainPID"])?.parse()?;
        let writer_ticks = ticks(writer_pid)?;
        let instance = Self {
            writer_plan,
            full,
            package,
            package_seal,
            admission,
            admitted,
            fleet: account["complete_fleet"].clone(),
            request,
            request_ref,
            writer_pid,
            writer_ticks,
        };
        instance.current_writer()?;
        Ok(instance)
    }
    pub fn current_writer(&self) -> Result<()> {
        let cmd = fs::read(proc_path(self.writer_pid, "cmdline"))?;
        let argv = cmd.split(|v| *v == 0).collect::<Vec<_>>();
        ensure!(
            argv.len() == 7
                && argv[1] == b"session"
                && argv[2] == text(&self.writer_plan["path"])?.as_bytes()
                && argv[3] == text(&self.writer_plan["sha256"])?.as_bytes()
                && argv[4] == text(&self.fleet["path"])?.as_bytes()
                && argv[5] == text(&self.fleet["sha256"])?.as_bytes()
                && argv[6].is_empty(),
            "different writer session arguments"
        );
        let r = native(WRITER)?;
        ensure!(
            r["ActiveState"] == "active"
                && r["SubState"] == "running"
                && r["Job"] == ""
                && r["NRestarts"] == "0"
                && r["ControlGroup"] == format!("/system.slice/{WRITER}")
                && text(&r["MainPID"])?.parse::<i32>()? == self.writer_pid
                && r["InvocationID"] == self.request["writer_invocation_id"]
                && ticks(self.writer_pid)? == self.writer_ticks
                && same_inode(
                    &proc_path(self.writer_pid, "exe"),
                    &self.package.join("admit136")
                )?
                && same_inode(
                    &proc_path(self.writer_pid, "root")
                        .join(at("controller/admit136").strip_prefix("/")?),
                    &self.package.join("admit136")
                )?,
            "wrong live writer or mount projection"
        );
        Ok(())
    }
    pub fn live_admission(&self) -> Result<()> {
        self.current_writer()?;
        let t = now();
        ensure!(
            self.admitted["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|v| v <= t)
                && self.request["launch_expires_unix_seconds"]
                    .as_u64()
                    .is_some_and(|v| v > t)
                && immutable(&self.admission)? == self.admitted
                && immutable(&self.request_ref)? == self.request,
            "expired or changed admission"
        );
        Ok(())
    }
}
fn shape(full: &Value, payload: &Value, r: &Value, a: &Value, wp: &Value) -> Result<()> {
    let keys = [
        "schema",
        "node",
        "worker",
        "helper",
        "tools_seal",
        "qualification",
        "source_proof",
        "history",
        "controller",
        "source_commit",
        "barrier_version",
    ];
    ensure!(
        payload.as_object().is_some_and(|x| x.len() == keys.len())
            && keys
                .iter()
                .all(|k| payload.get(k).is_some() && payload[k] == full[k]),
        "strict actor plan is not the writer's exact projection"
    );
    require_iid(&r["writer_invocation_id"])?;
    ensure!(
        r["schema"] == "horizon-epoch136-parent-launch-request-v1"
            && r["writer_plan"] == *wp
            && r["plan"] == a["plan"]
            && r["unit"] == ACTOR
            && r["helper"] == full["helper"]
            && r["writer"] == full["controller"]
            && r["writer"] == a["writer"]
            && r["writer_invocation_id"] == a["writer_invocation_id"]
            && r["actor_launch_performed"] == false
            && r["initialize_authorized"] == false
            && r["r2_mutations"] == false
            && a["schema"] == "horizon-epoch136-actual-admission-v1"
            && a["bounded_reproduction_authorized"] == true
            && a["full_epoch_span_proven"] == false
            && ["publication_authorized", "remote_mutations", "r2_mutations"]
                .iter()
                .all(|k| a[k] == false)
            && a["launch_expires_unix_seconds"] == r["launch_expires_unix_seconds"]
            && ["helper", "node", "worker", "tools_seal"]
                .iter()
                .all(|k| a[k] == payload[k])
            && r["helper"]
                == json!({"path":at("tools/epoch136-actual-payload"),"sha256":HELPER_SHA})
            && full["controller"]["path"] == json!(at("controller/admit136"))
            && full["tools_seal"]
                == json!({"path":at("tools/deployment-seal-receipt.json"),"sha256":TOOLS_SEAL_SHA}),
        "wrong request, donor or privileges"
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|a| a == "inspect-status" || a == "inspect-registration")
    {
        ensure!(
            args.len() == 3 && unsafe { libc::geteuid() } == 0,
            "parent136 inspect-status|inspect-registration FLEET SHA"
        );
        let head = status::inspect_head(&args[1], &args[2])?;
        if args[0] == "inspect-registration" {
            status::check_registration_environment()?;
            println!(
                "{}",
                json!({"head": head, "status_client_configured": true, "remote_requests": 0})
            );
        } else {
            println!("{head}");
        }
        return Ok(());
    }
    if args.first().is_some_and(|a| a == "dispatch") {
        ensure!(
            args.len() == 6 && unsafe { libc::geteuid() } == 0,
            "parent136 dispatch WRITER_IID WRITER_PLAN SHA CONTROLLER_SEAL SHA"
        );
        return dispatch::run(&args[1], &args[2..]);
    }
    if args.first().is_some_and(|a| a == "prepare-inputs") {
        ensure!(
            args.len() == 3 && unsafe { libc::geteuid() } == 0,
            "parent136 prepare-inputs FLEET SHA"
        );
        let binds = actor::mirrors(&json!({"path":args[1],"sha256":args[2]}), true)?;
        println!("{}", json!(binds));
        return Ok(());
    }
    if args.first().is_some_and(|a| a == "reconcile") {
        ensure!(
            args.len() == 1 && unsafe { libc::geteuid() } == 0,
            "parent136 reconcile"
        );
        return status::reconcile();
    }
    ensure!(
        args.len() == 5 && unsafe { libc::geteuid() } == 0,
        "parent136 preview|launch|register WRITER_PLAN SHA CONTROLLER_SEAL SHA"
    );
    if args[0] == "inspect" {
        let (doc, p, dir, seal) = qualified_package(&args[1..])?;
        let template = actor::quantity_args(
            &json!({"path":at("payload-plan.json"),"sha256":"<actual writer-emitted strict digest>"}),
            &p["helper"],
            &json!({"path":at("admission.json"),"sha256":"<actual admission digest>"}),
            &dir,
        )?;
        let installed = same_inode(&at("controller/admit136"), &dir.join("admit136"))?;
        let output = json!({"writer_plan":doc,"writer_deployment":seal,"host_controller_already_projects_selected_image":installed,"prospective_argv":template,
            "parent_request_exists":at("parent-launch-request.json").try_exists()?,"reproduction_exists":at("reproduction").try_exists()?,
            "actor_launched":false,"remote_mutations":false,"worker_initialize_authorized":false});
        println!("{output}");
        return Ok(());
    }
    let x = Input::load(&args[1..])?;
    match args[0].as_str() {
        "preview" => println!(
            "{}",
            json!({"argv":actor::launch_args(&x)?,"writer_plan":x.writer_plan,"payload_plan":x.request["plan"],"controller_seal":x.package_seal,"launched":false})
        ),
        "launch" => actor::launch(&x)?,
        "register" => status::register(&x)?,
        _ => anyhow::bail!("unknown mode"),
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn docs() -> (Value, Value, Value, Value, Value) {
        let fake = |s: &str| json!({"path":format!("/qualified/{s}"),"sha256":"a".repeat(64)});
        let mut payload = json!({"schema":"horizon-epoch136-actual-plan-v1","node":fake("node"),"worker":fake("worker"),
            "helper":{"path":at("tools/epoch136-actual-payload"),"sha256":HELPER_SHA},
            "tools_seal":{"path":at("tools/deployment-seal-receipt.json"),"sha256":TOOLS_SEAL_SHA},
            "qualification":fake("qualification"),"source_proof":fake("source"),"history":fake("history"),
            "controller":fake("controller"),"source_commit":"a".repeat(40),"barrier_version":"epoch136-actual-20261120-before-initialize-v1"});
        payload["controller"]["path"] = json!(at("controller/admit136"));
        let mut full = payload.clone();
        full["standard169_cpu_loan"] = json!({"cpu_quota_micros":4250000});
        let writer = fake("writer-plan");
        let plan = fake("payload-plan");
        let iid = "1".repeat(32);
        let admission = json!({"schema":"horizon-epoch136-actual-admission-v1","plan":plan,"helper":payload["helper"],"node":payload["node"],"worker":payload["worker"],
            "tools_seal":payload["tools_seal"],"writer":full["controller"],"writer_invocation_id":iid,"launch_expires_unix_seconds":200,
            "bounded_reproduction_authorized":true,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"full_epoch_span_proven":false});
        let request = json!({"schema":"horizon-epoch136-parent-launch-request-v1","unit":ACTOR,"helper":full["helper"],"writer":full["controller"],
            "writer_invocation_id":iid,"plan":plan,"writer_plan":writer,"launch_expires_unix_seconds":200,"actor_launch_performed":false,
            "r2_mutations":false,"initialize_authorized":false});
        (full, payload, request, admission, writer)
    }
    #[test]
    fn strict_plan_and_writer_plan_remain_distinct() {
        let (full, strict, r, a, w) = docs();
        shape(&full, &strict, &r, &a, &w).unwrap();
        assert!(shape(&full, &full, &r, &a, &w).is_err());
        let mut modified = r.clone();
        modified["plan"] = w.clone();
        assert!(shape(&full, &strict, &modified, &a, &w).is_err());
        let mut modified = r.clone();
        modified["writer_plan"] = r["plan"].clone();
        assert!(shape(&full, &strict, &modified, &a, &w).is_err());
    }
    #[test]
    fn previously_launched_or_overprivileged_request_rejected() {
        let (full, strict, r, a, w) = docs();
        for k in [
            "actor_launch_performed",
            "initialize_authorized",
            "r2_mutations",
        ] {
            let mut v = r.clone();
            v[k] = json!(true);
            assert!(shape(&full, &strict, &v, &a, &w).is_err(), "{k}");
        }
        for k in [
            "publication_authorized",
            "full_epoch_span_proven",
            "remote_mutations",
        ] {
            let mut v = a.clone();
            v[k] = json!(true);
            assert!(shape(&full, &strict, &r, &v, &w).is_err(), "{k}");
        }
    }
}
