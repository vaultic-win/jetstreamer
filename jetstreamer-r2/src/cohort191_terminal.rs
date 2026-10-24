//! First post191 terminal proof. No future observer, task launch or R2 access.
use super::*;
const PROGRAM: &str =
    "/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-r2";
const ROOT: &str = "/var/lib/jetstreamer/horizon-cohort191-terminal-transition-20261023-v1";
const CACHE_PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-cohort191-collected-delivery-tools-20261024-v1/jetstreamer-r2";
const CACHE_ROOT: &str =
    "/var/lib/jetstreamer/horizon-cohort191-terminal-cache-transition-20261024-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    program: Bound,
    source_batch: Bound,
    public_batch: Bound,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origins: Option<BTreeMap<u64, Bound>>,
    output: PathBuf,
}
fn collection_root(p: &Plan) -> Result<&'static Path> {
    let root = match (p.schema.as_str(), p.program.path.to_str()) {
        ("jetstreamer-cohort191-terminal-collection-plan-v1", Some(PROGRAM)) => ROOT,
        ("jetstreamer-cohort191-terminal-cache-collection-plan-v1", Some(CACHE_PROGRAM)) => {
            CACHE_ROOT
        }
        _ => anyhow::bail!("191 terminal collection schema/program differs"),
    };
    ensure!(
        p.output == Path::new(root).join("terminal.json"),
        "191 terminal output namespace differs"
    );
    ensure!(
        if root == CACHE_ROOT {
            p.origins
                .as_ref()
                .is_some_and(|o| o.keys().copied().eq(191..=194))
        } else {
            p.origins.is_none()
        },
        "191 terminal collection origin census differs"
    );
    Ok(Path::new(root))
}
fn producer() -> Result<Value> {
    let mut u = fleet::unit(UNIT)?;
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", UNIT, "--all", "--property=Job"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 1024,
        "191 terminal producer job unavailable"
    );
    let s = std::str::from_utf8(&out.stdout)?.trim_end();
    u["Job"] = json!(
        s.strip_prefix("Job=")
            .context("191 terminal producer job framing")?
    );
    Ok(u)
}
// A distinct all-public cache. Pending-import proof must never enter this path.
// Only immutable historical producer records are reused: the caller still
// rechecks current controller, imported public custody, task owners and every
// full/plugin/ready gate independently on each capture.
fn cache_scope(v: &Value, p: &Capture, cutoff: u64) -> Result<()> {
    jetstreamer_horizon_observe::cohort191_delivery_model::validate_terminal_transition(v, cutoff)?;
    cache_bindings(v, p)
}
fn cache_bindings(v: &Value, p: &Capture) -> Result<()> {
    ensure!(
        p.native_pending_proof.is_none()
            && p.source_batch
                .as_ref()
                .is_some_and(|b| json!(b) == v["source_batch"])
            && p.public_batch
                .as_ref()
                .is_some_and(|b| json!(b) == v["public_batch"])
            && !p.claims.is_empty()
            && p.claims.iter().all(|c| (191..=194).contains(&c.epoch)
                && matches!(
                    c.phase.as_str(),
                    "full-verification"
                        | "plugin-verification"
                        | "upload-readback"
                        | "cohort191-delivery"
                )),
        "191 terminal cache borrowed by pending/finalization or different import"
    );
    Ok(())
}
pub(super) fn retained_events(proof: &Bound, p: &Capture, cutoff: u64) -> Result<Value> {
    let v = bound(proof, false)?;
    cache_scope(&v, p, cutoff)?;
    let capture: Bound = serde_json::from_value(v["capture_plan"].clone())?;
    let plan: Plan = serde_json::from_value(bound(&capture, true)?)?;
    collection_root(&plan)?;
    ensure!(
        v["capture_program"].as_str() == plan.program.path.to_str()
            && v["capture_self_sha256"] == plan.program.sha256
            && plan.output == proof.path
            && json!(plan.source_batch) == v["source_batch"]
            && json!(plan.public_batch) == v["public_batch"],
        "191 terminal cache lacks exact sealed native collector provenance"
    );
    member(&plan.program.path, &plan.program.sha256)?;
    if let Some(origins) = &plan.origins {
        ensure!(
            json!(origins) == v["origins"] && json!(p.origins) == v["origins"],
            "191 terminal cached original launch bindings differ"
        );
    }
    ensure!(
        manager_terminal(cutoff)? == v["producer_terminal"],
        "191 cached producer terminal lifecycle changed"
    );
    let mut records = vec![v["native_events"]["root"].clone()];
    records.extend(
        v["native_events"]["closes"]
            .as_array()
            .context("191 terminal cache closes")?
            .iter()
            .cloned(),
    );
    let events = roots(&records, cutoff)?;
    ensure!(
        events == v["native_events"],
        "191 terminal cached native fields differ"
    );
    Ok(events)
}
pub(super) fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && a.len() == 7
            && a[1] == "capture-terminal191"
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && is_lower_hex(&a[4], 64)
            && is_lower_hex(&a[6], 64),
        "capture-terminal191 PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    let pb = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let p: Plan = serde_json::from_value(bound(&pb, true)?)?;
    let root = collection_root(&p)?;
    ensure!(
        p.program.sha256 == a[6] && fs::read_link("/proc/self/exe")? == p.program.path,
        "191 terminal collection scope/self differs"
    );
    member(&p.program.path, &p.program.sha256)?;
    let cutoff = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if let Some(origins) = &p.origins {
        for (epoch, origin) in origins {
            original(origin, *epoch, cutoff)?;
        }
    }
    let history = inputs()?;
    let before = producer()?;
    if before["LoadState"] == "loaded" {
        ensure!(
            prefix(&before["ExecStart"]) == prefix(&history["current_units"][UNIT]["ExecStart"]),
            "191 terminal producer command changed"
        );
    }
    let events = if p.program.path == Path::new(CACHE_PROGRAM) {
        collected::native_records(cutoff)?
    } else {
        native_events(cutoff)?
    };
    let terminal = manager_terminal(cutoff)?;
    let import = dispatch_import_check(
        &p.source_batch,
        &p.public_batch,
        &BTreeSet::from([191, 192, 193, 194]),
    )?;
    let v = json!({"schema":"jetstreamer-cohort191-terminal-transition-v1","first_epoch":191,"last_epoch":194,"recorded_unix_seconds":cutoff,"capture_plan":pb,"capture_program":p.program.path,"capture_self_sha256":p.program.sha256,"source_batch":p.source_batch,"public_batch":p.public_batch,"origins":p.origins,"native_events":events,"producer":before,"producer_terminal":terminal,"controller_lifecycle":import["controller_lifecycle"],"native_import":import,"resource_samples":0,"publication_authorized":false,"replay_launch_authorized":false,"archive_readiness_claimed":false,"r2_mutations":false});
    jetstreamer_horizon_observe::cohort191_delivery_model::validate_terminal_transition(
        &v, cutoff,
    )?;
    ensure!(
        producer()? == before
            && (if p.program.path == Path::new(CACHE_PROGRAM) {
                collected::native_records(cutoff)?
            } else {
                native_events(cutoff)?
            }) == v["native_events"]
            && manager_terminal(cutoff)? == v["producer_terminal"]
            && dispatch_import_check(
                &p.source_batch,
                &p.public_batch,
                &BTreeSet::from([191, 192, 193, 194])
            )? == v["native_import"],
        "191 terminal collection raced original ownership/import"
    );
    if !root.try_exists()? {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(root)?;
        File::open(root.parent().unwrap())?.sync_all()?;
    }
    let m = fs::symlink_metadata(root)?;
    ensure!(
        root.canonicalize()? == root && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "191 terminal output is not canonical root-private"
    );
    // Existing evidence is never replaced; all proof members came from actual
    // native writers and PID1. This is not a verification/readiness receipt.
    fleet::persist(&p.output, &v)?;
    println!("{}", p.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_cache_rejects_pending_scope_and_cross_import_borrowing() {
        let b = |path: &str| json!({"path":path,"sha256":"a".repeat(64)});
        let plan = json!({"schema":"jetstreamer-cohort191-delivery-capture-plan-v2",
            "observer":b("/sample"),"forecast":b("/forecast"),"origins":{},
            "claims":[{"epoch":191,"phase":"cohort191-delivery","unit":"queue",
                "invocation_id":"a".repeat(32),"expected_exec_start":"queue","program":null}],
            "source_batch":b("/source"),"public_batch":b("/public"),
            "gate_receipts":{},"gate_tools":{},"ready_receipts":{},"output":"/event"});
        let v = json!({"source_batch":b("/source"),"public_batch":b("/public")});
        let good: Capture = serde_json::from_value(plan.clone()).unwrap();
        cache_bindings(&v, &good).unwrap();
        for phase in [
            "local-publication",
            "controller-import-handoff",
            "producer-finalization",
        ] {
            let mut bad = plan.clone();
            bad["claims"][0]["phase"] = json!(phase);
            assert!(cache_bindings(&v, &serde_json::from_value(bad).unwrap()).is_err());
        }
        for name in ["source_batch", "public_batch"] {
            let mut bad = plan.clone();
            bad[name] = b("/different");
            assert!(cache_bindings(&v, &serde_json::from_value(bad).unwrap()).is_err());
        }
        let mut bad = plan;
        bad["claims"][0]["epoch"] = json!(195);
        assert!(cache_bindings(&v, &serde_json::from_value(bad.clone()).unwrap()).is_err());
        bad["claims"][0]["epoch"] = json!(191);
        bad["native_pending_proof"] = b("/pending");
        assert!(cache_bindings(&v, &serde_json::from_value(bad).unwrap()).is_err());
    }
    #[test]
    fn terminal_plan_cannot_import_future_observer_fields() {
        let v = json!({"schema":"jetstreamer-cohort191-terminal-collection-plan-v1","program":{"path":PROGRAM,"sha256":"a".repeat(64)},"source_batch":{"path":"/native/source","sha256":"b".repeat(64)},"public_batch":{"path":"/native/public","sha256":"c".repeat(64)},"output":Path::new(ROOT).join("terminal.json")});
        serde_json::from_value::<Plan>(v.clone()).unwrap();
        let mut bad = v;
        bad["observer"] = json!({"sha256":"future"});
        assert!(serde_json::from_value::<Plan>(bad).is_err());
    }
    #[test]
    fn corrected_collector_has_separate_program_schema_and_no_clobber_namespace() {
        let fixture = |schema: &str, program: &str, root: &str| {
            let mut p = serde_json::from_value::<Plan>(json!({
            "schema":schema,"program":{"path":program,"sha256":"a".repeat(64)},
            "source_batch":{"path":"/source","sha256":"b".repeat(64)},
            "public_batch":{"path":"/public","sha256":"c".repeat(64)},
            "output":Path::new(root).join("terminal.json")}))
            .unwrap();
            if schema == "jetstreamer-cohort191-terminal-cache-collection-plan-v1" {
                p.origins = Some(
                    (191..=194)
                        .map(|e| {
                            (
                                e,
                                Bound {
                                    path: "/origin".into(),
                                    sha256: "a".repeat(64),
                                },
                            )
                        })
                        .collect(),
                );
            }
            p
        };
        collection_root(&fixture(
            "jetstreamer-cohort191-terminal-collection-plan-v1",
            PROGRAM,
            ROOT,
        ))
        .unwrap();
        collection_root(&fixture(
            "jetstreamer-cohort191-terminal-cache-collection-plan-v1",
            CACHE_PROGRAM,
            CACHE_ROOT,
        ))
        .unwrap();
        assert!(
            collection_root(&fixture(
                "jetstreamer-cohort191-terminal-cache-collection-plan-v1",
                PROGRAM,
                CACHE_ROOT
            ))
            .is_err()
        );
        assert!(
            collection_root(&fixture(
                "jetstreamer-cohort191-terminal-cache-collection-plan-v1",
                CACHE_PROGRAM,
                ROOT
            ))
            .is_err()
        );
    }
}
