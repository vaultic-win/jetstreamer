//! First post 191 terminal proof. No future observer, task launch or R2 access.
use super::*;
const PROGRAM: &str =
    "/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-r2";
const ROOT: &str = "/var/lib/jetstreamer/horizon-cohort191-terminal-transition-20261023-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    program: Bound,
    source_batch: Bound,
    public_batch: Bound,
    output: PathBuf,
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
    ensure!(
        p.schema == "jetstreamer-cohort191-terminal-collection-plan-v1"
            && p.program.path == Path::new(PROGRAM)
            && p.program.sha256 == a[6]
            && p.output == Path::new(ROOT).join("terminal.json")
            && fs::read_link("/proc/self/exe")? == p.program.path,
        "191 terminal collection scope/self differs"
    );
    member(&p.program.path, &p.program.sha256)?;
    let cutoff = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let history = inputs()?;
    let before = producer()?;
    if before["LoadState"] == "loaded" {
        ensure!(
            prefix(&before["ExecStart"]) == prefix(&history["current_units"][UNIT]["ExecStart"]),
            "191 terminal producer command changed"
        );
    }
    let events = native_events(cutoff)?;
    let terminal = manager_terminal(cutoff)?;
    let import = dispatch_import_check(
        &p.source_batch,
        &p.public_batch,
        &BTreeSet::from([191, 192, 193, 194]),
    )?;
    let v = json!({"schema":"jetstreamer-cohort191-terminal-transition-v1","first_epoch":191,"last_epoch":194,"recorded_unix_seconds":cutoff,"capture_plan":pb,"capture_program":p.program.path,"capture_self_sha256":p.program.sha256,"source_batch":p.source_batch,"public_batch":p.public_batch,"native_events":events,"producer":before,"producer_terminal":terminal,"controller_lifecycle":import["controller_lifecycle"],"native_import":import,"resource_samples":0,"publication_authorized":false,"replay_launch_authorized":false,"archive_readiness_claimed":false,"r2_mutations":false});
    jetstreamer_horizon_observe::cohort191_delivery_model::validate_terminal_transition(
        &v, cutoff,
    )?;
    ensure!(
        producer()? == before
            && native_events(cutoff)? == v["native_events"]
            && manager_terminal(cutoff)? == v["producer_terminal"]
            && dispatch_import_check(
                &p.source_batch,
                &p.public_batch,
                &BTreeSet::from([191, 192, 193, 194])
            )? == v["native_import"],
        "191 terminal collection raced original ownership/import"
    );
    let root = Path::new(ROOT);
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
    fn terminal_plan_cannot_import_future_observer_fields() {
        let v = json!({"schema":"jetstreamer-cohort191-terminal-collection-plan-v1","program":{"path":PROGRAM,"sha256":"a".repeat(64)},"source_batch":{"path":"/native/source","sha256":"b".repeat(64)},"public_batch":{"path":"/native/public","sha256":"c".repeat(64)},"output":Path::new(ROOT).join("terminal.json")});
        serde_json::from_value::<Plan>(v.clone()).unwrap();
        let mut bad = v;
        bad["observer"] = json!({"sha256":"future"});
        assert!(serde_json::from_value::<Plan>(bad).is_err());
    }
}
