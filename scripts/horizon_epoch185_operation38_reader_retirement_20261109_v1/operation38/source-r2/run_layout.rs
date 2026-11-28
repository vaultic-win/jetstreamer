//! Create and verify the exact empty Sol run layout before any actor activation.
//! Metadata-only scan; no existing actor, ledger, payload, guard or timer mutation.
use super::*;
const CHILDREN: [&str; 4] = ["scratch", "ledger", "output", "receipts"];
fn directory(path: &Path, empty: bool) -> Result<()> {
    let m=fs::symlink_metadata(path)?;
    ensure!(m.is_dir() && !m.file_type().is_symlink() && path.canonicalize()?==path
        && m.uid()==1001 && m.gid()==1003 && m.mode()&0o777==0o700,"exact Sol0700 run layout directory");
    if empty { ensure!(fs::read_dir(path)?.next().is_none(),"run layout child must remain initially empty"); }
    Ok(())
}
fn inspect(run: &Path, control: &Path) -> Result<()> {
    directory(run,false)?;directory(control,true)?;
    let names=fs::read_dir(run)?.map(|e|Ok(e?.file_name().to_string_lossy().into_owned())).collect::<Result<std::collections::BTreeSet<_>>>()?;
    ensure!(names==CHILDREN.iter().map(|s|s.to_string()).collect::<std::collections::BTreeSet<_>>(),"run layout has missing or foreign children");
    for name in CHILDREN {directory(&run.join(name),true)?;}
    Ok(())
}
pub(super) fn prepare(run: &Path, control: &Path) -> Result<()> {
    // owned_sol is create-new: existing directories/symlinks are never repaired in place.
    owned_sol(run)?;owned_sol(control)?;
    for name in CHILDREN {owned_sol(&run.join(name))?;}
    inspect(run,control)
}
pub(crate) fn sol_check(spec: &Bound, own: &Bound) -> Result<()> {
    ensure!(unsafe{libc::geteuid()}==1001 && unsafe{libc::getegid()}==1003,"actual Sol:horizon scan");
    let v=storage::json(spec)?;
    ensure!(v["schema"]=="horizon-positive185-empty-sol-run-layout-v1" && v["no_input_or_replay"]==true,"run layout scan scope");
    let run=Path::new(text(&v,"run_root")?);let control=Path::new(text(&v,"control_root")?);
    inspect(run,control)?;
    for path in std::iter::once(run.to_path_buf()).chain(std::iter::once(control.to_path_buf())).chain(CHILDREN.iter().map(|s|run.join(s))) {
        let c=std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        ensure!(unsafe{libc::access(c.as_ptr(),libc::R_OK|libc::W_OK|libc::X_OK)}==0,"actual Sol directory read/write/traverse access");
        fs::File::open(&path)?;
        let _=fs::read_dir(&path)?.collect::<std::io::Result<Vec<_>>>()?;
    }
    let status=fs::read_to_string("/proc/self/status")?;
    let cap=status.lines().find(|l|l.starts_with("CapEff:")).context("scan CapEff")?.split_whitespace().nth(1).context("scan caps")?;
    ensure!(u64::from_str_radix(cap,16)?==0 && status.lines().any(|l|l=="NoNewPrivs:\t1"),"unprivileged layout scan");
    println!("{}",json!({"schema":"horizon-positive185-empty-sol-run-layout-scan-v1","program":own,"spec":spec,"actual_sol_uid":1001,"actual_horizon_gid":1003,"all_four_children_empty_and_accessible":true,"effective_capabilities":0,"no_input_or_replay":true}));
    Ok(())
}
pub(super) fn prove_access(r: &mut process::Runner<'_>,run: &Path,control: &Path) -> Result<Bound> {
    inspect(run,control)?;
    let spec=storage::save(r.root,"run-layout-spec.json",&json!({"schema":"horizon-positive185-empty-sol-run-layout-v1","run_root":run,"control_root":control,"no_input_or_replay":true}))?;
    let dest=Path::new("/usr/local/lib/jetstreamer").join(format!("horizon-positive185-run-layout-{}",r.iid));
    let sealed=seal(r,"run-layout-spec",&dest,&[("spec.json",spec)])?;
    let sb=binding(&sealed["members"]["spec.json"])?;
    let mut c=Command::new("/usr/bin/systemd-run");
    c.args(["--wait","--pipe","--service-type=exec","--unit",&format!("horizon-positive185-run-layout-{}",r.iid)]);
    for prop in ["User=sol","Group=horizon","AppArmorProfile=horizon-witness-test-deny199-20261107-v1","Restart=no","MemoryMax=64M","MemorySwapMax=0","CPUQuota=100%","TasksMax=64","RuntimeMaxSec=30","TimeoutStopSec=2","KillMode=control-group","UMask=0077","NoNewPrivileges=yes","ProtectSystem=strict","ProtectHome=read-only","PrivateTmp=yes","PrivateDevices=yes","PrivateNetwork=yes","CapabilityBoundingSet=","AmbientCapabilities=","LimitNOFILE=1048576:1048576"] {c.arg(format!("--property={prop}"));}
    c.arg(format!("--property=WorkingDirectory={}",run.display()));
    c.arg(format!("--property=ReadWritePaths={} {}",run.display(),control.display()));
    c.arg(&r.self_image.path).arg("kernel-sol-run-layout-check").arg(&sb.path).args(["--request-sha256",&sb.sha256,"--self-sha256",&r.self_image.sha256]);
    let raw=r.run("actual-Sol-empty-run-layout-scan",c,Duration::from_secs(35))?;
    let result=process::stdout_json(&raw)?;
    ensure!(result["spec"]==json!(sb) && result["program"]==json!(r.self_image) && result["all_four_children_empty_and_accessible"]==true,"actual original layout child result");
    inspect(run,control)?;
    storage::save(r.root,"actual-Sol-run-layout-accepted.json",&json!({"spec":sb,"actual_original":raw,"result":result,"no_resource_credit_or_replay":true}))
}
pub(crate) fn qualify(v: &Value,r: &mut process::Runner<'_>) -> Result<()> {
    let run=PathBuf::from(text(v,"layout_sol_run_root")?);let control=PathBuf::from(text(v,"layout_sol_control_root")?);
    for path in [&run,&control] {ensure!(path.parent()==Some(Path::new("/home/sol/.jetstreamer-private")) && path.file_name().and_then(|s|s.to_str()).is_some_and(|s|s.starts_with("epoch185-positive-layout-control-")),"disjoint disposable layout-control roots");}
    prepare(&run,&control)?;let positive=prove_access(r,&run,&control)?;
    ensure!(prepare(&run,&control).is_err(),"existing layout cannot be reused");
    let scratch=run.join("scratch");let probe=scratch.join("qualification-only-nonempty");
    fs::OpenOptions::new().create_new(true).write(true).open(&probe)?;
    ensure!(inspect(&run,&control).is_err(),"nonempty child must reject");fs::remove_file(&probe)?;
    fs::remove_dir(&scratch)?;std::os::unix::fs::symlink(&control,&scratch)?;
    ensure!(inspect(&run,&control).is_err(),"symlink child must reject");fs::remove_file(&scratch)?;owned_sol(&scratch)?;
    let c=std::ffi::CString::new(scratch.as_os_str().as_encoded_bytes())?;
    ensure!(unsafe{libc::chown(c.as_ptr(),0,0)}==0,"foreign-owner negative setup");
    ensure!(inspect(&run,&control).is_err(),"foreign child owner must reject");
    ensure!(unsafe{libc::chown(c.as_ptr(),1001,1003)}==0,"restore disposable control custody");inspect(&run,&control)?;
    println!("{}",json!({"schema":"horizon-positive185-run-layout-qualified-control-v1","program":r.self_image,"positive":positive,"actual_Sol_scan_passed":true,"preexisting_nonempty_symlink_foreign_rejected":true,"no_input_or_replay":true,"no_resource_credit":true}));
    Ok(())
}
