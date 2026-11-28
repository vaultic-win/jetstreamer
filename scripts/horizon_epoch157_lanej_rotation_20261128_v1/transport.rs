//! Use the proven epoch 186 conditional receiver, one anonymous HOME inode and no-clobber publication.
use super::*;
const GENESIS: &str =
    "/usr/local/lib/jetstreamer/horizon-node02-holding-custody-20261023-v1/custody.json";
const GEN_SHA: &str = "749435d6a63400446a85ef1b39062077f682311b796135c058af8cf465b64629";
// The existing, sealed receiver checks the ETag and length of the signed GET, hashes every
// received byte, fsyncs the destination and independently re-reads its full on-disk contents.
const BRIDGE: &str = r#"import json,os,pathlib,runpy,sys
api=runpy.run_path(sys.argv[1])
expected=json.loads(sys.argv[2])
expected["custody_path"]=sys.argv[3]
client, remote=api["checked_remote"](expected,True)
if sys.argv[4]=="receive":
    floor=int(sys.argv[5])
    directory=pathlib.Path(sys.argv[6])
    def guard(remaining):
        api["need"](api["avail"](directory)>=floor+remaining+(16<<20),"single-copy receiver reached protected HOME floor")
    with os.fdopen(os.dup(0),"r+b") as f:
        api["receive"](client,remote["blob"],expected["sha256"],f,guard)
    _, remote=api["checked_remote"](expected,True)
elif sys.argv[4]=="negative":
    shared=api["s3"]()
    try:
        client.get_object(Bucket=shared["BUCKET"],Key=expected["object_key"],IfMatch='"changed-fixture-etag"')
    except shared["ClientError"] as error:
        if error.response["ResponseMetadata"]["HTTPStatusCode"]!=412: raise
    else:
        raise ValueError("wrong ETag accepted")
    remote["wrong_etag_status"]=412
print(json.dumps(remote))
"#;
pub(super) fn custody_file(e: &Value) -> Result<PathBuf> {
    let sha = word(e, "manifest_sha256")?;
    ensure!(
        sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid manifest digest"
    );
    Ok(Path::new(HOLD)
        .join("receipts")
        .join(format!("custody-{sha}.json")))
}
fn network(e: &Value, mode: &str, source: Option<&File>, floor: u64, dir: &Path) -> Result<Value> {
    let pack = pinned(
        &Path::new(OLD).join("deployment-seal-receipt.json"),
        "81d6f44372cf6dd4150f213019425dece40aeef0cc4e7bfa97cfad0707873d74",
    );
    let old = member(&pack, "rotation.py")?;
    member(&pack, "consumers.py")?;
    let h = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanem-main-holding-20261127-v1/retirement-tools-v1/holding_identity.py",
    );
    ensure!(
        reference(h)?["sha256"]
            == "0568178c570d9c12fad62ca2d03b7322451a344ea6509cfdc2855d7a4a553a54",
        "different signed GET implementation"
    );
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.args(["-IB", "-c", BRIDGE])
        .arg(old)
        .arg(serde_json::to_string(e)?)
        .arg(custody_file(e)?)
        .arg(mode)
        .arg(floor.to_string())
        .arg(dir);
    if let Some(f) = source {
        cmd.stdin(Stdio::from(f.try_clone()?));
    }
    let o = cmd.output()?;
    ensure!(
        o.status.success(),
        "conditional holding receiver failed: {}",
        String::from_utf8_lossy(&o.stderr)
            .lines()
            .last()
            .unwrap_or("unknown")
    );
    let v: Value = serde_json::from_slice(&o.stdout)?;
    ensure!(
        v["blob"]["status"] == 200
            && v["blob"]["key"] == e["object_key"]
            && v["blob"]["length"] == e["length"]
            && v["manifest"]["key"] == e["manifest_key"]
            && v["owner"]["key"] == "node_02/owner.json"
            && v["custody"] == reference(&custody_file(e)?)?,
        "wrong authenticated remote"
    );
    Ok(v)
}
pub(super) fn remote(e: &Value, f: Option<&File>, floor: u64, dir: Option<&Path>) -> Result<Value> {
    network(
        e,
        if f.is_some() { "receive" } else { "metadata" },
        f,
        floor,
        dir.unwrap_or_else(|| Path::new(ROOT)),
    )
}
fn anonymous(dir: &Path) -> Result<File> {
    ensure!(
        dir.canonicalize()? == dir && fs::metadata(dir)?.dev() == fs::metadata("/home/sol")?.dev(),
        "not an exact HOME directory"
    );
    let x = CString::new(dir.as_os_str().as_encoded_bytes())?;
    let fd = unsafe {
        libc::open(
            x.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(fd >= 0, "anonymous file: {}", io::Error::last_os_error());
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn publish(f: &File, dst: &Path) -> io::Result<()> {
    let name = CString::new(dst.as_os_str().as_encoded_bytes())?;
    if unsafe {
        libc::linkat(
            f.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            name.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    File::open(dst.parent().unwrap())?.sync_all()
}
pub(super) fn restore_file(dst: &Path, e: &Value, floor: u64) -> Result<Value> {
    let parent = dst.parent().context("restore parent")?;
    let id = &e["source_identity"];
    let n = num(e, "length")?;
    let hash = word(e, "sha256")?;
    if dst.try_exists()? {
        let m = fs::symlink_metadata(dst)?;
        let mut v = identity(&m);
        let mut want = id.clone();
        for k in ["ctime_ns", "inode", "allocated"] {
            v.as_object_mut().unwrap().remove(k);
            want.as_object_mut().unwrap().remove(k);
        }
        ensure!(
            m.is_file() && dst.canonicalize()? == dst && v == want,
            "original path occupied by different metadata"
        );
        let mut f = File::open(dst)?;
        check_hash(&mut f, hash)?;
        ensure!(
            f.metadata()?.ino() == fs::symlink_metadata(dst)?.ino(),
            "existing restore changed"
        );
        return Ok(
            json!({"source":dst,"sha256":hash,"identity":identity(&m),"already_restored":true}),
        );
    }
    ensure!(
        available()?.0
            >= floor
                .checked_add(n)
                .and_then(|x| x.checked_add(META))
                .context("restore overflow")?,
        "insufficient space at original path"
    );
    let f = anonymous(parent)?;
    let auth = remote(e, Some(&f), floor, Some(parent))?;
    let fd = f.as_raw_fd();
    let ns = num(id, "mtime_ns")?;
    let t = libc::timespec {
        tv_sec: (ns / 1000000000).try_into()?,
        tv_nsec: (ns % 1000000000).try_into()?,
    };
    let ts = [t, t];
    ensure!(
        unsafe { libc::fchown(fd, num(id, "uid")?.try_into()?, num(id, "gid")?.try_into()?) } == 0
            && unsafe { libc::fchmod(fd, num(id, "mode")?.try_into()?) } == 0
            && unsafe { libc::futimens(fd, ts.as_ptr()) } == 0,
        "restore original metadata: {}",
        io::Error::last_os_error()
    );
    f.sync_all()?;
    let m = f.metadata()?;
    ensure!(
        m.nlink() == 0 && m.len() == n && m.dev() == fs::metadata(parent)?.dev(),
        "incorrect anonymous restored extent"
    );
    publish(&f, dst)?;
    let installed = fs::symlink_metadata(dst)?;
    ensure!(
        dst.canonicalize()? == dst && installed.ino() == m.ino() && installed.nlink() == 1,
        "different visible destination"
    );
    Ok(
        json!({"source":dst,"sha256":hash,"identity":identity(&installed),"authenticated_remote":auth,"single_inode":true,"fsynced":true,"whole_local_readback":true}),
    )
}
pub(super) fn fixture(fit: &Value) -> Result<Value> {
    let (_, iid) = role()?;
    let genesis = bound(&pinned(Path::new(GENESIS), GEN_SHA))?;
    let dir = root("workspace-fixture").join(&iid);
    fs::create_dir(&dir)?;
    let interrupted = anonymous(&dir)?;
    use std::io::Write;
    (&interrupted).write_all(b"interrupted")?;
    interrupted.sync_all()?;
    drop(interrupted);
    ensure!(
        fs::read_dir(&dir)?.next().is_none(),
        "aborted receive left a named file"
    );
    let mut witness = genesis.clone();
    witness["source_identity"] = screen()?["source_stat"].clone();
    witness["source_identity"]["length"] = genesis["length"].clone();
    let dst = dir.join(Path::new(SRC).file_name().unwrap());
    let n = network(&witness, "negative", None, 0, &dir)?;
    ensure!(n["wrong_etag_status"] == 412, "ETag test");
    let restored = restore_file(&dst, &witness, num(fit, "floor")?)?;
    let conflict = anonymous(&dir)?;
    ensure!(
        publish(&conflict, &dst).is_err_and(|e| e.kind() == io::ErrorKind::AlreadyExists),
        "existing inode replaced"
    );
    let again = restore_file(&dst, &witness, num(fit, "floor")?)?;
    ensure!(
        again["already_restored"] == true && again["identity"] == restored["identity"],
        "idempotent restoration differs"
    );
    let plan = expected()?;
    ensure!(
        num(&plan, "length")? + META == 122423339643 && LENGTH + META <= 123350028052,
        "real restoration exceeds the paid slot"
    );
    let q = json!({"passed":true,"scope":"single-copy authenticated original-path 157 lane-j restoration","target":SRC,"fixture_invocation":iid,"operator_seal":ours()?,"native_fixture":restored,"reference_186":reference(&Path::new(OLD).parent().unwrap().join("RESTORE_FIXTURE_ACCEPTED.json"))?,"interrupted_unnamed":true,"no_clobber":true,"wrong_etag":412,"idempotent":true,"retained_original_metadata":true,"charged_bytes":LENGTH+META,"paid_slot":123350028052u64,"future_command":"restore under fresh 157 serial holding admission","fixture_source":pinned(Path::new(GENESIS),GEN_SHA),"publication_authorized":false});
    stable(&root("RESTORE_QUALIFICATION.json"), &q)
}
