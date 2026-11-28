fn require(ok: bool, why: &str) -> R<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn clock() -> R<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn number(v: &Value, key: &str) -> R<u64> {
    v[key]
        .as_u64()
        .ok_or_else(|| format!("missing integer {key}").into())
}
fn string<'a>(v: &'a Value, key: &str) -> R<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("missing string {key}").into())
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.blocks()
    ])
}
fn bytes(path: &Path, cap: u64) -> R<Vec<u8>> {
    require(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical no-symlink path required",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    let before = f.metadata()?;
    require(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= cap,
        "unsafe Root metadata",
    )?;
    let mut out = Vec::new();
    Read::by_ref(&mut f).take(cap + 1).read_to_end(&mut out)?;
    require(
        out.len() as u64 == before.len()
            && identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "metadata changed",
    )?;
    Ok(out)
}
fn bound(b: &Value) -> R<Value> {
    let raw = bytes(Path::new(string(b, "path")?), 32 << 20)?;
    require(
        sha(&raw) == string(b, "sha256")?,
        "bound evidence SHA mismatch",
    )?;
    Ok(serde_json::from_slice(&raw)?)
}
fn durable(path: &Path, value: &Value) -> R<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    f.write_all(&serde_json::to_vec(value)?)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(path.parent().ok_or("receipt parent")?)?.sync_all()?;
    Ok(())
}
fn native(unit: &str) -> R<Value> {
    let fields = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Restart,Result,ExecMainCode,ExecMainStatus,ControlGroup,Job,TriggeredBy,Triggers,WantedBy,RequiredBy,Upholds,UpheldBy,DropInPaths,FragmentPath,ExecStart,ExecStartPre,Type,User,Group,KillMode,Delegate,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ExecMainPID,ExecMainStartTimestamp,ExecMainExitTimestamp,RuntimeMaxUSec";
    let out = Command::new("/usr/bin/systemctl")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .args(["show", unit, "--no-pager", "-p", fields])
        .output()?;
    require(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() < 65536,
        "native property capture failed",
    )?;
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').ok_or("native delimiter")?;
        require(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate native property",
        )?;
    }
    Ok(Value::Object(map))
}
fn unit_object(unit: &str) -> String {
    let mut s = String::from("/org/freedesktop/systemd1/unit/");
    for b in unit.bytes() {
        if b.is_ascii_alphanumeric() {
            s.push(char::from(b));
        } else {
            s.push_str(&format!("_{b:02x}"));
        }
    }
    s
}
fn empty_native_hook(unit: &str, property: &str) -> R<()> {
    let out = Command::new("/usr/bin/busctl")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .args([
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            &unit_object(unit),
            "org.freedesktop.systemd1.Service",
            property,
        ])
        .output()?;
    require(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() < 65536,
        "typed native hook capture failed",
    )?;
    let v: Value = serde_json::from_slice(&out.stdout)?;
    require(
        v["type"] == "a(sasbttttuii)" && v["data"] == json!([]),
        "nonempty or untyped native execution hook",
    )
}
fn path_ref(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).enumerate().any(|(i, s)| {
        s == needle
            && (i + needle.len() == bytes.len()
                || b"/\0\n\r\t '\";|&()<>[]{}:=,".contains(&bytes[i + needle.len()]))
    })
}
fn check_blob(bytes: &[u8], targets: &[PathBuf], label: &str) -> R<()> {
    for p in targets {
        require(
            !path_ref(bytes, p.as_os_str().as_encoded_bytes()),
            &format!("consumer reference: {label}"),
        )?;
    }
    Ok(())
}
fn transient(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(3)
}
fn proc_scan(targets: &[PathBuf]) -> R<Value> {
    let me = std::process::id().to_string();
    let mut count = 0;
    for entry in fs::read_dir("/proc")? {
        let p = entry?.path();
        let name = p.file_name().ok_or("pid name")?.to_string_lossy();
        if name == me || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let before = match fs::read(p.join("stat")) {
            Ok(x) => x,
            Err(e) if transient(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        for n in ["cmdline", "maps", "environ"] {
            match fs::read(p.join(n)) {
                Ok(b) => check_blob(&b, targets, &format!("{name}/{n}"))?,
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        for n in ["cwd", "root", "exe"] {
            match fs::read_link(p.join(n)) {
                Ok(q) => check_blob(
                    q.as_os_str().as_encoded_bytes(),
                    targets,
                    &format!("{name}/{n}"),
                )?,
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        match fs::read_dir(p.join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    let fd = fd?;
                    match fs::read_link(fd.path()) {
                        Ok(q) => check_blob(
                            q.as_os_str().as_encoded_bytes(),
                            targets,
                            &format!("{name}/fd"),
                        )?,
                        Err(e) if transient(&e) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Err(e) if transient(&e) => {}
            Err(e) => return Err(e.into()),
        }
        if let Ok(after) = fs::read(p.join("stat")) {
            require(
                start_ticks(&before)? == start_ticks(&after)?,
                "PID reused during census",
            )?;
        }
        count += 1;
    }
    Ok(json!({"processes":count,"permission_errors":0}))
}
fn start_ticks(b: &[u8]) -> R<&str> {
    let s = std::str::from_utf8(b)?;
    s.rsplit_once(')')
        .ok_or("bad proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| "missing proc start ticks".into())
}
