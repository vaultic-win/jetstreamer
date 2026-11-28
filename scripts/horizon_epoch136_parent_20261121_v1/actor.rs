use super::*;
use std::process::Command;

pub(super) fn mirrors(fleet: &Value, prepare: bool) -> Result<Vec<(PathBuf, PathBuf)>> {
    let target = Path::new(text(&fleet["path"])?);
    let dir = target.parent().context("fleet parent")?;
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .context("fleet name")?;
    ensure!(
        dir.parent() == Some(Path::new("/var/lib/jetstreamer/horizon_runtime_data"))
            && name.starts_with("root")
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            && target
                .file_name()
                .is_some_and(|n| n == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
        "unexpected fleet location"
    );
    let root = Path::new(OUT);
    let store = root.join("immutable-inputs");
    if prepare {
        trusted_dir(root, "immutable-inputs")?;
    } else {
        open_dir(&store)?;
    }
    let mut pins = Vec::new();
    for (original, digest) in [
        (
            Path::new(payload_scope::DOWNLOAD),
            payload_scope::DOWNLOAD_SHA,
        ),
        (target, text(&fleet["sha256"])?),
    ] {
        let bytes = read(original)?;
        ensure!(
            bytes.len() <= 16 << 20 && sha(&bytes) == digest,
            "stale actor input {}",
            original.display()
        );
        let copy = store.join(format!("{digest}.json"));
        if prepare && !copy.try_exists()? {
            create(&copy, &bytes, 0o400)?;
        }
        ensure!(
            fs::symlink_metadata(&copy)?.mode() & 0o222 == 0 && read(&copy)? == bytes,
            "unqualified actor input projection"
        );
        pins.push((copy, original.to_owned()));
    }
    Ok(pins)
}
pub(super) fn quantity_args(
    plan: &Value,
    image: &Value,
    admission: &Value,
    package: &Path,
) -> Result<Vec<String>> {
    let mut argv = vec!["--quiet".to_owned(), format!("--unit={ACTOR}")];
    for property in [
        "Type=exec",
        "Restart=no",
        "KillMode=control-group",
        "RuntimeMaxSec=21720",
        "TimeoutStopSec=120",
        "MemoryAccounting=yes",
        "MemoryHigh=68719476736",
        "MemoryMax=73014444032",
        "MemorySwapMax=0",
        "TasksMax=512",
        "CPUQuota=300%",
        "Delegate=no",
        "NoNewPrivileges=yes",
        "UMask=0077",
        "User=root",
        "Group=root",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "PrivateDevices=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID CAP_CHOWN CAP_SYS_PTRACE CAP_KILL",
    ] {
        argv.push(format!("--property={property}"));
    }
    // The sealed payload itself creates the reproduction directory and refuses
    // an existing one. Keep the parent writable for that creation and mount its
    // other, already-present children read-only for the actor's lifetime.
    argv.push(format!("--property=ReadWritePaths={BASE}"));
    argv.push(format!(
        "--property=BindReadOnlyPaths={}:{}",
        package.display(),
        at("controller").display()
    ));
    for entry in fs::read_dir(BASE)? {
        let p = entry?.path();
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .context("unsafe base child name")?;
        ensure!(
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && p.canonicalize()? == p
                && fs::symlink_metadata(&p)?.uid() == 0,
            "unsafe base child {}",
            p.display()
        );
        if name != "controller" && name != "reproduction" {
            argv.push(format!("--property=ReadOnlyPaths={}", p.display()));
        }
    }
    argv.extend(
        [
            text(&image["path"])?,
            text(&plan["path"])?,
            "--plan-sha256",
            text(&plan["sha256"])?,
            "--self-sha256",
            text(&image["sha256"])?,
            "--admission",
            text(&admission["path"])?,
            "--admission-sha256",
            text(&admission["sha256"])?,
        ]
        .map(str::to_owned),
    );
    Ok(argv)
}
pub fn launch_args(x: &Input) -> Result<Vec<String>> {
    let mut args = quantity_args(
        &x.request["plan"],
        &x.full["helper"],
        &x.admission,
        &x.package,
    )?;
    let idx = args
        .iter()
        .position(|v| v == x.full["helper"]["path"].as_str().unwrap_or(""))
        .context("missing payload command")?;
    for (image, target) in mirrors(&x.fleet, false)?.into_iter().rev() {
        args.insert(
            idx,
            format!(
                "--property=BindReadOnlyPaths={}:{}",
                image.display(),
                target.display()
            ),
        );
    }
    Ok(args)
}
fn closed(u: &str) -> Result<()> {
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "--property=Id,LoadState,ActiveState,MainPID,Job",
            "--",
            u,
        ])
        .output()?;
    let row: std::collections::HashMap<&str, &str> = std::str::from_utf8(&out.stdout)?
        .lines()
        .filter_map(|l| l.split_once('='))
        .collect();
    ensure!(
        row.get("Id") == Some(&u)
            && (out.status.success()
                || out.status.code() == Some(4) && row.get("LoadState") == Some(&"not-found"))
            && row.get("ActiveState") == Some(&"inactive")
            && row.get("Job") == Some(&"")
            && row.get("MainPID").is_none_or(|p| *p == "0")
            && group_members(&format!("/system.slice/{u}"))?.is_empty(),
        "{u} already owns or previously failed work"
    );
    Ok(())
}
pub fn launch(x: &Input) -> Result<()> {
    x.live_admission()?;
    let out = trusted_dir(
        Path::new(OUT),
        require_iid(&x.request["writer_invocation_id"])?,
    )?;
    let _lock = super::status::take_lock(&out.join("launch.lock"), true)?;
    ensure!(
        !out.join("LAUNCH_INTENT.json").try_exists()? && !at("reproduction").try_exists()?,
        "generation already attempted; inspect its native outcome"
    );
    closed(ACTOR)?;
    closed(&format!("{GUARD}.service"))?;
    closed(&format!("{GUARD}.timer"))?;
    let args = launch_args(x)?;
    let record = protect_json(
        &out.join("LAUNCH_INTENT.json"),
        &json!({"at":now(),"request":x.request_ref,"admission":x.admission,"writer_plan":x.writer_plan,"payload_plan":x.request["plan"],"writer_deployment":x.package_seal,"writer_pid":x.writer_pid,"writer_start_ticks":x.writer_ticks,"systemd_run":args}),
    )?;
    x.live_admission()?;
    let status = Command::new("/usr/bin/systemd-run").args(&args).status()?;
    ensure!(
        status.success(),
        "systemd submission uncertain or failed; inspect retained intent before retry"
    );
    let row = native(ACTOR)?;
    let iid = require_iid(&row["InvocationID"])?;
    let pid: i32 = text(&row["MainPID"])?.parse()?;
    ensure!(
        row["ActiveState"] == "active"
            && row["SubState"] == "running"
            && row["NRestarts"] == "0"
            && row["ControlGroup"] == format!("/system.slice/{ACTOR}")
            && same_inode(&proc_path(pid, "exe"), &at("tools/epoch136-actual-payload"))?
            && same_inode(
                &proc_path(pid, "root").join(at("controller/admit136").strip_prefix("/")?),
                &x.package.join("admit136")
            )?,
        "unexpected launched owner or controller mount"
    );
    for (image, target) in mirrors(&x.fleet, false)? {
        ensure!(
            same_inode(
                &proc_path(pid, "root").join(target.strip_prefix("/")?),
                &image
            )?,
            "launched actor input mount differs"
        );
    }
    println!(
        "{}",
        protect_json(
            &out.join("PARENT_LAUNCHED.json"),
            &json!({"at":now(),"intent":record,"unit":ACTOR,"invocation_id":iid,"pid":pid,"start_ticks":ticks(pid)?,"native":row,"worker_initialize_authorized":false,"ordinary_replay_claim":false})
        )?
    );
    Ok(())
}
