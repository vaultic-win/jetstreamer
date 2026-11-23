use super::*;

const TARGET: &str = concat!(
    "/home/sol/.jetstreamer-private/epochs-186-v4-20261009-v1/lane-a/private/",
    "destination-d3e225dfe9a113290dcdb5f265a104c6e23ff971ab73887d955fa8f353fffa85/",
    "work/root-cohort-183-186/run-2115557-1792142259217714017/archives/epoch-183.jet"
);
const PRIVATE_SHA: &str = "f94c75ffecab198bf9109fd5483ba48f7f3074335371ad2436db31a67d66a691";
const CANONICAL_SHA: &str = "53b09716b3717f0b56fec4391c74ee54c9f7eece4334764bce5a5c6c14b7acff";
const STATE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1";
const ELIGIBILITY: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch199-delivery-recovery-20261121-v1/large-183-holding-park-v1/eligibility.json";
const ELIGIBILITY_SHA: &str = "0a7866481847c59833ac2cd9744fedf19b946524f629feaa485c826b56a6b7a3";
const PARK_UNIT: &str = "horizon-closed183-lane-a-park-20261123-v1.service";
const PARK_SPEC_SHA: &str = "3e925d1181796d5a5da05c75241a970ff47cf8c80f251e6ee753425b4ac1268a";
const PARK_IMAGE_SHA: &str = "a034c804e253e807191bdacf9e06301f0a92b52a69e41b9bd4a2dfa0b04b4e0f";
const OLD_UNITS: [&str; 3] = [
    "jetstreamer-epochs183-186-target4-controller-v3-r2.service",
    "jetstreamer-root-sweep-e183-186-t4-20261016-v3-r2-e183-186-lane-a-1.service",
    "horizon-other183-scoped-inspection-20261115-v1.service",
];

pub(super) fn is_target(t: &Target) -> bool {
    let s = &t.identity;
    t.epoch == 183
        && t.path == Path::new(TARGET)
        && (s.dev, s.ino, s.len, s.blocks) == (64512, 104857899, 131738922353, 257302944)
        && (s.mode, s.uid, s.gid, s.nlink) == (0o100600, 1001, 1003, 1)
        && (s.mtime, s.mtime_ns, s.ctime, s.ctime_ns)
            == (1792406735, 679427867, 1792406735, 679427867)
}

fn lock_inode(path: &Path, device: u64, inode: u64) -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o777 == 0o600
            && (m.dev(), m.ino()) == (device, inode)
            && stamp(&exact(path)?) == stamp(&m),
        "changed lock {}",
        path.display()
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "busy lock {}",
        path.display()
    );
    Ok(lock)
}

pub(super) fn lock_original_owners() -> Result<(File, File)> {
    Ok((
        lock_inode(&Path::new(STATE).join("transition.lock"), 64512, 95818311)?,
        lock_inode(
            Path::new(
                "/var/lib/jetstreamer-root-sweep-epochs183-186-target4-20261016-v3/controller.lock",
            ),
            2304,
            2758518,
        )?,
    ))
}

fn bound_json(value: &Value) -> Result<Value> {
    let b: Bound = serde_json::from_value(value.clone())?;
    Ok(serde_json::from_slice(&bound(&b, LIMIT)?)?)
}

fn unit(unit: &str) -> Result<String> {
    let output = Command::new("/usr/bin/systemctl").args(["show", unit, "-p",
        "Id,ActiveState,SubState,MainPID,ControlPID,Job,Triggers,TriggeredBy,Result,ExecMainCode,ExecMainStatus,ExecStart"])
        .output()?;
    ensure!(
        matches!(output.status.code(), Some(0 | 4)) && output.stderr.is_empty(),
        "cannot inspect {unit}"
    );
    let text = String::from_utf8(output.stdout)?;
    for field in [
        format!("Id={unit}"),
        "MainPID=0".into(),
        "ControlPID=0".into(),
        "Job=".into(),
        "Triggers=".into(),
        "TriggeredBy=".into(),
    ] {
        ensure!(
            text.lines().any(|line| line == field),
            "live or scheduled owner {unit}"
        );
    }
    Ok(text)
}

pub(super) fn check_owners() -> Result<()> {
    for name in OLD_UNITS {
        let text = unit(name)?;
        ensure!(
            text.lines()
                .any(|l| matches!(l, "ActiveState=inactive" | "ActiveState=failed")),
            "live original owner {name}"
        );
    }
    let text = unit(PARK_UNIT)?;
    for field in [
        "ActiveState=active",
        "SubState=exited",
        "Result=success",
        "ExecMainCode=1",
        "ExecMainStatus=0",
    ] {
        ensure!(
            text.lines().any(|line| line == field),
            "holding worker has not completed successfully"
        );
    }
    let expect = format!(" --spec-sha256 {PARK_SPEC_SHA} --self-sha256 {PARK_IMAGE_SHA} ;");
    ensure!(
        text.lines().any(|l| l.starts_with("ExecStart=")
            && l.contains(" holding-park ")
            && l.contains(&expect)),
        "different holding worker command"
    );
    let run = Path::new(TARGET)
        .ancestors()
        .nth(2)
        .and_then(Path::file_name)
        .context("missing original run directory")?;
    let roots = [
        "/etc/systemd",
        "/run/systemd/transient",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/etc/cron.d",
        "/var/spool/cron",
    ];
    let scan = Command::new("/usr/bin/rg")
        .args(["--no-config", "--no-ignore", "--hidden", "-l", "-F", "-e"])
        .arg(run)
        .arg("--")
        .args(roots.into_iter().filter(|p| Path::new(p).exists()))
        .output()?;
    ensure!(
        matches!(scan.status.code(), Some(0 | 1)) && scan.stderr.is_empty(),
        "staged owner scan failed"
    );
    for line in String::from_utf8(scan.stdout)?.lines() {
        ensure!(
            Path::new(line)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| OLD_UNITS.contains(&name)),
            "unreviewed staged reference {line}"
        );
    }
    Ok(())
}

pub(super) fn has_mapping(maps: &[u8], t: &Target) -> bool {
    let dev = format!(
        "{:02x}:{:02x}",
        libc::major(t.identity.dev),
        libc::minor(t.identity.dev)
    );
    let ino = t.identity.ino.to_string();
    maps.split(|&b| b == b'\n').any(|line| {
        let mut fields = line
            .split(|b| b.is_ascii_whitespace())
            .filter(|part| !part.is_empty())
            .skip(3);
        fields.next() == Some(dev.as_bytes()) && fields.next() == Some(ino.as_bytes())
    })
}

fn check_custody(c: &Value, length: u64) -> Result<()> {
    ensure!(
        c["schema"] == "jetstreamer-horizon-holding-custody-v2"
            && c["host"] == "dev-samjohnson"
            && c["prefix"] == "node_02/"
            && c["bucket"] == "solana-archive-with-accounts-data"
            && c["source"] == TARGET
            && c["length"] == length
            && c["sha256"] == PRIVATE_SHA
            && c["object_key"] == format!("node_02/objects/{PRIVATE_SHA}.blob")
            && c["eligibility"] == json!({"path":ELIGIBILITY,"sha256":ELIGIBILITY_SHA})
            && c["remote_sha256_readback"] == true
            && c["local_source_revalidated"] == true
            && c["local_retirement_authorized"] == false
            && c["canonical_publication_authorized"] == false,
        "holding receipt does not prove custody of the selected private archive"
    );
    let m = &c["manifest"];
    let sha = c["manifest_sha256"]
        .as_str()
        .context("missing manifest digest")?;
    ensure!(
        sha.len() == 64
            && sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && c["manifest_key"] == format!("node_02/manifests/{sha}.json")
            && m["schema"] == "jetstreamer-horizon-holding-manifest-v2"
            && m["host"] == c["host"]
            && m["prefix"] == c["prefix"]
            && m["length"] == c["length"]
            && m["sha256"] == c["sha256"]
            && m["object_key"] == c["object_key"]
            && m["eligibility_sha256"] == ELIGIBILITY_SHA
            && m["canonical_archive"] == false
            && m["canonical_publication_authorized"] == false,
        "holding manifest differs from custody"
    );
    Ok(())
}

pub(super) fn verify(p: &Plan, lock: &File) -> Result<()> {
    let m = lock.metadata()?;
    ensure!(
        (m.dev(), m.ino(), m.uid(), m.gid(), m.mode()) == (64512, 101135013, 1001, 1003, 0o100600),
        "different shared mutation lock"
    );
    ensure!(
        p.targets.len() == 1 && p.proofs.len() == 1,
        "select exactly the parked lane-a archive"
    );
    ensure!(
        p.audit.parent() == Some(Path::new(STATE).join("retirements").as_path()),
        "retirement audit must stay in the holding state"
    );
    check_owners()?;
    let path = &p.holding_custody.path;
    let meta = exact(path)?;
    ensure!(
        path.parent() == Some(Path::new(STATE).join("receipts").as_path())
            && meta.uid() == 0
            && meta.mode() & 0o222 == 0,
        "custody must be an immutable native receipt"
    );
    let c: Value = serde_json::from_slice(&bound(&p.holding_custody, LIMIT)?)?;
    check_custody(&c, p.targets[0].identity.len)?;
    let name = format!(
        "custody-{}.json",
        c["manifest_sha256"]
            .as_str()
            .context("missing manifest digest")?
    );
    ensure!(
        path.file_name().and_then(|x| x.to_str()) == Some(name.as_str()),
        "custody filename differs from native manifest digest"
    );
    let eligibility = bound_json(&c["eligibility"])?;
    let canonical = bound_json(&eligibility["canonical"])?;
    ensure!(
        canonical["archive_sha256"] == CANONICAL_SHA && canonical["remote_sha256_readback"] == true,
        "missing canonical epoch 183 delivery evidence"
    );
    ensure!(
        eligibility["canonical"]
            == json!({"path":p.proofs[0].receipt.path,"sha256":p.proofs[0].receipt.sha256}),
        "different canonical inventory proof"
    );
    let verified = eligibility["canonical_verified"]
        .as_array()
        .context("missing canonical checks")?;
    ensure!(
        verified.len() == 4,
        "missing full, plugin or adjacent boundary checks"
    );
    for check in verified {
        bound(&serde_json::from_value(check.clone())?, 4096)?;
    }
    let remote = Command::new("/usr/bin/python3")
        .args(["-IB", "-c", include_str!("anza_parked_183_r2.py")])
        .arg(path)
        .output()?;
    ensure!(
        remote.status.success(),
        "authenticated holding recheck failed: {}",
        String::from_utf8_lossy(&remote.stderr)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_binds_only_verified_private_object() {
        let key = format!("node_02/objects/{PRIVATE_SHA}.blob");
        let length = 131738922353u64;
        let manifest = json!({"schema":"jetstreamer-horizon-holding-manifest-v2",
            "host":"dev-samjohnson","prefix":"node_02/","length":length,"sha256":PRIVATE_SHA,
            "object_key":key,"eligibility_sha256":ELIGIBILITY_SHA,"canonical_archive":false,
            "canonical_publication_authorized":false});
        let sha = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&manifest).unwrap())
        );
        let c = json!({"schema":"jetstreamer-horizon-holding-custody-v2","host":"dev-samjohnson",
            "bucket":"solana-archive-with-accounts-data","prefix":"node_02/","length":length,
            "source":TARGET,"sha256":PRIVATE_SHA,"object_key":key,"manifest":manifest,"manifest_sha256":sha,
            "manifest_key":format!("node_02/manifests/{sha}.json"),
            "eligibility":{"path":ELIGIBILITY,"sha256":ELIGIBILITY_SHA},"remote_sha256_readback":true,
            "local_source_revalidated":true,"local_retirement_authorized":false,"canonical_publication_authorized":false});
        check_custody(&c, length).unwrap();
        for (field, value) in [
            ("remote_sha256_readback", json!(false)),
            ("source", json!("/home/sol/horizon/epoch-183.jet")),
            ("sha256", json!(CANONICAL_SHA)),
            ("manifest_key", json!("node_02/manifests/foreign.json")),
        ] {
            let mut wrong = c.clone();
            wrong[field] = value;
            assert!(
                check_custody(&wrong, length).is_err(),
                "accepted changed {field}"
            );
        }
    }
}
