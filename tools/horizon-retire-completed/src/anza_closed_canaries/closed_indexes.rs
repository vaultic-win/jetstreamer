use super::*;

pub(crate) const REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/closed191194-index-retirement-20261125-v1/REVIEW.json";
pub(crate) const SHA: &str = "87f2d2f6bad703779f827d356ae26118026888f90f830f45cb435590cf0a22a6";
pub(crate) const SCHEMA: &str = "horizon-191-194-completed-car-index-review-v1";
const CACHE: &str =
    "/home/sol/.jetstreamer-private/epochs-191-194-v4-20261009-v1/lane-a/output/compact-indexes";
const CIDS: [(u64, &str); 4] = [
    (
        191,
        "bafyreiduie3qt2s6fydidb7hu7cjy5wzglbfqjpxazyslkbd4zsivukuby",
    ),
    (
        192,
        "bafyreidovuzmolqci5kemkcubd6753nq3lgpyx5afqjhsapqtcmxrqxjau",
    ),
    (
        193,
        "bafyreicxewnbrop5ypxtrjhssmgcd4ds2rmhkwb3qmwjvjmfmj4tc52a34",
    ),
    (
        194,
        "bafyreiasmb7n4dtqzb3uqjkiib4pke7n7hwqtq4rqcwlnz4v4rwfz46qp4",
    ),
];
const SUFFIXES: [&str; 2] = ["cid-to-offset-and-size.index", "slot-to-cid.index"];

fn index_path(epoch: u64, cid: &str, suffix: &str) -> PathBuf {
    Path::new(CACHE)
        .join(epoch.to_string())
        .join(format!("epoch-{epoch}-{cid}-mainnet-{suffix}"))
}

pub(crate) fn is_index(t: &Target) -> bool {
    CIDS.iter().any(|&(epoch, cid)| {
        t.epoch == epoch
            && SUFFIXES
                .iter()
                .any(|suffix| index_path(epoch, cid, suffix) == t.path)
    })
}

pub(super) fn complete_selection(targets: &[Target]) -> bool {
    targets.len() == 8
        && targets.iter().all(is_index)
        && targets
            .iter()
            .map(|t| &t.path)
            .collect::<BTreeSet<_>>()
            .len()
            == 8
}

pub(crate) fn lock_index_controllers() -> Result<[File; 2]> {
    Ok([
        controller_lock(
            "/var/lib/jetstreamer-root-sweep-epochs191-194-v4-20261009-v1/controller.lock",
            3802979,
        )?,
        controller_lock(
            "/var/lib/jetstreamer-root-sweep-epochs191-194-target5-20261016-v2/controller.lock",
            2758533,
        )?,
    ])
}

fn evidence(entry: &Value) -> Result<Vec<u8>> {
    bound(
        &Bound {
            path: entry["path"]
                .as_str()
                .context("missing evidence path")?
                .into(),
            sha256: entry["sha256"]
                .as_str()
                .context("missing evidence digest")?
                .into(),
        },
        LIMIT,
    )
}

fn check_marker(unit: &str, condition: &Value, loaded: bool) -> Result<()> {
    let marker = condition["marker"]
        .as_str()
        .context("missing admission marker")?;
    let fragment = String::from_utf8(evidence(&condition["dropin"])?)?;
    ensure!(
        fragment
            .lines()
            .any(|line| line == format!("ConditionPathExists={marker}")),
        "admission condition changed for {unit}"
    );
    ensure!(
        fs::symlink_metadata(marker).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "admission path present or inaccessible: {marker}"
    );
    if loaded {
        let mut object = String::from("/org/freedesktop/systemd1/unit/");
        use std::fmt::Write;
        for byte in unit.bytes() {
            if byte.is_ascii_alphanumeric() {
                object.push(char::from(byte));
            } else {
                write!(object, "_{byte:02x}")?;
            }
        }
        let out = Command::new("/usr/bin/busctl")
            .args([
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                &object,
                "org.freedesktop.systemd1.Unit",
                "Conditions",
            ])
            .output()?;
        ensure!(
            out.status.success() && out.stderr.is_empty(),
            "cannot read PID 1 conditions for {unit}"
        );
        let conditions: Value = serde_json::from_slice(&out.stdout)?;
        ensure!(
            conditions["type"] == "a(sbbsi)"
                && conditions["data"]
                    .as_array()
                    .is_some_and(|rows| rows.iter().any(|row| row[0] == "ConditionPathExists"
                        && row[1] == false
                        && row[2] == false
                        && row[3] == marker)),
            "PID 1 lacks fresh admission condition for {unit}"
        );
    }
    Ok(())
}

pub(super) fn check_owners(review: &Value) -> Result<()> {
    for key in [
        "original_failed_controller_state",
        "terminal_controller_state",
        "terminal_batch",
        "previous_verification",
    ] {
        evidence(&review[key])?;
    }
    for file in review["parent_unit_files"]
        .as_array()
        .context("missing owner definitions")?
    {
        evidence(file)?;
    }
    let mut scan = Command::new("/usr/bin/rg");
    scan.args([
        "--threads",
        "1",
        "--hidden",
        "--no-ignore",
        "--files-with-matches",
        "--fixed-strings",
    ]);
    for key in ["parent_references", "exact_references"] {
        let references: Value = serde_json::from_slice(&evidence(&review[key])?)?;
        for token in references["tokens"]
            .as_array()
            .context("missing owner tokens")?
        {
            scan.args(["-e", token.as_str().context("invalid owner token")?]);
        }
    }
    let out = scan
        .args([
            "/etc/systemd/system",
            "/run/systemd/transient",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
            "/etc/cron.d",
        ])
        .output()?;
    ensure!(
        matches!(out.status.code(), Some(0 | 1)) && out.stderr.is_empty(),
        "installed owner scan failed"
    );
    let definitions = review["definitions"]
        .as_array()
        .context("missing definitions")?;
    for path in std::str::from_utf8(&out.stdout)?.lines() {
        ensure!(
            definitions.iter().any(|p| p == path),
            "unreviewed installed owner {path}"
        );
    }

    // Compare the entire captured property set. A timer may omit process IDs.
    // The reviewed dormant timer retains its edge to the reviewed failed service.
    let managers = review["inactive_units"]
        .as_object()
        .context("missing closed units")?;
    for (unit, expected) in managers {
        let fields = expected.as_object().context("invalid unit properties")?;
        let names = "Id,FragmentPath,DropInPaths,LoadState,UnitFileState,ActiveState,SubState,ControlPID,MainPID,Job,Triggers,TriggeredBy,Conditions,NeedDaemonReload";
        let out = Command::new("/usr/bin/systemctl")
            .args(["show", unit, "-p", names])
            .output()?;
        ensure!(
            out.status.success() && out.stderr.is_empty(),
            "cannot read {unit}"
        );
        let mut actual = serde_json::Map::new();
        for line in std::str::from_utf8(&out.stdout)?.lines() {
            let (k, v) = line.split_once('=').context("malformed manager property")?;
            ensure!(
                actual.insert(k.into(), json!(v)).is_none(),
                "duplicate manager property"
            );
        }
        ensure!(
            &actual == fields,
            "closed unit properties changed for {unit}"
        );
        if let Some(condition) = review["fresh_admission_conditions"].get(unit) {
            check_marker(unit, condition, expected["LoadState"] == "loaded")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target(epoch: u64, path: PathBuf) -> Target {
        serde_json::from_value(
            json!({"epoch":epoch,"path":path,"reason":"test","identity":{
            "dev":1,"ino":2,"nlink":1,"mode":0o100600,"uid":1001,"gid":1003,"len":12345,
            "blocks":24,"mtime":1,"mtime_ns":0,"ctime":1,"ctime_ns":0}}),
        )
        .unwrap()
    }
    #[test]
    fn complete_index_set_requires_exact_epoch_cid_suffix_and_parent() {
        let mut targets: Vec<_> = CIDS
            .iter()
            .flat_map(|&(epoch, cid)| SUFFIXES.map(|s| target(epoch, index_path(epoch, cid, s))))
            .collect();
        assert!(complete_selection(&targets));
        assert!(!complete_selection(&targets[..7]));
        targets[0].epoch = 192;
        assert!(!complete_selection(&targets));
        targets[0].epoch = 191;
        for path in [
            targets[1].path.clone(),
            index_path(191, CIDS[1].1, SUFFIXES[0]),
            index_path(191, CIDS[0].1, "other.index"),
            Path::new("/tmp").join(targets[0].path.file_name().unwrap()),
        ] {
            targets[0].path = path;
            assert!(!complete_selection(&targets));
        }
    }
}
