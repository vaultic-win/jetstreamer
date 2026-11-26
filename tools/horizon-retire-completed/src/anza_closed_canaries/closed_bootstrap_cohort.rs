use super::*;

const ROOT: &str = "/home/sol/.jetstreamer-private/horizon-root-runtime-data/closed-support-migration-20261119-v1/runtime196-200";
const RUNTIME_ALIAS: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/closed-support-migration-20261119-v1/runtime196-200";
const PACKAGE_ALIAS: &str = "/usr/local/lib/jetstreamer/deploy-epochs196-200-target6-20261016-v1";
const SNAPSHOT: &str = "snapshot-84671469-FGt6gSbERBZ5MzrkEyF6V72fQ6xNY4iNbEAyVnk6PLiv.tar.zst";
const SIBLING: &str = "snapshot-85967282-BQvC7FcQTSguJkWHeLnpkVSFv32ZKRqUbgHKxVF97o3x.tar.zst";
const SNAPSHOT_SHA: &str = "3c5445ad5d28a0fd92ccb13d71fc3152d27bd36a803606c759d61d89b30112c6";
const SIBLING_SHA: &str = "d4a74f54f44258fd4b078d8d3304a6cb6a7911a87883160e1579727dafbf9e6d";
const GCS: &str = "/home/sol/.jetstreamer-private/epoch196-198-closed-bootstrap-review-20261126.tBMNtxJ0/GCS_EXACT_METADATA.json";
const TERMINAL: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch199-retained-full-verification-20261126-v1/boundary-198-199/native-bridge-v1/RETIREMENT_COMPLETE.json";
const RESTORE: &str = "horizon-epochs196-198-bootstrap-restore-20261016-v1.service";
const SINGLETON: &str = "jetstreamer-epoch196-singleton-target9-controller-v1-r2.service";
const SUPERSEDED: &str = "jetstreamer-epochs196-200-target6-controller-v1-r2.service";
const DEFINITIONS: [(&str, &str); 4] = [
    (
        "/etc/systemd/system/horizon-epochs196-198-bootstrap-restore-20261016-v1.service",
        "3a05c45f6af311c43321c7bf997c17eef88e2546d5664ed62d963ee36248bac7",
    ),
    (
        "/etc/systemd/system/jetstreamer-epoch196-singleton-target9-controller-v1-r2.service",
        "d9ccb468ec1c5d6746691b2da2a4c604ab6baa384d65ab87885d8eb7d73362f7",
    ),
    (
        "/etc/systemd/system/jetstreamer-epochs196-200-target6-controller-v1-r2.service.superseded-by-epoch196-singleton-20261017-v1",
        "f077144b49496439f5a8227eada896f818727c67a021175f4a524463c06d5252",
    ),
    (
        r"/etc/systemd/system/usr-local-lib-jetstreamer-deploy\x2depochs196\x2d200\x2dtarget6\x2d20261016\x2dv1.mount",
        "091a569dd4bcfd186f57dd35bd0d5904411c63c6d283ce0f55779f8e145d2d78",
    ),
];
const STAGED: [(&str, &str); 2] = [
    (
        "/var/lib/jetstreamer/horizon_runtime_data/closed-support-migration-20261119-v1/runtime196-200/preflight-196-200-v4.json",
        "6049e1118d61cd7e959c10ca67d846a70307383b8a30b52fee7c851f9c85a074",
    ),
    (
        "/home/sol/.jetstreamer-private/public-method-20261120/199-large-archive-rotation-20261121-v1/price.py",
        "4df9304d241dc6682f2c7a7fede73854a7d28cd42ea27862611794f22dc4ee24",
    ),
];
const RECEIPTS: [(u64, &str); 4] = [
    (
        195,
        "bf55b42dbbc1fd9e25146a2e68d6021eceb4365746f9f7ecdf5234b0a1e9a87b",
    ),
    (
        196,
        "eeefcf1fd63b4ecf4b7b2f93e38051d0817799f21160bcbb160ca4f4724b9a37",
    ),
    (
        197,
        "dff9cb4598bc7ccd0a10224e6e86fc25722e334a9dd1ee55467fc3d1d6f8f0ba",
    ),
    (
        198,
        "81470e448a855612c57c2727e11f08dbb9b52a19bbe6168cea440fe1b17ae1f3",
    ),
];
const BOUNDARIES: [(&str, &str); 4] = [
    (
        "/home/sol/.jetstreamer-private/horizon-boundary-audit-101-200-v1/receipts/boundary-195-196.ok",
        "b974734559bc6bd48a9d6f898819eafc5bb1c935210ea2d4631bd2df8d6b2ac2",
    ),
    (
        "/home/sol/.jetstreamer-private/horizon-boundary-audit-101-200-v1/receipts/boundary-196-197.ok",
        "7b76399f6427d7a0ab1e05f0d18405f8f4b64acc1e928f0707a3857ec4da2552",
    ),
    (
        "/home/sol/.jetstreamer-private/horizon-boundary-audit-101-200-v1/receipts/boundary-197-198.ok",
        "52546564da5960dc2d11179c57ce4f30a16241bbf105f1c2044ec56ccf42867e",
    ),
    (
        "/home/sol/.jetstreamer-private/epoch198-boundary-retirement-20261126.ALQM3wEf/boundaries/boundary-198-199.ok",
        "5eb571572364dec08efbcec246611b53b3e05b7b3593c59eb16fe39082d45f97",
    ),
];

fn pin(path: impl Into<PathBuf>, sha256: &str) -> Result<Vec<u8>> {
    bound(
        &Bound {
            path: path.into(),
            sha256: sha256.into(),
        },
        LIMIT,
    )
}

pub(crate) fn is_target(target: &Target) -> bool {
    target.epoch == 198 && target.path == Path::new(ROOT).join(SNAPSHOT)
}

pub(crate) fn alias_in_command(target: &Target, data: &[u8]) -> bool {
    is_target(target)
        && [RUNTIME_ALIAS, PACKAGE_ALIAS]
            .into_iter()
            .any(|root| contains(data, Path::new(root).join(SNAPSHOT).as_os_str().as_bytes()))
}

pub(crate) fn lock_controllers() -> Result<[File; 2]> {
    Ok([
        controller_lock(
            "/var/lib/jetstreamer-root-sweep-epochs196-200-v4-20261009-v1/controller.lock",
            3802983,
        )?,
        controller_lock(
            "/var/lib/jetstreamer-root-sweep-epoch196-singleton-20261017-v1/controller.lock",
            2758586,
        )?,
    ])
}

fn systemd_clear(unit: &str, expected_load: &str) -> Result<()> {
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "-p",
            "Id,LoadState,ActiveState,MainPID,ControlPID,Job,Triggers,TriggeredBy,UnitFileState",
        ])
        .output()?;
    ensure!(
        matches!(out.status.code(), Some(0 | 4)) && out.stderr.is_empty(),
        "cannot inspect {unit}"
    );
    let text = String::from_utf8(out.stdout)?;
    for field in [
        format!("Id={unit}"),
        format!("LoadState={expected_load}"),
        "ActiveState=inactive".into(),
        "MainPID=0".into(),
        "ControlPID=0".into(),
        "Job=".into(),
        "Triggers=".into(),
        "TriggeredBy=".into(),
        format!(
            "UnitFileState={}",
            if expected_load == "loaded" {
                "static"
            } else {
                ""
            }
        ),
    ] {
        ensure!(
            text.lines().any(|line| line == field),
            "changed owner {unit}: expected {field}"
        );
    }
    Ok(())
}

fn scan_references(roots: &[&str], globs: &[&str], reviewed: &[(&str, &str)]) -> Result<()> {
    let output = Command::new("/usr/bin/rg")
        .args([
            "--no-ignore",
            "--files-with-matches",
            "--fixed-strings",
            "--max-filesize",
            "12M",
        ])
        .args(
            [ROOT, RUNTIME_ALIAS, PACKAGE_ALIAS, SNAPSHOT]
                .into_iter()
                .flat_map(|pattern| ["-e", pattern]),
        )
        .args(globs.iter().flat_map(|pattern| ["-g", *pattern]))
        .args(roots)
        .output()?;
    ensure!(
        matches!(output.status.code(), Some(0 | 1)) && output.stderr.is_empty(),
        "staged consumer scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for path in String::from_utf8(output.stdout)?.lines() {
        ensure!(
            reviewed.iter().any(|(known, _)| *known == path),
            "unreviewed staged reference {path}"
        );
    }
    for (path, sha) in reviewed {
        pin(*path, sha)?;
    }
    Ok(())
}

pub(crate) fn check_owners() -> Result<()> {
    scan_references(
        &[
            "/etc/systemd/system",
            "/run/systemd/transient",
            "/run/systemd/generator",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ],
        &[],
        &DEFINITIONS,
    )?;
    scan_references(
        &[
            "/var/lib/jetstreamer/horizon_runtime_data",
            "/home/sol/workspace/jetstreamer/scripts",
            "/home/sol/.jetstreamer-private/public-method-20261120",
        ],
        &[
            "*.py",
            "*.sh",
            "*.service",
            "*PLAN*.json",
            "*plan*.json",
            "*manifest*.json",
            "*preflight*.json",
            "!**/fixtures/**",
        ],
        &STAGED,
    )?;
    systemd_clear(RESTORE, "loaded")?;
    systemd_clear(SINGLETON, "loaded")?;
    systemd_clear(SUPERSEDED, "not-found")?;
    ensure!(
        fs::symlink_metadata(
            "/var/lib/jetstreamer-root-sweep-epochs196-200-target6-20261016-v1/controller.lock"
        )
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "superseded cohort acquired a lock"
    );
    Ok(())
}

fn absent(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

pub(crate) fn check_aliases(target: &Target, removed: bool) -> Result<()> {
    for root in [ROOT, RUNTIME_ALIAS, PACKAGE_ALIAS] {
        let root = Path::new(root);
        let dir = fs::symlink_metadata(root)?;
        ensure!(
            dir.is_dir() && (dir.dev(), dir.ino()) == (64512, 100539622),
            "different package alias"
        );
        let sibling = stamp(&exact(&root.join(SIBLING))?);
        ensure!(
            sibling
                == Stamp {
                    dev: 64512,
                    ino: 100539629,
                    len: 7997778185,
                    blocks: 15620688,
                    uid: 0,
                    gid: 0,
                    mode: 0o100444,
                    nlink: 1,
                    mtime: 1792145399,
                    mtime_ns: 435622247,
                    ctime: 1795118034,
                    ctime_ns: 732139236,
                },
            "199–200 sibling changed"
        );
        let path = root.join(SNAPSHOT);
        if removed {
            ensure!(
                absent(&path),
                "removed snapshot is still present via package alias"
            );
        } else {
            ensure!(
                stamp(&exact(&path)?) == target.identity,
                "different snapshot package alias"
            );
        }
    }
    Ok(())
}

pub(crate) fn verify_scope(p: &Plan, lock: &File) -> Result<()> {
    ensure!(
        p.targets.len() == 1 && is_target(&p.targets[0]),
        "unexpected cohort retirement target set"
    );
    let target = &p.targets[0];
    ensure!(
        (
            target.identity.dev,
            target.identity.ino,
            target.identity.len,
            target.identity.blocks,
            target.identity.mode,
            target.identity.uid,
            target.identity.gid
        ) == (64512, 100539628, 7878572620, 15387864, 0o100444, 0, 0),
        "different closed-cohort snapshot"
    );
    let m = lock.metadata()?;
    ensure!(
        (m.dev(), m.ino(), m.uid(), m.gid()) == (64512, 101135013, 1001, 1003),
        "different shared mutation lock"
    );
    ensure!(
        p.inventory_binary.path == Path::new(INVENTORY)
            && p.inventory_binary.sha256 == INVENTORY_SHA,
        "different qualified inventory executable"
    );
    check_aliases(target, false)?;
    let seal: Value = serde_json::from_slice(&pin(
        Path::new(ROOT).join("deployment-seal-receipt.json"),
        "677f8dc8f26df10dd08eda3bff2d4597ba393d904cc19ef970f414a860cfccd7",
    )?)?;
    ensure!(
        seal["destination"] == PACKAGE_ALIAS,
        "different original deployment alias"
    );
    for (name, sha, len) in [
        (SNAPSHOT, SNAPSHOT_SHA, 7878572620u64),
        (SIBLING, SIBLING_SHA, 7997778185u64),
    ] {
        ensure!(
            seal["members"]
                .as_array()
                .context("missing deployment members")?
                .iter()
                .filter(|member| member["name"] == name
                    && member["sha256"] == sha
                    && member["bytes"] == len)
                .count()
                == 1,
            "different deployment member {name}"
        );
    }
    let gcs: Value = serde_json::from_slice(&pin(
        GCS,
        "d9a38e2ca92ba6137c210bec6a5a865bd0efc5f9a9b9a063c4d5f1e336cba200",
    )?)?;
    ensure!(
        gcs["bucket"] == "mainnet-beta-ledger-us-ny5"
            && gcs["name"] == format!("84671469/{SNAPSHOT}")
            && gcs["generation"] == "1634789201368970"
            && gcs["size"] == target.identity.len
            && gcs["crc32c_hash"] == "x7DlkA=="
            && gcs["md5_hash"] == "zKpFU1WlvvGEpHGPkRcl1Q==",
        "different authenticated GCS generation"
    );
    pin(
        "/home/sol/.jetstreamer-private/epochs196-200-bootstrap-revalidation-20261016-v1/receipts/snapshot-84671469-restore-receipt-v1.json",
        "fc1e22ced3e153dd9309848747f6abc094cbe2e12bd9139bd1fe17b6d57234a5",
    )?;
    let terminal: Value = serde_json::from_slice(&pin(
        TERMINAL,
        "190bd3e2b1492216eea626ccbaa462411466c8c76e011bbc40f8d319981bc33d",
    )?)?;
    ensure!(
        terminal["native"]["InvocationID"] == "73abdff9f186415987c49068be57597a"
            && terminal["no_consumer_check_under_shared_lock"] == true
            && terminal["r2_pair_revalidated"] == true
            && absent(Path::new("/home/sol/horizon/epoch-198.jet"))
            && absent(Path::new("/home/sol/horizon/epoch-198.jet.sha256")),
        "epoch 198 retirement is not closed"
    );
    for (path, sha) in BOUNDARIES {
        pin(path, sha)?;
    }
    ensure!(
        digest(&target.path)? == SNAPSHOT_SHA,
        "snapshot content changed"
    );
    check_aliases(target, false)?;
    check_owners()
}

pub(crate) fn verify_delivery(receipts: &Path, inventory: &Value) -> Result<()> {
    for (epoch, sha) in RECEIPTS {
        let report = pin(receipts.join(format!("epoch-{epoch}.r2.json")), sha)?;
        ready(epoch, &serde_json::from_slice(&report)?, inventory)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_home_backed_196_through_198_bootstrap_can_be_selected() {
        let mut target = Target {
            epoch: 198,
            path: Path::new(ROOT).join(SNAPSHOT),
            identity: Stamp {
                dev: 64512,
                ino: 100539628,
                len: 7878572620,
                blocks: 15387864,
                uid: 0,
                gid: 0,
                mode: 0o100444,
                nlink: 1,
                mtime: 1792145378,
                mtime_ns: 673513537,
                ctime: 1795118017,
                ctime_ns: 310057237,
            },
            reason: "test".into(),
            external_bootstrap_review: None,
        };
        assert!(is_target(&target));
        for alias in [RUNTIME_ALIAS, PACKAGE_ALIAS] {
            assert!(alias_in_command(
                &target,
                Path::new(alias).join(SNAPSHOT).as_os_str().as_bytes()
            ));
            assert!(!alias_in_command(
                &target,
                Path::new(alias).join(SIBLING).as_os_str().as_bytes()
            ));
        }
        target.path = Path::new(ROOT).join(SIBLING);
        assert!(!is_target(&target));
        target.path = Path::new(PACKAGE_ALIAS).join(SNAPSHOT);
        assert!(!is_target(&target));
        target.path = Path::new("/usr/local/lib/jetstreamer/deploy-epoch196-singleton-20261017-v1")
            .join(SNAPSHOT);
        assert!(!is_target(&target));
    }
}
