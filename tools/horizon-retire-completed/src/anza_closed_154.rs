use super::*;

const CANARY: &str =
    "/home/sol/.jetstreamer-private/epoch154-rayon10-growth-measurement-20261019-v1";
const TARGET: &str = "/home/sol/.jetstreamer-private/epoch154-rayon10-growth-measurement-20261019-v1/output/epoch-154-through-66958784.jet";
const OLD_UNITS: [&str; 2] = [
    "horizon-qualify-epoch154-rayon10-growth-20261019-v1.service",
    "jetstreamer-holding-scratch185-execute-0946-20261024-v2.service",
];
const INVENTORY: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1/uploader-tools/jetstreamer-r2";
const INVENTORY_SHA: &str = "eb448ede557144f04446dbe00a2d2ec7ad88c934a7a227797d0569a15307a904";
const DELIVERY_SHA: [&str; 3] = [
    "5d903b3f55de9fd31ce5de268ec232b3f82a6164ead125f923c74b66e55ce332",
    "7cde79b3e827c09951e7d48fa30ba7e074f44ab42d325030c675c4e2f10a3ad0",
    "9c5f7cff849e4300cb282feb2f688a6e6ccd6b7a28911c32fbe729d39a1eec8d",
];
const GATES: [(&str, &str); 4] = [
    (
        "final-audits/epochs-101-200-parallel-v1/receipts/epoch-154.full.ok",
        "b5700d2278aef6a28fda73e78dc255652a26e2af65edcec7b8adc8a65ff6b5bf",
    ),
    (
        "horizon-plugin-current-101-200-v2/receipts/epoch-154.plugin.ok",
        "0e3b270a5ef9f74ec5d893bdc8d8f3b1674f3adcfd11cbf9511db79257d634ce",
    ),
    (
        "horizon-boundary-audit-101-200-v1/receipts/boundary-153-154.ok",
        "e5b328b33db5001c3596c33a39cdedd1b0f8ac08b42efff90016f64a940911b8",
    ),
    (
        "horizon-boundary-audit-101-200-v1/receipts/boundary-154-155.ok",
        "d81ff94f656dc871d8e8f50051496c184d5a7f0811b034571e8a38ed47ca4670",
    ),
];

pub(super) fn is_target(t: &Target) -> bool {
    let s = &t.identity;
    t.epoch == 154
        && t.path == Path::new(TARGET)
        && (s.dev, s.ino, s.len, s.blocks) == (64512, 98369591, 23039249688, 44998600)
        && (s.mode, s.uid, s.gid, s.nlink) == (0o100600, 1001, 1003, 1)
        && (s.mtime, s.mtime_ns, s.ctime, s.ctime_ns)
            == (1792523498, 224188714, 1792523498, 224188714)
}

pub(super) fn check_owners() -> Result<()> {
    for unit in OLD_UNITS {
        let state = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                unit,
                "-p",
                "Id,ActiveState,MainPID,ControlPID,Job,Triggers,TriggeredBy",
            ])
            .output()?;
        ensure!(
            state.status.success() && state.stderr.is_empty(),
            "cannot inspect {unit}"
        );
        let state = String::from_utf8(state.stdout)?;
        for expected in [
            format!("Id={unit}").as_str(),
            "MainPID=0",
            "ControlPID=0",
            "Job=",
            "Triggers=",
            "TriggeredBy=",
        ] {
            ensure!(
                state.lines().any(|line| line == expected),
                "live or scheduled owner {unit}"
            );
        }
        ensure!(
            state
                .lines()
                .any(|line| matches!(line, "ActiveState=inactive" | "ActiveState=failed")),
            "live original owner {unit}"
        );
    }

    let scan = Command::new("/usr/bin/rg")
        .args([
            "--files-with-matches",
            "--fixed-strings",
            "epoch154-rayon10-growth-measurement-20261019-v1",
            "/etc/systemd/system",
            "/run/systemd/transient",
            "/usr/lib/systemd/system",
        ])
        .output()?;
    ensure!(
        matches!(scan.status.code(), Some(0 | 1)) && scan.stderr.is_empty(),
        "staged owner scan failed"
    );
    for path in String::from_utf8(scan.stdout)?.lines() {
        ensure!(
            Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| OLD_UNITS.contains(&name)),
            "unreviewed staged owner {path}"
        );
    }
    Ok(())
}

pub(super) fn verify_scope(plan: &Plan, mutation_lock: &File) -> Result<()> {
    let lock = mutation_lock.metadata()?;
    ensure!(
        (lock.dev(), lock.ino(), lock.uid(), lock.gid(), lock.mode())
            == (64512, 101135013, 1001, 1003, 0o100600),
        "different shared mutation lock"
    );
    ensure!(
        plan.targets.len() == 1 && plan.proofs.len() == 1,
        "select only the closed epoch 154 canary"
    );
    ensure!(
        plan.inventory_binary.path == Path::new(INVENTORY)
            && plan.inventory_binary.sha256 == INVENTORY_SHA,
        "different qualified inventory reader"
    );
    let canary: Value = serde_json::from_slice(&bound(
        &Bound {
            path: Path::new(CANARY).join("canary-receipt.json"),
            sha256: "daad66cc83959a1322882ecd4db78f74d0633e37df2d64c25c74da78b50ed730".into(),
        },
        LIMIT,
    )?)?;
    ensure!(
        canary["schema"] == "jetstreamer-historical-performance-canary-v2"
            && canary["systemd_invocation_id"] == "85214d064b014c2e981bbfa8709f34db"
            && canary["target_reached"] == true
            && canary["runner_return_code"] == 0
            && canary["command"]
                .as_array()
                .is_some_and(|args| args.contains(&json!(format!("--horizon-output={TARGET}")))),
        "different canary completion evidence"
    );
    check_owners()
}

fn receipt_fields(bytes: &[u8], digests: &[&str]) -> Result<()> {
    let fields: Vec<_> = std::str::from_utf8(bytes)?.split_whitespace().collect();
    ensure!(
        fields.len() == digests.len() + 2 && fields.starts_with(digests),
        "verification receipt differs from the authenticated archive digests"
    );
    Ok(())
}

pub(super) fn verify_delivery(receipts: &Path, inventory: &Value) -> Result<()> {
    let mut digests = Vec::new();
    for (epoch, sha256) in (153..=155).zip(DELIVERY_SHA) {
        let path = receipts.join(format!("epoch-{epoch}.r2.json"));
        let receipt: Value = serde_json::from_slice(&bound(
            &Bound {
                path,
                sha256: sha256.into(),
            },
            LIMIT,
        )?)?;
        ready(epoch, &receipt, inventory)?;
        digests.push(
            receipt["archive_sha256"]
                .as_str()
                .context("missing delivery digest")?
                .to_owned(),
        );
    }
    let [left, center, right] = digests.as_slice() else {
        unreachable!("verified the three adjacent epochs");
    };
    let private = Path::new(HOME_ROOT).join(".jetstreamer-private");
    for ((path, sha256), expected) in GATES.into_iter().zip([
        vec![center.as_str()],
        vec![center.as_str()],
        vec![left.as_str(), center.as_str()],
        vec![center.as_str(), right.as_str()],
    ]) {
        let bytes = bound(
            &Bound {
                path: private.join(path),
                sha256: sha256.into(),
            },
            4096,
        )?;
        receipt_fields(&bytes, &expected)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_requires_both_digests_in_order() {
        receipt_fields(b"left right binary script\n", &["left", "right"]).unwrap();
        assert!(receipt_fields(b"right left binary script\n", &["left", "right"]).is_err());
        assert!(receipt_fields(b"left right binary\n", &["left", "right"]).is_err());
    }
}
