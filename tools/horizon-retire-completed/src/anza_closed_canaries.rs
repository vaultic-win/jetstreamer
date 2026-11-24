use super::*;

const REVIEW: &str = "/home/sol/.jetstreamer-private/epoch145-v5t-stopped-price-20261124.zjcggc_6/RETIREMENT_CANDIDATES_130_195.json";
const REVIEW_SHA: &str = "6b4563c22f4d586bb8c2fc38c91e4a5c1b8180463b7b27de8de2fa1b115a1291";
const FOLLOWUP_REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/closed-canaries-retirement-134-154-20261124-v1/REVIEW.json";
const FOLLOWUP_REVIEW_SHA: &str =
    "3e4fb8c99b53cbec9ad8e8d2b0d63862c22a21d191229d539d3124f262710474";
const FOLLOWUP_SCHEMA: &str = "horizon-closed-canary-retirement-review-v1";
const INVENTORY: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1/uploader-tools/jetstreamer-r2";
const INVENTORY_SHA: &str = "eb448ede557144f04446dbe00a2d2ec7ad88c934a7a227797d0569a15307a904";
const DIAGNOSTIC: &str = "diagnostic-epoch130-v1417-qualification-v1";
const BENCHMARK: &str = "performance-ab-195-rayon-20261009-v2";
const DIAGNOSTIC_134: &str = "diagnostic-epoch134-v1419-status-probe-v1";
const BENCHMARK_154: &str = "performance-ab-154-v158-rayon-20261009-v3";

pub(super) fn is_target(t: &Target) -> bool {
    let root = Path::new(HOME_ROOT).join(".jetstreamer-private");
    match t.epoch {
        130 => {
            t.path
                == root
                    .join(DIAGNOSTIC)
                    .join("output/epoch-130-v1417-qualification.jet")
        }
        134 => {
            t.path
                == root
                    .join(DIAGNOSTIC_134)
                    .join("output/epoch-134-through-58019044.jet")
        }
        154 => ["control64", "candidate10"].iter().any(|case| {
            t.path
                == root
                    .join(BENCHMARK_154)
                    .join(case)
                    .join("output/epoch-154-through-66958784.jet")
        }),
        195 => ["control32", "candidate8"].iter().any(|case| {
            t.path
                == root
                    .join(BENCHMARK)
                    .join(case)
                    .join("output/epoch-195-through-84247825.jet")
        }),
        _ => false,
    }
}

fn identity(t: &Target) -> Value {
    let s = &t.identity;
    json!({
        "dev": s.dev, "ino": s.ino, "nlink": s.nlink, "mode": s.mode,
        "uid": s.uid, "gid": s.gid, "size": s.len, "blocks": s.blocks,
        "mtime_ns": s.mtime * 1_000_000_000 + s.mtime_ns,
        "ctime_ns": s.ctime * 1_000_000_000 + s.ctime_ns,
    })
}

pub(super) fn verify_scope(p: &Plan, epochs: &BTreeSet<u64>, lock: &File) -> Result<Option<Value>> {
    let (path, sha256, schema, expected_epochs) =
        if epochs.iter().any(|&epoch| matches!(epoch, 130 | 195)) {
            (
                REVIEW,
                REVIEW_SHA,
                "horizon-epoch145-disk-recovery-candidates-v1",
                [130, 195],
            )
        } else if p
            .targets
            .iter()
            .any(|target| matches!(target.epoch, 134 | 154) && is_target(target))
        {
            (
                FOLLOWUP_REVIEW,
                FOLLOWUP_REVIEW_SHA,
                FOLLOWUP_SCHEMA,
                [134, 154],
            )
        } else {
            return Ok(None);
        };
    let m = lock.metadata()?;
    ensure!(
        (m.dev(), m.ino(), m.uid(), m.gid()) == (64512, 101135013, 1001, 1003),
        "different shared mutation lock"
    );
    ensure!(
        epochs.iter().all(|epoch| expected_epochs.contains(epoch))
            && p.inventory_binary.path == Path::new(INVENTORY)
            && p.inventory_binary.sha256 == INVENTORY_SHA,
        "different canary retirement scope or inventory reader"
    );
    let review: Value = serde_json::from_slice(&bound(
        &Bound {
            path: path.into(),
            sha256: sha256.into(),
        },
        LIMIT,
    )?)?;
    ensure!(
        review["schema"] == schema
            && review["actual_reclaimed_bytes"] == 0
            && review["retirement_authorized"] == false,
        "different canary review"
    );
    let targets = review["targets"]
        .as_array()
        .context("missing reviewed targets")?;
    for target in &p.targets {
        let reviewed = targets
            .iter()
            .find(|v| v["epoch"] == target.epoch && v["path"].as_str() == target.path.to_str())
            .context("target was not reviewed")?;
        ensure!(
            reviewed["identity"] == identity(target),
            "different canary inode"
        );
        let terminal: Bound = serde_json::from_value(reviewed["terminal"].clone())?;
        bound(&terminal, LIMIT)?;
    }
    for proof in &p.proofs {
        let reference = &review["delivery_evidence"][proof.epoch.to_string()]["whole_object_receipts"]
            [proof.epoch.to_string()];
        ensure!(
            reference["path"].as_str() == proof.receipt.path.to_str()
                && reference["sha256"] == proof.receipt.sha256,
            "different canonical delivery receipt"
        );
    }
    check_owners(&review)?;
    Ok(Some(review))
}

pub(super) fn check_owners(review: &Value) -> Result<()> {
    let (diagnostic, benchmark) = if review["schema"] == FOLLOWUP_SCHEMA {
        (DIAGNOSTIC_134, BENCHMARK_154)
    } else {
        (DIAGNOSTIC, BENCHMARK)
    };
    let scan = Command::new("/usr/bin/rg")
        .args([
            "--files-with-matches",
            "--fixed-strings",
            "-e",
            diagnostic,
            "-e",
            benchmark,
            "/etc/systemd/system",
            "/run/systemd/transient",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ])
        .output()?;
    ensure!(
        matches!(scan.status.code(), Some(0 | 1)) && scan.stderr.is_empty(),
        "staged owner scan failed"
    );
    let definitions = review["definitions"]
        .as_array()
        .context("missing staged definitions")?;
    for path in String::from_utf8(scan.stdout)?.lines() {
        ensure!(
            definitions.iter().any(|entry| entry == path),
            "unreviewed staged owner {path}"
        );
    }
    let managers = review["inactive_units"]
        .as_object()
        .context("missing reviewed managers")?;
    let units: Vec<_> = managers.keys().cloned().collect();
    inactive(&units)?;
    for unit in units {
        let result = Command::new("/usr/bin/systemctl")
            .args(["show", &unit, "-p", "Id,ControlPID,Triggers,TriggeredBy"])
            .output()?;
        ensure!(
            result.status.success() && result.stderr.is_empty(),
            "cannot inspect {unit}"
        );
        let state = String::from_utf8(result.stdout)?;
        for expected in [
            format!("Id={unit}").as_str(),
            "ControlPID=0",
            "Triggers=",
            "TriggeredBy=",
        ] {
            ensure!(
                state.lines().any(|line| line == expected),
                "scheduled canary owner {unit}"
            );
        }
    }
    Ok(())
}

pub(super) fn verify_delivery(
    review: &Value,
    epochs: &BTreeSet<u64>,
    inventory: &Value,
) -> Result<()> {
    for &epoch in epochs {
        let evidence = &review["delivery_evidence"][epoch.to_string()];
        let mut digests = Vec::new();
        for n in epoch - 1..=epoch + 1 {
            let receipt: Bound =
                serde_json::from_value(evidence["whole_object_receipts"][n.to_string()].clone())?;
            let body: Value = serde_json::from_slice(&bound(&receipt, LIMIT)?)?;
            ready(n, &body, inventory)?;
            digests.push(
                body["archive_sha256"]
                    .as_str()
                    .context("missing delivered digest")?
                    .to_owned(),
            );
        }
        let [left, center, right] = digests.as_slice() else {
            unreachable!("three epoch receipts")
        };
        let gates = evidence["verification_gates"]
            .as_array()
            .context("missing verification receipts")?;
        ensure!(gates.len() == 4, "incomplete canary verification receipts");
        for (gate, expected) in gates.iter().zip([
            vec![center.as_str()],
            vec![center.as_str()],
            vec![left.as_str(), center.as_str()],
            vec![center.as_str(), right.as_str()],
        ]) {
            let bytes = bound(&serde_json::from_value(gate.clone())?, 4096)?;
            let fields: Vec<_> = std::str::from_utf8(&bytes)?.split_whitespace().collect();
            ensure!(
                fields.len() == expected.len() + 2 && fields.starts_with(&expected),
                "verification receipt differs from the authenticated archive digests"
            );
        }
    }
    Ok(())
}
