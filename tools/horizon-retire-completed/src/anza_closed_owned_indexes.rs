use super::*;

const REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch160174-closed-index-retirement-20261127-v1/REVIEW.json";
const REVIEW_SHA: &str = "c174cebe671255a195fab239a27c46efb2a0f9132357526f9a96a4cb95a53316";
const CASES_160174: [(u64, &str, &str); 2] = [
    (
        160,
        "epoch160-singleton-20261020-v1",
        "bafyreiflpamczh2izmbs4dhrp2q63z5zx6xkhd5pf2fffuz673o7pdhvfi",
    ),
    (
        174,
        "epoch174-20260922-v3",
        "bafyreicuprjedc2j2idcu5vxnxegrg4hno4sm65dud5stzifhsq352cizy",
    ),
];
const OWNER_LOCKS_160174: [(&str, u64); 5] = [
    (
        "/var/lib/jetstreamer-root-sweep-epoch160-singleton-20261020-v1/controller.lock",
        2759277,
    ),
    (
        "/var/lib/jetstreamer-root-sweep-epoch174-20260921-v27/controller.lock",
        3276848,
    ),
    (
        "/var/lib/jetstreamer-root-sweep-epoch174-20260922-v29/controller.lock",
        3276854,
    ),
    (
        "/var/lib/jetstreamer-root-sweep-epoch174-20260922-v30/controller.lock",
        3276857,
    ),
    (
        "/var/lib/jetstreamer-root-sweep-epoch174-20260922-v70/controller.lock",
        3276935,
    ),
];

const CASES_183184: [(u64, &str, &str); 2] = [
    (
        183,
        "epochs183-184-readerfix-20261020-v1",
        "bafyreihyhobwl4ffqvcwvellcltbnghpcc4diu2i7pzj7542f23bdluu3m",
    ),
    (
        184,
        "epochs183-184-readerfix-20261020-v1",
        "bafyreieuj7hyqsnq434loj52pwsdrdx2wlfiimt7ua7gnldw57rcqzsopu",
    ),
];
const OWNER_LOCKS_183184: [(&str, u64); 2] = [
    (
        "/var/lib/jetstreamer-root-sweep-epochs183-184-readerfix-full-20261023-v2/controller.lock",
        5671868,
    ),
    (
        "/var/lib/jetstreamer-root-sweep-epochs183-186-target4-20261016-v3/controller.lock",
        2758518,
    ),
];

pub(super) struct Profile {
    review: &'static str,
    review_sha: &'static str,
    schema: &'static str,
    cases: &'static [(u64, &'static str, &'static str)],
    owner_locks: &'static [(&'static str, u64)],
    completed_remain_after_exit: bool,
}

const PROFILE_160174: Profile = Profile {
    review: REVIEW,
    review_sha: REVIEW_SHA,
    schema: "horizon-160174-closed-compact-index-review-v1",
    cases: &CASES_160174,
    owner_locks: &OWNER_LOCKS_160174,
    completed_remain_after_exit: false,
};
const PROFILE_183184: Profile = Profile {
    review: "/var/lib/jetstreamer/horizon_runtime_data/epoch183184-closed-index-retirement-20261127-v1/REVIEW.json",
    review_sha: "d01673c4ff8a03ad0f737566805c2773be679e2a842e00c7e4a84379c03dd5c1",
    schema: "horizon-183184-closed-compact-index-review-v1",
    cases: &CASES_183184,
    owner_locks: &OWNER_LOCKS_183184,
    completed_remain_after_exit: true,
};

pub(super) fn profile(epochs: &BTreeSet<u64>) -> Option<&'static Profile> {
    if epochs.iter().copied().eq([160, 174]) {
        Some(&PROFILE_160174)
    } else if epochs.iter().copied().eq([183, 184]) {
        Some(&PROFILE_183184)
    } else {
        None
    }
}

pub(super) fn is_target(t: &Target) -> bool {
    is_case_target(t, &PROFILE_160174) || is_case_target(t, &PROFILE_183184)
}

fn is_case_target(t: &Target, profile: &Profile) -> bool {
    profile
        .cases
        .iter()
        .filter(|(epoch, _, _)| *epoch == t.epoch)
        .any(|(epoch, lane, cid)| {
            ["cid-to-offset-and-size", "slot-to-cid"]
                .iter()
                .any(|suffix| {
                    t.path
                        == Path::new(HOME_ROOT)
                            .join(".jetstreamer-private")
                            .join(lane)
                            .join("lane-a/output/compact-indexes")
                            .join(epoch.to_string())
                            .join(format!("epoch-{epoch}-{cid}-mainnet-{suffix}.index"))
                })
        })
}

pub(super) fn lock_controllers(profile: &Profile) -> Result<Vec<File>> {
    profile
        .owner_locks
        .iter()
        .map(|&(path, inode)| anza_closed_canaries::controller_lock(path, inode))
        .collect()
}

fn evidence(item: &Value) -> Result<Vec<u8>> {
    bound(&serde_json::from_value(item.clone())?, LIMIT)
}

pub(super) fn verify(profile: &Profile, p: &Plan) -> Result<Value> {
    let reference = Bound {
        path: profile.review.into(),
        sha256: profile.review_sha.into(),
    };
    let review: Value = serde_json::from_slice(&bound(&reference, LIMIT)?)?;
    ensure!(
        review["schema"] == profile.schema
            && review["archive_inputs_preserved"] == true
            && review["complete_roster_protected"] == true
            && review["authorized"] == true
            && p.targets.len() == profile.cases.len() * 2
            && p.targets.iter().all(|t| is_case_target(t, profile)),
        "wrong or incomplete closed compact-index review"
    );
    let reviewed = review["targets"]
        .as_array()
        .context("missing reviewed indexes")?;
    ensure!(
        reviewed.len() == p.targets.len()
            && p.targets.iter().all(|target| {
                reviewed.iter().any(|row| {
                    row["epoch"] == target.epoch
                        && row["path"] == json!(target.path)
                        && row["identity"] == json!(target.identity)
                        && row["reason"] == target.reason
                })
            }),
        "index files differ from the reviewed paths or identities"
    );

    for proof in &p.proofs {
        let key = proof.epoch.to_string();
        let expected = &review["delivery"][&key];
        ensure!(
            expected["whole_readback"]
                == json!({"path":proof.receipt.path,"sha256":proof.receipt.sha256}),
            "foreign delivery receipt for closed epoch {}",
            proof.epoch
        );
        let receipt: Value = serde_json::from_slice(&evidence(&expected["whole_readback"])?)?;
        let sha = receipt["archive_sha256"]
            .as_str()
            .context("missing whole-object digest")?;
        let state: Value = serde_json::from_slice(&evidence(&expected["terminal_controller"])?)?;
        let scope = expected["terminal_cohort"].as_str().unwrap_or(&key);
        let members = state["completed"][scope]["members"]
            .as_array()
            .context("missing terminal controller members")?;
        ensure!(
            members
                .iter()
                .filter(|member| member["epoch"] == proof.epoch)
                .map(|member| member["archive_sha256"].as_str())
                .eq([Some(sha)]),
            "controller terminal does not bind the published epoch"
        );
        for gate in ["full_scan", "plugin_scan"] {
            let proof = evidence(&expected[gate])?;
            ensure!(
                std::str::from_utf8(&proof)?.split_whitespace().next() == Some(sha),
                "verification gate does not match the published epoch"
            );
        }
    }
    check_owners(profile, &review)?;
    Ok(review)
}

pub(super) fn check_owners(profile: &Profile, review: &Value) -> Result<()> {
    let definitions = review["staged_definitions"]
        .as_object()
        .context("missing closed index definition census")?;
    let mut command = Command::new("/usr/bin/rg");
    command.args([
        "--threads",
        "1",
        "--hidden",
        "--no-ignore",
        "--files-with-matches",
        "--fixed-strings",
    ]);
    for &(_, lane, cid) in profile.cases {
        command.args(["-e", lane, "-e", cid]);
    }
    let output = command
        .args([
            "/etc/systemd/system",
            "/run/systemd/transient",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
            "/etc/cron.d",
        ])
        .output()?;
    ensure!(
        matches!(output.status.code(), Some(0 | 1)) && output.stderr.is_empty(),
        "installed index consumer scan could not be completed"
    );
    let observed: BTreeSet<_> = std::str::from_utf8(&output.stdout)?.lines().collect();
    let expected: BTreeSet<_> = definitions.keys().map(String::as_str).collect();
    ensure!(
        observed == expected,
        "installed consumer references changed since the index review"
    );
    for (path, item) in definitions {
        ensure!(item["path"] == *path, "crossed installed definition");
        evidence(item)?;
    }

    for (unit, pinned) in review["manager_properties"]
        .as_object()
        .context("missing index consumer manager properties")?
    {
        let standard = "Id,FragmentPath,DropInPaths,LoadState,UnitFileState,ActiveState,SubState,ControlPID,MainPID,Job,Triggers,TriggeredBy,Conditions,NeedDaemonReload";
        let fields = if profile.completed_remain_after_exit {
            format!("{standard},Type,Restart,RemainAfterExit,Result,ExecMainStatus")
        } else {
            standard.into()
        };
        let output = Command::new("/usr/bin/systemctl")
            .args(["show", unit, "-p", &fields])
            .output()?;
        ensure!(
            output.status.success() && output.stderr.is_empty(),
            "index consumer status failed for {unit}"
        );
        let actual: serde_json::Map<String, Value> = std::str::from_utf8(&output.stdout)?
            .lines()
            .map(|line| {
                let (key, value) = line.split_once('=').context("invalid manager property")?;
                Ok((key.into(), json!(value)))
            })
            .collect::<Result<_>>()?;
        let exited = profile.completed_remain_after_exit
            && pinned["ActiveState"] == "active"
            && pinned["SubState"] == "exited"
            && matches!(pinned["Type"].as_str(), Some("oneshot" | "exec"))
            && pinned["Restart"] == "no"
            && pinned["RemainAfterExit"] == "yes"
            && pinned["Result"] == "success"
            && pinned["ExecMainStatus"] == "0"
            && pinned["Triggers"] == ""
            && pinned["TriggeredBy"] == ""
            && pinned["MainPID"] == "0"
            && pinned["ControlPID"] == "0";
        ensure!(
            &Value::Object(actual) == pinned
                && (matches!(pinned["ActiveState"].as_str(), Some("inactive" | "failed"))
                    || exited)
                && pinned["Job"] == ""
                && pinned["NeedDaemonReload"] == "no"
                && !Path::new("/sys/fs/cgroup/system.slice").join(unit).exists(),
            "closed index consumer {unit} changed"
        );
    }
    Ok(())
}
