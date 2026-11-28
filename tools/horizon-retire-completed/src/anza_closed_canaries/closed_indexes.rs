use super::*;

pub(crate) const REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/closed191194-index-retirement-20261125-v1/REVIEW.json";
pub(crate) const SHA: &str = "87f2d2f6bad703779f827d356ae26118026888f90f830f45cb435590cf0a22a6";
pub(crate) const SCHEMA: &str = "horizon-191-194-completed-car-index-review-v1";
pub(crate) const SINGLETON_REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/closed196197-index-retirement-20261125-v1/REVIEW.json";
pub(crate) const SINGLETON_SHA: &str =
    "6bf48f94de15194596c9b96cb84b9dd445ade610461d9decca180f3fe3aafdd8";
pub(crate) const SINGLETON_SCHEMA: &str = "horizon-completed-singleton-196-197-car-index-review-v1";
pub(crate) const EARLY_SINGLETON_REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/closed130134-index-retirement-20261125-v1/REVIEW.json";
pub(crate) const EARLY_SINGLETON_SHA: &str =
    "e2f0469eee9498186094183b367c17b3e5c04571e6220191745eb19fe81f1a91";
pub(crate) const EARLY_SINGLETON_SCHEMA: &str =
    "horizon-completed-singleton-130-134-car-index-review-v1";
pub(crate) const EPOCH149_REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch149-closed-index-retirement-20261126-v1/REVIEW.json";
pub(crate) const EPOCH149_SHA: &str =
    "72077441003ba8edacdaff0f081911c25af1e0102373b43bdb2d62ba5c89007b";
pub(crate) const EPOCH149_SCHEMA: &str = "horizon-completed-lane-b-149-car-index-review-v1";
const EPOCH149_CACHE: &str =
    "/home/sol/.jetstreamer-private/epochs148-149-20260923-v1/lane-b/output/compact-indexes";
const EPOCH149_CID: &str = "bafyreih5mftinnahth3zenvhn725doa7mkdhiiq6igclxx4d6voyxj3mae";
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

fn index_path(cache: &Path, epoch: u64, cid: &str, suffix: &str) -> PathBuf {
    cache
        .join(epoch.to_string())
        .join(format!("epoch-{epoch}-{cid}-mainnet-{suffix}"))
}

pub(crate) fn is_index(t: &Target) -> bool {
    CIDS.iter().any(|&(epoch, cid)| {
        t.epoch == epoch
            && SUFFIXES
                .iter()
                .any(|suffix| index_path(Path::new(CACHE), epoch, cid, suffix) == t.path)
    })
}

pub(crate) fn is_epoch149_index(t: &Target) -> bool {
    t.epoch == 149
        && SUFFIXES.iter().any(|suffix| {
            t.path == index_path(Path::new(EPOCH149_CACHE), 149, EPOCH149_CID, suffix)
        })
}

fn singleton_cache(owner: u64) -> PathBuf {
    Path::new(HOME_ROOT)
        .join(".jetstreamer-private")
        .join(format!(
            "epoch{owner}-singleton-20261017-v1/lane-a/output/compact-indexes"
        ))
}

pub(crate) fn is_singleton_index(t: &Target) -> bool {
    let cid = match t.epoch {
        195 => "bafyreigawutckkq5wvdzd4o57mns2242r3h7naw7poyweshqem2dbvbhvi",
        196 => "bafyreidltgi5iolhvjxilp6yhu4sptwgwpwwgwkp5rehbrcbnuhzbxau5a",
        197 => "bafyreibzqylewmres6mm4i43dhjmbpilmcy6yz66wsqry7cjlr3ghnp7ty",
        _ => return false,
    };
    [196, 197].iter().any(|&owner| {
        let cache = singleton_cache(owner);
        // Each singleton downloaded both indexes for its own epoch and
        // only the slot index for the final slot of the preceding epoch.
        (t.epoch == owner
            && SUFFIXES
                .iter()
                .any(|suffix| index_path(&cache, owner, cid, suffix) == t.path))
            || (t.epoch + 1 == owner
                && index_path(&cache, t.epoch, cid, "slot-to-cid.index") == t.path)
    })
}

pub(crate) fn is_early_singleton_index(t: &Target) -> bool {
    let (lane, cid, own_epoch) = match t.epoch {
        129 => (
            "epoch130-v1417-production-20260930-v1",
            "bafyreig4chl35gz4li7pe5vzcpawcdkdlpxixzwci2mld6mkbe7e4x4l7u",
            false,
        ),
        130 => (
            "epoch130-v1417-production-20260930-v1",
            "bafyreiaebavqepkoxmlra3waxrww5shrrwqcfysdylwbjro5vry3muzioy",
            true,
        ),
        133 => (
            "epoch134-v1419-production-cd656ef-v1",
            "bafyreiaesmtvsk765okuilqhnpnxsgbjjjxs5imu4fdxcmamwrs6xhldkq",
            false,
        ),
        134 => (
            "epoch134-v1419-production-cd656ef-v1",
            "bafyreifx2sk2xvwnylotymgckkf4vwwcxd4mpu4pnwph3fdb7whhv2h4ge",
            true,
        ),
        _ => return false,
    };
    let cache = Path::new(HOME_ROOT)
        .join(".jetstreamer-private")
        .join(lane)
        .join("lane-a/output/compact-indexes");
    (own_epoch && index_path(&cache, t.epoch, cid, SUFFIXES[0]) == t.path)
        || index_path(&cache, t.epoch, cid, SUFFIXES[1]) == t.path
}

pub(super) fn complete_selection(
    targets: &[Target],
    count: usize,
    matches: fn(&Target) -> bool,
) -> bool {
    targets.len() == count
        && targets.iter().all(matches)
        && targets
            .iter()
            .map(|t| &t.path)
            .collect::<BTreeSet<_>>()
            .len()
            == count
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

pub(crate) fn lock_singleton_controllers() -> Result<[File; 2]> {
    Ok([
        controller_lock(
            "/var/lib/jetstreamer-root-sweep-epoch196-singleton-20261017-v1/controller.lock",
            2758586,
        )?,
        controller_lock(
            "/var/lib/jetstreamer-root-sweep-epoch197-singleton-20261017-v1/controller.lock",
            2758432,
        )?,
    ])
}

pub(crate) fn lock_epoch149_controllers() -> Result<[File; 3]> {
    Ok([
        controller_lock(
            "/var/lib/jetstreamer-root-sweep-epochs148-149-20260923-v81/controller.lock",
            3276956,
        )?,
        controller_lock(
            "/var/lib/jetstreamer-root-sweep-epoch149-20260923-v90/controller.lock",
            3276980,
        )?,
        controller_lock(
            "/var/lib/jetstreamer-root-sweep-epoch149-20261004-v92-r2/controller.lock",
            3802712,
        )?,
    ])
}

pub(crate) fn lock_early_singleton_controllers() -> Result<Vec<File>> {
    [
        ("/var/lib/jetstreamer-root-sweep-epoch130-v1417-production-20260930-v4/controller.lock", 3801199),
        ("/var/lib/jetstreamer-root-sweep-epoch130-v1417-production-20261002-v5-r2/controller.lock", 3801144),
        ("/var/lib/jetstreamer-root-sweep-epoch130-v1417-production-20261004-v6-r2/controller.lock", 3802700),
        ("/var/lib/jetstreamer-root-sweep-epoch134-v1419-production-20261007-cd656ef-v3-r2/controller.lock", 3802814),
        ("/var/lib/jetstreamer-root-sweep-epoch134-v1419-production-20261011-cd656ef-v4-r2/controller.lock", 2758102),
        ("/var/lib/jetstreamer-root-sweep-epoch134-v1419-production-20261011-cd656ef-v5-r2/controller.lock", 2758107),
        ("/var/lib/jetstreamer-root-sweep-epoch134-v1419-production-20261011-cd656ef-v6-r2/controller.lock", 2758115),
    ]
    .into_iter()
    .map(|(path, inode)| controller_lock(path, inode))
    .collect()
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
    let screens: &[&str] = if matches!(
        review["schema"].as_str(),
        Some(SINGLETON_SCHEMA | EARLY_SINGLETON_SCHEMA | EPOCH149_SCHEMA)
    ) {
        for key in ["controller_evidence", "consumer_programs"] {
            for entry in review[key]
                .as_array()
                .context("missing singleton owner proofs")?
            {
                evidence(entry)?;
            }
        }
        for link in review["unit_links"]
            .as_array()
            .context("missing linked guard definitions")?
        {
            let path = link["path"].as_str().context("missing guard link")?;
            let target = link["target"]
                .as_str()
                .context("missing guard definition")?;
            ensure!(
                fs::read_link(path)? == Path::new(target),
                "changed guard link {path}"
            );
        }
        &["installed_references"]
    } else {
        for key in [
            "original_failed_controller_state",
            "terminal_controller_state",
            "terminal_batch",
            "previous_verification",
        ] {
            evidence(&review[key])?;
        }
        &["parent_references", "exact_references"]
    };
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
    for &key in screens {
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
    fn two_singletons_require_their_own_and_previous_slot_indexes() {
        let files = [
            (
                196,
                "/home/sol/.jetstreamer-private/epoch196-singleton-20261017-v1/lane-a/output/compact-indexes/196/epoch-196-bafyreidltgi5iolhvjxilp6yhu4sptwgwpwwgwkp5rehbrcbnuhzbxau5a-mainnet-cid-to-offset-and-size.index",
            ),
            (
                196,
                "/home/sol/.jetstreamer-private/epoch196-singleton-20261017-v1/lane-a/output/compact-indexes/196/epoch-196-bafyreidltgi5iolhvjxilp6yhu4sptwgwpwwgwkp5rehbrcbnuhzbxau5a-mainnet-slot-to-cid.index",
            ),
            (
                195,
                "/home/sol/.jetstreamer-private/epoch196-singleton-20261017-v1/lane-a/output/compact-indexes/195/epoch-195-bafyreigawutckkq5wvdzd4o57mns2242r3h7naw7poyweshqem2dbvbhvi-mainnet-slot-to-cid.index",
            ),
            (
                197,
                "/home/sol/.jetstreamer-private/epoch197-singleton-20261017-v1/lane-a/output/compact-indexes/197/epoch-197-bafyreibzqylewmres6mm4i43dhjmbpilmcy6yz66wsqry7cjlr3ghnp7ty-mainnet-cid-to-offset-and-size.index",
            ),
            (
                197,
                "/home/sol/.jetstreamer-private/epoch197-singleton-20261017-v1/lane-a/output/compact-indexes/197/epoch-197-bafyreibzqylewmres6mm4i43dhjmbpilmcy6yz66wsqry7cjlr3ghnp7ty-mainnet-slot-to-cid.index",
            ),
            (
                196,
                "/home/sol/.jetstreamer-private/epoch197-singleton-20261017-v1/lane-a/output/compact-indexes/196/epoch-196-bafyreidltgi5iolhvjxilp6yhu4sptwgwpwwgwkp5rehbrcbnuhzbxau5a-mainnet-slot-to-cid.index",
            ),
        ];
        let mut targets: Vec<_> = files
            .iter()
            .map(|&(epoch, path)| target(epoch, path.into()))
            .collect();
        assert!(complete_selection(&targets, 6, is_singleton_index));
        assert!(!complete_selection(&targets[..5], 6, is_singleton_index));
        targets[0].path = targets[1].path.clone();
        assert!(!complete_selection(&targets, 6, is_singleton_index));
        let predecessor = targets.iter().find(|t| t.epoch == 195).unwrap();
        let misplaced = target(
            195,
            singleton_cache(197)
                .join("195")
                .join(predecessor.path.file_name().unwrap()),
        );
        assert!(!is_singleton_index(&misplaced));
        assert!(!is_singleton_index(&target(
            196,
            Path::new(files[0].1).with_file_name("epoch-196.jet")
        )));
    }

    #[test]
    fn epoch149_requires_both_indexes_from_the_original_lane() {
        let cache = Path::new(EPOCH149_CACHE);
        let mut targets =
            SUFFIXES.map(|suffix| target(149, index_path(cache, 149, EPOCH149_CID, suffix)));
        assert!(complete_selection(&targets, 2, is_epoch149_index));
        assert!(!complete_selection(&targets[..1], 2, is_epoch149_index));
        targets[0].path = targets[1].path.clone();
        assert!(!complete_selection(&targets, 2, is_epoch149_index));
        let other_lane = cache
            .ancestors()
            .nth(3)
            .unwrap()
            .join("lane-a/output/compact-indexes");
        assert!(!is_epoch149_index(&target(
            149,
            index_path(&other_lane, 149, EPOCH149_CID, SUFFIXES[0])
        )));
    }

    #[test]
    fn early_singleton_predecessor_allows_only_its_slot_index() {
        let cache = Path::new(
            "/home/sol/.jetstreamer-private/epoch130-v1417-production-20260930-v1/lane-a/output/compact-indexes",
        );
        let previous = "bafyreig4chl35gz4li7pe5vzcpawcdkdlpxixzwci2mld6mkbe7e4x4l7u";
        let slot_index = index_path(cache, 129, previous, SUFFIXES[1]);
        assert!(is_early_singleton_index(&target(129, slot_index.clone())));
        assert!(!is_early_singleton_index(&target(130, slot_index)));
        assert!(!is_early_singleton_index(&target(
            129,
            index_path(cache, 129, previous, SUFFIXES[0]),
        )));
    }

    #[test]
    fn complete_index_set_requires_exact_epoch_cid_suffix_and_parent() {
        let mut targets: Vec<_> = CIDS
            .iter()
            .flat_map(|&(epoch, cid)| {
                SUFFIXES.map(|s| target(epoch, index_path(Path::new(CACHE), epoch, cid, s)))
            })
            .collect();
        assert!(complete_selection(&targets, 8, is_index));
        assert!(!complete_selection(&targets[..7], 8, is_index));
        targets[0].epoch = 192;
        assert!(!complete_selection(&targets, 8, is_index));
        targets[0].epoch = 191;
        for path in [
            targets[1].path.clone(),
            index_path(Path::new(CACHE), 191, CIDS[1].1, SUFFIXES[0]),
            index_path(Path::new(CACHE), 191, CIDS[0].1, "other.index"),
            Path::new("/tmp").join(targets[0].path.file_name().unwrap()),
        ] {
            targets[0].path = path;
            assert!(!complete_selection(&targets, 8, is_index));
        }
    }
}
