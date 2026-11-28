use super::*;
const FILENAME_UNIT: &str = "horizon-265-production-node-filename-20261119-v1.service";
const FILENAME_IID: &str = "424280351c41494286db281771e6ce00";
const FINGERPRINT_UNIT: &str = "horizon-265-production-node-fingerprint-20261119-v1.service";
fn invocation(p: &Value, filename: bool) -> Result<Vec<String>> {
    let argv: Vec<String> = serde_json::from_value(p["argv"].clone())?;
    ensure!(
        argv.len() == 8
            && argv[0] == NODE
            && argv[1] == "265"
            && argv[3] == "--verify"
            && argv[4] == "--root-checkpoint-cohort"
            && argv[5] == format!("--cohort-manifest={MANIFEST}"),
        "selected-node probe command changed"
    );
    let output = Path::new(&argv[2]);
    ensure!(
        output.is_absolute()
            && output.file_name().is_some_and(|s| s == "output")
            && p["output_directory"] == argv[2],
        "probe output scope"
    );
    let fingerprint = argv[6]
        .strip_prefix("--cohort-manifest-fingerprint=")
        .context("fingerprint arg")?;
    ensure!(
        fingerprint.starts_with("sha256:") && hex(&fingerprint[7..], 64),
        "fingerprint syntax"
    );
    ensure!(
        if filename {
            fingerprint == FINGERPRINT
        } else {
            fingerprint == format!("sha256:{}", "0".repeat(64))
        },
        "probe must exercise selected exact rejection"
    );
    let snap = Path::new(
        argv[7]
            .strip_prefix("--snapshot-archive=")
            .context("snapshot arg")?,
    );
    ensure!(
        snap.is_absolute()
            && snap
                .file_name()
                .is_some_and(|s| s
                    != "snapshot-114479281-Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW.tar.zst"),
        "negative probe must never reach snapshot loading"
    );
    let dirs = p["empty_directories"]
        .as_array()
        .context("negative output/work directories")?;
    ensure!(
        dirs.len() >= 2 && dirs.len() <= 8 && dirs.contains(&json!(argv[2])),
        "complete probe output/work census"
    );
    Ok(argv)
}
fn empty(p: &Value) -> Result<Value> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for d in p["empty_directories"]
        .as_array()
        .context("empty directories")?
    {
        let path = Path::new(d.as_str().context("directory path")?);
        ensure!(
            path.is_absolute() && seen.insert(path.to_path_buf()),
            "directory scope/duplicate"
        );
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_dir()
                && path.canonicalize()? == path
                && m.uid() == 1000
                && m.mode() & 0o022 == 0
                && fs::read_dir(path)?.next().is_none(),
            "probe output/work not empty"
        );
        result.push(json!({"path":path,"identity":identity(&m)}));
    }
    Ok(json!(result))
}
fn one(p: &Value, filename: bool) -> Result<Value> {
    let unit = if filename {
        FILENAME_UNIT
    } else {
        FINGERPRINT_UNIT
    };
    let iid = text(p, "invocation_id")?;
    ensure!(
        p["unit"] == unit && (!filename || iid == FILENAME_IID),
        "original probe identity"
    );
    let argv = invocation(p, filename)?;
    let before = show(unit)?;
    let pid = terminal(&before, unit, iid, false)?;
    command(&before, &argv)?;
    drained(unit, pid)?;
    for (k, w) in [
        ("User", "ubuntu"),
        ("NoNewPrivileges", "yes"),
        ("MemorySwapMax", "0"),
    ] {
        ensure!(before[k] == w, "probe safety property {k}");
    }
    ensure!(
        before["Group"] == "ubuntu" || (filename && before["Group"] == ""),
        "probe group selection"
    );
    let cap = text(&before, "MemoryMax")?.parse::<u64>()?;
    ensure!(cap > 0 && cap <= 1 << 30, "bounded probe memory");
    // The old filename probe is retained evidence; do not demand a redesigned sandbox.
    // New fingerprint execution is tightly bounded and network isolated.
    if !filename {
        for (k, w) in [
            ("PrivateNetwork", "yes"),
            ("MemoryMax", "536870912"),
            ("TasksMax", "64"),
            ("RuntimeMaxUSec", "30s"),
            ("TimeoutStopUSec", "10s"),
            ("LimitFSIZE", "65536"),
        ] {
            ensure!(before[k] == w, "fingerprint bounded property {k}");
        }
    }
    let dirs = empty(p)?;
    let rows = journal(unit, iid)?;
    let marker = if filename {
        "root-checkpoint cohort snapshot override filename mismatch"
    } else {
        "cohort manifest fingerprint mismatch"
    };
    journal_owner(
        &rows,
        unit,
        iid,
        pid,
        &argv,
        marker,
        JournalEvidence::StrictNode,
    )?;
    if filename {
        ensure!(
            !rows.iter().any(|r| r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.contains("cohort manifest fingerprint mismatch"))),
            "filename probe never passed manifest fingerprint"
        );
    }
    ensure!(
        before == show(unit)? && dirs == empty(p)?,
        "probe owner/directories changed"
    );
    drained(unit, pid)?;
    Ok(
        json!({"schema":"horizon265-selected-node-negative-native-evidence-v1","unit":unit,"invocation_id":iid,"pid":pid,"argv":argv,"terminal":before,"journal":rows,"empty_directories":dirs,"expected_rejection":marker,"probe_plan":p}),
    )
}
pub(super) fn capture(p: &Value, plan: &Bound, self_sha: &str) -> Result<()> {
    ensure!(
        p["schema"] == "horizon265-negative-probes-capture-plan-v1",
        "probe plan scope"
    );
    ensure!(
        digest(&read(Path::new(NODE), 0, 256 << 20, true)?) == NODE_SHA
            && digest(&read(Path::new(MANIFEST), 0, 16 << 20, true)?) == MANIFEST_SHA,
        "selected node/manifest differ"
    );
    let filename = one(&p["wrong_filename"], true)?;
    let fingerprint = one(&p["fingerprint"], false)?;
    let output = Path::new(text(p, "output")?);
    let dir = output.parent().context("receipt parent")?;
    let mut refs = BTreeMap::new();
    for (key, mut evidence) in [("wrong_filename", filename), ("fingerprint", fingerprint)] {
        deny(&mut evidence);
        let raw = put(&dir.join(format!("{key}-command-journal.json")), &evidence)?;
        let mut receipt = json!({"schema":"horizon265-selected-node-negative-probe-v1","unit":evidence["unit"],"invocation_id":evidence["invocation_id"],"terminal":evidence["terminal"],"actual_command_and_journal":raw,"node":{"path":NODE,"sha256":NODE_SHA},"manifest":{"path":MANIFEST,"sha256":MANIFEST_SHA},"expected_rejection":evidence["expected_rejection"],"output_and_work_directories_empty":true,"plan":plan,"self_sha256":self_sha});
        deny(&mut receipt);
        refs.insert(key, put(&dir.join(format!("{key}.json")), &receipt)?);
    }
    let mut v = json!({"schema":"horizon265-selected-node-negative-probes-v1","epoch":265,"node":{"path":NODE,"sha256":NODE_SHA},"manifest_sha256":MANIFEST_SHA,"fingerprint_rejection_passed":true,"manifest_decoded_before_snapshot_filename_rejection":true,"output_and_work_directories_empty":true,"fingerprint":refs["fingerprint"],"wrong_filename":refs["wrong_filename"],"plan":plan,"self_sha256":self_sha});
    deny(&mut v);
    put(output, &v)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(filename: bool) -> Value {
        let root = "/home/ubuntu/.jetstreamer-private/probe265";
        json!({"argv":[NODE,"265",format!("{root}/output"),"--verify","--root-checkpoint-cohort",format!("--cohort-manifest={MANIFEST}"),format!("--cohort-manifest-fingerprint={}",if filename{FINGERPRINT.into()}else{format!("sha256:{}","0".repeat(64))}),format!("--snapshot-archive={root}/wrong-name.tar.zst")],"output_directory":format!("{root}/output"),"empty_directories":[format!("{root}/output"),format!("{root}/work")]})
    }
    #[test]
    fn probes_can_only_reach_expected_pre_restore_rejections() {
        for filename in [true, false] {
            let p = fixture(filename);
            invocation(&p, filename).unwrap();
            let mut bad = p.clone();
            bad["argv"][0] = json!("/other/node");
            assert!(invocation(&bad, filename).is_err());
            let mut bad = p.clone();
            bad["argv"][7] = json!(
                "--snapshot-archive=/input/snapshot-114479281-Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW.tar.zst"
            );
            assert!(invocation(&bad, filename).is_err());
            let mut bad = p.clone();
            bad["argv"].as_array_mut().unwrap().push(json!("--resume"));
            assert!(invocation(&bad, filename).is_err());
            let mut bad = p;
            bad["empty_directories"] = json!([]);
            assert!(invocation(&bad, filename).is_err());
        }
    }
    #[test]
    fn expected_command_rejects_argv_and_ignore_errors_substitution() {
        let p = fixture(true);
        let argv = invocation(&p, true).unwrap();
        let good = json!({"ExecStart":format!("{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=[x] ; stop_time=[y] ; pid=42 ; code=exited ; status=1 }}",argv[0],argv.join(" "))});
        command(&good, &argv).unwrap();
        let bad = json!({"ExecStart":text(&good,"ExecStart").unwrap().replace("ignore_errors=no","ignore_errors=yes")});
        assert!(command(&bad, &argv).is_err());
    }
}
