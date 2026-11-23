use super::*;
const NODE228: &str =
    "/var/lib/jetstreamer/horizon228-demotion-parent-natural-f797454e-v165-v1-qualified/parent";
const NODE228_SHA: &str = "16a534aa24d81274dfa581fb282352b6538e85c065799514cf0458da42936895";
const HANDOFF228: &str = "da3fdea0fa6f6682daa741e4c72d5f3a81d6bd420743d5df70c46d40b6319752";
pub(super) fn tree(p: &Profile, parent: u64) -> Result<BTreeMap<u64, Value>> {
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
    let mut tree = BTreeMap::new();
    let members = fs::read_to_string(cg.join("cgroup.procs"))?;
    let ids = members
        .lines()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    ensure!(
        (2..=8).contains(&ids.len()) && ids.contains(&parent),
        "incomplete native replay tree"
    );
    let mut workers = Vec::new();
    let (node, scratch, worker_sha) = match p.lane {
        Lane::Bounded266 | Lane::BoundedRetry266 => {
            (PathBuf::from(successor::NODE), "state", bounded::WORKER_SHA)
        }
        Lane::Epoch228 => (PathBuf::from(NODE228), "scratch", epoch228::WORKER_SHA),
        Lane::Instructions266 | Lane::Turnover266 => (
            PathBuf::from(successor::NODE),
            "state",
            successor::WORKER_SHA,
        ),
        Lane::Epoch266 => (
            Path::new(SNAPROOT).join("jetstreamer-node"),
            "state",
            "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae",
        ),
    };
    for id in ids {
        let info = PathBuf::from(format!("/proc/{id}"));
        let pin = info.join("exe");
        let exe = fs::read_link(&pin)?;
        let before = fs::read_to_string(info.join("stat"))?;
        let fields = before
            .rsplit_once(") ")
            .context("process stat")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        ensure!(fields.len() >= 20, "process stat length");
        ensure!(
            fs::read_to_string(info.join("cgroup"))?.trim()
                == format!("0::/system.slice/{}", p.unit),
            "worker changed cgroup"
        );
        let mapped = metadata_identity(&fs::metadata(&pin)?);
        ensure!(mapped == identity(&exe)?, "unlinked replay image");
        let role = if exe == node {
            if p.lane == Lane::Epoch228 {
                ensure!(
                    id == parent
                        && mapped.3 == 0
                        && mapped.4 & 0o222 == 0
                        && hash(&pin)? == NODE228_SHA,
                    "different original epoch 228 parent"
                );
            }
            "node"
        } else {
            ensure!(
                exe.starts_with(p.root.join(scratch))
                    && exe.ends_with("bound-worker/historical-worker")
                    && mapped.3 == 1000
                    && mapped.4 & 0o222 == 0
                    && hash(&pin)? == worker_sha,
                "different historical worker"
            );
            workers.push(id);
            "worker"
        };
        tree.insert(id,json!({"parent":fields[1].parse::<u64>()?,"start_ticks":fields[19].parse::<u64>()?,"role":role,"image":exe,"device":mapped.0,"inode":mapped.1}));
    }
    ensure!(
        workers.len() == 1 && tree[&parent]["parent"] == 1,
        "native replay lineage"
    );
    if p.lane == Lane::Epoch228 {
        ensure!(
            workers == [2819639] && tree[&workers[0]]["parent"] == parent,
            "different original epoch 228 Bank process"
        );
    }
    let mut cur = workers[0];
    let mut seen = BTreeSet::new();
    while cur != parent {
        ensure!(seen.insert(cur), "process cycle");
        let child = &tree[&cur];
        cur = num(child, "parent")?;
        let ancestor = tree.get(&cur).context("detached historical worker")?;
        ensure!(
            ancestor["role"] == "node"
                && num(ancestor, "start_ticks")? <= num(child, "start_ticks")?,
            "foreign worker parent"
        );
    }
    ensure!(seen.len() + 1 == tree.len(), "unaccounted replay processes");
    Ok(tree)
}
pub(super) fn progress(row: &Value, target: u64) -> Result<Option<(u64, u64, u64, u64)>> {
    let message = text(row, "MESSAGE")?;
    let Some((_, res)) = message.split_once("progress slot ") else {
        return Ok(None);
    };
    let (slot, tail) = res.split_once('/').context("progress window")?;
    let number = |s: &str| -> Result<u64> {
        let n = s.bytes().take_while(u8::is_ascii_digit).count();
        Ok(s[..n].parse()?)
    };
    ensure!(number(tail)? == target, "different replay target");
    let tx = number(message.split_once("txs=").context("transaction counter")?.1)?;
    let accounts = number(
        message
            .split_once("accounts=")
            .context("accounts counter")?
            .1,
    )?;
    Ok(Some((
        text(row, "__MONOTONIC_TIMESTAMP")?.parse()?,
        slot.parse()?,
        tx,
        accounts,
    )))
}
pub(super) fn witness(n: &mut Native, lane: Lane) -> Result<Value> {
    let p = Profile::new(lane, "pilot")?;
    let (bootstrap, target) = match lane {
        Lane::Epoch266
        | Lane::Instructions266
        | Lane::Turnover266
        | Lane::Bounded266
        | Lane::BoundedRetry266 => (114910768, 115343999),
        Lane::Epoch228 => (98495291, 98928278),
    };
    let handoff = bound_at(&p.state.join("handoff.json"))?;
    let h = handoff.sealed()?;
    let iid = text(&h, "iid")?;
    let pid = num(&h, "pid")?;
    if lane == Lane::Epoch228 {
        ensure!(
            handoff.sha256 == HANDOFF228
                && h["unit"] == p.unit
                && iid == "5566869f329b46309aa8a2ea8f46047a"
                && pid == 2819393
                && h["entry_replay_proven"] == false,
            "another epoch 228 original handoff"
        );
    }
    let m = n.show(&p.unit)?;
    ensure!(
        m["InvocationID"] == iid
            && m["MainPID"] == pid.to_string()
            && m["ActiveState"] == "active"
            && m["NRestarts"] == "0",
        "pilot owner"
    );
    let current = tree(&p, pid)?;
    let raw = n.run(
        "/usr/bin/journalctl",
        &[
            "--no-pager",
            "-b",
            "-n",
            "32",
            "-o",
            "json",
            "--grep=progress slot ",
            &format!("_SYSTEMD_UNIT={}", p.unit),
            &format!("_SYSTEMD_INVOCATION_ID={iid}"),
        ],
    )?;
    let mut points = Vec::new();
    for line in std::str::from_utf8(&raw)?.lines() {
        let row: Value = serde_json::from_str(line)?;
        ensure!(
            row["_BOOT_ID"] == BOOT.replace('-', "")
                && row["_SYSTEMD_INVOCATION_ID"] == iid
                && row["_SYSTEMD_UNIT"] == p.unit
                && row["_UID"] == "1000",
            "foreign progress journal"
        );
        if matches!(
            lane,
            Lane::Epoch228 | Lane::Bounded266 | Lane::BoundedRetry266
        ) {
            ensure!(
                row["_PID"].as_str().and_then(|v| v.parse::<u64>().ok()) == Some(pid)
                    && row["_EXE"]
                        == if lane == Lane::Epoch228 {
                            NODE228
                        } else {
                            successor::NODE
                        },
                "progress outside the original epoch 228 parent"
            );
        }
        if let Some(point) = progress(&row, target)? {
            if lane == Lane::Epoch228 && (point.1 <= bootstrap || point.2 == 0) {
                continue;
            }
            points.push((point, text(&row, "__CURSOR")?.to_owned()));
        }
    }
    points.sort_by_key(|(pt, _)| pt.0);
    ensure!(
        points.len() >= 2
            && points.windows(2).all(|w| {
                let (a, b) = (w[0].0, w[1].0);
                a.0 < b.0 && a.1 <= b.1 && a.2 <= b.2 && a.3 <= b.3
            }),
        "nonmonotonic replay progress"
    );
    let (a, b) = (points[0].0, points.last().unwrap().0);
    ensure!(
        points[0].1 != points.last().unwrap().1
            && a.1 > bootstrap
            && a.1 < b.1
            && b.1 <= target
            && a.2 < b.2
            && a.3 <= b.3,
        "missing proven first entries"
    );
    ensure!(
        tree(&p, pid)? == current && command_field(n, &p.unit, "InvocationID")? == iid,
        "process tree changed"
    );
    if lane == Lane::Epoch228 {
        let end = n.show(&p.unit)?;
        ensure!(
            [
                "MainPID",
                "InvocationID",
                "ActiveState",
                "SubState",
                "NRestarts",
                "ExecMainStartTimestampMonotonic"
            ]
            .iter()
            .all(|&k| end[k] == m[k])
                && end["SubState"] == "running",
            "original pilot changed during capture"
        );
        let journal = binding(&binding(&h["token"])?.sealed()?["guard_pid1"])?.sealed()?;
        ensure!(
            num(&journal, "last_monotonic_us")? < a.0,
            "entries preceded first guard release"
        );
    }
    if lane == Lane::Instructions266 {
        ensure!(
            b.1 > 114912038,
            "replacement has not yet passed the original transaction's slot"
        );
        let g = binding(&binding(&h["token"])?.sealed()?["guard_pid1"])?.sealed()?;
        ensure!(
            num(&g, "last_monotonic_us")? < a.0,
            "progress preceded release"
        );
    }
    let v = json!({"schema":format!("horizon{}-first-useful-native-entry-replay-v1",lane.epoch()),"handoff":handoff,"unit":p.unit,"iid":iid,"pid":pid,"processes":current,"first":points[0],"last":points.last().unwrap(),"entry_replay_proven":true,"full_epoch_qualified":false,"publication_authorized":false});
    if lane == Lane::Epoch228 {
        public(&n.root, "first-entries.json", &v)?;
    } else {
        save_json(&n.root, "first-entries.json", &v)?;
    }
    Ok(v)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_228_progress_requires_its_qualification_end() {
        let v = json!({"MESSAGE":"progress slot 98496002/98928278 txs=15 accounts=32","__MONOTONIC_TIMESTAMP":"100"});
        assert_eq!(
            progress(&v, 98928278).unwrap(),
            Some((100, 98496002, 15, 32))
        );
        assert!(progress(&v, 115343999).is_err());
    }
    #[test]
    fn native_window_uses_real_observer_message_format() {
        let mut v = json!({"MESSAGE":"progress slot 114912004/115343999 txs=15 accounts=32","__MONOTONIC_TIMESTAMP":"100"});
        assert_eq!(
            progress(&v, 115343999).unwrap(),
            Some((100, 114912004, 15, 32))
        );
        v["MESSAGE"] = json!("progress slot 114912004/114912004 txs=15 accounts=32");
        assert!(progress(&v, 115343999).is_err());
    }
}
