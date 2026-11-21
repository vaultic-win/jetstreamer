use super::*;
fn tree(p: &Profile, parent: u64) -> Result<BTreeMap<u64, Value>> {
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
        let role = if exe == Path::new(SNAPROOT).join("jetstreamer-node") {
            "node"
        } else {
            ensure!(
                exe.starts_with(p.root.join("state"))
                    && exe.ends_with("bound-worker/historical-worker")
                    && mapped.3 == 1000
                    && mapped.4 & 0o222 == 0
                    && hash(&pin)?
                        == "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae",
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
fn progress(row: &Value) -> Result<Option<(u64, u64, u64, u64)>> {
    let message = text(row, "MESSAGE")?;
    let Some((_, res)) = message.split_once("progress slot ") else {
        return Ok(None);
    };
    let (slot, tail) = res.split_once('/').context("progress window")?;
    let number = |s: &str| -> Result<u64> {
        let n = s.bytes().take_while(u8::is_ascii_digit).count();
        Ok(s[..n].parse()?)
    };
    ensure!(number(tail)? == 115343999, "different replay target");
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
pub(super) fn witness(n: &mut Native) -> Result<Value> {
    let p = Profile::new("pilot")?;
    let b = bound_at(&p.state.join("handoff.json"))?;
    let h = b.sealed()?;
    let iid = text(&h, "iid")?;
    let pid = num(&h, "pid")?;
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
        if let Some(point) = progress(&row)? {
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
        a.1 > 114910768 && a.1 < b.1 && b.1 <= 115343999 && a.2 < b.2 && a.3 <= b.3,
        "missing proven first entries"
    );
    ensure!(
        tree(&p, pid)? == current && command_field(n, &p.unit, "InvocationID")? == iid,
        "process tree changed"
    );
    let v = json!({"schema":"horizon266-first-useful-native-entry-replay-v1","handoff":b,"unit":p.unit,"iid":iid,"pid":pid,"processes":current,"first":points[0],"last":points.last().unwrap(),"entry_replay_proven":true,"full_epoch_qualified":false,"publication_authorized":false});
    save_json(&n.root, "first-entries.json", &v)?;
    Ok(v)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_window_uses_real_observer_message_format() {
        let mut v = json!({"MESSAGE":"progress slot 114912004/115343999 txs=15 accounts=32","__MONOTONIC_TIMESTAMP":"100"});
        assert_eq!(progress(&v).unwrap(), Some((100, 114912004, 15, 32)));
        v["MESSAGE"] = json!("progress slot 114912004/114912004 txs=15 accounts=32");
        assert!(progress(&v).is_err());
    }
}
