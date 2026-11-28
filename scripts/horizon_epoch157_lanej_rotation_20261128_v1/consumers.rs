//! Resolve kernel references and executable systemd/cron entry points before namespace changes.
use super::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
const LANE: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j";
const DEPLOY: &str =
    "/usr/local/lib/jetstreamer/deploy-epochs155-157-runtime-boundaries-md5-20261012-v1";
const RESERVE: &str = "jetstreamer-adaptive-reserve-epoch157-lane1-20261016-v1.service";
const TIMER: &str = "jetstreamer-adaptive-reserve-epoch157-lane1-20261016-v1.timer";
const PRODUCER: &str = "jetstreamer-root-sweep-e157-t3-20261014-v1-r2-e157-157-lane-j-1.service";
pub(super) fn kernel(own: Option<&str>) -> Result<Value> {
    let proof = pinned(
        &Path::new(OLD).join("deployment-seal-receipt.json"),
        "81d6f44372cf6dd4150f213019425dece40aeef0cc4e7bfa97cfad0707873d74",
    );
    let search = member(&proof, "consumers.py")?;
    let group = own
        .map(|u| format!("/system.slice/{u}"))
        .unwrap_or_else(|| format!("/system.slice/{PARK}"));
    let script = "import sys,runpy,json; row={'source':json.load(open(sys.argv[2]))['source'],'identity':[64512,102301753]}; f=runpy.run_path(sys.argv[1])['live_refs']; hits,allowed=f(row,sys.argv[3]); print(json.dumps({'references':hits,'own':allowed}))";
    let result: Value = serde_json::from_str(&command(
        "/usr/bin/python3",
        &[
            "-IB",
            "-c",
            script,
            search.to_str().unwrap(),
            root("park-package-v1/expected.json").to_str().unwrap(),
            &group,
        ],
    )?)?;
    ensure!(
        result["references"]
            .as_array()
            .context("references")?
            .is_empty(),
        "another kernel consumer: {}",
        result["references"]
    );
    Ok(result)
}
fn terms(text: &str) -> Vec<&'static str> {
    let mut v = Vec::new();
    for (key, term) in [
        ("original_path", SRC),
        ("segment", "epoch-157.segment-00-67824000-68140177.jet"),
        ("segment_directory", ".epoch-157.jet.runtime-segments"),
        ("lane", LANE),
        ("lane_option", "--lane=lane-j="),
        ("deployment", DEPLOY),
        ("managed_controller", CONTROLLER),
        ("retained_validator", VUNIT),
    ] {
        if text.contains(term) {
            v.push(key)
        }
    }
    v
}
fn properties(s: &str) -> BTreeMap<String, String> {
    s.lines()
        .filter_map(|l| {
            l.split_once('=')
                .map(|(a, b)| (a.to_string(), b.to_string()))
        })
        .collect()
}
fn tokens(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c.is_ascii_whitespace() || "\\\"'(){}[]=,;|:".contains(c))
        .filter(|n| n.starts_with('/'))
}
fn material(p: &Path) -> bool {
    let name = p.to_string_lossy();
    p.is_absolute()
        && [
            ROOT,
            "/var/lib/jetstreamer",
            "/usr/local/lib/jetstreamer",
            "/home/sol/.jetstreamer-private",
            "/etc/systemd",
            "/run/systemd",
        ]
        .iter()
        .any(|root| name.starts_with(root))
        && p.extension().and_then(|x| x.to_str()).is_some_and(|x| {
            matches!(
                x,
                "json" | "py" | "sh" | "toml" | "service" | "timer" | "path" | "socket" | "conf"
            )
        })
        && ![
            "credential",
            "secret",
            "/logs/",
            "/.git/",
            "/receipts/sample-",
            "/guard-receipts/sample-",
        ]
        .iter()
        .any(|r| name.to_ascii_lowercase().contains(r))
}
fn artifacts<'a>(
    s: &str,
    cache: &'a mut BTreeMap<PathBuf, (Vec<&'static str>, Vec<PathBuf>)>,
) -> Result<Vec<(PathBuf, Vec<&'static str>)>> {
    let mut hits = Vec::new();
    let mut queue: VecDeque<_> = tokens(s)
        .map(PathBuf::from)
        .filter(|p| material(p))
        .collect();
    let mut seen = BTreeSet::new();
    while let Some(p) = queue.pop_front() {
        if !seen.insert(p.clone()) {
            continue;
        }
        if !cache.contains_key(&p) {
            let a = match fs::metadata(&p) {
                Ok(x) => x,
                Err(e)
                    if e.kind() == io::ErrorKind::NotFound
                        || e.raw_os_error() == Some(libc::ENOTDIR) =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            if !a.is_file() || a.len() > 2 << 20 {
                continue;
            }
            let raw = fs::read(&p)?;
            let text = String::from_utf8_lossy(&raw);
            let children = tokens(&text)
                .map(PathBuf::from)
                .filter(|p| material(p))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            cache.insert(p.clone(), (terms(&text), children));
        }
        let (t, c) = &cache[&p];
        if !t.is_empty() {
            hits.push((p.clone(), t.clone()))
        }
        // Follow executable plans. Ledgers and receipts describe prior owners rather than launching them.
        let mut name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        if matches!(
            p.extension().and_then(|s| s.to_str()),
            Some("py" | "sh" | "service" | "timer" | "path" | "socket")
        ) {
            name.push_str(" launch")
        }
        if [
            "plan",
            "config",
            "contract",
            "launch",
            "profile",
            "manifest",
            "settings",
            "observer",
            "authority",
            "dispatch",
        ]
        .iter()
        .any(|t| name.contains(t))
        {
            queue.extend(c.iter().cloned())
        }
    }
    Ok(hits)
}
fn direct_sources() -> Result<Vec<Value>> {
    let dirs = [
        "/etc/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/home/sol/.config/systemd/user",
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
    ];
    let mut args = vec![
        "--files-with-matches",
        "--null",
        "--fixed-strings",
        "--hidden",
        "--no-ignore",
        "--text",
    ];
    for t in [
        SRC,
        "epoch-157.segment-00-67824000-68140177.jet",
        ".epoch-157.jet.runtime-segments",
        LANE,
        DEPLOY,
        CONTROLLER,
        VUNIT,
    ] {
        args.extend(["-e", t])
    }
    for d in dirs {
        if Path::new(d).is_dir() {
            args.push(d)
        }
    }
    let o = Command::new("/usr/bin/rg").args(args).output()?;
    ensure!(
        matches!(o.status.code(), Some(0 | 1)),
        "privileged definition search failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let mut hits = Vec::new();
    for b in o.stdout.split(|b| *b == 0).filter(|b| !b.is_empty()) {
        let p = Path::new(std::str::from_utf8(b)?);
        let bytes = fs::read(p)?;
        let sha = digest(&bytes);
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        let fixed = match name.as_ref() {
            RESERVE => Some("78300d905a50e76d81a61cb9510ac26e2099e0f59c9492157b291f4a0b5735c2"),
            CONTROLLER => Some("e0ac59c3ae96d1219a26c43202805ab1b1d4c5866bfb09a06ef2673fc295ab32"),
            OTHER => Some("3c3d09fa36c52038a5a35a9d4f1c2f1c4af9dce5af8f2538f7a6136a52b68882"),
            VUNIT => Some("76c6a32674cbd6580183c5a2cac25ed92e2930bace691ea301721e9198e451ef"),
            _ => None,
        };
        ensure!(
            fixed == Some(sha.as_str())
                && p.parent().is_some_and(|p| matches!(
                    p.to_str(),
                    Some("/etc/systemd/system" | "/run/systemd/transient")
                )),
            "unreviewed staged consumer {}",
            p.display()
        );
        hits.push(json!({"path":p,"sha256":sha,"terms":terms(&String::from_utf8_lossy(&bytes))}));
    }
    ensure!(
        hits.iter()
            .any(|v| v["path"].as_str().is_some_and(|p| p.ends_with(CONTROLLER)))
            && hits
                .iter()
                .any(|v| v["path"].as_str().is_some_and(|p| p.ends_with(OTHER))),
        "missing fixed original controller bindings"
    );
    Ok(hits)
}
fn idle_controller(u: &str) -> Result<Value> {
    let q = props(
        u,
        "Id,ActiveState,SubState,MainPID,ControlPID,Job,TriggeredBy,Triggers,UnitFileState,ControlGroup",
    )?;
    ensure!(
        q["Id"] == u
            && q["ActiveState"] == "inactive"
            && q["MainPID"] == "0"
            && q["ControlPID"] == "0"
            && q["Job"].is_empty()
            && q["TriggeredBy"].is_empty()
            && q["Triggers"].is_empty()
            && q["ControlGroup"].is_empty()
            && (u == PRODUCER || q["UnitFileState"] == "static"),
        "runnable original owner {u}"
    );
    Ok(json!(q))
}
pub(super) fn census(own: Option<&str>) -> Result<Value> {
    let o = ours()?;
    let known = [
        idle_controller(CONTROLLER)?,
        idle_controller(OTHER)?,
        idle_controller(PRODUCER)?,
    ];
    let timer = props(
        TIMER,
        "Id,ActiveState,SubState,Job,Triggers,TriggeredBy,UnitFileState",
    )?;
    let reserve = props(
        RESERVE,
        "Id,ActiveState,SubState,Job,Triggers,TriggeredBy,ExecStart,MainPID,ControlPID,ControlGroup",
    )?;
    ensure!(
        timer["ActiveState"] == "inactive"
            && timer["Job"].is_empty()
            && timer["Triggers"] == RESERVE
            && timer["UnitFileState"] == "static"
            && timer["TriggeredBy"].is_empty()
            && matches!(reserve["ActiveState"].as_str(), "failed" | "inactive")
            && reserve["Job"].is_empty()
            && reserve["ControlGroup"].is_empty()
            && reserve["MainPID"] == "0"
            && reserve["ControlPID"] == "0"
            && reserve["ExecStart"].contains("d66eddeac8304adfbd17e4ebe1c6c1f9")
            && reserve["ExecStart"].contains("94fd30ad116340b88e3189a3d486f9bd"),
        "old producer reserve guard rearmed"
    );
    ensure!(
        reference(Path::new(
            "/etc/systemd/system/jetstreamer-adaptive-reserve-epoch157-lane1-20261016-v1.timer"
        ))?["sha256"]
            == "30eeb806307b4161e58f0f31ee9445f0fcdf85ff238cdf7c504e49c9888441c0"
            && reference(Path::new(
                "/usr/local/lib/jetstreamer/adaptive-reserve-epoch157-20261016-v1/guard-adaptive-replay-reserve.py"
            ))?["sha256"]
                == "b62e58f5be764935a679408e1fcc446a9768170109a6639c87fd01571b9f2b62",
        "old guard/timer definition changed"
    );
    let validation = preserved()?;
    let v = props(
        VUNIT,
        "Id,ActiveState,SubState,MainPID,ControlPID,Job,ControlGroup,InvocationID,TriggeredBy,Triggers,RemainAfterExit,ExecMainStatus,Result",
    )?;
    ensure!(
        v["InvocationID"] == "9768a460a5284f5a8ebfd422e437e8b6"
            && v["ActiveState"] == "active"
            && v["SubState"] == "exited"
            && v["RemainAfterExit"] == "yes"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["ExecMainStatus"] == "0"
            && v["Result"] == "success"
            && v["ControlGroup"].is_empty()
            && v["TriggeredBy"].is_empty()
            && v["Triggers"].is_empty()
            && v["Job"].is_empty(),
        "original retained validator no longer terminal"
    );
    let definitions = direct_sources()?;
    let listing = command(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--all",
            "--plain",
            "--no-pager",
            "--no-legend",
            "--type=service,timer,path,socket",
        ],
    )?;
    let potential: Vec<_> = listing
        .lines()
        .filter_map(|s| {
            let mut i = s.split_whitespace();
            let name = i.next()?;
            let _load = i.next()?;
            let state = i.next()?;
            (!matches!(state, "inactive" | "failed")).then_some(name)
        })
        .collect();
    let mut cache = BTreeMap::new();
    let mut matches = Vec::new();
    let mut hits = Vec::new();
    let fields = "Id,ActiveState,SubState,Job,ControlPID,MainPID,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,WorkingDirectory,FragmentPath,DropInPaths,Triggers,TriggeredBy";
    for slice in potential.chunks(120) {
        let mut args = vec!["show", "--all", "-p", fields, "--"];
        args.extend_from_slice(slice);
        for record in command("/usr/bin/systemctl", &args)?.trim().split("\n\n") {
            let p = properties(record);
            let unit = &p["Id"];
            if matches!(p["ActiveState"].as_str(), "inactive" | "failed") {
                continue;
            }
            let projection = format!(
                "{} {} {} {} {} {} {}",
                p["ExecStart"],
                p["ExecStartPre"],
                p["ExecStartPost"],
                p["ExecCondition"],
                p["WorkingDirectory"],
                p["FragmentPath"],
                p["DropInPaths"]
            );
            let direct = terms(&projection);
            let nested = artifacts(&projection, &mut cache)?;
            if direct.is_empty() && nested.is_empty() {
                continue;
            }
            // The live holding and this operator can read their own custody plans. A historical ledger reached from
            // an observer is safe only if the executable entry point has no segment, lane or original-unit binding.
            let monitor = unit.starts_with("horizon-observer-")
                || unit.starts_with("horizon-cycle-")
                || unit.starts_with("horizon-continue-");
            let owned =
                Some(unit.as_str()) == own || unit == VUNIT || (own.is_none() && unit == PARK);
            let historical = monitor
                && direct.is_empty()
                && nested.iter().all(|(p, _)| {
                    p.file_name().is_some_and(|s| {
                        let t = s.to_string_lossy();
                        t.contains("OBSERVATION")
                            || t.contains("FLEET")
                            || t.contains("ADMISSION")
                            || t.contains("expected")
                    })
                });
            let row = json!({"unit":unit,"direct":direct,"plans":nested,"terminal_validator":unit==VUNIT,"ledger_only":historical});
            if !owned && !historical {
                hits.push(row.clone())
            }
            matches.push(row);
        }
    }
    ensure!(
        hits.is_empty(),
        "unresolved live consumer {}",
        serde_json::to_string(&hits)?
            .chars()
            .take(1600)
            .collect::<String>()
    );
    let live = kernel(own)?;
    Ok(
        json!({"operator_seal":o,"original_static_and_producer":known,"parked_original_reserve":reserve,"stopped_original_timer":timer,"original_validator":v,"preserved":validation,"systemd_units_seen":listing.lines().count(),"runnable_units":potential.len(),"resolved_material":cache.len(),"checked_definitions":definitions,"runnable_matches":matches,"kernel":live}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_segment_reference_matches_without_broad_epoch_text() {
        assert!(terms(SRC).contains(&"original_path"));
        assert!(terms("node_02/objects/non157.blob").is_empty());
        assert!(terms("/other/lane-k").is_empty());
    }
    #[test]
    fn only_resolved_operation_material_is_read() {
        assert!(material(Path::new(
            "/var/lib/jetstreamer/horizon_runtime_data/real/plan.json"
        )));
        assert!(!material(Path::new("/etc/jetstreamer/horizon-r2.env")));
        assert!(!material(Path::new(
            "/home/sol/.jetstreamer-private/credentials/plan.json"
        )));
    }
}
