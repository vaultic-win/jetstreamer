//! Close the two historical lane caches with their original replay and custody leases held.
use super::*;
use evidence::{command, digest, num, props, reference, word};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
};

pub(super) const DIR: &str = "closed157-lane-cache-index-retirement-20261128-v1";
const FAMILY: &str = "epochs150-173-20260923-v2";
const D: &str = "epochs150-173-20260923-v2/lane-d";
const J: &str = "epochs150-173-20260923-v2/lane-j";
const PRODUCER: &str = "jetstreamer-root-sweep-historical-151-173-v91-e157-157-lane-d-63.service";
const J_PRODUCER: &str = "jetstreamer-root-sweep-e157-t3-20261014-v1-r2-e157-157-lane-j-1.service";
const RESERVE: &str = "jetstreamer-adaptive-reserve-epoch157-lane1-20261016-v1.service";
const TIMER: &str = "jetstreamer-adaptive-reserve-epoch157-lane1-20261016-v1.timer";
const VALIDATOR: &str = "horizon-qualify-157-private-verification-20261021-v1.service";
const CONTROLLER: &str = "jetstreamer-epoch157-target3-controller-v1-r2.service";
const OTHER: &str = "jetstreamer-epochs155-156-target3-controller-v1-r2.service";
const J_ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch157-lanej-rotation-20261128-v1";
const D_ARCHIVE: &str = "0485071a587930de2b0007c23c84be27ca4b2e520eda6a56d5b5b076dcf6aa35";
const J_ARCHIVE: &str = "4a4d4403a4fe92bd24c8406cebb93eccbc614e8cb746dda9dcbf8b17eeeddadf";

pub(super) fn owners() -> [Owner; 6] {
    let mut scope = OWNERS;
    scope[0] = Owner {
        name: D,
        destination: "0b7ad71c41faf6eb847f0327cab4c67067e2b6ff55be1f2ab499ca6787159dcc",
        lock_inode: 94_109_798,
        index_inode: 99_291_218,
    };
    scope[1] = Owner {
        name: J,
        destination: "67fe8253649bb21cdfcde32bbdba73b67debf3c2a0cc74384f9a2ff472807c61",
        lock_inode: 100_408_634,
        index_inode: 103_224_521,
    };
    scope
}

// The original custody operator uses these adapters for its seven-controller lease implementation.
#[derive(serde::Deserialize, serde::Serialize)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
fn binding(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn bound(b: &Bound) -> Result<Value> {
    evidence::bound(&json!(b))
}
fn hex_lower(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(b.len() * 2);
    for n in b {
        write!(text, "{n:02x}").unwrap();
    }
    text
}
fn read_stable_bounded(p: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    ensure!(fs::symlink_metadata(p)?.len() <= limit, "oversized {label}");
    let content = evidence::trusted(p)?;
    ensure!(content.len() as u64 <= limit, "changed {label}");
    Ok(content)
}
#[path = "../../jetstreamer-r2/src/holding_epoch157_laned_creator_fence.rs"]
mod creator_fence;
pub(super) struct Fences {
    creators: Vec<creator_fence::Lease>,
    holding: File,
    controller: File,
}
impl Fences {
    pub(super) fn acquire() -> Result<Self> {
        let holding = lock(
            &Path::new(PRIVATE).join("r2-holding-state-dev-samjohnson-v1/transition.lock"),
            64512,
            95818311,
        )?;
        let controller = lock(
            Path::new(
                "/var/lib/jetstreamer-root-sweep-epoch157-target3-20261014-v1/controller.lock",
            ),
            2304,
            2758491,
        )?;
        Ok(Self {
            creators: creator_fence::acquire()?,
            holding,
            controller,
        })
    }
    pub(super) fn check(&self) -> Result<()> {
        for (held, path) in [
            (
                &self.holding,
                Path::new(PRIVATE).join("r2-holding-state-dev-samjohnson-v1/transition.lock"),
            ),
            (
                &self.controller,
                PathBuf::from(
                    "/var/lib/jetstreamer-root-sweep-epoch157-target3-20261014-v1/controller.lock",
                ),
            ),
        ] {
            let m = fs::symlink_metadata(&path)?;
            let fd = held.metadata()?;
            ensure!(
                path.canonicalize()? == path
                    && m.is_file()
                    && (m.dev(), m.ino(), m.nlink()) == (fd.dev(), fd.ino(), 1),
                "replaced original lock"
            );
        }
        creator_fence::check(&self.creators)
    }
}
fn fixed(path: &Path, sha: &str) -> Result<Value> {
    let r = reference(path)?;
    ensure!(
        r["sha256"] == sha,
        "changed original evidence {}",
        path.display()
    );
    Ok(r)
}
fn small_file(row: &Value) -> Result<()> {
    let p = Path::new(word(row, "path")?);
    let meta = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p && meta.is_file() && meta.len() <= 2 << 20,
        "indirect or oversized metadata"
    );
    let before = evidence::stamp(p)?;
    ensure!(
        digest(&fs::read(p)?) == word(row, "sha256")? && evidence::stamp(p)? == before,
        "preserved metadata changed"
    );
    Ok(())
}
fn absence(p: &Path) -> Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
pub(super) fn survey(owner: &Owner, stamp: &Value) -> Result<()> {
    let src = Path::new(RUNTIME)
        .join(super::DIR)
        .join("tools/CONTENT_PROOF.json");
    let proof = evidence::bound(&fixed(
        &src,
        "634fa9f66ca14cd9d19736bfa7d8be456d3086dc4f5899461f4b32436c1d3c4f",
    )?)?;
    let path = json!(index_path(owner));
    let rows = proof["inodes"].as_array().context("survey inodes")?;
    let row = rows
        .iter()
        .find(|r| r["paths"].as_array().is_some_and(|v| v.contains(&path)))
        .context("path absent from survey")?;
    let id = &row["identity"];
    ensure!(
        row["sha256"] == HASH
            && (0..5).all(|i| id[i] == stamp[i])
            && id[5].as_i64()
                == Some(
                    stamp[5].as_i64().context("mtime")? * 1_000_000_000
                        + stamp[6].as_i64().context("mtime ns")?
                )
            && id[6].as_i64()
                == Some(
                    stamp[7].as_i64().context("ctime")? * 1_000_000_000
                        + stamp[8].as_i64().context("ctime ns")?
                ),
        "index changed since the independent content survey"
    );
    Ok(())
}
pub(super) fn lineage() -> Result<Vec<Value>> {
    let dplan = fixed(
        Path::new(
            "/var/lib/jetstreamer/holding157-laned-retirement-evidence/execute-v1/execute-plan.json",
        ),
        "1f0b8a34097ea3f0d69414d38f29c0eee609174f8bc5004e3c6d0d6579e00166",
    )?;
    let dcomplete = fixed(
        &Path::new(PRIVATE)
            .join("r2-holding-state-dev-samjohnson-v1/retirements/epoch157-laned-completion.json"),
        "adab402b242a8c5fde7cf1fd9cf1ee6de42d2964135740139508bd054a715001",
    )?;
    let dp = evidence::bound(&dplan)?;
    let dc = evidence::bound(&dcomplete)?;
    let closure = evidence::bound(&dp["consumer_closure"])?;
    let inspection = evidence::bound(&dp["inspection"])?;
    let eligibility = evidence::bound(&dp["eligibility"])?;
    let park = evidence::bound(&dp["park_plan"])?;
    let dcustody = evidence::bound(&dp["custody"])?;
    ensure!(
        dp["archive_sha256"] == D_ARCHIVE
            && dc["intent"]["sha256"] == D_ARCHIVE
            && dp["custody"] == dc["intent"]["custody"]
            && dc["authenticated_custody_revalidated"] == true
            && dc["source_absent"] == true
            && dc["quarantine_absent"] == true
            && absence(Path::new(word(&dc["intent"], "source")?))?
            && closure["complete_transitive_consumer_graph_qualified"] == true
            && closure["unresolved_edges"] == json!([])
            && eligibility["closed"] == true
            && inspection["creator_fence_held_across_hash"] == true
            && inspection["controller_count"] == 7,
        "lane-d restore or closure changed"
    );
    small_file(&inspection["preserved_metadata"]["cohort"])?;
    for (path, identity) in dc["preserved"]["inputs"]
        .as_object()
        .context("retained inputs")?
    {
        let p = Path::new(path);
        let s = fs::symlink_metadata(p)?;
        ensure!(
            p.canonicalize()? == p
                && json!([
                    s.dev(),
                    s.ino(),
                    s.uid(),
                    s.gid(),
                    s.mode(),
                    s.nlink(),
                    s.len(),
                    s.blocks(),
                    s.mtime(),
                    s.mtime_nsec(),
                    s.ctime(),
                    s.ctime_nsec()
                ]) == *identity,
            "original lane-d snapshot input changed"
        );
    }
    let jr = Path::new(J_ROOT);
    let jdrain = fixed(
        &jr.join("VERIFIED_RETIREMENT_DRAIN.json"),
        "cccde7aaac57396e5ee39fb91cbb8caac435c3a7af853de34dc77a0d490fb589",
    )?;
    let drain = evidence::bound(&jdrain)?;
    let retired = evidence::bound(&drain["retired"])?;
    let rest = evidence::bound(&retired["restoration"])?;
    let jcustody = evidence::bound(&retired["custody"])?;
    ensure!(
        retired["sha256"] == J_ARCHIVE
            && rest["passed"] == true
            && rest["target"] == retired["source"]
            && rest["no_clobber"] == true
            && drain["original_and_quarantine_absent"] == true
            && drain["exact_cgroup_drained"] == true
            && drain["maintenance_inputs"] == retired["preserved"]
            && absence(Path::new(word(&retired, "source")?))?,
        "lane-j original path or custody changed"
    );
    for row in [
        &retired["preserved"]["manifest"],
        &retired["preserved"]["validation"],
        &retired["preserved"]["launch"],
    ] {
        small_file(row)?;
    }
    let bs = &retired["preserved"]["bootstrap"];
    let p = Path::new(word(bs, "path")?);
    let s = fs::symlink_metadata(p)?;
    let id = &bs["identity"];
    ensure!(
        p.canonicalize()? == p
            && s.is_file()
            && s.dev() == num(id, "device")?
            && s.ino() == num(id, "inode")?
            && s.len() == num(id, "length")?
            && s.mtime() as i128 * 1_000_000_000 + s.mtime_nsec() as i128
                == num(id, "mtime_ns")? as i128
            && s.ctime() as i128 * 1_000_000_000 + s.ctime_nsec() as i128
                == num(id, "ctime_ns")? as i128,
        "lane-j bootstrap changed"
    );
    for v in [&park, &eligibility, &dcustody, &rest, &jcustody] {
        let text = serde_json::to_string(v)?;
        ensure!(
            !text.contains(INDEX) && !text.contains("compact-indexes/157"),
            "a qualified original restore or custody reader now binds the compact index"
        );
    }
    let mut rows = vec![
        dcomplete,
        dplan,
        dp["consumer_closure"].clone(),
        dp["custody"].clone(),
        jdrain,
        retired["custody"].clone(),
        retired["restoration"].clone(),
    ];
    for (o, inode) in owners()[..2].iter().zip([99_289_976u64, 103_224_511u64]) {
        let p =
            index_path(o).with_file_name(INDEX.replace("cid-to-offset-and-size", "slot-to-cid"));
        let s = fs::symlink_metadata(&p)?;
        ensure!(
            p.canonicalize()? == p
                && s.is_file()
                && s.dev() == 64512
                && s.ino() == inode
                && s.len() == 13_438_987
                && s.nlink() == 1,
            "slot-to-CID sibling changed"
        );
        rows.push(json!({"preserved_slot_index":p,"stamp":evidence::stamp(&p)?}));
    }
    Ok(rows)
}

include!("consumer_plans.rs");

fn terms(text: &str) -> Vec<&'static str> {
    let mut found = BTreeSet::new();
    if text.contains(INDEX)
        && text
            .split(|c: char| c.is_ascii_whitespace() || "\\\"'(){}[]=,;|:".contains(c))
            .any(|arg| !arg.starts_with('/') && arg.ends_with(INDEX))
    {
        found.insert("relative CID index");
    }
    if !text.contains(FAMILY) {
        return found.into_iter().collect();
    }
    for (scope, label, selector) in [
        (D, "lane-d CID cache", "--lane=lane-d="),
        (J, "lane-j CID cache", "--lane=lane-j="),
    ] {
        let base = Path::new(PRIVATE).join(scope);
        let output = base.join("output");
        let indexes = output.join("compact-indexes");
        let epoch = indexes.join("157");
        let target = epoch.join(INDEX);
        if text.contains(&format!("{selector}{}", base.display()))
            || tokens(text)
                .map(Path::new)
                .any(|p| p == target || p == epoch || p == indexes || p == output || p == base)
        {
            found.insert(label);
        }
    }
    found.into_iter().collect()
}
const FRAGMENTS: [(&str, &str); 5] = [
    (
        CONTROLLER,
        "e0ac59c3ae96d1219a26c43202805ab1b1d4c5866bfb09a06ef2673fc295ab32",
    ),
    (
        "horizon-perf-epoch154-v158-rayon-v3@candidate10.service",
        "ae2469a35c92055b84daae8057c194f8eca2770c363841ce9e2b8e7a9f5173e4",
    ),
    (
        "horizon-perf-epoch154-v158-rayon-v3@control64.service",
        "a975d700970fecf11d9637f9981ba9151cf28b8e9ec65e26284f0d1aabb7beb8",
    ),
    (
        "horizon-epoch157-bootstrap-revalidate-20261012-v2.service",
        "aa26da82c373f4e8e6df6e22a665683478507097dd4b199569b4845fd1095666",
    ),
    (
        VALIDATOR,
        "76c6a32674cbd6580183c5a2cac25ed92e2930bace691ea301721e9198e451ef",
    ),
];
fn direct_definitions() -> Result<Vec<Value>> {
    let mut rg = Command::new("/usr/bin/rg");
    rg.args([
        "--no-config",
        "--files-with-matches",
        "--null",
        "--fixed-strings",
        "--hidden",
        "--no-ignore",
        "--text",
    ]);
    for term in [D, J, INDEX, "compact-indexes/157"] {
        rg.args(["-e", term]);
    }
    for path in [
        "/etc/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/home/sol/.config/systemd/user",
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
    ] {
        if Path::new(path).try_exists()? {
            rg.arg(path);
        }
    }
    let result = rg.output()?;
    ensure!(
        matches!(result.status.code(), Some(0 | 1)),
        "staged-definition search failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut receipts = Vec::new();
    for raw in result.stdout.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let path = Path::new(std::str::from_utf8(raw)?);
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .context("unit filename")?;
        let (_, sha) = FRAGMENTS
            .iter()
            .find(|(name, _)| *name == filename)
            .with_context(|| {
                format!("unreviewed index or creator definition {}", path.display())
            })?;
        let parent = if filename == VALIDATOR {
            "/run/systemd/transient"
        } else {
            "/etc/systemd/system"
        };
        ensure!(
            path == Path::new(parent).join(filename),
            "different fragment for {filename}"
        );
        let fragment = fixed(path, sha)?;
        let state = service(filename)?;
        receipts.push(json!({"definition":fragment,"native":state}));
    }
    ensure!(
        receipts.len() == FRAGMENTS.len(),
        "missing original owner definition"
    );
    Ok(receipts)
}
fn service(unit: &str) -> Result<Value> {
    let p = props(
        unit,
        "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job,TriggeredBy,Triggers,ControlGroup,InvocationID,UnitFileState,Restart,RemainAfterExit,Result,OnSuccess,OnFailure,DropInPaths",
    )?;
    let dropins = if unit == OTHER {
        let file = Path::new(
            "/run/systemd/system/jetstreamer-epochs155-156-target3-controller-v1-r2.service.d/99-terminal155156-growth-closure.conf",
        );
        let target = Path::new(
            "/usr/local/lib/jetstreamer/horizon-terminal155156-restart-tools-20261029-v4/99-terminal155156-growth-closure.conf",
        );
        ensure!(
            file.canonicalize()? == target,
            "different inactive controller drop-in"
        );
        fixed(
            target,
            "9b6943ff77b31e063152214a3aa57a6f73782b14434700170a0f30ca70ef2524",
        )?;
        file.to_str().unwrap()
    } else {
        ""
    };
    ensure!(
        p["Id"] == unit
            && p["MainPID"] == "0"
            && p["ControlPID"] == "0"
            && p["ControlGroup"].is_empty()
            && p["Job"].is_empty()
            && p["Triggers"].is_empty()
            && p["TriggeredBy"].is_empty()
            && p["DropInPaths"] == dropins,
        "original owner bound or changed {unit}: {p:?}"
    );
    if unit == VALIDATOR {
        ensure!(
            p["ActiveState"] == "active"
                && p["SubState"] == "exited"
                && p["RemainAfterExit"] == "yes"
                && p["InvocationID"] == "9768a460a5284f5a8ebfd422e437e8b6"
                && p["Result"] == "success"
                && p["Restart"] == "no",
            "retained validator reopened"
        );
    } else if matches!(unit, PRODUCER | J_PRODUCER) {
        ensure!(
            p["LoadState"] == "not-found"
                && p["ActiveState"] == "inactive"
                && p["SubState"] == "dead",
            "collected owner returned {unit}"
        );
    } else {
        ensure!(
            p["UnitFileState"] == "static"
                && (p["ActiveState"] == "inactive"
                    || unit == RESERVE && p["ActiveState"] == "failed"),
            "original controller or guard rearmed {unit}"
        );
    }
    Ok(json!(p))
}
fn fleet() -> Result<Value> {
    let mut latest = None;
    for item in fs::read_dir(RUNTIME)? {
        let ent = item?;
        if !ent.file_name().as_encoded_bytes().starts_with(b"root") {
            continue;
        }
        let f = ent.path().join("ROOT_COMPLETE_OPERATIONAL_FLEET.json");
        if !f.try_exists()? {
            continue;
        }
        let stamp = f.metadata()?.modified()?;
        if latest.as_ref().is_none_or(|(t, _)| stamp > *t) {
            latest = Some((stamp, f));
        }
    }
    let p = latest.context("missing current fleet")?.1;
    let raw = evidence::trusted(&p)?;
    let d: Value = serde_json::from_slice(&raw)?;
    let rows = d["epochs"].as_array().context("fleet epochs")?;
    let selected: Vec<_> = rows.iter().filter(|e| e["epoch"] == 157).collect();
    ensure!(
        d["owner"] == "/root"
            && selected.len() == 1
            && selected[0]["no_live_producer_claimed"] == true
            && selected[0]["state"] == "blocked-qualification"
            && terms(std::str::from_utf8(&raw)?).is_empty(),
        "fleet needs old epoch 157 inputs"
    );
    Ok(json!({"path":p,"sha256":digest(&raw),"epoch":selected[0]}))
}
fn scheduled_files(cache: &mut PlanCache) -> Result<usize> {
    let mut paths = Vec::new();
    for dir in [
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
    ] {
        if Path::new(dir).is_dir() {
            for entry in fs::read_dir(dir)? {
                let path = entry?.path();
                if path.is_file() {
                    paths.push(path);
                }
            }
        }
    }
    if Path::new("/etc/crontab").is_file() {
        paths.push("/etc/crontab".into());
    }
    for path in &paths {
        let s = fs::metadata(path)?;
        ensure!(
            s.is_file() && s.len() < 2 << 20,
            "unresolved scheduler file {}",
            path.display()
        );
        let contents = fs::read_to_string(path)?;
        let live = contents
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        ensure!(
            terms(&live).is_empty() && artifacts(&live, cache)?.is_empty(),
            "staged cron index reader {}",
            path.display()
        );
    }
    Ok(paths.len())
}
pub(super) fn staged() -> Result<Value> {
    let definitions = direct_definitions()?;
    let old = [
        service(PRODUCER)?,
        service(J_PRODUCER)?,
        service(OTHER)?,
        service(RESERVE)?,
    ];
    let timer = props(
        TIMER,
        "Id,ActiveState,SubState,Job,Triggers,TriggeredBy,UnitFileState",
    )?;
    ensure!(
        timer["ActiveState"] == "inactive"
            && timer["Job"].is_empty()
            && timer["Triggers"] == RESERVE
            && timer["UnitFileState"] == "static"
            && timer["TriggeredBy"].is_empty(),
        "retired guard timer is armed"
    );
    let current = fleet()?;
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
    let jobs = command(
        "/usr/bin/systemctl",
        &["list-jobs", "--plain", "--no-pager", "--no-legend"],
    )?;
    let mut potential = BTreeSet::new();
    for line in listing.lines() {
        let mut words = line.split_whitespace();
        let unit = words.next().context("missing unit")?;
        let active = words.nth(1).context("missing load state")?;
        if !matches!(active, "inactive" | "failed") {
            potential.insert(unit);
        }
    }
    for line in jobs.lines() {
        if let Some(u) = line.split_whitespace().nth(1) {
            if u.rsplit_once('.')
                .is_some_and(|(_, t)| matches!(t, "service" | "timer" | "path" | "socket"))
            {
                potential.insert(u);
            }
        }
    }
    let potential: Vec<_> = potential.into_iter().collect();
    let mut cache = PlanCache::default();
    let cron = scheduled_files(&mut cache)?;
    let mut closed = 0;
    let mut examined = 0;
    let mut gone = 0;
    let mut unresolved = Vec::new();
    for batch in potential.chunks(128) {
        for plan in native_plans(batch, true)? {
            if matches!(plan.state.as_str(), "inactive" | "failed" | "gone") {
                gone += 1;
                continue;
            }
            if plan.closed.is_some() {
                closed += 1;
                continue;
            }
            let direct = terms(&plan.projection);
            let nested = artifacts(&plan.projection, &mut cache)?;
            if !direct.is_empty() || !nested.is_empty() {
                unresolved.push(json!({"unit":plan.unit,"state":plan.state,"sub":plan.sub,"direct":direct,"plans":nested.iter().take(20).collect::<Vec<_>>(),"plan_count":nested.len()}));
            }
            examined += 1;
        }
    }
    ensure!(
        examined > 0 && closed + gone + examined == potential.len(),
        "incomplete activation inventory"
    );
    if !unresolved.is_empty() {
        let iid = std::env::var("INVOCATION_ID")?;
        ensure!(
            iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
            "missing invocation"
        );
        let diagnostic = json!({"fleet":current,"unresolved":unresolved,"units":potential.len(),"closed":closed,"material":cache.examined});
        ensure!(
            serde_json::to_vec(&diagnostic)?.len() < 2 << 20,
            "diagnostic size bound"
        );
        let report = evidence::receipt(
            &Path::new(RUNTIME)
                .join(DIR)
                .join(format!("STAGED_REVIEW_{iid}.json")),
            &diagnostic,
        )?;
        anyhow::bail!("unresolved staged reader(s), see {report}");
    }
    Ok(
        json!({"fleet":current,"definitions":definitions,"original_services":old,"original_timer":timer,"potential_units":potential.len(),"conclusively_closed_activations":closed,"inactive_or_collected":gone,"executable_activations":examined,"scheduled_files":cron,"resolved_plans":cache.examined}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lane_scope_keeps_the_four_hardlinks_and_two_slot_siblings() {
        let scope = owners();
        assert_eq!(
            [scope[0].index_inode, scope[1].index_inode],
            [99_291_218, 103_224_521]
        );
        assert!(scope[2..].iter().all(|o| o.index_inode == RETAINED_INODE));
        for o in &scope[..2] {
            let index = index_path(o);
            assert!(!terms(index.to_str().unwrap()).is_empty());
            assert!(!terms(index.parent().unwrap().to_str().unwrap()).is_empty());
            assert!(terms(index.with_file_name("slot-to-cid.index").to_str().unwrap()).is_empty());
            assert!(
                terms(
                    owner_path(o)
                        .join("private/run/archives/epoch-157.jet")
                        .to_str()
                        .unwrap()
                )
                .is_empty()
            );
        }
        assert!(terms(index_path(&scope[2]).to_str().unwrap()).is_empty());
        assert!(!terms(INDEX).is_empty());
    }
    #[test]
    fn consumed_calendar_requires_one_fixed_past_date_and_a_closed_target() {
        let test = r#"
u=dict(Id="old.timer",UnitFileState="static",Transient=False,ActiveState="active",SubState="elapsed",Job=[0],TriggeredBy=[],Triggers=["old.service"],OnSuccess=[],OnFailure=[])
t=dict(Unit="old.service",RemainAfterElapse=True,Persistent=False,OnClockChange=False,OnTimezoneChange=False,LastTriggerUSec=1792176600219944,LastTriggerUSecMonotonic=100,NextElapseUSecRealtime=2**64-1,NextElapseUSecMonotonic=2**64-1,TimersMonotonic=[],TimersCalendar=[("OnCalendar","2026-10-16 18:50:00 UTC",0)])
up=dict(UnitFileState="static",ActiveState="inactive",SubState="dead",Job=[0],TriggeredBy=["old.timer"])
sp=dict(MainPID=0,ControlPID=0,ControlGroup="",Restart="no",Result="success",ExecMainStatus=0,ExecMainExitTimestampMonotonic=101,ExecMainExitTimestamp=1792176601219944)
def fetch(n,k):return up,sp
assert consumed_static_calendar(u,t,fetch)
assert not consumed_static_calendar(u,dict(t,OnClockChange=True),fetch)
assert not consumed_static_calendar(u,dict(t,NextElapseUSecRealtime=10),fetch)
assert not consumed_static_calendar(u,dict(t,TimersCalendar=[("OnCalendar","daily",0)]),fetch)
assert not consumed_static_calendar(u,t,lambda n,k:(up,dict(sp,MainPID=17)))
"#;
        command(
            "/usr/bin/python3",
            &["-IB", "-c", &format!("{INERT_ACTIVATIONS}\n{test}")],
        )
        .unwrap();
    }
    #[test]
    fn staged_lane_controller_and_independent_checkpoint_are_distinguishable() {
        let root = Path::new(PRIVATE).join(J);
        assert!(!terms(&format!("--lane=lane-j={}", root.display())).is_empty());
        assert!(
            terms(&format!(
                "--bootstrap={}/private/snapshot.tar.zst",
                root.display()
            ))
            .is_empty()
        );
    }
}
