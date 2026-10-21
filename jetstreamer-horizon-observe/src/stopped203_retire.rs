//! One-case disk scratch retirement; all retained archives/inputs stay intact.
//! Separate check/execute roles, immutable ledger and durable resumable intent.
use {
    crate::{
        dev_cache_check, process_references,
        ram_artifact_retention::{self as retained, Bound},
        stopped203_check as check, stopped203_tree as tree,
    },
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    std::{
        collections::BTreeSet,
        env,
        fs::{self, File, OpenOptions},
        io::{BufReader, Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
        path::{Path, PathBuf},
    },
};
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/root-prefix-resource-203-v1";
const OLD_CHECK: &str =
    "/var/lib/jetstreamer/horizon-203-stopped-scratch-check-actual-v1/check.json";
const OLD_SHA: &str = "299580e8ce6a31899d5811afd22b6f5f581dbca31c7e482a9373d1fea237c800";
const CHECKER: &str = "/var/lib/jetstreamer/horizon-203-stopped-scratch-checker-c6f3089-v1/jetstreamer-epoch203-stopped-scratch-check";
const CHECKER_SHA: &str = "cb886043c96f84a4cdf2b60152f19cfd1a9faac7c1ffad3888eb42a36ffaad1f";
const CHECK_PLAN: &str =
    "/var/lib/jetstreamer/horizon-203-stopped-scratch-checker-c6f3089-v1/check-plan.json";
const CHECK_PLAN_SHA: &str = "f51bfc07b8c91378b33a1bd77e188bbafc8ee8e157560b9f1c530ca8864a910a";
const LEDGER_LIMIT: u64 = 1 << 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    original_check: Bound,
    checker: Bound,
    check_plan: Bound,
    check_unit: String,
    execute_unit: String,
    receipt_directory: PathBuf,
    authority: Authority,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    local_scratch_retirement_authorized: bool,
    preserve_partial_archive_and_inputs: bool,
    archive_deletion_authorized: bool,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}
fn unit_name(s: &str, prefix: &str) -> bool {
    s.starts_with(prefix)
        && s.ends_with(".service")
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-epoch203-stopped-scratch-retire-plan-v1"
            && p.original_check.path == Path::new(OLD_CHECK)
            && p.original_check.sha256 == OLD_SHA
            && p.checker.path == Path::new(CHECKER)
            && p.checker.sha256 == CHECKER_SHA
            && p.check_plan.path == Path::new(CHECK_PLAN)
            && p.check_plan.sha256 == CHECK_PLAN_SHA,
        "not the independently qualified stopped203case"
    );
    ensure!(
        unit_name(&p.check_unit, "horizon-203-stopped-scratch-retire-check-")
            && unit_name(&p.execute_unit, "horizon-203-stopped-scratch-retire-exec-")
            && p.check_unit != p.execute_unit,
        "unsafe lifecycle owner roles"
    );
    ensure!(
        p.receipt_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.receipt_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-203-stopped-scratch-retire-")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))),
        "retirement receipts outside exact private namespace"
    );
    let a = &p.authority;
    ensure!(
        a.local_scratch_retirement_authorized
            && a.preserve_partial_archive_and_inputs
            && !a.archive_deletion_authorized
            && !a.replay_launch_authorized
            && !a.publication_authorized
            && !a.remote_mutations
            && !a.r2_mutations,
        "wrong retirement policy authority"
    );
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path && m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "unsafe receipt directory"
    );
    Ok(())
}
fn absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
        Ok(_) => Ok(false),
    }
}
fn persist<T: Serialize>(path: &Path, value: &T) -> Result<String> {
    let parent = path.parent().context("receipt parent missing")?;
    private_dir(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer(&mut temp, value)?;
    temp.write_all(b"\n")?;
    ensure!(
        temp.as_file().metadata()?.len() <= LEDGER_LIMIT,
        "receipt exceeds bound"
    );
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("occupied receipt: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(retained::hash_file(path, LEDGER_LIMIT)?.0)
}
fn json_file(path: &Path) -> Result<(Value, String)> {
    let (sha, _) = retained::hash_file(path, 1 << 20)?;
    let v = retained::bound_json(&Bound {
        path: path.into(),
        sha256: sha.clone(),
    })?;
    Ok((v, sha))
}

fn original(p: &Plan) -> Result<Value> {
    let (sha, m) = retained::hash_file(&p.checker.path, 32 << 20)?;
    ensure!(
        sha == CHECKER_SHA && m.uid() == 0 && m.mode() & 0o222 == 0,
        "original checker replaced"
    );
    let old = retained::bound_json(&p.original_check)?;
    ensure!(
        old["schema"] == "jetstreamer-epoch203-stopped-scratch-check-v1"
            && old["self_sha256"] == CHECKER_SHA
            && old["plan"]["path"].as_str() == Some(CHECK_PLAN)
            && old["plan"]["sha256"] == CHECK_PLAN_SHA
            && old["scratch"]["path"] == format!("{ROOT}/scratch")
            && old["scratch"]["root"]["device"] == 66305
            && old["scratch"]["root"]["inode"] == 22832411
            && old["scratch"]["files"] == 695933
            && old["scratch_deletion_authorized"] == false,
        "original read-only proof differs"
    );
    let cp = retained::bound_json(&p.check_plan)?;
    for key in ["incident", "source_review", "build_receipt"] {
        let b: Bound = serde_json::from_value(cp[key].clone())?;
        retained::bound_json(&b)?;
    }
    Ok(old)
}
fn role_prefix(program: &Path, pb: &Bound, self_sha: &str, mode: &str) -> String {
    format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {} {} ; ignore_errors=no ;",
        program.display(),
        program.display(),
        pb.path.display(),
        pb.sha256,
        self_sha,
        mode
    )
}
fn validate_role(
    v: &Value,
    name: &str,
    prefix: &str,
    current: bool,
    pid: u32,
    inv: &str,
) -> Result<()> {
    for (k, w) in [
        ("Id", name),
        ("Names", name),
        ("LoadState", "loaded"),
        ("Type", "oneshot"),
        ("User", "root"),
        ("Group", "root"),
        ("Restart", "no"),
        ("NRestarts", "0"),
        ("Triggers", ""),
        ("TriggeredBy", ""),
        ("OnSuccess", ""),
        ("OnFailure", ""),
        ("DropInPaths", ""),
    ] {
        ensure!(v[k] == w, "lifecycle identity differs: {k}");
    }
    let command = v["ExecStart"]
        .as_str()
        .context("lifecycle command missing")?;
    ensure!(
        command.starts_with(prefix)
            && command.ends_with(" }")
            && command.matches("{ path=").count() == 1,
        "not the exact scoped retirement executable/plan/phase"
    );
    ensure!(
        v["FragmentPath"] == format!("/etc/systemd/system/{name}"),
        "lifecycle unit is not the sealed installed fragment"
    );
    if current {
        ensure!(
            v["ActiveState"] == "activating"
                && v["SubState"] == "start"
                && v["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok()) == Some(pid)
                && v["InvocationID"] == inv,
            "not the current owned oneshot invocation"
        );
    } else {
        ensure!(
            v["ActiveState"] == "inactive"
                && v["SubState"] == "dead"
                && v["MainPID"] == "0"
                && v["Result"] == "success"
                && v["ExecMainStatus"] == "0",
            "prior check unit not cleanly terminal"
        );
    }
    Ok(())
}
fn owners(
    p: &Plan,
    pb: &Bound,
    program: &Path,
    self_sha: &str,
    execute: bool,
) -> Result<(Value, BTreeSet<PathBuf>)> {
    let inv = env::var("INVOCATION_ID").context("not a persistent owned systemd invocation")?;
    ensure!(
        inv.len() == 32
            && inv
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid invocation"
    );
    let mut allowed = BTreeSet::new();
    let mut rows = Vec::new();
    let jobs = std::process::Command::new("/usr/bin/systemctl")
        .args(["list-jobs", "--no-legend", "--plain"])
        .output()?;
    ensure!(
        jobs.status.success() && jobs.stdout.len() <= 1 << 20,
        "lifecycle jobs census failed"
    );
    let other = if execute {
        &p.check_unit
    } else {
        &p.execute_unit
    };
    ensure!(
        !std::str::from_utf8(&jobs.stdout)?
            .lines()
            .any(|l| l.split_whitespace().any(|s| s == other)),
        "another lifecycle phase has a queued job"
    );
    for (name, mode, current) in [
        (&p.check_unit, "--check-only", !execute),
        (&p.execute_unit, "--execute", execute),
    ] {
        let values = retained::properties(
            name,
            "Id,Names,LoadState,Type,User,Group,Restart,NRestarts,Triggers,TriggeredBy,OnSuccess,OnFailure,DropInPaths,ExecStart,FragmentPath,ActiveState,SubState,MainPID,InvocationID,Result,ExecMainStatus",
        )?;
        let v = serde_json::to_value(values)?;
        if !current && !execute {
            ensure!(
                v["LoadState"] == "not-found"
                    && v["ActiveState"] == "inactive"
                    && v["MainPID"] == "0",
                "execute unit must remain uninstalled during check-only"
            );
        } else {
            validate_role(
                &v,
                name,
                &role_prefix(program, pb, self_sha, mode),
                current,
                std::process::id(),
                &inv,
            )?;
            let f = PathBuf::from(v["FragmentPath"].as_str().context("missing fragment")?);
            let m = fs::symlink_metadata(&f)?;
            ensure!(
                f.canonicalize()? == f
                    && m.uid() == 0
                    && m.is_file()
                    && m.nlink() == 1
                    && m.mode() & 0o222 == 0,
                "lifecycle fragment not root-owned immutable"
            );
            allowed.insert(f.clone());
            rows.push(json!({"unit":v,"fragment":check::artifact(&f,0,None,1<<20)?}));
        }
    }
    Ok((json!({"invocation_id":inv,"roles":rows}), allowed))
}
fn gates(
    p: &Plan,
    pb: &Bound,
    program: &Path,
    self_sha: &str,
    execute: bool,
    old: &Value,
) -> Result<Value> {
    let scratch = Path::new(ROOT).join("scratch");
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let point = Path::new(
            line.split_whitespace()
                .nth(4)
                .context("invalid mountinfo")?,
        );
        ensure!(
            !point.starts_with(&scratch) || point == scratch,
            "nested mount beneath exact scratch"
        );
    }
    let owner = check::terminal()?;
    ensure!(
        owner == old["owner"],
        "original failed owner or stopped guard changed"
    );
    let (roles, mut allowed) = owners(p, pb, program, self_sha, execute)?;
    let fragment =
        PathBuf::from("/run/systemd/transient/horizon-qualify-203-root-prefix-resource-v1.service");
    ensure!(
        check::artifact(&fragment, 0, None, 1 << 20)? == old["terminal_fragment"],
        "original terminal fragment changed"
    );
    allowed.insert(fragment);
    let mut missing = Vec::new();
    let staged = dev_cache_check::staged_references_exact(
        &[
            Path::new("/etc/systemd/system"),
            Path::new("/run/systemd/transient"),
            Path::new("/run/systemd/system"),
            Path::new("/usr/lib/systemd/system"),
            Path::new("/home/ubuntu/.config/systemd/user"),
        ],
        Path::new(ROOT),
        &mut missing,
        &allowed,
    )?;
    let refs = process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        staged.is_empty() && refs.references.is_empty(),
        "live/staged stopped-run consumers remain"
    );
    Ok(
        json!({"owner":owner,"lifecycle":roles,"allowed_fragments":allowed,"process_scan":refs,
        "staged_references":staged,"missing_aliases":missing}),
    )
}

fn stable_gates(a: &Value, b: &Value) -> bool {
    // A complete scan may see unrelated processes start/exit. Its count is
    // evidence, not an identity gate; both scans already reject every match.
    [a, b].iter().all(|v| {
        v["process_scan"]["references"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && v["staged_references"].as_array().is_some_and(Vec::is_empty)
    }) && ["owner", "lifecycle", "allowed_fragments"]
        .iter()
        .all(|k| a[k] == b[k])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        Plan {
            schema: "jetstreamer-epoch203-stopped-scratch-retire-plan-v1".into(),
            original_check: Bound {
                path: OLD_CHECK.into(),
                sha256: OLD_SHA.into(),
            },
            checker: Bound {
                path: CHECKER.into(),
                sha256: CHECKER_SHA.into(),
            },
            check_plan: Bound {
                path: CHECK_PLAN.into(),
                sha256: CHECK_PLAN_SHA.into(),
            },
            check_unit: "horizon-203-stopped-scratch-retire-check-test.service".into(),
            execute_unit: "horizon-203-stopped-scratch-retire-exec-test.service".into(),
            receipt_directory: "/var/lib/jetstreamer/horizon-203-stopped-scratch-retire-test"
                .into(),
            authority: Authority {
                local_scratch_retirement_authorized: true,
                preserve_partial_archive_and_inputs: true,
                archive_deletion_authorized: false,
                replay_launch_authorized: false,
                publication_authorized: false,
                remote_mutations: false,
                r2_mutations: false,
            },
        }
    }
    #[test]
    fn only_exact_prior_real_check_and_separate_nonpublishing_roles_are_admissible() {
        validate_plan(&plan()).unwrap();
        let mut p = plan();
        p.original_check.sha256 = "a".repeat(64);
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.checker.path = "/foreign/bin".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.receipt_directory = "/home/ubuntu/.jetstreamer-private".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.authority.archive_deletion_authorized = true;
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.authority.preserve_partial_archive_and_inputs = false;
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.execute_unit = p.check_unit.clone();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn lifecycle_fragment_exclusion_requires_exact_owned_oneshot_command_and_phase() {
        let name = "horizon-203-stopped-scratch-retire-check-test.service";
        let prefix = "{ path=/sealed/bin ; argv[]=/sealed/bin /sealed/plan --check-only ; ignore_errors=no ;";
        let mut v = json!({"Id":name,"Names":name,"LoadState":"loaded","Type":"oneshot","User":"root","Group":"root",
            "Restart":"no","NRestarts":"0","Triggers":"","TriggeredBy":"","OnSuccess":"","OnFailure":"",
            "DropInPaths":"","ExecStart":format!("{prefix} start_time=[n/a] ; }}"),
            "FragmentPath":format!("/etc/systemd/system/{name}"),"ActiveState":"activating","SubState":"start",
            "MainPID":"123","InvocationID":"a".repeat(32)});
        validate_role(&v, name, prefix, true, 123, &"a".repeat(32)).unwrap();
        for (k, x) in [
            ("MainPID", json!("124")),
            ("InvocationID", json!("foreign")),
            ("Restart", json!("on-failure")),
            ("TriggeredBy", json!("timer")),
            ("ExecStart", json!("foreign --execute")),
            ("ActiveState", json!("active")),
        ] {
            let mut bad = v.clone();
            bad[k] = x;
            assert!(validate_role(&bad, name, prefix, true, 123, &"a".repeat(32)).is_err());
        }
        v["ActiveState"] = json!("inactive");
        v["SubState"] = json!("dead");
        v["MainPID"] = json!("0");
        v["Result"] = json!("success");
        v["ExecMainStatus"] = json!("0");
        validate_role(&v, name, prefix, false, 123, "").unwrap();
        v["ExecMainStatus"] = json!("1");
        assert!(validate_role(&v, name, prefix, false, 123, "").is_err());
    }
    #[test]
    fn unrelated_process_count_is_not_identity_but_references_and_owners_are() {
        let a = json!({"owner":"fixed","lifecycle":"fixed","allowed_fragments":[],
            "process_scan":{"inspected_processes":100,"references":[]},"staged_references":[]});
        let mut b = a.clone();
        b["process_scan"]["inspected_processes"] = json!(101);
        assert!(stable_gates(&a, &b));
        b["owner"] = json!("replacement");
        assert!(!stable_gates(&a, &b));
        b = a.clone();
        b["process_scan"]["references"] = json!(["consumer"]);
        assert!(!stable_gates(&a, &b));
    }
    #[test]
    fn interrupted_intent_cannot_change_any_scope_or_authority_binding() {
        let mut v = json!({"schema":"jetstreamer-epoch203-disk-scratch-intent-v1","plan_sha256":"p","self_sha256":"s",
            "check_sha256":"c","ledger_sha256":"l","scratch":format!("{ROOT}/scratch"),"device":66305,"inode":22832411,
            "preserve_partial_archive_and_inputs":true});
        for f in [
            "archive_deletion_authorized",
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            v[f] = json!(false);
        }
        validate_intent(&v, "p", "s", "c", &json!("l")).unwrap();
        for (k, x) in [
            ("scratch", json!(ROOT)),
            ("inode", json!(1)),
            ("check_sha256", json!("other")),
            ("archive_deletion_authorized", json!(true)),
            ("preserve_partial_archive_and_inputs", json!(false)),
        ] {
            let mut bad = v.clone();
            bad[k] = x;
            assert!(validate_intent(&bad, "p", "s", "c", &json!("l")).is_err());
        }
    }
    #[test]
    fn check_only_receipt_is_not_a_deletion_or_publication_grant() {
        let mut v = json!({"schema":"jetstreamer-epoch203-disk-scratch-check-v1","plan_sha256":"p","self_sha256":"s",
            "original_check_sha256":OLD_SHA,"entries":695948,"preserved_artifacts":[]});
        for f in [
            "scratch_deletion_authorized",
            "archive_deletion_authorized",
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            v[f] = json!(false);
        }
        validate_checked(&v, "p", "s", &[]).unwrap();
        v["scratch_deletion_authorized"] = json!(true);
        assert!(validate_checked(&v, "p", "s", &[]).is_err());
    }
}
fn artifacts(old: &Value, flush: bool) -> Result<Vec<Value>> {
    let mut rows = Vec::new();
    for expected in old["artifacts"]
        .as_array()
        .context("retained artifact census missing")?
    {
        let path = Path::new(expected["path"].as_str().context("retained path missing")?);
        let uid: u32 = expected["identity"]["uid"]
            .as_u64()
            .context("owner missing")?
            .try_into()?;
        let sha = expected["sha256"].as_str().context("digest missing")?;
        let v = check::artifact(path, uid, Some(sha), 128 << 30)?;
        ensure!(v == *expected, "retained archive/input identity changed");
        if flush {
            File::open(path)?.sync_all()?;
            File::open(path.parent().context("input parent")?)?.sync_all()?;
        }
        rows.push(v);
    }
    for (path, sha) in [
        (
            "/var/lib/jetstreamer/horizon-203-root-prefix-resource-v1/resource-plan.json",
            "90c64b0a516ca23d7e93c6906b48c4182833128d68426d07f8addf880622d99d",
        ),
        (
            "/var/lib/jetstreamer/horizon-203-bounded-resource-store8-a72fd72-v1/epoch-hashes-203-prefix.txt",
            "9704e222d97efdd66b636a11c2f03223f2dff028a8d09830117836ae0df312c4",
        ),
    ] {
        rows.push(check::artifact(Path::new(path), 0, Some(sha), 1 << 20)?);
    }
    Ok(rows)
}
#[derive(Serialize)]
struct LedgerWrite<'a> {
    schema: &'static str,
    plan_sha256: &'a str,
    self_sha256: &'a str,
    entries: &'a tree::Ledger,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerRead {
    schema: String,
    plan_sha256: String,
    self_sha256: String,
    entries: tree::Ledger,
}
fn ledger(path: &Path, expected_sha: &str, plan_sha: &str, self_sha: &str) -> Result<tree::Ledger> {
    let (sha, m) = retained::hash_file(path, LEDGER_LIMIT)?;
    ensure!(
        sha == expected_sha && m.uid() == 0 && m.mode() & 0o222 == 0,
        "immutable ledger changed"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        check::file_identity(&f.metadata()?) == check::file_identity(&m),
        "ledger inode changed"
    );
    let mut de =
        serde_json::Deserializer::from_reader(BufReader::new((&mut f).take(LEDGER_LIMIT + 1)));
    let v = LedgerRead::deserialize(&mut de)?;
    de.end()?;
    ensure!(
        v.schema == "jetstreamer-epoch203-disk-scratch-ledger-v1"
            && v.plan_sha256 == plan_sha
            && v.self_sha256 == self_sha
            && check::file_identity(&f.metadata()?) == check::file_identity(&m)
            && check::file_identity(&fs::symlink_metadata(path)?) == check::file_identity(&m),
        "ledger binding changed"
    );
    Ok(v.entries)
}
fn free(path: &Path) -> Result<u64> {
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), v.as_mut_ptr()) } == 0,
        "free-space capture failed"
    );
    let v = unsafe { v.assume_init() };
    v.f_bavail
        .checked_mul(v.f_frsize)
        .context("free bytes overflow")
}

fn validate_checked(v: &Value, plan_sha: &str, self_sha: &str, preserved: &[Value]) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-epoch203-disk-scratch-check-v1"
            && v["plan_sha256"] == plan_sha
            && v["self_sha256"] == self_sha
            && v["original_check_sha256"] == OLD_SHA
            && v["entries"] == 695948
            && v["preserved_artifacts"] == json!(preserved),
        "execution lacks exact check/preservation evidence"
    );
    for field in [
        "scratch_deletion_authorized",
        "archive_deletion_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[field] == false,
            "check grants unrelated authority: {field}"
        );
    }
    Ok(())
}
fn validate_intent(
    v: &Value,
    plan_sha: &str,
    self_sha: &str,
    check_sha: &str,
    ledger_sha: &Value,
) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-epoch203-disk-scratch-intent-v1"
            && v["plan_sha256"] == plan_sha
            && v["self_sha256"] == self_sha
            && v["check_sha256"] == check_sha
            && v["ledger_sha256"] == *ledger_sha
            && v["scratch"] == format!("{ROOT}/scratch")
            && v["device"] == 66305
            && v["inode"] == 22832411
            && v["preserve_partial_archive_and_inputs"] == true,
        "intent belongs to another scope/check"
    );
    for f in [
        "archive_deletion_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[f] == false, "intent grants unrelated authority: {f}");
    }
    Ok(())
}
pub fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 7
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && matches!(a[6].as_str(), "--check-only" | "--execute"),
        "explicit check-only or execute required"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "retirement requires root");
    let execute = a[6] == "--execute";
    let program = fs::read_link("/proc/self/exe")?;
    let (self_sha, m) = retained::hash_file(&program, 32 << 20)?;
    ensure!(
        self_sha == a[5] && m.uid() == 0 && m.mode() & 0o222 == 0,
        "retirement executable not sealed"
    );
    let pb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(retained::bound_json(&pb)?)?;
    validate_plan(&p)?;
    private_dir(&p.receipt_directory)?;
    let old = original(&p)?;
    let check_path = p.receipt_directory.join("check.json");
    let ledger_path = p.receipt_directory.join("ledger.json");
    let intent_path = p.receipt_directory.join("intent.json");
    let complete_path = p.receipt_directory.join("completion.json");
    ensure!(
        absent(&complete_path)?,
        "completed retirement must not run again"
    );
    let scratch = Path::new(ROOT).join("scratch");
    let root = tree::open_root(&scratch, 66305, 22832411)?;
    let before_gate = gates(&p, &pb, &program, &self_sha, execute, &old)?;
    let preserved = artifacts(&old, execute)?;
    if !execute {
        ensure!(
            absent(&check_path)? && absent(&ledger_path)? && absent(&intent_path)?,
            "check requires fresh receipt paths"
        );
        ensure!(
            check::tree(&scratch)? == old["scratch"],
            "scratch changed since original read-only qualification"
        );
        let entries = tree::capture(&root, 66305, 1000, 1000)?;
        ensure!(
            entries.len() == 695948,
            "qualified scratch entry census differs"
        );
        let after_gate = gates(&p, &pb, &program, &self_sha, false, &old)?;
        ensure!(
            stable_gates(&after_gate, &before_gate),
            "consumer/owner state changed during check"
        );
        let digest = persist(
            &ledger_path,
            &LedgerWrite {
                schema: "jetstreamer-epoch203-disk-scratch-ledger-v1",
                plan_sha256: &pb.sha256,
                self_sha256: &self_sha,
                entries: &entries,
            },
        )?;
        persist(
            &check_path,
            &json!({"schema":"jetstreamer-epoch203-disk-scratch-check-v1","plan_sha256":pb.sha256,
            "self_sha256":self_sha,"original_check_sha256":OLD_SHA,"ledger_sha256":digest,"entries":entries.len(),
            "gates":after_gate,"preserved_artifacts":preserved,"scratch_deletion_authorized":false,
            "archive_deletion_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
        println!("{}", check_path.display());
        return Ok(());
    }
    let (checked, check_sha) = json_file(&check_path)?;
    validate_checked(&checked, &pb.sha256, &self_sha, &preserved)?;
    let expected = ledger(
        &ledger_path,
        checked["ledger_sha256"]
            .as_str()
            .context("ledger digest missing")?,
        &pb.sha256,
        &self_sha,
    )?;
    let resuming = !absent(&intent_path)?;
    let current = tree::capture(&root, 66305, 1000, 1000)?;
    tree::validate_remaining(&expected, &current, resuming)?;
    let before_free = free(&scratch)?;
    if resuming {
        let (intent, _) = json_file(&intent_path)?;
        validate_intent(
            &intent,
            &pb.sha256,
            &self_sha,
            &check_sha,
            &checked["ledger_sha256"],
        )?;
    } else {
        persist(
            &intent_path,
            &json!({"schema":"jetstreamer-epoch203-disk-scratch-intent-v1","plan_sha256":pb.sha256,
            "self_sha256":self_sha,"check_sha256":check_sha,"ledger_sha256":checked["ledger_sha256"],
            "scratch":scratch,"device":66305,"inode":22832411,"available_bytes_before":before_free,
            "preserve_partial_archive_and_inputs":true,"archive_deletion_authorized":false,"replay_launch_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
    }
    let final_gate = gates(&p, &pb, &program, &self_sha, true, &old)?;
    ensure!(
        stable_gates(&final_gate, &before_gate),
        "owner/consumer state changed before deletion"
    );
    // Descriptor-relative unlink is reachable only after the fsynced intent and
    // revalidated exact original ledger. No path/root/epoch comes from argv.
    let removed = tree::remove_contents(&root, &expected, 66305, 1000, 1000)?;
    let after_artifacts = artifacts(&old, true)?;
    ensure!(
        after_artifacts == preserved,
        "retained partial or input changed during retirement"
    );
    let after_gate = gates(&p, &pb, &program, &self_sha, true, &old)?;
    ensure!(
        stable_gates(&after_gate, &final_gate),
        "owner/consumer state changed during retirement"
    );
    let remaining = tree::capture(&root, 66305, 1000, 1000)?;
    ensure!(remaining.len() == 1, "original scratch root not empty");
    persist(
        &complete_path,
        &json!({"schema":"jetstreamer-epoch203-disk-scratch-completion-v1",
        "plan_sha256":pb.sha256,"self_sha256":self_sha,"check_sha256":check_sha,
        "ledger_sha256":checked["ledger_sha256"],"intent_sha256":retained::hash_file(&intent_path,1<<20)?.0,
        "resumed":resuming,"removed_entries_this_invocation":removed,"scratch_empty":true,
        "original_root_preserved":true,"partial_archive_and_inputs_preserved":true,
        "preserved_artifacts":after_artifacts,"available_bytes_before":before_free,"available_bytes_after":free(&scratch)?,
        "archive_deletion_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false,"repair_closed":false}),
    )?;
    println!("{}", complete_path.display());
    Ok(())
}
