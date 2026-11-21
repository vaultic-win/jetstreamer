//! Enumerate running, queued, and armed service entry points from both managers.
//! The operator binds the reviewed commands and actual executable/plan inputs.
//! Inert timer units without a next firing are still traversed by the file census.
use crate::{SHA, SOURCE, s, sha};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
};

fn ctl(user: bool, args: &[String]) -> Result<String> {
    let mut c = if user {
        let mut c = Command::new("/usr/sbin/runuser");
        c.args([
            "-u",
            "sol",
            "--",
            "/usr/bin/env",
            "XDG_RUNTIME_DIR=/run/user/1001",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus",
            "/usr/bin/systemctl",
            "--user",
        ]);
        c
    } else {
        Command::new("/usr/bin/systemctl")
    };
    let r = c
        .env_remove("SYSTEMD_HOST")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env("LC_ALL", "C")
        .arg("--no-pager")
        .arg("--no-legend")
        .args(args)
        .output()?;
    ensure!(
        r.status.success() && r.stdout.len() < 16 << 20,
        "manager command failed or oversized: {:?}",
        args.first()
    );
    Ok(String::from_utf8(r.stdout)?)
}
fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}
fn rows(user: bool, args: &[&str]) -> Result<Vec<Value>> {
    let mut a = strings(args);
    a.push("--output=json".into());
    Ok(serde_json::from_str(&ctl(user, &a)?)?)
}
fn scheduled(user: bool) -> Result<BTreeSet<String>> {
    let mut targets = BTreeSet::new();
    for r in rows(
        user,
        &[
            "list-units",
            "--type=service",
            "--state=running,activating,reloading,deactivating",
        ],
    )? {
        targets.insert(s(&r, "unit")?.into());
    }
    for r in rows(user, &["list-timers", "--all"])? {
        if r["next"].as_u64().is_some_and(|n| n > 0 && n != u64::MAX) {
            targets.insert(s(&r, "activates")?.into());
        }
    }
    for command in ["list-paths", "list-sockets"] {
        for r in rows(user, &[command])? {
            if let Some(n) = r["activates"].as_str() {
                targets.insert(n.to_owned());
            }
        }
    }
    for l in ctl(user, &strings(&["list-jobs"]))?.lines() {
        if let Some(n) = l.split_whitespace().nth(1) {
            targets.insert(n.into());
        }
    }
    targets.retain(|n| n.ends_with(".service") && !n.starts_with('-'));
    Ok(targets)
}
fn selected_fields(input: &str) -> Result<BTreeMap<String, String>> {
    let mut d = BTreeMap::new();
    for line in input.lines() {
        let (k, v) = line.split_once('=').context("invalid manager property")?;
        let value = if k.starts_with("Exec") {
            let mut cmds = Vec::new();
            for part in v.split("argv[]=").skip(1) {
                cmds.push(
                    part.split_once(" ; ignore_errors=")
                        .context("unparsed lifecycle command")?
                        .0,
                );
            }
            ensure!(
                v.is_empty() || !cmds.is_empty(),
                "missing executable arguments"
            );
            cmds.join("\n")
        } else {
            v.to_owned()
        };
        ensure!(
            d.insert(k.into(), value).is_none(),
            "duplicate manager property"
        );
    }
    Ok(d)
}
fn cold(bytes: &[u8]) -> bool {
    [
        SOURCE.as_bytes(),
        SHA.as_bytes(),
        b"run-382916-1790762712552279895",
        b"epoch130-v1417-production-20260930-v1",
        b"horizon-cold130-holding-plan-20261110-v1",
    ]
    .iter()
    .any(|s| bytes.windows(s.len()).any(|p| p == *s))
}
fn inspect_text(path: &Path, bytes: &[u8]) -> Result<()> {
    if !cold(bytes) {
        return Ok(());
    }
    // Complete read-only operational fleets embed as data the failed zero-hash
    // capability probe's historical ExecStart. No other candidate reference is allowed.
    ensure!(
        path.file_name()
            .is_some_and(|n| n == "ROOT_COMPLETE_OPERATIONAL_FLEET.json")
            && path.starts_with("/var/lib/jetstreamer/horizon_runtime_data"),
        "routed input contains historical source: {}",
        path.display()
    );
    let mut doc: Value = serde_json::from_slice(bytes)?;
    ensure!(
        doc["owner"] == "/root" && doc["primary_thread"] == crate::PRIMARY,
        "unknown fleet metadata"
    );
    let value =
        doc["metadata_unit_census"]["horizon-cold130-holding-capability-20261110-v1.service"]
            .as_object_mut()
            .and_then(|m| m.remove("ExecStart"))
            .context("original historical probe field")?;
    let field = value.as_str().context("probe field")?;
    ensure!(field.contains("holding-park /usr/local/lib/jetstreamer/horizon-cold130-holding-plan-20261110-v1/plan.json --spec-sha256 0000000000000000000000000000000000000000000000000000000000000000") && !cold(&serde_json::to_vec(&doc)?),"fleet contains another candidate reference");
    Ok(())
}
fn classifying(d: &BTreeMap<String, String>) -> bool {
    d.values()
        .any(|v| v.contains("jetstreamer") || v.contains("horizon") || v.contains("epoch-130"))
}
fn inputs(d: &BTreeMap<String, String>) -> Result<BTreeMap<String, Value>> {
    let mut found = BTreeMap::new();
    for (k, v) in d {
        if !(k.starts_with("Exec") || k == "FragmentPath" || k == "DropInPaths") {
            continue;
        }
        for word in v.split_ascii_whitespace() {
            let mut arg = word.trim_matches(['"', '\'']);
            if let Some((_, v)) = arg.rsplit_once('=') {
                if v.starts_with('/') {
                    arg = v;
                }
            }
            if !arg.starts_with('/') {
                continue;
            }
            let p = Path::new(arg);
            let m = match fs::metadata(p) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            ensure!(
                (m.dev(), m.ino()) != (64512, 100794422),
                "runtime selector aliases old body"
            );
            if !m.is_file() {
                continue;
            }
            let text = matches!(
                p.extension().and_then(|x| x.to_str()),
                Some("sh" | "bash" | "py" | "zsh" | "json" | "toml" | "service" | "conf")
            );
            let identity = json!([
                m.dev(),
                m.ino(),
                m.uid(),
                m.gid(),
                m.mode(),
                m.nlink(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec()
            ]);
            let mut item = json!({"identity":identity});
            if text {
                ensure!(
                    m.len() <= 64 << 20,
                    "routed script/plan too large to review: {arg}"
                );
                let b = fs::read(p)?;
                inspect_text(p, &b)?;
                item["sha256"] = json!(sha(&b));
                let after = fs::metadata(p)?;
                ensure!(
                    crate::ident(&after) == identity,
                    "routed file changed during inspection: {arg}"
                );
            }
            found.insert(arg.to_owned(), item);
        }
    }
    Ok(found)
}
const PROPS: &str = "Id,ExecCondition,ExecStartPre,ExecStart,ExecStartPost,ExecReload,ExecStop,ExecStopPost,WorkingDirectory,RootDirectory,EnvironmentFiles,BindPaths,BindReadOnlyPaths,FragmentPath,DropInPaths";
pub(super) fn snapshot() -> Result<Value> {
    let mut routes = BTreeMap::new();
    for user in [false, true] {
        let targets = scheduled(user)?;
        if targets.is_empty() {
            continue;
        }
        let mut args = strings(&["show", "-p", PROPS]);
        args.extend(targets);
        for block in ctl(user, &args)?.trim().split("\n\n") {
            let d = selected_fields(block)?;
            let id = d.get("Id").context("missing unit ID")?;
            if !classifying(&d) {
                continue;
            }
            if id == "horizon-cold130-backed-retire-check-20261110-v2.service"
                || id == "horizon-cold130-backed-retire-execute-20261110-v2.service"
            {
                let mine = std::fs::read_to_string("/proc/self/cgroup")?;
                ensure!(
                    mine.trim() == format!("0::/system.slice/{id}"),
                    "competing retirement actor: {id}"
                );
                continue;
            }
            if id.starts_with("jetstreamer-cold130-historical-qualification-") && !user {
                let mine = std::fs::read_to_string("/proc/self/cgroup")?;
                ensure!(
                    mine.trim() == format!("0::/system.slice/{id}"),
                    "competing historical assessor: {id}"
                );
                continue;
            }
            ensure!(
                !d.values().any(|v| cold(v.as_bytes())),
                "unresolved reachable historical reader unit: {id}"
            );
            let bound = inputs(&d)?;
            routes.insert(
                format!("{}:{id}", if user { "user" } else { "system" }),
                json!({"properties":d,"inputs":bound}),
            );
        }
    }
    Ok(json!(routes))
}
pub(super) fn reviewed(binding: &Value) -> Result<()> {
    let plan = crate::bound_with_limit(binding, 4 << 20, true)?;
    ensure!(
        plan["schema"] == "horizon-cold130-reviewed-scheduled-inputs-v1"
            && plan["source"] == SOURCE
            && plan["sha256"] == SHA,
        "unbound prospective reader inventory"
    );
    let current = snapshot()?;
    let approved = plan["reviewed_routes"]
        .as_object()
        .context("independently reviewed route set")?;
    for (unit, route) in current.as_object().context("sampled route set")? {
        ensure!(
            approved.get(unit) == Some(route),
            "new or changed reachable actor requires inspection: {unit}"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_lifecycle_digest_ignores_runtime_timestamps_but_not_arguments() {
        let a=selected_fields("Id=x.service\nExecStart={ path=/bin/a ; argv[]=/bin/a /first ; ignore_errors=no ; start_time=now }").unwrap();
        let b=selected_fields("Id=x.service\nExecStart={ path=/bin/a ; argv[]=/bin/a /second ; ignore_errors=no ; start_time=now }").unwrap();
        assert_ne!(a, b);
        assert!(selected_fields("Id=x\nExecStart=unknown").is_err());
        assert!(cold(b"args=../run-382916-1790762712552279895/archives"));
    }
}
