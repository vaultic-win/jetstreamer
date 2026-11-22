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
    let mut d: BTreeMap<String, String> = BTreeMap::new();
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
        if let Some(prior) = d.get_mut(k) {
            ensure!(
                k.starts_with("Exec") || k == "EnvironmentFiles",
                "duplicate scalar manager property: {k}"
            );
            prior.push('\n');
            prior.push_str(&value);
        } else {
            d.insert(k.into(), value);
        }
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
fn credential_names(d: &BTreeMap<String, String>) -> Result<()> {
    for line in d
        .get("EnvironmentFiles")
        .map(String::as_str)
        .unwrap_or("")
        .lines()
        .filter(|l| !l.is_empty())
    {
        let path = line
            .strip_suffix(" (ignore_errors=no)")
            .context("unreviewed optional environment-file argument")?;
        let audit = match path {
            "/etc/jetstreamer/horizon-r2.env" => false,
            "/var/lib/jetstreamer/r2-chronological-plugin-audit-deployment-20261118-v1/credentials.env" => {
                true
            }
            _ => anyhow::bail!("unreviewed mission environment file"),
        };
        let bytes = crate::raw(Path::new(path), 64 << 10, true)?;
        let mut keys = BTreeSet::new();
        for statement in std::str::from_utf8(&bytes)?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let (key, _) = statement
                .split_once('=')
                .context("unexpected environment statement")?;
            ensure!(keys.insert(key), "duplicate environment selector");
        }
        let mut approved = BTreeSet::from([
            "HORIZON_ACCESS_KEY_ID",
            "HORIZON_S3_ENDPOINT",
            "HORIZON_SECRET_ACCESS_KEY",
        ]);
        if audit {
            approved.insert("SSH_AUTH_SOCK");
        }
        ensure!(
            keys == approved,
            "preexisting credential file gained a noncredential selector"
        );
    }
    Ok(())
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
            credential_names(&d)?;
            let bound = inputs(&d)?;
            routes.insert(
                format!("{}:{id}", if user { "user" } else { "system" }),
                json!({"properties":d,"inputs":bound}),
            );
        }
    }
    Ok(json!(routes))
}
fn cadence_config(value: &Value) -> Result<(String, String, Value)> {
    let mut copy = value.clone();
    let map = copy.as_object_mut().context("observer input")?;
    let utc = map.remove("not_before_utc").context("observer timestamp")?;
    let utc = utc.as_str().context("observer timestamp type")?;
    ensure!(
        utc.len() == 20 && utc.starts_with("2026-11-21T") && utc.ends_with('Z'),
        "observer date differs"
    );
    let output = map.remove("output").context("observer output")?;
    let previous = map
        .remove("previous_sample")
        .context("observer predecessor")?;
    fn stamp(v: &Value) -> Result<String> {
        let x = v
            .as_str()
            .context("observer path")?
            .strip_prefix("/var/lib/jetstreamer/horizon_runtime_data/sample-root")
            .and_then(|t| t.strip_suffix("-live166167170-20261121-v1.json"))
            .context("unknown observer input/output family")?;
        ensure!(
            x.len() == 6 && x.bytes().all(|b| b.is_ascii_digit()),
            "observer time token"
        );
        Ok(x.into())
    }
    let out = stamp(&output)?;
    let prev = stamp(&previous)?;
    ensure!(
        out == utc[11..19].replace(':', "") && prev < out,
        "observer predecessor or timestamp differs"
    );
    Ok((out, prev, copy))
}
fn cadence(unit: &str, route: &Value, template: &Value) -> Result<bool> {
    let Some(id) = unit.strip_prefix("system:horizon-observer-root") else {
        return Ok(false);
    };
    let Some(now) = id.strip_suffix("-live166167170-20261121-v1.service") else {
        return Ok(false);
    };
    ensure!(
        now.len() == 6 && now.bytes().all(|b| b.is_ascii_digit()),
        "unrecognized future observer"
    );
    let props = &route["properties"];
    let exec = s(props, "ExecStart")?
        .split_whitespace()
        .collect::<Vec<_>>();
    let elf = "/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe";
    ensure!(
        exec.len() == 2 && exec[0] == elf && route["inputs"][elf] == template["executable"],
        "future observer executable changed"
    );
    let config = Path::new(exec[1]);
    let bytes = crate::raw(config, 2 << 20, true)?;
    let (actual, prev, stable) = cadence_config(&serde_json::from_slice(&bytes)?)?;
    let actual_id = format!("horizon-observer-root{now}-live166167170-20261121-v1.service");
    ensure!(
        actual == now
            && stable == template["config"]
            && exec[1]
                == format!(
                    "/var/lib/jetstreamer/horizon_runtime_data/root{prev}-live166167170-20261121-v1/sealed-next/observer.json"
                ),
        "observer has new activity scope"
    );
    let fragment = format!("/run/systemd/transient/{actual_id}");
    let unit_bytes = crate::raw(Path::new(&fragment), 1 << 16, true)?;
    let normalized = std::str::from_utf8(&unit_bytes)?.replace(exec[1], "<OBSERVER_PLAN>");
    let mut props = props.clone();
    let map = props
        .as_object_mut()
        .context("effective observer properties")?;
    ensure!(
        map.remove("Id") == Some(json!(actual_id))
            && map.remove("FragmentPath") == Some(json!(fragment)),
        "observer fragment or ID differs"
    );
    map.remove("ExecStart");
    ensure!(
        props == template["properties"]
            && sha(normalized.as_bytes()) == template["normalized_fragment_sha256"]
            && route["inputs"].as_object().is_some_and(|m| m.len() == 3),
        "observer lifecycle or staged inputs changed"
    );
    Ok(true)
}
pub(super) fn reviewed(binding: &Value) -> Result<()> {
    let plan = crate::bound_with_limit(binding, 4 << 20, true)?;
    ensure!(
        plan["schema"] == "horizon-cold130-reviewed-scheduled-inputs-v1"
            && plan["source"] == SOURCE
            && plan["sha256"] == SHA,
        "unbound prospective reader inventory"
    );
    let libs = plan["reviewed_transitive_inputs"]
        .as_array()
        .context("missing actual routed library/control inputs")?;
    ensure!(!libs.is_empty(), "empty dependency closure");
    for entry in libs {
        let p = Path::new(s(entry, "path")?);
        ensure!(
            p.is_absolute() && p.canonicalize()? == p,
            "indirect path changed"
        );
        let before = fs::metadata(p)?;
        ensure!(
            before.is_file()
                && before.len() <= 4 << 20
                && crate::ident(&before) == entry["identity"],
            "indirect reader identity differs: {}",
            p.display()
        );
        let bytes = fs::read(p)?;
        ensure!(
            sha(&bytes) == entry["sha256"]
                && crate::ident(&fs::metadata(p)?) == entry["identity"]
                && !cold(&bytes),
            "indirect source selection changed: {}",
            p.display()
        );
    }
    let current = snapshot()?;
    let approved = plan["reviewed_routes"]
        .as_object()
        .context("independently reviewed route set")?;
    for (unit, route) in current.as_object().context("sampled route set")? {
        ensure!(
            approved.get(unit) == Some(route)
                || cadence(unit, route, &plan["cadence_template"])?
                || crate::guard_observer::reviewed(unit, route, approved)?,
            "new or changed reachable actor requires inspection: {unit}"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cadence_time_substitution_preserves_original_paths_and_scope() {
        let good = json!({"not_before_utc":"2026-11-21T03:49:59Z","output":"/var/lib/jetstreamer/horizon_runtime_data/sample-root034959-live166167170-20261121-v1.json","previous_sample":"/var/lib/jetstreamer/horizon_runtime_data/sample-root031959-live166167170-20261121-v1.json","replays":["166"]});
        let (_, _, stable) = cadence_config(&good).unwrap();
        assert_eq!(stable, json!({"replays":["166"]}));
        let mut bad = good.clone();
        bad["output"] = json!(crate::SOURCE);
        assert!(cadence_config(&bad).is_err());
        bad = good;
        bad["previous_sample"] = bad["output"].clone();
        assert!(cadence_config(&bad).is_err());
    }
    #[test]
    fn native_lifecycle_digest_ignores_runtime_timestamps_but_not_arguments() {
        let a=selected_fields("Id=x.service\nExecStart={ path=/bin/a ; argv[]=/bin/a /first ; ignore_errors=no ; start_time=now }").unwrap();
        let b=selected_fields("Id=x.service\nExecStart={ path=/bin/a ; argv[]=/bin/a /second ; ignore_errors=no ; start_time=now }").unwrap();
        assert_ne!(a, b);
        let ordered=selected_fields("Id=test.service\nExecStart={ argv[]=/first ; ignore_errors=no }\nExecStart={ argv[]=/second ; ignore_errors=no }").unwrap();
        assert_eq!(ordered["ExecStart"], "/first\n/second");
        assert!(selected_fields("Id=x\nId=y").is_err());
        assert!(selected_fields("Id=x\nExecStart=unknown").is_err());
        assert!(cold(b"args=../run-382916-1790762712552279895/archives"));
    }
}

#[cfg(test)]
pub(super) fn captured_guard_inputs(block: &str) -> Result<Value> {
    let properties = selected_fields(block)?;
    let files = inputs(&properties)?;
    Ok(json!({"properties": properties, "inputs": files}))
}
