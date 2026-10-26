//! Authenticate only positively empty native arrays omitted by systemctl.
//! Raw show output is retained; missing or nonempty properties are never normalized.
use super::*;
const SERVICE: &str = "org.freedesktop.systemd1.Service";
const UNIT: &str = "org.freedesktop.systemd1.Unit";
const FIELDS: [(&str, &str, &str); 11] = [
    ("ExecStartPre", SERVICE, "a(sasbttttuii)"),
    ("ExecStartPost", SERVICE, "a(sasbttttuii)"),
    ("ExecCondition", SERVICE, "a(sasbttttuii)"),
    ("ExecReload", SERVICE, "a(sasbttttuii)"),
    ("ExecStop", SERVICE, "a(sasbttttuii)"),
    ("ExecStopPost", SERVICE, "a(sasbttttuii)"),
    ("OnSuccess", UNIT, "as"),
    ("OnFailure", UNIT, "as"),
    ("Environment", SERVICE, "as"),
    ("EnvironmentFiles", SERVICE, "a(sb)"),
    ("PassEnvironment", SERVICE, "as"),
];
fn object_path(service: &str) -> Result<String> {
    ensure!(
        guard_scope(service, 201, 300)
            || singleton210_admission::jit_issuer_scope(service)
            || [
                "full-verification",
                "plugin-verification",
                "upload-readback"
            ]
            .iter()
            .any(|role| pipeline_scope(role, service).is_some()),
        "completed typed empty-property reader cannot inspect a foreign service"
    );
    let mut path = "/org/freedesktop/systemd1/unit/".to_owned();
    for byte in service.bytes() {
        if byte.is_ascii_alphanumeric() {
            path.push(char::from(byte));
        } else {
            path.push_str(&format!("_{byte:02x}"));
        }
    }
    Ok(path)
}
fn empty_reply(success: bool, stdout: &[u8], stderr: &[u8], signature: &str) -> Result<()> {
    ensure!(
        success && stdout.len() <= 4096 && stderr.is_empty(),
        "completed typed native empty-property query failed or exceeded bound"
    );
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NativeArray {
        #[serde(rename = "type")]
        signature: String,
        data: Vec<Value>,
    }
    let value: NativeArray = serde_json::from_slice(stdout)?;
    ensure!(
        value.signature == signature && value.data.is_empty(),
        "completed native property is not an exact recognized empty array"
    );
    Ok(())
}
fn query(service: &str, path: &str, interface: &str, property: &str) -> Result<Value> {
    // Same bounded child-query policy as the reviewed TimersCalendar adapter.
    // Every executable, service, interface and property comes from the fixed roster.
    use std::process::Stdio;
    ensure!(
        object_path(service)? == path
            && FIELDS
                .iter()
                .any(|(p, i, _)| *p == property && *i == interface),
        "completed typed property query escaped its fixed roster"
    );
    let mut child = ProcessCommand::new("/usr/bin/busctl")
        .args([
            "--system",
            "--json=short",
            "--timeout=2s",
            "get-property",
            "org.freedesktop.systemd1",
            path,
            interface,
            property,
        ])
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    while child.try_wait()?.is_none() {
        if start.elapsed() >= Duration::from_secs(2) {
            child.kill()?;
            child.wait()?;
            bail!("completed typed property query exceeded two seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let reply = child.wait_with_output()?;
    let signature = FIELDS
        .iter()
        .find(|(p, i, _)| *p == property && *i == interface)
        .context("completed fixed property missing")?
        .2;
    empty_reply(
        reply.status.success(),
        &reply.stdout,
        &reply.stderr,
        signature,
    )?;
    Ok(
        json!({"unit":service,"object_path":path,"interface":interface,"property":property,
        "signature":signature,"exit_code":reply.status.code(),"stdout":std::str::from_utf8(&reply.stdout)?,
        "stderr":std::str::from_utf8(&reply.stderr)?}),
    )
}
fn roster(guard: bool, credentials: bool) -> Vec<(&'static str, &'static str, &'static str)> {
    FIELDS
        .into_iter()
        .filter(|(p, _, _)| {
            (guard || *p != "Environment") && (!credentials || *p != "EnvironmentFiles")
        })
        .collect()
}
fn normalize(
    service: &str,
    show: &BTreeMap<String, String>,
    proof: &Value,
    guard: bool,
    credentials: bool,
) -> Result<BTreeMap<String, String>> {
    let path = object_path(service)?;
    ensure!(!guard || !credentials, "guard cannot import credentials");
    let replies = proof
        .as_object()
        .context("completed typed empty replies missing")?;
    let fields = roster(guard, credentials);
    let omitted = fields
        .iter()
        .filter(|(p, _, _)| !show.contains_key(*p))
        .map(|(p, _, _)| *p)
        .collect::<BTreeSet<_>>();
    ensure!(
        replies.keys().map(String::as_str).collect::<BTreeSet<_>>() == omitted,
        "completed typed reply roster differs from omitted fields"
    );
    let mut effective = show.clone();
    for (property, interface, signature) in fields {
        if let Some(value) = show.get(property) {
            ensure!(
                value.is_empty(),
                "completed nonempty native control: {property}"
            );
        } else {
            let r = &replies[property];
            ensure!(
                r["unit"] == service
                    && r["object_path"] == path
                    && r["interface"] == interface
                    && r["property"] == property
                    && r["signature"] == signature
                    && r["exit_code"] == 0,
                "completed typed reply has foreign identity or failed query"
            );
            empty_reply(
                true,
                r["stdout"]
                    .as_str()
                    .context("completed typed stdout is not text")?
                    .as_bytes(),
                r["stderr"]
                    .as_str()
                    .context("completed typed stderr is not text")?
                    .as_bytes(),
                signature,
            )?;
            effective.insert(property.into(), String::new());
        }
    }
    ensure!(
        !show.contains_key("TypedEmptyRawShow") && !show.contains_key("TypedEmptyReplies"),
        "completed native properties contain reserved evidence fields"
    );
    effective.insert("TypedEmptyRawShow".into(), serde_json::to_string(show)?);
    effective.insert("TypedEmptyReplies".into(), serde_json::to_string(proof)?);
    Ok(effective)
}

pub(super) fn jit210_properties(name: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        singleton210_admission::jit_issuer_scope(name),
        "foreign JIT 210 typed property caller"
    );
    let show = singleton227_capture::properties(name, fields)?;
    let path = object_path(name)?;
    let mut proof = serde_json::Map::new();
    for (property, interface, _) in roster(false, false) {
        if !show.contains_key(property) {
            proof.insert(property.into(), query(name, &path, interface, property)?);
        }
    }
    normalize(name, &show, &Value::Object(proof), false, false)
}

pub(super) fn properties(s: &Spec, guard: bool, fields: &str) -> Result<BTreeMap<String, String>> {
    properties_with(s, guard, fields, singleton227_capture::properties)
}
pub(super) fn properties_with(
    s: &Spec,
    guard: bool,
    fields: &str,
    reader: fn(&str, &str) -> Result<BTreeMap<String, String>>,
) -> Result<BTreeMap<String, String>> {
    let name = if guard {
        &s.guard_units[s.phase.name()]
    } else {
        &s.units[s.phase.name()]
    };
    let path = object_path(name)?;
    ensure!(
        if guard {
            name.starts_with(&format!(
                "horizon-generic{}-{}-protective-",
                s.epoch,
                s.phase.name()
            )) && guard_scope(name, s.epoch, s.epoch)
        } else {
            pipeline_scope(
                match s.phase {
                    Phase::Full => "full-verification",
                    Phase::Plugin => "plugin-verification",
                    Phase::Upload => "upload-readback",
                },
                name,
            ) == Some(s.epoch)
        },
        "completed typed query escaped exact spec role"
    );
    let raw = reader(name, fields)?;
    let credentials = !guard && s.environment_file.is_some();
    let mut replies = serde_json::Map::new();
    for (property, interface, _) in roster(guard, credentials) {
        if !raw.contains_key(property) {
            replies.insert(property.into(), query(name, &path, interface, property)?);
        }
    }
    ensure!(
        reader(name, fields)? == raw,
        "completed native properties changed across typed empty queries"
    );
    normalize(name, &raw, &Value::Object(replies), guard, credentials)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn proof(service: &str, guard: bool, credentials: bool) -> Value {
        let path = object_path(service).unwrap();
        Value::Object(roster(guard, credentials).into_iter().map(|(p,i,s)| (p.into(), json!({"unit":service,"object_path":path,"interface":i,"property":p,"signature":s,"exit_code":0,"stdout":serde_json::to_string(&json!({"type":s,"data":[]})).unwrap(),"stderr":""}))).collect())
    }
    #[test]
    fn completed_typed_empty_worker_preserves_declared_environment_and_credential_requirements() {
        let service = "horizon-qualify-209-generic-upload-v1.service";
        let mut raw = BTreeMap::from([("Environment".into(), "LC_ALL=C".into())]);
        let p = proof(service, false, true);
        let normalized = normalize(service, &raw, &p, false, true).unwrap();
        assert_eq!(normalized["Environment"], "LC_ALL=C");
        assert!(!normalized.contains_key("EnvironmentFiles"));
        assert!(validate_environment_sources(&normalized, None).is_err());
        raw.insert(
            "EnvironmentFiles".into(),
            "/exact (ignore_errors=no)".into(),
        );
        let normalized = normalize(service, &raw, &p, false, true).unwrap();
        assert_eq!(normalized["EnvironmentFiles"], raw["EnvironmentFiles"]);
        assert_eq!(
            serde_json::from_str::<BTreeMap<String, String>>(&normalized["TypedEmptyRawShow"])
                .unwrap(),
            raw
        );
    }
    #[test]
    fn completed_typed_empty_guard_requires_all_exact_empty_arrays_and_keeps_raw_proof() {
        let service = "horizon-generic209-full-protective-v1.service";
        let raw = BTreeMap::new();
        let good = proof(service, true, false);
        let p = normalize(service, &raw, &good, true, false).unwrap();
        assert_eq!(p["TypedEmptyRawShow"], "{}");
        assert_eq!(
            serde_json::from_str::<Value>(&p["TypedEmptyReplies"]).unwrap(),
            good
        );
        for (field, _, _) in FIELDS {
            let mut missing = good.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(normalize(service, &raw, &missing, true, false).is_err());
            let mut foreign = good.clone();
            foreign[field]["unit"] = json!("foreign.service");
            assert!(normalize(service, &raw, &foreign, true, false).is_err());
            let mut nonempty = raw.clone();
            nonempty.insert(field.into(), "unsafe".into());
            assert!(normalize(service, &nonempty, &good, true, false).is_err());
        }
    }
    #[test]
    fn completed_typed_empty_rejects_foreign_scopes_malformed_duplicate_and_nonempty_replies() {
        for service in [
            "other.service",
            "horizon-generic0209-full-protective-v1.service",
            "horizon-generic209-replay-protective-v1.service",
        ] {
            assert!(object_path(service).is_err());
        }
        for raw in [
            r#"{"type":"as","data":[],"data":[]}"#,
            r#"{"type":"as","data":["x"]}"#,
            r#"{"type":"as","data":[],"extra":0}"#,
            r#"{"type":"a(sb)","data":[]}"#,
        ] {
            assert!(empty_reply(true, raw.as_bytes(), b"", "as").is_err());
        }
        assert!(empty_reply(false, br#"{"type":"as","data":[]}"#, b"", "as").is_err());
    }
}
