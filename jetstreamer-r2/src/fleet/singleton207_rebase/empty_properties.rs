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
        matches!(service, singleton207::PROTECTIVE | BRIDGE),
        "207 typed empty-property reader cannot inspect a foreign service"
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
        "207 typed native empty-property query failed or exceeded bound"
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
        "207 native property is not an exact recognized empty array"
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
        "207 typed property query escaped its fixed roster"
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
            bail!("207 typed property query exceeded two seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let reply = child.wait_with_output()?;
    let signature = FIELDS
        .iter()
        .find(|(p, i, _)| *p == property && *i == interface)
        .context("207 fixed property missing")?
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
pub(super) fn capture(service: &str, show: &BTreeMap<String, String>) -> Result<Value> {
    let path = object_path(service)?;
    let mut replies = serde_json::Map::new();
    for (property, interface, _) in FIELDS {
        match show.get(property) {
            Some(value) => ensure!(
                value.is_empty(),
                "207 guard has a nonempty hook/environment property: {property}"
            ),
            None => {
                replies.insert(property.into(), query(service, &path, interface, property)?);
            }
        }
    }
    let proof = Value::Object(replies);
    validate(service, show, &proof)?;
    Ok(proof)
}
pub(super) fn validate(
    service: &str,
    show: &BTreeMap<String, String>,
    proof: &Value,
) -> Result<()> {
    let path = object_path(service)?;
    let replies = proof
        .as_object()
        .context("207 typed empty-property replies missing")?;
    let omitted = FIELDS
        .iter()
        .filter(|(p, _, _)| !show.contains_key(*p))
        .map(|(p, _, _)| *p)
        .collect::<BTreeSet<_>>();
    ensure!(
        replies.keys().map(String::as_str).collect::<BTreeSet<_>>() == omitted,
        "207 typed empty-property roster differs from actual omitted fields"
    );
    for (property, interface, signature) in FIELDS {
        if let Some(value) = show.get(property) {
            ensure!(
                value.is_empty(),
                "207 guard has a nonempty native property: {property}"
            );
            continue;
        }
        let r = &replies[property];
        ensure!(
            r["unit"] == service
                && r["object_path"] == path
                && r["interface"] == interface
                && r["property"] == property
                && r["signature"] == signature
                && r["exit_code"] == 0,
            "207 typed reply belongs to a different service/property/interface or failed query"
        );
        empty_reply(
            true,
            text(r, "stdout")?.as_bytes(),
            text(r, "stderr")?.as_bytes(),
            signature,
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn proof(service: &str) -> Value {
        let path = object_path(service).unwrap();
        let mut rows = serde_json::Map::new();
        for (p, i, s) in FIELDS {
            rows.insert(p.into(),json!({"unit":service,"object_path":path,"interface":i,"property":p,
            "signature":s,"exit_code":0,"stdout":serde_json::to_string(&json!({"type":s,"data":[]})).unwrap(),"stderr":""}));
        }
        Value::Object(rows)
    }
    #[test]
    fn rebase207_omitted_hooks_require_exact_typed_empty_service_and_unit_arrays() {
        let show = BTreeMap::new();
        let proof = proof(singleton207::PROTECTIVE);
        validate(singleton207::PROTECTIVE, &show, &proof).unwrap();
        assert!(show.is_empty());
        assert_eq!(proof["OnSuccess"]["interface"], UNIT);
        assert_eq!(proof["EnvironmentFiles"]["signature"], "a(sb)");
        for (p, _, _) in FIELDS {
            let mut bad = proof.clone();
            bad.as_object_mut().unwrap().remove(p);
            assert!(
                validate(singleton207::PROTECTIVE, &show, &bad).is_err(),
                "{p}"
            );
        }
    }
    #[test]
    fn rebase207_typed_empty_proof_never_normalizes_nonempty_failed_or_foreign_values() {
        let show = BTreeMap::new();
        let good = proof(singleton207::PROTECTIVE);
        for (key, value) in [
            ("unit", json!(BRIDGE)),
            ("object_path", json!("/foreign")),
            ("interface", json!(UNIT)),
            ("signature", json!("as")),
            ("exit_code", json!(1)),
            ("stderr", json!("error")),
            (
                "stdout",
                json!("{\"type\":\"a(sasbttttuii)\",\"data\":[[]]}"),
            ),
        ] {
            let mut bad = good.clone();
            bad["ExecStartPre"][key] = value;
            assert!(
                validate(singleton207::PROTECTIVE, &show, &bad).is_err(),
                "{key}"
            );
        }
        let mut nonempty = BTreeMap::new();
        nonempty.insert("ExecStartPre".into(), "/unqualified".into());
        assert!(validate(singleton207::PROTECTIVE, &nonempty, &good).is_err());
        for raw in [
            b"".as_slice(),
            b"{}",
            b"{\"type\":\"a(sb)\",\"data\":null}",
            b"{\"type\":\"a(sb)\",\"data\":[],\"extra\":0}",
        ] {
            assert!(empty_reply(true, raw, b"", "a(sb)").is_err());
        }
        assert!(empty_reply(
            true,
            br#"{"type":"a(sb)","data":[["/untrusted",true]],"data":[]}"#,
            b"",
            "a(sb)"
        )
        .is_err());
        assert!(object_path("other.service").is_err());
    }
    #[test]
    fn rebase207_explicit_empty_show_is_retained_without_invented_typed_replies() {
        let show = FIELDS
            .iter()
            .map(|(p, _, _)| (p.to_string(), String::new()))
            .collect::<BTreeMap<_, _>>();
        let before = show.clone();
        validate(BRIDGE, &show, &json!({})).unwrap();
        assert_eq!(show, before);
        assert!(validate(BRIDGE, &show, &proof(BRIDGE)).is_err());
        assert!(empty_reply(false, b"{\"type\":\"as\",\"data\":[]}", b"", "as").is_err());
        assert!(empty_reply(true, &vec![b' '; 4097], b"", "as").is_err());
    }
}
