fn validate_transfer_provenance(proof: &Value, iid: &str) -> Result<()> {
    let booking = evidence_with_limit(&binding(BOOKING, BOOKING_SHA), false, 1 << 20)?;
    let start_ref: Bound = serde_json::from_value(proof["start"].clone())?;
    ensure!(
        start_ref.path == Path::new(PARK_START),
        "unexpected park start receipt"
    );
    let start = evidence_with_limit(&start_ref, false, 1 << 20)?;
    validate_profile_rows(proof, iid, &start, &booking)
}
fn validate_rows(proof: &Value, iid: &str, start: &Value, booking: &Value) -> Result<()> {
    let plan = serde_json::to_value(binding(PARK_PLAN, PARK_PLAN_SHA))?;
    let helper = &booking["qualified_image"];
    let native = &start["native"];
    let pid = native["MainPID"]
        .as_str()
        .context("start PID")?
        .parse::<u64>()?;
    let expected_cmd = json!([
        helper["path"],
        "holding-park",
        PARK_PLAN,
        "--spec-sha256",
        PARK_PLAN_SHA,
        "--self-sha256",
        helper["sha256"]
    ]);
    ensure!(
        proof["schema"] == profile!(epoch "horizon-closed", "-park-terminal-v1")
            && proof["unit"] == PARK
            && proof["park_plan"] == plan
            && proof["helper"] == *helper
            && start["booking"] == serde_json::to_value(binding(BOOKING, BOOKING_SHA))?
            && start["plan"] == plan
            && start["image"] == *helper
            && start["argv"] == expected_cmd
            && start["start_ticks"].as_u64().is_some_and(|n| n > 0)
            && start["local_credit_bytes"] == 0
            && booking["plans"][ATTEMPT]["plan"] == plan
            && booking["plans"][ATTEMPT]["object_sha256"] == SHA
            && booking["plans"][ATTEMPT]["length"] == LENGTH
            && native["Id"] == PARK
            && native["InvocationID"] == iid
            && native["MainPID"] == native["ExecMainPID"]
            && pid > 0
            && native["NRestarts"] == "0"
            && (native["ActiveState"] == "activating" || native["ActiveState"] == "active")
            && native["ExecMainStartTimestamp"]
                .as_str()
                .is_some_and(|ts| !ts.is_empty())
            && native["ControlGroup"] == format!("/system.slice/{PARK}")
            && proof["native"]["ExecMainStartTimestamp"] == native["ExecMainStartTimestamp"]
            && proof["native"]["ExecMainPID"] == native["ExecMainPID"]
            && proof["native"]["NRestarts"] == "0",
        "park start, terminal, unit, booking or command binding differs"
    );
    Ok(())
}

pub(super) fn capture_terminal(spec: &Bound) -> Result<()> {
    ensure!(
        same_bound(spec, &binding(PARK_PLAN, PARK_PLAN_SHA))
            && fs::read_link("/proc/self/exe")?.parent() == Some(Path::new(LIFECYCLE)),
        "exact park plan and sealed tool required"
    );
    let plan: Park = serde_json::from_value(bound(spec)?)?;
    let eligibility = bound(&plan.eligibility)?;
    source_scope(&plan, &eligibility)?;
    ensure!(
        plan.source == Path::new(SOURCE)
            && plan.length == LENGTH
            && plan.sha256 == SHA
            && same_bound(&plan.mapping, &binding(MAPPING, MAPPING_SHA))
            && same_bound(&plan.eligibility, &binding(ELIGIBILITY, ELIGIBILITY_SHA)),
        "foreign partial park"
    );
    let mapping: Mapping = serde_json::from_value(bound(&plan.mapping)?)?;
    let booking = evidence_with_limit(&binding(BOOKING, BOOKING_SHA), false, 1 << 20)?;
    let native_before = native(PARK)?;
    let iid = native_before["InvocationID"]
        .as_str()
        .context("native park invocation")?;
    park_shape(&native_before, iid)?;
    let start_bytes = read_stable_bounded(Path::new(PARK_START), 1 << 20, "park start")?;
    let mut proof = json!({"schema":profile!(epoch "horizon-closed", "-park-terminal-v1"),"unit":PARK,
        "park_plan":spec,"helper":booking[HOLDING_IMAGE_FIELD],"native":native_before,"invocation_id":iid,
        "start":binding(PARK_START,&hex_lower(&Sha256::digest(start_bytes)))});
    validate_transfer_provenance(&proof, iid)?;
    let manifest = manifest_bytes(
        &mapping,
        &plan,
        &object_key(&mapping, SHA)?,
        1001,
        1003,
        0o600,
    )?;
    let manifest_sha = hex_lower(&Sha256::digest(&manifest));
    let receipt_path = Path::new(STATE)
        .join("receipts")
        .join(format!("custody-{manifest_sha}.json"));
    let bytes = read_stable_bounded(&receipt_path, 1 << 20, "original custody receipt")?;
    let receipt = Bound {
        path: receipt_path,
        sha256: hex_lower(&Sha256::digest(bytes)),
    };
    let c = evidence_with_limit(&receipt, false, 1 << 20)?;
    let (_, _, sha, length) = custody(&c, &mapping)?;
    ensure!(
        sha == SHA
            && length == LENGTH
            && c["mapping"] == serde_json::to_value(&plan.mapping)?
            && c["eligibility"] == serde_json::to_value(&plan.eligibility)?
            && c["source"] == SOURCE
            && c["manifest_sha256"] == manifest_sha
            && c["manifest"] == serde_json::from_slice::<Value>(&manifest)?,
        "original custody does not match inspected prefix"
    );
    ensure!(native(PARK)? == native_before, "terminal park changed");
    proof["custody"] = serde_json::to_value(receipt)?;
    proof["local_retirement_authorized"] = json!(false);
    let output = Path::new(STATE)
        .join("receipts")
        .join(format!("{}-{iid}.json", profile!(epoch "epoch", "-park-terminal")));
    persist(&output, &proof)?;
    println!("{}", output.display());
    Ok(())
}

fn validate_terminal_custody(p: &Retire, proof: &Value) -> Result<()> {
    let original: Bound = serde_json::from_value(proof["custody"].clone())?;
    let custody = bound(&original)?;
    let key = custody["manifest_sha256"]
        .as_str()
        .context("custody manifest")?;
    ensure!(
        original.path
            == Path::new(STATE)
                .join("receipts")
                .join(format!("custody-{key}.json"))
            && original.sha256 == p.custody.sha256
            && bound(&p.custody)? == custody,
        "park terminal references different custody evidence"
    );
    Ok(())
}

#[cfg(test)]
mod terminal_tests {
    use super::*;

    #[test]
    fn original_live_and_terminal_invocations_bind_this_selected_park() {
        let iid = "0123456789abcdef0123456789abcdef";
        let plan = binding(PARK_PLAN, PARK_PLAN_SHA);
        let helper = binding("/qualified/park", &"a".repeat(64));
        let mut booking = json!({"qualified_image":helper, "plans":{}});
        booking["plans"][ATTEMPT] = json!({"plan":plan,"length":LENGTH,"object_sha256":SHA});
        let start = json!({"booking":binding(BOOKING,BOOKING_SHA),"plan":plan,"image":helper,
          "argv":[helper.path,"holding-park",PARK_PLAN,"--spec-sha256",PARK_PLAN_SHA,"--self-sha256",helper.sha256],
          "native":{"MainPID":"123","ExecMainPID":"123","Id":PARK,"InvocationID":iid,
          "ActiveState":"activating","NRestarts":"0","ControlGroup":format!("/system.slice/{PARK}"),"ExecMainStartTimestamp":"Fri 2026-11-20 02:10:00 UTC"},
          "start_ticks":99,"local_credit_bytes":0});
        let terminal = json!({"unit":PARK,"schema":profile!(epoch "horizon-closed", "-park-terminal-v1"),
           "park_plan":plan,"helper":helper,"native":{"ExecMainPID":"123","NRestarts":"0","ExecMainStartTimestamp":start["native"]["ExecMainStartTimestamp"]}});
        validate_rows(&terminal, iid, &start, &booking).unwrap();
        for (key, val) in [
            ("ExecMainPID", "0"),
            ("InvocationID", "foreign"),
            ("ControlGroup", "/wrong"),
            ("NRestarts", "1"),
        ] {
            let mut bad = start.clone();
            bad["native"][key] = json!(val);
            assert!(validate_rows(&terminal, iid, &bad, &booking).is_err());
        }
        let mut bad = terminal.clone();
        bad["park_plan"]["sha256"] = json!("0".repeat(64));
        assert!(validate_rows(&bad, iid, &start, &booking).is_err());
        booking["plans"][ATTEMPT]["object_sha256"] = json!("0".repeat(64));
        assert!(validate_rows(&terminal, iid, &start, &booking).is_err());
    }
}
