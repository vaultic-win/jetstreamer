//! Only authenticated declared adaptive guard services may renew their lifecycle.
use super::*;
pub(super) struct Policy<'a> {
    declarations: &'a [GuardSpec],
}
impl<'a> Policy<'a> {
    pub(super) fn new(
        declarations: &'a [GuardSpec],
        owners: &[core::Owner],
        helper: &Value,
        peers: &[Value],
    ) -> Result<Self> {
        ensure!(
            !declarations.is_empty() && declarations.len() <= 64,
            "guard_continuity.declarations_count"
        );
        let mut resources = owners
            .iter()
            .map(|o| o.unit.as_str())
            .collect::<BTreeSet<_>>();
        resources.insert(string(helper, "/unit")?);
        for peer in peers {
            resources.insert(string(peer, "/unit")?);
        }
        let mut names = BTreeSet::new();
        for g in declarations {
            for (name, suffix) in [(&g.unit, ".service"), (&g.timer, ".timer")] {
                ensure!(
                    name.len() <= 256
                        && name.ends_with(suffix)
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
                        && names.insert(name.as_str())
                        && !resources.contains(name.as_str()),
                    "guard_continuity.duplicate_foreign_or_resource_alias"
                );
            }
        }
        Ok(Self { declarations })
    }
    fn map<'b>(&self, rows: &'b Value) -> Result<BTreeMap<&'b str, &'b Value>> {
        let rows = rows.as_array().context("guard_continuity.rows_array")?;
        ensure!(
            rows.len() == self.declarations.len(),
            "guard_continuity.rows_count"
        );
        let mut map = BTreeMap::new();
        for row in rows {
            let name = string(row, "/unit")?;
            ensure!(
                self.declarations.iter().any(|g| g.unit == name) && map.insert(name, row).is_none(),
                "guard_continuity.duplicate_or_foreign_row"
            );
        }
        Ok(map)
    }
    pub(super) fn compare(
        &self,
        ga: &Value,
        gb: &Value,
        ea: &Value,
        eb: &Value,
        ca: &Value,
        cb: &Value,
    ) -> Result<()> {
        let (ga, gb, ea, eb) = (self.map(ga)?, self.map(gb)?, self.map(ea)?, self.map(eb)?);
        let mut ca = ca
            .as_object()
            .context("guard_continuity.census_object")?
            .clone();
        let mut cb = cb
            .as_object()
            .context("guard_continuity.census_object")?
            .clone();
        ensure!(
            ca.keys().eq(cb.keys()),
            "guard_continuity.census_membership"
        );
        for g in self.declarations {
            let (left, right, le, re) = (
                ga[g.unit.as_str()],
                gb[g.unit.as_str()],
                ea[g.unit.as_str()],
                eb[g.unit.as_str()],
            );
            for (proof, evidence) in [(left, le), (right, re)] {
                let typed: core::Guard = serde_json::from_value(proof.clone())?;
                ensure!(
                    typed.protection_shape() && typed.minimum_free_bytes > 0,
                    "guard_continuity.proof_required_fields"
                );
                if typed.retained_terminal_199 {
                    ensure!(
                        evidence["retained_terminal_199"] == true,
                        "guard_continuity.retained199_binding"
                    );
                    io::epoch199_append::validate_retained_snapshot(
                        g,
                        &evidence["terminal_guard_snapshot"],
                    )?;
                }
                if typed.retained_terminal_152 {
                    ensure!(
                        evidence["retained_terminal_152"] == true,
                        "guard_continuity.retained_terminal_binding"
                    );
                    io::terminal152_guard::payload_gate(&evidence["terminal_guard_sample"])?;
                }
                for key in [
                    "Id",
                    "LoadState",
                    "ActiveState",
                    "SubState",
                    "InvocationID",
                    "Triggers",
                    "Unit",
                    "Result",
                ] {
                    ensure!(
                        evidence["timer"].get(key).is_some_and(Value::is_string),
                        "guard_continuity.timer_required_field"
                    );
                }
                ensure!(
                    evidence["timer"]["LoadState"] == "loaded"
                        && evidence["timer"]["SubState"] == "waiting"
                        && evidence["timer"]["Result"] == "success"
                        && evidence["timer"]["Triggers"] == g.unit
                        && evidence["timer"]["InvocationID"]
                            .as_str()
                            .is_some_and(|v| digest(v, 32)),
                    "guard_continuity.timer_policy"
                );
                ensure!(
                    proof["iid"] == evidence["native"]["InvocationID"]
                        && proof["currently_armed"]
                            == json!(!typed.retained_terminal_152 && !typed.retained_terminal_199)
                        && proof["no_trip"] == true
                        && proof["command_and_binary_bound"] == true
                        && proof["receipt_fresh"] == true,
                    "guard_continuity.authenticated_proof"
                );
                ensure!(
                    evidence["timer"]["Id"] == g.timer
                        && evidence["timer"]["ActiveState"] == "active"
                        && evidence["timer"]["Unit"] == g.unit,
                    "guard_continuity.timer_binding"
                );
            }
            ensure!(le["timer"] == re["timer"], "guard_continuity.timer_policy");
            match g.kind {
                GuardKind::Epoch199Append => {
                    if left["retained_terminal_199"] == true
                        || right["retained_terminal_199"] == true
                    {
                        let mut l = left.clone();
                        let mut r = right.clone();
                        ensure!(
                            l["retained_terminal_199"] == true
                                && r["retained_terminal_199"] == true,
                            "guard_continuity.retained199_phase_changed"
                        );
                        l.as_object_mut()
                            .context("retained199 left proof")?
                            .remove("iid");
                        r.as_object_mut()
                            .context("retained199 right proof")?
                            .remove("iid");
                        ensure!(
                            l == r
                                && le["terminal_guard_snapshot"]["context"]
                                    == re["terminal_guard_snapshot"]["context"],
                            "guard_continuity.retained199_promises_changed"
                        );
                        let ls = &le["terminal_guard_snapshot"]["full_family"];
                        let rs = &re["terminal_guard_snapshot"]["full_family"];
                        let context = crate::fleet::terminal199_context::Retained::load(
                            &serde_json::from_value(
                                le["terminal_guard_snapshot"]["context"].clone(),
                            )?,
                        )?;
                        let enrolled = io::epoch199_append::enrollment_for_context(g, &context)?;
                        ensure!(
                            enrolled.normalize_guard_retained(ls, rs, &context)? == *ls,
                            "guard_continuity.retained199_family_policy"
                        );
                        ensure!(
                            retained199_project(
                                g,
                                &le["native"],
                                &ls[&g.unit],
                                Retained199View::Evidence
                            )? == retained199_project(
                                g,
                                &re["native"],
                                &rs[&g.unit],
                                Retained199View::Evidence
                            )?,
                            "guard_continuity.retained199_native_policy"
                        );
                        // Authenticate the actual complete census family under the
                        // already qualified retained-v2 policy. Keep every raw row;
                        // normalize only comparison views of completed guard fires
                        // and the existing protective timer deadline.
                        let mut census_left = json!({});
                        let mut census_right = json!({});
                        for name in crate::fleet::ordinary199::FAMILY {
                            census_left[name] = ca
                                .get(name)
                                .context("retained199 left family member absent")?
                                .clone();
                            census_right[name] = cb
                                .get(name)
                                .context("retained199 right family member absent")?
                                .clone();
                        }
                        let normalized_census = enrolled.normalize_guard_retained(
                            &census_left,
                            &census_right,
                            &context,
                        )?;
                        ensure!(
                            normalized_census == census_left,
                            "guard_continuity.retained199_census_family_policy"
                        );
                        let lp = retained199_project(
                            g,
                            ca.get(&g.unit).context("retained199 left census")?,
                            &ls[&g.unit],
                            Retained199View::Census,
                        )?;
                        let rp = retained199_project(
                            g,
                            cb.get(&g.unit).context("retained199 right census")?,
                            &rs[&g.unit],
                            Retained199View::Census,
                        )?;
                        ensure!(lp == rp, "guard_continuity.retained199_census_policy");
                        ca.insert(g.unit.clone(), lp);
                        cb.insert(g.unit.clone(), rp);
                        ca.insert(g.timer.clone(), census_left[&g.timer].clone());
                        cb.insert(g.timer.clone(), normalized_census[&g.timer].clone());
                    } else {
                        io::epoch199_append::compare(
                            g,
                            (left, right),
                            (le, re),
                            (&mut ca, &mut cb),
                        )?;
                    }
                }
                GuardKind::Epoch199Http500Append => {
                    use crate::fleet::recovery199_contract as r;
                    let binding = g.plan.as_ref().context("recovery199 guard enrollment")?;
                    let p = r::load(&serde_json::from_value(json!(binding))?)?;
                    r::guard::compare(
                        &p,
                        &le["epoch199_http500_append_continuity"],
                        &re["epoch199_http500_append_continuity"],
                    )?;
                    let mut pair = [left.clone(), right.clone()];
                    for v in &mut pair {
                        ensure!(
                            v.as_object_mut()
                                .context("recovery199 typed guard")?
                                .remove("iid")
                                .is_some(),
                            "recovery199 typed IID missing"
                        );
                    }
                    ensure!(
                        pair[0] == pair[1],
                        "recovery199 typed guard owner or resource promise changed"
                    );
                    let left_full = Value::Object(ca.clone());
                    let right_full = Value::Object(cb.clone());
                    let normalized = p.normalize_guard(&left_full, &right_full)?;
                    for unit in [r::GUARD, r::TIMER] {
                        cb.insert(unit.into(), normalized[unit].clone());
                    }
                }
                GuardKind::Cached145Continuous => {
                    io::cached145_continuous::compare(
                        g,
                        (left, right),
                        (le, re),
                        (&mut ca, &mut cb),
                    )?;
                }
                GuardKind::Standalone => ensure!(
                    left == right && le == re,
                    "guard_continuity.standalone_changed"
                ),
                GuardKind::AdaptiveController => {
                    let mut l = left
                        .as_object()
                        .context("guard_continuity.proof_object")?
                        .clone();
                    let mut r = right
                        .as_object()
                        .context("guard_continuity.proof_object")?
                        .clone();
                    ensure!(
                        l.remove("iid")
                            .and_then(|v| v.as_str().map(str::to_owned))
                            .is_some_and(|v| digest(&v, 32))
                            && r.remove("iid")
                                .and_then(|v| v.as_str().map(str::to_owned))
                                .is_some_and(|v| digest(&v, 32))
                            && l == r,
                        "guard_continuity.protected_owners_or_floor"
                    );
                    let mut le_policy = le.clone();
                    let mut re_policy = re.clone();
                    le_policy["native"] = project(g, &le["native"], false)?;
                    re_policy["native"] = project(g, &re["native"], false)?;
                    // The IO loader authenticated both fresh terminal samples.
                    // Available disk may change between real guard fires; retain
                    // the typed floor, custody and unarmed disposition above.
                    if left["retained_terminal_152"] == true {
                        le_policy
                            .as_object_mut()
                            .unwrap()
                            .remove("terminal_guard_sample");
                        re_policy
                            .as_object_mut()
                            .unwrap()
                            .remove("terminal_guard_sample");
                    }

                    ensure!(le_policy == re_policy, "guard_continuity.native_policy");
                    let lp = project(
                        g,
                        ca.get(&g.unit)
                            .context("guard_continuity.census_guard_absent")?,
                        true,
                    )?;
                    let rp = project(
                        g,
                        cb.get(&g.unit)
                            .context("guard_continuity.census_guard_absent")?,
                        true,
                    )?;
                    ensure!(lp == rp, "guard_continuity.census_guard_policy");
                    ca.insert(g.unit.clone(), lp);
                    cb.insert(g.unit.clone(), rp);
                }
            }
        }
        ensure!(ca == cb, "guard_continuity.other_native_census");
        Ok(())
    }
}
// Only the exact retained original 199 guard uses this installed profile.
// Snapshot validation and the retained-v2 family normalizer authenticate its
// context, original owners, command, sandbox and hard promises before projection.
#[derive(Clone, Copy)]
enum Retained199View {
    Evidence,
    Census,
}
fn retained199_project(
    g: &GuardSpec,
    native: &Value,
    authenticated: &Value,
    view: Retained199View,
) -> Result<Value> {
    ensure!(
        matches!(g.kind, GuardKind::Epoch199Append)
            && g.unit == crate::fleet::ordinary199::GUARD
            && g.timer == crate::fleet::ordinary199::TIMER,
        "guard_continuity.retained199_scope"
    );
    let mut row = native
        .as_object()
        .context("retained199 native object")?
        .clone();
    for (key, expected) in [
        ("Id", g.unit.as_str()),
        ("LoadState", "loaded"),
        ("Type", "oneshot"),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ExecMainCode", "1"),
        ("Restart", "no"),
        ("User", "root"),
        ("MemoryAccounting", "yes"),
        ("MemoryMax", "536870912"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "1s"),
        ("TasksMax", "256"),
        ("RuntimeMaxUSec", "infinity"),
        ("ControlGroup", ""),
    ] {
        ensure!(
            native[key] == expected,
            "guard_continuity.retained199_native_profile: {key}"
        );
    }
    ensure!(
        digest(string(native, "/InvocationID")?, 32)
            && matches!(
                (native["ActiveState"].as_str(), native["SubState"].as_str()),
                (Some("inactive"), Some("dead")) | (Some("active"), Some("exited"))
            ),
        "guard_continuity.retained199_completed_lifecycle"
    );
    if matches!(view, Retained199View::Evidence) {
        ensure!(
            native["TimeoutStartUSec"] == "5min"
                && native["TriggeredBy"] == g.timer
                && native["Triggers"] == ""
                && native["InvocationID"] == authenticated["InvocationID"],
            "guard_continuity.retained199_evidence_binding"
        );
    } else if let Some(timeout) = native.get("TimeoutStartUSec") {
        ensure!(
            timeout == "5min",
            "guard_continuity.retained199_census_timeout"
        );
    }
    let identity = command(g, native)?;
    ensure!(
        identity == command(g, authenticated)?,
        "guard_continuity.retained199_authenticated_command"
    );
    for (key, value) in &row {
        if matches!(
            key.as_str(),
            "InvocationID"
                | "MainPID"
                | "ActiveState"
                | "SubState"
                | "ControlGroup"
                | "ExecMainCode"
                | "ExecStart"
                | "ExecMainPID"
                | "ExecMainStartTimestamp"
                | "ExecMainExitTimestamp"
        ) {
            continue;
        }
        if let Some(expected) = authenticated.get(key) {
            ensure!(
                value == expected,
                "guard_continuity.retained199_authenticated_native: {key}"
            );
        }
    }
    row.insert("ExecStart".into(), json!(identity));
    for key in [
        "InvocationID",
        "MainPID",
        "ActiveState",
        "SubState",
        "ControlGroup",
        "ExecMainCode",
    ] {
        row.remove(key);
    }
    if matches!(view, Retained199View::Census) {
        for key in [
            "ExecMainPID",
            "ExecMainStartTimestamp",
            "ExecMainExitTimestamp",
        ] {
            if let Some(value) = row.get(key) {
                let text = value
                    .as_str()
                    .context("retained199 census execution metadata type")?;
                if key == "ExecMainPID" {
                    ensure!(
                        text.parse::<u64>()?.to_string() == text,
                        "retained199 census execution PID is not canonical"
                    );
                }
                // Preserve field membership, and every unrelated setting. This
                // comparison marker never replaces a raw native observation.
                row.insert(key.into(), json!("completed-guard-execution"));
            }
        }
    }
    Ok(Value::Object(row))
}

fn command(g: &GuardSpec, native: &Value) -> Result<String> {
    let raw = string(native, "/ExecStart")?;
    let (identity, display) = raw
        .split_once(" ; start_time=")
        .context("guard_continuity.command_shape")?;
    let canonical = format!(
        "{identity} ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
    );
    ensure!(
        crate::pipeline_status::same_exec_start(raw, &canonical)
            && (display.ends_with(" ; code=(null) ; status=0/0 }")
                || display.ends_with(" ; code=exited ; status=0/SUCCESS }")
                || display.ends_with(" ; code=exited ; status=0/0 }")
                || display.ends_with(" ; code=exited ; status=0 }")),
        "guard_continuity.command_outcome"
    );
    let hashed = raw
        .split_once(" ; ignore_errors=")
        .context("guard_continuity.command_identity")?
        .0;
    ensure!(
        hex_lower(&Sha256::digest(hashed.as_bytes())) == g.command_sha256
            && hashed.contains(
                g.binary
                    .path
                    .to_str()
                    .context("guard_continuity.binary_path")?
            ),
        "guard_continuity.command_binding"
    );
    Ok(identity.to_owned())
}
fn project(g: &GuardSpec, native: &Value, legacy: bool) -> Result<Value> {
    let mut row = native
        .as_object()
        .context("guard_continuity.native_object")?
        .clone();
    for key in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "Result",
        "ExecMainStatus",
        "ControlGroup",
        "ExecStart",
    ] {
        ensure!(
            native.get(key).is_some_and(Value::is_string),
            "guard_continuity.native_required_field"
        );
    }
    let iid = string(native, "/InvocationID")?;
    let pid = string(native, "/MainPID")?.parse::<u64>()?;
    let state = (
        string(native, "/ActiveState")?,
        string(native, "/SubState")?,
    );
    ensure!(
        native["Id"] == g.unit
            && native["LoadState"] == "loaded"
            && digest(iid, 32)
            && native["NRestarts"] == "0"
            && native["Result"] == "success"
            && native["ExecMainStatus"] == "0"
            && matches!(
                state,
                ("inactive", "dead") | ("active", "exited") | ("activating", "start")
            )
            && (pid == 0 || state == ("activating", "start"))
            && (native["ControlGroup"] == ""
                || native["ControlGroup"] == format!("/system.slice/{}", g.unit)),
        "guard_continuity.native_lifecycle"
    );
    if legacy {
        ensure!(native["Type"] == "oneshot", "guard_continuity.oneshot_type");
    } else {
        for key in [
            "Type",
            "TimeoutStartUSec",
            "Restart",
            "User",
            "MemoryAccounting",
            "MemoryMax",
            "MemorySwapMax",
            "CPUQuotaPerSecUSec",
            "TasksMax",
            "RuntimeMaxUSec",
            "ExecMainCode",
            "Triggers",
            "TriggeredBy",
        ] {
            ensure!(
                native.get(key).is_some_and(Value::is_string),
                "guard_continuity.policy_required_field"
            );
        }
        ensure!(
            native["Type"] == "oneshot"
                && native["TimeoutStartUSec"] == "2min"
                && native["MemoryMax"] == "1073741824"
                && native["MemorySwapMax"] == "infinity"
                && native["CPUQuotaPerSecUSec"] == "2s"
                && native["TasksMax"] == "512"
                && native["RuntimeMaxUSec"] == "infinity",
            "guard_continuity.reviewed_legacy_bounds"
        );
        ensure!(
            native["Restart"] == "no"
                && (native["User"] == "" || native["User"] == "root")
                && native["MemoryAccounting"] == "yes"
                && matches!(native["ExecMainCode"].as_str(), Some("0" | "1")),
            "guard_continuity.native_safety_policy"
        );
    }
    row.insert("ExecStart".into(), json!(command(g, native)?));
    for key in [
        "InvocationID",
        "MainPID",
        "ActiveState",
        "SubState",
        "ControlGroup",
    ] {
        row.remove(key);
    }
    if !legacy {
        row.remove("ExecMainCode");
    }
    Ok(Value::Object(row))
}
pub(super) fn components(checks: &[(&str, bool)]) -> Result<()> {
    let failed = checks
        .iter()
        .filter_map(|(label, ok)| (!ok).then_some(*label))
        .collect::<Vec<_>>();
    ensure!(
        failed.is_empty(),
        "accounting changed: {}",
        failed.join(",")
    );
    Ok(())
}

#[cfg(test)]
#[path = "guard_continuity_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "retained199_guard_continuity_tests.rs"]
mod retained199_tests;
