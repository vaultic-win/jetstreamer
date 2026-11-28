//! Ignore only systemd's display timestamps/PID, never gate or owner changes.
use serde_json::Value;

fn command(value: &str) -> Option<(&str, &str, &str)> {
    let (identity, metadata) = value.split_once(" ; start_time=")?;
    if !identity.starts_with("{ path=")
        || identity.matches(" ; argv[]=").count() != 1
        || !identity.ends_with(" ; ignore_errors=no")
        || value.matches(" ; start_time=").count() != 1
    {
        return None;
    }
    let fields: Vec<_> = metadata.strip_suffix(" }")?.split(" ; ").collect();
    if fields.len() != 5
        || !fields[0].starts_with('[')
        || !fields[0].ends_with(']')
        || !fields[1].starts_with("stop_time=[")
        || !fields[1].ends_with(']')
        || fields[2].strip_prefix("pid=")?.parse::<u32>().is_err()
        || !fields[3].starts_with("code=")
        || !fields[4].starts_with("status=")
    {
        return None;
    }
    Some((identity, fields[3], fields[4]))
}

pub(super) fn same_gate(expected: &Value, current: &Value) -> bool {
    if expected == current {
        return true;
    }
    let Some((a, b)) = expected["publisher"]["ExecStart"]
        .as_str()
        .zip(current["publisher"]["ExecStart"].as_str())
    else {
        return false;
    };
    if !command(a).zip(command(b)).is_some_and(|(a, b)| a == b) {
        return false;
    }
    let mut normalized = current.clone();
    normalized["publisher"]["ExecStart"] = expected["publisher"]["ExecStart"].clone();
    normalized == *expected
}

#[cfg(test)]
mod tests {
    use {super::*, serde_json::json};
    #[test]
    fn reload_display_changes_never_mask_other_gate_changes() {
        let old = "{ path=/sealed/tool ; argv[]=/sealed/tool /sealed/plan --run ; ignore_errors=no ; start_time=[now] ; stop_time=[then] ; pid=123 ; code=exited ; status=0 }";
        let reset = old
            .replace("[now]", "[n/a]")
            .replace("[then]", "[n/a]")
            .replace("pid=123", "pid=0");
        let a = json!({"publisher":{"ExecStart":old,"InvocationID":"original","MainPID":"0","NRestarts":"0"},"archive_identity":{"inode":123},"full_gate_sha256":"same"});
        let mut b = a.clone();
        b["publisher"]["ExecStart"] = json!(reset);
        assert!(same_gate(&a, &b));
        for (pointer, value) in [
            ("/publisher/InvocationID", json!("replacement")),
            ("/publisher/MainPID", json!("99")),
            ("/publisher/NRestarts", json!("1")),
            ("/archive_identity/inode", json!(124)),
            ("/full_gate_sha256", json!("changed")),
        ] {
            let mut bad = b.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(!same_gate(&a, &bad), "{pointer}");
        }
        for bad in [
            reset.replace("status=0", "status=1"),
            reset.replace("code=exited", "code=killed"),
            reset.replace("--run", "--other"),
            reset.replace("ignore_errors=no", "ignore_errors=yes"),
            reset.replace("pid=0", "pid=bad"),
        ] {
            b["publisher"]["ExecStart"] = json!(bad);
            assert!(!same_gate(&a, &b));
        }
    }
}
