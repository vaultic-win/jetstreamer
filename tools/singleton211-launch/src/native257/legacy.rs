use super::*;
// Each registered inert package invokes only the pinned harness and guard.
// Its successor still verifies all four installed definitions and current publication.
const PREPARED_V1: &str =
    "/var/lib/jetstreamer/horizon-native257-prepared-takeover-guard-v1/prepared.json";
const PREPARED_V1_SHA: &str = "4f1ed487e65e6f93e442672ee47df25c9dbc64e2b58a7593e35de88d199525d3";
const LAUNCHER_V1: &str =
    "/var/lib/jetstreamer/horizon257-native-launch-20261120-v1/horizon-native257-launch";
const LAUNCHER_V1_SHA: &str = "34ba46673bd5898e0f9a728a6f0f6aa8d05b4a393165bd4b9a98435ca57e5b6c";
const PREPARED_V10: &str =
    "/var/lib/jetstreamer/horizon-native257-prepared-early-guard-v151-v1/prepared.json";
const PREPARED_V10_SHA: &str = "3ced6828183000dd03b92c263705ae80af059e7d03a930038b20c6089d5c8cc6";
const LAUNCHER_V10: &str =
    "/var/lib/jetstreamer/horizon257-native-launch-20261120-v10/horizon-native257-launch";
const LAUNCHER_V10_SHA: &str = "32311e67aab80ef8bf003f47a3f333833f057c7fb9b4c098bece15a06c1c0672";
const REGISTERED: [(&str, &str, &str, &str, &str); 4] = [
    (
        PREPARED_V1,
        PREPARED_V1_SHA,
        LAUNCHER_V1,
        LAUNCHER_V1_SHA,
        "3a9d4e749c78893880c51f0ddd9aa28965fe16f9",
    ),
    (
        PREPARED_V10,
        PREPARED_V10_SHA,
        LAUNCHER_V10,
        LAUNCHER_V10_SHA,
        "1b19df41369667443eb931c529ce3cc96d221c66",
    ),
    (
        "/var/lib/jetstreamer/horizon-native257-prepared-cold-closed266-with265-v1/prepared.json",
        "525cc0b7e6db806817a4edfcbf1891d0ed4df215b15fb5ac4f243169892d08d1",
        "/var/lib/jetstreamer/horizon257-native-launch-20261121-v14/horizon-native257-launch",
        "33f192bec415e3fc02ebdeb8578225251fd334a025fc39381ea4fa89f18b8172",
        "2c0d1a5f12b65e281adfdb6f84bd91ce1d807980",
    ),
    (
        "/var/lib/jetstreamer/horizon-native257-prepared-guard-reap-closed266-v220/prepared.json",
        "faffd3762e74b2de405ca258d6e74a04711845d5a81ec130ec3735799a8bfdb5",
        "/var/lib/jetstreamer/horizon257-native-launch-closed266-v18/horizon-native257-launch",
        "0ae705e627fbece19e180d70a45c71799098e1c0f4c4faa0e219fe665bdf3715",
        "10fa020a5de302a36745fc196819759bfd141bd7",
    ),
];
pub(super) fn prepared_transition(
    reference: &Bound,
    gate: &Bound,
    current_gate: &Bound,
    old_source: &Value,
    current_source: &Value,
) -> Result<()> {
    let mut old = publication::prepared_artifacts(old_source)?;
    let mut current = publication::prepared_artifacts(current_source)?;
    ensure!(
        old["launcher"]["artifact"] == json!(gate)
            && current["launcher"]["artifact"] == json!(current_gate),
        "launcher publication differs from prepared or running image"
    );
    for (path, sha, predecessor, predecessor_sha, commit) in REGISTERED {
        if reference != &Bound::new(path, sha) {
            continue;
        }
        ensure!(
            gate == &Bound::new(predecessor, predecessor_sha)
                && old["launcher"]["source_commit"] == commit
                && current_gate.path == Path::new(LAUNCHER),
            "unknown prepared launcher transition"
        );
        old.remove("launcher");
        current.remove("launcher");
        break;
    }
    ensure!(old == current, "prepared executable or source changed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_registered_inert_preparation_can_transfer_to_the_successor() {
        for (path, sha, previous, old_sha, commit) in REGISTERED {
            let reference = Bound::new(path, sha);
            let old_gate = Bound::new(previous, old_sha);
            let new_gate = Bound::new(LAUNCHER, "d".repeat(64));
            let source = |gate: &Bound, commit: &str| {
                json!({"artifacts":[
            {"role":"launcher","artifact":gate,"source_commit":commit},
            {"role":"guard","artifact":Bound::new(GUARD,GUARD_SHA),"source_commit":"b".repeat(40)},
            {"role":"harness","artifact":Bound::new(HARNESS,HARNESS_SHA),"source_commit":"b".repeat(40)}]})
            };
            let old = source(&old_gate, commit);
            let new = source(&new_gate, &"e".repeat(40));
            prepared_transition(&reference, &old_gate, &new_gate, &old, &new).unwrap();
            let other = Bound::new(path, "a".repeat(64));
            assert!(prepared_transition(&other, &old_gate, &new_gate, &old, &new).is_err());
            prepared_transition(&other, &new_gate, &new_gate, &new, &new).unwrap();
            for role in 0..3 {
                let mut changed = old.clone();
                changed["artifacts"][role]["source_commit"] = json!("f".repeat(40));
                assert!(
                    prepared_transition(&reference, &old_gate, &new_gate, &changed, &new).is_err()
                );
            }
        }
    }
}
