//! Retry7's actual final guard, the first two-peer fleet after it stopped, and the untouched parent.
use super::*;
const LAST: &str = "c7765764ff52450ba71e8105439b9197";
const PLAN: &str = "8ec877d2d8c2dcf664ecb747f9177843abb6d7312957b39f8d9ea5a2b28aef5d";
const STOP7: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1/preparation/epoch170/local3retry7/guard-state/receipts/stop-completion.json";
const INTENT7: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1/preparation/epoch170/local3retry7/guard-state/receipts/stop-intent.json";
const STOP7_SHA: &str = "a7b35a191ec0e07863aa0357b2e48e37ca18e3b3a1d49e2ea51fa8a53f0d5a28";
const INTENT7_SHA: &str = "bdec2f5f6aefb0eb863ce6b9486ecf2e110fb16e9c4d00262126b4632a9425bf";
const ERROR: &str = "completed167 before allocation: bounded writer query failed; phase=\"before retained-tree verification\"; elapsed_millis=10001; exit_code=None; signal=Some(9); stdout_bytes=0; stderr_bytes=0; stdout_prefix=\"\"; stderr_prefix=\"\"";
pub(super) fn fleet() -> Bound {
    exact(
        "/var/lib/jetstreamer/horizon_runtime_data/root0615-terminal170-recovery-20261120-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json",
        "0ff6c812fc810ad5d0d019c1c53f3fac806814aa5285b5a6574243754f08ed62",
    )
}
pub(super) fn check_peers(e: &Value) -> Result<()> {
    let r = &e["active167"];
    ensure!(
        r["unit"] == peer::NEXT167
            && r["invocation_id"] == "93e60160c9164d3781a5b544fc2a48b4"
            && r["main_pid"] == 2472615
            && r["main_start_ticks"] == 349632179
            && r["admission"]["sha256"]
                == "31699c6f7dcf52f3bbf323cc1801120a4c4b2328587687ef1b6d70aa2ca4941a"
            && r["guard_protection"]["sha256"]
                == "fa95b8b0cf48bbb3090dfb2eadadae1f54b841541e3067cacdb88a7c614092df"
            && e["active166"] == peer::owner(),
        "both actual admitted peers required"
    );
    Ok(())
}
fn stop7_shape(stop: &Value, intent: &Value) -> Result<()> {
    stop_chain_shape(stop, intent, LAST, INTENT7, PLAN)?;
    let sample = &intent["sample"];
    ensure!(
        sample["guard_invocation_id"] == "b915afd1e374464c9ac3a91c3d10a38b"
            && sample["guard_sha256"]
                == "6b9b398287815ca9581ed3fbd5e15e772eceef3eacd31a7463822288b5641c6a"
            && sample["DATA_fulfillment_observation_error"] == ERROR
            && sample["minimum_free_bytes"] == RAW_FLOOR
            && sample["maximum_root_physical_bytes"] == ROOT_CAP
            && sample["fulfilled_existing_DATA_bytes"] == 0,
        "retry7 writer timeout and terminal identity required"
    );
    Ok(())
}
pub(super) fn check(r: &Request, p: &Plan) -> Result<()> {
    ensure!(
        r.stopped_retry7_170 == exact(STOP7, STOP7_SHA)
            && r.stop_intent_retry7_170 == exact(INTENT7, INTENT7_SHA),
        "retry7 stop bindings differ"
    );
    let stop = bound(&r.stopped_retry7_170)?;
    let intent = bound(&r.stop_intent_retry7_170)?;
    stop7_shape(&stop, &intent)?;
    let historical = bound(&fleet())?;
    let event = exact(
        "/var/lib/jetstreamer/horizon_runtime_data/root0615-terminal170-recovery-20261120-v1/event.json",
        "e6aa44d51e8375e10428372ad2e15d391a8ac866d7bdb39e6b979f75761b2760",
    );
    let transition = bound(&event)?;
    ensure!(
        historical["latest_terminal170_observation"] == serde_json::to_value(&event)?
            && transition["terminal_stop"] == serde_json::to_value(&r.stopped_retry7_170)?
            && transition["intent"] == serde_json::to_value(&r.stop_intent_retry7_170)?
            && transition["capacity_released"] == 0
            && transition["terminal"] == stop["terminal"]
            && transition["active_replay_epochs"] == json!([166, 167]),
        "terminal fleet lineage differs"
    );
    let staged = bound(&p.fleet)?;
    let failed = terminal8::authenticate(&staged["latest_terminal_retry8_170"])?;
    ensure!(
        failed["stopped_retry8_170"] == serde_json::to_value(&r.stopped_retry8_170)?
            && failed["stop_intent_retry8_170"] == serde_json::to_value(&r.stop_intent_retry8_170)?
            && failed["failed_setup_retry8_170"]
                == serde_json::to_value(&r.failed_setup_retry8_170)?,
        "retry8 failure bindings differ"
    );
    ensure!(
        staged["latest_terminal170_observation"] == historical["latest_terminal170_observation"]
            && staged["all_reservation_ending_bytes"] == 0
            && staged["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true
            && staged["complete_DATA_bytes"] == COMPLETE_DATA
            && staged["complete_projected_memory_bytes"] == 761_131_708_416u64,
        "staged fleet lost terminal lineage or original promises"
    );
    let parent = p.fresh_subtree.parent().context("retry9 parent")?;
    check_parent(parent)
}

fn check_parent(parent: &Path) -> Result<()> {
    let recorded = bound(&exact(
        "/var/lib/jetstreamer/horizon_runtime_data/root-zero-166167-stop-20261120-v1/SUCCESSOR_ROOTS_BEFORE_WITNESS.json",
        "d9e8ae44c9726811b2104cac494b4ccc4a5ef3cb7bf56e5cadec6bf6f9b4be89",
    ))?;
    let mut rows = recorded["roots"]
        .as_array()
        .context("precreated roots")?
        .iter()
        .filter(|row| row["epoch"] == 170);
    let row = rows.next().context("missing original epoch 170 root")?;
    ensure!(
        rows.next().is_none() && row["path"].as_str().map(Path::new) == Some(parent),
        "wrong original epoch 170 root"
    );
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent
            == Path::new(
                "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1"
            )
            && parent.canonicalize()? == parent
            && m.is_dir()
            && row["dev"].as_u64() == Some(m.dev())
            && row["ino"].as_u64() == Some(m.ino())
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o7777 == 0o700,
        "existing nested retry7 parent identity changed"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn corroborates_the_retry9_parent_against_the_original_precreation_receipt() {
        let parent = Path::new(
            "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1",
        );
        check_parent(parent).unwrap();
        assert!(check_parent(parent.parent().unwrap()).is_err());
    }
    #[test]
    fn authentic_stop7_rejects_mixed_guard_and_terminal() {
        let stop = bound(&exact(STOP7, STOP7_SHA)).unwrap();
        let intent = bound(&exact(INTENT7, INTENT7_SHA)).unwrap();
        stop7_shape(&stop, &intent).unwrap();
        let mut changed = intent.clone();
        changed["sample"]["DATA_fulfillment_observation_error"] = json!("other failure");
        assert!(stop7_shape(&stop, &changed).is_err());
        let mut changed = stop;
        changed["terminal"]["pid"] = json!(2485831);
        assert!(stop7_shape(&changed, &intent).is_err());
    }
}
