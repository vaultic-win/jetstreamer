//! Accept a separately typed, sealed resource-only recovery lineage. Original
//! routine completion and parent receipts retain their genuine clocks/schema.
use super::*;
use anyhow::Context;
use sha2::Digest;
#[path = "closed145_reload_source_loader.rs"]
mod closed145_reload_source_loader;
#[path = "recovered_resource_frame.rs"]
mod contract;
#[path = "input137_source_loader.rs"]
mod input137_source_loader;
#[path = "retained_input137_capture_scope.rs"]
mod retained_input137_capture_scope;
#[path = "retry0005_source_loader.rs"]
mod retry0005_source_loader;

const CAPTURE_TOOL_SHA: &str = "f719fb3566fbaa09098eadac7390a0587c5aa74727d792d4a10b305643e194eb";
const CHAIN_CAPTURE_TOOL_SHA: &str =
    "14ba6123094523d41a4193aa9018f810ca62ac5237832ec8cce1af36bb5ff365";
const NATIVE154_CAPTURE_TOOL_SHA: &str =
    "3f91bd309693f462008f3fcc559ef20ffdeb676eb1a3617dc88c64be379e8a96";

const NORMALIZED_NATIVE154_CAPTURE_SHA: &str =
    "f46dc4f18b3f553439370c41c0267b692ded168fcd2fef3f95591ff003a643df";

const COHORT183_CAPTURE_TOOL_SHA: &str =
    "a3c716f7f810d21d433539794d2e44729b761539624c373a66b3a79fb051d824";
const REPEATABLE_CAPTURE_TOOL_SHA: &str =
    "2742167e7fb1fe011de54b9f03323b20504c7c515f608391c612cca3a9ff9d89";
const VERIFIER183_CAPTURE_TOOL_SHA: &str =
    "69e53f7e19745b49b8fcb75bed95ca7d423cfc95487ad3f2ec8ca82617b2351e";

const DELIVERY184_CAPTURE_TOOL_SHA: &str =
    "989f90ecdc28a89fcf62b6f810c9201ac2eace0542c36c71472d9be440ae2058";

const REGISTERED183_CAPTURE_TOOL_SHA: &str =
    "14ad24282b0620a70dae5f80bf4fd9803d0b1deea59a37a56e442cfcb5a97ecf";
// Retain the actual accepted v3 frame while adding the qualified v4 contract.
const PLUGIN154_V3_CAPTURE_TOOL_SHA: &str =
    "af3ba92c1f67530c33a9d96ffc466145f73f07f08cc1488de9fb3eb00a33dce5";
const PLUGIN154_CAPTURE_TOOL_SHA: Option<&str> =
    Some("ca5e1d576320d409731232b471d87b1c5eab3b82cfe16d871dd17c56890d7ef6");
// Actual separately qualified Frame6 capture; the prior Frame4 remains accepted.
const PLUGIN154_FRAME6_CAPTURE_TOOL_SHA: &str =
    "1778a5b4405622710d17f981a68fbd6ac8d67f0ab200e986533b265a5fd567f7";
const PLUGIN154_FRAME7_CAPTURE_TOOL_SHA: &str =
    "2c57a8422795bf9401215a5c3640d47786635e3b8b2cb9cda9bca842f1f2929d";
const PLUGIN154_FRAME8_CAPTURE_TOOL_SHA: &str =
    "4d54ac9b4e72f558a06dbf9c9d93f8f53dd7adffb5f52637941ffd8bed19a84c";
const PLUGIN154_FRAME9_CAPTURE_TOOL_SHA: &str =
    "d4d7ade1a587f320369af33217312767c7cbbd3043322e4ea09e303943540f30";

// Actual separately qualified combined epoch 141 and retry 0003 Frame10.
const RETRY0003_FRAME10_CAPTURE_TOOL_SHA: Option<&str> =
    Some("38c5b390af0ea4321fb3ecce45a4f74999db882958fbdd05611a4ba0e7454d48");

// Actual separately qualified reader-correction successor; retain Frame10 above.
const RETRY0003_FRAME11_CAPTURE_TOOL_SHA: &str =
    "e273ef29773a79140de8320e22966afd0f8d80cf32fe6185aae32bfd0b6b99ac";

// Actual qualified and normally sealed terminal-first original 141 successor.
const EARLY_TERMINAL141_FRAME12_CAPTURE_TOOL_SHA: &str =
    "523360108ec4724660a39a2b9d0ff83b3fd4e9320614302f594446ee0945df98";

// Actual qualified and normally sealed projection-order successor; retain Frame12.
const EARLY_TERMINAL141_FRAME13_CAPTURE_TOOL_SHA: &str =
    "11ad91050994fc279370f4fd63433927dfd9aded46f2dba074b6b0cffd543b82";

// Preserve the qualified Frame 14 predecessor while selecting the raw-control repair.
const INPUT161_G6_FRAME14_CAPTURE_TOOL_SHA: &str =
    "026383f2da0fb854b22cda73aa3ca51a7eef32e572da883c860d5944e30c0831";
const INPUT161_G7_CAPTURE_TOOL_SHA: Option<&str> =
    Some("da2ba86ab133f388d0579008d37602ff49067f7df5b8fcbeacb3d4b47d616647");
const INPUT161_G7_DEFERRED_CAPTURE_TOOL_SHA: &str =
    "3a68117f43102498c1180844175151b1faaeffa6b22395e55e9fead5d1c247ed";
const INPUT161_G7_PRIOR16_CAPTURE_TOOL_SHA: &str =
    "f1e9728c8d7420571e0840a4c7aad7df15b90a7e376c23fe38605fab215324a4";
const RETAINED_G6_EXEC_IDENTITY_CAPTURE_SHA: &str =
    "18db4e154af9b7733a6200441dd5983a30a7a441a890644486dbabab299a1919";
const INPUT161_G6_NEXT_CAPTURE_TOOL_SHA: Option<&str> =
    Some("edca10fb1e1cb4c72409476cbd789c9a7d041dda56e1b12e399a3801b252a6f1");

const CACHED145_FRAME20_CAPTURE_TOOL_SHA: &str =
    "7ded52f2ef1f322491d7819d5b16ea96ed9891314d962f01ec1cdb5a8fccd45d";

// Qualified scoped PID1 census successor; preserve the original Frame20 pin.
const CACHED145_FRAME21_CAPTURE_TOOL_SHA: &str =
    "8fe92508bd29e1372cce6b88d6c283c5b2cc3bb7c3d3f31e0977e25b784c612f";

// Qualified independent rollover-custody successor; preserve earlier producer pins.
const CACHED145_FRAME22_CAPTURE_TOOL_SHA: &str =
    "4ddd0d7735e968d7561bd2bbad76199403fca43fed7b59e4a087eed760573dcf";

// Qualified transition successor preserves the currently accepted producer21 ancestry.
const CACHED145_FRAME23_CAPTURE_TOOL_SHA: &str =
    "9526cb9110d1a08608f44b7b2e1f0334baba153ac2cae8c59ad237871d2583f5";

// Exact producer25 binary: 219 library and 7 binary tests, normally sealed.
const CACHED145_FRAME25_CAPTURE_TOOL_SHA: &str =
    "473b13ca865f879802d93d577aea052f0d6becc19469123392a1be763ab9a3b4";

// Normally sealed producer26: 219 library and 8 binary tests.
const CACHED145_FRAME26_CAPTURE_TOOL_SHA: &str =
    "3fa515037d632bfd7410d6b561ccb2302193ceafe73e4f64e75e3625f262931e";

// Normally sealed producer33: 231 library and 9 binary tests; exact-node baseline passed.
const CACHED145_FRAME33_CAPTURE_TOOL_SHA: &str =
    "9dd1c2b42e0ee9e99f8d575838d33347d69b3659d24340e23b14605942d16e1e";

// Producer35 passed the actual retained-baseline capability only. This pin
// does not select the separate unqualified epoch137 route below.
const RETAINED_BASELINE_FRAME35_CAPTURE_TOOL_SHA: &str =
    "c9d7016b72c7c2731c96d49c9df77e8671d1e57559a18cb64b1cae8454b3f5b6";

// Qualified retry0005 Frame successor; actual retained baseline capability passed.
const RETRY0005_FRAME_CAPTURE_SHA: &str =
    "b251cbce25a75631ab808231a32edfcb0227366fcc82ffb92667d5f34c21d753";

// Root may fill this only after the effective-memory Frame tests, normal seal
// and current capability pass. It does not register input137 first entry/release.
const EFFECTIVE_MEMORY_RETRY0005_FRAME_CAPTURE_SHA: Option<&str> =
    Some("c97d413ab065c1a3455de336dd4009644e3eeaa0b8fb6e6559ed9a542225c377");
// Fill only after the v3 observer-chain Frame is independently tested and normally sealed.
const OBSERVER_CHAIN_FRAME_V3_CAPTURE_SHA: Option<&str> =
    Some("d7588b092b06ed0fef817568a06c8ac5383e5a7be59e9773969286549511b22d");
// Qualified buffered writer; keep the prior v3 capture for historical evidence.
const BUFFERED_OBSERVER_CHAIN_FRAME_V4_CAPTURE_SHA: &str =
    "6465811554ccbc97664f796d9bcce0baa361bb82febd9111ee287fdb84d32744";
// Qualified helper v3 Frame successor; preserve every older capture generation.
const HELPER_V3_BUFFERED_FRAME_V6_CAPTURE_SHA: &str =
    "7d320b8a4f4d7e87f4fa53d5c614cf13d032760533c84db5e4802928eff8e6de";
// Exact independently qualified/sealed Frame v5 that composes ordinary199 with
// cached145. The inherited local contract remains unchanged for older Frames.
const ORDINARY199_FRAME_V5_CAPTURE_SHA: &str =
    "79d4b08d0fb9a17363e85fb4b6b7462fab0a871d46fbd39ce2112240a8414acb";
// Exact normally sealed Frame v7 with actual immutable-image capability.
// Failed or pending intermediate capture digests remain unregistered.
const HELPER_V4_ADDITIVE_FRAME_CAPTURE_SHA: Option<&str> =
    Some("9981800180cabf7b6ccecb590dc460b0499cb44266becc6709f46c0525f60384");
// Exact QA-qualified and normally sealed canonical capture with genuine
// node capability; historical capture pins and dispatch remain independent.
const CANONICAL_V5_FRAME_CAPTURE_SHA: &str =
    "71d741c0a59f917a6e76ee8389efd6ce8843b50aca78a8932bb52b6565dad1d8";
// Additive retained-context capture. Native capability and a genuine current
// Frame remain separate requirements; this pin alone grants no authority.
const RETAINED199_V2_FRAME_CAPTURE_SHA: &str =
    "c30e3465987ec05870056260fb1285cbce888ba3406aa4cae57432289c0e53ca";
fn retained199_v2_selector() -> Value {
    serde_json::json!({
        "path": "/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v2/registry.json",
        "sha256": "733487fcb07438d603999234b0a0598d62261ba0c1cb0ba6003693260ebc1389"
    })
}
// The current plan may explicitly select the qualified wrapper around the same
// registry. Capture pins and the raw historical Frame selector stay unchanged.
fn retained199_v2_current_selector(selector: &Value) -> Result<bool> {
    if *selector == retained199_v2_selector() {
        return Ok(true);
    }
    let Ok(bound) =
        serde_json::from_value::<original199_input_witness_consumer::Bound>(selector.clone())
    else {
        return Ok(false);
    };
    if !original199_input_witness_consumer::is_selected_context(&bound) {
        return Ok(false);
    }
    let context = crate::fleet::terminal199_context::Retained::load(&serde_json::from_value(
        selector.clone(),
    )?)?;
    context.revalidate_inputs()?;
    Ok(serde_json::to_value(context.original_context())? == retained199_v2_selector())
}
fn retained199_v2_capture(frame: &Value) -> bool {
    frame["self_sha256"] == RETAINED199_V2_FRAME_CAPTURE_SHA
        && frame["epoch199_terminal_context"] == retained199_v2_selector()
}
// Exact successor capture passed strict QA and the normal production seal.
// The normal retained fleet policy remains unchanged; recovery199 enrollment is separate.
const TYPED_FLEET_BRIDGE_FRAME_CAPTURE_SHA: Option<&str> =
    Some("b8c5c8319ebd65d0b99ada0c2ba77efbd22b91e269f570effbc806044a1763a5");
fn typed_bridge_capture_with_pin(frame: &Value, pin: Option<&str>) -> bool {
    pin.is_some_and(|sha| {
        sha.len() == 64
            && sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && sha != RETAINED199_V2_FRAME_CAPTURE_SHA
            && frame["self_sha256"] == sha
            && frame["epoch199_terminal_context"] == retained199_v2_selector()
            && frame["epoch199_http500_capture_registration"].is_null()
            && frame["epoch199_http500_recovery_enrollment"].is_null()
    })
}
// Remains disabled until Root completes the new CLI QA and normal production seal.
// The exact new artifact SHA must be inserted by that independently audited transition.
const TERMINAL145_ANCESTRY_FRAME_CAPTURE_SHA: Option<&str> =
    Some("fe41252369a0bf84d8ac5cf8e5dd79ef24cb38b409c1e94b4bb828aaf8909bdc");
// Exact image passed full native capability and genuine 01:58 capture after closed-family QA.
const CLOSED145_FAMILY_FRAME_CAPTURE_SHA: Option<&str> =
    Some("ed4fcc72ea0a6c9824360803aefd05b3cacdc0400ea923b4a6e10506a11d94a5");
// Root inserts only a separately qualified and normally sealed successor CLI digest.
const CLOSED145_INACTIVE_TIMER_RELOAD_CAPTURE_SHA: Option<&str> =
    Some("6c8fe3a05a03d57ca933b83d02a027b516aad121760dd41ce553f49268669f2e");
// Independently qualified426-case library and50-case CLI; genuine10:28 capture retained.
const ACCEPTED0428_REFRESH_FRAME_CAPTURE_SHA: Option<&str> =
    Some("e0707f6f9eaa21ff2ac92bc496921b6997c402897027327f42ad968934d4e5a2");
// Qualified sealed-alias predecessor CLI; actual0558 capture and normal seal
// are preserved by the registration regressions. No first-entry authority.
const SEALED_ALIAS_PREDECESSOR_FRAME_CAPTURE_SHA: Option<&str> =
    Some("b692189704ed9001c016b1931ec6e54210104d36a5fbf787dfdd9d2505ae75eb");
// Root may fill only after genuine new CLI capability/capture; fleet support alone grants no reader authority.
const LIVE145_CENSUS_FRAME_CAPTURE_SHA: Option<&str> =
    Some("454ca6069a17ab9d917f59324a9c318dddb8c31203f5a753cb8070ee3efefec5");
fn typed_bridge_capture(frame: &Value) -> bool {
    typed_bridge_capture_with_pin(frame, TYPED_FLEET_BRIDGE_FRAME_CAPTURE_SHA)
        || typed_bridge_capture_with_pin(frame, TERMINAL145_ANCESTRY_FRAME_CAPTURE_SHA)
        || typed_bridge_capture_with_pin(frame, CLOSED145_FAMILY_FRAME_CAPTURE_SHA)
        || typed_bridge_capture_with_pin(frame, CLOSED145_INACTIVE_TIMER_RELOAD_CAPTURE_SHA)
        || typed_bridge_capture_with_pin(frame, ACCEPTED0428_REFRESH_FRAME_CAPTURE_SHA)
        || typed_bridge_capture_with_pin(frame, SEALED_ALIAS_PREDECESSOR_FRAME_CAPTURE_SHA)
        || typed_bridge_capture_with_pin(frame, LIVE145_CENSUS_FRAME_CAPTURE_SHA)
}

// Additive v2 route remains unregistered until exact Frame library/capture QA and normal seal.
const COLD185_FRAME_V2_CAPTURE_SHA: Option<&str> =
    Some("3fdb9c1384213c9a9f8cebd4b74b2a026d6fa834194030fb40b10f222bdc277a");
fn cold185_capture_with_pin(frame: &Value, pin: Option<&str>) -> bool {
    pin.is_some_and(|sha| {
        sha.len() == 64
            && sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && frame["self_sha256"] == sha
            && frame["epoch185_cold_startpre_registration"].is_object()
            && frame["epoch185_cold_lifecycle"].is_object()
            && frame["epoch199_http500_capture_registration"].is_null()
    })
}
pub(in crate::fleet) fn qualified_cold185_capture(frame: &Value) -> bool {
    cold185_capture_with_pin(frame, COLD185_FRAME_V2_CAPTURE_SHA)
}
fn validate_cold185_frame(
    frame: &Value,
    e: &contract::Evidence<'_>,
    bindings: &Value,
    now: u64,
) -> Result<()> {
    ensure!(
        qualified_cold185_capture(frame),
        "cold185 current Frame is not exact normally sealed qualified capture"
    );
    horizon_recovered_resource_frame_cold185_v2::validate_frame(
        frame,
        &horizon_recovered_resource_frame_cold185_v2::Evidence {
            observer: e.observer,
            fleet: e.fleet,
            fleet_plan: e.fleet_plan,
            prior_parent: e.prior_parent,
            prior_completion: e.prior_completion,
            prior_fleet_plan: e.prior_fleet_plan,
            transition: e.transition,
            prior_recovery: e.prior_recovery,
            fleet_transition: e.fleet_transition,
            capture_tool_sha: e.capture_tool_sha,
            cohort183_transition: e.cohort183_transition,
            cohort183_sources: e.cohort183_sources,
            native154_transition: e.native154_transition,
            native154_sources: e.native154_sources,
        },
        bindings,
        now,
    )
}

fn canonical_v5_capture(frame: &Value) -> bool {
    frame["self_sha256"] == CANONICAL_V5_FRAME_CAPTURE_SHA
}
fn helper_v4_capture(frame: &Value) -> bool {
    HELPER_V4_ADDITIVE_FRAME_CAPTURE_SHA.is_some_and(|sha| frame["self_sha256"] == sha)
}
fn ordinary199_capture(frame: &Value) -> bool {
    frame["self_sha256"] == ORDINARY199_FRAME_V5_CAPTURE_SHA
}
fn qualified_retry0005_capture(frame: &Value) -> bool {
    frame["self_sha256"] == RETRY0005_FRAME_CAPTURE_SHA
        || frame["self_sha256"] == HELPER_V3_BUFFERED_FRAME_V6_CAPTURE_SHA
        || ordinary199_capture(frame)
        || helper_v4_capture(frame)
        || canonical_v5_capture(frame)
        || retained199_v2_capture(frame)
        || typed_bridge_capture(frame)
        || qualified_cold185_capture(frame)
        || frame["self_sha256"] == BUFFERED_OBSERVER_CHAIN_FRAME_V4_CAPTURE_SHA
        || OBSERVER_CHAIN_FRAME_V3_CAPTURE_SHA.is_some_and(|sha| frame["self_sha256"] == sha)
        || EFFECTIVE_MEMORY_RETRY0005_FRAME_CAPTURE_SHA
            .is_some_and(|sha| frame["self_sha256"] == sha)
}

fn qualified_cached145_capture(frame: &Value) -> bool {
    [
        CACHED145_FRAME20_CAPTURE_TOOL_SHA,
        CACHED145_FRAME21_CAPTURE_TOOL_SHA,
        CACHED145_FRAME22_CAPTURE_TOOL_SHA,
        CACHED145_FRAME23_CAPTURE_TOOL_SHA,
        CACHED145_FRAME25_CAPTURE_TOOL_SHA,
        CACHED145_FRAME26_CAPTURE_TOOL_SHA,
        CACHED145_FRAME33_CAPTURE_TOOL_SHA,
        RETAINED_BASELINE_FRAME35_CAPTURE_TOOL_SHA,
        RETRY0005_FRAME_CAPTURE_SHA,
    ]
    .iter()
    .any(|sha| frame["self_sha256"] == *sha)
        || qualified_retry0005_capture(frame)
}

pub(super) fn accepted(
    s: &accounting::SpecView<'_>,
    b: &accounting::BundleView<'_>,
    now: u64,
) -> Result<bool> {
    let selected = s
        .phase_events
        .iter()
        .zip(b.events)
        .filter(|(binding, value)| {
            binding.schema == contract::SCHEMA || value["schema"] == contract::SCHEMA
        })
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Ok(false);
    }
    ensure!(
        selected.len() == 1,
        "recovered resource frame is duplicated"
    );
    let (selected, frame) = selected[0];
    ensure!(
        selected.schema == contract::SCHEMA
            && frame["schema"] == contract::SCHEMA
            && selected.owners.is_empty()
            && selected.clock_pointer == "/recorded_unix_seconds"
            && ([
                CAPTURE_TOOL_SHA,
                CHAIN_CAPTURE_TOOL_SHA,
                NATIVE154_CAPTURE_TOOL_SHA,
                NORMALIZED_NATIVE154_CAPTURE_SHA,
                COHORT183_CAPTURE_TOOL_SHA,
                REPEATABLE_CAPTURE_TOOL_SHA,
                VERIFIER183_CAPTURE_TOOL_SHA,
                REGISTERED183_CAPTURE_TOOL_SHA,
                "250a8822ca0bff6381b77bf4ccb322c0ab08df5c5ec49e6109c32f613977802a",
                "e63ead589a336bb5713755c77dc8326689ca6171a4c0668202bdf6fb624272cb",
                DELIVERY184_CAPTURE_TOOL_SHA,
                PLUGIN154_V3_CAPTURE_TOOL_SHA,
                PLUGIN154_FRAME6_CAPTURE_TOOL_SHA,
                PLUGIN154_FRAME7_CAPTURE_TOOL_SHA,
                PLUGIN154_FRAME8_CAPTURE_TOOL_SHA,
                PLUGIN154_FRAME9_CAPTURE_TOOL_SHA
            ]
            .iter()
            .any(|s| frame["self_sha256"] == *s)
                || frame["self_sha256"] == CACHED145_FRAME20_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME21_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME22_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME23_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME25_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME26_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME33_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == RETAINED_BASELINE_FRAME35_CAPTURE_TOOL_SHA
                || qualified_retry0005_capture(frame)
                || PLUGIN154_CAPTURE_TOOL_SHA.is_some_and(|sha| frame["self_sha256"] == sha)
                || RETRY0003_FRAME10_CAPTURE_TOOL_SHA
                    .is_some_and(|sha| frame["self_sha256"] == sha)
                || frame["self_sha256"] == RETRY0003_FRAME11_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == EARLY_TERMINAL141_FRAME12_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == EARLY_TERMINAL141_FRAME13_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == INPUT161_G6_FRAME14_CAPTURE_TOOL_SHA
                || INPUT161_G6_NEXT_CAPTURE_TOOL_SHA
                    .is_some_and(|sha| frame["self_sha256"] == sha)
                || (INPUT161_G7_CAPTURE_TOOL_SHA.is_some_and(|sha| frame["self_sha256"] == sha)
                    || (frame["self_sha256"] == INPUT161_G7_DEFERRED_CAPTURE_TOOL_SHA
                        || (frame["self_sha256"] == INPUT161_G7_PRIOR16_CAPTURE_TOOL_SHA
                            || frame["self_sha256"] == RETAINED_G6_EXEC_IDENTITY_CAPTURE_SHA)))),
        "recovered resource frame has foreign scope, owners, or capture artifact"
    );
    let bindings = &frame["bindings"];
    for (key, expected) in [
        ("observer", s.observer),
        ("fleet", s.fleet),
        ("fleet_plan", s.fleet_plan),
        ("prior_completion", s.completion),
        ("prior_parent", s.resource_parent),
        ("correction191", s.correction191),
    ] {
        ensure!(
            bindings[key] == binding(expected),
            "recovered resource frame crossed source: {key}"
        );
    }
    let prior_plan: BoundFile = serde_json::from_value(bindings["prior_fleet_plan"].clone())?;
    let transition: BoundFile = serde_json::from_value(bindings["transition"].clone())?;
    let prior_plan = io::read(&prior_plan)?;
    let transition = io::read(&transition)?;
    let optional_source = |key: &str| -> Result<Option<Value>> {
        if bindings[key].is_null() {
            return Ok(None);
        }
        let source: BoundFile = serde_json::from_value(bindings[key].clone())?;
        Ok(Some(io::read(&source)?))
    };
    let previous = optional_source("prior_recovery")?;
    let delta = optional_source("fleet_transition")?;
    let native154 = optional_source("native154_transition")?;
    let cohort183 = optional_source("cohort183_transition")?;
    let mut cohort183_sources = std::collections::BTreeMap::new();
    cohort183_sources.extend(closed145_reload_source_loader::load(
        cohort183.as_ref(),
        io::read,
    )?);

    if let Some(t) = cohort183
        .as_ref()
        .filter(|t| !t[crate::fleet::cached145_terminal_observer::FIELD].is_null())
    {
        use crate::fleet::cached145_terminal_observer as terminal;
        terminal::Witness::descriptor_matches(&t[terminal::FIELD])?;
        for (key, source) in [
            ("terminal145.capture", terminal::CAPTURE),
            ("terminal145.terminal", terminal::TERMINAL),
        ] {
            let bound = BoundFile {
                path: source.path.into(),
                sha256: source.sha256.into(),
            };
            cohort183_sources.insert(key.into(), io::read(&bound)?);
        }
    }

    if let Some(t) = &cohort183 {
        for member in [
            "canonical_import",
            "source_batch_snapshot",
            "canonical_batch_snapshot",
        ] {
            if t[member].is_null() {
                continue;
            }
            let source: BoundFile = serde_json::from_value(t[member].clone())?;
            cohort183_sources.insert(member.to_owned(), io::read(&source)?);
        }
    }
    if let Some(rows) = cohort183
        .as_ref()
        .and_then(|t| t["observation_bridge"].as_array())
    {
        ensure!(rows.len() <= 16, "observation bridge too long");
        for (index, row) in rows.iter().enumerate() {
            for member in ["observer", "fleet", "fleet_plan"] {
                if row[member].is_null() {
                    continue;
                }
                let source: BoundFile = serde_json::from_value(row[member].clone())?;
                cohort183_sources.insert(format!("bridge.{index}.{member}"), io::read(&source)?);
            }
        }
    }
    if let Some(t) = cohort183.as_ref().filter(|t| !t["verifier183"].is_null()) {
        for member in [
            "event",
            "full_launch",
            "plugin_launch",
            "previous_fleet",
            "previous_plan",
            "entry_fleet",
            "entry_plan",
            "declared_plan",
        ] {
            if t["verifier183"][member].is_null() {
                continue;
            }
            let source: BoundFile = serde_json::from_value(t["verifier183"][member].clone())?;
            cohort183_sources.insert(format!("verifier183.{member}"), io::read(&source)?);
        }
    }
    if let Some(t) = cohort183
        .as_ref()
        .filter(|t| !t["delivery_owner_delta"].is_null())
    {
        if !t["input161_retry6_pre_ready"].is_null() {
            ensure!(
                (INPUT161_G7_CAPTURE_TOOL_SHA.is_some_and(|sha| frame["self_sha256"] == sha)
                    || (frame["self_sha256"] == INPUT161_G7_DEFERRED_CAPTURE_TOOL_SHA
                        || (frame["self_sha256"] == INPUT161_G7_PRIOR16_CAPTURE_TOOL_SHA
                            || frame["self_sha256"] == RETAINED_G6_EXEC_IDENTITY_CAPTURE_SHA
                            || qualified_cached145_capture(frame)))),
                "pre-ready G6 graph requires a separately qualified capture artifact"
            );
        }
        if !t["input161_retry7"].is_null() {
            ensure!(
                (INPUT161_G7_CAPTURE_TOOL_SHA.is_some_and(|sha| frame["self_sha256"] == sha)
                    || (frame["self_sha256"] == INPUT161_G7_DEFERRED_CAPTURE_TOOL_SHA
                        || (frame["self_sha256"] == INPUT161_G7_PRIOR16_CAPTURE_TOOL_SHA
                            || frame["self_sha256"] == RETAINED_G6_EXEC_IDENTITY_CAPTURE_SHA
                            || qualified_cached145_capture(frame)))),
                "g7 graph requires a separately qualified capture artifact"
            );
        }
        if !t["input161_retry6"].is_null() {
            ensure!(
                frame["self_sha256"] == INPUT161_G6_FRAME14_CAPTURE_TOOL_SHA
                    || INPUT161_G6_NEXT_CAPTURE_TOOL_SHA
                        .is_some_and(|sha| frame["self_sha256"] == sha)
                    || (INPUT161_G7_CAPTURE_TOOL_SHA
                        .is_some_and(|sha| frame["self_sha256"] == sha)
                        || (frame["self_sha256"] == INPUT161_G7_DEFERRED_CAPTURE_TOOL_SHA
                            || (frame["self_sha256"] == INPUT161_G7_PRIOR16_CAPTURE_TOOL_SHA
                                || frame["self_sha256"] == RETAINED_G6_EXEC_IDENTITY_CAPTURE_SHA
                                || qualified_cached145_capture(frame)))),
                "g6 graph requires separately qualified future capture artifact"
            );
        }
        for (section, prefix) in [
            ("delivery_owner_delta", "delivery"),
            ("g5_entry", "g5_entry"),
            ("terminal154", "terminal154"),
            ("completed184", "completed184"),
            ("private154_scan_launch", "private154_scans"),
            ("private154_scan_combined", "private154_combined"),
            ("private154_plugin_terminal", "private154_plugin"),
            ("private154_downstream_roles", "private154_downstream"),
            ("charge136_retry0003", "new136"),
            ("charge136_retry0004", "new136_retry0004"),
            ("durable_prefix141", "native141"),
            ("input161_retry6", "g6"),
            ("input161_retry7", "g7"),
            ("input161_retry6_pre_ready", "g6_pre_ready"),
            ("cached145", "cached145"),
        ] {
            if t[section].is_null() {
                continue;
            }
            let members = t[section]["sources"]
                .as_object()
                .context("metadata history source map")?;
            ensure!(members.len() <= 32, "metadata history has too many sources");
            for (name, pair) in members {
                ensure!(
                    pair.as_object().is_some_and(|o| o.len() == 2
                        && o.contains_key("origin")
                        && o.contains_key("preserved")),
                    "metadata source pair differs"
                );
                let _: BoundFile = serde_json::from_value(pair["origin"].clone())?;
                let source: BoundFile = serde_json::from_value(pair["preserved"].clone())?;
                let value = if section == "completed184" && name.ends_with(".receipt") {
                    let size = io::sealed(&source.path)?.len();
                    ensure!(
                        size > 0 && size <= 1 << 20,
                        "completed verifier receipt size differs"
                    );
                    io::immutable(&source, size)?;
                    let raw = std::fs::read(&source.path)?;
                    ensure!(
                        raw.len() <= 1 << 20
                            && format!("{:x}", sha2::Sha256::digest(&raw)) == source.sha256,
                        "completed receipt bytes changed"
                    );
                    io::immutable(&source, size)?;
                    json!(String::from_utf8(raw)?)
                } else {
                    contract::delivery_history::source_value(section, name, io::read(&source)?)?
                };
                cohort183_sources.insert(format!("{prefix}.{name}"), value);
            }
        }
        if t["delivery_owner_delta"]["mode"] == "retained" {
            let source: BoundFile =
                serde_json::from_value(t["previous_cohort183_transition"].clone())?;
            cohort183_sources.insert("delivery.previous_transition".into(), io::read(&source)?);
        }
    }
    let mut native154_sources = std::collections::BTreeMap::new();
    if let Some(t) = &native154 {
        for (stage, members) in [
            ("entry", &["origin", "fleet", "fleet_plan"][..]),
            ("terminal", &["proof", "fleet", "fleet_plan"][..]),
        ] {
            if t[stage].is_null() {
                continue;
            }
            for member in members {
                let source: BoundFile = serde_json::from_value(t[stage][member].clone())?;
                native154_sources.insert(format!("{stage}.{member}"), io::read(&source)?);
            }
        }
    }
    const CACHED145_QUALIFIED_CAPTURE_SHA: Option<&str> = Some(CACHED145_FRAME20_CAPTURE_TOOL_SHA);
    if let Some(t) = cohort183.as_ref().filter(|t| !t["cached145"].is_null()) {
        ensure!(
            CACHED145_QUALIFIED_CAPTURE_SHA.is_some_and(|sha| frame["self_sha256"] == sha)
                || frame["self_sha256"] == CACHED145_FRAME21_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME22_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME23_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME25_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME26_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == CACHED145_FRAME33_CAPTURE_TOOL_SHA
                || frame["self_sha256"] == RETAINED_BASELINE_FRAME35_CAPTURE_TOOL_SHA
                || qualified_retry0005_capture(frame),
            "cached145 requires separately qualified producer20 or producer21 artifact"
        );
        let pb: BoundFile = serde_json::from_value(t["previous_recovery"].clone())?;
        let prior = io::read(&pb)?;
        let fb: BoundFile = serde_json::from_value(prior["bindings"]["fleet"].clone())?;
        cohort183_sources.insert("cached145.current_previous_fleet".into(), io::read(&fb)?);
    }
    if cohort183
        .as_ref()
        .is_some_and(|t| !t["charge136_retry0005"].is_null())
    {
        ensure!(
            qualified_retry0005_capture(frame),
            "retry 0005 requires its independently qualified Frame producer"
        );
        let values = retry0005_source_loader::load(
            cohort183.as_ref(),
            |bound| {
                ensure!(
                    io::sealed(&bound.path)?.permissions().readonly(),
                    "retry 0005 preserved source is writable"
                );
                io::read(bound)
            },
            super::super::charge136_retry0005_failed4_adapter::actual,
        )?;
        for (key, value) in values {
            ensure!(
                cohort183_sources.insert(key, value).is_none(),
                "retry 0005 adapter duplicated source role"
            );
        }
    }
    for observed in std::iter::once(frame).chain(previous.as_ref()) {
        if let Some(history) = observed.get("cached145_guard_history") {
            let rows = history.as_object().context("cached145 raw guard history")?;
            ensure!(rows.len() <= 6, "cached145 guard history exceeds bound");
            for (iid, row) in rows {
                ensure!(
                    iid.len() == 32
                        && iid
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "cached145 history IID differs"
                );
                let bound: BoundFile = serde_json::from_value(row["binding"].clone())?;
                ensure!(
                    std::fs::symlink_metadata(&bound.path)?.len() <= 1 << 20,
                    "cached145 guard sample exceeds bound"
                );
                ensure!(
                    io::read(&bound)? == row["value"],
                    "cached145 guard history raw source differs"
                );
            }
        }
    }
    super::super::cached145_rollover_sources::authenticate(b.fleet)?;
    for key in ["cached145.entry_fleet", "cached145.current_previous_fleet"] {
        if let Some(fleet) = cohort183_sources.get(key) {
            super::super::cached145_rollover_sources::authenticate(fleet)?;
        }
    }
    if cohort183.as_ref().is_some_and(|t| !t["input137"].is_null()) {
        // Retained composition is separately qualified. The first-entry and SDK
        // release registrations remain closed in epoch137_registration.
        retained_input137_capture_scope::program(
            frame,
            cohort183.as_ref().context("retained input137 transition")?,
            RETRY0005_FRAME_CAPTURE_SHA,
            EFFECTIVE_MEMORY_RETRY0005_FRAME_CAPTURE_SHA,
        )?;
        let values = input137_source_loader::load(cohort183.as_ref(), |bound, custody| {
            if custody == input137_source_loader::Custody::ImmutablePreserved {
                ensure!(
                    io::sealed(&bound.path)?.permissions().readonly(),
                    "epoch 137 preserved source is writable"
                );
            }
            io::read(bound)
        })?;
        for (k, v) in values {
            ensure!(
                cohort183_sources.insert(k, v).is_none(),
                "epoch 137 adapter duplicated source role"
            );
        }
    }

    if let Some(t) = cohort183.as_ref().filter(|t| !t["input137"].is_null()) {
        retained_input137_capture_scope::graph(
            frame,
            t,
            previous.as_ref(),
            &cohort183_sources,
            RETRY0005_FRAME_CAPTURE_SHA,
            EFFECTIVE_MEMORY_RETRY0005_FRAME_CAPTURE_SHA,
        )?;
    }

    let evidence = contract::Evidence {
        observer: b.observer,
        fleet: b.fleet,
        fleet_plan: b.fleet_plan,
        prior_parent: b.parent,
        prior_completion: b.completion,
        prior_fleet_plan: &prior_plan,
        transition: &transition,
        prior_recovery: previous.as_ref(),
        fleet_transition: delta.as_ref(),
        capture_tool_sha: frame["self_sha256"]
            .as_str()
            .context("capture SHA missing")?,
        native154_transition: native154.as_ref(),
        cohort183_transition: cohort183.as_ref(),
        cohort183_sources: &cohort183_sources,
        native154_sources: &native154_sources,
    };
    if !frame["epoch185_cold_lifecycle"].is_null() {
        validate_cold185_frame(frame, &evidence, bindings, now)?;
    } else if !frame["epoch199_http500_capture_registration"].is_null() {
        ensure!(
            horizon_recovered_resource_frame_recovery199::qualified_recovery199_capture(frame)?,
            "recovery199 current Frame capture is not normally sealed and qualified"
        );
        let _historical_comparison = crate::fleet::recovery199_contract::project_frame(frame)?;
        horizon_recovered_resource_frame_recovery199::validate_frame(
            frame,
            &horizon_recovered_resource_frame_recovery199::Evidence {
                observer: evidence.observer,
                fleet: evidence.fleet,
                fleet_plan: evidence.fleet_plan,
                prior_parent: evidence.prior_parent,
                prior_completion: evidence.prior_completion,
                prior_fleet_plan: evidence.prior_fleet_plan,
                transition: evidence.transition,
                prior_recovery: evidence.prior_recovery,
                fleet_transition: evidence.fleet_transition,
                capture_tool_sha: evidence.capture_tool_sha,
                cohort183_transition: evidence.cohort183_transition,
                cohort183_sources: evidence.cohort183_sources,
                native154_transition: evidence.native154_transition,
                native154_sources: evidence.native154_sources,
            },
            bindings,
            now,
        )?;
    } else if typed_bridge_capture(frame) {
        validate_typed_bridge_frame(
            frame,
            &evidence,
            bindings,
            now,
            &b.fleet_plan[crate::fleet::ordinary199::TERMINAL_FIELD],
        )?;
    } else if retained199_v2_capture(frame) {
        validate_retained199_v2_frame(
            frame,
            &evidence,
            bindings,
            now,
            &b.fleet_plan[crate::fleet::ordinary199::TERMINAL_FIELD],
        )?;
    } else if canonical_v5_capture(frame)
        && !b.fleet_plan[crate::fleet::ordinary199::TERMINAL_FIELD].is_null()
    {
        validate_canonical_v5_frame_retained199(
            frame,
            &evidence,
            bindings,
            now,
            &b.fleet_plan[crate::fleet::ordinary199::TERMINAL_FIELD],
        )?;
    } else if canonical_v5_capture(frame) {
        validate_canonical_v5_frame(frame, &evidence, bindings, now)?;
    } else if helper_v4_capture(frame) {
        // Use the separately linked new library only for the exact new capture.
        // Keep old v5 dispatch and its linked dependency intact below.
        horizon_recovered_resource_frame_cohort183_v8::validate_frame(
            frame,
            &horizon_recovered_resource_frame_cohort183_v8::Evidence {
                observer: evidence.observer,
                fleet: evidence.fleet,
                fleet_plan: evidence.fleet_plan,
                prior_parent: evidence.prior_parent,
                prior_completion: evidence.prior_completion,
                prior_fleet_plan: evidence.prior_fleet_plan,
                transition: evidence.transition,
                prior_recovery: evidence.prior_recovery,
                fleet_transition: evidence.fleet_transition,
                capture_tool_sha: evidence.capture_tool_sha,
                cohort183_transition: evidence.cohort183_transition,
                cohort183_sources: evidence.cohort183_sources,
                native154_transition: evidence.native154_transition,
                native154_sources: evidence.native154_sources,
            },
            bindings,
            now,
        )?;
    } else if ordinary199_capture(frame) {
        // Link only the already qualified/sealed v5 library under this explicit
        // extern name. Its full-view validation preserves new199 promises; an
        // old embedded contract cannot authenticate the additive native family.
        horizon_recovered_resource_frame_cohort183_v6::validate_frame(
            frame,
            &horizon_recovered_resource_frame_cohort183_v6::Evidence {
                observer: evidence.observer,
                fleet: evidence.fleet,
                fleet_plan: evidence.fleet_plan,
                prior_parent: evidence.prior_parent,
                prior_completion: evidence.prior_completion,
                prior_fleet_plan: evidence.prior_fleet_plan,
                transition: evidence.transition,
                prior_recovery: evidence.prior_recovery,
                fleet_transition: evidence.fleet_transition,
                capture_tool_sha: evidence.capture_tool_sha,
                cohort183_transition: evidence.cohort183_transition,
                cohort183_sources: evidence.cohort183_sources,
                native154_transition: evidence.native154_transition,
                native154_sources: evidence.native154_sources,
            },
            bindings,
            now,
        )?;
    } else {
        contract::validate_frame(frame, &evidence, bindings, now)?;
    }
    Ok(true)
}

// Convert the complete evidence graph into the independently qualified
// canonical library type; no historical library alias is repointed here.
fn validate_canonical_v5_frame(
    frame: &Value,
    evidence: &contract::Evidence<'_>,
    bindings: &Value,
    now: u64,
) -> Result<()> {
    ensure!(
        canonical_v5_capture(frame) && evidence.capture_tool_sha == CANONICAL_V5_FRAME_CAPTURE_SHA,
        "canonical v5 Frame capture or evidence image differs"
    );
    horizon_recovered_resource_frame_canonical_v5::validate_frame(
        frame,
        &horizon_recovered_resource_frame_canonical_v5::Evidence {
            observer: evidence.observer,
            fleet: evidence.fleet,
            fleet_plan: evidence.fleet_plan,
            prior_parent: evidence.prior_parent,
            prior_completion: evidence.prior_completion,
            prior_fleet_plan: evidence.prior_fleet_plan,
            transition: evidence.transition,
            prior_recovery: evidence.prior_recovery,
            fleet_transition: evidence.fleet_transition,
            capture_tool_sha: evidence.capture_tool_sha,
            cohort183_transition: evidence.cohort183_transition,
            cohort183_sources: evidence.cohort183_sources,
            native154_transition: evidence.native154_transition,
            native154_sources: evidence.native154_sources,
        },
        bindings,
        now,
    )
}

fn validate_canonical_v5_frame_retained199(
    frame: &Value,
    evidence: &contract::Evidence<'_>,
    bindings: &Value,
    now: u64,
    selector: &Value,
) -> Result<()> {
    ensure!(
        canonical_v5_capture(frame) && evidence.capture_tool_sha == CANONICAL_V5_FRAME_CAPTURE_SHA,
        "canonical v5 Frame capture or evidence image differs"
    );
    if selector != &retained199_v2_selector() && retained199_v2_current_selector(selector)? {
        return validate_selected_canonical_v5_frame(frame, evidence, bindings, now, selector);
    }
    let context =
        horizon_recovered_resource_frame_retained199::terminal199_context::Retained::load(
            &serde_json::from_value(selector.clone())?,
        )?;
    horizon_recovered_resource_frame_retained199::validate_frame_retained199(
        frame,
        &horizon_recovered_resource_frame_retained199::Evidence {
            observer: evidence.observer,
            fleet: evidence.fleet,
            fleet_plan: evidence.fleet_plan,
            prior_parent: evidence.prior_parent,
            prior_completion: evidence.prior_completion,
            prior_fleet_plan: evidence.prior_fleet_plan,
            transition: evidence.transition,
            prior_recovery: evidence.prior_recovery,
            fleet_transition: evidence.fleet_transition,
            capture_tool_sha: evidence.capture_tool_sha,
            cohort183_transition: evidence.cohort183_transition,
            cohort183_sources: evidence.cohort183_sources,
            native154_transition: evidence.native154_transition,
            native154_sources: evidence.native154_sources,
        },
        bindings,
        now,
        &context,
    )
}

fn validate_retained199_v2_frame(
    frame: &Value,
    evidence: &contract::Evidence<'_>,
    bindings: &Value,
    now: u64,
    selector: &Value,
) -> Result<()> {
    ensure!(
        retained199_v2_capture(frame)
            && evidence.capture_tool_sha == RETAINED199_V2_FRAME_CAPTURE_SHA
            && retained199_v2_current_selector(selector)?
            && evidence.fleet_plan["epoch199_terminal_context"] == *selector,
        "retained v2 Frame capture, evidence image or explicit selector differs"
    );
    let context =
        horizon_recovered_resource_frame_retained199_v2::terminal199_context::Retained::load(
            &serde_json::from_value(selector.clone())?,
        )?;
    horizon_recovered_resource_frame_retained199_v2::validate_frame_retained199(
        frame,
        &horizon_recovered_resource_frame_retained199_v2::Evidence {
            observer: evidence.observer,
            fleet: evidence.fleet,
            fleet_plan: evidence.fleet_plan,
            prior_parent: evidence.prior_parent,
            prior_completion: evidence.prior_completion,
            prior_fleet_plan: evidence.prior_fleet_plan,
            transition: evidence.transition,
            prior_recovery: evidence.prior_recovery,
            fleet_transition: evidence.fleet_transition,
            capture_tool_sha: evidence.capture_tool_sha,
            cohort183_transition: evidence.cohort183_transition,
            cohort183_sources: evidence.cohort183_sources,
            native154_transition: evidence.native154_transition,
            native154_sources: evidence.native154_sources,
        },
        bindings,
        now,
        &context,
    )
}

fn validate_selected_canonical_v5_frame(
    frame: &Value,
    evidence: &contract::Evidence<'_>,
    bindings: &Value,
    now: u64,
    selector: &Value,
) -> Result<()> {
    ensure!(
        canonical_v5_capture(frame)
            && evidence.capture_tool_sha == CANONICAL_V5_FRAME_CAPTURE_SHA
            && retained199_v2_current_selector(selector)?
            && evidence.fleet_plan["epoch199_terminal_context"] == *selector,
        "selected canonical v5 Frame context or capture differs"
    );
    let context =
        horizon_recovered_resource_frame_retained199_v2::terminal199_context::Retained::load(
            &serde_json::from_value(selector.clone())?,
        )?;
    horizon_recovered_resource_frame_retained199_v2::validate_frame_retained199(
        frame,
        &horizon_recovered_resource_frame_retained199_v2::Evidence {
            observer: evidence.observer,
            fleet: evidence.fleet,
            fleet_plan: evidence.fleet_plan,
            prior_parent: evidence.prior_parent,
            prior_completion: evidence.prior_completion,
            prior_fleet_plan: evidence.prior_fleet_plan,
            transition: evidence.transition,
            prior_recovery: evidence.prior_recovery,
            fleet_transition: evidence.fleet_transition,
            capture_tool_sha: evidence.capture_tool_sha,
            cohort183_transition: evidence.cohort183_transition,
            cohort183_sources: evidence.cohort183_sources,
            native154_transition: evidence.native154_transition,
            native154_sources: evidence.native154_sources,
        },
        bindings,
        now,
        &context,
    )
}

fn validate_typed_bridge_frame(
    frame: &Value,
    evidence: &contract::Evidence<'_>,
    bindings: &Value,
    now: u64,
    selector: &Value,
) -> Result<()> {
    ensure!(
        typed_bridge_capture(frame)
            && frame["self_sha256"] == evidence.capture_tool_sha
            && retained199_v2_current_selector(selector)?
            && evidence.fleet_plan["epoch199_terminal_context"] == *selector
            && evidence.fleet_plan["epoch199_http500_capture_registration"].is_null()
            && evidence.fleet_plan["epoch199_http500_recovery_enrollment"].is_null(),
        "typed fleet bridge capture, evidence image, retained selector or normal policy differs"
    );
    // Generic validation must execute the outer typed-bridge composition before
    // retained199 and cached145 views. Historical direct dispatch stays unchanged.
    horizon_recovered_resource_frame_typed_bridge_v1::validate_frame(
        frame,
        &horizon_recovered_resource_frame_typed_bridge_v1::Evidence {
            observer: evidence.observer,
            fleet: evidence.fleet,
            fleet_plan: evidence.fleet_plan,
            prior_parent: evidence.prior_parent,
            prior_completion: evidence.prior_completion,
            prior_fleet_plan: evidence.prior_fleet_plan,
            transition: evidence.transition,
            prior_recovery: evidence.prior_recovery,
            fleet_transition: evidence.fleet_transition,
            capture_tool_sha: evidence.capture_tool_sha,
            cohort183_transition: evidence.cohort183_transition,
            cohort183_sources: evidence.cohort183_sources,
            native154_transition: evidence.native154_transition,
            native154_sources: evidence.native154_sources,
        },
        bindings,
        now,
    )
}

#[cfg(test)]
#[path = "typed_bridge_capture_tests.rs"]
mod typed_bridge_capture_tests;

#[cfg(test)]
#[path = "canonical_v5_frame_regression.rs"]
mod canonical_v5_frame_regression;

#[cfg(test)]
#[path = "recovered_resource_early141_entry_regression.rs"]
mod early141_entry_regression;
#[cfg(test)]
pub(in crate::fleet) fn complete_early141_entry_regression(
    frame: &BoundFile,
    plan: &BoundFile,
    native: &std::collections::BTreeMap<String, Value>,
) -> Result<Value> {
    early141_entry_regression::run(frame, plan, native)
}

#[cfg(test)]
mod cached145_qualified_producer25_tests {
    use super::*;
    #[test]
    fn exact_sealed_producer25_is_accepted_and_foreign_hashes_are_rejected() {
        assert!(qualified_cached145_capture(
            &json!({"self_sha256": CACHED145_FRAME25_CAPTURE_TOOL_SHA})
        ));
        assert!(qualified_cached145_capture(
            &json!({"self_sha256": CACHED145_FRAME23_CAPTURE_TOOL_SHA})
        ));
        assert!(qualified_cached145_capture(
            &json!({"self_sha256": CACHED145_FRAME33_CAPTURE_TOOL_SHA})
        ));
        assert!(!qualified_cached145_capture(
            &json!({"self_sha256": "f".repeat(64)})
        ));
        assert!(!qualified_cached145_capture(&json!({"self_sha256": null})));
    }
    #[test]
    fn retry0005_scope_preserves_old_image_and_keeps_pending_successor_closed() {
        assert!(qualified_retry0005_capture(
            &json!({"self_sha256":RETRY0005_FRAME_CAPTURE_SHA})
        ));
        assert!(!qualified_retry0005_capture(
            &json!({"self_sha256":RETAINED_BASELINE_FRAME35_CAPTURE_TOOL_SHA})
        ));
        assert!(!qualified_retry0005_capture(
            &json!({"self_sha256":"f".repeat(64)})
        ));
        let transition = json!({"input137":{"mode":"entry"}});
        assert!(
            retained_input137_capture_scope::program(
                &json!({"self_sha256":RETRY0005_FRAME_CAPTURE_SHA}),
                &transition,
                RETRY0005_FRAME_CAPTURE_SHA,
                EFFECTIVE_MEMORY_RETRY0005_FRAME_CAPTURE_SHA,
            )
            .is_err()
        );
    }
    #[test]
    fn independently_qualified_ordinary199_frame_is_scoped_to_exact_v5_image() {
        let current = json!({"self_sha256":ORDINARY199_FRAME_V5_CAPTURE_SHA});
        assert!(ordinary199_capture(&current));
        assert!(qualified_retry0005_capture(&current));
        assert!(qualified_cached145_capture(&current));
        for sha in [
            HELPER_V3_BUFFERED_FRAME_V6_CAPTURE_SHA,
            RETRY0005_FRAME_CAPTURE_SHA,
            RETAINED_BASELINE_FRAME35_CAPTURE_TOOL_SHA,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            assert!(!ordinary199_capture(&json!({"self_sha256":sha})), "{sha}");
        }
        assert!(!ordinary199_capture(&json!({"self_sha256":null})));
    }
    #[test]
    fn producer35_baseline_pin_is_scoped_to_inherited_capture() {
        assert!(qualified_cached145_capture(
            &json!({"self_sha256":RETAINED_BASELINE_FRAME35_CAPTURE_TOOL_SHA})
        ));
        assert!(!qualified_cached145_capture(
            &json!({"self_sha256":"0".repeat(64)})
        ));
    }
    #[test]
    fn helper_v4_capture_registration_uses_real_v7_and_retains_old_dispatch() {
        assert!(ordinary199_capture(
            &json!({"self_sha256":ORDINARY199_FRAME_V5_CAPTURE_SHA})
        ));
        assert!(!helper_v4_capture(
            &json!({"self_sha256":ORDINARY199_FRAME_V5_CAPTURE_SHA})
        ));
        for sha in [
            "",
            "unknown",
            RETRY0005_FRAME_CAPTURE_SHA,
            HELPER_V3_BUFFERED_FRAME_V6_CAPTURE_SHA,
            "cb7c93fec595a1a78b6d0368c0e7870b4abf10e366a12b891e6cc452b1f6b13a",
        ] {
            assert!(!helper_v4_capture(&json!({"self_sha256":sha})));
        }
        match HELPER_V4_ADDITIVE_FRAME_CAPTURE_SHA {
            None => assert!(!helper_v4_capture(&json!({"self_sha256":"0".repeat(64)}))),
            Some(sha) => {
                assert!(helper_v4_capture(&json!({"self_sha256":sha})));
                assert!(qualified_retry0005_capture(&json!({"self_sha256":sha})));
                assert!(!ordinary199_capture(&json!({"self_sha256":sha})));
            }
        }
    }
}

#[cfg(test)]
mod retained199_v2_capture_registration_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn selected() -> Value {
        serde_json::json!({"self_sha256":RETAINED199_V2_FRAME_CAPTURE_SHA,
            "epoch199_terminal_context":retained199_v2_selector()})
    }
    #[test]
    fn actual_sealed_capture_and_exact_v2_selector_register_without_repointing_legacy() {
        let bytes = std::fs::read("/usr/local/lib/jetstreamer/horizon-original199-retained-frame-cli-tools-20261104-v3/jetstreamer-recovered-resource-frame-private154-plugin").unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            RETAINED199_V2_FRAME_CAPTURE_SHA
        );
        assert!(retained199_v2_capture(&selected()));
        assert!(qualified_retry0005_capture(&selected()));
        assert!(qualified_cached145_capture(&selected()));
        assert!(canonical_v5_capture(
            &serde_json::json!({"self_sha256":CANONICAL_V5_FRAME_CAPTURE_SHA})
        ));
    }
    #[test]
    fn new_capture_rejects_absent_old_crossed_or_neighbor_context() {
        for context in [
            Value::Null,
            serde_json::json!({"path":"/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v1/registry.json","sha256":"7744abca94e34c4531a9b439a85810f86784ecf1823276c72fc360e2f70013d5"}),
            serde_json::json!({"path":"/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v2/registry.json","sha256":"7744abca94e34c4531a9b439a85810f86784ecf1823276c72fc360e2f70013d5"}),
            serde_json::json!({"path":"/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v3/registry.json","sha256":"733487fcb07438d603999234b0a0598d62261ba0c1cb0ba6003693260ebc1389"}),
        ] {
            let frame = serde_json::json!({"self_sha256":RETAINED199_V2_FRAME_CAPTURE_SHA,"epoch199_terminal_context":context});
            assert!(!retained199_v2_capture(&frame));
            assert!(!qualified_retry0005_capture(&frame));
        }
    }
    #[test]
    fn matching_context_never_registers_a_foreign_image_or_changes_older_dispatch() {
        let mut frame = selected();
        frame["self_sha256"] =
            serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
        assert!(!retained199_v2_capture(&frame));
        assert!(!qualified_retry0005_capture(&frame));
        for sha in [
            CANONICAL_V5_FRAME_CAPTURE_SHA,
            ORDINARY199_FRAME_V5_CAPTURE_SHA,
        ] {
            let old = serde_json::json!({"self_sha256":sha});
            assert!(!retained199_v2_capture(&old));
            assert!(qualified_retry0005_capture(&old));
        }
    }
    #[test]
    fn image_pin_and_selector_alone_cannot_validate_a_frame_or_borrow_an_old_selector() {
        let empty = Value::Null;
        let sources = std::collections::BTreeMap::new();
        let evidence = contract::Evidence {
            observer: &empty,
            fleet: &empty,
            fleet_plan: &empty,
            prior_parent: &empty,
            prior_completion: &empty,
            prior_fleet_plan: &empty,
            transition: &empty,
            prior_recovery: None,
            fleet_transition: None,
            capture_tool_sha: RETAINED199_V2_FRAME_CAPTURE_SHA,
            native154_transition: None,
            cohort183_transition: None,
            cohort183_sources: &sources,
            native154_sources: &sources,
        };
        assert!(
            validate_retained199_v2_frame(&selected(), &evidence, &empty, 0, &Value::Null).is_err()
        );
        assert!(
            validate_retained199_v2_frame(
                &selected(),
                &evidence,
                &empty,
                0,
                &retained199_v2_selector()
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod accepted0428_refresh_capture_tests {
    use super::*;
    fn fixture(raw: &[u8], expected: &str) -> Value {
        assert_eq!(format!("{:x}", Sha256::digest(raw)), expected);
        serde_json::from_slice(raw).unwrap()
    }
    fn frame() -> Value {
        fixture(
            include_bytes!("accepted0428-capture-fixtures/frame1028.json"),
            "7e1dc36d0db8178b22b10710f55a2f01dc7e732a9e6ab8ce4a6ed1b84198f8f6",
        )
    }
    #[test]
    fn actual1028_new_capture_binds_genuine_native_success_and_independent_qualified_artifacts() {
        let frame = frame();
        let pin = ACCEPTED0428_REFRESH_FRAME_CAPTURE_SHA.unwrap();
        let acceptance = fixture(
            include_bytes!("accepted0428-capture-fixtures/native-acceptance.json"),
            "ddfce84424fa38e2417442131664449784276b237220a40210d61ba0d2184423",
        );
        let cli = fixture(
            include_bytes!("accepted0428-capture-fixtures/cli-artifact-proof.json"),
            "49b03cade0a2bee6649a868c0c28790067d8048402ca9b29d815d099a9d90d80",
        );
        let seal = fixture(
            include_bytes!("accepted0428-capture-fixtures/cli-seal.json"),
            "b86481f7d8c71208746d594264b16be28db440fd25f84df75ea0cc81685b13d6",
        );
        let library = fixture(
            include_bytes!("accepted0428-capture-fixtures/library-artifact-proof.json"),
            "f9afe567d0562f46382261cfb28756eeb82d0631a462b8ab0f6fae151018d4bf",
        );
        assert_eq!(frame["self_sha256"], pin);
        assert_eq!(frame["accepted_resource_lineage"], true);
        assert_eq!(
            acceptance["frame"]["sha256"],
            "7e1dc36d0db8178b22b10710f55a2f01dc7e732a9e6ab8ce4a6ed1b84198f8f6"
        );
        assert_eq!(
            acceptance["actual_completed_writer"]["InvocationID"],
            "ea6cba0b0b024116b47a61d13a02bd25"
        );
        assert_eq!(acceptance["actual_completed_writer"]["ExecMainStatus"], "0");
        assert_eq!(cli["artifact"]["sha256"], pin);
        assert_eq!(cli["ordinary_tests_passed"], 50);
        assert_eq!(cli["actual_native_saved_custody_passed"], 1);
        assert_eq!(library["ordinary_tests_passed"], 426);
        assert_eq!(
            seal["members"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|m| m["name"] == "jetstreamer-horizon-frame" && m["sha256"] == pin)
                .count(),
            1
        );
        assert!(typed_bridge_capture(&frame));
        assert!(qualified_retry0005_capture(&frame));
        assert!(qualified_cached145_capture(&frame));
    }
    #[test]
    fn new1028_capture_registration_rejects_foreign_image_context_and_recovery_registration() {
        let frame = frame();
        for (key, value) in [
            ("self_sha256", serde_json::json!("b".repeat(64))),
            (
                "epoch199_terminal_context",
                serde_json::json!({"foreign":true}),
            ),
            (
                "epoch199_http500_capture_registration",
                serde_json::json!({"foreign":true}),
            ),
            (
                "epoch199_http500_recovery_enrollment",
                serde_json::json!({"foreign":true}),
            ),
        ] {
            let mut bad = frame.clone();
            bad[key] = value;
            assert!(!typed_bridge_capture(&bad), "{key}");
        }
    }
    #[test]
    fn new1028_capture_addition_preserves_original_image_pins_and_disabled_pin_behavior() {
        assert_eq!(
            CLOSED145_FAMILY_FRAME_CAPTURE_SHA,
            Some("ed4fcc72ea0a6c9824360803aefd05b3cacdc0400ea923b4a6e10506a11d94a5")
        );
        assert_eq!(
            CLOSED145_INACTIVE_TIMER_RELOAD_CAPTURE_SHA,
            Some("6c8fe3a05a03d57ca933b83d02a027b516aad121760dd41ce553f49268669f2e")
        );
        let frame = frame();
        assert!(!typed_bridge_capture_with_pin(&frame, None));
        assert!(!typed_bridge_capture_with_pin(&frame, Some("bad")));
        assert!(typed_bridge_capture_with_pin(
            &frame,
            ACCEPTED0428_REFRESH_FRAME_CAPTURE_SHA
        ));
    }
}

#[cfg(test)]
#[path = "sealed_alias0558_capture_tests.rs"]
mod sealed_alias0558_capture_tests;

#[cfg(test)]
mod cold185_capture_registration_tests {
    use super::*;
    #[test]
    fn unqualified_cold185_image_is_never_accepted_from_selector_alone() {
        let f = json!({"self_sha256":"a".repeat(64),"epoch185_cold_startpre_registration":{"path":"/test-only/reg.json","sha256":"b".repeat(64)},"epoch185_cold_lifecycle":{"path":"/test-only/life.json","sha256":"c".repeat(64)}});
        assert!(!qualified_cold185_capture(&f));
        assert!(cold185_capture_with_pin(&f, Some(&"a".repeat(64))));
        let mut bad = f;
        bad["epoch199_http500_capture_registration"] =
            json!({"path":"/test-only/foreign.json","sha256":"d".repeat(64)});
        assert!(!cold185_capture_with_pin(&bad, Some(&"a".repeat(64))));
    }
    #[test]
    fn old_typed_bridge_registration_keeps_its_exact_independent_dispatch() {
        let f = json!({"self_sha256":TYPED_FLEET_BRIDGE_FRAME_CAPTURE_SHA,"epoch199_terminal_context":retained199_v2_selector()});
        assert!(typed_bridge_capture(&f));
        assert!(!qualified_cold185_capture(&f));
    }
}

#[cfg(test)]
#[path = "live145_genuine_capture_tests.rs"]
mod live145_genuine_capture_tests;
