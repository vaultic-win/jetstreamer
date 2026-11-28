//! Authenticate the exact reviewed effective DATA chain, independently of its summary flags.
use super::checker::{self as c, R};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const MANIFEST: &str = "/usr/local/lib/jetstreamer/horizon-original154-future-data-source-20261110-v2/lineage-manifest.json";
const MANIFEST_SHA: &str = "4906d22bdcc5656c2f28da7a9a28d45496c65ca57fc13cf898382b09a514b505";
fn array<'a>(v: &'a Value, k: &str) -> R<&'a Vec<Value>> {
    v[k].as_array()
        .ok_or_else(|| format!("missing array {k}").into())
}
fn data(v: &Value) -> R<u64> {
    let values = ["complete_DATA_bytes", "complete_DATA_lower_bound_bytes"]
        .iter()
        .filter_map(|k| v.get(k))
        .map(|v| v.as_u64().ok_or("invalid DATA integer"))
        .collect::<Result<Vec<_>, _>>()?;
    c::need(
        !values.is_empty() && values.iter().all(|n| *n == values[0]),
        "missing or ambiguous DATA total",
    )?;
    Ok(values[0])
}
fn amount(v: &Value, p: &str) -> R<u64> {
    v.pointer(p)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing numeric pointer {p}").into())
}
fn equation(parent: u64, child: u64, operation: &str, amount: u64) -> R<i128> {
    let expected = match operation {
        "add" => parent.checked_add(amount),
        "subtract" => parent.checked_sub(amount),
        "equal" if amount == 0 => Some(parent),
        _ => None,
    };
    c::need(expected == Some(child), "independent DATA equation differs")?;
    Ok(i128::from(child) - i128::from(parent))
}
fn other_claim(index: usize, child: &Value, support: &[Value]) -> R<()> {
    let (key, iid) = match index {
        5 | 30 | 35 => (
            "original_producer_invocation_id",
            if index == 5 {
                "722adc397ae24bb4b96d452783599f57"
            } else {
                "2a1c51f557a64cd1ad691281cbb77c94"
            },
        ),
        45 => (
            "ended_original_invocation_id",
            "722adc397ae24bb4b96d452783599f57",
        ),
        56 => (
            "ended_failed74_actor_future",
            "f37b155136614e0183ba2e9adb8714ef",
        ),
        68 => ("actor_invocation_id", "5f4b7cb4621a4a2080fd9b083c14f5a0"),
        _ => return Err("unreviewed negative DATA edge".into()),
    };
    // The exact manifest pins every original. Also derive claim identity from the genuine row.
    let direct = child[key] == iid;
    let original = support.iter().any(|v| {
        [
            "original_invocation_id",
            "producer_invocation_id",
            "actor_invocation_id",
            "ended_old722_actor_future",
        ]
        .iter()
        .any(|key| v[key] == iid)
    });
    c::need(
        iid != c::IID && (direct || original),
        "negative edge is not exact other claim",
    )?;
    if index == 68 {
        let rows = array(child, "ended_failed_startpre_obligations")?;
        c::need(
            rows.len() == 1 && rows[0]["invocation_id"] == iid,
            "failed1530 claim crossed",
        )?;
    }
    Ok(())
}
fn source_increment(kind: &str, value: &Value) -> R<u64> {
    match kind {
        "166-lane" => amount(value, "/new_candidate_own_DATA_bytes")?
            .checked_add(amount(value, "/new_candidate_guard_metadata_bytes")?)
            .ok_or_else(|| "lane increment overflow".into()),
        "167-lane" => amount(value, "/candidate_own_DATA_bytes")?
            .checked_add(amount(value, "/candidate_guard_metadata_bytes")?)
            .ok_or_else(|| "lane increment overflow".into()),
        "163-control" | "policy-QA" | "nine-cache-QA" | "ended-tool-QA" | "166-metadata"
        | "167-metadata" | "168-metadata" => amount(value, "/new_retained_DATA_bytes"),
        _ => Err("unreviewed canonical increment".into()),
    }
}

pub fn verify(request: &Value) -> R<Value> {
    c::need(
        request["manifest"] == json!({"path":MANIFEST,"sha256":MANIFEST_SHA}),
        "exact lineage selector required",
    )?;
    let manifest = c::bound(&request["manifest"])?;
    c::need(
        manifest["schema"] == "horizon-original154-DATA-lineage-source-inputs-v1"
            && manifest["current_authority"] == json!({"path":c::HEAD,"sha256":c::HEAD_SHA}),
        "lineage head crossed",
    )?;
    let nodes = array(&manifest, "nodes")?;
    let edges = array(&manifest, "edges")?;
    c::need(
        nodes.len() == 70
            && edges.len() == 69
            && nodes[0]["binding"] == manifest["current_authority"]
            && nodes[69]["binding"] == manifest["canonical_booking"],
        "complete exact lineage required",
    )?;
    let mut documents = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, node) in nodes.iter().enumerate() {
        c::need(
            node["index"] == i && seen.insert(c::string(&node["binding"], "path")?.to_owned()),
            "repeated or reordered lineage node",
        )?;
        let actual = c::bound(&node["binding"])?;
        c::need(
            actual["schema"] == node["schema"]
                && data(&actual)? == c::number(node, "complete_DATA_bytes")?,
            "actual node schema or total differs",
        )?;
        documents.push(actual);
    }
    let mut positive = 0i128;
    let mut negative = 0i128;
    for (i, edge) in edges.iter().enumerate() {
        c::need(
            edge["child_index"] == i
                && edge["parent_index"] == i + 1
                && edge["parent_key"] == nodes[i]["parent_key"],
            "lineage edge crossed or omitted",
        )?;
        let child = &documents[i];
        let parent = &documents[i + 1];
        let key = c::string(edge, "parent_key")?;
        c::need(
            child[key] == nodes[i + 1]["binding"],
            "actual hash-bound alias edge differs",
        )?;
        let supports = array(edge, "supporting_bindings")?
            .iter()
            .map(c::bound)
            .collect::<R<Vec<_>>>()?;
        let arithmetic = &edge["arithmetic"];
        let mut total = 0u64;
        for field in array(arithmetic, "fields")? {
            total = total
                .checked_add(amount(
                    child,
                    field.as_str().ok_or("numeric pointer string")?,
                )?)
                .ok_or("edge amount overflow")?;
        }
        if let Some(field) = arithmetic["external_amount_field"].as_str() {
            c::need(supports.len() == 1, "external arithmetic source ambiguity")?;
            total = total
                .checked_add(amount(&supports[0], field)?)
                .ok_or("external amount overflow")?;
        }
        let delta = equation(
            data(parent)?,
            data(child)?,
            c::string(arithmetic, "operation")?,
            total,
        )?;
        c::need(
            edge["signed_delta_bytes"].as_i64().map(i128::from) == Some(delta)
                && c::number(edge, "child_DATA_bytes")? == data(child)?
                && c::number(edge, "parent_DATA_bytes")? == data(parent)?,
            "recorded edge arithmetic differs",
        )?;
        if delta < 0 {
            other_claim(i, child, &supports)?;
            negative += delta;
        } else if delta > 0 {
            c::need(
                child.get("epoch").is_none_or(|e| e != 154)
                    && !child
                        .as_object()
                        .ok_or("node object")?
                        .values()
                        .any(|v| v.as_str() == Some(c::IID)),
                "original154 rebooking in effective chain",
            )?;
            positive += delta;
        }
    }
    c::need(
        positive == 2_084_401_315_840
            && negative == -2_301_968_252_928
            && i128::from(data(&documents[69])?) + positive + negative == i128::from(c::BASE_DATA),
        "full chain sum differs",
    )?;
    let raw = c::bound(&manifest["raw_accounting"])?;
    let projected = array(&raw, "projected_obligations")?;
    let peers = array(&raw, "active_peer_allocations")?;
    let mut keys = BTreeSet::new();
    let mut raw_sum = 0u64;
    let mut target_count = 0;
    for row in projected {
        c::need(
            keys.insert(c::string(row, "claim_key")?),
            "duplicate raw claim",
        )?;
        raw_sum = raw_sum
            .checked_add(c::number(row, "outstanding_bytes")?)
            .ok_or("raw sum overflow")?;
        if row["producer_invocation_id"] == c::IID {
            c::need(
                row["claim_key"] == format!("suffix154/{}", c::IID)
                    && row["epoch"] == 154
                    && row["outstanding_bytes"] == c::OLD_DATA,
                "raw154 charge differs",
            )?;
            target_count += 1;
        }
    }
    c::need(
        projected.len() == 38
            && target_count == 1
            && raw_sum == 5_290_153_274_320
            && raw["protected_existing_DATA_bytes"] == 5_367_462_685_648u64
            && raw_sum.checked_add(72u64 << 30)
                == Some(c::number(&raw, "protected_existing_DATA_bytes")?),
        "complete raw DATA proof differs",
    )?;
    let target_peers = peers
        .iter()
        .filter(|r| r["invocation_id"] == c::IID)
        .collect::<Vec<_>>();
    c::need(
        target_peers.len() == 1
            && target_peers[0]["data_reservation_bytes"] == c::OLD_DATA
            && target_peers[0]["unit"] == c::ACTOR
            && target_peers[0]["memory_max_bytes"] == 0
            && target_peers[0]["remaining_growth_released"] == false,
        "raw same-claim peer differs",
    )?;
    let base = &documents[69];
    let increments = array(base, "positive_increments")?;
    let previous = c::bound(&base["previous"])?;
    let mut external = 0u64;
    let mut increment_keys = BTreeSet::new();
    for row in increments {
        c::need(
            increment_keys.insert(c::string(row, "kind")?)
                && !c::string(row, "kind")?.contains("154"),
            "duplicate or target154 canonical increment",
        )?;
        let source = c::bound(&row["source"])?;
        let amount = source_increment(c::string(row, "kind")?, &source)?;
        c::need(
            amount == c::number(row, "bytes")?,
            "actual canonical increment differs",
        )?;
        external = external
            .checked_add(amount)
            .ok_or("canonical sum overflow")?;
    }
    c::need(
        increments.len() == 9
            && external == 679_347_695_616
            && previous["complete_retained_external_DATA_bytes"] == 752_782_484_322u64
            && base["all_original_raw_rows_and_obligations_retained"] == true
            && base["raw_DATA_bytes"] == raw["protected_existing_DATA_bytes"]
            && base["complete_retained_external_DATA_bytes"] == external + 752_782_484_322
            && data(base)?
                == c::number(base, "raw_DATA_bytes")?
                    + c::number(base, "complete_retained_external_DATA_bytes")?,
        "canonical retained complete booking differs",
    )?;
    Ok(
        json!({"current_authority":manifest["current_authority"],"original_invocation_id":c::IID,"charged_original_DATA_bytes":c::OLD_DATA,"prior_effective_original154_DATA_endings":0,"complete_ancestry_authenticated":true,"manifest":request["manifest"],"authenticated_nodes":70,"authenticated_edges":69,"positive_delta_sum_bytes":positive,"negative_delta_sum_bytes":negative,"raw154_representations_counted_as_one":true,"historical722_duplicate_and_exact_addback_preserved":true,"selection_performed":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_arithmetic_rejects_overflow_and_false_equal() {
        assert!(equation(u64::MAX, 0, "add", 1).is_err());
        assert!(equation(0, 0, "subtract", 1).is_err());
        assert!(equation(1, 1, "equal", 1).is_err());
        assert_eq!(equation(5, 3, "subtract", 2).unwrap(), -2);
    }
    #[test]
    fn unregistered_negative_or_target_claim_rejected() {
        assert!(other_claim(8, &json!({}), &[]).is_err());
        assert!(other_claim(5, &json!({"original_producer_invocation_id":c::IID}), &[]).is_err());
        assert!(
            other_claim(
                5,
                &json!({"original_producer_invocation_id":"722adc397ae24bb4b96d452783599f57"}),
                &[]
            )
            .is_ok()
        );
    }
    #[test]
    fn scalar_never_uses_previous_or_ambiguous_totals() {
        assert!(data(&json!({"previous_complete_DATA_bytes":5})).is_err());
        assert!(
            data(&json!({"complete_DATA_bytes":5,"complete_DATA_lower_bound_bytes":4})).is_err()
        );
        assert_eq!(data(&json!({"complete_DATA_bytes":5})).unwrap(), 5);
    }
}
