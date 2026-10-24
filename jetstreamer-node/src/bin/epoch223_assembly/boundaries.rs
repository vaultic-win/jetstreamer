//! Independent finalized RPC metadata scope for the exact epoch 223 edges.
//! Never opens an archive or grants replay/publication authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;
pub(super) const ENDPOINT: &str = "https://api.mainnet-beta.solana.com";
pub(super) const ROLES: [(&str, u64); 3] = [
    ("anchor", 96335999),
    ("first", 96336000),
    ("terminal", 96767999),
];
pub(super) fn request(slot: u64) -> Value {
    json!({"jsonrpc":"2.0","id":slot,"method":"getBlock","params":[slot,
    {"commitment":"finalized","transactionDetails":"none","rewards":false,"maxSupportedTransactionVersion":0}]})
}
fn hash(v: &Value) -> Result<&str> {
    let text = v.as_str().context("boundary blockhash must be a string")?;
    let value: text_hash::Hash = text.parse().context("invalid boundary blockhash")?;
    ensure!(
        value != text_hash::Hash::default() && value.to_string() == text,
        "noncanonical/zero boundary blockhash"
    );
    Ok(text)
}
// A small alias keeps the actual shared Hash parser/version explicit.
mod text_hash {
    pub(super) use solana_hash::Hash;
}
fn block(v: &Value, slot: u64) -> Result<&Value> {
    ensure!(
        v["jsonrpc"] == "2.0" && v["id"] == slot && v.get("error").is_none(),
        "boundary RPC response id/error differs"
    );
    let r = &v["result"];
    ensure!(
        r.is_object()
            && r["parentSlot"].as_u64().is_some_and(|p| p < slot)
            && r["blockHeight"].as_u64().is_some_and(|h| h > 0)
            && r["blockTime"].as_i64().is_some_and(|t| t > 0),
        "canonical boundary is unavailable/skipped or metadata is incomplete; preserve evidence and obtain a trusted exact boundary, never invent a hash"
    );
    hash(&r["blockhash"])?;
    hash(&r["previousBlockhash"])?;
    Ok(r)
}
pub(super) fn derive(responses: &BTreeMap<String, Value>) -> Result<Value> {
    ensure!(
        responses
            .keys()
            .map(String::as_str)
            .eq(ROLES.iter().map(|(r, _)| *r)),
        "incomplete canonical boundary response census"
    );
    let a = block(&responses["anchor"], ROLES[0].1)?;
    let f = block(&responses["first"], ROLES[1].1)?;
    let t = block(&responses["terminal"], ROLES[2].1)?;
    ensure!(
        f["parentSlot"] == ROLES[0].1
            && f["previousBlockhash"] == a["blockhash"]
            && f["blockHeight"].as_u64()
                == a["blockHeight"].as_u64().and_then(|n| n.checked_add(1))
            && t["blockHeight"]
                .as_u64()
                .zip(f["blockHeight"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && t["blockTime"]
                .as_i64()
                .zip(f["blockTime"].as_i64())
                .is_some_and(|(a, b)| a >= b),
        "canonical first block does not link to slot 96335999 or terminal metadata goes backwards"
    );
    Ok(
        json!({"candidate_anchor":{"slot":96335999,"blockhash":a["blockhash"]},
        "first_rpc_child":{"slot":96336000,"blockhash":f["blockhash"],"parent_slot":f["parentSlot"],"parent_blockhash":f["previousBlockhash"]},
        "expected_terminal":{"slot":96767999,"blockhash":t["blockhash"]},"canonical_epoch_output_start":96336000,
        "canonical_epoch_output_count":432000,"parent_and_child_rpc_hash_link_matches":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn response(slot: u64, parent: u64, height: u64, hash: u8, previous: u8) -> Value {
        json!({"jsonrpc":"2.0","id":slot,"result":{"parentSlot":parent,"blockHeight":height,"blockTime":1000+(slot-ROLES[0].1),
            "blockhash":text_hash::Hash::new_from_array([hash;32]).to_string(),"previousBlockhash":text_hash::Hash::new_from_array([previous;32]).to_string()}})
    }
    fn fixture() -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("anchor".into(), response(96335999, 96335998, 100, 1, 9)),
            ("first".into(), response(96336000, 96335999, 101, 2, 1)),
            ("terminal".into(), response(96767999, 96767998, 200, 3, 4)),
        ])
    }
    #[test]
    fn exact_adjacent_anchor_is_separate_from_the_earlier_native_bootstrap() {
        let rows = fixture();
        let d = derive(&rows).unwrap();
        assert_eq!(d["candidate_anchor"]["slot"], 96335999);
        assert_eq!(d["expected_terminal"]["slot"], 96767999);
        assert_eq!(d["canonical_epoch_output_count"], 432000);
        for (role, pointer, value) in [
            ("anchor", "/id", json!(96335538)),
            ("first", "/result/parentSlot", json!(96335538)),
            (
                "first",
                "/result/previousBlockhash",
                json!(text_hash::Hash::new_from_array([8; 32]).to_string()),
            ),
            ("terminal", "/result", Value::Null),
            ("terminal", "/result/blockHeight", json!(99)),
        ] {
            let mut bad = rows.clone();
            *bad.get_mut(role).unwrap().pointer_mut(pointer).unwrap() = value;
            assert!(derive(&bad).is_err(), "{role}:{pointer}");
        }
    }
    #[test]
    fn finalized_exact_requests_and_response_failures_never_grant_archive_coverage() {
        for (_, slot) in ROLES {
            let r = request(slot);
            assert_eq!(r["id"], slot);
            assert_eq!(r["params"][0], slot);
            assert_eq!(r["params"][1]["commitment"], "finalized");
        }
        let mut bad = fixture();
        bad.get_mut("anchor").unwrap()["error"] = json!({"code":-32004});
        assert!(derive(&bad).is_err());
        let mut bad = fixture();
        bad.remove("first");
        assert!(derive(&bad).is_err());
        assert!(hash(&json!(text_hash::Hash::default().to_string())).is_err());
    }
}
