// Read-only historical basis, not a successful counterfactual or launch permission.
use serde_json::Value;
pub const DIAGNOSIS_SHA256: &str =
    "1f9320d32c2ccf51a45731a0084a1f9e25875fc808c2fb30abede5cea77b00a6";
pub fn validate(d: &Value) -> Result<(), String> {
    let b = &d["positive_bank_bracket"];
    let t = &d["concrete_parent_transaction"];
    let v = &d["confirmed_failure"];
    if d["schema"] != "operator-native223-e70a-finalized-diagnosis-v2"
        || d["epoch"] != 223
        || d["unit"] != "horizon-qualify-223-v1620-root-prefix-resource-full-v1.service"
        || d["invocation_id"] != "e70aaf097e7c4583b216aba454145910"
        || b["last_matching_bank_slot"] != 96_544_586u64
        || b["matching_bank_hash"] != "3PMZX37CYLF9Ay87r1aKREnf1cZoWDLRKXRAMx5TZYso"
        || b["first_locally_bracketed_mismatching_bank_slot"] != 96_544_587u64
        || b["canonical_voted_bank_hash"] != "5UsE976GhKUXyUyKG1tUDiN7cT2BPYvKJN7Wx1ptJHm7"
        || b["actual_replay_bank_hash"] != "GRD2nwB5ADKJNu3oiKJibJysRLpMNw3aSkA4NhpKoHxX"
        || t["parent_slot"] != 96_544_587u64 || t["transaction_index"] != 432
        || t["signature"] != "358YDY6TSXgU4X8Q1UzjPRrYTzBCz8CKE9tbS5neXZYWNPuo2bvWrcmji1RiWS8mbvokPxS5vF1TMP3Htymyruj8"
        || t["wire_fixture"]["sha256"] != "388daeef55ab81c31a44ddfc665cdc8b2dd12f2cbce1fd53849f4e6522faf8b4"
        || v["slot"] != 96_544_588u64 || v["entry"] != 4 || v["transaction"] != 0
        || v["signature"] != "4P2u3JnCkqkaDMG4TC4o2mLVckYmt3MCYzdUvNpTu7RAz3kTfVyPrRzVnchncRpTdBv8nsrCJX9kxVXiAmUxrNtD"
        || !v.get("finalized_rpc_error").is_some_and(Value::is_null)
        || v["voted_hash"] != b["canonical_voted_bank_hash"]
        || d["independent_parent_chain"]["parent_slot"] != 96_544_587u64
        || d["independent_parent_chain"]["parent_parent_slot"] != 96_544_586u64
    {
        return Err("continuous root requires the exact preserved canonical divergence and original wires; history is not successful replay".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> Value {
        json!({"schema":"operator-native223-e70a-finalized-diagnosis-v2","epoch":223,
            "unit":"horizon-qualify-223-v1620-root-prefix-resource-full-v1.service",
            "invocation_id":"e70aaf097e7c4583b216aba454145910",
            "positive_bank_bracket":{"last_matching_bank_slot":96544586u64,
                "matching_bank_hash":"3PMZX37CYLF9Ay87r1aKREnf1cZoWDLRKXRAMx5TZYso",
                "first_locally_bracketed_mismatching_bank_slot":96544587u64,
                "canonical_voted_bank_hash":"5UsE976GhKUXyUyKG1tUDiN7cT2BPYvKJN7Wx1ptJHm7",
                "actual_replay_bank_hash":"GRD2nwB5ADKJNu3oiKJibJysRLpMNw3aSkA4NhpKoHxX"},
            "concrete_parent_transaction":{"parent_slot":96544587u64,"transaction_index":432,
                "signature":"358YDY6TSXgU4X8Q1UzjPRrYTzBCz8CKE9tbS5neXZYWNPuo2bvWrcmji1RiWS8mbvokPxS5vF1TMP3Htymyruj8",
                "wire_fixture":{"sha256":"388daeef55ab81c31a44ddfc665cdc8b2dd12f2cbce1fd53849f4e6522faf8b4"}},
            "confirmed_failure":{"slot":96544588u64,"entry":4,"transaction":0,"finalized_rpc_error":null,
                "signature":"4P2u3JnCkqkaDMG4TC4o2mLVckYmt3MCYzdUvNpTu7RAz3kTfVyPrRzVnchncRpTdBv8nsrCJX9kxVXiAmUxrNtD",
                "voted_hash":"5UsE976GhKUXyUyKG1tUDiN7cT2BPYvKJN7Wx1ptJHm7"},
            "independent_parent_chain":{"parent_slot":96544587u64,"parent_parent_slot":96544586u64}})
    }
    #[test]
    fn historical_failure_is_bound_without_claiming_a_passing_counterfactual() {
        validate(&fixture()).unwrap();
    }
    #[test]
    fn poh_hash_old_replay_hash_foreign_wire_or_missing_success_cannot_seed_root() {
        for (pointer, value) in [
            ("/positive_bank_bracket/canonical_voted_bank_hash", json!("BrifEBcMmiHTBhqcgwhNcFSErZn6cd12BmXjVxboeUV5")),
            ("/positive_bank_bracket/canonical_voted_bank_hash", json!("GRD2nwB5ADKJNu3oiKJibJysRLpMNw3aSkA4NhpKoHxX")),
            ("/concrete_parent_transaction/wire_fixture/sha256", json!("0".repeat(64))),
            ("/confirmed_failure/entry", json!(3)),
            ("/confirmed_failure/finalized_rpc_error", json!("SlotHashMismatch")),
            ("/invocation_id", json!("foreign")),
        ] {
            let mut d=fixture(); *d.pointer_mut(pointer).unwrap()=value;
            assert!(validate(&d).is_err(), "accepted {pointer}");
        }
        let mut missing=fixture(); missing["confirmed_failure"].as_object_mut().unwrap().remove("finalized_rpc_error");
        assert!(validate(&missing).is_err());
    }
}
