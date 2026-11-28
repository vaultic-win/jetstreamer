//! Admit the original retry-11 run with or without the optional, already protected 168 producer.
use super::*;

#[cfg(not(epoch166_after168_retry3))]
pub const FIT: &str =
    "incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry2-v2/post-stop-fit";
#[cfg(not(epoch166_after168_retry3))]
pub const FIT_SEAL: &str = "164f3562bcb6490b05d8ee0679670489a79864e7bb2cf06e5d1de1823f678268";
pub const PREPARED: &str = "ec59431a69b7e13fbb6cd8c14b3e49e915b9f9c003a1b5ba3d70375f42ecfe8c";
#[cfg(not(epoch166_after168_retry3))]
const PREVIOUS_WRITER: &str = "f1b4781788205dbc065f5b116577c2e263e523f65e19cd658c31a9ae7e86fdb4";
#[cfg(not(epoch166_after168_retry3))]
const NEXT_WRITER: &str = "8c06411819ee01049d5e799756b078e62fa0f6109a8afebf4deb34790d1dee5d";

#[cfg(all(epoch166_after168_retry3, not(any(epoch166_after168_closed, epoch166_after168_retry4))))]
pub const FIT: &str =
    "incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry3-v1/post-stop-fit";
#[cfg(epoch166_after168_retry4)]
pub const FIT: &str =
    "incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry4-v1/post-stop-fit";
#[cfg(epoch166_after168_closed)]
pub const FIT: &str =
    "incident-replay-fit-20261121-v1/tools-homefloor-closed168-retry3-v1/post-stop-fit";
#[cfg(epoch166_after168_retry3)]
pub const FIT_SEAL: &str = env!("RETRY3_FIT_SEAL");
#[cfg(epoch166_after168_retry4)]
const PREVIOUS_WRITER: &str = "2b36ded26d4e244c166c1f3623d8f125f558b94fb1a17555b96c361d5cb3cfd2";
#[cfg(all(epoch166_after168_retry3, not(epoch166_after168_retry4)))]
const PREVIOUS_WRITER: &str = "8c06411819ee01049d5e799756b078e62fa0f6109a8afebf4deb34790d1dee5d";
#[cfg(epoch166_after168_retry3)]
const NEXT_WRITER: &str = env!("RETRY3_WRITER_SEAL");
const PREVIOUS_PACKAGE: &str = if cfg!(epoch166_after168_retry4) {
    "tools-cold168-retry3-v1"
} else if cfg!(epoch166_after168_retry3) {
    "tools-cold168-retry2-v1"
} else {
    "tools-cold170-retry13-v2"
};
const NEXT_PACKAGE: &str = if cfg!(epoch166_after168_retry4) {
    "tools-cold168-retry4-v1"
} else if cfg!(epoch166_after168_retry3) {
    "tools-cold168-retry3-v1"
} else {
    "tools-cold168-retry2-v1"
};

/// The sealed fit already authenticates the service, its exclusive lock and the native peers.
/// Compare the stable generation evidence, excluding monotonically advancing guard samples.
pub fn peers_and_writer(price: &Value) -> Result<Value> {
    let survivors = price["survivors"].as_object().context("survivors")?;
    let saved = survivors.get("172").context("missing 172")?;
    let replicas = price["replacements"].as_object().context("replacements")?;
    ensure!(
        survivors.len() == 1 && replicas.contains_key("167") && replicas.contains_key("170"),
        "missing original peers"
    );
    let mut peers = json!({
        "172":[saved["unit"],saved["invocation_id"],saved["timer_invocation_id"],saved["processes"],saved["guard"]["plan"]]
    });
    for (epoch, row) in replicas {
        ensure!(
            matches!(epoch.as_str(), "167" | "168" | "170")
                && row["admission"].is_object()
                && row["first_guard"].is_object(),
            "foreign or unprotected peer {epoch}"
        );
        let processes = row["processes"]
            .as_array()
            .context("missing peer processes")?;
        ensure!(
            processes
                .iter()
                .any(|p| p[0] == row["producer_pid"] && p[1] == row["start_ticks"]),
            "missing peer producer {epoch}"
        );
        peers[epoch] = json!([
            row["producer_unit"],
            row["producer_invocation_id"],
            row["timer_invocation_id"],
            processes,
            row["plan"],
            row["admission"],
            row["first_guard"]
        ]);
    }
    for (_, row) in peers.as_object().unwrap() {
        let processes = row[3].as_array().context("missing processes")?;
        ensure!(
            row[0].as_str().is_some_and(|s| s.ends_with(".service"))
                && row[1].as_str().is_some_and(|s| hex(s, 32))
                && row[2].as_str().is_some_and(|s| hex(s, 32))
                && (1..=2).contains(&processes.len())
                && processes.iter().all(|p| p.as_array().is_some_and(
                    |a| a.len() == 4 && a.iter().all(|x| x.as_u64().is_some_and(|n| n > 0))
                ))
                && row[4]["sha256"].as_str().is_some_and(|s| hex(s, 64)),
            "incomplete guarded peer"
        );
    }
    let writer = &price["status_registration"];
    let seal = st(&writer["consumer_seal"], "sha256")?;
    let name = match seal {
        PREVIOUS_WRITER if !replicas.contains_key("168") => PREVIOUS_PACKAGE,
        NEXT_WRITER => NEXT_PACKAGE,
        _ => bail!("wrong registered writer for active peers"),
    };
    ensure!(
        writer["consumer_seal"]["path"]
            == json!(
                rt("survivor172-cadence-20261122-v1")
                    .join(name)
                    .join("deployment-seal-receipt.json")
            )
            && hex(st(writer, "invocation_id")?, 32)
            && n(writer, "pid")? > 1
            && n(writer, "start_ticks")? > 0
            && writer["registration"]["sha256"]
                == "02027e3e35364f64913b34162fde295bfb96b3123a9d9794545ce4e0b1a4e8ba",
        "incomplete registered writer"
    );
    Ok(json!({"peers":peers,"writer":writer,"fleet":price["fleet"]}))
}

pub fn prestart(price: &Value) -> Result<()> {
    let floor = fourth_lane_floor(price)?;
    let saved = &price["startup_nonexact_peer_floor"];
    let rows = price["replacements"].as_object().context("replacements")?;
    let retained = saved["retained_peer_bytes"]
        .as_object()
        .context("retained peers")?;
    let guards = saved["peer_guards"].as_object().context("peer guards")?;
    ensure!(
        retained.len() == rows.len() && guards.len() == rows.len(),
        "incomplete conservative peer coverage"
    );
    for (epoch, row) in rows {
        ensure!(
            n(&saved["retained_peer_bytes"], epoch)? > 0
                && guards.get(epoch) == Some(&row["guard"])
                && n(row, "floor")? <= floor,
            "missing protected peer {epoch}"
        );
    }
    Ok(())
}

/// A retry obtains a fresh authenticated inventory. Reuse its exact bytes if already recorded.
pub fn inventory(v: &Value) -> Result<Value> {
    let mut bytes = serde_json::to_vec_pretty(v)?;
    bytes.push(b'\n');
    let digest = sha(&bytes);
    let name = format!("INVENTORY_PRESTART_{digest}.json");
    let path = base().join(&name);
    if path.try_exists()? {
        Ok(doc(&path, Some(&digest))?.1)
    } else {
        record(&name, v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> Value {
        #[cfg(epoch166_after168_retry4)]
        let (mut price, _) = doc(
            &base().join("V7_PREFLIGHT_WITHOUT_168_20261123T013518026117Z.json"),
            Some("3a78fa27e1fbe889ba46d57a682e6e694a34cd1019365276e557f4c1f967056d"),
        )
        .unwrap();
        #[cfg(all(epoch166_after168_retry3, not(epoch166_after168_retry4)))]
        let (mut price, _) = doc(
            &base().join("INSTALLED_V5_AFTER_168_NODE_EXIT_20261123T005319083542Z.json"),
            Some("829680397007018b8ecbc0a200860e9ba4cddca27fc84c32d8a6bc505c329806"),
        )
        .unwrap();
        #[cfg(not(epoch166_after168_retry3))]
        let (mut price, _) = doc(
            &base().join("PREFLIGHT_001757_FIRST_AND_SECOND_20261123.json"),
            Some("307a182b84abb8bbd8428afbbfe05299cee6e1643cad778439764b86a2212aef"),
        )
        .unwrap();
        // Normalize the older three-peer quote into the successor provider's map shape.
        for epoch in ["167", "170"] {
            let floor = &price["startup_nonexact_peer_floor"];
            let bytes = floor[format!("retained{epoch}_bytes")].clone();
            let guard = floor[format!("peer_{epoch}_guard")].clone();
            price["startup_nonexact_peer_floor"]["retained_peer_bytes"][epoch] = bytes;
            price["startup_nonexact_peer_floor"]["peer_guards"][epoch] = guard;
        }
        price
    }

    #[test]
    fn original_status_and_prior_peers_remain_valid() {
        let price = original();
        prestart(&price).unwrap();
        let identity = peers_and_writer(&price).unwrap();
        for k in ["167", "170"] {
            let mut changed = price.clone();
            changed["replacements"].as_object_mut().unwrap().remove(k);
            assert!(peers_and_writer(&changed).is_err());
        }
        let mut updated = price.clone();
        updated["replacements"]["167"]["guard_time"] = json!(123);
        assert_eq!(peers_and_writer(&updated).unwrap(), identity);
        updated["replacements"]["167"]["processes"][1][1] = json!(9876);
        assert_ne!(peers_and_writer(&updated).unwrap(), identity);
        let mut rollback = price.clone();
        rollback["status_registration"]["invocation_id"] = json!("f".repeat(32));
        assert_ne!(peers_and_writer(&rollback).unwrap(), identity);
        rollback["status_registration"]["consumer_seal"]["sha256"] = json!("a".repeat(64));
        assert!(peers_and_writer(&rollback).is_err());
    }

    #[test]
    fn reverse_order_requires_admitted_168_and_qualified_writer() {
        let mut price = original();
        let (prepared, _) = doc(
            &rt(if cfg!(epoch166_after168_retry4) {
                "epoch168-retry4-rebook-20261123-v1/PREPARED.json"
            } else if cfg!(epoch166_after168_retry3) {
                "epoch168-retry3-rebook-20261123-v1/PREPARED.json"
            } else {
                "epoch168-retry2-rebook-20261122-v1/PREPARED.json"
            }),
            if cfg!(epoch166_after168_retry3) {
                None
            } else {
                Some("dd1b2296e8cd987eccf90053b999d647cd28c09a43279493fd625c719ed0388a")
            },
        )
        .unwrap();
        let mut peer = price["replacements"]["167"].clone();
        peer["producer_unit"] = prepared["profile"]["producer_unit"].clone();
        peer["producer_invocation_id"] = json!("4".repeat(32));
        price["replacements"]["168"] = peer.clone();
        assert!(peers_and_writer(&price).is_err());
        let (q, _) = doc(
            &rt(if cfg!(epoch166_after168_retry4) {
                "survivor172-cadence-20261122-v1/COLD168_RETRY4_V1_STATUS_QUALIFIED.json"
            } else if cfg!(epoch166_after168_retry3) {
                "survivor172-cadence-20261122-v1/COLD168_RETRY3_V1_STATUS_QUALIFIED.json"
            } else {
                "survivor172-cadence-20261122-v1/COLD168_RETRY2_V1_STATUS_QUALIFIED.json"
            }),
            None,
        )
        .unwrap();
        assert_eq!(q["package"]["sha256"], NEXT_WRITER);
        price["status_registration"]["consumer_seal"] = q["package"].clone();
        let identity = peers_and_writer(&price).unwrap();
        assert!(prestart(&price).is_err());
        price["startup_nonexact_peer_floor"]["retained_peer_bytes"]["168"] = json!(4096);
        price["startup_nonexact_peer_floor"]["peer_guards"]["168"] = peer["guard"].clone();
        prestart(&price).unwrap();
        for (key, val) in [
            ("first_guard", Value::Null),
            ("admission", Value::Null),
            ("producer_pid", json!(1)),
            ("processes", json!([])),
        ] {
            let mut bad = price.clone();
            bad["replacements"]["168"][key] = val;
            assert!(peers_and_writer(&bad).is_err(), "{key}");
        }
        let mut bad = price.clone();
        bad["replacements"]["168"]["floor"] = json!(u64::MAX);
        assert!(prestart(&bad).is_err());
        bad = price.clone();
        bad["replacements"]["168"]["timer_invocation_id"] = json!("b".repeat(32));
        assert_ne!(identity, peers_and_writer(&bad).unwrap());
    }
}
