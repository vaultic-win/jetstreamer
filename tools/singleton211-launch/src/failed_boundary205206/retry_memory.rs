//! An independently opted-in memory release for the completed second booking.
use super::*;
pub(super) const FIELD: &str = "completed_boundary205206_retry_memory_release";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon205206-adjacent-boundary-v137-v2";
const ORIGINAL_BOOKING: &str =
    "/home/ubuntu/.codex/diagnostics/horizon205206-adjacent-boundary-retry-v137-v2/booking.json";
const ORIGINAL_BOOKING_SHA: &str =
    "85afcbaa870ed3325181462780670812cba6878ffae74331aef2d63c4608e9be";
const LAUNCH: &str =
    "/home/ubuntu/.codex/diagnostics/horizon205206-adjacent-boundary-retry-v137-v2/launch.json";
const LAUNCH_SHA: &str = "7c02d083402287ecbb6c53e4e7511e8a21d144621f8903247cc75841397d771d";

fn only_row(rows: &[capacity::Reservation], currents: &BTreeMap<String, u64>) -> Result<usize> {
    let candidates: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.unit == RETRY || r.invocation_id == RETRY_IID)
        .collect();
    let [(index, r)] = candidates.as_slice() else {
        bail!("missing, duplicated or aliased original retry reservation")
    };
    ensure!(
        r.unit == RETRY
            && r.invocation_id == RETRY_IID
            && r.maximum_memory_bytes == CAP
            && r.minimum_free_bytes == 3_908_104_436_088
            && r.remaining_disk_growth_bytes == 268435456
            && r.release.is_none()
            && !currents.contains_key(RETRY)
            && r.source
                == Bound::new(
                    "/var/lib/jetstreamer/horizon-native257-current-bookings-v138-ops-v1/boundary-booking.json",
                    "834f51f10bf2221ccf5a48465a96c626db778481ce72af6518028c36530f77e6"
                ),
        "retry still live, already released or substituted"
    );
    Ok(*index)
}

fn original_sources(row: &capacity::Reservation, bridge: &Bound) -> Result<Value> {
    let launch = Bound::new(LAUNCH, LAUNCH_SHA);
    let booking = Bound::new(ORIGINAL_BOOKING, ORIGINAL_BOOKING_SHA);
    let nominal = row.source.sealed()?;
    let overlap = binding(&nominal["field_sources"]["unit"]["document"])?.sealed()?;
    let l = launch.json()?;
    let b = booking.json()?;
    ensure!(
        overlap["original"] == json!(booking)
            && overlap["launch"] == json!(launch)
            && l["booking"] == json!(booking)
            && l["unit"]["InvocationID"] == RETRY_IID
            && l["unit"]["Id"] == RETRY
            && text(&l["unit"], "MemoryMax")?.parse::<u64>()? == CAP
            && l["unit"]["MemorySwapMax"] == "0"
            && b["actor"] == RETRY
            && b["actual_credit"] == 0
            && b["command"] == json!([format!("{PACKAGE}/verify-pair")]),
        "original launch/owner/booking mismatch"
    );
    let receipt = bridge.json()?;
    let plan = Bound::new(
        Path::new(PACKAGE).join("plan.json"),
        "f7c21352dd5c9d938a30f57da0e3a8819a49bea62d39ee34adfc281842b67869",
    );
    let p = plan.sealed()?;
    let image = Bound::new(
        "/var/lib/jetstreamer/horizon205-boundary-plans-20261118-v1/jetstreamer-horizon-boundary-bridge",
        "845867e4656802f3565825b9f0875f2df6697a169a3cc3eb530b3af1324992d7",
    );
    image.artifact()?;
    let verifier = binding(&p["verifier"])?;
    verifier.artifact()?;
    let deployment = Bound::new(
        Path::new(PACKAGE).join("deployment-seal-receipt.json"),
        "1b7602af73f3fd35c8583ad5d1fc520774e67ee671a1babcdf69c6c27d96c8da",
    );
    deployment.sealed()?;
    ensure!(
        receipt["plan"] == json!(plan)
            && receipt["bridge"]["executable_sha256"] == image.sha256
            && receipt["bridge"]["verifier_sha256"] == verifier.sha256
            && receipt["authority"]
                == json!({"boundary_verified":true,"archive_publication_authorized":false,"local_archive_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        "different bridge outcome"
    );
    // The sealed script unsets the three configured R2 variables before
    // execing the bridge. This local check never opens the credential file.
    let shim = Bound::new(
        Path::new(PACKAGE).join("verify-pair"),
        "ee7347fd0801eaa1a5c4c703479067f6db60aaf255dbadfaaff6e9a4f26113c8",
    );
    let command = String::from_utf8(shim.bytes(true)?)?;
    ensure!(command.ends_with(&format!("unset HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY\nexec {} {} --plan-sha256 {} --self-sha256 {}\n",image.path.display(),plan.path.display(),plan.sha256,image.sha256)), "credential-free original bridge closure changed");
    Ok(
        json!({"original_launch":launch,"original_booking":booking,"nominal_row_source":row.source,"deployment":deployment,"plan":plan,"bridge_executable":image,"verifier":verifier,"script":shim}),
    )
}

fn fresh_claims(review: &Value, fleet: &Value) -> Result<()> {
    ensure!(
        review["boot_id"] == BOOT
            && fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == BOOT
            && review["Main_accepted"] == true
            && review["single_campaign_controller_confirmed"] == true,
        "unaccepted or foreign retry closure"
    );
    fresh(num(review, "recorded_unix_seconds")?, now()?, 300)?;
    fresh(num(fleet, "recorded_unix_seconds")?, now()?, 300)?;
    let plan = Bound::new(text(fleet, "plan")?, text(fleet, "plan_sha256")?).json()?;
    let names = |row: &Value| {
        row.to_string().contains(RETRY_IID)
            || row
                .to_string()
                .contains("horizon205206-adjacent-boundary-v137-v2")
    };
    for (document, fields) in [
        (
            fleet,
            &[
                "active",
                "diagnostics",
                "auxiliary_diagnostics",
                "pipelines",
            ][..],
        ),
        (&plan, &["diagnostics", "pipeline_claims"][..]),
    ] {
        for key in fields {
            ensure!(
                !document[*key]
                    .as_array()
                    .context("incomplete prospective owner roster")?
                    .iter()
                    .any(names),
                "fleet has a current or future retry claim"
            );
        }
    }
    ensure!(
        plan["tracked_units"]
            .as_array()
            .context("tracked fleet units")?
            .iter()
            .any(|u| u == RETRY),
        "retry missing from full fleet tracking"
    );
    Ok(())
}

fn future_claims(n: &mut Native) -> Result<()> {
    let jobs = n.run(
        "/usr/bin/systemctl",
        &["list-jobs", "--no-legend", "--plain", "--no-pager"],
    )?;
    ensure!(
        !std::str::from_utf8(&jobs)?.contains(RETRY),
        "retry has a pending job"
    );
    // The separately pinned failed v135 transient still names the old shared
    // mountpoint. Its original shape is the sole historical recipe exception.
    let old = Path::new("/run/systemd/transient").join(OLD);
    let expected = BTreeMap::from([(
        old.clone(),
        "02f4fa7fbefddc2ad5461dd4e7156e62d19da0d6a1a543667280fbeab8a7adc7".to_owned(),
    )]);
    super::super::native211_cold_growth::staged_recipes(
        &[b"horizon205206-adjacent-boundary-v137-v2", TMP.as_bytes()],
        &expected,
    )?;
    let refs = native265_growth::tree_references(Path::new("/proc"), Path::new(PACKAGE))?;
    ensure!(
        refs.references.is_empty(),
        "process retains retry's plan or executable"
    );
    Ok(())
}

pub(in crate::native257_fit) fn apply(
    n: &mut Native,
    review: &Value,
    fleet: &Value,
    currents: &BTreeMap<String, u64>,
    rows: &mut [capacity::Reservation],
    earlier: Option<&Value>,
) -> Result<Option<Value>> {
    let Some(request) = review.get(FIELD) else {
        return Ok(None);
    };
    let bridge = Bound::new(BRIDGE, BRIDGE_SHA);
    ensure!(
        request == &json!({"bridge":bridge,"no_pending_or_future_retry_confirmed":true}),
        "unregistered retry release choice"
    );
    for name in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "HORIZON_ACCESS_KEY_ID",
        "HORIZON_SECRET_ACCESS_KEY",
        "HORIZON_S3_ENDPOINT",
    ] {
        ensure!(
            std::env::var_os(name).is_none(),
            "retry closure must run without storage credentials"
        );
    }
    fresh_claims(review, fleet)?;
    let index = only_row(rows, currents)?;
    let sources = original_sources(&rows[index], &bridge)?;
    let retry = n.show(RETRY)?;
    let expected: Value = serde_json::from_str(COMPLETED_RETRY)?;
    ensure!(
        retry == expected["native"] && fleet["unit_census"][RETRY] == expected["fleet"],
        "retry is live, restartable or substituted"
    );
    let (completion, drainage) = if let Some(old) = earlier {
        ensure!(
            old["unit"] == OLD
                && old["retry_state"] == retry
                && old["completed_retry"]["bridge"] == json!(bridge),
            "independent old proof lacks original retry completion"
        );
        (old["completed_retry"].clone(), old["drainage"].clone())
    } else {
        (
            collected_retry(n, &retry, fleet, &rows[index])?,
            census(&retry)?,
        )
    };
    ensure!(
        drainage["old_cgroup_absent"] == true
            && drainage["retry_mount"].is_null()
            && drainage["host_target_empty"] == true
            && drainage["process_reference_scan"]["references"] == json!([]),
        "retry still retains a mount or process reference"
    );
    future_claims(n)?;
    ensure!(n.show(RETRY)? == retry, "retry changed during proof");
    unavailable(&Path::new("/sys/fs/cgroup/system.slice").join(RETRY))?;
    unavailable(&Path::new("/run/systemd/transient").join(RETRY))?;
    fresh_claims(review, fleet)?;
    n.check()?;
    rows[index].release = Some(bridge.clone());
    Ok(Some(
        json!({"schema":"horizon-completed-boundary205206-retry-memory-release-v1","unit":RETRY,"invocation_id":RETRY_IID,"bridge":bridge,"sources":sources,"completion":completion,"drainage":drainage,"released_memory_bytes":CAP,"released_disk_growth_bytes":0,"physical_allocation_credit_bytes":0,"inherited_floor_credit_bytes":0,"original_ledger_unchanged":true}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn retry() -> capacity::Reservation {
        capacity::Reservation {
            unit: RETRY.into(),
            invocation_id: RETRY_IID.into(),
            maximum_memory_bytes: CAP,
            minimum_free_bytes: 3_908_104_436_088,
            remaining_disk_growth_bytes: 268435456,
            source: Bound::new(
                "/var/lib/jetstreamer/horizon-native257-current-bookings-v138-ops-v1/boundary-booking.json",
                "834f51f10bf2221ccf5a48465a96c626db778481ce72af6518028c36530f77e6",
            ),
            release: None,
        }
    }
    #[test]
    fn independent_completed_retry_refuses_live_released_duplicate_or_substituted_row() {
        let row = retry();
        let idle = BTreeMap::new();
        assert_eq!(only_row(std::slice::from_ref(&row), &idle).unwrap(), 0);
        assert!(only_row(&[row.clone(), row.clone()], &idle).is_err());
        assert!(
            only_row(
                std::slice::from_ref(&row),
                &BTreeMap::from([(RETRY.to_string(), 0)])
            )
            .is_err()
        );
        for candidate in [
            capacity::Reservation {
                release: Some(Bound::new(BRIDGE, BRIDGE_SHA)),
                ..row.clone()
            },
            capacity::Reservation {
                invocation_id: IID.into(),
                ..row.clone()
            },
            capacity::Reservation {
                source: Bound::new(TERMINAL, SHA),
                ..row.clone()
            },
            capacity::Reservation {
                remaining_disk_growth_bytes: 0,
                ..row.clone()
            },
            capacity::Reservation {
                minimum_free_bytes: 0,
                ..row.clone()
            },
            capacity::Reservation {
                maximum_memory_bytes: 0,
                ..row.clone()
            },
        ] {
            assert!(only_row(&[candidate], &idle).is_err());
        }
    }
}
