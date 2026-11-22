use super::*;

const DIAGNOSTICS: &str = "/home/ubuntu/.codex/diagnostics";
const FLEET162: &str = "37d06338001d4b7a951e08bb9f9b68cf17e4064b29385ec3a5ec6c924e88eb4c";
const SAMPLE163: &str = "65905dea28eea35b719fc71357fe778bb9c4a1648c6f704db9c685324b4ba62f";
const SAMPLE164: &str = "02d87db0247b3cfe301a6090ccc9d3a129de987e555a4586a1e1f30f8f52ce8e";

const FLEET191: &str = "8930e45ed06f92fe0e3f2b91a9edb594abf3c23b35f4f16f16a2219f974f59ba";
const SAMPLE193: &str = "add251a1d3e42e0f9c3f5a4573c783a92207ab8d6b4887ca6991af143ae10ac1";

fn sample(version: u32, digest: &str) -> Bound {
    Bound::new(
        format!("{DIAGNOSTICS}/horizon-resume-observer-20261120-v{version}.json"),
        digest,
    )
}

fn completion(
    version: u32,
    family: &str,
    digest: &str,
    observer: &Bound,
    previous: &Bound,
) -> Result<()> {
    let state = PathBuf::from(format!(
        "{DIAGNOSTICS}/horizon-terminal-aware-cycle-v{version}-{family}-v1"
    ));
    let done = Bound::new(state.join("completion.json"), digest).json()?;
    let prescreen = binding(&done["prescreen"])?;
    let effective = binding(&done["effective_config"])?;
    ensure!(
        done["schema"] == "horizon-terminal-aware-observation-v1"
            && done["observer_output"].as_str() == observer.path.to_str()
            && done["observer_exit_code"] == 0
            && done["omitted_owners_unchanged"] == true
            && done["omitted_owner_reservations_retained"] == true
            && done["finalization_owner_reservations_retained"] == true
            && done["resource_release_authorized"] == false
            && prescreen.path == state.join("prescreen.json")
            && effective.path == state.join("effective-config.json"),
        "unqualified routine observation completion"
    );
    let before = prescreen.json()?;
    let wrapper = binding(&before["plan"])?.sealed()?;
    let config = binding(&wrapper["config"])?.sealed()?;
    let deployed = Bound::new(
        Path::new(text(&wrapper, "deployment")?).join("config.json"),
        &effective.sha256,
    );
    ensure!(
        effective.json()? == deployed.sealed()?
            && config["output"].as_str() == observer.path.to_str()
            && config["previous_sample"].as_str() == previous.path.to_str()
            && before["previous_sample_sha256"] == previous.sha256,
        "unbound routine effective observation"
    );
    Ok(())
}

/// Recover the authenticated intermediate sample for a registered gap in the fleet history.
pub fn validate_observer_predecessor(
    previous_fleet_path: &Path,
    previous_fleet_sha: &str,
    observer_path: &Path,
    observation: &Value,
) -> Result<()> {
    let (version, family, first_sha, middle_sha, last_sha, middle_done, last_done) =
        match previous_fleet_sha {
            FLEET162 => (
                162,
                "three-live-20261120",
                "0dda6f670a94ba9f2e6c9a395600e9417a7ce12fe754da49141f0dc46de76652",
                SAMPLE163,
                SAMPLE164,
                "628e5d8354b9df90787cde569921a93104f59e8d74bbd64be76e3f308ec55366",
                "858db1bdc67581c4df412a2a0e9403fde838bb63eef39af3b63967a5552ce0d0",
            ),
            FLEET191 => (
                191,
                "staged247-stopped228",
                "1a3e94567701f771c023f9a1bd9974957187562c293fc3bc869c9a83b2b2a738",
                "38bbc1c6a71266927829c516cdd35daf08a59cd8f5fc65ff9e93baf2e20708ba",
                SAMPLE193,
                "cc23480f253a6b57af52bc9c2d5502c39ca10087cb28cce1c6f575a8c5886a9f",
                "215110bd7bfb661a92647e1e117e980ee33b1de47356f85094c2dd79308fa6b3",
            ),
            _ => bail!("unregistered observation gap"),
        };
    let fleet = Bound::new(
        format!("{DIAGNOSTICS}/horizon-fleet-takeover-v{version}-20261120-v1/fleet-v1.json"),
        previous_fleet_sha,
    );
    let first = sample(version, first_sha);
    let middle = sample(version + 1, middle_sha);
    let last = sample(version + 2, last_sha);
    ensure!(
        previous_fleet_path == fleet.path
            && previous_fleet_sha == fleet.sha256
            && observer_path == last.path
            && observation == &last.json()?,
        "different fleet or final observation"
    );
    let prior = fleet.json()?;
    let a = first.json()?;
    let b = middle.json()?;
    ensure!(
        prior["first_epoch"] == 201
            && prior["last_epoch"] == 300
            && prior["observer_receipt"].as_str() == first.path.to_str()
            && prior["observer_sha256"] == first.sha256
            && prior["sampled_at_utc"] == a["recorded_at_utc"],
        "different predecessor coverage or clock"
    );
    for (bound, earlier, later) in [(&first, &a, &b), (&middle, &b, observation)] {
        let cadence = &later["cadence"];
        ensure!(
            cadence["previous_sample"].as_str() == bound.path.to_str()
                && cadence["previous_sample_sha256"] == bound.sha256
                && cadence["previous_sample_recorded_at_utc"] == earlier["recorded_at_utc"]
                && cadence["configured_not_before_utc"]
                    == earlier["cadence"]["next_routine_observation_not_before_utc"]
                && cadence["routine_minimum_interval_enforced"] == true
                && cadence["observation_reason"] == "routine"
                && num(cadence, "observed_interval_seconds")? >= 1800,
            "interrupted routine observation clock"
        );
    }
    completion(version + 1, family, middle_done, &middle, &first)?;
    completion(version + 2, family, last_done, &last, &middle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_a_different_fleet_without_host_evidence() {
        assert!(
            validate_observer_predecessor(
                Path::new("/other"),
                FLEET162,
                Path::new("/unused"),
                &Value::Null
            )
            .is_err()
        );
    }
    #[test]
    #[ignore = "requires original root-owned v162 to v164 observations"]
    fn accepts_only_the_original_v164_observation() {
        original_pair(162, FLEET162, SAMPLE164);
    }

    #[test]
    #[ignore = "requires original root-owned v191 to v193 observations"]
    fn accepts_only_the_original_v193_observation() {
        original_pair(191, FLEET191, SAMPLE193);
    }

    fn original_pair(version: u32, digest: &str, last_digest: &str) {
        let path = PathBuf::from(format!(
            "{DIAGNOSTICS}/horizon-fleet-takeover-v{version}-20261120-v1/fleet-v1.json"
        ));
        let last = sample(version + 2, last_digest);
        let mut observation = last.json().unwrap();
        validate_observer_predecessor(&path, digest, &last.path, &observation).unwrap();
        assert!(validate_observer_predecessor(&path, SAMPLE163, &last.path, &observation).is_err());
        assert!(
            validate_observer_predecessor(
                &path,
                digest,
                &sample(163, SAMPLE163).path,
                &observation
            )
            .is_err()
        );
        observation["cadence"]["previous_sample_recorded_at_utc"] = json!("2026-11-21T03:37:44Z");
        assert!(validate_observer_predecessor(&path, digest, &last.path, &observation).is_err());
    }
}
