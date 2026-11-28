//! Recognize successors of the exact Nov 22 guard_stops observer in the reviewed route set.
use crate::{ident, raw, sha};
use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const PREFIX: &str = "horizon-observer-root";
const TAIL: &str = "-live166167170-20261122-v1";
const SEED: &str = "system:horizon-observer-root024010-live166167170-20261122-v1.service";
const SURVIVOR_SEED: &str = "system:horizon-observer-root191757-live166167170-20261122-v1.service";
const SURVIVOR_CONFIG_SHA: &str =
    "cad29ce493591878fe4227ebeaf6f597b3e05620e5c73003196fbfd314693f92";
const WRAPPER: &str = "/var/lib/jetstreamer/horizon_runtime_data/prefix140-status-cadence-20261122-v1/cadence-tools/guard_stops.py";
const PYTHON: &str = "/usr/bin/python3";
const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/resident-observer-20261121-v1/observer/jetstreamer-horizon-observe";

#[derive(Clone, Copy)]
enum Observer {
    GuardStops,
    Survivor172,
}

struct Schedule {
    observer: Observer,
    seconds: u32,
    id: String,
    previous_dir: String,
    config: String,
    fragment: String,
}

fn tag(seconds: u32) -> String {
    format!(
        "{:02}{:02}{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}
fn utc(seconds: u32) -> String {
    format!(
        "2026-11-22T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}
fn sample(seconds: u32) -> String {
    format!("{BASE}/sample-root{}{TAIL}.json", tag(seconds))
}
impl Schedule {
    fn from_unit(unit: &str) -> Result<Option<Self>> {
        let Some(id) = unit.strip_prefix("system:") else {
            return Ok(None);
        };
        let Some(time) = id
            .strip_prefix(PREFIX)
            .and_then(|s| s.strip_suffix(&format!("{TAIL}.service")))
        else {
            return Ok(None);
        };
        ensure!(
            time.len() == 6 && time.bytes().all(|b| b.is_ascii_digit()),
            "invalid Nov 22 observer time"
        );
        let hour: u32 = time[..2].parse()?;
        let minute: u32 = time[2..4].parse()?;
        let second: u32 = time[4..].parse()?;
        let seconds = hour * 3600 + minute * 60 + second;
        ensure!(hour < 24, "observer hour outside day");
        let observer = match (minute, second) {
            (10 | 40, 10) if seconds >= 2 * 3600 + 40 * 60 + 10 => Observer::GuardStops,
            (17 | 47, 57) if seconds >= 19 * 3600 + 17 * 60 + 57 => Observer::Survivor172,
            _ => anyhow::bail!("observer is off the reviewed cadence"),
        };
        let previous_dir = format!("{BASE}/root{}{TAIL}", tag(seconds - 1800));
        Ok(Some(Self {
            observer,
            seconds,
            id: id.into(),
            config: format!("{previous_dir}/sealed-next/observer.json"),
            previous_dir,
            fragment: format!("/run/systemd/transient/{id}"),
        }))
    }

    fn seed(&self) -> &'static str {
        match self.observer {
            Observer::GuardStops => SEED,
            Observer::Survivor172 => SURVIVOR_SEED,
        }
    }

    fn manager(&self, route: &Value) -> Result<Value> {
        let mut stable = route.clone();
        let fields = stable.as_object_mut().context("route snapshot")?;
        ensure!(fields.len() == 2, "unexpected route fields");
        let props = fields
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .context("manager properties")?;
        let command = match self.observer {
            Observer::GuardStops => format!("{PYTHON} -B {WRAPPER} {}", self.config),
            Observer::Survivor172 => format!("{IMAGE} {}", self.config),
        };
        ensure!(
            props.remove("Id") == Some(json!(self.id))
                && props.remove("FragmentPath") == Some(json!(self.fragment))
                && props.remove("ExecStart") == Some(json!(command))
                && props.get("DropInPaths") == Some(&json!("")),
            "observer identity, arguments or drop-ins changed"
        );
        let files = fields
            .get_mut("inputs")
            .and_then(Value::as_object_mut)
            .context("manager files")?;
        ensure!(
            files.remove(&self.fragment).is_some()
                && files.remove(&self.config).is_some()
                && match self.observer {
                    Observer::GuardStops =>
                        files.len() == 2
                            && files.contains_key(PYTHON)
                            && files.contains_key(WRAPPER),
                    Observer::Survivor172 => files.len() == 1 && files.contains_key(IMAGE),
                },
            "different manager inputs"
        );
        Ok(stable)
    }
    fn normalize_config(&self, bytes: &[u8]) -> Result<String> {
        let cfg: Value = serde_json::from_slice(bytes)?;
        ensure!(
            cfg["minimum_interval_seconds"] == 1800 && cfg["observation_reason"] == "routine",
            "not a routine 30 minute observation"
        );
        let mut result = std::str::from_utf8(bytes)?.to_owned();
        for (key, expected) in [
            ("not_before_utc", utc(self.seconds)),
            ("previous_sample", sample(self.seconds - 1800)),
            ("output", sample(self.seconds)),
        ] {
            ensure!(cfg[key] == expected, "incorrect {key}");
            let quoted = serde_json::to_string(&expected)?;
            ensure!(
                result.matches(&quoted).count() == 1,
                "ambiguous observer {key}"
            );
            result = result.replace(&quoted, &format!("<{key}>"));
        }
        Ok(result)
    }
}

fn sample_bound(path: &str, limit: u64, binding: &Value) -> Result<Vec<u8>> {
    let path = Path::new(path);
    let bytes = raw(path, limit, true)?;
    ensure!(
        binding["identity"] == ident(&fs::metadata(path)?) && binding["sha256"] == sha(&bytes),
        "sampled input changed: {}",
        path.display()
    );
    Ok(bytes)
}

fn receipt(path: &str, limit: u64) -> Result<Value> {
    Ok(serde_json::from_slice(&raw(Path::new(path), limit, true)?)?)
}

fn check_seal(
    s: &Schedule,
    config: &[u8],
    plan_bytes: &[u8],
    seal_bytes: &[u8],
    manifest: &[u8],
) -> Result<()> {
    let digest = sha(config);
    let dest = format!("{}/sealed-next", s.previous_dir);
    let source = format!("{}/observer.json", s.previous_dir);
    let plan: Value = serde_json::from_slice(plan_bytes)?;
    ensure!(
        plan == json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":[{"source":source,"name":"observer.json","sha256":digest,"mode":292}]}),
        "unexpected scheduler plan"
    );
    let mut seal: Value = serde_json::from_slice(seal_bytes)?;
    let created = seal
        .as_object_mut()
        .and_then(|m| m.remove("created_unix_seconds"))
        .and_then(|t| t.as_u64())
        .context("seal time")?;
    let due = 1_795_305_600 + u64::from(s.seconds);
    ensure!(
        (due - 1800..due).contains(&created),
        "observer seal outside its predecessor period"
    );
    ensure!(
        seal == json!({"schema":"jetstreamer-sealed-deployment-receipt-v1","plan_sha256":sha(plan_bytes),
         "sealer_sha256":"e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3",
         "destination":dest,"members":[{"source":source,"name":"observer.json","sha256":digest,"bytes":config.len(),"mode":"0444"}],
         "publication_authorized":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        "observer seal changed"
    );
    ensure!(
        manifest
            == format!(
                "{}  deployment-seal-receipt.json\n{digest}  observer.json\n",
                sha(seal_bytes)
            )
            .as_bytes(),
        "observer manifest changed"
    );
    Ok(())
}
fn check_predecessor(s: &Schedule, config: &[u8], fleet: &Value, observed: &[u8]) -> Result<()> {
    let obs: Value = serde_json::from_slice(observed)?;
    ensure!(
        fleet["owner"] == "/root"
            && fleet["primary_thread"] == crate::PRIMARY
            && fleet["sampled_at_utc"] == utc(s.seconds - 1800)
            && fleet["sole_next_observer"] == json!({"path":s.config,"sha256":sha(config)})
            && fleet["sole_next_timer"] == format!("{}.timer", s.id.trim_end_matches(".service"))
            && fleet["observer"] == json!({"path":sample(s.seconds-1800),"sha256":sha(observed)})
            && obs["recorded_at_utc"] == utc(s.seconds - 1800)
            && obs["cadence"]["next_routine_observation_not_before_utc"] == utc(s.seconds)
            && obs["cadence"]["minimum_interval_seconds"] == 1800
            && obs["cadence"]["observation_reason"] == "routine",
        "not the registered next observation of the accepted predecessor"
    );
    Ok(())
}
fn verify_schedule(s: &Schedule, bytes: &[u8]) -> Result<()> {
    let dest = Path::new(&s.previous_dir).join("sealed-next");
    let mode = fs::symlink_metadata(&dest)?;
    ensure!(
        mode.is_dir()
            && mode.uid() == 0
            && mode.mode() & 0o7777 == 0o555
            && fs::read_dir(&dest)?
                .collect::<std::io::Result<Vec<_>>>()?
                .len()
                == 3,
        "different observer deployment directory"
    );
    for name in [
        "observer.json",
        "SHA256SUMS",
        "deployment-seal-receipt.json",
    ] {
        ensure!(
            fs::symlink_metadata(dest.join(name))?.mode() & 0o7777 == 0o444,
            "different sealed observer member mode"
        );
    }
    ensure!(
        raw(
            Path::new(&format!("{}/observer.json", s.previous_dir)),
            2 << 20,
            true
        )? == bytes,
        "pre-seal observer input changed"
    );
    let plan = raw(
        Path::new(&format!("{}/next-seal-plan.json", s.previous_dir)),
        1 << 16,
        true,
    )?;
    let seal = raw(&dest.join("deployment-seal-receipt.json"), 1 << 16, true)?;
    let manifest = raw(&dest.join("SHA256SUMS"), 1024, true)?;
    check_seal(s, bytes, &plan, &seal, &manifest)?;
    let fleet = receipt(
        &format!("{}/ROOT_COMPLETE_OPERATIONAL_FLEET.json", s.previous_dir),
        16 << 20,
    )?;
    let observed = raw(Path::new(&sample(s.seconds - 1800)), 2 << 20, true)?;
    check_predecessor(s, bytes, &fleet, &observed)
}

// The seed's transient fragment can be garbage-collected. Its digest and the
// two permanent direct inputs come from the original, sealed route review.
fn compare(
    s: &Schedule,
    route: &Value,
    seed: &Value,
    config: &[u8],
    seed_config: &[u8],
    fragment: &[u8],
) -> Result<()> {
    let base = Schedule::from_unit(s.seed())?.context("invalid compiled seed")?;
    ensure!(
        s.manager(route)? == base.manager(seed)?,
        "observer manager or fixed inputs changed"
    );
    ensure!(
        s.normalize_config(config)? == base.normalize_config(seed_config)?,
        "observer scope changed"
    );
    let fragment_text = std::str::from_utf8(fragment)?;
    ensure!(
        fragment_text.matches(&s.config).count() == 2
            && sha(fragment_text.replace(&s.config, &base.config).as_bytes())
                == seed["inputs"][&base.fragment]["sha256"],
        "different transient fragment"
    );
    Ok(())
}

pub(super) fn reviewed(unit: &str, route: &Value, approved: &Map<String, Value>) -> Result<bool> {
    let Some(s) = Schedule::from_unit(unit)? else {
        return Ok(false);
    };
    let Some(seed) = approved.get(s.seed()) else {
        return Ok(false);
    };
    let fragment = sample_bound(&s.fragment, 1 << 16, &route["inputs"][&s.fragment])?;
    verify_route(&s, route, seed, &fragment)?;
    Ok(true)
}

fn verify_route(s: &Schedule, route: &Value, seed: &Value, fragment: &[u8]) -> Result<()> {
    let base = Schedule::from_unit(s.seed())?.context("invalid compiled seed")?;
    let config = sample_bound(&s.config, 2 << 20, &route["inputs"][&s.config])?;
    let seed_config = sample_bound(&base.config, 2 << 20, &seed["inputs"][&base.config])?;
    ensure!(
        sha(fragment) == route["inputs"][&s.fragment]["sha256"],
        "unbound observer fragment"
    );
    compare(s, route, seed, &config, &seed_config, fragment)?;
    match s.observer {
        Observer::GuardStops => {
            ensure!(
                sha(&sample_bound(WRAPPER, 1 << 20, &route["inputs"][WRAPPER])?)
                    == "c02a87bfe7a37153b47ed11f0cd26439327e84010afb5d0fe5d91536017befc2",
                "unrecognized observer wrapper"
            );
            ensure!(
                sha(&raw(&Path::new(PYTHON).canonicalize()?, 16 << 20, true)?)
                    == "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"
                    && fs::metadata(PYTHON).map(|m| ident(&m))?
                        == seed["inputs"][PYTHON]["identity"],
                "observer interpreter changed"
            );
        }
        Observer::Survivor172 => {
            ensure!(
                sha(&seed_config) == SURVIVOR_CONFIG_SHA,
                "different survivor seed or replay population"
            );
            ensure!(
                route["inputs"][IMAGE]["identity"] == ident(&fs::metadata(IMAGE)?),
                "changed survivor executable identity"
            );
        }
    }
    ensure!(
        sha(&raw(Path::new(IMAGE), 4 << 20, true)?)
            == "1c248bf2b2c5e12886ae32a2d71ca8cfa12881f63368ce896b3fa832b2dfab1f",
        "native observer changed"
    );
    verify_schedule(s, &config)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(time: &str) -> Schedule {
        Schedule::from_unit(&format!("system:{PREFIX}{time}{TAIL}.service"))
            .unwrap()
            .unwrap()
    }
    fn config(s: &Schedule) -> Vec<u8> {
        serde_json::to_vec(&json!({"output":sample(s.seconds),"not_before_utc":utc(s.seconds),
             "previous_sample":sample(s.seconds-1800),"replays":[166],"minimum_interval_seconds":1800,"observation_reason":"routine"})).unwrap()
    }
    fn fragment(s: &Schedule) -> String {
        format!(
            "Description={WRAPPER} {}\nExecStart={PYTHON} -B {WRAPPER} {}\n",
            s.config, s.config
        )
    }
    fn route(s: &Schedule) -> Value {
        json!({"properties":{"Id":s.id,"FragmentPath":s.fragment,"DropInPaths":"","ExecStart":format!("{PYTHON} -B {WRAPPER} {}",s.config),"WorkingDirectory":""},
               "inputs":{PYTHON:{"identity":[1,2]},WRAPPER:{"sha256":"wrapper"},s.config.clone():{"sha256":sha(&config(s))},s.fragment.clone():{"sha256":sha(fragment(s).as_bytes())}}})
    }
    #[test]
    fn direct_survivor_routes_preserve_the_sealed_reader_and_epoch_scope() {
        let base = schedule("191757");
        let next = schedule("194757");
        let direct = |s: &Schedule| {
            let mut r = route(s);
            r["properties"]["ExecStart"] = json!(format!("{IMAGE} {}", s.config));
            let files = r["inputs"].as_object_mut().unwrap();
            files.remove(PYTHON);
            files.remove(WRAPPER);
            files.insert(IMAGE.into(), json!({"identity":[1,2]}));
            r
        };
        let mut seed = direct(&base);
        let first_fragment = format!(
            "Description={IMAGE} {}\nExecStart={IMAGE} {}\n",
            base.config, base.config
        );
        seed["inputs"][&base.fragment]["sha256"] = json!(sha(first_fragment.as_bytes()));
        let current = direct(&next);
        let cfg = config(&next);
        let seed_cfg = config(&base);
        let fragment = format!(
            "Description={IMAGE} {}\nExecStart={IMAGE} {}\n",
            next.config, next.config
        );
        let accepts = |route: &Value, bytes: &[u8]| {
            compare(&next, route, &seed, bytes, &seed_cfg, fragment.as_bytes())
        };
        assert!(accepts(&current, &cfg).is_ok());
        let mut wrong = current.clone();
        wrong["properties"]["ExecStart"] = json!(format!("{PYTHON} -B {WRAPPER} {}", next.config));
        assert!(accepts(&wrong, &cfg).is_err());
        let mut wrong_scope: Value = serde_json::from_slice(&cfg).unwrap();
        wrong_scope["replays"] = json!([170]);
        assert!(accepts(&current, &serde_json::to_vec(&wrong_scope).unwrap()).is_err());
        assert!(Schedule::from_unit(&SURVIVOR_SEED.replace("191757", "191758")).is_err());
        assert!(Schedule::from_unit(&SURVIVOR_SEED.replace("191757", "184757")).is_err());
    }

    #[test]
    #[ignore = "requires the signed current host route and predecessor fleet"]
    fn current_native_survivor_seed() -> Result<()> {
        let path = std::env::var("HORIZON_COLD130_SURVIVOR_ROUTE")?;
        let routes: Value = serde_json::from_slice(&fs::read(path)?)?;
        let seed = &routes[SURVIVOR_SEED];
        let s = Schedule::from_unit(SURVIVOR_SEED)?.unwrap();
        let f = fs::read(&s.fragment)?;
        verify_route(&s, seed, seed, &f)
    }
    #[test]
    fn only_approved_november_22_clock_and_predecessor() {
        for invalid in [
            "011010", "021010", "024009", "024011", "025010", "241010", "0240AA",
        ] {
            assert!(
                Schedule::from_unit(&format!("system:{PREFIX}{invalid}{TAIL}.service")).is_err()
            );
        }
        for wrong in [
            SEED.replace("20261122", "20261123"),
            SEED.replace("system:", "user:"),
            SEED.replace(".service", "-status.service"),
        ] {
            assert!(Schedule::from_unit(&wrong).unwrap().is_none());
        }
        let s = schedule("031010");
        let cfg = config(&s);
        let mut c: Value = serde_json::from_slice(&cfg).unwrap();
        for key in [
            "previous_sample",
            "output",
            "not_before_utc",
            "minimum_interval_seconds",
            "observation_reason",
        ] {
            let was = c[key].clone();
            c[key] = json!("wrong");
            assert!(
                s.normalize_config(&serde_json::to_vec(&c).unwrap())
                    .is_err()
            );
            c[key] = was;
        }
    }
    #[test]
    fn accepts_only_dated_path_substitutions_in_manager_and_fragment() {
        let seed = schedule("024010");
        let next = schedule("031010");
        let approved = route(&seed);
        let r = route(&next);
        let cfg = config(&next);
        let original = config(&seed);
        let f = fragment(&next);
        let test = |r: &Value, c: &[u8], f: &[u8]| compare(&next, r, &approved, c, &original, f);
        test(&r, &cfg, f.as_bytes()).unwrap();
        for (key, value) in [
            ("DropInPaths", "/tmp/a"),
            ("ExecStartPre", "/bin/other"),
            ("WorkingDirectory", "/tmp"),
            ("Id", &seed.id),
            ("FragmentPath", &seed.fragment),
            ("ExecStart", "/usr/bin/python3 -I /altered"),
        ] {
            let mut changed = r.clone();
            changed["properties"][key] = json!(value);
            assert!(test(&changed, &cfg, f.as_bytes()).is_err(), "{key}");
        }
        for key in [WRAPPER, PYTHON, "/extra"] {
            let mut changed = r.clone();
            changed["inputs"][key] = json!({"identity":[9,9]});
            assert!(test(&changed, &cfg, f.as_bytes()).is_err());
        }
        let mut c: Value = serde_json::from_slice(&cfg).unwrap();
        c["replays"] = json!([167]);
        assert!(test(&r, &serde_json::to_vec(&c).unwrap(), f.as_bytes()).is_err());
        assert!(test(&r, &cfg, f.replace("-B", "-S").as_bytes()).is_err());
        assert!(test(&r, &cfg, format!("{f}Environment=EXTRA=1\n").as_bytes()).is_err());
    }
    // The offline compiler job supplies two immutable captures of the actual PID1 fragment.
    #[test]
    #[ignore = "uses the Nov 22 native scheduler receipts and private route capture"]
    fn native_registered_guard_stops_routes() -> Result<()> {
        let at = std::env::var("HORIZON_COLD130_OBSERVER_FIXTURES")?;
        let fixture = Path::new(&at);
        let frozen = receipt(fixture.join("024010.route.json").to_str().unwrap(), 1 << 16)?;
        let approved_file = format!(
            "{BASE}/cold130-boot-lineage-20261121-v1/route-refresh-0230-v1/reviewed-routes.json"
        );
        let review = receipt(&approved_file, 4 << 20)?;
        let approved = review["reviewed_routes"]
            .as_object()
            .context("reviewed routes")?;
        ensure!(
            approved.get(SEED) == Some(&frozen),
            "seed differs from V8 native snapshot"
        );
        let seed = schedule("024010");
        let next = schedule("031010");
        let first_fragment = raw(&fixture.join("024010.fragment"), 1 << 16, true)?;
        verify_route(&seed, &frozen, &frozen, &first_fragment)?;
        let manager = raw(&fixture.join("031010.manager"), 1 << 16, true)?;
        let mut native =
            crate::launch_routes::captured_guard_inputs(std::str::from_utf8(&manager)?)?;
        let actual = receipt(fixture.join("031010.route.json").to_str().unwrap(), 1 << 16)?;
        let second_fragment = raw(&fixture.join("031010.fragment"), 1 << 16, true)?;
        // PID1 may collect the transient unit before the private build slot is available.
        // Reparse the retained original manager data using the native parser in both cases.
        if Path::new(&next.fragment).exists() {
            assert!(reviewed(&format!("system:{}", next.id), &actual, approved)?);
        } else {
            assert!(native["inputs"].get(&next.fragment).is_none());
            native["inputs"][&next.fragment] = actual["inputs"][&next.fragment].clone();
        }
        ensure!(
            native == actual,
            "retained manager dump or permanent direct inputs changed"
        );
        verify_route(&next, &actual, &frozen, &second_fragment)?;
        let bytes = sample_bound(&next.config, 2 << 20, &actual["inputs"][&next.config])?;
        let dir = Path::new(&next.previous_dir);
        let sealed = dir.join("sealed-next");
        let plan = raw(&dir.join("next-seal-plan.json"), 1 << 16, true)?;
        let seal = raw(&sealed.join("deployment-seal-receipt.json"), 1 << 16, true)?;
        let sums = raw(&sealed.join("SHA256SUMS"), 1024, true)?;
        check_seal(&next, &bytes, &plan, &seal, &sums)?;
        let mut p: Value = serde_json::from_slice(&plan)?;
        p["members"][0]["source"] = json!(seed.config);
        assert!(check_seal(&next, &bytes, &serde_json::to_vec(&p)?, &seal, &sums).is_err());
        let mut st: Value = serde_json::from_slice(&seal)?;
        st["r2_mutations"] = json!(true);
        assert!(check_seal(&next, &bytes, &plan, &serde_json::to_vec(&st)?, &sums).is_err());
        assert!(check_seal(&next, &bytes, &plan, &seal, b"unbound").is_err());
        let mut fleet = receipt(
            dir.join("ROOT_COMPLETE_OPERATIONAL_FLEET.json")
                .to_str()
                .unwrap(),
            16 << 20,
        )?;
        let observed = raw(Path::new(&sample(next.seconds - 1800)), 2 << 20, true)?;
        check_predecessor(&next, &bytes, &fleet, &observed)?;
        fleet["sole_next_timer"] = json!("another.timer");
        assert!(check_predecessor(&next, &bytes, &fleet, &observed).is_err());
        Ok(())
    }
}
