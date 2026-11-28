use super::*;

const DRAIN: &str = "84f37a4cb4886968c932b624b47a7863fde5b115eff2bbd11a4255f4c5f4bee9";
const ASSEMBLY: &str = "76196db58c045a44b3b910823a60ae16db769302c4bff681ccd1598eb3b856e9";
const SHARES: [(&str, &str, u64, u64); 3] = [
    (
        "source_qualification",
        "ab8147b379d144a696b1d210127ea866",
        4 << 30,
        1_000_000,
    ),
    (
        "epoch168_classifier_build",
        "9ea5ace532d34416afe0a678ef51a437",
        768 << 20,
        500_000,
    ),
    (
        "checksum_read",
        "e88bd2815ad54ea4aef39c4f59adfcbb",
        128 << 20,
        250_000,
    ),
];

fn signed(q: &Value, k: &str) -> Result<i64> {
    q[k].as_i64().with_context(|| format!("missing {k}"))
}

fn funded(q: &Value) -> Result<(u64, u64, Value)> {
    let s = &q["closed_167_suballocations"];
    ensure!(
        q.get("publication168_allocation").is_none()
            && q["resource_credit_bytes"] == 0
            && s["native_drain"]["sha256"] == DRAIN
            && s["retained_producer_ram"] == 42u64 << 30
            && s["retained_cpu_micros_per_second"] == 3_000_000
            && s["guard_ram_separate"] == 1u64 << 30
            && s["additional_ram"] == 0
            && s["additional_home"] == 0
            && q["epoch157_lanej_rotation"]["sublease"]["cpu_micros_per_second"] == 0
            && q["epoch157_lanej_rotation"]["sublease"]["ram_bytes"] == 0,
        "changed 167 or occupied 157 allocation"
    );
    let assembly = &q["epoch167_private_assembly"];
    let assembly_cpu = match string(assembly, "phase")? {
        "booked" => {
            ensure!(
                assembly["booking"]["sha256"] == ASSEMBLY
                    && assembly["additional_compute_cpu"] == 0
                    && assembly["additional_compute_ram"] == 0
                    && assembly["output_cap"] == 137_506_062_336u64,
                "different active 167 reservation"
            );
            1_000_000
        }
        "closed" => {
            ensure!(
                assembly["terminal"]["sha256"]
                    .as_str()
                    .is_some_and(custody::is_digest)
                    && assembly["additional_home"] == 0,
                "different completed 167 reservation"
            );
            0
        }
        _ => bail!("167 assembly has no recognized booking or terminal"),
    };
    let mut returned = 0;
    let mut closed = json!({});
    for (name, iid, mem, quota) in SHARES {
        let phase = &s["phases"][name];
        ensure!(
            phase["phase"] == "terminal"
                && phase["invocation"] == iid
                && phase["manager_message"] == "7ad2d189f7e94e70a38c781354912448"
                && phase["cursor"].as_str().is_some_and(|v| !v.is_empty())
                && s[name]["cpu_micros_per_second"] == quota
                && s[name]["ram_bytes"] == mem,
            "unreconciled {name} sublease"
        );
        returned += quota;
        closed[name] = json!({"terminal":phase,"cpu_micros_per_second":quota});
    }
    let pool = &s["unassigned"];
    let cpu = num(pool, "cpu_micros_per_second")?;
    ensure!(
        cpu + returned + assembly_cpu == 3_000_000 && cpu + returned >= CPU,
        "167 CPU is already pledged"
    );
    let mem = num(pool, "ram_bytes")?
        .checked_sub(MEMORY)
        .context("insufficient retained RAM")?;
    Ok((mem, cpu + returned - CPU, closed))
}

pub(super) fn account(q: Value, operator: &Bound) -> Result<Value> {
    ensure!(
        q["package"]["path"].as_str().is_some() && q["fits"].is_boolean(),
        "incomplete provider quote"
    );
    let owner = super::lifecycle::owner()?;
    apply(q, operator, owner)
}

fn apply(mut q: Value, operator: &Bound, owner: Value) -> Result<Value> {
    let (ram, cpu, closed) = funded(&q)?;
    let mut reservation = json!({"operator":operator,"epoch":168,"unit":UNIT,"workspace_sha256":WORKSPACE,
        "private_reconciliation_sha256":RECONCILED,"owner":owner,"closed_subleases":closed,
        "memory_max":MEMORY,"cpu_micros_per_second":CPU,"swap_max":0,"metadata_bytes":META,
        "additional_ram":0,"additional_cpu":0,"archive_scratch_bytes":0,"replay_lane":false,
        "resource_credit_bytes":0,"canonical_writes_authorized_by_account":false});
    if owner["phase"] != "closed" {
        let previous = signed(&q, "home_margin")?;
        q["required_home"] = json!(
            num(&q, "required_home")?
                .checked_add(META)
                .context("HOME overflow")?
        );
        q["guard_floor"] = json!(
            num(&q, "guard_floor")?
                .checked_add(META)
                .context("floor overflow")?
        );
        q["home_margin"] = json!(
            previous
                .checked_sub(META as i64)
                .context("HOME underflow")?
        );
        q["fits"] = json!(q["fits"] == true && signed(&q, "home_margin")? >= 0);
        let shares = &mut q["closed_167_suballocations"];
        shares["unassigned"]["ram_bytes"] = json!(ram);
        shares["unassigned"]["cpu_micros_per_second"] = json!(cpu);
        reservation["charged"] = json!(true);
        reservation["additional_home"] = json!(META);
    } else {
        reservation["charged"] = json!(false);
        reservation["additional_home"] = json!(0);
    }
    q["publication168_allocation"] = reservation;
    Ok(q)
}

fn provider(ref_: &Bound) -> Result<Value> {
    let family = Path::new(RT).join("epoch162-first-hourly-completion-20261127-v2");
    let dir = ref_.path.parent().context("no provider dir")?;
    let parse = |v: &str| {
        v.strip_prefix("issued-price-v")
            .and_then(|s| s.parse::<u32>().ok())
    };
    let ver = dir
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(parse)
        .context("unrecognized provider")?;
    ensure!(
        ref_.path
            .file_name()
            .is_some_and(|v| v == "deployment-seal-receipt.json")
            && dir.parent() == Some(&family)
            && ver >= 38,
        "unregistered 168 provider"
    );
    let latest = fs::read_dir(&family)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter_map(|e| {
            parse(e.file_name().to_str()?)
                .filter(|_| e.path().join("deployment-seal-receipt.json").is_file())
        })
        .max();
    ensure!(
        latest == Some(ver),
        "use the latest completely issued provider"
    );
    let seal = ref_.json()?;
    ensure!(
        seal["destination"] == dir.to_str().unwrap(),
        "different provider directory"
    );
    let member = seal["members"]
        .as_array()
        .context("provider members")?
        .iter()
        .find(|m| m["name"] == "capacity.py")
        .context("missing capacity")?;
    let entry = dir.join("capacity.py");
    fixed(&entry, string(member, "sha256")?).binary()?;
    let output = command(&[
        "/usr/bin/python3",
        "-IB",
        "-c",
        "import json,runpy,sys; print(json.dumps(runpy.run_path(sys.argv[1])['whole_roster']()))",
        entry.to_str().unwrap(),
    ])?;
    let w: Value = serde_json::from_str(&output)?;
    let time = w["recorded_unix_seconds"]
        .as_f64()
        .context("roster observation time")?;
    ensure!(
        w["package"] == serde_json::to_value(ref_)?
            && (0.0..=180.0).contains(&(nanos()? as f64 / 1e9 - time))
            && w["preparation_only"] == false
            && w["resource_credit_bytes"] == 0
            && w["publication168_allocation"]["operator"] == serde_json::to_value(own_seal()?)?
            && super::lifecycle::root_snapshot(&reference(&w, "fleet")?)?["owner"] == "/root",
        "changed provider or fleet"
    );
    super::lifecycle::root_snapshot(&reference(&w, "writer")?)?;
    Ok(w)
}

pub(super) fn quote(provider_: &Bound) -> Result<Value> {
    let complete = provider(provider_)?;
    let booking = &complete["publication168_allocation"];
    ensure!(
        booking["charged"] == true
            && booking["memory_max"] == MEMORY
            && booking["cpu_micros_per_second"] == CPU
            && booking["additional_ram"] == 0
            && booking["additional_home"] == META,
        "168 allocation is closed or missing"
    );
    let (free, ram) = actual()?;
    let floor = num(&complete, "required_home")?
        .max(num(&complete, "guard_floor")?)
        .max(u64::try_from(
            i128::from(num(&complete, "available_home")?)
                - i128::from(signed(&complete, "home_margin")?),
        )?);
    let avail = free.min(num(&complete, "available_home")?);
    let available_ram = ram.min(num(&complete, "available_ram")?);
    let need_ram = num(&complete, "required_ram")?;
    Ok(
        json!({"schema":"horizon-168-native-publication-quote-v1","provider":provider_,"whole_roster":complete,
        "fits":complete["fits"]==true && avail>=floor && available_ram>=need_ram,
        "home_available":avail,"minimum_free_bytes":floor,"home_margin":i128::from(avail)-i128::from(floor),
        "ram_available":available_ram,"required_ram":need_ram,"ram_margin":i128::from(available_ram)-i128::from(need_ram),
        "resource_credit_bytes":0,"additional_ram":0,"additional_home":META,"boot":boot()?}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    pub fn roster() -> Value {
        let mut q = json!({"resource_credit_bytes":0,"epoch157_lanej_rotation":{"sublease":{"ram_bytes":0,"cpu_micros_per_second":0}},
            "epoch167_private_assembly":{"phase":"booked","booking":{"sha256":ASSEMBLY},"additional_compute_cpu":0,"additional_compute_ram":0,"output_cap":137506062336u64},
            "closed_167_suballocations":{"retained_producer_ram":42u64<<30,"retained_cpu_micros_per_second":3000000,"native_drain":{"sha256":DRAIN},
            "guard_ram_separate":1u64<<30,"additional_ram":0,"additional_home":0,"unassigned":{"ram_bytes":31272730624u64,"cpu_micros_per_second":250000}}});
        for (n, id, m, c) in SHARES {
            q["closed_167_suballocations"][n] = json!({"ram_bytes":m,"cpu_micros_per_second":c});
            q["closed_167_suballocations"]["phases"][n] = json!({"phase":"terminal","invocation":id,"manager_message":"7ad2d189f7e94e70a38c781354912448","cursor":"fixture"});
        }
        q
    }
    #[test]
    fn keep_the_full_charge_through_start_failure_and_receipt_handoff() {
        let mut q = roster();
        q["fits"] = json!(true);
        q["required_home"] = json!(5u64 << 40);
        q["guard_floor"] = json!(4u64 << 40);
        q["home_margin"] = json!(2u64 << 30);
        q["required_ram"] = json!(700u64 << 30);
        let seal = fixed("/fixture", DRAIN);
        for phase in [
            "reserved",
            "transition",
            "starting",
            "running",
            "failed_drained",
            "awaiting_verified_receipt",
            "closed",
        ] {
            let w = apply(q.clone(), &seal, json!({"phase":phase})).unwrap();
            assert_eq!(w["required_ram"], q["required_ram"]);
            let charged = phase != "closed";
            assert_eq!(w["publication168_allocation"]["charged"], charged);
            assert_eq!(
                w["required_home"],
                (5u64 << 40) + if charged { META } else { 0 }
            );
            assert_eq!(
                w["closed_167_suballocations"]["unassigned"]["cpu_micros_per_second"],
                if charged { 0 } else { 250000 }
            );
            assert_eq!(
                w["epoch167_private_assembly"],
                q["epoch167_private_assembly"]
            );
            assert!(apply(w, &seal, json!({"phase":phase})).is_err());
        }
    }

    #[test]
    fn shares_while_167_runs() {
        let q = roster();
        let (m, c, _) = funded(&q).unwrap();
        assert_eq!((m, c), (22682796032, 0));
    }
    #[test]
    fn terminal_and_competing_bookings() {
        let q = roster();
        for name in [SHARES[0].0, SHARES[1].0, SHARES[2].0] {
            let mut v = q.clone();
            v["closed_167_suballocations"]["phases"][name]["phase"] = json!("active");
            assert!(funded(&v).is_err());
        }
        let mut v = q.clone();
        v["epoch157_lanej_rotation"]["sublease"]["cpu_micros_per_second"] = json!(250000);
        assert!(funded(&v).is_err());
        let mut v = q;
        v["epoch167_private_assembly"] =
            json!({"phase":"closed","terminal":{"sha256":ASSEMBLY},"additional_home":0});
        v["closed_167_suballocations"]["unassigned"]["cpu_micros_per_second"] = json!(1250000);
        assert_eq!(funded(&v).unwrap().1, 1000000);
    }
}
