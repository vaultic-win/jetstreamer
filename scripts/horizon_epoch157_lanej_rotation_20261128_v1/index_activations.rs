// Inspect executable plans, armed activation targets and scheduled jobs under the retirement lock.
fn scheduled_files(cache: &mut PlanCache) -> Result<usize> {
    let mut paths = Vec::new();
    for dir in [
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
    ] {
        if Path::new(dir).is_dir() {
            for entry in fs::read_dir(dir)? {
                let path = entry?.path();
                if path.is_file() {
                    paths.push(path);
                }
            }
        }
    }
    if Path::new("/etc/crontab").is_file() {
        paths.push("/etc/crontab".into());
    }
    for path in &paths {
        let s = fs::metadata(path)?;
        ensure!(
            s.is_file() && s.len() < 2 << 20,
            "unresolved scheduler file {}",
            path.display()
        );
        let contents = fs::read_to_string(path)?;
        let live = contents
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        ensure!(
            terms(&live).is_empty() && artifacts(&live, cache)?.is_empty(),
            "staged cron index reader {}",
            path.display()
        );
    }
    Ok(paths.len())
}
fn active_plans(current: &Value, runtime: &Path) -> Result<Value> {
    let listing = command(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--all",
            "--plain",
            "--no-pager",
            "--no-legend",
            "--type=service,timer,path,socket",
        ],
    )?;
    let jobs = command(
        "/usr/bin/systemctl",
        &["list-jobs", "--plain", "--no-pager", "--no-legend"],
    )?;
    let mut potential = BTreeSet::new();
    for line in listing.lines() {
        let mut words = line.split_whitespace();
        let unit = words.next().context("missing unit")?;
        let active = words.nth(1).context("missing load state")?;
        if !matches!(active, "inactive" | "failed") {
            potential.insert(unit);
        }
    }
    for line in jobs.lines() {
        if let Some(u) = line.split_whitespace().nth(1) {
            if u.rsplit_once('.')
                .is_some_and(|(_, t)| matches!(t, "service" | "timer" | "path" | "socket"))
            {
                potential.insert(u);
            }
        }
    }
    let potential: Vec<_> = potential.into_iter().collect();
    let mut cache = PlanCache::default();
    let cron = scheduled_files(&mut cache)?;
    let mut closed = 0;
    let mut examined = 0;
    let mut gone = 0;
    let mut unresolved = Vec::new();
    for batch in potential.chunks(128) {
        for plan in native_plans(batch, true)? {
            if matches!(plan.state.as_str(), "inactive" | "failed" | "gone") {
                gone += 1;
                continue;
            }
            if plan.closed.is_some() {
                closed += 1;
                continue;
            }
            let direct = terms(&plan.projection);
            let nested = artifacts(&plan.projection, &mut cache)?;
            if !direct.is_empty() || !nested.is_empty() {
                unresolved.push(json!({"unit":plan.unit,"state":plan.state,"sub":plan.sub,"direct":direct,"plans":nested.iter().take(20).collect::<Vec<_>>(),"plan_count":nested.len()}));
            }
            examined += 1;
        }
    }
    ensure!(
        examined > 0 && closed + gone + examined == potential.len(),
        "incomplete activation inventory"
    );
    if !unresolved.is_empty() {
        let iid = std::env::var("INVOCATION_ID")?;
        ensure!(
            iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
            "missing invocation"
        );
        let diagnostic = json!({"fleet":current,"unresolved":unresolved,"units":potential.len(),"closed":closed,"material":cache.examined});
        ensure!(
            serde_json::to_vec(&diagnostic)?.len() < 2 << 20,
            "diagnostic size bound"
        );
        let report = evidence::receipt(
            &runtime.join(format!("STAGED_REVIEW_{iid}.json")),
            &diagnostic,
        )?;
        anyhow::bail!("unresolved staged reader(s), see {report}");
    }
    Ok(
        json!({"potential_units":potential.len(),"conclusively_closed_activations":closed,"inactive_or_collected":gone,"executable_activations":examined,"scheduled_files":cron,"resolved_plans":cache.examined}),
    )
}
