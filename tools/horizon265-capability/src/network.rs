use super::*;
const UNIT: &str = "horizon265-car-header-network-proof-20261120-v3.service";
const TOKENS: &str = "/var/lib/jetstreamer/horizon265-replacement-20261119-tokens-v3";
const NATIVE_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/horizon265-network-native-evidence-20261120-v3";
const CID: &str = "bafyreibgf4smruua7seioyolngrziiqsgeae3d4zmcvptg7m4xwzyafqwu";
const CID_HEX: &str = "01711220262f24c8d280fc888761cb69a394221231004d8f9960aaf99bece5ed9c00b0b5";
fn directory() -> PathBuf {
    Path::new(ROOT).join("network-proof")
}
fn native_path() -> PathBuf {
    Path::new(NATIVE_ROOT).join("native-result.json")
}
fn tokens_absent() -> Result<()> {
    match fs::symlink_metadata(TOKENS) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("production tokens must remain absent during input-only probe"),
    }
}
fn namespace_exception() -> Value {
    json!({"schema":"horizon265-input-only-namespace-exception-v1",
        "production_tokens":TOKENS,"production_tokens_required_absent":true,
        "omitted_read_only_path":TOKENS,"additional_diagnostics_write_path":NATIVE_ROOT,
        "reason":"input-only probe precedes launcher prepare; no production token or startup gate exists",
        "useful_replay_authorized":false,"production_namespace_qualified":false})
}
fn member_names(names: &BTreeSet<std::ffi::OsString>) -> Result<()> {
    ensure!(
        *names
            == BTreeSet::from([
                std::ffi::OsString::from("headers"),
                std::ffi::OsString::from("body")
            ]),
        "network-proof must contain only headers/body"
    );
    Ok(())
}
fn network_members() -> Result<()> {
    let names = fs::read_dir(directory())?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    member_names(&names)
}
fn artifact_record(path: &Path, bytes: &[u8], id: Value) -> Result<Value> {
    ensure!(
        id["bytes"] == bytes.len() as u64,
        "network identity byte count"
    );
    Ok(json!({"path":path,"sha256":digest(bytes),"identity":id}))
}
fn artifact_identity(path: &Path, bytes: &[u8]) -> Result<Value> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        read(path, 1000, 65536, false)? == bytes
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "network artifact changed during identity capture"
    );
    let mut v = identity(&before);
    v["bytes"] = json!(before.len());
    Ok(v)
}
fn curl_args() -> Vec<String> {
    [
        "--fail",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--range",
        "0-4095",
        "--max-time",
        "60",
        "--max-filesize",
        "4096",
        "--dump-header",
        "network-proof/headers",
        "--output",
        "network-proof/body",
        "https://files.old-faithful.net/265/epoch-265.car",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}
fn expected() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for k in [
        "User",
        "Group",
        "UMask",
        "Restart",
        "KillMode",
        "Delegate",
        "ProtectSystem",
        "ProtectHome",
        "ProtectControlGroups",
        "NoNewPrivileges",
        "PrivateTmp",
        "PrivateNetwork",
        "ReadWritePaths",
        "ReadOnlyPaths",
        "WorkingDirectory",
        "CapabilityBoundingSet",
        "AmbientCapabilities",
        "OOMPolicy",
        "OOMScoreAdjust",
        "StandardOutput",
        "StandardError",
    ] {
        let prefix = format!("{k}=");
        let v = TEMPLATE
            .lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .expect("template field");
        m.insert(k.into(), v.into());
    }
    // Explicit input-only exception: startup-token path must not exist before
    // launcher prepare. Every other production readonly path remains exact.
    let readonly = TEMPLATE
        .lines()
        .find_map(|l| l.strip_prefix("ReadOnlyPaths="))
        .unwrap();
    let paths: Vec<_> = readonly.split_whitespace().collect();
    assert_eq!(paths.iter().filter(|p| **p == TOKENS).count(), 1);
    m.insert(
        "ReadOnlyPaths".into(),
        paths
            .into_iter()
            .filter(|p| *p != TOKENS)
            .collect::<Vec<_>>()
            .join(" "),
    );
    m.insert("ReadWritePaths".into(), format!("{ROOT} {NATIVE_ROOT}"));
    let mounts = TEMPLATE
        .lines()
        .find_map(|l| l.strip_prefix("BindReadOnlyPaths="))
        .unwrap()
        .split_whitespace()
        .map(|s| format!("{s}:rbind"))
        .collect::<Vec<_>>()
        .join(" ");
    m.insert("BindReadOnlyPaths".into(), mounts);
    for (k, v) in [
        ("Type", "oneshot"),
        ("RemainAfterExit", "yes"),
        ("MemoryMax", "268435456"),
        ("MemoryHigh", "201326592"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "32"),
        ("TimeoutStartUSec", "1min 30s"),
        ("TimeoutStopUSec", "10s"),
        ("LimitFSIZE", "65536"),
        ("CPUQuotaPerSecUSec", "1s"),
    ] {
        m.insert(k.into(), v.into());
    }
    m
}
fn properties(v: &Value) -> Result<()> {
    for (k, w) in expected() {
        ensure!(v[&k] == w, "effective network property {k}");
    }
    let families: BTreeSet<_> = text(v, "RestrictAddressFamilies")?
        .split_whitespace()
        .collect();
    ensure!(
        families == BTreeSet::from(["AF_UNIX", "AF_INET", "AF_INET6"]),
        "network address families"
    );
    let env: BTreeSet<_> = text(v, "Environment")?.split_whitespace().collect();
    let wanted: BTreeSet<_> = TEMPLATE
        .lines()
        .filter_map(|l| {
            l.strip_prefix("Environment=\"")
                .and_then(|s| s.strip_suffix('"'))
        })
        .collect();
    ensure!(env == wanted, "network environment differs from producer");
    let unset: BTreeSet<_> = text(v, "UnsetEnvironment")?.split_whitespace().collect();
    let wanted: BTreeSet<_> = TEMPLATE
        .lines()
        .find_map(|l| l.strip_prefix("UnsetEnvironment="))
        .unwrap()
        .split_whitespace()
        .collect();
    ensure!(unset == wanted, "network excluded secrets differ");
    Ok(())
}
fn namespace() -> Result<Value> {
    tokens_absent()?;
    let mut mounts = Vec::new();
    for (path, writable) in [
        (ROOT, true),
        (NATIVE_ROOT, true),
        (
            concat!(
                "/home/ubuntu/.jetstreamer-private/qualification-265-replacement-20261119-v3",
                "/output/compact-indexes"
            ),
            false,
        ),
        (
            "/var/lib/jetstreamer/horizon-contiguous-265-265-current-46b4b4a-v1",
            false,
        ),
    ] {
        let c = std::ffi::CString::new(path)?;
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0,
            "namespace statvfs"
        );
        let ro = s.f_flag & libc::ST_RDONLY != 0;
        ensure!(ro != writable, "namespace writable status {path}");
        mounts.push(json!({"path":path,"read_only":ro}));
    }
    for (source, target) in [
        (
            "/var/lib/jetstreamer/horizon265-index-20261119-v1",
            format!("{ROOT}/output/compact-indexes/264"),
        ),
        (
            "/var/lib/jetstreamer/horizon265-index-20261119-v1",
            format!("{ROOT}/output/compact-indexes/265"),
        ),
        (
            "/var/lib/jetstreamer/horizon-foundation-holding-probe-input-v1/genesis.tar.bz2",
            format!("{ROOT}/output/genesis.tar.bz2"),
        ),
    ] {
        let a = fs::metadata(source)?;
        let b = fs::metadata(&target)?;
        ensure!(
            a.dev() == b.dev() && a.ino() == b.ino(),
            "namespace projected inode mismatch"
        );
        let c = std::ffi::CString::new(target.clone())?;
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0 && s.f_flag & libc::ST_RDONLY != 0,
            "projection writable"
        );
        mounts.push(json!({"source":source,"target":target,"device":a.dev(),"inode":a.ino(),"read_only":true}));
    }
    Ok(
        json!({"mount_namespace":fs::read_link("/proc/self/ns/mnt")?,"network_namespace":fs::read_link("/proc/self/ns/net")?,"mounts":mounts,"mountinfo_sha256":digest(&fs::read("/proc/self/mountinfo")?),"input_only_exception":namespace_exception()}),
    )
}
fn response(headers: &[u8], body: &[u8]) -> Result<String> {
    ensure!(body.len() == 4096, "response body length");
    let h = std::str::from_utf8(headers)?;
    let blocks: Vec<_> = h.split("\r\n\r\n").filter(|s| !s.is_empty()).collect();
    ensure!(blocks.len() == 1, "redirect/proxy/multiple HTTP responses");
    let mut lines = blocks[0].split("\r\n");
    let status = lines.next().context("status")?;
    ensure!(
        status == "HTTP/2 206 "
            || status == "HTTP/2 206"
            || status == "HTTP/1.1 206 Partial Content",
        "not HTTP206"
    );
    let mut fields = BTreeMap::new();
    for line in lines {
        let (k, v) = line.split_once(':').context("HTTP header framing")?;
        let k = k.to_ascii_lowercase();
        if [
            "content-range",
            "content-length",
            "content-encoding",
            "transfer-encoding",
        ]
        .contains(&k.as_str())
        {
            ensure!(fields.insert(k, v.trim()).is_none(), "duplicate HTTP field");
        }
    }
    ensure!(
        fields.get("content-length") == Some(&"4096")
            && !fields.contains_key("transfer-encoding")
            && !fields.contains_key("content-encoding"),
        "HTTP length/encoding"
    );
    let range = *fields.get("content-range").context("content range")?;
    let total = range
        .strip_prefix("bytes 0-4095/")
        .context("wrong content range")?
        .parse::<u64>()?;
    ensure!(total > 4096, "CAR total length");
    let prefix = [
        0x3a, 0xa2, 0x65, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x81, 0xd8, 0x2a, 0x58, 0x25, 0x00,
    ];
    let cid: String = body[14..50].iter().map(|b| format!("{b:02x}")).collect();
    ensure!(
        body[..14] == prefix && cid == CID_HEX && &body[50..59] == b"\x67version\x01",
        "CAR root/version differs"
    );
    Ok(range.into())
}
pub(super) fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1000 && std::env::current_dir()? == Path::new(ROOT),
        "network native identity/root"
    );
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(hex(&iid, 32), "native IID missing");
    let d = directory();
    let m = fs::symlink_metadata(&d)?;
    ensure!(
        m.is_dir()
            && m.uid() == 1000
            && m.mode() & 0o777 == 0o700
            && d.canonicalize()? == d
            && fs::read_dir(&d)?.next().is_none(),
        "network output must be empty private directory"
    );
    let native_directory = Path::new(NATIVE_ROOT);
    let m = fs::symlink_metadata(native_directory)?;
    ensure!(
        m.is_dir()
            && m.uid() == 1000
            && m.mode() & 0o777 == 0o700
            && native_directory.canonicalize()? == native_directory
            && fs::read_dir(native_directory)?.next().is_none(),
        "separate native diagnostics directory must be empty ubuntu0700"
    );
    let before = namespace()?;
    let o = Command::new("/usr/bin/curl").args(curl_args()).output()?;
    ensure!(
        o.status.success() && o.stdout.is_empty() && o.stderr.is_empty(),
        "bounded curl failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let h = read(&d.join("headers"), 1000, 65536, false)?;
    let b = read(&d.join("body"), 1000, 4096, false)?;
    let range = response(&h, &b)?;
    ensure!(before == namespace()?, "namespace changed");
    let v = json!({"schema":"horizon265-network-native-result-v1","unit":UNIT,"invocation_id":iid,"pid":std::process::id(),"self_sha256":digest(&fs::read("/proc/self/exe")?),"curl":{"path":"/usr/bin/curl","sha256":digest(&fs::read("/usr/bin/curl")?),"args":curl_args(),"exit_code":0},"namespace":before,"headers_sha256":digest(&h),"body_sha256":digest(&b),"content_range":range,"download_bytes":4096,"producer_template_sha256":digest(TEMPLATE.as_bytes()),"entry_replay":false});
    put(&native_path(), &v)?;
    network_members()?;
    tokens_absent()?;
    println!("epoch265 bounded native HTTP206 CAR header accepted");
    Ok(())
}
pub(super) fn capture(p: &Value, plan: &Bound, self_sha: &str) -> Result<()> {
    ensure!(
        p["schema"] == "horizon265-network-capture-plan-v1"
            && p["unit"] == UNIT
            && p["producer_template_sha256"] == digest(TEMPLATE.as_bytes())
            && p["Main_accepted_namespace_exception"] == true
            && p["input_only_namespace_exception"] == namespace_exception(),
        "network plan scope"
    );
    let iid = text(p, "invocation_id")?;
    let helper: Bound = serde_json::from_value(p["helper"].clone())?;
    ensure!(
        helper.sha256 == self_sha
            && digest(&read(&helper.path, 0, 64 << 20, true)?) == helper.sha256,
        "network helper identity"
    );
    let argv = vec![
        helper.path.to_str().context("helper path")?.into(),
        "network-run".into(),
    ];
    let before = show(UNIT)?;
    let pid = terminal(&before, UNIT, iid, true)?;
    properties(&before)?;
    command(&before, &argv)?;
    drained(UNIT, pid)?;
    let d = directory();
    tokens_absent()?;
    network_members()?;
    let raw = read(&native_path(), 1000, 65536, true)?;
    let native: Value = serde_json::from_slice(&raw)?;
    ensure!(
        native["schema"] == "horizon265-network-native-result-v1"
            && native["unit"] == UNIT
            && native["invocation_id"] == iid
            && native["pid"] == pid
            && native["self_sha256"] == helper.sha256
            && native["producer_template_sha256"] == digest(TEMPLATE.as_bytes())
            && native["curl"]["args"] == json!(curl_args())
            && native["curl"]["exit_code"] == 0
            && native["namespace"]["input_only_exception"] == namespace_exception(),
        "network native evidence binding"
    );
    let h = read(&d.join("headers"), 1000, 65536, false)?;
    let b = read(&d.join("body"), 1000, 4096, false)?;
    let range = response(&h, &b)?;
    ensure!(
        native["headers_sha256"] == digest(&h)
            && native["body_sha256"] == digest(&b)
            && native["content_range"] == range,
        "network output changed"
    );
    let hi = artifact_identity(&d.join("headers"), &h)?;
    let bi = artifact_identity(&d.join("body"), &b)?;
    let rows = journal(UNIT, iid)?;
    journal_owner(
        &rows,
        UNIT,
        iid,
        pid,
        &argv,
        "epoch265 bounded native HTTP206 CAR header accepted",
        JournalEvidence::BoundNetworkNative,
    )?;
    let output = Path::new(text(p, "output")?);
    let dir = output.parent().context("receipt directory")?;
    let evidence = put(
        &dir.join("network-command-journal.json"),
        &json!({"schema":"horizon265-actual-command-and-journal-v1","unit":UNIT,"invocation_id":iid,"pid":pid,"effective_properties":before,"argv":argv,"journal":rows,"native_result":native,"native_result_sha256":digest(&raw),"headers_bytes":h,"body_bytes":b,"plan":plan}),
    )?;
    ensure!(before == show(UNIT)?, "network manager changed");
    drained(UNIT, pid)?;
    ensure!(
        read(&native_path(), 1000, 65536, true)? == raw
            && read(&d.join("headers"), 1000, 65536, false)? == h
            && read(&d.join("body"), 1000, 4096, false)? == b,
        "network outputs changed during capture"
    );
    ensure!(
        hi == artifact_identity(&d.join("headers"), &h)?
            && bi == artifact_identity(&d.join("body"), &b)?,
        "network identity changed"
    );
    network_members()?;
    tokens_absent()?;
    let mut receipt = json!({"schema":"horizon265-service-effective-car-header-proof-v1","epoch":265,"unit":UNIT,"invocation_id":iid,"effective_properties":before,"actual_command_and_journal":evidence,"http_status":206,"download_bytes":4096,"content_range":range,"expected_root_cid":CID,"car_header_accepted":true,"service_effective_namespace_verified":true,"producer_template_sha256":digest(TEMPLATE.as_bytes()),"headers":artifact_record(&d.join("headers"), &h, hi)?,"body":artifact_record(&d.join("body"), &b, bi)?,"namespace":native["namespace"],"native_result":{"path":native_path(),"sha256":digest(&raw)},"input_only_namespace_exception":namespace_exception(),"production_namespace_qualified":false,"self_sha256":self_sha,"plan":plan});
    deny(&mut receipt);
    put(output, &receipt)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Vec<u8>, Vec<u8>) {
        let h=b"HTTP/2 206 \r\ncontent-range: bytes 0-4095/500000000000\r\ncontent-length: 4096\r\n\r\n".to_vec();
        let mut b = vec![0; 4096];
        let raw = format!("3aa265726f6f747381d82a582500{CID_HEX}6776657273696f6e01");
        for (i, p) in raw.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            b[i] = u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap();
        }
        (h, b)
    }
    #[test]
    fn root_range_encoding_and_bounded_body_are_independent_gates() {
        let (h, mut b) = fixture();
        response(&h, &b).unwrap();
        b[20] ^= 1;
        assert!(response(&h, &b).is_err());
        b[20] ^= 1;
        assert!(response(&h, &b[..40]).is_err());
        for from in ["206", "0-4095", "4096"] {
            let bad = String::from_utf8(h.clone())
                .unwrap()
                .replacen(from, "999", 1);
            assert!(response(bad.as_bytes(), &b).is_err());
        }
        let mut duplicate = h.clone();
        duplicate.extend_from_slice(&h);
        assert!(response(&duplicate, &b).is_err());
    }
    #[test]
    fn properties_are_derived_from_current_producer_template() {
        let mut v = json!(expected());
        v["RestrictAddressFamilies"] = json!("AF_INET AF_INET6 AF_UNIX");
        v["Environment"] = json!(
            TEMPLATE
                .lines()
                .filter_map(|l| l
                    .strip_prefix("Environment=\"")
                    .and_then(|s| s.strip_suffix('"')))
                .collect::<Vec<_>>()
                .join(" ")
        );
        v["UnsetEnvironment"] = json!(
            TEMPLATE
                .lines()
                .find_map(|l| l.strip_prefix("UnsetEnvironment="))
                .unwrap()
        );
        properties(&v).unwrap();
        for key in [
            "PrivateNetwork",
            "ReadOnlyPaths",
            "BindReadOnlyPaths",
            "Environment",
            "MemoryMax",
        ] {
            let mut bad = v.clone();
            bad[key] = json!("changed");
            assert!(properties(&bad).is_err());
        }
    }
    #[test]
    fn launcher_artifact_byte_identity_and_pristine_members_are_preserved() {
        let body = vec![0u8; 4096];
        let record =
            artifact_record(&directory().join("body"), &body, json!({"bytes":4096})).unwrap();
        assert_eq!(record["identity"]["bytes"], 4096);
        assert!(artifact_record(&directory().join("body"), &body, json!({"bytes":4095})).is_err());
        assert!(artifact_record(&directory().join("body"), &body, json!({"len":4096})).is_err());
        let mut names = BTreeSet::from([
            std::ffi::OsString::from("headers"),
            std::ffi::OsString::from("body"),
        ]);
        member_names(&names).unwrap();
        names.insert(std::ffi::OsString::from("native-result.json"));
        assert!(member_names(&names).is_err());
        assert!(!native_path().starts_with(ROOT));
    }
    #[test]
    fn only_startup_token_readonly_path_is_omitted_for_input_probe() {
        let props = expected();
        let original: BTreeSet<_> = TEMPLATE
            .lines()
            .find_map(|l| l.strip_prefix("ReadOnlyPaths="))
            .unwrap()
            .split_whitespace()
            .collect();
        let actual: BTreeSet<_> = props["ReadOnlyPaths"].split_whitespace().collect();
        assert_eq!(
            original.difference(&actual).copied().collect::<Vec<_>>(),
            vec![TOKENS]
        );
        assert!(actual.difference(&original).next().is_none());
        assert_eq!(props["ReadWritePaths"], format!("{ROOT} {NATIVE_ROOT}"));
        assert_eq!(
            namespace_exception()["production_namespace_qualified"],
            false
        );
    }
}
