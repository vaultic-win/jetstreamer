//! Bounded GET-only comparison; never archive/sidecar publication evidence.
use super::*;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::{Duration, Instant},
};
const LENGTH: usize = 32 << 20;
const OFFSET: u64 = 8 << 30;
fn select_address(addresses: &[SocketAddr], ipv6: bool) -> Result<SocketAddr> {
    addresses
        .iter()
        .copied()
        .find(|a| a.is_ipv6() == ipv6)
        .context("address family unavailable")
}
fn validate_prefix(bytes: &[u8], expected: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() == LENGTH && bytes == expected,
        "probe bytes differ from local prefix"
    );
    Ok(())
}
fn profile(command: &str) -> Result<(u64, &'static str, &'static str)> {
    match command {
        "probe-transport-217" => Ok((
            217,
            "horizon-217-transport-probe-",
            "jetstreamer-private-epoch217-transport-probe-v2",
        )),
        "probe-transport-203" => Ok((
            203,
            "horizon-203-transport-probe-",
            "jetstreamer-private-epoch203-transport-probe-v1",
        )),
        _ => anyhow::bail!("unsupported transport probe profile"),
    }
}
pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--output" && args[4] == "--self-sha256",
        "usage: jetstreamer-r2 probe-transport-203|probe-transport-217 --output PRIVATE/probe.json --self-sha256 HEX"
    );
    let (epoch, output_prefix, schema) = profile(&args[1])?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "probe requires root private receipt identity"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let em = fs::symlink_metadata(&exe)?;
    ensure!(
        em.is_file()
            && em.uid() == 0
            && em.nlink() == 1
            && em.mode() & 0o222 == 0
            && em.len() < 256 << 20,
        "probe executable is not sealed"
    );
    ensure!(
        format!("{:x}", Sha256::digest(fs::read(&exe)?)) == args[5],
        "probe executable differs"
    );
    let output = PathBuf::from(&args[3]);
    let parent = output.parent().context("missing private parent")?;
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        output.is_absolute()
            && parent.canonicalize()? == parent
            && parent.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && parent
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(output_prefix))
            && output.file_name().is_some_and(|s| s == "probe.json")
            && pm.is_dir()
            && pm.uid() == 0
            && pm.mode() & 0o777 == 0o700,
        "foreign private probe output"
    );
    ensure!(!output.try_exists()?, "probe output occupied");
    let path = PathBuf::from(format!("/home/ubuntu/horizon/epoch-{epoch}.jet"));
    let key = format!("epoch-{epoch}.jet");
    let before = regular_identity(&path)?;
    let mut expected = vec![0u8; LENGTH];
    let mut local = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    local.seek(SeekFrom::Start(OFFSET))?;
    local.read_exact(&mut expected)?;
    let config = r2_config_from_env()?;
    let endpoint = Url::parse(&config.endpoint)?;
    ensure!(
        endpoint.scheme() == "https",
        "probe requires authenticated HTTPS endpoint"
    );
    let host = endpoint.host_str().context("missing endpoint host")?;
    let port = endpoint
        .port_or_known_default()
        .context("missing HTTPS port")?;
    let addresses: Vec<_> = (host, port).to_socket_addrs()?.take(16).collect();
    let client = s3_client(&config);
    let head = client
        .head_object()
        .bucket(&config.bucket)
        .key(&key)
        .send()
        .await
        .map_err(|_| anyhow!("probe HEAD failed"))?;
    ensure!(
        head.content_length().and_then(|n| u64::try_from(n).ok()) == Some(before.length),
        "remote length differs from local archive"
    );
    let etag = head.e_tag().context("missing immutable ETag")?;
    if epoch == 203 {
        ensure!(
            before.length == 103_802_397_352
                && etag.trim_matches('"') == "6f543a2b1f7c1d60647a9f5f8b541150-1547",
            "exact203 staged object identity differs"
        );
    }
    let range = format!("bytes={}-{}", OFFSET, OFFSET + LENGTH as u64 - 1);
    let expected_range = format!(
        "bytes {}-{}/{}",
        OFFSET,
        OFFSET + LENGTH as u64 - 1,
        before.length
    );
    let sdk_started = Instant::now();
    let sdk_attempt: Result<Value> = match tokio::time::timeout(Duration::from_secs(20), async {
        let response = client.get_object().bucket(&config.bucket).key(&key)
            .range(&range).if_match(etag).send().await.map_err(|_|anyhow!("SDK window request failed"))?;
        ensure!(response.content_length() == Some(LENGTH as i64) && response.content_range() == Some(expected_range.as_str()), "SDK window response bounds differ");
        let bytes = response.body.collect().await.map_err(|e|anyhow!(format!("{e:?}").replace(&config.access_key,"[redacted]").replace(&config.secret_key,"[redacted]")))?.into_bytes();
        validate_prefix(&bytes,&expected)?;
        Ok(serde_json::json!({"success":true,"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes))}))
    }).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("SDK window reached 20-second timeout")),
    };
    let sdk_result = match sdk_attempt {
        Ok(v) => v,
        Err(e) => serde_json::json!({"success":false,"error":e.to_string()}),
    };
    let sdk =
        serde_json::json!({"elapsed_millis":sdk_started.elapsed().as_millis(),"result":sdk_result});
    let signed = client
        .get_object()
        .bucket(&config.bucket)
        .key(&key)
        .range(&range)
        .if_match(etag)
        .presigned(aws_sdk_s3::presigning::PresigningConfig::expires_in(
            Duration::from_secs(120),
        )?)
        .await
        .map_err(|_| anyhow!("GET-only signing failed"))?;
    let mut results = Vec::new();
    for ipv6 in [false, true] {
        let started = Instant::now();
        let address = select_address(&addresses, ipv6)?;
        let attempt: Result<Value> = async {
            let http = reqwest::Client::builder().https_only(true).no_proxy().redirect(reqwest::redirect::Policy::none()).resolve(host,address).connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(20)).build().map_err(|e|anyhow!(e.without_url().to_string()))?;
            let mut request = http.get(signed.uri());
            for (key,value) in signed.headers() {request=request.header(key,value);}
            let response = request.send().await.map_err(|e|anyhow!(e.without_url().to_string()))?;
            ensure!(response.status()==reqwest::StatusCode::PARTIAL_CONTENT && response.content_length()==Some(LENGTH as u64), "GET probe returned wrong status or bounded length");
            ensure!(response.headers().get("content-range").and_then(|h|h.to_str().ok()) == Some(expected_range.as_str()), "GET probe Content-Range differs");
            let bytes = response.bytes().await.map_err(|e|anyhow!(e.without_url().to_string()))?;
            validate_prefix(&bytes,&expected)?;
            Ok(serde_json::json!({"success":true,"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes))}))
        }.await;
        let mut result = serde_json::json!({"ipv6":ipv6,"peer":address.ip().to_string(),"elapsed_millis":started.elapsed().as_millis()});
        match attempt {
            Ok(v) => result["result"] = v,
            Err(e) => result["result"] = serde_json::json!({"success":false,"error":e.to_string()}),
        };
        results.push(result);
    }
    ensure!(
        regular_identity(&path)? == before,
        "local source changed during probe"
    );
    let report = serde_json::json!({"schema":schema,"epoch":epoch,"archive_length":before.length,"range_start":OFFSET,"range_bytes":LENGTH,"sdk":sdk,"results":results,"publication_authorized":false,"whole_object_verified":false,"archive_mutations":false,"sidecar_mutations":false,"r2_mutations":false,"service_mutations":false});
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), &report)?;
    temporary.write_all(b"\n")?;
    persist_noclobber(temporary, &output)?;
    File::open(parent)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    #[test]
    fn probes_are_closed_profiles_with_disjoint_private_outputs() {
        let old = profile("probe-transport-217").unwrap();
        let staged = profile("probe-transport-203").unwrap();
        assert_eq!(old.0, 217);
        assert_eq!(staged.0, 203);
        assert_ne!(old.1, staged.1);
        for command in ["probe-transport-301", "probe-transport-204", "203", ""] {
            assert!(profile(command).is_err());
        }
    }
    #[test]
    fn address_family_is_explicit_and_missing_family_fails_closed() {
        let a = [
            SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 443),
            "[::1]:443".parse().unwrap(),
        ];
        assert!(select_address(&a, false).unwrap().is_ipv4());
        assert!(select_address(&a, true).unwrap().is_ipv6());
        assert!(select_address(&a[..1], true).is_err());
    }
    #[test]
    fn prefix_needs_exact_size_and_bytes_not_only_http_success() {
        let expected = vec![1; LENGTH];
        validate_prefix(&expected, &expected).unwrap();
        assert!(validate_prefix(&expected[..LENGTH - 1], &expected).is_err());
        assert!(validate_prefix(&vec![2; LENGTH], &expected).is_err());
    }
    #[test]
    fn request_error_does_not_expose_presigned_query() {
        let url = Url::parse("https://example.com/object?X-Amz-Credential=private-value").unwrap();
        let error = reqwest::Client::new()
            .get("not a URL")
            .build()
            .unwrap_err()
            .with_url(url);
        assert!(!error.without_url().to_string().contains("private-value"));
    }
}
