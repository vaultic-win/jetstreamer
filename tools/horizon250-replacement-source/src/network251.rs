//! Capture a completed, retained 4 KiB HTTP range probe, never run replay.
use super::*;
use std::{collections::BTreeMap, process::Command};
const UNIT: &str = "horizon251-car-header-network-proof-20261118-v1.service";
const IID: &str = "2a8c1450def74d878548674daea37345";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-251-replacement-20261118-v1";
const PROPS: &str = "InvocationID,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ExecStart,User,Group,NoNewPrivileges,ProtectSystem,ProtectHome,ProtectControlGroups,PrivateTmp,PrivateNetwork,RestrictAddressFamilies,ReadWritePaths,BindReadOnlyPaths,WorkingDirectory";

fn manager() -> Result<Vec<u8>> {
    let r = Command::new("/usr/bin/systemctl")
        .args(["show", UNIT, "--property", PROPS])
        .output()?;
    ensure!(
        r.status.success() && r.stderr.is_empty(),
        "manager read failed"
    );
    Ok(r.stdout)
}
fn check_manager(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut p = BTreeMap::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let (k, v) = line.split_once('=').context("unframed manager property")?;
        ensure!(
            p.insert(k.to_string(), v.to_string()).is_none(),
            "duplicate manager property"
        );
    }
    for (k, v) in [
        ("InvocationID", IID),
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("Result", "success"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", "0"),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("ProtectControlGroups", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateNetwork", "no"),
        ("ReadWritePaths", ROOT),
        ("WorkingDirectory", ROOT),
    ] {
        ensure!(
            p.get(k).map(String::as_str) == Some(v),
            "wrong manager property {k}"
        );
    }
    let families: std::collections::BTreeSet<_> = p
        .get("RestrictAddressFamilies")
        .context("families")?
        .split_whitespace()
        .collect();
    ensure!(
        families == ["AF_INET", "AF_INET6", "AF_UNIX"].into_iter().collect(),
        "network families differ"
    );
    let cmd = p.get("ExecStart").context("command")?;
    ensure!(cmd.starts_with("{ path=/usr/bin/curl ; argv[]=/usr/bin/curl --fail --silent --show-error --proto =https --range 0-4095 --max-time 60 --max-filesize 4096 --dump-header network-proof/headers --output network-proof/body --write-out %{http_code} %{size_download}\\n https://files.old-faithful.net/251/epoch-251.car ; ignore_errors=no ; ")
        && cmd.ends_with("; code=exited ; status=0 }"), "different HTTP request");
    let cache = "/var/lib/jetstreamer/horizon251-index-cache-20261118-v1";
    let mounts = format!(
        "{cache}:{ROOT}/output/compact-indexes/250:rbind {cache}:{ROOT}/output/compact-indexes/251:rbind /var/lib/jetstreamer/horizon251-native-input-20261118-v1/genesis.tar.bz2:{ROOT}/output/genesis.tar.bz2:rbind"
    );
    ensure!(
        p.get("BindReadOnlyPaths") == Some(&mounts),
        "cache or genesis binding differs"
    );
    Ok(p)
}
fn read(path: &Path) -> Result<(Vec<u8>, Value)> {
    let identity = |p: &Path| -> Result<Value> {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_file()
                && m.uid() == 1000
                && m.gid() == 1000
                && m.mode() & 0o777 == 0o600
                && m.nlink() == 1
                && m.len() <= 65536
                && p.canonicalize()? == p,
            "unsafe probe output"
        );
        Ok(
            json!({"dev":m.dev(),"ino":m.ino(),"bytes":m.len(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()}),
        )
    };
    let before = identity(path)?;
    let bytes = fs::read(path)?;
    ensure!(before == identity(path)?, "probe output changed");
    Ok((bytes, before))
}
fn check_response(headers: &[u8], body: &[u8]) -> Result<()> {
    let h = std::str::from_utf8(headers)?;
    ensure!(
        h.starts_with("HTTP/2 206 \r\n")
            && h.contains("\r\ncontent-range: bytes 0-4095/420666863585\r\n")
            && h.contains("\r\ncontent-length: 4096\r\n")
            && body.len() == 4096,
        "wrong HTTP range"
    );
    // Canonical one-root CAR v1 header, including CBOR CID tag and multibase byte.
    let prefix = [
        0x3a, 0xa2, 0x65, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x81, 0xd8, 0x2a, 0x58, 0x25, 0x00,
    ];
    let cid = "017112209310992bd217a84ad737224c38279f2da531f5b487283ca225eccebe344e936f";
    let observed: String = body[14..50].iter().map(|b| format!("{b:02x}")).collect();
    ensure!(
        body[..14] == prefix && observed == cid && &body[50..59] == b"\x67version\x01",
        "wrong CAR root or version"
    );
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 3, "usage: capture-251-network OUTPUT_JSON");
    let output = Path::new(&args[2]);
    ensure!(
        output.is_absolute()
            && output.parent().context("output parent")?.canonicalize()?
                == output.parent().unwrap(),
        "noncanonical output"
    );
    let before = manager()?;
    let props = check_manager(&before)?;
    let header_path = PathBuf::from(ROOT).join("network-proof/headers");
    let body_path = PathBuf::from(ROOT).join("network-proof/body");
    let (headers, hi) = read(&header_path)?;
    let (body, bi) = read(&body_path)?;
    check_response(&headers, &body)?;
    ensure!(before == manager()?, "probe manager changed during capture");
    let receipt = json!({"schema":"horizon251-service-effective-car-header-proof-v1","epoch":251,"unit":UNIT,"invocation_id":IID,"effective_properties":props,"headers":{"path":header_path,"sha256":digest(&headers),"identity":hi},"body":{"path":body_path,"sha256":digest(&body),"identity":bi},"http_status":206,"download_bytes":4096,"content_range":"bytes 0-4095/420666863585","expected_root_cid":"bafyreietccmsxuqxvbfnonzcjq4cphznuuy7lnehfa6kejpmz27ditutn4","car_header_accepted":true,"deployed_node_cache_reader_qualified":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(output)?;
    serde_json::to_writer_pretty(&mut file, &receipt)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(output.parent().unwrap())?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_wrong_root_and_full_object_response() {
        let h =
            b"HTTP/2 206 \r\ncontent-range: bytes 0-4095/420666863585\r\ncontent-length: 4096\r\n";
        let mut b = vec![0; 4096];
        let raw = "3aa265726f6f747381d82a582500017112209310992bd217a84ad737224c38279f2da531f5b487283ca225eccebe344e936f6776657273696f6e01";
        for (i, pair) in raw.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            b[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        check_response(h, &b).unwrap();
        b[20] ^= 1;
        assert!(check_response(h, &b).is_err());
        b[20] ^= 1;
        assert!(check_response(b"HTTP/2 200\r\n", &b).is_err());
        assert!(check_response(h, &b[..40]).is_err());
    }
}
