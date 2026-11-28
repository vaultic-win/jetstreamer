//! Limited epoch 266 compact source qualification. The native and firehose code
//! included below is materialized unchanged from both deployed revisions.
#![allow(dead_code)]
use cid::{Cid, multibase::Base};
use log::{info, warn};
use reqwest::{
    Client, StatusCode, Url,
    header::{RANGE, RETRY_AFTER},
};
use serde_cbor::Value;
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_clock::Slot;
use std::{
    collections::HashMap,
    env, fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use xxhash_rust::xxh64::xxh64;
const LOG_MODULE: &str = "jetstreamer::firehose";
const RIPGET_LOG_INTERVAL_SECS: u64 = 5;
mod archive;
mod epochs;
mod network {
    use reqwest::Client;
    include!("network.rs");
}
mod index;
use epochs::{BASE_URL, epoch_to_slot_range, slot_to_epoch};
include!("native.inc");

type ProbeResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const CAR_SIZE: u64 = 396186095544;
const CAR_ROOT: &str = "bafyreihxdx3dwzmgzbfpzo7z4n744c6cjnn63j3mg2mewkauxoa2tgxxqu";
const SELECTED: [(u64, &str); 3] = [
    (
        114912004,
        "bafyreiclwutvuud3u4mhbhudujnzog3q3s5zhz2msh3fwce2i3sejtke7q",
    ),
    (
        115128002,
        "bafyreidu663y34owttv5q6r2mfhsaenoxm57nxtklcueplmnn5euh4xyea",
    ),
    (
        115343448,
        "bafyreie3ohuhr2x7etdgvjsnpuss2xqvmlogwlzgnuf7tgy5ezlt4jmeaq",
    ),
];
fn check(ok: bool, msg: &str) -> ProbeResult<()> {
    if !ok {
        return Err(io::Error::other(msg).into());
    }
    Ok(())
}
async fn selected_bytes(c: &Client, start: u64, len: u64) -> ProbeResult<Vec<u8>> {
    let stop = start.checked_add(len).ok_or("offset overflow")?;
    check(
        len > 0 && len <= 20 * 1024 * 1024 && stop <= CAR_SIZE,
        "bounded epoch 266 CAR request",
    )?;
    let range = format!("bytes={}-{}", start, stop - 1);
    let url = "https://files.old-faithful.net/266/epoch-266.car";
    let mut response = c.get(url).header(RANGE, range).send().await?;
    check(
        response.url().as_str() == url
            && response.status() == StatusCode::PARTIAL_CONTENT
            && response.content_length() == Some(len)
            && response
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                == Some(format!("bytes {}-{}/{}", start, stop - 1, CAR_SIZE).as_str()),
        "CAR response identity or length",
    )?;
    let mut body = Vec::with_capacity(len as usize);
    while let Some(chunk) = response.chunk().await? {
        check(body.len() + chunk.len() <= len as usize, "excess CAR range")?;
        body.extend_from_slice(&chunk);
    }
    check(body.len() == len as usize, "short CAR range")?;
    Ok(body)
}
fn verify_sections(
    body: &[u8],
    absolute_offset: u64,
    block_offset: u64,
    slot: u64,
    expected_cid: &str,
) -> ProbeResult<usize> {
    let mut at = 0usize;
    let mut count = 0usize;
    let mut block = false;
    while at < body.len() {
        let begin = at;
        let (size, n) = decode_varint(&body[at..])?;
        let start = at.checked_add(n).ok_or("section prefix overflow")?;
        at = start
            .checked_add(usize::try_from(size)?)
            .ok_or("section length overflow")?;
        let section = body.get(start..at).ok_or("incomplete section")?;
        check(
            section.len() > 36 && section[..4] == [1, 113, 18, 32],
            "unexpected DAG-CBOR CID",
        )?;
        let data = &section[36..];
        check(
            Sha256::digest(data)[..] == section[4..36],
            "section content hash",
        )?;
        let Value::Array(fields) = serde_cbor::from_slice::<Value>(data)? else {
            return Err("expected DAG node array".into());
        };
        if fields.first() == Some(&Value::Integer(2)) {
            check(
                !block
                    && at == body.len()
                    && fields.get(1) == Some(&Value::Integer(i128::from(slot)))
                    && absolute_offset + begin as u64 == block_offset
                    && Cid::try_from(&section[..36])?.to_string_of_base(Base::Base32Lower)?
                        == expected_cid,
                "Block slot, section start, CID or end differs",
            )?;
            block = true;
        }
        count += 1;
    }
    check(block, "slot range lacked its final Block")?;
    Ok(count)
}
async fn qualify() -> ProbeResult<()> {
    check(
        env::var("JETSTREAMER_FORCE_LEGACY_INDEX")? == "1"
            && env::var("JETSTREAMER_NETWORK")? == "mainnet",
        "wrong service mode",
    )?;
    let base = resolve_remote_index_base_url()?;
    check(
        base.as_str() == "https://files.old-faithful.net/" && base == index::get_index_base_url()?,
        "effective origins differ",
    )?;
    let dir = Path::new("/run/horizon266-legacy-source-v2/ledger");
    let expected_bytes = fs::read("/run/horizon266-legacy-source-v2/expected.json")?;
    check(
        format!("{:x}", Sha256::digest(&expected_bytes))
            == "00dedd690ae9ed8e6f193dedfd17fb4c25d7fbc67ba8c9900ce32ac6b16c1196",
        "original acquired reference digest",
    )?;
    let expected: serde_json::Value = serde_json::from_slice(&expected_bytes)?;
    let cg = Path::new("/sys/fs/cgroup/system.slice/horizon266-legacy-source-sample-v2.service");
    check(
        fs::read_to_string("/proc/self/cgroup")?.trim()
            == "0::/system.slice/horizon266-legacy-source-sample-v2.service"
            && fs::read_to_string(cg.join("memory.max"))?.trim() == "1073741824"
            && fs::read_to_string(cg.join("memory.swap.max"))?.trim() == "0"
            && fs::read_to_string(cg.join("pids.max"))?.trim() == "96"
            && unsafe { libc::geteuid() } == 1000,
        "service identity or kernel resource limits",
    )?;
    let inputs = expected["members"]
        .as_array()
        .ok_or("missing acquired members")?;
    check(
        inputs.len() == 3 && expected["car_root"] == CAR_ROOT,
        "wrong acquired cache",
    )?;
    for (row, ep) in inputs.iter().zip([265, 266, 266]) {
        let name = row["name"].as_str().ok_or("missing name")?;
        let path = dir.join("compact-indexes").join(ep.to_string()).join(name);
        let sealed =
            Path::new("/var/lib/jetstreamer/horizon266-index-acquire-v1/cache/sealed").join(name);
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(&path)?;
        let src = fs::metadata(sealed)?;
        check(
            path.canonicalize()? == path
                && m.is_file()
                && m.uid() == 0
                && m.mode() & 0o777 == 0o444
                && (m.dev(), m.ino()) == (src.dev(), src.ino())
                && Some(m.len()) == row["bytes"].as_u64(),
            "wrong effective compact-index mount",
        )?;
        let mut flags = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        check(
            unsafe { libc::statvfs(c.as_ptr(), flags.as_mut_ptr()) } == 0,
            "statvfs",
        )?;
        check(
            unsafe { flags.assume_init() }.f_flag & libc::ST_RDONLY != 0,
            "writable cache projection",
        )?;
    }
    let c = network::create_http_client();
    let header = selected_bytes(&c, 0, 4096).await?;
    check(
        format!("{:x}", Sha256::digest(&header))
            == "f6b4974df3daa2b7181395c5380479a7a2b38d6c4554991a59502211295acd66"
            && fetch_epoch_root_cid(&c, &base.join("266/epoch-266.car")?)
                .await?
                .to_string_of_base(Base::Base32Lower)?
                == CAR_ROOT,
        "CAR root binding",
    )?;
    let map = build_slot_presence_map(
        114910769,
        115343999,
        Arc::new(AtomicBool::new(false)),
        dir,
        266,
    )
    .await?;
    let index = index::SlotOffsetIndex::new(base)?;
    let refs = expected["slots"].as_array().ok_or("no acquired lookups")?;
    check(refs.len() == SELECTED.len(), "wrong lookup count")?;
    let mut records = Vec::new();
    for ((slot, cid), row) in SELECTED.into_iter().zip(refs) {
        check(
            row["slot"] == slot
                && row["cid"] == cid
                && map.state(slot) == Some(SlotPresenceState::Present),
            "native presence or local CID differs",
        )?;
        let (offset, length) = index.get_range(slot).await?;
        check(
            row["offset"] == offset && row["length"] == length,
            "legacy HTTP result differs from acquired local indexes",
        )?;
        let bytes = selected_bytes(&c, offset, length).await?;
        let count = verify_sections(
            &bytes,
            offset,
            row["block_offset"].as_u64().ok_or("missing block offset")?,
            slot,
            cid,
        )
        .map_err(|err| {
            format!("CAR section at slot {slot}, offset {offset} length {length}: {err}")
        })?;
        records.push(json!({"slot":slot,"cid":cid,"offset":offset,"length":length,"nodes":count,"sha256":format!("{:x}",Sha256::digest(&bytes))}));
    }
    println!(
        "{}",
        json!({"schema":"horizon266-legacy-source-sample-v2","argv":env::args().collect::<Vec<_>>(),"cwd":env::current_dir()?,"invocation":env::var("INVOCATION_ID")?,
        "epoch":266,"car_root":CAR_ROOT,"native_presence_start":map.start,"native_presence_end":map.end_inclusive,
        "present_count":map.states.iter().filter(|v|**v==SlotPresenceState::Present).count(),
        "samples":records,"expected":expected,"entry_replay":false,"full_car_verified":false})
    );
    Ok(())
}
fn main() -> ProbeResult<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(qualify())
}
