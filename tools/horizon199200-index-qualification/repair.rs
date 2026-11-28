//! Recover affected index rows from CID-verified Old Faithful CAR windows.
#[path = "../../jetstreamer-firehose/src/bin/native_window/mod.rs"]
mod native_window;

use jetstreamer_firehose::node::{Node, NodeReader};
use native_window::{Block, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    env, fs,
    io::{Cursor, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};

const SLOTS: u64 = 432_000;
const REVIEWED_EPOCHS: std::ops::RangeInclusive<u64> = 268..=301;
const HEADER: u64 = 59;
const PROFILE: &str = include_str!("plan.json");

fn sha(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .ok_or_else(|| format!("missing unsigned {key}").into())
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("missing text {key}").into())
}

fn read(path: &Path, size: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() != size {
        return Err(format!("size/type mismatch for {}", path.display()).into());
    }
    let b = fs::read(path)?;
    if b.len() as u64 != size {
        return Err("input changed during read".into());
    }
    Ok(b)
}

fn save(p: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    fs::File::open(p.parent().ok_or("output parent")?)?.sync_all()?;
    Ok(())
}

struct Captures<'a> {
    root: &'a Path,
    entries: BTreeMap<String, &'a Value>,
}

impl Captures<'_> {
    fn read(&self, e: u64, kind: &str, lo: u64, hi: u64) -> Result<Vec<u8>> {
        let name = format!("{e}-{kind}-{lo}-{hi}.car");
        let proof = self
            .entries
            .get(&name)
            .ok_or("missing range from transfer manifest")?;
        if number(proof, "lo")? != lo
            || number(proof, "hi")? != hi
            || number(proof, "epoch")? != e
            || text(proof, "kind")? != kind
        {
            return Err("capture identity mismatch".into());
        }
        let body = read(
            &self.root.join(name),
            hi.checked_sub(lo).ok_or("negative range")?,
        )?;
        if sha(&body) != text(proof, "sha256")? {
            return Err("capture hash mismatch".into());
        }
        Ok(body)
    }
}

fn known_root(e: u64) -> Result<&'static str> {
    match e {
        199 => Ok("bafyreid5x4ci3xei4wy5rijuqfjh4y6svca3a7tkhhsirxuhu3bj7p5z7y"),
        200 => Ok("bafyreibhxmsejxsshqpplpyhrpvf3tbl2cgl7qj33snet5b3q2txorimfu"),
        267 => Ok("bafyreifn4ykgns5ih2lzfzrvky2u5vfh4jvqcqy7tdylujrbvl6pqavi4m"),
        268 => Ok("bafyreiadrsuockl4wyx2s2nu247atdi7xhc6pc7ynhmetagg7mdkjdktgu"),
        269 => Ok("bafyreihyxzt42dpkxrmluxqvkxqfnkas7czh5igcvorg5a7fr4ckvewxzm"),
        270 => Ok("bafyreiewpp2gte55lvp5ml7labmgudq72juwvj5o5j3jd6xyjjbaxpudcu"),
        271 => Ok("bafyreievtg2mp5c7prfzuntr3hhljck6hbhrmkb65jmswlke6norpck4my"),
        272 => Ok("bafyreibyphy25qwppk5bm2uum2kp3dbqrjtjljqhdulhbqxesjj5encc3a"),
        273 => Ok("bafyreiad53lhdnph2etnrbwslfirrx7rb6r2dma2aazgm4bs5dvfw4hax4"),
        274 => Ok("bafyreid47yanxmkgrltqmsa3lbjwnbphm6fgwj7lvvwdoait7yv2zfwglq"),
        275 => Ok("bafyreibnfz5x3wrgf6cr737wbsnnlkyuphtl4qcdc3cnsegjvmelwnnczq"),
        276 => Ok("bafyreidr6kpe7wvhmmu75e6epocnw7lyz7smhkf6n2r3nwmqdyzop7rfd4"),
        277 => Ok("bafyreif67ugalao4gsy2abytaf2uu3hsz6lnvx7odbjuf65pgmirfmbk2q"),
        278 => Ok("bafyreibwj2uert4mbjtpp5a4q4yfywk5igufgike5fbjcljygei5exty3a"),
        279 => Ok("bafyreiewswobkyx2a67vqxgt4am47yisrrgg6kxaq5mreia5dyeikfruoi"),
        280 => Ok("bafyreicaxdokcw7qflwsmqtbmqgias7elbm73tlqqzd53bzz7bn3phmlaq"),
        281 => Ok("bafyreibrchqyzzvyg3sw24wluvyvkbpcn4ji3etgx2gm2rnqc2fry3gdxe"),
        283 => Ok("bafyreid66hsdd2npjbab3zfwaop3c2xfhuslz5pozra6mc66ulet64jcj4"),
        284 => Ok("bafyreidt3s3do73p2hgffss7ch55joh5iabrygacb4ynjbxzpudxyf4i7a"),
        282 => Ok("bafyreibkincn5733dntwqsibbo6ehpxxsno5iwqtfkousxeah76inkol2u"),
        285 => Ok("bafyreiam2ndwsov4oj4jelptiiat3l67kil4mj5tnovqkjv7n4bi3rjtoe"),
        286 => Ok("bafyreibsdipvtbosqf75w3skclwjphlncov2is5iivnl5cccjqvm4exmbu"),
        287 => Ok("bafyreiatkwxgebjpf57nclv3snf6tr3wfbk5b62xezxfjtouzxsgdwmqbq"),
        288 => Ok("bafyreiahdgxtk3turqkhar76tkv4hp6kz3kaqjenlgvrwpjml5oaggmabq"),
        289 => Ok("bafyreicacdmz6ivzpuaofj2ytyknmkpnkb6b5544hczun3k7acrrsdvqse"),
        290 => Ok("bafyreihd6jxi75sl5polwtldkxdpatnkhhrkwh7cpjukyn42oe6pkagmiq"),
        291 => Ok("bafyreiabgztwahscuxhsjqdrv7sxxs7vys4rh37krbbm5mx3ds2ftdoqyq"),
        292 => Ok("bafyreie5o7qdkfcqlybizbhpyoc6yqvtbn5erdzf4g2aneatevb7p5n74a"),
        293 => Ok("bafyreihykwqix4y6y5ve4dl2xgxsv4mxybemg5sivlizxkgtjdap3jj52y"),
        294 => Ok("bafyreibagip3au2fkj5owmq6tswoflt266elzvcgqqls4scbiqfp2a4jre"),
        295 => Ok("bafyreifit4zyjy664wgdfzc75farxhnif2xrkvlkdvi5pufh2spav7lh3m"),
        296 => Ok("bafyreig5pqhwelpi6f4fikdp4bzd6ezntyuviuxdpvlausdmv5mpzewade"),
        297 => Ok("bafyreie34tp3pqsr2cxtyfxy7ugfcebu7k7yp3b7vvbavebsx7lcluc46u"),
        298 => Ok("bafyreihsmeo6tbb5vbwrk7md4k4mbbmjdhkkpvqnnpcpnxmmgjxkdeyu6a"),
        299 => Ok("bafyreiaom6ox5xoiql6sng2v6z53eemxqiwfaxvhkzcmysc5me4lo6xcoi"),
        300 => Ok("bafyreih45lcghluasjbqciqkixfjfjufbltuu3vhhkrx6ktdkotahpklva"),
        301 => Ok("bafyreierz53jcmi577gn5dv5rtubzbr3szebafo6lpffv3lmura2ywmw4e"),
        _ => Err("unexpected epoch".into()),
    }
}

fn row(raw: &[u8], e: u64, slot: u64) -> Result<(u64, u32)> {
    let i = slot
        .checked_sub(e * SLOTS)
        .filter(|i| *i < SLOTS)
        .ok_or("slot outside epoch")? as usize;
    let b = &raw[i * 12..(i + 1) * 12];
    Ok((
        u64::from_le_bytes(b[..8].try_into()?),
        u32::from_le_bytes(b[8..].try_into()?),
    ))
}

fn check_window(
    header: &[u8],
    body: &[u8],
    raw: &[u8],
    e: u64,
    w: &Value,
) -> Result<(Vec<Block>, u64)> {
    let lo = number(w, "lo_slot")?;
    let hi = number(w, "hi_slot")?;
    if lo >= hi || hi - lo > 64 {
        return Err("invalid flanking slot span".into());
    }
    let a = number(w, "start")?;
    let b = number(w, "end")?;
    let (ao, al) = row(raw, e, lo)?;
    let (bo, bl) = row(raw, e, hi)?;
    if ao != a || bo + u64::from(bl) != b || a < HEADER || body.len() as u64 != b - a {
        return Err("proposed window changed".into());
    }
    let (nodes, sections) = native_window::decode(header, body, a)?;
    let first = nodes.first().ok_or("empty window")?;
    let last = nodes.last().ok_or("empty window")?;
    if (first.slot, first.start, first.end - first.start) != (lo, ao, u64::from(al))
        || (last.slot, last.start, last.end) != (hi, bo, b)
        || first.parent >= first.slot
        || nodes
            .windows(2)
            .any(|p| p[0].slot >= p[1].slot || p[0].slot != p[1].parent || p[0].end != p[1].start)
    {
        return Err("native flanking block or physical parent chain mismatch".into());
    }
    Ok((nodes, sections))
}

type Witness = (u64, u32, u64, String);

fn membership(
    e: u64,
    header: &[u8],
    footer: Vec<u8>,
    witness: &BTreeMap<u64, Option<Witness>>,
) -> Result<(usize, usize)> {
    let mut targets = BTreeMap::new();
    for (slot, w) in witness {
        if let Some((_, _, _, hex)) = w {
            if hex.len() % 2 != 0 {
                return Err("invalid CID bytes".into());
            }
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<std::result::Result<Vec<u8>, _>>()?;
            if targets.insert(bytes, (*slot, 0_u32)).is_some() {
                return Err("duplicate physical CID".into());
            }
        }
    }
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(&footer);
    let len = bytes.len() as u64;
    let mut reader = NodeReader::new(Cursor::new(bytes))?;
    reader.read_raw_header()?;
    let mut subsets = Vec::new();
    let mut all = HashSet::new();
    let mut prior_last = None;
    loop {
        let n = reader.next()?;
        n.verify_sha256_cid()?;
        match n.parse()? {
            Node::Subset(s) => {
                if s.first > s.last
                    || s.first < e * SLOTS
                    || s.last >= (e + 1) * SLOTS
                    || prior_last.is_some_and(|p| s.first <= p)
                {
                    return Err("subset slot limits overlap or leave epoch".into());
                }
                prior_last = Some(s.last);
                subsets.push(*n.get_cid());
                for cid in s.blocks {
                    if !all.insert(cid) {
                        return Err("duplicate CID in canonical subsets".into());
                    }
                    if let Some((slot, count)) = targets.get_mut(&cid.to_bytes()) {
                        if !(s.first..=s.last).contains(slot) {
                            return Err("canonical subset disagrees with block slot".into());
                        }
                        *count += 1;
                    }
                }
            }
            Node::Epoch(root)
                if root.epoch == e
                    && n.get_cid().to_string() == known_root(e)?
                    && root.subsets == subsets
                    && !subsets.is_empty() =>
            {
                break;
            }
            _ => return Err("unexpected footer node or epoch membership".into()),
        }
    }
    if reader.into_inner().position() != len || targets.values().any(|(_, n)| *n != 1) {
        return Err("incomplete footer or missing rooted physical block".into());
    }
    Ok((all.len(), targets.len()))
}

fn run_epoch(plan: &Value, source: &Path, cap: &Captures<'_>, out: &Path) -> Result<Value> {
    let e = number(plan, "epoch")?;
    known_root(e)?;
    let raw = read(
        &source.join(format!("epoch-{e}-slot-ranges.raw")),
        SLOTS * 12,
    )?;
    if sha(&raw) != text(plan, "raw_sha256")? {
        return Err("original raw index mismatch".into());
    }
    let head = cap.read(e, "header", 0, HEADER)?;
    if sha(&head) != text(plan, "header_sha256")? {
        return Err("unexpected canonical CAR header".into());
    }
    let tail = number(plan, "footer_at")?;
    let footer = cap.read(e, "footer", tail, number(plan, "car_bytes")?)?;
    let mut witness: BTreeMap<u64, Option<Witness>> = BTreeMap::new();
    let mut sections = 0;
    let mut failures = Vec::new();
    let mut passed = 0;
    for w in plan["individual_windows"]
        .as_array()
        .ok_or("absent windows")?
    {
        let a = number(w, "start")?;
        let b = number(w, "end")?;
        let lo = number(w, "lo_slot")?;
        let hi = number(w, "hi_slot")?;
        let body = cap.read(e, "window", a, b)?;
        let (blocks, n) = match check_window(&head, &body, &raw, e, w) {
            Ok(row) => row,
            Err(error) => {
                failures.push(
                    json!({"lo_slot":lo,"hi_slot":hi,"start":a,"end":b,"error":error.to_string()}),
                );
                continue;
            }
        };
        let mut rows = BTreeMap::new();
        for node in blocks {
            rows.insert(
                node.slot,
                (
                    node.start,
                    u32::try_from(node.end - node.start)?,
                    node.parent,
                    node.cid,
                ),
            );
        }
        for slot in lo..=hi {
            let value = rows.remove(&slot);
            if let Some(prior) = witness.insert(slot, value.clone())
                && prior != value
            {
                return Err("incompatible overlapping native slot witnesses".into());
            }
        }
        if !rows.is_empty() {
            return Err("physical block outside accepted anchors".into());
        }
        passed += 1;
        sections += n;
    }
    let (canonical_count, rooted_witnesses) = membership(e, &head, footer, &witness)?;
    let partial = json!({"epoch":e,"root":known_root(e)?,"canonical_block_cids":canonical_count,"verified_windows":passed,
                      "verified_sections":sections,"rooted_observed_blocks":rooted_witnesses,"failures":failures});
    save(
        &out.join(format!("epoch-{e}-windows.json")),
        serde_json::to_string_pretty(&partial)?.as_bytes(),
    )?;
    if !failures.is_empty() {
        return Err(format!("{} windows failed for epoch {e}", failures.len()).into());
    }
    let mut corrected = raw.clone();
    let mut changes = Vec::new();
    let mut verified_skips = Vec::new();
    for (slot, value) in witness {
        if REVIEWED_EPOCHS.contains(&e) && value.is_none() {
            verified_skips.push(slot);
        }
        let was = row(&raw, e, slot)?;
        let now = value.as_ref().map(|v| (v.0, v.1)).unwrap_or_default();
        if was != now {
            let i = ((slot - e * SLOTS) * 12) as usize;
            corrected[i..i + 8].copy_from_slice(&now.0.to_le_bytes());
            corrected[i + 8..i + 12].copy_from_slice(&now.1.to_le_bytes());
            changes.push(json!({"slot":slot,"was":was,"now":now,"rooted_witness":value}));
        }
    }
    let mut pos = HEADER;
    let mut present = 0;
    for slot in e * SLOTS..(e + 1) * SLOTS {
        let (offset, len) = row(&corrected, e, slot)?;
        if len == 0 {
            if offset != 0 {
                return Err("nonzero skipped row".into());
            }
            continue;
        }
        if offset != pos {
            return Err(format!("still discontinuous at slot {slot}: {offset} vs {pos}").into());
        }
        pos = pos.checked_add(u64::from(len)).ok_or("CAR overflow")?;
        present += 1;
    }
    if pos != tail || present != canonical_count {
        return Err(format!(
            "whole-epoch coverage differs: end {pos} vs {tail} count {present} vs {canonical_count}"
        )
        .into());
    }
    let mut result = json!({"epoch":e,"root":known_root(e)?,"windows":partial,"changes":changes,"present":present,"skips":SLOTS-present as u64,
        "physical_end":pos,"original_sha256":sha(&raw),"corrected_sha256":sha(&corrected)});
    if REVIEWED_EPOCHS.contains(&e) {
        result["rooted_window_skips"] = json!(verified_skips);
    }
    save(&out.join(format!("epoch-{e}-slot-ranges.raw")), &corrected)?;
    save(
        &out.join(format!("epoch-{e}-repair.json")),
        serde_json::to_string_pretty(&result)?.as_bytes(),
    )?;
    Ok(
        json!({"epoch":e,"changes":changes.len(),"present":present,"rooted_blocks":rooted_witnesses,"windows":passed,"sections":sections,"corrected_sha256":sha(&corrected)}),
    )
}

fn reviewed(epoch: u64, plan_path: &Path, expected: &str) -> Result<(String, u64, usize)> {
    let (car_bytes, header_sha) = match epoch {
        268 => (
            476675176389,
            "56e3dd997f05185be809c81914781ae69a5c65c5199b2aca467041e11af41333",
        ),
        269 => (
            472271953708,
            "72d6c4f592052faafeb2f1f71ee13f61ec621db543ee11d6d1fc5dfa1a92337a",
        ),
        270 => (
            450199158585,
            "2f147ec43612148360a9eaca172011f46c64d61e5e521fd67621626423c818f7",
        ),
        271 => (
            346_337_409_273,
            "429a44f174c57aed966aaadb9434a099c6c2aa4fe81a5afec977c13cd393169f",
        ),
        272 => (
            504_331_014_291,
            "6a986aad1f381cf00fe9e518ea4f4dcd0cdfa1dc6c189c07c055a8ed4ac9fdb5",
        ),
        273 => (
            505_109_600_074,
            "be6e0aff06c92ac24e7fecd6eabd6ac5eaa8b496d3cb77a2745e7892a2917f86",
        ),
        274 => (
            500_678_680_702,
            "2686416a6fb87c18c97147bd0798ab9571cee9e7ffeffbecb3aa48deb72641da",
        ),
        275 => (
            490_317_638_534,
            "fe6b9cb1699871bb05d63931c7ed59417a81cbd6489f7999851357b09dc17c60",
        ),
        276 => (
            508_471_695_938,
            "da2898ffbef47715a7f101b85a5df12edcd763f8101be4e70d0847df99141b42",
        ),
        277 => (
            508_122_442_412,
            "bae90306002f343ade42a2aa2a1da3aac83bf332fb276b275298d441a09384fa",
        ),
        278 => (
            497_956_610_737,
            "e13fda159808631ef9e63e473c666c901305febaba3e298e2db42bd004b0100b",
        ),
        279 => (
            499_133_102_307,
            "05e86ddd653c50139f056f7dee88e62780d57e50970b0ecbbe3a0ef1e75479b0",
        ),
        280 => (
            497_546_531_409,
            "db4a6983225ace2707e8e0067dfe4c52320ad1e8649cfba1cfbf9293fd92b7ab",
        ),
        281 => (
            466_037_864_351,
            "71afea9bb428d7a10d3ec3e3327d8a8e996b7f02a58623241964031c779e3435",
        ),
        282 => (
            482_279_853_071,
            "c36914651aacd7599f5751afc4e43dc6a5169b478e5e7b5dc0f34927a59e92a3",
        ),
        283 => (
            484_898_077_871,
            "a61ef8ec0040a99f7c35e26ff67d423561744b824d98998580632410ccdeabfc",
        ),
        284 => (
            495_320_593_672,
            "3c4b697ad835af1cb28df64329758e28b141704612aa5e66b2c095b74524d0a1",
        ),
        285 => (
            489_731_879_514,
            "b04fbcf049bb5f986eaaf4c5dc6ce47c106308406bef14cef36e6e5aa54f5999",
        ),
        286 => (
            493_913_529_396,
            "d86d2019aa2f98ba30cace55bcecbaf4e5bcd7c9dc5c4fd19e7b7cc27b383911",
        ),
        287 => (
            471_816_188_164,
            "cea1a636793d0f375af497b42d0fe14913af3a6e8aeceb99a1038db42cfbf89e",
        ),
        288 => (
            502_563_875_656,
            "e61d9dc74899050a0913ec06642b6a977af9feb07748bd9ae530dcfbe68ea11d",
        ),
        289 => (
            445_210_450_979,
            "2502cd58d1e6f879343db5f7dcc1953985a8b5226543f2ae3711f37b50ba81fb",
        ),
        290 => (
            507_505_413_726,
            "f4d0c5e528988bdca41ce9e03738c96d983b077b501ef3539f430346be611bdf",
        ),
        291 => (
            497_952_843_848,
            "cb3d713eb1968e2c2156c7b24b552da2f83528cc2d27d9e6b3ba6e994dede04e",
        ),
        292 => (
            494_982_960_331,
            "fcc1353065c8bc00f6fd0b8ab37f26cf4c103356cdcd551f43da2ef6aff317e5",
        ),
        293 => (
            487_914_828_256,
            "75133dbb314c9fd6d78371300f21b2e32cbc02b1c6735cb46f9091743e67f8cd",
        ),
        294 => (
            508_172_775_221,
            "487c079309f4ffd35a069a7c67b2724ca6a5c9a9f8555aca731c81ecc02c2ac5",
        ),
        295 => (
            473_764_283_986,
            "37b92faeaef1b41ad4cd313f6f14b09c21117d25fbda54d7e95e82b47f9b9a28",
        ),
        296 => (
            409_134_410_703,
            "cc2a5c5318df3677ec330134a50952ae4304efc21d26e1987f255a195de5595b",
        ),
        297 => (
            361_472_655_299,
            "45612fd8f9aee6024a7f71bd698e7a40a14c7954126f0b8f4594c894a3468111",
        ),
        298 => (
            320_301_441_025,
            "451d491b8f887440f8177b1b18708f6ae7d1cb8b19e46ef46753743bc36f2f82",
        ),
        299 => (
            417_915_306_272,
            "4da64750e675da9aa5304335371390ceb22befa14c792ba78841640929dc326f",
        ),
        300 => (
            508_337_873_180,
            "ccd566b2535cf6e07f2aedb48fb22db221e5b79cb516ee2ec63e5b75fe456d87",
        ),
        301 => (
            459_390_679_072,
            "3365c64ba2d3b1244768a455d5dab105737627f6348945e73d6c51d1cce95569",
        ),
        _ => return Err("unregistered dynamic epoch".into()),
    };
    let first = epoch * SLOTS;
    let len = fs::symlink_metadata(plan_path)?.len();
    if len > 256_000 {
        return Err(format!("oversized epoch {epoch} capture plan").into());
    }
    let input = read(plan_path, len)?;
    if sha(&input) != expected {
        return Err(format!("unrecognized epoch {epoch} capture plan").into());
    }
    let doc: Value = serde_json::from_slice(&input)?;
    let epochs = doc["epochs"].as_array().ok_or("plan epochs")?;
    if epochs.len() != 1 {
        return Err("expected singleton dynamic epoch".into());
    }
    let p = &epochs[0];
    let car = number(p, "car_bytes")?;
    let foot = number(p, "footer_at")?;
    if number(p, "epoch")? != epoch
        || car != car_bytes
        || text(p, "root")? != known_root(epoch)?
        || text(p, "header_sha256")? != header_sha
        || foot < HEADER
        || foot >= car
        || car - foot > 32 << 20
    {
        return Err("wrong registered epoch geometry".into());
    }
    let ws = p["individual_windows"].as_array().ok_or("windows")?;
    if ws.len() > 256 {
        return Err("window count".into());
    }
    let mut bytes = HEADER + car - foot;
    let mut seen = HashSet::new();
    for w in ws {
        let lo = number(w, "lo_slot")?;
        let hi = number(w, "hi_slot")?;
        let a = number(w, "start")?;
        let b = number(w, "end")?;
        if lo < first
            || hi >= first + SLOTS
            || lo >= hi
            || hi - lo > 64
            || a < HEADER
            || b > foot
            || a >= b
            || b - a > 20 << 20
            || !seen.insert((a, b))
        {
            return Err("invalid or duplicate dynamic window".into());
        }
        bytes += b - a;
    }
    let count = ws.len() + 2;
    if bytes != number(&doc, "body_bytes")?
        || bytes > 256 << 20
        || count as u64 != number(&doc, "range_count")?
    {
        return Err("capture inventory differs".into());
    }
    Ok((String::from_utf8(input)?, bytes, count))
}
fn main() -> Result<()> {
    let mut command = env::args_os().skip(1).peekable();
    let owned;
    let dynamic_epoch = command
        .peek()
        .and_then(|arg| arg.to_str())
        .and_then(|arg| arg.strip_prefix("--epoch"))
        .filter(|digits| digits.len() == 3 && digits.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|digits| digits.parse::<u64>().ok())
        .filter(|epoch| REVIEWED_EPOCHS.contains(epoch));
    let (profile, body_bytes, range_count) = if let Some(epoch) = dynamic_epoch {
        command.next();
        let path = command.next().ok_or("usage: repair --epoch{268..301} PLAN PLAN_SHA256 PINNED_INDEX_DIR CAPTURE_DIR CAPTURE_MANIFEST_SHA256 EMPTY_OUTPUT_DIR")?;
        let digest = command.next().ok_or("missing reviewed plan SHA-256")?;
        let (plan, bytes, count) =
            reviewed(epoch, Path::new(&path), digest.to_str().ok_or("SHA-256")?)?;
        owned = plan;
        (owned.as_str(), bytes, count)
    } else if command.next_if(|s| s == "--epoch267").is_some() {
        (
            include_str!("../horizon267-slot-input/repair-windows.json"),
            99_707_283,
            32,
        )
    } else {
        (PROFILE, 205_729_899, 139)
    };
    let args: Vec<_> = command.collect();
    if args.len() != 4 {
        return Err(
            "usage: repair [--epoch267 | --epoch{268..301} PLAN PLAN_SHA256] PINNED_INDEX_DIR CAPTURE_DIR CAPTURE_MANIFEST_SHA256 EMPTY_OUTPUT_DIR"
                .into(),
        );
    }
    let source = Path::new(&args[0]);
    let captured = Path::new(&args[1]);
    let out = Path::new(&args[3]);
    let expected = args[2].to_str().ok_or("invalid SHA")?;
    if out.read_dir()?.next().is_some() {
        return Err("output directory must be empty".into());
    }
    let plan: Value = serde_json::from_str(profile)?;
    let manifest_path = captured.join("RESULT.json");
    let size = fs::symlink_metadata(&manifest_path)?.len();
    if size > 256_000 {
        return Err("oversized transfer manifest".into());
    }
    let m = read(&manifest_path, size)?;
    if sha(&m) != expected {
        return Err("capture manifest differs".into());
    }
    let manifest: Value = serde_json::from_slice(&m)?;
    if text(&manifest, "plan_sha256")? != text(&plan, "capture_plan_sha256")?
        || number(&manifest, "body_bytes")? != body_bytes
    {
        return Err("incomplete capture".into());
    }
    let mut entries = BTreeMap::new();
    for v in manifest["source_ranges"]
        .as_array()
        .ok_or("source ranges")?
    {
        if entries.insert(text(v, "name")?.to_owned(), v).is_some() {
            return Err("duplicate capture".into());
        }
    }
    if entries.len() != range_count {
        return Err(format!("expected {range_count} distinct captured ranges").into());
    }
    let cap = Captures {
        root: captured,
        entries,
    };
    let mut bad = false;
    for e in plan["epochs"].as_array().ok_or("epochs")? {
        match run_epoch(e, source, &cap, out) {
            Ok(report) => println!("{report}"),
            Err(err) => {
                eprintln!("epoch {}: {err}", e["epoch"]);
                bad = true;
            }
        }
    }
    if bad {
        return Err("incomplete qualification".into());
    }
    Ok(())
}
