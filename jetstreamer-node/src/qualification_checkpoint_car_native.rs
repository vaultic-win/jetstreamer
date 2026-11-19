//! Test-only HTTP mirror for the sealed native transcript. Uses the ordinary
//! firehose CAR reader, slot-index lookup and callback dispatcher unchanged.
use super::*;
use serde_cbor::Value::{self, Array, Bytes, Integer, Map, Null, Text};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Mutex, atomic::Ordering},
    thread::JoinHandle,
    time::Duration,
};

fn varint(mut value: usize, output: &mut Vec<u8>) {
    while value >= 128 {
        output.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    output.push(value as u8);
}

fn node(value: Value) -> (cid::Cid, Vec<u8>) {
    let data = serde_cbor::to_vec(&value).unwrap();
    let hash = cid::multihash::Multihash::<64>::wrap(0x12, &Sha256::digest(&data)).unwrap();
    let cid = cid::Cid::new_v1(0x71, hash);
    let mut body = cid.to_bytes();
    body.extend(data);
    let mut framed = Vec::new();
    varint(body.len(), &mut framed);
    framed.extend(body);
    (cid, framed)
}

fn link(cid: cid::Cid) -> Value {
    let mut bytes = vec![0];
    bytes.extend(cid.to_bytes());
    Bytes(bytes)
}

fn frame(bytes: Vec<u8>) -> Value {
    Array(vec![Integer(6), Null, Null, Null, Bytes(bytes)])
}

fn car_and_index(bootstrap: &Checkpoint, prefix_entries: &[EntryRequest]) -> (Vec<u8>, Vec<u8>) {
    let prefix = prefix_entries.first().unwrap();
    assert_eq!(bootstrap.slot + 1, prefix.slot);
    assert_eq!(prefix.entry_index, 0);
    let mut payload = Vec::new();
    let mut entries = Vec::new();
    let mut transaction_index = 0;
    for (entry_index, entry) in prefix_entries.iter().enumerate() {
        assert_eq!(entry.slot, prefix.slot);
        assert_eq!(entry.entry_index, entry_index as u64);
        let mut transactions = Vec::new();
        for tx in &entry.transactions {
            let (cid, bytes) = node(Array(vec![
                Integer(0),
                frame(tx.clone()),
                frame(vec![]),
                Integer(entry.slot.into()),
                Integer(transaction_index),
            ]));
            transaction_index += 1;
            transactions.push(link(cid));
            payload.extend(bytes);
        }
        let (cid, bytes) = node(Array(vec![
            Integer(1),
            Integer(entry.num_hashes.into()),
            Bytes(entry.hash.clone()),
            Array(transactions),
        ]));
        entries.push(link(cid));
        payload.extend(bytes);
    }
    let (rewards, bytes) = node(Array(vec![
        Integer(5),
        Integer(prefix.slot.into()),
        frame(vec![]),
    ]));
    payload.extend(bytes);
    let (block, bytes) = node(Array(vec![
        Integer(2),
        Integer(prefix.slot.into()),
        Array(vec![]),
        Array(entries),
        Array(vec![Integer(bootstrap.slot.into()), Integer(0), Null]),
        link(rewards),
    ]));
    payload.extend(bytes);
    let header = serde_cbor::to_vec(&Map(BTreeMap::from([
        (Text("roots".into()), Array(vec![link(block)])),
        (Text("version".into()), Integer(1)),
    ])))
    .unwrap();
    let mut car = Vec::new();
    varint(header.len(), &mut car);
    car.extend(header);
    let offset = car.len() as u64;
    let length = u32::try_from(payload.len()).unwrap();
    car.extend(payload);
    // A complete correctly sized index with only the synthetic slot present.
    // This is isolated under a loopback base URL, never a mainnet index override.
    let mut index = vec![0; 432_000 * 12];
    let row = (prefix.slot % 432_000) as usize * 12;
    index[row..row + 8].copy_from_slice(&offset.to_le_bytes());
    index[row + 8..row + 12].copy_from_slice(&length.to_le_bytes());
    (car, index)
}

struct Mirror {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    requests: Arc<Mutex<Vec<String>>>,
    base: reqwest::Url,
}

impl Mirror {
    fn start(bootstrap: &Checkpoint, prefix_entries: &[EntryRequest]) -> Self {
        let base =
            reqwest::Url::parse(&std::env::var("JETSTREAMER_HTTP_BASE_URL").unwrap()).unwrap();
        assert_eq!(base.scheme(), "http");
        assert_eq!(base.host_str(), Some("127.0.0.1"));
        assert_eq!(base.path(), "/");
        assert_eq!(
            std::env::var("JETSTREAMER_COMPACT_INDEX_BASE_URL").unwrap(),
            base.as_str()
        );
        assert_eq!(
            std::env::var("JETSTREAMER_NETWORK").unwrap(),
            "synthetic-pressure"
        );
        assert!(std::env::var_os("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST").is_none());
        let listener = TcpListener::bind(("127.0.0.1", base.port().unwrap())).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (car, index) = car_and_index(bootstrap, prefix_entries);
        let epoch = prefix_entries[0].slot / 432_000;
        eprintln!(
            "synthetic HTTP CAR sha256={:x} bytes={} slot_index_sha256={:x}",
            Sha256::digest(&car),
            car.len(),
            Sha256::digest(&index)
        );
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread = std::thread::spawn({
            let stop = stop.clone();
            let requests = requests.clone();
            move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => serve(stream, &car, &index, &requests, epoch),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        Err(error) => panic!("fixture listener: {error}"),
                    }
                }
            }
        });
        Self {
            stop,
            thread: Some(thread),
            requests,
            base,
        }
    }
}

impl Drop for Mirror {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}

fn serve(
    mut stream: TcpStream,
    car: &[u8],
    index: &[u8],
    requests: &Mutex<Vec<String>>,
    epoch: u64,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = Vec::new();
    let mut byte = [0];
    while !request.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        request.push(byte[0]);
        assert!(request.len() < 16_384);
    }
    let request = String::from_utf8(request).unwrap();
    let mut lines = request.split("\r\n");
    let first = lines.next().unwrap();
    requests.lock().unwrap().push(first.to_owned());
    let parts: Vec<_> = first.split_whitespace().collect();
    assert!(matches!(parts[0], "GET" | "HEAD"));
    let body = match parts[1] {
        path if path == format!("/{epoch}/epoch-{epoch}.car") => car,
        path if path == format!("/{epoch}/epoch-{epoch}-slot-ranges.raw") => index,
        other => panic!("unexpected fixture URL: {other}"),
    };
    let range = lines.find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case("range").then(|| value.trim())
    });
    let (start, end, status) = match range {
        Some(value) => {
            let (start, end) = value
                .strip_prefix("bytes=")
                .unwrap()
                .split_once('-')
                .unwrap();
            let start: usize = start.parse().unwrap();
            let end = if end.is_empty() {
                body.len() - 1
            } else {
                end.parse::<usize>().unwrap().min(body.len() - 1)
            };
            assert!(start <= end && end < body.len());
            (start, end, "206 Partial Content")
        }
        None => (0, body.len() - 1, "200 OK"),
    };
    let mut header = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n",
        end - start + 1
    );
    if range.is_some() {
        header.push_str(&format!(
            "Content-Range: bytes {start}-{end}/{}\r\n",
            body.len()
        ));
    }
    header.push_str("\r\n");
    let result = stream.write_all(header.as_bytes()).and_then(|_| {
        if parts[0] == "GET" {
            stream.write_all(&body[start..=end])
        } else {
            Ok(())
        }
    });
    if let Err(error) = result {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ),
            "fixture response: {error}"
        );
    }
}

/// Request pressure after the real decoder emits the parent edge, before its
/// transaction/entry/metadata callbacks. Completion remains the real firehose's
/// successful whole-batch acknowledgement.
struct PressureParent {
    inner: Arc<crate::BankBlockParentNotifier>,
    pressure: bool,
    completed: Arc<Mutex<Option<jetstreamer_firehose::source_quiescence::CompletedSourceBlock>>>,
}
impl jetstreamer_firehose::firehose::BlockParentNotifier for PressureParent {
    fn notify_block_parent(&self, parent: u64, slot: u64) {
        self.inner.notify_block_parent(parent, slot);
        if self.pressure {
            assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
        }
    }
    fn source_block_completed(
        &self,
        block: jetstreamer_firehose::source_quiescence::CompletedSourceBlock,
    ) -> jetstreamer_firehose::source_quiescence::SourceBlockAction {
        assert!(self.completed.lock().unwrap().replace(block).is_none());
        self.inner.source_block_completed(block)
    }
}

pub(super) fn deliver(
    bootstrap: &Checkpoint,
    prefix_entries: &[EntryRequest],
    producers: &crate::ReplayReadyEntryProducers,
    shutdown: Arc<AtomicBool>,
) -> jetstreamer_firehose::source_quiescence::CompletedSourceBlock {
    deliver_mode(bootstrap, prefix_entries, producers, shutdown, true)
}

pub(super) fn deliver_complete(
    bootstrap: &Checkpoint,
    entries: &[EntryRequest],
    producers: &crate::ReplayReadyEntryProducers,
    shutdown: Arc<AtomicBool>,
) -> jetstreamer_firehose::source_quiescence::CompletedSourceBlock {
    deliver_mode(bootstrap, entries, producers, shutdown, false)
}

fn deliver_mode(
    bootstrap: &Checkpoint,
    prefix_entries: &[EntryRequest],
    producers: &crate::ReplayReadyEntryProducers,
    shutdown: Arc<AtomicBool>,
    pressure: bool,
) -> jetstreamer_firehose::source_quiescence::CompletedSourceBlock {
    use jetstreamer_firehose::firehose::{
        FirehoseError, firehose_geyser_with_notifiers_and_block_parent,
    };
    let prefix = prefix_entries.first().unwrap();
    let mirror = Mirror::start(bootstrap, prefix_entries);
    let (confirmed_sender, _confirmed_receiver) = crossbeam_channel::unbounded();
    let completed = Arc::new(Mutex::new(None));
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
    );
    let result = firehose_geyser_with_notifiers_and_block_parent(
        rt,
        prefix.slot..prefix.slot + if pressure { 2 } else { 1 },
        producers.geyser_notifiers(),
        Some(Arc::new(PressureParent {
            inner: producers.block_parent.clone(),
            pressure,
            completed: completed.clone(),
        })),
        Some((
            bootstrap.slot,
            Hash::new_from_array(bootstrap.last_blockhash.clone().try_into().unwrap()),
        )),
        confirmed_sender,
        &mirror.base,
        &reqwest::Client::new(),
        shutdown,
        async { Ok(()) },
        1,
        true,
        Some(1 << 20),
    );
    let block = completed
        .lock()
        .unwrap()
        .expect("complete decoded source block");
    match result {
        Err((FirehoseError::SourceQuiesced(selected), slot)) if pressure => {
            assert_eq!(slot, block.slot);
            assert_eq!(selected, block);
        }
        Ok(()) if !pressure => {}
        other => panic!("unexpected real source result, pressure={pressure}: {other:?}"),
    };
    let requests = mirror.requests.lock().unwrap();
    let epoch = prefix.slot / 432_000;
    assert!(
        requests
            .iter()
            .any(|r| r.contains(&format!("/{epoch}/epoch-{epoch}.car")))
    );
    // At the epoch's first slot the production reader can begin at the CAR
    // header; it needs the slot index only when seeking into an epoch.
    if prefix.slot % 432_000 != 0 {
        assert!(
            requests
                .iter()
                .any(|r| r.contains(&format!("/{epoch}/epoch-{epoch}-slot-ranges.raw")))
        );
    }
    eprintln!(
        "real HTTP CAR source completed decoded block: pressure={pressure} requests={requests:?}"
    );
    drop(requests);
    block
}
