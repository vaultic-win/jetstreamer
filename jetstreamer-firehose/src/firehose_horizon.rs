//! Horizon-native firehose: streams a `.jet` archive (the horizon
//! container) instead of an Old Faithful CAR, driving the zero-copy
//! [`SlotVisitor`](jetstreamer_horizon::archive::SlotVisitor) callbacks.
//!
//! This is the network-seekable counterpart to [`firehose`](crate::firehose).
//! Bytes are fetched **async** over the same backends the rest of the crate
//! uses: `rseek::Seekable` for HTTP range requests and `tokio::fs` for local
//! files. Slot-frame **decode** stays synchronous and zero-copy in
//! [`jetstreamer_horizon`]'s
//! [`BucketDecoder`](jetstreamer_horizon::archive::BucketDecoder). The two are bridged per
//! worker by a small bounded channel: an async fetch task pulls the worker's
//! bucket range over its own connection and hands raw bytes to a blocking
//! decode task. The channel's depth gives one-bucket prefetch, so network
//! latency overlaps CPU decode.
//!
//! `.jet` buckets are independently compressed frames, so a slot lives in exactly
//! one bucket. A slot-range worker may share a boundary bucket with a neighbor;
//! each visitor receives only callbacks for its own half-open slot range.
use std::collections::HashMap;
use std::io;
use std::ops::Range;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use futures_util::future::try_join_all;
use reqwest::{Client, Url};
use rseek::Seekable;

mod pinned;
pub use pinned::PinnedArchives;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, BufReader, ReadBuf};

use tokio::sync::{Mutex, OnceCell, Semaphore};

use jetstreamer_horizon::account_updates::AccountUpdateView;
use jetstreamer_horizon::archive::{
    ArchiveFormatError, BlockNotification, BucketDecoder, BucketIndexEntry, Consumption,
    EntryRecord, EpochMeta, FOOTER_LEN, FileHeader, Footer, MAX_FILE_HEADER_BYTES, SlotKind,
    SlotVisitor, bucket_containing, parse_bucket_index, parse_file_header,
    validate_bucket_index_layout, validate_footer_layout,
};
use jetstreamer_horizon::transactions::Transaction;

use crate::epochs::{EpochStream, epoch_to_slot_range, slot_to_epoch};
use crate::firehose::generate_subranges;
use crate::node_reader::Len;

/// Bytes fetched from the file front to cover every header accepted by the
/// shared archive parser: magic + the longest length prefix + the bounded
/// header payload. Real headers are only a few dozen bytes; the larger bound
/// keeps local and network readers' acceptance rules identical.
const HEADER_PREFIX: usize = MAX_FILE_HEADER_BYTES as usize + 32;
/// Buckets a fetch task may run ahead of its decoder (prefetch depth).
const PREFETCH_DEPTH: usize = 2;

/// Where `.jet` files live. Each epoch resolves to `epoch-<N>.jet`.
#[derive(Clone)]
pub enum JetSource {
    /// One epoch's `.jet` bytes held entirely in memory (e.g. preloaded by a
    /// benchmark to take disk I/O out of the measurement). Serves only its
    /// own epoch; workers share the buffer via cheap `Arc` clones.
    ///
    /// `Arc<Vec<u8>>` rather than `Arc<[u8]>` deliberately: converting a
    /// `Vec` to `Arc<[u8]>` copies the whole buffer (the slice must live
    /// inline with the Arc header), which for a ~400 GB epoch means two
    /// full-size allocations alive at once, causing an immediate OOM. Wrapping the
    /// Vec is copy-free.
    Memory {
        /// The epoch these bytes are the archive for.
        epoch: u64,
        /// The complete `.jet` file contents.
        bytes: std::sync::Arc<Vec<u8>>,
    },
    /// A local directory holding `epoch-<N>.jet`, read with `tokio::fs`.
    LocalDir(PathBuf),
    /// A base URL under which `epoch-<N>.jet` is served, seeked with
    /// `rseek` HTTP range requests. Must end with `/` to join correctly.
    HttpBase(Url),
    /// HTTPS range reads with an explicit authenticated ETag and length per epoch.
    HttpPinned(PinnedArchives),
}

impl JetSource {
    /// A local directory of `epoch-<N>.jet` files.
    pub fn local(dir: impl Into<PathBuf>) -> Self {
        Self::LocalDir(dir.into())
    }

    /// A base URL serving `epoch-<N>.jet`. A trailing `/` is appended if
    /// missing so the per-epoch path joins as a sub-path, not a sibling.
    pub fn http(base_url: &str) -> Result<Self, HorizonFirehoseError> {
        let normalized = if base_url.ends_with('/') {
            base_url.to_string()
        } else {
            format!("{base_url}/")
        };
        let url = Url::parse(&normalized).map_err(|e| HorizonFirehoseError::Url(e.to_string()))?;
        Ok(Self::HttpBase(url))
    }

    /// One epoch's complete `.jet` contents held in memory. Serves only
    /// `epoch`; requesting any other epoch errors. Takes the `Vec` by value
    /// and never copies it. Callers hand over buffers the size of a whole
    /// epoch file.
    pub fn in_memory(epoch: u64, bytes: Vec<u8>) -> Self {
        Self::Memory {
            epoch,
            bytes: std::sync::Arc::new(bytes),
        }
    }
}

impl std::fmt::Debug for JetSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory { epoch, bytes } => f
                .debug_struct("Memory")
                .field("epoch", epoch)
                .field("len", &bytes.len())
                .finish(),
            Self::LocalDir(dir) => f.debug_tuple("LocalDir").field(dir).finish(),
            Self::HttpPinned(_) => f.write_str("HttpPinned"),
            Self::HttpBase(url) => f.debug_tuple("HttpBase").field(url).finish(),
        }
    }
}

/// Errors from the horizon firehose.
#[derive(Debug)]
pub enum HorizonFirehoseError {
    /// Network or filesystem I/O error fetching `.jet` bytes.
    Io(io::Error),
    /// The fetched bytes did not decode as a valid horizon archive.
    Archive(ArchiveFormatError),
    /// The archive header names a different epoch than the requested file.
    EpochMismatch {
        /// Epoch requested from the source.
        requested: u64,
        /// Epoch encoded in the archive header.
        archive: u64,
    },
    /// The `.jet` URL could not be built from the base + epoch.
    Url(String),
    /// The file is shorter than a footer and is not a Horizon archive.
    Truncated,
    /// A worker task panicked or was cancelled.
    Join(String),
}

impl std::fmt::Display for HorizonFirehoseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Archive(e) => write!(f, "archive decode error: {e}"),
            Self::EpochMismatch { requested, archive } => write!(
                f,
                "archive epoch mismatch: requested epoch {requested}, header names epoch {archive}"
            ),
            Self::Url(e) => write!(f, "invalid .jet url: {e}"),
            Self::Truncated => write!(f, "file shorter than a horizon footer"),
            Self::Join(e) => write!(f, "worker task failed: {e}"),
        }
    }
}

impl std::error::Error for HorizonFirehoseError {}

impl From<io::Error> for HorizonFirehoseError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ArchiveFormatError> for HorizonFirehoseError {
    fn from(e: ArchiveFormatError) -> Self {
        Self::Archive(e)
    }
}

/// Streams the `.jet` for `epoch` (restricted to `slot_range`) across
/// `threads` workers, driving a fresh [`SlotVisitor`] per worker built by
/// `make_visitor`. Returns the per-worker visitors in worker order, for the
/// caller to finalize (flush). Worker `t` owns a contiguous bucket range, so
/// every slot is visited exactly once across the workers.
pub async fn firehose_horizon<F, V>(
    threads: usize,
    src: JetSource,
    epoch: u64,
    slot_range: Range<u64>,
    make_visitor: F,
) -> Result<Vec<V>, HorizonFirehoseError>
where
    F: Fn(usize) -> V,
    V: SlotVisitor + Send + 'static,
{
    let threads = threads.max(1);
    let mut src = src;
    if let JetSource::HttpPinned(pins) = &mut src {
        pins.set_worker_count(threads);
    }
    let client = horizon_client(&src)?;
    let observed = HttpIdentities::default();
    let layout = load_layout(&src, epoch, &client, &observed).await?;
    if layout.index.is_empty() || slot_range.is_empty() {
        return Ok((0..threads).map(&make_visitor).collect());
    }
    let buckets = layout.buckets(&slot_range);
    let parts = partition_buckets(buckets.start, buckets.end - 1, threads);
    try_join_all(parts.into_iter().enumerate().map(|(id, chunk)| {
        stream_chunk(
            &src,
            &client,
            &layout,
            slot_range.clone(),
            chunk,
            make_visitor(id),
        )
    }))
    .await
}

/// Streams a half-open slot range across epoch archives. Workers own the standard
/// contiguous slot partitions and keep the same visitor across each epoch boundary.
/// Results are returned in worker ID order, including idle workers for short ranges.
pub async fn firehose_horizon_range<F, V>(
    threads: usize,
    src: JetSource,
    slots: Range<u64>,
    make_visitor: F,
) -> Result<Vec<V>, HorizonFirehoseError>
where
    F: Fn(usize) -> V + Send + Sync,
    V: SlotVisitor + Send + 'static,
{
    let threads = threads.max(1);
    let mut src = src;
    if let JetSource::HttpPinned(pins) = &mut src {
        pins.set_worker_count(threads);
    }
    if slots.start > slots.end {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "reversed Horizon slot range").into(),
        );
    }
    let ranges = generate_subranges(&slots, threads as u64);
    let client = horizon_client(&src)?;
    let cache = Mutex::new(HashMap::<u64, Weak<OnceCell<EpochLayout>>>::new());
    let observed = HttpIdentities::default();
    let resident_limit = match &src {
        JetSource::HttpPinned(pins) => pins.max_active_partitions,
        _ => None,
    };
    let permits = resident_limit
        .filter(|limit| limit.get() < threads)
        .map(|limit| Semaphore::new(limit.get().min(Semaphore::MAX_PERMITS)));
    let tasks = ranges.into_iter().enumerate().map(|(id, range)| {
        log::debug!(target: "jetstreamer_horizon_range",
            "horizon_worker id={id} first_slot={} end_slot_exclusive={}", range.start, range.end);
        let (src, client, cache, observed) = (&src, &client, &cache, &observed);
        let (permits, make_visitor) = (&permits, &make_visitor);
        async move {
            // Acquire before opening the archive or allocating decoder buffers.
            // try_join_all still returns visitors in partition order.
            let _permit = match permits {
                Some(permits) => Some(
                    permits
                        .acquire()
                        .await
                        .expect("partition limit remains open"),
                ),
                None => None,
            };
            let mut visitor = make_visitor(id);
            let mut start = range.start;
            while start < range.end {
                let epoch = slot_to_epoch(start);
                let end = if epoch == slot_to_epoch(range.end - 1) {
                    range.end
                } else {
                    epoch_to_slot_range(epoch).1 + 1
                };
                let cell = {
                    let mut epochs = cache.lock().await;
                    epochs.retain(|_, weak| weak.strong_count() > 0);
                    match epochs.get(&epoch).and_then(Weak::upgrade) {
                        Some(cell) => cell,
                        None => {
                            let cell = Arc::new(OnceCell::new());
                            epochs.insert(epoch, Arc::downgrade(&cell));
                            cell
                        }
                    }
                };
                let layout = cell
                    .get_or_try_init(|| load_layout(src, epoch, client, observed))
                    .await?;
                let header_end = layout
                    .header
                    .slot_start
                    .checked_add(layout.header.slot_count)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "archive slot range overflows")
                    })?;
                if layout.index.is_empty() || start < layout.header.slot_start || end > header_end {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("epoch {epoch} archive does not cover slots {start}..{end}"),
                    )
                    .into());
                }
                let slots = start..end;
                let buckets = layout.buckets(&slots);
                visitor = stream_chunk(src, client, layout, slots, buckets, visitor).await?;
                start = end;
            }
            Ok(visitor)
        }
    });
    try_join_all(tasks).await
}

fn horizon_client(src: &JetSource) -> Result<Client, HorizonFirehoseError> {
    Ok(if matches!(src, JetSource::HttpPinned(_)) {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(io::Error::other)?
    } else {
        Client::new()
    })
}

struct EpochLayout {
    http_recovery: Option<Arc<pinned::HttpRecovery>>,
    header: FileHeader,
    index: Arc<[BucketIndexEntry]>,
}

impl EpochLayout {
    fn buckets(&self, slots: &Range<u64>) -> Range<usize> {
        let lo = bucket_containing(&self.header, &self.index, slots.start);
        let hi = bucket_containing(&self.header, &self.index, slots.end - 1);
        lo..hi + 1
    }
}

// Layouts are evicted between visitors. Keep the much smaller per-epoch
// validator through the invocation so later visitors cannot join a new object.
type HttpIdentity = Arc<OnceCell<Option<Arc<pinned::HttpRecovery>>>>;
type HttpIdentities = Mutex<HashMap<u64, HttpIdentity>>;

async fn load_layout(
    src: &JetSource,
    epoch: u64,
    client: &Client,
    identities: &HttpIdentities,
) -> Result<EpochLayout, HorizonFirehoseError> {
    let http_recovery = if let JetSource::HttpBase(base) = src {
        let cell = identities.lock().await.entry(epoch).or_default().clone();
        cell.get_or_try_init(|| pinned::HttpRecovery::discover(client, base, epoch))
            .await?
            .clone()
    } else {
        None
    };
    let mut probe = open_jet_stream(src, epoch, client, None, http_recovery.clone()).await?;
    let total_len = probe.len();
    if total_len < FOOTER_LEN as u64 {
        return Err(HorizonFirehoseError::Truncated);
    }
    let prefix_len = (HEADER_PREFIX as u64).min(total_len) as usize;
    let prefix = read_range(&mut probe, 0, prefix_len).await?;
    let (header, header_end) = parse_file_header(&prefix)?;
    if header.epoch != epoch {
        return Err(HorizonFirehoseError::EpochMismatch {
            requested: epoch,
            archive: header.epoch,
        });
    }
    let footer_bytes = read_range(&mut probe, total_len - FOOTER_LEN as u64, FOOTER_LEN).await?;
    let footer_arr: [u8; FOOTER_LEN] = footer_bytes
        .as_slice()
        .try_into()
        .map_err(|_| HorizonFirehoseError::Truncated)?;
    let footer = Footer::from_bytes(&footer_arr)?;
    validate_footer_layout(total_len, header_end as u64, &footer)?;
    let index_bytes =
        read_range(&mut probe, footer.index_offset, footer.index_len as usize).await?;
    let index: Arc<[BucketIndexEntry]> = parse_bucket_index(&index_bytes, &footer)?.into();
    validate_bucket_index_layout(&header, header_end as u64, footer.index_offset, &index)?;
    if let RangeReader::Pinned(reader) = &probe {
        reader.log_verified_layout();
    }
    Ok(EpochLayout {
        header,
        index,
        http_recovery,
    })
}

async fn stream_chunk<V: SlotVisitor + Send + 'static>(
    src: &JetSource,
    client: &Client,
    layout: &EpochLayout,
    slots: Range<u64>,
    chunk: Range<usize>,
    mut visitor: V,
) -> Result<V, HorizonFirehoseError> {
    if chunk.is_empty() {
        return Ok(visitor);
    }
    let epoch = layout.header.epoch;
    let index = &layout.index;
    let decoder_header = layout.header.clone();
    let start = slots.start;
    let end = slots.end;
    let (tx, rx) = tokio::sync::mpsc::channel::<(BucketIndexEntry, RawBucket)>(PREFETCH_DEPTH);
    // Drained fetch buffers travel back to the fetcher for reuse, so the
    // stream path allocates a bounded handful of buffers per worker for
    // the whole run instead of one ~bucket-sized Vec per bucket. Sized so
    // a return can never block: at most PREFETCH_DEPTH buffers sit in
    // `tx` plus one in each task.
    let (recycle_tx, mut recycle_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(PREFETCH_DEPTH + 2);

    // Wide pinned runs have one reusable compressed bucket per decoder. It
    // returns immediately after decompression, so network I/O still overlaps
    // slot decoding without multiplying each worker's largest buffer by four.
    let compact = matches!(src, JetSource::HttpPinned(pins) if pins.compact());
    if compact {
        recycle_tx
            .try_send(Vec::new())
            .expect("new recycle channel");
    }
    let fetch = async move {
        // In-memory source: hand the decoder shared slices of the one
        // preloaded buffer, with zero per-bucket buffers and zero copies.
        if let JetSource::Memory { bytes, .. } = src {
            for b in chunk {
                let e = index[b];
                let bucket_start = e.offset as usize;
                let bucket_end = bucket_start + e.len as usize;
                if bucket_end > bytes.len() {
                    return Err(HorizonFirehoseError::Truncated);
                }
                let shared = RawBucket::Shared {
                    bytes: bytes.clone(),
                    range: bucket_start..bucket_end,
                };
                if tx.send((e, shared)).await.is_err() {
                    break; // decoder finished early or errored
                }
            }
            return Ok(());
        }

        // The validated index has contiguous, non-overflowing bucket extents.
        let first = index[chunk.start];
        let last = index[chunk.end - 1];
        let span = first.offset..last.offset + last.len;
        let mut s =
            open_jet_stream(src, epoch, client, Some(span), layout.http_recovery.clone()).await?;
        for b in chunk {
            let e = index[b];
            let mut buf = if compact {
                let Some(returned) = recycle_rx.recv().await else {
                    break;
                };
                returned
            } else {
                recycle_rx.try_recv().unwrap_or_default()
            };
            read_range_into(&mut s, e.offset, e.len as usize, &mut buf).await?;
            if tx.send((e, RawBucket::Owned(buf))).await.is_err() {
                break; // decoder finished early (reached end slot) or errored
            }
        }
        Ok::<(), HorizonFirehoseError>(())
    };
    let decode = tokio::task::spawn_blocking(move || {
        let mut rx = rx;
        let mut decoder = if compact {
            BucketDecoder::for_file_header_with_diff_capacity(&decoder_header, 0)?
        } else {
            BucketDecoder::for_file_header(&decoder_header)?
        };
        decoder.verify_chain = false;
        // Honor the visitor's declared consumption: unconsumed
        // account-update data is skipped, not reconstructed.
        decoder.set_consumption(visitor.consumption());
        'outer: while let Some((entry, raw)) = rx.blocking_recv() {
            decoder.load_indexed_bucket_bytes(raw.as_slice(), entry)?;
            // The decoder copied/decompressed what it needs; return the
            // buffer to the fetcher (capacity ensures this never blocks;
            // a closed channel just means the fetcher already finished).
            if let RawBucket::Owned(buf) = raw {
                let _ = recycle_tx.try_send(buf);
            }
            let mut bounded = Bounded {
                inner: &mut visitor,
                end,
                current_slot: None,
            };
            while decoder.slots_remaining() > 0 {
                decoder.decode_slot_frame(start, &mut bounded)?;
                if decoder.last_decoded_slot().is_some_and(|s| s >= end - 1) {
                    break 'outer; // past the requested range; stop this worker
                }
            }
        }
        Ok::<V, HorizonFirehoseError>(visitor)
    });
    // Dropping the fetch future closes the channel even if a neighboring worker
    // fails. The blocking decoder can then finish without an orphaned producer.
    let (fetched, decoded) = tokio::join!(fetch, decode);
    fetched?;
    decoded.map_err(|e| HorizonFirehoseError::Join(e.to_string()))?
}

/// Visitor wrapper that drops slots at or beyond `end` (the exclusive upper
/// bound of the requested range), so a worker's final bucket does not emit
/// slots past the range.
struct Bounded<'a, V: SlotVisitor> {
    inner: &'a mut V,
    end: u64,
    current_slot: Option<u64>,
}

impl<V: SlotVisitor> SlotVisitor for Bounded<'_, V> {
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        self.current_slot = Some(slot);
        if slot < self.end {
            self.inner.on_slot_start(slot, kind);
        }
    }
    fn on_epoch(&mut self, meta: &EpochMeta) {
        if self.current_slot.is_some_and(|slot| slot < self.end) {
            self.inner.on_epoch(meta);
        }
    }
    fn on_pre_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        if slot < self.end {
            self.inner.on_pre_account_update(slot, update);
        }
    }
    fn on_transaction(&mut self, slot: u64, tx_index: u32, tx: &Transaction) {
        if slot < self.end {
            self.inner.on_transaction(slot, tx_index, tx);
        }
    }
    fn on_post_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        if slot < self.end {
            self.inner.on_post_account_update(slot, update);
        }
    }
    fn on_block(&mut self, notification: &BlockNotification, entries: &[EntryRecord]) {
        if notification.slot() < self.end {
            self.inner.on_block(notification, entries);
        }
    }
    fn consumption(&self) -> Consumption {
        self.inner.consumption()
    }
}

/// Splits the inclusive bucket range `[start, end_inclusive]` into `threads`
/// contiguous chunks (trailing chunks are empty when there are fewer buckets
/// than workers).
fn partition_buckets(start: usize, end_inclusive: usize, threads: usize) -> Vec<Range<usize>> {
    let total = end_inclusive + 1 - start;
    let per = total / threads;
    let rem = total % threads;
    let mut out = Vec::with_capacity(threads);
    let mut s = start;
    for i in 0..threads {
        let n = per + usize::from(i < rem);
        out.push(s..s + n);
        s += n;
    }
    out
}

/// Opens an async, seekable stream over `epoch`'s `.jet` from `src`.
async fn open_jet_stream(
    src: &JetSource,
    epoch: u64,
    client: &Client,
    worker_span: Option<Range<u64>>,
    recovery: Option<Arc<pinned::HttpRecovery>>,
) -> Result<RangeReader, HorizonFirehoseError> {
    let stream = match src {
        JetSource::HttpPinned(inventory) => {
            return Ok(RangeReader::Pinned(inventory.open(
                epoch,
                client,
                worker_span,
            )?));
        }
        JetSource::Memory { epoch: held, bytes } => {
            if *held != epoch {
                return Err(HorizonFirehoseError::Url(format!(
                    "in-memory source holds epoch {held}, not {epoch}"
                )));
            }
            EpochStream::new(MemJetReader {
                bytes: bytes.clone(),
                pos: 0,
            })
        }
        JetSource::LocalDir(dir) => {
            let path = dir.join(format!("epoch-{epoch}.jet"));
            let file = tokio::fs::File::open(&path).await?;
            let len = file.metadata().await?.len();
            EpochStream::new(LocalJetReader { file, len })
        }
        JetSource::HttpBase(base) => {
            let url = base
                .join(&format!("epoch-{epoch}.jet"))
                .map_err(|e| HorizonFirehoseError::Url(e.to_string()))?;
            let client = client.clone();
            let observed = recovery.clone();
            let mut seekable = Seekable::new(move || match &observed {
                Some(identity) => identity.request(),
                None => client.get(url.clone()),
            })
            .await;
            if let Some(identity) = &recovery {
                if seekable.file_size.is_some_and(|len| len != identity.len()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ordinary archive length changed",
                    )
                    .into());
                }
                seekable.file_size = Some(identity.len());
            }
            EpochStream::new(BufReader::with_capacity(1 << 20, seekable))
        }
    };
    Ok(RangeReader::Seekable {
        stream,
        position: 0,
        recovery,
    })
}

/// One bucket's raw bytes on their way from a fetcher to its decoder:
/// either a fetched buffer the decoder recycles afterwards or, for
/// the in-memory source, a shared slice of the single preloaded file
/// buffer (no per-bucket buffer, no copy).
enum RawBucket {
    Owned(Vec<u8>),
    Shared {
        bytes: Arc<Vec<u8>>,
        range: Range<usize>,
    },
}

impl RawBucket {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(buf) => buf,
            Self::Shared { bytes, range } => &bytes[range.clone()],
        }
    }
}

enum RangeReader {
    Seekable {
        stream: EpochStream,
        position: u64,
        recovery: Option<Arc<pinned::HttpRecovery>>,
    },
    Pinned(pinned::Reader),
}
impl RangeReader {
    fn len(&self) -> u64 {
        match self {
            Self::Seekable { stream, .. } => stream.len(),
            Self::Pinned(stream) => stream.len(),
        }
    }
}

async fn read_range(stream: &mut RangeReader, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    read_range_into(stream, offset, len, &mut buf).await?;
    Ok(buf)
}

async fn read_range_into(
    stream: &mut RangeReader,
    offset: u64,
    len: usize,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    try_resize_read_buffer(buf, len)?;
    match stream {
        RangeReader::Pinned(reader) => reader.read_at(offset, buf).await?,
        RangeReader::Seekable {
            stream,
            position,
            recovery,
        } => {
            if *position != offset {
                stream.seek(io::SeekFrom::Start(offset)).await?;
            }
            let end = offset
                .checked_add(len as u64)
                .ok_or_else(|| io::Error::other("range overflow"))?;
            if let Some(identity) = recovery {
                let mut filled = 0;
                while filled < len {
                    match stream.read(&mut buf[filled..]).await {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) if resumable_http_error(&e) => break,
                        Err(e) => return Err(e),
                    }
                }
                if filled < len {
                    // The decoder receives a bucket only after read_range_into succeeds.
                    // BufReader can read ahead, so resume at bytes delivered to this
                    // buffer, then reset rseek's buffered position for the next bucket.
                    identity
                        .resume(offset + filled as u64, &mut buf[filled..])
                        .await?;
                    stream.seek(io::SeekFrom::Start(end)).await?;
                }
            } else {
                stream.read_exact(buf).await?;
            }
            *position = end;
        }
    }
    Ok(())
}

fn resumable_http_error(e: &io::Error) -> bool {
    if let Some(http) = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<reqwest::Error>())
    {
        return http.status().map_or_else(
            || http.is_connect() || http.is_timeout() || http.is_body() || http.is_decode(),
            |code| matches!(code.as_u16(), 408 | 429 | 500 | 502 | 503 | 504),
        );
    }
    // rseek 0.4.1 erases the reqwest body error to io::ErrorKind::Other.
    matches!(
        e.kind(),
        io::ErrorKind::Other
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

fn try_resize_read_buffer(buf: &mut Vec<u8>, len: usize) -> io::Result<()> {
    buf.clear();
    buf.try_reserve_exact(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "could not allocate horizon range-read buffer",
        )
    })?;
    buf.resize(len, 0);
    Ok(())
}

/// A local `.jet` file as an `AsyncRead + AsyncSeek + Len` reader, so it
/// shares the [`EpochStream`] code path with the network backends.
struct LocalJetReader {
    file: tokio::fs::File,
    len: u64,
}

impl AsyncRead for LocalJetReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_read(cx, buf)
    }
}

impl AsyncSeek for LocalJetReader {
    fn start_seek(self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        Pin::new(&mut self.get_mut().file).start_seek(position)
    }
    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.get_mut().file).poll_complete(cx)
    }
}

impl Len for LocalJetReader {
    fn len(&self) -> u64 {
        self.len
    }
}

/// A fully in-memory `.jet` as an `AsyncRead + AsyncSeek + Len` reader.
/// every read is a memcpy from the shared buffer, always `Ready`.
struct MemJetReader {
    bytes: std::sync::Arc<Vec<u8>>,
    pos: u64,
}

impl AsyncRead for MemJetReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let start = (this.pos as usize).min(this.bytes.len());
        let n = buf.remaining().min(this.bytes.len() - start);
        buf.put_slice(&this.bytes[start..start + n]);
        this.pos += n as u64;
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for MemJetReader {
    fn start_seek(self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        let this = self.get_mut();
        let new = match position {
            io::SeekFrom::Start(off) => off as i128,
            io::SeekFrom::End(off) => this.bytes.len() as i128 + off as i128,
            io::SeekFrom::Current(off) => this.pos as i128 + off as i128,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        this.pos = new as u64;
        Ok(())
    }
    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.get_mut().pos))
    }
}

impl Len for MemJetReader {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetstreamer_horizon::archive::{ArchiveWriter, ArchiveWriterConfig};

    /// Counts skipped/block slots seen, to verify the driver visited them all.
    #[derive(Default)]
    struct SlotCounter {
        skipped: u64,
        blocks: u64,
    }

    impl SlotVisitor for SlotCounter {
        fn on_block(&mut self, notification: &BlockNotification, _entries: &[EntryRecord]) {
            match notification {
                BlockNotification::Skipped(_) => self.skipped += 1,
                BlockNotification::Block(_) => self.blocks += 1,
            }
        }
    }

    #[tokio::test]
    async fn ordinary_http_reconnects_at_the_first_undelivered_byte() {
        use std::time::Duration;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        const BODY: &[u8] = b"0123456789abcdefghijklmnopqrstuv";
        for wrong_etag in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base: Url = format!("http://{}/", listener.local_addr().unwrap())
                .parse()
                .unwrap();
            let server = tokio::spawn(async move {
                let steps = [(0, 0), (0, 0), (0, 31), (6, 13), (14, 31)];
                let count = if wrong_etag { 4 } else { steps.len() };
                for (i, &(start, end)) in steps[..count].iter().enumerate() {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut lines = BufReader::new(&mut stream).lines();
                    assert_eq!(
                        lines.next_line().await.unwrap().unwrap(),
                        "GET /epoch-5.jet HTTP/1.1"
                    );
                    let mut range = None;
                    let mut condition = None;
                    while let Some(line) = lines.next_line().await.unwrap() {
                        if line.is_empty() {
                            break;
                        }
                        let (k, v) = line.split_once(": ").unwrap();
                        if k.eq_ignore_ascii_case("range") {
                            range = Some(v.to_owned());
                        }
                        if k.eq_ignore_ascii_case("if-match") {
                            condition = Some(v.to_owned());
                        }
                    }
                    assert_eq!(range, Some(format!("bytes={start}-{end}")));
                    assert_eq!(condition.as_deref(), (i != 0).then_some("\"original\""));
                    let tag = if i == 3 && wrong_etag {
                        "changed"
                    } else {
                        "original"
                    };
                    let head = format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/32\r\nETag: \"{tag}\"\r\nConnection: close\r\n\r\n",
                        end - start + 1
                    );
                    stream.write_all(head.as_bytes()).await.unwrap();
                    let sent_end = if i == 2 { 6 } else { end + 1 };
                    stream.write_all(&BODY[start..sent_end]).await.unwrap();
                    stream.flush().await.unwrap();
                    if i == 2 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    stream.shutdown().await.unwrap();
                }
            });
            let client = Client::builder().no_proxy().build().unwrap();
            tokio::time::timeout(Duration::from_secs(8), async {
                let identity = pinned::HttpRecovery::discover(&client, &base, 5)
                    .await
                    .unwrap()
                    .unwrap();
                let mut stream =
                    open_jet_stream(&JetSource::HttpBase(base), 5, &client, None, Some(identity))
                        .await
                        .unwrap();
                let first = read_range(&mut stream, 0, 14).await;
                if wrong_etag {
                    assert!(first.unwrap_err().to_string().contains("identity mismatch"));
                } else {
                    assert_eq!(first.unwrap(), BODY[..14]);
                    assert_eq!(read_range(&mut stream, 14, 18).await.unwrap(), BODY[14..]);
                }
                server.await.unwrap();
            })
            .await
            .expect("bounded ordinary HTTP fixture");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn range_workers_keep_visitors_across_epoch_boundary() {
        struct Slots {
            worker: usize,
            seen: Vec<u64>,
        }
        impl SlotVisitor for Slots {
            fn on_block(&mut self, block: &BlockNotification, _: &[EntryRecord]) {
                self.seen.push(block.slot());
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let boundary = epoch_to_slot_range(1).0;
        for (epoch, range) in [(0, boundary - 96..boundary), (1, boundary..boundary + 96)] {
            let mut writer = ArchiveWriter::new(
                std::io::Cursor::new(Vec::new()),
                epoch,
                range.start,
                range.end - range.start,
                ArchiveWriterConfig::default(),
            )
            .unwrap();
            for slot in range {
                writer.write_skipped_slot(slot).unwrap();
            }
            let (sink, _) = writer.finish().unwrap();
            std::fs::write(
                dir.path().join(format!("epoch-{epoch}.jet")),
                sink.into_inner(),
            )
            .unwrap();
        }

        let range = boundary - 60..boundary + 60;
        let create = |worker| Slots {
            worker,
            seen: Vec::new(),
        };
        let visitors =
            firehose_horizon_range(3, JetSource::local(dir.path()), range.clone(), create)
                .await
                .unwrap();
        let expected = generate_subranges(&range, 3);
        assert_eq!(visitors.len(), expected.len());
        for (id, (visitor, slots)) in visitors.into_iter().zip(expected).enumerate() {
            assert_eq!(visitor.worker, id);
            assert_eq!(visitor.seen, slots.collect::<Vec<_>>());
        }

        let short = firehose_horizon_range(
            3,
            JetSource::local(dir.path()),
            boundary..boundary + 1,
            create,
        )
        .await
        .unwrap();
        assert_eq!(short[0].seen, vec![boundary]);
        assert!(short[1..].iter().all(|worker| worker.seen.is_empty()));
        assert!(
            firehose_horizon_range(
                2,
                JetSource::local(dir.path()),
                boundary - 8..boundary + 97,
                create
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn bounded_gates_epoch_by_enclosing_frame_not_metadata() {
        #[derive(Default)]
        struct EpochCounter(u64);

        impl SlotVisitor for EpochCounter {
            fn on_epoch(&mut self, _meta: &EpochMeta) {
                self.0 += 1;
            }
        }

        let mut counter = EpochCounter::default();
        let mut meta = EpochMeta::new_boxed();
        let mut bounded = Bounded {
            inner: &mut counter,
            end: 200,
            current_slot: None,
        };

        // Malformed metadata claims this out-of-range frame belongs inside
        // the request. The enclosing frame slot is authoritative, so drop it.
        bounded.on_slot_start(200, SlotKind::Block);
        meta.first_block_slot = 199;
        bounded.on_epoch(&meta);
        assert_eq!(bounded.inner.0, 0);

        // Conversely, malformed metadata must not hide a notification whose
        // enclosing frame is inside the request.
        bounded.on_slot_start(199, SlotKind::Block);
        meta.first_block_slot = 200;
        bounded.on_epoch(&meta);
        assert_eq!(bounded.inner.0, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_jet_rejects_mismatched_header_epoch() {
        let archive_epoch = 7u64;
        let requested_epoch = 8u64;
        let slot = 1_000u64;
        let mut writer = ArchiveWriter::new(
            std::io::Cursor::new(Vec::new()),
            archive_epoch,
            slot,
            1,
            ArchiveWriterConfig::default(),
        )
        .unwrap();
        writer.write_skipped_slot(slot).unwrap();
        let (sink, _stats) = writer.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(format!("epoch-{requested_epoch}.jet")),
            sink.into_inner(),
        )
        .unwrap();

        let error = firehose_horizon(
            1,
            JetSource::local(dir.path()),
            requested_epoch,
            slot..slot + 1,
            |_tid| SlotCounter::default(),
        )
        .await
        .err()
        .expect("mismatched archive header epoch must fail");
        assert!(matches!(
            error,
            HorizonFirehoseError::EpochMismatch {
                requested,
                archive,
            } if requested == requested_epoch && archive == archive_epoch
        ));
    }

    #[test]
    fn range_buffer_capacity_overflow_is_reported() {
        let mut buffer = Vec::new();
        let error = try_resize_read_buffer(&mut buffer, usize::MAX).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(buffer.is_empty());
    }

    /// End-to-end over the local backend: build a tiny `.jet`, run it through
    /// the full async driver (framing, bucket partition, prefetch, blocking
    /// decode, and join), and confirm every slot is visited exactly once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_jet_drives_every_slot_once() {
        let epoch = 7u64;
        let slot_start = 1_000u64;
        let n = 300u64; // 3 buckets at the default 128 slots/bucket

        // A skipped-only archive is a fully valid `.jet` and needs no
        // transaction construction.
        let mut writer = ArchiveWriter::new(
            std::io::Cursor::new(Vec::new()),
            epoch,
            slot_start,
            n,
            ArchiveWriterConfig::default(),
        )
        .unwrap();
        for i in 0..n {
            writer.write_skipped_slot(slot_start + i).unwrap();
        }
        let (sink, _stats) = writer.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(format!("epoch-{epoch}.jet")),
            sink.into_inner(),
        )
        .unwrap();

        // 4 workers over 3 buckets exercises a trailing empty worker too.
        let visitors = firehose_horizon(
            4,
            JetSource::local(dir.path()),
            epoch,
            slot_start..slot_start + n,
            |_tid| SlotCounter::default(),
        )
        .await
        .unwrap();

        assert_eq!(visitors.len(), 4);
        let skipped: u64 = visitors.iter().map(|v| v.skipped).sum();
        let blocks: u64 = visitors.iter().map(|v| v.blocks).sum();
        assert_eq!(skipped, n, "every skipped slot visited exactly once");
        assert_eq!(blocks, 0);
    }

    /// A sub-range that starts and ends mid-bucket must visit only the
    /// requested slots (lower bound via the decoder, upper bound via `Bounded`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_jet_respects_sub_range() {
        let epoch = 8u64;
        let slot_start = 0u64;
        let n = 300u64;

        let mut writer = ArchiveWriter::new(
            std::io::Cursor::new(Vec::new()),
            epoch,
            slot_start,
            n,
            ArchiveWriterConfig::default(),
        )
        .unwrap();
        for i in 0..n {
            writer.write_skipped_slot(slot_start + i).unwrap();
        }
        let (sink, _stats) = writer.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(format!("epoch-{epoch}.jet")),
            sink.into_inner(),
        )
        .unwrap();

        // 50..200 spans bucket boundaries on both ends (buckets are 128 wide).
        let visitors = firehose_horizon(3, JetSource::local(dir.path()), epoch, 50..200, |_tid| {
            SlotCounter::default()
        })
        .await
        .unwrap();

        let skipped: u64 = visitors.iter().map(|v| v.skipped).sum();
        assert_eq!(skipped, 150, "only slots [50, 200) visited");
    }

    /// A visitor that declares it does not consume account-update data must
    /// get elided (empty) data slices with metadata and counts intact. The
    /// declaration travels from visitor to `Bounded` to decoder through the full
    /// async driver.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_jet_elides_update_data_when_declined() {
        use jetstreamer_horizon::account_updates::AccountUpdateView;
        use jetstreamer_horizon::block_metas::BlockMeta;
        use solana_address::Address;
        use solana_hash::Hash;

        let epoch = 9u64;
        let slot_start = 0u64;
        let n = 10u64;

        let mut writer = ArchiveWriter::new(
            std::io::Cursor::new(Vec::new()),
            epoch,
            slot_start,
            n,
            ArchiveWriterConfig::default(),
        )
        .unwrap();
        let owner = Address::new_from_array([7u8; 32]);
        for i in 0..n {
            let slot = slot_start + i;
            writer.begin_slot(slot).unwrap();
            writer
                .write_orphan_update(&AccountUpdateView {
                    pubkey: Address::new_from_array([11u8; 32]),
                    lamports: i,
                    owner,
                    executable: false,
                    rent_epoch: u64::MAX,
                    write_version: i,
                    data: &[0xAB; 64],
                })
                .unwrap();
            let mut meta = BlockMeta::new_boxed();
            meta.slot = slot;
            meta.parent_slot = slot.saturating_sub(1);
            meta.blockhash = Hash::new_from_array([i as u8 + 1; 32]);
            writer.end_slot(&meta, &[]).unwrap();
        }
        let (sink, _stats) = writer.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(format!("epoch-{epoch}.jet")),
            sink.into_inner(),
        )
        .unwrap();

        /// Tallies orphan updates and their data bytes; declines data.
        #[derive(Default)]
        struct DecliningTally {
            updates: u64,
            data_bytes: u64,
        }
        impl SlotVisitor for DecliningTally {
            fn on_block(&mut self, notification: &BlockNotification, _entries: &[EntryRecord]) {
                if let BlockNotification::Block(meta) = notification {
                    for (_, d) in meta.pre_updates.iter().chain(meta.post_updates.iter()) {
                        self.updates += 1;
                        self.data_bytes += d.len() as u64;
                    }
                }
            }
            fn consumption(&self) -> Consumption {
                Consumption::all().without_account_update_data()
            }
        }

        let visitors = firehose_horizon(
            2,
            JetSource::local(dir.path()),
            epoch,
            slot_start..slot_start + n,
            |_tid| DecliningTally::default(),
        )
        .await
        .unwrap();

        let updates: u64 = visitors.iter().map(|v| v.updates).sum();
        let data_bytes: u64 = visitors.iter().map(|v| v.data_bytes).sum();
        assert_eq!(updates, n, "every update's metadata still arrives");
        assert_eq!(data_bytes, 0, "declined update data decodes empty");
    }

    /// The in-memory source must drive the exact same decode as the local
    /// backend (and reject a mismatched epoch).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn memory_source_matches_local() {
        let epoch = 11u64;
        let slot_start = 0u64;
        let n = 300u64;

        let mut writer = ArchiveWriter::new(
            std::io::Cursor::new(Vec::new()),
            epoch,
            slot_start,
            n,
            ArchiveWriterConfig::default(),
        )
        .unwrap();
        for i in 0..n {
            writer.write_skipped_slot(slot_start + i).unwrap();
        }
        let (sink, _stats) = writer.finish().unwrap();
        let bytes = sink.into_inner();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(format!("epoch-{epoch}.jet")), &bytes).unwrap();

        let mem_src = JetSource::in_memory(epoch, bytes);
        for src in [JetSource::local(dir.path()), mem_src.clone()] {
            let visitors = firehose_horizon(3, src, epoch, slot_start..slot_start + n, |_tid| {
                SlotCounter::default()
            })
            .await
            .unwrap();
            let skipped: u64 = visitors.iter().map(|v| v.skipped).sum();
            assert_eq!(skipped, n, "every slot visited exactly once");
        }

        // A wrong epoch produces an error instead of silent garbage.
        let err = firehose_horizon(2, mem_src, epoch + 1, 0..1, |_tid| SlotCounter::default())
            .await
            .err();
        assert!(err.is_some(), "mismatched epoch must be rejected");
    }
}
