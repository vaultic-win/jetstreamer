//! Pinned read-only channel for the exact Original225 private custody object.

use serde::Deserialize;
use std::{
    fs,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};

const SOCKET: &str = "/run/jetstreamer-horizon-epoch226-holding-v1/source.sock";
const ETAG: &str = "\"4cd6d98c0ad728ddd15a128b17300724-3958\"";
const CHUNK: u64 = 4 << 20;
const CONTEXT_BYTES: &[u8] = b"original225/pinned-range-v1";
const RANGE_ATTEMPTS: usize = 3;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeldObject {
    schema: String,
    socket: PathBuf,
    socket_device: u64,
    socket_inode: u64,
    broker_pid: i32,
    length: u64,
    etag: String,
    sha256: String,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl HeldObject {
    pub(super) fn accept(self, length: u64, sha256: &str) -> io::Result<Self> {
        if self.schema != "foundation-epoch226-pinned-original225-broker-v1"
            || self.socket != Path::new(SOCKET)
            || self.broker_pid <= 1
            || self.length != length
            || self.sha256 != sha256
            || self.etag != ETAG
        {
            return Err(invalid(
                "wrong Original225 socket or pinned custody identity",
            ));
        }
        self.check_socket()?;
        Ok(self)
    }

    fn check_socket(&self) -> io::Result<()> {
        let directory = self
            .socket
            .parent()
            .ok_or_else(|| invalid("missing socket parent"))?;
        let dir = fs::symlink_metadata(directory)?;
        let socket = fs::symlink_metadata(&self.socket)?;
        if directory.canonicalize()? != directory
            || !dir.is_dir()
            || dir.uid() != 0
            || dir.mode() & 0o022 != 0
            || !socket.file_type().is_socket()
            || socket.uid() != 0
            || socket.mode() & 0o002 != 0
            || (socket.dev(), socket.ino()) != (self.socket_device, self.socket_inode)
        {
            return Err(invalid("Original225 broker socket custody changed"));
        }
        Ok(())
    }

    fn connect(&self) -> io::Result<UnixStream> {
        self.check_socket()?;
        let mut stream = UnixStream::connect(&self.socket)?;
        self.check_socket()?;
        let mut peer = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut size,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if size as usize != std::mem::size_of_val(&peer)
            || peer.uid != 0
            || peer.pid != self.broker_pid
        {
            return Err(invalid("wrong authenticated Original225 peer"));
        }
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(Duration::from_secs(15)))?;
        let label = format!("{}\n{}\n{}\n", self.length, self.etag, self.sha256);
        let mut expected = CONTEXT_BYTES.to_vec();
        expected.push(b'\n');
        expected.extend_from_slice(label.as_bytes());
        let mut got = vec![0; expected.len()];
        stream.read_exact(&mut got)?;
        if got != expected {
            return Err(invalid(
                "Original225 broker returned a different pinned object",
            ));
        }
        Ok(stream)
    }

    pub(super) fn open(&self) -> io::Result<impl Read + Seek + '_> {
        Ok(PinnedReader::new(self.connect()?, self.length, || {
            self.connect()
        }))
    }

    pub(super) fn recheck(&self) -> io::Result<()> {
        self.open().map(drop)
    }
}

struct PinnedReader<F> {
    stream: UnixStream,
    connect: F,
    length: u64,
    position: u64,
    buffer_start: u64,
    buffer: Vec<u8>,
}

fn interrupted(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::NotConnected
            | io::ErrorKind::Interrupted
    )
}

impl<F: Fn() -> io::Result<UnixStream>> PinnedReader<F> {
    fn new(stream: UnixStream, length: u64, connect: F) -> Self {
        Self {
            stream,
            connect,
            length,
            position: 0,
            buffer_start: 0,
            buffer: Vec::new(),
        }
    }

    fn request_range(&mut self, start: u64, length: u64) -> io::Result<Vec<u8>> {
        let mut request = [0u8; 16];
        request[..8].copy_from_slice(&start.to_be_bytes());
        request[8..].copy_from_slice(&length.to_be_bytes());
        let mut buffer = vec![0; length as usize];
        for attempt in 1..=RANGE_ATTEMPTS {
            let result = (|| {
                if attempt > 1 {
                    self.stream = (self.connect)()?;
                }
                self.stream.write_all(&request)?;
                self.stream.read_exact(&mut buffer)
            })();
            match result {
                Ok(()) => return Ok(buffer),
                Err(error) => {
                    let _ = self.stream.shutdown(std::net::Shutdown::Both);
                    if attempt == RANGE_ATTEMPTS || !interrupted(&error) {
                        return Err(error);
                    }
                    log::warn!(
                        "Original225 range at byte {start} interrupted on attempt {attempt}: {error}"
                    );
                }
            }
        }
        unreachable!("the final range attempt returns")
    }
}

impl<F: Fn() -> io::Result<UnixStream>> Read for PinnedReader<F> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        if self.position < self.buffer_start
            || self.position - self.buffer_start >= self.buffer.len() as u64
        {
            let start = self.position / CHUNK * CHUNK;
            let length = (self.length - start).min(CHUNK);
            let buffer = self.request_range(start, length)?;
            self.buffer_start = start;
            self.buffer = buffer;
        }
        let offset = (self.position - self.buffer_start) as usize;
        let count = bytes.len().min(self.buffer.len() - offset);
        bytes[..count].copy_from_slice(&self.buffer[offset..][..count]);
        self.position += count as u64;
        Ok(count)
    }
}

#[cfg(test)]
pub(crate) fn fixture_reader(bytes: Vec<u8>) -> impl Read + Seek {
    let length = bytes.len() as u64;
    let (stream, mut server) = UnixStream::pair().unwrap();
    std::thread::spawn(move || {
        let mut request = [0u8; 16];
        while server.read_exact(&mut request).is_ok() {
            let start = u64::from_be_bytes(request[..8].try_into().unwrap()) as usize;
            let length = u64::from_be_bytes(request[8..].try_into().unwrap()) as usize;
            if server.write_all(&bytes[start..start + length]).is_err() {
                break;
            }
        }
    });
    PinnedReader::new(stream, length, || Err(invalid("fixture stream closed")))
}

impl<F> Seek for PinnedReader<F> {
    fn seek(&mut self, offset: SeekFrom) -> io::Result<u64> {
        self.position = match offset {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => self.length.checked_add_signed(delta),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Original225 seek overflows"))?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn reconnect_requests_the_same_range_and_discards_incomplete_bytes() {
        let (client, mut initial) = UnixStream::pair().unwrap();
        let (replacement, mut resumed) = UnixStream::pair().unwrap();
        let replacement = RefCell::new(Some(replacement));
        let expected = [CHUNK.to_be_bytes(), 10_u64.to_be_bytes()].concat();
        let server = std::thread::spawn(move || {
            let mut request = [0; 16];
            initial.read_exact(&mut request).unwrap();
            assert_eq!(request.as_slice(), expected);
            initial.write_all(b"xx").unwrap();
            drop(initial);
            resumed.read_exact(&mut request).unwrap();
            assert_eq!(request.as_slice(), expected);
            resumed.write_all(b"abcdefghij").unwrap();
        });
        let mut reader = PinnedReader::new(client, CHUNK + 10, || {
            replacement
                .borrow_mut()
                .take()
                .ok_or_else(|| invalid("unexpected additional reconnect"))
        });
        reader.seek(SeekFrom::Start(CHUNK + 2)).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, b"cdefghij");
        assert!(replacement.borrow().is_none());
        server.join().unwrap();
    }

    #[test]
    fn different_broker_identity_terminates_range_recovery() {
        let (client, server) = UnixStream::pair().unwrap();
        drop(server);
        let mut reader = PinnedReader::new(client, 3, || Err(invalid("broker identity changed")));
        let mut output = [0; 3];
        let err = reader.read_exact(&mut output).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(reader.stream_position().unwrap(), 0);
        assert_eq!(output, [0; 3]);
    }
}
