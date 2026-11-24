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

    pub(super) fn open(&self) -> io::Result<PinnedReader> {
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
        Ok(PinnedReader {
            stream,
            length: self.length,
            position: 0,
            buffer_start: 0,
            buffer: Vec::new(),
        })
    }

    pub(super) fn recheck(&self) -> io::Result<()> {
        self.open().map(drop)
    }
}

pub(super) struct PinnedReader {
    stream: UnixStream,
    length: u64,
    position: u64,
    buffer_start: u64,
    buffer: Vec<u8>,
}

impl Read for PinnedReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        if self.position < self.buffer_start
            || self.position - self.buffer_start >= self.buffer.len() as u64
        {
            let start = self.position / CHUNK * CHUNK;
            let length = (self.length - start).min(CHUNK);
            let mut request = [0u8; 16];
            request[..8].copy_from_slice(&start.to_be_bytes());
            request[8..].copy_from_slice(&length.to_be_bytes());
            let mut buffer = vec![0; length as usize];
            if let Err(error) = self
                .stream
                .write_all(&request)
                .and_then(|()| self.stream.read_exact(&mut buffer))
            {
                let _ = self.stream.shutdown(std::net::Shutdown::Both);
                return Err(error);
            }
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
    PinnedReader {
        stream,
        length,
        position: 0,
        buffer_start: 0,
        buffer: Vec::new(),
    }
}

impl Seek for PinnedReader {
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
