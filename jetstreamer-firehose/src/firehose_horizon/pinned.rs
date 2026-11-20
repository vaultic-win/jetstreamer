//! Anonymous HTTP range reads bound to the authenticated archive inventory.
use std::{collections::BTreeMap, io, path::Path, sync::Arc, time::Duration};

use reqwest::{Client, StatusCode, Url, header};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub(super) struct Object {
    epoch: u64,
    key: String,
    etag: String,
    bytes: u64,
}

/// The immutable public origin and canonical archive identities of one audit.
#[derive(Clone, Debug)]
pub struct PinnedArchives {
    base: Url,
    objects: Arc<BTreeMap<u64, Object>>,
}

impl PinnedArchives {
    /// Loads a manifest containing an `objects` array with epoch, key, bytes and
    /// strong quoted ETag for every archive to be consumed.
    pub fn load(base: &str, path: &Path) -> io::Result<Self> {
        #[derive(Deserialize)]
        struct Manifest {
            objects: Vec<Object>,
        }
        let base =
            Url::parse(&format!("{}/", base.trim_end_matches('/'))).map_err(io::Error::other)?;
        if base.scheme() != "https"
            || base.host().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(io::Error::other(
                "public playback requires an anonymous HTTPS base URL",
            ));
        }
        let file = std::fs::File::open(path)?;
        if file.metadata()?.len() > 8 << 20 {
            return Err(io::Error::other("archive inventory exceeds 8 MiB"));
        }
        let manifest: Manifest = serde_json::from_reader(file)?;
        let mut objects = BTreeMap::new();
        for object in manifest.objects {
            let etag = object.etag.as_bytes();
            if object.key != format!("epoch-{}.jet", object.epoch)
                || object.bytes == 0
                || etag.len() < 3
                || etag.first() != Some(&b'"')
                || etag.last() != Some(&b'"')
                || !etag[1..etag.len() - 1]
                    .iter()
                    .all(|b| b.is_ascii_graphic() && *b != b'"')
                || objects.insert(object.epoch, object).is_some()
            {
                return Err(io::Error::other("invalid or duplicate archive identity"));
            }
        }
        Ok(Self {
            base,
            objects: Arc::new(objects),
        })
    }

    pub(super) fn open(&self, epoch: u64, client: &Client, read_ahead: bool) -> io::Result<Reader> {
        let object = self
            .objects
            .get(&epoch)
            .ok_or_else(|| io::Error::other("epoch absent from pinned inventory"))?;
        Ok(Reader {
            url: self.base.join(&object.key).map_err(io::Error::other)?,
            object: object.clone(),
            client: client.clone(),
            read_ahead,
            start: 0,
            cache: Vec::new(),
        })
    }
}

pub(super) struct Reader {
    url: Url,
    object: Object,
    client: Client,
    read_ahead: bool,
    start: u64,
    cache: Vec<u8>,
}

impl Reader {
    pub fn len(&self) -> u64 {
        self.object.bytes
    }

    async fn fill(&mut self, start: u64, needed: u64) -> io::Result<()> {
        // Coalesce neighboring small buckets; retrying a connection never needs
        // a local archive and never changes the object identity.
        const CHUNK: u64 = 8 << 20;
        let count = (self.len() - start).min(if self.read_ahead {
            CHUNK
        } else {
            needed.min(CHUNK)
        });
        let end = start + count - 1;
        let range = format!("bytes={start}-{end}");
        let expected = format!("bytes {start}-{end}/{}", self.len());
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
            }
            let response = self
                .client
                .get(self.url.clone())
                .header(header::IF_MATCH, &self.object.etag)
                .header(header::ACCEPT_ENCODING, "identity")
                .header(header::RANGE, &range)
                .timeout(Duration::from_secs(180))
                .send()
                .await;
            let mut response = match response {
                Err(_) if attempt < 2 => continue,
                Err(error) => {
                    return Err(io::Error::other(format!(
                        "public archive transport: {error}"
                    )));
                }
                Ok(response)
                    if attempt < 2
                        && (response.status().is_server_error()
                            || response.status() == StatusCode::TOO_MANY_REQUESTS) =>
                {
                    continue;
                }
                Ok(response) => response,
            };
            let headers = response.headers();
            if response.url() != &self.url
                || response.status() != StatusCode::PARTIAL_CONTENT
                || headers.get(header::ETAG).and_then(|v| v.to_str().ok())
                    != Some(self.object.etag.as_str())
                || headers
                    .get(header::CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                    != Some(expected.as_str())
                || response.content_length() != Some(count)
            {
                return Err(io::Error::other(format!(
                    "public archive HTTP status or range identity mismatch: {} at {range}",
                    response.status()
                )));
            }
            self.cache.clear();
            loop {
                let chunk = match response.chunk().await {
                    Err(_) if attempt < 2 => break,
                    Err(error) => {
                        return Err(io::Error::other(format!(
                            "public archive transport: {error}"
                        )));
                    }
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => break,
                };
                if chunk.len() > count as usize - self.cache.len() {
                    return Err(io::Error::other("oversized public range"));
                }
                self.cache.extend_from_slice(&chunk);
            }
            if self.cache.len() == count as usize {
                self.start = start;
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "public archive transport: incomplete range after retries",
        ))
    }

    pub async fn read_at(&mut self, mut offset: u64, mut dest: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(dest.len() as u64)
            .is_none_or(|end| end > self.len())
        {
            return Err(io::Error::other(
                "requested range exceeds pinned archive length",
            ));
        }
        while !dest.is_empty() {
            if !(self.start..self.start + self.cache.len() as u64).contains(&offset) {
                self.fill(offset, dest.len() as u64).await?;
            }
            let cached = &self.cache[(offset - self.start) as usize..];
            let n = cached.len().min(dest.len());
            dest[..n].copy_from_slice(&cached[..n]);
            offset += n as u64;
            dest = &mut dest[n..];
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    fn serve(response: &'static str) -> (Reader, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut headers = String::new();
            let mut reader = BufReader::new(&socket);
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line);
            }
            let headers = headers.to_ascii_lowercase();
            assert!(headers.starts_with("get /epoch-0.jet http/1.1\r\n"));
            assert!(headers.contains("range: bytes=0-7\r\n"));
            assert!(headers.contains("if-match: \"original\"\r\n"));
            assert!(!headers.contains("authorization:"));
            socket.write_all(response.as_bytes()).unwrap();
        });
        (
            Reader {
                url: Url::parse(&format!("http://{address}/epoch-0.jet")).unwrap(),
                object: Object {
                    epoch: 0,
                    key: "epoch-0.jet".into(),
                    etag: "\"original\"".into(),
                    bytes: 8,
                },
                client: Client::new(),
                read_ahead: true,
                start: 0,
                cache: Vec::new(),
            },
            handle,
        )
    }

    #[tokio::test]
    async fn verifies_headers_and_coalesces_sequential_bucket_reads() {
        let (mut reader, server) = serve(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 0-7/8\r\nETag: \"original\"\r\n\r\nabcdefgh",
        );
        let mut first = [0; 3];
        let mut second = [0; 5];
        reader.read_at(0, &mut first).await.unwrap();
        reader.read_at(3, &mut second).await.unwrap();
        assert_eq!(&first, b"abc");
        assert_eq!(&second, b"defgh");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn rejects_unconditional_or_wrong_generation_and_bounds() {
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nETag: \"original\"\r\n\r\nabcdefgh",
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 0-7/8\r\nETag: \"replacement\"\r\n\r\nabcdefgh",
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 0-7/9\r\nETag: \"original\"\r\n\r\nabcdefgh",
        ] {
            let (mut reader, server) = serve(response);
            let mut bytes = [0; 8];
            assert!(reader.read_at(0, &mut bytes).await.is_err());
            assert_eq!(bytes, [0; 8]);
            server.join().unwrap();
        }
    }
}
