//! Incremental bounded response storage. Reject excess bytes before allocation.
//! This library alone does not bound SDK internals or qualify a service cap.
use anyhow::{Context, Result, ensure};

#[derive(Debug)]
pub struct BoundedBody {
    bytes: Vec<u8>,
    maximum: usize,
    expected: Option<usize>,
}

impl BoundedBody {
    pub fn new(maximum: u64, expected: Option<u64>) -> Result<Self> {
        let maximum = usize::try_from(maximum).context("body limit exceeds address space")?;
        let expected = expected
            .map(usize::try_from)
            .transpose()
            .context("body length exceeds address space")?;
        ensure!(
            expected.is_none_or(|n| n <= maximum),
            "advertised body length exceeds limit"
        );
        Ok(Self {
            bytes: Vec::new(),
            maximum,
            expected,
        })
    }

    pub fn append(&mut self, chunk: &[u8]) -> Result<()> {
        let ceiling = self.expected.unwrap_or(self.maximum);
        let remaining = ceiling
            .checked_sub(self.bytes.len())
            .context("body collector invariant violated")?;
        ensure!(chunk.len() <= remaining, "response body exceeds limit");
        self.bytes
            .try_reserve_exact(chunk.len())
            .context("bounded response allocation failed")?;
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        ensure!(
            self.expected.is_none_or(|n| n == self.bytes.len()),
            "response body was truncated"
        );
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_length_accepts_arbitrary_chunk_boundaries() {
        let mut body = BoundedBody::new(8, Some(8)).unwrap();
        for bytes in [b"ab".as_slice(), b"", b"cde", b"fgh"] {
            body.append(bytes).unwrap();
        }
        assert_eq!(body.finish().unwrap(), b"abcdefgh");
    }

    #[test]
    fn unknown_length_accepts_up_to_the_limit() {
        let mut body = BoundedBody::new(3, None).unwrap();
        body.append(b"ab").unwrap();
        body.append(b"c").unwrap();
        assert_eq!(body.finish().unwrap(), b"abc");
    }

    #[test]
    fn oversized_chunk_is_rejected_without_reserving_or_copying() {
        let mut body = BoundedBody::new(512, None).unwrap();
        let oversized = vec![1; 1024 * 1024];
        assert!(body.append(&oversized).is_err());
        assert_eq!(body.bytes.len(), 0);
        assert_eq!(body.bytes.capacity(), 0);
    }

    #[test]
    fn cumulative_excess_preserves_the_previous_bounded_buffer() {
        let mut body = BoundedBody::new(4, None).unwrap();
        body.append(b"abc").unwrap();
        let before_capacity = body.bytes.capacity();
        assert!(body.append(b"de").is_err());
        assert_eq!(body.bytes, b"abc");
        assert_eq!(body.bytes.capacity(), before_capacity);
    }

    #[test]
    fn advertised_length_cannot_exceed_the_limit() {
        assert!(BoundedBody::new(512, Some(513)).is_err());
        assert!(BoundedBody::new(0, Some(u64::MAX)).is_err());
    }

    #[test]
    fn misleading_advertised_length_rejects_before_allocation() {
        let mut body = BoundedBody::new(512, Some(2)).unwrap();
        assert!(body.append(b"abc").is_err());
        assert_eq!(body.bytes.capacity(), 0);
    }

    #[test]
    fn truncation_never_returns_an_incomplete_body() {
        let mut body = BoundedBody::new(512, Some(5)).unwrap();
        body.append(b"abcd").unwrap();
        assert!(body.finish().is_err());
    }

    #[test]
    fn zero_length_requires_no_allocation() {
        let mut body = BoundedBody::new(0, Some(0)).unwrap();
        body.append(b"").unwrap();
        assert!(body.append(b"x").is_err());
        assert_eq!(body.bytes.capacity(), 0);
        assert!(body.finish().unwrap().is_empty());
    }

    #[test]
    fn maximum_limit_does_not_preallocate_from_untrusted_metadata() {
        let mut body = BoundedBody::new(u64::MAX, Some(u64::MAX)).unwrap();
        assert_eq!(body.bytes.capacity(), 0);
        body.append(b"a").unwrap();
        assert_eq!(body.bytes.len(), 1);
        assert!(body.finish().is_err());
    }
}
