//! Bound independent read-only inventory lookups without changing epoch order.
use anyhow::{Context, Result};
use futures_util::{StreamExt, TryStreamExt, stream};
use std::future::Future;

const CONCURRENCY: usize = 8;

pub(super) async fn collect<T, F, Fut>(epochs: &[u64], lookup: F) -> Result<Vec<T>>
where
    F: Fn(u64) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    stream::iter(epochs.iter().copied())
        .map(|epoch| {
            let read = lookup(epoch);
            async move {
                read.await
                    .with_context(|| format!("epoch {epoch} R2 inventory failed"))
            }
        })
        .buffered(CONCURRENCY)
        .try_collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn independent_reads_overlap_with_a_bound_and_keep_exact_input_order() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = AtomicUsize::new(0);
        let seen = Mutex::new(Vec::new());
        let epochs = (201..=300).rev().collect::<Vec<_>>();
        let result = collect(&epochs, |epoch| {
            let (active, peak, seen) = (&active, &peak, &seen);
            async move {
                let _active = Active(active.clone());
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                seen.lock().unwrap().push(epoch);
                tokio::task::yield_now().await;
                Ok(epoch)
            }
        })
        .await
        .unwrap();
        assert_eq!(result, epochs);
        let mut seen = seen.into_inner().unwrap();
        seen.sort_unstable();
        assert_eq!(seen, (201..=300).collect::<Vec<_>>());
        assert!(peak.load(Ordering::SeqCst) > 1);
        assert!(peak.load(Ordering::SeqCst) <= CONCURRENCY);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn lookup_failure_cancels_pending_reads_without_returning_a_partial_inventory() {
        let active = Arc::new(AtomicUsize::new(0));
        let result = collect(&(201..=300).collect::<Vec<_>>(), |epoch| {
            let active = &active;
            async move {
                let _active = Active(active.clone());
                active.fetch_add(1, Ordering::SeqCst);
                if epoch == 203 {
                    anyhow::bail!("authenticated lookup failed");
                }
                tokio::task::yield_now().await;
                Ok(epoch)
            }
        })
        .await;
        assert!(
            result
                .unwrap_err()
                .root_cause()
                .to_string()
                .contains("authenticated lookup failed")
        );
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
