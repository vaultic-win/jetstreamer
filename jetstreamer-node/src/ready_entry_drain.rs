//! Structural producer closure and explicit ready-entry drainage.
//!
//! A joined consumer is not necessarily a drained consumer: cancellation or a
//! panic can leave already-enqueued entries unexecuted. Only channel exhaustion
//! after successful execution permits the caller to freeze/close a checkpoint.
use std::{
    sync::atomic::{AtomicBool, Ordering},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use crossbeam_channel::{Receiver, Sender};

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DrainReport {
    pub(crate) batches: u64,
    pub(crate) entries: u64,
}

pub(crate) fn consume<T>(
    receiver: Receiver<Vec<T>>,
    shutdown: &AtomicBool,
    mut process: impl FnMut(Vec<T>) -> Result<(), String>,
    mut observed_receive: impl FnMut(Duration, usize),
) -> Result<DrainReport, String> {
    const COALESCE_CAP: usize = 4096;
    let mut report = DrainReport::default();
    loop {
        let start = Instant::now();
        let received = receiver.recv();
        if shutdown.load(Ordering::Acquire) {
            return Err("ready-entry drainage cancelled before channel exhaustion".into());
        }
        let mut entries = match received {
            Ok(entries) => entries,
            Err(_) => return Ok(report),
        };
        observed_receive(start.elapsed(), receiver.len());
        while entries.len() < COALESCE_CAP {
            match receiver.try_recv() {
                Ok(more) => entries.extend(more),
                Err(_) => break,
            }
        }
        let count = u64::try_from(entries.len()).map_err(|_| "ready-entry count overflow")?;
        if shutdown.load(Ordering::Acquire) {
            return Err("ready-entry drainage cancelled before execution".into());
        }
        process(entries)?;
        if shutdown.load(Ordering::Acquire) {
            return Err("ready-entry drainage cancelled during execution".into());
        }
        report.batches = report
            .batches
            .checked_add(1)
            .ok_or("ready batch count overflow")?;
        report.entries = report
            .entries
            .checked_add(count)
            .ok_or("ready-entry count overflow")?;
    }
}

/// Drop every source owner (including the block-parent notifier) before join.
/// A successful return requires genuine channel exhaustion and a clean consumer;
/// callers must still verify scheduler completeness and the frozen native state.
pub(crate) fn close<N, P, T>(
    notifiers: N,
    producers: P,
    sender: Sender<Vec<T>>,
    consumer: JoinHandle<Result<DrainReport, String>>,
) -> Result<DrainReport, String> {
    drop(notifiers);
    drop(producers);
    drop(sender);
    consumer
        .join()
        .map_err(|_| "ready-entry consumer panicked before verified drainage".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn closing_all_notifiers_drains_queued_entries_in_order_before_join_returns() {
        let (sender, receiver) = crossbeam_channel::bounded(3);
        let owners = [
            sender.clone(),
            sender.clone(),
            sender.clone(),
            sender.clone(),
        ];
        let notifiers = sender.clone();
        sender.send(vec![1, 2]).unwrap();
        sender.send(vec![3]).unwrap();
        sender.send(vec![4, 5]).unwrap();
        let values = Arc::new(Mutex::new(Vec::new()));
        let recorded = values.clone();
        let consumer = std::thread::spawn(move || {
            consume(
                receiver,
                &AtomicBool::new(false),
                |batch| {
                    recorded.lock().unwrap().extend(batch);
                    Ok(())
                },
                |_, _| {},
            )
        });
        let (done, completion) = crossbeam_channel::bounded(1);
        std::thread::spawn(move || {
            done.send(close(notifiers, owners, sender, consumer))
                .unwrap()
        });
        let report = completion
            .recv_timeout(Duration::from_secs(2))
            .expect("all notifier handles must close")
            .unwrap();
        assert_eq!(report.entries, 5);
        assert_eq!(*values.lock().unwrap(), [1, 2, 3, 4, 5]);
    }

    #[test]
    fn retained_producer_prevents_success_even_after_current_queue_drains() {
        let (sender, receiver) = crossbeam_channel::bounded::<Vec<u8>>(1);
        let retained = sender.clone();
        let consumer = std::thread::spawn(move || {
            consume(receiver, &AtomicBool::new(false), |_| Ok(()), |_, _| {})
        });
        let (done, completion) = crossbeam_channel::bounded(1);
        std::thread::spawn(move || done.send(close((), (), sender, consumer)).unwrap());
        assert!(completion.recv_timeout(Duration::from_millis(30)).is_err());
        drop(retained);
        assert_eq!(
            completion
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap()
                .entries,
            0
        );
    }

    #[test]
    fn shutdown_is_not_drain_success_even_when_channel_is_already_closed() {
        for queued in [false, true] {
            let (sender, receiver) = crossbeam_channel::bounded(1);
            if queued {
                sender.send(vec![1]).unwrap();
            }
            drop(sender);
            let result = consume(
                receiver,
                &AtomicBool::new(true),
                |_| panic!("cancelled work executed"),
                |_, _| {},
            );
            assert!(result.unwrap_err().contains("cancelled"));
        }
    }

    #[test]
    fn executor_error_or_cancellation_cannot_certify_drainage() {
        for cancel in [false, true] {
            let (sender, receiver) = crossbeam_channel::bounded(1);
            sender.send(vec![1]).unwrap();
            drop(sender);
            let shutdown = AtomicBool::new(false);
            let result = consume(
                receiver,
                &shutdown,
                |_| {
                    if cancel {
                        shutdown.store(true, Ordering::Release);
                        Ok(())
                    } else {
                        Err("native entry failed".into())
                    }
                },
                |_, _| {},
            );
            assert_eq!(
                result.unwrap_err(),
                if cancel {
                    "ready-entry drainage cancelled during execution"
                } else {
                    "native entry failed"
                }
            );
        }
    }

    #[test]
    fn consumer_panic_is_a_failed_drain() {
        let (sender, receiver) = crossbeam_channel::bounded::<Vec<u8>>(1);
        let consumer = std::thread::spawn(move || {
            drop(receiver);
            panic!("executor panic")
        });
        assert!(
            close((), (), sender, consumer)
                .unwrap_err()
                .contains("panicked")
        );
    }
}
