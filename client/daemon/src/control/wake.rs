//! Bounded control-plane wake hints. These bits never contain membership or
//! native authority: only the existing HTTP reconciliation may change either.
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone, Copy)]
pub(super) struct Wake(u8);

impl Wake {
    pub(super) const SIGNALS: Self = Self(1);
    pub(super) const ROSTER: Self = Self(2);
    pub(super) fn signals(self) -> bool {
        self.0 & Self::SIGNALS.0 != 0
    }
    pub(super) fn roster(self) -> bool {
        self.0 & Self::ROSTER.0 != 0
    }
}

// The authenticated ready frame binds identity. Typed roster notifications
// must name that same device/room and share the existing sequence stream.
pub(super) fn notification(
    roster: bool,
    identity: (&str, &str),
    expected: (&str, &str),
    sequence: u64,
    last_sequence: &mut u64,
) -> Result<Option<Wake>, &'static str> {
    if sequence == 0 {
        return Err("zero_notification_sequence");
    }
    if roster && identity != expected {
        return Err("roster_notification_scope");
    }
    if sequence <= *last_sequence {
        return Ok(None);
    }
    *last_sequence = sequence;
    Ok(Some(if roster { Wake::ROSTER } else { Wake::SIGNALS }))
}

#[derive(Clone)]
pub(super) struct Sender {
    queue: mpsc::Sender<Wake>,
    pending: Arc<AtomicU8>,
}

pub(super) struct Receiver {
    queue: mpsc::Receiver<Wake>,
    pending: Arc<AtomicU8>,
}

pub(super) fn channel(capacity: usize) -> (Sender, Receiver) {
    let (tx, rx) = mpsc::channel(capacity);
    let pending = Arc::new(AtomicU8::new(0));
    (
        Sender {
            queue: tx,
            pending: pending.clone(),
        },
        Receiver { queue: rx, pending },
    )
}

impl Sender {
    pub(super) fn notify(&self, wake: Wake) -> bool {
        // Publish before enqueue: a full queue already owns a wake token.
        // Even if it drains concurrently, the new enqueue or its existing
        // token carries these bits. Never discard a roster hint behind signals.
        self.pending.fetch_or(wake.0, Ordering::Release);
        match self.queue.try_send(wake) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

impl Receiver {
    pub(super) async fn recv(&mut self) -> Option<Wake> {
        let wake = self.queue.recv().await?;
        Some(Wake(wake.0 | self.pending.swap(0, Ordering::AcqRel)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn full_signal_queue_keeps_roster_hint_without_another_task_or_token() {
        let (tx, mut rx) = channel(1);
        assert!(tx.notify(Wake::SIGNALS));
        for _ in 0..100 {
            assert!(tx.notify(Wake::ROSTER));
        }
        let wake = rx.recv().await.unwrap();
        assert!(wake.signals() && wake.roster());
        assert!(rx.queue.try_recv().is_err());
    }

    #[tokio::test]
    async fn existing_signal_wakes_keep_their_bounded_queue_entries() {
        let (tx, mut rx) = channel(2);
        assert!(tx.notify(Wake::SIGNALS));
        assert!(tx.notify(Wake::SIGNALS));
        assert!(rx.recv().await.unwrap().signals());
        assert!(rx.recv().await.unwrap().signals());
    }

    #[test]
    fn closed_consumer_ends_the_original_producer() {
        let (tx, rx) = channel(1);
        drop(rx);
        assert!(!tx.notify(Wake::ROSTER));
        assert!(!tx.notify(Wake::SIGNALS));
    }

    #[test]
    fn roster_scope_and_shared_sequence_are_fenced_before_any_hint() {
        let expected = ("device-a", "room-a");
        let mut sequence = 4;
        assert!(notification(true, ("device-b", "room-a"), expected, 5, &mut sequence).is_err());
        assert!(notification(true, ("device-a", "room-b"), expected, 5, &mut sequence).is_err());
        assert_eq!(sequence, 4);
        assert!(notification(true, expected, expected, 0, &mut sequence).is_err());
        assert!(notification(true, expected, expected, 4, &mut sequence)
            .unwrap()
            .is_none());
        assert!(notification(true, expected, expected, 5, &mut sequence)
            .unwrap()
            .unwrap()
            .roster());
        assert!(notification(false, ("", ""), expected, 5, &mut sequence)
            .unwrap()
            .is_none());
        assert_eq!(sequence, 5);
    }

    #[test]
    fn legacy_signal_notification_still_uses_original_sequence_stream() {
        let mut sequence = 0;
        assert!(
            notification(false, ("", ""), ("device-a", "room-a"), 1, &mut sequence)
                .unwrap()
                .unwrap()
                .signals()
        );
        assert_eq!(sequence, 1);
    }
}
