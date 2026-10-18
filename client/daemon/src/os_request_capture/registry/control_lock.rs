//! One metadata owner. Packet callbacks only try; the single control actor may
//! yield within its caller's existing deadline. No guard crosses an IO await.
use crate::os_request_capture::plan::CaptureFailure;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::LockResult;
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError, TryLockResult};
use tokio::sync::Notify;

mod refusal;
pub(super) use refusal::InputRefusalSnapshot;

pub(super) struct ControlState<T> {
    inner: Mutex<T>,
    changed: Notify,
    completion_released: Notify,
    waiting: AtomicBool,
    refusals: refusal::RefusalDiagnostics,
}

pub(super) struct StateGuard<'a, T> {
    inner: Option<MutexGuard<'a, T>>,
    refusals: &'a refusal::RefusalDiagnostics,
    holder_token: u64,
    changed: &'a Notify,
    completion_released: &'a Notify,
}

struct Waiter<'a>(&'a AtomicBool);
impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl<T> ControlState<T> {
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            changed: Notify::new(),
            completion_released: Notify::new(),
            waiting: AtomicBool::new(false),
            refusals: refusal::RefusalDiagnostics::new(),
        }
    }

    fn wrap<'a>(&'a self, inner: MutexGuard<'a, T>, site: refusal::Site) -> StateGuard<'a, T> {
        StateGuard {
            inner: Some(inner),
            refusals: &self.refusals,
            holder_token: self.refusals.acquired(site),
            changed: &self.changed,
            completion_released: &self.completion_released,
        }
    }

    #[track_caller]
    pub(super) fn try_lock(&self) -> TryLockResult<StateGuard<'_, T>> {
        self.try_lock_at(refusal::Site::caller(), None)
    }

    #[track_caller]
    pub(super) fn try_input_lock(&self, read_ordinal: u64) -> TryLockResult<StateGuard<'_, T>> {
        self.try_lock_at(refusal::Site::caller(), Some(read_ordinal))
    }

    fn try_lock_at(
        &self,
        site: refusal::Site,
        input: Option<u64>,
    ) -> TryLockResult<StateGuard<'_, T>> {
        let started = input.and_then(|_| crate::os_request_capture::clock::monotonic_ns());
        let result = self.inner.try_lock();
        let returned = input.and_then(|_| crate::os_request_capture::clock::monotonic_ns());
        match result {
            Ok(guard) => Ok(self.wrap(guard, site)),
            Err(TryLockError::WouldBlock) => {
                if let Some(read) = input {
                    self.refusals.refused(read, started, returned);
                }
                Err(TryLockError::WouldBlock)
            }
            Err(TryLockError::Poisoned(error)) => Err(TryLockError::Poisoned(PoisonError::new(
                self.wrap(error.into_inner(), site),
            ))),
        }
    }

    pub(super) fn input_refusal_snapshot(&self) -> Option<InputRefusalSnapshot> {
        self.refusals.snapshot()
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) async fn completion_released(&self) {
        self.completion_released.notified().await;
    }

    #[cfg(test)]
    #[track_caller]
    pub(super) fn lock(&self) -> LockResult<StateGuard<'_, T>> {
        let site = refusal::Site::caller();
        self.inner
            .lock()
            .map(|guard| self.wrap(guard, site))
            .map_err(|error| PoisonError::new(self.wrap(error.into_inner(), site)))
    }

    /// At most one control waiter; no packet worker enters this path. The
    /// deadline belongs to the original command/window, never a new timeout.
    pub(super) async fn lock_until(
        &self,
        end: tokio::time::Instant,
    ) -> Result<StateGuard<'_, T>, CaptureFailure> {
        self.waiting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CaptureFailure::Contended)?;
        let _waiter = Waiter(&self.waiting);
        loop {
            if tokio::time::Instant::now() >= end {
                return Err(CaptureFailure::ControlNotReady);
            }
            let changed = self.changed.notified();
            tokio::pin!(changed);
            // Subscribe before trying, so release between try and await is
            // retained. Poison remains terminal instead of being waited out.
            changed.as_mut().enable();
            match self.try_lock() {
                Ok(guard) => {
                    if tokio::time::Instant::now() >= end {
                        return Err(CaptureFailure::ControlNotReady);
                    }
                    return Ok(guard);
                }
                Err(TryLockError::Poisoned(_)) => return Err(CaptureFailure::Contended),
                Err(TryLockError::WouldBlock) => {}
            }
            tokio::time::timeout_at(end, changed)
                .await
                .map_err(|_| CaptureFailure::ControlNotReady)?;
        }
    }
}

impl<T> Deref for StateGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.inner
            .as_deref()
            .expect("state guard exists until drop")
    }
}
impl<T> DerefMut for StateGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.inner
            .as_deref_mut()
            .expect("state guard exists until drop")
    }
}
impl<T> Drop for StateGuard<'_, T> {
    fn drop(&mut self) {
        let ended = crate::os_request_capture::clock::monotonic_ns();
        drop(self.inner.take());
        // Fixed first-refusal metadata only, after releasing the actual guard.
        self.refusals.released(self.holder_token, ended);
        // Waking can call an executor's waker; release the metadata first.
        self.changed.notify_one();
        // A distinct listener cannot consume the original command waiter's
        // release notification. Neither wake grants any native permission.
        self.completion_released.notify_one();
    }
}

#[cfg(test)]
mod tests;
