//! Single-assignment first facts and ordered, capped original membership.
//! Clones share the sole cells; readers cannot install or replace a fact.
use super::CaptureFailure;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

pub(super) struct First<T>(Arc<OnceLock<T>>);
impl<T> Clone for First<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> First<T> {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn new() -> Self {
        Self(Arc::new(OnceLock::new()))
    }
    pub(super) fn as_ref(&self) -> Option<&T> {
        self.0.get()
    }
    pub(super) fn is_some(&self) -> bool {
        self.0.get().is_some()
    }
    pub(super) fn is_none(&self) -> bool {
        self.0.get().is_none()
    }
    pub(super) fn get_or_insert_with(&mut self, make: impl FnOnce() -> T) -> &T {
        self.0.get_or_init(make)
    }
    pub(super) fn set(&mut self, value: T) -> Result<(), T> {
        self.0.set(value)
    }
}

struct Storage<T> {
    slots: Box<[OnceLock<T>]>,
    published: AtomicUsize,
}
pub(super) struct Published<T>(Arc<Storage<T>>);
impl<T> Clone for Published<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> Published<T> {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn new(capacity: usize) -> Result<Self, CaptureFailure> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| CaptureFailure::Capacity)?;
        slots.resize_with(capacity, OnceLock::new);
        Ok(Self(Arc::new(Storage {
            slots: slots.into_boxed_slice(),
            published: AtomicUsize::new(0),
        })))
    }
    pub(super) fn len(&self) -> usize {
        self.0.published.load(Ordering::Acquire)
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
        // Freeze the original published prefix once. Later appends are absent.
        self.0.slots[..self.len()].iter().filter_map(OnceLock::get)
    }
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn get(&self, index: usize) -> Option<&T> {
        (index < self.len())
            .then(|| self.0.slots[index].get())
            .flatten()
    }
    pub(super) fn try_reserve(&self, additional: usize) -> Result<(), CaptureFailure> {
        self.len()
            .checked_add(additional)
            .filter(|count| *count <= self.0.slots.len())
            .map(|_| ())
            .ok_or(CaptureFailure::Capacity)
    }
    // The original input registry's exclusive writer calls this once. Native
    // readers hold only shared clones and have no mutable append capability.
    pub(super) fn push(&mut self, value: T) -> Result<(), CaptureFailure> {
        let index = self.len();
        let cell = self.0.slots.get(index).ok_or(CaptureFailure::Capacity)?;
        cell.set(value).map_err(|_| CaptureFailure::FrameConflict)?;
        self.0.published.store(index + 1, Ordering::Release);
        Ok(())
    }
}

#[cfg(all(unix, test))]
mod tests;
