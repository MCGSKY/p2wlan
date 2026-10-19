//! The original peer counter fence. Optional diagnostics never own the worker,
//! retain a mutex beyond its actual guard, or supply a publication/owner fact.
use std::collections::HashMap;
use std::future::Future;
use std::ops::Deref;
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, MutexGuard, OwnedMutexGuard, TryLockError};

#[cfg(any(target_os = "linux", all(unix, test)))]
mod trace;
#[cfg(any(target_os = "linux", all(unix, test)))]
use trace::Site;
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) use trace::{EmitRefusalSnapshot, EmitTrace, EmitTryContext};
#[cfg(not(any(target_os = "linux", all(unix, test))))]
#[derive(Clone, Copy)]
pub(super) struct Site;

pub(super) struct EmitRegistry {
    inner: Mutex<HashMap<String, Weak<EmitGate>>>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    claimed: std::sync::atomic::AtomicBool,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    observer: std::sync::OnceLock<Weak<EmitTrace>>,
}

impl EmitRegistry {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            #[cfg(any(target_os = "linux", all(unix, test)))]
            claimed: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(target_os = "linux", all(unix, test)))]
            observer: std::sync::OnceLock::new(),
        }
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn bind(&self, observer: &Arc<EmitTrace>) {
        use std::sync::atomic::Ordering;
        if observer.live()
            && self
                .claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            // Exactly one initializer, never an initializer wait or rearm.
            let _ = self.observer.set(Arc::downgrade(observer));
        }
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    fn observer(&self) -> Option<Arc<EmitTrace>> {
        self.observer.get()?.upgrade().filter(|trace| trace.live())
    }
}

impl Deref for EmitRegistry {
    type Target = Mutex<HashMap<String, Weak<EmitGate>>>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub(super) struct EmitGate {
    inner: Arc<Mutex<()>>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    registry: Weak<EmitRegistry>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    holder: std::sync::OnceLock<Arc<trace::HolderState>>,
}

pub(super) struct EmitGuard<'a> {
    inner: Option<MutexGuard<'a, ()>>,
    owner: &'a EmitGate,
    token: Option<u64>,
}

pub(crate) struct OwnedEmitGuard {
    inner: Option<OwnedMutexGuard<()>>,
    // This is the original guard's ownership, not a diagnostic keeper. A weak
    // registry entry must still upgrade while an owned guard holds the mutex.
    owner: Arc<EmitGate>,
    token: Option<u64>,
}

impl EmitGate {
    pub(super) fn new(_registry: &Arc<EmitRegistry>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(())),
            #[cfg(any(target_os = "linux", all(unix, test)))]
            registry: Arc::downgrade(_registry),
            #[cfg(any(target_os = "linux", all(unix, test)))]
            holder: std::sync::OnceLock::new(),
        }
    }

    #[track_caller]
    pub(super) fn lock(&self) -> impl Future<Output = EmitGuard<'_>> {
        let site = caller_site();
        async move {
            let inner = self.inner.lock().await;
            EmitGuard {
                inner: Some(inner),
                owner: self,
                token: self.acquired(site),
            }
        }
    }

    #[track_caller]
    pub(super) fn try_lock(&self) -> Result<EmitGuard<'_>, TryLockError> {
        let site = caller_site();
        let inner = self.inner.try_lock()?;
        Ok(EmitGuard {
            inner: Some(inner),
            owner: self,
            token: self.acquired(site),
        })
    }

    #[track_caller]
    pub(super) fn lock_owned(self: Arc<Self>) -> impl Future<Output = OwnedEmitGuard> {
        self.lock_owned_at(caller_site())
    }

    pub(super) async fn lock_owned_at(self: Arc<Self>, site: Site) -> OwnedEmitGuard {
        let inner = self.inner.clone().lock_owned().await;
        self.wrap(inner, site)
    }

    #[track_caller]
    pub(super) fn try_lock_owned(self: Arc<Self>) -> Result<OwnedEmitGuard, TryLockError> {
        let site = caller_site();
        let inner = self.inner.clone().try_lock_owned()?;
        Ok(self.wrap(inner, site))
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    #[track_caller]
    pub(super) fn try_lock_original(
        self: Arc<Self>,
        context: Option<EmitTryContext>,
    ) -> Result<OwnedEmitGuard, TryLockError> {
        let site = caller_site();
        let observed = context.filter(|context| {
            self.registry
                .upgrade()
                .and_then(|registry| registry.observer())
                .is_some_and(|observer| {
                    Arc::ptr_eq(&observer, &context.trace) && context.accepted()
                })
        });
        let started = observed.as_ref().and_then(|_| trace::now_ns());
        let result = self.inner.clone().try_lock_owned(); // The one original actual try.
        let returned = observed.as_ref().and_then(|_| trace::now_ns());
        match result {
            Ok(inner) => Ok(self.wrap(inner, site)),
            Err(error) => {
                if let Some(context) = observed {
                    context.refused(self.holder.get(), started, returned);
                }
                Err(error)
            }
        }
    }

    fn wrap(self: Arc<Self>, inner: OwnedMutexGuard<()>, site: Site) -> OwnedEmitGuard {
        let token = self.acquired(site);
        OwnedEmitGuard {
            inner: Some(inner),
            owner: self,
            token,
        }
    }

    fn acquired(&self, site: Site) -> Option<u64> {
        #[cfg(any(target_os = "linux", all(unix, test)))]
        {
            let observer = self.registry.upgrade()?.observer()?;
            if self.holder.get().is_none() {
                // The actual peer mutex serializes all successful entrants.
                // No competing initializer or diagnostic lock is introduced.
                let _ = self.holder.set(Arc::new(trace::HolderState::new()));
            }
            self.holder.get()?.acquired(&observer, site)
        }
        #[cfg(not(any(target_os = "linux", all(unix, test))))]
        {
            let _ = site;
            None
        }
    }

    fn released(&self, token: Option<u64>, ended: Option<u64>) {
        #[cfg(any(target_os = "linux", all(unix, test)))]
        if let (Some(holder), Some(token)) = (self.holder.get(), token) {
            holder.released(token, ended);
        }
        #[cfg(not(any(target_os = "linux", all(unix, test))))]
        let _ = (token, ended);
    }
}

// Existing emit-fenced APIs may borrow the same actual owned guard. They
// cannot move it out of this wrapper or extend its original lifetime.
impl Deref for OwnedEmitGuard {
    type Target = OwnedMutexGuard<()>;
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().expect("emit guard exists until drop")
    }
}
impl Drop for OwnedEmitGuard {
    fn drop(&mut self) {
        let ended = observed_end(self.token);
        drop(self.inner.take());
        self.owner.released(self.token, ended);
    }
}
impl Drop for EmitGuard<'_> {
    fn drop(&mut self) {
        let ended = observed_end(self.token);
        drop(self.inner.take());
        self.owner.released(self.token, ended);
    }
}

#[track_caller]
pub(super) fn caller_site() -> Site {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    {
        Site::caller()
    }
    #[cfg(not(any(target_os = "linux", all(unix, test))))]
    {
        Site
    }
}
fn observed_end(token: Option<u64>) -> Option<u64> {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    {
        token.and_then(|_| trace::now_ns())
    }
    #[cfg(not(any(target_os = "linux", all(unix, test))))]
    {
        let _ = token;
        None
    }
}

#[cfg(all(unix, test))]
mod tests;
