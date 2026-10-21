//! One thread-scoped test observer; no production state or send authority.
use super::UdpTransport;
use std::{cell::RefCell, marker::PhantomData, rc::Rc};

struct Probe {
    transport: u64,
    callback: Box<dyn Fn()>,
}

thread_local! {
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
}

pub(crate) struct Scope(PhantomData<Rc<()>>);

pub(crate) fn install(udp: &UdpTransport, callback: impl Fn() + 'static) -> Scope {
    PROBE.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(slot.is_none());
        *slot = Some(Probe {
            transport: udp.transport_instance_id,
            callback: Box::new(callback),
        });
    });
    Scope(PhantomData)
}

pub(super) fn observe(udp: &UdpTransport) {
    PROBE.with(|slot| {
        let slot = slot.borrow();
        if let Some(probe) = slot
            .as_ref()
            .filter(|probe| probe.transport == udp.transport_instance_id)
        {
            (probe.callback)();
        }
    });
}

impl Drop for Scope {
    fn drop(&mut self) {
        PROBE.with(|slot| *slot.borrow_mut() = None);
    }
}
