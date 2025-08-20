use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy)]
pub(crate) struct RxCb {
    pub func: extern "C" fn(*const u8, u32, *mut std::ffi::c_void),
    pub user: *mut std::ffi::c_void,
}

unsafe impl Send for RxCb {}
unsafe impl Sync for RxCb {}

#[derive(Clone, Copy)]
pub(crate) struct StateCb {
    pub func: extern "C" fn(i32, *mut std::ffi::c_void),
    pub user: *mut std::ffi::c_void,
}

unsafe impl Send for StateCb {}
unsafe impl Sync for StateCb {}

#[derive(Clone, Copy)]
pub(crate) struct EventCb {
    pub func: extern "C" fn(i32, i32, *const c_char, *mut std::ffi::c_void),
    pub user: *mut std::ffi::c_void,
}

unsafe impl Send for EventCb {}
unsafe impl Sync for EventCb {}

#[derive(Clone, Copy)]
pub(crate) struct IpRxCb {
    pub func: extern "C" fn(*const u8, u32, *mut std::ffi::c_void),
    pub user: *mut std::ffi::c_void,
}

unsafe impl Send for IpRxCb {}
unsafe impl Sync for IpRxCb {}

#[inline]
pub(crate) fn emit_event(cb_arc: &Arc<Mutex<Option<Arc<EventCb>>>>, level: i32, code: i32, msg: &str) {
    if let Some(cb) = cb_arc.lock().unwrap().as_ref().cloned() {
        if let Ok(cmsg) = CString::new(msg.to_string()) {
            (cb.func)(level, code, cmsg.as_ptr(), cb.user);
        }
    }
}
