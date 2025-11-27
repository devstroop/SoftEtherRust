//! C FFI bindings for Swift integration

use crate::VirtualTapAdapter;
use crate::ring_buffer::RingBufferStats;
use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr;
use tracing::{error, info};

pub struct VTapHandle {
    adapter: VirtualTapAdapter,
}

#[repr(C)]
pub enum VTapResult {
    Success = 0,
    Error = -1,
    BufferFull = -2,
    BufferEmpty = -3,
    InvalidHandle = -4,
}

#[repr(C)]
pub struct VTapStats {
    pub packets_written: u64,
    pub packets_read: u64,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub drops: u64,
}

impl From<RingBufferStats> for VTapStats {
    fn from(stats: RingBufferStats) -> Self {
        Self {
            packets_written: stats.packets_written,
            packets_read: stats.packets_read,
            bytes_written: stats.bytes_written,
            bytes_read: stats.bytes_read,
            drops: stats.drops,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn vtap_create(mac: *const c_uchar, mtu: usize) -> *mut VTapHandle {
    if mac.is_null() { return ptr::null_mut(); }
    let mac_array = std::slice::from_raw_parts(mac, 6);
    let mac_buf: [u8; 6] = match mac_array.try_into() { Ok(b) => b, Err(_) => return ptr::null_mut() };
    match VirtualTapAdapter::new(mac_buf, mtu) {
        Ok(adapter) => {
            info!("Created VirtualTapAdapter: {}", adapter.interface_name());
            Box::into_raw(Box::new(VTapHandle { adapter }))
        }
        Err(e) => { error!("Failed to create VirtualTapAdapter: {}", e); ptr::null_mut() }
    }
}

#[no_mangle]
pub unsafe extern "C" fn vtap_destroy(handle: *mut VTapHandle) {
    if !handle.is_null() { drop(Box::from_raw(handle)); }
}

#[no_mangle]
pub unsafe extern "C" fn vtap_get_interface_name(handle: *const VTapHandle) -> *const c_char {
    if handle.is_null() { return ptr::null(); }
    (*handle).adapter.interface_name().as_ptr() as *const c_char
}

#[no_mangle]
pub unsafe extern "C" fn vtap_get_fd(handle: *const VTapHandle) -> c_int {
    if handle.is_null() { return -1; }
    (*handle).adapter.file_descriptor()
}

#[no_mangle]
pub unsafe extern "C" fn vtap_write_packet(handle: *mut VTapHandle, data: *const c_uchar, len: usize) -> VTapResult {
    if handle.is_null() || data.is_null() { return VTapResult::InvalidHandle; }
    let slice = std::slice::from_raw_parts(data, len);
    match (*handle).adapter.ring_buffer().write(slice) {
        Ok(()) => VTapResult::Success,
        Err(e) => if e.to_string().contains("BufferFull") { VTapResult::BufferFull } else { VTapResult::Error }
    }
}

#[no_mangle]
pub unsafe extern "C" fn vtap_read_packet(handle: *mut VTapHandle, buffer: *mut c_uchar, buffer_len: usize, out_len: *mut usize) -> VTapResult {
    if handle.is_null() || buffer.is_null() || out_len.is_null() { return VTapResult::InvalidHandle; }
    match (*handle).adapter.ring_buffer().read() {
        Ok(Some(packet)) => {
            if packet.len() > buffer_len { return VTapResult::Error; }
            let dest = std::slice::from_raw_parts_mut(buffer, packet.len());
            dest.copy_from_slice(&packet);
            *out_len = packet.len();
            VTapResult::Success
        }
        Ok(None) => VTapResult::BufferEmpty,
        Err(_) => VTapResult::Error
    }
}

#[no_mangle]
pub unsafe extern "C" fn vtap_get_stats(handle: *const VTapHandle, stats: *mut VTapStats) -> VTapResult {
    if handle.is_null() || stats.is_null() { return VTapResult::InvalidHandle; }
    *stats = (*handle).adapter.ring_buffer().stats().into();
    VTapResult::Success
}

#[no_mangle]
pub unsafe extern "C" fn vtap_reset_stats(handle: *mut VTapHandle) -> VTapResult {
    if handle.is_null() { return VTapResult::InvalidHandle; }
    (*handle).adapter.ring_buffer().reset_stats();
    VTapResult::Success
}
