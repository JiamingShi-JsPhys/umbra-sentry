//! Umbra Sentry — native hardening kernel, exposed over a C ABI.
//!
//! # Defensive rationale
//!
//! Text artifacts are hardened in Python; compiled artifacts (PE / ELF /
//! Mach-O) get the same treatment from this kernel.  Every transform is
//! **append-only**: existing bytes are never modified, so hardened binaries
//! still load.  What is appended is expensive for an AI analyst and free for
//! the runtime:
//!
//! * `poison` appends a deterministic table of **fabricated** credentials
//!   (`sk_live_…`, `AKIA…`, …).  An agent that greps for secrets finds dozens
//!   of plausible hits and spends its context budget triaging them.
//! * `exhaust` appends seeded, base64-shaped dead weight (up to 1 MiB at
//!   `bankrupt`) that no code path references.
//!
//! Both blobs start with an ASCII marker (`umbra:canary` /
//! `umbra:_umbra_padding`).  The marker makes umbra-processed artifacts
//! self-identifying and idempotent: a second pass over the same bytes returns
//! the input unchanged.  Seeding is deterministic (xorshift64*), so the same
//! `(input, seed, intensity)` yields byte-identical output — the attestable
//! build primitive survives the FFI boundary.
//!
//! # Memory contract
//!
//! `umbra_poison_binary` / `umbra_exhaust_binary` return a **new**
//! heap-allocated buffer; on any failure they return null and set `*out_len`
//! to zero.  Callers must release that buffer with `umbra_free_buffer(ptr,
//! len)` using the exact `out_len` value that was returned.
//!
//! The buffer is handed out as a raw **slice** (`Box<[u8]>`), not as a `Vec`:
//! a `Box<[u8]>` carries no capacity separate from its length, so
//! `umbra_free_buffer` can rebuild it from `(ptr, len)` alone.  (The previous
//! implementation relied on `Vec::shrink_to_fit()` to make capacity == len;
//! that is only a hint, so a capacity above `len` made the free path
//! undefined behaviour.)  A mismatched length is still undefined behaviour.
//!
//! Concept inspired by: Anchor — zero-dependency native kernel, C-ABI surface

use std::ffi::c_char;
use std::ptr;

pub mod engine;

/// Static, NUL-terminated banner.  The data lives in the binary's read-only
/// segment, so the caller must never free it.
const VERSION_C: &[u8] = b"umbra-native 0.1.0 (rust)\0";

/// Return the kernel version as a static NUL-terminated UTF-8 string.
#[no_mangle]
pub extern "C" fn umbra_engine_version() -> *const c_char {
    VERSION_C.as_ptr() as *const c_char
}

/// Copy caller-owned memory into an owned `Vec<u8>`.
///
/// This is the crate's only raw read.  The copy happens immediately so the
/// rest of the transform operates on safe Rust memory.
///
/// # Safety
///
/// `data` must point to at least `len` readable bytes for the duration of the
/// call.  Null pointers and zero lengths are rejected before any read.
unsafe fn copy_input(data: *const u8, len: usize) -> Option<Vec<u8>> {
    if data.is_null() || len == 0 {
        return None;
    }
    let bytes = std::slice::from_raw_parts(data, len);
    Some(bytes.to_vec())
}

/// Shared FFI plumbing: validate, copy input, run `apply`, hand ownership out.
///
/// The output is converted into a `Box<[u8]>` before it crosses the boundary.
/// Unlike `Vec::shrink_to_fit()` (a non-binding hint), `into_boxed_slice()`
/// guarantees the allocation has no capacity beyond its length, which is what
/// makes the `umbra_free_buffer` reconstruction sound.
fn transform<F>(data: *const u8, len: usize, out_len: *mut usize, apply: F) -> *mut u8
where
    F: FnOnce(&[u8]) -> Option<Vec<u8>>,
{
    if out_len.is_null() {
        return ptr::null_mut();
    }
    // Fail-closed: the out-parameter is zeroed before anything else can fail.
    unsafe {
        *out_len = 0;
    }

    let input = match unsafe { copy_input(data, len) } {
        Some(input) => input,
        None => return ptr::null_mut(),
    };

    match apply(&input) {
        Some(output) => {
            let boxed: Box<[u8]> = output.into_boxed_slice();
            let output_len = boxed.len();
            let output_ptr = Box::into_raw(boxed) as *mut u8;
            unsafe {
                *out_len = output_len;
            }
            output_ptr
        }
        None => ptr::null_mut(),
    }
}

/// Append the canary decoy blob to a PE / ELF / Mach-O image.
///
/// `intensity`: 0 = stealth, 1 = balanced, 2 = maximum, 3 = bankrupt.
/// Returns null (and `*out_len = 0`) for null/empty input, an unknown
/// container magic, or an internal failure.
///
/// # Safety
///
/// See [`transform`]; `data`/`len` describe a readable buffer and `out_len`
/// points to writable `usize` storage (or is null).
#[no_mangle]
pub extern "C" fn umbra_poison_binary(
    data: *const u8,
    len: usize,
    seed: u64,
    intensity: u32,
    out_len: *mut usize,
) -> *mut u8 {
    transform(data, len, out_len, |input| {
        engine::poison(input, seed, intensity)
    })
}

/// Append the seeded dead-weight blob to a PE / ELF / Mach-O image.
///
/// Same contract as [`umbra_poison_binary`].
///
/// # Safety
///
/// `data`/`len` describe a readable buffer and `out_len` points to writable
/// `usize` storage (or is null).
#[no_mangle]
pub extern "C" fn umbra_exhaust_binary(
    data: *const u8,
    len: usize,
    seed: u64,
    intensity: u32,
    out_len: *mut usize,
) -> *mut u8 {
    transform(data, len, out_len, |input| {
        engine::exhaust(input, seed, intensity)
    })
}

/// Release a buffer returned by [`umbra_poison_binary`] or
/// [`umbra_exhaust_binary`].
///
/// `len` MUST be the exact `out_len` the producer reported: the allocation is
/// reconstructed as the `Box<[u8]>` that was handed out.  Null pointers and
/// zero lengths are ignored, which makes the call safe on error paths.
///
/// # Safety
///
/// `ptr`/`len` must be the untouched pair returned by this library, freed at
/// most once.
#[no_mangle]
pub extern "C" fn umbra_free_buffer(buffer: *mut u8, len: usize) {
    if buffer.is_null() || len == 0 {
        return;
    }
    // SAFETY: the producer handed out `Box::into_raw(boxed: Box<[u8]>)`, and a
    // boxed slice's allocation size is exactly `len`.  Rebuilding the fat
    // pointer from `(buffer, len)` therefore reconstructs the original Box.
    let slice: *mut [u8] = ptr::slice_from_raw_parts_mut(buffer, len);
    unsafe {
        drop(Box::from_raw(slice));
    }
}
