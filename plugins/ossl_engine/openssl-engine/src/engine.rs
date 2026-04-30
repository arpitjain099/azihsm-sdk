// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe wrapper around `*mut ENGINE`.

use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ptr::null_mut;

use openssl_sys_engine as ffi;

pub struct Engine {
    ptr: *mut ffi::ENGINE,
}

// SAFETY: ENGINE is reference-counted and serialized by OpenSSL's internal locking.
#[allow(unsafe_code)]
unsafe impl Send for Engine {}
// SAFETY: Same as above.
#[allow(unsafe_code)]
unsafe impl Sync for Engine {}

impl Engine {
    pub fn from_ptr(ptr: *mut ffi::ENGINE) -> Self {
        debug_assert!(!ptr.is_null());
        Self { ptr }
    }

    /// Synchronize memory allocators with the host, then call `f`.
    #[allow(unsafe_code)]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn bind(
        &self,
        id: *const c_char,
        fns: *const ffi::dynamic_fns,
        f: fn(&Engine, &CStr) -> c_int,
    ) -> c_int {
        // SAFETY: fns is provided by OpenSSL's dynamic loader. We sync
        // allocators so engine and host share the same heap.
        unsafe {
            if ffi::ENGINE_get_static_state() != (*fns).static_state {
                ffi::CRYPTO_set_mem_functions(
                    (*fns).mem_fns.malloc_fn,
                    (*fns).mem_fns.realloc_fn,
                    (*fns).mem_fns.free_fn,
                );
                ffi::OPENSSL_init_crypto(ffi::OPENSSL_INIT_NO_ATEXIT as u64, null_mut());
            }
        }

        let id = if id.is_null() {
            c""
        } else {
            // SAFETY: OpenSSL guarantees id is a valid C string.
            unsafe { CStr::from_ptr(id) }
        };

        f(self, id)
    }

    #[allow(unsafe_code)]
    pub fn set_id(&self, id: &CStr) -> c_int {
        // SAFETY: id is a valid CStr, self.ptr is a valid ENGINE.
        unsafe { ffi::ENGINE_set_id(self.ptr, id.as_ptr()) }
    }

    #[allow(unsafe_code)]
    pub fn set_name(&self, name: &CStr) -> c_int {
        // SAFETY: name is a valid CStr, self.ptr is a valid ENGINE.
        unsafe { ffi::ENGINE_set_name(self.ptr, name.as_ptr()) }
    }
}
