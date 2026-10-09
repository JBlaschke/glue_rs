//! The only Rust/C execution boundary. Lua states and APIs remain C-owned.

use std::ffi::{CString, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_KEY: usize = 4096;
const PANIC_MESSAGE: &[u8] = b"archive callback panicked";

/// Private byte descriptor. C copies its bytes before releasing the cookie.
/// No Drop implementation: ownership transfers through the callback ABI to C.
#[repr(C)]
pub(crate) struct Reply {
    pub(crate) data: *const u8,
    pub(crate) len: usize,
    pub(crate) cookie: *mut c_void,
    pub(crate) status: c_int,
}

impl Reply {
    pub(crate) fn owned(status: c_int, bytes: Vec<u8>) -> Self {
        let bytes = Box::new(bytes);
        #[cfg(test)]
        OWNED_REPLIES.with(|count| count.set(count.get() + 1));
        let data = bytes.as_ptr();
        let len = bytes.len();
        Self {
            data,
            len,
            cookie: Box::into_raw(bytes).cast(),
            status,
        }
    }

    fn panic() -> Self {
        Self {
            data: PANIC_MESSAGE.as_ptr(),
            len: PANIC_MESSAGE.len(),
            cookie: std::ptr::null_mut(),
            status: 2,
        }
    }

    /// Consume an untransferred reply in protocol unit tests.
    #[cfg(test)]
    pub(crate) fn release_owned(self) {
        // SAFETY: Reply constructors own one Box<Vec<u8>>, or a null cookie.
        // Consuming self prevents another safe release of the same cookie.
        unsafe { release_cookie(self.cookie) };
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: the reply retains its owned buffer (or static panic bytes)
        // until it is consumed by release_owned or transferred to C.
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }
}

#[cfg(test)]
thread_local! {
    static OWNED_REPLIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn owned_reply_count() -> usize {
    OWNED_REPLIES.with(std::cell::Cell::get)
}

#[repr(C)]
struct Options {
    fail_after_allocations: usize,
    fail_after_reply_allocations: usize,
    collect_on_first_reply: c_int,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            fail_after_allocations: usize::MAX,
            fail_after_reply_allocations: usize::MAX,
            collect_on_first_reply: 0,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
struct RunResult {
    status: c_int,
    error_len: usize,
    error: [u8; 4096],
    allocation_attempts: usize,
    callbacks: usize,
    releases: usize,
    outstanding_replies: usize,
    peak_outstanding_replies: usize,
    shutdown_callbacks: usize,
}

type Request = unsafe extern "C" fn(*mut c_void, u32, *const u8, usize) -> Reply;
type Release = unsafe extern "C" fn(*mut c_void, *mut c_void);

unsafe extern "C" {
    fn glue_lua_run(
        context: *mut c_void,
        request: Request,
        release: Release,
        bootstrap: *const u8,
        bootstrap_len: usize,
        package_path: *const u8,
        package_path_len: usize,
        entry: *const u8,
        entry_len: usize,
        origin: *const std::ffi::c_char,
        options: *const Options,
        result: *mut RunResult,
    );

    #[cfg(all(test, feature = "linux-native"))]
    fn glue_lua_test_initializer(variant: std::ffi::c_uint) -> u64;
}

unsafe extern "C" fn request<F: FnMut(u32, &[u8]) -> Reply>(
    context: *mut c_void,
    operation: u32,
    key: *const u8,
    key_len: usize,
) -> Reply {
    // C validates keys before dispatch. Check defensively before constructing
    // a slice or dereferencing the synchronous, boxed callback context.
    if context.is_null() || key.is_null() || key_len > MAX_KEY {
        return Reply::panic();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: execute_inner supplies a stable Box<F> alive through close.
        // C dispatches synchronously; it only calls Lua after this borrow ends.
        let callback = unsafe { &mut *context.cast::<F>() };
        // SAFETY: C borrows a live Lua string of key_len bytes throughout this
        // callback. This slice is not retained or exposed beyond the callback.
        let key = unsafe { std::slice::from_raw_parts(key, key_len) };
        callback(operation, key)
    }));
    match result {
        Ok(reply) => reply,
        Err(payload) => {
            // Arbitrary panic payload destructors can themselves panic. Do not
            // run them inside an extern C frame; the sticky failure blocks all
            // further callbacks. Leak this one exceptional payload instead.
            std::mem::forget(payload);
            Reply::panic()
        }
    }
}

unsafe fn release_cookie(cookie: *mut c_void) {
    if !cookie.is_null() {
        // SAFETY: every nonnull cookie comes from Reply::owned. C calls this
        // once after protected copying, including copying failures. Vec<u8>
        // has no user destructor and this operation calls no Lua APIs.
        drop(unsafe { Box::from_raw(cookie.cast::<Vec<u8>>()) });
        #[cfg(test)]
        OWNED_REPLIES.with(|count| count.set(count.get() - 1));
    }
}

unsafe extern "C" fn release(_context: *mut c_void, cookie: *mut c_void) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: this is the reply cookie transferred to C by our constructor.
        unsafe { release_cookie(cookie) };
    }));
    if result.is_err() {
        // An unexpected allocator/accounting panic makes cleanup uncertain.
        // Fail closed without running its payload destructor or resuming Lua.
        std::process::abort();
    }
}

pub(crate) fn execute<F: FnMut(u32, &[u8]) -> Reply>(
    callback: F,
    bootstrap: &[u8],
    package_path: &str,
    entry: &[u8],
    origin: &str,
) -> Result<(), String> {
    execute_inner(
        callback,
        bootstrap,
        package_path,
        entry,
        origin,
        &Options::default(),
    )
    .0
}

fn execute_inner<F: FnMut(u32, &[u8]) -> Reply>(
    callback: F,
    bootstrap: &[u8],
    package_path: &str,
    entry: &[u8],
    origin: &str,
    options: &Options,
) -> (Result<(), String>, RunResult) {
    let mut result = RunResult {
        status: 0,
        error_len: 0,
        error: [0; 4096],
        allocation_attempts: 0,
        callbacks: 0,
        releases: 0,
        outstanding_replies: 0,
        peak_outstanding_replies: 0,
        shutdown_callbacks: 0,
    };
    let origin = match CString::new(format!("@{origin}")) {
        Ok(origin) => origin,
        Err(_) => return (Err("Lua source origin contains NUL".to_owned()), result),
    };
    let mut callback = Box::new(callback);
    // SAFETY: inputs, output, callback context and callbacks stay alive until
    // the synchronous C routine has closed the Lua state. C owns every Lua
    // call/protection frame and never jumps across either Rust callback.
    unsafe {
        glue_lua_run(
            (&mut *callback as *mut F).cast(),
            request::<F>,
            release,
            bootstrap.as_ptr(),
            bootstrap.len(),
            package_path.as_ptr(),
            package_path.len(),
            entry.as_ptr(),
            entry.len(),
            origin.as_ptr(),
            options,
            &mut result,
        );
    }
    let outcome = if result.status == 0 {
        Ok(())
    } else {
        let len = result.error_len.min(result.error.len());
        Err(String::from_utf8_lossy(&result.error[..len]).into_owned())
    };
    (outcome, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{OwnedReply, Value};
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    const BOOTSTRAP: &[u8] = b"request = ...";

    fn run<F: FnMut(u32, &[u8]) -> Reply>(
        callback: F,
        entry: &[u8],
        options: &Options,
    ) -> (Result<(), String>, RunResult) {
        execute_inner(
            callback,
            BOOTSTRAP,
            "",
            entry,
            "glue://test/entry.lua",
            options,
        )
    }

    fn bytes_reply() -> Reply {
        OwnedReply::success(&[Value::String(vec![b'x'; 8192])]).into_reply()
    }

    fn assert_released(stats: &RunResult) {
        assert_eq!(stats.outstanding_replies, 0, "{stats:?}");
        assert_eq!(stats.callbacks, stats.releases, "{stats:?}");
        assert_eq!(owned_reply_count(), 0);
    }

    #[test]
    fn callback_errors_and_non_string_lua_errors_are_protected() {
        let (outcome, stats) = run(
            |_, _| OwnedReply::error("resource missing").into_reply(),
            b"request(1, 'x')",
            &Options::default(),
        );
        assert!(outcome.unwrap_err().contains("resource missing"));
        assert_released(&stats);
        let (outcome, stats) = run(|_, _| bytes_reply(), b"error({})", &Options::default());
        assert!(outcome.unwrap_err().contains("non-string Lua error"));
        assert_released(&stats);
    }

    #[test]
    fn callback_panics_are_sticky_even_if_lua_catches_them() {
        let calls = Rc::new(Cell::new(0));
        let counted = Rc::clone(&calls);
        let (outcome, stats) = run(
            move |_, _| {
                counted.set(counted.get() + 1);
                panic!("fixture panic");
            },
            b"assert(not pcall(request, 1, 'x')); assert(not pcall(request, 1, 'x'))",
            &Options::default(),
        );
        assert_eq!(outcome.unwrap_err(), "archive callback panicked");
        assert_eq!(calls.get(), 1);
        assert_released(&stats);
    }

    #[test]
    fn panic_payload_destructors_never_run_inside_the_ffi_callback() {
        struct DropPanic(Arc<AtomicUsize>);
        impl Drop for DropPanic {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
                panic!("panic payload destructor");
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let tracked = Arc::clone(&drops);
        let (outcome, stats) = run(
            move |_, _| {
                std::panic::panic_any(DropPanic(Arc::clone(&tracked)));
            },
            b"pcall(request, 1, 'x')",
            &Options::default(),
        );
        assert_eq!(outcome.unwrap_err(), "archive callback panicked");
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_released(&stats);
    }

    #[test]
    fn state_and_initialization_allocation_failures_return_normally() {
        for limit in [0, 1, 10, 50, 100] {
            let (outcome, stats) = run(
                |_, _| bytes_reply(),
                b"",
                &Options {
                    fail_after_allocations: limit,
                    ..Options::default()
                },
            );
            assert!(outcome.is_err(), "limit={limit}, {stats:?}");
            assert_released(&stats);
        }
    }

    #[test]
    fn reply_allocation_failures_release_owned_bytes() {
        let mut observed_failure = false;
        let mut observed_success = false;
        for limit in 0..8 {
            let (outcome, stats) = run(
                |_, _| bytes_reply(),
                b"assert(#request(1, 'x') == 8192)",
                &Options {
                    fail_after_reply_allocations: limit,
                    ..Options::default()
                },
            );
            assert_eq!(stats.callbacks, 1, "limit={limit}, {stats:?}");
            if limit == 0 {
                assert!(outcome.is_err(), "reply OOM must fail the protected call");
            }
            observed_failure |= outcome.is_err();
            observed_success |= outcome.is_ok();
            assert_released(&stats);
        }
        assert!(
            observed_failure && observed_success,
            "fault budget must distinguish OOM and success"
        );
        let (outcome, stats) = run(
            |_, _| bytes_reply(),
            b"assert(#request(1, 'x') == 8192)",
            &Options::default(),
        );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_released(&stats);
    }

    #[test]
    fn finalizer_callbacks_keep_context_and_replies_alive() {
        let calls = Rc::new(Cell::new(0));
        let counted = Rc::clone(&calls);
        let (outcome, stats) = run(
            move |_, _| {
                counted.set(counted.get() + 1);
                bytes_reply()
            },
            b"keep = setmetatable({}, {__gc=function() assert(#request(1,'x') == 8192) end})",
            &Options::default(),
        );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(calls.get(), 1);
        assert_eq!(stats.shutdown_callbacks, 1);
        assert_released(&stats);
    }

    #[test]
    fn nested_gc_requests_keep_both_owned_reply_descriptors_live() {
        let operations = Rc::new(RefCell::new(Vec::new()));
        let observed = Rc::clone(&operations);
        let (outcome, stats) = run(
            move |operation, _| {
                observed.borrow_mut().push(operation);
                match operation {
                    1 => bytes_reply(),
                    2 => {
                        assert_eq!(owned_reply_count(), 1, "outer reply must remain owned");
                        OwnedReply::success(&[Value::Integer(42)]).into_reply()
                    }
                    _ => panic!("unexpected operation"),
                }
            },
            br#"
                collectgarbage('stop')
                do
                    local unreachable = setmetatable({}, {
                        __gc=function() assert(request(2,'inner') == 42) end
                    })
                end
                assert(#request(1,'outer') == 8192)
            "#,
            &Options {
                collect_on_first_reply: 1,
                ..Options::default()
            },
        );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(*operations.borrow(), [1, 2]);
        assert_eq!(stats.peak_outstanding_replies, 2);
        assert_released(&stats);
    }

    #[test]
    fn shutdown_reply_oom_releases_the_rust_buffer() {
        let (outcome, stats) = run(
            |_, _| bytes_reply(),
            b"keep = setmetatable({}, {__gc=function() request(1,'x') end})",
            &Options {
                fail_after_reply_allocations: 0,
                ..Options::default()
            },
        );
        // Official Lua ignores ordinary errors from finalizers during close.
        // The byte buffer must still be released before the C error propagates.
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(stats.shutdown_callbacks, 1);
        assert_released(&stats);
    }

    #[test]
    fn panic_during_shutdown_is_reported() {
        let (outcome, stats) = run(
            |_, _| panic!("shutdown panic"),
            b"keep = setmetatable({}, {__gc=function() request(1,'x') end})",
            &Options::default(),
        );
        assert_eq!(outcome.unwrap_err(), "archive callback panicked");
        assert_eq!(stats.shutdown_callbacks, 1);
        assert_released(&stats);
    }

    #[test]
    fn malformed_reply_is_released_before_error_propagation() {
        for bytes in [
            vec![],
            vec![17, 0, 0, 0],                                 // Too many results.
            vec![1, 0, 0, 0, 3, 255],                          // Truncated string length.
            vec![1, 0, 0, 0, 1, 2],                            // Invalid bool.
            vec![0, 0, 0, 0, 0],                               // Trailing bytes.
            vec![1, 0, 0, 0, 4, 255, 255, 255, 255],           // Impossible table count.
            vec![1, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], // Nil table key.
            vec![1, 0, 0, 0, 5], // Truncated native address (or unsupported tag).
            vec![1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0], // Null native address.
        ] {
            let (outcome, stats) = run(
                |_, _| Reply::owned(0, bytes.clone()),
                b"request(1,'x')",
                &Options::default(),
            );
            assert!(
                outcome
                    .unwrap_err()
                    .contains("invalid archive callback reply")
            );
            assert_released(&stats);
        }
    }

    #[test]
    fn c_decoder_preserves_signed_edges_binary_strings_and_table_keys() {
        let values = vec![
            Value::Nil,
            Value::Boolean(false),
            Value::Boolean(true),
            Value::Integer(i64::MIN),
            Value::Integer(i64::MAX),
            Value::String(vec![0, 255]),
            Value::Table(vec![
                (Value::Integer(-7), Value::Integer(42)),
                (Value::String(vec![0, 255]), Value::Boolean(true)),
            ]),
        ];
        let (outcome, stats) = run(
            move |_, _| OwnedReply::success(&values).into_reply(),
            br#"
            local a,b,c,d,e,f,g = request(1,'x', 'ignored extra argument')
            assert(a == nil and b == false and c == true)
            assert(d == math.mininteger and e == math.maxinteger)
            assert(f == string.char(0,255) and g[-7] == 42)
            assert(g[string.char(0,255)] == true)
        "#,
            &Options::default(),
        );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_released(&stats);
    }

    #[test]
    fn c_decoder_depth_boundary_matches_the_rust_encoder() {
        let mut value = Value::Integer(42);
        for _ in 1..32 {
            value = Value::Table(vec![(Value::Integer(1), value)]);
        }
        let (outcome, stats) = run(
            move |_, _| OwnedReply::success(std::slice::from_ref(&value)).into_reply(),
            b"local t=request(1,'x'); for i=1,31 do t=t[1] end; assert(t==42)",
            &Options::default(),
        );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_released(&stats);

        // Bypass the Rust encoder deliberately: 32 table parents put the leaf
        // at forbidden depth 33. C must independently reject and release it.
        let mut bytes = 1_u32.to_le_bytes().to_vec();
        for _ in 0..32 {
            bytes.push(4);
            bytes.extend_from_slice(&1_u32.to_le_bytes());
            bytes.push(2);
            bytes.extend_from_slice(&1_i64.to_le_bytes());
        }
        bytes.push(0);
        let (outcome, stats) = run(
            move |_, _| Reply::owned(0, bytes.clone()),
            b"request(1,'x')",
            &Options::default(),
        );
        assert!(
            outcome
                .unwrap_err()
                .contains("invalid archive callback reply")
        );
        assert_released(&stats);
    }

    #[test]
    fn bootstrap_gets_the_compiled_native_capability() {
        let bootstrap: &[u8] = if cfg!(feature = "linux-native") {
            b"local request,path,native=...; assert(type(request)=='function' and path=='paths' and native==true)"
        } else {
            b"local request,path,native=...; assert(type(request)=='function' and path=='paths' and native==false)"
        };
        let (outcome, stats) = execute_inner(
            |_, _| bytes_reply(),
            bootstrap,
            "paths",
            b"",
            "glue://test/entry.lua",
            &Options::default(),
        );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_released(&stats);
    }

    #[cfg(not(feature = "linux-native"))]
    #[test]
    fn source_only_decoder_rejects_nonnull_native_function_tags() {
        let mut bytes = 1_u32.to_le_bytes().to_vec();
        bytes.push(5);
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        let (outcome, stats) = run(
            move |_, _| Reply::owned(0, bytes.clone()),
            b"request(1,'x')",
            &Options::default(),
        );
        assert!(
            outcome
                .unwrap_err()
                .contains("invalid archive callback reply")
        );
        assert_released(&stats);
    }

    #[cfg(feature = "linux-native")]
    fn fixture_initializer_reply(variant: u32, trailing_string: bool) -> Reply {
        // SAFETY: the getter does not touch Lua or invoke the initializer. It
        // returns an address of a static C function whose code is process-live.
        // Production addresses come exclusively from native manager tokens.
        let address = unsafe { glue_lua_test_initializer(variant) };
        assert_ne!(address, 0);
        let mut bytes = (if trailing_string { 2_u32 } else { 1_u32 })
            .to_le_bytes()
            .to_vec();
        bytes.push(5);
        bytes.extend_from_slice(&address.to_le_bytes());
        if trailing_string {
            bytes.push(3);
            bytes.extend_from_slice(&8192_u32.to_le_bytes());
            bytes.extend_from_slice(&vec![b'x'; 8192]);
        }
        Reply::owned(0, bytes)
    }

    #[cfg(feature = "linux-native")]
    fn run_native_fixture(
        variant: u32,
        entry: &[u8],
        options: &Options,
    ) -> (Result<(), String>, RunResult) {
        execute_inner(
            move |operation, key| match operation {
                1 => {
                    assert_eq!(key, b"bridge.fixture");
                    fixture_initializer_reply(variant, false)
                }
                2 => {
                    assert_eq!(key, b"asset");
                    // The native initializer reply has already been released
                    // before Lua invokes the returned C function.
                    assert_eq!(owned_reply_count(), 0);
                    OwnedReply::success(&[Value::string(b"native asset")]).into_reply()
                }
                _ => panic!("unexpected fixture operation"),
            },
            br#"
                local req,path,native=...
                assert(native)
                request=req
                package.searchers={function(name)
                    return request(1,name),'glue://test/native/module.so'
                end}
            "#,
            "",
            entry,
            "glue://test/entry.lua",
            options,
        )
    }

    #[cfg(feature = "linux-native")]
    #[test]
    fn native_c_initializer_and_functions_run_after_reply_release() {
        let (outcome, stats) = run_native_fixture(
            0,
            br#"
            local module, origin = require('bridge.fixture')
            assert(origin == 'glue://test/native/module.so')
            assert(module.value == 42 and module.answer() == 42)
            assert(module.read() == 'native asset')
            assert(require('bridge.fixture') == module)
            local ok, message = pcall(module.fail)
            assert(not ok and message:find('native fixture function error', 1, true))
        "#,
            &Options::default(),
        );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(
            stats.callbacks, 2,
            "require must cache the initializer result"
        );
        assert_released(&stats);
    }

    #[cfg(feature = "linux-native")]
    #[test]
    fn native_c_initializer_and_function_errors_return_normally() {
        for (variant, source, expected) in [
            (
                1,
                b"require('bridge.fixture')".as_slice(),
                "native fixture initializer error",
            ),
            (
                0,
                b"require('bridge.fixture').fail()".as_slice(),
                "native fixture function error",
            ),
        ] {
            let (outcome, stats) = run_native_fixture(variant, source, &Options::default());
            assert!(outcome.unwrap_err().contains(expected));
            assert_eq!(stats.callbacks, 1);
            assert_released(&stats);
        }
    }

    #[cfg(feature = "linux-native")]
    #[test]
    fn native_c_initializer_oom_has_no_live_rust_reply() {
        let (outcome, stats) = run_native_fixture(
            0,
            b"require('bridge.fixture')",
            &Options {
                fail_after_reply_allocations: 0,
                ..Options::default()
            },
        );
        assert!(outcome.is_err(), "native table allocation must fail");
        assert_eq!(stats.callbacks, 1);
        assert_released(&stats);
    }

    #[cfg(feature = "linux-native")]
    #[test]
    fn native_function_marshalling_oom_releases_the_owned_reply() {
        let (outcome, stats) = run(
            |_, _| fixture_initializer_reply(0, true),
            b"request(1,'x')",
            &Options {
                fail_after_reply_allocations: 0,
                ..Options::default()
            },
        );
        assert!(
            outcome.is_err(),
            "string after native function must allocate"
        );
        assert_eq!(stats.callbacks, 1);
        assert_released(&stats);
    }
}
