//! Minimal Node-API 1 bridge. No Node headers, V8 ABI or libnode dependency.
//! Every foreign boundary catches unwinds; successful reads copy verified bytes.
use glue_format::Archive;
use std::{
    ffi::{CString, c_char, c_void},
    fs::File,
    ptr,
};
type Env = *mut c_void;
type Value = *mut c_void;
type Info = *mut c_void;
type Callback = unsafe extern "C" fn(Env, Info) -> Value;
type Finalize = unsafe extern "C" fn(Env, *mut c_void, *mut c_void);
unsafe extern "C" {
    fn napi_get_cb_info(
        e: Env,
        i: Info,
        n: *mut usize,
        a: *mut Value,
        this: *mut Value,
        data: *mut *mut c_void,
    ) -> i32;
    fn napi_get_value_string_utf8(
        e: Env,
        v: Value,
        p: *mut c_char,
        len: usize,
        n: *mut usize,
    ) -> i32;
    fn napi_create_external(
        e: Env,
        p: *mut c_void,
        f: Option<Finalize>,
        hint: *mut c_void,
        out: *mut Value,
    ) -> i32;
    fn napi_get_value_external(e: Env, v: Value, out: *mut *mut c_void) -> i32;
    fn napi_type_tag_object(e: Env, v: Value, tag: *const TypeTag) -> i32;
    fn napi_check_object_type_tag(e: Env, v: Value, tag: *const TypeTag, result: *mut bool) -> i32;
    fn napi_create_buffer_copy(
        e: Env,
        len: usize,
        p: *const c_void,
        data: *mut *mut c_void,
        out: *mut Value,
    ) -> i32;
    fn napi_create_string_utf8(e: Env, p: *const c_char, len: usize, out: *mut Value) -> i32;
    fn napi_create_function(
        e: Env,
        name: *const c_char,
        len: usize,
        cb: Option<Callback>,
        data: *mut c_void,
        out: *mut Value,
    ) -> i32;
    fn napi_set_named_property(e: Env, obj: Value, name: *const c_char, v: Value) -> i32;
    fn napi_throw_error(e: Env, code: *const c_char, text: *const c_char) -> i32;
}
#[repr(C)]
struct TypeTag {
    lower: u64,
    upper: u64,
}
static ARCHIVE_TAG: TypeTag = TypeTag {
    lower: 0xc9ab539423f26a8d,
    upper: 0x24cfc74d88d749fb,
};
fn check(status: i32) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!("Node-API status {status}"))
    }
}
unsafe fn text(e: Env, v: Value) -> Result<String, String> {
    let mut len = 0;
    check(unsafe { napi_get_value_string_utf8(e, v, ptr::null_mut(), 0, &mut len) })?;
    if len > 4096 {
        return Err("path exceeds 4096 UTF-8 bytes".into());
    }
    let mut bytes = vec![0_u8; len + 1];
    check(unsafe {
        napi_get_value_string_utf8(e, v, bytes.as_mut_ptr().cast(), bytes.len(), &mut len)
    })?;
    bytes.truncate(len);
    if bytes.contains(&0) {
        return Err("NUL in path".into());
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}
unsafe fn args<const N: usize>(e: Env, i: Info) -> Result<[Value; N], String> {
    let mut a = [ptr::null_mut(); N];
    let mut n = N;
    check(unsafe {
        napi_get_cb_info(
            e,
            i,
            &mut n,
            a.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    })?;
    if n != N {
        return Err(format!("expected {N} arguments"));
    }
    Ok(a)
}
// Node-API external values need a type tag before their raw pointer is trusted.
unsafe fn archive(e: Env, v: Value) -> Result<*mut Archive<File>, String> {
    let mut valid = false;
    check(unsafe { napi_check_object_type_tag(e, v, &ARCHIVE_TAG, &mut valid) })?;
    if !valid {
        return Err("expected glue archive handle".into());
    }
    let mut p = ptr::null_mut();
    check(unsafe { napi_get_value_external(e, v, &mut p) })?;
    if p.is_null() {
        return Err("null archive handle".into());
    }
    Ok(p.cast())
}
unsafe fn boundary(e: Env, f: impl FnOnce() -> Result<Value, String>) -> Value {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        result => {
            let message = match result {
                Ok(Err(message)) => message,
                _ => "Rust archive bridge panic".into(),
            };
            let message = CString::new(message.replace('\0', "?")).unwrap();
            unsafe {
                napi_throw_error(e, c"ERR_GLUE_ARCHIVE".as_ptr(), message.as_ptr());
            }
            ptr::null_mut()
        }
    }
}
unsafe extern "C" fn finalize(_: Env, data: *mut c_void, _: *mut c_void) {
    if !data.is_null() {
        drop(unsafe { Box::from_raw(data.cast::<Archive<File>>()) });
    }
}
unsafe extern "C" fn open(e: Env, i: Info) -> Value {
    unsafe {
        boundary(e, || {
            let [path] = args(e, i)?;
            let file = File::open(text(e, path)?).map_err(|e| e.to_string())?;
            let archive = Box::new(Archive::open(file).map_err(|e| e.to_string())?);
            let p = Box::into_raw(archive);
            let mut out = ptr::null_mut();
            if let Err(err) = check(napi_create_external(
                e,
                p.cast(),
                Some(finalize),
                ptr::null_mut(),
                &mut out,
            )) {
                drop(Box::from_raw(p));
                return Err(err);
            }
            check(napi_type_tag_object(e, out, &ARCHIVE_TAG))?;
            Ok(out)
        })
    }
}
unsafe extern "C" fn read(e: Env, i: Info) -> Value {
    unsafe {
        boundary(e, || {
            let [handle, path] = args(e, i)?;
            let bytes = (&mut *archive(e, handle)?)
                .read_resource(&text(e, path)?)
                .map_err(|e| e.to_string())?;
            let mut out = ptr::null_mut();
            check(napi_create_buffer_copy(
                e,
                bytes.len(),
                bytes.as_ptr().cast(),
                ptr::null_mut(),
                &mut out,
            ))?;
            Ok(out)
        })
    }
}
unsafe extern "C" fn list(e: Env, i: Info) -> Value {
    unsafe {
        boundary(e, || {
            let [handle] = args(e, i)?;
            let entries = (&*archive(e, handle)?).entries();
            let paths: Vec<_> = entries.keys().collect();
            let json = serde_json::to_string(&paths).map_err(|e| e.to_string())?;
            let mut out = ptr::null_mut();
            check(napi_create_string_utf8(
                e,
                json.as_ptr().cast(),
                json.len(),
                &mut out,
            ))?;
            Ok(out)
        })
    }
}
// Object type tags are Node-API 8. Explicitly advertise the bridge minimum.
#[unsafe(no_mangle)]
pub extern "C" fn node_api_module_get_api_version_v1() -> i32 {
    8
}
/// # Safety
/// Called by Node with its live environment and exports object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn napi_register_module_v1(e: Env, exports: Value) -> Value {
    unsafe {
        boundary(e, || {
            for (name, cb) in [
                (c"open", open as Callback),
                (c"read", read as Callback),
                (c"list", list as Callback),
            ] {
                let mut value = ptr::null_mut();
                check(napi_create_function(
                    e,
                    name.as_ptr(),
                    name.to_bytes().len(),
                    Some(cb),
                    ptr::null_mut(),
                    &mut value,
                ))?;
                check(napi_set_named_property(e, exports, name.as_ptr(), value))?;
            }
            Ok(exports)
        })
    }
}
