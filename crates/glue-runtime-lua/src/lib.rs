//! Official Lua linked into the launcher, with verified archive source imports.
//!
//! This first execution profile intentionally omits `io`, `os`, and `debug`.
//! `require` searches only `app/?.lua` and `app/?/init.lua`; `loadfile` and
//! `dofile` accept canonical archive keys. `load` accepts source strings only.
//! These restrictions are an initial compatibility profile, not a sandbox or
//! the final policy for applications' ordinary host I/O. Native loading is not
//! implemented here. The caller must validate runtime provisioning and target
//! compatibility before execution.

pub mod profile;

#[cfg(all(feature = "lua54", feature = "lua55"))]
compile_error!("select exactly one linked Lua profile: lua54 or lua55");
#[cfg(not(any(feature = "lua54", feature = "lua55")))]
compile_error!("select a linked Lua profile: lua54 or lua55");

use glue_format::{Compression, ResourcePath};
use glue_resources::{EntryKind, Metadata, ResourceError, Resources};
use mlua::{Function, Lua, LuaOptions, MultiValue, StdLib, Table, Value, chunk::ChunkMode};
use std::{
    cell::RefCell,
    io::{Read, Seek},
    rc::Rc,
    sync::Arc,
};

type SharedResources<R> = Rc<RefCell<Resources<R>>>;

/// Execute one verified archive source chunk in the restricted linked profile.
///
/// Entry return values are discarded. Errors retain virtual `glue://` source
/// names; no source or asset is materialized as a host file.
pub fn execute<R: Read + Seek + 'static>(
    resources: Resources<R>,
    entry_point: &str,
) -> mlua::Result<()> {
    ResourcePath::new(entry_point).map_err(mlua::Error::external)?;
    let resources = Rc::new(RefCell::new(resources));
    let lua = Lua::new_with(
        StdLib::COROUTINE
            | StdLib::TABLE
            | StdLib::STRING
            | StdLib::MATH
            | StdLib::UTF8
            | StdLib::PACKAGE,
        LuaOptions::default(),
    )?;
    install_imports(&lua, Rc::clone(&resources))?;
    install_loading(&lua, Rc::clone(&resources))?;
    install_assets(&lua, Rc::clone(&resources))?;
    let (bytes, origin) = read_verified(&resources, entry_point)?;
    compile(&lua, &bytes, &origin)?.call(())
}

fn install_imports<R: Read + Seek + 'static>(
    lua: &Lua,
    resources: SharedResources<R>,
) -> mlua::Result<()> {
    let package: Table = lua.globals().get("package")?;
    let old_searchers: Table = package.get("searchers")?;
    let preload: Function = old_searchers.raw_get(1)?;
    let app_id = resources
        .try_borrow()
        .map_err(mlua::Error::external)?
        .manifest()
        .app_id
        .clone();
    let archive_searcher = lua.create_function(move |lua, name: String| {
        let candidates = match module_candidates(&name) {
            Ok(candidates) => candidates,
            Err(message) => return one_string(lua, format!("\n\t{message}")),
        };
        let selected = {
            let borrowed = resources.try_borrow().map_err(mlua::Error::external)?;
            let mut selected = None;
            for path in &candidates {
                match borrowed.stat(path) {
                    Ok(metadata) if metadata.is_file() => {
                        selected = Some(path.clone());
                        break;
                    }
                    Ok(_) | Err(ResourceError::NotFound(_)) => {}
                    Err(error) => return Err(mlua::Error::external(error)),
                }
            }
            selected
        };
        let Some(path) = selected else {
            return one_string(
                lua,
                format!(
                    "\n\tno archive module {name:?} ({} or {})",
                    candidates[0], candidates[1]
                ),
            );
        };
        let origin = origin_for(&resources, &path)?;
        let loader_resources = Rc::clone(&resources);
        let loader = lua.create_function(move |lua, arguments: MultiValue| {
            let (bytes, origin) = read_verified(&loader_resources, &path)?;
            // The resource borrow ended before compilation or any Lua call.
            compile(lua, &bytes, &origin)?.call::<MultiValue>(arguments)
        })?;
        Ok(MultiValue::from_vec(vec![
            Value::Function(loader),
            Value::String(lua.create_string(origin)?),
        ]))
    })?;
    let searchers = lua.create_table()?;
    searchers.raw_set(1, preload)?;
    searchers.raw_set(2, archive_searcher)?;
    package.raw_set("searchers", searchers)?;
    // Informational templates only: archive resolution never uses mutable paths.
    package.raw_set(
        "path",
        format!("glue://{app_id}/app/?.lua;glue://{app_id}/app/?/init.lua"),
    )?;
    package.raw_set("cpath", "")?;
    package.raw_set("searchpath", Value::Nil)?;
    package.raw_set(
        "loadlib",
        lua.create_function(|_, _: MultiValue| -> mlua::Result<()> {
            Err(mlua::Error::runtime(
                "native Lua loading is unsupported by the linked source profile",
            ))
        })?,
    )?;
    // Lua's C require implementation treats names as NUL-terminated strings.
    // Validate the complete input first so an embedded NUL cannot alias a
    // different cached/preloaded module. Upstream require still owns loading
    // and cache semantics, including its optional loader-data return value.
    let require: Function = lua.globals().get("require")?;
    lua.globals().raw_set(
        "require",
        lua.create_function(move |_, name: String| {
            module_candidates(&name).map_err(mlua::Error::runtime)?;
            require.call::<MultiValue>(name)
        })?,
    )?;
    Ok(())
}

fn install_loading<R: Read + Seek + 'static>(
    lua: &Lua,
    resources: SharedResources<R>,
) -> mlua::Result<()> {
    // Retain the original source compiler, never the host-file loader. Its
    // protected Lua call preserves explicit nil/non-table _ENV values and
    // distinguishes an omitted environment from an explicitly supplied nil.
    let original_load: Function = lua.globals().get("load")?;
    let file_load = original_load.clone();
    let file_resources = Rc::clone(&resources);
    let loadfile = lua.create_function(move |lua, mut arguments: MultiValue| {
        let path: Option<String> = lua.unpack(arguments.pop_front().unwrap_or(Value::Nil))?;
        let mode: Option<String> = lua.unpack(arguments.pop_front().unwrap_or(Value::Nil))?;
        let environment = arguments.pop_front();
        let loaded = (|| {
            source_mode(mode.as_deref())?;
            let path = path.ok_or_else(|| {
                mlua::Error::runtime(
                    "loadfile requires an archive resource key; stdin is unsupported",
                )
            })?;
            let (bytes, origin) = read_verified(&file_resources, &path)?;
            load_text(
                lua,
                &file_load,
                lua.create_string(bytes.as_ref())?,
                format!("@{origin}"),
                environment,
            )
        })();
        loading_result(lua, loaded)
    })?;
    lua.globals().raw_set("loadfile", loadfile)?;
    lua.globals().raw_set(
        "dofile",
        lua.create_function(move |lua, path: Option<String>| {
            let path = path.ok_or_else(|| {
                mlua::Error::runtime(
                    "dofile requires an archive resource key; stdin is unsupported",
                )
            })?;
            let (bytes, origin) = read_verified(&resources, &path)?;
            compile(lua, &bytes, &origin)?.call::<MultiValue>(())
        })?,
    )?;
    lua.globals().raw_set(
        "load",
        lua.create_function(move |lua, mut arguments: MultiValue| {
            let source = arguments.pop_front().unwrap_or(Value::Nil);
            let name: Option<String> = lua.unpack(arguments.pop_front().unwrap_or(Value::Nil))?;
            let mode: Option<String> = lua.unpack(arguments.pop_front().unwrap_or(Value::Nil))?;
            let environment = arguments.pop_front();
            let loaded = (|| {
                source_mode(mode.as_deref())?;
                let Value::String(source) = source else {
                    return Err(mlua::Error::runtime(
                        "load accepts a source string only; reader functions are unsupported",
                    ));
                };
                load_text(
                    lua,
                    &original_load,
                    source,
                    name.unwrap_or_else(|| "=(load)".to_owned()),
                    environment,
                )
            })();
            loading_result(lua, loaded)
        })?,
    )?;
    Ok(())
}

fn load_text(
    lua: &Lua,
    original_load: &Function,
    source: mlua::LuaString,
    name: String,
    environment: Option<Value>,
) -> mlua::Result<MultiValue> {
    let mut arguments = MultiValue::from_vec(vec![
        Value::String(source),
        Value::String(lua.create_string(name)?),
        Value::String(lua.create_string("t")?),
    ]);
    if let Some(environment) = environment {
        arguments.push_back(environment);
    }
    original_load.call(arguments)
}

fn install_assets<R: Read + Seek + 'static>(
    lua: &Lua,
    resources: SharedResources<R>,
) -> mlua::Result<()> {
    let glue = lua.create_table()?;
    let read_resources = Rc::clone(&resources);
    glue.raw_set(
        "read",
        lua.create_function(move |lua, path: String| {
            let bytes = read_resources
                .try_borrow_mut()
                .map_err(mlua::Error::external)?
                .read(&path)
                .map_err(mlua::Error::external)?;
            lua.create_string(bytes.as_ref())
        })?,
    )?;
    let origin_resources = Rc::clone(&resources);
    glue.raw_set(
        "origin",
        lua.create_function(move |_, path: String| origin_for(&origin_resources, &path))?,
    )?;
    let stat_resources = Rc::clone(&resources);
    glue.raw_set(
        "stat",
        lua.create_function(move |lua, path: String| {
            let metadata = stat_resources
                .try_borrow()
                .map_err(mlua::Error::external)?
                .stat(&path)
                .map_err(mlua::Error::external)?;
            metadata_table(lua, metadata)
        })?,
    )?;
    glue.raw_set(
        "list",
        lua.create_function(move |lua, path: String| {
            let entries = resources
                .try_borrow()
                .map_err(mlua::Error::external)?
                .list(&path)
                .map_err(mlua::Error::external)?;
            let result = lua.create_table()?;
            for (index, entry) in entries.into_iter().enumerate() {
                let row = metadata_table(lua, entry.metadata)?;
                row.raw_set("name", entry.name)?;
                row.raw_set("path", entry.path)?;
                result.raw_set(index + 1, row)?;
            }
            Ok(result)
        })?,
    )?;
    lua.register_module("glue", glue.clone())?;
    lua.globals().raw_set("glue", glue)
}

fn module_candidates(name: &str) -> Result<[String; 2], String> {
    if name.is_empty()
        || name.len() > 4096
        || name.split('.').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        })
    {
        return Err(format!(
            "invalid archive module name {name:?}; use dot-separated ASCII letters, digits, underscores or hyphens"
        ));
    }
    let stem = name.replace('.', "/");
    let candidates = [format!("app/{stem}.lua"), format!("app/{stem}/init.lua")];
    for path in &candidates {
        ResourcePath::new(path).map_err(|error| error.to_string())?;
    }
    Ok(candidates)
}

fn source_mode(mode: Option<&str>) -> mlua::Result<()> {
    if mode.is_some_and(|mode| mode != "t") {
        return Err(mlua::Error::runtime(
            "only text mode ('t') is supported by the linked source profile",
        ));
    }
    Ok(())
}

fn compile(lua: &Lua, bytes: &[u8], origin: &str) -> mlua::Result<Function> {
    lua.load(bytes)
        .set_name(format!("@{origin}"))
        .set_mode(ChunkMode::Text)
        .into_function()
}

fn read_verified<R: Read + Seek>(
    resources: &SharedResources<R>,
    path: &str,
) -> mlua::Result<(Arc<[u8]>, String)> {
    let mut borrowed = resources.try_borrow_mut().map_err(mlua::Error::external)?;
    let bytes = borrowed.read(path).map_err(mlua::Error::external)?;
    let origin = resource_origin(&borrowed.manifest().app_id, path);
    Ok((bytes, origin))
}

fn origin_for<R: Read + Seek>(resources: &SharedResources<R>, path: &str) -> mlua::Result<String> {
    let borrowed = resources.try_borrow().map_err(mlua::Error::external)?;
    borrowed.stat(path).map_err(mlua::Error::external)?;
    Ok(resource_origin(&borrowed.manifest().app_id, path))
}

fn resource_origin(app_id: &str, path: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut origin = format!("glue://{app_id}/");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            origin.push(char::from(byte));
        } else {
            origin.push('%');
            origin.push(char::from(HEX[usize::from(byte >> 4)]));
            origin.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    origin
}

fn loading_result(lua: &Lua, loaded: mlua::Result<MultiValue>) -> mlua::Result<MultiValue> {
    match loaded {
        Ok(result) => Ok(result),
        Err(error) => Ok(MultiValue::from_vec(vec![
            Value::Nil,
            Value::String(lua.create_string(error.to_string())?),
        ])),
    }
}

fn one_string(lua: &Lua, message: String) -> mlua::Result<MultiValue> {
    Ok(MultiValue::from_vec(vec![Value::String(
        lua.create_string(message)?,
    )]))
}

fn metadata_table(lua: &Lua, metadata: Metadata) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.raw_set(
        "kind",
        match metadata.kind {
            EntryKind::File => "file",
            EntryKind::Directory => "directory",
        },
    )?;
    table.raw_set("size", metadata.size)?;
    table.raw_set("compressed_size", metadata.compressed_size)?;
    table.raw_set(
        "compression",
        metadata.compression.map(|compression| match compression {
            Compression::Stored => "stored",
            Compression::Deflate => "deflate",
        }),
    )?;
    Ok(table)
}
