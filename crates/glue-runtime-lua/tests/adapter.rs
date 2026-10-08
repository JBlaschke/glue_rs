use glue_format::{Archive, Compression, Manifest, ResourceSpec, digest, write_archive};
use glue_resources::Resources;
use glue_runtime_lua::execute;
use std::{
    collections::BTreeMap,
    io::Cursor,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

fn fixture(files: &[(&str, &[u8])]) -> (Manifest, Vec<u8>) {
    let mut manifest =
        Manifest::from_json(include_bytes!("../../../fixtures/resources/manifest.json")).unwrap();
    manifest.app_id = "lua.fixture".to_owned();
    let contents: BTreeMap<_, _> = files
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec()))
        .collect();
    manifest.resources = contents
        .iter()
        .map(|(path, bytes)| {
            (
                path.clone(),
                ResourceSpec {
                    size: bytes.len() as u64,
                    sha256: digest(bytes),
                    compression: Compression::Stored,
                },
            )
        })
        .collect();
    let bytes = write_archive(Cursor::new(Vec::new()), &manifest, &contents)
        .unwrap()
        .into_inner();
    (manifest, bytes)
}

fn resources(bytes: Vec<u8>) -> Resources<Cursor<Vec<u8>>> {
    Resources::with_default_cache(Archive::open(Cursor::new(bytes)).unwrap())
}

fn run(files: &[(&str, &[u8])]) -> mlua::Result<()> {
    execute(resources(fixture(files).1), "app/main.lua")
}

#[test]
fn interpreter_matches_the_compiled_profile() {
    let source = format!(
        "assert(_VERSION == {:?})",
        glue_runtime_lua::profile::LUA_VERSION
    );
    run(&[("app/main.lua", source.as_bytes())]).unwrap();
}

#[cfg(feature = "lua55")]
#[test]
fn lua55_named_vararg_tables_and_global_declarations_execute() {
    run(&[(
        "app/main.lua",
        br#"
        global assert, result
        local function collect(...values)
            assert(values.n == 3 and values[1] == 7 and values[2] == nil and values[3] == 35)
            return values[1] + values[3]
        end
        result = collect(7, nil, 35)
        assert(result == 42)
    "#,
    )])
    .unwrap();
}

#[test]
fn real_lua_nested_imports_cache_and_preload_keep_require_semantics() {
    run(&[
        (
            "app/main.lua",
            br#"
            assert(_VERSION == "Lua 5.4" or _VERSION == "Lua 5.5")
            local first, origin = require("outer")
            assert(first.answer == 42)
            assert(origin == "glue://lua.fixture/app/outer.lua")
            local second, cached_origin = require("outer")
            assert(first == second and cached_origin == nil)
            assert(inner_loads == 1 and outer_loads == 1)
            package.preload.preloaded = function(name, where)
                assert(name == "preloaded" and where == ":preload:")
                return 7
            end
            assert(require("preloaded") == 7)
            assert(require("glue") == glue)
        "#,
        ),
        (
            "app/outer.lua",
            br#"
            outer_loads = (outer_loads or 0) + 1
            local inner = require("nested.inner")
            return { answer = inner.answer + 7 }
        "#,
        ),
        (
            "app/nested/inner.lua",
            br#"
            inner_loads = (inner_loads or 0) + 1
            assert(glue.read("assets/value") == "35")
            return { answer = 35 }
        "#,
        ),
        ("assets/value", b"35"),
    ])
    .unwrap();
}

#[test]
fn archive_source_resolution_supports_init_and_prefers_direct_file() {
    run(&[
        (
            "app/main.lua",
            br#"
            assert(require("choice") == "direct")
            local value, origin = require("nested.package")
            assert(value == "init")
            assert(origin == "glue://lua.fixture/app/nested/package/init.lua")
        "#,
        ),
        ("app/choice.lua", b"return 'direct'"),
        ("app/choice/init.lua", b"error('wrong resolution order')"),
        ("app/nested/package/init.lua", b"return 'init'"),
    ])
    .unwrap();
}

#[test]
fn assets_are_binary_and_metadata_and_origins_are_virtual() {
    run(&[
        ("app/main.lua", br#"
            local bytes = glue.read("assets/a b%#x.bin")
            assert(#bytes == 4 and bytes == "a\0b\255")
            assert(glue.origin("assets/a b%#x.bin") == "glue://lua.fixture/assets/a%20b%25%23x.bin")
            local metadata = glue.stat("assets/a b%#x.bin")
            assert(metadata.kind == "file" and metadata.size == 4 and metadata.compression == "stored")
            assert(glue.stat("assets").kind == "directory")
            local children = glue.list("")
            assert(#children == 2 and children[1].name == "app" and children[2].name == "assets")
            assert(glue.list("assets")[1].path == "assets/a b%#x.bin")
        "#),
        ("assets/a b%#x.bin", b"a\0b\xff"),
    ]).unwrap();
}

#[test]
fn loadfile_and_dofile_use_verified_archive_source_and_preserve_results() {
    run(&[
        (
            "app/main.lua",
            br#"
            local chunk, message = loadfile("app/environment.lua", "t", { value = 19 })
            assert(type(chunk) == "function" and message == nil and chunk() == 19)
            assert(select('#', loadfile("app/environment.lua")) == 1)
            local a, b, c = dofile("app/results.lua")
            assert(a == 42 and b == "value" and c == false)
            assert(load("return value", "=dynamic", "t", { value = 7 })() == 7)
            local missing, error = loadfile("app/missing.lua")
            assert(missing == nil and error:find("resource does not exist", 1, true))
            assert(loadfile() == nil)
            assert(not pcall(dofile))
        "#,
        ),
        ("app/environment.lua", b"return value"),
        ("app/results.lua", b"return 42, 'value', false"),
    ])
    .unwrap();
}

#[test]
fn load_and_loadfile_preserve_omitted_nil_table_and_non_table_environments() {
    run(&[
        (
            "app/main.lua",
            br#"
            assert(load("return _ENV")() == _G)
            assert(load("return _ENV", nil, nil)() == _G)
            assert(loadfile("app/environment.lua")() == _G)
            assert(loadfile("app/environment.lua", nil)() == _G)

            assert(load("return _ENV", "=nil-env", "t", nil)() == nil)
            assert(loadfile("app/environment.lua", "t", nil)() == nil)

            local environment = { value = 19 }
            assert(load("return _ENV", "=table-env", "t", environment)() == environment)
            assert(loadfile("app/environment.lua", "t", environment)() == environment)
            assert(load("return value", "=table-env", "t", environment)() == 19)

            for _, value in ipairs({42, false, "raw environment", function() return 7 end}) do
                assert(load("return _ENV", "=raw-env", "t", value)() == value)
                assert(loadfile("app/environment.lua", "t", value)() == value)
            end
        "#,
        ),
        ("app/environment.lua", b"return _ENV"),
    ])
    .unwrap();
}

#[test]
fn explicit_nil_environment_errors_keep_virtual_archive_origins() {
    run(&[
        (
            "app/main.lua",
            br#"
            assert(loadfile("app/global.lua")() == 1)
            local isolated = assert(loadfile("app/global.lua", "t", nil))
            local ok, message = pcall(isolated)
            assert(not ok and message:find("glue://lua.fixture/app/global.lua", 1, true))
            local chunk, syntax = loadfile("app/broken.lua", "t", nil)
            assert(chunk == nil and syntax:find("glue://lua.fixture/app/broken.lua", 1, true))
            local loaded, dynamic_syntax = load("local = invalid", "=dynamic-nil-env", "t", nil)
            assert(loaded == nil and dynamic_syntax:find("dynamic-nil-env", 1, true))
        "#,
        ),
        ("app/global.lua", b"return math.abs(-1)"),
        ("app/broken.lua", b"local = invalid"),
    ])
    .unwrap();
}

#[test]
fn runtime_and_syntax_errors_name_virtual_sources() {
    let error = run(&[
        ("app/main.lua", b"require('broken')"),
        (
            "app/broken.lua",
            b"local function fail() error('module failure') end; fail()",
        ),
    ])
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("glue://lua.fixture/app/broken.lua"),
        "{error}"
    );
    assert!(error.contains("glue://lua.fixture/app/main.lua"), "{error}");
    assert!(error.contains("module failure"), "{error}");
    let error = run(&[
        ("app/main.lua", b"require('broken')"),
        ("app/broken.lua", b"local = invalid"),
    ])
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("glue://lua.fixture/app/broken.lua"),
        "{error}"
    );
}

#[test]
fn bytecode_is_rejected_on_entry_import_loadfile_dofile_and_load() {
    let error = run(&[("app/main.lua", b"\x1bLua\0invalid")])
        .unwrap_err()
        .to_string();
    assert!(error.contains("binary chunk"), "{error}");
    let error = run(&[
        ("app/main.lua", b"require('binary')"),
        ("app/binary.lua", b"\x1bLua\0invalid"),
    ])
    .unwrap_err()
    .to_string();
    assert!(error.contains("binary chunk"), "{error}");
    run(&[
        (
            "app/main.lua",
            br#"
            local result, message = loadfile("app/binary.lua")
            assert(result == nil and message:find("binary chunk", 1, true))
            assert(not pcall(dofile, "app/binary.lua"))
            local bytecode = string.dump(function() return 42 end)
            local f, error = load(bytecode)
            assert(f == nil and error:find("binary chunk", 1, true))
            assert(load("return 42", nil, "b") == nil)
            assert(load("return 42", nil, "bt") == nil)
            assert(loadfile("app/main.lua", "b") == nil)
            local reads = 0
            local f, error = load(function() reads = reads + 1; return "return 42" end)
            assert(f == nil and reads == 0 and error:find("reader functions", 1, true))
        "#,
        ),
        ("app/binary.lua", b"\x1bLua\0invalid"),
    ])
    .unwrap();
}

#[test]
fn unsupported_filesystem_and_native_surfaces_are_unavailable() {
    run(&[("app/main.lua", br#"
        assert(io == nil and os == nil and debug == nil)
        assert(package.loaded.io == nil and package.loaded.os == nil and package.loaded.debug == nil)
        assert(#package.searchers == 2 and package.searchpath == nil and package.cpath == "")
        assert(package.path:find("glue://lua.fixture/app/?.lua", 1, true))
        local ok, error = pcall(package.loadlib, "/host/library.so", "luaopen_example")
        assert(not ok and tostring(error):find("unsupported", 1, true))
        assert(loadfile("/etc/passwd") == nil)
        assert(not pcall(dofile, "/etc/passwd"))
        assert(not pcall(require, "io"))
        assert(not pcall(require, "os"))
    "#)]).unwrap();
}

#[test]
fn archive_paths_and_module_names_reject_traversal_and_aliases() {
    run(&[("app/main.lua", br#"
        for _, name in ipairs({"../escape", "foo..bar", "foo/bar", "foo\\bar", ".foo", "foo.", "", "foo\0bar", "glue\0alias"}) do
            local ok, error = pcall(require, name)
            assert(not ok and tostring(error):find("invalid archive module name", 1, true))
        end
        for _, path in ipairs({"../escape", "app/../main.lua", "./app/main.lua", "/app/main.lua", "app\\main.lua"}) do
            assert(not pcall(glue.read, path))
            assert(not pcall(glue.origin, path))
            assert(loadfile(path) == nil)
        end
        assert(loadfile("app") == nil)
    "#)]).unwrap();
}

#[test]
fn present_host_source_cannot_supply_a_missing_archive_import() {
    let directory = TempDirectory::new();
    std::fs::write(
        directory.0.join("hostonly.lua"),
        b"error('HOST SOURCE EXECUTED')",
    )
    .unwrap();
    let path = directory.0.to_str().unwrap().replace('\\', "/");
    let source = format!(
        r#"
        package.path = [[{path}/?.lua]]
        package.cpath = [[{path}/?.so]]
        local ok, error = pcall(require, "hostonly")
        assert(not ok and tostring(error):find("no archive module", 1, true))
        assert(not tostring(error):find("HOST SOURCE EXECUTED", 1, true))
    "#
    );
    run(&[("app/main.lua", source.as_bytes())]).unwrap();
}

fn wrong_declared_hash(mut manifest: Manifest, mut bytes: Vec<u8>, path: &str) -> Vec<u8> {
    manifest.resources.get_mut(path).unwrap().sha256 = digest(b"different bytes");
    let json = manifest.to_json().unwrap();
    let manifest_length = u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize;
    assert_eq!(json.len(), manifest_length);
    bytes[64..64 + manifest_length].copy_from_slice(&json);
    let hash = digest(&json);
    for index in 0..32 {
        bytes[32 + index] = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

#[test]
fn hash_mismatch_stops_entry_and_import_before_their_source_executes() {
    let (manifest, bytes) = fixture(&[("app/main.lua", b"error('ENTRY EXECUTED')")]);
    let error = execute(
        resources(wrong_declared_hash(manifest, bytes, "app/main.lua")),
        "app/main.lua",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("SHA-256"), "{error}");
    assert!(!error.contains("ENTRY EXECUTED"), "{error}");
    let (manifest, bytes) = fixture(&[
        ("app/main.lua", b"require('corrupt')"),
        ("app/corrupt.lua", b"error('MODULE EXECUTED')"),
    ]);
    let error = execute(
        resources(wrong_declared_hash(manifest, bytes, "app/corrupt.lua")),
        "app/main.lua",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("SHA-256"), "{error}");
    assert!(!error.contains("MODULE EXECUTED"), "{error}");
}

#[test]
fn no_resource_cache_budget_is_needed_for_recursive_imports() {
    let (_, bytes) = fixture(&[
        ("app/main.lua", b"assert(require('outer') == 42)"),
        (
            "app/outer.lua",
            b"return require('inner') + #glue.read('assets/bytes')",
        ),
        ("app/inner.lua", b"return 40"),
        ("assets/bytes", b"ok"),
    ]);
    execute(
        Resources::new(Archive::open(Cursor::new(bytes)).unwrap(), 0),
        "app/main.lua",
    )
    .unwrap();
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "glue-lua-host-source-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
