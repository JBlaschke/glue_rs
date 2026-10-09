fixture_seed = 123
fixture_init_error = 0
local native, origin = require("native_probe")
assert(origin == (fixture_baseline and ":preload:" or "glue://native-lua-demo/native/libglue_lua_native.so"))
assert(native.answer() == 42 and native.data == 7 and native.constructors == 1)
assert(native.initializers == 1 and native.pid > 0)
assert(native.version_num == (_VERSION == "Lua 5.4" and 504 or 505))
assert(native_observed_seed == 124)
local cached, cached_origin = require("native_probe")
assert(cached == native and cached_origin == nil)

local ok, message = pcall(native.fail)
assert(not ok and message:find("native function failure", 1, true))
fixture_init_error = 1
package.loaded.native_probe = nil
local initialized, diagnostic = pcall(require, "native_probe")
assert(not initialized and diagnostic:find("native initializer failure", 1, true))
fixture_init_error = 0
local retried = require("native_probe")
assert(retried.answer() == 42 and retried.constructors == 1 and retried.initializers == 3)
assert(native_observed_seed == 124)
assert(glue.read("assets/message.txt") == "archived native asset\n")
if not fixture_baseline then
    assert(type(package.loadlib("native/libglue_lua_native.so", "luaopen_native_probe")) == "function")
    for _, symbol in ipairs({"", "*", "luaopen_other", "luaopen_native_probe\0alias"}) do
        assert(not pcall(package.loadlib, "native/libglue_lua_native.so", symbol))
    end
    assert(not pcall(package.loadlib, "/tmp/libglue_lua_native.so", "luaopen_native_probe"))
    assert(not pcall(package.loadlib, "native/libglue_lua_dep.so", "luaopen_native_probe"))
end
print(_VERSION .. " native answer=42 data=7 constructors=1 state=" .. native_observed_seed ..
      " pid=" .. retried.pid .. " errors=2")
