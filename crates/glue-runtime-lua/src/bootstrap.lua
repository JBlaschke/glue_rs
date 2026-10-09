-- Only Lua and C call Lua APIs. Rust supplies verified resource replies through
-- request; the C trampoline raises a reply error after the Rust call returns.
local request, package_path, native_enabled = ...
local original_require, original_load = require, load
local raise, protected_call = error, pcall
local value_type, value_string, argument_count = type, tostring, select
local valid_utf8 = utf8.len

local READ, ORIGIN, STAT, LIST = 1, 2, 3, 4
local VALIDATE_MODULE, RESOLVE_MODULE = 5, 6
local NATIVE_MODULE, NATIVE_RESOURCE, NATIVE_INITIALIZER = 7, 8, 9

local function string_argument(value, optional, label)
    local kind = value_type(value)
    if optional and kind == "nil" then
        return nil
    end
    if kind == "number" then
        value = value_string(value)
    elseif kind ~= "string" then
        raise(label .. " requires a string or number", 3)
    end
    if not valid_utf8(value) then
        raise(label .. " requires a UTF-8 string", 3)
    end
    return value
end

local function text_mode(mode)
    if mode ~= nil and mode ~= "t" then
        return false, "only text mode ('t') is supported by the linked source profile"
    end
    return true
end

local function load_text(source, name, has_environment, environment)
    if has_environment then
        return original_load(source, name, "t", environment)
    end
    return original_load(source, name, "t")
end

local preload_searcher = package.searchers[1]
local function archive_searcher(name)
    name = string_argument(name, false, "archive module name")
    local valid, diagnostic = protected_call(request, VALIDATE_MODULE, name)
    if not valid then
        return "\n\t" .. value_string(diagnostic)
    end
    local path, origin = request(RESOLVE_MODULE, name)
    if path == nil then
        return origin
    end
    local function loader(...)
        local bytes, verified_origin = request(READ, path)
        local chunk, message = original_load(bytes, "@" .. verified_origin, "t")
        if chunk == nil then
            raise(message, 0)
        end
        return chunk(...)
    end
    return loader, origin
end

package.searchers = { preload_searcher, archive_searcher }
-- These are informational templates; the resolver ignores mutable Lua paths.
package.path = package_path
package.cpath = ""
package.searchpath = nil
package.loadlib = function()
    raise("native Lua loading is unsupported by the linked source profile", 2)
end
if native_enabled then
    -- The manager has already verified and loaded the complete closure before
    -- this Lua state exists. Requests only obtain retained C function leases;
    -- no constructor or Lua API runs during the Rust resource callback.
    package.searchers[3] = function(name)
        name = string_argument(name, false, "archive module name")
        request(VALIDATE_MODULE, name)
        local loader, origin = request(NATIVE_MODULE, name)
        if loader == nil then
            return origin
        end
        return loader, origin
    end
    package.loadlib = function(path, initializer)
        path = string_argument(path, false, "native resource key")
        initializer = string_argument(initializer, false, "native initializer")
        local expected, diagnostic = request(NATIVE_INITIALIZER, path)
        if expected == nil then
            raise(diagnostic, 2)
        end
        if initializer ~= expected then
            raise("package.loadlib requires the exact declared initializer " .. expected, 2)
        end
        local loader, origin = request(NATIVE_RESOURCE, path)
        if loader == nil then
            raise(origin, 2)
        end
        return loader
    end
end

require = function(name)
    name = string_argument(name, false, "archive module name")
    -- Validate the complete string before upstream require treats it as a
    -- NUL-terminated name or consults its cache/preloaded modules.
    request(VALIDATE_MODULE, name)
    return original_require(name)
end

loadfile = function(path, mode, ...)
    path = string_argument(path, true, "loadfile resource key")
    mode = string_argument(mode, true, "loadfile mode")
    local has_environment = argument_count("#", ...) ~= 0
    local environment = ...
    local supported, message = text_mode(mode)
    if not supported then
        return nil, message
    end
    if path == nil then
        return nil, "loadfile requires an archive resource key; stdin is unsupported"
    end
    local ok, chunk, diagnostic = protected_call(function()
        local bytes, origin = request(READ, path)
        return load_text(bytes, "@" .. origin, has_environment, environment)
    end)
    if not ok then
        return nil, value_string(chunk)
    end
    if diagnostic ~= nil then
        return chunk, diagnostic
    end
    return chunk
end

dofile = function(path)
    path = string_argument(path, true, "dofile resource key")
    if path == nil then
        raise("dofile requires an archive resource key; stdin is unsupported", 2)
    end
    local bytes, origin = request(READ, path)
    local chunk, message = original_load(bytes, "@" .. origin, "t")
    if chunk == nil then
        raise(message, 0)
    end
    return chunk()
end

load = function(source, name, mode, ...)
    name = string_argument(name, true, "load chunk name")
    mode = string_argument(mode, true, "load mode")
    local supported, message = text_mode(mode)
    if not supported then
        return nil, message
    end
    if value_type(source) ~= "string" then
        return nil, "load accepts a source string only; reader functions are unsupported"
    end
    local has_environment = argument_count("#", ...) ~= 0
    local environment = ...
    return load_text(source, name or "=(load)", has_environment, environment)
end

local archive_glue = {}
archive_glue.read = function(path)
    local bytes = request(READ, string_argument(path, false, "resource key"))
    return bytes
end
archive_glue.origin = function(path)
    return request(ORIGIN, string_argument(path, false, "resource key"))
end
archive_glue.stat = function(path)
    return request(STAT, string_argument(path, false, "resource key"))
end
archive_glue.list = function(path)
    return request(LIST, string_argument(path, false, "resource key"))
end
package.loaded.glue = archive_glue
glue = archive_glue
