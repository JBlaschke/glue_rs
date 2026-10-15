local project = table.remove(arg, 1)
package.path = project .. "/?.lua;" .. project .. "/?/init.lua"
package.cpath = project .. "/?.so"
local original_searcher, original_loadlib = package.searchers[3], package.loadlib
package.searchers[3] = function(name)
    local loader, origin = original_searcher(name)
    if type(loader) == "function" then origin = "app/" .. name:gsub("%.", "/") .. ".so" end
    return loader, origin
end
package.loadlib = function(path, symbol)
    if path:sub(1, 4) == "app/" then path = project .. "/" .. path:sub(5) end
    return original_loadlib(path, symbol)
end
arg[0] = project .. "/main.lua"
assert(loadfile(arg[0]))(table.unpack(arg))
