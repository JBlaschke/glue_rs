local project, entry = table.remove(arg, 1), table.remove(arg, 1)
package.path = project .. "/?.lua;" .. project .. "/?/init.lua"
package.cpath = ""
glue = { read = function(path)
    assert(path:sub(1, 4) == "app/")
    local file = assert(io.open(project .. "/" .. path:sub(5), "rb"))
    local bytes = assert(file:read("a"))
    assert(file:close())
    return bytes
end }
arg[0] = project .. "/" .. entry
assert(loadfile(arg[0]))(table.unpack(arg))
