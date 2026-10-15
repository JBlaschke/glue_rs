local declared = "plugin.value"
assert(require(declared) == 42)
assert(glue.read("app/assets/value.txt") == "42\n")
assert(arg[1] == "argument with spaces")
print(_VERSION .. " explicit-entry/dynamic-import passed")
