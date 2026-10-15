"""Compare an unchanged, independently supplied CPython _testmultiphase module.

The same prebuilt image is supplied under its exported create/exec error names.
Glue does not compile it or provide lifecycle entry shims.
"""
import importlib
import importlib.machinery
import json
import sys

module = importlib.import_module("_testmultiphase")
assert isinstance(module.__loader__, importlib.machinery.ExtensionFileLoader)
assert module.__spec__.origin == module.__file__
assert module.__spec__.has_location
assert module.foo(20, 22) == 42
assert module.Example().demo("stock") == "stock"
assert importlib.import_module("_testmultiphase") is module
example_type = module.Example
assert importlib.reload(module) is module and module.Example is example_type
errors = []
for name in ["_testmultiphase_create_raise", "_testmultiphase_exec_raise"]:
    for attempt in range(2):
        try:
            importlib.import_module(name)
        except SystemError:
            errors.append(name)
        else:
            raise AssertionError("native initialization error was lost: " + name)
        assert name not in sys.modules
print(json.dumps({"status": "python-lifecycle-ok", "stock_loader": True,
                  "repeat_import": True, "errors": errors}))
