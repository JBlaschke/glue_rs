"""Native initializer checks appended to the shared archive conformance app."""

import sys
import importlib
import atexit


def native_metadata(module, name):
    assert module.__name__ == module.__spec__.name == name
    assert module.__loader__ is module.__spec__.loader is sys.__loader__
    assert module.__loader__.__name__ == "BuiltinImporter"
    assert module.__loader__.__module__ == "_frozen_importlib"
    assert module.__spec__.origin == "built-in"
    assert not module.__spec__.has_location
    assert module.__spec__.submodule_search_locations is None
    assert module.__package__ == ""
    assert not hasattr(module, "__file__")
    assert not hasattr(module, "__cached__")
    assert name in sys.builtin_module_names
    assert sys.modules[name] is module


def native_error(function, message):
    try:
        function()
    except RuntimeError as error:
        assert str(error) == message, str(error)
    else:
        raise AssertionError("expected native RuntimeError: " + message)


native_names = (
    "glue_native_single",
    "glue_native_multi",
    "glue_native_init_error",
    "glue_native_exec_error",
)
assert all(name not in sys.modules for name in native_names)

native_single_first = importlib.import_module(native_names[0])
native_metadata(native_single_first, native_names[0])
assert native_single_first.answer() == native_single_first.initial_value == 42
assert native_single_first.init_calls() == 1
assert importlib.import_module(native_names[0]) is native_single_first
native_error(native_single_first.fail, "intentional native method error")
assert sys.modules[native_names[0]] is native_single_first
assert native_single_first.answer() == 42
native_single_first.initial_value = 900
native_single_first.user_value = "only on the first module"
assert importlib.reload(native_single_first) is native_single_first
assert native_single_first.initial_value == 900
assert native_single_first.init_calls() == 1
del sys.modules[native_names[0]]
native_single_second = importlib.import_module(native_names[0])
native_metadata(native_single_second, native_names[0])
assert native_single_second is not native_single_first
assert native_single_second.initial_value == native_single_second.answer() == 42
assert not hasattr(native_single_second, "user_value")
assert native_single_first.initial_value == 900
assert native_single_second.init_calls() == native_single_first.init_calls() == 1
# The legacy m_size=-1 cache restores the original shallow module dictionary.
assert native_single_second.answer is native_single_first.answer
assert importlib.reload(native_single_second) is native_single_second
assert native_single_second.init_calls() == 1

native_multi_first = importlib.import_module(native_names[1])
native_metadata(native_multi_first, native_names[1])
assert native_multi_first.answer() == native_multi_first.answer_value == 42
assert native_multi_first.executions() == native_multi_first.init_calls() == 1
assert importlib.import_module(native_names[1]) is native_multi_first
assert native_multi_first.bump() == native_multi_first.answer() == 43
native_multi_first.answer_value = 900
native_multi_first.user_value = "only on the first module"
assert importlib.reload(native_multi_first) is native_multi_first
assert native_multi_first.answer() == 43
assert native_multi_first.answer_value == 900
assert native_multi_first.executions() == native_multi_first.init_calls() == 1
del sys.modules[native_names[1]]
native_multi_second = importlib.import_module(native_names[1])
native_metadata(native_multi_second, native_names[1])
assert native_multi_second is not native_multi_first
assert native_multi_second.answer() == native_multi_second.answer_value == 42
assert native_multi_second.executions() == 1
assert native_multi_second.init_calls() == native_multi_first.init_calls() == 2
assert not hasattr(native_multi_second, "user_value")
assert native_multi_second.answer is not native_multi_first.answer
assert native_multi_second.bump() == 43
assert native_multi_second.bump() == native_multi_second.answer() == 44
assert native_multi_first.answer() == 43
assert importlib.reload(native_multi_second) is native_multi_second
assert native_multi_second.answer() == 44
assert native_multi_second.executions() == 1
assert native_multi_second.init_calls() == 2

native_error(
    lambda: importlib.import_module(native_names[2]),
    "intentional native initializer error",
)
assert native_names[2] not in sys.modules
assert sys.modules[native_names[0]] is native_single_second
assert sys.modules[native_names[1]] is native_multi_second
native_init_recovered = importlib.import_module(native_names[2])
native_metadata(native_init_recovered, native_names[2])
assert native_init_recovered.attempts() == 2
assert native_init_recovered.answer() == 42
assert importlib.import_module(native_names[2]) is native_init_recovered
assert importlib.reload(native_init_recovered) is native_init_recovered
assert native_init_recovered.attempts() == 2

native_error(
    lambda: importlib.import_module(native_names[3]),
    "intentional native exec error",
)
assert native_names[3] not in sys.modules
assert sys.modules[native_names[2]] is native_init_recovered
native_exec_recovered = importlib.import_module(native_names[3])
native_metadata(native_exec_recovered, native_names[3])
assert native_exec_recovered.init_calls() == 2
assert native_exec_recovered.executions() == 1
assert native_exec_recovered.answer() == 42
assert importlib.import_module(native_names[3]) is native_exec_recovered
assert importlib.reload(native_exec_recovered) is native_exec_recovered
assert native_exec_recovered.init_calls() == 2
assert native_exec_recovered.executions() == 1


def native_finalization_calls(
    single_first=native_single_first,
    single_second=native_single_second,
    multi_first=native_multi_first,
    multi_second=native_multi_second,
    init_recovered=native_init_recovered,
    exec_recovered=native_exec_recovered,
):
    # The adapter keeps extension code and its private dependency alive while
    # CPython runs callbacks in the real Py_FinalizeEx call.
    assert single_first.answer() == single_second.answer() == 42
    assert single_first.init_calls() == single_second.init_calls() == 1
    assert multi_first.answer() == 43 and multi_second.answer() == 44
    assert multi_first.executions() == multi_second.executions() == 1
    assert multi_first.init_calls() == multi_second.init_calls() == 2
    assert init_recovered.answer() == exec_recovered.answer() == 42
    assert init_recovered.attempts() == exec_recovered.init_calls() == 2
    assert exec_recovered.executions() == 1


atexit.register(native_finalization_calls)
print("GLUE_PYTHON_EXTENSIONS_PASS single=42 multi=44 retry=2 dependency=42")
