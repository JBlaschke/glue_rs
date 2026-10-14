"""Custom creation and owned-state GC, independent of archive discovery."""

import sys
import importlib
import atexit
import gc
import _weakref


def lifecycle_metadata(module, name):
    assert module.__name__ == module.__spec__.name == name
    assert module.__loader__ is module.__spec__.loader
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
    assert module.create_marker == 42


def lifecycle_error(action, message):
    try:
        action()
    except RuntimeError as error:
        assert str(error) == message, str(error)
    else:
        raise AssertionError("expected lifecycle RuntimeError: " + message)


lifecycle_names = (
    "glue_native_lifecycle",
    "glue_native_create_error",
    "glue_native_lifecycle_exec_error",
)
assert all(name not in sys.modules for name in lifecycle_names)

lifecycle_first = importlib.import_module(lifecycle_names[0])
lifecycle_metadata(lifecycle_first, lifecycle_names[0])
assert lifecycle_first.state_id() == 1
assert lifecycle_first.answer() == 42
assert lifecycle_first.executions() == 1
assert lifecycle_first.create_calls() == lifecycle_first.init_calls() == 1
assert importlib.import_module(lifecycle_names[0]) is lifecycle_first
lifecycle_error(lifecycle_first.fail, "intentional lifecycle method error")
assert lifecycle_first.answer() == 42
assert lifecycle_first.bump() == 43
lifecycle_first.user_value = "first instance only"
assert importlib.reload(lifecycle_first) is lifecycle_first
assert lifecycle_first.answer() == 43 and lifecycle_first.executions() == 1
assert lifecycle_first.create_calls() == lifecycle_first.init_calls() == 1
assert gc.is_tracked(lifecycle_first)
assert any(isinstance(value, list) and any(item is lifecycle_first for item in value)
           for value in gc.get_referents(lifecycle_first))
lifecycle_old_ref = _weakref.ref(lifecycle_first)
del sys.modules[lifecycle_names[0]]
lifecycle_second = importlib.import_module(lifecycle_names[0])
lifecycle_metadata(lifecycle_second, lifecycle_names[0])
assert lifecycle_second is not lifecycle_first
assert lifecycle_second.state_id() == 2
assert lifecycle_second.answer() == 42 and lifecycle_second.executions() == 1
assert lifecycle_first.answer() == 43
assert not hasattr(lifecycle_second, "user_value")
assert lifecycle_second.create_calls() == lifecycle_second.init_calls() == 2
# Drop the public dictionary too, leaving the owned state/list/module cycle.
lifecycle_first.__dict__.clear()
del lifecycle_first
gc.collect()
assert lifecycle_old_ref() is None
assert lifecycle_second.allocations() == 2
assert lifecycle_second.frees() == lifecycle_second.releases() == 1
assert lifecycle_second.owned() == 1
assert lifecycle_second.traversals() > 0
assert lifecycle_second.clears() > 0
assert lifecycle_second.protocol_errors() == 0
assert importlib.reload(lifecycle_second) is lifecycle_second
assert lifecycle_second.state_id() == 2 and lifecycle_second.executions() == 1
assert lifecycle_second.answer() == 42

lifecycle_error(
    lambda: importlib.import_module(lifecycle_names[1]),
    "intentional lifecycle create error",
)
assert lifecycle_names[1] not in sys.modules
gc.collect()
assert lifecycle_second.total_allocations() == 2
assert lifecycle_second.total_frees() == 1
lifecycle_create_recovered = importlib.import_module(lifecycle_names[1])
lifecycle_metadata(lifecycle_create_recovered, lifecycle_names[1])
assert lifecycle_create_recovered.state_id() == 3
assert lifecycle_create_recovered.answer() == 42
assert lifecycle_create_recovered.create_calls() == lifecycle_create_recovered.init_calls() == 2
assert lifecycle_create_recovered.created_objects() == lifecycle_create_recovered.allocations() == 1
assert lifecycle_create_recovered.frees() == 0
assert importlib.reload(lifecycle_create_recovered) is lifecycle_create_recovered
assert lifecycle_create_recovered.executions() == 1

lifecycle_error(
    lambda: importlib.import_module(lifecycle_names[2]),
    "intentional lifecycle exec error",
)
assert lifecycle_names[2] not in sys.modules
gc.collect()
assert lifecycle_second.total_allocations() == 4
assert lifecycle_second.total_frees() == lifecycle_second.total_releases() == 2
assert lifecycle_second.total_owned() == 2
assert lifecycle_second.protocol_errors() == 0
lifecycle_exec_recovered = importlib.import_module(lifecycle_names[2])
lifecycle_metadata(lifecycle_exec_recovered, lifecycle_names[2])
assert lifecycle_exec_recovered.state_id() == 5
assert lifecycle_exec_recovered.answer() == 42
assert lifecycle_exec_recovered.create_calls() == lifecycle_exec_recovered.init_calls() == 2
assert lifecycle_exec_recovered.allocations() == 2
assert lifecycle_exec_recovered.frees() == lifecycle_exec_recovered.releases() == 1
assert lifecycle_exec_recovered.owned() == 1
assert importlib.reload(lifecycle_exec_recovered) is lifecycle_exec_recovered
assert lifecycle_exec_recovered.executions() == 1
assert lifecycle_second.total_allocations() == 5
assert lifecycle_second.total_frees() == 2 and lifecycle_second.total_owned() == 3


def lifecycle_finalization_calls(
    normal=lifecycle_second,
    created=lifecycle_create_recovered,
    executed=lifecycle_exec_recovered,
    archive_package=globals().get("glue_demo"),
    archive_resources=globals().get("resources"),
):
    assert normal.answer() == created.answer() == executed.answer() == 42
    assert normal.state_id() == 2 and created.state_id() == 3 and executed.state_id() == 5
    assert normal.executions() == created.executions() == executed.executions() == 1
    assert normal.total_allocations() == 5 and normal.total_frees() == 2
    assert normal.total_owned() == 3 and normal.protocol_errors() == 0
    if archive_package is not None:
        tree = archive_resources.files(archive_package)
        assert tree.joinpath("data/binary.bin").read_bytes() == b"\x00\xffarchive\x00\x2a"
        assert tree.joinpath("data/text.txt").read_text() == "λ café\nsecond line\n"
    print("GLUE_PYTHON_NATIVE_LIFECYCLE_ATEXIT_PASS retained=3", flush=True)


atexit.register(lifecycle_finalization_calls)
print("GLUE_PYTHON_NATIVE_LIFECYCLE_PASS instances=5 collected=2 retained=3 create_retry=2 exec_retry=2", flush=True)
