"""Exact descriptor-backed children; stock CPython owns dynamic create/exec."""

import sys
import _frozen_importlib_external
from _glue_archive import request as _native_request

_NATIVE_PARENT = "glue_native_pkg"
_NATIVE_NAMES = tuple(_NATIVE_PARENT + "." + name for name in (
    "glue_native_lifecycle", "glue_native_create_error", "glue_native_lifecycle_exec_error",
))
_NATIVE_PARENT_PATH = "glue://stock-pbs-native-packages/app/python/glue_native_pkg"
_NATIVE_BASELINE = globals().get("__glue_native_baseline__", False)
if _NATIVE_BASELINE:
    _NATIVE_PARENT_PATH = globals()["__glue_native_parent_path__"]


def _native_ask(operation, fullname):
    if fullname not in _NATIVE_NAMES:
        raise ImportError("undeclared native package member", name=fullname)
    reply = _native_request(operation + "\t" + fullname)
    if not isinstance(reply, bytes) or len(reply) > 64:
        raise RuntimeError("invalid native package callback reply")
    return reply


def _native_path(fullname):
    value = _native_ask("native-path", fullname).decode("ascii", "strict")
    prefix = "/proc/self/fd/"
    number = value[len(prefix):] if value.startswith(prefix) else ""
    if not number or not number.isascii() or not number.isdigit() or number.startswith("0") or not 3 <= int(number) <= 1048576:
        raise RuntimeError("invalid retained native descriptor alias")
    return value


_native_aliases = {name: _native_path(name) for name in _NATIVE_NAMES}
if len(set(_native_aliases.values())) != len(_NATIVE_NAMES):
    raise RuntimeError("native package descriptor aliases collide")


def _native_check(fullname):
    if _native_path(fullname) != _native_aliases[fullname] or _native_ask("native-check", fullname) != b"checked":
        raise RuntimeError("native package ownership check differs")


class _NativePackageLoader(_frozen_importlib_external.ExtensionFileLoader):
    def _guard(self, spec):
        alias = _native_aliases.get(self.name)
        if (alias is None or self.path != alias or spec.name != self.name or
                spec.origin != alias or spec.loader is not self or spec.has_location is not True or
                spec.submodule_search_locations is not None or spec.cached is not None):
            raise ImportError("native package spec differs from retained descriptor", name=self.name)
        if sys.getdlopenflags() != 2:
            raise ImportError("native package requires RTLD_NOW and RTLD_LOCAL", name=self.name)

    def create_module(self, spec):
        self._guard(spec)
        _native_check(self.name)
        try:
            return super().create_module(spec)
        finally:
            _native_check(self.name)

    def exec_module(self, module):
        self._guard(module.__spec__)
        if module.__name__ != self.name or module.__file__ != self.path or module.__loader__ is not self:
            raise ImportError("native package module metadata differs", name=self.name)
        _native_check(self.name)
        try:
            super().exec_module(module)
        finally:
            _native_check(self.name)

    def get_data(self, path):
        raise RuntimeError("native package child has no path-based resource data")

    def get_resource_reader(self, fullname):
        raise RuntimeError("native package child has no resource reader")


class _NativePackageFinder:
    def find_spec(self, fullname, path=None, target=None):
        if fullname not in _NATIVE_NAMES:
            if fullname.startswith(_NATIVE_PARENT + ".glue_native_"):
                raise ModuleNotFoundError("undeclared native package member", name=fullname)
            return None
        if path != [_NATIVE_PARENT_PATH]:
            raise ImportError("native package parent path differs", name=fullname)
        loader = _NativePackageLoader(fullname, _native_aliases[fullname])
        return _frozen_importlib_external.spec_from_file_location(fullname, loader.path, loader=loader)

    def invalidate_caches(self):
        return None


_native_finder = _NativePackageFinder()
if _NATIVE_BASELINE:
    _native_position = next(index for index, finder in enumerate(sys.meta_path)
                            if finder is _frozen_importlib_external.PathFinder)
else:
    _native_position = next(index for index, finder in enumerate(sys.meta_path) if finder is _archive_finder)
sys.meta_path.insert(_native_position, _native_finder)
