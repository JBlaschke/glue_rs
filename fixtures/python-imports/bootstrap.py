"""Source-only archive importer shared by the controlled Python providers.

The native request function returns verified resource bytes. Virtual origins
are diagnostic identities and never become host filesystem paths. This is an
immutable, single-archive namespace profile, not a universal Python filesystem.
"""

import sys
import io
import _frozen_importlib
import _frozen_importlib_external
from _glue_archive import request as _request


_MAX_REPLY = 4 * 1024 * 1024
_MAX_POSITION = (1 << 64) - 1
# Stock CPython's syntax-error path tries to reopen a compile filename, even
# for angle-bracket pseudo names. In this pinned UTF-8 filesystem profile an
# unpaired high surrogate cannot encode to an OS path, so diagnostic lookup
# stops before a syscall. Restore the virtual identity before publishing code
# or exceptions. This is deliberately scoped to the observed Linux provider.
_COMPILE_SENTINEL = "\ud800"
_CODE_TYPE = type((lambda: None).__code__)


def _code_origin(code, origin):
    constants = tuple(_code_origin(value, origin) if isinstance(value, _CODE_TYPE) else value for value in code.co_consts)
    return code.replace(co_filename=origin, co_consts=constants)


def _compile_source(source, origin):
    try:
        code = compile(source, _COMPILE_SENTINEL, "exec", dont_inherit=True, optimize=0)
    except SyntaxError as error:
        error.filename = origin
        if len(error.args) == 2 and isinstance(error.args[1], tuple) and error.args[1]:
            error.args = (error.args[0], (origin,) + error.args[1][1:])
        raise
    return _code_origin(code, origin)


def _ask(operation, key):
    reply = _request(operation + "\t" + key)
    if not isinstance(reply, bytes) or len(reply) > _MAX_REPLY:
        raise RuntimeError("invalid archive callback reply")
    return reply


def _canonical(key, root=False):
    if not isinstance(key, str):
        raise TypeError("archive resource paths must be strings")
    if root and key == "":
        return key
    if not key or len(key) > 4096 or not key.isascii():
        raise ValueError("archive resource path is not canonical")
    if any(ord(c) < 32 or ord(c) == 127 or c in '\\<>:"|?*' for c in key):
        raise ValueError("archive resource path is not canonical")
    components = key.split("/")
    if len(components) > 64:
        raise ValueError("archive resource path is too deep")
    for component in components:
        stem = component.split(".", 1)[0].upper()
        device = stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
        device = device or (len(stem) == 4 and stem[:3] in {"COM", "LPT"} and stem[3] in "123456789")
        if component in {"", ".", ".."} or len(component) > 255 or component[-1:] in {" ", "."} or device:
            raise ValueError("archive resource path is not canonical")
    return key


def _origin(key):
    value = _ask("origin", _canonical(key, root=True)).decode("utf-8", "strict")
    if not value.startswith("glue://") or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise RuntimeError("invalid archive resource origin")
    return value


def _stat(key):
    fields = _ask("stat", key).decode("utf-8", "strict").split("\n")
    if len(fields) != 2 or fields[0] not in {"file", "directory", "missing"} or not fields[1].isascii() or not fields[1].isdigit():
        raise RuntimeError("invalid archive resource metadata")
    size = int(fields[1])
    if fields[0] != "file" and size != 0:
        raise RuntimeError("invalid archive resource metadata")
    return fields[0], size


class _ArchiveRaw(io.RawIOBase):
    """An immutable buffer with the ordinary read-only stream protocol."""

    def __init__(self, data, origin):
        super().__init__()
        if not isinstance(data, bytes):
            raise TypeError("archive stream backing bytes must be immutable")
        self._data = data
        self._position = 0
        self.name = origin
        self.mode = "rb"

    def readable(self):
        self._checkClosed()
        return True

    def writable(self):
        self._checkClosed()
        return False

    def seekable(self):
        self._checkClosed()
        return True

    def tell(self):
        self._checkClosed()
        return self._position

    def seek(self, offset, whence=0):
        self._checkClosed()
        if not isinstance(offset, int) or not isinstance(whence, int):
            raise TypeError("archive stream offsets must be integers")
        if whence == 0:
            position = offset
        elif whence == 1:
            position = self._position + offset
        elif whence == 2:
            position = len(self._data) + offset
        else:
            raise ValueError("invalid archive stream seek origin")
        if position < 0 or position > _MAX_POSITION:
            raise ValueError("archive stream seek out of range")
        self._position = position
        return position

    def readinto(self, buffer):
        self._checkClosed()
        output = memoryview(buffer).cast("B")
        if output.readonly:
            raise TypeError("readinto requires a writable buffer")
        count = min(len(output), max(0, len(self._data) - self._position))
        if count:
            output[:count] = self._data[self._position:self._position + count]
            self._position += count
        return count


class _ArchivePath:
    """The importlib.resources Traversable protocol, without OS path coercion."""

    def __init__(self, key):
        self._key = _canonical(key, root=True)

    @property
    def name(self):
        return self._key.rsplit("/", 1)[-1]

    def __repr__(self):
        return "ArchivePath(" + repr(_origin(self._key)) + ")"

    def is_file(self):
        return _stat(self._key)[0] == "file"

    def is_dir(self):
        return _stat(self._key)[0] == "directory"

    def iterdir(self):
        kind, _ = _stat(self._key)
        if kind == "missing":
            raise FileNotFoundError(_origin(self._key))
        if kind != "directory":
            raise NotADirectoryError(_origin(self._key))
        reply = _ask("list", self._key).decode("utf-8", "strict")
        names = reply.split("\n") if reply else []
        if names != sorted(set(names)):
            raise RuntimeError("invalid archive directory listing")
        for name in names:
            _canonical(name)
            if "/" in name:
                raise RuntimeError("invalid archive directory child")
        return (self.joinpath(name) for name in names)

    def joinpath(self, *descendants):
        if not descendants:
            return self
        parts = [self._key] if self._key else []
        for child in descendants:
            parts.append(_canonical(child))
        return type(self)("/".join(parts))

    def __truediv__(self, child):
        return self.joinpath(child)

    def open(self, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        if mode not in {"r", "rb"}:
            raise io.UnsupportedOperation("archive resource streams are read-only; use mode 'r' or 'rb'")
        if not isinstance(buffering, int) or buffering < -1:
            raise ValueError("invalid archive resource buffering")
        if mode == "rb" and any(value is not None for value in (encoding, errors, newline)):
            raise ValueError("binary archive streams do not accept text options")
        if mode == "r" and buffering == 0:
            raise ValueError("unbuffered text archive streams are unsupported")
        kind, _ = _stat(self._key)
        if kind == "missing":
            raise FileNotFoundError(_origin(self._key))
        if kind != "file":
            raise IsADirectoryError(_origin(self._key))
        raw = _ArchiveRaw(_ask("read", self._key), _origin(self._key))
        if mode == "rb" and buffering == 0:
            return raw
        binary = io.BufferedReader(raw, buffer_size=buffering if buffering > 1 else io.DEFAULT_BUFFER_SIZE)
        if mode == "rb":
            return binary
        try:
            return io.TextIOWrapper(binary, encoding=encoding or "utf-8", errors=errors or "strict", newline=newline, line_buffering=buffering == 1)
        except BaseException:
            binary.close()
            raise

    def read_bytes(self):
        with self.open("rb") as stream:
            return stream.read()

    def read_text(self, encoding=None, errors=None):
        with self.open("r", encoding=encoding, errors=errors) as stream:
            return stream.read()


class _ArchiveReader:
    def __init__(self, directory):
        self._directory = _canonical(directory)

    def files(self):
        return _ArchivePath(self._directory)

    def open_resource(self, resource):
        return self.files().joinpath(resource).open("rb")

    def resource_path(self, resource):
        raise FileNotFoundError("archive resource has no filesystem path; use open_resource() or files().read_bytes()")

    def is_resource(self, resource):
        return self.files().joinpath(resource).is_file()

    def contents(self):
        return (path.name for path in self.files().iterdir())


class _ArchiveLoader:
    def __init__(self, fullname, kind, key, origin, directory):
        self._fullname = fullname
        self._kind = kind
        self._key = key
        self._origin = origin
        self._directory = directory

    def _check_name(self, fullname):
        if fullname != self._fullname:
            raise ImportError("archive loader does not own module " + fullname, name=fullname)

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        self._check_name(module.__spec__.name)
        module.__cached__ = None
        if self._kind == "namespace":
            module.__file__ = None
            return
        module.__file__ = self._origin
        exec(self.get_code(module.__spec__.name), module.__dict__)

    def get_code(self, fullname):
        self._check_name(fullname)
        if self._kind == "namespace":
            return None
        return _compile_source(_ask("read", self._key), self._origin)

    def get_source(self, fullname):
        self._check_name(fullname)
        if self._kind == "namespace":
            return None
        from importlib.util import decode_source
        return decode_source(_ask("read", self._key))

    def get_filename(self, fullname):
        self._check_name(fullname)
        if self._kind == "namespace":
            raise ImportError("archive namespace has no source filename", name=fullname)
        return self._origin

    def is_package(self, fullname):
        self._check_name(fullname)
        return self._kind != "module"

    def get_resource_reader(self, fullname):
        self._check_name(fullname)
        # Python 3.13 also accepts non-package modules as resource anchors.
        directory = self._directory if self._kind != "module" else self._key.rsplit("/", 1)[0]
        return _ArchiveReader(directory)


class _ArchiveFinder:
    def find_spec(self, fullname, path=None, target=None):
        fields = _ask("resolve", fullname).decode("utf-8", "strict").split("\n")
        if len(fields) != 4 or fields[0] not in {"module", "package", "namespace", "blocked", "missing"}:
            raise RuntimeError("invalid archive module resolution")
        kind, key, origin, directory = fields
        if kind in {"missing", "blocked"}:
            if any(fields[1:]):
                raise RuntimeError("invalid missing archive module resolution")
            if kind == "blocked":
                raise ModuleNotFoundError("No module named " + repr(fullname) + " in the declared archive", name=fullname)
            return None
        _canonical(key)
        if kind == "module":
            if directory:
                raise RuntimeError("invalid archive module directory")
        else:
            _canonical(directory)
        if kind == "namespace":
            if origin or key != directory:
                raise RuntimeError("invalid archive namespace resolution")
        elif origin != _origin(key):
            raise RuntimeError("invalid archive module origin")
        loader = _ArchiveLoader(fullname, kind, key, origin, directory)
        spec = _frozen_importlib.ModuleSpec(fullname, loader, origin=origin or None, is_package=kind != "module")
        # Origins are virtual identities. Setting has_location would manufacture
        # a misleading filesystem __cached__ name from the diagnostic URI.
        spec.has_location = False
        if kind != "module":
            spec.submodule_search_locations = [_origin(directory)]
        return spec

    def invalidate_caches(self):
        # The archive index is immutable; normal sys.modules caching is CPython's.
        return None


_archive_finder = _ArchiveFinder()
_path_finder = _frozen_importlib_external.PathFinder
_path_position = next((index for index, finder in enumerate(sys.meta_path) if finder is _path_finder), len(sys.meta_path))
sys.meta_path.insert(_path_position, _archive_finder)

# Import the actual selected stdlib only after installing the archive finder.
# Register on the public function object: legacy resources.path() uses the same
# singledispatch object, so both entry points reject before creating temp files.
import importlib.resources as _resources


def _reject_materialization(path):
    raise RuntimeError("archive resources cannot be materialized; use read_bytes(), read_text(), or open()")


_resources.as_file.register(_ArchivePath)(_reject_materialization)
