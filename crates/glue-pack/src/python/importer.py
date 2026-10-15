"""Bounded source/metadata/resource adapter for the verified glue ZIP container."""
import hashlib
import importlib.abc
import importlib.machinery
import importlib.metadata
import importlib.resources
import importlib.resources.abc
import importlib.util
import io
import json
import os
import posixpath
import runpy
import struct
import sys
import zipfile
import contextlib
import pathlib

_VIRTUAL = "glue:///"


class GlueArchive:
    def __init__(self, filename):
        self.filename = filename
        self.stream = open(filename, "rb")
        header = self.stream.read(64)
        if len(header) != 64 or header[:8] != b"GLUERS00" or header[8:16] != b"\0" * 8:
            raise ImportError("invalid glue archive header")
        length, payload_length = struct.unpack("<QQ", header[16:32])
        if length > 16 * 1024 * 1024 or 64 + length + payload_length != os.fstat(self.stream.fileno()).st_size:
            raise ImportError("glue archive length exceeds bounds or differs")
        manifest = self.stream.read(length)
        if hashlib.sha256(manifest).digest() != header[32:64]:
            raise ImportError("glue manifest identity differs")
        self.manifest = json.loads(manifest)
        self.resources = self.manifest["resources"]
        self.native = {}
        self.distribution = None
        self.verified_native = set()
        if len(self.resources) > 100000:
            raise ImportError("glue archive resource count exceeds bound")
        self.zip = zipfile.ZipFile(self.stream)
        names = self.zip.namelist()
        if len(names) != len(set(names)) or set(names) != set(self.resources):
            raise ImportError("glue ZIP inventory differs from manifest")
        self.directories = set()
        for name, spec in self.resources.items():
            if name.startswith("/") or ".." in name.split("/") or "\\" in name or spec["size"] > 64 * 1024 * 1024:
                raise ImportError("invalid or oversized glue resource")
            info = self.zip.getinfo(name)
            if info.file_size != spec["size"] or info.compress_size > 128 * 1024 * 1024:
                raise ImportError("glue ZIP declared resource length differs")
            parent = posixpath.dirname(name)
            while parent:
                self.directories.add(parent)
                parent = posixpath.dirname(parent)

    def read(self, name):
        spec = self.resources.get(name)
        if spec is None:
            raise FileNotFoundError(name)
        with self.zip.open(name) as stream:
            data = stream.read(spec["size"] + 1)
        if len(data) != spec["size"] or hashlib.sha256(data).hexdigest() != spec["sha256"]:
            raise ImportError("glue resource identity differs: " + name)
        return data

    def native_path(self, name):
        relative = self.native.get(name)
        if relative is None:
            raise FileNotFoundError("undeclared native image: " + name)
        deployed = os.path.realpath(os.path.join(self.distribution, relative))
        if os.path.commonpath([self.distribution, deployed]) != self.distribution:
            raise ImportError("native mapping escapes distribution")
        spec = self.manifest["distribution"]["payloads"].get(relative)
        if spec is None or spec["size"] > 512 * 1024 * 1024:
            raise ImportError("native mapping has no bounded payload declaration")
        if relative not in self.verified_native:
            identity = hashlib.sha256()
            size = 0
            with open(deployed, "rb") as stream:
                while chunk := stream.read(64 * 1024):
                    size += len(chunk)
                    if size > spec["size"]:
                        raise ImportError("native payload size differs")
                    identity.update(chunk)
            if size != spec["size"] or identity.hexdigest() != spec["sha256"]:
                raise ImportError("native payload identity differs: " + relative)
            self.verified_native.add(relative)
        return deployed

    def install_native(self, index, distribution):
        self.native = index.get("native", {})
        self.distribution = distribution
        for name in self.native:
            parent = posixpath.dirname(name)
            while parent:
                self.directories.add(parent)
                parent = posixpath.dirname(parent)


class ArchivePath(importlib.resources.abc.Traversable):
    def __init__(self, archive, key):
        self.archive = archive
        self.key = key.rstrip("/")

    @property
    def name(self):
        return posixpath.basename(self.key)

    @property
    def parent(self):
        return ArchivePath(self.archive, posixpath.dirname(self.key))

    def is_file(self):
        return self.key in self.archive.resources or self.key in self.archive.native

    def is_dir(self):
        return self.key in self.archive.directories or not self.key

    def iterdir(self):
        if not self.is_dir():
            raise NotADirectoryError(self.key)
        prefix = self.key + "/" if self.key else ""
        names = sorted({name[len(prefix):].split("/", 1)[0]
                        for name in set(self.archive.resources) | set(self.archive.native) if name.startswith(prefix)})
        return iter(ArchivePath(self.archive, prefix + name) for name in names)

    def joinpath(self, *descendants):
        key = self.key
        for descendant in descendants:
            descendant = str(descendant)
            if descendant.startswith("/") or "\\" in descendant or any(part in ("..", "") for part in descendant.split("/")):
                raise ValueError("archive resource path traversal")
            key = posixpath.join(key, descendant)
        return ArchivePath(self.archive, key)

    def open(self, mode="r", *args, **kwargs):
        if mode not in ("r", "rb", "rt"):
            raise PermissionError("glue archive resources are read-only")
        if self.key in self.archive.native:
            return open(self.archive.native_path(self.key), mode, *args, **kwargs)
        stream = io.BytesIO(self.archive.read(self.key))
        if mode == "rb":
            return stream
        return io.TextIOWrapper(stream, *args, **kwargs)

    def deployed_path(self):
        return self.archive.native_path(self.key) if self.key in self.archive.native else None

    def __fspath__(self):
        deployed = self.deployed_path()
        if deployed is None:
            raise TypeError("archived resource has no filesystem path; use resource streams")
        return deployed

    def __str__(self):
        return self.deployed_path() or _VIRTUAL + self.key


@importlib.resources.as_file.register(ArchivePath)
def _no_resource_extraction(path):
    deployed = path.deployed_path()
    if deployed is not None:
        return contextlib.nullcontext(pathlib.Path(deployed))
    raise OSError("glue archive as_file extraction is unsupported; use resource streams")


class ResourceReader(importlib.resources.abc.TraversableResources):
    def __init__(self, archive, package):
        self.archive, self.package = archive, package

    def files(self):
        return ArchivePath(self.archive, self.package)


class MergedArchivePath(ArchivePath):
    def __init__(self, paths):
        self.paths = paths
        super().__init__(paths[0].archive, paths[0].key)

    def is_file(self):
        return any(path.is_file() for path in self.paths)

    def is_dir(self):
        return any(path.is_dir() for path in self.paths)

    def iterdir(self):
        names = sorted({child.name for path in self.paths if path.is_dir() for child in path.iterdir()})
        return iter(self.joinpath(name) for name in names)

    def joinpath(self, *descendants):
        return MergedArchivePath([path.joinpath(*descendants) for path in self.paths])

    def open(self, mode="r", *args, **kwargs):
        for path in self.paths:
            if path.is_file():
                return path.open(mode, *args, **kwargs)
        raise FileNotFoundError(self.key)

    def deployed_path(self):
        return next((deployed for path in self.paths if (deployed := path.deployed_path()) is not None), None)


class NamespaceLoader(importlib.abc.Loader):
    def __init__(self, archive, paths):
        self.paths = [ArchivePath(archive, path[len(_VIRTUAL):]) for path in paths]

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        pass

    def get_resource_reader(self, fullname):
        loader = self

        class NamespaceReader(importlib.resources.abc.TraversableResources):
            def files(self):
                return MergedArchivePath(loader.paths)

        return NamespaceReader()


class SourceLoader(importlib.abc.InspectLoader):
    def __init__(self, archive, key):
        self.archive, self.key = archive, key

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        exec(self.get_code(module.__name__), module.__dict__)

    def get_code(self, fullname):
        return compile(self.archive.read(self.key), _VIRTUAL + self.key, "exec", dont_inherit=True)

    def get_source(self, fullname):
        return importlib.util.decode_source(self.archive.read(self.key))

    def is_package(self, fullname):
        return self.key.endswith("/__init__.py")

    def get_filename(self, fullname):
        return _VIRTUAL + self.key

    def get_data(self, path):
        if not path.startswith(_VIRTUAL):
            raise FileNotFoundError(path)
        return self.archive.read(path[len(_VIRTUAL):])

    def get_resource_reader(self, fullname):
        return ResourceReader(self.archive, posixpath.dirname(self.key))


class ArchiveFinder(importlib.abc.MetaPathFinder):
    def __init__(self, archive, index, distribution):
        self.archive, self.index, self.distribution = archive, index, distribution

    def find_spec(self, fullname, path=None, target=None):
        if path is None:
            bases = [root + "/" + fullname for root in self.index["import_roots"]]
        else:
            bases = [root[len(_VIRTUAL):].rstrip("/") + "/" + fullname.rsplit(".", 1)[-1]
                     for root in path if isinstance(root, str) and root.startswith(_VIRTUAL)]
        namespaces = []
        for base in bases:
            for key in (base + "/__init__.py", base + ".py"):
                if key in self.archive.resources:
                    loader = SourceLoader(self.archive, key)
                    spec = importlib.util.spec_from_loader(fullname, loader, origin=_VIRTUAL + key,
                                                         is_package=key.endswith("/__init__.py"))
                    spec.has_location = True
                    if spec.submodule_search_locations is not None:
                        spec.submodule_search_locations[:] = [_VIRTUAL + base]
                    return spec
            for suffix in importlib.machinery.EXTENSION_SUFFIXES:
                for key in (base + "/__init__" + suffix, base + suffix):
                    if key in self.index.get("native", {}):
                        deployed = self.archive.native_path(key)
                        loader = importlib.machinery.ExtensionFileLoader(fullname, deployed)
                        spec = importlib.util.spec_from_file_location(fullname, deployed, loader=loader)
                        if key == base + "/__init__" + suffix:
                            spec.submodule_search_locations = [_VIRTUAL + base]
                        return spec
            if base in self.archive.directories:
                namespaces.append(_VIRTUAL + base)
        if namespaces:
            spec = importlib.machinery.ModuleSpec(fullname, NamespaceLoader(self.archive, namespaces), is_package=True)
            spec.submodule_search_locations = namespaces
            return spec
        return None

    def find_distributions(self, context=importlib.metadata.DistributionFinder.Context()):
        requested = context.name
        normalize = lambda value: value.lower().replace("-", "_").replace(".", "_")
        for root in self.index["import_roots"]:
            if _VIRTUAL + root not in context.path:
                continue
            for directory in sorted(self.archive.directories):
                if posixpath.dirname(directory) != root or not directory.endswith((".dist-info", ".egg-info")):
                    continue
                if requested is not None and normalize(posixpath.basename(directory).split("-", 1)[0]) != normalize(requested):
                    continue
                yield importlib.metadata.PathDistribution(ArchivePath(self.archive, directory))


def run_application(archive_path, distribution, arguments):
    archive = GlueArchive(archive_path)
    index = json.loads(archive.read("support/python-index.json"))
    if index["revision"] != 1:
        raise ImportError("unsupported Python application index")
    archive.install_native(index, distribution)
    finder = ArchiveFinder(archive, index, distribution)
    sys.meta_path.insert(0, finder)
    sys.path[:0] = [_VIRTUAL + root for root in index["import_roots"]]
    if archive.native:
        import ctypes
        original_cdll_init = ctypes.CDLL.__init__

        def declared_cdll_init(self, name, *args, **kwargs):
            if isinstance(name, str) and name.startswith(_VIRTUAL):
                name = archive.native_path(name[len(_VIRTUAL):])
            return original_cdll_init(self, name, *args, **kwargs)

        ctypes.CDLL.__init__ = declared_cdll_init
    entry = index["entry"]
    sys.argv = [entry["value"], *arguments]
    if entry["kind"] == "file":
        scope = {"__name__":"__main__", "__file__":_VIRTUAL + entry["value"],
                 "__package__":None, "__builtins__":__builtins__}
        exec(compile(archive.read(entry["value"]), scope["__file__"], "exec", dont_inherit=True), scope)
    elif entry["kind"] == "module":
        runpy.run_module(entry["value"], run_name="__main__", alter_sys=True)
    elif entry["kind"] == "console_script":
        module, attribute = entry["value"].split("[", 1)[0].strip().split(":", 1)
        value = __import__(module, fromlist=[attribute.split(".")[0]])
        for component in attribute.split("."):
            value = getattr(value, component)
        raise SystemExit(value())
    else:
        raise ImportError("unsupported Python entry kind")
