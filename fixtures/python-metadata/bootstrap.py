"""Pinned distribution metadata adapter for the source-only archive importer.

Append this helper to python-imports/bootstrap.py in the same namespace.
The provider validates the bounded dist-info inventory before execution. This
helper only exposes those bytes through importlib.metadata's public finder and
Distribution interfaces; it never discovers installed host distributions.
"""


# Metadata discovery passes explicit Context.path directly to every registered
# finder, independently of sys.path. Remove the stock filesystem finder before
# installing this adapter, including for bundled providers whose importer kept
# it available. Close its other discovery inputs without importing any module.
sys.meta_path[:] = [finder for finder in sys.meta_path if finder is not _path_finder]
sys.path[:] = []
sys.path_importer_cache.clear()
sys.path_hooks[:] = []


_METADATA_ROOT = "app/python"
_MetadataDistributionType = None


def _metadata_normalize_name(name):
    if not isinstance(name, str):
        raise TypeError("distribution names must be strings")
    if not name or not name.isascii() or not name[0].isalnum() or not name[-1].isalnum():
        return None
    result = []
    separator = False
    for character in name:
        if character in "._-":
            if not separator:
                result.append("-")
            separator = True
        elif character.isalnum():
            result.append(character.lower())
            separator = False
        else:
            return None
    return "".join(result)


class _MetadataPath(_ArchivePath):
    """Immutable archive path used by public metadata PackagePath objects."""

    def __init__(self, key):
        object.__setattr__(self, "_key", _canonical(key))

    def __setattr__(self, name, value):
        raise AttributeError("archive metadata paths are immutable")

    def __delattr__(self, name):
        raise AttributeError("archive metadata paths are immutable")

    def __str__(self):
        return _origin(self._key)

    def exists(self):
        return _stat(self._key)[0] != "missing"


def _metadata_distribution_type():
    global _MetadataDistributionType
    if _MetadataDistributionType is None:
        # Importing metadata brings substantial stdlib dependencies. Defer it
        # until a query, after the selected provider and importer are ready.
        from importlib.metadata import Distribution, PackagePath

        class _ArchiveDistribution(Distribution):
            def __init__(self, directory):
                self._directory = _canonical(directory)

            def read_text(self, filename):
                key = self._directory + "/" + _canonical(filename)
                kind, _ = _stat(key)
                if kind == "missing":
                    return None
                if kind != "file":
                    raise IsADirectoryError(_origin(key))
                return _ask("read", key).decode("utf-8", "strict")

            def locate_file(self, path):
                if isinstance(path, PackagePath):
                    path = str(path)
                elif not isinstance(path, str):
                    raise TypeError("distribution files require a string or PackagePath")
                if path == "":
                    return _MetadataPath(_METADATA_ROOT)
                return _MetadataPath(_METADATA_ROOT + "/" + _canonical(path))

        _MetadataDistributionType = _ArchiveDistribution
    return _MetadataDistributionType


def _metadata_find_distributions(self, context=None):
    if context is None:
        from importlib.metadata import DistributionFinder
        context = DistributionFinder.Context()
    name = context.name
    normalized = None if name is None else _metadata_normalize_name(name)
    if name is not None and normalized is None:
        return iter(())

    # The default Context.path reads sys.path, which is deliberately empty in
    # the controlled provider. Only an explicitly supplied path narrows this
    # archive's independent namespace; never coerce or inspect an OS path.
    if "path" in vars(context):
        virtual_root = _origin(_METADATA_ROOT)
        if not any(isinstance(path, str) and path == virtual_root for path in context.path):
            return iter(())

    distribution_type = _metadata_distribution_type()
    root = _MetadataPath(_METADATA_ROOT)
    if not root.exists():
        return iter(())

    def distributions():
        for child in root.iterdir():
            if not child.name.endswith(".dist-info") or not child.is_dir():
                continue
            distribution = distribution_type(child._key)
            if normalized is None or _metadata_normalize_name(distribution.name) == normalized:
                yield distribution

    return distributions()


_ArchiveFinder.find_distributions = _metadata_find_distributions
