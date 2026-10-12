"""Close default filesystem imports before installing the verified source index."""


def _glue_close_host_imports():
    import sys as _sys
    import _frozen_importlib_external as _external

    _sys.meta_path[:] = [finder for finder in _sys.meta_path if finder is not _external.PathFinder]
    _sys.path[:] = []
    _sys.path_importer_cache.clear()
    _sys.path_hooks[:] = []
    del globals()["_glue_close_host_imports"]


_glue_close_host_imports()
