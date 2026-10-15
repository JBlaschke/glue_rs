import importlib.machinery
import json
import platform
import sys
import sysconfig

print(json.dumps({
    "executable": sys.executable,
    "prefix": sys.base_prefix,
    "stdlib": sysconfig.get_path("stdlib"),
    "version": list(sys.version_info[:3]),
    "version_text": sys.version,
    "implementation": sys.implementation.name,
    "machine": platform.machine(),
    "system": platform.system(),
    "soabi": sysconfig.get_config_var("SOABI") or "",
    "gil_disabled": bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
    "debug": bool(sysconfig.get_config_var("Py_DEBUG")),
    "framework": sysconfig.get_config_var("PYTHONFRAMEWORK") or "",
    "extension_suffixes": importlib.machinery.EXTENSION_SUFFIXES,
}))
