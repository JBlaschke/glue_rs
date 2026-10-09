#!/usr/bin/env python3
"""Make an explicit build-only inventory for the controlled mapping probe."""
import hashlib
import json
import pathlib
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: manifest.py INPUT_ROOT")
    root = pathlib.Path(sys.argv[1])
    paths = [
        "native/libglue_probe_dep.dylib",
        "native/libglue_probe_module.dylib",
        "scaffold/main.lua",
    ]
    resources = {}
    for name in paths:
        data = (root / name).read_bytes()
        resources[name] = {
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "compression": "stored",
        }
    target = "macos-aarch64"
    manifest = {
        "schema_version": 0,
        "app_id": "macos.macho.probe",
        "entrypoint": "fixture",
        "targets": {
            target: {
                "os": "macos",
                "arch": "aarch64",
                "minimum_os_version": "13.0",
                "abi": {"family": "darwin"},
                "page_sizes": [16384],
                "cpu_features": [],
            }
        },
        "resources": resources,
        "runtimes": {
            "scaffold": {
                "target": target,
                "build_id": "unacquired-fixture-scaffold",
                "abi": {
                    "language": "lua",
                    "version": {"major": 5, "minor": 4, "patch": 9},
                    "integer_bits": 64,
                    "number": "float64",
                },
                "provisioning": {
                    "mode": "host",
                    "runtime_library": "/unacquired-fixture-scaffold/liblua.dylib",
                    "stdlib": "/unacquired-fixture-scaffold/stdlib",
                    "discovery": "explicit_paths",
                },
                "required_features": [],
            }
        },
        "components": {
            "fixture": {
                "runtime": "scaffold",
                "entry_point": "scaffold/main.lua",
                "native_modules": ["module"],
            }
        },
        "native_modules": {
            "dependency": {
                "target": target,
                "resource": paths[0],
                "format": "mach_o",
                "namespace": "probe",
                "runtime": None,
                "dependencies": [{"class": "operating_system", "import": "libsystem"}],
                "required_features": ["function_exports"],
            },
            "module": {
                "target": target,
                "resource": paths[1],
                "format": "mach_o",
                "namespace": "probe",
                "runtime": None,
                "dependencies": [
                    {"class": "archived_module", "module": "dependency"},
                    {"class": "operating_system", "import": "libsystem"},
                ],
                "required_features": ["function_exports", "data_exports", "constructors"],
            },
        },
        "host_imports": {
            "libsystem": {
                "class": "operating_system",
                "target": target,
                "library": "/usr/lib/libSystem.B.dylib",
                "symbols": ["getpid"],
            }
        },
    }
    print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
