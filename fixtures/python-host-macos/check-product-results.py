"""Compare every macOS product-route receipt with its expected exact value.

usage: python3 -I fixtures/python-host-macos/check-product-results.py EVIDENCE_DIR OUTPUT_DIR

Exit statuses, stdout and stderr of every product command must match. The
manifest digest that `glue inspect` prints is recomputed from the `inspect
--json` receipt, whose declarations must equal the expected manifest; the
GNU Linux declaration is pinned exactly because its inputs are checked in.
Build, test and lint logs must report success, the boundary provenance must
record the macOS cell and the no-boundary provenance its absence. The
deliberate cached-bytecode control is the only cache allowed after the runs;
the read-only installation and the empty working directory must be unchanged.
"""

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CONTROLS = ("wrong-library", "wrong-stdlib", "missing-encodings", "symlink-stdlib",
            "missing-library", "cached-bytecode")
APP_SHA256 = "e8ba0357be86b3d061493c4ec7565c258a1a961033ee8d60fb4fb4f9206a41ed"
APP_SIZE = 1572
LAUNCHER = ("Launcher: glue 0.1.0 on macos/aarch64\n"
            "Linked Lua: 5.4.9 (int64, float64)\n"
            "Available: archive packaging, inspection, verification, read-only resources, "
            "linked Lua source profile\n"
            "Pending: general runtime/package compatibility, Node adapters, workers, standalone signing\n")
SUMMARY = LAUNCHER + ("Python: controlled CPython 3.13.16 / PBS 20261009 profiles; "
                      "explicit macOS arm64 host startup execution only\n")
NO_BOUNDARY_SUMMARY = LAUNCHER + ("Python: controlled CPython 3.13.16 / PBS 20261009 profiles; "
                                  "declaration validation only; no execution boundary is compiled\n")
VALIDATED = "Validated metadata for stock-pbs-host-startup-macos\n"
READY = VALIDATED + ("Ready: controlled explicit-host macOS arm64 Python startup build/target "
                     "prerequisites, CPython 3.13.16 / PBS 20261009\n"
                     "Run checks profile archive limits, contents and explicit host prerequisites "
                     "before loading Python\n")
PASS = ("PASS Python=3.13.16 encodings=installed math=built-in ssl=built-in "
        "answer=42 openssl=OpenSSL 3.5.9 29 Sep 2026\n")
VERIFIED = f"Verified 1 resources ({APP_SIZE} uncompressed bytes)\n"
PREPARED = "prepared explicit macOS host Python startup archive\n"
NO_BOUNDARY = ("glue: the pinned Python boundary is not compiled; macOS arm64 builds require "
               "GLUE_PYTHON_INCLUDE_DIR to name the verified install-only header tree\n")
LINUX_UNSUPPORTED = "glue: the pinned Python target requires macOS arm64\n"
LOADER_OVERRIDE = "glue: loader override DYLD_LIBRARY_PATH is unsupported\n"
LINUX_PREFIX = "/nonexistent/pinned Linux Python"
LINUX_APP_ID = "distribution.metadata"
LINUX_BUILD_ID = "pbs-20261009-cpython-3.13.16-pgo-lto-host-install-metadata-apps-v1"
LINUX_RESOURCES = 10
LINUX_ARCHIVE_BYTES = 13485
LINUX_UNCOMPRESSED_BYTES = 21770
LINUX_MANIFEST_SHA256 = "08ca2f24f529c61ef6d7d1f02f93ea4ea128490eba67844172a568ebd48c2cc2"
LINUX_ARCHIVE_SHA256 = "7cff6b344b4cd167ca910d857bb2ff80d9e65cb108c65a940a01a349f94a9e04"
LINUX_TARGET = {"abi": {"family": "glibc", "minimum_version": "2.36"}, "arch": "aarch64",
                "cpu_features": [], "minimum_os_version": "7.1.4", "os": "linux", "page_sizes": [4096]}
LAUNCHER_DEPENDENCIES = {"/usr/lib/libSystem.B.dylib", "/usr/lib/libiconv.2.dylib"}
SHIPPED_CACHES = [
    "python/lib/python3.13/encodings/__pycache__/__init__.cpython-313.pyc",
    "python/lib/python3.13/encodings/__pycache__/aliases.cpython-313.pyc",
    "python/lib/python3.13/encodings/__pycache__/utf_8.cpython-313.pyc",
]
TRACING = ("No syscall or filesystem tracer is available to an unprivileged user on this macOS "
           "cell: fs_usage, ktrace and dtrace require root. Reproduce with: sudo fs_usage -w -f "
           "filesys <glue pid>. Absence of payload writes is supported here only by the read-only "
           "installation, the unavailable home/temp paths, the empty working directory and the "
           "unchanged installation snapshot, not by a trace.\n")
RUNTIME_TESTS = (
    "platform::tests::this_macos_cell_is_ready_for_the_explicit_host_startup_profile_only",
    "macos::tests::c_boundary_self_tests_pass_on_macos",
    "macos_host::tests::manifest_round_trips_through_admission_and_rejects_other_profiles",
    "profile::tests::explicit_macos_host_startup_is_admitted_portably_without_packaging_bounds",
)


def read(evidence, name):
    with open(os.path.join(evidence, name), "rb") as handle:
        return handle.read().decode("utf-8")


def expect(evidence, name, status, stdout, stderr):
    actual = (read(evidence, name + ".exit-status.txt").strip(), read(evidence, name + ".stdout.txt"),
              read(evidence, name + ".stderr.txt"))
    if actual != (str(status), stdout, stderr):
        raise SystemExit(f"{name}: expected {(status, stdout, stderr)!r}, observed {actual!r}")


def manifest(evidence, name):
    """The decoded `inspect --json` receipt and the digest `inspect` must print."""
    with open(os.path.join(evidence, name + ".stdout.txt"), "rb") as handle:
        data = handle.read()
    if read(evidence, name + ".exit-status.txt").strip() != "0" or read(evidence, name + ".stderr.txt"):
        raise SystemExit(f"{name}: inspect --json did not succeed silently")
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise SystemExit(f"{name}: inspect --json must print one JSON line")
    return json.loads(data), hashlib.sha256(data[:-1]).hexdigest()


def macos_manifest(prefix):
    return {
        "app_id": "stock-pbs-host-startup-macos",
        "components": {"main": {"entry_point": "app/main.py", "native_modules": [], "runtime": "python"}},
        "entrypoint": "main",
        "host_imports": {},
        "native_modules": {},
        "resources": {"app/main.py": {"compression": "stored", "sha256": APP_SHA256, "size": APP_SIZE}},
        "runtimes": {"python": {
            "abi": {"debug": False, "gil": "conventional", "language": "python",
                    "version": {"major": 3, "minor": 13, "patch": 16}},
            "build_id": "pbs-20261009-cpython-3.13.16-macos-host-startup-v1",
            "provisioning": {"discovery": "explicit_paths", "mode": "host",
                             "runtime_library": prefix + "/lib/libpython3.13.dylib",
                             "stdlib": prefix + "/lib/python3.13"},
            "required_features": [],
            "target": "macos-arm64"}},
        "schema_version": 0,
        "targets": {"macos-arm64": {"abi": {"family": "darwin"}, "arch": "aarch64", "cpu_features": [],
                                    "minimum_os_version": "26.7", "os": "macos", "page_sizes": [16384]}},
    }


def macos_inspect(prefix, digest):
    return ("App: stock-pbs-host-startup-macos (schema 0)\n"
            "Entrypoint: main\n"
            f"Manifest SHA-256: {digest}\n"
            "Resources: 1\n"
            "Target macos-arm64: Macos/Aarch64, minimum OS 26.7\n"
            f"Runtime python: Python 3.13.16 on macos-arm64, host library {prefix}/lib/libpython3.13.dylib, "
            f"stdlib {prefix}/lib/python3.13\n"
            "Payload verification: use glue verify\n"
            "Execution support: use glue doctor to check the selected runtime and target\n")


def linux_inspect(digest):
    return (f"App: {LINUX_APP_ID} (schema 0)\n"
            "Entrypoint: launch\n"
            f"Manifest SHA-256: {digest}\n"
            f"Resources: {LINUX_RESOURCES}\n"
            "Target linux-arm64: Linux/Aarch64, minimum OS 7.1.4\n"
            f"Runtime python: Python 3.13.16 on linux-arm64, host library {LINUX_PREFIX}/lib/libpython3.13.so.1.0, "
            f"stdlib {LINUX_PREFIX}/lib/python3.13\n"
            "Payload verification: use glue verify\n"
            "Execution support: use glue doctor to check the selected runtime and target\n")


def check_macos_archive(evidence, name, prefix):
    """inspect, inspect --json, verify and doctor receipts of one macOS archive."""
    decoded, digest = manifest(evidence, name + ".inspect-json")
    if decoded != macos_manifest(prefix):
        raise SystemExit(f"{name}: manifest differs from the explicit macOS host startup profile")
    expect(evidence, name + ".inspect", 0, macos_inspect(prefix, digest), "")
    expect(evidence, name + ".verify", 0, VERIFIED, "")
    return digest


def passed_tests(evidence, name):
    log = read(evidence, name)
    results = re.findall(r"^test result: (\w+)\. (\d+) passed; (\d+) failed", log, re.M)
    if not results or any(r[0] != "ok" or r[2] != "0" for r in results):
        raise SystemExit(f"{name} does not report success")
    return sum(int(r[1]) for r in results)


def clean_log(evidence, name, finished):
    log = read(evidence, name)
    if re.search(r"^(warning|error)", log, re.M) or (finished and "Finished" not in log):
        raise SystemExit(f"{name} reports diagnostics or did not finish")


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    evidence, out = argv[1:]
    valid = os.path.join(out, "host Python", "python")
    control = {mode: os.path.join(out, "controls", f"host Python {mode}", "python") for mode in CONTROLS}
    stdlib = lambda prefix: os.path.join(prefix, "lib", "python3.13")  # noqa: E731
    library = lambda prefix: os.path.join(prefix, "lib", "libpython3.13.dylib")  # noqa: E731
    with open(os.path.join(HERE, "pins.json"), "rb") as handle:
        pins = json.load(handle)
    with open(os.path.join(ROOT, "rust-toolchain.toml"), "rb") as handle:
        channel = re.search(r'^channel = "([^"]+)"$', handle.read().decode("utf-8"), re.M).group(1)

    # Inputs, environment and identities.
    if read(evidence, "artifact.sha256") != f"{pins['install_only']['sha256']}  {pins['install_only']['filename']}\n":
        raise SystemExit("artifact identity differs from pins.json")
    if read(evidence, "library.sha256") != f"{pins['library']['sha256']}  libpython3.13.dylib\n":
        raise SystemExit("installed library identity differs from pins.json")
    environment = read(evidence, "environment.txt")
    for line in ("ProductName:\t\tmacOS\n", " arm64\n", "hw.pagesize=16384\n", f"rustc {channel} (",
                 f"cargo {channel} ("):
        if line not in environment:
            raise SystemExit(f"environment lacks {line!r}")
    if not re.fullmatch(r"[0-9a-f]{40}\n", read(evidence, "source-revision.txt")):
        raise SystemExit("source revision is not a commit")
    if read(evidence, "shipped-caches.txt").splitlines() != SHIPPED_CACHES:
        raise SystemExit("artifact ships different caches than expected")
    launcher = read(evidence, "launcher.sha256").splitlines()
    if [line[66:] for line in launcher] != ["glue", "glue-python-bootstrap-probe"] or \
            not all(re.fullmatch(r"[0-9a-f]{64}  .*", line) for line in launcher):
        raise SystemExit("launcher inventory does not name the copied launcher and probe")
    if not re.fullmatch(r"[0-9a-f]{64}  glue-no-boundary\n", read(evidence, "no-boundary.launcher.sha256")):
        raise SystemExit("no-boundary launcher inventory is malformed")
    dependencies = read(evidence, "launcher.dependencies.txt").splitlines()
    if len(dependencies) != 1 + len(LAUNCHER_DEPENDENCIES) or \
            {line.strip().split(" (", 1)[0] for line in dependencies[1:]} != LAUNCHER_DEPENDENCIES:
        raise SystemExit("launcher links libraries beyond libSystem and libiconv")
    codesign = read(evidence, "launcher.codesign.txt")
    if "Signature=adhoc\n" not in codesign or "Format=Mach-O thin (arm64)\n" not in codesign:
        raise SystemExit("launcher is not an ad-hoc signed arm64 Mach-O")

    # Build, tests and lints.
    if read(evidence, "fmt.txt") != "":
        raise SystemExit("cargo fmt reports differences")
    workspace = passed_tests(evidence, "workspace-tests.txt")
    clean_log(evidence, "workspace-clippy.txt", True)
    clean_log(evidence, "build.txt", True)
    clean_log(evidence, "clippy.txt", True)
    clean_log(evidence, "no-boundary.build.txt", True)
    runtime = passed_tests(evidence, "tests.txt")
    tests = read(evidence, "tests.txt")
    for name in RUNTIME_TESTS:
        if f"test {name} ... ok" not in tests:
            raise SystemExit(f"missing test {name}")
    runner = passed_tests(evidence, "runner-tests.txt")
    if "Running tests/cli.rs" not in read(evidence, "runner-tests.txt") or runner == 0:
        raise SystemExit("runner CLI tests did not run")
    provenance = read(evidence, "boundary-provenance.txt")
    for line in ("pbs_bootstrap_feature=true\n", "boundary_compiled=true\n",
                 "boundary_cell=macos-arm64/install-only-artifact-headers\n",
                 f"install_only_artifact_sha256={pins['install_only']['sha256']}\n",
                 "verified_installed_header_count=264\n", 'TARGET="aarch64-apple-darwin"\n'):
        if line not in provenance:
            raise SystemExit(f"boundary provenance lacks {line.strip()}")
    provenance = read(evidence, "no-boundary.provenance.txt")
    for line in ("pbs_bootstrap_feature=true\n", "boundary_compiled=false\n", "boundary_cell=none\n",
                 'TARGET="aarch64-apple-darwin"\n'):
        if line not in provenance:
            raise SystemExit(f"no-boundary provenance lacks {line.strip()}")

    # Preparation.
    expect(evidence, "controls", 0, "".join(f"prepared control {mode}\n" for mode in CONTROLS), "")
    for mode in ("success",) + CONTROLS:
        expect(evidence, f"{mode}.prepare", 0, PREPARED, "")
    archives = read(evidence, "archives.sha256").splitlines()
    if [line[66:] for line in archives] != sorted(f"{mode}.glue" for mode in ("success",) + CONTROLS) or \
            not all(re.fullmatch(r"[0-9a-f]{64}  .*", line) for line in archives):
        raise SystemExit("archive inventory does not list the seven prepared archives")
    expect(evidence, "linux-declaration.stage", 0, "", "")
    expect(evidence, "linux-declaration.build", 0,
           f"Built {out}/linux/linux-declaration.glue: {LINUX_RESOURCES} resources, {LINUX_ARCHIVE_BYTES} "
           f"archive bytes, {LINUX_UNCOMPRESSED_BYTES} uncompressed bytes\nArchive SHA-256: {LINUX_ARCHIVE_SHA256}\n",
           "")
    if read(evidence, "linux-declaration.archive.sha256") != f"{LINUX_ARCHIVE_SHA256}  linux-declaration.glue\n":
        raise SystemExit("GNU Linux declaration archive identity differs from the pinned build")

    # Product receipts.
    expect(evidence, "doctor-summary", 0, SUMMARY, "")
    success_digest = check_macos_archive(evidence, "success", valid)
    expect(evidence, "success.doctor", 0, SUMMARY + READY, "")
    expect(evidence, "success.run", 0, PASS, "")
    for mode in CONTROLS:
        check_macos_archive(evidence, mode, control[mode])
        expect(evidence, f"{mode}.doctor", 0, SUMMARY + READY, "")
    expect(evidence, "wrong-library.run", 1, "",
           f"glue: host file identity mismatch: {library(control['wrong-library'])}\n")
    expect(evidence, "wrong-stdlib.run", 1, "",
           f"glue: host file identity mismatch: {stdlib(control['wrong-stdlib'])}/encodings/utf_8.py\n")
    expect(evidence, "missing-encodings.run", 1, "",
           f"glue: host path {stdlib(control['missing-encodings'])}/encodings/utf_8.py: "
           "No such file or directory (os error 2)\n")
    expect(evidence, "symlink-stdlib.run", 1, "",
           f"glue: host path {stdlib(control['symlink-stdlib'])} must be a directory without symlinks\n")
    expect(evidence, "missing-library.run", 1, "",
           f"glue: host path {library(control['missing-library'])}: No such file or directory (os error 2)\n")
    expect(evidence, "cached-bytecode.run", 1, "",
           f"glue: host startup bytecode cache is unsupported: {stdlib(control['cached-bytecode'])}/encodings/__pycache__\n")
    expect(evidence, "loader-override.doctor", 0, SUMMARY + READY, "")
    expect(evidence, "loader-override.run", 1, "", LOADER_OVERRIDE)

    decoded, digest = manifest(evidence, "linux-declaration.inspect-json")
    runtime_spec = decoded["runtimes"]["python"]
    if digest != LINUX_MANIFEST_SHA256 or decoded["app_id"] != LINUX_APP_ID or decoded["entrypoint"] != "launch" \
            or len(decoded["resources"]) != LINUX_RESOURCES or decoded["targets"] != {"linux-arm64": LINUX_TARGET} \
            or runtime_spec["build_id"] != LINUX_BUILD_ID or runtime_spec["target"] != "linux-arm64" \
            or runtime_spec["provisioning"] != {"discovery": "explicit_paths", "mode": "host",
                                                "runtime_library": LINUX_PREFIX + "/lib/libpython3.13.so.1.0",
                                                "stdlib": LINUX_PREFIX + "/lib/python3.13"}:
        raise SystemExit("GNU Linux declaration differs from the pinned install-only host metadata profile")
    expect(evidence, "linux-declaration.inspect", 0, linux_inspect(digest), "")
    expect(evidence, "linux-declaration.verify", 0,
           f"Verified {LINUX_RESOURCES} resources ({LINUX_UNCOMPRESSED_BYTES} uncompressed bytes)\n", "")
    expect(evidence, "linux-declaration.doctor", 2, SUMMARY + f"Validated metadata for {LINUX_APP_ID}\n",
           LINUX_UNSUPPORTED)
    expect(evidence, "linux-declaration.run", 2, "", LINUX_UNSUPPORTED)

    expect(evidence, "no-boundary.doctor-summary", 0, NO_BOUNDARY_SUMMARY, "")
    if check_macos_archive(evidence, "no-boundary", valid) != success_digest:
        raise SystemExit("no-boundary launcher inspected a different success archive")
    expect(evidence, "no-boundary.doctor", 2, NO_BOUNDARY_SUMMARY + VALIDATED, NO_BOUNDARY)
    expect(evidence, "no-boundary.run", 2, "", NO_BOUNDARY)

    # The installation after every receipt.
    caches = read(evidence, "caches-after.txt").splitlines()
    if caches != [os.path.join(stdlib(control["cached-bytecode"]), "encodings", "__pycache__")]:
        raise SystemExit(f"unexpected caches after runs: {caches!r}")
    if read(evidence, "installation.before.txt") != read(evidence, "installation.after.txt"):
        raise SystemExit("installation snapshot changed")
    if read(evidence, "working-directory.txt") != "":
        raise SystemExit("the empty working directory gained entries")
    if read(evidence, "tracing.txt") != TRACING:
        raise SystemExit("tracing limitation record differs")
    print("PASS macOS product route: doctor Ready and run PASS, 6 installation rejections, "
          "1 loader-override rejection, 1 GNU Linux declaration and 1 no-boundary build unsupported; "
          f"{workspace} workspace, {runtime} runtime and {runner} runner tests")


if __name__ == "__main__":
    main(sys.argv)
