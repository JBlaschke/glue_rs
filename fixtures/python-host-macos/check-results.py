"""Compare every macOS host fixture receipt with its expected exact value.

usage: python3 -I fixtures/python-host-macos/check-results.py EVIDENCE_DIR OUTPUT_DIR

Exit statuses, stdout and stderr of every runtime case must match. Build,
test and lint logs must report success, and the boundary provenance must
record the macOS cell. The deliberate cached-bytecode control is the only
cache allowed after the runs.
"""

import os
import re
import sys

PASS = ("PASS Python=3.13.16 encodings=installed math=built-in ssl=built-in "
        "answer=42 openssl=OpenSSL 3.5.9 29 Sep 2026\n")
PROBE = "glue-python-bootstrap-probe: "
CONTROLS = ("wrong-library", "wrong-stdlib", "missing-encodings", "symlink-stdlib",
            "missing-library", "cached-bytecode")


def read(evidence, name):
    with open(os.path.join(evidence, name), encoding="utf-8") as handle:
        return handle.read()


def expect(evidence, name, status, stdout, stderr):
    actual = (read(evidence, name + ".exit-status.txt").strip(), read(evidence, name + ".stdout.txt"),
              read(evidence, name + ".stderr.txt"))
    if actual != (str(status), stdout, stderr):
        raise SystemExit(f"{name}: expected {(status, stdout, stderr)!r}, observed {actual!r}")


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    evidence, out = argv[1:]
    valid = os.path.join(out, "host Python", "python")
    control = {mode: os.path.join(out, "controls", f"host Python {mode}", "python") for mode in CONTROLS}
    stdlib = lambda prefix: os.path.join(prefix, "lib", "python3.13")  # noqa: E731
    library = lambda prefix: os.path.join(prefix, "lib", "libpython3.13.dylib")  # noqa: E731

    for mode in ("success",) + CONTROLS:
        expect(evidence, f"{mode}.prepare", 0, "prepared explicit macOS host Python startup archive\n", "")
    expect(evidence, "success", 0, PASS, "")
    expect(evidence, "app-error", 1, PASS, PROBE + "intentional Python host app error\n")
    expect(evidence, "wrong-library", 1, "",
           PROBE + f"host file identity mismatch: {library(control['wrong-library'])}\n")
    expect(evidence, "wrong-stdlib", 1, "",
           PROBE + f"host file identity mismatch: {stdlib(control['wrong-stdlib'])}/encodings/utf_8.py\n")
    expect(evidence, "missing-encodings", 1, "",
           PROBE + f"host path {stdlib(control['missing-encodings'])}/encodings/utf_8.py: "
           "No such file or directory (os error 2)\n")
    expect(evidence, "symlink-stdlib", 1, "",
           PROBE + f"host path {stdlib(control['symlink-stdlib'])} must be a directory without symlinks\n")
    expect(evidence, "missing-library", 1, "",
           PROBE + f"host path {library(control['missing-library'])}: No such file or directory (os error 2)\n")
    expect(evidence, "cached-bytecode", 1, "",
           PROBE + f"host startup bytecode cache is unsupported: {stdlib(control['cached-bytecode'])}/encodings/__pycache__\n")
    expect(evidence, "loader-override", 1, "", PROBE + "loader override DYLD_LIBRARY_PATH is unsupported\n")
    expect(evidence, "unsupported-linux-mode", 2, "",
           PROBE + "execution requires pbs-bootstrap on GNU Linux arm64\n")

    caches = read(evidence, "caches-after.txt").splitlines()
    if caches != [os.path.join(stdlib(control["cached-bytecode"]), "encodings", "__pycache__")]:
        raise SystemExit(f"unexpected caches after runs: {caches!r}")
    if read(evidence, "installation.before.txt") != read(evidence, "installation.after.txt"):
        raise SystemExit("installation snapshot changed")
    if read(evidence, "controls.stderr.txt") != "":
        raise SystemExit("control preparation wrote to stderr")

    tests = read(evidence, "tests.txt")
    results = re.findall(r"^test result: (\w+)\. (\d+) passed; (\d+) failed", tests, re.M)
    if not results or any(r[0] != "ok" or r[2] != "0" for r in results):
        raise SystemExit("test log does not report success")
    passed = sum(int(r[1]) for r in results)
    for name in ("macos::tests::c_boundary_self_tests_pass_on_macos",
                 "macos_host::tests::manifest_round_trips_through_admission_and_rejects_other_profiles"):
        if f"test {name} ... ok" not in tests:
            raise SystemExit(f"missing test {name}")
    clippy = read(evidence, "clippy.txt")
    if "error" in clippy or "warning:" in clippy:
        raise SystemExit("clippy log reports diagnostics")
    provenance = read(evidence, "boundary-provenance.txt")
    for line in ("boundary_compiled=true", "boundary_cell=macos-arm64/install-only-artifact-headers",
                 "verified_installed_header_count=264", 'TARGET="aarch64-apple-darwin"'):
        if line not in provenance:
            raise SystemExit(f"boundary provenance lacks {line}")
    launcher = read(evidence, "launcher.dependencies.txt")
    if "libpython" in launcher:
        raise SystemExit("launcher links libpython")
    if read(evidence, "shipped-caches.txt").splitlines() != [
        "python/lib/python3.13/encodings/__pycache__/__init__.cpython-313.pyc",
        "python/lib/python3.13/encodings/__pycache__/aliases.cpython-313.pyc",
        "python/lib/python3.13/encodings/__pycache__/utf_8.cpython-313.pyc",
    ]:
        raise SystemExit("artifact ships different caches than expected")
    print(f"PASS macOS host fixture: 1 success, 1 app error, 6 installation rejections, "
          f"1 loader-override rejection, 1 unsupported mode, {passed} tests")


if __name__ == "__main__":
    main(sys.argv)
