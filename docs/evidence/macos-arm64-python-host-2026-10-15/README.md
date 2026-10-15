# macOS arm64 explicit-host Python startup evidence

Captured on 15 October 2026 from clean feature commit `6c1207b` on
`claude/macos-python-host`, based on merged `0c9b522`.
[Decision 0031](../../decisions/0031-macos-python-host-startup.md) defines the
experiment; the [fixture](../../../fixtures/python-host-macos/README.md)
describes the harness. This is the project's first Python execution on macOS.

The observed cell is macOS 26.7 (Darwin 25.6.0, build 25G229) on Apple
silicon with 16 KiB pages, Rust 1.88.0 and Apple clang 21.0.0. The runtime is
the unchanged stock PBS `20261009` CPython 3.13.16 aarch64-apple-darwin
install-only artifact (SHA-256 `3338fcd5…`), whose `libpython3.13.dylib`
(18,023,664 bytes, SHA-256 `c688d6d2…`, ad-hoc linker-signed) and six
reviewed startup sources were verified without extraction before the
application-only archive (2,864 bytes) was written. The artifact ships three
encodings bytecode caches; the harness removes them before runtime, as the
Linux startup profile requires, and the installation is read-only throughout.

The C boundary compiled against the artifact's 264 verified headers
(`boundary-provenance.txt`); the probe links only libSystem and libiconv, not
libpython (`launcher.dependencies.txt`). The feature-enabled crate suite
passes 173 tests, including the C boundary self-tests and the Mach-O UUID
parser checks, and Clippy is clean with warnings denied (`tests.txt`,
`clippy.txt`).

Runtime receipts, all run with poisoned Python environment variables,
unavailable home and temporary paths and no loader overrides:

| Case | Status | Observation |
| --- | --- | --- |
| `success` | 0 | `PASS Python=3.13.16 encodings=installed math=built-in ssl=built-in answer=42 openssl=OpenSSL 3.5.9 29 Sep 2026` |
| `app-error` | 1 | same output, then `intentional Python host app error` |
| `wrong-library` | 1 | library identity mismatch before loading |
| `wrong-stdlib` | 1 | `encodings/utf_8.py` identity mismatch before loading |
| `missing-encodings` | 1 | missing startup source rejected before loading |
| `symlink-stdlib` | 1 | symlinked stdlib directory rejected before loading |
| `missing-library` | 1 | missing library rejected before loading |
| `cached-bytecode` | 1 | startup bytecode cache rejected before loading |
| `loader-override` | 1 | `DYLD_LIBRARY_PATH` rejected in preflight |
| `unsupported-linux-mode` | 2 | the Linux `run-host` route reports unsupported |

`check-results.py` compared every status, stdout and stderr with its expected
exact value. The installation snapshot (`installation.before.txt`,
`installation.after.txt`: mode, owner, size, mtime and ctime of every entry)
is identical after all runs, and the only cache present afterwards is the
deliberate `cached-bytecode` control (`caches-after.txt`).

No syscall or filesystem tracer is available to an unprivileged user on this
cell; `tracing.txt` records that and the root `fs_usage` command that would
supply a trace. Absence of payload writes is therefore supported by the
read-only installation, the unavailable home and temporary paths and the
unchanged snapshot, not by a trace. That trace, the product registry route,
bundled macOS Python and the distribution signing policy remain open.

`artifacts.sha256` covers every retained file except itself. Under
[decision 0030](../../decisions/0030-evidence-retention.md) the receipts
beyond this README and the inventory are published as a release asset and
restored with `scripts/fetch-evidence.sh`; `bundle.json` records that
publication.
