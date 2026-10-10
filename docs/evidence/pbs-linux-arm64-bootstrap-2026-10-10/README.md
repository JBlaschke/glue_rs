# Stock PBS frozen bootstrap — GNU Linux arm64

The optimized `glue-python-bootstrap-probe` started the unchanged stock CPython
3.13.16 / PBS `20261009` shared library from a read-only archive on 2026-10-10.
Frozen `encodings` and built-in `math`/`_ssl` imports succeeded, and its output
matched ordinary loading of the same library, frozen bundle and app. All four
complete syscall traces pass the strict fixture policy, including the three
intentional error controls.

The final build and captures used clean implementation commit
`30a152624f6f10ecf78cf7688800208a93b3d375` on
`codex/a7-linux-pbs-bootstrap`, based on merged `8b56f7c`.
`source-status.txt` and `source-diff.patch` are empty. `source.sha256` records the
tracked files at that implementation checkpoint, excluding evidence directories;
later evidence/documentation changes are recorded in the following commit.

## Observed cell and inputs

The immutable local image ID is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`, with
repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`.
It uses Rust 1.88.0 and Debian bookworm. The observed Podman VM has Linux
`7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, GCC 12.2.0, strace 6.1,
4,096-byte pages and `vm.memfd_noexec=0`. See `environment.txt` and
`image-inspect.json` for the complete records.

`upstream-pins.json` retains the full and unstripped install-only artifact URLs,
sizes and hashes. The matching stock executable compiled six pinned startup
sources at build time. `freeze-provenance.json` records both upstream pins,
selected source/library/compiler identities, installed headers and compiler
command. `freeze-bundle.json` is the exact trusted compiled startup bundle.
`build-provenance/` contains the release C bridge records and undefined-symbol
inventories: no Python symbols are linked into the launcher. The shim used 264
verified installed headers totaling 1,830,329 bytes.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Release launcher | 2,211,760 | `f9d0989cd796ff8646b452abc2f7a71fcfd042011e65b9ec6930ee42d6bff796` |
| Prepared archive | 73,705,762 | `8b053ffce2bb07a3fa4e68bd9fb1659fe30808d76c1b307f653a2441a577aad4` |
| Frozen bundle | 138,635 | `fabac46c75f9a0a7e2e705cf269a8b212fdead5ab657e2572ee26d079696c5d0` |
| Unchanged stock libpython | 73,563,968 | `42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219` |

`fixture-summary.json`, `artifacts.sha256` and `manifest.canonical.json` retain
the exact runtime/resource identities. The large launcher, upstream archives
and prepared archive are reproducible build outputs and are not committed here.
The baseline library hashes recorded immediately before and after ordinary
loading are identical.

## Execution and trace results

The build container provisioned the stock producer and headers, froze the
startup modules, ran release tests/Clippy, prepared the archive and captured the
ordinary-loader baseline. It then removed the producer, installed stdlib,
headers, library files and Cargo intermediates. `post-removal-files.txt` shows
only the relocated launcher/archive, runtime harness and Rust metadata.

A separate runtime container had a read-only root and build mount, no workspace
mount, no network and no installed Python executable. The payload ran as
UID/GID 65534, with an empty working directory, poisoned Python environment
variables, unavailable HOME/TMPDIR paths and mode-000 `/tmp`. The outer harness
created trace/stdout/stderr files in its evidence mount; the traced launcher
only wrote to inherited output descriptors. `runtime-identity.txt`,
`runtime-mounts.txt` and `commands.sh` retain those conditions.

| Mode | Exit | Result | Trace records |
| --- | ---: | --- | ---: |
| Ordinary baseline | 0 | Expected stdout, empty stderr | Not traced |
| Sealed archive success | 0 | Byte-identical baseline stdout, empty stderr | 2,489 |
| Missing frozen encodings | 1 | Empty stdout, exact startup-error stderr | 2,594 |
| Corrupt encodings marshal bytes | 1 | Empty stdout, exact startup-error stderr | 2,594 |
| Intentional app error | 1 | Expected stdout followed by exact app-error stderr | 2,492 |

The successful output is exactly 108 bytes:

```text
PASS Python=3.13.16 encodings=frozen math=built-in ssl=built-in answer=42 openssl=OpenSSL 3.5.9 29 Sep 2026
```

Each trace captures every syscall with `strace -f -s 256 -yy -e trace=all`.
The checker verifies one process, complete archive read coverage, exactly one
fully populated memfd, all four seals installed and independently queried
before image use, both expected private stock image segments, exact diagnostic
writes and the expected exit. It rejects filesystem mutation attempts, fallback
source lookups, extra processes, unknown calls and executable anonymous or W+X
mappings. The original memfd remains pinned through process exit.

Admitted OS reads are the controlled loader libraries/cache, self process maps
and PBS mimalloc's exact `overcommit_memory` read. Startup makes one failed
lookup of `/__glue_archive__/launcher`; glibc makes one failed
`/usr/share/zoneinfo/UTC0` lookup before using `TZ=UTC0`. Neither reads file
contents. Only these exact absent-path queries are admitted.

`trace-summary.json` records raw and deterministic-gzip byte counts and SHA-256
identities. All four compressed traces were decompressed and hash-checked,
then independently replayed through the checker. The original and compressed
replay logs are retained separately.

## Validation and reproduction

Mac and GNU Linux source workspaces passed 291 tests with `lua54` and 292 with
`lua55`, plus all-target Clippy with warnings denied. These logs were collected
while assembling the implementation. They include 64 PBS inspector tests and
15 portable bootstrap bundle/profile tests. The fresh clean-commit release
bootstrap capture passed 16 GNU opt-in tests, release Clippy and release build.
All 89 Python trace-policy tests passed, including 18 new bootstrap policy
tests. Mac opt-in compilation passed; direct execution rejected with status 2
before opening the missing archive. All logs are retained in this directory.

From the repository root, provision the independently pinned upstream inputs
as described in [the PBS fixture](../../../fixtures/python-pbs/README.md), make
the recorded image available, and use new capture/build directories:

```sh
sh fixtures/python-bootstrap/run-linux.sh target/python-bootstrap-recapture \
  target/python-bootstrap-recapture-build
```

The exact final harness is retained as `commands.sh`;
`linux-workspace-commands.sh` records source workspace validation. Host harness
stdout/stderr and exit status are also retained. Replay the saved traces from
the repository root without the large archive:

```sh
evidence=docs/evidence/pbs-linux-arm64-bootstrap-2026-10-10
for mode in success missing-encodings bad-bytecode app-error; do
  python3 scripts/check-linux-python-bootstrap-trace.py "$evidence/$mode.trace.txt.gz" \
    --mode "$mode" --stdout-file "$evidence/$mode.stdout.txt" \
    --stderr-file "$evidence/$mode.stderr.txt" --archive-bytes 73705762
done
```

`SHA256SUMS` covers every retained file other than itself. It records corruption
detection, not author authentication.

## Limits

This is one optimized GNU Linux arm64 startup observation using the exact stock
library and a trusted frozen startup subset. The ordinary-loader comparison
does not implement the host provider with an installed stdlib. Product Python
execution, archive imports/resources, native extensions, general stdlib support,
other operating systems/architectures and release acceptance remain open.
It is not a sandbox for arbitrary bytecode or app code. The generic native Lua
loader profile and product resource limits remain unchanged; G0/G1/G2 remain
open. See [the bootstrap decision](../../decisions/0011-stock-pbs-frozen-bootstrap.md).
