# Installed host Python startup — GNU Linux arm64

The optimized fixture started the unchanged stock CPython 3.13.16 / PBS
`20261009` library with its declared installed standard library on 2026-10-10.
Installed `encodings` and built-in `math`/`_ssl` imports succeeded. All eight
complete host traces pass, including six invalid-installation controls that
reject before Python image mapping and a controlled application error.

Both the host capture and separate frozen-bootstrap regression used clean
implementation `a50ae864acf3cf2b59a338215ead55efea2e179e` on
`codex/a7-linux-host-python`, based on merged `06b92ea`. Their `source-status.txt`
and `source-diff.patch` files are empty. `source.sha256` records tracked source
at that checkpoint, excluding evidence directories. The following commit adds
this evidence and documentation links.

## Observed cell and identities

The immutable local image ID is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`, with
repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`.
It uses Rust 1.88.0 and Debian bookworm. The observed Podman VM has Linux
`7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, GCC 12.2.0, strace 6.1 and
4,096-byte pages. See `environment.txt` and `image-inspect.json`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Release launcher | 2,288,488 | `ccf3b5d9170e9a566e88206956124326116d3407337e7038df670beeadd6b9a5` |
| Successful host archive | 2,741 | `950ce62eaeab9eb59dbe3777b087e0428b97fbbb0fc4fddd98747de11da11d18` |
| Unchanged stock library | 73,563,968 | `42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219` |
| Shared app source | 1,572 | `e8ba0357be86b3d061493c4ec7565c258a1a961033ee8d60fb4fb4f9206a41ed` |

The seven prepared host archives contain only `app/main.py`, with explicit host
library/stdlib paths under prefixes containing spaces. `fixture-summary.json`
and `manifests/` retain every archive identity, canonical manifest and verified
input identity. The app-error run uses the successful archive.

`upstream-pins.json` retains both independently pinned PBS input URLs, sizes and
hashes. `freeze-provenance.json` records the matching build-time producer,
selected sources, library and 264 verified installed headers totaling 1,830,329
bytes. The frozen bundle is a build-time prerequisite for common fixture
preparation and the ordinary-loader comparison; it is absent from host archives
and the runtime build mount. `build-provenance/` records C bridge API revision 2,
21 dynamically acquired Python exports and no linked Python symbols.

`host-runtime-provenance.json` inventories the retained installed source tree
and each invalid control. Runtime verification covers the exact library and
six startup sources. It also requires both startup `__pycache__` locations to
be absent. This does not certify every installed stdlib member.

## Runtime observations

Build-time preparation removes the producer executable, headers, compiler
intermediates, frozen archive/bundle and all valid-installation bytecode caches.
The installed library and stdlib sources remain as explicit host prerequisites.
`post-removal-files.txt` retains the final build-tree inventory.

The separate runtime container has a read-only root and build mount, no
workspace mount, no network and no Python executable. It runs the traced payload
as UID/GID 65534 from an empty working directory, with poisoned Python environment
variables, unavailable HOME/TMPDIR paths and mode-000 `/tmp`. The outer harness
creates capture files in its evidence mount; the traced launcher only writes to
inherited stdout/stderr. See `commands.sh`, `runtime-identity.txt` and
`runtime-mounts.txt`.

| Mode | Exit | Observation | Trace records | Archive bytes |
| --- | ---: | --- | ---: | ---: |
| Success | 0 | Installed encodings, exact stdout, empty stderr | 1,718 | 2,741 |
| Wrong library | 1 | Exact library identity mismatch before loading | 1,298 | 2,769 |
| Wrong stdlib | 1 | Exact encodings source identity mismatch before loading | 1,373 | 2,767 |
| Missing encodings | 1 | Exact missing-source diagnostic before loading | 1,365 | 2,777 |
| Symlinked stdlib | 1 | Exact path-kind rejection before loading | 112 | 2,771 |
| Missing library | 1 | Exact missing-library diagnostic before loading | 169 | 2,773 |
| Cached bytecode | 1 | Exact startup-cache rejection before loading | 148 | 2,773 |
| App error | 1 | Successful stdout followed by exact application error | 1,721 | 2,741 |

Successful output is exactly 111 bytes:

```text
PASS Python=3.13.16 encodings=installed math=built-in ssl=built-in answer=42 openssl=OpenSSL 3.5.9 29 Sep 2026
```

The shared app checks the exact version/build mode, installed encodings source,
all installed prefix fields, one declared stdlib search path, isolated flags,
UTF-8 and the answer 42. C owns configuration, Python references, error buffers
and finalization; no Python object crosses Rust. Host startup leaves the public
custom frozen table untouched, while stock private frozen modules remain stock
CPython behavior.

Each trace captures every syscall using `strace -f -s 256 -yy -e trace=all`.
The strict policy requires complete archive verification and closure before host
validation, no-follow path checks, complete exact input reads with EOF and rewind
before loading, the verified read-only descriptor alias, both expected private
stock-library mappings and installed encodings source imports. The original
library descriptor and loader remain pinned through process exit. Host loading
uses no memfd. Source/directory descriptors remain owned through finalization.
Exact diagnostic publication is gated on the corresponding initialization or
rejection observations.

Only the recorded loader/OS reads, declared source reads, two directory
enumerations and narrowly specified failed CPython import probes are admitted.
The checker rejects unknown calls, filesystem mutation attempts, bundled fallback,
extra processes and anonymous executable or W+X mappings, including failed
attempts. It is an evidence policy for this trusted fixture, not a runtime sandbox.

`trace-summary.json` records raw and deterministic-gzip sizes, SHA-256 identities,
record counts and PIDs. All eight compressed traces were decompressed, hash-checked
and independently replayed through the checker; replay logs are retained.

## Regression and validation

[The frozen regression](frozen-regression/README.md) uses the same clean commit,
release launcher and shared app. Its ordinary-loader baseline and all four fresh
sealed-memfd traces pass after removing the installed producer/stdlib/library.
It proves the existing frozen-startup path survived the shared C/API changes.
Its `encodings=frozen` stdout is 108 bytes; application results agree with the
installed-host cell, while provider diagnostics differ.

Mac and GNU Linux source workspaces passed 308 tests with `lua54` and 309 with
`lua55`, plus all-target Clippy with warnings denied. These logs were collected
while assembling the implementation and include 32 portable bootstrap/host
tests. Both fresh clean-commit Linux fixture builds passed 34 opt-in release
tests, Clippy and compilation. All 112 Python policy tests passed, including
23 adversarial host-checker tests. Independent review also rejected eleven
hostile mutations of real captures. Mac opt-in compilation passed and direct
execution returned status 2 before opening a missing archive.

The source workspace logs, Python policy log and unsupported-target outputs are
retained here. `linux-workspace-commands.sh` records the Linux workspace checks.
The fixture harnesses retain their separate stdout/stderr and exit statuses.

## Reproduction

From the repository root, provision the cached inputs as described in
[the PBS fixture](../../../fixtures/python-pbs/README.md), use the recorded image
and Rust toolchain, and choose new output directories:

```sh
sh fixtures/python-host/run-linux.sh target/python-host-recapture \
  target/python-host-recapture-build
sh fixtures/python-bootstrap/run-linux.sh target/python-host-frozen-recapture \
  target/python-host-frozen-recapture-build
```

Replay the retained host traces without storing the large runtime/build outputs:

```sh
python3 - <<'PY'
import json, pathlib, subprocess, sys
p = pathlib.Path('docs/evidence/pbs-linux-arm64-host-python-2026-10-10')
for mode, archive in json.loads((p / 'fixture-summary.json').read_text())['archives'].items():
    subprocess.run([sys.executable, 'scripts/check-linux-python-host-trace.py',
        str(p / (mode + '.trace.txt.gz')), '--mode', mode,
        '--stdout-file', str(p / (mode + '.stdout.txt')),
        '--stderr-file', str(p / (mode + '.stderr.txt')),
        '--archive-bytes', str(archive['size'])], check=True)
PY
```

`SHA256SUMS` covers every retained file other than itself, including the frozen
regression. It detects corruption and does not authenticate the author.

## Limits

The installation is immutable on a read-only mount. Retained descriptors and
inode checks do not prevent mutation of backing bytes or bind Python's later
source-path lookups against concurrent changes in an arbitrary installation.
General mutable host installations require separate identity/lifetime evidence.

This is one optimized GNU Linux arm64 startup subset with trusted pinned
artifacts. Product Python execution/discovery, application imports/resources,
native extension loading, full-stdlib compatibility, other Python builds/versions,
other platforms and release acceptance remain open. G0/G1/G2 remain open. See
[the host decision](../../decisions/0012-explicit-host-python-startup.md).
