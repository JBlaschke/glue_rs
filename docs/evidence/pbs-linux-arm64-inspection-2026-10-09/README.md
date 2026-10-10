# Stock PBS build-time inspection evidence

Captured on 2026-10-09 from clean implementation
`886a415`, branch `codex/a7-pbs-artifact-inspection`, based on merged `1425d6d`.
This is A7/A10 input inspection, not Python execution or G1 acceptance.
The [decision](../../decisions/0010-pinned-pbs-inspection.md) defines admission
and remaining work.

## Inputs and observations

Stock conventional-GIL CPython **3.13.16**, PBS release **20261009**, source
commit `ccc07c40c2731bfb459c119f2388f65a5a470de6`, GNU Linux arm64 / `pgo+lto`:

| Artifact | Compressed bytes | SHA-256 |
| --- | ---: | --- |
| Full `.tar.zst` | 95,632,430 | `8907ec2f181f0fc5cd08b9d897d36159432405af78f68f8faca728f48940e0ca` |
| Unstripped install-only `.tar.gz` | 57,626,877 | `397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34` |

[Pins and exact URLs](inputs/pins.json), upstream checksum manifest, selected
asset identities, raw release/tag API records and original-record hashes are
retained under `inputs`. Both actual downloads matched the upstream checksum
manifest and GitHub asset digests. Downloaded runtime archives and compiled
executables remain ignored build-time files, outside this bundle.

The Rust inspector inventories **6,574** full entries and **4,526** install-only
entries. All retained entries match type, mode, size, digest and raw/resolved
links after the reviewed upstream projection. Omissions are 393 outside the
installation, 2 static libpython archives, 1,645 stdlib test files and 8 test
extension images. Independent Python TAR inventories agree with every original
path/type/mode/size/hash/raw-link field.

The optimized Mac and Linux reports are byte-identical: **3,368,785 bytes**,
SHA-256 `03d417402bae7556432dc43b3a407c7f5579e06b5bd72c0b6c5debf4ab554f8b`.
The complete [report](inspection.json.gz) is retained as deterministic gzip;
[metadata.json](metadata.json) exposes the startup candidates directly.
The Mac full-only command agrees with the same full inventory and metadata;
the wrong-digest command exits 1 with empty stdout before decompression.

## Validation

Mac arm64 and offline Podman GNU Linux arm64 both pass **268/269 workspace
tests** for Lua 5.4/5.5 and all-target Clippy with warnings denied. Both pass
**56 optimized PBS inspection tests**. All **71 Python policy tests** pass,
including 17 new adversarial PBS trace-policy tests. Formatting passes.
Exact environment, commands, compiler/test logs and executable hashes are
retained. Linux uses immutable image
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`, read-only
workspace/root filesystem, anonymous build/tmp storage and no network.

The [complete Linux trace](linux/inspection.trace.txt.gz) retains every record,
including failed attempts. The strict checker admits only declared inputs and
observed Rust/OS startup reads, two complete compressed read passes per artifact,
and inherited stdout for the report. It rejects unknown operations, mutation
attempts, executable payload mappings, shared/writable file mappings and extra
processes. Its [result](linux/trace-check.txt) passes. Read/write buffer contents
are abbreviated by strace; the returned stdout byte total is checked, while the
actual report contents/hash are independently verified.

[capture.json](capture.json) records uncompressed report/trace identities and
counts. [source-file-sha256.json](source-file-sha256.json) matches every retained
source/fixture path to the clean implementation commit; historical evidence is
excluded. [SHA256SUMS](SHA256SUMS) covers every other file in this bundle.

## Runtime findings and limits

Actual libpython is a 73,563,968-byte ELF64 AArch64 shared object, exceeding the
controlled Lua loader's 16 MiB image limit. Separate
[file research](inputs/linux-aarch64-libpython-elf-research.json) observes
ABS64/TLSDESC relocations outside its admitted subset, seven OS dependencies
with GLIBC 2.17 requirements, and no RPATH/RUNPATH. The actual file's inittab
contains `math` and `_ssl` with matching initializer symbols. This file-table
observation does not prove initialization or imports in a running interpreter.
The upstream metadata's malformed `glibc-max-symbol-version:2.17)` claim is
preserved rather than used as an accepted release floor.

The Rust report only checks binary headers and metadata/resource identity. It
always leaves `bootstrap_observed` and `loader_compatibility_validated` false.
No Python interpreter was loaded or executed, no host-Python provider was
validated, and no runnable glue archive was produced. uv trees, stripped
artifacts, other OS/architecture slices and portable resource normalization
remain pending. Existing macOS signing/tracing and FreeBSD producer blockers
remain open.

The pinned primary sources are the
[PBS release](https://github.com/astral-sh/python-build-standalone/releases/tag/20261009),
[metadata format](https://github.com/astral-sh/python-build-standalone/blob/ccc07c40c2731bfb459c119f2388f65a5a470de6/docs/distributions.rst)
and [install-only conversion](https://github.com/astral-sh/python-build-standalone/blob/ccc07c40c2731bfb459c119f2388f65a5a470de6/src/release.rs#L470).
Upstream documentation/source hashes are recorded; these source files and
`config.c` are not redistributed in this bundle.

## Reproduce

Acquire the two exact inputs from `inputs/pins.json` into `target/pbs-inspection`.
Use the [fixture command](../../../fixtures/python-pbs/README.md), or run the
retained `macos-validation.sh` / `linux-validation.sh` with their stated output
paths and the same offline image. The Linux invocation used:

```sh
podman run --rm --network none --read-only \
  --tmpfs /tmp:rw,size=256m --tmpfs /build-target:rw,size=2g \
  --mount "type=bind,source=$PWD,destination=/workspace,ro" \
  --mount "type=bind,source=$PWD/target/pbs-inspection/final-886a415,destination=/evidence" \
  --workdir /workspace --env RUSTUP_TOOLCHAIN=1.88.0 \
  --env CARGO_HOME=/tmp/cargo --env CARGO_TARGET_DIR=/build-target \
  62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe \
  sh /evidence/linux-validation.sh
```

Vendor locked dependencies to `target/vendor` first. Trace revalidation needs
only Python and the retained gzip file; no runtime download is necessary:

```sh
python3 scripts/check-linux-pbs-trace.py \
  docs/evidence/pbs-linux-arm64-inspection-2026-10-09/linux/inspection.trace.txt.gz \
  --stdout-bytes 3368785
```

The auxiliary `inspect-libpython-file.py` reproduces the file research against
the pinned full input using Python 3.11+ and the build-time `zstd` command; it
verifies the compressed pin first, keeps libpython/config bytes in memory and
emits JSON. It is separate from the Rust inspector and its no-extra-process
trace. The original checksum/API hashes refer to uncompressed record bytes;
gzip copies preserve them exactly.
