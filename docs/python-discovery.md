# P01 Python discovery

`glue_pack::python::discovery::discover` accepts an existing environment and an
optional local runtime executable/root. It reads `pyvenv.cfg` separately from an
isolated `-I -S -B` metadata probe, handles base-runtime symlinks and uv-installed
trees, and records exact version, ABI, GIL/debug flags, stdlib, extension suffixes,
site directories and console entry metadata. It never invokes uv/pip or imports
application packages. A selected executable is trusted build code, not sandboxed.

The probe has a 15-second deadline and 64 KiB per-output-stream limit. ELF/Mach-O
architecture is checked before executing a runtime; foreign/inspection-only
requests cannot invoke the interpreter. `inspect_tree` and `inspect_pbs_archive`
inspect without executing; the latter reuses glue-pbs's bounded tar parser and
accepts local raw tar/gzip/zstd bytes without a content-identity catalog. Exact
ABI facts absent from a foreign tree are diagnosed rather than guessed.

Runtime overrides must match the environment's major/minor, SOABI and GIL/debug
mode. Conventional CPython 3.11+ has no hardcoded upper minor ceiling. Debug and
free-threaded execution are explicit unsupported capabilities. `python_version`
accepts `MAJOR.MINOR[.PATCH]` and `==MAJOR.MINOR[.PATCH]`; other constraint syntax
reports a remedy. Framework discovery succeeds, but P02/C04 must decide whether
their absolute binary load paths require explicitly authorized normalization.

```sh
cargo run -p glue-pack --features python --example discover-python -- \
  /supplied/environment /supplied/runtime
GLUE_TEST_PYTHON=/supplied/bin/python3.13 cargo test -p glue-pack \
  --features python --test python_discovery -- --include-ignored
```

The live test ran on macOS arm64 with PBS/uv 3.13.16, 3.14.5 and 3.15.0b1. It
uses a controlled venv-shaped fixture with spaces/non-ASCII and a base-interpreter
link, checks console metadata, poisons `.pth` and `sitecustomize`, and verifies
version-constraint rejection. This proves safe discovery, not uv environment
creation or package installation. Malformed output, oversized output and timeout
tests run with tiny independent executables. Ordinary/framework discovery can
also use the example; no non-PBS relocation or foreign-target execution is
claimed. The broader provider/environment matrix belongs to P05.
