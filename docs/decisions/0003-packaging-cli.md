# Explicit-inventory builder and CLI

Status: accepted for schema zero, 8 October 2026.

`glue-pack` consumes an existing validated manifest and a stable builder input
tree. It includes exactly the declared resource inventory; package resolution,
native dependency closure and runtime artifact ingestion are later work. The
CLI exposes `build --manifest --root --output`. The experimental builder keeps
inputs and compressed output in memory, so it limits total decoded build inputs
to 256 MiB independently of the archive reader's per-entry/metadata limits.

All resource components must be regular files beneath the canonical input root;
symlink components are rejected. Lengths and hashes are checked against bounded
reads, then the generated container is opened and verified. Only then is the
destination created with `create_new`. Existing destinations are preserved.
Output I/O failures may leave a partial file; readers reject truncated containers.
The builder is not a race-resistant sandbox for a concurrently mutated input
tree. Runtime readers do not depend on this filesystem packaging module.

`inspect` validates metadata and reports provider/target/host declarations.
`verify` checks all resource contents. `cat` returns a verified member on stdout;
it has no materialization API. `explain-size` separates compressed payload,
uncompressed payload and container/manifest overhead. `doctor` reports available
core operations and pending runtime/platform capabilities.

The initial executable advertises no runnable language/native profile. `run`,
`doctor APP.glue` and `build --standalone` return 2 with a useful pending-feature
diagnostic. They never select a different provider to simulate success.
Successful core commands return 0; malformed input and argument errors return 1.
The CLI consumes ordinary host paths with spaces and Unicode while archive
resource identities retain the version-zero portable-path contract.
