# N00: stock Node archive proof

The stock Node subprocess route works for the tested CJS/ESM/JSON/resource and
Node-API corpus. The Rust bridge uses `glue-format::Archive`, retaining its bounds,
CRC32 and SHA-256 checks; it never materializes a source or resource. Node-API 8
provides tagged external handles, a GC finalizer and copied output buffers. The
bridge links no libnode and requires no Node headers. Native fixture preparation
is a separate developer operation; packaging copies its existing images unchanged.

```sh
export PATH="$(dirname "$(rustup which cargo)"):$PATH"
export CARGO_TARGET_DIR=/tmp/glue-node-target
cargo build --manifest-path spikes/node-archive/Cargo.toml --locked
# macOS: .dylib; Linux: .so
cp "$CARGO_TARGET_DIR/debug/libglue_node_archive_probe.dylib" "$CARGO_TARGET_DIR/debug/archive.node"
spikes/node-archive/prepare-native.sh /opt/homebrew/include/node /tmp/node-native-input
python3 spikes/node-archive/run-probe.py \
  --node /opt/homebrew/bin/node \
  --pack "$CARGO_TARGET_DIR/debug/pack" \
  --bridge "$CARGO_TARGET_DIR/debug/archive.node" \
  --native-dir /tmp/node-native-input --output /tmp/node-probe-evidence
```

Repeat `--node` to test additional installed major lines. The harness deletes its
actual source input before running, relocates output under a path with spaces and
Unicode, marks files read-only, uses an unrelated cwd and removes language tools,
HOME, temp and compile-cache access. A failed subprocess fails the recipe. The
receipt reports missing major/platform coverage rather than treating it as a pass.

Actual execution on 15 October 2026: macOS arm64, Node 26.10.0, Node-API 10,
addon ABI 147. Bridge boundary tests and all three application cases passed;
secondary library and addon hashes matched their prepared inputs. Raw local
receipt: `/private/tmp/glue-node-n00-evidence/receipt.json` (not a published
release-evidence asset). Node 22/24 and Linux execution remain unproven: no second
major was installed, and attempted access to nodejs.org failed DNS resolution.
This is executable implementation with incomplete N00 acceptance evidence.

The archive's legacy resource-only envelope is deliberately a spike detail. It
contains a Lua fixture descriptor which is never used for execution. N01 uses the
new compact distribution descriptor; this does not claim legacy Node dispatch.
The hook presently implements the bounded probe corpus; N02 owns the general
resolution semantics. N04 owns an fs facade. The source count stays inside the
archive, but this spike does not provide an R02 extraction trace or bundled Node
runtime closure.

## Index and bridge contract

`module-index.schema.json` freezes logical index revision 1 for N02/N03. All keys
in `files` and all nonempty package roots use canonical archive-relative paths.
The root package key is `""`. Resource/deployed paths obey the same rules.
`entry` must identify a file; addon records declare a deployed sibling path and
minimum Node-API version, with no duplicated archive bytes. Sources and JSON
refer to verified archive resources. `packages[root].dependencies` maps each
installed dependency name to its logical root, preserving separate versions and
pnpm indirection. Package exports/imports preserve JSON object insertion order
because conditional selection is ordered. Runtime-specific decisions are made
by the resolver; N03 must not flatten exports to a single preselected target.

The bridge exports `open(path) -> handle`, `read(handle, canonicalPath) -> Buffer`
and `list(handle) -> JSON string of canonical resource names`. Handles own their
archive file until garbage collection/process exit. No arbitrary JavaScript
external pointer can pass the type-tag check. Bad arguments, wrong handles,
malformed archives and integrity errors throw `ERR_GLUE_ARCHIVE`. Individual path
arguments are capped at 4096 UTF-8 bytes; resource bounds come from glue-format.
