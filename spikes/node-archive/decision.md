# Provider choice from N00

Use stock Node with public synchronous `module.registerHooks` and a Node-API 8
Rust bridge, loaded before the entry module. Synchronous hooks cover both CJS and
ESM without coupling Rust to V8/libnode internals; a verified archive reader can
serve bytes directly. Virtual `file:` URLs preserve CJS filenames/createRequire
and module identity. Declared native records resolve to their already deployed
`.node` paths, allowing Node's normal loader to retain the secondary library's
OS-loader layout. Compile caches are disabled by the launch environment.

The macOS 26.10.0 execution demonstrates this mechanism. It does not establish
two-major or Linux acceptance; those explicit gaps remain in the N00 README.
There is no hook limitation requiring a Deno substitution, so implementing a
second runtime has no demonstrated benefit.

Primary references, checked 15 October 2026:
[Node synchronous hooks](https://nodejs.org/api/module.html#moduleregisterhooksoptions)
and [Node-API](https://nodejs.org/api/n-api.html). The implementation probes the
actual runtime rather than inferring support only from its version number.


Revision-one index extension: `aliases` is optional and empty when absent. Each
canonical alias key maps to `{target,directory,link_size}` with a canonical target
(root target may be empty). This retains ordinary realpath module cache identity
and exposes internal resource links without duplicate archive/native bytes. New
distributions ship their matching bounded resolver/bootstrap; existing no-alias
indexes retain their behavior. Cycles and escapes fail rather than consulting
host filesystem paths.

Installed npm/pnpm lockfiles are build-time provenance rather than instructions.
The bounded YAML token parser accepts ordinary pnpm mappings but rejects aliases,
tags, duplicate keys, excessive depth and token counts. It never expands YAML
references. `glue.lock.json` records lock byte identities and version/presence
mismatches with installed metadata; unsupported lock shapes say comparison was
unavailable. Installed package/resource bytes remain authoritative in all cases.
