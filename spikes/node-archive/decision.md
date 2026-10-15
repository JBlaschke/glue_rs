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
