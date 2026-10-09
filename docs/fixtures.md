# Conformance fixture protocol

Fixtures must report the command, commit, native OS/architecture, toolchain,
runtime source/build IDs, supported features, unsupported features and observed
result. Preserve stdout/stderr, exit code and payload-write traces as evidence.
Record whether memory objects or direct mapping were used. Tests must not infer
no extraction from an empty directory after exit.

The first native fixture exports a function and data value, calls one archived
dependency and one actual OS dependency, and reports constructor count. Compare
it with normal OS loading. Wrong architecture, missing imports and unsupported
relocations must fail before a constructor. Later fixtures cover dependency cycles,
TLS on existing/new/library-created threads, callbacks, weak/versioned symbols,
unwind registration and runtime aliases. A trivial function call proves only that
fixture's declared ABI profile.

The integrated [Linux native Lua fixture](../fixtures/native/lua-linux/README.md)
uses the exact linked 5.4.9/5.5.1 core, one archived dependency and a versioned
libc `getpid` import. It checks constructor/data observations, selected-state
identity, real C-function caching and initializer/function errors, and routes
`package.loadlib` through the same retained initializer. All images are sealed
before the first constructor; ordinary loading and archive loading agree.
Portable adversarial tests validate closure metadata without running code;
actual GNU negative captures must reject before any memfd creation/loading.

The [macOS arm64 fixture](../fixtures/native/macos-macho/README.md) compares
ordinary dyld loading with a separate signed anonymous-mapping probe. Its
allow-jit/hardened-runtime launcher checks real function/data exports, one
archived dependency, libSystem `getpid` and a constructor. It never acquires
the schema's Lua scaffold. Complete tracing and Developer ID distribution
remain separate acceptance requirements; an unavailable tracer is recorded as
unavailable, not a no-extraction result.

Python startup must use actual stock PBS and compatible host libraries, import
`encodings`, `math` and `_ssl`, and prove library/stdlib identity. FreeBSD needs
its own bundled producer. Node and Lua fixtures must use the actual runtimes;
synthetic workers prove protocol behavior only.

Parser/resource fixtures may be synthetic and run on the development host. They
must cover deterministic output, stored/deflate and ZIP64 members, path/case
collisions, undeclared payloads, symlinks, encryption, unknown schema fields,
duplicate JSON keys, truncated/overlapping ranges, corrupt hashes/CRC, decoding
limits, positional reads, EOF, streams, cache bounds and a relocated archive.
Those tests are foundation evidence, not G1 or G2 acceptance.
