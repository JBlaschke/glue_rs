# Descriptor-backed Python package extensions (A7)

Implementation contract, 14 October 2026. Start from merged `478ebcd` on
`codex/a7-python-native-package-imports`. Add a separate closed
`stock-pbs-native-packages` profile before expanding to third-party native wheels.
Preserve both registered-initializer profiles, their exact app bytes, image/API
inventories and trace policies.

Reuse the unchanged lifecycle dependency and three native roots, with their
reviewed twelve public Python imports and sole integer ledger export. Map the
three exact dotted names `glue_native_pkg.glue_native_lifecycle`,
`glue_native_pkg.glue_native_create_error` and
`glue_native_pkg.glue_native_lifecycle_exec_error` to the existing leaf
`PyInit_*` exports. The parent is an archive source package with a relative-import
helper and stream-based text/binary resources. Native children are non-package
modules; native `__init__` packages and native-child resource readers are later
contracts.

Use the stock public `ExtensionFileLoader` create/exec protocol, delegated by a
narrow loader subclass. Native `__file__`, spec origin, loader path and filename
remain the truthful `/proc/self/fd/N` alias of the retained verified descriptor.
Parent source/package/resource identities remain virtual `glue://` identities.
Do not temporarily replace a spec or pretend native children are built-ins.
Kernel memory objects are already permitted by the no-extraction contract;
descriptor aliases do not create payload directory entries. Path-relative native
data consumers remain unsupported until separately adapted and tested.

Before Python starts, completely verify the archive and host native bytes,
inspect every ELF image, then privately load and owner-check the complete
dependency-first closure exactly as for the lifecycle profile. Retain the exact
same source-FD alias used by preloading for stock dynamic import. Descriptors and
loader handles remain process-pinned. Require the reviewed local/eager dynamic
loader flags and verify closure bases, exports, relocations and global absence
again after stock creation/execution, including failure paths. Reuse the same
five-state pure-C ledger check after finalization, preserving the original app
error when checks pass.

A scoped byte callback exposes only those three verified descriptor aliases and
performs native ownership checks. The resource callback/context remains live
through finalization and uses existing bounded reply ownership and panic guards.
The native finder accepts only its exact full names under the expected archive
parent path. Unknown owned children, source/native collisions and forged aliases
must fail explicitly without filesystem fallback. Existing source-only callbacks
retain their behavior. No Python object crosses Rust.

Keep the API4 29-export table and C boundary unchanged. Pass zero
`AppendInittab` registrations for this profile; stock dynamic import owns module
creation, execution, caching and error cleanup. Establish this through source/
contract checks and absent names in `sys.builtin_module_names`, rather than
claiming syscall tracing can observe an API call.

Require an early independent stock-PBS descriptor-loader baseline before shared
runtime edits. Measure dynamic-cache initializer counts instead of assuming they
match built-in registration. It must prove dotted metadata, relative imports,
package resources, cache/reload/removal, create/exec failures and retry, GC and
five-state final cleanup. Then require portable protocol/admission tests and the
same four independently selected bundled/host runtime × archived/host native
image cells, their app errors, and pre-load corruption/missing-image controls.
Use the original unstripped CPython 3.13.16 / PBS `20261009` GNU Linux arm64
runtime, unchanged frozen/69-source host prerequisites and verified headers.

Run offline, unprivileged and read-only after producer, headers, input interpreter,
repository and staging are unavailable. Reuse a fresh lifecycle trace graph with
new exact source/manifest/command bindings; add only measured workload predicates.
Retain compact complete traces, source/artifact identities and rejection receipts.
Historical native cases must still run through their unchanged policies.

This establishes package-member dynamic loading for the reviewed corpus. Real
native wheel ingestion, libc/dependency-heavy extension admission, other runtime
versions/platforms, subinterpreters and image unloading remain open. The public
[loader protocol](https://docs.python.org/3.13/library/importlib.html#importlib.machinery.ExtensionFileLoader),
pinned [stock loader](https://github.com/python/cpython/blob/v3.13.16/Lib/importlib/_bootstrap_external.py)
and [dynamic backend](https://github.com/python/cpython/blob/v3.13.16/Python/dynload_shlib.c)
define the behavior used here.
