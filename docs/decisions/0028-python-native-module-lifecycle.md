# Registered Python module lifecycle conformance (A7)

Implementation contract, 14 October 2026. Continue from merged `3f6bf8f` on
`codex/a7-python-native-lifecycle`.

Add a separate exact registered-initializer lifecycle corpus and profile. Keep
the historical registered-extension corpus, its five-image inventory, admission,
runtime/stdlib pins and trace policies unchanged. This step uses the original
unstripped CPython 3.13.16 / PBS `20261009` GNU Linux arm64 runtime and the same
four independently selected bundled/host runtime × archived/host native-image
combinations. It does not extend the stripped metadata provider to native modules.

The new closure has three roots: `glue_native_lifecycle`,
`glue_native_create_error` and `glue_native_lifecycle_exec_error`, plus a pure-C
`libglue_python_lifecycle.so` dependency. Each root has multi-phase initialization,
a real custom `Py_mod_create`, positive `m_size`, execution, traversal, clearing
and free callbacks. Creation obtains `spec.name` through public APIs and returns
`PyModule_NewObject`; state becomes available during execution. State owns a
Python reference cycle (state → list → module), with no global Python references.
Monotonic instance IDs identify records; pointer addresses are not stable IDs.

The application checks built-in metadata, import caching, reload preservation,
fresh state on removal/reimport, method errors without state loss and explicit GC
of a removed instance. It uses built-in `gc` and `_weakref` to avoid expanding the
host source inventory. A first custom-create failure occurs before state
allocation; a separate first execution failure occurs after allocating owned
state. Both remove incomplete imports, allow successful retry and leave no
failed-state ownership after collection. Retained instances and archive resource
callbacks remain usable from `atexit` during actual interpreter finalization.

Callbacks handle absent state safely. Traversal visits every owned Python
reference; clearing detaches references before decref; free releases any remaining
reference idempotently. Do not require an exact traversal count or universal
clear-before-free order. Assert observed traversal and release/free semantics for
the deliberately constructed cycles, with ordinary stock execution establishing
the concrete observations. CPython does not call these callbacks when positive
state size was requested but state has not yet been allocated.

Trace replay checks descriptor/mapping operations and publication order. The
reviewed C/Rust call sequence, pinned integer ledger and independent stock driver
establish finalization timing and callback semantics; syscall tracing does not
observe Python API call returns directly.

The dependency exports exactly one reviewed pure-C integer dispatch function,
`glue_python_lifecycle_ledger`, with a bounded fixed record array and no Python,
libc, allocation, constructor or TLS dependency. Roots record plain IDs/events;
the ledger owns no Python pointers. Its query/check operations remain callable
after finalization. Rust verifies its export address and loader owner, retains
the native images, and checks every allocated state was freed exactly once with
no owned references after the C boundary returns. Run this check on both successful
and intentional application-error paths; preserve the original application error
when lifecycle checks pass. An independent ordinary stock registration driver
checks the same ledger after its own `Py_FinalizeEx`.

Complete cleanup is a measured acceptance condition for this bounded fixture.
CPython's finalization API does not guarantee a universal destruction order or
complete cleanup of every extension/reference cycle. Require the independent
stock baseline to establish the observation before claiming it for the adapter.

Carry a private closed profile descriptor through manifest preparation, complete
archive/host-byte verification, ELF admission and native loading. Its finite public
Python import set and sole dependency export belong only to this lifecycle profile.
Inspect and owner-check every actual relocation against the selected runtime or
dependency. Preserve the old descriptor's exact imports/exports and five-image
rules. Keep the existing API4 29-export C table, extension record and public
`PyImport_AppendInittab` protocol unchanged. No Python object crosses Rust, and no
Python object/API is used to inspect the ledger after finalization.

Require portable contract tests, stock ordinary-loading comparison, native
four-cell success/application-error runs and archive/host corruption or missing
image rejection before loading. Run offline and unprivileged from relocated,
read-only inputs with producer, compiler headers, input interpreters and staging
absent. Retain complete traces, source/artifact identities, plain-C post-finalize
observations and bounded evidence. New trace predicates describe only measured
workload changes; historical policy bodies remain intact. Keep evidence compact
and avoid unnecessary repeated tests after all required checks pass.

This establishes additional lifecycle cases for trusted registered C code, not
arbitrary wheels, extension-file discovery, subinterpreters, free-threaded/debug
ABIs, image unloading, another runtime version or another platform. The native
package corpus and four-platform gates remain later work. CPython's
[module API](https://docs.python.org/3.13/c-api/module.html) and pinned
[module implementation](https://github.com/python/cpython/blob/v3.13.16/Objects/moduleobject.c)
define the callback/state behavior being tested.
