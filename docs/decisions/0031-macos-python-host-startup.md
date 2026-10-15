# Explicit macOS arm64 host Python startup (A7/A1)

Implementation contract, 15 October 2026. Start from merged `0c9b522` on
`claude/macos-python-host`. This is the first Python execution on macOS in
the project and the first corrective step from the
[status review](../reviews/2026-10-15-status-review.md): platform breadth
before more A7 depth on the Linux arm64 cell.

## Scope

Add a separate `stock-pbs-host-startup-macos` profile that starts the exact
pinned stock PBS CPython 3.13.16 / `20261009` macOS arm64 install-only
library from an explicitly declared installation and runs the shared startup
application from an application-only archive. The profile mirrors the GNU
Linux [explicit host startup](0012-explicit-host-python-startup.md): the same
six reviewed startup sources, whose bytes are identical in the macOS artifact,
the same cache rejection, isolated configuration, poisoned environment and
C-owned interpreter lifecycle through the unchanged API4 29-export boundary.

Preparation verifies the independently pinned install-only artifact's
compressed identity, complete tar inventory, library bytes and the six
startup sources without extracting. The build script compiles the same C
boundary with Apple clang against the artifact's 264 verified headers; only
`pyconfig.h` differs from the GNU Linux pin set. On macOS the boundary is
compiled only when `GLUE_PYTHON_INCLUDE_DIR` names that verified tree, so
feature-enabled Mac builds without one continue to validate declarations only.

## Mechanism

Execution preflight rejects nonempty `DYLD_*` overrides, requires 16 KiB
pages, admits one attempt per process, requires that no Python API export is
already visible and that every preloaded image other than the launcher lives
below `/usr/lib/` or `/System/Library/`. Verification opens every path
component without following symlinks, hashes the library and startup sources
through retained descriptors and rejects startup bytecode caches. dyld then
loads the library by its verified canonical path with eager binding and local
scope. After loading, the dyld image table must contain exactly the verified
path plus approved OS images, the mapped header's `LC_UUID` must equal the
`LC_UUID` of the verified bytes, and all 29 API addresses must resolve inside
that image. Descriptors and the loader handle stay pinned for process life.

Loading by path is a host-provider property, not a relaxation of the
no-extraction rule: the installation is a declared prerequisite, the archive
holds only the application, and nothing is written. Open descriptors do not
freeze mutable files on macOS, so the installation must remain immutable and
read-only throughout execution, as the Linux host profiles already require.

## Evidence and limits

The fixture captures success, an intentional application error, six rejected
installations, a loader-override rejection and the Linux-only mode's
unsupported status, with before/after snapshots of the read-only
installation. No syscall or filesystem tracer is available to an unprivileged
user on this cell; the evidence records that explicitly, and a root `fs_usage`
capture remains a separate acceptance item. The target profile records the
observed macOS 26.7 cell as its minimum version; it is not a tested floor.

This establishes the macOS explicit-host provider for one startup subset. It
does not map a bundled runtime, admit native extensions, discover
installations, cover the complete stdlib or settle the distribution signing
policy. Product registry integration follows as a separate step.

## Bundled macOS feasibility, measured

The same artifact's `libpython3.13.dylib` was inspected for the bundled
route, which would map the image from the archive through the A1 Mach-O
mapper instead of dyld:

| Property | Value |
| --- | --- |
| Fixup format | classic `LC_DYLD_INFO_ONLY`, no chained fixups |
| Thread-local variables | 4 descriptors, including `_Py_tss_tstate` and mimalloc's heap |
| Lazy symbol pointers | 684 |
| Weak references | 45 |
| Constructors | 2 |
| Unwind metadata | `__unwind_info` and `__eh_frame` present |
| OS dependencies | libSystem, libz, libedit, libncurses, libpanel, SystemConfiguration, CoreFoundation |
| Signature | ad-hoc, linker-signed |

The A1 mapper deliberately rejects thread-local variables, lazy and weak
binding streams and unwind sections. Thread-local support is the blocking
item: CPython's thread state lookup uses it on every API call, and a mapper
must supply the per-image key allocation and thunk that dyld provides for
thread-local access, on every thread Python creates. Lazy pointers can be
bound eagerly by the mapper and weak references can be resolved explicitly;
unwind registration matters for diagnostics rather than execution. A
launcher-plus-archive form could also let dyld load the library directly if
the archive file doubled as a fat Mach-O container holding one slice per file,
which does not extend to the standalone executable form. These remain open
A1 decisions; they are recorded here so that bundled macOS Python is planned
from measurements rather than assumptions.
