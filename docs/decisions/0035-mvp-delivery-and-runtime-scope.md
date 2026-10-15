# MVP delivery and runtime scope

Product direction, 15 October 2026; implementation pending. This records the
owner's clarifications and the sequencing chosen in [PLAN.md](../../PLAN.md).

## Context and decision

The owner requires no runtime extraction, accepts existing compiled modules
without rebuilding, permits a compact collection of shared libraries, and uses
“static” to mean self-contained language distribution. The deployment concern
is HPC nodes and shared-filesystem startup pressure, not literal static linkage.

Use `compact` as the native-capable MVP: the builder emits a relocatable launcher,
archives, selected runtime/helpers and shared-library closure. Payload creation
happens before execution. The launcher never restores or unpacks missing files.
Add explicit `memory` mode for archived native images without payload filesystem
paths. No silent memory-to-compact fallback.

Compact mode is a sequencing choice under the allowed tree distribution, not
proof of filesystem-free deployment. That requires the memory milestones. A
transport tarball may be unpacked by deployment tooling before the app starts;
glue never extracts it on first invocation.

## Scope

Linux and macOS first; Windows/BSD later. Lua 5.4/5.5, extensible to later
versions. User-selected modern CPython (including PBS/uv trees) and Node, without
hardcoded upper-version ceilings or input-artifact allowlists. Stock interpreter
processes are the compact Python/Node design; existing embedding work remains
for memory mode. Deno is a possible measured substitution, not a parallel MVP.

Native support depends on interfaces, binary features and runtime dependencies.
C, C++ and Rust internals are allowed, including their TLS/unwind requirements.
Archived ObjC/Swift runtime registration is outside the initial memory mapper.
Future Julia support accepts complete prebuilt PackageCompiler library bundles.

## Consequences

- Preserve exact fixture profiles as historical tests. General inputs do not
  need package names, app IDs or digests added to Rust code.
- Compact OS loading must not inherit the experimental memory parser's narrow
  feature restrictions. Keep parsing safety, target, dependency and ABI checks.
- Runtime selection cannot replace a version underneath incompatible modules.
- Load-path normalization is opt-in, reported and signed where necessary. It is
  neither recompilation nor byte-identical repackaging.
- Runtime subprocesses are execution adapters; general RPC remains later work.
- M0–M4 replace G0–G6. Old Windows/FreeBSD-first, pinned-only and Python-before-Node
  assignments no longer determine the next work.

See [contracts](../plans/mvp-contract.md), [tasks](../plans/mvp-tasks.md), and
[memory gates](../plans/memory-roadmap.md) for implementation acceptance.
