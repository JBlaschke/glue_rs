# Reuse the native macOS product-version query

Status: accepted for implementation.

Compact startup currently forks `/usr/bin/sw_vers`, starts a reader thread and polls the child solely to discover the host macOS version. The linked Lua layer already implements the read-only `sysctlbyname("kern.osproductversion")` query behind its private platform boundary. The runner already depends on that crate and forbids unsafe code.

Expose one safe, documented `glue_runtime_lua::profile::macos_product_version()` function that reuses this existing query and returns the existing capability error type. This public function observes only the host product version; it selects or initializes no Lua runtime, archive, provider or process. Other hosts return unsupported. Keep the existing unsafe call in its current reviewed platform module, with its existing bounded output buffer, static selector and null new-value pointer. Add no crate, dependency, unsafe block or lint exception to the runner.

Replace compact host's subprocess/thread path with this function, preserving its existing numeric OS-floor comparison and MissingDependency classification when the host version cannot be queried. Validate the bounded native C string before returning it, including reported length, exact termination and UTF-8; invalid query data must not become a truncated usable version. This change does not relax extraction-oracle spawn/exec handling or substitute a host query for native capture.

Verify the real native query against an env-cleared sw_vers reference inside a macOS-only test, exercise malformed/oversized/unterminated native-string boundaries and numeric macOS floor regressions, then run scoped Lua/runner checks under Rust 1.88.0 and its matching Clippy. Native tests may need the task's existing read-only kernel-query sandbox approval; no SIP, VM or privileged-provider action is involved.
