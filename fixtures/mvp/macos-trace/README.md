# macOS syscall capability probe

This is a diagnostic prerequisite for R02, not a complete macOS extraction
backend. A new [native capability transport](CAPTURE_FORMAT.md) can be built on
the host and copied to an approved guest without guest Python or compiler tools.
Its raw syscall/process fixtures remain capability-only until a full decoder and
oracle are implemented and validated.

The owned UTM guest completed all nine v8 diagnostics on 16 October 2026:
2,647 original events, no reported drops/errors and consistent receipt identities
under the [independent reader](READER.md). The captures calibrate exec-shadow
cleanup, failed-spawn parent continuation, process-tree coverage and open-only
queue draining in this corpus. The [open observer](OPEN_OBSERVATIONS.md) also
replays the two v8 open-only streams, retaining 15 whole-stream calls. These
root-run captures have networking enabled and do not satisfy the offline
application corpus or full R02/M2. After guest-only restoration in Recovery and
normal reboot, the running guest reports SIP enabled. All ten read-only metadata
commands and the independent proof/hash review pass; the
[separate restoration checkpoint](../../../docs/evidence/compact-mvp-darwin-restoration-2026-10-16/README.md)
retains that observation. The physical host's policy remains unchanged.

The [raw-call pairing adapter](call-pairing/README.md) independently validates
capture/toolkit inputs and pairs 1,193 returned calls across the seven v8 tree
captures. Thirteen additional entries retain explicit termination boundaries
with no fabricated return. Pairing preserves raw provenance and supplies no
filesystem or Mach effects decision.

The [tree-open bridge](tree-open/README.md) retains 68 named-open observations
across those process/thread lifetimes. The
[Mach scalar observer](mach-msg2/README.md) retains 18 packed message-call
observations in the Mach-enabled capture and reports the other six profiles as
not enabled. Copied paths, numeric descriptors and message fields do not prove
file objects, port identities or effects; both acceptance APIs remain closed.

The separate [credential primitive](target-credentials/README.md) validates and
applies an explicit numeric identity only in an owned child, with precise
failure stages and exact real/effective ID and group readback. Its controls and
independent review pass; it is not integrated into the collector. Privileged
Darwin transition calibration, inherited-FD/cwd/signal setup and the launch gate
remain open. Existing root-target capture bytes and receipts are unchanged.

A root-authenticated wildcard preflight on the physical host reported:

```
dtrace: failed to match syscall:::entry: System Integrity Protection is on
```

The root-authenticated exact-name capture on Darwin 25.6.0 arm64 also failed:

```
probe description syscall::open:entry does not match any probes. System Integrity Protection is on
```

It returned exit 1, recorded zero events and did not start the fixture body.
This rules out a wildcard-listing-only limitation. Root authentication does not
override this OS tracing restriction. No SIP,
tracing-policy, entitlement, signing-credential or other system setting is
changed. Passwords never enter these scripts. A narrower owned-fixture probe
reproduces the exact-name capability check.

Prepare an independent diagnostic fixture, without root:

```sh
fixtures/mvp/macos-trace/prepare-probe.sh /new/absolute/probe-directory
```

The helper compiles only the checked-in test source, signs it ad-hoc and verifies
its signature at its actual path. The fixture directly calls Darwin `SYS_open`,
reads a 20-byte controlled input, writes a fixed completion marker and exits.
Its three-second alarm bounds fixture execution. The deprecated libc `syscall`
entry is used deliberately here to avoid ambiguity between libc's open/openat/
open_nocancel wrappers; it is not a product runtime interface.

The operator reviews and invokes this command through the host's native
administrator authentication mechanism:

```sh
/usr/bin/python3 fixtures/mvp/macos-trace/capture-probe.py \
  /new/absolute/probe-directory --output /new/absolute/capture-directory
```

The capture script requires root, never elevates itself, and runs `/usr/sbin/dtrace`
with the checked-in `open-probe.d`, `-c` containing only the quoted owned fixture
and input, and a new output directory. It deliberately omits `-Z`, so a missing
or prohibited `syscall::open:entry` probe fails instead of appearing successful.
A 15-second timeout kills/reaps the capture process group. Raw trace, DTrace
stderr, target stdout, exact argv, native host facts and file identities are
retained in `capability.json` and its accompanying files.

`captured` means only that this particular owned fixture completed and emitted
at least one matching syscall event. `unavailable` records the observed SIP
provider rejection. Neither status is an R02 application acceptance pass.

Before a complete Darwin backend can be accepted, actual captures must establish:

- syscall entry/return/errno conventions, with complete successful and failed
  attempts and lossless bounded path decoding;
- exec, fork/vfork/posix_spawn, exits, thread coverage and descendants that outlive
  their parent, including any protected executable that becomes unobservable;
- descriptor inheritance/dup/close and received file descriptors, cwd/dirfd and
  Darwin-specific filesystem mutation calls;
- shared writable mmap and Mach/fileport or other write routes, rejecting
  unsupported mechanisms instead of assuming they are read-only;
- explicit rejection of DTrace errors, dropped events, truncation and incomplete
  entry/return/process terminal records;
- actual positive, create/unlink, denied-write, descendant-write and shared-map
  controls, followed by the relocated/offline Lua/Python/Node corpus.

The Linux strace protocol and its oracle remain separate. A userspace libc
interposer, `fs_usage` summary, parser-only test or file snapshot does not replace
complete Darwin capture evidence. The native guest diagnostics supply the
bounded calibration above; the physical-host failures below remain unchanged.

## Retained local result identities

Raw/local inventory files remain outside Git. No release asset or durable remote
retention is claimed. These local identities describe unavailable capability,
not macOS application acceptance:

| Local file | SHA-256 |
| --- | --- |
| `/private/tmp/glue-mvp-macos-dtrace-preflight.log` | `b7b865fe2eaa5f34034e660c7dbc313d6fe75e9fd5f1d66e84a0f8034b3405f1` |
| `/private/tmp/glue-mvp-macos-dtrace-open-probe/capability.json` | `88a86175c4630f4a3d975c00778bcf8ede0f0def2166af83787b00cbe7202c9a` |
| `/private/tmp/glue-mvp-macos-dtrace-open-probe/dtrace.stderr` | `c43d5a21988439ba4a3e96562c299feb28ee016ab8dfdd430ec4e5ebb903cbd8` |
| `/private/tmp/glue-mvp-macos-trace-capability-inventory.json` | `87252a9ff28dcf25f46f8bed66a9b898bccc3a79a9e3ce927837ecb87629a413` |

The prepared ad-hoc fixture was independently verified and completed its
readiness run before capture; the authenticated capture failed at provider
selection before it could run. Full descendant/filesystem tracing remains
unavailable on this host under the unchanged OS policy.
