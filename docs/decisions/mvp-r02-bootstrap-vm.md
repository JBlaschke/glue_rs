# R02: proposed owned VM NONTRACING bootstrap batch

Status: approved implementation boundary; no authentication, staging or VM execution
is authorized by this component. Candidate
kit02 has build ID `a75d54bba97103ec8b15dd7be7beb5b8eb23de5bfdda624ad2fcd9f224ab84d5`
and manifest `098b758fe740d61efccd2ef34d3fe8cf00caba82e281dbc752e419e7a973995c`;
independent audit must approve the final literal bindings first.
The reviewed-input registration is `5200be9`; its production closure is pinned to
`3d500d4`. This draft does not authorize a root attempt or change SIP/network policy.

## Closed preparation interface

Host-only interface: `prepare-vm-batch --kit ABS --output NEW`.
The reviewed implementation has one literal approved kit/audit input record after
the actual audit; it has no hash, identity, profile, program or trust override.
This needs no new general registration framework. Missing approval refuses before
rendering. Verify normal builder exit zero, its complete exact inventory/result,
both builds and the actual catalog/profile; reject partial-failure output.

Create an exclusive physical output outside the repository. It contains three
unchanged payload executables; catalog/recipe/source-lock/admitted-proof/build
metadata; `root-stage.sh`, `outer.sh`, a plan and a new packet inventory. This is an
explicit **derived subset**, with selected original paths/hashes and the original
kit/audit identities. Its inventory must never masquerade as the complete kit.

Render a fresh ASCII batch nonce and all guest paths as literals. Render the root
script first, pinning payload hashes, build ID, actual root/Data tuples and fixed
case paths; then render the outer script with the literal root-script SHA. The
external inventory pins both scripts. The root script does not embed the outer
or external inventory hash. Preserve equal root/Data device numbers when FSIDs
differ. No guest Python, compiler or newly built helper is required.

## Exact sequence

1. The ordinary outer script verifies the complete derived packet, expected VM
   model/OS/SIP-enabled context and nonroot real/effective IDs. It creates one
   exclusive ordinary-user 0700 workspace at a rendered physical private/tmp
   path. Identity/group declarations come only from actual `make-request`
   syscalls, never `SUDO_*`, `id` group reordering or caller-provided values.

2. Use at most one private `sudo -v` authentication; all subsequent calls use
   `sudo -n` with fixed argv and a clean environment. Expired authentication
   stops the batch. A small reviewed literal OS bootstrap command creates the
   rendered fresh root0700 stager directory, copies the root script, closes the
   writer, verifies its destination SHA against the literal, and only then
   invokes `/bin/sh` on that destination. Never stream or dot-source share code.
   Later root invocations use only closed phase names and the verified script;
   there is no arbitrary command, path, hash, profile or ID parameter.

3. The install phase observes existing physical root/System/Volumes/Data/Library
   ancestors without changing them. Create a fresh root0700
   `Library/GlueMVPFixtures` and its exact 64-hex compiled build directory. For
   this first batch, an existing fixture prefix/build directory refuses; do not
   repair/chmod an unreviewed existing prefix. Copy the three executables into
   fresh root-owned, single-link destination files. Close all writers, remove
   inherited ACLs only on newly owned objects, and set files0555 while directories
   remain0700. Verify destination bytes and strict signatures for all three before
   any new native executable runs. Expose directories0755 last. No writable
   aliases are retained; this is a controlled fresh installation under the
   explicit no concurrent privileged mutation invariant, not proof against an
   administrator. Preserve the root stager and journals; do not automatically
   remove evidence or the protected deployment.

4. As the real ordinary user, invoke the protected `make-request` with no args
   for positive/denied cases and exactly `--simulate-provider-failure` for SIM.
   Close and retain every stdout/stderr/status; a short or failed request is
   partial and never replayed. Generate denied-cwd input while the build directory
   is0755. Derive the trailing case from a canonical request plus exactly one byte.
   Each root phase snapshots its fixed input into new private closed root files;
   there are no concurrent request/namespace writers. The native decoder remains
   authoritative. Request declarations are not authentication of an arbitrary user.

5. Run these fixed cases in order using only the protected native CLI with
   `--request FIXED_ABS --output FIXED_NEW_PHYSICAL_TMP`, clean environment and
   fixed compiled catalog/probe/cwd. Record the native status separately from
   sudo/stager status, before any classification:

   | Case | Required native outcome |
   |---|---|
   | Positive | CLI0, consistent probe, exact READY/ATTEMPT/probe bindings, normal reaped exit0. |
   | SIM | CLI1; child ERROR seq1/stage9/reason10/errno0/flags3; READY matched, no GO. |
   | Denied cwd | In one root call: chmod newly owned build dir0700, run, verify closure, restore0755. CLI1; ERROR seq0/stage6/reason3/errno13/flags1; no READY or GO. |
   | Trailing request, LAST | CLI2 and fixed new output absent before/after; read no probe outputs. |

6. For SIM/denied require the exact reported ERROR, reported-error EOF2,
   protocol records2/1, no wire/IO faults, probe_matched=false, go attempted and
   possibly_released=false, bytes0 and closed=true. Do not require raw wait120:
   cleanup may kill/reap before natural error exit. Before restoring denied mode
   or exporting files require normal CLI0/1, the exact result schema,
   wait.forked/reaped=true, lost=false, zero cleanup_error, and successful
   restore_called/pipe_restored/mask_restored. Source-pinned promotion additionally
   guarantees no ambiguous close. Use typed `plutil` extraction on the protected
   canonical producer JSON; host validation later decodes all binary records.
   Separate closure from expected-case matching: restore0755 after verified
   closure even if the expected failure differs, then mark failure and halt.
   Any unresolved ownership/closure or unexpected CLI2 halts, leaves mode/state
   and exact root output pointer recorded, and never reads possibly live outputs.

7. Export only known-closed `request.bin`, `status.bin`, `probe.stdout`,
   `probe.stderr`, `result.json`, plus batch-owned closed journals/logs. Require
   capture-valid flags and exact observed lengths/hashes; zero placeholders are
   not observations. Root read streams feed exclusive ordinary-user files;
   never recursively copy/chown into a user-controlled destination. Pending is
   omitted unless separate closure proof exists. Transfer only this owned fixed
   allowlist to a new results-share directory. Failed/partial export stays marked
   partial. Strict host validation checks inventory, typed JSON, canonical request,
   status/probe records, all identities and expected outcomes before any conclusion.

## Remaining prerequisites and limits

Approved audit bindings and final render bytes remain pending. Implementation
belongs only under the new `bootstrap-vm` directory and this decision, without
changing the production builder or this actual kit's bytes. Host controls cover
closed kit/subset validation, quoting and rejected selectors, exclusive outputs,
hash-DAG rendering, shell syntax and modeled closure-before-restore/export order;
they do not execute a root script or stage a VM. The final bytes require separate
review before authentication. Implementation must verify the guest `plutil`
typed-extraction behavior; unsupported behavior refuses without regex fallback.
There is no new watchdog: the runner's attempt/cleanup deadlines do not bound a
stalled native syscall or arbitrary descendants. An uncertain/hung attempt needs
separate investigation, never an automatic retry, fabricated closure or export.
All outcomes retain `tracing`, `exec_proved` and `full_acceptance` false. This batch
does not implement the Darwin tracer or establish full R02/M2 acceptance.
