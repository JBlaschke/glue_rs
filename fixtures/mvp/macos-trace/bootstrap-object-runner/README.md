# Adopt descriptor observations in the real bootstrap READY path

This source-selected profile uses the actual bootstrap runner implementation.
The fixed wrapper translation units define `GLUE_FD_OBJECTS` before including
that implementation. The default profile keeps its legacy wire, public IO result
sizes and closed native admission. No runtime option chooses a protocol or
weakens credentials, signals, executable admission or the root-only native entry.

The child completes endpoint mapping, credential/CWD setup, numeric descriptor
closure and signal verification, then captures the five retained descriptors
using `tfo_snapshot_in_owned_child`. It checks the original absolute deadline
before and after capture. Its complete READY uses the distinct 512-byte object
status envelope. ERROR/EXEC_ATTEMPT use that same envelope with zero object rows;
failed or late writes exit without appending a replacement record.

The parent transfers ownership of its existing output source handles into two
explicit held-reference slots. It retains them through cleanup. It reads and
validates the complete envelope, applies the existing request/READY comparison,
checks that its actual child has not been reaped/lost, and matches the captured
regular output backing observations against those held references. Matching and
a post-match check of the original deadline precede trace creation or GO. The
trace entry also requires the match. Another child check precedes GO. Failure
routes use existing whole-child cleanup; reference close failures suppress final
promotion. No pathname reopen substitutes for a held-reference match.

The object GO has distinct magic/version. A legacy controller cannot accept the
first256 object-status bytes as READY, and this profile never accepts a legacy
GO or status record. There is no negotiation or fallback. Record transport may
be fragmented; confirmed prefixes from failed IO stay opaque and are never
replayed. The new fixed512 IO API shares its internal engine with legacy IO,
whose public result prefix remains256 and whose APIs still refuse512 requests.

`status.bin` retains exact received envelope bytes. The distinct v2 diagnostic
receipt records the profile and match result. `exec_proved` and full acceptance
remain false. Backing observations rely on controlled, quiescent owned-child
lineage; they do not establish OFD/generation/path identity, later descriptor
lifetimes, arbitrary process state or the Darwin extraction oracle.

Run `python3 fixtures/mvp/macos-trace/bootstrap-object-runner/test_object_runner.py -v`.
Controls exercise the real child/parent source through isolated process/native
boundaries and the actual wire/BIO decoder. Ordinary native gated exchanges use
real TE mapping, Darwin native TD closure (Linux test-only procfs inventory),
actual snapshots, full-envelope decoding, held-reference matching and GO/output
bytes. They also refuse legacy/truncated status, wrong references and legacy GO.
The credential/request digest fields in this standalone exchange are observed
credential data and fixed test bindings; it does not execute the root-only
production admission/credential transition. Separate controls compile both fixed
profiles, execute only ordinary-user admission refusal and never start a tracing
provider. Native preconditions may skip unsupported root/group/FD-capacity cases.

Set `GLUE_OBJECT_RUNNER_TEST_RETAIN` to a new directory to retain exact compile
argv, source/binary hashes and command outputs/status. No VM, sudo or SIP change
is involved. Guarded kit construction remains separately unconfigured; source
registration is a separate reviewed C-to-R commit transition.
