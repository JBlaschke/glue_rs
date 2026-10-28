# R02: bounded standalone owned-trace diagnostics

Status: accepted for an operator inspection command. Native acceptance stays open.

The integrated request assessment accepts original bytes and a raw line stream.
Add an operator entry point without adopting a native capture, bypassing its
export gates or introducing a second extraction oracle.

## A separate diagnostic input

Add `owned-trace-assessment/inspect_trace.py` with
`inspect_directory(path, *, owner_pid, target_pid)` and a CLI:

```
python3 inspect_trace.py --input DIRECTORY --owner-pid PID --target-pid PID
```

The directory must contain exactly `program.d`, `probes.tsv`, `errors.jsonl` and
`events.jsonl`. Stop scanning at a fifth entry; no recursive discovery, wildcard
input or extra sidecar is accepted. Require numeric mode0700 and current-user
ownership on the directory, and mode0600, own-user, ordinary single-link files.
These are numeric ownership/mode checks, not ACL privacy attestation. Reject
privileged or mismatched real/effective UID/GID operation before input access.

The input origin and owner/target PIDs remain caller declarations. Exact rosters,
valid transport and ownership do not authenticate a capture or establish native
export safety. Native packet, metadata/closure and export workflows retain their
own requirements; this command must not call or replace their admission APIs,
create an export or authorize reading/copying protected failed captures. Tests
use independent synthetic diagnostic inputs only.

## Held inputs and complete publication

Hold directory and leaf descriptors with no-follow, close-on-exec and
nonblocking flags. Verify held file identities against anchored directory
entries before and after reads, and verify root path/held identity and exact
roster again. Use fixed upstream program/inventory/error/transport/line bounds;
no caller limit overrides. Static bytes are bounded; events stream through the
assessment once. Use the fixed exact contract asset through bounded trusted
source handling. Load assessment code/dependencies only when input inspection
is requested; there are no hash or helper-path overrides.

Every input must finish validation and closure before a report is returned or
stdout is touched. Attempt all closes once; any read, identity, roster or close
failure suppresses the report. Stable trusted source and owned input namespaces
without a concurrent privileged mutator remain workflow preconditions. These
checks are not a native process, object or causal-order attestation.

Return a distinct diagnostic report binding exact file byte counts/hashes,
declared PIDs and fixed assessor/core identities, plus the complete assessment.
Its origin is explicitly caller-supplied/unverified, native/export admission is
false, status is incomplete, and full acceptance/state-feed eligibility are
false. Canonical JSON, including its final LF, must fit16MiB before any stdout
write. Oversize output refuses without truncation or a partial fallback report.
Ordinary stdout I/O failure cannot promise atomic publication to a broken pipe.

Normal exit0 means a diagnostic report was produced; invalid input exits1 and
argument errors exit2. `--acceptance` alone always exits1 before required-input
checks, helper imports or filesystem input access. It cannot be selected as a
native harness backend. Error diagnostics are bounded and do not dump raw input.

Controls cover actual temporary directory/file/FIFO/symlink/hardlink boundaries,
exact caps/roster, stable and changed identities, static refusal before event
consumption, read/close failures, early acceptance refusal and output-byte bounds.
Run ordinary CLI success on synthetic inputs with incomplete results and verify
stdout remains empty on invalid input. Preserve the assessment implementation,
upstream/native sources and admission pins. Add the new suite to portable CI and
publish this feature on its own dependent branch/PR while other CI continues.
