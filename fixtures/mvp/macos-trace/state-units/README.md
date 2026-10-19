# Synthetic normalized process and descriptor state

This reusable replay engine checks a **synthetic normalized unit model**. It is
not a Darwin raw decoder, observation backend, full syscall coverage table or
filesystem oracle. It accepts only `darwin-normalized-state-unit-v1` records with
`origin: synthetic-unit`. Every report has `full_trace_acceptance: false`, and
`require_full_trace_acceptance()` always rejects. Neither this protocol nor the
capability transport is registered as an acceptance backend.

Run the checked-in synthetic descriptor-reuse example and controls:

```sh
python3 fixtures/mvp/macos-trace/state-units/state_machine.py \
  --input fixtures/mvp/macos-trace/state-units/synthetic-fd-reuse.jsonl
python3 fixtures/mvp/macos-trace/state-units/test_state_machine.py -v
```

Exit 0 means the declared synthetic model is internally closed. It does not mean
no extraction: the example deliberately retains a failed write attempt to a file
after fd 1 has been reused. `--acceptance` always exits 1. There is no network,
tracer, privilege, OS setting, filesystem mutation or application execution in
the model. Python 3.9 or newer and its standard library suffice.

## Normalized contract

Each JSONL record has exactly `revision`, `protocol`, `origin`, `index`, `event`
and `data`. Revision is integer 1. Indexes start at 1 and must be consecutive.
JSON duplicate keys, nonfinite values and unsupported fields/types reject.
Process/thread/object/call tokens are distinct supplied identities, not inferred
from numeric PID/TID values. Tokens have 1–64 ASCII identifier characters.
Every actor event supplies its current integer exec epoch. A live numeric PID
or TID cannot be reused; after termination its number can be reused with a new
generation token. Old tokens remain retired and cannot acquire the new state.

Admitted events are:

| Event | Required data |
| --- | --- |
| `start` | root `process`, `pid`, `thread`, `tid`, initial `objects`, directory `cwd`, complete modeled `fds` |
| `object-declare` | new `object: {id, kind}`; only regular/directory objects after start |
| `thread-start` | `process`, `exec`, new `thread`, `tid` |
| `call-enter` | `process`, `thread`, `exec`, unique `call`, canonical `operation`, exact operation `args` |
| `call-return` | same actor/call, canonical `value`, `error`, returned `object` or null |
| `process-fork` | `parent`, calling `thread`, `exec`, pending parent-side `call`, new `child`, `pid` |
| `exec-success` | old actor/call, `new_exec`, new thread generation/ID, exact `abandoned_calls` |
| `thread-exit` | actor and exact `abandoned_calls` |
| `process-exit` | target `process`, `exec`, canonical `exit_status` (0–255), exact `abandoned_calls` |
| `finish` | exact `records` count including footer, exact lifecycle/call `totals` |

`objects` contain `{id, kind}`. Initial kinds are `regular`, `directory`,
`stdio-sink` and `anonymous-pipe`. These are supplied unit facts, not labels
inferred from path text, descriptor number or `stat` after execution. Initial
descriptors are `{fd, object, cloexec}`. New open results cannot manufacture an
authorized sink/pipe. A full adapter would need authoritative identities and
authorization for initial inherited sinks; declaring a unit object is not proof.

Supported canonical operations and argument keys:

| Operation | Args | Successful return effect |
| --- | --- | --- |
| `fd-open` | `path_hex`, `dirfd`, `cloexec` | install returned fd with supplied resolved regular/directory object |
| `fd-close` | `fd` | remove the same tracked binding |
| `fd-dup` | `source` | install lowest unused fd with shared object, CLOEXEC cleared |
| `fd-dup2` | `source`, `target` | replace target; source==target preserves its flags |
| `fd-flags` | `fd`, `cloexec` | set this descriptor's CLOEXEC only |
| `read` / `write` | `fd`, requested `bytes` | require stable source binding; returned count cannot exceed request |
| `cwd-set` | directory `object` | set process cwd |
| `cwd-from-fd` | directory `fd` | set process cwd from entry-time directory identity |
| `thread-cwd-set` | directory `object` or null | set/clear explicit unit thread override |
| `fork-parent` | empty | parent return must match the child PID of its explicit birth event |
| `exec` | empty | failure may return; success requires explicit nonreturning lifecycle event |

Canonical returns are `value >= 0, error == 0` or `value == -1, error > 0`.
`object` is nonnull only for successful `fd-open`; that identity must already be
declared. Other failed modeled calls have no effect, **except failed close is
unsupported** because descriptor state on error is not inferred. The ABI's raw
return slots, errno representation and interrupted/restarted calls are outside
this model. These operation names are semantic units, not raw syscall aliases.

At most one call is pending per thread. Returns must match actor, exec epoch and
call identity. Exec/exit must explicitly enumerate every pending call they retire;
missing or extra abandonment is an error. Successful exec retires all old thread
generations, advances the epoch exactly once, preserves modeled process cwd and
closes only that process's CLOEXEC descriptors. Fork copies the descriptor table
while retaining shared object identities; subsequent table changes are independent.
Children can act before the parent-side fork return and remain live after the
root exits. The footer requires all declared process/thread generations terminal
and every call returned or explicitly abandoned. These checks prove only declared
unit closure, not kernel event coverage or absence of an unobserved child.

Relative path requests retain the entry-time effective cwd object, or a tracked
directory fd object. Darwin `AT_FDCWD=-2` and null choose effective cwd. Absolute
paths have no dirfd anchor. Path bytes remain hex; no symlink, mount, `..`, vnode
alias, actual target or application-output resolution is performed. A later cwd
change cannot rewrite an earlier anchor. Duplication and I/O require their source
descriptor's object, flags and binding version unchanged at return, including
failed returns. The same source guard applies to `cwd-from-fd`. Destination slots
for dup2 and returned allocation slots for open/dup must be untouched during the
pending interval; per-slot versions retain close/absence history, so a temporary
allocation followed by close cannot be mistaken for an unchanged empty slot.
Relative-open directory anchors and effective cwd versions must also remain
unchanged; cwd change-and-restore rejects. Fork and exec reject descriptor-table
or process cwd changes between entry and child birth / successful exec.
Concurrent close/reuse
or even restoration of the same object
rejects because this model has no observed kernel lookup identity. The entry-time
binding is a supplied normalized causal-order assumption; a raw adapter cannot
establish it merely by snapshotting the userspace descriptor table at syscall
entry. File/directory write attempts are retained even on failure when that binding
is stable. This is not the full mutation policy:
write-open/create/truncate flags remain the separate open-intent unit, and many
other data/metadata/namespace write routes are unsupported.

## Grounding and deliberate gaps

The installed Apple macOS 26.5 SDK's `usr/share/man/man2/dup.2`, `fork.2`,
`execve.2`, `close.2`, `chdir.2` and `fchdir.2`, plus `usr/include/sys/fcntl.h`,
ground descriptor sharing, per-descriptor CLOEXEC and Darwin AT_FDCWD. The dup
page distinguishes ordinary duplication from same-fd dup2 flag preservation.
These sources support the primitive semantics; they do not calibrate an actual
guest's DTrace layout, process identity or event ordering.

Fork/exec under a thread cwd override rejects until its inheritance is calibrated.
The unit protocol models copied tables with no CLOFORK entries; shared descriptor
tables, CLOFORK and unmodeled inheritance forms have no admitted operation. There
is no spawn action, child-side raw fork-return, vfork, descriptor-right transfer,
socket/Mach/fileport, shared mapping/mprotect, fcntl selector, ioctl, async I/O,
exit-signal or interrupted-call adapter. Unknown events, operations, object kinds
and unresolved descriptors reject; a similarly named raw syscall is not accepted.

A future raw adapter must prove the explicit selected-exec start boundary, seeded
FD identities, process/exec/thread generations, causal effect ordering, resolved
objects and canonical results. Gate-read returns before that boundary must be
accounted for, not excused by accepting arbitrary orphan returns. DTrace `cwd`
basenames are not full directory identities. `proc:::exit` arg0 is not treated as
the application exit status; target generation/outcome must be decoded separately.
Actual syscall/Mach/proc captures and positive/negative controls are still needed.

Bounds are 64 total process generations, 256 total thread generations, 4096 object
identities, 1024 descriptors per process, descriptor numbers up to 1048575,
10000 calls, 50000 records, 64 KiB lines and 8 MiB per input file. Initial object
and descriptor lists are each bounded to 128. Inputs must be singly linked regular
files, opened no-follow/nonblocking; size/mtime/ctime are checked after reading.
Any record error poisons that machine instance. No report is printed until valid
footer closure. Reports retain the exact input SHA256, unit counts, entry bindings,
anchors, explicit abandonment outcomes and attempted writes.
