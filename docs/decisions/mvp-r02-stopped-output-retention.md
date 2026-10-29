# R02: file-synced retention of one completed GLUEPX observation

Status: staged implementation, 29 October 2026; decision draft preceded code. Independent source
prerequisite only; no controller, TS, backend, signal or reader adoption.

Add an opaque once-only C retention context taking the actual const
`px_observer *`, a borrowed fresh held private directory FD, and the launch
attempt's original absolute monotonic deadline. Its only native operation is
the fixed file-retention path. It gets the exact4096 bytes through the published
observer's actual encoder, verifies current owner, retained child ownership,
completed match/no loss and matching original deadline, and accepts no packet,
pathname, policy boolean, signal, program or production callback input.

Exclusively create the fixed `post-exec-output.bin` at0600 with O_NOFOLLOW.
Check actual regular/single-link/current-EUID file identity. Keep a finite64-call
short-write/EINTR journal. Check the original deadline before and after every
issued syscall, recording the native return/errno and transferred prefix before
the after-clock. Only complete timely content followed by one successful file
fsync and one successful close can be file-retention eligible. No directory
fsync or namespace durability is claimed. Checks cannot interrupt blocked calls.

Consume file ownership before once-only close; never retry close on EINTR or
invent closed=true on failure. Cleanup close still runs once for the acquired
file after earlier write/clock/deadline failures, retaining its timing/faults;
cleanup cannot restore eligibility. No overwrite, reopen, unlink of a partial
artifact, replay or hidden close in free occurs. Caller owns unresolved cleanup.

Pure typed snapshots and original-byte copying preserve first/last and every
per-call late fault. All native/state/output/full authority stays false. Model
controls use private test-only syscall seams while always calling the actual
observer encoder/owns APIs. Small original observer fixtures avoid cloning the
large suite. Real owned temporary-file writer controls distinguish real file I/O
from modeled stop/observer data. Both Python3.15/3.9 and ASan/UBSan are planned.
No native provider, target trace, protected action, Git mutation, status bridge,
CONT receipt producer/schema, signal or current-reader change belongs here.

Final controls pass12 methods on both Python3.15.2 and3.9.6, normal and
ASan/UBSan:48 final method executions, zero skips. Each run checks4095 short
lengths and63 clock fault points plus four after-call lateness cases, alongside
the other focused controls. Real owned-file I/O is distinguished from modeled
observer wait/query/child ownership; no actual child or signal was used. Earlier
passing pilot/preliminary logs are retained. Source review tightened the once
attempt rule so a null error-output argument consumes/refuses a valid context
without I/O; final controls cover that behavior. Original dependency bytes and
repository metadata are checked separately in the retained validation report.
