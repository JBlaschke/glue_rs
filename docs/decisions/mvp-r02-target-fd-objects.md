# Capture fixed owned-child descriptor backing observations before GO

Status: accepted for a bounded native capture primitive; full native trace/state admission remains open.

29 October 2026. Add a read-only C snapshot over exactly
[0,1,2,gate_reader,status_writer], after the existing numeric closure and before
GO in a quiescent, owned single-threaded child. The original controller PID is
captured before fork. Signals must already have been blocked before child setup;
callbacks, handlers, other threads and shared-status aliases must not mutate the
selected descriptors during capture. PID/mask readback catches misuse but does
not authenticate ownership or prove that history.

The snapshot API validates the entire callback table and fixed plan, checks
child/mask guards, and samples fstat, F_GETFD and F_GETFL twice for all five FDs.
It preserves numeric backing device/inode, mode/link count and the observed flag
words. Full matching samples permit publication of one complete snapshot; any
error, shape disagreement, changed identity/flags or final mask failure publishes
no prefix. Repeated samples detect some changes but do not prove atomicity or
exclude concurrent mutation. No path lookup, opening, closing, remapping,
allocation, flag update, credentials, native tracing or GO occurs in this API.

A separate controller-side matcher reads still-held stdout/stderr capture handles
twice and compares regular single-link, distinct sink backing identities and
compatible write-only access/status observations against child slots1/2. Source
handles must remain held through capture/matching; the controller owns the actual
unreaped child and maintains the barrier. Descriptor flags are recorded but are
not required equal: CLOEXEC on held sources and clear dup2 stdio are intentional.
Child output CLOEXEC must be clear. A backing match does not prove shared open
file description, generation, path, absence of aliases or current slot state.
Two independent opens of the same file can match. Controlled dup/fork lineage
is an explicit integration assumption, not a caller boolean granting authority.

Both APIs use local pending storage and publish only complete results. All
callback inputs/output spans are valid, stable and nonoverlapping, and adapters
are trusted test/native implementations, not arbitrary plugins. Syscall errno is
saved only on actual failure; stale errno on success is ignored. No retry,
cleanup/rollback or guessed ownership follows failure. Child failure forbids
launch; the caller must enforce a whole-child deadline and reap its actual owned
child. The primitive cannot interrupt a blocked system call.

Real unprivileged Mac controls will create owned files/pipes, use existing te_
preparation/dup2 mapping and actual td_close_in_owned_child, capture while gated,
match against still-held controller references, and only then send a test GO.
They verify output bytes and unchanged controller descriptors/limits. Failure
controls do not release GO. Linux builds run injected boundary controls and any
truthfully scoped native POSIX controls; the existing native TD Linux adapter
stays unsupported. No VM, sudo, SIP change or privileged collector is involved.

This adds observed backing metadata, not an OFD/object-generation registry,
filesystem-path authority, arbitrary pipe/CWD binding, after-exec state or an
extraction oracle. Production controller/wire/kit adoption is separate work;
existing registered sources, capture gates and state engines remain unchanged.
No ready/matched flag is native trace admission or a launch authorization.
