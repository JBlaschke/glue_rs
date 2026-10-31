# File-synced GLUEPX content retention

`post_exec_retention.[ch]` is a separate private source helper. It writes the
exact original4096-byte encoding of an actual completed `px_observer` to the
fixed `post-exec-output.bin` basename. It adds no controller, TS/backend bridge,
signals, CONT receipt/schema, reader input or native admission route.

```c
struct px_retention_error error;
struct px_retention *writer = px_retention_new(observer, held_directory_fd,
                                              original_deadline_ns, &error);
int result = writer ? px_retention_write(writer, &error) : -1;
struct px_retention_status status;
if (writer) px_retention_snapshot(writer, &status);
px_retention_free(writer); /* memory only; never implicit file cleanup */
```

The constructor takes the actual const observer pointer, borrowed directory FD
and launch attempt's original absolute monotonic deadline. There are no caller
packet/path/program/boolean/production-callback inputs. Keep the observer, its
storage, credentials, held directory/namespace and FD identities stable, with
one owner and the actual fork-PID sole-reaper/controller lease. This helper
checks the observer's retained ownership and current PID/EUID, not a new OS
lifetime or foreign-control witness. Equal packets cannot create native origin.

The once-only attempt calls the actual `px_observer_encode` and preserves its
original bytes, even when they describe a refusal. Only completed matched
observations with retained ownership, no loss/error and exactly matching
original deadline can reach file creation. Current owner is compared with the
encoded owner. No incomplete/failed/modeled packet is accepted as a caller
substitute for the opaque observer. Private injected observer fixtures remain
models with no native authority.

The borrowed fd must be >=3, actually readonly/CLOEXEC, a current-EUID-owned
private0700 directory. The helper uses only fixed F_GETFD/F_GETFL reads and fstat
on it; it never sets flags, duplicates or closes it. Freshness, exclusive control
and stable namespace are source obligations, not facts proved by directory stat.

The file is created using O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, mode0600.
Actual fd flags and fstat must identify an empty regular0600 single-link file
owned by the unchanged effective UID. Existing files/symlinks are refused and
retained unchanged. No overwrite, reopening, chmod repair, unlink or cleanup of
partial output occurs. A rejected new file remains as diagnostic evidence.

At most64 write calls include short writes and EINTR. Each actual return/errno
and confirmed transferred prefix is saved before after-clock validation. Zero,
impossible oversized or non-EINTR errors refuse. Full content on the64th call
can succeed; needing a65th call refuses. The original deadline is checked before
and after flags/stat/open/write/fsync/close calls, with monotonic continuity from
the original observer's last clock. No deadline is created or refreshed.
Identity fields retain the initial fstat results and their call windows; they
are not a metadata snapshot after retention returns.

One file fsync follows a complete timely write. One close resolves the acquired
file, including after earlier failures. Cleanup close still records its failed
before/after checks and actual result; it cannot restore eligibility. No close
retry occurs, including EINTR. On close failure `close_succeeded` stays false
and `file_ownership_unresolved` stays true; `opened_fd` retains its diagnostic
number. Capture the snapshot before freeing: free releases only memory and is
not evidence that any unresolved descriptor was closed. The caller must retain
the unresolved-resource diagnosis, without a blind retry of an ambiguous close.

`file_synced_content`/`PXRET_FILE_SYNCED` mean the exact full content was written,
file fsync succeeded, close actually succeeded, and all eligibility checks were
timely. Actual sync/close success remains separately visible if a later clock
fails, while eligibility stays false. There is no directory fsync, namespace or
power-loss durability claim. A native call can block beyond these cooperative
checks; they cannot interrupt it.

The pure snapshot retains each bounded call result, errno, available clocks,
before/after clock fault, byte count, identities, first and last failures, and
unresolved closure. `px_retention_copy_observation` copies only the exact actual
encoder output; it accepts no raw input. Both getters detach their output and
perform no I/O/clock/owner callback. Replay performs no new operation and leaves
the first attempt's facts unchanged. All native/state/output/full, namespace
and power-loss authority fields remain false. No fact here authorizes SIGCONT,
output writes, sink exemptions or a current reader's retention flag.

## Focused controls

Run from the repository root:

```sh
python3 -B fixtures/mvp/macos-trace/post-exec-output-retention/test_post_exec_retention.py -v
```

The12 methods compile and run the actual C writer plus a small separate opaque
observer fixture using the published private model factory. Writer test-only
syscall/clock seams never replace the observer's encoder or ownership getter.
Production compilation exposes neither those seams nor a signal/wait interface.
The suite covers4095 short lengths, finite EINTR boundaries,63 clock fault
points, late native outcomes, pending/failed/terminal/lost/owner/UID/deadline
refusals, metadata/flags, exact prefix/error ordering, no replay or implicit
cleanup, and original copied bytes.

Four additional scenarios within those12 methods use real owned temporary
directories/files and the production writer constructor: exact4096 content,
existing file retention, symlink refusal, and missing-CLOEXEC refusal. Their
file operations are real while observer stop/query/child ownership remains
modeled. No actual child, signal, provider or privileged bootstrap runs. The
fixture's GLUERW metadata/digests are model inputs, not captured native evidence.

Set `PXRET_CONTROL_DIR` to a new output directory to retain compiler/source/call
receipts. `PXRET_SANITIZE=1` adds ASan/UBSan. Both are test harness controls, not
production policy inputs. Stage evidence records both Python3.15/3.9 runs,
normal/sanitizer results, exact counts, source hashes and real/model limits.

The dependency is the published PR113 observer header/C source, unchanged. No
stopped producer/status bridge/reader source, native closure, proof, historical
receipt, current registry, HEAD or other frozen stage is edited by this feature.
