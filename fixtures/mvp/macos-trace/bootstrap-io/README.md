# Fixed-record nonblocking pipe I/O

This standalone C dependency transports exactly 64 or 256 bytes, or requires EOF.
It does not decode GO/status, launch a target, infer exec or grant full trace
acceptance. The wire codec lives separately in `bootstrap-wire`.

`bio_read_record`, `bio_write_record` and `bio_require_eof` return zero only when
the requested operation completed before the absolute monotonic deadline. Every
other result is failure. Both output objects are required. `result.prefix` is
zero-initialized and retains exactly `bytes_moved` confirmed bytes; unused bytes
stay zero on every path. The error repeats that count and identifies stage,
reason and original positive syscall errno when that syscall failed. Adapter,
validation and poll-event errors have errno zero. Invalid output pointers cannot
be diagnosed; all C objects/spans must be valid, mutually nonoverlapping and
stable during the call.

A record write that reports failure can already have delivered its entire record,
including GO. There is no rollback: never replay a failed record. The launch
controller must treat a failed GO send as possibly released and terminate/reap
its owned child. Failed READY transmission requires child exit and cannot finish
an accepted launch sequence. Partial reads and late full reads are retained
bytes, not valid decoded records. EOF means no pipe writer remains; it does not
prove successful exec or a live parent.

The caller owns sole-writer and endpoint provenance, stable FD mapping/status
flags across every shared open-file-description alias, and an explicit SIGPIPE
policy. No concurrent close, rebind or status-flag mutation is permitted. Each
call requires a FIFO with exact `O_RDONLY` for reads/EOF or `O_WRONLY` for writes,
plus `O_NONBLOCK`. The helper does not change flags, masks or signal dispositions
and closes nothing. In the future bootstrap all four private control ends must
be made nonblocking before fork; this helper checks its supplied end.

A normalized `{uint64 seconds,uint64 nanoseconds}` deadline must flatten into
uint64 nanoseconds, be strictly future and no more than 30 seconds away at entry.
Clock rollback or reaching the deadline fails, including a full transfer whose
post-I/O clock check is late. Poll uses a ceiling millisecond timeout, then
checks time before touching bytes. Every retry/progress loop checks time again;
EINTR/EAGAIN retain the original absolute deadline and confirmed offset. The
4096-step diagnostic limit bounds even a frozen/faulty injected clock. Early
poll timeouts may retry; they never reset the deadline. This is not an unlimited
streaming API. Native OS calls or trusted adapters must return; callers need an
independent external process deadline for a kernel/adapter stall.

The six-operation table is trusted and libc-conforming, not a plugin boundary.
All callbacks must exist before any runs. They must preserve API objects and FD
mapping/flags, obey buffer spans, return only documented values and save errno
immediately after a failing call. The helper snapshots this table and outgoing
bytes. Reads land in bounded temporary scratch before copying confirmed bytes,
so an unsuccessful read cannot contaminate the retained unused prefix. A
`POLLIN|POLLHUP` result drains buffered data; HUP alone also performs a read. Poll
ERR/NVAL, unknown events/returns and invalid read/write counts fail. A zero write
fails immediately. A zero record read is truncation; EOF validation reads at
most one byte and rejects that byte as trailing data. Leaked writers time out.

Run the focused controls without privilege:

```sh
python3 fixtures/mvp/macos-trace/bootstrap-io/test_bootstrap_io.py -v
BIO_TEST_CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  python3 fixtures/mvp/macos-trace/bootstrap-io/test_bootstrap_io.py -v
```

The 17 groups cover injected preflight/length/type/access, clock format/overflow/
rollback/deadline/future limits, interruption storms/4096-step bounds, exact
partial offsets, zero/oversized/negative syscall results, poll errors, EOF/trailing
bytes and complete-but-late writes. Native private-pipe controls cover both
record sizes, fragmented child writes, buffered data plus HUP, truncation,
trailing data, leaked writer deadline, endpoint rejection and broken-peer policy.
SIGPIPE is ignored only inside that private test process and checked/restored;
production code never changes it. Native forked writers have a parent-owned
monotonic wait deadline and an exact unreaped-child kill/reap path. Python adds
an outer subprocess timeout. Tests never execute a target or change credentials.
