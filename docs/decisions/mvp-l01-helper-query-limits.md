# L01: bound helper discovery without hiding execution errors

Native hosted Linux helper tests observed `ETXTBSY` immediately after copying an
installed helper. The copy API has returned and closed its own writer at that
point. Concurrent fork/exec activity can briefly inherit a writer before
close-on-exec; the logs establish the transient error, not its exact kernel
owner. Adding fsync to the fixture would not establish that every inherited
writer has closed.

Only `ETXTBSY` from spawning the selected executable retries, at 10 ms intervals
for at most 200 ms. A persistent busy executable returns the original I/O error.
Missing paths, denied execution, invalid formats and every other spawn error
return directly. This does not change helper selection, ABI checks, identity
hashes, descriptors, family restrictions or search paths.

After a successful spawn, descriptor capture has a five-second deadline and a
64 KiB output limit (plus one overflow-detection byte). An owned nonblocking
pipe avoids blocking reads and detached reader threads when stdout stays open.
The child has its own process group; errors/timeouts kill that group and kill/
reap the direct child. Stderr stays null as before. The small Unix fcntl/kill
operations are the only added unsafe platform calls, with no Lua API crossing.
The deadline is process capture time; the separate bounded spawn retry can add
up to 200 ms.

Regression fixtures independently compile tiny C programs before querying them.
They cover a real Linux writable-open executable that becomes runnable, a busy
executable that stays busy, excess stdout, preserved ENOENT/EACCES, and programs
that hang with partial stdout or close stdout after valid JSON. Native PID
liveness checks verify the timed-out direct programs are killed and reaped.
No test weakens or skips the existing real helper discovery/byte-identity test.
No compiler is invoked by production helper discovery.
