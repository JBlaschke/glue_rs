# Fixed stopped-runtime producer foundation

`rt_stopped_recipe_create` is a distinct source-selected backend class using
the existing runtime-recipe binding, fixture 2. It renders one fixed program
that follows the first selected successful exec to its new thread and requests
`raise(17)` at that thread's initial `proc:::lwp-start`. Later execs remain in
the raw stream and make the first-episode identity unusable. There is no new
trace-session profile, runner call site, controller or native admission.

Only this class requests the per-consumer `destructive=yes` option. Ordinary
factories retain their original options and program bytes. Option success,
the consumed marker and its raise action describe an attempted action; they
do not establish signal delivery, an actual stopped wait, quiescence, output
retention before continuation, or native acceptance. Restrictive platform
policy can refuse the option or action. No protection setting is changed.

The 23 fixed selectors retain the entire physical owner/child stream. Owner
entries have a per-thread call ID in the header detail field. Owner returns
retain the paired raw syscall outcome and, only for fixed argument shapes,
176 original `proc_info` bytes or four original wait-status-buffer bytes.
Unexpected query/wait shapes produce a scalar-only fallback. Shape checks
do not establish pointer validity: a `copyin` fault can lose the entire ECB,
including its scalar return, and makes the capture incomplete. A wait buffer
on zero/error return is opaque; it is not an observed kernel stop status.

Record classes 19 through 23 use separate private counters. `rt_snapshot`
refuses this new class and clears its output; its structure and old classes
are unchanged. `rt_stopped_identity` is a pure copy of the actual serialized
first exec/new-thread/stop-marker prefix, with its physical outer ordinals,
program digest, request/catalog binding and fixed profile identity. It is
pending until complete and becomes unusable after an error, drop, fault,
output failure or later exec. It never grants native or policy authority.

The typed getter is not a runner finalization interface. A later controller
needs a distinct typed bridge for final snapshot/reporting, writer-close
outcomes and resource cleanup; current runner adapters still use the old
snapshot. It also needs an actual sole-owner stopped wait, original deadline
and stable query buffers, retained GLUEPX observation, and a real continuation
producer. The current reader can correlate raw kill entry only conditionally;
there is no continuation-delivery packet or retention-before-CONT claim.

The exact native descriptor layouts are pinned source/SDK predictions, not
a measured D compiler calibration. Unknown action, offset, count, selector
order or enabling layout is refused. Independent ECB timestamps need not be
equal, and their timestamp is before payload copying finishes. Native clock
values are not compared with DTrace timestamps.

`test_runtime_stopped_backend.c` links the actual backend with fake libdtrace
functions and injected original record buffers. It does not link libdtrace,
run a provider or send a signal. Its optional third argument is an existing
empty test-artifact directory. The retained files are producer model evidence,
not a native trace. `test_runtime_stopped_program.c` exercises pure formatting.
