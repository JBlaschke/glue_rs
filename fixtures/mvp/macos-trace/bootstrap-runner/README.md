# Standalone owned bootstrap diagnostic

This closed Darwin runner combines the reviewed credential, descriptor, endpoint,
wire, request, pipe-IO, signal and protected-admission components without tracing.
It is an owned context-probe diagnostic. `exec_proved`, `tracing` and
`full_acceptance` always remain false. No collector or raw-reader adoption occurs.

Build with `sh build.sh NEW_BINARY [REVIEWED_GENERATED_CATALOG.c]`. The optional
argument is a compiler input, never a native runtime option. A generated TU must
include `runner_catalog.h` and define `nr_compiled_catalog()` returning immutable
storage. It replaces `catalog_unconfigured.c`; the default refuses every attempt.
The build script links only the closed listed C sources and Darwin libproc;
CommonCrypto supplies SHA256. The later kit must independently retain the exact
source, build recipe, deployment/profile proof and dyld/libSystem-only provenance.
The generated catalog and final binaries are excluded from their own static input
hashes. See the decision for the complete canonical catalog offsets.

The native CLI accepts exactly:

```
owned-bootstrap-native --request /absolute/request.bin --output /System/Volumes/Data/private/tmp/NEW_ASCII_NAME
```

Darwin real/effective root and a compiled catalog are mandatory before any input
or output open. Linux refuses before setup. There is no test driver, environment,
catalog, digest or helper override in this executable. The canonical request does
supply declared nonroot UID/GID/ordered groups; the controller compares them to
observations, not to a compiled deployment identity or authenticated user policy.
The closed request writer derives those declarations from its actual caller. Run only in
a separately authorized owned environment with the documented protected fixture,
mount/ACL/no historical writable alias/no concurrent privileged mutation invariant.
The request selects only the compiled context probe, its build-directory cwd,
empty environment and derived closed argv. It cannot choose arbitrary arguments.
The physical protected path remains stable through pathname exec; two hashes or
stats do not establish that invariant.

The controller is single-threaded, has no custom handler/reaper or atfork callback
that changes state, and starts with ordinary retained SIGCHLD policy. It blocks
signals before fork and restores its original mask/PIPE policy after cleanup.
The child uses real helpers, absolute chdir only after verified credentials,
exact five-FD closure, full READY comparison and one GO. A late/failed GO may have
been consumed: it is never replayed. Status EOF, ATTEMPT and even the probe's own
report do not independently prove kernel exec/credential or filesystem effects.
Only a normal reaped direct child with exact report, empty stderr, matched fields
and completed protocol can produce the consistent diagnostic with CLI exit0.

The closed output names are `request.bin`, `status.bin`, `probe.stdout`,
`probe.stderr`, `result.pending` and `result.json`. Pending is only an incomplete
failure artifact. Final JSON is promoted exclusively after owned resources and
child reap are resolved and parent signal restoration attempted; promotion has
no later fallible finalization. Its absolute rename relies on the checked fresh
root0700 directory under root sticky1777 and the recorded no privileged mutator
invariant. A close failure suppresses promotion. Capture-valid flags distinguish measured bytes/hashes from unavailable placeholders;
stderr diagnostics are bounded at4096 bytes. The final file alone is never a
completed outcome: consumers must also require normal CLI exit0 and inspect the
explicit scope/observations. CLI1 is a finalized failed diagnostic; CLI2 may be
preflight, unresolved cleanup or incomplete finalization, with no final marker.
Do not copy/read possibly live probe outputs after CLI2; stop the batch and retain
the CLI status, logs and exact private output pointer for separate investigation.

The attempt uses one original-start absolute deadline (maximum10s); cleanup gets
a separate maximum2s deadline. There is no watchdog and the reviewed probe has no
alarm. Native syscall stalls, controller death and arbitrary descendant containment
remain outside this bound. Cleanup signals only the actual known unreaped child;
reaped or ECHILD ownership can never be reused for a later signal.

Run focused verification with:

```
python3 test_bootstrap_runner.py
GLUE_RUNNER_SANITIZE=1 python3 test_bootstrap_runner.py
```

The C model checks all status phases, retained prefixes/extra bytes/bindings,
sticky poisoning, zero-prefix EOF that becomes late, and full-but-late records.
It compares canonical catalog bytes to an independent Python struct golden and
rejects mismatched READY/probe observations. A separately compiled source-isolated
parent model replaces fork/wait/kill/close/clock/pipe operations with assertions;
it never performs those native operations and never links into the production CLI.
Source-isolated child controls cover TC/CWD/TD error routing, GO/EOF/gate failures,
and failed READY/ATTEMPT writes without appended ERROR framing. Finalization models
cover capture/dir/pending close failures and exclusive-promotion ordering.
Native controls compile the whole CLI and exercise only argument/nonroot or Linux
unsupported refusal, before output. Sanitizer controls do not run the native CLI.
No privileged positive, credential-transition, protected guest admission or
end-to-end target execution has been performed by these controls; those require a
fresh separately reviewed kit and authorization. The native runner is not yet
adopted by the tracing collector.

`nr_status_next_observed` is an explicit internal status-codec seam for a trusted
`bio_observer`; the native parent still uses the legacy entry point. The shared
decoder uses observed record reads and strict EOF checks, including zero-record
fallback, with the caller's unchanged absolute deadline. Missing callbacks fail
closed. Failed partial or complete I/O prefixes remain retained and undecoded;
poisoned streams perform no further I/O. These cooperative model controls supply
no native tracing or execution evidence:

```
python3 -B test_runner_protocol_observed.py -v
NR_STATUS_TEST_CFLAGS='-g -fsanitize=address,undefined -fno-omit-frame-pointer' python3 -B test_runner_protocol_observed.py -v
```
