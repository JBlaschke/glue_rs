# R02: strict offline verification of one owned NONTRACING batch

This checker is the read-only consumer of the fixed batch described in
[the VM batch decision](mvp-r02-bootstrap-vm.md). It neither prepares a packet,
authenticates, stages files, launches a command nor changes VM/security state.
It creates no new kit registry or general trust framework. The prepared packet's
source-pinned literal approved kit/catalog binding is shared with its producer;
caller-selected hashes, profiles, IDs or alternate programs are not overrides.

The public operation consumes a trusted prepared packet, a completed exported
batch and a separately retained normal outer-command receipt. Exact filenames,
closed JSON types and journal records are coordinated with that producer before
dependent code is written. A self-reported `complete` line alone cannot attest a
normal shell exit. A missing, partial, unexpected or failed receipt is rejected.

Verification first establishes the small terminal batch/journal/stage metadata.
Only a complete expected batch with recorded closure permits opening case
payloads and checking their exact fixed inventory. It never polls a live root
output pointer, follows a partial-case pointer, reads `result.pending`, or hashes
possibly live outputs merely to produce a partial success. Unexpected native
CLI2 rejects except the final deliberate trailing-input case; that case requires
recorded output absence and has no probe/output files. Incomplete batches retain
their original evidence and are rejected, not repaired or converted to a pass.
These observations rely on the owned, source-pinned producer/closure contract;
they are not an independent kernel liveness or administrator-resistant attestor.

All reads are bounded and read-only. Physical paths and fixed inventories reject
symlinks, hard links, special members, path escapes, extra/missing members and
changed bytes. JSON has exact keys and scalar types, no duplicate keys, floating
point values or integer coercion. Manifests use canonical lowercase SHA-256 and
relative member names. Status and boolean byte records have exact encodings.

The checker independently decodes canonical BR requests, BW status streams,
the 269-byte NR catalog and NP self-reports using the reviewed wire layouts.
It checks reserved bytes, exact lengths, closed selectors, numeric bounds,
group ordering/unused slots, status phase/order and all request/PID/catalog/source
bindings. Result JSON must agree with the retained raw streams, captures,
digests, identities, typed cleanup/signal restoration and expected case outcome.
The positive case requires normal reaped exit0 and a matching NP report. SIM and
denied-cwd cases require their exact child ERROR, no GO bytes/release and a closed
reported-error stream; their raw wait status is retained without assuming natural
exit120 instead of a cleanup kill. Trailing input must be canonical positive
request bytes plus one NUL, native CLI2 and output absence, never fabricated
zero-length probe observations.

Tests use conspicuously synthetic, independently packed wire fixtures and exact
producer-shape metadata. Adversarial controls rebuild hashes while changing
semantic records, so manifest consistency alone cannot make malformed records
pass. They cover truncation, extra data, wrong binding/phase, incomplete closure,
typed JSON confusion, linked/path-escaping/extra files and normal outer receipt
requirements. They perform no native target or VM execution.

A successful check means consistency of this controlled NONTRACING diagnostic
batch only. Reports retain `tracing`, `exec_proved` and `full_acceptance` false.
No checker output establishes the full Darwin filesystem oracle, unrestricted
host acceptance, kernel object/effect identity or completion of R02/M2.

The command is `python3 -B checker.py --packet ABS --evidence ABS
--run-receipt ABS`. The public `check(packet, evidence, run_receipt)` operation
loads the adjacent reviewed preparer and its source-pinned kit parser; it has no
caller approval, profile, hash or execution-policy override. The current reviewed
preparer remains execution-disabled, so actual successful-batch checking is held
until a separately reviewed source follow-up enables the exact rendered packet.
Synthetic tests replace that source contract only inside test mocks and execute
no script or binary.

The parser's existing limits remain: 256 files, depth16, 8MiB per member, 64MiB
total, 256KiB manifests/metadata; native result JSON is further limited to8192
ASCII bytes with compact integer/boolean encoding and one final LF. Wire bounds
are BR208–16384, catalog269, BW1–3 exact256-byte records and NP256. Each scalar
and reserved span is checked independently. Canonical signal policy bytes follow
`bs_policy_bytes` and the compiled Darwin SDK `sys/signal.h` constants: NSIG32,
SIGKILL9 and SIGSTOP17. Their digest describes the declared setup policy; it
does not attest a prior kernel signal state. Negative child wait values retain
either the controlled `_exit(120)` result or SIGKILL9 from cleanup, without
requiring a natural exit instead of a cleanup kill.

The NP report preserves all raw stdio status/descriptor flags and checks the
closed direction/blocking/CLOEXEC policy, request/PID/FD/cwd/groups and failed
root-regain fields. The producer JSON omits its original F_GETFL vector, so exact
pre/post flag-vector equality remains the reviewed runner's observation. READY
control descriptor numbers are checked as distinct numeric slots at least3;
the checker cannot reconstruct an unavailable independent endpoint-object
inventory. The original full kit inventory and source lock remain detached
provenance of that approved kit; changed current repository production files do
not invalidate a frozen, separately reviewed old kit or silently replace it.
