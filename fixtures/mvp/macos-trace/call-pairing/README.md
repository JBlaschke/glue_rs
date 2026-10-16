# Actual raw call pairing

`pair_calls.py` accepts a raw-v4 capture directory and its matching toolkit. The
public `pair_capture(capture, toolkit)` API runs the strict capability reader
itself. It requires clean completed tree or tree-mach transport on the observed
Darwin 25.6 arm64 / macOS 26.6.2 build 25G83 calibration host.

```sh
python3 fixtures/mvp/macos-trace/call-pairing/pair_calls.py \
  --capture /absolute/owned/case --toolkit /absolute/matching/native-capture-v8 \
  > /absolute/new-local-pairs.json
python3 fixtures/mvp/macos-trace/call-pairing/test_pair_calls.py -v
```

The returned object retains source/toolkit/receipt provenance and every raw
frame. Calls reference those exact consumer indexes and retain all eight entry
words, five BSD return words or one Mach return word. Named-open string records
stay opaque. Provider returns are observations, not successful operation or
effect verdicts. The 45 BSD and 12 Mach names form a closed calibration roster
for opaque pairing; **never use this roster as an effects allowlist**. Legitimate
traces outside this ordering, name roster, host or diagnostic bound may reject.

Observed PID/TID lifetimes and exec epochs are conservative session tokens,
not attested kernel generations. One call may be pending per thread across both
provider families. Unknown/reused threads, unexplained nesting, orphan returns,
descriptor mismatch, control-flow returns, missing path clauses and pending
calls crossing exec reject. The initial root's first close entry identifies the
already-gated thread; later threads require observed declarations and starts.
BSD primary duplication and kernel-error/builtin-errno agreement are checked
only as a conservative observed tuple shape. Negative control-flow encodings or
other unobserved shapes reject; these checks do not normalize generic XNU results.

Two source-grounded termination routes retain explicit
`terminated-without-return` outcomes: `exit` and `bsdthread_terminate`. They keep
the entry and matching thread/process lifecycle boundaries, with null return
index/words. No return or successful result is fabricated. A context-only
`proc:::exit` while the parent calls `posix_spawn` does not retire that call.
For a pending `exit`, detail 1 is checked solely as the observed raw
`CLD_EXITED` context tag, never application status or normal-completion proof.
Old exec-shadow exits never flush live pending calls, including interleaved
Mach traps. The object/flag association remains diagnostic and source-guided.

There is no FD object, resolved path, spawn-action, shared-map, async-I/O,
Mach message or filesystem mutation decision. The acceptance API and CLI always
reject. Bounds are 32,768 events, 16,384 calls, 4,096 observed threads and 16 MiB
of strict-reader timeline. Source review and actual replay details are in the
[decision](../../../../docs/decisions/mvp-r02-darwin-raw-call-pairing.md).
