# Tree-open request intent observations

`observe_tree_open_intent(capture, toolkit)` invokes the strict tree-open
observer itself, including its complete raw-v4 capture/toolkit validation and
call pairing. There is no entry accepting caller-provided observations,
validation claims or normalized records. The pure `classify_flags` helper
classifies the already observed canonical unsigned32 flag words directly;
no synthetic or self-report origin is manufactured.

```sh
python3 fixtures/mvp/macos-trace/tree-open-intent/observe_tree_open_intent.py \
  --capture /absolute/owned/tree-case --toolkit /absolute/matching/native-capture-v8
python3 -B fixtures/mvp/macos-trace/tree-open-intent/test_observe_tree_open_intent.py -v
```

The report retains the complete upstream tree-open report in
`source_observations`, including all non-open calls, raw frames and provenance.
Every classification links its one-based source observation, pair/consumer
indexes and observed PID/TID/exec epoch. Copied path bytes, all flag bits and
success/ENOENT results remain in that source. Classification retains attempted
write access, create, truncate and append intent even when the open failed.
Read-only creation remains a write request. Unknown/unmodeled flags retain
their bits and write reasons as explicit unsupported classifications.

The ABI, classifier and this observer's source hashes are retained; upstream
hashes stay in the preserved report. The inherited4096-open bound and stricter
raw/pairing limits still apply. A malformed non-open call or any upstream
integrity/pairing failure rejects the whole operation before a report.

CLI exit0 means supported flags were classified, including observed write
requests. Inspect `intent`, `no_output_policy` and `write_reasons`; exit0 is
never a no-extraction verdict. Unsupported combinations produce a report and
exit1. Malformed inputs return1 without a report. `--acceptance` and
`require_full_trace_acceptance` unconditionally refuse before input access.
Every successful report has `full_trace_acceptance: false`.

There are no application-output exemptions or resolved pathname, FD/object,
causal ordering, successful effect or full process-tree coverage claims. Read
intent cannot authorize a file/device or an execution. The current owned trace
backend has no copied paths or authoritative filesystem identities; this bridge
does not make its format interchangeable with historical raw-v4 captures.

Controls construct complete rehashed synthetic raw capture/toolkit fixtures and
exercise strict source validation. They run no native fixture, provider, VM,
SDK build, registry update or actual capture. See the
[decision](../../../../docs/decisions/mvp-r02-tree-open-intent.md). Native
calibration, the complete extraction oracle/corpus and R02/M2 remain open.
