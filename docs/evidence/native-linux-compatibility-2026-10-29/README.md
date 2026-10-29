# Native Linux Python archive and uv routes

[Run 40851345339](https://github.com/JBlaschke/glue_rs/actions/runs/40851345339)
at `e90e21a4` executes the original 24 cases/five unchanged budgets plus seven
Python archive/uv routes on both native Linux targets. The combined run fails:

| Target | Base cases/budgets | New routes | Independent verification |
| --- | --- | --- | --- |
| GNU Linux arm64 | 24 cases/five profiles pass | All seven pass | 46 receipts, 184 oracle controls and 990 rank results verify. |
| GNU Linux x86_64 | 24 cases/five profiles pass | Five pass; full/install-only build fails | Base 39 receipts, 156 controls and 990 ranks verify; the five passing routes separately verify with 20 controls. Strict complete replay remains failed. |

The full and install-only x86 archives include a required
`lib/libpython3.13.so.1.0` of 143,259,064 bytes. Build-time materialization uses a
128 MiB retained-member reader and refuses it. Stripped input and all uv routes
pass. The separate streaming repair preserves the failed receipts and requires
a new native run; it does not substitute stripped input or relax accepted limits.

[acceptance.json](acceptance.json) binds the exact original ZIP, raw inventory
and independent replay identities for each target. Raw captures, frozen tools
and reports remain ignored under
`.evidence-local/native-linux-compatibility-20261029/runs/40851345339-ARCH`.
These local copies do not establish external durability or publish a release.
The arm cell's success is distinct from the combined workflow's failure.

All executions use the recorded syscall-fallback policy. Time/RSS budgets retain
their matching-host-fingerprint scope; no cold-cache or universal timing claim
is made. Patch/abi3 evidence, Darwin oracle/corpus, Mac budgets and final M2
sign-off remain separate. No Mac VM data or new source-runtime admission catalog
is included.
