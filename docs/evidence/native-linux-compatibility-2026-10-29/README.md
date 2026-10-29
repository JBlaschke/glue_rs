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
pass. The streaming repair preserves these failed receipts; it does not substitute
stripped input or relax accepted limits. Its fresh result is recorded below.

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

## Repaired x86 execution

[Run 40858319517](https://github.com/JBlaschke/glue_rs/actions/runs/40858319517)
at `3698a40d` passes all 24 base cases, seven archive/uv routes and five unchanged
budget profiles. Independent replay verifies 46 receipts, 184 oracle controls
and 990 rank results. [repaired-x86.json](repaired-x86.json) binds the original
195,489,066-byte ZIP, all 4,952 raw files/873,285,180 bytes and the replay result.
No archived applications execute during replay.

The bounded streaming staging repair handles the required large library while
retaining the existing in-memory reader limit and archive validation. Structural,
I/O, FD and scaling limits apply. Every time/RSS gate is inapplicable because the
recorded host fingerprint differs from the frozen budget host. There is no fresh
timing acceptance claim. Arm's seven-route result above predates this repair;
these are distinct source revisions, not a same-source pair. Raw evidence remains
local; this record neither publishes assets nor closes M2.

## Current same-source compatibility cohort

[Run 40863475232](https://github.com/JBlaschke/glue_rs/actions/runs/40863475232)
at `8532d509a61ab8e762b0926ef55dc179d9b821cd` completes successfully on both
native Linux architectures. Per target, complete independent replay verifies
49 V02 receipts: 24 base applications, seven archive/uv routes, three patch/abi3
cases and fifteen benchmark variants. All 196 oracle controls and 990 rank
results verify. A separate genuine wrong-ABI build refuses before creating its
output; retained streams, source identity, unchanged before/after inputs, sibling
sentinel and pinned cp314 CFFI wheel/member bindings verify.

The patch case uses CPython 3.13.15 with the identical included glue bytes as the
3.13.16 source case. Both selected minors use the same original cryptography
abi3 wheel/native inputs within each architecture. Explicit normalization remains
a separate product transformation; no identical normalized-payload claim is made.

[current-cohort-inventory.json](current-cohort-inventory.json) binds each original
artifact ZIP, all 5,037 raw members, source revision and independent replay. The
retained cryptography/cp314 CFFI wheels and members are actually rehashed. The
original patch runtime archive and other provisioning archives are absent from
this evidence set; replay verifies their exact source-pinned provenance chain,
not absent archive bytes. Earlier failures and separate revisions above remain
unchanged. The arm acquisition observed its selected job completed while the
combined run was still pending; the later final workflow result is success.

All five unchanged profiles pass structural, I/O, FD and scaling gates. Every
time/RSS gate is inapplicable because these hosts differ from their frozen
fingerprints. There is no fresh timing, cold-cache or unrestricted-host claim.
Raw captures/tools remain local and in expiring CI artifacts; no new release
assets are published, and external retention of this cohort remains open. Full
Mac oracle/corpus, Mac budgets and final M2 sign-off remain separate.
