# Native GNU Linux arm64 acceptance — 28 October 2026

[Run 40754980497](https://github.com/JBlaschke/glue_rs/actions/runs/40754980497)
at [30e8d08](https://github.com/JBlaschke/glue_rs/commit/30e8d080500de2bd6646c1c68d814eb80208f5f8)
passes all 24 application cases and five unchanged reviewed budgets. Complete
independent offline replay verifies 39 receipts, 156 oracle controls, 990 rank
measurements/streams, eighteen Python environment checks and fifteen payload
inventory cost reconstructions. All source/capture identities remain unchanged.

The failed predecessor run `40722874852` remains retained separately. Its seeded
pip input mismatch was corrected by explicit pip-free ordinary arm benchmark
preparation. All application cases retain seeded ordinary environments. Current
source/native Python scaled archives are 3,904,572/7,552,604 bytes, within the
unchanged 4,294,176/8,306,594 limits; seek series exactly match prior observations.
No budget was relaxed or automatically refrozen.

The entire process trees use the recorded `traceable-native-syscalls-v1` policy.
It selects ordinary syscall fallback by returning ENOSYS for asynchronous kernel
I/O; this is not unrestricted-host acceptance. Fixed structure/I/O/FD/scaling
limits apply, while time/RSS limits remain host-fingerprint scoped. See
[budget-replay.json](budget-replay.json) and [acceptance.json](acceptance.json).

The original CI ZIP and all 4,803 extracted files are verified. A local transfer
bundle containing the capture, source snapshots and replay tools also prepares
and restores successfully: 4,844 source files/848,966,499 bytes, with every restored
hash, size, mode and exact roster checked. [Retention metadata](retention.json)
records that local archive's exact identities; the larger backup stays local.
Separately, the owner approved the exact eight-file, 153,582,706-byte arm evidence
set for [public prerelease retention](https://github.com/JBlaschke/glue_rs/releases/tag/evidence-linux-arm64-2026-10-28).
Every server digest/size matched, and a fresh download passed all documented
checksum, extraction and full replay steps. Anonymous checksum retrieval also
passed. [Release metadata](release.json) binds the approved/public/downloaded
identities. This establishes external retention for the arm capture and verifier
set. Asset README/summary bytes preserve their prepublication snapshot; release
notes and this record describe publication and subsequent remote verification.
Raw captures/archives remain outside Git under ignored `.evidence-local`.

These records concern the exact tested arm source. Historical x86 acceptance
at `e3962701` predates the Python version-probe fix; fresh same-source x86
[run 40758958354](https://github.com/JBlaschke/glue_rs/actions/runs/40758958354)
is dispatched separately. Complete Darwin oracle/corpus, Mac budgets, remaining
target retention and final M2 sign-off remain open. Guest SIP stays enabled.
