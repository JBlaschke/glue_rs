# V02/R03: bind arm benchmark environment inputs

Status: accepted for a fresh native rerun; no changed budget limits.

Native arm run 40722874852 passed all 24 case receipts and all five benchmark
executions. Enforcement failed only for the two Python profiles: archive size
and seek counts exceeded accepted arm limits. Every source variant grew by
exactly 1,930,282 compressed bytes, including the empty-runtime variant, while
CPython 3.13.16 and 86,219,627 deployed runtime bytes remained unchanged.
Source scaling still added exactly 3,810,000 archive bytes; other structural
scaling checks passed. The new ordinary environment seeds pip (889 inventory
entries), unlike the pip-free payload shape in the recorded arm observations.
The historical record does not establish its exact environment kind.

Make the benchmark input shape explicit in each closed Linux profile: arm64
uses an ordinary `venv --copies --without-pip`, while x86_64 retains its ordinary
seeded venv. Add an explicit preparation kind and retain it in the existing
environment receipt. This is independent input preparation, never product
package filtering or runtime installation. Supplied application packages and all
native fixtures remain included. Every one of the 24 acceptance cases continues
to use the ordinary seeded environment; only arm Python benchmarks select the
pip-free preparation. The final acceptance plan records this distinction.

Keep every accepted budget byte-for-byte. Do not subtract package costs, change
source count/ranks/corpus, suppress a failure or automatically refreeze limits.
Portable controls verify environment selection and actual ordinary venv seeding
behavior; a fresh native run must independently prove archive and seek limits.
Retain the failed capture and its diagnosis. Full raw receipt/oracle/rank replay,
external retention, Darwin acceptance and M2 closure remain separate gates.

This milestone also integrates the reviewed PR #90 tree into a new branch based
directly on `main`: #90 merged into its already-closed feature base rather than
`main`. New PRs target `main` explicitly to avoid stranding dependent work.
