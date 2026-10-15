# R03: native compact-distribution cost budgets

The compact MVP keeps Lua, Python and Node source and resources in an archive.
Declared native libraries remain ordinary filesystem images. Hashing, archive
validation, runtime prerequisites and OS-loader dependency search all contribute
to startup cost. No claim of zero filesystem traffic or a shared-memory runtime
is made.

`fixtures/mvp/benchmark.py` runs V02/R02 acceptance before measuring each empty,
baseline and 10,000-extra-source variant. Empty means replacing the application
entry while retaining the selected dependency closure. Every timed rank must
match its stock reference output and exit status. The workload runs at 1 and 32
ranks, with a fresh process for each observation. First-process and warm-process
results do not imply a cold filesystem page cache. A supplied `--cold-hook` JSON
argv can record an operator-controlled cache reset; the operator must describe
its guarantee. The default reports `cold_cache.status=uncontrolled`.

Copied fixture input trees are deleted before included execution after byte
preservation and stock-reference comparisons. Original developer inputs are
read-only build inputs and remain untouched.

A tiny independently compiled C parent uses monotonic time and `wait4` kernel
resource usage, avoiding a Python parent's inherited RSS high-water mark.
Peak RSS includes the waited process's accounted children; per-rank PSS and FD
observations sample the launcher PID every 5 ms and are lower bounds, with null
for unavailable samples. The complete startup trace separately reconstructs
peak descriptors per process. Full Linux traces count all open, metadata and
read calls, including validation/hashing and native dependency search. The
1/32-rank timing observations run the same included distribution without trace
instrumentation. They are per-rank elapsed time and memory, not total cluster
memory or a synchronization guarantee.

The numeric budget configuration lives in `fixtures/mvp/budgets/index.json`.
Structure limits are target/case scoped; time and RSS limits only apply when the
recorded kernel/CPU/libc/CPU-count/host-boot fingerprint matches. Other hosts still check
structure and source-count scaling, without acquiring a universal latency
promise. Budgets include measured artifact identities and explicit margins:
10% bytes, 2x maximum observed elapsed time, 25% RSS/read calls, eight extra
open/metadata/read calls and four extra descriptors. Deployment file and native
byte deltas must remain zero when adding source. Metadata delta is bounded by
ten calls for 10,000 entries. A complete failing or missing metric is never
converted to zero, and incomplete acceptance cannot freeze a budget.

The archive reader uses a seek-aware buffer bounded at 64 KiB. The diagnostic
`cargo run --release -p glue-format --example reader-cost -- plain ARCHIVE`
can be compared with `buffered` on exactly the same validated archive under
`strace -c -e trace=read,lseek`. Both retain canonical archive checks and manifest
integrity. This isolates the buffer effect from application/runtime differences.

Run on a native target with independently prepared case inputs:

```sh
GLUE_MVP_TRACE=required scripts/benchmark-mvp.py \
  --case lua55-project --target aarch64-unknown-linux-gnu \
  --output /new/evidence/lua55-project \
  --budget fixtures/mvp/budgets/aarch64-unknown-linux-gnu/lua55-project.json
scripts/check-mvp-budgets.py --target aarch64-unknown-linux-gnu \
  --reports /new/evidence
```

`--repository` selects the root for recipe-relative input paths. The compiler
used for the measurement helper and all runtime/bridge/helper paths are recorded
or hashed in the receipts; no application native input is rebuilt by the
packager. Large traces and binaries remain outside Git with summary identities.

macOS development acceptance uses ad-hoc signatures. Public release requires
Developer ID signing and notarization. Ad-hoc verification does not prove those
public-release requirements. A complete macOS extraction trace remains
unavailable. Native Linux x86_64 measurements were unavailable during the original
arm64 observations; the reviewed x86_64 follow-up is recorded below. No privileged cache
reset, signing credential change or tracing-policy change is performed.

The recorded Linux arm64 release observations used a 4-CPU native Podman VM,
Linux 7.1.4 and glibc 2.36. `budgets/observations.json` retains exact host,
artifact, measurement-tool and raw-report identities. The launcher source
revision is a hint where the build included dirty documentation; its captured
binary SHA identifies the measured bytes. No clean exact-commit build is
inferred.

| Case | Deployed files baseline → +10,000 | Metadata calls baseline → +10,000 | Read calls baseline → +10,000 | Peak descriptors |
| --- | ---: | ---: | ---: | ---: |
| Lua source | 6 → 6 | 15 → 15 | 134 → 207 | 5 |
| Lua native | 8 → 8 | 31 → 31 | 164 → 236 | 5 |
| Node CommonJS | 12 → 12 | 68 → 68 | 2,166 → 2,243 | 19 |
| Python source | 12 → 12 | 351 → 351 | 1,884 → 1,923 | 6 |
| Python NumPy/native | 40 → 40 | 504 → 504 | 3,118 → 3,151 | 5 |

The native-heavy Python closure contained 50,689,322 native bytes, unchanged by
source scaling, alongside 86,219,627 runtime bytes. Its largest observed per-rank
RSS was 70,004,736 bytes and maximum 32-rank elapsed time was about 9.12 seconds.
No explicit BLAS/OpenMP override was needed in this 4-CPU cell. These are local
observations, not universal time bounds. All individual rank outputs matched
the stock reference.

On one identical 10,003-resource archive, the plain reader made 60,027 reads
and 60,022 seeks; the bounded buffered reader made 42 reads and 7 seeks. Both
validated all canonical archive structure and manifest integrity. Native
payload hashing still causes substantial real reads: Python native-heavy
startup read about 171 MB in the scaled case, and Node about 143 MB. Archive
metadata parsing also consumes CPU/RSS as source count grows; buffering does
not remove those checks or the ordinary loader's work.

## Reviewed hosted Linux x86_64 cost observations

Five R03 profiles from native GitHub Actions run
[38796669924](https://github.com/JBlaschke/glue_rs/actions/runs/38796669924)
were independently replayed before accepting numeric limits. This accepts those
cost profiles only: the overall run failed one of its 24 acceptance cases because
the separate Python 3.14 native build selected incompatible GCC runtime inputs.
That failure remains recorded and does not invalidate the independently complete
Python 3.13 benchmark profiles. No whole-target acceptance pass is claimed.

The exact runtime versions were Lua 5.5.1, Node 24.22.0 and Python 3.13.16.
All five profiles retain empty-entry, baseline and +10,000-source variants;
each variant has first/warm fresh-process measurements at 1 and 32 ranks.
Independent review checked all 15 acceptance receipts, 60 actual oracle-control
captures, and 990 rank results. The current strict Linux parser replayed raw
process/thread traces, including their retained hashes; stock-reference and rank
stream hashes, wait4 kernel metadata, aggregates and the proposed numeric limits
were checked independently. Deployment byte/file counts were reconciled against
the retained inventories. Every rank matched the stock reference.

The observed host had four available CPUs, an AMD EPYC 9V74 processor, Linux
6.17.0-1022-azure and glibc 2.39. Its full boot fingerprint is
`7eb6db48acd6b68de0840e5dacb631e22f230fdc37b11e2e6916bf2dc8a01cc5`.
Time/RSS limits retain that exact scope; a fresh hosted VM boot does not acquire
a latency/RSS promise, while fixed structure, size, I/O, descriptor and scaling
limits still apply. No cold-cache or aggregate-cluster-memory claim is made.

This run used the explicit `traceable-native-syscalls-v1` CI environment for the
builder, stock reference, included launcher, oracle controls and every measured
rank. It returns ENOSYS for asynchronous kernel I/O and selects the runtime's
ordinary syscall fallback. The actual native x86 pre-policy io_uring setup
succeeded; the filtered parent and executed child returned ENOSYS for all nine
blocked interfaces and the x32/i386 guard probes. The oracle was unchanged. These
results do not establish unrestricted-host acceptance when asynchronous kernel
I/O is available, and the same scope applies to the accepted numeric profiles.

| Case | Files baseline → +10,000 | Metadata calls baseline → +10,000 | Read calls baseline → +10,000 | Peak descriptors | Maximum per-rank RSS, bytes | Maximum per-rank elapsed, seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Lua source | 6 → 6 | 15 → 15 | 156 → 229 | 5 | 19,210,240 | 2.880 |
| Lua native | 8 → 8 | 27 → 27 | 200 → 272 | 5 | 21,803,008 | 2.934 |
| Node CommonJS | 12 → 12 | 67 → 67 | 2,246 → 2,324 | 19 | 91,881,472 | 5.475 |
| Python source | 12 → 12 | 357 → 357 | 2,043 → 2,078 | 6 | 41,283,584 | 13.142 |
| Python NumPy/native | 41 → 41 | 516 → 516 | 3,391 → 3,424 | 5 | 81,154,048 | 20.142 |

The Python native-heavy profile contains 53,083,602 native bytes and 94,618,454
runtime bytes, both unchanged by source scaling. Lua's native profile contains
32,072 native bytes. Source scaling adds zero deployed files, native bytes,
runtime bytes and metadata calls in all five profiles. The maxima in the table
span empty/baseline/scaled and both rank counts; they are observations on this
host, not universal timing limits. No explicit BLAS/OpenMP override was set.

The reviewed profiles live under `fixtures/mvp/budgets/x86_64-unknown-linux-gnu`.
Their numeric values exactly match the independently recomputed proposals;
review provenance and the required trace policy were added separately.
`observations-x86_64-unknown-linux-gnu.json` retains report/proposal/accepted-budget,
receipt, raw-trace manifest, launcher, host, measurement and review identities.
The measured launcher SHA-256 is
`80114ea81faceefc540aafce40854d26e88d5d1f67398ebd9a3d0492f6669830`,
from source `26bc25446cf257794947394e8075267a43ae3029` with an empty recorded
source-status file. The retained artifact metadata reports
`9dea9422cefedf9d938164883cb088a82fb3757f6dbc9ed4bfe422ba104d68a8`;
local report/receipt/trace hashes were independently rechecked. GitHub's artifact
expires on 2026-10-29; this observation does not claim durable release-asset
retention. The overall failed receipt remains unchanged.
