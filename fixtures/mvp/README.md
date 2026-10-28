# Native MVP acceptance harness (V02)

The task contract has one entry point and one receipt checker:

```sh
scripts/run-mvp.sh --case lua55-project --target aarch64-apple-darwin --output /new/receipt-directory
scripts/check-mvp-results.py /new/receipt-directory/receipt.json
```

Python 3.9+ runs the build/measurement harness; the deployed application runs
with its included launcher and a PATH containing no language tools. A foreign
execution target is rejected before work begins. Linux glibc x86_64/arm64 and
macOS arm64 are explicit cells; cross compilation cannot satisfy execution.

Cases are version-one JSON recipes under `fixtures/mvp/cases` (override this
directory with `GLUE_MVP_CASES_DIR`). The checked-in Lua recipes demonstrate:

- `inputs`: existing source files/trees copied under a fresh build prefix.
  `source` can be repository-relative or `${ENVIRONMENT_INPUT}`; `destination`
  stays under that prefix. Internal relative links are allowed; escaping or
  absolute links reject. Fixture preparation may construct a controlled venv.
- `prepare` (optional), `build`, and `reference`: command objects with an `argv`
  string array, optional `cwd` and `environment`. No shell text is interpreted.
  The stock reference runs before build inputs disappear; `reference_kind`
  must be `stock` for acceptance.
- Templates: `{repo}`, `{work}`, `{inputs}`, `{build}`, `{payload}`, `{output}`, `{target}`.
  The builder publishes the complete distribution at `{build}`. `arguments`
  supplies application argv. Optional `run.argv` must invoke `{payload}/glue`.
  Optional `expected_exit` defaults to zero, and `timeout` to 120 seconds.
- `required_checks` may add checks, never remove baseline requirements.

For Lua cases supply `GLUE_MVP_GLUE`, `GLUE_MVP_HELPERS`, and the selected stock
`GLUE_MVP_LUA54`/`GLUE_MVP_LUA55` executable. Python and Node owners supply recipes
using their independent runtime/fixture inputs. The harness never installs
packages, runs package-manager hooks, compiles user dependencies or downloads.

The harness inventories input bytes before/after packaging, compares exit/stdout/
stderr against the stock runtime, moves the distribution to a new path with
spaces/non-ASCII, deletes the copied input trees and build prefix before included
execution, clears execution environment, uses
an unrelated cwd, makes payloads read-only and makes HOME/temp/cache unusable.
Those paths are read-only regular files, so child paths fail with ENOTDIR even
under rootless VM filesystem mounts.
Linux root runners drop to uid/gid 65534 for application execution so mode bits
remain meaningful. macOS uses sandbox-exec to deny network and quarantined input
reads; Linux requires a network namespace with loopback only (for example an
offline Podman container). An unavailable enforcement mechanism records an
unavailable check and fails acceptance. macOS sandbox application may require
an approved host execution outside an enclosing agent sandbox.

Receipts retain exact argv, exit/stdout/stderr hashes, native host/kernel/libc,
input/payload identities, exact runtime selection and individual check statuses. The checker verifies
evidence files and rejects missing/skipped checks or absent target execution.
Snapshot equality is supplementary: full extraction traces belong to R02,
and timing/file/I/O budgets to R03. This harness does not claim those gates pass.

`fixtures/mvp/run-linux-lua.sh` runs both source/native Lua families in the
offline Linux arm64 cell with read-only `/workspace` and `/vendor` mounts and a
writable `/evidence` mount. Supply a cached Python 3.9+ harness runtime on PATH.
It independently compiles stock Lua reference drivers from the vendored official
source, and prepares fixture native binaries before invoking glue. This explicit
fixture preparation is separate from packaging existing user modules. When Git
metadata is outside a read-only worktree mount, pass the host's full commit via
`GLUE_MVP_COMMIT`; the runtime and artifact hashes are always recorded.

Run harness oracle tests with:

```sh
python3 -m unittest discover -s fixtures/mvp -p 'test_*.py'
```

The synthetic tests exercise rejection of input fallback, cache writes, missing
dependencies, wrong exits, changed bytes, missing offline policy and skipped
target execution. They do not count as a language/OS product acceptance run.

## Complete execution traces and macOS deployment (R02)

Set `GLUE_MVP_TRACE=required` when running any language case, or select the
`no-extraction` recipe with `GLUE_MVP_EXTRACTION_CASE=lua55-native` (substitute
the actual corpus case). This adds mandatory trace completeness, no-extraction,
oracle-control and target signing checks to the same receipt. Linux needs
`strace` and an approved ptrace-capable native runner, for example the offline
container with `--cap-add SYS_PTRACE --security-opt seccomp=unconfined`.

The runner retains `strace -ff -yy` logs for every process/thread. The checker
requires a successful initial exec, terminal records and every cloned child;
it rejoins unfinished/resumed records and rejects malformed/truncated evidence.
Filesystem writes, open-for-write, create/unlink pairs, metadata mutations and
writable shared file mappings outside explicitly declared application outputs
reject even if the kernel denied them. Successful asynchronous I/O mechanisms
without a decoder reject. Anonymous memory objects remain distinct from
filesystem extraction. Source/resources/native bytes are not recognized by a
fixture digest registry. `application_outputs` may name directories strictly
under `{output}/application-output`; payloads, inputs and caches are never
implicit writable destinations.

Actual negative controls attempt ordinary create/unlink, denied writes and a
descendant's payload write. A read-only positive control must pass, preventing
an oracle that simply rejects every trace. The receipt checker re-parses raw
traces and checks retained trace hashes. `scripts/check-mvp-trace.py` exposes the
same oracle for independent operator captures.

Hosted native GNU Linux CI supports x86_64 and arm64 through closed,
host-matched profiles. Dispatch `mvp-native.yml` with `target=x86_64`,
`target=aarch64` or `target=both`; the default remains x86_64. Every selected
cell requires the complete 24-case corpus and all five reviewed target budgets.
Target-specific Node/PBS/wheel inputs and the exact CPython 3.14 conda closure
are prepared independently before packaging. Foreign hosts refuse before
provisioning, and artifacts and final summaries retain the selected target.
The arm64 automation requires a fresh passing native result and retained replay;
portable controls alone do not establish it.

Both Linux profiles use the explicitly recorded
[trace environment policy](../../docs/decisions/mvp-v02-ci-trace-environment.md)
to disable kernel asynchronous I/O before every case/reference/control and
benchmark rank. These results cover the runtime's syscall fallback in that
environment; they do not establish unrestricted-host acceptance. The oracle
continues to reject unobservable successful asynchronous I/O.

On macOS, `GLUE_MVP_SIGNING_POLICY=ad-hoc|developer-id` selects the intended
policy; `scripts/check-macos-deployment.py PAYLOAD --policy ad-hoc` also checks a
final layout independently. Every Mach-O image gets strict codesign verification
and its actual signature metadata is reported. Developer ID mode also records
Gatekeeper assessment. Ad-hoc verification never proves Developer ID signing or
notarization. No code is silently re-signed by these checks. The selected development policy
is ad-hoc: strict-valid ad-hoc and existing Developer ID signatures are accepted
and retain their actual class. Public release requires Developer ID signatures
on every image, Gatekeeper assessment and separate notarization evidence.

Local R02 evidence: all four source/native Lua family cases passed complete
Linux arm64 traces plus injected controls. macOS arm64 final Lua54 and Lua55
layouts passed relocated/offline execution and strict development signature
verification. Native administrator authentication succeeded, but both wildcard
and exact owned ad-hoc fixture syscall probes were rejected by SIP. The exact
probe emitted zero events and never started the fixture body. See the
[capability diagnostic](macos-trace/README.md). A complete Darwin capture,
decoder and extraction oracle still require implementation and validation on
a trace-capable approved host. Hosted native x86_64 acceptance is being rerun
after harness fixes. Public Developer ID/notarization evidence remains open.


## Deployment cost budgets (R03)

`./scripts/benchmark-mvp.py --case CASE --target TARGET --output NEWDIR`
measures empty-entry, baseline and 10,000-extra-source distributions at 1 and 32
ranks. Supply the same runtime/build input variables as the acceptance case and
`GLUE_MVP_TRACE=required` for complete Linux startup I/O counts. The output
`benchmark.json` retains individual rank exits/output hashes, elapsed time,
kernel RSS and sampled PSS/FD data, plus archive/runtime/native sizes and file
counts. Fresh processes are not labelled cold filesystem cache measurements.
`--cold-hook FILE` records an explicit operator cache-reset argv only.

`--budget FILE` checks a frozen numeric profile; `--freeze-budget FILE` only
accepts a complete passing report. The CI matrix and accepted numeric profiles
live under `fixtures/mvp/budgets`. Check all cases for a target with:

```sh
scripts/check-mvp-budgets.py --target aarch64-unknown-linux-gnu --reports /evidence
```

Missing reports, unavailable required metrics and source-scaling regressions
fail the gate. Time/RSS limits apply only to the recorded host boot fingerprint;
structure and size limits remain target/case scoped. See
`docs/decisions/mvp-r03-hpc-cost-budgets.md` for measurement methods, margins and
compact-mode costs. Native libraries still incur ordinary OS loader work.
