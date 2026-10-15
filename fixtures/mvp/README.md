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
spaces/non-ASCII, removes the build prefix, clears execution environment, uses
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

The optional Linux CI
[trace environment policy](../../docs/decisions/mvp-v02-ci-trace-environment.md)
uses `trace_environment.c` to return `ENOSYS` for kernel asynchronous I/O before
executing a complete case/reference/control or benchmark process tree. Its
independent probe and `trace_environment.py` retain and verify the helper,
source and proof identities. This selects a syscall fallback for complete
tracing; it does not establish unrestricted-host acceptance or provide a
security sandbox. The combined CI orchestration belongs to the integration
branch; this V02 branch carries only the helper, evidence checks and tests.
