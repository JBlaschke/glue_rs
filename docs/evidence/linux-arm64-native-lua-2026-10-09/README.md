# Native Lua closure evidence — 2026-10-09

This bundle records the optional GNU Linux arm64 native profile for separate
Lua 5.4.9 and 5.5.1 launchers. Both Linux captures used clean source commit
`fb61e5e22a4c3edc4e8a8c58af1f229c051d1a1a` on
`codex/a6-linux-native-lua`, from merged `main` at `7853282`. Implementation is
`3a24833`; `fb61e5e` additionally removes adversarial compiled inputs before
the relocated positive run. Both captures and all twelve rejection traces pass.

The launcher verifies every image's hash, ELF metadata and declared dependency
closure before loading. It fills and seals both memfds before the first
`dlopen`, loads dependencies locally before creating the Lua state, and returns
cached C initializers to the existing C-owned error boundary. See
[ADR 0008](../../decisions/0008-linux-native-lua-closure.md) for the accepted
ELF subset, ownership checks, trusted-code requirements and remaining gates.

| Validation | Lua 5.4 | Lua 5.5 |
| --- | ---: | ---: |
| Source-profile workspace tests, Mac and GNU Linux arm64 | 181 | 182 |
| Native-feature workspace tests, GNU Linux arm64 | 178 | 179 |
| Native-feature workspace tests, Mac arm64 | 177 | 178 |
| Optimized native-feature `glue-runtime-lua` tests, Mac arm64 | 53 | 54 |
| Workspace/all-targets Clippy, all four profiles on both systems | passed | passed |
| Relocated native execution and complete trace check | exit 0 | exit 0 |
| Six complete ELF rejection trace checks | passed | passed |

The portable native parser/closure suite has 37 passing tests. The combined
Python syscall-policy suites have [54 passing tests](python-policy-tests.txt).
Mac native-feature tests
exercise portable validation and C-only boundary fixtures; no Mac native loader
execution is claimed. The one-test workspace difference is a GNU observed-host
test. Mac logs precede the fixture-only cleanup commit; attribution and toolchain
records are in [validation-context.txt](macos/validation-context.txt).

Both positive runs have empty stderr and match ordinary disk loading after PID
normalization. The ordinary loader links the same Cargo-produced static Lua
core and headers, exports the same ten reviewed Lua APIs, and loads the closure
before creating its state. The observed native outputs are:

```text
Lua 5.4 native answer=42 data=7 constructors=1 state=124 pid=5734 errors=2
Lua 5.5 native answer=42 data=7 constructors=1 state=124 pid=5736 errors=2
```

These observations cover an archived dependency, native function/data,
constructor count, the selected Lua state, require caching, initializer and
function errors, archive source/resources, and canonical `package.loadlib`.
The raw positive traces are [5.4](lua54/native-lua.trace.txt) and
[5.5](lua55/native-lua.trace.txt); the checker records are
[5.4](lua54/trace-check.txt) and [5.5](lua55/trace-check.txt). They check exact
stdout/PID, complete exits, two executable memfds with all four seals verified
before any loading, private mappings without W+X, and no payload filesystem
mutation or source/native fallback. This is fixture evidence, not a sandbox.

| Rejection fixture, both versions | Exit status | Memfd attempts |
| --- | ---: | ---: |
| Wrong architecture | 2 | 0 |
| SONAME mismatch | 1 | 0 |
| Executable stack | 2 | 0 |
| Undeclared `DT_NEEDED` | 1 | 0 |
| Undeclared constructor import | 1 | 0 |
| Wrong initializer | 1 | 0 |

Each case runs in a fresh process and checks its exact diagnostic, empty stdout,
status and full trace. Records and checker results are retained separately for
[5.4](lua54/rejection-trace-check.txt) and
[5.5](lua55/rejection-trace-check.txt), with the inputs, manifests, ELF inspection
and raw traces in each profile's `native-rejections` directory. Status 2 denotes
an unsupported capability; status 1 denotes an invalid closure in these cases.

## Environment and identities

Both Linux captures used kernel `7.1.4-200.fc44.aarch64`, glibc
`2.36-9+deb12u10`, 4096-byte pages, `vm.memfd_noexec=0`, GCC
`12.2.0-14+deb12u1`, Rust/Clippy 1.88.0 and strace `6.1-0.1`. The launchers and
Lua cores are debug builds with Lua API checks; C shared-library fixtures use
`-O2 -g0`. See [5.4](lua54/environment.txt), [5.5](lua55/environment.txt) and
the build commands. Mac validation used macOS 26.7 (25G229), arm64 and actual
Rust/Clippy 1.88.0.

The immutable local image ID is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`, digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`.
[image-summary.json](image-summary.json) retains selected inspection fields.
[image.Dockerfile](image.Dockerfile) pins the Rust base and strace; its moving
apt repository does not establish a byte-reproducible image producer.

The source pin is `lua-src 551.0.2`, selecting Lua 5.4.9 or 5.5.1 with
int64/float64 and separate native-v1/c-boundary-1 build IDs. Each profile retains
its manifest, feature graph and all four `build-provenance` records for source
and native builds. Provenance records describe default compiler arguments and
source-builder additions; they are partial build records. Exact dynamic Lua
exports match the reviewed allowlist in both launcher and baseline; neither
links a shared `liblua`. The ELF and export inspection records are retained.

| Profile | Debug launcher SHA-256 | Positive archive SHA-256 |
| --- | --- | --- |
| Lua 5.4 | `2551f67260e2c0f0d0be3536fd9f645911266198f562e21181bcfea8b926dccd` | `e58f06e98e869f90f2bd2022716f5e24f317d4520e1e28ae7287df34fa20b9be` |
| Lua 5.5 | `eb626996d17b128ee152483f29dfd2f4f971c6328bfd2d0eb5f6e1d5db776a7c` | `1e8a3fbbcb5f47f519868afae3d6509b47857d875d37b3cbccf4f6baa1099f33` |

The corresponding [5.4](lua54/artifacts.sha256) and
[5.5](lua55/artifacts.sha256) files also identify the ordinary-loader binary.

## Capture and verification

Exact Podman invocations are retained for [5.4](lua54/podman-command.txt) and
[5.5](lua55/podman-command.txt), with [5.4](lua54/commands.sh) and
[5.5](lua55/commands.sh) build/run commands. Containers have networking disabled,
a read-only root and repository, and ephemeral build storage. All current-run
valid and adversarial shared-library inputs are removed before the positive
run. The archive is relocated to a path containing spaces and made read-only;
neither trace reads payload inputs from the mounted repository.

Each Linux profile retains clean Git status, an empty source diff, 80 source
hashes, fixture input hashes, seven archive identities, test/Clippy logs and
exact statuses/output. Copied records were compared byte-for-byte; source hashes
were checked against clean Git blobs, and all fourteen archive contents and
compiled fixture hashes were verified in memory. See
[verification.txt](verification.txt). The retained copies also pass all fourteen
[trace checks](retained-trace-validation.txt). Binaries and archives remain outside this
text bundle. [SHA256SUMS](SHA256SUMS) covers every bundle file except itself;
verify from this directory with `shasum -a 256 -c SHA256SUMS`.

## Limits

This observes one GNU Linux arm64 kernel/glibc/page-size cell. Declared minimum
versions, Linux x86_64, other OS native loaders, signed release deployment and
release Linux execution remain untested. Native code is trusted C/Lua ABI code;
arbitrary foreign exceptions or constructor reentry are outside this profile.
Constructors must leave relocation slots unchanged; actual slot checks follow
constructors, while metadata/closure defects are rejected before loading.
Separate launchers select one Lua version. General native compatibility,
simultaneous runtimes, host/bundled runtime acquisition and four-OS acceptance
remain open.
