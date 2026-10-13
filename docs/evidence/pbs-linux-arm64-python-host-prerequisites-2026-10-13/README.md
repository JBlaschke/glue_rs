# Product host Python prerequisites — GNU Linux arm64 / Mac preparation

Product implementation `42c5abed05f85cd2b6525346af397288d4c13e93` adds
`glue python-host` on `codex/a7-python-host-prerequisites`, based on merged
`c4a901e`. The clean Mac capture uses that revision. The clean native capture
uses `3f3f31a18b59c664dda2dee36d409029c06dfc9f`, which adds the isolated inventory-specific trace checker
and tightened preparation checks; product/runtime code is unchanged.
See [decision 0024](../../decisions/0024-python-host-prerequisites.md) and the
[fixture](../../../fixtures/python-host-prerequisites/README.md).

The command verifies an explicit pinned PBS artifact as data and publishes the
two already admitted host prerequisite projections. It executes no Python,
performs no runtime discovery and adds no interpreter executable. The resulting
prefix is used by `glue python-template`, then `glue build-python`.

| Provider | Sources | Encoding caches | Payload files | Bytes | Directories |
| --- | ---: | ---: | ---: | ---: | ---: |
| host-full | 2,174 | 0 | 2,175 | 112,722,024 | 204 |
| host-install | 1,037 | 3 | 1,041 | 89,479,393 | 103 |

Files receive `0444`, directories `0555`, and every file/directory mtime is
exactly epoch `1704067200`. Provenance is a separate final file, excluded from
payload counts. The report records selected/omitted regular-file counts and
bytes, complete artifact entry counts, each payload identity and the provenance
file identity. The trees are embedding prerequisites, not complete installations;
provenance explicitly leaves runtime execution and fresh full/install pairing
unobserved. Immutable backing remains an execution requirement.

## Preparation evidence

Both builders pass four actual generations, including repeated full/install
preparation, and all 63 hostile controls. The independent oracle checks every
payload path/hash/mode/mtime, every directory mode/mtime, exact provenance and
report fields, publication protection and deterministic bytes. See
[GNU controls](host-controls/audit.json) and
[Mac controls](macos/host-controls/audit.json). No owned payload tree remains in
the retained controls; scratch trees are removed after independent checks.

Two complete preparation syscall traces require a single process and builder
execution. Their scoped checker rejects target image reads/mapping, executable
anonymous mappings, execute-granting protections, foreign executable images,
publication outside the prefix, descriptor reassignment, child processes and
network activity. The exact executable system-file mappings are the observed
GNU libm/libgcc_s/libc startup images. Standard stdout/stderr carry reports.
Creation, writes, permissions and mtimes remain confined to the new owned tree.
The retained traces use a 512-byte string display bound; every fixed file path is
at most 126 bytes. Binary buffer truncation does not omit syscall records or
path/descriptor evidence. The preparation oracle passes 46 regression
tests on Mac and stock GNU Python, including all previously discovered loopholes.

The historical host installer fixtures are absent from the native setup path.
The stock producer still supplies the already verified frozen startup bundle,
headers and genuine offline pip fixture during builder setup. Both host trees
are prepared by the product and audited before adding the separately reported
physical metadata lures. The immutable runtime stage runs after removing the
producer, headers and staging inputs.

## Runtime and product evidence

All six runtime cases execute as expected and pass the closed trace checker:
bundled/full-host/install-only succeed; each single-byte metadata CRC control
fails before acquiring its provider. Archive, source, cache, loader, descriptor,
output and no-extraction checks remain inherited from the original installed-
package policy.

The new install-only tree deliberately omits `LICENSE.txt` and `lib-dynload`
from its stdlib root. Its independently SHA-bound source/cache pins derive 189
direct children, plus dot entries: exactly 191. The prior complete stock tree
had 193; full-source remains 192. An isolated subclass changes only the two
metadata-host enumeration predicates for this workload. All historical checker
files remain byte-identical. Cross-policy tests prove the old checker admits its
193-entry capture and rejects the 191-entry capture, while the new checker does
the reverse. Added directory-count/owner/EOF/phase controls supplement the prior
126 hostile trace mutations: all 149 reject. Extra or missing entries are not
silently admitted. See [hostile audit](host-prerequisite-hostile-audit.json).

Independent [product checks](product-audit.json) verify all 27 commands, 4,427
valid archive members, exact application/metadata/RECORD transformation bytes
and three intentional CRC failures. Both installed-input modes and all 30 hostile
build controls still pass. Three separate build process traces contain one builder
execution and no child interpreter. All six archive hashes match the previous
clean template increment; see [equivalence](prior-archive-equivalence.json).
Runtime/helper/C bridge/host admission/template bodies remain unchanged; see
[source identities](unchanged-runtime.json).

## Cell and validation

The pinned offline Podman image is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`,
with kernel `7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, GCC 12.2,
strace 6.1 and 4 KiB pages. Rust 1.88.0 builds the actual GNU launcher against
verified CPython 3.13.16 headers. Runtime uid/gid are 65534; runtime storage is
read-only, network is disabled, and temporary/home paths are inaccessible.

Mac/GNU source workspaces pass 476/477 tests for Lua 5.4/5.5 with Clippy. The Mac
packaging workspace passes 506. Optimized GNU suites pass 142 Python/probe,
49 packaging and 21 CLI tests with Clippy. Metadata/importer/entry protocols pass
32/16/7. The Python policy suite passes 241 tests on Mac and stock GNU Python,
including six new trace-adapter boundary tests. Format is clean. Pre-commit Rust
logs are explicitly bound to identical committed inputs by
[Mac bindings](macos/validation-binding.json) and
[GNU bindings](linux-source-workspace/committed-code-binding.json); their
263-file scope excludes new standalone fixture scripts and Markdown.
[Follow-up binding](policy-change-binding.json) verifies all those inputs and
all product crates remain unchanged at the native revision. The
[clean Mac preparation receipt](macos/clean-receipt.json) uses the product
implementation revision; the final 46-test oracle and 241-test policy suites
use the final checks, separately identified in
[checker bindings](final-checker-validation-binding.json). No cross-compilation result is claimed as
native runtime execution.

## Replay

All six complete runtime traces, both complete host preparation traces, three
template process traces and three build process traces are retained as gzip.
Compressed replays match their original observations. Large upstream payload
trees and distribution archives are not duplicated in Git.

```sh
evidence=docs/evidence/pbs-linux-arm64-python-host-prerequisites-2026-10-13
python3 scripts/check-linux-python-host-prerequisites-trace.py \
  "$evidence/install-host.trace.txt.gz" --mode install-host \
  --stdout-file "$evidence/install-host.stdout.txt" \
  --stderr-file "$evidence/install-host.stderr.txt" \
  --metadata-file "$evidence/source-metadata.json" --archive-bytes 15068
python3 scripts/test_linux_python_host_prerequisites_trace.py --audit-capture \
  "$evidence" target/host-prerequisite-hostile-replay.json
python3 fixtures/python-host-prerequisites/test_prepare.py \
  --audit-process-trace "$evidence/host.host-process.trace.txt.gz" \
  --program /build-target/release/glue
```

With matching exported archives, `product-audit.py` independently rechecks this
retained capture. `SHA256SUMS` covers every retained file except itself. This
supports the fixed GNU cell and portable Unix preparation; general installation,
uv-tree ingestion, version selection, real-package/native compatibility and other
platforms remain separate work. G0/G1/G2/G3 remain open.
