# Real pure-Python packages — GNU Linux arm64 and Mac preparation

Clean implementation `e525db8542886800ff008c300c25bd56e7e3e09a` on
`codex/a7-python-real-packages`, from merged `fce3dad`. See
[decision 0025](../../decisions/0025-python-real-package-compatibility.md) and
[fixture usage](../../../fixtures/python-real-packages/README.md).

The product now validates distribution `Requires-Python` against its selected
runtime, including metadata supplied in an explicit application tree. The
bounded release-only subset supports numeric comparisons, conjuncts, equality
prefixes and compatible releases; unsupported, malformed, duplicate, folded,
empty and unsatisfied fields reject. Building checks the combined owned
application before provider-root reads or publication. Direct metadata archives
apply the same policy before acquiring their runtime. This adds no version
selection, installation or dependency solving.

## Genuine upstream corpus

The checked-in wheels are the unmodified
[markdown-it-py 4.2.0](https://pypi.org/project/markdown-it-py/4.2.0/),
[mdit-py-plugins 0.6.1](https://pypi.org/project/mdit-py-plugins/0.6.1/) and
[mdurl 0.1.2](https://pypi.org/project/mdurl/0.1.2/) artifacts. Their pins, original
source, assets, metadata and licenses are independently verified. Optional extras
are not selected. Stock CPython 3.13.16 / PBS `20261009` and its pip install them
offline into a fresh `--without-pip` venv, with pip outside that environment.

| Inventory | Count |
| --- | ---: |
| Upstream wheel members | 145 |
| Genuine installed site files | 261 |
| Retained package files | 151 |
| Application resources including entry | 152 |
| Retained application bytes | 451,195 |
| Omitted default bytecode caches | 110 |
| Omitted generated console wrapper | 1 |

The independent installer/oracle checks every installed file and original
RECORD, cache ownership/magic/timestamp/source-size headers, the wrapper identity
and deterministic RECORD rewriting. No upstream source, asset or other metadata
is rewritten. See [installation provenance](installation-provenance.json),
[expected inventory](expected-inventory.json) and the
[checked-in golden HTML/tokens](../../../fixtures/python-real-packages/expected-workload.json).

Ordinary stock Python and all three archive providers produce the same exact
129-byte success output. The application checks rendering and complete token
serialization, Unicode URL encoding, front matter/footnote/task-list plugins,
real versions/requirements/dependencies/files, the loaded console callable's
`--version`, package data/type markers and preserved licenses. Archive resource
objects remain virtual and reject filesystem coercion/materialization; physical
metadata lures remain invisible. The fixture hashes through the pinned built-in
`_sha2`, avoiding incidental OpenSSL configuration. Golden SHA-256 assertions
check the complete rendering and token bytes, beyond the success line.

## Product and requirement checks

Mac and GNU each pass three template generations/builds with independent
complete archive/report audits. All three Mac archives equal their GNU counterparts
byte for byte. The Mac projection runs after removing input interpreters; builds
run after removing the entire venv interpreter directory. See
[clean Mac receipt](macos/corpus-capture/receipt.json).

Both builders also pass 32 hostile requirement commands across explicit
site-packages/venv inputs and absent/existing outputs, plus two compatible
builds. Each hostile case lacks provider files and input interpreters. All 16
existing-output sentinels remain unchanged. Compatible variants preserve exact
modified METADATA and normalized RECORD bytes and produce identical archives
through both input modes. Package copies and successful control archives are
removed after auditing. See [GNU controls](requirement-controls/audit.json) and
[Mac controls](macos/requirement-controls/audit.json).

The prior installed-input fixture still passes two input forms and all 30 hostile
build controls. A separate [product audit](product-audit.json) verifies all 27
build/inspect/verify/doctor/cat commands, 5,273 valid ZIP members across six
archives and three exact first-byte entry CRC mutations. Damaged `verify` and
`cat` commands fail with the exact entry diagnostic. Three build process traces
contain only one builder exec and its exit, with no child/interpreter execution.
Compressed product auditing gives the identical report.

## Native execution and closed traces

The three providers succeed; each damaged-entry control exits 1 before runtime
acquisition. All six complete traces pass raw and compressed replay against the
independently pinned corpus, complete archive identity and exact outcomes. See
[capture summary](capture-summary.json). Two complete host-prerequisite
preparation traces and three template-process traces also replay with identical
observations; compressed-input identities are recorded separately from raw hashes.

The isolated workload policy preserves historical archive/readiness, loader,
source/cache, descriptor, process, network and no-extraction predicates. It pins
five failed stdout terminal-width queries from argparse after initialization and
before output. Install-only additionally owns one anonymous RW allocation growth
from 282,624 to 565,248 bytes, separately from its original four startup remaps.
Its exact ownership, sizes, flags, alignment, image/other-owner exclusions and
complete release before terminal queries are checked. These are scoped observed
operations, not open-ended allocation or terminal permissions.

All 229 hostile trace mutations reject: the 126 inherited cases plus 103 corpus,
entry-CRC, terminal and allocation controls. See
[hostile audit](strict-real-package-controls.json). Every historical Python
trace policy/test, trusted importer/metadata helper and C/private runtime/loader
body remains byte-identical to the merged parent; see
[unchanged inputs](unchanged-execution-inputs.json). Metadata admission and the
builder facade intentionally add the new requirement policy.

The pinned offline image is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`:
GNU Linux arm64 kernel `7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, GCC 12.2,
strace 6.1, 4 KiB pages and Rust 1.88.0. Native runtime uid/gid are 65534 on
immutable relocated storage with network disabled and temporary/home paths
inaccessible. Producer, headers and staging inputs are removed before execution.
The payload host trees come from `glue python-host`, then separately audited
metadata lures are added; their original provenance is preserved.

## Validation and replay

Mac/GNU source workspaces pass 484/485 tests for Lua 5.4/5.5 and Clippy. Mac
packaging workspace passes 518; optimized GNU suites pass 150 Python/probe,
53 packaging and 21 CLI tests. Metadata/importer/entry protocols pass 32/16/7.
The corpus oracle passes 21 and the Python policy suite 253 on both interpreters;
12 policy tests cover the new workload boundaries. Format is clean. Pre-commit
Rust checks bind to 264 identical committed inputs in
[GNU](linux-source-workspace/committed-code-binding.json) and
[Mac](macos/validation-binding.json) records. New standalone corpus/policy checks
are attributed separately; no Mac execution of a GNU runtime is claimed.

```sh
evidence=docs/evidence/pbs-linux-arm64-python-real-packages-2026-10-14
python3 scripts/check-linux-python-real-packages-trace.py \
  "$evidence/install-host.trace.txt.gz" --mode install-host \
  --stdout-file "$evidence/install-host.stdout.txt" \
  --stderr-file "$evidence/install-host.stderr.txt" \
  --metadata-file "$evidence/source-metadata.json" \
  --archive-bytes 513404
python3 scripts/test_linux_python_real_packages_trace.py --audit-capture \
  "$evidence" target/real-package-hostile-replay.json
```

With matching exported archives, `product-audit.py` reruns the independent product
checks. `SHA256SUMS` covers every retained file except itself. Large runtime trees,
installed package copies and successful application archives are not duplicated
in Git. This evidence establishes the chosen corpus and cell. Wider package/native
compatibility, runtime/provider/version selection, other platforms and release
gates remain open; G0/G1/G2/G3 are not closed.
