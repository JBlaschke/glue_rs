# Reviewed bootstrap kit construction

This prepares inputs for a later separately reviewed protected installation and
NONTRACING bootstrap attempt. The checked-in registry is **unconfigured**: no
actual guest proof or frozen runner closure is admitted yet. The default command
fails before compilation or output creation. Unit fixtures cannot enable it.

```sh
python3 -B fixtures/mvp/macos-trace/bootstrap-kit/build_kit.py \
  --guest-proof /private/tmp/actual-reviewed-guest-inspection \
  --inspector-kit /private/tmp/frozen-reviewed-inspector-kit \
  --output /private/tmp/exclusive-new-bootstrap-kit

python3 -B fixtures/mvp/macos-trace/bootstrap-kit/test_build_kit.py -v
```

The only builder arguments are those three paths. Evidence and output paths must
be absolute physical chains without symlinks or `..`. A new output must be outside
the repository, checked by directory device/inode ancestry as well as physical
path traversal; existing outputs are never overwritten or removed. Input trees
have at most 256 files, depth 16, 8 MiB per file, 64 MiB total, and 256 KiB JSON or
manifest files. Manifests list exactly the regular single-link members (no links,
special files, duplicate entries, extra files or empty directories). JSON rejects
duplicate keys, nonfinite values and coercion of integer fields, including bools.

An approved follow-up must configure `reviewed-inputs.json` with the independently
reviewed **actual** proof/inspector manifest identities, its independent audit
manifest, exact guest OS/kernel values and the complete immutable source closure.
This registry is a review workflow guard. It does not authenticate an administrator
or turn self-consistent hashes into execution authorization. It is committed and
verified separately, never included in its own source digest. The frozen closure
must include the builder, the request utility, the probe, all runner translation
units and their headers/helpers. Compile lists contain only locked C sources and
cannot include `catalog_unconfigured.c`. The checkout must be clean and committed;
all locked bytes must match the pinned revision and current working tree.

The proof parser checks all six exact recorded command argv/status pairs, the
wrapper source, actual binary hash check, exact SIP-enabled output, VM model and
arm64 kernel/OS values. It requires a compatible real kernel ID/group vector and
the complete five-component root/Data observation. Source, binary and wrapper
identity are fixed by the admitted inspector manifest. These are retained
observations under that owned inspector's assumptions, not a new kernel attestor.

The digest graph is deliberately acyclic:

* The static source map, normalized fixed recipe/toolchain version/SDK identity
  and admitted proof manifest determine a 64-hex build ID.
* The independently built probe's actual size/SHA plus source/recipe digests and
  observed device/FSID tuples determine canonical `GLUENC01` bytes.
* One generated constant C translation unit supplies both the runner's catalog
  and the request utility's identical canonical bytes. Generated C, catalog hash
  and all resulting executable bytes are excluded from their own input digests.
* The external final inventory records all resulting bytes.

The fixed recipe builds arm64 executables with minimum macOS 26.0 and maps source
paths to one fixed prefix. It preserves the linker's required UUID load command
(an actual ordinary-user refusal control found that macOS 26 dyld rejects
`-no_uuid` binaries before `main`). It ad-hoc signs with a
fixed identifier and no timestamp, then performs strict signature verification.
A bounded Mach-O load-command check requires one `/usr/lib/dyld` loader, one
`/usr/lib/libSystem.B.dylib` dependency and the selected minimum OS. It rejects
unknown load commands, rpaths, weak/reexport/upward/lazy loads and dyld environment
commands. This check supplements codesign; it is not a full Mach-O verifier.
Two fresh builds must produce identical signed probe, runner and utility bytes.
This demonstrates reproducibility for the recorded local toolchain/SDK/recipe,
not arbitrary SDK contents or compiler versions. No resulting executable is run.

Successful output has `kit/{context-probe,bootstrap-runner,make-request}`,
`catalog.bin`, `catalog.generated.c`, `recipe.json`, `source-lock.json`,
`admitted-proof.json`, source snapshots, both build trees, exact command logs,
`result.json` and `SHA256SUMS`. Nothing is installed. Compiler/signing commands have
60-second limits. A failed build keeps its new directory, source/command logs and
failed result when writable. An oversized or otherwise incomplete failed tree may
lack a complete inventory; absence of the final success record is never success.

`make-request` is a separate ordinary-user executable. Its only optional argument
is exact `--simulate-provider-failure`; no argument selects SEND_GO. It rejects
root or differing real/effective IDs and incompatible actual ordered groups,
without normalization. Its compiled catalog fixes the build directory and probe.
It walks the seven directory components read-only, without following links. Every
component must satisfy complete populated filesec scalar equality, ACL absence,
ownership/mode/FD flags and the compiled root/Data mount policy; callback return
zero alone is insufficient. All owned descriptors close once before output, and
identities/groups are reread. The utility hashes its canonical catalog using
CommonCrypto and emits one canonical BR request with fixed limits/policies and
the observed compiled cwd's device/inode. Target argv is derived by the runner
only after hashing that request, so no report/request digest refers to itself.

A failed/short stdout write may expose a prefix and is never replayed. A consumer
requires an exact canonical request and normal utility exit. The utility neither
changes cwd/credentials/signals nor executes a target. Generating a denied-cwd
request requires generating it while that directory is accessible, before a later
separately reviewed attempt changes its permissions. There is no bypass flag.

The C helpers accept caller-supplied unit data with stable, valid, nonalias storage.
Their successful normalization is not native validation. Tests compile pure C
codecs and compare independent Python `struct`/SHA vectors, plus strict parser,
metadata, group, bounds, output and refusal controls. No actual guest-backed kit,
protected installation, successful credential transition, kernel execution proof,
syscall effect classification or full R02/M2 acceptance is claimed here.
