# Product Python host-prerequisite fixture

This fixture exercises `glue python-host`, which prepares the exact embedding
prerequisites for the existing stock CPython 3.13.16 / PBS `20261009` full-source
and install-only host metadata providers on GNU Linux arm64. The command belongs
to the portable `python-pack` feature; `python-pbs` also enables it. Unix builders,
including Mac, can prepare the target files without starting a target
interpreter. Permission and mtime publication on non-Unix builders remains
explicitly unsupported. See the
[implementation contract](../../docs/decisions/0024-python-host-prerequisites.md).

For a fresh output directory whose parent already exists:

```sh
cargo build --locked --offline -p glue-runner --features python-pack
mkdir -p target/python-hosts target/python-templates
full_prefix="$PWD/target/python-hosts/full"
install_prefix="$PWD/target/python-hosts/install"
target/debug/glue python-host --provider host-full \
    --pbs-full target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst \
    --output "$full_prefix" --json
target/debug/glue python-host --provider host-install \
    --pbs-install-only target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz \
    --output "$install_prefix" --json
target/debug/glue python-template --provider host-install \
    --host-prefix "$install_prefix" \
    --output target/python-templates/install --json
```

`--output` must be an absolute canonical ASCII prefix satisfying the selected
runtime profile's existing expanded-path and retained-descriptor budgets. The
full and install-only profiles retain distinct budgets. Prefix admission happens
before the artifact is opened. Host templates declare the execution prefix
separately; place the prepared tree at that prefix on the GNU Linux target. The
prepared bytes and provenance contain no builder-specific prefix. The stdout
report records the publication prefix.

Use the generated template with the existing installed-package builder:

```sh
target/debug/glue build-python \
    --provider-template target/python-templates/install/manifest.json \
    --provider-root target/python-templates/install/root \
    --app APPLICATION_DIRECTORY --venv VENV_DIRECTORY \
    --app-id example.application --entry app/main.py \
    --output target/example.glue --json
```

Both providers publish `lib/libpython3.13.so.1.0`, with size 73,563,968 and
SHA-256 `42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219`.
Their stdlib projections differ:

| Provider | Sources | Encoding caches | Selected files | Selected bytes |
| --- | ---: | ---: | ---: | ---: |
| `host-full` | 2,174 | 0 | 2,175 | 112,722,024 |
| `host-install` | 1,037 | 3 | 1,041 | 89,479,393 |

The source inventories are the checked-in
[full pins](../python-imports/stdlib-pins.json) and
[install-only pins](../python-install-host-source-apps/source-pins.json).
The install-only provider retains exactly the three stock encoding caches in
[the cache inventory](../python-install-host-source-apps/cache-pins.json).
The full input also contains those caches, but the full-source provider's
published tree omits them to preserve its existing cache-free startup policy.

Full preparation verifies the 95,632,430-byte compressed artifact with SHA-256
`8907ec2f181f0fc5cd08b9d897d36159432405af78f68f8faca728f48940e0ca`.
Install-only preparation verifies the 57,626,877-byte artifact with SHA-256
`397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34`.
The full reader reuses the existing complete metadata inspector. The selective
install-only reader validates a single gzip stream and the complete tar inventory
and requires full-distribution `PYTHON.json` metadata to be absent. Both readers
verify compressed identity before parsing and again over the bytes consumed.
Selected regular payloads fit the existing 128 MiB selective-reader cap.

The full artifact has 6,574 entries and 5,525 regular files containing 395,119,171
payload bytes. The install-only artifact has 4,526 entries and 3,478 regular files
containing 182,155,939 bytes. The report distinguishes the selected prerequisite
projection from omitted regular files and payload bytes. Directories and links
count toward complete artifact entries, but not omitted regular-file counts.
The projection is an embedding prerequisite tree: it supplies the admitted
library, sources and startup caches. A complete Python installation with an
interpreter executable, headers and arbitrary extension modules remains separate
work.

Every selected file is admitted against its fixed size and SHA-256 before output
creation. Publication creates the prefix exclusively, writes each file with
exclusive creation, then writes `provenance.json` last. Payload and provenance
files receive mode `0444`; directories receive `0555` from leaves to the prefix.
All emitted mtimes are set to the stock epoch `1704067200` (2024-01-01 UTC).
The report's `files`, `file_count` and `payload_bytes` cover selected payloads and
exclude provenance. `directory_count` includes the new prefix and every selected
payload ancestor directory, while excluding the pre-existing parent.
`provenance_file` identifies the actual JSON bytes, including the trailing LF.

Existing output files, directories, symlinks and dangling symlinks reject without
modification. Input and parent trees must stay stable while preparation runs.
Publication I/O failure can leave a partial newly created tree and returns
failure. Publication does not claim atomic directory replacement or remove
unrelated paths. Keep the installed files on immutable backing storage during
execution; read-only permissions alone do not freeze backing files. Runtime
verification still checks the actual declared installation before acquiring
Python. Provenance explicitly makes no runtime-execution, full/install-pairing
or complete-installation claim.

`test_prepare.py` independently checks every emitted path, payload identity,
file mode and mtime, directory mode, report and provenance field using the
checked-in pins. It exercises repeated preparation and rejection controls for
prefix/layout budgets, damaged/trailing/unpinned or nonregular inputs, option
combinations, publication protection and missing/non-directory parents. Large
payload trees are audited in fixture-owned scratch directories and removed;
the retained results contain identities and observations.

```sh
python3 fixtures/python-host-prerequisites/test_prepare.py \
    --glue GLUE --full PINNED_FULL_ARTIFACT --install PINNED_INSTALL_ARTIFACT \
    --output NEW_AUDIT_DIRECTORY --scratch NEW_SCRATCH_DIRECTORY
python3 fixtures/python-host-prerequisites/test_prepare.py \
    --audit-tree PREPARED_PREFIX --provider host-install \
    --report CAPTURED_STDOUT_JSON --output NEW_TREE_AUDIT_JSON
python3 fixtures/python-host-prerequisites/test_prepare.py \
    --audit-process-trace PREPARATION_TRACE --program GLUE
```

The preparation process audit requires one builder execution and rejects child
creation, network activity and acquisition of a target runtime. Native conformance capture for this new product
step is pending. The harness below replaces historical host-installer fixture
calls with product preparation, audits both published prerequisite trees and
preparation traces, and builds the existing genuine installed-package application
through all three product-generated templates. It removes build-only inputs,
then captures the existing six runtime modes with an unprivileged user, no
network and read-only runtime storage. The existing installed-package trace
policy and previous archive identities remain the execution comparison. The
isolated host-prerequisite checker preserves the original policy and changes
only the install-only root enumeration expectation to the exact 191 entries
derived from its source/cache pins. The complete stock tree had two additional
unselected entries, `LICENSE.txt` and `lib-dynload`; full-host enumeration remains
192. Extra or missing entries reject, as do the inherited cache, loader, ownership,
archive, CRC, process and no-extraction violations.

```sh
sh fixtures/python-host-prerequisites/run-linux.sh \
    target/python-host-prerequisites-validation \
    target/python-host-prerequisites-validation-build
```

Fresh evidence must record the clean implementation commit, independent file
and process audits, native captures and their replay. This step prepares the two
current pinned profiles. Subsequent Python work includes ingestion/discovery of
uv-managed installations, candidate-specific runtime/version profiles, real
package compatibility and broader native/platform evidence.
