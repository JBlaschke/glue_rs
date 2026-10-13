# Product Python runtime-template fixture

This fixture exercises `glue python-template` followed by `glue build-python`
for the three pinned stock CPython 3.13.16 / PBS `20261009` metadata providers
on GNU Linux arm64. The product command is enabled by `python-pack`; `python-pbs`
also enables it and supplies the admitted Linux execution backend. The
[implementation contract](../../docs/decisions/0023-python-runtime-templates.md)
describes the input and publication boundaries.

Build-time template preparation is portable. For example, a Mac builder can
prepare these Linux inputs without executing a target interpreter:

```sh
cargo build --locked --offline -p glue-runner --features python-pack
mkdir -p target/python-templates
target/debug/glue python-template --provider bundled \
    --pbs-full target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst \
    --frozen-bootstrap docs/evidence/pbs-linux-arm64-host-python-2026-10-10/freeze-bundle.json \
    --output target/python-templates/bundled --json
target/debug/glue python-template --provider host-full \
    --host-prefix '/opt/full Python' \
    --output target/python-templates/host-full --json
target/debug/glue python-template --provider host-install \
    --host-prefix '/opt/install-only Python' \
    --output target/python-templates/host-install --json
```

The bundled choice requires the exact explicit full PBS artifact and the retained
139,523-byte frozen startup bundle, whose SHA-256 is
`6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7`.
It inspects the artifact as bounded data, verifies the complete regular `.py`
projection, and retains libpython and the exact 2,174-source inventory. Startup
bundle parsing and producer/source checks follow its complete identity check.
The two importer helpers come from the compiled-in trusted sources. The command
does not generate new startup bytes or run the stock Python compiler.

The host choices declare the existing full or install-only layout at a canonical
explicit target prefix. They package only the two helpers and placeholder entry.
They do not read that prefix, acquire its library, discover an interpreter or
install an interpreter. Their provenance marks host prerequisites as unverified;
the existing runtime admission checks the declared installation at execution.
A target installation may be absent on the builder.

Each new output contains `manifest.json`, `root/` and `provenance.json`.
`manifest.json` is canonical manifest JSON followed by one LF. `root/` holds
exactly the declared resource bytes. The JSON report contains provider and
provenance facts, the published manifest and provenance file identities,
resource specifications, resource count and total uncompressed bytes. Its nested
provenance equals the parsed `provenance.json`; file identities include the LF.
The provenance's `manifest_sha256` identifies the canonical manifest without LF.

The component is `launch`, with a placeholder at `app/main.py` that raises an
actionable error if run directly. A template is a build input. Supply its manifest
and root to the existing source-only installed-package builder, which replaces
the placeholder application while preserving the provider declaration:

```sh
target/debug/glue build-python \
    --provider-template target/python-templates/bundled/manifest.json \
    --provider-root target/python-templates/bundled/root \
    --app APPLICATION_DIRECTORY --venv VENV_DIRECTORY \
    --app-id example.application --entry app/main.py \
    --output target/example.glue --json
```

Preparation completes declaration, content and budget validation before creating
the output directory. Its parent must already exist. Existing files, directories,
links and dangling links at the output are rejected without modification.
Resource files and provenance are written first; `manifest.json` is published
last. A publication I/O error can leave a partial newly created directory and
returns failure. No atomic directory-publication guarantee is claimed. Input and
output-parent trees must remain stable during the operation.

`test_templates.py` independently compares every emitted resource and profile
against checked-in pins and helper sources, rather than importing the product
constructor. Its generation audit exercises eight valid generations: one initial
and one repeated generation per provider, plus two absent-target declarations.
It requires byte-identical repeated reports and resource inventories. Forty-five
hostile controls cover prefix/layout budgets, malformed or corrupt inputs,
nonregular inputs, existing-output protection, missing or non-directory parents,
and command-line option combinations. With the installed fixture supplied, it
also checks three application builds against the independent installed-package
inventory and verifies placeholder replacement.

```sh
python3 fixtures/python-runtime-templates/test_templates.py \
    --glue GLUE --full PINNED_FULL_ARTIFACT --frozen RETAINED_STARTUP_BUNDLE \
    --prepared INSTALLED_FIXTURE --output NEW_AUDIT_DIRECTORY
python3 fixtures/python-runtime-templates/test_audit.py
```

`test_audit.py` contains thirteen oracle and process-audit regression tests.
The process audit requires one successful builder execution, rejects child
creation and network attempts, and rejects any lookup of the declared target
host prefix or target Python library. The Linux harness records these preparation
traces separately from application execution.

```sh
sh fixtures/python-runtime-templates/run-linux.sh \
    target/python-runtime-templates-validation \
    target/python-runtime-templates-validation-build
```

The harness requires a clean checkout and fresh output paths, the cached pinned
offline Linux image, and the pinned full/install-only PBS artifacts. It prepares
the genuine installed-package fixture using the verified stock producer and
materializes stock full and install-only host installations solely for evidence
setup. Those fixture operations are separate from the product command. It builds
the application through all three generated templates, removes build-only
inputs, and records six complete runtime traces: three successful providers and
three corrupted-metadata failures. Execution runs without network access, with
an unprivileged user and read-only runtime storage. The unchanged six-mode
installed-package trace policy checks those captures.

The [capture report](../../docs/evidence/pbs-linux-arm64-python-runtime-templates-2026-10-13/README.md)
is planned for this increment; capture and retained-result verification are
currently pending. The fixture invocations above describe checks to run, rather
than claiming their results. General runtime/version selection, installation,
native-package support and additional target/provider compatibility remain
separate work.
