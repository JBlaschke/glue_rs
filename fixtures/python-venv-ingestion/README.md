# Offline installed-package input fixture

This fixture exercises `glue build-python` with a real conventional Python 3.13
venv containing a tiny pure-Python distribution. Runtime execution reuses the
metadata application and all three previously admitted Python providers.

`prepare.py wheel` reproduces the checked-in 2,674-byte
`glue_meta_demo-1.2.3-py3-none-any.whl` from the existing metadata source fixture.
It adds purelib WHEEL metadata and a `glue-meta-demo` console entry while
preserving the archive plugin. ZIP order, timestamps, attributes and compression
are fixed; `wheel-provenance.json` records every source and generated identity.
The application entry stays byte-identical to the existing metadata fixture.

```sh
python3 fixtures/python-venv-ingestion/prepare.py wheel \
    fixtures/python-venv-ingestion/glue_meta_demo-1.2.3-py3-none-any.whl --verify
python3 fixtures/python-venv-ingestion/test_prepare.py
```

The installation helper must run with the verified stock Linux Python 3.13
producer. It creates a venv using `--without-pip`, then uses the producer's pip
26.2.1 with `--python`, `--no-index`, `--find-links`, `--no-deps` and
`--no-cache-dir`. Installation selects the package by name/version, preserving
the same source bytes without creating path-dependent `direct_url.json`.
Neither installation command imports or invokes the fixture's plugin or console
entry. Ordinary pip compilation generates two bytecode files; installation also
generates a console wrapper. All thirteen installed RECORD rows are retained in
installation provenance, including those three omitted runtime inputs.

```sh
PRODUCER/bin/python3.13 -I -S -B fixtures/python-venv-ingestion/prepare.py \
    install PRODUCER OUTPUT
```

The helper writes `OUTPUT/venv`, `OUTPUT/application`,
`OUTPUT/installation-provenance.json`, command logs and an independently
constructed `OUTPUT/expected-input`. The latter must equal checked-in
`expected-input` and `expected-inventory.json`: ten retained distribution files
and one application entry. Expected RECORD is sorted, LF-terminated CSV with
fresh SHA-256/size values and an empty self-entry. Runtime stdout reports ten
distribution files. No console wrapper or bytecode enters the archive.

`test_build.py` independently checks a valid venv build and an explicit
site-packages build. It verifies archive bytes against `expected-input` and
requires identical archive identities. Thirty mutated installed-input controls
cover native files, `.pth`, editable/egg metadata, traversal/absolute/unknown
wrapper paths, missing and corrupt inputs, duplicate rows before omission,
shared ownership, unrecorded files, file/directory symlinks, venv configuration,
wheel declarations, app collisions, metadata/application bounds and existing
output protection. Each control saves its command, stdout, stderr and status.

```sh
python3 fixtures/python-venv-ingestion/test_build.py \
    --glue GLUE --template METADATA_MANIFEST --provider-root PROVIDER_ROOT \
    --prepared OUTPUT --output AUDIT_DIRECTORY
```

The real pip installation is build-time evidence preparation. The product
normalizer executes no input interpreter, installer, activation hook or package
code. General wheel installation, dependency solving, native dependencies and
additional target/provider cells remain outside this fixture.
