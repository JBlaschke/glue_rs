# Python: an ordinary venv with NumPy

This application solves a small linear system with NumPy's compiled LAPACK code
and parses its version with the pure Python `packaging` package. Its source is
an ordinary folder, `app/`; dependencies live in a separate conventional venv.
Glue packages both, including NumPy's extensions and bundled native libraries.

## Prepare the installed environment

Use an installed, standard (GIL-enabled) CPython 3.14 with pip. A portable
[python-build-standalone](https://github.com/astral-sh/python-build-standalone)
installation is a convenient input; one way to obtain it explicitly is:

```sh
uv python install 3.14.5
PYTHON="$(uv python find 3.14.5)"
```

Alternatively, set `PYTHON` to an existing interpreter's absolute path. Python
3.14.5, NumPy 2.4.3 and packaging 26.0 are the versions used for this example's
macOS arm64 check (the selected NumPy wheel requires macOS 14 or later). The requirements pin those package releases, and installation
requires prebuilt wheels rather than falling back to a source compilation.
Other target/runtime combinations need compatible wheels and their own check.

From the repository root:

```sh
sh examples/python-venv/prepare.sh "$PYTHON"
```

The script creates `target/examples/python-venv-env` with `venv --without-pip`,
uses the base interpreter's pip to install `requirements.txt` into it, then runs
the unbundled application. It downloads packages during this explicit preparation
step. The base pip must support `--python` (pip 22.3 or later). An existing output
environment is refused. Pass a second argument to select another new venv path.

The script uses an ordinary venv without installer packages or executable
`.pth` hooks. Neither package installers nor an activated venv are needed to
run the final distribution. For an existing uv-created environment, see the
[environment inventory guide](../../docs/python-inventory.md) for explicit
pruning of executable hooks.

## Define and bundle the application

First install Glue's tools as described in [the examples overview](../README.md).
All commands below run from the repository root. The checked-in `glue.toml`
declares the source directory, environment, entry point, Python minor version
and bundled compact delivery. Configuration paths are relative to that file:

```sh
mkdir -p target/examples
glue build python examples/python-venv \
  --output target/examples/python-venv
```

The corresponding explicit command defines the application from its source
folder and installed environment without selecting the example's configuration:

```sh
glue build python --project examples/python-venv/app \
  --env target/examples/python-venv-env --python 3.14 --entry main.py \
  --output target/examples/python-venv-explicit
```

Output paths must be new. Choose either build, or use both distinct outputs to
compare them. CLI values override the manifest: use `--env /other/venv` for a
custom environment, `--module main` for a module entry, or
`--runtime /matching/python/root` to supply a compatible base runtime explicitly.
Glue performs runtime/ABI discovery; it does not copy the venv interpreter
symlink as a runtime or install anything from `requirements.txt`.

If native inputs contain absolute or otherwise non-relocatable load paths, the
build reports `native_normalization_required`. Opt in on a fresh output with
`--normalize-native-paths`. On macOS this uses `install_name_tool` and ad-hoc
codesign from the Apple command line tools. On Linux, install patchelf separately
and set `GLUE_PATCHELF` to its absolute path if it is not `/usr/bin/patchelf`.
Supply a reported missing library's directory with `--native-search /path/to/lib`
(for example `/usr/lib/aarch64-linux-gnu` on Debian arm64). Exact requirements
depend on the supplied Python installation and wheel. Only deployed copies are
normalized; input runtimes and packages are unchanged. See
[the native dependency guide](../../docs/native-compact.md).

## Run, inspect and relocate

```sh
target/examples/python-venv/glue doctor \
  target/examples/python-venv/app.glue
target/examples/python-venv/glue run \
  target/examples/python-venv/app.glue -- 'hello from relocated app'
```

Expected application output:

```text
python-venv: numpy + packaging
mean=4.50; solve=[2.00, 3.00]
argument=hello from relocated app
```

With no argument the last line is `argument=world`. Errors remain ordinary
Python errors and a nonzero exit status. Source, package data and metadata live
in `app.glue`; the runtime and native libraries are deployed beside it. Inspect
that split with:

```sh
target/examples/python-venv/glue explain-size \
  target/examples/python-venv/app.glue --json
```

Copy the **whole distribution directory**, preserving modes and internal links,
to a compatible OS/CPU/libc target. This copy to a fresh temporary directory
checks that the working directory and Python PATH are not part of the
application definition:

```sh
RELOCATED="$(mktemp -d "${TMPDIR:-/tmp}/glue-python-example.XXXXXX")"
cp -Rp target/examples/python-venv "$RELOCATED/python app"
BUNDLE="$RELOCATED/python app"
(cd / && PATH= "$BUNDLE/glue" run "$BUNDLE/app.glue" -- 'hello from relocated app')
```

The output is identical. Keep `app.glue`, `runtime/`, `native/` if present,
`support/` and the remaining generated files together. The bundled application
does not require its original venv. `glue.lock.json` records build provenance;
rebuilding from it still needs the original source, environment and runtime.
