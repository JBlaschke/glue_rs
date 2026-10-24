# Basic applications

These examples start with ordinary application inputs, build a compact
distribution, and run it with its included launcher. Start with one row:

| Example | Define the app | Dependencies exercised |
| --- | --- | --- |
| [Lua + C](lua-native/README.md) | A project folder, a LuaRocks-layout tree, and `glue.toml` | `inspect.lua`, a Lua C module, and its shared C library |
| [Python venv](python-venv/README.md) | A source folder, `requirements.txt`, a venv, and `glue.toml` | NumPy native extensions/BLAS and the pure Python `packaging` package |
| [Node + npm](node-npm/README.md) | `package.json`, `package-lock.json`, installed `node_modules`, and `glue.toml` | An ESM app importing the CommonJS `ms` package and reading JSON data |

The per-example guides include dependency preparation, the Glue build, expected
output, and relocation. Preparation may download packages
or compile the Lua C library; `glue build` consumes those prepared inputs. Run the
commands from the directory stated in each guide.

## Install Glue once

From the repository root, with Rust 1.88.0 through Rustup and a C toolchain:

```sh
scripts/install-glue.sh "$PWD/target/example-tools"
export PATH="$PWD/target/example-tools/bin:$PATH"
mkdir -p target/examples
```

The installer supplies `glue`, both Lua helpers, and the Node archive bridge.
Python and Node examples also need a compatible runtime supplied by you. Build
on the OS/architecture where the distribution will run. See the individual guides
for runtime selection and native-library prerequisites.

## Folder, environment, and manifest inputs

`glue.toml` is the optional build configuration used by these examples. CLI values
override it; configuration paths are relative to the configuration file. Python
selects installed packages from the venv; Node selects the already-installed npm
project; Lua can add an already-prepared LuaRocks tree to its source folder.
Language manifests describe or help prepare those inputs; Glue does not resolve
or install their dependencies.

`app.glue` contains the generated distribution manifest and archived sources.
`glue.lock.json` records build inputs/options for `glue rebuild`; rebuilding still
needs the original inputs. The older `glue build --manifest ...` interface in
historical fixtures uses a different schema and is not required here.

The Node example uses npm. Glue currently launches Node, and does not consume a
Deno runtime or a Deno-only `deno.json` project. See its guide for that boundary.

## Inspect, run, and relocate

After building any example, set `app` to its output directory:

```sh
app="$PWD/target/examples/node-npm"  # or the Lua/Python output from its guide
"$app/glue" inspect "$app/app.glue" --json
"$app/glue" explain-size "$app/app.glue" --json
"$app/glue" doctor "$app/app.glue" --json
"$app/glue" run "$app/app.glue" -- 'hello from the command line'
```

Deploy the **whole directory**, including its launcher, archive, runtime, and
native libraries. A compatible destination needs no original venv, `node_modules`,
LuaRocks tree, compiler, or package manager to run these bundled examples.

For a repeatable local smoke check, from the repository root:

```sh
python3 examples/verify.py lua target/examples/lua-native
python3 examples/verify.py python target/examples/python-venv
python3 examples/verify.py node target/examples/node-npm
```

The checker runs `doctor`, copies the complete distribution to a temporary path
containing spaces, runs from a different directory with an isolated home and a
minimal environment, and checks the example's calculation and quoted argument.
It removes only its own temporary copy. It does not hide the original inputs or
enforce network isolation; it is a relocation smoke check, not the project's
no-extraction acceptance suite.

These are development-preview examples. Supported inputs and current constraints
are in the [CLI guide](../docs/compact-cli.md), [native dependency guide](../docs/native-compact.md),
and [MVP acceptance record](../docs/plans/mvp-implementation.md). The examples do
not close the outstanding macOS tracing, performance, or release-signing gates.

The three examples and the relocation checker passed on macOS arm64 on
22 October 2026 with Lua 5.4.9, CPython 3.14.5 (NumPy 2.4.3 and packaging 26.0),
and standalone Node 24.19.0 (`ms` 2.1.3). The GNU Linux recipes are included but
have not been executed for these new examples.
