# Node application from an npm project

This is a normal ESM application with `package.json`, an npm lockfile, and an
installed `node_modules` tree. It imports the small CommonJS package
`ms` to parse and format durations and
reads `data/tasks.json` relative to its own module. The packaged application uses
the same source and dependencies, including the JSON resource.

Follow the [shared prerequisites](../README.md) first. The `glue` executable and
its adjacent `glue-archive.node` bridge must be installed. These commands start
at the repository root and then stay in this example directory.

## Prepare and run normally

```sh
cd examples/node-npm
npm ci --ignore-scripts --no-audit --no-fund
npm start -- 'hello from relocated app'
```

The app prints the following, after npm's own script banner:

```text
tasks=3
total=35 minutes
milliseconds=2100000
argument=hello from relocated app
```

The dependency is pinned to `ms@2.1.3`; `package-lock.json` records the registry
artifact's integrity. This package needs no install scripts or compilation.
Installing dependencies is a separate preparation step: glue consumes the
existing files and never invokes npm or package scripts. There is no separate
JavaScript compilation step in this example. For TypeScript or another build
system, generate Node-compatible JavaScript before invoking glue and point
`entry` at that generated file.

## Define and build the app

`package.json` declares the dependency, ESM format, and normal `main` entry.
`glue.toml` makes the packaging choices explicit: `src/main.js`, compact delivery,
and a bundled Node runtime. The selected runtime path stays outside the checked-in
manifest so it can vary by machine.

Select a real Node executable for the current OS and CPU. The manifest requires
Node 24 or later, and glue separately probes the runtime capabilities it needs;
a version number alone does not establish support. A stock Node distribution is
a simpler starting point than a system package with many shared-library links.

```sh
export GLUE_NODE="$(command -v node)"
# Or: export GLUE_NODE=/absolute/path/to/your/node/bin/node
npm run build
```

The npm `build` script creates the output parent and runs the equivalent of:

```sh
mkdir -p ../../target/examples
glue build node . --node "$GLUE_NODE" \
  --output ../../target/examples/node-npm
```

This automatically reads `glue.toml` from the project folder. The output directory
must be new; move an earlier build aside or select another output with the direct
CLI command. To choose the manifest explicitly, use a fresh output:

```sh
glue build node . --config glue.toml --node "$GLUE_NODE" \
  --entry src/main.js --output ../../target/examples/node-npm-explicit
```

The CLI entry overrides the manifest entry. You may instead set
`[node] executable = "/absolute/path/to/node"` in a local manifest and omit
`--node` when using the direct CLI. The default npm script uses `GLUE_NODE`, or
`node` from `PATH` when the variable is unset.

If the runtime's native dependencies cannot relocate unchanged (for example,
some Homebrew builds), retry the build with explicit normalization:

```sh
npm run build -- --normalize-native-paths
```

Use a new output or move a previous successful build before retrying. Linux
normalization requires an independently installed `patchelf`, selected with the
absolute `GLUE_PATCHELF` environment variable or available at `/usr/bin/patchelf`.
Some installations also need explicit `--native-search /absolute/library/root`
arguments. See [native closure details](../../docs/native-compact.md); edits and
signing consequences are recorded in the build report.

## Inspect, run, and relocate

```sh
../../target/examples/node-npm/glue doctor \
  ../../target/examples/node-npm/app.glue --json
../../target/examples/node-npm/glue inspect \
  ../../target/examples/node-npm/app.glue --json
../../target/examples/node-npm/glue run \
  ../../target/examples/node-npm/app.glue -- 'hello from relocated app'
```

The application output matches `expected.txt`. The launcher preserves the quoted
argument as one argument. Copy the **whole output directory**, including its
runtime and support files, to a matching target; `app.glue` alone is insufficient.
For a local relocation check from an unrelated working directory:

```sh
relocated=$(mktemp -d)
cp -R ../../target/examples/node-npm "$relocated/node app"
(
  cd "$relocated"
  env -i PATH=/usr/bin:/bin "./node app/glue" run \
    "./node app/app.glue" -- 'hello from relocated app'
)
```

Neither npm nor an installed Node on `PATH` is needed to run this bundled output.
The app's JSON and npm dependency are read from the archive. The runtime still
requires the compatible OS/CPU and system libraries recorded by `doctor`.
The [shared smoke check](../README.md) also checks output after relocation.

## Deno scope

This recipe uses npm's `package.json` workflow and packages a **Node** runtime.
The current glue CLI has no Deno provider. It does not interpret `deno.json` or
`deno.lock`, resolve JSR/URL imports, consume Deno's package cache, or provide
Deno-specific APIs. A Deno
project would first need a separately prepared and tested Node-compatible project
with JavaScript entrypoints, `package.json`, and installed `node_modules`.
That conversion is outside this example; `deno compile` is not a glue build.

See the [Node provider notes](../../crates/glue-runtime-node/README.md) for the
supported module and resource APIs and current platform limitations.
