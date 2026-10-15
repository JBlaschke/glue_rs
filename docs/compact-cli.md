# Compact builders and launcher

The high-level builders consume existing projects and installed dependencies.
They never invoke pip, uv, npm, pnpm, LuaRocks or an application compiler.
A selected Python/Node executable is trusted build code: discovery executes a
bounded isolated metadata/capability probe before packaging. The target must
match the build host; inspection APIs can inspect foreign runtime metadata.

Install the glue-owned tools with Rust 1.88.0, its C toolchain and locked Cargo
dependencies:

```sh
scripts/install-glue.sh /absolute/install/prefix
export PATH="/absolute/install/prefix/bin:$PATH"
```

This builds `glue`, `glue-lua54`, `glue-lua55` and `glue-archive.node`. A Lua
application includes only its selected helper. Neither Python headers nor Node
headers/libnode are required for this installation. The interpreter and existing
application native modules remain supplied inputs.

```sh
glue build lua ./lua-project --lua 5.4 --entry main.lua --output dist/lua54
glue build lua ./lua-project --lua 5.5 --entry main.lua --output dist/lua55
glue build python --project ./python-project --env ./python-project/.venv \
  --entry main.py --output dist/python-app
glue build python --project ./python-project --env ./python-project/.venv \
  --module my_app --output dist/python-module
glue build python --env ./python-project/.venv --console-script my-command \
  --output dist/python-command
glue build node ./node-project --node /absolute/node/bin/node \
  --entry dist/main.js --output dist/node-app
```

The output parent must exist and the output directory must be new. Python
accepts exactly one file/module/console entry, a `--python MAJOR.MINOR[.PATCH]`
constraint and a matching `--runtime EXECUTABLE_OR_ROOT_OR_LOCAL_PBS_ARCHIVE`.
A uv-created environment uses the same interface. Environments containing an
executable `_virtualenv.pth` hook reject by default; the tested uv environment
uses explicit `--prune app/site/0/_virtualenv.pth`, recorded as an omission.
Input files remain unchanged. Node accepts a supplied stock
runtime and optional `--node-version` semver constraint. It checks public hook
behavior and Node-API capabilities rather than admitting runtime hashes.

Default delivery is `--delivery compact --runtime-mode bundled`. Python and Node
also accept explicitly selected `--runtime-mode host`, which records an absolute
host executable prerequisite and verifies its identity. Lua uses its bundled
helper. High-level memory builds report `unsupported_mode`; they do not change
delivery mode. Historical schema-zero commands remain separate.

The distribution unit is the entire output directory: `glue`, `app.glue`, selected
runtime, loose native closure/support files, `glue.lock.json`, `build-report.json`
and notices. Copy all of it to a matching target with compatible OS/CPU/libc.
Source and ordinary resources stay archived; native images are stored once in
the deployed tree. Missing files are errors and are never restored by the launcher.

```sh
./dist/python-app/glue inspect ./dist/python-app/app.glue --json
./dist/python-app/glue explain-size ./dist/python-app/app.glue --json
./dist/python-app/glue doctor ./dist/python-app/app.glue --json
./dist/python-app/glue run ./dist/python-app/app.glue -- 'argument with spaces'
glue rebuild dist/python-app/glue.lock.json --output dist/python-rebuilt
```

`inspect` reports the manifest. `explain-size` ranks archived source/resources and
deployed payloads; the build report includes complete archive/file/byte totals.
`doctor` verifies payloads and selected runtime/host requirements without running
application code. `run` verifies payloads and host requirements, then replaces the
launcher with the selected runtime; argv, standard streams, exit status and
signals pass through without a shell. Removing write permission from deployed
payloads is supported. Content, executable/read modes and internal symlink targets
must retain their recorded identity. `rebuild` reuses recorded source cwd/options
and exact runtime identities, requires a new output and permits explicit source
and runtime-location overrides. It needs the original input files; the lock is
provenance, not an installer or a copy of every build input.

Optional `glue.toml` is read from the project, or selected with `--config`.
CLI values override configuration. Paths in configuration are relative to its
parent. Unknown keys/options and duplicate scalar flags are errors. For example:

```toml
entry = "main.lua"
delivery = "compact"
runtime-mode = "bundled"
[lua]
version = "5.5"
```

Python keys are `[python] environment`, `project`, `runtime`, `version`, `module`,
`console-script` and `prune`. Node keys are `[node] executable`, `bridge` and
`version`. Common `native-search` lists explicit dependency roots.
`normalize-native-paths = true` (or `--normalize-native-paths`) opts into metadata
edits when unchanged inputs cannot relocate. The report records original/result
hashes, edits and signing consequences. Linux needs an independently installed
absolute `GLUE_PATCHELF` or `/usr/bin/patchelf`; macOS uses its platform tools.
Normalization is disabled by default. Native Lua inputs also need explicit ABI
declarations when not otherwise known, for example
`--native-abi app/module.so=5.4`. See [native closure details](native-compact.md).

Use `--json` for stable diagnostic codes on stderr. Errors in mode, entry,
configuration, runtime ABI, missing dependencies or escaping paths occur before
publication. Resource bounds remain enforced: defaults include 100,000 deployed
payloads, 1 GiB per input and 8 GiB total deployed payload bytes, together with the
archive's entry, manifest, expansion and per-resource bounds. Library callers can
supply explicit distribution limits; the CLI uses these defaults.

Execution evidence and open platform/release gates are recorded separately in
[the current progress record](progress.md). A portable unit-test pass does not
establish a missing target, no-extraction trace or public macOS signing policy.
