# Lua package + native C dependency

A small temperature report imports the real third-party
[`inspect.lua` 3.1.3 package](https://github.com/kikito/inspect.lua/tree/v3.1.3)
and a Lua C module, `temperature`. That module calls a separate shared C library,
`libtemperature`, to convert Celsius to Fahrenheit. The C library and wrapper
are example code; inspect.lua is unmodified upstream code with its MIT notice.

`main.lua` is the application. `glue.toml` defines its entry, Lua version, installed
dependency tree and C-module ABI. `prepare.sh` supplies an ordinary LuaRocks-style
tree in `.deps/rocks`: Lua source under `share/lua/5.4`, native modules and their
libraries under `lib/lua/5.4`. This demonstrates both a project folder and an
already prepared dependency environment. No resource inventory is handwritten.

## Prepare the inputs

Start in the repository root after installing glue and its helpers as described
in [the examples guide](../README.md). You need a C compiler and the **unmodified
Lua 5.4.9 headers** matching the current `glue-lua54` helper. No installed Lua
interpreter or Lua shared library is needed. On macOS the script uses the
Xcode command line compiler and ad-hoc `codesign`; on GNU Linux use GCC or Clang.

The helper installation downloads `lua-src` through Cargo. Its source tree
includes the exact headers; locate and select them explicitly:

```sh
find "${CARGO_HOME:-$HOME/.cargo}/registry/src" \
  -path '*/lua-src-551.0.2/lua-5.4.9/lua.h' -print
export LUA_HEADERS=/absolute/path/to/lua-src-551.0.2/lua-5.4.9
./examples/lua-native/prepare.sh "$LUA_HEADERS"
```

Alternatively pass an unmodified official Lua 5.4.9 source directory containing
`lua.h`, `lauxlib.h` and `luaconf.h`. The selected helper's version can be inspected
with `glue-lua54 --describe`. LuaJIT, Lua 5.1–5.3, Lua 5.5 and customized
integer/number ABIs do not match this example. The wrapper checks Lua 5.4 headers
and 64-bit numeric sizes at compile time, then checks the runtime ABI at load.
Do not link the module against another `liblua`; the bundled helper exports its
Lua API. Switching to Lua 5.5 requires recompiling with matching 5.5 headers and
changing the configuration and installed tree together.

Preparation copies the vendored pure Lua package and compiles the two native
images before packaging. It requires no network and refuses to replace an
existing `.deps` tree. Select `CC=/absolute/compiler` if needed. The vendored
package's [source identity and license](vendor/inspect-3.1.3/README.md) are retained.

## Define and build

From the repository root, the folder form reads `glue.toml` automatically:

```sh
mkdir -p target/examples
glue build lua examples/lua-native --output target/examples/lua-native
```

Select the manifest explicitly to make the same app definition visible on the
command line. Use a fresh output directory for each build:

```sh
glue build lua examples/lua-native \
  --config examples/lua-native/glue.toml --output target/examples/lua-native-config
```

Configuration paths are relative to `glue.toml`; `rocks-tree = ".deps/rocks"`
therefore finds this example's prepared dependencies from either working
directory. The declaration `"app/temperature.so" = "5.4"` supplies ABI metadata
that cannot be inferred from the C image. The builder follows its link to
`libtemperature`, so the secondary library is included automatically. Both
libraries already use relative loader paths; no native normalization is needed.

For another existing LuaRocks installation, point `--rocks-tree` at that tree;
glue consumes its installed files without invoking LuaRocks. Install for Lua 5.4
and supply explicit ABI declarations for any additional native modules. Dependencies
remain your prepared inputs; glue does not install or compile them.

## Run and relocate

```sh
./target/examples/lua-native/glue doctor ./target/examples/lua-native/app.glue --json
./target/examples/lua-native/glue run ./target/examples/lua-native/app.glue
./target/examples/lua-native/glue run ./target/examples/lua-native/app.glue -- 'hello from Lua'
```

The default output is:

```text
samples_c={ 18, 20, 22 }
mean_c=20.00 mean_f=68.00
argument=friend
```

The argument example changes the last line to `argument=hello from Lua`.
To run from another directory, copy the **entire** distribution, then change the
working directory. The temporary destination below is new on every invocation:

```sh
relocated=$(mktemp -d "${TMPDIR:-/tmp}/glue-lua-example.XXXXXX")
cp -R target/examples/lua-native "$relocated/app"
(cd / && "$relocated/app/glue" run "$relocated/app/app.glue")
```

The distribution contains its launcher, Lua helper, source archive and native
libraries. A target needs the same OS/architecture and compatible system
libraries; it does not need this source checkout, LuaRocks, Lua headers or a C
compiler. macOS signatures here are for local development, not notarized releases.

Inspect the generated manifest and recorded inputs with:

```sh
glue inspect target/examples/lua-native/app.glue --json
glue explain-size target/examples/lua-native/app.glue --json
glue rebuild target/examples/lua-native/glue.lock.json --output target/examples/lua-native-rebuilt
```

A rebuild still needs this project and `.deps`. The lock records exact inputs;
it does not reinstall them.
