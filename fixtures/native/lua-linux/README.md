# Controlled native Lua fixture on GNU Linux

From the repository root, run either profile with the existing pinned local
`localhost/glue-linux-probe:rust-1.88.0` image:

```sh
sh scripts/run-linux-native-lua.sh lua54
sh scripts/run-linux-native-lua.sh lua55
python3 -m unittest discover -s scripts -p 'test_linux_*.py'
```

The harness vendors cached dependencies offline and uses Rust 1.88.0. It runs
full workspace tests and Clippy for the selected source profile, then repeats
both with the opt-in `linux-native` feature and builds the native launcher. It
neither pulls an image nor installs packages. Its two native profile identities
are:

- `glue-lua54-native-linux-v1/c-boundary-1/lua-src-551.0.2/int64-float64`
- `glue-lua55-native-linux-v1/c-boundary-1/lua-src-551.0.2/int64-float64`

The source-only Lua 5.4/5.5 v2 profiles and their existing harness remain
unchanged. These native fixtures target GNU Linux AArch64, glibc 2.36, 4 KiB
pages and a kernel with explicit executable memfds (`MFD_EXEC`, Linux 6.3).
Those floors are declared prerequisites, not a compatibility test of every
kernel or libc release at or above them.

`module.c` compiles against pinned Lua 5.4.9 or 5.5.1 headers without `-llua`.
It imports ten reviewed APIs supplied by the selected launcher, the archived
`libglue_lua_dep.so`, and `getpid` from `libc.so.6`. The dependency returns 35;
the module adds its exported data value 7. The Lua script observes answer 42,
one constructor, the selected Lua state's global seed changing from 123 to 124,
a real process ID, require caching, a caught native function error, and a
caught initializer error followed by a successful retry. The product run also
checks canonical `package.loadlib` keys and exact initializer names. No host
library path or `*` shortcut is accepted there.

Both images use explicit SONAMEs, SysV symbol hashes, immediate binding and a
non-executable stack, with no RPATH/RUNPATH. All declared images and their
dependency closure are verified before constructors. Both anonymous executable
memfds are populated and their four seals verified before either image is
loaded with `RTLD_NOW | RTLD_LOCAL`. Handles and descriptors are retained for
process lifetime. Local scope is ordinary glibc scope, not an isolated linker
namespace.

Six separate traced product runs check wrong architecture, a mismatched SONAME,
an executable stack, an undeclared dependency, an undeclared import from a
constructor, and a wrong initializer. Each must read only its archive and OS
startup files, emit its exact rejection diagnostic and status, and create no
memfd. Their archives, ELF metadata, hashes and complete traces are retained
under each run's `native-rejections` directory.

`baseline.c` runs the same fixture script through ordinary disk `dlopen`, linked
to the exact static Lua core and headers produced by the selected Cargo build.
It uses the same reviewed export list and registers the initializer in
`package.preload`; the script accounts for the resulting `:preload:` origin.
The baseline reads its build-time source/asset files directly. It is a separate
C comparison program, not a product host-file loading mode. Its output matches
the archive run after replacing their different process IDs. The harness
checks the exact dynamic Lua export set of both executables and rejects a
`DT_NEEDED` dependency on a separate `liblua`.

After the baseline and packaging, the harness removes all compiler-produced
input files, relocates the archive into a directory containing spaces, and
makes it read-only. The product run uses a container with no network and a
read-only root filesystem. Its complete `strace` log and artifacts are retained
under `target/evidence/linux-native-lua/run-*` together with source/input/archive
hashes, build provenance, feature tree, stdout/stderr and exit statuses.

The checker permits only observed OS startup/archive reads, private mappings,
the two named sealed memfds and exact stdout with a PID matching the trace.
Failed filesystem mutation attempts, unknown syscalls, incomplete records,
extra processes/threads, shared mappings, host source/library fallback and early
payload loading fail the check. This is a narrow evidence policy, not a runtime
sandbox. Unwind, TLS, arbitrary constructors/reentry, multiple native closures,
other architectures/OSes, host runtimes and broad addon compatibility remain
unproven. Trace inputs are capped at 32 MiB, 100,000 records and 8192 characters
per record before policy evaluation.
