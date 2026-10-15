# P05: Python 3.14 libffi static trampolines and temporary code

The first hosted native Linux x86_64 run, `38791248353`, exposed a real
no-temporary-file failure in the selected PBS 20261009 CPython 3.14.8 native
corpus. Application output matched its reference, but the extraction oracle
correctly rejected an executable trampoline table written to `/tmp`. This is
not a passing R02 receipt. Keep the failed evidence and the relocated path
containing spaces; neither an anonymous-looking filename nor immediate deletion
makes a filesystem-backed executable temporary file acceptable.

## Observed execution and cause

The selected original runtime executable is 78,156,032 bytes, SHA-256
`499c677181da6cc0aa6d844771b951d9e980ab9e6b7d786bddbc754c223e6aa5`.
The independently downloaded input was
`cpython-3.14.8+20261009-x86_64-unknown-linux-gnu-install_only.tar.gz`, pinned
SHA-256 `83f9cb480b702548c592443f86209cf0fc03448d90692df257f095c01791dccc`.
The observed host was x86_64 Linux `6.17.0-1022-azure`, glibc 2.39.

The retained main trace is
`/private/tmp/glue-native-x86-evidence-38791248353/cases/python-3.14.8-native/trace/syscalls.6413`,
SHA-256 `65f96f2c95cf058289c736bc2683369c9098e01f1791c273a36487fddd5da526`.
Lines 4727–4736 show the sequence:

1. Read `/proc/6413/maps`, whose mapping names include
   `payload with spaces ü/runtime/bin/python3.14`.
2. Try opening the truncated name ending in `/payload`; receive `ENOENT`.
3. Open `/tmp` with `O_RDWR|O_EXCL|O_CLOEXEC|O_TMPFILE`, mode 0700.
4. Write 4,096 bytes, then map that file with `PROT_READ|PROT_EXEC`.

The page consists of one 32-byte x86 trampoline repeated 128 times; its SHA-256
is `b19c0fada10195aac191b8ea7207f35ab662fb2f3e6c69899fb5b3505d450238`.
It is executable code materialization, not an application output or a harmless
lifecycle sentinel. The local decoded context is retained separately at
`/private/tmp/glue-native-x86-evidence-38791248353/python314-tempfile-triage.json`.

The upstream implementation explains every step. CPython 3.14.8's
[`_ctypes_mod_exec`](https://github.com/python/cpython/blob/v3.14.8/Modules/_ctypes/_ctypes.c#L5999-L6011)
allocates and frees a libffi closure during module initialization, to initialize
the allocator before concurrent use. Plain `_ctypes` import is sufficient;
the fixture does not need to create a callback. The change and the difference
between libffi build configurations are discussed in
[CPython issue 135893](https://github.com/python/cpython/issues/135893).

PBS 20261009 pins libffi 3.8.0. In that version,
[`ffi_tramp_get_libffi`](https://github.com/libffi/libffi/blob/v3.8.0/src/tramp.c#L191-L248)
parses the mapped filename with a width-bounded `%s`, which stops at whitespace.
Failure to reopen the truncated filename selects
[`ffi_tramp_get_temp_file`](https://github.com/libffi/libffi/blob/v3.8.0/src/tramp.c#L253-L283),
which writes the existing trampoline table to a temporary file for executable
mapping. The PBS build configures `--disable-shared` and leaves static
trampolines enabled; its only `tramp.c` patch changes header includes.
Current libffi master also retained whitespace-delimited parsing when reviewed;
no compatible released version fix has been verified.

## Exact upstream source identities

The PBS release resolves to commit
`ccc07c40c2731bfb459c119f2388f65a5a470de6`, tree
`4a6a8c81c84a783b1d6231b2410242c0efbd5452`. These SHA-256 values identify the
source bytes read for this diagnosis, not rebuilt application inputs:

| Source | SHA-256 |
| --- | --- |
| [PBS libffi build script](https://raw.githubusercontent.com/astral-sh/python-build-standalone/ccc07c40c2731bfb459c119f2388f65a5a470de6/cpython-unix/build-libffi.sh) | `9706cddc0de6755ca85a1f3d4a611508998600368ab2550428eaa5afc1710575` |
| [PBS download pins](https://raw.githubusercontent.com/astral-sh/python-build-standalone/ccc07c40c2731bfb459c119f2388f65a5a470de6/pythonbuild/downloads.json) | `79f0c8ef6fb96601fa4689d80d42bc081ac0201a6dfb3cb8fd14cf156eeddc27` |
| [CPython 3.14.8 `_ctypes.c`](https://raw.githubusercontent.com/python/cpython/v3.14.8/Modules/_ctypes/_ctypes.c) | `acf89be10917afccd5d15c2ef4237ef53c2b57bbb5b690bb406c077e1559f880` |
| [libffi 3.8.0 `tramp.c`](https://raw.githubusercontent.com/libffi/libffi/v3.8.0/src/tramp.c) | `803ae4e289003cbd38659dad39bf15cfdfc06a18406cf9f8f7d190b703d942d0` |

The PBS build script's Git blob is
`3d0b60ae3025032415bacf7256c972dc857e1459`. Its selected libffi source archive
has SHA-256 `7da3e2d9a171eb0a038f592ecad3ff2bb2550f3496d87b3b29ad0cf4430c0db4`.

## Compatible input candidate and acceptance boundary

Use an independently installed runtime with a libffi configuration that avoids
this static-trampoline fallback, then rerun the unchanged corpus. The
[conda-forge libffi build recipe](https://raw.githubusercontent.com/conda-forge/libffi-feedstock/2bf49f461cd740f7bb3cb3844e4bf95e72a4189f/recipe/build.sh)
explicitly uses `--disable-exec-static-tramp`; its source SHA-256 is
`b2264fe2727669e53c25c6bb933cfe9bd0850615bb67ca7cd8d725bd69e7c86c`.
Public package metadata identifies these existing conventional x86_64 inputs:

| Candidate package | SHA-256 |
| --- | --- |
| [Python 3.14.8 `hcd007b5_102_cp314`](https://api.anaconda.org/download/conda-forge/python/3.14.8/linux-64/python-3.14.8-hcd007b5_102_cp314.conda) | `32a39d6b85fd55d9949ea48d63887bef0dc61dca46d9844d4b409eb993460617` |
| [libffi 3.7.0 `h81df57d_1`](https://api.anaconda.org/download/conda-forge/libffi/3.7.0/linux-64/libffi-3.7.0-h81df57d_1.conda) | `c8c7583ef063bc3c430f1d48298e5ad24f796a35c22ed5b14183325825a61106` |

These two packages alone are not a complete runtime. Python also requires its
matching `libpython` and declared dependency closure. Preserve the independently
installed environment and its provenance; do not graft a different libffi onto
the PBS executable. Replacing the CFFI wheel alone cannot fix PBS's embedded
`_ctypes`/libffi implementation.

The conda-forge candidate is **unexecuted at this decision**. Recipe inspection
does not establish compatibility, successful relocation or no-temporary-file
behavior. Acceptance requires native x86_64 execution with the same source
removal, spaces/non-ASCII relocation, read-only payload, unusable temp/cache,
stock-reference comparison, complete process-tree trace and negative controls.
Any anonymous executable-memory fallback remains subject to the tested host's
memory policy. Record exact installed files and original/output identities.

Do not add a temporary-file exception, suppress denied write attempts, remove
spaces, pre-initialize FFI outside the traced execution, or recompile/patch the
selected runtime or supplied native modules to turn the failed input into a
pass. Keep Python 3.14 source/module/console observations and macOS native
observations separate from this failed x86_64 FFI case. The limitation is this
observed input/configuration; it does not establish that all CPython 3.14 or
CFFI inputs are incompatible. No product support gate is added by this record.
