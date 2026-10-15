# Compact Python native inputs (P04)

The environment inventory hands native images to the shared ELF/Mach-O closure
collector. Their paths remain relative to the project or installed site root;
source, data and metadata remain in `app.glue`. Native image bytes are not duplicated
in the archive. The importer selects stock `ExtensionFileLoader` with a real,
manifest-declared image path, preserving CPython's module creation, execution,
errors, cache and reload behavior. It supplies no `PyInit` lifecycle emulation.

Extension suffixes, WHEEL Python/ABI tags and Requires-Python are checked before
publication. The native collector checks the actual target, dependency closure and
OS requirements. Explicit libpython linkage must use the interpreter's shared
core: adding a shared core to a statically linked interpreter is rejected with
`runtime_abi_mismatch`. This avoids admitting independently linked runtime state.
The packager never compiles, installs or substitutes a supplied extension.

`importlib.resources.files(package)` exposes an existing declared native image as
a physical path (`os.fspath`). `as_file` can yield that already deployed image;
archived source/data resources still reject extraction. Ordinary `ctypes.CDLL`
paths work, and `glue:///` paths formed from an archived package's `__file__` are
mapped only when the native index declares them. The tested CFFI route is
`ffi.dlopen(os.fspath(importlib.resources.files(package).joinpath(name)))`.

The ignored `python_native` integration test consumes independent prebuilt site
trees through `GLUE_TEST_NATIVE_SITES`, `GLUE_TEST_PYTHON` and
`GLUE_TEST_NATIVE_SECONDARY`. It compares operations under the stock interpreter,
then removes the copied input environment/project and runs relocated output with
empty PATH, arbitrary cwd and unusable HOME/TMPDIR. It hashes native inputs before
and after packaging and tests incompatible extension suffix/WHEEL diagnostics.
`GLUE_TEST_RECEIPT` writes supplemental execution evidence. These focused receipts
are not complete V02/R02 process-tree or public-signing evidence.

Executed native cells: macOS arm64 CPython 3.14.5 with NumPy 2.5.3, contourpy 1.4.0,
pydantic_core 2.41.5 and CFFI 2.1.1; Linux arm64 CPython 3.13.16 with NumPy 2.5.4,
contourpy 1.4.0, pydantic_core 2.50.1 and CFFI 2.1.1. Operations include BLAS/LAPACK,
translated C++ exceptions, Rust validation errors, repeated imports and four
threads. Both use the independently prepared secondary C/TLS/pthreads library
shared with the Lua corpus; all original native bytes remain unchanged. Linux
runs in a native arm64 container with `--network none`, explicit patchelf
normalization and the declared system library search root. macOS uses the
unchanged-byte dependency route.

Linux 3.13 also runs independently supplied CPython `_testmultiphase` images from
the cached manylinux runtime under their existing exported create/exec-error
names. Reference and packaged runs match on failed initialization, sys.modules
cleanup, repeated errors, normal import caching and reload. These inputs are
copied unchanged; neither test preparation nor packaging rebuilds them.

`fixtures/mvp/python-native/provision.py --fetch` is explicit test provisioning
only: it downloads exact requested upstream wheels, verifies upstream SHA-256 and
size, safely unpacks existing bytes and records `inputs.json`. It is never called
by a product build. The fixture app deliberately avoids package-specific product
configuration, and the same code runs with different compatible native versions.

Native Linux x86_64 execution, complete descendant tracing on macOS and public
signing/notarization remain external evidence gaps. Unsupported executable `.pth`
hooks, editable installs and ctypes/CFFI paths outside declared images continue
to require explicit input changes; no import failure triggers a package install.
