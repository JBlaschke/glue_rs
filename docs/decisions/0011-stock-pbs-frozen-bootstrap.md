# Stock PBS frozen startup experiment

The GNU Linux arm64 fixture starts the unmodified, pinned CPython 3.13.16 / PBS
`20261009` shared library from one read-only `.glue` archive. It is a separate
`glue-python-bootstrap-probe`, enabled with `pbs-bootstrap`, rather than a
product Python runtime provider. Other platforms and builds reject execution
with status 2 before opening an archive.

Build-time preparation verifies the complete upstream full archive through
`glue-pbs::inspect_full_selected`. The selected library is returned only after
both compressed SHA checks, decompression integrity, complete tar admission and
metadata checks. Selection retains bounded exact regular-file members; aliases
are never followed. Existing inspection still streams and discards payloads.

The matching stock PBS executable compiles six pinned startup sources into
marshal code at build time: `codecs`, `encodings`, `encodings.aliases`,
`encodings.ascii`, `encodings.latin_1` and `encodings.utf_8`. The bundle records
producer, source, bytecode and app identities. This trusted build artifact is
not a bytecode sandbox or a proof that arbitrary bytecode corresponds to source.
The runtime verifies all archive resources and the exact source/runtime profile
before entering C. The manifest's `stdlib` resource is the bounded frozen startup
bundle; it does not claim to contain the full standard library.

C owns the public CPython structures, frozen descriptors, configuration,
references, exception diagnostics and finalization. Rust supplies verified
function/data addresses, byte buffers and lengths through ABI revision 1. No
Python object reaches Rust, and no Rust callback executes under Python frames.
Public `PyImport_FrozenModules` is installed before isolated initialization;
the stock private frozen tables remain intact. Python's public isolated
configuration specifies empty search paths and virtual diagnostic path fields,
ignores Python environment variables and disables site packages and cache writes.
See [CPython's import API](https://docs.python.org/3.13/c-api/import.html) and
[initialization API](https://docs.python.org/3.13/c-api/init_config.html).

The C boundary compiles against the 264 installed headers from the exact verified
stock distribution. Their sizes and hashes are checked and copied into an owned
build directory before compilation. The launcher links no libpython. At runtime,
every bound Python API function and data export must belong to the selected
image, and preloaded Python exports and loader override variables are rejected.

The stock library is 73,563,968 bytes and has ABS64 and TLSDESC relocations outside
the existing native Lua profile. This experiment admits one exact library hash
and delegates its known PIC/TLS image to GNU `ld.so` using `RTLD_NOW|RTLD_LOCAL`.
It leaves the general ELF loader's limits and relocation subset unchanged.
Archive loading uses an explicit executable memfd, with all four seals verified
before the first load. Its descriptor and loader handle remain pinned for the
process lifetime, including error paths. There is no extraction fallback.
The probe alone raises the archive's per-resource limit to 80 MiB for this
73.6 MB image; the product reader's default 64 MiB limit is unchanged.

Only the observed GNU Linux arm64 / 4 KiB cell is claimed. The exact stock image
uses the OS loader and libc, libm, libpthread, librt, libdl, libutil and the GNU
loader; the Rust launcher also uses libgcc_s. External libraries are checked by
loaded-image inventory and full syscall trace. This is a controlled OS profile,
not a general dependency resolver or an upstream minimum-version claim.
Stock mimalloc reads `/proc/sys/vm/overcommit_memory`; the launcher/runtime also
read `/proc/self/maps` and the system loader cache. The controlled cell sets
`TZ=UTC0`: glibc makes one failed lookup for `/usr/share/zoneinfo/UTC0` but reads
no timezone data. CPython makes one failed `readlink` query for the virtual
`/__glue_archive__/launcher`. The checker permits only these exact absent-path
queries and rejects successful or alternative lookups.

The ordinary-loader comparison uses the exact same read-only stock library,
frozen bundle and app. It does not implement the planned host provider paired
with an installed standard library. The archive run must occur after removing
the build-time Python installation and headers, with read-only inputs, an empty
working directory, poisoned Python environment, inaccessible temporary paths
and network disabled. Complete tracing must reject payload filesystem writes,
Python-home fallback, unsealed executable mapping, unexpected processes and
unapproved library reads. Missing startup modules, malformed marshal data and
an application exception exercise the C error boundary separately.

G0/G1 remain open. Python package imports, resources, native extension loading,
host-runtime integration, other architectures/OSes and distribution signing
still require implementation and evidence.
