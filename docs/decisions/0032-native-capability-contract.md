# Native capability contract for ELF Python wheels (A5)

Proposed contract, 15 October 2026, prepared by Claude (Fable 5.1) at the
request of the repository owner. The [status review](../reviews/2026-10-15-status-review.md)
found native support fixture-shaped and `PLAN.md` section 8 requires the
required-versus-optional native feature set to be frozen against a
representative package corpus before general wheel admission. This record
supplies that measurement for the project's cell, CPython 3.13 on GNU Linux
aarch64, and proposes the frozen release profile. It changes no code: the
inspector in `crates/glue-native/src/elf.rs` and the Python native profiles are
unchanged at this commit. It becomes the contract when the owner accepts it;
until then decisions [0015](0015-python-registered-extensions.md) and
[0029](0029-python-native-package-imports.md) stand.

## Corpus and method

Four unmodified upstream wheels, pinned by exact file name, URL, size and
SHA-256 in [`fixtures/native/corpus/wheel-pins.json`](../../fixtures/native/corpus/wheel-pins.json):

| Wheel | Role | Images | Bytes |
| --- | --- | --- | --- |
| markupsafe 3.0.4, `cp313-cp313-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64` | small C extension | 1 | 230,848 |
| numpy 2.5.4, `cp313-cp313-manylinux_2_27_aarch64.manylinux_2_28_aarch64` | dependency-heavy C/C++/Fortran package; bundles OpenBLAS and libgfortran | 21 | 41,472,933 |
| pydantic-core 2.50.1, `cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64` | Rust-built extension (PyO3) | 1 | 4,417,792 |
| cryptography 50.0.2, `cp311-abi3-manylinux_2_34_aarch64` | Rust-built stable-ABI extension with OpenSSL linked in | 1 | 13,652,416 |

The selection is the latest stable release on 15 October 2026 and, where a
release publishes several manylinux levels, the wheel pip selects for the
Debian bookworm (glibc 2.36) test cell. Every shared object was read
statically by [`fixtures/native/corpus/survey.py`](../../fixtures/native/corpus/README.md),
a section-independent ELF64 reader that consults the same program headers and
dynamic table as the inspector. Its NEEDED, SONAME, segment, relocation-type,
symbol-count and version-need facts were cross-checked against llvm-readelf
23.1.2 with zero disagreements. Every `Py*`/`_Py*` import was checked against
the export table of the selected stock PBS `libpython3.13.so.1.0` (SHA-256
`42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219`, 1,758
exports). The project inspector was run on every image through the
`elf-survey` example, once as a closed fixture profile calls it and once with
the image's own SONAME and every undefined symbol declared; both calls stop at
the same structural rejection for all 24 images. Nothing was mapped, loaded or
executed. The committed `survey.json` and `summary.md` hold every number
below.

## What the corpus requires from the loader

On GNU Linux the OS loader performs mapping, relocation, TLS setup and
constructor execution for images that glue opens from sealed memfds. "Support"
therefore means that glue admits the feature at inspection, keeps it bounded
and well-formed, resolves every dependency edge itself, and proves the
behavior with fixtures and real-package tests. "Reject" means the image is
refused at inspection, before any memfd, mapping, constructor or Python
initialization.

| Loader feature | Images (of 24) | Observed | Proposal |
| --- | --- | --- | --- |
| DT_GNU_HASH without DT_HASH | 24 | every image; the inspector requires SysV DT_HASH and rejects the GNU_HASH tag | required: size the symbol table from the GNU hash chains |
| No DT_SONAME | 22 | every extension module; SONAME present only on the two bundled libraries | required: extension identity comes from the manifest resource and content hash, SONAME is required only for dependency images |
| Nonzero `e_entry` in ET_DYN | 2 | libgfortran, pydantic-core | required: ignore, as `ld.so` does for `dlopen` |
| No BIND_NOW flag | 21 | only cryptography, libgfortran and pydantic-core request immediate binding | required: immediate binding is a property of glue's `RTLD_NOW` call, not of the image |
| Runtime symbols through the global lookup scope | 22 | every extension module imports `Py*` symbols, 444 distinct, with no NEEDED provider; two numpy modules have no NEEDED entry at all | required: the selected runtime image enters the global scope before the first extension load (see below) |
| Private-prefix `_Py*` imports | 21 | 30 distinct symbols; every one, and every other Python import, is exported by the pinned runtime | required: resolvability against the runtime export table replaces reviewed name lists |
| Strong unversioned import through the global scope | 1 | `dladdr` in numpy core | required: must resolve to a declared OS library in the global scope |
| Weak undefined imports beyond the compiler hooks | 24 | `__cxa_finalize` everywhere; `getrandom`, `gettid`, `statx`, `getentropy`, `getauxval`, `__cxa_thread_atexit_impl`, gthread `pthread_*` probes, `omp_in_parallel` | required: weak imports may bind to a declared provider or stay null; the three compiler hooks remain the only undeclared imports |
| OBJECT (data) imports | 6 | `stderr`, `stdout`, `stdin`, `__stack_chk_guard`, C++ `typeinfo` and vtables from libstdc++ | required: GLOB_DAT data imports against declared providers; COPY relocations stay rejected |
| OS libraries from the manylinux policy | 21 | `libc`, `libm`, `libpthread`, `libdl`, `libgcc_s` (8), `libstdc++` (2), `libz` (libgfortran), `ld-linux-aarch64` | required: an explicit per-target allowlist with version floors verified on the host before any mapping |
| Symbol version needs | 21 | GLIBC_2.17 to GLIBC_2.34; GCC_3.0 to GCC_4.5.0; GLIBCXX_3.4 to 3.4.21; CXXABI_1.3 to 1.3.9; GFORTRAN_8 | required: already admitted; host floors are the manylinux level of the wheel |
| Bundled dependency libraries with DT_VERDEF | 1 | libgfortran defines GFORTRAN_8, GFORTRAN_F2C_8 and GFORTRAN_C99_8; OpenBLAS needs GFORTRAN_8 from it | required: version definitions in dependency images and versioned edges between archived images |
| NEEDED edges to bundled libraries | 4 | OpenBLAS → libgfortran; numpy core, `_umath_linalg`, `lapack_lite` → OpenBLAS, 6 to 35 unversioned imports each | required: dependency-first loading with SONAME identity, as today |
| DT_RPATH with `$ORIGIN` | 4 | `$ORIGIN` on OpenBLAS, `$ORIGIN/../../numpy.libs` on three modules; auditwheel writes RPATH, not RUNPATH | required to admit, never honored: every NEEDED must already be loaded by SONAME so no search runs; non-`$ORIGIN` entries reject |
| R_AARCH64_ABS64 with addends | 13 | 11,751 in total, 11,546 of them in OpenBLAS function tables | required: `S + A` against declared providers or the image itself |
| TLSDESC relocations and PT_TLS | 4 | cryptography and pydantic-core (112-byte templates), OpenBLAS (61,448), numpy core (46,240, one STT_TLS symbol); 31 TLSDESC relocations, DT_TLSDESC_PLT/GOT on the GNU ld images | required: dynamic TLS under `dlopen`, proven on existing, new and library-created threads |
| Thread creation and thread-exit destructors | 2 / 1 | `pthread_create` in cryptography and OpenBLAS; `__cxa_thread_atexit_impl` in cryptography | required: TLS and destructor fixtures on library-created threads |
| STB_GNU_UNIQUE | 2 | 16 highway template statics in numpy core, 1 in pocketfft | required: admit; uniqueness is resolved by `ld.so` across the global scope |
| STV_PROTECTED | 1 | 10,355 of OpenBLAS's 14,177 exports | required: admit; protected definitions bind within the image |
| Absolute symbols | 1 | version base names in libgfortran | required: admit SHN_ABS for version names only |
| Constructors and destructors | 24 | DT_INIT and DT_FINI everywhere; up to 5 `init_array` and 3 `fini_array` entries | required: already admitted; constructors run inside `dlopen` after full closure verification, images stay pinned so destructors run only at exit |
| Unwinding through archived code | 5 | C++ `throw`/`catch` and `__gxx_personality_v0` in numpy core and pocketfft; `_Unwind_*` in cryptography, pydantic-core and libgfortran | required: unwind registration through `PT_GNU_EH_FRAME` and `dl_iterate_phdr`, with no exception crossing the C boundary |
| Loader introspection | 4 | `dl_iterate_phdr` (3), `dladdr` (2) | required: these report the `/proc/self/fd/N` aliases that decision 0029 already makes truthful |
| Nested `dlopen` | 1 | cryptography imports `dlopen`, `dlsym`, `dlclose`, `dlerror` (OpenSSL's dynamic-module support) | optional with declaration: admitted only when the module declares `nested_loading`; execution evidence must show no nested image acquisition or only declared OS libraries; interception stays unsupported |
| More than four PT_LOAD segments | 5 | auditwheel's patchelf appends segments; OpenBLAS has 9 loads with file offsets that differ from virtual addresses | required: bounded segment counts with the existing congruence checks |
| Images above 256 KiB | 16 | OpenBLAS is 27,121,113 bytes; the extension profile caps images at 256 KiB and the Lua closure at 16 MiB per image | required: 64 MiB per image, as the inspector already allows |
| R_AARCH64_IRELATIVE / STT_GNU_IFUNC | 0 | none | optional: reject |
| TLS_TPREL64 (initial-exec TLS) | 0 | none; initial-exec TLS consumes static TLS surplus under `dlopen` | optional: reject until a fixture establishes the static TLS budget |
| TLS_DTPMOD64 / TLS_DTPREL64 | 0 | none | optional: reject |
| DT_RELR | 0 | none; newer linkers emit it with `-z pack-relative-relocs` | optional: reject now, revisit when a pinned package needs it |
| DT_REL tables, COPY relocations, TEXTREL, DF_SYMBOLIC | 0 | none | optional: reject |
| PT_GNU_PROPERTY (BTI/PAC) | 0 | every image carries only a GNU build-id note | optional: reject until a branch-protection fixture exists |
| Hidden symbol-version bit | 0 | none | optional: reject |
| Executable stack, writable code | 0 | every image declares a non-executable GNU stack | reject, as today |
| Over 64 MiB, over 65,536 symbols or relocations | 0 | largest image 27 MB, 14,277 symbols, 34,973 relocations | keep the inspector bounds |

Four findings carry most of the weight.

**Scope.** The stock interpreter exposes `libpython3.13.so.1.0` to every
extension through the executable's global lookup scope; no manylinux wheel
names it in DT_NEEDED, and auditwheel refuses to vendor it. Decision 0015
instead loads the runtime `RTLD_LOCAL`, gives the fixture roots an explicit
NEEDED edge and checks that runtime exports are absent from the global scope.
Real wheels cannot use that route. This record proposes that the selected
runtime image is promoted to the global scope exactly once, before the first
extension load, after the existing interposition check has proven that no
loaded image defines any of its exports; extension images stay `RTLD_LOCAL`;
and the ownership check after each load verifies that every `Py*` relocation
of every extension resolved into the selected runtime image. The alternative,
rewriting DT_NEEDED into every wheel image at build time, preserves the local
scope but modifies upstream bytes, invalidates RECORD identities and needs its
own decision; it is not proposed here.

**Import policy.** Enumerated reviewed import lists do not scale: the corpus
imports 444 distinct Python symbols, 30 with the private `_Py` prefix (several
of them stable-ABI members such as `_Py_NoneStruct` and `_Py_Dealloc`), up to
616 undefined symbols in one image, and every one is exported by the pinned
runtime. The policy becomes a resolvability rule checked at build time and
rechecked at startup: every undefined symbol must resolve to exactly one
declared provider, the runtime export table by name, an allowlisted OS library
by name and version, or an archived image of the same closure by SONAME; weak
symbols may additionally stay null; anything else rejects with the requesting
image and symbol named. Private runtime symbols are admitted because the
runtime exports them; this is not a sandbox and the record does not claim one.

**Host prerequisites.** The manylinux level of a wheel sets the glibc floor,
GLIBC_2.34 for the selected cryptography wheel, and the libstdc++ and libgcc_s
floors follow from the version needs (GLIBCXX_3.4.21, CXXABI_1.3.9,
GCC_4.5.0). The bundled libgfortran additionally needs host `libz.so.1`, which
the manylinux whitelists do not name, so the allowlist must be measured from
the images rather than derived from the policy alone. Declared OS libraries
and their version floors are verified on the host before the first mapping of
any archived image, through the ordinary loader-owned handles the plan
reserves for actual system libraries.

**Search paths.** Every RPATH in the corpus is `$ORIGIN`-relative and points
inside the wheel. Because the closure is loaded dependency-first and `ld.so`
matches a NEEDED name against the SONAME of an already loaded object before it
searches any path, no search ever runs when glue preloads the closure; with a
`/proc/self/fd/N` origin a search could only probe `/proc/self/fd/`. The
contract admits `$ORIGIN`-relative entries, never honors them, and requires
trace evidence that no such probe occurs.

## Frozen release profile for GNU Linux aarch64

Required features, in the plan's sense that a failed required feature blocks
release and cannot be reclassified to make G5 pass:

1. GNU-hash-only images, images without SONAME, nonzero entry points and
   images without BIND_NOW.
2. Runtime symbol resolution through the promoted global scope, resolvability
   of every undefined symbol against declared providers, weak and data
   imports, private runtime symbols.
3. OS libraries from a measured per-target allowlist with version floors
   checked before mapping; version needs and version definitions; versioned
   and unversioned edges to archived dependency images loaded dependency-first
   by SONAME; `$ORIGIN` RPATH admitted and never honored.
4. Relocations RELATIVE, GLOB_DAT, JUMP_SLOT, ABS64 with addends and TLSDESC;
   PT_TLS with dynamic TLS proven on existing, new and library-created
   threads, including thread-exit destructors.
5. STB_GNU_UNIQUE, STV_PROTECTED and absolute version-name symbols;
   constructors and destructors; unwinding through archived C++ and Rust code;
   `dl_iterate_phdr` and `dladdr` over descriptor aliases.
6. Up to 64 MiB per image, 65,536 symbols and relocations, 64 NEEDED entries
   and 16 PT_LOAD segments per image; a closure of at most 64 images and
   256 MiB per application, which holds numpy's 21 images and 41.5 MB with
   room for the scientific stress test the plan names.

Optional features, rejected at inspection before any mapping, constructor or
Python initialization, with the rejection naming the image and feature:
IFUNC and IRELATIVE, initial-exec and general-dynamic TLS relocations, RELR,
REL tables, COPY relocations, TEXTREL, DF_SYMBOLIC, PT_GNU_PROPERTY, hidden
symbol versions, executable stacks, writable code, non-`$ORIGIN` search paths,
NEEDED names outside the three provider classes, undeclared nested loading,
and every bound above. Reclassifying an optional feature as required needs a
new decision record with its own fixture and real-package evidence.

## What blocks the corpus today

The inspector rejects all 24 images before any import policy applies: 17 at
the GNU_HASH dynamic tag, 3 at the PT_TLS program header (cryptography,
OpenBLAS, numpy core), 2 at the nonzero entry point (libgfortran,
pydantic-core) and 2 at the RPATH tag (`_umath_linalg`, `lapack_lite`).
Behind the first rejection the complete ladder, in the inspector's own check
order, is:

| Inspector rejection | Images |
| --- | --- |
| missing SysV DT_HASH; GNU_HASH tag | 24 |
| every undefined symbol must be declared; weak undefined symbols beyond the three compiler hooks | 24 |
| missing SONAME | 22 |
| immediate binding (BIND_NOW) required | 21 |
| Python extension-profile bound of 256 KiB | 16 |
| ABS64 relocations | 13 |
| OBJECT imports without the data-import opt-in | 6 |
| RPATH tag; TLSDESC relocations; PT_TLS segment | 4 each |
| TLSDESC_PLT/TLSDESC_GOT tags; nonzero entry point; named relocation with nonzero addend; STB_GNU_UNIQUE | 2 each |
| VERDEF tags and versioned definitions; STT_TLS symbol; absolute section index; protected visibility | 1 each |

Nothing in the corpus needs IFUNC, RELR, REL, COPY, initial-exec TLS,
branch-protection properties, hidden versions or any of the inspector's size
bounds; those rejections are free.

## Consequences

For A5, the inspector keeps its structure, section independence, bounds and
hostile-input tests, and gains: GNU hash parsing with chain-derived symbol
counts; optional SONAME for root images; tolerated entry points; TLS segments,
TLSDESC relocations and their tags; ABS64 with addends; UNIQUE binding,
protected visibility, absolute version names, VERDEF; RPATH admission limited
to `$ORIGIN`-relative entries; data imports and weak imports governed by the
resolvability rule instead of reviewed lists. Every added admission needs the
same adversarial tests the existing checks have. The Python native loader
promotes the runtime, verifies host prerequisites first, loads bundled
closures dependency-first and keeps the post-load owner checks. The
extension-profile image bound of 256 KiB and the Lua closure's 16 MiB bound
are replaced by the limits above, with the manifest recording them.

For G5, the fixtures the plan already lists must be built or extended for
this profile and then run against the corpus in the GNU Linux arm64 cell with
complete traces: TLS on existing, new and library-created threads with
thread-exit destructors; C++ exceptions inside numpy and Rust panics inside
pydantic-core that surface as Python exceptions; constructors once per image;
data imports; version floors with a deliberately old host library rejected
before mapping; a bundled library with VERDEF; `$ORIGIN` RPATH with trace
evidence of no path probe; declared nested loading with trace evidence of no
undeclared image acquisition; and the no-extraction trace over the whole
numpy import. Real-package tests exercise `markupsafe.escape`, a numpy
matrix product through OpenBLAS, `numpy.linalg` through LAPACK, a numpy
`random` generator, a pydantic model validation and a cryptography hash and
AEAD operation, under both the bundled and the explicit host runtime.

For A10, wheel admission must accept `abi3` wheels for the conventional
3.13 runtime and refuse them for free-threaded builds, and must record the
manylinux level of every admitted wheel as a host prerequisite.

## Decisions this record asks for

- Scope: accept global-scope promotion of the runtime image as proposed, or
  commission the build-time DT_NEEDED normalization alternative.
- Nested loading: accept per-module declaration for cryptography's OpenSSL
  `dlopen` imports, or reject any image importing `dlopen` until interception
  exists.
- Bounds: accept the per-image, per-closure and per-application limits above.

## Limits

This is a static survey of one cell and four packages. It did not execute any
corpus image, measure startup or memory, or examine x86_64, musl, free-threaded
or other Python versions. Packages outside the corpus may need optional
features, IFUNC and RELR being the likely first, and the survey script is
meant to be rerun on them before any reclassification. The record does not
relax the no-extraction constraint, the manifest or ABI contracts, or any trace
requirement, and it does not claim that admission is a sandbox.
