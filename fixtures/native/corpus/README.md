# Native wheel corpus survey (A5)

A measured basis for the native capability contract in
[decision 0032](../../../docs/decisions/0032-native-capability-contract.md).
Four unmodified upstream wheels for the project's cell, CPython 3.13 on
manylinux aarch64, are downloaded as build-time inputs and every shared object
in them is read statically. Nothing here maps, loads or executes corpus code,
and no loader code changes.

| Wheel | Role | Images |
| --- | --- | --- |
| markupsafe 3.0.4 | small C extension | 1 |
| numpy 2.5.4 | dependency-heavy C/C++/Fortran package bundling OpenBLAS and libgfortran | 21 |
| pydantic-core 2.50.1 | Rust-built extension (PyO3) | 1 |
| cryptography 50.0.2 | Rust-built stable-ABI extension with OpenSSL linked in | 1 |

`wheel-pins.json` records the exact file names, PyPI URLs, sizes, SHA-256
digests and upload times. The selection rule is the latest stable release on
15 October 2026 and, where a release publishes several manylinux levels, the
wheel pip would choose for the Debian bookworm (glibc 2.36) test cell:
cryptography's `cp311-abi3-manylinux_2_34_aarch64` wheel rather than its
`manylinux_2_17` or `manylinux_2_28` variants.

## Files

- `wheel-pins.json`: the pinned corpus.
- `fetch-corpus.py`: downloads each wheel with the system curl into
  `target/native-corpus/wheels/`, verifies size and SHA-256, and unpacks it into
  `target/native-corpus/unpacked/<project>-<version>/`. The unpacked trees are
  untrusted data; nothing imports or executes them.
- `survey.py`: a section-independent ELF64 reader. It records, per image,
  the facts listed below and derives a feature matrix and the complete list of
  rejections the current glue-native inspector would raise, in that inspector's
  check order.
- `survey.json`: the committed survey output for the pinned corpus.
- `summary.md`: the generated Markdown view of `survey.json`.
- `crates/glue-native/examples/elf-survey.rs`: a thin command around
  `glue_native::elf::inspect_with_data_imports` that prints the inspector's
  first rejection for one image. It adds no policy and loads nothing.

## Reproduce

```sh
export PATH="$(dirname "$(rustup which cargo)"):$PATH"
python3 -I fixtures/native/corpus/fetch-corpus.py
cargo build -p glue-native --example elf-survey --locked
python3 -I fixtures/native/corpus/survey.py \
  --inspector target/debug/examples/elf-survey \
  --readelf /opt/homebrew/opt/llvm/bin/llvm-readelf \
  --runtime-library /absolute/producer/lib/libpython3.13.so.1.0
```

`--readelf` (llvm-readelf or GNU readelf) cross-checks NEEDED, SONAME,
segment types, relocation type counts, dynamic symbol counts and version needs
against an independent reader; the committed output records zero
disagreements. `--runtime-library` takes the selected stock PBS
`libpython3.13.so.1.0` (SHA-256
`42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219`, the
identity already pinned by the host-prerequisite fixture) and checks every
`Py*`/`_Py*` import of the corpus against its export table. Both options are
optional; without them the structural facts are identical.

## Facts recorded per image

- ELF header: type, machine, OS ABI, entry point, flags.
- Program headers: every segment with permissions, offsets, sizes and
  alignment; PT_TLS template sizes; PT_GNU_STACK permissions; PT_GNU_RELRO and
  PT_GNU_PROPERTY presence; notes in PT_NOTE segments, including AArch64
  BTI/PAC property bits when present.
- Dynamic table: every tag with its count; NEEDED entries classified as OS
  policy library, library bundled in the wheel, runtime or unknown; SONAME,
  RPATH and RUNPATH; DT_FLAGS and DT_FLAGS_1 bits; hash tables present;
  constructor and destructor counts from DT_INIT/DT_FINI and the array sizes.
- Dynamic symbols: counts by binding, type and visibility; GNU_UNIQUE, IFUNC
  and TLS symbols; weak undefined symbols beyond the three compiler hooks the
  inspector already tolerates; OBJECT imports; `PyInit_*` exports; imports of
  the dlopen, thread and unwinder families; unversioned imports split into
  those satisfied by another image of the same wheel and those that bind
  through the global lookup scope, strong and weak.
- Versions: every version need per library, the highest GLIBC version,
  version definitions.
- Relocations: a histogram per table (RELA, PLT, REL) and overall, RELR entry
  counts, named relocations with nonzero addends, TLS relocations with symbols.
- `glue_native_rejection_ladder`: every rejection the inspector in
  `crates/glue-native/src/elf.rs` would raise for the image, derived from the
  facts in the inspector's own order.
- `glue_native_inspector`: the inspector's actual first rejection, called twice:
  as a closed fixture profile would call it (expected SONAME equal to the file
  name, no declared imports) and with the image's own SONAME and every
  undefined symbol declared. For all 24 images both calls stop at the same
  structural rejection, before any import policy applies.

The feature matrix at the end of `summary.md` counts images per loader
feature; the decision record turns those counts into the required and optional
feature sets. Rerunning the survey against the pinned corpus must reproduce
`survey.json` except for the generation date and the absolute paths of the
optional tools.
