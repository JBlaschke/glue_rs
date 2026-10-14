# Installed runtime tree fixture

This fixture exercises `glue python-host --provider host-install --runtime-tree`
with stock conventional-GIL CPython 3.13.16 / PBS `20261009` on GNU Linux arm64.
Its input audit verifies only the existing 1,041 selected prerequisites: the
73,563,968-byte embedding library, 1,037 source files and three startup caches.
It does not certify the complete installation or accept arbitrary uv versions,
default stripped uv downloads, additional native modules or other Python ABIs.

The setup runs genuine uv 0.12.23 offline with an explicit custom download
catalog pointing to the already authenticated **unstripped** install-only
artifact. `uv-pins.json` binds the GNU arm64 uv release archive, official checksum
URL and extracted executable. Mac setup uses the existing Homebrew 0.12.23
executable and records its complete binary identity and version output. A fresh
installation and cache directory, `--no-bin`, `--no-registry`, `--no-config` and
`--offline` isolate installation from ordinary uv state. This is a configured uv
compatibility cell; the built-in catalog ordinarily selects a different stripped
artifact.

```sh
python3 -B fixtures/python-runtime-trees/prepare.py install \
  --uv /absolute/path/to/regular/uv \
  --pbs-install-only /absolute/path/to/pinned-install-only.tar.gz \
  --output /absolute/new/fixture-directory --remove-bin
```

The helper writes the catalog, installation command/status/stdout/stderr,
`installation-provenance.json`, cache and managed installation under that new
directory. It verifies all selected bytes first, then removes its own `bin/`
directory and verifies that selected bytes remain unchanged. Product preparation
can therefore operate with the input interpreter absent. Installation itself is
a separate setup operation; it is not performed by the product preparer.

Uv changes one selected payload, `_sysconfigdata__linux_aarch64-linux-gnu.py`.
The other 1,040 selected identities remain stock. The independent oracle parses
the separately pinned original source as a literal dictionary without evaluating
it, applies the 72 recorded scalar changes in `uv-0.12.23-adjustments.json`
(71 existing keys and the new `PYTHON_BUILD_STANDALONE` marker), and serializes
the exact expected source independently. Its 27 root substitutions include JSON
escaping for quoted paths. Tests compare this reconstruction with the separately
bound product template and genuine installation bytes. Semantic equivalence,
extra whitespace, another root or arbitrary source does not qualify.

The product publishes the original stock sysconfig source, restoring the
existing 89,479,393-byte prerequisite projection. Its provenance records the
selected input root/layout, sysconfig input/output identities and normalization;
observed compressed artifact/inventory and omitted totals are null in tree mode.
Uv's build-tool configuration is not preserved in this embedding projection.
The file audit verifies every emitted path, payload hash, exact `0444` file and
`0555` directory mode, and nanosecond-exact epoch `1704067200` mtime.

```sh
python3 -B fixtures/python-runtime-trees/prepare.py audit-output \
  --runtime-tree /absolute/verified/input \
  --prefix /absolute/published/prefix --report /absolute/report.json \
  --output /absolute/new/publication-audit.json
python3 -B fixtures/python-runtime-trees/prepare.py controls \
  --glue /absolute/regular/glue --runtime-tree /absolute/verified/input \
  --output /absolute/new/control-evidence
python3 -B fixtures/python-runtime-trees/test_prepare.py
```

Five valid preparations cover genuine uv, a repeated preparation, a selected
stock tree, a quoted relocated uv root, and ignored unselected FIFO/native
alias/cache contents. Nineteen portable hostile commands cover missing/corrupt/oversized
selected files, selected symlink ancestors and leaves, FIFO sources, modified
sysconfig/root values, input/output overlap, existing file/directory/symlink
outputs, provider conflicts and invalid parser combinations. A twentieth command
uses a valid stock tree and case aliases on a case-insensitive filesystem to
verify physical overlap rejection; case-sensitive builders record its explicit
skip. The other overlap cases also remove the library to prove rejection
precedes selected payload reads. Existing
sentinels and original selected input bytes, file modes and mtimes are checked
afterward. The fixture retains bounded receipts and complete selected identities
and 512-byte input prefixes. It copies one selected base into fresh native
temporary storage so FIFO controls work independently of shared input filesystems.
Subsequent clones link only to this owned base, with a copy fallback when links
are unavailable; the original input is never hardlinked or chmodded. With native
temporary-filesystem links, the peak scratch payload is below 180 MiB;
copy-only fallback storage can require more. `--scratch-parent` can select another ordinary
temporary directory. Cleanup removes only the fixture's own scratch trees.

`test_process.py` audits the complete product preparation trace against the
independently verified selected inputs. `run-linux.sh` runs preparation and the
existing real-package three-provider application matrix. Historical runtime
policies remain unchanged; resulting archives must retain their prior identities.
Mac's default case-insensitive filesystem folds some unselected `terminfo`
paths in a full GNU installation, which is outside this selected-only contract.
The generic complete-installation and platform release gates remain open.

Primary references: [uv custom installation catalog](https://docs.astral.sh/uv/reference/environment/#uv_python_downloads_json_url),
[uv 0.12.23 download metadata](https://github.com/astral-sh/uv/blob/0.12.23/crates/uv-python/download-metadata.json),
[uv 0.12.23 release](https://github.com/astral-sh/uv/releases/tag/0.12.23).
