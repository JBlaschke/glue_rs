# Native Linux patch and stable-ABI compatibility extension

The existing 24 native Linux cases and five accepted budgets do not prove that
a different CPython patch works with unchanged glue bytes, or that an unchanged
prebuilt stable-ABI extension runs on two conventional CPython minors. The
seven archive/uv route cells remain separate and unchanged.

Add three optional, separately retained positive cells per Linux architecture:

| Cell | Existing recipe family | Runtime | Required relationship |
| --- | --- | --- | --- |
| `python-patch-3.13.15-source` | normalized source | PBS 20260929 CPython 3.13.15 | Different runtime-executable SHA-256 from the checked 3.13.16 source case; identical included glue launcher identity |
| `python-abi3-3.13.16` | `python-abi3` | existing PBS 3.13.16 | Exact pinned cryptography wheel and its original native members |
| `python-abi3-3.14.8` | `python-abi3` | existing non-PBS 3.14.8 | The same cryptography wheel/native bytes as the 3.13.16 case; independently compatible cffi inputs |

Only conventional GIL builds are included. The existing abi3 application
performs SHA-256 hashing and Ed25519 key generation, signing and verification;
matching an import or version string alone is insufficient. All three cells
use the unchanged V02 relocation, offline, complete descendant-trace and
injected extraction controls. Their preparer retains the same environment
receipt bytes outside the subsequently deleted input tree.

Pin the exact target-matched PBS install-only archive, cryptography 50.0.2,
cffi 2.1.1 and pycparser 3.0 assets from official release metadata. The existing
test-only wheel provisioner's actual lexical selection is the
`cp39-abi3-manylinux_2_34` cryptography wheel on both minors. Its two target
variants are distinct; bytes are shared across minors within one target.
This wheel requires glibc 2.34 or newer, independently of its Python stable ABI.
The existing provisioner downloads and verifies prebuilt wheels without
compilation or package installation hooks. cffi uses its matching cp313/cp314
wheel; no cross-minor compatibility claim is made for that dependency.

Retain the small wheel provenance receipts and the selected cryptography wheel
once in each native evidence bundle. The pure summary verifies its official
SHA-256/size and safe ZIP members, and binds every installed cryptography
member and prepared copy through each original input inventory. This proves
unchanged source wheel/native inputs. Explicit native-path normalization in
the product remains separately declared; the claim does not imply identical
normalized payload files. A retained patch provenance record binds the verified
official archive identity to the staged interpreter identity. The original
runtime archive is absent from the evidence bundle, so offline replay checks
that metadata chain rather than claiming to rehash absent archive bytes.

Use separate `abi-case-status.tsv`, `abi-inputs.json`, `abi-plan.json` and
`abi-summary.json` records. The summary checks exact case and asset rosters,
native target, complete version/ABI, same source commit, own prepared input
paths, the selected entry route and all required V02 statuses. The native
runner independently checks retained full receipts/traces before recording a
zero case status. Metadata controls and pure summary tests are not native
acceptance, and this extension does not establish complete M2 acceptance.

A separate real refusal control should supply the already downloaded genuine
cp314 cffi wheel to a conventional 3.13 environment. Require the product's
`runtime_abi_mismatch` diagnostic before creating an absent output, while
preserving an unrelated sibling sentinel tree, including with the explicit
matching `--python 3.13` selector. An existing output is a separate collision
refusal and need not produce an ABI diagnostic. Existing ignored native tests cover rejection, but
are not selected by the 24/7 case runner and do not establish a fresh native
receipt. The refusal is reported separately and cannot be inferred from unit
controls or from the three positive executions.

The source audit retains official small metadata under the ignored
`.evidence-local/provisioning/linux-patch-abi3-audit-20261029` directory. It
downloads or executes no runtime or wheel locally. This decision changes no
accepted budget, existing corpus, Darwin tracing requirement or signing policy.

Sources: [PBS 20260929 release](https://github.com/astral-sh/python-build-standalone/releases/tag/20260929),
[cryptography 50.0.2 metadata](https://pypi.org/pypi/cryptography/50.0.2/json),
[cffi 2.1.1 metadata](https://pypi.org/pypi/cffi/2.1.1/json),
[pycparser 3.0 metadata](https://pypi.org/pypi/pycparser/3.0/json),
[PyPA platform compatibility tags](https://packaging.python.org/en/latest/specifications/platform-compatibility-tags/).
