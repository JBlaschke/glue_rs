# Python compatibility inputs and native execution

The baseline native Linux runner exercises source, module, console and native
cases on CPython 3.12.15, 3.13.16 and the independent conda 3.14.8 runtime.
`linux_compatibility.py` describes a separate, optional seven-cell extension:

| Cells | Supplied input | Environment |
| --- | --- | --- |
| `python-archive-full` | PBS 3.13.16 full archive, passed directly to `glue build --runtime` | Ordinary seeded venv |
| `python-archive-install-only` | PBS 3.13.16 install-only archive | Ordinary seeded venv |
| `python-archive-stripped` | PBS 3.13.16 stripped install-only archive | Ordinary seeded venv |
| `python-uv-source`, `python-uv-module`, `python-uv-console`, `python-uv-native` | Installed PBS 3.13.16 tree and existing fixture packages | uv 0.13.6 venv, offline preparation |

These exact versions and hashes identify independently supplied test inputs;
they do not restrict the product's runtime discovery to a catalog. Both native
Linux architectures have their own official archive/tool identities. Original
archives are checked before use. No installed user package is compiled or
downloaded by `glue build` or by a deployed application.

Dispatch the existing workflow against the feature revision to execute the
extension as well as the original 24 cases and five unchanged cost profiles:

```sh
gh workflow run mvp-native.yml --ref YOUR_FEATURE_BRANCH \
  -f target=both -f compatibility=true
```

On an already prepared native runner the explicit shell selection is
`GLUE_MVP_COMPATIBILITY=required bash scripts/ci-mvp-linux.sh`, with a new
absolute `GLUE_MVP_CI_ROOT` and the prerequisites in the workflow. Default
`disabled` retains the original acceptance scope. The existing trace environment
disables unobservable asynchronous kernel I/O throughout the process tree;
these cases do not establish unrestricted-host acceptance.

Each extra cell uses the shared V02 stock-reference comparison, relocated
read-only distribution, removed original inputs, unusable caches/home, offline
namespace, complete descendant trace and positive/negative oracle controls.
Normalized uv recipes explicitly prune `app/site/0/_virtualenv.pth` and request
native-path normalization. The removed executable hook is a reported limitation;
its original behavior is not claimed. Existing recipes remain available.

`prepare.py --receipt-output PATH` retains the exact preparation receipt outside
the copied inputs. The compatibility summary binds that copy to the verified
input inventory, checks actual environment kinds, binds all three archive
identities to both input inventories and builder runtime reports, and checks
the uv runtime against the baseline PBS runtime identities. A missing or failed
cell fails the extension. Runner failures remain failures even when some cases
pass. Complete raw checker inputs and statuses stay in the native CI artifact.

```sh
python3 fixtures/mvp/python-matrix/linux_compatibility.py plan --architecture x86_64
python3 fixtures/mvp/python-matrix/linux_compatibility.py summary \
  --architecture x86_64 --evidence /retained/evidence --result 0
```

Portable controls validate refusal and receipt binding, not native acceptance.
Fresh native execution and independent raw replay must prove the new cells.
Additional-patch/same-launcher and abi3 evidence, macOS oracle/signing and Mac
budgets remain separate gates. `matrix.py` reports supplied historical receipts;
it cannot infer unrecorded provider or input-route coverage or complete M2.

## Different patch, abi3 and an actual wrong-ABI refusal

An independent optional extension adds three more traced positive cases:

- CPython 3.13.15 source, compared with the baseline 3.13.16 source receipt:
  different runtime-executable hashes and patch versions, identical included
  glue launcher bytes and source revision.
- Prebuilt cryptography 50.0.2 abi3 operations on PBS 3.13.16 and the independent
  conda 3.14.8 runtime. The same target-specific cryptography wheel and all its
  input members must match on both minors. Each minor has its own compatible
  CFFI backend; dependency equality across minors is not inferred. Explicit
  native-path normalization remains separately reported.

`linux_abi_compatibility.py` checks these retained bindings, crypto operation
stdout, official runtime/wheel pins and the bounded retained cryptography ZIP.
The patch staging bridge records verified archive-to-staged-interpreter
provenance; offline replay does not rehash an absent runtime archive.

`run_abi_refusal.py` separately prepares a real ordinary 3.13.16 environment
containing the genuine pinned cp314 CFFI wheel, then invokes the existing glue
binary. It must return `runtime_abi_mismatch` before publishing output. The
collector retains the wheel, command streams, absent-output observations, input
inventories and unrelated sibling sentinel contents. A target mismatch refuses
before any output creation or runtime execution. It downloads no input and
imports no application code. Its normal preparer uses only the selected
runtime's bundled venv/ensurepip seed.

The three positive routes and wrong-ABI diagnostic have separate verdicts.
Native CI also requires the collector's complete status, empty collection
errors and exact unchanged before/after input observations. A partial or failed
collection cannot become a passing refusal through its diagnostic alone.

```sh
gh workflow run mvp-native.yml --ref YOUR_FEATURE_BRANCH \
  -f target=both -f compatibility=true -f python_abi=true
```

With both extensions selected this runs 34 application cases, the five unchanged
performance profiles and one actual prepublication refusal. Both options default
to false. Portable metadata/collector tests use synthetic evidence and controlled
children; only fresh native executions and independent retained replay can
prove these additional cells. Mac compatibility/oracle, Mac budgets, external
retention and final M2 sign-off remain separate.
