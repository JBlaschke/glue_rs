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
