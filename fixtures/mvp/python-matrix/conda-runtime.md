# Independent non-PBS Python 3.14 CI input

`provision-conda.py` prepares a complete prebuilt conda-forge installation before
any glue build. The checked-in lock contains all 24 package URLs, versions,
builds, SHA256 and MD5 identities (58,036,501 archive bytes), including CPython
3.14.8, libffi 3.7.0 and the matching GCC 16.2 libstdc++/libgcc closure. Micromamba 2.3.3 is independently pinned by SHA256.

```sh
/usr/bin/python3 fixtures/mvp/python-matrix/provision-conda.py \
  --lock fixtures/mvp/python-matrix/conda-linux-x86_64-3.14.8.lock.json \
  --work "$ci_root/downloads/python-3.14.8-conda" \
  --output "$ci_root/runtimes/python-3.14.8" \
  --evidence "$evidence/provisioning/python-3.14.8-conda"
```

The helper verifies each downloaded archive before an offline explicit
installation, records commands and package-manager output, probes conventional
CPython/ensurepip, then uses the shared execution-input staging helper. It does
not compile native images or alter the glue builder, launcher or trace oracle.
Package installation can perform the upstream package's normal prefix setup.
Only the resulting complete installation is supplied to the existing Python
source/module/console/native recipes. Keep `GLUE_MVP_NATIVE_SEARCH=/usr/lib/x86_64-linux-gnu`: the Tk closure
also needs explicitly supplied host X11 libraries. The builder already declares
the copied runtime and its `lib` directory as search roots for the combined
runtime/application closure; their deeper paths precede the extra host root.
The pinned conda libstdc++ and its `$ORIGIN/.` RPATH therefore select the matching
conda libgcc without losing the independent X11 inputs. PBS 3.12/3.13 and all
R03 Python 3.13 inputs remain unchanged.

The lock was cross-resolved as Linux metadata using verified native Mac
micromamba, with glibc 2.39 as the target virtual package. This is input selection,
not Linux execution evidence. `--lock` replays the complete closure without
solving; omitting it deliberately creates a fresh lock requiring independent
review. No package archives or installed runtime are committed.

The exact libffi package's embedded `info/recipe/build.sh` has SHA256
`b2264fe2727669e53c25c6bb933cfe9bd0850615bb67ca7cd8d725bd69e7c86c` and
uses `--disable-exec-static-tramp`. Its embedded recipe identifies feedstock
commit `dc557589925d228815625e735ff1e63236d5fcd7`. This avoids selecting the
known PBS static-trampoline configuration; compatibility and absence of
filesystem code materialization still require the unchanged hosted V02/R02
checks, including relocation into a path containing spaces.

The first hosted run passed 3.14 source/module/console but correctly rejected
native packaging when its wheel C++ closure selected the host GCC 13 libgcc
alongside the runtime's GCC 16 libgcc. The additional pinned libstdc++ package
depends on the exact already-locked GCC 16 libgcc build; its original ELF
RPATH is `$ORIGIN/.`. No conflicting-identity or symbol-version validation is
relaxed. The full 3.14 native case was then rerun with this complete input.


Hosted native x86_64 run
[38800548172](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172)
passed all four 3.14 source/module/console/native recipes and the complete
24-case matrix, with immutable inputs, relocated paths containing spaces,
read-only payloads, unusable caches and the strict process-tree write oracle.
The 3.14 native receipt SHA256 is
`828387c67c36fbeb2d1ea820be5eab3e7d4efcfb3401c12b7cb41da7a366209d`.
Its ten-process trace records no memory-object writes or temporary code files;
only the expected stdout write occurs. The selected conda runtime is an
independent non-PBS input, with no native compilation or input-byte patches.

The execution environment explicitly inherits `traceable-native-syscalls-v1`,
which makes asynchronous kernel I/O return ENOSYS for both stock references and
packaged trees so the syscall oracle can observe operations. Unrestricted
ring-enabled hosts are outside this evidence. Complete receipts and controls
are in [artifact 12005186009](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172/artifacts/12005186009),
ZIP SHA256 `c1cc519d76e73888ed0339714deec1e97eea816c1f8861ab551da4579644e7a4`.
Local independently replayed evidence is
`/private/tmp/glue-native-x86-evidence-38800548172/independent-replay.json`.
