# macOS host Python product route (A7/A1)

Implementation contract, 15 October 2026. Continue from merged `28b0cab`,
the pull request that landed [decision 0031](0031-macos-python-host-startup.md).
This is the product registry integration that record left as a separate
step: the same
`stock-pbs-host-startup-macos` archive now runs through `glue doctor` and
`glue run` on macOS arm64.

## Scope

Admit the profile in the product registry of `glue-runtime-python` so that a
runner built with `--features python-pbs` on macOS arm64, with
`GLUE_PYTHON_INCLUDE_DIR` naming the verified install-only header tree,
reports readiness for the archive and executes it. The manifest, the pins,
the application-only archive, the dyld loading mechanism, the `LC_UUID`
binding and the unchanged API4 29-export C boundary are the ones decision
0031 established. Nothing about them changes here.

## Mechanism

Admission is portable. `profile::validate` selects `Kind::MacosHostStartup`
when the application identity is `stock-pbs-host-startup-macos` and the
manifest equals the exact fixture manifest for its declared installation
prefix, through the existing `macos_host::admit_manifest`. The profile has no
packaging bounds; it is a controlled fixture, not a source-application build
identity. Every other cell admits the manifest and reports it as unsupported.

Readiness gains a macOS arm64 branch that exists only when the build script
set `glue_python_macos_host`. The selected target must declare macOS,
aarch64, the Darwin ABI, a numeric minimum version, exactly 16384-byte pages
and no CPU features. The host is then observed through `sysctlbyname` with
`kern.osproductversion` and `sysconf` for the page size, and the declared
minimum is compared with the observed version using the numeric floor helpers
the GNU Linux branch already uses. Observation never loads a library, opens
the declared installation or claims the process execution attempt. The GNU
Linux declaration is unsupported on this cell, as the macOS declaration is on
GNU Linux; wrong ABI or page sizes under the right OS and architecture are
invalid. A feature-enabled Mac build without the header tree keeps its
unsupported status and now names `GLUE_PYTHON_INCLUDE_DIR`. The GNU Linux
arm64 readiness code and its diagnostics are unchanged.

Execution dispatches `Kind::MacosHostStartup` to the same `macos::run_host`
the probe uses. The application is read from the archive the runner already
opened: `macos_host::read_payload_from` re-applies the profile's 64 KiB bounds
through `Archive::check_limits`, requires exactly the one shared application
entry, verifies its bytes and closes the archive before the installation is
opened. `glue doctor` names the compiled execution cell in its Python summary
instead of assuming GNU Linux arm64; the GNU Linux line is byte-identical.

## Evidence and limits

On the observed macOS 26.7 cell, `glue doctor` prints `Ready` for the
fixture's archive and `glue run` prints the same PASS line as the probe, under
the fixture's poisoned environment and unavailable home and temporary paths.
The six rejected installations and the loader override reject through
`glue run` with status 1 and the `glue:` prefix, while `doctor` still reports
them ready because readiness does not inspect host files. GNU Linux
declarations report unsupported on this cell with status 2, and a
feature-enabled Mac build without the header tree reports the macOS archive
unsupported with status 2. The read-only installation is unchanged after
every run.

This serves one controlled startup profile from one explicitly declared
installation. It does not add a checked-in product harness for the macOS
cell, a root-level trace, installation discovery, native extensions, the
complete stdlib, bundled macOS Python or the distribution signing policy.
