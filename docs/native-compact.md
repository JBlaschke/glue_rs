# Compact native dependency collection

The build-time collector reads ELF64 or Mach-O metadata without executing user
images. Supply every runtime/package/search root explicitly. Deployed paths
preserve source-relative layout; OS baseline dependencies are recorded, and
other missing or escaping edges fail. TLS, unwind and GNU hash features use the
ordinary OS loader. A source dependency is never compiled by this collector.

Inputs already using `$ORIGIN` or dyld-relative paths retain their bytes.
`--normalize-native-paths` permits metadata edits. On Linux install patchelf as
a build prerequisite (`/usr/bin/patchelf`, or explicit absolute `GLUE_PATCHELF`).
The tool is never installed or invoked at runtime. On Mac normalization uses
install_name_tool and ad-hoc codesign, followed by independent metadata checks
and `codesign --verify --strict`; it does not prove Developer ID/notarization.
Reports contain exact input/output identities and every applied edit.

The Linux native tests execute a prebuilt extension plus secondary library with
TLS, compare readelf, relocate and remove the source prefix. The normalization
case starts with no RUNPATH, verifies default refusal, then executes normalized
output and checks unchanged input bytes. All four cases executed on Linux
arm64 with Rust1.88.0 and independently provisioned Debian patchelf0.14.3.
Linux x86_64 native execution remains a required external cell.
