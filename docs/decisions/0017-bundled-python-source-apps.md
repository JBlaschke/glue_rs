# Pinned bundled Python source applications

This A7 increment starts from merged `90c4a10` on
`codex/a7-python-source-apps`. It admits application-owned source and assets
through the product runner while retaining the observed GNU Linux arm64 stock
CPython 3.13.16 / PBS `20261009` runtime contract.

## Declarations and admission

The selected runtime identifies this profile with
`pbs-20261009-cpython-3.13.16-pgo-lto-bundled-source-apps-v1` and the bundled
source variant `pgo+lto-full/bundled-source-apps-v1`. Application IDs and the
selected component name can vary. The original fixture IDs keep their exact
validators; changing a fixture's app bytes does not select this new profile.

One target, one bundled runtime and one component are admitted. Target,
producer, runtime ABI, conventional GIL, non-debug mode and required platform
prerequisites retain the earlier pinned declarations. Native modules, host
imports and host runtime provisioning are outside this profile. Provider
selection remains explicit.

The runtime library, all 2,174 stdlib sources and the original archive importer
retain exact size, hash and compression declarations. The frozen startup
bundle is pinned to 139,523 bytes and SHA-256
`6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7`, from
the earlier clean captures. Its legacy conformance-app metadata is validated
but does not select the new application's entry script.

Application resources live below `app/`. The declared entry is a `.py` resource
of at most 64 KiB; importable modules and packages live below `app/python/`.
Other application files are immutable assets. Application inventory limits are
1,024 resources, 8 MiB total and 4 MiB per resource. Stored and deflated app
members are accepted. The overall archive retains the existing 128 MiB,
4,096-entry policy with an 80 MiB member bound for the pinned library.

Schema-zero resource names remain portable ASCII. Paths, case collisions,
module/package ambiguity and unsupported module names reject during portable
admission. App imports cannot shadow pinned built-ins, frozen aliases, bridge
modules or stdlib roots. Bytecode caches, bytecode and native image paths reject
in this source profile. These checks describe supported payloads; they do not
turn trusted Python application code into a security sandbox.

## Entry execution and ownership

The product transfers its already-open archive to the shared executor. It
rechecks selected limits, verifies every declared resource into owned memory
and closes the archive before loading the selected runtime. The opaque token
remains tied to that manifest. Readiness checks build/target prerequisites;
content verification belongs to execution.

The unchanged C bridge receives a small trusted ASCII launcher. That launcher
reads the entry as bytes through the immutable archive callback and uses the
existing source compiler, preserving encoding cookies and bounded virtual
filename diagnostics. User source is never passed as a NUL-terminated C string.
Syntax errors and embedded NULs are diagnosed by stock compilation.

The entry runs as `__main__` with a virtual `glue://` filename, `sys.argv` holding
that one identity, and `__package__`, `__spec__`, `__cached__` and `__loader__`
set to `None`. This is script execution; module `-m` execution and application
arguments require later work. The temporary launcher function is removed
before user compilation/execution. Existing application exceptions, including
`SystemExit`, use the runtime's bounded diagnostic and CLI status 1; this is
not the exit-code behavior of the standalone `python` command.

The synchronous C owner still controls initialization and finalization.
Archive streams and callbacks remain live through finalization, and loaded
images remain pinned for process life. The API4 table, its 29 selected exports
and the one-attempt lifecycle remain unchanged.

## Packaging and scope

With `python-pbs`, `glue build` chooses the larger packaging bounds only after
portable admission of this profile. `glue-pack::build_with_policy` invokes that
policy on the same parsed manifest that is subsequently packaged, before input
root lookup, resource reads or output creation. Other builds retain their
existing limits. Payload hashes and the generated archive are still verified
before output publication.

The portable build-time staging helper projects already verified runtime inputs
and an application directory into an explicit manifest and input root. The
ordinary product builder creates the archive. It never downloads inputs or
executes application source. PBS ingestion and version selection remain separate
producer work.

Source admission expands application inventories, not the accepted runtime ABI
or platform set. General host-stdlib admission, extension discovery, wheels,
path-required packages, broader diagnostic consumers, worker processes and
other runtime versions remain open. G0/G1/G2 remain open. Representative apps
and complete traces establish the exercised operations, not compatibility with
every Python package.

See [the controlled runner decision](0016-controlled-python-runner.md),
[archive imports](0013-python-archive-source-resources.md) and
[the source application fixture](../../fixtures/python-source-apps/README.md).

The [clean evidence](../evidence/pbs-linux-arm64-python-source-apps-2026-10-12/README.md)
uses implementation `d3ddac3`: six application traces and 42 fresh regressions
pass both live checks and compressed replays. All 34 source-app and 30 existing
CLI controls match exact results, and all 198 hostile source-app edits reject.
Mac/Linux source workspaces pass 366/367 tests and Clippy; optimized GNU shared
Python/probe builds pass 87 tests, with 238 policy, 16 importer and seven entry
protocol tests passing on both interpreters. The evidence distinguishes complete
write coverage/seals and visible ELF bytes from complete payload hashing, which
is verified separately against the pinned inputs.
