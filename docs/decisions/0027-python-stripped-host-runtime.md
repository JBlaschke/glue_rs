# Pinned stripped Python host runtime (A7/A10)

Implementation contract, 14 October 2026. Continue from merged `a52424c`,
stacking on the retained runtime-tree evidence `421b24f`, on
`codex/a7-python-stripped-host`.

Add a separate `host-install-stripped` metadata application provider for the
official conventional-GIL CPython 3.13.16 / PBS `20261009` GNU Linux arm64
`install_only_stripped` artifact. Pin its compressed artifact and unchanged
upstream shared-library bytes independently. Do not accept an arbitrary stripped
copy or select an image by ABI alone. Existing full, unstripped install-only,
bundled, source-only and native-extension profiles retain their exact identities.

Before admitting this provider, compare complete upstream inventories, selected
source/cache bytes and ELF program headers, allocated sections, dynamic
dependencies, symbol versions, API exports and build ID with the admitted
unstripped image. Stripping may change ELF header section-table fields in the
first load segment; report these differences explicitly. Matching mapped code
and data supports reuse of the embedding bridge, but actual stock GNU execution
is still required. A producer pairing claim is limited to the facts compared.

Expose explicit preparation and template selection:

```text
glue python-host --provider host-install-stripped --pbs-install-only ARTIFACT --output PREFIX [--json]
glue python-host --provider host-install-stripped --runtime-tree ROOT --output PREFIX [--json]
glue python-template --provider host-install-stripped --host-prefix PREFIX --output DIR [--json]
```

Reuse the independently identical 1,037 sources, three stock encoding caches and
trusted archive helpers. Give the runtime image and execution profile distinct
identities. Read and verify the selected library against that profile before
loading it; a missing, corrupt or opposite-profile library must fail without
provider fallback. Portable preparation reads target files as data and never
starts Python, uv or a target executable. The installed-tree reader retains the
existing descriptor, no-follow, bounded-read and overlap contract. Admit stock
sysconfig initially; any relocated installer spelling needs an exact independent
byte comparison before sharing the existing normalization.

Provenance distinguishes the original producer/source inventory from the selected
stripped artifact and library. Keep the earlier reports byte-identical where no
new provider is selected. The new prerequisite tree omits the interpreter and
unselected files, uses the existing exclusive output and fixed mode/mtime
semantics, and makes no complete-installation or execution claim at preparation.

Validate deterministic artifact/tree preparation on Mac and GNU Linux, with
independent output identities and cross-image, missing, corrupt, link, FIFO,
overlap and existing-output rejection controls. Build a minimal deterministic
source/metadata application and run it from relocated read-only prerequisites,
offline and unprivileged, with no input interpreter, uv, headers or producer
staging. Retain complete runtime traces, exact stdout/status and pre-acquisition
CRC/missing/wrong-image controls. Extend the trace contract only for independently
measured image differences; preserve old predicates and replay earlier profiles.

This is one explicit pinned host image. It does not establish uv 0.12.23 default
catalog support (that catalog selects a different PBS release), bundled stripped
startup, version discovery/selection, arbitrary host installations or another
platform. Native lifecycle and real native-package conformance remain subsequent
Python work; A8 Node work remains pending.
