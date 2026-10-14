# Pinned installed Python runtime trees (A7/A10)

Implementation contract, 14 October 2026. Continue from merged `3b83f2f` on
`codex/a7-python-installed-runtime-trees`.

Add an exclusive installed-tree input to the existing Unix build-time host
preparer:

```text
glue python-host --provider host-install --runtime-tree ROOT --output PREFIX [--json]
```

The selected runtime remains stock conventional-GIL CPython 3.13.16 / PBS
`20261009`, GNU Linux arm64. ROOT is an explicit canonical absolute ASCII
installation prefix, not a venv, discovery request or interpreter command.
The reader owns the existing 1,041 library/source/startup-cache prerequisites.
It reads only those selected files; other contents, including executable aliases,
uv markers, headers, native modules and additional caches, are not inspected or
copied. It does not certify the complete input installation. Runtime verification
and all runtime/helper/native-loader/template identities remain unchanged.

On Unix, open every absolute root ancestor and selected descendant relative to
directory descriptors with no-follow directory opens. Open selected leaves with
no-follow, nonblocking read-only flags, require a regular file, check its bounded
size, consume its exact bytes and EOF, and verify its identity before publication.
Input backing bytes and the output parent must stay stable during preparation;
descriptor ownership does not freeze writable files. Reject overlapping input
and output trees, including a symlinked output-parent alias, before payload reads.
Compare the retained input-root device/inode with every resolved output-parent
ancestor before selected reads, so case-insensitive and mount aliases cannot
bypass containment admission. Existing output protection and fixed 0444/0555/1704067200 publication semantics
are the same as artifact preparation.

Two exact selected-content layouts are admitted. The stock layout uses every
existing install-only file identity. The uv layout differs only in the one
`_sysconfigdata__linux_aarch64-linux-gnu.py` source. A genuine offline uv 0.12.23
installation, explicitly configured with a custom download catalog for the
existing pinned unstripped artifact, changes its paths, compiler/tool names,
flag formatting and uv marker. Check the entire observed source against the
checked-in uv 0.12.23 template expanded with the input root; arbitrary Python
source or merely matching fields do not qualify. Restore the separately pinned
original stock source in the output and report both identities and this exact
normalization. Neither source is executed to parse or normalize it. JSON string
escaping supplies the root replacement inside the template's string literals.
The other 1,040 selected payloads must remain exact stock bytes.

This normalization produces the already admitted embedding prerequisites. It
does not preserve uv's build-tool sysconfig configuration or claim that uv's
usual stripped runtimes are accepted. The checked-in original source must match
its existing source pin, and the template's fixed bytes and 27 root substitutions
must be bound in provenance and tests. Any other source/runtime/cache drift
rejects before output creation. A changed uv version needs its own evidence.

Tree provenance distinguishes selected-file inspection from compressed-artifact
inspection. Tree mode has no observed artifact identity, complete inventory or
omitted-file/byte totals; those fields are null. It names the expected upstream
producer pin as a reference, selected files and bytes, input root/layout,
sysconfig input/output identities and whether normalization occurred. Artifact
mode keeps its existing serialized report identities. No runtime-execution,
complete-installation or new full/install-pairing claim is added.

Validate genuine uv installation and product preparation on Mac and GNU Linux,
with independent selected-input/output audits and hostile missing/corrupt/size,
symlink/FIFO, root/profile/option, overlap and existing-output controls. Installation
is a separate build-time operation with its own catalog, uv binary and command
identities. Product preparation must run without the input interpreter or uv and
have one process, no network, and only declared selected input reads plus ordinary
launcher/OS reads. Replay the existing real-package three-provider runtime matrix
and unchanged trace policies; resulting application archives must retain their
previous byte identities. Keep complete compressed traces and bounded evidence,
not duplicate large runtime trees in Git.

Default uv stripped builds, version selection, arbitrary installations/native
packages, other runtime/platform cells and release gates remain separate work.
See uv's [custom installation catalog](https://docs.astral.sh/uv/reference/environment/#uv_python_downloads_json_url)
and [managed Python builds](https://docs.astral.sh/uv/concepts/python-versions/).
