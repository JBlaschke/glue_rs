# External-root evidence bundles

15 October 2026. Extends decision 0030 for explicitly indexed evidence captured
outside the checkout. This is evidence tooling, not application extraction.

`scripts/evidence-bundle.py prepare --source-root ROOT --inventory INDEX
--output NEWDIR` copies only the SHA-256 index's ordinary files to
`payload/<original relative path>`. It preserves captured bytes, Unicode names,
logical aliases and ordinary permission bits. Contained parent-directory aliases
may be resolved beneath the held source-root descriptor; final file aliases,
escaping aliases, hard links, special files and special permission bits fail.
Source identities are checked before and after copying. No receipt or trace is
rewritten, and recorded commands are never executed.

The new directory contains the exact source index, a canonical file manifest,
`bundle-payload.sha256`, deterministic `evidence.tar.gz`, and `prepared.json`.
The preparation record describes actual local bytes; it is not a publication
pointer. The complete payload index covers the manifest, source index and every
captured file. Tar ownership and timestamps and the gzip header are fixed;
ordinary source permissions are recorded. Preparation does not create a release,
write `bundle.json`, or remove original evidence.

`restore --archive FILE --metadata RECORD --inventory INDEX --output NEWROOT`
checks the compressed identity, bounded complete inventory and every archive
member before exposing a newly created output root. Links, devices, duplicate or
unexpected names, path escapes, unsupported modes, oversized metadata and
mismatched bytes fail. Failure preserves any existing output and original
capture. The default bounds are 100,000 files and 32 GiB of uncompressed data;
operators can lower them. Metadata cannot increase these limits. Restored files
live at `NEWROOT/payload/<original relative path>`.

A published external-root pointer uses schema `glue-evidence-bundle-2`, profile
`external-root-v1`, with the same archive identity fields as preparation and a
release repository, tag and asset. `fetch-evidence.sh DIR --output NEWROOT`
dispatches this profile to the strict restorer. Its legacy version-one behavior
is unchanged. The committed complete inventory and pointer remain the integrity
anchor. Publication still requires separate authorization and an actual upload.

Replay locates relative command streams, inventories and trace prefixes below
restored receipt directories. Absolute names inside captures retain their
original meaning as logical trace paths. An external index of receipt locations
can be mapped from its declared old root to `NEWROOT/payload` by the caller;
this does not authorize arbitrary old paths or rewrite captures. Retrospective
replay is supported; a bundle that omits deployed runtime payloads is not a fresh
application execution environment. Darwin diagnostic evidence remains diagnostic
and cannot satisfy the open complete Darwin oracle or M2 acceptance gate.
