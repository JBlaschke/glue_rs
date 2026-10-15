# Out-of-tree evidence retention (integration)

Policy record, 15 October 2026. Adopted after the
[status review](../reviews/2026-10-15-status-review.md) measured 480 MB of
evidence in the working tree and 289 MB of Git history after eight days, with
14,441 of 14,849 tracked files under `docs/evidence`. Each step adds a bundle
of tens of megabytes, dominated by compressed complete syscall traces, and
reruns every historical fixture. At that rate the repository becomes slow to
clone and review long before the platform gates close.

## Rule

Evidence remains mandatory and unchanged in content: commands, source and
artifact identities, environment, complete traces, outputs, statuses and
replay results, as `docs/fixtures.md` requires. What changes is where the
bulk bytes live.

From this record on, a new evidence directory under `docs/evidence` commits
only:

- `README.md`, the narrative, commands and claims;
- every `*.sha256` and `SHA256SUMS*` inventory, at any depth;
- `bundle-payload.sha256`, a complete inventory of every published file,
  generated at publication from the actual bytes;
- `bundle.json`, naming the release tag, asset, size and SHA-256 of the
  published archive.

Everything else in the directory, including traces, launchers, archives,
native images, logs and receipts, is packed into one gzip tar archive and
published as an asset of a GitHub release tagged `evidence/<directory name>`
on the repository. Release assets are not Git history; cloning does not fetch
them, and they can be retrieved individually.

## Mechanism

`scripts/retain-evidence.sh docs/evidence/NAME` verifies the author's
inventory, writes `bundle-payload.sha256`, packs the payload deterministically
and reports the archive identity. Without `--publish` it changes nothing in the
tree. With `--publish` it creates the release, uploads the asset, writes
`bundle.json` and removes the payload files from the working tree so that the
same commit records the publication and the removal.
`scripts/fetch-evidence.sh docs/evidence/NAME` downloads the asset, checks its
size and SHA-256 against `bundle.json`, unpacks it in place and verifies every
file against `bundle-payload.sha256` and the author's inventory. A bundle
whose asset fails any check is not evidence; the fetch aborts.

The integrity anchor is the committed hash set, not the release. Release
assets can be replaced by repository administrators; the committed
`bundle.json` and inventories make any replacement detectable, and reviewers
must fetch through the script rather than trusting an asset by name.

## Existing bundles

The 24 bundles already committed stay where they are. Moving their files out
of the tree would not shrink clones, because the bytes remain in history, and
rewriting history would invalidate every merged `codex/*` branch and pull
request reference. The repository owner may later choose a one-time rewrite
with `git filter-repo` or `git lfs migrate` after publishing those bundles
with the same script; that decision is explicitly deferred.

## Limits

The scripts need the `gh` CLI authenticated with repository write access and
assume a public GitHub repository. There is no continuous integration, so
publication and verification remain manual steps of the fixture protocol.
This record does not change the archive, manifest or runtime contracts and
does not relax any trace requirement.
