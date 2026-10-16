# Owned guest SIP restoration and approved hosted-CI checkpoint

This small local checkpoint preserves the post-reboot SIP observation from the
explicitly owned macOS test VM and the portable CI result for the exact approved
follow-up branch. It is separate from the [preliminary Darwin calibration
checkpoint](../compact-mvp-darwin-calibration-2026-10-15/README.md) and the
[combined MVP checkpoint](../compact-mvp-2026-10-15/README.md). Both earlier source
inventories and archives remain unchanged. Only narrative and hash inventories
are committed here; no public evidence asset or `bundle.json` exists.

## Exact selection

`local-evidence.sha256` selects ordinary files relative to `/private/tmp` from
only these explicit owned roots:

- `glue-mvp-macos-vm-results/glue-mvp-guest-sip-status-v1-l7QCb5lW`: the exact
  new 36-file read-only status observation, including its original commands,
  command exits/stdout/stderr, wrapper, scope, export plan and hash manifest;
- `glue-portable-darwin-followup-38895660723-20261016`: the frozen exact GitHub
  run/job metadata, progress snapshots, source workflow/script, summary and an
  unsubmitted PR-body draft;
- `glue-portable-darwin-followup-38895660723-lua-review-20261016`: the frozen
  independent read-only review of that portable CI metadata;
- `glue-sip-restoration-independent-review-20261016`: the finalized independent
  restoration review, its exact source driver and read-only review log.

The frozen selection contains 57 ordinary files / 160140 bytes. The source
inventory SHA-256 is
`8afb1bc5ce60559ccc26571a9ea81c1eaec066e2349a54fa579e61777f874967`.

There is no broad copy of temporary directories, credentials, VM disks or
unrelated configuration. The exact status wrapper is already inside the proof
root. Earlier captures, toolkits and the two larger checkpoint payloads are not
copied into this small checkpoint. Original bytes and absolute logical paths
remain unchanged. Historical CI progress/review/draft records correctly retain
SIP-proof-pending language from before the later status observation.

## Observed scope

After the owner-authorized guest-only restoration in Recovery and normal reboot,
the running-guest script records `System Integrity Protection status: enabled.`
exactly, at 2026-10-16T12:14:43Z. It identifies macOS 26.6.2 / build 25G83,
`VirtualMac2,1`, arm64, and non-root UID 501. All ten named metadata commands
exit zero; `run.tsv` records proof exit zero, zero metadata failures, observed
SIP enabled, no setting changes by this script and false full R02 acceptance.
The original proof manifest SHA-256 is
`73c4f5abfd66ac9fdf61d7251b7d7a69cdceb02dc476b796fc790bda042512eb`.
The copied wrapper SHA-256 is
`cff50b1f01edcdbcdecafce7d15577fdfbb10c67c024941cb95670c1e4d84ba0`,
matching the wrapper frozen before the calibration runs. This observation is a
read-only SIP status proof; it does not independently attest every startup
security policy, notarization, physical-host settings or application behavior.

The independent restoration review confirms all original bytes/modes unchanged,
all 35 indexed proof payload files plus their manifest, exact command argv and
empty command stderr. Its review JSON SHA-256 is
`e99c5c804803d7235555fde6afd52ef73aef6b34abd5a857bcd2f388472cc0bc`;
its manifest SHA-256 is
`a25a399fb2b7120b68d7a172d237bd9dd301dc5a4a3b1d55fc1c1180b9261e5d`.
The reviewer executed neither the wrapper nor retained native targets. The
operator-supplied Recovery and normal-boot context is distinguished from the
retained running-guest status observation.

[Portable baseline run 38895660723](https://github.com/JBlaschke/glue_rs/actions/runs/38895660723)
checks exact approved source
[`8567d387f41862883de4ea830042d7408c8412ed`](https://github.com/JBlaschke/glue_rs/commit/8567d387f41862883de4ea830042d7408c8412ed)
on branch `codex/mvp-r04-darwin-followup-status`, event `push`, attempt one.
All nine unique expected jobs completed successfully: baseline, Lua55 and
packaging on native Linux x86_64, Linux arm64 and macOS arm64. Exact final API
responses, rather than a rewritten summary alone, are retained. The metadata
manifest SHA-256 is
`835180043d5290beb3df3ae200d7dbbeab085d6983e61ec806ffa1f6129222c3`;
its independent review manifest SHA-256 is
`d0aeaf3dcb7833eee12369df230ba6bd8dd2335dfcd1a8ed0269048f3ac14ee2`.

Portable CI success and restored guest SIP do not complete the Darwin extraction
oracle, its full corpus/controls/budgets, M2 or public signing/notarization.
Durable evidence publication also remains separate and open. No captured
binary, recorded command or security-changing operation is executed by the
retrospective preparation/restoration checks.

## Prepare and restore

The prepared archive is 22,316 bytes, with 59 exact members (57 selected
source files plus the source inventory and format manifest). Its SHA-256 is
`5fce43e9becae690558e7f84f99757fb45f6e7fb012d796e3671310ff81c5219`;
the committed complete member-inventory SHA-256 is
`8b6fdd997591d52fe17e47c3bff8789858658a37995d17e17b00be5940427e39`.
Prepared metadata SHA-256 is
`f28d9654544a3949ce68f96e9e3862b057cc1f62473b51063269b70393c2c94d`.
Local prepared and restored roots are respectively:

- `/private/tmp/glue-darwin-restoration-checkpoint-prepared-01-20261016`;
- `/private/tmp/glue-darwin-restoration-checkpoint-restored-01-20261016`.

Preparation and restoration completed successfully. A separate local read-only
post-restore verification checked exact membership, every file hash/size/mode,
all four original manifests, all ten proof argv/status records, the independent
proof identities, and all nine exact approved CI job/critical-step results. It
found no extra files or restored byte/mode changes. Its driver, log and report
are frozen at
`/private/tmp/glue-darwin-restoration-checkpoint-verification-01-20261016`,
outside the selected payload. Its report SHA-256 is
`94cf836d795ac2b736fc8cc22f81710ec2eccf9880f576245d4ca0593e178c76`;
its verification-root manifest SHA-256 is
`2157a2196feab8458efd98527cc2009d0c6c86c1c5165863d72300a895ec4ed5`.
No recorded command or target was executed.

An independent restore into
`/private/tmp/glue-darwin-restoration-independent-restore-20261016` reproduced
all 59 members, hashes, sizes and modes. The reviewer also checked the exact
ten-command SIP proof, nine unique CI jobs and critical steps, and workflow/script
bytes against the approved Git objects. The four-file review root is separate
from the frozen checkpoint at
`/private/tmp/glue-restoration-checkpoint-independent-review-20261016`.
Its review JSON SHA-256 is
`31a81d9840286a42ebec96390153eefdd3c6f702091ecd2d53ade37c40f0d17b`;
its manifest SHA-256 is
`6fccab28387a5bd5c026d423d0bfddd49795db1e4795f25801046f95f26d4c38`.
Existing roots remained unchanged; no captured programs or retained argv were
executed. This review adds no full Darwin acceptance or remote publication.

Use the bounded external-root
[retention profile](../../decisions/mvp-r04-external-evidence-retention.md) with
new output directories:

```sh
python3 scripts/evidence-bundle.py prepare \
  --source-root /private/tmp \
  --inventory docs/evidence/compact-mvp-darwin-restoration-2026-10-16/local-evidence.sha256 \
  --output /absolute/new/restoration-prepared
python3 scripts/evidence-bundle.py restore \
  --archive /absolute/new/restoration-prepared/evidence.tar.gz \
  --metadata /absolute/new/restoration-prepared/prepared.json \
  --inventory docs/evidence/compact-mvp-darwin-restoration-2026-10-16/bundle-payload.sha256 \
  --output /absolute/new/restoration-restored
```

The restorer checks the compressed identity, exact member set, sizes, hashes and
ordinary modes before promoting a new output root. Original proof files are
restored below `payload/<original relative path>`; captured absolute strings
are not rewritten. Local preparation is not remote publication or a verified
public fetch.

## Later credential CI result, outside this frozen selection

After separate owner approval, source
`64a4dd2d59e23820553521c5e21484dc81d421f4` on
`codex/mvp-v01-darwin-credential-ci` passed all nine portable jobs in
[run 38903379520](https://github.com/JBlaschke/glue_rs/actions/runs/38903379520).
That later run adds the bounded credential primitive controls to baseline CI;
it supplies no privileged Darwin bootstrap or full extraction acceptance.
Its 13-file metadata root is
`/private/tmp/glue-portable-darwin-credential-38903379520-20261016`, with manifest
SHA-256 `6fa02c86daa6203a5729299fad1000ce4ed8441abfbf855ba46450f154022072`.
An independent raw API/Git-object review is separate at
`/private/tmp/glue-portable-darwin-credential-38903379520-root-review-20261016`,
with review JSON SHA-256
`1d22b449c25fdd5590c673d74a9ca9add17c0e3b1036dd328a2769607202961e`.
Neither later root is part of the 57-file selection or its immutable archive.
The original checkpoint and its hash inventories remain unchanged.
