# Completed kit03 preservation

This separate tool prepares fixed owned-VM inspection or retention packets.
It never invokes guest tools from the host. It preserves the original kit03,
packet04, completed batch and run-receipt byte identities in
`completed-files.json`; these are hashes and sizes, without raw captures.

The `inspect` operation is bound to the actual SIP-disabled normal-boot proof
`cd57a36af2a9db11f7d24105485137f7afb2ad9743161db190d7ed6c7ca361fd`
and independent review
`2b3c60fc811ed292cd3e33a33851ba751a1de8c3667c5c2df8f4062000d80dfb`.
Its ordinary launcher checks the unchanged native inspector, complete typed
credential/ancestor/mount observation, guest OS and SIP state before private
sudo authentication. It records the actual `/usr/bin/perl -V` command and both
streams. Core `Digest::SHA`, `JSON::PP`, `Fcntl` and `Errno` are dependencies;
no guest Python installation is required.

The root inventory script reads 32 fixed historical roots and seven parents.
It distinguishes missing entries from observation/permission failures, rejects
symlinks, special files, hardlinks, ACLs, writable entries and mount transitions,
and checks stable file/directory identities around bounded reads. Limits are
2,048 entries, depth five, 128 names per directory, 4 MiB per file, 64 MiB hashed
bytes per pass and a 1 MiB JSON report. It hashes the entire fixed forest twice,
checks the three live kit03 binary pins, and records strict `codesign` status and
argv. Signature stdout and stderr are deliberately combined into `phase.stderr`;
the report labels this combination. No kit payload is executed.

Perl `stat` exposes timestamps at seconds resolution. Its before/after checks
provide consistency checks under the coordinated stable-namespace precondition;
they do not exclude adversarial rapid mutation. The root-owned nonwritable parent
and an exclusive owned-VM fixture slot are required. Stop other privileged tests,
installations and manual fixture changes, including ordinary-user checkpoint
writers, from inspection through retention. A lock file does not exclude another
root process. Record that coordination separately rather than claiming a tool
proved the absence of every possible privileged mutator.

`retain` selects only the actual `kit03-library-intact-tmp-absent-20261018`
profile. Its source-pinned `actual-retention-approval.json` binds inspection
manifest `563731431c81c3ee0790f5451cfad108bacd3b09f1a0c54667615659f0d03724`,
independent review `bd56990e6ddc6a067b52d780c2706d96d1e275425f129737108ac499ff2869d1`,
the exact literal snapshot and the separate root workflow coordination receipt.
All seven protected parents and both five-entry Library installations are bound
by full identities/metadata, rosters and hashes. All 30 named temporary roots
must remain absent. Their absence has no established cause. The inspection did
not observe destination or attempt-path absence; retention checks those fresh.

The same approval separately names immutable historical host kit, packet, batch,
outer receipt and independent actual-result review manifests. Those were checked
before source admission; preparation does not freshly audit those host trees.
They establish the earlier run's bytes and outcomes, without claiming the
historical guest temporary trees remain present or recreating them. The earlier
complete-checkpoint predicate remains separately tested, with no production
fallback between the two profiles. The inventory/launcher and inspection
rendering remain byte-identical to the actual read-only inspection source.
Retain rendering makes exact, count-checked transitions from the hash-pinned
launcher template to checked command-output guards. Every expected-output
credential/platform/SIP check, typed-fixture read, copied-size check and root
bootstrap id/stat/hash check requires the command itself to succeed before
comparing its output. Expected text followed by a nonzero status refuses.

There is no CLI, path, profile, hash, case or environment override. The explicit
unconfigured test fixture still refuses retention before reads, imports or
writes. Preparation accepts only an operation and a fresh absolute host output
directory:

```sh
python3 fixtures/mvp/macos-trace/bootstrap-retain-kit03/prepare.py inspect --output /private/tmp/NEW_INSPECTION_PACKET
```

A concrete packet needs independent source/packet review before staging or
launch. The generated launcher creates only its fresh private receipts and a
hash-checked root script stage. It exports actual packet-check argv/cwd/status/
streams, inspector signature, current observation, interpreter and root-phase
receipts after a zero root status. Failure leaves its private receipt and root
stage untouched. Root signatures have combined streams as described above.

The admitted source does not authorize an unreviewed packet launch. Retention
requires a fresh exact snapshot and three strict signature results, then creates
one fixed exclusive private attempt directory/record before one `/bin/mv -n`.
Its marker is the protected durable Library sibling
`/System/Volumes/Data/Library/GlueMVPFixtures-retain-attempt-1b85f0ac-da1aaf9a`.
An existing entry of any type refuses. The marker survives ordinary temporary
directory loss and remains on every later outcome; no power-loss/fsync or hostile
writer guarantee is claimed. The common inventory's old unused temporary marker
variable is overridden in retain main before its first use, preserving actual
inspection bytes. Retention then requires source absence and the same
prefix/build/file device and inode identities, unchanged bytes/modes/rosters,
unchanged old archive and all30 temporary-root absences, followed by three strict
relocated signatures. The fixed destination is
`/System/Volumes/Data/Library/GlueMVPFixtures-retained-1b85f0ac-da1aaf9a`.
It never repairs permissions, retries, deletes old data or executes a payload.
Actual rename success is separate from source preparation and inspection.

Run `python3 fixtures/mvp/macos-trace/bootstrap-retain-kit03/test_prepare.py` for
bounded source/physical-file controls. The complete actual snapshot fixture is
independent of the approval loader. Controls accept that full baseline before
focused identity/mode/roster/byte/absence corruptions, verify exact approval and
historical bindings, preserve unconfigured/closed-CLI refusals, and check the
durable marker and once-only move ordering. Extracted read-only existence guards
exercise existing directories, files, dangling links and FIFOs in owned host
fixtures; generated root mains are never run. Shell syntax checks run separately
from Perl compilation. The latter first probes `Digest::SHA`, `JSON::PP`, `Fcntl`
and `Errno` through `/usr/bin/perl`, and skips only an explicit missing declared
module; unexpected probe failures fail the control. Both generated Perl programs
are compiled without running their root mains when those dependencies exist.
Native file tests adapt only their temporary
fixture owner's UID to the host account; production guest policy remains 0/501.
The tool proves neither tracing, kernel exec, extraction nor full R02/M2 acceptance.
See the [original decision](../../../../docs/decisions/mvp-r02-bootstrap-retain-kit03.md)
and [observed-state admission](../../../../docs/decisions/mvp-r02-kit03-observed-retention.md).
