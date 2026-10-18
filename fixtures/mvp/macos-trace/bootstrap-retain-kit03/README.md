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

`retain` remains disabled: `APPROVED = None` and `RETENTION_ENABLED = False`.
It refuses before reads, imports or writes. A later reviewed source change must
bind the actual physical inspection and independent review, a coordination
receipt and every literal observed tree. There is no CLI, path, profile, hash,
case or environment override. Preparation accepts only an operation and a fresh
absolute host output directory:

```sh
python3 fixtures/mvp/macos-trace/bootstrap-retain-kit03/prepare.py inspect --output /private/tmp/NEW_INSPECTION_PACKET
```

A concrete packet needs independent source/packet review before staging or
launch. The generated launcher creates only its fresh private receipts and a
hash-checked root script stage. It exports actual packet-check argv/cwd/status/
streams, inspector signature, current observation, interpreter and root-phase
receipts after a zero root status. Failure leaves its private receipt and root
stage untouched. Root signatures have combined streams as described above.

When eventually activated, retention verifies the exact completed kit03 stage,
three closed native outputs, trailing-output absence, ordinary completed evidence
and outer receipt, plus every preserved historical checkpoint. It creates one
fixed exclusive private attempt record before one `/bin/mv -n`, so a later packet
cannot retry an uncertain move. It then requires source absence and the same
prefix/build/file device and inode identities, unchanged bytes/modes/rosters and
unchanged preserved checkpoints. The fixed destination is
`/System/Volumes/Data/Library/GlueMVPFixtures-retained-1b85f0ac-da1aaf9a`.
It never repairs permissions, retries, deletes old data or executes a payload.
Actual rename success is separate from source preparation and inspection.

Run `python3 fixtures/mvp/macos-trace/bootstrap-retain-kit03/test_prepare.py` for
bounded source/physical-file controls. Shell syntax checks always run separately
from Perl compilation. The latter first probes `Digest::SHA`, `JSON::PP`, `Fcntl`
and `Errno` through `/usr/bin/perl`, and skips only an explicit missing declared
module; unexpected probe failures fail the control. Both generated Perl programs
are compiled without running their root mains when those dependencies exist.
Native file tests adapt only their temporary
fixture owner's UID to the host account; production guest policy remains 0/501.
The tool proves neither tracing, kernel exec, extraction nor full R02/M2 acceptance.
See [the decision](../../../../docs/decisions/mvp-r02-bootstrap-retain-kit03.md).
