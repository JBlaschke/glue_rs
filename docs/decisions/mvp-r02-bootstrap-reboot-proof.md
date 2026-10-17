# R02: register a fresh deployment observation after the VM reboot

The SIP-enabled owned VM reboot changed its observed APFS device/FSID tuples.
The earlier registered observation and frozen kit02 bind device `16777230`,
root FSID `[16777236,26]` and Data FSID `[16777230,26]`. The fresh inspection
observes device `16777231` for both mounts, root FSID `[16777236,27]` and Data
FSID `[16777231,27]`. Directory inode and ownership observations alone cannot
make these different mount identities interchangeable.

Keep complete literal device/FSID admission. Do not mask a word, normalize a
device number, accept either boot's tuples in one catalog, or add a runtime
trust/profile override. The old kit's request writer refused before the first
case after installation completed. Its protected prefix already exists and
must remain untouched; it is neither repaired nor retried. The observed tuple
mismatch explains the refusal consistently with the source, without claiming a
branch trace of that request-writer execution.

Append the new actual proof only after independent verification of its complete
inventory and inspector provenance. Retain the earlier registry entry unchanged
as historical evidence. The new proof must come from the unchanged inspector
with direct six-file source provenance `d2bd45d`; the inspector kit's older
`source_manifest_sha256` field still names its whole producer inventory, not
that narrower source closure. Raw proof and audit logs stay outside Git.

The 34 production/controller source hashes, compile lists, source revision
`863e3279cb701676cc90d32507f7513742abd695` and builder parser remain unchanged.
A new proof supplies a new build-ID input and literal catalog mount tuples.
Using it requires a fresh reproducible kit, independent review, a new protected
prefix and a separately reviewed packet; registration does not relabel kit02 or
approve that later packet. No native code, admission policy or bootstrap-VM
approved-kit constants change in this step.

Focused controls exercise multiple independently named proof entries and retain
both complete mount tuples through parser/catalog generation. They use explicit
synthetic parser data and do not execute guest binaries or establish actual guest
facts. Registering actual observations does not prove bootstrap completion,
kernel exec, tracing, no extraction or full R02/M2 acceptance.

The closed actual proof is `glue-bootstrap-deployment-v1-Pf78Qtnu`, with manifest
`ca2e111c6f6abcdb94ca8b6851b464a95f7cea0792990aec7d60b995ab1be09f`.
Its independent review manifest is
`ac654ed36717a52fdbeadd3fcd09853265b0bcdc117befc2efe4836156bb1cc8`.
The review verifies the complete proof, all six exact command argv/status pairs,
unchanged inspector binary/wrapper/toolkit and direct six-file Git provenance.
All six commands returned zero, including strict signature verification and the
exact SIP-enabled status. This is a closed deployment observation, not a
bootstrap or tracing run.
