# R02: bounded F_GETFL status conversion

Status: staged source diagnostic, 29 October 2026. Native Darwin/R02 acceptance
remains incomplete. This is a separate helper; the reviewed four-command fcntl
helper, raw readers, contracts, configured source closures and runtime policy v2
remain unchanged.

`bsd-fgetfl-semantics/bsd_fgetfl_semantics.py` pairs original immutable raw
inputs once, retain every original phase, and use private fixed decoders. Its
public factory accepts no normalized capture, flag constants, process-policy
selection or authority assertions. Existing F_DUPFD/F_GETFD/F_SETFD/
F_DUPFD_CLOEXEC rows retain their existing type and exact behavior.

The additional command is F_GETFL (3), for fcntl and fcntl_nocancel. Its argument
is an ignored signed64 long in the command branch; the complete value and all
tail words stay visible. Descriptor lookup and earlier MAC/audit processing are
not elided. A success needs a canonical signed32 primary, initialized zero
secondary and nonnegative descriptor. These are necessary conditions, not proof
of an actual fileglob state.

The pinned branch reads unsigned `fp->f_flag`, conditionally reinserts FREAD in a
local copy for O_EVTONLY under process policy, then applies OFLAGS. OFLAGS masks
O_ACCMODE when FEXEC is present; otherwise uint32 subtraction precedes storage in
int32. The result therefore supplies a uint32 bit view and algebraic preimages,
not the observed raw PROC_PIDFDVNODEINFO flag value. Every event-only policy
alternative remains conditional; raw transport observes neither process policy
nor the original/adjusted fileglob flags.

Only an explicit conservative subset receives a conditional conversion rule:
FREAD/FWRITE/FREAD|FWRITE with optional FNONBLOCK/FAPPEND, optionally FWASWRITTEN
when FWRITE is present, and FEXEC alone. This demonstrates that some source
construction exists, without identifying the actual source state or object.
Other flags/combinations retain their exact bits and arithmetic alternatives as
unresolved. Unknown bits are never masked away to obtain permission. FMASK is an
open-time retention mask and is insufficient as the entire live fg_flag domain.

Core source is Apple XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea. Byte hashes and
physical anchors are frozen in the helper/README. Supplemental official pages
audit open1's FMASK plus O_EVTONLY/data-protection retention and FWASWRITTEN,
write's FWASWRITTEN, UNIX socket GC's FMARK/FDEFER, and relaxed process-policy
reads. Their full original bytes/hashes were not available through the public
browsing interface, so no full-file hash is claimed for those pages. Reachability
of arbitrary combinations, all flag writers and the installed native ABI remain
unproved.

No conditional rule establishes at-return flags/backing identity, fd generation,
alias-wide state or successful-effect ordering. F_SETFL stays unsupported,
including shared updates before driver-ioctl error and partial rollback. Unknown
commands receive no family-wide safe-query permission. No numeric fd0/1/2 output
exemption follows. All native ABI, state-feed, extraction/output and full-trace
acceptance fields remain false and report status remains incomplete.

Portable controls construct physical original-byte records independently and
test single-pass/refusal behavior, both command names, unchanged scalar rows,
flag-domain limits and dependency identities. All 24 test methods passed under
Python 3.15.2 and 3.9.6. These include 42 ordinary-subset command vectors (21 per
name); they are not 42 distinct test methods. An initial 22-method pilot had one
test-only misspelled mock target; its failure log is retained. No native,
provider or target run occurred for this source step. Supplemental source hashes
and the split sync-header numeric values remain explicit audit gaps.
