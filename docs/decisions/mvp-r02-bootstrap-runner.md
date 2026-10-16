# Standalone native owned-bootstrap runner

This is the first nontracing integration of the reviewed bootstrap components.
It does not change capture-native.c, raw readers, trace policy or full R02/M2
acceptance. No root/VM execution is authorized by this implementation step.

## Closed native entry and source dependencies

A process-local C runner and thin CLI expose exactly:

```
owned-bootstrap-native --request /absolute/request.bin --output /absolute/NEW
int nr_native_run_once(const char *request_path, const char *output_path);
```

The native entry always uses real TC/TD/TE/BIO/BS/BA operations. Linux rejects as
unsupported before fork or endpoint creation; Darwin requires real/effective UID0
before opening input/output. There is no elevation, sudo, environment-selected
adapter, test-identity flag, alternate executable/profile/hash argument or runtime
catalog file. The CLI performs one attempt and exits after cleanup.

Initial implementation is based on integrated885660b (TC/TD/TE/BW/BIO, BR49b44cf,
NPdf062f15 production plus driver-only53e9a1a/ac36669, BS83148d9+12fff2f).
BA3f6d388 is a frozen dependency pending independent approval/integration; no
native admission claim is made by selecting those source bytes.

Normal-user integration controls are a separately linked source-isolated driver.
Identity-preserving TC callbacks only accept actual current IDs/exact native
ordered groups and do no mutation; readbacks remain native. If that group vector
cannot meet TC's bounds/primary-first order, report the native test unavailable.
Synthetic declarations remain pure model controls. Neither test driver nor its
fixture/admission assumptions can be selected or linked by the root CLI.

## Compiled catalog and reproducible build interface

A generated **build-time** constant supplies:

```
struct nr_catalog {
    uint64_t probe_bytes;
    struct ba_deployment deployment;
    uint8_t probe_sha256[32], probe_sources_sha256[32];
    uint8_t runner_static_sources_sha256[32], build_recipe_sha256[32];
    char build_id[65], leaf[65];
};
const struct nr_catalog *nr_compiled_catalog(void);
```

Default unconfigured builds return NULL and fail closed before setup/fork. The
native build links a generated catalog translation unit instead of the default.
Only one reviewed context-probe build is supported. Leaf is exactly
`context-probe`; build-id follows BA's closed ASCII component grammar. Probe
size is1..4MiB. Its independently inspected build has only selected platform
dyld/libSystem linkage, no script, RPATH/plugin/user loader route. No general
Mach-O parser is added. The root/Data device+FSID constants must come from a
retained read-only preflight on the actual target guest; there is no discover-
and-accept or caller override. Host/synthetic catalogs support only clearly
labelled local compile/model checks, not root-positive admission.

Canonical catalog bytes GLUENC01: magic8; versionu16=1 at8, header-lengthu16=192
at10, exact-totalu32 at12; probe-sizeu64 at16; root deviceu64 at24, fsid i32x2 at32;
Data deviceu64 at40, fsid i32x2 at48; four SHA256 fields at56/88/120/152;
build-id/leaf byte-lengths u16 at184/186; reserved188..191 zero; exact tail
build-id then leaf bytes with no terminators. FSID signed values retain their
u32 wire bit pattern. SHA256 of those canonical bytes is calculated internally
with Darwin CommonCrypto and must match BR's selected catalog digest. Static
source/build-recipe digests exclude the generated catalog and resulting binaries
to avoid self-reference; final native binary identity is recorded externally by
the kit builder. The held admitted probe is hashed internally to exact catalog
size/SHA. No input hash alone authorizes code.

The protected deployment invariant includes independently reviewed fresh-file
provisioning with no historical writable alias and no concurrent privileged
namespace/mount/content/metadata change. Root ownership/no ACL/no unprivileged
write route cannot prove that history. The runtime keeps the admitted handles,
but final pathname exec relies on that explicit invariant; no invented fexecve
or two-stat race-proof claim exists.

## Bounded paths, request, cwd and private output

BR's exact canonical bytes are read once into bounded immutable parent storage,
with exclusive ownership of the consumed snapshot. Hash them internally via
CommonCrypto, then derive exactly `[exe,"--request-sha256",lowercase64hex]`.
No ambient target environment: envp is `{NULL}`. Reject trailing/partial/unknown
request data; never reparse a mutable file in the child.

Executable bytes must equal BA_PREFIX+compiled-build-id+`/context-probe` before
real BA admission. Cwd must equal the exact build-id ancestor path (component6),
and request dev/ino must equal that held directory's checked metadata. This is
an explicit use of the checked ancestor, not generic cwd or catalog-file
admission. Child performs absolute chdir only after real TC/readback; never use
fchdir or hand an admission/cwd directory FD to the target. TD closes them all.

Output supports only `/System/Volumes/Data/private/tmp/<new ASCII name>`.
Check its held fixed ancestor chain against the compiled root/Data mount facts,
with root ownership/populated FILESEC scalar equality/no ACL/no symlink/no unsafe
mode; tmp alone must be exact root-owned sticky1777. Create NEW0700 exclusively,
open it without following links and verify name/opened inode equality. Fixed
files use openat O_EXCL|O_NOFOLLOW|O_CLOEXEC0600. No overwrite, arbitrary resolver,
export option or target directory capability. A later separately reviewed batch
may export only closed finalized files to a new evidence directory.

## Preparation, owned child and complete READY comparison

Use fresh BS storage once. Parent admits SIGCHLD default/no autoreap and no
custom handler, snapshots/blocks catchable signals before fork, temporarily
ignores PIPE and verifies policy. All failures retain original parent error;
cleanup attempts BS restoration once after channel/child resolution, preserving
its separate first restoration error and verified outcomes.

Prepare deliberate read-only /dev/null, distinct exclusive stdout/stderr sinks,
private GO/status pipes with all4 ends NONBLOCK+CLOEXEC, and TE's distinct>=3
owned copies. No worker/watchdog exists. After fork parent closes every child-
side alias and all sink writer aliases; child TD closes every controller/admission
source spare. Only the child writes final probe stdout/stderr. Parent may reopen
these files read-only after reap. Close errors never retry/guess ownership.

Child, with setup signals blocked: check original controller relation; checked
setpgid/getpgrp; BS reset/readback/altstack; TE map; real TC/drop/readback; absolute
permission-checked chdir+stat compared to admitted ancestor; TD exact five-FD
closure/rescan; BS check; native-width readbacks and canonical READY256. Flags
come from actual TC/TD attempt outcomes and must equal3 in this topology.
Parent owns the actual unreaped fork child and independently compares every BR
READY observation: bindings/digest, four IDs, ordered/count/unused groups,
intended cwd, all keep numbers, policy digest and flags3. No matching codec alone
can send GO. Group creation is checked in both processes, never used as arbitrary
or descendant containment.

SEND_GO attempts exactly one bound64-byte BIO write and once-only writer close;
mark possibly-released before attempting it, even if late/failed. Never replay.
SIMULATED_PROVIDER_FAILURE closes with no bytes after accepted READY; it is a
nontracing simulation, not provider evidence. Child requires full bound GO+EOF,
checked gate close and BS release/pending/readback before ATTEMPT256 and execve.
On exec return save errno, emit ERROR2 if possible, _exit. Every child error exits
without retry, rollback or target launch. New signals can terminate after unmask;
there is no atomic signal-to-exec guarantee.

## Status, probe, wait and exact output vocabulary

Retain raw status records and every confirmed incomplete BIO prefix, at most
three256-byte records plus a one-byte extra probe. Decode only on-time complete
records. Zero-prefix record-read truncation is only a candidate boundary EOF; require
a second bounded BIO require_eof with the same absolute deadline before accepting
it, since record-mode zero read lacks a post-read clock check. Late observed EOF
is failure. Nonzero prefix is incomplete. ATTEMPT can legally be followed by ERROR2, so do not prematurely
require EOF there. Terminal ERROR requires EOF and rejects any extra byte.

A complete NP256 report and normal direct-child exit0 are additionally required
for a consistent owned-probe diagnostic. Decode against request digest and
compare actual PID/PPID/PGID to the known child/controller/group, all IDs/groups,
cwd to request/READY, fd0/1/2+flags to declared stdio, and native report policy/
empty environment/root-regain EPERM/post-attempt IDs. NP validity alone does not
compare those requests. Probe stdout must be exactly256 bytes; stderr empty.

Closed outputs: request.bin, status.bin, probe.stdout, probe.stderr, result.pending
(failure artifact only) and result.json. Final metadata is written to pending
only after other writers/resources and owned child are resolved; the held private
dir is closed/checked before serialization. After pending write+close succeed,
renamex_np(RENAME_EXCL) promotes it over the already-verified absolute physical
path under the fresh root0700/sticky1777/no-other-privileged-mutator invariant.
This is not generic pathname race-proofing. Close/write/rename failure leaves no
final marker, with no retry. No close or fallible finalization follows promotion.
Consumers additionally require normal CLI exit0: a fatal signal after rename can
leave result.json, so its existence alone never establishes a completed result.
The JSON has a closed schema with separate first parent failure, child ERROR,
protocol fault, confirmed prefixes/counts, GO action/attempt/possibly-released,
READY comparison, NP comparison, exact wait/reap, signal-restoration and file/
catalog/source identities. Store path bytes as hex if needed, not unsafe JSON
strings. `tracing=false`, `exec_proved=false`, `full_acceptance=false` always.
CLI0 means only consistent closed-probe diagnostic, never exec proof. Withheld
GO/reported failure/incomplete/invalid protocol is nonzero with retained evidence.

One absolute checked CLOCK_MONOTONIC deadline (request<=10s) covers attempt;
BIO keeps it unchanged. Cleanup has a separate<=2s deadline. WNOHANG wait checks
time even after EINTR, tracks live-unreaped/reaped state and never signals a
reaped/forged PID, group or pid0. On postfork failure close GO, kill only actual
unreaped child, reap once and record unresolved cleanup as failure. The reviewed probe has no descendants and no postexec alarm. Only actual owned
parent and external test deadlines apply; no timer is silently added. There is
no controller-death/arbitrary-child containment or uninterruptible-kernel
deadline guarantee.

Finalize only after all writers closed, owned child reaped, outputs stable and
both parent signal restore outcomes checked. Status EOF/ATTEMPT without reported
exec error is never successful exec. The report is an owned fixture self-report,
not kernel exec/credential/object/Mach-effects attestation.

## Verification and adoption boundary

Implement catalog/closed path/output and comparison controls first, then bounded
native lifecycle and distinct model/unprivileged driver tests. Test every status
phase, valid-but-mismatched READY/NP, partial/extra/leaked-writer/late GO, failure
at each helper boundary, once-only close, mask restoration, cleanup ownership and
unconfigured/nonroot/Linux refusal, and zero-prefix EOF observed after the
attempt deadline. CommonCrypto goldens use independent hashlib.
Do not run root/VM tests here. Native positive protected admission, actual Darwin
credential drop and later tracing require separately authorized execution and a
fresh reviewed kit built from actual guest facts. No source fixtures/runtime
payloads or old evidence bytes are modified by this diagnostic implementation.
