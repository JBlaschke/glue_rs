# Type owned BSD entry arguments through a fixed LP64 source profile

Status: accepted for source-defined LP64 argument interpretation; native calibration remains open.

28 October 2026. The owned reader retains raw BSD entry arguments and source
selectors, including failed and unpaired attempts. Add a pure ABI-typing API
that invokes observe_raw_bsd on original caller bytes and consumes its complete
strict transport before producing typed entry rows. It does not require a paired
successful return and does not replace entry-side mutation attempts with outcomes.

The exact existing contract contains 161 declarations, 530 declared argument
positions and 49 type spellings. A closed LP64 alias map handles all of them:
189 signed32 ints; 53 unsigned32 arguments; 11 signed64 longs/offsets;
35 unsigned64 sizes/integers; 108 user-address64 arguments; 134 opaque pointer64
arguments. Every row and role links to its original phase/argument index. Raw
trailing register words remain only in the source and are not invented arguments.

Canonical signed32 values must be sign-extended into their uint64 record; unsigned32
values must be zero-extended. Signed64 values decode without truncation; all
unsigned64/user-address/pointer words retain full bits. Pointer addresses remain
opaque, with no dereference, untagging, validity or object inference. Unknown
entry names and noncanonical arguments retain unsupported reasons and no typed
value. No public caller-created facts, alternate profile or calibration assertion
is accepted. Exact helper hashes are checked before imports; after import only
caller bytes and the iterable are accessed.

The generator's cast spelling alone does not determine signedness. gid_t,
socklen_t, mach_port_name_t and sae_associd_t reach its int64 branch but their
actual types are unsigned32; C conversion still zero-extends. The fixed table is
grounded in pinned public XNU headers and generator, not local SDK sizes.

All output stays immutable and serializes to fresh containers. Return phases,
Mach/lifecycle counts and source obligations remain retained. Native ABI
calibration, state eligibility and full extraction acceptance stay false. Numeric
FDs, dirfds, mode/flags words and offsets acquire types only: no FD generation,
cwd resolution, cloexec/output policy, filesystem effects or state update follows.
Guest SIP, collectors, native kits, existing reader/contracts and state engines
remain unchanged. Native calibration and complete object/operation semantics are
separate required gates.

Sources use Apple XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea. Physical lines:
makesyscalls.sh 512–530 (conversion), 551–611 (argument-field aliases);
bsd/arm/types.h 77–97 and bsd/i386/types.h 100–111 (user-width aliases);
bsd/sys/_types.h 83–98 (gid/uid/off aliases); machine _types.h for natural/socklen
and basic widths; socket.h 322 (sae_associd_t); mach/port.h 109 and machine
vm_types.h 95/96 (Mach-name type chain); _caddr_t.h 30–36 and _size_t.h 60–68.
Exact fetched source identities and independent controls must accompany the
implementation; no native run is claimed by portable source typing.
