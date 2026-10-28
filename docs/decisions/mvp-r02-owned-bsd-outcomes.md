# Interpret paired BSD returns through fixed public source rules

Status: accepted for source-defined interpretation; native ABI calibration remains open.

28 October 2026. R02's owned reader can correlate complete provider intervals,
but its existing return facts only check raw duplication and errno agreement.
Add typed kernel outcomes from those pairs without substituting synthetic state
units or another caller-origin assertion.

The new pure API invokes strict `pair_raw_owned` directly on original immutable
static bytes and the bounded event iterable. It decodes only after complete
transport and pairing exhaustion. Exact pinned contract bytes select the source
return type; callers cannot supply predecoded pairs, a profile or calibration.
Source objects retain all BSD/Mach intervals and lifecycle records. Unknown and
unsupported outcomes retain original pairs and explicit reasons.

Use pinned XNU `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` LP64 provider/generator
rules: int results must have canonical signed32 widening; user_ssize_t has a
signed64 primary and zero secondary; user_addr_t has unsigned64 primary and zero
secondary. Positive signed32 kernel errors require the provider's all-ones
failure results. Preserve private positive codes rather than capping at ELAST.
A successful signed -1 remains distinct from a kernel error. ERESTART and
EJUSTRETURN are unsupported control-flow cases; other negative/noncanonical
codes and malformed words remain unsupported. No return proves absence of
partial effects or removes entry-side mutation attempts.

Fixed helper hashes are checked before import. No file/network/process access
occurs in the API after import. All results remain incomplete with native ABI
calibration, successful-effect ordering, state-feed eligibility and full
acceptance false. No object/path/FD/rights binding, state-engine update, native
capture/export admission or SIP change is added. Native ABI calibration and
complete semantics remain separate required acceptance work.

Source evidence: systrace.c lines 216–257/300–341 (primary duplication 275/343),
makesyscalls.sh 648–658 and errno.h 275–293, with exact hashes and public links
in the feature README.
Portable controls use independent serialized raw fixtures and literal return
rosters; malformed/late input cannot yield a prefix. Native testing is not claimed.
