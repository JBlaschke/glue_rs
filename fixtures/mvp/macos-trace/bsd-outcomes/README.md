# Source-defined BSD outcomes

`bsd_outcomes.py` interprets BSD return values from the complete, strict owned
call-pair reader. This supplies typed kernel-result semantics for a future
Darwin adapter. It does not bind filesystem objects, order successful effects,
attest the installed native ABI or establish extraction acceptance.

```python
from bsd_outcomes import decode_owned_bsd_outcomes

result = decode_owned_bsd_outcomes(
    program_bytes, probe_inventory_bytes, error_bytes, raw_event_lines,
    owner_pid=owner_pid, target_pid=target_pid,
    contract_bytes=exact_contract_bytes)
report = result.to_dict()
```

The API accepts original immutable static bytes and a bounded byte-line iterable.
It calls `pair_raw_owned` itself. Complete strict transport validation, exact
contract identity and closed unambiguous pairing must finish before any outcome
is decoded or returned. Invalid or incomplete input and a late iterator failure
return no prefix. The existing bounds and lifecycle/exec support limits apply;
caller-created pairs, calibration assertions and alternate profiles are not
accepted inputs.

The result retains the reader's complete frozen `source`: original entry/return
phases, raw words, source requirements, every Mach pair and lifecycle record.
Each BSD outcome identifies its original `source_pair_index` and correlation
ordinals. Mach pairs stay uninterpreted rather than disappearing. Unknown BSD
names and unsupported return shapes keep an outcome with a reason and no typed
result. Nested collections are immutable; `to_dict()` creates fresh containers.

## Fixed source interpretation

The interpretation is for the pinned public XNU LP64 provider, not a claim that
a particular installed kernel or capture matches it. The asset pins 161
selected declarations: 143 `int`, 16 `user_ssize_t` and two `user_addr_t` returns.
The generator maps these types to the provider's result classes. The decoder
uses the following source rules:

| Kernel return code | Typed outcome |
| --- | --- |
| Zero with `int` | Canonically widened signed32 primary and secondary values; high bits are checked, never truncated. |
| Zero with `user_ssize_t` | Signed64 primary, zero secondary. |
| Zero with `user_addr_t` | Unsigned64 primary, zero secondary; no pointer validity is inferred. |
| Positive signed32 | `kernel-error` only with all-ones primary/secondary failure results. Preserve the positive code without an errno-name allowlist or an `ELAST` cap. |
| `ERESTART` / `EJUSTRETURN` | Unsupported control flow, preserving its name and reason. No ordinary result or state transition is manufactured. |
| Other negative/noncanonical code or malformed tuple | Unsupported with original words retained. |

Primary duplication and equality of kernel error/builtin errno are checked by
the unchanged source-contract helper. Its failure stays an unsupported result.
A successful signed result of `-1` remains distinct from a kernel error.
`kernel-success` describes the provider outcome only, not successful filesystem
mutation. A failed return does not erase its entry-side attempt or prove absence
of partial effects. Numeric descriptors 0/1/2 receive no output exemption.

The complete result always has `status: incomplete`,
`native_abi_calibrated: false`, `successful_effect_ordering: false`,
`state_feed_eligible: false` and `full_trace_acceptance: false`.
No normalized state engine, native capture/export admission or SIP operation is
invoked. After module import, only caller-provided bytes and the iterable are
accessed. Fixed helper code is hash-checked before imports; a stable trusted
checkout remains an import precondition.

## Source evidence

All sources use Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`:

- [Provider result conversion](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/dtrace/systrace.c#L216), lines 216–257 and 300–341; primary duplication at lines 275/343; SHA256 `be8c6f8fca90cf95d97bd653056b2ad1c6b1c7a19ca36ba95eac5c848ac4efdd`.
- [Generated return-class selection](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/makesyscalls.sh#L648), lines 648–658; SHA256 `bd44c344880e121277d33c7539c05915a030a52c4ceab7c9f88e54f373293c67`.
- [Kernel control-flow and private codes](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/errno.h#L275), control-flow constants at lines 275–276 and private codes at 279–293; SHA256 `b16e5eb195f153793b14c3826e6b04db945e9ed6a37c5a9046196555bded6906`.

Public source agreement is separate from required native calibration. Paths,
FD/backing/port identities, operation-specific interpretation, process/image
semantics and extraction policy remain unresolved. This feature changes no
collector, raw reader, existing assessment/inspector, state engine or native kit.

Run portable controls from the repository root:

```sh
python3 fixtures/mvp/macos-trace/bsd-outcomes/test_bsd_outcomes.py -v
```
