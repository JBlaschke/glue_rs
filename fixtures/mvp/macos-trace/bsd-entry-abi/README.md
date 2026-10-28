# Source-defined BSD entry ABI

`bsd_entry_abi.py` types declared BSD entry arguments through a closed public-XNU
LP64 profile. It consumes the strict owned raw observer itself, retaining failed
and unpaired entry attempts and every BSD return phase. It does not call the
closed-call pairer or infer filesystem effects from a subsequent result.

```python
from bsd_entry_abi import decode_owned_bsd_entries

result = decode_owned_bsd_entries(
    program_bytes, probe_inventory_bytes, error_bytes, raw_event_lines,
    owner_pid=owner_pid, target_pid=target_pid,
    contract_bytes=exact_contract_bytes)
report = result.to_dict()
```

The API takes immutable static bytes and a bounded byte-line iterable. Complete
strict transport exhaustion and exact contract validation precede all typing;
a late malformed record or iterator failure produces no prefix. Existing raw
observer bounds remain. The API accepts no predecoded phases, caller profile,
ABI assertion or state units.

The frozen result retains the full `OwnedBsdObservations` source. Each entry row
has its original `phase_index` and ordinal; argument indices and selected role
names point into that phase's original raw words and source requirements. Only
the declared arguments are typed. Other captured register words remain in the
source and do not become invented arguments. Unknown entry names receive an
unsupported row with no declared arguments. A noncanonical argument retains its
type information and explicit reason, with no typed value; its original bits
remain in the source. Other arguments of that request stay visible.

Return phases, including unsupported/orphan returns, remain in the source.
The observer retains **aggregate Mach and lifecycle counts**, not their full
bodies; this API does not manufacture or reconstruct those bodies.

## Fixed LP64 type rules

The pinned 161 declarations contain 530 argument positions and 49 exact type
spellings. Their closed aliases yield these classes:

| ABI class | Positions | Rule |
| --- | ---: | --- |
| signed32 | 189 | `int` must be canonically sign-extended into its uint64 record. |
| unsigned32 | 53 | `u_int`, `unsigned int`, `uint32_t`, `uid_t`, `gid_t`, `socklen_t`, `mach_port_name_t`, `sae_associd_t` must be zero-extended. |
| signed64 | 11 | `long`/`off_t` retain their full signed64 value. |
| unsigned64 | 35 | `u_long`, `size_t`, `size_ut`, `uint64_t`, `user_size_t` retain all bits as unsigned64. |
| opaque-address64 | 242 | `user_addr_t`, `caddr_t`/`caddr_ut` and the 30 exact pointer spellings retain their full numeric bits. |

There is no generic rule accepting arbitrary future pointer/type spellings.
The generator's `(int64_t)` spelling does not itself imply signed source data:
`gid_t`, `socklen_t`, `mach_port_name_t` and `sae_associd_t` use that branch but
have underlying unsigned32 types. Their C conversion still zero-extends.

No bits are truncated to repair noncanonical widening. Address words are not
dereferenced, untagged or validated as actual memory. Declared `int` mode/flag
words keep their source width rather than being narrowed to an anticipated API
type. Numeric descriptors and `dirfd=-2` acquire signedness only; they establish
no descriptor generation, cwd binding, close-on-exec or output exemption.
Offsets and sizes acquire no operation-specific range or successful-effect claim.

All results have `status: incomplete`, `native_abi_calibrated: false`,
`state_feed_eligible: false` and `full_trace_acceptance: false`. Typed source
values are not native ABI calibration. Nested collections are immutable and
`to_dict()` creates fresh containers. Fixed executable helper hashes are checked
before ordinary imports, which assume a stable trusted checkout. After import,
only caller bytes and their iterable are accessed; no asset loading, subprocess,
network operation, native collector, state engine or SIP change is invoked.

## Source evidence

Sources are fixed to Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`; exact SHA256 identities of all 19
supporting sources are carried by `SOURCE_IDENTITIES` and each result. Physical
source lines are:

- [Entry conversions and generated argument aliases](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/makesyscalls.sh#L512), lines512–530 and551–611.
- [arm64 user-width aliases](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/arm/types.h#L77), lines77–97; [x86 user-width aliases](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/i386/types.h#L100), lines100–111.
- [Group/user/offset base types](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/_types.h#L83), lines83–98; their public alias headers are separately pinned.
- [arm machine scalar types](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/arm/_types.h#L127) and [i386 machine scalar types](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/i386/_types.h#L151) define `socklen_t`'s unsigned32 base.
- [Socket association identifier](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/socket.h#L322), line322; [Mach port-name alias](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/port.h#L109), line109, with pinned machine `vm_types.h`/`_types.h` defining the unsigned32 `natural_t` chain.
- [Character-address aliases](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/_types/_caddr_t.h#L30), lines30–36; [size aliases](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/_types/_size_t.h#L60), lines60–68.

These declarations do not attest the installed kernel or its provider. Pointer
snapshots, path/FD/backing/port identity, process/image transitions, operation
semantics and extraction policy still require implementation and native evidence.
Existing collectors, raw readers/contracts, assessment/inspector, native kits and
state engines are unchanged.

Run the portable controls from the repository root:

```sh
python3 fixtures/mvp/macos-trace/bsd-entry-abi/test_bsd_entry_abi.py -v
```
