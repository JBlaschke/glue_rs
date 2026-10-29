# Conditional F_GETFL status conversion

`bsd_fgetfl_semantics.py` adds F_GETFL (3) through `fcntl` and
`fcntl_nocancel` in a separate fixed helper. The existing four scalar command
rows and public API remain unchanged. This helper's public factory is:

```python
from bsd_fgetfl_semantics import decode_owned_fgetfl_semantics

report = decode_owned_fgetfl_semantics(
    program_bytes, probe_inventory_bytes, error_bytes, raw_event_lines,
    owner_pid=owner_pid, target_pid=target_pid,
    contract_bytes=exact_contract_bytes)
```

The factory makes one complete strict `pair_raw_owned` pass over original bytes.
Only after closed unambiguous pairing does its private `_decode_operation`
reuse fixed identity-checked scalar, entry-ABI and outcome helpers. A future
recipe may use this private decoder after its own single fixed pairing pass;
the public factory never accepts caller-created pairs or normalized captures.
No caller chooses constants, source profile, process policy or authority flags.
After import, only caller bytes and the original bounded iterable are accessed.

Each BSD pair remains explicit. F_DUPFD/F_GETFD/F_SETFD/F_DUPFD_CLOEXEC return
their original frozen row type and behavior. Other BSD calls, unknown commands,
failures, original pair indices/correlation ordinals, all physical scalar words,
Mach pairs and lifecycle phases remain retained. A malformed late record,
orphan/unpaired call or iterator exception returns no semantic prefix.

## Result domain and limits

F_GETFL's branch ignores the full typed signed64 long argument; its original
bits and five undeclared tail words remain retained. Earlier MAC/audit paths can
still see the argument. A successful branch needs a canonically sign-extended
signed32 primary, a zero initialized secondary, and a nonnegative descriptor.
Typing alone proves no reachable flag state.

The branch reads the chosen shared `fileglob.fg_flag` into unsigned `fflag`.
Under O_EVTONLY plus a process-policy condition, it inserts FREAD into that local
copy. OFLAGS then masks O_ACCMODE if FEXEC is present, otherwise subtracts one
with uint32 arithmetic before writing int32 return storage. The report retains
the typed signed32 result and its uint32 bit view, plus *all algebraic preimages*
for those two conversion branches and both event-only policy alternatives.
They are conditional explanations, never observed fg_flag or policy snapshots.

For example result `0x40000000` has four algebraic FEXEC preimages with low bits
0/1/2/3. Only the zero-low-bit construction is in this helper's source-feasible
subset. Result `0x8000` can arise from `0x8001` with process policy clear, or
from `0x8000`/`0x8001` when the process-policy branch inserts FREAD. The report
selects none. Policy can change since open; result `0x7fff` retains the
zero-access event-only `0x8000` subtraction alternative. Event-only combinations
remain unresolved.

The conditional-conversion subset has exactly 21 source constructions:

| Source construction | Count |
| --- | ---: |
| FREAD, FWRITE, or both; each with optional FNONBLOCK/FAPPEND | 12 |
| FWRITE or FREAD\|FWRITE with FWASWRITTEN; optional FNONBLOCK/FAPPEND | 8 |
| FEXEC alone | 1 |

`conditional-conversion` means at least one preimage has a construction in this
subset. It does not identify the actual preimage, object, process policy or
history. Other named/private/unknown bits and unproved combinations remain
`unresolved-conversion`, with exact candidate bits, names and reasons retained.
No candidate bit is discarded to enter the subset. `unknown_bits_uint32` means
outside this helper's audited numeric name table, not impossible in XNU. Results
with no algebraic preimage remain explicit; a canonical successful `-1` remains
a kernel success with uint32 `0xffffffff` and algebraic zero-flags preimage,
whose source reachability is unproved. Unsupported provider typing has no
invented uint32 observation.

The source domains are distinct:

| Domain | Treatment |
| --- | --- |
| `fileproc.fp_flags` / FD_CLOEXEC | Existing descriptor-specific scalar rules; separate storage from status flags. |
| OFLAGS result | Converted signed32/uint32 view; never the raw PROC_PIDFDVNODEINFO flag value. |
| FMASK | Open-time save mask, not the whole live fg_flag domain. |
| Live named fg_flag extras | FWASWRITTEN/FWASLOCKED, FMARK/FDEFER, O_EVTONLY, cache/read-ahead/direct/data-protection/single-writer bits retain exact alternatives. |
| O_NOCTTY | `F_NOCACHE_EXT` reuses this bit privately in live flags; its open-time name alone is insufficient. |
| FFSYNC/FFDSYNC | Pinned fcntl.h aliases split O_SYNC/O_DSYNC headers; their numeric header bytes are unavailable in this audit, so numeric name classification stays unresolved. |
| Open-only flags or unbound numeric bits | Retained without inferring a valid live combination or permission. |

The kernel flag read, process-policy read and other shared-flag writers do not
form an observed atomic snapshot. The process fd lock/I/O reference does not
prove alias-wide flag immutability. No row establishes at-return flags/backing,
descriptor generations, effect ordering, initial state or output authorization.
The local FREAD adjustment is not a shared fg_flag mutation. Kernel errors
retain lookup/MAC/lifetime uncertainty and no absence-of-effects verdict.

F_SETFL and all other commands retain existing unsupported rows. Its shared
flag update can precede driver ioctl failure and partial rollback. No family-wide
safe-query permission follows. Numeric descriptors 0/1/2 have no output grant.
Every report, including an empty-BSD/Mach-only one, has `status: incomplete` and
false native ABI, successful ordering, state-feed, output, extraction and
full-trace acceptance. All output is immutable; `to_dict()` detaches containers.

## Frozen source audit

Apple XNU commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` is the fixed profile.
The six core original-byte SHA256 values below were checked against previously
retained local source bytes; they also remain in every result. Physical line
numbers below refer to those bytes, not transformed browser excerpt numbering.

| Source | SHA256 | Physical anchors |
| --- | --- | --- |
| [bsd/sys/fcntl.h](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/fcntl.h#L237) | `0f93c8918a70ffafe20bfe9c72e671fde67438cbee9f9de8c2f87b5c704c9a9e` | Flags103–196; conversion237–246; command281 |
| [bsd/sys/file_internal.h](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/file_internal.h#L120) | `eecc3ac648ef62b90cefeeb9f13ab82fa166018abedc2a04b64ccf9dcef3fc09` | fileproc120–130; uint32 fg_flag180; separate fg_lflags183 |
| [bsd/sys/file.h](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/file.h) | `382bbfc44dcc94ca7122fc51f0d6b030bc54007ca0069e684217d988ed838c0c` | Retained core header identity; no extra result-domain inference |
| [bsd/kern/kern_descrip.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_descrip.c#L2865) | `480cfed4e987be874bd71fb6933c254adf9fb1f36de8496dee8f351b18da13b1` | f_flag140; unsigned fflag2784; lookup/MAC2794–2823; F_GETFL2865–2877; F_SETFL2879–2905; private writers3588–3647/5852 |
| [bsd/dev/arm/systemcalls.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/arm/systemcalls.c#L130) | `7eb44232e6da37c8e6f5d2317ed5cf1d55d02032410b0ddf7007e4ca7b495df4` | Result initialization130/136 |
| [bsd/dev/i386/systemcalls.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/i386/systemcalls.c#L365) | `7822b31e4f62fcd5f2baeb7fc41fde518b1f44b98fab3908594e18ee2c48426f` | Result initialization365–366 |

Supplemental official commit-pinned sources were inspected through public
browsing, with the following symbol anchors. Full original-file bytes/SHA256
and physical line numbers are unavailable for these pages; none is fabricated:

- [vfs_syscalls.c, open1](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c): access validation, flag retention and FWASWRITTEN construction.
- [sys_generic.c, fp_writev](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/sys_generic.c): nonzero write result sets FWASWRITTEN.
- [uipc_usrreq.c, unp_gc/unp_mark](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_usrreq.c): GC sets FMARK/FDEFER.
- [kern_proc.c, proc_disallow_rw_for_o_evtonly](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c): relaxed policy read.

The subset is a source construction argument conditional on ordinary resource
and object preconditions. This is not an exhaustive writer audit or a proof of
installed-kernel reachability. Core full-file hashes do not establish native
calibration of supplemental source paths or the host.

Run the portable controls from the repository root:

```sh
python3 -B fixtures/mvp/macos-trace/bsd-fgetfl-semantics/test_bsd_fgetfl_semantics.py -v
```

The staged run uses five symlinks to unchanged reviewed helper directories only
for local testing; publication includes this new directory and decision, not
those links. Evidence in the staging root records interpreter versions, exact
control counts, pilot faults and final source/artifact identities. No native
fixture, target/provider trace, VM, security change or source-closure update ran.
