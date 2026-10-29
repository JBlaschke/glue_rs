# Scalar fcntl descriptor semantics

`bsd_fcntl_semantics.py` supplies exact source rules for four scalar commands
through both `fcntl` and `fcntl_nocancel`: F_DUPFD (0), F_GETFD (1), F_SETFD (2)
and F_DUPFD_CLOEXEC (67). It interprets command-specific argument/result relations
and emits conditional descriptor rules. It does not update a descriptor table,
identify objects or grant native/extraction acceptance.

```python
from bsd_fcntl_semantics import decode_owned_fcntl_semantics

result = decode_owned_fcntl_semantics(
    program_bytes, probe_inventory_bytes, error_bytes, raw_event_lines,
    owner_pid=owner_pid, target_pid=target_pid,
    contract_bytes=exact_contract_bytes)
report = result.to_dict()
```

One strict `pair_raw_owned` call consumes the original immutable static bytes and
bounded event iterable. Only after complete transport validation and closed,
unambiguous pairing does the module reuse identity-checked private entry ABI
and outcome helpers. It never reconsumes the stream through their public APIs.
An orphan, incomplete, malformed or ambiguous stream returns no prefix.

Every BSD pair has a row linking its original pair index and correlation
ordinals. Original phases, all words, source requirements, Mach pairs and
lifecycle records stay in the frozen source. Non-fcntl calls, unsupported
commands and unknown names stay explicit with unmodeled intent; they are not
ignored or declared harmless. Failed paired attempts remain visible.

## Exact supported commands

| Command | Scalar interpretation and successful result | Conditional rule |
| --- | --- | --- |
| F_DUPFD | Captured long must fit the supported signed32 minimum subset. Success needs `0 <= minimum <= returned fd`, with returned fd distinct from the source. | Alias finishdup's kernel-chosen shared fileglob. Allocate the lowest free descriptor at or above the minimum at the allocation point; clear close-on-exec. |
| F_DUPFD_CLOEXEC | Same minimum/result domain. | Same allocation/alias relation; set close-on-exec on the new descriptor. |
| F_GETFD | Command branch ignores its argument and returns exactly 0 or FD_CLOEXEC. The complete argument remains retained. | Observe the chosen fileproc's descriptor close-on-exec bit at the kernel read point. |
| F_SETFD | Test only FD_CLOEXEC in the full already-typed signed64 argument. Other bits are retained and ignored by this command branch. Success has primary result zero. | Set/clear that fileproc descriptor bit. Guarded clearing can fail. |

Supported successes also require a nonnegative source fd and zero secondary
result. Both pinned LP64 dispatchers initialize result slots, and these four
branches modify only the primary or leave return storage unused. Typed results
are preserved unchanged when a relation fails.

The minimum subset deliberately excludes captured longs outside signed32 range;
no truncation is performed to guess the kernel's explicit narrowing. Negative
canonical minima remain failed requests when an error is observed, and cannot
have supported successful allocation. Signed negative arguments such as `-1`
for F_SETFD retain their bits: its low bit requests setting close-on-exec.
This source-defined bit test is not a repair of noncanonical argument typing.

The flag commands act on `fileproc.fp_flags`, not `fileglob` flags shared by
aliases. Conditional duplication relates to the fileglob actually chosen by
`finishdup`, not an assumed entry-time fd association. No rule supplies a
generation/object identity, initial flag state, global alias update, effect
linearization or slot state at return. Even an argument unused by the command
branch remains visible to earlier source policy/audit paths.

A `source-consistent` row means the scoped scalar relations hold. Object/resource
preconditions and native origin are still unproved. Every conditional rule lists
required kernel-lookup, descriptor lifetime and ordering witnesses.

## Unsupported commands and failures

F_GETFL/F_SETFL, lock/pointer commands, filesystem-specific and unknown command
numbers remain unsupported. F_GETFL needs the full status-flag and event-only
policy model. F_SETFL can update shared flags before driver ioctls fail and can
perform partial rollback; an unsupported row retains that uncertainty. No
family-wide read-only or safe-control permission is inferred.

A kernel error produces no conditional rule and no absence-of-effects verdict.
Duplication errors retain allocation reservation/finishdup association gaps.
Failed flag queries/changes retain descriptor lookup, guard, lifetime and
concurrency uncertainty. Noncanonical fd/command words and unsupported result
frames retain their original bits, attempted command and reasons. Invalid fd
values never suppress a recognized flag-change/allocation attempt.

All output remains immutable and has `status: incomplete`,
`native_abi_calibrated: false`, `successful_effect_ordering: false`,
`state_feed_eligible: false` and `full_trace_acceptance: false`, including a report
with no BSD pairs. Numeric descriptors 0/1/2 have no output exemption. No synthetic
state unit, state-engine update, pointer dereference, collector, capture/export
admission or SIP change occurs. `to_dict()` creates detached nested containers.

Fixed executable helpers are checked before ordinary imports, assuming a stable
trusted checkout. After import, the API accesses only caller bytes and their
bounded iterable; there is no asset fallback, subprocess or network operation.

## Source evidence

The fixed source profile uses Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`; six retained source identities are
included in `SOURCE_IDENTITIES` and every result. Physical source lines:

- [Command constants](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/fcntl.h#L278): 278–280,397 and FD_CLOEXEC at401. Status conversions at240–245 belong to the deferred flag model.
- [fcntl routing and scalar branches](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_descrip.c#L2769): cancel wrapper2565–2568, command routing2769–2863 and common exit2654–2658. Shared-flag/ioctl behavior is at2865–2905.
- [Duplication helpers](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_descrip.c#L516): finishdup516–578, zeroed allocation1107–1113 and fdalloc1177–1214.
- [Descriptor storage](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/file_internal.h#L102): flags102–109 and separate fileproc/fileglob fields120–125. The retained `file.h` is part of the deferred status-flag source audit.
- [arm64 result initialization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/arm/systemcalls.c#L130): 130/136; [x86_64 initialization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/i386/systemcalls.c#L365): 365–366.

Existing raw readers/contracts, scalar/outcome helpers, descriptor semantics,
collectors, native kits and state engines remain unchanged. Public source
agreement and portable synthetic controls do not replace native ABI calibration
or complete Darwin oracle acceptance.

Run the portable controls from the repository root:

```sh
python3 fixtures/mvp/macos-trace/bsd-fcntl-semantics/test_bsd_fcntl_semantics.py -v
```
