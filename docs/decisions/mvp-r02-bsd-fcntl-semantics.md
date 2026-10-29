# Interpret four scalar fcntl commands from complete owned pairs

Status: accepted for source-grounded interpretation; native/object admission remains open.

29 October 2026. Extend R02 with exact command rules for F_DUPFD (0),
F_GETFD (1), F_SETFD (2) and F_DUPFD_CLOEXEC (67), through both fcntl and
fcntl_nocancel. Every other command, including F_GETFL/F_SETFL, pointer/lock
commands and unknown values, stays explicitly unsupported. No broad fcntl
family permission or harmless-query exemption is added.

The pure raw-input API calls pair_raw_owned once, then reuses the fixed private
entry ABI/outcome helpers after complete transport and pairing exhaustion.
It accepts no caller-created facts, alternate command constants, profile or
calibration. Original BSD/Mach pairs and lifecycle records remain retained;
every BSD pair has a row. Unpaired or ambiguous input refuses without a prefix.
Failed paired attempts, all argument bits and unsupported outcomes stay visible.

Use the exact pinned LP64 source rules:

- F_DUPFD/F_DUPFD_CLOEXEC require a canonical signed32-range minimum in the
  captured long. Larger/noncanonical minimum values remain unsupported instead
  of guessing the source's explicit int narrowing. Success needs a nonnegative
  minimum and returned fd at least that minimum, distinct from the source fd.
  The conditional alias shares finishdup's kernel-chosen fileglob; allocation is
  lowest-free at or above the minimum at the allocation point. Close-on-exec is
  clear for F_DUPFD and set for F_DUPFD_CLOEXEC.
- F_GETFD ignores the argument and returns exactly zero or FD_CLOEXEC. Its
  conditional observation concerns the kernel-chosen fileproc descriptor bit,
  not all aliases sharing an open file description.
- F_SETFD tests only the FD_CLOEXEC bit of the complete signed64 argument. Other
  bits remain retained and are ignored by this command, not rejected as a new
  flag policy. Successful set/clear conditionally changes that descriptor bit;
  guarded clearing can fail. Success has primary zero.
- All supported successes need a nonnegative source fd and zero secondary result.
  Both LP64 dispatchers initialize result slots; these branches modify only
  retval[0] or leave the storage unused. Preserve original typed results even
  when a command-specific relation is unsupported.

Conditional rules require descriptor/object generations, kernel lookup/lifetime
binding and successful-effect ordering. Numeric descriptors, entry/return order
and shared-fileglob aliases cannot supply those witnesses or slot state at return.
Failures produce no postcondition or no-effect assertion; reservation, guard,
concurrency and object effects remain unresolved. Source F_SETFL can mutate
shared flags before driver ioctls fail and can perform partial rollback, so it
stays unsupported until that full model exists.

Results stay immutable and incomplete, with native calibration, effect ordering,
state-feed eligibility and full acceptance false. Fresh serialization has no
mutable aliases. Helper hashes are checked before import; a stable trusted
checkout is assumed. After import the API accesses only caller bytes and the
bounded iterable. No pointer dereference, asset fallback, subprocess/network,
state-engine update, capture/export admission, native kit or SIP change occurs.

Evidence uses Apple XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea: fcntl.h278–280,
397/401; kern_descrip.c2565–2568, 2769–2863, finishdup516–578, allocation1107–1113/
1177–1214 and common exit2654–2658. file_internal.h102–125 separates descriptor
flags from fileglob. arm/systemcalls.c130/136 and i386/systemcalls.c365–366 prove
LP64 result initialization. Exact hashes and retained source provenance accompany
the implementation. Public source and portable controls do not replace native
ABI calibration or complete Darwin oracle acceptance.
