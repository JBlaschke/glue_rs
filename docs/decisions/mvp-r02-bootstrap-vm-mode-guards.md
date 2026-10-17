# R02: retain file type and special bits in VM shell mode guards

The fresh bootstrap diagnostic stopped during installation before creating its
root stager or launching any case. Native BSD `stat -f '%u:%p:%Lp'` observes the
physical private/tmp directory as `0:41777:777`: `%Lp` prints only the low
permission bits, so the previous comparison with `0:1777` could never accept the
required sticky directory. The same format also concealed special bits on the
other directory and regular-file guards.

Use BSD `stat`'s complete octal `%p` value for every numeric mode guard in the
inline bootstrap/check commands and protected root script. Compare exact closed
values including type: directories `40700`, `40755`, or sticky `41777`, and
regular files `100500`, `100555`, or `100600`, as appropriate to each operation.
Retain real/effective root checks, physical/no-symlink checks, single-link regular
files, explicit failure edges, content/signature checks, fresh namespaces and
closure-before-restoration/export. There is no low-bit mask or fallback, and no
repair of existing protected objects.

Add portable tests of the actual narrow mode predicates against closed type,
permission, special-bit, owner and link-count observations. Native macOS controls
must exercise BSD `stat` on ordinary temporary objects and discriminate sticky
1777 from 777, directory 700/755, regular-file 500/555 and special/set-ID modes.
They may extract only narrow predicates/helpers; they do not execute generated
phases, the native kit, sudo or guest commands. The actual host private/tmp guard
must pass its exact full-mode predicate, reproducing the old failure with `%Lp`.

This bounded repair changes only VM orchestration and its focused controls/docs.
It neither changes the approved native kit/production source registration nor
completes bootstrap, tracing, kernel-exec or full MVP acceptance. Historical
failed packets/results remain immutable; any new packet needs separate review.
