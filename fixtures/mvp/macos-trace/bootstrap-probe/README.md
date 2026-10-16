# Owned post-exec context probe

This is a fixed Darwin diagnostic and a separate portable report codec. It does
not launch a target, obtain privilege, accept plugins/actions, integrate a
controller/tracer or establish kernel exec/full Darwin acceptance.

The native executable accepts exactly:

```text
context-probe --request-sha256 <64 lowercase hexadecimal characters>
```

The caller hashes canonical request bytes **before** constructing argv. The
supplied digest binds the output; the probe does not authenticate original
request bytes or make a self-referential request hash. Native context must have
nonzero equal real/effective UID/GID, own PID==PGID and a distinct positive PPID.
Actual kernel groups must be1..16, unique, primary-first and in range. No sorting,
truncation, account lookup or invented group vector is permitted.

The probe observes cwd device/inode, empty environment, blocking directional
stdio with CLOEXEC clear, all catchable dispositions DFL, empty catchable mask
and disabled alternate stack. Two strict self libproc inventories require exact
numeric set0/1/2 with a spare four-record buffer; full/clipped/unaligned/duplicate/
negative/missing/extra sets reject. It closes/repairs no descriptor and changes
no cwd, signal policy or status flags. Different FD numbers/types are not object
identity or a filesystem-effects proof. Native F_GETFL/F_GETFD words are retained;
unknown bits never authorize effects. Device bits preserve Darwin's32-bit device
representation inside the64-bit field, and inode preserves its unsigned64-bit
value. These are host SDK checks, not guest-kernel attestation.

Only after initial context checks does the program attempt `setuid(0)` once.
It requires actual result-1/EPERM, immediate unchanged four IDs and a second
unchanged context observation. Unexpected success/error/change exits without
rollback or other target actions. There is no successful privilege call, test
callback or synthetic observation in the native CLI. Linux native observations
are unsupported before any identity/regain call; its pure codec remains usable.

All checks and canonical encoding precede one256-byte stdout write. Check failure
emits only a bounded fixed-vocabulary stage/errno attempt on stderr and exits
nonzero with `_exit`. The final write can leave a partial prefix on failure;
default SIGPIPE can terminate a broken pipe before stderr. Never replay a failed
report. A consumer needs **exactly256 bytes and normal exit0**, strict decode,
known source/build/probe provenance and independent request/READY/known-child
comparison. A complete self-report is still not a kernel exec event or proof
about arbitrary applications or saved IDs.

The `GLUENP01` v1 layout is frozen in the
[decision](../../../../docs/decisions/mvp-r02-bootstrap-probe.md). Header16 bytes,
request digest32, actual process/identity/group/cwd data, exact numeric FDs,
stdio flags and actual failed-root-regain readback fill bytes0..231;24 reserved
bytes are zero. No padded host C struct is serialized. Pure codecs clear outputs
on failure, reject exact-length/header/binding/canonicality violations and use
wide host fields to reject overflow before narrowing. `golden-vectors.json`
contains synthetic vectors independently constructed by Python struct/hashlib;
they are not native observations. The codec C helper does not link native code.

Run pure controls without any native observation or privilege call:

```sh
python3 fixtures/mvp/macos-trace/bootstrap-probe/test_probe_report.py -v
NP_TEST_CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  python3 fixtures/mvp/macos-trace/bootstrap-probe/test_probe_report.py -v
```

The12 groups cover exact lengths/null outputs, lowercase digest parsing, headers,
all reserved bytes, request binding, PID/group/ID/stdio widths, zero/duplicate/
unused groups, changed post-attempt IDs, root-result/policy rejection, independent
golden bytes/hashes and malformed wire fields. No native report is fabricated.

After independent native-source safety review, ordinary-user controls are:

```sh
python3 fixtures/mvp/macos-trace/bootstrap-probe/test_context_probe.py -v
```

The source-isolated C test driver only configures its own ordinary-user process
and execs the just-built probe; it has no root mode, fork, set* credential call,
report injection or alternate action outside closed unit modes. Python gives
that owned child a distinct session/group, empty environment, blocking private
pipe stdio and a3-second deadline, then kills only its own unreaped child and
reaps on timeout. Driver changes affect only child endpoints/signals; in the
nonblock control the parent owns the pipe's separate read OFD, never an alias
to the changed write-end flags. Parent IDs/groups/cwd/PGID/mask/PIPE/stdio flags
are checked unchanged. No limits are raised; sparseFD4096 skips if existing
capacity is insufficient.

Native positive/signal/FD controls explicitly skip if the current actual kernel
group vector/IDs do not fit the declared profile. A separate native negative
checks that unmodified unsupported vector rejects; there is no identity-preserving
injection in this probe. Native tests also cover argv, environment, wrong process
group, extra/sparse FD, blocking/direction, stdin closed by exec's CLOEXEC,
ignored SIGPIPE and inherited blocked mask. The alternate stack is observed
post-exec; no pre-exec enabled stack is falsely presented as surviving exec.
Linux tests verify explicit native unavailability, while Darwin-only tests skip.
All reports and skips remain diagnostic-unit scope.
