# Packed Mach-message observations

`observe_msg2.py` calls the strict `pair_capture(capture, toolkit)` API itself.
It retains that entire result and every raw frame, plus eight entry words and
the opaque one-word return for each `mach_msg2_trap` pair. Public callers cannot
substitute decoded timelines or native-validation assertions.

```sh
python3 fixtures/mvp/macos-trace/mach-msg2/observe_msg2.py \
  --capture /absolute/owned/case --toolkit /absolute/matching/native-capture-v8 \
  > /absolute/new-local-mach-observations.json
PYTHONDONTWRITEBYTECODE=1 python3 \
  fixtures/mvp/macos-trace/mach-msg2/test_observe_msg2.py -v
```

The output decodes only pinned-source scalar low/high32 fields, signed message
ID, disposition bitfields, COMPLEX, requested SEND/RECEIVE/KOBJECT_CALL bits and
the source timeout cast. Other bits remain explicit residuals with unresolved
semantics. No pointer is dereferenced. VECTOR rejects because sizes and buffer
interpretation differ. Other scalar shapes are values, not claims that the
kernel accepts them. At most 4,096 messages may be selected, in addition to the
pairing limits.

Port names and message IDs remain numeric labels. No message body, descriptor,
consumed bytes, reply, RPC result, destination object or completed effect is
inferred. A zero trap return is opaque here. KOBJECT_CALL cannot prove a kernel
object: the pinned source permits message queues when
`CSR_ALLOW_KERNEL_DEBUGGER` enables its SIP-off compatibility path. The actual
calibration guest had SIP disabled. An ID or flag must never become an effects
allowlist.

Six v8 tree captures did not enable Mach tracing, so empty observations from
those profiles report `not-enabled-in-profile`, without an absence claim. The
Mach-enabled capture has 18 selected pairs. Full acceptance remains false and
the acceptance API/CLI always reject. The public source contract is documented
in the [decision](../../../../docs/decisions/mvp-r02-mach-msg2-scalars.md); it is
not an attestation of the installed guest kernel.
