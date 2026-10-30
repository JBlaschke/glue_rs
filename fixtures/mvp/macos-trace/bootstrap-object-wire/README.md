# Bootstrap descriptor-object wire v2: pure data only

This additive codec transports a canonical bootstrap status and five descriptor
observations in an exact 512-byte envelope. It performs no IO, allocation,
native descriptor query, process operation, tracing or launch. The
[implementation decision](../../../../docs/decisions/mvp-r02-ready-fd-objects.md)
defines its source-selected integration. A successful decode establishes only
data validity in the caller's selected binding; ownership, capture provenance,
held-reference matching and trace or extraction acceptance require their own
checks.

Every integer uses big-endian byte order. Host struct layouts are never wire
layouts. The status envelope has these exact fields:

| Byte offset | Size | Value |
| --- | --- | --- |
| 0 | 8 | ASCII `GLUEFS02` |
| 8 | 2 | Version `2` |
| 10 | 2 | Existing `bw_kind` |
| 12 | 4 | Total length `512` |
| 16 | 4 | Row count `5` for READY, otherwise `0` |
| 20 | 4 | Payload length `256` |
| 24 | 8 | Zero reserved bytes |
| 32 | 256 | Complete canonical existing BW v1 status payload |
| 288 | 200 | Five 40-byte rows, or entirely zero for ERROR/EXEC_ATTEMPT |
| 488 | 24 | Zero reserved bytes |

Each row contains `fd`, descriptor flags, status flags and mode as four `u32`
fields, followed by device, inode and link count as three `u64` fields. READY
encoding requires `snapshot.ready == 1`, exact controller/child equality with
the BW binding and the same five kept descriptors in order. Native `int` FDs
and flags must be nonnegative and fit their wire fields. All flag bits are
preserved. Decoding rejects FD/flag values that cannot fit nonnegative native
`int`; callers must also check their native conversions before encoding. The
codec transports raw mode/device/inode/link observations, including zero or
unsigned extrema; native mode shape and object matching belong to the caller.

ERROR and EXEC_ATTEMPT encoding require a NULL snapshot. Their wire rows must
be entirely zero, and successful decode returns an entirely zero snapshot.
The inner BW codec enforces its unchanged identity/group/FD shape, stage,
reason, mutation, errno, detail, reserved-byte and binding guards. The outer
kind must equal the inner kind. The envelope's row and payload lengths are
fixed; no truncated prefix, extra byte, alternate row count or extension is
accepted.

GO remains exactly 64 bytes with the existing BW GO binding/reserved layout,
but uses ASCII `GLUEFG02` at byte zero and version `2` at byte 8. After strictly
checking those two new fields, decode locally rebases only them into the
existing BW GO validator. This is an explicit validation adapter with no
profile detection or fallback. Both codecs reject the other profile's GO, and
every prefix of a new status is refused by the legacy status decoder. The
canonical inner BW payload is available only at offset 32 after full envelope
validation; it is never sent as a standalone READY by this codec.

`bootstrap_object_wire.h` exposes `bow_status_encode`, `bow_status_decode`,
`bow_go_encode` and `bow_go_decode`, returning existing `enum bw_fault` values.
Every non-NULL encode output must have the complete advertised fixed size;
all available outputs are cleared on refusal, and decode publishes both status
and snapshot only after every check succeeds. All non-NULL objects, nested
members and spans must be valid, aligned, stable and nonoverlapping for the
call. The codec cannot validate hostile pointers or concurrent caller mutation.
It keeps no state and supplies no stream, EOF, deadline or sequence validator;
integration must validate ordering and the original absolute attempt deadline.

The fixed build dependencies are:

- `bootstrap-object-wire/bootstrap_object_wire.c` and its header;
- `bootstrap-wire/bootstrap_wire.c` and its header, for unchanged canonical BW
  status/GO validation;
- `target-fd-objects/target_fd_objects.h`, for host observation types only.

The TFO implementation and its native adapter are not linked by the controls.
Run the focused portable controls from the repository root:

```sh
python3 fixtures/mvp/macos-trace/bootstrap-object-wire/test_bootstrap_object_wire.py -v
GLUE_BOOTSTRAP_OBJECT_WIRE_SANITIZE=1 python3 fixtures/mvp/macos-trace/bootstrap-object-wire/test_bootstrap_object_wire.py -v
```

The Python harness compiles those two production C codecs and the local C
driver with strict C11 warnings. Independently constructed Python
`struct.pack_into` vectors cover READY, EXEC_ATTEMPT, three ERROR phases and GO,
testing every byte of C encoding and C decoding of the independent bytes.
Controls cover every status prefix length, extra lengths, both magic/version
profiles, every outer header and reserved byte, inner BW guards, all five rows,
negative or overflowing native integer representations, exact binding/FD
agreement, full nonnegative flags, opaque unsigned metadata, zero non-READY
rows, NULL outputs and clearing after a late fifth-row refusal. Sanitizer mode
adds ASan/UBSan. These tests make no native bootstrap, tracing, descriptor
authority or full extraction claim.
